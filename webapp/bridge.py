"""Python side of the Veilmark web app (runs inside Pyodide in a Web Worker).

Everything here is ordinary Veilmark API usage; the worker only moves bytes and
progress messages between JavaScript and these functions. Keys live in the
in-memory filesystem of this worker for the session; persistence is the user's
encrypted keyfile (and optionally an encrypted copy in browser storage, handled by
the page). The same functions run under CPython, which is how they are tested.
"""

from __future__ import annotations

import io
import os
import shutil
import tempfile
import time
from collections.abc import Callable
from fractions import Fraction
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image

from veilmark.api import Veilmark, WatermarkSpec, parse_strength
from veilmark.core.tasks import CancelToken, Reporter
from veilmark.crypto import keyfile, keys
from veilmark.image import io as image_io
from veilmark.security.limits import InputError, Limits
from veilmark.video import detect as vdetect
from veilmark.video import embed as vembed
from veilmark.video.ffmpeg import VideoInfo

# Browser memory is limited: refuse very large images up front.
BROWSER_LIMITS = Limits(max_image_pixels=40_000_000, max_file_bytes=200 * 1024**2)
# Video runs single-threaded in WebAssembly (roughly 5-15 frames per second at 720p):
# keep jobs to a length a browser tab can finish.
BROWSER_VIDEO_SECONDS = 600.0
BROWSER_VIDEO_PIXELS = 1920 * 1088
WEB_DETECT_FRAMES = 300  # frames analysed when detecting (the CLI uses up to 900)
FORMATS = {"png": "PNG", "jpg": "JPEG", "jpeg": "JPEG", "webp": "WEBP"}

_home = Path(tempfile.mkdtemp(prefix="veilmark-web-"))
_vm = Veilmark(_home, BROWSER_LIMITS)


def _reset() -> None:
    global _home, _vm
    shutil.rmtree(_home, ignore_errors=True)
    _home = Path(tempfile.mkdtemp(prefix="veilmark-web-"))
    _vm = Veilmark(_home, BROWSER_LIMITS)


def _reporter(progress: Callable[[float, str], Any] | None) -> Reporter:
    if progress is None:
        return Reporter()

    def relay(f: float, m: str) -> None:
        # Inner steps report "done" when *they* finish; only the last one is final.
        progress(float(f), "working…" if m == "done" and f < 0.999 else str(m))

    return Reporter(relay, CancelToken())


# ------------------------------------------------------------------- keys


def status() -> dict[str, Any]:
    ids = [i for i in _vm.keystore.identities() if i.status == "active"]
    pks = _vm.keystore.pattern_keys()
    me = ids[-1] if ids else None
    return {
        "has_keys": bool(me and pks),
        "label": me.label if me else None,
        "key_id": me.key_id if me else None,
        "fingerprint": keys.format_fingerprint(me.public_bytes) if me else None,
        "public_line": f"{keys.PUBLIC_KEY_PREFIX} {me.public_key} {me.label}" if me else None,
        "pattern_keys": [{"key_id": k.key_id, "label": k.label} for k in pks],
        # Trusted issuers' public keys alone can find their publicly verifiable watermarks.
        "can_detect": bool(_vm.detection_pattern_keys()),
        "trusted": [
            {
                "key_id": t.key_id,
                "label": t.label,
                "status": t.status,
                "fingerprint": keys.format_fingerprint(t.public_bytes),
                "own": bool(me and t.key_id == me.key_id),
            }
            for t in _vm.trust.issuers()
        ],
    }


def generate_keys(label: str) -> dict[str, Any]:
    label = (label or "").strip()[:60] or "My identity"
    _reset()
    bundle = keyfile.generate(label)
    keyfile.install_bundle(_vm.keystore, _vm.trust, bundle, None)
    return status()


def peek_keyfile(text: str) -> dict[str, Any]:
    return keyfile.peek(text)


def load_keyfile(text: str, passphrase: str) -> dict[str, Any]:
    bundle = keyfile.decrypt(text, passphrase)
    _reset()
    keyfile.install_bundle(_vm.keystore, _vm.trust, bundle, None)
    return status()


def save_keyfile(passphrase: str) -> str:
    if not status()["has_keys"]:
        raise InputError("no keys to save yet")
    bundle = keyfile.bundle_from_store(_vm.keystore, _vm.trust, None, None)
    return keyfile.encrypt(bundle, passphrase)


def forget_keys() -> dict[str, Any]:
    _reset()
    return status()


def add_trusted(public_line: str, label: str) -> dict[str, Any]:
    if not (public_line or "").strip():
        raise InputError("paste the issuer's public key")
    try:
        pub, line_label = keys.parse_key_line(public_line, keys.PUBLIC_KEY_PREFIX)
    except ValueError as e:
        raise InputError("not a valid public key") from e
    name = ((label or "").strip() or line_label or "issuer")[:60]
    _vm.trust.add(pub, name)
    return status()


def remove_trusted(key_id: str) -> dict[str, Any]:
    _vm.trust.remove(key_id)
    return status()


def add_pattern_key(line: str, label: str) -> dict[str, Any]:
    """Import someone's shared pattern key (``veilmark-pattern <b64> <label>``) to detect
    their watermarks. Pattern keys are secrets: only accept them from the issuer."""
    if not (line or "").strip():
        raise InputError("paste a pattern key")
    try:
        key, line_label = keys.parse_key_line(line, keys.PATTERN_KEY_PREFIX)
    except ValueError as e:
        raise InputError("not a valid pattern key") from e
    _vm.keystore.add_pattern_key(key, ((label or "").strip() or line_label or "shared")[:60])
    return status()


def export_pattern_line() -> str:
    """Your own pattern key as a shareable line. Without keys of your own every pattern
    key here was shared by someone else, so there is nothing to export."""
    if not status()["has_keys"]:
        raise InputError("create or open your keys first")
    pk = _vm.keystore.pattern_key()
    # Name the line after the identity (what the recipient needs), not the key's own label.
    return f"{keys.PATTERN_KEY_PREFIX} {pk.key} {status()['label']}"


# ------------------------------------------------------------------ media


def _as_bytes(data: Any) -> bytes:
    """Accept Python bytes or a Pyodide JsProxy of a Uint8Array."""
    if hasattr(data, "to_bytes"):
        return bytes(data.to_bytes())
    return bytes(data)


def _load(data: bytes, name: str) -> image_io.ImageData:
    if len(data) > BROWSER_LIMITS.max_file_bytes:
        raise InputError("file too large for the browser version")
    Image.MAX_IMAGE_PIXELS = BROWSER_LIMITS.max_image_pixels
    try:
        with Image.open(io.BytesIO(data)) as im:
            if im.width * im.height > BROWSER_LIMITS.max_image_pixels:
                raise InputError("image too large for the browser version (40 MP max)")
            im.load()
            return image_io.from_pil(im)
    except InputError:
        raise
    except Exception as e:
        raise InputError(f"cannot read {name or 'image'}: {e}") from e


def embed(
    data: bytes,
    name: str,
    text: str,
    strength: str,
    out_format: str,
    quality: int,
    sign: bool,
    self_check: bool,
    progress: Callable[[float, str], Any] | None = None,
    allow_rewatermark: bool = False,
    public: bool = False,
) -> dict[str, Any]:
    """Watermark image bytes; returns the result dict plus the encoded output bytes.

    ``public``: publicly verifiable (pattern derived from the signing public key)."""
    rep = _reporter(progress)
    if not status()["has_keys"]:
        raise InputError("generate or load keys first")
    rep(0.02, "reading image")
    img = _load(_as_bytes(data), name)
    stem, ext = os.path.splitext(name or "image.png")
    fmt_key = (out_format if out_format != "same" else ext.lstrip(".")).lower()
    fmt = FORMATS.get(fmt_key, "PNG")
    spec = WatermarkSpec(
        text=text or None,
        sign=bool(sign),
        strength=parse_strength(strength),
        quality=int(quality),
        allow_rewatermark=bool(allow_rewatermark),
        public=bool(public),
    )
    out, res = _vm.embed_image_data(img, spec, rep.sub(0.05, 0.55 if self_check else 0.9))
    rep(0.56 if self_check else 0.92, "encoding output")
    blob = image_io.encode(out, fmt, int(quality))
    if fmt == "JPEG" and img.alpha is not None:
        res.notes.append("JPEG has no alpha channel; transparency was dropped")
    if self_check:
        check = _vm.detect_image_data(_load(blob, name), "self-check", reporter=rep.sub(0.58, 0.99))
        ok = check.payload_recovered_for(res.watermark_id)
        res.extra["self_check"] = {"status": check.status, "payload_recoverable": ok}
        if not ok:
            res.notes.append(
                f"SELF-CHECK FAILED ({check.status}): the payload cannot be recovered even from this "
                "unmodified output. The image is too small or too flat for this payload; use a shorter "
                "text, a larger image or the 'robust' strength."
            )
    ext_out = {"PNG": "png", "JPEG": "jpg", "WEBP": "webp"}[fmt]
    rep(1.0, "done")
    d = res.to_dict()
    d["output_name"] = f"{stem}.wm.{ext_out}"
    d["mime"] = {"PNG": "image/png", "JPEG": "image/jpeg", "WEBP": "image/webp"}[fmt]
    d["size"] = [img.width, img.height]
    return {"result": d, "output": blob}


def detect(
    data: bytes, name: str, thorough: bool = True, progress: Callable[[float, str], Any] | None = None
) -> dict[str, Any]:
    rep = _reporter(progress)
    if not _vm.detection_pattern_keys():
        raise InputError(
            "add the issuer's public key (enough for publicly verifiable watermarks) or their "
            "pattern key, or load your own keys"
        )
    rep(0.02, "reading image")
    img = _load(_as_bytes(data), name)
    r = _vm.detect_image_data(img, name or "image", reporter=rep.sub(0.05, 1.0), deep=bool(thorough))
    return r.to_dict()


# ------------------------------------------------------------------ video
#
# The worker decodes and encodes video with the browser's WebCodecs (Mediabunny) and
# hands luma planes to these functions one frame at a time. Detection is a sequence of
# frame requests (see veilmark.video.detect.DetectSteps):
#
#   req = video_*_begin(...)                  # {"stride", "max_frames", "run_length"}
#   loop: for each wanted frame: video_frame(y)
#         r = video_frames_end()              # {"request": ...} again, or {"report": ...}
#
# Embedding: video_embed_begin (returns the request of the check for an existing
# watermark, or None), video_embed_start, video_embed_frame per frame,
# video_embed_finish, then optionally video_self_check_begin for the read-back check.

_job: dict[str, Any] = {}


def _video_info(meta: Any) -> VideoInfo:
    m = meta.to_py() if hasattr(meta, "to_py") else dict(meta)
    w, h = int(m["width"]), int(m["height"])
    fps = Fraction(float(m.get("fps") or 30.0)).limit_denominator(1001)
    duration = float(m.get("duration") or 0.0)
    if duration > BROWSER_VIDEO_SECONDS:
        raise InputError(f"video too long for the browser version ({BROWSER_VIDEO_SECONDS / 60:.0f} min max)")
    if w * h > BROWSER_VIDEO_PIXELS:
        raise InputError("video frame too large for the browser version (1080p max)")
    frames = m.get("frames")
    return VideoInfo(
        path=Path(str(m.get("name") or "video")),
        width=w,
        height=h,
        fps=fps,
        duration=duration,
        frames=int(frames) if frames else None,
        codec=str(m.get("codec") or "?"),
        pix_fmt="yuv420p",
        rotation=int(m.get("rotation") or 0),
        has_audio=bool(m.get("audio_codecs")),
        audio_codecs=[str(c) for c in (m.get("audio_codecs") or [])],
        bit_rate=None,
        variable_frame_rate=False,
    )


def _luma(data: Any, info: VideoInfo) -> np.ndarray:
    buf = _as_bytes(data)
    if len(buf) != info.width * info.height:
        raise InputError("frame size changed mid-video")
    return np.frombuffer(buf, dtype=np.uint8).reshape(info.height, info.width)


def _start_steps(steps: vdetect.DetectSteps) -> dict[str, int]:
    _job["steps"] = steps
    req = next(steps)
    assert req is not None
    return req.to_dict()


def video_frame(data: Any) -> None:
    """One wanted frame (luma bytes, width x height) for the running detection."""
    if _job["steps"].send(_luma(data, _job["info"])) is not None:
        raise RuntimeError("detector out of step")


def video_frames_end() -> dict[str, Any]:
    """All wanted frames were sent: the next request, or the finished report."""
    try:
        req = _job["steps"].send(None)
        return {"request": req.to_dict()}
    except StopIteration as stop:
        _job["report"] = stop.value
        return {"report": stop.value.to_dict()}


def video_detect_begin(
    meta: Any, progress: Callable[[float, str], Any] | None = None, max_frames: int = WEB_DETECT_FRAMES
) -> dict[str, int]:
    if not _vm.detection_pattern_keys():
        raise InputError(
            "add the issuer's public key (enough for publicly verifiable watermarks) or their "
            "pattern key, or load your own keys"
        )
    _job.clear()
    info = _job["info"] = _video_info(meta)
    rep = _reporter(progress)
    return _start_steps(vdetect.detect_steps(_vm, info, info.path.name, None, int(max_frames), None, rep))


def video_embed_begin(
    meta: Any,
    text: str,
    strength: str,
    mode: str = "robust",
    public: bool = False,
    allow_rewatermark: bool = False,
    self_check: bool = True,
    progress: Callable[[float, str], Any] | None = None,
) -> dict[str, int] | None:
    """Validate and prepare; returns the frame request of the existing-watermark check
    (finish it with video_frame / video_frames_end before video_embed_start)."""
    if not status()["has_keys"]:
        raise InputError("generate or load keys first")
    _job.clear()
    info = _job["info"] = _video_info(meta)
    if min(info.width, info.height) < 128:
        raise InputError("video too small to watermark (minimum 128 px on the short side)")
    if mode not in ("robust", "light"):
        raise InputError(f"unknown video mode {mode!r}")
    spec = WatermarkSpec(
        text=text or None,
        sign=True,
        strength=parse_strength(strength),
        allow_rewatermark=bool(allow_rewatermark),
        public=bool(public),
    )
    rep = _reporter(progress)
    # Progress: existing-watermark check, embedding, read-back check.
    split = (0.12, 0.6) if self_check else (0.12, 1.0)
    _job.update(spec=spec, mode=mode, rep=rep, split=split, t0=time.perf_counter(), notes=[])
    return _start_steps(
        vdetect.detect_steps(
            _vm, info, info.path.name, None, vembed.EXISTING_CHECK_FRAMES, None, rep.sub(0.0, split[0])
        )
    )


def video_embed_start() -> dict[str, Any]:
    """After the existing-watermark check: refuse, or set up the frame embedder."""
    info: VideoInfo = _job["info"]
    avoid = vembed.existing_watermark(_job["spec"], _job.pop("report"), _job["notes"])
    _job["embedder"] = vembed.FrameEmbedder(
        _vm, _job["spec"], info.width, info.height, float(info.fps), _job["mode"], avoid
    )
    return {"watermark_id": _job["embedder"].wid.hex()}


def video_embed_frame(data: Any) -> bytes:
    """Watermark one frame's luma plane (in presentation order); returns the new plane."""
    info: VideoInfo = _job["info"]
    fe: vembed.FrameEmbedder = _job["embedder"]
    lo, hi = _job["split"]
    total = info.frames or max(1, round(info.duration * float(info.fps)))
    _job["rep"](lo + (hi - lo) * min(0.99, fe.frames / total), f"frame {fe.frames + 1}/{total}")
    return fe.luma(_luma(data, info)).tobytes()


def video_embed_finish(output_name: str, size: int, notes: Any = None) -> dict[str, Any]:
    fe: vembed.FrameEmbedder = _job["embedder"]
    if fe.frames == 0:
        raise InputError("no frames could be decoded from the video")
    extra_notes = [str(n) for n in (notes.to_py() if hasattr(notes, "to_py") else notes or [])]
    res = fe.result(output_name, int(size), time.perf_counter() - _job["t0"], _job["notes"] + extra_notes)
    info: VideoInfo = _job["info"]
    res.extra["source"] = info.summary()
    _job["result"] = res
    return _video_result(res)


def _video_result(res: Any) -> dict[str, Any]:
    info: VideoInfo = _job["info"]
    d: dict[str, Any] = res.to_dict()
    d["output_name"] = res.output
    d["size"] = [info.width, info.height]
    return d


def video_self_check_begin(meta: Any) -> dict[str, int]:
    """Read-back check of the encoded output (same request protocol as detection)."""
    info = _job["info"] = _video_info(meta)
    lo = _job["split"][1]
    return _start_steps(
        vdetect.detect_steps(
            _vm, info, "self-check", None, WEB_DETECT_FRAMES, None, _job["rep"].sub(lo, 0.99)
        )
    )


def video_self_check_result() -> dict[str, Any]:
    res = _job["result"]
    check = _job.pop("report")
    ok = check.payload_recovered_for(res.watermark_id)
    res.extra["self_check"] = {"status": check.status, "payload_recoverable": ok}
    if not ok:
        res.notes.append(
            f"SELF-CHECK FAILED ({check.status}): the payload cannot be recovered from the encoded "
            "output. The video may be too short, small or flat, or the browser's encoder too lossy; "
            "use a shorter text, the 'robust' strength or the desktop app."
        )
    return _video_result(res)
