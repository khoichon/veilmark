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
from collections.abc import Callable
from pathlib import Path
from typing import Any

from PIL import Image

from veilmark.api import Veilmark, WatermarkSpec, parse_strength
from veilmark.core.tasks import CancelToken, Reporter
from veilmark.crypto import keyfile, keys
from veilmark.image import io as image_io
from veilmark.security.limits import InputError, Limits

# Browser memory is limited: refuse very large images up front.
BROWSER_LIMITS = Limits(max_image_pixels=40_000_000, max_file_bytes=200 * 1024**2)
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
