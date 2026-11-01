"""Video embedding: stream frames through ffmpeg, watermark luma, re-encode.

Only the Y plane of yuv420p frames is modified (chroma bytes are passed through
untouched). The perceptual masking map is smoothed over time with an exponential
moving average so the embedding strength does not flicker with sensor noise.
"""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

import numpy as np

from veilmark.core import metrics
from veilmark.core.tasks import Cancelled, Reporter
from veilmark.security.limits import InputError, check_input_file, check_output_path
from veilmark.video import ffmpeg
from veilmark.video.schedule import Schedule
from veilmark.watermark import engine, framing, perceptual
from veilmark.watermark.pattern import KeyedPatterns

if TYPE_CHECKING:
    from veilmark.api import EmbedResult, Veilmark, WatermarkSpec

MASK_EMA = 0.3  # weight of the newest frame in the temporal mask average
LIGHT_STRENGTH_FACTOR = 0.75
LOW_GAIN_WARNING = 0.4  # mean masking gain below which embedding is very weak


def embed_video(
    vm: Veilmark,
    src: Path,
    dst: Path,
    spec: WatermarkSpec,
    overwrite: bool = False,
    mode: str = "robust",
    encode: ffmpeg.EncodeSettings | None = None,
    reporter: Reporter | None = None,
    measure_every: int = 30,
    max_frames: int | None = None,
) -> EmbedResult:
    from veilmark.api import EmbedResult

    rep = reporter or Reporter()
    t0 = time.perf_counter()
    src = check_input_file(Path(src), vm.limits)
    dst = check_output_path(src, Path(dst), overwrite)
    info = ffmpeg.probe(src)
    if info.duration > vm.limits.max_video_seconds:
        raise InputError("video exceeds the configured duration limit")
    if info.width * info.height > vm.limits.max_video_pixels_per_frame:
        raise InputError("video frame size exceeds the configured limit")
    if min(info.width, info.height) < 128:
        raise InputError("video too small to watermark (minimum 128 px on the short side)")
    notes: list[str] = []
    if info.variable_frame_rate:
        notes.append(
            "source looks variable-frame-rate; output is constant-rate at the average "
            "frame rate (timing of individual frames may shift slightly)"
        )
    if info.rotation:
        notes.append(f"rotation metadata ({info.rotation} deg) was applied to the pixels")

    avoid: list[float] | None = None
    if spec.check_existing:
        rep(0.0, "checking for existing watermarks")
        prior = vm.detect_video(src, max_frames=120)
        if prior.detected:
            from veilmark.api import AlreadyWatermarked, _existing_entry

            geo = prior.geometry or {}
            period = float(np.mean([geo.get("period_x", 0.0), geo.get("period_y", 0.0)]))
            entry = _existing_entry(prior, period, float(prior.confidence.get("sync_z", 0.0)))
            if not spec.allow_rewatermark:
                raise AlreadyWatermarked([entry])
            avoid = [period]
            notes.append(
                "the input already carried a watermark; the new one uses a different tile period "
                "so both remain separately detectable"
            )
    wid = spec.watermark_id or os.urandom(8)
    raw, signer = vm.build_payload(spec, wid)
    pk = vm.keystore.pattern_key(spec.pattern_key)
    pats = KeyedPatterns(pk.key_bytes)
    strength = spec.strength * (LIGHT_STRENGTH_FACTOR if mode == "light" else 1.0)
    plan = engine.make_plan(
        pats, wid, raw, info.height, info.width, strength, spec.chip_px, avoid_periods=avoid
    )
    sched = Schedule(pk.key_bytes, wid, float(info.fps), mode)
    ysize = ffmpeg.yuv420_sizes(info.width, info.height)[0]

    fd, tmp_name = tempfile.mkstemp(dir=dst.parent, prefix=".veilmark-", suffix=".partial" + dst.suffix)
    os.close(fd)
    tmp = Path(tmp_name)
    reader = ffmpeg.FrameReader(info, "yuv420p", max_frames=max_frames)
    writer = ffmpeg.FrameWriter(info, tmp, encode or ffmpeg.EncodeSettings())
    total = info.frames or 1
    gain: np.ndarray | None = None
    psnrs: list[float] = []
    n = 0
    try:
        for frame in reader:
            rep(min(0.98, n / total), f"frame {n + 1}/{total}")
            y = frame[:ysize].reshape(info.height, info.width).astype(np.float32)
            g = perceptual.masking_map(y, plan.chip_px)
            if gain is None and float(np.mean(g)) < LOW_GAIN_WARNING:
                notes.append(
                    "content is mostly flat or near pure black/white: the watermark is embedded "
                    "very weakly and may not be recoverable (measured: binary cellular graphics "
                    "were not detected even without modification)"
                )
            gain = g if gain is None else (1 - MASK_EMA) * gain + MASK_EMA * g
            delta = plan.delta(y, sched.weights(n), gain)
            y2 = np.clip(np.rint(y + delta), 0, 255).astype(np.uint8)
            if n % measure_every == 0:
                psnrs.append(metrics.psnr(y, y2))
            out = bytearray(frame.tobytes())
            out[:ysize] = y2.tobytes()
            writer.write(bytes(out))
            n += 1
        if n == 0:
            raise InputError("no frames could be decoded from the input video")
        rep(0.985, "finalising encode")
        writer.finish()
        os.replace(tmp, dst)
    except (Cancelled, Exception):
        writer.abort()
        reader.close()
        tmp.unlink(missing_ok=True)
        raise
    res = EmbedResult(
        output=str(dst),
        watermark_id=wid.hex(),
        payload_bytes=len(raw),
        capacity_class=framing.LENGTH_CLASSES[plan.frame.class_index],
        signed=signer is not None,
        signer_key_id=signer,
        pattern_key_id=pk.key_id,
        chip_px=plan.chip_px,
        tile_period_px=plan.period,
        strength=strength,
        psnr_db=round(float(np.mean(psnrs)), 2) if psnrs else None,
        ssim=None,
        bytes_written=dst.stat().st_size,
        seconds=round(time.perf_counter() - t0, 2),
        notes=notes,
    )
    extra: dict[str, Any] = {
        "frames": n,
        "mode": mode,
        "segments": sched.segment_of(max(n - 1, 0)) + 1,
        "source": info.summary(),
        "psnr_note": f"pre-encode luma PSNR, sampled every {measure_every} frames",
    }
    if info.has_audio:
        extra["audio"] = "preserved (" + ", ".join(info.audio_codecs) + ")"
    res.extra = extra
    rep(1.0, "done")
    return res
