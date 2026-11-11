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
    from veilmark.detection.report import DetectionReport

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
        avoid = existing_watermark(spec, vm.detect_video(src, max_frames=EXISTING_CHECK_FRAMES), notes)
    fe = FrameEmbedder(vm, spec, info.width, info.height, float(info.fps), mode, avoid, measure_every)
    ysize = ffmpeg.yuv420_sizes(info.width, info.height)[0]

    fd, tmp_name = tempfile.mkstemp(dir=dst.parent, prefix=".veilmark-", suffix=".partial" + dst.suffix)
    os.close(fd)
    tmp = Path(tmp_name)
    reader = ffmpeg.FrameReader(info, "yuv420p", max_frames=max_frames)
    writer = ffmpeg.FrameWriter(info, tmp, encode or ffmpeg.EncodeSettings())
    total = info.frames or 1
    try:
        for frame in reader:
            rep(min(0.98, fe.frames / total), f"frame {fe.frames + 1}/{total}")
            y2 = fe.luma(frame[:ysize].reshape(info.height, info.width))
            out = bytearray(frame.tobytes())
            out[:ysize] = y2.tobytes()
            writer.write(bytes(out))
        if fe.frames == 0:
            raise InputError("no frames could be decoded from the input video")
        rep(0.985, "finalising encode")
        writer.finish()
        os.replace(tmp, dst)
    except (Cancelled, Exception):
        writer.abort()
        reader.close()
        tmp.unlink(missing_ok=True)
        raise
    res = fe.result(str(dst), dst.stat().st_size, time.perf_counter() - t0, notes)
    res.extra["source"] = info.summary()
    if info.has_audio:
        res.extra["audio"] = "preserved (" + ", ".join(info.audio_codecs) + ")"
    rep(1.0, "done")
    return res


EXISTING_CHECK_FRAMES = 120  # frames analysed when looking for an earlier watermark


def existing_watermark(spec: WatermarkSpec, prior: DetectionReport, notes: list[str]) -> list[float] | None:
    """Act on the pre-embed detection result: refuse (AlreadyWatermarked) unless
    re-watermarking is allowed; then return the tile period(s) the new mark must avoid."""
    if not prior.detected:
        return None
    from veilmark.api import AlreadyWatermarked, _existing_entry

    geo = prior.geometry or {}
    period = float(np.mean([geo.get("period_x", 0.0), geo.get("period_y", 0.0)]))
    entry = _existing_entry(prior, period, float(prior.confidence.get("sync_z", 0.0)))
    if not spec.allow_rewatermark:
        raise AlreadyWatermarked([entry])
    notes.append(
        "the input already carried a watermark; the new one uses a different tile period "
        "so both remain separately detectable"
    )
    return [period]


class FrameEmbedder:
    """Watermarks the luma plane of one video frame after another, in presentation order.

    Independent of how frames are decoded and encoded: ``embed_video`` feeds it from
    ffmpeg, the web app (webapp/bridge.py) from WebCodecs.
    """

    def __init__(
        self,
        vm: Veilmark,
        spec: WatermarkSpec,
        width: int,
        height: int,
        fps: float,
        mode: str = "robust",
        avoid_periods: list[float] | None = None,
        measure_every: int = 30,
    ) -> None:
        self.wid = spec.watermark_id or os.urandom(8)
        self.raw, self.signer = vm.build_payload(spec, self.wid)
        self.pk = vm.embedding_pattern_key(spec)
        self.strength = spec.strength * (LIGHT_STRENGTH_FACTOR if mode == "light" else 1.0)
        self.plan = engine.make_plan(
            KeyedPatterns(self.pk.key_bytes),
            self.wid,
            self.raw,
            height,
            width,
            self.strength,
            spec.chip_px,
            avoid_periods=avoid_periods,
        )
        self.sched = Schedule(self.pk.key_bytes, self.wid, fps, mode)
        self.mode = mode
        self.shape = (height, width)
        self.measure_every = measure_every
        self.gain: np.ndarray | None = None
        self.psnrs: list[float] = []
        self.frames = 0
        self.weak = False

    def luma(self, y_in: np.ndarray) -> np.ndarray:
        """Watermarked copy of one frame's luma plane (uint8, height x width)."""
        if y_in.shape != self.shape:
            raise InputError(f"frame size changed mid-video ({y_in.shape[1]}x{y_in.shape[0]})")
        y = y_in.astype(np.float32)
        g = perceptual.masking_map(y, self.plan.chip_px)
        if self.gain is None:
            self.weak = float(np.mean(g)) < LOW_GAIN_WARNING
        self.gain = g if self.gain is None else (1 - MASK_EMA) * self.gain + MASK_EMA * g
        delta = self.plan.delta(y, self.sched.weights(self.frames), self.gain)
        y2 = np.clip(np.rint(y + delta), 0, 255).astype(np.uint8)
        if self.frames % self.measure_every == 0:
            self.psnrs.append(metrics.psnr(y, y2))
        self.frames += 1
        return y2

    def result(self, output: str, bytes_written: int, seconds: float, notes: list[str]) -> EmbedResult:
        from veilmark.api import EmbedResult

        notes = list(notes)
        if self.weak:
            notes.append(
                "content is mostly flat or near pure black/white: the watermark is embedded "
                "very weakly and may not be recoverable (measured: binary cellular graphics "
                "were not detected even without modification)"
            )
        res = EmbedResult(
            output=output,
            watermark_id=self.wid.hex(),
            payload_bytes=len(self.raw),
            capacity_class=framing.LENGTH_CLASSES[self.plan.frame.class_index],
            signed=self.signer is not None,
            signer_key_id=self.signer,
            pattern_key_id=self.pk.key_id,
            chip_px=self.plan.chip_px,
            tile_period_px=self.plan.period,
            strength=self.strength,
            psnr_db=round(float(np.mean(self.psnrs)), 2) if self.psnrs else None,
            ssim=None,
            bytes_written=bytes_written,
            seconds=round(seconds, 2),
            notes=notes,
        )
        extra: dict[str, Any] = {
            "frames": self.frames,
            "mode": self.mode,
            "segments": self.sched.segment_of(max(self.frames - 1, 0)) + 1,
            "psnr_note": f"pre-encode luma PSNR, sampled every {self.measure_every} frames",
        }
        res.extra = extra
        return res
