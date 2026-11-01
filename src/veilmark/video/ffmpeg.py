"""Thin, safe wrappers around the ffmpeg / ffprobe executables.

* Commands are always argument lists (never a shell), and user paths are passed
  after ``-i`` or as the final output argument, so file names cannot inject options
  (paths starting with ``-`` are made explicit with ``./`` or ``file:``).
* Frames are streamed through pipes one at a time (bounded memory).
* Video is decoded with ffmpeg's default autorotation, so pixels are upright and
  the output carries no rotation flag.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from fractions import Fraction
from pathlib import Path
from typing import IO, Any

import numpy as np

from veilmark.security.limits import InputError


class FFmpegMissing(RuntimeError):
    pass


class FFmpegError(RuntimeError):
    pass


INSTALL_HINT = (
    "FFmpeg is required for video. Install it and make sure `ffmpeg` and `ffprobe` are on "
    "PATH (or set VEILMARK_FFMPEG / VEILMARK_FFPROBE):\n"
    "  macOS:   brew install ffmpeg\n"
    "  Windows: winget install Gyan.FFmpeg   (or choco install ffmpeg)\n"
    "  Linux:   sudo apt install ffmpeg      (or your distribution's package)"
)


def ffmpeg_bin() -> str:
    exe = os.environ.get("VEILMARK_FFMPEG") or shutil.which("ffmpeg")
    if not exe:
        raise FFmpegMissing(INSTALL_HINT)
    return exe


def ffprobe_bin() -> str:
    exe = os.environ.get("VEILMARK_FFPROBE") or shutil.which("ffprobe")
    if not exe:
        raise FFmpegMissing(INSTALL_HINT)
    return exe


def available() -> bool:
    try:
        ffmpeg_bin()
        ffprobe_bin()
        return True
    except FFmpegMissing:
        return False


def safe_path(p: Path) -> str:
    """Path string that ffmpeg can never mistake for an option or protocol."""
    s = str(p)
    return "file:" + str(Path(s).resolve()) if s.startswith("-") or ":" in Path(s).name else s


def version() -> str:
    out = subprocess.run(
        [ffmpeg_bin(), "-hide_banner", "-version"], capture_output=True, text=True, check=False
    )
    return out.stdout.splitlines()[0] if out.stdout else "unknown"


@dataclass
class VideoInfo:
    path: Path
    width: int  # display width after rotation
    height: int
    fps: Fraction
    duration: float
    frames: int | None
    codec: str
    pix_fmt: str
    rotation: int
    has_audio: bool
    audio_codecs: list[str]
    bit_rate: int | None
    variable_frame_rate: bool
    color: dict[str, str] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    def summary(self) -> dict[str, Any]:
        return {
            "width": self.width,
            "height": self.height,
            "fps": float(self.fps),
            "duration": round(self.duration, 3),
            "frames": self.frames,
            "codec": self.codec,
            "pix_fmt": self.pix_fmt,
            "rotation": self.rotation,
            "audio": self.audio_codecs,
            "bit_rate": self.bit_rate,
            "variable_frame_rate": self.variable_frame_rate,
        }


def _fraction(s: str | None) -> Fraction | None:
    if not s or s in ("0/0", "N/A"):
        return None
    try:
        f = Fraction(s)
        return f if f > 0 else None
    except (ValueError, ZeroDivisionError):
        return None


def probe(path: Path) -> VideoInfo:
    cmd = [
        ffprobe_bin(),
        "-v",
        "error",
        "-print_format",
        "json",
        "-show_format",
        "-show_streams",
        safe_path(path),
    ]
    r = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=60)
    if r.returncode != 0:
        raise InputError(f"ffprobe could not read {Path(path).name}: {r.stderr.strip()[:300]}")
    data = json.loads(r.stdout or "{}")
    vstreams = [
        s
        for s in data.get("streams", [])
        if s.get("codec_type") == "video" and not s.get("disposition", {}).get("attached_pic")
    ]
    if not vstreams:
        raise InputError("no video stream found")
    v = vstreams[0]
    astreams = [s for s in data.get("streams", []) if s.get("codec_type") == "audio"]
    rot = 0
    for sd in v.get("side_data_list", []) or []:
        if "rotation" in sd:
            rot = int(round(float(sd["rotation"])))
    if "rotate" in (v.get("tags") or {}):
        rot = int(v["tags"]["rotate"])
    w, h = int(v["width"]), int(v["height"])
    if abs(rot) % 180 == 90:
        w, h = h, w
    avg = _fraction(v.get("avg_frame_rate"))
    rfr = _fraction(v.get("r_frame_rate"))
    fps = avg or rfr or Fraction(30)
    vfr = bool(avg and rfr and abs(float(avg) - float(rfr)) / float(rfr) > 0.01)
    dur = float(v.get("duration") or data.get("format", {}).get("duration") or 0.0)
    nb = v.get("nb_frames")
    frames = int(nb) if nb and str(nb).isdigit() else (int(round(dur * float(fps))) if dur else None)
    color = {k: v[k] for k in ("color_range", "color_space", "color_primaries", "color_transfer") if k in v}
    br = v.get("bit_rate") or data.get("format", {}).get("bit_rate")
    return VideoInfo(
        Path(path),
        w,
        h,
        fps,
        dur,
        frames,
        v.get("codec_name", "?"),
        v.get("pix_fmt", "?"),
        rot,
        bool(astreams),
        [a.get("codec_name", "?") for a in astreams],
        int(br) if br and str(br).isdigit() else None,
        vfr,
        color,
        data,
    )


def yuv420_sizes(w: int, h: int) -> tuple[int, int, int]:
    cw, ch = (w + 1) // 2, (h + 1) // 2
    return w * h, cw * ch, w * h + 2 * cw * ch


class _StderrDrain(threading.Thread):
    """Collect stderr in the background so ffmpeg never blocks on a full pipe."""

    def __init__(self, stream: IO[bytes]) -> None:
        super().__init__(daemon=True)
        self.stream = stream
        self.chunks: list[bytes] = []

    def run(self) -> None:
        for line in iter(self.stream.readline, b""):
            if sum(len(c) for c in self.chunks) < 64_000:
                self.chunks.append(line)

    def text(self) -> str:
        return b"".join(self.chunks).decode("utf-8", "replace")


class FrameReader:
    """Iterate decoded frames as numpy arrays (``gray`` -> (H, W); ``yuv420p`` -> bytes)."""

    def __init__(
        self,
        info: VideoInfo,
        pix_fmt: str = "gray",
        stride: int = 1,
        start: float | None = None,
        max_frames: int | None = None,
        run_length: int = 1,
    ) -> None:
        """``stride``/``run_length``: keep ``run_length`` consecutive frames out of every
        ``stride`` (e.g. 4 of every 60)."""
        self.info = info
        self.pix_fmt = pix_fmt
        self.stride = max(1, stride)
        self.max_frames = max_frames
        cmd = [ffmpeg_bin(), "-v", "error", "-nostdin"]
        if start:
            cmd += ["-ss", f"{start:.3f}"]
        cmd += ["-i", safe_path(info.path), "-map", "0:v:0", "-an", "-sn", "-dn"]
        if self.stride > 1:
            run = max(1, min(run_length, self.stride))
            cmd += ["-vf", f"select=lt(mod(n\\,{self.stride})\\,{run})", "-fps_mode", "passthrough"]
        else:
            cmd += ["-fps_mode", "passthrough"]
        cmd += ["-f", "rawvideo", "-pix_fmt", pix_fmt, "pipe:1"]
        self.cmd = cmd
        self.proc: subprocess.Popen[bytes] | None = None

    def frame_bytes(self) -> int:
        w, h = self.info.width, self.info.height
        return w * h if self.pix_fmt == "gray" else yuv420_sizes(w, h)[2]

    def __iter__(self) -> Iterator[np.ndarray]:
        self.proc = subprocess.Popen(
            self.cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL
        )
        assert self.proc.stdout is not None and self.proc.stderr is not None
        drain = _StderrDrain(self.proc.stderr)
        drain.start()
        n = self.frame_bytes()
        count = 0
        try:
            while self.max_frames is None or count < self.max_frames:
                buf = self.proc.stdout.read(n)
                if len(buf) < n:
                    break
                count += 1
                a = np.frombuffer(buf, dtype=np.uint8)
                if self.pix_fmt == "gray":
                    yield a.reshape(self.info.height, self.info.width)
                else:
                    yield a
        finally:
            self.close()
            drain.join(timeout=2)
        if self.proc.returncode not in (0, None, -15, -9) and count == 0:
            raise FFmpegError(f"ffmpeg decode failed: {drain.text().strip()[:500]}")

    def close(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=10)


@dataclass
class EncodeSettings:
    codec: str = "auto"  # auto | libx264 | libx265 | libvpx-vp9 | libsvtav1
    crf: int | None = None  # None -> codec default below
    preset: str = "medium"
    bitrate: str | None = None  # e.g. "4M" (overrides CRF)
    audio: str = "auto"  # auto | copy | aac | opus | none

    def video_args(self, container: str) -> list[str]:
        codec = self.codec
        if codec == "auto":
            codec = "libvpx-vp9" if container == ".webm" else "libx264"
        args = ["-c:v", codec]
        if codec in ("libx264", "libx265"):
            args += ["-preset", self.preset]
            if self.bitrate:
                args += ["-b:v", self.bitrate]
            else:
                args += [
                    "-crf",
                    str(self.crf if self.crf is not None else (18 if codec == "libx264" else 20)),
                ]
            if codec == "libx265":
                args += ["-tag:v", "hvc1"] if container in (".mp4", ".mov", ".m4v") else []
        elif codec == "libvpx-vp9":
            args += ["-row-mt", "1", "-deadline", "good", "-cpu-used", "2"]
            args += (
                ["-b:v", self.bitrate]
                if self.bitrate
                else ["-crf", str(self.crf if self.crf is not None else 24), "-b:v", "0"]
            )
        elif codec == "libsvtav1":
            args += ["-crf", str(self.crf if self.crf is not None else 28), "-preset", "8"]
        else:
            if self.bitrate:
                args += ["-b:v", self.bitrate]
        return args

    def audio_args(self, container: str, src_codecs: list[str]) -> list[str]:
        if self.audio == "none" or not src_codecs:
            return ["-an"]
        mode = self.audio
        if mode == "auto":
            ok = {
                ".mp4": {"aac", "mp3", "alac", "ac3", "eac3", "opus"},
                ".m4v": {"aac", "mp3", "alac", "ac3"},
                ".mov": {"aac", "mp3", "alac", "pcm_s16le", "pcm_s24le", "ac3"},
                ".webm": {"opus", "vorbis"},
                ".mkv": None,
            }.get(container, set())
            if ok is None or all(c in ok for c in src_codecs):
                mode = "copy"
            else:
                mode = "opus" if container == ".webm" else "aac"
        if mode == "copy":
            return ["-c:a", "copy"]
        if mode == "opus":
            return ["-c:a", "libopus", "-b:a", "160k"]
        return ["-c:a", "aac", "-b:a", "192k"]


class FrameWriter:
    """Encode yuv420p frames from a pipe, muxing audio/metadata from the source."""

    def __init__(self, info: VideoInfo, out_path: Path, settings: EncodeSettings) -> None:
        container = out_path.suffix.lower()
        fps = info.fps
        cmd = [
            ffmpeg_bin(),
            "-v",
            "error",
            "-nostdin",
            "-y",
            "-f",
            "rawvideo",
            "-pix_fmt",
            "yuv420p",
            "-s",
            f"{info.width}x{info.height}",
            "-framerate",
            f"{fps.numerator}/{fps.denominator}",
            "-i",
            "pipe:0",
            "-i",
            safe_path(info.path),
            "-map",
            "0:v:0",
            "-map",
            "1:a?",
            "-map_metadata",
            "1",
            "-map_chapters",
            "1",
        ]
        cmd += settings.video_args(container)
        cmd += ["-pix_fmt", "yuv420p"]
        for k, flag in (
            ("color_primaries", "-color_primaries"),
            ("color_transfer", "-color_trc"),
            ("color_space", "-colorspace"),
            ("color_range", "-color_range"),
        ):
            val = info.color.get(k)
            if val and val != "unknown":
                cmd += [flag, val]
        cmd += settings.audio_args(container, info.audio_codecs)
        if container in (".mp4", ".mov", ".m4v"):
            cmd += ["-movflags", "+faststart"]
        fmt = {".mp4": "mp4", ".m4v": "mp4", ".mov": "mov", ".mkv": "matroska", ".webm": "webm"}.get(
            container
        )
        if fmt is None:
            raise InputError(
                f"unsupported video output container {container!r} (use .mp4, .mov, .mkv, .webm)"
            )
        cmd += ["-f", fmt, safe_path(out_path)]
        self.cmd = cmd
        self.proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
        )
        assert self.proc.stderr is not None
        self._drain = _StderrDrain(self.proc.stderr)
        self._drain.start()

    def write(self, frame: bytes | np.ndarray) -> None:
        assert self.proc.stdin is not None
        try:
            self.proc.stdin.write(frame if isinstance(frame, bytes) else frame.tobytes())
        except BrokenPipeError as e:
            self.proc.wait()
            raise FFmpegError(f"encoder exited early: {self._drain.text().strip()[:800]}") from e

    def finish(self) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.close()
        rc = self.proc.wait()
        self._drain.join(timeout=5)
        if rc != 0:
            raise FFmpegError(f"ffmpeg encode failed ({rc}): {self._drain.text().strip()[:800]}")

    def abort(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=10)


def run(cmd_args: list[str], timeout: float | None = None) -> None:
    """Run an ffmpeg command (args after the executable); raise with stderr on failure."""
    r = subprocess.run(
        [ffmpeg_bin(), "-v", "error", "-nostdin", "-y", *cmd_args],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )
    if r.returncode != 0:
        raise FFmpegError(r.stderr.strip()[:800])
