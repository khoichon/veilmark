"""User settings shared by all front-ends (JSON in the data home)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any

from veilmark.security.limits import Limits
from veilmark.storage import paths


@dataclass
class Settings:
    default_output_dir: str = ""  # empty: next to the input file
    output_suffix: str = ".wm"
    default_strength: float = 1.0
    jpeg_quality: int = 95
    video_mode: str = "robust"
    video_codec: str = "auto"
    video_crf: int | None = None
    detect_max_frames: int = 900
    max_image_megapixels: float = 120.0
    max_video_minutes: float = 240.0
    max_file_gb: float = 4.0
    temp_dir: str = ""  # empty: system default / output directory
    benchmark_workers: int = 0  # 0: auto
    # Veilmark has no network features; this is recorded so the UI can state it.
    network_enabled: bool = False
    show_disclaimer: bool = True

    def limits(self) -> Limits:
        return Limits(
            max_image_pixels=int(self.max_image_megapixels * 1e6),
            max_file_bytes=int(self.max_file_gb * 1024**3),
            max_video_seconds=self.max_video_minutes * 60.0,
        )

    def validate(self) -> list[str]:
        probs = []
        if not 0.1 <= self.default_strength <= 4.0:
            probs.append("strength must be within 0.1..4.0")
        if not 1 <= self.jpeg_quality <= 100:
            probs.append("JPEG quality must be 1..100")
        if self.video_mode not in ("robust", "light"):
            probs.append("video mode must be robust or light")
        if self.max_image_megapixels <= 0 or self.max_video_minutes <= 0 or self.max_file_gb <= 0:
            probs.append("limits must be positive")
        if self.default_output_dir and not Path(self.default_output_dir).is_dir():
            probs.append("default output directory does not exist")
        if self.network_enabled:
            probs.append("network features do not exist in this release")
        return probs


def path(home: Path | None = None) -> Path:
    return (home or paths.data_home()) / "settings.json"


def load(home: Path | None = None) -> Settings:
    data: dict[str, Any] = paths.read_json(path(home), {})
    known = {f.name for f in fields(Settings)}
    return Settings(**{k: v for k, v in data.items() if k in known})


def save(s: Settings, home: Path | None = None) -> None:
    probs = s.validate()
    if probs:
        raise ValueError("; ".join(probs))
    paths.atomic_write_json(path(home), asdict(s))
