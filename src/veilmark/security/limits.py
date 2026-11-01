"""Input validation limits and safe output-path handling."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


class InputError(ValueError):
    """Invalid or disallowed input (user-correctable)."""


@dataclass(frozen=True)
class Limits:
    max_image_pixels: int = 120_000_000  # ~11k x 11k
    max_file_bytes: int = 4 * 1024**3
    max_video_seconds: float = 4 * 3600.0
    max_video_pixels_per_frame: int = 8192 * 4320


DEFAULT_LIMITS = Limits()


def check_input_file(path: Path, limits: Limits = DEFAULT_LIMITS) -> Path:
    p = Path(path)
    if not p.exists():
        raise InputError(f"input not found: {p}")
    if not p.is_file():
        raise InputError(f"input is not a regular file: {p}")
    size = p.stat().st_size
    if size == 0:
        raise InputError(f"input is empty: {p}")
    if size > limits.max_file_bytes:
        raise InputError(f"input exceeds size limit ({size} > {limits.max_file_bytes} bytes)")
    return p


def check_output_path(src: Path | None, dst: Path, overwrite: bool = False) -> Path:
    """Refuse to clobber the source, and refuse existing files unless allowed."""
    d = Path(dst)
    if src is not None and d.exists() and os.path.samefile(src, d):
        raise InputError("refusing to overwrite the input file; choose another output path")
    if src is not None and d.resolve() == Path(src).resolve():
        raise InputError("refusing to overwrite the input file; choose another output path")
    if d.exists() and not overwrite:
        raise InputError(f"output exists: {d} (use --overwrite to replace it)")
    if not d.parent.exists():
        raise InputError(f"output directory does not exist: {d.parent}")
    return d
