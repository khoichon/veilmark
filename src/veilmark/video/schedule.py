"""Keyed temporal schedule for the moving watermark distribution.

A video is split into segments of keyed, pseudo-random length. Each segment uses one
of the key's pattern *variants*. Variants differ in sync pattern, spreading signs,
chip-to-bit permutation and cyclic tile offset, so the image region that carries a
given payload bit changes from segment to segment: a fixed crop sees different parts
of the code over time, and naive frame averaging (an estimation attack against a
static pattern) mixes independent patterns instead of reinforcing one.

Segment boundaries are cross-faded with energy-preserving (cos/sin) weights over a
few frames to avoid a visible pattern "jump". The detector does not need the
schedule: it identifies each frame's variant from the sync correlation, so dropped,
duplicated, reordered or trimmed frames are tolerated.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from veilmark.crypto import kdf
from veilmark.watermark.pattern import NUM_VARIANTS


@dataclass(frozen=True)
class ScheduleParams:
    min_seconds: float
    max_seconds: float
    fade_seconds: float


MODES = {
    # Fast variant changes: short surviving clips still see several variants.
    "robust": ScheduleParams(0.5, 1.2, 0.15),
    # Longer segments and lower strength: less distortion, relies on accumulation.
    "light": ScheduleParams(1.5, 3.0, 0.3),
}


class Schedule:
    def __init__(self, pattern_key: bytes, watermark_id: bytes, fps: float, mode: str = "robust") -> None:
        if mode not in MODES:
            raise ValueError(f"unknown schedule mode {mode!r}")
        self.p = MODES[mode]
        self.fps = max(fps, 1.0)
        self._key = kdf.derive_key(pattern_key, "video.schedule", watermark_id)
        self.fade = max(1, int(round(self.p.fade_seconds * self.fps)))
        self._starts: list[int] = [0]
        self._variants: list[int] = []
        self._block = 0

    def _extend(self) -> None:
        """Generate the next block of 64 segments deterministically."""
        lo = max(self.fade + 2, int(round(self.p.min_seconds * self.fps)))
        hi = max(lo + 1, int(round(self.p.max_seconds * self.fps)))
        lens = kdf.random_ints(self._key, "lengths", self._block, n=64, high=hi - lo + 1) + lo
        picks = kdf.random_ints(self._key, "variants", self._block, n=64, high=NUM_VARIANTS - 1)
        for ln, pk in zip(lens, picks, strict=True):
            prev = (
                self._variants[-1]
                if self._variants
                else int(kdf.random_ints(self._key, "first", n=1, high=NUM_VARIANTS)[0])
            )
            # Never repeat the previous variant (offset 1..NUM_VARIANTS-1).
            v = prev if not self._variants else (prev + 1 + int(pk)) % NUM_VARIANTS
            self._variants.append(v)
            self._starts.append(self._starts[-1] + int(ln))
        self._block += 1

    def weights(self, frame: int) -> dict[int, float]:
        """Variant -> amplitude weight for a frame (sum of squares == 1)."""
        while self._starts[-1] <= frame + self.fade:
            self._extend()
        seg = int(np.searchsorted(self._starts, frame, side="right") - 1)
        v = self._variants[seg]
        end = self._starts[seg + 1]
        into_next = frame - (end - self.fade)
        if into_next >= 0:
            # Cross-fade towards the next segment's variant.
            t = (into_next + 0.5) / self.fade
            return {v: float(np.cos(t * np.pi / 2)), self._variants[seg + 1]: float(np.sin(t * np.pi / 2))}
        return {v: 1.0}

    def segment_of(self, frame: int) -> int:
        while self._starts[-1] <= frame:
            self._extend()
        return int(np.searchsorted(self._starts, frame, side="right") - 1)
