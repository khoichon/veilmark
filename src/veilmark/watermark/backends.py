"""Watermark backend interface and registry.

A backend embeds a (watermark id, payload bytes) pair into pixels and blindly
recovers it. Signing, payload parsing and trust live outside the backend, so any
backend automatically gets authenticated payloads.

The built-in backend is ``tss`` (tiled spread spectrum, :mod:`.engine`); plugins may
register more for images. Video always uses ``tss`` in this release.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

import numpy as np

from veilmark.watermark import engine, framing
from veilmark.watermark.pattern import KeyedPatterns


@dataclass(frozen=True)
class BackendInfo:
    name: str
    version: str
    media: tuple[str, ...]
    max_payload_bytes: int
    robust_to: tuple[str, ...]
    not_robust_to: tuple[str, ...]
    compute: str
    limitations: tuple[str, ...] = ()
    experimental: bool = False


@dataclass
class BackendDetection:
    watermark_id: bytes | None
    payload: bytes | None  # padded payload bytes (may include trailing zeros)
    sync_z: float
    searched: int
    details: dict[str, object] = field(default_factory=dict)


@runtime_checkable
class ImageBackend(Protocol):
    info: BackendInfo

    def embed_luma_delta(
        self, luma: np.ndarray, watermark_id: bytes, payload: bytes, pattern_key: bytes, strength: float
    ) -> np.ndarray:
        """Return a float32 luma delta (H, W) to add to R, G and B."""
        ...

    def detect_luma(self, luma: np.ndarray, pattern_keys: list[bytes]) -> BackendDetection: ...


class TSSBackend:
    info = BackendInfo(
        name="tss",
        version="1",
        media=("image", "video"),
        max_payload_bytes=framing.LENGTH_CLASSES[-1] - 4,
        robust_to=(
            "crop (>= ~1 tile)",
            "uniform scaling ~0.5x-2x",
            "rotation",
            "mirroring",
            "JPEG/WebP/H.264/VP9 recompression",
            "brightness/contrast/gamma",
            "colour and saturation changes",
            "greyscale",
            "mild blur/sharpen/noise",
            "video frame drops, rate changes, short clips",
        ),
        not_robust_to=(
            "strong non-uniform resizing or perspective",
            "heavy denoising at low strength",
            "camera recapture of a screen",
            "tiny crops (< one tile)",
            "collusion / averaging of many differently watermarked copies",
            "targeted attacks by holders of the pattern key",
        ),
        compute="CPU, NumPy/OpenCV; ~1-3 s per megapixel image detect, real-time-ish video embed",
        limitations=("payload <= 188 bytes; signed payloads use 70+ bytes",),
    )

    def embed_luma_delta(
        self,
        luma: np.ndarray,
        watermark_id: bytes,
        payload: bytes,
        pattern_key: bytes,
        strength: float,
        chip_px: int | None = None,
    ) -> np.ndarray:
        pats = KeyedPatterns(pattern_key)
        plan = engine.make_plan(pats, watermark_id, payload, luma.shape[0], luma.shape[1], strength, chip_px)
        return plan.delta(luma, {engine.variant_for_id(watermark_id): 1.0})

    def detect_luma(self, luma: np.ndarray, pattern_keys: list[bytes]) -> BackendDetection:
        keyring = [KeyedPatterns(k) for k in pattern_keys]
        det = engine.detect_luma(luma, keyring)
        out = det.outcome
        z = det.best.hit.z if det.best and det.best.hit else 0.0
        return BackendDetection(
            out.core.watermark_id if out and out.core.ok else None,
            out.full.body if out and out.full and out.full.ok else None,
            z,
            det.searched_positions,
        )


_REGISTRY: dict[str, ImageBackend] = {"tss": TSSBackend()}


def register(backend: ImageBackend) -> None:
    if not isinstance(backend, ImageBackend):
        raise TypeError("backend does not implement the ImageBackend interface")
    name = backend.info.name
    if name in _REGISTRY:
        raise ValueError(f"backend {name!r} already registered")
    _REGISTRY[name] = backend


def unregister(name: str) -> None:
    if name == "tss":
        raise ValueError("the built-in backend cannot be removed")
    _REGISTRY.pop(name, None)


def get(name: str) -> ImageBackend:
    try:
        return _REGISTRY[name]
    except KeyError:
        raise ValueError(f"unknown backend {name!r}; available: {sorted(_REGISTRY)}") from None


def available() -> list[BackendInfo]:
    return [b.info for b in _REGISTRY.values()]
