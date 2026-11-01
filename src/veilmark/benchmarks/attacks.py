"""Attack catalogue for the robustness laboratory.

Image attacks operate on RGB uint8 arrays; randomised parameters (crop position,
noise) come from a ``numpy.random.Generator`` seeded by the benchmark — never from
cryptographic sources. Video attacks are ffmpeg argument templates.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import cv2
import numpy as np


@dataclass(frozen=True)
class Attack:
    name: str
    group: str
    fn: Callable[[np.ndarray, np.random.Generator], np.ndarray]
    params: dict[str, Any] = field(default_factory=dict)
    expected: str = "robust"  # robust | partial | not-supported (documented expectation)


def _codec(a: np.ndarray, ext: str, flags: list[int]) -> np.ndarray:
    ok, buf = cv2.imencode(ext, cv2.cvtColor(a, cv2.COLOR_RGB2BGR), flags)
    if not ok:
        raise RuntimeError("encode failed")
    dec = cv2.imdecode(buf, cv2.IMREAD_COLOR)
    if dec is None:
        raise RuntimeError("decode failed")
    return cv2.cvtColor(dec, cv2.COLOR_BGR2RGB)


def jpeg(q: int) -> Callable[[np.ndarray, np.random.Generator], np.ndarray]:
    return lambda a, r: _codec(a, ".jpg", [cv2.IMWRITE_JPEG_QUALITY, q])


def webp(q: int) -> Callable[[np.ndarray, np.random.Generator], np.ndarray]:
    return lambda a, r: _codec(a, ".webp", [cv2.IMWRITE_WEBP_QUALITY, q])


def scale(f: float, fy: float | None = None) -> Callable[[np.ndarray, np.random.Generator], np.ndarray]:
    def run(a: np.ndarray, r: np.random.Generator) -> np.ndarray:
        fx, fyy = f, fy if fy is not None else f
        interp = cv2.INTER_AREA if max(fx, fyy) < 1 else cv2.INTER_CUBIC
        return cv2.resize(a, None, fx=fx, fy=fyy, interpolation=interp)

    return run


def crop(area: float) -> Callable[[np.ndarray, np.random.Generator], np.ndarray]:
    """Random-position crop keeping ``area`` of the pixels (random aspect 0.6..1.6)."""

    def run(a: np.ndarray, r: np.random.Generator) -> np.ndarray:
        h, w = a.shape[:2]
        aspect = float(np.exp(r.uniform(np.log(0.6), np.log(1.6))))
        ch = int(min(h, np.sqrt(area * h * w / aspect)))
        cw = int(min(w, area * h * w / max(ch, 1)))
        y0 = int(r.integers(0, h - ch + 1))
        x0 = int(r.integers(0, w - cw + 1))
        return np.ascontiguousarray(a[y0 : y0 + ch, x0 : x0 + cw])

    return run


def rotate(deg: float, crop_valid: bool = True) -> Callable[[np.ndarray, np.random.Generator], np.ndarray]:
    def run(a: np.ndarray, r: np.random.Generator) -> np.ndarray:
        h, w = a.shape[:2]
        if deg % 90 == 0:
            return np.ascontiguousarray(np.rot90(a, int(deg // 90)))
        m = cv2.getRotationMatrix2D((w / 2, h / 2), deg, 1.0)
        out = cv2.warpAffine(a, m, (w, h), flags=cv2.INTER_LINEAR, borderMode=cv2.BORDER_REFLECT)
        if crop_valid:  # keep the central region that contains no padding
            t = np.radians(abs(deg))
            s = 1.0 / (np.cos(t) + np.sin(t) * max(w, h) / min(w, h))
            ch, cw = int(h * s), int(w * s)
            out = out[(h - ch) // 2 : (h + ch) // 2, (w - cw) // 2 : (w + cw) // 2]
        return np.ascontiguousarray(out)

    return run


def _lut(f: Callable[[np.ndarray], np.ndarray]) -> Callable[[np.ndarray, np.random.Generator], np.ndarray]:
    table = np.clip(f(np.arange(256, dtype=np.float32)), 0, 255).astype(np.uint8)
    return lambda a, r: table[a]


def saturation(s: float) -> Callable[[np.ndarray, np.random.Generator], np.ndarray]:
    def run(a: np.ndarray, r: np.random.Generator) -> np.ndarray:
        hsv = cv2.cvtColor(a, cv2.COLOR_RGB2HSV).astype(np.float32)
        hsv[..., 1] = np.clip(hsv[..., 1] * s, 0, 255)
        return cv2.cvtColor(hsv.astype(np.uint8), cv2.COLOR_HSV2RGB)

    return run


def hue(deg: float) -> Callable[[np.ndarray, np.random.Generator], np.ndarray]:
    def run(a: np.ndarray, r: np.random.Generator) -> np.ndarray:
        hsv = cv2.cvtColor(a, cv2.COLOR_RGB2HSV)
        hsv[..., 0] = ((hsv[..., 0].astype(np.int32) + int(deg / 2)) % 180).astype(np.uint8)
        return cv2.cvtColor(hsv, cv2.COLOR_HSV2RGB)

    return run


def grayscale(a: np.ndarray, r: np.random.Generator) -> np.ndarray:
    g = cv2.cvtColor(a, cv2.COLOR_RGB2GRAY)
    return np.dstack([g] * 3)


def blur(sigma: float) -> Callable[[np.ndarray, np.random.Generator], np.ndarray]:
    return lambda a, r: cv2.GaussianBlur(a, (0, 0), sigma)


def sharpen(amount: float) -> Callable[[np.ndarray, np.random.Generator], np.ndarray]:
    def run(a: np.ndarray, r: np.random.Generator) -> np.ndarray:
        b = cv2.GaussianBlur(a, (0, 0), 1.5)
        return cv2.addWeighted(a, 1 + amount, b, -amount, 0)

    return run


def noise(sigma: float) -> Callable[[np.ndarray, np.random.Generator], np.ndarray]:
    return lambda a, r: np.clip(a + r.normal(0, sigma, a.shape), 0, 255).astype(np.uint8)


def denoise(h: float) -> Callable[[np.ndarray, np.random.Generator], np.ndarray]:
    return lambda a, r: cv2.fastNlMeansDenoisingColored(a, None, h, h, 7, 21)


def median(k: int) -> Callable[[np.ndarray, np.random.Generator], np.ndarray]:
    return lambda a, r: cv2.medianBlur(a, k)


def mirror(a: np.ndarray, r: np.random.Generator) -> np.ndarray:
    return np.ascontiguousarray(a[:, ::-1])


def perspective(strength: float) -> Callable[[np.ndarray, np.random.Generator], np.ndarray]:
    def run(a: np.ndarray, r: np.random.Generator) -> np.ndarray:
        h, w = a.shape[:2]
        d = strength * min(h, w)
        src = np.array([[0, 0], [w, 0], [w, h], [0, h]], dtype=np.float32)
        dst = src + r.uniform(-d, d, (4, 2)).astype(np.float32)
        m = cv2.getPerspectiveTransform(src, dst)
        return cv2.warpPerspective(a, m, (w, h), borderMode=cv2.BORDER_REFLECT)

    return run


def chain(
    *fns: Callable[[np.ndarray, np.random.Generator], np.ndarray],
) -> Callable[[np.ndarray, np.random.Generator], np.ndarray]:
    def run(a: np.ndarray, r: np.random.Generator) -> np.ndarray:
        for f in fns:
            a = f(a, r)
        return a

    return run


IMAGE_ATTACKS: list[Attack] = [
    Attack("none", "baseline", lambda a, r: a),
    Attack("png-roundtrip", "baseline", lambda a, r: _codec(a, ".png", [])),
    Attack("jpeg-90", "compression", jpeg(90), {"quality": 90}),
    Attack("jpeg-75", "compression", jpeg(75), {"quality": 75}),
    Attack("jpeg-50", "compression", jpeg(50), {"quality": 50}),
    Attack("jpeg-30", "compression", jpeg(30), {"quality": 30}, "partial"),
    Attack("webp-80", "compression", webp(80), {"quality": 80}),
    Attack("webp-50", "compression", webp(50), {"quality": 50}),
    Attack("scale-0.5", "geometry", scale(0.5), {"factor": 0.5}),
    Attack("scale-0.75", "geometry", scale(0.75), {"factor": 0.75}),
    Attack("scale-1.5", "geometry", scale(1.5), {"factor": 1.5}),
    Attack("aspect-0.9", "geometry", scale(0.9, 1.0), {"fx": 0.9, "fy": 1.0}, "partial"),
    Attack("crop-75", "crop", crop(0.75), {"area": 0.75}),
    Attack("crop-50", "crop", crop(0.5), {"area": 0.5}),
    Attack("crop-25", "crop", crop(0.25), {"area": 0.25}),
    Attack("crop-10", "crop", crop(0.10), {"area": 0.10}, "partial"),
    Attack("rotate-2", "geometry", rotate(2), {"degrees": 2}),
    Attack("rotate-10", "geometry", rotate(10), {"degrees": 10}),
    Attack("rotate-90", "geometry", rotate(90), {"degrees": 90}),
    Attack("mirror", "geometry", mirror),
    Attack("perspective-2pct", "geometry", perspective(0.02), {"corner_jitter": 0.02}, "partial"),
    Attack("grayscale", "colour", grayscale),
    Attack("brightness+30", "colour", _lut(lambda x: x + 30), {"offset": 30}),
    Attack("contrast-0.7", "colour", _lut(lambda x: (x - 128) * 0.7 + 128), {"factor": 0.7}),
    Attack("gamma-0.6", "colour", _lut(lambda x: 255 * (x / 255) ** 0.6), {"gamma": 0.6}),
    Attack("gamma-1.6", "colour", _lut(lambda x: 255 * (x / 255) ** 1.6), {"gamma": 1.6}),
    Attack("saturation-1.6", "colour", saturation(1.6), {"factor": 1.6}),
    Attack("hue+30", "colour", hue(30), {"degrees": 30}),
    Attack("blur-1", "filter", blur(1.0), {"sigma": 1.0}),
    Attack("blur-2", "filter", blur(2.0), {"sigma": 2.0}, "partial"),
    Attack("sharpen", "filter", sharpen(1.0), {"amount": 1.0}),
    Attack("noise-5", "filter", noise(5), {"sigma": 5}),
    Attack("noise-12", "filter", noise(12), {"sigma": 12}),
    Attack("median-3", "filter", median(3), {"kernel": 3}),
    Attack("denoise-nlm", "filter", denoise(7), {"h": 7}, "partial"),
    Attack("combo-crop50-scale0.7-jpeg75", "combination", chain(crop(0.5), scale(0.7), jpeg(75))),
    Attack("combo-rot5-crop60-jpeg70", "combination", chain(rotate(5), crop(0.6), jpeg(70))),
    Attack(
        "combo-screenshot-like",
        "combination",
        chain(scale(0.8), _lut(lambda x: 255 * (x / 255) ** 0.9), sharpen(0.5), jpeg(85)),
    ),
    Attack("combo-social-media", "combination", chain(scale(0.6), saturation(1.2), jpeg(70))),
]

QUICK_ATTACKS = [
    "none",
    "jpeg-75",
    "scale-0.5",
    "crop-50",
    "rotate-10",
    "grayscale",
    "noise-5",
    "combo-crop50-scale0.7-jpeg75",
]


def image_attacks(names: list[str] | None = None) -> list[Attack]:
    if not names:
        return list(IMAGE_ATTACKS)
    by = {a.name: a for a in IMAGE_ATTACKS}
    missing = [n for n in names if n not in by]
    if missing:
        raise ValueError(f"unknown attacks: {missing}")
    return [by[n] for n in names]


# ------------------------------------------------------------------- video


@dataclass(frozen=True)
class VideoAttack:
    name: str
    group: str
    args: list[str]  # ffmpeg args between "-i input" and the output path
    params: dict[str, Any] = field(default_factory=dict)
    ext: str = ".mp4"
    expected: str = "robust"


VIDEO_ATTACKS: list[VideoAttack] = [
    VideoAttack("none", "baseline", ["-c", "copy"]),
    VideoAttack(
        "h264-crf23", "transcode", ["-c:v", "libx264", "-crf", "23", "-preset", "veryfast"], {"crf": 23}
    ),
    VideoAttack(
        "h264-crf30", "transcode", ["-c:v", "libx264", "-crf", "30", "-preset", "veryfast"], {"crf": 30}
    ),
    VideoAttack(
        "h264-1mbps", "transcode", ["-c:v", "libx264", "-b:v", "1M", "-preset", "veryfast"], {"bitrate": "1M"}
    ),
    VideoAttack(
        "vp9-crf36",
        "transcode",
        ["-c:v", "libvpx-vp9", "-crf", "36", "-b:v", "0", "-deadline", "realtime", "-cpu-used", "8"],
        {"crf": 36},
        ".webm",
    ),
    VideoAttack(
        "hevc-crf28",
        "transcode",
        ["-c:v", "libx265", "-crf", "28", "-preset", "veryfast", "-x265-params", "log-level=error"],
        {"crf": 28},
    ),
    VideoAttack(
        "downscale-480p",
        "geometry",
        ["-vf", "scale=-2:480", "-c:v", "libx264", "-crf", "26", "-preset", "veryfast"],
        {"height": 480},
    ),
    VideoAttack(
        "downscale-360p",
        "geometry",
        ["-vf", "scale=-2:360", "-c:v", "libx264", "-crf", "26", "-preset", "veryfast"],
        {"height": 360},
        expected="partial",
    ),
    VideoAttack(
        "fps-24",
        "temporal",
        ["-vf", "fps=24", "-c:v", "libx264", "-crf", "23", "-preset", "veryfast"],
        {"fps": 24},
    ),
    VideoAttack(
        "drop-1-of-3",
        "temporal",
        [
            "-vf",
            "select='mod(n\\,3)'",
            "-fps_mode",
            "vfr",
            "-c:v",
            "libx264",
            "-crf",
            "23",
            "-preset",
            "veryfast",
        ],
        {"dropped": "1/3"},
    ),
    VideoAttack(
        "clip-2s",
        "temporal",
        ["-ss", "2", "-t", "2", "-c:v", "libx264", "-crf", "23", "-preset", "veryfast"],
        {"seconds": 2},
    ),
    VideoAttack(
        "clip-1s",
        "temporal",
        ["-ss", "3", "-t", "1", "-c:v", "libx264", "-crf", "23", "-preset", "veryfast"],
        {"seconds": 1},
    ),
    VideoAttack(
        "clip-0.5s",
        "temporal",
        ["-ss", "3", "-t", "0.5", "-c:v", "libx264", "-crf", "23", "-preset", "veryfast"],
        {"seconds": 0.5},
        expected="partial",
    ),
    VideoAttack(
        "crop-50-fixed",
        "crop",
        ["-vf", "crop=iw*0.7:ih*0.7:iw*0.2:ih*0.1", "-c:v", "libx264", "-crf", "23", "-preset", "veryfast"],
        {"area": 0.49},
    ),
    VideoAttack(
        "crop-25-fixed",
        "crop",
        ["-vf", "crop=iw*0.5:ih*0.5:iw*0.4:ih*0.3", "-c:v", "libx264", "-crf", "23", "-preset", "veryfast"],
        {"area": 0.25},
    ),
    VideoAttack(
        "crop-moving",
        "crop",
        [
            "-vf",
            "crop=iw*0.6:ih*0.6:'(iw*0.4)*t/6':'(ih*0.4)*(0.5+0.5*sin(t))'",
            "-c:v",
            "libx264",
            "-crf",
            "23",
            "-preset",
            "veryfast",
        ],
        {"area": 0.36, "motion": "pan+sine"},
    ),
    VideoAttack(
        "crop-scale-compress",
        "combination",
        [
            "-vf",
            "crop=iw*0.7:ih*0.7:iw*0.15:ih*0.15,scale=-2:432",
            "-c:v",
            "libx264",
            "-crf",
            "27",
            "-preset",
            "veryfast",
        ],
        {"area": 0.49, "height": 432, "crf": 27},
    ),
    VideoAttack(
        "hflip", "geometry", ["-vf", "hflip", "-c:v", "libx264", "-crf", "23", "-preset", "veryfast"]
    ),
    VideoAttack(
        "color-eq",
        "colour",
        [
            "-vf",
            "eq=brightness=0.06:contrast=1.2:saturation=1.4:gamma=0.9",
            "-c:v",
            "libx264",
            "-crf",
            "23",
            "-preset",
            "veryfast",
        ],
    ),
]

QUICK_VIDEO_ATTACKS = ["none", "h264-crf30", "downscale-480p", "clip-1s", "crop-moving"]


def video_attacks(names: list[str] | None = None) -> list[VideoAttack]:
    if not names:
        return list(VIDEO_ATTACKS)
    by = {a.name: a for a in VIDEO_ATTACKS}
    missing = [n for n in names if n not in by]
    if missing:
        raise ValueError(f"unknown video attacks: {missing}")
    return [by[n] for n in names]
