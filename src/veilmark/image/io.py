"""Image import/export with Pillow.

Pixels are handled as 8-bit RGB (plus optional alpha). The watermark lives in
luminance: the same delta is added to R, G and B, which changes BT.601 luma by
exactly that delta and leaves chroma untouched (up to clipping). Alpha is preserved
unchanged.

Metadata policy: EXIF orientation is applied to the pixels (so the output is
upright), the ICC colour profile is preserved, and other EXIF/XMP metadata is NOT
copied to the output (it may contain personal data such as GPS position).
"""

from __future__ import annotations

import io
import os
import tempfile
import warnings
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
from PIL import Image, ImageOps

from veilmark.security.limits import DEFAULT_LIMITS, InputError, Limits, check_input_file

SUPPORTED_WRITE = {
    ".png": "PNG",
    ".jpg": "JPEG",
    ".jpeg": "JPEG",
    ".webp": "WEBP",
    ".tif": "TIFF",
    ".tiff": "TIFF",
    ".bmp": "BMP",
}
LUMA = np.array([0.299, 0.587, 0.114], dtype=np.float32)


@dataclass
class ImageData:
    rgb: np.ndarray  # (H, W, 3) uint8
    alpha: np.ndarray | None = None  # (H, W) uint8
    source_format: str | None = None
    icc_profile: bytes | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def height(self) -> int:
        return int(self.rgb.shape[0])

    @property
    def width(self) -> int:
        return int(self.rgb.shape[1])

    def luma(self) -> np.ndarray:
        return self.rgb.astype(np.float32) @ LUMA


def from_pil(im: Image.Image, notes: list[str] | None = None) -> ImageData:
    notes = notes if notes is not None else []
    fmt = im.format
    icc = im.info.get("icc_profile")
    try:
        im = ImageOps.exif_transpose(im)
    except Exception:
        notes.append("EXIF orientation could not be applied")
    alpha = None
    if im.mode in ("I;16", "I;16B", "I;16L", "I", "F"):
        a = np.asarray(im, dtype=np.float64)
        scale = 255.0 / max(float(np.max(a)), 1.0) if im.mode != "I;16" else 255.0 / 65535.0
        im = Image.fromarray(np.clip(a * scale, 0, 255).astype(np.uint8), "L")
        notes.append("high bit-depth greyscale converted to 8-bit")
    if im.mode == "CMYK":
        notes.append("CMYK converted to RGB")
    if im.mode == "P":
        im = im.convert("RGBA" if "transparency" in im.info else "RGB")
        notes.append("palette image converted to true colour")
    if im.mode in ("RGBA", "LA", "PA") or (im.mode == "RGBa"):
        rgba = np.asarray(im.convert("RGBA"))
        rgb = rgba[..., :3].copy()
        # Fully opaque alpha carries no information; dropping it avoids pointless
        # "transparency lost" warnings when saving to JPEG.
        alpha = None if bool((rgba[..., 3] == 255).all()) else rgba[..., 3].copy()
    else:
        rgb = np.asarray(im.convert("RGB")).copy()
    return ImageData(rgb, alpha, fmt, icc, notes)


def load(path: Path, limits: Limits = DEFAULT_LIMITS) -> ImageData:
    p = check_input_file(Path(path), limits)
    Image.MAX_IMAGE_PIXELS = limits.max_image_pixels
    notes: list[str] = []
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(p) as im:
                if im.width * im.height > limits.max_image_pixels:
                    raise InputError("image exceeds the configured pixel limit")
                if getattr(im, "n_frames", 1) > 1:
                    notes.append("multi-frame image: only the first frame is used")
                im.load()
                return from_pil(im, notes)
    except (Image.DecompressionBombError, Image.DecompressionBombWarning) as e:
        raise InputError(f"image rejected by decompression-bomb guard: {e}") from e
    except InputError:
        raise
    except Exception as e:
        raise InputError(f"cannot decode image {p.name}: {e}") from e


def to_pil(img: ImageData) -> Image.Image:
    if img.alpha is not None:
        return Image.fromarray(np.dstack([img.rgb, img.alpha]), "RGBA")
    return Image.fromarray(img.rgb, "RGB")


def encode(img: ImageData, fmt: str, quality: int = 95) -> bytes:
    fmt = fmt.upper()
    pil = to_pil(img)
    kw: dict[str, object] = {}
    if img.icc_profile:
        kw["icc_profile"] = img.icc_profile
    if fmt == "JPEG":
        if img.alpha is not None:
            pil = pil.convert("RGB")
        kw.update(quality=quality, subsampling=0 if quality >= 90 else 2, optimize=True)
    elif fmt == "WEBP":
        kw.update(quality=quality, method=4)
        if quality >= 100:
            kw.update(lossless=True)
    elif fmt == "PNG":
        kw.update(optimize=False, compress_level=6)
    buf = io.BytesIO()
    pil.save(buf, format=fmt, **kw)
    return buf.getvalue()


def format_for(path: Path) -> str:
    ext = Path(path).suffix.lower()
    if ext not in SUPPORTED_WRITE:
        raise InputError(f"unsupported output format {ext!r}; use one of {sorted(SUPPORTED_WRITE)}")
    return SUPPORTED_WRITE[ext]


def save(img: ImageData, path: Path, quality: int = 95) -> int:
    """Atomically write ``img``; returns the written size in bytes."""
    path = Path(path)
    data = encode(img, format_for(path), quality)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".veilmark-", suffix=".partial")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return len(data)
