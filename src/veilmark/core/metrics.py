"""Objective image-quality metrics (computed on luma unless stated)."""

from __future__ import annotations

import cv2
import numpy as np


def psnr(a: np.ndarray, b: np.ndarray, peak: float = 255.0) -> float:
    mse = float(np.mean((a.astype(np.float64) - b.astype(np.float64)) ** 2))
    return float("inf") if mse == 0 else float(10.0 * np.log10(peak * peak / mse))


def ssim(a: np.ndarray, b: np.ndarray, peak: float = 255.0) -> float:
    """Mean SSIM (Wang et al. 2004; Gaussian window sigma 1.5) of 2-D arrays."""
    x = a.astype(np.float64)
    y = b.astype(np.float64)
    c1, c2 = (0.01 * peak) ** 2, (0.03 * peak) ** 2

    def blur(z: np.ndarray) -> np.ndarray:
        return cv2.GaussianBlur(z, (11, 11), 1.5)

    mx, my = blur(x), blur(y)
    sxx = blur(x * x) - mx * mx
    syy = blur(y * y) - my * my
    sxy = blur(x * y) - mx * my
    num = (2 * mx * my + c1) * (2 * sxy + c2)
    den = (mx * mx + my * my + c1) * (sxx + syy + c2)
    return float(np.mean(num / den))


def luma(rgb: np.ndarray) -> np.ndarray:
    if rgb.ndim == 2:
        return rgb.astype(np.float32)
    return rgb[..., :3].astype(np.float32) @ np.array([0.299, 0.587, 0.114], np.float32)
