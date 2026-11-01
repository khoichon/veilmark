"""Perceptual weighting of the watermark signal.

The added luminance signal is scaled by a local masking map:

* **Texture masking**: busy regions hide more signal than flat ones. Activity is the
  local standard deviation at the chip scale, followed by a local *minimum* (grey
  erosion). A pixel next to an isolated edge (text, UI borders, object outlines) sees
  the flat side within the window and gets low gain, so the pattern forms less of a
  halo around edges; genuinely textured areas keep high gain. The map is then rescaled
  to the energy of the plain texture mask: measured on the tuning set this kept
  robustness unchanged and raised SSIM (0.973 -> 0.977 median); without rescaling it
  cost ~3 dB of signal and JPEG-50 payload recovery fell from 89% to 11%.
* **Headroom**: amplitude is reduced near black and white, where clipping would both
  waste energy and bias the signal.
"""

from __future__ import annotations

import cv2
import numpy as np

# Masking curve parameters (luminance units, 0..255).
FLAT_FLOOR = 0.30
MAX_GAIN = 1.8
ACTIVITY_REF = 10.0
EXTREME_RAMP = 20.0
EDGE_AWARE = True
RENORMALISE = True  # keep the total energy of the plain texture mask


def masking_map(y: np.ndarray, chip_px: float) -> np.ndarray:
    """Relative embedding gain (mean ~1 on typical content) for a luma plane."""
    y = y.astype(np.float32, copy=False)
    sigma = max(1.5, 1.5 * chip_px)
    mu = cv2.GaussianBlur(y, (0, 0), sigma)
    var = cv2.GaussianBlur(y * y, (0, 0), sigma) - mu * mu
    sd = np.sqrt(np.maximum(var, 0.0))
    plain = np.clip((sd + 0.15 * ACTIVITY_REF) / ACTIVITY_REF, FLAT_FLOOR, MAX_GAIN)
    gain = plain
    if EDGE_AWARE:
        k = 2 * int(round(2 * sigma)) + 1
        sd = cv2.erode(sd, cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (k, k)))
        gain = np.clip((sd + 0.15 * ACTIVITY_REF) / ACTIVITY_REF, FLAT_FLOOR, MAX_GAIN)
        if RENORMALISE:
            scale = np.sqrt(np.mean(plain**2) / max(float(np.mean(gain**2)), 1e-9))
            gain = np.minimum(gain * scale, MAX_GAIN * 1.5)
    # Smooth the map so it does not itself introduce visible edges.
    gain = cv2.GaussianBlur(gain, (0, 0), sigma)
    headroom = np.minimum(mu, 255.0 - mu)
    gain *= np.clip(headroom / EXTREME_RAMP, 0.15, 1.0)
    return gain
