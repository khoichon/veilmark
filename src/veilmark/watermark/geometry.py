"""Blind geometric synchronisation.

Two stages:

1. **Template search (incoherent, keyed).** Each pattern variant contains a few keyed
   sinusoids at tile harmonics. In the whitened magnitude spectrum of a (possibly
   cropped, scaled, rotated or mirrored) image they appear as strong lines at
   ``f = B^-T k`` where ``B`` is the image-space tile basis. Magnitudes ignore
   translation, so a dense search over period, angle and mirroring followed by a
   least-squares fit of the observed line positions recovers ``B`` without knowing
   the crop offset.
2. **Folding.** With ``B`` known, every pixel is mapped into canonical tile
   coordinates and averaged into one canonical P0 x P0 tile; the remaining cyclic
   offset is found by the coherent keyed sync correlation in
   :mod:`veilmark.watermark.engine`.
"""

from __future__ import annotations

from dataclasses import dataclass

import cv2
import numpy as np

from veilmark.watermark.pattern import NUM_VARIANTS, P0, TEMPLATE_RADII, KeyedPatterns, N

MIN_FFT = 1536  # spectra of smaller crops are zero-padded to this size
MAX_ANALYSIS = 2048  # analysis window for spectral geometry estimation (px)
CLIP = 12.0  # cap on whitened spectral power (limits strong periodic host textures)
PERIOD_RANGE = (64.0, 1000.0)  # searchable image-space tile periods (px)
PERIOD_STEP = 0.003  # relative step of the coarse period grid
LOG_CAP = float(np.log(8.0))  # per-line cap on log whitened power
COARSE_KEEP = 40  # coarse hypotheses kept per (variant, mirror)
FINE_KEEP = 320  # hypotheses refined on the full-resolution spectrum
POOL = 3  # max-pool window (bins) tolerating coarse-grid quantisation


@dataclass(frozen=True)
class Lattice:
    """Columns of ``basis`` are the image-space vectors (x, y) of one tile period."""

    basis: np.ndarray  # (2, 2) float64
    score: float
    source: str
    variant: int | None = None
    key_index: int | None = None

    @property
    def period(self) -> float:
        return float(np.sqrt(abs(np.linalg.det(self.basis))))

    def describe(self) -> dict[str, float | str]:
        b = self.basis
        sx, sy = float(np.hypot(*b[:, 0])), float(np.hypot(*b[:, 1]))
        return {
            "source": self.source,
            "period_x": round(sx, 2),
            "period_y": round(sy, 2),
            "rotation_deg": round(float(np.degrees(np.arctan2(b[1, 0], b[0, 0]))), 2),
            "mirrored": "yes" if np.linalg.det(b) < 0 else "no",
        }


def center_crop(a: np.ndarray, size: int) -> np.ndarray:
    h, w = a.shape[:2]
    ch, cw = min(h, size), min(w, size)
    y0, x0 = (h - ch) // 2, (w - cw) // 2
    return a[y0 : y0 + ch, x0 : x0 + cw]


def _tukey(n: int, alpha: float = 0.25) -> np.ndarray:
    """Tapered-cosine window: suppresses edge leakage but keeps most processing gain."""
    w = np.ones(n)
    m = int(alpha * n / 2)
    if m > 0:
        ramp = 0.5 * (1 - np.cos(np.pi * np.arange(m) / m))
        w[:m] = ramp
        w[-m:] = ramp[::-1]
    return w


def whitened_power(y: np.ndarray) -> np.ndarray:
    """Whitened, clipped power spectrum of a luma crop (fftshifted layout).

    The spectrum is divided by its smoothed envelope so that natural-image 1/f
    falloff disappears and narrow lines stand out. Codec block-grid frequencies
    (multiples of 1/16 cycles/px on either axis) and very low frequencies are
    neutralised so JPEG/H.264 blocking cannot masquerade as template lines.
    """
    y = y.astype(np.float32)
    y = y - cv2.GaussianBlur(y, (0, 0), 24.0)
    sd = float(y.std()) + 1e-6
    y = np.clip(y, -3 * sd, 3 * sd)
    h, w = y.shape
    y = y * np.outer(_tukey(h), _tukey(w)).astype(np.float32)
    # Zero-pad small crops: finer spectral sampling keeps line positions precise.
    H, W = max(h, MIN_FFT), max(w, MIN_FFT)
    F = np.fft.fftshift(np.fft.fft2(y, s=(H, W)))
    pw = (F.real**2 + F.imag**2).astype(np.float32)
    env = cv2.GaussianBlur(pw, (0, 0), 4.0 * max(H / h, W / w))
    z = pw / (env + 1e-6 * float(env.mean()) + 1e-12)
    fy = np.abs(np.fft.fftshift(np.fft.fftfreq(H)))
    fx = np.abs(np.fft.fftshift(np.fft.fftfreq(W)))
    for k in range(1, 9):
        f = k / 16.0
        z[np.abs(fy - f) < 1.5 / h, :] = 1.0
        z[:, np.abs(fx - f) < 1.5 / w] = 1.0
    r = np.hypot(fy[:, None], fx[None, :])
    z[r < 1.0 / (2 * N)] = 1.0
    np.clip(z, 0.0, CLIP, out=z)
    return z


def _rot(theta: np.ndarray | float) -> np.ndarray:
    c, s = np.cos(theta), np.sin(theta)
    return np.array([[c, -s], [s, c]])


JOINT = -1  # pseudo-variant: the union of every variant's template lines


def _harmonics_xy(pats: KeyedPatterns, v: int, mirror: bool) -> np.ndarray:
    """Template harmonics as (kx, ky) columns, optionally mirrored in y.

    ``v == JOINT`` returns the lines of all variants (used for video, where frames
    carry different variants but share one geometry).
    """
    if v == JOINT:
        k = np.concatenate([_harmonics_xy(pats, u, False) for u in range(NUM_VARIANTS)], axis=1)
        return k * np.array([[1.0], [-1.0]]) if mirror else k
    k = pats.variant(v).template_k[:, ::-1].T.astype(np.float64)  # (2, J): kx, ky
    if mirror:
        k = k * np.array([[1.0], [-1.0]])
    return k


def _line_scores(zp: np.ndarray, k: np.ndarray, angles: np.ndarray, periods: np.ndarray) -> np.ndarray:
    """Score array (len(angles), len(periods)) for harmonics ``k`` (2, J).

    Each line contributes ``clip(log z, 0, LOG_CAP)``: unit-mean noise bins add
    little, and a single very strong host line cannot dominate the sum.
    """
    h, w = zp.shape
    c, s = np.cos(angles)[:, None], np.sin(angles)[:, None]
    fx = c * k[0][None, :] - s * k[1][None, :]  # (A, J) cycles per tile
    fy = s * k[0][None, :] + c * k[1][None, :]
    inv_p = (1.0 / periods)[None, None, :]
    col = np.rint(fx[:, :, None] * inv_p * w + w // 2).astype(np.int64)
    row = np.rint(fy[:, :, None] * inv_p * h + h // 2).astype(np.int64)
    ok = (col >= 0) & (col < w) & (row >= 0) & (row < h)
    vals = np.where(ok, zp.ravel()[np.where(ok, row * w + col, 0)], 1.0)
    return np.clip(np.log(np.maximum(vals, 1e-6)), 0.0, LOG_CAP).sum(axis=1)


def _maxpool2(z: np.ndarray) -> np.ndarray:
    h, w = (z.shape[0] // 2) * 2, (z.shape[1] // 2) * 2
    return z[:h, :w].reshape(h // 2, 2, w // 2, 2).max(axis=(1, 3))


def template_search(
    z: np.ndarray, pats: KeyedPatterns, max_candidates: int = 6, joint: bool = False
) -> list[Lattice]:
    """Coarse-to-fine (period, angle, mirror, variant) search over template lines.

    Returns lattice hypotheses (best first) with ``score`` = summed clipped
    log-power at the predicted line positions; verification is left to the
    coherent sync search.
    """
    _h, _w = z.shape
    fine = cv2.dilate(z, np.ones((POOL, POOL), np.uint8))
    coarse_z = cv2.dilate(_maxpool2(z), np.ones((POOL, POOL), np.uint8))
    ch, cw = coarse_z.shape
    lo, hi = np.log(PERIOD_RANGE[0]), np.log(PERIOD_RANGE[1])
    c_step = 2 * PERIOD_STEP
    periods = np.exp(np.arange(lo, hi, c_step))
    rmax = TEMPLATE_RADII[1] / PERIOD_RANGE[0] * max(ch, cw)
    n_ang = int(np.clip(np.ceil(np.pi * rmax), 180, 1200))
    a_step = np.pi / n_ang
    angles = np.arange(n_ang) * a_step

    coarse: list[tuple[float, int, bool, float, float]] = []
    groups = [JOINT] if joint else list(range(NUM_VARIANTS))
    for v in groups:
        for mirror in (False, True):
            k = _harmonics_xy(pats, v, mirror)
            sc = _line_scores(coarse_z, k, angles, periods).astype(np.float32)
            # Non-maximum suppression so one peak does not occupy every slot.
            peak = sc >= cv2.dilate(sc, np.ones((5, 5), np.uint8))
            flat = np.flatnonzero(peak)
            for f in flat[np.argsort(sc.ravel()[flat])[::-1][:COARSE_KEEP]]:
                ai, pi = np.unravel_index(int(f), sc.shape)
                coarse.append((float(sc[ai, pi]), v, mirror, angles[ai], periods[pi]))
    coarse.sort(key=lambda r: -r[0])

    # Fine search in the neighbourhood of the best coarse hypotheses.
    refined: list[tuple[float, int, bool, float, float]] = []
    for _, v, mirror, ang, per in coarse[:FINE_KEEP]:
        k = _harmonics_xy(pats, v, mirror)
        loc_a = ang + np.linspace(-1.5, 1.5, 13) * a_step
        loc_p = per * np.exp(np.linspace(-1.5, 1.5, 13) * c_step)
        sc = _line_scores(fine, k, loc_a, loc_p)
        ai, pi = np.unravel_index(int(np.argmax(sc)), sc.shape)
        refined.append((float(sc[ai, pi]), v, mirror, float(loc_a[ai]), float(loc_p[pi])))
    refined.sort(key=lambda r: -r[0])

    out: list[Lattice] = []
    seen: list[tuple[int, np.ndarray]] = []
    for score, v, mirror, ang, per in refined:
        if len(out) >= max_candidates:
            break
        basis = per * _rot(ang) @ np.diag([1.0, -1.0 if mirror else 1.0])
        if any(sv == v and np.allclose(sb, basis, rtol=0.02, atol=2.0) for sv, sb in seen):
            continue
        seen.append((v, basis))
        variant = None if v == JOINT else v
        out.append(Lattice(refine_basis(z, pats, v, basis), score, "template", variant))
    return out


def refine_basis(z: np.ndarray, pats: KeyedPatterns, v: int, basis: np.ndarray) -> np.ndarray:
    """Least-squares affine fit of observed template line positions.

    With ``f = A k`` (``A = B^-T``) each line contributes two equations; eight lines
    over-determine the four unknowns, so mild aspect-ratio change and shear are
    recovered too.
    """
    h, w = z.shape
    mirror = np.linalg.det(basis) < 0
    k = _harmonics_xy(pats, v, bool(mirror))
    # Mirroring is folded into k, so fit the remaining proper part.
    m = np.diag([1.0, -1.0 if mirror else 1.0])
    A = np.linalg.inv(basis @ m).T
    obs, ks = [], []
    for j in range(k.shape[1]):
        f = A @ k[:, j]
        cx, cy = f[0] * w + w // 2, f[1] * h + h // 2
        xi, yi = int(round(cx)), int(round(cy))
        if not (3 <= xi < w - 3 and 3 <= yi < h - 3):
            continue
        win = z[yi - 2 : yi + 3, xi - 2 : xi + 3]
        oy, ox = np.unravel_index(int(np.argmax(win)), win.shape)
        yi, xi = yi - 2 + int(oy), xi - 2 + int(ox)
        c = z[yi, xi]
        if c < 3.0:  # line not clearly visible; do not let noise steer the fit
            continue

        def para(a: float, b: float, d: float) -> float:
            den = a - 2 * b + d
            return 0.0 if den >= 0 else float(np.clip(0.5 * (a - d) / den, -0.5, 0.5))

        sx = para(z[yi, xi - 1], c, z[yi, xi + 1])
        sy = para(z[yi - 1, xi], c, z[yi + 1, xi])
        obs.append([(xi + sx - w // 2) / w, (yi + sy - h // 2) / h])
        ks.append(k[:, j])
    if len(obs) < 4:
        return basis
    K = np.array(ks)  # (n, 2)
    F = np.array(obs)  # (n, 2)
    At, *_ = np.linalg.lstsq(K, F, rcond=None)  # F = K A^T
    A_new = At.T
    new = np.linalg.inv(A_new).T @ m
    # Reject wild fits (e.g. one mismatched line): stay near the coarse estimate.
    if np.max(np.abs(new - basis)) > 0.03 * abs(np.linalg.det(basis)) ** 0.5 + 1.0:
        return basis
    return new


def nominal_lattices(chip_sizes: tuple[int, ...] = (2, 3, 4, 5, 6)) -> list[Lattice]:
    """Unscaled lattice hypotheses (cheap fallback for unresampled media): every chip
    size combined with every keyed period-jitter level."""
    from veilmark.watermark.engine import PERIOD_JITTER

    out: list[Lattice] = []
    for c in chip_sizes:
        for j in PERIOD_JITTER:
            p = round(N * c * (1.0 + j))
            out.append(Lattice(np.eye(2) * p, 0.0, f"nominal:{c}{j:+.0%}" if j else f"nominal:{c}"))
    return out


def smooth(a: np.ndarray, sigma: float) -> np.ndarray:
    """Gaussian blur; wide kernels run on a decimated copy (same result for smooth
    low-pass estimates, at a fraction of the cost)."""
    if sigma <= 12.0:
        return cv2.GaussianBlur(a, (0, 0), sigma)
    f = int(sigma // 4)
    h, w = a.shape[:2]
    if h // f < 8 or w // f < 8:
        return cv2.GaussianBlur(a, (0, 0), sigma)
    small = cv2.resize(a, (w // f, h // f), interpolation=cv2.INTER_AREA)
    small = cv2.GaussianBlur(small, (0, 0), sigma / f)
    return cv2.resize(small, (w, h), interpolation=cv2.INTER_LINEAR)


def prepare_for_folding(y: np.ndarray, chip_px: float) -> np.ndarray:
    """High-pass and locally normalise luma so host content and contrast drop out."""
    y = y.astype(np.float32, copy=False)
    s = max(0.8, 0.9 * chip_px)
    hp = y - smooth(y, s)
    rms = np.sqrt(np.maximum(smooth(hp * hp, 4.0 * s), 0.0)) + 0.5
    out = hp / rms
    np.clip(out, -2.5, 2.5, out=out)
    return out


def fold(w: np.ndarray, basis: np.ndarray, origin: tuple[int, int] = (0, 0)) -> tuple[np.ndarray, int]:
    """Average a prepared plane into a canonical P0 x P0 tile.

    ``origin`` is the (y, x) position of ``w`` within the full plane, so sub-regions
    fold into the same canonical coordinates. Returns (tile, number of pixels).
    """
    h, wd = w.shape
    inv = np.linalg.inv(basis) * P0
    ys = np.arange(origin[0], origin[0] + h, dtype=np.float64)
    xs = np.arange(origin[1], origin[1] + wd, dtype=np.float64)
    u = (inv[0, 0] * xs)[None, :] + (inv[0, 1] * ys)[:, None]
    v = (inv[1, 0] * xs)[None, :] + (inv[1, 1] * ys)[:, None]
    # Nearest canonical sample (tile sample i sits at canonical coordinate i).
    iu = np.floor(u + 0.5).astype(np.int64) % P0
    iv = np.floor(v + 0.5).astype(np.int64) % P0
    idx = (iv * P0 + iu).ravel()
    tile = np.bincount(idx, weights=w.ravel().astype(np.float64), minlength=P0 * P0)
    count = np.bincount(idx, minlength=P0 * P0).astype(np.float64)
    # Average (not sum): with non-integer resampling ratios bins receive unequal
    # pixel counts, and summing would modulate (alias) the watermark spectrum.
    tile = np.where(count > 0, tile / np.maximum(count, 1.0), 0.0)
    return tile.reshape(P0, P0), h * wd
