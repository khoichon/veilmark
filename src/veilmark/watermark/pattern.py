"""Keyed, band-limited, periodic spread-spectrum tile patterns.

A watermark *tile* is an ``N x N`` grid of +-1 "chips". Each chip carries either the
synchronisation signal or one chip of a spread-spectrum coded payload bit. The chip
grid is converted to a smooth pixel pattern by spectral shaping (removing the lowest
spatial frequencies, which are both visible and swamped by image content) and exact
band-limited (Fourier) interpolation to the tile's pixel period. The tile repeats
periodically across the image; periodicity is what lets the detector recover scale,
rotation and crop offset blindly.

A small keyed *template* of sinusoids at tile harmonics is added on top. Its energy
is concentrated in a few spectral lines, so the detector can estimate scale,
rotation and mirroring from the image's magnitude spectrum before the (much more
sensitive, but geometry-dependent) coherent sync search.

Everything secret (sync chips, spreading signs, chip-to-bit assignment, per-variant
offset, template frequencies and phases) is derived from the pattern key with
domain-separated SHAKE-256.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass

import numpy as np

from veilmark.crypto import kdf

N = 64  # chips per tile side (protocol constant)
C0 = 2  # canonical pixels per chip used by the detector
P0 = N * C0  # canonical tile period in pixels
NUM_VARIANTS = 8  # independent keyed pattern families per key
R_LO = 10.0  # spectral low cut, in cycles per tile
CORE_FRACTION = 0.13  # share of data chips given to the robust core layer
SYNC_ENERGY = 0.15  # share of pattern energy spent on synchronisation
RING_WIDTH = 2.0  # radial bin width (cycles/tile) for channel estimation
TEMPLATE_ENERGY = 0.20  # share of pattern energy in the geometric template
TEMPLATE_LINES = 10  # sinusoids per variant
TEMPLATE_RADII = (10.0, 24.0)  # template harmonic radius range (cycles/tile)


@functools.cache
def spectral_mask() -> np.ndarray:
    """Real, symmetric N x N frequency mask (unshifted FFT layout)."""
    f = np.fft.fftfreq(N) * N
    fy, fx = np.meshgrid(f, f, indexing="ij")
    r = np.hypot(fx, fy)
    # Smooth ramp from R_LO/2 to R_LO, cut Nyquist row/column to keep upsampling exact.
    mask = np.clip((r - R_LO / 2) / (R_LO / 2), 0.0, 1.0)
    nyq = np.abs(f) == N // 2
    mask[nyq, :] = 0.0
    mask[:, nyq] = 0.0
    return mask


def render_tile(chips: np.ndarray, period: int) -> np.ndarray:
    """Band-limited interpolation of an N x N chip grid to a period x period tile."""
    if period < N:
        raise ValueError("tile period must be at least N pixels")
    spec = np.fft.fft2(chips) * spectral_mask()
    big = np.zeros((period, period), dtype=np.complex128)
    h = N // 2
    # Copy the four low-frequency quadrants (Nyquist already zeroed).
    big[:h, :h] = spec[:h, :h]
    big[:h, -h:] = spec[:h, -h:]
    big[-h:, :h] = spec[-h:, :h]
    big[-h:, -h:] = spec[-h:, -h:]
    tile = np.fft.ifft2(big).real * (period * period) / (N * N)
    return tile.astype(np.float32)


def chip_spectrum(tile_spectrum: np.ndarray) -> np.ndarray:
    """N x N chip-domain spectrum from the FFT of an aligned P0 x P0 tile.

    This is the adjoint of the band-limited interpolation in :func:`render_tile`.
    """
    h = N // 2
    small = np.empty((N, N), dtype=np.complex128)
    small[:h, :h] = tile_spectrum[:h, :h]
    small[:h, -h:] = tile_spectrum[:h, -h:]
    small[-h:, :h] = tile_spectrum[-h:, :h]
    small[-h:, -h:] = tile_spectrum[-h:, -h:]
    return small


@functools.cache
def _rings() -> tuple[np.ndarray, int]:
    f = np.fft.fftfreq(N) * N
    r = np.hypot(*np.meshgrid(f, f, indexing="ij"))
    ring = np.minimum((r / RING_WIDTH).astype(np.int64), int(N / 2 / RING_WIDTH))
    return ring, int(ring.max()) + 1


@dataclass(frozen=True)
class Variant:
    index: int
    sync_chips: np.ndarray  # (N, N) +-1
    spread: np.ndarray  # (N*N,) +-1 spreading signs
    order: np.ndarray  # (N*N,) keyed chip permutation
    offset: tuple[int, int]  # (dy, dx) cyclic tile offset, in chips
    template_k: np.ndarray  # (TEMPLATE_LINES, 2) integer harmonics (ky, kx)
    template_phase: np.ndarray  # (TEMPLATE_LINES,) radians


def _template_harmonics(key: bytes, v: int) -> tuple[np.ndarray, np.ndarray]:
    raw = kdf.random_uint64(key, "tile.template", v, n=512).astype(np.float64) / 2.0**64
    ks: list[tuple[int, int]] = []
    i = 0
    while len(ks) < TEMPLATE_LINES:
        r = TEMPLATE_RADII[0] + raw[i] * (TEMPLATE_RADII[1] - TEMPLATE_RADII[0])
        a = raw[i + 1] * np.pi
        i += 2
        ky, kx = int(round(r * np.sin(a))), int(round(r * np.cos(a)))
        ang = np.degrees(np.arctan2(ky, kx)) % 90.0
        if min(ang, 90.0 - ang) < 12.0:  # keep clear of codec block-grid axes
            continue
        if any(abs(ky - y) + abs(kx - x) < 3 or abs(ky + y) + abs(kx + x) < 3 for y, x in ks):
            continue
        ks.append((ky, kx))
    phase = raw[i : i + TEMPLATE_LINES] * 2 * np.pi
    return np.array(ks, dtype=np.int64), phase


def render_template(k: np.ndarray, phase: np.ndarray, period: int) -> np.ndarray:
    """Unit-RMS sum of the template sinusoids sampled on a period x period tile."""
    yy, xx = np.mgrid[0:period, 0:period].astype(np.float64) / period
    t = np.zeros((period, period))
    for (ky, kx), ph in zip(k, phase, strict=True):
        t += np.cos(2 * np.pi * (ky * yy + kx * xx) + ph)
    return t / np.sqrt(np.mean(t**2))


class KeyedPatterns:
    """All key-derived pattern material for one pattern key (cached)."""

    def __init__(self, pattern_key: bytes) -> None:
        if len(pattern_key) != 32:
            raise ValueError("pattern key must be 32 bytes")
        self._key = pattern_key
        self._variants: dict[int, Variant] = {}
        self._maps: dict[tuple[int, int, int], np.ndarray] = {}
        self._sync_fft: dict[int, np.ndarray] = {}
        self._sync_spec: dict[int, np.ndarray] = {}
        self._notch: dict[int, np.ndarray] = {}

    def variant(self, v: int) -> Variant:
        if not 0 <= v < NUM_VARIANTS:
            raise ValueError("variant out of range")
        if v not in self._variants:
            k = self._key
            sync = kdf.random_signs(k, "tile.sync", v, n=N * N).reshape(N, N)
            spread = kdf.random_signs(k, "tile.spread", v, n=N * N)
            order = kdf.permutation(k, "tile.order", v, n=N * N)
            off = kdf.random_ints(k, "tile.offset", v, n=2, high=N)
            tk, tph = _template_harmonics(k, v)
            self._variants[v] = Variant(v, sync, spread, order, (int(off[0]), int(off[1])), tk, tph)
        return self._variants[v]

    def chip_map(self, v: int, n_core: int, n_full: int) -> np.ndarray:
        """Coded-bit index carried by each chip (flattened N*N)."""
        key = (v, n_core, n_full)
        if key not in self._maps:
            n_chips = N * N
            n_core_chips = int(round(CORE_FRACTION * n_chips))
            assign = np.empty(n_chips, dtype=np.int64)
            assign[:n_core_chips] = np.arange(n_core_chips) % n_core
            assign[n_core_chips:] = n_core + np.arange(n_chips - n_core_chips) % n_full
            cmap = np.empty(n_chips, dtype=np.int64)
            cmap[self.variant(v).order] = assign
            self._maps[key] = cmap
        return self._maps[key]

    def data_chips(self, v: int, coded_core: np.ndarray, coded_full: np.ndarray) -> np.ndarray:
        """+-1 data chip grid for coded bits (0/1 arrays)."""
        bits = np.concatenate([coded_core, coded_full]).astype(np.float32)
        symbols = 1.0 - 2.0 * bits
        cmap = self.chip_map(v, len(coded_core), len(coded_full))
        return (symbols[cmap] * self.variant(v).spread).reshape(N, N)

    def tile(self, v: int, coded_core: np.ndarray, coded_full: np.ndarray, period: int) -> np.ndarray:
        """Unit-RMS pixel tile of the given period for variant ``v``."""
        var = self.variant(v)
        data = self.data_chips(v, coded_core, coded_full)
        chips = np.sqrt(SYNC_ENERGY) * var.sync_chips + np.sqrt(1 - SYNC_ENERGY) * data
        chips = np.roll(chips, var.offset, axis=(0, 1))
        t = render_tile(chips, period).astype(np.float64)
        t /= np.sqrt(np.mean(t**2))
        t = np.sqrt(1 - TEMPLATE_ENERGY) * t + np.sqrt(TEMPLATE_ENERGY) * render_template(
            var.template_k, var.template_phase, period
        )
        return (t / np.sqrt(np.mean(t**2))).astype(np.float32)

    def template_notch(self, v: int) -> np.ndarray:
        """Chip-spectrum mask that removes the template lines (they are not data)."""
        if v not in self._notch:
            m = np.ones((N, N))
            for ky, kx in self.variant(v).template_k:
                m[ky % N, kx % N] = 0.0
                m[-ky % N, -kx % N] = 0.0
            self._notch[v] = m
        return self._notch[v]

    def sync_template_fft(self, v: int) -> np.ndarray:
        """Conjugate rFFT of the canonical (P0) sync template including the offset."""
        if v not in self._sync_fft:
            var = self.variant(v)
            chips = np.roll(var.sync_chips, var.offset, axis=(0, 1))
            t = render_tile(chips, P0).astype(np.float64)
            t /= np.sqrt(np.sum(t**2))
            self._sync_fft[v] = np.conj(np.fft.rfft2(t))
        return self._sync_fft[v]

    def sync_spectrum(self, v: int) -> np.ndarray:
        """Transmitted (rolled, band-limited) sync chip spectrum."""
        if v not in self._sync_spec:
            var = self.variant(v)
            sync = np.roll(var.sync_chips, var.offset, axis=(0, 1))
            self._sync_spec[v] = np.fft.fft2(sync) * spectral_mask()
        return self._sync_spec[v]

    def soft_bits(self, v: int, spectrum: np.ndarray, n_core: int, n_full: int) -> tuple[np.ndarray, float]:
        """Per-coded-bit soft values from an aligned tile's chip spectrum.

        The known sync component doubles as a pilot: per radial frequency ring we
        estimate the channel gain ``g`` (blur, compression, detector filtering) and
        the residual noise power ``n``, cancel the sync, and apply the
        maximum-ratio weight ``g / n`` before despreading. Soft values are therefore
        SNR-scaled and can be summed directly across observations.

        Returns (soft values, pilot SNR estimate).
        """
        var = self.variant(v)
        S = self.sync_spectrum(v)
        ring, n_rings = _rings()
        mask = spectral_mask() * self.template_notch(v)
        keep = mask > 0
        cross = np.bincount(ring.ravel(), ((spectrum * np.conj(S)).real * keep).ravel(), n_rings)
        energy = np.bincount(ring.ravel(), (np.abs(S) ** 2 * keep).ravel(), n_rings)
        g = np.where(energy > 0, cross / np.maximum(energy, 1e-12), 0.0)
        resid = spectrum - g[ring] * S
        count = np.bincount(ring.ravel(), keep.ravel().astype(float), n_rings)
        noise = np.bincount(ring.ravel(), (np.abs(resid) ** 2 * keep).ravel(), n_rings)
        noise = np.where(count > 0, noise / np.maximum(count, 1), np.inf)
        weight = np.where(np.isfinite(noise) & (noise > 0), g / noise, 0.0)
        y = np.fft.ifft2(resid * mask * weight[ring]).real
        chips = np.roll(y, (-var.offset[0], -var.offset[1]), axis=(0, 1)).reshape(-1)
        cmap = self.chip_map(v, n_core, n_full)
        soft = np.bincount(cmap, weights=chips * var.spread, minlength=n_core + n_full)
        valid = np.isfinite(noise) & (noise > 0)
        pilot_snr = float(np.sum(g[valid] ** 2 * energy[valid] / noise[valid]))
        return soft, pilot_snr
