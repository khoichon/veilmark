"""Tiled spread-spectrum (TSS) embedding and blind detection on luminance planes.

This module is media-agnostic: image and video front-ends hand it 2-D luma arrays
(float or uint8, 0..255) and receive luma deltas or detection evidence back.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from dataclasses import dataclass, field

import numpy as np

from veilmark.watermark import framing, geometry, perceptual
from veilmark.watermark.pattern import NUM_VARIANTS, P0, KeyedPatterns, N, chip_spectrum

# Embedding amplitude for strength 1.0, in luma levels (RMS before masking).
BASE_AMPLITUDE = 2.6
MIN_CHIP_PX, MAX_CHIP_PX = 2, 6

# Detection thresholds on the sync peak z-score. Calibrated against unwatermarked
# media (see docs/benchmarking.md); payload acceptance additionally requires CRCs.
SYNC_PRESENT_Z = 7.5  # "watermark signal present" without a decodable payload
SYNC_DECODE_Z = 5.0  # minimum sync evidence before payload decoding is attempted
# Accepting an id from the core layer alone (CRC-16) additionally requires stronger
# sync and re-encoding agreement. Under noise, agreement averages 0.76 (99th pct
# 0.82) and P(sync z >= 6) is ~10%, so a false id needs all three: ~1e-6 per image.
SYNC_ID_Z = 6.0
CORE_MIN_AGREEMENT = 0.80


def choose_chip_px(height: int, width: int) -> int:
    """Chip size scaled with resolution (480p -> 2, 720p -> 3, 1080p -> 4, >=1440p -> 6).

    Larger chips survive downscaling and lossy compression better (measured: a 720p
    video downscaled to 480p at CRF 28 left 9.6% raw bit errors with 2-px chips vs
    0.4% with 3-px chips) at the cost of a coarser, slightly more visible pattern.
    """
    c = int(round(min(height, width) / 260.0))
    return max(MIN_CHIP_PX, min(MAX_CHIP_PX, c))


ProgressFn = Callable[[float, str], None]


def _no_progress(_f: float, _m: str) -> None:
    return None


# --------------------------------------------------------------------------- embed


@dataclass
class EmbedPlan:
    """Everything needed to watermark planes of one geometry with one payload."""

    patterns: KeyedPatterns
    frame: framing.CodedFrame
    height: int
    width: int
    chip_px: int
    amplitude: float
    origin: tuple[int, int] = (0, 0)
    period: int = 0  # tile period in pixels (N * chip_px * (1 + jitter))
    _planes: dict[int, np.ndarray] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if not self.period:
            self.period = N * self.chip_px

    def plane(self, variant: int) -> np.ndarray:
        """Unit-RMS full-size pattern plane for a variant (cached, float32)."""
        if variant not in self._planes:
            if len(self._planes) >= 3:  # bounded cache (video crossfades need 2)
                self._planes.pop(next(iter(self._planes)))
            tile = self.patterns.tile(variant, self.frame.coded_core, self.frame.coded_full, self.period)
            oy, ox = self.origin
            tile = np.roll(tile, (oy, ox), axis=(0, 1))
            reps_y = -(-self.height // self.period)
            reps_x = -(-self.width // self.period)
            full = np.tile(tile, (reps_y, reps_x))[: self.height, : self.width]
            self._planes[variant] = np.ascontiguousarray(full)
        return self._planes[variant]

    def delta(
        self,
        luma: np.ndarray,
        weights: dict[int, float],
        gain: np.ndarray | None = None,
    ) -> np.ndarray:
        """Luma delta for a mix of variants (weights should be energy-normalised)."""
        if gain is None:
            gain = perceptual.masking_map(luma, self.chip_px)
        sig = np.zeros((self.height, self.width), dtype=np.float32)
        for v, w in weights.items():
            if w:
                sig += np.float32(w) * self.plane(v)
        return (np.float32(self.amplitude) * gain * sig).astype(np.float32)


# Keyed tile-period diversity. Two watermarks with the same tile period fold onto each
# other coherently and garble each other (measured: both payloads lost). With periods
# a few percent apart, each folds incoherently into the other's tile and behaves like
# ordinary noise (measured: both payloads recovered). Each watermark picks one level
# from its id; re-watermarking deliberately picks a level away from existing marks.
PERIOD_JITTER = (0.0, -0.08, -0.04, 0.04, 0.08)
MIN_PERIOD_SEPARATION = 0.035


def period_for(chip_px: int, level: int) -> int:
    return int(round(N * chip_px * (1.0 + PERIOD_JITTER[level])))


def choose_period_level(watermark_id: bytes, chip_px: int, avoid: list[float] | None = None) -> int:
    """Jitter level from the watermark id, skipping levels too close to ``avoid``."""
    start = watermark_id[3] % len(PERIOD_JITTER)
    order = [(start + i) % len(PERIOD_JITTER) for i in range(len(PERIOD_JITTER))]
    if avoid:
        for lvl in order:
            p = period_for(chip_px, lvl)
            if all(abs(p - a) / a >= MIN_PERIOD_SEPARATION for a in avoid):
                return lvl
        raise ValueError(
            "cannot choose a tile period far enough from the existing watermark(s); "
            "use the unwatermarked original"
        )
    return start


def make_plan(
    patterns: KeyedPatterns,
    watermark_id: bytes,
    payload: bytes,
    height: int,
    width: int,
    strength: float = 1.0,
    chip_px: int | None = None,
    origin: tuple[int, int] | None = None,
    avoid_periods: list[float] | None = None,
) -> EmbedPlan:
    """Plan an embedding. ``avoid_periods``: tile periods (px) of watermarks already in
    the media; the new one keeps its period at least 3.5% away so both survive."""
    if not 0.1 <= strength <= 4.0:
        raise ValueError("strength must be within 0.1..4.0")
    c = chip_px or choose_chip_px(height, width)
    if not MIN_CHIP_PX <= c <= 12:
        raise ValueError("chip size out of range")
    period = period_for(c, choose_period_level(watermark_id, c, avoid_periods))
    if origin is None:
        # Per-watermark tile origin: derived from the watermark id (not secret).
        origin = (watermark_id[0] * period // 256, watermark_id[1] * period // 256)
    return EmbedPlan(
        patterns,
        framing.encode(watermark_id, payload),
        height,
        width,
        c,
        BASE_AMPLITUDE * strength,
        origin,
        period,
    )


def variant_for_id(watermark_id: bytes) -> int:
    return watermark_id[2] % NUM_VARIANTS


# -------------------------------------------------------------------------- detect

_DIHEDRAL = [(k, f) for f in (False, True) for k in range(4)]


# Coordinate matrices D with (u, v)_original = D (u, v)_transformed; folding with
# basis ``B @ D`` yields ``dihedral(fold(B), d)`` directly.
_DIHEDRAL_MATRIX = [
    ((1, 0), (0, 1)),
    ((0, -1), (1, 0)),
    ((-1, 0), (0, -1)),
    ((0, 1), (-1, 0)),
    ((0, 1), (1, 0)),
    ((1, 0), (0, -1)),
    ((0, -1), (-1, 0)),
    ((-1, 0), (0, 1)),
]


def canonical_basis(basis: np.ndarray, d: int) -> np.ndarray:
    return basis @ np.array(_DIHEDRAL_MATRIX[d], dtype=np.float64)


def dihedral(a: np.ndarray, d: int) -> np.ndarray:
    k, flip = _DIHEDRAL[d]
    if flip:
        a = a.T
    return np.rot90(a, k)


@dataclass(frozen=True)
class SyncHit:
    z: float
    key_index: int
    variant: int
    dihedral: int
    shift: tuple[int, int]
    sign: float
    frac: tuple[float, float] = (0.0, 0.0)  # sub-sample refinement of ``shift``


def _parabolic(m1: float, c: float, p1: float) -> float:
    d = m1 - 2.0 * c + p1
    if d == 0:
        return 0.0
    return float(np.clip(0.5 * (m1 - p1) / d, -0.5, 0.5))


def refine_peak(surface: np.ndarray, py: int, px: int, sign: float) -> tuple[float, float]:
    s = sign * surface
    h, w = s.shape
    fy = _parabolic(s[(py - 1) % h, px], s[py, px], s[(py + 1) % h, px])
    fx = _parabolic(s[py, (px - 1) % w], s[py, px], s[py, (px + 1) % w])
    return fy, fx


def normalise_tile(tile: np.ndarray) -> np.ndarray:
    t = tile - tile.mean()
    s = float(np.sqrt(np.mean(t**2)))
    return t / s if s > 0 else t


def sync_surfaces(
    tile: np.ndarray, patterns: KeyedPatterns, d: int, variants: list[int] | None = None
) -> np.ndarray:
    """z-normalised circular correlation of a tile with variant sync templates.

    Returns array (len(variants), P0, P0). Tiles must be unit-RMS normalised.
    """
    vs = list(range(NUM_VARIANTS)) if variants is None else variants
    F = np.fft.rfft2(dihedral(tile, d))
    out = np.empty((len(vs), P0, P0), dtype=np.float32)
    for i, v in enumerate(vs):
        out[i] = np.fft.irfft2(F * patterns.sync_template_fft(v), s=(P0, P0))
    out -= out.mean(axis=(1, 2), keepdims=True)
    out /= out.std(axis=(1, 2), keepdims=True) + 1e-12
    return out


def search_sync(
    tile: np.ndarray,
    keyring: list[KeyedPatterns],
    key_indices: list[int] | None = None,
    variants: list[int] | None = None,
    dihedrals: list[int] | None = None,
) -> SyncHit | None:
    """Best sync peak over keys, dihedral transforms and variants."""
    best: SyncHit | None = None
    keys = key_indices if key_indices is not None else range(len(keyring))
    for ki in keys:
        pats = keyring[ki]
        for d in dihedrals if dihedrals is not None else range(len(_DIHEDRAL)):
            s = sync_surfaces(tile, pats, d, variants)
            flat = int(np.argmax(np.abs(s)))
            vi, py, px = np.unravel_index(flat, s.shape)
            val = float(s[vi, py, px])
            if best is None or abs(val) > best.z:
                sign = float(np.sign(val))
                frac = refine_peak(s[vi], int(py), int(px), sign)
                v = variants[vi] if variants is not None else int(vi)
                best = SyncHit(abs(val), ki, int(v), d, (int(py), int(px)), sign, frac)
    return best


def aligned_tile(tile: np.ndarray, hit: SyncHit) -> np.ndarray:
    a = dihedral(tile, hit.dihedral)
    return hit.sign * np.roll(a, (-hit.shift[0], -hit.shift[1]), axis=(0, 1))


def chips_from_aligned(a: np.ndarray, frac: tuple[float, float] = (0.0, 0.0)) -> np.ndarray:
    """Chip-domain spectrum of an aligned tile (input to ``soft_bits``).

    ``frac`` is the residual sub-sample shift, removed with a Fourier phase ramp.
    """
    F = np.fft.fft2(a)
    if frac != (0.0, 0.0):
        f = np.fft.fftfreq(P0)
        F = F * np.exp(2j * np.pi * (frac[0] * f[:, None] + frac[1] * f[None, :]))
    return chip_spectrum(F)


def hit_chips(tile: np.ndarray, hit: SyncHit) -> np.ndarray:
    return chips_from_aligned(aligned_tile(tile, hit), hit.frac)


@dataclass
class SoftEvidence:
    """Accumulated per-coded-bit soft values for every length class."""

    core: np.ndarray = field(default_factory=lambda: np.zeros(framing.N_CORE_CODED))
    full: dict[int, np.ndarray] = field(default_factory=dict)
    observations: int = 0

    pilot_snr: float = 0.0

    def add(self, pats: KeyedPatterns, variant: int, chips: np.ndarray, weight: float = 1.0) -> None:
        nc = framing.N_CORE_CODED
        for ci in range(len(framing.LENGTH_CLASSES)):
            nf = framing.full_coded_length(ci)
            soft, snr = pats.soft_bits(variant, chips, nc, nf)
            if ci == 0:
                self.pilot_snr += snr
            if ci == 0:
                self.core += weight * soft[:nc]
            self.full[ci] = self.full.get(ci, np.zeros(nf)) + weight * soft[nc:]
        self.observations += 1


@dataclass(frozen=True)
class DecodeOutcome:
    core: framing.CoreResult
    full: framing.FullResult | None
    class_index: int | None


def decode_evidence(ev: SoftEvidence) -> DecodeOutcome:
    core = framing.decode_core(ev.core)
    if core.ok and core.class_index is not None:
        full = framing.decode_full(ev.full[core.class_index], core.class_index)
        return DecodeOutcome(core, full, core.class_index)
    # Core failed: the full layer is self-checking (CRC-32), so try every class.
    best: framing.FullResult | None = None
    best_ci = None
    for ci, soft in ev.full.items():
        res = framing.decode_full(soft, ci)
        if res.ok:
            return DecodeOutcome(core, res, ci)
        if best is None or res.bit_agreement > best.bit_agreement:
            best, best_ci = res, ci
    return DecodeOutcome(core, best, best_ci)


@dataclass
class LumaCandidate:
    lattice: geometry.Lattice
    tile: np.ndarray  # normalised folded tile
    pixels: int
    hit: SyncHit | None


def lattice_candidates(
    luma: np.ndarray, keyring: list[KeyedPatterns], per_key: int = 16
) -> list[geometry.Lattice]:
    """Template-derived lattices (per key) followed by unscaled nominal fallbacks."""
    z = geometry.whitened_power(geometry.center_crop(luma, geometry.MAX_ANALYSIS))
    found: list[geometry.Lattice] = []
    for ki, pats in enumerate(keyring):
        for lat in geometry.template_search(z, pats, max_candidates=per_key):
            found.append(dataclasses.replace(lat, key_index=ki))
    return found + geometry.nominal_lattices()


def fold_luma(luma: np.ndarray, lattice: geometry.Lattice) -> tuple[np.ndarray, int]:
    chip_px = lattice.period / N
    prepared = geometry.prepare_for_folding(luma, chip_px)
    tile, n = geometry.fold(prepared, lattice.basis)
    return normalise_tile(tile), n


def _local_peak(surface: np.ndarray, center: tuple[int, int], radius: int) -> tuple[float, float, float]:
    """Sub-sample peak (dy, dx, z) of ``surface`` within ``radius`` of ``center``."""
    offs = np.arange(-radius, radius + 1)
    rows = (center[0] + offs) % P0
    cols = (center[1] + offs) % P0
    win = surface[np.ix_(rows, cols)]
    iy, ix = np.unravel_index(int(np.argmax(win)), win.shape)
    fy, fx = refine_peak(surface, int(rows[iy]), int(cols[ix]), 1.0)
    return offs[iy] + fy, offs[ix] + fx, float(win[iy, ix])


def _summed_surface(
    tiles: list[np.ndarray], pats: KeyedPatterns, variants: list[int], sign: float
) -> np.ndarray:
    """Sum over planes of the (max over variants) z-normalised sync surface."""
    acc = np.zeros((P0, P0))
    for t in tiles:
        s = (sign * sync_surfaces(t, pats, 0, variants)).max(axis=0)
        acc += (s - s.mean()) / (s.std() + 1e-12)
    return (acc - acc.mean()) / (acc.std() + 1e-12)


def refine_lattice(
    planes: np.ndarray | list[np.ndarray],
    lattice: geometry.Lattice,
    hit: SyncHit,
    keyring: list[KeyedPatterns],
    iterations: int = 2,
    variants: list[int] | None = None,
) -> tuple[geometry.Lattice, np.ndarray, SyncHit]:
    """Polish the lattice by measuring how the sync peak drifts across the image.

    A basis error makes canonical coordinates drift linearly with position, so the
    peak found in each sub-region moves by ``a + G c`` (``c`` = region centre).
    A weighted least-squares fit of ``G`` corrects ``B^-1``. Several planes (video
    frames sharing one geometry) may be given; their sync surfaces are summed, and
    ``variants`` (default: the hit's variant) are max-combined. Also folds the hit's
    dihedral transform into the basis so the returned hit has ``dihedral == 0``.

    Returns (lattice, folded tile of the first plane, hit).
    """
    plist = [planes] if isinstance(planes, np.ndarray) else list(planes)
    pats = keyring[hit.key_index]
    vs = [hit.variant] if variants is None else variants
    sign = hit.sign
    basis = canonical_basis(lattice.basis, hit.dihedral)
    chip_px = lattice.period / N
    prepared = [geometry.prepare_for_folding(p, chip_px) for p in plist]
    h, w = prepared[0].shape
    period = lattice.period

    def full_hit(b: np.ndarray) -> tuple[np.ndarray, SyncHit]:
        tiles = [normalise_tile(geometry.fold(p, b)[0]) for p in prepared]
        if len(tiles) == 1 and len(vs) == 1:
            found = search_sync(tiles[0], keyring, [hit.key_index], vs, [0])
            assert found is not None
            return tiles[0], found
        srf = _summed_surface(tiles, pats, vs, sign)
        py, px = np.unravel_index(int(np.argmax(srf)), srf.shape)
        frac = refine_peak(srf, int(py), int(px), 1.0)
        return tiles[0], SyncHit(
            float(srf[py, px]), hit.key_index, hit.variant, 0, (int(py), int(px)), sign, frac
        )

    tile, cur = full_hit(basis)
    for _ in range(iterations):
        g = 3 if min(h, w) >= 4.5 * period else 2
        if min(h, w) < 2.0 * period:
            break
        ys = np.linspace(0, h, g + 1).astype(int)
        xs = np.linspace(0, w, g + 1).astype(int)
        rows, targets, weights = [], [], []
        for i in range(g):
            for j in range(g):
                sub_tiles = [
                    normalise_tile(
                        geometry.fold(
                            p[ys[i] : ys[i + 1], xs[j] : xs[j + 1]], basis, (int(ys[i]), int(xs[j]))
                        )[0]
                    )
                    for p in prepared
                ]
                srf = _summed_surface(sub_tiles, pats, vs, sign)
                dy, dx, z = _local_peak(srf, cur.shift, 10)
                if z < 4.0:
                    continue
                cy, cx = (ys[i] + ys[i + 1]) / 2, (xs[j] + xs[j + 1]) / 2
                rows.append([1.0, cx, cy])
                targets.append([dx, dy])  # canonical (u, v) drift
                weights.append(z)
        if len(rows) < 3:
            break
        A = np.array(rows) * np.array(weights)[:, None]
        T = np.array(targets) * np.array(weights)[:, None]
        coef, *_ = np.linalg.lstsq(A, T, rcond=None)  # (3, 2)
        G = coef[1:].T  # (2, 2): d(u, v) / d(x, y)
        # Peak drift equals the canonical-coordinate error, so subtract it.
        new_basis = np.linalg.inv(np.linalg.inv(basis) - G / P0)
        new_tile, new_hit = full_hit(new_basis)
        if new_hit.z < cur.z:
            break
        basis, tile, cur = new_basis, new_tile, new_hit
    refined = dataclasses.replace(lattice, basis=basis, source=lattice.source + "+refined")
    return refined, tile, cur


def sync_for_lattice(
    tile: np.ndarray, lattice: geometry.Lattice, keyring: list[KeyedPatterns]
) -> SyncHit | None:
    """Sync search; template lattices already fix key, variant and orientation
    (up to the 180-degree ambiguity of a magnitude spectrum)."""
    if lattice.variant is not None and lattice.key_index is not None:
        return search_sync(tile, keyring, [lattice.key_index], [lattice.variant], [0, 2])
    return search_sync(tile, keyring)


def analyse_luma(
    luma: np.ndarray,
    keyring: list[KeyedPatterns],
    lattices: list[geometry.Lattice] | None = None,
    verify_size: int = 1024,
    progress: ProgressFn | None = None,
) -> list[LumaCandidate]:
    """Rank lattice hypotheses by keyed sync strength; best candidate first.

    Hypotheses are screened on a central crop (cheap); the best ones are re-folded
    over the whole plane so decoding uses every available pixel.
    """
    tick = progress or _no_progress
    if lattices is None:
        tick(0.02, "searching the spectrum for the watermark template")
        lattices = lattice_candidates(luma, keyring)
    crop = geometry.center_crop(luma, verify_size)
    screened = []
    for i, lat in enumerate(lattices):
        tick(0.15 + 0.6 * i / max(1, len(lattices)), f"testing geometry hypothesis {i + 1}/{len(lattices)}")
        tile, n = fold_luma(crop, lat)
        screened.append(LumaCandidate(lat, tile, n, sync_for_lattice(tile, lat, keyring)))
    screened.sort(key=lambda c: -(c.hit.z if c.hit else 0.0))
    out = []
    for j, cand in enumerate(screened[:2]):
        if cand.hit is None:
            continue
        tick(0.78 + 0.1 * j, "refining the best geometry")
        # Coarse-to-fine: polish on the screening crop (where the hit was found),
        # then on the whole plane, whose larger extent needs a more exact basis.
        lat, _, hit = refine_lattice(crop, cand.lattice, cand.hit, keyring)
        if crop.shape != luma.shape:
            tile, _ = fold_luma(luma, lat)
            full = search_sync(tile, keyring, [hit.key_index], [hit.variant], [0])
            if full is not None:
                lat, tile, hit = refine_lattice(luma, lat, full, keyring)
        else:
            tile, _ = fold_luma(luma, lat)
        out.append(LumaCandidate(lat, tile, luma.size, hit))
    out.sort(key=lambda c: -(c.hit.z if c.hit else 0.0))
    return out + screened[2:]


@dataclass
class LumaDetection:
    """Outcome of blind detection on one luma plane."""

    candidates: list[LumaCandidate]
    best: LumaCandidate | None
    outcome: DecodeOutcome | None
    evidence: SoftEvidence | None
    searched_positions: int
    # Further watermarks at clearly different tile periods (media marked more than once).
    additional: list[tuple[LumaCandidate, DecodeOutcome]] = field(default_factory=list)


def search_space(n_lattices: int, n_keys: int) -> int:
    """Approximate number of sync hypotheses tested (for false-alarm estimates)."""
    return max(1, n_lattices) * max(1, n_keys) * NUM_VARIANTS * len(_DIHEDRAL) * P0 * P0 * 2


def evidence_for(cand: LumaCandidate, keyring: list[KeyedPatterns]) -> SoftEvidence:
    assert cand.hit is not None
    ev = SoftEvidence()
    ev.add(keyring[cand.hit.key_index], cand.hit.variant, hit_chips(cand.tile, cand.hit))
    return ev


SCAN_CROP = 640  # central crop used by the coherent scale scan
SCAN_STEP = 0.007  # relative period step (fold coherence tolerance on SCAN_CROP)
SCAN_PERIODS = (64.0, 1000.0)


def scale_scan(
    luma: np.ndarray, keyring: list[KeyedPatterns], keep: int = 3, progress: ProgressFn | None = None
) -> list[geometry.Lattice]:
    """Coherent fallback geometry search: fold an unrotated central crop at every
    tile period on a fine log grid and run the full keyed sync search at each.

    Far more sensitive than the spectral template on content with strong periodic
    structure (e.g. pixel-art screenshots after crop + downscale), but covers only
    uniform scaling with rotations by multiples of 90 degrees and mirroring.
    """
    crop = geometry.center_crop(luma, SCAN_CROP)
    lo, hi = np.log(SCAN_PERIODS[0]), np.log(SCAN_PERIODS[1])
    periods = np.exp(np.arange(lo, hi, SCAN_STEP))
    prepared: dict[float, np.ndarray] = {}
    found: list[tuple[float, float]] = []
    tick = progress or _no_progress
    for k, per in enumerate(periods):
        if k % 8 == 0:
            tick(k / len(periods), f"thorough search: tile period {per:.0f} px")
        chip = round(per / N * 2) / 2
        if chip not in prepared:
            prepared.clear()
            prepared[chip] = geometry.prepare_for_folding(crop, chip)
        tile, _ = geometry.fold(prepared[chip], np.eye(2) * per)
        hit = search_sync(normalise_tile(tile), keyring)
        if hit is not None:
            found.append((hit.z, float(per)))
    found.sort(reverse=True)
    out: list[geometry.Lattice] = []
    for z, per in found:
        if any(abs(per - o.period) / o.period < 0.03 for o in out):
            continue
        out.append(geometry.Lattice(np.eye(2) * per, z, "scan"))
        if len(out) >= keep:
            break
    return out


def _decode_candidates(
    cands: list[LumaCandidate], keyring: list[KeyedPatterns], max_decode: int
) -> tuple[LumaCandidate | None, DecodeOutcome | None, SoftEvidence | None]:
    best_c: LumaCandidate | None = cands[0] if cands else None
    best_o: DecodeOutcome | None = None
    best_e: SoftEvidence | None = None
    best_rank = -1
    for cand in cands[:max_decode]:
        if cand.hit is None or cand.hit.z < SYNC_DECODE_Z:
            continue
        ev = evidence_for(cand, keyring)
        out = decode_evidence(ev)
        rank = 2 if (out.full and out.full.ok) else 1 if out.core.ok else 0
        if rank > best_rank:
            best_c, best_o, best_e, best_rank = cand, out, ev, rank
        if rank == 2:
            break
    return best_c, best_o, best_e


def detect_luma(
    luma: np.ndarray,
    keyring: list[KeyedPatterns],
    max_decode: int = 3,
    deep: bool = True,
    progress: ProgressFn | None = None,
) -> LumaDetection:
    """Blind detection: geometry search, sync, then decoding of the best candidates.

    If nothing is found and ``deep`` is set, the coherent :func:`scale_scan` is run as
    a fallback (a few seconds); its larger search space is included in
    ``searched_positions`` for the false-alarm estimate.
    """
    tick = progress or _no_progress
    cands = analyse_luma(luma, keyring, progress=lambda f, m: tick(0.5 * f, m))
    n_lat = len(cands)
    tick(0.5, "decoding the payload")
    best_c, best_o, best_e = _decode_candidates(cands, keyring, max_decode)
    found = best_o is not None and (best_o.core.ok or (best_o.full is not None and best_o.full.ok))
    strong = best_c is not None and best_c.hit is not None and best_c.hit.z >= SYNC_PRESENT_Z
    if deep and not found and not strong:
        scan = scale_scan(luma, keyring, progress=lambda f, m: tick(0.55 + 0.4 * f, m))
        n_lat += int(np.ceil((np.log(SCAN_PERIODS[1]) - np.log(SCAN_PERIODS[0])) / SCAN_STEP))
        if scan:
            more = analyse_luma(luma, keyring, scan, progress=lambda f, m: tick(0.95 + 0.04 * f, m))
            c2, o2, e2 = _decode_candidates(more, keyring, max_decode)
            if o2 is not None or (c2 and c2.hit and best_c and best_c.hit and c2.hit.z > best_c.hit.z):
                best_c, best_o, best_e = c2, o2, e2
                cands = more + cands
    det = LumaDetection(cands, best_c, best_o, best_e, search_space(n_lat, len(keyring)))
    if best_c is not None and best_o is not None and _accepted(best_c, best_o):
        tick(0.99, "checking for further watermarks")
        det.additional = find_additional(luma, keyring, det.candidates, best_c)
    return det


def _accepted(cand: LumaCandidate, out: DecodeOutcome) -> bool:
    if out.full is not None and out.full.ok:
        return True
    z = cand.hit.z if cand.hit else 0.0
    return out.core.ok and out.core.bit_agreement >= CORE_MIN_AGREEMENT and z >= SYNC_ID_Z


def find_additional(
    luma: np.ndarray,
    keyring: list[KeyedPatterns],
    cands: list[LumaCandidate],
    best: LumaCandidate,
    max_extra: int = 2,
) -> list[tuple[LumaCandidate, DecodeOutcome]]:
    """Decode other strong candidates whose tile period differs from those already
    found (a second watermark embedded with a different period). The same acceptance
    gates as the primary result apply, so noise cannot produce extra claims."""
    used = [best.lattice.period]
    out: list[tuple[LumaCandidate, DecodeOutcome]] = []
    for c in cands:
        if len(out) >= max_extra:
            break
        if c.hit is None or c.hit.z < SYNC_DECODE_Z:
            continue
        if any(abs(c.lattice.period - u) / u < MIN_PERIOD_SEPARATION * 0.7 for u in used):
            continue
        refined = analyse_luma(luma, keyring, [c.lattice])[0]
        if refined.hit is None or refined.hit.z < SYNC_DECODE_Z:
            continue
        dec = decode_evidence(evidence_for(refined, keyring))
        if _accepted(refined, dec):
            out.append((refined, dec))
            used.append(refined.lattice.period)
    return out
