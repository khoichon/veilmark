"""Blind video detection with temporal evidence accumulation.

Pipeline (bounded memory; nothing proportional to the decoded video is kept except
one 128x128 canonical tile per sampled frame, stored as float16):

1. **Geometry pass** on a sparse set of frames: whitened spectra are averaged so the
   template lines of all variants reinforce, then lattice hypotheses are verified by
   per-frame keyed sync and polished with region-drift refinement.
2. **Fold pass**: every sampled frame is folded into a canonical tile with a
   precomputed index map.
3. **Alignment**: sync correlation surfaces are maxed over variants and summed over
   a sliding temporal window (tracks moving crops) and over the whole clip (fixed
   crops); the stronger estimate gives each frame's crop offset.
4. **Variant identification**: each frame's variant (the moving distribution) is
   read from the sync templates at that offset, smoothed over neighbouring frames.
5. **Accumulation**: aligned chip spectra are summed per variant; soft bits from all
   variants are combined (maximum-ratio weighted) and decoded once.
"""

from __future__ import annotations

import itertools
import math
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import cv2
import numpy as np

from veilmark.core.tasks import Reporter
from veilmark.crypto import kdf
from veilmark.detection import report as report_mod
from veilmark.security.limits import InputError, check_input_file
from veilmark.video import ffmpeg
from veilmark.watermark import engine, geometry
from veilmark.watermark.pattern import NUM_VARIANTS, P0, KeyedPatterns, N

if TYPE_CHECKING:
    from veilmark.api import Veilmark

GEOMETRY_GROUPS = 8  # runs of consecutive frames sampled across the clip
GROUP_LEN = 4
WINDOW = 4  # +- frames summed (motion-compensated) per frame for moving crops
MAX_MOTION = 6  # max tracked crop motion per analysed frame, canonical samples
N_DECOYS = 3  # decoy keys used to calibrate the moving-crop statistic
DECOY_FLOOR = 4.5  # typical fixed-alignment null level; moving z = floor + excess over decoys
MIN_FRAMES_FOR_MEAN = 24
SWITCH_PENALTY = 8.0  # DP cost (in z units) of a variant change between frames
MIN_SEGMENT_Z = 3.0  # segments with less accumulated evidence are not used


@dataclass
class _GeometryResult:
    lattice: geometry.Lattice
    key_index: int
    score: float


def _surfaces(tile: np.ndarray, pats: KeyedPatterns) -> np.ndarray:
    return engine.sync_surfaces(tile, pats, 0)  # (V, P0, P0), z-normalised


def _geometry(
    frames: list[np.ndarray], keyring: list[KeyedPatterns], rep: Reporter
) -> _GeometryResult | None:
    z_sum: np.ndarray | None = None
    big = [geometry.center_crop(f.astype(np.float32), geometry.MAX_ANALYSIS) for f in frames]
    # Remove the static background (its spectral lines would compete with the
    # template); the watermark survives because its variant changes over time.
    mean_frame = np.mean(big, axis=0) if len(big) >= 8 else 0.0
    for b in big:
        z = geometry.whitened_power(b - mean_frame)
        z_sum = z if z_sum is None else z_sum + z
    del big
    assert z_sum is not None
    z_avg = z_sum / len(frames)
    # Averaging reduces noise variance; rescale so line statistics stay comparable.
    z_avg = 1.0 + (z_avg - 1.0) * math.sqrt(len(frames))
    np.clip(z_avg, 0.0, geometry.CLIP, out=z_avg)
    lattices: list[tuple[geometry.Lattice, int | None]] = []
    for ki, pats in enumerate(keyring):
        for lat in geometry.template_search(z_avg, pats, max_candidates=10, joint=True):
            lattices.append((lat, ki))
    lattices += [(lat, None) for lat in geometry.nominal_lattices()]
    rep(0.3, "verifying geometry hypotheses")
    crops = [geometry.center_crop(f.astype(np.float32), 1024) for f in frames]
    all_v = list(range(NUM_VARIANTS))

    groups = [list(range(i, min(i + GROUP_LEN, len(crops)))) for i in range(0, len(crops), GROUP_LEN)]
    prepared_cache: dict[float, list[np.ndarray]] = {}

    def score(lat: geometry.Lattice, keys: list[int]) -> tuple[float, int, int, float, int]:
        """Accumulated sync evidence: (z, key, dihedral, sign, best group).

        Frames within a group are consecutive, so they are summed coherently even
        under a moving crop; the score is the better of the whole-clip coherent sum
        (fixed crops) and the mean of the per-group peaks (moving crops).
        """
        chip_key = round(lat.period / N * 4) / 4
        if chip_key not in prepared_cache:
            prepared_cache.clear()  # keep memory bounded: one chip size at a time
            prepared_cache[chip_key] = [geometry.prepare_for_folding(c, chip_key) for c in crops]
        tiles = [engine.normalise_tile(geometry.fold(p, lat.basis)[0]) for p in prepared_cache[chip_key]]
        if len(tiles) >= 8:
            # Same static-host suppression as the main pass (see detect_video).
            mean_tile = np.mean(tiles, axis=0)
            tiles = [engine.normalise_tile(t - mean_tile) for t in tiles]
        best = (0.0, keys[0], 0, 1.0, 0)
        dset = [0, 2] if lat.source.startswith("template") else list(range(8))
        for ki in keys:
            for d in dset:
                # One FFT pass per frame; both signs and all groupings reuse it.
                raw = [engine.sync_surfaces(engine.dihedral(t, d), keyring[ki], 0) for t in tiles]
                for sign in (1.0, -1.0):
                    per = []
                    for r in raw:
                        m = (sign * r).max(axis=0)
                        per.append((m - m.mean()) / (m.std() + 1e-12))

                    def peak(idx: list[int], per: list[np.ndarray] = per) -> float:
                        a = np.sum([per[i] for i in idx], axis=0)
                        return float(((a - a.mean()) / (a.std() + 1e-12)).max())

                    z_all = peak(list(range(len(per))))
                    gz = [peak(g) for g in groups]
                    z = max(z_all, float(np.mean(gz)))
                    if z > best[0]:
                        best = (z, ki, d, sign, int(np.argmax(gz)))
        return best

    ranked = []
    # Group hypotheses by chip size so prepared frames are reused.
    for lat, kidx in sorted(lattices, key=lambda li: li[0].period):
        keys = [kidx] if kidx is not None else list(range(len(keyring)))
        ranked.append((score(lat, keys), lat))
    ranked.sort(key=lambda r: -r[0][0])
    (best_z, best_k, best_d, best_sign, g), lat = ranked[0]
    if best_z < engine.SYNC_DECODE_Z:
        return None
    hit = engine.SyncHit(best_z, best_k, 0, best_d, (0, 0), best_sign)
    # Polish the basis on the strongest group of consecutive frames.
    lat_r, _, _ = engine.refine_lattice(
        [crops[i] for i in groups[g]], lat, hit, keyring, iterations=2, variants=all_v
    )
    return _GeometryResult(lat_r, best_k, best_z)


@dataclass
class _Alignment:
    shifts: list[tuple[int, int, float, float]]
    stat: float  # sync evidence (global z, or median motion-compensated window z)
    moving: bool


def _align(tiles: list[np.ndarray], pats: KeyedPatterns, radius: int) -> _Alignment:
    """Per-frame crop offsets: one global offset (fixed crop) or a tracked path."""
    nf = len(tiles)
    maxsurf = np.empty((nf, P0, P0), dtype=np.float16)
    for i, t in enumerate(tiles):
        s = _surfaces(t.astype(np.float64), pats).max(axis=0)
        maxsurf[i] = (s - s.mean()) / (s.std() + 1e-9)
    glob = maxsurf.astype(np.float32).sum(axis=0)
    glob = (glob - glob.mean()) / (glob.std() + 1e-9)
    gy, gx = np.unravel_index(int(np.argmax(glob)), glob.shape)
    path = track_peak(maxsurf, radius)
    stationary = float(np.mean(np.all(np.abs(_wrap(path - np.array([gy, gx]))) <= 1, axis=1)))
    if stationary >= 0.8:
        fy, fx = engine.refine_peak(glob, int(gy), int(gx), 1.0)
        return _Alignment([(int(gy), int(gx), fy, fx)] * nf, float(glob[gy, gx]), False)
    shifts: list[tuple[int, int, float, float]] = []
    window_z: list[float] = []
    for i in range(nf):
        # Motion-compensated window: shift neighbours by the tracked path so their
        # peaks stack on frame i's offset.
        lo, hi = max(0, i - WINDOW), min(nf, i + WINDOW + 1)
        acc_s = np.zeros((P0, P0), np.float32)
        for j in range(lo, hi):
            d = path[i] - path[j]
            acc_s += np.roll(maxsurf[j].astype(np.float32), (int(d[0]), int(d[1])), axis=(0, 1))
        srf = (acc_s - acc_s.mean()) / (acc_s.std() + 1e-9)
        dy, dx, _ = engine._local_peak(srf, (int(path[i][0]), int(path[i][1])), 2)
        py, px = int(path[i][0] + round(dy)) % P0, int(path[i][1] + round(dx)) % P0
        window_z.append(float(srf[py, px]))
        fy, fx = engine.refine_peak(srf, py, px, 1.0)
        shifts.append((py, px, fy, fx))
    return _Alignment(shifts, float(np.median(window_z)), True)


def pats_key_bytes(pats: KeyedPatterns) -> bytes:
    return pats._key


def _wrap(d: np.ndarray) -> np.ndarray:
    """Cyclic difference on the canonical tile (range -P0/2 .. P0/2)."""
    return (d + P0 // 2) % P0 - P0 // 2


def track_peak(surfaces: np.ndarray, radius: int, move_cost: float = 1.0) -> np.ndarray:
    """Viterbi tracking of the sync peak through time (moving crops).

    Maximises ``sum_f M_f(p_f)`` over cyclic paths whose per-frame step is at most
    ``radius`` (steps beyond one sample cost ``move_cost``). The max over the motion
    neighbourhood is a grey-scale dilation, so each frame costs two dilations.
    Returns the (y, x) path, shape (nf, 2).
    """
    nf = surfaces.shape[0]
    k1 = np.ones((3, 3), np.uint8)
    kr = np.ones((2 * radius + 1, 2 * radius + 1), np.uint8)

    def dil(a: np.ndarray, k: np.ndarray, r: int) -> np.ndarray:
        padded = np.pad(a, r, mode="wrap")
        return cv2.dilate(padded, k)[r:-r, r:-r]

    scores = np.empty((nf, P0, P0), np.float32)
    scores[0] = surfaces[0]
    for f in range(1, nf):
        prev = scores[f - 1]
        best = np.maximum(dil(prev, k1, 1), dil(prev, kr, radius) - move_cost)
        best -= best.max()  # keep numbers bounded
        scores[f] = surfaces[f].astype(np.float32) + best
    path = np.empty((nf, 2), dtype=np.int64)
    path[-1] = np.unravel_index(int(np.argmax(scores[-1])), (P0, P0))
    offs = np.arange(-radius, radius + 1)
    oy, ox = np.meshgrid(offs, offs, indexing="ij")
    cost = np.where((np.abs(oy) <= 1) & (np.abs(ox) <= 1), 0.0, move_cost)
    for f in range(nf - 1, 0, -1):
        y, x = path[f]
        win = scores[f - 1][np.ix_((y + offs) % P0, (x + offs) % P0)] - cost
        iy, ix = np.unravel_index(int(np.argmax(win)), win.shape)
        path[f - 1] = ((y + offs[iy]) % P0, (x + offs[ix]) % P0)
    return path


def segment_variants(zv: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Most likely per-frame variant sequence given per-frame sync scores.

    Variants change only at (rare) segment boundaries, so a Viterbi pass maximising
    ``sum z[f, v_f] - SWITCH_PENALTY * #changes`` labels weak frames far more
    reliably than per-frame decisions. Returns (variant per frame, accumulated
    segment evidence z/sqrt(len) assigned to each frame of the segment).
    """
    nf, nv = zv.shape
    score = zv[0].copy()
    back = np.zeros((nf, nv), dtype=np.int64)
    for f in range(1, nf):
        stay = score
        best_prev = int(np.argmax(score))
        switch = score[best_prev] - SWITCH_PENALTY
        choose_switch = switch > stay
        back[f] = np.where(choose_switch, best_prev, np.arange(nv))
        score = np.where(choose_switch, switch, stay) + zv[f]
    path = np.empty(nf, dtype=np.int64)
    path[-1] = int(np.argmax(score))
    for f in range(nf - 1, 0, -1):
        path[f - 1] = back[f, path[f]]
    seg_z = np.zeros(nf)
    start = 0
    for f in range(1, nf + 1):
        if f == nf or path[f] != path[start]:
            vals = zv[start:f, path[start]]
            seg_z[start:f] = vals.sum() / math.sqrt(len(vals))
            start = f
    return path, seg_z


def _fold_index(h: int, w: int, basis: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    inv = np.linalg.inv(basis) * P0
    ys = np.arange(h, dtype=np.float64)
    xs = np.arange(w, dtype=np.float64)
    u = (inv[0, 0] * xs)[None, :] + (inv[0, 1] * ys)[:, None]
    v = (inv[1, 0] * xs)[None, :] + (inv[1, 1] * ys)[:, None]
    iu = np.floor(u + 0.5).astype(np.int64) % P0
    iv = np.floor(v + 0.5).astype(np.int64) % P0
    idx = (iv * P0 + iu).ravel().astype(np.int32)
    count = np.bincount(idx, minlength=P0 * P0).astype(np.float64)
    return idx, np.maximum(count, 1.0)


def detect_video(
    vm: Veilmark,
    path: Path,
    pattern_key: str | None = None,
    max_frames: int = 900,
    stride: int | None = None,
    reporter: Reporter | None = None,
) -> report_mod.DetectionReport:
    rep = reporter or Reporter()
    t0 = time.perf_counter()
    path = check_input_file(Path(path), vm.limits)
    info = ffmpeg.probe(path)
    # Stored keys first; public keys only if nothing was found (see Veilmark.keyring_tiers).
    tiers = vm.keyring_tiers(pattern_key)
    first: report_mod.DetectionReport | None = None
    searched = 0
    for i, (keyring, kids) in enumerate(tiers):
        sub = rep.sub(i / len(tiers), (i + 1) / len(tiers))
        r, n = _detect_video_with(vm, path, info, keyring, kids, max_frames, stride, sub, searched)
        searched += n
        if r.detected:
            break
        first = first or r
    else:
        r = first if first is not None else r
    r.diagnostics["seconds"] = round(time.perf_counter() - t0, 2)
    rep(1.0, "done")
    return r


def _detect_video_with(
    vm: Veilmark,
    path: Path,
    info: ffmpeg.VideoInfo,
    keyring: list[KeyedPatterns],
    kids: list[str],
    max_frames: int,
    stride: int | None,
    rep: Reporter,
    searched_before: int,
) -> tuple[report_mod.DetectionReport, int]:
    """One detection pass over the video with one set of keys."""
    t0 = time.perf_counter()
    total = info.frames or int(max(1.0, info.duration) * float(info.fps))
    if stride is None:
        stride = max(1, math.ceil(total / max(1, max_frames)))
    rep(0.02, "geometry pass")
    g_stride = max(GROUP_LEN, total // GEOMETRY_GROUPS)
    gframes = [
        f.copy()
        for f in ffmpeg.FrameReader(
            info, "gray", stride=g_stride, max_frames=GEOMETRY_GROUPS * GROUP_LEN, run_length=GROUP_LEN
        )
    ]
    if not gframes:
        raise InputError("no frames could be decoded from the video")
    geo = _geometry(gframes, keyring, rep.sub(0.02, 0.25))
    del gframes
    diag: dict[str, object] = {"video": info.summary(), "stride": stride}
    if geo is None:
        r = report_mod.interpret(str(path), "video", 0.0, 1, None, vm.trust, vm.own_public_keys(), kids)
        r.notes.append("no plausible watermark geometry found")
        r.diagnostics.update(diag)
        return r, 0
    lat = geo.lattice
    pats = keyring[geo.key_index]

    # ---- fold pass ---------------------------------------------------------
    rep(0.25, "folding frames")
    idx, count = _fold_index(info.height, info.width, lat.basis)
    chip_px = lat.period / N
    tiles: list[np.ndarray] = []
    frame_numbers: list[int] = []
    n_expected = max(1, min(max_frames, math.ceil(total / stride)))
    for i, frame in enumerate(ffmpeg.FrameReader(info, "gray", stride=stride, max_frames=max_frames)):
        rep(0.25 + 0.6 * min(1.0, i / n_expected), f"frame {i * stride + 1}/{total}")
        prepared = geometry.prepare_for_folding(frame, chip_px)
        t = np.bincount(idx, weights=prepared.ravel(), minlength=P0 * P0) / count
        tiles.append(engine.normalise_tile(t.reshape(P0, P0)).astype(np.float16))
        frame_numbers.append(i * stride)
    if not tiles:
        raise InputError("no frames could be decoded from the video")

    # ---- static-host suppression -------------------------------------------
    # Folding is (nearly) linear, so static scene content folds into the same tile
    # every frame. The watermark changes variant every segment, so subtracting the
    # temporal mean tile removes static host interference while keeping most of
    # each variant's signal (it is present only a fraction of the time).
    nf = len(tiles)
    if nf >= MIN_FRAMES_FOR_MEAN:
        mean_tile = np.mean([t.astype(np.float32) for t in tiles], axis=0)
        for i in range(nf):
            tiles[i] = engine.normalise_tile(tiles[i].astype(np.float64) - mean_tile).astype(np.float16)

    # ---- alignment -----------------------------------------------------------
    rep(0.86, "aligning frames")
    radius = min(MAX_MOTION * stride, P0 // 4)
    al = _align(tiles, pats, radius)
    shifts = al.shifts
    if al.moving:
        # Peak tracking follows noise maxima too, so its statistic is biased upward
        # by an amount that depends on the content. Calibrate against decoy keys
        # (never used for embedding) run through the identical procedure.
        decoys = [
            _align(tiles, KeyedPatterns(kdf.derive_key(pats_key_bytes(pats), "video.decoy", i)), radius).stat
            for i in range(N_DECOYS)
        ]
        sync_z = DECOY_FLOOR + al.stat - max(decoys)
        diag["moving_alignment"] = {"raw_z": round(al.stat, 2), "decoy_z": [round(d, 2) for d in decoys]}
    else:
        sync_z = al.stat
    moving = nf if al.moving else 0

    # ---- variant identification + accumulation -------------------------------
    rep(0.92, "identifying variants and accumulating evidence")
    zv = np.zeros((nf, NUM_VARIANTS))
    for i, t in enumerate(tiles):
        s = _surfaces(t.astype(np.float64), pats)
        py, px, _, _ = shifts[i]
        zv[i] = s[:, py, px]
    path_v, seg_z = segment_variants(zv)
    acc: dict[int, np.ndarray] = {}
    used = 0
    timeline: list[tuple[int, int, float]] = []
    for i, t in enumerate(tiles):
        v = int(path_v[i])
        timeline.append((frame_numbers[i], v, round(float(zv[i, v]), 2)))
        if seg_z[i] < MIN_SEGMENT_Z:
            continue
        py, px, fy, fx = shifts[i]
        aligned = np.roll(t.astype(np.float64), (-py, -px), axis=(0, 1))
        X = engine.chips_from_aligned(aligned, (fy, fx))
        acc[v] = acc[v] + X if v in acc else X
        used += 1
    ev = engine.SoftEvidence()
    for v, X in acc.items():
        ev.add(pats, v, X)
    outcome = engine.decode_evidence(ev) if acc else None

    searched = (len(keyring) * 15) * NUM_VARIANTS * 8 * P0 * P0 * 2
    r = report_mod.interpret(
        str(path), "video", sync_z, searched_before + searched, outcome, vm.trust, vm.own_public_keys(), kids
    )
    r.geometry = lat.describe()
    seg_changes = sum(1 for a, b in itertools.pairwise(timeline) if a[1] != b[1])
    counts = np.bincount([v for _, v, _ in timeline], minlength=NUM_VARIANTS)
    diag.update(
        {
            "frames_analysed": nf,
            "frames_with_evidence": used,
            "frames_using_moving_alignment": moving,
            "variants_observed": int(np.count_nonzero(counts[list(acc)])) if acc else 0,
            "variant_changes": seg_changes,
            "pattern_key_id": kids[geo.key_index],
            "seconds": round(time.perf_counter() - t0, 2),
        }
    )
    r.diagnostics.update(diag)
    # Only meaningful for a detected watermark, not a below-threshold candidate.
    r.diagnostics["publicly_verifiable"] = r.detected and kids[geo.key_index] in {
        k.key_id for k in vm.public_pattern_keys()
    }
    r.diagnostics["timeline_sample"] = timeline[:: max(1, len(timeline) // 40)]
    if nf * stride < total * 0.5 and stride > 1:
        r.notes.append(f"analysed every {stride}th frame (max_frames={max_frames})")
    rep(1.0, "done")
    return r, searched
