# Watermarking algorithm (backend `tss`, format v1)

Tiled spread spectrum with a keyed Fourier-domain template for geometric
synchronisation, a keyed coherent sync pattern for alignment, pilot-based
maximum-ratio despreading and turbo coding. All techniques are established; the
combination and parameters were chosen by measurement (see the design log below).

## Signal

* **Tile**: 64 x 64 *chips*. A chip is `c` pixels wide where `c = round(short side /
  260)` clamped to 2..6 (480p → 2, 720p → 3, 1080p → 4, ≥1440p → 6). Tile period
  `P = round(64c · (1 + j))` pixels with a keyed jitter `j ∈ {0, ±4%, ±8%}` chosen from
  the watermark id; the tile repeats over the whole frame. The jitter keeps independent
  watermarks on different periods, which is what lets two of them coexist (see the
  threat model); re-watermarking explicitly picks a period ≥ 3.5% from existing marks.
* **Energy split**: 20% keyed template sinusoids; of the remaining 80%, 15% sync
  chips and 85% data chips. Data chips: 13% carry the core layer, 87% the full layer.
* **Data chips** hold coded bits as `b · s_j` (keyed ±1 spreading `s`), with a keyed
  permutation spreading every bit across the whole tile.
* **Spectral shaping**: chip frequencies below 10 cycles/tile are removed (measured:
  host content leaves them with ~0 SNR, and they are the most visible); Nyquist
  rows/columns are removed so Fourier interpolation to `P` pixels is exact.
* **Template**: 10 sinusoids at keyed tile harmonics (radius 10–24 cycles/tile, at
  least 12° from the axes to avoid codec block-grid frequencies, keyed phases).
* **Variants**: 8 independent keyed variants per pattern key (sync, spreading,
  permutation, cyclic chip offset, template). An image uses one variant (chosen by
  the watermark id); video switches variants over time.
* **Perceptual masking**: gain = clip((local σ + 1.5)/10, 0.3, 1.8), smoothed, and
  reduced near black/white. The delta is added equally to R, G and B (luma only).
* **Strength 1.0**: RMS 2.6 luma levels before masking. Measured PSNR is reported for
  every output (typically 37–43 dB; lower on small images, see benchmark).

## Channel coding

* Core: 64-bit watermark id + 8-bit length class + CRC-16 (88 bits), rate-1/3 turbo
  code (3GPP RSC 13/15 octal, keyed-independent public interleaver), 8 iterations, one
  CRC test.
* Full: payload padded to one of 32/48/64/80/96/128/160/192 bytes incl. CRC-32,
  rate-1/3 turbo, early termination on CRC.
* Turbo coding gained ~1.5–2 dB over K=9 convolutional codes; on the tuning subset it
  raised payload recovery under JPEG-50 from 22% to 89% (measured).

## Detection

1. **Template search** (`geometry.template_search`): whitened, clipped magnitude
   spectrum of a ≤2048 px centre crop (zero-padded to ≥1536). Coarse-to-fine search
   over period 64–1000 px, rotation 0–180°, mirroring and variant, scoring
   `Σ clip(log z, 0, log 8)` at the predicted line positions, then a least-squares
   affine fit of the observed line positions. Codec grid frequencies are neutralised.
2. **Verification**: each of the top 16 lattices (plus 5 unscaled nominal lattices) is
   folded on a 1024 px crop and correlated with the keyed sync templates
   (z-normalised circular correlation; template lattices fix variant and orientation
   up to 180°, nominal ones search all 8 dihedral transforms).
3. **Refinement**: fold sub-regions, measure sync-peak drift, least-squares fit of the
   inverse-basis error (coarse-to-fine: crop, then full image). Converges to ±0.05 px
   per period.
4. **Folding**: nearest-sample averaging of high-passed, locally normalised luma into a
   128 x 128 canonical tile (averaging, not summing, avoids aliasing at non-integer
   ratios); sub-sample alignment by parabolic peak fit + Fourier phase ramp.
5. **Despreading**: per radial frequency ring, the known sync acts as a pilot to
   estimate channel gain `g` and noise `n`; sync is cancelled and data weighted by
   `g/n` (maximum-ratio combining). Soft values from several observations add.
6. **Coherent scale-scan fallback** (`engine.scale_scan`): if nothing is found, an
   unrotated 640 px centre crop is folded at every tile period from 64 to 1000 px in
   0.7% steps and the full keyed sync search is run at each (~4 s). It rescues content
   whose own periodic structure defeats the spectral template (pixel-art screenshots
   after crop + downscale) but covers only uniform scaling, 90° rotations and mirroring.
   Its extra hypotheses are included in the false-alarm estimate.
7. **Decision**: see `detection/report.py`. Thresholds: sync z ≥ 5 to attempt decoding;
   id-only claims need CRC-16 + sync z ≥ 6 + agreement ≥ 0.80 (≈10⁻⁶ false id per
   image, estimated); payload claims need CRC-32 (≈2⁻³² per attempt).

## Capacity and practical limits

* Maximum payload 188 bytes. A signed payload costs ≥ 70 bytes (64-byte signature); a
  signed 20-character text with timestamp is ~95 bytes. Shorter is more robust.
* The full signed payload needs roughly ≥ 0.3 MP of surviving, moderately compressed
  content at strength 1.0; the 64-bit id needs much less. Crops smaller than one tile
  in each direction cannot be aligned.
* Scaling range ~0.45x–2x relative to embedding; arbitrary rotation and mirroring;
  mild aspect change/perspective only (see benchmark `aspect-0.9`, `perspective-2pct`).

## Design log (what was tried, measured, and kept or dropped)

| Change | Measured effect | Kept |
|---|---|---|
| Autocorrelation (ACF) lattice estimation, 128-chip tiles | watermark ACF peaks 2–6σ, buried under host texture periodicity | dropped |
| 64-chip tiles (more repetitions, same energy per bit) | synchronisation feasible; capacity unchanged | yes |
| Sync cancellation + pilot MRC | raw BER on a clean pattern from ~10% to 0% | yes |
| Fold by averaging, round-to-nearest, sub-pixel phase ramp | noise-free extraction became exact at all chip sizes | yes |
| Keyed Fourier template (6 lines → 10 lines) | geometry found in 63/72 → 66/72 scaled cases | yes (10) |
| Energy: sync 30→15%, template 25→20% | payload rates up on tuning subset | yes |
| Spectral low cut 4→10 cycles/tile | wasted low-frequency energy removed; mixed small-n effect | yes |
| K=7 conv → K=9 conv → turbo | turbo: JPEG-50 payload 22% → 89% (tuning subset) | turbo |
| Minimum chip 3 px for small images | worse overall (JPEG-50 89% → 56%) | reverted |
| Video: temporal mean-tile subtraction | raw BER 13–18% → 0–0.5% on a static scene | yes |
| Video: Viterbi peak tracking for moving crops | moving crop recovered (previously failed) | yes |
| Video: decoy-key calibration of tracked statistic | negatives from z≈8.8 (false "signal") to 3.9–4.7 | yes |
| Edge-aware masking (erosion of activity), energy-preserving | halos at edges reduced, SSIM 0.973 → 0.977, robustness unchanged; without energy preservation JPEG-50 fell 89% → 11% | yes (preserving) |
| Image coherent scale-scan fallback | dev subset: scale-0.5 67% → 100%; max negative z 6.1 → 6.7 (< 7.5) | yes |
| Video coherent scale-scan fallback (frame runs) | no case improved (failures were signal-limited), +20 s per negative | dropped |
| Keyed tile-period jitter + pre-embed check + multi-watermark reporting | second watermark on the same period: both payloads lost; on periods 20% apart: both recovered; refusal + reporting tested | yes |
