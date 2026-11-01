# Benchmark summary (committed run)

Run on 2026-10-25 with veilmark 0.1.0 (format v1), macOS 26 / Apple Silicon (10 cores),
Python 3.14.7, FFmpeg 9.0.1, via `scripts/run_benchmarks.sh`. Every number below comes
from the `records.jsonl` files in this directory; full tables are in each run's
`report.html` / `report.md`. 95% Wilson intervals in brackets.

## Headline

* **False positives: 0 of 1,170** unwatermarked held-out image detections (95% upper
  bound ≈ 0.3%), 0 of 702 dev, 0 of 1,170 at subtle strength, 0 of 24 unwatermarked
  video runs. Highest sync statistic on any negative: 6.3 (presence threshold 7.5).
* **Wrong payloads: 0** across all positive runs (3,156 detections): every decoded
  payload was the one embedded.
* **Forgeries: never accepted as authentic** (0 of 234 checks). Altered text, a payload
  moved to another watermark id, and an untrusted signer were each correctly rejected
  in 26/30 held-out and 18/18 dev cases; in the remaining 4 the payload did not decode
  at all (tiny images), so nothing was reported as authentic.
* **Image size dominates robustness.** At the default strength:

| Held-out attack | Large images (≥ 0.8 MP) | Small images (< 0.3 MP) |
|---|---|---|
| no attack | 100% [76-100] | 75% [51-90] |
| JPEG 75 / JPEG 50 | 100% / 92% | 69% / 38% |
| WebP 80 | 83% [55-95] | 38% |
| scale 0.75 / 0.5 | 100% / 92% | 31% / 12% |
| crop to 50% / 25% of area | 92% / 67% | 62% / 38% |
| rotate 10° | 92% | 50% |
| Gaussian noise σ 12 | 100% | 38% |
| screenshot-like (scale 0.8, gamma, sharpen, JPEG 85) | 100% | 56% |
| social-media-like (scale 0.6, saturation, JPEG 70) | 100% | 0% |
| crop 50% + scale 0.7 + JPEG 75 | 83% | 0% |

  (n = 12 large / 16 small per attack; payload = exact signed payload recovered.) Full
  stratified tables, including the subtle preset: [size_breakdown.md](size_breakdown.md).

## Images, held-out split (independent evaluation), strength 1.0

15 images x 2 seeds x 39 attacks. Embedding quality: luma PSNR median 39.3 dB (min
34.8 dB on `gravel`), SSIM median 0.974.

Not robust (measured): **non-uniform aspect change** (0% at 0.9x horizontal),
**non-local-means denoising** (7%), heavy WebP (37% at q50). Two images (`coins`,
0.12 MP; `text-page`, 0.07 MP) never yielded the signed payload, even unmodified;
the embed self-check (added after this run) now flags such cases.

## Images, subtle preset (strength 0.6)

PSNR median 43.6 dB (min 39.2), SSIM 0.990, but robustness drops sharply: large images
keep 83% without attack and under JPEG 75, yet only 33% under JPEG 50 and 25% under
WebP 80. Use it only where little processing is expected.

## Images, dev split (used for tuning; not independent)

9 images x 2 seeds. 100% for no attack, JPEG 75, crops to 75%, rotations, mirror and
colour edits; JPEG 50 83%, WebP 80 83%, scale 0.5 67%, crop 25% 67%. PSNR median 38.8 dB.

## Video, held-out split (4 synthetic sources, 1280x720, 6 s)

| Source | Payload recovered (19 attacks) |
|---|---|
| testsrc2 (moving synthetic) | 18/19 |
| pan over photograph | 13/19 |
| mandelbrot (fine detail) | 12/19 |
| cellauto (binary black/white cellular graphics) | 0/19, **not detected even unmodified** |

For the three non-binary sources: stream copy, H.264 CRF 23, VP9 CRF 36, 24 fps
conversion, dropping every 3rd frame, 2 s and 0.5 s clips, fixed crops to 49% and 25%
of the area, horizontal flip and colour changes all recovered 3/3. Failures cluster on
low-bitrate transcodes (H.264 1 Mbit/s 1/3, H.264 CRF 30 2/3, HEVC CRF 28 2/3),
downscaling (480p 1/3, 360p 0/3), combined crop+downscale+compress (1/3) and the moving
crop (2/3). Cellauto fails because the headroom rule suppresses the signal near pure
black and white; video embedding now warns about such content.

The video sample is small (n = 4 per attack, 3 effective). Treat these as indicative.

## Video, dev split (2 clips of the example screen recording)

Clean, CRF 23, VP9, frame-rate change, frame drops, crops, the moving crop, flip and
colour changes: 2/2. CRF 30 0/2 (id 1/2), 480p 1/2, 360p 0/2, 1 s clip 1/2.

## Timing (benchmark machine, all cores busy)

Median image detection 1.6–3.7 s per image depending on attack; video detection
9–20 s per 6 s 720p clip; video embedding ~1x real time including x264 encoding.
