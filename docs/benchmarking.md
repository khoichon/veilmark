# Benchmarking

The robustness laboratory measures what survives, on which content, with what
uncertainty. Committed results live in [`benchmarks/results/`](../benchmarks/results)
(`report.html`, `report.md`, `summary.json`, `summary.csv`, `records.jsonl` per run).

## Reproduce

```bash
pip install --require-hashes -r requirements-dev.lock && pip install --no-deps -e .
scripts/run_benchmarks.sh                       # all committed runs (1-2 h on 10 cores)
veilmark benchmark --split heldout --profile quick --out /tmp/q   # a few minutes
veilmark benchmark --list                       # datasets and attacks
veilmark benchmark --add-image my.jpg --attacks jpeg-75 crop-50 --out /tmp/mine
```

## Method

* **Splits.** `dev` media were used while designing and tuning the algorithm
  (including the repository's example screenshot and video); `heldout` media were never
  used for tuning. **Only held-out numbers are independent evidence.** Dev numbers are
  reported for transparency.
* **Content.** Photographs (scikit-image sample data, some 2x Lanczos-upscaled to reach
  typical sizes — upscaled images are smoother than native photos), textures,
  scientific images, text, flat UI graphics and vector-style illustrations
  (procedurally generated), plus game-capture screenshots/video (dev only). Video:
  synthetic motion (`testsrc2`), fine detail (`mandelbrot`), flat cellular graphics
  (`cellauto`), a camera pan over a photograph, and two clips of the example video (dev).
* **Seeds.** Each image is watermarked with `--seeds` independent random watermark ids
  and payloads (2 in the standard profile); seeds drive crop positions and noise.
  Keys are fresh per run (ephemeral benchmark keys).
* **Payload.** Signed (Ed25519) with timestamp and ~15-20 characters of text: 86–92
  bytes, i.e. the 96-byte class. Smaller payloads are more robust than reported.
* **Positives.** Watermarked copy → attack → blind detection. *Payload* = exact text
  recovered and parsed; *ID* = correct 64-bit id; *Authentic* = valid signature from a
  trusted issuer; *wrong payload* = any payload different from the embedded one.
* **Negatives.** The *unwatermarked* original under the same attack → detection. Any
  status other than `not-detected` counts as a false positive; payload recoveries on
  negatives are counted separately. (Video: negatives on a representative subset.)
* **Forgery checks.** Per image: a payload with one altered text byte (re-CRC'd so it
  decodes), a valid payload moved under a different watermark id, and a payload signed
  by a key outside the trust list. The verifier must reject (signature invalid /
  untrusted) and never report *authentic*.
* **Uncertainty.** Rates are given with 95% Wilson score intervals and sample counts.
  With n = 30 a 100% observed rate still has a lower bound of ~89%.
* **Quality.** Luma PSNR and SSIM of each embedding (before attacks). Video PSNR is
  pre-encode, sampled every 30 frames.
* **Timing.** Detection seconds per attacked file (median) on the benchmark machine
  with all workers busy, so absolute times are pessimistic.

## Attacks

Images (39): none, PNG round trip, JPEG 90/75/50/30, WebP 80/50, scale 0.5/0.75/1.5,
aspect 0.9, random-position crops keeping 75/50/25/10% of the area, rotation 2/10/90°,
mirror, 2% perspective, greyscale, brightness +30, contrast 0.7, gamma 0.6/1.6,
saturation 1.6, hue +30°, Gaussian blur σ 1/2, sharpen, Gaussian noise σ 5/12, median
3x3, non-local-means denoise, and four combinations (crop+scale+JPEG, rotate+crop+JPEG,
screenshot-like, social-media-like). The `expected` column records whether an attack
was expected to be within the design envelope (`robust`) or at/over its edge
(`partial`). Expectations were written before the runs and are not adjusted to results.

Video (19): stream copy, H.264 CRF 23/30, H.264 1 Mbit/s, VP9 CRF 36, HEVC CRF 28,
downscale to 480p/360p, 24 fps conversion, dropping every third frame, 2 s / 1 s /
0.5 s clips, fixed crops keeping 49%/25%, a moving crop (36% area, pan + sine),
crop+downscale+compress, horizontal flip, colour/brightness/contrast/gamma changes.

## Results

See [`benchmarks/results/SUMMARY.md`](../benchmarks/results/SUMMARY.md) for the
headline tables of the committed run, and each run's `report.html` for full tables.

## Interpreting the numbers

* A high rate on one dataset does not transfer to every image: small images (≤0.3 MP),
  very flat graphics and heavily downscaled copies are the hard cases.
* "Detected" without payload (`id-only`, `signal-only`) is useful evidence but cannot
  be verified cryptographically (except that the id itself passed a CRC).
* The false-positive estimate is bounded by the number of negatives tested; a 0/N
  result means "below ~3/N with 95% confidence", not zero.
