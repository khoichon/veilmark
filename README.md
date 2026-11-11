# Veilmark

Local-first invisible watermarking for **images and video**, with **Ed25519-signed
payloads** that anyone holding your public key can verify.

* Blind detection: no original needed. Survives common crops, resizing, rotation,
  mirroring, recompression (JPEG/WebP/H.264/H.265/VP9), colour edits, mild filtering,
  frame drops, frame-rate changes, short clips and moving crops, **to the degree
  measured in [`benchmarks/results`](benchmarks/results)**, not unconditionally.
* Detection, signature validity and issuer trust are reported **separately**.
* Keyed embedding pattern (a secret *pattern key*), moving spatial distribution for
  video, turbo-coded two-layer payload (robust 64-bit id + full signed payload).
* Five front-ends over one engine: **CLI**, **desktop GUI** (PySide6), a **static web
  app** that runs entirely in the browser (Pyodide/WebAssembly, no server), a **local
  web helper** (`veilmark serve`, 127.0.0.1 only) and a Python API.
* Robustness laboratory with dev/held-out split, false-positive measurement and
  Wilson confidence intervals. Plugin system with explicit approval and hash pinning.
* Everything runs locally. No network access, no telemetry.

> **Limitations, up front.** Watermarks can be weakened or removed by a determined
> attacker. At default strength the pattern can be visible as fine grain on flat or very
> smooth areas when inspected at 100%; use the preview and strength setting. A valid
> signature proves only that the key holder signed the hidden payload, not that the
> media is original, unedited or truthful. Veilmark is not a substitute for backups,
> access control, copyright registration or legal evidence. See
> [docs/threat-model.md](docs/threat-model.md).

---

## Install

Requirements: Python 3.11+ (developed and tested on **3.14.7**, macOS 26 arm64), and
**FFmpeg** on `PATH` for video. No administrator rights needed.

```bash
# 1. FFmpeg (video only)
#    macOS:   brew install ffmpeg
#    Windows: winget install Gyan.FFmpeg
#    Linux:   sudo apt install ffmpeg
# 2. Veilmark in a virtual environment
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install --require-hashes -r requirements-gui.lock   # pinned deps incl. GUI
#   (CLI only: requirements.lock;  development + tests + benchmarks: requirements-dev.lock)
pip install --no-deps -e .
veilmark doctor
```

With [uv](https://docs.astral.sh/uv/): `uv sync --extra gui` (or `--all-extras`) uses
the committed `uv.lock`. Without lock files: `pip install -e ".[gui]"`.

## Quick start (CLI)

```bash
veilmark keys init --label "Studio North"         # pattern key + passphrase-encrypted signing key
veilmark watermark image photo.jpg -o photo.wm.jpg --text "© Studio North 2026"
#   --strength subtle | balanced (default) | robust   trades visibility for robustness
veilmark verify photo.wm.jpg                       # exit 0 = authentic payload from a trusted issuer
#   --public  makes a watermark verifiable with your public key alone (anyone can then find it)
veilmark watermark video clip.mp4 -o clip.wm.mp4 --text "© Studio North 2026"
veilmark detect clip.wm.mp4 --json
```

Sample output of `veilmark verify`:

```
photo.wm.jpg: payload-recovered
  watermark id : db9d5e455b2db2eb
  text         : 'CLI test'
  timestamp    : 2026-10-25T08:09:18+00:00 (self-asserted)
  signature    : valid
  issuer trust : trusted (me, b0f4a0fa3d77df15)
  verdict      : valid signature from a trusted issuer
  evidence     : sync z=24.1, est. false-alarm p~8.9e-121, core agreement 1.00, payload agreement 0.98
```

### Commands

| Command | Purpose |
|---|---|
| `veilmark keys init / generate / list / rotate / set-status / export-public / export-private / import-private` | signing identities |
| `veilmark keys pattern generate / export / import` | secret pattern keys (needed to detect) |
| `veilmark keys export-keyfile / import-keyfile` | encrypted keyfiles (shared with the web app) |
| `veilmark trust add / list / revoke / remove` | trusted issuers (verifiers) |
| `veilmark watermark image IN... (-o OUT \| --out-dir DIR)` | images, batch with `--out-dir` |
| `veilmark watermark video IN -o OUT [--mode robust\|light] [--codec ...] [--crf N]` | video (audio preserved) |
| `veilmark detect FILE... [--report r.json] [--export markdown]` | blind detection + verification |
| `veilmark verify FILE...` | like detect, but succeeds only for authentic payloads |
| `veilmark capacity --text ...` | payload size before embedding |
| `veilmark benchmark --split heldout --profile standard --out DIR` | robustness laboratory |
| `veilmark plugins list / info / install / enable / disable / remove` | plugins |
| `veilmark serve` | local web helper |
| `veilmark gui` (or `veilmark-gui`) | desktop application |
| `veilmark doctor`, `veilmark cleanup` | environment check, stale temp files |

**Watermarking twice:** by default Veilmark refuses media that already carries a
watermark it can read (a second mark on the same tile period would damage both).
`--allow-rewatermark` adds one anyway on a different tile period; detection then
reports every watermark found.

Global options: `--json` (machine-readable), `--home DIR` (data directory, also
`VEILMARK_HOME`), `--debug`. Passphrases come from a prompt or `VEILMARK_PASSPHRASE`.

**Exit codes:** 0 success (verify: authentic) · 1 internal error · 2 invalid usage/input
· 3 no watermark · 4 watermark found but payload not recovered · 5 **invalid
signature** · 6 (verify) unsigned/unknown/untrusted/revoked issuer · 130 cancelled.

## Desktop GUI

`veilmark gui`: tabs **Watermark** (batch, preview with 1:1 crops and amplified
difference, measured PSNR/SSIM), **Detect** (detection / signature / trust shown
separately, report export), **Keys & trust**, **Robustness lab**, **Plugins**,
**Settings**. Long tasks run on worker threads with progress and cancel.

## Web app (serverless, runs in the browser)

```bash
python scripts/build_webapp.py [--vendor-pyodide]   # -> dist/web (static files)
python -m http.server -d dist/web 8000              # or upload dist/web to any static host
```

Create keys in the browser or open a keyfile, watermark and verify images and video
(decoded and encoded by the browser's WebCodecs) with live progress bars; nothing is
uploaded anywhere. Keyfiles are passphrase-encrypted and interchangeable with the CLI
(`veilmark keys export-keyfile` / `import-keyfile`).
Video up to 1080p and 10 minutes. Details: [docs/webapp.md](docs/webapp.md).

## Web helper

`veilmark serve` opens a single page at `http://127.0.0.1:8765/` to watermark and
verify by drag-and-drop. It binds to localhost only, requires a per-session token,
rejects foreign `Host` headers, and deletes uploads after processing.

## Python API

```python
from pathlib import Path
from veilmark.api import Veilmark, WatermarkSpec

vm = Veilmark()                                   # default data directory
res = vm.embed_image(Path("in.png"), Path("out.png"), WatermarkSpec(text="hello", passphrase="..."))
report = vm.detect(Path("out.png"))
print(report.status, report.payload, report.verification)
```

## How it works (short)

A keyed 64x64-chip spread-spectrum tile repeats over the image luminance, perceptually
masked. A keyed set of Fourier-domain template sinusoids lets the detector recover
scale/rotation/mirroring blindly; a keyed sync pattern then aligns the tile, a pilot
equaliser despreads the chips, and turbo codes decode a robust 64-bit id and the full
signed payload. Video switches between 8 keyed pattern variants over time, tracks
moving crops, removes static background and accumulates evidence across frames.
Details: [docs/watermarking.md](docs/watermarking.md),
[docs/video-processing.md](docs/video-processing.md),
[docs/cryptography.md](docs/cryptography.md), [docs/architecture.md](docs/architecture.md).

## Robustness (measured)

Measured on the held-out set (never used for tuning), default strength, signed
~90-byte payloads; full details in
[benchmarks/results/SUMMARY.md](benchmarks/results/SUMMARY.md):

| Held-out image attack | Images ≥ 0.8 MP | Images < 0.3 MP |
|---|---|---|
| none / JPEG 75 / JPEG 50 | 100% / 100% / 92% | 75% / 69% / 38% |
| WebP 80 | 83% | 38% |
| scale 0.75 / 0.5 | 100% / 92% | 31% / 12% |
| crop to 50% / 25% of the area | 92% / 67% | 62% / 38% |
| rotate 10°, noise σ 12 | 92%, 100% | 50%, 38% |
| social-media-like (scale 0.6 + saturation + JPEG 70) | 100% | 0% |

* **0 false positives in 1,170** unwatermarked held-out detections; **0 wrong
  payloads**; forged/altered/untrusted payloads **never** reported as authentic.
* Not robust: non-uniform aspect change, strong denoising, very small images (< ~0.15
  MP cannot carry a signed payload; the embed self-check warns), pure black/white
  graphics in video. The `subtle` preset (+4 dB PSNR) roughly halves robustness.
* Video (indicative, small sample): survives re-encoding at moderate quality, frame-rate
  changes, frame drops, ≥ 0.5–2 s clips, fixed and moving crops; weak against
  low-bitrate transcodes and downscaling to ≤ 480p.

Reproduce with `scripts/run_benchmarks.sh`; method in
[docs/benchmarking.md](docs/benchmarking.md).

## Development

```bash
pip install --require-hashes -r requirements-dev.lock && pip install --no-deps -e .
pytest                      # 119 tests: unit, integration (image+video), end-to-end (CLI, GUI offscreen, web)
pytest -m "not slow"        # skip video tests
ruff check src tests && ruff format --check src tests && mypy
scripts/run_benchmarks.sh   # regenerate benchmarks/results (1-2 h)
```

Continuous integration (`.github/workflows/`): **ci.yml** runs lint/format/mypy and
the test suite on Linux (Python 3.11–3.14), macOS and Windows with FFmpeg and an
offscreen Qt, builds the web app and runs it on the real Pyodide/WebAssembly runtime;
**pages.yml** deploys the web app to GitHub Pages from `main` (enable Pages → "GitHub
Actions" first); **benchmark.yml** runs the robustness benchmark on demand and
uploads the reports. Dependabot keeps actions and locked dependencies current.

Repository layout:

```
src/veilmark/
  api.py            high-level operations used by every front-end
  watermark/        engine: pattern, geometry, framing, turbo/ecc, perceptual, backends
  crypto/           payload format, keys, signing/trust, KDF
  image/ video/     media I/O; video embed/detect/schedule/ffmpeg
  detection/        reports and status logic
  benchmarks/       datasets (dev/held-out), attacks, runner, report
  plugins/          manifest validation, approval, loading, plugin API
  cli/ app/ web/    command line, PySide6 GUI, local web helper
webapp/             static browser app (index.html, app.js, worker.js, bridge.py); build with scripts/build_webapp.py
  core/ security/ storage/   tasks/metrics, limits/temp files, paths/settings
tests/  unit/ integration/ end_to_end/
docs/   architecture, threat model, watermarking, cryptography, video, plugins, benchmarking, troubleshooting
examples/plugins/markdown-report/   example exporter plugin
benchmarks/results/                 committed benchmark reports
```

## Status

| Feature | Status |
|---|---|
| Image embed/detect, signed payloads, trust lists, rotation/revocation | implemented, tested |
| Video embed/detect (moving distribution, temporal accumulation, moving-crop tracking) | implemented, tested |
| CLI, GUI, web helper, plugins (in-process, approval + hash pinning) | implemented, tested |
| Static browser app (images and video; keyfiles; progress) | implemented; bridge tested under CPython, full path checked in headless Chromium |
| Benchmark laboratory (images and video, dev/held-out, CIs, FP rates, forgery checks) | implemented, results committed |
| Perspective / non-uniform scaling robustness | **experimental** (mild only) |
| Payload encryption, isolated (out-of-process) plugins, key registries | **not implemented** |
| Screen re-recording with a camera | **not supported** |

License: MIT.
