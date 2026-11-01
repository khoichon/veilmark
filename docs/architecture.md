# Architecture

Veilmark is a layered Python package. Every front-end (CLI, desktop GUI, local web
helper) is a thin shell over one API object; the watermarking engine knows nothing
about files, keys or user interfaces.

```
 front-ends      cli/  (argparse)    app/  (PySide6)    web/  (127.0.0.1 HTTP + one HTML page)
                    \                    |                   /
 api.py                 Veilmark: keys, trust, settings, limits, embed/detect for images & video
                    /        |              |                  \
 media           image/io.py         video/ffmpeg.py, embed.py, detect.py, schedule.py
                    \        |              |
 engine          watermark/  engine.py  (embed plan, analyse, decode)
                             geometry.py (template search, folding, refinement)
                             pattern.py  (keyed tiles, sync, template, MRC despreading)
                             framing.py + turbo.py + ecc.py (two-layer channel coding)
                             perceptual.py (masking)   backends.py (backend interface)
 trust           crypto/  payload.py (canonical format), keys.py (store), trust.py (sign/verify), kdf.py
 reporting       detection/report.py  (status levels, confidence, verification, disclaimer)
 extensibility   plugins/ manager.py (discover/approve/load), api.py (registration surface)
 support         core/ (tasks: progress+cancel, metrics), security/ (limits, temp files),
                 storage/ (paths, atomic writes, settings), benchmarks/ (datasets, attacks, runner, report)
```

## Data flow: embedding

1. `api.Veilmark.build_payload` serialises the payload (canonical, `crypto/payload.py`)
   and signs it with the chosen Ed25519 identity (`crypto/trust.py`). The signature
   covers a domain string, the random 64-bit watermark id and the payload body.
2. `watermark/framing.py` turbo-encodes two layers: a robust **core** (watermark id +
   length class + CRC-16) and the **full** payload (+ CRC-32).
3. `watermark/pattern.py` turns coded bits into a keyed 64x64-chip tile (spreading,
   permutation, sync chips, keyed template sinusoids), band-limits it, and renders it
   at the tile period chosen for the media resolution.
4. `watermark/engine.EmbedPlan` tiles the pattern across the frame, applies the
   perceptual mask and returns a luma delta. Images add it to R, G and B equally; video
   adds it to the Y plane of yuv420p frames streamed through ffmpeg. Video mixes
   variants over time following the keyed schedule in `video/schedule.py`.

## Data flow: detection

1. Spectral template search estimates scale, rotation and mirroring (`geometry.py`).
2. Each hypothesis is verified by keyed coherent sync on a folded tile; the winner is
   refined by measuring sync drift across image regions.
3. The aligned tile's chip spectrum is equalised with the sync pilot and despread into
   soft bits; turbo decoding plus CRCs yield the core and full layers.
4. `detection/report.interpret` assigns a status (`payload-recovered`, `id-only`,
   `signal-only`, `not-detected`), then verifies the signature against the trust list.
   Detection, signature validity and issuer trust are reported separately.

Video adds temporal stages (static-background suppression, peak tracking, variant
segmentation, evidence accumulation): see [video-processing.md](video-processing.md).

## Design rules

* The engine is pure NumPy/OpenCV, has no I/O, and is deterministic given its inputs.
* Secret-derived randomness comes only from `crypto/kdf.py` (SHAKE-256). Simulation
  randomness (benchmarks, tests) uses seeded `numpy.random.Generator`s.
* Long operations take a `core.tasks.Reporter` for progress and cooperative
  cancellation; front-ends run them on worker threads (GUI) or with a progress line.
* Outputs are written to a temporary file in the destination directory and atomically
  renamed; inputs are never overwritten.
* Plugins can only register through `plugins/api.PluginAPI`, which exposes no keys.

## Module size and boundaries

No module exceeds ~550 lines. Cross-layer imports point downward only (front-ends →
api → media/engine/crypto); `watermark/` never imports `crypto/keys.py` or any
front-end.
