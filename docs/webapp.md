# Veilmark Web (static, client-side)

A static website that watermarks and verifies **images** entirely inside the visitor's
browser. There is no server-side code: the same Python engine runs on
[Pyodide](https://pyodide.org) (CPython compiled to WebAssembly) inside a Web Worker.
Images, keys and passphrases never leave the browser tab.

## Build and host

```bash
python scripts/build_webapp.py                  # -> dist/web, Python runtime from jsDelivr
python scripts/build_webapp.py --vendor-pyodide # also copy the runtime (~30 MB): no third-party requests
python -m http.server -d dist/web 8000          # preview at http://127.0.0.1:8000/
```

Upload `dist/web/` to any static host (GitHub Pages, Cloudflare Pages, Netlify, S3,
nginx). It must be served over http(s); opening `index.html` as a `file://` URL does
not work because browsers refuse module workers from local files.

Without `--vendor-pyodide` the page downloads the pinned Pyodide 314.0.7 runtime from
`cdn.jsdelivr.net`. The CDN then sees that a visitor loaded the runtime (not their
images or keys). Vendoring removes that dependency; the build script verifies every
downloaded wheel against the SHA-256 in Pyodide's lock file.

## What the user sees

1. **Your keys**: *Create new keys* (in the browser) or *Open keyfile*. Keys exist only
   in the tab until saved. *Save keyfile* downloads a passphrase-encrypted file and can
   also keep an **encrypted** copy in this browser's storage (unlocked with the
   passphrase on the next visit). The page warns before closing with unsaved keys.
2. **Watermark an image**: drop an image, type the hidden text (≤ 60 bytes), choose a
   strength and output format. A read-back check (on by default) decodes the written
   file before offering it for download. Press and hold the result to compare with the
   original; click to view at 100%.
3. **Detect & verify**: drop any copy. Detect is available once any pattern key is
   loaded or any issuer is trusted (for publicly verifiable watermarks); otherwise a hint
   says what to add. Detection, signature and issuer trust are shown
   as three separate results.

Until the engine has loaded (and while it restarts after *Cancel*) a full-screen panel
covers the page, with download progress; nothing on the page can be used before that.
If the engine cannot start, the panel says why and offers a reload.

Every long step shows a progress bar with moving stripes, a status line and elapsed
seconds, plus **Cancel** (which restarts the engine; loaded keys are restored from an
in-memory encrypted copy).

## Keyfiles

The keyfile format is shared with the CLI, so keys move between web and desktop:

```bash
veilmark keys export-keyfile -o me.vmkey.json      # CLI -> web
veilmark keys import-keyfile me.vmkey.json         # web -> CLI
```

Format: JSON with a clear header (label, key ids, public key, fingerprint) and the
signing seed, pattern key and trusted-issuer list encrypted with XSalsa20-Poly1305
under an Argon2id key (64 MiB, libsodium "interactive" limits so unlocking takes
seconds in WebAssembly). On import the header is compared with the decrypted secrets,
so a tampered header is rejected. Losing the passphrase means losing the keys.

## Sharing verification with others

There are two kinds of watermark:

* **Publicly verifiable** (tick *Publicly verifiable* when watermarking, or `--public`
  on the CLI): the pattern is derived from your public key, so verifiers need only your
  **public key** (*Copy public key*), added under *Trusted issuers & shared pattern
  keys*. Trade-off: anyone who has your public key can also find the watermark and try
  to remove it.
* **Private** (the default): verifiers need your public key *and* your pattern key.

For private watermarks:

* Give people your **public key** (*Copy public key*); they add it under *Trusted
  issuers & shared pattern keys*.
* Detection also needs your **pattern key** (*Copy pattern key…*, or
  `veilmark keys pattern export` on the CLI), which is a secret: whoever has it can
  detect and attempt to remove your watermarks. Share it only with people who should
  verify your images.
* Verifiers do **not** need keys of their own: the *Trusted issuers & shared pattern
  keys* section works before any keys are created or opened.
* With only the pattern key, detection already shows the hidden text, but the signature
  reads *unknown key*: anyone holding the pattern key could have written it. Only a
  valid signature from a trusted issuer shows it came from you.
* Shared pattern keys are not stored in keyfiles (a keyfile holds its owner's pattern
  key and trusted issuers); add them again in a new tab.

## Limits and performance

* Images only (PNG, JPEG, WebP; up to 40 MP and 200 MB). Video stays in the CLI and
  desktop app: decoding video in WebAssembly is slow and memory-bound.
* Speed: the engine runs single-threaded in WebAssembly. Measured under Node.js with
  Pyodide on the development machine (which was heavily loaded at the time, so treat
  these as rough): first visit downloads ~30 MB and starts in a few seconds once
  cached; embedding a 1 MP image ~0.6 s; detection of a watermarked 1 MP image 5–8 s;
  an *unwatermarked* image takes longest (~20 s) because the thorough search runs. A
  5 MP image with read-back check took ~22 s.
* Browser storage can be cleared by the browser or the user at any time; the keyfile
  you downloaded is the real backup.
* Security model, robustness and limitations are those of the engine; see
  [threat-model.md](threat-model.md) and [benchmarking.md](benchmarking.md).

## Tests

`tests/end_to_end/test_webapp.py` runs the bridge (`webapp/bridge.py`) under CPython,
including a two-person verification flow and the static build. The full browser path
(worker, Pyodide, UI, keyfile save, progress) was exercised in headless Chromium
(QtWebEngine) during development; that script is not part of the automated suite.
