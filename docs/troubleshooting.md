# Troubleshooting

Start with `veilmark doctor`: it prints versions, the data directory, key counts and
known problems.

| Symptom | Cause / fix |
|---|---|
| `FFmpeg is required for video` | Install ffmpeg (`brew install ffmpeg`, `winget install Gyan.FFmpeg`, `sudo apt install ffmpeg`) or set `VEILMARK_FFMPEG` / `VEILMARK_FFPROBE` to the executables. |
| `no pattern key available` | Run `veilmark keys init`, or import a pattern key you were given (`veilmark keys pattern import FILE --label NAME`). |
| `passphrase required to unlock signing key` | Run in a terminal (you will be prompted) or set `VEILMARK_PASSPHRASE`. Use `--no-sign` for an unsigned payload. |
| `wrong passphrase` | The private key cannot be recovered without it. Generate a new identity and distribute its public key. |
| `payload of N bytes exceeds the maximum in-band capacity` | Shorten the text/metadata. `veilmark capacity --text "..."` shows the size. |
| Detection says `not-detected` on a file you watermarked | Check you have the right pattern key (`veilmark keys list`). Heavy downscaling, tiny crops, strong denoising or screen recapture can destroy the mark; see the benchmark limits. Files watermarked by a pre-release development build use an older, incompatible format. |
| `signal-only` / `id-only` | The watermark is present but too damaged for the full payload. Nothing is guessed. Try the original or a larger copy. |
| `signature INVALID` | The payload bytes do not match the signature: altered or forged. Exit code 5. |
| `signed by unknown key` | Import the issuer's public key with `veilmark trust add` after checking its fingerprint. |
| Signature valid but `untrusted` | The key verified the signature but is not in your trust list (e.g. one of your own keys you removed). |
| `refusing to overwrite the input file` / `output exists` | Choose a different output path or pass `--overwrite` (never allowed for the input itself). |
| `image rejected by decompression-bomb guard` / pixel limit | Raise limits in Settings (or `settings.json`: `max_image_megapixels`) if the file is trustworthy. |
| GUI does not start (`No module named PySide6`) | `pip install -e '.[gui]'` (or the GUI lock file). On Linux without a display use the CLI or `veilmark serve`. |
| Qt platform plugin errors on Linux | Install the XCB libraries (`sudo apt install libxcb-cursor0 libxkbcommon-x11-0`), or run headless with `QT_QPA_PLATFORM=offscreen` for tests. |
| `veilmark serve` port in use | `veilmark serve --port 8790`. The helper only listens on 127.0.0.1. |
| Leftover `.veilmark-*.partial` files after a crash | `veilmark cleanup [DIR] --dry-run` then `veilmark cleanup [DIR]`. |
| Benchmark shows `(unavailable)` images | Install the bench extra: `pip install -e '.[bench]'` (scikit-image sample data). |
| Video detection is slow | Lower `--max-frames` (e.g. 300) or set a `--stride`; cost is roughly proportional to analysed frames. |
| Plugin listed as `modified` | Its files changed since you approved it. Inspect the change, then `veilmark plugins enable NAME` to re-approve. |
