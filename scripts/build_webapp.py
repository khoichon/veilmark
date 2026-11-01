#!/usr/bin/env python3
"""Build the static Veilmark web app into a folder you can host anywhere.

    python scripts/build_webapp.py                    # -> dist/web (Pyodide from jsDelivr)
    python scripts/build_webapp.py --vendor-pyodide   # also copy the runtime: no third-party requests
    python -m http.server -d dist/web 8000            # preview at http://127.0.0.1:8000/

The output is plain static files (HTML, JS, CSS, a zip of the Python engine). Any
static host works (GitHub Pages, Cloudflare Pages, S3, nginx); it must be served over
http(s), not opened as a file:// URL, because browsers do not run module workers from
local files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYODIDE_VERSION = "314.0.7"
CDN = f"https://cdn.jsdelivr.net/pyodide/v{PYODIDE_VERSION}/full/"
CORE_FILES = ["pyodide.mjs", "pyodide.asm.mjs", "pyodide.asm.wasm", "python_stdlib.zip", "pyodide-lock.json"]
PACKAGES = ["numpy", "opencv-python", "pillow", "pynacl", "cffi", "pycparser"]
# Engine modules the browser does not need (desktop GUI, CLI, video, benchmarks, plugins, web helper).
EXCLUDE = {"app", "benchmarks", "cli", "web", "video", "plugins"}
STATIC = ["index.html", "style.css", "app.js", "worker.js", "bridge.py"]


def build_zip(dest: Path) -> int:
    src = ROOT / "src" / "veilmark"
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(src.rglob("*.py")):
            rel = f.relative_to(src.parent)
            if rel.parts[1] in EXCLUDE or "__pycache__" in rel.parts:
                continue
            z.write(f, rel.as_posix())
    return dest.stat().st_size


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()


def vendor(out: Path) -> int:
    pdir = out / "pyodide"
    pdir.mkdir(parents=True, exist_ok=True)
    total = 0
    for name in CORE_FILES:
        data = fetch(CDN + name)
        (pdir / name).write_bytes(data)
        total += len(data)
    lock = json.loads((pdir / "pyodide-lock.json").read_text())
    for pkg in PACKAGES:
        info = lock["packages"][pkg]
        data = fetch(CDN + info["file_name"])
        digest = hashlib.sha256(data).hexdigest()
        if digest != info["sha256"]:
            raise SystemExit(f"checksum mismatch for {info['file_name']}: {digest} != {info['sha256']}")
        (pdir / info["file_name"]).write_bytes(data)
        total += len(data)
    return total


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=ROOT / "dist" / "web")
    ap.add_argument("--vendor-pyodide", action="store_true", help="copy the Python runtime next to the app")
    args = ap.parse_args()
    out: Path = args.out
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    for name in STATIC:
        shutil.copy2(ROOT / "webapp" / name, out / name)
    size = build_zip(out / "veilmark.zip")
    cfg: dict[str, object] = {"pyodide_version": PYODIDE_VERSION}
    if args.vendor_pyodide:
        n = vendor(out)
        cfg["pyodide_base"] = "./pyodide/"
        print(f"vendored Pyodide runtime: {n / 1e6:.1f} MB")
    (out / "config.json").write_text(json.dumps(cfg, indent=2) + "\n")
    print(f"built {out} (engine zip {size / 1e3:.0f} kB)")
    print(f"preview: python -m http.server -d {out} 8000  ->  http://127.0.0.1:8000/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
