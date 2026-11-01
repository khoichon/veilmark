"""Discovery of stale temporary files left by interrupted runs.

Veilmark writes outputs to ``.veilmark-*.partial*`` / ``.veilmark-*.tmp`` files in
the destination folder and renames them atomically on success; interrupted runs
delete them. Only a crash (power loss, SIGKILL) can leave them behind. Benchmark
scratch folders are named ``veilmark-bench-*`` inside the system temp directory.
"""

from __future__ import annotations

import shutil
import tempfile
import time
from pathlib import Path


def find_stale(dirs: list[Path] | None = None, older_than_hours: float = 1.0) -> list[Path]:
    cutoff = time.time() - older_than_hours * 3600
    dirs = dirs or [Path(tempfile.gettempdir())]
    out: list[Path] = []
    for d in dirs:
        if not d.is_dir():
            continue
        for f in d.glob(".veilmark-*"):
            is_temp = f.suffix == ".tmp" or ".partial" in f.name
            if f.is_file() and is_temp and f.stat().st_mtime < cutoff:
                out.append(f)
        for f in d.glob("veilmark-bench-*"):
            if f.is_dir() and f.stat().st_mtime < cutoff:
                out.append(f)
    return out


def remove(paths: list[Path]) -> int:
    n = 0
    for p in paths:
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
        else:
            p.unlink(missing_ok=True)
        n += 1
    return n
