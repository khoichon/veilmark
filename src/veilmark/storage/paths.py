"""Per-user data locations and safe file writing."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any


def data_home() -> Path:
    """Root directory for keys, trust lists, settings and plugin state.

    Override with ``VEILMARK_HOME`` (used by tests and portable installs).
    """
    env = os.environ.get("VEILMARK_HOME")
    if env:
        return Path(env).expanduser()
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Veilmark"
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / "Veilmark"
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "veilmark"


def ensure_dir(p: Path, private: bool = False) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    if private and os.name == "posix":
        os.chmod(p, 0o700)
    return p


def atomic_write_bytes(path: Path, data: bytes, private: bool = False) -> None:
    """Write via a temp file in the same directory, then rename (no torn files)."""
    ensure_dir(path.parent)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".veilmark-", suffix=".tmp")
    try:
        if private and os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def atomic_write_json(path: Path, obj: Any, private: bool = False) -> None:
    atomic_write_bytes(path, (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode(), private)


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text("utf-8"))
    except FileNotFoundError:
        return default
