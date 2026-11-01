"""Plugin discovery, validation, approval and loading.

Security model (read docs/plugins.md):

* In-process Python plugins can execute arbitrary code with the user's privileges.
  Permission declarations are *informational* and are shown to the user before
  approval; they are NOT a sandbox.
* Plugins are discovered by reading ``veilmark-plugin.json`` manifests only. Nothing
  is imported until the user explicitly enables a plugin.
* Enabling records a SHA-256 over every file in the plugin directory plus the
  declared permissions. If either changes, the plugin is refused until re-approved.
* The registration API handed to plugins exposes no keys, passphrases or trust
  store objects.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import shutil
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from veilmark.plugins.api import PluginAPI
from veilmark.storage import paths

API_VERSION = 1
SUPPORTED_API = {1}
MANIFEST = "veilmark-plugin.json"
KINDS = {"backend", "exporter", "metadata-provider", "key-registry", "batch"}
PERMISSION_KEYS = {"filesystem", "network", "media", "subprocess"}
FS_LEVELS = {"none", "read", "output-only", "read-write"}
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,40}$")
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+([.-][0-9A-Za-z.-]+)?$")
ENTRY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*:[A-Za-z_][A-Za-z0-9_]*$")


class PluginError(Exception):
    pass


@dataclass
class Manifest:
    name: str
    version: str
    api_version: int
    description: str
    entry: str
    kinds: list[str]
    permissions: dict[str, Any]
    author: str = ""
    homepage: str = ""


@dataclass
class PluginInfo:
    manifest: Manifest | None
    path: Path
    enabled: bool
    status: str  # ok | incompatible | invalid | modified | permissions-changed | not-approved
    problems: list[str] = field(default_factory=list)
    loaded: bool = False

    @property
    def name(self) -> str:
        return self.manifest.name if self.manifest else self.path.name

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": str(self.path),
            "enabled": self.enabled,
            "status": self.status,
            "problems": self.problems,
            "loaded": self.loaded,
            "manifest": asdict(self.manifest) if self.manifest else None,
        }


def validate_manifest(data: Any) -> tuple[Manifest | None, list[str]]:
    probs: list[str] = []
    if not isinstance(data, dict):
        return None, ["manifest is not a JSON object"]
    req = {
        "name": str,
        "version": str,
        "api_version": int,
        "description": str,
        "entry": str,
        "kinds": list,
        "permissions": dict,
    }
    for k, t in req.items():
        if k not in data:
            probs.append(f"missing field {k!r}")
        elif not isinstance(data[k], t) or (t is int and isinstance(data[k], bool)):
            probs.append(f"field {k!r} must be {t.__name__}")
    if probs:
        return None, probs
    unknown = set(data) - set(req) - {"author", "homepage"}
    if unknown:
        probs.append(f"unknown fields: {sorted(unknown)}")
    if not NAME_RE.match(data["name"]):
        probs.append("name must be lowercase letters, digits and dashes (2-41 chars)")
    if not VERSION_RE.match(data["version"]):
        probs.append("version must look like MAJOR.MINOR.PATCH")
    if not ENTRY_RE.match(data["entry"]):
        probs.append("entry must be 'module.path:function'")
    bad_kinds = [k for k in data["kinds"] if k not in KINDS]
    if bad_kinds or not data["kinds"]:
        probs.append(f"kinds must be a non-empty subset of {sorted(KINDS)}")
    perms = data["permissions"]
    if set(perms) - PERMISSION_KEYS:
        probs.append(f"unknown permissions: {sorted(set(perms) - PERMISSION_KEYS)}")
    if perms.get("filesystem", "none") not in FS_LEVELS:
        probs.append(f"filesystem permission must be one of {sorted(FS_LEVELS)}")
    for b in ("network", "media", "subprocess"):
        if b in perms and not isinstance(perms[b], bool):
            probs.append(f"permission {b!r} must be true/false")
    if len(data["description"]) > 500:
        probs.append("description too long")
    m = Manifest(**{k: data[k] for k in data if k in Manifest.__dataclass_fields__})
    return (m if not probs else None), probs


def tree_hash(root: Path) -> str:
    """SHA-256 over relative paths and contents of every regular file (sorted)."""
    h = hashlib.sha256()
    for f in sorted(p for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts):
        rel = f.relative_to(root).as_posix().encode()
        h.update(len(rel).to_bytes(4, "big") + rel)
        data = f.read_bytes()
        h.update(len(data).to_bytes(8, "big") + data)
    return h.hexdigest()


class PluginManager:
    def __init__(self, home: Path | None = None) -> None:
        self.home = home or paths.data_home()
        self.dir = self.home / "plugins"
        self.state_path = self.home / "plugins.json"
        self.api = PluginAPI()
        self._loaded: dict[str, Any] = {}

    # -- state -------------------------------------------------------------
    def _state(self) -> dict[str, Any]:
        return paths.read_json(self.state_path, {})

    def _save(self, st: dict[str, Any]) -> None:
        paths.atomic_write_json(self.state_path, st)

    # -- discovery (never imports) ------------------------------------------
    def discover(self) -> list[PluginInfo]:
        out: list[PluginInfo] = []
        st = self._state()
        if not self.dir.exists():
            return out
        for d in sorted(p for p in self.dir.iterdir() if p.is_dir()):
            out.append(self._inspect(d, st))
        return out

    def _inspect(self, d: Path, st: dict[str, Any]) -> PluginInfo:
        mf = d / MANIFEST
        if not mf.is_file():
            return PluginInfo(None, d, False, "invalid", [f"no {MANIFEST}"])
        try:
            data = json.loads(mf.read_text("utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            return PluginInfo(None, d, False, "invalid", [f"manifest unreadable: {e}"])
        m, probs = validate_manifest(data)
        if m is None:
            return PluginInfo(None, d, False, "invalid", probs)
        if m.name != d.name:
            return PluginInfo(m, d, False, "invalid", ["directory name must equal plugin name"])
        entry = st.get(m.name, {})
        enabled = bool(entry.get("enabled"))
        if m.api_version not in SUPPORTED_API:
            return PluginInfo(
                m,
                d,
                enabled,
                "incompatible",
                [f"plugin targets API v{m.api_version}; this Veilmark supports {sorted(SUPPORTED_API)}"],
            )
        if not enabled:
            return PluginInfo(m, d, False, "not-approved" if not entry else "ok")
        if entry.get("hash") != tree_hash(d):
            return PluginInfo(
                m, d, True, "modified", ["plugin files changed since approval; re-enable to approve"]
            )
        if entry.get("permissions") != m.permissions:
            return PluginInfo(
                m, d, True, "permissions-changed", ["declared permissions changed; re-enable to approve"]
            )
        return PluginInfo(m, d, True, "ok", [], m.name in self._loaded)

    def get(self, name: str) -> PluginInfo:
        for p in self.discover():
            if p.name == name:
                return p
        raise PluginError(f"plugin {name!r} not found in {self.dir}")

    # -- lifecycle ---------------------------------------------------------
    def install(self, src: Path, confirm: Callable[[Manifest], bool]) -> PluginInfo:
        """Copy a plugin directory into the plugins folder (left disabled)."""
        src = Path(src)
        mf = src / MANIFEST
        if not mf.is_file():
            raise PluginError(f"{src} has no {MANIFEST}")
        m, probs = validate_manifest(json.loads(mf.read_text("utf-8")))
        if m is None:
            raise PluginError("invalid manifest: " + "; ".join(probs))
        if not confirm(m):
            raise PluginError("installation not confirmed")
        dst = paths.ensure_dir(self.dir) / m.name
        if dst.exists():
            raise PluginError(f"plugin {m.name!r} already installed; remove it first")
        shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        return self._inspect(dst, self._state())

    def enable(self, name: str, confirm: Callable[[Manifest], bool]) -> PluginInfo:
        info = self.get(name)
        if info.manifest is None or info.status in ("invalid", "incompatible"):
            raise PluginError(f"cannot enable {name}: " + "; ".join(info.problems))
        if not confirm(info.manifest):
            raise PluginError("not enabled: user did not approve")
        st = self._state()
        st[name] = {
            "enabled": True,
            "hash": tree_hash(info.path),
            "permissions": info.manifest.permissions,
            "version": info.manifest.version,
        }
        self._save(st)
        return self.get(name)

    def disable(self, name: str) -> None:
        st = self._state()
        if name not in st:
            st[name] = {}
        st[name]["enabled"] = False
        self._save(st)
        self._loaded.pop(name, None)
        self.api.unregister_plugin(name)

    def remove(self, name: str) -> None:
        info = self.get(name)
        self.disable(name)
        shutil.rmtree(info.path)
        st = self._state()
        st.pop(name, None)
        self._save(st)

    # -- loading -----------------------------------------------------------
    def load_enabled(self) -> list[PluginInfo]:
        """Import every enabled, approved, unmodified plugin; returns their info."""
        results = []
        for info in self.discover():
            if not info.enabled:
                continue
            if info.status != "ok" or info.manifest is None:
                results.append(info)
                continue
            try:
                self._load(info)
                info.loaded = True
            except Exception as e:
                info.status = "load-error"
                info.problems.append(f"{type(e).__name__}: {e}")
                self.api.unregister_plugin(info.name)
            results.append(info)
        return results

    def _load(self, info: PluginInfo) -> None:
        assert info.manifest is not None
        if info.name in self._loaded:
            return
        mod_path, func = info.manifest.entry.split(":")
        rel = Path(*mod_path.split("."))
        candidates = [info.path / (str(rel) + ".py"), info.path / rel / "__init__.py"]
        file = next((c for c in candidates if c.is_file()), None)
        if file is None:
            raise PluginError(f"entry module {mod_path!r} not found")
        if not file.resolve().is_relative_to(info.path.resolve()):
            raise PluginError("entry module escapes the plugin directory")
        modname = f"veilmark_plugin_{info.name.replace('-', '_')}"
        spec = importlib.util.spec_from_file_location(
            modname,
            file,
            submodule_search_locations=[str(file.parent)] if file.name == "__init__.py" else None,
        )
        if spec is None or spec.loader is None:
            raise PluginError("cannot create import spec")
        module = importlib.util.module_from_spec(spec)
        sys.modules[modname] = module
        spec.loader.exec_module(module)
        register = getattr(module, func, None)
        if not callable(register):
            raise PluginError(f"entry function {func!r} not found")
        with self.api.scope(info.name, set(info.manifest.kinds)):
            register(self.api)
        self._loaded[info.name] = module
