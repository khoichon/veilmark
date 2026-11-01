"""The registration API handed to plugins (version 1).

Plugins receive a :class:`PluginAPI` instance in their entry function and may only
register the kinds they declared in their manifest. No signing keys, pattern keys,
passphrases or trust-store objects are reachable through this API.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

from veilmark.watermark import backends

# report dict -> (file bytes, file extension without dot)
Exporter = Callable[[dict[str, Any]], tuple[bytes, str]]
# media path -> metadata bytes to embed (<= 120 bytes)
MetadataProvider = Callable[[str], bytes]


class PluginAPI:
    version = 1

    def __init__(self) -> None:
        self.exporters: dict[str, tuple[str, Exporter]] = {}
        self.metadata_providers: dict[str, tuple[str, MetadataProvider]] = {}
        self.backends: dict[str, str] = {}
        self._current: str | None = None
        self._kinds: set[str] = set()

    @contextmanager
    def scope(self, plugin: str, kinds: set[str]) -> Iterator[None]:
        self._current, self._kinds = plugin, kinds
        try:
            yield
        finally:
            self._current, self._kinds = None, set()

    def _require(self, kind: str) -> str:
        if self._current is None:
            raise RuntimeError("registration is only allowed while a plugin is loading")
        if kind not in self._kinds:
            raise PermissionError(f"plugin {self._current!r} did not declare kind {kind!r}")
        return self._current

    def register_exporter(self, name: str, fn: Exporter) -> None:
        owner = self._require("exporter")
        if name in self.exporters:
            raise ValueError(f"exporter {name!r} already registered")
        self.exporters[name] = (owner, fn)

    def register_metadata_provider(self, name: str, fn: MetadataProvider) -> None:
        owner = self._require("metadata-provider")
        self.metadata_providers[name] = (owner, fn)

    def register_backend(self, backend: backends.ImageBackend) -> None:
        owner = self._require("backend")
        backends.register(backend)
        self.backends[backend.info.name] = owner

    def unregister_plugin(self, plugin: str) -> None:
        for reg in (self.exporters, self.metadata_providers):
            for k in [k for k, (o, _) in reg.items() if o == plugin]:
                reg.pop(k)
        for k in [k for k, o in self.backends.items() if o == plugin]:
            backends.unregister(k)
            self.backends.pop(k)
