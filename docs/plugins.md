# Plugins

Veilmark works fully without plugins. Plugins add exporters, metadata providers or
image watermark backends through a small, versioned API.

## Security model — read this first

* **An in-process Python plugin can execute arbitrary code with your user privileges**
  (read your keys, files, the network). Permission declarations in the manifest are
  shown to you before approval but are **not enforced**; they are not a sandbox.
* Plugins are **discovered by reading manifests only**. Nothing is imported merely
  because it sits in the plugins folder (tested).
* Enabling requires explicit confirmation and records a SHA-256 over every file in the
  plugin directory plus its declared permissions. If either changes, the plugin is
  refused until you approve it again (tested).
* The registration API exposes no keys, passphrases or trust-store objects, and a
  plugin may only register the kinds it declared.
* Veilmark never installs plugins from the network and has no marketplace.

## Layout

```
<data home>/plugins/<name>/
    veilmark-plugin.json
    plugin.py            (or a package directory)
```

```json
{
  "name": "markdown-report",
  "version": "1.0.0",
  "api_version": 1,
  "description": "Exports detection/verification reports as Markdown documents.",
  "entry": "plugin:register",
  "kinds": ["exporter"],
  "permissions": {"filesystem": "none", "network": false, "media": false, "subprocess": false},
  "author": "Veilmark example"
}
```

Rules: `name` = lowercase letters/digits/dashes and equal to the directory name;
`version` = MAJOR.MINOR.PATCH; `entry` = `module:function` inside the plugin directory;
`kinds` ⊆ {`backend`, `exporter`, `metadata-provider`, `key-registry`, `batch`};
`permissions` keys ⊆ {`filesystem` (`none|read|output-only|read-write`), `network`,
`media`, `subprocess`}. Unknown fields are rejected. `api_version` must be supported
(currently `1`); otherwise the plugin is listed as *incompatible* with an explanation.

## API v1

```python
def register(api):                      # called once when the enabled plugin loads
    api.register_exporter(name, fn)     # fn(report_dict) -> (bytes, extension)
    api.register_metadata_provider(name, fn)   # fn(media_path) -> bytes (<= 120)
    api.register_backend(backend)       # object implementing watermark.backends.ImageBackend
```

`ImageBackend` declares a `BackendInfo` (media types, payload capacity, robust_to /
not_robust_to, compute cost, limitations, experimental flag) and implements
`embed_luma_delta(...)` and `detect_luma(...)`. Signing, payload format and trust stay
outside the backend, so any backend gets authenticated payloads for free.

`key-registry` and `batch` kinds are reserved names in API v1 (accepted in manifests,
no registration hook yet).

## Commands

```
veilmark plugins list
veilmark plugins info NAME
veilmark plugins install PATH [--yes]     # copies into the plugins folder, disabled
veilmark plugins enable NAME [--yes]      # shows manifest + warning, pins hash
veilmark plugins disable NAME
veilmark plugins remove NAME [--yes]
veilmark detect FILE --export markdown    # use a plugin exporter
```

The GUI *Plugins* tab offers the same operations with the same confirmations.

## Example

`examples/plugins/markdown-report/` is a complete exporter plugin.

## Future: isolated plugins

Strong isolation requires running plugins in a separate process with a restricted IPC
protocol (e.g. JSON over stdin/stdout, media passed as files the user selected, no
inherited environment, OS sandboxing where available). This is designed for but not
implemented in this release; until then, only enable plugins you would be willing to
run as ordinary programs.
