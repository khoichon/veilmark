"""Local web helper: a browser UI served from 127.0.0.1 only.

Security measures (the server can read keys and sign, so it must not be reachable by
other machines or by other web pages open in the same browser):

* binds to 127.0.0.1 only; no CORS headers are ever sent;
* every API call must carry a random per-session token (``X-Veilmark-Token``) that
  is embedded only in the page served to the user who started the server;
* the ``Host`` header must be ``127.0.0.1:<port>`` or ``localhost:<port>``
  (defeats DNS-rebinding);
* uploads are capped by the configured file-size limit, written to a private
  temporary directory, and removed after processing or at shutdown;
* processed files are downloadable once, then deleted.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import tempfile
import threading
import urllib.parse
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any

from veilmark import __version__
from veilmark.api import Veilmark, WatermarkSpec, media_type
from veilmark.crypto.keys import KeyStoreError
from veilmark.security.limits import InputError

SAFE_EXT = {
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".tif",
    ".tiff",
    ".bmp",
    ".mp4",
    ".mov",
    ".m4v",
    ".mkv",
    ".webm",
}


class _State:
    def __init__(self, vm: Veilmark, port: int) -> None:
        self.vm = vm
        self.port = port
        self.token = secrets.token_urlsafe(32)
        self.tmp = Path(tempfile.mkdtemp(prefix="veilmark-web-"))
        os.chmod(self.tmp, 0o700)
        self.downloads: dict[str, tuple[Path, str]] = {}
        self.lock = threading.Lock()
        self.busy = threading.Semaphore(2)  # bound concurrent media jobs


def _safe_name(name: str) -> str:
    base = Path(urllib.parse.unquote(name or "upload")).name
    keep = "".join(c for c in base if c.isalnum() or c in "._- ") or "upload"
    return keep[:120]


def make_handler(state: _State) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "Veilmark"
        sys_version = ""

        def log_message(self, fmt: str, *args: Any) -> None:  # quiet: no paths/payloads in logs
            return

        # -- helpers --------------------------------------------------------
        def _host_ok(self) -> bool:
            return self.headers.get("Host", "") in (f"127.0.0.1:{state.port}", f"localhost:{state.port}")

        def _authorised(self) -> bool:
            sent = self.headers.get("X-Veilmark-Token", "")
            return self._host_ok() and secrets.compare_digest(sent, state.token)

        def _send(self, code: int, body: bytes, ctype: str, extra: dict[str, str] | None = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; img-src 'self' blob: data:; "
                "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
            )
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, obj: Any) -> None:
            self._send(code, json.dumps(obj, default=str).encode(), "application/json")

        def _read_upload(self) -> Path:
            n = int(self.headers.get("Content-Length", "0"))
            if n <= 0:
                raise InputError("empty upload")
            if n > state.vm.limits.max_file_bytes:
                raise InputError("upload exceeds the configured size limit")
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            name = _safe_name(q.get("name", ["upload"])[0])
            if Path(name).suffix.lower() not in SAFE_EXT:
                raise InputError("unsupported file type")
            d = Path(tempfile.mkdtemp(dir=state.tmp))
            p = d / name
            with p.open("wb") as f:
                remaining = n
                while remaining:
                    chunk = self.rfile.read(min(1 << 20, remaining))
                    if not chunk:
                        raise InputError("upload interrupted")
                    f.write(chunk)
                    remaining -= len(chunk)
            return p

        def _params(self) -> dict[str, str]:
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            return {k: v[0] for k, v in q.items()}

        # -- routes ---------------------------------------------------------
        def do_GET(self) -> None:
            if not self._host_ok():
                self._send(HTTPStatus.FORBIDDEN, b"forbidden", "text/plain")
                return
            path = urllib.parse.urlparse(self.path).path
            if path == "/":
                html = resources.files("veilmark.web").joinpath("index.html").read_text("utf-8")
                html = html.replace("__TOKEN__", state.token).replace("__VERSION__", __version__)
                self._send(HTTPStatus.OK, html.encode(), "text/html; charset=utf-8")
                return
            if not self._authorised():
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "missing or invalid session token"})
                return
            if path == "/api/status":
                vm = state.vm
                self._json(
                    HTTPStatus.OK,
                    {
                        "version": __version__,
                        "identities": [
                            {
                                "key_id": i.key_id,
                                "label": i.label,
                                "encrypted": i.private.get("scheme") != "plaintext",
                            }
                            for i in vm.keystore.identities()
                            if i.status == "active"
                        ],
                        "pattern_keys": [
                            {"key_id": k.key_id, "label": k.label} for k in vm.keystore.pattern_keys()
                        ],
                        "trusted_issuers": len(vm.trust.issuers()),
                    },
                )
                return
            if path.startswith("/api/download/"):
                did = path.rsplit("/", 1)[-1]
                with state.lock:
                    item = state.downloads.pop(did, None)
                if item is None:
                    self._json(HTTPStatus.NOT_FOUND, {"error": "unknown or already downloaded"})
                    return
                p, name = item
                data = p.read_bytes()
                shutil.rmtree(p.parent, ignore_errors=True)
                self._send(
                    HTTPStatus.OK,
                    data,
                    "application/octet-stream",
                    {"Content-Disposition": f'attachment; filename="{_safe_name(name)}"'},
                )
                return
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_POST(self) -> None:
            if not self._authorised():
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "missing or invalid session token"})
                return
            path = urllib.parse.urlparse(self.path).path
            src: Path | None = None
            try:
                with state.busy:
                    src = self._read_upload()
                    if path == "/api/watermark":
                        self._json(HTTPStatus.OK, self._watermark(src))
                    elif path == "/api/detect":
                        self._json(HTTPStatus.OK, state.vm.detect(src).to_dict())
                    else:
                        self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            except (InputError, KeyStoreError, ValueError, OSError) as e:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(e)})
            except Exception as e:
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"{type(e).__name__}: {e}"})
            finally:
                if src is not None:
                    shutil.rmtree(src.parent, ignore_errors=True)

        def _watermark(self, src: Path) -> dict[str, Any]:
            p = self._params()
            ident = p.get("identity") or None
            spec = WatermarkSpec(
                text=p.get("text") or None,
                include_timestamp=p.get("timestamp", "1") == "1",
                sign=ident != "none",
                identity=None if ident in (None, "none") else ident,
                passphrase=self.headers.get("X-Veilmark-Passphrase") or None,
                strength=float(p.get("strength", "1.0")),
                quality=int(p.get("quality", "95")),
            )
            fmt = p.get("format", "same")
            ext = src.suffix if fmt == "same" else "." + fmt
            out_dir = Path(tempfile.mkdtemp(dir=state.tmp))
            out = out_dir / f"{src.stem}.wm{ext}"
            if media_type(src) == "video":
                res = state.vm.embed_video(src, out, spec, mode=p.get("mode", "robust"))
            else:
                res = state.vm.embed_image(src, out, spec)
            did = secrets.token_urlsafe(16)
            with state.lock:
                state.downloads[did] = (out, out.name)
            d = res.to_dict()
            d["output"] = out.name
            d["download"] = f"/api/download/{did}"
            return d

    return Handler


def serve(vm: Veilmark, port: int = 8765, open_browser: bool = True) -> None:
    state = _State(vm, port)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(state))
    url = f"http://127.0.0.1:{port}/"
    print(f"Veilmark web helper on {url} (local only; Ctrl+C to stop)")
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        shutil.rmtree(state.tmp, ignore_errors=True)
