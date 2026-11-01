"""Local web helper: security checks and an upload round trip."""

from __future__ import annotations

import io
import json
import socket
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import numpy as np
import pytest
from PIL import Image

from veilmark.web.server import _State, make_handler


@pytest.fixture
def server(vm):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    state = _State(vm, port)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(state))
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield state, f"http://127.0.0.1:{port}"
    httpd.shutdown()
    httpd.server_close()


def _req(url: str, method: str = "GET", data: bytes | None = None, headers: dict[str, str] | None = None):
    r = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(r, timeout=120) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


def test_token_and_host_enforced(server) -> None:
    state, base = server
    code, body, _ = _req(base + "/")
    assert code == 200 and state.token.encode() in body
    assert _req(base + "/api/status")[0] == 401
    assert _req(base + "/api/status", headers={"X-Veilmark-Token": "wrong"})[0] == 401
    # DNS-rebinding style request with a foreign Host header
    assert _req(base + "/", headers={"Host": "evil.example:80"})[0] == 403
    code, _, hdrs = _req(base + "/api/status", headers={"X-Veilmark-Token": state.token})
    assert code == 200 and "Access-Control-Allow-Origin" not in hdrs


def test_watermark_then_detect_via_http(server, synthetic_photo: np.ndarray) -> None:
    state, base = server
    h = {"X-Veilmark-Token": state.token}
    buf = io.BytesIO()
    Image.fromarray(synthetic_photo).save(buf, "PNG")
    code, body, _ = _req(
        base + "/api/watermark?name=p.png&text=web%20test&format=png", "POST", buf.getvalue(), h
    )
    res = json.loads(body)
    assert code == 200, res
    code, data, _hdrs = _req(base + res["download"], headers=h)
    assert code == 200 and data.startswith(b"\x89PNG")
    assert _req(base + res["download"], headers=h)[0] == 404  # one-time download
    code, body, _ = _req(base + "/api/detect?name=w.png", "POST", data, h)
    rep = json.loads(body)
    assert rep["status"] == "payload-recovered" and rep["payload"]["text"] == "web test" and rep["authentic"]


def test_rejects_bad_uploads(server) -> None:
    state, base = server
    h = {"X-Veilmark-Token": state.token}
    assert _req(base + "/api/detect?name=x.exe", "POST", b"MZ....", h)[0] == 400
    assert _req(base + "/api/detect?name=../../x.png", "POST", b"notpng", h)[0] == 400
