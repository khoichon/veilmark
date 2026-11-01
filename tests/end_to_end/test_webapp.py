"""The web app's Python bridge, exercised under CPython (the same code runs in Pyodide),
plus the static build."""

from __future__ import annotations

import importlib.util
import io
import json
import re
import subprocess
import sys
import zipfile
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def bridge():
    spec = importlib.util.spec_from_file_location("veilmark_bridge_test", ROOT / "webapp" / "bridge.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    yield mod
    mod.forget_keys()


def _png(rgb: np.ndarray) -> bytes:
    buf = io.BytesIO()
    Image.fromarray(rgb).save(buf, "PNG")
    return buf.getvalue()


def test_keys_lifecycle(bridge) -> None:
    assert bridge.status()["has_keys"] is False
    st = bridge.generate_keys("Web Studio")
    assert st["has_keys"] and st["label"] == "Web Studio" and st["trusted"][0]["own"]
    text = bridge.save_keyfile("long passphrase")
    assert json.loads(text)["public"]["label"] == "Web Studio"
    bridge.forget_keys()
    assert bridge.status()["has_keys"] is False
    with pytest.raises(ValueError, match="wrong passphrase"):
        bridge.load_keyfile(text, "not the passphrase")
    assert bridge.load_keyfile(text, "long passphrase")["key_id"] == st["key_id"]


def test_embed_detect_roundtrip(bridge, synthetic_photo: np.ndarray) -> None:
    bridge.generate_keys("Web Studio")
    seen = []
    res = bridge.embed(
        _png(synthetic_photo),
        "photo.png",
        "hello web",
        "balanced",
        "jpg",
        92,
        True,
        True,
        lambda f, m: seen.append(f),
    )
    r = res["result"]
    assert r["output_name"] == "photo.wm.jpg" and r["mime"] == "image/jpeg"
    assert r["extra"]["self_check"]["payload_recoverable"] is True
    assert len(seen) > 10 and seen[-1] == 1.0
    rep = bridge.detect(res["output"], "photo.wm.jpg", True)
    assert rep["status"] == "payload-recovered" and rep["payload"]["text"] == "hello web" and rep["authentic"]
    assert bridge.detect(_png(synthetic_photo), "orig.png", False)["status"] == "not-detected"


def test_shared_keys_between_people(bridge, synthetic_photo: np.ndarray) -> None:
    """Alice watermarks; Bob verifies with her public key and shared pattern key."""
    bridge.generate_keys("Alice")
    alice = bridge.status()
    pattern = bridge.export_pattern_line()
    out = bridge.embed(_png(synthetic_photo), "a.png", "by alice", "balanced", "png", 92, True, False)[
        "output"
    ]
    bridge.generate_keys("Bob")
    rep = bridge.detect(out, "a.png", False)
    assert rep["status"] == "not-detected"  # Bob lacks Alice's pattern key
    bridge.add_pattern_key(pattern, "alice")
    rep = bridge.detect(out, "a.png", False)
    assert rep["verification"]["signature"] == "unknown-key" and not rep["authentic"]
    bridge.add_trusted(alice["public_line"], "")
    rep = bridge.detect(out, "a.png", False)
    assert rep["authentic"] and rep["verification"]["issuer_label"] == "Alice"


def test_verify_without_own_keys(bridge, synthetic_photo: np.ndarray) -> None:
    """A verifier needs only the issuer's pattern key and public key, no keys of their own."""
    bridge.generate_keys("Alice")
    alice = bridge.status()
    pattern = bridge.export_pattern_line()
    out = bridge.embed(_png(synthetic_photo), "a.png", "by alice", "balanced", "png", 92, True, False)[
        "output"
    ]
    st = bridge.forget_keys()
    assert not st["has_keys"] and not st["pattern_keys"]
    with pytest.raises(ValueError, match="your keys first"):
        bridge.export_pattern_line()  # nothing of your own to share
    st = bridge.add_pattern_key(pattern, "")
    assert not st["has_keys"] and len(st["pattern_keys"]) == 1
    rep = bridge.detect(out, "a.png", False)
    assert rep["payload"]["text"] == "by alice"  # text readable without the public key
    assert rep["verification"]["signature"] == "unknown-key" and not rep["authentic"]
    bridge.add_trusted(alice["public_line"], "")
    rep = bridge.detect(out, "a.png", False)
    assert rep["authentic"] and rep["verification"]["issuer_label"] == "Alice"


def test_public_watermark_in_browser_bridge(bridge, synthetic_photo: np.ndarray) -> None:
    """Public watermark: a verifier with only the issuer's public key can detect and verify."""
    alice = bridge.generate_keys("Alice")
    out = bridge.embed(
        _png(synthetic_photo), "a.png", "public", "balanced", "png", 92, True, False, None, False, True
    )["output"]
    st = bridge.forget_keys()
    assert not st["can_detect"]
    with pytest.raises(ValueError, match="public key"):
        bridge.detect(out, "a.png", False)
    st = bridge.add_trusted(alice["public_line"], "")
    assert st["can_detect"] and not st["has_keys"]
    rep = bridge.detect(out, "a.png", False)
    assert rep["authentic"] and rep["payload"]["text"] == "public"
    assert rep["diagnostics"]["publicly_verifiable"]


def test_shared_key_names_keep_spaces(bridge) -> None:
    alice = bridge.generate_keys("Studio North Ltd")
    pattern = bridge.export_pattern_line()
    bridge.forget_keys()
    st = bridge.add_trusted(alice["public_line"], "")
    assert [t["label"] for t in st["trusted"]] == ["Studio North Ltd"]
    st = bridge.add_pattern_key(pattern, "")
    assert [k["label"] for k in st["pattern_keys"]] == ["Studio North Ltd"]


def test_own_pattern_key_stays_default(bridge) -> None:
    """Shared pattern keys added right after your own must not displace it."""
    bridge.generate_keys("Alice")
    alice_pattern = bridge.export_pattern_line()
    bridge.generate_keys("Bob")
    bob_pattern = bridge.export_pattern_line()
    bridge.add_pattern_key(alice_pattern, "alice")  # same second as Bob's own key
    assert bridge.export_pattern_line() == bob_pattern


def test_bad_inputs(bridge) -> None:
    with pytest.raises(ValueError, match="keys first"):
        bridge.embed(b"x", "x.png", "", "balanced", "png", 92, True, False)
    bridge.generate_keys("x")
    with pytest.raises(ValueError, match="cannot read"):
        bridge.embed(b"not an image", "x.png", "", "balanced", "png", 92, True, False)
    with pytest.raises(ValueError):
        bridge.add_trusted("garbage!!", "")


def test_static_build(tmp_path: Path) -> None:
    out = tmp_path / "web"
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "build_webapp.py"), "--out", str(out)],
        check=True,
        capture_output=True,
    )
    for name in (
        "index.html",
        "app.js",
        "worker.js",
        "bridge.py",
        "style.css",
        "config.json",
        "veilmark.zip",
    ):
        assert (out / name).is_file()
    # Asset references carry a build version so browsers never mix cached deploys.
    assert re.search(r'src="app\.js\?v=[0-9a-f]{12}"', (out / "index.html").read_text())
    assert re.search(r'new Worker\("worker\.js\?v=[0-9a-f]{12}"', (out / "app.js").read_text())
    assert (out / "worker.js").read_text().count("?v=") == 2
    names = zipfile.ZipFile(out / "veilmark.zip").namelist()
    assert "veilmark/api.py" in names and not any(
        n.startswith(("veilmark/app/", "veilmark/cli/")) for n in names
    )


def test_bridge_refuses_rewatermark(bridge, synthetic_photo: np.ndarray) -> None:
    bridge.generate_keys("x")
    out = bridge.embed(_png(synthetic_photo), "a.png", "one", "balanced", "png", 92, True, False)["output"]
    with pytest.raises(ValueError, match="already carries"):
        bridge.embed(out, "a.png", "two", "balanced", "png", 92, True, False)
    res = bridge.embed(out, "a.png", "two", "balanced", "png", 92, True, False, None, True)
    rep = bridge.detect(res["output"], "b.png", False)
    texts = {rep["payload"]["text"]} | {a["payload"]["text"] for a in rep["additional_watermarks"]}
    assert texts == {"one", "two"}
