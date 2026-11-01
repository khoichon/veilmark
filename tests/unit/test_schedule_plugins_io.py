import json
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

from veilmark.image import io as image_io
from veilmark.plugins.manager import PluginError, PluginManager, tree_hash, validate_manifest
from veilmark.security.limits import InputError, check_output_path
from veilmark.video.schedule import Schedule

# ------------------------------------------------------------------ schedule


def test_schedule_is_deterministic_energy_preserving_and_moves() -> None:
    a = Schedule(bytes(32), b"\x01" * 8, 30.0)
    b = Schedule(bytes(32), b"\x01" * 8, 30.0)
    c = Schedule(bytes(32), b"\x02" * 8, 30.0)
    wa = [a.weights(i) for i in range(900)]
    assert wa == [b.weights(i) for i in range(900)]
    assert wa != [c.weights(i) for i in range(900)]  # per-watermark schedule
    for w in wa:
        assert abs(sum(x * x for x in w.values()) - 1.0) < 1e-9
    dominant = [max(w, key=w.get) for w in wa]
    changes = [i for i in range(1, 900) if dominant[i] != dominant[i - 1]]
    assert len(changes) >= 15  # moves at least every ~1.2 s at 30 fps
    assert all(dominant[i] != dominant[i - 1] for i in changes)  # never repeats
    gaps = np.diff(changes)
    assert len(set(gaps.tolist())) > 3  # segment lengths are not periodic
    assert len(set(dominant)) == 8


def test_schedule_crossfades() -> None:
    s = Schedule(bytes(32), bytes(8), 30.0)
    assert any(len(s.weights(i)) == 2 for i in range(200))


# ------------------------------------------------------------------ plugins


def _write_plugin(
    root: Path, name: str = "demo-exporter", side_effect: Path | None = None, **over: object
) -> Path:
    d = root / name
    d.mkdir(parents=True)
    manifest = {
        "name": name,
        "version": "1.0.0",
        "api_version": 1,
        "description": "test plugin",
        "entry": "plugin:register",
        "kinds": ["exporter"],
        "permissions": {"filesystem": "none", "network": False},
    }
    manifest.update(over)
    (d / "veilmark-plugin.json").write_text(json.dumps(manifest))
    marker = f"open({str(side_effect)!r}, 'w').write('imported')\n" if side_effect else ""
    (d / "plugin.py").write_text(
        marker
        + "def register(api):\n"
        + "    api.register_exporter('txt', lambda rep: (rep['status'].encode(), 'txt'))\n"
    )
    return d


def test_manifest_validation() -> None:
    ok, probs = validate_manifest(
        {
            "name": "x-y",
            "version": "1.2.3",
            "api_version": 1,
            "description": "d",
            "entry": "a.b:c",
            "kinds": ["exporter"],
            "permissions": {"network": False},
        }
    )
    assert ok and not probs
    _, probs = validate_manifest(
        {
            "name": "Bad Name",
            "version": "1",
            "api_version": 1,
            "description": "",
            "entry": "nope",
            "kinds": ["rootkit"],
            "permissions": {"camera": True},
        }
    )
    assert len(probs) >= 4


def test_discovery_never_imports_and_enable_requires_approval(tmp_path: Path) -> None:
    pm = PluginManager(tmp_path)
    marker = tmp_path / "imported.txt"
    _write_plugin(pm.dir, side_effect=marker)
    infos = pm.discover()
    assert [i.name for i in infos] == ["demo-exporter"] and infos[0].status == "not-approved"
    assert pm.load_enabled() == []
    assert not marker.exists()  # nothing imported merely by being present
    with pytest.raises(PluginError):
        pm.enable("demo-exporter", lambda m: False)
    assert not marker.exists()
    pm.enable("demo-exporter", lambda m: True)
    loaded = pm.load_enabled()
    assert loaded[0].loaded and marker.exists()
    assert pm.api.exporters["txt"][1]({"status": "ok"}) == (b"ok", "txt")
    pm.disable("demo-exporter")
    assert "txt" not in pm.api.exporters
    assert PluginManager(tmp_path).load_enabled() == []


def test_modified_plugin_is_refused(tmp_path: Path) -> None:
    pm = PluginManager(tmp_path)
    d = _write_plugin(pm.dir)
    pm.enable("demo-exporter", lambda m: True)
    h = tree_hash(d)
    (d / "plugin.py").write_text((d / "plugin.py").read_text() + "\n# tampered\n")
    assert tree_hash(d) != h
    info = PluginManager(tmp_path).get("demo-exporter")
    assert info.status == "modified"
    assert PluginManager(tmp_path).load_enabled()[0].loaded is False


def test_incompatible_and_undeclared_kind(tmp_path: Path) -> None:
    pm = PluginManager(tmp_path)
    _write_plugin(pm.dir, "future", api_version=99)
    assert pm.get("future").status == "incompatible"
    with pytest.raises(PluginError):
        pm.enable("future", lambda m: True)
    _write_plugin(pm.dir, "sneaky", kinds=["metadata-provider"])  # registers an exporter anyway
    pm.enable("sneaky", lambda m: True)
    res = {i.name: i for i in pm.load_enabled()}
    assert res["sneaky"].status == "load-error" and "did not declare" in res["sneaky"].problems[0]


def test_install_and_remove(tmp_path: Path) -> None:
    src = _write_plugin(tmp_path / "src")
    pm = PluginManager(tmp_path / "home")
    with pytest.raises(PluginError):
        pm.install(src, lambda m: False)
    info = pm.install(src, lambda m: True)
    assert info.enabled is False
    pm.remove("demo-exporter")
    assert pm.discover() == []


# ------------------------------------------------------------------ image io / limits


def test_alpha_preserved_and_no_overwrite(tmp_path: Path) -> None:
    rgba = np.zeros((300, 400, 4), np.uint8)
    rgba[..., :3] = 120
    rgba[..., 3] = np.linspace(0, 255, 400, dtype=np.uint8)[None, :]
    src = tmp_path / "a.png"
    Image.fromarray(rgba, "RGBA").save(src)
    img = image_io.load(src)
    assert img.alpha is not None and np.array_equal(img.alpha, rgba[..., 3])
    image_io.save(img, tmp_path / "b.png")
    assert np.array_equal(np.asarray(Image.open(tmp_path / "b.png"))[..., 3], rgba[..., 3])
    with pytest.raises(InputError):
        check_output_path(src, src)
    with pytest.raises(InputError):
        check_output_path(src, tmp_path / "b.png")  # exists, no overwrite
    check_output_path(src, tmp_path / "b.png", overwrite=True)


def test_corrupt_and_empty_inputs(tmp_path: Path) -> None:
    bad = tmp_path / "bad.jpg"
    bad.write_bytes(b"\xff\xd8\xff\xe0garbage" * 10)
    with pytest.raises(InputError):
        image_io.load(bad)
    empty = tmp_path / "empty.png"
    empty.write_bytes(b"")
    with pytest.raises(InputError):
        image_io.load(empty)
    with pytest.raises(InputError):
        image_io.load(tmp_path / "missing.png")


def test_pixel_limit(tmp_path: Path) -> None:
    from veilmark.security.limits import Limits

    p = tmp_path / "big.png"
    Image.new("RGB", (400, 400)).save(p)
    with pytest.raises(InputError):
        image_io.load(p, Limits(max_image_pixels=1000))


def test_stale_tempfile_cleanup(tmp_path: Path) -> None:
    import os
    import time

    from veilmark.security import tempfiles

    old = tmp_path / ".veilmark-abc.partial.mp4"
    fresh = tmp_path / ".veilmark-def.tmp"
    unrelated = tmp_path / "notes.tmp"
    for f in (old, fresh, unrelated):
        f.write_text("x")
    past = time.time() - 7200
    os.utime(old, (past, past))
    os.utime(unrelated, (past, past))
    stale = tempfiles.find_stale([tmp_path], older_than_hours=1.0)
    assert stale == [old]
    tempfiles.remove(stale)
    assert not old.exists() and fresh.exists() and unrelated.exists()


def test_metadata_provider_plugin_via_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from veilmark.cli.main import main

    home = tmp_path / "home"
    monkeypatch.setenv("VEILMARK_HOME", str(home))
    assert main(["keys", "init", "--no-passphrase"]) == 0
    d = home / "plugins" / "asset-id"
    d.mkdir(parents=True)
    (d / "veilmark-plugin.json").write_text(
        json.dumps(
            {
                "name": "asset-id",
                "version": "0.1.0",
                "api_version": 1,
                "description": "asset ids",
                "entry": "plugin:register",
                "kinds": ["metadata-provider"],
                "permissions": {"filesystem": "read"},
            }
        )
    )
    (d / "plugin.py").write_text(
        "def register(api):\n    api.register_metadata_provider('asset', lambda p: b'ASSET:' + p.encode()[-6:])\n"
    )
    assert main(["plugins", "enable", "asset-id", "--yes"]) == 0
    img = tmp_path / "img.png"
    Image.fromarray(np.full((400, 600, 3), 128, np.uint8)).save(img)
    out = tmp_path / "o.png"
    assert (
        main(["watermark", "image", str(img), "-o", str(out), "--meta-provider", "asset", "--no-sign"]) == 0
    )
