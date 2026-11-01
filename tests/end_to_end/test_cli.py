"""End-to-end CLI workflows with exit codes and JSON output."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

from veilmark.cli import common
from veilmark.cli.main import main


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, synthetic_photo: np.ndarray) -> Path:
    monkeypatch.setenv("VEILMARK_PASSPHRASE", "e2e-passphrase")
    assert main(["keys", "init", "--label", "me"]) == 0
    Image.fromarray(synthetic_photo).save(tmp_path / "in.png")
    return tmp_path


def run_json(args: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, object]:
    code = main(["--json", *args])
    out = capsys.readouterr().out
    return code, json.loads(out) if out.strip() else None


def test_full_workflow(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    capsys.readouterr()
    code, res = run_json(
        ["watermark", "image", str(env / "in.png"), "-o", str(env / "out.png"), "--text", "hello cli"], capsys
    )
    assert code == 0 and res["signed"] and res["psnr_db"] > 36
    code, rep = run_json(["verify", str(env / "out.png")], capsys)
    assert code == common.EXIT_OK
    assert rep["status"] == "payload-recovered" and rep["authentic"] and rep["payload"]["text"] == "hello cli"
    assert rep["verification"]["signature"] == "valid" and rep["verification"]["trust"] == "trusted"
    code, rep = run_json(["detect", str(env / "in.png")], capsys)
    assert code == common.EXIT_NOT_DETECTED and rep["status"] == "not-detected"


def test_secrets_never_printed(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    capsys.readouterr()
    main(["keys", "list"])
    main(["keys", "export-public"])
    out = capsys.readouterr().out
    keydir = Path(env / "home" / "keys" / "pattern")
    secret = json.loads(next(keydir.glob("*.json")).read_text())["key"]
    assert secret not in out and "e2e-passphrase" not in out


def test_unsigned_fails_verify_but_passes_detect(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert (
        main(
            ["watermark", "image", str(env / "in.png"), "-o", str(env / "u.png"), "--text", "x", "--no-sign"]
        )
        == 0
    )
    capsys.readouterr()
    assert main(["detect", str(env / "u.png")]) == common.EXIT_OK
    assert main(["verify", str(env / "u.png")]) == common.EXIT_UNTRUSTED


def test_revoked_issuer_fails_verify(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["watermark", "image", str(env / "in.png"), "-o", str(env / "o.png"), "--text", "x"]) == 0
    assert main(["trust", "revoke", "me"]) == 0
    capsys.readouterr()
    code, rep = run_json(["verify", str(env / "o.png")], capsys)
    assert code == common.EXIT_UNTRUSTED and rep["verification"]["trust"] == "revoked"


def test_rotation_and_trust_import(env: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["keys", "rotate"]) == 0
    assert main(["keys", "export-public", "-o", str(tmp_path / "me.pub")]) == 0
    assert (
        main(
            [
                "--home",
                str(tmp_path / "verifier"),
                "trust",
                "add",
                str(tmp_path / "me.pub"),
                "--label",
                "partner",
            ]
        )
        == 0
    )
    capsys.readouterr()
    code, rows = run_json(["--home", str(tmp_path / "verifier"), "trust", "list"], capsys)
    assert code == 0 and rows[0]["label"] == "partner"


def test_batch_and_bad_input(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (env / "bad.png").write_bytes(b"not an image")
    code = main(
        [
            "watermark",
            "image",
            str(env / "in.png"),
            str(env / "bad.png"),
            "--out-dir",
            str(env / "batch"),
            "--text",
            "b",
            "--format",
            "jpg",
        ]
    )
    assert code == common.EXIT_USAGE  # one failure reported, the other still processed
    assert (env / "batch" / "in.wm.jpg").exists()
    assert main(["detect", str(env / "missing.png")]) == common.EXIT_USAGE


def test_refuses_to_overwrite_input(env: Path) -> None:
    assert (
        main(["watermark", "image", str(env / "in.png"), "-o", str(env / "in.png"), "--text", "x"])
        == common.EXIT_USAGE
    )


def test_doctor_and_capacity(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    capsys.readouterr()
    code, rep = run_json(["doctor"], capsys)
    assert rep["pattern_keys"] == 1 and rep["signing_identities"] == 1
    code, cap = run_json(["capacity", "--text", "x" * 200], capsys)
    assert code == common.EXIT_USAGE and cap["fits"] is False


def test_self_check_flags_unrecoverable_tiny_image(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rng = np.random.default_rng(0)
    tiny = (rng.normal(128, 30, (200, 260, 3))).clip(0, 255).astype(np.uint8)
    Image.fromarray(tiny).save(env / "tiny.png")
    capsys.readouterr()
    code, res = run_json(
        ["watermark", "image", str(env / "tiny.png"), "-o", str(env / "t.png"), "--text", "x" * 40], capsys
    )
    assert code == common.EXIT_PARTIAL
    assert res["extra"]["self_check"]["payload_recoverable"] is False
    assert any("SELF-CHECK FAILED" in n for n in res["notes"])


def test_cli_refuses_rewatermark(env: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["watermark", "image", str(env / "in.png"), "-o", str(env / "a.png"), "--text", "a"]) == 0
    capsys.readouterr()
    assert (
        main(["watermark", "image", str(env / "a.png"), "-o", str(env / "b.png"), "--text", "b"])
        == common.EXIT_USAGE
    )
    assert "already carries a Veilmark watermark" in capsys.readouterr().err
    assert (
        main(
            [
                "watermark",
                "image",
                str(env / "a.png"),
                "-o",
                str(env / "b.png"),
                "--text",
                "b",
                "--allow-rewatermark",
            ]
        )
        == 0
    )
