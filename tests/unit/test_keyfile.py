import json
from pathlib import Path

import pytest

from veilmark.crypto import keyfile, keys, trust


def test_roundtrip_and_header() -> None:
    b = keyfile.generate("Studio")
    b.trusted.append({"label": "partner", "public_key": keys.b64e(bytes(range(32)))})
    text = keyfile.encrypt(b, "correct horse battery", fast=True)
    assert "signing_seed" not in text and keys.b64e(b.signing_seed) not in text
    assert keyfile.peek(text)["label"] == "Studio"
    back = keyfile.decrypt(text, "correct horse battery")
    assert (
        back.signing_seed == b.signing_seed
        and back.pattern_key == b.pattern_key
        and back.trusted == b.trusted
    )


def test_wrong_passphrase_and_tampering() -> None:
    text = keyfile.encrypt(keyfile.generate("x"), "passphrase-1", fast=True)
    with pytest.raises(keyfile.KeyfileError):
        keyfile.decrypt(text, "passphrase-2")
    doc = json.loads(text)
    doc["public"]["label"] = "someone else"
    with pytest.raises(keyfile.KeyfileError, match="tampered"):
        keyfile.decrypt(json.dumps(doc), "passphrase-1")
    doc = json.loads(text)
    doc["encryption"]["memlimit"] = 2**40
    with pytest.raises(keyfile.KeyfileError, match="unreasonable"):
        keyfile.decrypt(json.dumps(doc), "passphrase-1")
    with pytest.raises(keyfile.KeyfileError):
        keyfile.encrypt(keyfile.generate("x"), "short")
    with pytest.raises(keyfile.KeyfileError):
        keyfile.peek("{}")


def test_store_roundtrip(tmp_path: Path) -> None:
    a_keys, a_trust = keys.KeyStore(tmp_path / "a"), trust.TrustStore(tmp_path / "a")
    a_keys.generate_pattern_key()
    ident = a_keys.generate_identity("alice", None)
    a_trust.add(ident.public_bytes, "alice")
    a_trust.add(bytes(range(32)), "partner")
    text = keyfile.encrypt(
        keyfile.bundle_from_store(a_keys, a_trust, None, None), "longpassphrase", fast=True
    )
    b_keys, b_trust = keys.KeyStore(tmp_path / "b"), trust.TrustStore(tmp_path / "b")
    added = keyfile.install_bundle(b_keys, b_trust, keyfile.decrypt(text, "longpassphrase"), None)
    assert added["identity"] == ident.key_id and added["trusted"] == 1
    assert b_keys.pattern_keys()[0].key_bytes == a_keys.pattern_keys()[0].key_bytes
    assert {i.label for i in b_trust.issuers()} == {"alice", "partner"}
    assert (
        keyfile.install_bundle(b_keys, b_trust, keyfile.decrypt(text, "longpassphrase"), None)["identity"]
        is None
    )
