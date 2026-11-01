import os
import time
from pathlib import Path

import nacl.signing
import pytest

from veilmark.crypto import keys, trust
from veilmark.crypto import payload as pl


@pytest.fixture
def store(tmp_path: Path) -> tuple[keys.KeyStore, trust.TrustStore]:
    return keys.KeyStore(tmp_path), trust.TrustStore(tmp_path)


def _signed(signer: nacl.signing.SigningKey, wid: bytes, **kw: object) -> tuple[pl.Payload, bytes]:
    p = trust.sign(wid, pl.Payload(text="hello", timestamp=int(time.time()), **kw), signer)  # type: ignore[arg-type]
    return pl.parse(p.to_bytes())


def test_encrypted_identity_roundtrip(store) -> None:
    ks, _ = store
    ident = ks.generate_identity("alice", "correct horse", fast_kdf=True)
    assert ident.private["scheme"] == "argon2id-secretbox"
    assert "seed" not in ident.private
    sk = ident.unlock("correct horse")
    assert bytes(sk.verify_key) == ident.public_bytes
    with pytest.raises(keys.KeyStoreError):
        ident.unlock("wrong")
    with pytest.raises(keys.KeyStoreError):
        ident.unlock(None)


def test_private_key_file_permissions(store, tmp_path: Path) -> None:
    ks, _ = store
    ident = ks.generate_identity("bob", None)
    f = tmp_path / "keys" / "signing" / f"{ident.key_id}.json"
    if os.name == "posix":
        assert (f.stat().st_mode & 0o777) == 0o600
        assert (f.parent.stat().st_mode & 0o777) == 0o700


def test_valid_trusted_signature(store) -> None:
    ks, ts = store
    ident = ks.generate_identity("alice", None)
    ts.add(ident.public_bytes, "alice")
    wid = os.urandom(8)
    p, body = _signed(ident.unlock(None), wid)
    v = trust.verify(wid, p, body, ts)
    assert (v.signature, v.trust, v.authentic) == ("valid", "trusted", True)


def test_altered_payload_fails(store) -> None:
    ks, ts = store
    ident = ks.generate_identity("alice", None)
    ts.add(ident.public_bytes, "alice")
    wid = os.urandom(8)
    p, _ = _signed(ident.unlock(None), wid)
    raw = bytearray(p.to_bytes())
    raw[raw.index(b"hello")] ^= 0x20  # 'hello' -> 'Hello'
    q, body = pl.parse(bytes(raw))
    v = trust.verify(wid, q, body, ts)
    assert v.signature == "invalid" and not v.authentic


def test_swapped_watermark_id_fails(store) -> None:
    ks, ts = store
    ident = ks.generate_identity("alice", None)
    ts.add(ident.public_bytes, "alice")
    p, body = _signed(ident.unlock(None), b"A" * 8)
    assert trust.verify(b"B" * 8, p, body, ts).signature == "invalid"


def test_untrusted_and_unknown_issuers(store) -> None:
    ks, ts = store
    ident = ks.generate_identity("mallory", None)
    wid = os.urandom(8)
    p, body = _signed(ident.unlock(None), wid)
    v = trust.verify(wid, p, body, ts)
    assert v.signature == "unknown-key" and not v.authentic
    v = trust.verify(wid, p, body, ts, extra_public_keys=[(ident.public_bytes, "mallory")])
    assert (v.signature, v.trust) == ("valid", "untrusted") and not v.authentic


def test_embedded_key_hint_is_not_trusted(store) -> None:
    """A forger reusing a trusted key's 4-byte id hint must still fail verification."""
    ks, ts = store
    good = ks.generate_identity("alice", None)
    ts.add(good.public_bytes, "alice")
    forger = nacl.signing.SigningKey.generate()
    wid = os.urandom(8)
    body = pl.Payload(
        text="fake", key_id=keys.fingerprint(good.public_bytes)[:4], signature=b"\0" * 64
    ).body()
    sig = forger.sign(pl.signing_message(wid, body)).signature
    p, b = pl.parse(body + sig)
    v = trust.verify(wid, p, b, ts)
    assert v.signature == "invalid" and not v.authentic


def test_revoked_and_expired(store) -> None:
    ks, ts = store
    ident = ks.generate_identity("alice", None)
    now = int(time.time())
    ts.add(ident.public_bytes, "alice", not_after=now - 10)
    wid = os.urandom(8)
    p, body = _signed(ident.unlock(None), wid)
    assert trust.verify(wid, p, body, ts).trust == "expired"
    ts.add(ident.public_bytes, "alice")
    ts.revoke("alice", at=now - 100)
    v = trust.verify(wid, p, body, ts)
    assert (v.signature, v.trust, v.authentic) == ("valid", "revoked", False)


def test_unsigned_payload(store) -> None:
    _, ts = store
    p, body = pl.parse(pl.Payload(text="x").to_bytes())
    v = trust.verify(b"\0" * 8, p, body, ts)
    assert v.signature == "unsigned" and not v.authentic


def test_rotation_retires_old_key(store) -> None:
    ks, ts = store
    old = ks.generate_identity("alice", None)
    retired, new = ks.rotate(None, None, None)
    assert retired.key_id == old.key_id and retired.status == "retired" and retired.replaced_by == new.key_id
    assert ks.identity().key_id == new.key_id  # newest active identity is the default
    # Signatures made before rotation still verify once the old key is trusted.
    ts.add(old.public_bytes, "alice-old")
    wid = os.urandom(8)
    p, body = _signed(old.unlock(None), wid)
    assert trust.verify(wid, p, body, ts).authentic


def test_retired_identity_cannot_sign_via_api(tmp_path: Path) -> None:
    from veilmark.api import Veilmark, WatermarkSpec

    vm = Veilmark(tmp_path)
    vm.keystore.generate_pattern_key()
    ident = vm.keystore.generate_identity("a", None)
    vm.keystore.set_status(ident.key_id, "retired")
    with pytest.raises(keys.KeyStoreError):
        vm.build_payload(WatermarkSpec(text="x", identity=ident.key_id), os.urandom(8))


def test_key_ids_stable() -> None:
    pub = bytes(range(32))
    assert keys.key_id(pub) == keys.fingerprint(pub)[:8].hex()
    assert len(keys.format_fingerprint(pub).split(":")) == 8


def test_trust_rejects_bad_key(store) -> None:
    _, ts = store
    with pytest.raises(ValueError):
        ts.add(b"short", "x")
