"""Key material: Ed25519 signing identities and symmetric pattern keys.

* **Signing identities** sign payloads. Private keys are stored encrypted with a
  passphrase (Argon2id key derivation + XSalsa20-Poly1305 via libsodium/PyNaCl).
  Unencrypted storage requires an explicit opt-in.
* **Pattern keys** (32 random bytes) seed the secret embedding pattern. Anyone who
  holds a pattern key can *detect* (and therefore attempt to remove or forge the
  presence of) watermarks made with it, so it is a secret shared only with
  authorised detectors. Pattern keys never sign anything; authenticity always comes
  from Ed25519 signatures.
"""

from __future__ import annotations

import base64
import hashlib
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

import nacl.exceptions
import nacl.pwhash
import nacl.secret
import nacl.signing
import nacl.utils

from veilmark.crypto import kdf
from veilmark.storage import paths

FINGERPRINT_DOMAIN = b"veilmark/keyid/v1\x00"


class KeyStoreError(Exception):
    """Key store problem (missing key, wrong passphrase, invalid state)."""


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


def fingerprint(public_key: bytes) -> bytes:
    """32-byte fingerprint; the first 4 bytes are the in-band key id hint."""
    return hashlib.sha256(FINGERPRINT_DOMAIN + public_key).digest()


def key_id(public_key: bytes) -> str:
    """Human-facing key id: first 8 bytes of the fingerprint, hex."""
    return fingerprint(public_key)[:8].hex()


def pattern_key_id(key: bytes) -> str:
    return hashlib.sha256(b"veilmark/patternkey-id/v1\x00" + key).digest()[:8].hex()


def public_pattern_key(public_key: bytes) -> bytes:
    """Pattern key of *publicly verifiable* watermarks, derived from a signing public key.

    Anyone holding the public key can derive it, so such watermarks can be found (and
    attacked) by anyone who has the public key. Domain separation keeps it unrelated to
    every secret pattern key.
    """
    if len(public_key) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return kdf.derive_key(public_key, "public-pattern/v1")


def format_fingerprint(public_key: bytes) -> str:
    h = fingerprint(public_key).hex()
    return ":".join(h[i : i + 4] for i in range(0, 32, 4))


# ------------------------------------------------------------------ signing keys


@dataclass
class SigningIdentity:
    key_id: str
    label: str
    public_key: str  # base64
    created: int
    status: str = "active"  # active | retired | revoked
    retired_at: int | None = None
    replaced_by: str | None = None
    private: dict[str, str | int] = field(default_factory=dict)

    @property
    def public_bytes(self) -> bytes:
        return b64d(self.public_key)

    def unlock(self, passphrase: str | None) -> nacl.signing.SigningKey:
        p = self.private
        if p.get("scheme") == "plaintext":
            return nacl.signing.SigningKey(b64d(str(p["seed"])))
        if p.get("scheme") != "argon2id-secretbox":
            raise KeyStoreError("unsupported private key scheme")
        if passphrase is None:
            raise KeyStoreError("passphrase required to unlock signing key " + self.key_id)
        kek = nacl.pwhash.argon2id.kdf(
            nacl.secret.SecretBox.KEY_SIZE,
            passphrase.encode("utf-8"),
            b64d(str(p["salt"])),
            opslimit=int(p["opslimit"]),
            memlimit=int(p["memlimit"]),
        )
        try:
            seed = nacl.secret.SecretBox(kek).decrypt(b64d(str(p["box"])))
        except nacl.exceptions.CryptoError as e:
            raise KeyStoreError("wrong passphrase") from e
        sk = nacl.signing.SigningKey(seed)
        if bytes(sk.verify_key) != self.public_bytes:
            raise KeyStoreError("private key does not match public key")
        return sk


def _seal(seed: bytes, passphrase: str | None, fast: bool = False) -> dict[str, str | int]:
    if passphrase is None:
        return {"scheme": "plaintext", "seed": b64e(seed)}
    ops = nacl.pwhash.argon2id.OPSLIMIT_INTERACTIVE if fast else nacl.pwhash.argon2id.OPSLIMIT_MODERATE
    mem = nacl.pwhash.argon2id.MEMLIMIT_INTERACTIVE if fast else nacl.pwhash.argon2id.MEMLIMIT_MODERATE
    salt = nacl.utils.random(nacl.pwhash.argon2id.SALTBYTES)
    kek = nacl.pwhash.argon2id.kdf(
        nacl.secret.SecretBox.KEY_SIZE, passphrase.encode("utf-8"), salt, opslimit=ops, memlimit=mem
    )
    box = nacl.secret.SecretBox(kek).encrypt(seed)
    return {
        "scheme": "argon2id-secretbox",
        "salt": b64e(salt),
        "opslimit": ops,
        "memlimit": mem,
        "box": b64e(bytes(box)),
    }


@dataclass
class PatternKey:
    key_id: str
    label: str
    key: str  # base64 (secret)
    created: int

    @property
    def key_bytes(self) -> bytes:
        return b64d(self.key)


class KeyStore:
    """Filesystem key store under ``<data_home>/keys`` (directory mode 0700)."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = (root or paths.data_home()) / "keys"

    # -- signing identities -------------------------------------------------
    def _sdir(self) -> Path:
        return paths.ensure_dir(self.root / "signing", private=True)

    def _pdir(self) -> Path:
        return paths.ensure_dir(self.root / "pattern", private=True)

    def save_identity(self, ident: SigningIdentity) -> None:
        paths.atomic_write_json(self._sdir() / f"{ident.key_id}.json", asdict(ident), private=True)

    def generate_identity(
        self, label: str, passphrase: str | None, fast_kdf: bool = False
    ) -> SigningIdentity:
        """Create an identity. ``passphrase=None`` stores the key unencrypted."""
        sk = nacl.signing.SigningKey.generate()
        return self.import_identity_seed(bytes(sk), label, passphrase, fast_kdf)

    def import_identity_seed(
        self, seed: bytes, label: str, passphrase: str | None, fast_kdf: bool = False
    ) -> SigningIdentity:
        if len(seed) != 32:
            raise KeyStoreError("Ed25519 seed must be 32 bytes")
        sk = nacl.signing.SigningKey(seed)
        pub = bytes(sk.verify_key)
        ident = SigningIdentity(
            key_id=key_id(pub),
            label=label,
            public_key=b64e(pub),
            created=int(time.time()),
            private=_seal(seed, passphrase, fast_kdf),
        )
        if (self._sdir() / f"{ident.key_id}.json").exists():
            raise KeyStoreError(f"identity {ident.key_id} already exists")
        self.save_identity(ident)
        return ident

    def identities(self) -> list[SigningIdentity]:
        out = []
        for f in sorted(self._sdir().glob("*.json")):
            d = paths.read_json(f, None)
            if d:
                out.append(SigningIdentity(**d))
        return sorted(out, key=lambda i: i.created)

    def identity(self, ref: str | None = None) -> SigningIdentity:
        """Look up by key id prefix or label; default = newest active identity."""
        ids = self.identities()
        if ref is None:
            active = [i for i in ids if i.status == "active"]
            if not active:
                raise KeyStoreError("no active signing identity; run `veilmark keys generate`")
            return active[-1]
        matches = [i for i in ids if i.key_id.startswith(ref.lower()) or i.label == ref]
        if len(matches) != 1:
            raise KeyStoreError(f"identity {ref!r} not found or ambiguous")
        return matches[0]

    def rotate(
        self, ref: str | None, label: str | None, passphrase: str | None, fast_kdf: bool = False
    ) -> tuple[SigningIdentity, SigningIdentity]:
        """Generate a successor and retire the old identity (it can no longer sign,
        but signatures it made remain verifiable)."""
        old = self.identity(ref)
        if old.status != "active":
            raise KeyStoreError("only active identities can be rotated")
        new = self.generate_identity(label or old.label, passphrase, fast_kdf)
        old.status = "retired"
        old.retired_at = int(time.time())
        old.replaced_by = new.key_id
        self.save_identity(old)
        return old, new

    def set_status(self, ref: str, status: str) -> SigningIdentity:
        if status not in ("active", "retired", "revoked"):
            raise KeyStoreError("invalid status")
        ident = self.identity(ref)
        ident.status = status
        if status != "active" and ident.retired_at is None:
            ident.retired_at = int(time.time())
        self.save_identity(ident)
        return ident

    def export_private_seed(self, ref: str, passphrase: str | None) -> bytes:
        return bytes(self.identity(ref).unlock(passphrase))

    def delete_identity(self, ref: str) -> None:
        ident = self.identity(ref)
        (self._sdir() / f"{ident.key_id}.json").unlink()

    # -- pattern keys -------------------------------------------------------
    def pattern_keys(self) -> list[PatternKey]:
        out = []
        for f in sorted(self._pdir().glob("*.json")):
            d = paths.read_json(f, None)
            if d:
                out.append(PatternKey(**d))
        return sorted(out, key=lambda k: k.created)

    def add_pattern_key(self, key: bytes, label: str) -> PatternKey:
        if len(key) != 32:
            raise KeyStoreError("pattern key must be 32 bytes")
        kid = pattern_key_id(key)
        path = self._pdir() / f"{kid}.json"
        if path.exists():
            raise KeyStoreError("pattern key already present")
        # The oldest key is the default (own) one, so creation order must be strict even
        # when several keys are added within the same second.
        created = max([int(time.time())] + [k.created + 1 for k in self.pattern_keys()])
        pk = PatternKey(kid, label, b64e(key), created)
        paths.atomic_write_json(path, asdict(pk), private=True)
        return pk

    def generate_pattern_key(self, label: str = "default") -> PatternKey:
        return self.add_pattern_key(os.urandom(32), label)

    def pattern_key(self, ref: str | None = None) -> PatternKey:
        keys = self.pattern_keys()
        if not keys:
            raise KeyStoreError("no pattern key; run `veilmark keys init`")
        if ref is None:
            return keys[0]
        m = [k for k in keys if k.key_id.startswith(ref.lower()) or k.label == ref]
        if len(m) != 1:
            raise KeyStoreError(f"pattern key {ref!r} not found or ambiguous")
        return m[0]

    def ensure_pattern_key(self) -> PatternKey:
        keys = self.pattern_keys()
        return keys[0] if keys else self.generate_pattern_key()

    def delete_pattern_key(self, ref: str) -> None:
        k = self.pattern_key(ref)
        (self._pdir() / f"{k.key_id}.json").unlink()
