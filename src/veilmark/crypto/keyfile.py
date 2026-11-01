"""Portable, passphrase-encrypted keyfiles (shared by the CLI and the web app).

A keyfile bundles everything one issuer needs on another device: the Ed25519 signing
seed, the secret pattern key and the trusted-issuer list. The secrets are encrypted
with XSalsa20-Poly1305 under a key derived from the passphrase with Argon2id
(libsodium via PyNaCl). Public, non-secret metadata (labels, key ids, public key) is
stored in the clear so a user can see whose keyfile it is before unlocking it.

The secrets are authenticated by the cipher. The clear header is not encrypted, but
on import it is compared with values re-derived from the decrypted secrets, so a
tampered header is rejected.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import nacl.exceptions
import nacl.pwhash
import nacl.secret
import nacl.signing
import nacl.utils

from veilmark.crypto import keys

FORMAT = "veilmark-keyfile"
VERSION = 1
MIN_PASSPHRASE = 8


class KeyfileError(ValueError):
    pass


@dataclass
class KeyBundle:
    label: str
    signing_seed: bytes
    pattern_key: bytes
    pattern_label: str = "default"
    trusted: list[dict[str, Any]] = field(default_factory=list)  # {label, public_key(b64)}

    @property
    def public_key(self) -> bytes:
        return bytes(nacl.signing.SigningKey(self.signing_seed).verify_key)

    def header(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "signing_key_id": keys.key_id(self.public_key),
            "signing_public_key": keys.b64e(self.public_key),
            "fingerprint": keys.format_fingerprint(self.public_key),
            "pattern_key_id": keys.pattern_key_id(self.pattern_key),
        }


def encrypt(bundle: KeyBundle, passphrase: str, fast: bool = False) -> str:
    """Serialise ``bundle`` to keyfile JSON text."""
    if len(passphrase) < MIN_PASSPHRASE:
        raise KeyfileError(f"passphrase must be at least {MIN_PASSPHRASE} characters")
    if len(bundle.signing_seed) != 32 or len(bundle.pattern_key) != 32:
        raise KeyfileError("invalid key material")
    # Interactive limits keep unlocking fast enough in a browser (WebAssembly);
    # Argon2id with 64 MiB is still memory-hard.
    ops = nacl.pwhash.argon2id.OPSLIMIT_INTERACTIVE
    mem = nacl.pwhash.argon2id.MEMLIMIT_INTERACTIVE if not fast else nacl.pwhash.argon2id.MEMLIMIT_MIN
    salt = nacl.utils.random(nacl.pwhash.argon2id.SALTBYTES)
    kek = nacl.pwhash.argon2id.kdf(
        nacl.secret.SecretBox.KEY_SIZE, passphrase.encode(), salt, opslimit=ops, memlimit=mem
    )
    secret = json.dumps(
        {
            "label": bundle.label,
            "signing_seed": keys.b64e(bundle.signing_seed),
            "pattern_key": keys.b64e(bundle.pattern_key),
            "pattern_label": bundle.pattern_label,
            "trusted": bundle.trusted,
        },
        sort_keys=True,
    ).encode()
    box = nacl.secret.SecretBox(kek).encrypt(secret)
    doc = {
        "format": FORMAT,
        "version": VERSION,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "public": bundle.header(),
        "encryption": {
            "kdf": "argon2id",
            "opslimit": ops,
            "memlimit": mem,
            "salt": keys.b64e(salt),
            "cipher": "xsalsa20-poly1305",
        },
        "ciphertext": keys.b64e(bytes(box)),
    }
    return json.dumps(doc, indent=2) + "\n"


def peek(text: str) -> dict[str, Any]:
    """Public header of a keyfile, without the passphrase."""
    doc = _parse(text)
    return dict(doc["public"])


def _parse(text: str) -> dict[str, Any]:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        raise KeyfileError("not a Veilmark keyfile (invalid JSON)") from e
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise KeyfileError("not a Veilmark keyfile")
    if doc.get("version") != VERSION:
        raise KeyfileError(f"unsupported keyfile version {doc.get('version')}")
    enc = doc.get("encryption", {})
    if enc.get("kdf") != "argon2id" or enc.get("cipher") != "xsalsa20-poly1305":
        raise KeyfileError("unsupported keyfile encryption")
    return doc


def decrypt(text: str, passphrase: str) -> KeyBundle:
    doc = _parse(text)
    enc = doc["encryption"]
    ops, mem = int(enc["opslimit"]), int(enc["memlimit"])
    if mem > nacl.pwhash.argon2id.MEMLIMIT_SENSITIVE or ops > nacl.pwhash.argon2id.OPSLIMIT_SENSITIVE:
        raise KeyfileError("keyfile asks for unreasonable key-derivation cost")
    kek = nacl.pwhash.argon2id.kdf(
        nacl.secret.SecretBox.KEY_SIZE,
        passphrase.encode(),
        keys.b64d(enc["salt"]),
        opslimit=ops,
        memlimit=mem,
    )
    try:
        secret = json.loads(nacl.secret.SecretBox(kek).decrypt(keys.b64d(doc["ciphertext"])))
    except nacl.exceptions.CryptoError as e:
        raise KeyfileError("wrong passphrase or damaged keyfile") from e
    bundle = KeyBundle(
        label=secret["label"],
        signing_seed=keys.b64d(secret["signing_seed"]),
        pattern_key=keys.b64d(secret["pattern_key"]),
        pattern_label=secret.get("pattern_label", "default"),
        trusted=list(secret.get("trusted", [])),
    )
    if bundle.header() != {k: doc["public"].get(k) for k in bundle.header()}:
        raise KeyfileError("keyfile header does not match its encrypted contents (tampered?)")
    return bundle


def generate(label: str) -> KeyBundle:
    import os

    return KeyBundle(
        label=label, signing_seed=bytes(nacl.signing.SigningKey.generate()), pattern_key=os.urandom(32)
    )


def bundle_from_store(
    keystore: keys.KeyStore, trust: Any, identity: str | None, store_passphrase: str | None
) -> KeyBundle:
    """Collect an identity, the first pattern key and the trust list for export."""
    ident = keystore.identity(identity)
    pk = keystore.pattern_key()
    trusted = [
        {"label": i.label, "public_key": i.public_key}
        for i in trust.issuers()
        if i.status == "trusted" and i.public_key != ident.public_key
    ]
    return KeyBundle(
        label=ident.label,
        signing_seed=keystore.export_private_seed(ident.key_id, store_passphrase),
        pattern_key=pk.key_bytes,
        pattern_label=pk.label,
        trusted=trusted,
    )


def install_bundle(
    keystore: keys.KeyStore, trust: Any, bundle: KeyBundle, store_passphrase: str | None
) -> dict[str, Any]:
    """Add the bundle's keys to a store (existing keys are kept, not duplicated)."""
    added: dict[str, Any] = {"identity": None, "pattern_key": None, "trusted": 0}
    kid = keys.key_id(bundle.public_key)
    if not any(i.key_id == kid for i in keystore.identities()):
        keystore.import_identity_seed(bundle.signing_seed, bundle.label, store_passphrase)
        added["identity"] = kid
    pid = keys.pattern_key_id(bundle.pattern_key)
    if not any(k.key_id == pid for k in keystore.pattern_keys()):
        keystore.add_pattern_key(bundle.pattern_key, bundle.pattern_label)
        added["pattern_key"] = pid
    trust.add(bundle.public_key, bundle.label, note="from keyfile (own identity)")
    for t in bundle.trusted:
        trust.add(keys.b64d(t["public_key"]), t["label"], note="from keyfile")
        added["trusted"] += 1
    return added
