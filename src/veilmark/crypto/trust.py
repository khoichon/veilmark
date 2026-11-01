"""Trusted-issuer list and signature verification.

Signature validity (a cryptographic fact about the bytes) and issuer trust (a policy
decision about the key) are reported separately. A key embedded in or claimed by a
payload is never trusted automatically: only keys present in the trust list, with a
``trusted`` status, can make a payload "trusted".
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from pathlib import Path

import nacl.exceptions
import nacl.signing

from veilmark.crypto import keys, payload
from veilmark.storage import paths


@dataclass
class TrustedIssuer:
    key_id: str
    label: str
    public_key: str  # base64
    status: str = "trusted"  # trusted | revoked
    added: int = 0
    not_before: int | None = None
    not_after: int | None = None
    revoked_at: int | None = None
    note: str = ""

    @property
    def public_bytes(self) -> bytes:
        return keys.b64d(self.public_key)


class TrustStore:
    def __init__(self, root: Path | None = None) -> None:
        self.path = (root or paths.data_home()) / "trust.json"

    def issuers(self) -> list[TrustedIssuer]:
        data = paths.read_json(self.path, {"issuers": []})
        return [TrustedIssuer(**d) for d in data.get("issuers", [])]

    def _save(self, issuers: list[TrustedIssuer]) -> None:
        paths.atomic_write_json(self.path, {"issuers": [asdict(i) for i in issuers]})

    def add(
        self,
        public_key: bytes,
        label: str,
        not_before: int | None = None,
        not_after: int | None = None,
        note: str = "",
    ) -> TrustedIssuer:
        if len(public_key) != 32:
            raise ValueError("Ed25519 public key must be 32 bytes")
        nacl.signing.VerifyKey(public_key)  # validates encoding
        kid = keys.key_id(public_key)
        issuers = [i for i in self.issuers() if i.key_id != kid]
        entry = TrustedIssuer(
            kid, label, keys.b64e(public_key), "trusted", int(time.time()), not_before, not_after, None, note
        )
        issuers.append(entry)
        self._save(issuers)
        return entry

    def revoke(self, ref: str, at: int | None = None) -> TrustedIssuer:
        issuers = self.issuers()
        m = [i for i in issuers if i.key_id.startswith(ref.lower()) or i.label == ref]
        if len(m) != 1:
            raise ValueError(f"issuer {ref!r} not found or ambiguous")
        m[0].status = "revoked"
        m[0].revoked_at = int(time.time()) if at is None else at
        self._save(issuers)
        return m[0]

    def remove(self, ref: str) -> None:
        issuers = self.issuers()
        keep = [i for i in issuers if not (i.key_id.startswith(ref.lower()) or i.label == ref)]
        if len(keep) == len(issuers):
            raise ValueError(f"issuer {ref!r} not found")
        self._save(keep)

    def candidates(self, hint: bytes) -> list[TrustedIssuer]:
        """Issuers whose fingerprint starts with the 4-byte in-band key id hint."""
        return [i for i in self.issuers() if keys.fingerprint(i.public_bytes)[:4] == hint]


@dataclass(frozen=True)
class Verification:
    signature: str  # valid | invalid | unsigned | unknown-key
    trust: str  # trusted | revoked | expired | not-yet-valid | untrusted | n/a
    issuer_key_id: str | None
    issuer_label: str | None
    message: str

    @property
    def authentic(self) -> bool:
        """True only when the signature is valid *and* the issuer is trusted."""
        return self.signature == "valid" and self.trust == "trusted"

    def as_dict(self) -> dict[str, object]:
        return {**asdict(self), "authentic": self.authentic}


def sign(
    watermark_id: bytes,
    p: payload.Payload,
    signer: nacl.signing.SigningKey,
) -> payload.Payload:
    """Return ``p`` with key id and signature filled in."""
    pub = bytes(signer.verify_key)
    unsigned = payload.Payload(p.text, p.timestamp, p.metadata, keys.fingerprint(pub)[:4], None)
    msg = payload.signing_message(watermark_id, unsigned.body())
    sig = signer.sign(msg).signature
    return payload.Payload(p.text, p.timestamp, p.metadata, unsigned.key_id, bytes(sig))


def _check(pub: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        nacl.signing.VerifyKey(pub).verify(msg, sig)
        return True
    except nacl.exceptions.BadSignatureError:
        return False


def verify(
    watermark_id: bytes,
    p: payload.Payload,
    body: bytes,
    trust: TrustStore,
    extra_public_keys: list[tuple[bytes, str]] | None = None,
) -> Verification:
    """Verify a parsed payload against the trust list.

    ``extra_public_keys`` (e.g. the user's own identities, or a key supplied on the
    command line) can establish *signature validity* but never trust.
    """
    if not p.signed or p.key_id is None or p.signature is None:
        return Verification("unsigned", "n/a", None, None, "payload carries no signature")
    msg = payload.signing_message(watermark_id, body)
    for issuer in trust.candidates(p.key_id):
        if not _check(issuer.public_bytes, msg, p.signature):
            continue
        ts = p.timestamp
        if issuer.status == "revoked":
            if ts is not None and issuer.revoked_at is not None and ts < issuer.revoked_at:
                status, why = (
                    "revoked",
                    (
                        "signature valid; issuer key was revoked after the claimed signing "
                        "time (timestamps are self-asserted, treat with caution)"
                    ),
                )
            else:
                status, why = "revoked", "signature valid but issuer key is revoked"
        elif issuer.not_after is not None and ts is not None and ts > issuer.not_after:
            status, why = "expired", "claimed signing time is after the key's validity period"
        elif issuer.not_before is not None and ts is not None and ts < issuer.not_before:
            status, why = "not-yet-valid", "claimed signing time precedes the key's validity"
        else:
            status, why = "trusted", "valid signature from a trusted issuer"
        return Verification("valid", status, issuer.key_id, issuer.label, why)
    for pub, label in extra_public_keys or []:
        if keys.fingerprint(pub)[:4] == p.key_id and _check(pub, msg, p.signature):
            return Verification(
                "valid",
                "untrusted",
                keys.key_id(pub),
                label,
                "signature valid, but the key is not in the trust list",
            )
    known_extra = [k for k, _ in (extra_public_keys or []) if keys.fingerprint(k)[:4] == p.key_id]
    if trust.candidates(p.key_id) or known_extra:
        return Verification(
            "invalid",
            "n/a",
            None,
            None,
            "signature does NOT verify for the claimed issuer: payload altered or forged",
        )
    return Verification(
        "unknown-key",
        "untrusted",
        None,
        None,
        f"signed by unknown key (id hint {p.key_id.hex()}); import its public key to check",
    )
