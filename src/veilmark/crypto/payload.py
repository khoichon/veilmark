"""Versioned, canonical binary payload format (v1).

Layout (all integers big-endian)::

    u8   version            (= 1)
    u8   flags              bit0 signed, bit1 timestamp, bit2 text, bit3 metadata
    [4]  key_id             if signed: first 4 bytes of the issuer key fingerprint
    u32  timestamp          if timestamp flag: Unix seconds (UTC)
    u8 n + n bytes text     if text flag: UTF-8, NFC-normalised
    u8 n + n bytes meta     if metadata flag: opaque application bytes
    [64] signature          if signed: Ed25519 over SIGNING_DOMAIN || watermark_id || all
                            preceding payload bytes

The 64-bit watermark id travels in the robust core layer of the watermark; it is
bound into the signature so it cannot be swapped between payloads.

There is exactly one valid encoding of every payload: flags must match the fields
present, reserved flag bits must be zero, text must be NFC, lengths must be exact
and any padding after the payload must be all zero bytes. ``parse`` enforces this,
so the signed bytes are canonical by construction.
"""

from __future__ import annotations

import struct
import unicodedata
from dataclasses import dataclass

VERSION = 1
SIGNING_DOMAIN = b"veilmark/payload/v1\x00"
SIG_LEN = 64
KEY_ID_LEN = 4

F_SIGNED = 0x01
F_TIMESTAMP = 0x02
F_TEXT = 0x04
F_META = 0x08
_KNOWN = F_SIGNED | F_TIMESTAMP | F_TEXT | F_META

MAX_TEXT_BYTES = 120
MAX_META_BYTES = 120


class PayloadError(ValueError):
    """Malformed or non-canonical payload bytes."""


@dataclass(frozen=True)
class Payload:
    text: str | None = None
    timestamp: int | None = None
    metadata: bytes | None = None
    key_id: bytes | None = None  # 4-byte hint; None when unsigned
    signature: bytes | None = None

    @property
    def signed(self) -> bool:
        return self.signature is not None

    def body(self) -> bytes:
        """Bytes covered by the signature (everything except the signature)."""
        flags = 0
        out = bytearray()
        if self.key_id is not None:
            if len(self.key_id) != KEY_ID_LEN:
                raise PayloadError("key id must be 4 bytes")
            flags |= F_SIGNED
            out += self.key_id
        if self.timestamp is not None:
            if not 0 <= self.timestamp < 2**32:
                raise PayloadError("timestamp out of range")
            flags |= F_TIMESTAMP
            out += struct.pack(">I", self.timestamp)
        if self.text is not None:
            t = normalise_text(self.text).encode("utf-8")
            if len(t) > MAX_TEXT_BYTES:
                raise PayloadError(f"text exceeds {MAX_TEXT_BYTES} bytes")
            flags |= F_TEXT
            out += bytes([len(t)]) + t
        if self.metadata is not None:
            if len(self.metadata) > MAX_META_BYTES:
                raise PayloadError(f"metadata exceeds {MAX_META_BYTES} bytes")
            flags |= F_META
            out += bytes([len(self.metadata)]) + self.metadata
        return bytes([VERSION, flags]) + bytes(out)

    def to_bytes(self) -> bytes:
        body = self.body()
        if self.key_id is not None:
            if self.signature is None or len(self.signature) != SIG_LEN:
                raise PayloadError("signed payload requires a 64-byte signature")
            return body + self.signature
        if self.signature is not None:
            raise PayloadError("signature without key id")
        return body


def normalise_text(text: str) -> str:
    return unicodedata.normalize("NFC", text)


def signing_message(watermark_id: bytes, body: bytes) -> bytes:
    if len(watermark_id) != 8:
        raise PayloadError("watermark id must be 8 bytes")
    return SIGNING_DOMAIN + watermark_id + body


def parse(data: bytes, allow_padding: bool = True) -> tuple[Payload, bytes]:
    """Strictly parse payload bytes. Returns (payload, signed body bytes)."""
    if len(data) < 2:
        raise PayloadError("payload too short")
    if data[0] != VERSION:
        raise PayloadError(f"unsupported payload version {data[0]}")
    flags = data[1]
    if flags & ~_KNOWN:
        raise PayloadError("reserved flag bits set")
    pos = 2

    def take(n: int) -> bytes:
        nonlocal pos
        if pos + n > len(data):
            raise PayloadError("truncated payload")
        b = data[pos : pos + n]
        pos += n
        return b

    key_id = take(KEY_ID_LEN) if flags & F_SIGNED else None
    ts = struct.unpack(">I", take(4))[0] if flags & F_TIMESTAMP else None
    text = None
    if flags & F_TEXT:
        n = take(1)[0]
        if n > MAX_TEXT_BYTES:
            raise PayloadError("text too long")
        raw = take(n)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as e:
            raise PayloadError("text is not valid UTF-8") from e
        if normalise_text(text) != text:
            raise PayloadError("text is not NFC-normalised")
    meta = None
    if flags & F_META:
        n = take(1)[0]
        if n > MAX_META_BYTES:
            raise PayloadError("metadata too long")
        meta = take(n)
    body = data[:pos]
    sig = take(SIG_LEN) if flags & F_SIGNED else None
    rest = data[pos:]
    if rest and (not allow_padding or any(rest)):
        raise PayloadError("unexpected trailing bytes")
    p = Payload(text=text, timestamp=ts, metadata=meta, key_id=key_id, signature=sig)
    if p.body() != body:  # defence in depth: re-encode must be byte-identical
        raise PayloadError("non-canonical encoding")
    return p, body
