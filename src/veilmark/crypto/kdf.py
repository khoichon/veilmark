"""Domain-separated key derivation and cryptographically secure pseudorandom streams.

All secret-derived watermark patterns come from SHAKE-256 (a NIST-standardised
extendable-output function) keyed with the 32-byte pattern key. Inputs are
length-prefixed so distinct (domain, parts) tuples can never collide.

Simulation randomness (benchmarks, tests) must use ``numpy.random.default_rng``
and never these functions, and these functions must never be fed ordinary RNGs.
"""

from __future__ import annotations

import hashlib
import struct

import numpy as np

_PREFIX = b"veilmark/v1/"


def _encode(*parts: bytes | str | int) -> bytes:
    out = bytearray()
    for p in parts:
        if isinstance(p, int):
            b = struct.pack(">q", p)
        elif isinstance(p, str):
            b = p.encode("utf-8")
        else:
            b = bytes(p)
        out += struct.pack(">I", len(b)) + b
    return bytes(out)


def xof(key: bytes, domain: str, *parts: bytes | str | int, length: int) -> bytes:
    """Return ``length`` pseudorandom bytes bound to (key, domain, parts)."""
    if len(key) < 16:
        raise ValueError("key too short")
    h = hashlib.shake_256(_encode(_PREFIX + domain.encode(), key, *parts))
    return h.digest(length)


def derive_key(key: bytes, domain: str, *parts: bytes | str | int) -> bytes:
    return xof(key, "derive:" + domain, *parts, length=32)


def random_signs(key: bytes, domain: str, *parts: bytes | str | int, n: int) -> np.ndarray:
    """``n`` independent +-1 values (float32)."""
    raw = np.frombuffer(xof(key, domain, *parts, length=(n + 7) // 8), dtype=np.uint8)
    bits = np.unpackbits(raw)[:n]
    return (1.0 - 2.0 * bits).astype(np.float32)


def random_uint64(key: bytes, domain: str, *parts: bytes | str | int, n: int) -> np.ndarray:
    raw = xof(key, domain, *parts, length=8 * n)
    return np.frombuffer(raw, dtype=">u8").astype(np.uint64)


def permutation(key: bytes, domain: str, *parts: bytes | str | int, n: int) -> np.ndarray:
    """Keyed uniform permutation of range(n) (argsort of 64-bit keyed values)."""
    vals = random_uint64(key, domain, *parts, n=n)
    return np.argsort(vals, kind="stable")


def random_ints(key: bytes, domain: str, *parts: bytes | str | int, n: int, high: int) -> np.ndarray:
    """``n`` keyed integers in [0, high) with negligible modulo bias (64-bit source)."""
    return (random_uint64(key, domain, *parts, n=n) % np.uint64(high)).astype(np.int64)
