"""Two-layer channel framing.

Both layers use the rate-1/3 turbo code in :mod:`.turbo` (about 1.5-2 dB better than
the best convolutional codes at these block lengths).

* **Core layer** (always 88 information bits, ~13% of chips):
  64-bit watermark id + 8-bit length class + CRC-16. It is the most robust part and
  lets the detector recover the watermark id (and the full layer's size) even when
  the full signed payload cannot be recovered.
* **Full layer** (remaining chips): the serialized payload padded to
  one of a few fixed length classes, terminated by a CRC-32.
"""

from __future__ import annotations

import binascii
import struct
import zlib
from dataclasses import dataclass

import numpy as np

from veilmark.watermark import ecc, turbo

LENGTH_CLASSES = (32, 48, 64, 80, 96, 128, 160, 192)
CORE_BYTES = 11
CORE_BITS = CORE_BYTES * 8
N_CORE_CODED = turbo.coded_length(CORE_BITS)
TURBO_ITERATIONS = 8


def full_coded_length(class_index: int) -> int:
    return turbo.coded_length(LENGTH_CLASSES[class_index] * 8)


def choose_class(payload_len: int) -> int:
    for i, size in enumerate(LENGTH_CLASSES):
        if payload_len + 4 <= size:
            return i
    raise ValueError(
        f"payload of {payload_len} bytes exceeds the maximum in-band capacity "
        f"({LENGTH_CLASSES[-1] - 4} bytes)"
    )


@dataclass(frozen=True)
class CodedFrame:
    class_index: int
    coded_core: np.ndarray
    coded_full: np.ndarray


def encode(watermark_id: bytes, payload: bytes) -> CodedFrame:
    if len(watermark_id) != 8:
        raise ValueError("watermark id must be 8 bytes")
    ci = choose_class(len(payload))
    size = LENGTH_CLASSES[ci]
    core = watermark_id + bytes([ci])
    core += struct.pack(">H", binascii.crc_hqx(core, 0xFFFF))
    body = payload + bytes(size - 4 - len(payload))
    full = body + struct.pack(">I", zlib.crc32(body))
    return CodedFrame(
        ci,
        turbo.encode(ecc.bytes_to_bits(core)),
        turbo.encode(ecc.bytes_to_bits(full)),
    )


@dataclass(frozen=True)
class CoreResult:
    ok: bool
    watermark_id: bytes | None
    class_index: int | None
    bit_agreement: float  # fraction of coded soft values agreeing with re-encoding


def _agreement(bits: np.ndarray, soft: np.ndarray) -> float:
    re = ecc.bpsk(turbo.encode(bits))
    w = np.abs(soft)
    if w.sum() == 0:
        return 0.0
    return float(np.sum(w * (np.sign(soft) == re)) / w.sum())


def _core_crc_ok(raw: bytes) -> bool:
    return struct.unpack(">H", raw[9:11])[0] == binascii.crc_hqx(raw[:9], 0xFFFF)


def decode_core(soft: np.ndarray) -> CoreResult:
    # Fixed iteration count and a single CRC test: early stopping would give the
    # 16-bit CRC several chances to accept noise.
    bits, _ = turbo.decode(soft, CORE_BITS, TURBO_ITERATIONS)
    raw = ecc.bits_to_bytes(bits)
    agree = _agreement(bits, soft)
    crc_ok = _core_crc_ok(raw)
    if not crc_ok or raw[8] >= len(LENGTH_CLASSES):
        return CoreResult(False, None, None, agree)
    return CoreResult(True, raw[:8], raw[8], agree)


@dataclass(frozen=True)
class FullResult:
    ok: bool
    body: bytes | None  # padded payload bytes (without CRC)
    bit_agreement: float


def _full_crc_ok(raw: bytes) -> bool:
    return zlib.crc32(raw[:-4]) == struct.unpack(">I", raw[-4:])[0]


def decode_full(soft: np.ndarray, class_index: int) -> FullResult:
    k = LENGTH_CLASSES[class_index] * 8
    # CRC-32 makes early stopping safe (false-accept ~ iterations * 2^-32).
    bits, _ = turbo.decode(soft, k, TURBO_ITERATIONS, check=lambda b: _full_crc_ok(ecc.bits_to_bytes(b)))
    raw = ecc.bits_to_bytes(bits)
    agree = _agreement(bits, soft)
    body, crc = raw[:-4], struct.unpack(">I", raw[-4:])[0]
    if zlib.crc32(body) != crc:
        return FullResult(False, None, agree)
    return FullResult(True, body, agree)
