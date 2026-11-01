"""Error-correction, key derivation and pattern-format stability tests."""

import hashlib

import numpy as np
import pytest

from veilmark.crypto import kdf
from veilmark.watermark import ecc, framing, turbo
from veilmark.watermark.pattern import P0, KeyedPatterns, N


@pytest.mark.parametrize("code", [ecc.RATE_1_2, ecc.RATE_1_3, ecc.RATE_1_3_K9])
def test_convolutional_roundtrip(code: ecc.ConvCode) -> None:
    rng = np.random.default_rng(0)
    bits = rng.integers(0, 2, 300)
    coded = code.encode(bits)
    assert len(coded) == code.coded_length(300)
    soft = ecc.bpsk(coded) * 1.5 + rng.normal(0, 1, len(coded))
    out, _ = code.decode(soft)
    assert np.array_equal(out, bits)


def test_turbo_noiseless_and_noisy() -> None:
    rng = np.random.default_rng(1)
    k = 512
    bits = rng.integers(0, 2, k)
    coded = turbo.encode(bits)
    assert len(coded) == turbo.coded_length(k)
    out, _ = turbo.decode(1.0 - 2.0 * coded, k)
    assert np.array_equal(out, bits)
    # Eb/N0 ~ 1.6 dB: comfortably above the turbo threshold.
    soft = (1.0 - 2.0 * coded) * 1.0 + rng.normal(0, 1, len(coded))
    out, iters = turbo.decode(soft, k, check=lambda b: bool(np.array_equal(b, bits)))
    assert np.array_equal(out, bits) and iters <= 8


def test_turbo_is_scale_invariant() -> None:
    rng = np.random.default_rng(2)
    bits = rng.integers(0, 2, 256)
    soft = (1.0 - 2.0 * turbo.encode(bits)) + rng.normal(0, 0.9, turbo.coded_length(256))
    a, _ = turbo.decode(soft, 256)
    b, _ = turbo.decode(soft * 37.5, 256)
    assert np.array_equal(a, b)


def test_interleaver_is_a_stable_format_constant() -> None:
    pi = turbo.interleaver(88)
    assert sorted(pi.tolist()) == list(range(88))
    # Changing this hash changes the on-media format: bump the payload/format version.
    assert hashlib.sha256(pi.astype(np.int64).tobytes()).hexdigest()[:16] == _PINNED_INTERLEAVER


def test_kdf_domain_separation_and_known_answer() -> None:
    key = bytes(range(32))
    a = kdf.xof(key, "x", 1, length=16)
    assert a == kdf.xof(key, "x", 1, length=16)
    assert a != kdf.xof(key, "y", 1, length=16)
    assert a != kdf.xof(key, "x", 2, length=16)
    assert kdf.xof(key, "ab", "c", length=8) != kdf.xof(key, "a", "bc", length=8)
    assert a.hex() == _PINNED_KDF
    with pytest.raises(ValueError):
        kdf.xof(b"short", "x", length=4)


def test_framing_roundtrip_all_classes() -> None:
    wid = bytes(range(8))
    for n in (10, 60, 120, 180):
        payload = bytes(range(n % 256))[:n] + bytes(max(0, n - 256))
        f = framing.encode(wid, payload)
        core = framing.decode_core(ecc.bpsk(f.coded_core) * 4)
        assert core.ok and core.watermark_id == wid and core.class_index == f.class_index
        full = framing.decode_full(ecc.bpsk(f.coded_full) * 4, f.class_index)
        assert full.ok and full.body is not None and full.body[:n] == payload


def test_framing_rejects_oversized() -> None:
    with pytest.raises(ValueError):
        framing.encode(bytes(8), bytes(framing.LENGTH_CLASSES[-1]))


def test_core_crc_rejects_noise() -> None:
    rng = np.random.default_rng(3)
    accepted = sum(framing.decode_core(rng.normal(0, 1, framing.N_CORE_CODED)).ok for _ in range(30))
    assert accepted == 0


def test_pattern_render_extract_decodes() -> None:
    """Noise-free render -> extract: band-limiting leaves a little inter-chip
    crosstalk (raw errors), which the error-correcting code must remove entirely."""
    from veilmark.watermark import engine

    pats = KeyedPatterns(bytes(32))
    f = framing.encode(bytes(8), b"x" * 80)
    nc, nf = framing.N_CORE_CODED, framing.full_coded_length(f.class_index)
    for v in range(3):
        tile = pats.tile(v, f.coded_core, f.coded_full, P0)
        soft, _ = pats.soft_bits(v, engine.chips_from_aligned(tile.astype(np.float64)), nc, nf)
        assert np.mean((soft[:nc] < 0) != f.coded_core.astype(bool)) < 0.01
        assert np.mean((soft[nc:] < 0) != f.coded_full.astype(bool)) < 0.03
        core = framing.decode_core(soft[:nc])
        full = framing.decode_full(soft[nc:], f.class_index)
        assert core.ok and full.ok and full.body is not None and full.body.startswith(b"x" * 80)


def test_variants_are_distinct_and_key_dependent() -> None:
    a, b = KeyedPatterns(bytes(32)), KeyedPatterns(bytes([1]) + bytes(31))
    assert not np.array_equal(a.variant(0).sync_chips, a.variant(1).sync_chips)
    assert not np.array_equal(a.variant(0).sync_chips, b.variant(0).sync_chips)
    assert a.variant(0).sync_chips.shape == (N, N)


# Known-answer values: if these change, media watermarked by earlier versions can no
# longer be decoded, so the change must come with a format version bump.
_PINNED_INTERLEAVER = "d3a41636b2acfccd"
_PINNED_KDF = "862c3b757877dbd4bb1eac40d4635d68"


def test_period_jitter_and_avoidance() -> None:
    from veilmark.watermark import engine

    levels = {engine.choose_period_level(bytes([0, 0, 0, b, 0, 0, 0, 0]), 4) for b in range(10)}
    assert levels == set(range(len(engine.PERIOD_JITTER)))
    wid = bytes([0, 0, 0, 0, 0, 0, 0, 0])
    p0 = engine.period_for(4, engine.choose_period_level(wid, 4))
    p1 = engine.period_for(4, engine.choose_period_level(wid, 4, avoid=[p0]))
    assert abs(p1 - p0) / p0 >= engine.MIN_PERIOD_SEPARATION
    with pytest.raises(ValueError):
        engine.choose_period_level(wid, 4, avoid=[float(engine.period_for(4, i)) for i in range(5)])
