"""Image embed -> attack -> blind detect round trips.

Thresholds are never relaxed to make these pass: every positive must recover the
exact signed payload (or the exact id where noted) and every negative must report
``not-detected``.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from veilmark.api import Veilmark, WatermarkSpec
from veilmark.benchmarks import attacks as atk
from veilmark.detection import report as rep_mod
from veilmark.image.io import ImageData

FIXED_ID = bytes.fromhex("5eed0123456789ab")


def _embed(vm: Veilmark, rgb: np.ndarray, text: str = "test payload") -> tuple[ImageData, str]:
    # Fixed id and no timestamp make every test fully deterministic.
    spec = WatermarkSpec(text=text, watermark_id=FIXED_ID, include_timestamp=False)
    out, res = vm.embed_image_data(ImageData(rgb), spec)
    assert res.psnr_db is not None and res.psnr_db > 36
    assert res.ssim is not None and res.ssim > 0.95
    return out, res.watermark_id


def _detect(vm: Veilmark, rgb: np.ndarray) -> rep_mod.DetectionReport:
    return vm.detect_image_data(ImageData(np.ascontiguousarray(rgb)))


def test_clean_roundtrip_signed_and_trusted(vm: Veilmark, photo: np.ndarray) -> None:
    out, wid = _embed(vm, photo, "© Example 2026")
    r = _detect(vm, out.rgb)
    assert r.status == rep_mod.STATUS_PAYLOAD
    assert r.watermark_id == wid
    assert r.payload is not None and r.payload["text"] == "© Example 2026"
    assert r.verification is not None and r.verification["signature"] == "valid"
    assert r.verification["trust"] == "trusted" and r.authentic


@pytest.mark.parametrize(
    "attack",
    [
        "jpeg-75",
        "webp-80",
        "crop-50",
        "scale-0.75",
        "scale-1.5",
        "rotate-10",
        "rotate-90",
        "mirror",
        "grayscale",
        "gamma-0.6",
        "hue+30",
        "blur-1",
        "noise-5",
        "combo-crop50-scale0.7-jpeg75",
    ],
)
def test_attacks_recover_payload(vm: Veilmark, photo_large: np.ndarray, attack: str) -> None:
    out, wid = _embed(vm, photo_large)
    a = atk.image_attacks([attack])[0]
    r = _detect(vm, a.fn(out.rgb, np.random.default_rng(11)))
    assert r.status == rep_mod.STATUS_PAYLOAD, r.summary()
    assert r.watermark_id == wid and r.authentic


@pytest.mark.parametrize("seed", range(4))
def test_small_region_recovers_id(vm: Veilmark, photo: np.ndarray, seed: int) -> None:
    """A 25%-area crop of this ~0.8 MP photo leaves ~200k pixels: enough for the
    robust 64-bit id (core layer) but often not for the ~90-byte signed payload
    (measured ~1 in 6). The id must be correct whenever it is reported, and nothing
    beyond it may be guessed."""
    out, wid = _embed(vm, photo)
    part = atk.image_attacks(["crop-25"])[0].fn(out.rgb, np.random.default_rng(seed))
    r = _detect(vm, part)
    assert r.detected
    if r.watermark_id is not None:
        assert r.watermark_id == wid
    if r.status != rep_mod.STATUS_PAYLOAD:
        assert r.payload is None


def test_small_regions_mostly_yield_id(vm: Veilmark, photo: np.ndarray) -> None:
    out, wid = _embed(vm, photo)
    a = atk.image_attacks(["crop-25"])[0]
    ids = [_detect(vm, a.fn(out.rgb, np.random.default_rng(s))).watermark_id for s in range(6)]
    # Near-capacity case (~0.2 MP left): measured 3-4 of 6 on this image depending
    # on mask settings; the benchmark reports rates with confidence intervals. The
    # property that must always hold is that no *wrong* id is ever reported.
    assert sum(i == wid for i in ids) >= 3
    assert all(i in (None, wid) for i in ids)


@pytest.mark.parametrize("fixture", ["synthetic_photo", "illustration", "flat_image"])
def test_diverse_content(vm: Veilmark, fixture: str, request: pytest.FixtureRequest) -> None:
    rgb = request.getfixturevalue(fixture)
    out, wid = _embed(vm, rgb)
    r = _detect(vm, atk.image_attacks(["jpeg-90"])[0].fn(out.rgb, np.random.default_rng(0)))
    assert r.status == rep_mod.STATUS_PAYLOAD and r.watermark_id == wid


@pytest.mark.parametrize("fixture", ["photo", "synthetic_photo", "illustration", "flat_image"])
@pytest.mark.parametrize("attack", ["none", "jpeg-50", "scale-0.5"])
def test_unwatermarked_is_not_detected(
    vm: Veilmark, fixture: str, attack: str, request: pytest.FixtureRequest
) -> None:
    rgb = request.getfixturevalue(fixture)
    r = _detect(vm, atk.image_attacks([attack])[0].fn(rgb, np.random.default_rng(0)))
    assert r.status == rep_mod.STATUS_NONE, r.summary()
    assert r.payload is None and r.watermark_id is None


def test_wrong_pattern_key_cannot_detect(vm: Veilmark, photo: np.ndarray, tmp_path: Path) -> None:
    out, _ = _embed(vm, photo)
    other = Veilmark(tmp_path / "other")
    other.keystore.generate_pattern_key()
    assert other.detect_image_data(ImageData(out.rgb)).status == rep_mod.STATUS_NONE


def test_unsigned_payload_reported_as_unsigned(vm: Veilmark, photo: np.ndarray) -> None:
    out, _ = vm.embed_image_data(ImageData(photo), WatermarkSpec(text="anon", sign=False))
    r = _detect(vm, out.rgb)
    assert r.status == rep_mod.STATUS_PAYLOAD
    assert r.verification is not None and r.verification["signature"] == "unsigned"
    assert not r.authentic


def test_file_roundtrip_preserves_alpha_and_never_overwrites(
    vm: Veilmark, tmp_path: Path, photo: np.ndarray
) -> None:
    from PIL import Image

    h, w = photo.shape[:2]
    alpha = np.full((h, w), 255, np.uint8)
    alpha[: h // 4] = 128
    src = tmp_path / "in.png"
    Image.fromarray(np.dstack([photo, alpha]), "RGBA").save(src)
    dst = tmp_path / "out.png"
    vm.embed_image(src, dst, WatermarkSpec(text="alpha"))
    back = np.asarray(Image.open(dst))
    assert back.shape[2] == 4 and np.array_equal(back[..., 3], alpha)
    assert vm.detect_image(dst).status == rep_mod.STATUS_PAYLOAD
    with pytest.raises(ValueError):
        vm.embed_image(src, src, WatermarkSpec(text="x"))
    with pytest.raises(ValueError):
        vm.embed_image(src, dst, WatermarkSpec(text="x"))  # exists


def test_capacity_errors_are_clear(vm: Veilmark, photo: np.ndarray) -> None:
    with pytest.raises(ValueError, match="exceeds"):
        vm.embed_image_data(ImageData(photo), WatermarkSpec(text="x" * 119, metadata=b"y" * 60))


def test_cancellation(vm: Veilmark, photo: np.ndarray) -> None:
    from veilmark.core.tasks import Cancelled, CancelToken, Reporter

    tok = CancelToken()
    tok.cancel()
    with pytest.raises(Cancelled):
        vm.embed_image_data(ImageData(photo), WatermarkSpec(text="x"), Reporter(cancel=tok))


def test_rewatermark_refused_by_default(vm: Veilmark, photo_large: np.ndarray) -> None:
    from veilmark.api import AlreadyWatermarked

    out, wid = _embed(vm, photo_large)
    with pytest.raises(AlreadyWatermarked, match="already carries") as e:
        vm.embed_image_data(ImageData(out.rgb), WatermarkSpec(text="second"))
    assert e.value.existing[0]["watermark_id"] == wid


@pytest.mark.parametrize("same_keys", [True, False])
def test_allowed_rewatermark_keeps_both(
    vm: Veilmark, photo_large: np.ndarray, tmp_path: Path, same_keys: bool
) -> None:
    """A second watermark uses a different tile period, so both survive; with the same
    keys the detector reports both (with different keys each owner finds their own)."""
    first, wid1 = _embed(vm, photo_large, "first")
    other = vm
    if not same_keys:
        other = Veilmark(tmp_path / "other")
        other.keystore.add_pattern_key(bytes(range(200, 232)), "other")
        ident = other.keystore.import_identity_seed(bytes(range(40, 72)), "other", None)
        other.trust.add(ident.public_bytes, "other")
    spec = WatermarkSpec(
        text="second",
        allow_rewatermark=True,
        include_timestamp=False,
        # Byte 3 selects the period level; FIXED_ID uses level 1, this one level 2.
        watermark_id=bytes.fromhex("0bad0102456789ab"),
    )
    second, res = other.embed_image_data(ImageData(first.rgb), spec)
    r1 = vm.detect_image_data(ImageData(second.rgb))
    texts = {(r1.payload or {}).get("text")} | {(a.get("payload") or {}).get("text") for a in r1.additional}
    assert "first" in texts
    if same_keys:
        assert res.extra["existing_watermarks"][0]["watermark_id"] == wid1
        assert "second" in texts and len(r1.additional) == 1
    else:
        r2 = other.detect_image_data(ImageData(second.rgb))
        assert r2.status == rep_mod.STATUS_PAYLOAD and r2.payload["text"] == "second"


def test_independent_marks_on_same_period_collide(
    vm: Veilmark, photo_large: np.ndarray, tmp_path: Path
) -> None:
    """Documented limitation: a second watermark made with *someone else's* pattern key
    is invisible to the pre-check, so if it happens to pick the same period level (1 in
    5) the two marks garble each other. Nothing wrong may ever be reported, though."""
    first, wid1 = _embed(vm, photo_large, "first")
    other = Veilmark(tmp_path / "other")
    other.keystore.add_pattern_key(bytes(range(200, 232)), "other")
    other.keystore.import_identity_seed(bytes(range(40, 72)), "other", None)
    same_level = bytes.fromhex("0bad0101456789ab")  # byte 3 = 0x01, the same level as FIXED_ID
    second, _ = other.embed_image_data(
        ImageData(first.rgb), WatermarkSpec(text="second", include_timestamp=False, watermark_id=same_level)
    )
    r = vm.detect_image_data(ImageData(second.rgb))
    assert r.status != rep_mod.STATUS_PAYLOAD or (r.payload or {}).get("text") == "first"
    assert r.watermark_id in (None, wid1)
