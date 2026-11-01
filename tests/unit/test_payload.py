import struct

import pytest

from veilmark.crypto import payload as pl


def test_roundtrip_all_fields() -> None:
    p = pl.Payload(
        text="Café ☕", timestamp=1_700_000_000, metadata=b"\x01\x02", key_id=b"abcd", signature=b"s" * 64
    )
    raw = p.to_bytes()
    q, body = pl.parse(raw)
    assert q == p
    assert raw.startswith(body) and len(raw) == len(body) + 64


def test_minimal_unsigned() -> None:
    raw = pl.Payload().to_bytes()
    assert raw == bytes([1, 0])
    assert pl.parse(raw)[0] == pl.Payload()


def test_zero_padding_allowed_but_not_garbage() -> None:
    raw = pl.Payload(text="x").to_bytes()
    assert pl.parse(raw + bytes(10))[0].text == "x"
    with pytest.raises(pl.PayloadError):
        pl.parse(raw + b"\x00\x01")
    with pytest.raises(pl.PayloadError):
        pl.parse(raw + bytes(3), allow_padding=False)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        bytes([2, 0]),  # unknown version
        bytes([1, 0x10]),  # reserved flag
        bytes([1, pl.F_TEXT, 5]) + b"ab",  # truncated text
        bytes([1, pl.F_TEXT, 2]) + b"\xff\xfe",  # invalid UTF-8
        bytes([1, pl.F_TEXT, 3]) + "é".encode(),  # not NFC
        bytes([1, pl.F_SIGNED]) + b"abcd" + b"s" * 10,  # truncated signature
        bytes([1, pl.F_TIMESTAMP]) + struct.pack(">H", 1),  # truncated timestamp
    ],
)
def test_rejects_malformed(raw: bytes) -> None:
    with pytest.raises(pl.PayloadError):
        pl.parse(raw)


def test_text_is_nfc_normalised_on_encode() -> None:
    p = pl.Payload(text="é")
    q, _ = pl.parse(p.to_bytes())
    assert q.text == "é"


def test_limits() -> None:
    with pytest.raises(pl.PayloadError):
        pl.Payload(text="x" * (pl.MAX_TEXT_BYTES + 1)).to_bytes()
    with pytest.raises(pl.PayloadError):
        pl.Payload(timestamp=2**32).to_bytes()
    with pytest.raises(pl.PayloadError):
        pl.Payload(key_id=b"abcd").to_bytes()  # signed without signature


def test_signing_message_domain_separated() -> None:
    m = pl.signing_message(b"\0" * 8, b"\x01\x00")
    assert m.startswith(pl.SIGNING_DOMAIN)
    with pytest.raises(pl.PayloadError):
        pl.signing_message(b"short", b"")
