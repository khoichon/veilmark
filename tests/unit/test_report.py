"""Detection report helpers."""

from veilmark.detection import report as rep


def test_payload_recovered_for_primary_and_additional() -> None:
    """Self-checks after re-watermarking: the new mark may be outranked by the old one
    and then appears among the additional watermarks; it still counts as recovered."""
    r = rep.DetectionReport("x", "image", rep.STATUS_PAYLOAD, watermark_id="aaaa")
    r.additional = [
        {"status": rep.STATUS_PAYLOAD, "watermark_id": "bbbb"},
        {"status": rep.STATUS_ID, "watermark_id": "cccc"},
    ]
    assert r.payload_recovered_for("aaaa")
    assert r.payload_recovered_for("bbbb")
    assert not r.payload_recovered_for("cccc")  # id only: payload not recovered
    assert not r.payload_recovered_for("dddd")
    weak = rep.DetectionReport("x", "image", rep.STATUS_ID, watermark_id="aaaa")
    assert not weak.payload_recovered_for("aaaa")
