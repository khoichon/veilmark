"""Video embed / detect round trips (require ffmpeg; marked slow)."""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import make_test_video, requires_ffmpeg
from veilmark.api import Veilmark, WatermarkSpec
from veilmark.core.tasks import Cancelled, CancelToken, Reporter
from veilmark.detection import report as rep_mod
from veilmark.security.limits import InputError
from veilmark.video import ffmpeg

pytestmark = [requires_ffmpeg, pytest.mark.video, pytest.mark.slow]

FIXED_ID = bytes.fromhex("0fedcba987654321")


@pytest.fixture(scope="module")
def marked(tmp_path_factory: pytest.TempPathFactory) -> tuple[Veilmark, Path, Path, str]:
    d = tmp_path_factory.mktemp("video")
    vm = Veilmark(d / "home")
    vm.keystore.add_pattern_key(bytes(range(50, 82)), "video-test")
    ident = vm.keystore.import_identity_seed(bytes(range(3, 35)), "video-tester", None)
    vm.trust.add(ident.public_bytes, "video-tester")
    src = make_test_video(d / "src.mp4", seconds=5.0)
    out = d / "marked.mp4"
    spec = WatermarkSpec(text="video test", watermark_id=FIXED_ID, include_timestamp=False)
    res = vm.embed_video(src, out, spec)
    assert res.extra["frames"] == 150
    return vm, src, out, res.watermark_id


def test_audio_timing_and_frames_preserved(marked) -> None:
    _, src, out, _ = marked
    a, b = ffmpeg.probe(src), ffmpeg.probe(out)
    assert b.has_audio and b.audio_codecs == a.audio_codecs
    assert b.fps == a.fps
    assert abs(b.duration - a.duration) < 0.1
    assert (b.width, b.height) == (a.width, a.height)
    frames = sum(1 for _ in ffmpeg.FrameReader(b, "gray"))
    assert frames == 150


def test_clean_detection(marked) -> None:
    vm, _, out, wid = marked
    r = vm.detect_video(out)
    assert r.status == rep_mod.STATUS_PAYLOAD and r.watermark_id == wid and r.authentic
    assert r.payload is not None and r.payload["text"] == "video test"
    assert r.diagnostics["variants_observed"] >= 3  # the moving distribution was observed


ATTACKS = {
    "h264-crf30": ["-c:v", "libx264", "-crf", "30"],
    "drop-1-of-3": ["-vf", "select='mod(n\\,3)'", "-fps_mode", "vfr", "-c:v", "libx264", "-crf", "23"],
    "fps-24": ["-vf", "fps=24", "-c:v", "libx264", "-crf", "23"],
    "clip-1.5s": ["-ss", "2", "-t", "1.5", "-c:v", "libx264", "-crf", "23"],
    "crop-fixed": ["-vf", "crop=iw*0.6:ih*0.6:iw*0.3:ih*0.2", "-c:v", "libx264", "-crf", "23"],
    "crop-moving": [
        "-vf",
        "crop=iw*0.65:ih*0.65:'(iw*0.35)*t/5':'(ih*0.35)*(0.5+0.5*sin(t))'",
        "-c:v",
        "libx264",
        "-crf",
        "23",
    ],
    "downscale": ["-vf", "scale=-2:360", "-c:v", "libx264", "-crf", "24"],
    "vp9-webm": ["-c:v", "libvpx-vp9", "-crf", "36", "-b:v", "0", "-deadline", "realtime", "-cpu-used", "8"],
}


@pytest.mark.parametrize("name", list(ATTACKS))
def test_video_attacks(marked, tmp_path: Path, name: str) -> None:
    vm, _, out, wid = marked
    ext = ".webm" if "webm" in name else ".mp4"
    att = tmp_path / f"att{ext}"
    ffmpeg.run(["-i", str(out), *ATTACKS[name], "-an", str(att)])
    r = vm.detect_video(att)
    assert r.status == rep_mod.STATUS_PAYLOAD, r.summary()
    assert r.watermark_id == wid and r.authentic


def test_unwatermarked_video_not_detected(marked, tmp_path: Path) -> None:
    vm, src, _, _ = marked
    att = tmp_path / "neg.mp4"
    ffmpeg.run(["-i", str(src), "-c:v", "libx264", "-crf", "26", "-an", str(att)])
    for p in (src, att):
        r = vm.detect_video(p)
        assert r.status == rep_mod.STATUS_NONE, r.summary()


def test_cancellation_leaves_no_files(marked, tmp_path: Path) -> None:
    vm, src, _, _ = marked
    tok = CancelToken()

    def progress(f: float, msg: str) -> None:
        if f > 0.3:
            tok.cancel()

    dst = tmp_path / "cancelled.mp4"
    with pytest.raises(Cancelled):
        vm.embed_video(src, dst, WatermarkSpec(text="x"), reporter=Reporter(progress, tok))
    assert not dst.exists()
    assert not list(tmp_path.glob(".veilmark-*"))


def test_malformed_video_rejected(vm: Veilmark, tmp_path: Path) -> None:
    bad = tmp_path / "bad.mp4"
    bad.write_bytes(b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 200)
    with pytest.raises(InputError):
        vm.embed_video(bad, tmp_path / "o.mp4", WatermarkSpec(text="x"))
    with pytest.raises(InputError):
        vm.detect_video(bad)


def test_light_mode_and_webm_output(marked, tmp_path: Path) -> None:
    vm, src, _, _ = marked
    out = tmp_path / "light.webm"
    res = vm.embed_video(src, out, WatermarkSpec(text="light"), mode="light")
    assert res.strength < 1.0
    assert ffmpeg.probe(out).codec == "vp9" and ffmpeg.probe(out).audio_codecs == ["opus"]
    r = vm.detect_video(out)
    assert r.status == rep_mod.STATUS_PAYLOAD and r.payload["text"] == "light"
