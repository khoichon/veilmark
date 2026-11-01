"""Shared fixtures. Every test gets an isolated data home (keys, trust, plugins)."""

from __future__ import annotations

import warnings
from pathlib import Path

import cv2
import numpy as np
import pytest

from veilmark.api import Veilmark
from veilmark.video import ffmpeg


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VEILMARK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("VEILMARK_PASSPHRASE", raising=False)


@pytest.fixture
def vm(tmp_path: Path) -> Veilmark:
    """A store with one pattern key and one trusted, unencrypted test identity."""
    v = Veilmark(tmp_path / "home")
    # Fixed test keys: with random keys every run embeds a different pattern and
    # signature, so near-threshold tests would pass or fail by chance. Robustness
    # *rates* are measured by the benchmark over many keys, not by these tests.
    v.keystore.add_pattern_key(bytes(range(100, 132)), "test")
    ident = v.keystore.import_identity_seed(bytes(range(7, 39)), "tester", None)
    v.trust.add(ident.public_bytes, "tester")
    return v


def _photo_like(seed: int, h: int = 720, w: int = 960) -> np.ndarray:
    """Deterministic natural-looking image (smooth regions, edges, texture, noise)."""
    rng = np.random.default_rng(seed)
    base = rng.normal(0, 1, (h // 16, w // 16, 3))
    img = cv2.resize(base, (w, h), interpolation=cv2.INTER_CUBIC)
    img = (img - img.min()) / (img.max() - img.min()) * 200 + 25
    for _ in range(12):
        c = tuple(float(x) for x in rng.uniform(20, 235, 3))
        cv2.circle(
            img,
            (int(rng.integers(0, w)), int(rng.integers(0, h))),
            int(rng.integers(20, 160)),
            c,
            -1,
            cv2.LINE_AA,
        )
    tex = cv2.GaussianBlur(rng.normal(0, 12, (h, w)), (0, 0), 1.0)[..., None]
    return np.clip(img + tex, 0, 255).astype(np.uint8)


@pytest.fixture(scope="session")
def photo() -> np.ndarray:
    """A real photograph if scikit-image data is installed, else a synthetic one."""
    try:
        import skimage.data as skd

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            a = skd.stereo_motorcycle()[0]
        return cv2.resize(a, None, fx=1.5, fy=1.5, interpolation=cv2.INTER_LANCZOS4)
    except Exception:
        return _photo_like(7)


@pytest.fixture(scope="session")
def photo_large(photo: np.ndarray) -> np.ndarray:
    """~1.8 MP: a typical web/phone-export photo size (attack tests use this)."""
    return cv2.resize(photo, None, fx=1.47, fy=1.47, interpolation=cv2.INTER_LANCZOS4)


@pytest.fixture(scope="session")
def synthetic_photo() -> np.ndarray:
    return _photo_like(3)


@pytest.fixture(scope="session")
def illustration() -> np.ndarray:
    from veilmark.benchmarks.datasets import _illustration

    return _illustration(55, 1200, 900)()


@pytest.fixture(scope="session")
def flat_image() -> np.ndarray:
    from veilmark.benchmarks.datasets import _flat

    return _flat(77, 1024, 768)()


requires_ffmpeg = pytest.mark.skipif(not ffmpeg.available(), reason="ffmpeg not installed")


def make_test_video(
    path: Path, seconds: float = 4.0, size: str = "960x540", fps: int = 30, audio: bool = True
) -> Path:
    args = ["-f", "lavfi", "-i", f"testsrc2=size={size}:rate={fps}:duration={seconds}"]
    if audio:
        args += ["-f", "lavfi", "-i", f"sine=frequency=440:duration={seconds}"]
    args += ["-c:v", "libx264", "-crf", "16", "-pix_fmt", "yuv420p"]
    if audio:
        args += ["-c:a", "aac", "-shortest"]
    ffmpeg.run([*args, str(path)])
    return path
