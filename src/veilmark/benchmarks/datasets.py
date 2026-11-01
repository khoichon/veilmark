"""Benchmark media sets with a strict development / held-out split.

* ``dev`` images were used while designing and tuning the algorithm (including the
  repository's example image). Results on them are *not* independent evidence.
* ``heldout`` images were never used for tuning. Report these as the evaluation.

Sources: scikit-image sample data (public domain / permissive; optional ``bench``
extra), procedurally generated illustrations and flat graphics, and optional
user-provided example media from the repository root.
"""

from __future__ import annotations

import warnings
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import cv2
import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class ImageSample:
    name: str
    split: str
    kind: str  # photo | texture | illustration | flat | screenshot | text | scientific
    loader: Callable[[], np.ndarray]

    def load(self) -> np.ndarray:
        a = self.loader()
        if a.dtype == bool:
            a = a.astype(np.uint8) * 255
        if a.ndim == 2:
            a = np.dstack([a] * 3)
        if a.shape[2] == 4:  # composite RGBA over white for benchmarking
            alpha = a[..., 3:4].astype(np.float32) / 255.0
            a = (a[..., :3] * alpha + 255 * (1 - alpha)).astype(np.uint8)
        return np.ascontiguousarray(a[..., :3])


def _sk(name: str) -> Callable[[], np.ndarray]:
    def load() -> np.ndarray:
        import skimage.data as skd

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            a = getattr(skd, name)()
        return a[0] if isinstance(a, tuple) else a

    return load


def _illustration(seed: int, w: int = 1600, h: int = 1200) -> Callable[[], np.ndarray]:
    """Flat-colour vector-style illustration with gradients, shapes and text."""

    def make() -> np.ndarray:
        rng = np.random.default_rng(seed)
        yy, xx = np.mgrid[0:h, 0:w].astype(np.float32)
        c0, c1 = rng.integers(40, 220, 3), rng.integers(40, 220, 3)
        t = (xx / w * 0.6 + yy / h * 0.4)[..., None]
        img = (c0 * (1 - t) + c1 * t).astype(np.uint8)
        for _ in range(40):
            col = tuple(int(v) for v in rng.integers(0, 256, 3))
            kind = rng.integers(0, 3)
            if kind == 0:
                p1 = (int(rng.integers(0, w)), int(rng.integers(0, h)))
                p2 = (int(p1[0] + rng.integers(40, 500)), int(p1[1] + rng.integers(40, 400)))
                cv2.rectangle(img, p1, p2, col, -1, cv2.LINE_AA)
            elif kind == 1:
                cv2.circle(
                    img,
                    (int(rng.integers(0, w)), int(rng.integers(0, h))),
                    int(rng.integers(20, 250)),
                    col,
                    -1,
                    cv2.LINE_AA,
                )
            else:
                pts = rng.integers(0, [w, h], size=(int(rng.integers(3, 7)), 2)).astype(np.int32)
                cv2.fillPoly(img, [pts], col, cv2.LINE_AA)
        for _ in range(8):
            cv2.putText(
                img,
                f"Veilmark sample {rng.integers(0, 9999)}",
                (int(rng.integers(0, w - 400)), int(rng.integers(40, h))),
                cv2.FONT_HERSHEY_SIMPLEX,
                float(rng.uniform(0.8, 2.5)),
                (int(rng.integers(0, 256)),) * 3,
                2,
                cv2.LINE_AA,
            )
        return img

    return make


def _flat(seed: int, w: int = 1280, h: int = 960) -> Callable[[], np.ndarray]:
    """Mostly flat UI-like graphic: the hardest case for invisibility."""

    def make() -> np.ndarray:
        rng = np.random.default_rng(seed)
        img = np.empty((h, w, 3), np.uint8)
        img[:] = rng.integers(180, 250, 3)
        for _ in range(10):
            x, y = int(rng.integers(0, w - 200)), int(rng.integers(0, h - 100))
            cv2.rectangle(
                img,
                (x, y),
                (x + int(rng.integers(150, 600)), y + int(rng.integers(60, 300))),
                tuple(int(v) for v in rng.integers(30, 240, 3)),
                -1,
            )
        cv2.putText(img, "Settings", (60, 90), cv2.FONT_HERSHEY_DUPLEX, 2.0, (30, 30, 30), 2, cv2.LINE_AA)
        return img

    return make


def _repo_image(name: str) -> Callable[[], np.ndarray]:
    def load() -> np.ndarray:
        a = cv2.imread(str(REPO_ROOT / name), cv2.IMREAD_COLOR)
        if a is None:
            raise FileNotFoundError(name)
        return cv2.cvtColor(a, cv2.COLOR_BGR2RGB)

    return load


def _video_frame(name: str, t: float) -> Callable[[], np.ndarray]:
    def load() -> np.ndarray:
        cap = cv2.VideoCapture(str(REPO_ROOT / name))
        cap.set(cv2.CAP_PROP_POS_MSEC, t * 1000)
        ok, f = cap.read()
        cap.release()
        if not ok:
            raise FileNotFoundError(name)
        return cv2.cvtColor(f, cv2.COLOR_BGR2RGB)

    return load


def _upscaled(loader: Callable[[], np.ndarray], f: float) -> Callable[[], np.ndarray]:
    def load() -> np.ndarray:
        a = loader()
        return cv2.resize(a, None, fx=f, fy=f, interpolation=cv2.INTER_LANCZOS4)

    return load


IMAGES: list[ImageSample] = [
    # ---- development set (used during tuning) ----
    ImageSample("example-screenshot", "dev", "screenshot", _repo_image("exampleimage.png")),
    ImageSample("example-video-frame", "dev", "screenshot", _video_frame("examplevideo.mov", 10.0)),
    ImageSample("astronaut", "dev", "photo", _sk("astronaut")),
    ImageSample("coffee", "dev", "photo", _sk("coffee")),
    ImageSample("camera", "dev", "photo", _sk("camera")),
    ImageSample("brick", "dev", "texture", _sk("brick")),
    ImageSample("rocket-2x", "dev", "photo", _upscaled(_sk("rocket"), 2.0)),
    ImageSample("illustration-dev", "dev", "illustration", _illustration(1)),
    ImageSample("flat-ui-dev", "dev", "flat", _flat(1)),
    # ---- held-out evaluation set (never used for tuning) ----
    ImageSample("chelsea", "heldout", "photo", _sk("chelsea")),
    ImageSample("motorcycle", "heldout", "photo", _sk("stereo_motorcycle")),
    ImageSample("motorcycle-2x", "heldout", "photo", _upscaled(_sk("stereo_motorcycle"), 2.0)),
    ImageSample("hubble", "heldout", "scientific", _sk("hubble_deep_field")),
    ImageSample("retina", "heldout", "scientific", _sk("retina")),
    ImageSample("immunohistochemistry", "heldout", "scientific", _sk("immunohistochemistry")),
    ImageSample("gravel", "heldout", "texture", _sk("gravel")),
    ImageSample("coins", "heldout", "photo", _sk("coins")),
    ImageSample("clock", "heldout", "photo", _sk("clock")),
    ImageSample("logo", "heldout", "illustration", _sk("logo")),
    ImageSample("colorwheel", "heldout", "flat", _sk("colorwheel")),
    ImageSample("text-page", "heldout", "text", _sk("page")),
    ImageSample("illustration-heldout", "heldout", "illustration", _illustration(1001)),
    ImageSample("illustration-heldout-2", "heldout", "illustration", _illustration(1002, 1920, 1080)),
    ImageSample("flat-ui-heldout", "heldout", "flat", _flat(1001)),
]


def images(split: str = "heldout", names: list[str] | None = None) -> list[ImageSample]:
    out = []
    for s in IMAGES:
        if split != "all" and s.split != split:
            continue
        if names and s.name not in names:
            continue
        out.append(s)
    return out


def available(sample: ImageSample) -> bool:
    try:
        sample.load()
        return True
    except Exception:
        return False


# ------------------------------------------------------------------ videos


@dataclass(frozen=True)
class VideoSample:
    name: str
    split: str
    kind: str
    ffmpeg_input: list[str]  # ffmpeg input arguments producing the source
    filters: str = ""


VIDEOS: list[VideoSample] = [
    VideoSample(
        "example-platform",
        "dev",
        "screen recording",
        ["-ss", "5", "-t", "6", "-i", str(REPO_ROOT / "examplevideo.mov")],
    ),
    VideoSample(
        "example-late",
        "dev",
        "screen recording",
        ["-ss", "30", "-t", "6", "-i", str(REPO_ROOT / "examplevideo.mov")],
    ),
    VideoSample(
        "testsrc2",
        "heldout",
        "synthetic motion",
        ["-f", "lavfi", "-i", "testsrc2=size=1280x720:rate=30:duration=6"],
    ),
    VideoSample(
        "mandelbrot",
        "heldout",
        "synthetic detail",
        ["-f", "lavfi", "-i", "mandelbrot=size=1280x720:rate=30", "-t", "6"],
    ),
    VideoSample(
        "pan-photo",
        "heldout",
        "camera pan over photo",
        ["-f", "lavfi", "-i", "color=c=black:s=1280x720:r=30:d=6"],
        "PAN",
    ),
    VideoSample(
        "cellauto",
        "heldout",
        "flat graphics",
        ["-f", "lavfi", "-i", "cellauto=s=1280x720:rule=110:rate=30", "-t", "6"],
    ),
]


def videos(split: str = "heldout") -> list[VideoSample]:
    return [v for v in VIDEOS if split == "all" or v.split == split]
