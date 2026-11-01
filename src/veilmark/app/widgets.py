"""Reusable widgets: file lists, progress bar with cancel, image previews."""

from __future__ import annotations

from pathlib import Path

import numpy as np
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QImage, QPixmap
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QProgressBar,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

IMAGE_FILTER = "Images (*.png *.jpg *.jpeg *.webp *.tif *.tiff *.bmp)"
VIDEO_FILTER = "Videos (*.mp4 *.mov *.m4v *.mkv *.webm *.avi)"
MEDIA_FILTER = "Media (*.png *.jpg *.jpeg *.webp *.tif *.tiff *.bmp *.mp4 *.mov *.m4v *.mkv *.webm *.avi)"


class FileList(QWidget):
    """A list of input files with add/remove buttons (supports drag and drop)."""

    changed = Signal()

    def __init__(self, label: str, file_filter: str = MEDIA_FILTER, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.filter = file_filter
        self.list = QListWidget()
        self.list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.list.setAccessibleName(label)
        self.list.setAcceptDrops(True)
        self.setAcceptDrops(True)
        add = QPushButton("Add files…")
        add.setAccessibleName(f"Add files to {label}")
        rem = QPushButton("Remove selected")
        add.clicked.connect(self._add)
        rem.clicked.connect(self._remove)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(QLabel(label))
        lay.addWidget(self.list)
        row = QHBoxLayout()
        row.addWidget(add)
        row.addWidget(rem)
        row.addStretch()
        lay.addLayout(row)

    def paths(self) -> list[Path]:
        return [Path(self.list.item(i).text()) for i in range(self.list.count())]

    def add_paths(self, paths: list[str]) -> None:
        existing = {str(p) for p in self.paths()}
        for p in paths:
            if p and p not in existing:
                self.list.addItem(p)
        self.changed.emit()

    def _add(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, "Choose files", "", self.filter)
        self.add_paths(files)

    def _remove(self) -> None:
        for it in self.list.selectedItems():
            self.list.takeItem(self.list.row(it))
        self.changed.emit()

    def dragEnterEvent(self, e) -> None:
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e) -> None:
        self.add_paths([u.toLocalFile() for u in e.mimeData().urls()])


class ProgressRow(QWidget):
    """Progress bar, status text and a cancel button."""

    cancel_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.bar = QProgressBar()
        self.bar.setRange(0, 1000)
        self.bar.setAccessibleName("Progress")
        self.status = QLabel("Idle")
        self.status.setAccessibleName("Status")
        self.cancel = QPushButton("Cancel")
        self.cancel.setEnabled(False)
        self.cancel.clicked.connect(self.cancel_requested)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.bar, 2)
        lay.addWidget(self.status, 3)
        lay.addWidget(self.cancel)

    def set_busy(self, busy: bool) -> None:
        self.cancel.setEnabled(busy)
        if busy:
            self.bar.setValue(0)

    def update(self, fraction: float, message: str) -> None:  # type: ignore[override]
        self.bar.setValue(int(fraction * 1000))
        self.status.setText(message)


def to_pixmap(rgb: np.ndarray, max_side: int = 520) -> QPixmap:
    a = np.ascontiguousarray(rgb[..., :3])
    h, w = a.shape[:2]
    img = QImage(a.data, w, h, 3 * w, QImage.Format.Format_RGB888).copy()
    pm = QPixmap.fromImage(img)
    if max(h, w) > max_side:
        pm = pm.scaled(
            max_side, max_side, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation
        )
    return pm


class ImagePane(QLabel):
    def __init__(self, caption: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.caption = caption
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setMinimumSize(240, 180)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setText(caption)
        self.setAccessibleName(caption)
        self.setStyleSheet("QLabel { border: 1px solid palette(mid); }")
        # Never let the pixmap dictate the layout size.
        self.setMinimumSize(160, 120)

        self._pixmap: QPixmap | None = None

    def show_array(self, rgb: np.ndarray | None) -> None:
        if rgb is None:
            self._pixmap = None
            self.setText(self.caption)
            return
        self._pixmap = to_pixmap(rgb, max_side=4096)
        self._rescale()

    def _rescale(self) -> None:
        if self._pixmap is not None:
            self.setPixmap(
                self._pixmap.scaled(
                    max(1, self.width() - 4),
                    max(1, self.height() - 4),
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation,
                )
            )

    def resizeEvent(self, e) -> None:
        super().resizeEvent(e)
        self._rescale()


def zoom_crop(rgb: np.ndarray, size: int = 256) -> np.ndarray:
    """Central crop for 1:1 inspection of fine detail."""
    h, w = rgb.shape[:2]
    y0, x0 = max(0, h // 2 - size // 2), max(0, w // 2 - size // 2)
    return np.ascontiguousarray(rgb[y0 : y0 + size, x0 : x0 + size])


def amplified_difference(a: np.ndarray, b: np.ndarray, gain: float = 12.0) -> np.ndarray:
    d = b.astype(np.int16) - a.astype(np.int16)
    return np.clip(d * gain + 128, 0, 255).astype(np.uint8)
