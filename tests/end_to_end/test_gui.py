"""Offscreen GUI smoke test: the window builds, tabs work, a preview task completes."""

from __future__ import annotations

import os
import time
from pathlib import Path

import numpy as np
import pytest
from PIL import Image

pytest.importorskip("PySide6")
pytestmark = pytest.mark.gui


@pytest.fixture(scope="module")
def qapp():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def _wait(app, cond, timeout: float = 120.0) -> None:
    end = time.time() + timeout
    while not cond() and time.time() < end:
        app.processEvents()
        time.sleep(0.02)
    assert cond(), "timed out waiting for background task"


def test_main_window_and_preview(qapp, vm, tmp_path: Path, synthetic_photo: np.ndarray) -> None:
    from veilmark.app.main import MainWindow

    win = MainWindow(vm)
    assert win.tabs.count() == 6
    for i in range(win.tabs.count()):
        win.tabs.setCurrentIndex(i)
        qapp.processEvents()
    src = tmp_path / "p.png"
    Image.fromarray(synthetic_photo).save(src)
    page = win.wm
    page.files.add_paths([str(src)])
    page.text.setText("gui test")
    assert "Payload" in page.capacity.text()
    page.preview()
    _wait(qapp, lambda: not page.runner.busy and "PSNR" in page.metrics.text())
    page.out_dir.setText(str(tmp_path))
    page.run()
    _wait(qapp, lambda: not page.runner.busy and "✓" in page.log.toPlainText())
    out = tmp_path / "p.wm.png"
    assert out.exists()
    det = win.det
    det.files.add_paths([str(out)])
    det.run()
    _wait(qapp, lambda: not det.runner.busy and det.results.count() == 1)
    assert "Payload recovered" in det.results.item(0).text()
    assert "Issuer trusted" in det.details.toHtml()
    win.close()


def test_cancel_task(qapp) -> None:
    from veilmark.app.worker import TaskRunner

    r = TaskRunner()
    state = {}
    r.cancelled.connect(lambda: state.setdefault("cancelled", True))

    def job(rep):
        for i in range(1000):
            rep(i / 1000, "working")
            time.sleep(0.005)
        return "done"

    r.start(job)
    r.cancel()
    _wait(qapp, lambda: "cancelled" in state, 10)
    assert not r.busy
