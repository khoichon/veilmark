"""Veilmark desktop application (PySide6)."""

from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from veilmark import __version__
from veilmark.api import Veilmark
from veilmark.app.page_detect import DetectPage
from veilmark.app.page_keys import KeysPage
from veilmark.app.page_lab import LabPage
from veilmark.app.page_plugins_settings import PluginsPage, SettingsPage
from veilmark.app.page_watermark import WatermarkPage
from veilmark.video import ffmpeg

NOTICE = (
    "Invisible watermarks can be weakened or removed by determined attackers, and a valid "
    "signature only shows who signed the hidden payload, not that the media is original or "
    "unedited. Veilmark is not a substitute for backups, access control, copyright "
    "registration or legal evidence."
)


class MainWindow(QMainWindow):
    def __init__(self, vm: Veilmark) -> None:
        super().__init__()
        self.vm = vm
        self.setWindowTitle(f"Veilmark {__version__}")
        self.resize(1280, 860)
        plugin_problems = [i for i in vm.load_plugins() if i.problems]

        self.wm = WatermarkPage(vm)
        self.det = DetectPage(vm)
        self.keys = KeysPage(vm, on_change=self._keys_changed)
        self.lab = LabPage(vm)
        self.plugins = PluginsPage(vm, on_change=self.det.refresh)
        self.settings = SettingsPage(vm)
        tabs = QTabWidget()
        tabs.addTab(self.wm, "Watermark")
        tabs.addTab(self.det, "Detect")
        tabs.addTab(self.keys, "Keys && trust")
        tabs.addTab(self.lab, "Robustness lab")
        tabs.addTab(self.plugins, "Plugins")
        tabs.addTab(self.settings, "Settings")
        self.tabs = tabs

        central = QWidget()
        lay = QVBoxLayout(central)
        if vm.settings.show_disclaimer:
            banner = QFrame()
            banner.setFrameShape(QFrame.Shape.StyledPanel)
            bl = QHBoxLayout(banner)
            text = QLabel(NOTICE)
            text.setWordWrap(True)
            close = QPushButton("Dismiss")
            close.clicked.connect(banner.hide)
            bl.addWidget(text, 1)
            bl.addWidget(close, 0, Qt.AlignmentFlag.AlignTop)
            lay.addWidget(banner)
        lay.addWidget(tabs)
        self.setCentralWidget(central)

        status = []
        if not ffmpeg.available():
            status.append("FFmpeg not found: video features disabled")
        if not vm.keystore.pattern_keys():
            status.append("No keys yet: open 'Keys & trust' and generate an identity")
            tabs.setCurrentWidget(self.keys)
        status.append(f"Data: {vm.home} · local processing only, no network")
        self.statusBar().showMessage("   |   ".join(status))
        if plugin_problems:
            QMessageBox.warning(
                self,
                "Plugins",
                "Some plugins were not loaded:\n"
                + "\n".join(f"{i.name}: {'; '.join(i.problems)}" for i in plugin_problems),
            )

    def _keys_changed(self) -> None:
        self.wm.refresh()
        self.det.refresh()


def main(argv: list[str] | None = None, home: Path | None = None) -> int:
    app = QApplication.instance() or QApplication(argv if argv is not None else sys.argv)
    app.setApplicationName("Veilmark")
    win = MainWindow(Veilmark(home))
    win.show()
    return int(app.exec())


if __name__ == "__main__":
    sys.exit(main())
