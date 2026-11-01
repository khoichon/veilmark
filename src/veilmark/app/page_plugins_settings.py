"""Plugins and Settings tabs."""

from __future__ import annotations

import tempfile
from dataclasses import asdict
from pathlib import Path

from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from veilmark.api import Veilmark
from veilmark.plugins.manager import Manifest, PluginError
from veilmark.storage import settings as settings_mod

PLUGIN_WARNING = (
    "Plugins are Python code that runs inside Veilmark with your full user permissions. "
    "Declared permissions are shown for information only and are NOT enforced by a sandbox. "
    "Only enable plugins from sources you trust."
)


def describe(m: Manifest) -> str:
    perms = ", ".join(f"{k}: {v}" for k, v in sorted(m.permissions.items())) or "none declared"
    return (
        f"{m.name} {m.version} (plugin API v{m.api_version})\n{m.description}\n\n"
        f"Kinds: {', '.join(m.kinds)}\nDeclared permissions: {perms}\n"
        f"Author: {m.author or 'unknown'}\n\n{PLUGIN_WARNING}"
    )


class PluginsPage(QWidget):
    def __init__(self, vm: Veilmark, on_change=None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.vm = vm
        self.on_change = on_change or (lambda: None)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Name", "Version", "Enabled", "Status", "Kinds", "Permissions"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table.setAccessibleName("Plugins")
        self.table.currentCellChanged.connect(lambda *_: self._details())
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        warn = QLabel(PLUGIN_WARNING)
        warn.setWordWrap(True)
        row = QHBoxLayout()
        for label, slot in (
            ("Install from folder…", self.install),
            ("Enable…", self.enable),
            ("Disable", self.disable),
            ("Remove…", self.remove),
            ("Refresh", self.refresh),
        ):
            b = QPushButton(label)
            b.clicked.connect(slot)
            row.addWidget(b)
        row.addStretch()
        lay = QVBoxLayout(self)
        lay.addWidget(warn)
        lay.addWidget(QLabel(f"Plugin folder: {vm.plugins.dir}"))
        lay.addWidget(self.table, 2)
        lay.addLayout(row)
        lay.addWidget(self.details, 1)
        self.refresh()

    def refresh(self) -> None:
        self.infos = self.vm.plugins.discover()
        self.table.setRowCount(len(self.infos))
        for r, i in enumerate(self.infos):
            m = i.manifest
            vals = [
                i.name,
                m.version if m else "?",
                "yes" if i.enabled else "no",
                i.status,
                ", ".join(m.kinds) if m else "",
                ", ".join(f"{k}={v}" for k, v in (m.permissions.items() if m else [])),
            ]
            for c, v in enumerate(vals):
                self.table.setItem(r, c, QTableWidgetItem(v))
        self._details()

    def _current(self):  # type: ignore[no-untyped-def]
        r = self.table.currentRow()
        return self.infos[r] if 0 <= r < len(self.infos) else None

    def _details(self) -> None:
        i = self._current()
        if i is None:
            self.details.setPlainText("")
            return
        text = describe(i.manifest) if i.manifest else ""
        if i.problems:
            text += "\n\nProblems:\n- " + "\n- ".join(i.problems)
        self.details.setPlainText(text)

    def _confirm(self, title: str, m: Manifest) -> bool:
        return (
            QMessageBox.question(self, title, describe(m) + "\n\nProceed?") == QMessageBox.StandardButton.Yes
        )

    def _do(self, fn) -> None:
        try:
            fn()
        except (PluginError, OSError, ValueError) as e:
            QMessageBox.warning(self, "Plugins", str(e))
        self.refresh()
        self.on_change()

    def install(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Plugin folder (containing veilmark-plugin.json)")
        if d:
            self._do(lambda: self.vm.plugins.install(Path(d), lambda m: self._confirm("Install plugin", m)))

    def enable(self) -> None:
        i = self._current()
        if i is None or i.manifest is None:
            return

        def do() -> None:
            self.vm.plugins.enable(i.name, lambda m: self._confirm("Enable plugin", m))
            loaded = {x.name: x for x in self.vm.plugins.load_enabled()}
            if i.name in loaded and loaded[i.name].problems:
                raise PluginError("; ".join(loaded[i.name].problems))

        self._do(do)

    def disable(self) -> None:
        i = self._current()
        if i:
            self._do(lambda: self.vm.plugins.disable(i.name))

    def remove(self) -> None:
        i = self._current()
        if (
            i
            and QMessageBox.question(self, "Remove plugin", f"Delete {i.name} from disk?")
            == QMessageBox.StandardButton.Yes
        ):
            self._do(lambda: self.vm.plugins.remove(i.name))


class SettingsPage(QWidget):
    def __init__(self, vm: Veilmark, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.vm = vm
        s = vm.settings
        self.out_dir = QLineEdit(s.default_output_dir)
        self.suffix = QLineEdit(s.output_suffix)
        self.strength = QDoubleSpinBox()
        self.strength.setRange(0.3, 3.0)
        self.strength.setValue(s.default_strength)
        self.quality = QSpinBox()
        self.quality.setRange(50, 100)
        self.quality.setValue(s.jpeg_quality)
        self.mode = QComboBox()
        self.mode.addItems(["robust", "light"])
        self.mode.setCurrentText(s.video_mode)
        self.codec = QComboBox()
        self.codec.addItems(["auto", "libx264", "libx265", "libvpx-vp9", "libsvtav1"])
        self.codec.setCurrentText(s.video_codec)
        self.crf = QSpinBox()
        self.crf.setRange(0, 63)
        self.crf.setSpecialValueText("codec default")
        self.crf.setValue(s.video_crf or 0)
        self.frames = QSpinBox()
        self.frames.setRange(30, 20000)
        self.frames.setValue(s.detect_max_frames)
        self.mpix = QDoubleSpinBox()
        self.mpix.setRange(1, 1000)
        self.mpix.setValue(s.max_image_megapixels)
        self.vmin = QDoubleSpinBox()
        self.vmin.setRange(0.1, 10000)
        self.vmin.setValue(s.max_video_minutes)
        self.gb = QDoubleSpinBox()
        self.gb.setRange(0.01, 1000)
        self.gb.setValue(s.max_file_gb)
        self.workers = QSpinBox()
        self.workers.setRange(0, 256)
        self.workers.setSpecialValueText("automatic")
        self.workers.setValue(s.benchmark_workers)
        self.disclaimer = QCheckBox("Show the limitations notice at startup")
        self.disclaimer.setChecked(s.show_disclaimer)
        form = QFormLayout()
        form.addRow("Default output folder", self.out_dir)
        form.addRow("Output file suffix", self.suffix)
        form.addRow("Default strength", self.strength)
        form.addRow("JPEG/WebP quality", self.quality)
        form.addRow("Video mode", self.mode)
        form.addRow("Video codec", self.codec)
        form.addRow("Video CRF", self.crf)
        form.addRow("Detection: max video frames", self.frames)
        form.addRow("Limit: image megapixels", self.mpix)
        form.addRow("Limit: video minutes", self.vmin)
        form.addRow("Limit: file size (GB)", self.gb)
        form.addRow("Benchmark worker processes", self.workers)
        form.addRow("", self.disclaimer)
        save = QPushButton("Save settings")
        save.clicked.connect(self.save)
        clean = QPushButton("Remove stale temporary files")
        clean.clicked.connect(self.cleanup)
        privacy = QLabel(
            "Privacy: Veilmark processes everything locally. It makes no network connections, sends no "
            "telemetry and uploads nothing. Output files do not carry your EXIF/GPS metadata (the ICC colour "
            f"profile is kept). Keys, trust list and settings live in: {vm.home}"
        )
        privacy.setWordWrap(True)
        lay = QVBoxLayout(self)
        lay.addLayout(form)
        row = QHBoxLayout()
        row.addWidget(save)
        row.addWidget(clean)
        row.addStretch()
        lay.addLayout(row)
        lay.addWidget(privacy)
        lay.addStretch()

    def save(self) -> None:
        s = settings_mod.Settings(
            **{
                **asdict(self.vm.settings),
                "default_output_dir": self.out_dir.text().strip(),
                "output_suffix": self.suffix.text() or ".wm",
                "default_strength": self.strength.value(),
                "jpeg_quality": self.quality.value(),
                "video_mode": self.mode.currentText(),
                "video_codec": self.codec.currentText(),
                "video_crf": self.crf.value() or None,
                "detect_max_frames": self.frames.value(),
                "max_image_megapixels": self.mpix.value(),
                "max_video_minutes": self.vmin.value(),
                "max_file_gb": self.gb.value(),
                "benchmark_workers": self.workers.value(),
                "show_disclaimer": self.disclaimer.isChecked(),
            }
        )
        try:
            settings_mod.save(s, self.vm.home)
        except ValueError as e:
            QMessageBox.warning(self, "Settings", str(e))
            return
        self.vm.settings = s
        self.vm.limits = s.limits()
        QMessageBox.information(self, "Settings", "Saved.")

    def cleanup(self) -> None:
        from veilmark.security import tempfiles

        dirs = [Path(tempfile.gettempdir())]
        if self.vm.settings.default_output_dir:
            dirs.append(Path(self.vm.settings.default_output_dir))
        n = tempfiles.remove(tempfiles.find_stale(dirs))
        QMessageBox.information(self, "Cleanup", f"Removed {n} stale temporary item(s).")
