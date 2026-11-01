"""Watermark tab: payload entry, options, preview and batch embedding."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from veilmark.api import Veilmark, WatermarkSpec, media_type
from veilmark.app.widgets import FileList, ImagePane, ProgressRow, amplified_difference, zoom_crop
from veilmark.app.worker import TaskRunner
from veilmark.core.tasks import Reporter
from veilmark.image import io as image_io
from veilmark.video import ffmpeg


class WatermarkPage(QWidget):
    def __init__(self, vm: Veilmark, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.vm = vm
        self.runner = TaskRunner(self)
        self.files = FileList("Images and videos to watermark")

        self.text = QLineEdit()
        self.text.setPlaceholderText("e.g. © Studio North 2026 — short text is more robust")
        self.text.setAccessibleName("Hidden text")
        self.meta = QLineEdit()
        self.meta.setPlaceholderText("optional application metadata, hex")
        self.capacity = QLabel()
        self.identity = QComboBox()
        self.identity.setAccessibleName("Signing identity")
        self.pattern = QComboBox()
        self.pattern.setAccessibleName("Pattern key")
        self.timestamp = QCheckBox("Include creation timestamp (self-asserted)")
        self.timestamp.setChecked(True)
        self.strength = QDoubleSpinBox()
        self.strength.setRange(0.3, 3.0)
        self.strength.setSingleStep(0.1)
        self.strength.setValue(vm.settings.default_strength)
        self.strength.setToolTip("Higher = more robust but more visible. 1.0 ≈ 37–43 dB PSNR.")
        self.quality = QSpinBox()
        self.quality.setRange(50, 100)
        self.quality.setValue(vm.settings.jpeg_quality)
        self.video_mode = QComboBox()
        self.video_mode.addItems(["robust", "light"])
        self.video_mode.setCurrentText(vm.settings.video_mode)
        self.out_dir = QLineEdit(vm.settings.default_output_dir)
        self.out_dir.setPlaceholderText("same folder as each input")
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse)
        self.out_fmt = QComboBox()
        self.out_fmt.addItems(["same as input", "png", "jpg", "webp"])
        self.overwrite = QCheckBox("Allow replacing existing output files")
        self.public = QCheckBox("Publicly verifiable (anyone with your public key can verify)")
        self.public.setToolTip(
            "Uses a pattern derived from your public key instead of your secret pattern key, so "
            "verifiers need only your public key. Anyone who has it can also find the watermark and "
            "try to remove it. Requires a signing identity."
        )
        self.public.toggled.connect(lambda on: self.pattern.setEnabled(not on))
        self.rewatermark = QCheckBox("Allow adding a watermark to media that already has one")
        self.rewatermark.setToolTip(
            "Normally refused: a second watermark on the same tile period damages both. When allowed, "
            "the new one uses a different period so both stay detectable."
        )

        form = QFormLayout()
        form.addRow("Hidden text", self.text)
        form.addRow("", self.capacity)
        form.addRow("Metadata (hex)", self.meta)
        form.addRow("Signing identity", self.identity)
        form.addRow("Pattern key", self.pattern)
        form.addRow("", self.public)
        form.addRow("", self.timestamp)
        form.addRow("Strength", self.strength)
        form.addRow("JPEG/WebP quality", self.quality)
        form.addRow("Video mode", self.video_mode)
        od = QHBoxLayout()
        od.addWidget(self.out_dir)
        od.addWidget(browse)
        form.addRow("Output folder", od)
        form.addRow("Image output format", self.out_fmt)
        form.addRow("", self.overwrite)
        form.addRow("", self.rewatermark)
        opts = QGroupBox("Payload and options")
        opts.setLayout(form)

        self.before = ImagePane("Original")
        self.after = ImagePane("Watermarked")
        self.zoom_a = ImagePane("Original (1:1 centre)")
        self.zoom_b = ImagePane("Watermarked (1:1 centre)")
        self.diff = ImagePane("Difference ×12")
        self.metrics = QLabel("Preview shows the first image. PSNR/SSIM are measured, not assumed.")
        self.metrics.setWordWrap(True)
        prev_box = QGroupBox("Preview")
        pl = QVBoxLayout(prev_box)
        r1 = QHBoxLayout()
        r1.addWidget(self.before)
        r1.addWidget(self.after)
        r2 = QHBoxLayout()
        r2.addWidget(self.zoom_a)
        r2.addWidget(self.zoom_b)
        r2.addWidget(self.diff)
        pl.addLayout(r1)
        pl.addLayout(r2)
        pl.addWidget(self.metrics)

        self.preview_btn = QPushButton("Preview")
        self.run_btn = QPushButton("Watermark all files")
        self.run_btn.setDefault(True)
        self.preview_btn.clicked.connect(self.preview)
        self.run_btn.clicked.connect(self.run)
        self.progress = ProgressRow()
        self.progress.cancel_requested.connect(self.runner.cancel)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setAccessibleName("Results log")
        self.log.setMaximumBlockCount(2000)

        left = QVBoxLayout()
        left.addWidget(self.files, 2)
        left.addWidget(opts, 3)
        btns = QHBoxLayout()
        btns.addWidget(self.preview_btn)
        btns.addWidget(self.run_btn)
        left.addLayout(btns)
        right = QVBoxLayout()
        right.addWidget(prev_box, 3)
        right.addWidget(self.log, 1)
        top = QHBoxLayout()
        top.addLayout(left, 2)
        top.addLayout(right, 3)
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(self.progress)

        self.text.textChanged.connect(self._update_capacity)
        self.meta.textChanged.connect(self._update_capacity)
        self.identity.currentIndexChanged.connect(self._update_capacity)
        self.timestamp.toggled.connect(self._update_capacity)
        self.runner.progress.connect(self.progress.update)
        self.runner.busy_changed.connect(self._busy)
        self.runner.failed.connect(
            lambda m: (self._log("ERROR: " + m), QMessageBox.warning(self, "Watermark", m))
        )
        self.runner.cancelled.connect(lambda: self._log("cancelled (partial outputs removed)"))
        self.refresh()

    # ------------------------------------------------------------------ state
    def refresh(self) -> None:
        self.identity.clear()
        for i in self.vm.keystore.identities():
            if i.status == "active":
                self.identity.addItem(f"{i.label} ({i.key_id})", i.key_id)
        self.identity.addItem("Unsigned (no authenticity)", None)
        self.pattern.clear()
        for k in self.vm.keystore.pattern_keys():
            self.pattern.addItem(f"{k.label} ({k.key_id})", k.key_id)
        self._update_capacity()

    def _busy(self, busy: bool) -> None:
        self.progress.set_busy(busy)
        self.run_btn.setEnabled(not busy)
        self.preview_btn.setEnabled(not busy)

    def _browse(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Output folder")
        if d:
            self.out_dir.setText(d)

    def _log(self, s: str) -> None:
        self.log.appendPlainText(s)

    def _meta_bytes(self) -> bytes | None:
        t = self.meta.text().strip()
        return bytes.fromhex(t) if t else None

    def _update_capacity(self) -> None:
        try:
            spec = WatermarkSpec(
                text=self.text.text() or None,
                metadata=self._meta_bytes(),
                include_timestamp=self.timestamp.isChecked(),
                sign=self.identity.currentData() is not None,
            )
        except ValueError:
            self.capacity.setText("metadata must be hex")
            return
        c = self.vm.capacity_report(spec)
        if c["fits"]:
            self.capacity.setText(
                f"Payload {c['payload_bytes']} of {c['max_payload_bytes']} bytes "
                "(signature uses 64; shorter is more robust)"
            )
        else:
            self.capacity.setText(
                "Too long: "
                + str(c.get("reason") or f"{c['payload_bytes']} > {c['max_payload_bytes']} bytes")
            )

    def _spec(self) -> WatermarkSpec | None:
        if not self.vm.keystore.pattern_keys():
            QMessageBox.information(self, "Watermark", "Create a pattern key first (Keys & trust tab).")
            return None
        kid = self.identity.currentData()
        public = self.public.isChecked()
        if public and kid is None:
            QMessageBox.information(self, "Watermark", "A publicly verifiable watermark must be signed.")
            return None
        pw = None
        if kid is not None:
            ident = self.vm.keystore.identity(kid)
            if ident.private.get("scheme") != "plaintext":
                pw, ok = QInputDialog.getText(
                    self, "Unlock signing key", f"Passphrase for {ident.label}:", QLineEdit.EchoMode.Password
                )
                if not ok:
                    return None
        try:
            meta = self._meta_bytes()
        except ValueError:
            QMessageBox.warning(self, "Watermark", "Metadata must be hexadecimal.")
            return None
        return WatermarkSpec(
            text=self.text.text() or None,
            metadata=meta,
            include_timestamp=self.timestamp.isChecked(),
            sign=kid is not None,
            identity=kid,
            passphrase=pw,
            pattern_key=None if public else self.pattern.currentData(),
            public=public,
            strength=self.strength.value(),
            quality=self.quality.value(),
            allow_rewatermark=self.rewatermark.isChecked(),
        )

    def _output_for(self, src: Path) -> Path:
        d = Path(self.out_dir.text()) if self.out_dir.text().strip() else src.parent
        suffix = self.vm.settings.output_suffix
        if media_type(src) == "video":
            ext = src.suffix if src.suffix.lower() in (".mp4", ".mov", ".mkv", ".webm") else ".mp4"
            return d / f"{src.stem}{suffix}{ext}"
        fmt = self.out_fmt.currentText()
        ext = src.suffix if fmt == "same as input" else "." + fmt
        if ext.lower() not in image_io.SUPPORTED_WRITE:
            ext = ".png"
        return d / f"{src.stem}{suffix}{ext}"

    # ---------------------------------------------------------------- actions
    def preview(self) -> None:
        imgs = [p for p in self.files.paths() if media_type(p) == "image"]
        if not imgs:
            QMessageBox.information(self, "Preview", "Add at least one image to preview.")
            return
        spec = self._spec()
        if spec is None:
            return
        vm = self.vm

        def job(rep: Reporter) -> Any:
            img = image_io.load(imgs[0], vm.limits)
            out, res = vm.embed_image_data(img, spec, rep)
            return img.rgb, out.rgb, res

        def show(result: Any) -> None:
            a, b, res = result
            self.before.show_array(a)
            self.after.show_array(b)
            self.zoom_a.show_array(zoom_crop(a))
            self.zoom_b.show_array(zoom_crop(b))
            self.diff.show_array(amplified_difference(zoom_crop(a), zoom_crop(b)))
            self.metrics.setText(
                f"PSNR {res.psnr_db} dB · SSIM {res.ssim} · chip {res.chip_px}px · tile {res.tile_period_px}px · "
                f"payload {res.payload_bytes} B. Inspect the 1:1 crops on flat areas before publishing."
            )

        self._connect_once(show)
        self.runner.start(job)

    def run(self) -> None:
        paths = self.files.paths()
        if not paths:
            QMessageBox.information(self, "Watermark", "Add files first.")
            return
        spec = self._spec()
        if spec is None:
            return
        if any(media_type(p) == "video" for p in paths) and not ffmpeg.available():
            QMessageBox.warning(self, "Watermark", ffmpeg.INSTALL_HINT)
            return
        vm, mode, overwrite = self.vm, self.video_mode.currentText(), self.overwrite.isChecked()
        jobs = [(p, self._output_for(p)) for p in paths]

        def job(rep: Reporter) -> list[str]:
            lines = []
            for i, (src, dst) in enumerate(jobs):
                sub = rep.sub(i / len(jobs), (i + 1) / len(jobs))
                try:
                    if media_type(src) == "video":
                        enc = ffmpeg.EncodeSettings(codec=vm.settings.video_codec, crf=vm.settings.video_crf)
                        r = vm.embed_video(
                            src, dst, spec, overwrite=overwrite, mode=mode, encode=enc, reporter=sub
                        )
                    else:
                        r = vm.embed_image(src, dst, spec, overwrite=overwrite, reporter=sub)
                    lines.append(
                        f"✓ {src.name} → {dst}  id {r.watermark_id}  PSNR {r.psnr_db} dB"
                        + "".join(f"\n   note: {n}" for n in r.notes)
                    )
                except (ValueError, OSError, RuntimeError) as e:
                    lines.append(f"✗ {src.name}: {e}")
            return lines

        self._connect_once(lambda lines: [self._log(s) for s in lines])
        self.runner.start(job)

    def _connect_once(self, slot: Any) -> None:
        def wrapper(result: object) -> None:
            self.runner.finished.disconnect(wrapper)
            slot(result)

        self.runner.finished.connect(wrapper)
