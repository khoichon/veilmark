"""Robustness laboratory tab: attack a chosen image, or run the dataset benchmark."""

from __future__ import annotations

import csv
import json
import time
from pathlib import Path
from typing import Any

import numpy as np
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from veilmark.api import Veilmark, WatermarkSpec
from veilmark.app.widgets import ProgressRow
from veilmark.app.worker import TaskRunner
from veilmark.benchmarks import attacks as atk
from veilmark.core.tasks import Reporter
from veilmark.image import io as image_io

COLUMNS = ["Attack", "Group", "Status", "Payload exact", "Signature", "Sync z", "Seconds", "Size"]


class LabPage(QWidget):
    def __init__(self, vm: Veilmark, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.vm = vm
        self.runner = TaskRunner(self)
        self.rows: list[dict[str, Any]] = []

        self.media = QLineEdit()
        self.media.setPlaceholderText("Choose a test image…")
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse)
        self.attacks = QListWidget()
        self.attacks.setAccessibleName("Attacks to run")
        for a in atk.IMAGE_ATTACKS:
            it = QListWidgetItem(f"{a.name}  [{a.group}]")
            it.setData(Qt.ItemDataRole.UserRole, a.name)
            it.setFlags(it.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            it.setCheckState(
                Qt.CheckState.Checked if a.name in atk.QUICK_ATTACKS else Qt.CheckState.Unchecked
            )
            self.attacks.addItem(it)
        self.strength = QDoubleSpinBox()
        self.strength.setRange(0.3, 3.0)
        self.strength.setValue(1.0)
        self.seed = QSpinBox()
        self.seed.setRange(0, 10_000)
        run = QPushButton("Run on this image")
        run.clicked.connect(self.run_single)
        self.split = QComboBox()
        self.split.addItems(["heldout", "dev", "all"])
        self.profile = QComboBox()
        self.profile.addItems(["quick", "standard", "full"])
        bench = QPushButton("Run dataset benchmark…")
        bench.clicked.connect(self.run_benchmark)
        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table.setAccessibleName("Robustness results")
        self.summary = QLabel("Results are measurements on your media; they are not guarantees.")
        self.summary.setWordWrap(True)
        exp = QPushButton("Export CSV/JSON…")
        exp.clicked.connect(self.export)
        self.progress = ProgressRow()
        self.progress.cancel_requested.connect(self.runner.cancel)

        g = QGroupBox("Single-image test")
        gl = QVBoxLayout(g)
        row = QHBoxLayout()
        row.addWidget(self.media)
        row.addWidget(browse)
        gl.addLayout(row)
        gl.addWidget(QLabel("Transformations"))
        gl.addWidget(self.attacks)
        row = QHBoxLayout()
        row.addWidget(QLabel("Strength"))
        row.addWidget(self.strength)
        row.addWidget(QLabel("Random seed"))
        row.addWidget(self.seed)
        row.addStretch()
        row.addWidget(run)
        gl.addLayout(row)
        g2 = QGroupBox("Dataset benchmark (dev / held-out split, multiple seeds, false-positive measurement)")
        g2l = QHBoxLayout(g2)
        g2l.addWidget(QLabel("Split"))
        g2l.addWidget(self.split)
        g2l.addWidget(QLabel("Profile"))
        g2l.addWidget(self.profile)
        g2l.addStretch()
        g2l.addWidget(bench)
        left = QVBoxLayout()
        left.addWidget(g)
        left.addWidget(g2)
        right = QVBoxLayout()
        right.addWidget(self.table)
        right.addWidget(self.summary)
        er = QHBoxLayout()
        er.addStretch()
        er.addWidget(exp)
        right.addLayout(er)
        top = QHBoxLayout()
        top.addLayout(left, 2)
        top.addLayout(right, 3)
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(self.progress)
        self.runner.progress.connect(self.progress.update)
        self.runner.busy_changed.connect(self.progress.set_busy)
        self.runner.failed.connect(lambda m: QMessageBox.warning(self, "Lab", m))

    def _browse(self) -> None:
        p, _ = QFileDialog.getOpenFileName(
            self, "Test image", "", "Images (*.png *.jpg *.jpeg *.webp *.tif *.tiff)"
        )
        if p:
            self.media.setText(p)

    def _selected(self) -> list[str]:
        out = []
        for i in range(self.attacks.count()):
            it = self.attacks.item(i)
            if it.checkState() == Qt.CheckState.Checked:
                out.append(it.data(Qt.ItemDataRole.UserRole))
        return out

    def run_single(self) -> None:
        path = Path(self.media.text())
        names = self._selected()
        if not path.is_file() or not names:
            QMessageBox.information(self, "Lab", "Choose an image and at least one transformation.")
            return
        if not self.vm.keystore.pattern_keys():
            QMessageBox.information(self, "Lab", "Create a pattern key first (Keys & trust tab).")
            return
        vm, strength, seed = self.vm, self.strength.value(), self.seed.value()

        def job(rep: Reporter) -> dict[str, Any]:
            img = image_io.load(path, vm.limits)
            text = "lab test"
            marked, res = vm.embed_image_data(img, WatermarkSpec(text=text, sign=False, strength=strength))
            rows = []
            for i, name in enumerate(names):
                rep(i / len(names), f"{name}")
                a = atk.image_attacks([name])[0]
                for pol, src in (("watermarked", marked.rgb), ("original", img.rgb)):
                    out = a.fn(src, np.random.default_rng(seed))
                    t0 = time.perf_counter()
                    r = vm.detect_image_data(image_io.ImageData(np.ascontiguousarray(out)))
                    rows.append(
                        {
                            "attack": name,
                            "group": a.group,
                            "copy": pol,
                            "status": r.status,
                            "payload_exact": bool(r.payload and r.payload.get("text") == text)
                            if pol == "watermarked"
                            else None,
                            "signature": (r.verification or {}).get("signature"),
                            "sync_z": r.confidence.get("sync_z"),
                            "seconds": round(time.perf_counter() - t0, 2),
                            "size": f"{out.shape[1]}x{out.shape[0]}",
                        }
                    )
            return {"rows": rows, "psnr": res.psnr_db, "ssim": res.ssim}

        def done(result: object) -> None:
            self.runner.finished.disconnect(done)
            assert isinstance(result, dict)
            self.rows = result["rows"]
            self._fill()
            pos = [r for r in self.rows if r["copy"] == "watermarked"]
            neg = [r for r in self.rows if r["copy"] == "original"]
            ok = sum(bool(r["payload_exact"]) for r in pos)
            fp = sum(r["status"] != "not-detected" for r in neg)
            self.summary.setText(
                f"Embedding PSNR {result['psnr']} dB, SSIM {result['ssim']}. Payload recovered exactly in {ok}/{len(pos)} "
                f"transformed copies; false detections on the unwatermarked original: {fp}/{len(neg)}. "
                "One image and one seed: use the dataset benchmark for rates with confidence intervals."
            )

        self.runner.finished.connect(done)
        self.runner.start(job)

    def run_benchmark(self) -> None:
        out = QFileDialog.getExistingDirectory(self, "Folder for benchmark reports")
        if not out:
            return
        from veilmark.benchmarks import runner

        cfg = runner.BenchConfig(
            out_dir=Path(out), split=self.split.currentText(), profile=self.profile.currentText()
        )
        if self.vm.settings.benchmark_workers:
            cfg.workers = self.vm.settings.benchmark_workers

        def job(rep: Reporter) -> dict[str, Any]:
            return runner.run(cfg, rep)

        def done(result: object) -> None:
            self.runner.finished.disconnect(done)
            assert isinstance(result, dict)
            self.rows = [
                {
                    "attack": r["attack"],
                    "group": r["group"],
                    "copy": r["media"],
                    "status": f"payload {100 * r['payload_recovery']['rate']:.0f}% (n={r['payload_recovery']['n']})",
                    "payload_exact": f"[{100 * r['payload_recovery']['ci95_low']:.0f}-{100 * r['payload_recovery']['ci95_high']:.0f}]",
                    "signature": f"FP {100 * r['false_positive_detect']['rate']:.0f}%",
                    "sync_z": r["median_sync_z_pos"],
                    "seconds": r["median_detect_seconds"],
                    "size": "",
                }
                for r in result["rows"]
            ]
            self._fill()
            self.summary.setText(f"Benchmark written to {out} (report.html, summary.csv, records.jsonl).")

        self.runner.finished.connect(done)
        self.runner.start(job)

    def _fill(self) -> None:
        self.table.setRowCount(len(self.rows))
        keys = ["attack", "group", "status", "payload_exact", "signature", "sync_z", "seconds", "size"]
        for r, row in enumerate(self.rows):
            for c, k in enumerate(keys):
                v = row.get(k)
                text = (
                    f"{row['copy']}: {v}"
                    if k == "status" and row.get("copy") in ("watermarked", "original")
                    else ("" if v is None else str(v))
                )
                self.table.setItem(r, c, QTableWidgetItem(text))

    def export(self) -> None:
        if not self.rows:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export results", "lab-results.csv", "CSV (*.csv);;JSON (*.json)"
        )
        if not path:
            return
        if path.endswith(".json"):
            Path(path).write_text(json.dumps(self.rows, indent=2))
        else:
            with open(path, "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(self.rows[0]))
                w.writeheader()
                w.writerows(self.rows)
