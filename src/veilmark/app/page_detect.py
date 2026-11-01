"""Detect tab: blind detection with separate detection / signature / trust results."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from veilmark.api import Veilmark, media_type
from veilmark.app.widgets import FileList, ProgressRow
from veilmark.app.worker import TaskRunner
from veilmark.core.tasks import Reporter
from veilmark.detection import report as rep_mod

STATUS_TEXT = {
    rep_mod.STATUS_PAYLOAD: ("Payload recovered", "#1a7f37"),
    rep_mod.STATUS_ID: ("Watermark id only", "#9a6700"),
    rep_mod.STATUS_SIGNAL: ("Signal present, payload unreadable", "#9a6700"),
    rep_mod.STATUS_NONE: ("No watermark detected", "#57606a"),
}
SIG_TEXT = {
    "valid": ("Signature valid", "#1a7f37"),
    "invalid": ("Signature INVALID — altered or forged", "#cf222e"),
    "unsigned": ("Unsigned payload", "#9a6700"),
    "unknown-key": ("Signed by an unknown key", "#9a6700"),
    "unverifiable": ("Signature could not be checked", "#9a6700"),
}
TRUST_TEXT = {
    "trusted": ("Issuer trusted", "#1a7f37"),
    "untrusted": ("Issuer NOT in your trust list", "#cf222e"),
    "revoked": ("Issuer key revoked", "#cf222e"),
    "expired": ("Outside the key's validity period", "#cf222e"),
    "not-yet-valid": ("Before the key's validity period", "#cf222e"),
    "n/a": ("Issuer trust not applicable", "#57606a"),
}


def _badge(text: str, color: str) -> str:
    return (
        f'<span style="background:{color};color:white;padding:2px 8px;border-radius:8px;">'
        f"{html.escape(text)}</span>"
    )


def render(r: rep_mod.DetectionReport) -> str:
    st = STATUS_TEXT.get(r.status, (r.status, "#57606a"))
    parts = [f"<h3>{html.escape(Path(r.source).name)}</h3>", "<p><b>1. Detection</b> ", _badge(*st), "</p>"]
    c = r.confidence
    parts.append(
        f"<p>sync z = {c.get('sync_z')} (presence threshold {c.get('sync_present_threshold')}); "
        f"estimated false-alarm p ≈ {c.get('sync_false_alarm', 1):.1e}"
    )
    if c.get("core_agreement") is not None:
        parts.append(f"; core agreement {c['core_agreement']}")
    if c.get("payload_agreement") is not None:
        parts.append(f"; payload agreement {c['payload_agreement']}")
    parts.append("</p>")
    if r.watermark_id:
        parts.append(f"<p>Watermark id: <code>{r.watermark_id}</code></p>")
    if r.payload:
        p = r.payload
        parts.append("<p><b>Recovered payload</b><br>")
        if p.get("text") is not None:
            parts.append(f"Text: <code>{html.escape(p['text'])}</code><br>")
        if p.get("timestamp_iso"):
            parts.append(f"Timestamp: {p['timestamp_iso']} <i>(claimed by the signer)</i><br>")
        if p.get("metadata_hex"):
            parts.append(f"Metadata: <code>{p['metadata_hex']}</code><br>")
        parts.append("</p>")
    v = r.verification
    if v:
        parts.append(
            "<p><b>2. Signature</b> "
            + _badge(*SIG_TEXT.get(v["signature"], (v["signature"], "#57606a")))
            + "</p>"
        )
        trust = TRUST_TEXT.get(v["trust"], (v["trust"], "#57606a"))
        who = f" — {html.escape(v['issuer_label'])} ({v['issuer_key_id']})" if v.get("issuer_key_id") else ""
        parts.append("<p><b>3. Issuer trust</b> " + _badge(*trust) + who + "</p>")
        parts.append(f"<p>{html.escape(v['message'])}</p>")
    if r.geometry:
        g = r.geometry
        parts.append(
            f"<p><small>Geometry: period {g['period_x']}×{g['period_y']} px, rotation "
            f"{g['rotation_deg']}°, mirrored {g['mirrored']} ({g['source']})</small></p>"
        )
    for a in r.additional:
        av = a.get("verification") or {}
        text = (a.get("payload") or {}).get("text")
        parts.append(
            "<p><b>Also found another watermark</b>: "
            + (f"<code>{html.escape(text)}</code> · " if text is not None else "")
            + f"signature {html.escape(str(av.get('signature', 'n/a')))}, "
            + f"issuer {html.escape(str(av.get('issuer_label') or 'unknown'))} ({html.escape(str(av.get('trust', '')))})</p>"
        )
    for n in r.notes:
        parts.append(f"<p><small>Note: {html.escape(n)}</small></p>")
    parts.append(f"<p><small><i>{html.escape(rep_mod.DISCLAIMER)}</i></small></p>")
    return "".join(parts)


class DetectPage(QWidget):
    def __init__(self, vm: Veilmark, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.vm = vm
        self.runner = TaskRunner(self)
        self.reports: list[rep_mod.DetectionReport] = []
        self.files = FileList("Media to check")
        self.pattern = QComboBox()
        self.pattern.setAccessibleName("Pattern key to try")
        self.max_frames = QSpinBox()
        self.max_frames.setRange(30, 20000)
        self.max_frames.setValue(vm.settings.detect_max_frames)
        self.max_frames.setToolTip("Video: frames analysed (sampled evenly); more = slower, more evidence")
        run = QPushButton("Detect")
        run.setDefault(True)
        run.clicked.connect(self.run)
        self.run_btn = run
        self.results = QListWidget()
        self.results.setAccessibleName("Detection results")
        self.results.currentRowChanged.connect(self._show)
        self.details = QTextBrowser()
        self.details.setAccessibleName("Report details")
        export = QPushButton("Export report…")
        export.clicked.connect(self.export)
        self.exporter = QComboBox()
        self.exporter.setAccessibleName("Export format")
        self.progress = ProgressRow()
        self.progress.cancel_requested.connect(self.runner.cancel)

        opts = QHBoxLayout()
        opts.addWidget(QLabel("Pattern key"))
        opts.addWidget(self.pattern)
        opts.addWidget(QLabel("Video frames"))
        opts.addWidget(self.max_frames)
        opts.addStretch()
        opts.addWidget(run)
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.addWidget(self.files)
        ll.addLayout(opts)
        ll.addWidget(QLabel("Results"))
        ll.addWidget(self.results)
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.addWidget(self.details)
        er = QHBoxLayout()
        er.addStretch()
        er.addWidget(self.exporter)
        er.addWidget(export)
        rl.addLayout(er)
        split = QSplitter()
        split.addWidget(left)
        split.addWidget(right)
        split.setStretchFactor(1, 2)
        lay = QVBoxLayout(self)
        lay.addWidget(split)
        lay.addWidget(self.progress)

        self.runner.progress.connect(self.progress.update)
        self.runner.busy_changed.connect(
            lambda b: (self.progress.set_busy(b), self.run_btn.setEnabled(not b))
        )
        self.runner.failed.connect(lambda m: QMessageBox.warning(self, "Detect", m))
        self.runner.finished.connect(self._done)
        self.refresh()

    def refresh(self) -> None:
        self.pattern.clear()
        self.pattern.addItem("All known keys", None)
        for k in self.vm.keystore.pattern_keys():
            self.pattern.addItem(f"{k.label} ({k.key_id})", k.key_id)
        self.exporter.clear()
        self.exporter.addItem("JSON", "json")
        api = getattr(self.vm.plugins, "api", None)
        for name in sorted(api.exporters if api else {}):
            self.exporter.addItem(f"{name} (plugin)", name)

    def run(self) -> None:
        paths = self.files.paths()
        if not paths:
            QMessageBox.information(self, "Detect", "Add files first.")
            return
        vm, key, maxf = self.vm, self.pattern.currentData(), self.max_frames.value()

        def job(rep: Reporter) -> list[Any]:
            out: list[Any] = []
            for i, p in enumerate(paths):
                sub = rep.sub(i / len(paths), (i + 1) / len(paths))
                try:
                    kw: dict[str, Any] = {"pattern_key": key, "reporter": sub}
                    if media_type(p) == "video":
                        kw["max_frames"] = maxf
                    out.append(vm.detect(p, **kw))
                except (ValueError, OSError, RuntimeError) as e:
                    out.append(f"{p.name}: {e}")
            return out

        self.runner.start(job)

    def _done(self, result: object) -> None:
        assert isinstance(result, list)
        self.results.clear()
        self.reports = []
        for r in result:
            if isinstance(r, str):
                self.results.addItem(QListWidgetItem("✗ " + r))
                self.reports.append(None)  # type: ignore[arg-type]
                continue
            label = STATUS_TEXT.get(r.status, (r.status, ""))[0]
            if r.verification:
                label += (
                    " · " + SIG_TEXT.get(r.verification["signature"], (r.verification["signature"], ""))[0]
                )
            self.results.addItem(f"{Path(r.source).name}: {label}")
            self.reports.append(r)
        if result:
            self.results.setCurrentRow(0)

    def _show(self, row: int) -> None:
        if 0 <= row < len(self.reports) and self.reports[row] is not None:
            self.details.setHtml(render(self.reports[row]))

    def export(self) -> None:
        row = self.results.currentRow()
        if not (0 <= row < len(self.reports)) or self.reports[row] is None:
            return
        r = self.reports[row]
        fmt = self.exporter.currentData()
        if fmt == "json":
            data, ext = json.dumps(r.to_dict(), indent=2, default=str).encode(), "json"
        else:
            data, ext = self.vm.plugins.api.exporters[fmt][1](r.to_dict())
        path, _ = QFileDialog.getSaveFileName(self, "Save report", f"{Path(r.source).stem}.report.{ext}")
        if path:
            Path(path).write_bytes(data)
