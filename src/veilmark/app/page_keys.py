"""Keys & trust tab: signing identities, pattern keys and trusted issuers."""

from __future__ import annotations

import base64
import contextlib
from datetime import UTC, datetime
from pathlib import Path

from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from veilmark.api import Veilmark
from veilmark.crypto import keys as keys_mod
from veilmark.storage.paths import atomic_write_bytes


def _ts(t: int | None) -> str:
    return datetime.fromtimestamp(t, UTC).strftime("%Y-%m-%d") if t else ""


def _table(headers: list[str]) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    t.horizontalHeader().setStretchLastSection(True)
    return t


class KeysPage(QWidget):
    def __init__(self, vm: Veilmark, on_change=None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.vm = vm
        self.on_change = on_change or (lambda: None)
        self.ids = _table(["Key id", "Label", "Status", "Encrypted", "Created", "Fingerprint"])
        self.ids.setAccessibleName("Signing identities")
        self.pks = _table(["Key id", "Label", "Created"])
        self.pks.setAccessibleName("Pattern keys")
        self.trust = _table(["Key id", "Label", "Status", "Revoked", "Fingerprint"])
        self.trust.setAccessibleName("Trusted issuers")

        def btn(label: str, slot) -> QPushButton:
            b = QPushButton(label)
            b.clicked.connect(slot)
            return b

        g1 = QGroupBox("Signing identities (Ed25519; private keys encrypted with your passphrase)")
        l1 = QVBoxLayout(g1)
        l1.addWidget(self.ids)
        r = QHBoxLayout()
        for b in (
            btn("Generate…", self.generate),
            btn("Rotate…", self.rotate),
            btn("Retire", lambda: self.set_status("retired")),
            btn("Revoke", lambda: self.set_status("revoked")),
            btn("Export public key…", self.export_public),
            btn("Export private key…", self.export_private),
            btn("Import private key…", self.import_private),
        ):
            r.addWidget(b)
        r.addStretch()
        l1.addLayout(r)

        g2 = QGroupBox("Pattern keys (secret; anyone holding one can detect your watermarks)")
        l2 = QVBoxLayout(g2)
        l2.addWidget(self.pks)
        r = QHBoxLayout()
        for b in (
            btn("Generate", self.gen_pattern),
            btn("Export…", self.export_pattern),
            btn("Import…", self.import_pattern),
        ):
            r.addWidget(b)
        r.addStretch()
        l2.addLayout(r)

        g3 = QGroupBox("Trusted issuers (only these make a signature 'trusted')")
        l3 = QVBoxLayout(g3)
        l3.addWidget(self.trust)
        r = QHBoxLayout()
        for b in (
            btn("Add issuer…", self.add_issuer),
            btn("Revoke", self.revoke_issuer),
            btn("Remove", self.remove_issuer),
        ):
            r.addWidget(b)
        r.addStretch()
        l3.addLayout(r)

        lay = QVBoxLayout(self)
        lay.addWidget(g1, 3)
        lay.addWidget(g2, 2)
        lay.addWidget(g3, 3)
        self.refresh()

    # ---------------------------------------------------------------- helpers
    def refresh(self) -> None:
        ids = self.vm.keystore.identities()
        self.ids.setRowCount(len(ids))
        for r, i in enumerate(ids):
            vals = [
                i.key_id,
                i.label,
                i.status,
                "yes" if i.private.get("scheme") != "plaintext" else "NO",
                _ts(i.created),
                keys_mod.format_fingerprint(i.public_bytes),
            ]
            for c, v in enumerate(vals):
                self.ids.setItem(r, c, QTableWidgetItem(v))
        pks = self.vm.keystore.pattern_keys()
        self.pks.setRowCount(len(pks))
        for r, k in enumerate(pks):
            for c, v in enumerate([k.key_id, k.label, _ts(k.created)]):
                self.pks.setItem(r, c, QTableWidgetItem(v))
        tr = self.vm.trust.issuers()
        self.trust.setRowCount(len(tr))
        for r, t in enumerate(tr):
            for c, v in enumerate(
                [t.key_id, t.label, t.status, _ts(t.revoked_at), keys_mod.format_fingerprint(t.public_bytes)]
            ):
                self.trust.setItem(r, c, QTableWidgetItem(v))

    def _changed(self) -> None:
        self.refresh()
        self.on_change()

    def _sel(self, table: QTableWidget) -> str | None:
        row = table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Keys", "Select a row first.")
            return None
        item = table.item(row, 0)
        return item.text() if item else None

    def _new_passphrase(self) -> tuple[bool, str | None]:
        pw, ok = QInputDialog.getText(
            self,
            "Passphrase",
            "Passphrase to encrypt the private key\n(leave empty to store it UNENCRYPTED):",
            QLineEdit.EchoMode.Password,
        )
        if not ok:
            return False, None
        if not pw:
            sure = QMessageBox.warning(
                self,
                "Unencrypted key",
                "Store the private key without encryption?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            return sure == QMessageBox.StandardButton.Yes, None
        again, ok = QInputDialog.getText(
            self, "Passphrase", "Repeat passphrase:", QLineEdit.EchoMode.Password
        )
        if not ok or again != pw:
            QMessageBox.warning(self, "Passphrase", "Passphrases do not match.")
            return False, None
        return True, pw

    def _try(self, fn) -> None:
        try:
            fn()
            self._changed()
        except (ValueError, OSError, keys_mod.KeyStoreError) as e:
            QMessageBox.warning(self, "Keys", str(e))

    # ---------------------------------------------------------------- actions
    def generate(self) -> None:
        label, ok = QInputDialog.getText(self, "New identity", "Label (e.g. your name or organisation):")
        if not ok or not label:
            return
        ok, pw = self._new_passphrase()
        if not ok:
            return

        def do() -> None:
            ident = self.vm.keystore.generate_identity(label, pw)
            self.vm.trust.add(ident.public_bytes, label, note="own identity")
            if not self.vm.keystore.pattern_keys():
                self.vm.keystore.generate_pattern_key()

        self._try(do)

    def rotate(self) -> None:
        kid = self._sel(self.ids)
        if not kid:
            return
        ok, pw = self._new_passphrase()
        if ok:

            def do() -> None:
                _, new = self.vm.keystore.rotate(kid, None, pw)
                self.vm.trust.add(new.public_bytes, new.label, note=f"rotated from {kid}")

            self._try(do)

    def set_status(self, status: str) -> None:
        kid = self._sel(self.ids)
        if not kid:
            return
        if (
            QMessageBox.question(self, "Key status", f"Mark {kid} as {status}?")
            != QMessageBox.StandardButton.Yes
        ):
            return

        def do() -> None:
            self.vm.keystore.set_status(kid, status)
            if status == "revoked":
                with contextlib.suppress(ValueError):
                    self.vm.trust.revoke(kid)

        self._try(do)

    def export_public(self) -> None:
        kid = self._sel(self.ids)
        if not kid:
            return
        ident = self.vm.keystore.identity(kid)
        path, _ = QFileDialog.getSaveFileName(self, "Export public key", f"{ident.label}.pub")
        if path:
            Path(path).write_text(f"veilmark-ed25519 {ident.public_key} {ident.label}\n")

    def export_private(self) -> None:
        kid = self._sel(self.ids)
        if not kid:
            return
        warn = QMessageBox.warning(
            self,
            "Export private key",
            "Anyone holding the exported file can sign as this identity.\n"
            "Only export for backup to secure storage. Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if warn != QMessageBox.StandardButton.Yes:
            return
        ident = self.vm.keystore.identity(kid)
        pw = None
        if ident.private.get("scheme") != "plaintext":
            pw, ok = QInputDialog.getText(self, "Unlock", "Passphrase:", QLineEdit.EchoMode.Password)
            if not ok:
                return
        path, _ = QFileDialog.getSaveFileName(self, "Export private key", f"{ident.label}.key")
        if path:

            def do() -> None:
                seed = self.vm.keystore.export_private_seed(kid, pw)
                atomic_write_bytes(Path(path), base64.b64encode(seed) + b"\n", private=True)

            self._try(do)

    def import_private(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import private key")
        if not path:
            return
        label, ok = QInputDialog.getText(self, "Import", "Label:")
        if not ok:
            return
        ok, pw = self._new_passphrase()
        if ok:
            self._try(
                lambda: self.vm.keystore.import_identity_seed(
                    base64.b64decode(Path(path).read_text().strip(), validate=True), label, pw
                )
            )

    def gen_pattern(self) -> None:
        label, ok = QInputDialog.getText(self, "Pattern key", "Label:", text="default")
        if ok:
            self._try(lambda: self.vm.keystore.generate_pattern_key(label or "default"))

    def export_pattern(self) -> None:
        kid = self._sel(self.pks)
        if not kid:
            return
        if (
            QMessageBox.warning(
                self,
                "Export pattern key",
                "Share pattern keys only with authorised detectors.\n"
                "Holders can detect and attempt to remove your watermarks. Continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        pk = self.vm.keystore.pattern_key(kid)
        path, _ = QFileDialog.getSaveFileName(self, "Export pattern key", f"{pk.label}.pattern")
        if path:
            atomic_write_bytes(Path(path), f"veilmark-pattern {pk.key} {pk.label}\n".encode(), private=True)

    def import_pattern(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import pattern key")
        if not path:
            return
        label, ok = QInputDialog.getText(self, "Import", "Label:")
        if ok:
            parts = Path(path).read_text().split()
            raw = parts[1] if parts and parts[0] == "veilmark-pattern" else parts[0]
            self._try(lambda: self.vm.keystore.add_pattern_key(keys_mod.b64d(raw), label or "imported"))

    def add_issuer(self) -> None:
        text, ok = QInputDialog.getMultiLineText(
            self,
            "Trust issuer",
            "Paste the issuer's public key (base64 or exported .pub line).\n"
            "Verify its fingerprint with the issuer over a separate channel:",
        )
        if not ok or not text.strip():
            return
        parts = text.split()
        raw = parts[1] if parts[0] == "veilmark-ed25519" else parts[0]
        label, ok = QInputDialog.getText(
            self, "Trust issuer", "Label:", text=parts[2] if len(parts) > 2 else ""
        )
        if not ok:
            return

        def do() -> None:
            pub = keys_mod.b64d(raw)
            fp = keys_mod.format_fingerprint(pub)
            if (
                QMessageBox.question(self, "Confirm fingerprint", f"Trust key with fingerprint\n{fp}?")
                == QMessageBox.StandardButton.Yes
            ):
                self.vm.trust.add(pub, label or "issuer")

        self._try(do)

    def revoke_issuer(self) -> None:
        kid = self._sel(self.trust)
        if kid:
            self._try(lambda: self.vm.trust.revoke(kid))

    def remove_issuer(self) -> None:
        kid = self._sel(self.trust)
        if (
            kid
            and QMessageBox.question(self, "Remove", f"Remove {kid} from the trust list?")
            == QMessageBox.StandardButton.Yes
        ):
            self._try(lambda: self.vm.trust.remove(kid))
