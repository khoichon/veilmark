"""Detection reports: what was found, how sure we are, and who signed it.

Three questions are answered separately and must never be conflated:

1. *Is a watermark signal present?* (sync statistic, calibrated thresholds)
2. *Was the payload recovered intact?* (error correction + CRC; never guessed)
3. *Is the payload authentic?* (Ed25519 signature validity + issuer trust policy)

Even a fully authentic result only says that the recovered payload was signed by a
trusted key. It does not prove that the media is unedited, that the signer created
it, or anything about the depicted content.
"""

from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from veilmark import __version__
from veilmark.crypto import payload as payload_mod
from veilmark.crypto import trust as trust_mod
from veilmark.watermark import engine

STATUS_PAYLOAD = "payload-recovered"
STATUS_ID = "id-only"
STATUS_SIGNAL = "signal-only"
STATUS_NONE = "not-detected"

DISCLAIMER = (
    "A valid signature shows only that the recovered payload was signed by the listed "
    "key. It does not prove the media is unedited, who created it, or that its content "
    "is true. Watermarks can be weakened or removed; absence of a detected watermark "
    "proves nothing."
)


def sync_false_alarm(z: float, searched: int) -> float:
    """Union-bound estimate of P(max sync z >= z | no watermark), Gaussian model.

    Approximate; empirical false-positive rates are measured by the benchmark.
    """
    q = 0.5 * math.erfc(z / math.sqrt(2.0))
    return float(min(1.0, searched * q))


@dataclass
class DetectionReport:
    source: str
    media_type: str
    status: str
    watermark_id: str | None = None
    payload: dict[str, Any] | None = None
    verification: dict[str, Any] | None = None
    confidence: dict[str, Any] = field(default_factory=dict)
    geometry: dict[str, Any] | None = None
    diagnostics: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    # Other watermarks found in the same media (e.g. it was watermarked more than once).
    additional: list[dict[str, Any]] = field(default_factory=list)
    created: str = field(default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds"))

    @property
    def detected(self) -> bool:
        return self.status in (STATUS_PAYLOAD, STATUS_ID, STATUS_SIGNAL)

    @property
    def authentic(self) -> bool:
        return bool(self.verification and self.verification.get("authentic"))

    def summary(self) -> str:
        lines = [f"{self.source}: {self.status}"]
        if self.watermark_id:
            lines.append(f"  watermark id : {self.watermark_id}")
        if self.payload:
            if self.payload.get("text") is not None:
                lines.append(f"  text         : {self.payload['text']!r}")
            if self.payload.get("timestamp_iso"):
                lines.append(f"  timestamp    : {self.payload['timestamp_iso']} (self-asserted)")
            if self.payload.get("metadata_hex"):
                lines.append(f"  metadata     : {self.payload['metadata_hex']}")
        if self.verification:
            v = self.verification
            lines.append(f"  signature    : {v['signature']}")
            lines.append(
                f"  issuer trust : {v['trust']}"
                + (f" ({v['issuer_label']}, {v['issuer_key_id']})" if v.get("issuer_key_id") else "")
            )
            lines.append(f"  verdict      : {v['message']}")
        c = self.confidence
        if c:
            lines.append(
                f"  evidence     : sync z={c.get('sync_z', 0):.1f}"
                + (f", est. false-alarm p~{c['sync_false_alarm']:.1e}" if "sync_false_alarm" in c else "")
                + (
                    f", core agreement {c['core_agreement']:.2f}"
                    if c.get("core_agreement") is not None
                    else ""
                )
                + (
                    f", payload agreement {c['payload_agreement']:.2f}"
                    if c.get("payload_agreement") is not None
                    else ""
                )
            )
        for a in self.additional:
            who = (a.get("verification") or {}).get("issuer_label") or "unknown issuer"
            sig = (a.get("verification") or {}).get("signature", "n/a")
            text = (a.get("payload") or {}).get("text")
            lines.append(
                f"  ALSO FOUND   : watermark {a.get('watermark_id')} ({a['status']}, signature {sig}, {who})"
                + (f" text {text!r}" if text is not None else "")
            )
        for n in self.notes:
            lines.append(f"  note         : {n}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "veilmark_version": __version__,
            "report_version": 1,
            "source": self.source,
            "media_type": self.media_type,
            "status": self.status,
            "detected": self.detected,
            "authentic": self.authentic,
            "watermark_id": self.watermark_id,
            "payload": self.payload,
            "verification": self.verification,
            "confidence": self.confidence,
            "geometry": self.geometry,
            "diagnostics": self.diagnostics,
            "notes": self.notes,
            "additional_watermarks": self.additional,
            "created": self.created,
            "disclaimer": DISCLAIMER,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=False, default=str)


def payload_dict(p: payload_mod.Payload) -> dict[str, Any]:
    return {
        "text": p.text,
        "timestamp": p.timestamp,
        "timestamp_iso": (
            datetime.fromtimestamp(p.timestamp, UTC).isoformat() if p.timestamp is not None else None
        ),
        "metadata_hex": p.metadata.hex() if p.metadata is not None else None,
        "signed": p.signed,
        "key_id_hint": p.key_id.hex() if p.key_id else None,
    }


def interpret(
    source: str,
    media_type: str,
    sync_z: float,
    searched: int,
    outcome: engine.DecodeOutcome | None,
    trust: trust_mod.TrustStore,
    extra_keys: list[tuple[bytes, str]] | None = None,
    pattern_key_ids: list[str] | None = None,
) -> DetectionReport:
    """Turn raw decode results into a report with honest status levels."""
    t0 = time.perf_counter()
    rep = DetectionReport(source, media_type, STATUS_NONE)
    rep.confidence = {
        "sync_z": round(float(sync_z), 2),
        "sync_false_alarm": sync_false_alarm(sync_z, searched),
        "sync_present_threshold": engine.SYNC_PRESENT_Z,
    }
    if pattern_key_ids:
        rep.diagnostics["pattern_keys_tried"] = pattern_key_ids
    core_ok = False
    if outcome is not None:
        rep.confidence["core_agreement"] = round(outcome.core.bit_agreement, 3)
        if outcome.full is not None:
            rep.confidence["payload_agreement"] = round(outcome.full.bit_agreement, 3)
        core_ok = (
            outcome.core.ok
            and outcome.core.bit_agreement >= engine.CORE_MIN_AGREEMENT
            and sync_z >= engine.SYNC_ID_Z
        )
        if core_ok and outcome.core.watermark_id is not None:
            rep.watermark_id = outcome.core.watermark_id.hex()
            rep.status = STATUS_ID
        if outcome.full is not None and outcome.full.ok and outcome.full.body is not None:
            try:
                p, body = payload_mod.parse(outcome.full.body)
            except payload_mod.PayloadError as e:
                rep.notes.append(f"payload layer passed its CRC but is malformed: {e}")
            else:
                rep.payload = payload_dict(p)
                rep.status = STATUS_PAYLOAD
                if outcome.core.ok and outcome.core.watermark_id is not None:
                    wid = outcome.core.watermark_id
                    rep.watermark_id = wid.hex()
                    rep.verification = trust_mod.verify(wid, p, body, trust, extra_keys).as_dict()
                elif p.signed:
                    rep.verification = trust_mod.Verification(
                        "unverifiable",
                        "n/a",
                        None,
                        None,
                        "payload recovered but the watermark id (core layer) was not, so "
                        "the signature cannot be checked",
                    ).as_dict()
                else:
                    rep.verification = trust_mod.Verification(
                        "unsigned", "n/a", None, None, "payload carries no signature"
                    ).as_dict()
                if rep.verification and rep.verification["signature"] == "unsigned":
                    rep.notes.append("unsigned payload: anyone with the pattern key could have embedded it")
    if rep.status == STATUS_NONE and sync_z >= engine.SYNC_PRESENT_Z:
        rep.status = STATUS_SIGNAL
        rep.notes.append(
            "watermark signal detected but the payload could not be recovered; nothing is guessed"
        )
    if rep.status == STATUS_ID:
        rep.notes.append(
            "only the watermark id was recovered (robust core layer); the signed payload "
            "was too damaged to decode"
        )
    rep.diagnostics["interpret_ms"] = round((time.perf_counter() - t0) * 1000, 2)
    return rep
