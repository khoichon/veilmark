"""High-level operations shared by the CLI, desktop GUI and local web helper.

Front-ends never touch the watermark engine or key files directly; they go through
:class:`Veilmark`, which owns the key store, trust list and limits.
"""

from __future__ import annotations

import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

from veilmark.core import metrics
from veilmark.core.tasks import Reporter
from veilmark.crypto import keys as keys_mod
from veilmark.crypto import payload as payload_mod
from veilmark.crypto import trust as trust_mod
from veilmark.detection import report as report_mod
from veilmark.image import io as image_io
from veilmark.security.limits import InputError, Limits, check_output_path
from veilmark.storage import paths
from veilmark.storage import settings as settings_mod
from veilmark.watermark import backends, engine, framing
from veilmark.watermark.pattern import KeyedPatterns

STRENGTH_PRESETS = {"subtle": 0.6, "balanced": 1.0, "robust": 1.5}


def parse_strength(value: str | float) -> float:
    """A preset name (subtle / balanced / robust) or a number in 0.1..4.0."""
    if isinstance(value, str) and value.lower() in STRENGTH_PRESETS:
        return STRENGTH_PRESETS[value.lower()]
    try:
        v = float(value)
    except ValueError:
        raise ValueError(f"strength must be a number or one of {sorted(STRENGTH_PRESETS)}") from None
    if not 0.1 <= v <= 4.0:
        raise ValueError("strength must be within 0.1..4.0")
    return v


@dataclass
class WatermarkSpec:
    """What to embed and how."""

    text: str | None = None
    metadata: bytes | None = None
    include_timestamp: bool = True
    sign: bool = True
    identity: str | None = None  # key id prefix or label; None = newest active
    passphrase: str | None = None
    pattern_key: str | None = None  # key id prefix or label; None = first key
    public: bool = False  # publicly verifiable: pattern derived from the signing public key
    strength: float = 1.0
    chip_px: int | None = None
    quality: int = 95  # lossy output quality (JPEG/WebP)
    backend: str = "tss"  # image backend (plugins may add more)
    check_existing: bool = True  # look for watermarks already present before embedding
    allow_rewatermark: bool = False  # proceed anyway (new mark uses a different tile period)
    watermark_id: bytes | None = None  # normally random; fixed only for tests


class AlreadyWatermarked(InputError):
    """The input already carries a watermark readable with the local pattern keys."""

    def __init__(self, existing: list[dict[str, Any]]) -> None:
        self.existing = existing
        first = existing[0]
        who = first.get("issuer") or "an unknown or untrusted issuer"
        ident = f"id {first['watermark_id']}" if first.get("watermark_id") else first["status"]
        super().__init__(
            f"this media already carries a Veilmark watermark ({ident}, signed by {who}). "
            "Watermarking it again on the same tile period would damage both. Use the "
            "unwatermarked original, or allow re-watermarking (--allow-rewatermark): the new "
            "watermark then uses a different tile period so both stay detectable."
        )


def _existing_entry(rep: report_mod.DetectionReport, period: float, z: float) -> dict[str, Any]:
    v = rep.verification or {}
    return {
        "status": rep.status,
        "watermark_id": rep.watermark_id,
        "issuer": v.get("issuer_label") if v.get("signature") == "valid" else None,
        "period": float(period),
        "sync_z": round(z, 2),
    }


@dataclass
class EmbedResult:
    output: str | None
    watermark_id: str
    payload_bytes: int
    capacity_class: int
    signed: bool
    signer_key_id: str | None
    pattern_key_id: str
    chip_px: int
    tile_period_px: int
    strength: float
    psnr_db: float | None
    ssim: float | None
    bytes_written: int | None
    seconds: float
    notes: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class Veilmark:
    def __init__(self, home: Path | None = None, limits: Limits | None = None) -> None:
        self.home = Path(home) if home else paths.data_home()
        self.keystore = keys_mod.KeyStore(self.home)
        self.trust = trust_mod.TrustStore(self.home)
        self.settings = settings_mod.load(self.home)
        self.limits = limits or self.settings.limits()
        self._plugins: Any = None

    @property
    def plugins(self) -> Any:
        """Plugin manager (plugins are only imported by :meth:`load_plugins`)."""
        if self._plugins is None:
            from veilmark.plugins.manager import PluginManager

            self._plugins = PluginManager(self.home)
        return self._plugins

    def load_plugins(self) -> list[Any]:
        return self.plugins.load_enabled()

    # ------------------------------------------------------------------ keys
    def public_pattern_keys(self) -> list[keys_mod.PatternKey]:
        """Pattern keys of publicly verifiable watermarks: derived from the public key of
        every identity of your own and every issuer in the trust list."""
        out: dict[str, keys_mod.PatternKey] = {}
        sources = [(i.public_bytes, i.label) for i in self.keystore.identities()]
        sources += [(t.public_bytes, t.label) for t in self.trust.issuers()]
        for pub, label in sources:
            key = keys_mod.public_pattern_key(pub)
            kid = keys_mod.pattern_key_id(key)
            out.setdefault(kid, keys_mod.PatternKey(kid, f"public: {label}", keys_mod.b64e(key), 0))
        return list(out.values())

    def detection_pattern_keys(self) -> list[keys_mod.PatternKey]:
        """Every pattern key detection tries: stored (secret) keys, then public ones."""
        stored = self.keystore.pattern_keys()
        seen = {k.key_id for k in stored}
        return stored + [k for k in self.public_pattern_keys() if k.key_id not in seen]

    def embedding_pattern_key(self, spec: WatermarkSpec) -> keys_mod.PatternKey:
        """The pattern key a new watermark uses: a stored secret key, or for a public
        watermark the key derived from the signing identity's public key."""
        if not spec.public:
            return self.keystore.pattern_key(spec.pattern_key)
        if not spec.sign:
            raise InputError("a publicly verifiable watermark must be signed")
        if spec.pattern_key is not None:
            raise InputError("a publicly verifiable watermark cannot use a chosen pattern key")
        ident = self.keystore.identity(spec.identity)
        key = keys_mod.public_pattern_key(ident.public_bytes)
        kid = keys_mod.pattern_key_id(key)
        return keys_mod.PatternKey(kid, f"public: {ident.label}", keys_mod.b64e(key), 0)

    def keyring(self, ref: str | None = None) -> tuple[list[KeyedPatterns], list[str]]:
        """Pattern keys to try during detection (one, or all known keys)."""
        pk = [self.keystore.pattern_key(ref)] if ref is not None else self.detection_pattern_keys()
        if not pk:
            raise keys_mod.KeyStoreError(
                "no pattern key available; run `veilmark keys init`, import a pattern key, "
                "or trust an issuer who makes publicly verifiable watermarks"
            )
        return [KeyedPatterns(k.key_bytes) for k in pk], [k.key_id for k in pk]

    def own_public_keys(self) -> list[tuple[bytes, str]]:
        return [(i.public_bytes, i.label) for i in self.keystore.identities()]

    def build_payload(self, spec: WatermarkSpec, watermark_id: bytes) -> tuple[bytes, str | None]:
        ts = int(time.time()) if spec.include_timestamp else None
        p = payload_mod.Payload(text=spec.text, timestamp=ts, metadata=spec.metadata)
        signer_id = None
        if spec.sign:
            ident = self.keystore.identity(spec.identity)
            if ident.status != "active":
                raise keys_mod.KeyStoreError(f"identity {ident.key_id} is {ident.status} and cannot sign")
            p = trust_mod.sign(watermark_id, p, ident.unlock(spec.passphrase))
            signer_id = ident.key_id
        raw = p.to_bytes()
        framing.choose_class(len(raw))  # raises a clear error if over capacity
        return raw, signer_id

    @staticmethod
    def capacity_report(spec: WatermarkSpec) -> dict[str, Any]:
        """Size of the payload that ``spec`` would produce, without signing."""
        p = payload_mod.Payload(
            text=spec.text,
            timestamp=0 if spec.include_timestamp else None,
            metadata=spec.metadata,
            key_id=b"\0" * 4 if spec.sign else None,
            signature=b"\0" * 64 if spec.sign else None,
        )
        maxp = framing.LENGTH_CLASSES[-1] - 4
        try:
            n = len(p.to_bytes())
        except payload_mod.PayloadError as e:
            return {
                "payload_bytes": None,
                "class_bytes": None,
                "max_payload_bytes": maxp,
                "fits": False,
                "reason": str(e),
            }
        try:
            ci = framing.choose_class(n)
            return {
                "payload_bytes": n,
                "class_bytes": framing.LENGTH_CLASSES[ci],
                "max_payload_bytes": maxp,
                "fits": True,
            }
        except ValueError:
            return {"payload_bytes": n, "class_bytes": None, "max_payload_bytes": maxp, "fits": False}

    # ---------------------------------------------------------------- images
    def embed_image_data(
        self, img: image_io.ImageData, spec: WatermarkSpec, reporter: Reporter | None = None
    ) -> tuple[image_io.ImageData, EmbedResult]:
        rep = reporter or Reporter()
        t0 = time.perf_counter()
        rep(0.05, "preparing payload")
        wid = spec.watermark_id or os.urandom(8)
        raw, signer = self.build_payload(spec, wid)
        pk = self.embedding_pattern_key(spec)
        pats = KeyedPatterns(pk.key_bytes)
        if min(img.height, img.width) < 128:
            raise InputError("image too small to watermark (minimum 128 px on the short side)")
        avoid: list[float] | None = None
        existing: list[dict[str, Any]] = []
        if spec.check_existing:
            rep(0.08, "checking for existing watermarks")
            existing = self.existing_watermarks(img)
            if existing and not spec.allow_rewatermark:
                raise AlreadyWatermarked(existing)
            avoid = [e["period"] for e in existing] or None
        plan = engine.make_plan(
            pats, wid, raw, img.height, img.width, spec.strength, spec.chip_px, avoid_periods=avoid
        )
        rep(0.3, "embedding")
        y = img.luma()
        if spec.backend == "tss":
            delta = plan.delta(y, {engine.variant_for_id(wid): 1.0})
        else:
            delta = backends.get(spec.backend).embed_luma_delta(y, wid, raw, pk.key_bytes, spec.strength)
        out_rgb = np.clip(np.rint(img.rgb.astype(np.float32) + delta[..., None]), 0, 255).astype(np.uint8)
        out = image_io.ImageData(out_rgb, img.alpha, img.source_format, img.icc_profile, list(img.notes))
        rep(0.8, "measuring quality")
        y2 = out.luma()
        res = EmbedResult(
            output=None,
            watermark_id=wid.hex(),
            payload_bytes=len(raw),
            capacity_class=framing.LENGTH_CLASSES[plan.frame.class_index],
            signed=signer is not None,
            signer_key_id=signer,
            pattern_key_id=pk.key_id,
            chip_px=plan.chip_px,
            tile_period_px=plan.period,
            strength=spec.strength,
            psnr_db=round(metrics.psnr(y, y2), 2),
            ssim=round(metrics.ssim(y, y2), 5),
            bytes_written=None,
            seconds=0.0,
            notes=list(img.notes),
        )
        if existing:
            res.extra["existing_watermarks"] = existing
            res.notes.append(
                f"the input already carried {len(existing)} watermark(s); the new one uses a "
                f"different tile period ({plan.period} px) so they remain separately detectable"
            )
        if img.height * img.width < 150_000:
            res.notes.append(
                "image is below ~0.15 MP: measured payload recovery on such images is poor even "
                "without modification (see docs/benchmarking.md)"
            )
        if min(img.height, img.width) < 2 * plan.period:
            res.notes.append(
                "image is smaller than two watermark tiles; robustness to cropping and scaling is reduced"
            )
        res.seconds = round(time.perf_counter() - t0, 3)
        rep(1.0, "done")
        return out, res

    def embed_image(
        self,
        src: Path,
        dst: Path,
        spec: WatermarkSpec,
        overwrite: bool = False,
        reporter: Reporter | None = None,
        self_check: bool = True,
    ) -> EmbedResult:
        """Watermark an image file.

        With ``self_check`` the written file is read back and blindly detected, so the
        result states whether the payload is actually recoverable (tiny or very flat
        images often cannot carry a signed payload; see the benchmark).
        """
        rep = reporter or Reporter()
        t0 = time.perf_counter()
        dst = check_output_path(Path(src), Path(dst), overwrite)
        fmt = image_io.format_for(dst)
        img = image_io.load(Path(src), self.limits)
        out, res = self.embed_image_data(img, spec, rep.sub(0.0, 0.75))
        if fmt == "JPEG" and img.alpha is not None:
            res.notes.append("JPEG has no alpha channel; transparency was dropped")
        if fmt in ("JPEG", "WEBP") and spec.quality < 100:
            res.notes.append(f"lossy output (quality {spec.quality}) slightly weakens the watermark")
        rep(0.92, "writing output")
        res.bytes_written = image_io.save(out, dst, spec.quality)
        res.output = str(dst)
        if self_check:
            rep(0.94, "self-check: detecting the written file")
            check = self.detect_image(dst, pattern_key=spec.pattern_key)
            ok = check.status == report_mod.STATUS_PAYLOAD and check.watermark_id == res.watermark_id
            res.extra["self_check"] = {
                "status": check.status,
                "payload_recoverable": ok,
                "sync_z": check.confidence.get("sync_z"),
            }
            if not ok:
                res.notes.append(
                    f"SELF-CHECK FAILED ({check.status}): the payload cannot be recovered even from "
                    "this unmodified output. The image is too small or too flat for this payload; "
                    "use a shorter text, a larger image or a higher --strength."
                )
        res.seconds = round(time.perf_counter() - t0, 3)
        rep(1.0, "done")
        return res

    def existing_watermarks(self, img: image_io.ImageData) -> list[dict[str, Any]]:
        """Watermarks already present (readable with the local pattern keys).

        Uses the fast detector; a watermark made with someone else's pattern key cannot
        be seen and is therefore not reported here.
        """
        pks = self.detection_pattern_keys()
        if not pks:
            return []
        keyring = [KeyedPatterns(k.key_bytes) for k in pks]
        det = engine.detect_luma(img.luma(), keyring, deep=False)
        if det.best is None or det.best.hit is None:
            return []
        z = det.best.hit.z
        rep = report_mod.interpret(
            "<input>", "image", z, det.searched_positions, det.outcome, self.trust, self.own_public_keys()
        )
        if not rep.detected:
            return []
        found = [_existing_entry(rep, det.best.lattice.period, z)]
        for cand, out in det.additional:
            zc = cand.hit.z if cand.hit else 0.0
            sub = report_mod.interpret(
                "<input>", "image", zc, det.searched_positions, out, self.trust, self.own_public_keys()
            )
            found.append(_existing_entry(sub, cand.lattice.period, zc))
        return found

    def detect_image_data(
        self,
        img: image_io.ImageData,
        source: str = "<memory>",
        pattern_key: str | None = None,
        reporter: Reporter | None = None,
        backend: str = "tss",
        deep: bool = True,
    ) -> report_mod.DetectionReport:
        """Blind detection. ``deep=False`` skips the slower coherent scale scan that
        runs when the fast search finds nothing."""
        rep = reporter or Reporter()
        t0 = time.perf_counter()
        keyring, kids = self.keyring(pattern_key)
        rep(0.1, "searching for watermark geometry")
        if backend != "tss":
            return self._detect_plugin_backend(img, source, backend, pattern_key, t0)
        det = engine.detect_luma(img.luma(), keyring, deep=deep, progress=lambda f, m: rep(0.1 + 0.8 * f, m))
        rep(0.9, "verifying payload")
        z = det.best.hit.z if det.best and det.best.hit else 0.0
        r = report_mod.interpret(
            source,
            "image",
            z,
            det.searched_positions,
            det.outcome,
            self.trust,
            self.own_public_keys(),
            kids,
        )
        r.diagnostics["backend"] = "tss"
        for cand, out in det.additional:
            z_extra = cand.hit.z if cand.hit else 0.0
            sub = report_mod.interpret(
                source,
                "image",
                z_extra,
                det.searched_positions,
                out,
                self.trust,
                self.own_public_keys(),
                kids,
            )
            r.additional.append(
                {
                    "status": sub.status,
                    "watermark_id": sub.watermark_id,
                    "payload": sub.payload,
                    "verification": sub.verification,
                    "sync_z": round(z_extra, 2),
                    "tile_period_px": round(cand.lattice.period, 1),
                }
            )
        if r.additional:
            r.notes.append(
                f"this image carries {1 + len(r.additional)} watermarks (it was watermarked more than once); "
                "each is verified separately"
            )
        if det.best is not None:
            r.geometry = det.best.lattice.describe()
            if det.best.hit is not None:
                r.diagnostics["pattern_key_id"] = kids[det.best.hit.key_index]
                # Only meaningful for a detected watermark, not a below-threshold candidate.
                r.diagnostics["publicly_verifiable"] = r.detected and kids[det.best.hit.key_index] in {
                    k.key_id for k in self.public_pattern_keys()
                }
        r.diagnostics["image_size"] = [img.width, img.height]
        r.diagnostics["seconds"] = round(time.perf_counter() - t0, 3)
        r.notes = list(img.notes) + r.notes
        rep(1.0, "done")
        return r

    def _detect_plugin_backend(
        self, img: image_io.ImageData, source: str, backend: str, pattern_key: str | None, t0: float
    ) -> report_mod.DetectionReport:
        pks = [self.keystore.pattern_key(pattern_key)] if pattern_key else self.detection_pattern_keys()
        res = backends.get(backend).detect_luma(img.luma(), [k.key_bytes for k in pks])
        core = framing.CoreResult(res.watermark_id is not None, res.watermark_id, None, 1.0)
        full = framing.FullResult(res.payload is not None, res.payload, 1.0) if res.payload else None
        outcome = engine.DecodeOutcome(core, full, None)
        r = report_mod.interpret(
            source,
            "image",
            res.sync_z,
            res.searched,
            outcome,
            self.trust,
            self.own_public_keys(),
            [k.key_id for k in pks],
        )
        r.diagnostics.update(
            {"backend": backend, "seconds": round(time.perf_counter() - t0, 3), **res.details}
        )
        return r

    def detect_image(
        self,
        path: Path,
        pattern_key: str | None = None,
        reporter: Reporter | None = None,
        backend: str = "tss",
    ) -> report_mod.DetectionReport:
        img = image_io.load(Path(path), self.limits)
        return self.detect_image_data(img, str(path), pattern_key, reporter, backend)

    # ----------------------------------------------------------------- video
    def embed_video(self, src: Path, dst: Path, spec: WatermarkSpec, **kw: Any) -> EmbedResult:
        from veilmark.video import embed as vembed

        return vembed.embed_video(self, Path(src), Path(dst), spec, **kw)

    def detect_video(self, path: Path, **kw: Any) -> report_mod.DetectionReport:
        from veilmark.video import detect as vdetect

        return vdetect.detect_video(self, Path(path), **kw)

    # -------------------------------------------------------------- generic
    def detect(self, path: Path, **kw: Any) -> report_mod.DetectionReport:
        if media_type(Path(path)) == "video":
            return self.detect_video(path, **kw)
        kw.pop("max_frames", None)
        kw.pop("stride", None)
        return self.detect_image(path, **kw)


VIDEO_EXT = {".mp4", ".mov", ".m4v", ".mkv", ".webm", ".avi", ".mpg", ".mpeg", ".ts", ".gif"}


def media_type(path: Path) -> str:
    return "video" if Path(path).suffix.lower() in VIDEO_EXT else "image"
