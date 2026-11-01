"""`veilmark watermark ...`, `detect` and `verify` commands."""

from __future__ import annotations

import argparse
import dataclasses
import json
from pathlib import Path
from typing import Any

from veilmark.api import Veilmark, WatermarkSpec, media_type, parse_strength
from veilmark.cli import common
from veilmark.detection import report as report_mod
from veilmark.video import ffmpeg


def register(sub: argparse._SubParsersAction) -> None:
    w = sub.add_parser("watermark", help="embed a watermark into images or a video")
    ws = w.add_subparsers(dest="wm_cmd", required=True)

    def payload_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--text", help="short human-readable text (UTF-8)")
        p.add_argument("--meta-hex", help="application metadata as hex bytes")
        p.add_argument("--meta-provider", help="plugin metadata provider computing metadata per file")
        p.add_argument("--no-sign", action="store_true", help="embed an unsigned payload")
        p.add_argument("--no-timestamp", action="store_true")
        p.add_argument("--identity", help="signing identity (key id prefix or label)")
        p.add_argument("--pattern-key", help="pattern key (id prefix or label)")
        p.add_argument(
            "--strength",
            default="balanced",
            help="subtle (0.6) | balanced (1.0, default) | robust (1.5) | a number 0.1..4.0; "
            "higher survives more but is more visible",
        )
        p.add_argument("--chip-size", type=int, help="override chip size in px (advanced)")
        p.add_argument("--overwrite", action="store_true", help="allow replacing existing outputs")
        p.add_argument(
            "--allow-rewatermark",
            action="store_true",
            help="add a watermark even if the input already carries one (it gets a different tile "
            "period so both stay detectable); by default such inputs are refused",
        )
        p.add_argument(
            "--public",
            action="store_true",
            help="publicly verifiable: anyone with your public key can find and verify the "
            "watermark (and also try to remove it); no pattern key needs to be shared",
        )
        p.add_argument("--passphrase-env", help="env var holding the key passphrase")

    p = ws.add_parser("image", help="watermark one or more images")
    p.add_argument("inputs", nargs="+", type=Path)
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-o", "--output", type=Path, help="output file (single input)")
    g.add_argument("--out-dir", type=Path, help="output directory (batch)")
    p.add_argument(
        "--format", choices=["png", "jpg", "webp", "same"], default="same", help="batch output format"
    )
    p.add_argument("--quality", type=int, default=95, help="JPEG/WebP quality")
    p.add_argument("--no-self-check", action="store_true", help="skip re-detecting each written file")
    payload_args(p)
    p.set_defaults(func=cmd_watermark_image)

    p = ws.add_parser("video", help="watermark a video (requires ffmpeg)")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--output", type=Path, required=True)
    p.add_argument(
        "--mode",
        choices=["robust", "light"],
        default="robust",
        help="robust: fast variant changes, full strength; light: lower distortion",
    )
    p.add_argument("--codec", default="auto", help="auto|libx264|libx265|libvpx-vp9|libsvtav1")
    p.add_argument("--crf", type=int)
    p.add_argument("--preset", default="medium")
    p.add_argument("--bitrate", help="target video bitrate, e.g. 6M (overrides CRF)")
    p.add_argument("--audio", default="auto", choices=["auto", "copy", "aac", "opus", "none"])
    payload_args(p)
    p.set_defaults(func=cmd_watermark_video)

    p = sub.add_parser("detect", help="blindly detect and decode watermarks")
    _detect_args(p)
    p.set_defaults(func=cmd_detect)

    p = sub.add_parser(
        "verify",
        help="detect and require an authentic signed payload",
        description="Exit code 0 only if every input carries a payload with a valid "
        "signature from a trusted issuer.",
    )
    _detect_args(p)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("capacity", help="show how many payload bytes some text would need")
    p.add_argument("--text")
    p.add_argument("--meta-hex")
    p.add_argument("--no-sign", action="store_true")
    p.add_argument("--no-timestamp", action="store_true")
    p.set_defaults(func=cmd_capacity)


def _detect_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("inputs", nargs="+", type=Path)
    p.add_argument("--pattern-key", help="restrict to one pattern key (default: try all)")
    p.add_argument("--report", type=Path, help="write JSON report(s) to this file")
    p.add_argument(
        "--export",
        metavar="FORMAT",
        help="also write each report with a plugin exporter (e.g. markdown) next to the input",
    )
    p.add_argument("--max-frames", type=int, default=900, help="video: max frames analysed")
    p.add_argument("--stride", type=int, help="video: analyse every Nth frame")


def _spec(args: argparse.Namespace) -> WatermarkSpec:
    meta = bytes.fromhex(args.meta_hex) if args.meta_hex else None
    sign = not args.no_sign
    return WatermarkSpec(
        text=args.text,
        metadata=meta,
        include_timestamp=not args.no_timestamp,
        sign=sign,
        identity=args.identity,
        passphrase=common.passphrase(args) if sign else None,
        pattern_key=args.pattern_key,
        strength=parse_strength(args.strength),
        chip_px=args.chip_size,
        quality=getattr(args, "quality", 95),
        allow_rewatermark=args.allow_rewatermark,
        public=args.public,
    )


def _with_provider(vm: Veilmark, args: argparse.Namespace, spec: WatermarkSpec, src: Path) -> WatermarkSpec:
    if not getattr(args, "meta_provider", None):
        return spec
    vm.load_plugins()
    providers = vm.plugins.api.metadata_providers
    if args.meta_provider not in providers:
        raise ValueError(
            f"no metadata provider {args.meta_provider!r}; enabled: {sorted(providers) or 'none'}"
        )
    meta = providers[args.meta_provider][1](str(src))
    if not isinstance(meta, bytes) or len(meta) > 120:
        raise ValueError("metadata provider must return at most 120 bytes")
    return dataclasses.replace(spec, metadata=meta)


def _outputs(args: argparse.Namespace) -> list[tuple[Path, Path]]:
    if args.output:
        if len(args.inputs) != 1:
            raise SystemExit("use --out-dir for multiple inputs")
        return [(args.inputs[0], args.output)]
    args.out_dir.mkdir(parents=True, exist_ok=True)
    pairs = []
    for src in args.inputs:
        ext = src.suffix if args.format == "same" else "." + args.format
        if ext.lower() not in (".png", ".jpg", ".jpeg", ".webp", ".tif", ".tiff", ".bmp"):
            ext = ".png"
        pairs.append((src, args.out_dir / f"{src.stem}.wm{ext}"))
    return pairs


def cmd_watermark_image(vm: Veilmark, args: argparse.Namespace) -> int:
    spec = _spec(args)
    results: list[dict[str, Any]] = []
    failures = 0
    for src, dst in _outputs(args):
        try:
            r = vm.embed_image(
                src,
                dst,
                _with_provider(vm, args, spec, src),
                overwrite=args.overwrite,
                reporter=common.progress_reporter(not args.json),
                self_check=not args.no_self_check,
            )
            results.append(r.to_dict())
            if not args.json:
                print(
                    f"{src} -> {dst}  id={r.watermark_id}  {r.payload_bytes}B payload  "
                    f"PSNR {r.psnr_db} dB  SSIM {r.ssim}" + "".join(f"\n  note: {n}" for n in r.notes)
                )
        except (ValueError, OSError) as e:
            failures += 1
            results.append({"input": str(src), "error": str(e)})
            common.err(f"{src}: {e}")
    if args.json:
        common.emit(results if len(results) > 1 else results[0], True)
    if failures:
        return common.EXIT_USAGE
    unrecoverable = [
        r for r in results if not r.get("extra", {}).get("self_check", {}).get("payload_recoverable", True)
    ]
    return common.EXIT_PARTIAL if unrecoverable else common.EXIT_OK


def cmd_watermark_video(vm: Veilmark, args: argparse.Namespace) -> int:
    settings = ffmpeg.EncodeSettings(args.codec, args.crf, args.preset, args.bitrate, args.audio)
    r = vm.embed_video(
        args.input,
        args.output,
        _with_provider(vm, args, _spec(args), args.input),
        overwrite=args.overwrite,
        mode=args.mode,
        encode=settings,
        reporter=common.progress_reporter(not args.json),
    )
    common.emit(
        r.to_dict(),
        args.json,
        f"{args.input} -> {r.output}  id={r.watermark_id}  {r.extra.get('frames')} frames  "
        f"PSNR~{r.psnr_db} dB  {r.seconds}s" + "".join(f"\n  note: {n}" for n in r.notes),
    )
    return 0


def _run_detect(vm: Veilmark, args: argparse.Namespace) -> list[report_mod.DetectionReport]:
    reps = []
    for path in args.inputs:
        kw: dict[str, Any] = {
            "pattern_key": args.pattern_key,
            "reporter": common.progress_reporter(not args.json),
        }
        if media_type(path) == "video":
            kw.update(max_frames=args.max_frames, stride=args.stride)
        reps.append(vm.detect(path, **kw))
    if args.report:
        data = [r.to_dict() for r in reps]
        args.report.write_text(json.dumps(data if len(data) > 1 else data[0], indent=2, default=str))
    if args.export:
        vm.load_plugins()
        exporters = vm.plugins.api.exporters
        if args.export not in exporters:
            raise ValueError(f"no exporter {args.export!r}; enabled exporters: {sorted(exporters) or 'none'}")
        for path, r in zip(args.inputs, reps, strict=True):
            data_b, ext = exporters[args.export][1](r.to_dict())
            out = path.with_name(f"{path.stem}.report.{ext}")
            out.write_bytes(data_b)
            if not args.json:
                print(f"report written to {out}")
    return reps


def _exit_for(r: report_mod.DetectionReport, require_trust: bool) -> int:
    if r.status == report_mod.STATUS_NONE:
        return common.EXIT_NOT_DETECTED
    if r.status in (report_mod.STATUS_ID, report_mod.STATUS_SIGNAL):
        return common.EXIT_PARTIAL
    sig = (r.verification or {}).get("signature")
    if sig == "invalid":
        return common.EXIT_BAD_SIGNATURE
    if require_trust and not r.authentic:
        return common.EXIT_UNTRUSTED
    return common.EXIT_OK


def _print(reps: list[report_mod.DetectionReport], as_json: bool) -> None:
    if as_json:
        data = [r.to_dict() for r in reps]
        common.emit(data if len(data) > 1 else data[0], True)
    else:
        for r in reps:
            print(r.summary())


def cmd_detect(vm: Veilmark, args: argparse.Namespace) -> int:
    reps = _run_detect(vm, args)
    _print(reps, args.json)
    return max(_exit_for(r, False) for r in reps)


def cmd_verify(vm: Veilmark, args: argparse.Namespace) -> int:
    reps = _run_detect(vm, args)
    _print(reps, args.json)
    return max(_exit_for(r, True) for r in reps)


def cmd_capacity(vm: Veilmark, args: argparse.Namespace) -> int:
    spec = WatermarkSpec(
        text=args.text,
        metadata=bytes.fromhex(args.meta_hex) if args.meta_hex else None,
        include_timestamp=not args.no_timestamp,
        sign=not args.no_sign,
    )
    c = vm.capacity_report(spec)
    common.emit(
        c,
        args.json,
        f"payload {c['payload_bytes']} bytes; fits: {c['fits']} (max {c['max_payload_bytes']}; "
        f"smaller payloads are more robust)" + (f"\n  {c['reason']}" if c.get("reason") else ""),
    )
    return 0 if c["fits"] else common.EXIT_USAGE
