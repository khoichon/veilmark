"""`doctor`, `cleanup`, `benchmark`, `plugins`, `serve` and `gui` commands."""

from __future__ import annotations

import argparse
import platform
import sys
import tempfile
from pathlib import Path

from veilmark import __version__
from veilmark.api import Veilmark
from veilmark.cli import common


def register(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("doctor", help="check the environment and installation")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("cleanup", help="remove stale temporary files left by interrupted runs")
    p.add_argument("dirs", nargs="*", type=Path, help="directories to scan (default: temp dir and cwd)")
    p.add_argument("--older-than", type=float, default=1.0, help="hours (default 1)")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=cmd_cleanup)

    b = sub.add_parser("benchmark", help="run the robustness benchmark laboratory")
    b.add_argument("--profile", choices=["quick", "standard", "full"], default="standard")
    b.add_argument("--split", choices=["dev", "heldout", "all"], default="heldout")
    b.add_argument("--media", choices=["image", "video", "both"], default="image")
    b.add_argument("--out", type=Path, required=True, help="output directory for reports")
    b.add_argument("--seeds", type=int)
    b.add_argument("--images", nargs="*", help="restrict to named dataset images")
    b.add_argument("--attacks", nargs="*", help="restrict image attacks")
    b.add_argument("--video-attacks", nargs="*")
    b.add_argument("--add-image", nargs="*", type=Path, default=[], help="extra user images")
    b.add_argument("--add-video", nargs="*", type=Path, default=[], help="extra user videos")
    b.add_argument("--strength", type=float, default=1.0)
    b.add_argument("--workers", type=int)
    b.add_argument("--list", action="store_true", help="list datasets and attacks, then exit")
    b.set_defaults(func=cmd_benchmark)

    pl = sub.add_parser("plugins", help="list, install, enable, disable or remove plugins")
    pls = pl.add_subparsers(dest="plugins_cmd", required=True)
    p = pls.add_parser("list")
    p.set_defaults(func=cmd_plugins_list)
    p = pls.add_parser("info")
    p.add_argument("name")
    p.set_defaults(func=cmd_plugins_info)
    p = pls.add_parser("install", help="copy a plugin directory into the plugins folder (disabled)")
    p.add_argument("path", type=Path)
    p.add_argument("--yes", action="store_true")
    p.set_defaults(func=cmd_plugins_install)
    p = pls.add_parser("enable", help="approve and enable a plugin (it can run arbitrary code)")
    p.add_argument("name")
    p.add_argument("--yes", action="store_true")
    p.set_defaults(func=cmd_plugins_enable)
    p = pls.add_parser("disable")
    p.add_argument("name")
    p.set_defaults(func=cmd_plugins_disable)
    p = pls.add_parser("remove")
    p.add_argument("name")
    p.add_argument("--yes", action="store_true")
    p.set_defaults(func=cmd_plugins_remove)

    p = sub.add_parser("serve", help="start the local web helper (127.0.0.1 only)")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--no-browser", action="store_true")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("gui", help="launch the desktop application (requires PySide6)")
    p.set_defaults(func=cmd_gui)


def cmd_doctor(vm: Veilmark, args: argparse.Namespace) -> int:
    from veilmark.video import ffmpeg

    checks: dict[str, object] = {
        "veilmark": __version__,
        "python": platform.python_version(),
        "platform": f"{platform.system()} {platform.release()} {platform.machine()}",
        "data_home": str(vm.home),
    }
    problems = []
    for mod in ("numpy", "cv2", "PIL", "nacl"):
        try:
            m = __import__(mod)
            checks[mod] = getattr(m, "__version__", "ok")
        except ImportError as e:
            checks[mod] = f"MISSING ({e})"
            problems.append(f"python package {mod} missing: pip install -e .")
    try:
        import PySide6

        checks["PySide6"] = PySide6.__version__
    except ImportError:
        checks["PySide6"] = "not installed (GUI unavailable: pip install -e '.[gui]')"
    if ffmpeg.available():
        checks["ffmpeg"] = ffmpeg.version()
    else:
        checks["ffmpeg"] = "MISSING"
        problems.append(ffmpeg.INSTALL_HINT)
    ids = vm.keystore.identities()
    pks = vm.keystore.pattern_keys()
    checks["signing_identities"] = len(ids)
    checks["pattern_keys"] = len(pks)
    checks["trusted_issuers"] = len(vm.trust.issuers())
    if not pks:
        problems.append("no pattern key yet: run `veilmark keys init`")
    plain = [i.key_id for i in ids if i.private.get("scheme") == "plaintext"]
    if plain:
        problems.append(f"unencrypted private keys: {plain}")
    checks["problems"] = problems
    if args.json:
        common.emit(checks, True)
    else:
        for k, v in checks.items():
            if k != "problems":
                print(f"{k:>20}: {v}")
        for p in problems:
            print(f"  ! {p}")
        if not problems:
            print("  all good")
    return 0 if not problems else common.EXIT_USAGE


def cmd_cleanup(vm: Veilmark, args: argparse.Namespace) -> int:
    from veilmark.security import tempfiles

    stale = tempfiles.find_stale(args.dirs or [Path(tempfile.gettempdir()), Path.cwd()], args.older_than)
    if not args.dry_run:
        tempfiles.remove(stale)
    common.emit(
        {"removed": [str(p) for p in stale], "dry_run": args.dry_run},
        args.json,
        ("would remove" if args.dry_run else "removed") + f" {len(stale)} stale item(s)",
    )
    return 0


def cmd_benchmark(vm: Veilmark, args: argparse.Namespace) -> int:
    from veilmark.benchmarks import attacks, datasets, runner

    if args.list:
        print("Images:")
        for s in datasets.IMAGES:
            print(f"  {s.split:<8} {s.kind:<12} {s.name}{'' if datasets.available(s) else '  (unavailable)'}")
        print("Videos:")
        for v in datasets.VIDEOS:
            print(f"  {v.split:<8} {v.kind:<22} {v.name}")
        print("Image attacks:", ", ".join(a.name for a in attacks.IMAGE_ATTACKS))
        print("Video attacks:", ", ".join(a.name for a in attacks.VIDEO_ATTACKS))
        return 0
    cfg = runner.BenchConfig(
        out_dir=args.out,
        split=args.split,
        profile=args.profile,
        media=args.media,
        seeds=args.seeds,
        image_names=args.images,
        attack_names=args.attacks,
        video_attack_names=args.video_attacks,
        strength=args.strength,
        extra_images=args.add_image,
        extra_videos=args.add_video,
    )
    if args.workers:
        cfg.workers = args.workers
    rep = common.progress_reporter(not args.json)
    summary = runner.run(cfg, rep.progress)
    if args.json:
        common.emit(summary, True)
    else:
        print((args.out / "report.md").read_text())
        print(
            f"reports written to {args.out}/ (report.html, report.md, summary.json, summary.csv, records.jsonl)"
        )
    return 0


def _confirm(prompt: str, yes: bool) -> bool:
    if yes:
        return True
    if not sys.stdin.isatty():
        common.err("confirmation required (re-run with --yes)")
        return False
    return input(prompt + " [type 'yes']: ").strip() == "yes"


def _describe(m: object) -> str:
    from veilmark.plugins.manager import Manifest

    assert isinstance(m, Manifest)
    perms = ", ".join(f"{k}={v}" for k, v in sorted(m.permissions.items())) or "none declared"
    return (
        f"{m.name} {m.version} (API v{m.api_version}) - {m.description}\n"
        f"  kinds: {', '.join(m.kinds)}\n  declared permissions: {perms}\n"
        f"  NOTE: in-process plugins run with your full user privileges; declarations are not a sandbox."
    )


def cmd_plugins_list(vm: Veilmark, args: argparse.Namespace) -> int:
    infos = vm.plugins.discover()
    if args.json:
        common.emit([i.as_dict() for i in infos], True)
        return 0
    if not infos:
        print(f"no plugins installed (folder: {vm.plugins.dir})")
    for i in infos:
        ver = i.manifest.version if i.manifest else "?"
        state = "enabled" if i.enabled else "disabled"
        print(f"{i.name:<24} {ver:<10} {state:<9} {i.status}" + "".join(f"\n    - {p}" for p in i.problems))
    return 0


def cmd_plugins_info(vm: Veilmark, args: argparse.Namespace) -> int:
    i = vm.plugins.get(args.name)
    common.emit(i.as_dict(), args.json, _describe(i.manifest) if i.manifest else "; ".join(i.problems))
    return 0


def cmd_plugins_install(vm: Veilmark, args: argparse.Namespace) -> int:
    info = vm.plugins.install(
        args.path, lambda m: (print(_describe(m)), _confirm("Install this plugin?", args.yes))[1]
    )
    common.emit(
        info.as_dict(),
        args.json,
        f"installed {info.name} (disabled; run `veilmark plugins enable {info.name}`)",
    )
    return 0


def cmd_plugins_enable(vm: Veilmark, args: argparse.Namespace) -> int:
    info = vm.plugins.enable(
        args.name, lambda m: (print(_describe(m)), _confirm("Enable and trust this plugin?", args.yes))[1]
    )
    common.emit(info.as_dict(), args.json, f"enabled {info.name}")
    return 0


def cmd_plugins_disable(vm: Veilmark, args: argparse.Namespace) -> int:
    vm.plugins.disable(args.name)
    common.emit({"disabled": args.name}, args.json, f"disabled {args.name}")
    return 0


def cmd_plugins_remove(vm: Veilmark, args: argparse.Namespace) -> int:
    if not _confirm(f"Delete plugin {args.name} from disk?", args.yes):
        return common.EXIT_USAGE
    vm.plugins.remove(args.name)
    common.emit({"removed": args.name}, args.json, f"removed {args.name}")
    return 0


def cmd_serve(vm: Veilmark, args: argparse.Namespace) -> int:
    from veilmark.web.server import serve

    serve(vm, args.port, open_browser=not args.no_browser)
    return 0


def cmd_gui(vm: Veilmark, args: argparse.Namespace) -> int:
    try:
        from veilmark.app.main import main as gui_main
    except ImportError as e:
        common.err(f"GUI unavailable ({e}); install with: pip install -e '.[gui]'")
        return common.EXIT_USAGE
    return gui_main(home=vm.home)
