"""Veilmark command-line interface."""

from __future__ import annotations

import argparse
import sys
import traceback
from pathlib import Path

from veilmark import __version__
from veilmark.cli import common, keys_cmd, media_cmd, misc_cmd
from veilmark.core.tasks import Cancelled
from veilmark.crypto.keys import KeyStoreError
from veilmark.security.limits import InputError
from veilmark.video.ffmpeg import FFmpegError, FFmpegMissing


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="veilmark",
        description="Local-first invisible watermarking for images and video with signed payloads.",
        epilog=common.EXIT_CODES_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"veilmark {__version__}")
    p.add_argument("--home", type=Path, help="data directory (default: per-user; env VEILMARK_HOME)")
    p.add_argument("--json", action="store_true", help="machine-readable JSON output")
    p.add_argument("--debug", action="store_true", help="show tracebacks")
    sub = p.add_subparsers(dest="cmd", required=True)
    keys_cmd.register(sub)
    media_cmd.register(sub)
    misc_cmd.register(sub)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    from veilmark.api import Veilmark

    try:
        vm = Veilmark(args.home)
        return int(args.func(vm, args) or 0)
    except Cancelled:
        common.err("cancelled")
        return common.EXIT_CANCELLED
    except KeyboardInterrupt:
        common.err("interrupted")
        return common.EXIT_CANCELLED
    except (InputError, KeyStoreError, FFmpegMissing, ValueError, FileNotFoundError) as e:
        if args.debug:
            traceback.print_exc()
        common.err(str(e))
        return common.EXIT_USAGE
    except FFmpegError as e:
        if args.debug:
            traceback.print_exc()
        common.err(f"ffmpeg failed: {e}")
        return common.EXIT_INTERNAL
    except Exception as e:
        if args.debug:
            traceback.print_exc()
        common.err(f"internal error: {type(e).__name__}: {e} (re-run with --debug)")
        return common.EXIT_INTERNAL


if __name__ == "__main__":
    sys.exit(main())
