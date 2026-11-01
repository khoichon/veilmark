"""Shared CLI helpers: exit codes, output, passphrases, progress."""

from __future__ import annotations

import getpass
import json
import os
import sys
from typing import Any

from veilmark.core.tasks import Reporter

# Exit codes (documented in README / `veilmark --help`).
EXIT_OK = 0
EXIT_INTERNAL = 1
EXIT_USAGE = 2  # invalid arguments or input files
EXIT_NOT_DETECTED = 3  # no watermark found
EXIT_PARTIAL = 4  # watermark signal/id found but payload not recovered
EXIT_BAD_SIGNATURE = 5  # payload recovered but signature invalid
EXIT_UNTRUSTED = 6  # (verify) signature valid/unknown but issuer not trusted, or unsigned
EXIT_CANCELLED = 130

EXIT_CODES_HELP = """exit codes:
  0  success (verify: authentic payload from a trusted issuer)
  1  internal error
  2  invalid usage or input
  3  no watermark detected
  4  watermark signal or id detected, payload not recovered
     (watermark image: written, but the self-check could not recover the payload)
  5  payload recovered but its signature is INVALID (altered or forged)
  6  verify only: unsigned, unknown-key, revoked or otherwise untrusted issuer
130 cancelled"""


def emit(obj: Any, as_json: bool, text: str | None = None) -> None:
    if as_json:
        print(json.dumps(obj, indent=2, default=str))
    elif text is not None:
        print(text)


def err(msg: str) -> None:
    print(f"veilmark: {msg}", file=sys.stderr)


def passphrase(args: Any, confirm: bool = False, purpose: str = "signing key") -> str | None:
    """Passphrase from --passphrase-env (default VEILMARK_PASSPHRASE) or a TTY prompt."""
    env = getattr(args, "passphrase_env", None) or "VEILMARK_PASSPHRASE"
    if env in os.environ:
        return os.environ[env]
    if not sys.stdin.isatty():
        return None
    p = getpass.getpass(f"Passphrase for {purpose}: ")
    if confirm and getpass.getpass("Repeat passphrase: ") != p:
        raise SystemExit("passphrases do not match")
    return p


def progress_reporter(enabled: bool) -> Reporter:
    if not enabled or not sys.stderr.isatty():
        return Reporter()
    last = {"pct": -1}

    def show(f: float, msg: str) -> None:
        pct = int(f * 100)
        if pct != last["pct"]:
            last["pct"] = pct
            sys.stderr.write(f"\r{pct:3d}% {msg[:60]:<60}")
            sys.stderr.flush()
            if pct >= 100:
                sys.stderr.write("\n")

    return Reporter(show)
