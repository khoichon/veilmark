"""`veilmark keys ...` and `veilmark trust ...` commands."""

from __future__ import annotations

import argparse
import base64
import contextlib
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from veilmark.api import Veilmark
from veilmark.cli import common
from veilmark.crypto import keys as keys_mod


def _ts(t: int | None) -> str | None:
    return datetime.fromtimestamp(t, UTC).isoformat(timespec="seconds") if t else None


def register(sub: argparse._SubParsersAction) -> None:
    k = sub.add_parser("keys", help="manage signing identities and pattern keys")
    ks = k.add_subparsers(dest="keys_cmd", required=True)

    p = ks.add_parser("init", help="create a pattern key and a signing identity (first run)")
    p.add_argument("--label", default="default")
    p.add_argument("--no-passphrase", action="store_true", help="store the private key UNENCRYPTED")
    p.set_defaults(func=cmd_init)

    p = ks.add_parser("generate", help="generate a new Ed25519 signing identity")
    p.add_argument("--label", required=True)
    p.add_argument("--no-passphrase", action="store_true", help="store the private key UNENCRYPTED")
    p.add_argument("--no-trust", action="store_true", help="do not add the new public key to the trust list")
    p.set_defaults(func=cmd_generate)

    p = ks.add_parser("list", help="list identities and pattern keys")
    p.set_defaults(func=cmd_list)

    p = ks.add_parser("export-public", help="export a public key (base64) for verifiers")
    p.add_argument("identity", nargs="?")
    p.add_argument("-o", "--output", type=Path)
    p.set_defaults(func=cmd_export_public)

    p = ks.add_parser("export-private", help="export a private signing key (DANGEROUS)")
    p.add_argument("identity")
    p.add_argument("-o", "--output", type=Path, required=True)
    p.add_argument("--yes", action="store_true", help="confirm you understand the risk")
    p.set_defaults(func=cmd_export_private)

    p = ks.add_parser("import-private", help="import a private signing key seed file")
    p.add_argument("file", type=Path)
    p.add_argument("--label", required=True)
    p.add_argument("--no-passphrase", action="store_true")
    p.set_defaults(func=cmd_import_private)

    p = ks.add_parser("rotate", help="create a successor identity and retire the old one")
    p.add_argument("identity", nargs="?")
    p.add_argument("--label")
    p.add_argument("--no-passphrase", action="store_true")
    p.set_defaults(func=cmd_rotate)

    p = ks.add_parser("set-status", help="mark an identity active, retired or revoked")
    p.add_argument("identity")
    p.add_argument("status", choices=["active", "retired", "revoked"])
    p.set_defaults(func=cmd_set_status)

    p = ks.add_parser(
        "export-keyfile", help="write a passphrase-encrypted keyfile (also used by the web app)"
    )
    p.add_argument("-o", "--output", type=Path, required=True)
    p.add_argument("--identity")
    p.set_defaults(func=cmd_export_keyfile)
    p = ks.add_parser("import-keyfile", help="import a keyfile created here or in the web app")
    p.add_argument("file", type=Path)
    p.add_argument("--no-passphrase", action="store_true", help="store the imported private key UNENCRYPTED")
    p.set_defaults(func=cmd_import_keyfile)

    pk = ks.add_parser("pattern", help="manage secret pattern keys (needed to detect)")
    pks = pk.add_subparsers(dest="pattern_cmd", required=True)
    p = pks.add_parser("generate")
    p.add_argument("--label", default="default")
    p.set_defaults(func=cmd_pattern_generate)
    p = pks.add_parser("export", help="export a pattern key (share only with authorised detectors)")
    p.add_argument("key", nargs="?")
    p.add_argument("-o", "--output", type=Path, required=True)
    p.add_argument("--yes", action="store_true")
    p.set_defaults(func=cmd_pattern_export)
    p = pks.add_parser("import")
    p.add_argument("file", type=Path)
    p.add_argument("--label", required=True)
    p.set_defaults(func=cmd_pattern_import)

    t = sub.add_parser("trust", help="manage trusted issuers (public keys)")
    ts = t.add_subparsers(dest="trust_cmd", required=True)
    p = ts.add_parser("add", help="trust a public key (base64 string or file)")
    p.add_argument("key", help="base64 public key, or path to an exported .pub file")
    p.add_argument("--label", required=True)
    p.add_argument("--not-before", type=int, help="unix time")
    p.add_argument("--not-after", type=int, help="unix time")
    p.set_defaults(func=cmd_trust_add)
    p = ts.add_parser("list")
    p.set_defaults(func=cmd_trust_list)
    p = ts.add_parser("revoke")
    p.add_argument("issuer")
    p.add_argument("--at", type=int, help="revocation unix time (default now)")
    p.set_defaults(func=cmd_trust_revoke)
    p = ts.add_parser("remove")
    p.add_argument("issuer")
    p.set_defaults(func=cmd_trust_remove)


def _pass_for_new(args: argparse.Namespace) -> str | None:
    if args.no_passphrase:
        common.err("WARNING: the private key will be stored unencrypted on disk")
        return None
    pw = common.passphrase(args, confirm=True, purpose="new signing key")
    if pw is None:
        raise SystemExit(
            "a passphrase is required (set VEILMARK_PASSPHRASE or use a terminal); "
            "pass --no-passphrase to store the key unencrypted"
        )
    return pw


def cmd_init(vm: Veilmark, args: argparse.Namespace) -> int:
    out: dict[str, object] = {}
    pk = vm.keystore.ensure_pattern_key()
    out["pattern_key_id"] = pk.key_id
    if not vm.keystore.identities():
        ident = vm.keystore.generate_identity(args.label, _pass_for_new(args))
        vm.trust.add(ident.public_bytes, args.label, note="own identity")
        out["identity"] = ident.key_id
        out["fingerprint"] = keys_mod.format_fingerprint(ident.public_bytes)
    else:
        out["identity"] = vm.keystore.identity().key_id
    common.emit(
        out,
        args.json,
        f"pattern key {out['pattern_key_id']}, signing identity {out['identity']} (store: {vm.home})",
    )
    return 0


def cmd_generate(vm: Veilmark, args: argparse.Namespace) -> int:
    ident = vm.keystore.generate_identity(args.label, _pass_for_new(args))
    if not args.no_trust:
        vm.trust.add(ident.public_bytes, args.label, note="own identity")
    fp = keys_mod.format_fingerprint(ident.public_bytes)
    common.emit(
        {"key_id": ident.key_id, "fingerprint": fp, "public_key": ident.public_key},
        args.json,
        f"created identity {ident.key_id} ({args.label})\nfingerprint {fp}",
    )
    return 0


def cmd_list(vm: Veilmark, args: argparse.Namespace) -> int:
    ids = [
        {
            "key_id": i.key_id,
            "label": i.label,
            "status": i.status,
            "created": _ts(i.created),
            "encrypted": i.private.get("scheme") != "plaintext",
            "replaced_by": i.replaced_by,
            "fingerprint": keys_mod.format_fingerprint(i.public_bytes),
        }
        for i in vm.keystore.identities()
    ]
    pks = [
        {"key_id": k.key_id, "label": k.label, "created": _ts(k.created)} for k in vm.keystore.pattern_keys()
    ]
    if args.json:
        common.emit({"identities": ids, "pattern_keys": pks}, True)
        return 0
    print("Signing identities:")
    for i in ids:
        enc = "" if i["encrypted"] else "  [UNENCRYPTED]"
        print(f"  {i['key_id']}  {i['status']:<8} {i['label']}{enc}\n      fingerprint {i['fingerprint']}")
    print("Pattern keys (secret; needed to detect):")
    for k in pks:
        print(f"  {k['key_id']}  {k['label']}")
    return 0


def cmd_export_public(vm: Veilmark, args: argparse.Namespace) -> int:
    ident = vm.keystore.identity(args.identity)
    text = f"veilmark-ed25519 {ident.public_key} {ident.label}\n"
    if args.output:
        args.output.write_text(text)
    common.emit(
        {"key_id": ident.key_id, "public_key": ident.public_key},
        args.json,
        None if args.output else text.strip(),
    )
    return 0


def cmd_export_private(vm: Veilmark, args: argparse.Namespace) -> int:
    common.err("WARNING: anyone holding this file can sign payloads as this identity.")
    if not args.yes and (not sys.stdin.isatty() or input("Type 'export' to continue: ").strip() != "export"):
        common.err("aborted (use --yes to confirm non-interactively)")
        return common.EXIT_USAGE
    if args.output.exists():
        common.err("output exists; refusing to overwrite a key file")
        return common.EXIT_USAGE
    seed = vm.keystore.export_private_seed(args.identity, common.passphrase(args))
    from veilmark.storage.paths import atomic_write_bytes

    atomic_write_bytes(args.output, (base64.b64encode(seed).decode() + "\n").encode(), private=True)
    common.emit({"written": str(args.output)}, args.json, f"private key written to {args.output} (mode 0600)")
    return 0


def cmd_import_private(vm: Veilmark, args: argparse.Namespace) -> int:
    seed = base64.b64decode(args.file.read_text().strip(), validate=True)
    ident = vm.keystore.import_identity_seed(seed, args.label, _pass_for_new(args))
    common.emit({"key_id": ident.key_id}, args.json, f"imported identity {ident.key_id}")
    return 0


def cmd_rotate(vm: Veilmark, args: argparse.Namespace) -> int:
    old, new = vm.keystore.rotate(args.identity, args.label, _pass_for_new(args))
    vm.trust.add(new.public_bytes, new.label, note=f"rotated from {old.key_id}")
    common.emit(
        {"retired": old.key_id, "new": new.key_id},
        args.json,
        f"retired {old.key_id}; new active identity {new.key_id} (added to trust list)",
    )
    return 0


def cmd_set_status(vm: Veilmark, args: argparse.Namespace) -> int:
    ident = vm.keystore.set_status(args.identity, args.status)
    if args.status == "revoked":
        with contextlib.suppress(ValueError):
            vm.trust.revoke(ident.key_id)
    common.emit(
        {"key_id": ident.key_id, "status": ident.status}, args.json, f"{ident.key_id} -> {ident.status}"
    )
    return 0


def cmd_pattern_generate(vm: Veilmark, args: argparse.Namespace) -> int:
    pk = vm.keystore.generate_pattern_key(args.label)
    common.emit({"key_id": pk.key_id}, args.json, f"created pattern key {pk.key_id}")
    return 0


def cmd_pattern_export(vm: Veilmark, args: argparse.Namespace) -> int:
    common.err("WARNING: a pattern key lets its holder detect, and attempt to remove, your watermarks.")
    if not args.yes:
        common.err("re-run with --yes to confirm")
        return common.EXIT_USAGE
    if args.output.exists():
        common.err("output exists; refusing to overwrite a key file")
        return common.EXIT_USAGE
    pk = vm.keystore.pattern_key(args.key)
    from veilmark.storage.paths import atomic_write_bytes

    atomic_write_bytes(args.output, (f"veilmark-pattern {pk.key} {pk.label}\n").encode(), private=True)
    common.emit({"written": str(args.output)}, args.json, f"pattern key written to {args.output}")
    return 0


def cmd_pattern_import(vm: Veilmark, args: argparse.Namespace) -> int:
    parts = args.file.read_text().split()
    raw = parts[1] if parts and parts[0] == "veilmark-pattern" else parts[0]
    pk = vm.keystore.add_pattern_key(keys_mod.b64d(raw), args.label)
    common.emit({"key_id": pk.key_id}, args.json, f"imported pattern key {pk.key_id}")
    return 0


def _read_pub(s: str) -> bytes:
    p = Path(s)
    if p.exists():
        parts = p.read_text().split()
        s = parts[1] if parts and parts[0] == "veilmark-ed25519" else parts[0]
    return keys_mod.b64d(s)


def cmd_trust_add(vm: Veilmark, args: argparse.Namespace) -> int:
    pub = _read_pub(args.key)
    e = vm.trust.add(pub, args.label, args.not_before, args.not_after)
    fp = keys_mod.format_fingerprint(pub)
    common.emit(
        {"key_id": e.key_id, "fingerprint": fp},
        args.json,
        f"trusted {e.key_id} ({args.label})\nfingerprint {fp}\nCompare this fingerprint with the issuer over a separate channel.",
    )
    return 0


def cmd_trust_list(vm: Veilmark, args: argparse.Namespace) -> int:
    rows = [
        {
            "key_id": i.key_id,
            "label": i.label,
            "status": i.status,
            "revoked_at": _ts(i.revoked_at),
            "not_before": _ts(i.not_before),
            "not_after": _ts(i.not_after),
            "fingerprint": keys_mod.format_fingerprint(i.public_bytes),
        }
        for i in vm.trust.issuers()
    ]
    if args.json:
        common.emit(rows, True)
    else:
        for r in rows:
            extra = f" revoked {r['revoked_at']}" if r["revoked_at"] else ""
            print(f"{r['key_id']}  {r['status']:<8} {r['label']}{extra}\n    {r['fingerprint']}")
        if not rows:
            print("(trust list is empty)")
    return 0


def cmd_trust_revoke(vm: Veilmark, args: argparse.Namespace) -> int:
    e = vm.trust.revoke(args.issuer, args.at)
    common.emit({"key_id": e.key_id, "revoked_at": e.revoked_at}, args.json, f"revoked {e.key_id}")
    return 0


def cmd_trust_remove(vm: Veilmark, args: argparse.Namespace) -> int:
    vm.trust.remove(args.issuer)
    common.emit({"removed": args.issuer}, args.json, f"removed {args.issuer}")
    return 0


def _keyfile_passphrase(confirm: bool) -> str:
    env = os.environ.get("VEILMARK_KEYFILE_PASSPHRASE")
    if env is not None:
        return env
    if not sys.stdin.isatty():
        raise SystemExit("set VEILMARK_KEYFILE_PASSPHRASE or run in a terminal")
    import getpass

    pw = getpass.getpass("Keyfile passphrase: ")
    if confirm and getpass.getpass("Repeat keyfile passphrase: ") != pw:
        raise SystemExit("passphrases do not match")
    return pw


def cmd_export_keyfile(vm: Veilmark, args: argparse.Namespace) -> int:
    from veilmark.crypto import keyfile
    from veilmark.storage.paths import atomic_write_bytes

    if args.output.exists():
        common.err("output exists; refusing to overwrite a key file")
        return common.EXIT_USAGE
    common.err("WARNING: the keyfile contains your private signing key and pattern key (encrypted).")
    bundle = keyfile.bundle_from_store(vm.keystore, vm.trust, args.identity, common.passphrase(args))
    text = keyfile.encrypt(bundle, _keyfile_passphrase(confirm=True))
    atomic_write_bytes(args.output, text.encode(), private=True)
    common.emit(bundle.header(), args.json, f"keyfile written to {args.output}")
    return 0


def cmd_import_keyfile(vm: Veilmark, args: argparse.Namespace) -> int:
    from veilmark.crypto import keyfile

    text = args.file.read_text("utf-8")
    hdr = keyfile.peek(text)
    common.err(f"keyfile for {hdr['label']} ({hdr['signing_key_id']}), fingerprint {hdr['fingerprint']}")
    bundle = keyfile.decrypt(text, _keyfile_passphrase(confirm=False))
    added = keyfile.install_bundle(vm.keystore, vm.trust, bundle, _pass_for_new(args))
    common.emit(added, args.json, f"imported: {added}")
    return 0
