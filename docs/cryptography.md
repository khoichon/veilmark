# Cryptography and key management

All cryptography comes from libsodium via **PyNaCl** and from Python's `hashlib`. No
primitives are implemented in Veilmark.

## Primitives

| Purpose | Primitive |
|---|---|
| Payload signatures | Ed25519 (PyNaCl `SigningKey`/`VerifyKey`) |
| Private-key encryption at rest | Argon2id (`nacl.pwhash`, `MODERATE` limits) → XSalsa20-Poly1305 (`SecretBox`) |
| Secret pattern derivation | SHAKE-256 XOF keyed with the 32-byte pattern key, length-prefixed domain separation (`crypto/kdf.py`) |
| Public pattern key (publicly verifiable watermarks) | SHAKE-256 `derive_key(public key, "public-pattern/v1")` (`keys.public_pattern_key`) |
| Key ids / fingerprints | SHA-256(`"veilmark/keyid/v1\0"` ‖ public key) |
| Integrity in the channel | CRC-16 (core), CRC-32 (payload) — error detection only, not security |

## Payload format v1 (canonical)

```
u8  version = 1
u8  flags        bit0 signed, bit1 timestamp, bit2 text, bit3 metadata (others must be 0)
[4] key id hint  (signed)    first 4 bytes of the signer's fingerprint
u32 timestamp    (flag)      Unix seconds, self-asserted
u8 n, n bytes    (flag)      text, UTF-8, NFC-normalised, n ≤ 120
u8 n, n bytes    (flag)      metadata, opaque, n ≤ 120
[64] signature   (signed)    Ed25519 over "veilmark/payload/v1\0" ‖ watermark_id(8) ‖ all bytes above
```

The parser rejects unknown versions, reserved flags, truncation, invalid or non-NFC
UTF-8, oversize fields and non-zero trailing bytes, and finally re-encodes the parsed
payload and requires byte equality. There is therefore exactly one byte string per
payload, so different serialisers cannot produce ambiguous signed messages.

The 64-bit **watermark id** is random per watermark (CSPRNG), travels in the robust
core layer, and is bound into the signature, so a valid payload cannot be moved under
another id (tested: `forgery-swapped-id`).

## Publicly verifiable watermarks

`WatermarkSpec(public=True)` (CLI `--public`, GUI and web checkbox) embeds with a pattern
key derived from the signing identity's Ed25519 public key instead of a stored secret
pattern key. Detection always tries, besides the stored pattern keys, the derived key of
every own identity and every trusted issuer, so a verifier needs only the issuer's public
key. Such watermarks must be signed. Because the derived key is public, anyone with the
public key can locate, remove or transplant these watermarks (see
[threat-model.md](threat-model.md)); the signature still prevents forging new payloads.
Reports flag them with `diagnostics.publicly_verifiable`. Because every extra key adds a full
search, detection tries the stored (secret) pattern keys first, exactly as without this
feature, and the public keys only when that finds nothing; the false-alarm estimate of
a public-key match counts both searches. A watermark made with a stored key costs no
more to detect than before, while an unwatermarked image costs one extra search.

## Verification result

`trust.verify` returns two independent fields:

* `signature`: `valid` | `invalid` | `unsigned` | `unknown-key` | `unverifiable`
* `trust`: `trusted` | `untrusted` | `revoked` | `expired` | `not-yet-valid` | `n/a`

`authentic` is true only for `valid` + `trusted`. The 4-byte key-id hint merely
selects candidate keys from the local trust list; a key "claimed" by a payload is never
trusted automatically.

## Key store

Location: `VEILMARK_HOME` or the per-user data directory (`veilmark doctor` prints it):
macOS `~/Library/Application Support/Veilmark`, Linux `~/.local/share/veilmark`,
Windows `%APPDATA%\Veilmark`.

```
keys/signing/<key-id>.json   identity: public key, status, encrypted private key   (0600, dir 0700)
keys/pattern/<key-id>.json   pattern key (secret, base64)                          (0600, dir 0700)
trust.json                   trusted issuers
plugins.json, settings.json
```

* Private keys are encrypted with a passphrase by default. `--no-passphrase` (CLI) or
  an empty passphrase (GUI, after a warning) stores them unencrypted.
* Passphrases come from a TTY prompt or `VEILMARK_PASSPHRASE` (or `--passphrase-env
  NAME`); they are never logged or printed.
* **Pattern keys are stored unencrypted** (0600) because every detection needs them.
  Protect the data directory accordingly (full-disk encryption recommended).

## Lifecycle

| Operation | CLI |
|---|---|
| First run (pattern key + identity, own key trusted) | `veilmark keys init` |
| New identity | `veilmark keys generate --label NAME` |
| Export public key for verifiers | `veilmark keys export-public [ID] -o me.pub` |
| Trust an issuer (compare fingerprint out of band!) | `veilmark trust add me.pub --label NAME` |
| Rotate (successor created; old one *retired*, can't sign, old signatures still verify) | `veilmark keys rotate` |
| Retire / revoke your own identity | `veilmark keys set-status ID retired|revoked` |
| Revoke an issuer in your trust list | `veilmark trust revoke ID [--at UNIXTIME]` |
| Validity window | `veilmark trust add ... --not-before T --not-after T` |
| Backup private key (warns, 0600) | `veilmark keys export-private ID -o file --yes` |
| Share pattern key with an authorised detector | `veilmark keys pattern export -o file --yes` |

Revocation semantics: a payload signed by a revoked key is never reported as trusted.
If its self-asserted timestamp precedes the revocation time the message says so, but
timestamps are not proof (no trusted time-stamping is used).
