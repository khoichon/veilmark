# Threat model

Veilmark embeds a hidden, signed payload into images and video. It is designed to make
the payload *hard to remove accidentally or casually* and *impossible to forge without
a signing key*. It does **not** make removal impossible.

## Assets

| Asset | Held by | If compromised |
|---|---|---|
| Ed25519 signing private key | issuer (encrypted at rest) | attacker can sign arbitrary payloads as the issuer |
| Pattern key (32 bytes, symmetric) | issuer + authorised detectors | holder can detect, read, *remove or transplant* watermarks made with it |
| Trust list | each verifier | wrong keys accepted / right keys rejected |
| Original (unwatermarked) media | issuer | enables exact removal by substitution |

## Three separate properties

* **A. Payload confidentiality** — *not provided.* Anyone holding the pattern key can
  read the payload. Payload text is not encrypted. If confidential text is needed it
  must be encrypted before embedding (not implemented in this release); authorised
  decryption would then need a further secret key.
* **B. Signal concealment and robustness** — provided *to a measured degree*. The
  pattern is keyed, so an attacker without the pattern key cannot locate it precisely,
  and it survives the common transformations measured in
  [benchmarking.md](benchmarking.md). It can still be destroyed.
* **C. Payload authenticity** — provided by Ed25519 signatures over a canonical
  encoding bound to the watermark id. Verification is independent of the embedding
  algorithm. A valid signature from a trusted key proves only that **the key holder
  signed this payload**. It does *not* prove that the media is unedited, that the
  signer created or captured it, when it was made (timestamps are self-asserted), or
  that its content is true.

## Attacker capabilities considered

| Capability | Effect on Veilmark |
|---|---|
| Knows the algorithms and source code | Assumed (Kerckhoffs). Security rests on the keys. |
| Has the public verification keys | Harmless: they verify, they cannot sign. |
| Has many watermarked files | Can attempt **estimation/averaging attacks**. The tile pattern repeats inside each file and keyed template sinusoids are identical for a given key+variant across files; averaging spectra of many files can reveal template peaks, which can then be notched out, disabling geometric resynchronisation (unscaled copies remain detectable). Video averaging over time mixes independent variants (see below), which raises but does not eliminate this bar. |
| Crops, resizes, rotates, recolours, filters, recompresses | Measured; see benchmark. Small surviving areas, heavy downscaling, strong denoising and non-uniform scaling can defeat detection. |
| Drops, duplicates, reorders, retimes frames; extracts short clips | Tolerated: each frame's variant is identified from its own sync evidence. Very short clips (< ~0.5 s at 720p) may be insufficient. |
| Moving crops | Tracked (Viterbi peak tracking); measured. |
| Screenshots | Equivalent to scaling + recompression; often survives (measured as `combo-screenshot-like`). |
| Camera recording of a screen (recapture) | **Not supported**: perspective, moiré, blur and lens effects are outside the model. |
| Combines several transformations | Measured for a few combinations; robustness degrades multiplicatively. |
| Has a public detection oracle | If a detector with the pattern key is exposed, an attacker can iteratively perturb a file until detection fails (oracle attack). **Do not expose detection publicly**; Veilmark's web helper binds to 127.0.0.1 only. |
| Has the pattern key | Can detect, remove (subtract the estimated pattern), or **copy** a watermark (including a valid signed payload) onto other media. Signatures still prevent *new* payloads, but a genuine signed payload can be transplanted. Treat pattern keys as secrets. |
| Has the signing key | Can forge authentic-looking payloads. Revoke the key in every trust list; signatures with self-asserted timestamps before the revocation time are reported as `revoked`, never `trusted`. |
| Adds a second watermark (overwriting / ambiguity attack) | Two Veilmark watermarks on the **same tile period** fold onto each other coherently and garble each other (measured: both payloads lost). Mitigations: (1) each watermark uses one of five keyed periods (±0/4/8%), so independent watermarks usually differ in period and then both survive (measured: both payloads recovered); (2) embedding refuses media that already carries a watermark readable with the local keys, unless `--allow-rewatermark`, in which case a period ≥ 3.5% away is chosen; (3) detection reports *every* watermark it can decode. Limits: a watermark made with someone else's pattern key is invisible to your pre-check; random period choices collide with probability 1/5; and a determined attacker who estimates your period (e.g. from the template lines) can deliberately overwrite on the same period. Verifiers must still decide which issuers they trust. |
| Collusion: compares differently watermarked copies of one source | Not defended. Differences reveal the pattern; fingerprinting codes are out of scope. |
| Supplies malicious media files | Decoders (Pillow, OpenCV, ffmpeg) are third-party code. Veilmark enforces size/pixel/duration limits, uses decompression-bomb guards, never invokes a shell, and treats decoding errors as invalid input, but cannot fix codec vulnerabilities. Keep ffmpeg and Pillow up to date. |
| Supplies malicious plugins | In-process plugins run with the user's privileges. Mitigations: explicit approval, hash pinning, no key access through the API. Not a sandbox. |

## Trust boundaries

1. **Media in** → untrusted. Validated, size-limited, decoded by third-party libraries.
2. **Payload out** → untrusted until verified. Never display recovered text as
   authoritative without the signature and trust result next to it.
3. **Embedded key id** → a 4-byte *hint* only. It selects candidate keys from the local
   trust list; it is never trusted itself. A forged payload that reuses a trusted key's
   hint fails verification (tested).
4. **Trust list** → local policy. Add keys only after comparing fingerprints with the
   issuer over an independent channel.
5. **Plugins** → untrusted code; see [plugins.md](plugins.md).
6. **Web helper** → local only; per-session token + Host check; never expose it on a
   network interface.

## False positives and false negatives

* Detection claims are gated by calibrated thresholds (sync z ≥ 7.5 for "signal
  present"), and payload claims additionally require CRCs (CRC-16 for the id alone,
  with stricter sync/agreement gates; CRC-32 for the payload). Measured false-positive
  rates on unwatermarked media are reported in [benchmarking.md](benchmarking.md).
* Absence of a detected watermark proves nothing about the media's origin.

## What Veilmark is not

Not a substitute for backups, access control, copyright registration, content
provenance standards (e.g. C2PA manifests, which can complement it), or legal evidence.
