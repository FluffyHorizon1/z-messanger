# Security

Z is a zero-trust, end-to-end encrypted messenger: the relay only ever sees
ciphertext addressed to opaque routing IDs, and it stores nothing on disk.
Because it makes cryptographic claims, verifiability matters — this file covers
how to report an issue and how to verify what you install.

## Reporting a vulnerability

Please report security issues privately, not in public GitHub issues. Open a
[private security advisory](https://github.com/FluffyHorizon1/z-messanger/security/advisories/new)
on the repository, or email the maintainer listed on the GitHub profile.

Include what you need to reproduce it and, if you can, the affected version or
commit. We aim to acknowledge within a few days, agree on a disclosure timeline,
and credit you in the fix notes unless you'd rather stay anonymous.

Especially interested in: anything that lets the relay (or an on-path attacker)
read message content or reconstruct who is talking to whom, any way to bypass
the Double Ratchet or device-verification, and any path that writes plaintext to
disk.

## Supported versions

Z is pre-1.0 in practice; only the latest release on `main` receives security
fixes. Please upgrade before reporting.

## Verifying your download

Every tagged release attaches a `SHA256SUMS.txt` listing the SHA-256 of each
artifact. After downloading, check the file matches:

```
# Linux / macOS
sha256sum -c SHA256SUMS.txt        # (shasum -a 256 -c on macOS)

# Windows (PowerShell)
Get-FileHash z-windows-x64.zip -Algorithm SHA256
```

Platform code-signatures, when a release is signed (see `docs/SIGNING.md`):

- **Android** — `apksigner verify --print-certs app-release.apk` shows the
  signing certificate. Compare its SHA-256 fingerprint to the one published with
  the release.
- **macOS** — `codesign --verify --deep --strict Z.app` and
  `spctl -a -vv Z.app` (Gatekeeper) should both pass on a notarized build.
- **Windows** — right-click `zapp.exe` → Properties → Digital Signatures, or
  `Get-AuthenticodeSignature zapp.exe`.

An unsigned build still works; it just triggers the OS "unknown developer"
warnings. The checksum is your integrity check either way.

## What protects your messages

- Content is end-to-end encrypted with a Signal-style Double Ratchet; keys never
  leave your device unencrypted.
- The local vault is sealed with XChaCha20-Poly1305; the key lives in the OS
  keystore (optionally behind an app passphrase).
- The relay holds queued ciphertext in RAM only, addressed to routing IDs that
  are hashes, never the keys themselves.

See `docs/PROTOCOL.md` (the normative wire format, with test vectors) and
`docs/THREAT_MODEL.md` for the full model, and `docs/AUDIT_SCOPE.md` for the
brief we hand to security reviewers — the claims we make, where each is
specified and tested, and where we would like the most scrutiny.
