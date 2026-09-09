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
commit.

**`docs/VDP.md` is the full policy**, and the part worth reading before you
start is the safe harbour: research that follows it is authorised, and we will
not pursue or support legal action over it. It also states the response targets
(acknowledge in 5 working days, triage in 10, 90-day coordinated disclosure by
default — yours to shorten if we go quiet), what we most want broken, what is
already a documented limit rather than a finding, and that there is no funded
bounty, because saying otherwise would waste your time.

`https://zmessengers.com/.well-known/security.txt` carries the same contacts in
machine-readable form.

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

### Where the bytes came from

A checksum only proves two files match. If the download page and the checksum
come from the same place, checking one against the other proves that place was
consistent — which is what an attacker who controlled it would also be. Tagged
releases therefore carry a **build provenance attestation**, signed keyless
through Sigstore and recorded in a public transparency log:

```
gh attestation verify z-linux-x64.tar.gz --repo FluffyHorizon1/z-messanger
```

That names the commit, workflow and runner the file was built from, and it is
logged publicly, so the same answer cannot be given quietly to one person and
not to everyone. To go further and check those bytes match the source, build it
yourself: `docs/REPRODUCIBLE_BUILDS.md`. What provenance does and does not
prove — including that there is no in-app updater, and what that means — is in
`docs/PROVENANCE.md`.

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
