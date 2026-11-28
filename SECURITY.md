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
  signing certificate. Compare it with the matching fingerprint in [Release
  signing certificate](#release-signing-certificate-android) below: the
  upload key for an APK from the releases page, or the app signing key
  (classical or post-quantum) for a copy from Google Play. Once one release
  is installed, Android refuses an update signed by any other certificate.
  A certificate reading `CN=Android Debug` is not a release key: everyday
  CI and local `--release` builds still fall back to the debug key when the
  release keystore is absent; a tagged (`v*`) release build fails instead
  of shipping one. The copy on Google Play is re-signed by Google (Play
  App Signing), so its certificate differs from the APK on the releases
  page, and neither installs over the other.
- **macOS** — `codesign --verify --deep --strict Z.app` and
  `spctl -a -vv Z.app` (Gatekeeper) should both pass on a notarized build.
- **Windows** — right-click `zapp.exe` → Properties → Digital Signatures, or
  `Get-AuthenticodeSignature zapp.exe`.

An unsigned build still works; it just triggers the OS "unknown developer"
warnings. The checksum is your integrity check either way.

## Release signing certificate (Android)

Three SHA-256 fingerprints. Compare the `SHA-256 digest` line from:

```
apksigner verify --print-certs app-release.apk
```

with the fingerprint that matches where the APK came from.

**Upload key** — the certificate that signs the GitHub release APK and AAB,
and the one used to upload the bundle to Play.

```
13:E6:92:03:8F:5E:1A:60:19:B1:9C:F0:39:9D:E9:99:B2:4F:8B:B3:1D:E5:8C:C2:19:C2:36:BE:C0:21:16:2C
```

**Classical app signing key** — the classical certificate Google uses,
under Play App Signing, to re-sign the copy served from the Play Store.

```
15:34:82:0A:EA:F6:79:CC:DF:06:CB:D0:C4:39:FA:88:3D:71:F4:75:79:36:31:A5:EA:BE:30:68:B9:E8:9B:55
```

**Post-quantum cryptography (PQC) app signing key** — the post-quantum
certificate Google also uses under Play App Signing, alongside the
classical key, for quantum-ready hybrid signing.

```
56:4E:50:D9:97:A5:8D:70:44:38:E8:39:38:00:A0:78:A2:A2:CD:27:A1:10:36:AA:EF:A1:25:D5:38:F8:34:23
```

The Play Store copy is re-signed by Google, so its certificate will not
match the upload key, and neither install will replace the other. See
`docs/SIGNING.md`.

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

If you want the reasoning rather than the byte layout, start with
`docs/WHITEPAPER.md`: it takes each claim in turn and says what is asserted,
what mechanism carries it, why that mechanism and not the obvious
alternative, and what it does not cover. `docs/DATA_MAP.md` is the inventory
underneath both — every column of the vault, everything the relay holds, and
every third party that learns anything.
