# Release signing

Roadmap Phase 2. Signing is **opt-in via repository secrets**. With no secrets
set, CI still builds every platform — Android falls back to the debug key and
desktop ships unsigned — so PRs and forks are never blocked. Add the secrets for
a platform and the next tagged build is signed. Nothing secret is ever committed
(`key.properties`, `*.jks`, `*.keystore` are git-ignored).

Set secrets under **Settings → Secrets and variables → Actions**.

## Android (fully wired + verified)

Signs the APK and the Play `.aab`. Generate an upload keystore once and guard it
— losing it means you can't update the Play listing.

```
keytool -genkeypair -v -keystore upload-keystore.jks -storetype JKS \
  -keyalg RSA -keysize 2048 -validity 9125 -alias upload
base64 -w0 upload-keystore.jks          # value for ANDROID_KEYSTORE_BASE64
```

| Secret | Value |
|--------|-------|
| `ANDROID_KEYSTORE_BASE64` | base64 of `upload-keystore.jks` |
| `ANDROID_KEYSTORE_PASSWORD` | the store password |
| `ANDROID_KEY_ALIAS` | the key alias (e.g. `upload`) |
| `ANDROID_KEY_PASSWORD` | the key password |

CI decodes these into `app/android/app/upload-keystore.jks` + `key.properties`
before building and deletes them after. Locally, drop your own
`app/android/key.properties` (see the same four fields) to sign a local
`flutter build`. Verify with `apksigner verify --print-certs`.

This path is exercised in this repo: a throwaway keystore produces an APK and an
AAB whose signer is the release cert, and with no `key.properties` the build
falls back to the debug cert — both confirmed before this landed.

## Windows (wired, needs a certificate to activate)

Needs an Authenticode code-signing certificate (`.pfx`) from a CA (e.g.
DigiCert/Sectigo) or via Azure Trusted Signing. Without one, SmartScreen warns
on first run; the build still ships.

```
base64 -w0 cert.pfx                      # value for WINDOWS_CERT_BASE64
```

| Secret | Value |
|--------|-------|
| `WINDOWS_CERT_BASE64` | base64 of the `.pfx` |
| `WINDOWS_CERT_PASSWORD` | its password |

CI runs `signtool sign … zapp.exe` with a SHA-256 timestamp when the secret is
present. Verify with `Get-AuthenticodeSignature zapp.exe`.

## macOS (wired, needs an Apple Developer account to activate)

Needs the Apple Developer Program ($99/yr): a **Developer ID Application**
certificate (export as `.p12`) and an app-specific password for notarization.
Without them, Gatekeeper warns; the build still ships.

| Secret | Value |
|--------|-------|
| `APPLE_CERT_BASE64` | base64 of the Developer ID `.p12` |
| `APPLE_CERT_PASSWORD` | its password |
| `APPLE_SIGN_IDENTITY` | e.g. `Developer ID Application: Name (TEAMID)` |
| `APPLE_ID` | your Apple ID email |
| `APPLE_TEAM_ID` | your 10-char team ID |
| `APPLE_APP_PASSWORD` | app-specific password for notarytool |

CI imports the cert into a throwaway keychain, `codesign`s with the hardened
runtime, submits to `notarytool --wait`, and staples the ticket. Verify with
`spctl -a -vv Z.app`.

### Known hazard — resolve before the first signed macOS build

**Do not set the Apple secrets until the signing step passes the app's
entitlements.** As written, the `macos` job re‑signs with
`codesign --deep --force --options runtime --timestamp --sign "$APPLE_SIGN_IDENTITY"`
and no `--entitlements`. A forced re‑sign does not carry the old signature's
entitlements across, so the signed app has none — none of
`app/macos/Runner/Release.entitlements`, which today's unsigned builds do carry
(Xcode signs them ad hoc with that file). On a Mac that runs the first signed
build over an unsigned one:

- **The vault moves.** The app keeps its vault, `prefs.json` and its app‑lock
  settings in `<Application Support>/z` (`Vault.defaultRoot()`). Sandboxed, as
  every build so far is, that is inside the app's container:
  `~/Library/Containers/com.zmessenger.www/Data/Library/Application Support/com.zmessenger.www/z/`.
  Unsandboxed, the same call answers
  `~/Library/Application Support/com.zmessenger.www/z/`, which is empty. The
  signed build finds no vault and starts as a new install.
- **What the user loses** — nothing is deleted, the old folder stays in the
  container, but the app no longer looks there: their identity (a new one is
  made at onboarding, so every contact sees a new key and every safety number
  changes), all contacts, every message and attachment, their groups and
  linked devices, and their settings (relay address, theme, app lock,
  transparency log). The only way back inside the app is restoring a `.zbk`
  backup with its recovery code, for those who made one. Moving the folder by
  hand works only if the per‑device secret that wraps the vault's key can
  still be read: `Vault` keeps it in the keychain, or in the folder's `.device`
  file when the keychain refuses it, and which of the two a given Mac used was
  not checked here.
- **The microphone stops.** Under the hardened runtime (`--options runtime`)
  audio input needs `com.apple.security.device.audio-input`; without it voice
  recording is refused.
- **The app is no longer confined:** unsandboxed, it can read anything the
  user can.

It has to be right the first time. Fixing the step after a signed build has
shipped moves the vault back into the container — and anyone who set up a new
identity in the unsandboxed build then loses that one.

The fix is a change to `.github/workflows/build.yml`, not made here: sign the
nested frameworks first, without entitlements, then the app itself with
`--entitlements app/macos/Runner/Release.entitlements` (not with `--deep`,
which would give every nested framework the app's entitlements), and before
notarizing check that `codesign -d --entitlements - Z.app` lists
`com.apple.security.app-sandbox`.

## Reproducibility

Every tagged release also publishes `SHA256SUMS.txt` (see `SECURITY.md`), so a
download can be integrity-checked even where a platform build is unsigned.
