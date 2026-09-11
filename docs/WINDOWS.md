# Running Z on Windows

Z's Windows app is the same Flutter codebase as Linux/macOS/Android — nothing
Windows-specific is missing. The only catch is that Windows binaries must be
*compiled on Windows*, so you get one in either of two ways.

## Option A — Download it

Every release on the [Releases page](https://github.com/FluffyHorizon1/z-messanger/releases/latest)
carries `z-windows-x64.zip`, built by the repository's CI on GitHub's Windows
machines, with its SHA‑256 in `SHA256SUMS.txt`. Unzip anywhere and run
**`zapp.exe`**. On first launch, keep the default relay or paste your own
address, hit **Test connection**, and you're in.

If you have forked the repository, the same workflow
(`.github/workflows/build.yml`) builds the zip on every push under the
**Actions** tab, and tagging `vX.Y.Z` attaches it to a release of your own.

## Option B — Build locally on your Windows PC

1. Install [Flutter](https://docs.flutter.dev/get-started/install/windows)
   (stable channel) and Visual Studio 2022 with the **"Desktop development
   with C++"** workload.
2. In the project folder:
   ```powershell
   cd app
   flutter pub get
   flutter build windows --release
   ```
3. Your app is at `app\build\windows\x64\runner\Release\zapp.exe` (the whole
   `Release` folder is the app — keep the DLLs and `data\` next to the exe).

## Two things to expect on first run

**SmartScreen warning.** The build is not code-signed yet, so Windows shows
"Windows protected your PC" the first time. Click **More info → Run anyway**.
Code-signing (which removes this) is on the roadmap for public distribution —
it requires a paid certificate or the Microsoft Store's signing.

**Where your data lives.** Z stores its encrypted vault under your user profile
(`%APPDATA%`), with the vault key in **Windows Credential Manager**. Messages
are encrypted at rest exactly as on every other platform, and nothing syncs
anywhere — the vault on this PC is its own device identity.

## Windows-specific notes

The QR **scan** tab is hidden on desktop (no camera assumption); add contacts
by pasting codes, and show your own QR for a phone to scan. Attachments open
and save through the standard Windows file dialogs. The relay address, once
tested, is remembered; `wss://` addresses work out of the box.
