# Running Z on Windows

Z's Windows app is the same Flutter codebase as Linux/macOS/Android — nothing
Windows-specific is missing. The only catch is that Windows binaries must be
*compiled on Windows*, so you get one in either of two ways.

## Option A — Let GitHub build it for you (recommended, zero setup)

You already push this repo to GitHub for the Render relay deploy; the included
CI pipeline (`.github/workflows/build.yml`) builds Windows automatically on
GitHub's Windows machines.

1. Push the repo to GitHub (see `DEPLOY.md`, or `bash deploy/push-to-github.sh`).
2. On GitHub, open your repo → **Actions** tab. The **build** workflow starts on
   every push (you can also start it manually via **Run workflow**).
3. When the **Windows build** job finishes (~5–8 min), open the run and download
   the **`z-windows-x64`** artifact.
4. Unzip anywhere and run **`zapp.exe`**. Paste your relay address on first
   launch, hit **Test connection**, and you're in.

Tagging a release (`git tag v1.0.0 && git push --tags`) attaches the Windows
zip — along with the Android APKs, Linux tarball, and macOS app — to a GitHub
Release page, which is the easiest thing to share with other people.

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
tested, is remembered; `wss://` works out of the box with your Render/Fly URL.
