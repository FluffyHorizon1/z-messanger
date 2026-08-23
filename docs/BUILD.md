# Building Z from source

Z is one Flutter app plus a Node relay and a pure‑Dart crypto library. CI in
`.github/workflows/build.yml` builds installable artifacts for all four client
platforms on every push and attaches them to tagged releases; the steps below
are the same thing by hand.

## Toolchain

| Tool | Version used / minimum |
|------|------------------------|
| Flutter | 3.44.7 stable (Dart 3.9+) |
| Node.js | 20+ (relay & protocol integration test) |
| Android | JDK 17, Android SDK (compileSdk 35), the Gradle version pinned in `app/android/gradle/wrapper/gradle-wrapper.properties` (Android Gradle Plugin in `app/android/settings.gradle.kts`) |
| Linux | clang, cmake, ninja, `libgtk-3-dev`, `libsecret-1-dev`, `liblzma-dev` |
| Windows | Visual Studio 2022 with “Desktop development with C++” |
| macOS | Xcode 15+ |

> Note on the Android Gradle toolchain: the repo ships the Flutter‑generated
> default (AGP 9.0.1 / Gradle 9.1.0). If you build on a machine that cannot
> reach `services.gradle.org` for that exact distribution, you can pin any
> AGP 8.7+/Gradle 8.9+ pair instead (e.g. AGP `8.7.3` with
> `gradle-8.14.3-bin.zip`) — the app and all plugins compile cleanly on both;
> only the wrapper/plugin versions change, not the code.

## Clients (Flutter)

```bash
cd app
flutter pub get

flutter build apk --release            # Android → build/app/outputs/flutter-apk/
flutter build apk --release --split-per-abi   # smaller per-ABI APKs
flutter build linux   --release        # → build/linux/x64/release/bundle/
flutter build windows --release        # → build/windows/x64/runner/Release/
flutter build macos   --release        # → build/macos/Build/Products/Release/
```

Run locally during development with `flutter run -d linux`
(or `windows`, `macos`, or an attached Android device).

## Relay (Node)

```bash
cd server
npm install
npm start            # ws://0.0.0.0:8080
# container (read-only fs, no volumes → provably storage-less):
docker compose up --build
```

## Tests

```bash
cd server   && npm test    # relay: auth, RAM queueing, no-disk-writes, spoofing
cd protocol && dart test   # crypto + a REAL conversation through the Node relay
```

The protocol suite includes `test/relay_integration_test.dart`, which launches
the actual relay process, connects two real clients, and verifies the full
handshake / ratchet / offline‑queue / attachment / receipt flow end‑to‑end —
and asserts the relay never observed any plaintext.

## Signing for distribution

- **Android:** the release build is debug‑signed by default so
  `flutter build apk` works out of the box. For store/public distribution,
  create a keystore and a `app/android/key.properties`, and wire a `signingConfig`
  in `app/android/app/build.gradle.kts`.
- **macOS/Windows:** sign/notarize with your platform certificates before wide
  distribution. Unsigned builds run locally and for testing.
