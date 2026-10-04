# ADR 0013 — A voice-note backend for Linux and Windows

**Status:** **Accepted** (2026‑09‑19) — built (24.1). Linux/Windows only; the
platforms with a working backend are untouched. **Amended 2026‑10‑04:** on Linux
libmpv is a system library the build does not bundle, and a machine without it
now starts with playback off and is told what to install (see the end).
**Decides:** how voice notes play on the two desktop platforms `just_audio` does
not support, and what dependency that is worth.

## Context

Voice notes (7.4) play through `just_audio`, fed already‑decrypted bytes from
memory by a `StreamAudioSource` (`MemoryAudioSource`) so a note is never written
to disk in plaintext — the vault invariant. `just_audio` has native players on
Android, iOS and macOS. On **Linux and Windows it has none**, and the deliberate
choice recorded in `pubspec.yaml` was to degrade gracefully: catch the failure,
show a notice, and let the message menu's Save action take the note off the
device. 24.1 asks to actually play them there.

The reason this was left is worth stating, because reversing it has a cost: a
desktop audio backend means a native media engine, and this is a zero‑trust
messenger where every added dependency widens the desktop attack surface. So the
question is not only "does it play" but "is the dependency worth it, and does it
keep the invariant".

## Decision

Register a **`media_kit` (libmpv) backend for `just_audio` on Linux and Windows
only**, via `just_audio_media_kit`, opt‑in per platform from `main()`
(`initDesktopAudio`, `core/desktop_audio.dart`). Android, iOS and macOS keep
their native backend — nothing that already works changes, and only these two
platforms' native libs are added, so the mobile and macOS builds gain no new
native code.

**The vault invariant holds unchanged.** `just_audio_media_kit` serves a
`StreamAudioSource` to media_kit over `just_audio`'s own loopback HTTP server —
the decrypted note travels as bytes on `127.0.0.1`, never a plaintext file — which
is the **same route macOS already used**. This is the property that made the
choice acceptable; a backend that required a temp file would have been rejected.

**The fallback stays.** The notice + Save path is not removed. A build with the
backend disabled, or a playback that fails for any other reason, still degrades
exactly as before. The backend is an upgrade to the good case, not a load‑bearing
new dependency for correctness.

## Rejected

- **Spilling the note to a temp file and playing that.** The obvious way to make
  any player work, and a direct vault‑invariant violation — a decrypted note on
  disk is the one thing the memory‑source design exists to prevent. Non‑starter.
- **A hand‑written ALSA/PulseAudio + WASAPI backend.** No new dependency, but a
  pile of platform audio code to own and get right for a feature this size, when
  a maintained package does exactly this.
- **Enabling media_kit on every platform.** It would replace three working,
  better‑integrated native backends with one library to no benefit, and put
  libmpv on mobile where it is not wanted. Scoped to the two platforms that have
  no backend at all.
- **Leaving it as notice + Save.** The status quo, and defensible — but the
  desktop apps are real targets and "voice notes you cannot hear" is a genuine
  gap. Finnian asked to close it (24.1).

## Consequences

- **Supply chain.** `just_audio_media_kit` pulls **10 packages** transitively:
  `media_kit` and its `image`, `archive`, `posix`, `safe_local_storage`,
  `universal_platform`, `uri_parser`, plus the two native‑lib bundles
  (`media_kit_libs_linux`, `media_kit_libs_windows_audio`). media_kit is a
  video+audio engine, so `image`/`archive` come along unused by our audio‑only
  path — dead weight, not a secret‑carrying path, but named here because the
  pusher's review lens asks for the closure. All pinned in `pubspec.lock`; no
  credentials, no config, nothing at rest.
- **Desktop CI build.** `media_kit_libs_linux`/`_windows_audio` download and
  bundle libmpv (and mimalloc) at build time, so the `linux` and `windows` jobs
  in `build.yml` now fetch those. The `pubspec.yaml` note that said "desktop CI
  builds are unaffected" is updated; that sentence is now false.
- **Android reproducibility is unaffected.** The native libs are desktop‑only, so
  the Android APK gains no `.so` and the `reproducible`/`reproducible-compare`
  jobs' fingerprint set is unchanged. (To confirm on CI, not asserted here.)
- **Sealed sender, ratchet, wire, relay:** untouched. This is a client‑side
  player on already‑decrypted bytes; nothing crosses the wire and nothing new is
  stored.

## What was verified, and what is CI/hardware‑gated

Recorded honestly, because the sandbox this was built in cannot do the desktop
part:

- **Verified here:** dependency resolution; the Linux/Windows plugin registrants
  regenerate to register media_kit and nothing else; `flutter analyze` clean; the
  platform‑selection policy (`mediaKitAudioFor`) tested; the full app suite green,
  so the `test` CI job (which runs `flutter test`, not a desktop build) is
  unaffected and nothing regressed.
- **CI/hardware‑gated (the pusher must confirm before landing):** `flutter build
  linux --release` and `flutter build windows --release` completing with media_kit
  — the sandbox's outbound proxy blocks the build‑time libmpv/mimalloc download
  from GitHub, so the build could not be run here; CI has no such proxy — and
  actual playback of a note on Linux/Windows hardware. The runtime audio check
  was hardware‑gated from the start (the 24.1 scoping said so).

## Amendment (2026‑10‑04) — libmpv is not bundled on Linux, and its absence no longer stops the app

Two sentences above were wrong for Linux, and the second one hid a defect that
shipped in every Linux build from 3.7.1 to 3.10.0 (P1‑18 in the 2026‑10‑03
analysis).

- **"`media_kit_libs_linux`/`_windows_audio` download and bundle libmpv."** True
  of Windows: `media_kit_libs_windows_audio` downloads an audio‑only
  `libmpv-2.dll` and installs it beside the executable. Not of Linux:
  `media_kit_libs_linux` 1.2.1 bundles nothing (its
  `media_kit_libs_linux_bundled_libraries` is empty). Its build step downloads
  and compiles mimalloc, which media_kit's *video* package links and this app
  does not. At run time media_kit looks for a **system** libmpv —
  `libmpv.so`, `libmpv.so.2`, then `libmpv.so.1`, or the path in
  `LIBMPV_LIBRARY_PATH` — so on Linux libmpv is a runtime dependency of the
  user's machine, now listed per distribution in `BUILD.md`.
- **"A build with the backend disabled, or a playback that fails for any other
  reason, still degrades exactly as before."** Not this failure. `main()` called
  `initDesktopAudio` before `runApp` with nothing around it, and media_kit
  rethrows when no libmpv loads. The Linux runner shows its window on Flutter's
  first frame, so on a machine without libmpv the process started and no window
  ever appeared — not a degraded voice note, an app that does not open.

What changed:

- **`initDesktopAudio` cannot throw.** A backend that fails to load leaves
  `voicePlayback` at `unavailable` for the run; the app starts as usual.
  `main()` is now `startApp()`, whose operating system and loader a test can
  replace — which is how `desktop_startup_test.dart` reproduces a machine
  without libmpv on one that has it.
- **The app says so, above its first screen.** A dismissible notice: voice
  messages cannot play on this computer, and what fixes it — on Linux the
  package to install (`libmpv2` on Debian and Ubuntu, `libmpv1` on older
  releases, `mpv-libs` on Fedora, `mpv` on Arch), on Windows unpacking the
  download again, since the DLL ships with Z. English and Spanish. It returns
  at the next start for as long as the library is missing.
- **A voice message's control says playback is off,** and tapping it gives the
  same explanation. Nothing is decrypted and no player is made — `just_audio`'s
  platform instance is already media_kit's by then (it is registered before
  libmpv is looked for), so trying would only fail later. The message menu's
  Save still takes the note off the device.
- **Recording is left on.** It does not use libmpv: `record`'s Linux
  implementation captures through `parecord` (PulseAudio's utilities, which
  PipeWire systems provide too), and its own failure already says "recording
  isn't available". Turning it off because playback is off would have told the
  user to install a library that does not fix it.
- **Nothing is logged.** The app neither prints nor stores the error. media_kit
  prints its own fixed banner to standard output, which names no path, machine
  or person.

Not changed: the backend, the two platforms it is registered on, and the vault
invariant — a note that is not played is not read at all. Bundling libmpv and
its FFmpeg into the Linux build was not taken up here: it would add a large
native supply chain to the release, and the build job would have to change.

Tested in `desktop_startup_test.dart` (criteria 1, 2 and 4–6): the real
backend on a Linux machine without libmpv no longer throws, and the app's own
`main()` reaches its first screen there; an injected
failing backend is caught on Linux and Windows and loads nothing elsewhere; the
app started with it shows the notice in both languages and dismisses it; and a
voice message's control is off and explains without reading the note. Still
hardware‑gated: a real `flutter build linux` bundle started on a desktop with
and without libmpv, and a Windows build with the DLL removed.
