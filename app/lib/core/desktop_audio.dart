import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:just_audio_media_kit/just_audio_media_kit.dart';

/// 24.1 — desktop audio backend selection for voice-note playback.
///
/// `just_audio` ships native players for Android, iOS and macOS but none for
/// Linux or Windows, where playback used to fall back to a notice + Save. This
/// registers a `media_kit` (libmpv) backend for `just_audio` on those two
/// platforms *only* — the platforms with a working native backend are left
/// untouched, so nothing regresses on mobile or macOS.
///
/// The vault invariant is unaffected: a `StreamAudioSource` (our
/// `MemoryAudioSource`) is served to media_kit over just_audio's own loopback
/// HTTP server, so the decrypted note travels as bytes in memory, never a
/// plaintext file on disk — the same route macOS already takes.

/// Which desktop platforms need the media_kit backend, as a pure function of
/// the OS name (`Platform.operatingSystem`) so the policy is testable without a
/// desktop host. Only Linux and Windows; everything else keeps native.
({bool linux, bool windows}) mediaKitAudioFor(String operatingSystem) => (
      linux: operatingSystem == 'linux',
      windows: operatingSystem == 'windows',
    );

/// Registers the media_kit backend for the platforms [mediaKitAudioFor] selects.
/// A no-op on web and on platforms with a native backend, so it is always safe
/// to call once at startup. Calling `ensureInitialized` is what loads libmpv, so
/// it happens here (from main()) and never from a test.
void initDesktopAudio(String operatingSystem, {bool isWeb = kIsWeb}) {
  if (isWeb) return;
  final mk = mediaKitAudioFor(operatingSystem);
  if (mk.linux || mk.windows) {
    JustAudioMediaKit.ensureInitialized(linux: mk.linux, windows: mk.windows);
  }
}
