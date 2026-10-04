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

/// What voice-note playback has to work with in this run, decided once at
/// start-up by [initDesktopAudio].
enum VoicePlayback {
  /// just_audio's own player (Android, iOS, macOS), or no registration at all.
  native,

  /// The media_kit backend, registered with libmpv loaded (Linux, Windows).
  mediaKit,

  /// The media_kit backend could not load libmpv: on Linux it is a system
  /// library that is not installed, on Windows the copy that ships beside the
  /// executable is missing or broken. Playback is off for this run and the
  /// app says what is missing. Recording does not use libmpv (it captures
  /// through the `record` package) and is unaffected.
  unavailable,
}

VoicePlayback _playback = VoicePlayback.native;
String _playbackOs = '';

/// What [initDesktopAudio] decided for this run. The voice-note bubble and the
/// start-up notice read it; it does not change while the app runs.
VoicePlayback get voicePlayback => _playback;

/// The operating system [voicePlayback] was decided for. When playback is
/// [VoicePlayback.unavailable] this is what tells the notice which fix to
/// name: a library to install on Linux, a file that ships with Z on Windows.
String get voicePlaybackOs => _playbackOs;

/// Loads the media_kit backend for the platforms named. Throws when libmpv
/// cannot be loaded, as `JustAudioMediaKit.ensureInitialized` does.
typedef MediaKitLoader = void Function(
    {required bool linux, required bool windows});

void _loadMediaKit({required bool linux, required bool windows}) =>
    JustAudioMediaKit.ensureInitialized(linux: linux, windows: windows);

/// Registers the media_kit backend for the platforms [mediaKitAudioFor]
/// selects, and records the outcome in [voicePlayback]. A no-op on web and on
/// platforms with a native backend. Calling `ensureInitialized` is what loads
/// libmpv, so it happens here, from main(), once.
///
/// It never throws. Until 2026-10-04 it did: media_kit rethrows when libmpv is
/// not found, this ran before `runApp`, and a Linux machine without libmpv —
/// it is a system library there, which the build does not bundle — got a
/// process that never drew a window (P1-18). A backend that cannot load now
/// leaves playback off for the run, and the app starts and says so. The error
/// itself is not logged: media_kit prints its own fixed banner, and nothing
/// this adds names the machine or the person.
///
/// [load] stands in for the real loader in a test, which is how a machine
/// without libmpv is reproduced on one that has it.
VoicePlayback initDesktopAudio(String operatingSystem,
    {bool isWeb = kIsWeb, MediaKitLoader? load}) {
  _playbackOs = operatingSystem;
  final mk = mediaKitAudioFor(operatingSystem);
  if (isWeb || !(mk.linux || mk.windows)) {
    return _playback = VoicePlayback.native;
  }
  try {
    (load ?? _loadMediaKit)(linux: mk.linux, windows: mk.windows);
    return _playback = VoicePlayback.mediaKit;
  } catch (_) {
    // media_kit throws a plain Exception when no libmpv loads under any name
    // it tries; anything else thrown on the way means the same thing here.
    return _playback = VoicePlayback.unavailable;
  }
}
