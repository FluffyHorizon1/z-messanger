// 24.1 — which platforms get the media_kit voice-note backend.
//
// A pure policy function so the choice is checkable without a desktop host:
// only Linux and Windows, where just_audio has no native backend, are turned
// on; Android, iOS and macOS keep the native player they already had, so this
// change cannot regress playback on a platform that already worked. The actual
// libmpv load happens in initDesktopAudio (called from main()), never here, so
// this test touches no native code.
import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/desktop_audio.dart';

void main() {
  test('media_kit is enabled on Linux and Windows only', () {
    expect(mediaKitAudioFor('linux'), (linux: true, windows: false));
    expect(mediaKitAudioFor('windows'), (linux: false, windows: true));
  });

  test('platforms with a native just_audio backend are left untouched', () {
    for (final os in ['macos', 'android', 'ios', 'fuchsia', '']) {
      final mk = mediaKitAudioFor(os);
      expect(mk.linux, isFalse, reason: '$os must keep its native backend');
      expect(mk.windows, isFalse, reason: '$os must keep its native backend');
    }
  });
}
