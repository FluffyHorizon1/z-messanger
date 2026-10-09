// Screen security (42.1): whether the system may capture Z's window.
//
// An Android window can carry FLAG_SECURE. With it the system takes no
// screenshot of the window, leaves it out of screen recordings and screen
// sharing, and shows a blank card for the app in the recent-apps screen.
// Without it that card is a picture of whatever the app showed as it left
// the front — the open chat — taken and kept by the system, outside the
// vault, and shown to anyone who opens the recent-apps screen. The app lock
// does not cover it: the lock is drawn when Z comes back to the front, after
// the picture was taken.
//
// So the flag is set while the vault is open: the chats, the backup screen's
// recovery code, a link code, the lock screen over them. Before the vault is
// open there is nothing on screen worth taking — the unlock screen, whose
// field is obscured.
//
// It is a setting, on unless the person turns it off. A screenshot of one's
// own chat is a real use — keeping what someone said, showing it to somebody
// who needs to see it — and whoever needs one can have it: Settings ›
// Security says what turning the switch off costs. But the default is the
// one that keeps the vault's promise. A screenshot is a plaintext copy of the
// chat in the gallery, which many phones then copy to a cloud photo library
// by themselves, and the recent-apps card is a copy the system makes without
// being asked. Setting the flag only while the app lock is on was the other
// choice: it would hide the card from someone holding the phone of a person
// who turned the lock on, leave every copy the system makes of everybody
// else's chats, and cost exactly the people who chose the lock their
// screenshots unless the lock came off with them.
//
// Android only. Windows and macOS have their own ways of keeping a window out
// of a capture, which nothing here asks for yet; Linux has none a program can
// rely on. (There is no iOS build.)

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'prefs.dart';

/// Whether this platform has the flag at all — what decides whether Settings
/// offers the switch.
bool get screenSecurityAvailable =>
    !kIsWeb && defaultTargetPlatform == TargetPlatform.android;

/// Whether Z's window is to be kept from capture: on Android, while the
/// vault is open, unless the person turned [setting] off.
bool screenSecureFor({
  required TargetPlatform platform,
  required bool vaultOpen,
  required bool setting,
  bool isWeb = kIsWeb,
}) =>
    !isWeb && platform == TargetPlatform.android && vaultOpen && setting;

/// Applies [screenSecureFor] to the window, through the `z/screen` channel
/// the main activity answers (`MainActivity.kt`, `secure`: FLAG_SECURE on or
/// off). Follows [prefs] as it changes; the bootstrapper says when the vault
/// is open ([vaultOpened]).
class ScreenSecurity {
  ScreenSecurity(this.prefs, {TargetPlatform? platform})
      : _platform = platform {
    prefs.addListener(_onPrefs);
  }

  static const channel = MethodChannel('z/screen');

  final AppPrefs prefs;
  final TargetPlatform? _platform;
  bool _vaultOpen = false;

  /// What the window was last told; null until it is told anything. A
  /// window starts without the flag, so there is nothing to clear before
  /// the first time it is set.
  bool? _told;

  bool get _wanted => screenSecureFor(
      platform: _platform ?? defaultTargetPlatform,
      vaultOpen: _vaultOpen,
      setting: prefs.screenSecurity);

  /// The vault is open: from here on the window is kept from capture
  /// (unless the setting is off). Awaited before anything from the vault is
  /// shown.
  Future<void> vaultOpened() {
    _vaultOpen = true;
    return _apply();
  }

  void _onPrefs() => _apply();

  Future<void> _apply() async {
    final want = _wanted;
    if (want == (_told ?? false)) return;
    _told = want;
    try {
      await channel.invokeMethod<void>('secure', want);
    } catch (_) {
      // No activity to answer (a desktop build has no such channel and is
      // never asked; this is for a platform that should have one and did
      // not answer). Forget what was asked, so the next change asks again.
      _told = null;
    }
  }

  void dispose() => prefs.removeListener(_onPrefs);
}
