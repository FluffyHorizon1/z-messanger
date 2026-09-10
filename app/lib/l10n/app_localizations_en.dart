// ignore: unused_import
import 'package:intl/intl.dart' as intl;
import 'app_localizations.dart';

// ignore_for_file: type=lint

/// The translations for English (`en`).
class AppLocalizationsEn extends AppLocalizations {
  AppLocalizationsEn([String locale = 'en']) : super(locale);

  @override
  String get unlockTitle => 'Unlock';

  @override
  String get unlockPassphraseLabel => 'Passphrase';

  @override
  String get unlockPrompt => 'Enter your passphrase to unlock this device.';

  @override
  String get unlockShowPassphrase => 'Show passphrase';

  @override
  String get unlockHidePassphrase => 'Hide passphrase';

  @override
  String get unlockUseBiometrics => 'Use fingerprint / face';

  @override
  String get unlockFootnote =>
      'Your passphrase unlocks the encrypted vault on THIS device only. It is never sent anywhere, and there is no way to recover it — if you forget it, restore your identity from a .zid backup.';

  @override
  String get lockedTitle => 'Locked';

  @override
  String get lockUnlock => 'Unlock';

  @override
  String get lockWaiting => 'Waiting…';

  @override
  String get lockUsePassphraseInstead => 'Use passphrase instead';

  @override
  String get lockUnlockWithPassphrase => 'Unlock with passphrase';

  @override
  String get lockCancelled => 'Unlock cancelled.';

  @override
  String get lockCouldNotVerify =>
      'Could not verify. Try again, or use your passphrase.';

  @override
  String get lockIncorrectPassphrase => 'Incorrect passphrase. Try again.';

  @override
  String get lockNoBiometrics =>
      'No fingerprint, face or device PIN is available on this device.';

  @override
  String get voicePlay => 'Play voice note';

  @override
  String get voicePause => 'Pause voice note';

  @override
  String get voiceNoPlayback =>
      'Playback isn\'t available on this device — save the file instead.';

  @override
  String get searchHint => 'Search messages…';

  @override
  String get searchClear => 'Clear search';

  @override
  String get searchIntro =>
      'Search your messages. Everything is decrypted on this device only for the search — nothing leaves it.';

  @override
  String searchNoResults(String query) {
    return 'No messages match “$query”.';
  }

  @override
  String get searchYouPrefix => 'You: ';

  @override
  String searchSenderPrefix(String name) {
    return '$name: ';
  }

  @override
  String get homeSearch => 'Search messages';

  @override
  String get homeNewGroup => 'New group';

  @override
  String get homeSettings => 'Settings';

  @override
  String get homeAddContact => 'Add contact';

  @override
  String get relayLinked => 'relay linked';

  @override
  String get relayLinking => 'linking…';

  @override
  String get relayOffline => 'offline';

  @override
  String get homeEmptyTitle => 'No conversations yet';

  @override
  String get homeEmptyBody =>
      'Exchange contact codes in person or over a channel you trust, then every message is end-to-end encrypted and stored only on your two devices.';

  @override
  String get chatPreviewEmpty => 'Say hello — the line is encrypted.';

  @override
  String chatPreviewSender(String name, String body) {
    return '$name: $body';
  }

  @override
  String get dismiss => 'Dismiss';

  @override
  String contactAdded(String name) {
    return '$name added. Compare safety numbers when you can.';
  }

  @override
  String get addMyCode => 'MY CODE';

  @override
  String get addPaste => 'PASTE';

  @override
  String get addScan => 'SCAN';

  @override
  String get addMyCodeHelp =>
      'Have your contact scan this QR code, or send them the text code over a channel you trust. Codes contain only PUBLIC keys.';

  @override
  String get addCopyCode => 'Copy code';

  @override
  String get addCodeCopied => 'Code copied';

  @override
  String get addTheirCode => 'Their contact code';

  @override
  String get addNameOverride => 'Name (optional — overrides theirs)';

  @override
  String get addVerifyAndAdd => 'Verify & add';

  @override
  String get addSignatureNote =>
      'The code\'s signature is checked before the contact is added — a tampered code is rejected.';

  @override
  String get addScanPrompt => 'Point the camera at their Z code.';

  @override
  String chatPreviewFile(String name) {
    return '📎 $name';
  }
}
