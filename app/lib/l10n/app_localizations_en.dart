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
}
