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

  @override
  String get onbEnterRelayFirst => 'Enter your relay address first.';

  @override
  String get onbRelayReachable => 'Connected — the relay is reachable.';

  @override
  String get onbRelayUnreachable =>
      'Check the address and that it shows Live in your host dashboard.';

  @override
  String get onbPickName =>
      'Pick a display name (only your contacts ever see it).';

  @override
  String get onbChooseBackup => 'Choose your Z backup';

  @override
  String get onbNotABackup => 'That file is not a Z backup.';

  @override
  String get onbRestoreFailed =>
      'Restore failed: wrong secret, or the file is damaged.';

  @override
  String get onbRecoveryCode => 'Recovery code';

  @override
  String get onbRecoveryCodeHelp =>
      'The 25-character code you saved when you made this backup.';

  @override
  String get cancel => 'Cancel';

  @override
  String get onbRestore => 'Restore';

  @override
  String get onbBackupPassphrase => 'Backup passphrase';

  @override
  String get passphrase => 'Passphrase';

  @override
  String get unlock => 'Unlock';

  @override
  String get onbDisplayName => 'Display name';

  @override
  String get onbDisplayNameHelp =>
      'Shared only inside your encrypted contact code';

  @override
  String get onbRelayAddress => 'Relay address (developer)';

  @override
  String get onbRelayHelp =>
      'Custom or self-hosted relay. Leave as-is to use the default zmessengers.com relay.';

  @override
  String get onbTesting => 'Testing…';

  @override
  String get onbTestConnection => 'Test connection';

  @override
  String get onbCreateIdentity => 'Create my identity';

  @override
  String get onbRestoreFromBackup => 'Restore from a backup';

  @override
  String get onbLinkExisting => 'Link to an existing account';

  @override
  String get onbHideDevOptions => 'Hide developer options';

  @override
  String get onbDevOptions => 'Developer options';

  @override
  String get onbIdentityNote =>
      'Your identity is a cryptographic key pair generated on this device. It never leaves it unencrypted.';

  @override
  String get grpNeedNameAndMember =>
      'Pick a group name and at least one member.';

  @override
  String grpCreateFailed(String error) {
    return 'Could not create: $error';
  }

  @override
  String get grpNew => 'New group';

  @override
  String get grpName => 'Group name';

  @override
  String get grpNameHelp =>
      'Members see this name. Messages are end-to-end encrypted to each member individually.';

  @override
  String get grpAddContactsFirst => 'Add some contacts first.';

  @override
  String grpCreateWithCount(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: 'Create group ($count members)',
      one: 'Create group (1 member)',
    );
    return '$_temp0';
  }

  @override
  String get grpAddMembers => 'Add members';

  @override
  String get add => 'Add';

  @override
  String get grpLeaveTitle => 'Leave this group?';

  @override
  String get grpLeaveBody =>
      'You will stop receiving its messages. Your copy of the history stays on this device.';

  @override
  String get grpLeave => 'Leave';

  @override
  String get grpRemoved => 'Group removed';

  @override
  String get grpNoLongerIn => 'You are no longer in this group';

  @override
  String grpMemberCount(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other:
          '$count members · every message is end-to-end encrypted to each member',
      one: '1 member · every message is end-to-end encrypted to each member',
    );
    return '$_temp0';
  }

  @override
  String get grpYouAdmin => 'You (admin)';

  @override
  String get grpYou => 'You';

  @override
  String get grpUnknown => 'Unknown';

  @override
  String get grpAdmin => 'admin';

  @override
  String get grpRemoveFromGroup => 'Remove from group';

  @override
  String get grpLeaveGroup => 'Leave group';

  @override
  String get grpFootnote =>
      'Groups have no server-side existence: the relay never learns the group\'s name or member list. Each message is sent as separate end-to-end encrypted copies over your verified 1:1 channels.';

  @override
  String onbRelayUnreachableAt(String url) {
    return 'Could not reach a relay at $url.\nCheck the address and that it shows Live in your host dashboard.';
  }
}
