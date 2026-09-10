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

  @override
  String get linkCompareTitle => 'Compare the safety code';

  @override
  String get linkCompareBody => 'This exact code must show on BOTH devices:';

  @override
  String get linkCompareWarn =>
      'If they differ, cancel — someone may be intercepting the link.';

  @override
  String get linkTheyDiffer => 'They differ — cancel';

  @override
  String get linkTheyMatch => 'They match';

  @override
  String get linkDone =>
      'Device linked. It now carries your account and contacts.';

  @override
  String get linkCancelled => 'Link cancelled.';

  @override
  String linkFailed(String error) {
    return 'Link failed: $error';
  }

  @override
  String get linkADevice => 'Link a device';

  @override
  String get linkHostHelp =>
      'On the device you want to add, install Z and choose \"Link to an existing account\". It will show a pairing code — enter it here.';

  @override
  String get linkPairingCode => 'Pairing code';

  @override
  String get linkDeviceAction => 'Link device';

  @override
  String get linkSyncNote =>
      'Live message sync across your devices arrives in a follow-up update; linking establishes the trusted, verified connection now.';

  @override
  String get linkToAccount => 'Link to an account';

  @override
  String get linkJoinHelp =>
      'On your existing device, open Settings → Linked devices → \"Link a device\", then enter the code below.';

  @override
  String get copyCode => 'Copy code';

  @override
  String get relayAddressDev => 'Relay address (developer)';

  @override
  String get relayHelpLink =>
      'Custom or self-hosted relay. Leave as-is for the default zmessengers.com relay.';

  @override
  String get hideDevOptions => 'Hide developer options';

  @override
  String get devOptions => 'Developer options';

  @override
  String get linkStart => 'Start linking';

  @override
  String get linkRevokeTitle => 'Revoke this device?';

  @override
  String linkRevokeBody(String device) {
    return 'Messages will stop syncing to \"$device\", and your contacts will no longer deliver to it. This can\'t be undone — to use that device again you would link it fresh.';
  }

  @override
  String get revoke => 'Revoke';

  @override
  String get linkedDevices => 'Linked devices';

  @override
  String get linkNoneYet => 'No other devices linked yet.';

  @override
  String get linkNotRoot =>
      'This is a linked device. Adding or revoking devices is done from your main device — the one that created the account.';

  @override
  String get linkRevokeNote =>
      'Each device has its own keys. Revoking one re-signs your device list so your contacts immediately stop trusting it.';

  @override
  String get linkThisDevice => 'This device';

  @override
  String linkKeyFingerprint(String fingerprint) {
    return 'Key $fingerprint…';
  }

  @override
  String get linkRevokeDevice => 'Revoke device';

  @override
  String get backupTitle => 'Backup';

  @override
  String get backupNoneYet => 'No backup yet';

  @override
  String backupLastTaken(String when) {
    return 'Last backup $when';
  }

  @override
  String get backupNoneBody =>
      'Your messages live only on this device. If you lose it, they are gone — there is no copy on any server.';

  @override
  String backupExistsBody(String size) {
    return '$size · kept on this device. Save a copy somewhere else so a lost phone does not take it with them.';
  }

  @override
  String get backupWorking => 'Working…';

  @override
  String get backupCreate => 'Create a backup';

  @override
  String get backupCreateHelp =>
      'Every message, contact, group and attachment, encrypted with a recovery code only you hold.';

  @override
  String get backupSaveCopy => 'Save a copy…';

  @override
  String get backupSaveCopyHelp =>
      'Put the latest backup somewhere off this device.';

  @override
  String get backupAuto => 'Back up automatically';

  @override
  String backupAutoOnHelp(int days) {
    return 'Every $days days, using the recovery code you saved. That code is kept on this device to make it possible.';
  }

  @override
  String get backupAutoOffHelp =>
      'Off. Turning it on stores your recovery code on this device, so a backup can run without you.';

  @override
  String get backupFootnote =>
      'A backup restores your history onto a new device. It does not restore your live conversations — those re-handshake by themselves the first time you message someone, and the other person sees nothing unusual.\n\nThe backup never touches the relay. It is encrypted here, on this device, and only the recovery code opens it. Lose the code and the file cannot be opened by anyone — there is no server-side way in, which is the point.';

  @override
  String get backupPreparing => 'Preparing…';

  @override
  String get backupPackingMessages => 'Packing messages…';

  @override
  String get backupPackingAttachments => 'Packing attachments…';

  @override
  String get backupFinishing => 'Finishing…';

  @override
  String get backupCreated => 'Backup created. Save a copy somewhere safe.';

  @override
  String backupFailed(String error) {
    return 'Backup failed: $error';
  }

  @override
  String get backupAutoOff =>
      'Automatic backup off. The stored code was erased.';

  @override
  String get backupAutoOn => 'Z will back up every 7 days with that code.';

  @override
  String get backupCopySaved => 'Copy saved.';

  @override
  String backupTooLargeForPicker(String name) {
    return 'That backup is too large for this device\'s file picker. It is still saved in the app as $name.';
  }

  @override
  String backupSaveFailed(String error) {
    return 'Could not save: $error';
  }

  @override
  String sizeKb(String kb) {
    return '$kb KB';
  }

  @override
  String sizeMb(String mb) {
    return '$mb MB';
  }

  @override
  String get timeJustNow => 'just now';

  @override
  String timeMinutesAgo(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count min ago',
      one: '1 min ago',
    );
    return '$_temp0';
  }

  @override
  String timeHoursAgo(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count h ago',
      one: '1 h ago',
    );
    return '$_temp0';
  }

  @override
  String get timeYesterday => 'yesterday';

  @override
  String timeDaysAgo(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count days ago',
    );
    return '$_temp0';
  }

  @override
  String get backupCodeTitle => 'Your recovery code';

  @override
  String get backupCodeWriteDown =>
      'Write this down and keep it somewhere separate from the backup file itself. It is the only thing that opens the backup.';

  @override
  String get backupCodeNobodyCan =>
      'Nobody can recover it for you — not us, not the relay, not with a court order. That is deliberate, and it is the reason nobody can be compelled to hand over your messages either.';

  @override
  String get copy => 'Copy';

  @override
  String get codeCopied => 'Code copied';

  @override
  String get backupCodeWritten => 'I have written it down';

  @override
  String get backupWrongCode => 'That is a valid code, but not this one.';

  @override
  String get back => 'Back';

  @override
  String get confirm => 'Confirm';

  @override
  String get backupConfirmTitle => 'Type it back';

  @override
  String get backupConfirmBody =>
      'So we know it is written down correctly. Capitals, spacing and dashes do not matter.';

  @override
  String get backupAskCodeTitle => 'Your recovery code';

  @override
  String get backupAskCodeBody =>
      'Type the code you saved. It is stored on this device so a backup can run on its own — anyone who can already open this app could then open your backup files too.';

  @override
  String get backupAskCodeTurnOn => 'Turn on';
}
