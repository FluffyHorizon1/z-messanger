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
  String get unlockBiometricStale =>
      'Biometric unlock is out of date — enter your passphrase, then turn it on again in Settings.';

  @override
  String get unlockBiometricInvalidated =>
      'Your fingerprints or face changed, so biometric unlock was reset. Enter your passphrase, then turn it on again in Settings.';

  @override
  String get vaultTooNew =>
      'The data on this device was saved by a newer version of Z. Update Z to open it — nothing has been changed.';

  @override
  String startupFailed(String detail) {
    return 'Z could not start:\n$detail';
  }

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
  String get voicePlaybackOff => 'Voice playback is off on this computer';

  @override
  String get voiceNoLibmpvLinux =>
      'Voice messages can\'t play on this computer: libmpv, the library Z plays them with, isn\'t installed. Install it with your package manager — libmpv2 on Debian and Ubuntu (libmpv1 on older releases), mpv-libs on Fedora, mpv on Arch — then restart Z. Everything else works, and a voice message can still be saved from its menu.';

  @override
  String get voiceNoLibmpvWindows =>
      'Voice messages can\'t play on this computer: libmpv-2.dll, which comes with Z, is missing or could not be loaded. Unpack the Z download again with all of its files kept together, then restart Z. Everything else works, and a voice message can still be saved from its menu.';

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
  String contactUpgraded(String name) {
    return '$name was already in your contacts — their post-quantum commitment was taken from this code.';
  }

  @override
  String contactUpgradedUnsigned(String name) {
    return '$name was already in your contacts. The post-quantum commitment in this code is not signed, so it will only be used if the key their app sends matches it.';
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
  String get addShareCode => 'Share';

  @override
  String get addOpenImage => 'Open a QR image';

  @override
  String get addNoCodeInImage => 'No code found in that image.';

  @override
  String get addTheirCode => 'Their contact code';

  @override
  String get addNameOverride => 'Name (optional — overrides theirs)';

  @override
  String get addVerifyAndAdd => 'Verify & add';

  @override
  String get addSignatureNote =>
      'The code\'s signatures are checked before the contact is added, and a code whose keys were altered is rejected. Its post-quantum part is checked too: against its own signature where it carries one, against anything you already hold for them, and against their key when it arrives. The name in a code is only a suggestion.';

  @override
  String addRefusedCommitStripped(String name) {
    return 'This code is missing the signed post-quantum commitment that $name\'s codes carry. It may be an old code of theirs, or someone removed it. Nothing was changed — ask $name for their current code.';
  }

  @override
  String addRefusedUnsignedCommit(String name) {
    return 'The post-quantum commitment in this code does not match the key $name\'s app sent, and nothing in the code signs it, so it may have been altered. Nothing was changed. Compare the safety number with $name instead.';
  }

  @override
  String get addRefusedOwnCode => 'That is your own contact code.';

  @override
  String addRefusedAlreadyContact(String name) {
    return '$name is already in your contacts.';
  }

  @override
  String addRefusedOtherIdentity(String name) {
    return 'This code is for a different identity than the one you hold for $name. Nothing was changed.';
  }

  @override
  String addRefusedProvenElsewhere(String name) {
    return 'The device in this code has already proved it belongs to a different account than $name claims here. Nothing was added — do not trust this code.';
  }

  @override
  String addRefusedCommitChanged(String name) {
    return 'The post-quantum commitment in this code is not the one you hold for $name. If they reset their identity, delete the contact and add them again; otherwise do not trust this code.';
  }

  @override
  String addRefusedCommitMissesKey(String name) {
    return 'The post-quantum commitment in this code does not match the key you confirmed for $name. Do not trust this code.';
  }

  @override
  String addRefusedKeyMismatch(String name) {
    return 'The post-quantum key held for $name does not match the commitment in this code. It has been refused and the contact is flagged. Do not rely on this chat until you have spoken to $name on another channel.';
  }

  @override
  String get addRefusedInvalidCode =>
      'This code did not verify: it is not a Z contact code, or it was damaged or changed after its owner made it. Nothing was added — ask them for their code again.';

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
  String get onbBackupTooNew =>
      'This backup was made by a newer version of Z. Update Z first, then restore it — the backup itself is untouched.';

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
  String get grpRemoveTitle => 'Remove member?';

  @override
  String grpRemoveBody(String name) {
    return '$name will be removed from the group for everyone, and cannot be added back without a new invitation. There is no undo.';
  }

  @override
  String get grpRemoveConfirm => 'Remove';

  @override
  String get grpLeaveGroup => 'Leave group';

  @override
  String get grpFootnote =>
      'Groups have no server-side existence: the relay never learns the group\'s name or member list. Each message is sent as separate end-to-end encrypted copies over your verified 1:1 channels.';

  @override
  String get grpMsgPqBody =>
      'New messages in this group, in both directions, are protected by the post-quantum key exchange (ML-KEM-768) as well as X25519, on every device they reach.';

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
  String get linkPeerTooOld =>
      'The other device is running an older version of Z. Update it, then pair again — this version will not fall back to the older pairing.';

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
      'Your linked devices stay in sync: the messages you send and receive appear on all of them, and your contacts come across too. Linking sets up the trusted, verified connection they travel over.';

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

  @override
  String get save => 'Save';

  @override
  String get delete => 'Delete';

  @override
  String get ciContactRemoved => 'Contact removed';

  @override
  String ciRoutingId(String id) {
    return 'routing id: $id…';
  }

  @override
  String ciAddedOnDevice(String device) {
    return 'Added on $device';
  }

  @override
  String get ciAddedOnDeviceBody =>
      'This contact came from another of your devices, so no code was scanned here. Compare the safety number below before you rely on it.';

  @override
  String get ciPqSigMissing => 'A post-quantum signature never arrived';

  @override
  String get ciPqRefused => 'Post-quantum key refused';

  @override
  String ciPqRefusedBody(String name) {
    return 'A post-quantum key arrived for $name that does not match the code you scanned, so it was rejected and their identity was NOT upgraded. Either something is broken at their end, or someone is substituting keys. Compare the number below before trusting this chat.';
  }

  @override
  String get ciSafetyNumber => 'Safety number';

  @override
  String get ciSafetyCompare =>
      'Compare these 60 digits with the ones on their device (in person or on a call you trust). If they match, no one is sitting between you — not even the relay.';

  @override
  String get ciDevListHybrid =>
      'Their device list is signed post-quantum too, so no device can be added to the set you send to, or taken out of it, without that signature failing. It does not yet cover the key each of their linked devices receives messages on: that key is signed classically only, so someone holding their account key — or, one day, a quantum computer — could swap it without anything here changing.';

  @override
  String get ciDevListClassical =>
      'Their device list is signed classically only. That is correct today; the post-quantum signature for it travels separately and may not have arrived yet.';

  @override
  String get ciDevListHybridKeys =>
      'Their device list is signed post-quantum too, including the key each of their devices receives messages on, so the set you send to cannot be forged or quietly changed.';

  @override
  String get ciReaderBehind => 'Their app may not read your device list';

  @override
  String ciReaderBehindBody(String name) {
    return 'Your device list is now signed in the newer form, which apps older than 3.9.9 cannot read, and $name\'s app has not said it can read it. If it is that old, it cannot reach your other devices and may warn them about your account until they update. Nothing is wrong with either account.';
  }

  @override
  String get ciMsgPqTitle => 'Messages: post-quantum';

  @override
  String get ciMsgPqBody =>
      'New messages in this chat, in both directions, are protected by the post-quantum key exchange (ML-KEM-768) as well as X25519, on every device they reach.';

  @override
  String get ciMsgNotYetTitle => 'Messages: not post-quantum yet';

  @override
  String ciMsgNotYetBody(String channels) {
    return 'The post-quantum key exchange has not completed with $channels, so messages there are not yet protected by it in both directions. It needs messages to go both ways; until it completes, someone recording that traffic today could read some or all of it with a future quantum computer.';
  }

  @override
  String ciMsgChanContact(String name) {
    return '$name\'s device';
  }

  @override
  String ciMsgChanTheirOther(int count, String name) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count of $name\'s other devices',
      one: '1 of $name\'s other devices',
    );
    return '$_temp0';
  }

  @override
  String ciMsgChanMine(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count of your other devices',
      one: '1 of your other devices',
    );
    return '$_temp0';
  }

  @override
  String get ciRename => 'Rename';

  @override
  String get ciRenameContact => 'Rename contact';

  @override
  String get ciResetSession => 'Reset secure session';

  @override
  String get ciResetSessionHelp =>
      'Start a fresh encryption session (use if messages stop decrypting)';

  @override
  String get ciResetSessionDone => 'Secure session reset';

  @override
  String get ciResetTitle => 'Reset secure session?';

  @override
  String get ciResetBody =>
      'This throws away the current encryption session with this contact. Anything already on its way that hasn\'t arrived yet may be lost. Only do this if messages have stopped decrypting.';

  @override
  String get ciResetConfirm => 'Reset';

  @override
  String get ciDeleteContact => 'Delete contact & all messages';

  @override
  String get ciDeleteTitle => 'Delete everything?';

  @override
  String get ciDeleteBody =>
      'This wipes the contact, your chat with them and every attachment in it from THIS device. Anything a group\'s chat holds of them stays in that chat. There is no server copy to restore from — that is the point.';

  @override
  String ciDeleteBodyInGroups(int count, String groups) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other:
          'This wipes the contact, your chat with them and every attachment in it from THIS device, but not what the groups $groups hold of them: deleting a contact takes nobody out of a group.',
      one:
          'This wipes the contact, your chat with them and every attachment in it from THIS device, but not what the group $groups holds of them: deleting a contact takes nobody out of a group.',
    );
    return '$_temp0 Because a group goes on naming its members, this device keeps their routing id, public key and name in each group\'s record; and while they are in a group, a change made to it by someone else — or by you on another device — adds them back as a contact, as it does any member. Removing them from the group, or leaving it, drops them from its record. Anything a group\'s chat holds of them stays in that chat. There is no server copy to restore from — that is the point.';
  }

  @override
  String get ciBlurbClassical =>
      'This identity is signed with Ed25519. Their app has not published a post-quantum key, so there is nothing further to check.';

  @override
  String get ciBlurbPending =>
      'The code you scanned promised a post-quantum key that has not arrived yet. When it does, this number changes ONCE — that is the upgrade, not tampering, and you will be asked to compare it again. Until then only the Ed25519 half is covered.';

  @override
  String get ciBlurbHybrid =>
      'Covers both halves of both identities: Ed25519 and ML-DSA-65. The post-quantum key arrived over the encrypted session and matched the commitment in the code you scanned.';

  @override
  String get ciBlurbWaiting =>
      'Their post-quantum key has arrived, but they do not have yours yet, so the number below is still the Ed25519 one — the same number their device is showing. It becomes the post-quantum number on both devices at once, as soon as each of you holds the other\'s key.';

  @override
  String get ciBlurbCandidate =>
      'The number below covers both halves of both identities, but this app has not been able to check their post-quantum key against anything — you added them from a code that predates it, or they sent it after you added them. Comparing this number IS the check: if it matches on their device, the key is theirs, and confirming it below records that.';

  @override
  String get ciSwitchVerified => 'Verified';

  @override
  String get ciSwitchComparedAgain => 'I have compared it again';

  @override
  String get ciSwitchMarkVerified => 'Mark as verified';

  @override
  String get ciPillClassical => 'Classical';

  @override
  String get ciPillPqPending => 'Post-quantum pending';

  @override
  String get ciPillPq => 'Post-quantum';

  @override
  String get ciBlurbRefused =>
      'A post-quantum key arrived for them and did NOT match the code you scanned, so it was refused. The number below is the Ed25519 one — the only number left that means anything here. Nothing will upgrade this identity until the refusal is resolved; read the warning above.';

  @override
  String get ciPillPqRefused => 'Key refused';

  @override
  String get ciPillPqWaiting => 'Waiting for them';

  @override
  String get ciPillPqUnconfirmed => 'Post-quantum, unconfirmed';

  @override
  String get ciNoticeVerified => 'Verified';

  @override
  String ciNoticeVerifiedBody(String name) {
    return 'This is the number you compared with $name.';
  }

  @override
  String get ciNoticeUpgraded => 'The number changed — here is why';

  @override
  String ciNoticeUpgradedBody(String name) {
    return '$name\'s identity gained a post-quantum key, so the number is now derived from both halves. That is an upgrade, and it happens once. It is not a sign that anyone tampered with anything — but the number you checked before no longer applies, so please read this one out and compare it again.';
  }

  @override
  String get ciNoticeChanged =>
      'The number changed and this app cannot explain why';

  @override
  String ciNoticeChangedBody(String name) {
    return 'The number you verified with $name is not the one shown now, and this is not the one-time post-quantum upgrade. Do not rely on the previous verification. Compare the number below in person or on a call you trust before continuing.';
  }

  @override
  String get disappearingMessages => 'Disappearing messages';

  @override
  String get you => 'You';

  @override
  String sizeB(String b) {
    return '$b B';
  }

  @override
  String get chatMicPermission => 'Microphone permission is needed to record.';

  @override
  String get chatRecordingUnavailable =>
      'Recording isn\'t available on this device.';

  @override
  String get chatVoiceTooShort => 'Voice message too short.';

  @override
  String chatSendFailed(String error) {
    return 'Send failed: $error';
  }

  @override
  String get chatTooFarBack => 'That message is too far back to jump to.';

  @override
  String get chatEditTitle => 'Edit message';

  @override
  String get chatEditHint => 'Message';

  @override
  String get chatEditExpired => 'That message can no longer be edited.';

  @override
  String get chatDeleteEveryoneTitle => 'Delete for everyone?';

  @override
  String get chatDeleteEveryoneBody =>
      'The message is removed here and the other side is asked to remove it too. Anyone who already read it may have kept a copy — no app can undo that.';

  @override
  String get chatNoForwardTarget => 'No other conversation to forward to.';

  @override
  String get chatForwardTo => 'Forward to';

  @override
  String get chatForwarded => 'Forwarded.';

  @override
  String chatForwardFailed(String error) {
    return 'Forward failed: $error';
  }

  @override
  String chatReactionFailed(String error) {
    return 'Reaction failed: $error';
  }

  @override
  String get ttlOff => 'Off';

  @override
  String ttlSeconds(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count seconds',
      one: '1 second',
    );
    return '$_temp0';
  }

  @override
  String ttlMinutes(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count minutes',
      one: '1 minute',
    );
    return '$_temp0';
  }

  @override
  String ttlHours(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count hours',
      one: '1 hour',
    );
    return '$_temp0';
  }

  @override
  String ttlDays(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count days',
      one: '1 day',
    );
    return '$_temp0';
  }

  @override
  String ttlWeeks(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count weeks',
      one: '1 week',
    );
    return '$_temp0';
  }

  @override
  String get chatConversationRemoved => 'Conversation removed';

  @override
  String chatGroupSubtitle(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count members · end-to-end encrypted',
      one: '1 member · end-to-end encrypted',
    );
    return '$_temp0';
  }

  @override
  String get chatSubVerified => 'end-to-end encrypted · verified';

  @override
  String get chatSubReverify => 'end-to-end encrypted · re-verify';

  @override
  String get chatSubNumberChanged => 'end-to-end encrypted · number changed';

  @override
  String get chatSubEncrypted => 'end-to-end encrypted';

  @override
  String get chatLeftGroupNotice =>
      'You are no longer in this group. History stays on this device; no new messages can be sent or received.';

  @override
  String get chatRecordingHint => 'Recording… sent encrypted, like everything';

  @override
  String get chatDiscard => 'Discard';

  @override
  String get chatSendVoice => 'Send voice message';

  @override
  String get chatAttachFile => 'Attach a file';

  @override
  String get chatAttachCamera => 'Take a photo';

  @override
  String get chatAttachGallery => 'Photo or video';

  @override
  String get chatAttachFileOption => 'File';

  @override
  String get chatInputHint => 'Encrypted message…';

  @override
  String get chatReplyHint => 'Reply…';

  @override
  String get chatRecordVoice => 'Record a voice message';

  @override
  String get chatForwardedLabel => 'Forwarded';

  @override
  String get chatYouDeleted => 'You deleted this message';

  @override
  String get chatTheyDeleted => 'This message was deleted';

  @override
  String get chatFailedTapRetry => 'Failed to send — tap to retry';

  @override
  String chatRemoveReaction(String emoji) {
    return 'Remove $emoji reaction';
  }

  @override
  String chatReactWith(String emoji) {
    return 'React with $emoji';
  }

  @override
  String chatReactionChip(String emoji, int count) {
    return '$emoji $count';
  }

  @override
  String get chatReply => 'Reply';

  @override
  String get chatCopyText => 'Copy text';

  @override
  String get chatForward => 'Forward';

  @override
  String get chatEdit => 'Edit';

  @override
  String get chatDeleteForEveryone => 'Delete for everyone';

  @override
  String get chatRetrySend => 'Retry send';

  @override
  String get chatRetryFailed => 'Could not retry this message.';

  @override
  String get chatDeleteForMe => 'Delete for me';

  @override
  String get chatSomeone => 'Someone';

  @override
  String get chatThem => 'Them';

  @override
  String get chatReplyingToSelf => 'Replying to yourself';

  @override
  String get chatReplyingToThem => 'Replying to them';

  @override
  String chatReplyingTo(String name) {
    return 'Replying to $name';
  }

  @override
  String get chatCancelReply => 'Cancel reply';

  @override
  String get chatMessageUnavailable => 'Message unavailable';

  @override
  String get chatImage => 'Image';

  @override
  String get chatSaveDialogTitle => 'Save decrypted copy';

  @override
  String get chatSavedDecrypted => 'Saved (decrypted copy)';

  @override
  String chatSaveFailed(String error) {
    return 'Save failed: $error';
  }

  @override
  String get onbTagline =>
      'Zero-trust messaging.\nNo accounts. No phone number. No server storage.';

  @override
  String get ok => 'OK';

  @override
  String get stSettings => 'Settings';

  @override
  String get stProfile => 'Profile';

  @override
  String get stDisplayName => 'Display name';

  @override
  String get stDisplayNameSaved =>
      'Saved. Share a fresh contact code so new contacts see it.';

  @override
  String get stAppearance => 'Appearance';

  @override
  String get stTheme => 'Theme';

  @override
  String get stThemeSystem => 'System';

  @override
  String get stThemeLight => 'Light';

  @override
  String get stThemeDark => 'Dark';

  @override
  String get stConnection => 'Connection';

  @override
  String get stRelay => 'Relay';

  @override
  String get stRelayConnected => 'Connected — zero-knowledge link up';

  @override
  String get stRelayConnecting => 'Connecting…';

  @override
  String get stRelayOffline => 'Offline';

  @override
  String stRelayOfflineWithError(String error) {
    return 'Offline ($error)';
  }

  @override
  String get stDevices => 'Devices';

  @override
  String get stLinkedDevices => 'Linked devices';

  @override
  String get stLinkedDevicesHelp =>
      'See the devices on your account, link a new one, or revoke one you no longer use.';

  @override
  String get stNotifications => 'Notifications';

  @override
  String get stPush => 'Push notifications';

  @override
  String get stPushOnHelp =>
      'When a message waits for you while Z is closed, the relay asks Google\'s Firebase Cloud Messaging to wake this device, using a token this device gave it. The wake carries no message and no sender: Google learns that this device was woken, and when. The relay keeps the token until 30 days after this device was last online, or until you turn push off.';

  @override
  String get stPushOffHelp =>
      'Off. The relay holds no push token for this device and nothing wakes it: Z fetches your messages when you open it.';

  @override
  String get stPushOffPendingHelp =>
      'Off. The relay will be told to forget this device\'s push token the next time this device is online; until then it may still wake it.';

  @override
  String get stPushNotAllowedHelp =>
      'Notifications are not allowed for Z, so this device is not registered for push and nothing wakes it: Z fetches your messages when you open it. Allow notifications for Z in Android\'s settings to use push.';

  @override
  String get stPushNotAllowedPendingHelp =>
      'Notifications are not allowed for Z, so push is off. The relay will be told to forget this device\'s push token the next time this device is online; until then it may still wake it.';

  @override
  String get stPrivacy => 'Privacy';

  @override
  String get stReceipts => 'Delivery and read receipts';

  @override
  String get stReceiptsOnHelp =>
      'People who write to you see a second tick when their message reaches this device, and the ticks change colour once you have read it. Each receipt waits between 5 seconds and a minute, chosen at random — or, once 5 seconds have passed, goes with your next message to them — so it never leaves the moment a message arrives. This device only.';

  @override
  String get stReceiptsOffHelp =>
      'Off. This device tells nobody when their message arrives or when you read it, so they see one tick, never two, even once it has arrived. Your other devices answer for themselves.';

  @override
  String get stSecurity => 'Security';

  @override
  String get stKeystoreUnavailable => 'OS keystore unavailable';

  @override
  String get stKeystoreUnavailableHelp =>
      'The vault key is stored in a restricted file instead of the system keychain. Install/enable a keyring (e.g. GNOME Keyring / KWallet on Linux) and re-create your identity for hardware-backed protection.';

  @override
  String get stWhereMessagesLive => 'Where your messages live';

  @override
  String get stWhereMessagesLiveHelp =>
      'Only in this device\'s encrypted vault (XChaCha20-Poly1305, key in the OS keystore). The relay holds ciphertext in RAM only until delivery, never on disk.';

  @override
  String get stScreenLock => 'Screen lock';

  @override
  String stScreenLockOnHelp(String after) {
    return 'Z asks for your fingerprint, face or device PIN when it opens and after $after in the background.';
  }

  @override
  String get stScreenLockOnImmediateHelp =>
      'Z asks for your fingerprint, face or device PIN when it opens and as soon as it goes to the background.';

  @override
  String get stScreenLockOffHelp =>
      'Ask for your fingerprint, face or device PIN to open Z. Messages still arrive while it is locked.';

  @override
  String get stLockAfter => 'Lock after';

  @override
  String get lockImmediately => 'Immediately';

  @override
  String get stScreenSecurity => 'Screen security';

  @override
  String get stScreenSecurityOnHelp =>
      'Screenshots and screen recordings of Z are blocked, and the recent-apps screen shows a blank card instead of your chats.';

  @override
  String get stScreenSecurityOffHelp =>
      'Screenshots are allowed. A screenshot is a copy of the chat outside Z, in your gallery, and the recent-apps screen shows the chat you were in — even with the screen lock on.';

  @override
  String get lockPromptUnlock => 'Unlock Z';

  @override
  String get lockPromptEnableScreenLock => 'Confirm to enable screen lock';

  @override
  String get lockPromptEnableBiometric => 'Confirm to enable biometric unlock';

  @override
  String get stPassphraseOn => 'App passphrase — on';

  @override
  String get stPassphraseOff => 'App passphrase — off';

  @override
  String get stPassphraseOnHelp =>
      'This device asks for your passphrase on launch. Tap to change or remove it.';

  @override
  String get stPassphraseOffHelp =>
      'Add a passphrase that unlocks the app on this device. Combined with the device keystore; never sent anywhere.';

  @override
  String get stBiometricBound => 'Unlock with biometrics — hardware-bound';

  @override
  String get stBiometric => 'Unlock with biometrics';

  @override
  String get stBiometricLead =>
      'Open the vault with your fingerprint or face instead of typing the passphrase. ';

  @override
  String get stBiometricBoundBody =>
      'The key that opens it is sealed by this device\'s secure hardware and can only be used right after the system prompt — copying the app\'s data does not reveal it. Re-enrolling a fingerprint or face resets it.';

  @override
  String get stBiometricUnboundBody =>
      'While this is on, a key derived from your passphrase (never the passphrase itself) sits in this device\'s keystore — so on THIS device, someone who can break into the keystore no longer needs your passphrase. Turning it off deletes that key.';

  @override
  String get stBackup => 'Backup';

  @override
  String get stBackupHelp =>
      'Everything — messages, contacts, groups, attachments — encrypted with a recovery code only you hold.';

  @override
  String get stDeveloper => 'Developer';

  @override
  String get stDevMode => 'Developer mode';

  @override
  String get stDevModeHelp =>
      'Reveal the custom relay address, for a self-hosted or test relay. Off by default — Z uses its built-in relay.';

  @override
  String get stRelayAddress => 'Relay address';

  @override
  String get stRelayUrlTitle => 'Relay server URL';

  @override
  String get stConnect => 'Connect';

  @override
  String get stDangerZone => 'Danger zone';

  @override
  String get stWipe => 'Wipe everything';

  @override
  String get stWipeHelp =>
      'Destroys identity, contacts, messages and keys on this device.';

  @override
  String get stWipeFailedTitle => 'Some of it could not be deleted';

  @override
  String get stWipeFailedBody =>
      'Part of your data is still on this device, so nothing was reported as wiped. Close the app, make sure it is not running, and try again — or delete the app, which removes its files with it.';

  @override
  String get stWipeTitle => 'Wipe everything?';

  @override
  String get stWipeBody =>
      'Your identity, contacts, messages and attachments will be destroyed on this device. Without a .zid backup your identity is unrecoverable — no server has a copy.';

  @override
  String get stWipeAction => 'Wipe';

  @override
  String get stFooter =>
      'Z — zero-trust messenger\nNo accounts · No analytics · No server storage';

  @override
  String stVersion(String version) {
    return 'Version $version';
  }

  @override
  String get stUpdateTitle => 'Update available';

  @override
  String stUpdateBody(String version) {
    return 'Z $version is available. Z has no in-app updater, by design — get it from:';
  }

  @override
  String get stScreenLockOn => 'Screen lock on. Z will ask before opening.';

  @override
  String get stScreenLockUnavailable =>
      'Set up a fingerprint, face or device PIN in your system settings first.';

  @override
  String get stPromptNotCompleted =>
      'Not enabled — the prompt was not completed.';

  @override
  String get stBackupPassphraseTitle => 'Backup passphrase';

  @override
  String get stPassphraseMinLabel => 'Passphrase (12+ characters)';

  @override
  String get stRepeat => 'Repeat';

  @override
  String get stPassphraseTooShort => 'Use at least 12 characters.';

  @override
  String get stPassphraseMismatch => 'Passphrases do not match.';

  @override
  String get stEncryptAndSave => 'Encrypt & save';

  @override
  String get stBiometricOff =>
      'Biometric unlock off — the stored key was deleted.';

  @override
  String get stEnterPassphrase => 'Enter your passphrase';

  @override
  String get stBiometricOn => 'Biometric unlock on.';

  @override
  String get stIncorrectPassphrase => 'Incorrect passphrase.';

  @override
  String stCouldNotEnable(String error) {
    return 'Could not enable: $error';
  }

  @override
  String get stPassphraseSet =>
      'Passphrase set. You\'ll be asked for it next launch.';

  @override
  String get stChangePassphrase => 'Change passphrase';

  @override
  String get stRemovePassphrase => 'Remove passphrase';

  @override
  String get stEnterCurrentPassphrase => 'Enter current passphrase';

  @override
  String get stPassphraseChanged => 'Passphrase changed.';

  @override
  String get stPassphraseRemoved =>
      'Passphrase removed. The app opens automatically now.';

  @override
  String sysPqMismatch(String name) {
    return '$name\'s post-quantum key does not match the code you scanned. Their identity has not been upgraded — compare safety numbers before trusting this chat.';
  }

  @override
  String get sysSessionReset => 'Secure session was reset.';

  @override
  String get sysTtlOffYou => 'You turned off disappearing messages.';

  @override
  String sysTtlSetYou(String duration) {
    return 'You set disappearing messages to $duration.';
  }

  @override
  String sysDecryptFailed(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other:
          '$count messages could not be decrypted (session reset). Ask them to resend.',
      one:
          'A message could not be decrypted (session reset). Ask them to resend.',
    );
    return '$_temp0';
  }

  @override
  String sysTtlOffThem(String name) {
    return '$name turned off disappearing messages.';
  }

  @override
  String sysTtlSetThem(String name, String duration) {
    return '$name set disappearing messages to $duration.';
  }

  @override
  String sysGroupTtlSetYou(String duration) {
    return 'You set disappearing messages to $duration. A member whose app is older than this version keeps the messages, and theirs do not disappear.';
  }

  @override
  String sysGroupTtlSetBy(String by, String duration) {
    return '$by set disappearing messages to $duration. A member whose app is older than this version keeps the messages, and theirs do not disappear.';
  }

  @override
  String sysGroupTtlIs(String duration) {
    return 'Disappearing messages are on in this group: $duration. A member whose app is older than this version keeps the messages, and theirs do not disappear.';
  }

  @override
  String sysGroupTtlDroppedBy(String by) {
    return 'Disappearing messages are now off: $by\'s change to the group came without the group\'s timer. An app older than this version cannot carry it.';
  }

  @override
  String get sysAttachmentDiscarded =>
      'An attachment failed integrity checks and was discarded.';

  @override
  String get sysLeftYou => 'You left the group.';

  @override
  String sysCreatedYou(String name) {
    return 'You created \"$name\".';
  }

  @override
  String sysAddedYou(String names) {
    return 'You added $names.';
  }

  @override
  String sysRemovedYou(String name) {
    return 'You removed $name.';
  }

  @override
  String sysRemovedFrom(String name) {
    return 'You were removed from \"$name\".';
  }

  @override
  String sysAddedToBy(String by, String name) {
    return '$by added you to \"$name\".';
  }

  @override
  String get sysMembershipUpdated => 'Group membership updated.';

  @override
  String sysMemberLeft(String name) {
    return '$name left the group.';
  }

  @override
  String get sysAMember => 'a member';

  @override
  String get sysSomeone => 'Someone';

  @override
  String get sysUnknownMemberLeft => 'A member left the group.';

  @override
  String ktBannerHeld(String name) {
    return '$name\'s newest device list is not in the transparency log. The devices only that list added are not receiving your messages until it is.';
  }

  @override
  String ktBannerConflict(String name) {
    return 'The transparency log and $name\'s devices disagree about their device list. Your messages to them are held until they agree, or until you choose to send anyway.';
  }

  @override
  String ktBannerGroupHeld(String names, int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other:
          'Messages to $names are held: the transparency log disagrees with their device lists, so this message has not reached them.',
      one:
          'Messages to $names are held: the transparency log disagrees with their device list, so this message has not reached them.',
    );
    return '$_temp0';
  }

  @override
  String get ktSendAnyway => 'Send anyway';

  @override
  String get ktComposerHeld =>
      'Messages to this contact are held — see the notice above.';

  @override
  String homeKtOwnAlert(int v) {
    return 'A device list you did not issue has been published to the transparency log for your account (version $v). Check your linked devices now.';
  }

  @override
  String homeKtFault(String reason) {
    return 'The transparency log has shown two different histories: $reason. Nothing new is being confirmed. Settings › Transparency log has the details.';
  }

  @override
  String homeKtUnreachable(String when) {
    return 'The transparency log has not been reachable since $when. Device lists are being checked by your contacts\' devices alone in the meantime.';
  }

  @override
  String homeOwnOlderList(int sent, int held) {
    return 'Your main device published an older device list (v$sent) than this device already holds (v$held). The newer list was signed by another device holding your account key. If that wasn\'t you, reset your identity now.';
  }

  @override
  String get homeOwnUnissued =>
      'A contact was given a device list for your account that this device never issued. A device holding your account key may have enrolled another device. If that wasn\'t you, reset your identity now.';

  @override
  String homeRemovedDevice(int v) {
    return 'This device was removed from your account (device list v$v). If you did not do this, your account key may be compromised — reset your identity.';
  }

  @override
  String get ciKtTitle => 'Transparency log';

  @override
  String ciKtConfirmed(int v) {
    return 'Confirmed: their device list (version $v) is the one in the log.';
  }

  @override
  String get ciKtUnlogged =>
      'Not in the log. This account has never published a device list — an older app, or one that has not been online since updating.';

  @override
  String ciKtUnconfirmed(int held, int log) {
    return 'Their newest device list (version $held) is not in the log yet; the log has version $log.';
  }

  @override
  String ciKtConflict(int v) {
    return 'The log holds a different device list at version $v than their devices sent. Messages to them are held.';
  }

  @override
  String get ciKtOff => 'No transparency log is configured on this device.';

  @override
  String get ciKtUnchecked => 'Not checked yet.';

  @override
  String get stTransparency => 'Transparency log';

  @override
  String get stKtStatus => 'Status';

  @override
  String get stKtHealthOff => 'Not configured';

  @override
  String get stKtHealthUnknown => 'Not checked yet';

  @override
  String stKtHealthOk(String when, int n) {
    return 'Verified $when — $n entries';
  }

  @override
  String stKtHealthUnreachable(String when) {
    return 'Unreachable since $when';
  }

  @override
  String stKtHealthFault(String reason) {
    return 'Fault: $reason';
  }

  @override
  String get stKtCheckNow => 'Check now';

  @override
  String get stKtChecked => 'Checked.';

  @override
  String get stKtLogAddress => 'Log address';

  @override
  String get stKtLogUrlTitle => 'Transparency log URL';

  @override
  String get stKtLogKey => 'Log public key';

  @override
  String get stKtLogKeyTitle => 'Log public key (base64)';

  @override
  String get stKtWitness => 'Witness';

  @override
  String get stKtWitnessTitle => 'Witness record URL';

  @override
  String get stKtWitnessEdit => 'Witness';

  @override
  String get stKtWitnessHelp =>
      'A witness is an address and the key you pin for it. Both, or neither — an address alone would let whoever answers it co-sign with a key you never chose.';

  @override
  String get stKtWitnessNeedsKey =>
      'That address needs a key. Without one, whoever answers it agrees with the log using a key you never pinned, and the check means nothing.';

  @override
  String get stKtWitnessNeedsUrl =>
      'That key needs an address. On its own it is never used.';

  @override
  String get stKtWitnessBadKey =>
      'A witness key is 32 bytes, written in base64.';

  @override
  String get stKtWitnessKeyTitle => 'Witness public key (base64)';

  @override
  String get stKtNone => 'none';

  @override
  String get stKtReset => 'Forget the log\'s history';

  @override
  String get stKtResetHelp =>
      'Start again from the log\'s current head. Only after changing logs deliberately, or once a fault has been reported.';

  @override
  String get stKtResetConfirm => 'Forget the log\'s history?';

  @override
  String get stDevlistSigning => 'Device-list signing';

  @override
  String get stDevlistDual =>
      'Dual-signed, so every app can read it. Its post-quantum signature covers which devices are on it, not their keys.';

  @override
  String get stDevlistMoved =>
      'Signed v2-only. Its post-quantum signature and fingerprint cover every device\'s keys.';

  @override
  String stDevlistContactsBehind(int count) {
    return 'Contacts\' devices not yet capable: $count';
  }

  @override
  String stDevlistOwnBehind(int count) {
    return 'Your other devices not yet capable: $count';
  }

  @override
  String get stDevlistWaiting => 'Moves to v2-only by itself when both are 0.';

  @override
  String get stDevlistMoving => 'Moving to v2-only now.';

  @override
  String get stDevlistNeedsBoth =>
      'Moves once this account has a linked device and a contact, and every one of them is capable.';

  @override
  String get stDevlistSwitchedOff => 'Moving is switched off in this build.';

  @override
  String get stDevlistRootDecides => 'Your main device decides when to move.';

  @override
  String get stKtSave => 'Save';

  @override
  String get stCryptoBench => 'Cryptography benchmark';

  @override
  String get stCryptoBenchHelp => 'Time every primitive Z uses, on this device';

  @override
  String cbRunning(int n) {
    return 'Measuring… $n done';
  }

  @override
  String cbDone(int n) {
    return 'Done — $n measurements';
  }

  @override
  String get cbNote =>
      'Every line is pure Dart: the app wires in no platform implementation. The Argon2id line is what a passphrase unlock costs here. Medians; the phone\'s clock and thermal state move them.';

  @override
  String get cbCopy => 'Copy as table';

  @override
  String get cbCopied => 'Copied';

  @override
  String get cbAgain => 'Run again';

  @override
  String get addConnect => 'CONNECT';

  @override
  String get connectIntro =>
      'For someone you cannot stand next to. Send them a one-time invite over any channel — even one you do not trust — then compare eight digits to prove nobody was in the middle.';

  @override
  String get connectCreate => 'Create an invite';

  @override
  String get connectOpenTitle => 'Open an invite';

  @override
  String get connectOpenField => 'Invite link or code';

  @override
  String get connectOpen => 'Open';

  @override
  String get connectShareLink => 'Copy link';

  @override
  String get connectShareCode => 'Copy code';

  @override
  String get connectCopied => 'Copied';

  @override
  String get connectLinkLabel => 'Link';

  @override
  String get connectCodeLabel => 'Code';

  @override
  String get connectSameSecret =>
      'The link and the code are the same invite. Send whichever suits the channel.';

  @override
  String get connectOneTime => 'Works once, and expires after 24 hours.';

  @override
  String get connectPending => 'Waiting for them to open it';

  @override
  String get connectPendingOpened => 'Waiting for them';

  @override
  String get connectExpired => 'Expired';

  @override
  String get connectAborted => 'Refused';

  @override
  String get connectDiscard => 'Discard';

  @override
  String get connectCheck => 'Check now';

  @override
  String connectLastFailure(String reason) {
    return 'Could not reach the relay — will keep trying. ($reason)';
  }

  @override
  String get connectNoInvites => 'No invites waiting.';

  @override
  String get connectConfirmTitle => 'Compare these digits';

  @override
  String connectWhoAccepted(String name) {
    return '$name took your invite. Whoever had the link could have taken it — so if this is not who you meant to reach, stop below instead of adding them.';
  }

  @override
  String get connectGroupNotice =>
      'This invite also adds you to a group. You will see which one once you are connected, and you can leave it whenever you like.';

  @override
  String connectGroupLinkGoAhead(String group) {
    return 'This link is for \"$group\": if you go ahead, they join the group as soon as they go ahead on their side too.';
  }

  @override
  String connectGroupLinkTooOld(String group) {
    return 'Their app is too old to join a group from a link. If you go ahead they will be a contact only — add them to \"$group\" by hand.';
  }

  @override
  String connectGroupLinkNotAdmin(String group) {
    return 'You can no longer add members to \"$group\", so if you go ahead they will be a contact only.';
  }

  @override
  String connectGroupLinkLabel(String group) {
    return 'Group link: \"$group\"';
  }

  @override
  String get connectJoinGroup => 'Also join the group';

  @override
  String connectJoinGroupOff(String name) {
    return 'You will be $name\'s contact only, and $name will be told you chose not to join.';
  }

  @override
  String connectGroupLinkExpired(String group) {
    return 'This link\'s 24 hours are over: if you go ahead they will be a contact only, not added to \"$group\".';
  }

  @override
  String connectAlreadyContact(String name) {
    return '$name was already your contact, and nothing about them changed.';
  }

  @override
  String connectAlreadyContactJoining(String name) {
    return '$name was already your contact, and nothing about them changed. You join the group once $name\'s device adds you.';
  }

  @override
  String get connectLinkWaitsTitle => 'Waiting to join your groups';

  @override
  String connectLinkWait(String name, String group) {
    return '$name, to \"$group\"';
  }

  @override
  String get connectLinkWaitStop => 'Stop waiting';

  @override
  String connectLinkWaitTooLate(String name, String group) {
    return 'Too late to stop: $name had already said yes, and is being added to \"$group\".';
  }

  @override
  String connectConfirmBody(Object name) {
    return 'Read these eight digits to $name on a call, or in person. They must see exactly the same. If they do, nobody is in the middle — not the relay, not the network, not whoever could see the message that carried the invite.';
  }

  @override
  String get connectMatch => 'They match';

  @override
  String get connectNotYet => 'We have not compared yet';

  @override
  String get connectMismatch => 'They do not match';

  @override
  String connectAdded(Object name) {
    return '$name added and verified';
  }

  @override
  String connectAddedUnverified(Object name) {
    return '$name added, but not verified';
  }

  @override
  String get connectUnverifiedNote =>
      'Nobody compared the digits, so this contact is unverified. Compare safety numbers from their chat whenever you can.';

  @override
  String get connectStopped => 'Stopped. Nothing was added.';

  @override
  String get connectMismatchWarning =>
      'If the digits differ, someone is relaying between you. Do not try the same invite again — make a new one and send it another way.';

  @override
  String get connectPendingTitle => 'Invites in flight';

  @override
  String alertDlConflict(String name) {
    return '$name\'s devices disagree about their device list. One of them may not be theirs — check with them before continuing.';
  }

  @override
  String alertDlRollback(String name) {
    return '$name\'s device list went backwards a version. One of their devices may be replaying an old list — check with them.';
  }

  @override
  String alertDlUnconfirmed(String name) {
    return '$name\'s devices don\'t confirm the device list this device was given. One of their devices may not be theirs — check with them before continuing.';
  }

  @override
  String alertDlMissingUpdate(String name) {
    return '$name\'s device list changed but the update never arrived. Their new device could not be verified.';
  }

  @override
  String alertDlPqMissing(String name) {
    return '$name\'s app says it sent the post-quantum signature for its device list, and it has not arrived. Their device list is still verified classically, which works today but is what a future quantum adversary could forge. Something on the network may be removing it.';
  }

  @override
  String alertDlShared(String name, String other) {
    return '$name\'s device list names a device that $other\'s list also names, so it was not used. A device belongs to one account, and Z cannot tell which of them is right — check with both of them.';
  }

  @override
  String alertDlSharedAnother(String name) {
    return '$name\'s device list names a device that another account\'s list also named, so it was not used. A device belongs to one account — check with them.';
  }

  @override
  String alertDlSharedMine(String name) {
    return '$name\'s device list names one of your own devices, so it was not used. A device belongs to one account — check with them.';
  }

  @override
  String alertDlClaimed(String name, String other) {
    return '$name\'s device list names a device that has proved it belongs to $other\'s account, so $name\'s list is not used. A device belongs to one account — ask $name about it.';
  }

  @override
  String alertDlClaimedAnother(String name) {
    return '$name\'s device list names a device that has proved it belongs to another account, so $name\'s list is not used. A device belongs to one account — ask $name about it.';
  }

  @override
  String get relayInsecureTitle => 'This relay is not using TLS';

  @override
  String relayInsecureBody(String url) {
    return '$url is a plain ws:// address, so anyone on the network between you and it can see which mailbox you are collecting from and how often — the pattern of who you talk to, though never what you say. Message contents stay end-to-end encrypted whatever the transport. Use wss:// for any relay that is not on your own network.';
  }

  @override
  String get relayInsecureUseAnyway => 'Connect anyway';

  @override
  String connectExpiresHours(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count hours left',
      one: '1 hour left',
    );
    return '$_temp0';
  }

  @override
  String connectExpiresMinutes(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count minutes left',
      one: '1 minute left',
    );
    return '$_temp0';
  }

  @override
  String get connectExpiresSoon => 'Less than a minute left';

  @override
  String get connectQrLabel => 'As a QR code';

  @override
  String get connectShareSheet => 'Share';

  @override
  String get connectSharedToClipboard =>
      'No share sheet here — the link is on the clipboard instead.';

  @override
  String get connectHeldStatus => 'Opened from a link — nothing sent yet';

  @override
  String get connectHeldBody =>
      'Connecting sends your contact code to whoever made this invite, and then the two of you compare eight digits. If you were not expecting an invite, discard it.';

  @override
  String get connectHeldGo => 'Connect';

  @override
  String get connectOldInvite =>
      'This invite was made by an older version of Z. Until you compare the digits, even the relay could be in the middle.';

  @override
  String get requestsTitle => 'Requests';

  @override
  String requestsBanner(int count) {
    String _temp0 = intl.Intl.pluralLogic(
      count,
      locale: localeName,
      other: '$count people want to connect',
      one: '1 person wants to connect',
    );
    return '$_temp0';
  }

  @override
  String get requestsWantsToConnect => 'Wants to connect';

  @override
  String get requestsNote =>
      'Accepting adds them to your chats. It does not confirm who they are — compare safety numbers for that.';

  @override
  String get requestsEmpty => 'No requests right now';

  @override
  String get requestAccept => 'Accept';

  @override
  String get requestDecline => 'Decline';

  @override
  String get requestBlock => 'Block';

  @override
  String get chatRequested => 'Requested';

  @override
  String get videoNoPlayback =>
      'This video can\'t be played here — save it and open it in another app.';

  @override
  String get chatPlayVideo => 'Play video';

  @override
  String get chatPauseVideo => 'Pause video';

  @override
  String get chatVideo => 'Video';

  @override
  String sysRenamedYou(String name) {
    return 'You renamed the group to \"$name\".';
  }

  @override
  String sysRenamedBy(String by, String name) {
    return '$by renamed the group to \"$name\".';
  }

  @override
  String get grpRename => 'Rename group';

  @override
  String sysPromotedYou(String name) {
    return 'You made $name an admin.';
  }

  @override
  String sysDemotedYou(String name) {
    return 'You removed $name as an admin.';
  }

  @override
  String sysTransferredYou(String name) {
    return 'You made $name the owner.';
  }

  @override
  String sysPromotedBy(String by, String name) {
    return '$by made $name an admin.';
  }

  @override
  String sysPromotedMeBy(String by) {
    return '$by made you an admin.';
  }

  @override
  String sysDemotedBy(String by, String name) {
    return '$by removed $name as an admin.';
  }

  @override
  String sysDemotedMeBy(String by) {
    return '$by removed you as an admin.';
  }

  @override
  String sysOwnerBy(String by, String name) {
    return '$by made $name the owner.';
  }

  @override
  String sysOwnerMeBy(String by) {
    return '$by made you the owner.';
  }

  @override
  String sysSteppedDown(String name) {
    return '$name is no longer an admin.';
  }

  @override
  String sysChangeOverriddenBy(String by) {
    return '$by\'s change to the group replaced yours, which did not stand. Make it again if you still want it.';
  }

  @override
  String get sysChangeOverriddenMine =>
      'A change made on your other device at the same moment replaced this one, which did not stand. Make it again if you still want it.';

  @override
  String sysAddedFromLinkBy(String by, String name) {
    return '$by added you to \"$name\" from the link you opened.';
  }

  @override
  String sysLinkJoined(String name) {
    return '$name joined from your invite link.';
  }

  @override
  String sysLinkTooOld(String name) {
    return '$name is your contact, but was not added to this group: their app is too old to join from a link. Add them by hand.';
  }

  @override
  String sysLinkExpired(String name) {
    return '$name is your contact, but was not added to this group: their go-ahead did not reach you within the invite link\'s 24 hours. Add them by hand if you still want them here.';
  }

  @override
  String sysLinkRefused(String name) {
    return '$name is your contact, but was not added to this group: you can no longer add members to it.';
  }

  @override
  String sysLinkDeclined(String name) {
    return '$name is your contact, and chose not to join this group.';
  }

  @override
  String sysLinkCancelled(String name) {
    return 'You stopped waiting for $name to join from your invite link. They are still your contact.';
  }

  @override
  String get grpYouOwner => 'You (owner)';

  @override
  String get grpOwner => 'owner';

  @override
  String get grpChangeRole => 'Change role';

  @override
  String get grpMakeAdmin => 'Make admin';

  @override
  String get grpRemoveAdmin => 'Remove as admin';

  @override
  String get grpMakeOwner => 'Make owner';

  @override
  String grpTransferTitle(String name) {
    return 'Make $name the owner?';
  }

  @override
  String grpTransferBody(String name) {
    return '$name will be the only person who can change who the admins are. You cannot take this back — only the new owner can give it back to you.';
  }

  @override
  String get grpTransferKeepAdmin => 'Stay on as an admin';

  @override
  String get grpLeaveOwnerTitle => 'You own this group';

  @override
  String get grpLeaveOwnerBody =>
      'If you leave now, nobody will be able to change who the admins are. The admins can still add, remove and rename. Make someone else the owner first?';

  @override
  String get grpLeaveAnyway => 'Leave anyway';

  @override
  String get grpTransferFirst => 'Transfer ownership';

  @override
  String get grpPickNewOwner => 'New owner';

  @override
  String get grpRolesOnMainDevice =>
      'Admins and ownership can only be changed on your main device.';

  @override
  String get grpAdminNotMember => 'admin, no longer in the group';

  @override
  String get grpLeaveOwnerBodyLinked =>
      'If you leave now, nobody will be able to change who the admins are. The admins can still add, remove and rename. To hand the group on first, use your main device.';

  @override
  String grpTransferOldBuild(String name) {
    return 'If $name still has a version of Z from before group admins, nobody will be able to change who the admins are until they update.';
  }

  @override
  String get grpInviteByLink => 'Invite to group by link';

  @override
  String get grpInviteByLinkNote =>
      'Works once, for 24 hours. Whoever opens it first becomes your contact, and joins this group once they agree. The link itself says nothing about the group.';

  @override
  String get grpTtlAdminsOnly => 'Only an admin can change this.';

  @override
  String get grpTtlOldBuild =>
      'A member whose app is older than this version keeps the messages, and theirs do not disappear.';

  @override
  String get stHandleSection => 'Handle';

  @override
  String get hdlYourHandle => 'Your handle';

  @override
  String get hdlRowUnavailable => 'Not available in this version';

  @override
  String get hdlRowLinked => 'Held by your main device';

  @override
  String get hdlRowNone => 'None. People add you with your code or an invite';

  @override
  String hdlRowPending(String handle) {
    return '@$handle, waiting to be published';
  }

  @override
  String hdlRowHeld(String handle) {
    return '@$handle, not published';
  }

  @override
  String hdlRowPaused(String handle) {
    return '@$handle, paused';
  }

  @override
  String hdlRowTaken(String handle) {
    return '@$handle, taken by someone else';
  }

  @override
  String hdlRowLost(String handle) {
    return '@$handle, held by another key';
  }

  @override
  String get stHdlLogAddress => 'Handle service address';

  @override
  String get stHdlLogKey => 'Handle service key';

  @override
  String get stHdlLogUrlTitle => 'Handle service URL';

  @override
  String get stHdlLogKeyTitle => 'Handle service public key (base64)';

  @override
  String get hdlTitle => 'Your handle';

  @override
  String get hdlUnavailable =>
      'Handles are not available yet. This version of Z has no handle service set up, so you cannot claim a handle or find anyone by one.';

  @override
  String get hdlLinkedDevice =>
      'Only your main device can hold a handle. Claim or manage it there; the people you meet through it appear here too.';

  @override
  String get hdlIntro =>
      'A handle is a name people can find you by, like @alex.42. It is optional, and you can pause it or give it up later.';

  @override
  String get hdlWhatItShows =>
      'Anyone can look a handle up and send it a request. Requests go to an inbox of the handle\'s own, not to your account, and you decide whether to accept each one. A handle is public: anyone can learn that it exists, and the people who run the handle service and the relay can see your device\'s internet address when you claim, check or use it.';

  @override
  String get hdlClaim => 'Claim a handle';

  @override
  String get hdlRecover => 'Recover a handle';

  @override
  String get hdlNickLabel => 'Name';

  @override
  String get hdlNickHelp =>
      '3 to 20 letters, digits or _, starting with a letter';

  @override
  String get hdlDigitsRandom => 'Random digits';

  @override
  String get hdlDigitsChoose => 'Choose digits';

  @override
  String get hdlDigitsLabel => 'Digits (2 to 6)';

  @override
  String get hdlCheck => 'Check';

  @override
  String hdlAvailable(String handle) {
    return '@$handle is free.';
  }

  @override
  String hdlTaken(String handle) {
    return '@$handle is taken.';
  }

  @override
  String get hdlNoneFree =>
      'Every random choice was taken. Try again, or choose the digits.';

  @override
  String get hdlTryOtherDigits => 'Try other digits';

  @override
  String hdlClaimThis(String handle) {
    return 'Claim @$handle';
  }

  @override
  String get hdlCodeTitle => 'Your handle\'s recovery code';

  @override
  String hdlCodeBody(String handle) {
    return 'Write this down and keep it somewhere safe. It is shown once and Z does not keep it. It is the only way to get @$handle back if you lose this device, and anyone who has it can take the handle, so keep it private.';
  }

  @override
  String get hdlSemCode => 'Recovery code';

  @override
  String get hdlCodeWritten => 'I have written it down';

  @override
  String get hdlCodeConfirmTitle => 'Type the code back';

  @override
  String get hdlCodeConfirmBody =>
      'This makes sure it was written down correctly. Nothing is published until you do.';

  @override
  String get hdlCodeLabel => 'Recovery code';

  @override
  String get hdlCodeWrong => 'That is not the code that was shown.';

  @override
  String hdlPendingBody(String handle, int minutes) {
    String _temp0 = intl.Intl.pluralLogic(
      minutes,
      locale: localeName,
      other: '@$handle will be published in about $minutes minutes.',
      one: '@$handle will be published in about a minute.',
      zero: '@$handle will be published in a moment.',
    );
    return '$_temp0';
  }

  @override
  String get hdlPendingWhy =>
      'It is published later on purpose, at a random moment, so that the time you claimed it cannot be matched with anything else you did in Z. Keep Z open until then.';

  @override
  String get hdlCancelClaim => 'Cancel claim';

  @override
  String get hdlHeldBody =>
      'This claim was waiting to be published when the backup you restored was made. It has not been published from this device.';

  @override
  String get hdlPublishNow => 'Publish now';

  @override
  String hdlTakenBody(String handle) {
    return 'Someone else claimed @$handle before your claim was published. Nothing was published for you.';
  }

  @override
  String get hdlChooseOther => 'Choose other digits';

  @override
  String get hdlDismiss => 'Dismiss';

  @override
  String get hdlLiveBody =>
      'Taking requests. Each request costs the sender some work, so they cannot be sent in bulk.';

  @override
  String get hdlNotVerification =>
      'A handle is not a verification: whoever you meet through it, compare safety numbers to be sure who they are.';

  @override
  String get hdlRelayUnguarded =>
      'Your relay is too old to protect the handle\'s inbox: requests reach it without any work.';

  @override
  String get hdlIntroUnknown =>
      'The handle\'s inbox was changed on another device after the backup you restored. Choose New inbox to take requests here.';

  @override
  String get hdlCopy => 'Copy handle';

  @override
  String get hdlCopied => 'Handle copied';

  @override
  String hdlSemHandle(String handle) {
    return 'Your handle, @$handle';
  }

  @override
  String get hdlPause => 'Pause';

  @override
  String get hdlPauseHelp =>
      'Stop taking requests. People who look it up are told it is paused.';

  @override
  String get hdlResume => 'Resume';

  @override
  String get hdlPausedBody =>
      'Paused: people who look it up are told so, and cannot send requests.';

  @override
  String get hdlRotate => 'New inbox';

  @override
  String get hdlRotateHelp =>
      'Give the handle a new inbox, to end a wave of unwanted requests. The handle stays the same, and requests already waiting stay.';

  @override
  String get hdlDifficulty => 'Work per request';

  @override
  String get hdlDifficultyHelp =>
      'How much work a request costs whoever sends it. More stops more spam and makes everyone who asks wait longer.';

  @override
  String get hdlPow16 => 'Lowest: a fraction of a second';

  @override
  String get hdlPow18 => 'Low: under a second';

  @override
  String get hdlPow20 => 'Normal: about a second, a few on a slow phone';

  @override
  String get hdlPow22 => 'High: several seconds';

  @override
  String get hdlPow24 => 'Highest: up to a minute on a slow phone';

  @override
  String get hdlRetire => 'Give up handle';

  @override
  String hdlRetireConfirmTitle(String handle) {
    return 'Give up @$handle?';
  }

  @override
  String get hdlRetireConfirmBody =>
      'Nobody will be able to reach you through it, and this device forgets its keys. The name stays in the public log and nobody else can claim it; only its recovery code can bring it back.';

  @override
  String hdlLostBody(String handle) {
    return '@$handle is now held by another key: its recovery code was used. This device can no longer change it.';
  }

  @override
  String get hdlForget => 'Forget it';

  @override
  String get hdlRecoverTitle => 'Recover a handle';

  @override
  String get hdlRecoverBody =>
      'Enter the handle and its recovery code. The handle moves to this account with new keys, and you get a new code.';

  @override
  String get hdlHandleLabel => 'Handle';

  @override
  String get hdlRecoverAction => 'Recover';

  @override
  String hdlRecovered(String handle) {
    return '@$handle is yours again.';
  }

  @override
  String get hdlBadEmpty => 'Type a handle, like alex.42.';

  @override
  String hdlBadCharacter(String char) {
    return '“$char” cannot be in a handle. Use a to z, 0 to 9 and _.';
  }

  @override
  String get hdlBadMissingDigits => 'Add the digits after a dot, like alex.42.';

  @override
  String get hdlBadDigitsNotDigits => 'Only digits go after the dot.';

  @override
  String get hdlBadReserved => 'That name is reserved.';

  @override
  String get hdlBadNickShort => 'The name needs at least 3 characters.';

  @override
  String get hdlBadNickLong => 'The name can have at most 20 characters.';

  @override
  String get hdlBadNickStart => 'The name must start with a letter.';

  @override
  String get hdlBadNickDoubleUnderscore =>
      'The name cannot have two _ in a row.';

  @override
  String get hdlBadNickEndUnderscore => 'The name cannot end with _.';

  @override
  String get hdlBadDigitsShort => 'A handle has at least 2 digits.';

  @override
  String get hdlBadDigitsLong => 'A handle has at most 6 digits.';

  @override
  String get hdlErrUnreachable =>
      'Could not reach the handle service. Try again later.';

  @override
  String get hdlErrBadAnswer =>
      'The handle service\'s answer did not check out, so nothing it said was used.';

  @override
  String get hdlErrRefused => 'The handle service refused that.';

  @override
  String get hdlErrTaken => 'Someone else holds that handle.';

  @override
  String get hdlErrChanged =>
      'The handle changed while you were doing that. Try again.';

  @override
  String get hdlErrLost => 'That handle is held by another key now.';

  @override
  String get hdlErrNotConnected =>
      'Not connected to the relay. Try again when you are online.';

  @override
  String get hdlErrPowRefused =>
      'The relay did not accept the request\'s proof of work. Nothing was delivered; try again later.';

  @override
  String get hdlErrRelayRefused => 'The relay refused the request.';

  @override
  String get hdlErrPaused => 'That handle is paused, so nothing was sent.';

  @override
  String get hdlErrNotClaimed => 'Nobody holds that handle.';

  @override
  String get hdlErrWrongCode => 'That code does not recover this handle.';

  @override
  String get hdlErrBadCode =>
      'That is not a recovery code. Check it and try again.';

  @override
  String get hdlErrBackupCode =>
      'That is a backup recovery code. A handle has a code of its own, starting ZHR.';

  @override
  String get hdlErrAlreadyHasOne => 'This account already has a handle.';

  @override
  String get hdlErrNoHandle => 'There is no handle here to change.';

  @override
  String get addHandle => 'Handle';

  @override
  String get hdlFindHelp =>
      'If someone told you their handle, find them here and send a request. They decide whether to accept.';

  @override
  String get hdlFindLabel => 'Their handle';

  @override
  String get hdlFindHint => '@alex.42';

  @override
  String get hdlFind => 'Find';

  @override
  String get hdlLookingUp => 'Looking it up…';

  @override
  String hdlFound(String handle) {
    return 'Found @$handle.';
  }

  @override
  String get hdlFoundNote =>
      'A handle is not a verification. If they accept, compare safety numbers to be sure who they are.';

  @override
  String get hdlSendRequest => 'Send request';

  @override
  String get hdlSending => 'Sending. This takes a few seconds on purpose…';

  @override
  String hdlRequestSent(String handle) {
    return 'Request sent to @$handle. If they accept, they will appear in your chats.';
  }

  @override
  String hdlNotFound(String handle) {
    return 'Nobody has claimed @$handle.';
  }

  @override
  String hdlFoundPaused(String handle) {
    return '@$handle is paused: its owner is not taking requests right now.';
  }

  @override
  String hdlFoundInvalid(String handle) {
    return 'The handle service\'s answer for @$handle did not check out. Nothing was sent.';
  }

  @override
  String get hdlFoundOwn => 'That is your own handle.';

  @override
  String hdlSemFound(String handle) {
    return 'Handle @$handle';
  }

  @override
  String get hdlWaiting => 'Waiting for an answer';

  @override
  String get hdlForgetRequest => 'Forget';

  @override
  String requestsVia(String handle) {
    return 'Via @$handle';
  }

  @override
  String sysHandleAccepted(String handle) {
    return '@$handle accepted. Compare safety numbers to verify.';
  }
}
