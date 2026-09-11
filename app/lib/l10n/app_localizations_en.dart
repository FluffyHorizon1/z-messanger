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
      'Their device list is signed post-quantum too, so the set of devices you send to cannot be forged or quietly reduced.';

  @override
  String get ciDevListClassical =>
      'Their device list is signed classically only. That is correct today; the post-quantum signature for it travels separately and may not have arrived yet.';

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
  String get ciDeleteContact => 'Delete contact & all messages';

  @override
  String get ciDeleteTitle => 'Delete everything?';

  @override
  String get ciDeleteBody =>
      'This wipes the contact, every message and every attachment from THIS device. There is no server copy to restore from — that is the point.';

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
  String get stPushHelp =>
      'Wake this device when a message arrives while Z is closed. The alert is content-free — messages are fetched and decrypted only on your device, never inside the notification.';

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
  String get stKtWitness => 'Witness address';

  @override
  String get stKtWitnessTitle => 'Witness record URL';

  @override
  String get stKtWitnessKey => 'Witness public key';

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
}
