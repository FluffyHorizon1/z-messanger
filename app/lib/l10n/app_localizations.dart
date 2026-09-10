import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:intl/intl.dart' as intl;

import 'app_localizations_en.dart';

// ignore_for_file: type=lint

/// Callers can lookup localized strings with an instance of AppLocalizations
/// returned by `AppLocalizations.of(context)`.
///
/// Applications need to include `AppLocalizations.delegate()` in their app's
/// `localizationDelegates` list, and the locales they support in the app's
/// `supportedLocales` list. For example:
///
/// ```dart
/// import 'l10n/app_localizations.dart';
///
/// return MaterialApp(
///   localizationsDelegates: AppLocalizations.localizationsDelegates,
///   supportedLocales: AppLocalizations.supportedLocales,
///   home: MyApplicationHome(),
/// );
/// ```
///
/// ## Update pubspec.yaml
///
/// Please make sure to update your pubspec.yaml to include the following
/// packages:
///
/// ```yaml
/// dependencies:
///   # Internationalization support.
///   flutter_localizations:
///     sdk: flutter
///   intl: any # Use the pinned version from flutter_localizations
///
///   # Rest of dependencies
/// ```
///
/// ## iOS Applications
///
/// iOS applications define key application metadata, including supported
/// locales, in an Info.plist file that is built into the application bundle.
/// To configure the locales supported by your app, you’ll need to edit this
/// file.
///
/// First, open your project’s ios/Runner.xcworkspace Xcode workspace file.
/// Then, in the Project Navigator, open the Info.plist file under the Runner
/// project’s Runner folder.
///
/// Next, select the Information Property List item, select Add Item from the
/// Editor menu, then select Localizations from the pop-up menu.
///
/// Select and expand the newly-created Localizations item then, for each
/// locale your application supports, add a new item and select the locale
/// you wish to add from the pop-up menu in the Value field. This list should
/// be consistent with the languages listed in the AppLocalizations.supportedLocales
/// property.
abstract class AppLocalizations {
  AppLocalizations(String locale)
      : localeName = intl.Intl.canonicalizedLocale(locale.toString());

  final String localeName;

  static AppLocalizations of(BuildContext context) {
    return Localizations.of<AppLocalizations>(context, AppLocalizations)!;
  }

  static const LocalizationsDelegate<AppLocalizations> delegate =
      _AppLocalizationsDelegate();

  /// A list of this localizations delegate along with the default localizations
  /// delegates.
  ///
  /// Returns a list of localizations delegates containing this delegate along with
  /// GlobalMaterialLocalizations.delegate, GlobalCupertinoLocalizations.delegate,
  /// and GlobalWidgetsLocalizations.delegate.
  ///
  /// Additional delegates can be added by appending to this list in
  /// MaterialApp. This list does not have to be used at all if a custom list
  /// of delegates is preferred or required.
  static const List<LocalizationsDelegate<dynamic>> localizationsDelegates =
      <LocalizationsDelegate<dynamic>>[
    delegate,
    GlobalMaterialLocalizations.delegate,
    GlobalCupertinoLocalizations.delegate,
    GlobalWidgetsLocalizations.delegate,
  ];

  /// A list of this localizations delegate's supported locales.
  static const List<Locale> supportedLocales = <Locale>[Locale('en')];

  /// Button that submits the typed passphrase on the unlock screen.
  ///
  /// In en, this message translates to:
  /// **'Unlock'**
  String get unlockTitle;

  /// Label on the passphrase field.
  ///
  /// In en, this message translates to:
  /// **'Passphrase'**
  String get unlockPassphraseLabel;

  /// Instruction shown above the passphrase field.
  ///
  /// In en, this message translates to:
  /// **'Enter your passphrase to unlock this device.'**
  String get unlockPrompt;

  /// Screen-reader label for the reveal control. Says what it DOES, not what the icon looks like.
  ///
  /// In en, this message translates to:
  /// **'Show passphrase'**
  String get unlockShowPassphrase;

  /// Screen-reader label for the same control once the passphrase is visible.
  ///
  /// In en, this message translates to:
  /// **'Hide passphrase'**
  String get unlockHidePassphrase;

  /// Offers the biometric path instead of typing.
  ///
  /// In en, this message translates to:
  /// **'Use fingerprint / face'**
  String get unlockUseBiometrics;

  /// The honest note under the field. 'THIS device' is emphasised deliberately: users assume a passphrase is checked by a server, and it is not. Keep that emphasis when translating.
  ///
  /// In en, this message translates to:
  /// **'Your passphrase unlocks the encrypted vault on THIS device only. It is never sent anywhere, and there is no way to recover it — if you forget it, restore your identity from a .zid backup.'**
  String get unlockFootnote;

  /// Heading on the screen shown when the app is locked.
  ///
  /// In en, this message translates to:
  /// **'Locked'**
  String get lockedTitle;

  /// Retries the biometric prompt.
  ///
  /// In en, this message translates to:
  /// **'Unlock'**
  String get lockUnlock;

  /// Shown while the OS biometric prompt is up.
  ///
  /// In en, this message translates to:
  /// **'Waiting…'**
  String get lockWaiting;

  /// Reveals the passphrase fallback. Only shown when the vault has a passphrase.
  ///
  /// In en, this message translates to:
  /// **'Use passphrase instead'**
  String get lockUsePassphraseInstead;

  /// Submits the passphrase fallback.
  ///
  /// In en, this message translates to:
  /// **'Unlock with passphrase'**
  String get lockUnlockWithPassphrase;

  /// The user dismissed the OS prompt.
  ///
  /// In en, this message translates to:
  /// **'Unlock cancelled.'**
  String get lockCancelled;

  /// The biometric attempt failed for a reason other than cancellation.
  ///
  /// In en, this message translates to:
  /// **'Could not verify. Try again, or use your passphrase.'**
  String get lockCouldNotVerify;

  /// The typed passphrase did not open the vault.
  ///
  /// In en, this message translates to:
  /// **'Incorrect passphrase. Try again.'**
  String get lockIncorrectPassphrase;

  /// Shown when the device offers no authentication method at all.
  ///
  /// In en, this message translates to:
  /// **'No fingerprint, face or device PIN is available on this device.'**
  String get lockNoBiometrics;

  /// Screen-reader label for the play control on a voice message.
  ///
  /// In en, this message translates to:
  /// **'Play voice note'**
  String get voicePlay;

  /// Screen-reader label for the same control while it is playing.
  ///
  /// In en, this message translates to:
  /// **'Pause voice note'**
  String get voicePause;

  /// Shown when the audio player cannot start. The voice note is intact; only in-app playback is unavailable, so the user is pointed at saving it.
  ///
  /// In en, this message translates to:
  /// **'Playback isn\'t available on this device — save the file instead.'**
  String get voiceNoPlayback;

  /// Placeholder in the search field.
  ///
  /// In en, this message translates to:
  /// **'Search messages…'**
  String get searchHint;

  /// Screen-reader label for the control that empties the search field.
  ///
  /// In en, this message translates to:
  /// **'Clear search'**
  String get searchClear;

  /// Shown before anything is typed. The second half is a security statement and the point of it is that no query reaches a server; keep that meaning.
  ///
  /// In en, this message translates to:
  /// **'Search your messages. Everything is decrypted on this device only for the search — nothing leaves it.'**
  String get searchIntro;

  /// Empty state. {query} is what the user typed.
  ///
  /// In en, this message translates to:
  /// **'No messages match “{query}”.'**
  String searchNoResults(String query);

  /// Prefixes a search hit the user sent themselves, in a group thread. Keep the trailing space.
  ///
  /// In en, this message translates to:
  /// **'You: '**
  String get searchYouPrefix;

  /// Prefixes a search hit sent by someone else in a group thread. Keep the trailing space; the separator may differ by language.
  ///
  /// In en, this message translates to:
  /// **'{name}: '**
  String searchSenderPrefix(String name);

  /// Screen-reader label for the search control in the app bar.
  ///
  /// In en, this message translates to:
  /// **'Search messages'**
  String get homeSearch;

  /// Screen-reader label for the create-group control.
  ///
  /// In en, this message translates to:
  /// **'New group'**
  String get homeNewGroup;

  /// Screen-reader label for the settings control.
  ///
  /// In en, this message translates to:
  /// **'Settings'**
  String get homeSettings;

  /// Label on the button that opens the add-contact screen.
  ///
  /// In en, this message translates to:
  /// **'Add contact'**
  String get homeAddContact;

  /// Connection status: connected to the relay. Lower case on purpose — it sits inline in a status row.
  ///
  /// In en, this message translates to:
  /// **'relay linked'**
  String get relayLinked;

  /// Connection status: still connecting.
  ///
  /// In en, this message translates to:
  /// **'linking…'**
  String get relayLinking;

  /// Connection status: not connected. Messages still queue locally.
  ///
  /// In en, this message translates to:
  /// **'offline'**
  String get relayOffline;

  /// Empty state heading on the conversation list.
  ///
  /// In en, this message translates to:
  /// **'No conversations yet'**
  String get homeEmptyTitle;

  /// Empty state body. 'a channel you trust' is the security point — the codes must not be exchanged over something an attacker controls.
  ///
  /// In en, this message translates to:
  /// **'Exchange contact codes in person or over a channel you trust, then every message is end-to-end encrypted and stored only on your two devices.'**
  String get homeEmptyBody;

  /// Preview text for a conversation with no messages yet.
  ///
  /// In en, this message translates to:
  /// **'Say hello — the line is encrypted.'**
  String get chatPreviewEmpty;

  /// Conversation-list preview of a group message from someone else.
  ///
  /// In en, this message translates to:
  /// **'{name}: {body}'**
  String chatPreviewSender(String name, String body);

  /// Dismisses a banner or alert.
  ///
  /// In en, this message translates to:
  /// **'Dismiss'**
  String get dismiss;

  /// Confirmation after adding a contact. The second sentence is the nudge to verify; it is advice, not an alarm.
  ///
  /// In en, this message translates to:
  /// **'{name} added. Compare safety numbers when you can.'**
  String contactAdded(String name);

  /// Tab: show my own contact code. Upper case in the design.
  ///
  /// In en, this message translates to:
  /// **'MY CODE'**
  String get addMyCode;

  /// Tab: paste a contact code as text.
  ///
  /// In en, this message translates to:
  /// **'PASTE'**
  String get addPaste;

  /// Tab: scan a contact code with the camera.
  ///
  /// In en, this message translates to:
  /// **'SCAN'**
  String get addScan;

  /// Explains the code is safe to share. The emphasis on PUBLIC is deliberate — people assume a code is a secret.
  ///
  /// In en, this message translates to:
  /// **'Have your contact scan this QR code, or send them the text code over a channel you trust. Codes contain only PUBLIC keys.'**
  String get addMyCodeHelp;

  /// Copies my contact code to the clipboard.
  ///
  /// In en, this message translates to:
  /// **'Copy code'**
  String get addCopyCode;

  /// Confirmation that the code is on the clipboard.
  ///
  /// In en, this message translates to:
  /// **'Code copied'**
  String get addCodeCopied;

  /// Label on the field where a pasted code goes.
  ///
  /// In en, this message translates to:
  /// **'Their contact code'**
  String get addTheirCode;

  /// Label on the optional local-name field. The name they chose is used if this is blank.
  ///
  /// In en, this message translates to:
  /// **'Name (optional — overrides theirs)'**
  String get addNameOverride;

  /// Button that checks the code's signature and adds the contact.
  ///
  /// In en, this message translates to:
  /// **'Verify & add'**
  String get addVerifyAndAdd;

  /// Reassurance under the add button. It is a statement about what the app does, not advice.
  ///
  /// In en, this message translates to:
  /// **'The code\'s signature is checked before the contact is added — a tampered code is rejected.'**
  String get addSignatureNote;

  /// Instruction on the camera scanning screen.
  ///
  /// In en, this message translates to:
  /// **'Point the camera at their Z code.'**
  String get addScanPrompt;

  /// Conversation-list preview of an attachment. The paperclip leads in left-to-right scripts; a right-to-left layout may want it after the name, which is why this is a whole string rather than a prefix.
  ///
  /// In en, this message translates to:
  /// **'📎 {name}'**
  String chatPreviewFile(String name);

  /// Validation: the connection test was pressed with an empty address.
  ///
  /// In en, this message translates to:
  /// **'Enter your relay address first.'**
  String get onbEnterRelayFirst;

  /// Result of a successful connection test.
  ///
  /// In en, this message translates to:
  /// **'Connected — the relay is reachable.'**
  String get onbRelayReachable;

  /// Validation: continue was pressed with no display name. The parenthetical answers the unspoken 'who can see this'.
  ///
  /// In en, this message translates to:
  /// **'Pick a display name (only your contacts ever see it).'**
  String get onbPickName;

  /// File-picker title when restoring.
  ///
  /// In en, this message translates to:
  /// **'Choose your Z backup'**
  String get onbChooseBackup;

  /// The chosen file is not a .zbk or .zid.
  ///
  /// In en, this message translates to:
  /// **'That file is not a Z backup.'**
  String get onbNotABackup;

  /// Restore failed. Deliberately does NOT say which of the two, because saying so would tell an attacker holding the file whether a guess was close.
  ///
  /// In en, this message translates to:
  /// **'Restore failed: wrong secret, or the file is damaged.'**
  String get onbRestoreFailed;

  /// Label on the recovery-code field.
  ///
  /// In en, this message translates to:
  /// **'Recovery code'**
  String get onbRecoveryCode;

  /// Help text under the recovery-code field.
  ///
  /// In en, this message translates to:
  /// **'The 25-character code you saved when you made this backup.'**
  String get onbRecoveryCodeHelp;

  /// Dismisses a dialog without acting.
  ///
  /// In en, this message translates to:
  /// **'Cancel'**
  String get cancel;

  /// Confirms a restore.
  ///
  /// In en, this message translates to:
  /// **'Restore'**
  String get onbRestore;

  /// Dialog title when the archive is passphrase-protected rather than code-protected.
  ///
  /// In en, this message translates to:
  /// **'Backup passphrase'**
  String get onbBackupPassphrase;

  /// Label on a passphrase field.
  ///
  /// In en, this message translates to:
  /// **'Passphrase'**
  String get passphrase;

  /// Confirms a passphrase entry.
  ///
  /// In en, this message translates to:
  /// **'Unlock'**
  String get unlock;

  /// Label on the display-name field.
  ///
  /// In en, this message translates to:
  /// **'Display name'**
  String get onbDisplayName;

  /// Help text: the name travels in the contact code, not to a server.
  ///
  /// In en, this message translates to:
  /// **'Shared only inside your encrypted contact code'**
  String get onbDisplayNameHelp;

  /// Label on the relay field, shown only with developer options open.
  ///
  /// In en, this message translates to:
  /// **'Relay address (developer)'**
  String get onbRelayAddress;

  /// Help text under the relay field.
  ///
  /// In en, this message translates to:
  /// **'Custom or self-hosted relay. Leave as-is to use the default zmessengers.com relay.'**
  String get onbRelayHelp;

  /// The connection test is in flight.
  ///
  /// In en, this message translates to:
  /// **'Testing…'**
  String get onbTesting;

  /// Starts a connection test against the relay address.
  ///
  /// In en, this message translates to:
  /// **'Test connection'**
  String get onbTestConnection;

  /// Primary action: generate a new identity and finish onboarding.
  ///
  /// In en, this message translates to:
  /// **'Create my identity'**
  String get onbCreateIdentity;

  /// Secondary action: restore an existing identity from a .zbk or .zid.
  ///
  /// In en, this message translates to:
  /// **'Restore from a backup'**
  String get onbRestoreFromBackup;

  /// Secondary action: become an additional device of an account that already exists.
  ///
  /// In en, this message translates to:
  /// **'Link to an existing account'**
  String get onbLinkExisting;

  /// Collapses the developer section.
  ///
  /// In en, this message translates to:
  /// **'Hide developer options'**
  String get onbHideDevOptions;

  /// Expands the developer section.
  ///
  /// In en, this message translates to:
  /// **'Developer options'**
  String get onbDevOptions;

  /// Footnote on the onboarding screen. Both halves matter: it is generated here, and it does not leave in the clear.
  ///
  /// In en, this message translates to:
  /// **'Your identity is a cryptographic key pair generated on this device. It never leaves it unencrypted.'**
  String get onbIdentityNote;

  /// Validation on the create-group screen.
  ///
  /// In en, this message translates to:
  /// **'Pick a group name and at least one member.'**
  String get grpNeedNameAndMember;

  /// Group creation failed; {error} is the underlying message.
  ///
  /// In en, this message translates to:
  /// **'Could not create: {error}'**
  String grpCreateFailed(String error);

  /// Title of the create-group screen.
  ///
  /// In en, this message translates to:
  /// **'New group'**
  String get grpNew;

  /// Label on the group-name field.
  ///
  /// In en, this message translates to:
  /// **'Group name'**
  String get grpName;

  /// Help text: the name is shared with members, and there is no group key — each member gets their own encrypted copy.
  ///
  /// In en, this message translates to:
  /// **'Members see this name. Messages are end-to-end encrypted to each member individually.'**
  String get grpNameHelp;

  /// Empty state: a group needs contacts to invite.
  ///
  /// In en, this message translates to:
  /// **'Add some contacts first.'**
  String get grpAddContactsFirst;

  /// Create button, with the number of members selected.
  ///
  /// In en, this message translates to:
  /// **'{count, plural, =1{Create group (1 member)} other{Create group ({count} members)}}'**
  String grpCreateWithCount(int count);

  /// Opens the add-members screen, and titles it.
  ///
  /// In en, this message translates to:
  /// **'Add members'**
  String get grpAddMembers;

  /// Confirms an addition.
  ///
  /// In en, this message translates to:
  /// **'Add'**
  String get add;

  /// Confirmation dialog title.
  ///
  /// In en, this message translates to:
  /// **'Leave this group?'**
  String get grpLeaveTitle;

  /// Confirmation dialog body. The second sentence matters: leaving does not delete what you already have.
  ///
  /// In en, this message translates to:
  /// **'You will stop receiving its messages. Your copy of the history stays on this device.'**
  String get grpLeaveBody;

  /// Confirms leaving a group.
  ///
  /// In en, this message translates to:
  /// **'Leave'**
  String get grpLeave;

  /// Shown after leaving and deleting a group.
  ///
  /// In en, this message translates to:
  /// **'Group removed'**
  String get grpRemoved;

  /// Subtitle on a group you have left.
  ///
  /// In en, this message translates to:
  /// **'You are no longer in this group'**
  String get grpNoLongerIn;

  /// Subtitle on the group screen. The clause after the separator is the design statement: no group key, one encrypted copy per member.
  ///
  /// In en, this message translates to:
  /// **'{count, plural, =1{1 member · every message is end-to-end encrypted to each member} other{{count} members · every message is end-to-end encrypted to each member}}'**
  String grpMemberCount(int count);

  /// The current user's row in the member list, when they created the group.
  ///
  /// In en, this message translates to:
  /// **'You (admin)'**
  String get grpYouAdmin;

  /// The current user's row in the member list.
  ///
  /// In en, this message translates to:
  /// **'You'**
  String get grpYou;

  /// A member whose contact record is missing.
  ///
  /// In en, this message translates to:
  /// **'Unknown'**
  String get grpUnknown;

  /// Badge next to the member who administers the group. Lower case: it sits as a chip, not a sentence.
  ///
  /// In en, this message translates to:
  /// **'admin'**
  String get grpAdmin;

  /// Removes the selected member.
  ///
  /// In en, this message translates to:
  /// **'Remove from group'**
  String get grpRemoveFromGroup;

  /// Action in the group screen's menu.
  ///
  /// In en, this message translates to:
  /// **'Leave group'**
  String get grpLeaveGroup;

  /// Footnote on the group screen. This is the whole group design in three clauses; keep all three.
  ///
  /// In en, this message translates to:
  /// **'Groups have no server-side existence: the relay never learns the group\'s name or member list. Each message is sent as separate end-to-end encrypted copies over your verified 1:1 channels.'**
  String get grpFootnote;

  /// Connection test failed. {url} is the normalised address that was tried. 'Live' is the wording a hosting dashboard uses; keep it recognisable.
  ///
  /// In en, this message translates to:
  /// **'Could not reach a relay at {url}.\nCheck the address and that it shows Live in your host dashboard.'**
  String onbRelayUnreachableAt(String url);

  /// Heading on the pairing confirmation step.
  ///
  /// In en, this message translates to:
  /// **'Compare the safety code'**
  String get linkCompareTitle;

  /// Instruction above the SAS code. BOTH is emphasised because comparing on one screen proves nothing.
  ///
  /// In en, this message translates to:
  /// **'This exact code must show on BOTH devices:'**
  String get linkCompareBody;

  /// The whole point of the SAS. A mismatch is the machine-in-the-middle case, and the user must be told to stop rather than to retry.
  ///
  /// In en, this message translates to:
  /// **'If they differ, cancel — someone may be intercepting the link.'**
  String get linkCompareWarn;

  /// Rejects the pairing because the codes did not match.
  ///
  /// In en, this message translates to:
  /// **'They differ — cancel'**
  String get linkTheyDiffer;

  /// Confirms the codes matched and completes the link.
  ///
  /// In en, this message translates to:
  /// **'They match'**
  String get linkTheyMatch;

  /// Success confirmation after linking.
  ///
  /// In en, this message translates to:
  /// **'Device linked. It now carries your account and contacts.'**
  String get linkDone;

  /// The pairing was abandoned, by either side.
  ///
  /// In en, this message translates to:
  /// **'Link cancelled.'**
  String get linkCancelled;

  /// Pairing failed; {error} is the underlying message.
  ///
  /// In en, this message translates to:
  /// **'Link failed: {error}'**
  String linkFailed(String error);

  /// Title of the screen that adds a device, and the action that opens it.
  ///
  /// In en, this message translates to:
  /// **'Link a device'**
  String get linkADevice;

  /// Instructions on the existing device. The quoted phrase must match the button label on the other screen.
  ///
  /// In en, this message translates to:
  /// **'On the device you want to add, install Z and choose \"Link to an existing account\". It will show a pairing code — enter it here.'**
  String get linkHostHelp;

  /// Label on the pairing-code field.
  ///
  /// In en, this message translates to:
  /// **'Pairing code'**
  String get linkPairingCode;

  /// Button that starts pairing from the entered code.
  ///
  /// In en, this message translates to:
  /// **'Link device'**
  String get linkDeviceAction;

  /// Sets expectations: linking works, live sync of new messages does not yet.
  ///
  /// In en, this message translates to:
  /// **'Live message sync across your devices arrives in a follow-up update; linking establishes the trusted, verified connection now.'**
  String get linkSyncNote;

  /// Title of the screen on the device being added.
  ///
  /// In en, this message translates to:
  /// **'Link to an account'**
  String get linkToAccount;

  /// Instructions on the new device. The menu path must match the real one.
  ///
  /// In en, this message translates to:
  /// **'On your existing device, open Settings → Linked devices → \"Link a device\", then enter the code below.'**
  String get linkJoinHelp;

  /// Copies the shown code to the clipboard.
  ///
  /// In en, this message translates to:
  /// **'Copy code'**
  String get copyCode;

  /// Label on the relay field in the developer section.
  ///
  /// In en, this message translates to:
  /// **'Relay address (developer)'**
  String get relayAddressDev;

  /// Help text under the relay field on the linking screen.
  ///
  /// In en, this message translates to:
  /// **'Custom or self-hosted relay. Leave as-is for the default zmessengers.com relay.'**
  String get relayHelpLink;

  /// Collapses the developer section.
  ///
  /// In en, this message translates to:
  /// **'Hide developer options'**
  String get hideDevOptions;

  /// Expands the developer section.
  ///
  /// In en, this message translates to:
  /// **'Developer options'**
  String get devOptions;

  /// Begins pairing from the new device.
  ///
  /// In en, this message translates to:
  /// **'Start linking'**
  String get linkStart;

  /// Confirmation dialog title for revoking a linked device.
  ///
  /// In en, this message translates to:
  /// **'Revoke this device?'**
  String get linkRevokeTitle;

  /// Confirmation body. {device} is the device's id. Irreversibility is the point of the warning.
  ///
  /// In en, this message translates to:
  /// **'Messages will stop syncing to \"{device}\", and your contacts will no longer deliver to it. This can\'t be undone — to use that device again you would link it fresh.'**
  String linkRevokeBody(String device);

  /// Confirms revoking a device.
  ///
  /// In en, this message translates to:
  /// **'Revoke'**
  String get revoke;

  /// Title of the linked-devices list.
  ///
  /// In en, this message translates to:
  /// **'Linked devices'**
  String get linkedDevices;

  /// Empty state on the linked-devices list.
  ///
  /// In en, this message translates to:
  /// **'No other devices linked yet.'**
  String get linkNoneYet;

  /// Shown on a device that is not the account root. It cannot administer the device list.
  ///
  /// In en, this message translates to:
  /// **'This is a linked device. Adding or revoking devices is done from your main device — the one that created the account.'**
  String get linkNotRoot;

  /// Footnote explaining what revocation does: it is a re-signed list, not a request to a server.
  ///
  /// In en, this message translates to:
  /// **'Each device has its own keys. Revoking one re-signs your device list so your contacts immediately stop trusting it.'**
  String get linkRevokeNote;

  /// Marks the row for the device you are holding.
  ///
  /// In en, this message translates to:
  /// **'This device'**
  String get linkThisDevice;

  /// Shows the start of a device's key fingerprint. The ellipsis means it is truncated.
  ///
  /// In en, this message translates to:
  /// **'Key {fingerprint}…'**
  String linkKeyFingerprint(String fingerprint);

  /// Action that revokes the selected device.
  ///
  /// In en, this message translates to:
  /// **'Revoke device'**
  String get linkRevokeDevice;

  /// Title of the backup screen.
  ///
  /// In en, this message translates to:
  /// **'Backup'**
  String get backupTitle;

  /// Status when no backup has been made.
  ///
  /// In en, this message translates to:
  /// **'No backup yet'**
  String get backupNoneYet;

  /// Status line; {when} is a relative time such as 'yesterday'.
  ///
  /// In en, this message translates to:
  /// **'Last backup {when}'**
  String backupLastTaken(String when);

  /// Shown when there is no backup. It states the consequence plainly because there is no recovery path to fall back on.
  ///
  /// In en, this message translates to:
  /// **'Your messages live only on this device. If you lose it, they are gone — there is no copy on any server.'**
  String get backupNoneBody;

  /// Shown when a backup exists but may not have been copied off the device. {size} is e.g. '4.2 MB'.
  ///
  /// In en, this message translates to:
  /// **'{size} · kept on this device. Save a copy somewhere else so a lost phone does not take it with them.'**
  String backupExistsBody(String size);

  /// A backup is being written.
  ///
  /// In en, this message translates to:
  /// **'Working…'**
  String get backupWorking;

  /// Starts a backup.
  ///
  /// In en, this message translates to:
  /// **'Create a backup'**
  String get backupCreate;

  /// Explains what goes into a backup and what protects it.
  ///
  /// In en, this message translates to:
  /// **'Every message, contact, group and attachment, encrypted with a recovery code only you hold.'**
  String get backupCreateHelp;

  /// Exports the latest backup through the platform file picker.
  ///
  /// In en, this message translates to:
  /// **'Save a copy…'**
  String get backupSaveCopy;

  /// Why to export: a backup on the lost phone is no backup.
  ///
  /// In en, this message translates to:
  /// **'Put the latest backup somewhere off this device.'**
  String get backupSaveCopyHelp;

  /// Toggle for scheduled backups.
  ///
  /// In en, this message translates to:
  /// **'Back up automatically'**
  String get backupAuto;

  /// Shown when automatic backup is on. The second sentence is the trade-off being accepted.
  ///
  /// In en, this message translates to:
  /// **'Every {days} days, using the recovery code you saved. That code is kept on this device to make it possible.'**
  String backupAutoOnHelp(int days);

  /// Shown when automatic backup is off, stating what turning it on costs.
  ///
  /// In en, this message translates to:
  /// **'Off. Turning it on stores your recovery code on this device, so a backup can run without you.'**
  String get backupAutoOffHelp;

  /// The long explanation at the foot of the backup screen. Two paragraphs, separated by a blank line: what a restore does and does not do, then where the encryption happens and what losing the code means. Keep both, and keep 'which is the point' — the irrecoverability is a design choice, not a shortcoming.
  ///
  /// In en, this message translates to:
  /// **'A backup restores your history onto a new device. It does not restore your live conversations — those re-handshake by themselves the first time you message someone, and the other person sees nothing unusual.\n\nThe backup never touches the relay. It is encrypted here, on this device, and only the recovery code opens it. Lose the code and the file cannot be opened by anyone — there is no server-side way in, which is the point.'**
  String get backupFootnote;

  /// First stage of writing a backup.
  ///
  /// In en, this message translates to:
  /// **'Preparing…'**
  String get backupPreparing;

  /// Progress stage.
  ///
  /// In en, this message translates to:
  /// **'Packing messages…'**
  String get backupPackingMessages;

  /// Progress stage.
  ///
  /// In en, this message translates to:
  /// **'Packing attachments…'**
  String get backupPackingAttachments;

  /// Last stage of writing a backup.
  ///
  /// In en, this message translates to:
  /// **'Finishing…'**
  String get backupFinishing;

  /// Success confirmation.
  ///
  /// In en, this message translates to:
  /// **'Backup created. Save a copy somewhere safe.'**
  String get backupCreated;

  /// The backup could not be written.
  ///
  /// In en, this message translates to:
  /// **'Backup failed: {error}'**
  String backupFailed(String error);

  /// Confirms turning scheduled backups off, and that the stored code is gone with it.
  ///
  /// In en, this message translates to:
  /// **'Automatic backup off. The stored code was erased.'**
  String get backupAutoOff;

  /// Confirms turning scheduled backups on.
  ///
  /// In en, this message translates to:
  /// **'Z will back up every 7 days with that code.'**
  String get backupAutoOn;

  /// The export through the file picker succeeded.
  ///
  /// In en, this message translates to:
  /// **'Copy saved.'**
  String get backupCopySaved;

  /// The export failed but the backup itself is fine. Says where it is rather than implying it did not happen.
  ///
  /// In en, this message translates to:
  /// **'That backup is too large for this device\'s file picker. It is still saved in the app as {name}.'**
  String backupTooLargeForPicker(String name);

  /// The export failed.
  ///
  /// In en, this message translates to:
  /// **'Could not save: {error}'**
  String backupSaveFailed(String error);

  /// A file size in kilobytes.
  ///
  /// In en, this message translates to:
  /// **'{kb} KB'**
  String sizeKb(String kb);

  /// A file size in megabytes.
  ///
  /// In en, this message translates to:
  /// **'{mb} MB'**
  String sizeMb(String mb);

  /// Relative time, under a minute ago.
  ///
  /// In en, this message translates to:
  /// **'just now'**
  String get timeJustNow;

  /// Relative time in minutes.
  ///
  /// In en, this message translates to:
  /// **'{count, plural, =1{1 min ago} other{{count} min ago}}'**
  String timeMinutesAgo(int count);

  /// Relative time in hours.
  ///
  /// In en, this message translates to:
  /// **'{count, plural, =1{1 h ago} other{{count} h ago}}'**
  String timeHoursAgo(int count);

  /// Relative time, one day ago.
  ///
  /// In en, this message translates to:
  /// **'yesterday'**
  String get timeYesterday;

  /// Relative time in days, always two or more.
  ///
  /// In en, this message translates to:
  /// **'{count, plural, other{{count} days ago}}'**
  String timeDaysAgo(int count);

  /// Title of the dialog showing a freshly generated recovery code.
  ///
  /// In en, this message translates to:
  /// **'Your recovery code'**
  String get backupCodeTitle;

  /// Instruction with the recovery code. 'separate from the backup file' matters: either alone is harmless, together they are the whole history.
  ///
  /// In en, this message translates to:
  /// **'Write this down and keep it somewhere separate from the backup file itself. It is the only thing that opens the backup.'**
  String get backupCodeWriteDown;

  /// The second half of the recovery-code warning. It explains WHY irrecoverability is a feature; a translation that makes it sound like an apology loses the point.
  ///
  /// In en, this message translates to:
  /// **'Nobody can recover it for you — not us, not the relay, not with a court order. That is deliberate, and it is the reason nobody can be compelled to hand over your messages either.'**
  String get backupCodeNobodyCan;

  /// Copies text to the clipboard.
  ///
  /// In en, this message translates to:
  /// **'Copy'**
  String get copy;

  /// Confirms the code is on the clipboard.
  ///
  /// In en, this message translates to:
  /// **'Code copied'**
  String get codeCopied;

  /// Confirms the user has recorded the recovery code, and dismisses the dialog.
  ///
  /// In en, this message translates to:
  /// **'I have written it down'**
  String get backupCodeWritten;

  /// The typed code is well-formed but is not the code for this backup — so the user has a code, just the wrong one.
  ///
  /// In en, this message translates to:
  /// **'That is a valid code, but not this one.'**
  String get backupWrongCode;

  /// Returns to the previous step of a multi-step dialog without cancelling it. Distinct from cancel, which abandons the whole flow.
  ///
  /// In en, this message translates to:
  /// **'Back'**
  String get back;

  /// Submits the current step of a dialog. Generic; used where the action is self-evident from the dialog above it.
  ///
  /// In en, this message translates to:
  /// **'Confirm'**
  String get confirm;

  /// Title of the dialog asking the user to re-type the recovery code they were just shown, to prove they recorded it.
  ///
  /// In en, this message translates to:
  /// **'Type it back'**
  String get backupConfirmTitle;

  /// Explains why the code must be typed back. The second sentence is load-bearing: without it users retype in a panic about exact formatting, and the check is in fact case- and separator-insensitive.
  ///
  /// In en, this message translates to:
  /// **'So we know it is written down correctly. Capitals, spacing and dashes do not matter.'**
  String get backupConfirmBody;

  /// Title of the dialog asking for a recovery code the user ALREADY has, in order to turn on automatic backup. The English matches backupCodeTitle but the situation is the opposite one — that dialog hands out a new code, this one asks for an existing one — so a locale that distinguishes giving from asking must render them differently.
  ///
  /// In en, this message translates to:
  /// **'Your recovery code'**
  String get backupAskCodeTitle;

  /// The cost of turning on automatic backup, stated before the user agrees to it. The clause after the dash is the whole warning: storing the code trades some of the backup's independence from the device for convenience. A translation that drops it turns an informed choice into a silent one.
  ///
  /// In en, this message translates to:
  /// **'Type the code you saved. It is stored on this device so a backup can run on its own — anyone who can already open this app could then open your backup files too.'**
  String get backupAskCodeBody;

  /// Confirms turning automatic backup on, using the code just typed.
  ///
  /// In en, this message translates to:
  /// **'Turn on'**
  String get backupAskCodeTurnOn;

  /// Commits an edit made in a dialog. Generic.
  ///
  /// In en, this message translates to:
  /// **'Save'**
  String get save;

  /// Confirms a destructive action in a dialog. Generic; the dialog above it says what is being deleted.
  ///
  /// In en, this message translates to:
  /// **'Delete'**
  String get delete;

  /// Shown in place of the whole contact screen when the contact was deleted while the screen was open — a state, not a confirmation of an action the user just took.
  ///
  /// In en, this message translates to:
  /// **'Contact removed'**
  String get ciContactRemoved;

  /// The first 16 characters of the contact's routing id, shown small under their name for support and debugging. 'routing id' is the protocol's term (§18.7) and is deliberately not translated into a friendlier word: it is the mailbox address, not an account name.
  ///
  /// In en, this message translates to:
  /// **'routing id: {id}…'**
  String ciRoutingId(String id);

  /// Banner heading. {device} is the name of ANOTHER of the user's own devices, the one that added this contact. Not the contact's device.
  ///
  /// In en, this message translates to:
  /// **'Added on {device}'**
  String ciAddedOnDevice(String device);

  /// Why a contact the user does not remember adding is present. The second sentence is the actionable half: a linked device can assert a contact with no scan behind it, so the user is asked to do the scan's job themselves.
  ///
  /// In en, this message translates to:
  /// **'This contact came from another of your devices, so no code was scanned here. Compare the safety number below before you rely on it.'**
  String get ciAddedOnDeviceBody;

  /// Banner heading (§18.9). The body is supplied by the service. Nothing is broken — the wording should read as unfinished, not as failed.
  ///
  /// In en, this message translates to:
  /// **'A post-quantum signature never arrived'**
  String get ciPqSigMissing;

  /// Banner heading for the serious case: a post-quantum key was offered and rejected. 'refused' is active on purpose — the app did something, rather than something being missing.
  ///
  /// In en, this message translates to:
  /// **'Post-quantum key refused'**
  String get ciPqRefused;

  /// The most serious message on the screen. Three clauses are load-bearing: the key was REJECTED (nothing unsafe was accepted); the identity was NOT upgraded (so the old guarantees still hold); and substitution is one of two live explanations, stated without deciding which. A translation that softens 'someone is substituting keys' into a generic error leaves the user with no reason to act.
  ///
  /// In en, this message translates to:
  /// **'A post-quantum key arrived for {name} that does not match the code you scanned, so it was rejected and their identity was NOT upgraded. Either something is broken at their end, or someone is substituting keys. Compare the number below before trusting this chat.'**
  String ciPqRefusedBody(String name);

  /// Heading of the card holding the 60-digit number. This is the app's name for it throughout — keep one term per locale.
  ///
  /// In en, this message translates to:
  /// **'Safety number'**
  String get ciSafetyNumber;

  /// How to use the number, and what it proves. '60' is fixed by the protocol, not by the locale. 'not even the relay' is the point of the whole screen: the relay is Z's own server, and the number is what makes trusting it unnecessary.
  ///
  /// In en, this message translates to:
  /// **'Compare these 60 digits with the ones on their device (in person or on a call you trust). If they match, no one is sitting between you — not even the relay.'**
  String get ciSafetyCompare;

  /// Shown when the contact's device list carries a post-quantum signature. 'quietly reduced' names the specific attack — removing a device from the list so a message reaches fewer places than the user believes — and is worth keeping concrete.
  ///
  /// In en, this message translates to:
  /// **'Their device list is signed post-quantum too, so the set of devices you send to cannot be forged or quietly reduced.'**
  String get ciDevListHybrid;

  /// The same fact in its unfinished state. 'That is correct today' must survive translation: without it this reads as a warning, and it is not one.
  ///
  /// In en, this message translates to:
  /// **'Their device list is signed classically only. That is correct today; the post-quantum signature for it travels separately and may not have arrived yet.'**
  String get ciDevListClassical;

  /// Row label opening the rename dialog.
  ///
  /// In en, this message translates to:
  /// **'Rename'**
  String get ciRename;

  /// Title of the rename dialog. The name is local to this device and is never sent to the contact or the relay.
  ///
  /// In en, this message translates to:
  /// **'Rename contact'**
  String get ciRenameContact;

  /// Row label for the session reset.
  ///
  /// In en, this message translates to:
  /// **'Reset secure session'**
  String get ciResetSession;

  /// When to use the reset. The parenthesis is the only guidance a user has for a control they should almost never touch.
  ///
  /// In en, this message translates to:
  /// **'Start a fresh encryption session (use if messages stop decrypting)'**
  String get ciResetSessionHelp;

  /// Confirms the reset happened. Past tense: the work is already done.
  ///
  /// In en, this message translates to:
  /// **'Secure session reset'**
  String get ciResetSessionDone;

  /// Row label, shown in the danger colour. It names both things that go, because deleting a contact elsewhere in most apps does not take the messages.
  ///
  /// In en, this message translates to:
  /// **'Delete contact & all messages'**
  String get ciDeleteContact;

  /// Title of the delete confirmation.
  ///
  /// In en, this message translates to:
  /// **'Delete everything?'**
  String get ciDeleteTitle;

  /// The last warning before an irreversible delete. 'THIS device' is capitalised because other linked devices keep their copies. The final clause explains that irrecoverability is the design, not a limitation — the same argument as the backup recovery code.
  ///
  /// In en, this message translates to:
  /// **'This wipes the contact, every message and every attachment from THIS device. There is no server copy to restore from — that is the point.'**
  String get ciDeleteBody;

  /// What the safety number covers when the contact is classical-only. 'nothing further to check' is reassurance: this is a complete state, not a partial one. Ed25519 is an algorithm name and stays as it is.
  ///
  /// In en, this message translates to:
  /// **'This identity is signed with Ed25519. Their app has not published a post-quantum key, so there is nothing further to check.'**
  String get ciBlurbClassical;

  /// The pre-emptive explanation of a number that is going to move. This exists so that when it moves, the user has already been told why — 'that is the upgrade, not tampering' is the sentence doing that work, and must not be dropped or softened.
  ///
  /// In en, this message translates to:
  /// **'The code you scanned promised a post-quantum key that has not arrived yet. When it does, this number changes ONCE — that is the upgrade, not tampering, and you will be asked to compare it again. Until then only the Ed25519 half is covered.'**
  String get ciBlurbPending;

  /// The complete state. 'matched the commitment in the code you scanned' is what distinguishes this from simply having received a key: the scanned code bound it in advance. Ed25519 and ML-DSA-65 are algorithm names.
  ///
  /// In en, this message translates to:
  /// **'Covers both halves of both identities: Ed25519 and ML-DSA-65. The post-quantum key arrived over the encrypted session and matched the commitment in the code you scanned.'**
  String get ciBlurbHybrid;

  /// Label of the verification toggle when it is on. A control label, not a heading — ciNoticeVerified is the heading with the same English.
  ///
  /// In en, this message translates to:
  /// **'Verified'**
  String get ciSwitchVerified;

  /// Label of the verification toggle after the number has moved, under BOTH the expected upgrade and the unexplained change. The user is asserting an action they performed, so it stays first-person.
  ///
  /// In en, this message translates to:
  /// **'I have compared it again'**
  String get ciSwitchComparedAgain;

  /// Label of the verification toggle when nothing has been verified yet.
  ///
  /// In en, this message translates to:
  /// **'Mark as verified'**
  String get ciSwitchMarkVerified;

  /// Pill beside the safety-number heading. 'Classical' means pre-quantum cryptography, not 'traditional' or 'standard'.
  ///
  /// In en, this message translates to:
  /// **'Classical'**
  String get ciPillClassical;

  /// Pill for an identity that has promised a post-quantum key and not yet delivered it.
  ///
  /// In en, this message translates to:
  /// **'Post-quantum pending'**
  String get ciPillPqPending;

  /// Pill for an identity covered by both algorithms. Kept short to fit the pill; the blurb below carries the detail.
  ///
  /// In en, this message translates to:
  /// **'Post-quantum'**
  String get ciPillPq;

  /// Banner heading confirming a verification still holds. Same English as ciSwitchVerified but this is a heading over a body, not a control label.
  ///
  /// In en, this message translates to:
  /// **'Verified'**
  String get ciNoticeVerified;

  /// Confirms the number on screen is the one that was checked. Present tense and specific: the guarantee is about THIS number, not about the contact in general.
  ///
  /// In en, this message translates to:
  /// **'This is the number you compared with {name}.'**
  String ciNoticeVerifiedBody(String name);

  /// Banner heading for the expected, one-time change. The 'here is why' half is what stops the heading reading as an alarm.
  ///
  /// In en, this message translates to:
  /// **'The number changed — here is why'**
  String get ciNoticeUpgraded;

  /// The benign explanation of a changed safety number — the case a user cannot distinguish from an attack without being told. Both halves must survive: this is not tampering, AND the old verification no longer applies. Dropping the first causes needless alarm; dropping the second lets a stale tick stand. {name} takes an English possessive here; render it however the locale forms one.
  ///
  /// In en, this message translates to:
  /// **'{name}\'s identity gained a post-quantum key, so the number is now derived from both halves. That is an upgrade, and it happens once. It is not a sign that anyone tampered with anything — but the number you checked before no longer applies, so please read this one out and compare it again.'**
  String ciNoticeUpgradedBody(String name);

  /// Banner heading for the case that is not the known upgrade. It says the app cannot explain rather than naming an attack, because it does not know — an honest 'cannot explain' is what earns the user's attention for the body.
  ///
  /// In en, this message translates to:
  /// **'The number changed and this app cannot explain why'**
  String get ciNoticeChanged;

  /// The most serious wording on the screen after ciPqRefusedBody. It rules out the innocent explanation explicitly — without that clause the user has no way to tell this apart from ciNoticeUpgradedBody — then gives one instruction. 'in person or on a call you trust' rules out doing it over the channel that may itself be compromised.
  ///
  /// In en, this message translates to:
  /// **'The number you verified with {name} is not the one shown now, and this is not the one-time post-quantum upgrade. Do not rely on the previous verification. Compare the number below in person or on a call you trust before continuing.'**
  String ciNoticeChangedBody(String name);

  /// The feature's name, used wherever it is referred to: the contact-info row, the chat toolbar tooltip and the timer picker's heading. One term per locale.
  ///
  /// In en, this message translates to:
  /// **'Disappearing messages'**
  String get disappearingMessages;

  /// The user, named as an author or actor — over a quoted message, in a reaction tooltip. Second person, not a name.
  ///
  /// In en, this message translates to:
  /// **'You'**
  String get you;

  /// A size in bytes, for a file too small to show in KB.
  ///
  /// In en, this message translates to:
  /// **'{b} B'**
  String sizeB(String b);

  /// Shown when the OS refused microphone access. States the missing permission, not a fault in the app.
  ///
  /// In en, this message translates to:
  /// **'Microphone permission is needed to record.'**
  String get chatMicPermission;

  /// Shown when starting the recorder threw for any reason other than permission.
  ///
  /// In en, this message translates to:
  /// **'Recording isn\'t available on this device.'**
  String get chatRecordingUnavailable;

  /// A recording under half a second was discarded as a misfire rather than sent.
  ///
  /// In en, this message translates to:
  /// **'Voice message too short.'**
  String get chatVoiceTooShort;

  /// A text or voice message could not be queued. {error} is the exception text.
  ///
  /// In en, this message translates to:
  /// **'Send failed: {error}'**
  String chatSendFailed(String error);

  /// Tapping a quote whose original is beyond the jump window. The message exists; the screen will not scroll to it.
  ///
  /// In en, this message translates to:
  /// **'That message is too far back to jump to.'**
  String get chatTooFarBack;

  /// Title of the edit dialog.
  ///
  /// In en, this message translates to:
  /// **'Edit message'**
  String get chatEditTitle;

  /// Hint in the edit dialog's text field.
  ///
  /// In en, this message translates to:
  /// **'Message'**
  String get chatEditHint;

  /// The edit was refused — too old, or already deleted. Not an error in the app.
  ///
  /// In en, this message translates to:
  /// **'That message can no longer be edited.'**
  String get chatEditExpired;

  /// Title of the confirmation for a delete that is also requested of the other side.
  ///
  /// In en, this message translates to:
  /// **'Delete for everyone?'**
  String get chatDeleteEveryoneTitle;

  /// The honest limit of 'delete for everyone'. 'asked to' (not 'made to') and the last sentence are the point: this is a request the other app honours, and nothing recalls what a person already saw. A translation that promises more than that misleads.
  ///
  /// In en, this message translates to:
  /// **'The message is removed here and the other side is asked to remove it too. Anyone who already read it may have kept a copy — no app can undo that.'**
  String get chatDeleteEveryoneBody;

  /// Forwarding is impossible because this is the user's only conversation.
  ///
  /// In en, this message translates to:
  /// **'No other conversation to forward to.'**
  String get chatNoForwardTarget;

  /// Heading of the sheet listing conversations to forward into.
  ///
  /// In en, this message translates to:
  /// **'Forward to'**
  String get chatForwardTo;

  /// Confirms the forward was queued.
  ///
  /// In en, this message translates to:
  /// **'Forwarded.'**
  String get chatForwarded;

  /// The forward could not be queued.
  ///
  /// In en, this message translates to:
  /// **'Forward failed: {error}'**
  String chatForwardFailed(String error);

  /// Toggling a reaction could not be queued.
  ///
  /// In en, this message translates to:
  /// **'Reaction failed: {error}'**
  String chatReactionFailed(String error);

  /// Disappearing-messages timer disabled. Shown as a picker option and as the current setting.
  ///
  /// In en, this message translates to:
  /// **'Off'**
  String get ttlOff;

  /// A disappearing-messages timer, in seconds.
  ///
  /// In en, this message translates to:
  /// **'{count, plural, =1{1 second} other{{count} seconds}}'**
  String ttlSeconds(int count);

  /// A disappearing-messages timer, in minutes.
  ///
  /// In en, this message translates to:
  /// **'{count, plural, =1{1 minute} other{{count} minutes}}'**
  String ttlMinutes(int count);

  /// A disappearing-messages timer, in hours.
  ///
  /// In en, this message translates to:
  /// **'{count, plural, =1{1 hour} other{{count} hours}}'**
  String ttlHours(int count);

  /// A disappearing-messages timer, in days.
  ///
  /// In en, this message translates to:
  /// **'{count, plural, =1{1 day} other{{count} days}}'**
  String ttlDays(int count);

  /// A disappearing-messages timer, in weeks.
  ///
  /// In en, this message translates to:
  /// **'{count, plural, =1{1 week} other{{count} weeks}}'**
  String ttlWeeks(int count);

  /// Shown in place of the chat when its contact or group was deleted while the screen was open.
  ///
  /// In en, this message translates to:
  /// **'Conversation removed'**
  String get chatConversationRemoved;

  /// Under a group's name in the chat header. The count includes the user.
  ///
  /// In en, this message translates to:
  /// **'{count, plural, =1{1 member · end-to-end encrypted} other{{count} members · end-to-end encrypted}}'**
  String chatGroupSubtitle(int count);

  /// Under a contact's name when the safety number was compared and still covers the identity shown. 'verified' is a claim about the number the user checked, not about the contact.
  ///
  /// In en, this message translates to:
  /// **'end-to-end encrypted · verified'**
  String get chatSubVerified;

  /// Under a contact's name after the one-time post-quantum upgrade moved the number: the old tick no longer covers it, and the user is asked to compare again.
  ///
  /// In en, this message translates to:
  /// **'end-to-end encrypted · re-verify'**
  String get chatSubReverify;

  /// Under a contact's name when the number moved for a reason the app cannot explain. Deliberately neutral; the contact-info screen carries the warning.
  ///
  /// In en, this message translates to:
  /// **'end-to-end encrypted · number changed'**
  String get chatSubNumberChanged;

  /// Under a contact's name when nothing has been verified.
  ///
  /// In en, this message translates to:
  /// **'end-to-end encrypted'**
  String get chatSubEncrypted;

  /// Replaces the composer in a group the user left or was removed from.
  ///
  /// In en, this message translates to:
  /// **'You are no longer in this group. History stays on this device; no new messages can be sent or received.'**
  String get chatLeftGroupNotice;

  /// Beside the timer while a voice note records. The clause after the ellipsis answers the question people ask about voice: yes, this too.
  ///
  /// In en, this message translates to:
  /// **'Recording… sent encrypted, like everything'**
  String get chatRecordingHint;

  /// Tooltip: throw the recording away without sending.
  ///
  /// In en, this message translates to:
  /// **'Discard'**
  String get chatDiscard;

  /// Tooltip: stop recording and send.
  ///
  /// In en, this message translates to:
  /// **'Send voice message'**
  String get chatSendVoice;

  /// Tooltip on the paperclip.
  ///
  /// In en, this message translates to:
  /// **'Attach a file'**
  String get chatAttachFile;

  /// Hint in the composer. 'Encrypted' is deliberate: the field itself says what happens to what is typed in it.
  ///
  /// In en, this message translates to:
  /// **'Encrypted message…'**
  String get chatInputHint;

  /// Hint in the composer while replying to a message.
  ///
  /// In en, this message translates to:
  /// **'Reply…'**
  String get chatReplyHint;

  /// Tooltip on the microphone.
  ///
  /// In en, this message translates to:
  /// **'Record a voice message'**
  String get chatRecordVoice;

  /// Small label above a bubble whose message was forwarded from elsewhere.
  ///
  /// In en, this message translates to:
  /// **'Forwarded'**
  String get chatForwardedLabel;

  /// Placeholder body of a message the user deleted for everyone.
  ///
  /// In en, this message translates to:
  /// **'You deleted this message'**
  String get chatYouDeleted;

  /// Placeholder body of a message the sender deleted for everyone.
  ///
  /// In en, this message translates to:
  /// **'This message was deleted'**
  String get chatTheyDeleted;

  /// Under a bubble whose send failed permanently. The second half is an instruction.
  ///
  /// In en, this message translates to:
  /// **'Failed to send — tap to retry'**
  String get chatFailedTapRetry;

  /// Tooltip on a quick-reaction button when that emoji is already the user's reaction. Read by screen readers; the glyph alone says nothing.
  ///
  /// In en, this message translates to:
  /// **'Remove {emoji} reaction'**
  String chatRemoveReaction(String emoji);

  /// Tooltip on a quick-reaction button.
  ///
  /// In en, this message translates to:
  /// **'React with {emoji}'**
  String chatReactWith(String emoji);

  /// A reaction chip under a bubble when more than one person reacted: the emoji and how many. Order can be swapped for a locale that reads the other way.
  ///
  /// In en, this message translates to:
  /// **'{emoji} {count}'**
  String chatReactionChip(String emoji, int count);

  /// Message action.
  ///
  /// In en, this message translates to:
  /// **'Reply'**
  String get chatReply;

  /// Message action: copies the body to the clipboard.
  ///
  /// In en, this message translates to:
  /// **'Copy text'**
  String get chatCopyText;

  /// Message action.
  ///
  /// In en, this message translates to:
  /// **'Forward'**
  String get chatForward;

  /// Message action, own messages only.
  ///
  /// In en, this message translates to:
  /// **'Edit'**
  String get chatEdit;

  /// Message action, own messages only. Opens the confirmation whose body states the limit.
  ///
  /// In en, this message translates to:
  /// **'Delete for everyone'**
  String get chatDeleteForEveryone;

  /// Action on a failed message.
  ///
  /// In en, this message translates to:
  /// **'Retry send'**
  String get chatRetrySend;

  /// The retry itself was refused.
  ///
  /// In en, this message translates to:
  /// **'Could not retry this message.'**
  String get chatRetryFailed;

  /// Action on a failed message: removes the local row only.
  ///
  /// In en, this message translates to:
  /// **'Delete for me'**
  String get chatDeleteForMe;

  /// A reactor whose name is not known, in a reaction tooltip.
  ///
  /// In en, this message translates to:
  /// **'Someone'**
  String get chatSomeone;

  /// The other party as author of a quoted message, when the sender's name is not known.
  ///
  /// In en, this message translates to:
  /// **'Them'**
  String get chatThem;

  /// Reply bar heading when the quoted message is the user's own. A separate string from chatReplyingTo because 'yourself' inflects differently from a name in most languages.
  ///
  /// In en, this message translates to:
  /// **'Replying to yourself'**
  String get chatReplyingToSelf;

  /// Reply bar heading when the quoted message's sender has no known name.
  ///
  /// In en, this message translates to:
  /// **'Replying to them'**
  String get chatReplyingToThem;

  /// Reply bar heading. {name} is the quoted message's sender.
  ///
  /// In en, this message translates to:
  /// **'Replying to {name}'**
  String chatReplyingTo(String name);

  /// Tooltip on the reply bar's close button.
  ///
  /// In en, this message translates to:
  /// **'Cancel reply'**
  String get chatCancelReply;

  /// Quote block whose original message is no longer held.
  ///
  /// In en, this message translates to:
  /// **'Message unavailable'**
  String get chatMessageUnavailable;

  /// Semantic label for an inline image attachment whose file name is unknown.
  ///
  /// In en, this message translates to:
  /// **'Image'**
  String get chatImage;

  /// Title of the OS save dialog for an attachment. 'decrypted' is a warning: what leaves the app is plaintext.
  ///
  /// In en, this message translates to:
  /// **'Save decrypted copy'**
  String get chatSaveDialogTitle;

  /// Confirms the attachment was written outside the app, and repeats that the copy is not encrypted.
  ///
  /// In en, this message translates to:
  /// **'Saved (decrypted copy)'**
  String get chatSavedDecrypted;

  /// The attachment could not be written.
  ///
  /// In en, this message translates to:
  /// **'Save failed: {error}'**
  String chatSaveFailed(String error);

  /// The line under the wordmark on the first screen. It is the brand's own claim, in the brand's own words ('No account. No phone number. No server storage.' on the artwork); keep the three short sentences and the line break after the first.
  ///
  /// In en, this message translates to:
  /// **'Zero-trust messaging.\nNo accounts. No phone number. No server storage.'**
  String get onbTagline;

  /// Generic confirm on a dialog with nothing more specific to say.
  ///
  /// In en, this message translates to:
  /// **'OK'**
  String get ok;

  /// Screen title.
  ///
  /// In en, this message translates to:
  /// **'Settings'**
  String get stSettings;

  /// Section header. Rendered in capitals by the widget; write it in normal case.
  ///
  /// In en, this message translates to:
  /// **'Profile'**
  String get stProfile;

  /// Row label and the title of the dialog that edits it.
  ///
  /// In en, this message translates to:
  /// **'Display name'**
  String get stDisplayName;

  /// After renaming. The second sentence is the useful half: the name is baked into the contact code, so existing contacts do not see the change and new ones need a new code.
  ///
  /// In en, this message translates to:
  /// **'Saved. Share a fresh contact code so new contacts see it.'**
  String get stDisplayNameSaved;

  /// Section header.
  ///
  /// In en, this message translates to:
  /// **'Appearance'**
  String get stAppearance;

  /// Row label for the light/dark/system choice.
  ///
  /// In en, this message translates to:
  /// **'Theme'**
  String get stTheme;

  /// Theme option: follow the OS. Keep short — three of these share one row.
  ///
  /// In en, this message translates to:
  /// **'System'**
  String get stThemeSystem;

  /// Theme option.
  ///
  /// In en, this message translates to:
  /// **'Light'**
  String get stThemeLight;

  /// Theme option.
  ///
  /// In en, this message translates to:
  /// **'Dark'**
  String get stThemeDark;

  /// Section header.
  ///
  /// In en, this message translates to:
  /// **'Connection'**
  String get stConnection;

  /// Row label. 'Relay' is the app's word for its server throughout — it relays ciphertext and holds nothing.
  ///
  /// In en, this message translates to:
  /// **'Relay'**
  String get stRelay;

  /// Relay status. 'zero-knowledge' is the claim: the link is up and the relay still learns nothing from it.
  ///
  /// In en, this message translates to:
  /// **'Connected — zero-knowledge link up'**
  String get stRelayConnected;

  /// Relay status.
  ///
  /// In en, this message translates to:
  /// **'Connecting…'**
  String get stRelayConnecting;

  /// Relay status, with no error to show.
  ///
  /// In en, this message translates to:
  /// **'Offline'**
  String get stRelayOffline;

  /// Relay status with the last transport error in parentheses.
  ///
  /// In en, this message translates to:
  /// **'Offline ({error})'**
  String stRelayOfflineWithError(String error);

  /// Section header.
  ///
  /// In en, this message translates to:
  /// **'Devices'**
  String get stDevices;

  /// Row label, opens the device list.
  ///
  /// In en, this message translates to:
  /// **'Linked devices'**
  String get stLinkedDevices;

  /// Under the linked-devices row.
  ///
  /// In en, this message translates to:
  /// **'See the devices on your account, link a new one, or revoke one you no longer use.'**
  String get stLinkedDevicesHelp;

  /// Section header.
  ///
  /// In en, this message translates to:
  /// **'Notifications'**
  String get stNotifications;

  /// Toggle label.
  ///
  /// In en, this message translates to:
  /// **'Push notifications'**
  String get stPush;

  /// What a push notification does and does not carry. 'content-free' and 'never inside the notification' are the privacy claim: the push service sees a wake-up, not a message. A translation that implies the notification shows the message contradicts the design.
  ///
  /// In en, this message translates to:
  /// **'Wake this device when a message arrives while Z is closed. The alert is content-free — messages are fetched and decrypted only on your device, never inside the notification.'**
  String get stPushHelp;

  /// Section header.
  ///
  /// In en, this message translates to:
  /// **'Security'**
  String get stSecurity;

  /// Warning row shown when the vault key could not be placed in the system keychain.
  ///
  /// In en, this message translates to:
  /// **'OS keystore unavailable'**
  String get stKeystoreUnavailable;

  /// What the fallback means and how to leave it. 'GNOME Keyring' and 'KWallet' are product names.
  ///
  /// In en, this message translates to:
  /// **'The vault key is stored in a restricted file instead of the system keychain. Install/enable a keyring (e.g. GNOME Keyring / KWallet on Linux) and re-create your identity for hardware-backed protection.'**
  String get stKeystoreUnavailableHelp;

  /// Informational row label.
  ///
  /// In en, this message translates to:
  /// **'Where your messages live'**
  String get stWhereMessagesLive;

  /// The storage claim in one sentence each for the device and the relay. 'RAM only until delivery, never on disk' is the relay's whole promise; keep it exact. XChaCha20-Poly1305 is an algorithm name.
  ///
  /// In en, this message translates to:
  /// **'Only in this device\'s encrypted vault (XChaCha20-Poly1305, key in the OS keystore). The relay holds ciphertext in RAM only until delivery, never on disk.'**
  String get stWhereMessagesLiveHelp;

  /// Toggle label for the biometric/PIN gate on opening the app.
  ///
  /// In en, this message translates to:
  /// **'Screen lock'**
  String get stScreenLock;

  /// Under the toggle when it is on. {after} is a duration such as '1 minute' or '15 minutes'.
  ///
  /// In en, this message translates to:
  /// **'Z asks for your fingerprint, face or device PIN when it opens and after {after} in the background.'**
  String stScreenLockOnHelp(String after);

  /// Under the toggle when it is on and the lock-after setting is 0 — the sentence for 'immediately', which does not fit the {after} slot in any language.
  ///
  /// In en, this message translates to:
  /// **'Z asks for your fingerprint, face or device PIN when it opens and as soon as it goes to the background.'**
  String get stScreenLockOnImmediateHelp;

  /// Under the toggle when it is off. The second sentence pre-empts the worry that a locked app is an offline app.
  ///
  /// In en, this message translates to:
  /// **'Ask for your fingerprint, face or device PIN to open Z. Messages still arrive while it is locked.'**
  String get stScreenLockOffHelp;

  /// Row label and dialog title for how long the app may sit in the background before it locks.
  ///
  /// In en, this message translates to:
  /// **'Lock after'**
  String get stLockAfter;

  /// Lock-after option: lock the moment the app goes to the background.
  ///
  /// In en, this message translates to:
  /// **'Immediately'**
  String get lockImmediately;

  /// Row label when a passphrase is set.
  ///
  /// In en, this message translates to:
  /// **'App passphrase — on'**
  String get stPassphraseOn;

  /// Row label when no passphrase is set.
  ///
  /// In en, this message translates to:
  /// **'App passphrase — off'**
  String get stPassphraseOff;

  /// Under the passphrase row when one is set.
  ///
  /// In en, this message translates to:
  /// **'This device asks for your passphrase on launch. Tap to change or remove it.'**
  String get stPassphraseOnHelp;

  /// Under the passphrase row when none is set. 'never sent anywhere' is the claim to keep.
  ///
  /// In en, this message translates to:
  /// **'Add a passphrase that unlocks the app on this device. Combined with the device keystore; never sent anywhere.'**
  String get stPassphraseOffHelp;

  /// Toggle label when the biometric key is sealed by secure hardware (Android). 'hardware-bound' is a stronger guarantee than the plain form and the suffix must not be dropped.
  ///
  /// In en, this message translates to:
  /// **'Unlock with biometrics — hardware-bound'**
  String get stBiometricBound;

  /// Toggle label when the biometric key is held in the ordinary keystore.
  ///
  /// In en, this message translates to:
  /// **'Unlock with biometrics'**
  String get stBiometric;

  /// First sentence of the biometric help, shared by both variants below; note the trailing space, which joins it to the next sentence.
  ///
  /// In en, this message translates to:
  /// **'Open the vault with your fingerprint or face instead of typing the passphrase. '**
  String get stBiometricLead;

  /// The hardware-bound case. Two facts: the key is unusable without a fresh biometric prompt, and it is invalidated by a biometric change. Both are what 'hardware-bound' means.
  ///
  /// In en, this message translates to:
  /// **'The key that opens it is sealed by this device\'s secure hardware and can only be used right after the system prompt — copying the app\'s data does not reveal it. Re-enrolling a fingerprint or face resets it.'**
  String get stBiometricBoundBody;

  /// The ordinary-keystore case, and it is a warning: convenience here costs something, and the sentence says exactly what. 'never the passphrase itself' and 'no longer needs your passphrase' must both survive.
  ///
  /// In en, this message translates to:
  /// **'While this is on, a key derived from your passphrase (never the passphrase itself) sits in this device\'s keystore — so on THIS device, someone who can break into the keystore no longer needs your passphrase. Turning it off deletes that key.'**
  String get stBiometricUnboundBody;

  /// Row label, opens the backup screen.
  ///
  /// In en, this message translates to:
  /// **'Backup'**
  String get stBackup;

  /// Under the backup row.
  ///
  /// In en, this message translates to:
  /// **'Everything — messages, contacts, groups, attachments — encrypted with a recovery code only you hold.'**
  String get stBackupHelp;

  /// Section header.
  ///
  /// In en, this message translates to:
  /// **'Developer'**
  String get stDeveloper;

  /// Toggle label.
  ///
  /// In en, this message translates to:
  /// **'Developer mode'**
  String get stDevMode;

  /// Under the developer toggle.
  ///
  /// In en, this message translates to:
  /// **'Reveal the custom relay address, for a self-hosted or test relay. Off by default — Z uses its built-in relay.'**
  String get stDevModeHelp;

  /// Row label showing the relay URL in developer mode.
  ///
  /// In en, this message translates to:
  /// **'Relay address'**
  String get stRelayAddress;

  /// Title of the dialog that edits the relay URL.
  ///
  /// In en, this message translates to:
  /// **'Relay server URL'**
  String get stRelayUrlTitle;

  /// Confirms the relay URL dialog.
  ///
  /// In en, this message translates to:
  /// **'Connect'**
  String get stConnect;

  /// Section header for the irreversible action.
  ///
  /// In en, this message translates to:
  /// **'Danger zone'**
  String get stDangerZone;

  /// Row label, shown in the danger colour.
  ///
  /// In en, this message translates to:
  /// **'Wipe everything'**
  String get stWipe;

  /// Under the wipe row.
  ///
  /// In en, this message translates to:
  /// **'Destroys identity, contacts, messages and keys on this device.'**
  String get stWipeHelp;

  /// Title of the wipe confirmation.
  ///
  /// In en, this message translates to:
  /// **'Wipe everything?'**
  String get stWipeTitle;

  /// The last warning before an irreversible wipe. 'no server has a copy' is the design restated as a consequence.
  ///
  /// In en, this message translates to:
  /// **'Your identity, contacts, messages and attachments will be destroyed on this device. Without a .zid backup your identity is unrecoverable — no server has a copy.'**
  String get stWipeBody;

  /// Confirms the wipe.
  ///
  /// In en, this message translates to:
  /// **'Wipe'**
  String get stWipeAction;

  /// Footer under the settings list. Two lines; the second is the brand claim in three parts.
  ///
  /// In en, this message translates to:
  /// **'Z — zero-trust messenger\nNo accounts · No analytics · No server storage'**
  String get stFooter;

  /// After enabling screen lock.
  ///
  /// In en, this message translates to:
  /// **'Screen lock on. Z will ask before opening.'**
  String get stScreenLockOn;

  /// Screen lock could not be enabled because the OS has no credential to gate with.
  ///
  /// In en, this message translates to:
  /// **'Set up a fingerprint, face or device PIN in your system settings first.'**
  String get stScreenLockUnavailable;

  /// The system biometric prompt was cancelled or failed, so nothing changed.
  ///
  /// In en, this message translates to:
  /// **'Not enabled — the prompt was not completed.'**
  String get stPromptNotCompleted;

  /// Title of the new-passphrase dialog.
  ///
  /// In en, this message translates to:
  /// **'Backup passphrase'**
  String get stBackupPassphraseTitle;

  /// Label on the first passphrase field, stating the minimum.
  ///
  /// In en, this message translates to:
  /// **'Passphrase (12+ characters)'**
  String get stPassphraseMinLabel;

  /// Label on the second passphrase field.
  ///
  /// In en, this message translates to:
  /// **'Repeat'**
  String get stRepeat;

  /// Validation: under the minimum.
  ///
  /// In en, this message translates to:
  /// **'Use at least 12 characters.'**
  String get stPassphraseTooShort;

  /// Validation: the two fields differ.
  ///
  /// In en, this message translates to:
  /// **'Passphrases do not match.'**
  String get stPassphraseMismatch;

  /// Confirms the new passphrase.
  ///
  /// In en, this message translates to:
  /// **'Encrypt & save'**
  String get stEncryptAndSave;

  /// After disabling biometric unlock. The second half matters: the key is gone, not merely unused.
  ///
  /// In en, this message translates to:
  /// **'Biometric unlock off — the stored key was deleted.'**
  String get stBiometricOff;

  /// Title of the secret prompt when enabling biometric unlock.
  ///
  /// In en, this message translates to:
  /// **'Enter your passphrase'**
  String get stEnterPassphrase;

  /// After enabling biometric unlock.
  ///
  /// In en, this message translates to:
  /// **'Biometric unlock on.'**
  String get stBiometricOn;

  /// The typed passphrase did not verify.
  ///
  /// In en, this message translates to:
  /// **'Incorrect passphrase.'**
  String get stIncorrectPassphrase;

  /// Biometric enrolment threw.
  ///
  /// In en, this message translates to:
  /// **'Could not enable: {error}'**
  String stCouldNotEnable(String error);

  /// After setting a passphrase for the first time.
  ///
  /// In en, this message translates to:
  /// **'Passphrase set. You\'ll be asked for it next launch.'**
  String get stPassphraseSet;

  /// Sheet action.
  ///
  /// In en, this message translates to:
  /// **'Change passphrase'**
  String get stChangePassphrase;

  /// Sheet action.
  ///
  /// In en, this message translates to:
  /// **'Remove passphrase'**
  String get stRemovePassphrase;

  /// Title of the secret prompt before changing or removing.
  ///
  /// In en, this message translates to:
  /// **'Enter current passphrase'**
  String get stEnterCurrentPassphrase;

  /// After a change.
  ///
  /// In en, this message translates to:
  /// **'Passphrase changed.'**
  String get stPassphraseChanged;

  /// After removal. The second sentence states the consequence plainly.
  ///
  /// In en, this message translates to:
  /// **'Passphrase removed. The app opens automatically now.'**
  String get stPassphraseRemoved;

  /// System message in the chat when an offered post-quantum key was refused. The same warning the contact screen carries; 'has not been upgraded' and the instruction to compare must survive. {name} takes an English possessive here.
  ///
  /// In en, this message translates to:
  /// **'{name}\'s post-quantum key does not match the code you scanned. Their identity has not been upgraded — compare safety numbers before trusting this chat.'**
  String sysPqMismatch(String name);

  /// System message after the user reset the encryption session.
  ///
  /// In en, this message translates to:
  /// **'Secure session was reset.'**
  String get sysSessionReset;

  /// System message: the user disabled the timer.
  ///
  /// In en, this message translates to:
  /// **'You turned off disappearing messages.'**
  String get sysTtlOffYou;

  /// System message: the user set the timer. {duration} is already in words, e.g. '5 minutes'.
  ///
  /// In en, this message translates to:
  /// **'You set disappearing messages to {duration}.'**
  String sysTtlSetYou(String duration);

  /// System message when an inbound message failed to decrypt and the session was reset. The second sentence is the instruction; the parenthesis says what the app did.
  ///
  /// In en, this message translates to:
  /// **'A message could not be decrypted (session reset). Ask them to resend.'**
  String get sysDecryptFailed;

  /// System message: the contact disabled the timer.
  ///
  /// In en, this message translates to:
  /// **'{name} turned off disappearing messages.'**
  String sysTtlOffThem(String name);

  /// System message: the contact set the timer.
  ///
  /// In en, this message translates to:
  /// **'{name} set disappearing messages to {duration}.'**
  String sysTtlSetThem(String name, String duration);

  /// System message when an inbound attachment's authentication failed. 'discarded' is deliberate — nothing unverified was kept.
  ///
  /// In en, this message translates to:
  /// **'An attachment failed integrity checks and was discarded.'**
  String get sysAttachmentDiscarded;

  /// System message in a group the user left.
  ///
  /// In en, this message translates to:
  /// **'You left the group.'**
  String get sysLeftYou;

  /// System message: the user created the group. {name} is the group's name, in quotes.
  ///
  /// In en, this message translates to:
  /// **'You created \"{name}\".'**
  String sysCreatedYou(String name);

  /// System message: the user added members. {names} is a list of names joined for display.
  ///
  /// In en, this message translates to:
  /// **'You added {names}.'**
  String sysAddedYou(String names);

  /// System message: the user removed a member.
  ///
  /// In en, this message translates to:
  /// **'You removed {name}.'**
  String sysRemovedYou(String name);

  /// System message: an admin removed the user from the group.
  ///
  /// In en, this message translates to:
  /// **'You were removed from \"{name}\".'**
  String sysRemovedFrom(String name);

  /// System message: {by} (a contact) added the user to the group {name}.
  ///
  /// In en, this message translates to:
  /// **'{by} added you to \"{name}\".'**
  String sysAddedToBy(String by, String name);

  /// System message when the member list changed in a way with no single actor to name.
  ///
  /// In en, this message translates to:
  /// **'Group membership updated.'**
  String get sysMembershipUpdated;

  /// System message: a member left.
  ///
  /// In en, this message translates to:
  /// **'{name} left the group.'**
  String sysMemberLeft(String name);

  /// Stands in for a member whose name is not known, inside another sentence (lower case, mid-sentence).
  ///
  /// In en, this message translates to:
  /// **'a member'**
  String get sysAMember;

  /// Stands in for an actor whose name is not known, at the start of a sentence.
  ///
  /// In en, this message translates to:
  /// **'Someone'**
  String get sysSomeone;

  /// System message: a member whose name is not known left. A whole sentence rather than sysMemberLeft with a stand-in, because the stand-in would begin the sentence.
  ///
  /// In en, this message translates to:
  /// **'A member left the group.'**
  String get sysUnknownMemberLeft;
}

class _AppLocalizationsDelegate
    extends LocalizationsDelegate<AppLocalizations> {
  const _AppLocalizationsDelegate();

  @override
  Future<AppLocalizations> load(Locale locale) {
    return SynchronousFuture<AppLocalizations>(lookupAppLocalizations(locale));
  }

  @override
  bool isSupported(Locale locale) =>
      <String>['en'].contains(locale.languageCode);

  @override
  bool shouldReload(_AppLocalizationsDelegate old) => false;
}

AppLocalizations lookupAppLocalizations(Locale locale) {
  // Lookup logic when only language code is specified.
  switch (locale.languageCode) {
    case 'en':
      return AppLocalizationsEn();
  }

  throw FlutterError(
      'AppLocalizations.delegate failed to load unsupported locale "$locale". This is likely '
      'an issue with the localizations generation tool. Please file an issue '
      'on GitHub with a reproducible sample app and the gen-l10n configuration '
      'that was used.');
}
