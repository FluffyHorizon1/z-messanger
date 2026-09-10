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

  /// Result of a failed connection test. 'Live' is the wording a hosting dashboard uses; keep it recognisable.
  ///
  /// In en, this message translates to:
  /// **'Check the address and that it shows Live in your host dashboard.'**
  String get onbRelayUnreachable;

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
