import 'dart:convert';

/// How a system message — "You left the group.", "Secure session was reset."
/// — is stored: as a kind and its parameters, never as the sentence.
///
/// A sentence written into the vault is frozen in the language the app
/// spoke that day and reads in that language for ever, which is the same
/// mistake as storing a missing contact name as the word "Unknown". So the
/// service stores `{"k":"ttl_set_you","sec":300}` and the screen renders it
/// through the ARB at the moment it is shown (`lib/l10n/system_text.dart`).
///
/// The kinds are the contract between the two files. Rows written before
/// this held the English sentence; they are shown as they are.
abstract final class SystemKind {
  static const pqMismatch = 'pq_mismatch'; // name
  static const sessionReset = 'session_reset';
  static const ttlOffYou = 'ttl_off_you';
  static const ttlSetYou = 'ttl_set_you'; // sec
  static const decryptFailed = 'decrypt_failed'; // n? (1 if absent)
  static const ttlOffThem = 'ttl_off_them'; // name
  static const ttlSetThem = 'ttl_set_them'; // name, sec
  static const attachmentDiscarded = 'attachment_discarded';
  static const leftYou = 'left_you';
  static const createdYou = 'created_you'; // name
  static const addedYou = 'added_you'; // names (list)
  static const removedYou = 'removed_you'; // name?
  static const removedFrom = 'removed_from'; // name
  static const addedToBy = 'added_to_by'; // by?, name
  static const membershipUpdated = 'membership_updated';
  static const renamedYou = 'renamed_you'; // name (23.1)
  static const renamedBy = 'renamed_by'; // by?, name (23.1)
  static const memberLeft = 'member_left'; // name?
}

/// The stored form of a system message.
String systemBody(String kind, [Map<String, Object?> params = const {}]) =>
    jsonEncode({'k': kind, ...params});

/// A device-list alert — the banner on a chat, and the one on a contact's
/// screen — stored the same way and for the same reason: a kind, never a
/// sentence.
///
/// These were worse than a frozen sentence. Every one of them named the
/// contact ("Dana's devices disagree about their device list"), and they were
/// written to the `kv` table with `sensitive: false`, so a display name sat
/// in the database in the clear next to the routing id that identifies whose
/// it is — in a vault whose own documentation says that names are among the
/// things encrypted cell by cell. And the screens that show them are both on
/// `check_l10n.py`'s migrated list, which is a promise that they hold no
/// user-visible English; they held a paragraph of it, handed to them by the
/// service at run time where the check cannot see it.
///
/// The name is not stored at all now. The screen has the contact.
abstract final class DevlistAlertKind {
  /// Their devices disagree about their own device list.
  static const conflict = 'dl_conflict';

  /// Their list went backwards a version — an old list replayed.
  static const rollback = 'dl_rollback';

  /// None of their devices confirms the list this device was handed.
  static const unconfirmed = 'dl_unconfirmed';

  /// A device claims a newer list and the update never arrived.
  static const missingUpdate = 'dl_missing_update';

  /// §18.9: the post-quantum signature was claimed and never arrived.
  static const pqSignatureMissing = 'dl_pq_missing';
}

/// The stored form of a device-list alert.
String devlistAlertBody(String kind) => jsonEncode({'k': kind});

/// The two loudest banners on the home screen — the owner's own-account
/// alarms — stored the same way and for the same reason: a kind and its
/// version numbers, never a sentence.
///
/// These were the last two account alerts written as finished English prose
/// into `kv` with `sensitive: false`: frozen in the language the app spoke
/// that day, so a Spanish user read them in English, and rendered by
/// `home_screen.dart` — on `check_l10n.py`'s migrated list, a promise it holds
/// no English — from a string the service handed it at run time where the
/// check cannot see it (the 2026-09-14 review's finding 38, the pair the
/// 2026-09-13 device-list fix missed). Unlike the device-list alerts these
/// carry no contact name, only device-list versions, which are public by
/// construction, so nothing here was secret; the fix is the localisation, and
/// the words are chosen in the reader's language when the banner is drawn
/// (`lib/l10n/account_alert_text.dart`). Rows an earlier build wrote as prose
/// are shown as they are.
abstract final class OwnAlertKind {
  /// T1/T2: the account's own main device published a device list at a
  /// version BELOW one this device already holds, signed by another device
  /// holding the account key. Params: `sent`, `held`.
  static const olderList = 'own_older';

  /// A contact was handed a device list for this account that this device
  /// never issued. No params.
  static const unissued = 'own_unissued';

  /// T3: this device was told by a contact that it was removed from its own
  /// account's device list. Param: `v` (the list version).
  static const removed = 'own_removed';
}

/// The stored form of an own-account alert.
String ownAlertBody(String kind, [Map<String, Object?> params = const {}]) =>
    jsonEncode({'k': kind, ...params});

/// True if [stored] is a device-list alert this build wrote.
///
/// Anything else is an alert written as English prose by a build before
/// 2026-09-13. Those are dropped rather than shown: the sentence carries a
/// contact's name in the clear, which is the thing being fixed, and the check
/// that raised it raises it again on its next pass if it is still true.
bool isDevlistAlertBody(String stored) {
  if (!stored.startsWith('{')) return false;
  try {
    final d = jsonDecode(stored);
    return d is Map && d['k'] is String;
  } on FormatException {
    return false;
  }
}
