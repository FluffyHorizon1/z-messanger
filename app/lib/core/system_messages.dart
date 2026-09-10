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
  static const decryptFailed = 'decrypt_failed';
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
  static const memberLeft = 'member_left'; // name?
}

/// The stored form of a system message.
String systemBody(String kind, [Map<String, Object?> params = const {}]) =>
    jsonEncode({'k': kind, ...params});
