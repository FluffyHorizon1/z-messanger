import 'dart:convert';

import '../core/system_messages.dart';
import 'app_localizations.dart';
import 'ttl_text.dart';

/// The words for a system message — "You left the group.", "Secure session
/// was reset." — in the user's language, at the moment it is shown.
///
/// The service stores a system message as a small JSON object: a kind and
/// its parameters, e.g. `{"k":"ttl_set_you","sec":300}`. It does NOT store
/// the sentence, because a sentence stored in the vault is frozen in
/// whatever language the app spoke on the day it was written, and would
/// read in that language for ever after — the same reason a contact's
/// missing name is not stored as the word "Unknown".
///
/// Rows written before this change hold the English sentence itself. They
/// are left as they are and shown as they are: rewriting stored ciphertext
/// to relocate prose is not worth a migration, and English is what they
/// were.
///
/// [body] is the unsealed stored string. Anything that is not a JSON object
/// with a `k` is returned untouched.
String systemText(AppLocalizations l, String body) {
  if (!body.startsWith('{')) return body;
  Map<String, Object?> m;
  try {
    final decoded = jsonDecode(body);
    if (decoded is! Map || decoded['k'] is! String) return body;
    m = decoded.cast<String, Object?>();
  } on FormatException {
    return body;
  }
  String s(String key, String fallback) => (m[key] as String?) ?? fallback;
  int n(String key) => (m[key] as num?)?.toInt() ?? 0;
  return switch (m['k'] as String) {
    SystemKind.pqMismatch => l.sysPqMismatch(s('name', l.sysSomeone)),
    SystemKind.sessionReset => l.sysSessionReset,
    SystemKind.ttlOffYou => l.sysTtlOffYou,
    SystemKind.ttlSetYou => l.sysTtlSetYou(ttlText(l, n('sec'))),
    // `n` arrived with the coalesced notice; rows written before it hold one.
    SystemKind.decryptFailed => l.sysDecryptFailed(m['n'] == null ? 1 : n('n')),
    SystemKind.ttlOffThem => l.sysTtlOffThem(s('name', l.sysSomeone)),
    SystemKind.ttlSetThem =>
      l.sysTtlSetThem(s('name', l.sysSomeone), ttlText(l, n('sec'))),
    SystemKind.attachmentDiscarded => l.sysAttachmentDiscarded,
    SystemKind.leftYou => l.sysLeftYou,
    SystemKind.createdYou => l.sysCreatedYou(s('name', '')),
    SystemKind.addedYou => l.sysAddedYou([
        for (final x in (m['names'] as List?) ?? const [])
          x is String ? x : l.sysAMember
      ].join(', ')),
    SystemKind.removedYou => l.sysRemovedYou(s('name', l.sysAMember)),
    SystemKind.removedFrom => l.sysRemovedFrom(s('name', '')),
    SystemKind.addedToBy =>
      l.sysAddedToBy(s('by', l.sysSomeone), s('name', '')),
    SystemKind.membershipUpdated => l.sysMembershipUpdated,
    SystemKind.memberLeft => m['name'] is String
        ? l.sysMemberLeft(m['name'] as String)
        : l.sysUnknownMemberLeft,
    // A kind this build does not know — written by a newer one. The stored
    // object is the only thing there is to show; better than nothing, and
    // it says plainly that something happened here.
    _ => body,
  };
}
