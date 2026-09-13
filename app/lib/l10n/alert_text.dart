import 'dart:convert';

import '../core/system_messages.dart';
import 'app_localizations.dart';

/// The words for a device-list alert, in the user's language, at the moment
/// it is shown — and with the contact's name supplied by the caller rather
/// than read out of the vault's `kv` table, where it used to live unsealed.
///
/// See [DevlistAlertKind]. [stored] is the value the service holds; [name] is
/// the contact the banner is about.
String devlistAlertText(AppLocalizations l, String stored, String name) {
  if (!stored.startsWith('{')) return stored;
  Map<String, Object?> m;
  try {
    final decoded = jsonDecode(stored);
    if (decoded is! Map || decoded['k'] is! String) return stored;
    m = decoded.cast<String, Object?>();
  } on FormatException {
    return stored;
  }
  return switch (m['k'] as String) {
    DevlistAlertKind.conflict => l.alertDlConflict(name),
    DevlistAlertKind.rollback => l.alertDlRollback(name),
    DevlistAlertKind.unconfirmed => l.alertDlUnconfirmed(name),
    DevlistAlertKind.missingUpdate => l.alertDlMissingUpdate(name),
    DevlistAlertKind.pqSignatureMissing => l.alertDlPqMissing(name),
    // A kind written by a newer build. Showing the object is better than
    // showing nothing: it says plainly that something was raised here.
    _ => stored,
  };
}
