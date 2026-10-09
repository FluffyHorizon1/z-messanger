import 'dart:convert';

import '../core/system_messages.dart';
import 'app_localizations.dart';

/// The words for a device-list alert, in the user's language, at the moment
/// it is shown — and with the contact's name supplied by the caller rather
/// than read out of the vault's `kv` table, where it used to live unsealed.
///
/// See [DevlistAlertKind]. [stored] is the value the service holds; [name] is
/// the contact the banner is about. [nameOf] turns the routing id of a SECOND
/// contact into a name, for the two kinds that name two people
/// ([DevlistAlertKind.sharedDevice], [DevlistAlertKind.claimedDevice]); the
/// vault holds that contact's routing id, never their name.
String devlistAlertText(AppLocalizations l, String stored, String name,
    {String? Function(String rid)? nameOf}) {
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
    DevlistAlertKind.sharedDevice => switch (m['with'] is String
        ? nameOf?.call(m['with'] as String)
        : null) {
        final String other => l.alertDlShared(name, other),
        // The other contact has been deleted (the alert no longer names
        // them), or the caller cannot say who they are.
        null => l.alertDlSharedAnother(name),
      },
    DevlistAlertKind.sharedWithMe => l.alertDlSharedMine(name),
    // ADR 0022: the device proved whose it is, so this one names the list
    // that is wrong rather than accusing neither.
    DevlistAlertKind.claimedDevice => switch (m['with'] is String
        ? nameOf?.call(m['with'] as String)
        : null) {
        final String other => l.alertDlClaimed(name, other),
        null => l.alertDlClaimedAnother(name),
      },
    // A kind written by a newer build. Showing the object is better than
    // showing nothing: it says plainly that something was raised here.
    _ => stored,
  };
}
