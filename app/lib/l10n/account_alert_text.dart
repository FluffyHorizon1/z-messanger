import 'dart:convert';

import '../core/system_messages.dart';
import 'app_localizations.dart';

/// The words for the two owner-account banners — the older-list alarm, the
/// "a list you never issued" alarm, and the "this device was removed" alarm —
/// in the reader's language, at the moment the banner is drawn.
///
/// The service stores `{"k":"own_older","sent":5,"held":7}` and the like (see
/// [OwnAlertKind]); the sentence is chosen here. A value written by an earlier
/// build is the English sentence itself — no `{`, or a JSON object with a kind
/// this build does not know — and is returned untouched, as `systemText` does:
/// these carry no name and no secret, only public version numbers, so there is
/// nothing to drop.
String _text(AppLocalizations l, String stored,
    String Function(AppLocalizations, Map<String, Object?>) render) {
  if (!stored.startsWith('{')) return stored;
  Map<String, Object?> m;
  try {
    final decoded = jsonDecode(stored);
    if (decoded is! Map || decoded['k'] is! String) return stored;
    m = decoded.cast<String, Object?>();
  } on FormatException {
    return stored;
  }
  return render(l, m);
}

int _n(Map<String, Object?> m, String key) => (m[key] as num?)?.toInt() ?? 0;

/// The `ownAccountAlert` banner (`OwnAlertKind.olderList` / `unissued`).
String ownAccountAlertText(AppLocalizations l, String stored) =>
    _text(l, stored, (l, m) => switch (m['k'] as String) {
          OwnAlertKind.olderList =>
            l.homeOwnOlderList(_n(m, 'sent'), _n(m, 'held')),
          OwnAlertKind.unissued => l.homeOwnUnissued,
          // A kind written by a newer build. The stored object says plainly
          // that something was raised here, which beats showing nothing.
          _ => stored,
        });

/// The `removedDeviceAlert` banner (`OwnAlertKind.removed`).
String removedDeviceAlertText(AppLocalizations l, String stored) =>
    _text(l, stored, (l, m) => switch (m['k'] as String) {
          OwnAlertKind.removed => l.homeRemovedDevice(_n(m, 'v')),
          _ => stored,
        });
