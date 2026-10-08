/// The evidence behind an alarm about this account itself (ADR 0026).
///
/// Four banners speak to the owner about their own account — a list a
/// contact was given that this device never issued, an older list from the
/// account's own root, this device removed from the account, and a list in
/// the transparency log this device never issued — and three of them tell the
/// user to reset their identity. Each is raised only on evidence that nobody
/// but whoever holds the account's key can produce: a device list that
/// verifies under that key. What the evidence is, for each, is in
/// `chat_service.dart` and `key_transparency.dart`; what lives here is the
/// one rule they share about dismissing one.
///
/// **A dismissal is of the evidence on the screen.** Until 2026-10-04 a
/// dismissed banner came back with the next message that carried the same
/// claim, the next reconnect that re-asserted the same list, the next check
/// of the log that read the same entry — so a contact could raise one again
/// with every message, and a vault the own-list race had damaged showed the
/// log's banner at every start, however often it was put away. Each alarm is
/// now keyed by what it was raised on (its kind, the list's version and its
/// fingerprint), the user's dismissal records that key, and the same key
/// never raises the same alarm again — across restarts, since the record is
/// in the vault. Different evidence is a different key, and raises it.
library;

import 'dart:convert';

import 'vault.dart';

/// "A contact was given a list for this account that this device never
/// issued" (`OwnAlertKind.unissued`), raised on that list.
String unissuedEvidence(int version, String fpB64) => 'list|$version|$fpB64';

/// "This device was removed" (`OwnAlertKind.removed`), raised on the list
/// that omits it.
String removalEvidence(int version, String fpB64) =>
    'removed|$version|$fpB64';

/// "Your main device published an older list" (`OwnAlertKind.olderList`),
/// raised on the list the root sent and the version this device held.
String olderListEvidence(int sentVersion, String sentFpB64, int heldVersion) =>
    'older|$sentVersion|$sentFpB64|$heldVersion';

/// The log holds a list for this account that this device never issued
/// (`KeyTransparency.ownAlert`), raised on that entry.
String logEntryEvidence(int version, String fpB64) => 'log|$version|$fpB64';

/// The evidence keys of every own-account alarm the user has dismissed.
///
/// Sealed like any other `kv` value: what it holds is public (versions and
/// fingerprints of this account's own lists), but nothing about it needs to
/// be in the clear, and a key off `Vault.plainKeys` cannot be written there.
/// Bounded, oldest out: only the user adds to it, by dismissing, and a
/// dismissal old enough to fall off costs at most one more banner if the same
/// evidence ever turns up again.
class OwnAlarmDismissals {
  OwnAlarmDismissals(this._vault);

  final Vault _vault;

  static const String vaultKey = 'own_alarm_dismissed';
  static const int cap = 256;

  final List<String> _keys = [];

  Future<void> load() async {
    final stored = await _vault.kvGet(vaultKey);
    if (stored == null) return;
    try {
      _keys
        ..clear()
        ..addAll((jsonDecode(stored) as List).whereType<String>());
    } catch (_) {
      // A record this build cannot read dismisses nothing.
    }
  }

  bool contains(String evidence) => _keys.contains(evidence);

  Future<void> add(String evidence) async {
    if (_keys.contains(evidence)) return;
    _keys.add(evidence);
    while (_keys.length > cap) {
      _keys.removeAt(0);
    }
    await _vault.kvPut(vaultKey, jsonEncode(_keys));
  }
}
