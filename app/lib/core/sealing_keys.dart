// What this device holds of the sealing keys (44.3, ADR 0033 §1, PROTOCOL
// §18.11): its own, and each one announced to it by a device it has a
// session with.
//
// Every device has one sealing key for its life — an ML-KEM-768 pair from a
// 64-byte seed (`SealingKey`) — which a `zs2.` envelope to it will one day be
// sealed to (44.7), and its account vouches for it post-quantum in `pqdc`.
// This build draws the key, gets the attestation, announces the key to every
// device it has a session with (`pqseal`) and keeps the keys announced to it;
// nothing uses any of them yet. What it keeps, all of it sealed in the vault:
//
//   * `seal_seed` — this device's own seed, drawn once at the first start of
//     this build and carried in the archive ([SealingKeyBackup]);
//   * `pqdc` — this device's own attestation: the root signs its own, a
//     linked device is given one by its root over self-sync (§9,
//     `dir:"pqdc"`); in the archive beside the seed;
//   * `cseal_<rid>` — one [SealRecord] per contact: each of their devices'
//     sealing key and `pqdc` as announced, whether that device has said it
//     holds this one's (`pqs:1`) and when this one last announced its own to
//     it. Gone with the contact (`ChatService.contactKvFamilies`);
//   * `oseal` — the same for this account's own other devices.
//
// Neither of the last two is in the archive. A device that lost them — a
// restore, a contact deleted and added back, a device linked again — learns
// the keys again because it opens new ratchet sessions, and a new session
// with a device forgets that the device holds this one's key
// ([DeviceSeal.holdsMine]), so each side announces again.
//
// The keys of other devices are judged by nothing here beyond FIPS 203 §7.2's
// check, which `InnerMessage.pqSealKey` applies before any key is taken:
// whether a `pqdc` verifies under a contact's established ML-DSA key, and what
// the screen says about it, is 44.5.

import 'dart:convert';
import 'dart:typed_data';

import 'package:z_protocol/z_protocol.dart';

import 'vault.dart';

/// What this device holds about one other device's sealing key, and what it
/// has told that device about its own.
class DeviceSeal {
  /// That device's sealing key, from its `pqseal`, taken only once FIPS 203
  /// §7.2 accepts it ([InnerMessage.pqSealKey]). Null until one arrives.
  Uint8List? ek;

  /// That device's `pqdc` (§18.11), from its `pqid` for a contact's device
  /// or over self-sync for one of mine: kept with the key, unjudged.
  Uint8List? pqdc;

  /// That device has stamped `pqs:1` on what it sent here: it holds this
  /// device's sealing key, and this device's announcements to it stop —
  /// until a new ratchet session with it begins, accepted from it or opened
  /// to it, which forgets this (a restore, a contact deleted and added back
  /// and a device linked again all open one), and they resume on their
  /// clock.
  bool holdsMine;

  /// When this device last announced its own key to that one, in ms since
  /// the epoch; 0 for never. The re-announcement clock runs from here.
  int announcedMs;

  DeviceSeal(
      {this.ek, this.pqdc, this.holdsMine = false, this.announcedMs = 0});

  Map<String, Object?> toJson() => {
        if (ek != null) 'ek': b64(ek!),
        if (pqdc != null) 'pqdc': b64(pqdc!),
        if (holdsMine) 'pqs': 1,
        if (announcedMs > 0) 'at': announcedMs,
      };

  /// Each member held to the shape it must have — a key FIPS 203 §7.2
  /// accepts, an attestation of its length — and left out otherwise: the
  /// vault is sealed, but what is read at start-up is not trusted blindly.
  static DeviceSeal fromJson(Object? raw) {
    final out = DeviceSeal();
    if (raw is! Map) return out;
    Uint8List? bytes(Object? v) {
      if (v is! String) return null;
      try {
        return unb64(v);
      } on FormatException {
        return null;
      }
    }

    final ek = bytes(raw['ek']);
    if (ek != null && mlKemEncapsulationKeyValid(ek)) out.ek = ek;
    final pqdc = bytes(raw['pqdc']);
    if (pqdc != null && pqdc.length == deviceAttestationBytes) out.pqdc = pqdc;
    out.holdsMine = raw['pqs'] == 1;
    final at = raw['at'];
    if (at is int && at > 0) out.announcedMs = at;
    return out;
  }
}

/// One owner's devices as [DeviceSeal]s: a contact's (`cseal_<rid>`), or this
/// account's own other devices (`oseal`).
class SealRecord {
  /// Device routing id → what is held about it.
  final Map<String, DeviceSeal> devices;

  /// A contact's record only: this device's own `pqdc` has gone to them in a
  /// `pqid` (§18.11), so the one more `pqid` a contact that already held the
  /// account's key is owed has been sent, or was never owed.
  bool pqdcSent;

  SealRecord({Map<String, DeviceSeal>? devices, this.pqdcSent = false})
      : devices = devices ?? <String, DeviceSeal>{};

  DeviceSeal device(String deviceRid) =>
      devices.putIfAbsent(deviceRid, DeviceSeal.new);

  String encode() => jsonEncode({
        'd': {for (final e in devices.entries) e.key: e.value.toJson()},
        if (pqdcSent) 'dc': 1,
      });

  /// A record as [encode] wrote it; an empty one for null or anything that
  /// does not read as one.
  static SealRecord decode(String? text) {
    if (text == null) return SealRecord();
    try {
      final j = jsonDecode(text);
      if (j is! Map) return SealRecord();
      final d = j['d'];
      return SealRecord(
        devices: {
          if (d is Map)
            for (final e in d.entries)
              if (e.key is String) e.key as String: DeviceSeal.fromJson(e.value)
        },
        pqdcSent: j['dc'] == 1,
      );
    } on FormatException {
      return SealRecord();
    }
  }
}

/// Whether a `pqseal` may ride the next message on [conv] (§18.11), on any
/// channel — a contact's device, a contact's other device, or one of this
/// account's own: that message is mixed (`pq:1`), and its ratchet header
/// carries no ML-KEM ciphertext. Beside `pqct` a `pqseal` is a 16 384-bucket
/// envelope rather than a 4 096-bucket one, so it never rides such a message
/// and waits for the next that carries none (Finnian's decision of
/// 2026-10-20) — the encapsulating side's, after its peer's first mixed
/// message has arrived, and after each re-key once the peer mixes again.
bool pqSealMayRide(Conversation conv) =>
    conv.nextSendIsPostQuantum && !conv.nextSendCarriesPqCiphertext;

/// Whether this build sends its `pqdc` to the contacts that already held the
/// account's post-quantum key — the `pqid` once more, §18.11 — and it does
/// not: built in 44.3 and held until 44.5, which reads the attestation and
/// paces the re-send. Turned on as it stood, every device sends one
/// 16 384-bucket envelope to every such contact device about two hours after
/// it updates, and the relay holds each for a contact who is offline: a wave
/// across a whole user base at once, for an attestation nothing reads before
/// 44.5. A `pqid` that goes for any other reason still carries the device's
/// `pqdc`. Tests turn the re-send on through `ChatService.init`.
const bool pqdcResendsEnabled = false;

/// The vault key of this device's own sealing seed, and of its `pqdc`.
const String sealSeedKey = 'seal_seed';
const String ownPqdcKey = 'pqdc';

/// A sealing key's seed: `d || z`, FIPS 203's `KeyGen_internal` inputs.
const int sealSeedBytes = 64;

/// This device's own sealing key in the archive (ADR 0025): a record of its
/// own, marked [ZArchive.keepField], so a build from before 44.3 keeps it on
/// a restore and writes it back into every archive it makes — "fields added
/// to a known record are not carried". A restore that drew a new key would
/// leave every contact sealing to one nobody holds once `zs2.` is on.
///
/// ```
/// {"t":"seal","keep":1,"v":1,"seed":b64(64 bytes)[,"pqdc":b64(3 309 bytes)]}
/// ```
abstract final class SealingKeyBackup {
  static const String recordType = 'seal';

  /// The record, or null when this vault holds no sealing key (a build from
  /// before 44.3 wrote it, and nothing since has started on it).
  static Future<Map<String, Object?>?> export(Vault vault) async {
    final seed = await vault.kvGet(sealSeedKey);
    if (seed == null) return null;
    final pqdc = await vault.kvGet(ownPqdcKey);
    return {
      't': recordType,
      ZArchive.keepField: 1,
      'v': 1,
      'seed': seed,
      if (pqdc != null) 'pqdc': pqdc,
    };
  }

  /// The `kv` rows a restore writes for [record]: the seed when it is 64
  /// bytes, and the `pqdc` beside it when it is 3 309 — an archive is a file
  /// that can come from anywhere. Whether the `pqdc` is this device's is
  /// checked at the first start, with the key the seed makes
  /// (`ChatService`), and one that is not is dropped there.
  static Map<String, String> restore(Map<String, Object?> record) {
    final out = <String, String>{};
    if (record['t'] != recordType || record['v'] != 1) return out;
    final seed = _decoded(record['seed']);
    if (seed == null || seed.length != sealSeedBytes) return out;
    out[sealSeedKey] = b64(seed);
    final pqdc = _decoded(record['pqdc']);
    if (pqdc != null && pqdc.length == deviceAttestationBytes) {
      out[ownPqdcKey] = b64(pqdc);
    }
    return out;
  }

  /// A build from before 44.3 that restored an archive this one made kept
  /// the record, unread, among the ones it writes back ([keptKey]). The first
  /// start of this build on that vault takes the key from it instead of
  /// drawing a new one — the same key, so contacts that hold it go on
  /// holding the one this device holds — and takes the record out of the
  /// kept ones, since the vault now carries it. Whether anything was taken.
  static Future<bool> adoptKept(Vault vault, String keptKey) async {
    final kept = await vault.kvGet(keptKey);
    if (kept == null) return false;
    final List<String> texts;
    try {
      texts = (jsonDecode(kept) as List).cast<String>();
    } catch (_) {
      return false;
    }
    for (var i = 0; i < texts.length; i++) {
      Map<String, Object?> r;
      try {
        r = (jsonDecode(texts[i]) as Map).cast<String, Object?>();
      } catch (_) {
        continue;
      }
      final rows = restore(r);
      if (rows.isEmpty) continue;
      await vault.db.transaction((txn) async {
        for (final e in rows.entries) {
          await vault.kvPut(e.key, e.value, txn: txn);
        }
        final rest = [...texts]..removeAt(i);
        if (rest.isEmpty) {
          for (final p in const ['s:', 'p:']) {
            await txn.delete('kv', where: 'k = ?', whereArgs: ['$p$keptKey']);
          }
        } else {
          await vault.kvPut(keptKey, jsonEncode(rest), txn: txn);
        }
      });
      return true;
    }
    return false;
  }

  static Uint8List? _decoded(Object? v) {
    if (v is! String) return null;
    try {
      return unb64(v);
    } on FormatException {
      return null;
    }
  }
}
