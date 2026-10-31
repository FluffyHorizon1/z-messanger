// What this device holds of the sealing keys (44.3, ADR 0033 §1, PROTOCOL
// §18.11): its own, and each one announced to it by a device it has a
// session with.
//
// Every device has one sealing key for its life — an ML-KEM-768 pair from a
// 64-byte seed (`SealingKey`) — which a `zs2.` envelope to it will one day be
// sealed to (44.7), and its account vouches for it post-quantum in `pqdc`.
// This build draws the key, gets the attestation, announces the key to every
// device it has a session with (`pqseal`) and keeps the keys announced to it;
// nothing seals to any of them yet. One use is made of them (44.5): the
// device a contact was added from is linked post-quantum when its `pqdc`
// verifies under their established ML-DSA key over the key it announced
// (`ChatService`, ADR 0033 §2). What it keeps, all of it sealed in the vault:
//
//   * `seal_seed` — this device's own seed, drawn once at the first start of
//     this build — or, on a device linked by pairing v3 (44.4), by the link
//     screen before the ceremony, which binds it — and carried in the archive
//     ([SealingKeyBackup]);
//   * `pqdc` — this device's own attestation: the root signs its own, a
//     device linked by pairing v3 is given one in its enrolment (§10.2), and
//     a device linked before that, or whose enrolment's did not verify, is
//     given one by its root over self-sync (§9, `dir:"pqdc"`); in the archive
//     beside the seed;
//   * `cseal_<rid>` — one [SealRecord] per contact: each of their devices'
//     sealing key and `pqdc` as announced, the ratchet session each came on
//     and whether the two are known to be of one state of that device, the
//     post-quantum account key the `pqid` that carried the `pqdc` named,
//     whether that device has said it holds this one's (`pqs:1`) since this
//     one gave it its key, when this one last did, and whether this one's
//     `pqdc` has reached it. Gone with the contact
//     (`ChatService.contactKvFamilies`);
//   * `oseal` — the same for this account's own other devices.
//
// Neither of the last two is in the archive. A device that lost them — a
// restore, a contact deleted and added back, a device linked again — learns
// the keys again because it opens new ratchet sessions, and a new session
// with a device forgets that the device holds this one's key
// ([DeviceSeal.holdsMine]), so each side announces again — from 4.9.0, with
// a contact's device, at once, when that device started over or had said it
// holds this one's key: what this device had announced there goes too. And
// the device that lost them takes no device's word that it holds its key
// until it has announced it there (4.8.1, [DeviceSeal.announcedMs]): a
// restore that drew a new key is told "I hold your key" of the old one, by
// devices of every build.
//
// The keys of other devices are judged here by nothing beyond FIPS 203 §7.2's
// check, which `InnerMessage.pqSealKey` applies before any key is taken;
// whether the `pqdc` of the device a contact was added from verifies under
// their established ML-DSA key, and what the screen says of it, is
// `ChatService`'s (44.5), and what it found is kept beside the contact
// (`dlink_<rid>`, which a backup and an enrolment carry). One key is more
// than announced (44.6, §20.9): a contact's device that revealed it in a
// CONNECT ceremony of version 3 gave it under the ceremony's hybrid channel,
// and once the eight digits are compared it is as authentic as they are —
// the device link is post-quantum without a `pqdc` ([DeviceSeal.byCeremony]).

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/dart.dart' show DartSha256;
import 'package:z_protocol/z_protocol.dart';

import 'vault.dart';

final Expando<Uint8List> _hashes = Expando<Uint8List>('sha256');

/// The SHA-256 of [bytes], worked out at once and kept beside them: what the
/// device link compares a key with — the hash a finding was made of
/// (`dlink_`'s `sk`), and the account key a `pqdc` came with
/// ([DeviceSeal.pqdcAccount]) — on every build of the contact screen, where
/// a [Future] will not do.
Uint8List keyHash(Uint8List bytes) => _hashes[bytes] ??=
    Uint8List.fromList(const DartSha256().hashSync(bytes).bytes);

/// What this device holds about one other device's sealing key, and what it
/// has told that device about its own.
class DeviceSeal {
  /// That device's sealing key, from its `pqseal`, taken only once FIPS 203
  /// §7.2 accepts it ([InnerMessage.pqSealKey]). Null until one arrives.
  Uint8List? ek;

  /// That device's `pqdc` (§18.11), from its `pqid` for a contact's device
  /// or over self-sync for one of mine: kept with the key, unjudged.
  Uint8List? pqdc;

  /// That device has stamped `pqs:1` on what it sent here since this device
  /// gave it its key ([announcedMs]): it holds this device's sealing key, and
  /// this device's announcements to it stop — until a new ratchet session
  /// with it begins, accepted from it or opened to it, which forgets this (a
  /// restore, a contact deleted and added back and a device linked again all
  /// open one), and they resume on their clock — at once, for a contact's
  /// device, from 4.9.0 ([announcedMs]). 4.8.1: a stamp with nothing given
  /// before it is not this ([ChatService]'s `_keepSeal`).
  bool holdsMine;

  /// When this device last gave that one its own key — announced it in a
  /// `pqseal` queued there, or (44.6) handed it over in a CONNECT ceremony of
  /// version 3's reveal — in ms since the epoch; 0 for never, and 0 again
  /// once this device draws another key, and (4.9.0, for a contact's device)
  /// once a new ratchet session with it begins after it started over or had
  /// stamped `pqs:1`. The re-announcement clock runs from here, and (4.8.1)
  /// a `pqs:1` from that device stands only beside it.
  int announcedMs;

  /// 44.6 (§20.9): [ek] came in the reveal of a CONNECT ceremony of version
  /// 3 whose eight digits this side's person compared and found matching —
  /// so it is as authentic as the digits, and the link to this device is
  /// post-quantum without a `pqdc` (ADR 0033 §4). It goes with the key: a
  /// different key from the device clears it, as it clears [pqdc].
  bool byCeremony;

  /// 4.9.0 (§18.11): the ratchet session [ek] last arrived on, and the one
  /// [pqdc] arrived on — the session ids the ratchet names them by — while
  /// nothing that device sent there since has been skipped over, lost at
  /// the relay or yet to come ([ChatService]'s `_gapOn`). What says whether
  /// the two are of one state of that device ([pqdcBound]); null for a
  /// record an older build wrote, for what came by another door than the
  /// ratchet's, and once such a gap has been read past.
  String? ekSid, pqdcSid;

  /// 4.9.0 (§18.11): [pqdc] and [ek] are known to be of one state of that
  /// device, so a `pqdc` that misses the key is evidence against it
  /// ([ChatService]'s `_judgeDeviceLink`). A device announces a key it draws
  /// ahead of the next message it sends on the session it has — a mixed one
  /// that carries no ML-KEM ciphertext — so what it sends after that key on
  /// the same session is of the key's state: a `pqdc` read after the key held,
  /// on the session the key came on, in the order it was sent. And one read
  /// before it on that session is of the key's state when the key is the
  /// first this device holds of that device, or one it held before that
  /// `pqdc` arrived. Each with nothing that device sent between the two
  /// skipped over ([ekSid]): an announcement the relay lost would lie
  /// there. Anything else may be of two states — a restore's new
  /// `pqid` can arrive before its new `pqseal`, and a device whose seed no
  /// longer reads keeps the sessions its old `pqdc` came on — and is
  /// evidence of nothing. A key that replaces the one held takes with it a
  /// `pqdc` bound to that one, which was of the state it ends.
  bool pqdcBound;

  /// 4.9.0: a key was held for that device when [pqdc] arrived, and has not
  /// been replaced since — so a re-announcement of it after the `pqdc`, on
  /// the session the `pqdc` came on, binds the two ([pqdcBound]).
  bool pqdcAfterKey;

  /// 4.9.0 (§18.11): the SHA-256 of the post-quantum account key (ML-DSA)
  /// the `pqid` that carried [pqdc] named. A `pqdc` is checked under the
  /// contact's established key; one that came with another — their account
  /// drew a new one, as a restore from a backup made before 2.2.4 or from a
  /// `.zid` does — is evidence of nothing here, and the screen says their
  /// post-quantum key changed. Null for a record an older build wrote.
  Uint8List? pqdcAccount;

  /// 44.5 (§18.11): this device's own `pqdc` has reached that device in a
  /// `pqid`, sent while that device had shown it reads one — it had
  /// announced its own key, sent its own `pqdc`, or said it holds this
  /// device's (`pqs:1`) — so the one more `pqid` is not owed to it. A device
  /// not known to read it does not spend it. Forgotten when that device next
  /// opens a ratchet session here, which a restore and a contact added back
  /// do.
  bool pqdcSent;

  DeviceSeal(
      {this.ek,
      this.pqdc,
      this.holdsMine = false,
      this.announcedMs = 0,
      this.byCeremony = false,
      this.ekSid,
      this.pqdcSid,
      this.pqdcBound = false,
      this.pqdcAfterKey = false,
      this.pqdcAccount,
      this.pqdcSent = false});

  /// Whether that device has shown it runs 44.3 or later, which keeps a
  /// `pqdc` it is sent: it announced its sealing key, its own `pqid` carried
  /// its `pqdc`, or it said it holds this device's key.
  bool get readsPqdc => ek != null || pqdc != null || holdsMine;

  Map<String, Object?> toJson() => {
        if (ek != null) 'ek': b64(ek!),
        if (pqdc != null) 'pqdc': b64(pqdc!),
        if (holdsMine) 'pqs': 1,
        if (announcedMs > 0) 'at': announcedMs,
        if (byCeremony && ek != null) 'c3': 1,
        if (ekSid != null && ek != null) 'es': ekSid,
        if (pqdcSid != null && pqdc != null) 'ds': pqdcSid,
        if (pqdcBound && pqdc != null && ek != null) 'db': 1,
        if (pqdcAfterKey && pqdc != null && ek != null) 'dk': 1,
        if (pqdcAccount != null && pqdc != null) 'da': b64(pqdcAccount!),
        if (pqdcSent) 'pd': 1,
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
    // Only beside the key it was said of.
    out.byCeremony = out.ek != null && raw['c3'] == 1;
    // Only beside what they are said of. A record from 4.8.1 or before has
    // none of them, so nothing it holds is taken as evidence against a
    // device, nor as of another account key.
    String? sid(Object? v) => v is String && v.isNotEmpty && v.length <= 64
        ? v
        : null;
    if (out.ek != null) out.ekSid = sid(raw['es']);
    if (out.pqdc != null) {
      out.pqdcSid = sid(raw['ds']);
      out.pqdcBound = out.ek != null && raw['db'] == 1;
      out.pqdcAfterKey = out.ek != null && raw['dk'] == 1;
      final da = bytes(raw['da']);
      if (da != null && da.length == 32) out.pqdcAccount = da;
    }
    out.pqdcSent = raw['pd'] == 1;
    return out;
  }
}

/// One owner's devices as [DeviceSeal]s: a contact's (`cseal_<rid>`), or this
/// account's own other devices (`oseal`).
class SealRecord {
  /// Device routing id → what is held about it.
  final Map<String, DeviceSeal> devices;

  SealRecord({Map<String, DeviceSeal>? devices})
      : devices = devices ?? <String, DeviceSeal>{};

  DeviceSeal device(String deviceRid) =>
      devices.putIfAbsent(deviceRid, DeviceSeal.new);

  String encode() => jsonEncode({
        'd': {for (final e in devices.entries) e.key: e.value.toJson()},
      });

  /// A record as [encode] wrote it; an empty one for null or anything that
  /// does not read as one.
  ///
  /// 44.3 through 4.8.1 kept one flag per contact (`"dc":1`), set by the
  /// first `pqid` carrying this device's `pqdc` that fanned out to the
  /// contact's devices — a device of theirs still on a build from before 44.3
  /// then dropped the member, and once updated was never owed it again. The
  /// record is per device now ([DeviceSeal.pqdcSent]); the old flag says
  /// nothing of which device kept the `pqdc`, so it is not read, and each of
  /// that contact's devices is owed one more `pqid` once it shows it reads
  /// one.
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
/// not. Built in 44.3, held in 4.7.1, and still held in 44.5, which reads the
/// attestation and keeps the record of it per contact device but builds no
/// pacing for the re-send. On the schedule built — one 16 384-bucket envelope
/// to every owed contact device, about two hours after a device updates — a
/// release's updates leave from 1.2 to 273 times the reference relay's
/// 256 MiB store waiting for the contacts who are offline in the worst three
/// days; riding the re-send on messages sent anyway fills that store at
/// `docs/CAPACITY.md`'s bad moment once three owed devices write to someone
/// away; and a per-device budget that fits takes 39 days or more to finish
/// (CAPACITY.md (e), "The `pqid` once more"). A contact added from 44.5 gets
/// the `pqdc` in the `pqid` its add sends, and the link ADR 0033's decision 3
/// requires rests on that; the held re-send would bring the link to contacts
/// added before, and to those whose app was older than 4.7 when they were
/// added. A `pqid` that goes for any other reason still carries the device's
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
