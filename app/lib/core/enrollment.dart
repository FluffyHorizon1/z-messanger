// What a newly linked device does with its enrolment (PROTOCOL §10, phase 33).
//
// The host is the account's root, the channel is the one both screens'
// digits confirmed, and the new device adopts its account from this same
// payload, so it trusts what the payload says about each contact as much as
// it trusts the account itself. Until phase 33 it kept, of each contact, a
// routing id, the scanned device's keys and a name — and dropped the
// account key and certificate that were in front of it, while the
// post-quantum commitment and key, the records kept beside them, the tick
// and the contact's device list were never sent at all. So a laptop showed
// every contact a person had verified on their phone as unverified, a
// different safety number for every contact added from someone's laptop,
// classical where the phone was post-quantum, and refused every device list
// those contacts' accounts signed (the 2026-10-03 analysis, P1-5).
//
// Every record is still checked before it is believed, as a restored
// archive's are (`archive.dart`): it describes the contact the account
// bundle beside it names, every key is the length it must be, a key is the
// one its commitment commits to, a list verifies under the contact's
// account. A record that fails is not installed; the contact is then
// installed from its account bundle alone, which is what a host that
// predates the record sends.
//
// Since 44.4 the ceremony is pairing v3 (§10.2, ADR 0033 §3), on both sides,
// and nothing older: [NewDeviceLink] is this device's side of it. The new
// device draws its sealing key before the ceremony — the commitment, the
// opening and the digits all carry its hash `sk`, and the root signs this
// device's `pqdc` over it — and [installEnrollment] keeps the key and the
// `pqdc` that verifies for it.

import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/foundation.dart' show visibleForTesting;
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:z_protocol/z_protocol.dart';

import 'archive.dart' show BackupArchive;
import 'sealing_keys.dart' show ownPqdcKey, sealSeedKey;
import 'vault.dart';

/// The new device's side of linking (PROTOCOL §10.2, 44.4): this device's
/// sealing key, and the ceremony's initiator — the pairing code the screen
/// shows, this device's keys, and the ML-KEM key the ceremony decapsulates
/// with once.
///
/// The sealing key is drawn here, before the ceremony, because the ceremony
/// binds it: the commitment, the opening and the digits carry `sk`, its hash,
/// and the root signs this device's `pqdc` over that hash. It is the
/// device's key for its life ([installEnrollment] keeps it), and the same
/// for every attempt. The initiator is not: once its KEM key has
/// decapsulated (§10.2 rule 5) it is spent, and the next attempt is a new
/// ceremony under a new code, the spent initiator dropped with its key.
/// Until then an attempt that heard nothing is tried again on the same code,
/// as the person may already have typed it on the other device.
class NewDeviceLink {
  NewDeviceLink._(this.sealingKey, this._v3, this._v2);

  /// This device's sealing key (ADR 0033 §1).
  final SealingKey sealingKey;

  PairingInitiatorV3? _v3;
  final PairingInitiatorV2? _v2;

  /// A new device's side of a link, with its sealing key drawn.
  static Future<NewDeviceLink> create() async {
    final key = SealingKey.generate();
    return NewDeviceLink._(
        key, await PairingInitiatorV3.create(sealKey: key.ek), null);
  }

  /// Test seam: the new device as a build from before 44.4 is one — it runs
  /// pairing v2 (§10.1), whose ceremony carries no sealing key and no
  /// `pqdc`. What a host of this build makes of it is the case it models.
  @visibleForTesting
  static Future<NewDeviceLink> createAsVersion2() async => NewDeviceLink._(
      SealingKey.generate(), null, await PairingInitiatorV2.create());

  /// The pairing code to show, for the person to enter on the other device.
  String get code => (_v3?.code ?? _v2!.code).text;

  /// Runs one attempt over [relayUrl]: the enrolment, or null when the person
  /// said the digits differ. Throws what the ceremony throws — among them
  /// [PairingNoAnswer] when nothing answered, most likely an existing device
  /// on an older version (§10.2 rule 6). Afterwards [code] is a new one if
  /// this attempt's KEM key was spent, or if someone else holding the code
  /// took its mailbox over ([PairingTakenOver]).
  ///
  /// [install], when given, keeps the enrolment — the link screen installs
  /// it into this device's vault ([installEnrollment]) — before the ceremony
  /// acknowledges it: the existing device lists this one on that
  /// acknowledgement, so it then means this device holds its account, and an
  /// install that fails leaves this device unlisted. [margin] is what the
  /// enrolment is allowed beyond [timeout] to arrive in
  /// (`RelayPairing.enrolmentMargin`).
  ///
  /// [cancel] stops the attempt — the link screen stops it when its person
  /// leaves it — until it begins to install the enrolment, after which it
  /// runs to its end ([PairingCancel], `RelayPairing.runNewDeviceV3`).
  Future<PairingResult?> run({
    required String relayUrl,
    required Future<bool> Function(String sas) confirm,
    Duration timeout = const Duration(seconds: 40),
    Duration margin = RelayPairing.enrolmentMargin,
    Future<void> Function(PairingResult result)? install,
    PairingCancel? cancel,
  }) async {
    final v2 = _v2;
    if (v2 != null) {
      final result = await RelayPairing.runNewDeviceV2(
          relayUrl: relayUrl, n: v2, confirm: confirm, timeout: timeout);
      if (result != null && install != null) await install(result);
      return result;
    }
    final n = _v3!;
    var known = false;
    try {
      return await RelayPairing.runNewDeviceV3(
          relayUrl: relayUrl,
          n: n,
          confirm: confirm,
          timeout: timeout,
          margin: margin,
          install: install,
          cancel: cancel);
    } on PairingTakenOver {
      // Someone else holds this code: another connection logged in as its
      // mailbox. The next attempt is a new ceremony whatever was spent.
      known = true;
      rethrow;
    } finally {
      if (n.opened || known) {
        _v3 = await PairingInitiatorV3.create(sealKey: sealingKey.ek);
      }
    }
  }
}

/// What `ChatService.hostDeviceLink` throws for a code it will not use: one
/// it saw taken over while it hosted a link with it, when someone else
/// holding the code logged in as its mailbox (§10.2, [PairingTakenOver]).
/// Whoever did that still has the code, so the person is told to get a new
/// one from the new device. Nothing is sent.
class PairingCodeSpent implements Exception {
  const PairingCodeSpent();
  @override
  String toString() => 'PairingCodeSpent: this device saw this code taken '
      'over, and will not use it again';
}

/// What `ChatService.hostDeviceLink` throws for a code whose link on this
/// device ended without linking once the relay had taken its reply to the
/// new device — stopped, the digits said to differ, a wait run out, a
/// connection dropped: the new device can hold that answer and takes no
/// other (§10.2 rule 5), so the code has no ceremony left, and the new device
/// shows a new one once it gives up. Said at once, where the call used to
/// wait out its timer for a commitment that would not come. Nothing is sent.
class PairingCodeAnswered implements Exception {
  const PairingCodeAnswered();
  @override
  String toString() => 'PairingCodeAnswered: a link on this device that did '
      'not finish had answered the new device with this code';
}

/// The per-contact `kv` families an enrolment carries (§10 `cstate`): the
/// three post-quantum records (ADR 0027, 26.3), the contact's device list,
/// the signature floor it has reached and the list's post-quantum
/// signature; and (44.5) whether the host added the contact on 44.5 or
/// later, and what it found of the device they were added from. Not the
/// versions beside them, which the new device reads off the list and the
/// signature themselves ([_kvOf]); not what is a device's own to observe —
/// what the contact's devices claimed, the log's standing, alarms, when the
/// chat was last opened; and not `cdev_at_`, which is when a list arrived
/// HERE and is written as now.
///
/// 44.5 (ADR 0033 decision 3): the new device takes the first from here, and
/// marks none itself: every contact in an enrolment was added on the host,
/// before the link, so one the host added before 44.5 stays one whose link
/// is said and asks nothing, and one it added since asks for the link here
/// too. The second is the host's judgement, taken as its tick is: on the
/// channel both screens confirmed, from the device the new one takes its
/// whole account from. Neither travels in a `cadd`, which any linked device
/// can send: a contact mirrored here is added by this device itself.
const List<String> enrollmentKvFamilies = [
  'pqcs_', 'vpqc_', 'pqcc_', 'cdev_', 'cdev_sigfloor_', 'cdev_pq_',
  'dlreq_', 'dlink_',
];

/// The vault key under which a linked device keeps its account's root
/// bundle (§8.1, §10 `hostbundle`).
const String rootBundleKey = 'root_bundle';

/// Install [result] — the account, this device's certificate, the device
/// that linked it and every contact — into [vault], a fresh vault on the new
/// device, before its `ChatService` starts. The relay address is not stored
/// here: the screen that asked the user about it stores it (`setRelayUrl`).
///
/// [sealingKey] is the key the ceremony ran with ([NewDeviceLink]): kept as
/// this device's (`seal_seed`), so its first start draws none, and the
/// enrolment's `pqdc` is checked against it (§10.2 rule 7). One that
/// verifies, under the account's ML-DSA key the enrolment carries, for the
/// account, this device's two keys and this key, is held (`pqdc`); one that
/// does not is refused, and nothing else with it: the account, the
/// certificate and the contacts are each checked on their own, and this
/// device then asks its root for its `pqdc` over self-sync, as a device
/// linked before 44.4 does (§9, `dir:"pqdc"`).
///
/// All of it is one transaction, and `identity` its last write: a vault
/// that holds an identity is a device that is set up, and its next start
/// opens the account rather than onboarding (`main.dart`). Every row used to
/// be written on its own, the identity first, so an install that failed
/// part-way — storage full, a write the vault refused — left a vault that
/// started as a linked device, with the account and not all of its
/// contacts, on an account that never listed it. It now leaves nothing of
/// the account: the link screen says it could not install, and the next
/// attempt starts again on a vault with no identity.
Future<void> installEnrollment(Vault vault, PairingResult result,
    {SealingKey? sealingKey}) async {
  final acct = result.account;
  final data = result.data;
  // Nothing inside reaches for `vault.db`, which waits for this transaction:
  // every write goes through `txn`, and what is worked out between them —
  // sealing, checking each record — reads nothing from the vault.
  await vault.db.transaction((txn) async {
    await vault.kvPut('account', jsonEncode(acct.toJson()), txn: txn);
    if (sealingKey != null) {
      await vault.kvPut(sealSeedKey, b64(sealingKey.seed), txn: txn);
      if (enrolmentAttestsMe(data, acct, sealingKey)) {
        await vault.kvPut(ownPqdcKey, b64(data.pqdc!), txn: txn);
      }
    }
    await vault.kvPut('display_name', data.displayName ?? 'Me', txn: txn);
    // Remember the device that linked us, so our messages mirror back to it.
    await vault.kvPut(
        'my_devices', jsonEncode([data.hostDeviceCert.toJson()]),
        sensitive: false, txn: txn);
    final root = data.hostBundle;
    if (root != null &&
        await isRootBundle(root, data.accountEdPub, data.hostDeviceCert)) {
      await vault.kvPut(rootBundleKey, jsonEncode(root.toJson()), txn: txn);
    }
    await _installContacts(vault, txn, data);
    await vault.kvPut(
        'identity',
        jsonEncode({
          'edSeed': b64(acct.deviceEdSeed),
          'xSeed': b64(acct.deviceXSeed)
        }),
        txn: txn);
  });
}

/// [installEnrollment]'s contacts, each as the phone holds it when its
/// record checks out and from its account bundle alone when not, written
/// through [txn].
Future<void> _installContacts(
    Vault vault, DatabaseExecutor txn, EnrollmentData data) async {
  final state = <String, Map<String, Object?>>{
    for (final r in data.contactState ?? const <Map<String, Object?>>[])
      r['rid'] as String: r
  };
  final now = DateTime.now().millisecondsSinceEpoch;
  for (final b in data.contacts) {
    if (b.devices.isEmpty) continue;
    final dev = b.devices.first;
    final rid = b64url(await sha256Bytes(dev.deviceEdPub));
    final fromBundle = await _fromAccountBundle(b, dev);
    if (fromBundle == null) continue;
    final record = state[rid];
    final full = record == null
        ? null
        : await _fromRecord(record, rid, b, dev, fromBundle, now);
    await txn.insert(
        'contacts',
        {
          'rid': rid,
          'enc_bundle':
              await vault.seal(jsonEncode((full?.bundle ?? fromBundle.bundle)
                  .toJson())),
          'enc_name': await vault.seal(
              full?.name ?? b.displayName ?? 'Unknown'),
          'ttl_seconds': full?.ttl ?? 0,
          // The tick and the number it was given on (13.3), as a restore
          // writes them: a tick with no number is backfilled at start, as
          // on the host.
          'verified': (full?.verified ?? false) ? 1 : 0,
          'verified_sn': (full?.verified ?? false) ? full!.verifiedSn : null,
          'created_ms': full?.createdMs ?? now,
          if (fromBundle.acct != null) 'acct_ed': b64(fromBundle.acct!),
          if (fromBundle.cert != null)
            'dev_cert': jsonEncode(fromBundle.cert!.toJson()),
          if (full?.pqCommit != null) 'pq_commit': b64(full!.pqCommit!),
          if (full?.pqPub != null)
            'enc_pq_pub': await vault.seal(b64(full!.pqPub!)),
          if (full?.pqCandidate != null)
            'enc_pq_cand': await vault.seal(b64(full!.pqCandidate!)),
          'pq_acked': (full?.pqAcked ?? false) ? 1 : 0,
          'pq_told': (full?.pqTold ?? false) ? 1 : 0,
          if (full?.pqMismatch ?? false) 'pq_mismatch': 1,
          if (full?.addedBy != null) 'added_by': full!.addedBy,
          'requested': (full?.requested ?? false) ? 1 : 0,
        },
        conflictAlgorithm: ConflictAlgorithm.replace);
    for (final e in (full?.kv ?? const <String, String>{}).entries) {
      final key = '${e.key}$rid';
      await vault.kvPut(key, e.value,
          sensitive: !Vault.mayBePlain(key), txn: txn);
    }
  }
}

/// Whether the enrolment [data] carries a `pqdc` that is the account's
/// attestation of [key] as the sealing key of [me], this device (§18.11):
/// it verifies under the account's ML-DSA key the enrolment carries
/// (`pqpub`), over the account key, this device's two keys as its
/// certificate names them, and [key]. The root signed it over `sk`, the hash
/// the digits covered; checking it with the key itself is FIPS 203 §7.2's
/// check of the key too. False when either is absent: an enrolment from a
/// host with no ML-DSA key carries neither.
bool enrolmentAttestsMe(
    EnrollmentData data, AccountIdentity me, SealingKey key) {
  final pqdc = data.pqdc;
  final ml = data.accountMlPub;
  if (pqdc == null || ml == null) return false;
  return deviceAttestationValid(
      accountMlPub: ml,
      accountEdPub: data.accountEdPub,
      deviceEdPub: me.deviceEdPub,
      deviceXPub: me.deviceXPub,
      sealEk: key.ek,
      pqdc: pqdc);
}

/// Whether [root] is the bundle of the device [hostCert] certifies as the
/// root of the account [accountEdPub]: its key IS the account key, its
/// ratchet key is the certificate's, and it binds that key itself.
Future<bool> isRootBundle(ContactBundle root, Uint8List accountEdPub,
    DeviceCertificate hostCert) async {
  if (!constantTimeEquals(root.edPub, accountEdPub)) return false;
  if (!constantTimeEquals(hostCert.deviceEdPub, accountEdPub) ||
      !constantTimeEquals(hostCert.deviceXPub, root.xPub)) {
    return false;
  }
  return root.verify();
}

/// What the account bundle alone says about a contact — all that a host
/// that predates `cstate` sends, and what every contact falls back to. The
/// device's keys and, when the certificate is a real one, the account it
/// proves the device belongs to: the account key and certificate were
/// always in the enrolment, and were dropped until phase 33. A legacy
/// record is a device that IS its account (§3.5), and its signature is the
/// device's own binding signature, so the bundle is exact; a real
/// certificate's signature is the account's, and the device's own binding
/// signature is not in the account bundle at all — a host from before
/// `cstate` cannot supply it, and the bundle then carries the certificate's
/// signature in its place, as every enrolment did.
Future<({ContactBundle bundle, Uint8List? acct, DeviceCertificate? cert})?>
    _fromAccountBundle(AccountBundle b, DeviceCertificate dev) async {
  if (dev.deviceEdPub.length != 32 || dev.deviceXPub.length != 32) {
    return null;
  }
  final bundle = ContactBundle(
      edPub: dev.deviceEdPub, xPub: dev.deviceXPub, bindingSig: dev.sig);
  if (dev.legacy ||
      constantTimeEquals(dev.deviceEdPub, b.accountEdPub) ||
      b.accountEdPub.length != 32 ||
      !await dev.verify(b.accountEdPub)) {
    return (bundle: bundle, acct: null, cert: null);
  }
  return (bundle: bundle, acct: b.accountEdPub, cert: dev);
}

typedef _Record = ({
  ContactBundle bundle,
  String? name,
  int ttl,
  bool verified,
  String? verifiedSn,
  int? createdMs,
  Uint8List? pqCommit,
  Uint8List? pqPub,
  Uint8List? pqCandidate,
  bool pqAcked,
  bool pqTold,
  bool pqMismatch,
  String? addedBy,
  bool requested,
  Map<String, String> kv,
});

/// A record's `kv` member, family by family, each held to the shape a
/// restore insists on ([BackupArchive.contactValueOk]).
///
/// What a list is worth is read off the list, not off the numbers beside it:
/// its version is the list's own, a floor above it is not believed, a floor
/// below what the list itself carries (`sig2`/`sig3`) is raised to it, and
/// the post-quantum signature's version is the signature's own. A version or
/// floor with no list behind it would refuse, as a replay, every list the
/// contact's account signs below it — the very lists this device must take.
Future<Map<String, String>> _kvOf(
    Object? raw, Uint8List account, int now) async {
  final kv = <String, String>{};
  if (raw is! Map) return kv;
  Future<String?> ok(String f) async {
    final v = raw[f];
    return v is String && await BackupArchive.contactValueOk(f, v, account)
        ? v
        : null;
  }

  for (final f in const ['pqcs_', 'vpqc_', 'pqcc_', 'dlreq_', 'dlink_']) {
    final v = await ok(f);
    if (v != null) kv[f] = v;
  }
  // Each value is parsed again below, after [ok] has parsed it once: one that
  // does not parse — which [ok] already refuses, so nothing reaches here that
  // way — is left out as [ok] leaves it out, rather than thrown out of the
  // enrolment (the 2026-10-28 review's F3).
  final listJson = await ok('cdev_');
  final list = listJson == null ? null : _parsedOrNull(listJson,
      (j) => SignedDeviceList.fromJson(j));
  if (listJson != null && list != null) {
    kv['cdev_'] = listJson;
    kv['cdev_ver_'] = '${list.version}';
    // A list installed as one that arrived now: the log's grace for it runs
    // from here, as for any list this device installs.
    kv['cdev_at_'] = '$now';
    var floor = int.tryParse(await ok('cdev_sigfloor_') ?? '') ?? 0;
    if (floor > list.version) floor = 0;
    if ((list.sig2 != null || list.sig3 != null) && list.version > floor) {
      floor = list.version;
    }
    if (floor > 0) kv['cdev_sigfloor_'] = '$floor';
  }
  final sigJson = await ok('cdev_pq_');
  final sig = sigJson == null ? null : _parsedOrNull(sigJson,
      (j) => HybridDeviceListSignature.fromJson(j));
  if (sigJson != null && sig != null) {
    if (constantTimeEquals(sig.accountEdPub, account)) {
      kv['cdev_pq_'] = sigJson;
      kv['cdev_pq_ver_'] = '${sig.version}';
    }
  }
  return kv;
}

/// [json] parsed as an object and read by [read], or null for anything that
/// is not one it reads — whatever the parser throws for it.
T? _parsedOrNull<T>(String json, T Function(Map<String, Object?> j) read) {
  try {
    final j = jsonDecode(json);
    return j is Map ? read(j.cast<String, Object?>()) : null;
  } catch (_) {
    return null;
  }
}

/// A `cstate` record, checked against the contact the account bundle beside
/// it describes. Null when it does not describe that contact; a member that
/// is malformed is left out, as a restore leaves one out.
Future<_Record?> _fromRecord(
    Map<String, Object?> r,
    String rid,
    AccountBundle b,
    DeviceCertificate dev,
    ({ContactBundle bundle, Uint8List? acct, DeviceCertificate? cert}) base,
    int now) async {
  final ContactBundle bundle;
  try {
    bundle = ContactBundle.fromJson((r['bundle'] as Map).cast<String, Object?>());
  } catch (_) {
    return null;
  }
  // The scanned device the account bundle names, and nothing else: the
  // routing id, both keys, and — for a device that is its own account,
  // whose certificate IS its binding signature — that signature too.
  if (r['rid'] != rid ||
      !constantTimeEquals(bundle.edPub, dev.deviceEdPub) ||
      !constantTimeEquals(bundle.xPub, dev.deviceXPub) ||
      (base.cert == null &&
          !constantTimeEquals(bundle.bindingSig, base.bundle.bindingSig))) {
    return null;
  }
  final account = base.acct ?? bundle.edPub;
  Uint8List? bytes(Object? v, int length) {
    if (v is! String) return null;
    try {
      final out = unb64(v);
      return out.length == length ? out : null;
    } catch (_) {
      return null;
    }
  }

  final pqCommit = bytes(r['pqc'], 32);
  var pqPub = bytes(r['pqk'], mlDsaPublicKeyBytes);
  final pqCandidate = bytes(r['pqcand'], mlDsaPublicKeyBytes);
  // An established key the record's own commitment does not commit to is
  // not installed: no honest host holds that pair, and the key that does
  // match arrives in-band and is checked there (§18.2).
  if (pqPub != null && pqCommit != null) {
    final key = HybridPublicKey(edPub: account, mlPub: pqPub);
    if (!constantTimeEquals(await key.pqCommitment(), pqCommit)) pqPub = null;
  }
  final vsn = r['vsn'];
  final kv = await _kvOf(r['kv'], account, now);
  int? count(Object? v) => v is int && v >= 0 ? v : null;
  final name = r['name'];
  final addedBy = r['addedby'];
  return (
    bundle: ContactBundle(
        edPub: bundle.edPub, xPub: bundle.xPub, bindingSig: bundle.bindingSig),
    name: name is String && name.isNotEmpty && name.length <= 256 ? name : null,
    ttl: count(r['ttl']) ?? 0,
    verified: r['verified'] == 1,
    verifiedSn: vsn is String && vsn.isNotEmpty && vsn.length <= 256 ? vsn : null,
    createdMs: count(r['created']),
    pqCommit: pqCommit,
    pqPub: pqPub,
    pqCandidate: pqPub == null ? pqCandidate : null,
    pqAcked: r['pqack'] == 1,
    pqTold: r['pqtold'] == 1,
    pqMismatch: r['pqbad'] == 1,
    addedBy: addedBy is String && addedBy.length <= 256 ? addedBy : null,
    requested: r['req'] == 1,
    kv: kv,
  );
}
