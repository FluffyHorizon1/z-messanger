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

import 'dart:convert';
import 'dart:typed_data';

import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:z_protocol/z_protocol.dart';

import 'archive.dart' show BackupArchive;
import 'vault.dart';

/// The per-contact `kv` families an enrolment carries (§10 `cstate`): the
/// three post-quantum records (ADR 0027, 26.3), the contact's device list,
/// the signature floor it has reached and the list's post-quantum
/// signature. Not the versions beside them, which the new device reads off
/// the list and the signature themselves ([_kvOf]); not what is a device's
/// own to observe — what the contact's devices claimed, the log's standing,
/// alarms, when the chat was last opened; and not `cdev_at_`, which is when
/// a list arrived HERE and is written as now.
const List<String> enrollmentKvFamilies = [
  'pqcs_', 'vpqc_', 'pqcc_', 'cdev_', 'cdev_sigfloor_', 'cdev_pq_',
];

/// The vault key under which a linked device keeps its account's root
/// bundle (§8.1, §10 `hostbundle`).
const String rootBundleKey = 'root_bundle';

/// Install [result] — the account, this device's certificate, the device
/// that linked it and every contact — into [vault], a fresh vault on the new
/// device, before its `ChatService` starts. The relay address is not stored
/// here: the screen that asked the user about it stores it (`setRelayUrl`).
Future<void> installEnrollment(Vault vault, PairingResult result) async {
  final acct = result.account;
  final data = result.data;
  await vault.kvPut(
      'identity',
      jsonEncode(
          {'edSeed': b64(acct.deviceEdSeed), 'xSeed': b64(acct.deviceXSeed)}));
  await vault.kvPut('account', jsonEncode(acct.toJson()));
  await vault.kvPut('display_name', data.displayName ?? 'Me');
  // Remember the device that linked us, so our messages mirror back to it.
  await vault.kvPut('my_devices', jsonEncode([data.hostDeviceCert.toJson()]),
      sensitive: false);
  final root = data.hostBundle;
  if (root != null &&
      await isRootBundle(root, data.accountEdPub, data.hostDeviceCert)) {
    await vault.kvPut(rootBundleKey, jsonEncode(root.toJson()));
  }
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
    await vault.db.insert(
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
      await vault.kvPut(key, e.value, sensitive: !Vault.mayBePlain(key));
    }
  }
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

  for (final f in const ['pqcs_', 'vpqc_', 'pqcc_']) {
    final v = await ok(f);
    if (v != null) kv[f] = v;
  }
  final listJson = await ok('cdev_');
  if (listJson != null) {
    final list = SignedDeviceList.fromJson(
        (jsonDecode(listJson) as Map).cast<String, Object?>());
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
  if (sigJson != null) {
    final sig = HybridDeviceListSignature.fromJson(
        (jsonDecode(sigJson) as Map).cast<String, Object?>());
    if (constantTimeEquals(sig.accountEdPub, account)) {
      kv['cdev_pq_'] = sigJson;
      kv['cdev_pq_ver_'] = '${sig.version}';
    }
  }
  return kv;
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
