// ADR 0017: a dual-signed device list with its `sig` deleted is refused.
//
// Every list signed until the stage-2 signer is switched on carries `sig` and
// `sig2`, and its `sig2` is a genuine account signature over the v2 input.
// Anyone who passes a list on can delete `sig` — the transparency-log operator
// among them, because a log value is sealed under a key derived from the
// account's PUBLIC key (§19.1), so the operator can open one, edit it and seal
// it again. Were what is left a list a reader takes, the operator could make,
// out of any list the account ever published, one the account never sent:
// fingerprinted over another input than every other reader holds for that
// version, and lifting the reader's floor to a level the account never
// reached. So the shape is part of what is verified, and `sig2` never stands
// alone.
//
// Written against the API every reader already had, so the same file runs
// against a build that took `sig2` alone, and fails there.
//
// Criteria, each a test below:
//   1. every genuine dual-signed list in the vectors — wherever it sits, the
//      sealed values in the transparency log's vectors included — is refused
//      once `sig` is deleted, in code and from JSON, though the `sig2` left
//      behind still verifies over its own input;
//   2. the ML-DSA half, with the list's genuine ML-DSA kept: the deletion does
//      not move the v1 input that signature is over, so it still covers the
//      stripped list's bytes — and the post-quantum check refuses the list
//      all the same, as the classical one does;
//   3. the ML-DSA half, with the ML-DSA deleted too: there is nothing
//      post-quantum to check, and the list is refused all the same — the
//      refusal never rested on the post-quantum half.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

Uint8List _unhex(String s) => Uint8List.fromList([
      for (var i = 0; i < s.length; i += 2)
        int.parse(s.substring(i, i + 2), radix: 16)
    ]);

Map<String, Object?> _map(Object? o) => (o as Map).cast<String, Object?>();

Map<String, Object?> _vectors(String rel) =>
    _map(jsonDecode(File('../docs/vectors/$rel').readAsStringSync()));

/// A device list found in the vectors: where, and its JSON.
typedef _Found = ({String where, Map<String, Object?> json});

/// Every object in [node] with the members of a signed device list, including
/// those inside JSON-encoded strings.
void _collect(Object? node, String where, List<_Found> out) {
  if (node is Map) {
    final m = node.cast<String, Object?>();
    if (m.containsKey('acct') && m.containsKey('ver') && m.containsKey('devs')) {
      out.add((where: where, json: m));
    }
    for (final e in m.entries) {
      _collect(e.value, '$where/${e.key}', out);
    }
  } else if (node is List) {
    for (var i = 0; i < node.length; i++) {
      _collect(node[i], '$where[$i]', out);
    }
  } else if (node is String && node.startsWith('{') && node.contains('"devs"')) {
    try {
      _collect(jsonDecode(node), '$where(json)', out);
    } on FormatException {
      // Not JSON after all; nothing to find in it.
    }
  }
}

Future<bool> _edVerify(Uint8List pub, Uint8List msg, Uint8List sig) =>
    Ed25519().verify(msg,
        signature: Signature(sig,
            publicKey: SimplePublicKey(pub, type: KeyPairType.ed25519)));

SignedDeviceList _stripped(SignedDeviceList l) => SignedDeviceList(
    accountEdPub: l.accountEdPub,
    version: l.version,
    devices: l.devices,
    sig2: l.sig2);

void main() {
  /// Every genuine dual-signed list in the vectors: found by shape anywhere in
  /// any vector file, plus each transparency-log value opened with its
  /// account's key — what the operator would open — and kept only if it
  /// verifies as found (a substitution vector carries a `sig2` that does not).
  late List<(String, SignedDeviceList, Map<String, Object?>)> genuine;

  setUpAll(() async {
    final found = <_Found>[];
    final root = Directory('../docs/vectors');
    for (final f in root.listSync(recursive: true).whereType<File>()) {
      if (!f.path.endsWith('.json')) continue;
      final rel = f.path.substring(root.path.length + 1);
      _collect(jsonDecode(f.readAsStringSync()), rel, found);
    }
    final kt = _vectors('kt/kt_log.json');
    final accounts = _map(kt['accounts']);
    final publishes = kt['publishes'] as List;
    for (var i = 0; i < publishes.length; i++) {
      final p = _map(publishes[i]);
      final pub = _unhex(_map(accounts[p['account']])['account_ed_pub'] as String);
      final opened = await ktOpenValue(pub, _unhex(p['value'] as String));
      if (opened == null) continue;
      try {
        _collect(jsonDecode(utf8.decode(opened)),
            'kt/kt_log.json/publishes[$i]/value(opened)', found);
      } on FormatException {
        // A stand-in value, not a list.
      }
    }
    genuine = [];
    for (final f in found) {
      // Dual-signed: both members, and signatures — not a must-refuse entry
      // that carries one as null, or a third one beside them.
      if (f.json['sig'] is! String ||
          f.json['sig2'] is! String ||
          f.json.containsKey('sig3')) {
        continue;
      }
      final list = SignedDeviceList.fromJson(f.json);
      if (await list.verify()) genuine.add((f.where, list, f.json));
    }
  });

  test(
      '1. every genuine dual-signed list in the vectors is refused once its '
      'sig is deleted', () async {
    final where = [for (final g in genuine) g.$1];
    // The scan must have found what it is for, or it proves nothing.
    expect(where, contains('v1/multidevice.json/device_list/json'));
    expect(where, contains('v3/device_cert_v3.json/device_list/list_json(json)'));
    expect(where, contains('kt/kt_log.json/publishes[0]/value(opened)'));
    expect(genuine.length, greaterThanOrEqualTo(5),
        reason: 'the multidevice and device_cert_v3 lists, the excluded and '
            'rolled-back ones, and the log value: $where');

    for (final (w, list, json) in genuine) {
      // What is left after the deletion is a genuine account signature.
      expect(
          await _edVerify(list.accountEdPub,
              SignedDeviceList.signingInputV2(list.version, list.devices),
              list.sig2!),
          isTrue,
          reason: '$w: the sig2 left behind verifies over its own input');
      expect(await _stripped(list).verify(), isFalse,
          reason: '$w: with sig deleted, in code');
      final fromWire = Map.of(json)..remove('sig');
      expect(fromWire.containsKey('sig2'), isTrue);
      expect(
          await SignedDeviceList.fromJson(
                  _map(jsonDecode(jsonEncode(fromWire))))
              .verify(),
          isFalse,
          reason: '$w: with sig deleted, from JSON');
    }
  });

  test(
      '2. with its ML-DSA kept, the stripped list is refused by the '
      'post-quantum check too, though that signature still covers its bytes',
      () async {
    final v = _vectors('v3/device_cert_v3.json');
    final mlPub = _unhex(_map(v['account'])['ml_pub'] as String);
    final dl = _map(v['device_list']);
    final list = SignedDeviceList.fromJson(
        _map(jsonDecode(dl['list_json'] as String)));
    final ml = HybridDeviceListSignature.fromJson(
        _map(jsonDecode(dl['sig_json'] as String)));
    expect(await list.verify(), isTrue);
    expect(await ml.verifies(list, mlPub), isTrue,
        reason: 'the genuine pair, for contrast');

    final stripped = _stripped(list);
    // The deletion leaves the v1 input — the bytes the stage-1 ML-DSA is
    // over — exactly as it was, so that signature still covers the stripped
    // list: the post-quantum half cannot tell the two apart by its signature.
    expect(
        pqDsaVerify(
            mlPub,
            SignedDeviceList.signingInput(stripped.version, stripped.devices),
            ml.mlSig),
        isTrue);
    // A reader's two checks both refuse it.
    expect(await stripped.verify(), isFalse);
    expect(await ml.verifies(stripped, mlPub), isFalse);
  });

  test(
      '3. with its ML-DSA deleted too, there is nothing post-quantum to check '
      'and the stripped list is refused all the same', () async {
    final v = _vectors('v3/device_cert_v3.json');
    final dl = _map(v['device_list']);
    final json = _map(jsonDecode(dl['list_json'] as String));
    final wire = Map.of(json)..remove('sig');
    // The list travels without its signature (the ML-DSA is its own message
    // and can be dropped): what is left to a reader is the list alone.
    final stripped = SignedDeviceList.fromJson(wire);
    expect(stripped.sig, isNull);
    expect(stripped.sig2, isNotNull);
    expect(await stripped.verify(), isFalse);
  });
}
