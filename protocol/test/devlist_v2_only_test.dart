// ADR 0017 stage 2 in the protocol: a v2-only device list, signed with `sig3`
// alone over the v2 content under its own context.
//
// Stage 2a is the reading side and is on from this release: such a list is
// verified, fingerprinted and ML-DSA-checked by every client. Stage 2b is the
// signer, behind `devlistSignV2Only`, which is off. The rule both halves hang
// on is `SignedDeviceList.commitmentInput`: the fingerprint and the ML-DSA
// input follow the strongest signature that is alone — v1 while a v1
// signature is produced; once it is not, the input of the one signature the
// list carries. A list has three shapes and only three — {sig}, {sig, sig2},
// {sig3} — so that no list with one signature can be made from a list with
// two (devlist_sig_deletion_test.dart).
//
// Criteria, each a test below:
//   1. a v2-only list is signed with sig3 alone and verifies, and stays one on
//      the wire: its JSON carries sig3 and neither sig nor sig2, and parses
//      back to the same list;
//   2. a list carrying no signature is refused, whether built in code or
//      arriving as JSON whose certificates are all genuine;
//   3. a v2-only list with one device's deviceXPub replaced — the certificate
//      re-signed with the account key, the genuine sig3 carried over — is
//      refused, though the v1 input cannot see the change;
//   4. a dual-signed list still needs both signatures: a bad sig2 beside a
//      good sig is refused, and so is a bad sig beside a good sig2;
//   5. the fingerprint follows the rule: v1 for a v1-only and for a
//      dual-signed list, v3 for a v2-only list — neither the v1 nor the v2 one;
//   6. the ML-DSA input follows the same rule: v1 for a dual-signed list (what
//      a client from before ADR 0010 checks), v3 for a v2-only one — not v2,
//      the input ML-DSAs between ADR 0010 and ADR 0017 were made over — where
//      the ratchet-key swap of criterion 3 fails the post-quantum check too;
//   7. as shipped the signer is off: the constant is false, and signing the
//      recorded account's list reproduces the dual-signed stage-1 vector byte
//      for byte, while `v2Only: true` reproduces the v2-only one — sig3, and
//      no sig or sig2;
//   8. the v2-only vectors replay from their recorded inputs alone: admission,
//      the fingerprint and every refusal from v1/multidevice.json; the ML-DSA
//      over the v3 input, not the v1 or the v2 one, and the swap refused, from
//      v3/device_cert_v3.json;
//   9. a list has exactly three shapes: of the eight ways to carry sig, sig2
//      and sig3 — every signature genuine over its own input — only {sig},
//      {sig, sig2} and {sig3} verify, and the ML-DSA check takes only those;
//      the other five are refused for their shape alone, and so is a genuine
//      sig2 moved into sig3;
//  10. the v3 input is the v2 content under a context of its own: the two
//      differ in their first 13 bytes and nowhere else, as v1 and v2 differ
//      from each other, so a signature over one verifies over neither other;
//  11. a signature member that is present is a signature: each valid list
//      with an absent member added as null — {sig, sig2, "sig3": null} and
//      {"sig": null, sig3} among them — does not parse, where reading null
//      as absent would have admitted every one of them.
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

String _hex(List<int> b) =>
    [for (final x in b) x.toRadixString(16).padLeft(2, '0')].join();

Map<String, Object?> _vectors(String dir, String suite) =>
    (jsonDecode(File('../docs/vectors/$dir/$suite.json').readAsStringSync())
            as Map)
        .cast<String, Object?>();

Map<String, Object?> _map(Object? o) => (o as Map).cast<String, Object?>();

SignedDeviceList _listFrom(Object? json) => SignedDeviceList.fromJson(
    _map(json is String ? jsonDecode(json) : json));

Future<bool> _edVerify(Uint8List pub, Uint8List msg, Uint8List sig) =>
    Ed25519().verify(msg,
        signature: Signature(sig,
            publicKey: SimplePublicKey(pub, type: KeyPairType.ed25519)));

void main() {
  late AccountIdentity account;
  late HybridKeyPair pq;
  late ZIdentity laptopKeys;
  late DeviceCertificate laptop;
  late List<DeviceCertificate> devices;

  setUpAll(() async {
    account = await AccountIdentity.generate();
    pq = await HybridKeyPair.fromSeeds(
        edSeed: account.accountEdSeed!, mlSeed: Uint8List(32));
    laptopKeys = await ZIdentity.generate();
    laptop = await account.signDeviceCert(
        deviceEdPub: laptopKeys.edPub,
        deviceXPub: laptopKeys.xPub,
        deviceId: 'laptop');
    devices = [account.deviceCert, laptop];
  });

  /// The laptop with a ratchet key somebody else holds, its certificate signed
  /// by the account key: what an adversary who can forge Ed25519 produces.
  Future<List<DeviceCertificate>> withSwappedLaptop() async {
    final attacker = await ZIdentity.generate();
    final forged = await account.signDeviceCert(
        deviceEdPub: laptop.deviceEdPub,
        deviceXPub: attacker.xPub,
        deviceId: laptop.deviceId);
    return [account.deviceCert, forged];
  }

  test('1. a v2-only list is signed with sig3 alone, verifies, and stays one '
      'on the wire', () async {
    final list = await account.signDeviceList(devices, 5, v2Only: true);
    expect(list.sig, isNull);
    expect(list.sig2, isNull);
    expect(list.sig3, isNotNull);
    expect(list.isV2Only, isTrue);
    expect(list.hasValidShape, isTrue);
    expect(await list.verify(), isTrue);

    final json = list.toJson();
    expect(json.containsKey('sig'), isFalse,
        reason: 'no v1 signature means no `sig` member, not an empty one');
    expect(json.containsKey('sig2'), isFalse);
    expect(json['sig3'], isA<String>());
    final back = _listFrom(jsonEncode(json));
    expect(back.isV2Only, isTrue);
    expect(back.sig3, list.sig3);
    expect(await back.verify(), isTrue);
    expect(await back.fingerprint(), await list.fingerprint());
  });

  test('2. a list carrying no signature is refused', () async {
    final bare = SignedDeviceList(
        accountEdPub: account.accountEdPub, version: 5, devices: devices);
    expect(bare.isV2Only, isFalse);
    expect(bare.hasValidShape, isFalse);
    expect(await bare.verify(), isFalse);
    // The same from the wire: no signature member, every certificate in it
    // genuine — which is not a signature over the set.
    final json = bare.toJson();
    expect(json.keys, isNot(anyOf(contains('sig'), contains('sig2'),
        contains('sig3'))));
    for (final d in devices) {
      expect(await d.verify(account.accountEdPub), isTrue);
    }
    expect(await _listFrom(jsonEncode(json)).verify(), isFalse);
  });

  test('3. a v2-only list with a replaced deviceXPub is refused', () async {
    final list = await account.signDeviceList(devices, 5, v2Only: true);
    final swappedDevices = await withSwappedLaptop();
    final forged = SignedDeviceList(
        accountEdPub: account.accountEdPub,
        version: 5,
        devices: swappedDevices,
        sig3: list.sig3);
    for (final d in forged.devices) {
      expect(await d.verify(account.accountEdPub), isTrue,
          reason: 'each certificate is well signed on its own');
    }
    expect(SignedDeviceList.signingInput(5, swappedDevices),
        SignedDeviceList.signingInput(5, devices),
        reason: 'the v1 input cannot see a ratchet key');
    expect(await forged.verify(), isFalse,
        reason: 'sig3 is over the v3 input, which names the ratchet key');
    expect(await forged.fingerprint(), isNot(await list.fingerprint()));
  });

  test('4. a dual-signed list still needs both signatures', () async {
    final dual = await account.signDeviceList(devices, 5, v2Only: false);
    final other = await account.signDeviceList(devices, 6, v2Only: false);
    expect(await dual.verify(), isTrue);
    final badSig2 = SignedDeviceList(
        accountEdPub: account.accountEdPub,
        version: 5,
        devices: devices,
        sig: dual.sig,
        sig2: other.sig2); // a genuine sig2, for another version
    expect(await badSig2.verify(), isFalse);
    final badSig = SignedDeviceList(
        accountEdPub: account.accountEdPub,
        version: 5,
        devices: devices,
        sig: other.sig,
        sig2: dual.sig2);
    expect(await badSig.verify(), isFalse,
        reason: 'a present sig must verify even when sig2 does');
  });

  test('5. the fingerprint follows the strongest signature that is alone',
      () async {
    final dual = await account.signDeviceList(devices, 5, v2Only: false);
    final v1Only = SignedDeviceList(
        accountEdPub: account.accountEdPub,
        version: 5,
        devices: devices,
        sig: dual.sig);
    final v2Only = await account.signDeviceList(devices, 5, v2Only: true);
    final v1Fp = await deviceListFingerprint(5, devices);
    final v2Fp = await deviceListFingerprintV2(5, devices);
    final v3Fp = await deviceListFingerprintV3(5, devices);
    expect({_hex(v1Fp), _hex(v2Fp), _hex(v3Fp)}, hasLength(3));

    expect(await v1Only.verify(), isTrue);
    expect(await v1Only.fingerprint(), v1Fp);
    expect(v1Only.commitmentInput, SignedDeviceList.signingInput(5, devices));
    expect(await dual.fingerprint(), v1Fp,
        reason: 'stage 1: a v1 signature is still produced, so v1');
    expect(dual.commitmentInput, SignedDeviceList.signingInput(5, devices));
    expect(await v2Only.fingerprint(), v3Fp,
        reason: 'stage 2: sig3 alone, so the v3 input');
    expect(
        v2Only.commitmentInput, SignedDeviceList.signingInputV3(5, devices));
  });

  test('6. the ML-DSA input follows the same rule', () async {
    final mlPub = pq.publicKey.mlPub;
    final dual = await account.signDeviceList(devices, 5, v2Only: false);
    final dualSig =
        await HybridDeviceListSignature.sign(accountKey: pq, list: dual);
    // What a client from before ADR 0010 checks: the v1 input, nothing else.
    expect(
        pqDsaVerify(
            mlPub, SignedDeviceList.signingInput(5, devices), dualSig.mlSig),
        isTrue);
    expect(await dualSig.verifies(dual, mlPub), isTrue);

    final v2Only = await account.signDeviceList(devices, 6, v2Only: true);
    final v3Sig =
        await HybridDeviceListSignature.sign(accountKey: pq, list: v2Only);
    expect(await v3Sig.verifies(v2Only, mlPub), isTrue);
    expect(
        pqDsaVerify(
            mlPub, SignedDeviceList.signingInputV3(6, devices), v3Sig.mlSig),
        isTrue);
    for (final other in [
      SignedDeviceList.signingInput(6, devices),
      SignedDeviceList.signingInputV2(6, devices),
    ]) {
      expect(pqDsaVerify(mlPub, other, v3Sig.mlSig), isFalse);
    }

    // The swap of criterion 3, at this version: in stage 1 the post-quantum
    // half could not see it; here it does.
    final swapped = SignedDeviceList(
        accountEdPub: account.accountEdPub,
        version: 6,
        devices: await withSwappedLaptop(),
        sig3: v2Only.sig3);
    expect(await v3Sig.verifies(swapped, mlPub), isFalse);
    // And neither signature stands in for the other's list.
    expect(await dualSig.verifies(v2Only, mlPub), isFalse);
    expect(await v3Sig.verifies(dual, mlPub), isFalse);
  });

  test('7. as shipped the signer is off, and stage 1 is reproduced exactly',
      () async {
    expect(devlistSignV2Only, isFalse,
        reason: 'stage 2b is built switched off; the flip is a release '
            'decision, not something a test turns on, and the release that '
            'makes it changes this test with it (ADR 0017, "The flip itself")');
    // The account and devices recorded in v1/multidevice.json, rebuilt from
    // their seeds: device #1's Ed25519 key is the account key.
    final v = _vectors('v1', 'multidevice');
    final d1 = _map(v['device1']);
    final recorded = await AccountIdentity.fromV1(
        await ZIdentity.fromSeeds(
            edSeed: _unhex(d1['ed_seed'] as String),
            xSeed: _unhex(d1['x_seed'] as String)),
        deviceId: d1['device_id'] as String);
    final cert2 = DeviceCertificate.fromJson(
        _map(_map(v['device2'])['json']));
    final given = [cert2, recorded.deviceCert]; // the vector's input order

    final dl = _map(v['device_list']);
    final byDefault = await recorded.signDeviceList(given, 3);
    expect(byDefault.toJson(), dl['json'],
        reason: 'with the constant off, the list is the stage-1 list');
    expect(_hex(byDefault.sig!), dl['sig']);
    expect(_hex(byDefault.sig2!), dl['sig2']);
    expect(byDefault.sig3, isNull);
    expect(_hex(await byDefault.fingerprint()), dl['fingerprint']);

    final v2o = _map(v['device_list_v2_only']);
    final asked = await recorded.signDeviceList(given, 4, v2Only: true);
    expect(asked.toJson(), v2o['json']);
    expect(asked.sig, isNull);
    expect(asked.sig2, isNull);
    expect(_hex(asked.sig3!), v2o['sig3']);
  });

  test('8. the v2-only vectors replay from their recorded inputs alone',
      () async {
    final md = _vectors('v1', 'multidevice');
    final acct = _unhex(md['account_ed_pub'] as String);
    final v2o = _map(md['device_list_v2_only']);
    final list = _listFrom(v2o['json']);
    expect(list.isV2Only, isTrue);
    expect(_hex(list.accountEdPub), md['account_ed_pub']);
    expect(list.version, v2o['version']);
    expect(await list.verify(), isTrue);
    expect(_hex(list.commitmentInput), v2o['signing_input_v3']);
    expect(_hex(await list.fingerprint()), v2o['fingerprint']);
    expect(_hex(await deviceListFingerprint(list.version, list.devices)),
        v2o['v1_fingerprint_not_reported']);
    expect(_hex(await deviceListFingerprintV2(list.version, list.devices)),
        v2o['v2_fingerprint_not_reported']);

    final refuse = _map(v2o['must_refuse']);
    expect(await _listFrom(refuse['no_signature_json']).verify(), isFalse);
    final sw = _map(refuse['swapped_ratchet_key']);
    final swapped = _listFrom(sw['json']);
    final attacker = await ZIdentity.fromSeeds(
        edSeed: Uint8List(32), xSeed: _unhex(sw['attacker_x_seed'] as String));
    expect(_hex(attacker.xPub), sw['attacker_x_pub']);
    final moved =
        swapped.devices.singleWhere((d) => d.deviceId == sw['device_id']);
    expect(moved.deviceXPub, attacker.xPub);
    expect(await moved.verify(acct), isTrue,
        reason: 'the substituted certificate is well signed');
    expect(swapped.sig3, list.sig3, reason: 'the genuine sig3, replayed');
    expect(await swapped.verify(), isFalse);
    expect(_hex(swapped.commitmentInput), sw['signing_input_v3']);
    expect(_hex(await swapped.fingerprint()), sw['fingerprint']);
    final stripped = _listFrom(refuse['sig_stripped_json']);
    expect(stripped.toJson(),
        Map.of(_map(_map(md['device_list'])['json']))..remove('sig'));
    expect(await stripped.verify(), isFalse);
    expect(await _listFrom(refuse['sig2_as_sig3_json']).verify(), isFalse);
    final others = refuse['other_shapes'] as List;
    expect([for (final o in others) _map(o)['shape']],
        unorderedEquals(['sig2', 'sig+sig3', 'sig2+sig3', 'sig+sig2+sig3']));
    for (final o in others) {
      expect(await _listFrom(_map(o)['json']).verify(), isFalse,
          reason: '${_map(o)['shape']}');
    }
    final nulls = refuse['null_members'] as List;
    expect(nulls, hasLength(5));
    for (final n in nulls) {
      final json = _map(_map(n)['json']);
      expect(json.containsKey(_map(n)['member']), isTrue);
      expect(() => SignedDeviceList.fromJson(json), throwsFormatException,
          reason: 'a null ${_map(n)['member']} member');
    }

    final cv = _vectors('v3', 'device_cert_v3');
    final mlPub = _unhex(_map(cv['account'])['ml_pub'] as String);
    final c2 = _map(cv['device_list_v2_only']);
    final clist = _listFrom(c2['list_json']);
    expect(clist.isV2Only, isTrue);
    expect(await clist.verify(), isTrue);
    expect(_hex(clist.commitmentInput), c2['signing_input_v3']);
    expect(_hex(await clist.fingerprint()), c2['fingerprint']);
    final mlsig = HybridDeviceListSignature.fromJson(
        _map(jsonDecode(c2['sig_json'] as String)));
    expect(_hex(mlsig.mlSig), c2['ml_sig']);
    expect(await mlsig.verifies(clist, mlPub), isTrue);
    for (final k in ['v1_signing_input', 'v2_signing_input']) {
      expect(pqDsaVerify(mlPub, _unhex(c2[k] as String), mlsig.mlSig), isFalse,
          reason: 'over the v3 input, and not the one in $k');
    }
    final cref = _map(c2['must_refuse']);
    final cswapped = _listFrom(cref['swapped_list_json']);
    expect(cswapped.sig3, clist.sig3);
    expect(await cswapped.verify(), isFalse);
    expect(await mlsig.verifies(cswapped, mlPub), isFalse,
        reason: 'the post-quantum half refuses the swap in stage 2');
    expect(_hex(cswapped.commitmentInput), cref['swapped_signing_input_v3']);
    expect(_hex(await cswapped.fingerprint()), cref['swapped_fingerprint']);
    expect(await _listFrom(cref['sig_stripped_list_json']).verify(), isFalse);
    final stage1 = HybridDeviceListSignature.fromJson(
        _map(jsonDecode(_map(cv['device_list'])['sig_json'] as String)));
    expect(await stage1.verifies(clist, mlPub), isFalse,
        reason: 'the stage-1 ML-DSA does not cover the stage-2 list');
  });

  test('9. a list has exactly three shapes', () async {
    final mlPub = pq.publicKey.mlPub;
    // Every signature genuine, over its own input, at one version and set —
    // which a real account never does (it signs a version one way) — so that
    // each list below stands or falls by its shape and nothing else.
    final dual = await account.signDeviceList(devices, 7, v2Only: false);
    final sole = await account.signDeviceList(devices, 7, v2Only: true);
    final s1 = dual.sig!, s2 = dual.sig2!, s3 = sole.sig3!;
    final pub = account.accountEdPub;
    expect(
        await _edVerify(pub, SignedDeviceList.signingInput(7, devices), s1),
        isTrue);
    expect(
        await _edVerify(pub, SignedDeviceList.signingInputV2(7, devices), s2),
        isTrue);
    expect(
        await _edVerify(pub, SignedDeviceList.signingInputV3(7, devices), s3),
        isTrue);

    final accepted = {'sig', 'sig+sig2', 'sig3'};
    for (var mask = 0; mask < 8; mask++) {
      final has1 = mask & 1 != 0, has2 = mask & 2 != 0, has3 = mask & 4 != 0;
      final shape = [
        if (has1) 'sig',
        if (has2) 'sig2',
        if (has3) 'sig3',
      ].join('+');
      final list = SignedDeviceList(
          accountEdPub: pub,
          version: 7,
          devices: devices,
          sig: has1 ? s1 : null,
          sig2: has2 ? s2 : null,
          sig3: has3 ? s3 : null);
      final ok = accepted.contains(shape);
      expect(list.hasValidShape, ok, reason: '{$shape}');
      expect(await list.verify(), ok, reason: '{$shape}');
      // The ML-DSA check takes a list only in one of the three shapes. A
      // signature over the input the list would otherwise commit to is
      // offered for each, so a refusal can only be the shape's.
      final ml = await HybridDeviceListSignature.sign(
          accountKey: pq, list: list, deterministic: true);
      expect(await ml.verifies(list, mlPub), ok, reason: 'ML-DSA, {$shape}');
    }

    // A genuine sig2 moved into sig3 is the right shape and the wrong input.
    final relabelled = SignedDeviceList(
        accountEdPub: pub, version: 7, devices: devices, sig3: s2);
    expect(relabelled.hasValidShape, isTrue);
    expect(await relabelled.verify(), isFalse);
  });

  test('10. the v3 input is the v2 content under a context of its own',
      () async {
    final v1 = SignedDeviceList.signingInput(8, devices);
    final v2 = SignedDeviceList.signingInputV2(8, devices);
    final v3 = SignedDeviceList.signingInputV3(8, devices);
    expect(utf8.decode(v1.sublist(0, 13)), 'z-devlist-v1:');
    expect(utf8.decode(v2.sublist(0, 13)), 'z-devlist-v2:');
    expect(utf8.decode(v3.sublist(0, 13)), 'z-devlist-v3:');
    expect(v3.sublist(13), v2.sublist(13), reason: 'the same content');
    expect(v3.length, v2.length);
    // A signature over any one of the three inputs verifies over neither of
    // the others.
    final seed = account.accountEdSeed!;
    final kp = await Ed25519().newKeyPairFromSeed(seed);
    final inputs = [v1, v2, v3];
    for (var i = 0; i < 3; i++) {
      final sig = Uint8List.fromList(
          (await Ed25519().sign(inputs[i], keyPair: kp)).bytes);
      for (var j = 0; j < 3; j++) {
        expect(await _edVerify(account.accountEdPub, inputs[j], sig), i == j,
            reason: 'a signature over input ${i + 1}, checked over ${j + 1}');
      }
    }
  });

  test('11. a signature member that is present is a signature', () async {
    final dual = await account.signDeviceList(devices, 9, v2Only: false);
    final sole = await account.signDeviceList(devices, 9, v2Only: true);
    final v1Only = SignedDeviceList(
        accountEdPub: account.accountEdPub,
        version: 9,
        devices: devices,
        sig: dual.sig);
    // Each valid shape, with each member it does not carry added as null.
    final cases = <(SignedDeviceList, String)>[
      (dual, 'sig3'),
      (sole, 'sig'),
      (sole, 'sig2'),
      (v1Only, 'sig2'),
      (v1Only, 'sig3'),
    ];
    for (final (list, member) in cases) {
      expect(await list.verify(), isTrue, reason: 'the list itself is valid');
      final json = {...list.toJson(), member: null};
      expect(() => SignedDeviceList.fromJson(json), throwsFormatException,
          reason: 'a null $member beside ${list.toJson().keys}');
      // Through the wire format too, where a null member is what a sender
      // would actually write.
      expect(
          () => SignedDeviceList.fromJson(
              _map(jsonDecode(jsonEncode(json)))),
          throwsFormatException);
      // What reading null as absent would have done: admitted it.
      final absent = Map.of(json)..remove(member);
      expect(await SignedDeviceList.fromJson(absent).verify(), isTrue);
    }
    // Any other non-string value is no better.
    expect(() => SignedDeviceList.fromJson({...dual.toJson(), 'sig3': 7}),
        throwsFormatException);
  });
}
