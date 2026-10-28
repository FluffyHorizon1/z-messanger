// Every Ed25519 signature the library checks is held to §21.4's one rule, and
// every key that arrives from outside is a strong one — the 2026-10-28
// review's F1 and F2 — and the parsers those doors read through throw what
// their docs say they throw (F3).
//
// `package:cryptography`'s verifier compares the two points of the
// verification equation by x alone, so with A the point of order 2
// (`ecff…7f`), R the identity (`0100…00`) and S = 0, one fixed 64 bytes
// verify over ANY message under that key; under the identity they do too,
// and under a point of order 4 or 8 they do for one message in two or four.
// `ed25519VerifyStrict` and `handleStrongEdKey` were wired into the handle
// log and `iks` only: every other door called the lenient verifier and held
// its Ed25519 keys to a length, and a listed device's X25519 key to a length
// too. Each forgery below is first shown to be one the library's verifier
// takes — which it still does; the doors no longer ask it.
//
// Run against 14a5b3c, criteria 1, 2, 4 and 5 fail there; criterion 3 is
// what must not change, and passes on both. `vectors_test.dart` is the
// byte-for-byte check that every vector still replays.
//
// Criteria, each a test below:
//   1. the forged triple is refused by ContactBundle.verify and decode,
//      DeviceCertificate.verify, SignedDeviceList.verify in each of its three
//      shapes, commitSignatureValid and ContactBundleV3.decode, and
//      ContactRequest.verify and anchor — each of which took it before;
//   2. each of those doors, and AccountBundle.decode, refuses each of the
//      eight Ed25519 keys of small order in every place it reads a key — a
//      bundle's ed, a certificate's account key and ded, a list's acct and a
//      listed ded, a code's ed and acct, a request's bundle and its anchor's
//      root — with a forged signature the library's verifier takes beside
//      it wherever that key signs; and each refuses a second spelling at or
//      above p;
//   3. honest keys and signatures pass every door, as they did, and the
//      library's verifier and the rule agree on every signature they carry;
//   4. a listed device whose X25519 key is of small order — zero among
//      them — or spelled at or above p, or has its top bit set, is refused
//      by DeviceCertificate.verify and SignedDeviceList.verify, built and
//      after a JSON round trip, though the account signed it; and an
//      existing device's pairing, in each of its three versions, refuses to
//      certify a device key that is not strong;
//   5. every malformed shape of SignedDeviceList.fromJson,
//      DeviceCertificate.fromJson, AccountBundle.fromJson and
//      ZArchive.parseHeader throws a FormatException, never a TypeError —
//      and so do ContactBundle.decode and AccountBundle.decode, which read
//      the same members out of a code.
import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart' show DartSha256;
import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

Uint8List _hex(String s) => Uint8List.fromList([
      for (var i = 0; i < s.length; i += 2)
        int.parse(s.substring(i, i + 2), radix: 16)
    ]);

Uint8List _cat(List<List<int>> parts) =>
    Uint8List.fromList([for (final p in parts) ...p]);

Uint8List _seed(String tag, int i) =>
    Uint8List.fromList(_sha256(utf8.encode('key_doors_test $tag $i')));

List<int> _sha256(List<int> data) => const DartSha256().hashSync(data).bytes;

final _ed = Ed25519();
final _x = X25519();

/// The library's own verifier, which every door but the handle log's called
/// until 2026-10-28.
Future<bool> _lenient(List<int> pub, List<int> msg, List<int> sig) async {
  try {
    return await _ed.verify(msg,
        signature: Signature(sig,
            publicKey: SimplePublicKey(pub, type: KeyPairType.ed25519)));
  } catch (_) {
    return false;
  }
}

/// R the identity, S = 0.
final Uint8List _forged = Uint8List(64)..[0] = 1;

/// The point of order 2.
final Uint8List _order2 =
    _hex('ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f');

/// The eight Ed25519 points of small order, each in its one canonical
/// spelling: the identity, the point of order 2, the two of order 4 and the
/// four of order 8.
const _smallOrderHex = [
  '0100000000000000000000000000000000000000000000000000000000000000',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0000000000000000000000000000000000000000000000000000000000000080',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
];

/// Two second spellings, y at or above p: p + 1 (the identity) and p (y = 0,
/// a point of order 4).
const _secondSpellingHex = [
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
];

/// X25519 u of small order, on the curve and its twist — 0, 1, the two of
/// order 8 and p − 1 — then p and p + 1, which X25519 reads as 0 and 1, and
/// one key with its top bit set.
const _weakXHex = [
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
  '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
];

Future<Uint8List> _xPub(String tag, int i) async => Uint8List.fromList(
    (await (await _x.newKeyPairFromSeed(_seed(tag, i))).extractPublicKey())
        .bytes);

Uint8List _bindInput(List<int> xPub) =>
    _cat([utf8.encode(bindContext), xPub]);

/// The first i for which the library's verifier takes [_forged] under [key]
/// over every message [messages] gives for it: one in every i for a key of
/// order 1 or 2, about one in two for order 4, one in four for order 8.
/// Null for a key no forgery verifies under in that verifier — a second
/// spelling, which it refuses (y ≥ p) before any arithmetic.
Future<int?> _forgeable(
    Uint8List key, Future<List<Uint8List>> Function(int i) messages) async {
  for (var i = 0; i < 256; i++) {
    var all = true;
    for (final m in await messages(i)) {
      if (!await _lenient(key, m, _forged)) {
        all = false;
        break;
      }
    }
    if (all) return i;
  }
  return null;
}

/// Asserts what makes each case below a forgery and not a mere bad key:
/// the library's verifier, which the door asked until 2026-10-28, takes it.
Future<void> _libraryTakes(Uint8List key, List<Uint8List> messages,
    {required String why}) async {
  for (final m in messages) {
    expect(await _lenient(key, m, _forged), isTrue,
        reason: '$why: the library\'s verifier takes R = identity, S = 0');
  }
}

// ---------------------------------------------------------------------------
// The doors, each built around a key K in the place named, with the forged
// signature wherever K is the signer and an honest one everywhere else.
// [forgeable] says whether to look for a message the library takes (for a
// key of small order) or to take any (for a second spelling).
// ---------------------------------------------------------------------------

/// A `zc1.` bundle whose ed is [k]: its binding forged.
Future<ContactBundle> _bundleUnder(Uint8List k, {bool check = true}) async {
  final i = await _forgeable(k, (i) async => [_bindInput(await _xPub('b', i))]);
  final x = await _xPub('b', i ?? 0);
  if (check && i != null) {
    await _libraryTakes(k, [_bindInput(x)], why: 'binding');
  }
  return ContactBundle(edPub: k, xPub: x, bindingSig: _forged, displayName: 'K');
}

/// A certificate for an honest device "signed" by the account key [k].
Future<DeviceCertificate> _certUnderAccount(Uint8List k,
    {required ZIdentity device, String tag = 'c'}) async {
  final i = await _forgeable(
      k,
      (i) async => [
            DeviceCertificate.signingInput(device.edPub, device.xPub, '$tag$i')
          ]);
  final id = '$tag${i ?? 0}';
  if (i != null) {
    await _libraryTakes(
        k, [DeviceCertificate.signingInput(device.edPub, device.xPub, id)],
        why: 'certificate');
  }
  return DeviceCertificate(
      deviceEdPub: device.edPub,
      deviceXPub: device.xPub,
      deviceId: id,
      sig: _forged);
}

/// A one-device list `{sig}` under the account key [k], everything forged.
Future<SignedDeviceList> _listUnderAccount(Uint8List k) async {
  final device = await ZIdentity.generate();
  final cert = await _certUnderAccount(k, device: device);
  final v = await _forgeable(
      k, (j) async => [SignedDeviceList.signingInput(j + 2, [cert])]);
  final version = (v ?? 0) + 2;
  if (v != null) {
    await _libraryTakes(k, [SignedDeviceList.signingInput(version, [cert])],
        why: 'list');
  }
  return SignedDeviceList(
      accountEdPub: k, version: version, devices: [cert], sig: _forged);
}

/// A post-quantum code whose ed — the device, and with no `acct` the
/// account — is [k]: its binding and its commitment's signature forged.
Future<ContactBundleV3> _codeUnderDevice(Uint8List k) async {
  final i = await _forgeable(k, (i) async => [_bindInput(await _xPub('v', i))]);
  final x = await _xPub('v', i ?? 0);
  Uint8List commit(int j) => Uint8List.fromList(_sha256(utf8.encode('pqc $j')));
  final j = await _forgeable(
      k, (j) async => [pqCommitSigningInput(k, commit(j))]);
  final c = commit(j ?? 0);
  if (i != null && j != null) {
    await _libraryTakes(k, [_bindInput(x), pqCommitSigningInput(k, c)],
        why: 'code');
  }
  return ContactBundleV3(
      edPub: k,
      xPub: x,
      bindingSig: _forged,
      pqCommit: c,
      pqCommitSig: _forged,
      displayName: 'K');
}

/// An honest device's account-anchored code naming the account key [k],
/// whose certificate [k] "signed".
Future<ContactBundleV3> _codeUnderAccount(Uint8List k) async {
  final dev = await ZIdentity.generate();
  final cert = await _certUnderAccount(k, device: dev, tag: 'a');
  final c = Uint8List.fromList(_sha256(utf8.encode('pqc anchored')));
  final pqcs = await _ed.sign(pqCommitSigningInput(k, c), keyPair: dev.edKeyPair);
  return ContactBundleV3(
      edPub: dev.edPub,
      xPub: dev.xPub,
      bindingSig: await dev.bindingSignature(),
      pqCommit: c,
      pqCommitSig: Uint8List.fromList(pqcs.bytes),
      displayName: 'anchored',
      declaredAccountEdPub: k,
      deviceCert: cert);
}

/// A request from the identity [k], to [to]: its bundle's binding and the
/// request's signature forged.
Future<ContactRequest> _requestFrom(Uint8List k, String to) async {
  final bundle = await _bundleUnder(k);
  final t = await _forgeable(
      k, (t) async => [ContactRequest.signingInput(bundle, to, 1000 + t)]);
  final ts = 1000 + (t ?? 0);
  if (t != null) {
    await _libraryTakes(k, [ContactRequest.signingInput(bundle, to, ts)],
        why: 'request');
  }
  return ContactRequest(bundle: bundle, toRid: to, ts: ts, sig: _forged);
}

/// An honest request from a linked device, anchored to a root whose key is
/// [k]: the root's binding and the account's certificate for the device
/// forged, the request and its `asig` the device's own.
Future<(ContactRequest, ZIdentity)> _requestAnchoredTo(
    Uint8List k, String to) async {
  final me = await ZIdentity.generate();
  final root = await _bundleUnder(k);
  final cert = await _certUnderAccount(k, device: me, tag: 'r');
  final req = await ContactRequest.create(
      me: me, toRid: to, ts: 5000, root: root, cert: cert);
  return (req, me);
}

const _to = 'the-recipient-routing-id';

void main() {
  test('1. the forged triple — order-2 A, identity R, S = 0 — is refused at '
      'every door', () async {
    final k = _order2;
    // A sample of messages, each taken: the triple verifies over anything.
    for (final m in [Uint8List(0), _hex('00'), utf8.encode('z-bind-v1:xxxxx')]) {
      expect(await _lenient(k, m, _forged), isTrue);
      expect(ed25519VerifyStrict(k, m, _forged), isFalse);
    }

    final bundle = await _bundleUnder(k);
    expect(await bundle.verify(), isFalse, reason: 'ContactBundle.verify');
    await expectLater(ContactBundle.decode(bundle.encode()),
        throwsA(isA<FormatException>()),
        reason: 'ContactBundle.decode');

    final device = await ZIdentity.generate();
    final cert = await _certUnderAccount(k, device: device);
    expect(await cert.verify(k), isFalse, reason: 'DeviceCertificate.verify');

    // The list, in each of its three shapes, every signature the triple.
    final listed = [cert];
    final shapes = {
      '{sig}': SignedDeviceList(
          accountEdPub: k, version: 7, devices: listed, sig: _forged),
      '{sig, sig2}': SignedDeviceList(
          accountEdPub: k,
          version: 7,
          devices: listed,
          sig: _forged,
          sig2: _forged),
      '{sig3}': SignedDeviceList(
          accountEdPub: k, version: 7, devices: listed, sig3: _forged),
    };
    for (final e in shapes.entries) {
      final l = e.value;
      await _libraryTakes(k, [
        SignedDeviceList.signingInput(7, listed),
        SignedDeviceList.signingInputV2(7, listed),
        SignedDeviceList.signingInputV3(7, listed),
      ], why: e.key);
      expect(await l.verify(), isFalse, reason: 'SignedDeviceList ${e.key}');
      expect(
          await SignedDeviceList.fromJson(
                  (jsonDecode(jsonEncode(l.toJson())) as Map)
                      .cast<String, Object?>())
              .verify(),
          isFalse,
          reason: 'SignedDeviceList ${e.key}, from the wire');
    }

    final code = await _codeUnderDevice(k);
    expect(await code.commitSignatureValid(), isFalse,
        reason: 'commitSignatureValid');
    for (final c in [code.encode(), code.encodeStrict()]) {
      await expectLater(
          ContactBundleV3.decode(c), throwsA(isA<FormatException>()),
          reason: 'ContactBundleV3.decode');
      await expectLater(scanContactCode(c), throwsA(isA<FormatException>()),
          reason: 'scanContactCode');
    }
    final anchored = await _codeUnderAccount(k);
    await expectLater(ContactBundleV3.decode(anchored.encode()),
        throwsA(isA<FormatException>()),
        reason: 'ContactBundleV3.decode, the account key');

    final req = await _requestFrom(k, _to);
    final from = await req.bundle.routingId();
    expect(await req.verify(expectedTo: _to, sealedFrom: from), isFalse,
        reason: 'ContactRequest.verify');
    final wire = ContactRequest.tryParse(req.encode())!;
    expect(await wire.verify(expectedTo: _to, sealedFrom: from), isFalse,
        reason: 'ContactRequest.verify, from the wire');

    final (anchoredReq, me) = await _requestAnchoredTo(k, _to);
    expect(
        await anchoredReq.verify(
            expectedTo: _to, sealedFrom: await me.routingId()),
        isTrue,
        reason: 'the request itself is honest');
    expect(await anchoredReq.anchor(), isNull, reason: 'ContactRequest.anchor');
  });

  test('2. every door refuses every Ed25519 key of small order, in every '
      'place, and a second spelling', () async {
    final keys = <String, (Uint8List, bool)>{
      for (final h in _smallOrderHex) 'small order $h': (_hex(h), true),
      for (final h in _secondSpellingHex) 'second spelling $h': (_hex(h), false),
    };
    final honest = await AccountIdentity.generate();
    for (final MapEntry(key: name, value: (k, small)) in keys.entries) {
      expect(handleStrongEdKey(k), isFalse, reason: name);
      final forgeable = await _forgeable(k, (i) async => [Uint8List(i)]);
      expect(forgeable != null, small,
          reason: '$name: the library\'s verifier takes a forgery under a '
              'key of small order, and none under a second spelling');

      // A bundle's ed, and the code it is.
      final bundle = await _bundleUnder(k);
      expect(await bundle.verify(), isFalse, reason: '$name: bundle');
      await expectLater(ContactBundle.decode(bundle.encode()),
          throwsA(isA<FormatException>()),
          reason: '$name: zc1. code');
      await expectLater(AccountBundle.decode(bundle.encode()),
          throwsA(isA<FormatException>()),
          reason: '$name: zc1. code read as an account');

      // A certificate's account key, its ded, and its ded as the signer of
      // its proof of possession.
      final device = await ZIdentity.generate();
      final cert = await _certUnderAccount(k, device: device);
      expect(await cert.verify(k), isFalse, reason: '$name: certificate, account');
      final signedFor = await honest.signDeviceCert(
          deviceEdPub: k, deviceXPub: device.xPub, deviceId: 'ded');
      expect(await signedFor.verify(honest.accountEdPub), isFalse,
          reason: '$name: certificate, ded (the account signed it)');
      final p = await _forgeable(
          k,
          (i) async => [
                DeviceCertificate.popInput(
                    honest.accountEdPub, k, device.xPub, 'pop$i')
              ]);
      final popId = 'pop${p ?? 0}';
      final popped = (await honest.signDeviceCert(
              deviceEdPub: k, deviceXPub: device.xPub, deviceId: popId))
          .withPop(_forged);
      if (p != null) {
        await _libraryTakes(k, [
          DeviceCertificate.popInput(honest.accountEdPub, k, device.xPub, popId)
        ], why: '$name: proof of possession');
      }
      expect(await popped.verify(honest.accountEdPub), isFalse,
          reason: '$name: certificate, ded signing its proof');
      expect(await popped.provesPossession(honest.accountEdPub), isFalse,
          reason: '$name: proves nothing');

      // A list's acct, and a listed ded the account signed.
      final list = await _listUnderAccount(k);
      expect(await list.verify(), isFalse, reason: '$name: list, account');
      final honestList = await honest.signDeviceList(
          [honest.deviceCert, signedFor], 3);
      expect(await honestList.verify(), isFalse,
          reason: '$name: list naming the key as a device');
      final v2Only = await honest.signDeviceList(
          [honest.deviceCert, signedFor], 3,
          v2Only: true);
      expect(await v2Only.verify(), isFalse,
          reason: '$name: v2-only list naming the key as a device');

      // An account code's acct, and a device in it the account signed.
      final acctCode = AccountBundle(accountEdPub: k, devices: [cert]).encode();
      await expectLater(
          AccountBundle.decode(acctCode), throwsA(isA<FormatException>()),
          reason: '$name: zc2. account');
      final devCode = AccountBundle(
          accountEdPub: honest.accountEdPub,
          devices: [honest.deviceCert, signedFor]).encode();
      await expectLater(
          AccountBundle.decode(devCode), throwsA(isA<FormatException>()),
          reason: '$name: zc2. device');

      // A post-quantum code's ed (and with it the commitment's signer), and
      // its acct.
      final code = await _codeUnderDevice(k);
      expect(await code.commitSignatureValid(), isFalse,
          reason: '$name: commitment signature');
      await expectLater(ContactBundleV3.decode(code.encode()),
          throwsA(isA<FormatException>()),
          reason: '$name: post-quantum code, ed');
      final anchored = await _codeUnderAccount(k);
      await expectLater(ContactBundleV3.decode(anchored.encode()),
          throwsA(isA<FormatException>()),
          reason: '$name: post-quantum code, acct');

      // A request's bundle, and its anchor's root.
      final req = await _requestFrom(k, _to);
      expect(
          await req.verify(
              expectedTo: _to, sealedFrom: await req.bundle.routingId()),
          isFalse,
          reason: '$name: request');
      final (anchoredReq, _) = await _requestAnchoredTo(k, _to);
      expect(await anchoredReq.anchor(), isNull,
          reason: '$name: request anchor');
    }
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('3. honest keys and signatures pass every door, and the library and '
      'the rule agree on each', () async {
    Future<void> agree(List<int> pub, List<int> msg, List<int> sig,
        String why) async {
      expect(ed25519VerifyStrict(pub, msg, sig), isTrue, reason: why);
      expect(await _lenient(pub, msg, sig), isTrue, reason: why);
    }

    for (var round = 0; round < 6; round++) {
      // A zc1. bundle, its code, and the code read as an account.
      final id = await ZIdentity.generate();
      final bundle = await id.bundle(displayName: 'Ann $round');
      expect(await bundle.verify(), isTrue);
      await agree(id.edPub, _bindInput(id.xPub), bundle.bindingSig, 'binding');
      final decoded = await ContactBundle.decode(bundle.encode());
      expect(decoded.displayName, 'Ann $round');
      expect((await AccountBundle.decode(bundle.encode())).devices.single.legacy,
          isTrue);

      // An account, a linked device with its proof, and its lists.
      final a = await AccountIdentity.generate();
      final laptop = await ZIdentity.generate();
      final cert = await a.signDeviceCert(
          deviceEdPub: laptop.edPub, deviceXPub: laptop.xPub, deviceId: 'l$round');
      final proven = cert.withPop(await cert.makePop(laptop.edSeed, a.accountEdPub));
      expect(await a.deviceCert.verify(a.accountEdPub), isTrue);
      expect(await proven.verify(a.accountEdPub), isTrue);
      expect(await proven.provesPossession(a.accountEdPub), isTrue);
      await agree(
          a.accountEdPub,
          DeviceCertificate.signingInput(laptop.edPub, laptop.xPub, 'l$round'),
          proven.sig,
          'certificate');
      await agree(
          laptop.edPub,
          DeviceCertificate.popInput(
              a.accountEdPub, laptop.edPub, laptop.xPub, 'l$round'),
          proven.pop!,
          'proof');
      for (final v2Only in [false, true]) {
        final list =
            await a.signDeviceList([a.deviceCert, proven], 2, v2Only: v2Only);
        expect(await list.verify(), isTrue, reason: 'v2Only $v2Only');
        final back = SignedDeviceList.fromJson(
            (jsonDecode(jsonEncode(list.toJson())) as Map)
                .cast<String, Object?>());
        expect(await back.verify(), isTrue, reason: 'v2Only $v2Only, wire');
      }
      final acctCode = a.toAccountBundle(otherDevices: [proven]).encode();
      expect((await AccountBundle.decode(acctCode)).devices.length, 2);

      // Post-quantum codes, a root's and a linked device's.
      final pq = await HybridKeyPair.fromSeeds(
          edSeed: a.accountEdSeed!, mlSeed: _seed('ml', round));
      final rootId = await ZIdentity.fromSeeds(
          edSeed: a.accountEdSeed!, xSeed: a.deviceXSeed);
      final rootCode = await ContactBundleV3.forIdentity(rootId, pq.publicKey);
      expect(await rootCode.commitSignatureValid(), isTrue);
      expect((await ContactBundleV3.decode(rootCode.encode())).commitSigned,
          isTrue);
      final linkedCode = await ContactBundleV3.forIdentity(
          laptop, pq.publicKey,
          accountEdPub: a.accountEdPub, cert: proven);
      final read = await ContactBundleV3.decode(linkedCode.encodeStrict());
      expect(read.accountEdPub, a.accountEdPub);
      expect(await read.commitSignatureValid(), isTrue);

      // Requests, the device's own and one anchored to its account.
      final req = await ContactRequest.create(me: id, toRid: _to);
      expect(
          await ContactRequest.tryParse(req.encode())!
              .verify(expectedTo: _to, sealedFrom: await id.routingId()),
          isTrue);
      final rootBundle = await rootId.bundle();
      final anchoredReq = await ContactRequest.create(
          me: laptop, toRid: _to, root: rootBundle, cert: proven);
      expect(
          await anchoredReq.verify(
              expectedTo: _to, sealedFrom: await laptop.routingId()),
          isTrue);
      final anchor = await anchoredReq.anchor();
      expect(anchor, isNotNull);
      expect(anchor!.accountEdPub, a.accountEdPub);

      // The hybrid signature's classical half.
      final hs = await pq.sign(Uint8List.fromList(utf8.encode('hybrid $round')));
      expect(
          await hybridVerify(
              pq.publicKey, Uint8List.fromList(utf8.encode('hybrid $round')), hs),
          isTrue);
    }
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('4. a listed device whose X25519 key is not strong is refused, built '
      'and from the wire, and pairing will not certify one', () async {
    final a = await AccountIdentity.generate();
    final laptop = await ZIdentity.generate();
    final honestX = laptop.xPub;
    final topBit = Uint8List.fromList(honestX)..[31] |= 0x80;
    final cases = <String, Uint8List>{
      for (final h in _weakXHex) h: _hex(h),
      'top bit set': topBit,
    };
    Future<bool> fromWireCert(DeviceCertificate c) => DeviceCertificate.fromJson(
            (jsonDecode(jsonEncode(c.toJson())) as Map).cast<String, Object?>())
        .verify(a.accountEdPub);
    Future<bool> fromWireList(SignedDeviceList l) => SignedDeviceList.fromJson(
            (jsonDecode(jsonEncode(l.toJson())) as Map).cast<String, Object?>())
        .verify();

    for (final MapEntry(key: name, value: dx) in {
      ...cases,
      'the device\'s own (control)': honestX,
    }.entries) {
      final strong = identical(dx, honestX);
      expect(handleStrongXKey(dx), strong, reason: name);
      final cert = await a.signDeviceCert(
          deviceEdPub: laptop.edPub, deviceXPub: dx, deviceId: 'l');
      final proven = cert.withPop(await cert.makePop(laptop.edSeed, a.accountEdPub));
      // The account's signature over it is genuine whatever the key.
      expect(
          ed25519VerifyStrict(a.accountEdPub,
              DeviceCertificate.signingInput(laptop.edPub, dx, 'l'), cert.sig),
          isTrue,
          reason: name);
      for (final c in [cert, proven]) {
        expect(await c.verify(a.accountEdPub), strong, reason: name);
        expect(await fromWireCert(c), strong, reason: '$name, wire');
      }
      for (final v2Only in [false, true]) {
        final list =
            await a.signDeviceList([a.deviceCert, proven], 4, v2Only: v2Only);
        expect(await list.verify(), strong, reason: '$name, list');
        expect(await fromWireList(list), strong, reason: '$name, list, wire');
      }
    }

    // Pairing: the existing device refuses to certify a weak key, in each
    // version, where the frame is otherwise exactly what it expects.
    final eph = await _xPub('eph', 0);
    final weakEd = _order2;
    final weakX = _hex(_weakXHex.first);
    for (final (ded, dx, what) in [
      (laptop.edPub, weakX, 'dx'),
      (weakEd, laptop.xPub, 'ded'),
      (laptop.edPub, laptop.xPub, null),
    ]) {
      final why = what ?? 'honest keys (control)';
      // v1: the hello.
      final hello = {
        'ephx': b64(eph),
        'ded': b64(ded),
        'dx': b64(dx),
        'id': 'linked',
      };
      if (what == null) {
        final (_, session) = await PairingResponder.respond(hello);
        expect(session.peerDeviceXPub, dx, reason: 'v1 $why');
      } else {
        await expectLater(PairingResponder.respond(hello),
            throwsA(isA<PairingAbort>().having(
                (e) => e.message, 'message', contains('weak device key: $what'))),
            reason: 'v1 $why');
      }
      // v2: the opening, under a commitment that matches it.
      final open = {...hello};
      final c2 = _sha256(_cat([
        utf8.encode('z-pair-commit-v2:'),
        eph,
        ded,
        dx,
        utf8.encode('linked'),
      ]));
      final (_, r2) = await PairingResponderV2.reply({'c': b64(c2)});
      if (what == null) {
        expect((await r2.accept(open)).peerDeviceEdPub, ded, reason: 'v2 $why');
      } else {
        await expectLater(r2.accept(open),
            throwsA(isA<PairingAbort>().having(
                (e) => e.message, 'message', contains('weak device key: $what'))),
            reason: 'v2 $why');
      }
      // v3: the same, keyed by the code and covering the KEM key.
      final code = PairingCode.generate();
      final (_, ek) = pqGenerate();
      final sk = Uint8List(32)..[0] = 7;
      final mac = await Hmac.sha256().calculateMac(
          _cat([
            utf8.encode('z-pair-commit-v3:'),
            eph,
            ded,
            dx,
            _sha256(ek),
            sk,
            utf8.encode('linked'),
          ]),
          secretKey: SecretKey(await code.pairKey()));
      final (_, r3) = await PairingResponderV3.reply(
          {'c': b64(mac.bytes), 'ek': b64(ek)},
          code: code);
      final open3 = {...open, 'sk': b64(sk)};
      if (what == null) {
        expect((await r3.accept(open3)).peerDeviceXPub, dx, reason: 'v3 $why');
      } else {
        await expectLater(r3.accept(open3),
            throwsA(isA<PairingAbort>().having(
                (e) => e.message, 'message', contains('weak device key: $what'))),
            reason: 'v3 $why');
      }
    }
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('5. every malformed shape of the four parsers, and of the two code '
      'decoders, is a FormatException, never a TypeError', () async {
    final a = await AccountIdentity.generate();
    final laptop = await ZIdentity.generate();
    final cert = await a.signDeviceCert(
        deviceEdPub: laptop.edPub, deviceXPub: laptop.xPub, deviceId: 'l');
    final certJson =
        (jsonDecode(jsonEncode(cert.toJson())) as Map).cast<String, Object?>();
    final list = await a.signDeviceList([a.deviceCert, cert], 2);
    final listJson =
        (jsonDecode(jsonEncode(list.toJson())) as Map).cast<String, Object?>();
    final acctJson = (jsonDecode(jsonEncode(
            a.toAccountBundle(displayName: 'A', otherDevices: [cert]).toJson()))
        as Map).cast<String, Object?>();

    // The controls parse.
    expect(DeviceCertificate.fromJson(certJson).deviceId, 'l');
    expect(SignedDeviceList.fromJson(listJson).version, 2);
    expect(AccountBundle.fromJson(acctJson).devices.length, 2);

    const wrong = <Object?>[null, 5, 1.5, true, <Object?>[], <String, Object?>{}];
    Map<String, Object?> without(Map<String, Object?> j, String k) =>
        {...j}..remove(k);
    Map<String, Object?> withValue(Map<String, Object?> j, String k, Object? v) =>
        {...j, k: v};

    void refuses(Object Function() parse, String why) {
      expect(parse, throwsA(isA<FormatException>()), reason: why);
    }

    // Every member of a certificate, missing or of every wrong type, and a
    // byte member that is not base64; then the same inside a list and an
    // account, where a certificate is read.
    final badCerts = <(String, Object?)>[
      for (final k in ['ded', 'dx', 'id', 'sig']) ...[
        ('$k missing', without(certJson, k)),
        for (final v in wrong) ('$k = ${jsonEncode(v)}', withValue(certJson, k, v)),
      ],
      for (final k in ['ded', 'dx', 'sig'])
        ('$k not base64', withValue(certJson, k, '!!not base64!!')),
      for (final v in wrong) ('pop = ${jsonEncode(v)}', withValue(certJson, 'pop', v)),
    ];
    for (final (why, c) in badCerts) {
      refuses(
          () => DeviceCertificate.fromJson((c as Map).cast<String, Object?>()),
          'certificate: $why');
    }

    final badLists = <(String, Map<String, Object?>)>[
      for (final k in ['acct', 'ver', 'devs']) ('$k missing', without(listJson, k)),
      for (final v in wrong) ('acct = ${jsonEncode(v)}', withValue(listJson, 'acct', v)),
      ('acct not base64', withValue(listJson, 'acct', '!!')),
      for (final v in <Object?>['2', null, true, 2.5, <Object?>[], <String, Object?>{}])
        ('ver = ${jsonEncode(v)}', withValue(listJson, 'ver', v)),
      ('ver = 1e999', withValue(listJson, 'ver', double.infinity)),
      ('ver = NaN', withValue(listJson, 'ver', double.nan)),
      ('ver = 1e300', withValue(listJson, 'ver', 1e300)),
      for (final v in <Object?>[null, 5, 'x', <String, Object?>{}])
        ('devs = ${jsonEncode(v)}', withValue(listJson, 'devs', v)),
      for (final v in <Object?>[null, 5, 'x', <Object?>[]])
        ('a device = ${jsonEncode(v)}', withValue(listJson, 'devs', [certJson, v])),
      for (final (why, c) in badCerts)
        ('a device whose $why', withValue(listJson, 'devs', [certJson, c])),
      for (final k in ['sig', 'sig2', 'sig3'])
        for (final v in wrong) ('$k = ${jsonEncode(v)}', withValue(listJson, k, v)),
    ];
    for (final (why, l) in badLists) {
      refuses(() => SignedDeviceList.fromJson(l), 'list: $why');
    }
    // A whole number written with a fraction part is the number it is, as
    // it always was.
    expect(SignedDeviceList.fromJson(withValue(listJson, 'ver', 2.0)).version, 2);

    final badAccounts = <(String, Map<String, Object?>)>[
      for (final k in ['acct', 'devs']) ('$k missing', without(acctJson, k)),
      for (final v in wrong) ('acct = ${jsonEncode(v)}', withValue(acctJson, 'acct', v)),
      for (final v in <Object?>[null, 5, 'x', <String, Object?>{}])
        ('devs = ${jsonEncode(v)}', withValue(acctJson, 'devs', v)),
      for (final v in <Object?>[5, 'x', <Object?>[]])
        ('a device = ${jsonEncode(v)}', withValue(acctJson, 'devs', [v])),
      for (final (why, c) in badCerts)
        ('a device whose $why', withValue(acctJson, 'devs', [c])),
      for (final v in <Object?>[5, true, <Object?>[], <String, Object?>{}])
        ('name = ${jsonEncode(v)}', withValue(acctJson, 'name', v)),
    ];
    for (final (why, j) in badAccounts) {
      refuses(() => AccountBundle.fromJson(j), 'account: $why');
      // The same members read out of a `zc2.` code.
      final code = 'zc2.${b64url(utf8.encode(jsonEncode({'v': 2, ...j})))}';
      await expectLater(
          AccountBundle.decode(code), throwsA(isA<FormatException>()),
          reason: 'zc2. code: $why');
    }

    // A `zc1.` code's members.
    final id = await ZIdentity.generate();
    final v1 = (jsonDecode(utf8.decode(unb64url(
                (await id.bundle(displayName: 'B')).encode().substring(4))))
            as Map)
        .cast<String, Object?>();
    String zc1(Object? j) => 'zc1.${b64url(utf8.encode(jsonEncode(j)))}';
    expect((await ContactBundle.decode(zc1(v1))).displayName, 'B');
    final badCodes = <(String, Object?)>[
      for (final k in ['ed', 'x', 'sig']) ...[
        ('$k missing', without(v1, k)),
        for (final v in wrong) ('$k = ${jsonEncode(v)}', withValue(v1, k, v)),
        ('$k not base64', withValue(v1, k, '!!')),
      ],
      for (final v in <Object?>[5, true, <Object?>[], <String, Object?>{}])
        ('name = ${jsonEncode(v)}', withValue(v1, 'name', v)),
      ('a list, not an object', [1, 2, 3]),
      ('a string, not an object', 'zc1'),
    ];
    for (final (why, j) in badCodes) {
      await expectLater(ContactBundle.decode(zc1(j)),
          throwsA(isA<FormatException>()),
          reason: 'zc1. code: $why');
      await expectLater(AccountBundle.decode(zc1(j)),
          throwsA(isA<FormatException>()),
          reason: 'zc1. code read as an account: $why');
    }

    // The archive header.
    final header = ZArchive.buildHeader(
        salt: Uint8List(16), noncePrefix: Uint8List(16), schema: 13,
        createdMs: 1);
    final hj = (jsonDecode(utf8.decode(header)) as Map).cast<String, Object?>();
    expect(ZArchive.parseHeader(header)['schema'], 13);
    Uint8List line(Object? j) => Uint8List.fromList(utf8.encode(jsonEncode(j)));
    final badHeaders = <(String, Uint8List)>[
      for (final j in <Object?>[<Object?>[], 'zbk', 5, null, true])
        ('${jsonEncode(j)}, not an object', line(j)),
      ('not JSON', Uint8List.fromList(utf8.encode('{"z":"zbk",'))),
      ('not UTF-8', Uint8List.fromList([0x7b, 0xff, 0xfe, 0x7d])),
      ('z missing', line(without(hj, 'z'))),
      for (final k in ['salt', 'np']) ...[
        ('$k missing', line(without(hj, k))),
        for (final v in wrong) ('$k = ${jsonEncode(v)}', line(withValue(hj, k, v))),
        ('$k not base64', line(withValue(hj, k, '!!'))),
        ('$k 15 bytes', line(withValue(hj, k, b64(Uint8List(15))))),
        ('$k 17 bytes', line(withValue(hj, k, b64(Uint8List(17))))),
      ],
    ];
    for (final (why, h) in badHeaders) {
      refuses(() => ZArchive.parseHeader(h), 'archive header: $why');
    }
    // A newer major is still said as such, whatever else it carries.
    expect(() => ZArchive.parseHeader(line({...without(hj, 'salt'), 'v': 2})),
        throwsA(isA<ArchiveTooNewException>()));
  });
}
