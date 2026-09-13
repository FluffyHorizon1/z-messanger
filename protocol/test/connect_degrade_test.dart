// A v3 contact code that will not decode used to become a classical one.
//
// `ConnectIdentity.fromCode` was a try-v3/catch-`FormatException` ladder, and
// the fallback (`ContactBundle.decode`) does not read `pqc`, `acct` or `cert`
// at all. So any malformed v3 member — a stripped commitment, a stale
// certificate, a truncated account key — quietly produced an identity
// anchored on the DEVICE key with a commitment of 32 zero bytes.
//
// What makes that worse than a downgrade is what the digits are for. Both
// sides degrade the same way, so `_deriveSas` agrees; the humans compare
// eight digits that MATCH; and `confirm()` then records the contact as
// verified — over an identity the comparison never covered. The contact is
// added by re-scanning the same string through `scanContactCode`, which has
// refused these codes since v3 shipped, so the stored record can be
// account-anchored while the number that "verified" it was the device's.
//
// §18.2, §18.3 and §18.7 each require an abort here. `_carriesV3Members`
// exists precisely to route these codes to a refusal; `fromCode` was the one
// identity-reading path that did not use it.
//
// What is asserted below:
//   1. every way a v3 code can fail to decode is an abort, not a downgrade —
//      and `fromCode` agrees with `scanContactCode` on every one of them;
//   2. a genuinely classical code still reads as a classical identity, since
//      that is a supported thing and not a degrade;
//   3. a member of the wrong TYPE is a FormatException rather than a
//      TypeError, which is an Error and escapes every handler between the
//      decode and the ceremony;
//   4. and a reveal carrying such a code aborts the ceremony rather than
//      completing it over a weaker identity.

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

String _mangle(String code, void Function(Map<String, Object?> j) edit) {
  final prefix = code.substring(0, code.indexOf('.') + 1);
  final j = (jsonDecode(utf8.decode(unb64url(code.substring(prefix.length))))
          as Map)
      .cast<String, Object?>();
  edit(j);
  return '$prefix${b64url(utf8.encode(jsonEncode(j)))}';
}

void main() {
  late ZIdentity root;
  late ZIdentity laptop;
  late HybridKeyPair pq;
  late String v3Code;
  late String anchored;

  setUp(() async {
    final edSeed = randomBytes(32);
    root = await ZIdentity.fromSeeds(edSeed: edSeed, xSeed: randomBytes(32));
    laptop = await ZIdentity.fromSeeds(
        edSeed: randomBytes(32), xSeed: randomBytes(32));
    pq = await HybridKeyPair.fromSeeds(edSeed: edSeed, mlSeed: randomBytes(32));
    v3Code = (await ContactBundleV3.forIdentity(root, pq.publicKey,
            displayName: 'Root'))
        .encode();
    final account = await AccountIdentity.fromV1(root);
    final cert = await account.signDeviceCert(
        deviceEdPub: laptop.edPub,
        deviceXPub: laptop.xPub,
        deviceId: 'laptop');
    anchored = (await ContactBundleV3.forIdentity(laptop, pq.publicKey,
            displayName: 'Laptop', accountEdPub: root.edPub, cert: cert))
        .encode();
  });

  test('1. a v3 code that will not decode is refused, never downgraded',
      () async {
    final broken = <String, String>{
      'the commitment stripped from an account-anchored code':
          _mangle(anchored, (j) => j.remove('pqc')),
      'a claim with no proof': _mangle(anchored, (j) => j.remove('cert')),
      'a commitment of the wrong length':
          _mangle(v3Code, (j) => j['pqc'] = b64(Uint8List(16))),
      'an account key of the wrong length':
          _mangle(anchored, (j) => j['acct'] = b64(Uint8List(31))),
      'an account key that is not base64':
          _mangle(anchored, (j) => j['acct'] = 'not base64!'),
      'a certificate that is not a certificate':
          _mangle(anchored, (j) => j['cert'] = <String, Object?>{'no': 'thanks'}),
    };
    for (final e in broken.entries) {
      await expectLater(ConnectIdentity.fromCode(e.value), throwsFormatException,
          reason: e.key);
      // And the two identity-reading paths agree, which is the property that
      // stops this class of bug rather than this instance of it.
      await expectLater(scanContactCode(e.value), throwsFormatException,
          reason: '${e.key} (scan)');
    }
  });

  test('2. a genuinely classical code is still a classical identity',
      () async {
    // Not a degrade: a code carrying no v3 member at all is a supported
    // thing, and it must keep reading as the device-is-the-account identity
    // with a commitment of zeroes.
    final classical =
        (await ContactBundleV3.decode(v3Code)).classical.encode();
    final id = await ConnectIdentity.fromCode(classical);
    expect(b64(id.accountEdPub), b64(root.edPub));
    expect(b64(id.pqCommit), b64(Uint8List(32)),
        reason: 'a classical code commits to nothing');

    // And the v3 code for the same account reads as the hybrid identity,
    // which is a DIFFERENT identity to confirm (§18.2).
    final hybrid = await ConnectIdentity.fromCode(v3Code);
    expect(b64(hybrid.accountEdPub), b64(root.edPub));
    expect(b64(hybrid.pqCommit), isNot(b64(Uint8List(32))));

    // The account-anchored code names the ACCOUNT, not the laptop holding it.
    final byLaptop = await ConnectIdentity.fromCode(anchored);
    expect(b64(byLaptop.accountEdPub), b64(root.edPub),
        reason: 'the device is not the account when a cert says otherwise');
    expect(b64(byLaptop.accountEdPub), isNot(b64(laptop.edPub)));
  });

  test('3. a member of the wrong type is malformed, not an Error', () async {
    // `j['ed'] as String` throws a TypeError, which is an Error and not an
    // Exception — so it escapes `on FormatException` at every layer between
    // the decode and the ceremony, and comes out raw with the invite unspent.
    for (final edit in <void Function(Map<String, Object?>)>[
      (j) => j.remove('ed'),
      (j) => j['ed'] = 42,
      (j) => j['x'] = <String, Object?>{},
      (j) => j['sig'] = false,
      (j) => j['name'] = 7,
    ]) {
      final bad = _mangle(v3Code, edit);
      await expectLater(ContactBundleV3.decode(bad), throwsFormatException);
      await expectLater(ConnectIdentity.fromCode(bad), throwsFormatException);
    }
  });

  test('4. a reveal carrying such a code aborts the ceremony', () async {
    final alice = await ConnectIdentity.fromCode(v3Code, displayName: 'Root');
    final bobSeed = randomBytes(32);
    final bobId =
        await ZIdentity.fromSeeds(edSeed: bobSeed, xSeed: randomBytes(32));
    final bobPq =
        await HybridKeyPair.fromSeeds(edSeed: bobSeed, mlSeed: randomBytes(32));
    final bobCode = (await ContactBundleV3.forIdentity(bobId, bobPq.publicKey,
            displayName: 'Bob'))
        .encode();
    final bob = await ConnectIdentity.fromCode(bobCode, displayName: 'Bob');

    // The ceremony, honestly, up to the point where the acceptor reveals.
    final inviter = await ConnectInviter.create(me: alice);
    final (reply, acceptor) =
        await ConnectAcceptor.reply(await inviter.commit(), me: bob);
    final opening = await inviter.open(reply);
    final (_, session) = await acceptor.accept(opening);

    // And now the reveal the acceptor did NOT send: the same ceremony, the
    // same channel key, with a code inside that will not decode. Before this
    // change the inviter read it as Bob's DEVICE key with a commitment of
    // zeroes, derived digits over that, and — because the acceptor degraded
    // the same way — the two sides agreed. The humans compare eight matching
    // digits and the app writes `verified`.
    final poisoned = _mangle(bobCode, (j) => j.remove('pqc'));
    final aead = Chacha20.poly1305Aead();
    final box = await aead.encrypt(
        Uint8List.fromList(
            utf8.encode(jsonEncode({'code': poisoned, 'name': 'Bob'}))),
        secretKey: SecretKey(session.channelKey),
        nonce: randomBytes(12));
    final blob = {'blob': b64(Uint8List.fromList(box.concatenation()))};

    await expectLater(inviter.complete(blob), throwsA(isA<ConnectAbort>()),
        reason: 'an unusable code is an abort, not a weaker identity');

    // The honest reveal still completes, so the abort is about the code and
    // not about the frame.
    final inviter2 = await ConnectInviter.create(me: alice);
    final (reply2, acceptor2) =
        await ConnectAcceptor.reply(await inviter2.commit(), me: bob);
    final opening2 = await inviter2.open(reply2);
    final (honest, session2) = await acceptor2.accept(opening2);
    final done = await inviter2.complete(honest);
    expect(done.sas, session2.sas);
    expect(b64(done.peer.accountEdPub), b64(bobId.edPub));
    expect(b64(done.peer.pqCommit), isNot(b64(Uint8List(32))),
        reason: 'the identity the digits covered is the hybrid one');
  });
}
