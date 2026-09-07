// Contact code v3 (§13.2): a post-quantum identity that fits in a QR.
//
// The security of the whole arrangement rests on one thing — the QR carries a
// binding COMMITMENT to the post-quantum key, not a reference to it — so the
// tests that matter are the ones where a key arrives that is not the one the
// person in front of you committed to.
import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

void main() {
  group('contact code v3', () {
    late ZIdentity me;
    late HybridKeyPair pq;
    late ContactBundleV3 code;

    setUpAll(() async {
      // The hybrid key's classical half IS the identity's Ed25519 key: one
      // identity, two signature algorithms over it.
      final edSeed = randomBytes(32);
      me = await ZIdentity.fromSeeds(edSeed: edSeed, xSeed: randomBytes(32));
      pq = await HybridKeyPair.fromSeeds(
          edSeed: edSeed, mlSeed: randomBytes(32));
      code = await ContactBundleV3.forIdentity(me, pq.publicKey,
          displayName: 'Finn');
    });

    test('it fits in a QR, which is the entire point', () {
      final s = code.encode();
      expect(s, startsWith('zc3.'));
      // A comfortable QR is a few hundred bytes; the key this commits to is
      // 1952 on its own, and a full hybrid account code would be ~7.4 KB.
      expect(s.length, lessThan(400),
          reason: 'encoded v3 code must stay scannable');
      expect(code.pqCommit.length, 32);
    });

    test('round-trips and verifies', () async {
      final back = await ContactBundleV3.decode(code.encode());
      expect(back.edPub, me.edPub);
      expect(back.xPub, me.xPub);
      expect(back.pqCommit, code.pqCommit);
      expect(back.displayName, 'Finn');
      expect(await back.routingId(), await me.routingId());
      // The classical view is exactly a v1 bundle, so every existing code
      // path — routing, sessions, safety numbers — consumes it unchanged.
      expect(await back.classical.verify(), isTrue);
    });

    test('the committed key is accepted; anything else is not', () async {
      expect(await code.acceptsPqKey(pq.publicKey), isTrue);

      // A different post-quantum key under the same classical identity — the
      // substitution the commitment exists to catch.
      final other = await HybridKeyPair.fromSeeds(
          edSeed: me.edSeed, mlSeed: randomBytes(32));
      expect(await code.acceptsPqKey(other.publicKey), isFalse,
          reason: 'a substituted ML-DSA key must not be accepted');

      // The right post-quantum key under a different classical identity.
      final stranger = await HybridKeyPair.generate();
      final mixed = HybridPublicKey(
          edPub: stranger.publicKey.edPub, mlPub: pq.publicKey.mlPub);
      expect(await code.acceptsPqKey(mixed), isFalse,
          reason: 'the halves must belong to the same identity');
    });

    test(
        'a code whose commitment was altered still parses but accepts '
        'nothing', () async {
      // Tampering with the commitment does not break the binding signature
      // (which covers the X25519 key, not the commitment), so the code still
      // decodes — and then no key on earth satisfies it, which is the correct
      // failure: refuse the identity rather than fall back to classical.
      final j = jsonDecode(utf8.decode(unb64url(code.encode().substring(4))))
          as Map<String, Object?>;
      final bent = Uint8List.fromList(unb64(j['pqc'] as String))..[0] ^= 0x01;
      j['pqc'] = b64(bent);
      final tampered = 'zc3.${b64url(utf8.encode(jsonEncode(j)))}';
      final parsed = await ContactBundleV3.decode(tampered);
      expect(await parsed.acceptsPqKey(pq.publicKey), isFalse);
    });

    test('a tampered classical half is rejected outright', () async {
      final j = jsonDecode(utf8.decode(unb64url(code.encode().substring(4))))
          as Map<String, Object?>;
      j['x'] = b64((await ZIdentity.generate()).xPub);
      expect(
          () => ContactBundleV3.decode(
              'zc3.${b64url(utf8.encode(jsonEncode(j)))}'),
          throwsFormatException);
    });

    test('a v3 code with no commitment is refused, not downgraded', () async {
      // The downgrade: strip the post-quantum promise and hope the reader
      // treats it as an old code. It says v3, so it must carry one.
      final j = jsonDecode(utf8.decode(unb64url(code.encode().substring(4))))
          as Map<String, Object?>;
      j.remove('pqc');
      expect(
          () => ContactBundleV3.decode(
              'zc3.${b64url(utf8.encode(jsonEncode(j)))}'),
          throwsFormatException);
    });

    test('a hybrid key that is not this identity cannot be committed to',
        () async {
      final stranger = await HybridKeyPair.generate();
      expect(() => ContactBundleV3.forIdentity(me, stranger.publicKey),
          throwsFormatException);
    });
  });

  group('scanning any code', () {
    test(
        'v1 reports classical, v3 reports pending, and the difference is '
        'visible to the caller', () async {
      final edSeed = randomBytes(32);
      final id =
          await ZIdentity.fromSeeds(edSeed: edSeed, xSeed: randomBytes(32));
      final pq = await HybridKeyPair.fromSeeds(
          edSeed: edSeed, mlSeed: randomBytes(32));

      final v1 =
          await scanContactCode((await id.bundle(displayName: 'Old')).encode());
      expect(v1.assurance, IdentityAssurance.classical);
      expect(v1.v3, isNull,
          reason: 'nothing post-quantum was promised, so nothing is pending');

      final v3 = await scanContactCode((await ContactBundleV3.forIdentity(
              id, pq.publicKey,
              displayName: 'New'))
          .encode());
      expect(v3.assurance, IdentityAssurance.pendingPostQuantum,
          reason: 'the key is committed to but has not arrived yet');
      expect(v3.v3, isNotNull);
      expect(await v3.classical.routingId(), await id.routingId());

      // Both give the same classical bundle for the same identity, so the
      // rest of the protocol does not care which code was scanned.
      expect(v3.classical.edPub, v1.classical.edPub);
    });

    test('junk is rejected', () async {
      for (final s in ['hello', 'zc9.abc', '', 'zc3.!!!']) {
        expect(() => scanContactCode(s), throwsFormatException, reason: s);
      }
    });
  });

  group('the in-band delivery', () {
    test('a pqid message carries the key the commitment expects', () async {
      final edSeed = randomBytes(32);
      final id =
          await ZIdentity.fromSeeds(edSeed: edSeed, xSeed: randomBytes(32));
      final pq = await HybridKeyPair.fromSeeds(
          edSeed: edSeed, mlSeed: randomBytes(32));
      final code = await ContactBundleV3.forIdentity(id, pq.publicKey);

      final inner = InnerMessage.pqIdentity('m1', 1, pq.publicKey.mlPub);
      final wire = InnerMessage.fromBytes(inner.toBytes());
      expect(wire.kind, 'pqid');
      expect(wire.data['alg'], 'ML-DSA-65');

      final delivered = HybridPublicKey(
          edPub: id.edPub, mlPub: unb64(wire.data['pk'] as String));
      expect(await code.acceptsPqKey(delivered), isTrue);

      // And the same message carrying somebody else's key does not pass.
      final impostor = await HybridKeyPair.generate();
      final forged = InnerMessage.fromBytes(
          InnerMessage.pqIdentity('m2', 2, impostor.publicKey.mlPub).toBytes());
      expect(
          await code.acceptsPqKey(HybridPublicKey(
              edPub: id.edPub, mlPub: unb64(forged.data['pk'] as String))),
          isFalse);
    });
  });
}
