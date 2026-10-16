import 'dart:typed_data';

import 'package:cryptography/cryptography.dart'
    show KeyPairType, SimplePublicKey, X25519;
import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

Uint8List _hex(String s) => Uint8List.fromList([
      for (var i = 0; i < s.length; i += 2)
        int.parse(s.substring(i, i + 2), radix: 16)
    ]);

/// Every spelling X25519 reads as a point of small order: the five u of
/// PROTOCOL §21.4, the two encodings at or above p that reduce to 0 and 1,
/// and each of the seven with the top bit set, which X25519 ignores.
final List<Uint8List> smallOrderSpellings = () {
  final canonical = [
    '0000000000000000000000000000000000000000000000000000000000000000',
    '0100000000000000000000000000000000000000000000000000000000000000',
    'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
    '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
    'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', // p
    'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', // p + 1
  ].map(_hex).toList();
  return [
    ...canonical,
    for (final k in canonical) Uint8List.fromList(k)..[31] |= 0x80,
  ];
}();

void main() {
  group('a recipient key of small order (RFC 7748 §6.1)', () {
    test('each spelling agrees all zeros with any key, so an envelope sealed '
        'to it would be open to anyone', () async {
      // The premise, checked with the primitive rather than taken on trust:
      // what `seal` refuses is exactly what makes its key public.
      final x = X25519();
      for (final k in smallOrderSpellings) {
        for (var i = 0; i < 3; i++) {
          final s = await x.sharedSecretKey(
              keyPair: await x.newKeyPairFromSeed(randomBytes(32)),
              remotePublicKey: SimplePublicKey(k, type: KeyPairType.x25519));
          expect(await s.extractBytes(), everyElement(0), reason: b64(k));
        }
      }
    });

    test('is refused, and nothing is produced', () async {
      final rid = await (await ZIdentity.generate()).routingId();
      for (final k in smallOrderSpellings) {
        await expectLater(
            SealedEnvelope.seal(toXPub: k, fromRid: rid, payload: 'p'),
            throwsA(isA<SealRefusedException>()),
            reason: b64(k));
      }
    });

    test('is the only refusal: an honest key always seals and opens', () async {
      final rid = await (await ZIdentity.generate()).routingId();
      for (var i = 0; i < 32; i++) {
        final bob = await ZIdentity.generate();
        final blob = await SealedEnvelope.seal(
            toXPub: bob.xPub, fromRid: rid, payload: 'p$i');
        final opened = await SealedEnvelope.open(
            myXSeed: bob.xSeed, myXPub: bob.xPub, blob: blob);
        expect(opened?.payload, 'p$i');
      }
    });
  });

  group('sealed sender envelope', () {
    test('round-trips sender and payload; only the recipient can open it',
        () async {
      final alice = await ZIdentity.generate();
      final bob = await ZIdentity.generate();
      final eve = await ZIdentity.generate();
      final aliceRid = await alice.routingId();

      final blob = await SealedEnvelope.seal(
          toXPub: bob.xPub, fromRid: aliceRid, payload: 'ratchet-ciphertext');
      expect(SealedEnvelope.looksSealed(blob), isTrue);

      final opened = await SealedEnvelope.open(
          myXSeed: bob.xSeed, myXPub: bob.xPub, blob: blob);
      expect(opened, isNotNull);
      expect(opened!.fromRid, aliceRid);
      expect(opened.payload, 'ratchet-ciphertext');

      // The wrong recipient learns nothing — not even that it failed "almost".
      expect(
          await SealedEnvelope.open(
              myXSeed: eve.xSeed, myXPub: eve.xPub, blob: blob),
          isNull);
    });

    test('the blob leaks no sender bytes', () async {
      final alice = await ZIdentity.generate();
      final bob = await ZIdentity.generate();
      final aliceRid = await alice.routingId();
      final blob = await SealedEnvelope.seal(
          toXPub: bob.xPub, fromRid: aliceRid, payload: 'x');
      expect(blob.contains(aliceRid), isFalse);
      expect(blob.contains(aliceRid.substring(0, 12)), isFalse);
    });

    test('tampering is rejected', () async {
      final alice = await ZIdentity.generate();
      final bob = await ZIdentity.generate();
      final blob = await SealedEnvelope.seal(
          toXPub: bob.xPub,
          fromRid: await alice.routingId(),
          payload: 'payload');
      // Flip one character in the body (past the prefix).
      final i = blob.length ~/ 2;
      final flipped = blob.substring(0, i) +
          (blob[i] == 'A' ? 'B' : 'A') +
          blob.substring(i + 1);
      expect(
          await SealedEnvelope.open(
              myXSeed: bob.xSeed, myXPub: bob.xPub, blob: flipped),
          isNull);
    });

    test('padding makes different-length payloads the same size', () async {
      final alice = await ZIdentity.generate();
      final bob = await ZIdentity.generate();
      final rid = await alice.routingId();
      final a = await SealedEnvelope.seal(
          toXPub: bob.xPub, fromRid: rid, payload: 'hi');
      final b = await SealedEnvelope.seal(
          toXPub: bob.xPub, fromRid: rid, payload: 'x' * 500);
      expect(a.length, b.length,
          reason: 'both fit the first bucket, so blobs must match in size');
      final c = await SealedEnvelope.seal(
          toXPub: bob.xPub, fromRid: rid, payload: 'x' * 3000);
      expect(c.length, greaterThan(a.length)); // next bucket
      // Round-trips still exact.
      final ob = await SealedEnvelope.open(
          myXSeed: bob.xSeed, myXPub: bob.xPub, blob: b);
      expect(ob!.payload.length, 500);
    });

    test('a large chunk-sized payload seals and opens', () async {
      final alice = await ZIdentity.generate();
      final bob = await ZIdentity.generate();
      final big = String.fromCharCodes(
          Uint8List.fromList(List.generate(900 * 1024, (i) => 65 + (i % 26))));
      final blob = await SealedEnvelope.seal(
          toXPub: bob.xPub, fromRid: await alice.routingId(), payload: big);
      final opened = await SealedEnvelope.open(
          myXSeed: bob.xSeed, myXPub: bob.xPub, blob: blob);
      expect(opened!.payload.length, big.length);
    });

    test('non-sealed payloads are recognised as such', () {
      expect(SealedEnvelope.looksSealed('{"v":1}'), isFalse);
      expect(SealedEnvelope.looksSealed('zc1.abc'), isFalse);
      expect(SealedEnvelope.looksSealed('zs1.abc'), isTrue);
    });

    test('a max-size attachment chunk, sealed, fits the relay frame cap',
        () async {
      // Regression: 480 KiB chunks sealed to ~1.5 MB and were rejected by the
      // relay (MAX_ENVELOPE_BYTES = 1,000,000) as too_large, silently breaking
      // every attachment over ~147 KB once sealed sender shipped.
      final bob = await ZIdentity.generate();
      final km = FileKeyMaterial.generate();
      final chunk = await encryptChunk(km, 0, Uint8List(defaultChunkSize));
      final blob = await SealedEnvelope.seal(
          toXPub: bob.xPub, fromRid: 'x' * 43, payload: chunk);
      expect(blob.length, lessThanOrEqualTo(1000000));
      // ...and lands in the 262144 bucket, so every chunk envelope is the same
      // size on the wire.
      final raw = unb64url(blob.substring(4));
      expect(raw.length - 32 - 12 - 16, 262144);
    });
  });
}
