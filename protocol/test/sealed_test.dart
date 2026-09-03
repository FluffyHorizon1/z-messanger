import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

void main() {
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
