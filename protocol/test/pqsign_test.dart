// Protocol v3 (§13.1): hybrid Ed25519 + ML-DSA-65 signatures.
//
// The attack this module exists to stop is a downgrade. An adversary who can
// forge Ed25519 — the whole premise of the phase — strips the half they
// cannot forge and presents the half they can. So the interesting tests here
// are the negative ones: every way of arriving at a verifier with less than
// two good signatures must fail, and a stripped signature must not even be
// expressible as a value a verifier could evaluate.
import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

Uint8List msg(String s) => Uint8List.fromList(utf8.encode(s));

void main() {
  group('hybrid signatures', () {
    late HybridKeyPair kp;
    late Uint8List m;
    late HybridSignature sig;

    setUpAll(() async {
      kp = await HybridKeyPair.generate();
      m = msg('z-device-cert-v1:laptop');
      sig = await kp.sign(m);
    });

    test('sizes match FIPS 204 and the identity stays seed-derived', () {
      expect(kp.publicKey.edPub.length, 32);
      expect(kp.publicKey.mlPub.length, 1952);
      expect(sig.ed.length, 64);
      expect(sig.ml.length, 3309);
      // The secret material an identity has to persist is two 32-byte seeds,
      // not a 4032-byte ML-DSA secret key: a backup archive carries 32 more
      // bytes rather than four kilobytes.
      expect(kp.edSeed.length, 32);
      expect(kp.mlSeed.length, 32);
    });

    test('a genuine signature verifies', () async {
      expect(await hybridVerify(kp.publicKey, m, sig), isTrue);
    });

    test('the same seeds reproduce the same identity', () async {
      final again =
          await HybridKeyPair.fromSeeds(edSeed: kp.edSeed, mlSeed: kp.mlSeed);
      expect(again.publicKey.edPub, kp.publicKey.edPub);
      expect(again.publicKey.mlPub, kp.publicKey.mlPub);
      // …so a restored identity can still verify what the original signed,
      // which is what makes phase 9 restore work at all.
      expect(await hybridVerify(again.publicKey, m, sig), isTrue);
    });

    test('a signature with only a valid classical half is rejected', () async {
      // The exit criterion for the phase, stated directly. Take a REAL
      // Ed25519 signature and pair it with an ML-DSA signature over different
      // bytes: exactly what an adversary who has broken Ed25519 can produce.
      final other = await kp.sign(msg('z-device-cert-v1:not-this-one'));
      final forged = HybridSignature(ed: sig.ed, ml: other.ml);
      expect(await hybridVerify(kp.publicKey, m, forged), isFalse);
    });

    test('a signature with only a valid post-quantum half is rejected',
        () async {
      final other = await kp.sign(msg('z-device-cert-v1:not-this-one'));
      final forged = HybridSignature(ed: other.ed, ml: sig.ml);
      expect(await hybridVerify(kp.publicKey, m, forged), isFalse);
    });

    test('a stripped signature does not parse at all', () {
      // Stripping must not be expressible. A verifier should never be handed
      // a half-signature it could evaluate and return false for, because a
      // false is something callers retry and log; this is a structural fault.
      final full = sig.toJson();
      expect(() => HybridSignature.fromJson({'ed': full['ed']}),
          throwsA(isA<HybridFormatException>()));
      expect(() => HybridSignature.fromJson({'ml': full['ml']}),
          throwsA(isA<HybridFormatException>()));
      expect(() => HybridSignature.fromJson({}),
          throwsA(isA<HybridFormatException>()));
      // …and a wrong-length half is refused rather than padded or truncated.
      expect(
          () => HybridSignature(
              ed: sig.ed, ml: Uint8List.fromList(sig.ml.sublist(0, 100))),
          throwsA(isA<HybridFormatException>()));
    });

    test('a half-length public key does not parse either', () {
      expect(() => HybridPublicKey.fromJson({'ed': b64(kp.publicKey.edPub)}),
          throwsA(isA<HybridFormatException>()));
      expect(
          () => HybridPublicKey(
              edPub: kp.publicKey.edPub, mlPub: Uint8List(1951)),
          throwsA(isA<HybridFormatException>()));
    });

    test('another identity cannot verify, on either half', () async {
      final other = await HybridKeyPair.generate();
      expect(await hybridVerify(other.publicKey, m, sig), isFalse);
      // Mixing your Ed25519 key with someone else's ML-DSA key fails too, so
      // a stolen half cannot be paired with one you control.
      final mixed = HybridPublicKey(
          edPub: kp.publicKey.edPub, mlPub: other.publicKey.mlPub);
      expect(await hybridVerify(mixed, m, sig), isFalse);
    });

    test('a tampered message fails', () async {
      expect(
          await hybridVerify(kp.publicKey, msg('z-device-cert-v1:laptoq'), sig),
          isFalse);
    });

    test('garbage in a signature returns false, never throws', () async {
      // A hostile peer must not be able to turn verification into an
      // exception a caller might handle as something other than "no".
      final junk = HybridSignature(
          ed: Uint8List(64), ml: Uint8List(3309)..fillRange(0, 3309, 0xff));
      expect(await hybridVerify(kp.publicKey, m, junk), isFalse);
    });

    test('the commitment binds the post-quantum key, and only it', () async {
      // ADR 0003: this 32-byte value is what a `zc3.` QR carries in place of
      // the 1952-byte key, so the key can travel in-band and still be bound
      // to the exchange the two people actually performed.
      final c = await kp.publicKey.pqCommitment();
      expect(c.length, 32);
      final again =
          await HybridKeyPair.fromSeeds(edSeed: kp.edSeed, mlSeed: kp.mlSeed);
      expect(await again.publicKey.pqCommitment(), c, reason: 'deterministic');

      final other = await HybridKeyPair.generate();
      expect(await other.publicKey.pqCommitment(), isNot(c));

      // It commits to the ML-DSA half alone: the same PQ key under a
      // different Ed25519 key gives the same commitment, which is why the
      // classical half travels in the QR in full rather than under a hash.
      final swapped = HybridPublicKey(
          edPub: other.publicKey.edPub, mlPub: kp.publicKey.mlPub);
      expect(await swapped.pqCommitment(), c);

      // And it is domain-separated, so it can never collide with a bare hash
      // of the key computed for some other purpose.
      final bare = await sha256Bytes(kp.publicKey.mlPub);
      expect(c, isNot(bare));
    });
  });
}
