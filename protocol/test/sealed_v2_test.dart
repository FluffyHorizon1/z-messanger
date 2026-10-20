// The hybrid sealed outer layer, `zs2.` (44.1; ADR 0033 §5, PROTOCOL §8.2):
// `zs1.` with an ML-KEM-768 encapsulation to the recipient device's sealing
// key mixed into the envelope's key. Built in the library only — no client
// seals or opens one before 44.7, which waits for constant-time ML-KEM
// upstream — so everything here drives `SealedEnvelopeV2` directly.
//
// The adversary is ADR 0033's: it holds every classical private key — the
// recipient's X25519 seed among them — and no ML-KEM or ML-DSA secret. Under
// `zs1.` that adversary reads the sender of every envelope it recorded; under
// `zs2.` it must read nothing.
//
// Exit criteria, each a test below:
//   1. an envelope opens with the recipient device's X25519 key and sealing
//      key, giving back the sender and the payload, in every bucket, and with
//      nothing else: another device's two keys open none of it;
//   2. the envelope is exactly §8.2's, re-derived here from the primitives
//      rather than taken from the library: its layout, the key
//      HKDF(X25519(eph, xPub) || K, ∅, "z-sealed-v2" || ephPub || xPub ||
//      SHA-256(ct), 32), the associated data and §8's padding of {f, p};
//   3. the adversary opens nothing: not with the recipient's X25519 seed and
//      a sealing key of its own, not with K guessed as zeros, and not by
//      stripping the KEM ciphertext and reading what is left as `zs1.`;
//   4. a swapped KEM ciphertext — another encapsulation to the same key, or
//      another envelope's — and a stripped one return what `zs1.`'s open
//      returns for a bad envelope (null), and so do a `zs1.` body under
//      `zs2.`, a `zs2.` body under `zs1.`, a truncated envelope and a flipped
//      bit anywhere in one;
//   5. the KEM ciphertext sits outside the padding: the box is exactly one of
//      §8's buckets, the bucket a payload lands in is the one it lands in as
//      `zs1.` on both sides of a boundary, and neither prefix's reader takes
//      the other's;
//   6. a recipient X25519 key of small order is refused for `zs2.` as `zs1.`
//      refuses it, in every spelling — once the ephemeral seed is drawn,
//      which the check needs, and before the encapsulation or the nonce is —
//      and a sealing key FIPS 203 §7.2 refuses is refused before anything is
//      drawn; either way nothing is produced;
//   7. the only seam is the protocol's RNG: a seal draws the ephemeral seed,
//      the encapsulation's m and the nonce, in that order, and nothing else;
//      the envelope is a function of those three draws, and two seals of one
//      payload left to the RNG differ.
import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';
import 'package:z_protocol/src/util.dart' show concatBytes, randomOverrideKey;
import 'package:z_protocol/z_protocol.dart';

// The fourteen X25519 spellings of a point of small order, as `zs1.`'s
// refusal is tested with them (patch 95).
import 'sealed_test.dart' show smallOrderSpellings;

Uint8List utf8b(String s) => Uint8List.fromList(utf8.encode(s));

Future<Uint8List> sha256(List<int> b) async =>
    Uint8List.fromList((await Sha256().hash(b)).bytes);

Future<Uint8List> x25519(Uint8List seed, Uint8List pub) async {
  final x = X25519();
  final s = await x.sharedSecretKey(
      keyPair: await x.newKeyPairFromSeed(seed),
      remotePublicKey: SimplePublicKey(pub, type: KeyPairType.x25519));
  return Uint8List.fromList(await s.extractBytes());
}

Future<Uint8List> hkdf(List<int> ikm, List<int> info) async {
  final k = await Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
      secretKey: SecretKey(ikm), nonce: Uint8List(0), info: info);
  return Uint8List.fromList(await k.extractBytes());
}

/// ChaCha20-Poly1305 open, or null when the tag does not verify.
Future<Uint8List?> aeadOpen(Uint8List key, Uint8List nonce, Uint8List box,
    Uint8List mac, String aad) async {
  try {
    return Uint8List.fromList(await Chacha20.poly1305Aead().decrypt(
        SecretBox(box, nonce: nonce, mac: Mac(mac)),
        secretKey: SecretKey(key),
        aad: utf8b(aad)));
  } on SecretBoxAuthenticationError {
    return null;
  }
}

/// A device: its X25519 identity and its sealing key.
class Device {
  final ZIdentity id;
  final SealingKey seal;
  Device(this.id, this.seal);
  static Future<Device> make() async =>
      Device(await ZIdentity.generate(), SealingKey.generate());
  Future<({String fromRid, String payload})?> open(String blob) =>
      SealedEnvelopeV2.open(
          myXSeed: id.xSeed, myXPub: id.xPub, mySealKey: seal, blob: blob);
}

/// The parts of a `zs2.` body, by §8.2's layout.
({
  Uint8List eph,
  Uint8List ct,
  Uint8List nonce,
  Uint8List box,
  Uint8List mac
}) parts(String blob) {
  final raw = unb64url(blob.substring(4));
  return (
    eph: raw.sublist(0, 32),
    ct: raw.sublist(32, 1120),
    nonce: raw.sublist(1120, 1132),
    box: raw.sublist(1132, raw.length - 16),
    mac: raw.sublist(raw.length - 16),
  );
}

String zs2(List<List<int>> body) => 'zs2.${b64url(concatBytes(body))}';

/// Runs [body] with the protocol's random draws served from [draws] in
/// order, recording each request's length.
Future<T> scripted<T>(List<Uint8List> draws, List<int> asked,
    Future<T> Function() body) {
  var i = 0;
  return runZoned(body, zoneValues: {
    randomOverrideKey: (int n) {
      asked.add(n);
      if (i >= draws.length) fail('more random draws than scripted');
      final d = draws[i++];
      if (d.length != n) fail('draw $i is ${d.length} bytes, asked $n');
      return d;
    }
  });
}

void main() {
  late Device alice, bob, carol;
  late String aliceRid;
  setUpAll(() async {
    alice = await Device.make();
    bob = await Device.make();
    carol = await Device.make();
    aliceRid = await alice.id.routingId();
  });

  Future<String> sealToBob(String payload) => SealedEnvelopeV2.seal(
      toXPub: bob.id.xPub,
      toSealEk: bob.seal.ek,
      fromRid: aliceRid,
      payload: payload);

  test('1. it opens with the recipient device\'s two keys, in every bucket, '
      'and with no other device\'s', () async {
    for (final n in [10, 1500, 6000, 30000, 200000, 900000]) {
      final payload = String.fromCharCodes(
          List.generate(n, (i) => 0x41 + i % 26));
      final blob = await sealToBob(payload);
      expect(SealedEnvelopeV2.looksSealed(blob), isTrue);
      final opened = await bob.open(blob);
      expect(opened?.fromRid, aliceRid, reason: '$n characters');
      expect(opened?.payload, payload, reason: '$n characters');
      expect(await carol.open(blob), isNull,
          reason: "another device's X25519 key and sealing key: $n");
    }
    // Each of Bob's keys with the other's wrong half opens nothing either.
    final blob = await sealToBob('p');
    expect(
        await SealedEnvelopeV2.open(
            myXSeed: carol.id.xSeed,
            myXPub: carol.id.xPub,
            mySealKey: bob.seal,
            blob: blob),
        isNull,
        reason: "Bob's sealing key, Carol's X25519 key");
    expect(
        await SealedEnvelopeV2.open(
            myXSeed: bob.id.xSeed,
            myXPub: bob.id.xPub,
            mySealKey: carol.seal,
            blob: blob),
        isNull,
        reason: "Bob's X25519 key, Carol's sealing key");
  });

  test('2. the envelope is §8.2\'s, re-derived from the primitives', () async {
    final draws = [randomBytes(32), randomBytes(32), randomBytes(12)];
    const payload = 'ratchet-ciphertext-placeholder';
    final blob = await scripted(draws, [], () => sealToBob(payload));
    expect(blob, startsWith('zs2.'));
    final p = parts(blob);
    final ephSeed = draws[0], m = draws[1], nonce = draws[2];

    // Layout: ephPub, the KEM ciphertext, the nonce, the box, the MAC.
    final ephPub = Uint8List.fromList((await (await X25519()
                .newKeyPairFromSeed(ephSeed))
            .extractPublicKey())
        .bytes);
    expect(p.eph, ephPub, reason: 'ephPub(32) first');
    final (ct, k) = pqEncapsulate(bob.seal.ek, m: m);
    expect(p.ct, ct, reason: 'then ct(1088) = Encaps_internal(sealEk, m)');
    expect(p.nonce, nonce, reason: 'then the nonce(12)');

    // The key, by the formula.
    final shared = await x25519(ephSeed, bob.id.xPub);
    final key = await hkdf(
        [...shared, ...k],
        concatBytes([
          utf8b('z-sealed-v2'),
          ephPub,
          bob.id.xPub,
          await sha256(ct),
        ]));
    final plain = await aeadOpen(key, nonce, p.box, p.mac, 'z-sealed-v2');
    expect(plain, isNotNull,
        reason: 'the box opens under HKDF(X25519 || K, ∅, "z-sealed-v2" || '
            'ephPub || xPub || SHA-256(ct)) with aad "z-sealed-v2"');

    // §8's padding: u32be(len) || {f, p} || zeros, to the bucket.
    final inner = utf8b(jsonEncode({'f': aliceRid, 'p': payload}));
    expect(plain!.length, 1024);
    expect(ByteData.view(plain.buffer).getUint32(0), inner.length);
    expect(plain.sublist(4, 4 + inner.length), inner);
    expect(plain.sublist(4 + inner.length), everyElement(0));

    // And the recipient's side of the agreement is the same secret.
    expect(await x25519(bob.id.xSeed, ephPub), shared);
    expect(bob.seal.decapsulate(ct), k);
  });

  test('3. every classical private key, and no ML-KEM secret, opens nothing',
      () async {
    const payload = 'who sent this?';
    final blob = await sealToBob(payload);
    final p = parts(blob);
    // What zs1. would have given this adversary: Bob's X25519 seed is enough.
    final zs1Blob = await SealedEnvelope.seal(
        toXPub: bob.id.xPub, fromRid: aliceRid, payload: payload);
    expect(
        (await SealedEnvelope.open(
                myXSeed: bob.id.xSeed, myXPub: bob.id.xPub, blob: zs1Blob))
            ?.fromRid,
        aliceRid,
        reason: 'the premise: zs1. falls to the X25519 key alone');

    // a) Bob's X25519 seed, and a sealing key of the adversary's own.
    for (var i = 0; i < 4; i++) {
      expect(
          await SealedEnvelopeV2.open(
              myXSeed: bob.id.xSeed,
              myXPub: bob.id.xPub,
              mySealKey: SealingKey.generate(),
              blob: blob),
          isNull);
    }
    // b) Bob's X25519 seed, and K guessed: zeros, or the shared secret again.
    final shared = await x25519(bob.id.xSeed, p.eph);
    final info = concatBytes(
        [utf8b('z-sealed-v2'), p.eph, bob.id.xPub, await sha256(p.ct)]);
    for (final guess in [Uint8List(32), shared]) {
      final key = await hkdf([...shared, ...guess], info);
      expect(await aeadOpen(key, p.nonce, p.box, p.mac, 'z-sealed-v2'), isNull);
    }
    // ... or no K at all, which is the key a mixing that dropped it would use.
    expect(
        await aeadOpen(await hkdf(shared, info), p.nonce, p.box, p.mac,
            'z-sealed-v2'),
        isNull);
    // c) The KEM ciphertext stripped and the rest read as zs1.
    final stripped = 'zs1.${b64url(concatBytes([p.eph, p.nonce, p.box, p.mac]))}';
    expect(
        await SealedEnvelope.open(
            myXSeed: bob.id.xSeed, myXPub: bob.id.xPub, blob: stripped),
        isNull);
    // Nothing in the envelope names the sender in the clear.
    expect(blob.contains(aliceRid), isFalse);
  });

  test('4. a swapped or stripped KEM ciphertext, and every other alteration, '
      'is null', () async {
    final blob = await sealToBob('x' * 3000); // the 4 096 bucket
    final other = await sealToBob('x' * 3000);
    final p = parts(blob), q = parts(other);
    final (fresh, _) = pqEncapsulate(bob.seal.ek);
    final cases = <String, String>{
      'another encapsulation to the same key':
          zs2([p.eph, fresh, p.nonce, p.box, p.mac]),
      "another envelope's ciphertext": zs2([p.eph, q.ct, p.nonce, p.box, p.mac]),
      'an encapsulation to another device':
          zs2([p.eph, pqEncapsulate(carol.seal.ek).$1, p.nonce, p.box, p.mac]),
      'the ciphertext stripped, as zs2.': zs2([p.eph, p.nonce, p.box, p.mac]),
      'the ciphertext stripped, as zs1.':
          'zs1.${b64url(concatBytes([p.eph, p.nonce, p.box, p.mac]))}',
      'a zs1. body under zs2.': 'zs2.${(await SealedEnvelope.seal(
          toXPub: bob.id.xPub, fromRid: aliceRid, payload: 'x' * 3000)).substring(4)}',
      'a zs2. body under zs1.': 'zs1.${blob.substring(4)}',
      'truncated by one byte': zs2([p.eph, p.ct, p.nonce, p.box, p.mac.sublist(1)]),
      'shorter than any zs2. body': zs2([p.eph, p.ct, p.nonce, p.mac.sublist(1)]),
      'not base64url': 'zs2.!!!!',
      'empty': 'zs2.',
    };
    for (final e in cases.entries) {
      expect(await bob.open(e.value), isNull, reason: e.key);
      expect(
          await SealedEnvelope.open(
              myXSeed: bob.id.xSeed, myXPub: bob.id.xPub, blob: e.value),
          isNull,
          reason: 'and as zs1.: ${e.key}');
    }
    // A flipped bit in each part: ephPub, ct, nonce, box (start, middle,
    // end) and the MAC.
    final raw = unb64url(blob.substring(4));
    for (final at in [0, 31, 32, 600, 1119, 1120, 1131, 1132, 2000,
        raw.length - 17, raw.length - 16, raw.length - 1]) {
      final flipped = Uint8List.fromList(raw)..[at] ^= 0x01;
      expect(await bob.open('zs2.${b64url(flipped)}'), isNull,
          reason: 'bit flipped at byte $at');
    }
    expect((await bob.open(blob))?.payload, 'x' * 3000,
        reason: 'the genuine envelope still opens');
  });

  test('5. the KEM ciphertext is outside the padding: a payload lands in '
      'the bucket it lands in as zs1.', () async {
    final exactFit = 1024 - 4 - '{"f":"","p":""}'.length - aliceRid.length;
    for (final (n, bucket) in [
      (exactFit, 1024),
      (exactFit + 1, 4096),
      (4096 - 4 - 15 - aliceRid.length, 4096),
      (4096 - 4 - 15 - aliceRid.length + 1, 16384),
    ]) {
      final payload = 'B' * n;
      final blob = await sealToBob(payload);
      final p = parts(blob);
      expect(p.box.length, bucket, reason: '$n characters: the box');
      expect(sealedBuckets, contains(p.box.length));
      final z1 = await SealedEnvelope.seal(
          toXPub: bob.id.xPub, fromRid: aliceRid, payload: payload);
      expect(unb64url(z1.substring(4)).length - 60, bucket,
          reason: '$n characters: the same bucket as zs1.');
      expect(blob.length, z1.length + SealedEnvelopeV2.extraChars,
          reason: '$n characters');
    }
    // Neither reader takes the other's prefix.
    final blob = await sealToBob('p');
    expect(SealedEnvelope.looksSealed(blob), isFalse);
    expect(
        SealedEnvelopeV2.looksSealed(await SealedEnvelope.seal(
            toXPub: bob.id.xPub, fromRid: aliceRid, payload: 'p')),
        isFalse);
  });

  test('6. a key of small order, or a sealing key FIPS 203 refuses, is '
      'refused before the encapsulation is drawn', () async {
    for (final k in smallOrderSpellings) {
      final asked = <int>[];
      await expectLater(
          scripted([randomBytes(32)], asked, () => SealedEnvelopeV2.seal(
              toXPub: k,
              toSealEk: bob.seal.ek,
              fromRid: aliceRid,
              payload: 'p')),
          throwsA(isA<SealRefusedException>()),
          reason: b64(k));
      // The ephemeral seed is drawn before the agreement can be checked, as
      // for zs1.; the encapsulation and the nonce never are.
      expect(asked, [32], reason: b64(k));
    }
    final ek = bob.seal.ek;
    final atQ = Uint8List.fromList(ek)
      ..[0] = 0x01
      ..[1] = (ek[1] & 0xf0) | 0x0d; // the first coefficient of t̂ at q, 3329
    for (final (why, bad) in [
      ('a byte short', Uint8List.fromList(ek.sublist(0, 1183))),
      ('a byte long', Uint8List.fromList([...ek, 0])),
      ('a coefficient at q', atQ),
      ('empty', Uint8List(0)),
    ]) {
      final asked = <int>[];
      await expectLater(
          scripted(const [], asked, () => SealedEnvelopeV2.seal(
              toXPub: bob.id.xPub, toSealEk: bad, fromRid: aliceRid, payload: 'p')),
          throwsArgumentError,
          reason: why);
      expect(asked, isEmpty, reason: '$why: nothing drawn');
    }
    // An honest pair of keys always seals.
    for (var i = 0; i < 8; i++) {
      final d = await Device.make();
      final blob = await SealedEnvelopeV2.seal(
          toXPub: d.id.xPub, toSealEk: d.seal.ek, fromRid: aliceRid, payload: '$i');
      expect((await d.open(blob))?.payload, '$i');
    }
  });

  test('7. a seal draws eph, m and the nonce, in that order, and is a '
      'function of them', () async {
    final draws = [randomBytes(32), randomBytes(32), randomBytes(12)];
    final asked = <int>[];
    final once = await scripted(draws, asked, () => sealToBob('same'));
    expect(asked, [32, 32, 12]);
    final twice = await scripted(draws, [], () => sealToBob('same'));
    expect(twice, once, reason: 'the same three draws, the same envelope');
    // Each draw is where §8.2 says it goes.
    final p = parts(once);
    expect(p.ct, pqEncapsulate(bob.seal.ek, m: draws[1]).$1);
    expect(p.nonce, draws[2]);
    // Left to the RNG, two seals of one payload share no part.
    final a = parts(await sealToBob('same')), b = parts(await sealToBob('same'));
    expect(a.eph, isNot(b.eph));
    expect(a.ct, isNot(b.ct));
    expect(a.nonce, isNot(b.nonce));
  });
}
