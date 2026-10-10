// The one Ed25519 rule a handle's signatures are held to, and the strong-key
// test its record's keys pass (PROTOCOL.md §21.4, `ed25519_strict.dart`).
//
// `package:cryptography`'s verifier compares the points of the verification
// equation by x alone, so a key's owner can make it accept a signature
// OpenSSL — the handle log — refuses, and under a small-order key anybody
// can; OpenSSL accepts the identity as R, which a key's owner can always
// make. Both are shown below, and the strict rule refusing both.
//
// Criteria, each a test below:
//   1. RFC 8032's test vectors verify, and a flipped bit anywhere — message,
//      R, S, key — fails;
//   2. honest signatures: 200 keys and messages signed by the library verify
//      under the strict rule, and the library's verify and the strict one
//      agree on each of them and on each with one bit flipped;
//   3. what only a lenient verifier takes is refused: R carrying the point of
//      order 2 (the library accepts it), R the identity (OpenSSL accepts it),
//      S + L, every small-order key with R the identity and S = 0, and a key
//      at or above p;
//   4. strong keys: every encoding of a point of small order, and every
//      encoding at or above p, is refused as an Ed25519 key, every small-order
//      u, top-bit and u ≥ p as an X25519 key, and 500 keys of each kind the
//      library makes are strong.

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

Uint8List _hex(String s) => Uint8List.fromList([
      for (var i = 0; i < s.length; i += 2)
        int.parse(s.substring(i, i + 2), radix: 16)
    ]);

Uint8List _flip(List<int> b, int bit) =>
    Uint8List.fromList(b)..[bit >> 3] ^= 1 << (bit & 7);

final _ed = Ed25519();

Future<bool> _library(List<int> pub, List<int> msg, List<int> sig) async {
  try {
    return await _ed.verify(msg,
        signature: Signature(sig,
            publicKey: SimplePublicKey(pub, type: KeyPairType.ed25519)));
  } catch (_) {
    return false;
  }
}

void main() {
  test('1. RFC 8032 §7.1: the test vectors verify, and a flipped bit anywhere fails', () {
    const vectors = [
      // public key, message, signature
      ['d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', '',
       'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'],
      ['3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', '72',
       '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'],
      ['fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025', 'af82',
       '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a'],
    ];
    for (final [pk, m, s] in vectors) {
      final pub = _hex(pk), msg = _hex(m), sig = _hex(s);
      expect(ed25519VerifyStrict(pub, msg, sig), isTrue, reason: pk);
      for (final bit in [0, 9, 255, 256, 300, 511]) {
        expect(ed25519VerifyStrict(pub, msg, _flip(sig, bit)), isFalse, reason: 'sig bit $bit');
      }
      for (final bit in [0, 100, 254]) {
        expect(ed25519VerifyStrict(_flip(pub, bit), msg, sig), isFalse, reason: 'key bit $bit');
      }
      expect(ed25519VerifyStrict(pub, [...msg, 0], sig), isFalse, reason: 'a byte more');
      if (msg.isNotEmpty) {
        expect(ed25519VerifyStrict(pub, _flip(msg, 0), sig), isFalse, reason: 'message bit');
      }
    }
  });

  test('2. honest signatures: the strict rule and the library agree on every one, and on every one flipped', () async {
    final sw = Stopwatch()..start();
    var checks = 0;
    for (var i = 0; i < 200; i++) {
      final kp = await _ed.newKeyPairFromSeed(
          List<int>.generate(32, (j) => (i * 31 + j * 7 + 1) & 0xff));
      final pub = (await kp.extractPublicKey()).bytes;
      final msg = List<int>.generate(i % 97, (j) => (i + j) & 0xff);
      final sig = (await _ed.sign(msg, keyPair: kp)).bytes;
      expect(ed25519VerifyStrict(pub, msg, sig), isTrue, reason: 'key $i');
      expect(await _library(pub, msg, sig), isTrue);
      final bad = _flip(sig, (i * 13) % 512);
      expect(ed25519VerifyStrict(pub, msg, bad), await _library(pub, msg, bad),
          reason: 'key $i, bit ${(i * 13) % 512} flipped');
      checks += 2;
    }
    // ignore: avoid_print
    print('strict Ed25519: $checks verifications in ${sw.elapsedMilliseconds} ms '
        '(${(sw.elapsedMicroseconds / checks / 1000).toStringAsFixed(2)} ms each, '
        'with the library\'s own beside each)');
  });

  test('3. what only a lenient verifier takes is refused', () async {
    // A key and message of a test's own (seed: SHA-256 of "strict verifier
    // test: owner"), and two signatures only that key's holder can make.
    final pub = _hex('4ea76a9d0f9a844305c05f87ef068e93a47587ac08a991a5e3a887fc25687ed5');
    final msg = _hex('61206d65737361676520746865206f776e6572207369676e7320776974682052206361727279696e672074686520706f696e74206f66206f726465722032');
    final honest = _hex('06143c47689e241e76dc5421fdbeb7340b509f00a93e12b0c5f51c0ab9e1240804586ef6f54f0596c19cad618cbea6ae3f87f3f29a4637d32487ae33a7d2cb05');
    expect(ed25519VerifyStrict(pub, msg, honest), isTrue);
    // R = rB + T2, S = −(r + k·a): R + [k]A = −[S]B + T2, the same x as [S]B.
    final mixedR = _hex('bc1a8f2e70c0490f1dcae63ce6991bf0c0a50e0e2a5dd8fd4be600d306567786fbdbfa3b60f11fe6acc637900a59b2cc206c6c1b4339f758bf86d676de0cec02');
    expect(await _library(pub, msg, mixedR), isTrue,
        reason: 'the library compares the points by x — the leniency this rule exists to not have');
    expect(ed25519VerifyStrict(pub, msg, mixedR), isFalse);
    // R = the identity, S = k·a: [S]B − [k]A is the identity, so OpenSSL,
    // comparing bytes, takes it; R is of small order.
    final identityR = _hex('0100000000000000000000000000000000000000000000000000000000000000d300f489e6daec7ec9fc401e8e0c6b048802f09225c3ef1fc261384990605402');
    expect(ed25519VerifyStrict(pub, msg, identityR), isFalse);
    // S + L.
    var s = BigInt.zero;
    for (var i = 63; i >= 32; i--) {
      s = (s << 8) | BigInt.from(honest[i]);
    }
    s += (BigInt.one << 252) + BigInt.parse('27742317777372353535851937790883648493');
    final malleated = Uint8List.fromList(honest);
    for (var i = 32; i < 64; i++) {
      malleated[i] = (s & BigInt.from(0xff)).toInt();
      s >>= 8;
    }
    expect(ed25519VerifyStrict(pub, msg, malleated), isFalse);
    // Every small-order key, with the signature that verifies under it for
    // any message in a cofactored or x-only check: R the identity, S = 0.
    final zeroSig = Uint8List(64)..[0] = 1;
    for (final k in [
      '0100000000000000000000000000000000000000000000000000000000000000',
      'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      '0000000000000000000000000000000000000000000000000000000000000000',
      '0000000000000000000000000000000000000000000000000000000000000080',
      'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
      'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa',
      '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
      '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85',
      'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    ]) {
      for (final m in [msg, Uint8List(0), _hex('00ff')]) {
        expect(ed25519VerifyStrict(_hex(k), m, zeroSig), isFalse, reason: k);
      }
    }
  });

  test('4. strong keys: every small-order or second encoding refused, every key the library makes strong', () async {
    String le(BigInt n) {
      final b = StringBuffer();
      for (var i = 0; i < 32; i++) {
        b.write((n & BigInt.from(0xff)).toInt().toRadixString(16).padLeft(2, '0'));
        n >>= 8;
      }
      return b.toString();
    }

    final p = (BigInt.one << 255) - BigInt.from(19);
    // Ed25519: the eight points of small order, both signs where there are
    // two, the sign bit on x = 0, and every y from p to 2^255 − 1.
    final smallY = [
      '0100000000000000000000000000000000000000000000000000000000000000',
      'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      '0000000000000000000000000000000000000000000000000000000000000000',
      '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
      'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
    ];
    for (final y in smallY) {
      expect(handleStrongEdKey(_hex(y)), isFalse, reason: y);
      expect(handleStrongEdKey(_flip(_hex(y), 255)), isFalse, reason: '$y, sign bit');
    }
    for (var y = p; y < (BigInt.one << 255); y += BigInt.one) {
      expect(handleStrongEdKey(_hex(le(y))), isFalse, reason: 'y = $y');
      expect(handleStrongEdKey(_flip(_hex(le(y)), 255)), isFalse);
    }
    expect(handleStrongEdKey(_hex(le(p - BigInt.two))), isTrue,
        reason: 'p − 2 is below p and of no small order (whether it is a point is the signature\'s to find)');
    // X25519.
    for (final u in [
      '0000000000000000000000000000000000000000000000000000000000000000',
      '0100000000000000000000000000000000000000000000000000000000000000',
      'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
      '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
      'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    ]) {
      expect(handleStrongXKey(_hex(u)), isFalse, reason: u);
    }
    final x = X25519();
    for (var i = 0; i < 500; i++) {
      final seed = List<int>.generate(32, (j) => (i * 17 + j * 3 + 5) & 0xff);
      final ed = await (await _ed.newKeyPairFromSeed(seed)).extractPublicKey();
      expect(handleStrongEdKey(ed.bytes), isTrue, reason: 'Ed25519 key $i');
      final xp = await (await x.newKeyPairFromSeed(seed)).extractPublicKey();
      expect(handleStrongXKey(xp.bytes), isTrue, reason: 'X25519 key $i');
      expect(handleStrongXKey(_flip(xp.bytes, 255)), isFalse, reason: 'X25519 key $i, top bit');
    }
  });
}
