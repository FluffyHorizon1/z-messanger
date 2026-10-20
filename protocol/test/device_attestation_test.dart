// A device's sealing key and the account's attestation of it, `pqdc` (44.1;
// ADR 0033 §1, PROTOCOL §18.11) — and the wire members that carry them,
// `pqseal`, `pqs` and `pqid.pqdc`. Built in the library only: no client sends
// any of it before 44.3.
//
// `pqdc` is what lets a contact show a device link as post-quantum (ADR 0033
// §2). The adversary it exists for is ADR 0033's: one who holds every
// classical private key — the account's Ed25519 seed among them, so it can
// forge a device's certificate, the code's signatures and the list — and no
// ML-DSA secret. Whatever it does, a `pqdc` must not verify for a device it
// chose.
//
// Exit criteria, each a test below:
//   1. a sealing key is FIPS 203 KeyGen_internal(d, z) of its 64-byte seed,
//      holds only the seed and `ek`, decapsulates from the seed what an
//      encapsulation to `ek` carries, hashes to `sealKeyHash(ek)`, and
//      refuses a seed of any other length;
//   2. `pqdc` is ML-DSA-65 by the account's key over the 143 bytes
//      utf8("z-device-pq-v1:") || acct || ded || dx || SHA-256(sealEk),
//      rebuilt here from its parts, under a context no other signing
//      context is a prefix of or begins with; it verifies, for the root
//      device (whose `ded` is the account key) and for a linked one;
//   3. verification refuses a swapped `acct`, `ded`, `dx` or sealing key, one
//      at a time, another device's `pqdc`, and another account's ML-DSA key;
//   4. verification refuses a wrong length of every input, and never throws;
//      the input refuses wrong widths, and signing refuses a sealing key FIPS
//      203 §7.2 refuses;
//   5. the adversary makes no `pqdc` that verifies for a device of its own:
//      not with an ML-DSA key of its own beside the account's genuine Ed25519
//      half, not by moving a genuine `pqdc` to its device, and not by
//      re-signing the genuine input with that key;
//   6. signing is hedged — two signatures over one input differ and both
//      verify — and deterministic only when asked, which is FIPS 204's
//      `rnd = 0` signature, for the vectors;
//   7. the wire members: a `pqid` carrying `pqdc` is the `pqid` without it
//      plus that member, byte for byte, reads exactly as today's reader reads
//      a `pqid` — kind, `alg`, `pk`, `ack` — and gives its `pqdc` back; a
//      `pqseal` gives its key back, and a malformed one gives none and still
//      parses; `pqs:1` reads back, and no message without it says it;
//   8. a `pqdc` signed from the sealing key's hash, as pairing v3's root signs
//      it holding only the opened `sk`, is over the same 143 bytes as one
//      signed from the key, is the same signature when deterministic, and
//      verifies with the key; the hash form refuses a hash of another
//      length, and the key it cannot check is checked where it is held — a
//      `pqdc` over the hash of a key FIPS 203 §7.2 refuses does not verify
//      with that key, and a `pqseal` carrying it gives none.
import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' show Sha256;
import 'package:test/test.dart';
import 'package:z_protocol/src/util.dart' show concatBytes;
import 'package:z_protocol/z_protocol.dart';

Uint8List utf8b(String s) => Uint8List.fromList(utf8.encode(s));

Future<Uint8List> sha256(List<int> b) async =>
    Uint8List.fromList((await Sha256().hash(b)).bytes);

/// An account: its root identity and hybrid key; and a linked device of it.
class Account {
  final ZIdentity root;
  final HybridKeyPair key;
  final SealingKey rootSeal;
  final ZIdentity laptop;
  final SealingKey laptopSeal;
  Account(this.root, this.key, this.rootSeal, this.laptop, this.laptopSeal);

  static Future<Account> make() async {
    final root = await ZIdentity.generate();
    return Account(
      root,
      await HybridKeyPair.fromSeeds(edSeed: root.edSeed, mlSeed: randomBytes(32)),
      SealingKey.generate(),
      await ZIdentity.generate(),
      SealingKey.generate(),
    );
  }

  Uint8List get acct => key.publicKey.edPub;
  Uint8List get mlPub => key.publicKey.mlPub;

  Future<Uint8List> attest(ZIdentity device, SealingKey seal,
          {bool deterministic = false}) =>
      signDeviceAttestation(
          accountKey: key,
          deviceEdPub: device.edPub,
          deviceXPub: device.xPub,
          sealEk: seal.ek,
          deterministic: deterministic);
}

bool valid(
        {required List<int> mlPub,
        required List<int> acct,
        required List<int> ded,
        required List<int> dx,
        required List<int> ek,
        required List<int> pqdc}) =>
    deviceAttestationValid(
        accountMlPub: mlPub,
        accountEdPub: acct,
        deviceEdPub: ded,
        deviceXPub: dx,
        sealEk: ek,
        pqdc: pqdc);

void main() {
  late Account a, b;
  setUpAll(() async {
    a = await Account.make();
    b = await Account.make();
  });

  test('1. a sealing key is its seed\'s ML-KEM-768 pair, and holds only the '
      'seed and ek', () async {
    final seed = randomBytes(64);
    final key = SealingKey.fromSeed(seed);
    final (ek, _) = pqKeyPairFromSeed(seed);
    expect(key.ek, ek, reason: 'KeyGen_internal(d, z), d || z = the seed');
    expect(key.ek.length, 1184);
    expect(key.seed, seed);
    expect(SealingKey.fromSeed(seed).ek, key.ek, reason: 'deterministic');
    expect(key.hash, sealKeyHash(key.ek));
    expect(key.hash, await sha256(key.ek));
    for (var i = 0; i < 3; i++) {
      final (ct, k) = pqEncapsulate(key.ek);
      expect(key.decapsulate(ct), k, reason: 'from the seed alone');
      expect(pqDecapsulate(seed, ct), k);
    }
    // A ciphertext for another key decapsulates, by implicit rejection, to
    // a secret that is not the one encapsulated — and does not throw.
    final (ctOther, kOther) = pqEncapsulate(SealingKey.generate().ek);
    expect(key.decapsulate(ctOther), isNot(kOther));
    for (final n in [0, 32, 63, 65]) {
      expect(() => SealingKey.fromSeed(Uint8List(n)), throwsArgumentError,
          reason: '$n bytes');
    }
    expect(SealingKey.generate().ek, isNot(SealingKey.generate().ek));
  });

  test('2. pqdc is ML-DSA-65 by the account over the 143-byte input, for '
      'the root device and a linked one', () async {
    for (final (name, device, seal) in [
      ('root', a.root, a.rootSeal),
      ('linked', a.laptop, a.laptopSeal),
    ]) {
      final input = concatBytes([
        utf8b('z-device-pq-v1:'),
        a.acct,
        device.edPub,
        device.xPub,
        await sha256(seal.ek),
      ]);
      expect(input.length, 143, reason: name);
      expect(
          deviceAttestationInput(
              accountEdPub: a.acct,
              deviceEdPub: device.edPub,
              deviceXPub: device.xPub,
              sealEk: seal.ek),
          input,
          reason: name);
      final pqdc = await a.attest(device, seal);
      expect(pqdc.length, 3309, reason: name);
      expect(pqDsaVerify(a.mlPub, input, pqdc), isTrue,
          reason: '$name: ML-DSA-65 over exactly that input');
      expect(
          valid(
              mlPub: a.mlPub,
              acct: a.acct,
              ded: device.edPub,
              dx: device.xPub,
              ek: seal.ek,
              pqdc: pqdc),
          isTrue,
          reason: name);
    }
    expect(a.root.edPub, a.acct, reason: "the root device's ded is the account key");
    // The context: named as the others are, and apart from each of them.
    expect(devicePqContext, 'z-device-pq-v1:');
    for (final other in [
      deviceCertContext,
      devicePopContext,
      pqCommitContext,
      pqCommitSigContext,
      introKeyContext,
      'z-devlist-v1:',
      'z-devlist-v2:',
      'z-devlist-v3:',
    ]) {
      expect(other.startsWith(devicePqContext), isFalse, reason: other);
      expect(devicePqContext.startsWith(other), isFalse, reason: other);
    }
  });

  test('3. a swapped acct, ded, dx or sealing key, another device\'s pqdc and '
      'another account\'s key are refused', () async {
    final pqdc = await a.attest(a.laptop, a.laptopSeal);
    final rootPqdc = await a.attest(a.root, a.rootSeal);
    final ok = (
      mlPub: a.mlPub,
      acct: a.acct,
      ded: a.laptop.edPub,
      dx: a.laptop.xPub,
      ek: a.laptopSeal.ek,
    );
    expect(
        valid(
            mlPub: ok.mlPub,
            acct: ok.acct,
            ded: ok.ded,
            dx: ok.dx,
            ek: ok.ek,
            pqdc: pqdc),
        isTrue);
    final cases = <String, bool>{
      'acct swapped': valid(
          mlPub: ok.mlPub, acct: b.acct, ded: ok.ded, dx: ok.dx, ek: ok.ek, pqdc: pqdc),
      'ded swapped': valid(
          mlPub: ok.mlPub, acct: ok.acct, ded: a.root.edPub, dx: ok.dx, ek: ok.ek, pqdc: pqdc),
      'dx swapped': valid(
          mlPub: ok.mlPub, acct: ok.acct, ded: ok.ded, dx: a.root.xPub, ek: ok.ek, pqdc: pqdc),
      'sealing key swapped': valid(
          mlPub: ok.mlPub, acct: ok.acct, ded: ok.ded, dx: ok.dx, ek: a.rootSeal.ek, pqdc: pqdc),
      "the root device's pqdc for the laptop": valid(
          mlPub: ok.mlPub, acct: ok.acct, ded: ok.ded, dx: ok.dx, ek: ok.ek, pqdc: rootPqdc),
      "another account's ML-DSA key": valid(
          mlPub: b.mlPub, acct: ok.acct, ded: ok.ded, dx: ok.dx, ek: ok.ek, pqdc: pqdc),
      'ded and dx exchanged': valid(
          mlPub: ok.mlPub, acct: ok.acct, ded: ok.dx, dx: ok.ded, ek: ok.ek, pqdc: pqdc),
    };
    for (final e in cases.entries) {
      expect(e.value, isFalse, reason: e.key);
    }
  });

  test('4. a wrong length is refused without a throw, and signing refuses a '
      'key FIPS 203 refuses', () async {
    final pqdc = await a.attest(a.laptop, a.laptopSeal);
    Uint8List cut(Uint8List x, int d) => d < 0
        ? Uint8List.fromList(x.sublist(0, x.length + d))
        : Uint8List.fromList([...x, ...List.filled(d, 0)]);
    for (final d in [-1, 1]) {
      final cases = <String, bool Function()>{
        'mlPub': () => valid(mlPub: cut(a.mlPub, d), acct: a.acct,
            ded: a.laptop.edPub, dx: a.laptop.xPub, ek: a.laptopSeal.ek, pqdc: pqdc),
        'acct': () => valid(mlPub: a.mlPub, acct: cut(a.acct, d),
            ded: a.laptop.edPub, dx: a.laptop.xPub, ek: a.laptopSeal.ek, pqdc: pqdc),
        'ded': () => valid(mlPub: a.mlPub, acct: a.acct,
            ded: cut(a.laptop.edPub, d), dx: a.laptop.xPub, ek: a.laptopSeal.ek, pqdc: pqdc),
        'dx': () => valid(mlPub: a.mlPub, acct: a.acct, ded: a.laptop.edPub,
            dx: cut(a.laptop.xPub, d), ek: a.laptopSeal.ek, pqdc: pqdc),
        'sealEk': () => valid(mlPub: a.mlPub, acct: a.acct, ded: a.laptop.edPub,
            dx: a.laptop.xPub, ek: cut(a.laptopSeal.ek, d), pqdc: pqdc),
        'pqdc': () => valid(mlPub: a.mlPub, acct: a.acct, ded: a.laptop.edPub,
            dx: a.laptop.xPub, ek: a.laptopSeal.ek, pqdc: cut(pqdc, d)),
      };
      for (final e in cases.entries) {
        expect(e.value(), isFalse, reason: '${e.key} ${d < 0 ? 'short' : 'long'}');
      }
    }
    expect(valid(mlPub: [], acct: [], ded: [], dx: [], ek: [], pqdc: []), isFalse);
    // The input itself has no meaning at another width.
    expect(
        () => deviceAttestationInput(
            accountEdPub: a.acct,
            deviceEdPub: a.laptop.edPub,
            deviceXPub: Uint8List(31),
            sealEk: a.laptopSeal.ek),
        throwsArgumentError);
    expect(
        () => deviceAttestationInput(
            accountEdPub: a.acct,
            deviceEdPub: a.laptop.edPub,
            deviceXPub: a.laptop.xPub,
            sealEk: Uint8List(1183)),
        throwsArgumentError);
    // A root never vouches for a key nobody can encapsulate to.
    final ek = a.laptopSeal.ek;
    final atQ = Uint8List.fromList(ek)
      ..[0] = 0x01
      ..[1] = (ek[1] & 0xf0) | 0x0d; // the first coefficient of t̂ at q
    expect(mlKemEncapsulationKeyValid(atQ), isFalse);
    await expectLater(
        signDeviceAttestation(
            accountKey: a.key,
            deviceEdPub: a.laptop.edPub,
            deviceXPub: a.laptop.xPub,
            sealEk: atQ),
        throwsArgumentError);
  });

  test('5. holding every classical private key and no ML-DSA secret, the '
      'adversary attests no device of its own', () async {
    // Its device: keys it made, a sealing key it holds.
    final mine = await ZIdentity.generate();
    final mySeal = SealingKey.generate();
    // a) An account key whose Ed25519 half is the genuine one — it holds the
    //    seed — and whose ML-DSA half is its own.
    final forger =
        await HybridKeyPair.fromSeeds(edSeed: a.root.edSeed, mlSeed: randomBytes(32));
    expect(forger.publicKey.edPub, a.acct);
    final forged = await signDeviceAttestation(
        accountKey: forger,
        deviceEdPub: mine.edPub,
        deviceXPub: mine.xPub,
        sealEk: mySeal.ek);
    expect(
        valid(mlPub: forger.publicKey.mlPub, acct: a.acct, ded: mine.edPub,
            dx: mine.xPub, ek: mySeal.ek, pqdc: forged),
        isTrue,
        reason: 'the premise: it verifies under the forger\'s own key');
    expect(
        valid(mlPub: a.mlPub, acct: a.acct, ded: mine.edPub, dx: mine.xPub,
            ek: mySeal.ek, pqdc: forged),
        isFalse,
        reason: "and not under the account's");
    // b) A genuine pqdc moved to its device, whole or field by field: its
    //    keys, or only its sealing key beside the genuine device's keys.
    final genuine = await a.attest(a.laptop, a.laptopSeal);
    for (final (why, ded, dx, ek) in [
      ('its device', mine.edPub, mine.xPub, mySeal.ek),
      ('its sealing key, the genuine keys', a.laptop.edPub, a.laptop.xPub,
          mySeal.ek),
      ('its keys, the genuine sealing key', mine.edPub, mine.xPub,
          a.laptopSeal.ek),
    ]) {
      expect(
          valid(mlPub: a.mlPub, acct: a.acct, ded: ded, dx: dx, ek: ek,
              pqdc: genuine),
          isFalse,
          reason: why);
    }
    // c) The genuine input re-signed under its own key: still not the
    //    account's signature.
    final input = deviceAttestationInput(
        accountEdPub: a.acct,
        deviceEdPub: a.laptop.edPub,
        deviceXPub: a.laptop.xPub,
        sealEk: a.laptopSeal.ek);
    final resigned = (await forger.sign(input)).ml;
    expect(
        valid(mlPub: a.mlPub, acct: a.acct, ded: a.laptop.edPub,
            dx: a.laptop.xPub, ek: a.laptopSeal.ek, pqdc: resigned),
        isFalse);
  });

  test('6. signing is hedged, and deterministic only when asked', () async {
    final x = await a.attest(a.laptop, a.laptopSeal);
    final y = await a.attest(a.laptop, a.laptopSeal);
    expect(x, isNot(y), reason: 'hedged: a fresh rnd each time (FIPS 204)');
    for (final s in [x, y]) {
      expect(
          valid(mlPub: a.mlPub, acct: a.acct, ded: a.laptop.edPub,
              dx: a.laptop.xPub, ek: a.laptopSeal.ek, pqdc: s),
          isTrue);
    }
    final d1 = await a.attest(a.laptop, a.laptopSeal, deterministic: true);
    final d2 = await a.attest(a.laptop, a.laptopSeal, deterministic: true);
    expect(d1, d2);
    final (_, mlSk) = pqDsaKeyPairSeeded(a.key.mlSeed);
    expect(
        d1,
        pqDsaSignDeterministic(
            mlSk,
            deviceAttestationInput(
                accountEdPub: a.acct,
                deviceEdPub: a.laptop.edPub,
                deviceXPub: a.laptop.xPub,
                sealEk: a.laptopSeal.ek)),
        reason: "FIPS 204's rnd = 0 signature");
  });

  test('7. pqid carrying pqdc, pqseal and pqs: built, read back, and read by '
      "today's reader as before", () async {
    final pqdc = await a.attest(a.laptop, a.laptopSeal);
    final mid = newMessageId();
    const ts = 1760000000000;
    final bare = InnerMessage.pqIdentity(mid, ts, a.mlPub);
    final withIt = InnerMessage.pqIdentity(mid, ts, a.mlPub, pqdc: pqdc);
    final bareJson = utf8.decode(bare.toBytes());
    final json = utf8.decode(withIt.toBytes());
    expect(json, '${bareJson.substring(0, bareJson.length - 1)},'
        '"pqdc":"${b64(pqdc)}"}',
        reason: 'the pqid of today, and one member more');
    expect(
        utf8.decode(
            InnerMessage.pqIdentity(mid, ts, a.mlPub, ack: true, pqdc: pqdc)
                .toBytes()),
        '${bareJson.substring(0, bareJson.length - 1)},"ack":true,'
        '"pqdc":"${b64(pqdc)}"}');
    // What the app reads of a pqid (`_onPqIdentity`: alg, pk, ack) through
    // the parse it runs (`InnerMessage.fromBytes`), unchanged by the member.
    final read = InnerMessage.fromBytes(withIt.toBytes());
    final readBare = InnerMessage.fromBytes(bare.toBytes());
    expect(read.kind, 'pqid');
    expect(read.mid, readBare.mid);
    for (final k in ['alg', 'pk', 'ack']) {
      expect(read.data[k], readBare.data[k], reason: k);
    }
    expect(read.pqidAttestation, pqdc);
    expect(readBare.pqidAttestation, isNull);
    // A pqdc of the wrong length is no pqdc, and the pqid still reads.
    final short = InnerMessage(kind: 'pqid', mid: mid, ts: ts, data: {
      ...withIt.data,
      'pqdc': b64(pqdc.sublist(0, 3308)),
    });
    expect(InnerMessage.fromBytes(short.toBytes()).pqidAttestation, isNull);
    expect(InnerMessage.fromBytes(short.toBytes()).data['pk'], b64(a.mlPub));

    final seal = InnerMessage.pqSeal(newMessageId(), ts, a.laptopSeal.ek);
    final sealRead = InnerMessage.fromBytes(seal.toBytes());
    expect(sealRead.kind, 'pqseal');
    expect(sealRead.data['alg'], 'ML-KEM-768');
    expect(sealRead.pqSealKey, a.laptopSeal.ek);
    expect(InnerMessage.looksLikeKind(seal.toBytes(), 'pqseal'), isTrue);
    final ek = a.laptopSeal.ek;
    final atQ = Uint8List.fromList(ek)
      ..[0] = 0x01
      ..[1] = (ek[1] & 0xf0) | 0x0d;
    for (final (why, members) in [
      ('another algorithm', {'alg': 'ML-KEM-512', 'ek': b64(ek)}),
      ('no alg', {'ek': b64(ek)}),
      ('a byte short', {'alg': 'ML-KEM-768', 'ek': b64(ek.sublist(0, 1183))}),
      ('a coefficient at q', {'alg': 'ML-KEM-768', 'ek': b64(atQ)}),
      ('not a string', {'alg': 'ML-KEM-768', 'ek': 7}),
      ('not base64', {'alg': 'ML-KEM-768', 'ek': '!!!'}),
    ]) {
      final m = InnerMessage(kind: 'pqseal', mid: mid, ts: ts, data: members);
      final r = InnerMessage.fromBytes(m.toBytes()); // parses: no throw
      expect(r.pqSealKey, isNull, reason: why);
    }
    // A key under any other kind is not a pqseal's.
    expect(
        InnerMessage.fromBytes(InnerMessage.pqOffer(mid, ts, ek).toBytes())
            .pqSealKey,
        isNull,
        reason: 'a pqek offer carries a key of the same shape');

    final text = InnerMessage.text(newMessageId(), ts, 'ok');
    expect(InnerMessage.fromBytes(text.toBytes()).saysHoldsSealKey, isFalse);
    text.stampHoldsSealKey();
    expect(utf8.decode(text.toBytes()), endsWith(',"pqs":1}'));
    final held = InnerMessage.fromBytes(text.toBytes());
    expect(held.saysHoldsSealKey, isTrue);
    expect(held.data['body'], 'ok', reason: 'the message is unchanged');
  });

  test("8. pqdc signed from the sealing key's hash, as pairing v3's root "
      'signs it, is the pqdc over the key', () async {
    for (final (name, device, seal) in [
      ('root', a.root, a.rootSeal),
      ('linked', a.laptop, a.laptopSeal),
    ]) {
      // What the root holds in pairing v3: the new device's two keys, and
      // the hash its opening carries.
      final sk = sealKeyHash(seal.ek);
      final fromHash = deviceAttestationInputFromHash(
          accountEdPub: a.acct,
          deviceEdPub: device.edPub,
          deviceXPub: device.xPub,
          sk: sk);
      expect(fromHash.length, 143, reason: name);
      expect(
          fromHash,
          deviceAttestationInput(
              accountEdPub: a.acct,
              deviceEdPub: device.edPub,
              deviceXPub: device.xPub,
              sealEk: seal.ek),
          reason: '$name: the same input as from the key');
      final hedged = await signDeviceAttestationFromHash(
          accountKey: a.key,
          deviceEdPub: device.edPub,
          deviceXPub: device.xPub,
          sk: sk);
      expect(
          valid(
              mlPub: a.mlPub,
              acct: a.acct,
              ded: device.edPub,
              dx: device.xPub,
              ek: seal.ek,
              pqdc: hedged),
          isTrue,
          reason: '$name: it verifies with the key, once its pqseal brings it');
      expect(
          await signDeviceAttestationFromHash(
              accountKey: a.key,
              deviceEdPub: device.edPub,
              deviceXPub: device.xPub,
              sk: sk,
              deterministic: true),
          await a.attest(device, seal, deterministic: true),
          reason: '$name: the same signature as from the key');
    }
    // Over another key's hash, it is no pqdc for this one.
    final otherKeys = await signDeviceAttestationFromHash(
        accountKey: a.key,
        deviceEdPub: a.laptop.edPub,
        deviceXPub: a.laptop.xPub,
        sk: sealKeyHash(a.rootSeal.ek));
    expect(
        valid(
            mlPub: a.mlPub,
            acct: a.acct,
            ded: a.laptop.edPub,
            dx: a.laptop.xPub,
            ek: a.laptopSeal.ek,
            pqdc: otherKeys),
        isFalse);
    // A hash of another length is no hash.
    for (final n in [0, 31, 33, 1184]) {
      expect(
          () => deviceAttestationInputFromHash(
              accountEdPub: a.acct,
              deviceEdPub: a.laptop.edPub,
              deviceXPub: a.laptop.xPub,
              sk: Uint8List(n)),
          throwsArgumentError,
          reason: '$n bytes');
      await expectLater(
          signDeviceAttestationFromHash(
              accountKey: a.key,
              deviceEdPub: a.laptop.edPub,
              deviceXPub: a.laptop.xPub,
              sk: Uint8List(n)),
          throwsArgumentError,
          reason: '$n bytes');
    }
    // A hash says nothing of the key it is of, so the key is checked where it
    // is held: signed over the hash of a key FIPS 203 §7.2 refuses, the
    // signature is good over its input, and still no pqdc for that key, and a
    // pqseal carrying the key gives none.
    final ek = a.laptopSeal.ek;
    final atQ = Uint8List.fromList(ek)
      ..[0] = 0x01
      ..[1] = (ek[1] & 0xf0) | 0x0d; // the first coefficient of t̂ at q
    expect(mlKemEncapsulationKeyValid(atQ), isFalse);
    final overBad = await signDeviceAttestationFromHash(
        accountKey: a.key,
        deviceEdPub: a.laptop.edPub,
        deviceXPub: a.laptop.xPub,
        sk: sealKeyHash(atQ));
    expect(
        pqDsaVerify(
            a.mlPub,
            deviceAttestationInputFromHash(
                accountEdPub: a.acct,
                deviceEdPub: a.laptop.edPub,
                deviceXPub: a.laptop.xPub,
                sk: sealKeyHash(atQ)),
            overBad),
        isTrue,
        reason: 'the premise: the signature itself is good');
    expect(
        valid(
            mlPub: a.mlPub,
            acct: a.acct,
            ded: a.laptop.edPub,
            dx: a.laptop.xPub,
            ek: atQ,
            pqdc: overBad),
        isFalse,
        reason: 'the key fails FIPS 203 §7.2, so no pqdc stands for it');
    expect(
        InnerMessage.fromBytes(
                InnerMessage.pqSeal(newMessageId(), 1760000000000, atQ)
                    .toBytes())
            .pqSealKey,
        isNull,
        reason: 'and a pqseal carrying it brings no key');
  });
}
