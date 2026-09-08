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
      expect(s, startsWith('zc1.'),
          reason: 'the emitted code is a v1 code carrying one extra member, '
              'so every build already in the field can still read it');
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
      final tampered = 'zc1.${b64url(utf8.encode(jsonEncode(j)))}';
      final parsed = await ContactBundleV3.decode(tampered);
      expect(await parsed.acceptsPqKey(pq.publicKey), isFalse);
    });

    test('a tampered classical half is rejected outright', () async {
      final j = jsonDecode(utf8.decode(unb64url(code.encode().substring(4))))
          as Map<String, Object?>;
      j['x'] = b64((await ZIdentity.generate()).xPub);
      expect(
          () => ContactBundleV3.decode(
              'zc1.${b64url(utf8.encode(jsonEncode(j)))}'),
          throwsFormatException);
    });

    test('a v3 code with no commitment is refused, not downgraded', () async {
      // The downgrade: strip the post-quantum promise and hope the reader
      // treats it as an old code. It says v3, so it must carry one.
      final j = jsonDecode(utf8.decode(unb64url(code.encode().substring(4))))
          as Map<String, Object?>;
      j['v'] = 3;
      j.remove('pqc');
      expect(
          () => ContactBundleV3.decode(
              'zc3.${b64url(utf8.encode(jsonEncode(j)))}'),
          throwsFormatException);
    });

    test('a client already in the field can still read the emitted code',
        () async {
      // The whole reason the commitment rides in a v1 code rather than behind
      // a zc3. prefix. PROTOCOL §14: a new optional member is compatible
      // evolution; a new prefix is a flag day, and every build in the field
      // rejects zc3. outright.
      final emitted = code.encode();
      final old = await ContactBundle.decode(emitted); // the v1 decoder
      expect(old.edPub, me.edPub);
      expect(old.xPub, me.xPub);
      expect(old.displayName, 'Finn');
      expect(await old.verify(), isTrue);

      // …while the strict form is not readable by that decoder at all.
      expect(() => ContactBundle.decode(code.encodeStrict()),
          throwsFormatException);
      // Both forms carry the same commitment to a v3 client.
      expect((await ContactBundleV3.decode(code.encodeStrict())).pqCommit,
          (await ContactBundleV3.decode(emitted)).pqCommit);
    });

    test('a hybrid key that is not this identity cannot be committed to',
        () async {
      final stranger = await HybridKeyPair.generate();
      expect(() => ContactBundleV3.forIdentity(me, stranger.publicKey),
          throwsFormatException);
    });
  });

  group('an account-anchored code (18.7)', () {
    // A contact code has always described the DEVICE showing it. That was
    // invisible while every account had one device, and wrong the moment one
    // did not: scanning someone's laptop added the laptop, so their device
    // list failed the "signed by this contact's account key" check and their
    // safety number was computed against a per-device key. The fix is for the
    // code to name the account and carry the account's certificate for the
    // device it describes.
    late ZIdentity root; // the account root
    late ZIdentity laptop; // a linked device
    late HybridKeyPair accountPq;
    late DeviceCertificate laptopCert;
    late AccountIdentity account;

    setUpAll(() async {
      final rootSeed = randomBytes(32);
      root =
          await ZIdentity.fromSeeds(edSeed: rootSeed, xSeed: randomBytes(32));
      accountPq = await HybridKeyPair.fromSeeds(
          edSeed: rootSeed, mlSeed: randomBytes(32));
      account = await AccountIdentity.fromV1(root);
      laptop = await ZIdentity.generate();
      laptopCert = await account.signDeviceCert(
          deviceEdPub: laptop.edPub,
          deviceXPub: laptop.xPub,
          deviceId: 'laptop');
    });

    Future<ContactBundleV3> laptopCode() => ContactBundleV3.forIdentity(
          laptop,
          accountPq.publicKey,
          displayName: 'Finn',
          accountEdPub: root.edPub,
          cert: laptopCert,
        );

    test('scanning a linked device yields the person, not the device',
        () async {
      final scanned = await scanContactCode((await laptopCode()).encode());
      // The session still opens with the device that is actually reachable…
      expect(scanned.classical.edPub, laptop.edPub);
      expect(scanned.classical.xPub, laptop.xPub);
      // …but the identity a human confirms is the account.
      expect(scanned.accountEdPub, root.edPub);
      expect(scanned.deviceCert!.deviceId, 'laptop');
      expect(scanned.assurance, IdentityAssurance.pendingPostQuantum);
    });

    test('so the safety number is the same whichever device was scanned',
        () async {
      // The property the whole change exists for. Two people who verified on
      // one pairing must not read different numbers because one of them
      // happened to scan a laptop.
      final other = await ZIdentity.generate();
      final viaLaptop = await scanContactCode((await laptopCode()).encode());
      final viaRoot = await scanContactCode(
          (await ContactBundleV3.forIdentity(root, accountPq.publicKey))
              .encode());
      expect(await safetyNumber(other.edPub, viaLaptop.accountEdPub),
          await safetyNumber(other.edPub, viaRoot.accountEdPub));
      // And it is NOT the number the laptop's own key would have produced,
      // which is what an unfixed client shows.
      expect(await safetyNumber(other.edPub, viaLaptop.accountEdPub),
          isNot(await safetyNumber(other.edPub, laptop.edPub)));
    });

    test('the post-quantum commitment belongs to the account', () async {
      // Before 18.7 a linked device could not carry a commitment at all: the
      // commitment binds the ACCOUNT's key and the code named the DEVICE's,
      // so the two could not be glued together honestly. Now they can.
      final scanned = await scanContactCode((await laptopCode()).encode());
      expect(await scanned.v3!.acceptsPqKey(accountPq.publicKey), isTrue);
    });

    test('a claimed account with no certificate is refused', () async {
      final good = (await laptopCode()).encode();
      final j = jsonDecode(utf8.decode(unb64url(good.substring(4))))
          as Map<String, Object?>;
      j.remove('cert');
      expect(() => scanContactCode('zc1.${b64url(utf8.encode(jsonEncode(j)))}'),
          throwsFormatException,
          reason: 'a claim without proof is an assertion');
    });

    test("someone else's certificate does not make you them", () async {
      // The attack this format has to survive: an attacker holds a genuine
      // certificate of the account (they are public — they travel in device
      // lists) and presents it beside their OWN keys.
      final attacker = await ZIdentity.generate();
      final good = (await laptopCode()).encode();
      final j = jsonDecode(utf8.decode(unb64url(good.substring(4))))
          as Map<String, Object?>;
      j['ed'] = b64(attacker.edPub);
      j['x'] = b64(attacker.xPub);
      j['sig'] = b64(await attacker.bindingSignature()); // their own, valid
      expect(() => scanContactCode('zc1.${b64url(utf8.encode(jsonEncode(j)))}'),
          throwsFormatException,
          reason: 'the certificate must be FOR the device in the code');
    });

    test('a certificate signed by a different account is refused', () async {
      final stranger = await AccountIdentity.fromV1(await ZIdentity.generate());
      final forged = await stranger.signDeviceCert(
          deviceEdPub: laptop.edPub,
          deviceXPub: laptop.xPub,
          deviceId: 'laptop');
      // Built by hand: `forIdentity` refuses to assemble this at all.
      expect(
          () => ContactBundleV3.forIdentity(laptop, accountPq.publicKey,
              accountEdPub: root.edPub, cert: forged),
          throwsFormatException);
      final j = jsonDecode(
              utf8.decode(unb64url((await laptopCode()).encode().substring(4))))
          as Map<String, Object?>;
      j['cert'] = forged.toJson();
      expect(() => scanContactCode('zc1.${b64url(utf8.encode(jsonEncode(j)))}'),
          throwsFormatException);
    });

    test('a legacy record cannot stand in for an account endorsement',
        () async {
      // The legacy rule is "the device key IS the account key" — exactly what
      // an account-anchored code is not. Allowing one here would let a v1
      // binding signature pass as an account's endorsement of a device it
      // never signed for.
      final j = jsonDecode(
              utf8.decode(unb64url((await laptopCode()).encode().substring(4))))
          as Map<String, Object?>;
      j['cert'] = DeviceCertificate(
        deviceEdPub: laptop.edPub,
        deviceXPub: laptop.xPub,
        deviceId: 'legacy-v1',
        sig: await laptop.bindingSignature(),
        legacy: true,
      ).toJson();
      expect(() => scanContactCode('zc1.${b64url(utf8.encode(jsonEncode(j)))}'),
          throwsFormatException);
    });

    test('stripping the anchor cannot silently reduce it to a device',
        () async {
      // `acct` without `pqc` must not fall through to the v1 decoder, which
      // ignores members it does not know — that would turn the person back
      // into the laptop without anything failing.
      final j = jsonDecode(
              utf8.decode(unb64url((await laptopCode()).encode().substring(4))))
          as Map<String, Object?>;
      j.remove('pqc');
      expect(() => scanContactCode('zc1.${b64url(utf8.encode(jsonEncode(j)))}'),
          throwsFormatException);
    });

    test('a client already in the field still reads it as the device',
        () async {
      // The compatibility bargain. An old client cannot learn the account —
      // it has no idea `acct` exists — so it does what it does today and adds
      // the device. That is not a regression; it is exactly the behaviour
      // being replaced, and nothing about it breaks.
      final old = await ContactBundle.decode((await laptopCode()).encode());
      expect(old.edPub, laptop.edPub);
      expect(await old.verify(), isTrue);
    });

    test('a root device does not pay for what it does not need', () async {
      // Account and device are the same identity there, so saying so twice
      // only makes the QR bigger.
      final code = await ContactBundleV3.forIdentity(root, accountPq.publicKey);
      expect(code.declaredAccountEdPub, isNull);
      expect(code.accountEdPub, root.edPub);
      expect(code.encode().length, lessThan(400));
      // The linked device's code is bigger, and still comfortably scannable.
      expect((await laptopCode()).encode().length, lessThan(800));
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

  _hybridCertsAndSafetyNumber();

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

void _hybridCertsAndSafetyNumber() {
  group('hybrid device certificates', () {
    late HybridKeyPair account;
    late ZIdentity device;
    late HybridDeviceCertificate cert;

    setUpAll(() async {
      account = await HybridKeyPair.generate();
      device = await ZIdentity.generate();
      cert = await HybridDeviceCertificate.sign(
        accountKey: account,
        deviceEdPub: device.edPub,
        deviceXPub: device.xPub,
        deviceId: 'laptop',
      );
    });

    test('a genuine certificate verifies under both halves', () async {
      expect(await cert.verify(account.publicKey), isTrue);
      // …and its classical half is a plain v2 certificate, so a client that
      // has never heard of v3 reads it unchanged.
      expect(await cert.classical.verify(account.publicKey.edPub), isTrue);
      expect(cert.classical.deviceId, 'laptop');
    });

    test('a cert with only a valid classical half is rejected', () async {
      // The phase's exit criterion. This is what an adversary who has broken
      // Ed25519 produces: a real classical signature over the device they
      // want to insert, and a post-quantum signature they cannot forge — here
      // stood in for by a valid signature over a DIFFERENT device.
      final other = await HybridDeviceCertificate.sign(
        accountKey: account,
        deviceEdPub: (await ZIdentity.generate()).edPub,
        deviceXPub: device.xPub,
        deviceId: 'rogue',
      );
      final forged = HybridDeviceCertificate(
          classical: cert.classical, mlSig: other.mlSig);
      expect(await forged.verify(account.publicKey), isFalse);
      // The classical half alone still passes, which is exactly why the
      // hybrid check has to be the one that gates anything.
      expect(await forged.classical.verify(account.publicKey.edPub), isTrue);
    });

    test('a cert with only a valid post-quantum half is rejected', () async {
      final stranger = await HybridKeyPair.generate();
      final wrongEd = await HybridDeviceCertificate.sign(
        accountKey: stranger,
        deviceEdPub: device.edPub,
        deviceXPub: device.xPub,
        deviceId: 'laptop',
      );
      final forged = HybridDeviceCertificate(
          classical: wrongEd.classical, mlSig: cert.mlSig);
      expect(await forged.verify(account.publicKey), isFalse);
    });

    test('another account cannot vouch for this device', () async {
      final stranger = await HybridKeyPair.generate();
      expect(await cert.verify(stranger.publicKey), isFalse);
      // Nor can half of one: the right classical account key paired with
      // somebody else's post-quantum key.
      final mixed = HybridPublicKey(
          edPub: account.publicKey.edPub, mlPub: stranger.publicKey.mlPub);
      expect(await cert.verify(mixed), isFalse);
    });

    test('a stripped certificate does not parse', () {
      final j = cert.toJson()..remove('mlsig');
      expect(() => HybridDeviceCertificate.fromJson(j),
          throwsA(isA<HybridFormatException>()));
      expect(
          () => HybridDeviceCertificate(
              classical: cert.classical, mlSig: Uint8List(100)),
          throwsA(isA<HybridFormatException>()));
    });

    test('a legacy v1 record cannot be dressed as hybrid', () async {
      // A legacy record is a v1 identity read as a device: its "signature" is
      // the v1 binding signature and there is no separate account key. Letting
      // one carry a post-quantum half would present a v1 identity as
      // post-quantum verified.
      final v1 = await ZIdentity.generate();
      final legacy = DeviceCertificate(
        deviceEdPub: v1.edPub,
        deviceXPub: v1.xPub,
        deviceId: 'legacy-v1',
        sig: await v1.bindingSignature(),
        legacy: true,
      );
      expect(await legacy.verify(v1.edPub), isTrue,
          reason: 'still valid as v1');
      expect(
          () => HybridDeviceCertificate(classical: legacy, mlSig: cert.mlSig),
          throwsA(isA<HybridFormatException>()));
    });

    test('it round-trips through JSON', () async {
      final back = HybridDeviceCertificate.fromJson(cert.toJson());
      expect(await back.verify(account.publicKey), isTrue);
      expect(back.mlSig, cert.mlSig);
    });
  });

  group('safety number v2', () {
    test('symmetric, stable, and never equal to the v1 number', () async {
      final a = await HybridKeyPair.generate();
      final b = await HybridKeyPair.generate();

      final ab = await safetyNumberV3(a.publicKey, b.publicKey);
      final ba = await safetyNumberV3(b.publicKey, a.publicKey);
      expect(ab, ba, reason: 'both people must read the same number');
      expect(ab.split(' ').length, 12);
      expect(ab.replaceAll(' ', '').length, 60);

      // Domain separation: the v1 number over the same classical keys is a
      // different value, so the one-time change is unambiguous rather than
      // looking like a substitution.
      final v1 = await safetyNumber(a.publicKey.edPub, b.publicKey.edPub);
      expect(ab, isNot(v1));

      // It depends on the post-quantum halves, which is the entire point: a
      // substituted ML-DSA key changes the number two people read aloud.
      final bPqSwapped = HybridPublicKey(
          edPub: b.publicKey.edPub,
          mlPub: (await HybridKeyPair.generate()).publicKey.mlPub);
      expect(await safetyNumberV3(a.publicKey, bPqSwapped), isNot(ab));

      // …and on the classical halves too.
      final c = await HybridKeyPair.generate();
      expect(await safetyNumberV3(a.publicKey, c.publicKey), isNot(ab));
    });

    test('the v1 number is unchanged by the refactor', () async {
      // safetyNumberFromMaterial was extracted out of safetyNumber; v1 output
      // must be byte-identical or every verified contact in the wild breaks.
      //
      // The ordering is FULL lexicographic (§2.5), not a comparison of first
      // bytes: two keys agreeing on byte 0 and differing later are ordered by
      // the later byte. Comparing only `edPub[0]` here made this test disagree
      // with the implementation about one pair in every few hundred — a flake
      // that says nothing about the code when it fires, on the one property
      // that must never move.
      final a = await ZIdentity.generate();
      final b = await ZIdentity.generate();
      var less = a.edPub.length < b.edPub.length;
      for (var i = 0; i < a.edPub.length && i < b.edPub.length; i++) {
        if (a.edPub[i] != b.edPub[i]) {
          less = a.edPub[i] < b.edPub[i];
          break;
        }
      }
      final lo = less ? a.edPub : b.edPub;
      final hi = less ? b.edPub : a.edPub;
      expect(
          await safetyNumber(a.edPub, b.edPub),
          await safetyNumberFromMaterial(Uint8List.fromList([...lo, ...hi]),
              context: safetyContext));
      // Pinned against a fixed pair too, so the ordering rule cannot drift in
      // both places at once.
      final x = Uint8List.fromList([1, 2, ...List.filled(30, 0)]);
      final y = Uint8List.fromList([1, 3, ...List.filled(30, 0)]);
      expect(
          await safetyNumber(y, x),
          await safetyNumberFromMaterial(Uint8List.fromList([...x, ...y]),
              context: safetyContext),
          reason: 'ordered by the first byte that differs, not the first byte');
    });
  });
}
