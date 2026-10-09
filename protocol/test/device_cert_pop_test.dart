// A device certificate's proof of possession (ADR 0022, PROTOCOL §3.1).
//
// A certificate proves that the ACCOUNT signed it, not that whoever holds the
// account holds the device key it names: an account signs whatever public
// keys it is handed. `pop` is the device's own signature, naming the one
// account it is a device of. These are the bytes; what a receiver does with
// them — a device proven for one account refused in another's list, a device
// once proven refused without its proof — is the app's (§3.4,
// `app/test/device_pop_test.dart`).
//
// Criteria, each a test below:
//   1. a linked device's proof verifies and proves possession for its own
//      account; device #1 and a legacy record prove it with none; the same
//      certificate without one verifies and proves nothing;
//   2. the proof is the device key's signature over exactly the context, the
//      account key, both device keys and the id: a change to any of them, or
//      the account key signing in the device's place, fails it — and the
//      certificate with it;
//   3. a certificate whose proof does not verify makes the list and the zc2.
//      code carrying it refused, while the same without the member is
//      admitted;
//   4. the member changes nothing the account signs: a list carrying it has
//      the signing inputs, signatures and fingerprint of the same list
//      without it, in all three shapes, and its JSON without the member is
//      that list's byte for byte;
//   5. a member present as anything but a base64 string does not parse, and
//      a certificate without it encodes exactly as before;
//   6. the context is its own: no other context in the library is a prefix
//      of it or has it as a prefix, so its input can equal no other signed
//      input;
//   7. a device makes its own proof — `devicePop` is the device key's
//      signature and `provenDeviceCert` carries it, device #1's carrying
//      none — and the root, holding every account key but not the device's,
//      cannot make one that verifies.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';
import 'package:z_protocol/src/util.dart' show concatBytes;
import 'package:z_protocol/z_protocol.dart';

Future<Uint8List> edSign(Uint8List seed, List<int> msg) async {
  final ed = Ed25519();
  return Uint8List.fromList(
      (await ed.sign(msg, keyPair: await ed.newKeyPairFromSeed(seed))).bytes);
}

/// A root and one linked device of its account, the device's certificate
/// signed by the root as the enrolment does.
Future<
    ({
      AccountIdentity root,
      ZIdentity laptop,
      DeviceCertificate cert,
      AccountIdentity laptopAccount
    })> rootAndLaptop() async {
  final root = await AccountIdentity.generate();
  final laptop = await ZIdentity.generate();
  final cert = await root.signDeviceCert(
      deviceEdPub: laptop.edPub, deviceXPub: laptop.xPub, deviceId: 'laptop');
  final laptopAccount = await AccountIdentity.fromEnrollment(
    accountEdPub: root.accountEdPub,
    deviceEdSeed: laptop.edSeed,
    deviceXSeed: laptop.xSeed,
    deviceId: 'laptop',
    deviceCert: cert,
  );
  return (
    root: root,
    laptop: laptop,
    cert: cert,
    laptopAccount: laptopAccount
  );
}

void main() {
  test(
      '1. a linked device proves possession with its proof; device #1 and a '
      'legacy record with none; without one, nothing is proven', () async {
    final s = await rootAndLaptop();
    final acct = s.root.accountEdPub;
    final proven = s.cert.withPop(await s.cert.makePop(s.laptop.edSeed, acct));
    expect(await proven.verify(acct), isTrue);
    expect(await proven.provesPossession(acct), isTrue);
    expect(await s.cert.verify(acct), isTrue,
        reason: 'a certificate from before the member verifies as ever');
    expect(await s.cert.provesPossession(acct), isFalse,
        reason: 'and proves only that the account signed it');
    expect(await s.root.deviceCert.provesPossession(acct), isTrue,
        reason: "device #1's key is the account key: its certificate is the "
            "device key's own signature");
    expect(s.root.deviceCert.pop, isNull);
    // A zc1. code read as a one-device account.
    final v1 = await ZIdentity.generate();
    final legacy = (await AccountBundle.decode((await v1.bundle()).encode()))
        .devices
        .single;
    expect(legacy.legacy, isTrue);
    expect(await legacy.provesPossession(v1.edPub), isTrue);
    // Proven for its own account only.
    final other = await AccountIdentity.generate();
    expect(await proven.provesPossession(other.accountEdPub), isFalse);
  });

  test(
      '2. the proof covers the context, the account, both device keys and '
      'the id, and only the device key makes it', () async {
    final s = await rootAndLaptop();
    final acct = s.root.accountEdPub;
    final input = concatBytes([
      utf8.encode('z-device-pop-v1:'),
      acct,
      s.laptop.edPub,
      s.laptop.xPub,
      utf8.encode('laptop'),
    ]);
    expect(
        DeviceCertificate.popInput(acct, s.laptop.edPub, s.laptop.xPub, 'laptop'),
        input);
    final pop = await s.cert.makePop(s.laptop.edSeed, acct);
    expect(pop, await edSign(s.laptop.edSeed, input),
        reason: 'RFC 8032 Ed25519 by the device seed over the input');

    final otherX = (await ZIdentity.generate()).xPub;
    final other = await AccountIdentity.generate();
    final variants = <String, Uint8List>{
      'another account': await edSign(
          s.laptop.edSeed,
          DeviceCertificate.popInput(
              other.accountEdPub, s.laptop.edPub, s.laptop.xPub, 'laptop')),
      'another ratchet key': await edSign(
          s.laptop.edSeed,
          DeviceCertificate.popInput(
              acct, s.laptop.edPub, otherX, 'laptop')),
      'another id': await edSign(
          s.laptop.edSeed,
          DeviceCertificate.popInput(
              acct, s.laptop.edPub, s.laptop.xPub, 'phone')),
      'another context': await edSign(s.laptop.edSeed, [
        ...utf8.encode('z-device-cert-v1:'),
        ...input.sublist('z-device-pop-v1:'.length),
      ]),
      'the account key signing': await edSign(s.root.accountEdSeed!, input),
    };
    for (final e in variants.entries) {
      final c = s.cert.withPop(e.value);
      expect(await c.verify(acct), isFalse, reason: e.key);
      expect(await c.provesPossession(acct), isFalse, reason: e.key);
    }
    // The certificate's own fields moved under a genuine proof: the root
    // re-signs the laptop's certificate over another ratchet key and keeps
    // the proof — the swap a root-key holder would make.
    final swapped = await s.root.signDeviceCert(
        deviceEdPub: s.laptop.edPub, deviceXPub: otherX, deviceId: 'laptop');
    expect(await swapped.verify(acct), isTrue);
    expect(await swapped.withPop(pop).verify(acct), isFalse,
        reason: 'the proof covers the ratchet key');
  });

  test(
      '3. a proof that does not verify refuses the list and the account code '
      'carrying it; the same without it is admitted', () async {
    final s = await rootAndLaptop();
    final acct = s.root.accountEdPub;
    final good = s.cert.withPop(await s.cert.makePop(s.laptop.edSeed, acct));
    final bad = s.cert.withPop(Uint8List.fromList(
        [...good.pop!.sublist(0, 63), good.pop![63] ^ 1]));
    final short = s.cert.withPop(Uint8List.fromList(good.pop!.sublist(0, 63)));
    for (final v2Only in [false, true]) {
      expect(
          await (await s.root.signDeviceList([s.root.deviceCert, good], 2,
                  v2Only: v2Only))
              .verify(),
          isTrue);
      for (final c in [bad, short]) {
        final list = await s.root
            .signDeviceList([s.root.deviceCert, c], 2, v2Only: v2Only);
        expect(await list.verify(), isFalse,
            reason: 'the account signed it, and the proof inside fails');
        // Through the wire form too.
        expect(
            await SignedDeviceList.fromJson(
                    jsonDecode(jsonEncode(list.toJson())) as Map<String, Object?>)
                .verify(),
            isFalse);
        expect(
            await SignedDeviceList(
                    accountEdPub: list.accountEdPub,
                    version: list.version,
                    devices: [s.root.deviceCert, s.cert],
                    sig: list.sig,
                    sig2: list.sig2,
                    sig3: list.sig3)
                .verify(),
            isTrue,
            reason: 'the same list with the member taken off is admitted');
      }
    }
    final goodCode =
        s.root.toAccountBundle(otherDevices: [good]).encode();
    expect((await AccountBundle.decode(goodCode)).devices.last.pop, good.pop);
    final badCode = s.root.toAccountBundle(otherDevices: [bad]).encode();
    await expectLater(AccountBundle.decode(badCode), throwsFormatException);
  });

  test(
      '4. the member changes nothing the account signs, in any of the three '
      'shapes', () async {
    final s = await rootAndLaptop();
    final acct = s.root.accountEdPub;
    final good = s.cert.withPop(await s.cert.makePop(s.laptop.edSeed, acct));
    final devsPlain = [s.cert, s.root.deviceCert];
    final devsProven = [good, s.root.deviceCert];
    for (final v2Only in [false, true]) {
      final a = await s.root.signDeviceList(devsPlain, 5, v2Only: v2Only);
      final b = await s.root.signDeviceList(devsProven, 5, v2Only: v2Only);
      expect(SignedDeviceList.signingInput(5, devsProven),
          SignedDeviceList.signingInput(5, devsPlain));
      expect(SignedDeviceList.signingInputV2(5, devsProven),
          SignedDeviceList.signingInputV2(5, devsPlain));
      expect(SignedDeviceList.signingInputV3(5, devsProven),
          SignedDeviceList.signingInputV3(5, devsPlain));
      expect(b.sig, a.sig);
      expect(b.sig2, a.sig2);
      expect(b.sig3, a.sig3);
      expect(await b.fingerprint(), await a.fingerprint());
      expect(b.commitmentInput, a.commitmentInput);
      final stripped = b.toJson();
      for (final d in (stripped['devs'] as List).cast<Map>()) {
        d.remove('pop');
      }
      expect(jsonEncode(stripped), jsonEncode(a.toJson()),
          reason: 'taken off, the list is the one a reader before it holds');
    }
    // A {sig}-only list (from before ADR 0010) — what remains of a
    // dual-signed one with sig2 taken off, which is a valid shape — likewise.
    final dual = await s.root.signDeviceList(devsProven, 6, v2Only: false);
    final v1Only = SignedDeviceList(
        accountEdPub: acct, version: 6, devices: devsProven, sig: dual.sig);
    expect(await v1Only.verify(), isTrue);
    expect(await v1Only.fingerprint(), await dual.fingerprint());
  });

  test(
      '5. a member that is not a base64 string does not parse, and a '
      'certificate without one encodes as before', () async {
    final s = await rootAndLaptop();
    final good = s.cert
        .withPop(await s.cert.makePop(s.laptop.edSeed, s.root.accountEdPub));
    for (final value in <Object?>[null, 7, true, <int>[1], <String, int>{}]) {
      expect(
          () => DeviceCertificate.fromJson({...good.toJson(), 'pop': value}),
          throwsFormatException,
          reason: 'pop: $value');
    }
    expect(s.cert.toJson().keys, ['ded', 'dx', 'id', 'sig'],
        reason: 'no member is written for a proof that is not there');
    expect(good.toJson().keys, ['ded', 'dx', 'id', 'sig', 'pop']);
    final back = DeviceCertificate.fromJson(
        jsonDecode(jsonEncode(good.toJson())) as Map<String, Object?>);
    expect(back.pop, good.pop);
    expect(back.withPop(null).toJson(), s.cert.toJson());
  });

  test(
      '6. no other context in the library is a prefix of the proof\'s, or '
      'has it as a prefix', () {
    // Every 'z-…' literal in lib/src: the contexts the protocol signs, MACs,
    // derives and hashes under. Read from the source so a context added
    // later is held to this too.
    final contexts = <String>{};
    for (final f in Directory('lib/src').listSync().whereType<File>()) {
      for (final m in RegExp(r"'(z-[a-z0-9-]+:?)'")
          .allMatches(f.readAsStringSync())) {
        contexts.add(m.group(1)!);
      }
    }
    expect(contexts, contains(devicePopContext));
    expect(contexts, containsAll(['z-device-cert-v1:', 'z-bind-v1:',
        'z-relay-auth-v2:', 'z-pqc-sig-v1:', 'z-contact-request-acct-v1:']),
        reason: 'the scan found the contexts a device key signs under');
    for (final c in contexts) {
      if (c == devicePopContext) continue;
      expect(devicePopContext.startsWith(c), isFalse, reason: c);
      expect(c.startsWith(devicePopContext), isFalse, reason: c);
    }
  });

  test(
      '7. a device makes its own proof, and the root cannot make one for it',
      () async {
    final s = await rootAndLaptop();
    final acct = s.root.accountEdPub;
    final pop = await s.laptopAccount.devicePop();
    expect(pop,
        await edSign(s.laptop.edSeed,
            DeviceCertificate.popInput(acct, s.laptop.edPub, s.laptop.xPub, 'laptop')));
    expect(await s.laptopAccount.devicePop(), pop, reason: 'deterministic');
    final presented = await s.laptopAccount.provenDeviceCert();
    expect(presented.pop, pop);
    expect(await presented.provesPossession(acct), isTrue);
    expect(s.laptopAccount.isAccountKeyDevice, isFalse);
    expect(s.root.isAccountKeyDevice, isTrue);
    expect((await s.root.provenDeviceCert()).pop, isNull,
        reason: 'device #1 needs none');
    // The root holds the account seed and its own device seed — which are
    // the same — and signs the laptop's certificate; what it can make for
    // the laptop does not verify.
    final byRoot = await s.cert.makePop(s.root.deviceEdSeed, acct);
    expect(await s.cert.withPop(byRoot).verify(acct), isFalse);
  });
}
