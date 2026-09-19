import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

/// ADR 0010: the account's device-list signature — classical and post-quantum —
/// and the fingerprint derived from it must cover each device's X25519 ratchet
/// key, not only its Ed25519 key and the version. These lock in that a v2 list
/// closes the substitution the v1 format was blind to, while a legacy v1 list
/// still verifies and keeps its v1 fingerprint.
void main() {
  group('ADR 0010: the device-list signature covers the ratchet keys', () {
    late AccountIdentity acct;
    late HybridKeyPair pq;
    late DeviceCertificate laptop;
    late List<DeviceCertificate> devices;
    late SignedDeviceList list;

    setUp(() async {
      acct = await AccountIdentity.generate();
      pq = await HybridKeyPair.fromSeeds(
          edSeed: acct.accountEdSeed!, mlSeed: Uint8List(32));
      final dev = await ZIdentity.generate();
      laptop = await acct.signDeviceCert(
          deviceEdPub: dev.edPub, deviceXPub: dev.xPub, deviceId: 'laptop');
      devices = [acct.deviceCert, laptop];
      list = await acct.signDeviceList(devices, 2);
    });

    // A device with the same Ed key as [laptop] but a different ratchet key,
    // its certificate signed by the account (the adversary who has broken
    // Ed25519 can forge that — the whole premise of §18).
    Future<DeviceCertificate> swappedLaptop() async {
      final other = await ZIdentity.generate();
      return acct.signDeviceCert(
          deviceEdPub: laptop.deviceEdPub,
          deviceXPub: other.xPub,
          deviceId: laptop.deviceId);
    }

    test('a signed list carries sig2, but its fingerprint holds at v1 (ADR 0016)',
        () async {
      expect(list.sig2, isNotNull);
      expect(await list.verify(), isTrue);
      // The list is dual-signed, but the fingerprint follows v1 while v1 signing
      // continues, so a not-yet-migrated contact — which can only compute the v1
      // fingerprint — agrees with it rather than seeing a phantom split. The v2
      // commitment activates in stage 2 (v2-only lists). ADR 0016; the
      // ratchet-key coverage meanwhile is enforced by verify() (sig2), below.
      expect(await list.fingerprint(), await deviceListFingerprint(2, devices));
      expect(await list.fingerprint(),
          isNot(await deviceListFingerprintV2(2, devices)));
    });

    test('a legacy v1 list still verifies and keeps its v1 fingerprint',
        () async {
      final v1 = SignedDeviceList(
          accountEdPub: list.accountEdPub,
          version: 2,
          devices: devices,
          sig: list.sig); // no sig2
      expect(await v1.verify(), isTrue);
      expect(await v1.fingerprint(), await deviceListFingerprint(2, devices));
    });

    test('swapping a ratchet key: the v1 input is blind, the v2 input is not',
        () async {
      final swapped = [devices[0], await swappedLaptop()];
      expect(SignedDeviceList.signingInput(2, swapped),
          SignedDeviceList.signingInput(2, devices),
          reason: 'the v1 input is over the Ed keys and the version only');
      expect(await deviceListFingerprint(2, swapped),
          await deviceListFingerprint(2, devices));
      expect(SignedDeviceList.signingInputV2(2, swapped),
          isNot(SignedDeviceList.signingInputV2(2, devices)));
      expect(await deviceListFingerprintV2(2, swapped),
          isNot(await deviceListFingerprintV2(2, devices)));
    });

    test('a list carrying the genuine sig and sig2 but a swapped key fails verify',
        () async {
      final forged = SignedDeviceList(
          accountEdPub: list.accountEdPub,
          version: 2,
          devices: [devices[0], await swappedLaptop()],
          sig: list.sig, // the v1 input did not move, so this still verifies
          sig2: list.sig2); // the v2 input did, so this does not
      expect(await forged.verify(), isFalse);
    });

    test('the hybrid signature holds at v1 during the transition (ADR 0016)',
        () async {
      final sig =
          await HybridDeviceListSignature.sign(accountKey: pq, list: list);
      expect(await sig.verifies(list, pq.publicKey.mlPub), isTrue);
      // A not-yet-migrated client verifies this ML-DSA over the v1 input, so the
      // signing input is held at v1 while v1 signing continues (ADR 0016) — that
      // is what stops the false pqSignatureMissing at a 3.5.7 contact. v1 is blind
      // to an X-only swap, so during stage 1 the ML-DSA does NOT catch it; the
      // swapped list is refused by verify() instead (its sig2 is over the moved v2
      // input — the test above). The post-quantum ratchet-key coverage returns in
      // stage 2, when signing moves to v2-only.
      final swapped = SignedDeviceList(
          accountEdPub: list.accountEdPub,
          version: 2,
          devices: [devices[0], await swappedLaptop()],
          sig: list.sig,
          sig2: list.sig2);
      expect(await sig.verifies(swapped, pq.publicKey.mlPub), isTrue,
          reason: 'the ML-DSA is held at the v1 input, which is blind to the swap');
      expect(await swapped.verify(), isFalse,
          reason: 'verify() catches the swap in stage 1: sig2 is over the moved '
              'v2 input');
    });

    test('the hybrid signature over a legacy v1 list still verifies (no reissue)',
        () async {
      final v1 = SignedDeviceList(
          accountEdPub: list.accountEdPub,
          version: 2,
          devices: devices,
          sig: list.sig); // no sig2 → v1 format
      final sig = await HybridDeviceListSignature.sign(accountKey: pq, list: v1);
      expect(await sig.verifies(v1, pq.publicKey.mlPub), isTrue);
    });
  });
}
