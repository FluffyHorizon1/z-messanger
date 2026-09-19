import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

/// Mixed-version device lists: a not-yet-migrated (pre-ADR-0010) client and a
/// current one must agree about a list they both hold.
///
/// The field bug this guards (P0, 2026-09-19): the migration dual-signs every
/// list (v1 `sig` + v2 `sig2`) and bumps the version. A current client then
/// reported the **v2** fingerprint and signed the ML-DSA over the **v2** input,
/// while a 3.5.7 client — which accepts the list on the v1 signature and knows
/// nothing of v2 — computed the **v1** fingerprint and verified the ML-DSA over
/// the **v1** input. Same list, same version, disagreeing fingerprint: each side
/// is built to read that as an attack (a "split" / "reset your identity" alarm),
/// and the ML-DSA check fails too (a false `pqSignatureMissing`). ADR 0017.
///
/// This is checkable in ONE tree. The v1 signing input (`z-devlist-v1:`) is
/// frozen and byte-identical in 3.5.7 (`b6d7b90`) and HEAD — `git diff b6d7b90
/// HEAD -- protocol/lib/src/multidevice.dart` only ADDS the v2 machinery and does
/// not touch `signingInput` or `deviceListFingerprint`, and 3.5.7's
/// `fingerprint()` is exactly `deviceListFingerprint(version, devices)`. So
/// HEAD's own v1 fingerprint and v1 signing input ARE what a 3.5.7 client
/// computes: the old side of the mix, without a second package.
///
/// Criteria, each a test below:
///   1. a dual-signed list reports the v1 fingerprint a not-yet-migrated client
///      computes for it — the two sides agree;
///   2. the ML-DSA signature on a dual-signed list verifies over the v1 input a
///      not-yet-migrated client checks it against;
///   3. a current client still verifies its own dual-signed list end to end —
///      the hold does not weaken same-version verification.
void main() {
  group('mixed-version device lists agree (ADR 0017)', () {
    late AccountIdentity acct;
    late HybridKeyPair pq;
    late List<DeviceCertificate> devices;
    late SignedDeviceList list;

    setUp(() async {
      acct = await AccountIdentity.generate();
      pq = await HybridKeyPair.fromSeeds(
          edSeed: acct.accountEdSeed!, mlSeed: Uint8List(32));
      final dev = await ZIdentity.generate();
      final laptop = await acct.signDeviceCert(
          deviceEdPub: dev.edPub, deviceXPub: dev.xPub, deviceId: 'laptop');
      devices = [acct.deviceCert, laptop];
      // Exactly what `_migrateDeviceListToV2` produces: a dual-signed list.
      list = await acct.signDeviceList(devices, 2);
    });

    test('1. a dual-signed list reports the v1 fingerprint an old client computes',
        () async {
      expect(list.sig2, isNotNull, reason: 'the migration dual-signs');
      expect(await list.fingerprint(),
          await deviceListFingerprint(list.version, devices),
          reason: 'a not-yet-migrated contact computes the v1 fingerprint for '
              'this list; a current one must report the same, or every mixed '
              'pair sees a phantom split at the same version');
    });

    test('2. the ML-DSA on a dual-signed list verifies over the v1 input',
        () async {
      final sig =
          await HybridDeviceListSignature.sign(accountKey: pq, list: list);
      // What a 3.5.7 client checks: the ML-DSA over the v1 signing input.
      final okOldClient = pqDsaVerify(pq.publicKey.mlPub,
          SignedDeviceList.signingInput(list.version, devices), sig.mlSig);
      expect(okOldClient, isTrue,
          reason: 'a not-yet-migrated client verifies the ML-DSA over the v1 '
              'input; signing it over v2 is what raised the false '
              'pqSignatureMissing');
      // And a current client still verifies it (the two agree, not just the old).
      expect(await sig.verifies(list, pq.publicKey.mlPub), isTrue);
    });

    test('3. a current client still verifies its own dual-signed list', () async {
      // The classical v2 signature is still produced and still enforced in
      // verify() — holding the fingerprint and ML-DSA at v1 does not touch it.
      expect(await list.verify(), isTrue);
    });
  });
}
