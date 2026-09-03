import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

void main() {
  group('M1 — account/device data model', () {
    test('fresh account: one-device bundle round-trips and verifies', () async {
      final a = await AccountIdentity.generate();
      final bundle = a.toAccountBundle(displayName: 'Alice');
      expect(bundle.devices.length, 1);
      expect(await bundle.verifyAll(), isTrue);

      final decoded = await AccountBundle.decode(bundle.encode());
      expect(b64(decoded.accountEdPub), b64(a.accountEdPub));
      expect(decoded.displayName, 'Alice');
      expect(await decoded.verifyAll(), isTrue);
      // Device #1's routing id is the account key's hash.
      expect(await decoded.devices.first.routingId(), await a.routingId());
    });

    test('device #1 key equals the account key; holds the root', () async {
      final a = await AccountIdentity.generate();
      expect(b64(a.deviceEdPub), b64(a.accountEdPub));
      expect(a.holdsAccountRoot, isTrue);
    });

    test('v1 migration preserves routing id and X25519 (sessions survive)',
        () async {
      final old = await ZIdentity.generate();
      final acct = await AccountIdentity.fromV1(old);
      expect(await acct.routingId(), await old.routingId()); // same mailbox
      expect(b64(acct.deviceXPub), b64(old.xPub)); // same ratchet key
      expect(b64(acct.accountEdPub), b64(old.edPub));
      expect(await acct.toAccountBundle().verifyAll(), isTrue);
    });

    test('enrollment: primary signs a 2nd device; scoped to the account',
        () async {
      final primary = await AccountIdentity.generate();
      final dev =
          await ZIdentity.generate(); // stand-in keypairs for new device
      final cert = await primary.signDeviceCert(
          deviceEdPub: dev.edPub, deviceXPub: dev.xPub, deviceId: 'desktop');

      expect(await cert.verify(primary.accountEdPub), isTrue);
      final stranger = await AccountIdentity.generate();
      expect(await cert.verify(stranger.accountEdPub), isFalse);

      final desktop = await AccountIdentity.fromEnrollment(
        accountEdPub: primary.accountEdPub,
        deviceEdSeed: dev.edSeed,
        deviceXSeed: dev.xSeed,
        deviceId: 'desktop',
        deviceCert: cert,
      );
      expect(desktop.holdsAccountRoot, isFalse);
      expect(await desktop.routingId(), b64url(await sha256Bytes(dev.edPub)));

      final bundle =
          primary.toAccountBundle(displayName: 'Alice', otherDevices: [cert]);
      expect(bundle.devices.length, 2);
      expect(await bundle.verifyAll(), isTrue);
      final routes = await bundle.deviceRoutingIds();
      expect(routes.toSet().length, 2); // two distinct mailboxes
    });

    test('a device without the account root cannot enroll others', () async {
      final primary = await AccountIdentity.generate();
      final dev = await ZIdentity.generate();
      final cert = await primary.signDeviceCert(
          deviceEdPub: dev.edPub, deviceXPub: dev.xPub, deviceId: 'd2');
      final desktop = await AccountIdentity.fromEnrollment(
        accountEdPub: primary.accountEdPub,
        deviceEdSeed: dev.edSeed,
        deviceXSeed: dev.xSeed,
        deviceId: 'd2',
        deviceCert: cert,
      );
      final dev3 = await ZIdentity.generate();
      expect(
        () => desktop.signDeviceCert(
            deviceEdPub: dev3.edPub, deviceXPub: dev3.xPub, deviceId: 'd3'),
        throwsStateError,
      );
    });

    test('tampered device cert fails verification and rejects the code',
        () async {
      final primary = await AccountIdentity.generate();
      final dev = await ZIdentity.generate();
      final cert = await primary.signDeviceCert(
          deviceEdPub: dev.edPub, deviceXPub: dev.xPub, deviceId: 'd');
      final badSig = Uint8List.fromList(cert.sig);
      badSig[0] ^= 0xFF;
      final tampered = DeviceCertificate(
        deviceEdPub: cert.deviceEdPub,
        deviceXPub: cert.deviceXPub,
        deviceId: cert.deviceId,
        sig: badSig,
      );
      expect(await tampered.verify(primary.accountEdPub), isFalse);

      final bundle = AccountBundle(
          accountEdPub: primary.accountEdPub, devices: [tampered]);
      expect(await bundle.verifyAll(), isFalse);
      expect(
          () => AccountBundle.decode(bundle.encode()), throwsFormatException);
    });

    test('legacy zc1. code reads as a one-device account', () async {
      final id = await ZIdentity.generate();
      final v1 = await id.bundle(displayName: 'Bob');
      final acct = await AccountBundle.decode(v1.encode()); // zc1. code
      expect(b64(acct.accountEdPub), b64(v1.edPub));
      expect(acct.devices.length, 1);
      expect(b64(acct.devices.first.deviceXPub), b64(v1.xPub));
      expect(acct.displayName, 'Bob');
      expect(await acct.verifyAll(), isTrue); // legacy device pre-verified
      expect(await acct.devices.first.routingId(), await v1.routingId());
    });

    test('the legacy flag selects a rule, it cannot bypass verification',
        () async {
      // Audit-prep finding: `legacy` is attacker-controlled JSON input. A
      // crafted zc2. code (or device list) must not be able to smuggle an
      // unsigned device in by flagging it legacy.
      final victim = await AccountIdentity.generate();
      final attacker = await AccountIdentity.generate();
      final rogue = DeviceCertificate(
        deviceEdPub: attacker.deviceEdPub,
        deviceXPub: attacker.deviceXPub,
        deviceId: 'legacy-v1',
        sig: Uint8List(64),
        legacy: true,
      );
      expect(await rogue.verify(victim.accountEdPub), isFalse);
      final code = AccountBundle(
          accountEdPub: victim.accountEdPub,
          devices: [victim.deviceCert, rogue]).encode();
      expect(() => AccountBundle.decode(code), throwsFormatException);
      final list = SignedDeviceList.fromJson({
        'acct': b64(victim.accountEdPub),
        'ver': 9,
        'devs': [victim.deviceCert.toJson(), rogue.toJson()],
        'sig': b64(Uint8List(64)),
      });
      expect(await list.verify(), isFalse);

      // ...while a genuine legacy record (device key == account key, id
      // 'legacy-v1', sig = v1 binding signature) still verifies.
      final id = await ZIdentity.generate();
      final genuine = DeviceCertificate(
        deviceEdPub: id.edPub,
        deviceXPub: id.xPub,
        deviceId: 'legacy-v1',
        sig: await id.bindingSignature(),
        legacy: true,
      );
      expect(await genuine.verify(id.edPub), isTrue);
      expect(await genuine.verify(victim.accountEdPub), isFalse);
      // Wrong id or a device key that is not the account key: rejected.
      expect(
          await DeviceCertificate(
                  deviceEdPub: id.edPub,
                  deviceXPub: id.xPub,
                  deviceId: 'phone',
                  sig: await id.bindingSignature(),
                  legacy: true)
              .verify(id.edPub),
          isFalse);
    });

    test('safety number is symmetric and account-key derived', () async {
      final a = await AccountIdentity.generate();
      final b = await AccountIdentity.generate();
      final ab = await b.toAccountBundle().safetyNumberWith(a.accountEdPub);
      final ba = await a.toAccountBundle().safetyNumberWith(b.accountEdPub);
      expect(ab, ba);
      expect(ab.replaceAll(' ', '').length, 60);
    });

    test('local identity JSON round-trips (root and non-root)', () async {
      final a = await AccountIdentity.generate();
      final ra = await AccountIdentity.fromJson(a.toJson());
      expect(b64(ra.deviceEdPub), b64(a.deviceEdPub));
      expect(ra.holdsAccountRoot, isTrue);
      expect(await ra.toAccountBundle().verifyAll(), isTrue);

      final dev = await ZIdentity.generate();
      final cert = await a.signDeviceCert(
          deviceEdPub: dev.edPub, deviceXPub: dev.xPub, deviceId: 'd');
      final desktop = await AccountIdentity.fromEnrollment(
        accountEdPub: a.accountEdPub,
        deviceEdSeed: dev.edSeed,
        deviceXSeed: dev.xSeed,
        deviceId: 'd',
        deviceCert: cert,
      );
      final rd = await AccountIdentity.fromJson(desktop.toJson());
      expect(rd.holdsAccountRoot, isFalse); // account seed not persisted here
      expect(b64(rd.deviceEdPub), b64(dev.edPub));
      expect(await rd.deviceCert.verify(a.accountEdPub), isTrue);
    });

    test('signed device list: verifies; tampering & foreign keys rejected',
        () async {
      final me = await AccountIdentity.generate();
      final dev = await ZIdentity.generate();
      final cert = await me.signDeviceCert(
          deviceEdPub: dev.edPub, deviceXPub: dev.xPub, deviceId: 'd2');
      final list = await me.signDeviceList([me.deviceCert, cert], 2);

      expect(await list.verify(), isTrue);
      expect(list.version, 2);
      expect((await list.routingIds()).length, 2);
      expect(await SignedDeviceList.fromJson(list.toJson()).verify(), isTrue);

      // Bump the version without re-signing → invalid.
      expect(
          await SignedDeviceList(
                  accountEdPub: list.accountEdPub,
                  version: 99,
                  devices: list.devices,
                  sig: list.sig)
              .verify(),
          isFalse);

      // A different account could not have signed it.
      final other = await AccountIdentity.generate();
      expect(
          await SignedDeviceList(
                  accountEdPub: other.accountEdPub,
                  version: 2,
                  devices: list.devices,
                  sig: list.sig)
              .verify(),
          isFalse);

      // A device without the account root cannot sign a list.
      final rootless = await AccountIdentity.fromEnrollment(
        accountEdPub: me.accountEdPub,
        deviceEdSeed: dev.edSeed,
        deviceXSeed: dev.xSeed,
        deviceId: 'd2',
        deviceCert: cert,
      );
      expect(
          () => rootless.signDeviceList([me.deviceCert], 1), throwsStateError);
    });
  });
}
