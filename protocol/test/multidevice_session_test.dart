import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

Uint8List utf8b(String s) => Uint8List.fromList(utf8.encode(s));

class TestDevice {
  final AccountIdentity id; // this device's local identity
  final DeviceCertificate cert; // its public membership record
  TestDevice(this.id, this.cert);
}

/// Build an account with [devices] members, all signed by the same account key.
Future<List<TestDevice>> makeAccount(int devices) async {
  final primary = await AccountIdentity.generate();
  final out = <TestDevice>[TestDevice(primary, primary.deviceCert)];
  for (var i = 1; i < devices; i++) {
    final kp = await ZIdentity.generate(); // stand-in keypairs for a new device
    final cert = await primary.signDeviceCert(
        deviceEdPub: kp.edPub, deviceXPub: kp.xPub, deviceId: 'd$i');
    final dev = await AccountIdentity.fromEnrollment(
      accountEdPub: primary.accountEdPub,
      deviceEdSeed: kp.edSeed,
      deviceXSeed: kp.xSeed,
      deviceId: 'd$i',
      deviceCert: cert,
    );
    out.add(TestDevice(dev, cert));
  }
  return out;
}

void main() {
  group('M2 — fan-out messaging engine', () {
    test('a message reaches every one of a contact\'s devices', () async {
      final alice = await makeAccount(1); // A1
      final bob = await makeAccount(2); // B1, B2
      final a1 = alice[0].id;
      final a1rid = await a1.routingId();

      final aliceSess = await AccountSession.create(a1, [
        DeviceTarget.fromCert(bob[0].cert),
        DeviceTarget.fromCert(bob[1].cert),
      ]);
      final fan = await aliceSess.encrypt(utf8b('hi bob'));
      expect(fan.length, 2, reason: 'one payload per contact device');

      for (final bd in bob) {
        final rid = await bd.id.routingId();
        final msg = fan.firstWhere((f) => f.routingId == rid);
        final sess = await AccountSession.create(
            bd.id, [DeviceTarget.fromCert(alice[0].cert)]);
        final dec = await sess.decryptFrom(a1rid, msg.payload);
        expect(utf8.decode(dec.plaintext), 'hi bob');
      }
    });

    test('self-sync mirrors a sent message to my own other device', () async {
      final alice = await makeAccount(2); // A1, A2
      final bob = await makeAccount(1); // B1
      final a1 = alice[0].id, a2 = alice[1].id;
      final a1rid = await a1.routingId();

      // A1 sends to Bob AND to my own second device.
      final sess = await AccountSession.create(a1, [
        DeviceTarget.fromCert(bob[0].cert),
        DeviceTarget.fromCert(alice[1].cert),
      ]);
      final fan = await sess.encrypt(utf8b('note to self+bob'));
      expect(fan.length, 2);

      final a2rid = await a2.routingId();
      final mine = fan.firstWhere((f) => f.routingId == a2rid);
      final a2sess =
          await AccountSession.create(a2, [DeviceTarget.fromCert(alice[0].cert)]);
      final dec = await a2sess.decryptFrom(a1rid, mine.payload);
      expect(utf8.decode(dec.plaintext), 'note to self+bob');
    });

    test('bidirectional round-trip between two single-device accounts',
        () async {
      final alice = await makeAccount(1);
      final bob = await makeAccount(1);
      final a1 = alice[0].id, b1 = bob[0].id;
      final a1rid = await a1.routingId(), b1rid = await b1.routingId();

      final aSess =
          await AccountSession.create(a1, [DeviceTarget.fromCert(bob[0].cert)]);
      final bSess =
          await AccountSession.create(b1, [DeviceTarget.fromCert(alice[0].cert)]);

      final f1 = await aSess.encrypt(utf8b('hi'));
      expect(utf8.decode((await bSess.decryptFrom(a1rid, f1.single.payload)).plaintext),
          'hi');
      final f2 = await bSess.encrypt(utf8b('hey back'));
      expect(utf8.decode((await aSess.decryptFrom(b1rid, f2.single.payload)).plaintext),
          'hey back');
    });

    test('session state serializes mid-conversation', () async {
      final alice = await makeAccount(1);
      final bob = await makeAccount(1);
      final a1 = alice[0].id, b1 = bob[0].id;
      final a1rid = await a1.routingId();

      var aSess =
          await AccountSession.create(a1, [DeviceTarget.fromCert(bob[0].cert)]);
      final bSess =
          await AccountSession.create(b1, [DeviceTarget.fromCert(alice[0].cert)]);

      final f1 = await aSess.encrypt(utf8b('m1'));
      await bSess.decryptFrom(a1rid, f1.single.payload);

      aSess = await AccountSession.fromJson(a1, aSess.toJson()); // persist + restore
      final f2 = await aSess.encrypt(utf8b('m2'));
      expect(utf8.decode((await bSess.decryptFrom(a1rid, f2.single.payload)).plaintext),
          'm2');
    });

    test('decrypting from an unknown device is rejected', () async {
      final alice = await makeAccount(1);
      final bob = await makeAccount(1);
      final aSess = await AccountSession.create(
          alice[0].id, [DeviceTarget.fromCert(bob[0].cert)]);
      expect(() => aSess.decryptFrom('not-a-real-rid', 'x'),
          throwsA(isA<UnknownSessionException>()));
    });

    test('addTarget extends fan-out to a newly linked device', () async {
      final alice = await makeAccount(1);
      final bob = await makeAccount(2);
      final a1 = alice[0].id;
      final a1rid = await a1.routingId();

      final sess =
          await AccountSession.create(a1, [DeviceTarget.fromCert(bob[0].cert)]);
      expect(sess.targetRoutingIds.length, 1);
      await sess.addTarget(DeviceTarget.fromCert(bob[1].cert));
      expect(sess.targetRoutingIds.length, 2);

      final fan = await sess.encrypt(utf8b('now to both'));
      expect(fan.length, 2);

      final b2 = bob[1].id;
      final b2rid = await b2.routingId();
      final msg = fan.firstWhere((f) => f.routingId == b2rid);
      final b2sess =
          await AccountSession.create(b2, [DeviceTarget.fromCert(alice[0].cert)]);
      expect(utf8.decode((await b2sess.decryptFrom(a1rid, msg.payload)).plaintext),
          'now to both');
    });
  });
}
