import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

void main() {
  group('M3 — relay pairing core', () {
    test('happy path: a new device joins the account over the channel',
        () async {
      final phone = await AccountIdentity.generate(); // existing device, has root
      final carol = await AccountIdentity.generate();
      final contacts = [carol.toAccountBundle(displayName: 'Carol')];

      final code = PairingCode.generate();
      final desktop = await PairingInitiator.create(code: code); // new device

      final (reply, sessPhone) = await PairingResponder.respond(desktop.hello());
      final sessDesktop = await desktop.complete(reply);

      // The safety strings shown on both screens match → the user confirms.
      expect(sessDesktop.sas, sessPhone.sas);
      expect(sessPhone.sas, matches(RegExp(r'^\d{3} \d{3}$')));

      final sealed = await sessPhone.sealEnrollment(phone,
          contacts: contacts, includeAccountRoot: false, displayName: 'Alice');
      final acct = await desktop.install(sessDesktop, sealed);

      expect(b64(acct.accountEdPub), b64(phone.accountEdPub)); // same account
      expect(acct.holdsAccountRoot, isFalse); // root not shared by default
      expect(await acct.deviceCert.verify(phone.accountEdPub), isTrue);
      // Distinct device → distinct mailbox from the phone.
      expect(await acct.routingId(), isNot(await phone.routingId()));

      final data = await sessDesktop.openEnrollment(sealed);
      expect(data.contacts.length, 1);
      expect(await data.contacts.first.verifyAll(), isTrue);
      expect(data.contacts.first.displayName, 'Carol');
    });

    test('MITM cannot bridge the channel: the two screens differ', () async {
      final code = PairingCode.generate();
      // Attacker relays but must inject its own ephemeral to each side, so it
      // ends up in TWO separate channels — one with the new device, one with
      // the existing device.
      final desktop = await PairingInitiator.create(code: code);
      final (replyToDesktop, sessAttackerSide) =
          await PairingResponder.respond(desktop.hello()); // attacker answers
      final sessDesktop = await desktop.complete(replyToDesktop);
      expect(sessDesktop.sas, sessAttackerSide.sas); // attacker paired w/ desktop

      final attackerInit = await PairingInitiator.create(code: code);
      final (_, sessPhone) =
          await PairingResponder.respond(attackerInit.hello()); // phone answers

      // The desktop's channel and the phone's channel are cryptographically
      // distinct — no shared key — so their SAS cannot match. (Comparing the
      // 32-byte channel keys is collision-free; the 6-digit SAS derives from it.)
      expect(b64(sessDesktop.channelKey), isNot(b64(sessPhone.channelKey)));
    });

    test('a tampered enrollment blob is rejected', () async {
      final phone = await AccountIdentity.generate();
      final desktop = await PairingInitiator.create();
      final (reply, sessPhone) = await PairingResponder.respond(desktop.hello());
      final sessDesktop = await desktop.complete(reply);
      final sealed = await sessPhone.sealEnrollment(phone,
          contacts: const [], includeAccountRoot: false);
      final bad = Uint8List.fromList(sealed);
      bad[bad.length - 1] ^= 0xFF;
      expect(() => desktop.install(sessDesktop, bad), throwsA(anything));
    });

    test('a cert not bound to my device keys is rejected on install', () async {
      final phone = await AccountIdentity.generate();
      final desktop = await PairingInitiator.create();
      final (reply, sessPhone) = await PairingResponder.respond(desktop.hello());
      final sessDesktop = await desktop.complete(reply);

      // The existing side seals a cert for someone ELSE's device keys.
      final other = await ZIdentity.generate();
      final swapped = PairingSession(
        channelKey: sessPhone.channelKey,
        sas: sessPhone.sas,
        peerDeviceEdPub: other.edPub,
        peerDeviceXPub: other.xPub,
        peerDeviceId: 'x',
      );
      final sealed = await swapped.sealEnrollment(phone,
          contacts: const [], includeAccountRoot: false);
      expect(() => desktop.install(sessDesktop, sealed),
          throwsA(isA<FormatException>()));
    });

    test('includeAccountRoot controls whether the new device can enroll others',
        () async {
      final phone = await AccountIdentity.generate();
      Future<AccountIdentity> link(bool root) async {
        final d = await PairingInitiator.create();
        final (reply, sessPhone) = await PairingResponder.respond(d.hello());
        final sessD = await d.complete(reply);
        final sealed = await sessPhone.sealEnrollment(phone,
            contacts: const [], includeAccountRoot: root);
        return d.install(sessD, sealed);
      }

      final rooted = await link(true);
      final rootless = await link(false);
      expect(rooted.holdsAccountRoot, isTrue);
      expect(rootless.holdsAccountRoot, isFalse);

      final k = await ZIdentity.generate();
      expect(
          await rooted.signDeviceCert(
              deviceEdPub: k.edPub, deviceXPub: k.xPub, deviceId: 'z'),
          isA<DeviceCertificate>());
      expect(
          () => rootless.signDeviceCert(
              deviceEdPub: k.edPub, deviceXPub: k.xPub, deviceId: 'z'),
          throwsStateError);
    });

    test('pairing code round-trips and gives a stable rendezvous', () async {
      final c = PairingCode.generate();
      final parsed = PairingCode.parse(c.text);
      expect(b64(parsed.secret), b64(c.secret));
      expect(await parsed.rendezvousRoutingId(), await c.rendezvousRoutingId());
      expect(c.text, contains('-')); // grouped for readability
    });
  });
}
