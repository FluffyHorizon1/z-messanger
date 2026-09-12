import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

// Device pairing v2 (PROTOCOL §10.1). Two defects in v1 are closed here, and
// each was exploitable by a different party.
//
// The responder used to choose its ephemeral AFTER seeing the initiator's, and
// the ephemerals are the whole input to the safety string — so whoever spoke
// in the responder's place could search ephemerals until the six digits came
// out at a value it had already read aloud. About a million tries.
//
// And the safety string covered the ephemerals and the new device's SIGNING
// key only, while the existing device signed a certificate over the ratchet
// key and device id it read from an unauthenticated rendezvous frame. A relay
// that rewrote nothing but `dx` therefore left BOTH screens showing the same
// six digits while the host certified an X25519 key the attacker held, at the
// real device's routing id — reproduced against v1 before this was written.
//
// v2 puts a commitment first and every certified field into the safety string.
//
// Criteria, each asserted below:
//  1. a completed v2 exchange derives the same channel key and the same
//     eight-digit safety string on both sides, and the enrollment opens;
//  2. an opening that does not match the commitment is REFUSED and the
//     ceremony aborts — not continued at reduced assurance;
//  3. the responder cannot derive the safety string before the opening, so it
//     cannot choose an ephemeral that produces a value it has already said;
//  4. the safety string changes when ANY certified field changes — the
//     ephemerals, the signing key, the ratchet key or the device id — which
//     is the v1 finding, written as a test;
//  5. a machine-in-the-middle running both legs gets two different safety
//     strings, one per screen;
//  6. v1 and v2 share no mailbox, no channel key and no safety string for one
//     code, so neither ceremony can be talked into the other.
void main() {
  group('pairing v2', () {
    test('1. both sides agree, and the enrollment opens', () async {
      final phone = await AccountIdentity.generate();
      final carol = await AccountIdentity.generate();
      final code = PairingCode.generate();
      final desktop = await PairingInitiatorV2.create(code: code);

      final (reply, pending) = await PairingResponderV2.reply(await desktop.commit());
      final (open, sessDesktop) = await desktop.open(reply);
      final sessPhone = await pending.accept(open);

      expect(sessDesktop.sas, sessPhone.sas);
      expect(sessPhone.sas, matches(RegExp(r'^\d{4} \d{4}$')),
          reason: 'eight digits, in two groups');
      expect(b64(sessDesktop.channelKey), b64(sessPhone.channelKey));

      // The responder learned every field it needs to certify, from the
      // opening it verified rather than from an unchecked frame.
      expect(b64(sessPhone.peerDeviceEdPub!), b64(desktop.deviceEdPub));
      expect(b64(sessPhone.peerDeviceXPub!), b64(desktop.deviceXPub));
      expect(sessPhone.peerDeviceId, desktop.deviceId);

      final sealed = await sessPhone.sealEnrollment(phone,
          contacts: [carol.toAccountBundle(displayName: 'Carol')],
          includeAccountRoot: false,
          displayName: 'Alice');
      final acct =
          await desktop.installFromData(await sessDesktop.openEnrollment(sealed));
      expect(b64(acct.accountEdPub), b64(phone.accountEdPub));
      expect(await acct.deviceCert.verify(phone.accountEdPub), isTrue);
      expect(b64(acct.deviceCert.deviceXPub), b64(desktop.deviceXPub),
          reason: 'the certificate binds the ratchet key the SAS covered');
    });

    test('2. an opening that does not match the commitment is refused',
        () async {
      final code = PairingCode.generate();
      final desktop = await PairingInitiatorV2.create(code: code);
      final attacker = await PairingInitiatorV2.create(code: code);

      final (reply, pending) = await PairingResponderV2.reply(await desktop.commit());
      final (open, _) = await desktop.open(reply);

      // Every single-field substitution a relay could make, one at a time.
      for (final entry in {
        'dx': b64(attacker.deviceXPub),
        'ded': b64(attacker.deviceEdPub),
        'id': attacker.deviceId,
        'ephx': b64(attacker.ephXPub),
      }.entries) {
        final tampered = Map<String, Object?>.from(open)
          ..[entry.key] = entry.value;
        await expectLater(pending.accept(tampered), throwsA(isA<PairingAbort>()),
            reason: 'rewriting ${entry.key} must abort the ceremony');
      }
      // And the honest opening still works afterwards: the responder held its
      // state rather than being knocked over by the attempt.
      expect((await pending.accept(open)).sas, isNotEmpty);
    });

    test('3. the responder cannot know the safety string before the opening',
        () async {
      // The commitment is the only thing the responder holds when it picks
      // its ephemeral, and it is a hash: nothing in it can be searched
      // against a target safety string without the opening.
      final code = PairingCode.generate();
      final desktop = await PairingInitiatorV2.create(code: code);
      final commit = await desktop.commit();
      expect(commit.keys.toSet(), {'c'},
          reason: 'the first frame carries the commitment and nothing else');
      expect(unb64(commit['c'] as String).length, 32);

      // A responder that tries a thousand ephemerals cannot steer the result:
      // it does not have the initiator's ephemeral to combine with.
      final seen = <String>{};
      for (var i = 0; i < 25; i++) {
        final (reply, pending) = await PairingResponderV2.reply(commit);
        final (open, _) = await desktop.open(reply);
        seen.add((await pending.accept(open)).sas);
      }
      expect(seen.length, greaterThan(20),
          reason: 'a fresh ephemeral each time moves the safety string, so '
              'there is nothing to aim at until the opening is in hand');
    });

    test('4. the safety string covers every field the certificate binds',
        () async {
      // Recomputed here from primitives rather than by calling the library,
      // so this checks the derivation as well as the property: an independent
      // HKDF over the input §10.1 specifies must reproduce the string the
      // library showed, and must MOVE when only the ratchet key changes.
      final code = PairingCode.generate();
      final a = await PairingInitiatorV2.create(code: code);
      final b = await PairingInitiatorV2.create(code: code);

      final (reply, pending) = await PairingResponderV2.reply(await a.commit());
      final (open, sessInitiator) = await a.open(reply);
      final sessResponder = await pending.accept(open);
      final ephR = unb64(reply['ephx'] as String);

      final dh = Uint8List.fromList(await X25519().sharedSecretKey(
        keyPair: await X25519().newKeyPairFromSeed(a.ephXSeed),
        remotePublicKey: SimplePublicKey(ephR, type: KeyPairType.x25519),
      ).then((k) => k.extractBytes()));

      Future<String> sasOver(Uint8List ded, Uint8List dx, String id) async {
        final k = await Hkdf(hmac: Hmac.sha256(), outputLength: 8).deriveKey(
          secretKey: SecretKey(dh),
          nonce: Uint8List.fromList([...a.ephXPub, ...ephR]),
          info: Uint8List.fromList([
            ...utf8.encode('z-pair-sas-v2'),
            ...ded,
            ...dx,
            ...utf8.encode(id),
          ]),
        );
        final o = await k.extractBytes();
        var n = 0;
        for (var i = 0; i < 7; i++) {
          n = (n << 8) | o[i];
        }
        final d = (n % 100000000).toString().padLeft(8, '0');
        return '${d.substring(0, 4)} ${d.substring(4)}';
      }

      final recomputed =
          await sasOver(a.deviceEdPub, a.deviceXPub, a.deviceId);
      expect(sessInitiator.sas, recomputed,
          reason: 'the library derives what §10.1 says it does');
      expect(sessResponder.sas, recomputed);

      // One field at a time. Each of these is a field the existing device
      // signs a certificate over, so each must be visible on the screen.
      expect(await sasOver(b.deviceEdPub, a.deviceXPub, a.deviceId),
          isNot(recomputed),
          reason: 'the signing key');
      expect(await sasOver(a.deviceEdPub, b.deviceXPub, a.deviceId),
          isNot(recomputed),
          reason: 'the RATCHET key — the field v1 left out, which is what let '
              'a relay substitute it with both screens still agreeing');
      expect(await sasOver(a.deviceEdPub, a.deviceXPub, b.deviceId),
          isNot(recomputed),
          reason: 'the device id');
    });

    test('5. a machine-in-the-middle gets two different safety strings',
        () async {
      final code = PairingCode.generate();
      final desktop = await PairingInitiatorV2.create(code: code);
      // The attacker runs both legs: its own initiator towards the phone, and
      // its own responder towards the desktop. It must commit to the phone
      // before it has seen the desktop's opening.
      final mitm = await PairingInitiatorV2.create(code: code);

      // Leg 1: attacker as responder, towards the real desktop.
      final (replyToDesktop, attackerAsResponder) =
          await PairingResponderV2.reply(await desktop.commit());
      final (desktopOpen, sessDesktop) = await desktop.open(replyToDesktop);
      final sessAttackerSide = await attackerAsResponder.accept(desktopOpen);

      // Leg 2: attacker as initiator, towards the real phone.
      final (replyToAttacker, phoneAsResponder) =
          await PairingResponderV2.reply(await mitm.commit());
      final (attackerOpen, _) = await mitm.open(replyToAttacker);
      final sessPhone = await phoneAsResponder.accept(attackerOpen);

      expect(sessDesktop.sas, sessAttackerSide.sas, reason: 'leg 1 agrees');
      expect(sessPhone.sas, isNot(sessDesktop.sas),
          reason: 'the two screens disagree, which is what the user sees');
    });

    test('6. v1 and v2 share nothing derived from one code', () async {
      final code = PairingCode.generate();
      expect(await code.rendezvousRoutingIdV2(),
          isNot(await code.rendezvousRoutingId()),
          reason: 'different rendezvous');
      for (final role in ['i', 'r']) {
        final v1 = await RelayPairing.relayIdentity(code, role);
        final v2 = await RelayPairing.relayIdentityV2(code, role);
        expect(await v2.routingId(), isNot(await v1.routingId()),
            reason: 'different mailbox for role $role: a v2 device and a v1 '
                'device holding one code never meet');
      }

      // And a v1 hello cannot be fed to a v2 responder: it carries no
      // commitment, so there is nothing to check an opening against.
      final v1Initiator = await PairingInitiator.create(code: code);
      await expectLater(PairingResponderV2.reply(v1Initiator.hello()),
          throwsA(isA<PairingAbort>()),
          reason: 'detect, do not transact');
    });
  });
}
