import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

// Device pairing v3 (PROTOCOL §10.2, ADR 0033 §3): v2's four frames, hybrid
// with ML-KEM-768. A recording of a v2 rendezvous gives the account's whole
// contact list to whoever later breaks X25519; one who breaks it while the
// ceremony runs can pass both ephemerals through and read the enrolment. In
// v3 the new device offers a fresh ML-KEM-768 key beside its commitment, the
// existing device encapsulates to it, and the KEM secret K joins the X25519
// output in the channel key and in the digits.
//
// The adversary throughout is ADR 0033's: it holds every classical private
// key — here also the pairing code, which is no long-term secret — every
// frame, and no ML-KEM secret.
//
// Criteria, each asserted below:
//  1. a completed v3 exchange derives one channel key and one eight-digit
//     string on both sides; the enrolment opens, binds the ratchet key the
//     digits covered, carries the host's `pqdc` as the bytes it gave, and
//     never the account root; and the frames have the sizes reported;
//  2. every value is §10.2's, re-derived here from the primitives and the
//     text alone — the code's `pairKey`, the keyed commitment over SHA-256 of
//     the offered KEM key, the channel key from `dh || K` salted with
//     `pairKey`, the digits over `dh || K` with SHA-256(ekN || ct) in the
//     info — and none of them is what v2 computes from the same inputs;
//  3. the adversary derives no channel key from a recording: not from the
//     X25519 output alone, not with any K it can compute, not as v2 would,
//     and the enrolment opens under none of its keys — while the one K the
//     new device decapsulated opens it;
//  4. a machine in the middle that swaps only the KEM gets nowhere: the
//     commitment binds SHA-256(ekN), so a swapped key is refused before any
//     digits — where both channel keys would otherwise have been its — and
//     a swapped ciphertext leaves two different strings on the two screens
//     and the host's enrolment sealed to a key it does not hold;
//  5. a machine in the middle running both legs with keys of its own gets
//     two different strings — one blind guess, not a search;
//  6. nobody can grind the digits: the side that contributes last committed
//     first. The first frame is the commitment and the KEM key and nothing
//     else; the reply is chosen holding only those, and each reply moves the
//     digits; the opening is held to the commitment field by field; and the
//     new device opens once, so its KEM key decapsulates one ciphertext;
//  7. v3 shares nothing with v2 or v1 for one code — no rendezvous, no
//     mailbox, no key — and each version's frames abort the other's steps;
//  8. every field of every v3 frame is its width — `ek` 1 184 bytes and a
//     key FIPS 203 accepts, `ct` 1 088, `sk` 32 — or an abort before anything
//     is hashed, encapsulated or decapsulated; an ephemeral of small order is
//     refused on either side; an enrolment carrying the account root is
//     refused; and a sealing key that is not one is refused at the start;
//  9. through a real relay the library runs the whole ceremony: both screens
//     agree, the new device installs the account with the attestation the
//     host gave, and the host learns the certificate it signed;
// 10. a v3 existing device recognises a v2 new device, and a v1 one, by its
//     first frame on the older mailbox, and says which, answering nothing;
//     a v3 new device facing a v2 existing device hears nothing and says the
//     other device may be older — there is no fallback either way;
// 11. a v2 frame on a v3 mailbox, and a v3 frame on a v2 one, transact
//     nothing: the ceremony listening there answers nothing and shows no
//     digits;
// 12. an existing device whose relay refuses one of the three connections
//     it opens closes the ones it had already made: no socket is left
//     open.

/// An abort for a field's width or shape.
Matcher malformed(String key) => isA<PairingAbort>()
    .having((e) => e.message, 'message', 'malformed frame: $key');

/// A device's sealing key (ADR 0033 §1), from a seed: what 44.3 gives every
/// device, made here with the library's keygen.
Uint8List sealKeyOf(Uint8List seed) => pqKeyPairFromSeed(seed).$1;

void main() {
  group('pairing v3', () {
    test('1. both sides agree, and the enrolment opens without the root',
        () async {
      final phone = await withMlKey(await AccountIdentity.generate());
      final carol = await AccountIdentity.generate();
      final code = PairingCode.generate();
      final seal = sealKeyOf(randomBytes(64));
      final desktop = await PairingInitiatorV3.create(code: code, sealKey: seal);
      expect(b64(desktop.sealKeyHash), b64(sealKeyHash(seal)),
          reason: 'sk is SHA-256 of the sealing key');

      final commit = await desktop.commit();
      final (reply, pending) =
          await PairingResponderV3.reply(commit, code: code);
      final (open, sessDesktop) = await desktop.open(reply);
      final sessPhone = await pending.accept(open);

      expect(sessDesktop.sas, sessPhone.sas);
      expect(sessPhone.sas, matches(RegExp(r'^\d{4} \d{4}$')));
      expect(b64(sessDesktop.channelKey), b64(sessPhone.channelKey));
      expect(b64(sessPhone.peerDeviceEdPub!), b64(desktop.deviceEdPub));
      expect(b64(sessPhone.peerDeviceXPub!), b64(desktop.deviceXPub));
      expect(sessPhone.peerDeviceId, desktop.deviceId);
      expect(b64(sessPhone.peerSealKeyHash!), b64(sealKeyHash(seal)),
          reason: 'what the root attests the new device by');

      // pqdc is the root's (ADR 0033 §1); here it is opaque bytes of the
      // attestation's width, carried as given.
      final pqdc = randomBytes(3309);
      final sealed = await sessPhone.sealEnrollment(phone,
          contacts: [carol.toAccountBundle(displayName: 'Carol')],
          displayName: 'Alice',
          pqdc: pqdc);
      final data = await sessDesktop.openEnrollment(sealed);
      expect(b64(data.pqdc!), b64(pqdc));
      expect(data.accountEdSeed, isNull, reason: 'never the account root');
      expect(b64(data.accountMlPub!), b64(phone.accountMlPub!));
      final acct = await desktop.installFromData(data);
      expect(b64(acct.accountEdPub), b64(phone.accountEdPub));
      expect(await acct.deviceCert.verify(phone.accountEdPub), isTrue);
      expect(b64(acct.deviceCert.deviceXPub), b64(desktop.deviceXPub),
          reason: 'the certificate binds the ratchet key the digits covered');
      expect(acct.holdsAccountRoot, isFalse);

      // The plaintext has §10's members and pqdc, and no root, whatever
      // was asked: there is nothing to ask with.
      final plain = await openWith(sessPhone.channelKey, sealed);
      expect(plain.keys.toList(), [
        'acct', 'pqpub', 'name', 'cert', 'hostcert', 'contacts', 'pqdc', //
      ]);
      // Without an attestation, none goes: a host with no ML-DSA key.
      final bare = await sessDesktop.openEnrollment(
          await sessPhone.sealEnrollment(await AccountIdentity.generate(),
              contacts: const []));
      expect(bare.pqdc, isNull);
      expect(bare.accountMlPub, isNull);

      // The sizes, as the payload the relay carries for each frame.
      final sizes = {
        'commit-v3': jsonEncode({'k': 'commit-v3', ...commit}).length,
        'reply-v3': jsonEncode({'k': 'reply-v3', ...reply}).length,
        'open-v3': jsonEncode({'k': 'open-v3', ...open}).length,
        'enroll-v3 (one contact, pqdc)':
            jsonEncode({'k': 'enroll-v3', 'blob': b64(sealed)}).length,
      };
      expect(sizes['commit-v3'], inInclusiveRange(1600, 1700));
      expect(sizes['reply-v3'], inInclusiveRange(1450, 1550));
      print('pairing v3 frames, payload bytes: $sizes');
    });

    test('2. every value is §10.2\'s, and none is v2\'s', () async {
      final code = PairingCode.generate();
      final seal = sealKeyOf(randomBytes(64));
      final n = await PairingInitiatorV3.create(code: code, sealKey: seal);
      final commit = await n.commit();
      final (reply, pending) =
          await PairingResponderV3.reply(commit, code: code);
      final (open, sessN) = await n.open(reply);
      final sessE = await pending.accept(open);

      final pairKey =
          await hkdf(code.secret, const [], utf8.encode('z-pair-key-v3'), 32);
      expect(await code.pairKey(), pairKey);
      final ek = unb64(commit['ek'] as String);
      expect(ek, n.kemEk);
      expect(mlKemEncapsulationKeyValid(ek), isTrue);
      expect(pqKeyPairFromSeed(n.kemSeed).$1, ek,
          reason: 'the key offered is the one the seed makes');
      final sk = sealKeyHash(seal);
      expect(unb64(commit['c'] as String),
          await commitOf(pairKey, n.ephXPub, n.deviceEdPub, n.deviceXPub, ek,
              sk, n.deviceId));
      expect(open.keys.toSet(), {'ephx', 'ded', 'dx', 'sk', 'id'});
      expect(unb64(open['sk'] as String), sk);

      final ephE = unb64(reply['ephx'] as String);
      final ct = unb64(reply['ct'] as String);
      final dh = await x25519(n.ephXSeed, ephE);
      final k = pqDecapsulate(n.kemSeed, ct);
      expect(sessN.channelKey, await channelOf(dh, k, pairKey));
      expect(sessE.channelKey, sessN.channelKey);
      final sas = await sasOf(dh, k, n.ephXPub, ephE, n.deviceEdPub,
          n.deviceXPub, sk, n.deviceId, ek, ct);
      expect(sessN.sas, sas, reason: 'the library derives what §10.2 says');
      expect(sessE.sas, sas);

      // The digits move with K and with the KEM exchange each: neither is
      // decoration.
      expect(
          await sasOf(dh, Uint8List(32), n.ephXPub, ephE, n.deviceEdPub,
              n.deviceXPub, sk, n.deviceId, ek, ct),
          isNot(sas),
          reason: 'K is in the input');
      final otherCt = pqEncapsulate(ek).$1;
      expect(
          await sasOf(dh, k, n.ephXPub, ephE, n.deviceEdPub, n.deviceXPub, sk,
              n.deviceId, ek, otherCt),
          isNot(sas),
          reason: 'SHA-256(ekN || ct) is in the info');
      expect(
          await sasOf(dh, k, n.ephXPub, ephE, n.deviceEdPub, n.deviceXPub,
              sealKeyHash(sealKeyOf(randomBytes(64))), n.deviceId, ek, ct),
          isNot(sas),
          reason: 'sk is in the info');

      // What v2 computes from the same ephemerals and device fields: none of
      // it is anything v3 uses.
      final v2Channel =
          await hkdf(dh, Uint8List(32), utf8.encode('z-pair-channel-v2'), 32);
      final v2Commit = await sha256([
        ...utf8.encode('z-pair-commit-v2:'),
        ...n.ephXPub,
        ...n.deviceEdPub,
        ...n.deviceXPub,
        ...utf8.encode(n.deviceId),
      ]);
      final v2Sas = digits(await hkdf(
          dh,
          [...n.ephXPub, ...ephE],
          [
            ...utf8.encode('z-pair-sas-v2'),
            ...n.deviceEdPub,
            ...n.deviceXPub,
            ...utf8.encode(n.deviceId),
          ],
          8));
      expect(sessN.channelKey, isNot(v2Channel));
      expect(unb64(commit['c'] as String), isNot(v2Commit));
      expect(sessN.sas, isNot(v2Sas));
    });

    test('3. a recording yields no channel key to the quantum adversary',
        () async {
      final phone = await AccountIdentity.generate();
      final carol = await AccountIdentity.generate();
      final code = PairingCode.generate();
      final n = await PairingInitiatorV3.create(
          code: code, sealKey: sealKeyOf(randomBytes(64)));
      final commit = await n.commit();
      final (reply, pending) =
          await PairingResponderV3.reply(commit, code: code);
      final (open, sessN) = await n.open(reply);
      final sessE = await pending.accept(open);
      final blob = await sessE.sealEnrollment(phone,
          contacts: [carol.toAccountBundle(displayName: 'Carol')],
          displayName: 'Alice');

      // What the adversary holds: the code, every X25519 private key (the new
      // device's ephemeral among them, so the X25519 output), the frames.
      final pairKey = await code.pairKey();
      final ephE = unb64(reply['ephx'] as String);
      final ct = unb64(reply['ct'] as String);
      final dh = await x25519(n.ephXSeed, ephE);
      // And every K it can compute without the new device's ML-KEM secret:
      // none at all, zeros, and what its own ML-KEM key decapsulates from the
      // recorded ciphertext.
      final ownKem = randomBytes(64);
      final guesses = <String, Uint8List>{
        'the X25519 output alone': await hkdf(
            dh, pairKey, utf8.encode('z-pair-channel-v3'), 32),
        'with K = 0': await channelOf(dh, Uint8List(32), pairKey),
        "with K from its own ML-KEM key":
            await channelOf(dh, pqDecapsulate(ownKem, ct), pairKey),
        'as v2 derives it': await hkdf(
            dh, Uint8List(32), utf8.encode('z-pair-channel-v2'), 32),
      };
      for (final MapEntry(key: how, value: key) in guesses.entries) {
        expect(b64(key), isNot(b64(sessN.channelKey)), reason: how);
        expect(await opens(key, blob), isFalse,
            reason: 'the enrolment does not open $how');
      }
      // The control: the K the new device decapsulated opens it.
      final k = pqDecapsulate(n.kemSeed, ct);
      expect(await opens(await channelOf(dh, k, pairKey), blob), isTrue);
    });

    test('4. swapping only the KEM is refused, or caught by the digits',
        () async {
      final code = PairingCode.generate();
      final pairKey = await code.pairKey();

      // (a) The key swapped. The machine holds the code and every classical
      // key, and passes the ephemerals and the device fields through; it
      // cannot recompute the commitment before the opening, so it forwards
      // it and swaps the key beside it for one of its own.
      final n = await PairingInitiatorV3.create(
          code: code, sealKey: sealKeyOf(randomBytes(64)));
      final commit = await n.commit();
      final mSeed = randomBytes(64);
      final mEk = sealKeyOf(mSeed);
      final (replyToMallory, phone) = await PairingResponderV3.reply(
          {...commit, 'ek': b64(mEk)},
          code: code);
      // It decapsulates what the phone sent it, and encapsulates afresh to
      // the new device's real key.
      final kPhone =
          pqDecapsulate(mSeed, unb64(replyToMallory['ct'] as String));
      final (ctToN, kN) = pqEncapsulate(n.kemEk);
      final (open, sessN) = await n
          .open({'ephx': replyToMallory['ephx'], 'ct': b64(ctToN)});
      // Had the phone gone on, the machine would hold both channel keys:
      // the X25519 output is its, and so are both K.
      final dh = await x25519(n.ephXSeed, unb64(replyToMallory['ephx'] as String));
      expect(await channelOf(dh, kN, pairKey), sessN.channelKey);
      expect(kPhone, isNot(kN));
      // The commitment binds SHA-256(ekN): the phone stops at the opening,
      // before any digits.
      await expectLater(phone.accept(open),
          throwsA(isA<PairingAbort>().having((e) => e.message, 'message',
              'the opening does not match the commitment')),
          reason: 'a swapped KEM key is refused at the commitment');

      // (b) The ciphertext swapped: the commitment does not cover it, so
      // both sides reach their digits — and the digits differ.
      final n2 = await PairingInitiatorV3.create(
          code: code, sealKey: sealKeyOf(randomBytes(64)));
      final (reply2, phone2) =
          await PairingResponderV3.reply(await n2.commit(), code: code);
      final (ctM, kM) = pqEncapsulate(n2.kemEk);
      final (open2, sessN2) =
          await n2.open({'ephx': reply2['ephx'], 'ct': b64(ctM)});
      final sessPhone2 = await phone2.accept(open2);
      expect(sessN2.sas, isNot(sessPhone2.sas),
          reason: 'the two screens disagree');
      // The machine holds the new device's channel key — its own K — but
      // not the phone's, and the phone's enrolment is sealed under that.
      final dh2 = await x25519(n2.ephXSeed, unb64(reply2['ephx'] as String));
      final kMallory = await channelOf(dh2, kM, pairKey);
      expect(kMallory, sessN2.channelKey);
      final blob = await sessPhone2.sealEnrollment(
          await AccountIdentity.generate(),
          contacts: const []);
      expect(await opens(kMallory, blob), isFalse);
    });

    test('5. a machine in the middle gets two different strings', () async {
      final code = PairingCode.generate();
      final desktop = await PairingInitiatorV3.create(
          code: code, sealKey: sealKeyOf(randomBytes(64)));
      final mitm = await PairingInitiatorV3.create(
          code: code, sealKey: sealKeyOf(randomBytes(64)));

      // Leg 1: the machine as the existing device, toward the real desktop.
      final (replyToDesktop, asPhone) =
          await PairingResponderV3.reply(await desktop.commit(), code: code);
      final (desktopOpen, sessDesktop) = await desktop.open(replyToDesktop);
      final sessMallory1 = await asPhone.accept(desktopOpen);
      // Leg 2: the machine as the new device, toward the real phone. It had
      // to commit before the phone answered.
      final (replyToMallory, phone) =
          await PairingResponderV3.reply(await mitm.commit(), code: code);
      final (malloryOpen, _) = await mitm.open(replyToMallory);
      final sessPhone = await phone.accept(malloryOpen);

      expect(sessDesktop.sas, sessMallory1.sas, reason: 'leg 1 agrees');
      expect(sessPhone.sas, isNot(sessDesktop.sas),
          reason: 'the two screens disagree, which is what the users see');
    });

    test('6. nobody can grind the digits: whoever contributes last committed '
        'first', () async {
      final code = PairingCode.generate();
      final n = await PairingInitiatorV3.create(
          code: code, sealKey: sealKeyOf(randomBytes(64)));
      final commit = await n.commit();
      // The new device contributes everything it ever will in this frame:
      // its ephemeral, its keys, sk and id behind the commitment, and the KEM
      // key beside it, covered by it. It encapsulates nothing.
      expect(commit.keys.toSet(), {'c', 'ek'});
      expect(unb64(commit['c'] as String), hasLength(32));
      expect(unb64(commit['ek'] as String), hasLength(1184));

      // The existing device encapsulates holding only that. Whatever it
      // picks, the digits come out somewhere it could not see: each reply
      // gives another string, which it learns only after the opening.
      final seen = <String>{};
      for (var i = 0; i < 20; i++) {
        final (reply, _) = await PairingResponderV3.reply(commit, code: code);
        final ephE = unb64(reply['ephx'] as String);
        final ct = unb64(reply['ct'] as String);
        seen.add(await sasOf(
            await x25519(n.ephXSeed, ephE),
            pqDecapsulate(n.kemSeed, ct),
            n.ephXPub,
            ephE,
            n.deviceEdPub,
            n.deviceXPub,
            n.sealKeyHash,
            n.deviceId,
            n.kemEk,
            ct));
      }
      expect(seen.length, greaterThan(15),
          reason: 'nothing to aim at before the opening');

      // The opening is held to the commitment, field by field — the KEM key
      // the reply was encapsulated to among them — so the new device cannot
      // move after seeing the reply either.
      final other = await PairingInitiatorV3.create(
          code: code, sealKey: sealKeyOf(randomBytes(64)));
      final (reply, pending) =
          await PairingResponderV3.reply(commit, code: code);
      final (open, sessN) = await n.open(reply);
      final otherOpen = (await other.open(
              (await PairingResponderV3.reply(await other.commit(), code: code))
                  .$1))
          .$1;
      for (final key in ['ephx', 'ded', 'dx', 'sk', 'id']) {
        await expectLater(
            pending.accept({...open, key: otherOpen[key]}),
            throwsA(isA<PairingAbort>().having((e) => e.message, 'message',
                'the opening does not match the commitment')),
            reason: 'rewriting $key must abort');
      }
      expect((await pending.accept(open)).sas, sessN.sas,
          reason: 'the honest opening still agrees');

      // And it opens once. A second reply — another ephemeral, another
      // encapsulation, chosen after the first opening showed what the
      // digits are made of — is refused: the KEM key decapsulates one
      // ciphertext in its life.
      final (second, _) = await PairingResponderV3.reply(commit, code: code);
      await expectLater(n.open(second), throwsStateError);
    });

    test('7. v3 shares nothing with v2 or v1, and each refuses the other\'s '
        'frames', () async {
      final code = PairingCode.generate();
      final rendezvous = {
        await code.rendezvousRoutingId(),
        await code.rendezvousRoutingIdV2(),
        await code.rendezvousRoutingIdV3(),
      };
      expect(rendezvous, hasLength(3));
      final mailboxes = <String>{};
      for (final role in ['i', 'r']) {
        mailboxes.add(await (await RelayPairing.relayIdentity(code, role))
            .routingId());
        mailboxes.add(await (await RelayPairing.relayIdentityV2(code, role))
            .routingId());
        final v3 = await RelayPairing.relayIdentityV3(code, role);
        final okm = await hkdf(
            code.secret, const [], utf8.encode('z-pair-relay-v3:$role'), 64);
        expect(v3.edSeed, okm.sublist(0, 32), reason: 'the v3 mailbox $role');
        expect(v3.xSeed, okm.sublist(32, 64));
        mailboxes.add(await v3.routingId());
      }
      expect(mailboxes, hasLength(6), reason: 'no mailbox shared');
      expect(mailboxes.intersection(rendezvous), isEmpty);

      // v2's frames at v3's steps: each lacks what v3 needs, and aborts.
      final v2n = await PairingInitiatorV2.create(code: code);
      await expectLater(
          PairingResponderV3.reply(await v2n.commit(), code: code),
          throwsA(malformed('ek')));
      final v3n = await PairingInitiatorV3.create(
          code: code, sealKey: sealKeyOf(randomBytes(64)));
      final (v2reply, v2pending) =
          await PairingResponderV2.reply(await v2n.commit());
      await expectLater(v3n.open(v2reply), throwsA(malformed('ct')));
      final (v3reply, v3pending) =
          await PairingResponderV3.reply(await v3n.commit(), code: code);
      final (v2open, _) = await v2n.open(v3reply);
      await expectLater(v3pending.accept(v2open), throwsA(malformed('sk')));
      // And a v3 opening at v2's: it does not match a v2 commitment.
      final (v3open, _) = await v3n.open(v3reply);
      await expectLater(v2pending.accept(v3open),
          throwsA(isA<PairingAbort>()));
    });

    test('8. a field of the wrong width, a key of small order, an enrolment '
        'with the root: each an abort', () async {
      Future<void> refusedBy(
          Future<Object?> Function(Map<String, Object?>) take,
          Map<String, Object?> good,
          String key,
          int width) async {
        for (final bad in <Object?>[
          b64(Uint8List(width - 1)),
          b64(Uint8List(width + 1)),
          b64(Uint8List(0)),
          'not base64!!',
          42,
          null,
        ]) {
          await expectLater(take({...good, key: bad}), throwsA(malformed(key)),
              reason: '$key = $bad must abort');
        }
      }

      final code = PairingCode.generate();
      final n = await PairingInitiatorV3.create(
          code: code, sealKey: sealKeyOf(randomBytes(64)));
      final commit = await n.commit();
      await refusedBy(
          (f) => PairingResponderV3.reply(f, code: code), commit, 'c', 32);
      await refusedBy(
          (f) => PairingResponderV3.reply(f, code: code), commit, 'ek', 1184);
      // A key of the right length that FIPS 203 §7.2 refuses: its first
      // coefficient is q.
      final notAKey = Uint8List.fromList(n.kemEk)
        ..[0] = 0x01
        ..[1] = (n.kemEk[1] & 0xf0) | 0x0d;
      expect(mlKemEncapsulationKeyValid(notAKey), isFalse);
      await expectLater(
          PairingResponderV3.reply({...commit, 'ek': b64(notAKey)},
              code: code),
          throwsA(malformed('ek')));

      final (reply, pending) =
          await PairingResponderV3.reply(commit, code: code);
      for (final (key, width) in [('ephx', 32), ('ct', 1088)]) {
        // A fresh initiator per frame: each opens once.
        final fresh = await PairingInitiatorV3.create(
            code: code, sealKey: sealKeyOf(randomBytes(64)));
        await refusedBy(fresh.open, reply, key, width);
      }
      final (open, _) = await n.open(reply);
      for (final key in ['ephx', 'ded', 'dx', 'sk']) {
        await refusedBy(pending.accept, open, key, 32);
      }
      for (final badId in <Object?>['', 'x' * (maxDeviceIdLength + 1), 7, null]) {
        await expectLater(pending.accept({...open, 'id': badId}),
            throwsA(malformed('id')),
            reason: 'id = $badId must abort');
      }

      // An ephemeral of small order: at the new device in the reply, and at
      // the existing device in an opening committed to it — what someone
      // holding the code could send.
      final zero = Uint8List(32);
      final atN = await PairingInitiatorV3.create(
          code: code, sealKey: sealKeyOf(randomBytes(64)));
      final (replyN, _) =
          await PairingResponderV3.reply(await atN.commit(), code: code);
      await expectLater(atN.open({...replyN, 'ephx': b64(zero)}),
          throwsA(isA<PairingAbort>().having(
              (e) => e.message, 'message', contains('small order'))));
      final kem = sealKeyOf(randomBytes(64));
      final sk = sealKeyHash(sealKeyOf(randomBytes(64)));
      final ded = randomBytes(32), dx = randomBytes(32);
      final forged = {
        'c': b64(await commitOf(
            await code.pairKey(), zero, ded, dx, kem, sk, 'dev')),
        'ek': b64(kem),
      };
      final (_, atE) = await PairingResponderV3.reply(forged, code: code);
      await expectLater(
          atE.accept({
            'ephx': b64(zero),
            'ded': b64(ded),
            'dx': b64(dx),
            'sk': b64(sk),
            'id': 'dev',
          }),
          throwsA(isA<PairingAbort>().having(
              (e) => e.message, 'message', contains('small order'))),
          reason: 'past the commitment, and refused by the X25519 check');

      // An enrolment carrying the account root, sealed under a v3 channel
      // key with v2's sealer, which still offers it: refused.
      final phone = await AccountIdentity.generate();
      final good = await PairingInitiatorV3.create(
          code: code, sealKey: sealKeyOf(randomBytes(64)));
      final (r, p) = await PairingResponderV3.reply(await good.commit(),
          code: code);
      final (o, sessN) = await good.open(r);
      final sessE = await p.accept(o);
      final withRoot = await PairingSession(
              channelKey: sessE.channelKey,
              sas: sessE.sas,
              peerDeviceEdPub: sessE.peerDeviceEdPub,
              peerDeviceXPub: sessE.peerDeviceXPub,
              peerDeviceId: sessE.peerDeviceId)
          .sealEnrollment(phone, contacts: const [], includeAccountRoot: true);
      await expectLater(
          sessN.openEnrollment(withRoot), throwsFormatException);
      expect((await sessN.openEnrollment(
                  await sessE.sealEnrollment(phone, contacts: const [])))
              .accountEdSeed,
          isNull);

      // A sealing key that is not one: refused before anything is drawn.
      await expectLater(
          PairingInitiatorV3.create(code: code, sealKey: notAKey),
          throwsArgumentError);
      await expectLater(
          PairingInitiatorV3.create(code: code, sealKey: Uint8List(1183)),
          throwsArgumentError);
    });
  });

  group('pairing v3 over the relay', tags: ['integration'], () {
    late Process relay;
    late String url;

    setUpAll(() async {
      final serverDir =
          '${Directory.current.parent.path}${Platform.pathSeparator}server';
      final portProbe =
          await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      final port = portProbe.port;
      await portProbe.close();
      relay = await Process.start('node', ['server.js'],
          workingDirectory: serverDir,
          environment: {'PORT': '$port', 'LOG_LEVEL': 'silent'});
      relay.stderr
          .transform(utf8.decoder)
          .listen((s) => print('[relay-err] ${s.trimRight()}'));
      url = 'ws://127.0.0.1:$port';
      for (var i = 0; i < 50; i++) {
        try {
          final res = await (await HttpClient()
                  .getUrl(Uri.parse('http://127.0.0.1:$port/health')))
              .close();
          await res.drain<void>();
          if (res.statusCode == 200) return;
        } catch (_) {
          await Future<void>.delayed(const Duration(milliseconds: 100));
        }
      }
      fail('relay did not start');
    });

    tearDownAll(() => relay.kill());

    /// Everything left in [who]'s mailbox, read without acknowledging it.
    ///
    /// A marker is posted behind whatever the mailbox holds, and the mailbox
    /// is read until the marker arrives: the relay flushes a mailbox in the
    /// order it was filled, so by then everything queued before it has
    /// arrived too. Only the marker is acknowledged.
    Future<List<RelayInbound>> peek(ZIdentity who) async {
      final marker = 'z-peek-${b64url(randomBytes(9))}';
      final poster = await RelayClient.connect(url, await ZIdentity.generate());
      await poster.send(to: await who.routingId(), id: marker, payload: '{}');
      await poster.close();
      final c = await RelayClient.connect(url, who);
      final got = <RelayInbound>[];
      final sub = c.messages.listen(got.add);
      try {
        await waitUntil(() => got.any((e) => e.id == marker),
            what: 'the marker posted behind what the mailbox holds');
        final m = got.firstWhere((e) => e.id == marker);
        c.ackReceived(id: m.id, from: m.from);
      } finally {
        await sub.cancel();
        await c.close();
      }
      return [
        for (final e in got)
          if (!e.id.startsWith('z-peek-')) e
      ];
    }

    test('9. the library runs the whole ceremony through a real relay',
        () async {
      final phone = await withMlKey(await AccountIdentity.generate());
      final carol = await AccountIdentity.generate();
      final code = PairingCode.generate();
      final seal = sealKeyOf(randomBytes(64));
      final desktop = await PairingInitiatorV3.create(code: code, sealKey: seal);
      final attestation = randomBytes(3309);

      String? sasPhone, sasDesktop;
      PairingSessionV3? attested;
      final results = await Future.wait([
        RelayPairing.runNewDeviceV3(
          relayUrl: url,
          n: desktop,
          confirm: (s) async {
            sasDesktop = s;
            return true;
          },
        ),
        RelayPairing.runExistingDeviceV3(
          relayUrl: url,
          code: code,
          me: phone,
          contacts: [carol.toAccountBundle(displayName: 'Carol')],
          displayName: 'Alice',
          attest: (s) async {
            attested = s;
            return attestation;
          },
          confirm: (s) async {
            sasPhone = s;
            return true;
          },
        ),
      ]);
      final result = results[0] as PairingResult?;
      final linkedCert = results[1] as DeviceCertificate?;

      expect(sasDesktop, sasPhone);
      expect(sasPhone, matches(RegExp(r'^\d{4} \d{4}$')));
      expect(result, isNotNull);
      expect(linkedCert, isNotNull);
      expect(b64(linkedCert!.deviceXPub), b64(desktop.deviceXPub));
      expect(await linkedCert.verify(phone.accountEdPub), isTrue);
      // The host was asked to attest exactly what the digits covered.
      expect(b64(attested!.peerDeviceEdPub!), b64(desktop.deviceEdPub));
      expect(b64(attested!.peerDeviceXPub!), b64(desktop.deviceXPub));
      expect(b64(attested!.peerSealKeyHash!), b64(sealKeyHash(seal)));
      expect(b64(result!.data.pqdc!), b64(attestation));
      expect(b64(result.account.accountEdPub), b64(phone.accountEdPub));
      expect(result.account.holdsAccountRoot, isFalse);
      expect(b64(result.data.accountMlPub!), b64(phone.accountMlPub!));
      expect(result.data.contacts.single.displayName, 'Carol');
    }, timeout: const Timeout(Duration(minutes: 2)));

    test('10. an older device on either side is recognised, never answered',
        () async {
      final phone = await AccountIdentity.generate();

      // A v2 new device: its commit-v2 arrives on the v2 mailbox the v3 host
      // holds open, and is recognised for what it is.
      for (final version in [2, 1]) {
        final code = PairingCode.generate();
        var confirmed = false;
        final host = RelayPairing.runExistingDeviceV3(
          relayUrl: url,
          code: code,
          me: phone,
          contacts: const [],
          confirm: (s) async {
            confirmed = true;
            return true;
          },
          timeout: const Duration(seconds: 20),
        );
        final old = version == 2
            ? RelayPairing.runNewDeviceV2(
                relayUrl: url,
                n: await PairingInitiatorV2.create(code: code),
                confirm: (s) async => true,
                timeout: const Duration(seconds: 4),
              ).then<Object?>((r) => r, onError: (Object e) => e)
            : RelayPairing.runNewDevice(
                relayUrl: url,
                n: await PairingInitiator.create(code: code),
                confirm: (s) async => true,
                timeout: const Duration(seconds: 4),
              ).then<Object?>((r) => r, onError: (Object e) => e);
        await expectLater(
            host,
            throwsA(isA<PairingPeerOutdated>()
                .having((e) => e.version, 'version', version)),
            reason: 'the host names the version the other device spoke');
        expect(confirmed, isFalse, reason: 'no digits were ever shown');
        expect(await old, isNot(isA<PairingResult>()),
            reason: 'and the older device paired with nothing');
        // Nothing was answered on any mailbox the older device listens on.
        final iV1 = await peek(await RelayPairing.relayIdentity(code, 'i'));
        final iV2 = await peek(await RelayPairing.relayIdentityV2(code, 'i'));
        expect([...iV1, ...iV2], isEmpty, reason: 'detect, do not transact');
      }

      // A v3 new device facing a v2 host: the host listens where v2 speaks,
      // so nothing answers, and the new device says the other may be older.
      final code = PairingCode.generate();
      var shown = false;
      final v2host = RelayPairing.runExistingDeviceV2(
        relayUrl: url,
        code: code,
        me: phone,
        contacts: const [],
        includeAccountRoot: false,
        confirm: (s) async {
          shown = true;
          return true;
        },
        timeout: const Duration(seconds: 6),
      ).then<Object?>((r) => r, onError: (Object e) => e);
      await expectLater(
          RelayPairing.runNewDeviceV3(
            relayUrl: url,
            n: await PairingInitiatorV3.create(
                code: code, sealKey: sealKeyOf(randomBytes(64))),
            confirm: (s) async {
              shown = true;
              return true;
            },
            timeout: const Duration(seconds: 4),
          ),
          throwsA(isA<PairingAbort>().having(
              (e) => e.message, 'message', contains('older version'))));
      expect(await v2host, isA<TimeoutException>(),
          reason: 'the v2 host heard nothing it would answer');
      expect(shown, isFalse);
    }, timeout: const Timeout(Duration(minutes: 2)));

    test('11. a frame of the other version, on either mailbox, transacts '
        'nothing', () async {
      final phone = await AccountIdentity.generate();

      // A v2 commitment posted on the v3 host's own mailbox — by someone
      // holding the code, which holds every mailbox key.
      final code = PairingCode.generate();
      var shown = false;
      final v3host = RelayPairing.runExistingDeviceV3(
        relayUrl: url,
        code: code,
        me: phone,
        contacts: const [],
        confirm: (s) async {
          shown = true;
          return true;
        },
        timeout: const Duration(seconds: 4),
      ).then<Object?>((r) => r, onError: (Object e) => e);
      final asV3New = await RelayClient.connect(
          url, await RelayPairing.relayIdentityV3(code, 'i'));
      await asV3New.send(
          to: await (await RelayPairing.relayIdentityV3(code, 'r'))
              .routingId(),
          id: 'z-pair-commit',
          payload: jsonEncode({
            'k': 'commit-v2',
            ...await (await PairingInitiatorV2.create(code: code)).commit()
          }));
      await asV3New.close();
      expect(await v3host, isA<TimeoutException>(),
          reason: 'not its kind of frame: no reply, no digits');
      expect(await peek(await RelayPairing.relayIdentityV3(code, 'i')),
          isEmpty);

      // A v3 commitment posted on the v2 host's mailbox.
      final code2 = PairingCode.generate();
      final v2host = RelayPairing.runExistingDeviceV2(
        relayUrl: url,
        code: code2,
        me: phone,
        contacts: const [],
        includeAccountRoot: false,
        confirm: (s) async {
          shown = true;
          return true;
        },
        timeout: const Duration(seconds: 4),
      ).then<Object?>((r) => r, onError: (Object e) => e);
      final asV2New = await RelayClient.connect(
          url, await RelayPairing.relayIdentityV2(code2, 'i'));
      final v3n = await PairingInitiatorV3.create(
          code: code2, sealKey: sealKeyOf(randomBytes(64)));
      await asV2New.send(
          to: await (await RelayPairing.relayIdentityV2(code2, 'r'))
              .routingId(),
          id: 'z-pair-commit',
          payload: jsonEncode({'k': 'commit-v3', ...await v3n.commit()}));
      await asV2New.close();
      expect(await v2host, isA<TimeoutException>());
      expect(await peek(await RelayPairing.relayIdentityV2(code2, 'i')),
          isEmpty);
      expect(shown, isFalse, reason: 'no digits on either host');
    }, timeout: const Timeout(Duration(minutes: 2)));

    test('12. a host whose third connection is refused leaves no socket open',
        () async {
      // A front before the relay that refuses the third connection it is
      // asked to upgrade, and holds each client socket it accepted until
      // that socket closes. It passes the Host header through, so the relay
      // checks each authentication as it would without the front.
      final front = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      final open = <WebSocket>{};
      var asked = 0;
      front.listen((req) async {
        asked++;
        if (asked == 3) {
          req.response.statusCode = HttpStatus.serviceUnavailable;
          await req.response.close();
          return;
        }
        final down = await WebSocketTransformer.upgrade(req);
        open.add(down);
        final up = await WebSocket.connect(url,
            headers: {'host': req.headers.value('host') ?? ''});
        void gone() {
          open.remove(down);
          up.close();
        }

        down.listen(up.add, onDone: gone, onError: (Object _) => gone());
        up.listen(down.add,
            onDone: () => down.close(), onError: (Object _) => down.close());
      });
      try {
        var shown = false;
        await expectLater(
            RelayPairing.runExistingDeviceV3(
              relayUrl: 'ws://127.0.0.1:${front.port}',
              code: PairingCode.generate(),
              me: await AccountIdentity.generate(),
              contacts: const [],
              confirm: (s) async {
                shown = true;
                return true;
              },
            ),
            throwsA(isA<WebSocketException>()),
            reason: 'the third connection is refused');
        expect(asked, 3, reason: 'two connections made, the third refused');
        expect(shown, isFalse);
        await waitUntil(() => open.isEmpty,
            what: 'both connections the host had made to close');
      } finally {
        await front.close(force: true);
      }
    }, timeout: const Timeout(Duration(minutes: 2)));
  });
}

/// Polls [done] until it holds, failing with [what] after [timeout]: a wait
/// on something observable, never a sleep standing in for one.
Future<void> waitUntil(bool Function() done,
    {required String what,
    Duration timeout = const Duration(seconds: 15)}) async {
  final deadline = DateTime.now().add(timeout);
  while (!done()) {
    if (DateTime.now().isAfter(deadline)) fail('timed out waiting for $what');
    await Future<void>.delayed(const Duration(milliseconds: 20));
  }
}

/// The account with an ML-DSA-65 key, so its enrolment carries `pqpub`.
Future<AccountIdentity> withMlKey(AccountIdentity a) async =>
    a.withAccountMlPub((await HybridKeyPair.fromSeeds(
            edSeed: a.accountEdSeed!, mlSeed: randomBytes(32)))
        .publicKey
        .mlPub);

// --- §10.2 from the text alone ---------------------------------------------

Future<Uint8List> hkdf(
    List<int> ikm, List<int> salt, List<int> info, int n) async {
  final k = await Hkdf(hmac: Hmac.sha256(), outputLength: n)
      .deriveKey(secretKey: SecretKey(ikm), nonce: salt, info: info);
  return Uint8List.fromList(await k.extractBytes());
}

Future<Uint8List> sha256(List<int> data) async =>
    Uint8List.fromList((await Sha256().hash(data)).bytes);

Future<Uint8List> x25519(Uint8List seed, Uint8List peer) async {
  final x = X25519();
  final s = await x.sharedSecretKey(
      keyPair: await x.newKeyPairFromSeed(seed),
      remotePublicKey: SimplePublicKey(peer, type: KeyPairType.x25519));
  return Uint8List.fromList(await s.extractBytes());
}

/// `c = HMAC(pairKey, "z-pair-commit-v3:" || ephN || ded || dx ||
/// SHA-256(ekN) || sk || id)`.
Future<Uint8List> commitOf(Uint8List pairKey, Uint8List eph, Uint8List ded,
    Uint8List dx, Uint8List ek, Uint8List sk, String id) async {
  final mac = await Hmac.sha256().calculateMac([
    ...utf8.encode('z-pair-commit-v3:'),
    ...eph,
    ...ded,
    ...dx,
    ...await sha256(ek),
    ...sk,
    ...utf8.encode(id),
  ], secretKey: SecretKey(pairKey));
  return Uint8List.fromList(mac.bytes);
}

/// `channelKey = HKDF(dh || K, pairKey, "z-pair-channel-v3", 32)`.
Future<Uint8List> channelOf(Uint8List dh, Uint8List k, Uint8List pairKey) =>
    hkdf([...dh, ...k], pairKey, utf8.encode('z-pair-channel-v3'), 32);

/// Eight digits from seven bytes.
String digits(List<int> okm) {
  var n = 0;
  for (var i = 0; i < 7; i++) {
    n = (n << 8) | okm[i];
  }
  final d = (n % 100000000).toString().padLeft(8, '0');
  return '${d.substring(0, 4)} ${d.substring(4)}';
}

/// `SAS = 8 digits of HKDF(dh || K, ephN || ephE, "z-pair-sas-v3" || ded ||
/// dx || sk || id || SHA-256(ekN || ct))`.
Future<String> sasOf(
        Uint8List dh,
        Uint8List k,
        Uint8List ephN,
        Uint8List ephE,
        Uint8List ded,
        Uint8List dx,
        Uint8List sk,
        String id,
        Uint8List ek,
        Uint8List ct) async =>
    digits(await hkdf(
        [...dh, ...k],
        [...ephN, ...ephE],
        [
          ...utf8.encode('z-pair-sas-v3'),
          ...ded,
          ...dx,
          ...sk,
          ...utf8.encode(id),
          ...await sha256([...ek, ...ct]),
        ],
        8));

/// Whether [sealed] — nonce, ChaCha20-Poly1305, tag — opens under [key].
Future<bool> opens(Uint8List key, Uint8List sealed) async {
  try {
    await openWith(key, sealed);
    return true;
  } catch (_) {
    return false;
  }
}

Future<Map<String, Object?>> openWith(Uint8List key, Uint8List sealed) async {
  final clear = await Chacha20.poly1305Aead().decrypt(
      SecretBox.fromConcatenation(sealed, nonceLength: 12, macLength: 16),
      secretKey: SecretKey(key));
  return (jsonDecode(utf8.decode(clear)) as Map).cast<String, Object?>();
}
