import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';
import 'package:z_protocol/src/util.dart' show base32Decode;
import 'package:z_protocol/z_protocol.dart';

// CONNECT v3 (PROTOCOL §20.9, ADR 0033 §4): the connect ceremony hybrid with
// ML-KEM-768. A recording of a version-2 ceremony gives both codes and both
// names to whoever later breaks X25519 and holds the invite, whose carrier
// the ceremony assumes hostile. In version 3 the inviter offers a fresh
// ML-KEM-768 key in message 1, beside a commitment covering its hash; the
// acceptor encapsulates to it in message 2, committing to the ciphertext's
// hash, before the inviter's ephemeral is revealed; and the KEM secret K
// joins the X25519 output in the channel key and in the digits. Each reveal
// adds the account's ML-DSA key and the device's sealing key.
//
// The adversary throughout is ADR 0033's: every classical private key —
// here also the invite, the bearer token — every frame, and no ML-KEM
// secret.
//
// Criteria, each asserted below:
//  1. both sides of a version-3 ceremony agree — one channel key, one
//     string, one go-ahead tag — and each ends holding the other's account
//     ML-DSA key and device sealing key, as authentic as the digits; the
//     frames have the sizes reported;
//  2. every value is §20.9's, re-derived from the primitives and the text
//     alone — `inviteKey3`, the keyed commitments covering SHA-256 of each
//     side's KEM value, the channel key from `dh || K` salted with
//     `inviteKey3`, the digits over `dh || K` with SHA-256(ek || ct) in the
//     info, the reveals' members — and none is what version 2 computes from
//     the same inputs;
//  3. the adversary derives no channel key from a recording, and neither
//     reveal opens under anything it can compute, while the K the inviter
//     decapsulated opens both;
//  4. a machine in the middle that swaps only the KEM — holding the invite
//     and every classical key — is refused by the commitment of the side
//     whose value it swapped: the inviter's key in message 1 at the
//     acceptor, before it reveals itself; the acceptor's ciphertext in
//     message 2 at the inviter. One that re-commits to make the swap pass
//     must bring ephemerals of its own, and though it completes both legs
//     carrying the two real identities, the two screens show different
//     digits;
//  5. a machine in the middle with identities of its own gets two
//     different strings with the invite, and completes neither leg without
//     it;
//  6. nobody can grind the digits: message 1 is the commitment and the KEM
//     key and nothing else; message 2 is chosen holding only those, and each
//     reply moves the digits; the inviter's reveal is held to its
//     commitment; and the inviter opens once, so its KEM key decapsulates
//     one ciphertext;
//  7. a version-3 invite carries its version: both renderings start with
//     `8` and read back, in either case and with or without separators, by
//     the version-3 reader alone; every rendering is refused by this
//     library's own version-2 parser, unmodified, and by verbatim copies of
//     the parser of every build before ADR 0024 and of Release 4.3.2's; the
//     version-3 reader refuses every other version and every malformed code;
//     the link reader refuses it too; and `generate()` still mints version 2;
//  8. a version-3 invite never runs as version 2: the version-1 and
//     version-2 inviter, acceptor and run refuse one before anything is
//     posted, and the version-3 ones refuse any other; the same ten
//     bytes name nine different mailboxes and rendezvous across the three
//     versions; frames of either version abort the other's steps; records
//     keep their version, and each reader refuses the other's;
//  9. a reveal carries `pqk` exactly when its code commits to an ML-DSA key,
//     and then that key, and `pqseal` always — a key FIPS 203 accepts, and
//     the one the code names when it carries `sk`; anything else is an abort
//     on either side; each side's own keys are checked by the same rules
//     before it starts; a KEM member of the wrong width or a key FIPS 203
//     refuses is an abort; and an ephemeral of small order is refused on
//     either side;
// 10. through a real relay, store-and-forward, both sides resumed from
//     storage after every step and every frame posted once: both screens
//     agree, each side holds the other's keys, the mailboxes are left empty,
//     and the four frames measure as reported, message 3 one length with the
//     group bit set and clear;
// 11. a relay in the middle with every classical key but not the invite,
//     rewriting the KEM in every frame it carries, completes neither leg: the
//     acceptor stops at message 3 without revealing itself, and the relay
//     opens nothing it carried;
// 12. a frame of one version on the other's mailbox transacts nothing: runs
//     of version 2 and version 3 on the same ten bytes never meet, and a
//     version-2 message 1 posted into a version-3 acceptor's mailbox stops
//     that run before it posts anything.

/// One side of a ceremony: what the app holds about itself.
class Party {
  final ConnectIdentity id;
  final Uint8List? pqKey; // the account's ML-DSA-65 key; null when classical
  final Uint8List sealKey; // the device's sealing key
  final ZIdentity device;
  Party(this.id, this.pqKey, this.sealKey, this.device);
}

/// A person with a v3 code (or a [classical] one), a sealing key and, when
/// [sk], the code carrying that key's hash (ADR 0033 addendum A1).
Future<Party> person(String name,
    {bool sk = false, bool classical = false}) async {
  final edSeed = randomBytes(32);
  final device =
      await ZIdentity.fromSeeds(edSeed: edSeed, xSeed: randomBytes(32));
  final pq =
      await HybridKeyPair.fromSeeds(edSeed: edSeed, mlSeed: randomBytes(32));
  final seal = pqKeyPairFromSeed(randomBytes(64)).$1;
  final bundle = await ContactBundleV3.forIdentity(device, pq.publicKey,
      displayName: name, sealKeyCommit: sk ? sealKeyHash(seal) : null);
  final code = classical ? bundle.classical.encode() : bundle.encode();
  return Party(await ConnectIdentity.fromCode(code, displayName: name),
      classical ? null : pq.publicKey.mlPub, seal, device);
}

/// One whole in-memory ceremony.
Future<(ConnectSessionV3, ConnectSessionV3, List<Map<String, Object?>>)> run(
    Party i, Party a,
    {ConnectCode? code, bool? group, bool aware = true}) async {
  final inviter = await ConnectInviterV3.create(
      me: i.id, sealKey: i.sealKey, pqKey: i.pqKey, code: code, group: group);
  final x1 = await inviter.commit();
  final (x2, acceptor) = await ConnectAcceptorV3.reply(x1,
      me: a.id,
      code: inviter.code,
      sealKey: a.sealKey,
      pqKey: a.pqKey,
      groupAware: aware);
  final x3 = await inviter.open(x2);
  final (x4, sessionA) = await acceptor.accept(x3);
  final sessionI = await inviter.complete(x4);
  return (sessionI, sessionA, [x1, x2, x3, x4]);
}

void main() {
  group('CONNECT v3', () {
    test('1. both sides agree, and each holds the other\'s post-quantum keys',
        () async {
      final alice = await person('Alice', sk: true);
      final bob = await person('Bob');
      final (sI, sA, frames) = await run(alice, bob, group: false);

      expect(sI.sas, sA.sas);
      expect(sI.sas, matches(RegExp(r'^\d{4} \d{4}$')));
      expect(b64(sI.channelKey), b64(sA.channelKey));
      expect(await sI.goAheadTag(), await sA.goAheadTag(),
          reason: 'the go-ahead tag, from the hybrid channel key');
      expect(sI.peer.displayName, 'Bob');
      expect(sA.peer.displayName, 'Alice');
      expect(b64(sI.peerPqKey!), b64(bob.pqKey!));
      expect(b64(sA.peerPqKey!), b64(alice.pqKey!));
      expect(b64(sI.peerSealKey), b64(bob.sealKey));
      expect(b64(sA.peerSealKey), b64(alice.sealKey));
      expect(sI.group, isFalse);
      expect(sA.group, isFalse);
      // The ML-DSA key each holds is the one the other's code commits to:
      // the contact needs no `pqid` to reach it (ADR 0033 §4).
      final bobCode = await ContactBundleV3.decode(sI.peer.contactCode);
      expect(
          await bobCode.acceptsPqKey(HybridPublicKey(
              edPub: bobCode.accountEdPub, mlPub: sI.peerPqKey!)),
          isTrue);

      final names = ['x1', 'x2', 'x3', 'x4'];
      final sizes = {
        for (var n = 0; n < 4; n++)
          names[n]: jsonEncode({'k': names[n], ...frames[n]}).length
      };
      expect(frames[0].keys.toSet(), {'c', 'ek'});
      expect(frames[1].keys.toSet(), {'ephx', 'c', 'ct'});
      expect(frames[2].keys.toSet(), {'ephx', 'blob'});
      expect(frames[3].keys.toSet(), {'blob'});
      expect(sizes['x1'], inInclusiveRange(1600, 1700));
      expect(sizes['x2'], inInclusiveRange(1500, 1650));
      expect(sizes['x3'], inInclusiveRange(6000, 7000));
      expect(sizes['x4'], inInclusiveRange(6000, 7000));
      print('CONNECT v3 frames, payload bytes (Alice with sk, Bob without): '
          '$sizes');
    });

    test('2. every value is §20.9\'s, and none is version 2\'s', () async {
      final ivy = await person('Ivy');
      final rob = await person('Rob', sk: true);
      final code = ConnectCode.generate(version: 3);
      final inviter = await ConnectInviterV3.create(
          me: ivy.id, sealKey: ivy.sealKey, pqKey: ivy.pqKey, code: code,
          group: false);
      final x1 = await inviter.commit();
      final (x2, acceptor) = await ConnectAcceptorV3.reply(x1,
          me: rob.id,
          code: code,
          sealKey: rob.sealKey,
          pqKey: rob.pqKey,
          groupAware: true);
      final x3 = await inviter.open(x2);
      final (x4, sA) = await acceptor.accept(x3);
      final sI = await inviter.complete(x4);

      final ik3 = await hkdf(
          code.secret, const [], utf8.encode('z-connect-invite-v3'), 32);
      expect(await code.inviteKey(), ik3);
      final ek = unb64(x1['ek'] as String);
      expect(ek, inviter.kemEk);
      expect(pqKeyPairFromSeed(inviter.kemSeed).$1, ek);
      final ct = unb64(x2['ct'] as String);
      final ephA = unb64(x2['ephx'] as String);
      expect(unb64(x1['c'] as String),
          await commitV3(ik3, inviter.ephPub, ek, ivy.id),
          reason: "the inviter's commitment covers SHA-256(ek)");
      expect(unb64(x2['c'] as String), await commitV3(ik3, ephA, ct, rob.id),
          reason: "the acceptor's covers SHA-256(ct)");

      final dh = await x25519(inviter.ephSeed, ephA);
      final k = pqDecapsulate(inviter.kemSeed, ct);
      final channel = await hkdf(
          [...dh, ...k], ik3, utf8.encode('z-connect-channel-v3'), 32);
      expect(sI.channelKey, channel);
      expect(sA.channelKey, channel);
      final sas = await sasV3(dh, k, ivy.id, inviter.ephPub, rob.id, ephA, ek,
          ct);
      expect(sI.sas, sas, reason: 'the library derives what §20.9 says');
      expect(sA.sas, sas);
      expect(await sI.goAheadTag(),
          await hkdf(channel, Uint8List(32), utf8.encode('z-connect-gjoin-v1'),
              16));
      // The digits move with K, and with the KEM exchange.
      expect(
          await sasV3(dh, Uint8List(32), ivy.id, inviter.ephPub, rob.id, ephA,
              ek, ct),
          isNot(sas));
      expect(
          await sasV3(dh, k, ivy.id, inviter.ephPub, rob.id, ephA, ek,
              pqEncapsulate(ek).$1),
          isNot(sas));

      // The reveals, opened with the channel key alone: version 2's members
      // and then `pqk` and `pqseal`.
      final open3 = await openBlob(channel, x3['blob'] as String);
      expect(open3.keys.toList(), ['code', 'name', 'grp', 'pqk', 'pqseal']);
      expect(open3['code'], ivy.id.contactCode);
      expect(unb64(open3['pqk'] as String), ivy.pqKey);
      expect(unb64(open3['pqseal'] as String), ivy.sealKey);
      final open4 = await openBlob(channel, x4['blob'] as String);
      expect(open4.keys.toList(), ['code', 'name', 'grp', 'pqk', 'pqseal']);
      expect(unb64(open4['pqseal'] as String), rob.sealKey);
      expect(sealKeyHash(rob.sealKey), rob.id.sealKeyCommit,
          reason: "Rob's code names his sealing key");

      // What version 2 computes from the same inputs: none of it.
      final ik2 = await hkdf(
          code.secret, const [], utf8.encode('z-connect-invite-v2'), 32);
      final v2Commit = await hmac(ik2, [
        ...utf8.encode('z-connect-commit-v2:'),
        ...inviter.ephPub,
        ...committedTail(ivy.id),
      ]);
      final v2Channel =
          await hkdf(dh, ik2, utf8.encode('z-connect-channel-v2'), 32);
      final v2Sas = await sasV2(dh, ivy.id, inviter.ephPub, rob.id, ephA);
      expect(unb64(x1['c'] as String), isNot(v2Commit));
      expect(sI.channelKey, isNot(v2Channel));
      expect(sI.sas, isNot(v2Sas));
      expect(ik3, isNot(ik2));
    });

    test('3. a recording yields no channel key to the quantum adversary',
        () async {
      final alice = await person('Alice');
      final bob = await person('Bob');
      final code = ConnectCode.generate(version: 3);
      final inviter = await ConnectInviterV3.create(
          me: alice.id, sealKey: alice.sealKey, pqKey: alice.pqKey, code: code);
      final (x2, acceptor) = await ConnectAcceptorV3.reply(
          await inviter.commit(),
          me: bob.id,
          code: code,
          sealKey: bob.sealKey,
          pqKey: bob.pqKey);
      final x3 = await inviter.open(x2);
      final (x4, session) = await acceptor.accept(x3);

      // The invite, every X25519 private key (so the X25519 output), every
      // frame — and whatever K it can compute without the inviter's ML-KEM
      // secret.
      final ik3 = (await code.inviteKey())!;
      final ik2 = await hkdf(
          code.secret, const [], utf8.encode('z-connect-invite-v2'), 32);
      final dh = await x25519(inviter.ephSeed, unb64(x2['ephx'] as String));
      final ct = unb64(x2['ct'] as String);
      final ctx = utf8.encode('z-connect-channel-v3');
      final guesses = <String, Uint8List>{
        'the X25519 output alone': await hkdf(dh, ik3, ctx, 32),
        'with K = 0': await hkdf([...dh, ...Uint8List(32)], ik3, ctx, 32),
        'with K from its own ML-KEM key': await hkdf(
            [...dh, ...pqDecapsulate(randomBytes(64), ct)], ik3, ctx, 32),
        'as version 2 derives it':
            await hkdf(dh, ik2, utf8.encode('z-connect-channel-v2'), 32),
      };
      for (final MapEntry(key: how, value: key) in guesses.entries) {
        expect(b64(key), isNot(b64(session.channelKey)), reason: how);
        for (final blob in [x3['blob'], x4['blob']]) {
          expect(await opensBlob(key, blob as String), isFalse,
              reason: 'no reveal opens $how');
        }
      }
      final k = pqDecapsulate(inviter.kemSeed, ct);
      final real = await hkdf([...dh, ...k], ik3, ctx, 32);
      for (final blob in [x3['blob'], x4['blob']]) {
        expect(await opensBlob(real, blob as String), isTrue,
            reason: 'the control: with the K the inviter decapsulated');
      }
    });

    test('4. swapping only the KEM is refused by the commitment it breaks, '
        'and re-committing to it changes the digits', () async {
      final alice = await person('Alice');
      final bob = await person('Bob');

      // (a) The inviter's key, swapped in message 1. The machine holds the
      // invite and every classical key, passes the ephemerals and the
      // identities through, decapsulates what the acceptor sent it, and
      // encapsulates afresh to the inviter's real key. It cannot recompute
      // the inviter's commitment before message 3 shows the ephemeral, so it
      // forwards it.
      final code = ConnectCode.generate(version: 3);
      final ik3 = (await code.inviteKey())!;
      final inviter = await ConnectInviterV3.create(
          me: alice.id, sealKey: alice.sealKey, pqKey: alice.pqKey, code: code);
      final x1 = await inviter.commit();
      final mSeed = randomBytes(64);
      final mEk = pqKeyPairFromSeed(mSeed).$1;
      final (x2, acceptor) = await ConnectAcceptorV3.reply(
          {...x1, 'ek': b64(mEk)},
          me: bob.id,
          code: code,
          sealKey: bob.sealKey,
          pqKey: bob.pqKey);
      final kBob = pqDecapsulate(mSeed, unb64(x2['ct'] as String));
      final (ctToAlice, kAlice) = pqEncapsulate(inviter.kemEk);
      final x3 = await inviter.open({...x2, 'ct': b64(ctToAlice)});
      final dh = await x25519(inviter.ephSeed, acceptor.ephPub);
      final ctx = utf8.encode('z-connect-channel-v3');
      final withAlice = await hkdf([...dh, ...kAlice], ik3, ctx, 32);
      final withBob = await hkdf([...dh, ...kBob], ik3, ctx, 32);
      final aliceReveal = await openBlob(withAlice, x3['blob'] as String);
      expect(aliceReveal['code'], alice.id.contactCode,
          reason: 'with both K, the machine reads the reveal');
      await expectLater(
          acceptor.accept({
            'ephx': x3['ephx'],
            'blob': await sealBlob(withBob, aliceReveal),
          }),
          throwsA(isA<ConnectAbort>().having((e) => e.message, 'message',
              'the other side revealed something it had not committed to')),
          reason: "the inviter's commitment binds SHA-256(ek): Bob stops "
              'at message 3, before revealing himself');

      // (b) The acceptor's ciphertext, swapped in message 2. The acceptor
      // cannot open message 3 then, and stops; the machine, holding the
      // inviter's channel key, forges message 4 with the acceptor's public
      // code — refused, since the acceptor's commitment covers SHA-256(ct).
      final inviter2 = await ConnectInviterV3.create(
          me: alice.id, sealKey: alice.sealKey, pqKey: alice.pqKey, code: code);
      final (x2b, acceptor2) = await ConnectAcceptorV3.reply(
          await inviter2.commit(),
          me: bob.id,
          code: code,
          sealKey: bob.sealKey,
          pqKey: bob.pqKey);
      final (ctM, kM) = pqEncapsulate(inviter2.kemEk);
      final x3b = await inviter2.open({...x2b, 'ct': b64(ctM)});
      await expectLater(
          acceptor2.accept(x3b),
          throwsA(isA<ConnectAbort>().having(
              (e) => e.message, 'message', 'the sealed reveal did not open')));
      final dh2 = await x25519(inviter2.ephSeed, acceptor2.ephPub);
      final withAlice2 = await hkdf([...dh2, ...kM], ik3, ctx, 32);
      await expectLater(
          inviter2.complete({
            'blob': await sealBlob(withAlice2, {
              'code': bob.id.contactCode,
              'name': 'Bob',
              'pqk': b64(bob.pqKey!),
              'pqseal': b64(bob.sealKey),
            })
          }),
          throwsA(isA<ConnectAbort>().having((e) => e.message, 'message',
              'the other side revealed something it had not committed to')),
          reason: "the acceptor's commitment binds SHA-256(ct)");

      // (c) The machine re-commits, which it can only do with ephemerals of
      // its own: it runs one leg with each side under the other's real
      // public identity — and its own sealing keys, which it would like each
      // side to seal to. Both legs complete; both reveals are its to read;
      // and the digits differ, which is what they are for.
      final mSeal1 = pqKeyPairFromSeed(randomBytes(64)).$1;
      final mSeal2 = pqKeyPairFromSeed(randomBytes(64)).$1;
      final realAlice = await ConnectInviterV3.create(
          me: alice.id, sealKey: alice.sealKey, pqKey: alice.pqKey, code: code);
      final mAsAlice = await ConnectInviterV3.create(
          me: alice.id, sealKey: mSeal1, pqKey: alice.pqKey, code: code);
      final (toMallory, realBob) = await ConnectAcceptorV3.reply(
          await mAsAlice.commit(),
          me: bob.id,
          code: code,
          sealKey: bob.sealKey,
          pqKey: bob.pqKey);
      final (toAlice, mAsBob) = await ConnectAcceptorV3.reply(
          await realAlice.commit(),
          me: bob.id,
          code: code,
          sealKey: mSeal2,
          pqKey: bob.pqKey);
      final aliceX3 = await realAlice.open(toAlice);
      final (forAlice, mLeg1) = await mAsBob.accept(aliceX3);
      final (bobX4, bobSees) =
          await realBob.accept(await mAsAlice.open(toMallory));
      final mLeg2 = await mAsAlice.complete(bobX4);
      final aliceSees = await realAlice.complete(forAlice);
      expect(b64(aliceSees.peer.accountEdPub), b64(bob.id.accountEdPub),
          reason: "Alice holds Bob's real identity");
      expect(b64(bobSees.peer.accountEdPub), b64(alice.id.accountEdPub));
      expect(b64(aliceSees.peerSealKey), b64(mSeal2),
          reason: "and the machine's sealing key, were she to go on");
      expect(b64(mLeg1.peerSealKey), b64(alice.sealKey));
      expect(b64(mLeg2.peerSealKey), b64(bob.sealKey));
      expect(aliceSees.sas, isNot(bobSees.sas),
          reason: 'the two screens disagree');
    });

    test('5. identities of its own: two strings with the invite, nothing '
        'without it', () async {
      final alice = await person('Alice');
      final bob = await person('Bob');
      final mallory = await person('Mallory');
      final code = ConnectCode.generate(version: 3);
      final (aliceSees, mLeg1, _) = await run(alice, mallory, code: code);
      final (mLeg2, bobSees, _) = await run(mallory, bob, code: code);
      expect(aliceSees.sas, mLeg1.sas);
      expect(mLeg2.sas, bobSees.sas);
      expect(bobSees.sas, isNot(aliceSees.sas),
          reason: 'the digits are what catch whoever holds the link');

      // Without the invite: everything it does is under an invite of its
      // own, and the real acceptor stops at message 3.
      final guess = ConnectCode.generate(version: 3);
      final real = await ConnectInviterV3.create(
          me: alice.id, sealKey: alice.sealKey, pqKey: alice.pqKey, code: code);
      final mAsInviter = await ConnectInviterV3.create(
          me: mallory.id,
          sealKey: mallory.sealKey,
          pqKey: mallory.pqKey,
          code: guess);
      final (towardBob, bobSide) = await ConnectAcceptorV3.reply(
          await mAsInviter.commit(),
          me: bob.id,
          code: code,
          sealKey: bob.sealKey,
          pqKey: bob.pqKey);
      await expectLater(bobSide.accept(await mAsInviter.open(towardBob)),
          throwsA(isA<ConnectAbort>()),
          reason: 'Bob stops at message 3 and never reveals himself');
      final (towardAlice, mAsAcceptor) = await ConnectAcceptorV3.reply(
          await real.commit(),
          me: mallory.id,
          code: guess,
          sealKey: mallory.sealKey,
          pqKey: mallory.pqKey);
      await expectLater(mAsAcceptor.accept(await real.open(towardAlice)),
          throwsA(isA<ConnectAbort>()),
          reason: "Alice's reveal does not open for it");
    });

    test('6. nobody can grind the digits: whoever contributes last committed '
        'first', () async {
      final alice = await person('Alice');
      final bob = await person('Bob');
      final code = ConnectCode.generate(version: 3);
      final inviter = await ConnectInviterV3.create(
          me: alice.id, sealKey: alice.sealKey, pqKey: alice.pqKey, code: code);
      final x1 = await inviter.commit();
      expect(x1.keys.toSet(), {'c', 'ek'},
          reason: 'the commitment, and the key it covers: nothing to aim at');

      final seen = <String>{};
      for (var n = 0; n < 20; n++) {
        final (x2, _) = await ConnectAcceptorV3.reply(x1,
            me: bob.id, code: code, sealKey: bob.sealKey, pqKey: bob.pqKey);
        final ephA = unb64(x2['ephx'] as String);
        final ct = unb64(x2['ct'] as String);
        seen.add(await sasV3(
            await x25519(inviter.ephSeed, ephA),
            pqDecapsulate(inviter.kemSeed, ct),
            alice.id,
            inviter.ephPub,
            bob.id,
            ephA,
            inviter.kemEk,
            ct));
      }
      expect(seen.length, greaterThan(15),
          reason: 'each reply moves the digits, which the acceptor learns '
              'only after message 3');

      // The inviter's reveal is held to its commitment: another ephemeral,
      // or another identity under the same channel, is refused.
      final (x2, acceptor) = await ConnectAcceptorV3.reply(x1,
          me: bob.id, code: code, sealKey: bob.sealKey, pqKey: bob.pqKey);
      final x3 = await inviter.open(x2);
      final mallory = await person('Mallory');
      final other = await ConnectInviterV3.create(
          me: mallory.id,
          sealKey: mallory.sealKey,
          pqKey: mallory.pqKey,
          code: code);
      final dh = await x25519(inviter.ephSeed, acceptor.ephPub);
      final channel = await hkdf(
          [...dh, ...pqDecapsulate(inviter.kemSeed, acceptor.ct)],
          (await code.inviteKey())!,
          utf8.encode('z-connect-channel-v3'),
          32);
      await expectLater(
          acceptor.accept({
            'ephx': x3['ephx'],
            'blob': await sealBlob(channel, {
              'code': mallory.id.contactCode,
              'name': 'Alice',
              'pqk': b64(mallory.pqKey!),
              'pqseal': b64(mallory.sealKey),
            }),
          }),
          throwsA(isA<ConnectAbort>().having((e) => e.message, 'message',
              'the other side revealed something it had not committed to')));
      await expectLater(acceptor.accept({...x3, 'ephx': b64(other.ephPub)}),
          throwsA(isA<ConnectAbort>()));
      final (_, session) = await acceptor.accept(x3);
      expect(session.peer.displayName, 'Alice');

      // And the inviter opens once: a second reply is refused, so its KEM
      // key decapsulates one ciphertext in its life.
      final (again, _) = await ConnectAcceptorV3.reply(x1,
          me: bob.id, code: code, sealKey: bob.sealKey, pqKey: bob.pqKey);
      await expectLater(inviter.open(again), throwsA(isA<ConnectAbort>()));
      expect(inviter.opened, isTrue);
    });

    test('7. the version rides in the invite, and every older parser refuses '
        'it', () async {
      for (var n = 0; n < 200; n++) {
        final code = ConnectCode.generate(version: 3);
        expect(code.version, 3);
        expect(code.text,
            matches(RegExp(r'^8[A-Z2-7]{4}-[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{2}$')));
        final link = code.link();
        expect(link, startsWith('https://www.zmessengers.com/i#8'));
        for (final r in [
          code.text,
          code.text.toLowerCase(),
          code.text.replaceAll('-', ''),
          code.text.replaceAll('-', ' '),
        ]) {
          final back = ConnectCode.parseV3(r);
          expect(back.version, 3, reason: r);
          expect(back.secret, code.secret, reason: r);
          expect(() => ConnectCode.parse(r), throwsFormatException,
              reason: "this library's version-2 parser refuses \"$r\"");
          expect(() => _parseBefore0032(r), throwsFormatException,
              reason: 'Release 4.3.2 refuses "$r"');
          expect(() => _parseBefore0024(r), throwsFormatException,
              reason: 'a build before ADR 0024 refuses "$r"');
        }
        final back = ConnectCode.fromLinkV3(link)!;
        expect(back.version, 3);
        expect(back.secret, code.secret);
        expect(ConnectCode.fromLink(link), isNull);
        expect(_fromLinkBefore0032(link), isNull);
        expect(_fromLinkBefore0024(link), isNull);
        expect(IntroLink.problemWith(link), IntroLinkProblem.notALink);
        expect(IntroLink.problemWith(code.text), IntroLinkProblem.notALink);
      }

      // The version-3 reader reads version 3 and nothing else.
      for (final v in [1, 2]) {
        final code = ConnectCode.generate(version: v);
        expect(() => ConnectCode.parseV3(code.text), throwsFormatException);
        expect(ConnectCode.fromLinkV3(code.link()), isNull);
        expect(ConnectCode.parse(code.text).version, v,
            reason: 'and the version-2 parser still reads its own');
      }
      final good = ConnectCode.generate(version: 3).text.replaceAll('-', '');
      for (final bad in [
        '8',
        good.substring(0, 16),
        '${good}A',
        '${good.substring(0, 16)}1',
        '8$good',
        '9${good.substring(1)}',
        '${good.substring(1, 5)}8${good.substring(5)}',
      ]) {
        expect(() => ConnectCode.parseV3(bad), throwsFormatException,
            reason: '"$bad" is not a version-3 code');
      }
      for (final page in [
        'https://www.zmessengers.com/index.html#$good',
        'https://www.zmessengers.com/c#$good',
      ]) {
        expect(ConnectCode.fromLinkV3(page), isNull, reason: page);
      }

      // Minted only when asked for: generate() mints connectInviteVersion,
      // which stays 2. Version 3 is minted by its own inviter, with the
      // device's sealing key, a release after the readers ship; the
      // version-2 ceremony refuses one whatever the constant says.
      expect(connectInviteVersion, 2);
      expect(ConnectCode.generate().version, 2);
      final alice = await person('Alice');
      expect((await ConnectInviter.create(me: alice.id)).code.version, 2);
      expect((await ConnectRun.invite(me: alice.id)).code.version, 2);
      expect(
          (await ConnectInviterV3.create(
                  me: alice.id, sealKey: alice.sealKey, pqKey: alice.pqKey))
              .code
              .version,
          3,
          reason: 'the version-3 inviter mints its own');
    });

    test('8. a version-3 invite never runs as version 2, nor the reverse',
        () async {
      final alice = await person('Alice');
      final bob = await person('Bob');
      final secret = randomBytes(10);
      final one = ConnectCode(secret),
          two = ConnectCode(secret, version: 2),
          three = ConnectCode(secret, version: 3);
      final ids = <String>{
        for (final c in [one, two, three]) ...[
          for (final role in ['i', 'r'])
            await (await mailboxIdentity(c, role)).routingId(),
          await c.rendezvousRoutingId(),
        ]
      };
      expect(ids, hasLength(9), reason: 'nine mailboxes and rendezvous');
      for (final role in ['i', 'r']) {
        final okm = await hkdf(
            secret, const [], utf8.encode('z-connect-relay-v3:$role'), 64);
        final id = await mailboxIdentity(three, role);
        expect(id.edSeed, okm.sublist(0, 32));
        expect(id.xSeed, okm.sublist(32, 64));
      }
      expect(
          await three.rendezvousRoutingId(),
          b64url(await sha256(
              [...utf8.encode('z-connect-rendezvous-v3:'), ...secret])));
      expect(await one.inviteKey(), isNull);
      expect(await three.inviteKey(), isNot(await two.inviteKey()));

      // The version-1 and version-2 ceremony refuses a version-3 invite
      // before it draws or posts anything.
      expect(() => ConnectRun.accept(me: bob.id, code: three),
          throwsArgumentError);
      await expectLater(
          ConnectRun.invite(me: alice.id, code: three), throwsArgumentError);
      await expectLater(ConnectInviter.create(me: alice.id, code: three),
          throwsArgumentError);
      final v2inviter = await ConnectInviter.create(me: alice.id, code: two);
      await expectLater(
          ConnectAcceptor.reply(await v2inviter.commit(),
              me: bob.id, code: three),
          throwsArgumentError);
      // And the version-3 ceremony refuses any other.
      for (final c in [one, two]) {
        await expectLater(
            ConnectInviterV3.create(
                me: alice.id,
                sealKey: alice.sealKey,
                pqKey: alice.pqKey,
                code: c),
            throwsArgumentError);
        expect(
            () => ConnectRunV3.accept(
                me: bob.id, sealKey: bob.sealKey, pqKey: bob.pqKey, code: c),
            throwsArgumentError);
      }

      // Frames of one version at the other's steps abort.
      final v3inviter = await ConnectInviterV3.create(
          me: alice.id, sealKey: alice.sealKey, pqKey: alice.pqKey, code: three);
      await expectLater(
          ConnectAcceptorV3.reply(await v2inviter.commit(),
              me: bob.id, code: three, sealKey: bob.sealKey, pqKey: bob.pqKey),
          throwsA(isA<ConnectAbort>()),
          reason: 'a version-2 message 1 carries no KEM key');
      final (v2reply, v2acceptor) = await ConnectAcceptor.reply(
          await v2inviter.commit(),
          me: bob.id,
          code: two);
      await expectLater(v3inviter.open(v2reply), throwsA(isA<ConnectAbort>()),
          reason: 'a version-2 message 2 carries no ciphertext');
      expect(v3inviter.opened, isFalse);
      final (v3reply, v3acceptor) = await ConnectAcceptorV3.reply(
          await v3inviter.commit(),
          me: bob.id,
          code: three,
          sealKey: bob.sealKey,
          pqKey: bob.pqKey);
      final v2open = await v2inviter.open(v2reply);
      await expectLater(v3acceptor.accept(v2open), throwsA(isA<ConnectAbort>()),
          reason: 'a version-2 message 3 does not open under version 3');
      final v3open = await v3inviter.open(v3reply);
      await expectLater(v2acceptor.accept(v3open), throwsA(isA<ConnectAbort>()),
          reason: 'nor the reverse');
      final (v3x4, _) = await v3acceptor.accept(v3open);
      await expectLater(v2inviter.complete(v3x4), throwsA(isA<ConnectAbort>()));

      // Records keep their version, and each reader refuses the other's.
      Map<String, Object?> stored(Map<String, Object?> j) =>
          jsonDecode(jsonEncode(j)) as Map<String, Object?>;
      final run3 = await ConnectRunV3.invite(
          me: alice.id, sealKey: alice.sealKey, pqKey: alice.pqKey);
      final j3 = stored(run3.toJson());
      expect(j3['cv'], 3);
      final back = await ConnectRunV3.fromJson(j3);
      expect(back.code.version, 3);
      expect(back.code.text, startsWith('8'));
      await expectLater(ConnectRun.fromJson(j3), throwsFormatException,
          reason: 'the version-2 run reads no version-3 record');
      final run2 = await ConnectRun.invite(me: alice.id);
      await expectLater(
          ConnectRunV3.fromJson(stored(run2.toJson())), throwsFormatException);
      await expectLater(
          ConnectInviterV3.fromJson(v2inviter.toJson()), throwsFormatException);
      await expectLater(
          ConnectInviter.fromJson(v3inviter.toJson()), throwsFormatException);
    });

    test('9. what a reveal carries, and every key either side starts with, '
        'are checked', () async {
      final alice = await person('Alice', sk: true);
      final bob = await person('Bob');
      final classical = await person('Cleo', classical: true);
      final code = ConnectCode.generate(version: 3);
      final ik3 = (await code.inviteKey())!;

      // Message 3 sealed by hand under the real channel, carrying [members]
      // beside the inviter's committed code and name.
      Future<void> refusedAtAcceptor(Party inviterParty,
          Map<String, Object?> Function(Map<String, Object?>) edit,
          String why) async {
        final inviter = await ConnectInviterV3.create(
            me: inviterParty.id,
            sealKey: inviterParty.sealKey,
            pqKey: inviterParty.pqKey,
            code: code);
        final (x2, acceptor) = await ConnectAcceptorV3.reply(
            await inviter.commit(),
            me: bob.id,
            code: code,
            sealKey: bob.sealKey,
            pqKey: bob.pqKey);
        final x3 = await inviter.open(x2);
        final dh = await x25519(inviter.ephSeed, acceptor.ephPub);
        final channel = await hkdf(
            [...dh, ...pqDecapsulate(inviter.kemSeed, acceptor.ct)],
            ik3,
            utf8.encode('z-connect-channel-v3'),
            32);
        final honest = await openBlob(channel, x3['blob'] as String);
        await expectLater(
            acceptor.accept({
              'ephx': x3['ephx'],
              'blob': await sealBlob(channel, edit(Map.of(honest))),
            }),
            throwsA(isA<ConnectAbort>()
                .having((e) => e.message, 'message', contains(why))),
            reason: why);
      }

      final notAKey = Uint8List.fromList(bob.sealKey)
        ..[0] = 0x01
        ..[1] = (bob.sealKey[1] & 0xf0) | 0x0d;
      expect(mlKemEncapsulationKeyValid(notAKey), isFalse);
      final cases = <String, Map<String, Object?> Function(Map<String, Object?>)>{
        'carries no ML-DSA key': (m) => m..remove('pqk'),
        'an ML-DSA key its code does not commit to': (m) =>
            m..['pqk'] = b64(bob.pqKey!),
        'malformed "pqk"': (m) => m..['pqk'] = b64(Uint8List(1951)),
        'missing "pqseal"': (m) => m..remove('pqseal'),
        'malformed "pqseal"': (m) => m..['pqseal'] = b64(Uint8List(1183)),
        'a sealing key its code does not name': (m) =>
            m..['pqseal'] = b64(bob.sealKey),
      };
      for (final MapEntry(key: why, value: edit) in cases.entries) {
        await refusedAtAcceptor(alice, edit, why);
      }
      await refusedAtAcceptor(
          alice, (m) => m..['pqseal'] = b64(notAKey), 'malformed "pqseal"');
      // A classical code commits to no ML-DSA key, so a reveal with one is
      // as wrong as a post-quantum code's without one.
      await refusedAtAcceptor(classical,
          (m) => m..['pqk'] = b64(alice.pqKey!), 'its code commits to none');

      // The same rules at the inviter, for message 4.
      final inviter = await ConnectInviterV3.create(
          me: bob.id, sealKey: bob.sealKey, pqKey: bob.pqKey, code: code);
      final (x2, acceptor) = await ConnectAcceptorV3.reply(
          await inviter.commit(),
          me: alice.id,
          code: code,
          sealKey: alice.sealKey,
          pqKey: alice.pqKey);
      final x3 = await inviter.open(x2);
      final (x4, _) = await acceptor.accept(x3);
      final dh = await x25519(inviter.ephSeed, acceptor.ephPub);
      final channel = await hkdf(
          [...dh, ...pqDecapsulate(inviter.kemSeed, acceptor.ct)],
          ik3,
          utf8.encode('z-connect-channel-v3'),
          32);
      final honest4 = await openBlob(channel, x4['blob'] as String);
      await expectLater(
          inviter.complete({
            'blob': await sealBlob(
                channel, Map.of(honest4)..['pqseal'] = b64(bob.sealKey))
          }),
          throwsA(isA<ConnectAbort>().having((e) => e.message, 'message',
              contains('a sealing key its code does not name'))));
      expect((await inviter.complete(x4)).peer.displayName, 'Alice',
          reason: 'the honest message 4 still completes');

      // Each side's own keys, by the same rules, before it starts.
      for (final (what, start) in <(String, Future<Object?> Function())>[
        (
          'a sealing key the code does not name',
          () => ConnectInviterV3.create(
              me: alice.id, sealKey: bob.sealKey, pqKey: alice.pqKey)
        ),
        (
          'no ML-DSA key for a code that commits to one',
          () => ConnectInviterV3.create(me: bob.id, sealKey: bob.sealKey)
        ),
        (
          'another ML-DSA key',
          () => ConnectInviterV3.create(
              me: bob.id, sealKey: bob.sealKey, pqKey: alice.pqKey)
        ),
        (
          'an ML-DSA key for a classical code',
          () => ConnectInviterV3.create(
              me: classical.id,
              sealKey: classical.sealKey,
              pqKey: alice.pqKey)
        ),
        (
          'a sealing key FIPS 203 refuses',
          () => ConnectInviterV3.create(
              me: bob.id, sealKey: notAKey, pqKey: bob.pqKey)
        ),
        (
          'an acceptor with no ML-DSA key',
          () async => ConnectAcceptorV3.reply(
              await (await ConnectInviterV3.create(
                      me: alice.id,
                      sealKey: alice.sealKey,
                      pqKey: alice.pqKey,
                      code: code))
                  .commit(),
              me: bob.id,
              code: code,
              sealKey: bob.sealKey)
        ),
      ]) {
        await expectLater(start(), throwsArgumentError, reason: what);
      }
      expect(
          () => ConnectRunV3.accept(
              me: bob.id, sealKey: notAKey, pqKey: bob.pqKey, code: code),
          throwsArgumentError);

      // The KEM members of messages 1 and 2: their width, and a key FIPS 203
      // accepts.
      final i2 = await ConnectInviterV3.create(
          me: alice.id, sealKey: alice.sealKey, pqKey: alice.pqKey, code: code);
      final x1 = await i2.commit();
      for (final bad in [
        b64(Uint8List(1183)),
        b64(Uint8List(1185)),
        b64(notAKey),
        'not base64!!',
      ]) {
        await expectLater(
            ConnectAcceptorV3.reply({...x1, 'ek': bad},
                me: bob.id,
                code: code,
                sealKey: bob.sealKey,
                pqKey: bob.pqKey),
            throwsA(isA<ConnectAbort>()),
            reason: 'ek = ${bad.length} characters');
      }
      final (goodX2, a2) = await ConnectAcceptorV3.reply(x1,
          me: bob.id, code: code, sealKey: bob.sealKey, pqKey: bob.pqKey);
      for (final bad in [b64(Uint8List(1087)), b64(Uint8List(1089)), null]) {
        await expectLater(i2.open({...goodX2, 'ct': bad}),
            throwsA(isA<ConnectAbort>()));
        expect(i2.opened, isFalse,
            reason: 'nothing of a refused reply is kept');
      }

      // An ephemeral of small order, on either side.
      final zero = Uint8List(32);
      await expectLater(
          i2.open({...goodX2, 'ephx': b64(zero)}),
          throwsA(isA<ConnectAbort>().having(
              (e) => e.message, 'message', contains('small order'))));
      expect(i2.opened, isFalse);
      final x3b = await i2.open(goodX2);
      await expectLater(
          a2.accept({...x3b, 'ephx': b64(zero)}),
          throwsA(isA<ConnectAbort>().having(
              (e) => e.message, 'message', contains('small order'))));
    });
  });

  group('CONNECT v3 over the relay', tags: ['integration'], () {
    late Process relay;
    late HttpServer tap;
    late String url;
    final seen = <Map<String, Object?>>[];
    final raw = <String>[];
    QuantumRelayInTheMiddle? mitm;

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
      var up = false;
      for (var i = 0; i < 50 && !up; i++) {
        try {
          final res = await (await HttpClient()
                  .getUrl(Uri.parse('http://127.0.0.1:$port/health')))
              .close();
          await res.drain<void>();
          up = res.statusCode == 200;
        } catch (_) {
          await Future<void>.delayed(const Duration(milliseconds: 100));
        }
      }
      if (!up) fail('relay did not start');

      // A recording tap in front of the relay, which can also stand in for
      // a relay in the middle (criterion 11). It passes the Host header
      // through, as a front does, so authentication binds as it would.
      tap = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      tap.listen((req) async {
        WebSocket down;
        try {
          down = await WebSocketTransformer.upgrade(req);
        } catch (_) {
          req.response.statusCode = HttpStatus.badRequest;
          await req.response.close();
          return;
        }
        final upstream = await WebSocket.connect('ws://127.0.0.1:$port',
            headers: {'host': req.headers.value('host') ?? ''});
        void note(dynamic d) {
          if (d is! String) return;
          raw.add(d);
          try {
            final j = jsonDecode(d);
            if (j is Map) seen.add(j.cast<String, Object?>());
          } catch (_) {}
        }

        var inOrder = Future<void>.value();
        down.listen((d) {
          inOrder = inOrder.then((_) async {
            note(d);
            final m = mitm;
            Map<String, Object?>? f;
            try {
              final j = jsonDecode(d as String);
              if (j is Map) f = j.cast<String, Object?>();
            } catch (_) {}
            final payload = f?['payload'];
            if (m != null &&
                f != null &&
                f['t'] == 'send' &&
                '${f['id']}'.startsWith('z-connect-c') &&
                payload is String) {
              upstream
                  .add(jsonEncode({...f, 'payload': await m.rewrite(payload)}));
            } else {
              upstream.add(d);
            }
          });
        },
            onDone: () => inOrder = inOrder.then((_) => upstream.close()),
            onError: (_) => inOrder = inOrder.then((_) => upstream.close()));
        upstream.listen((d) {
          note(d);
          down.add(d);
        }, onDone: () => down.close(), onError: (_) => down.close());
      });
      url = 'ws://127.0.0.1:${tap.port}';
    });

    tearDownAll(() async {
      await tap.close(force: true);
      relay.kill();
    });

    setUp(() {
      seen.clear();
      raw.clear();
      mitm = null;
    });

    const p = Duration(milliseconds: 500);

    Future<ConnectRunV3> reopen(ConnectRunV3 r) async => ConnectRunV3.fromJson(
        jsonDecode(jsonEncode(r.toJson())) as Map<String, Object?>);

    int sends(String id) =>
        seen.where((f) => f['t'] == 'send' && f['id'] == id).length;

    String sent(String id) => seen
        .where((f) => f['t'] == 'send' && f['id'] == id)
        .single['payload'] as String;

    /// Everything left in one of [code]'s mailboxes, read without
    /// acknowledging it. A marker is posted behind whatever the mailbox
    /// holds, and the mailbox is read until the marker arrives: the relay
    /// flushes a mailbox in the order it was filled, so by then everything
    /// queued before it has arrived too. Only the marker is acknowledged.
    Future<List<RelayInbound>> peek(ConnectCode code, String role) async {
      final who = await mailboxIdentity(code, role);
      final marker = 'z-peek-${b64url(randomBytes(9))}';
      final poster = await RelayClient.connect(url, await ZIdentity.generate());
      await poster.send(to: await who.routingId(), id: marker, payload: '{}');
      await poster.close();
      final c = await RelayClient.connect(url, who);
      final got = <RelayInbound>[];
      final sub = c.messages.listen(got.add);
      try {
        await waitUntil(() => got.any((e) => e.id == marker),
            what: 'the marker posted behind what mailbox $role holds');
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

    test('10. through a real relay, resumed after every step, both screens '
        'agree', () async {
      // Two-word names on purpose: a space cannot occur inside base64, so
      // the sweep of the wire below cannot fail by coincidence.
      final alice = await person('Alice Quartermain', sk: true);
      final bob = await person('Bob Wickersham');

      Future<(ConnectRunV3, ConnectRunV3, Map<String, int>)> through(
          bool group) async {
        seen.clear();
        var inv = await reopen(await ConnectRunV3.invite(
            me: alice.id,
            sealKey: alice.sealKey,
            pqKey: alice.pqKey,
            group: group));
        final code = ConnectCode.parseV3(inv.code.text);
        var acc = await reopen(ConnectRunV3.accept(
            me: bob.id,
            sealKey: bob.sealKey,
            pqKey: bob.pqKey,
            code: code,
            groupAware: true));
        for (final (side, want) in [
          ('i', ConnectProgress.waiting),
          ('r', ConnectProgress.waiting),
          ('i', ConnectProgress.waiting),
          ('r', ConnectProgress.confirm),
          ('i', ConnectProgress.confirm),
        ]) {
          if (side == 'i') {
            expect(await inv.step(relayUrl: url, poll: p), want);
            inv = await reopen(inv);
          } else {
            expect(await acc.step(relayUrl: url, poll: p), want);
            acc = await reopen(acc);
          }
        }
        for (final id in const [
          'z-connect-c1',
          'z-connect-c2',
          'z-connect-c3',
          'z-connect-c4'
        ]) {
          expect(sends(id), 1, reason: '$id posted once');
        }
        return (
          inv,
          acc,
          {
            for (final (n, id) in [
              ('x1', 'z-connect-c1'),
              ('x2', 'z-connect-c2'),
              ('x3', 'z-connect-c3'),
              ('x4', 'z-connect-c4')
            ])
              n: sent(id).length
          }
        );
      }

      final (inv, acc, sizes) = await through(false);
      expect(inv.session!.sas, acc.session!.sas);
      expect(b64(inv.session!.channelKey), b64(acc.session!.channelKey));
      expect(inv.session!.peer.displayName, 'Bob Wickersham');
      expect(acc.session!.peer.displayName, 'Alice Quartermain');
      expect(b64(inv.session!.peerPqKey!), b64(bob.pqKey!));
      expect(b64(acc.session!.peerSealKey), b64(alice.sealKey));
      expect(inv.code.version, 3);
      // The finished ceremony leaves nothing in relay RAM to replay.
      for (final role in const ['i', 'r']) {
        final left = await peek(inv.code, role);
        expect(left.where((e) => e.id.startsWith('z-connect-c')), isEmpty,
            reason: 'mailbox $role was left empty');
      }
      // And the reveals crossed the relay sealed: no code, key or name.
      final wire = raw.join('\n');
      for (final needle in [
        alice.id.contactCode,
        bob.id.contactCode,
        b64(alice.pqKey!),
        b64(bob.sealKey),
        'Alice Quartermain',
        'Bob Wickersham',
      ]) {
        expect(wire.contains(needle), isFalse);
      }

      final (_, accSet, sizesSet) = await through(true);
      expect(accSet.session!.group, isTrue);
      expect(sizesSet['x3'], sizes['x3'],
          reason: 'message 3 is one length with the bit set and clear');
      print('CONNECT v3 frames at the relay, payload bytes: $sizes '
          '(group bit set: $sizesSet)');
    }, timeout: const Timeout(Duration(minutes: 3)));

    test('11. a relay in the middle without the invite completes neither leg',
        () async {
      final alice = await person('Alice');
      final bob = await person('Bob');
      final middle = QuantumRelayInTheMiddle();
      mitm = middle;

      final inv = await ConnectRunV3.invite(
          me: alice.id, sealKey: alice.sealKey, pqKey: alice.pqKey);
      final acc = ConnectRunV3.accept(
          me: bob.id, sealKey: bob.sealKey, pqKey: bob.pqKey, code: inv.code);
      final progress = <ConnectProgress>[];
      for (var n = 0; n < 3; n++) {
        progress.add(await inv.step(relayUrl: url, poll: p));
        progress.add(await acc.step(relayUrl: url, poll: p));
      }
      expect(middle.replaced, containsAll(['x1', 'x2', 'x3']),
          reason: 'the relay rewrote what it carried');
      expect(acc.session, isNull);
      expect(acc.abortReason, isNotNull,
          reason: 'the acceptor stopped at the reveal it could not open');
      expect(acc.finished, isTrue, reason: 'and the invite is spent');
      expect(inv.session, isNull);
      expect(sends('z-connect-c4'), 0,
          reason: 'the acceptor revealed itself to nobody');
      expect(middle.readFromInviter, isNull,
          reason: "no key the relay can derive opens the inviter's reveal");
      print('a relay in the middle without the invite: $progress');
    }, timeout: const Timeout(Duration(minutes: 2)));

    test('12. a frame of one version on the other\'s mailbox transacts '
        'nothing', () async {
      final alice = await person('Alice');
      final bob = await person('Bob');
      final secret = randomBytes(10);

      // A version-3 inviter and a version-2 acceptor holding the same ten
      // bytes, and the reverse: none of them ever sees a frame.
      final v3inv = await ConnectRunV3.invite(
          me: alice.id,
          sealKey: alice.sealKey,
          pqKey: alice.pqKey,
          code: ConnectCode(secret, version: 3));
      final v2acc =
          ConnectRun.accept(me: bob.id, code: ConnectCode(secret, version: 2));
      final secret2 = randomBytes(10);
      final v2inv = await ConnectRun.invite(
          me: alice.id, code: ConnectCode(secret2, version: 2));
      final v3acc = ConnectRunV3.accept(
          me: bob.id,
          sealKey: bob.sealKey,
          pqKey: bob.pqKey,
          code: ConnectCode(secret2, version: 3));
      for (var n = 0; n < 2; n++) {
        expect(await v3inv.step(relayUrl: url, poll: p),
            ConnectProgress.waiting);
        expect(await v2acc.step(relayUrl: url, poll: p),
            ConnectProgress.waiting);
        expect(await v2inv.step(relayUrl: url, poll: p),
            ConnectProgress.waiting);
        expect(await v3acc.step(relayUrl: url, poll: p),
            ConnectProgress.waiting);
      }
      expect(sends('z-connect-c2'), 0, reason: 'no acceptor answered');

      // A version-2 message 1 posted into a version-3 acceptor's mailbox by
      // someone holding the code: the run stops there, posting nothing.
      final code = ConnectCode.generate(version: 3);
      final acc = ConnectRunV3.accept(
          me: bob.id, sealKey: bob.sealKey, pqKey: bob.pqKey, code: code);
      final impostor =
          await RelayClient.connect(url, await mailboxIdentity(code, 'i'));
      final v2 = await ConnectInviter.create(
          me: alice.id, code: ConnectCode(code.secret, version: 2));
      await impostor.send(
          to: await (await mailboxIdentity(code, 'r')).routingId(),
          id: 'z-connect-c1',
          payload: jsonEncode({'k': 'x1', ...await v2.commit()}));
      await impostor.close();
      seen.clear();
      expect(await acc.step(relayUrl: url, poll: p), ConnectProgress.aborted);
      expect(acc.finished, isTrue);
      expect(sends('z-connect-c2'), 0);
    }, timeout: const Timeout(Duration(minutes: 2)));
  });
}

/// A relay in the middle of a version-3 ceremony that holds every classical
/// key — it brings ephemerals of its own, so every X25519 output is its — and
/// ML-KEM keys of its own, but not the invite, which travels in a link the
/// relay never carries. It swaps the KEM in every frame and derives every key
/// it can: the channel key without the invite key, as the earlier versions
/// salt it. Written from the primitives, sharing no code with the library.
class QuantumRelayInTheMiddle {
  final _x = X25519();
  final _aead = Chacha20.poly1305Aead();
  final Uint8List _kemSeed = randomBytes(64);
  late final Uint8List _kemEk = pqKeyPairFromSeed(_kemSeed).$1;
  Uint8List? _inviterEk, _kAcceptor, _kInviter;
  SimpleKeyPair? _towardInviter, _towardAcceptor;
  Uint8List? _acceptorEph;

  /// What it read of the inviter's reveal, if anything opened it.
  Map<String, Object?>? readFromInviter;

  /// The frames it replaced, by kind.
  final List<String> replaced = [];

  Future<Uint8List> _pub(SimpleKeyPair k) async =>
      Uint8List.fromList((await k.extractPublicKey()).bytes);

  Future<Uint8List> _dh(SimpleKeyPair mine, Uint8List theirs) async =>
      Uint8List.fromList(await (await _x.sharedSecretKey(
              keyPair: mine,
              remotePublicKey:
                  SimplePublicKey(theirs, type: KeyPairType.x25519)))
          .extractBytes());

  /// Every channel key it can make from what it holds.
  Future<List<Uint8List>> _keys(Uint8List dh, Uint8List k) async => [
        for (final (ikm, salt) in [
          ([...dh, ...k], Uint8List(32)),
          ([...dh, ...k], Uint8List(0)),
          (dh, Uint8List(32)),
        ])
          for (final info in [
            'z-connect-channel-v3',
            'z-connect-channel-v2',
            'z-connect-channel-v1'
          ])
            await hkdf(ikm, salt, utf8.encode(info), 32)
      ];

  Future<String> rewrite(String payload) async {
    final j = (jsonDecode(payload) as Map).cast<String, Object?>();
    switch (j['k']) {
      case 'x1':
        _inviterEk = base64Decode(j['ek'] as String);
        replaced.add('x1');
        return jsonEncode({...j, 'ek': base64Encode(_kemEk)});
      case 'x2':
        _acceptorEph = base64Decode(j['ephx'] as String);
        _kAcceptor = pqDecapsulate(_kemSeed, base64Decode(j['ct'] as String));
        final (ct, k) = pqEncapsulate(_inviterEk!);
        _kInviter = k;
        _towardInviter ??= await _x.newKeyPair();
        replaced.add('x2');
        return jsonEncode({
          ...j,
          'ephx': base64Encode(await _pub(_towardInviter!)),
          'ct': base64Encode(ct),
        });
      case 'x3':
        final dh = await _dh(
            _towardInviter!, base64Decode(j['ephx'] as String));
        for (final key in await _keys(dh, _kInviter!)) {
          readFromInviter ??= await _open(key, j['blob'] as String);
        }
        _towardAcceptor ??= await _x.newKeyPair();
        final toAcceptor = await _keys(
            await _dh(_towardAcceptor!, _acceptorEph!), _kAcceptor!);
        replaced.add('x3');
        return jsonEncode({
          'k': 'x3',
          'ephx': base64Encode(await _pub(_towardAcceptor!)),
          'blob': await _seal(toAcceptor.first,
              readFromInviter ?? {'code': 'zc1.', 'name': 'Alice'}),
        });
    }
    replaced.add('${j['k']}');
    return payload;
  }

  Future<Map<String, Object?>?> _open(Uint8List key, String blob) async {
    try {
      final clear = await _aead.decrypt(
          SecretBox.fromConcatenation(base64Decode(blob),
              nonceLength: 12, macLength: 16),
          secretKey: SecretKey(key));
      return (jsonDecode(utf8.decode(clear)) as Map).cast<String, Object?>();
    } catch (_) {
      return null;
    }
  }

  Future<String> _seal(Uint8List key, Map<String, Object?> m) async {
    final box = await _aead.encrypt(utf8.encode(jsonEncode(m)),
        secretKey: SecretKey(key), nonce: _aead.newNonce());
    return base64Encode(box.concatenation());
  }
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

// --- §20.9 from the text alone ---------------------------------------------

Future<Uint8List> hkdf(
    List<int> ikm, List<int> salt, List<int> info, int n) async {
  final k = await Hkdf(hmac: Hmac.sha256(), outputLength: n)
      .deriveKey(secretKey: SecretKey(ikm), nonce: salt, info: info);
  return Uint8List.fromList(await k.extractBytes());
}

Future<Uint8List> hmac(List<int> key, List<int> data) async =>
    Uint8List.fromList(
        (await Hmac.sha256().calculateMac(data, secretKey: SecretKey(key)))
            .bytes);

Future<Uint8List> sha256(List<int> data) async =>
    Uint8List.fromList((await Sha256().hash(data)).bytes);

Future<Uint8List> x25519(Uint8List seed, Uint8List peer) async {
  final x = X25519();
  final s = await x.sharedSecretKey(
      keyPair: await x.newKeyPairFromSeed(seed),
      remotePublicKey: SimplePublicKey(peer, type: KeyPairType.x25519));
  return Uint8List.fromList(await s.extractBytes());
}

/// `u16be(len(code)) || code || name`: the end of every commitment.
List<int> committedTail(ConnectIdentity id) {
  final code = utf8.encode(id.contactCode);
  return [
    (code.length >> 8) & 0xff,
    code.length & 0xff,
    ...code,
    ...utf8.encode(id.displayName ?? ''),
  ];
}

/// `HMAC(inviteKey3, "z-connect-commit-v3:" || eph || SHA-256(kem) ||
/// u16be(len(code)) || code || name)`.
Future<Uint8List> commitV3(Uint8List ik3, Uint8List eph, Uint8List kemValue,
        ConnectIdentity id) async =>
    hmac(ik3, [
      ...utf8.encode('z-connect-commit-v3:'),
      ...eph,
      ...await sha256(kemValue),
      ...committedTail(id),
    ]);

String digits(List<int> okm) {
  var n = 0;
  for (var i = 0; i < 7; i++) {
    n = (n << 8) | okm[i];
  }
  final d = (n % 100000000).toString().padLeft(8, '0');
  return '${d.substring(0, 4)} ${d.substring(4)}';
}

bool _aFirst(ConnectIdentity a, ConnectIdentity b) {
  for (var i = 0; i < 32; i++) {
    if (a.accountEdPub[i] != b.accountEdPub[i]) {
      return a.accountEdPub[i] < b.accountEdPub[i];
    }
  }
  return false;
}

/// §20.4's digits under §20.9: over `dh || K`, the ephemerals in canonical
/// order, both identities and SHA-256(ek || ct).
Future<String> sasV3(Uint8List dh, Uint8List k, ConnectIdentity a,
    Uint8List ephA, ConnectIdentity b, Uint8List ephB, Uint8List ek,
    Uint8List ct) async {
  final f = _aFirst(a, b);
  final lo = f ? a : b, hi = f ? b : a;
  return digits(await hkdf(
      [...dh, ...k],
      [...(f ? ephA : ephB), ...(f ? ephB : ephA)],
      [
        ...utf8.encode('z-connect-sas-v3'),
        ...lo.accountEdPub,
        ...lo.pqCommit,
        ...hi.accountEdPub,
        ...hi.pqCommit,
        ...await sha256([...ek, ...ct]),
      ],
      8));
}

/// Version 2's digits from the same inputs.
Future<String> sasV2(Uint8List dh, ConnectIdentity a, Uint8List ephA,
    ConnectIdentity b, Uint8List ephB) async {
  final f = _aFirst(a, b);
  final lo = f ? a : b, hi = f ? b : a;
  return digits(await hkdf(
      dh,
      [...(f ? ephA : ephB), ...(f ? ephB : ephA)],
      [
        ...utf8.encode('z-connect-sas-v2'),
        ...lo.accountEdPub,
        ...lo.pqCommit,
        ...hi.accountEdPub,
        ...hi.pqCommit,
      ],
      8));
}

Future<Map<String, Object?>> openBlob(Uint8List key, String blob) async {
  final clear = await Chacha20.poly1305Aead().decrypt(
      SecretBox.fromConcatenation(unb64(blob), nonceLength: 12, macLength: 16),
      secretKey: SecretKey(key));
  return (jsonDecode(utf8.decode(clear)) as Map).cast<String, Object?>();
}

Future<bool> opensBlob(Uint8List key, String blob) async {
  try {
    await openBlob(key, blob);
    return true;
  } catch (_) {
    return false;
  }
}

Future<String> sealBlob(Uint8List key, Map<String, Object?> m) async {
  final box = await Chacha20.poly1305Aead().encrypt(utf8.encode(jsonEncode(m)),
      secretKey: SecretKey(key), nonce: randomBytes(12));
  return b64(box.concatenation());
}

// --- the parsers of earlier builds, verbatim but for their names ----------

/// `ConnectCode.parse` as every build before ADR 0024 ships it, verbatim but
/// for its name: what an old client does with whatever it is handed.
ConnectCode _parseBefore0024(String code) {
  for (final ch in code.toUpperCase().codeUnits) {
    const separators = [0x2D, 0x20, 0x09, 0x0A, 0x0D]; // - space tab nl cr
    if (separators.contains(ch)) continue;
    if (!'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.codeUnits.contains(ch)) {
      throw const FormatException('not a connect code');
    }
  }
  final b = base32Decode(code);
  if (b.length < 10) throw const FormatException('connect code too short');
  return ConnectCode(Uint8List.fromList(b.sublist(0, 10)));
}

/// `ConnectCode.fromLink` as every build before ADR 0024 ships it.
ConnectCode? _fromLinkBefore0024(String url) {
  final hash = url.indexOf('#');
  if (hash < 0 || hash == url.length - 1) return null;
  final before = url.substring(0, hash);
  if (!before.contains('/i')) return null;
  try {
    return _parseBefore0024(url.substring(hash + 1));
  } on FormatException {
    return null;
  }
}

/// The base32 alphabet `ConnectCode.parse` reads, which the library keeps
/// private.
final Set<int> _b32CharsBefore0032 =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.codeUnits.toSet();

/// `ConnectCode.parse` as Release 4.3.2 ships it — every build from ADR 0024
/// to ADR 0032 — verbatim but for its name and the alphabet above.
ConnectCode _parseBefore0032(String code) {
  const separators = [0x2D, 0x20, 0x09, 0x0A, 0x0D]; // - space tab nl cr
  final chars = <int>[
    for (final ch in code.toUpperCase().codeUnits)
      if (!separators.contains(ch)) ch
  ];
  if (chars.isNotEmpty && chars.first == connectV2Marker.codeUnitAt(0)) {
    final rest = chars.sublist(1);
    if (rest.length != 16 || !rest.every(_b32CharsBefore0032.contains)) {
      throw const FormatException('not a connect code');
    }
    return ConnectCode(base32Decode(String.fromCharCodes(rest)), version: 2);
  }
  for (final ch in chars) {
    if (!_b32CharsBefore0032.contains(ch)) {
      throw const FormatException('not a connect code');
    }
  }
  final b = base32Decode(code);
  if (b.length < 10) throw const FormatException('connect code too short');
  return ConnectCode(Uint8List.fromList(b.sublist(0, 10)));
}

/// `ConnectCode.fromLink` as Release 4.3.2 ships it, verbatim but for its
/// name: any `/i` before the `#` makes the part after it an invite's.
ConnectCode? _fromLinkBefore0032(String url) {
  final hash = url.indexOf('#');
  if (hash < 0 || hash == url.length - 1) return null;
  final before = url.substring(0, hash);
  if (!before.contains('/i')) return null;
  try {
    return _parseBefore0032(url.substring(hash + 1));
  } on FormatException {
    return null;
  }
}
