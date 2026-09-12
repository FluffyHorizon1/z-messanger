import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

// 17.1 — the connect ceremony: adding a contact you cannot stand next to.
//
// In person, adding someone is a QR code and the QR IS the verification: the
// channel is your eyes. The remote path was "copy your code, send it over a
// channel you trust, they paste it" — one-directional, hands out a permanent
// identifier, ends unverified, and rests on advice ("a channel you trust")
// that the people who need it most do not have.
//
// This ceremony is the device-pairing shape pointed at a different payload,
// with three differences, all because the code travels over a channel that may
// be hostile rather than between two screens one person holds: both sides
// commit before either reveals, the confirmation string is bound to the
// IDENTITIES being exchanged rather than only to the channel, and one ceremony
// adds both people.
//
// Criteria, each asserted below:
//  1. a completed exchange derives an identical confirmation string, and an
//     identical channel key, on both sides;
//  2. a reveal that does not match its commitment is REFUSED and the ceremony
//     aborts — on either side, for any field, rather than continuing at
//     reduced assurance;
//  3. neither side can derive the string before the other has revealed, and
//     the ordering is enforced by the code rather than by convention;
//  4. the string changes when either account key or either post-quantum
//     commitment changes, and is invariant to which side invited;
//  5. a machine-in-the-middle running both legs, holding the code, gets
//     DIFFERENT strings on the two sides — one blind guess, not a search;
//  6. a connect code never derives a pairing rendezvous, and vice versa;
//  7. the exchange carries a contact code in both directions, so one ceremony
//     adds both people, and each side ends holding something its existing
//     scan path accepts.
void main() {
  /// A v3 contact code for a fresh identity — what the app puts in a QR.
  Future<ConnectIdentity> person(String name) async {
    final edSeed = randomBytes(32);
    final id = await ZIdentity.fromSeeds(edSeed: edSeed, xSeed: randomBytes(32));
    final pq = await HybridKeyPair.fromSeeds(
        edSeed: edSeed, mlSeed: randomBytes(32));
    final code =
        await ContactBundleV3.forIdentity(id, pq.publicKey, displayName: name);
    return ConnectIdentity.fromCode(code.encode(), displayName: name);
  }

  /// The same identity as a CLASSICAL code, with no post-quantum commitment.
  Future<ConnectIdentity> classicalOf(ConnectIdentity v3) async {
    final b = await ContactBundleV3.decode(v3.contactCode);
    return ConnectIdentity.fromCode(b.classical.encode(),
        displayName: v3.displayName);
  }

  group('connect ceremony', () {
    test('1. both sides derive the same string and the same channel',
        () async {
      final alice = await person('Alice');
      final bob = await person('Bob');

      final inviter = await ConnectInviter.create(me: alice);
      final (reply, acceptor) =
          await ConnectAcceptor.reply(await inviter.commit(), me: bob);
      final open = await inviter.open(reply);
      final (revealB, sessionB) = await acceptor.accept(open);
      final sessionA = await inviter.complete(revealB);

      expect(sessionA.sas, sessionB.sas);
      expect(sessionA.sas, matches(RegExp(r'^\d{4} \d{4}$')));
      expect(b64(sessionA.channelKey), b64(sessionB.channelKey));
    });

    test('2. a reveal that does not match its commitment is refused',
        () async {
      final alice = await person('Alice');
      final bob = await person('Bob');

      // Whoever carries the traffic rewrites the INVITER's commitment. The
      // acceptor's check is what catches it, and it aborts rather than
      // continuing with an identity nobody promised.
      final inviter = await ConnectInviter.create(me: alice);
      final commit = await inviter.commit();
      final (_, acceptorA) = await ConnectAcceptor.reply(
          {'c': b64(Uint8List(32))},
          me: bob);
      final (replyHonest, acceptorB) =
          await ConnectAcceptor.reply(commit, me: bob);
      await expectLater(acceptorA.accept(await inviter.open(replyHonest)),
          throwsA(isA<ConnectAbort>()),
          reason: 'a rewritten commitment must abort');
      // The honest pair still completes: nothing was left broken.
      final (revealB, _) = await acceptorB.accept(await inviter.open(replyHonest));
      expect((await inviter.complete(revealB)).peer.displayName, 'Bob');

      // And the other direction: the ACCEPTOR's commitment rewritten, caught
      // by the inviter when the reveal arrives.
      final inviter2 = await ConnectInviter.create(me: alice);
      final (reply2, acceptor2) =
          await ConnectAcceptor.reply(await inviter2.commit(), me: bob);
      final tampered = {...reply2, 'c': b64(Uint8List(32))};
      final (reveal2, _) = await acceptor2.accept(await inviter2.open(tampered));
      await expectLater(
          inviter2.complete(reveal2), throwsA(isA<ConnectAbort>()),
          reason: 'a rewritten commitment must abort here too');

      // A rewritten ephemeral in the opening is refused as well — the
      // commitment covers it, and the channel it would derive is not the one
      // the acceptor holds.
      final inviter3 = await ConnectInviter.create(me: alice);
      final (reply3, acceptor3) =
          await ConnectAcceptor.reply(await inviter3.commit(), me: bob);
      final open3 = await inviter3.open(reply3);
      await expectLater(
          acceptor3.accept({...open3, 'ephx': reply3['ephx']}),
          throwsA(isA<ConnectAbort>()));

      // A malformed frame is an abort, never a crash or a silent pass.
      final inviter4 = await ConnectInviter.create(me: alice);
      await expectLater(ConnectAcceptor.reply({'c': 'not base64!'}, me: bob),
          throwsA(isA<ConnectAbort>()));
      await expectLater(inviter4.open({'ephx': b64(Uint8List(31))}),
          throwsA(isA<ConnectAbort>()));
    });

    test('3. neither side can derive the string before the other reveals',
        () async {
      final alice = await person('Alice');
      final bob = await person('Bob');

      final inviter = await ConnectInviter.create(me: alice);
      final commit = await inviter.commit();
      // Message 1 carries the commitment and nothing else: there is nothing
      // in it to search against a target string.
      expect(commit.keys.toSet(), {'c'});
      expect(unb64(commit['c'] as String).length, 32);

      // Out of order is refused by the code, not by a comment.
      await expectLater(
          inviter.complete({'blob': b64(Uint8List(40))}),
          throwsA(isA<ConnectAbort>()),
          reason: 'complete() before open() has no channel to open a reveal');

      // The acceptor commits to its ephemeral while holding only that hash,
      // so a fresh run moves the string every time and there is nothing to
      // aim at.
      final seen = <String>{};
      for (var i = 0; i < 20; i++) {
        final inv = await ConnectInviter.create(me: alice);
        final (reply, acc) =
            await ConnectAcceptor.reply(await inv.commit(), me: bob);
        final (_, s) = await acc.accept(await inv.open(reply));
        seen.add(s.sas);
      }
      expect(seen.length, greaterThan(15));
    });

    test('4. the string is bound to both identities', () async {
      final alice = await person('Alice');
      final bob = await person('Bob');

      // A different account key on one side: a different string.
      final alice2 = await person('Alice');
      expect(await _run(alice, bob), isNot(await _run(alice2, bob)));

      // The post-quantum commitment is in the input too, so the SAME account
      // key with a classical code must not read as the hybrid identity. It is
      // a different identity to confirm, and saying so is the point of §18.2.
      final classical = await classicalOf(alice);
      expect(b64(classical.accountEdPub), b64(alice.accountEdPub),
          reason: 'same account, two codes');
      expect(b64(classical.pqCommit), b64(Uint8List(32)),
          reason: 'a classical code commits to nothing');
      expect(b64(alice.pqCommit), isNot(b64(Uint8List(32))));
      expect(await _run(classical, bob), isNot(await _run(alice, bob)));

      // Neither side's own key is privileged in the input: the two parties
      // are sorted by account key, which is why both sides of one run agree
      // (criterion 1) without either knowing which of them invited. The
      // recorded `sas_info` in the vectors shows that ordering explicitly —
      // it cannot be asserted here, because running the same pair in the
      // other direction necessarily draws fresh ephemerals.
      expect(await _run(bob, alice), matches(RegExp(r'^\d{4} \d{4}$')));
    });

    test('5. a machine-in-the-middle gets two different strings', () async {
      final alice = await person('Alice');
      final bob = await person('Bob');
      final mallory = await person('Mallory');

      // Mallory holds the code and sits at the rendezvous, running both legs
      // with her own identity and her own ephemerals.
      // Leg 1: Mallory as acceptor towards the real Alice.
      final inviter = await ConnectInviter.create(me: alice);
      final (replyM, mAcceptor) =
          await ConnectAcceptor.reply(await inviter.commit(), me: mallory);
      final openA = await inviter.open(replyM);
      final (revealM, mSessionA) = await mAcceptor.accept(openA);
      final aliceSession = await inviter.complete(revealM);
      expect(aliceSession.sas, mSessionA.sas, reason: 'leg 1 agrees');

      // Leg 2: Mallory as inviter towards the real Bob. She must commit
      // before Bob replies, and she cannot make this leg's string match the
      // first: the string covers Bob's identity, which leg 1 never saw.
      final mInviter = await ConnectInviter.create(me: mallory);
      final (replyB, bAcceptor) =
          await ConnectAcceptor.reply(await mInviter.commit(), me: bob);
      final openM = await mInviter.open(replyB);
      final (revealB, bobSession) = await bAcceptor.accept(openM);
      await mInviter.complete(revealB);

      expect(bobSession.sas, isNot(aliceSession.sas),
          reason: 'the two screens disagree, which is what the users see');
      // And each real party ends up holding MALLORY's identity, not each
      // other's — which is exactly what the mismatch is telling them.
      expect(b64(aliceSession.peer.accountEdPub), b64(mallory.accountEdPub));
      expect(b64(bobSession.peer.accountEdPub), b64(mallory.accountEdPub));
    });

    test('6. a connect code and a pairing code address different rendezvous',
        () async {
      final secret = Uint8List.fromList(List<int>.generate(10, (i) => i * 11));
      final connect = ConnectCode(secret);
      final pairing = PairingCode(secret);
      expect(await connect.rendezvousRoutingId(),
          isNot(await pairing.rendezvousRoutingId()));
      expect(await connect.rendezvousRoutingId(),
          isNot(await pairing.rendezvousRoutingIdV2()));
      // Same rendering, so a person cannot tell them apart by looking — which
      // is why the contexts, not the text, are what keep them separate.
      expect(connect.text, pairing.text);
      expect(ConnectCode.parse(connect.text).secret, secret);

      // The link is the same secret, and the code lives in the fragment.
      final link = connect.link();
      expect(link, startsWith('https://zmessengers.com/i#'));
      expect(link, isNot(contains('?')), reason: 'never a query parameter');
      expect(ConnectCode.fromLink(link)!.secret, secret);
      expect(ConnectCode.fromLink('https://zmessengers.com/i'), isNull);
      expect(ConnectCode.fromLink(connect.text), isNull);
    });

    test('7. one ceremony adds both people', () async {
      final alice = await person('Alice');
      final bob = await person('Bob');

      final inviter = await ConnectInviter.create(me: alice);
      final (reply, acceptor) =
          await ConnectAcceptor.reply(await inviter.commit(), me: bob);
      final (revealB, sessionB) = await acceptor.accept(await inviter.open(reply));
      final sessionA = await inviter.complete(revealB);

      // Each side holds the other's contact code — the same string a QR would
      // have carried, so the existing scan path accepts it unchanged.
      expect(sessionA.peer.displayName, 'Bob');
      expect(sessionB.peer.displayName, 'Alice');
      expect(b64(sessionA.peer.accountEdPub), b64(bob.accountEdPub));
      expect(b64(sessionB.peer.accountEdPub), b64(alice.accountEdPub));
      final decoded = await ContactBundleV3.decode(sessionA.peer.contactCode);
      expect(b64(decoded.accountEdPub), b64(bob.accountEdPub));
      expect(await decoded.classical.verify(), isTrue);
    });
  });
}

/// One whole ceremony, returning the string both sides agreed on.
Future<String> _run(ConnectIdentity a, ConnectIdentity b) async {
  final inviter = await ConnectInviter.create(me: a);
  final (reply, acceptor) =
      await ConnectAcceptor.reply(await inviter.commit(), me: b);
  final (reveal, sessionB) = await acceptor.accept(await inviter.open(reply));
  final sessionA = await inviter.complete(reveal);
  expect(sessionA.sas, sessionB.sas);
  return sessionA.sas;
}
