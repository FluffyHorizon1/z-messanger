import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';
import 'package:z_protocol/src/util.dart' show base32Decode;
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
//     scan path accepts;
//  8. (ADR 0020) message 3 can say that the invite also brings the acceptor
//     into a group — one sealed bit, read by an acceptor that knows it and
//     repeated in message 4 — and the bit set and the bit clear make frames
//     of the same length, while a client from before the bit, on either
//     side, completes the same ceremony ignoring it (§14);
//  9. a bit that is not 0 or 1 is an abort, as a malformed name is; an
//     acceptor that repeats a different bit from the one sent is an abort at
//     the inviter; and the bit is not in the commitment — two inviters that
//     differ only in it commit identically — so its integrity is the AEAD's,
//     under a key only the two ends, or a machine in the middle whom the
//     digits catch, can hold;
// 10. (ADR 0020) the go-ahead tag — HKDF-SHA256 of the channel key, zero
//     salt, info `z-connect-gjoin-v1`, 16 bytes: a key of its own, not the
//     sealing key used as an HMAC key — is the same at both ends of one
//     ceremony and different for every other: a second ceremony between the
//     same two people, and each leg a machine in the middle runs;
// 11. an ephemeral of small order — the zero point among them — is refused
//     on either side (RFC 7748 §6.1): with one, X25519's output is all zeros
//     whatever the other key is, so the channel key, and every tag derived
//     from it, would be a constant anyone can compute.
//
// 1–11 are the ceremony as ADR 0009 built it, version 1, and every invite
// they make is one. An invite of version 2 binds its secret into the
// ceremony (ADR 0024, PROTOCOL §20.8):
// 12. both sides of a version-2 ceremony agree, on exactly the values §20.8
//     defines — the invite key from the secret, the keyed commitments, the
//     channel key salted with the invite key, the digits under their own
//     context — none of which is the version-1 value for the same inputs;
// 13. a machine in the middle WITHOUT the invite — every frame, every
//     value it can compute, an invite of its own — completes neither leg:
//     the acceptor stops at message 3 before revealing itself, the inviter
//     at message 4, and neither reveal opens for it; the same machine
//     holding the invite completes both, with two different strings, which
//     is the bearer token the digits are for (R23);
// 14. a commitment is keyed: the same identity behind the same ephemeral
//     commits differently under two invites, and to neither of them as
//     version 1 would, so a candidate contact code cannot be tested against
//     one without the invite;
// 15. both renderings of a version-2 invite start with its marker and parse
//     back, in either case and with or without separators, as version 2;
//     every one of them is refused by the parser every build before ADR 0024
//     ships; a version-1 invite still parses as version 1; and a malformed
//     version-2 code is refused;
// 16. the versions never meet: the same ten bytes name different mailboxes
//     and a different rendezvous in each, frames of one version abort a
//     ceremony of the other on both sides rather than completing it, and a
//     stored ceremony keeps its version — a record from before ADR 0024
//     reads back as version 1, and an unknown version is refused.
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

      final inviter = await ConnectInviter.create(me: alice, code: _v1());
      final (reply, acceptor) =
          await ConnectAcceptor.reply(await inviter.commit(),
              me: bob, code: inviter.code);
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
      final inviter = await ConnectInviter.create(me: alice, code: _v1());
      final commit = await inviter.commit();
      final (_, acceptorA) = await ConnectAcceptor.reply(
          {'c': b64(Uint8List(32))},
          me: bob,
          code: inviter.code);
      final (replyHonest, acceptorB) =
          await ConnectAcceptor.reply(commit, me: bob, code: inviter.code);
      await expectLater(acceptorA.accept(await inviter.open(replyHonest)),
          throwsA(isA<ConnectAbort>()),
          reason: 'a rewritten commitment must abort');
      // The honest pair still completes: nothing was left broken.
      final (revealB, _) = await acceptorB.accept(await inviter.open(replyHonest));
      expect((await inviter.complete(revealB)).peer.displayName, 'Bob');

      // And the other direction: the ACCEPTOR's commitment rewritten, caught
      // by the inviter when the reveal arrives.
      final inviter2 = await ConnectInviter.create(me: alice, code: _v1());
      final (reply2, acceptor2) =
          await ConnectAcceptor.reply(await inviter2.commit(),
              me: bob, code: inviter2.code);
      final tampered = {...reply2, 'c': b64(Uint8List(32))};
      final (reveal2, _) = await acceptor2.accept(await inviter2.open(tampered));
      await expectLater(
          inviter2.complete(reveal2), throwsA(isA<ConnectAbort>()),
          reason: 'a rewritten commitment must abort here too');

      // A rewritten ephemeral in the opening is refused as well — the
      // commitment covers it, and the channel it would derive is not the one
      // the acceptor holds.
      final inviter3 = await ConnectInviter.create(me: alice, code: _v1());
      final (reply3, acceptor3) =
          await ConnectAcceptor.reply(await inviter3.commit(),
              me: bob, code: inviter3.code);
      final open3 = await inviter3.open(reply3);
      await expectLater(
          acceptor3.accept({...open3, 'ephx': reply3['ephx']}),
          throwsA(isA<ConnectAbort>()));

      // A malformed frame is an abort, never a crash or a silent pass.
      final inviter4 = await ConnectInviter.create(me: alice, code: _v1());
      await expectLater(
          ConnectAcceptor.reply({'c': 'not base64!'},
              me: bob, code: inviter4.code),
          throwsA(isA<ConnectAbort>()));
      await expectLater(inviter4.open({'ephx': b64(Uint8List(31))}),
          throwsA(isA<ConnectAbort>()));
    });

    test('3. neither side can derive the string before the other reveals',
        () async {
      final alice = await person('Alice');
      final bob = await person('Bob');

      final inviter = await ConnectInviter.create(me: alice, code: _v1());
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
        final inv = await ConnectInviter.create(me: alice, code: _v1());
        final (reply, acc) =
            await ConnectAcceptor.reply(await inv.commit(),
                me: bob, code: inv.code);
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
      final inviter = await ConnectInviter.create(me: alice, code: _v1());
      final (replyM, mAcceptor) =
          await ConnectAcceptor.reply(await inviter.commit(),
              me: mallory, code: inviter.code);
      final openA = await inviter.open(replyM);
      final (revealM, mSessionA) = await mAcceptor.accept(openA);
      final aliceSession = await inviter.complete(revealM);
      expect(aliceSession.sas, mSessionA.sas, reason: 'leg 1 agrees');

      // Leg 2: Mallory as inviter towards the real Bob. She must commit
      // before Bob replies, and she cannot make this leg's string match the
      // first: the string covers Bob's identity, which leg 1 never saw.
      final mInviter = await ConnectInviter.create(me: mallory, code: _v1());
      final (replyB, bAcceptor) =
          await ConnectAcceptor.reply(await mInviter.commit(),
              me: bob, code: mInviter.code);
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

    test('a code is base32 and nothing else — a URL is not ten bytes of luck',
        () async {
      // base32Decode skips what it does not recognise, which is right for a
      // code read down a phone line and wrong for deciding whether a string
      // IS one: every URL has enough letters between its punctuation to make
      // ten bytes. The app has a public entry point for these now (any app
      // on the device can send it a VIEW intent), so the separators are
      // named and everything else is a refusal.
      final code = ConnectCode.generate();
      for (final ok in [
        code.text,
        code.text.toLowerCase(),
        code.text.replaceAll('-', ' '),
        code.text.replaceAll('-', ''),
      ]) {
        expect(b64(ConnectCode.parse(ok).secret), b64(code.secret),
            reason: 'people paste what they were sent: "$ok"');
      }
      for (final not in [
        'https://zmessengers.com/',
        'https://example.com/anything/at/all',
        'hello, world!',
        'zc1.notaninvite',
        '',
        'ABCDE', // base32, and far too little of it
      ]) {
        expect(() => ConnectCode.parse(not), throwsFormatException,
            reason: '"$not" is not a connect code');
      }
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
      expect(link, startsWith('https://www.zmessengers.com/i#'));
      expect(link, isNot(contains('?')), reason: 'never a query parameter');
      expect(ConnectCode.fromLink(link)!.secret, secret);
      expect(ConnectCode.fromLink('https://www.zmessengers.com/i'), isNull);
      expect(ConnectCode.fromLink(connect.text), isNull);
    });

    test('7. one ceremony adds both people', () async {
      final alice = await person('Alice');
      final bob = await person('Bob');

      final inviter = await ConnectInviter.create(me: alice, code: _v1());
      final (reply, acceptor) =
          await ConnectAcceptor.reply(await inviter.commit(),
              me: bob, code: inviter.code);
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

    test('8. one sealed bit says a group is attached, at no cost in length',
        () async {
      final alice = await person('Alice');
      final bob = await person('Bob');

      /// A whole ceremony: the inviter's [group] bit (null: a client from
      /// before ADR 0020 writes none) against an acceptor that does or does
      /// not read it. The frames are returned as the relay would carry them.
      Future<({ConnectSession i, ConnectSession a, String x3, String x4})> run(
          bool? group, bool aware) async {
        final inviter = await ConnectInviter.create(
            me: alice, code: _v1(), group: group);
        final (reply, acceptor) = await ConnectAcceptor.reply(
            await inviter.commit(),
            me: bob,
            code: inviter.code,
            groupAware: aware);
        final open = await inviter.open(reply);
        final (reveal, sessionB) = await acceptor.accept(open);
        final sessionA = await inviter.complete(reveal);
        expect(sessionA.sas, sessionB.sas, reason: 'both sides agree');
        return (
          i: sessionA,
          a: sessionB,
          x3: jsonEncode({'k': 'x3', ...open}),
          x4: jsonEncode({'k': 'x4', ...reveal}),
        );
      }

      // Both sides know the bit: set, the acceptor reads it and says so
      // back; clear, both read clear.
      final bitSet = await run(true, true);
      expect(bitSet.a.group, isTrue, reason: 'the acceptor was told: a group');
      expect(bitSet.i.group, isTrue, reason: 'and repeated it to the inviter');
      final bitClear = await run(false, true);
      expect(bitClear.a.group, isFalse);
      expect(bitClear.i.group, isFalse);

      // The bit is inside the seal and nothing new is outside it: message 3
      // is still `k`, `ephx` and `blob`.
      expect((jsonDecode(bitSet.x3) as Map).keys.toSet(), {'k', 'ephx', 'blob'});
      expect((jsonDecode(bitSet.x4) as Map).keys.toSet(), {'k', 'blob'});

      // Connect frames are not padded to a bucket (§20.5): the relay sees
      // each one's exact length. Set and clear are the same length, in both
      // directions, so the length says nothing about a group.
      expect(bitSet.x3.length, bitClear.x3.length,
          reason: 'message 3 with the bit set and clear: one length');
      expect(bitSet.x4.length, bitClear.x4.length,
          reason: 'and message 4, which repeats it');

      // A client from before the bit, on either side, completes the same
      // ceremony, the bit simply ignored — §14's rule for an unknown member,
      // never an abort.
      final oldAcceptor = await run(true, false);
      expect(oldAcceptor.a.group, isNull,
          reason: 'an acceptor that predates the bit never reads it');
      expect(oldAcceptor.i.group, isNull,
          reason: 'and the inviter hears nothing back: so it knows that '
              'client could not have told its person about a group');
      final oldInviter = await run(null, true);
      expect(oldInviter.a.group, isNull,
          reason: 'an inviter that predates the bit attached no group');
      expect(oldInviter.i.group, isNull,
          reason: 'it reads no repetition either');
      final neither = await run(null, false);
      expect(neither.x3.length, lessThan(bitSet.x3.length),
          reason: "the bytes a client before ADR 0020 sends, which "
              "vectors/connect/connect.json pins");

      // The numbers, for PROTOCOL §20.3 and the report: the length of each
      // message as the relay receives it.
      print('connect frames, bytes as the relay sees them:\n'
          '  x3  no bit ${neither.x3.length}  bit clear ${bitClear.x3.length}'
          '  bit set ${bitSet.x3.length}\n'
          '  x4  no bit ${neither.x4.length}  bit clear ${bitClear.x4.length}'
          '  bit set ${bitSet.x4.length}');
    });

    test('9. a malformed or contradicted bit aborts; the commitment omits it',
        () async {
      final alice = await person('Alice');
      final bob = await person('Bob');

      // Message 3 sealed by hand, carrying [extra] beside the identity — what
      // a client that writes nonsense would send.
      Future<Map<String, Object?>> forgedOpen(ConnectInviter inviter,
              ConnectAcceptor acceptor, Map<String, Object?> extra) async =>
          {
            'ephx': b64(inviter.ephPub),
            'blob': await _seal(
                await _channelKey(inviter.ephSeed, acceptor.ephPub),
                {'code': alice.contactCode, 'name': 'Alice', ...extra}),
          };

      for (final bad in <Object?>[2, -1, '1', true, 1.0, <int>[1]]) {
        final inviter = await ConnectInviter.create(
            me: alice, code: _v1(), group: true);
        final (_, aware) = await ConnectAcceptor.reply(await inviter.commit(),
            me: bob, code: inviter.code, groupAware: true);
        await expectLater(
            aware.accept(await forgedOpen(inviter, aware, {'grp': bad})),
            throwsA(isA<ConnectAbort>()),
            reason: 'a group bit of $bad is not 0 or 1');
        // A client that never reads the member is not troubled by it.
        final (_, old) =
            await ConnectAcceptor.reply(await inviter.commit(),
                me: bob, code: inviter.code);
        final (_, s) =
            await old.accept(await forgedOpen(inviter, old, {'grp': bad}));
        expect(s.group, isNull);
      }

      // Message 4 repeating the opposite bit: the two sides disagree about
      // what the ceremony is, so the inviter stops.
      for (final group in [true, false]) {
        final inviter = await ConnectInviter.create(
            me: alice, code: _v1(), group: group);
        final (reply, acceptor) = await ConnectAcceptor.reply(
            await inviter.commit(),
            me: bob,
            code: inviter.code,
            groupAware: true);
        await inviter.open(reply);
        final key = await _channelKey(inviter.ephSeed, acceptor.ephPub);
        final contradicted = {
          'blob': await _seal(key,
              {'code': bob.contactCode, 'name': 'Bob', 'grp': group ? 0 : 1})
        };
        await expectLater(inviter.complete(contradicted),
            throwsA(isA<ConnectAbort>()),
            reason: 'sent $group, read back ${!group}');
      }

      // The commitment covers the code and the name, not the bit: an
      // inviter that differs from another only in the bit commits to the
      // same value, so the acceptor's check passes either way and the bit's
      // integrity is the AEAD's. That is enough, because the only party able
      // to seal under the channel key besides the two ends is a machine in
      // the middle, and criterion 5 is what happens to one of those.
      final withBit = await ConnectInviter.create(
          me: alice, code: _v1(), group: true);
      final withoutBit = await ConnectInviter.fromJson(
          {...withBit.toJson(), 'grp': false});
      expect(await withoutBit.commit(), await withBit.commit());
      final (reply, acceptor) = await ConnectAcceptor.reply(
          await withBit.commit(),
          me: bob,
          code: withBit.code,
          groupAware: true);
      final (_, flipped) = await acceptor.accept(await withoutBit.open(reply));
      expect(flipped.group, isFalse,
          reason: 'the flipped opening passed the commitment check');
    });

    test('10. the go-ahead tag names one ceremony, at both of its ends',
        () async {
      final alice = await person('Alice');
      final bob = await person('Bob');
      final mallory = await person('Mallory');
      Future<(ConnectSession, ConnectSession)> run(
          ConnectIdentity i, ConnectIdentity a) async {
        final inviter = await ConnectInviter.create(
            me: i, code: _v1(), group: true);
        final (reply, acceptor) = await ConnectAcceptor.reply(
            await inviter.commit(),
            me: a,
            code: inviter.code,
            groupAware: true);
        final (reveal, sa) = await acceptor.accept(await inviter.open(reply));
        return (await inviter.complete(reveal), sa);
      }

      final (i1, a1) = await run(alice, bob);
      final t1 = await i1.goAheadTag();
      expect(t1, hasLength(connectGoAheadTagBytes));
      expect(await a1.goAheadTag(), t1, reason: 'both ends of one ceremony');
      // What it is, from the definition alone — and what it is not: the
      // channel key used as an HMAC key, as it was until 2026-10-03.
      final derived = await Hkdf(hmac: Hmac.sha256(), outputLength: 16)
          .deriveKey(
              secretKey: SecretKey(i1.channelKey),
              nonce: Uint8List(32),
              info: utf8.encode('z-connect-gjoin-v1'));
      expect(t1, await derived.extractBytes());
      final keyedWithIt = await Hmac.sha256().calculateMac(
          utf8.encode('z-connect-gjoin-v1'),
          secretKey: SecretKey(i1.channelKey));
      expect(t1, isNot(keyedWithIt.bytes.sublist(0, 16)));

      // The same two people again: another ceremony, another tag.
      final (i2, a2) = await run(alice, bob);
      expect(await i2.goAheadTag(), isNot(t1));
      expect(await a2.goAheadTag(), await i2.goAheadTag());

      // A machine in the middle runs two ceremonies: the tag of one leg is
      // not the tag of the other, so a go-ahead given on the acceptor's leg
      // answers nothing the inviter holds.
      final (aliceLeg, _) = await run(alice, mallory);
      final (_, bobLeg) = await run(mallory, bob);
      expect(await bobLeg.goAheadTag(), isNot(await aliceLeg.goAheadTag()));
    });

    test('11. an ephemeral of small order is refused, on either side',
        () async {
      // The u-coordinates of every point of small order an X25519 key can
      // name, little-endian as on the wire: 0, 1, the two of order 8, and
      // p - 1, p and p + 1, which name points of order 2, 4 and 1 (the list
      // libsodium refuses).
      Uint8List fromHex(String h) => Uint8List.fromList([
            for (var i = 0; i < h.length; i += 2)
              int.parse(h.substring(i, i + 2), radix: 16)
          ]);
      final high = 'ff' * 30;
      final smallOrder = {
        'zero': Uint8List(32),
        'one': fromHex('01${'00' * 31}'),
        'order 8 (a)': fromHex(
            'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800'),
        'order 8 (b)': fromHex(
            '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157'),
        'p - 1': fromHex('ec${high}7f'),
        'p': fromHex('ed${high}7f'),
        'p + 1': fromHex('ee${high}7f'),
      };
      final x = X25519();
      final alice = await person('Alice');
      final bob = await person('Bob');
      for (final MapEntry(key: name, value: point) in smallOrder.entries) {
        // What makes it dangerous: whatever this side's key, all zeros.
        final shared = await x.sharedSecretKey(
            keyPair: await x.newKeyPair(),
            remotePublicKey:
                SimplePublicKey(point, type: KeyPairType.x25519));
        expect(await shared.extractBytes(), everyElement(0), reason: name);

        // At the inviter: message 2 carrying it as the acceptor's ephemeral,
        // with a commitment that matches it — what a machine in the middle
        // would send.
        final inviter = await ConnectInviter.create(
            me: alice, code: _v1(), group: true);
        final (reply, _) = await ConnectAcceptor.reply(await inviter.commit(),
            me: bob, code: inviter.code, groupAware: true);
        await expectLater(
            inviter.open({...reply, 'ephx': b64(point)}),
            throwsA(isA<ConnectAbort>()
                .having((e) => e.message, 'message', contains('small order'))),
            reason: name);
        expect(inviter.opened, isFalse,
            reason: '$name: nothing of a refused reply is kept');
        expect(inviter.toJson().containsKey('peerEph'), isFalse,
            reason: '$name: nor written into the state a resumed run reads');

        // At the acceptor: message 3 carrying it as the inviter's ephemeral.
        final inviter2 = await ConnectInviter.create(
            me: alice, code: _v1(), group: true);
        final (reply2, acceptor) = await ConnectAcceptor.reply(
            await inviter2.commit(),
            me: bob,
            code: inviter2.code,
            groupAware: true);
        final open = await inviter2.open(reply2);
        await expectLater(
            acceptor.accept({...open, 'ephx': b64(point)}),
            throwsA(isA<ConnectAbort>()
                .having((e) => e.message, 'message', contains('small order'))),
            reason: name);
      }

      // An honest ceremony is untouched by the check.
      final inviter = await ConnectInviter.create(me: alice, code: _v1());
      final (reply, acceptor) =
          await ConnectAcceptor.reply(await inviter.commit(),
              me: bob, code: inviter.code);
      final (reveal, sb) = await acceptor.accept(await inviter.open(reply));
      expect((await inviter.complete(reveal)).sas, sb.sas);
    });
  });

  group('invite version 2 (ADR 0024)', () {
    test('12. both sides agree, on the values §20.8 defines', () async {
      final alice = await person('Alice');
      final bob = await person('Bob');
      final code = ConnectCode.generate();
      expect(code.version, 2, reason: 'what the library mints on its own');

      final inviter = await ConnectInviter.create(me: alice, code: code);
      final commit = await inviter.commit();
      final (reply, acceptor) =
          await ConnectAcceptor.reply(commit, me: bob, code: code);
      final open = await inviter.open(reply);
      final (reveal, sessionB) = await acceptor.accept(open);
      final sessionA = await inviter.complete(reveal);
      expect(sessionA.sas, sessionB.sas);
      expect(sessionA.sas, matches(RegExp(r'^\d{4} \d{4}$')));
      expect(b64(sessionA.channelKey), b64(sessionB.channelKey));
      expect(sessionA.peer.displayName, 'Bob');
      expect(sessionB.peer.displayName, 'Alice');
      expect(await sessionA.goAheadTag(), await sessionB.goAheadTag());

      // Every value from §20.8 alone, sharing no code with the library.
      final key = await _inviteKeyOf(code.secret);
      expect(await code.inviteKey(), key);
      expect(unb64(commit['c'] as String),
          await _commitV2(key, inviter.ephPub, alice));
      expect(unb64(reply['c'] as String),
          await _commitV2(key, acceptor.ephPub, bob));
      final dh = await _dh(inviter.ephSeed, acceptor.ephPub);
      expect(sessionA.channelKey,
          await _hkdf(dh, key, 'z-connect-channel-v2', 32));
      expect(
          sessionA.sas,
          await _sasOf(dh, alice, inviter.ephPub, bob, acceptor.ephPub,
              'z-connect-sas-v2'));

      // The frames are the shape and the length version 1's are, so the
      // relay cannot tell the versions apart by what it carries.
      final old = await ConnectInviter.create(me: alice, code: _v1());
      final oldCommit = await old.commit();
      final (oldReply, oldAcceptor) = await ConnectAcceptor.reply(oldCommit,
          me: bob, code: old.code);
      final oldOpen = await old.open(oldReply);
      final (oldReveal, _) = await oldAcceptor.accept(oldOpen);
      for (final (v2, v1) in [
        (commit, oldCommit),
        (reply, oldReply),
        (open, oldOpen),
        (reveal, oldReveal),
      ]) {
        expect(v2.keys.toSet(), v1.keys.toSet());
        expect(jsonEncode(v2).length, jsonEncode(v1).length);
      }

      // And none of them is what version 1 computes from the same inputs.
      expect(sessionA.channelKey,
          isNot(await _channelKey(inviter.ephSeed, acceptor.ephPub)));
      expect(unb64(commit['c'] as String),
          isNot(await _commitV1(inviter.ephPub, alice)));
      expect(
          sessionA.sas,
          isNot(await _sasOf(dh, alice, inviter.ephPub, bob, acceptor.ephPub,
              'z-connect-sas-v1')));
    });

    test('13. without the invite, a machine in the middle completes neither '
        'leg', () async {
      final alice = await person('Alice');
      final bob = await person('Bob');
      final mallory = await person('Mallory');
      final code = ConnectCode.generate();
      // Everything Mallory can compute without the invite: the frames, keys
      // of her own, and an invite of her own to derive with.
      final guess = await _inviteKeyOf(randomBytes(10));
      final x = X25519();
      final mSeed = randomBytes(32);
      final mPub = Uint8List.fromList(
          (await (await x.newKeyPairFromSeed(mSeed)).extractPublicKey())
              .bytes);

      // Leg 1, Mallory as the acceptor toward Alice. Alice cannot check a
      // commitment before its reveal, so she opens: message 3 goes out.
      final inviter = await ConnectInviter.create(me: alice, code: code);
      final openA = await inviter.open({
        'ephx': b64(mPub),
        'c': b64(await _commitV1(mPub, mallory)),
      });
      final dhA = await _dh(mSeed, unb64(openA['ephx'] as String));
      // Alice's reveal is sealed, and nothing Mallory can derive opens it:
      // not the version-1 key, not one from an invite of her own.
      for (final k in [
        await _channelKey(mSeed, unb64(openA['ephx'] as String)),
        await _hkdf(dhA, guess, 'z-connect-channel-v2', 32),
      ]) {
        expect(await _opens(k, openA['blob'] as String), isFalse);
      }
      // Only the invite does — the control that shows the reveal is there.
      expect(
          await _opens(
              await _hkdf(dhA, await _inviteKeyOf(code.secret),
                  'z-connect-channel-v2', 32),
              openA['blob'] as String),
          isTrue);
      // And whatever message 4 she seals under a key she can derive, Alice
      // refuses it: no session, no peer.
      for (final k in [
        await _channelKey(mSeed, unb64(openA['ephx'] as String)),
        await _hkdf(dhA, guess, 'z-connect-channel-v2', 32),
      ]) {
        await expectLater(
            inviter.complete({
              'blob':
                  await _seal(k, {'code': mallory.contactCode, 'name': 'Bob'})
            }),
            throwsA(isA<ConnectAbort>()));
      }

      // Leg 2, Mallory as the inviter toward Bob, committing and sealing as
      // version 1 does — the only way that needs no invite.
      final commitM = b64(await _commitV1(mPub, mallory));
      final (replyB, bAcceptor) = await ConnectAcceptor.reply({'c': commitM},
          me: bob, code: code);
      final bEph = unb64(replyB['ephx'] as String);
      for (final k in [
        await _channelKey(mSeed, bEph),
        await _hkdf(await _dh(mSeed, bEph), guess, 'z-connect-channel-v2', 32),
      ]) {
        await expectLater(
            bAcceptor.accept({
              'ephx': b64(mPub),
              'blob':
                  await _seal(k, {'code': mallory.contactCode, 'name': 'Alice'})
            }),
            throwsA(isA<ConnectAbort>()),
            reason: 'Bob stops at message 3, and never reveals himself');
      }

      // The same machine HOLDING the invite completes both legs — that is
      // the bearer token (R23) — and the two screens disagree.
      final i2 = await ConnectInviter.create(me: alice, code: code);
      final (r1, m1) = await ConnectAcceptor.reply(await i2.commit(),
          me: mallory, code: code);
      final (x4, mLeg1) = await m1.accept(await i2.open(r1));
      final aliceSees = await i2.complete(x4);
      expect(aliceSees.sas, mLeg1.sas);
      final mInv = await ConnectInviter.create(me: mallory, code: code);
      final (r2, b2) = await ConnectAcceptor.reply(await mInv.commit(),
          me: bob, code: code);
      final (x4b, bobSees) = await b2.accept(await mInv.open(r2));
      await mInv.complete(x4b);
      expect(bobSees.sas, isNot(aliceSees.sas),
          reason: 'the digits are what catch whoever holds the link');
    });

    test('14. a commitment is keyed by the invite', () async {
      final alice = await person('Alice');
      final one = await ConnectInviter.create(me: alice);
      final other = await ConnectInviter.fromJson(
          {...one.toJson(), 'code': b64(randomBytes(10))});
      expect(other.ephPub, one.ephPub, reason: 'the same ephemeral');
      expect(other.code.version, 2);
      final c1 = (await one.commit())['c'], c2 = (await other.commit())['c'];
      expect(c2, isNot(c1), reason: 'another invite, another commitment');
      // A carrier with a candidate contact code, once message 3 has shown
      // the ephemeral, could test it against a version-1 commitment. Here
      // neither the unkeyed form nor a key of its own reproduces either.
      final unkeyed = b64(await _commitV1(one.ephPub, alice));
      final ownKey = b64(await _commitV2(
          await _inviteKeyOf(randomBytes(10)), one.ephPub, alice));
      for (final c in [c1, c2]) {
        expect(c, isNot(unkeyed));
        expect(c, isNot(ownKey));
      }
      // A version-1 invite still commits as it always did.
      final before = await ConnectInviter.fromJson(
          {...one.toJson(), 'code': b64(randomBytes(10))}..remove('cv'));
      expect(before.code.version, 1);
      expect((await before.commit())['c'], unkeyed);
    });

    test('15. a version-2 invite carries its version, and old parsers refuse '
        'it', () async {
      for (var i = 0; i < 200; i++) {
        final code = ConnectCode.generate();
        expect(code.text,
            matches(RegExp(r'^9[A-Z2-7]{4}-[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{2}$')));
        final link = code.link();
        expect(link, startsWith('https://www.zmessengers.com/i#9'));
        for (final r in [
          code.text,
          code.text.toLowerCase(),
          code.text.replaceAll('-', ''),
          code.text.replaceAll('-', ' '),
        ]) {
          final back = ConnectCode.parse(r);
          expect(back.version, 2, reason: r);
          expect(back.secret, code.secret, reason: r);
          expect(() => _parseBefore0024(r), throwsFormatException,
              reason: 'a build before ADR 0024 refuses "$r"');
        }
        final back = ConnectCode.fromLink(link)!;
        expect(back.version, 2);
        expect(back.secret, code.secret);
        expect(_fromLinkBefore0024(link), isNull,
            reason: 'and the link, which it then ignores');
      }

      // A version-1 invite is what it always was, to either parser.
      final old = ConnectCode.generate(version: 1);
      expect(old.text, matches(RegExp(r'^[A-Z2-7-]{19}$')));
      expect(ConnectCode.parse(old.text).version, 1);
      expect(ConnectCode.parse(old.text).secret, old.secret);
      expect(ConnectCode.fromLink(old.link())!.version, 1);
      expect(_parseBefore0024(old.text).secret, old.secret);

      // A version-2 code that is not exactly the marker and sixteen base32
      // characters is not one.
      final good = ConnectCode.generate().text.replaceAll('-', '');
      for (final bad in [
        '9',
        good.substring(0, 16),
        '${good}A',
        '${good.substring(0, 16)}1',
        '9$good',
        '${good.substring(1, 5)}9${good.substring(5)}',
      ]) {
        expect(() => ConnectCode.parse(bad), throwsFormatException,
            reason: '"$bad" is not a connect code');
      }
    });

    test('16. the two versions never meet', () async {
      final alice = await person('Alice');
      final bob = await person('Bob');
      final secret = randomBytes(10);
      final one = ConnectCode(secret), two = ConnectCode(secret, version: 2);
      final ids = <String>{
        for (final c in [one, two]) ...[
          for (final role in ['i', 'r'])
            await (await mailboxIdentity(c, role)).routingId(),
          await c.rendezvousRoutingId(),
        ]
      };
      expect(ids, hasLength(6),
          reason: 'six mailboxes and rendezvous, none shared');

      // An acceptor of one version and an inviter of the other: aborted,
      // whichever way round, before either has the other's identity.
      for (final (iCode, aCode) in [(two, one), (one, two)]) {
        final inviter = await ConnectInviter.create(me: alice, code: iCode);
        final (reply, acceptor) = await ConnectAcceptor.reply(
            await inviter.commit(),
            me: bob,
            code: aCode);
        await expectLater(acceptor.accept(await inviter.open(reply)),
            throwsA(isA<ConnectAbort>()));
      }
      // And an inviter given the other version's message 4 refuses it.
      final inviter = await ConnectInviter.create(me: alice, code: two);
      final (reply, acceptor) = await ConnectAcceptor.reply(
          await inviter.commit(),
          me: bob,
          code: two);
      final (x4, _) = await acceptor.accept(await inviter.open(reply));
      final asOne =
          await ConnectInviter.fromJson(inviter.toJson()..remove('cv'));
      expect(asOne.code.version, 1);
      await expectLater(asOne.complete(x4), throwsA(isA<ConnectAbort>()));

      // A stored ceremony keeps its version; a record from before ADR 0024
      // has none and is version 1; one this build does not know is refused.
      expect(inviter.toJson()['cv'], 2);
      expect((await ConnectInviter.fromJson(inviter.toJson())).code.version, 2);
      final before = await ConnectInviter.create(me: alice, code: one);
      expect(before.toJson().containsKey('cv'), isFalse);
      expect((await ConnectInviter.fromJson(before.toJson())).code.version, 1);
      await expectLater(
          ConnectInviter.fromJson({...inviter.toJson(), 'cv': 3}),
          throwsFormatException);
      final run = await ConnectRun.invite(me: alice);
      expect(run.code.version, 2);
      Future<ConnectRun> reread(ConnectRun r) => ConnectRun.fromJson(
          jsonDecode(jsonEncode(r.toJson())) as Map<String, Object?>);
      expect((await reread(run)).code.version, 2);
      final opened = ConnectRun.accept(me: bob, code: one);
      expect(opened.toJson().containsKey('cv'), isFalse);
      expect((await reread(opened)).code.version, 1);
      expect((await reread(ConnectRun.accept(me: bob, code: two))).code.version,
          2);
    });
  });
}

/// The channel key both sides derive (§20.3), recomputed here so a test can
/// seal a reveal the library itself would never write.
Future<Uint8List> _channelKey(Uint8List mySeed, Uint8List peerPub) async {
  final x = X25519();
  final shared = await x.sharedSecretKey(
      keyPair: await x.newKeyPairFromSeed(mySeed),
      remotePublicKey: SimplePublicKey(peerPub, type: KeyPairType.x25519));
  final k = await Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
      secretKey: SecretKey(await shared.extractBytes()),
      nonce: Uint8List(32),
      info: utf8.encode('z-connect-channel-v1'));
  return Uint8List.fromList(await k.extractBytes());
}

/// §20.3's `seal`: nonce, then ChaCha20-Poly1305 of the JSON.
Future<String> _seal(Uint8List key, Map<String, Object?> payload) async {
  final box = await Chacha20.poly1305Aead().encrypt(
      utf8.encode(jsonEncode(payload)),
      secretKey: SecretKey(key),
      nonce: randomBytes(12));
  return b64(box.concatenation());
}

/// One whole ceremony, returning the string both sides agreed on.
Future<String> _run(ConnectIdentity a, ConnectIdentity b) async {
  final inviter = await ConnectInviter.create(me: a, code: _v1());
  final (reply, acceptor) =
      await ConnectAcceptor.reply(await inviter.commit(),
          me: b, code: inviter.code);
  final (reveal, sessionB) = await acceptor.accept(await inviter.open(reply));
  final sessionA = await inviter.complete(reveal);
  expect(sessionA.sas, sessionB.sas);
  return sessionA.sas;
}

/// A fresh invite of version 1 — the ceremony as ADR 0009 built it, which
/// is what criteria 1–11 are about. Version 2, bound to its secret, is
/// 12–16; ConnectCode.generate() makes one by default.
ConnectCode _v1() => ConnectCode.generate(version: 1);

// --- §20.8, re-derived from the text alone (criteria 12–16) ---------------

Future<Uint8List> _hkdfBytes(
    List<int> ikm, List<int> salt, List<int> info, int n) async {
  final k = await Hkdf(hmac: Hmac.sha256(), outputLength: n)
      .deriveKey(secretKey: SecretKey(ikm), nonce: salt, info: info);
  return Uint8List.fromList(await k.extractBytes());
}

Future<Uint8List> _hkdf(List<int> ikm, List<int> salt, String info, int n) =>
    _hkdfBytes(ikm, salt, utf8.encode(info), n);

/// The invite key: HKDF-SHA256 of the secret, empty salt, 32 bytes.
Future<Uint8List> _inviteKeyOf(Uint8List secret) =>
    _hkdf(secret, const <int>[], 'z-connect-invite-v2', 32);

Future<Uint8List> _dh(Uint8List seed, Uint8List peerPub) async {
  final x = X25519();
  final s = await x.sharedSecretKey(
      keyPair: await x.newKeyPairFromSeed(seed),
      remotePublicKey: SimplePublicKey(peerPub, type: KeyPairType.x25519));
  return Uint8List.fromList(await s.extractBytes());
}

/// What a commitment covers after its context: the ephemeral, the code
/// length-prefixed, the name last.
List<int> _committed(Uint8List eph, ConnectIdentity id) {
  final code = utf8.encode(id.contactCode);
  return [
    ...eph,
    (code.length >> 8) & 0xff,
    code.length & 0xff,
    ...code,
    ...utf8.encode(id.displayName ?? ''),
  ];
}

Future<Uint8List> _commitV1(Uint8List eph, ConnectIdentity id) async =>
    Uint8List.fromList((await Sha256().hash(
            [...utf8.encode('z-connect-commit-v1:'), ..._committed(eph, id)]))
        .bytes);

Future<Uint8List> _commitV2(
        Uint8List key, Uint8List eph, ConnectIdentity id) async =>
    Uint8List.fromList((await Hmac.sha256().calculateMac(
            [...utf8.encode('z-connect-commit-v2:'), ..._committed(eph, id)],
            secretKey: SecretKey(key)))
        .bytes);

/// §20.4's eight digits, under the context [ctx].
Future<String> _sasOf(Uint8List dh, ConnectIdentity a, Uint8List ephA,
    ConnectIdentity b, Uint8List ephB, String ctx) async {
  var aFirst = false;
  for (var i = 0; i < 32; i++) {
    if (a.accountEdPub[i] != b.accountEdPub[i]) {
      aFirst = a.accountEdPub[i] < b.accountEdPub[i];
      break;
    }
  }
  final lo = aFirst ? a : b, hi = aFirst ? b : a;
  final okm = await _hkdfBytes(dh, [...(aFirst ? ephA : ephB), ...(aFirst ? ephB : ephA)], [
    ...utf8.encode(ctx),
    ...lo.accountEdPub,
    ...lo.pqCommit,
    ...hi.accountEdPub,
    ...hi.pqCommit,
  ], 8);
  var n = 0;
  for (var i = 0; i < 7; i++) {
    n = (n << 8) | okm[i];
  }
  final d = (n % 100000000).toString().padLeft(8, '0');
  return '${d.substring(0, 4)} ${d.substring(4)}';
}

/// Whether [blob] — §20.3's `seal` output, base64 — opens under [key].
Future<bool> _opens(Uint8List key, String blob) async {
  try {
    await Chacha20.poly1305Aead().decrypt(
        SecretBox.fromConcatenation(unb64(blob), nonceLength: 12, macLength: 16),
        secretKey: SecretKey(key));
    return true;
  } catch (_) {
    return false;
  }
}

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
