import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
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

    test('8. one sealed bit says a group is attached, at no cost in length',
        () async {
      final alice = await person('Alice');
      final bob = await person('Bob');

      /// A whole ceremony: the inviter's [group] bit (null: a client from
      /// before ADR 0020 writes none) against an acceptor that does or does
      /// not read it. The frames are returned as the relay would carry them.
      Future<({ConnectSession i, ConnectSession a, String x3, String x4})> run(
          bool? group, bool aware) async {
        final inviter = await ConnectInviter.create(me: alice, group: group);
        final (reply, acceptor) = await ConnectAcceptor.reply(
            await inviter.commit(),
            me: bob,
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
        final inviter = await ConnectInviter.create(me: alice, group: true);
        final (_, aware) = await ConnectAcceptor.reply(await inviter.commit(),
            me: bob, groupAware: true);
        await expectLater(
            aware.accept(await forgedOpen(inviter, aware, {'grp': bad})),
            throwsA(isA<ConnectAbort>()),
            reason: 'a group bit of $bad is not 0 or 1');
        // A client that never reads the member is not troubled by it.
        final (_, old) =
            await ConnectAcceptor.reply(await inviter.commit(), me: bob);
        final (_, s) =
            await old.accept(await forgedOpen(inviter, old, {'grp': bad}));
        expect(s.group, isNull);
      }

      // Message 4 repeating the opposite bit: the two sides disagree about
      // what the ceremony is, so the inviter stops.
      for (final group in [true, false]) {
        final inviter = await ConnectInviter.create(me: alice, group: group);
        final (reply, acceptor) = await ConnectAcceptor.reply(
            await inviter.commit(),
            me: bob,
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
      final withBit = await ConnectInviter.create(me: alice, group: true);
      final withoutBit = await ConnectInviter.fromJson(
          {...withBit.toJson(), 'grp': false});
      expect(await withoutBit.commit(), await withBit.commit());
      final (reply, acceptor) = await ConnectAcceptor.reply(
          await withBit.commit(),
          me: bob,
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
        final inviter = await ConnectInviter.create(me: i, group: true);
        final (reply, acceptor) = await ConnectAcceptor.reply(
            await inviter.commit(),
            me: a,
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
        final inviter = await ConnectInviter.create(me: alice, group: true);
        final (reply, _) = await ConnectAcceptor.reply(await inviter.commit(),
            me: bob, groupAware: true);
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
        final inviter2 = await ConnectInviter.create(me: alice, group: true);
        final (reply2, acceptor) = await ConnectAcceptor.reply(
            await inviter2.commit(),
            me: bob,
            groupAware: true);
        final open = await inviter2.open(reply2);
        await expectLater(
            acceptor.accept({...open, 'ephx': b64(point)}),
            throwsA(isA<ConnectAbort>()
                .having((e) => e.message, 'message', contains('small order'))),
            reason: name);
      }

      // An honest ceremony is untouched by the check.
      final inviter = await ConnectInviter.create(me: alice);
      final (reply, acceptor) =
          await ConnectAcceptor.reply(await inviter.commit(), me: bob);
      final (reveal, sb) = await acceptor.accept(await inviter.open(reply));
      expect((await inviter.complete(reveal)).sas, sb.sas);
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
  final inviter = await ConnectInviter.create(me: a);
  final (reply, acceptor) =
      await ConnectAcceptor.reply(await inviter.commit(), me: b);
  final (reveal, sessionB) = await acceptor.accept(await inviter.open(reply));
  final sessionA = await inviter.complete(reveal);
  expect(sessionA.sas, sessionB.sas);
  return sessionA.sas;
}
