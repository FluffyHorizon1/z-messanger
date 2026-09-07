import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

Uint8List utf8b(String s) => Uint8List.fromList(utf8.encode(s));

Future<(ZIdentity, ZIdentity, Conversation, Conversation)> pair() async {
  final alice = await ZIdentity.generate();
  final bob = await ZIdentity.generate();
  final aliceConv =
      await Conversation.create(alice, await bob.bundle(displayName: 'Bob'));
  final bobConv =
      await Conversation.create(bob, await alice.bundle(displayName: 'Alice'));
  return (alice, bob, aliceConv, bobConv);
}

/// Carries a message from one side to the other the way the app does
/// (`ChatService._sendInner`): any pending post-quantum offer goes out ahead
/// of the message, and any offer the receiver produces on decrypt is
/// delivered straight back. Returns the plaintext the receiver saw.
Future<String> carry(Conversation from, Conversation to, String text) async {
  final offer = await from.takePqOfferPayload();
  if (offer != null) await to.decrypt(offer);
  final got = await to.decrypt(await from.encrypt(utf8b(text)));
  final back = got.pqOfferPayload;
  if (back != null) await from.decrypt(back);
  return utf8.decode(got.plaintext);
}

void main() {
  group('identity & contact codes', () {
    test('contact code round-trip with signature verification', () async {
      final id = await ZIdentity.generate();
      final code = (await id.bundle(displayName: 'Finn')).encode();
      expect(code, startsWith('zc1.'));
      final parsed = await ContactBundle.decode(code);
      expect(parsed.edPub, equals(id.edPub));
      expect(parsed.xPub, equals(id.xPub));
      expect(parsed.displayName, 'Finn');
    });

    test('tampered contact code is rejected', () async {
      final id = await ZIdentity.generate();
      final other = await ZIdentity.generate();
      final bundle = await id.bundle();
      // Swap in another x25519 key without re-signing -> must fail.
      final forged = ContactBundle(
        edPub: bundle.edPub,
        xPub: other.xPub,
        bindingSig: bundle.bindingSig,
      );
      expect(await forged.verify(), isFalse);
      expect(() => ContactBundle.decode(forged.encode()),
          throwsFormatException);
    });

    test('garbage codes are rejected', () async {
      expect(() => ContactBundle.decode('hello'), throwsFormatException);
      expect(() => ContactBundle.decode('zc1.!!!!'), throwsFormatException);
    });

    test('safety number is symmetric and key-sensitive', () async {
      final a = await ZIdentity.generate();
      final b = await ZIdentity.generate();
      final c = await ZIdentity.generate();
      final ab = await safetyNumber(a.edPub, b.edPub);
      final ba = await safetyNumber(b.edPub, a.edPub);
      expect(ab, equals(ba));
      expect(ab.split(' ').length, 12);
      expect(ab.replaceAll(' ', '').length, 60);
      expect(await safetyNumber(a.edPub, c.edPub), isNot(equals(ab)));
    });

    test('routing id is a hash, not the key', () async {
      final id = await ZIdentity.generate();
      final rid = await id.routingId();
      expect(rid, isNot(contains(b64(id.edPub))));
      expect(rid.length, greaterThanOrEqualTo(43)); // 32 bytes b64url
    });
  });

  group('sessions & double ratchet', () {
    test('basic two-way conversation', () async {
      final (_, __, aliceConv, bobConv) = await pair();

      final p1 = await aliceConv.encrypt(utf8b('hi bob'));
      final r1 = await bobConv.decrypt(p1);
      expect(utf8.decode(r1.plaintext), 'hi bob');
      expect(r1.createdNewSession, isTrue);

      final p2 = await bobConv.encrypt(utf8b('hey alice'));
      final r2 = await aliceConv.decrypt(p2);
      expect(utf8.decode(r2.plaintext), 'hey alice');
      expect(r2.createdNewSession, isFalse);

      // Long alternating exchange exercises repeated DH ratchet turns.
      for (var i = 0; i < 12; i++) {
        final fromAlice = i.isEven;
        final sender = fromAlice ? aliceConv : bobConv;
        final receiver = fromAlice ? bobConv : aliceConv;
        final res = await receiver.decrypt(await sender.encrypt(utf8b('m$i')));
        expect(utf8.decode(res.plaintext), 'm$i');
      }
    });

    test('out-of-order delivery within a chain', () async {
      final (_, __, aliceConv, bobConv) = await pair();
      // Establish the session first.
      await bobConv.decrypt(await aliceConv.encrypt(utf8b('start')));

      final batch = <String>[];
      for (var i = 0; i < 6; i++) {
        batch.add(await aliceConv.encrypt(utf8b('n$i')));
      }
      // Deliver shuffled: 4, 0, 5, 2, 1, 3
      for (final i in [4, 0, 5, 2, 1, 3]) {
        final res = await bobConv.decrypt(batch[i]);
        expect(utf8.decode(res.plaintext), 'n$i');
      }
    });

    test('out-of-order delivery across a DH ratchet turn', () async {
      final (_, __, aliceConv, bobConv) = await pair();
      await bobConv.decrypt(await aliceConv.encrypt(utf8b('start')));
      await aliceConv.decrypt(await bobConv.encrypt(utf8b('reply')));

      final oldChain = await aliceConv.encrypt(utf8b('before-turn'));
      // Bob replies; Alice's next message starts a new chain.
      await bobConv.decrypt(await aliceConv.encrypt(utf8b('mid')));
      await aliceConv.decrypt(await bobConv.encrypt(utf8b('turn')));
      final newChain = await aliceConv.encrypt(utf8b('after-turn'));

      // New chain arrives before the old chain's straggler.
      expect(utf8.decode((await bobConv.decrypt(newChain)).plaintext),
          'after-turn');
      expect(utf8.decode((await bobConv.decrypt(oldChain)).plaintext),
          'before-turn');
    });

    test('tampered ciphertext and headers are rejected without state damage',
        () async {
      final (_, __, aliceConv, bobConv) = await pair();
      await bobConv.decrypt(await aliceConv.encrypt(utf8b('start')));

      final good = await aliceConv.encrypt(utf8b('secret'));
      final j = jsonDecode(utf8.decode(base64Decode(good)))
          as Map<String, Object?>;

      // Flip a ciphertext byte.
      final ct = base64Decode(j['ct'] as String);
      ct[0] ^= 0xff;
      final tampered1 = Map<String, Object?>.from(j)..['ct'] = base64Encode(ct);
      expect(
        () => bobConv
            .decrypt(base64Encode(utf8.encode(jsonEncode(tampered1)))),
        throwsA(isA<RatchetDecryptException>()),
      );

      // Tamper the header (AEAD-bound).
      final h = Map<String, Object?>.from((j['h'] as Map).cast());
      h['n'] = 7;
      final tampered2 = Map<String, Object?>.from(j)..['h'] = h;
      expect(
        () => bobConv
            .decrypt(base64Encode(utf8.encode(jsonEncode(tampered2)))),
        throwsA(isA<RatchetDecryptException>()),
      );

      // The genuine message still decrypts -> failed attempts left no trace.
      expect(utf8.decode((await bobConv.decrypt(good)).plaintext), 'secret');
    });

    test('replayed envelopes are rejected (used keys are gone)', () async {
      final (_, __, aliceConv, bobConv) = await pair();
      final p = await aliceConv.encrypt(utf8b('once'));
      await bobConv.decrypt(p);
      expect(() => bobConv.decrypt(p),
          throwsA(isA<RatchetDecryptException>()));
    });

    test('state serialization round-trip mid-conversation', () async {
      final (alice, bob, aliceConv, bobConv) = await pair();
      await bobConv.decrypt(await aliceConv.encrypt(utf8b('one')));
      await aliceConv.decrypt(await bobConv.encrypt(utf8b('two')));

      // Persist and restore BOTH sides (simulates app restart).
      final aliceRestored =
          await Conversation.fromJson(alice, aliceConv.toJson());
      final bobRestored = await Conversation.fromJson(bob, bobConv.toJson());

      final res = await bobRestored
          .decrypt(await aliceRestored.encrypt(utf8b('three')));
      expect(utf8.decode(res.plaintext), 'three');
      final res2 = await aliceRestored
          .decrypt(await bobRestored.encrypt(utf8b('four')));
      expect(utf8.decode(res2.plaintext), 'four');
    });

    test('simultaneous initiation converges to one session', () async {
      final (_, __, aliceConv, bobConv) = await pair();

      // Both send before seeing anything from the other.
      final fromAlice = await aliceConv.encrypt(utf8b('alice-first'));
      final fromBob = await bobConv.encrypt(utf8b('bob-first'));

      expect(utf8.decode((await bobConv.decrypt(fromAlice)).plaintext),
          'alice-first');
      expect(utf8.decode((await aliceConv.decrypt(fromBob)).plaintext),
          'bob-first');

      // Now both continue; they must converge on the designated session and
      // still understand each other.
      final a2 = await aliceConv.encrypt(utf8b('a2'));
      final b2 = await bobConv.encrypt(utf8b('b2'));
      expect(utf8.decode((await bobConv.decrypt(a2)).plaintext), 'a2');
      expect(utf8.decode((await aliceConv.decrypt(b2)).plaintext), 'b2');

      expect(aliceConv.outboundSid, equals(bobConv.outboundSid));
    });

    test('unknown session without ek raises UnknownSessionException',
        () async {
      final (_, bob, aliceConv, bobConv) = await pair();
      await bobConv.decrypt(await aliceConv.encrypt(utf8b('est')));
      await aliceConv.decrypt(await bobConv.encrypt(utf8b('ok')));

      // Bob reinstalls: fresh conversation state, same identity.
      final bobFresh = await Conversation.create(bob, bobConv.them);
      final late = await aliceConv.encrypt(utf8b('you there?'));
      expect(() => bobFresh.decrypt(late),
          throwsA(isA<UnknownSessionException>()));
    });

    test('a peer that lost its state is talked to again, both rid orders',
        () async {
      // A device that reinstalls — or restores from a backup, which
      // deliberately carries no session state (§9) — opens a fresh session.
      // The peer must adopt it, AND must restart the v2 post-quantum
      // handshake: the ML-KEM secret belonged to the session that was lost,
      // so a peer that keeps mixing it makes every reply undecryptable.
      //
      // Two ordering-dependent hazards live here. Convergence prefers the
      // session opened by the DESIGNATED INITIATOR, and the PQ roles
      // (offerer vs encapsulator) are fixed by the same rid comparison, so
      // each bug shows up in only one of the two orderings. Loop until both
      // have actually been exercised rather than trusting random ids.
      final ordersSeen = <bool>{};
      for (var i = 0; i < 40 && ordersSeen.length < 2; i++) {
        final (_, bob, aliceConv, bobConv) = await pair();
        ordersSeen.add(aliceConv.isDesignatedInitiator);

        // An established, two-way conversation — and a fully established
        // post-quantum layer, which is the state the bug hid in.
        expect(await carry(aliceConv, bobConv, 'hello'), 'hello');
        expect(await carry(bobConv, aliceConv, 'hi back'), 'hi back');
        expect(await carry(aliceConv, bobConv, 'settled'), 'settled');
        expect(await carry(bobConv, aliceConv, 'settled too'), 'settled too');
        expect(aliceConv.isPostQuantum, isTrue, reason: 'PQ up before loss');
        expect(bobConv.isPostQuantum, isTrue, reason: 'PQ up before loss');

        // Bob loses everything and starts from a fresh conversation.
        final bobFresh = await Conversation.create(bob, bobConv.them);

        // He speaks first, as a restored device does…
        expect(await carry(bobFresh, aliceConv, 'back on a new phone'),
            'back on a new phone');
        // …and Alice's reply must reach him, rather than going out on the
        // session — or under the ML-KEM secret — he no longer holds.
        expect(
            await carry(aliceConv, bobFresh, 'welcome back'), 'welcome back');

        // Alice answers on the session Bob just opened. She KEEPS the old
        // one — see the next test for why — but never sends on it again.
        expect(aliceConv.outboundSid, bobFresh.outboundSid);
        expect(aliceConv.sessions.length, 2);
        expect(await carry(aliceConv, bobFresh, 'again'), 'again');
        expect(await carry(bobFresh, aliceConv, 'and again'), 'and again');

        // And the post-quantum layer came back up on the new session, so the
        // restore is not a silent permanent downgrade to classical crypto.
        expect(aliceConv.isPostQuantum, isTrue, reason: 'PQ back up');
        expect(bobFresh.isPostQuantum, isTrue, reason: 'PQ back up');
      }
      expect(ordersSeen.length, 2, reason: 'both rid orderings exercised');
    });

    test('a session the peer replaced is still readable when it comes back',
        () async {
      // Adopting a newcomer must not make the session it replaced unreadable.
      // We cannot tell a peer that restored from a second device holding the
      // same identity key (7.7a's rogue, or simply a phone that was offline),
      // so if dropping the old session were the rule, anyone able to open one
      // session could permanently cut the other off — and a device-list
      // contradiction that only the returning device can reveal would never
      // be heard. Each session keeps its own post-quantum era, so the old one
      // still decrypts after the new one has re-handshaked from classical.
      for (var i = 0; i < 4; i++) {
        final (_, bob, aliceConv, bobConv) = await pair();
        expect(await carry(aliceConv, bobConv, 'hello'), 'hello');
        expect(await carry(bobConv, aliceConv, 'hi back'), 'hi back');
        expect(await carry(aliceConv, bobConv, 'settled'), 'settled');
        expect(await carry(bobConv, aliceConv, 'settled too'), 'settled too');
        expect(bobConv.isPostQuantum, isTrue);

        // A second device with the same identity opens its own session.
        final bobOther = await Conversation.create(bob, bobConv.them);
        expect(await carry(bobOther, aliceConv, 'from the other one'),
            'from the other one');
        expect(await carry(aliceConv, bobOther, 'noted'), 'noted');

        // The original speaks again — on the session Alice stopped using.
        expect(await carry(bobConv, aliceConv, 'still me'), 'still me');
        // …and her answer goes back where it can be read.
        expect(await carry(aliceConv, bobConv, 'heard you'), 'heard you');
        expect(aliceConv.sessions.length, 2);

        // Neither era leaked into the other: both are still post-quantum on
        // their own secret, and both keep working.
        expect(bobConv.isPostQuantum, isTrue);
        expect(bobOther.isPostQuantum, isTrue);
        expect(
            await carry(bobOther, aliceConv, 'and me again'), 'and me again');
        expect(await carry(aliceConv, bobOther, 'both of you'), 'both of you');
      }
    });

    test('simultaneous first messages still converge, not reset', () async {
      // The narrow condition above must not fire for the initiation race:
      // both sides open a session before hearing anything, and convergence —
      // not session-dropping — is what settles it.
      for (var i = 0; i < 10; i++) {
        final (_, __, aliceConv, bobConv) = await pair();
        final fromA = await aliceConv.encrypt(utf8b('a1'));
        final fromB = await bobConv.encrypt(utf8b('b1'));
        expect(utf8.decode((await bobConv.decrypt(fromA)).plaintext), 'a1');
        expect(utf8.decode((await aliceConv.decrypt(fromB)).plaintext), 'b1');
        // Two sessions existed; both sides settle on the same one and talk.
        expect(aliceConv.outboundSid, bobConv.outboundSid);
        await bobConv.decrypt(await aliceConv.encrypt(utf8b('a2')));
        await aliceConv.decrypt(await bobConv.encrypt(utf8b('b2')));
      }
    });

    test('padding hides exact plaintext length', () async {
      final (_, __, aliceConv, bobConv) = await pair();
      await bobConv.decrypt(await aliceConv.encrypt(utf8b('start')));

      int ctLen(String payload) {
        final j = jsonDecode(utf8.decode(base64Decode(payload)))
            as Map<String, Object?>;
        return base64Decode(j['ct'] as String).length;
      }

      // 1-byte and 200-byte messages produce identical ciphertext sizes.
      final small = ctLen(await aliceConv.encrypt(utf8b('a')));
      final medium = ctLen(await aliceConv.encrypt(utf8b('b' * 150)));
      expect(small, equals(medium));
      expect(small % 256, equals(0));
    });
  });

  group('inner messages', () {
    test('round-trip all kinds', () {
      final t = InnerMessage.text('m1', 123, 'hello', ttlSec: 60);
      final parsed = InnerMessage.fromBytes(t.toBytes());
      expect(parsed.kind, 'text');
      expect(parsed.mid, 'm1');
      expect(parsed.ttlSec, 60);
      expect(parsed.data['body'], 'hello');

      final timer = InnerMessage.fromBytes(
          InnerMessage.timer('m2', 5, 3600).toBytes());
      expect(timer.data['sec'], 3600);

      final read = InnerMessage.fromBytes(
          InnerMessage.read('m3', 6, ['a', 'b']).toBytes());
      expect((read.data['mids'] as List).length, 2);
    });
  });

  group('attachments', () {
    test('chunk encrypt/decrypt round-trip with reassembly + hash check',
        () async {
      final km = FileKeyMaterial.generate();
      final file = randomBytes(500 * 1000); // ~0.5 MB, 4 chunks at 140 KiB
      final chunks = splitChunks(file);
      expect(chunks.length, 4);

      final payloads = <String>[];
      for (var i = 0; i < chunks.length; i++) {
        payloads.add(await encryptChunk(km, i, chunks[i]));
      }

      // Receive out of order.
      final received = List<Uint8List?>.filled(chunks.length, null);
      for (final i in [2, 0, 3, 1]) {
        final parsed = tryParseChunk(payloads[i])!;
        expect(parsed.fid, km.fid);
        received[parsed.index] = await decryptChunk(
            fk: km.fk, fn: km.fn, fid: km.fid, chunk: parsed);
      }
      final reassembled = Uint8List.fromList(
          received.expand((c) => c!).toList());
      expect(await sha256Bytes(reassembled),
          equals(await sha256Bytes(file)));
    });

    test('tampered chunk fails authentication', () async {
      final km = FileKeyMaterial.generate();
      final payload = await encryptChunk(km, 0, randomBytes(1024));
      final parsed = tryParseChunk(payload)!;
      parsed.cipherText[10] ^= 0x01;
      expect(
        () => decryptChunk(fk: km.fk, fn: km.fn, fid: km.fid, chunk: parsed),
        throwsA(anything),
      );
    });

    test('chunk from a different file id fails (aad binding)', () async {
      final km = FileKeyMaterial.generate();
      final payload = await encryptChunk(km, 0, randomBytes(64));
      final parsed = tryParseChunk(payload)!;
      expect(
        () => decryptChunk(
            fk: km.fk, fn: km.fn, fid: 'different', chunk: parsed),
        throwsA(anything),
      );
    });

    test('ratchet payloads are not mistaken for chunks', () async {
      final (_, __, aliceConv, ___) = await pair();
      final p = await aliceConv.encrypt(utf8b('x'));
      expect(tryParseChunk(p), isNull);
    });
  });
}
