// Protocol v2: post-quantum hybrid (ML-KEM-768 mixed into message keys).

import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

Uint8List utf8b(String s) => Uint8List.fromList(utf8.encode(s));

Map<String, Object?> headerOf(String payload) =>
    ((jsonDecode(utf8.decode(base64Decode(payload))) as Map)['h'] as Map)
        .cast<String, Object?>();

/// Two conversations with a fixed role assignment: [enc] is the designated
/// initiator (encapsulates), [off] the other side (offers the ML-KEM key).
Future<(Conversation enc, Conversation off)> pair(
    {bool encPq = true, bool offPq = true}) async {
  var a = await ZIdentity.generate();
  var b = await ZIdentity.generate();
  // The designated initiator is the lower routing id: make that `a`.
  if ((await a.routingId()).compareTo(await b.routingId()) > 0) {
    (a, b) = (b, a);
  }
  final enc =
      await Conversation.create(a, await b.bundle(), postQuantum: encPq);
  final off =
      await Conversation.create(b, await a.bundle(), postQuantum: offPq);
  assert(enc.isDesignatedInitiator && off.isPqOfferer);
  return (enc, off);
}

void main() {
  group('ML-KEM-768 wrapper', () {
    test('key generation is deterministic from the seed', () {
      final seed = Uint8List.fromList(List.generate(64, (i) => i));
      final (ek1, dk1) = pqKeyPairFromSeed(seed);
      final (ek2, dk2) = pqKeyPairFromSeed(seed);
      expect(ek1, ek2);
      expect(dk1, dk2);
      expect(ek1.length, 1184);
      expect(dk1.length, 2400);
    });

    test(
        'encapsulate/decapsulate agree; a tampered ciphertext is implicitly '
        'rejected (different secret, no exception)', () {
      final (seed, ek) = pqGenerate();
      final (ct, k) = pqEncapsulate(ek);
      expect(ct.length, 1088);
      expect(k.length, 32);
      expect(pqDecapsulate(seed, ct), k);
      final bad = Uint8List.fromList(ct);
      bad[100] ^= 0x01;
      final kBad = pqDecapsulate(seed, bad);
      expect(kBad, isNot(equals(k)));
      expect(kBad.length, 32);
    });

    test('rejects wrong lengths', () {
      expect(() => pqKeyPairFromSeed(Uint8List(32)), throwsArgumentError);
      expect(() => pqEncapsulate(Uint8List(10)), throwsArgumentError);
      expect(() => pqDecapsulate(Uint8List(64), Uint8List(10)),
          throwsArgumentError);
    });
  });

  group('v2 upgrade over a conversation', () {
    test('offer → encapsulate → mixed keys, in one round trip', () async {
      final (enc, off) = await pair();
      expect(enc.isPqOfferer, isFalse);
      expect(off.isPqOfferer, isTrue);

      // Encapsulator opens the session (classical hello).
      final hello = await enc.encrypt(utf8b('hello'));
      expect(headerOf(hello).containsKey('pq'), isFalse);
      final r1 = await off.decrypt(hello);
      expect(utf8.decode(r1.plaintext), 'hello');
      // The offerer answers with its key offer, encrypted like any message.
      expect(r1.pqOfferPayload, isNotNull);
      expect(off.pq.dkSeed, isNotNull);
      expect(off.isPostQuantum, isFalse);

      // The encapsulator consumes the offer silently and now holds K.
      final r2 = await enc.decrypt(r1.pqOfferPayload!);
      expect(InnerMessage.looksLikeKind(r2.plaintext, 'pqek'), isTrue);
      expect(r2.pqOfferPayload, isNull);
      expect(enc.isPostQuantum, isTrue);
      expect(enc.pq.ct, isNotNull);
      expect(enc.pq.acked, isFalse);

      // Its next message is PQ-mixed and carries the ciphertext.
      final m1 = await enc.encrypt(utf8b('first pq message'));
      final h1 = headerOf(m1);
      expect(h1['pq'], 1);
      expect(base64Decode(h1['pqct'] as String).length, 1088);
      final r3 = await off.decrypt(m1);
      expect(utf8.decode(r3.plaintext), 'first pq message');
      expect(off.isPostQuantum, isTrue);
      expect(off.pq.k, enc.pq.k);
      expect(off.pq.dkSeed, isNull, reason: 'decapsulation key is single-use');

      // The offerer's reply is mixed too (flag only, no ciphertext) …
      final m2 = await off.encrypt(utf8b('reply'));
      final h2 = headerOf(m2);
      expect(h2['pq'], 1);
      expect(h2.containsKey('pqct'), isFalse);
      final r4 = await enc.decrypt(m2);
      expect(utf8.decode(r4.plaintext), 'reply');
      // … which tells the encapsulator to stop attaching the ciphertext.
      expect(enc.pq.acked, isTrue);
      final m3 = await enc.encrypt(utf8b('steady state'));
      expect(headerOf(m3)['pq'], 1);
      expect(headerOf(m3).containsKey('pqct'), isFalse);
      expect(utf8.decode((await off.decrypt(m3)).plaintext), 'steady state');
    });

    test(
        'ciphertext keeps riding until the peer proves it holds K, and '
        'out-of-order delivery still works', () async {
      final (enc, off) = await pair();
      final r1 = await off.decrypt(await enc.encrypt(utf8b('hello')));
      await enc.decrypt(r1.pqOfferPayload!);
      final a = await enc.encrypt(utf8b('a'));
      final b = await enc.encrypt(utf8b('b'));
      final c = await enc.encrypt(utf8b('c'));
      for (final p in [a, b, c]) {
        expect(headerOf(p).containsKey('pqct'), isTrue);
      }
      // Deliver c, then a, then b.
      expect(utf8.decode((await off.decrypt(c)).plaintext), 'c');
      expect(off.isPostQuantum, isTrue);
      expect(utf8.decode((await off.decrypt(a)).plaintext), 'a');
      expect(utf8.decode((await off.decrypt(b)).plaintext), 'b');
    });

    test('a tampered ciphertext fails closed and leaves state untouched',
        () async {
      final (enc, off) = await pair();
      final r1 = await off.decrypt(await enc.encrypt(utf8b('hello')));
      await enc.decrypt(r1.pqOfferPayload!);
      final m1 = await enc.encrypt(utf8b('pq'));
      // Flip one byte of pqct inside the payload JSON (it is in the AAD).
      final j = (jsonDecode(utf8.decode(base64Decode(m1))) as Map)
          .cast<String, Object?>();
      final h = (j['h'] as Map).cast<String, Object?>();
      final ct = base64Decode(h['pqct'] as String);
      ct[5] ^= 0xff;
      h['pqct'] = base64Encode(ct);
      final tampered = base64Encode(utf8.encode(jsonEncode(j)));
      await expectLater(
          off.decrypt(tampered), throwsA(isA<RatchetDecryptException>()));
      expect(off.isPostQuantum, isFalse);
      expect(off.pq.dkSeed, isNotNull, reason: 'pending key must survive');
      // The genuine message still goes through afterwards.
      expect(utf8.decode((await off.decrypt(m1)).plaintext), 'pq');
      expect(off.isPostQuantum, isTrue);
    });

    test('state survives persistence at every stage', () async {
      var (enc, off) = await pair();
      final encId = enc.me, offId = off.me;
      Future<void> roundTrip() async {
        enc = await Conversation.fromJson(
            encId, jsonDecode(jsonEncode(enc.toJson())));
        off = await Conversation.fromJson(
            offId, jsonDecode(jsonEncode(off.toJson())));
      }

      final r1 = await off.decrypt(await enc.encrypt(utf8b('hello')));
      await roundTrip();
      expect(off.pq.dkSeed, isNotNull);
      await enc.decrypt(r1.pqOfferPayload!);
      await roundTrip();
      expect(enc.isPostQuantum, isTrue);
      final m1 = await enc.encrypt(utf8b('one'));
      await roundTrip();
      expect(utf8.decode((await off.decrypt(m1)).plaintext), 'one');
      await roundTrip();
      expect(off.pq.k, enc.pq.k);
      final m2 = await off.encrypt(utf8b('two'));
      await roundTrip();
      expect(utf8.decode((await enc.decrypt(m2)).plaintext), 'two');
      expect(enc.pq.acked, isTrue);
    });

    test('interoperates with a v1 peer on either side (stays classical)',
        () async {
      // v1 offerer: never offers, so nothing changes.
      var (enc, off) = await pair(offPq: false);
      var r = await off.decrypt(await enc.encrypt(utf8b('hi')));
      expect(r.pqOfferPayload, isNull);
      var reply = await off.encrypt(utf8b('yo'));
      expect(headerOf(reply).containsKey('pq'), isFalse);
      expect(utf8.decode((await enc.decrypt(reply)).plaintext), 'yo');
      expect(enc.isPostQuantum, isFalse);

      // v1 encapsulator: receives the offer as an unknown inner kind and
      // ignores it; the v2 offerer never sees a ciphertext.
      (enc, off) = await pair(encPq: false);
      r = await off.decrypt(await enc.encrypt(utf8b('hi')));
      expect(r.pqOfferPayload, isNotNull);
      final offer = await enc.decrypt(r.pqOfferPayload!);
      expect(InnerMessage.fromBytes(offer.plaintext).kind, 'pqek');
      expect(enc.isPostQuantum, isFalse);
      final m = await enc.encrypt(utf8b('still classical'));
      expect(headerOf(m).containsKey('pq'), isFalse);
      expect(utf8.decode((await off.decrypt(m)).plaintext), 'still classical');
      expect(off.isPostQuantum, isFalse);
    });

    test('a pq message cannot be decrypted without the shared secret',
        () async {
      final (enc, off) = await pair();
      final r1 = await off.decrypt(await enc.encrypt(utf8b('hello')));
      await enc.decrypt(r1.pqOfferPayload!);
      final m1 = await enc.encrypt(utf8b('pq'));
      // Simulate a receiver that never got the ciphertext: strip pqct.
      final j = (jsonDecode(utf8.decode(base64Decode(m1))) as Map)
          .cast<String, Object?>();
      (j['h'] as Map).remove('pqct');
      final stripped = base64Encode(utf8.encode(jsonEncode(j)));
      await expectLater(
          off.decrypt(stripped), throwsA(isA<RatchetDecryptException>()));
    });

    test('reset drops the secret and the offer is made again', () async {
      final (enc, off) = await pair();
      final r1 = await off.decrypt(await enc.encrypt(utf8b('hello')));
      await enc.decrypt(r1.pqOfferPayload!);
      await off.decrypt(await enc.encrypt(utf8b('pq')));
      expect(off.isPostQuantum, isTrue);
      off.resetSessions();
      enc.resetSessions();
      expect(off.isPostQuantum, isFalse);
      expect(off.pq.offered, isFalse);
      final r2 = await off.decrypt(await enc.encrypt(utf8b('again')));
      expect(r2.pqOfferPayload, isNotNull);
    });

    test('the offerer also offers on its own first send', () async {
      final (enc, off) = await pair();
      // The offerer speaks first: it must hand out the offer before its
      // message so the pair upgrades even if the peer never initiates.
      final offer = await off.takePqOfferPayload();
      expect(offer, isNotNull);
      final msg = await off.encrypt(utf8b('first from offerer'));
      await enc.decrypt(offer!);
      expect(enc.isPostQuantum, isTrue);
      expect(utf8.decode((await enc.decrypt(msg)).plaintext),
          'first from offerer');
      final back = await enc.encrypt(utf8b('pq back'));
      expect(headerOf(back)['pq'], 1);
      expect(utf8.decode((await off.decrypt(back)).plaintext), 'pq back');
      expect(off.isPostQuantum, isTrue);
    });
  });
}
