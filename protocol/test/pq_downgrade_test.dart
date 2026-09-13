// One withheld envelope, and the conversation was classical for ever.
//
// PROTOCOL §17.4 says an active attacker cannot force a downgrade, and
// reasons about TAMPERING: the offer is inside the ratchet, `pqct` is in the
// AAD, and stripping either only produces an authentication failure. All
// true, and beside the point. A relay does not have to strip anything — it
// can simply not deliver the one envelope that carried the offer, which is a
// thing every relay can always do (R14, R22) and which looks, from both
// sides, exactly like a peer who was briefly offline.
//
// The offer was made once per session and never again, so that one envelope
// cost the conversation its post-quantum layer permanently, on both sides,
// with nothing on either screen to say so. §18 had already learned this for
// the identity offer (`pqid` is re-made for several reasons); the same
// reasoning was never carried back to `pqek`.
//
// Criteria, each a test below:
//  1. an offer nobody ever received is made again once the retry interval
//     has passed, and the conversation ends post-quantum without anybody
//     doing anything;
//  2. the retry is the SAME encapsulation key, so an answer to the first
//     copy — arriving late, as withheld envelopes do — still establishes;
//  3. it does not fire before its interval, nor more than once within one:
//     a peer who is merely offline is not chased;
//  4. once the secret is established, the retry is silent and the periodic
//     re-key owns the key from there.
import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

Uint8List utf8b(String s) => Uint8List.fromList(utf8.encode(s));

Map<String, Object?> headerOf(String payload) =>
    ((jsonDecode(utf8.decode(base64Decode(payload))) as Map)['h'] as Map)
        .cast<String, Object?>();

/// [enc] encapsulates (the designated initiator); [off] offers the ML-KEM key.
Future<(Conversation enc, Conversation off)> pair({int retryMs = 3600000}) async {
  var a = await ZIdentity.generate();
  var b = await ZIdentity.generate();
  if ((await a.routingId()).compareTo(await b.routingId()) > 0) {
    (a, b) = (b, a);
  }
  final enc = await Conversation.create(a, await b.bundle());
  final off = await Conversation.create(b, await a.bundle());
  off.pqOfferRetryMs = retryMs;
  enc.pqOfferRetryMs = retryMs;
  return (enc, off);
}

void main() {
  const t0 = 1000000;
  const hour = 3600000;

  test('1. an offer nobody received is made again, and the secret establishes',
      () async {
    final (enc, off) = await pair();
    // The encapsulator opens the session; the offerer answers with its key.
    final r1 = await off.decrypt(await enc.encrypt(utf8b('hello')), nowMs: t0);
    expect(r1.pqOfferPayload, isNotNull);
    expect(off.isPostQuantum, isFalse);

    // The relay never delivers it. Nothing is stripped and nothing fails:
    // the envelope simply does not arrive, which no authentication can
    // detect because there is nothing to authenticate.
    final withheld = r1.pqOfferPayload!;
    expect(enc.isPostQuantum, isFalse);

    // Traffic continues, classical, and no further offer is made yet.
    expect(await off.takePqOfferPayload(nowMs: t0), isNull,
        reason: 'a peer who is merely offline is not chased');

    // Six hours later the offerer says it again, riding the next message.
    final retry = await off.takePqOfferPayload(nowMs: t0 + hour * 2);
    expect(retry, isNotNull, reason: 'one withheld envelope is not forever');
    expect(retry, isNot(withheld),
        reason: 'a fresh envelope: same offer, different ratchet step');

    // This one arrives, and the conversation becomes post-quantum.
    final r2 = await enc.decrypt(retry!);
    expect(InnerMessage.looksLikeKind(r2.plaintext, 'pqek'), isTrue);
    expect(enc.isPostQuantum, isTrue);
    final m = await enc.encrypt(utf8b('now post-quantum'));
    expect(headerOf(m)['pq'], 1);
    final r3 = await off.decrypt(m);
    expect(utf8.decode(r3.plaintext), 'now post-quantum');
    expect(off.isPostQuantum, isTrue);
    expect(off.pq.k, enc.pq.k);
  });

  test('2. the retry is the same key, so a late first answer still works',
      () async {
    final (enc, off) = await pair();
    final r1 = await off.decrypt(await enc.encrypt(utf8b('hello')), nowMs: t0);
    final first = r1.pqOfferPayload!;
    final keyAtFirstOffer = b64((pqKeyPairFromSeed(off.pq.dkSeed!)).$1);

    final retry = await off.takePqOfferPayload(nowMs: t0 + hour * 2);
    expect(retry, isNotNull);
    expect(b64((pqKeyPairFromSeed(off.pq.dkSeed!)).$1), keyAtFirstOffer,
        reason: 'a retry is not a re-key: the seed is unchanged');

    // The FIRST copy turns up after all — a withheld envelope released, or a
    // slow path. It must still establish, which it cannot if the retry had
    // replaced the key underneath it.
    final r2 = await enc.decrypt(first);
    expect(InnerMessage.looksLikeKind(r2.plaintext, 'pqek'), isTrue);
    expect(enc.isPostQuantum, isTrue);
    final r3 = await off.decrypt(await enc.encrypt(utf8b('established')));
    expect(utf8.decode(r3.plaintext), 'established');
    expect(off.pq.k, enc.pq.k, reason: 'the same secret on both sides');
  });

  test('3. not before the interval, and not twice within one', () async {
    final (enc, off) = await pair();
    await off.decrypt(await enc.encrypt(utf8b('hello')), nowMs: t0);

    expect(await off.takePqOfferPayload(nowMs: t0 + hour ~/ 2), isNull);
    expect(await off.takePqOfferPayload(nowMs: t0 + hour - 1), isNull,
        reason: 'a minute short of the interval is short of the interval');
    expect(await off.takePqOfferPayload(nowMs: t0 + hour * 4), isNotNull);
    expect(await off.takePqOfferPayload(nowMs: t0 + hour * 4), isNull,
        reason: 'one retry per interval, not an offer storm');
    expect(await off.takePqOfferPayload(nowMs: t0 + hour * 4 + hour ~/ 2),
        isNull,
        reason: 'the clock restarts from the retry, not from the first offer');
    expect(await off.takePqOfferPayload(nowMs: t0 + hour * 5), isNotNull,
        reason: 'and again once another whole interval has passed');

    // Off by configuration is off: the frozen v2 vectors run this way.
    off.pqOfferRetryMs = 0;
    expect(await off.takePqOfferPayload(nowMs: t0 + hour * 100), isNull);
  });

  test('4. once established, the retry is silent', () async {
    final (enc, off) = await pair();
    final r1 = await off.decrypt(await enc.encrypt(utf8b('hello')), nowMs: t0);
    await enc.decrypt(r1.pqOfferPayload!);
    await off.decrypt(await enc.encrypt(utf8b('pq')));
    expect(off.isPostQuantum, isTrue);

    off.pqRekeyIntervalMs = 0; // re-keying disabled: nothing else may fire
    expect(await off.takePqOfferPayload(nowMs: t0 + hour * 100), isNull,
        reason: 'an established secret is the re-key path\'s business');

    // And with re-keying on, what fires is a re-key — a NEW generation, not
    // the initial offer said again.
    off.pqRekeyIntervalMs = hour;
    final rekey = await off.takePqOfferPayload(nowMs: t0 + hour * 200);
    expect(rekey, isNotNull);
    expect(off.pq.offerGen, greaterThan(0));
  });
}
