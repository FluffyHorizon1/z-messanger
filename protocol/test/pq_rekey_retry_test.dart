// Phase 26.2 at the protocol level: the post-quantum layer keeps itself
// alive on every conversation, and one lost envelope is never forever.
//
// Until this change the two intervals that keep it alive — the re-key
// interval (§17.7) and the retry of an unanswered initial offer (§17.4) —
// were mutable fields that defaulted to zero, set by the app on the
// conversations it built for a person's main chat and on nothing else: an
// `AccountSession` (the self-sync channel, and the channel to a contact's
// other devices) built every conversation it held at zero, so those channels
// neither retried nor re-keyed. And once established, a re-key offer the
// peer never received froze re-keying for the life of the session: the next
// offer waited for an answer to this one, and nothing ever made this one
// again.
//
// Criteria, each a test below:
//   1. an account session's conversations carry the intervals however they
//      were built — `create`, `fromJson`, `addTarget` — and follow a change;
//      and a pair of them, a phone and its laptop, re-makes an initial offer
//      the relay withheld and then re-keys on the interval, exactly as a
//      primary conversation does;
//   2. a re-key offer that never arrived is made again with the SAME key once
//      the retry interval has passed — not before it, and once per interval
//      — and the next generation establishes;
//   3. an offer unanswered for a whole re-key interval while the peer went on
//      talking is abandoned: a fresh key, offered for the same generation
//      (the only one an older peer accepts), and that one establishes;
//   4. an answer to the abandoned key that turns up late still establishes:
//      the peer takes whichever copy reaches it first and ignores the rest;
//   5. no abandonment while the peer is silent — the same key is said again,
//      since a fresh one would not reach a peer that is not there either;
//   6. the previous generation's secret is kept until the peer has been seen
//      on the new one and 72 hours more (`pqCrossoverMs`, the relay's queue
//      lifetime), then erased — a late message of the old generation decrypts
//      inside that window and is refused after it, on both sides;
//   7. once the peer has been seen mixing, a classical message on that
//      session is refused — except a straggler at a position the peer had
//      already used before it started mixing, and that only within the same
//      72 hours — while one already read, delivered again, is still reported
//      as a replay;
//   8. all of it survives persistence: an abandoned key still decapsulates
//      after a round trip through JSON, and the windows keep their deadlines.
import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

Uint8List utf8b(String s) => Uint8List.fromList(utf8.encode(s));

const int hour = 3600000;
const int t0 = 1000000;
const PqIntervals iv = PqIntervals(rekeyMs: hour, offerRetryMs: hour ~/ 4);

Map<String, Object?> headerOf(String payload) =>
    ((jsonDecode(utf8.decode(base64Decode(payload))) as Map)['h'] as Map)
        .cast<String, Object?>();

/// [enc] encapsulates (the designated initiator); [off] offers.
Future<(Conversation enc, Conversation off)> pair(
    {PqIntervals intervals = iv}) async {
  var a = await ZIdentity.generate();
  var b = await ZIdentity.generate();
  if ((await a.routingId()).compareTo(await b.routingId()) > 0) {
    (a, b) = (b, a);
  }
  final enc = await Conversation.create(a, await b.bundle(),
      intervals: intervals);
  final off = await Conversation.create(b, await a.bundle(),
      intervals: intervals);
  return (enc, off);
}

/// A pair at generation 0, established and acknowledged both ways, at [now].
Future<void> establish(Conversation enc, Conversation off, int now) async {
  final r1 = await off.decrypt(await enc.encrypt(utf8b('hi'), nowMs: now),
      nowMs: now);
  await enc.decrypt(r1.pqOfferPayload!, nowMs: now);
  await off.decrypt(await enc.encrypt(utf8b('m1'), nowMs: now), nowMs: now);
  await enc.decrypt(await off.encrypt(utf8b('r1'), nowMs: now), nowMs: now);
  expect(enc.isPostQuantum && off.isPostQuantum, isTrue);
  expect(enc.pq.acked, isTrue);
}

/// The ML-KEM key [off] would offer from its pending seed.
String pendingKey(Conversation off) =>
    b64(pqKeyPairFromSeed(off.pq.dkSeed!).$1);

/// The key a `pqek` payload offers, read as its receiver would.
Future<String> offeredKey(Conversation receiverCopyOf, String payload) async {
  final copy = await Conversation.fromJson(
      receiverCopyOf.me, jsonDecode(jsonEncode(receiverCopyOf.toJson())),
      intervals: PqIntervals.disabled);
  final inner = InnerMessage.fromBytes((await copy.decrypt(payload)).plaintext);
  expect(inner.kind, 'pqek');
  return inner.data['ek'] as String;
}

class TestDevice {
  final AccountIdentity id;
  final DeviceCertificate cert;
  TestDevice(this.id, this.cert);
}

/// An account with two devices: the root and one linked.
Future<List<TestDevice>> phoneAndLaptop() async {
  final root = await AccountIdentity.generate();
  final kp = await ZIdentity.generate();
  final cert = await root.signDeviceCert(
      deviceEdPub: kp.edPub, deviceXPub: kp.xPub, deviceId: 'laptop');
  final laptop = await AccountIdentity.fromEnrollment(
    accountEdPub: root.accountEdPub,
    deviceEdSeed: kp.edSeed,
    deviceXSeed: kp.xSeed,
    deviceId: 'laptop',
    deviceCert: cert,
  );
  return [TestDevice(root, root.deviceCert), TestDevice(laptop, cert)];
}

void main() {
  test('1. an account session carries the intervals onto every conversation',
      () async {
    final me = await phoneAndLaptop();
    final contact = await phoneAndLaptop(); // someone else, two devices
    final rids = [
      for (final d in [...me, ...contact]) await d.id.routingId()
    ];

    // Built by create, grown by addTarget, rebuilt by fromJson: the three ways
    // a session comes to hold a conversation.
    final s = await AccountSession.create(
        me[0].id, [DeviceTarget.fromCert(me[1].cert)],
        intervals: iv);
    await s.addTarget(DeviceTarget.fromCert(contact[1].cert));
    final s2 = await AccountSession.fromJson(
        me[0].id, jsonDecode(jsonEncode(s.toJson())) as Map<String, Object?>,
        intervals: iv);
    for (final sess in [s, s2]) {
      for (final rid in [rids[1], rids[3]]) {
        final c = sess.targetConversation(rid)!;
        expect(c.pqRekeyIntervalMs, hour, reason: 'rekey on $rid');
        expect(c.pqOfferRetryMs, hour ~/ 4, reason: 'retry on $rid');
      }
    }
    s2.pqIntervals = const PqIntervals(rekeyMs: 7, offerRetryMs: 3);
    await s2.addTarget(DeviceTarget.fromCert(contact[0].cert));
    for (final rid in [rids[1], rids[2], rids[3]]) {
      expect(s2.targetConversation(rid)!.pqRekeyIntervalMs, 7);
      expect(s2.targetConversation(rid)!.pqOfferRetryMs, 3);
    }

    // And they act on them. The phone and its laptop, each an account
    // session toward the other; whichever has the higher routing id offers.
    final offerFirst = rids[0].compareTo(rids[1]) > 0;
    final o = offerFirst ? me[0] : me[1], e = offerFirst ? me[1] : me[0];
    final oRid = await o.id.routingId(), eRid = await e.id.routingId();
    final os = await AccountSession.create(o.id, [DeviceTarget.fromCert(e.cert)],
        intervals: iv);
    final es = await AccountSession.create(e.id, [DeviceTarget.fromCert(o.cert)],
        intervals: iv);
    List<String> to(List<FanoutMessage> fan, String rid) =>
        [for (final f in fan) if (f.routingId == rid) f.payload];

    // The encapsulator opens; the offer the offerer answers with is withheld.
    final hello = to(await es.encrypt(utf8b('hello'), nowMs: t0), oRid);
    final r1 = await os.decryptFrom(eRid, hello.single, nowMs: t0);
    expect(r1.pqOfferPayload, isNotNull, reason: 'the offer was made');
    // Before the retry interval: one payload — the message, no offer.
    final early = to(await os.encrypt(utf8b('a'), nowMs: t0 + hour ~/ 8), eRid);
    expect(early.length, 1);
    for (final p in early) {
      await es.decryptFrom(oRid, p, nowMs: t0 + hour ~/ 8);
    }
    // After it, the offer rides ahead of the next message again.
    final again = to(await os.encrypt(utf8b('b'), nowMs: t0 + hour ~/ 4), eRid);
    expect(again.length, 2, reason: 'a withheld offer is made again');
    for (final p in again) {
      await es.decryptFrom(oRid, p, nowMs: t0 + hour ~/ 4);
    }
    for (final p in to(await es.encrypt(utf8b('c'), nowMs: t0 + hour ~/ 4), oRid)) {
      await os.decryptFrom(eRid, p, nowMs: t0 + hour ~/ 4);
    }
    expect(os.targetConversation(eRid)!.isPostQuantum, isTrue);
    expect(es.targetConversation(oRid)!.isPostQuantum, isTrue);

    // A re-key interval later, the next send carries a re-key offer.
    final t1 = t0 + hour ~/ 4 + hour;
    final rekey = to(await os.encrypt(utf8b('d'), nowMs: t1), eRid);
    expect(rekey.length, 2, reason: 'the re-key offer rides ahead');
    for (final p in rekey) {
      await es.decryptFrom(oRid, p, nowMs: t1);
    }
    for (final p in to(await es.encrypt(utf8b('e'), nowMs: t1), oRid)) {
      await os.decryptFrom(eRid, p, nowMs: t1);
    }
    expect(os.targetConversation(eRid)!.pqGeneration, 1);
    expect(es.targetConversation(oRid)!.pqGeneration, 1);
  });

  test('2. a re-key offer that never arrived is made again, with the same key',
      () async {
    final (enc, off) = await pair();
    await establish(enc, off, t0);
    final t1 = t0 + hour;
    final lost = await off.takePqOfferPayload(nowMs: t1);
    expect(lost, isNotNull);
    expect(off.pq.offerGen, 1);
    final key = pendingKey(off);
    // The peer goes on talking at generation 0; the offer never reached it.
    await off.decrypt(await enc.encrypt(utf8b('g0'), nowMs: t1 + 1),
        nowMs: t1 + 1);
    expect(await off.takePqOfferPayload(nowMs: t1 + hour ~/ 4 - 1), isNull,
        reason: 'not before the retry interval');
    final retry = await off.takePqOfferPayload(nowMs: t1 + hour ~/ 4);
    expect(retry, isNotNull, reason: 'one lost offer is not forever');
    expect(pendingKey(off), key, reason: 'a retry is the same key');
    expect(await offeredKey(enc, retry!), key);
    expect(await off.takePqOfferPayload(nowMs: t1 + hour ~/ 4 + 1), isNull,
        reason: 'once per interval');
    await enc.decrypt(retry, nowMs: t1 + hour ~/ 4);
    expect(enc.pqGeneration, 1);
    await off.decrypt(await enc.encrypt(utf8b('g1'), nowMs: t1 + hour ~/ 2),
        nowMs: t1 + hour ~/ 2);
    expect(off.pqGeneration, 1);
    expect(off.pq.k, enc.pq.k);
    expect(off.pq.dkSeed, isNull);
  });

  test('3. an offer unanswered for an interval while the peer talks is '
      'abandoned for a fresh key', () async {
    final (enc, off) = await pair();
    await establish(enc, off, t0);
    final t1 = t0 + hour;
    expect(await off.takePqOfferPayload(nowMs: t1), isNotNull); // lost
    final first = pendingKey(off);
    for (var k = 1; k <= 3; k++) {
      final now = t1 + k * (hour ~/ 4);
      // The peer speaks just before each retry falls due — a decrypt makes
      // any offer that IS due itself, which is not what this step counts.
      final dec = await off.decrypt(
          await enc.encrypt(utf8b('g0 $k'), nowMs: now - 1),
          nowMs: now - 1);
      expect(dec.pqOfferPayload, isNull, reason: 'nothing due yet at $k');
      final r = await off.takePqOfferPayload(nowMs: now);
      expect(r, isNotNull, reason: 'retry $k');
      expect(pendingKey(off), first, reason: 'retry $k is the same key');
    }
    // A whole re-key interval since the first offer: given up.
    final fresh = await off.takePqOfferPayload(nowMs: t1 + hour);
    expect(fresh, isNotNull);
    expect(pendingKey(off), isNot(first), reason: 'a fresh key');
    expect(off.pq.offerGen, 1, reason: 'for the SAME generation');
    expect(off.pq.staleSeeds.length, 1);
    expect(await offeredKey(enc, fresh!), pendingKey(off));
    // This one arrives.
    await enc.decrypt(fresh, nowMs: t1 + hour);
    expect(enc.pqGeneration, 1);
    final m = await enc.encrypt(utf8b('g1'), nowMs: t1 + hour + 1);
    expect(headerOf(m)['pqg'], 1);
    await off.decrypt(m, nowMs: t1 + hour + 1);
    expect(off.pqGeneration, 1);
    expect(off.pq.k, enc.pq.k);
    expect(off.pq.dkSeed, isNull, reason: 'erased once used');
    expect(off.pq.staleSeeds, isEmpty, reason: 'and so are the abandoned ones');
  });

  test('4. a late answer to the abandoned key still establishes', () async {
    final (enc, off) = await pair();
    await establish(enc, off, t0);
    final t1 = t0 + hour;
    // Something the peer sent before the offer reached it, still in flight.
    final inFlight = await enc.encrypt(utf8b('sent before'), nowMs: t1);
    final a = await off.takePqOfferPayload(nowMs: t1);
    // The offer DID reach the peer, which encapsulated to it...
    await enc.decrypt(a!, nowMs: t1 + 1);
    expect(enc.pqGeneration, 1);
    // ...but all the offerer hears for an interval is the old message.
    await off.decrypt(inFlight, nowMs: t1 + 2);
    final b = await off.takePqOfferPayload(nowMs: t1 + hour + 2);
    expect(b, isNotNull, reason: 'abandoned: the peer talked and never answered');
    // The fresh offer reaches the peer, which has moved on and ignores it,
    // exactly as a peer from before this change does.
    await enc.decrypt(b!, nowMs: t1 + hour + 3);
    expect(enc.pqGeneration, 1);
    // Its answer to the FIRST key now arrives — and establishes.
    final late = await enc.encrypt(utf8b('answer to the first key'),
        nowMs: t1 + hour + 4);
    expect(headerOf(late)['pqct'], isNotNull);
    final r = await off.decrypt(late, nowMs: t1 + hour + 4);
    expect(utf8.decode(r.plaintext), 'answer to the first key');
    expect(off.pqGeneration, 1);
    expect(off.pq.k, enc.pq.k);
    expect(off.pq.dkSeed, isNull);
    expect(off.pq.staleSeeds, isEmpty);
  });

  test('5. a silent peer is offered the same key, never a fresh one',
      () async {
    final (enc, off) = await pair();
    await establish(enc, off, t0);
    final t1 = t0 + hour;
    expect(await off.takePqOfferPayload(nowMs: t1), isNotNull); // lost
    final key = pendingKey(off);
    // Nothing from the peer for five intervals.
    final r = await off.takePqOfferPayload(nowMs: t1 + 5 * hour);
    expect(r, isNotNull, reason: 'it is still said again');
    expect(pendingKey(off), key, reason: 'but it is the same key');
    expect(off.pq.staleSeeds, isEmpty);
    await enc.decrypt(r!, nowMs: t1 + 5 * hour);
    await off.decrypt(await enc.encrypt(utf8b('back'), nowMs: t1 + 5 * hour),
        nowMs: t1 + 5 * hour);
    expect(off.pqGeneration, 1);
  });

  test('6. the previous generation lives 72 hours past the crossover, no more',
      () async {
    expect(pqCrossoverMs, 72 * hour, reason: 'the relay queue lifetime');
    final (enc, off) = await pair();
    await establish(enc, off, t0);
    final t1 = t0 + hour;
    // Two generation-0 messages from the encapsulator, delayed in the network.
    final lateA = await enc.encrypt(utf8b('late A'), nowMs: t1);
    final lateB = await enc.encrypt(utf8b('late B'), nowMs: t1);
    // Two from the offerer, likewise.
    final offLateA = await off.encrypt(utf8b('off late A'), nowMs: t1);
    final offLateB = await off.encrypt(utf8b('off late B'), nowMs: t1);
    // A full rotation to generation 1, both sides seeing the other on it.
    await enc.decrypt((await off.takePqOfferPayload(nowMs: t1))!, nowMs: t1);
    await off.decrypt(await enc.encrypt(utf8b('g1'), nowMs: t1), nowMs: t1);
    await enc.decrypt(await off.encrypt(utf8b('g1 back'), nowMs: t1),
        nowMs: t1);
    expect(off.pqGeneration, 1);
    expect(enc.pqGeneration, 1);
    expect(off.pq.oldK, isNotNull);
    expect(enc.pq.oldK, isNotNull);

    // Inside the window the old generation still decrypts...
    expect(utf8.decode((await off.decrypt(lateA, nowMs: t1 + 71 * hour)).plaintext),
        'late A');
    expect(
        utf8.decode(
            (await enc.decrypt(offLateA, nowMs: t1 + 71 * hour)).plaintext),
        'off late A');
    // ...and past it, it is gone: refused, and the secret erased.
    await expectLater(off.decrypt(lateB, nowMs: t1 + 72 * hour),
        throwsA(isA<RatchetDecryptException>()));
    await expectLater(enc.decrypt(offLateB, nowMs: t1 + 72 * hour),
        throwsA(isA<RatchetDecryptException>()));
    expect(off.pq.oldK, isNull);
    expect(enc.pq.oldK, isNull);
    // The current generation is untouched.
    final now = await enc.encrypt(utf8b('still fine'), nowMs: t1 + 73 * hour);
    expect(
        utf8.decode((await off.decrypt(now, nowMs: t1 + 73 * hour)).plaintext),
        'still fine');
  });

  test('7. a classical message after the peer has mixed is refused', () async {
    final (enc, off) = await pair(intervals: PqIntervals.disabled);
    // The offerer speaks classically before it holds K: two such messages are
    // still in flight when the secret is established.
    final r1 = await off.decrypt(await enc.encrypt(utf8b('hi'), nowMs: t0),
        nowMs: t0);
    final straggler1 = await off.encrypt(utf8b('classical 1'), nowMs: t0);
    final straggler2 = await off.encrypt(utf8b('classical 2'), nowMs: t0);
    await enc.decrypt(r1.pqOfferPayload!, nowMs: t0);
    await off.decrypt(await enc.encrypt(utf8b('m1'), nowMs: t0), nowMs: t0);
    final mixed = await off.encrypt(utf8b('mixed'), nowMs: t0);
    expect(headerOf(mixed)['pq'], 1);
    await enc.decrypt(mixed, nowMs: t0);

    // A classical message at a position the offerer reaches only now — what
    // a downgraded peer, or someone who can derive the classical chain keys,
    // would send. Made from a copy of the offerer with its secret removed.
    final down = await Conversation.fromJson(
        off.me, jsonDecode(jsonEncode(off.toJson())),
        intervals: PqIntervals.disabled);
    down.sessions[down.outboundSid]!.pq.k = null;
    final forged = await down.encrypt(utf8b('classical after mixing'), nowMs: t0);
    expect(headerOf(forged).containsKey('pq'), isFalse);
    await expectLater(enc.decrypt(forged, nowMs: t0 + 1),
        throwsA(isA<RatchetDecryptException>()));

    // A straggler the peer sent BEFORE it mixed still lands, inside 72 hours.
    expect(
        utf8.decode((await enc.decrypt(straggler1, nowMs: t0 + hour)).plaintext),
        'classical 1');
    // After them, not even that.
    await expectLater(enc.decrypt(straggler2, nowMs: t0 + 72 * hour + 1),
        throwsA(isA<RatchetDecryptException>()));
    // The conversation itself is unharmed by any of it.
    final ok = await off.encrypt(utf8b('carry on'), nowMs: t0 + 73 * hour);
    expect(
        utf8.decode((await enc.decrypt(ok, nowMs: t0 + 73 * hour)).plaintext),
        'carry on');

    // And a classical message already read, delivered again by the relay, is
    // still reported as the replay it is — not as a downgrade. That needs the
    // classical and the first mixed message on one chain, where a replay can
    // be recognised at all: the offer is read late, from the skipped keys,
    // so no ratchet step separates them.
    final (enc2, off2) = await pair(intervals: PqIntervals.disabled);
    final r = await off2.decrypt(await enc2.encrypt(utf8b('hi'), nowMs: t0),
        nowMs: t0);
    final heldOffer = r.pqOfferPayload!;
    await enc2.decrypt(await off2.encrypt(utf8b('m'), nowMs: t0), nowMs: t0);
    final e1 = await enc2.encrypt(utf8b('classical e1'), nowMs: t0);
    await off2.decrypt(e1, nowMs: t0);
    await enc2.decrypt(heldOffer, nowMs: t0); // from the skipped keys
    final e2 = await enc2.encrypt(utf8b('mixed e2'), nowMs: t0);
    expect(headerOf(e2)['pq'], 1);
    expect(headerOf(e2)['dh'], headerOf(e1)['dh'], reason: 'one chain');
    await off2.decrypt(e2, nowMs: t0);
    expect(off2.pq.classicalSkips, isNotNull, reason: 'seen mixing');
    await expectLater(off2.decrypt(e1, nowMs: t0 + 1),
        throwsA(isA<RatchetReplayException>()));
  });

  test('8. abandoned keys and the windows survive persistence', () async {
    var (enc, off) = await pair();
    await establish(enc, off, t0);
    Future<void> roundTrip() async {
      enc = await Conversation.fromJson(
          enc.me, jsonDecode(jsonEncode(enc.toJson())),
          intervals: iv);
      off = await Conversation.fromJson(
          off.me, jsonDecode(jsonEncode(off.toJson())),
          intervals: iv);
    }

    final t1 = t0 + hour;
    final inFlight = await enc.encrypt(utf8b('sent before'), nowMs: t1);
    final a = await off.takePqOfferPayload(nowMs: t1);
    await roundTrip();
    await enc.decrypt(a!, nowMs: t1 + 1);
    await off.decrypt(inFlight, nowMs: t1 + 2);
    await roundTrip();
    expect(await off.takePqOfferPayload(nowMs: t1 + hour + 2), isNotNull);
    expect(off.pq.staleSeeds.length, 1);
    await roundTrip();
    expect(off.pq.staleSeeds.length, 1, reason: 'the abandoned key is kept');
    await off.decrypt(await enc.encrypt(utf8b('g1'), nowMs: t1 + hour + 3),
        nowMs: t1 + hour + 3);
    expect(off.pqGeneration, 1);
    final crossover = off.pq.oldUntilMs;
    expect(crossover, t1 + hour + 3 + pqCrossoverMs);
    await roundTrip();
    expect(off.pq.oldUntilMs, crossover, reason: 'the deadline is persisted');
    expect(off.pq.classicalSkips, isNotNull,
        reason: 'and that the peer has been seen mixing');
  });
}
