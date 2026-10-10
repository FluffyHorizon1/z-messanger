// Handles in the app (phase 38): the numbers PROTOCOL §21.8 gives the
// client, as the pure functions that apply them — when a claim is
// published, when the introduction mailbox is drained, which pending handle
// requests the cap drops, what stamp the owner's drain counts and for how
// long it remembers one — and what a restore makes of a backup's handle
// record. No relay and no log: `handle_flow_test.dart` and
// `handle_inbox_test.dart` are the end to end.
//
// Criteria, each a test below:
//   1. a claim is published at a moment uniform in [10, 60] minutes after it
//      is confirmed: never outside, and the window is used, not a corner;
//   2. a claim whose moment passed while the app was closed is published at
//      a moment drawn again in [3, 20] minutes after the start, and one whose
//      moment is still ahead keeps it;
//   3. the mailbox is drained every 15 minutes give or take a third, and the
//      first drain after the app comes to the foreground waits 3 to 30
//      seconds — never outside either window;
//   4. the cap: at 100 pending handle requests nothing goes; past it the
//      oldest UNSEEN goes first, a seen request is kept over a newer unseen
//      one, and when every older request has been seen the newest is the
//      one dropped;
//   5. a backup's handle record restores a published handle as it was, a
//      claim that was waiting to be published as held (a restore publishes
//      nothing by itself), the requests' records only for requests the
//      archive restored, and nothing of a part that is malformed;
//   6. the stamp the owner's drain counts is the relay's: the bits of the
//      protocol's own `introPowInput` for the mailbox, `powDay`, the
//      envelope and the nonce — and nothing at all for no `pow`, a `pow`
//      that is not the canonical 22 characters, or a `powDay` that is not
//      the relay's day of `ts` or the day before;
//   7. the difficulty a stamp must reach is the published one; after a
//      raise the previous one counts for two days and not a moment longer,
//      and after a lowering the new one counts at once;
//   8. the ledger of decided requests knows an envelope by a digest keyed
//      with this device's salt, refuses it again under any day, keeps a day
//      until 48 hours after its stamps stop being good (the end of the next
//      day), and past its count for a day turns that day into a filter that
//      still refuses every one it held; a round trip through the vault's
//      JSON keeps all of it, and one that is not the ledger reads as empty;
//   9. the handle's record keeps the previous difficulty and its deadline
//      through a round trip, and reads none where there is none or where
//      it is out of range;
//  10. a day's filter holding 100 000 envelopes refuses every one of them,
//      and an envelope it never saw less than 1 % of the time.
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/handles.dart';

HandleRequestMeta meta(int seq, {bool seen = false}) => HandleRequestMeta(
    handle: 'alice.42',
    introRid: 'rid',
    creqId: Uint8List(32),
    at: seq,
    seq: seq,
    seen: seen);

void main() {
  test('1. a claim is published uniformly 10 to 60 minutes after it is confirmed',
      () {
    final r = Random(38);
    final draws = [
      for (var i = 0; i < 4000; i++)
        handleUniform(r, handleClaimDelayMin, handleClaimDelayMax)
    ];
    expect(handleClaimDelayMin, const Duration(minutes: 10));
    expect(handleClaimDelayMax, const Duration(minutes: 60));
    for (final d in draws) {
      expect(d, greaterThanOrEqualTo(handleClaimDelayMin));
      expect(d, lessThanOrEqualTo(handleClaimDelayMax));
    }
    final ms = draws.map((d) => d.inMilliseconds).toList()..sort();
    // Uniform: the extremes are near the ends and the median near the middle.
    expect(ms.first, lessThan(const Duration(minutes: 11).inMilliseconds));
    expect(ms.last, greaterThan(const Duration(minutes: 59).inMilliseconds));
    expect(ms[ms.length ~/ 2],
        inInclusiveRange(const Duration(minutes: 32).inMilliseconds,
            const Duration(minutes: 38).inMilliseconds));
  });

  test('2. a moment that passed while closed is drawn again after the start',
      () {
    final r = Random(7);
    const now = 1791500000000;
    for (var i = 0; i < 1000; i++) {
      final passed = handlePublishAtAfterStart(now - 1, now, r);
      expect(passed - now,
          inInclusiveRange(handleStartDelayMin.inMilliseconds,
              handleStartDelayMax.inMilliseconds));
      final never = handlePublishAtAfterStart(null, now, r);
      expect(never - now,
          inInclusiveRange(handleStartDelayMin.inMilliseconds,
              handleStartDelayMax.inMilliseconds));
    }
    expect(handlePublishAtAfterStart(now + 5000, now, r), now + 5000,
        reason: 'a moment still ahead is kept');
    expect(handleStartDelayMin, const Duration(minutes: 3));
    expect(handleStartDelayMax, const Duration(minutes: 20));
  });

  test('3. drains: every 15 minutes give or take a third; 3 to 30 s after the foreground',
      () {
    final r = Random(15);
    expect(handleDrainEvery, const Duration(minutes: 15));
    var lo = 1 << 62, hi = 0;
    for (var i = 0; i < 4000; i++) {
      final d = handleJittered(r, handleDrainEvery).inMilliseconds;
      expect(d, inInclusiveRange(const Duration(minutes: 10).inMilliseconds,
          const Duration(minutes: 20).inMilliseconds));
      lo = min(lo, d);
      hi = max(hi, d);
      final f =
          handleUniform(r, handleForegroundDelayMin, handleForegroundDelayMax);
      expect(f, greaterThanOrEqualTo(const Duration(seconds: 3)));
      expect(f, lessThanOrEqualTo(const Duration(seconds: 30)));
    }
    expect(lo, lessThan(const Duration(minutes: 10, seconds: 30).inMilliseconds));
    expect(hi, greaterThan(const Duration(minutes: 19, seconds: 30).inMilliseconds));
  });

  test('4. the cap keeps 100, dropping the oldest unseen first', () {
    expect(handleInboundCap, 100);
    final held = {for (var i = 1; i <= 100; i++) 'r$i': meta(i)};
    expect(handleRequestsToEvict(held), isEmpty, reason: 'at the cap, none');

    held['r101'] = meta(101);
    expect(handleRequestsToEvict(held), ['r1'], reason: 'the oldest unseen');

    // The oldest three were seen: the first unseen after them goes.
    for (final r in ['r1', 'r2', 'r3']) {
      held[r]!.seen = true;
    }
    expect(handleRequestsToEvict(held), ['r4']);

    // Two over: the two oldest unseen, in arrival order.
    held['r102'] = meta(102);
    expect(handleRequestsToEvict(held), ['r4', 'r5']);

    // Every older request seen: the newcomer is the one dropped.
    final seenAll = {for (var i = 1; i <= 100; i++) 'r$i': meta(i, seen: true)}
      ..['new'] = meta(101);
    expect(handleRequestsToEvict(seenAll), ['new']);

    // A smaller cap, to show the order is by arrival and not by key.
    final mixed = {'b': meta(2), 'a': meta(3), 'c': meta(1)};
    expect(handleRequestsToEvict(mixed, cap: 1), ['c', 'b']);
  });

  test('5. a backup\'s handle record: held, filtered, shape-checked', () async {
    final label = Uint8List(32)..fillRange(0, 32, 7);
    final own = OwnHandle(
      handle: Handle.parse('alice.42'),
      label: label,
      ownerSeed: Uint8List(32)..fillRange(0, 32, 1),
      introSeed: Uint8List(32)..fillRange(0, 32, 2),
      pow: 20,
      rc: Uint8List(32)..fillRange(0, 32, 3),
      version: 0,
      phase: HandlePhase.pending,
      publishAt: 1791500000000,
    );
    final kept = meta(1);
    final record = {
      't': 'handle',
      'keep': 1,
      'v': 1,
      'kv': {
        'handle': own.toJson(),
        'handle_in': {
          'reqs': {
            'restored': kept.toJson(),
            'not-restored': meta(2).toJson(),
            'broken': {'h': 'not a handle!', 'intro': 'x', 'id': 'AA', 'at': 1, 'seq': 3},
          },
          'seeds': {'old': b64(Uint8List(32)), 'short': b64(Uint8List(5))},
        },
        'handle_out': [
          {
            'h': 'bob.07',
            'owner': b64(Uint8List(32)),
            'intro': b64(Uint8List(32)),
            'xintro': b64(Uint8List(32)),
            'ids': [b64(Uint8List(32))],
            'at': 5,
          },
          {'h': 'bob.07', 'owner': 'nope'},
        ],
        'handle_config': {'url': 'https://handles.example', 'pub': b64(Uint8List(32))},
      },
    };
    final out = HandleBackup.restore(record, {'restored'});
    final back = OwnHandle.fromJson(
        (jsonDecode(out['handle']!) as Map).cast<String, Object?>());
    expect(back.phase, HandlePhase.held,
        reason: 'a claim waiting to be published waits for the person');
    expect(back.publishAt, isNull);
    expect(back.handle.canonical, 'alice.42');
    expect(back.ownerSeed, own.ownerSeed);
    final inbound = jsonDecode(out['handle_in']!) as Map;
    expect((inbound['reqs'] as Map).keys, ['restored']);
    expect((inbound['seeds'] as Map).keys, ['old']);
    expect((jsonDecode(out['handle_out']!) as List), hasLength(1));
    expect(jsonDecode(out['handle_config']!),
        {'url': 'https://handles.example', 'pub': b64(Uint8List(32))});

    // A published handle comes back exactly as it was.
    own
      ..phase = HandlePhase.live
      ..version = 3
      ..publishAt = null;
    final live = HandleBackup.restore({
      't': 'handle',
      'keep': 1,
      'v': 1,
      'kv': {'handle': own.toJson()}
    }, const {});
    expect(jsonDecode(live['handle']!), own.toJson());

    // Malformed: nothing of it is written.
    final bad = HandleBackup.restore({
      't': 'handle',
      'keep': 1,
      'v': 1,
      'kv': {
        'handle': {...own.toJson(), 'owner': b64(Uint8List(31))},
        'handle_out': 'not a list',
      }
    }, const {});
    expect(bad.containsKey('handle'), isFalse);
    expect(bad.containsKey('handle_out'), isFalse);
  });

  test('6. the stamp the owner counts is the one the relay counted', () async {
    final intro = await handleIntroIdentity(Uint8List(32)..fillRange(0, 32, 4));
    final rid = await intro.routingId();
    const payload = 'zs1.not-really-sealed-but-any-string-will-do';
    const ts = 1791600000000; // the relay's clock when it took the envelope
    final day = introPowDay(ts);
    final nonce = createIntroPowStamp(
        introRid: rid, day: day, envelope: utf8.encode(payload), bits: 12);
    final pow = b64url(nonce);

    // The bits, computed from the protocol library's own input.
    final want = introPowZeroBits(await sha256Bytes(introPowInput(
        ridBytes: unb64url(rid),
        day: day,
        envelopeHash: await sha256Bytes(utf8.encode(payload)),
        nonce: nonce)));
    final got = (await handleStampOf(
        introRid: rid, payload: payload, pow: pow, powDay: day, serverTs: ts))!;
    expect(got.bits, want);
    expect(got.bits, greaterThanOrEqualTo(12));
    expect(got.day, day);
    expect(got.envelopeHash, await sha256Bytes(utf8.encode(payload)));
    // Yesterday's stamp, taken just after the relay's midnight, counts too.
    final y = createIntroPowStamp(
        introRid: rid, day: day - 1, envelope: utf8.encode(payload), bits: 12);
    expect(
        (await handleStampOf(
                introRid: rid,
                payload: payload,
                pow: b64url(y),
                powDay: day - 1,
                serverTs: ts))!
            .bits,
        greaterThanOrEqualTo(12));
    // Another envelope under this stamp: almost no bits.
    final other = (await handleStampOf(
        introRid: rid,
        payload: '${payload}x',
        pow: pow,
        powDay: day,
        serverTs: ts))!;
    expect(other.bits, lessThan(12));

    Future<HandleStamp?> of({String? p = '', int? d = -9}) => handleStampOf(
        introRid: rid,
        payload: payload,
        pow: p == '' ? pow : p,
        powDay: d == -9 ? day : d,
        serverTs: ts);
    expect(await of(p: null), isNull, reason: 'no pow');
    expect(await of(d: null), isNull, reason: 'no powDay');
    expect(await of(p: '$pow='), isNull, reason: 'padded: not canonical');
    expect(await of(p: pow.substring(1)), isNull, reason: 'not 16 bytes');
    expect(await of(p: '!${pow.substring(1)}'), isNull, reason: 'not b64url');
    expect(await of(d: day - 2), isNull, reason: 'two days before ts');
    expect(await of(d: day + 1), isNull, reason: 'after the day of ts');
  });

  test('7. the difficulty in force, and two days of the previous one', () {
    const t = 1791600000000;
    const grace = 2 * 86400000;
    expect(handlePowGrace, const Duration(days: 2));
    expect(handleStampFloor(20, nowMs: t), 20);
    // Raised from 16 to 22 at t.
    expect(handleStampFloor(22, prevPow: 16, prevPowUntil: t + grace, nowMs: t),
        16);
    expect(
        handleStampFloor(22,
            prevPow: 16, prevPowUntil: t + grace, nowMs: t + grace - 1),
        16);
    expect(
        handleStampFloor(22,
            prevPow: 16, prevPowUntil: t + grace, nowMs: t + grace),
        22,
        reason: 'not a moment longer');
    // Lowered from 24 to 18: the lower one at once.
    expect(handleStampFloor(18, prevPow: 24, prevPowUntil: t + grace, nowMs: t),
        18);
  });

  test('8. the ledger: once per request, for its stamp\'s life and 48 h; '
      'past a day\'s count, a filter', () async {
    const dayMs = 86400000;
    const d = 20737;
    final noon = d * dayMs + dayMs ~/ 2;
    final rnd = Random(8);
    Uint8List h() =>
        Uint8List.fromList(List<int>.generate(32, (_) => rnd.nextInt(256)));

    final l = HandleStampLedger();
    final e1 = h();
    final g1 = await l.digestOf(e1);
    expect(g1, hasLength(16));
    expect(await l.digestOf(e1), g1);
    expect(await HandleStampLedger().digestOf(e1), isNot(g1),
        reason: 'another salt, another digest');
    expect(l.refuses(g1), isFalse);
    l.add(d, g1, noon);
    expect(l.refuses(g1), isTrue,
        reason: 'decided already, under whatever stamp it comes again');
    expect(l.refuses(await l.digestOf(h())), isFalse);
    l.add(d - 1, g1, noon);
    expect(l.length, 2, reason: 'one entry for each day it was stamped for');

    // Kept until (day + 4) days: the end of the next day, and 48 hours.
    expect(l.prune((d + 4) * dayMs - 1), isTrue, reason: 'yesterday\'s went');
    expect(l.refuses(g1), isTrue);
    expect(l.prune((d + 4) * dayMs), isTrue);
    expect(l.refuses(g1), isFalse);
    expect(l.length, 0);

    // One by one up to a day's count; one more and the day is a filter that
    // still refuses every one of them. Other days stay as they were.
    final small = HandleStampLedger(exactPerDay: 8);
    final kept = <Uint8List>[];
    for (var i = 0; i < 9; i++) {
      final g = await small.digestOf(h());
      kept.add(g);
      small.add(d, g, noon);
      expect(small.isFilter(d), i == 8);
    }
    final other = await small.digestOf(h());
    small.add(d + 1, other, noon);
    expect(small.isFilter(d + 1), isFalse);
    expect(small.length, 10);
    for (final g in kept) {
      expect(small.refuses(g), isTrue, reason: 'a filter forgets nothing');
    }
    small.add(d, kept.first, noon);
    expect(small.length, 10, reason: 'a digest it holds is not counted again');

    // Through the vault's JSON: the salt, the days, the filter.
    final back = HandleStampLedger.fromJson(
        jsonDecode(jsonEncode(small.toJson())),
        exactPerDay: 8);
    expect(back.salt, small.salt);
    expect(back.isFilter(d), isTrue);
    expect(back.isFilter(d + 1), isFalse);
    expect(back.length, 10);
    for (final g in [...kept, other]) {
      expect(back.refuses(g), isTrue);
    }
    expect(back.refuses(await back.digestOf(h())), isFalse);

    // Not a ledger: empty, with a salt of its own.
    for (final junk in <Object?>[
      null,
      7,
      'x',
      {'v': 2, 'salt': b64url(small.salt), 'days': {}},
      {'v': 1, 'days': {}},
      {'v': 1, 'salt': 'short', 'days': {}},
    ]) {
      final e = HandleStampLedger.fromJson(junk);
      expect(e.length, 0);
      expect(e.salt, hasLength(16));
      expect(e.salt, isNot(small.salt));
    }
    // A day that is not one: skipped, the rest kept.
    final mixed = HandleStampLedger.fromJson({
      ...back.toJson(),
      'days': {
        ...(back.toJson()['days'] as Map),
        'x': {'n': 1, 'k': []},
        '${d + 2}': {'n': 1, 'f': 'AAAA'},
        '${d + 3}': 5,
      },
    }, exactPerDay: 8);
    expect(mixed.length, 10);
    expect(mixed.refuses(other), isTrue);
  });

  test('9. the previous difficulty survives the handle\'s record', () {
    final o = OwnHandle(
      handle: Handle.parse('alice.42'),
      label: Uint8List(32),
      ownerSeed: Uint8List(32)..fillRange(0, 32, 1),
      introSeed: Uint8List(32)..fillRange(0, 32, 2),
      pow: 22,
      rc: Uint8List(32),
      version: 3,
      phase: HandlePhase.live,
      prevPow: 16,
      prevPowUntil: 1791600000000,
    );
    final back = OwnHandle.fromJson(
        (jsonDecode(jsonEncode(o.toJson())) as Map).cast<String, Object?>());
    expect(back.prevPow, 16);
    expect(back.prevPowUntil, 1791600000000);
    final none = OwnHandle.fromJson(
        {...o.toJson()}..remove('prevPow')..remove('prevUntil'));
    expect(none.prevPow, isNull);
    expect(none.prevPowUntil, isNull);
    final odd = OwnHandle.fromJson({...o.toJson(), 'prevPow': 3});
    expect(odd.prevPow, isNull, reason: 'out of range reads as none');
    expect(odd.prevPowUntil, isNull);
  });

  test('10. a day\'s filter at 100 000: every one refused, under 1 % of the '
      'rest', () {
    const dayMs = 86400000;
    const d = 20737;
    final noon = d * dayMs + dayMs ~/ 2;
    final rnd = Random(10);
    // Digests are a keyed hash: uniform, as these are.
    Uint8List g() =>
        Uint8List.fromList(List<int>.generate(16, (_) => rnd.nextInt(256)));

    final l = HandleStampLedger();
    final held = [for (var i = 0; i < 100000; i++) g()];
    for (final x in held) {
      l.add(d, x, noon);
    }
    expect(l.isFilter(d), isTrue);
    expect(held.where(l.refuses), hasLength(held.length),
        reason: 'no envelope it was given is ever let through again');
    const trials = 20000;
    final wrong = [for (var i = 0; i < trials; i++) g()].where(l.refuses).length;
    // (1 − e^(−6·100000/2^20))^6 ≈ 0.68 %.
    expect(wrong, lessThan(trials ~/ 100),
        reason: '$wrong of $trials never seen were refused');
    expect(wrong, greaterThan(0),
        reason: 'a filter this full does make mistakes; this test sees them');
  });
}
