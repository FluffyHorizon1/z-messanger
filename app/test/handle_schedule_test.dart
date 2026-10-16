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
//      with this device's salt, refuses it again under any kept day, keeps a
//      day until the fifth day after it begins, writes a day as rows of a
//      fixed number of digests — each row rewritten as it fills, then left
//      — and reads them back whole, the row being filled included; a day at
//      its cap remembers nothing more and says so; the tallies of what the
//      drains dropped go through the ledger's record, and what is not the
//      record reads as nothing;
//   9. the handle's record keeps the previous difficulty and its deadline
//      through a round trip, and reads none where there is none or where
//      it is out of range;
//  10. a day flooded with 500 000 distinct requests refuses every one of
//      them again and none of 20 000 it never saw, within 4 MiB; at the
//      day's cap the next request is filed unremembered, and still nothing
//      never seen is refused.
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

  test('8. the ledger: once per request, for five days, in rows; at the cap '
      'nothing more', () async {
    const dayMs = 86400000;
    const d = 20737;
    final rnd = Random(8);
    Uint8List h() =>
        Uint8List.fromList(List<int>.generate(32, (_) => rnd.nextInt(256)));

    final l = HandleStampLedger();
    final e1 = h();
    final g1 = await l.digestOf(e1);
    expect(g1, inInclusiveRange(0, (1 << 48) - 1));
    expect(await l.digestOf(e1), g1);
    expect(await HandleStampLedger().digestOf(e1), isNot(g1),
        reason: 'another salt, another digest');
    expect(l.refuses(g1), isFalse);
    final row = l.add(d, g1);
    expect(row, isNotNull);
    expect((row!.day, row.seq), (d, 0));
    expect(row.key, 'handle_stamps_${d}_0');
    expect(row.digests, [g1]);
    expect(l.refuses(g1), isTrue,
        reason: 'decided already, under whatever stamp it comes again');
    expect(l.add(d, g1), isNull, reason: 'held already: no row');
    expect(l.refuses(await l.digestOf(h())), isFalse);
    expect(l.add(d - 1, g1), isNotNull);
    expect(l.length, 2, reason: 'one entry for each day it was stamped for');

    // Kept until the fifth day after the stamp's day begins.
    expect(l.prune((d + 4) * dayMs - 1), isEmpty);
    expect(l.prune((d + 4) * dayMs), {d - 1: 1}, reason: 'd - 1 went');
    expect(l.refuses(g1), isTrue, reason: 'still held under d');
    expect(l.prune((d + 5) * dayMs - 1), isEmpty);
    expect(l.prune((d + 5) * dayMs), {d: 1});
    expect(l.refuses(g1), isFalse);
    expect(l.length, 0);

    // Rows: the one being filled is rewritten with each digest; full, it is
    // left and the next begins. Read back, every digest is held, and the
    // row being filled goes on filling under its own number.
    final rows = HandleStampLedger(chunk: 4, perDay: 10);
    final kept = <int>[];
    final written = <String, HandleStampChunk>{};
    for (var i = 0; i < 9; i++) {
      final g = await rows.digestOf(h());
      kept.add(g);
      final r = rows.add(d, g)!;
      written[r.key] = r;
      expect(r.seq, i ~/ 4);
      expect(r.digests, kept.sublist(4 * (i ~/ 4)));
    }
    expect(written.keys, ['handle_stamps_${d}_0', 'handle_stamps_${d}_1',
      'handle_stamps_${d}_2']);
    expect(written['handle_stamps_${d}_2']!.digests, hasLength(1));
    for (final g in kept) {
      expect(rows.refuses(g), isTrue);
    }
    expect(rows.bytesInMemory, 8 * 9);

    final back = HandleStampLedger(
        salt: rows.salt, chunk: 4, perDay: 10, chunks: written.values);
    expect(back.length, 9);
    for (final g in kept) {
      expect(back.refuses(g), isTrue, reason: 'read back whole');
    }
    expect(back.refuses(await back.digestOf(h())), isFalse);
    final tenth = await back.digestOf(h());
    final r10 = back.add(d, tenth)!;
    expect(r10.seq, 2, reason: 'the row being filled goes on');
    expect(r10.digests, [kept.last, tenth]);
    expect(back.isFull(d), isTrue);
    expect(back.add(d, await back.digestOf(h())), isNull,
        reason: 'at the cap a day remembers nothing more');
    expect(back.isFull(d + 1), isFalse);
    expect(back.add(d + 1, await back.digestOf(h())), isNotNull);
    expect(back.prune((d + 5) * dayMs), {d: 3},
        reason: 'the rows a day had, so they can go too');

    // Rows read back with a row size other than theirs are still whole:
    // only the last row of a day can be the one being filled.
    final other = HandleStampLedger(
        salt: rows.salt, chunk: 512, chunks: written.values);
    expect(other.length, 9);
    for (final g in kept) {
      expect(other.refuses(g), isTrue);
    }
    expect(other.add(d, tenth)!.seq, 2);

    // The record: the salt and the tallies, through JSON.
    rows.tally(d).unstamped += 3;
    rows.tally(d).copies += 2;
    rows.tally(d + 1).unremembered += 1;
    final rec = HandleStampLedger.readJson(jsonDecode(jsonEncode(rows.toJson())));
    expect(rec, isNotNull);
    expect(rec!.salt, rows.salt);
    expect(rec.tallies[d]!.toJson(), [3, 2, 0]);
    expect(rec.tallies[d + 1]!.toJson(), [0, 0, 1]);
    final again = HandleStampLedger(salt: rec.salt, tallies: rec.tallies);
    expect(again.tallied.toJson(), [3, 2, 1]);
    expect(again.prune((d + 5) * dayMs), isEmpty);
    expect(again.tallied.toJson(), [0, 0, 1], reason: 'a day\'s tally goes with it');

    // Not the record: nothing.
    for (final junk in <Object?>[
      null,
      7,
      'x',
      {'v': 1, 'salt': b64url(rows.salt), 'days': {}},
      {'v': 2, 'tally': {}},
      {'v': 2, 'salt': 'short'},
    ]) {
      expect(HandleStampLedger.readJson(junk), isNull);
    }
    final odd = HandleStampLedger.readJson({
      'v': 2,
      'salt': b64url(rows.salt),
      'tally': {'x': [1, 1, 1], '$d': [1, 2], '${d + 1}': [1, 1, 1]},
    })!;
    expect(odd.tallies.keys, [d + 1], reason: 'a tally that is not one is skipped');
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

  test('10. a day flooded with 500 000: every one refused again, none never '
      'seen, within 4 MiB; at the cap, filed unremembered', () async {
    const d = 20737;
    final rnd = Random(10);
    // Digests are a keyed hash: uniform, as these are.
    int g() => rnd.nextInt(1 << 32) << 16 | rnd.nextInt(1 << 16);

    final l = HandleStampLedger();
    const flood = 500000;
    final held = <int>[];
    var rows = 0;
    for (var i = 0; i < flood; i++) {
      final x = g();
      final r = l.add(d, x);
      if (r == null) continue; // one in 2⁴⁸: two of the flood share a digest
      held.add(x);
      if (r.digests.length == l.chunk) rows++;
    }
    expect(held.length, greaterThanOrEqualTo(flood - 2));
    expect(l.isFull(d), isFalse, reason: 'the cap is above a day\'s flood');
    expect(l.length, held.length);
    expect(rows, held.length ~/ l.chunk, reason: 'a row of ${l.chunk} each');
    expect(l.bytesInMemory, lessThanOrEqualTo(4 << 20));
    expect(held.where(l.refuses), hasLength(held.length),
        reason: 'no request it decided is ever filed again');
    const trials = 20000;
    final wrong = [for (var i = 0; i < trials; i++) g()].where(l.refuses).length;
    // 500 000 / 2⁴⁸ a trial: none expected in twenty thousand.
    expect(wrong, 0, reason: '$wrong of $trials never seen were refused');

    // At the cap: filed unremembered, and still nothing never seen refused.
    final capped = HandleStampLedger(perDay: 1000);
    for (var i = 0; i < 1000; i++) {
      expect(capped.add(d, g()), isNotNull);
    }
    expect(capped.isFull(d), isTrue);
    final more = g();
    expect(capped.add(d, more), isNull);
    expect(capped.refuses(more), isFalse,
        reason: 'unremembered: it could be filed again, and is not refused');
    expect([for (var i = 0; i < trials; i++) g()].where(capped.refuses),
        isEmpty);
  });
}
