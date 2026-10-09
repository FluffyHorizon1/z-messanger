// Handles in the app (phase 38): the numbers PROTOCOL §21.8 gives the
// client, as the pure functions that apply them — when a claim is
// published, when the introduction mailbox is drained, which pending handle
// requests the cap drops — and what a restore makes of a backup's handle
// record. No relay and no log: `handle_flow_test.dart` is the end to end.
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
//      archive restored, and nothing of a part that is malformed.
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
}
