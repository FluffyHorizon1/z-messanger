// REVIEW D probe (phase 41, receipt timing), kept as a regression guard: the
// "no sooner than 5 s" floor (ADR 0028 / THREAT_MODEL R41) must be measured on
// a MONOTONIC clock, not the wall clock. A forward wall-clock jump — sleep/wake,
// an NTP step, the user setting the time, all routine on mobile — must NOT make
// a held receipt "past its floor" before the real 5 s has elapsed. The riding
// path (_sendInner -> _receipts.anyEligible -> _releaseReceipts(riding:true) ->
// take(all:false)) and the timer-fire path both consult exactly these two
// methods, so a wall jump that made them return early would release a receipt
// inside its real floor in the product — re-opening the Signal/Martiny timing
// link the floor exists to blunt.
//
// Only the wall clock is injected here (`now`), as the queue's constructor has
// always allowed; the monotonic floor runs on the queue's own clock, which
// barely advances across this synchronous test (no awaits, no delays), so the
// jump below moves wall time without moving real time. At 9939882, where the
// floor was wall-clock, the post-jump assertions fail — the receipt is eligible
// ~1 s after delivery; with the monotonic floor they pass.
//
// Run: flutter test --concurrency=1 test/review_d_receipt_clockjump_probe_test.dart
import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/receipts.dart';

void main() {
  test('a forward wall-clock jump does not release a receipt inside its real '
      'floor', () {
    var clock = 1000000; // our stand-in wall clock, in ms
    final q = ReceiptQueue(
        timing: const ReceiptTiming(
            floor: Duration(seconds: 5), ceiling: Duration(seconds: 60)),
        now: () => clock);

    // A message from Alice is delivered "now"; a delivery receipt is owed.
    q.owe('alice', 'mid1', read: false);

    // 1 s of REAL time passes: well inside the 5 s floor.
    clock += 1000;
    expect(q.anyEligible('alice'), isFalse,
        reason: 'inside the real 5 s floor it must not be eligible');

    // The wall clock steps forward by an hour (an NTP correction of a slow
    // clock, or the user changing the time). No more real time has passed.
    clock += 3600 * 1000;

    // The floor is monotonic, so the wall jump buys nothing: ~1 s of real time
    // after the delivery, the receipt is still inside its floor.
    expect(q.anyEligible('alice'), isFalse,
        reason: 'a forward wall-clock jump must not make a held receipt '
            'eligible before its real 5 s floor has elapsed');
    final taken = q.take('alice');
    expect(taken.delivered, isNot(contains('mid1')),
        reason: 'a message the user sends Alice now must NOT carry this '
            'receipt, which would pair it with its delivery for the relay '
            '(the attack ADR 0028 closes) within the real floor');

    // And it was not silently dropped by the floor check: the receipt is still
    // held, to leave once its real floor has truly elapsed.
    expect(q.count(), 1,
        reason: 'the receipt is held, not discarded, by the floor');
  });
}
