// The rules a private transparency refresh follows, on their own (phase 35;
// ADR 0023's client policy, PROTOCOL §19.9.1) — what k a count of the log's
// labels allows, how a fresh install makes that count, and what coming back
// to the front does to the schedule. `kt_private_lookup_test.dart` runs them
// against the real log and relay.
//
// Criteria, each a test below:
//   1. k is never finer than the log's recommendation, the signed size or
//      the ceiling a count of labels sets — the finest k at which they fill
//      a bucket to sixteen — and a count moves that ceiling down at once,
//      up a bit at a time, and not at all while buckets at it hold 16 to 64;
//   2. a probe of random buckets starts at the finest k the signed size
//      allows and goes coarser by what each bucket fell short of 32 labels;
//      on logs whose size versions have inflated thirtyfold, the ceiling it
//      sets never binds an honest recommendation and never lets buckets hold
//      fewer than eight labels on average;
//   3. coming back to the front plans again from the clock: a window's
//      moment that went by unseen is caught up between `catchUpMin` and
//      `catchUpMax` later, never at that instant; a moment still ahead
//      stands; and a refresh the user starts is that window's, the next
//      one planned in the next window.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/key_transparency.dart';
import 'package:zapp/core/kt_private_lookups.dart';
import 'package:zapp/core/vault.dart';
import 'package:z_protocol/z_protocol.dart';

/// A client with no contacts and no account: what is under test is when it
/// asks, not what.
class _NoHost implements KtHost {
  @override
  Future<List<KtContactInput>> ktContacts() async => const [];
  @override
  Future<KtOwnInput?> ktOwn() async => null;
  @override
  Future<bool> ktInstallFromLog(String rid, SignedDeviceList list) async =>
      false;
  @override
  void ktChanged() {}
}

/// Remembers every request and answers each with a failure.
class _CountingFetcher implements KtFetcher {
  final List<Uri> asked = [];
  @override
  Future<KtResponse> get(Uri url) async {
    asked.add(url);
    return KtResponse(500, '{}');
  }

  @override
  Future<KtResponse> post(Uri url, String jsonBody) async {
    asked.add(url);
    return KtResponse(500, '{}');
  }
}

/// A Poisson count with mean [mean]: how many of a log's labels fall in one
/// bucket drawn at random.
int poisson(Random r, double mean) {
  if (mean < 30) {
    final limit = exp(-mean);
    var k = 0;
    var p = r.nextDouble();
    while (p > limit) {
      k++;
      p *= r.nextDouble();
    }
    return k;
  }
  // Box–Muller: the normal a large mean's Poisson is.
  final g = sqrt(-2 * log(1 - r.nextDouble())) * cos(2 * pi * r.nextDouble());
  return max(0, (mean + sqrt(mean) * g).round());
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  Future<void> waitUntil(FutureOr<bool> Function() cond,
      {Duration timeout = const Duration(seconds: 10),
      required String what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
  }

  test(
      '1. k is never finer than the recommendation, the signed size or the '
      'ceiling a count of labels sets', () {
    // The ceiling: the finest k at which the labels fill a bucket to 16.
    expect(ktCeilingFor(0), 0);
    expect(ktCeilingFor(31), 0);
    expect(ktCeilingFor(32), 1);
    expect(ktCeilingFor(2047), 6);
    expect(ktCeilingFor(2108), 7, reason: 'the fixture\'s log: 16.5 a bucket');
    expect(ktCeilingFor(20600), 10, reason: 'the live log: 20 a bucket');
    expect(ktCeilingFor(1 << 40), ktMaxBucketBits);
    // One bit finer than the log's own rule, ⌊log₂(labels / 32)⌋: an honest
    // recommendation is never held back by a count that is right.
    for (final labels in [64, 100, 2108, 20600, 300000]) {
      final honest = labels.bitLength - 1 - 5;
      expect(ktCeilingFor(labels), honest + 1);
      expect(ktCeilingFor(labels ~/ 2), greaterThanOrEqualTo(honest),
          reason: 'nor by one that is half of it');
    }
    // The size counts entries: it bounds k, and versions loosen the bound.
    expect(ktSizeBits(63), 0);
    expect(ktSizeBits(22094), 9);
    expect(ktSizeBits(66100), 11, reason: 'the review\'s 2,108 labels at '
        '66,100 entries');
    // k: the least of the three.
    expect(ktRefreshBits(recommended: 24, headSize: 66100, ceiling: 7), 7);
    expect(ktRefreshBits(recommended: 6, headSize: 66100, ceiling: 7), 6);
    expect(ktRefreshBits(recommended: 24, headSize: 2108, ceiling: 7), 6);
    expect(ktRefreshBits(recommended: null, headSize: 66100, ceiling: 7), 0);
    // A count of labels moves the ceiling down at once to what it bears out,
    // up a bit at a time, and not at all while buckets at it would hold 16
    // to 64: the noise in a count does not move every bucket asked.
    expect(ktNextCeiling(null, 2048), 7, reason: 'the first count');
    expect(ktNextCeiling(11, 2048), 7, reason: 'a label a bucket at 11: down');
    expect(ktNextCeiling(7, 2048), 7, reason: '16 a bucket');
    expect(ktNextCeiling(7, 2047), 6, reason: 'just under 16: down at once');
    expect(ktNextCeiling(6, 2200), 6, reason: '34 a bucket: kept, not 7');
    expect(ktNextCeiling(6, 8192), 7, reason: '128 a bucket: one bit, not 9');
    expect(ktNextCeiling(7, 8192), 8);
    expect(ktNextCeiling(8, 8192), 8, reason: '32 a bucket: kept');
    expect(ktNextCeiling(23, 1 << 40), 24);
    expect(ktNextCeiling(24, 1 << 40), 24);
  });

  test(
      '2. a probe goes coarser by the shortfall, and the ceiling it sets '
      'neither binds an honest recommendation nor lets buckets thin out',
      () {
    expect(ktProbeNext(11, 32), isNull, reason: 'a bucket of 32: done');
    expect(ktProbeNext(0, 3), isNull, reason: 'k = 0: nothing coarser');
    expect(ktProbeNext(11, 0), 6, reason: 'empty: five bits coarser');
    expect(ktProbeNext(11, 1), 6);
    expect(ktProbeNext(11, 2), 7);
    expect(ktProbeNext(11, 16), 10);
    expect(ktProbeNext(11, 31), 10);
    expect(ktProbeNext(3, 1), 0);
    // A thousand fresh installs against logs whose operator has inflated
    // the size thirtyfold with versions: each probes from the finest k that
    // size allows, a random bucket at a time, as the client does.
    final r = Random(2);
    for (final labels in [300, 2108, 20600, 250000]) {
      final honest = max(0, labels.bitLength - 1 - 5);
      final start = ktSizeBits(labels * 30);
      var bound = 0;
      var thinnest = double.infinity;
      var steps = 0;
      for (var t = 0; t < 1000; t++) {
        var bits = start;
        int? ceiling;
        for (var s = 0; s < ktProbeSteps; s++) {
          steps = max(steps, s + 1);
          final count = poisson(r, labels / (1 << bits));
          final next = ktProbeNext(bits, count);
          if (next == null) {
            ceiling = ktCeilingFor(count << bits);
            break;
          }
          bits = next;
        }
        expect(ceiling, isNotNull,
            reason: '$labels labels: a probe ends within $ktProbeSteps');
        if (ceiling! < honest) bound++;
        thinnest = min(thinnest, labels / (1 << ceiling));
      }
      // ignore: avoid_print
      print('criterion 2: $labels labels, size ${labels * 30}: probes from '
          'k = $start in at most $steps; ceiling under the honest k $honest '
          'in $bound of 1000; thinnest buckets ${thinnest.toStringAsFixed(1)} '
          'labels');
      expect(bound, lessThanOrEqualTo(2),
          reason: 'an honest recommendation is followed');
      expect(thinnest, greaterThanOrEqualTo(8),
          reason: 'the inflated size never thins the buckets out');
    }
  });

  test(
      '3. coming back to the front catches up a moment that went by unseen, '
      'never at that instant', () async {
    const w = 6 * 3600 * 1000;
    final dir = await Directory.systemTemp.createTemp('z_ktr_front');
    addTearDown(() => dir.delete(recursive: true).catchError((_) => dir));
    final vault = await Vault.open(rootOverride: dir);
    addTearDown(() => vault.db.close());
    // An hour into a window, ten windows from now; the last refresh half an
    // hour before it began, and this window's moment three hours in.
    final base = (DateTime.now().millisecondsSinceEpoch ~/ w + 10) * w;
    final moment = base + 3 * 3600 * 1000;
    var clock = base + 3600 * 1000;
    await vault.kvPut(
        'kt_refresh',
        jsonEncode(KtRefreshSchedule(
                lastMs: base - 1800 * 1000, window: base ~/ w, atMs: moment)
            .toJson()));
    final f = _CountingFetcher();
    final kt = KeyTransparency(
      vault: vault,
      host: _NoHost(),
      fetcher: f,
      config: KtConfig(logUrl: 'http://127.0.0.1:1', logPubB64: b64(Uint8List(32))),
      now: () => clock,
    );
    addTearDown(kt.dispose);
    // Long enough that no real timer comes due while the test runs.
    kt.catchUpMin = const Duration(minutes: 2);
    kt.catchUpMax = const Duration(minutes: 3);
    kt.start();
    await waitUntil(() => kt.nextRefreshMs != null, what: 'a refresh planned');
    expect(kt.nextRefreshMs, moment, reason: 'a moment still ahead stands');
    await kt.onForeground();
    expect(kt.nextRefreshMs, moment, reason: 'and stands on coming back');

    // The app is put away before that moment and comes back two hours
    // after it, in the same window — five and a half hours since the last
    // refresh, so not a whole window: what makes it owed is the moment.
    clock = base + 5 * 3600 * 1000;
    await kt.onForeground();
    final owed = kt.nextRefreshMs!;
    expect(f.asked, isEmpty, reason: 'nothing at the instant it came back');
    final bounds = inInclusiveRange(
        kt.catchUpMin.inMilliseconds, kt.catchUpMax.inMilliseconds);
    expect(owed - clock, bounds,
        reason: 'caught up between the bounds, not drawn again for later');
    // Put away and back within those bounds: still a catch-up between them
    // from now — the one drawn, or one drawn again if it was nearer.
    clock += 30 * 1000;
    await kt.onForeground();
    expect(kt.nextRefreshMs! - clock, bounds);
    expect(f.asked, isEmpty);

    // A refresh the user starts (the contact screen's, or Settings') is this
    // window's: the next is planned in the next window, not as a second one
    // in this.
    await kt.check();
    await waitUntil(() => (kt.nextRefreshMs ?? 0) ~/ w == clock ~/ w + 1,
        what: 'the next refresh planned in the next window');
    expect(f.asked, isNotEmpty, reason: 'the refresh asked (and failed)');
  });
}
