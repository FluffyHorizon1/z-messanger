/// How this client asks the transparency log about its contacts without
/// naming them (phase 35; ADR 0023, "The client's refresh policy";
/// PROTOCOL.md §19.9.1). `key_transparency.dart` does the asking; this file
/// decides what to ask and when, and holds nothing that talks to the network,
/// so every rule here can be tested on its own.
///
/// Four decisions live here.
///
/// **What size.** A bucket is the labels sharing a contact's first k bits
/// (§19.9), and labels are what it hides the contact among. The log
/// recommends k as `bucketBits`, outside its signed head, and its signed size
/// counts entries, which anyone holding an account key — the operator first
/// — multiplies by publishing versions. Neither says how many labels there
/// are. So k is also held under a ceiling this client sets from labels it
/// counted itself, in buckets it verified complete: before its first refresh,
/// random buckets nothing chose ([ktProbeNext]); after every refresh, its
/// decoy buckets ([KtDecoys.observe]). The ceiling falls at once to what they
/// bear out, rises a bit a refresh at most, and between the two stays put
/// ([ktNextCeiling]).
///
/// **Which buckets.** A contact is checked through the bucket that holds its
/// label (§19.9) — about one label in 2^k — never through the label itself.
/// The buckets are padded with decoys to a multiple of [ktDecoyBlock], and the
/// decoys are kept: drawn once, stored sealed, asked again at every refresh
/// and carried in a backup. Fresh decoys at each refresh would be no decoys
/// at all, since what two refreshes have in common is exactly the real
/// buckets. A bucket once asked is not dropped while the log's k stays where
/// it was: a contact who is removed leaves their bucket behind as a decoy, so
/// the removal changes nothing the log sees; a contact whose bucket was
/// already asked changes nothing either; one whose bucket was not arrives in
/// a block of [ktDecoyBlock] new buckets, of which it is one.
///
/// **Which entries.** A bucket says which entry is each label's latest, not
/// what it holds; a contact whose entry moved needs that entry's value, asked
/// by index (`POST /kt/v1/entries`). What is fetched does not depend on which
/// contacts moved, or on whether any did: every entry in the asked buckets
/// this client had not seen at its last refresh, made up to [ktEntryFloor]
/// with others from them in an order this install's key fixes — or every
/// entry in the asked buckets, when a needed one is in neither (one added in
/// a bucket already asked), and when there is no last refresh to compare
/// against (a first refresh, a restore, another log). Past [ktMaxEntries] it
/// is those needed and a sample of the rest in an order this install's key
/// and the needed set fix: asked again, the same fetch; needing other
/// entries, an unrelated one.
///
/// **When.** One refresh in each window of [KeyTransparency.checkEvery], at a
/// random moment in it — never at the instant the app starts or comes to the
/// front, and never because a contact's list changed (a refresh 30 seconds
/// after a contact publishes would tell the log, by its timing alone, whose
/// contact this is). A window whose moment went by while the app was not
/// running — a phone suspends an app it is not showing — and a client with
/// no refresh for a whole window catch up between [ktCatchUpMin] and
/// [ktCatchUpMax] after the app is next in front: a phone used in short
/// visits is in front at a window's moment seldom, and a check that never
/// happens protects no one.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/dart.dart' show DartSha256;
import 'package:z_protocol/z_protocol.dart';

/// The bucket count is padded to a multiple of this: a client with one
/// contact and a client with sixteen ask the same number.
const int ktDecoyBlock = 16;

/// Buckets this client's own counts show to hold fewer labels than this, on
/// average, are too fine to hide a label in: the ceiling on k is the finest
/// at which they hold this many ([ktCeilingFor]). Half the lower end of what
/// the log recommends (§19.9), so an honest recommendation sits a bit under
/// the ceiling and a count that is a little low does not move what is asked.
const int ktMinBucketLeaves = 16;

/// A probe for the size of the log ([ktProbeNext]) stops at a random bucket
/// that proves this many labels, whose count is then seldom a third off. A
/// count as low as half the truth still leaves the ceiling at or above an
/// honest recommendation; one that is high lets the first refresh ask a bit
/// finer than the counts after it bear out, and they bring it back.
const int ktProbeLabels = 32;

/// At most this many random buckets in one probe; a log that has not shown a
/// bucket of [ktProbeLabels] by then is unreachable for that refresh.
const int ktProbeSteps = 8;

/// At most this many entries in one refresh's fetch (~1.5 MB of sealed
/// lists): past it, the needed ones and a sample of the rest.
const int ktMaxEntries = 1024;

/// Every fetch of entries is at least this many — the asked buckets' new
/// ones, made up with others from them — so a contact's entry is never
/// fetched alone. Sixteen sealed lists with their proofs are ~30 KB, about
/// half of what the sixteen buckets beside them cost.
const int ktEntryFloor = 16;

/// A refresh that is owed — its window's moment went by while the app was
/// not in front, or a whole window has passed without one — runs this long
/// after the app is next in front, at a random point between the two: never
/// at that instant, which would mark it, and within a half-minute visit.
const Duration ktCatchUpMin = Duration(seconds: 5);
const Duration ktCatchUpMax = Duration(seconds: 30);

const String _orderContext = 'z-kt-decoy-order-v1:';
const String _sampleContext = 'z-kt-entry-sample-v1:';

/// ⌊log₂(size / 32)⌋, at most 24 (0 below 64): the finest k at which a log
/// of [size] entries could still put 32 labels in a bucket. It holds at most
/// that many labels, and may hold far fewer: an account's versions are
/// entries too.
int ktSizeBits(int size) =>
    size < 64 ? 0 : min(ktMaxBucketBits, size.bitLength - 1 - 5);

/// The finest k at which [labels] labels fill a bucket to
/// [ktMinBucketLeaves] on average — ⌊log₂(labels / 16)⌋, at most 24 (0 below
/// 32): the ceiling a count of the log's labels sets.
int ktCeilingFor(int labels) => labels < 2 * ktMinBucketLeaves
    ? 0
    : min(ktMaxBucketBits, (labels ~/ ktMinBucketLeaves).bitLength - 1);

/// The ceiling after a count of [labels]: while buckets at it would hold
/// [ktMinBucketLeaves] to four times that on average, where it is — a
/// count's noise does not move what is asked, and every bucket asked moves
/// with k; under that, down at once to what the count bears out
/// ([ktCeilingFor]); at four times it or more, up by one bit, so a log that
/// fills with labels overnight, of its operator's minting or not, moves
/// what is asked a bit a refresh at most.
int ktNextCeiling(int? ceiling, int labels) {
  final bearsOut = ktCeilingFor(labels);
  if (ceiling == null) return bearsOut;
  final perBucket = labels >> ceiling;
  if (perBucket < ktMinBucketLeaves) return min(ceiling, bearsOut);
  if (perBucket >= 4 * ktMinBucketLeaves) {
    return min(ktMaxBucketBits, min(ceiling + 1, max(ceiling, bearsOut)));
  }
  return ceiling;
}

/// The k a refresh asks with: the log's recommendation (`bucketBits`), never
/// finer — never finer than the log's signed size allows ([ktSizeBits]),
/// since the recommendation is unsigned and the operator writes it, and
/// never finer than [ceiling], which this client's own counts of labels set:
/// the size counts entries, which the operator can multiply.
int ktRefreshBits({
  required int? recommended,
  required int headSize,
  required int ceiling,
}) {
  final k = min((recommended ?? 0).clamp(0, ktMaxBucketBits),
      ktSizeBits(headSize));
  return min(k, max(0, ceiling));
}

/// The k a probe asks next after a random bucket at [bits] proved [count]
/// labels — or null when that bucket is the estimate: it held
/// [ktProbeLabels], or [bits] is 0 and there is nothing coarser. Coarser by
/// as many bits as the count fell short (the least s with count · 2^s ≥ 32),
/// and by five for an empty bucket. A probe starts at the finest k the
/// signed size allows; its buckets are drawn at random each time and never
/// kept, so they say nothing of the contacts — the decoys would, since the
/// refresh that follows asks them beside the contacts' buckets.
int? ktProbeNext(int bits, int count) {
  if (count >= ktProbeLabels || bits <= 0) return null;
  var s = 5;
  if (count > 0) {
    s = 1;
    while (count << s < ktProbeLabels) {
      s++;
    }
  }
  return max(0, bits - s);
}

/// [prefix] (at [fromBits]) cut to its first [toBits] bits.
String _cut(String prefix, int fromBits, int toBits) =>
    ktBucketPrefix(ktParseBucketPrefix(prefix, fromBits)!, toBits);

/// 32 random bytes whose first [bits] bits are [prefix]'s: a decoy label
/// that lands in that bucket at [bits] and in a random one of its
/// descendants at any finer k.
Uint8List _within(Uint8List random32, Uint8List prefix, int bits) {
  final out = Uint8List.fromList(random32);
  for (var d = 0; d < bits; d++) {
    final mask = 1 << (7 - (d & 7));
    if (prefix[d >> 3] & mask != 0) {
      out[d >> 3] |= mask;
    } else {
      out[d >> 3] &= ~mask;
    }
  }
  return out;
}

/// The child of [q] one bit finer, on side [bit] — what a bucket the log
/// refuses as too large is asked as, both halves of it, so the two together
/// say no more than the bucket did.
KtBucketQuery ktChildBucket(KtBucketQuery q, int bit) {
  final p = ktParseBucketPrefix(q.prefix, q.bits)!;
  final mask = 1 << (7 - (q.bits & 7));
  if (bit == 1) p[q.bits >> 3] |= mask;
  return KtBucketQuery.parse(ktBucketPrefix(p, q.bits + 1), q.bits + 1);
}

/// This install's decoys and what it last asked — persisted, sealed, under
/// `kt_decoys`, and carried in a backup so a restore asks what the device it
/// came from asked, at the ceiling it had reached.
class KtDecoys {
  /// Orders the candidates for entry decoys ([ktEntriesToFetch]); never
  /// leaves this vault except in a backup.
  final Uint8List key;

  /// Decoy labels: 32 bytes each, mapped to buckets as a label is.
  final List<Uint8List> pool;

  /// The k of [asked], and the buckets the last refresh asked, sorted.
  int? bits;
  List<String> asked;

  /// The finest k this client's own counts of the log's labels bear out
  /// ([ktCeilingFor]); null until a probe has counted some, and again after
  /// a change of log.
  int? ceiling;

  KtDecoys({
    required this.key,
    required this.pool,
    this.bits,
    List<String>? asked,
    this.ceiling,
  }) : asked = asked ?? [];

  factory KtDecoys.fresh() => KtDecoys(key: randomBytes(32), pool: []);

  Map<String, Object?> toJson() => {
        'key': b64(key),
        'd': [for (final d in pool) b64(d)],
        if (bits != null) 'k': bits,
        'p': asked,
        if (ceiling != null) 'c': ceiling,
      };

  /// The stored form, or null when [text] is not one — a backup is a file
  /// that can come from anywhere, and this is read on every refresh.
  static KtDecoys? parse(String text) {
    try {
      final j = jsonDecode(text);
      if (j is! Map) return null;
      final key = unb64(j['key'] as String);
      final d = j['d'] as List;
      final p = j['p'] as List;
      final k = j['k'];
      final c = j['c'];
      if (key.length != 32 || d.length > 65536 || p.length > 65536) return null;
      if (k != null && (k is! int || k < 0 || k > ktMaxBucketBits)) return null;
      if (c != null && (c is! int || c < 0 || c > ktMaxBucketBits)) return null;
      final pool = <Uint8List>[];
      for (final x in d) {
        final v = unb64(x as String);
        if (v.length != 32) return null;
        pool.add(v);
      }
      final asked = <String>[];
      for (final x in p) {
        if (k is! int || x is! String || ktParseBucketPrefix(x, k) == null) {
          return null;
        }
        asked.add(x);
      }
      return KtDecoys(
          key: key, pool: pool, bits: k as int?, asked: asked, ceiling: c as int?);
    } catch (_) {
      return null;
    }
  }

  /// The buckets a refresh asks at [bits] for [labels]: every label's, and
  /// decoys, sorted by prefix so the order says nothing about which is which.
  /// Updates this state; the caller persists it before asking, so a refresh
  /// that fails is asked again the same way.
  List<KtBucketQuery> plan(Iterable<Uint8List> labels, int bits,
      {Uint8List Function(int n) random = randomBytes}) {
    final asked = <String>{
      for (final l in labels) ktBucketPrefix(l, bits),
      for (final d in pool) ktBucketPrefix(d, bits),
    };
    // A bucket the last refresh asked that nothing covers now held a contact
    // who has gone. It stays, as a decoy inside it: a bucket that vanished
    // would say which ones were real.
    final last = this.bits;
    if (last != null) {
      final up = last <= bits
          ? {for (final x in asked) _cut(x, bits, last)}
          : null;
      for (final p in this.asked) {
        final covered =
            up != null ? up.contains(p) : asked.contains(_cut(p, last, bits));
        if (covered) continue;
        final d = _within(random(32), ktParseBucketPrefix(p, last)!, last);
        pool.add(d);
        asked.add(ktBucketPrefix(d, bits));
      }
    }
    // Padded to the block, from decoys drawn now and kept from now on. A draw
    // that lands in a bucket already asked is not kept: it would change
    // nothing today, and at another k it would add a bucket nothing chose.
    final everyBucket = 1 << bits;
    final target = min(everyBucket,
        max(ktDecoyBlock, (asked.length + ktDecoyBlock - 1) ~/ ktDecoyBlock * ktDecoyBlock));
    var draws = 0;
    while (asked.length < target && draws++ < 1 << 20) {
      final d = random(32);
      if (asked.add(ktBucketPrefix(d, bits))) pool.add(d);
    }
    this.bits = bits;
    this.asked = asked.toList()..sort();
    return [for (final p in this.asked) KtBucketQuery.parse(p, bits)];
  }

  /// What the answers said about k. The buckets no contact is in are a fair
  /// sample of the log's buckets — they were drawn at random — and each was
  /// proved complete, so their mean size times 2^k counts the log's labels,
  /// whatever `bucketBits` claims and however many versions the size counts.
  /// The ceiling follows that count down at once and up a bit at a time, and
  /// not at all while it sits where buckets hold 16 to 64 ([ktNextCeiling]).
  void observe(List<KtVerifiedBucket> answered, Iterable<Uint8List> labels) {
    final k = bits;
    if (k == null) return;
    final real = {for (final l in labels) ktBucketPrefix(l, k)};
    var n = 0;
    var sum = 0;
    for (final b in answered) {
      if (b.query.bits != k || real.contains(b.query.prefix)) continue;
      n++;
      sum += b.leaves.length;
    }
    if (n == 0) return;
    ceiling = ktNextCeiling(ceiling, (sum << k) ~/ n);
  }
}

/// The entry indexes a refresh fetches (`POST /kt/v1/entries`), ascending:
/// every one in [needed], among others from the leaves of the buckets it
/// asked ([leaves], every index they hold). [seen] is the indexes those
/// buckets held at the last refresh, or null when there was none.
///
/// Up to [ktMaxEntries], the fetch is chosen without looking at [needed],
/// except to see that it holds them: every entry new since the last refresh
/// — contact or not, so a fetch is not a sign that a contact moved — made up
/// to [ktEntryFloor] with others from the asked buckets in the order [key]
/// gives, which is the same at every refresh. When a needed entry is not
/// among those (a contact added in a bucket already asked, whose entry is
/// old) or there is no last refresh at all, it is every entry in the asked
/// buckets. None of it depends on which contact moved, or whether one did:
/// two fetches set beside each other differ by what changed in the buckets,
/// and the entries made up with, which are the same give or take that.
/// Empty only when nothing is new and nothing needed.
///
/// Past [ktMaxEntries], the needed ones go with a sample of the rest at
/// least as large, drawn in an order [key] and the needed set fix: asked
/// again for the same entries — after a failure — the same fetch, and two
/// fetches that need different entries draw samples that have nothing to do
/// with each other, so neither difference names what the other needed.
List<int> ktEntriesToFetch({
  required Set<int> needed,
  required Set<int> leaves,
  required Set<int>? seen,
  required Uint8List key,
}) {
  var take = leaves;
  if (seen != null) {
    final fresh = {for (final i in leaves) if (!seen.contains(i)) i};
    if (fresh.isEmpty && needed.isEmpty) return const [];
    final made = <int>{
      ...fresh,
      ..._first([for (final i in leaves) if (!fresh.contains(i)) i],
          max(0, ktEntryFloor - fresh.length), key),
    };
    if (made.containsAll(needed)) take = made;
  }
  if (take.length <= ktMaxEntries) return take.toList()..sort();
  final rest = [for (final i in take) if (!needed.contains(i)) i];
  final room = max(ktMaxEntries - needed.length, needed.length);
  final out = <int>{
    ...needed,
    ..._first(rest, room, _sampleKey(key, needed)),
  };
  return out.toList()..sort();
}

/// The key a sample past [ktMaxEntries] is drawn under: this install's,
/// bound to the entries the fetch needs.
Uint8List _sampleKey(Uint8List key, Set<int> needed) {
  final b = ByteData(8);
  return Uint8List.fromList(const DartSha256().hashSync([
    ...key,
    ...utf8.encode(_sampleContext),
    for (final i in needed.toList()..sort())
      ...(b..setUint64(0, i)).buffer.asUint8List(),
  ]).bytes);
}

/// The first [n] of [indexes] in the order [key] gives them.
List<int> _first(List<int> indexes, int n, Uint8List key) {
  if (n <= 0) return const [];
  if (indexes.length <= n) return indexes;
  final ctx = utf8.encode(_orderContext);
  final rank = <int, List<int>>{};
  for (final i in indexes) {
    final b = ByteData(8)..setUint64(0, i);
    rank[i] = const DartSha256()
        .hashSync([...key, ...ctx, ...b.buffer.asUint8List()]).bytes;
  }
  final sorted = [...indexes]..sort((a, b) {
      final x = rank[a]!, y = rank[b]!;
      for (var j = 0; j < x.length; j++) {
        if (x[j] != y[j]) return x[j] - y[j];
      }
      return a - b;
    });
  return sorted.sublist(0, n);
}

/// When the next scheduled refresh runs, persisted (`kt_refresh`) so that a
/// restart keeps the moment already drawn for a window rather than drawing
/// again: [lastMs] is when a refresh last asked the log; [window] and [atMs]
/// are the window the next one is for and its moment.
class KtRefreshSchedule {
  final int? lastMs;
  final int? window;
  final int? atMs;

  const KtRefreshSchedule({this.lastMs, this.window, this.atMs});

  Map<String, Object?> toJson() => {
        if (lastMs != null) 'last': lastMs,
        if (window != null) 'w': window,
        if (atMs != null) 'at': atMs,
      };

  static KtRefreshSchedule fromJson(Map<String, Object?> j) {
    int? n(Object? v) => v is int ? v : null;
    return KtRefreshSchedule(lastMs: n(j['last']), window: n(j['w']), atMs: n(j['at']));
  }

  KtRefreshSchedule withLast(int ms) =>
      KtRefreshSchedule(lastMs: ms, window: window, atMs: atMs);

  /// The schedule from [nowMs] — when the app starts, when it comes back to
  /// the front, and after every refresh. Windows are [every] long and
  /// counted from the epoch, so where they fall says nothing about this
  /// install. Never earlier than [catchUpMin] from now — so never at the
  /// instant the app starts or comes back.
  ///
  /// Owed — no refresh in a whole window, or none yet, or this window's
  /// moment gone by without its refresh (the app was not running then): a
  /// catch-up at a random moment between [catchUpMin] and [catchUpMax] from
  /// now; one already drawn in that range stands. Otherwise: the first
  /// window that has not had its refresh, at a random moment in it — the
  /// moment already drawn for it while it is still ahead, or a random one in
  /// what is left of it.
  KtRefreshSchedule next({
    required int nowMs,
    required Duration every,
    required Duration catchUpMin,
    required Duration catchUpMax,
    required Random random,
  }) {
    final w = max<int>(1, every.inMilliseconds);
    final earliest = nowMs + max<int>(0, catchUpMin.inMilliseconds);
    final latest = max<int>(earliest, nowMs + catchUpMax.inMilliseconds);
    final last = lastMs;
    final at = atMs;
    KtRefreshSchedule catchUp() {
      if (at != null && at >= earliest && at <= latest) return this;
      final t = earliest + _below(random, latest - earliest + 1);
      return KtRefreshSchedule(lastMs: last, window: t ~/ w, atMs: t);
    }

    if (last == null || nowMs - last >= w) return catchUp();
    var target = nowMs ~/ w;
    if (last ~/ w >= target) target = last ~/ w + 1;
    if (window == target && at != null) {
      if (at >= earliest) return this;
      // This window's moment came while the app was not running — or comes
      // sooner than a catch-up would — and the window has had no refresh.
      if (target == nowMs ~/ w) return catchUp();
    }
    while (true) {
      final start = target * w;
      final lo = max<int>(start, earliest);
      final end = start + w;
      if (lo < end) {
        return KtRefreshSchedule(
            lastMs: last, window: target, atMs: lo + _below(random, end - lo));
      }
      target++;
    }
  }

  /// A uniform integer in [0, n) — n may pass `nextInt`'s 2³² bound.
  static int _below(Random random, int n) {
    if (n <= 1) return 0;
    if (n <= 1 << 32) return random.nextInt(n);
    return min<int>((random.nextDouble() * n).floor(), n - 1);
  }
}
