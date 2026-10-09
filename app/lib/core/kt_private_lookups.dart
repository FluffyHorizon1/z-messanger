/// How this client asks the transparency log about its contacts without
/// naming them (phase 35; ADR 0023, "The client's refresh policy";
/// PROTOCOL.md §19.9.1). `key_transparency.dart` does the asking; this file
/// decides what to ask and when, and holds nothing that talks to the network,
/// so every rule here can be tested on its own.
///
/// Three decisions live here.
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
/// by index (`POST /kt/v1/entries`). What is fetched is a set the log could
/// list for itself, whichever contacts moved: every entry in the asked
/// buckets that this client has not seen at its last refresh — whether or not
/// any of them is a contact's — or, when a contact needs an entry the client
/// HAS seen (one added in a bucket already asked), every entry in the asked
/// buckets. Past [ktMaxEntries] it is those needed and a sample of the rest;
/// with no last refresh to compare against, those needed and a sample of
/// [ktFirstEntries]. A sample is the same sample every time it is drawn from
/// the same set, so a fetch asked again after a failure is the same fetch.
///
/// **When.** One refresh in each window of [KeyTransparency.checkEvery], at a
/// random moment in it — never when the app starts, and never because a
/// contact's list changed (a refresh 30 seconds after a contact publishes
/// would tell the log, by its timing alone, whose contact this is). A client
/// that has had no refresh for a whole window catches up once it has been
/// running a while, at a random moment between [KeyTransparency.catchUpMin]
/// and [KeyTransparency.catchUpMax] — the app may not be running at the
/// window's moment at all, and a check that never happens protects no one.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/dart.dart' show DartSha256;
import 'package:z_protocol/z_protocol.dart';

/// The bucket count is padded to a multiple of this: a client with one
/// contact and a client with sixteen ask the same number.
const int ktDecoyBlock = 16;

/// Buckets the log's answers show to hold fewer labels than this, on
/// average, are too fine to hide a label in: the client asks coarser ones
/// from then on. Half the lower end of what the log recommends (§19.9).
const int ktMinBucketLeaves = 16;

/// At most this many entries in one refresh's fetch (~1.5 MB of sealed
/// lists): past it, the needed ones and a sample of the rest.
const int ktMaxEntries = 1024;

/// The sample a refresh with no last refresh to compare against fetches
/// beside the entries it needs.
const int ktFirstEntries = 64;

const String _orderContext = 'z-kt-decoy-order-v1:';

/// The k a refresh asks with: the log's recommendation (`bucketBits`), never
/// finer — and never finer than the log's own signed size allows, because a
/// recommendation is unsigned and the operator writes it. A log of N entries
/// holds at most N labels, so ⌊log₂(N / 32)⌋ is the finest k that could still
/// put 32 labels in a bucket; and [ceiling], when the client's own evidence
/// (decoy buckets that came back nearly empty) has set one.
int ktRefreshBits({
  required int? recommended,
  required int headSize,
  int? ceiling,
}) {
  var k = (recommended ?? 0).clamp(0, ktMaxBucketBits);
  final bySize = headSize < 64 ? 0 : headSize.bitLength - 1 - 5;
  k = min(k, min(bySize, ktMaxBucketBits));
  if (ceiling != null) k = min(k, max(0, ceiling));
  return k;
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
/// came from asked.
class KtDecoys {
  /// Orders the candidates for entry decoys ([ktEntriesToFetch]); never
  /// leaves this vault except in a backup.
  final Uint8List key;

  /// Decoy labels: 32 bytes each, mapped to buckets as a label is.
  final List<Uint8List> pool;

  /// The k of [asked], and the buckets the last refresh asked, sorted.
  int? bits;
  List<String> asked;

  /// The finest k the log's answers have been seen to support, when they
  /// have said (see [observe]).
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
  /// sample of the log's buckets — they were drawn at random — so their mean
  /// size is the log's labels over 2^k, whatever `bucketBits` claims. Below
  /// [ktMinBucketLeaves] the next refresh asks one bit coarser; at four times
  /// that, a ceiling set earlier is lifted one bit, since a log grows.
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
    final mean = sum / n;
    if (mean < ktMinBucketLeaves && k > 0) {
      ceiling = k - 1;
    } else if (mean >= 4 * ktMinBucketLeaves && ceiling != null && ceiling! <= k) {
      ceiling = ceiling! + 1 > ktMaxBucketBits ? null : ceiling! + 1;
    }
  }
}

/// The entry indexes a refresh fetches (`POST /kt/v1/entries`), ascending:
/// every one in [needed], and decoys from the leaves of the buckets it asked
/// ([leaves], every index they hold). [seen] is the indexes those buckets
/// held at the last refresh, or null when there was none.
///
/// The fetch is meant to be a set the log could compute for itself. A
/// contact's entry is needed because it moved, so it is new to this client:
/// every entry new to it is fetched, contact or not. A needed entry the
/// client has seen — a contact added in a bucket it already asks — would
/// stand out among new ones, so then every entry in the asked buckets is.
/// The log learns whether that happened, never which entry it was for.
/// Past [ktMaxEntries], and with no [seen] to compare against at all, the
/// needed ones go with a sample of the rest drawn in the order [key] gives,
/// at least as large as what is needed.
List<int> ktEntriesToFetch({
  required Set<int> needed,
  required Set<int> leaves,
  required Set<int>? seen,
  required Uint8List key,
}) {
  final List<int> others;
  final int room;
  if (seen == null) {
    others = [for (final i in leaves) if (!needed.contains(i)) i];
    room = max(ktFirstEntries, needed.length);
  } else {
    final all = needed.any(seen.contains);
    others = [
      for (final i in leaves)
        if (!needed.contains(i) && (all || !seen.contains(i))) i
    ];
    room = max(ktMaxEntries - needed.length, needed.length);
  }
  final out = <int>{...needed, ..._first(others, room, key)};
  return out.toList()..sort();
}

/// The first [n] of [indexes] in the order [key] gives them.
List<int> _first(List<int> indexes, int n, Uint8List key) {
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

  /// The schedule from [nowMs]. Windows are [every] long and counted from
  /// the epoch, so where they fall says nothing about this install. Never
  /// earlier than [catchUpMin] from now — so never at start.
  ///
  /// Overdue (no refresh in a whole window, or none yet): a random moment
  /// between [catchUpMin] and [catchUpMax] from now; one already drawn in
  /// that range stands. Otherwise: the first window that has not had its
  /// refresh, at a random moment in it — the moment already drawn for it if
  /// it is still ahead, or a random one in what is left of it.
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
    if (last == null || nowMs - last >= w) {
      if (at != null && at >= earliest && at <= latest) return this;
      final t = earliest + _below(random, latest - earliest + 1);
      return KtRefreshSchedule(lastMs: last, window: t ~/ w, atMs: t);
    }
    var target = nowMs ~/ w;
    if (last ~/ w >= target) target = last ~/ w + 1;
    if (window == target && at != null && at >= earliest) return this;
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
