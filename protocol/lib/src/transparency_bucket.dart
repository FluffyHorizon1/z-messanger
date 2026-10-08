/// Lookups by bucket (PROTOCOL.md §19.9, ADR 0023) — the reader's side, for
/// both logs `kt/` runs: the key-transparency log (§19) and the handle log
/// (§21.5).
///
/// A reader that wants one label asks for every label sharing its first k
/// bits, and gets them all with the map siblings that fold their subtree to
/// the head's `mapRoot`. So the log learns a bucket, not a label, and the
/// reader can tell nothing in the bucket was left out: a label omitted,
/// added or changed changes the subtree, and the fold no longer reaches the
/// root the log signed. In the handle log each leaf also carries the latest
/// record for its label, its time, the owner's signature and its audit path,
/// so a resolver reads the record without a second request that names the
/// label. The same text `kt/lib/smt.js` (`verifyBucket`), `kt/lib/log.js`
/// (`verifyBucketAnswer`) and `kt/tools/verify_vectors.py` implement;
/// `docs/vectors/kt/bucket.json` pins all four.
///
/// Phase 35 reads the key-transparency log through [ktVerifyBucketAnswer] and,
/// for a value, [ktVerifyEntriesAnswer]; phase 38 resolves a handle through
/// [ktVerifyBucketAnswer] with [KtLogMode.handles] and gives the leaf's
/// `value` to the handle library, which holds the record to the owner rule.
/// Nothing here talks to the network, and nothing here decides what to ask
/// for: which buckets, how many decoys and how often are the caller's.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart' show DartSha256;

import 'transparency.dart';
import 'util.dart';

/// Which log an answer comes from. The two sign and hash under different
/// contexts, so a head of one never verifies as a head of the other; and a
/// handle log is a separate instance with its own pinned key besides.
enum KtLogMode {
  /// The key-transparency log: leaves are (label, index, version).
  kt,

  /// The handle log: leaves also carry the record, its hour, the owner's
  /// signature and the entry's audit path.
  handles,
}

/// The largest k a reader may ask for.
const int ktMaxBucketBits = 24;

/// A bucket over this many labels is refused (`bucket_too_large`) by the log,
/// and refused here if a log serves one: the reader asks with more bits.
const int ktMaxBucketLeaves = 4096;

/// At most this many buckets in one `POST /kt/v1/buckets`.
const int ktMaxBuckets = 64;

/// A handle record is at most this many bytes (§21.5, rule 6).
const int handleMaxRecordBytes = 1024;

/// A handle log keeps no finer time than an hour.
const int handleHourMs = 3600000;

const String _handleSthContext = 'z-handle-sth-v1:';
const String _handleLeafContext = 'z-handle-leaf-v1:';

// --- hashing, synchronously -------------------------------------------------------

/// A bucket's subtree is ~250 hashes a leaf (a label alone below depth k is a
/// chain of empty siblings down to depth 256), so a bucket of fifty is
/// twelve thousand: computed synchronously, without a Future each.
Uint8List _sha(List<int> data) =>
    Uint8List.fromList(const DartSha256().hashSync(data).bytes);

Uint8List _u64(int n) {
  if (n < 0) throw ArgumentError.value(n, 'n', 'negative');
  final b = ByteData(8);
  b.setUint64(0, n);
  return b.buffer.asUint8List();
}

Uint8List _mapLeaf(Uint8List label, int index, int version) =>
    _sha(concatBytes([const [0x10], label, _u64(index), _u64(version)]));

Uint8List _mapNode(List<int> left, List<int> right) =>
    _sha(concatBytes([const [0x11], left, right]));

List<Uint8List>? _emptyTable;

/// `empty(d)` for d = 0..256 (§19.2), the same values `ktMapEmpty` gives.
List<Uint8List> _empty() {
  final e = _emptyTable;
  if (e != null) return e;
  final t = List<Uint8List>.filled(ktMapDepth + 1, Uint8List(0));
  t[ktMapDepth] = _sha(const [0x12]);
  for (var d = ktMapDepth - 1; d >= 0; d--) {
    t[d] = _mapNode(t[d + 1], t[d + 1]);
  }
  return _emptyTable = t;
}

int _bit(Uint8List bytes, int d) => (bytes[d >> 3] >> (7 - (d & 7))) & 1;

int _compare(Uint8List a, Uint8List b) {
  for (var i = 0; i < a.length && i < b.length; i++) {
    if (a[i] != b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

// --- prefixes ----------------------------------------------------------------------

/// The first [bits] bits of [label] as the protocol writes a bucket's
/// prefix: ⌈bits/4⌉ lowercase hex digits, the unused low bits zero ("" at
/// k = 0).
String ktBucketPrefix(Uint8List label, int bits) {
  if (label.length != 32) throw ArgumentError('a label is 32 bytes');
  if (bits < 0 || bits > ktMaxBucketBits) {
    throw ArgumentError.value(bits, 'bits', '0..$ktMaxBucketBits');
  }
  final p = Uint8List(32);
  for (var d = 0; d < bits; d++) {
    if (_bit(label, d) == 1) p[d >> 3] |= 1 << (7 - (d & 7));
  }
  final hex = [for (final b in p) b.toRadixString(16).padLeft(2, '0')].join();
  return hex.substring(0, (bits + 3) ~/ 4);
}

/// The prefix [hex] names at [bits] as 32 bytes (the bits past [bits] zero),
/// or null unless it is exactly ⌈bits/4⌉ hex digits with the unused low bits
/// zero — the one spelling every bucket has.
Uint8List? ktParseBucketPrefix(String hex, int bits) {
  if (bits < 0 || bits > ktMaxBucketBits) return null;
  if (hex.length != (bits + 3) ~/ 4) return null;
  if (!RegExp(r'^[0-9a-fA-F]*$').hasMatch(hex)) return null;
  final padded = hex.length.isOdd ? '${hex}0' : hex;
  final p = Uint8List(32);
  for (var i = 0; i < padded.length; i += 2) {
    p[i ~/ 2] = int.parse(padded.substring(i, i + 2), radix: 16);
  }
  for (var d = bits; d < hex.length * 4; d++) {
    if (_bit(p, d) == 1) return null;
  }
  return p;
}

/// One bucket to ask for.
class KtBucketQuery {
  final int bits;

  /// ⌈bits/4⌉ lowercase hex digits.
  final String prefix;

  final Uint8List _prefixBytes;

  KtBucketQuery._(this.bits, this.prefix, this._prefixBytes);

  /// The bucket that holds [label] at [bits] — what a reader asks for when
  /// it wants [label] without naming it.
  factory KtBucketQuery.forLabel(Uint8List label, int bits) =>
      KtBucketQuery.parse(ktBucketPrefix(label, bits), bits);

  /// A bucket by its prefix (a decoy, or one the caller chose); throws
  /// [ArgumentError] unless [prefix] is the spelling [ktParseBucketPrefix]
  /// accepts.
  factory KtBucketQuery.parse(String prefix, int bits) {
    final p = ktParseBucketPrefix(prefix, bits);
    if (p == null) {
      throw ArgumentError('not a bucket: prefix "$prefix" at $bits bits');
    }
    return KtBucketQuery._(bits, prefix.toLowerCase(), p);
  }

  /// Whether [label] falls in this bucket.
  bool holds(Uint8List label) {
    if (label.length != 32) return false;
    for (var d = 0; d < bits; d++) {
      if (_bit(label, d) != _bit(_prefixBytes, d)) return false;
    }
    return true;
  }

  /// The `GET` path for this bucket.
  String get path => '/kt/v1/bucket?prefix=$prefix&bits=$bits';

  /// One element of `POST /kt/v1/buckets`'s `buckets`.
  Map<String, Object?> toJson() => {'prefix': prefix, 'bits': bits};

  @override
  bool operator ==(Object other) =>
      other is KtBucketQuery && other.bits == bits && other.prefix == prefix;

  @override
  int get hashCode => Object.hash(bits, prefix);

  @override
  String toString() => 'bucket($prefix/$bits)';
}

/// The body of `POST /kt/v1/buckets` for [queries] (at most [ktMaxBuckets]).
Map<String, Object?> ktBucketsRequest(List<KtBucketQuery> queries) {
  if (queries.isEmpty || queries.length > ktMaxBuckets) {
    throw ArgumentError('1..$ktMaxBuckets buckets in one request');
  }
  return {
    'buckets': [for (final q in queries) q.toJson()]
  };
}

// --- heads and leaves ----------------------------------------------------------------

/// What a head of [mode]'s log signs (§19.4; §21.5 for the handle log, the
/// same layout under its own context).
Uint8List ktHeadInput(KtTreeHead head, KtLogMode mode) => mode == KtLogMode.kt
    ? head.signingInput
    : concatBytes([
        utf8.encode(_handleSthContext),
        _u64(head.size),
        head.logRoot,
        head.mapRoot,
        _u64(head.ts),
      ]);

/// [head]'s signature under [logPub] in [mode]'s context.
Future<bool> ktVerifyHead(
    KtTreeHead head, Uint8List logPub, KtLogMode mode) async {
  if (logPub.length != 32 || head.sig.length != 64) return false;
  try {
    return await Ed25519().verify(ktHeadInput(head, mode),
        signature: Signature(head.sig,
            publicKey: SimplePublicKey(logPub, type: KeyPairType.ed25519)));
  } catch (_) {
    return false;
  }
}

/// The handle log's leaf (§21.5):
/// `"z-handle-leaf-v1:" ‖ label ‖ u64be(v) ‖ SHA-256(value) ‖ u64be(tsHour)`.
Uint8List handleLeafInput({
  required Uint8List label,
  required int version,
  required Uint8List valueHash,
  required int ts,
}) =>
    concatBytes([
      utf8.encode(_handleLeafContext),
      label,
      _u64(version),
      valueHash,
      _u64(ts),
    ]);

/// One label in a bucket: the map's (index, version) for it — the latest
/// entry — and, in the handle log, that entry's record ([value]), its hour
/// ([ts]), the owner's signature over it ([sig]) and its audit path.
///
/// [value] is proved here only as the bytes the log committed to at that
/// index. Its encoding and members (`k, owner, intro, xintro, pow, rc`, and
/// `rpub, rsig` on a recover — PROTOCOL §21.5) and [sig] are the handle
/// library's to check, against the owner rule.
class KtBucketLeaf {
  final Uint8List label;
  final int index;
  final int version;
  final Uint8List? value;
  final int? ts;
  final Uint8List? sig;
  final List<Uint8List>? audit;

  KtBucketLeaf({
    required this.label,
    required this.index,
    required this.version,
    this.value,
    this.ts,
    this.sig,
    this.audit,
  });
}

/// The hash at [depth] of the subtree holding exactly [leaves] — labels in
/// strictly ascending order sharing their first [depth] bits — with every
/// other position empty (§19.2's leaf and node hashes and empty subtrees).
Uint8List ktBucketSubtreeRoot(List<KtBucketLeaf> leaves, int depth) {
  final empty = _empty();
  Uint8List rec(int lo, int hi, int d) {
    if (lo == hi) return empty[d];
    if (hi - lo == 1) {
      // A label alone: its leaf, hashed up through empty siblings to depth d.
      final l = leaves[lo];
      var h = _mapLeaf(l.label, l.index, l.version);
      for (var e = ktMapDepth - 1; e >= d; e--) {
        h = _bit(l.label, e) == 0
            ? _mapNode(h, empty[e + 1])
            : _mapNode(empty[e + 1], h);
      }
      return h;
    }
    if (d >= ktMapDepth) throw KtVerifyException('two leaves for one label');
    var split = lo;
    while (split < hi && _bit(leaves[split].label, d) == 0) {
      split++;
    }
    return _mapNode(rec(lo, split, d + 1), rec(split, hi, d + 1));
  }

  return rec(0, leaves.length, depth);
}

/// [subtree] at depth [bits] folded to the root through [siblings] (depth
/// bits−1 first), branching by the bits of [prefix].
Uint8List ktBucketFold(Uint8List subtree, Uint8List prefix, int bits,
    List<Uint8List> siblings) {
  if (siblings.length != bits) {
    throw KtVerifyException('$bits bits need $bits siblings, not ${siblings.length}');
  }
  var h = subtree;
  for (var i = 0; i < bits; i++) {
    final d = bits - 1 - i;
    h = _bit(prefix, d) == 0 ? _mapNode(h, siblings[i]) : _mapNode(siblings[i], h);
  }
  return h;
}

// --- answers ---------------------------------------------------------------------------

/// A bucket whose every leaf was proved under [head].
class KtVerifiedBucket {
  final KtBucketQuery query;

  /// In label order.
  final List<KtBucketLeaf> leaves;

  KtVerifiedBucket(this.query, this.leaves);

  /// The leaf for [label], or null — a VERIFIED absence: the bucket is
  /// complete, so a label it does not hold is not in the log. Throws
  /// [ArgumentError] for a label outside the bucket, about which this
  /// answer proves nothing.
  KtBucketLeaf? leafFor(Uint8List label) {
    if (!query.holds(label)) {
      throw ArgumentError('the label is not in $query; this answer says nothing about it');
    }
    for (final l in leaves) {
      if (constantTimeEquals(l.label, label)) return l;
    }
    return null;
  }
}

/// A verified bucket answer: the head the proofs hold under and the buckets
/// in the order asked. [recommendedBits] is the log's `bucketBits` beside
/// the head — advisory and unsigned, null when absent.
class KtVerifiedBuckets {
  final KtTreeHead head;
  final List<KtVerifiedBucket> buckets;
  final int? recommendedBits;

  KtVerifiedBuckets(this.head, this.buckets, this.recommendedBits);
}

/// Verify a `GET /kt/v1/bucket` or `POST /kt/v1/buckets` answer (§19.9),
/// [json] as parsed, for the buckets [asked] in the order asked, against
/// the log key the caller pinned, in [mode]'s context:
///
/// 1. the head verifies;
/// 2. each bucket is the one asked for and holds at most [ktMaxBucketLeaves]
///    labels, each with the prefix, in strictly ascending order;
/// 3. the subtree its leaves make, folded through its siblings, is the
///    head's mapRoot — so no label is missing, none is extra, and every
///    (index, version) is the map's;
/// 4. in the handle log, every leaf's record is the entry at its index: the
///    handle leaf of (label, version, SHA-256(value), ts) is included there
///    under the head's logRoot by its audit path, ts is a whole hour, the
///    record is at most [handleMaxRecordBytes] and the signature 64 bytes.
///
/// Throws [KtVerifyException]. The head is checked for its signature only:
/// whether it extends the head the caller holds is [ktCheckHeadExtends]'s
/// question, asked by the caller before it believes anything under it.
Future<KtVerifiedBuckets> ktVerifyBucketAnswer(
  Map<String, Object?> json, {
  required List<KtBucketQuery> asked,
  required Uint8List logPub,
  required KtLogMode mode,
}) async {
  final sthJ = json['sth'];
  if (sthJ is! Map) throw KtVerifyException('bucket answer: no head');
  final sth = sthJ.cast<String, Object?>();
  final head = KtTreeHead.fromJson(sth);
  if (!await ktVerifyHead(head, logPub, mode)) {
    throw KtVerifyException(
        'bucket answer: the head is not signed by the pinned key in the ${mode.name} log\'s context');
  }
  final rb = sth['bucketBits'];
  final served = json.containsKey('buckets') ? json['buckets'] : [json];
  if (served is! List || served.length != asked.length) {
    throw KtVerifyException('bucket answer: not the ${asked.length} buckets asked for');
  }
  final out = <KtVerifiedBucket>[];
  for (var n = 0; n < asked.length; n++) {
    final want = asked[n];
    final b = served[n];
    if (b is! Map) throw KtVerifyException('bucket $n: not an object');
    final bits = b['bits'];
    final prefix = b['prefix'];
    if (bits != want.bits || prefix is! String || prefix.toLowerCase() != want.prefix) {
      throw KtVerifyException('bucket $n: not the bucket asked for ($want)');
    }
    final leavesJ = b['leaves'];
    final sibsJ = b['siblings'];
    if (leavesJ is! List || sibsJ is! List) {
      throw KtVerifyException('bucket $n: leaves and siblings are required');
    }
    if (leavesJ.length > ktMaxBucketLeaves) {
      throw KtVerifyException('bucket $n: more than $ktMaxBucketLeaves leaves');
    }
    final leaves = <KtBucketLeaf>[];
    for (final lj in leavesJ) {
      if (lj is! Map) throw KtVerifyException('bucket $n: a leaf is not an object');
      final l = lj.cast<String, Object?>();
      leaves.add(KtBucketLeaf(
        label: _bytes(l['label'], 32, 'leaf.label'),
        index: _int(l['index'], 'leaf.index'),
        version: _int(l['version'], 'leaf.version'),
        value: mode == KtLogMode.handles ? _bytes(l['value'], null, 'leaf.value') : null,
        ts: mode == KtLogMode.handles ? _int(l['ts'], 'leaf.ts') : null,
        sig: mode == KtLogMode.handles ? _bytes(l['sig'], 64, 'leaf.sig') : null,
        audit: mode == KtLogMode.handles ? _hashes(l['audit'], 'leaf.audit') : null,
      ));
    }
    for (var i = 0; i < leaves.length; i++) {
      if (!want.holds(leaves[i].label)) {
        throw KtVerifyException('bucket $n: a label outside the bucket');
      }
      if (i > 0 && _compare(leaves[i - 1].label, leaves[i].label) >= 0) {
        throw KtVerifyException('bucket $n: the labels are not in strictly ascending order');
      }
    }
    final siblings = _hashes(sibsJ, 'bucket.siblings');
    final root = ktBucketFold(ktBucketSubtreeRoot(leaves, want.bits), want._prefixBytes, want.bits, siblings);
    if (!constantTimeEquals(root, head.mapRoot)) {
      throw KtVerifyException(
          'bucket $n: the leaves and siblings do not fold to the head\'s mapRoot — a label left out, added or changed');
    }
    if (mode == KtLogMode.handles) {
      for (final l in leaves) {
        if (l.ts! % handleHourMs != 0) {
          throw KtVerifyException('bucket $n: a ts that is not a whole hour');
        }
        if (l.value!.length > handleMaxRecordBytes) {
          throw KtVerifyException('bucket $n: a record over $handleMaxRecordBytes bytes');
        }
        final leafHash = await ktLeafHash(handleLeafInput(
            label: l.label, version: l.version, valueHash: _sha(l.value!), ts: l.ts!));
        final ok = await ktVerifyInclusion(
            leafHash: leafHash, index: l.index, size: head.size, root: head.logRoot, path: l.audit!);
        if (!ok) {
          throw KtVerifyException(
              'bucket $n: the record at index ${l.index} is not the entry the log tree holds there');
        }
      }
    }
    out.add(KtVerifiedBucket(want, leaves));
  }
  return KtVerifiedBuckets(head, out, rb is int && rb >= 0 && rb <= ktMaxBucketBits ? rb : null);
}

/// The body of `POST /kt/v1/entries` for [indexes] — the entries whose
/// values a bucket named, with the caller's decoys (phase 35).
Map<String, Object?> ktEntriesRequest(List<int> indexes) => {'indexes': indexes};

/// A verified `POST /kt/v1/entries` answer: its head, how many were asked
/// ([total]), and the entries served — a prefix of those asked, in order.
class KtVerifiedEntries {
  final KtTreeHead head;
  final int total;
  final List<KtEntry> entries;
  KtVerifiedEntries(this.head, this.total, this.entries);
}

/// Verify a `POST /kt/v1/entries` answer from the key-transparency log for
/// [asked]: the head under [logPub], each entry the one asked for at its
/// place, its value hashing to its valueHash, and included at its index
/// under the head's logRoot. A short answer is a page (`total` says how many
/// were asked); ask again for the rest. Throws [KtVerifyException].
Future<KtVerifiedEntries> ktVerifyEntriesAnswer(
  Map<String, Object?> json, {
  required List<int> asked,
  required Uint8List logPub,
}) async {
  final sthJ = json['sth'];
  if (sthJ is! Map) throw KtVerifyException('entries answer: no head');
  final head = KtTreeHead.fromJson(sthJ.cast<String, Object?>());
  if (!await ktVerifyHead(head, logPub, KtLogMode.kt)) {
    throw KtVerifyException('entries answer: the head is not signed by the pinned log key');
  }
  final total = _int(json['total'], 'total');
  final items = json['entries'];
  if (total != asked.length || items is! List || items.length > asked.length) {
    throw KtVerifyException('entries answer: not an answer to the ${asked.length} indexes asked');
  }
  if (asked.isNotEmpty && items.isEmpty) {
    throw KtVerifyException('entries answer: empty, though entries were asked for');
  }
  final out = <KtEntry>[];
  for (var n = 0; n < items.length; n++) {
    final item = items[n];
    if (item is! Map) throw KtVerifyException('entries answer: an item is not an object');
    final e = item['entry'];
    final i = item['inclusion'];
    if (e is! Map || i is! Map) {
      throw KtVerifyException('entries answer: entry and inclusion are required');
    }
    final entry = await KtEntry.fromJson(e.cast<String, Object?>());
    final inc = KtInclusionProof.fromJson(i.cast<String, Object?>());
    if (entry.index != asked[n] || inc.index != entry.index || inc.size != head.size) {
      throw KtVerifyException('entries answer: item $n is not index ${asked[n]} at the head\'s size');
    }
    final ok = await ktVerifyInclusion(
        leafHash: await entry.leafHash(), index: inc.index, size: inc.size, root: head.logRoot, path: inc.path);
    if (!ok) throw KtVerifyException('entries answer: entry ${entry.index} is not included under logRoot');
    out.add(entry);
  }
  return KtVerifiedEntries(head, total, out);
}

// --- helpers -------------------------------------------------------------------------------

int _int(Object? v, String what) {
  if (v is int && v >= 0 && v <= 0x1FFFFFFFFFFFFF) return v;
  throw KtVerifyException('$what is not a non-negative integer');
}

Uint8List _bytes(Object? v, int? len, String what) {
  if (v is! String) throw KtVerifyException('$what is not base64');
  final Uint8List b;
  try {
    b = unb64(v);
  } on FormatException {
    throw KtVerifyException('$what is not base64');
  }
  if (len != null && b.length != len) {
    throw KtVerifyException('$what is ${b.length} bytes, expected $len');
  }
  return b;
}

List<Uint8List> _hashes(Object? v, String what) {
  if (v is! List) throw KtVerifyException('$what is not a list');
  return [for (final h in v) _bytes(h, 32, '$what[]')];
}
