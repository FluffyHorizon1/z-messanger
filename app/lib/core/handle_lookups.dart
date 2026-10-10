/// How the handle resolver asks the handle log (phase 38; PROTOCOL.md §21.8,
/// "Finding and asking"): which buckets, at what size, and what it remembers
/// of the handles it found. `handles.dart` does the asking; this file holds
/// nothing that talks to the network, so every rule here can be tested on
/// its own. The transparency log's client keeps rules of the same kind for
/// its refreshes (`kt_private_lookups.dart`); the two are written apart, and
/// differ where a lookup differs from a refresh, as said beside each.
///
/// **What size.** A bucket is the labels whose first k bits are the handle's
/// (§19.9). The log recommends k as `bucketBits`, which sits beside its
/// signed head and outside it, so its operator — or whatever terminates its
/// TLS (R44) — writes it; and the head's signed size counts entries, which
/// anyone holding a handle's owner key, the operator first, multiplies by
/// publishing versions. Neither says how many LABELS the log holds, and
/// labels are what a bucket hides a handle among. So k comes from labels this
/// client counted itself, in buckets it verified complete:
///
/// * a first estimate from random buckets, never the handle's
///   ([handleProbeNext]): the finest k the signed size allows first, then
///   coarser, until one bucket holds [handleProbeLabels] labels;
/// * after each lookup, from the buckets it asked ([handleNextBits]): under
///   [handleMinBucketLabels] a bucket on average and k falls at once to what
///   they bear out; at four times that it rises one bit, and no more;
/// * and never finer than the signed size allows, ⌊log₂(size / 32)⌋, nor
///   than `bucketBits`.
///
/// **Which buckets.** The handle's and [handleDecoys] decoys', each asked
/// once, in prefix order. The decoys are a function of the handle's label and
/// of a key this install keeps ([handleDecoyPoints]): fresh decoys at each
/// lookup would leave the handle's bucket as what two lookups of it have in
/// common, and one kept set as what lookups of two different handles do not.
///
/// **What it remembers.** For each handle a lookup found: its owner key, its
/// recovery commitment, its version and its record's hash ([KnownHandle]). A
/// later lookup of it must find a record the owner rule could have led to
/// from there, as far as one record shows ([handleKnownChange]); one that is
/// not is refused, and the person told why.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/dart.dart' show DartSha256;
import 'package:z_protocol/z_protocol.dart';

/// Decoy buckets beside the handle's in one lookup: a handle's bucket is one
/// of four. A refresh of the transparency log pads to sixteen, because it
/// asks for every contact at once; a lookup asks for one handle, and each
/// bucket costs ~50–100 KB of records at a million entries (ADR 0023's
/// ~1.5 KB a handle leaf).
const int handleDecoys = 3;

/// Under this many labels a bucket on average, the buckets a lookup asked
/// were too fine to hide a handle in, and the next lookup asks coarser ones
/// (the transparency client's `ktMinBucketLeaves`, for the same reason). At
/// four times it, k rises one bit.
const int handleMinBucketLabels = 16;

/// A probe stops at a bucket that proves this many labels: the estimate it
/// gives is then within a fifth of the truth two times in three, and the k
/// it gives seldom more than one bit out.
const int handleProbeLabels = 32;

/// At most this many random buckets in one estimate.
const int handleProbeSteps = 8;

/// A head older than this is not believed: the log re-signs its head at least
/// every 10 minutes while it runs, so a day-old one is a log that stopped,
/// or an old answer served again — which would show a handle as it was, its
/// old owner or its old mailbox, after a recovery or a new inbox. A day, not
/// minutes, for the same reason as the transparency client's `staleHead`: a
/// phone's clock may be wrong by hours, and a check that fails on every
/// lookup for a clock it cannot see is one the person learns to ignore.
const Duration handleStaleHead = Duration(hours: 24);

/// At most this many handles remembered; past it, the one found longest ago
/// is forgotten (and its next lookup is a first one again).
const int handleKnownCap = 256;

/// The vault key of [HandleLookupMemory].
const String handleLookupKey = 'handle_lookup';

const String _decoyContext = 'z-handle-decoy-v1:';

/// max(0, ⌊log₂(labels / 32)⌋), at most 24: the k at which [labels] labels
/// put 32 to 64 in a bucket on average — the log's own rule for `bucketBits`
/// (§19.9), applied to a number the client has reason to believe.
int handleBitsFor(int labels) =>
    labels < 64 ? 0 : min(ktMaxBucketBits, labels.bitLength - 1 - 5);

/// The k a probe asks next, after a random bucket at [bits] proved [count]
/// labels — or null when that bucket is the estimate: it held
/// [handleProbeLabels], or [bits] is 0 and there is nothing coarser. Coarser
/// by as many bits as the count fell short (the least s with
/// count · 2^s ≥ 32), and by five for an empty bucket.
int? handleProbeNext(int bits, int count) {
  if (count >= handleProbeLabels || bits <= 0) return null;
  var s = 5;
  if (count > 0) {
    s = 0;
    while (count * (1 << s) < handleProbeLabels) {
      s++;
    }
  }
  return max(0, bits - s);
}

/// What a lookup's answers say k should be next. [current] is the estimate
/// the lookup was asked under; it asked at [asked] (coarser when the signed
/// size or `bucketBits` held it back); [counts] is the labels in each
/// distinct bucket it asked, every one verified complete. Their mean at
/// [asked] bits, times 2^asked, is the log's labels, whatever its head and
/// `bucketBits` say — the handle's own bucket included, which a found handle
/// makes one label fuller, a bias the thresholds dwarf (the transparency
/// client counts its decoy buckets alone; a lookup has three, and at k = 0
/// none distinct from the handle's).
///
/// Under [handleMinBucketLabels] a bucket at [current], k falls at once to
/// what that number bears out — all the way, where the transparency
/// client's ceiling falls a bit per refresh; at four times it, k rises one
/// bit and no more, so a log that fills with labels overnight moves a lookup
/// a bit at a time.
int handleNextBits(int current, int asked, List<int> counts) {
  if (counts.isEmpty) return current;
  final sum = counts.fold<int>(0, (a, b) => a + b);
  final labels = sum * (1 << asked) ~/ counts.length;
  final perBucket = labels ~/ (1 << current);
  if (perBucket < handleMinBucketLabels) {
    return min(current, handleBitsFor(labels));
  }
  if (perBucket >= 4 * handleMinBucketLabels) {
    return min(current + 1, handleBitsFor(labels));
  }
  return current;
}

/// [handleDecoys] decoy points for [label] under this install's [key], each
/// 32 bytes and mapped to a bucket as a label is:
/// SHA-256(key ‖ "z-handle-decoy-v1:" ‖ label ‖ i). A function of the two
/// alone, so looking the same handle up again asks the same buckets — at a
/// finer k, a child of each — and two handles' decoys share nothing but
/// chance.
List<Uint8List> handleDecoyPoints(Uint8List key, Uint8List label) {
  final ctx = utf8.encode(_decoyContext);
  return [
    for (var i = 0; i < handleDecoys; i++)
      Uint8List.fromList(
          const DartSha256().hashSync([...key, ...ctx, ...label, i]).bytes),
  ];
}

/// The buckets one lookup of [label] asks at [bits]: its own and its
/// decoys', each once, in prefix order, which says nothing about which is
/// which. At a k with few buckets some coincide, and fewer are asked — at
/// k = 0, the one bucket that is the whole log.
List<KtBucketQuery> handleLookupBuckets(
    Uint8List key, Uint8List label, int bits) {
  final prefixes = <String>{
    ktBucketPrefix(label, bits),
    for (final d in handleDecoyPoints(key, label)) ktBucketPrefix(d, bits),
  }.toList()
    ..sort();
  return [for (final p in prefixes) KtBucketQuery.parse(p, bits)];
}

/// Why [leaf] cannot be a handle's latest entry in an honest log, or null.
/// A label at version v has had v entries (§21.4 rule 5: a claim is 1, each
/// later entry the next), the latest at [KtBucketLeaf.index], so v is at
/// most index + 1. And at 2^53 − 1 no version is left for an update or a
/// recover to take: a change to such a handle would fail as arithmetic, so
/// the answer fails here, as one that does not check out.
String? handleLeafProblem(KtBucketLeaf leaf) {
  if (leaf.version < 1) {
    return 'version ${leaf.version}: a label\'s first entry is version 1';
  }
  if (leaf.version > leaf.index + 1) {
    return 'version ${leaf.version} at index ${leaf.index}: more versions '
        'than the log has entries before it';
  }
  if (leaf.version >= handleMaxVersion) {
    return 'version ${leaf.version}: no version can follow it';
  }
  return null;
}

/// A handle a lookup found, remembered so the next lookup of it can be held
/// to it (§21.8). Never the handle itself: the label, which only someone who
/// guesses the handle can tie to it, keys it.
class KnownHandle {
  /// The owner key the record named, and its recovery commitment: only that
  /// owner signs a later record, and only the key behind that commitment
  /// installs another owner.
  final Uint8List owner;
  final Uint8List rc;

  /// The version found and SHA-256 of the record's bytes: a later lookup may
  /// find a later version, never an earlier one, and at this version only
  /// this record.
  final int version;
  final Uint8List hash;

  /// When it was last found; the cap forgets the one found longest ago.
  final int atMs;

  const KnownHandle({
    required this.owner,
    required this.rc,
    required this.version,
    required this.hash,
    required this.atMs,
  });

  Map<String, Object?> toJson() => {
        'o': b64(owner),
        'rc': b64(rc),
        'v': version,
        'h': b64(hash),
        'at': atMs,
      };

  /// The stored form, or null when [j] is not one.
  static KnownHandle? fromJson(Object? j) {
    try {
      if (j is! Map) return null;
      final owner = unb64(j['o'] as String);
      final rc = unb64(j['rc'] as String);
      final hash = unb64(j['h'] as String);
      final v = j['v'];
      final at = j['at'];
      if (owner.length != 32 || rc.length != 32 || hash.length != 32) {
        return null;
      }
      if (v is! int || v < 1 || v >= handleMaxVersion) return null;
      if (at is! int || at < 0) return null;
      return KnownHandle(owner: owner, rc: rc, version: v, hash: hash, atMs: at);
    } catch (_) {
      return null;
    }
  }
}

/// Why a lookup was refused against what this device remembered of the
/// handle.
enum HandleChange {
  /// The record names another owner, and is not the recover that opens the
  /// commitment this device remembers — so it cannot see what changed the
  /// owner: the recovery code, with changes since that it has not seen, or
  /// the log's operator.
  owner,

  /// The log shows an older record than it showed this device before,
  /// another record at a version already seen, or none at all — what a log
  /// does not do to a record it accepted.
  history,
}

/// Whether the record a lookup found — [rec], at [version], its bytes
/// hashing to [hash] — can follow [known] under the owner rule, as far as one
/// record shows: null when it can. The owner remembered signed it, whatever
/// came between; or it is the recover that opens the commitment remembered
/// (an update keeps the commitment, so updates before the recover change
/// nothing). Another owner any other way — an update naming one, which the
/// rule forbids, or a recover after entries this device has not seen — is
/// [HandleChange.owner]: from one record, the code's work cannot be told
/// from the log's.
Future<HandleChange?> handleKnownChange(
  KnownHandle known, {
  required int version,
  required Uint8List hash,
  required HandleRecord rec,
}) async {
  if (version < known.version) return HandleChange.history;
  if (version == known.version) {
    return constantTimeEquals(hash, known.hash) ? null : HandleChange.history;
  }
  if (constantTimeEquals(rec.owner, known.owner)) return null;
  if (rec.kind == HandleRecordKind.recover &&
      constantTimeEquals(
          await handleRecoveryCommitment(rec.rpub!), known.rc)) {
    return null;
  }
  return HandleChange.owner;
}

/// What the resolver keeps between lookups, sealed in the vault under
/// [handleLookupKey] and carried in a backup: the decoy [key], the k the
/// log's answers bear out ([bits]; null until the first estimate), and the
/// handles found ([known], by the label in base64url) — all for one log,
/// [log], its pinned key in base64. A memory of another log is not this
/// one's: a log set in its place starts from nothing.
class HandleLookupMemory {
  final String log;
  final Uint8List key;
  int? bits;
  final Map<String, KnownHandle> known;

  HandleLookupMemory({
    required this.log,
    required this.key,
    this.bits,
    Map<String, KnownHandle>? known,
  }) : known = known ?? {};

  Map<String, Object?> toJson() => {
        'log': log,
        'key': b64(key),
        if (bits != null) 'k': bits,
        'known': {for (final e in known.entries) e.key: e.value.toJson()},
      };

  /// The stored form, or null when [text] is not one — a backup is a file
  /// that can come from anywhere. A handle that is not one is left out, and
  /// past [handleKnownCap] the ones found longest ago are.
  static HandleLookupMemory? parse(String text) {
    try {
      final j = jsonDecode(text);
      if (j is! Map) return null;
      final log = j['log'];
      final key = unb64(j['key'] as String);
      final k = j['k'];
      if (log is! String || log.isEmpty || key.length != 32) return null;
      if (k != null && (k is! int || k < 0 || k > ktMaxBucketBits)) {
        return null;
      }
      final known = <String, KnownHandle>{};
      final kn = j['known'];
      if (kn is Map) {
        for (final e in kn.entries) {
          final id = e.key;
          if (id is! String) continue;
          try {
            if (unb64url(id).length != 32) continue;
          } on FormatException {
            continue;
          }
          final h = KnownHandle.fromJson(e.value);
          if (h != null) known[id] = h;
        }
      }
      final m = HandleLookupMemory(log: log, key: key, bits: k as int?, known: known);
      m._trim();
      return m;
    } catch (_) {
      return null;
    }
  }

  KnownHandle? knownFor(Uint8List label) => known[b64url(label)];

  /// Remember [h] for [label], forgetting the handle found longest ago past
  /// [handleKnownCap].
  void remember(Uint8List label, KnownHandle h) {
    known[b64url(label)] = h;
    _trim();
  }

  void forget(Uint8List label) => known.remove(b64url(label));

  void _trim() {
    while (known.length > handleKnownCap) {
      final oldest = known.entries
          .reduce((a, b) => a.value.atMs <= b.value.atMs ? a : b)
          .key;
      known.remove(oldest);
    }
  }
}
