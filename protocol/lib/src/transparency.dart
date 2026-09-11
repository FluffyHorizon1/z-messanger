/// The transparency log, from the reader's side (PROTOCOL.md §19, ADR 0006).
///
/// Everything a client needs to read the log without trusting it: labels and
/// sealed values (§19.1), the map tree's compressed proof (§19.2), the RFC
/// 9162 log tree's inclusion and consistency proofs (§19.3), signed tree
/// heads (§19.4), the head-extension check and a full lookup verification
/// (§19.5), the publish request an account signs (§19.6), and witness records
/// (§19.8). The same text `kt/lib` implements in Node and
/// `kt/tools/verify_vectors.py` in Python; `docs/vectors/kt/` pins all three.
///
/// Nothing here talks to the network. The app's client (`key_transparency.dart`)
/// fetches; this file decides.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'util.dart';

final _ed = Ed25519();
final _aead = Chacha20.poly1305Aead();

const int ktMapDepth = 256;

const String _labelContext = 'z-kt-label-v1:';
const String _leafContext = 'z-kt-leaf-v1:';
const String _sthContext = 'z-kt-sth-v1:';
const String _publishContext = 'z-kt-publish-v1:';
const String _witnessContext = 'z-kt-witness-v1:';
const String _valueSalt = 'z-kt-value-v1';
const String _valueInfo = 'value';

/// The largest value a log accepts (§19.1).
const int ktMaxValueBytes = 256 * 1024;

/// A proof, head or record that does not verify. [reason] is for the log's
/// operator and the user's "details" screen, not for a decision: any
/// exception means "do not use this answer".
class KtVerifyException implements Exception {
  final String reason;
  KtVerifyException(this.reason);
  @override
  String toString() => 'KtVerifyException: $reason';
}

Uint8List _u64be(int n) {
  if (n < 0) throw ArgumentError.value(n, 'n', 'negative');
  final b = ByteData(8);
  b.setUint64(0, n);
  return b.buffer.asUint8List();
}

// --- §19.1 labels and values --------------------------------------------------

/// `label = SHA-256("z-kt-label-v1:" || accountEdPub)`.
Future<Uint8List> ktLabel(Uint8List accountEdPub) =>
    sha256Bytes(concatBytes([utf8.encode(_labelContext), accountEdPub]));

/// `vk = HKDF-SHA256(ikm = accountEdPub, salt = "z-kt-value-v1", info = "value", 32)`.
Future<SecretKey> ktValueKey(Uint8List accountEdPub) {
  final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  return hkdf.deriveKey(
    secretKey: SecretKey(accountEdPub),
    nonce: utf8.encode(_valueSalt),
    info: utf8.encode(_valueInfo),
  );
}

/// Seal a signed device list's JSON for the log: `nonce || ct || tag`.
Future<Uint8List> ktSealValue(Uint8List accountEdPub, List<int> listJson,
    {Uint8List? nonce}) async {
  final n = nonce ?? randomBytes(12);
  if (n.length != 12) throw ArgumentError('a nonce is 12 bytes');
  final box = await _aead.encrypt(listJson,
      secretKey: await ktValueKey(accountEdPub),
      nonce: n,
      aad: await ktLabel(accountEdPub));
  return concatBytes([n, box.cipherText, box.mac.bytes]);
}

/// Open a value sealed for [accountEdPub]; null if it was not, or was
/// tampered with.
Future<Uint8List?> ktOpenValue(Uint8List accountEdPub, Uint8List value) async {
  if (value.length < 12 + 16) return null;
  try {
    final plain = await _aead.decrypt(
      SecretBox(
        Uint8List.sublistView(value, 12, value.length - 16),
        nonce: Uint8List.sublistView(value, 0, 12),
        mac: Mac(Uint8List.sublistView(value, value.length - 16)),
      ),
      secretKey: await ktValueKey(accountEdPub),
      aad: await ktLabel(accountEdPub),
    );
    return Uint8List.fromList(plain);
  } on SecretBoxAuthenticationError {
    return null;
  }
}

// --- §19.3 the log tree --------------------------------------------------------

Future<Uint8List> ktLeafHash(List<int> input) =>
    sha256Bytes(concatBytes([const [0x00], input]));

Future<Uint8List> ktNodeHash(List<int> left, List<int> right) =>
    sha256Bytes(concatBytes([const [0x01], left, right]));

/// RFC 9162 §2.1.3.2 — does [path] prove [leafHash] at [index] in a tree of
/// [size] whose root is [root]?
Future<bool> ktVerifyInclusion({
  required Uint8List leafHash,
  required int index,
  required int size,
  required Uint8List root,
  required List<Uint8List> path,
}) async {
  if (index < 0 || index >= size) return false;
  var fn = index;
  var sn = size - 1;
  var r = leafHash;
  for (final p in path) {
    if (sn == 0) return false;
    if (fn.isOdd || fn == sn) {
      r = await ktNodeHash(p, r);
      if (fn.isEven) {
        while (!(fn.isOdd || fn == 0)) {
          fn >>= 1;
          sn >>= 1;
        }
      }
    } else {
      r = await ktNodeHash(r, p);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn == 0 && constantTimeEquals(r, root);
}

/// RFC 9162 §2.1.4.2 — does [proof] show the tree of [first] entries (root
/// [firstRoot]) is a prefix of the tree of [second] (root [secondRoot])?
Future<bool> ktVerifyConsistency({
  required int first,
  required int second,
  required Uint8List firstRoot,
  required Uint8List secondRoot,
  required List<Uint8List> proof,
}) async {
  if (first > second) return false;
  if (first == second) {
    return proof.isEmpty && constantTimeEquals(firstRoot, secondRoot);
  }
  if (first == 0) return proof.isEmpty;
  if (proof.isEmpty) return false;
  final p = (first & (first - 1)) == 0 ? [firstRoot, ...proof] : proof;
  var fn = first - 1;
  var sn = second - 1;
  while (fn.isOdd) {
    fn >>= 1;
    sn >>= 1;
  }
  var fr = p[0];
  var sr = p[0];
  for (final c in p.skip(1)) {
    if (sn == 0) return false;
    if (fn.isOdd || fn == sn) {
      fr = await ktNodeHash(c, fr);
      sr = await ktNodeHash(c, sr);
      if (fn.isEven) {
        while (!(fn.isOdd || fn == 0)) {
          fn >>= 1;
          sn >>= 1;
        }
      }
    } else {
      sr = await ktNodeHash(sr, c);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return constantTimeEquals(fr, firstRoot) &&
      constantTimeEquals(sr, secondRoot) &&
      sn == 0;
}

// --- §19.2 the map tree ----------------------------------------------------------

Future<Uint8List> ktMapLeafHash(Uint8List label, int index, int version) =>
    sha256Bytes(
        concatBytes([const [0x10], label, _u64be(index), _u64be(version)]));

Future<Uint8List> ktMapNodeHash(List<int> left, List<int> right) =>
    sha256Bytes(concatBytes([const [0x11], left, right]));

List<Uint8List>? _empty;

/// `empty(d)` for d = 0..256, computed once.
Future<List<Uint8List>> ktMapEmpty() async {
  if (_empty != null) return _empty!;
  final e = List<Uint8List>.filled(ktMapDepth + 1, Uint8List(0));
  e[ktMapDepth] = await sha256Bytes(const [0x12]);
  for (var d = ktMapDepth - 1; d >= 0; d--) {
    e[d] = await ktMapNodeHash(e[d + 1], e[d + 1]);
  }
  _empty = e;
  return e;
}

int _bit(Uint8List bytes, int d) => (bytes[d >> 3] >> (7 - (d & 7))) & 1;

/// A compressed map proof (§19.2). [index] and [version] are null for a proof
/// of absence.
class KtMapProof {
  final int? index;
  final int? version;
  final Uint8List bitmap;
  final List<Uint8List> siblings;

  KtMapProof({
    required this.index,
    required this.version,
    required this.bitmap,
    required this.siblings,
  });

  bool get present => index != null;

  static KtMapProof fromJson(Map<String, Object?> j) {
    final leaf = j['leaf'];
    int? index;
    int? version;
    if (leaf != null) {
      final l = (leaf as Map).cast<String, Object?>();
      index = _int(l['index'], 'map.leaf.index');
      version = _int(l['v'], 'map.leaf.v');
    }
    final bitmap = _bytes(j['bitmap'], 32, 'map.bitmap');
    final sibs = j['siblings'];
    if (sibs is! List) throw KtVerifyException('map.siblings is not a list');
    return KtMapProof(
      index: index,
      version: version,
      bitmap: bitmap,
      siblings: [for (final s in sibs) _bytes(s, 32, 'map.siblings[]')],
    );
  }

  /// Verify against [root] for [label].
  Future<bool> verify(Uint8List root, Uint8List label) async {
    if (label.length != 32 || bitmap.length != 32) return false;
    var expected = 0;
    for (var d = 0; d < ktMapDepth; d++) {
      expected += _bit(bitmap, d);
    }
    if (siblings.length != expected) return false;
    final empty = await ktMapEmpty();
    var h = present
        ? await ktMapLeafHash(label, index!, version!)
        : empty[ktMapDepth];
    var s = siblings.length - 1;
    for (var d = ktMapDepth - 1; d >= 0; d--) {
      final sib = _bit(bitmap, d) == 1 ? siblings[s--] : empty[d + 1];
      h = _bit(label, d) == 0
          ? await ktMapNodeHash(h, sib)
          : await ktMapNodeHash(sib, h);
    }
    return constantTimeEquals(h, root);
  }
}

// --- §19.4 signed tree heads ---------------------------------------------------------

class KtTreeHead {
  final int size;
  final Uint8List logRoot;
  final Uint8List mapRoot;
  final int ts;
  final Uint8List sig;

  KtTreeHead({
    required this.size,
    required this.logRoot,
    required this.mapRoot,
    required this.ts,
    required this.sig,
  });

  Uint8List get signingInput => concatBytes([
        utf8.encode(_sthContext),
        _u64be(size),
        logRoot,
        mapRoot,
        _u64be(ts),
      ]);

  Future<bool> verify(Uint8List logPub) => _verify(logPub, signingInput, sig);

  bool sameRootsAs(KtTreeHead o) =>
      size == o.size &&
      constantTimeEquals(logRoot, o.logRoot) &&
      constantTimeEquals(mapRoot, o.mapRoot);

  Map<String, Object?> toJson() => {
        'size': size,
        'logRoot': b64(logRoot),
        'mapRoot': b64(mapRoot),
        'ts': ts,
        'sig': b64(sig),
      };

  static KtTreeHead fromJson(Map<String, Object?> j) => KtTreeHead(
        size: _int(j['size'], 'sth.size'),
        logRoot: _bytes(j['logRoot'], 32, 'sth.logRoot'),
        mapRoot: _bytes(j['mapRoot'], 32, 'sth.mapRoot'),
        ts: _int(j['ts'], 'sth.ts'),
        sig: _bytes(j['sig'], 64, 'sth.sig'),
      );
}

/// §19.5 steps 1–2: [fresh] verifies under [logPub] and extends [held] (or
/// [held] is null, a first head). [consistency] is the proof the log served
/// for `first = held.size, second = fresh.size`, required when the sizes
/// differ. Throws [KtVerifyException] otherwise.
Future<void> ktCheckHeadExtends({
  required KtTreeHead? held,
  required KtTreeHead fresh,
  required List<Uint8List>? consistency,
  required Uint8List logPub,
}) async {
  if (!await fresh.verify(logPub)) {
    throw KtVerifyException('the head is not signed by the pinned log key');
  }
  if (held == null) return;
  if (fresh.size < held.size) {
    throw KtVerifyException(
        'the log shrank: held size ${held.size}, served ${fresh.size}');
  }
  if (fresh.size == held.size) {
    if (!held.sameRootsAs(fresh)) {
      throw KtVerifyException(
          'same size ${held.size}, different roots — a fork');
    }
    return;
  }
  if (consistency == null) {
    throw KtVerifyException(
        'no consistency proof from ${held.size} to ${fresh.size}');
  }
  final ok = await ktVerifyConsistency(
    first: held.size,
    second: fresh.size,
    firstRoot: held.logRoot,
    secondRoot: fresh.logRoot,
    proof: consistency,
  );
  if (!ok) {
    throw KtVerifyException(
        'the head of size ${fresh.size} does not extend the held head of size ${held.size} — a fork');
  }
}

// --- entries, inclusion, lookups -------------------------------------------------------

class KtEntry {
  final int index;
  final Uint8List label;
  final int version;
  final Uint8List fp;
  final Uint8List valueHash;
  final Uint8List value;
  final int ts;

  KtEntry({
    required this.index,
    required this.label,
    required this.version,
    required this.fp,
    required this.valueHash,
    required this.value,
    required this.ts,
  });

  Uint8List get leafInput => concatBytes([
        utf8.encode(_leafContext),
        label,
        _u64be(version),
        fp,
        valueHash,
        _u64be(ts),
      ]);

  Future<Uint8List> leafHash() => ktLeafHash(leafInput);

  /// Parse and check `SHA-256(value) == valueHash` (§19.7).
  static Future<KtEntry> fromJson(Map<String, Object?> j) async {
    final value = _bytes(j['value'], null, 'entry.value');
    final valueHash = _bytes(j['valueHash'], 32, 'entry.valueHash');
    if (!constantTimeEquals(await sha256Bytes(value), valueHash)) {
      throw KtVerifyException('entry.value does not hash to entry.valueHash');
    }
    return KtEntry(
      index: _int(j['index'], 'entry.index'),
      label: _bytes(j['label'], 32, 'entry.label'),
      version: _int(j['v'], 'entry.v'),
      fp: _bytes(j['fp'], 16, 'entry.fp'),
      valueHash: valueHash,
      value: value,
      ts: _int(j['ts'], 'entry.ts'),
    );
  }
}

class KtInclusionProof {
  final int index;
  final int size;
  final List<Uint8List> path;
  KtInclusionProof({required this.index, required this.size, required this.path});

  static KtInclusionProof fromJson(Map<String, Object?> j) {
    final path = j['path'];
    if (path is! List) throw KtVerifyException('inclusion.path is not a list');
    return KtInclusionProof(
      index: _int(j['index'], 'inclusion.index'),
      size: _int(j['size'], 'inclusion.size'),
      path: [for (final h in path) _bytes(h, 32, 'inclusion.path[]')],
    );
  }
}

/// A `/kt/v1/lookup/<label>` response, parsed but not yet verified.
class KtLookup {
  final KtTreeHead head;
  final KtMapProof map;
  final KtEntry? entry;
  final KtInclusionProof? inclusion;

  KtLookup({
    required this.head,
    required this.map,
    required this.entry,
    required this.inclusion,
  });

  static Future<KtLookup> fromJson(Map<String, Object?> j) async {
    final sth = j['sth'];
    final map = j['map'];
    if (sth is! Map || map is! Map) {
      throw KtVerifyException('lookup: sth and map are required');
    }
    final e = j['entry'];
    final inc = j['inclusion'];
    return KtLookup(
      head: KtTreeHead.fromJson(sth.cast<String, Object?>()),
      map: KtMapProof.fromJson(map.cast<String, Object?>()),
      entry: e == null
          ? null
          : await KtEntry.fromJson((e as Map).cast<String, Object?>()),
      inclusion: inc == null
          ? null
          : KtInclusionProof.fromJson((inc as Map).cast<String, Object?>()),
    );
  }
}

/// What a verified lookup says: the head it was proved under, and the latest
/// entry for the label or null for a verified absence.
class KtLookupResult {
  final KtTreeHead head;
  final KtEntry? latest;
  KtLookupResult({required this.head, required this.latest});
  bool get absent => latest == null;
}

/// §19.5 — verify every proof in a lookup for [label]. The head must already
/// have passed [ktCheckHeadExtends] (or be the client's held head); this
/// re-checks its signature anyway, because a head is cheap to verify and
/// expensive to trust by mistake. Throws [KtVerifyException].
Future<KtLookupResult> ktVerifyLookup(
  KtLookup lookup, {
  required Uint8List label,
  required Uint8List logPub,
}) async {
  if (!await lookup.head.verify(logPub)) {
    throw KtVerifyException('lookup: head not signed by the pinned log key');
  }
  if (!await lookup.map.verify(lookup.head.mapRoot, label)) {
    throw KtVerifyException('lookup: the map proof does not hash to mapRoot');
  }
  if (!lookup.map.present) {
    if (lookup.entry != null || lookup.inclusion != null) {
      throw KtVerifyException(
          'lookup: an entry was served with a proof of absence');
    }
    return KtLookupResult(head: lookup.head, latest: null);
  }
  final entry = lookup.entry;
  final inc = lookup.inclusion;
  if (entry == null || inc == null) {
    throw KtVerifyException(
        'lookup: the map names an entry the response does not carry');
  }
  if (!constantTimeEquals(entry.label, label)) {
    throw KtVerifyException('lookup: the entry is for another label');
  }
  if (entry.index != lookup.map.index || entry.version != lookup.map.version) {
    throw KtVerifyException(
        'lookup: the entry (${entry.index}, v${entry.version}) is not the one the map names (${lookup.map.index}, v${lookup.map.version})');
  }
  if (inc.index != entry.index || inc.size != lookup.head.size) {
    throw KtVerifyException(
        'lookup: the inclusion proof is not for this entry at the head\'s size');
  }
  final ok = await ktVerifyInclusion(
    leafHash: await entry.leafHash(),
    index: inc.index,
    size: inc.size,
    root: lookup.head.logRoot,
    path: inc.path,
  );
  if (!ok) {
    throw KtVerifyException('lookup: the inclusion proof does not hash to logRoot');
  }
  return KtLookupResult(head: lookup.head, latest: entry);
}

/// One `{entry, inclusion}` of a `/kt/v1/history/<label>` response, verified
/// under [head]. Returns the entry; throws [KtVerifyException].
Future<KtEntry> ktVerifyHistoryItem(
  Map<String, Object?> item, {
  required KtTreeHead head,
  required Uint8List label,
}) async {
  final e = item['entry'];
  final i = item['inclusion'];
  if (e is! Map || i is! Map) {
    throw KtVerifyException('history: entry and inclusion are required');
  }
  final entry = await KtEntry.fromJson(e.cast<String, Object?>());
  final inc = KtInclusionProof.fromJson(i.cast<String, Object?>());
  if (!constantTimeEquals(entry.label, label)) {
    throw KtVerifyException('history: an entry for another label');
  }
  if (inc.index != entry.index || inc.size != head.size) {
    throw KtVerifyException('history: inclusion is not for this entry at the head\'s size');
  }
  final ok = await ktVerifyInclusion(
    leafHash: await entry.leafHash(),
    index: inc.index,
    size: inc.size,
    root: head.logRoot,
    path: inc.path,
  );
  if (!ok) throw KtVerifyException('history: inclusion does not hash to logRoot');
  return entry;
}

// --- §19.6 publishing -------------------------------------------------------------------

Future<Uint8List> ktPublishInput({
  required Uint8List label,
  required int version,
  required Uint8List fp,
  required Uint8List valueHash,
}) async =>
    concatBytes([
      utf8.encode(_publishContext),
      label,
      _u64be(version),
      fp,
      valueHash,
    ]);

/// The body of `POST /kt/v1/publish` for a list at [version] with fingerprint
/// [fp], sealed as [value], signed by the account seed.
Future<Map<String, Object?>> ktPublishRequest({
  required Uint8List accountEdSeed,
  required int version,
  required Uint8List fp,
  required Uint8List value,
}) async {
  final kp = await _ed.newKeyPairFromSeed(accountEdSeed);
  final pub = Uint8List.fromList((await kp.extractPublicKey()).bytes);
  final input = await ktPublishInput(
    label: await ktLabel(pub),
    version: version,
    fp: fp,
    valueHash: await sha256Bytes(value),
  );
  final sig = await _ed.sign(input, keyPair: kp);
  return {
    'acct': b64(pub),
    'v': version,
    'fp': b64(fp),
    'value': b64(value),
    'sig': b64(sig.bytes),
  };
}

// --- §19.8 witnesses ---------------------------------------------------------------------

Uint8List ktWitnessInput(KtTreeHead head) =>
    concatBytes([utf8.encode(_witnessContext), head.signingInput]);

/// A witness's `sth.json`: the head it verified, co-signed.
class KtWitnessRecord {
  final KtTreeHead head;
  final Uint8List witnessPub;
  final Uint8List witnessSig;
  final int verifiedAt;

  KtWitnessRecord({
    required this.head,
    required this.witnessPub,
    required this.witnessSig,
    required this.verifiedAt,
  });

  static KtWitnessRecord fromJson(Map<String, Object?> j) {
    final sth = j['sth'];
    final w = j['witness'];
    if (sth is! Map || w is! Map) {
      throw KtVerifyException('witness record: sth and witness are required');
    }
    return KtWitnessRecord(
      head: KtTreeHead.fromJson(sth.cast<String, Object?>()),
      witnessPub: _bytes(w['pub'], 32, 'witness.pub'),
      witnessSig: _bytes(w['sig'], 64, 'witness.sig'),
      verifiedAt: _int(j['verifiedAt'], 'verifiedAt'),
    );
  }

  /// Both signatures: the log's over the head, the witness's over the head.
  /// [expectedWitnessPub], when given, must be the record's key.
  Future<bool> verify(Uint8List logPub, {Uint8List? expectedWitnessPub}) async {
    if (expectedWitnessPub != null &&
        !constantTimeEquals(expectedWitnessPub, witnessPub)) {
      return false;
    }
    if (!await head.verify(logPub)) return false;
    return _verify(witnessPub, ktWitnessInput(head), witnessSig);
  }
}

// --- helpers -----------------------------------------------------------------------------

Future<bool> _verify(Uint8List pub, Uint8List data, Uint8List sig) async {
  if (pub.length != 32 || sig.length != 64) return false;
  try {
    return await _ed.verify(data,
        signature: Signature(sig,
            publicKey: SimplePublicKey(pub, type: KeyPairType.ed25519)));
  } catch (_) {
    return false;
  }
}

int _int(Object? v, String what) {
  if (v is int && v >= 0 && v <= 0x1FFFFFFFFFFFFF) return v;
  if (v is num && v == v.roundToDouble() && v >= 0 && v <= 0x1FFFFFFFFFFFFF) {
    return v.toInt();
  }
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
