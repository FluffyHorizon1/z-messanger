import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'util.dart';

/// The `.zbk` backup archive format (§9, `docs/BACKUP.md`).
///
/// A file is one plaintext header line followed by a stream of sealed frames:
///
///     <header JSON>\n
///     [u32be len][ciphertext‖mac]     frame 0
///     [u32be len][ciphertext‖mac]     frame 1
///     …
///
/// Every frame is XChaCha20‑Poly1305 under one key derived from the recovery
/// code, with nonce `noncePrefix(16) ‖ u64be(index)` — so frames stream in
/// both directions without holding the archive in memory, and a frame's
/// nonce is unique by construction. The header bytes and the frame index are
/// the AEAD's associated data, which pins each frame to its position in this
/// archive: a frame cannot be reordered, duplicated, or lifted into another
/// file without the tag failing.
///
/// The last frame is a terminator carrying the record count. Without it an
/// importer refuses the archive, so a truncated file — the most likely way a
/// backup goes wrong — fails loudly instead of restoring a silently shorter
/// history.
///
/// **Versions.** The header's `v` is the format's MAJOR version: a reader
/// refuses any major version it does not know ([ArchiveTooNewException]),
/// because a major bump is by definition a file an older reader would get
/// wrong. `mv` counts MINOR revisions within a major: new record types and
/// new optional fields, which an older reader of the same major skips —
/// except that a record whose writer marked it [keepField] is one a reader
/// that does not know its type stores and writes back, byte for byte, into
/// the archives it takes later (`BACKUP.md` §5). An archive with no `mv` is
/// minor 0, which is what every build before minor 1 wrote.
class ZArchive {
  static final _aead = Xchacha20.poly1305Aead();

  static const magic = 'zbk';
  static const version = 1;

  /// The minor revision this build writes (see the class comment). 1 adds
  /// the account's device-list and transparency state, the block list and
  /// pending requests, the ids of past sessions, and [keepField].
  static const minorVersion = 1;

  /// A record member: `"keep": 1` says a reader that does not know this
  /// record's type may carry it into the next archive unchanged. Its writer
  /// sets it only where a copy that has gone stale — kept by a build that
  /// could not read it, through whatever that build did meanwhile — is
  /// still right to restore.
  static const keepField = 'keep';

  /// Argon2id parameters, matching the vault's (OWASP guidance). The recovery
  /// code is already 120 random bits; this is defence in depth, not the thing
  /// standing between an attacker and the archive.
  static const kdfMemoryKib = 19 * 1024;
  static const kdfIterations = 2;
  static const kdfParallelism = 1;

  /// Frame kinds.
  static const kindRecord = 0; // UTF-8 JSON record
  static const kindBlob = 1; // [u8 idLen][id][bytes] — an attachment chunk
  static const kindEnd = 2; // UTF-8 JSON terminator

  static Argon2id _kdf() => Argon2id(
        memory: kdfMemoryKib,
        parallelism: kdfParallelism,
        iterations: kdfIterations,
        hashLength: 32,
      );

  /// Derives the archive key from the recovery code's canonical bytes.
  static Future<SecretKey> deriveKey(
          Uint8List codeMaterial, Uint8List salt) async =>
      _kdf().deriveKey(secretKey: SecretKey(codeMaterial), nonce: salt);

  /// The plaintext header. `schema` records the vault schema the records were
  /// written at, so a newer build knows what it is reading. [minor] is
  /// written as `mv` when given; the app passes [minorVersion], and a minor-0
  /// header (the frozen `archive.json` vector's) leaves it out.
  static Uint8List buildHeader({
    required Uint8List salt,
    required Uint8List noncePrefix,
    required int schema,
    required int createdMs,
    String app = 'z',
    int? minor,
  }) =>
      Uint8List.fromList(utf8.encode(jsonEncode({
        'z': magic,
        'v': version,
        if (minor != null) 'mv': minor,
        'app': app,
        'kdf': 'argon2id',
        'm': kdfMemoryKib,
        't': kdfIterations,
        'p': kdfParallelism,
        'salt': b64(salt),
        'np': b64(noncePrefix),
        'schema': schema,
        'created': createdMs,
      })));

  /// Whether [header] — a parsed header line, or anything carrying its `z`
  /// and `v` — is an archive of a major version newer than this build reads.
  /// Answerable from the plaintext header alone, so before any key is
  /// derived.
  static bool isNewerMajor(Map<String, Object?> header) {
    final v = header['v'];
    return header['z'] == magic && v is int && v > version;
  }

  /// The header's minor revision; 0 when it names none.
  static int minorOf(Map<String, Object?> header) {
    final mv = header['mv'];
    return mv is int && mv >= 0 ? mv : 0;
  }

  static Map<String, Object?> parseHeader(Uint8List headerLine) {
    final j = jsonDecode(utf8.decode(headerLine)) as Map<String, Object?>;
    if (j['z'] != magic) {
      throw const FormatException('not a Z backup archive');
    }
    if (isNewerMajor(j)) throw ArchiveTooNewException(j['v'] as int);
    if (j['v'] != version) {
      throw FormatException('unsupported archive version ${j['v']}');
    }
    return j;
  }

  static Uint8List _nonce(Uint8List prefix, int index) {
    final n = Uint8List(24)..setRange(0, 16, prefix);
    final bd = ByteData.view(n.buffer);
    bd.setUint64(16, index);
    return n;
  }

  static Uint8List _aad(Uint8List header, int index) {
    final out = Uint8List(header.length + 8);
    out.setRange(0, header.length, header);
    ByteData.view(out.buffer).setUint64(header.length, index);
    return out;
  }

  /// Seals one frame. [payload] is the frame body *without* its kind byte.
  static Future<Uint8List> sealFrame({
    required SecretKey key,
    required Uint8List header,
    required Uint8List noncePrefix,
    required int index,
    required int kind,
    required List<int> payload,
  }) async {
    final plain = Uint8List(payload.length + 1)
      ..[0] = kind
      ..setRange(1, payload.length + 1, payload);
    final box = await _aead.encrypt(plain,
        secretKey: key,
        nonce: _nonce(noncePrefix, index),
        aad: _aad(header, index));
    // Exact-size typed buffer rather than a spread into a growable
    // `List<int>`, which costs eight bytes an element and doubles as it
    // grows: this runs once per 256 KiB attachment frame.
    final ct = box.cipherText;
    final mac = box.mac.bytes;
    final out = Uint8List(ct.length + mac.length);
    out.setRange(0, ct.length, ct);
    out.setRange(ct.length, out.length, mac);
    return out;
  }

  /// Opens one frame, returning its kind and body. Throws [FormatException]
  /// when the tag fails — a wrong code, a corrupt file, or a frame that was
  /// moved.
  static Future<(int kind, Uint8List payload)> openFrame({
    required SecretKey key,
    required Uint8List header,
    required Uint8List noncePrefix,
    required int index,
    required Uint8List sealed,
  }) async {
    if (sealed.length < 17) throw const FormatException('short frame');
    final mac = sealed.sublist(sealed.length - 16);
    final ct = sealed.sublist(0, sealed.length - 16);
    try {
      final clear = await _aead.decrypt(
        SecretBox(ct, nonce: _nonce(noncePrefix, index), mac: Mac(mac)),
        secretKey: key,
        aad: _aad(header, index),
      );
      return (clear.first, Uint8List.fromList(clear.sublist(1)));
    } on SecretBoxAuthenticationError {
      throw const FormatException('wrong recovery code, or the archive is '
          'damaged');
    }
  }

  /// Frame body for an attachment chunk.
  static Uint8List blobPayload(String fid, List<int> bytes) {
    final id = utf8.encode(fid);
    if (id.length > 255) throw const FormatException('file id too long');
    final out = Uint8List(1 + id.length + bytes.length);
    out[0] = id.length;
    out.setRange(1, 1 + id.length, id);
    out.setRange(1 + id.length, out.length, bytes);
    return out;
  }

  static (String fid, Uint8List bytes) parseBlobPayload(Uint8List payload) {
    if (payload.isEmpty) throw const FormatException('empty blob frame');
    final idLen = payload[0];
    if (payload.length < 1 + idLen) {
      throw const FormatException('truncated blob frame');
    }
    return (
      utf8.decode(payload.sublist(1, 1 + idLen)),
      Uint8List.fromList(payload.sublist(1 + idLen)),
    );
  }
}

/// An archive of a major format version this build does not read — written
/// by a newer build. Refused rather than read in part: a major bump is a
/// change an older reader would get wrong, and what it would get wrong is
/// the user's history. A [FormatException], so every caller that already
/// refuses a damaged file refuses this one too; the message says what to do.
class ArchiveTooNewException extends FormatException {
  final int major;
  ArchiveTooNewException(this.major)
      : super('This backup was made by a newer version of Z (archive format '
            '$major). Update Z first, then restore it.');
}
