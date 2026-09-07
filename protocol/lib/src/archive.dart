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
class ZArchive {
  static final _aead = Xchacha20.poly1305Aead();

  static const magic = 'zbk';
  static const version = 1;

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
  /// written at, so a newer build knows what it is reading.
  static Uint8List buildHeader({
    required Uint8List salt,
    required Uint8List noncePrefix,
    required int schema,
    required int createdMs,
    String app = 'z',
  }) =>
      Uint8List.fromList(utf8.encode(jsonEncode({
        'z': magic,
        'v': version,
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

  static Map<String, Object?> parseHeader(Uint8List headerLine) {
    final j = jsonDecode(utf8.decode(headerLine)) as Map<String, Object?>;
    if (j['z'] != magic) {
      throw const FormatException('not a Z backup archive');
    }
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
    return Uint8List.fromList([...box.cipherText, ...box.mac.bytes]);
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
    return Uint8List.fromList([id.length, ...id, ...bytes]);
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
