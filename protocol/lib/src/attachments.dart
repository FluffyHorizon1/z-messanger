import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'util.dart';

/// Attachment encryption.
///
/// A file is encrypted CLIENT-SIDE with its own random 256-bit key `fk`.
/// The key travels to the recipient inside a ratchet-encrypted 'file' offer
/// message, so it enjoys the exact same E2E protection as text. The encrypted
/// chunks themselves are relayed as opaque blobs OUTSIDE the ratchet (they
/// are already sealed under `fk`, and this keeps big transfers from bloating
/// ratchet state). Chunk nonces are deterministic: fileNonce(16) || index(8).
///
/// The relay learns only: sizes, counts and timing — never names, types or
/// content. File name/mime/hash travel only inside the ratchet.

/// Raw bytes per chunk.
///
/// A chunk payload is base64 twice over (inside the chunk JSON and around the
/// whole payload, ~1.78x), then SEALED (sealed.dart): padded up to a size
/// bucket and base64url'd again (~1.33x). The largest bucket whose sealed
/// envelope still fits the relay's default 1,000,000-character frame cap is
/// 262144 bytes, and a 140 KiB raw chunk is the most that lands inside it
/// (255,022 bytes of padded input, ~2.8% padding). Every chunk envelope is
/// therefore the same size on the wire. 480 KiB (the pre-sealed-sender value)
/// sealed to 1.5 MB and was rejected by the relay as `too_large`.
const int defaultChunkSize = 140 * 1024;
const String _fileAadContext = 'z-file-v1:';

final _aead = Xchacha20.poly1305Aead();

/// The shape PROTOCOL.md §7 gives a file id: `b64url(12 random bytes)`, which
/// is exactly sixteen characters of the base64url alphabet and nothing else.
///
/// This is a RECEIVER's check. The id is chosen by whoever sends the offer
/// and is carried in an ordinary inner field, so "it is one of ours" is an
/// assumption about a peer rather than a fact — and a client that treats it
/// as a name (a filename, a directory entry, a key in a store) is trusting a
/// string a contact wrote. `..`, a leading `/`, a drive letter and a path
/// separator are all valid Dart strings and none of them is a file id.
final RegExp _fidShape = RegExp(r'^[A-Za-z0-9_-]{16}$');

/// True if [s] is a file id as §7 defines one. Anything else is not a file
/// this protocol produced, whatever else it may be.
bool isWellFormedFid(String s) => _fidShape.hasMatch(s);

class FileKeyMaterial {
  final String fid; // public chunk-routing id (random, meaningless)
  final Uint8List fk; // 32-byte file key (E2E-protected)
  final Uint8List fn; // 16-byte nonce base
  FileKeyMaterial({required this.fid, required this.fk, required this.fn});

  static FileKeyMaterial generate() => FileKeyMaterial(
        fid: b64url(randomBytes(12)),
        fk: randomBytes(32),
        fn: randomBytes(16),
      );
}

Uint8List chunkNonce(Uint8List fnBase16, int index) {
  final n = Uint8List(24);
  n.setRange(0, 16, fnBase16);
  var v = index;
  for (var i = 0; i < 8; i++) {
    n[16 + i] = v & 0xff;
    v >>= 8;
  }
  return n;
}

/// Encrypts one chunk -> opaque transport payload (base64 string).
Future<String> encryptChunk(
    FileKeyMaterial km, int index, Uint8List chunkBytes) async {
  final box = await _aead.encrypt(
    chunkBytes,
    secretKey: SecretKey(km.fk),
    nonce: chunkNonce(km.fn, index),
    aad: utf8.encode('$_fileAadContext${km.fid}'),
  );
  final payload = <String, Object?>{
    'v': 1,
    't': 'f',
    'fid': km.fid,
    'idx': index,
    'ct': b64(box.cipherText),
    'mac': b64(box.mac.bytes),
  };
  return base64Encode(utf8.encode(jsonEncode(payload)));
}

class FileChunk {
  final String fid;
  final int index;
  final Uint8List cipherText;
  final Uint8List mac;
  FileChunk(this.fid, this.index, this.cipherText, this.mac);
}

/// Returns null if the payload is not a file chunk.
FileChunk? tryParseChunk(String transportPayload) {
  try {
    final j = jsonDecode(utf8.decode(base64Decode(transportPayload)))
        as Map<String, Object?>;
    if (j['v'] != 1 || j['t'] != 'f') return null;
    return FileChunk(
      j['fid'] as String,
      (j['idx'] as num).toInt(),
      unb64(j['ct'] as String),
      unb64(j['mac'] as String),
    );
  } catch (_) {
    return null;
  }
}

/// Decrypts one chunk with the key material from the (ratchet-protected)
/// file offer. Throws on tampering.
Future<Uint8List> decryptChunk(
    {required Uint8List fk,
    required Uint8List fn,
    required String fid,
    required FileChunk chunk}) async {
  final clear = await _aead.decrypt(
    SecretBox(chunk.cipherText,
        nonce: chunkNonce(fn, chunk.index), mac: Mac(chunk.mac)),
    secretKey: SecretKey(fk),
    aad: utf8.encode('$_fileAadContext$fid'),
  );
  return Uint8List.fromList(clear);
}

/// Splits [data] into chunks of [chunkSize].
List<Uint8List> splitChunks(Uint8List data,
    {int chunkSize = defaultChunkSize}) {
  final out = <Uint8List>[];
  for (var off = 0; off < data.length; off += chunkSize) {
    out.add(Uint8List.sublistView(data, off,
        off + chunkSize > data.length ? data.length : off + chunkSize));
  }
  if (out.isEmpty) out.add(Uint8List(0));
  return out;
}
