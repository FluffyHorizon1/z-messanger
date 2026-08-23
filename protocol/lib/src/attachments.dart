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

/// Raw bytes per chunk. The transport wraps chunk bytes in base64 twice
/// (once inside the chunk JSON, once around the whole payload), a ~1.78x
/// expansion — 480 KiB raw stays safely under the relay's 1 MB frame cap.
const int defaultChunkSize = 480 * 1024;
const String _fileAadContext = 'z-file-v1:';

final _aead = Xchacha20.poly1305Aead();

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
List<Uint8List> splitChunks(Uint8List data, {int chunkSize = defaultChunkSize}) {
  final out = <Uint8List>[];
  for (var off = 0; off < data.length; off += chunkSize) {
    out.add(Uint8List.sublistView(
        data, off, off + chunkSize > data.length ? data.length : off + chunkSize));
  }
  if (out.isEmpty) out.add(Uint8List(0));
  return out;
}
