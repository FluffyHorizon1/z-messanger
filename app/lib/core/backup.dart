import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:z_protocol/z_protocol.dart';

/// Passphrase-encrypted identity backup (.zid file).
///
/// Contains: identity seeds, display name, and contact bundles.
/// Does NOT contain messages — messages live only in each device's vault,
/// by design. KDF: Argon2id (19 MiB, t=2, p=1, per OWASP guidance), then
/// XChaCha20-Poly1305.
class BackupFile {
  static final _aead = Xchacha20.poly1305Aead();

  static Argon2id _kdf() => Argon2id(
        memory: 19 * 1024, // KiB
        parallelism: 1,
        iterations: 2,
        hashLength: 32,
      );

  static Future<Uint8List> export({
    required ZIdentity identity,
    required String displayName,
    required List<Map<String, Object?>> contactRecords,
    required String passphrase,
  }) async {
    final inner = jsonEncode({
      'v': 1,
      'identity': identity.toJson(),
      'name': displayName,
      'contacts': contactRecords,
    });
    final salt = randomBytes(16);
    final key = await _kdf().deriveKey(
      secretKey: SecretKey(utf8.encode(passphrase)),
      nonce: salt,
    );
    final nonce = randomBytes(24);
    final box = await _aead.encrypt(utf8.encode(inner),
        secretKey: key, nonce: nonce);
    final envelope = jsonEncode({
      'z': 'backup',
      'v': 1,
      'kdf': 'argon2id',
      'm': 19 * 1024,
      't': 2,
      'p': 1,
      'salt': b64(salt),
      'nonce': b64(nonce),
      'ct': b64(box.cipherText),
      'mac': b64(box.mac.bytes),
    });
    return Uint8List.fromList(utf8.encode(envelope));
  }

  /// Throws on wrong passphrase or corrupt file.
  static Future<Map<String, Object?>> import(
      Uint8List fileBytes, String passphrase) async {
    final j = jsonDecode(utf8.decode(fileBytes)) as Map<String, Object?>;
    if (j['z'] != 'backup' || j['v'] != 1) {
      throw const FormatException('not a Z backup file');
    }
    final kdf = Argon2id(
      memory: (j['m'] as num).toInt(),
      parallelism: (j['p'] as num).toInt(),
      iterations: (j['t'] as num).toInt(),
      hashLength: 32,
    );
    final key = await kdf.deriveKey(
      secretKey: SecretKey(utf8.encode(passphrase)),
      nonce: unb64(j['salt'] as String),
    );
    final clear = await _aead.decrypt(
      SecretBox(unb64(j['ct'] as String),
          nonce: unb64(j['nonce'] as String),
          mac: Mac(unb64(j['mac'] as String))),
      secretKey: key,
    );
    return (jsonDecode(utf8.decode(clear)) as Map).cast<String, Object?>();
  }
}
