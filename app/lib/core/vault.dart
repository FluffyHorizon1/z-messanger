import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:z_protocol/z_protocol.dart' as zp;

/// The encrypted local vault.
///
/// - A random 256-bit master key lives in the OS keystore (Android Keystore,
///   macOS Keychain, Windows credential store, Linux Secret Service). If the
///   platform keystore is unavailable (e.g. a Linux box with no keyring),
///   the key falls back to a 0600 file next to the database and the UI shows
///   a warning so the user knows.
/// - Every sensitive value (message bodies, names, contact bundles, session
///   state, file metadata) is encrypted cell-by-cell with XChaCha20-Poly1305
///   under the master key before it touches SQLite.
/// - Attachments are stored as separate blobs, each sealed with its own
///   random key, which is itself stored only inside an encrypted cell.
/// - Nothing is ever uploaded anywhere: this vault IS the message store.
/// Thrown by [Vault.open] when the vault is passphrase-protected and no
/// passphrase (or the wrong one) was supplied.
class VaultLockedException implements Exception {
  @override
  String toString() => 'VaultLockedException: a passphrase is required';
}

class WrongPassphraseException implements Exception {
  @override
  String toString() => 'WrongPassphraseException: incorrect passphrase';
}

/// Result of [Vault.inspect]: whether a vault exists and whether opening it
/// needs the user's passphrase.
class VaultStatus {
  final bool exists;
  final bool requiresPassphrase;
  const VaultStatus({required this.exists, required this.requiresPassphrase});
}

class Vault {
  final Database db;
  final Directory root;
  final Directory filesDir;
  final SecretKey _masterKey;
  final Uint8List
      _masterKeyBytes; // kept so we can re-wrap on passphrase change
  final Uint8List _deviceSecret;
  final bool usedFallbackKeyStore;
  bool _hasPassphrase;

  static final _aead = Xchacha20.poly1305Aead();

  // Argon2id params (OWASP-ish): 19 MiB, t=2, p=1 — matches the .zid backup.
  static Argon2id _kdf() => Argon2id(
        memory: 19 * 1024,
        parallelism: 1,
        iterations: 2,
        hashLength: 32,
      );

  Vault._(
      this.db,
      this.root,
      this.filesDir,
      this._masterKey,
      this._masterKeyBytes,
      this._deviceSecret,
      this.usedFallbackKeyStore,
      this._hasPassphrase);

  bool get hasPassphrase => _hasPassphrase;

  static File _configFile(Directory root) =>
      File(p.join(root.path, 'key.json'));

  /// Reports whether a vault exists here and whether it is passphrase-locked —
  /// without needing the passphrase or opening the database. The bootstrapper
  /// calls this to decide whether to show the unlock screen.
  static Future<VaultStatus> inspect({Directory? rootOverride}) async {
    final root = rootOverride ??
        Directory(p.join((await getApplicationSupportDirectory()).path, 'z'));
    final cfg = _configFile(root);
    if (await cfg.exists()) {
      try {
        final j = jsonDecode(await cfg.readAsString()) as Map<String, Object?>;
        return VaultStatus(
            exists: true, requiresPassphrase: j['hasPassphrase'] == true);
      } catch (_) {
        return const VaultStatus(exists: true, requiresPassphrase: false);
      }
    }
    // No config yet: a legacy install (pre-passphrase) counts as "exists,
    // no passphrase"; a brand-new device counts as not existing.
    final legacy = await _legacyMasterKey(root, deleteAfter: false);
    return VaultStatus(exists: legacy != null, requiresPassphrase: false);
  }

  /// Opens the vault. Supply [passphrase] when [inspect] reported
  /// requiresPassphrase. [rootOverride] lets tests use a temp directory.
  static Future<Vault> open(
      {String? passphrase, Directory? rootOverride}) async {
    final root = rootOverride ??
        Directory(p.join((await getApplicationSupportDirectory()).path, 'z'));
    final filesDir = Directory(p.join(root.path, 'files'));
    await filesDir.create(recursive: true);

    final (deviceSecret, fallback) = await _loadOrCreateDeviceSecret(root);
    final cfg = _configFile(root);

    Uint8List masterKeyBytes;
    bool hasPass;

    if (await cfg.exists()) {
      final j = jsonDecode(await cfg.readAsString()) as Map<String, Object?>;
      hasPass = j['hasPassphrase'] == true;
      final salt =
          j['salt'] != null ? zp.unb64(j['salt'] as String) : Uint8List(0);
      if (hasPass && (passphrase == null || passphrase.isEmpty)) {
        throw VaultLockedException();
      }
      final wrapKey = await _deriveWrapKey(deviceSecret,
          passphrase: hasPass ? passphrase : null, salt: salt);
      masterKeyBytes = await _unwrap(j['wrapped'] as String, wrapKey);
    } else {
      // First open with the new scheme: migrate a legacy key or make a new one.
      final legacy = await _legacyMasterKey(root, deleteAfter: true);
      masterKeyBytes = legacy ?? zp.randomBytes(32);
      hasPass = false;
      final wrapKey = await _deriveWrapKey(deviceSecret,
          passphrase: null, salt: Uint8List(0));
      await _writeConfig(root,
          hasPassphrase: false,
          salt: Uint8List(0),
          wrapped: await _wrap(masterKeyBytes, wrapKey));
    }

    sqfliteFfiInit();
    final db = await databaseFactoryFfi.openDatabase(
      p.join(root.path, 'z.db'),
      options: OpenDatabaseOptions(
        version: 1,
        onCreate: (db, v) async {
          await db.execute('''
            CREATE TABLE contacts(
              rid TEXT PRIMARY KEY,
              enc_bundle TEXT NOT NULL,
              enc_name TEXT NOT NULL,
              ttl_seconds INTEGER NOT NULL DEFAULT 0,
              verified INTEGER NOT NULL DEFAULT 0,
              created_ms INTEGER NOT NULL
            )''');
          await db.execute('''
            CREATE TABLE conversations(
              rid TEXT PRIMARY KEY,
              enc_state TEXT NOT NULL,
              updated_ms INTEGER NOT NULL
            )''');
          await db.execute('''
            CREATE TABLE messages(
              mid TEXT NOT NULL,
              rid TEXT NOT NULL,
              outgoing INTEGER NOT NULL,
              kind TEXT NOT NULL,
              enc_body TEXT NOT NULL,
              fid TEXT,
              ts_ms INTEGER NOT NULL,
              status INTEGER NOT NULL DEFAULT 0,
              expire_at_ms INTEGER NOT NULL DEFAULT 0,
              receipt_sent INTEGER NOT NULL DEFAULT 0,
              PRIMARY KEY (rid, mid)
            )''');
          await db.execute(
              'CREATE INDEX idx_messages_rid_ts ON messages(rid, ts_ms)');
          await db.execute('''
            CREATE TABLE files(
              fid TEXT PRIMARY KEY,
              rid TEXT NOT NULL,
              mid TEXT NOT NULL,
              enc_meta TEXT NOT NULL,
              complete INTEGER NOT NULL DEFAULT 0,
              got_chunks INTEGER NOT NULL DEFAULT 0,
              total_chunks INTEGER NOT NULL DEFAULT 0
            )''');
          await db.execute('''
            CREATE TABLE chunks(
              fid TEXT NOT NULL,
              idx INTEGER NOT NULL,
              payload TEXT NOT NULL,
              PRIMARY KEY (fid, idx)
            )''');
          await db.execute('''
            CREATE TABLE outbox(
              seq INTEGER PRIMARY KEY AUTOINCREMENT,
              id TEXT NOT NULL,
              rid TEXT NOT NULL,
              payload TEXT NOT NULL,
              created_ms INTEGER NOT NULL
            )''');
          await db.execute('''
            CREATE TABLE inbox_dedupe(
              from_rid TEXT NOT NULL,
              mid TEXT NOT NULL,
              seen_ms INTEGER NOT NULL,
              PRIMARY KEY (from_rid, mid)
            )''');
          await db.execute('''
            CREATE TABLE kv(
              k TEXT PRIMARY KEY,
              v TEXT NOT NULL
            )''');
        },
      ),
    );
    return Vault._(db, root, filesDir, SecretKey(masterKeyBytes),
        masterKeyBytes, deviceSecret, fallback, hasPass);
  }

  // ------------------------------------------------------------------
  // Passphrase management — re-wraps the (unchanged) master key so that all
  // already-sealed data stays valid. The passphrase never leaves the device.
  // ------------------------------------------------------------------

  /// Sets or replaces the app passphrase. Requires the vault to be unlocked
  /// (it always is once open()). The master key is unchanged.
  Future<void> setPassphrase(String passphrase) async {
    if (passphrase.isEmpty) {
      throw ArgumentError('passphrase must not be empty');
    }
    final salt = zp.randomBytes(16);
    final wrapKey =
        await _deriveWrapKey(_deviceSecret, passphrase: passphrase, salt: salt);
    await _writeConfig(root,
        hasPassphrase: true,
        salt: salt,
        wrapped: await _wrap(_masterKeyBytes, wrapKey));
    _hasPassphrase = true;
  }

  /// Removes the passphrase; the app will open automatically again (device
  /// keystore only).
  Future<void> removePassphrase() async {
    final wrapKey = await _deriveWrapKey(_deviceSecret,
        passphrase: null, salt: Uint8List(0));
    await _writeConfig(root,
        hasPassphrase: false,
        salt: Uint8List(0),
        wrapped: await _wrap(_masterKeyBytes, wrapKey));
    _hasPassphrase = false;
  }

  /// Confirms a candidate passphrase against the stored wrapped key (for a
  /// "confirm current passphrase" step before changing/removing it).
  Future<bool> verifyPassphrase(String passphrase) async {
    try {
      final j = jsonDecode(await _configFile(root).readAsString())
          as Map<String, Object?>;
      if (j['hasPassphrase'] != true) return true;
      final salt = zp.unb64(j['salt'] as String);
      final wrapKey = await _deriveWrapKey(_deviceSecret,
          passphrase: passphrase, salt: salt);
      await _unwrap(j['wrapped'] as String, wrapKey);
      return true;
    } catch (_) {
      return false;
    }
  }

  // ------------------------------------------------------------------
  // Key wrapping internals
  // ------------------------------------------------------------------

  /// K_wrap = HKDF( deviceSecret [|| Argon2id(passphrase, salt)] ). Composing
  /// the device keystore secret with the passphrase means BOTH the device and
  /// the passphrase are needed to unlock — neither alone suffices.
  static Future<SecretKey> _deriveWrapKey(Uint8List deviceSecret,
      {String? passphrase, required Uint8List salt}) async {
    var material = deviceSecret;
    if (passphrase != null && passphrase.isNotEmpty) {
      final passKey = await _kdf().deriveKey(
        secretKey: SecretKey(utf8.encode(passphrase)),
        nonce: salt,
      );
      material = Uint8List.fromList(
          [...deviceSecret, ...await passKey.extractBytes()]);
    }
    final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
    return hkdf.deriveKey(
      secretKey: SecretKey(material),
      nonce: Uint8List(0),
      info: utf8.encode('z-wrap-v1'),
    );
  }

  static Future<String> _wrap(Uint8List masterBytes, SecretKey wrapKey) async {
    final nonce = zp.randomBytes(24);
    final box =
        await _aead.encrypt(masterBytes, secretKey: wrapKey, nonce: nonce);
    return base64Encode(<int>[...nonce, ...box.cipherText, ...box.mac.bytes]);
  }

  static Future<Uint8List> _unwrap(String blob, SecretKey wrapKey) async {
    final raw = base64Decode(blob);
    final nonce = raw.sublist(0, 24);
    final mac = raw.sublist(raw.length - 16);
    final ct = raw.sublist(24, raw.length - 16);
    try {
      final clear = await _aead.decrypt(
        SecretBox(ct, nonce: nonce, mac: Mac(mac)),
        secretKey: wrapKey,
      );
      return Uint8List.fromList(clear);
    } on SecretBoxAuthenticationError {
      throw WrongPassphraseException();
    }
  }

  static Future<void> _writeConfig(Directory root,
      {required bool hasPassphrase,
      required Uint8List salt,
      required String wrapped}) async {
    final j = <String, Object?>{
      'v': 1,
      'hasPassphrase': hasPassphrase,
      if (hasPassphrase) 'salt': zp.b64(salt),
      'wrapped': wrapped,
    };
    await _configFile(root).writeAsString(jsonEncode(j), flush: true);
  }

  /// A device-held secret (in the OS keystore, or a 0600 file fallback). This
  /// is NOT the master key — it only helps wrap it.
  static Future<(Uint8List, bool)> _loadOrCreateDeviceSecret(
      Directory root) async {
    const storage = FlutterSecureStorage(
      aOptions: AndroidOptions(encryptedSharedPreferences: true),
    );
    try {
      final existing = await storage.read(key: 'z_device_secret');
      if (existing != null) return (zp.unb64(existing), false);
      final fresh = zp.randomBytes(32);
      await storage.write(key: 'z_device_secret', value: zp.b64(fresh));
      final readBack = await storage.read(key: 'z_device_secret');
      if (readBack == zp.b64(fresh)) return (fresh, false);
      throw Exception('keystore write not persisted');
    } catch (_) {
      final f = File(p.join(root.path, '.device'));
      if (await f.exists()) {
        return (zp.unb64((await f.readAsString()).trim()), true);
      }
      final fresh = zp.randomBytes(32);
      await f.writeAsString(zp.b64(fresh), flush: true);
      if (Platform.isLinux || Platform.isMacOS) {
        try {
          await Process.run('chmod', ['600', f.path]);
        } catch (_) {}
      }
      return (fresh, true);
    }
  }

  /// Reads (and optionally clears) a pre-passphrase master key from the old
  /// keystore entry or `.master` file, for one-time migration.
  static Future<Uint8List?> _legacyMasterKey(Directory root,
      {required bool deleteAfter}) async {
    const storage = FlutterSecureStorage(
      aOptions: AndroidOptions(encryptedSharedPreferences: true),
    );
    try {
      final existing = await storage.read(key: 'z_master_key');
      if (existing != null) {
        if (deleteAfter) {
          try {
            await storage.delete(key: 'z_master_key');
          } catch (_) {}
        }
        return zp.unb64(existing);
      }
    } catch (_) {}
    final f = File(p.join(root.path, '.master'));
    if (await f.exists()) {
      final bytes = zp.unb64((await f.readAsString()).trim());
      if (deleteAfter) {
        try {
          await f.delete();
        } catch (_) {}
      }
      return bytes;
    }
    return null;
  }

  // ------------------------------------------------------------------
  // Cell encryption
  // ------------------------------------------------------------------

  Future<String> seal(String plaintext) async {
    final nonce = zp.randomBytes(24);
    final box = await _aead.encrypt(utf8.encode(plaintext),
        secretKey: _masterKey, nonce: nonce);
    return base64Encode(<int>[...nonce, ...box.cipherText, ...box.mac.bytes]);
  }

  Future<String> unseal(String sealed) async {
    final raw = base64Decode(sealed);
    final nonce = raw.sublist(0, 24);
    final mac = raw.sublist(raw.length - 16);
    final ct = raw.sublist(24, raw.length - 16);
    final clear = await _aead.decrypt(
      SecretBox(ct, nonce: nonce, mac: Mac(mac)),
      secretKey: _masterKey,
    );
    return utf8.decode(clear);
  }

  // ------------------------------------------------------------------
  // Encrypted blob storage for attachments
  // ------------------------------------------------------------------

  /// Writes [bytes] encrypted under a fresh random key; returns the key
  /// material to stash inside an encrypted DB cell.
  Future<Map<String, String>> writeBlob(String fid, Uint8List bytes) async {
    final key = zp.randomBytes(32);
    final nonce = zp.randomBytes(24);
    final box =
        await _aead.encrypt(bytes, secretKey: SecretKey(key), nonce: nonce);
    final f = File(p.join(filesDir.path, '$fid.bin'));
    await f
        .writeAsBytes(<int>[...box.cipherText, ...box.mac.bytes], flush: true);
    return {'k': zp.b64(key), 'n': zp.b64(nonce)};
  }

  Future<Uint8List> readBlob(String fid, Map<String, Object?> keyInfo) async {
    final f = File(p.join(filesDir.path, '$fid.bin'));
    final raw = await f.readAsBytes();
    final ct = raw.sublist(0, raw.length - 16);
    final mac = raw.sublist(raw.length - 16);
    final clear = await _aead.decrypt(
      SecretBox(ct, nonce: zp.unb64(keyInfo['n'] as String), mac: Mac(mac)),
      secretKey: SecretKey(zp.unb64(keyInfo['k'] as String)),
    );
    return Uint8List.fromList(clear);
  }

  Future<void> deleteBlob(String fid) async {
    final f = File(p.join(filesDir.path, '$fid.bin'));
    if (await f.exists()) {
      // Best-effort overwrite before unlink (not guaranteed on flash/COW
      // filesystems, but cheap defense in depth).
      try {
        final len = await f.length();
        await f.writeAsBytes(Uint8List(len), flush: true);
      } catch (_) {}
      await f.delete();
    }
  }

  // ------------------------------------------------------------------
  // Simple encrypted kv
  // ------------------------------------------------------------------

  Future<void> kvPut(String key, String value, {bool sensitive = true}) async {
    final v = sensitive ? await seal(value) : value;
    await db.insert('kv', {'k': (sensitive ? 's:' : 'p:') + key, 'v': v},
        conflictAlgorithm: ConflictAlgorithm.replace);
  }

  Future<String?> kvGet(String key) async {
    for (final prefix in ['s:', 'p:']) {
      final rows =
          await db.query('kv', where: 'k = ?', whereArgs: [prefix + key]);
      if (rows.isNotEmpty) {
        final v = rows.first['v'] as String;
        return prefix == 's:' ? await unseal(v) : v;
      }
    }
    return null;
  }

  Future<void> kvDelete(String key) async {
    for (final prefix in ['s:', 'p:']) {
      await db.delete('kv', where: 'k = ?', whereArgs: [prefix + key]);
    }
  }

  /// Destroys everything: database, attachments, master key.
  Future<void> wipe() async {
    await db.close();
    const storage = FlutterSecureStorage();
    for (final k in ['z_device_secret', 'z_master_key']) {
      try {
        await storage.delete(key: k);
      } catch (_) {}
    }
    if (await root.exists()) {
      for (final entity in root.listSync(recursive: true).reversed) {
        try {
          if (entity is File) {
            final len = entity.lengthSync();
            entity.writeAsBytesSync(Uint8List(len > 0 ? len : 0), flush: true);
          }
          entity.deleteSync();
        } catch (_) {}
      }
      try {
        await root.delete(recursive: true);
      } catch (_) {}
    }
  }
}
