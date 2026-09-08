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
/// - With a passphrase set, the master key is wrapped under
///   HKDF(deviceSecret || Argon2id(passphrase)). Biometric unlock (7.8) keeps
///   that Argon2id output — never the passphrase — in the OS keystore and
///   feeds it back through [Vault.open]`(passKey:)` after the OS prompt.
///
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

  /// Database schema version.
  ///
  /// 1 — the original store.
  /// 2 — message interactions (8.1): reply/edit/delete columns on `messages`
  ///     and the `reactions` table.
  /// 3 — 8.1c: `forwarded`, which needs a column of its own — a 1:1 text
  ///     row's sealed body is the bare message, with no envelope to put a
  ///     flag in, and inventing one would misparse ordinary text.
  static const int schemaVersion = 5;

  // Message ids are already stored in the clear (they are the primary key),
  // so `reply_to` — a mid within the same chat — reveals nothing the row
  // layout does not. Bodies and reaction emoji stay sealed.
  static const String _v2MessageColumns = '''
              reply_to TEXT,
              edited_ms INTEGER NOT NULL DEFAULT 0,
              deleted INTEGER NOT NULL DEFAULT 0,
              forwarded INTEGER NOT NULL DEFAULT 0''';

  static const String _createReactions = '''
            CREATE TABLE reactions(
              rid TEXT NOT NULL,
              mid TEXT NOT NULL,
              sender_rid TEXT NOT NULL,
              enc_emoji TEXT NOT NULL,
              ts_ms INTEGER NOT NULL,
              PRIMARY KEY (rid, mid, sender_rid)
            )''';

  /// Schema migrations. Each step is additive (new nullable/defaulted columns
  /// and new tables) so an interrupted upgrade cannot lose messages, and a
  /// vault written by a newer build still opens read-compatible rows.
  static Future<void> _migrate(Database db, int from, int to) async {
    if (from < 2) {
      for (final column in const [
        'reply_to TEXT',
        'edited_ms INTEGER NOT NULL DEFAULT 0',
        'deleted INTEGER NOT NULL DEFAULT 0',
      ]) {
        await db.execute('ALTER TABLE messages ADD COLUMN $column');
      }
      await db.execute(_createReactions);
    }
    if (from < 3) {
      await db.execute(
          'ALTER TABLE messages ADD COLUMN forwarded INTEGER NOT NULL DEFAULT 0');
    }
    if (from < 4) {
      // v3 identity (§18). Two columns, both nullable, both meaning "not
      // known yet" when absent:
      //   pq_commit  — the 32-byte commitment from a scanned zc3. code
      //   enc_pq_pub — the ML-DSA key that arrived in-band and matched it
      // A contact with a commitment but no key is pendingPostQuantum; with
      // neither, classical. The pair is what decides which safety number is
      // shown, so neither may be inferred from the other.
      for (final column in const ['pq_commit TEXT', 'enc_pq_pub TEXT']) {
        await db.execute('ALTER TABLE contacts ADD COLUMN $column');
      }
    }
    if (from < 5) {
      // 13.3. Two more nullable columns on contacts:
      //   verified_sn  — the safety number the user actually compared, so a
      //                  number that has since MOVED can be told apart from
      //                  one that has not. `verified` alone cannot: it says
      //                  a number was checked, not which.
      //   pq_mismatch  — a post-quantum key arrived and did not match the
      //                  commitment. Refusal is durable state; without it
      //                  the warning is re-announced on every retry and the
      //                  contact screen has nothing to show at all.
      // An existing verified contact has no recorded number; ChatService
      // backfills the classical one on first load, since that is what every
      // earlier build showed. See `_backfillVerifiedSn`.
      for (final column in const ['verified_sn TEXT', 'pq_mismatch INTEGER']) {
        await db.execute('ALTER TABLE contacts ADD COLUMN $column');
      }
    }
  }

  static File _configFile(Directory root) =>
      File(p.join(root.path, 'key.json'));

  /// The vault directory for this install (also home to the app-lock
  /// settings, see `AppLock`). Tests pass `rootOverride` instead.
  static Future<Directory> defaultRoot() async =>
      Directory(p.join((await getApplicationSupportDirectory()).path, 'z'));

  /// Reports whether a vault exists here and whether it is passphrase-locked —
  /// without needing the passphrase or opening the database. The bootstrapper
  /// calls this to decide whether to show the unlock screen.
  static Future<VaultStatus> inspect({Directory? rootOverride}) async {
    final root = rootOverride ?? await defaultRoot();
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
  /// requiresPassphrase — or, for biometric unlock (7.8), the [passKey]
  /// previously obtained from [passKeyFor] (the Argon2id output for the
  /// current passphrase, so the slow KDF is skipped and the passphrase itself
  /// is never stored). A stale [passKey] — one derived before the passphrase
  /// was changed — fails with [WrongPassphraseException] exactly like a wrong
  /// passphrase. [rootOverride] lets tests use a temp directory.
  static Future<Vault> open(
      {String? passphrase, Uint8List? passKey, Directory? rootOverride}) async {
    final root = rootOverride ?? await defaultRoot();
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
      final havePassphrase = passphrase != null && passphrase.isNotEmpty;
      if (hasPass && !havePassphrase && passKey == null) {
        throw VaultLockedException();
      }
      final wrapKey = hasPass && !havePassphrase
          ? await _deriveWrapKey(deviceSecret, passKey: passKey, salt: salt)
          : await _deriveWrapKey(deviceSecret,
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
        version: schemaVersion,
        onUpgrade: _migrate,
        onCreate: (db, v) async {
          await db.execute('''
            CREATE TABLE contacts(
              rid TEXT PRIMARY KEY,
              enc_bundle TEXT NOT NULL,
              enc_name TEXT NOT NULL,
              ttl_seconds INTEGER NOT NULL DEFAULT 0,
              verified INTEGER NOT NULL DEFAULT 0,
              created_ms INTEGER NOT NULL,
              pq_commit TEXT,
              enc_pq_pub TEXT,
              verified_sn TEXT,
              pq_mismatch INTEGER
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
              $_v2MessageColumns,
              PRIMARY KEY (rid, mid)
            )''');
          await db.execute(
              'CREATE INDEX idx_messages_rid_ts ON messages(rid, ts_ms)');
          await db.execute(_createReactions);
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
      await passKeyFor(passphrase);
      return true;
    } catch (_) {
      return false;
    }
  }

  /// The 32-byte Argon2id output for [passphrase] under the current salt —
  /// the "pass key" that biometric unlock (7.8) keeps in the OS keystore so
  /// the vault can be opened with [open]`(passKey:)` after a successful
  /// biometric prompt. The result is verified against the wrapped master key
  /// first, so a wrong passphrase throws [WrongPassphraseException] rather
  /// than producing a key that could never unlock anything. Throws
  /// [StateError] when no passphrase is set (there is nothing to derive).
  Future<Uint8List> passKeyFor(String passphrase) async {
    final j = jsonDecode(await _configFile(root).readAsString())
        as Map<String, Object?>;
    if (j['hasPassphrase'] != true) {
      throw StateError('no passphrase is set');
    }
    final salt = zp.unb64(j['salt'] as String);
    final passKey = await _argon2(passphrase, salt);
    final wrapKey =
        await _deriveWrapKey(_deviceSecret, passKey: passKey, salt: salt);
    await _unwrap(j['wrapped'] as String, wrapKey); // WrongPassphraseException
    return passKey;
  }

  // ------------------------------------------------------------------
  // Key wrapping internals
  // ------------------------------------------------------------------

  static Future<Uint8List> _argon2(String passphrase, Uint8List salt) async {
    final k = await _kdf().deriveKey(
      secretKey: SecretKey(utf8.encode(passphrase)),
      nonce: salt,
    );
    return Uint8List.fromList(await k.extractBytes());
  }

  /// K_wrap = HKDF( deviceSecret [|| Argon2id(passphrase, salt)] ). Composing
  /// the device keystore secret with the passphrase means BOTH the device and
  /// the passphrase are needed to unlock — neither alone suffices. The
  /// Argon2id output may be supplied precomputed as [passKey] (biometric
  /// unlock); the derivation is otherwise identical.
  static Future<SecretKey> _deriveWrapKey(Uint8List deviceSecret,
      {String? passphrase, Uint8List? passKey, required Uint8List salt}) async {
    var material = deviceSecret;
    if (passphrase != null && passphrase.isNotEmpty) {
      passKey = await _argon2(passphrase, salt);
    }
    if (passKey != null) {
      if (passKey.length != 32) {
        throw ArgumentError('passKey must be 32 bytes');
      }
      material = Uint8List.fromList([...deviceSecret, ...passKey]);
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
