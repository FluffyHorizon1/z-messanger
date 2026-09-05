// App lock (7.8): biometric / device-credential gate for opening Z.
//
// Two independent features share this class:
//
//  * Screen lock — the OS prompt (fingerprint, face, or the device PIN /
//    pattern / passcode as fallback) is required to open Z, and again when
//    it returns from the background after `lockAfterSec`. It is a UI gate:
//    the vault stays open underneath so messages keep arriving, exactly as
//    a phone's own lock screen works.
//
//  * Biometric unlock — when an app passphrase is set, the vault can be
//    opened with the OS prompt instead of typing the passphrase. What is
//    kept in the OS keystore is the Argon2id output for the current
//    passphrase (the "pass key", see `Vault.passKeyFor`), never the
//    passphrase itself. Honest trade-off, also spelled out in the settings
//    copy: while this is enabled, someone who can extract the app's keystore
//    entries from THIS device (root / a forensic image) no longer needs the
//    passphrase, because the device secret and the pass key together unwrap
//    the vault key. Turning the feature off deletes the entry again.
//
// The OS prompt itself comes from `local_auth`; it is wrapped in
// [BiometricGate] so the lock logic is testable with a fake gate. There is no
// Linux implementation, so the feature is hidden there.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/widgets.dart' show AppLifecycleState, ChangeNotifier;
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';
import 'package:path/path.dart' as p;
import 'package:z_protocol/z_protocol.dart' as zp;

import 'vault.dart';

/// Outcome of one OS authentication prompt.
enum GateResult {
  /// The user authenticated.
  ok,

  /// The user dismissed the prompt (or the system cancelled it).
  cancelled,

  /// Nothing to authenticate with: no hardware, nothing enrolled, no device
  /// credential, or an unsupported platform.
  unavailable,

  /// The attempt failed (lockout after too many tries, a device error).
  failed,
}

/// The OS biometric / device-credential prompt.
abstract class BiometricGate {
  /// Whether this device can authenticate at all (biometrics or a device
  /// credential such as a PIN).
  Future<bool> get isAvailable;

  /// Shows the prompt with [reason] and reports the outcome.
  Future<GateResult> authenticate(String reason);
}

/// [BiometricGate] over `local_auth` (Android, iOS, macOS, Windows Hello).
class LocalAuthGate implements BiometricGate {
  final _auth = LocalAuthentication();

  static bool get platformSupported =>
      !kIsWeb &&
      (Platform.isAndroid ||
          Platform.isIOS ||
          Platform.isMacOS ||
          Platform.isWindows);

  @override
  Future<bool> get isAvailable async {
    if (!platformSupported) return false;
    try {
      return await _auth.isDeviceSupported();
    } catch (_) {
      return false;
    }
  }

  @override
  Future<GateResult> authenticate(String reason) async {
    if (!platformSupported) return GateResult.unavailable;
    try {
      final ok = await _auth.authenticate(
        localizedReason: reason,
        // Not a payment: skip the extra "confirm" tap after face unlock.
        sensitiveTransaction: false,
        // A phone call mid-prompt should retry when we come back, not fail.
        persistAcrossBackgrounding: true,
      );
      return ok ? GateResult.ok : GateResult.failed;
    } on LocalAuthException catch (e) {
      switch (e.code) {
        case LocalAuthExceptionCode.userCanceled:
        case LocalAuthExceptionCode.systemCanceled:
        case LocalAuthExceptionCode.timeout:
          return GateResult.cancelled;
        case LocalAuthExceptionCode.noCredentialsSet:
        case LocalAuthExceptionCode.noBiometricsEnrolled:
        case LocalAuthExceptionCode.noBiometricHardware:
          return GateResult.unavailable;
        default:
          return GateResult.failed;
      }
    } catch (_) {
      return GateResult.failed;
    }
  }
}

/// Where the pass key lives: the OS keystore in production, a map in tests.
abstract class SecretStore {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
  Future<void> delete(String key);
}

class KeystoreSecretStore implements SecretStore {
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );
  @override
  Future<String?> read(String key) => _storage.read(key: key);
  @override
  Future<void> write(String key, String value) =>
      _storage.write(key: key, value: value);
  @override
  Future<void> delete(String key) => _storage.delete(key: key);
}

class MemorySecretStore implements SecretStore {
  final map = <String, String>{};
  @override
  Future<String?> read(String key) async => map[key];
  @override
  Future<void> write(String key, String value) async => map[key] = value;
  @override
  Future<void> delete(String key) async => map.remove(key);
}

/// Persisted app-lock settings (`lock.json` next to the vault, readable
/// before the vault is open — the lock screen has to be decided first).
class LockSettings {
  /// Require the OS prompt to open Z, and after [lockAfterSec] in background.
  final bool screenLock;

  /// Seconds in the background before the app locks again (0 = immediately).
  final int lockAfterSec;

  /// A passphrase-protected vault may be opened with the OS prompt.
  final bool biometricUnlock;

  const LockSettings({
    this.screenLock = false,
    this.lockAfterSec = 300,
    this.biometricUnlock = false,
  });

  static const lockAfterChoices = [0, 60, 300, 900, 3600];

  LockSettings copyWith(
          {bool? screenLock, int? lockAfterSec, bool? biometricUnlock}) =>
      LockSettings(
        screenLock: screenLock ?? this.screenLock,
        lockAfterSec: lockAfterSec ?? this.lockAfterSec,
        biometricUnlock: biometricUnlock ?? this.biometricUnlock,
      );

  Map<String, Object?> toJson() => {
        'v': 1,
        'screenLock': screenLock,
        'lockAfterSec': lockAfterSec,
        'biometricUnlock': biometricUnlock,
      };

  factory LockSettings.fromJson(Map<String, Object?> j) => LockSettings(
        screenLock: j['screenLock'] == true,
        lockAfterSec: (j['lockAfterSec'] as num?)?.toInt() ?? 300,
        biometricUnlock: j['biometricUnlock'] == true,
      );
}

/// Whether returning to the foreground at [nowMs], having gone to the
/// background at [backgroundedAtMs], must lock the app.
bool lockDue(
        {required int backgroundedAtMs,
        required int nowMs,
        required int lockAfterSec}) =>
    nowMs - backgroundedAtMs >= lockAfterSec * 1000;

class AppLock extends ChangeNotifier {
  static const passKeyStorageKey = 'z_bio_passkey';

  final Directory root;
  final BiometricGate gate;
  final SecretStore store;
  final int Function() _now;

  LockSettings _settings = const LockSettings();
  LockSettings get settings => _settings;

  bool _locked = false;
  bool _authInFlight = false;
  int? _backgroundedAtMs;
  GateResult? _lastResult;

  AppLock({
    required this.root,
    BiometricGate? gate,
    SecretStore? store,
    int Function()? clock,
  })  : gate = gate ?? LocalAuthGate(),
        store = store ?? KeystoreSecretStore(),
        _now = clock ?? (() => DateTime.now().millisecondsSinceEpoch);

  File get _file => File(p.join(root.path, 'lock.json'));

  /// Whether the OS prompt can be used here at all. Decides whether the
  /// settings section is shown.
  Future<bool> get available => gate.isAvailable;

  // ------------------------------------------------------------------
  // Settings
  // ------------------------------------------------------------------

  Future<void> load() async {
    try {
      if (await _file.exists()) {
        _settings = LockSettings.fromJson(
            (jsonDecode(await _file.readAsString()) as Map)
                .cast<String, Object?>());
      }
    } catch (_) {
      _settings = const LockSettings();
    }
    notifyListeners();
  }

  Future<void> save(LockSettings s) async {
    _settings = s;
    await root.create(recursive: true);
    await _file.writeAsString(jsonEncode(s.toJson()), flush: true);
    notifyListeners();
  }

  /// Turns the screen lock on after one successful prompt (so a user never
  /// enables a gate they cannot pass). Returns the prompt's outcome; the
  /// setting is saved only for [GateResult.ok].
  Future<GateResult> enableScreenLock() async {
    if (!await gate.isAvailable) return GateResult.unavailable;
    final r = await gate.authenticate('Confirm to enable screen lock');
    if (r == GateResult.ok) await save(_settings.copyWith(screenLock: true));
    return r;
  }

  Future<void> disableScreenLock() async {
    _locked = false;
    _backgroundedAtMs = null;
    await save(_settings.copyWith(screenLock: false));
  }

  Future<void> setLockAfter(int sec) =>
      save(_settings.copyWith(lockAfterSec: sec));

  // ------------------------------------------------------------------
  // Screen lock (UI gate)
  // ------------------------------------------------------------------

  bool get locked => _locked;
  bool get authInFlight => _authInFlight;

  /// Outcome of the most recent prompt, for the lock screen's status line.
  GateResult? get lastResult => _lastResult;

  /// Locks the UI now (launch with screen lock on, or a due resume).
  void lockNow() {
    if (_locked) return;
    _locked = true;
    _lastResult = null;
    notifyListeners();
  }

  /// The user proved themselves some other way (typed the passphrase, or the
  /// vault was just opened through the biometric prompt).
  void markAuthenticated() {
    _backgroundedAtMs = null;
    if (!_locked) return;
    _locked = false;
    notifyListeners();
  }

  /// Feed every lifecycle transition here. Backgrounding starts the clock;
  /// resuming after [LockSettings.lockAfterSec] locks. Transitions caused by
  /// our own prompt (it takes the app inactive) are ignored.
  void onLifecycle(AppLifecycleState state) {
    if (_authInFlight) return;
    switch (state) {
      case AppLifecycleState.hidden:
      case AppLifecycleState.paused:
        _backgroundedAtMs ??= _now();
      case AppLifecycleState.resumed:
        final at = _backgroundedAtMs;
        _backgroundedAtMs = null;
        if (_settings.screenLock &&
            at != null &&
            lockDue(
                backgroundedAtMs: at,
                nowMs: _now(),
                lockAfterSec: _settings.lockAfterSec)) {
          lockNow();
        }
      case AppLifecycleState.inactive:
      case AppLifecycleState.detached:
        break;
    }
  }

  /// Shows the OS prompt and unlocks on success. Idempotent while a prompt
  /// is already showing. Returns the outcome (also kept in [lastResult]).
  /// [passphraseFallback] says whether the lock screen can also take the
  /// vault passphrase; without one, a device that has lost its credential
  /// (the OS lock was removed after enabling this) would be a gate nobody
  /// can pass — so the app opens and the feature switches itself off, to be
  /// re-enabled once a device lock exists again.
  Future<GateResult> requestUnlock(
      {String reason = 'Unlock Z', bool passphraseFallback = false}) async {
    if (!_locked) return GateResult.ok;
    if (_authInFlight) return GateResult.cancelled;
    _authInFlight = true;
    notifyListeners();
    GateResult r;
    try {
      r = await gate.authenticate(reason);
    } finally {
      _authInFlight = false;
    }
    _lastResult = r;
    if (r == GateResult.ok) {
      _backgroundedAtMs = null;
      _locked = false;
    } else if (r == GateResult.unavailable && !passphraseFallback) {
      _locked = false;
      await save(_settings.copyWith(screenLock: false));
    }
    notifyListeners();
    return r;
  }

  // ------------------------------------------------------------------
  // Biometric unlock of a passphrase vault
  // ------------------------------------------------------------------

  /// Runs the OS prompt and, on success, stores the pass key for
  /// [passphrase] so the vault can later be opened without it. Throws
  /// [WrongPassphraseException] for a wrong passphrase, [StateError] when
  /// the vault has no passphrase. Returns false when the prompt did not
  /// succeed (nothing is stored then).
  Future<bool> enrolBiometricUnlock(Vault vault, String passphrase) async {
    final passKey = await vault.passKeyFor(passphrase); // verifies first
    final r = await gate.authenticate('Confirm to enable biometric unlock');
    if (r != GateResult.ok) return false;
    await store.write(passKeyStorageKey, zp.b64(passKey));
    await save(_settings.copyWith(biometricUnlock: true));
    return true;
  }

  /// Deletes the stored pass key and switches the feature off.
  Future<void> disableBiometricUnlock() async {
    try {
      await store.delete(passKeyStorageKey);
    } catch (_) {}
    if (_settings.biometricUnlock) {
      await save(_settings.copyWith(biometricUnlock: false));
    }
  }

  /// The passphrase changed: the stored pass key is stale (new salt), so
  /// re-derive it from the new passphrase while the feature stays on.
  Future<void> onPassphraseChanged(Vault vault, String newPassphrase) async {
    if (!_settings.biometricUnlock) return;
    try {
      final passKey = await vault.passKeyFor(newPassphrase);
      await store.write(passKeyStorageKey, zp.b64(passKey));
    } catch (_) {
      await disableBiometricUnlock();
    }
  }

  /// The passphrase was removed: nothing left to unlock biometrically.
  Future<void> onPassphraseRemoved() => disableBiometricUnlock();

  /// Launch path: prompt, then hand back the stored pass key. Null when the
  /// feature is off, the prompt did not succeed, or nothing is stored (the
  /// caller falls back to the passphrase screen). A successful prompt also
  /// satisfies the screen lock, so the app does not ask twice at launch.
  Future<Uint8List?> passKeyAfterPrompt() async {
    if (!_settings.biometricUnlock) return null;
    if (_authInFlight) return null;
    _authInFlight = true;
    notifyListeners();
    GateResult r;
    try {
      r = await gate.authenticate('Unlock Z');
    } finally {
      _authInFlight = false;
    }
    _lastResult = r;
    notifyListeners();
    if (r != GateResult.ok) return null;
    final stored = await store.read(passKeyStorageKey);
    if (stored == null) return null;
    markAuthenticated();
    return zp.unb64(stored);
  }
}
