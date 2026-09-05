// App lock (7.8). The OS prompt is replaced by a scripted gate so the lock
// logic — background timing, prompt outcomes, the auto-disable rule, and the
// biometric-unlock key lifecycle against a real vault — runs headless.

import 'dart:async';
import 'dart:io';

import 'package:flutter/widgets.dart' show AppLifecycleState;
import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/app_lock.dart';
import 'package:zapp/core/vault.dart';

/// A gate whose answers are queued by the test. [pending] lets a test hold a
/// prompt open to check what happens while one is in flight.
class FakeGate implements BiometricGate {
  bool available = true;
  final answers = <GateResult>[];
  final reasons = <String>[];
  Completer<GateResult>? pending;
  int calls = 0;

  @override
  Future<bool> get isAvailable async => available;

  @override
  Future<GateResult> authenticate(String reason) async {
    calls++;
    reasons.add(reason);
    if (pending != null) return pending!.future;
    if (answers.isEmpty) throw StateError('no scripted answer');
    return answers.removeAt(0);
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late Directory dir;
  late FakeGate gate;
  late MemorySecretStore store;
  int now = 1000000;

  AppLock makeLock() =>
      AppLock(root: dir, gate: gate, store: store, clock: () => now);

  setUp(() async {
    dir = await Directory.systemTemp.createTemp('z_applock');
    gate = FakeGate();
    store = MemorySecretStore();
    now = 1000000;
  });

  tearDown(() async {
    if (dir.existsSync()) dir.deleteSync(recursive: true);
  });

  test('lockDue: boundary is inclusive, 0 means immediately', () {
    expect(
        lockDue(backgroundedAtMs: 0, nowMs: 59999, lockAfterSec: 60), isFalse);
    expect(
        lockDue(backgroundedAtMs: 0, nowMs: 60000, lockAfterSec: 60), isTrue);
    expect(lockDue(backgroundedAtMs: 5, nowMs: 5, lockAfterSec: 0), isTrue);
  });

  test('settings persist in lock.json; a missing file means defaults',
      () async {
    final a = makeLock();
    await a.load();
    expect(a.settings.screenLock, isFalse);
    expect(a.settings.biometricUnlock, isFalse);
    expect(a.settings.lockAfterSec, 300);

    await a.save(const LockSettings(
        screenLock: true, lockAfterSec: 60, biometricUnlock: true));
    final b = makeLock();
    await b.load();
    expect(b.settings.screenLock, isTrue);
    expect(b.settings.lockAfterSec, 60);
    expect(b.settings.biometricUnlock, isTrue);

    // Garbage on disk falls back to defaults rather than crashing.
    await File('${dir.path}/lock.json').writeAsString('{nope');
    final c = makeLock();
    await c.load();
    expect(c.settings.screenLock, isFalse);
  });

  test('enabling the screen lock needs one successful prompt', () async {
    final lock = makeLock();
    await lock.load();
    gate.answers.add(GateResult.cancelled);
    expect(await lock.enableScreenLock(), GateResult.cancelled);
    expect(lock.settings.screenLock, isFalse);

    gate.available = false;
    expect(await lock.enableScreenLock(), GateResult.unavailable);
    expect(gate.calls, 1, reason: 'no prompt without a credential');

    gate.available = true;
    gate.answers.add(GateResult.ok);
    expect(await lock.enableScreenLock(), GateResult.ok);
    expect(lock.settings.screenLock, isTrue);
    expect(gate.reasons.last, contains('enable screen lock'));
  });

  test('locks on resume only after lockAfterSec in the background', () async {
    final lock = makeLock();
    await lock.save(const LockSettings(screenLock: true, lockAfterSec: 60));
    expect(lock.locked, isFalse);

    // Inactive (a system dialog, the notification shade) never starts the
    // clock — otherwise the lock would trip on its own prompt.
    lock.onLifecycle(AppLifecycleState.inactive);
    now += 3600 * 1000;
    lock.onLifecycle(AppLifecycleState.resumed);
    expect(lock.locked, isFalse);

    // A short trip to the background: still open.
    lock.onLifecycle(AppLifecycleState.hidden);
    lock.onLifecycle(AppLifecycleState.paused);
    now += 30 * 1000;
    lock.onLifecycle(AppLifecycleState.resumed);
    expect(lock.locked, isFalse);

    // A long one: locked, and the clock is measured from the FIRST
    // background transition (hidden), not the later paused.
    lock.onLifecycle(AppLifecycleState.hidden);
    now += 45 * 1000;
    lock.onLifecycle(AppLifecycleState.paused);
    now += 15 * 1000;
    lock.onLifecycle(AppLifecycleState.resumed);
    expect(lock.locked, isTrue);

    // Prompt outcomes: cancelled keeps it locked, ok opens it.
    gate.answers.add(GateResult.cancelled);
    expect(await lock.requestUnlock(), GateResult.cancelled);
    expect(lock.locked, isTrue);
    expect(lock.lastResult, GateResult.cancelled);
    gate.answers.add(GateResult.ok);
    expect(await lock.requestUnlock(), GateResult.ok);
    expect(lock.locked, isFalse);

    // Unlocked: a request is a no-op that does not touch the gate.
    final calls = gate.calls;
    expect(await lock.requestUnlock(), GateResult.ok);
    expect(gate.calls, calls);

    // With the feature off, even a day away does not lock.
    await lock.disableScreenLock();
    lock.onLifecycle(AppLifecycleState.paused);
    now += 86400 * 1000;
    lock.onLifecycle(AppLifecycleState.resumed);
    expect(lock.locked, isFalse);
  });

  test('lifecycle noise during an in-flight prompt is ignored', () async {
    final lock = makeLock();
    await lock.save(const LockSettings(screenLock: true, lockAfterSec: 0));
    lock.lockNow();
    gate.pending = Completer<GateResult>();
    final first = lock.requestUnlock();
    expect(lock.authInFlight, isTrue);
    // A second request while one is showing does not open another prompt.
    expect(await lock.requestUnlock(), GateResult.cancelled);
    expect(gate.calls, 1);
    // The prompt itself takes the app inactive/paused and back; none of
    // that starts the background clock.
    lock.onLifecycle(AppLifecycleState.paused);
    now += 10 * 1000;
    lock.onLifecycle(AppLifecycleState.resumed);
    gate.pending!.complete(GateResult.ok);
    expect(await first, GateResult.ok);
    expect(lock.locked, isFalse);
    expect(lock.authInFlight, isFalse);
    // And immediately afterwards a resume does not re-lock either.
    lock.onLifecycle(AppLifecycleState.resumed);
    expect(lock.locked, isFalse);
  });

  test('a lock nobody can pass opens and switches itself off', () async {
    final lock = makeLock();
    await lock.save(const LockSettings(screenLock: true));
    lock.lockNow();
    gate.answers.add(GateResult.unavailable);
    expect(await lock.requestUnlock(), GateResult.unavailable);
    expect(lock.locked, isFalse);
    expect(lock.settings.screenLock, isFalse);
    final again = makeLock();
    await again.load();
    expect(again.settings.screenLock, isFalse, reason: 'persisted');

    // … unless the lock screen can take the vault passphrase: then it stays
    // locked (and on) and the passphrase is the way in.
    await lock.save(const LockSettings(screenLock: true));
    lock.lockNow();
    gate.answers.add(GateResult.unavailable);
    await lock.requestUnlock(passphraseFallback: true);
    expect(lock.locked, isTrue);
    expect(lock.settings.screenLock, isTrue);
    lock.markAuthenticated(); // the typed passphrase
    expect(lock.locked, isFalse);
  });

  test('biometric unlock: pass key lifecycle against a real vault', () async {
    const pass = 'correct horse battery staple';
    final vault = await Vault.open(rootOverride: dir);
    await vault.kvPut('identity', '{"x":1}');
    final lock = makeLock();
    await lock.load();

    // Needs a passphrase first.
    await expectLater(
        lock.enrolBiometricUnlock(vault, pass), throwsA(isA<StateError>()));
    await vault.setPassphrase(pass);

    // Wrong passphrase: rejected before any prompt, nothing stored.
    await expectLater(lock.enrolBiometricUnlock(vault, 'wrong'),
        throwsA(isA<WrongPassphraseException>()));
    expect(gate.calls, 0);
    expect(store.map, isEmpty);

    // Prompt dismissed: nothing stored, feature stays off.
    gate.answers.add(GateResult.cancelled);
    expect(await lock.enrolBiometricUnlock(vault, pass), isFalse);
    expect(store.map, isEmpty);
    expect(lock.settings.biometricUnlock, isFalse);

    // Enrolled.
    gate.answers.add(GateResult.ok);
    expect(await lock.enrolBiometricUnlock(vault, pass), isTrue);
    expect(store.map.keys, [AppLock.passKeyStorageKey]);
    expect(lock.settings.biometricUnlock, isTrue);
    await vault.db.close();

    // Launch path: a fresh AppLock (as after a restart) hands back the key
    // only after a successful prompt, and it opens the vault.
    final launch = makeLock();
    await launch.load();
    launch.lockNow();
    gate.answers.add(GateResult.cancelled);
    expect(await launch.passKeyAfterPrompt(), isNull);
    expect(launch.locked, isTrue);
    gate.answers.add(GateResult.ok);
    final pk = await launch.passKeyAfterPrompt();
    expect(pk, isNotNull);
    expect(pk!.length, 32);
    expect(launch.locked, isFalse, reason: 'the prompt satisfied the lock');
    var v = await Vault.open(rootOverride: dir, passKey: pk);
    expect(await v.kvGet('identity'), '{"x":1}');

    // Passphrase change re-keys the entry; the old key no longer opens.
    const pass2 = 'a different much longer passphrase';
    await v.setPassphrase(pass2);
    await launch.onPassphraseChanged(v, pass2);
    await v.db.close();
    await expectLater(Vault.open(rootOverride: dir, passKey: pk),
        throwsA(isA<WrongPassphraseException>()));
    gate.answers.add(GateResult.ok);
    final pk2 = await launch.passKeyAfterPrompt();
    expect(pk2, isNot(pk));
    v = await Vault.open(rootOverride: dir, passKey: pk2);
    expect(await v.kvGet('identity'), '{"x":1}');

    // Removing the passphrase deletes the entry and switches the feature off.
    await v.removePassphrase();
    await launch.onPassphraseRemoved();
    expect(store.map, isEmpty);
    expect(launch.settings.biometricUnlock, isFalse);
    expect(await launch.passKeyAfterPrompt(), isNull);
    await v.db.close();

    // Off means off: no prompt is even shown.
    final calls = gate.calls;
    expect(await launch.passKeyAfterPrompt(), isNull);
    expect(gate.calls, calls);
  });
}
