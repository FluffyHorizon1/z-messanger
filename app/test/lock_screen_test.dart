// The lock screen (7.8) drives the AppLock: it prompts on appearance, shows
// the outcome, re-prompts on demand and — when the vault has a passphrase —
// accepts it as a fallback.

import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/app_lock.dart';
import 'package:zapp/ui/lock_screen.dart';

class _ScriptedGate implements BiometricGate {
  final answers = <GateResult>[];
  int calls = 0;
  @override
  Future<bool> get isAvailable async => true;
  @override
  Future<GateResult> authenticate(String reason) async {
    calls++;
    return answers.isEmpty ? GateResult.cancelled : answers.removeAt(0);
  }
}

void main() {
  late Directory dir;
  late _ScriptedGate gate;
  late AppLock lock;

  setUp(() async {
    dir = await Directory.systemTemp.createTemp('z_lockscreen');
    gate = _ScriptedGate();
    lock = AppLock(root: dir, gate: gate, store: MemorySecretStore());
    await lock.save(const LockSettings(screenLock: true));
    lock.lockNow();
  });

  tearDown(() {
    if (dir.existsSync()) dir.deleteSync(recursive: true);
  });

  testWidgets('prompts on show, reports a cancel, unlocks on retry',
      (tester) async {
    gate.answers.addAll([GateResult.cancelled, GateResult.ok]);
    await tester.pumpWidget(MaterialApp(home: LockScreen(lock: lock)));
    await tester.pumpAndSettle();
    expect(gate.calls, 1, reason: 'prompted as soon as it appeared');
    expect(find.text('Unlock cancelled.'), findsOneWidget);
    expect(lock.locked, isTrue);
    // No passphrase on this vault: no fallback offered.
    expect(find.text('Use passphrase instead'), findsNothing);

    await tester.tap(find.text('Unlock'));
    await tester.pumpAndSettle();
    expect(gate.calls, 2);
    expect(lock.locked, isFalse);
  });

  testWidgets('the passphrase fallback verifies against the vault',
      (tester) async {
    gate.answers.add(GateResult.failed);
    await tester.pumpWidget(MaterialApp(
      home: LockScreen(
        lock: lock,
        verifyPassphrase: (p) async => p == 'open sesame',
      ),
    ));
    await tester.pumpAndSettle();
    expect(find.textContaining('Could not verify'), findsOneWidget);

    await tester.tap(find.text('Use passphrase instead'));
    await tester.pumpAndSettle();
    // From here the focused field's cursor keeps animating, so settle by
    // pumping a few frames instead of pumpAndSettle.
    Future<void> pumpSome() async {
      for (var i = 0; i < 5; i++) {
        await tester.pump(const Duration(milliseconds: 100));
      }
    }

    await tester.enterText(find.byType(TextField), 'wrong');
    await tester.tap(find.text('Unlock with passphrase'));
    await pumpSome();
    expect(find.text('Incorrect passphrase. Try again.'), findsOneWidget);
    expect(lock.locked, isTrue);

    await tester.enterText(find.byType(TextField), 'open sesame');
    await tester.testTextInput.receiveAction(TextInputAction.done);
    await pumpSome();
    expect(lock.locked, isFalse);
    expect(gate.calls, 1, reason: 'the passphrase path never prompts');
  });
}
