// Edge-to-edge (Android 15+, target SDK 35): the system bars are
// transparent overlays, so every screen has to keep its own content out of
// the bottom band. These tests give the screens a viewport with a fake
// 48-px navigation bar inset and a height too small for the content, then
// check that the last element can still be scrolled fully above that band.

import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/core/app_lock.dart';
import 'package:zapp/ui/lock_screen.dart';
import 'package:zapp/ui/unlock_screen.dart';

const _size = Size(360, 420);
const _inset = 48.0;

Widget _host(Widget child) => MediaQuery(
      data: const MediaQueryData(
        size: _size,
        padding: EdgeInsets.only(top: 24, bottom: _inset),
      ),
      child: MaterialApp(
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      supportedLocales: AppLocalizations.supportedLocales,home: child),
    );

// Both screens autofocus a text field whose cursor blinks forever, so the
// tests settle with a few timed pumps instead of pumpAndSettle.
Future<void> _settle(WidgetTester tester) async {
  for (var i = 0; i < 6; i++) {
    await tester.pump(const Duration(milliseconds: 100));
  }
}

Future<void> _scrollToEnd(WidgetTester tester) async {
  final scrollable = find.byType(Scrollable).first;
  await tester.drag(scrollable, const Offset(0, -2000));
  await _settle(tester);
}

void main() {
  setUp(() {
    // The tests run at exactly the logical size above.
    TestWidgetsFlutterBinding.ensureInitialized();
  });

  testWidgets('unlock screen: the footer clears the navigation bar',
      (tester) async {
    await tester.binding.setSurfaceSize(_size);
    await tester.pumpWidget(_host(UnlockScreen(onUnlock: (_) async {})));
    await _settle(tester);
    await _scrollToEnd(tester);
    final footer = find.textContaining('never sent anywhere');
    expect(footer, findsOneWidget);
    final bottom = tester.getBottomLeft(footer).dy;
    expect(bottom, lessThanOrEqualTo(_size.height - _inset),
        reason: 'the last line must sit above the system bar band');
  });

  testWidgets('lock screen: the passphrase fallback clears the navigation bar',
      (tester) async {
    await tester.binding.setSurfaceSize(_size);
    // Sync: testWidgets runs under FakeAsync, where real I/O never resolves.
    final dir = Directory.systemTemp.createTempSync('z_e2e');
    final lock = AppLock(root: dir, gate: _NoGate(), store: MemorySecretStore())
      ..lockNow();
    await tester.pumpWidget(_host(LockScreen(
      lock: lock,
      verifyPassphrase: (_) async => false,
    )));
    await _settle(tester);
    // Below the fold in this small viewport: bring it on screen first.
    await tester.ensureVisible(find.text('Use passphrase instead'));
    await _settle(tester);
    await tester.tap(find.text('Use passphrase instead'));
    await _settle(tester);
    await _scrollToEnd(tester);
    final button = find.text('Unlock with passphrase');
    expect(button, findsOneWidget);
    expect(tester.getBottomLeft(button).dy,
        lessThanOrEqualTo(_size.height - _inset));
    dir.deleteSync(recursive: true);
  });
}

class _NoGate implements BiometricGate {
  @override
  Future<bool> get isAvailable async => true;
  @override
  Future<GateResult> authenticate(String reason) async => GateResult.cancelled;
}
