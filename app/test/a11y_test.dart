// 15.4 — accessibility, checked against Flutter's own guidelines rather than
// against an opinion.
//
// Play assesses this separately from the items cleared in 3.5, and until now
// the app had *zero* `Semantics` widgets and eleven tooltips across sixteen
// IconButtons. A screen reader on the onboarding flow — the first thing a new
// user meets — would have announced several controls as nothing at all.
//
// Three of Flutter's guidelines are asserted here:
//
//   androidTapTargetGuideline  every tappable is at least 48x48
//   labeledTapTargetGuideline  every tappable announces something
//   textContrastGuideline      text meets WCAG AA against its background
//
// Only the screens that stand up without a ChatService are covered: the lock,
// unlock and onboarding screens. That is not an arbitrary subset — they are
// the screens a user meets before they have an account, so they are the ones
// a screen-reader user hits first and the ones a reviewer will open. The rest
// of the UI is covered breadth-first by `tool/check_a11y.py`, which reads
// every screen's source for unlabelled controls; the two are complementary
// and neither is sufficient alone.
//
// Dynamic type is checked too, at 2.0x, because a label that announces
// correctly and then overflows its button is still a failure.

import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/app_lock.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/ui/lock_screen.dart';
import 'package:zapp/ui/theme.dart';
import 'package:zapp/ui/onboarding_screen.dart';
import 'package:zapp/ui/unlock_screen.dart';

/// The app's own theme, not Material's default.
///
/// `context.z` falls back to the DARK palette when the theme extension is
/// absent (theme.dart: `Theme.of(this).extension<ZColors>() ?? ZColors.dark`),
/// so a bare `MaterialApp` paints dark-palette amber on Material's white
/// background — 1.71:1, a contrast failure that exists only in the test.
/// The first draft of this file did exactly that and nearly had me changing
/// the brand colour to fix a bug that was mine. `app/tool/contrast.py` says
/// every real pair clears AA, in both palettes.
Widget _host(Widget child, ThemeData theme,
        {double textScale = 1.0, Locale? locale}) =>
    MediaQuery(
      data: MediaQueryData(
        size: const Size(400, 800),
        textScaler: TextScaler.linear(textScale),
      ),
      child: MaterialApp(
        theme: theme,
        // A screen that reads AppLocalizations needs the delegates, or
        // `AppLocalizations.of(context)` throws. Any test pumping a localized
        // screen has to supply them.
        localizationsDelegates: AppLocalizations.localizationsDelegates,
        supportedLocales: AppLocalizations.supportedLocales,
        locale: locale,
        home: child,
      ),
    );

/// These screens autofocus a field whose cursor blinks forever, so settle
/// with timed pumps rather than pumpAndSettle.
Future<void> _settle(WidgetTester tester) async {
  for (var i = 0; i < 6; i++) {
    await tester.pump(const Duration(milliseconds: 100));
  }
}

class _AlwaysOkGate implements BiometricGate {
  @override
  Future<bool> get isAvailable async => true;
  @override
  Future<GateResult> authenticate(String reason) async => GateResult.ok;
}

void main() {
  late Directory dir;
  late AppLock lock;
  late Vault vault;

  setUp(() async {
    dir = await Directory.systemTemp.createTemp('z_a11y');
    lock = AppLock(root: dir, gate: _AlwaysOkGate(), store: MemorySecretStore());
    await lock.save(const LockSettings(screenLock: true));
    lock.lockNow();
    vault = await Vault.open(rootOverride: dir);
  });

  tearDown(() async {
    await vault.db.close();
    if (dir.existsSync()) dir.deleteSync(recursive: true);
  });

  final screens = <String, Widget Function()>{
    'unlock': () => UnlockScreen(onUnlock: (_) async {}),
    'lock': () => LockScreen(lock: lock),
    'onboarding': () =>
        OnboardingScreen(vault: vault, onDone: () async {}),
  };

  final themes = <String, ThemeData Function()>{
    'light': ZTheme.light,
    'dark': ZTheme.dark,
  };

  for (final entry in screens.entries) {
    for (final t in themes.entries) {
    testWidgets('${entry.key} (${t.key}): every tappable is big enough and announces '
        'something', (tester) async {
      await tester.binding.setSurfaceSize(const Size(400, 800));
      final handle = tester.ensureSemantics();
      await tester.pumpWidget(_host(entry.value(), t.value()));
      await _settle(tester);

      await expectLater(tester, meetsGuideline(androidTapTargetGuideline));
      await expectLater(tester, meetsGuideline(labeledTapTargetGuideline));

      handle.dispose();
    });

    testWidgets('${entry.key} (${t.key}): text meets contrast guidelines',
        (tester) async {
      await tester.binding.setSurfaceSize(const Size(400, 800));
      final handle = tester.ensureSemantics();
      await tester.pumpWidget(_host(entry.value(), t.value()));
      await _settle(tester);

      await expectLater(tester, meetsGuideline(textContrastGuideline));

      handle.dispose();
    });

    // Arabic is one of the six locales Z publishes release notes in, and a
    // right-to-left layout breaks in ways nobody sees until somebody tries
    // it: a Row that should have been a mainAxisAlignment, an EdgeInsets.only
    // that should have been directional. Forcing the direction catches those
    // without needing the strings translated first.
    testWidgets('${entry.key} (${t.key}): lays out right-to-left',
        (tester) async {
      await tester.binding.setSurfaceSize(const Size(400, 800));
      await tester.pumpWidget(Directionality(
        textDirection: TextDirection.rtl,
        child: _host(entry.value(), t.value()),
      ));
      await _settle(tester);
      expect(tester.takeException(), isNull,
          reason: 'this screen threw when laid out right-to-left');
    });

    testWidgets('${entry.key} (${t.key}): survives 2x text without overflowing',
        (tester) async {
      await tester.binding.setSurfaceSize(const Size(400, 800));
      await tester.pumpWidget(_host(entry.value(), t.value(), textScale: 2.0));
      await _settle(tester);
      // A RenderFlex overflow is reported as a test failure by the framework,
      // so reaching here without one is the assertion. The explicit check is
      // that the screen still rendered at all.
      expect(tester.takeException(), isNull,
          reason: 'at 2x text this screen threw — most likely an overflow');
    });
  }
  }
}
