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
        {double textScale = 1.0, Locale? locale, TextDirection? forceDir}) =>
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
        // A Directionality wrapped ABOVE this MaterialApp does nothing: the
        // WidgetsApp inside inserts its own from the resolved locale, and the
        // home subtree renders under that. To force a direction on the screen
        // it has to go through `builder`, which wraps the home BELOW that
        // boundary. Without this, the RTL test below rendered LTR and asserted
        // nothing (the 2026-09-14 review's finding 36).
        builder: forceDir == null
            ? null
            : (context, child) =>
                Directionality(textDirection: forceDir, child: child!),
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

/// The horizontal centre of every laid-out text and icon, grouped by a key
/// that is stable across a re-pump (the text, or the icon's code point) so the
/// same element can be compared in LTR and RTL. Lists are sorted, so duplicate
/// keys still compare as a set. Used by the RTL test to check the layout is a
/// true mirror rather than merely exception-free.
Map<String, List<double>> _elementCentresX(WidgetTester tester) {
  final out = <String, List<double>>{};
  void grab(Iterable<Element> els, String Function(Widget) key) {
    for (final e in els) {
      final ro = e.renderObject;
      if (ro is RenderBox && ro.attached && ro.hasSize && ro.size.width > 0) {
        (out[key(e.widget)] ??= [])
            .add(ro.localToGlobal(ro.size.center(Offset.zero)).dx);
      }
    }
  }

  grab(find.byType(Text).evaluate(), (w) => 'text:${(w as Text).data ?? ''}');
  grab(find.byType(Icon).evaluate(),
      (w) => 'icon:${(w as Icon).icon?.codePoint}');
  for (final v in out.values) {
    v.sort();
  }
  return out;
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
    // without needing the strings translated first — but only if the force
    // actually reaches the screen, which through `_host`'s builder it now does
    // (finding 36: the old wrap sat above the MaterialApp and the screen
    // rendered LTR, so nothing here was about RTL at all).
    testWidgets('${entry.key} (${t.key}): lays out right-to-left',
        (tester) async {
      await tester.binding.setSurfaceSize(const Size(400, 800));

      // First the honest layout, to mirror against.
      await tester.pumpWidget(
          _host(entry.value(), t.value(), forceDir: TextDirection.ltr));
      await _settle(tester);
      final ltr = _elementCentresX(tester);

      await tester.pumpWidget(
          _host(entry.value(), t.value(), forceDir: TextDirection.rtl));
      await _settle(tester);
      expect(tester.takeException(), isNull,
          reason: 'this screen threw when laid out right-to-left');

      // The force reached the screen: an element below the MaterialApp is
      // genuinely in RTL. A mutation that moves the Directionality back above
      // `_host` fails here.
      expect(Directionality.of(tester.element(find.byType(Scaffold).first)),
          TextDirection.rtl,
          reason: 'the screen is not actually laid out right-to-left');

      // And it is the LTR layout mirrored: every text and icon sits where its
      // reflection across the 400px width should be. An `EdgeInsets.only(left:)`
      // that should have been `EdgeInsetsDirectional.only(start:)` leaves its
      // child on the same side in both directions, so it lands where the
      // mirror is not — which is what this catches, without translated
      // strings (the glyphs, and so the widths, are identical both ways).
      final rtl = _elementCentresX(tester);
      expect(rtl.keys.toSet(), ltr.keys.toSet(),
          reason: 'the same elements are present both ways');
      for (final k in ltr.keys) {
        final expected = [for (final x in ltr[k]!) 400.0 - x]..sort();
        final actual = rtl[k]!;
        expect(actual, hasLength(expected.length), reason: k);
        for (var i = 0; i < actual.length; i++) {
          expect((actual[i] - expected[i]).abs(), lessThan(1.5),
              reason:
                  '$k is not mirrored under RTL — a non-directional inset?');
        }
      }
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
