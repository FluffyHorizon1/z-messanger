// The launch-time unlock errors, chosen in the reader's language.
//
// They were built as English sentences in `main.dart` — above the MaterialApp,
// where AppLocalizations is not in scope — and `check_l10n.py` scanned only
// `lib/ui`, never `main.dart`, so a Spanish user met the passphrase and
// biometric errors in English and nothing caught it (the 2026-09-14 review's
// finding 39). The bootstrapper now hands `UnlockScreen` a typed [UnlockError]
// and the words are chosen here.
//
// Criteria, each a test below:
//   1. each error kind renders its own string, and follows the locale;
//   2. the unexpected case shows its raw diagnostic, which has no translation.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/l10n/app_localizations_en.dart';
import 'package:zapp/l10n/app_localizations_es.dart';
import 'package:zapp/ui/unlock_screen.dart';

void main() {
  final en = AppLocalizationsEn();
  final es = AppLocalizationsEs();

  Future<void> pump(WidgetTester tester, UnlockError error, Locale locale) async {
    await tester.pumpWidget(MaterialApp(
      locale: locale,
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      supportedLocales: AppLocalizations.supportedLocales,
      home: UnlockScreen(onUnlock: (_) async {}, error: error),
    ));
    await tester.pump(const Duration(milliseconds: 100));
  }

  testWidgets('1. each error kind renders its own localized string',
      (tester) async {
    await pump(tester, const WrongPassphrase(), const Locale('en'));
    expect(find.text(en.lockIncorrectPassphrase), findsOneWidget);

    await pump(tester, const BiometricStale(), const Locale('en'));
    expect(find.text(en.unlockBiometricStale), findsOneWidget);

    await pump(tester, const BiometricInvalidated(), const Locale('en'));
    expect(find.text(en.unlockBiometricInvalidated), findsOneWidget);

    // Spanish: the same kinds, different words — the point of the fix.
    await pump(tester, const BiometricStale(), const Locale('es'));
    expect(find.text(es.unlockBiometricStale), findsOneWidget);
    expect(es.unlockBiometricStale, isNot(equals(en.unlockBiometricStale)));

    await pump(tester, const WrongPassphrase(), const Locale('es'));
    expect(find.text(es.lockIncorrectPassphrase), findsOneWidget);
  });

  testWidgets('2. the unexpected case shows its raw diagnostic', (tester) async {
    await pump(tester,
        const UnexpectedUnlockError('Exception: keystore unavailable'),
        const Locale('en'));
    expect(find.text('Exception: keystore unavailable'), findsOneWidget);
  });
}
