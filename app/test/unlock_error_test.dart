// The launch-time unlock errors, chosen in the reader's language.
//
// They were built as English sentences in `main.dart` — above the MaterialApp,
// where AppLocalizations is not in scope — and `check_l10n.py` scanned only
// `lib/ui`, never `main.dart`, so a Spanish user met the passphrase and
// biometric errors in English and nothing caught it (the 2026-09-14 review's
// finding 39). The bootstrapper now hands `UnlockScreen` a typed [UnlockError]
// and the words are chosen here.
//
// Until 2026-10-31 the unexpected case showed its error's text, as it came,
// in English to every reader, and criterion 2 held it to that. It says what
// failed in the reader's language now (`unlockFailureText`).
//
// Criteria, each a test below:
//   1. each error kind renders its own string, and follows the locale;
//   2. the unexpected case says what failed — a store that could not be
//      opened, the system's secure storage refusing, anything else — in the
//      reader's language, and never the error's text.
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
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

  testWidgets(
      '2. the unexpected case says what failed in the reader\'s language, '
      'never the error\'s text', (tester) async {
    for (final (error, words) in <(Object, String Function(AppLocalizations))>[
      (
        const FileSystemException('Cannot open file', '/z/z.db'),
        (l) => l.unlockFailedStorage
      ),
      (
        PlatformException(code: 'NotAvailable', message: 'keystore unavailable'),
        (l) => l.unlockFailedKeystore
      ),
      (StateError('something nobody expected'), (l) => l.unlockFailedOther),
    ]) {
      for (final (locale, l) in [
        (const Locale('en'), en as AppLocalizations),
        (const Locale('es'), es as AppLocalizations),
      ]) {
        await pump(tester, UnexpectedUnlockError(error), locale);
        expect(find.text(words(l)), findsOneWidget, reason: '$error, $locale');
        expect(
            find.textContaining(
                RegExp('Exception|Error|Cannot open|keystore unavailable|nobody')),
            findsNothing,
            reason: '$error, $locale: never the error\'s text');
      }
      expect(words(es), isNot(words(en)), reason: 'the Spanish its own');
    }
  });
}
