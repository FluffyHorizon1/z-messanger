// The two owner-account banners, stored as a kind and rendered in the
// reader's language — the pair the 2026-09-13 device-list fix missed and the
// 2026-09-14 review's finding 38 named.
//
// Until now `home_screen.dart` (on `check_l10n.py`'s migrated list, a promise
// it holds no English) showed a sentence the service built in English in
// `core/` and stored in `kv` as prose: a Spanish user read it in English, and
// the check could not see it because it lived in core. Now the service stores
// `{"k":"own_older","sent":5,"held":7}` and the screen chooses the words when
// it draws the banner.
//
// Criteria, each a test below:
//   1. the stored form is a kind and its version numbers, with no sentence in
//      it — so nothing an author must translate is frozen into the vault;
//   2. the words follow the reader's language, not the language the alarm was
//      raised in, and carry the stored numbers;
//   3. a value an earlier build wrote as prose is shown as it is (these carry
//      no name and no secret, so there is nothing to drop).
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/system_messages.dart';
import 'package:zapp/l10n/account_alert_text.dart';
import 'package:zapp/l10n/app_localizations_en.dart';
import 'package:zapp/l10n/app_localizations_es.dart';

void main() {
  final en = AppLocalizationsEn();
  final es = AppLocalizationsEs();

  test('1. stored as a kind and its numbers, no sentence', () {
    final older = ownAlertBody(OwnAlertKind.olderList, {'sent': 5, 'held': 7});
    final unissued = ownAlertBody(OwnAlertKind.unissued);
    final removed = ownAlertBody(OwnAlertKind.removed, {'v': 9});

    for (final s in [older, unissued, removed]) {
      final m = jsonDecode(s) as Map<String, Object?>;
      expect(m['k'], isA<String>());
      // No prose: every value is a kind token or a number.
      for (final e in m.entries) {
        if (e.key == 'k') continue;
        expect(e.value, isA<num>(), reason: '${e.key} is a number, not words');
      }
      expect(s, isNot(contains(' ')), reason: 'the stored form has no sentence');
    }
    expect((jsonDecode(older) as Map)['sent'], 5);
    expect((jsonDecode(older) as Map)['held'], 7);
    expect((jsonDecode(removed) as Map)['v'], 9);
  });

  test('2. the words follow the reader language and carry the numbers', () {
    final older = ownAlertBody(OwnAlertKind.olderList, {'sent': 5, 'held': 7});
    final unissued = ownAlertBody(OwnAlertKind.unissued);
    final removed = ownAlertBody(OwnAlertKind.removed, {'v': 9});

    // English carries the exact ARB wording and the numbers.
    expect(ownAccountAlertText(en, older), contains('v5'));
    expect(ownAccountAlertText(en, older), contains('v7'));
    expect(ownAccountAlertText(en, older), contains('reset your identity'));
    expect(ownAccountAlertText(en, unissued), contains('never issued'));
    expect(removedDeviceAlertText(en, removed), contains('v9'));

    // Spanish is a different string for the same kind — the point of the fix.
    expect(ownAccountAlertText(es, older),
        isNot(equals(ownAccountAlertText(en, older))));
    expect(ownAccountAlertText(es, older), contains('restablece'));
    expect(ownAccountAlertText(es, older), contains('v5'));
    expect(ownAccountAlertText(es, unissued), contains('nunca emitió'));
    expect(removedDeviceAlertText(es, removed), contains('v9'));
  });

  test('3. a prose value from an earlier build is shown as it is', () {
    const legacy = 'This device was removed from your account (device list v9).';
    expect(removedDeviceAlertText(en, legacy), legacy);
    expect(ownAccountAlertText(es, 'Un mensaje antiguo'), 'Un mensaje antiguo');
    // A JSON object with a kind this build does not know: the object stands in
    // rather than nothing.
    final future = jsonEncode({'k': 'own_from_the_future', 'x': 1});
    expect(ownAccountAlertText(en, future), future);
  });
}
