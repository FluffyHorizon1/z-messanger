// The second locale (G9). The guard (`tool/check_l10n.py`) proves the
// Spanish ARB has every key with the same placeholders and plural cases;
// this proves the generated class is what the app loads for a Spanish
// device and that the things a translation can get wrong at run time —
// plurals, placeholders inside stored system messages, the duration words —
// come out in Spanish.
//
// Criteria, each a test below:
//  1. a Spanish locale resolves to the Spanish strings, and an unknown one
//     to English;
//  2. plural forms select the right case and carry the count;
//  3. system messages stored as a kind render in Spanish, duration included;
//  4. every string differs from English unless it is a symbol, a number or a
//     product name — a copy-through would be a translation that was never
//     made.
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/system_messages.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/l10n/app_localizations_en.dart';
import 'package:zapp/l10n/app_localizations_es.dart';
import 'package:zapp/l10n/system_text.dart';
import 'package:zapp/l10n/ttl_text.dart';

void main() {
  late AppLocalizations es;
  late AppLocalizations en;

  setUpAll(() async {
    es = await AppLocalizations.delegate.load(const Locale('es'));
    en = await AppLocalizations.delegate.load(const Locale('en'));
  });

  test('a Spanish device gets Spanish; an unsupported locale falls back to English', () async {
    expect(es, isA<AppLocalizationsEs>());
    expect(en, isA<AppLocalizationsEn>());
    expect(AppLocalizations.supportedLocales, contains(const Locale('es')));
    expect(AppLocalizations.delegate.isSupported(const Locale('es', 'MX')), isTrue);
    expect(AppLocalizations.delegate.isSupported(const Locale('fr')), isFalse);
    expect(es.homeSettings, 'Ajustes');
    expect(es.chatInputHint, isNot(en.chatInputHint));
  });

  test('plurals select the right case and carry the count', () {
    expect(es.ttlMinutes(1), '1 minuto');
    expect(es.ttlMinutes(5), '5 minutos');
    expect(es.grpCreateWithCount(1), 'Crear grupo (1 miembro)');
    expect(es.grpCreateWithCount(3), 'Crear grupo (3 miembros)');
    expect(es.timeDaysAgo(2), 'hace 2 días');
    expect(es.sysDecryptFailed(1), contains('Un mensaje'));
    expect(es.sysDecryptFailed(4), startsWith('4 mensajes'));
    expect(ttlText(es, 300), '5 minutos');
    expect(ttlText(es, 0), 'Desactivados');
  });

  test('stored system messages render in Spanish, the duration in words', () {
    expect(
      systemText(es, systemBody(SystemKind.ttlSetThem, {'name': 'Ana', 'sec': 3600})),
      'Ana configuró los mensajes temporales a 1 hora.',
    );
    expect(
      systemText(es, systemBody(SystemKind.createdYou, {'name': 'Equipo'})),
      'Creaste «Equipo».',
    );
    expect(systemText(es, systemBody(SystemKind.sessionReset)),
        'La sesión segura se restableció.');
  });

  test('nothing was copied through untranslated', () {
    // The two ARBs, key by key: a Spanish value equal to the English one is
    // a translation that was never made — unless the string is a symbol, a
    // format or a name that is the same in both languages.
    const same = {
      'searchSenderPrefix', 'chatPreviewSender', 'chatPreviewFile', 'sizeKb', 'sizeMb', 'sizeB',
      'chatReactionChip', 'stRelay',
    };
    Map<String, Object?> arb(String name) =>
        (jsonDecode(File('lib/l10n/$name').readAsStringSync()) as Map).cast<String, Object?>();
    final enArb = arb('app_en.arb');
    final esArb = arb('app_es.arb');
    final copied = <String>[];
    for (final k in enArb.keys) {
      if (k.startsWith('@')) continue;
      if (same.contains(k)) continue;
      if (enArb[k] == esArb[k]) copied.add(k);
    }
    expect(copied, isEmpty, reason: 'identical to English: $copied');
    expect(esArb['@@locale'], 'es');
    // The claims travel: a sentence about the relay never touching disk is
    // still a sentence about the relay never touching disk.
    expect(es.stWhereMessagesLiveHelp, contains('RAM'));
    expect(es.stWhereMessagesLiveHelp, contains('nunca en disco'));
    expect(es.backupCodeNobodyCan, contains('orden judicial'));
  });
}
