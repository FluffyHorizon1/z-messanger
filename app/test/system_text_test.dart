// 15.4 — system messages are stored as a kind, rendered in the user's
// language at the moment they are shown.
//
// The risks are specific. A kind the service writes that the renderer does
// not know shows as raw JSON in the chat; a row from before the change — the
// English sentence itself — must still read as it did; and the duration
// inside "You set disappearing messages to …" has to come out in words.
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/system_messages.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/l10n/system_text.dart';

void main() {
  late AppLocalizations l;

  setUpAll(() async {
    l = await AppLocalizations.delegate.load(const Locale('en'));
  });

  test('every kind the service can write has a rendering', () {
    // Every static const String on SystemKind, without reflection: the
    // list is the contract, and adding a kind means adding it here too —
    // which is the point, because the renderer's fallback is raw JSON.
    const kinds = [
      SystemKind.pqMismatch,
      SystemKind.sessionReset,
      SystemKind.ttlOffYou,
      SystemKind.ttlSetYou,
      SystemKind.decryptFailed,
      SystemKind.ttlOffThem,
      SystemKind.ttlSetThem,
      SystemKind.attachmentDiscarded,
      SystemKind.leftYou,
      SystemKind.createdYou,
      SystemKind.addedYou,
      SystemKind.removedYou,
      SystemKind.removedFrom,
      SystemKind.addedToBy,
      SystemKind.membershipUpdated,
      SystemKind.memberLeft,
    ];
    for (final k in kinds) {
      final out = systemText(
          l,
          systemBody(k, {
            'name': 'Alice',
            'by': 'Bob',
            'sec': 300,
            'names': ['Carol', 'Dave']
          }));
      expect(out, isNot(startsWith('{')),
          reason: '$k rendered as raw JSON: no arm in systemText for it');
      expect(out.trim(), isNotEmpty, reason: '$k rendered empty');
    }
  });

  test('the duration is rendered in words from the stored seconds', () {
    expect(systemText(l, systemBody(SystemKind.ttlSetYou, {'sec': 300})),
        'You set disappearing messages to 5 minutes.');
    expect(
        systemText(l,
            systemBody(SystemKind.ttlSetThem, {'name': 'Alice', 'sec': 3600})),
        'Alice set disappearing messages to 1 hour.');
  });

  test('a missing name is worded, not printed as null', () {
    expect(systemText(l, systemBody(SystemKind.memberLeft, {'name': null})),
        'A member left the group.');
    expect(
        systemText(
            l,
            systemBody(SystemKind.addedYou, {
              'names': ['Carol', null]
            })),
        'You added Carol, a member.');
    expect(
        systemText(l,
            systemBody(SystemKind.addedToBy, {'by': null, 'name': 'Hikers'})),
        'Someone added you to "Hikers".');
  });

  test('a row from before the change reads exactly as it was stored', () {
    const old = 'You left the group.';
    expect(systemText(l, old), old);
    // Prose that happens to start with a brace, or JSON without a kind, is
    // also left alone rather than half-parsed.
    expect(systemText(l, '{not json'), '{not json');
    expect(systemText(l, '{"x":1}'), '{"x":1}');
  });

  test('a kind from a newer build falls back to the stored body', () {
    final body = systemBody('something_new', {'a': 1});
    expect(systemText(l, body), body);
  });
}
