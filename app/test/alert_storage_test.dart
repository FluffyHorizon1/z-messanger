// A contact's name, written into the database in the clear.
//
// The device-list banners — "Dana's devices disagree about their device
// list", "Dana's app says it sent the post-quantum signature" — were stored
// as the finished English sentence, in the `kv` table, with
// `sensitive: false`. So a display name sat in the database unencrypted,
// beside a routing id that says exactly whose name it is, in a vault whose
// own documentation opens with: "Every sensitive value (message bodies,
// NAMES, contact bundles, session state, file metadata) is encrypted
// cell-by-cell ... before it touches SQLite."
//
// The same sentences were a second problem. `chat_screen.dart` and
// `contact_info_screen.dart` are both on `check_l10n.py`'s migrated list,
// which is a promise that they contain no user-visible English — and they
// rendered a paragraph of it, handed to them by the service at run time,
// where the check cannot see it. A Spanish user got the banner in English.
//
// One change fixes both, and it is the one `system_messages.dart` already
// describes for system messages: store the KIND, never the sentence. The
// name is not stored at all now — the screen has the contact — and the words
// are chosen in the reader's language when the banner is drawn.
//
// Criteria, each a test below:
//  1. an alert is stored as a kind with no name in it, and still reads with
//     the name when it is shown;
//  2. an alert an earlier build wrote as prose is dropped when the app next
//     opens: not shown, and gone from the database file, name and all;
//  3. the words follow the reader's language, not the language the alert was
//     raised in;
//  4. and the general case behind it: a value rewritten from unsealed to
//     sealed leaves no unsealed copy behind, which it used to.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/system_messages.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/alert_text.dart';
import 'package:zapp/l10n/app_localizations_en.dart';
import 'package:zapp/l10n/app_localizations_es.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  final temps = <Directory>[];
  final live = <ChatService>[];

  tearDownAll(() async {
    for (final s in live) {
      s.dispose();
      await s.transport.stop();
    }
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<Directory> tempDir(String name) async {
    final d = await Directory.systemTemp.createTemp('z_alert_$name');
    temps.add(d);
    return d;
  }

  /// A service with no relay: nothing here needs the network, and the port is
  /// deliberately one nothing listens on.
  Future<ChatService> open(Directory dir, {String name = 'Me'}) async {
    final vault = await Vault.open(rootOverride: dir);
    final stored = await vault.kvGet('identity');
    final me = stored == null
        ? await ZIdentity.generate()
        : await ZIdentity.fromJson(
            (jsonDecode(stored) as Map).cast<String, Object?>());
    await vault.kvPut('identity', jsonEncode(me.toJson()));
    final svc = await ChatService.init(
        vault: vault,
        identity: me,
        displayName: name,
        transport: Transport(identity: me, serverUrl: 'ws://127.0.0.1:1'));
    live.add(svc);
    return svc;
  }

  Future<void> close(ChatService svc) async {
    svc.dispose();
    await svc.transport.stop();
    live.remove(svc);
    await svc.vault.db.close();
  }

  /// Dana, whose name is the thing that used to end up in the file.
  String? danaCode;
  Future<String> addDana(ChatService svc) async {
    if (danaCode == null) {
      final dana = await open(await tempDir('dana'), name: 'Dana');
      danaCode = await dana.myContactCode();
      await close(dana);
    }
    await svc.addContactFromCode(danaCode!);
    final rid = svc.contacts.keys.single;
    expect(svc.contacts[rid]!.name, 'Dana');
    return rid;
  }

  /// The whole database, as a forensic reader would see it.
  String rawDb(Directory dir) => utf8
      .decode(File('${dir.path}/z.db').readAsBytesSync(), allowMalformed: true);

  test('1. an alert is stored as a kind, and reads with the name anyway',
      () async {
    final dir = await tempDir('one');
    final svc = await open(dir);
    final rid = await addDana(svc);
    final body = devlistAlertBody(DevlistAlertKind.conflict);
    await svc.vault.kvPut('cdl_alert_$rid', body, sensitive: false);
    await svc.vault.db.rawQuery('PRAGMA wal_checkpoint');

    expect(rawDb(dir), contains('dl_conflict'),
        reason: 'the kind is in the file, as plain per-contact state');
    expect(rawDb(dir), isNot(contains("Dana's")),
        reason: 'and the name the sentence used to carry is not');

    // The reader still sees the name: it comes from the contact, at the
    // moment the banner is drawn.
    final shown = devlistAlertText(AppLocalizationsEn(), body, 'Dana');
    expect(shown, contains('Dana'));
    expect(shown, contains('may not be theirs'));
  });

  test('2. an alert an older build wrote as prose is dropped, not shown',
      () async {
    final dir = await tempDir('two');
    final svc = await open(dir);
    final rid = await addDana(svc);
    // Exactly what a build before 2026-09-13 stored, unsealed.
    const legacy = "Dana's devices disagree about their device list. One of "
        'them may not be theirs — check with them before continuing.';
    await svc.vault.kvPut('cdl_alert_$rid', legacy, sensitive: false);
    await svc.vault.kvPut('pql_alert_$rid', "Dana's app says it sent the "
        'post-quantum signature for its device list, and it has not arrived.',
        sensitive: false);
    expect(rawDb(dir), contains("Dana's"), reason: 'it really was in there');

    await close(svc);

    // The app starts again, with the same vault and the same contact.
    final again = await open(dir);
    expect(again.contacts.keys.single, rid);
    expect(again.contactDevlistAlerts[rid], isNull,
        reason: 'a sentence is not an alert this build knows how to show');
    expect(again.pqListAlerts[rid], isNull);
    expect(await again.vault.kvGet('cdl_alert_$rid'), isNull,
        reason: 'and it is not left in the vault either');
    expect(await again.vault.kvGet('pql_alert_$rid'), isNull);
    expect(rawDb(dir), isNot(contains("Dana's")),
        reason: 'the name is gone from the file, not merely from the query');
  });

  test('3. the words follow the reader language, not the raiser', () async {
    for (final kind in const [
      DevlistAlertKind.conflict,
      DevlistAlertKind.rollback,
      DevlistAlertKind.unconfirmed,
      DevlistAlertKind.missingUpdate,
      DevlistAlertKind.pqSignatureMissing,
    ]) {
      final body = devlistAlertBody(kind);
      final en = devlistAlertText(AppLocalizationsEn(), body, 'Dana');
      final es = devlistAlertText(AppLocalizationsEs(), body, 'Dana');
      expect(en, isNot(equals(body)), reason: '$kind has English words');
      expect(es, isNot(equals(body)), reason: '$kind has Spanish words');
      expect(en, isNot(equals(es)), reason: '$kind was not copied through');
      expect(es, contains('Dana'), reason: '$kind names the contact');
    }
    // A kind from a newer build renders as itself rather than as nothing.
    expect(devlistAlertText(AppLocalizationsEn(),
        devlistAlertBody('dl_from_the_future'), 'Dana'),
        contains('dl_from_the_future'));
  });

  test('4. a value rewritten sealed leaves no unsealed copy', () async {
    final dir = await tempDir('four');
    final vault = await Vault.open(rootOverride: dir);
    await vault.kvPut('a_name', 'Dana Whitfield', sensitive: false);
    expect(rawDb(dir), contains('Dana Whitfield'));

    await vault.kvPut('a_name', 'Dana Whitfield'); // sealed this time
    expect(await vault.kvGet('a_name'), 'Dana Whitfield');
    expect(rawDb(dir), isNot(contains('Dana Whitfield')),
        reason: 'the cleartext row went with the rewrite; it used to stay '
            'for the life of the vault, correct to every reader and '
            'invisible to all of them');
    final rows = await vault.db
        .query('kv', columns: ['k'], where: "k LIKE '%a\\_name' ESCAPE '\\'");
    expect(rows, hasLength(1), reason: 'one row, not one of each class');
    expect(rows.single['k'], 's:a_name');
    await vault.db.close();
  });
}
