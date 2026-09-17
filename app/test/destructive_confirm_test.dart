// Two destructive actions that fired on a single tap, where every other one
// in the app asks first (the 2026-09-14 review's findings 40 and 41):
//   - "Reset secure session" threw away every ratchet session with a contact
//     and the skipped-message keys, so anything the relay still held for the
//     old chain became undecryptable;
//   - an admin removed a group member — signed, fanned out to everyone, no
//     undo — with one icon tap.
// Both are gated by a confirmation now. These tests pin the gate: cancelling
// changes nothing, confirming does the work.
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/l10n/app_localizations_en.dart';
import 'package:zapp/ui/contact_info_screen.dart';
import 'package:zapp/ui/group_screens.dart';
import 'package:zapp/ui/theme.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final l = AppLocalizationsEn();

  late Directory dir;
  late Vault vault;
  late ChatService svc;
  late String rid;

  setUp(() async {
    dir = await Directory.systemTemp.createTemp('z_confirm');
    vault = await Vault.open(rootOverride: dir);
    final me = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(me.toJson()));
    // Port 1 is never listening: these are UI gate tests, and the service
    // renders and queues the same whether or not a relay answers.
    final transport = Transport(identity: me, serverUrl: 'ws://127.0.0.1:1');
    svc = await ChatService.init(
        vault: vault, identity: me, displayName: 'Finn', transport: transport);
    final alice = await ZIdentity.generate();
    final code = await ContactBundleV3.forIdentity(
        alice, (await HybridKeyPair.fromSeeds(edSeed: alice.edSeed, mlSeed: randomBytes(32))).publicKey,
        displayName: 'Alice');
    rid = (await svc.addContactFromCode(code.encode(), alias: 'Alice')).rid;
  });

  tearDown(() async {
    await Future<void>.delayed(const Duration(milliseconds: 200));
    await svc.transport.stop();
    await svc.vault.db.close();
    if (dir.existsSync()) dir.deleteSync(recursive: true);
  });

  Widget wrap(Widget child) => ChangeNotifierProvider<ChatService>.value(
        value: svc,
        child: MaterialApp(
          debugShowCheckedModeBanner: false,
          theme: ZTheme.light(),
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: child,
        ),
      );

  testWidgets('40. resetting a secure session asks first', (tester) async {
    // The reset row is near the bottom of a ListView; a tall (and wide enough
    // to avoid a test-only horizontal overflow) surface builds every row so
    // the finder reaches it without scrolling.
    await tester.binding.setSurfaceSize(const Size(800, 3000));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.runAsync(() async {
      await tester.pumpWidget(wrap(ContactInfoScreen(rid: rid)));
      await Future<void>.delayed(const Duration(milliseconds: 100));
      await tester.pump();

      // Tapping the row opens a confirmation, and resets nothing yet.
      await tester.tap(find.text(l.ciResetSession));
      await tester.pump();
      expect(find.text(l.ciResetTitle), findsOneWidget,
          reason: 'reset must ask before it destroys the session');

      // Cancel: the dialog closes and no reset happened (no confirmation
      // snackbar, which only follows a completed reset).
      await tester.tap(find.text(l.cancel));
      await tester.pump();
      expect(find.text(l.ciResetTitle), findsNothing);
      expect(find.text(l.ciResetSessionDone), findsNothing,
          reason: 'cancelling reset nothing');

      // Confirm: now it resets, and says so.
      await tester.tap(find.text(l.ciResetSession));
      await tester.pump();
      await tester.tap(find.text(l.ciResetConfirm));
      await Future<void>.delayed(const Duration(milliseconds: 100));
      await tester.pump();
      expect(find.text(l.ciResetSessionDone), findsOneWidget,
          reason: 'confirming reset the session');
    });
  });

  testWidgets('41. removing a group member asks first', (tester) async {
    await tester.runAsync(() async {
      final gid = await svc.createGroup('Trio', [rid]);
      expect(svc.groups[gid]!.memberRids, contains(rid));

      await tester.pumpWidget(wrap(GroupInfoScreen(gid: gid)));
      await Future<void>.delayed(const Duration(milliseconds: 100));
      await tester.pump();

      final removeIcon = find.byIcon(Icons.person_remove_outlined);
      expect(removeIcon, findsOneWidget, reason: 'the admin sees one member');

      // Tap: a confirmation, and the member is still in the group.
      await tester.tap(removeIcon);
      await tester.pump();
      expect(find.text(l.grpRemoveTitle), findsOneWidget,
          reason: 'removal must ask before it signs and fans out');
      await tester.tap(find.text(l.cancel));
      await Future<void>.delayed(const Duration(milliseconds: 50));
      await tester.pump();
      expect(svc.groups[gid]!.memberRids, contains(rid),
          reason: 'cancelling removed nobody');

      // Confirm: now the member is gone.
      await tester.tap(removeIcon);
      await tester.pump();
      await tester.tap(find.text(l.grpRemoveConfirm));
      await Future<void>.delayed(const Duration(milliseconds: 100));
      await tester.pump();
      expect(svc.groups[gid]!.memberRids, isNot(contains(rid)),
          reason: 'confirming removed the member');
    });
  });
}
