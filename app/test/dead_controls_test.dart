// The "Disappearing messages" row on the contact screen was a read-only
// ListTile with no onTap, between three interactive rows — a dead control
// (the 2026-09-14 review sweep). It opens the shared timer picker now, the
// same one the chat screen's app-bar icon opens.
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
import 'package:zapp/ui/theme.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final l = AppLocalizationsEn();

  late Directory dir;
  late Vault vault;
  late ChatService svc;
  late String rid;

  setUp(() async {
    dir = await Directory.systemTemp.createTemp('z_dead');
    vault = await Vault.open(rootOverride: dir);
    final me = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(me.toJson()));
    svc = await ChatService.init(
        vault: vault,
        identity: me,
        displayName: 'Finn',
        transport: Transport(identity: me, serverUrl: 'ws://127.0.0.1:1'));
    final alice = await ZIdentity.generate();
    final code = await ContactBundleV3.forIdentity(
        alice,
        (await HybridKeyPair.fromSeeds(edSeed: alice.edSeed, mlSeed: randomBytes(32)))
            .publicKey,
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

  testWidgets('the disappearing-messages row opens the timer picker',
      (tester) async {
    await tester.binding.setSurfaceSize(const Size(800, 3000));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.runAsync(() async {
      await tester.pumpWidget(wrap(ContactInfoScreen(rid: rid)));
      await Future<void>.delayed(const Duration(milliseconds: 100));
      await tester.pump();

      // The row is present, and nothing radio-shaped is on screen yet.
      expect(find.text(l.disappearingMessages), findsOneWidget);
      expect(find.byIcon(Icons.radio_button_checked), findsNothing);

      await tester.tap(find.text(l.disappearingMessages));
      await tester.pump();
      await tester.pump(const Duration(milliseconds: 50));

      // The picker is open: one option checked (the current "off"), the rest
      // unchecked. A dead row could not have produced this.
      expect(find.byIcon(Icons.radio_button_checked), findsOneWidget,
          reason: 'the timer picker opened');
      expect(find.byIcon(Icons.radio_button_off), findsWidgets);
    });
  });
}
