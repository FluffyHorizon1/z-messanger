// 13.3's user-facing half: what a person actually sees when a safety number
// moves.
//
// The protocol work is done — the number is anchored to the account key and
// derived from both halves once the post-quantum key has arrived and matched.
// But the number moves ONCE for every contact in existence, and a number that
// changes with no explanation is indistinguishable from a key substitution.
// That is the whole risk of this phase: an upgrade meant to strengthen
// authentication, presented in a way that teaches people to ignore the one
// signal that catches an attack.
//
// So these tests are about words on a screen. They pin that the three
// assurance states are shown apart, that a tick never stands against a number
// the user did not compare, and that when the number does move the app says
// why — in the same place the user goes to check it.
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/models.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/ui/contact_info_screen.dart';
import 'package:zapp/ui/theme.dart';
import 'package:zapp/l10n/app_localizations.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late Directory dir;
  late Vault vault;
  late ChatService svc;
  late String rid;
  late HybridKeyPair alicePq;

  setUp(() async {
    dir = await Directory.systemTemp.createTemp('z_vux');
    vault = await Vault.open(rootOverride: dir);
    final me = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(me.toJson()));
    // Port 1 is never listening: this test is about rendering, and a service
    // that cannot reach a relay renders exactly the same.
    final transport = Transport(identity: me, serverUrl: 'ws://127.0.0.1:1');
    svc = await ChatService.init(
        vault: vault, identity: me, displayName: 'Finn', transport: transport);

    final alice = await ZIdentity.generate();
    alicePq = await HybridKeyPair.fromSeeds(
        edSeed: alice.edSeed, mlSeed: randomBytes(32));
    final code = await ContactBundleV3.forIdentity(alice, alicePq.publicKey,
        displayName: 'Alice');
    rid = (await svc.addContactFromCode(code.encode(), alias: 'Alice')).rid;
  });

  tearDown(() async {
    // The screen derives its safety number asynchronously and that work
    // outlives the last pump: `mounted` guards the setState, but the awaits
    // inside are already in flight and will touch the vault. Deleting the
    // directory underneath them turns a finished test into a failure of
    // whichever test runs next. tearDown is outside FakeAsync, so a real
    // pause here is a real pause.
    await Future<void>.delayed(const Duration(milliseconds: 300));
    await svc.transport.stop();
    await svc.vault.db.close();
    if (dir.existsSync()) dir.deleteSync(recursive: true);
  });

  /// Installs the post-quantum key the scanned code committed to, exactly as
  /// an inbound `pqid` would, and reloads so the service reclassifies from
  /// disk. Going through the database rather than the network keeps this a
  /// widget test — the acceptance path itself is covered in
  /// `pq_identity_test.dart`.
  Future<void> upgradeToHybrid() async {
    await vault.db.update('contacts',
        {'enc_pq_pub': await vault.seal(b64(alicePq.publicKey.mlPub))},
        where: 'rid = ?', whereArgs: [rid]);
    await svc.reloadContacts();
  }

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

  /// `testWidgets` runs under FakeAsync, which does not advance real database
  /// I/O or the thousands of SHA-256 rounds behind a safety number. Every
  /// service-level mutation these tests make therefore goes through
  /// `runAsync`, and so does the screen's own derivation.
  Future<void> real(WidgetTester tester, Future<void> Function() body) =>
      tester.runAsync(body).then((_) {});

  Future<void> show(WidgetTester tester) async {
    await tester.pumpWidget(wrap(ContactInfoScreen(rid: rid)));
    await tester.runAsync(
        () => Future<void>.delayed(const Duration(milliseconds: 100)));
    await tester.pump();
    await tester.pump();
  }

  testWidgets('a pending identity says so, and warns the number will move',
      (tester) async {
    // The hazard §18.3 names: the classical view of a v3 code works
    // perfectly, so it is easy to show an identity as post-quantum when all
    // that has happened is a scan. It has not been verified post-quantum, and
    // the screen must not imply it has.
    expect(svc.contacts[rid]!.assurance, IdentityAssurance.pendingPostQuantum);
    await show(tester);

    expect(find.text('Post-quantum pending'), findsOneWidget);
    expect(find.textContaining('changes ONCE'), findsOneWidget,
        reason: 'the user is warned BEFORE the number moves, not after');
    expect(find.text('Post-quantum'), findsNothing,
        reason: 'a promise is not an arrival');
  });

  testWidgets('a verified tick that still covers the number shown',
      (tester) async {
    await real(tester, () => svc.setVerified(rid, true));
    await show(tester);
    expect(svc.verificationWith(rid), VerificationState.verified);
    expect(find.text('Verified'), findsWidgets);
    expect(
        find.textContaining('This is the number you compared'), findsOneWidget);
  });

  testWidgets('when the number moves, the screen explains why and asks again',
      (tester) async {
    await real(tester, () async {
      await svc.setVerified(rid, true);
      await upgradeToHybrid();
    });
    expect(svc.verificationWith(rid), VerificationState.upgradedReverify);

    await show(tester);
    // The identity is now genuinely hybrid…
    expect(find.text('Post-quantum'), findsOneWidget);
    // …and the change is named as an upgrade rather than left to be guessed
    // at. This sentence is the deliverable of 13.3.
    expect(find.text('The number changed — here is why'), findsOneWidget);
    expect(find.textContaining('gained a post-quantum key'), findsOneWidget);
    expect(
        find.textContaining('not a sign that anyone tampered'), findsOneWidget);
    expect(find.textContaining('compare it again'), findsOneWidget);

    // And the tick is not left standing against a number nobody read.
    final sw = tester.widget<SwitchListTile>(find.byType(SwitchListTile));
    expect(sw.value, isFalse);
    expect(find.text('I have compared it again'), findsOneWidget);
  });

  testWidgets('reading it again restores the tick', (tester) async {
    await real(tester, () async {
      await svc.setVerified(rid, true);
      await upgradeToHybrid();
      await svc.setVerified(rid, true); // the user compares the new number
    });
    expect(svc.verificationWith(rid), VerificationState.verified);

    await show(tester);
    expect(find.text('The number changed — here is why'), findsNothing);
    expect(
        find.textContaining('This is the number you compared'), findsOneWidget);
  });

  testWidgets('a device list that is only classically signed says so',
      (tester) async {
    // §18.9. The identity is post-quantum verified; the DEVICE LIST behind it
    // may not be yet, and those are different claims. Collapsing them would
    // let a suppressed signature hide behind a hybrid identity.
    await real(tester, upgradeToHybrid);
    await show(tester);
    expect(find.text('Post-quantum'), findsOneWidget);
    expect(find.textContaining('signed classically only'), findsOneWidget,
        reason: 'the list is a separate claim from the identity');
    expect(find.textContaining('may not have arrived yet'), findsOneWidget,
        reason: 'and its absence is normal at first, not an accusation');
  });

  testWidgets('a refused post-quantum key is stated plainly, at the top',
      (tester) async {
    // The one case where the app knows something is wrong. It must not be a
    // line buried in the transcript that scrolls away.
    await real(tester, () async {
      await vault.db.update('contacts', {'pq_mismatch': 1},
          where: 'rid = ?', whereArgs: [rid]);
      await svc.reloadContacts();
    });

    await show(tester);
    expect(find.text('Post-quantum key refused'), findsOneWidget);
    expect(find.textContaining('someone is substituting keys'), findsOneWidget);
    // Refused means NOT upgraded — the screen must not also be claiming the
    // identity is post-quantum.
    expect(find.text('Post-quantum pending'), findsOneWidget);
  });
}
