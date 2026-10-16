// The handle screens (phase 38): Settings › Your handle, Add contact's Handle
// tab, and what the Requests screen shows of a request that came through the
// handle. A real ChatService over a real vault; no relay and no log answer
// (port 1), because what is asserted is what each screen SAYS in each state,
// and the states are set directly where a log would have to be driven to
// reach them (handle_flow_test.dart drives the real ones).
//
// Criteria, each a test below:
//   1. with no handle service configured — this build's defaults — the
//      Settings row says handles are not available, and the handle screen
//      and the Handle tab say so plainly and offer nothing;
//   2. on a linked device, with a service configured, the handle screen says
//      only the main device holds a handle and offers no claim;
//   3. on the main device the claim form judges the name as it is typed, in
//      words — a reserved name, a look-alike letter, a name too short — and
//      offers Check only for a valid one; Recover is offered beside it;
//   4. a published handle is shown with its screen-reader label, the line
//      that a handle is not a verification, and the actions, and a log that
//      cannot be reached when the screen reads the handle back is said;
//      giving it up asks first, and cancelling changes nothing;
//   5. a request that came through the handle reads "Via @nick.digits" on
//      the Requests screen, and being shown marks it seen, in the vault too;
//   6. in Spanish, the screens read in Spanish;
//   7. when the relay's last answer to `intro` says it is not guarding the
//      handle's inbox — too old, full, or pacing — the handle screen says so,
//      each in its own words, with the line that this phone still checks the
//      work on every request; while the relay guards it, neither; and in
//      Spanish too;
//   8. a handle lost because its inbox was moved to a key this device does
//      not hold says that, not that its recovery code was used, and offers
//      Recover and Forget — and a log that cannot be reached when the screen
//      reads the handle back does not put another reason in its place;
//   9. what the phone's own checks dropped is on the handle screen — how
//      many requests came without the work and how many copies of requests
//      already decided were refused, over the ledger's five days, singular
//      and plural, nothing while both are zero — and a day of the ledger at
//      its cap is said as a warning with the cap; in Spanish too.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/handles.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/l10n/app_localizations_en.dart';
import 'package:zapp/l10n/app_localizations_es.dart';
import 'package:zapp/l10n/handle_text.dart';
import 'package:zapp/ui/find_handle_screen.dart';
import 'package:zapp/ui/handle_screen.dart';
import 'package:zapp/ui/requests_screen.dart';
import 'package:zapp/ui/theme.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final l = AppLocalizationsEn();
  final es = AppLocalizationsEs();
  // A handle service on loopback that nothing answers: available, and every
  // request to it fails — which the screens must survive.
  final silent = HandleConfig(
      logUrl: 'http://127.0.0.1:1',
      logPubB64: b64(Uint8List(32)..fillRange(0, 32, 9)));

  final dirs = <Directory>[];
  final services = <ChatService>[];

  Future<ChatService> service({HandleConfig? config, bool linked = false}) async {
    final dir = await Directory.systemTemp.createTemp('z_hscreens');
    dirs.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final me = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(me.toJson()));
    if (linked) {
      // Enrolled to an account whose root it does not hold.
      final root = await ZIdentity.generate();
      final account = await AccountIdentity.fromV1(root, deviceId: 'phone');
      final cert = await account.signDeviceCert(
          deviceEdPub: me.edPub, deviceXPub: me.xPub, deviceId: 'laptop');
      final enrolled = await AccountIdentity.fromEnrollment(
        accountEdPub: account.accountEdPub,
        deviceEdSeed: me.edSeed,
        deviceXSeed: me.xSeed,
        deviceId: 'laptop',
        deviceCert: cert,
      );
      await vault.kvPut('account', jsonEncode(enrolled.toJson()));
    }
    final svc = await ChatService.init(
        vault: vault,
        identity: me,
        displayName: 'Finn',
        transport: Transport(identity: me, serverUrl: 'ws://127.0.0.1:1'),
        handleConfig: config ?? HandleConfig.defaults);
    services.add(svc);
    return svc;
  }

  tearDown(() async {
    for (final s in services) {
      s.dispose();
      await s.transport.stop();
      await s.vault.db.close();
    }
    services.clear();
    for (final d in dirs) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
    dirs.clear();
  });

  Widget wrap(ChatService svc, Widget child, {Locale? locale}) =>
      ChangeNotifierProvider<ChatService>.value(
        value: svc,
        child: MaterialApp(
          debugShowCheckedModeBanner: false,
          theme: ZTheme.light(),
          locale: locale,
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: Scaffold(body: child),
        ),
      );

  Future<void> until(
      WidgetTester tester, bool Function() cond, String what) async {
    final deadline = DateTime.now().add(const Duration(seconds: 15));
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 20));
      await tester.pump();
    }
  }

  Future<void> untilAsync(WidgetTester tester, Future<bool> Function() cond,
      String what) async {
    final deadline = DateTime.now().add(const Duration(seconds: 15));
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 20));
      await tester.pump();
    }
  }

  OwnHandle published(String handle) => OwnHandle(
        handle: Handle.parse(handle),
        label: Uint8List(32),
        ownerSeed: randomBytes(32),
        introSeed: randomBytes(32),
        pow: handleDefaultPow,
        rc: Uint8List(32),
        version: 3,
        phase: HandlePhase.live,
      );

  testWidgets('1. no handle service: every surface says so and offers nothing',
      (tester) async {
    await tester.runAsync(() async {
      final svc = await service();
      expect(svc.handles.available, isFalse);
      expect(handleRowText(l, svc.handles), l.hdlRowUnavailable);
      await tester.pumpWidget(wrap(svc, const HandleScreen()));
      await until(tester, () => find.text(l.hdlUnavailable).evaluate().isNotEmpty,
          'the handle screen saying handles are unavailable');
      expect(find.text(l.hdlClaim), findsNothing);
      expect(find.text(l.hdlRecover), findsNothing);
      await tester.pumpWidget(wrap(svc, const FindHandleView()));
      await until(tester, () => find.text(l.hdlUnavailable).evaluate().isNotEmpty,
          'the Handle tab saying handles are unavailable');
      expect(find.text(l.hdlFind), findsNothing);
    });
  });

  testWidgets('2. a linked device: only the main device holds a handle',
      (tester) async {
    await tester.runAsync(() async {
      final svc = await service(config: silent, linked: true);
      expect(svc.handles.available, isTrue);
      expect(svc.handles.canManage, isFalse);
      expect(handleRowText(l, svc.handles), l.hdlRowLinked);
      await tester.pumpWidget(wrap(svc, const HandleScreen()));
      await until(tester, () => find.text(l.hdlLinkedDevice).evaluate().isNotEmpty,
          'the linked-device line');
      expect(find.text(l.hdlClaim), findsNothing);
      // Finding someone by their handle is any device's.
      await tester.pumpWidget(wrap(svc, const FindHandleView()));
      await until(tester, () => find.text(l.hdlFind).evaluate().isNotEmpty,
          'the Find button on a linked device');
    });
  });

  testWidgets('3. the claim form says what is wrong with a name, in words',
      (tester) async {
    await tester.runAsync(() async {
      final svc = await service(config: silent);
      expect(handleRowText(l, svc.handles), l.hdlRowNone);
      await tester.pumpWidget(wrap(svc, const HandleScreen()));
      await until(tester, () => find.text(l.hdlClaim).evaluate().isNotEmpty,
          'the Claim button');
      expect(find.text(l.hdlRecover), findsOneWidget);
      expect(find.text(l.hdlWhatItShows), findsOneWidget,
          reason: 'what a handle makes public is said before a claim');
      await tester.tap(find.text(l.hdlClaim));
      await tester.pump();
      final field = find.byType(TextField).first;
      FilledButton check() => tester.widget<FilledButton>(
          find.ancestor(of: find.text(l.hdlCheck), matching: find.byType(FilledButton)));

      await tester.enterText(field, 'support');
      await tester.pump();
      expect(find.text(l.hdlBadReserved), findsOneWidget);
      expect(check().onPressed, isNull);

      // A Cyrillic "а" where a Latin "a" belongs: refused by name.
      await tester.enterText(field, 'bаrbara');
      await tester.pump();
      expect(find.text(l.hdlBadCharacter('а')), findsOneWidget);
      expect(check().onPressed, isNull);

      await tester.enterText(field, 'fi');
      await tester.pump();
      expect(find.text(l.hdlBadNickShort), findsOneWidget);

      await tester.enterText(field, 'finn');
      await tester.pump();
      expect(find.text(l.hdlBadNickShort), findsNothing);
      expect(check().onPressed, isNotNull);
    });
  });

  testWidgets('4. a published handle: label, the verification line, actions; '
      'giving it up asks first', (tester) async {
    await tester.binding.setSurfaceSize(const Size(800, 2000));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.runAsync(() async {
      final svc = await service(config: silent);
      svc.handles.own = published('finn.42');
      expect(handleRowText(l, svc.handles), '@finn.42');
      final semantics = tester.ensureSemantics();
      await tester.pumpWidget(wrap(svc, const HandleScreen()));
      await until(tester, () => find.text(l.hdlNotVerification).evaluate().isNotEmpty,
          'the published handle');
      // Opening the screen reads the handle back from the log, which nothing
      // answers here: that is said on the screen, and kept.
      await untilAsync(
          tester,
          () async => ((await svc.vault.kvGet('handle')) ?? '')
              .contains('"problem":"unreachable"'),
          'the read-back finished, the log unreachable');
      await until(tester, () => find.text(l.hdlErrUnreachable).evaluate().isNotEmpty,
          'the unreachable log said on the screen');
      expect(find.bySemanticsLabel(l.hdlSemHandle('finn.42')), findsOneWidget);
      expect(find.byTooltip(l.hdlCopy), findsOneWidget);
      for (final a in [l.hdlPause, l.hdlRotate, l.hdlDifficulty, l.hdlRetire]) {
        expect(find.text(a), findsOneWidget, reason: 'the action "$a"');
      }
      await tester.tap(find.text(l.hdlRetire));
      await tester.pump();
      expect(find.text(l.hdlRetireConfirmTitle('finn.42')), findsOneWidget,
          reason: 'giving a handle up asks first');
      await tester.tap(find.text(l.cancel));
      await tester.pump();
      expect(svc.handles.own?.phase, HandlePhase.live,
          reason: 'cancelling changed nothing');
      semantics.dispose();
      await tester.pumpWidget(const SizedBox());
    });
  });

  testWidgets('5. a request through the handle reads "Via"; shown, it is seen',
      (tester) async {
    await tester.runAsync(() async {
      final svc = await service(config: silent);
      final rick = await ZIdentity.generate();
      final rid = await rick.routingId();
      final creq = await ContactRequest.create(
          me: rick, toRid: 'intro-mailbox', displayName: 'Rick');
      expect(
          await svc.addHandleRequest(creq, requesterRid: rid, handle: 'finn.42'),
          isTrue);
      await svc.handles.recordInbound(rid,
          handle: 'finn.42', introRid: 'intro-mailbox', creqId: Uint8List(32));
      expect(svc.handles.inboundFor(rid)!.seen, isFalse);
      await tester.pumpWidget(wrap(svc, const RequestsScreen()));
      await until(tester, () => find.text(l.requestsVia('finn.42')).evaluate().isNotEmpty,
          'the request shown via the handle');
      await until(tester, () => svc.handles.inboundFor(rid)!.seen,
          'the request marked seen once shown');
      // And kept: what the cap reads after a restart is the stored record.
      await untilAsync(tester, () async {
        final stored = await svc.vault.kvGet('handle_in');
        if (stored == null) return false;
        final reqs = (jsonDecode(stored) as Map)['reqs'] as Map?;
        return (reqs?[rid] as Map?)?['seen'] == 1;
      }, 'the seen mark stored in the vault');
      // Off the screen, so no frame asks again while the vault closes.
      await tester.pumpWidget(const SizedBox());
    });
  });

  testWidgets('6. in Spanish', (tester) async {
    await tester.runAsync(() async {
      final svc = await service(config: silent);
      await tester.pumpWidget(
          wrap(svc, const HandleScreen(), locale: const Locale('es')));
      await until(tester, () => find.text(es.hdlClaim).evaluate().isNotEmpty,
          'the handle screen in Spanish');
      expect(find.text(es.hdlIntro), findsOneWidget);
      expect(es.hdlIntro, isNot(l.hdlIntro));
      await tester.pumpWidget(
          wrap(svc, const FindHandleView(), locale: const Locale('es')));
      await until(tester, () => find.text(es.hdlFind).evaluate().isNotEmpty,
          'the Handle tab in Spanish');
    });
  });

  testWidgets('7. the relay not guarding the inbox, said, and what still holds',
      (tester) async {
    await tester.binding.setSurfaceSize(const Size(800, 2400));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.runAsync(() async {
      final svc = await service(config: silent);
      svc.handles.own = published('finn.42');
      for (final (guard, en, sp) in [
        (HandleRelayGuard.tooOld, l.hdlRelayUnguarded, es.hdlRelayUnguarded),
        (HandleRelayGuard.full, l.hdlRelayFull, es.hdlRelayFull),
        (HandleRelayGuard.paced, l.hdlRelayPaced, es.hdlRelayPaced),
      ]) {
        svc.handles.relayGuard = guard;
        expect(svc.handles.relayUnguarded, isTrue);
        await tester.pumpWidget(wrap(svc, HandleScreen(key: UniqueKey())));
        await until(tester, () => find.text(en).evaluate().isNotEmpty,
            'the relay\'s ${guard.name} said');
        expect(find.text(l.hdlStampsChecked), findsOneWidget,
            reason: 'and that this phone still checks every request');
        await tester.pumpWidget(wrap(svc, HandleScreen(key: UniqueKey()),
            locale: const Locale('es')));
        await until(tester, () => find.text(sp).evaluate().isNotEmpty,
            '${guard.name} in Spanish');
        expect(find.text(es.hdlStampsChecked), findsOneWidget);
        expect(sp, isNot(en));
      }
      for (final guard in [HandleRelayGuard.guarded, HandleRelayGuard.unknown]) {
        svc.handles.relayGuard = guard;
        expect(svc.handles.relayUnguarded, isFalse);
        await tester.pumpWidget(wrap(svc, HandleScreen(key: UniqueKey())));
        await until(
            tester,
            () => find.text(l.hdlNotVerification).evaluate().isNotEmpty,
            'the published handle');
        expect(find.text(l.hdlStampsChecked), findsNothing);
        for (final t in [l.hdlRelayUnguarded, l.hdlRelayFull, l.hdlRelayPaced]) {
          expect(find.text(t), findsNothing);
        }
      }
      // Every read-back the screens started is done before the vault
      // closes: the service runs them one at a time, so one more, awaited,
      // comes after them all.
      await svc.handles.refresh();
      await tester.pumpWidget(const SizedBox());
    });
  });

  testWidgets('8. a handle lost because its inbox moved says so', (tester) async {
    await tester.binding.setSurfaceSize(const Size(800, 2000));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.runAsync(() async {
      final svc = await service(config: silent);
      svc.handles.own = published('finn.42')
        ..phase = HandlePhase.lost
        ..problem = 'introUnknown';
      expect(handleRowText(l, svc.handles), l.hdlRowLost('finn.42'));
      await tester.pumpWidget(wrap(svc, const HandleScreen()));
      await until(
          tester,
          () => find.text(l.hdlIntroUnknown('finn.42')).evaluate().isNotEmpty,
          'the moved inbox said');
      expect(find.text(l.hdlLostBody('finn.42')), findsNothing,
          reason: 'nobody used the recovery code');
      expect(find.text(l.hdlRecover), findsOneWidget);
      expect(find.text(l.hdlForget), findsOneWidget);
      // The screen reads the handle back, and the log cannot be reached:
      // the reason it is lost stays. (The service runs read-backs one at a
      // time, so this one, awaited, comes after the screen's.)
      await svc.handles.refresh();
      await tester.pump();
      expect(svc.handles.own!.problem, 'introUnknown');
      expect(svc.handles.own!.phase, HandlePhase.lost);
      expect(find.text(l.hdlIntroUnknown('finn.42')), findsOneWidget);
      await tester.pumpWidget(const SizedBox());
    });
  });

  testWidgets('9. what the phone dropped is said, and a day at its cap',
      (tester) async {
    await tester.binding.setSurfaceSize(const Size(800, 2400));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.runAsync(() async {
      final svc = await service(config: silent);
      svc.handles.own = published('finn.42');
      final today = introPowDay(DateTime.now().millisecondsSinceEpoch);
      Future<void> shown(Locale? locale, String what,
          {required bool Function() ready}) async {
        await tester.pumpWidget(
            wrap(svc, HandleScreen(key: UniqueKey()), locale: locale));
        await until(tester, ready, what);
      }

      // Nothing dropped: no line, no warning.
      await shown(null, 'the published handle',
          ready: () => find.text(l.hdlNotVerification).evaluate().isNotEmpty);
      expect(find.textContaining('In the last five days'), findsNothing);
      expect(find.text(l.hdlInboxSaturated(handleStampDayCap)), findsNothing);

      // Some dropped: the counts, singular and plural.
      svc.handles.stampLedger.tally(today).unstamped = 1;
      svc.handles.stampLedger.tally(today - 1).copies = 12;
      expect(svc.handles.inboxTally.toJson(), [1, 12, 0]);
      await shown(null, 'the counts',
          ready: () => find.text(l.hdlInboxDrops(1, 12)).evaluate().isNotEmpty);
      expect(l.hdlInboxDrops(1, 12), contains('one request'));
      expect(l.hdlInboxDrops(1, 12), contains('12 copies'));
      expect(l.hdlInboxDrops(3, 1), contains('3 requests'));
      expect(l.hdlInboxDrops(3, 1), contains('one copy'));
      expect(find.text(l.hdlInboxSaturated(handleStampDayCap)), findsNothing);
      await shown(const Locale('es'), 'the counts in Spanish',
          ready: () =>
              find.text(es.hdlInboxDrops(1, 12)).evaluate().isNotEmpty);
      expect(es.hdlInboxDrops(1, 12), isNot(l.hdlInboxDrops(1, 12)));
      expect(es.hdlInboxDrops(1, 12), contains('una solicitud'));
      expect(es.hdlInboxDrops(3, 1), contains('una copia'));

      // A day at the ledger's cap: the warning, with the cap.
      final full = HandleStampLedger(perDay: 2);
      full.add(today, 1);
      full.add(today, 2);
      svc.handles.stampLedger = full;
      expect(svc.handles.inboxSaturated, isTrue);
      expect(svc.handles.inboxTally.isEmpty, isTrue);
      await shown(null, 'the cap said',
          ready: () => find
              .text(l.hdlInboxSaturated(handleStampDayCap))
              .evaluate()
              .isNotEmpty);
      expect(l.hdlInboxSaturated(handleStampDayCap), contains('524,288'));
      expect(find.textContaining('In the last five days'), findsNothing,
          reason: 'nothing was dropped');
      await shown(const Locale('es'), 'the cap in Spanish',
          ready: () => find
              .text(es.hdlInboxSaturated(handleStampDayCap))
              .evaluate()
              .isNotEmpty);
      expect(es.hdlInboxSaturated(handleStampDayCap), contains('524.288'));
      await svc.handles.refresh();
      await tester.pumpWidget(const SizedBox());
    });
  });
}
