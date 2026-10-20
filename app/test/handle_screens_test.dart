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
//      its cap is said as a warning with the cap; in Spanish too;
//  10. Settings says whether the handle service is checked against its
//      witness (2026-10-19), outside developer mode once a witness is set,
//      each state in English and in Spanish: no answer yet; agreed, with
//      when, in the agreeing tone; gone quiet, with since when, in the
//      warning tone; a history the witness did not see, with when, in the
//      danger tone and before anything else; and with no witness, no row —
//      but in developer mode a row saying it is off, beside the row that
//      edits the pair;
//  11. in developer mode the witness's address and key are edited in one
//      dialog and saved together: an address alone, or a key that is not
//      one, is refused there with its reason and nothing is saved; both are
//      saved, sealed, and the row asks for an answer; and the log's address
//      edited afterwards keeps the witness beside it;
//  12. a claim the handle service refused as taken, whose read-back its
//      witness then contradicted, says that — not that someone else holds
//      the handle, nor the words for a claim a restore brought back — and
//      offers to publish it again or cancel it, in Spanish too.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/app_lock.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/handles.dart';
import 'package:zapp/core/prefs.dart';
import 'package:zapp/core/push_service.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/l10n/app_localizations_en.dart';
import 'package:zapp/l10n/app_localizations_es.dart';
import 'package:zapp/l10n/handle_text.dart';
import 'package:zapp/l10n/when_text.dart';
import 'package:zapp/ui/find_handle_screen.dart';
import 'package:zapp/ui/handle_screen.dart';
import 'package:zapp/ui/requests_screen.dart';
import 'package:zapp/ui/settings_screen.dart';
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

  /// Settings over [svc], with the providers the screen reads (its preferences
  /// and lock under [dir]), pumped until [ready].
  Future<void> settingsOf(
      WidgetTester tester, ChatService svc, Directory dir, String what,
      {Locale? locale, required bool Function() ready}) async {
    final prefs = AppPrefs(root: dir);
    await prefs.load();
    await tester.pumpWidget(MultiProvider(
      providers: [
        ChangeNotifierProvider<ChatService>.value(value: svc),
        ChangeNotifierProvider<Transport>.value(value: svc.transport),
        ChangeNotifierProvider<PushService>.value(
            value: PushService(transport: svc.transport, vault: svc.vault)),
        ChangeNotifierProvider<AppLock>.value(
            value: AppLock(root: dir, store: MemorySecretStore())),
        ChangeNotifierProvider<AppPrefs>.value(value: prefs),
      ],
      child: MaterialApp(
        debugShowCheckedModeBanner: false,
        theme: ZTheme.light(),
        locale: locale,
        localizationsDelegates: AppLocalizations.localizationsDelegates,
        supportedLocales: AppLocalizations.supportedLocales,
        home: SettingsScreen(key: UniqueKey()),
      ),
    ));
    await until(tester, ready, what);
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

  testWidgets('10. Settings says whether the handle service is checked against '
      'its witness — no answer yet, agreed, quiet, a history the witness did '
      'not see, and off — in English and in Spanish', (tester) async {
    await tester.binding.setSurfaceSize(const Size(800, 3000));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.runAsync(() async {
      // A witness on loopback that nothing answers: the states are set here,
      // as a lookup would leave them (handle_lookup_test.dart drives them).
      final witnessed = HandleConfig(
          logUrl: silent.logUrl,
          logPubB64: silent.logPubB64,
          witnessUrl: 'http://127.0.0.1:1/sth.json',
          witnessPubB64: b64(Uint8List(32)..fillRange(0, 32, 7)));
      final svc = await service(config: witnessed);
      final dir = dirs.last;

      Icon iconOf(String title) => tester.widget<Icon>(find.descendant(
          of: find.widgetWithText(ListTile, title), matching: find.byType(Icon)));

      // The row, in English and then in Spanish: [text] is what it says in
      // [words], with the screen's context for any date in it, and [tone]
      // the colour of its icon in both.
      Future<void> says(String what,
          String Function(AppLocalizations words, BuildContext ctx) text,
          {required Color Function(BuildContext ctx) tone}) async {
        for (final (words, locale) in <(AppLocalizations, Locale?)>[
          (l, null),
          (es, const Locale('es')),
        ]) {
          await settingsOf(tester, svc, dir, '$what (${words.localeName})',
              locale: locale,
              ready: () => find
                  .text(text(words, tester.element(find.byType(SettingsScreen))))
                  .evaluate()
                  .isNotEmpty);
          final ctx = tester.element(find.byType(SettingsScreen));
          expect(find.text(words.stHdlWitness), findsOneWidget, reason: what);
          expect(iconOf(words.stHdlWitness).color, tone(ctx),
              reason: '$what, its tone (${words.localeName})');
        }
      }

      expect(svc.devMode, isFalse, reason: 'the row is everyone’s');
      expect(svc.handles.witnessState, HandleWitnessState.pending);
      await says('no answer yet', (w, _) => w.stHdlWitnessPending,
          tone: (c) => c.z.textSecondary);
      expect(find.text(es.stHdlWitnessPin), findsNothing,
          reason: 'the pair is edited in developer mode only');

      // Agreed five minutes ago, in the agreeing tone.
      final now = DateTime.now().millisecondsSinceEpoch;
      svc.handles.witnessOkMs = now - const Duration(minutes: 5).inMilliseconds;
      expect(svc.handles.witnessState, HandleWitnessState.agreed);
      await says('agreed, with when',
          (w, c) => w.stHdlWitnessAgreed(whenText(c, svc.handles.witnessOkMs!)),
          tone: (c) => c.z.ok);

      // Lookups have asked for two days since without an answer: quiet since
      // the last agreement, in the warning tone.
      svc.handles.witnessOkMs = now - const Duration(days: 3).inMilliseconds;
      svc.handles.witnessSinceMs = now - const Duration(days: 2).inMilliseconds;
      svc.handles.witnessLastAskMs = now;
      expect(svc.handles.witnessState, HandleWitnessState.quiet);
      await says('quiet, with since when',
          (w, c) => w.stHdlWitnessQuiet(whenText(c, svc.handles.witnessOkMs!)),
          tone: (c) => c.z.warn);

      // A lookup refused a minute ago because the witness's record
      // contradicted the log: said before anything else, in the danger tone,
      // until the witness agrees again.
      svc.handles.witnessForkMs = now - const Duration(minutes: 1).inMilliseconds;
      expect(svc.handles.witnessState, HandleWitnessState.forked);
      await says('a history its witness did not see, with when',
          (w, c) => w.stHdlWitnessForked(whenText(c, svc.handles.witnessForkMs!)),
          tone: (c) => c.z.danger);
      svc.handles.witnessForkMs = null;

      // No witness: no row for everyone; in developer mode, off, beside the
      // row that edits the pair.
      svc.handles.config =
          HandleConfig(logUrl: silent.logUrl, logPubB64: silent.logPubB64);
      expect(svc.handles.witnessState, HandleWitnessState.none);
      await settingsOf(tester, svc, dir, 'no witness',
          ready: () => find.text(l.hdlYourHandle).evaluate().isNotEmpty);
      expect(find.text(l.stHdlWitness), findsNothing);
      svc.devMode = true;
      await says('off, in developer mode', (w, _) => w.stHdlWitnessOff,
          tone: (c) => c.z.textSecondary);
      expect(find.text(es.stHdlWitnessPin), findsOneWidget);

      // Each of them Spanish, not English copied.
      for (final (en, sp) in [
        (l.stHdlWitness, es.stHdlWitness),
        (l.stHdlWitnessPending, es.stHdlWitnessPending),
        (l.stHdlWitnessAgreed('x'), es.stHdlWitnessAgreed('x')),
        (l.stHdlWitnessQuiet('x'), es.stHdlWitnessQuiet('x')),
        (l.stHdlWitnessForked('x'), es.stHdlWitnessForked('x')),
        (l.stHdlWitnessOff, es.stHdlWitnessOff),
      ]) {
        expect(sp, isNot(en));
      }
      await tester.pumpWidget(const SizedBox());
    });
  });

  testWidgets('11. in developer mode the witness is edited as a pair: half of '
      'one refused in the dialog, both saved together, and kept when the log '
      'is edited', (tester) async {
    await tester.binding.setSurfaceSize(const Size(800, 3000));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.runAsync(() async {
      final svc = await service(config: silent);
      final dir = dirs.last;
      svc.devMode = true;
      await settingsOf(tester, svc, dir, 'the developer rows',
          ready: () => find.text(l.stHdlWitnessPin).evaluate().isNotEmpty);
      expect(find.text(l.stHdlWitnessOff), findsOneWidget);

      final dialog = find.byType(AlertDialog);
      Finder inDialog(Finder f) => find.descendant(of: dialog, matching: f);
      final urlField = inDialog(find.widgetWithText(TextField, l.stKtWitnessTitle));
      final keyField = inDialog(find.widgetWithText(TextField, l.stKtWitnessKeyTitle));
      final save = inDialog(find.text(l.stKtSave));
      const url = 'http://127.0.0.1:1/sth.json';
      final key = b64(Uint8List(32)..fillRange(0, 32, 5));

      await tester.tap(find.text(l.stHdlWitnessPin));
      await until(tester, () => dialog.evaluate().isNotEmpty, 'the pair\'s dialog');
      // An address alone: refused there, with the reason, and the dialog
      // stays open with what was typed.
      await tester.enterText(urlField, url);
      await tester.tap(save);
      await until(tester, () => inDialog(find.text(l.stKtWitnessNeedsKey)).evaluate().isNotEmpty,
          'an address without its key refused');
      expect(svc.handles.config.witnessUrl, isEmpty, reason: 'nothing saved');
      // A key that is not one: likewise.
      await tester.enterText(keyField, 'not a key');
      await tester.tap(save);
      await until(tester, () => inDialog(find.text(l.stKtWitnessBadKey)).evaluate().isNotEmpty,
          'a key that is not 32 bytes refused');
      expect(svc.handles.config.hasWitness, isFalse);
      expect(await svc.vault.kvGet('handle_config'), isNull, reason: 'nor stored');

      // Both: saved together, sealed, and the row asks for an answer.
      await tester.enterText(keyField, key);
      await tester.tap(save);
      await until(tester, () => dialog.evaluate().isEmpty, 'the dialog closed on saving');
      expect(svc.handles.config.witnessUrl, url);
      expect(svc.handles.config.witnessPubB64, key);
      expect(svc.handles.config.logUrl, silent.logUrl, reason: 'the log as it was');
      await until(tester, () => find.text(l.stHdlWitnessPending).evaluate().isNotEmpty,
          'no answer yet');
      final rows = await svc.vault.db.query('kv',
          columns: ['k'], where: 'k LIKE ?', whereArgs: ['%:handle_config']);
      expect(rows.map((r) => r['k']), ['s:handle_config'], reason: 'sealed');
      Future<HandleConfig> stored() async => HandleConfig.fromJson(
          (jsonDecode((await svc.vault.kvGet('handle_config'))!) as Map)
              .cast<String, Object?>());
      expect((await stored()).witnessUrl, url, reason: 'read back as saved');
      expect((await stored()).witnessPubB64, key);

      // The log's address edited after: the witness stays beside it.
      await tester.tap(find.text(l.stHdlLogAddress));
      await until(tester, () => dialog.evaluate().isNotEmpty, 'the address dialog');
      await tester.enterText(inDialog(find.byType(TextField)), 'http://127.0.0.1:2');
      await tester.tap(save);
      await untilAsync(
          tester,
          () async => ((await svc.vault.kvGet('handle_config')) ?? '')
              .contains('"url":"http://127.0.0.1:2"'),
          'the new address stored');
      expect(svc.handles.config.logUrl, 'http://127.0.0.1:2');
      expect(svc.handles.config.witnessUrl, url);
      expect(svc.handles.config.witnessPubB64, key);
      expect(svc.handles.config.hasWitness, isTrue);
      expect((await stored()).hasWitness, isTrue, reason: 'and stored so');
      await tester.pumpWidget(const SizedBox());
    });
  });

  testWidgets('12. a claim held because the witness contradicted its read-back '
      'says so, and offers to publish it again or cancel it', (tester) async {
    await tester.binding.setSurfaceSize(const Size(800, 2000));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.runAsync(() async {
      final svc = await service(config: silent);
      // As handle_lookup_test 28 leaves it: the log answered the claim's
      // publish "taken", and the head it read the handle back under was one
      // the witness's record contradicted.
      svc.handles.own = published('finn.42')
        ..phase = HandlePhase.held
        ..problem = HandleFailure.forked.name;
      for (final (words, locale) in <(AppLocalizations, Locale?)>[
        (l, null),
        (es, const Locale('es')),
      ]) {
        await tester.pumpWidget(wrap(svc, const HandleScreen(), locale: locale));
        await until(
            tester,
            () => find.text(words.hdlClaimForked('finn.42')).evaluate().isNotEmpty,
            'the fork said (${words.localeName})');
        expect(find.text(words.hdlTakenBody('finn.42')), findsNothing,
            reason: 'not someone else\'s');
        expect(find.text(words.hdlHeldBody), findsNothing,
            reason: 'not a claim a restore brought back');
        expect(find.text(words.hdlErrForked), findsNothing,
            reason: 'the claim was published: not "nothing was sent"');
        expect(find.text(words.hdlPublishNow), findsOneWidget);
        expect(find.text(words.hdlCancelClaim), findsOneWidget);
      }
      expect(es.hdlClaimForked('x'), isNot(l.hdlClaimForked('x')));
      await tester.pumpWidget(const SizedBox());
    });
  });
}
