// 17.9 — what the invite card was missing.
//
// The invite is a bearer token for 24 hours (§20, R23), and the card that
// showed it said "Pending". Not which hour of the 24: the one number a person
// needs in order to decide whether to send it again was the one number the
// screen did not have. It also went on offering the link, the code and the
// Discard button for an invite that had run out — a token that no longer
// works, still sitting there to be copied and sent to somebody.
//
// And the two ways to hand it over were both "it is on the clipboard now",
// which leaves the person to find their messaging app and paste into the
// right conversation themselves. A share sheet is where that belongs, and a
// QR is the rendering for a screen somebody else is looking at.
//
// Three renderings, one secret. That was already the rule for the link and
// the code, and the QR is held to it: it carries the link verbatim, so a
// photograph of the screen is the same token, not a second one.
//
// Criteria, each a test below:
//  1. an invite says how long it has left, and says it has expired rather
//     than counting past zero;
//  2. the QR is the link and nothing but the link;
//  3. Share hands the link to the system, and falls back to the clipboard —
//     saying which happened — where there is no share sheet;
//  4. an invite that has run out offers none of the three renderings and no
//     share, because a token that no longer works should not be circulating.
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/connect_invites.dart';
import 'package:zapp/core/share_text.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/l10n/app_localizations_en.dart';
import 'package:zapp/l10n/remaining_text.dart';
import 'package:zapp/ui/connect_tab.dart';
import 'package:zapp/ui/theme.dart';

typedef Person = ({ChatService svc, Vault vault, ConnectInvites invites});

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  final temps = <Directory>[];
  final live = <Person>[];

  tearDownAll(() async {
    for (final p in live) {
      p.svc.dispose();
      await p.svc.transport.stop();
    }
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
    ShareText.debugHandler = null;
  });

  /// No relay: none of this needs one, and the port is one nothing listens on.
  Future<Person> person(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_cp_');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final id = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(id.toJson()));
    final svc = await ChatService.init(
        vault: vault,
        identity: id,
        displayName: name,
        transport: Transport(identity: id, serverUrl: 'ws://127.0.0.1:1'));
    final p = (svc: svc, vault: vault, invites: ConnectInvites(svc));
    live.add(p);
    return p;
  }

  Widget tabWith(Person p, ConnectInvites inv) => MultiProvider(
        providers: [
          ChangeNotifierProvider<ChatService>.value(value: p.svc),
          ChangeNotifierProvider<ConnectInvites>.value(value: inv),
        ],
        child: MaterialApp(
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          theme: ZTheme.dark(),
          home: const Scaffold(body: ConnectTab()),
        ),
      );

  Widget tab(Person p) => tabWith(p, p.invites);

  /// Put the clock back on the STORED invite and load it again, which is the
  /// app being opened the next day without a day passing in the test.
  Future<ConnectInvites> reopenAged(Person p, Duration by) async {
    final raw = await p.vault.kvGet('connect_invites');
    final list = (jsonDecode(raw!) as List).cast<Map<String, Object?>>();
    for (final e in list) {
      e['created'] = (e['created'] as num).toInt() - by.inMilliseconds;
    }
    await p.vault.kvPut('connect_invites', jsonEncode(list));
    final fresh = ConnectInvites(p.svc);
    await fresh.load();
    return fresh;
  }

  /// Rebuild until [cond] holds, letting real work happen in between: a
  /// widget test's clock is fake and never advances a database or a key
  /// generation on its own, and making an invite does both. The condition is
  /// checked against the WIDGET TREE, never the model behind it.
  Future<void> settleUntil(WidgetTester t, bool Function() cond,
      {Duration timeout = const Duration(seconds: 30)}) async {
    final deadline = DateTime.now().add(timeout);
    await t.pump(const Duration(milliseconds: 50));
    while (!cond() && DateTime.now().isBefore(deadline)) {
      await t.runAsync(
          () => Future<void>.delayed(const Duration(milliseconds: 100)));
      await t.pump(const Duration(milliseconds: 50));
    }
    await t.pump(const Duration(milliseconds: 350));
  }

  /// The tab starts a relay poll behind every action; let it finish so no
  /// test ends with work in flight.
  Future<void> drain(WidgetTester t) async {
    await t.runAsync(() => Future<void>.delayed(const Duration(seconds: 1)));
    await t.pump(const Duration(seconds: 20));
    await t.pump(const Duration(seconds: 20));
  }

  /// An invite made through the screen, as a person makes one.
  Future<PendingInvite> createThroughUi(WidgetTester t, Person p) async {
    await t.pumpWidget(tab(p));
    await t.pumpAndSettle();
    await t.tap(find.text(AppLocalizationsEn().connectCreate));
    await settleUntil(t, () => find.byType(InviteQr).evaluate().isNotEmpty);
    return p.invites.invites.single;
  }

  testWidgets('1. an invite says how long it has left', (t) async {
    final l = AppLocalizationsEn();
    // The pure part first, because the card only renders what this decides.
    expect(remainingText(l, const Duration(hours: 23, minutes: 59)),
        '23 hours left',
        reason: 'rounded down: it never promises more time than it has');
    expect(remainingText(l, const Duration(hours: 1)), '1 hour left');
    expect(remainingText(l, const Duration(minutes: 59)), '59 minutes left');
    expect(remainingText(l, const Duration(minutes: 1)), '1 minute left');
    expect(remainingText(l, const Duration(seconds: 30)), l.connectExpiresSoon,
        reason: 'the last minute says so in words; a 0 that sits there reads '
            'as a bug');
    expect(remainingText(l, Duration.zero), l.connectExpired);
    expect(remainingText(l, const Duration(hours: -3)), l.connectExpired,
        reason: 'and it never counts past zero');

    late Person alice;
    await t.runAsync(() async => alice = await person('Alice'));
    await createThroughUi(t, alice);
    expect(find.text('23 hours left'), findsOneWidget,
        reason: 'a fresh invite has 23-and-a-bit hours of its 24');
    await drain(t);
  });

  testWidgets('2. the QR is the link and nothing but the link', (t) async {
    late Person alice;
    await t.runAsync(() async => alice = await person('Alice'));
    final invite = await createThroughUi(t, alice);

    final qr = t.widget<InviteQr>(find.byType(InviteQr));
    expect(qr.link, invite.link);
    expect(qr.link, isNot(invite.code),
        reason: 'the QR carries the link rendering, as the label says');
    // One secret in three renderings, not three secrets: the link IS the
    // printed code with its groups run together.
    expect(invite.link, endsWith(invite.code.replaceAll('-', '')));
    expect(ConnectCode.fromLink(qr.link)!.text, invite.code,
        reason: 'and scanning it yields the same code, not another invite');
    expect(find.text(AppLocalizationsEn().connectQrLabel), findsOneWidget);
    await drain(t);
  });

  testWidgets('3. Share hands over the link, or says it could not', (t) async {
    late Person alice;
    await t.runAsync(() async => alice = await person('Alice'));
    final invite = await createThroughUi(t, alice);
    final l = AppLocalizationsEn();

    String? shared;
    ShareText.debugHandler = (text) async {
      shared = text;
      return true;
    };
    // The card is a tall one now — status, time left, both renderings, the
    // QR — so the button has to be brought into view before it can be
    // tapped. A tap that lands on nothing warns and carries on, which is a
    // test that passes for the wrong reason waiting to happen.
    await t.ensureVisible(find.text(l.connectShareSheet));
    await t.pump();
    await t.tap(find.text(l.connectShareSheet));
    await t.pump(const Duration(milliseconds: 50));
    expect(shared, invite.link, reason: 'the link, and nothing else');
    expect(find.text(l.connectSharedToClipboard), findsNothing,
        reason: 'no fallback message when the share sheet took it');

    // A platform with no share sheet: the clipboard, and a message saying so.
    // The channel is watched rather than read back, because what matters is
    // that the app asked the SYSTEM to hold the link — a test-binding
    // clipboard that answers `getData` would prove only that the test
    // remembered it.
    String? copied;
    final messenger = t.binding.defaultBinaryMessenger;
    messenger.setMockMethodCallHandler(SystemChannels.platform, (call) async {
      if (call.method == 'Clipboard.setData') {
        copied = (call.arguments as Map)['text'] as String?;
      }
      return null;
    });
    ShareText.debugHandler = (text) async => false;
    await t.ensureVisible(find.text(l.connectShareSheet));
    await t.pump();
    await t.tap(find.text(l.connectShareSheet));
    await t.pump(const Duration(milliseconds: 50));
    expect(find.text(l.connectSharedToClipboard), findsOneWidget,
        reason: 'a button that sometimes does nothing is worse than none');
    expect(copied, invite.link);
    ShareText.debugHandler = null;
    messenger.setMockMethodCallHandler(SystemChannels.platform, null);
    await drain(t);
  });

  testWidgets('4. an invite that has run out offers nothing to send',
      (t) async {
    late Person alice;
    await t.runAsync(() async => alice = await person('Alice'));
    final invite = await createThroughUi(t, alice);
    final l = AppLocalizationsEn();
    expect(find.byType(InviteQr), findsOneWidget);
    expect(find.text(l.connectShareSheet), findsOneWidget);

    late ConnectInvites aged;
    await t.runAsync(
        () async => aged = await reopenAged(alice, const Duration(hours: 25)));
    await t.pumpWidget(tabWith(alice, aged));
    await t.pump(const Duration(milliseconds: 50));

    expect(find.text(l.connectExpired), findsOneWidget,
        reason: 'the clock decides this, not the last thing the relay said');
    expect(find.byType(InviteQr), findsNothing);
    expect(find.text(l.connectShareSheet), findsNothing);
    expect(find.text(l.connectShareLink), findsNothing);
    expect(find.text(l.connectShareCode), findsNothing);
    expect(find.text(invite.code), findsNothing,
        reason: 'a token that no longer works is not left on screen to copy');
    expect(find.text(l.connectDiscard), findsOneWidget,
        reason: 'but it can still be cleared away');
    await drain(t);
  });
}
