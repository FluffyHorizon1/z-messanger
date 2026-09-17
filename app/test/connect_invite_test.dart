// 17.3 — the CONNECT tab: adding somebody you cannot stand next to.
//
// The other three tabs hand a code across a gap the user has already decided
// to trust: a QR between two screens, or a paste over a channel they picked.
// This one assumes the opposite. The invite travels over whatever the two
// people have — WhatsApp, SMS, a work chat — and the design answers that with
// three things: the invite is one-time, it is short-lived, and it ends in
// eight digits the two people compare out loud. Until those digits are
// compared, "somebody answered the invite" is all anyone knows.
//
// So most of what is tested here is about what the app says and what it
// refuses to do, not about cryptography — that is `protocol/`'s, and 17.1 and
// 17.2 have it.
//
// Criteria, each a test below:
//  1. generating an invite shows both renderings, and they are ONE secret —
//     a link and a code that can drift apart is a bug reported as "the code
//     doesn't work";
//  2. opening a https://www.zmessengers.com/i#… link routes into the ceremony,
//     and the fragment never leaves the device: no network is touched to
//     consume it, and no request is ever made to that host;
//  3. a pending invite survives the app being killed and still completes —
//     an invite sent at lunchtime may be opened at midnight;
//  4. confirming the digits marks the contact verified, and adding without
//     comparing lands it unverified AND says so on screen;
//  5. a mismatch offers only "stop": no path from a failed comparison ends
//     with a contact, and the invite is spent so it cannot be retried into
//     the same attacker;
//  6. every new string is in both ARBs, with a description that names the
//     load-bearing clause;
//  7. the ceremony carries itself: with the app in front, neither person
//     presses anything and both reach the digits — until 2026-09-17 the only
//     thing that ran a round was the tab opening or "Check now", so two
//     people had to press it alternately, in the right order, four times;
//  8. two rounds asked for at once are one round: a second pump joins the
//     one in flight, because two steps on one run can pick two ephemerals,
//     the relay keeps one and the run the other, and the invite is spent on
//     a mismatch nobody produced;
//  9. a relay that cannot be reached is said so on the card, and the invite
//     is kept for the next try rather than read as "waiting for them".
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/models.dart';
import 'package:zapp/core/connect_invites.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/ui/connect_tab.dart';
import 'package:zapp/ui/theme.dart';

typedef Person = ({ChatService svc, Vault vault, ConnectInvites invites});

/// An `HttpOverrides` that lets nothing construct an HTTP client and counts the
/// attempts. Opening an invite parses a fragment the browser never sent to a
/// server; the point of criterion 2 is that consuming it touches no network at
/// all, so under this override the open must complete having created zero
/// clients. If a future edit adds an `HttpClient().getUrl(...)` to
/// `ConnectInvites.open` — leaking the fragment (the whole bearer secret) to
/// the landing host — the construction throws here and the test fails, where
/// before nothing watched (the 2026-09-14 review's finding 37).
class _NoNetwork extends HttpOverrides {
  int created = 0;
  @override
  HttpClient createHttpClient(SecurityContext? context) {
    created++;
    throw const SocketException('consuming an invite must touch no network');
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  // The widget binding replaces HttpClient with one that answers 400 to
  // everything, which would fail the relay's health probe below.
  HttpOverrides.global = null;

  late Process relay;
  late int port;
  final temps = <Directory>[];
  final live = <Person>[];

  setUpAll(() async {
    HttpOverrides.global = null;
    final serverDir =
        '${Directory.current.parent.path}${Platform.pathSeparator}server';
    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    port = probe.port;
    await probe.close();
    relay = await Process.start('node', ['server.js'],
        workingDirectory: serverDir,
        environment: {'PORT': '$port', 'LOG_LEVEL': 'silent'});
    for (var i = 0; i < 60; i++) {
      try {
        final res = await (await HttpClient()
                .getUrl(Uri.parse('http://127.0.0.1:$port/health')))
            .close();
        await res.drain<void>();
        if (res.statusCode == 200) return;
      } catch (_) {
        await Future<void>.delayed(const Duration(milliseconds: 100));
      }
    }
    fail('relay did not start');
  });

  tearDownAll(() async {
    for (final p in live) {
      p.invites.pause();
      await p.svc.transport.stop();
      await p.vault.db.close();
    }
    relay.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<Person> open(Directory dir, ZIdentity id, String name,
      {String? url, Duration? pollEvery}) async {
    final vault = await Vault.open(rootOverride: dir);
    await vault.kvPut('identity', jsonEncode(id.toJson()));
    final transport =
        Transport(identity: id, serverUrl: url ?? 'ws://127.0.0.1:$port');
    final svc = await ChatService.init(
        vault: vault, identity: id, displayName: name, transport: transport);
    final person = (
      svc: svc,
      vault: vault,
      invites: ConnectInvites(svc,
          pollEvery: pollEvery ?? ConnectInvites.defaultPollEvery)
    );
    live.add(person);
    return person;
  }

  Future<Person> person(String name, {String? url, Duration? pollEvery}) async {
    final dir = await Directory.systemTemp.createTemp('z_ci_');
    temps.add(dir);
    return open(dir, await ZIdentity.generate(), name,
        url: url, pollEvery: pollEvery);
  }

  /// The app being killed and relaunched: nothing in memory survives.
  Future<Person> restart(Person p, Directory dir, ZIdentity id, String name) async {
    await p.svc.transport.stop();
    p.svc.dispose();
    await p.vault.db.close();
    live.remove(p);
    return open(dir, id, name);
  }

  /// Step both sides until the ceremony is done or we give up.
  Future<void> danceTo(Person a, Person b, {int rounds = 6}) async {
    for (var i = 0; i < rounds; i++) {
      await a.invites.pump();
      await b.invites.pump();
      final done = a.invites.invites.any((x) => x.sas != null) &&
          b.invites.invites.any((x) => x.sas != null);
      if (done) return;
    }
  }

  /// The tab, wired to a person, with no relay to reach. Everything below
  /// that is about what is on screen mounts through this.
  Widget tab(Person p, Widget child) => MultiProvider(
        providers: [
          ChangeNotifierProvider<ChatService>.value(value: p.svc),
          ChangeNotifierProvider<ConnectInvites>.value(value: p.invites),
        ],
        child: MaterialApp(
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          theme: ZTheme.dark(),
          home: Scaffold(body: child),
        ),
      );

  /// Rebuild until [cond] holds, letting real work happen in between: a
  /// widget test's clock is fake and never advances a socket, a database or
  /// a key generation on its own, and the ARB-backed screens here do all
  /// three behind a single tap.
  /// The condition is checked against the WIDGET TREE, never against the
  /// model behind it: a model that has changed and a screen that has not is
  /// exactly the bug these tests exist to catch, and waiting on the model
  /// would hide it. `pumpAndSettle` is deliberately not used at the end —
  /// it advances the fake clock until nothing is scheduled, which runs a
  /// SnackBar's four seconds out and dismisses the message being asserted.
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

  /// The tab starts a relay poll behind every action. Let it finish — in real
  /// time if the socket is going to be refused, and on the fake clock if its
  /// connect timeout has to fire — so no test ends with work in flight.
  Future<void> drain(WidgetTester t) async {
    await t.runAsync(() => Future<void>.delayed(const Duration(seconds: 1)));
    await t.pump(const Duration(seconds: 20));
    await t.pump(const Duration(seconds: 20));
  }

  testWidgets('1. an invite has two renderings and one secret', (t) async {
    // No relay for this one: making an invite and rendering it is local work,
    // and nothing here should need a network to happen.
    late Person alice;
    await t.runAsync(
        () async => alice = await person('Alice', url: 'ws://127.0.0.1:1'));

    await t.pumpWidget(tab(alice, const ConnectTab()));
    await t.pumpAndSettle();
    expect(find.text('Create an invite'), findsOneWidget);
    expect(find.textContaining('Works once'), findsOneWidget,
        reason: 'the two limits are on screen before an invite is made');
    expect(find.text('No invites waiting.'), findsOneWidget);

    await t.tap(find.text('Create an invite'));
    await settleUntil(
        t, () => find.byType(SelectableText).evaluate().isNotEmpty);

    final invite = alice.invites.invites.single;
    // BOTH renderings are shown, and the screen says they are one invite.
    expect(
        find.byWidgetPredicate(
            (w) => w is SelectableText && w.data == invite.link),
        findsOneWidget,
        reason: 'the link is on screen');
    expect(
        find.byWidgetPredicate(
            (w) => w is SelectableText && w.data == invite.code),
        findsOneWidget,
        reason: 'and so is the code');
    expect(find.textContaining('the same invite'), findsOneWidget);

    // A link and a printed code, computed from the same ten bytes.
    expect(invite.link, startsWith('https://www.zmessengers.com/i#'));
    expect(invite.code, matches(RegExp(r'^[A-Z2-7-]{16,}$')));
    final fromLink = ConnectCode.fromLink(invite.link);
    final fromCode = ConnectCode.parse(invite.code);
    expect(fromLink, isNotNull);
    expect(b64(fromLink!.secret), b64(invite.run.code.secret));
    expect(b64(fromCode.secret), b64(invite.run.code.secret),
        reason: 'the two renderings are one invite, not two');

    // And the app accepts either of them back.
    for (final rendering in [invite.link, invite.code]) {
      final parsed = ConnectInvites.parseInvite(rendering);
      expect(parsed, isNotNull);
      expect(b64(parsed!.secret), b64(invite.run.code.secret));
    }
    expect(ConnectInvites.parseInvite('not an invite'), isNull);
    await drain(t);
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('2. an invite link is consumed entirely on the device', () async {
    // A service whose relay is a port nothing is listening on. If opening a
    // link needed the network — to resolve the URL, to fetch the page, to ask
    // anything of zmessengers.com — this could not work at all.
    final offline = await person('Offline', url: 'ws://127.0.0.1:1');
    final maker = await person('Maker');
    final invite = await maker.invites.create();

    // Consume the link with all network construction forbidden and counted, so
    // "no network is touched to consume it" is asserted, not merely asserted in
    // prose. `open` makes no request, so nothing is constructed.
    final net = _NoNetwork();
    final previous = HttpOverrides.current;
    HttpOverrides.global = net;
    final PendingInvite opened;
    try {
      opened = await offline.invites.open(invite.link);
    } finally {
      HttpOverrides.global = previous;
    }
    expect(net.created, 0,
        reason: 'consuming the invite constructed no HTTP client — the '
            'fragment never left the device');
    expect(b64(opened.run.code.secret), b64(invite.run.code.secret),
        reason: 'the code in the fragment is what the ceremony runs on');
    expect(opened.mine, isFalse);
    expect(offline.invites.invites, contains(opened));

    // Nothing about the invite is addressed to the host in the link: the only
    // endpoint this ceremony will ever contact is the relay the app is
    // configured for.
    expect(offline.svc.transport.serverUrl, 'ws://127.0.0.1:1');
    expect(invite.link.contains(ConnectCode.parse(invite.code).text), isFalse,
        reason: 'the link carries the raw secret, not the printed rendering');

    // A pump against the dead relay changes nothing and throws nothing: an
    // unreachable relay is not a fact about the invite.
    await offline.invites.pump();
    expect(offline.invites.invites.length, 1);
    expect(opened.sas, isNull);

    // The same invite cannot be opened twice on one device.
    await expectLater(
        offline.invites.open(invite.link), throwsA(isA<FormatException>()));
  });

  test('3. a pending invite survives the app being killed, and completes',
      () async {
    final dir = await Directory.systemTemp.createTemp('z_ci_restart_');
    temps.add(dir);
    final id = await ZIdentity.generate();
    var alice = await open(dir, id, 'Alice');
    final bob = await person('Bob');

    // Alice makes an invite over lunch and posts it.
    final invite = await alice.invites.create();
    final link = invite.link;
    await alice.invites.pump();

    // Her phone is killed. Everything in memory is gone.
    alice = await restart(alice, dir, id, 'Alice');
    await alice.invites.load();
    expect(alice.invites.invites, hasLength(1),
        reason: 'the invite was read back out of the vault');
    expect(alice.invites.invites.single.link, link,
        reason: 'and it is the same invite, not a new one');

    // Midnight. Bob opens the link and the ceremony finishes without Alice
    // touching anything — she was not even running when he started.
    await bob.invites.open(link);
    await danceTo(alice, bob);

    final aliceSide = alice.invites.invites.single;
    final bobSide = bob.invites.invites.single;
    expect(aliceSide.sas, isNotNull);
    expect(bobSide.sas, aliceSide.sas, reason: 'both screens show the same digits');
    expect(aliceSide.sas, matches(RegExp(r'^\d{4} \d{4}$')));
    expect(aliceSide.peer?.displayName, 'Bob');
    expect(bobSide.peer?.displayName, 'Alice');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('4. confirming marks the contact verified; not comparing says so',
      () async {
    final alice = await person('Alice');
    final bob = await person('Bob');
    final invite = await alice.invites.create();
    await bob.invites.open(invite.link);
    await danceTo(alice, bob);
    expect(alice.invites.invites.single.sas, isNotNull);

    // Alice read the digits and they matched.
    final added = await alice.invites.confirm(alice.invites.invites.single);
    expect(added.name, 'Bob');
    final contact = alice.svc.contacts[added.rid]!;
    expect(contact.verified, isTrue);
    expect(contact.verifiedSn, isNotNull,
        reason: 'a tick must never stand without the number behind it (13.3)');
    expect(contact.verifiedSn, await alice.svc.safetyNumberWith(added.rid),
        reason: 'and it is the number this pair actually has, so every reader '
            'of verified_sn treats a connect-verified contact like a scanned one');
    expect(alice.svc.verificationWith(added.rid), VerificationState.verified);
    // The invite is spent and gone from the list either way.
    expect(alice.invites.invites, isEmpty);

    // Bob did not compare anything: he added Alice and the app says the
    // contact is unverified rather than implying the ceremony verified it.
    final bobAdded = await bob.invites.defer(bob.invites.invites.single);
    final bobContact = bob.svc.contacts[bobAdded.rid]!;
    expect(bobContact.verified, isFalse);
    expect(bobContact.verifiedSn, isNull);
    expect(bob.svc.verificationWith(bobAdded.rid), VerificationState.unverified);
    expect(bob.invites.invites, isEmpty);
  }, timeout: const Timeout(Duration(minutes: 3)));

  testWidgets('5. a mismatch offers only stop, and adds nothing', (t) async {
    late Person alice;
    late PendingInvite ready;
    // The ceremony is real sockets and real timers, and a widget test's fake
    // clock never advances them: it runs outside the fake zone.
    await t.runAsync(() async {
      alice = await person('Alice');
      final bob = await person('Bob');
      final invite = await alice.invites.create();
      await bob.invites.open(invite.link);
      await danceTo(alice, bob);
      ready = alice.invites.invites.single;
    });
    expect(ready.sas, isNotNull);

    await t.pumpWidget(tab(alice, ConnectConfirmPanel(invite: ready)));
    await t.pumpAndSettle();

    // The digits are on screen, and so is the warning about what a mismatch
    // means — before the user has to decide anything.
    expect(find.text(ready.sas!), findsOneWidget);
    expect(find.textContaining('someone is relaying between you'), findsOneWidget);
    expect(find.textContaining('Do not try the same invite again'), findsOneWidget);

    // Exactly three ways out, and only one of them is a mismatch.
    expect(find.text('They match'), findsOneWidget);
    expect(find.text('We have not compared yet'), findsOneWidget);
    expect(find.text('They do not match'), findsOneWidget);
    // Criterion 4's on-screen half: what "not yet" costs is stated before the
    // user picks it, not discovered afterwards.
    expect(find.textContaining('this contact is unverified'), findsOneWidget);

    await t.tap(find.text('They do not match'));
    await settleUntil(
        t, () => find.textContaining('Nothing was added').evaluate().isNotEmpty);

    // Nothing was added, and there is no second chance on this invite: a
    // retry would meet whoever produced the mismatch.
    expect(alice.svc.contacts, isEmpty);
    expect(alice.invites.invites, isEmpty);
    expect(find.text('They match'), findsNothing,
        reason: 'the panel is gone; there is no path back to adding');
    expect(find.textContaining('Nothing was added'), findsOneWidget);
    await drain(t);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('7. the ceremony carries itself: nobody presses anything', () async {
    // Both apps are in front, and neither person touches the tab again after
    // the first tap. Fast poll so the test is not a minute of waiting.
    const fast = Duration(milliseconds: 400);
    final alice = await person('Alice', pollEvery: fast);
    final bob = await person('Bob', pollEvery: fast);
    alice.invites.resume();
    bob.invites.resume();

    final invite = await alice.invites.create();
    await bob.invites.open(invite.link);

    // No pump() from here on. The two polls carry it: x1, x2, x3, x4. Five
    // rounds of a second and a half each on a quiet machine; the budget is
    // for the loaded CI runner, not for this one.
    final deadline = DateTime.now().add(const Duration(seconds: 120));
    while (DateTime.now().isBefore(deadline) &&
        !(alice.invites.invites.any((i) => i.sas != null) &&
            bob.invites.invites.any((i) => i.sas != null))) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    alice.invites.pause();
    bob.invites.pause();

    final a = alice.invites.invites.single, b = bob.invites.invites.single;
    expect(a.sas, isNotNull, reason: 'the inviter reached the digits unaided');
    expect(b.sas, a.sas, reason: 'and so did the acceptor, the same digits');
    expect(a.lastFailure, isNull);
    expect(b.lastFailure, isNull);
    expect(a.progress, ConnectProgress.confirm);
    expect(b.progress, ConnectProgress.confirm);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('8. two rounds asked for at once are one round', () async {
    final alice = await person('Alice');
    final bob = await person('Bob');
    final invite = await alice.invites.create();
    await alice.invites.pump(); // x1 is in Bob's mailbox
    await bob.invites.open(invite.link);

    // The poll and the button, in the same instant: the second call is the
    // first call's future, not a second step on the same run.
    final one = bob.invites.pump();
    final two = bob.invites.pump();
    expect(identical(one, two), isTrue,
        reason: 'a pump asked for while one is in flight joins it');
    await Future.wait([one, two]);
    // And a pump asked for AFTER it finished is a new one.
    final three = bob.invites.pump();
    expect(identical(three, one), isFalse);
    await three;

    await danceTo(alice, bob);
    final a = alice.invites.invites.single, b = bob.invites.invites.single;
    expect(b.progress, isNot(ConnectProgress.aborted),
        reason: 'one ephemeral was chosen, so the reveal opened');
    expect(a.sas, isNotNull);
    expect(b.sas, a.sas);
  }, timeout: const Timeout(Duration(minutes: 3)));

  testWidgets('9. a relay that cannot be reached is said so, and the invite kept',
      (t) async {
    late Person alice;
    await t.runAsync(
        () async => alice = await person('Alice', url: 'ws://127.0.0.1:1'));
    await t.pumpWidget(tab(alice, const ConnectTab()));
    await t.pumpAndSettle();

    await t.tap(find.text('Create an invite'));
    // The tab pumps behind the tap; the socket is refused at once.
    await settleUntil(t, () => find.textContaining('keep trying').evaluate().isNotEmpty);

    final invite = alice.invites.invites.single;
    expect(invite.lastFailure, isNotNull,
        reason: 'the refusal was recorded rather than swallowed');
    expect(invite.progress, ConnectProgress.waiting,
        reason: 'and it is not a fact about the invite, which is kept');
    expect(find.textContaining('Could not reach the relay'), findsOneWidget,
        reason: 'the card says why, not only "waiting for them"');
    expect(find.text('Waiting for them to open it'), findsOneWidget,
        reason: 'the state line is still the state, not the failure');
    // The invite is still on offer: a refused round is not an expired token.
    expect(
        find.byWidgetPredicate(
            (w) => w is SelectableText && w.data == invite.link),
        findsOneWidget);
    await drain(t);
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('6. every new string is in both locales, with a description', () async {
    final root = Directory.current.path;
    final en = jsonDecode(File('$root/lib/l10n/app_en.arb').readAsStringSync())
        as Map<String, Object?>;
    final es = jsonDecode(File('$root/lib/l10n/app_es.arb').readAsStringSync())
        as Map<String, Object?>;
    final keys = en.keys
        .where((k) => k.startsWith('connect') || k == 'addConnect')
        .toList();
    expect(keys.length, greaterThanOrEqualTo(30),
        reason: 'the CONNECT tab has strings and they are all in the ARB');

    for (final k in keys) {
      final meta = en['@$k'];
      expect(meta, isA<Map>(), reason: '$k has no metadata');
      final description = (meta as Map)['description'] as String?;
      expect(description, isNotNull, reason: '$k has no description');
      expect(description!.length, greaterThan(20),
          reason: '$k: a translator cannot render a string from four words');
      expect(es[k], isNotNull, reason: '$k is missing from Spanish');
      expect((es[k] as String).trim(), isNotEmpty, reason: '$k is empty in Spanish');
      expect(es[k], isNot(en[k]),
          reason: '$k was copied through rather than translated');
    }

    // The clauses that carry the security meaning are named as load-bearing,
    // so a translator knows which words cannot be smoothed away (15.4).
    final flagged = keys
        .where((k) =>
            ((en['@$k'] as Map)['description'] as String).contains('load-bearing'))
        .toList();
    expect(flagged.length, greaterThanOrEqualTo(4),
        reason: 'the security wording is marked, not left to be guessed');

    // And the Spanish carries them: the one-time rule, the unverified state
    // and the do-not-retry instruction all survive the translation.
    expect(es['connectOneTime'] as String, contains('una sola vez'));
    expect(es['connectAddedUnverified'] as String, contains('sin verificar'));
    expect(es['connectMismatchWarning'] as String, contains('No vuelvas'));
  });
}
