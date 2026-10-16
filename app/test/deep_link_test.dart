// 17.3b — an invite link arriving from the platform.
//
// The invite is `https://www.zmessengers.com/i#<code>`, and the code is in the
// FRAGMENT. No browser sends a fragment to a server, and Android carries it
// intact in the intent, so the whole secret goes from the tap into the app
// without the site that serves the landing page ever learning an invite
// exists. This file is the Dart half of that: the platform channel, and what
// happens to whatever comes down it.
//
// It is a PUBLIC entry point — any app on the device can send a VIEW intent —
// so most of these tests are about it being safe to hand rubbish to.
//
// Criteria, each a test below:
//  1. the link the app was launched with is drained on start and opens the
//     ceremony, with the code from the fragment and nothing fetched;
//  2. a link arriving while the app is running is handled the same way;
//  3. anything that is not an invite is ignored in silence, and a platform
//     with no deep links at all (desktop, or a test) starts cleanly;
//  4. the same invite arriving twice opens one ceremony, not two;
//  5. an invite that arrived by link is handed to the UI to show — until
//     2026-09-17 it was written to the vault and nothing else happened: no
//     screen, the app came up on the home screen as if nothing had been
//     tapped — and is HELD there: no round runs, not even when the poll
//     does, until its person says yes (ADR 0024; until 2026-10-09 the tap
//     itself ran the first round, and the code went out without a yes);
//  6. the platform is asked for the invite page alone: the intent filter
//     names the path /i exactly, where until 2026-10-16 a prefix of /i also
//     claimed /index.html and every other page beginning with the letter.
import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/connect_invites.dart';
import 'package:zapp/core/deep_links.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';

/// An `HttpOverrides` that forbids and counts HTTP-client construction. The
/// fragment carries the whole invite secret, and the file's promise is that
/// consuming it reaches the landing host not at all; under this override,
/// opening an invite must complete having constructed nothing. An
/// `HttpClient().getUrl(...)` added to `ConnectInvites.open` would leak the
/// fragment and is what this catches (the 2026-09-14 review's finding 37).
class _NoNetwork extends HttpOverrides {
  int created = 0;
  @override
  HttpClient createHttpClient(SecurityContext? context) {
    created++;
    throw const SocketException('opening an invite must touch no network');
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late Directory dir;
  late Vault vault;
  late ChatService svc;
  late ConnectInvites invites;
  late MethodChannel channel;

  /// What the platform side will answer `take` with, and the calls it saw.
  String? initial;
  var takes = 0;

  setUp(() async {
    dir = await Directory.systemTemp.createTemp('z_dl_');
    vault = await Vault.open(rootOverride: dir);
    final me = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(me.toJson()));
    // Nothing is listening on port 1: none of this needs a relay.
    final transport = Transport(identity: me, serverUrl: 'ws://127.0.0.1:1');
    svc = await ChatService.init(
        vault: vault, identity: me, displayName: 'Finn', transport: transport);
    invites = ConnectInvites(svc);

    initial = null;
    takes = 0;
    channel = const MethodChannel('z/deeplink/test');
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      if (call.method == 'take') {
        takes++;
        final was = initial;
        initial = null; // drained, exactly as the platform side drains it
        return was;
      }
      return null;
    });
  });

  tearDown(() async {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
    await svc.transport.stop();
    await svc.vault.db.close();
    if (dir.existsSync()) dir.deleteSync(recursive: true);
  });

  /// Deliver a link as the platform would, to a listener already running.
  Future<void> push(String url) async {
    await TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .handlePlatformMessage(
      channel.name,
      const StandardMethodCodec().encodeMethodCall(MethodCall('link', url)),
      (_) {},
    );
  }

  test('1. the link the app was launched with opens the ceremony', () async {
    final code = ConnectCode.generate();
    initial = code.link();

    final links = DeepLinks(invites, channel: channel);
    await links.start();

    expect(takes, 1, reason: 'the launch intent is asked for exactly once');
    expect(invites.invites, hasLength(1));
    expect(b64(invites.invites.single.run.code.secret), b64(code.secret),
        reason: 'the ceremony runs on the code from the fragment');
    expect(invites.invites.single.mine, isFalse);
    await links.dispose();
  });

  test('1b. opening an invite fetches nothing — the fragment never leaves the '
      'device', () async {
    // The whole secret is in the fragment of a www.zmessengers.com link. This
    // pins the header's promise: consuming it constructs no HTTP client, so the
    // landing host is never asked and never learns an invite exists. Under the
    // guard, `open` completes and creates zero clients; an outbound fetch added
    // to `ConnectInvites.open` would throw here.
    final code = ConnectCode.generate();
    final net = _NoNetwork();
    final previous = HttpOverrides.current;
    HttpOverrides.global = net;
    try {
      await invites.open(code.link(host: 'www.zmessengers.com'));
    } finally {
      HttpOverrides.global = previous;
    }
    expect(net.created, 0,
        reason: 'opening the invite constructed no HTTP client');
    expect(invites.invites, hasLength(1));
    expect(b64(invites.invites.single.run.code.secret), b64(code.secret));
  });

  test('2. a link arriving while the app is running is handled too', () async {
    final links = DeepLinks(invites, channel: channel);
    await links.start();
    expect(invites.invites, isEmpty);

    final opened = <PendingInvite>[];
    final sub = links.opened.listen(opened.add);
    final code = ConnectCode.generate();
    await push(code.link());
    await Future<void>.delayed(const Duration(milliseconds: 50));

    expect(invites.invites, hasLength(1));
    expect(b64(invites.invites.single.run.code.secret), b64(code.secret));
    expect(opened, hasLength(1),
        reason: 'the UI is told, so it can show the ceremony');
    await sub.cancel();
    await links.dispose();
  });

  test('3. anything that is not an invite is ignored in silence', () async {
    final links = DeepLinks(invites, channel: channel);
    await links.start();

    // A fragment that reads as an invite, on pages that are not the invite
    // page: until 2026-10-16 any `/i` before the `#` made it one.
    final fragment = ConnectCode.generate().link().split('#').last;
    for (final rubbish in [
      'https://zmessengers.com/',
      'https://www.zmessengers.com/i', // no fragment: nothing was handed over
      'https://www.zmessengers.com/i#not-base32-at-all-!!',
      'zc1.notaninvite', // a contact code is not an invite
      'https://zmessengers.com/how-it-works',
      'https://www.zmessengers.com/index.html#$fragment',
      'https://www.zmessengers.com/info#$fragment',
      '',
    ]) {
      expect(await links.handle(rubbish), isNull, reason: rubbish);
    }
    expect(invites.invites, isEmpty,
        reason: 'a foreign VIEW intent must not create anything');

    // A link on ANOTHER host is not rubbish, and is accepted: the invite is
    // the secret in the fragment, and the host is only where the landing page
    // happens to live — self-hosting a relay means self-hosting that page
    // too. Android never delivers one by tap (the intent filter is scoped to
    // zmessengers.com); it arrives by paste, from someone running their own.
    final elsewhere = ConnectCode.generate();
    expect(await links.handle(elsewhere.link(host: 'relay.example.org')),
        isNotNull);
    expect(invites.invites, hasLength(1));
    await links.dispose();

    // A platform with nothing behind the channel — desktop, or any build
    // without the native side — starts without complaint.
    const bare = MethodChannel('z/deeplink/absent');
    final none = DeepLinks(invites, channel: bare);
    await none.start();
    expect(invites.invites, hasLength(1),
        reason: 'nothing behind the channel means nothing to hand over');
    await none.dispose();
  });

  test('4. the same invite arriving twice opens one ceremony', () async {
    final code = ConnectCode.generate();
    final links = DeepLinks(invites, channel: channel);
    await links.start();

    expect(await links.handle(code.link()), isNotNull);
    // The second delivery — a double tap, or a relaunch on the same intent.
    expect(await links.handle(code.link()), isNull);
    expect(invites.invites, hasLength(1),
        reason: 'one invite, however many times the link is opened');
    // And the printed rendering of the same secret is the same invite.
    expect(await links.handle(code.text), isNull);
    expect(invites.invites, hasLength(1));
    await links.dispose();
  });

  test('5. an opened link is held, and handed to the UI', () async {
    final code = ConnectCode.generate();
    initial = code.link();
    final links = DeepLinks(invites, channel: channel);
    expect(links.takeUnshown(), isNull);
    await links.start();

    final invite = invites.invites.single;
    // No round ran: a tap is not the person's yes (ADR 0024). One that ran
    // would have recorded the refusal from port 1 on the invite.
    expect(invite.held, isTrue);
    expect(invite.lastFailure, isNull,
        reason: 'nothing was stepped when the link was opened');
    await invites.pump();
    expect(invite.lastFailure, isNull, reason: 'nor when the poll ran');
    expect(invite.progress, ConnectProgress.waiting);

    // The launch intent is drained before any screen exists to listen, so
    // the invite is held for the first screen that asks — once.
    expect(identical(links.takeUnshown(), invite), isTrue);
    expect(links.takeUnshown(), isNull, reason: 'handed over exactly once');

    // A link arriving later, with a screen listening, is both told and held.
    final later = <PendingInvite>[];
    final sub = links.opened.listen(later.add);
    final second = ConnectCode.generate();
    await push(second.link());
    await Future<void>.delayed(const Duration(milliseconds: 50));
    expect(later, hasLength(1));
    expect(identical(links.takeUnshown(), later.single), isTrue);
    await sub.cancel();
    await links.dispose();
  });

  test('6. the platform hands over the invite page alone', () {
    // What Android delivers by tap is decided by the intent filter, before
    // any of the Dart above runs: a path PREFIX of /i also claimed
    // /index.html, /images/… and every other page beginning with the
    // letter, so once the hosts verify, those would have opened the app.
    final manifest = File('android/app/src/main/AndroidManifest.xml')
        .readAsStringSync()
        // Comments say what the filter used to be; only elements count.
        .replaceAll(RegExp(r'<!--.*?-->', dotAll: true), '');
    final filter = RegExp(
            r'<intent-filter[^>]*>(?:(?!</intent-filter>).)*android\.intent\.action\.VIEW(?:(?!</intent-filter>).)*</intent-filter>',
            dotAll: true)
        .firstMatch(manifest);
    expect(filter, isNotNull, reason: 'the VIEW filter for invite links');
    final data = RegExp(r'<data\b[^>]*/>', dotAll: true)
        .allMatches(filter!.group(0)!)
        .map((m) => m.group(0)!)
        .toList();
    expect(data, hasLength(2), reason: 'one per host');
    for (final d in data) {
      expect(d, contains('android:path="/i"'), reason: d);
      expect(d, isNot(contains('pathPrefix')), reason: d);
      expect(d, isNot(contains('pathPattern')), reason: d);
      expect(d, isNot(contains('pathAdvancedPattern')), reason: d);
      expect(d, isNot(contains('pathSuffix')), reason: d);
    }
  });
}
