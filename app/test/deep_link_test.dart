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
//  5. an invite that arrived by link is carried forward at once and handed
//     to the UI to show — until 2026-09-17 it was written to the vault and
//     nothing else happened: no round, no screen, the app came up on the
//     home screen as if nothing had been tapped.
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

    for (final rubbish in [
      'https://zmessengers.com/',
      'https://www.zmessengers.com/i', // no fragment: nothing was handed over
      'https://www.zmessengers.com/i#not-base32-at-all-!!',
      'zc1.notaninvite', // a contact code is not an invite
      'https://zmessengers.com/how-it-works',
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

  test('5. an opened link is carried forward at once, and handed to the UI',
      () async {
    final code = ConnectCode.generate();
    initial = code.link();
    final links = DeepLinks(invites, channel: channel);
    expect(links.takeUnshown(), isNull);
    await links.start();

    final invite = invites.invites.single;
    // The first round ran without anybody opening the tab. There is no relay
    // on port 1, so what it recorded is the refusal — the point is that it
    // ran, and that the refusal is on the invite rather than swallowed.
    expect(invite.lastFailure, isNotNull,
        reason: 'the ceremony was stepped as soon as the link was opened');
    expect(invite.progress, ConnectProgress.waiting,
        reason: 'a refused round leaves the invite where it was');

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
}
