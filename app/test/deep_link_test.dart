// 17.3b — an invite link arriving from the platform.
//
// The invite is `https://www.zmessengers.com/i#<code>`, and the code is in the
// FRAGMENT. No browser sends a fragment to a server, and Android carries it
// intact in the intent, so the whole secret goes from the tap into the app
// without the site that serves the landing page ever learning an invite
// exists. This file is the Dart half of that: the platform channel, and what
// happens to whatever comes down it.
//
// It is a PUBLIC entry point — any app on the device can send a VIEW intent,
// and one that names the activity is never held to the intent filter — so
// most of these tests are about it being safe to hand rubbish to.
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
//     claimed /index.html and every other page beginning with the letter;
//  7. and for no app that takes text: the manifest queries none for
//     ACTION_PROCESS_TEXT, which until 4.7.2 put a button for each beside
//     Copy in every selection toolbar, and nothing in lib/ asks for one;
//  8. what the filter would not hand over is dropped before the vault is
//     touched, however it came: a URI of another scheme, host or path, with
//     a port or a name before the host — which another app can send by
//     naming the activity, past the filter — opens nothing and writes
//     nothing, where until 4.7.2 one that read as an invite was opened on
//     any host, by http as well as https; and the hosts taken are the hosts
//     the filter names;
//  9. a genuine link that arrives behind the app lock — engaged at launch,
//     or due as the app comes back to the front, which it hears only after
//     the link — waits for it, and is opened once, after it; and the app's
//     own links are given its lock.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter/widgets.dart' show AppLifecycleState;
import 'package:flutter_test/flutter_test.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/app_lock.dart';
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

/// The invites, writing down every link or code they are asked to open: an
/// open is the vault's read and its write, and asked twice for one link is
/// one link handled twice, though the second is refused as already open.
class _CountingInvites extends ConnectInvites {
  _CountingInvites(super.svc);
  final asked = <String>[];

  @override
  Future<PendingInvite> open(String linkOrCode,
      {int? nowMs, bool consented = true}) {
    asked.add(linkOrCode);
    return super.open(linkOrCode, nowMs: nowMs, consented: consented);
  }
}

/// The OS prompt, passed every time.
class _PassingGate implements BiometricGate {
  @override
  Future<bool> get isAvailable async => true;
  @override
  Future<GateResult> authenticate(String reason) async => GateResult.ok;
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

  /// Deliver a link as the platform does, and wait for the app's answer,
  /// which comes once it has done with the link.
  Future<void> deliver(String url) {
    final answered = Completer<void>();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .handlePlatformMessage(
      channel.name,
      const StandardMethodCodec().encodeMethodCall(MethodCall('link', url)),
      (_) => answered.complete(),
    );
    return answered.future.timeout(const Duration(seconds: 10));
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

    // A link on ANOTHER host is not rubbish where it is pasted: the invite is
    // the secret in the fragment, and the host is only where the landing page
    // happens to live — self-hosting a relay means self-hosting that page
    // too (PROTOCOL §20.2). Android never delivers one by tap (the intent
    // filter is scoped to zmessengers.com), so from the platform it can only
    // be another app naming the activity, and since 4.7.2 it is refused
    // there (8); it arrives by paste, from someone running their own, and is
    // accepted there.
    final elsewhere = ConnectCode.generate();
    expect(await links.handle(elsewhere.link(host: 'relay.example.org')),
        isNull);
    expect(invites.invites, isEmpty);
    await invites.open(elsewhere.link(host: 'relay.example.org'));
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
    // And the printed rendering of the same secret, pasted, is the same
    // invite. (From the platform it is no link at all, and refused: 8.)
    await expectLater(
        invites.open(code.text),
        throwsA(isA<FormatException>().having(
            (e) => e.message, 'message', 'that invite is already open')));
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

  test('7. the platform is asked for no app that takes text', () {
    // Flutter's selection toolbar adds a button for every app Android lists
    // as taking ACTION_PROCESS_TEXT — a translator, a dictionary, a notes
    // app — on every field that shows its text and every text that can be
    // selected, and a tap hands that app the selection: a recovery code, a
    // pairing code, an invite, a message being edited. From Android 11 the
    // platform lists only apps the manifest asks about, and until 4.7.2 it
    // asked about these — `flutter create`'s <queries> block, which nothing
    // in Z used. (Android 10 and earlier list them regardless: THREAT_MODEL
    // R51.)
    final manifest = File('android/app/src/main/AndroidManifest.xml')
        .readAsStringSync()
        .replaceAll(RegExp(r'<!--.*?-->', dotAll: true), '');
    expect(manifest, contains('<application'), reason: 'the manifest was read');
    expect(manifest, isNot(contains('android.intent.action.PROCESS_TEXT')),
        reason: 'a query for PROCESS_TEXT puts every installed app that takes '
            'text beside Copy, on every field that shows a secret');

    // Nor does anything in the app ask for them itself.
    final callers = <String>[];
    var files = 0;
    for (final f in Directory('lib')
        .listSync(recursive: true)
        .whereType<File>()
        .where((f) => f.path.endsWith('.dart'))) {
      files++;
      final lines = f.readAsLinesSync();
      for (var i = 0; i < lines.length; i++) {
        final line = lines[i].trimLeft();
        if (line.startsWith('//')) continue;
        if (line.contains(RegExp('ProcessText|processText'))) {
          callers.add('${f.path}:${i + 1}: ${line.trim()}');
        }
      }
    }
    expect(files, greaterThanOrEqualTo(50), reason: 'lib/ was read');
    expect(callers, isEmpty,
        reason: 'ProcessTextService and the processText channel hand text to '
            'another app');
  });

  test('8. what the filter would not hand over opens nothing and writes '
      'nothing, however it came', () async {
    // MainActivity is exported, and an intent that names it is never held
    // to the filter, so any app can hand over any URI at all. What is taken
    // is what the filter claims: its hosts are DeepLinks.filterHosts, on
    // https, at /i.
    final manifest = File('android/app/src/main/AndroidManifest.xml')
        .readAsStringSync()
        .replaceAll(RegExp(r'<!--.*?-->', dotAll: true), '');
    final filter = RegExp(
            r'<intent-filter[^>]*>(?:(?!</intent-filter>).)*android\.intent\.action\.VIEW(?:(?!</intent-filter>).)*</intent-filter>',
            dotAll: true)
        .firstMatch(manifest)!
        .group(0)!;
    String? attr(String data, String name) =>
        RegExp('android:$name="([^"]*)"').firstMatch(data)?.group(1);
    final claimed = {
      for (final m
          in RegExp(r'<data\b[^>]*/>', dotAll: true).allMatches(filter))
        (attr(m.group(0)!, 'scheme'), attr(m.group(0)!, 'host'),
            attr(m.group(0)!, 'path')),
    };
    expect(claimed,
        {for (final h in DeepLinks.filterHosts) ('https', h, '/i')});

    final counted = _CountingInvites(svc);
    final links = DeepLinks(counted, channel: channel);
    await links.start();
    // A real invite's code, everywhere but where the filter would take it.
    final fragment = ConnectCode.generate().link().split('#').last;
    for (final uri in [
      'http://www.zmessengers.com/i#$fragment', // another scheme
      'zmessengers://i#$fragment',
      'intent://www.zmessengers.com/i#$fragment',
      'file:///sdcard/i#$fragment',
      'content://media/external/i#$fragment',
      // The filter compares the scheme and the host exactly.
      'HTTPS://WWW.ZMESSENGERS.COM/i#$fragment',
      ' https://www.zmessengers.com/i#$fragment',
      'https://relay.example.org/i#$fragment', // another host: pasted, 3
      'https://zmessengers.com.example.org/i#$fragment',
      'https://www.zmessengers.com.example.org/i#$fragment',
      'https://example.org/https://www.zmessengers.com/i#$fragment',
      'https://www.zmessengers.com:8443/i#$fragment', // a port
      'https://someone@www.zmessengers.com/i#$fragment', // a name before it
      'https://www.zmessengers.com/i/#$fragment', // another path
      'https://www.zmessengers.com/x/i#$fragment',
      'https://www.zmessengers.com/c#$fragment', // public links are off
    ]) {
      await deliver(uri);
      expect(links.lastRejected, uri, reason: 'refused: $uri');
    }
    expect(counted.asked, isEmpty, reason: 'no invite was opened for any');
    expect(await vault.kvGet('connect_invites'), isNull,
        reason: 'nothing was written to the vault');
    expect(counted.invites, isEmpty);
    expect(links.takeUnshown(), isNull);

    // The same code on the invite page itself, on either host, is taken.
    await deliver('https://zmessengers.com/i#$fragment');
    expect(counted.invites, hasLength(1));
    expect(await vault.kvGet('connect_invites'), isNotNull);
    expect(await links.handle('https://www.zmessengers.com/i?x=1#$fragment'),
        isNull, reason: 'the same invite, already open');
    expect(counted.asked, [
      'https://zmessengers.com/i#$fragment',
      'https://www.zmessengers.com/i?x=1#$fragment',
    ]);
    await links.dispose();
  });

  test('9. a link that arrives behind the app lock waits for it, and is '
      'opened once, after it', () async {
    var now = 1000000;
    final lock = AppLock(
        root: dir,
        gate: _PassingGate(),
        store: MemorySecretStore(),
        clock: () => now);
    await lock.save(const LockSettings(screenLock: true, lockAfterSec: 60));
    final counted = _CountingInvites(svc);
    final links = DeepLinks(counted, channel: channel, lock: lock);

    // Launched with the screen lock on: locked before the first screen, and
    // the launch intent drained behind it.
    final first = ConnectCode.generate();
    initial = first.link();
    lock.lockNow();
    await links.start();
    expect(takes, 1);
    expect(counted.asked, isEmpty, reason: 'nothing opened behind the lock');
    expect(await vault.kvGet('connect_invites'), isNull,
        reason: 'nothing written behind the lock');
    expect(links.takeUnshown(), isNull);
    expect(links.lastRejected, isNull, reason: 'waiting, not refused');

    var next = links.opened.first;
    expect(await lock.requestUnlock(), GateResult.ok);
    final one = await next.timeout(const Duration(seconds: 10));
    expect(b64(one.run.code.secret), b64(first.secret));
    expect(one.held, isTrue, reason: 'held as every tapped link is: no yes');
    expect(identical(links.takeUnshown(), one), isTrue);

    // In the background past the lock's time, a tapped link reaches the app
    // before it is told it is in front, and only that locks it: the link
    // waits all the same, and a second tap of it waits as one.
    lock.onLifecycle(AppLifecycleState.paused);
    now += 61 * 1000;
    final second = ConnectCode.generate();
    await deliver(second.link());
    expect(lock.locked, isFalse, reason: 'due, not yet locked');
    lock.onLifecycle(AppLifecycleState.resumed);
    expect(lock.locked, isTrue);
    await deliver(second.link());
    expect(counted.asked, [first.link()], reason: 'the second still waits');

    next = links.opened.first;
    expect(await lock.requestUnlock(), GateResult.ok);
    final two = await next.timeout(const Duration(seconds: 10));
    expect(b64(two.run.code.secret), b64(second.secret));

    // Once: locked and unlocked again, nothing waits. A link handled after
    // that is taken in turn behind anything an unlock could have queued, so
    // when it is done, so is all of that.
    lock.lockNow();
    expect(await lock.requestUnlock(), GateResult.ok);
    next = links.opened.first;
    final third = ConnectCode.generate();
    expect(await links.handle(third.link()), isNotNull);
    final three = await next.timeout(const Duration(seconds: 10));
    expect(b64(three.run.code.secret), b64(third.secret),
        reason: 'the next one opened is the link that came next');
    expect(counted.asked, [first.link(), second.link(), third.link()],
        reason: 'each link opened once, in the order it came');

    // And the app's own links are given the app's lock.
    final main = File('lib/main.dart').readAsStringSync();
    expect(
        RegExp(r'DeepLinks\([^;]*\block: _appLock\b').hasMatch(main), isTrue,
        reason: 'main.dart hands DeepLinks the app lock');
    await links.dispose();
  });
}
