// Phase 41 — push asks first, and a withdrawal reaches the relay.
//
// Push is on by default on Android, and until phase 41 the app registered its
// Firebase token with the relay whether or not the user had allowed
// notifications (the 2026-10-03 analysis, P1-20), kept it registered after
// permission was taken away, and lost a "push off" made while offline: the
// relay was never told, and woke the device through Google for every message
// until the token aged out thirty days later (the analysis's P2, reproduced
// here). The relay is `server/test/support/observed_relay.js`: it prints every
// registration and withdrawal it is asked for, and every wake ping it sends.
//
// Exit criteria:
//   1. Push turned off while the device is offline reaches the relay when the
//      device is back: the relay is asked to forget the token and answers, and
//      a message that waits for the device afterwards wakes nothing.
//   2. A device whose user did not allow notifications registers no token:
//      the relay is never asked to hold one, not at start and not at any
//      reconnect, and a message waiting for the device wakes nothing.
//   3. Notifications taken away after push was registered: at the next start
//      the token is withdrawn — the relay told, and answering — and nothing
//      wakes the device after.
//   4. Notifications taken away while the app runs are noticed when it comes
//      back to the foreground, and the token withdrawn and deleted at FCM;
//      allowed again, it registers again.
//   5. A withdrawal made offline survives a restart: the next start's first
//      connection tells the relay, and once the relay has answered no later
//      start asks again.
//   6. Settings says what push sends and to whom — the relay, Google's
//      Firebase Cloud Messaging, no content and no sender, thirty days — and,
//      when nothing is registered, says why: off, notifications not allowed,
//      or a withdrawal the relay has yet to hear.
//   7. A token refresh that FCM fires after notifications were taken away
//      while the app ran — with no return to the foreground to re-check — does
//      not re-register: permission is checked afresh inside the refresh
//      callback, so a revoked device hands the relay nothing.
@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/app_lock.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/key_transparency.dart';
import 'package:zapp/core/prefs.dart';
import 'package:zapp/core/push_service.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/l10n/app_localizations_en.dart';
import 'package:zapp/ui/settings_screen.dart';
import 'package:zapp/ui/theme.dart';

/// The platform side of push, as a test can drive it: whether notifications
/// are allowed, and the token FCM would hand out. Firebase itself has no
/// implementation here.
class FakePushPlatform implements PushPlatform {
  bool allowed;
  final String fcmToken;
  int asked = 0;
  int forgotten = 0;
  final refresh = StreamController<String>.broadcast();
  final wakes = StreamController<void>.broadcast();
  FakePushPlatform({required this.allowed, required this.fcmToken});

  @override
  Future<bool> requestPermission() async {
    asked++;
    return allowed;
  }

  @override
  Future<bool> permitted() async => allowed;

  @override
  Future<String?> token() async => fcmToken;

  @override
  Future<void> forgetToken() async => forgotten++;

  @override
  Stream<String> get tokenRefresh => refresh.stream;

  @override
  Stream<void> get foregroundWakes => wakes.stream;
}

/// One line the observed relay printed (see `observed_relay.js`).
class RelayEvent {
  final String ev;
  final String? to;
  final String? rid;
  final String? token;
  final int at;
  RelayEvent(Map<String, Object?> j)
      : ev = j['ev'] as String,
        to = j['to'] as String?,
        rid = j['rid'] as String?,
        token = j['token'] as String?,
        at = (j['at'] as num).toInt();
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  late Process relay;
  late int port;
  final events = <RelayEvent>[];
  final temps = <Directory>[];
  final live = <ChatService>[];

  setUpAll(() async {
    HttpOverrides.global = null;
    final serverDir =
        '${Directory.current.parent.path}${Platform.pathSeparator}server';
    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    port = probe.port;
    await probe.close();
    relay = await Process.start('node', ['test/support/observed_relay.js'],
        workingDirectory: serverDir,
        environment: {'PORT': '$port', 'LOG_LEVEL': 'silent'});
    relay.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen((line) {
      if (line.startsWith('OBS ')) {
        events.add(RelayEvent(
            (jsonDecode(line.substring(4)) as Map).cast<String, Object?>()));
      }
    });
    relay.stderr.drain<void>();
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
    for (final s in live) {
      await s.transport.stop();
    }
    relay.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<void> waitUntil(FutureOr<bool> Function() cond,
      {Duration timeout = const Duration(seconds: 20),
      required String what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  Future<ChatService> start(Directory dir, String name) async {
    final vault = await Vault.open(rootOverride: dir);
    final stored = await vault.kvGet('identity');
    final me = stored == null
        ? await ZIdentity.generate()
        : await ZIdentity.fromJson(
            (jsonDecode(stored) as Map).cast<String, Object?>());
    if (stored == null) await vault.kvPut('identity', jsonEncode(me.toJson()));
    final transport =
        Transport(identity: me, serverUrl: 'ws://127.0.0.1:$port');
    final svc = await ChatService.init(
        vault: vault, identity: me, displayName: name, transport: transport);
    live.add(svc);
    await waitUntil(() => transport.isConnected && transport.isSenderConnected,
        what: '$name connected');
    return svc;
  }

  Future<ChatService> person(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_push_');
    temps.add(dir);
    return start(dir, name);
  }

  Future<void> introduce(ChatService a, ChatService b) async {
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
    await a.sendText(b.myRid, 'hello from ${a.displayName}');
    await b.sendText(a.myRid, 'hello from ${b.displayName}');
    await waitUntil(
        () =>
            (a.messagesByChat[b.myRid] ?? []).any((m) => !m.outgoing) &&
            (b.messagesByChat[a.myRid] ?? []).any((m) => !m.outgoing),
        what: '${a.displayName} and ${b.displayName} have spoken');
  }

  Future<void> offline(ChatService s) => s.transport.stop();

  Future<void> online(ChatService s) async {
    s.transport.start();
    await waitUntil(
        () => s.transport.isConnected && s.transport.isSenderConnected,
        what: '${s.displayName} back online');
  }

  /// [from] writes to [to], who is offline, and the relay takes it; then a
  /// second message, whose acceptance the relay logs only after it has done
  /// everything it does for the first — waking its recipient included. So
  /// once the second is seen, a wake for the first would have been too.
  Future<void> writeWhileAway(ChatService from, ChatService to) async {
    for (final body in ['are you there?', 'still there?']) {
      final mark = events.length;
      await from.sendText(to.myRid, body);
      await waitUntil(
          () => events
              .skip(mark)
              .any((e) => e.ev == 'accept' && e.to == to.myRid),
          what: 'the relay holds "$body" for ${to.displayName}');
    }
  }

  List<RelayEvent> wakesFor(String token) => [
        for (final e in events)
          if (e.ev == 'wake' && e.token == token) e
      ];

  test(
      '1. push turned off while offline reaches the relay once the device is '
      'back, and nothing wakes it after', () async {
    final dev = await person('Dev');
    final friend = await person('Friend');
    await introduce(dev, friend);

    // Push on: the relay holds Dev's token, and a message while Dev is away
    // wakes the device — the baseline the rest is measured against.
    const token = 'fcm-token-dev-1';
    dev.transport.setPushToken(token);
    await waitUntil(
        () => events.any((e) => e.ev == 'push-register' && e.rid == dev.myRid),
        what: "the relay holds Dev's token");
    await offline(dev);
    await writeWhileAway(friend, dev);
    expect(wakesFor(token), isNotEmpty,
        reason: 'with push on, a message waiting for Dev wakes the device');
    await online(dev);

    // Dev goes offline — a phone in a lift — and turns push off there.
    await offline(dev);
    final mark = events.length;
    dev.transport.unregisterPush();
    await online(dev);
    // Told, and answered: the relay's `push-ok` to Dev's own connection.
    bool told() =>
        events
            .skip(mark)
            .any((e) => e.ev == 'push-unregister' && e.rid == dev.myRid) &&
        events.skip(mark).any((e) => e.ev == 'push-ok' && e.rid == dev.myRid);
    var withdrawn = true;
    try {
      await waitUntil(told,
          timeout: const Duration(seconds: 10),
          what: 'the relay is told to forget the token once Dev is back');
    } on TimeoutException {
      withdrawn = false; // asserted below, after what it costs is measured
    }

    // And from then on nothing wakes the device.
    final before = wakesFor(token).length;
    await offline(dev);
    await writeWhileAway(friend, dev);
    expect(wakesFor(token).length, before,
        reason: 'a device whose user turned push off was woken through '
            'Google anyway');
    expect(withdrawn, isTrue,
        reason: 'the relay was never told to forget the token');
    await online(dev);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test(
      '2. a device whose user did not allow notifications registers no '
      'token, at start or at any reconnect', () async {
    final dev = await person('Denied');
    final friend = await person('Friend2');
    await introduce(dev, friend);
    const token = 'fcm-token-denied';
    final platform = FakePushPlatform(allowed: false, fcmToken: token);
    final push = PushService(
        transport: dev.transport,
        vault: dev.vault,
        platform: platform,
        supported: true);
    await push.init(); // push is on by default
    expect(platform.asked, greaterThan(0),
        reason: 'push on by default asks for notifications');

    // A reconnect is when a registration would be repeated.
    await offline(dev);
    await online(dev);
    await offline(dev);
    await writeWhileAway(friend, dev);
    expect(events.where((e) => e.ev == 'push-register' && e.rid == dev.myRid),
        isEmpty,
        reason: 'the relay was asked to hold the token of a device whose '
            'user did not allow notifications');
    expect(wakesFor(token), isEmpty, reason: 'and woke it through Google');
    await online(dev);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test(
      '3. notifications taken away after push was registered: the next start '
      'withdraws the token', () async {
    final dev = await person('Revoked');
    final friend = await person('Friend3');
    await introduce(dev, friend);
    const token = 'fcm-token-revoked';
    final platform = FakePushPlatform(allowed: true, fcmToken: token);
    await PushService(
            transport: dev.transport,
            vault: dev.vault,
            platform: platform,
            supported: true)
        .init();
    await waitUntil(
        () => events.any((e) => e.ev == 'push-register' && e.rid == dev.myRid),
        what: 'push on and allowed: the relay holds the token');

    // The user takes notifications away in Android's settings, and the app
    // next starts: a new service over the same vault and the same link.
    platform.allowed = false;
    final mark = events.length;
    await PushService(
            transport: dev.transport,
            vault: dev.vault,
            platform: platform,
            supported: true)
        .init();
    await waitUntil(
        () =>
            events
                .skip(mark)
                .any((e) => e.ev == 'push-unregister' && e.rid == dev.myRid) &&
            events
                .skip(mark)
                .any((e) => e.ev == 'push-ok' && e.rid == dev.myRid),
        timeout: const Duration(seconds: 10),
        what: 'the relay is told to forget the token, and says it has');
    expect(
        events
            .skip(mark)
            .where((e) => e.ev == 'push-register' && e.rid == dev.myRid),
        isEmpty,
        reason: 'the token was registered again without permission');
    final before = wakesFor(token).length;
    await offline(dev);
    await writeWhileAway(friend, dev);
    expect(wakesFor(token).length, before,
        reason: 'a device without notifications was woken through Google');
    await online(dev);
  }, timeout: const Timeout(Duration(minutes: 3)));

  /// The relay was asked, after event [mark], to forget [s]'s token, and
  /// answered on [s]'s own connection.
  bool withdrawnSince(int mark, ChatService s) =>
      events
          .skip(mark)
          .any((e) => e.ev == 'push-unregister' && e.rid == s.myRid) &&
      events.skip(mark).any((e) => e.ev == 'push-ok' && e.rid == s.myRid);

  bool registeredSince(int mark, ChatService s) =>
      events.skip(mark).any((e) => e.ev == 'push-register' && e.rid == s.myRid);

  test(
      '4. notifications taken away while the app runs are noticed on its '
      'return, and allowed again, registered again', () async {
    final dev = await person('Resume');
    final friend = await person('Friend4');
    await introduce(dev, friend);
    const token = 'fcm-token-resume';
    final platform = FakePushPlatform(allowed: true, fcmToken: token);
    final push = PushService(
        transport: dev.transport,
        vault: dev.vault,
        platform: platform,
        supported: true);
    var mark = events.length;
    await push.init();
    await waitUntil(() => registeredSince(mark, dev),
        what: 'push on and allowed: registered');
    expect(push.status, PushStatus.on);

    // Taken away in Android's settings while Z sat in the background.
    platform.allowed = false;
    mark = events.length;
    await push.onResume();
    expect(push.status, PushStatus.notAllowed);
    await waitUntil(() => withdrawnSince(mark, dev),
        what: 'the relay is told to forget the token, and says it has');
    await waitUntil(() => !push.withdrawalPending,
        what: 'the withdrawal is recorded as answered');
    expect(platform.forgotten, greaterThan(0),
        reason: 'and the token is deleted at FCM, so a copy anywhere wakes '
            'nothing');
    var before = wakesFor(token).length;
    await offline(dev);
    await writeWhileAway(friend, dev);
    expect(wakesFor(token).length, before,
        reason: 'a device without notifications was woken');
    await online(dev);

    // Allowed again.
    platform.allowed = true;
    mark = events.length;
    await push.onResume();
    expect(push.status, PushStatus.on);
    await waitUntil(() => registeredSince(mark, dev),
        what: 'allowed again: registered again');
    before = wakesFor(token).length;
    await offline(dev);
    await writeWhileAway(friend, dev);
    expect(wakesFor(token).length, greaterThan(before),
        reason: 'push is back on: a waiting message wakes the device');
    await online(dev);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test(
      '5. a withdrawal made offline survives a restart, and is not repeated '
      'once answered', () async {
    final dir = await Directory.systemTemp.createTemp('z_push_');
    temps.add(dir);
    var dev = await start(dir, 'Restart');
    final friend = await person('Friend5');
    await introduce(dev, friend);
    const token = 'fcm-token-restart';
    final platform = FakePushPlatform(allowed: true, fcmToken: token);
    PushService pushFor(ChatService s) => PushService(
        transport: s.transport,
        vault: s.vault,
        platform: platform,
        supported: true);
    var push = pushFor(dev);
    var mark = events.length;
    await push.init();
    await waitUntil(() => registeredSince(mark, dev),
        what: 'push on and allowed: registered');

    // Off, with no connection to say so on — and the app is killed before
    // it is back.
    await offline(dev);
    await push.setEnabled(false);
    expect(push.status, PushStatus.off);
    expect(push.withdrawalPending, isTrue,
        reason: 'Settings has to be able to say the relay has not heard');
    // The app is killed: nothing more from this process. The database is
    // left open — what a stopped service's last connection started may
    // still be finishing, and a closed handle under it would be an error
    // about this test, not about the app — and the next start opens the
    // same file.
    Future<void> kill(ChatService s, PushService p) async {
      p.dispose();
      s.dispose();
      await s.transport.stop();
      live.remove(s);
    }

    await kill(dev, push);
    mark = events.length;
    dev = await start(dir, 'Restart');
    push = pushFor(dev);
    await push.init();
    expect(push.status, PushStatus.off);
    await waitUntil(() => withdrawnSince(mark, dev),
        what: 'the next start tells the relay, and it answers');
    await waitUntil(() async => await dev.vault.kvGet('push_relay') == 'off',
        what: 'the answer is written down');
    expect(registeredSince(mark, dev), isFalse);
    final before = wakesFor(token).length;
    await offline(dev);
    await writeWhileAway(friend, dev);
    expect(wakesFor(token).length, before,
        reason: 'push turned off before a restart woke the device anyway');
    await online(dev);
    await waitUntil(
        () => (dev.messagesByChat[friend.myRid] ?? [])
            .any((m) => m.body == 'still there?'),
        what: 'what waited for Dev has arrived');

    // And a start after that has nothing to withdraw: no frame, and no
    // second deletion at FCM.
    final forgotten = platform.forgotten;
    await kill(dev, push);
    dev = await start(dir, 'Restart');
    push = pushFor(dev);
    await push.init();
    expect(push.withdrawalPending, isFalse);
    expect(platform.forgotten, forgotten,
        reason: 'a withdrawal the relay already answered was made again');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test(
      '7. a token refresh after notifications were taken away while the app '
      'ran, with no resume, does not re-register the token', () async {
    final dev = await person('Refresh');
    final friend = await person('Friend7');
    await introduce(dev, friend);
    const token = 'fcm-token-refresh-a';
    final platform = FakePushPlatform(allowed: true, fcmToken: token);
    final push = PushService(
        transport: dev.transport,
        vault: dev.vault,
        platform: platform,
        supported: true);
    final mark = events.length;
    await push.init();
    await waitUntil(() => registeredSince(mark, dev),
        what: 'push on and allowed: the token is registered');

    // Notifications are taken away in Android's settings while Z sits in the
    // background — no return to the foreground, so nothing refreshes what the
    // service last learned about permission (its `_permitted` stays true).
    platform.allowed = false;

    // FCM rotates this install's token and fires onTokenRefresh. A second
    // listener on the same broadcast stream, subscribed after the service's
    // own, completes once the service's refresh listener has been invoked;
    // whichever token the refresh leaves set is then what a reconnection
    // re-registers below. The relay logs no token on a registration, only on
    // the wake it sends, so the held token is read from that wake.
    const refreshed = 'fcm-token-refresh-b';
    final ran = Completer<void>();
    final order = platform.refresh.stream.listen((_) {
      if (!ran.isCompleted) ran.complete();
    });
    platform.refresh.add(refreshed);
    await ran.future;
    await order.cancel();

    // A reconnection re-registers the device's current push token — the relay
    // holds tokens in RAM only — so once it has logged that registration the
    // token the relay holds is settled: `refreshed` if the refresh registered
    // on the stale flag, the original token if permission was re-checked and
    // the refresh left it untouched.
    final reMark = events.length;
    await offline(dev);
    await online(dev);
    await waitUntil(() => registeredSince(reMark, dev),
        what: 'the reconnection re-registers the current token');

    // Away again: the relay wakes the device through the token it holds.
    await offline(dev);
    await writeWhileAway(friend, dev);
    expect(wakesFor(refreshed), isEmpty,
        reason: 'a token refresh re-registered the token after notifications '
            'were revoked, with no resume to re-check permission, so the '
            'relay woke the device through the refreshed token');
    await online(dev);
  }, timeout: const Timeout(Duration(minutes: 3)));

  group('Settings', () {
    late Directory dir;
    late ChatService svc;
    late PushService push;
    late FakePushPlatform platform;
    late AppLock lock;

    setUp(() async {
      dir = await Directory.systemTemp.createTemp('z_push_ui');
      final vault = await Vault.open(rootOverride: dir);
      final me = await ZIdentity.generate();
      await vault.kvPut('identity', jsonEncode(me.toJson()));
      // Offline on purpose: a closed local port, and no transparency log.
      svc = await ChatService.init(
          vault: vault,
          identity: me,
          displayName: 'Finn',
          transport: Transport(identity: me, serverUrl: 'ws://127.0.0.1:1'),
          ktConfig: KtConfig.off);
      platform = FakePushPlatform(allowed: true, fcmToken: 'fcm-token-ui');
      push = PushService(
          transport: svc.transport,
          vault: vault,
          platform: platform,
          supported: true);
      lock = AppLock(root: dir, store: MemorySecretStore());
    });

    tearDown(() async {
      await svc.transport.stop();
      await svc.vault.db.close();
      if (dir.existsSync()) dir.deleteSync(recursive: true);
    });

    Future<void> settleUntil(WidgetTester t, bool Function() cond,
        {required String what}) async {
      final deadline = DateTime.now().add(const Duration(seconds: 30));
      await t.pump();
      while (!cond()) {
        if (DateTime.now().isAfter(deadline)) {
          throw TimeoutException('condition not met: $what');
        }
        await t.runAsync(
            () => Future<void>.delayed(const Duration(milliseconds: 40)));
        await t.pump(const Duration(milliseconds: 16));
      }
    }

    Future<void> open(WidgetTester t) async {
      // Tall enough that every row of Settings is built, not only the ones a
      // phone's first screen shows.
      t.view.physicalSize = const Size(900, 6000);
      t.view.devicePixelRatio = 1.0;
      addTearDown(t.view.resetPhysicalSize);
      addTearDown(t.view.resetDevicePixelRatio);
      final prefs = AppPrefs(root: dir);
      await t.runAsync(prefs.load);
      await t.pumpWidget(MultiProvider(
        providers: [
          ChangeNotifierProvider<ChatService>.value(value: svc),
          ChangeNotifierProvider<Transport>.value(value: svc.transport),
          ChangeNotifierProvider<PushService>.value(value: push),
          ChangeNotifierProvider<AppLock>.value(value: lock),
          ChangeNotifierProvider<AppPrefs>.value(value: prefs),
        ],
        child: MaterialApp(
          debugShowCheckedModeBanner: false,
          theme: ZTheme.light(),
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: const SettingsScreen(),
        ),
      ));
    }

    bool shows(WidgetTester t, String text) =>
        find.text(text, skipOffstage: false).evaluate().isNotEmpty;

    testWidgets(
        '6. Settings says what push sends and to whom, and why nothing is '
        'registered when nothing is', (t) async {
      final l = AppLocalizationsEn();
      // What push sends, and to whom — the claim this row makes.
      for (final phrase in [
        'relay',
        "Google's Firebase Cloud Messaging",
        'no message and no sender',
        '30 days',
      ]) {
        expect(l.stPushOnHelp, contains(phrase));
      }
      await t.runAsync(push.init);
      await open(t);
      await settleUntil(t, () => shows(t, l.stPushOnHelp),
          what: 'push on and allowed');

      // Not allowed: nothing registered, and offline, so the relay has yet to
      // hear that it should forget whatever it held.
      platform.allowed = false;
      await t.runAsync(push.onResume);
      await settleUntil(t, () => shows(t, l.stPushNotAllowedPendingHelp),
          what: 'notifications not allowed, withdrawal pending');

      // Off.
      platform.allowed = true;
      await t.runAsync(() => push.setEnabled(false));
      await settleUntil(t, () => shows(t, l.stPushOffPendingHelp),
          what: 'push off, withdrawal pending');

      // And receipts are a switch beside it, saying what turning them off
      // costs.
      expect(shows(t, l.stReceiptsOnHelp), isTrue);
      await t.runAsync(() => svc.setSendsReceipts(false));
      await settleUntil(t, () => shows(t, l.stReceiptsOffHelp),
          what: 'receipts off');
      expect(svc.sendsReceipts, isFalse);
    });
  });
}
