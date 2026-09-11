// §18.9's last paragraph: what happens when the post-quantum signature does
// not arrive.
//
// A device-list signature travels as its own ~16 KB envelope on a delayed
// schedule, which makes it the single easiest thing on the wire for a relay to
// drop: it is the only envelope of that size an ordinary conversation
// produces. Dropping it leaves the list CLASSICALLY verified — everything
// keeps working, nothing fails, and the account quietly never gets the
// protection phase 13 was built for.
//
// It cannot be prevented at the network layer. It can be noticed, and the hard
// part is noticing it without crying wolf: a contact running an older v3 build
// has a post-quantum identity and simply never signs its lists, and treating
// that as an attack would train people to ignore the warning. So the sender
// says, inside the ratchet where it cannot be stripped, that it has SENT the
// signature — and only a claim with no signature behind it is a problem.
@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/models.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:z_protocol/z_protocol.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  late Process relay;
  late int port;
  final temps = <Directory>[];
  final services = <ChatService>[];

  setUpAll(() async {
    HttpOverrides.global = null;
    final serverDir =
        '${Directory.current.parent.path}${Platform.pathSeparator}server';
    // An OS-assigned free port, as group_test.dart does: the clock formula
    // this replaced gave two suites starting in the same millisecond the
    // same port, and `flutter test` runs files concurrently.
    final portProbe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    port = portProbe.port;
    await portProbe.close();
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
    for (final s in services) {
      await s.transport.stop();
    }
    relay.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<ChatService> start(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_sup_$name');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final id = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(id.toJson()));
    final transport =
        Transport(identity: id, serverUrl: 'ws://127.0.0.1:$port');
    final svc = await ChatService.init(
        vault: vault, identity: id, displayName: name, transport: transport);
    svc.pqListDelay = const Duration(milliseconds: 150);
    svc.devlistGrace = const Duration(seconds: 3);
    services.add(svc);
    return svc;
  }

  Future<void> waitUntil(bool Function() cond,
      {Duration timeout = const Duration(seconds: 25),
      String what = ''}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 30));
    }
  }

  /// Two accounts talking, the second with a linked device so it has a list
  /// worth signing.
  Future<(ChatService, ChatService)> pairWithDevice(String a, String b,
      {PqListSuppression mode = PqListSuppression.none}) async {
    final x = await start(a);
    final y = await start(b);
    // Set BEFORE the list exists: delivery follows signing by 150 ms here, so
    // switching it afterwards would race the thing being modelled.
    y.debugSuppressPqList = mode;
    await waitUntil(() => x.transport.isConnected && y.transport.isConnected,
        what: 'connected');
    await x.addContactFromCode(await y.myContactCode());
    await y.addContactFromCode(await x.myContactCode());
    await x.sendText(y.myRid, 'hi');
    await y.sendText(x.myRid, 'hi back');
    final acct = await y.accountIdentity();
    final laptop = await ZIdentity.generate();
    await y.addMyDevice(await acct.signDeviceCert(
        deviceEdPub: laptop.edPub,
        deviceXPub: laptop.xPub,
        deviceId: 'laptop'));
    return (x, y);
  }

  test('the honest case raises nothing', () async {
    final (alice, ben) = await pairWithDevice('h1', 'h2');
    await waitUntil(
        () => alice.deviceAssuranceWith(ben.myRid) == DeviceAssurance.hybrid,
        what: 'settles');
    await Future<void>.delayed(alice.devlistGrace * 2);
    await ben.sendText(alice.myRid, 'still here');
    await Future<void>.delayed(const Duration(seconds: 1));
    expect(alice.pqListAlerts[ben.myRid], isNull);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('a contact whose client never signs its lists is NOT accused', () async {
    // The cry-wolf case, and the reason the claim exists. An older v3 build
    // has a post-quantum identity — it emits `pqid`, so its contacts reach
    // `hybrid` — and simply never signs its device lists. Nothing has been
    // suppressed and nobody is under attack; treating this as an alarm would
    // teach people that the alarm means nothing.
    final (alice, ben) =
        await pairWithDevice('o1', 'o2', mode: PqListSuppression.silent);
    // Keep talking well past the grace period: an alarm that needed silence
    // to stay quiet would not be worth much.
    for (var i = 0; i < 8; i++) {
      await ben.sendText(alice.myRid, 'hello from an older build $i');
      await Future<void>.delayed(const Duration(milliseconds: 600));
    }

    expect(alice.deviceAssuranceWith(ben.myRid), DeviceAssurance.classical,
        reason: 'honestly reported as classical…');
    expect(alice.pqListAlerts[ben.myRid], isNull,
        reason: '…but not as an attack');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('a signature dropped in flight is asked for again, not alarmed about',
      () async {
    // Most losses are innocent: a connection dropped mid-send, an outbox that
    // did not flush. Alarming on the first miss would make the alarm noise, so
    // the claim triggers a request first.
    final (alice, ben) =
        await pairWithDevice('d1', 'd2', mode: PqListSuppression.claimOnly);
    unawaited(() async {
      for (var i = 0; i < 40; i++) {
        try {
          await ben.sendText(alice.myRid, 'ping $i');
        } catch (_) {}
        await Future<void>.delayed(const Duration(milliseconds: 400));
      }
    }());
    await waitUntil(() => alice.pqListRequestsSent(ben.myRid) > 0,
        what: 'alice asks for the signature she was told about');
    // Delivery resumes, as it would when the connection recovers.
    ben.debugSuppressPqList = PqListSuppression.none;
    await waitUntil(
        () => alice.deviceAssuranceWith(ben.myRid) == DeviceAssurance.hybrid,
        what: 'the repair works');
    expect(alice.pqListAlerts[ben.myRid], isNull,
        reason: 'a loss that repairs itself is not an attack');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('a signature suppressed persistently is surfaced', () async {
    // The attack §18.9 names. Ben's client says, inside the ratchet where it
    // cannot be stripped, that it has sent the signature; Alice never receives
    // one, and asking does not help. Something between them is removing the
    // one envelope that carries post-quantum protection, and Alice is told —
    // because a list that stays classical for ever is exactly what an attacker
    // wants and exactly what looks like nothing at all.
    final (alice, ben) =
        await pairWithDevice('s1', 's2', mode: PqListSuppression.claimOnly);
    unawaited(() async {
      for (var i = 0; i < 60; i++) {
        try {
          await ben.sendText(alice.myRid, 'ping $i');
        } catch (_) {}
        await Future<void>.delayed(const Duration(milliseconds: 500));
      }
    }());
    await waitUntil(() => alice.pqListAlerts[ben.myRid] != null,
        timeout: const Duration(seconds: 40),
        what: 'alice is told the signature never arrives');
    expect(alice.pqListAlerts[ben.myRid], contains('post-quantum'));
    expect(alice.deviceAssuranceWith(ben.myRid), DeviceAssurance.classical,
        reason: 'and nothing was accepted on the strength of the claim');
  }, timeout: const Timeout(Duration(minutes: 3)));
}
