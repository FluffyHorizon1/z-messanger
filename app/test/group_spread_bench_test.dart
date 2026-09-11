// What a group message looks like from the relay's side.
//
// Z has no group key and no group id on the wire: a group message is one
// pairwise-encrypted envelope per member, sent one after another over the
// sender's single socket. The relay therefore sees N mailboxes each receive a
// same-bucket envelope within a few tens of milliseconds — and it sees the
// same N mailboxes do so every time anyone in the group speaks. The trust
// table used to say the relay "cannot learn who is in a group"; that is true
// of any one envelope and false of the pattern. This measures the pattern so
// THREAT_MODEL.md R18 quotes a number rather than an adjective.
//
// A measurement, not an assertion — the spread depends on the machine and the
// relay. Run it deliberately:
//
//     flutter test test/group_spread_bench_test.dart --tags bench
//
// What it prints, per message: the spread between the earliest and latest
// relay timestamp on the members' copies, and how long after the send the
// first copy was stamped. Measured 2026-09-11 (five members, one relay on
// loopback): 64–135 ms spread, first copy stamped 15–25 ms after the send.
@Tags(['bench'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/chat_service.dart';
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
    // An OS-assigned free port. The old formula derived the port from the
    // clock, so two suites starting in the same millisecond got the SAME
    // port — and `flutter test` runs files concurrently, so one relay lost
    // the bind and its whole file failed in setUpAll with 'relay did not
    // start'. Asking the OS removes the shared input entirely.
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

  Future<ChatService> makeClient(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_gsp_$name');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final identity = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(identity.toJson()));
    final transport =
        Transport(identity: identity, serverUrl: 'ws://127.0.0.1:$port');
    final svc = await ChatService.init(
        vault: vault,
        identity: identity,
        displayName: name,
        transport: transport);
    services.add(svc);
    return svc;
  }

  Future<void> waitUntil(bool Function() cond,
      {Duration timeout = const Duration(seconds: 30), String? what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: ${what ?? ''}');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  List<String> groupTexts(ChatService svc, String gid) => [
        for (final m in svc.messagesByChat[gid] ?? const [])
          if (m.kind == 'gtext') m.body
      ];

  test('a group message reaches every other member within one burst', () async {
    final alice = await makeClient('Alice');
    final members = [for (var i = 0; i < 4; i++) await makeClient('M$i')];
    await waitUntil(
        () =>
            alice.transport.isConnected &&
            members.every((m) => m.transport.isConnected),
        what: 'everyone connected');
    for (final m in members) {
      await alice.addContactFromCode(await m.myContactCode());
      await m.addContactFromCode(await alice.myContactCode());
    }
    await Future<void>.delayed(const Duration(seconds: 2));
    final gid =
        await alice.createGroup('Five', [for (final m in members) m.myRid]);
    await waitUntil(() => members.every((m) => m.groups.containsKey(gid)),
        what: 'the group exists everywhere');
    await Future<void>.delayed(const Duration(seconds: 2));

    // Stamp every inbound envelope per member from here on, as the relay
    // stamped it (`serverTs`) and as it arrived.
    final stamps = <int, List<(int server, int local)>>{};
    for (var i = 0; i < members.length; i++) {
      final orig = members[i].transport.onMessage;
      stamps[i] = [];
      members[i].transport.onMessage = (m) {
        stamps[i]!.add((m.serverTs, DateTime.now().millisecondsSinceEpoch));
        orig?.call(m);
      };
    }
    final spreads = <int>[];
    for (var k = 0; k < 5; k++) {
      for (final s in stamps.values) {
        s.clear();
      }
      final t0 = DateTime.now().millisecondsSinceEpoch;
      await alice.sendGroupText(gid, 'msg $k');
      await waitUntil(
          () => members.every((m) => groupTexts(m, gid).contains('msg $k')),
          what: 'msg $k everywhere');
      final firsts = [for (final s in stamps.values) s.first];
      final srv = firsts.map((e) => e.$1).toList()..sort();
      final spread = srv.last - srv.first;
      spreads.add(spread);
      // ignore: avoid_print
      print('msg $k: relay-stamped spread $spread ms across '
          '${members.length} mailboxes; first copy stamped '
          '+${srv.first - t0} ms after the send');
    }
    // The one thing asserted: the copies are a burst, not a trickle. If this
    // ever fails because the fan-out was deliberately spread out, R18 in
    // THREAT_MODEL.md needs rewriting, which is the point of asserting it.
    expect(spreads.reduce((a, b) => a > b ? a : b), lessThan(2000),
        reason: 'one group message is one burst at the relay: $spreads');
  }, timeout: const Timeout(Duration(minutes: 3)));
}
