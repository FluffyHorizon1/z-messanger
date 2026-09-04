// Protocol v2 periodic re-key (7.5b) end to end: two real ChatService
// instances over the real relay establish the post-quantum secret, then rotate
// it to a new generation while messages keep flowing — including a message that
// crosses the rotation boundary out of order. Post-compromise security for the
// PQ layer: a state stolen at one generation cannot decrypt the next.
@Tags(['integration'])
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
    final serverDir =
        '${Directory.current.parent.path}${Platform.pathSeparator}server';
    port = 41000 + DateTime.now().millisecondsSinceEpoch % 20000;
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
    final dir = await Directory.systemTemp.createTemp('z_rk_$name');
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

  Future<void> waitUntil(Future<bool> Function() cond,
      {Duration timeout = const Duration(seconds: 30), String? what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: ${what ?? ''}');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  List<String> texts(ChatService svc, String rid) => [
        for (final m in svc.messagesByChat[rid] ?? const [])
          if (m.kind == 'text') m.body
      ];

  test('a conversation rotates its post-quantum secret and keeps talking',
      () async {
    final alice = await makeClient('alice');
    final bob = await makeClient('bob');
    await waitUntil(
        () async => alice.transport.isConnected && bob.transport.isConnected,
        what: 'clients connect');
    final aliceRid = alice.myRid, bobRid = bob.myRid;
    final initiator = aliceRid.compareTo(bobRid) < 0 ? alice : bob;
    final offerer = identical(initiator, alice) ? bob : alice;
    final initiatorRid = identical(initiator, alice) ? aliceRid : bobRid;
    final offererRid = identical(initiator, alice) ? bobRid : aliceRid;

    await offerer.addContactFromCode(await initiator.myContactCode());
    await initiator.addContactFromCode(await offerer.myContactCode());

    // Establish generation 0 (the first exchange), exactly as 7.5.
    await waitUntil(() => initiator.isPostQuantumWith(offererRid),
        what: 'initiator holds gen0');
    await initiator.sendText(offererRid, 'g0-a');
    await waitUntil(() async => texts(offerer, initiatorRid).contains('g0-a'),
        what: 'gen0 message delivered');
    await offerer.sendText(initiatorRid, 'g0-b');
    await waitUntil(() async => texts(initiator, offererRid).contains('g0-b'),
        what: 'gen0 reply delivered');
    // At the default (week-long) interval the secret does NOT rotate just from
    // traffic — it stays on generation 0.
    expect(await initiator.pqGenerationWith(offererRid), 0);
    expect(await offerer.pqGenerationWith(initiatorRid), 0);

    // Now shorten the interval so the offerer re-offers on its next send; a few
    // round trips complete the rotation on BOTH sides.
    initiator.pqRekeyInterval = 1;
    offerer.pqRekeyInterval = 1;
    for (var i = 0; i < 6; i++) {
      await offerer.sendText(initiatorRid, 'r$i');
      await initiator.sendText(offererRid, 's$i');
      await waitUntil(
          () async =>
              texts(initiator, offererRid).contains('r$i') &&
              texts(offerer, initiatorRid).contains('s$i'),
          what: 'round $i delivered');
    }

    await waitUntil(
        () async => await initiator.pqGenerationWith(offererRid) >= 1,
        what: 'initiator rotated to gen >= 1');
    await waitUntil(
        () async => await offerer.pqGenerationWith(initiatorRid) >= 1,
        what: 'offerer rotated to gen >= 1');
    expect(await initiator.isPostQuantumWith(offererRid), isTrue);

    // Stop rotating and let the crossover settle; the two sides then converge
    // on the same generation (during continuous re-keying they legitimately
    // leapfrog by one).
    initiator.pqRekeyInterval = pqRekeyIntervalMs;
    offerer.pqRekeyInterval = pqRekeyIntervalMs;
    for (var i = 0; i < 4; i++) {
      await initiator.sendText(offererRid, 't$i');
      await offerer.sendText(initiatorRid, 'u$i');
      await waitUntil(
          () async =>
              texts(offerer, initiatorRid).contains('t$i') &&
              texts(initiator, offererRid).contains('u$i'),
          what: 'settle round $i delivered');
    }
    await waitUntil(
        () async =>
            await initiator.pqGenerationWith(offererRid) ==
            await offerer.pqGenerationWith(initiatorRid),
        what: 'generations converge once rotation stops');

    // Everything sent still arrived, exactly once, across every generation.
    final gotByOfferer = texts(offerer, initiatorRid);
    final gotByInitiator = texts(initiator, offererRid);
    for (var i = 0; i < 6; i++) {
      expect(gotByOfferer.where((t) => t == 's$i').length, 1, reason: 's$i');
      expect(gotByInitiator.where((t) => t == 'r$i').length, 1, reason: 'r$i');
    }
    for (var i = 0; i < 4; i++) {
      expect(gotByOfferer.where((t) => t == 't$i').length, 1, reason: 't$i');
      expect(gotByInitiator.where((t) => t == 'u$i').length, 1, reason: 'u$i');
    }
  }, timeout: const Timeout(Duration(minutes: 3)), retry: 2);
}
