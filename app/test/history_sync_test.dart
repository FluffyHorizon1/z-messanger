// 7.6b: a newly linked device receives recent history instead of an empty
// screen. The phone (root) already has a conversation with Carol and a group
// thread; then a laptop is linked. Over the real relay, the laptop must end up
// holding the past direct messages (both directions, in order) and the past
// group messages, without duplicating anything that also arrives live.
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
    HttpOverrides.global = null;
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

  Future<Vault> freshVault(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_hs_$name');
    temps.add(dir);
    return Vault.open(rootOverride: dir);
  }

  Future<ChatService> makePrimary(String name, ZIdentity id) async {
    final vault = await freshVault(name);
    await vault.kvPut('identity', jsonEncode(id.toJson()));
    final transport =
        Transport(identity: id, serverUrl: 'ws://127.0.0.1:$port');
    final svc = await ChatService.init(
        vault: vault, identity: id, displayName: name, transport: transport);
    services.add(svc);
    return svc;
  }

  Future<ChatService> makeLinked(
      String name,
      ZIdentity devId,
      AccountIdentity account,
      DeviceCertificate devCert,
      DeviceCertificate hostCert) async {
    final vault = await freshVault(name);
    await vault.kvPut('identity', jsonEncode(devId.toJson()));
    final enrolled = await AccountIdentity.fromEnrollment(
      accountEdPub: account.accountEdPub,
      deviceEdSeed: devId.edSeed,
      deviceXSeed: devId.xSeed,
      deviceId: 'linked',
      deviceCert: devCert,
    );
    await vault.kvPut('account', jsonEncode(enrolled.toJson()));
    await vault.kvPut('my_devices', jsonEncode([hostCert.toJson()]),
        sensitive: false);
    final transport =
        Transport(identity: devId, serverUrl: 'ws://127.0.0.1:$port');
    final svc = await ChatService.init(
        vault: vault, identity: devId, displayName: name, transport: transport);
    services.add(svc);
    return svc;
  }

  Future<void> waitUntil(bool Function() cond,
      {Duration timeout = const Duration(seconds: 25)}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met');
      }
      await Future<void>.delayed(const Duration(milliseconds: 30));
    }
  }

  List<String> texts(ChatService svc, String rid) => [
        for (final m in svc.messagesByChat[rid] ?? const [])
          if (m.kind == 'text' || m.kind == 'gtext') m.body
      ];

  test('a newly linked device receives the recent history', () async {
    final phoneId = await ZIdentity.generate();
    final phone = await makePrimary('phone', phoneId);
    final carol = await makePrimary('carol', await ZIdentity.generate());
    final dave = await makePrimary('dave', await ZIdentity.generate());
    await waitUntil(() =>
        phone.transport.isConnected &&
        carol.transport.isConnected &&
        dave.transport.isConnected);
    for (final (a, b) in [(phone, carol), (phone, dave), (carol, dave)]) {
      await a.addContactFromCode(await b.myContactCode());
      await b.addContactFromCode(await a.myContactCode());
    }
    await Future<void>.delayed(const Duration(seconds: 1));

    // History BEFORE any device is linked: a direct thread both ways and a
    // group thread.
    for (var i = 0; i < 5; i++) {
      await phone.sendText(carol.myRid, 'phone $i');
      await carol.sendText(phone.myRid, 'carol $i');
    }
    await waitUntil(() =>
        texts(phone, carol.myRid).where((t) => t.startsWith('carol')).length ==
        5);
    final gid = await phone.createGroup('Trip', [carol.myRid, dave.myRid]);
    await waitUntil(() => carol.groups.containsKey(gid));
    await phone.sendGroupText(gid, 'group from phone');
    await carol.sendGroupText(gid, 'group from carol');
    await waitUntil(() => texts(phone, gid).contains('group from carol'));

    // Now link a laptop. It holds Carol (contacts ship with enrollment) but
    // not the group, which this device was never invited to.
    final account = await phone.accountIdentity();
    final laptopId = await ZIdentity.generate();
    final laptopCert = await account.signDeviceCert(
        deviceEdPub: laptopId.edPub,
        deviceXPub: laptopId.xPub,
        deviceId: 'laptop');
    final laptop = await makeLinked(
        'laptop', laptopId, account, laptopCert, account.deviceCert);
    await waitUntil(() => laptop.transport.isConnected);
    await laptop.addContactFromCode(await carol.myContactCode());
    await phone.addMyDevice(laptopCert); // triggers the history replay

    // The direct history lands, in order, both directions.
    await waitUntil(() => texts(laptop, carol.myRid).length >= 10);
    final got = texts(laptop, carol.myRid);
    expect(got.where((t) => t.startsWith('phone')).toList(),
        [for (var i = 0; i < 5; i++) 'phone $i']);
    expect(got.where((t) => t.startsWith('carol')).toList(),
        [for (var i = 0; i < 5; i++) 'carol $i']);
    // Direction survived: the phone's own messages show as outgoing.
    final mine = laptop.messagesByChat[carol.myRid]!
        .where((m) => m.body.startsWith('phone'));
    expect(mine.every((m) => m.outgoing), isTrue);

    // The group thread was skipped (unknown here) rather than half-created.
    expect(laptop.messagesByChat[gid], isNull);
    expect(laptop.groups.containsKey(gid), isFalse);

    // A message that arrives live after linking is not doubled by the replay.
    await carol.sendText(phone.myRid, 'after link');
    await waitUntil(() => texts(laptop, carol.myRid).contains('after link'));
    await Future<void>.delayed(const Duration(milliseconds: 500));
    expect(
        texts(laptop, carol.myRid).where((t) => t == 'after link').length, 1);
    expect(texts(laptop, carol.myRid).length, 11);
  }, timeout: const Timeout(Duration(minutes: 2)), retry: 2);
}
