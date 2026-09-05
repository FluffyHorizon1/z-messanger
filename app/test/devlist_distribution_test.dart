// 7.7a hardening: self-healing device-list distribution.
//
// The gossip echoes from 7.7a double as a repair channel. This proves, over
// the real relay:
//   1. a contact added AFTER a device was linked still learns the device list
//      (no explicit broadcast happens at that point — the echo triggers it);
//   2. a linked device that missed the root's list (linked before 7.7a, lost
//      sync) is caught up by its root and raises NO false owner alert when a
//      contact's honest echo is newer than what it knew;
//   3. an owner alert raised while the root was unreachable clears itself once
//      the root's answer shows the echo was an honest update.
// The rogue cases in devlist_transparency_test.dart must keep passing: there
// the root cannot explain the echo, so the alert stands.
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

  const grace = Duration(milliseconds: 700);

  Future<Vault> freshVault(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_dd_$name');
    temps.add(dir);
    return Vault.open(rootOverride: dir);
  }

  ChatService register(ChatService s) {
    s.devlistGrace = grace;
    services.add(s);
    return s;
  }

  Future<ChatService> makePrimary(String name, ZIdentity id) async {
    final vault = await freshVault(name);
    await vault.kvPut('identity', jsonEncode(id.toJson()));
    final transport =
        Transport(identity: id, serverUrl: 'ws://127.0.0.1:$port');
    return register(await ChatService.init(
        vault: vault, identity: id, displayName: name, transport: transport));
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
    return register(await ChatService.init(
        vault: vault,
        identity: devId,
        displayName: name,
        transport: transport));
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

  Future<bool> reaches(Future<int> Function() read, int want) async {
    final deadline = DateTime.now().add(const Duration(seconds: 15));
    while (DateTime.now().isBefore(deadline)) {
      if (await read() >= want) return true;
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
    return false;
  }

  List<String> texts(ChatService svc, String rid) => [
        for (final m in svc.messagesByChat[rid] ?? const [])
          if (m.kind == 'text') m.body
      ];

  // Phone (root) with a linked laptop at v2 = {phone, laptop}; NO contacts yet.
  Future<
      ({
        ChatService phone,
        ChatService laptop,
        AccountIdentity account,
        DeviceCertificate laptopCert,
      })> linkedAccount() async {
    final phoneId = await ZIdentity.generate();
    final phone = await makePrimary('phone', phoneId);
    final account = await phone.accountIdentity();
    final laptopId = await ZIdentity.generate();
    final laptopCert = await account.signDeviceCert(
        deviceEdPub: laptopId.edPub,
        deviceXPub: laptopId.xPub,
        deviceId: 'laptop');
    final laptop = await makeLinked(
        'laptop', laptopId, account, laptopCert, account.deviceCert);
    await waitUntil(
        () => phone.transport.isConnected && laptop.transport.isConnected);
    await phone.addMyDevice(laptopCert); // v2, self-synced to the laptop
    expect(await reaches(() => laptop.ownDeviceListVersion(), 2), isTrue,
        reason: 'laptop never learned v2');
    return (
      phone: phone,
      laptop: laptop,
      account: account,
      laptopCert: laptopCert
    );
  }

  test('a contact added after linking learns the device list on first exchange',
      () async {
    final a = await linkedAccount();
    final carol = await makePrimary('carol', await ZIdentity.generate());
    await waitUntil(() => carol.transport.isConnected);

    // Carol is added AFTER the laptop was linked, and adds the account back.
    // Whichever side is the designated initiator, no broadcast is triggered
    // here — only hellos (and, if the phone initiates, an introduction that
    // may be dropped because Carol had not added it yet).
    await carol.addContactFromCode(await a.phone.myContactCode());
    await a.phone.addContactFromCode(await carol.myContactCode());
    await laptopAddsCarol(a.laptop, carol);

    // Carol's first message echoes the baseline (v1) list she holds for the
    // account; the phone sees the stale echo and hands over its v2 list.
    await carol.sendText(a.phone.myRid, 'hello there');
    await waitUntil(() => texts(a.phone, carol.myRid).contains('hello there'));
    expect(await reaches(() => carol.heldContactListVersion(a.phone.myRid), 2),
        isTrue,
        reason: 'Carol never received the device list via the echo path');

    // And from now on Carol reaches the laptop directly: her next message is
    // fanned out to it (the laptop sees it as a message from Carol).
    await carol.sendText(a.phone.myRid, 'direct to both');
    await waitUntil(
        () => texts(a.laptop, carol.myRid).contains('direct to both'),
        timeout: const Duration(seconds: 25));
  }, timeout: const Timeout(Duration(minutes: 2)), retry: 2);

  test('a stale linked device is caught up by its root — no false alert',
      () async {
    final a = await linkedAccount();
    final carol = await makePrimary('carol', await ZIdentity.generate());
    await waitUntil(() => carol.transport.isConnected);
    await carol.addContactFromCode(await a.phone.myContactCode());
    await a.phone.addContactFromCode(await carol.myContactCode());
    await laptopAddsCarol(a.laptop, carol);
    // Carol gets the v2 list (introduction or echo path) and so fans to the
    // laptop.
    await carol.sendText(a.phone.myRid, 'warm-up');
    expect(await reaches(() => carol.heldContactListVersion(a.phone.myRid), 2),
        isTrue);

    // Simulate a laptop that never learned its account's list (linked before
    // 7.7a): forget the own-list knowledge and drop back to the v1 baseline.
    await a.laptop.vault.kvDelete('own_list_v');
    await a.laptop.vault.kvDelete('own_list_h');
    await a.laptop.vault.kvPut('my_devlist_version', '1', sensitive: false);
    expect(await a.laptop.ownDeviceListVersion(), 1);

    // Carol's next message reaches the laptop directly with pdl = v2 — newer
    // than the laptop knows. Rather than alarming, the laptop asks its root,
    // which answers with the honest v2 list; the pending check clears.
    await carol.sendText(a.phone.myRid, 'how are you');
    await waitUntil(() => texts(a.laptop, carol.myRid).contains('how are you'));
    expect(await reaches(() => a.laptop.ownDeviceListVersion(), 2), isTrue,
        reason: 'laptop was not caught up by its root');
    await Future<void>.delayed(grace + const Duration(seconds: 1));
    expect(a.laptop.ownAccountAlert, isNull,
        reason: 'an honest, merely-missed update must not raise the alert');
  }, timeout: const Timeout(Duration(minutes: 2)), retry: 2);

  test('an alert raised while the root was offline clears when it answers',
      () async {
    final a = await linkedAccount();
    final carol = await makePrimary('carol', await ZIdentity.generate());
    await waitUntil(() => carol.transport.isConnected);
    await carol.addContactFromCode(await a.phone.myContactCode());
    await a.phone.addContactFromCode(await carol.myContactCode());
    await laptopAddsCarol(a.laptop, carol);
    await carol.sendText(a.phone.myRid, 'warm-up');
    expect(await reaches(() => carol.heldContactListVersion(a.phone.myRid), 2),
        isTrue);
    // Carol must already reach the laptop directly before the phone goes away.
    await carol.sendText(a.phone.myRid, 'reach check');
    await waitUntil(() => texts(a.laptop, carol.myRid).contains('reach check'));

    // Stale laptop again, but this time the root is unreachable.
    await a.laptop.vault.kvDelete('own_list_v');
    await a.laptop.vault.kvDelete('own_list_h');
    await a.laptop.vault.kvPut('my_devlist_version', '1', sensitive: false);
    await a.phone.transport.stop();

    await carol.sendText(a.phone.myRid, 'while phone is off');
    await waitUntil(
        () => texts(a.laptop, carol.myRid).contains('while phone is off'));
    // No answer can arrive: after the grace period the laptop must alert —
    // it cannot tell an honest missed update from a rogue list on its own.
    await waitUntil(() => a.laptop.ownAccountAlert != null,
        timeout: grace + const Duration(seconds: 5));

    // The root returns, receives the queued request and answers with its
    // honest v2 list, which explains the echo: the alert clears itself.
    a.phone.transport.start();
    await waitUntil(() => a.phone.transport.isConnected);
    await waitUntil(() => a.laptop.ownAccountAlert == null,
        timeout: const Duration(seconds: 25));
    expect(await a.laptop.ownDeviceListVersion(), 2);
  }, timeout: const Timeout(Duration(minutes: 2)), retry: 2);
}

/// The laptop needs Carol as a contact to decrypt what she fans to it.
Future<void> laptopAddsCarol(ChatService laptop, ChatService carol) async {
  await laptop.addContactFromCode(await carol.myContactCode());
}
