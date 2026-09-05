// Integration test for 7.7a device-list transparency (gossip).
//
// The scenario the ADR (docs/adr/0001-key-transparency.md) sets as the
// definition of done: an account with two honest devices (a phone that holds
// the root, and a linked laptop) has its root seed used by a THIRD, rogue
// device to publish a new device list. In case (a) the rogue publishes to the
// contact only (a split view: the owner's own devices are kept in the dark);
// in case (b) it publishes a list with the honest laptop removed. In BOTH
// cases an honest device and the contact must surface the corresponding alert.
// The control: an honest device added at the same version and distributed to
// everyone must raise nothing.
//
// The rogue holds the stolen backup, so it speaks as device #1 (the phone's
// keys) AND can sign a new device list — exactly the T1/T2/T3 attacker.
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

  // Short grace so the deferred (owner-echo / unconfirmed-list) checks resolve
  // quickly instead of the 8 s production default.
  const grace = Duration(milliseconds: 700);

  Future<Vault> freshVault(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_$name');
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

  // A rogue built from the stolen backup: it speaks as device #1 (the phone's
  // identity) and holds the account root, and is pre-seeded with the device
  // set + version it will publish.
  Future<ChatService> makeRogue(ZIdentity phoneId, AccountIdentity account,
      List<DeviceCertificate> myDevices, int version) async {
    final vault = await freshVault('rogue');
    await vault.kvPut('identity', jsonEncode(phoneId.toJson()));
    await vault.kvPut('account', jsonEncode(account.toJson()));
    await vault.kvPut(
        'my_devices', jsonEncode([for (final d in myDevices) d.toJson()]),
        sensitive: false);
    await vault.kvPut('my_devlist_version', '$version', sensitive: false);
    final transport =
        Transport(identity: phoneId, serverUrl: 'ws://127.0.0.1:$port');
    return register(await ChatService.init(
        vault: vault,
        identity: phoneId,
        displayName: 'phone',
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

  List<String> texts(ChatService svc, String rid) => [
        for (final m in svc.messagesByChat[rid] ?? const [])
          if (m.kind == 'text') m.body
      ];

  Future<bool> versionReaches(Future<int> Function() read, int want) async {
    final deadline = DateTime.now().add(const Duration(seconds: 15));
    while (DateTime.now().isBefore(deadline)) {
      if (await read() >= want) return true;
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
    return false;
  }

  // Stand up the phone (root), a linked laptop, and the contact Carol, all at
  // device-list version 2 = {phone, laptop}. Returns the pieces the scenarios
  // build on.
  Future<
      ({
        ChatService phone,
        ChatService laptop,
        ChatService carol,
        ZIdentity phoneId,
        AccountIdentity account,
        DeviceCertificate laptopCert,
        String accountRid,
      })> bringUpAccount() async {
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

    final carol = await makePrimary('carol', await ZIdentity.generate());

    await waitUntil(() =>
        phone.transport.isConnected &&
        laptop.transport.isConnected &&
        carol.transport.isConnected);

    final accountRid = phone.myRid;
    await carol.addContactFromCode(await phone.myContactCode());
    await phone.addContactFromCode(await carol.myContactCode());
    await laptop.addContactFromCode(await carol.myContactCode());

    // Root publishes v2={phone,laptop} to Carol and self-syncs it to the laptop.
    await phone.addMyDevice(laptopCert);

    // Carol learns the laptop; the laptop learns its own account is at v2.
    expect(
        await versionReaches(() => carol.heldContactListVersion(accountRid), 2),
        isTrue,
        reason: 'Carol never received the v2 device list');
    expect(await versionReaches(() => laptop.ownDeviceListVersion(), 2), isTrue,
        reason: 'the laptop never learned it is at v2');
    return (
      phone: phone,
      laptop: laptop,
      carol: carol,
      phoneId: phoneId,
      account: account,
      laptopCert: laptopCert,
      accountRid: accountRid,
    );
  }

  test('split view (a): a rogue list shown only to the contact is caught',
      () async {
    final s = await bringUpAccount();
    final rogueDevId = await ZIdentity.generate();
    final rogueCert = await s.account.signDeviceCert(
        deviceEdPub: rogueDevId.edPub,
        deviceXPub: rogueDevId.xPub,
        deviceId: 'rogue');

    // The phone goes offline; the attacker takes over device #1's mailbox.
    await s.phone.transport.stop();
    // Rogue publishes v3={phone,laptop,rogue} — but ONLY to Carol (a split
    // view: rule 8 self-sync deliberately skipped).
    final rogue =
        await makeRogue(s.phoneId, s.account, [s.laptopCert, rogueCert], 3);
    await waitUntil(() => rogue.transport.isConnected);
    await rogue.addContactFromCode(await s.carol.myContactCode());
    await rogue.broadcastMyDeviceList(alsoOwnDevices: false);
    expect(
        await versionReaches(
            () => s.carol.heldContactListVersion(s.accountRid), 3),
        isTrue,
        reason: 'Carol never installed the rogue v3 list');

    // Carol echoes the (rogue) list she now holds back to the account's
    // devices. The laptop sees a version it never received and asks its root
    // for the truth — but the rogue is squatting on the root's mailbox and
    // answers with its own v3, so the laptop swallows it for now. (A rogue
    // holding device #1's keys could always have pushed that list; the split
    // view is caught the moment the honest root is heard from again.)
    await s.carol.sendText(s.accountRid, 'hey');
    await waitUntil(() => texts(s.laptop, s.carol.myRid).contains('hey'));
    expect(
        await versionReaches(() => s.laptop.ownDeviceListVersion(), 3), isTrue,
        reason: 'the rogue, impersonating the root, fed the laptop its list');

    // The honest phone returns. Three independent detections follow:
    await rogue.transport.stop();
    s.phone.transport.start();
    await waitUntil(() => s.phone.transport.isConnected);
    // 1. On reconnect the phone re-asserts its honest v2 list to its own
    //    devices; the laptop holds v3 from "the root" — an honest root never
    //    regresses, so the laptop flags the newer list as signed by someone else.
    await waitUntil(() => s.laptop.ownAccountAlert != null);
    expect(s.laptop.ownAccountAlert, contains('older device list'),
        reason: 'the laptop did not flag the contradicting root sync');
    // 2. The phone speaks with its true (v2) claim; Carol sees device #1
    //    contradict the v3 list it was handed (a rollback on that device).
    await s.phone.sendText(s.carol.myRid, 'still me');
    await waitUntil(() => s.carol.contactDevlistAlerts[s.accountRid] != null);
    expect(s.carol.contactDevlistAlerts[s.accountRid], isNotNull,
        reason: 'Carol did not flag the contradictory device list');
    // 3. Carol's receipt back to the phone echoes v3 — a list the root never
    //    issued and cannot explain: after the grace period the root alerts.
    await waitUntil(() => s.phone.ownAccountAlert != null,
        timeout: const Duration(seconds: 25));
  }, timeout: const Timeout(Duration(minutes: 2)), retry: 2);

  test('exclusion (b): a rogue list that drops the honest device is caught',
      () async {
    final s = await bringUpAccount();
    final rogueDevId = await ZIdentity.generate();
    final rogueCert = await s.account.signDeviceCert(
        deviceEdPub: rogueDevId.edPub,
        deviceXPub: rogueDevId.xPub,
        deviceId: 'rogue');

    await s.phone.transport.stop();
    // Rogue publishes v3={phone,rogue} — the honest laptop is removed.
    final rogue = await makeRogue(s.phoneId, s.account, [rogueCert], 3);
    await waitUntil(() => rogue.transport.isConnected);
    await rogue.addContactFromCode(await s.carol.myContactCode());
    await rogue.broadcastMyDeviceList();
    expect(
        await versionReaches(
            () => s.carol.heldContactListVersion(s.accountRid), 3),
        isTrue,
        reason: 'Carol never installed the rogue v3 list');

    // Installing a list that drops the laptop, Carol sends it a removal notice
    // over the still-open pairwise session — which the rogue cannot suppress.
    await waitUntil(() => s.laptop.removedDeviceAlert != null);
    expect(s.laptop.removedDeviceAlert, isNotNull,
        reason: 'the removed laptop was never told it was cut off');

    // And the contact still catches the contradiction when device #1 returns.
    await rogue.transport.stop();
    s.phone.transport.start();
    await waitUntil(() => s.phone.transport.isConnected);
    await s.phone.sendText(s.carol.myRid, 'still me');
    await waitUntil(() => s.carol.contactDevlistAlerts[s.accountRid] != null);
    expect(s.carol.contactDevlistAlerts[s.accountRid], isNotNull);
  }, timeout: const Timeout(Duration(minutes: 2)), retry: 2);

  test('control: an honest device added and distributed to all raises nothing',
      () async {
    final s = await bringUpAccount();
    final tabletId = await ZIdentity.generate();
    final tabletCert = await s.account.signDeviceCert(
        deviceEdPub: tabletId.edPub,
        deviceXPub: tabletId.xPub,
        deviceId: 'tablet');

    // Honest enrolment: v3={phone,laptop,tablet}, broadcast to Carol AND
    // self-synced to the laptop (rule 8).
    await s.phone.addMyDevice(tabletCert);
    expect(
        await versionReaches(
            () => s.carol.heldContactListVersion(s.accountRid), 3),
        isTrue);
    expect(
        await versionReaches(() => s.laptop.ownDeviceListVersion(), 3), isTrue,
        reason: 'the laptop never caught up to the honest v3');

    // Traffic flows both ways; the echoes now match what every device knows.
    await s.carol.sendText(s.accountRid, 'nice');
    await s.phone.sendText(s.carol.myRid, 'thanks');

    // Give the grace window time to fire, then assert everything is quiet.
    await Future<void>.delayed(grace + const Duration(seconds: 1));
    expect(s.laptop.ownAccountAlert, isNull, reason: 'false owner alarm');
    expect(s.laptop.removedDeviceAlert, isNull, reason: 'false removal alarm');
    expect(s.phone.ownAccountAlert, isNull);
    expect(s.carol.contactDevlistAlerts[s.accountRid], isNull,
        reason: 'false contact alarm on an honest update');
  }, timeout: const Timeout(Duration(minutes: 2)), retry: 2);
}
