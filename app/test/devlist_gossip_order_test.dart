// A contact's device-list claims are judged in the order their devices made
// them (PROTOCOL §3.6), so nothing an honest account does makes one of its
// devices look as if it went back a version — and the banner that says a
// device did still comes up for what it is for.
//
// Every inner message carries its sender's claim about its own account's
// list (`dl`), and a receiver tells its user that a contact's device list
// went back (`dl_rollback`) when one of that contact's devices claims a
// version below one it claimed before. Someone holding the account's key and
// an older backup of it, speaking as one of its devices after that device
// has claimed the newer list, makes exactly that. Through 4.7.2 an honest
// account made it too: device_pop_test 4 failed on it once in five runs of
// the whole file — Vic shown that Bob's list had rolled back.
//
// The receiver recorded a claim as the message's last step, after its list
// (if it carried one) was installed, and its contact's own door takes the
// steps of two messages from one device in no fixed order: an install waits
// behind every other install, a `pqid` waits for nothing. Bob's version 2,
// read first, was recorded after his version 3, read next.
//
// Real clients through the real relay; no transparency log. An order the
// fault met by luck is made here with a seam that holds one message's steps
// once it has been read (`debugBeforeInboundActs`).
//
// Criteria, each a test below:
//   1. a contact's list whose message is read and then held, while the same
//      device's next list is read and acted on, raises nothing when it is
//      acted on after it, and is refused as the older list it is (on
//      4a716af it raises dl_rollback, as device_pop_test 4 met);
//   2. the banner still comes up for what it exists for: a backup of the
//      account from before its last list, run by someone holding it as the
//      account's own device after that device has claimed the newer list,
//      raises dl_rollback at once — with no grace to wait out, so nothing
//      else here can raise anything — and the list it hands over is refused.
@Tags(['integration'])
@Timeout(Duration(minutes: 4))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart' show DatabaseException;
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/key_transparency.dart';
import 'package:zapp/core/receipts.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:z_protocol/z_protocol.dart';

// Receipts within 300 ms rather than ADR 0028's 5 s to a minute: what is
// counted here is claims, not when a tick turns (as device_pop_test).
const promptReceipts =
    ReceiptTiming(floor: Duration.zero, ceiling: Duration(milliseconds: 300));

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  late Process relay;
  late int port;
  final dirs = <String, Directory>{};
  final live = <ChatService>[];

  // Each service runs in an error zone of its own; an error raised inside a
  // running service fails the test that was running — except the one a
  // service [stop] has shut down still has in flight against the database
  // it closed.
  final stopped = <ChatService>{};
  final strays = <String>[];

  Future<void> stop(ChatService svc) async {
    stopped.add(svc);
    svc.dispose();
    await svc.transport.stop();
    live.remove(svc);
    await svc.vault.db.close();
  }

  tearDown(() async {
    for (final s in live.toList()) {
      await stop(s);
    }
    final found = [...strays];
    strays.clear();
    expect(found, isEmpty, reason: 'errors raised inside a running service');
  });

  setUpAll(() async {
    HttpOverrides.global = null;
    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    port = probe.port;
    await probe.close();
    relay = await Process.start('node', ['server.js'],
        workingDirectory:
            '${Directory.current.parent.path}${Platform.pathSeparator}server',
        environment: {'PORT': '$port', 'LOG_LEVEL': 'silent'});
    var ok = false;
    for (var i = 0; i < 100 && !ok; i++) {
      try {
        final res = await (await HttpClient()
                .getUrl(Uri.parse('http://127.0.0.1:$port/health')))
            .close();
        await res.drain<void>();
        ok = res.statusCode == 200;
      } catch (_) {}
      if (!ok) await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    if (!ok) fail('relay did not start');
  });

  tearDownAll(() async {
    relay.kill();
    for (final d in dirs.values) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<ChatService> run(String name, Vault vault, ZIdentity id) {
    final ready = Completer<ChatService>();
    ChatService? made;
    runZonedGuarded(() async {
      try {
        final svc = await ChatService.init(
          vault: vault,
          identity: id,
          displayName: name,
          transport: Transport(identity: id, serverUrl: 'ws://127.0.0.1:$port'),
          // The versions counted here are the ones these tests link devices
          // for; ADR 0029's one-time move to v2-only signing would land a
          // version of its own among them (as device_pop_test).
          signDevlistV2Only: false,
          receiptTiming: promptReceipts,
          ktConfig: KtConfig.off,
        );
        made = svc;
        live.add(svc);
        ready.complete(svc);
      } catch (e, st) {
        ready.completeError(e, st);
      }
    }, (e, st) {
      final svc = made;
      if (svc != null &&
          stopped.contains(svc) &&
          e is DatabaseException &&
          e.isDatabaseClosedError()) {
        return;
      }
      strays.add('$name: $e\n$st');
    });
    return ready.future;
  }

  /// A new account called [name].
  Future<ChatService> start(String name) async {
    final dir = dirs[name] = await Directory.systemTemp.createTemp('z_ord_$name');
    final vault = await Vault.open(rootOverride: dir);
    final id = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(id.toJson()));
    return run(name, vault, id);
  }

  Future<void> waitUntil(FutureOr<bool> Function() cond,
      {required String what,
      Duration timeout = const Duration(seconds: 30)}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  bool linked(ChatService s) =>
      s.transport.isConnected && s.transport.isSenderConnected;

  bool received(ChatService svc, String rid, String body) =>
      svc.messagesByChat[rid]?.any((m) => !m.outgoing && m.body == body) ==
      true;

  /// Two accounts that have exchanged codes and a message each way.
  Future<void> introduce(ChatService a, ChatService b) async {
    await waitUntil(() => linked(a) && linked(b), what: 'both connected');
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
    await a.sendText(b.myRid, 'hello ${b.displayName}');
    await b.sendText(a.myRid, 'hello ${a.displayName}');
    await waitUntil(
        () =>
            received(a, b.myRid, 'hello ${a.displayName}') &&
            received(b, a.myRid, 'hello ${b.displayName}'),
        what: '${a.displayName} and ${b.displayName} have spoken');
  }

  /// A device of [owner]'s account that runs no client: a certificate its
  /// account signed over keys nobody here uses. Linking one moves the
  /// account's list a version.
  Future<DeviceCertificate> deviceOf(ChatService owner, String id) async {
    final d = await ZIdentity.generate();
    return (await owner.accountIdentity())
        .signDeviceCert(deviceEdPub: d.edPub, deviceXPub: d.xPub, deviceId: id);
  }

  /// The version [inner] claims for its sender's own account's list.
  int? claimOf(InnerMessage inner) {
    final dl = inner.data['dl'];
    return dl is Map && dl['v'] is num ? (dl['v'] as num).toInt() : null;
  }

  /// The kind of the device-list alert [svc] holds on [rid]'s chat.
  String? alertKind(ChatService svc, String rid) {
    final s = svc.contactDevlistAlerts[rid];
    return s == null ? null : (jsonDecode(s) as Map)['k'] as String?;
  }

  test(
      "1. a contact's list read and held while the device's next list is "
      'acted on raises nothing when it is acted on after it', () async {
    final vic = await start('vic1');
    final bob = await start('bob1');
    await introduce(vic, bob);

    // Bob links a device: version 2. Vic reads its message, stores it, and
    // what it says waits — as a list's install waits behind another on a
    // loaded device — while Bob links another and Vic reads and acts on
    // version 3.
    final release = Completer<void>();
    String? held;
    var heldActedOn = false;
    var nextActedOn = false;
    String? alertThen;
    vic.debugBeforeInboundActs = (rid, inner) async {
      if (rid != bob.myRid || held != null) return;
      if (inner.kind != 'devlist' || claimOf(inner) != 2) return;
      held = inner.mid;
      await release.future;
    };
    vic.debugInboundActedOn = (rid, inner) {
      if (rid != bob.myRid) return;
      if (inner.kind == 'devlist' && claimOf(inner) == 3) nextActedOn = true;
      if (inner.mid == held) {
        heldActedOn = true;
        // What the user is shown the moment version 2's message has been
        // acted on: before anything Bob sends afterwards can change it.
        alertThen = vic.contactDevlistAlerts[bob.myRid];
      }
    };
    await bob.addMyDevice(await deviceOf(bob, 'tablet'));
    await waitUntil(() => held != null,
        what: "Vic has read Bob's version 2, and holds what it says");
    await bob.addMyDevice(await deviceOf(bob, 'phone2'));
    await waitUntil(() => nextActedOn,
        what: "Vic reads and acts on Bob's version 3");
    expect(await vic.heldContactListVersion(bob.myRid), 3);
    expect(vic.contactDevlistAlerts[bob.myRid], isNull);

    release.complete();
    await waitUntil(() => heldActedOn,
        what: "Vic acts on Bob's version 2, after his version 3");
    expect(alertThen, isNull,
        reason: "Bob's device claimed version 2 and then version 3, in the "
            'order Vic read them: nothing went back');
    expect(vic.contactDevlistAlerts[bob.myRid], isNull);
    expect(await vic.heldContactListVersion(bob.myRid), 3,
        reason: 'version 2, read before version 3, is the older list');
  });

  test(
      '2. a backup of the account from before its last list, speaking as its '
      'device after that device claimed the newer one, raises dl_rollback',
      () async {
    final vic = await start('vic2');
    final bob = await start('bob2');
    // Nothing waits out a grace here: what is raised is the rollback rule's,
    // and an unconfirmed list's (§3.6) cannot be.
    vic.devlistGrace = const Duration(hours: 1);
    await introduce(vic, bob);
    await bob.addMyDevice(await deviceOf(bob, 'tablet'));
    await waitUntil(
        () async => await vic.heldContactListVersion(bob.myRid) == 2,
        what: "Vic installs Bob's version 2");

    // Bob's backup as it stands now — the device's identity, the account's
    // root, its devices at version 2 — in someone else's hands.
    final identity = (await bob.vault.kvGet('identity'))!;
    final account = jsonEncode((await bob.accountIdentity()).toJson());
    final devices = (await bob.vault.kvGet('my_devices'))!;

    // Bob moves on, and his device says so to Vic.
    await bob.addMyDevice(await deviceOf(bob, 'phone2'));
    await waitUntil(
        () async => await vic.heldContactListVersion(bob.myRid) == 3,
        what: "Vic installs Bob's version 3");
    await bob.sendText(vic.myRid, 'at version 3');
    await waitUntil(() => received(vic, bob.myRid, 'at version 3'),
        what: "Vic reads a message of Bob's claiming version 3");
    expect(vic.contactDevlistAlerts[bob.myRid], isNull);

    // Bob's device goes quiet, and the backup comes up as it.
    await stop(bob);
    final dir = dirs['bob2backup'] =
        await Directory.systemTemp.createTemp('z_ord_bob2backup');
    final vault = await Vault.open(rootOverride: dir);
    await vault.kvPut('identity', identity);
    await vault.kvPut('account', account);
    await vault.kvPut('my_devices', devices, sensitive: false);
    await vault.kvPut('my_devlist_version', '2', sensitive: false);
    final backup = await run(
        'bob2backup',
        vault,
        await ZIdentity.fromJson(
            (jsonDecode(identity) as Map).cast<String, Object?>()));
    expect(backup.myRid, bob.myRid, reason: "it speaks as Bob's device");
    expect(await backup.ownDeviceListVersion(), 2);
    await waitUntil(() => linked(backup), what: 'the backup connected');
    await backup.addContactFromCode(await vic.myContactCode());
    await backup.sendText(vic.myRid, 'still me');
    await waitUntil(() => received(vic, bob.myRid, 'still me'),
        what: 'Vic reads the backup, as Bob');

    await waitUntil(() => vic.contactDevlistAlerts[bob.myRid] != null,
        what: "Vic says Bob's device list went back");
    expect(alertKind(vic, bob.myRid), 'dl_rollback',
        reason: 'the same device claimed version 3 and then version 2');
    expect(await vic.heldContactListVersion(bob.myRid), 3,
        reason: 'the version 2 the backup hands over is refused');
  });
}
