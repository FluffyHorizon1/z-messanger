// 13.1's last piece, and the phase's exit criterion: a device list that a
// quantum adversary cannot forge (§18.9, ADR 0004).
//
// The account signs its device list under ML-DSA-65 as well as Ed25519, over
// exactly the bytes §3.4 already defines — version and the sorted device
// keys. The post-quantum signature travels as its OWN message on an unrelated
// schedule, so the list keeps its 1024-byte padding bucket and its timing, and
// the 16 KB envelope the signature needs says nothing about when a device set
// changed.
//
// What these tests pin is the part that is easy to get wrong: the signature is
// worth nothing until it has been checked against the contact's account key,
// that key arrives on its own independent schedule, and either order must end
// in the same place.
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

  Future<ChatService> start(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_dlpq_$name');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final id = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(id.toJson()));
    final transport =
        Transport(identity: id, serverUrl: 'ws://127.0.0.1:$port');
    final svc = await ChatService.init(
        vault: vault, identity: id, displayName: name, transport: transport);
    // The production delay is hours, deliberately: it is what decorrelates the
    // signature from the list. Tests cannot wait, and the delay is not what is
    // under test here — the verification is.
    svc.pqListDelay = const Duration(milliseconds: 150);
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

  /// Two accounts that have exchanged codes and spoken once.
  Future<(ChatService, ChatService)> pair(String a, String b) async {
    final x = await start(a);
    final y = await start(b);
    await waitUntil(() => x.transport.isConnected && y.transport.isConnected,
        what: 'connected');
    await x.addContactFromCode(await y.myContactCode());
    await y.addContactFromCode(await x.myContactCode());
    await x.sendText(y.myRid, 'hi');
    await y.sendText(x.myRid, 'hi back');
    return (x, y);
  }

  test(
      'the list is usable before the signature arrives, and post-quantum '
      'verified after', () async {
    final (alice, ben) = await pair('alice2', 'ben2');
    final acct = await ben.accountIdentity();
    final laptop = await ZIdentity.generate();
    final cert = await acct.signDeviceCert(
        deviceEdPub: laptop.edPub, deviceXPub: laptop.xPub, deviceId: 'laptop');
    await ben.addMyDevice(cert);

    var version = 0;
    await waitUntil(() {
      unawaited(
          alice.heldContactListVersion(ben.myRid).then((v) => version = v));
      return version >= 2;
    }, what: 'alice installs the list');

    // It converges to hybrid on its own schedule. Before that it is
    // `classical` — correct today, forgeable by a quantum adversary later, and
    // §18.4 requires the two be told apart rather than the second presented as
    // the first.
    await waitUntil(
        () => alice.deviceAssuranceWith(ben.myRid) == DeviceAssurance.hybrid,
        what: 'the post-quantum signature arrives and checks');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('a signature for a different device set is refused', () async {
    // The attack ADR 0004 turns on, end to end: an adversary who can forge
    // Ed25519 presents a SUBSET of the genuine list. Every certificate in it
    // is genuine and the classical signature checks out — so only a signature
    // over the SET can catch it.
    final (alice, ben) = await pair('alice3', 'ben3');
    final acct = await ben.accountIdentity();
    final laptop = await ZIdentity.generate();
    final cert = await acct.signDeviceCert(
        deviceEdPub: laptop.edPub, deviceXPub: laptop.xPub, deviceId: 'laptop');
    await ben.addMyDevice(cert);
    await waitUntil(
        () => alice.deviceAssuranceWith(ben.myRid) == DeviceAssurance.hybrid,
        what: 'the honest list is verified first');

    // Ben's account never signed the one-device set at this version.
    final subset = await acct.signDeviceList([acct.deviceCert], 2);
    final sig = await ben.debugPqSignatureForCurrentList();
    expect(await sig!.verifies(subset, (await ben.pqAccountPublic())!), isFalse,
        reason: 'a genuine signature does not cover a set it never saw');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test(
      'a signature that arrives before the key it needs is held, not thrown '
      'away', () async {
    // The two schedules are independent by design (ADR 0004), so the signature
    // can land before the contact's ML-DSA key has arrived and matched its
    // commitment — and there is nothing to check it with until then. Dropping
    // it would make the two schedules depend on each other, which is the thing
    // being avoided.
    final alice = await start('alice4');
    final ben = await start('ben4');
    await waitUntil(
        () => alice.transport.isConnected && ben.transport.isConnected,
        what: 'connected');
    await alice.addContactFromCode(await ben.myContactCode());
    await ben.addContactFromCode(await alice.myContactCode());
    await alice.sendText(ben.myRid, 'hi');
    await ben.sendText(alice.myRid, 'hi back');

    final acct = await ben.accountIdentity();
    final laptop = await ZIdentity.generate();
    await ben.addMyDevice(await acct.signDeviceCert(
        deviceEdPub: laptop.edPub,
        deviceXPub: laptop.xPub,
        deviceId: 'laptop'));
    await waitUntil(
        () => alice.deviceAssuranceWith(ben.myRid) == DeviceAssurance.hybrid,
        what: 'settles normally');

    // Now replay the same signature onto a client that has forgotten Ben's
    // post-quantum key: it must be kept and applied when the key returns,
    // not discarded.
    expect(await alice.debugHeldPqListSignature(ben.myRid), isNotNull,
        reason: 'the signature is stored, not merely applied and forgotten');

    final benMl = (await ben.pqAccountPublic())!;
    await alice.vault.db.update('contacts', {'enc_pq_pub': null},
        where: 'rid = ?', whereArgs: [ben.myRid]);
    await alice.reloadContacts();
    expect(alice.deviceAssuranceWith(ben.myRid), DeviceAssurance.classical,
        reason: 'with no key there is nothing to check the signature with');

    await alice.vault.db.update(
        'contacts', {'enc_pq_pub': await alice.vault.seal(b64(benMl))},
        where: 'rid = ?', whereArgs: [ben.myRid]);
    await alice.reloadContacts();
    expect(alice.deviceAssuranceWith(ben.myRid), DeviceAssurance.hybrid,
        reason: 'the stored signature is re-checked when the key returns');
  }, timeout: const Timeout(Duration(minutes: 3)));
}
