// Phase 10 exit criteria, tested directly.
//
// M1–M5 were built incrementally across phases 3–7; what had never been
// demonstrated end to end is the promise the phase actually makes:
//
//   * a phone and a desktop both send and receive on one identity, with no
//     mailbox contention (each device has its own routing id, so the relay's
//     one-socket-per-id rule must never bite);
//   * the safety number does not move when a device is added or removed —
//     otherwise verification is worthless, because a contact cannot tell a
//     man-in-the-middle from a laptop being linked;
//   * a device-list update reaches a contact who was offline for the whole
//     enrollment.
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
    final dir = await Directory.systemTemp.createTemp('z_md_$name');
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
      deviceId: 'laptop',
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

  List<String> texts(ChatService svc, String rid) => [
        for (final m in svc.messagesByChat[rid] ?? const [])
          if (m.kind == 'text' || m.kind == 'gtext') m.body
      ];

  /// A phone holding the account root, a laptop linked to it, and Carol.
  Future<
      ({
        ChatService phone,
        ChatService laptop,
        ChatService carol,
        AccountIdentity account,
        DeviceCertificate laptopCert,
      })> linkedPair({bool carolFirst = true}) async {
    final phoneId = await ZIdentity.generate();
    final phone = await makePrimary('phone', phoneId);
    final carol = await makePrimary('carol', await ZIdentity.generate());
    final account = await phone.accountIdentity();

    await waitUntil(
        () => phone.transport.isConnected && carol.transport.isConnected,
        what: 'phone and carol connected');
    if (carolFirst) {
      await carol.addContactFromCode(await phone.myContactCode());
      await phone.addContactFromCode(await carol.myContactCode());
    }

    final laptopId = await ZIdentity.generate();
    final laptopCert = await account.signDeviceCert(
        deviceEdPub: laptopId.edPub,
        deviceXPub: laptopId.xPub,
        deviceId: 'laptop');
    final laptop = await makeLinked(
        'laptop', laptopId, account, laptopCert, account.deviceCert);
    await waitUntil(() => laptop.transport.isConnected,
        what: 'laptop connected');
    return (
      phone: phone,
      laptop: laptop,
      carol: carol,
      account: account,
      laptopCert: laptopCert
    );
  }

  test('the safety number does not move when a device is linked', () async {
    // This is the whole point of a safety number: two people read it aloud to
    // rule out a man-in-the-middle. If it changes because someone opened the
    // desktop app, a real attack and an ordinary Tuesday look identical — and
    // worse, the person who verified on their phone sees a MISMATCH on their
    // laptop for the same contact and concludes they are being attacked.
    // It must be anchored to the account key, which is stable by design,
    // never to a per-device key.
    final s = await linkedPair();
    final before = await s.carol.safetyNumberWith(s.phone.myRid);

    // Anchoring to the account key must not MOVE the number for an account
    // that has never linked anything, or every already-verified contact in
    // the wild would suddenly read as compromised. On a device holding the
    // root the account key is the original identity key, so the value is
    // byte-identical to the pre-multi-device formula.
    expect(before,
        await safetyNumber(s.phone.identity.edPub, s.carol.identity.edPub),
        reason: 'a single-device account keeps the number it always had');

    await s.phone.addMyDevice(s.laptopCert);
    await s.laptop.addContactFromCode(await s.carol.myContactCode());
    await waitUntil(() => s.laptop.contacts.containsKey(s.carol.myRid),
        what: 'laptop knows carol');

    // Carol's view of this account is unchanged by the linking.
    expect(await s.carol.safetyNumberWith(s.phone.myRid), before,
        reason: 'linking a device must not look like a new identity');

    // And both of the account's own devices show Carol the same number, so a
    // user who verified on one can check on the other.
    expect(await s.laptop.safetyNumberWith(s.carol.myRid),
        await s.phone.safetyNumberWith(s.carol.myRid),
        reason: 'one account, one safety number, whichever device shows it');

    // Removing the device leaves it alone too.
    await s.phone.removeMyDevice(s.laptopCert);
    expect(await s.carol.safetyNumberWith(s.phone.myRid), before,
        reason: 'revoking a device must not look like a new identity either');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('phone and laptop both send and receive, with no mailbox contention',
      () async {
    final s = await linkedPair();
    await s.phone.addMyDevice(s.laptopCert);
    await s.laptop.addContactFromCode(await s.carol.myContactCode());
    await waitUntil(() => s.laptop.contacts.containsKey(s.carol.myRid),
        what: 'laptop knows carol');
    await Future<void>.delayed(const Duration(seconds: 1));

    // The laptop sends; Carol receives it, and the phone mirrors it.
    await s.laptop.sendText(s.carol.myRid, 'from the laptop');
    await waitUntil(
        () => texts(s.carol, s.phone.myRid).contains('from the laptop'),
        what: 'carol got the laptop message');
    await waitUntil(
        () => texts(s.phone, s.carol.myRid).contains('from the laptop'),
        what: 'phone mirrored the laptop message');

    // Carol replies; BOTH devices of the account see it, because she fans out
    // to every device in the list she holds.
    await s.carol.sendText(s.phone.myRid, 'to whichever of you is awake');
    await waitUntil(
        () => texts(s.phone, s.carol.myRid)
            .contains('to whichever of you is awake'),
        what: 'phone got the reply');
    await waitUntil(
        () => texts(s.laptop, s.carol.myRid)
            .contains('to whichever of you is awake'),
        what: 'laptop got the reply');

    // The phone sends; Carol receives, the laptop mirrors.
    await s.phone.sendText(s.carol.myRid, 'from the phone');
    await waitUntil(
        () => texts(s.carol, s.phone.myRid).contains('from the phone'),
        what: 'carol got the phone message');
    await waitUntil(
        () => texts(s.laptop, s.carol.myRid).contains('from the phone'),
        what: 'laptop mirrored the phone message');

    // Neither device was ever kicked. The relay allows one socket per routing
    // id and closes the older with 4002; two devices of one account must have
    // distinct ids, so this can only fail if the device model collapsed.
    expect(s.phone.transport.isConnected, isTrue);
    expect(s.laptop.transport.isConnected, isTrue);
    expect(s.phone.myRid, isNot(s.laptop.myRid));

    // Nothing arrived twice on either device.
    for (final svc in [s.phone, s.laptop]) {
      final all = texts(svc, s.carol.myRid);
      expect(all.toSet().length, all.length, reason: 'no duplicates');
    }
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('a contact offline for the whole enrollment still learns the device',
      () async {
    final s = await linkedPair();
    // Carol goes away BEFORE the laptop is linked and misses every update.
    await s.carol.transport.stop();
    await s.phone.addMyDevice(s.laptopCert);
    await s.laptop.addContactFromCode(await s.carol.myContactCode());
    await Future<void>.delayed(const Duration(seconds: 1));

    // She comes back and the two sides exchange one message.
    s.carol.transport.start();
    await waitUntil(() => s.carol.transport.isConnected,
        what: 'carol reconnected');
    await s.phone.sendText(s.carol.myRid, 'while you were out');
    await waitUntil(
        () => texts(s.carol, s.phone.myRid).contains('while you were out'),
        what: 'carol got the message');

    // She now holds the newer list…
    var version = 0;
    await waitUntil(() {
      unawaited(s.carol
          .heldContactListVersion(s.phone.myRid)
          .then((v) => version = v));
      return version >= 2;
    }, what: 'carol learned the device list');

    // …and that is not just bookkeeping: her next message reaches the laptop,
    // which is the only thing the device list is actually for.
    await s.carol.sendText(s.phone.myRid, 'caught up now');
    await waitUntil(
        () => texts(s.laptop, s.carol.myRid).contains('caught up now'),
        what: 'the laptop is in the fan-out');
  }, timeout: const Timeout(Duration(minutes: 3)));
}
