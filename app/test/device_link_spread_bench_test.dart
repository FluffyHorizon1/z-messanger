// What linking a device looks like from the relay's side.
//
// Every message a phone sends or receives is mirrored to the account's other
// devices over the self-sync channel, at once. So each time the phone talks
// to a contact, the laptop's mailbox lights up too — and the relay, which
// cannot group a person's devices from any envelope (per-device sealing,
// per-device routing ids), can group them from the pattern, exactly as it
// can group a group's members (R18). WHITEPAPER §3 said "the relay cannot
// group a person's devices either"; this measures what it can do instead.
//
// A measurement, not an assertion — run it deliberately:
//
//     flutter test test/device_link_spread_bench_test.dart --tags bench
//
// What it prints, per message: how long after the contact's copy was
// relay-stamped the laptop's copy was — the phone's mirror when the phone
// sends; the contact's own fan-out (she holds the device list) when the
// contact sends. Measured 2026-09-11 (one relay on loopback): see
// THREAT_MODEL.md R19.
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

  Future<Vault> freshVault(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_dls_$name');
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
      // Forwarded exactly as `hostDeviceLink` does: public, so it travels
      // even though the account root does not.
      accountMlPub: account.accountMlPub,
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
      // Adding each other opens no session on its own: only the designated
      // initiator greets, and if it greeted before the other side had added
      // it, that greeting was dropped. That is by design — nothing is lost,
      // and until someone speaks both sides honestly show a CLASSICAL
      // identity (ADR 0003, "a window where the PQ half is unknown"). So
      // exchange a word, as two people who have just swapped codes do,
      // rather than waiting on a convergence the protocol never promised.
      await carol.sendText(phone.myRid, 'hi');
      await phone.sendText(carol.myRid, 'hi back');
      // And let the post-quantum halves land. When the greeting was dropped
      // the side holding the unmet commitment re-offers its key a moment
      // after the first traffic, not on it (§18.2, the reference client's
      // wait), so a test that verifies "immediately" would verify a number
      // about to move — which the app correctly reports as an upgrade to
      // re-check, and which is not what these tests are about.
      await waitUntil(
          () =>
              phone.assuranceWith(carol.myRid) == IdentityAssurance.hybrid &&
              carol.assuranceWith(phone.myRid) == IdentityAssurance.hybrid,
          what: 'phone and carol hold each other\'s post-quantum keys');
    }

    final laptopId = await ZIdentity.generate();
    final laptopCert = await account.signDeviceCert(
        deviceEdPub: laptopId.edPub,
        deviceXPub: laptopId.xPub,
        deviceId: 'laptop');
    // Enrollment as `hostDeviceLink` performs it: the account's post-quantum
    // PUBLIC key rides along, so both devices speak for one identity. Without
    // it the laptop would be honest but classical, and the two devices would
    // show different safety numbers for the same contact.
    final myMl = await phone.pqAccountPublic();
    final laptop = await makeLinked(
        'laptop',
        laptopId,
        myMl == null ? account : account.withAccountMlPub(myMl),
        laptopCert,
        account.deviceCert);
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

  test('the mirror to a linked device follows the contact copy at once',
      () async {
    final s = await linkedPair();
    await s.phone.addMyDevice(s.laptopCert);
    await s.laptop.addContactFromCode(await s.carol.myContactCode());
    await waitUntil(() => s.laptop.contacts.containsKey(s.carol.myRid),
        what: 'laptop knows carol');
    await Future<void>.delayed(const Duration(seconds: 3));

    // Stamp every inbound envelope at carol, the phone and the laptop, as
    // the relay stamped it.
    List<int> stampsOf(ChatService svc) {
      final out = <int>[];
      final orig = svc.transport.onMessage;
      svc.transport.onMessage = (m) {
        out.add(m.serverTs);
        orig?.call(m);
      };
      return out;
    }

    final atCarol = stampsOf(s.carol);
    final atPhone = stampsOf(s.phone);
    final atLaptop = stampsOf(s.laptop);
    final gaps = <int>[];

    for (var k = 0; k < 5; k++) {
      atCarol.clear();
      atLaptop.clear();
      final before = (s.laptop.messagesByChat[s.carol.myRid] ?? []).length;
      await s.phone.sendText(s.carol.myRid, 'out $k');
      await waitUntil(
          () =>
              (s.carol.messagesByChat[s.phone.myRid] ?? [])
                  .any((m) => m.body == 'out $k') &&
              (s.laptop.messagesByChat[s.carol.myRid] ?? []).length > before,
          what: 'out $k at carol and mirrored to the laptop');
      final gap = atLaptop.first - atCarol.first;
      gaps.add(gap.abs());
      // ignore: avoid_print
      print("phone → carol, message $k: the laptop's mirror copy was "
          "relay-stamped $gap ms after carol's copy");
    }
    for (var k = 0; k < 5; k++) {
      atPhone.clear();
      atLaptop.clear();
      final before = (s.laptop.messagesByChat[s.carol.myRid] ?? []).length;
      await s.carol.sendText(s.phone.myRid, 'in $k');
      await waitUntil(
          () =>
              (s.phone.messagesByChat[s.carol.myRid] ?? [])
                  .any((m) => m.body == 'in $k') &&
              (s.laptop.messagesByChat[s.carol.myRid] ?? []).length > before,
          what: 'in $k at the phone and mirrored to the laptop');
      // Carol holds the account's device list, so she fans out to both
      // devices herself; the phone mirrors as well. Either way the laptop's
      // first copy follows the phone's within the burst.
      final gap = atLaptop.first - atPhone.first;
      gaps.add(gap.abs());
      // ignore: avoid_print
      print("carol → phone, message $k: the laptop's first copy was "
          "relay-stamped $gap ms after the phone's copy");
    }
    // The one thing asserted: the mirror is a burst with the contact copy,
    // not a trickle. If this fails because mirroring was deliberately
    // delayed, R19 needs rewriting — which is why it is asserted.
    expect(gaps.reduce((a, b) => a > b ? a : b), lessThan(2000),
        reason: 'the mirror follows the contact copy at once: $gaps');
  }, timeout: const Timeout(Duration(minutes: 3)));
}
