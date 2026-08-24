// Integration test for cross-device attachment sync.
//
// Text already mirrors across a user's linked devices; this proves a *file*
// does too. It stands up three REAL ChatService instances through the REAL
// Node relay — a phone and a linked laptop belonging to ONE account, plus a
// separate contact (Carol) — sends a file from the phone to Carol, and asserts
// the attachment fully reassembles BOTH on Carol (the normal path) and on the
// phone's own laptop (self-sync), byte-for-byte.
@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

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

  // A fresh account's primary device (its keys ARE the account root).
  Future<ChatService> makePrimary(String name, ZIdentity id) async {
    final dir = await Directory.systemTemp.createTemp('z_$name');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    await vault.kvPut('identity', jsonEncode(id.toJson()));
    final transport =
        Transport(identity: id, serverUrl: 'ws://127.0.0.1:$port');
    final svc = await ChatService.init(
        vault: vault, identity: id, displayName: name, transport: transport);
    services.add(svc);
    return svc;
  }

  // A linked (secondary) device enrolled under [account], pre-wired to
  // self-sync with the primary [hostCert] — the on-disk state the pairing flow
  // would leave behind.
  Future<ChatService> makeLinked(String name, ZIdentity devId,
      AccountIdentity account, DeviceCertificate devCert,
      DeviceCertificate hostCert) async {
    final dir = await Directory.systemTemp.createTemp('z_$name');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
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
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  // Poll an async attachment read until it succeeds (assembled + verified).
  Future<Uint8List?> awaitAttachment(ChatService svc, String rid) async {
    final deadline = DateTime.now().add(const Duration(seconds: 25));
    while (DateTime.now().isBefore(deadline)) {
      String? fid;
      for (final m in svc.messagesByChat[rid] ?? const []) {
        if (m.kind == 'file' && m.fid != null) fid = m.fid;
      }
      if (fid != null) {
        try {
          return await svc.readAttachment(fid);
        } catch (_) {
          // not complete yet
        }
      }
      await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    return null;
  }

  test('a sent attachment reassembles on the sender\'s own linked device',
      () async {
    // Phone + its linked laptop (one account), and a separate contact Carol.
    final phoneId = await ZIdentity.generate();
    final phone = await makePrimary('phone', phoneId);
    final account = await phone.accountIdentity();

    final laptopId = await ZIdentity.generate();
    final laptopCert = await account.signDeviceCert(
        deviceEdPub: laptopId.edPub,
        deviceXPub: laptopId.xPub,
        deviceId: 'laptop');
    await phone.addMyDevice(laptopCert); // wires the phone's sync channel
    final laptop =
        await makeLinked('laptop', laptopId, account, laptopCert, account.deviceCert);

    final carolId = await ZIdentity.generate();
    final carol = await makePrimary('carol', carolId);

    await waitUntil(() =>
        phone.transport.isConnected &&
        laptop.transport.isConnected &&
        carol.transport.isConnected);

    // Phone <-> Carol become contacts; the laptop also holds Carol so the
    // mirrored offer has a home thread.
    final carolCode = await carol.myContactCode();
    final phoneCode = await phone.myContactCode();
    await phone.addContactFromCode(carolCode);
    await carol.addContactFromCode(phoneCode);
    await laptop.addContactFromCode(carolCode);
    final carolRid = carol.myRid;
    final phoneRid = phone.myRid;

    await Future<void>.delayed(const Duration(seconds: 1)); // hellos settle

    // A multi-chunk payload with a distinctive pattern.
    final bytes =
        Uint8List.fromList(List<int>.generate(60000, (i) => (i * 7) % 256));
    await phone.sendFile(carolRid, 'photo.bin', bytes, 'application/octet-stream');

    // Normal path: Carol receives and reassembles it.
    final carolGot = await awaitAttachment(carol, phoneRid);
    expect(carolGot, isNotNull, reason: 'Carol never received the attachment');
    expect(carolGot, equals(bytes), reason: 'Carol got corrupt bytes');

    // Self-sync: the phone's own laptop reassembles it too, byte-for-byte.
    final laptopGot = await awaitAttachment(laptop, carolRid);
    expect(laptopGot, isNotNull,
        reason: 'attachment did not sync to the linked device');
    expect(laptopGot, equals(bytes),
        reason: 'linked device got corrupt bytes');
  }, timeout: const Timeout(Duration(minutes: 2)));
}
