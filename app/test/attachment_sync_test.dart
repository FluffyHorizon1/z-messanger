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
  Future<ChatService> makeLinked(
      String name,
      ZIdentity devId,
      AccountIdentity account,
      DeviceCertificate devCert,
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
      {Duration timeout = const Duration(seconds: 25),
      required String what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  /// Wait for a freshly-added pair to have finished introducing themselves,
  /// instead of sleeping a second and hoping — the same copied second, and
  /// the same wait that replaced it, as `settled()` in `replies_test.dart`
  /// (whose comments carry the reasoning): a positive signal first, each
  /// side holding the other's post-quantum key, which means the requests
  /// crossed, the hello landed and a session exists; then quiescence, the
  /// outbox read last and the send flag re-read after it.
  Future<void> settled(List<ChatService> pair) async {
    final deadline = DateTime.now().add(const Duration(seconds: 25));
    while (true) {
      var done = true;
      for (final s in pair) {
        for (final o in pair) {
          if (identical(s, o)) continue;
          final c = s.contacts[o.myRid];
          if (c == null) continue;
          if (c.pqPub == null && c.pqCandidate == null) done = false;
        }
      }
      if (done) {
        for (final s in pair) {
          if ((await s.vault.db.query('outbox', limit: 1)).isNotEmpty) {
            done = false;
            break;
          }
        }
      }
      if (done && pair.every((s) => !s.pqSendPending)) return;
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('the pair never settled');
      }
      await Future<void>.delayed(const Duration(milliseconds: 30));
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
    final laptop = await makeLinked(
        'laptop', laptopId, account, laptopCert, account.deviceCert);

    final carolId = await ZIdentity.generate();
    final carol = await makePrimary('carol', carolId);

    await waitUntil(
        () =>
            phone.transport.isConnected &&
            laptop.transport.isConnected &&
            carol.transport.isConnected,
        what: 'phone, laptop and carol connected');

    // Phone <-> Carol become contacts; the laptop also holds Carol so the
    // mirrored offer has a home thread.
    final carolCode = await carol.myContactCode();
    final phoneCode = await phone.myContactCode();
    await phone.addContactFromCode(carolCode);
    await carol.addContactFromCode(phoneCode);
    // 13.7: the phone's contact now propagates to its own devices, so the
    // laptop may already hold Carol by the time this runs — in which case
    // scanning her code here is a duplicate and says so. Either route gets
    // the laptop to the same place, which is all this setup wants.
    try {
      await laptop.addContactFromCode(carolCode);
    } on FormatException {
      // already synced from the phone
    }
    await waitUntil(() => laptop.contacts.containsKey(carol.myRid),
        what: 'the laptop holds carol');
    final carolRid = carol.myRid;
    final phoneRid = phone.myRid;

    // The phone and Carol have finished introducing themselves before the
    // file goes. (The laptop is the phone's own device, not a contact of
    // Carol's, so it is not in the pair: the self-sync channel opens on the
    // first mirror and needs no handshake to wait for.)
    await settled([phone, carol]);

    // A multi-chunk payload with a distinctive pattern. Self-sync now delivers
    // through the durable outbox, so a single send reaches the linked device
    // reliably (offer + every chunk), no retry pump needed.
    final bytes = Uint8List.fromList(
        List<int>.generate(1000000, (i) => (i * 7) % 256)); // 7 sealed chunks
    await phone.sendFile(
        carolRid, 'photo.bin', bytes, 'application/octet-stream');

    // Normal path: Carol receives and reassembles it.
    final carolGot = await awaitAttachment(carol, phoneRid);
    expect(carolGot, isNotNull, reason: 'Carol never received the attachment');
    expect(carolGot, equals(bytes), reason: 'Carol got corrupt bytes');

    // Self-sync: the phone's own laptop reassembles it too, byte-for-byte.
    final laptopGot = await awaitAttachment(laptop, carolRid);
    expect(laptopGot, isNotNull,
        reason: 'attachment did not sync to the linked device');
    expect(laptopGot, equals(bytes), reason: 'linked device got corrupt bytes');
  }, timeout: const Timeout(Duration(minutes: 2)));
}
