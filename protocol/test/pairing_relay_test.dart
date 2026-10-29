@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

/// Full-stack: two devices complete the M3 pairing over the REAL Node relay —
/// the exact rendezvous choreography the app will drive from its UI.
void main() {
  late Process relay;
  late int port;

  setUpAll(() async {
    final serverDir =
        '${Directory.current.parent.path}${Platform.pathSeparator}server';
    // Ask the OS for a free port rather than derive one from the clock:
    // `dart test` runs files concurrently, so two files computing a port from
    // the same millisecond collided and one relay lost the bind (the app
    // tests already bind port 0 for exactly this reason).
    final portProbe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    port = portProbe.port;
    await portProbe.close();
    relay = await Process.start('node', ['server.js'],
        workingDirectory: serverDir,
        environment: {'PORT': '$port', 'LOG_LEVEL': 'silent'});
    relay.stderr
        .transform(utf8.decoder)
        .listen((s) => print('[relay-err] ${s.trimRight()}'));
    for (var i = 0; i < 50; i++) {
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

  tearDownAll(() => relay.kill());

  test('a new device links to an account over the relay', () async {
    final url = 'ws://127.0.0.1:$port';

    // Existing device (phone), holding the account root, with one contact.
    final phone = await AccountIdentity.generate();
    final carol = await AccountIdentity.generate();
    final contacts = [carol.toAccountBundle(displayName: 'Carol')];

    // New device (desktop) shows a pairing code; phone enters it.
    final code = PairingCode.generate();
    final desktop = await PairingInitiator.create(code: code);

    String? sasPhone, sasDesktop;

    final desktopFut = RelayPairing.runNewDevice(
      relayUrl: url,
      n: desktop,
      confirm: (s) async {
        sasDesktop = s;
        return true; // stands in for the user tapping "matches"
      },
    );
    final phoneFut = RelayPairing.runExistingDevice(
      relayUrl: url,
      code: code,
      me: phone,
      contacts: contacts,
      includeAccountRoot: false,
      displayName: 'Alice',
      confirm: (s) async {
        sasPhone = s;
        return true;
      },
    );

    final results = await Future.wait([desktopFut, phoneFut]);
    final result = results[0] as PairingResult?;
    final linkedCert = results[1] as DeviceCertificate?;

    // The phone learned the device it just linked (to mirror to it later).
    expect(linkedCert, isNotNull);
    expect(await linkedCert!.verify(phone.accountEdPub), isTrue);
    expect(result, isNotNull);

    // The desktop learned the phone's device keys (to mirror back to it).
    expect(await result!.data.hostDeviceCert.verify(phone.accountEdPub), isTrue);
    expect(b64(result.data.hostDeviceCert.deviceEdPub), b64(phone.deviceEdPub));

    // Both screens showed the same safety string.
    expect(sasPhone, isNotNull);
    expect(sasDesktop, sasPhone);

    // The desktop now belongs to the phone's account, on its own mailbox.
    final acct = result.account;
    expect(b64(acct.accountEdPub), b64(phone.accountEdPub));
    expect(await acct.deviceCert.verify(phone.accountEdPub), isTrue);
    expect(await acct.routingId(), isNot(await phone.routingId()));
    expect(acct.holdsAccountRoot, isFalse); // we linked without sharing the root

    // The contact list came across intact and still verifies.
    expect(result.data.contacts.length, 1);
    expect(await result.data.contacts.first.verifyAll(), isTrue);
    expect(result.data.contacts.first.displayName, 'Carol');
    expect(result.data.displayName, 'Alice');
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('a new device links over the relay with the v2 ceremony', () async {
    final url = 'ws://127.0.0.1:$port';
    final phone = await AccountIdentity.generate();
    final carol = await AccountIdentity.generate();
    final code = PairingCode.generate();
    final desktop = await PairingInitiatorV2.create(code: code);

    String? sasPhone, sasDesktop;
    final results = await Future.wait([
      RelayPairing.runNewDeviceV2(
        relayUrl: url,
        n: desktop,
        confirm: (s) async {
          sasDesktop = s;
          return true;
        },
      ),
      RelayPairing.runExistingDeviceV2(
        relayUrl: url,
        code: code,
        me: phone,
        contacts: [carol.toAccountBundle(displayName: 'Carol')],
        includeAccountRoot: false,
        displayName: 'Alice',
        confirm: (s) async {
          sasPhone = s;
          return true;
        },
      ),
    ]);
    final result = results[0] as PairingResult?;
    final linkedCert = results[1] as DeviceCertificate?;

    expect(result, isNotNull);
    expect(linkedCert, isNotNull);
    expect(sasDesktop, sasPhone);
    expect(sasPhone, matches(RegExp(r'^\d{4} \d{4}$')));
    // The certificate the host signed binds the ratchet key the two users
    // compared, which is the whole point of v2 (§10.1).
    expect(b64(linkedCert!.deviceXPub), b64(desktop.deviceXPub));
    expect(await linkedCert.verify(phone.accountEdPub), isTrue);
    expect(b64(result!.account.accountEdPub), b64(phone.accountEdPub));
    expect(result.data.contacts.length, 1);
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('a v2 device meeting a v1 device detects it and refuses to transact',
      () async {
    final url = 'ws://127.0.0.1:$port';
    final phone = await AccountIdentity.generate();
    final code = PairingCode.generate();
    // The lagging side is the NEW device here, which is the direction an old
    // peer is detectable in: it speaks first, so its v1 hello arrives on the
    // v1 mailbox the v2 host holds open and never answers.
    final oldDesktop = await PairingInitiator.create(code: code);

    var confirmCalled = false;
    final hostFut = RelayPairing.runExistingDeviceV2(
      relayUrl: url,
      code: code,
      me: phone,
      contacts: const [],
      includeAccountRoot: false,
      displayName: 'Alice',
      confirm: (s) async {
        confirmCalled = true;
        return true;
      },
      timeout: const Duration(seconds: 20),
    );
    // The old device runs its v1 ceremony; it will time out, because nothing
    // answers a v1 hello any more.
    final oldFut = RelayPairing.runNewDevice(
      relayUrl: url,
      n: oldDesktop,
      confirm: (s) async => true,
      timeout: const Duration(seconds: 8),
    ).catchError((_) => null);

    await expectLater(hostFut, throwsA(isA<PairingAbort>()),
        reason: 'the host recognises an older peer and says so');
    expect(confirmCalled, isFalse,
        reason: 'no safety string was ever shown: detect, do not transact');
    await oldFut;
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('a v2 host whose relay refuses its second connection closes the first',
      () async {
    // A front before the relay that refuses the second connection it is
    // asked to upgrade, and holds each client socket it accepted until that
    // socket closes. It passes the Host header through, so the relay checks
    // each authentication as it would without the front.
    final front = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final open = <WebSocket>{};
    var asked = 0;
    front.listen((req) async {
      asked++;
      if (asked == 2) {
        req.response.statusCode = HttpStatus.serviceUnavailable;
        await req.response.close();
        return;
      }
      final down = await WebSocketTransformer.upgrade(req);
      open.add(down);
      final up = await WebSocket.connect('ws://127.0.0.1:$port',
          headers: {'host': req.headers.value('host') ?? ''});
      void gone() {
        open.remove(down);
        up.close();
      }

      down.listen(up.add, onDone: gone, onError: (Object _) => gone());
      up.listen(down.add,
          onDone: () => down.close(), onError: (Object _) => down.close());
    });
    try {
      var shown = false;
      await expectLater(
          RelayPairing.runExistingDeviceV2(
            relayUrl: 'ws://127.0.0.1:${front.port}',
            code: PairingCode.generate(),
            me: await AccountIdentity.generate(),
            contacts: const [],
            includeAccountRoot: false,
            confirm: (s) async {
              shown = true;
              return true;
            },
          ),
          throwsA(isA<WebSocketException>()),
          reason: 'the second connection is refused');
      expect(asked, 2, reason: 'one connection made, the second refused');
      expect(shown, isFalse);
      await waitUntil(() => open.isEmpty,
          what: 'the connection the host had made to close');
    } finally {
      await front.close(force: true);
    }
  }, timeout: const Timeout(Duration(minutes: 2)));

  // Every frame a ceremony reads is acknowledged, as an ordinary envelope
  // is (§12.5), and the existing device stays until the relay reports the
  // enrolment acknowledged, so nothing of a finished ceremony is left on the
  // relay — not a frame, not a receipt. Until 44.4 neither side acknowledged
  // anything, and each ceremony's four frames, the whole enrolment among
  // them, stayed in relay RAM for QUEUE_TTL_HOURS (72). Read from the
  // relay's own gauges, on a relay of the group's own: z_queued_envelopes
  // and z_store_bytes, each before the ceremony and once both sides are
  // done.
  group('acknowledgements', () {
    late Process ackRelay;
    late int ackPort;
    late String url;
    const token = 'z-pairtest-metrics';

    setUpAll(() async {
      final serverDir =
          '${Directory.current.parent.path}${Platform.pathSeparator}server';
      final portProbe =
          await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      ackPort = portProbe.port;
      await portProbe.close();
      ackRelay = await Process.start('node', ['server.js'],
          workingDirectory: serverDir,
          environment: {
            'PORT': '$ackPort',
            'LOG_LEVEL': 'silent',
            'METRICS_TOKEN': token,
          });
      ackRelay.stderr
          .transform(utf8.decoder)
          .listen((s) => print('[relay-err] ${s.trimRight()}'));
      url = 'ws://127.0.0.1:$ackPort';
      for (var i = 0; i < 50; i++) {
        try {
          final res = await (await HttpClient()
                  .getUrl(Uri.parse('http://127.0.0.1:$ackPort/health')))
              .close();
          await res.drain<void>();
          if (res.statusCode == 200) return;
        } catch (_) {
          await Future<void>.delayed(const Duration(milliseconds: 100));
        }
      }
      fail('relay did not start');
    });

    tearDownAll(() => ackRelay.kill());

    /// What the relay holds: (envelopes queued, bytes they are charged at).
    Future<(int, int)> held() async {
      final req = await HttpClient()
          .getUrl(Uri.parse('http://127.0.0.1:$ackPort/metrics'));
      req.headers.set('authorization', 'Bearer $token');
      final res = await req.close();
      final body = await res.transform(utf8.decoder).join();
      expect(res.statusCode, 200, reason: '/metrics with the test token');
      int gauge(String name) => int.parse(RegExp('^$name (\\d+)\$',
              multiLine: true)
          .firstMatch(body)!
          .group(1)!);
      return (gauge('z_queued_envelopes'), gauge('z_store_bytes'));
    }

    /// Waits until the relay holds again what it held at [before]; fails
    /// with what it holds instead.
    Future<void> heldAgain((int, int) before, String what) async {
      var now = await held();
      final deadline = DateTime.now().add(const Duration(seconds: 10));
      while (now != before && DateTime.now().isBefore(deadline)) {
        await Future<void>.delayed(const Duration(milliseconds: 50));
        now = await held();
      }
      print('$what: the relay held $before before and $now after '
          '(envelopes, bytes)');
      expect(now, before,
          reason: '$what leaves nothing on the relay: '
              '${now.$1 - before.$1} envelopes, ${now.$2 - before.$2} bytes '
              'more than before');
    }

    test('a v3 ceremony leaves nothing on the relay', () async {
      final before = await held();
      final phone = await AccountIdentity.generate();
      final carol = await AccountIdentity.generate();
      final code = PairingCode.generate();
      final desktop = await PairingInitiatorV3.create(
          code: code, sealKey: pqKeyPairFromSeed(randomBytes(64)).$1);
      final results = await Future.wait([
        RelayPairing.runNewDeviceV3(
            relayUrl: url, n: desktop, confirm: (s) async => true),
        RelayPairing.runExistingDeviceV3(
          relayUrl: url,
          code: code,
          me: phone,
          contacts: [carol.toAccountBundle(displayName: 'Carol')],
          displayName: 'Alice',
          attest: (s) async => randomBytes(3309),
          confirm: (s) async => true,
        ),
      ]);
      expect(results[0], isNotNull, reason: 'the new device was enrolled');
      expect(results[1], isNotNull, reason: 'the host linked it');
      await heldAgain(before, 'a v3 ceremony');
    }, timeout: const Timeout(Duration(minutes: 2)));

    test('a v2 ceremony leaves nothing on the relay', () async {
      final before = await held();
      final phone = await AccountIdentity.generate();
      final carol = await AccountIdentity.generate();
      final code = PairingCode.generate();
      final results = await Future.wait([
        RelayPairing.runNewDeviceV2(
            relayUrl: url,
            n: await PairingInitiatorV2.create(code: code),
            confirm: (s) async => true),
        RelayPairing.runExistingDeviceV2(
          relayUrl: url,
          code: code,
          me: phone,
          contacts: [carol.toAccountBundle(displayName: 'Carol')],
          includeAccountRoot: false,
          displayName: 'Alice',
          confirm: (s) async => true,
        ),
      ]);
      expect(results[0], isNotNull, reason: 'the new device was enrolled');
      expect(results[1], isNotNull, reason: 'the host linked it');
      await heldAgain(before, 'a v2 ceremony');
    }, timeout: const Timeout(Duration(minutes: 2)));

    test('a v3 host that hears an older device leaves nothing of it',
        () async {
      for (final version in [2, 1]) {
        final before = await held();
        final code = PairingCode.generate();
        final host = RelayPairing.runExistingDeviceV3(
          relayUrl: url,
          code: code,
          me: await AccountIdentity.generate(),
          contacts: const [],
          confirm: (s) async => true,
          timeout: const Duration(seconds: 20),
        ).then<Object?>((r) => r, onError: (Object e) => e);
        final old = version == 2
            ? RelayPairing.runNewDeviceV2(
                relayUrl: url,
                n: await PairingInitiatorV2.create(code: code),
                confirm: (s) async => true,
                timeout: const Duration(seconds: 4),
              ).then<Object?>((r) => r, onError: (Object e) => e)
            : RelayPairing.runNewDevice(
                relayUrl: url,
                n: await PairingInitiator.create(code: code),
                confirm: (s) async => true,
                timeout: const Duration(seconds: 4),
              ).then<Object?>((r) => r, onError: (Object e) => e);
        expect(await host, isA<PairingAbort>(),
            reason: 'the host recognised the version-$version device');
        expect(await old, isNot(isA<PairingResult>()));
        await heldAgain(
            before, 'a v3 host recognising a version-$version device');
      }
    }, timeout: const Timeout(Duration(minutes: 2)));
  });
}

/// Polls [done] until it holds, failing with [what] after [timeout]: a wait
/// on something observable, never a sleep standing in for one.
Future<void> waitUntil(bool Function() done,
    {required String what,
    Duration timeout = const Duration(seconds: 15)}) async {
  final deadline = DateTime.now().add(timeout);
  while (!done()) {
    if (DateTime.now().isAfter(deadline)) fail('timed out waiting for $what');
    await Future<void>.delayed(const Duration(milliseconds: 20));
  }
}
