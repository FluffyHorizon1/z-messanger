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

    // A relay delivers at least once (§12.5): an HA relay sends a mailbox
    // that has not moved for a sweep again, on the live connection
    // (`reflushStalled`). Here a front before the relay hands the new device
    // its reply twice, as that sweep does, and its person then says the
    // digits differ. The copy it did not take is not acknowledged: the
    // phone, whose person said they match, hears nothing, sends nothing and
    // links nothing, and the relay keeps the reply alone.
    test(
        "a copy of the reply delivered again does not say the new device's "
        'person confirmed', () async {
      final before = await held();
      final code = PairingCode.generate();
      final desktop = await PairingInitiatorV3.create(
          code: code, sealKey: pqKeyPairFromSeed(randomBytes(64)).$1);
      var replies = 0, replyCharge = 0;
      final tap = await front(url, (frame) {
        if (kindOfFrame(frame) != 'reply-v3') return [frame];
        replies += 2;
        replyCharge =
            charged(((jsonDecode(frame) as Map)['payload'] as String));
        return [frame, frame];
      });
      try {
        var phoneConfirmed = false;
        final host = RelayPairing.runExistingDeviceV3(
          relayUrl: url,
          code: code,
          me: await AccountIdentity.generate(),
          contacts: const [],
          attest: (s) async => randomBytes(3309),
          confirm: (s) async => phoneConfirmed = true,
          timeout: const Duration(seconds: 4),
        ).then<Object?>((r) => r, onError: (Object e) => e);
        final laptop = await RelayPairing.runNewDeviceV3(
            relayUrl: 'ws://127.0.0.1:${tap.port}',
            n: desktop,
            confirm: (s) async {
              // Both copies were handed over before this device sent the
              // opening the phone's digits came from.
              await waitUntil(() => replies == 2 && phoneConfirmed,
                  what: 'both copies of the reply in, and the phone confirmed');
              return false;
            });
        expect(laptop, isNull, reason: 'its person said the digits differ');
        final outcome = await host;
        expect(outcome, isA<PairingAbort>(),
            reason: 'the phone hears no confirmation, and links nothing');
        expect('$outcome', contains('did not say its person confirmed'));
        expect(await held(), (before.$1 + 1, before.$2 + replyCharge),
            reason: 'the relay keeps the reply, unacknowledged, and nothing '
                'else: no enrolment was sent');
      } finally {
        await tap.close(force: true);
      }
    }, timeout: const Timeout(Duration(minutes: 2)));

    // The new device acknowledges the enrolment only once it has opened and
    // installed it, and the existing device links on the relay's report of
    // that alone. Here a front spoils the sealed blob on its way to the new
    // device — one base64 character changed — so it does not open: it is
    // not acknowledged, and the existing device, with no report, links
    // nothing.
    test('an enrolment the new device cannot open is not acknowledged, and '
        'the existing device links nothing', () async {
      final before = await held();
      final code = PairingCode.generate();
      final desktop = await PairingInitiatorV3.create(
          code: code, sealKey: pqKeyPairFromSeed(randomBytes(64)).$1);
      var enrolCharge = 0;
      final tap = await front(url, (frame) {
        if (kindOfFrame(frame) != 'enroll-v3') return [frame];
        final f = (jsonDecode(frame) as Map).cast<String, Object?>();
        final payload = f['payload'] as String;
        enrolCharge = charged(payload);
        final p = (jsonDecode(payload) as Map).cast<String, Object?>();
        final blob = p['blob'] as String;
        final i = blob.length ~/ 2;
        p['blob'] = blob.replaceRange(i, i + 1, blob[i] == 'A' ? 'B' : 'A');
        return [jsonEncode({...f, 'payload': jsonEncode(p)})];
      });
      try {
        final host = RelayPairing.runExistingDeviceV3(
          relayUrl: url,
          code: code,
          me: await AccountIdentity.generate(),
          contacts: const [],
          attest: (s) async => randomBytes(3309),
          confirm: (s) async => true,
          timeout: const Duration(seconds: 3),
          margin: const Duration(seconds: 1),
        ).then<Object?>((r) => r, onError: (Object e) => e);
        final laptop = await RelayPairing.runNewDeviceV3(
          relayUrl: 'ws://127.0.0.1:${tap.port}',
          n: desktop,
          confirm: (s) async => true,
          timeout: const Duration(seconds: 3),
          margin: const Duration(seconds: 1),
        ).then<Object?>((r) => r, onError: (Object e) => e);
        expect(laptop, isNot(isA<PairingResult>()),
            reason: 'the spoiled enrolment does not open');
        final outcome = await host;
        expect(outcome, isA<PairingAbort>(),
            reason: 'the existing device links nothing: the new device '
                'never said it installed the enrolment');
        expect('$outcome', contains('did not finish linking'));
        expect(await held(), (before.$1 + 1, before.$2 + enrolCharge),
            reason: 'the enrolment waits at the relay, unacknowledged, and '
                'nothing else does');
      } finally {
        await tap.close(force: true);
      }
    }, timeout: const Timeout(Duration(minutes: 2)));

    // The new device acknowledges the reply when its person confirms, and
    // waits for the enrolment the ceremony's timeout and the margin from
    // then. An existing device whose person confirms more than the timeout
    // after that sends nothing: the margin is what an enrolment needs to be
    // sealed and to reach the new device, and it would arrive, if at all,
    // after the new device stopped. Inside the margin as past it; within the
    // timeout the link is made. The people's delays are the scenario: each
    // stands for a person deliberating, not for a wait on anything.
    test('an existing device whose person confirms too long after the new '
        "device's sends nothing", () async {
      const timeout = Duration(seconds: 3), margin = Duration(seconds: 2);
      for (final (after, linked) in [
        (const Duration(milliseconds: 3500), false), // inside the margin
        (const Duration(milliseconds: 5500), false), // past its whole wait
        (const Duration(milliseconds: 1500), true), // within the timeout
      ]) {
        final before = await held();
        final code = PairingCode.generate();
        final desktop = await PairingInitiatorV3.create(
            code: code, sealKey: pqKeyPairFromSeed(randomBytes(64)).$1);
        DateTime? acknowledgedAt;
        final host = RelayPairing.runExistingDeviceV3(
          relayUrl: url,
          code: code,
          me: await AccountIdentity.generate(),
          contacts: const [],
          attest: (s) async => randomBytes(3309),
          confirm: (s) async {
            await waitUntil(() => acknowledgedAt != null,
                what: "the new device's person confirmed");
            await Future<void>.delayed(
                acknowledgedAt!.add(after).difference(DateTime.now()));
            return true;
          },
          timeout: timeout,
          margin: margin,
        ).then<Object?>((r) => r, onError: (Object e) => e);
        final laptop = await RelayPairing.runNewDeviceV3(
          relayUrl: url,
          n: desktop,
          confirm: (s) async {
            acknowledgedAt = DateTime.now();
            return true;
          },
          timeout: timeout,
          margin: margin,
        ).then<Object?>((r) => r, onError: (Object e) => e);
        final outcome = await host;
        final what = "the existing device's person ${after.inMilliseconds} "
            "ms after the new device's";
        if (linked) {
          expect(laptop, isA<PairingResult>(), reason: what);
          expect(outcome, isA<DeviceCertificate>(), reason: what);
          await heldAgain(before, what);
        } else {
          expect(outcome, isA<PairingAbort>(),
              reason: '$what: the existing device sends nothing and links '
                  'nothing');
          expect('$outcome', contains('stopped waiting'), reason: what);
          expect(laptop, isA<PairingAbort>(),
              reason: '$what: the new device stopped waiting');
          expect('$laptop', contains('no "enroll-v3" frame arrived'),
              reason: what);
          await heldAgain(before, what);
        }
      }
    }, timeout: const Timeout(Duration(minutes: 2)));

    // The other side of the same race: an existing device that believes the
    // new device waits longer than it does — here the new device waits two
    // seconds and the margin half of one, and the existing device's person
    // confirms three seconds after its — sends the enrolment, which arrives
    // after the new device stopped. It is not acknowledged, and the existing
    // device, with no report, links nothing.
    test('an enrolment that arrives after the new device stopped waiting is '
        'not acknowledged, and the existing device links nothing', () async {
      final before = await held();
      final code = PairingCode.generate();
      final desktop = await PairingInitiatorV3.create(
          code: code, sealKey: pqKeyPairFromSeed(randomBytes(64)).$1);
      DateTime? acknowledgedAt;
      final host = RelayPairing.runExistingDeviceV3(
        relayUrl: url,
        code: code,
        me: await AccountIdentity.generate(),
        contacts: const [],
        attest: (s) async => randomBytes(3309),
        confirm: (s) async {
          await waitUntil(() => acknowledgedAt != null,
              what: "the new device's person confirmed");
          await Future<void>.delayed(acknowledgedAt!
              .add(const Duration(seconds: 3))
              .difference(DateTime.now()));
          return true;
        },
        timeout: const Duration(seconds: 6),
        margin: const Duration(seconds: 1),
      ).then<Object?>((r) => r, onError: (Object e) => e);
      final laptop = await RelayPairing.runNewDeviceV3(
        relayUrl: url,
        n: desktop,
        confirm: (s) async {
          acknowledgedAt = DateTime.now();
          return true;
        },
        timeout: const Duration(seconds: 2),
        margin: const Duration(milliseconds: 500),
      ).then<Object?>((r) => r, onError: (Object e) => e);
      final outcome = await host;
      expect(outcome, isA<PairingAbort>(),
          reason: 'the existing device links nothing: no report came');
      expect('$outcome', contains('did not finish linking'));
      expect(laptop, isA<PairingAbort>(),
          reason: 'the new device stopped waiting for the enrolment');
      final now = await held();
      expect(now.$1, before.$1 + 1,
          reason: 'the enrolment, unacknowledged, and nothing else waits at '
              'the relay');
    }, timeout: const Timeout(Duration(minutes: 2)));

    // The existing device links on the relay's report of the new device's
    // acknowledgement alone. It does not wait for the relay's `sent` for the
    // enrolment, nor give up when that is late or never comes: an enrolment
    // near the frame cap, on a slow connection, takes longer than a send's
    // twenty seconds to go up, and the new device installs it all the same.
    // Here a front before the existing device drops the relay's `sent` for
    // the enrolment, and the connection stays: the report alone links.
    test('an existing device that never hears the relay take its enrolment '
        'links on the report', () async {
      final code = PairingCode.generate();
      final desktop = await PairingInitiatorV3.create(
          code: code, sealKey: pqKeyPairFromSeed(randomBytes(64)).$1);
      var dropped = 0;
      final tap = await front(url, (frame) {
        if (!isSentFor(frame, 'z-pair-enroll')) return [frame];
        dropped++;
        return const [];
      });
      try {
        final host = RelayPairing.runExistingDeviceV3(
          relayUrl: 'ws://127.0.0.1:${tap.port}',
          code: code,
          me: await AccountIdentity.generate(),
          contacts: const [],
          attest: (s) async => randomBytes(3309),
          confirm: (s) async => true,
          timeout: const Duration(seconds: 3),
          margin: const Duration(seconds: 1),
        ).then<Object?>((r) => r, onError: (Object e) => e);
        final laptop = await RelayPairing.runNewDeviceV3(
          relayUrl: url,
          n: desktop,
          confirm: (s) async => true,
          timeout: const Duration(seconds: 3),
          margin: const Duration(seconds: 1),
        ).then<Object?>((r) => r, onError: (Object e) => e);
        expect(laptop, isA<PairingResult>(),
            reason: 'the new device installed the enrolment and said so');
        expect(await host, isA<DeviceCertificate>(),
            reason: 'the existing device links on the report, with no `sent`');
        expect(dropped, 1, reason: "the relay's `sent` never reached it");
      } finally {
        await tap.close(force: true);
      }
    }, timeout: const Timeout(Duration(minutes: 2)));

    // And when the connection closes with the `sent`, once the enrolment has
    // gone up, the report cannot reach the existing device. It cannot tell
    // whether the enrolment got through — here it did, and the new device
    // installed it — and says its own connection closed while it sent the
    // enrolment, rather than that the new device did not finish, and links
    // nothing.
    test('an existing device whose connection closes once its enrolment has '
        'gone up says so, and not that the new device failed', () async {
      final code = PairingCode.generate();
      final desktop = await PairingInitiatorV3.create(
          code: code, sealKey: pqKeyPairFromSeed(randomBytes(64)).$1);
      final tap = await front(url, (frame) => [frame],
          cut: (frame) => isSentFor(frame, 'z-pair-enroll'));
      try {
        final host = RelayPairing.runExistingDeviceV3(
          relayUrl: 'ws://127.0.0.1:${tap.port}',
          code: code,
          me: await AccountIdentity.generate(),
          contacts: const [],
          attest: (s) async => randomBytes(3309),
          confirm: (s) async => true,
          timeout: const Duration(seconds: 3),
          margin: const Duration(seconds: 1),
        ).then<Object?>((r) => r, onError: (Object e) => e);
        final laptop = await RelayPairing.runNewDeviceV3(
          relayUrl: url,
          n: desktop,
          confirm: (s) async => true,
          timeout: const Duration(seconds: 3),
          margin: const Duration(seconds: 1),
        ).then<Object?>((r) => r, onError: (Object e) => e);
        expect(laptop, isA<PairingResult>(),
            reason: 'the enrolment reached the new device, which installed '
                'it: the residual §10.2 names');
        final outcome = await host;
        expect(outcome, isA<PairingAbort>(),
            reason: 'the existing device links nothing: no report came');
        expect('$outcome', contains('connection to the relay closed while'),
            reason: 'it says its own connection went, not that the new '
                'device did not finish');
      } finally {
        await tap.close(force: true);
      }
    }, timeout: const Timeout(Duration(minutes: 2)));

    // The other side of the same race: the connection goes as the enrolment
    // is put up, and the frame never reaches the relay. The existing device
    // cannot tell that from the case above, and says the same; the new
    // device, sent nothing, waits out its wait. Both used to blame the other
    // device: the existing device said the new one did not finish, and the
    // new one that the other's person said the codes differ or was late.
    test('an existing device whose connection drops as it puts the enrolment '
        'up says so, and the new device is sent nothing', () async {
      final code = PairingCode.generate();
      final desktop = await PairingInitiatorV3.create(
          code: code, sealKey: pqKeyPairFromSeed(randomBytes(64)).$1);
      final tap = await front(url, (frame) => [frame],
          cutUp: (frame) => isSendOf(frame, 'z-pair-enroll'));
      try {
        final host = RelayPairing.runExistingDeviceV3(
          relayUrl: 'ws://127.0.0.1:${tap.port}',
          code: code,
          me: await AccountIdentity.generate(),
          contacts: const [],
          attest: (s) async => randomBytes(3309),
          confirm: (s) async => true,
          timeout: const Duration(seconds: 3),
          margin: const Duration(seconds: 1),
        ).then<Object?>((r) => r, onError: (Object e) => e);
        final laptop = await RelayPairing.runNewDeviceV3(
          relayUrl: url,
          n: desktop,
          confirm: (s) async => true,
          timeout: const Duration(seconds: 3),
          margin: const Duration(seconds: 1),
        ).then<Object?>((r) => r, onError: (Object e) => e);
        final outcome = await host;
        expect('$outcome', contains('connection to the relay closed while'),
            reason: 'the existing device says its own connection went');
        expect(laptop, isA<PairingAbort>(),
            reason: 'the new device was sent nothing, and stopped waiting');
        expect('$laptop', contains('no "enroll-v3" frame arrived'));
      } finally {
        await tap.close(force: true);
      }
    }, timeout: const Timeout(Duration(minutes: 2)));

    // A relay that refuses the enrolment — here `store_full`, which names
    // the frame — has taken nothing to the new device, and the existing
    // device says the relay refused it: neither that the new device did not
    // finish, as it did, nor that its connection was lost.
    test('an existing device whose enrolment the relay refuses says so',
        () async {
      final code = PairingCode.generate();
      final desktop = await PairingInitiatorV3.create(
          code: code, sealKey: pqKeyPairFromSeed(randomBytes(64)).$1);
      final tap = await front(url, (frame) => [frame],
          refuseUp: (frame) => isSendOf(frame, 'z-pair-enroll')
              ? jsonEncode(
                  {'t': 'error', 'code': 'store_full', 'id': 'z-pair-enroll'})
              : null);
      try {
        final host = RelayPairing.runExistingDeviceV3(
          relayUrl: 'ws://127.0.0.1:${tap.port}',
          code: code,
          me: await AccountIdentity.generate(),
          contacts: const [],
          attest: (s) async => randomBytes(3309),
          confirm: (s) async => true,
          timeout: const Duration(seconds: 3),
          margin: const Duration(seconds: 1),
        ).then<Object?>((r) => r, onError: (Object e) => e);
        final laptop = await RelayPairing.runNewDeviceV3(
          relayUrl: url,
          n: desktop,
          confirm: (s) async => true,
          timeout: const Duration(seconds: 3),
          margin: const Duration(seconds: 1),
        ).then<Object?>((r) => r, onError: (Object e) => e);
        final outcome = await host;
        expect('$outcome', contains('the relay refused the enrolment: '
            'store_full'));
        expect(laptop, isA<PairingAbort>(),
            reason: 'nothing reached the new device');
      } finally {
        await tap.close(force: true);
      }
    }, timeout: const Timeout(Duration(minutes: 2)));

    // A wait ends at once when its connection closes, and says that is why.
    // The new device used to wait out the whole of its wait for the
    // enrolment over a connection that had gone, and then say the other
    // device had sent nothing. Here a front before the new device closes
    // its connection as the enrolment comes down it.
    test('a new device whose connection closes while it waits for the '
        'enrolment says so at once', () async {
      const timeout = Duration(seconds: 4), margin = Duration(seconds: 2);
      final code = PairingCode.generate();
      final desktop = await PairingInitiatorV3.create(
          code: code, sealKey: pqKeyPairFromSeed(randomBytes(64)).$1);
      final tap = await front(url, (frame) => [frame],
          cut: (frame) => kindOfFrame(frame) == 'enroll-v3');
      try {
        final host = RelayPairing.runExistingDeviceV3(
          relayUrl: url,
          code: code,
          me: await AccountIdentity.generate(),
          contacts: const [],
          attest: (s) async => randomBytes(3309),
          confirm: (s) async => true,
          timeout: timeout,
          margin: margin,
        ).then<Object?>((r) => r, onError: (Object e) => e);
        final waited = Stopwatch();
        final laptop = await RelayPairing.runNewDeviceV3(
          relayUrl: 'ws://127.0.0.1:${tap.port}',
          n: desktop,
          confirm: (s) async {
            waited.start();
            return true;
          },
          timeout: timeout,
          margin: margin,
        ).then<Object?>((r) => r, onError: (Object e) => e);
        waited.stop();
        expect(laptop, isA<RelayException>(),
            reason: 'its connection closed, and it says so');
        expect(waited.elapsed, lessThan(timeout),
            reason: 'at once, and not when its wait for the enrolment, '
                '${timeout + margin}, ran out');
        final outcome = await host;
        expect('$outcome', contains('did not finish linking'),
            reason: 'the enrolment never reached it, and nothing is linked');
      } finally {
        await tap.close(force: true);
      }
    }, timeout: const Timeout(Duration(minutes: 2)));

    // Both ceremony mailboxes' keys derive from the pairing code alone, so
    // whoever has seen the code can log in as either, and the relay closes
    // the connection that login replaces (4002). Here someone holding the
    // code logs in as the new device's mailbox while the new device's person
    // compares the digits, and acknowledges what the relay hands it — the
    // reply among it, which the existing device takes for the new device's
    // word. The new device says so once its person has answered, and does
    // not wait out its timer for an enrolment that goes to the other login.
    test('a new device whose mailbox someone holding the code logs in as '
        'says so at once', () async {
      const timeout = Duration(seconds: 4), margin = Duration(seconds: 2);
      final code = PairingCode.generate();
      final desktop = await PairingInitiatorV3.create(
          code: code, sealKey: pqKeyPairFromSeed(randomBytes(64)).$1);
      final comparing = Completer<void>(), loggedIn = Completer<void>();
      final host = RelayPairing.runExistingDeviceV3(
        relayUrl: url,
        code: code,
        me: await AccountIdentity.generate(),
        contacts: const [],
        attest: (s) async => randomBytes(3309),
        confirm: (s) async => true,
        timeout: timeout,
        margin: margin,
      ).then<Object?>((r) => r, onError: (Object e) => e);
      final waited = Stopwatch();
      final laptop = RelayPairing.runNewDeviceV3(
        relayUrl: url,
        n: desktop,
        confirm: (s) async {
          comparing.complete();
          // The person answers once the other login is in.
          await loggedIn.future;
          waited.start();
          return true;
        },
        timeout: timeout,
        margin: margin,
      ).then<Object?>((r) => r, onError: (Object e) => e);
      await comparing.future;
      final other = await RelayClient.connect(
          url, await RelayPairing.relayIdentityV3(code, 'i'));
      final sub = other.messages
          .listen((m) => other.ackReceived(id: m.id, from: m.from));
      loggedIn.complete();
      try {
        final outcome = await laptop;
        waited.stop();
        expect('$outcome', contains('another connection took over'),
            reason: 'the new device says another connection took its '
                'mailbox over');
        expect(waited.elapsed, lessThan(timeout),
            reason: 'at once, and not when its wait for the enrolment ran '
                'out');
        // What §10.2 says is left: the existing device took the other
        // login's acknowledgements for the new device's word.
        final phone = await host;
        // ignore: avoid_print
        print('the existing device, on the other login\'s acknowledgements: '
            '${phone is DeviceCertificate ? 'lists the new device' : phone}');
      } finally {
        await sub.cancel();
        await other.close();
      }
    }, timeout: const Timeout(Duration(minutes: 2)));

    // The other way round: someone holding the code logs in as the
    // existing device's mailbox while its person compares the digits. The
    // new device, whose person has confirmed, waits for an enrolment that
    // will not come, and cannot see why: it used to wait out its timer and
    // then say the other's person had refused or was late. The existing
    // device, taken over, logs in once as the new device's mailbox, which
    // closes the new device's connection the same way, and it says so at
    // once.
    test('an existing device whose mailbox someone holding the code logs in '
        "as closes the new device's too, which says so at once", () async {
      const timeout = Duration(seconds: 4), margin = Duration(seconds: 2);
      final code = PairingCode.generate();
      final desktop = await PairingInitiatorV3.create(
          code: code, sealKey: pqKeyPairFromSeed(randomBytes(64)).$1);
      RelayClient? other;
      final host = RelayPairing.runExistingDeviceV3(
        relayUrl: url,
        code: code,
        me: await AccountIdentity.generate(),
        contacts: const [],
        attest: (s) async => randomBytes(3309),
        confirm: (s) async {
          // While its person compares, the other login comes in.
          other = await RelayClient.connect(
              url, await RelayPairing.relayIdentityV3(code, 'r'));
          return true;
        },
        timeout: timeout,
        margin: margin,
      ).then<Object?>((r) => r, onError: (Object e) => e);
      final waited = Stopwatch();
      final laptop = await RelayPairing.runNewDeviceV3(
        relayUrl: url,
        n: desktop,
        confirm: (s) async {
          waited.start();
          return true;
        },
        timeout: timeout,
        margin: margin,
      ).then<Object?>((r) => r, onError: (Object e) => e);
      waited.stop();
      try {
        expect('${await host}', contains('another connection took over'),
            reason: 'the existing device says so');
        expect('$laptop', contains('another connection took over'),
            reason: 'and so does the new device, closed the same way');
        expect(waited.elapsed, lessThan(timeout),
            reason: 'at once, and not when its wait for the enrolment, '
                '${timeout + margin}, ran out');
      } finally {
        await other?.close();
      }
    }, timeout: const Timeout(Duration(minutes: 2)));

    // The other login can come while the new device's first frame is still
    // going up: the relay closes the connection with 4002 before it has
    // taken the frame, and the send fails. That failure used to say only
    // that the connection closed, as one that dropped does, so the new
    // device said its connection was lost and kept its code (the 2026-10-30
    // review). Here a front keeps the commitment from the relay.
    test('a new device whose mailbox someone holding the code logs in as '
        'while its first frame is still going up says so at once', () async {
      const timeout = Duration(seconds: 4), margin = Duration(seconds: 2);
      final code = PairingCode.generate();
      final desktop = await PairingInitiatorV3.create(
          code: code, sealKey: pqKeyPairFromSeed(randomBytes(64)).$1);
      var going = false;
      final tap = await front(url, (frame) => [frame], holdUp: (frame) {
        if (!isSendOf(frame, 'z-pair-commit')) return null;
        going = true;
        return Completer<void>().future;
      });
      RelayClient? other;
      try {
        final laptop = RelayPairing.runNewDeviceV3(
          relayUrl: 'ws://127.0.0.1:${tap.port}',
          n: desktop,
          confirm: (s) async => true,
          timeout: timeout,
          margin: margin,
        ).then<Object?>((r) => r, onError: (Object e) => e);
        await waitUntil(() => going,
            what: "the new device's commitment on its way up");
        final waited = Stopwatch()..start();
        other = await RelayClient.connect(
            url, await RelayPairing.relayIdentityV3(code, 'i'));
        final outcome = await laptop;
        waited.stop();
        expect('$outcome', contains('another connection took over'),
            reason: 'the new device says another connection took its '
                'mailbox over, not that its connection was lost');
        expect(waited.elapsed, lessThan(timeout),
            reason: 'at once, and not when a wait ran out');
      } finally {
        await other?.close();
        await tap.close(force: true);
      }
    }, timeout: const Timeout(Duration(minutes: 2)));

    // The app hosts one link per code (`ChatService.hostDeviceLink`): an
    // attempt on a code it is still hosting first stops the one before it,
    // through the cancel it was run with. Two attempts on a code log in as
    // the same mailbox, and the relay closed the first for the second, as
    // for someone else holding the code: until 2026-10-30 the first then said
    // it was taken over and closed the new device's connection too, and the
    // second waited for a commitment that never came. Here the new device
    // has started, its commitment on its way up while the first attempt
    // waits for it.
    test('an existing device whose attempt is cancelled stops at once, closes '
        "nothing of the new device's, and the next attempt on the code "
        'links', () async {
      const timeout = Duration(seconds: 4), margin = Duration(seconds: 2);
      final code = PairingCode.generate();
      final desktop = await PairingInitiatorV3.create(
          code: code, sealKey: pqKeyPairFromSeed(randomBytes(64)).$1);
      final me = await AccountIdentity.generate();
      final release = Completer<void>();
      var going = false;
      final tap = await front(url, (frame) => [frame], holdUp: (frame) {
        if (!isSendOf(frame, 'z-pair-commit')) return null;
        going = true;
        return release.future;
      });
      // The first attempt connects through a front that notes each login
      // the relay welcomes.
      final welcomed = <String>[];
      final watch = await front(url, (frame) {
        final id = readyFor(frame);
        if (id != null) welcomed.add(id);
        return [frame];
      });
      final mailbox = await (await RelayPairing.relayIdentityV3(code, 'r'))
          .routingId();
      try {
        final cancel = PairingCancel();
        final first = RelayPairing.runExistingDeviceV3(
          relayUrl: 'ws://127.0.0.1:${watch.port}',
          code: code,
          me: me,
          contacts: const [],
          attest: (s) async => randomBytes(3309),
          confirm: (s) async => true,
          timeout: timeout,
          margin: margin,
          cancel: cancel,
        ).then<Object?>((r) => r, onError: (Object e) => e);
        await waitUntil(() => welcomed.contains(mailbox),
            what: "the first attempt logged in as the phone's mailbox");
        final laptop = RelayPairing.runNewDeviceV3(
          relayUrl: 'ws://127.0.0.1:${tap.port}',
          n: desktop,
          confirm: (s) async => true,
          timeout: timeout,
          margin: margin,
        ).then<Object?>((r) => r, onError: (Object e) => e);
        await waitUntil(() => going,
            what: "the new device's commitment on its way up");
        final waited = Stopwatch()..start();
        cancel.cancel();
        final stopped = await first;
        waited.stop();
        expect(stopped, isA<PairingCancelled>(),
            reason: 'the first attempt says it was cancelled');
        expect(cancel.closedByAnotherLogin, isFalse,
            reason: 'and no other login closed it');
        expect(waited.elapsed, lessThan(timeout),
            reason: 'at once, and not when its wait for the commitment ran '
                'out');
        release.complete();
        final second = await RelayPairing.runExistingDeviceV3(
          relayUrl: url,
          code: code,
          me: me,
          contacts: const [],
          attest: (s) async => randomBytes(3309),
          confirm: (s) async => true,
          timeout: timeout,
          margin: margin,
        ).then<Object?>((r) => r, onError: (Object e) => e);
        expect(await laptop, isA<PairingResult>(),
            reason: 'the new device was left alone, and links');
        expect(second, isA<DeviceCertificate>(),
            reason: 'the next attempt on the code links it');
      } finally {
        await tap.close(force: true);
        await watch.close(force: true);
      }
    }, timeout: const Timeout(Duration(minutes: 2)));

    // A cancelled attempt does not say what closed its connection: its
    // caller's own next attempt on the code would be such a login. It says
    // whether one had, and its caller, which knows whether that login could
    // have been its own, decides: the app, which logs in as the mailbox
    // again only once the attempt is over, takes it for a takeover
    // (`pairing_pq_test.dart` 24). Until 2026-10-31 this test read "cancelled,
    // not taken over" for a stranger's login, and nothing kept it. Here the
    // other login comes while the existing device's person compares the
    // digits, and the attempt is cancelled before it answers.
    test('an existing device whose attempt is cancelled once another login '
        'has closed it says it was cancelled, and that another login closed '
        'it', () async {
      const timeout = Duration(seconds: 4), margin = Duration(seconds: 2);
      final code = PairingCode.generate();
      final desktop = await PairingInitiatorV3.create(
          code: code, sealKey: pqKeyPairFromSeed(randomBytes(64)).$1);
      RelayClient? other;
      final cancel = PairingCancel();
      // The phone connects through a front that notes how the relay closed
      // each of its connections.
      final closes = <int?>[];
      final watch = await front(url, (frame) => [frame], closedBy: closes.add);
      try {
        final phone = RelayPairing.runExistingDeviceV3(
          relayUrl: 'ws://127.0.0.1:${watch.port}',
          code: code,
          me: await AccountIdentity.generate(),
          contacts: const [],
          attest: (s) async => randomBytes(3309),
          confirm: (s) async {
            other = await RelayClient.connect(
                url, await RelayPairing.relayIdentityV3(code, 'r'));
            await waitUntil(() => closes.contains(relayCloseReplaced),
                what: "the relay closing the phone's mailbox for the other "
                    'login');
            cancel.cancel();
            return true;
          },
          timeout: timeout,
          margin: margin,
          cancel: cancel,
        ).then<Object?>((r) => r, onError: (Object e) => e);
        final laptop = await RelayPairing.runNewDeviceV3(
          relayUrl: url,
          n: desktop,
          confirm: (s) async => true,
          timeout: timeout,
          margin: margin,
        ).then<Object?>((r) => r, onError: (Object e) => e);
        expect(await phone, isA<PairingCancelled>(),
            reason: 'cancelled, as its caller asked');
        expect(cancel.closedByAnotherLogin, isTrue,
            reason: 'and another login had closed its connection: its caller '
                'is told');
        expect(laptop, isA<PairingNoEnrolment>(),
            reason: "the new device's mailbox is its caller's to close: it "
                'waited for an enrolment that was never sent');
      } finally {
        await other?.close();
        await watch.close(force: true);
      }
    }, timeout: const Timeout(Duration(minutes: 2)));

    // The other login can come while the existing device's person compares
    // the digits, as on the new device, and the person's answer then changes
    // nothing: the attempt was taken over. An existing device whose person
    // said the digits differ used to end as though the link were cancelled
    // — the code not kept, the new device left waiting out its timer.
    test('an existing device whose person says the digits differ once '
        "another login has closed its mailbox says it was taken over, and "
        "closes the new device's too", () async {
      const timeout = Duration(seconds: 4), margin = Duration(seconds: 2);
      final code = PairingCode.generate();
      final desktop = await PairingInitiatorV3.create(
          code: code, sealKey: pqKeyPairFromSeed(randomBytes(64)).$1);
      RelayClient? other;
      final closes = <int?>[];
      final watch = await front(url, (frame) => [frame], closedBy: closes.add);
      try {
        final phone = RelayPairing.runExistingDeviceV3(
          relayUrl: 'ws://127.0.0.1:${watch.port}',
          code: code,
          me: await AccountIdentity.generate(),
          contacts: const [],
          attest: (s) async => randomBytes(3309),
          confirm: (s) async {
            other = await RelayClient.connect(
                url, await RelayPairing.relayIdentityV3(code, 'r'));
            await waitUntil(() => closes.contains(relayCloseReplaced),
                what: "the relay closing the phone's mailbox for the other "
                    'login');
            return false;
          },
          timeout: timeout,
          margin: margin,
        ).then<Object?>((r) => r, onError: (Object e) => e);
        final waited = Stopwatch();
        final laptop = await RelayPairing.runNewDeviceV3(
          relayUrl: url,
          n: desktop,
          confirm: (s) async {
            waited.start();
            return true;
          },
          timeout: timeout,
          margin: margin,
        ).then<Object?>((r) => r, onError: (Object e) => e);
        waited.stop();
        expect('${await phone}', contains('another connection took over'),
            reason: 'taken over, whatever its person answered');
        expect('$laptop', contains('another connection took over'),
            reason: 'and the new device, closed the same way, says so too');
        expect(waited.elapsed, lessThan(timeout),
            reason: 'at once, and not when its wait for the enrolment, '
                '${timeout + margin}, ran out');
      } finally {
        await other?.close();
        await watch.close(force: true);
      }
    }, timeout: const Timeout(Duration(minutes: 2)));

    // Once the enrolment is handed over the new device may come to hold the
    // account, and only the relay's report lists it: a cancel then changes
    // nothing, and the attempt runs to its end.
    test('an existing device whose attempt is cancelled once it has sent the '
        'enrolment runs on, and links the new device', () async {
      const timeout = Duration(seconds: 4), margin = Duration(seconds: 2);
      final code = PairingCode.generate();
      final desktop = await PairingInitiatorV3.create(
          code: code, sealKey: pqKeyPairFromSeed(randomBytes(64)).$1);
      final cancel = PairingCancel();
      final installing = Completer<void>(), goOn = Completer<void>();
      final phone = RelayPairing.runExistingDeviceV3(
        relayUrl: url,
        code: code,
        me: await AccountIdentity.generate(),
        contacts: const [],
        attest: (s) async => randomBytes(3309),
        confirm: (s) async => true,
        timeout: timeout,
        margin: margin,
        cancel: cancel,
      ).then<Object?>((r) => r, onError: (Object e) => e);
      final laptop = RelayPairing.runNewDeviceV3(
        relayUrl: url,
        n: desktop,
        confirm: (s) async => true,
        timeout: timeout,
        margin: margin,
        install: (r) async {
          installing.complete();
          await goOn.future;
        },
      ).then<Object?>((r) => r, onError: (Object e) => e);
      await installing.future;
      expect(cancel.sentEnrolment, isTrue,
          reason: 'the enrolment reached the new device');
      cancel.cancel();
      goOn.complete();
      expect(await laptop, isA<PairingResult>());
      expect(await phone, isA<DeviceCertificate>(),
          reason: 'it waited for the report, and links the new device on it');
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

/// A front before the relay at [relayUrl] for one client: every frame passes
/// both ways, and [down] says what the client is handed for each frame the
/// relay sends it — the frame, a copy of it too, something else, or
/// nothing. [cut], when given, names the frame from the relay at which the
/// connection closes instead, both ways: the client is not handed it, and
/// the relay sees the connection go. [cutUp] does the same for a frame from
/// the client, which never reaches the relay. [refuseUp], when it answers a
/// frame from the client, keeps that frame from the relay and hands the
/// client its answer as if the relay had sent it. [holdUp], when it answers
/// a frame from the client with a future, keeps that frame from the relay —
/// as one still going up — until the future completes, then passes it on if
/// the connection is still there. The Host header passes through, so the
/// relay checks each authentication against the address the client
/// dialled, and the relay's own close code passes on to the client — 4002
/// above all, its word that another connection logged in as this one's
/// routing id — and then to [closedBy], when given, once the client has
/// taken it.
Future<HttpServer> front(
    String relayUrl, List<String> Function(String frame) down,
    {bool Function(String frame)? cut,
    bool Function(String frame)? cutUp,
    String? Function(String frame)? refuseUp,
    Future<void>? Function(String frame)? holdUp,
    void Function(int? code)? closedBy}) async {
  final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
  server.listen((req) async {
    final client = await WebSocketTransformer.upgrade(req);
    final relay = await WebSocket.connect(relayUrl,
        headers: {'host': req.headers.value('host') ?? ''});
    var gone = false;
    // Whether the relay closed this connection, and with what code.
    var relayClosed = false;
    int? relayCode;
    client.listen((d) {
      if (gone) return;
      if (cutUp != null && cutUp(d as String)) {
        gone = true;
        client.close();
        relay.close();
        return;
      }
      final answer = refuseUp?.call(d as String);
      if (answer != null) {
        client.add(answer);
        return;
      }
      final held = holdUp?.call(d as String);
      if (held != null) {
        held.then((_) {
          if (!gone && relay.readyState == WebSocket.open) relay.add(d);
        });
        return;
      }
      relay.add(d);
    }, onDone: () {
      // The client's side has closed: a close the relay made is told now,
      // the client having taken it, its code read.
      if (relayClosed) closedBy?.call(relayCode);
      relay.close();
    }, onError: (Object _) => relay.close());
    relay.listen((d) {
      if (gone) return;
      if (cut != null && cut(d as String)) {
        gone = true;
        client.close();
        relay.close();
        return;
      }
      for (final f in down(d as String)) {
        client.add(f);
      }
    }, onDone: () {
      final c = relay.closeCode;
      relayClosed = true;
      relayCode = c;
      client.close(c != null && c >= 3000 && c <= 4999 ? c : null);
    }, onError: (Object _) => client.close());
  });
  return server;
}

/// Whether [frame], from the relay, is its `sent` for the envelope [id] —
/// its word that it took that envelope.
bool isSentFor(String frame, String id) {
  try {
    final f = jsonDecode(frame);
    return f is Map && f['t'] == 'sent' && f['id'] == id;
  } catch (_) {
    return false;
  }
}

/// The routing id a relay `ready` [frame] welcomes a login as, or null for
/// anything else.
String? readyFor(String frame) {
  try {
    final f = jsonDecode(frame);
    return f is Map && f['t'] == 'ready' && f['id'] is String
        ? f['id'] as String
        : null;
  } catch (_) {
    return null;
  }
}

/// Whether [frame], from a client, is its `send` of the envelope [id].
bool isSendOf(String frame, String id) {
  try {
    final f = jsonDecode(frame);
    return f is Map && f['t'] == 'send' && f['id'] == id;
  } catch (_) {
    return false;
  }
}

/// What the relay charges an envelope whose payload is [payload] against
/// its store (`server.js`, `envelopeSize`): the payload as the store holds
/// it, JSON-escaped, and 256 bytes for the entry around it.
int charged(String payload) => jsonEncode(payload).length - 2 + 256;

/// The kind (`k`) of the pairing frame a relay `msg` [frame] carries, or
/// null for anything else.
String? kindOfFrame(String frame) {
  try {
    final f = jsonDecode(frame);
    if (f is! Map || f['t'] != 'msg' || f['payload'] is! String) return null;
    final p = jsonDecode(f['payload'] as String);
    return p is Map && p['k'] is String ? p['k'] as String : null;
  } catch (_) {
    return null;
  }
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
