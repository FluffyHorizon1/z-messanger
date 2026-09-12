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
    port = 41000 + DateTime.now().millisecondsSinceEpoch % 20000;
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
}
