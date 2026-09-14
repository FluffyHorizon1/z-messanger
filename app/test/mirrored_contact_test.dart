// A contact mirrored between an account's own devices carries a post-quantum
// key, and it used to be installed because the device sending it said so.
//
// Everything else in that record is checked: the routing id is re-derived
// from the bundle, the bundle's own signature is verified, and §18.7's
// certificate rules are re-applied rather than trusted. Then `pqk` was taken
// straight out of the message and written into `Contact.pqPub`, whose own
// doc-comment says it is never set from an unverified source — because its
// being non-null is what `assurance` reports as hybrid.
//
// The sender chooses `pqc` and `pqk` together, so a self-consistent pair
// passed every check there was. A compromised linked device — no account
// root, so well inside the T1/T2 model — mirrors a contact with a commitment
// of its own and the key that matches it, and the receiving device shows
// hybrid assurance and a safety number over a key the contact never
// published.
//
// Its own file rather than a third and fourth case in `multidevice_test.dart`:
// each of these starts a linked pair, that file shares one relay across every
// test in it, and adding them there made an unrelated test in it time out
// under full-suite load about one run in three. A test that makes its
// neighbours flaky is a test in the wrong file.
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

  test('a mirrored post-quantum key is checked against its commitment',
      () async {
    // Everything else about a mirrored contact is checked: the routing id is
    // re-derived from the bundle, the bundle's own signature is verified, and
    // §18.7's certificate rules are re-applied rather than trusted. Then the
    // post-quantum key was taken straight out of the message and installed —
    // and `Contact.pqPub`'s own doc-comment says it is never set from an
    // unverified source, because its being non-null is what `assurance`
    // reports as hybrid.
    //
    // The sender chooses BOTH `pqc` and `pqk`, so a self-consistent pair
    // passed. A compromised linked device — no account root, so well inside
    // the T1/T2 model — mirrors a contact with a commitment of its own and
    // the key that matches it, and the receiving device shows hybrid
    // assurance and a safety number over a key the contact never published.
    final s = await linkedPair();
    await s.phone.addMyDevice(s.laptopCert);

    final victim = await ZIdentity.generate();
    final victimRid = await (await victim.bundle()).routingId();
    final real = await HybridKeyPair.generate();
    final attacker = await HybridKeyPair.generate();

    // The commitment the contact really published, with the attacker's key
    // beside it: this is the substitution the commitment exists to catch.
    await s.laptop.debugAssertContactToMyDevices(
      rid: victimRid,
      bundle: await victim.bundle(displayName: 'Victim'),
      pqCommit: await real.publicKey.pqCommitment(),
      pqPub: attacker.publicKey.mlPub,
    );
    await waitUntil(() => s.phone.contacts.containsKey(victimRid),
        what: 'the mirrored contact arrives');

    final got = s.phone.contacts[victimRid]!;
    expect(got.pqPub, isNull,
        reason: 'a key that does not match the commitment is not installed');
    expect(got.pqMismatch, isTrue,
        reason: 'and the refusal is durable, as the in-band path records it');
    expect(s.phone.assuranceWith(victimRid), isNot(IdentityAssurance.hybrid),
        reason: 'so the identity does not read as post-quantum');
    expect(got.pqCommit, isNotNull, reason: 'the commitment still stands');

  }, timeout: const Timeout(Duration(minutes: 3)));

  test('a mirrored post-quantum key that DOES match is installed', () async {
    // The other half: the check is a check, not a refusal of the mechanism.
    // Its own test rather than a second half of the one above, because each
    // mirror is one fire-and-forget message over the relay and two in one
    // test is two things that can be in flight at once.
    final s = await linkedPair();
    await s.phone.addMyDevice(s.laptopCert);

    final honest = await ZIdentity.generate();
    final honestRid = await (await honest.bundle()).routingId();
    final pq = await HybridKeyPair.generate();
    await s.laptop.debugAssertContactToMyDevices(
      rid: honestRid,
      bundle: await honest.bundle(displayName: 'Honest'),
      pqCommit: await pq.publicKey.pqCommitment(),
      pqPub: pq.publicKey.mlPub,
    );
    await waitUntil(() => s.phone.contacts.containsKey(honestRid),
        what: 'the honest mirrored contact arrives');

    final got = s.phone.contacts[honestRid]!;
    expect(got.pqPub, pq.publicKey.mlPub,
        reason: 'a key that matches its commitment is installed');
    expect(got.pqMismatch, isFalse);
    expect(s.phone.assuranceWith(honestRid), IdentityAssurance.hybrid);
  }, timeout: const Timeout(Duration(minutes: 3)));

}
