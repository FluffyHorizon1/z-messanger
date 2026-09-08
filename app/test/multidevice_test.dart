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
      // Adding each other opens no session on its own: only the designated
      // initiator greets, and if it greeted before the other side had added
      // it, that greeting was dropped. That is by design — nothing is lost,
      // and until someone speaks both sides honestly show a CLASSICAL
      // identity (ADR 0003, "a window where the PQ half is unknown"). So
      // exchange a word, as two people who have just swapped codes do,
      // rather than waiting on a convergence the protocol never promised.
      await carol.sendText(phone.myRid, 'hi');
      await phone.sendText(carol.myRid, 'hi back');
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

  test('the safety number does not move when a device is linked', () async {
    // This is the whole point of a safety number: two people read it aloud to
    // rule out a man-in-the-middle. If it changes because someone opened the
    // desktop app, a real attack and an ordinary Tuesday look identical — and
    // worse, the person who verified on their phone sees a MISMATCH on their
    // laptop for the same contact and concludes they are being attacked.
    // It must be anchored to the account key, which is stable by design,
    // never to a per-device key.
    final s = await linkedPair();
    // Let the v3 identity exchange settle first. Codes now carry a
    // post-quantum commitment (§18.2), so a contact's number moves ONCE when
    // the key arrives and the identity becomes hybrid. That is a different
    // event from linking a device, and straddling it would test nothing —
    // the invariant here is that a DEVICE change moves nothing, at whatever
    // assurance level the identity has reached.
    await waitUntil(
        () => s.carol.assuranceWith(s.phone.myRid) == IdentityAssurance.hybrid,
        what: 'carol holds the account post-quantum key');
    final before = await s.carol.safetyNumberWith(s.phone.myRid);

    // Anchoring to the account key must not MOVE the number for an account
    // that has never linked anything, or every already-verified contact in
    // the wild would suddenly read as compromised. On a device holding the
    // root the account key is the original identity key, so the value is
    // byte-identical to the pre-multi-device formula — for the CLASSICAL
    // number, which is what a contact who has not upgraded still computes.
    // (`before` is the v3 number here, since the identity has settled to
    // hybrid; the property being pinned is that anchoring to the account key
    // moved nothing, not that the two versions agree — they must not.)
    expect(
        await safetyNumber(s.phone.identity.edPub, s.carol.identity.edPub),
        await safetyNumber((await s.phone.accountIdentity()).accountEdPub,
            (await s.carol.accountIdentity()).accountEdPub),
        reason: 'a single-device account keeps the number it always had');
    expect(
        before,
        isNot(
            await safetyNumber(s.phone.identity.edPub, s.carol.identity.edPub)),
        reason: 'and the v3 number is deliberately a different value');

    await s.phone.addMyDevice(s.laptopCert);
    await s.laptop.addContactFromCode(await s.carol.myContactCode());
    await waitUntil(() => s.laptop.contacts.containsKey(s.carol.myRid),
        what: 'laptop knows carol');

    // Carol's view of this account is unchanged by the linking.
    expect(await s.carol.safetyNumberWith(s.phone.myRid), before,
        reason: 'linking a device must not look like a new identity');

    // And both of the account's own devices show Carol the same number, so a
    // user who verified on one can check on the other. The laptop reaches
    // that view asynchronously — Carol's post-quantum key was offered to this
    // account before the laptop existed, so it is re-offered when the device
    // appears on the list (§18.2). Converging is the requirement; converging
    // instantly is not.
    await waitUntil(
        () => s.laptop.assuranceWith(s.carol.myRid) == IdentityAssurance.hybrid,
        what: 'the laptop reaches the same view of carol as the phone');
    expect(await s.laptop.safetyNumberWith(s.carol.myRid),
        await s.phone.safetyNumberWith(s.carol.myRid),
        reason: 'one account, one safety number, whichever device shows it');

    // Removing the device leaves it alone too.
    await s.phone.removeMyDevice(s.laptopCert);
    expect(await s.carol.safetyNumberWith(s.phone.myRid), before,
        reason: 'revoking a device must not look like a new identity either');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test(
      'a linked device speaks for the account post-quantum identity, never '
      'one of its own', () async {
    // The phase-10 bug, in its v3 form. A linked device that derived a
    // post-quantum key of its own would be a SECOND identity wearing the
    // account's name: it would show a different safety number for the same
    // contact, and a contact scanning it would be told to expect a key the
    // account cannot sign with. The account key is public, so it travels at
    // enrollment even though the account root does not.
    final phoneId = await ZIdentity.generate();
    final phone = await makePrimary('acctphone', phoneId);
    await waitUntil(() => phone.transport.isConnected, what: 'connected');
    final account = await phone.accountIdentity();
    final accountMl = (await phone.pqIdentity())!.publicKey.mlPub;

    final laptopId = await ZIdentity.generate();
    final cert = await account.signDeviceCert(
        deviceEdPub: laptopId.edPub,
        deviceXPub: laptopId.xPub,
        deviceId: 'laptop');
    final laptop = await makeLinked('acctlaptop', laptopId,
        account.withAccountMlPub(accountMl), cert, account.deviceCert);
    await waitUntil(() => laptop.transport.isConnected, what: 'laptop up');

    // The laptop holds no account root, so it cannot derive a key pair…
    expect(await laptop.pqIdentity(), isNull);
    // …but it knows the account's public half, and it is the SAME one. This
    // is what makes both devices show one safety number (§18.5).
    expect(await laptop.pqAccountPublic(), accountMl);
    expect(await phone.pqAccountPublic(), accountMl);

    // The code the ROOT hands out carries the commitment.
    final fromPhone = await scanContactCode(await phone.myContactCode());
    expect(fromPhone.assurance, IdentityAssurance.pendingPostQuantum);
    expect(
        fromPhone.v3!.pqCommit,
        await HybridPublicKey(edPub: account.accountEdPub, mlPub: accountMl)
            .pqCommitment());

    // And so does the laptop's — the SAME commitment, because there is one
    // account and one post-quantum identity. It can only do that because the
    // code is account-anchored (§18.7): a commitment binds the ACCOUNT's key
    // to the classical identity beside it, so before the code could name the
    // account, a linked device gluing the two together would have produced a
    // binding signature that does not verify.
    final laptopCode = await laptop.myContactCode();
    final fromLaptop = await scanContactCode(laptopCode);
    expect(fromLaptop.assurance, IdentityAssurance.pendingPostQuantum);
    expect(fromLaptop.v3!.pqCommit, fromPhone.v3!.pqCommit,
        reason: 'one account, one post-quantum identity');
    expect(fromLaptop.accountEdPub, account.accountEdPub);
    // The code still describes the DEVICE, because that is the mailbox a
    // contact can actually reach.
    expect(fromLaptop.classical.edPub, laptopId.edPub);

    // And the anchor is structural, not a courtesy of this call site: a code
    // claiming an account it cannot prove membership of will not be built.
    expect(
        () => ContactBundleV3.forIdentity(laptopId,
            HybridPublicKey(edPub: account.accountEdPub, mlPub: accountMl),
            accountEdPub: account.accountEdPub),
        throwsA(isA<FormatException>()),
        reason: 'a claim needs the certificate that proves it');
    expect(
        () => ContactBundleV3.forIdentity(laptopId,
            HybridPublicKey(edPub: account.accountEdPub, mlPub: accountMl)),
        throwsA(isA<FormatException>()),
        reason:
            "and unanchored, the laptop cannot speak for the account's key");
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('scanning a linked device adds the person, not the laptop', () async {
    // 13.6, and the last of the phase-10 family. A contact code names the
    // device showing it — true since v1, invisible while every account had
    // one device. Scanning someone's laptop therefore added the LAPTOP: their
    // device list failed the "signed by this contact's account key" check, so
    // multi-device delivery never worked for that contact, and their safety
    // number was computed against a per-device key, so two people who both
    // verified could read different numbers depending on which device each
    // had scanned.
    final phoneId = await ZIdentity.generate();
    final phone = await makePrimary('l6phone', phoneId);
    final carol = await makePrimary('l6carol', await ZIdentity.generate());
    await waitUntil(
        () => phone.transport.isConnected && carol.transport.isConnected,
        what: 'connected');
    final account = await phone.accountIdentity();
    final accountMl = await phone.pqAccountPublic();

    final laptopId = await ZIdentity.generate();
    final laptopCert = await account.signDeviceCert(
        deviceEdPub: laptopId.edPub,
        deviceXPub: laptopId.xPub,
        deviceId: 'laptop');
    final laptop = await makeLinked('l6laptop', laptopId,
        account.withAccountMlPub(accountMl!), laptopCert, account.deviceCert);
    await waitUntil(() => laptop.transport.isConnected, what: 'laptop up');
    await phone.addMyDevice(laptopCert);

    // Carol scans the LAPTOP's code.
    await carol.addContactFromCode(await laptop.myContactCode());
    final rid = laptop.myRid;
    final contact = carol.contacts[rid]!;

    // She reaches the laptop, because that is the mailbox in the code…
    expect(contact.bundle.edPub, laptopId.edPub);
    // …but the identity she has added is the account.
    expect(contact.accountEd, account.accountEdPub);
    expect(contact.deviceCert!.deviceId, 'laptop');

    // So the number she reads is the one she would have read from the phone.
    expect(
        await carol.safetyNumberWith(rid),
        await safetyNumber(
            (await carol.accountIdentity()).accountEdPub, account.accountEdPub),
        reason: 'one account, one number, whichever device was scanned');

    // And the commitment is the account's, so the post-quantum upgrade
    // completes from a scan of a laptop exactly as from a scan of the phone —
    // it could not be carried at all before 18.7.
    expect(contact.pqCommit, isNotNull);
    await laptop.addContactFromCode(await carol.myContactCode());
    await carol.sendText(rid, 'hello from carol');
    await waitUntil(() => carol.assuranceWith(rid) == IdentityAssurance.hybrid,
        what: "carol reaches hybrid from the laptop's code");
    expect(carol.contacts[rid]!.pqPub, accountMl,
        reason: "the key that arrived is the ACCOUNT's");
  }, timeout: const Timeout(Duration(minutes: 3)));

  test("a contact scanned from a laptop accepts that account's device list",
      () async {
    // The other half of the same bug, and the one with teeth: a device list
    // is rejected unless it is signed by the account key held for that
    // contact. Anchored to a device, that check could never pass, so a
    // contact added by scanning a laptop silently lost multi-device delivery
    // AND every 7.7a transparency guarantee that rides on the list.
    final phoneId = await ZIdentity.generate();
    final phone = await makePrimary('dlphone', phoneId);
    final carol = await makePrimary('dlcarol', await ZIdentity.generate());
    await waitUntil(
        () => phone.transport.isConnected && carol.transport.isConnected,
        what: 'connected');
    final account = await phone.accountIdentity();
    final accountMl = await phone.pqAccountPublic();

    final laptopId = await ZIdentity.generate();
    final laptopCert = await account.signDeviceCert(
        deviceEdPub: laptopId.edPub,
        deviceXPub: laptopId.xPub,
        deviceId: 'laptop');
    final laptop = await makeLinked('dllaptop', laptopId,
        account.withAccountMlPub(accountMl!), laptopCert, account.deviceCert);
    await waitUntil(() => laptop.transport.isConnected, what: 'laptop up');
    await phone.addMyDevice(laptopCert);

    await carol.addContactFromCode(await laptop.myContactCode());
    await laptop.addContactFromCode(await carol.myContactCode());
    await laptop.sendText(carol.myRid, 'from the laptop');
    await waitUntil(
        () => texts(carol, laptop.myRid).contains('from the laptop'),
        what: 'carol hears the laptop');

    // The account's list reaches her and VERIFIES — the check that could
    // never pass before, because it compares the list's account key against
    // the key held for this contact.
    var version = 0;
    await waitUntil(() {
      unawaited(
          carol.heldContactListVersion(laptop.myRid).then((v) => version = v));
      return version >= 2;
    }, what: "carol installs the account's device list");

    // …and no false alarm along the way. Without a linked device being able
    // to forward the list its root signed, Carol would hold a one-device list
    // for ever, watch the laptop claim a newer version on every message, and
    // be told after the grace period that "their device list changed but the
    // update never arrived" — 7.7a's alarm, raised by ordinary use, which is
    // how a real one stops being read.
    await Future<void>.delayed(carol.devlistGrace + const Duration(seconds: 1));
    await carol.sendText(laptop.myRid, 'still here');
    await waitUntil(() => texts(laptop, carol.myRid).contains('still here'),
        what: 'a later message still flows');
    expect(carol.contactDevlistAlerts[laptop.myRid], isNull,
        reason:
            'ordinary multi-device use must not raise a transparency alarm');

    // KNOWN GAP, not a 13.6 regression: Carol's fan-out now reaches the phone,
    // but the phone has never heard of Carol — a contact added on one device
    // is not propagated to that account's others. That predates §18.7 and was
    // simply unreachable while a contact could only be added by scanning a
    // root device. Tracked as ROADMAP 13.7.
    expect(phone.contacts.containsKey(carol.myRid), isFalse);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('a device linked before v3 stays honest rather than inventing a key',
      () async {
    // An enrollment performed by a build that predates v3 carries no account
    // post-quantum key. Such a device must show the classical number and a
    // code with no commitment — not fabricate an identity.
    final phoneId = await ZIdentity.generate();
    final phone = await makePrimary('oldphone', phoneId);
    await waitUntil(() => phone.transport.isConnected, what: 'connected');
    final account = await phone.accountIdentity();
    final laptopId = await ZIdentity.generate();
    final cert = await account.signDeviceCert(
        deviceEdPub: laptopId.edPub,
        deviceXPub: laptopId.xPub,
        deviceId: 'laptop');
    // NOTE: no withAccountMlPub — this is the pre-v3 enrollment.
    final laptop = await makeLinked(
        'oldlaptop', laptopId, account, cert, account.deviceCert);
    await waitUntil(() => laptop.transport.isConnected, what: 'laptop up');

    expect(await laptop.pqIdentity(), isNull);
    expect(await laptop.pqAccountPublic(), isNull);
    final code = await laptop.myContactCode();
    expect(code, startsWith('zc1.'));
    expect((await scanContactCode(code)).assurance, IdentityAssurance.classical,
        reason: 'no commitment is better than a made-up one');
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
