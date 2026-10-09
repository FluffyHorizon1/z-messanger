// Phase 33 — a linked device knows its contacts as well as the phone does.
//
// Linking a laptop handed it the account, and of each contact only a routing
// id, the device's keys and a name. The contact's account key and the
// certificate that proves the device is theirs WERE in the enrolment and
// were dropped on the floor; their post-quantum commitment and key, the
// records ADR 0027 and 26.3 keep beside them, and the tick the user had
// given them were never sent at all. So the laptop showed every contact a
// person had verified on their phone as unverified, under a different
// safety number for every contact added from someone's laptop, classical
// where the phone was post-quantum — and refused, as "not signed by this
// contact's account", every device list those contacts' accounts signed
// (the 2026-10-03 analysis, P1-5). Around it: a request, a decline and a
// block were the business of whichever device saw them; a request sent
// from a laptop told the person who accepted it that the laptop was the
// account; the account's post-quantum seed could be made twice; and a
// restore lost the 26.3 and ADR 0027 records.
//
// Everything here runs real `ChatService`s through a real relay, and a
// device is linked by the real ceremony (§10.1) over it.
//
// Criteria, each a test below:
//   1. a laptop linked after the phone added its contacts — one verified by
//      a connect ceremony whose key had not landed, one hybrid and verified
//      whose codes sign their commitment, one held as an account with a
//      certificate and another device, one holding an unsigned commitment
//      as a candidate and still waiting to be accepted — shows each with the
//      phone's safety number, verification state and post-quantum state,
//      holds the same device list for the third, and installs the next list
//      that contact's account signs;
//   2. a root that predates the per-contact state (it sends only what it
//      always sent) still links a new device, and the new device keeps each
//      contact's account key and certificate, talks to them, and learns its
//      root's bundle from the next list the root sends it, so its requests
//      are the account's;
//   3. a new root still links a device that predates it (one that reads
//      only what it always read), and that device talks to its contacts;
//   4. two first callers of `pqIdentity()` at once get one key — the one
//      the vault keeps, and the one the contact code commits to;
//   5. a device-list signature made with a post-quantum key the vault does
//      not keep is replaced at start by one that verifies, and the contact
//      that was handed the bad one is handed the good one;
//   6. a request reaches both devices, and a block on the phone holds on the
//      laptop — a later request to the laptop from the same person never
//      surfaces — and one on the laptop holds on the phone;
//   7. a request accepted on the laptop is accepted on the phone, which
//      answers the person who asked it, and one accepted on the phone is
//      accepted on the laptop; one declined on the phone is gone from the
//      laptop; and one declined on the laptop and delivered to the phone
//      again afterwards is not shown there again;
//   8. a request sent from a linked device ends with the recipient holding
//      the account — its root's routing id and key, the account's safety
//      number and device list — and reaching both of its devices;
//   9. a contact holding a laptop as an account of its own (a request from
//      a build before this one) comes to hold the account when the
//      account's list reaches it;
//  10. a restore keeps the records of ADR 0027 and 26.3 (`pqcs_`, `vpqc_`,
//      `pqcc_`): a code stripped of its signed commitment is still refused,
//      and the ceremony's tick and the candidate commitment are still held;
//  11. an enrolment too large for one relay frame is cut down in order —
//      list signatures, lists, then keys, a key with no commitment going as
//      its commitment and a tick on the post-quantum number as the classical
//      number with the commitment it covered — and the laptop shows each
//      contact verified at once, and as the phone does once their keys
//      arrive.
@Tags(['integration'])
@Timeout(Duration(minutes: 5))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/archive.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/connect_invites.dart';
import 'package:zapp/core/enrollment.dart';
import 'package:zapp/core/key_transparency.dart';
import 'package:zapp/core/models.dart';
import 'package:zapp/core/relay_url.dart';
import 'package:zapp/core/restore.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';

typedef Person = ({
  ChatService svc,
  Vault vault,
  Directory dir,
  ZIdentity id,
  String name,
});

typedef Installer = Future<void> Function(
    Vault vault, PairingResult result, String relayUrl);

/// What a device of the build before this one did with an enrolment — the
/// body of `NewDeviceLinkScreen._start` at e751133, as it stood: a routing
/// id, the scanned device's keys and a name for each contact, and nothing
/// else. It reads only the members it always read.
Future<void> installAsE751133(
    Vault vault, PairingResult result, String relayUrl) async {
  final acct = result.account;
  await vault.kvPut(
      'identity',
      jsonEncode(
          {'edSeed': b64(acct.deviceEdSeed), 'xSeed': b64(acct.deviceXSeed)}));
  await vault.kvPut('account', jsonEncode(acct.toJson()));
  await vault.kvPut('display_name', result.data.displayName ?? 'Me');
  await setRelayUrl(vault, relayUrl, acceptedInsecure: true);
  await vault.kvPut(
      'my_devices', jsonEncode([result.data.hostDeviceCert.toJson()]),
      sensitive: false);
  for (final b in result.data.contacts) {
    final dev = b.devices.first;
    final rid = b64url(await sha256Bytes(dev.deviceEdPub));
    await vault.db.insert(
      'contacts',
      {
        'rid': rid,
        'enc_bundle': await vault.seal(jsonEncode(ContactBundle(
                edPub: dev.deviceEdPub,
                xPub: dev.deviceXPub,
                bindingSig: dev.sig)
            .toJson())),
        'enc_name': await vault.seal(b.displayName ?? 'Unknown'),
        'ttl_seconds': 0,
        'verified': 0,
        'created_ms': DateTime.now().millisecondsSinceEpoch,
      },
      conflictAlgorithm: null,
    );
  }
}

/// How a device of THIS build installs an enrolment: the relay address as
/// the link screen stores it, then the enrolment.
Future<void> newDeviceInstall(
    Vault vault, PairingResult result, String relayUrl) async {
  await setRelayUrl(vault, relayUrl, acceptedInsecure: true);
  await installEnrollment(vault, result);
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  late Process relay;
  late int port;
  final temps = <Directory>[];
  final live = <Person>[];

  setUpAll(() async {
    HttpOverrides.global = null;
    final serverDir =
        '${Directory.current.parent.path}${Platform.pathSeparator}server';
    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    port = probe.port;
    await probe.close();
    relay = await Process.start('node', ['server.js'],
        workingDirectory: serverDir,
        environment: {'PORT': '$port', 'LOG_LEVEL': 'silent'});
    relay.stdout.drain<void>();
    relay.stderr.drain<void>();
    for (var i = 0; i < 100; i++) {
      try {
        final res = await (await HttpClient()
                .getUrl(Uri.parse('http://127.0.0.1:$port/health')))
            .close();
        await res.drain<void>();
        if (res.statusCode == 200) return;
      } catch (_) {}
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    fail('relay did not start');
  });

  // Every service a test started is stopped when it ends, so nothing one
  // test left running speaks into the next. Vaults are left open, as the
  // other relay-driven files leave them: a periodic sweep that has just
  // started would otherwise fail against a closed database.
  tearDown(() async {
    for (final x in live) {
      x.svc.dispose();
      await x.svc.transport.stop();
    }
    live.clear();
  });

  tearDownAll(() async {
    relay.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  String relayUrl() => 'ws://127.0.0.1:$port';

  Future<Directory> tempDir(String name) async {
    final d = await Directory.systemTemp.createTemp('z_le_$name');
    temps.add(d);
    return d;
  }

  /// A service over the vault in [dir], whose identity is the one the vault
  /// holds. The log is off: what is under test is not the log.
  Future<Person> boot(Directory dir, String name, {Vault? vault}) async {
    final v = vault ?? await Vault.open(rootOverride: dir);
    final id = await ZIdentity.fromJson(
        (jsonDecode((await v.kvGet('identity'))!) as Map)
            .cast<String, Object?>());
    final svc = await ChatService.init(
        vault: v,
        identity: id,
        displayName: await v.kvGet('display_name') ?? name,
        transport: Transport(identity: id, serverUrl: relayUrl()),
        ktConfig: KtConfig.off,
        // What is under test is what a linked device shows of each contact
        // beside its phone, read at one moment on both. An account moving
        // itself to v2-only lists between the two reads (ADR 0029) would
        // make them differ for a moment, so accounts here stay at stage 1:
        // the kill switch thrown.
        signDevlistV2Only: false);
    // The production delay is hours; what is under test is not the delay.
    svc.pqListDelay = const Duration(milliseconds: 150);
    final x = (svc: svc, vault: v, dir: dir, id: id, name: name);
    live.add(x);
    return x;
  }

  Future<Person> person(String name) async {
    final dir = await tempDir(name);
    final vault = await Vault.open(rootOverride: dir);
    await vault.kvPut(
        'identity', jsonEncode((await ZIdentity.generate()).toJson()));
    await vault.kvPut('display_name', name);
    return boot(dir, name, vault: vault);
  }

  /// The app stopped and started again on the same vault.
  Future<Person> restart(Person x) async {
    x.svc.dispose();
    await x.svc.transport.stop();
    await x.vault.db.close();
    live.remove(x);
    return boot(x.dir, x.name);
  }

  Future<void> waitUntil(bool Function() cond,
      {Duration timeout = const Duration(seconds: 45),
      required String what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  Future<void> waitFor(Future<bool> Function() cond,
      {Duration timeout = const Duration(seconds: 45),
      required String what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 60));
    }
  }

  Future<void> connected(List<Person> people) => waitUntil(
      () => people.every((x) => x.svc.transport.isConnected),
      what: 'everyone connected to the relay');

  /// [body] is in [x]'s chat [rid].
  Future<void> arrived(Person x, String rid, String body) => waitUntil(
      () => (x.svc.messagesByChat[rid] ?? []).any((m) => m.body == body),
      what: '"$body" in ${x.name}\'s chat with $rid');

  /// Both hold each other's post-quantum key and have finished saying so.
  Future<void> keysSettled(Person a, String bRid, Person b, String aRid) =>
      waitUntil(
          () =>
              a.svc.contacts[bRid]?.numberKey != null &&
              b.svc.contacts[aRid]?.numberKey != null &&
              !a.svc.pqSendPending &&
              !b.svc.pqSendPending,
          what: 'both post-quantum keys landed and the exchange went quiet');

  /// [a]'s screen for [aRid] and [b]'s for [bRid] show one safety number —
  /// once whatever post-quantum exchange is in the air has landed on both.
  Future<void> sameNumber(Person a, String aRid, Person b, String bRid) =>
      waitFor(
          () async =>
              !a.svc.pqSendPending &&
              !b.svc.pqSendPending &&
              await a.svc.safetyNumberWith(aRid) ==
                  await b.svc.safetyNumberWith(bRid),
          what: "${a.name} and ${b.name} read one safety number");

  /// [a] and [b] scan each other's codes and speak both ways.
  Future<void> pairUp(Person a, Person b) async {
    await connected([a, b]);
    await a.svc.addContactFromCode(await b.svc.myContactCode());
    await b.svc.addContactFromCode(await a.svc.myContactCode());
    await a.svc.sendText(b.svc.myRid, 'hi ${b.name}');
    await arrived(b, a.svc.myRid, 'hi ${b.name}');
    await b.svc.sendText(a.svc.myRid, 'hi ${a.name}');
    await arrived(a, b.svc.myRid, 'hi ${a.name}');
    await keysSettled(a, b.svc.myRid, b, a.svc.myRid);
  }

  /// [phone] links a new device by the real ceremony over the relay
  /// (§10.1): the new device shows its code, the phone hosts the link, both
  /// people say the digits match, and the new device installs what it was
  /// sent with [install] and starts.
  Future<Person> link(Person phone, String name, {Installer? install}) async {
    final n = await PairingInitiatorV2.create();
    final hosted =
        phone.svc.hostDeviceLink(n.code.text, confirmSas: (_) async => true);
    final result = await RelayPairing.runNewDeviceV2(
        relayUrl: relayUrl(), n: n, confirm: (_) async => true);
    expect(result, isNotNull, reason: 'the new device was enrolled');
    expect(await hosted, isTrue, reason: 'the phone linked it');
    final dir = await tempDir(name);
    final vault = await Vault.open(rootOverride: dir);
    await (install ?? newDeviceInstall)(vault, result!, relayUrl());
    final x = await boot(dir, name, vault: vault);
    await connected([x]);
    return x;
  }

  /// A device enrolled to [phone]'s account directly — for a CONTACT's
  /// account, where the ceremony is not what is under test.
  Future<Person> linkDirect(Person phone, String name) async {
    final account = await phone.svc.accountIdentity();
    final devId = await ZIdentity.generate();
    final cert = await account.signDeviceCert(
        deviceEdPub: devId.edPub, deviceXPub: devId.xPub, deviceId: name);
    final dir = await tempDir(name);
    final vault = await Vault.open(rootOverride: dir);
    await vault.kvPut('identity', jsonEncode(devId.toJson()));
    await vault.kvPut('display_name', phone.name);
    final enrolled = await AccountIdentity.fromEnrollment(
      accountEdPub: account.accountEdPub,
      accountMlPub: await phone.svc.pqAccountPublic(),
      deviceEdSeed: devId.edSeed,
      deviceXSeed: devId.xSeed,
      deviceId: name,
      deviceCert: cert,
    );
    await vault.kvPut('account', jsonEncode(enrolled.toJson()));
    await vault.kvPut(
        'my_devices', jsonEncode([account.deviceCert.toJson()]),
        sensitive: false);
    final x = await boot(dir, name, vault: vault);
    await connected([x, phone]);
    await phone.svc.addMyDevice(cert);
    await waitFor(() async => await x.svc.ownDeviceListVersion() >= 2,
        what: '$name learned its account\'s list');
    return x;
  }

  /// Erin, whose phone has a laptop linked, added by [a] from the LAPTOP's
  /// code — an account-anchored code (§18.7) — and holding [a]'s key and
  /// her account's list.
  Future<(Person, Person)> anchoredContact(Person a, String name) async {
    final erin = await person(name);
    final erinLaptop = await linkDirect(erin, '$name-laptop');
    await connected([a, erin, erinLaptop]);
    await a.svc.addContactFromCode(await erinLaptop.svc.myContactCode());
    await waitUntil(
        () => erinLaptop.svc.requestsByRid.containsKey(a.svc.myRid),
        what: "${a.name}'s request reached $name's laptop");
    await erinLaptop.svc.acceptRequest(a.svc.myRid);
    final rid = erinLaptop.svc.myRid;
    await a.svc.sendText(rid, 'hello $name');
    await arrived(erinLaptop, a.svc.myRid, 'hello $name');
    await keysSettled(a, rid, erinLaptop, a.svc.myRid);
    await waitFor(() async => await a.svc.heldContactListVersion(rid) >= 2,
        what: "${a.name} holds $name's account's list");
    return (erin, erinLaptop);
  }

  /// One side of a connect ceremony stepped until both show the digits.
  Future<void> danceTo(ConnectInvites a, ConnectInvites b) async {
    for (var i = 0; i < 8; i++) {
      await a.pump();
      await b.pump();
      if (a.invites.any((x) => x.sas != null) &&
          b.invites.any((x) => x.sas != null)) {
        return;
      }
    }
    fail('the ceremony did not reach the digits');
  }

  /// [b] added to [a] by a connect ceremony only [a] confirmed: [a] holds
  /// the tick and the commitment the digits covered, and [b]'s key never
  /// travels, because [b]'s app never added [a].
  Future<String> ceremonyNotAnswered(Person a, Person b) async {
    await connected([a, b]);
    final ai = ConnectInvites(a.svc), bi = ConnectInvites(b.svc);
    try {
      final invite = await ai.create();
      await bi.open(invite.link);
      await danceTo(ai, bi);
      return (await ai.confirm(ai.invites.single)).rid;
    } finally {
      ai.pause();
      bi.pause();
    }
  }

  /// Someone [a] adds from their classical code and who never comes online,
  /// then pastes a code of theirs whose commitment nobody signed: a
  /// candidate commitment (ADR 0027), and a request still waiting.
  Future<String> candidateCommitment(Person a, String name) async {
    final id = await ZIdentity.generate();
    final pq =
        await HybridKeyPair.fromSeeds(edSeed: id.edSeed, mlSeed: randomBytes(32));
    await a.svc.addContactFromCode((await id.bundle(displayName: name)).encode());
    await a.svc.addContactFromCode((await ContactBundleV3.forIdentity(
            id, pq.publicKey,
            displayName: name, signCommitment: false))
        .encode());
    final rid = await id.routingId();
    expect(a.svc.contacts[rid]!.pqcHint, isNotNull,
        reason: 'the unsigned commitment is held as a candidate');
    return rid;
  }

  String hexOf(Uint8List? b) => b == null ? '-' : b64(b);

  /// Everything a screen shows about [rid], as one comparable value.
  Future<Map<String, Object?>> shown(Person x, String rid) async {
    final c = x.svc.contacts[rid];
    if (c == null) return {'missing': rid};
    return {
      'number': await x.svc.safetyNumberWith(rid),
      'verification': x.svc.verificationWith(rid).name,
      'pq': c.pqDisplay.name,
      'assurance': c.assurance.name,
      'signedCommitments': c.pqcSigned,
      'ceremonyCovered': hexOf(c.verifiedPqc),
      'candidateCommitment': hexOf(c.pqcHint),
      'requested': c.requested,
      'account': b64(c.accountEd),
      'certificate': c.deviceCert != null,
      'devices': x.svc.deviceAssuranceWith(rid).name,
      'list': await x.svc.heldContactListVersion(rid),
    };
  }

  test(
      '1. a laptop linked after the phone added its contacts shows them as '
      'the phone does, and takes their accounts\' lists', () async {
    final alice = await person('Alice');
    final bob = await person('Bob');
    final dave = await person('Dave');
    final bobRid = await ceremonyNotAnswered(alice, bob);
    await pairUp(alice, dave);
    await alice.svc.setVerified(dave.svc.myRid, true);
    final (erin, erinLaptop) = await anchoredContact(alice, 'Erin');
    final erinRid = erinLaptop.svc.myRid;
    final fayRid = await candidateCommitment(alice, 'Fay');

    // What the phone shows is what each case is about.
    final onPhone = {
      for (final rid in [bobRid, dave.svc.myRid, erinRid, fayRid])
        rid: await shown(alice, rid)
    };
    expect(onPhone[bobRid]!['verification'], VerificationState.verified.name);
    expect(onPhone[bobRid]!['ceremonyCovered'], isNot('-'));
    expect(onPhone[dave.svc.myRid]!['verification'],
        VerificationState.verified.name);
    expect(onPhone[dave.svc.myRid]!['pq'], PqDisplay.postQuantum.name);
    expect(onPhone[dave.svc.myRid]!['signedCommitments'], isTrue);
    expect(onPhone[erinRid]!['certificate'], isTrue);
    expect(onPhone[erinRid]!['account'],
        b64((await erin.svc.accountIdentity()).accountEdPub));
    expect(onPhone[erinRid]!['list'], 2);
    expect(onPhone[fayRid]!['candidateCommitment'], isNot('-'));
    expect(onPhone[fayRid]!['requested'], isTrue);

    final laptop = await link(alice, 'Alice-laptop');
    for (final rid in onPhone.keys) {
      expect(await shown(laptop, rid), onPhone[rid],
          reason: 'the laptop shows $rid as the phone does');
    }

    // Erin's account signs its next list — a third device — and the laptop
    // installs it, as the phone does.
    await linkDirect(erin, 'Erin-tablet');
    await waitFor(
        () async => await laptop.svc.heldContactListVersion(erinRid) >= 3,
        what: "the laptop installed Erin's account's next list");
    await waitFor(
        () async => await alice.svc.heldContactListVersion(erinRid) >= 3,
        what: "the phone installed it too");
  });

  test(
      '2. a root that sends only what it always sent still links a device, '
      'which keeps each contact\'s account', () async {
    final alice = await person('Alice2');
    final dave = await person('Dave2');
    await pairUp(alice, dave);
    final (erin, erinLaptop) = await anchoredContact(alice, 'Erin2');
    final erinRid = erinLaptop.svc.myRid;
    final erinAccount = (await erin.svc.accountIdentity()).accountEdPub;

    // The phone links as a build from before phase 33 does.
    alice.svc.debugEnrollAsBefore = true;
    final laptop = await link(alice, 'Alice2-laptop');
    final held = laptop.svc.contacts[erinRid]!;
    expect(b64(held.accountEd), b64(erinAccount),
        reason: "the account key the enrolment carried is kept");
    expect(held.deviceCert, isNotNull,
        reason: 'and the certificate that proves the device is theirs');
    final mine = (await laptop.svc.accountIdentity()).accountEdPub;
    expect(await safetyNumber(mine, held.accountEd),
        await safetyNumber(mine, alice.svc.contacts[erinRid]!.accountEd),
        reason: 'so the classical number is the phone\'s');

    // And it talks, both ways.
    await laptop.svc.sendText(dave.svc.myRid, 'from the laptop');
    await arrived(dave, alice.svc.myRid, 'from the laptop');
    await dave.svc.sendText(alice.svc.myRid, 'to both of them');
    await arrived(laptop, dave.svc.myRid, 'to both of them');
    await arrived(alice, dave.svc.myRid, 'to both of them');

    // Linked without its root's bundle, it learns it from the list the root
    // sent it on linking, and a request it sends is then the account's.
    await waitFor(() async => await laptop.vault.kvGet(rootBundleKey) != null,
        what: "the laptop learned its root's bundle");
    final hal = await person('Hal2');
    await connected([hal]);
    await laptop.svc.addContactFromCode(await hal.svc.myContactCode());
    await waitUntil(() => hal.svc.requests.isNotEmpty,
        what: "the laptop's request reached Hal");
    expect(hal.svc.requests.single.rid, alice.svc.myRid,
        reason: "the account's request, under its root's routing id");
  });

  test(
      '3. a new root still links a device that reads only what it always '
      'read, and it talks', () async {
    final alice = await person('Alice3');
    final dave = await person('Dave3');
    await pairUp(alice, dave);
    final laptop =
        await link(alice, 'Alice3-laptop', install: installAsE751133);
    expect(laptop.svc.contacts.containsKey(dave.svc.myRid), isTrue,
        reason: 'the contact list came across');
    await laptop.svc.sendText(dave.svc.myRid, 'old laptop here');
    await arrived(dave, alice.svc.myRid, 'old laptop here');
    await dave.svc.sendText(alice.svc.myRid, 'hello old laptop');
    await arrived(laptop, dave.svc.myRid, 'hello old laptop');
  });

  test('4. two first callers of pqIdentity get one key, the one kept',
      () async {
    final alice = await person('Alice4');
    expect(await alice.vault.kvGet('pq_seed'), isNull,
        reason: 'a fresh account has not made its seed yet');
    final both = await Future.wait(
        [alice.svc.pqIdentity(), alice.svc.pqIdentity()]);
    final stored = await alice.vault.kvGet('pq_seed');
    expect(stored, isNotNull);
    final kept = await HybridKeyPair.fromSeeds(
        edSeed: alice.id.edSeed, mlSeed: unb64(stored!));
    for (final k in both) {
      expect(b64(k!.publicKey.mlPub), b64(kept.publicKey.mlPub),
          reason: 'each caller got the key the vault keeps');
    }
    final code = await scanContactCode(await alice.svc.myContactCode());
    expect(b64(code.v3!.pqCommit), b64(await kept.publicKey.pqCommitment()),
        reason: 'and the contact code commits to it');
  });

  test(
      '5. a list signature made with a key the vault does not keep is '
      'replaced at start, and re-sent', () async {
    var alice = await person('Alice5');
    final dave = await person('Dave5');
    await pairUp(alice, dave);
    // The account signs its first list — what its first log check does —
    // and the signature left there is one a second seed made: the race.
    alice.svc.pqListDelay = const Duration(hours: 1);
    await alice.svc.ktOwn();
    final list = SignedDeviceList.fromJson(
        (jsonDecode((await alice.vault.kvGet('own_list_json'))!) as Map)
            .cast<String, Object?>());
    final stray = await HybridKeyPair.fromSeeds(
        edSeed: alice.id.edSeed, mlSeed: randomBytes(32));
    final bad = await HybridDeviceListSignature.sign(accountKey: stray, list: list);
    await alice.vault.kvPut('own_list_mlsig', jsonEncode(bad.toJson()),
        sensitive: false);
    final ml = (await alice.svc.pqAccountPublic())!;
    Future<bool> daveHoldsGood() async {
      final held = await dave.svc.debugHeldPqListSignature(alice.svc.myRid);
      if (held == null) return false;
      return HybridDeviceListSignature.fromJson(
              (jsonDecode(held) as Map).cast<String, Object?>())
          .verifies(list, ml);
    }

    alice.svc.pqListDelay = const Duration(milliseconds: 150);
    await waitFor(
        () async =>
            await dave.svc.debugHeldPqListSignature(alice.svc.myRid) != null,
        what: 'the stray signature reached Dave');
    expect(await daveHoldsGood(), isFalse,
        reason: 'what Dave holds does not verify under the key Alice sends');

    alice = await restart(alice);
    await waitFor(() async {
      final now = await alice.vault.kvGet('own_list_mlsig');
      return now != null &&
          await HybridDeviceListSignature.fromJson(
                  (jsonDecode(now) as Map).cast<String, Object?>())
              .verifies(list, ml);
    }, what: "Alice's own list signature verifies under her key again");
    await waitFor(daveHoldsGood,
        what: 'Dave was handed the signature that verifies');
  });

  test(
      '6. a request reaches both devices, and a block on either holds on '
      'the other', () async {
    final alice = await person('Alice6');
    final laptop = await link(alice, 'Alice6-laptop');
    final mal = await person('Mal');
    await connected([mal]);
    await mal.svc.addContactFromCode(await alice.svc.myContactCode());
    await waitUntil(() => alice.svc.requestsByRid.containsKey(mal.svc.myRid),
        what: "Mal's request reached the phone");
    await waitUntil(() => laptop.svc.requestsByRid.containsKey(mal.svc.myRid),
        what: "and the laptop shows it too");

    await alice.svc.blockRequest(mal.svc.myRid);
    await waitUntil(
        () =>
            laptop.svc.isBlocked(mal.svc.myRid) &&
            !laptop.svc.requestsByRid.containsKey(mal.svc.myRid),
        what: 'the block on the phone holds on the laptop');

    // Mal tries the laptop instead: a request carried to it by hand, so the
    // test knows it was read.
    await mal.svc.transport.stop();
    await mal.svc.deleteContact(alice.svc.myRid);
    await mal.svc.addContactFromCode(await laptop.svc.myContactCode());
    final rows = await mal.vault.db.query('outbox',
        where: 'rid = ?', whereArgs: [laptop.svc.myRid]);
    expect(rows, isNotEmpty, reason: 'Mal wrote a request to the laptop');
    for (final r in rows) {
      await laptop.svc.debugInbound(RelayInbound(
          id: r['id'] as String,
          from: '',
          payload: r['payload'] as String,
          serverTs: DateTime.now().millisecondsSinceEpoch));
    }
    expect(laptop.svc.requestsByRid.containsKey(mal.svc.myRid), isFalse,
        reason: 'a person blocked on the phone cannot reach the laptop');

    // And the other way round.
    final nina = await person('Nina');
    await connected([nina]);
    await nina.svc.addContactFromCode(await laptop.svc.myContactCode());
    await waitUntil(
        () =>
            laptop.svc.requestsByRid.containsKey(nina.svc.myRid) &&
            alice.svc.requestsByRid.containsKey(nina.svc.myRid),
        what: "Nina's request on both devices");
    await laptop.svc.blockRequest(nina.svc.myRid);
    await waitUntil(
        () =>
            alice.svc.isBlocked(nina.svc.myRid) &&
            !alice.svc.requestsByRid.containsKey(nina.svc.myRid),
        what: 'the block on the laptop holds on the phone');
  });

  test(
      '7. a request accepted on either device is accepted on the other, and '
      'a decline on one is a decline on both', () async {
    final alice = await person('Alice7');
    final laptop = await link(alice, 'Alice7-laptop');
    final oscar = await person('Oscar');
    await connected([oscar]);
    await oscar.svc.addContactFromCode(await alice.svc.myContactCode());
    await waitUntil(
        () =>
            alice.svc.requestsByRid.containsKey(oscar.svc.myRid) &&
            laptop.svc.requestsByRid.containsKey(oscar.svc.myRid),
        what: "Oscar's request on both devices");

    await laptop.svc.acceptRequest(oscar.svc.myRid);
    expect(laptop.svc.contacts.containsKey(oscar.svc.myRid), isTrue);
    await waitUntil(
        () =>
            alice.svc.contacts.containsKey(oscar.svc.myRid) &&
            !alice.svc.requestsByRid.containsKey(oscar.svc.myRid),
        what: 'accepted on the phone too');
    await waitUntil(
        () => oscar.svc.contacts[alice.svc.myRid]?.requested == false,
        what: 'Oscar was answered');
    await oscar.svc.sendText(alice.svc.myRid, 'thanks');
    await arrived(alice, oscar.svc.myRid, 'thanks');
    await alice.svc.sendText(oscar.svc.myRid, 'welcome');
    await arrived(oscar, alice.svc.myRid, 'welcome');

    // The other way round: accepted on the phone, which it was sent to.
    final rhea = await person('Rhea');
    await connected([rhea]);
    await rhea.svc.addContactFromCode(await alice.svc.myContactCode());
    await waitUntil(
        () =>
            alice.svc.requestsByRid.containsKey(rhea.svc.myRid) &&
            laptop.svc.requestsByRid.containsKey(rhea.svc.myRid),
        what: "Rhea's request on both devices");
    await alice.svc.acceptRequest(rhea.svc.myRid);
    await waitUntil(
        () =>
            laptop.svc.contacts.containsKey(rhea.svc.myRid) &&
            !laptop.svc.requestsByRid.containsKey(rhea.svc.myRid),
        what: 'accepted on the laptop too');
    await waitUntil(
        () => rhea.svc.contacts[alice.svc.myRid]?.requested == false,
        what: 'Rhea was answered');

    final pat = await person('Pat');
    await connected([pat]);
    await pat.svc.addContactFromCode(await laptop.svc.myContactCode());
    await waitUntil(
        () =>
            laptop.svc.requestsByRid.containsKey(pat.svc.myRid) &&
            alice.svc.requestsByRid.containsKey(pat.svc.myRid),
        what: "Pat's request on both devices");
    await alice.svc.declineRequest(pat.svc.myRid);
    await waitUntil(
        () => !laptop.svc.requestsByRid.containsKey(pat.svc.myRid),
        what: 'declined on the laptop too');
    expect(laptop.svc.contacts.containsKey(pat.svc.myRid), isFalse);
    expect(laptop.svc.isBlocked(pat.svc.myRid), isFalse,
        reason: 'a decline is not a block');

    // A request made before a decline and delivered after it — late, or
    // again — is not shown again. Carried to the phone by hand, so the test
    // knows when it was read.
    final quinn = await person('Quinn');
    await quinn.svc.transport.stop();
    await quinn.svc.addContactFromCode(await alice.svc.myContactCode());
    final rows = await quinn.vault.db.query('outbox',
        where: 'rid = ?', whereArgs: [alice.svc.myRid], orderBy: 'seq');
    Future<void> deliver() async {
      for (final r in rows) {
        await alice.svc.debugInbound(RelayInbound(
            id: r['id'] as String,
            from: '',
            payload: r['payload'] as String,
            serverTs: DateTime.now().millisecondsSinceEpoch));
      }
    }

    await deliver();
    expect(alice.svc.requestsByRid.containsKey(quinn.svc.myRid), isTrue);
    await waitUntil(
        () => laptop.svc.requestsByRid.containsKey(quinn.svc.myRid),
        what: "Quinn's request on the laptop");
    await laptop.svc.declineRequest(quinn.svc.myRid);
    await waitUntil(
        () => !alice.svc.requestsByRid.containsKey(quinn.svc.myRid),
        what: 'declined on the phone too');
    await deliver();
    expect(alice.svc.requestsByRid.containsKey(quinn.svc.myRid), isFalse,
        reason: 'the request the laptop declined is not shown again');
  });

  test(
      '8. a request from a linked device leaves the recipient holding the '
      'account', () async {
    final alice = await person('Alice8');
    final laptop = await link(alice, 'Alice8-laptop');
    final frank = await person('Frank');
    await connected([frank]);
    final account = (await alice.svc.accountIdentity()).accountEdPub;

    await laptop.svc.addContactFromCode(await frank.svc.myContactCode());
    await waitUntil(() => frank.svc.requests.isNotEmpty,
        what: "the laptop's request reached Frank");
    expect(frank.svc.requests.single.rid, alice.svc.myRid,
        reason: "it is the account's request: its root's routing id");
    await frank.svc.acceptRequest(frank.svc.requests.single.rid);

    final held = frank.svc.contacts[alice.svc.myRid];
    expect(held, isNotNull, reason: 'Frank holds the account');
    expect(b64(held!.accountEd), b64(account));
    expect(frank.svc.contacts.containsKey(laptop.svc.myRid), isFalse,
        reason: 'and not the laptop as an account of its own');

    // Frank reaches both of the account's devices, and the laptop him.
    await frank.svc.sendText(alice.svc.myRid, 'hello Alice');
    await arrived(alice, frank.svc.myRid, 'hello Alice');
    await waitFor(
        () async => await frank.svc.heldContactListVersion(alice.svc.myRid) >= 2,
        what: "Frank holds the account's list");
    await frank.svc.sendText(alice.svc.myRid, 'and her laptop');
    await arrived(laptop, frank.svc.myRid, 'and her laptop');
    await laptop.svc.sendText(frank.svc.myRid, 'from the laptop');
    await arrived(frank, alice.svc.myRid, 'from the laptop');
    // And the number Frank reads is the one the account's devices read.
    await sameNumber(frank, alice.svc.myRid, alice, frank.svc.myRid);
    await sameNumber(frank, alice.svc.myRid, laptop, frank.svc.myRid);
  });

  test(
      '9. a contact holding a laptop as an account of its own comes to hold '
      'the account', () async {
    final alice = await person('Alice9');
    final laptop = await link(alice, 'Alice9-laptop');
    final gina = await person('Gina');
    await connected([gina]);
    final account = (await alice.svc.accountIdentity()).accountEdPub;

    // A request as every build before this one sent it from a laptop: the
    // laptop's own keys, and nothing to say whose they are.
    laptop.svc.debugPlainContactRequests = true;
    await laptop.svc.addContactFromCode(await gina.svc.myContactCode());
    await waitUntil(() => gina.svc.requests.isNotEmpty,
        what: "the laptop's request reached Gina");
    final rid = gina.svc.requests.single.rid;
    expect(rid, laptop.svc.myRid);
    await gina.svc.acceptRequest(rid);
    expect(b64(gina.svc.contacts[rid]!.accountEd),
        b64((await laptop.svc.accountIdentity()).deviceEdPub),
        reason: 'held as an account of its own');

    // They speak; the account's list reaches her, and with it the account.
    await gina.svc.sendText(rid, 'hi laptop');
    await arrived(laptop, gina.svc.myRid, 'hi laptop');
    await waitUntil(
        () => b64(gina.svc.contacts[rid]!.accountEd) == b64(account),
        what: 'Gina holds the account');
    expect(gina.svc.contacts[rid]!.deviceCert, isNotNull);
    await waitFor(() async => await gina.svc.heldContactListVersion(rid) >= 2,
        what: "and the account's list");
    // The number she reads is the one the account's devices read.
    await sameNumber(gina, rid, laptop, gina.svc.myRid);
  });

  test('10. a restore keeps the records of ADR 0027 and 26.3', () async {
    final alice = await person('Alice10');
    final bob = await person('Bob10');
    final bobRid = await ceremonyNotAnswered(alice, bob);
    final fayRid = await candidateCommitment(alice, 'Fay10');
    final before = {
      bobRid: await shown(alice, bobRid),
      fayRid: await shown(alice, fayRid),
    };
    expect(before[bobRid]!['signedCommitments'], isTrue);
    expect(before[bobRid]!['ceremonyCovered'], isNot('-'));
    expect(before[fayRid]!['candidateCommitment'], isNot('-'));

    final code = await RecoveryCode.generate();
    final file = File(p.join((await tempDir('zbk')).path, 'b.zbk'));
    final sink = file.openWrite();
    await BackupArchive.export(vault: alice.vault, code: code, out: sink);
    await sink.close();

    alice.svc.dispose();
    await alice.svc.transport.stop();
    live.remove(alice);
    final dir = await tempDir('Alice10-restored');
    final vault = await Vault.open(rootOverride: dir);
    await Restore.run(
      vault: vault,
      file: file,
      secret: await code.format(),
      kind: (await Restore.identify(file)).kind,
      serverUrl: relayUrl(),
    );
    final back = await boot(dir, 'Alice10', vault: vault);
    for (final rid in before.keys) {
      expect(await shown(back, rid), before[rid],
          reason: 'restored, $rid is as it was');
    }
    // Bob's codes sign their commitment, and a code of his without the
    // signature is still refused for it.
    final stripped = await bob.svc.myContactCode();
    final j = (jsonDecode(utf8.decode(unb64url(stripped.substring(4)))) as Map)
        .cast<String, Object?>()
      ..remove('pqcs');
    await expectLater(
        back.svc.addContactFromCode(
            stripped.substring(0, 4) + b64url(utf8.encode(jsonEncode(j)))),
        throwsA(isA<ContactCodeRefused>().having(
            (e) => e.kind, 'kind', ContactCodeRefusal.commitStripped)));
  });

  test(
      '11. an enrolment cut down to one relay frame still shows each contact '
      'as the phone does', () async {
    final alice = await person('Alice11');
    final dave = await person('Dave11');
    await pairUp(alice, dave);
    await alice.svc.setVerified(dave.svc.myRid, true); // the post-quantum number
    // Gus asked and Alice accepted, so no commitment came with him; the
    // number they compared confirmed his key (ADR 0021).
    final gus = await person('Gus11');
    await connected([gus]);
    await gus.svc.addContactFromCode(await alice.svc.myContactCode());
    await waitUntil(() => alice.svc.requestsByRid.containsKey(gus.svc.myRid),
        what: "Gus's request reached Alice");
    await alice.svc.acceptRequest(gus.svc.myRid);
    await alice.svc.sendText(gus.svc.myRid, 'hi Gus');
    await arrived(gus, alice.svc.myRid, 'hi Gus');
    await keysSettled(alice, gus.svc.myRid, gus, alice.svc.myRid);
    await waitUntil(
        () => alice.svc.contacts[gus.svc.myRid]!.showsPostQuantumNumber,
        what: "Gus's post-quantum number shows on Alice's screen");
    await alice.svc.setVerified(gus.svc.myRid, true);
    expect(alice.svc.contacts[gus.svc.myRid]!.pqPub, isNotNull);
    expect(alice.svc.contacts[gus.svc.myRid]!.pqCommit, isNull);

    // Room for the account bundles and the smallest per-contact state only.
    final bundles = alice.svc.contactsAsBundles();
    final base =
        utf8.encode(jsonEncode([for (final b in bundles) b.toJson()])).length;
    int size(List<Map<String, Object?>> st) => utf8.encode(jsonEncode(st)).length;
    final smallest = size(await alice.svc.enrollmentState(level: 3));
    expect(size(await alice.svc.enrollmentState(level: 2)),
        greaterThan(smallest + 1000),
        reason: 'the keys are what the last cut takes');
    alice.svc.enrollmentBudgetBytes = base + smallest + 64;

    final onPhone = {
      for (final rid in [dave.svc.myRid, gus.svc.myRid])
        rid: await shown(alice, rid)
    };
    final laptop = await link(alice, 'Alice11-laptop');
    for (final rid in onPhone.keys) {
      final c = laptop.svc.contacts[rid]!;
      expect(c.pqPub, isNull, reason: 'the key was cut');
      expect(c.pqCommit, isNotNull,
          reason: 'its commitment was not, or was sent in its place');
      expect(laptop.svc.verificationWith(rid), VerificationState.verified,
          reason: 'verified at once, on the number the laptop can compute');
    }
    for (final rid in onPhone.keys) {
      await waitFor(
          () async =>
              jsonEncode(await shown(laptop, rid)) == jsonEncode(onPhone[rid]),
          what: 'the laptop shows $rid as the phone does, its key landed');
    }
  });
}
