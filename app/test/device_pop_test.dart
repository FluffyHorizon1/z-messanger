// A device that has proved whose it is cannot be taken by another account's
// list, whichever arrived first (ADR 0022, PROTOCOL §3.1, §3.4).
//
// A device certificate proves that an account SIGNED it, not that whoever
// holds the account holds the device key it names, so any contact can list
// another person's device. Since patch 41 a receiver refuses a list naming a
// device it already holds for another account — but only first come: a claim
// that reaches a receiver before the real owner's list took the device there,
// and the owner's list, arriving second, was the one refused. A certificate
// now carries a proof of possession: the device's own signature, naming its
// account. A list proving a device takes it from a list that held it by the
// first-come rule, and a device once proven for one account is not accepted
// for another while a contact of that account is held.
//
// Real clients through the real relay. The claimant is a peer running
// modified code, which is the only kind that can make such a list; it sends it
// with `debugSendRawInner`. A device "from before ADR 0022" is a client of
// this build with `debugNoDevicePop` set: it never hands its proof to its root.
//
// Criteria, each a test below:
//   1. first come, closed for a proven device: a contact's list claiming my
//      contact's linked device reaches me BEFORE my contact's own list, and
//      takes it, and my contact's list is refused — until the list carries the
//      device's proof, which my next message to my contact brings back; then
//      the claim is withdrawn, my contact's list installs, the claimant's chat
//      says whose device it proved to be, and the device's messages arrive as
//      my contact's. (On 0d00a69 the claim keeps the device.)
//   2. likewise for one of MY devices: a contact's list naming a device of
//      mine before this device knew it was mine — the root, and a linked
//      device learning it from the root's list — is withdrawn when my own list
//      names it. (On 0d00a69 the claim keeps it until a restart.)
//   3. migration: a device linked by a build without proofs hands its own to
//      its root at its first start on a build with them; the root keeps it,
//      re-signs and sends nothing for it, and the account's next list carries
//      it to a contact, which then holds the device proven for that account;
//      and the device's own copy of the list then carries it too;
//   4. a device that never makes a proof still works: listed, heard from as
//      its account, reached, and kept on the account's later lists;
//   5. for a device that has proved nothing, patch 41's rule holds: a claim on
//      it while it is held for its owner is refused, naming both and accusing
//      neither, and a claim that arrives first keeps it — the owner's list is
//      refused, and stays refused when it is handed over again;
//   6. a device once proven for one account is refused in any other's list:
//      at once, and after its owner's list has dropped it — the claimant's
//      chat naming the owner, in English and in Spanish — and a code naming
//      it for another account is refused at the scan;
//   7. once a contact's list has carried a device's proof, a list from them
//      naming it without — the member taken off, or a ratchet key swapped
//      under the old proof — is refused in-band and from the log, nothing
//      installed and nothing said, and their next honest list installs;
//   8. what was proven survives a restart — a list an earlier build installed
//      is held to it at start-up — and goes when the account's last contact
//      record is deleted, with the alerts that named them;
//   9. a claim on someone who is not a contact yet: a list naming a person's
//      linked device reaches me before I add them from that device's code,
//      which signs their account (ADR 0027); the add takes the device back,
//      so its messages arrive as theirs. (On 0d00a69 the claim keeps it, and
//      the device is never heard.)
@Tags(['integration'])
@Timeout(Duration(minutes: 6))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart' show DatabaseException;
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/system_messages.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/alert_text.dart';
import 'package:zapp/l10n/app_localizations_en.dart';
import 'package:zapp/l10n/app_localizations_es.dart';
import 'package:z_protocol/z_protocol.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  late Process relay;
  late int port;
  final dirs = <String, Directory>{};
  final live = <ChatService>[];

  // Each service runs in an error zone of its own; an error raised inside a
  // running service fails the test that was running. A service [stop] has
  // shut down can still have work in flight that then fails against the
  // database it closed — that error, and only that one, is expected.
  final stopped = <ChatService>{};
  final strays = <String>[];
  tearDown(() {
    final found = [...strays];
    strays.clear();
    expect(found, isEmpty, reason: 'errors raised inside a running service');
  });

  setUpAll(() async {
    HttpOverrides.global = null;
    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    port = probe.port;
    await probe.close();
    relay = await Process.start('node', ['server.js'],
        workingDirectory:
            '${Directory.current.parent.path}${Platform.pathSeparator}server',
        environment: {'PORT': '$port', 'LOG_LEVEL': 'silent'});
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

  tearDownAll(() async {
    for (final s in live.toList()) {
      s.dispose();
      await s.transport.stop();
    }
    relay.kill();
    for (final d in dirs.values) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<ChatService> run(String name, Vault vault, ZIdentity id) {
    final ready = Completer<ChatService>();
    ChatService? made;
    runZonedGuarded(() async {
      try {
        final svc = await ChatService.init(
          vault: vault,
          identity: id,
          displayName: name,
          transport: Transport(identity: id, serverUrl: 'ws://127.0.0.1:$port'),
          // ADR 0022 is what this file tests: proofs, claims and patch 41's
          // first-come rule, on dual-signed lists. The v2-only move (ADR 0029)
          // is a separate concern with its own tests; left on, its one-time
          // version bump once the gate opens lands on top of the versions
          // these criteria count, so every account here keeps the switch
          // thrown and the list stays dual-signed.
          signDevlistV2Only: false,
        );
        made = svc;
        live.add(svc);
        ready.complete(svc);
      } catch (e, st) {
        ready.completeError(e, st);
      }
    }, (e, st) {
      final svc = made;
      if (svc != null &&
          stopped.contains(svc) &&
          e is DatabaseException &&
          e.isDatabaseClosedError()) {
        return;
      }
      strays.add('$name: $e\n$st');
    });
    return ready.future;
  }

  /// [name]'s client: a new account the first time, the same vault after
  /// [stop] — a linked device's included, which keeps its account.
  Future<ChatService> start(String name) async {
    final dir =
        dirs[name] ??= await Directory.systemTemp.createTemp('z_pop_$name');
    final vault = await Vault.open(rootOverride: dir);
    final stored = await vault.kvGet('identity');
    final ZIdentity id;
    if (stored == null) {
      id = await ZIdentity.generate();
      await vault.kvPut('identity', jsonEncode(id.toJson()));
    } else {
      id = await ZIdentity.fromJson(
          (jsonDecode(stored) as Map).cast<String, Object?>());
    }
    return run(name, vault, id);
  }

  /// A device linked to [host]'s account, as `hostDeviceLink` enrolls one,
  /// running as a client of its own. The host still has to list it
  /// (`addMyDevice`). Its certificate carries no proof: the root signs it
  /// and cannot make one.
  Future<({ChatService svc, DeviceCertificate cert})> linkedTo(
      ChatService host, String name) async {
    final account = await host.accountIdentity();
    final ml = await host.pqAccountPublic();
    final devId = await ZIdentity.generate();
    final cert = await account.signDeviceCert(
        deviceEdPub: devId.edPub, deviceXPub: devId.xPub, deviceId: name);
    final dir =
        dirs[name] = await Directory.systemTemp.createTemp('z_pop_$name');
    final vault = await Vault.open(rootOverride: dir);
    await vault.kvPut('identity', jsonEncode(devId.toJson()));
    final enrolled = await AccountIdentity.fromEnrollment(
      accountEdPub: account.accountEdPub,
      accountMlPub: ml,
      deviceEdSeed: devId.edSeed,
      deviceXSeed: devId.xSeed,
      deviceId: name,
      deviceCert: cert,
    );
    await vault.kvPut('account', jsonEncode(enrolled.toJson()));
    await vault.kvPut('my_devices', jsonEncode([account.deviceCert.toJson()]),
        sensitive: false);
    return (svc: await run(name, vault, devId), cert: cert);
  }

  Future<void> stop(ChatService svc) async {
    stopped.add(svc);
    svc.dispose();
    await svc.transport.stop();
    live.remove(svc);
    await svc.vault.db.close();
  }

  Future<void> waitUntil(FutureOr<bool> Function() cond,
      {required String what,
      Duration timeout = const Duration(seconds: 30)}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  /// [waitUntil] for a criterion whose verdict is the `expect` after it: it
  /// polls until [cond] holds or [timeout] passes and returns either way, so
  /// that a build on which the condition never comes true — the base this
  /// was written against — reaches that `expect` and says what it found.
  Future<void> upTo(FutureOr<bool> Function() cond,
      {required String what,
      Duration timeout = const Duration(seconds: 20)}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        printOnFailure('not within ${timeout.inSeconds}s: $what');
        return;
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  bool linked(ChatService s) =>
      s.transport.isConnected && s.transport.isSenderConnected;

  bool received(ChatService svc, String rid, String body) =>
      svc.messagesByChat[rid]?.any((m) => !m.outgoing && m.body == body) ==
      true;

  /// Two accounts that have exchanged codes and a message each way.
  Future<void> introduce(ChatService a, ChatService b) async {
    await waitUntil(() => linked(a) && linked(b), what: 'both connected');
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
    await a.sendText(b.myRid, 'hello ${b.displayName}');
    await b.sendText(a.myRid, 'hello ${a.displayName}');
    await waitUntil(
        () =>
            received(a, b.myRid, 'hello ${a.displayName}') &&
            received(b, a.myRid, 'hello ${b.displayName}'),
        what: '${a.displayName} and ${b.displayName} have spoken');
  }

  /// [from] says [text] to [to], and it arrives — filed under [asRid].
  Future<void> heard(ChatService from, ChatService to, String asRid,
      String text) async {
    await from.sendText(to.myRid, text);
    await waitUntil(() => received(to, asRid, text),
        what: '"$text" reaches ${to.displayName}');
  }

  /// The list [svc] holds installed for [rid]'s account, as stored.
  Future<String?> heldRow(ChatService svc, String rid) =>
      svc.vault.kvGet('cdev_$rid');

  /// [claimant]'s own devices plus a device under [keysOf]'s public keys,
  /// signed by [claimant]'s account at [version] — what a modified client
  /// can sign, since the account signs whatever certificate it is handed.
  Future<SignedDeviceList> claim(ChatService claimant,
      ({Uint8List edPub, Uint8List xPub}) keysOf, int version) async {
    final acct = await claimant.accountIdentity();
    final crafted = await acct.signDeviceCert(
        deviceEdPub: keysOf.edPub, deviceXPub: keysOf.xPub, deviceId: 'extra');
    return acct.signDeviceList(
        [...await claimant.myFullDeviceList(), crafted], version);
  }

  Future<void> sendList(
          ChatService from, ChatService to, SignedDeviceList list) =>
      from.debugSendRawInner(
          to.myRid,
          InnerMessage(
              kind: 'devlist',
              mid: newMessageId(),
              ts: DateTime.now().millisecondsSinceEpoch,
              data: {'list': jsonEncode(list.toJson())}));

  ({Uint8List edPub, Uint8List xPub}) keysOfCert(DeviceCertificate c) =>
      (edPub: c.deviceEdPub, xPub: c.deviceXPub);

  /// The kind of the device-list alert [svc] holds on [rid]'s chat, and the
  /// contact it names besides them — read from the stored JSON.
  ({String? k, Object? with_}) alertOn(ChatService svc, String rid) {
    final s = svc.contactDevlistAlerts[rid];
    if (s == null) return (k: null, with_: null);
    final m = jsonDecode(s) as Map;
    return (k: m['k'] as String?, with_: m['with']);
  }

  /// Waits for [svc] to refuse a list from [rid] for naming a device held
  /// elsewhere: the alert that refusal raises.
  Future<void> refused(ChatService svc, String rid) => waitUntil(
      () => isSharedDeviceAlert(svc.contactDevlistAlerts[rid]),
      what: '${svc.displayName} refuses the list from $rid');

  /// Whether [host]'s root holds a proof of possession for its linked
  /// device [deviceRid] — read from the certificates it holds, in the form
  /// it stores them.
  Future<bool> rootHoldsProof(ChatService host, String deviceRid) async {
    for (final c in await host.linkedDevices()) {
      if (await c.routingId() == deviceRid && c.toJson().containsKey('pop')) {
        return true;
      }
    }
    return false;
  }

  test(
      "1. a contact's list claiming my contact's device arrives first and "
      'takes it, and loses it when the device proves whose it is', () async {
    final vic = await start('vic1');
    final bob = await start('bob1');
    final mal = await start('mal1');
    await introduce(vic, bob);
    await introduce(vic, mal);
    // Bob's laptop, its client running. Its keys reach Mal before Bob's
    // list reaches Vic — from Bob's list to Mal, a group's member list, the
    // laptop's own code — and Mal lists them at once.
    final laptop = await linkedTo(bob, 'bob1laptop');
    final laptopRid = await laptop.cert.routingId();
    await sendList(mal, vic,
        await claim(mal, keysOfCert(laptop.cert),
            await vic.heldContactListVersion(mal.myRid) + 1));
    await waitUntil(() => vic.debugListedDeviceOwner(laptopRid) == mal.myRid,
        what: "Mal's claim installed: nothing held contradicted it");

    // Bob lists his laptop. The root has no proof from it yet, so the list
    // proves nothing, and here it is the one refused: first come.
    await bob.addMyDevice(laptop.cert);
    await refused(vic, bob.myRid);
    expect(vic.debugListedDeviceOwner(laptopRid), mal.myRid);
    expect(await vic.heldContactListVersion(bob.myRid), 1);

    // The laptop hands its proof to Bob's root when Bob's list reaches it.
    await upTo(() => rootHoldsProof(bob, laptopRid),
        what: "Bob's root holds the laptop's proof");
    // Vic's next message to Bob echoes the list she holds for him — the one
    // before the laptop — and Bob's root hands the list over again: the same
    // version, carrying the proof now.
    await vic.sendText(bob.myRid, 'still there?');
    await upTo(() => vic.debugListedDeviceOwner(laptopRid) == bob.myRid,
        what: "Vic holds the laptop for Bob");
    expect(vic.debugListedDeviceOwner(laptopRid), bob.myRid,
        reason: 'a claim that arrived first is withdrawn once the device '
            'proves whose it is');
    expect(await vic.heldContactListVersion(bob.myRid), 2,
        reason: "Bob's list installed");
    expect(alertOn(vic, mal.myRid), (k: 'dl_claimed', with_: bob.myRid),
        reason: "Mal's chat says whose device it proved to be");
    expect(vic.contactDevlistAlerts[bob.myRid], isNull,
        reason: "the refusal of Bob's list is superseded");

    // The laptop is Bob's, both ways, and never Mal's.
    await waitUntil(() => linked(laptop.svc), what: 'the laptop connected');
    await laptop.svc.addContactFromCode(await vic.myContactCode());
    await heard(laptop.svc, vic, bob.myRid, "from Bob's laptop");
    expect(received(vic, mal.myRid, "from Bob's laptop"), isFalse);
    await heard(mal, vic, mal.myRid, 'Mal is still a contact');
  });

  test(
      "2. a contact's list naming a device of mine before I knew it is "
      'withdrawn when my own list names it', () async {
    final vic = await start('vic2');
    final mal = await start('mal2');
    // Vic's laptop first, so that Mal, added after, reaches it too.
    final laptop = await linkedTo(vic, 'vic2laptop');
    await vic.addMyDevice(laptop.cert);
    await introduce(vic, mal);
    await waitUntil(
        () =>
            laptop.svc.contacts.containsKey(mal.myRid) &&
            mal.debugListedDeviceOwner(laptop.svc.myRid) == vic.myRid,
        what: "the laptop knows Mal, and Mal holds Vic's list with it");
    // A tablet Vic is about to link. Mal has its keys first and lists them;
    // his list reaches Vic's phone and Vic's laptop.
    final tabletId = await ZIdentity.generate();
    final tabletCert = await (await vic.accountIdentity()).signDeviceCert(
        deviceEdPub: tabletId.edPub,
        deviceXPub: tabletId.xPub,
        deviceId: 'tablet');
    final tabletRid = await tabletCert.routingId();
    await sendList(mal, vic,
        await claim(mal, keysOfCert(tabletCert),
            await vic.heldContactListVersion(mal.myRid) + 1));
    await waitUntil(
        () =>
            vic.debugListedDeviceOwner(tabletRid) == mal.myRid &&
            laptop.svc.debugListedDeviceOwner(tabletRid) == mal.myRid,
        what: "Mal's claim installed on both of Vic's devices");

    // Vic links the tablet: the phone lists it, and the laptop learns it
    // from the phone's list.
    await vic.addMyDevice(tabletCert);
    // On each, the routing changes first and the alert is written last.
    await upTo(
        () =>
            vic.debugListedDeviceOwner(tabletRid) == null &&
            laptop.svc.debugListedDeviceOwner(tabletRid) == null &&
            alertOn(vic, mal.myRid).k == 'dl_shared_mine' &&
            alertOn(laptop.svc, mal.myRid).k == 'dl_shared_mine',
        what: "the claim withdrawn on both of Vic's devices, and said");
    expect(vic.debugListedDeviceOwner(tabletRid), isNull,
        reason: 'the phone: the tablet is mine, whoever listed it first');
    expect(laptop.svc.debugListedDeviceOwner(tabletRid), isNull,
        reason: "the laptop, once its account's list names the tablet");
    for (final s in [vic, laptop.svc]) {
      expect(alertOn(s, mal.myRid).k, 'dl_shared_mine', reason: s.displayName);
    }
    await heard(mal, vic, mal.myRid, 'Mal is still a contact');
  });

  test(
      '3. a device linked before proofs hands its own to its root, and the '
      "account's next list carries it", () async {
    final vic = await start('vic3');
    final bob = await start('bob3');
    await introduce(vic, bob);
    final bobAcct = (await bob.accountIdentity()).accountEdPub;
    final laptop = await linkedTo(bob, 'bob3laptop');
    laptop.svc.debugNoDevicePop = true; // a build from before ADR 0022
    final laptopRid = await laptop.cert.routingId();
    await bob.addMyDevice(laptop.cert);
    await waitUntil(() => vic.debugListedDeviceOwner(laptopRid) == bob.myRid,
        what: "Vic installs Bob's list with the laptop");
    await waitUntil(
        () async => await laptop.svc.vault.kvGet('own_list_json') != null,
        what: "the laptop learned its account's list");
    expect(vic.debugProvenDevice(laptopRid), isNull,
        reason: 'nothing proven: the old build made no proof');
    expect(await rootHoldsProof(bob, laptopRid), isFalse);

    // The laptop updated: the same vault, a build that makes proofs.
    await stop(laptop.svc);
    final updated = await start('bob3laptop');
    await waitUntil(() => rootHoldsProof(bob, laptopRid),
        what: "Bob's root holds the laptop's proof");
    final held = (await bob.linkedDevices()).single;
    expect(held.pop, await (await updated.accountIdentity()).devicePop(),
        reason: "the laptop's own signature");
    expect(await held.provesPossession(bobAcct), isTrue);
    expect(await vic.heldContactListVersion(bob.myRid), 2,
        reason: 'nothing re-signed or sent for it');
    expect(vic.debugProvenDevice(laptopRid), isNull);

    // The account's next list: Bob links a tablet, and the list carries the
    // laptop's proof to Vic.
    final tablet = await ZIdentity.generate();
    await bob.addMyDevice(await (await bob.accountIdentity()).signDeviceCert(
        deviceEdPub: tablet.edPub, deviceXPub: tablet.xPub, deviceId: 'tablet'));
    await waitUntil(
        () async =>
            await vic.heldContactListVersion(bob.myRid) == 3 &&
            vic.debugProvenDevice(laptopRid) != null,
        what: "Vic installs Bob's next list, and holds the laptop proven");
    expect(vic.debugProvenDevice(laptopRid), (acct: b64(bobAcct), inList: true));
    final list = SignedDeviceList.fromJson(
        (jsonDecode((await heldRow(vic, bob.myRid))!) as Map)
            .cast<String, Object?>());
    final carried =
        list.devices.firstWhere((d) => b64(d.deviceEdPub) == b64(held.deviceEdPub));
    expect(carried.pop, held.pop);
    expect(vic.debugProvenDevice(await tablet.routingId()), isNull,
        reason: 'the tablet has no client and has proved nothing');
    expect(vic.debugProvenDevice(bob.myRid), (acct: b64(bobAcct), inList: true),
        reason: "the root's own device proves it with its certificate");
    // And the laptop's own copy of its account's list carries its proof.
    await waitUntil(
        () async =>
            (await updated.vault.kvGet('own_list_json'))
                ?.contains(b64(held.pop!)) ==
            true,
        what: "the laptop's copy of the list carries its proof");
  });

  test(
      '4. a device that never makes a proof still works: listed, heard and '
      'reached', () async {
    final vic = await start('vic4');
    final bob = await start('bob4');
    await introduce(vic, bob);
    final laptop = await linkedTo(bob, 'bob4laptop');
    laptop.svc.debugNoDevicePop = true;
    final laptopRid = await laptop.cert.routingId();
    await bob.addMyDevice(laptop.cert);
    await waitUntil(() => vic.debugListedDeviceOwner(laptopRid) == bob.myRid,
        what: "Vic installs Bob's list with the old laptop");
    await waitUntil(() => linked(laptop.svc), what: 'the laptop connected');
    await laptop.svc.addContactFromCode(await vic.myContactCode());
    await heard(laptop.svc, vic, bob.myRid, 'from the old laptop');
    await vic.sendText(bob.myRid, 'to all of you');
    await waitUntil(() => received(laptop.svc, vic.myRid, 'to all of you'),
        what: 'the old laptop is reached');

    // Bob's next list, still without the laptop's proof, installs: nothing
    // was ever proven for it, so nothing is required.
    final tablet = await ZIdentity.generate();
    await bob.addMyDevice(await (await bob.accountIdentity()).signDeviceCert(
        deviceEdPub: tablet.edPub, deviceXPub: tablet.xPub, deviceId: 'tablet'));
    final tabletRid = await tablet.routingId();
    await waitUntil(() => vic.debugListedDeviceOwner(tabletRid) == bob.myRid,
        what: "Vic installs Bob's next list");
    expect(vic.debugListedDeviceOwner(laptopRid), bob.myRid);
    expect(vic.debugProvenDevice(laptopRid), isNull);
    expect(vic.contactDevlistAlerts[bob.myRid], isNull);
    await heard(laptop.svc, vic, bob.myRid, 'still from the old laptop');
  });

  test(
      "5. a device that has proved nothing keeps patch 41's rule: held is "
      'refused, and first come keeps it', () async {
    final vic = await start('vic5');
    final bob = await start('bob5');
    final mal = await start('mal5');
    await introduce(vic, bob);
    await introduce(vic, mal);
    final laptop = await linkedTo(bob, 'bob5laptop');
    laptop.svc.debugNoDevicePop = true;
    final laptopRid = await laptop.cert.routingId();
    await bob.addMyDevice(laptop.cert);
    await waitUntil(() => vic.debugListedDeviceOwner(laptopRid) == bob.myRid,
        what: "Vic holds the old laptop for Bob");

    // Held for Bob: Mal's claim is refused, naming both, accusing neither.
    final malRow = await heldRow(vic, mal.myRid);
    await sendList(mal, vic,
        await claim(mal, keysOfCert(laptop.cert),
            await vic.heldContactListVersion(mal.myRid) + 1));
    await refused(vic, mal.myRid);
    expect(alertOn(vic, mal.myRid), (k: 'dl_shared', with_: bob.myRid));
    expect(
        devlistAlertText(
            AppLocalizationsEn(), vic.contactDevlistAlerts[mal.myRid]!, 'mal5',
            nameOf: (r) => vic.contacts[r]?.name),
        contains('cannot tell which of them is right'));
    expect(await heldRow(vic, mal.myRid), malRow);
    expect(vic.debugListedDeviceOwner(laptopRid), bob.myRid);

    // First come, for a device with no proof: Bob's tablet, which runs no
    // client and so never makes one, claimed by Mal before Bob lists it.
    await vic.acknowledgeContactDevlistAlert(mal.myRid);
    final tablet = await ZIdentity.generate();
    final tabletCert = await (await bob.accountIdentity()).signDeviceCert(
        deviceEdPub: tablet.edPub, deviceXPub: tablet.xPub, deviceId: 'tablet');
    final tabletRid = await tabletCert.routingId();
    await sendList(mal, vic,
        await claim(mal, keysOfCert(tabletCert),
            await vic.heldContactListVersion(mal.myRid) + 1));
    await waitUntil(() => vic.debugListedDeviceOwner(tabletRid) == mal.myRid,
        what: "Mal's claim on the tablet installed first");
    await bob.addMyDevice(tabletCert);
    await refused(vic, bob.myRid);
    expect(alertOn(vic, bob.myRid), (k: 'dl_shared', with_: mal.myRid));
    // Handed over again — Vic's echo is behind, so Bob's root re-sends it —
    // and refused again: there is nothing to overrule the claim with.
    await vic.acknowledgeContactDevlistAlert(bob.myRid);
    await vic.sendText(bob.myRid, 'echoing an older list');
    await refused(vic, bob.myRid);
    expect(vic.debugListedDeviceOwner(tabletRid), mal.myRid);
    expect(await vic.heldContactListVersion(bob.myRid), 2,
        reason: "Bob's list with the tablet is not installed");
  });

  /// Bob's laptop, its client running, proven for Bob at [vic]: linked,
  /// its proof handed to Bob's root, and a tablet linked after so that
  /// Bob's next list carries the proof to Vic.
  Future<({({ChatService svc, DeviceCertificate cert}) laptop, String rid})>
      provenLaptop(ChatService vic, ChatService bob, String name) async {
    final laptop = await linkedTo(bob, name);
    final rid = await laptop.cert.routingId();
    await bob.addMyDevice(laptop.cert);
    await waitUntil(() => rootHoldsProof(bob, rid),
        what: "Bob's root holds the laptop's proof");
    final tablet = await ZIdentity.generate();
    await bob.addMyDevice(await (await bob.accountIdentity()).signDeviceCert(
        deviceEdPub: tablet.edPub, deviceXPub: tablet.xPub, deviceId: 'tablet'));
    await waitUntil(() => vic.debugProvenDevice(rid)?.inList == true,
        what: "Vic holds the laptop proven for Bob");
    return (laptop: laptop, rid: rid);
  }

  test(
      '6. a device proven for one account is refused in any other, held or '
      'dropped, and the chat says whose it is; and in its code', () async {
    final vic = await start('vic6');
    final bob = await start('bob6');
    final mal = await start('mal6');
    await introduce(vic, bob);
    await introduce(vic, mal);
    final p = await provenLaptop(vic, bob, 'bob6laptop');

    final malRow = await heldRow(vic, mal.myRid);
    await sendList(mal, vic,
        await claim(mal, keysOfCert(p.laptop.cert),
            await vic.heldContactListVersion(mal.myRid) + 1));
    await refused(vic, mal.myRid);
    expect(alertOn(vic, mal.myRid), (k: 'dl_claimed', with_: bob.myRid));
    final stored = vic.contactDevlistAlerts[mal.myRid]!;
    String? nameOf(String r) => vic.contacts[r]?.name;
    final en = devlistAlertText(AppLocalizationsEn(), stored, 'mal6',
        nameOf: nameOf);
    final es = devlistAlertText(AppLocalizationsEs(), stored, 'mal6',
        nameOf: nameOf);
    for (final text in [en, es]) {
      expect(text, allOf(contains('mal6'), contains('bob6')));
    }
    expect(en, contains('has proved it belongs to'));
    expect(en, isNot(contains('cannot tell')),
        reason: 'this time it can tell');
    expect(es, isNot(en), reason: 'translated, not copied');
    expect(await heldRow(vic, mal.myRid), malRow);

    // Bob drops the laptop. Nobody holds it here now, and it is still
    // Bob's: a device once proven is never accepted for another account.
    await bob.removeMyDevice(p.laptop.cert);
    await waitUntil(() => vic.debugListedDeviceOwner(p.rid) == null,
        what: "Vic installs Bob's list without the laptop");
    await vic.acknowledgeContactDevlistAlert(mal.myRid);
    await sendList(mal, vic,
        await claim(mal, keysOfCert(p.laptop.cert),
            await vic.heldContactListVersion(mal.myRid) + 1));
    await refused(vic, mal.myRid);
    expect(alertOn(vic, mal.myRid), (k: 'dl_claimed', with_: bob.myRid));
    expect(vic.debugListedDeviceOwner(p.rid), isNull);
    expect(await heldRow(vic, mal.myRid), malRow);

    // Nor from a code. Mal's account certifies the laptop's keys, beside the
    // binding signature every code of the laptop's carries and Mal's own
    // post-quantum commitment: a code that decodes and verifies as Mal's,
    // which Vic's scan refuses.
    final malAccount = await mal.accountIdentity();
    final forged = ContactBundleV3(
      edPub: p.laptop.cert.deviceEdPub,
      xPub: p.laptop.cert.deviceXPub,
      bindingSig: (await p.laptop.svc.identity.bundle()).bindingSig,
      pqCommit: await HybridPublicKey(
              edPub: malAccount.accountEdPub,
              mlPub: (await mal.pqAccountPublic())!)
          .pqCommitment(),
      displayName: 'mal6',
      declaredAccountEdPub: malAccount.accountEdPub,
      deviceCert: await malAccount.signDeviceCert(
          deviceEdPub: p.laptop.cert.deviceEdPub,
          deviceXPub: p.laptop.cert.deviceXPub,
          deviceId: 'extra'),
    ).encode();
    expect(b64((await scanContactCode(forged)).accountEdPub),
        b64(malAccount.accountEdPub),
        reason: "a well-formed code, anchored to Mal's account");
    await expectLater(
        vic.addContactFromCode(forged), throwsA(isA<FormatException>()));
    expect(vic.contacts.containsKey(p.rid), isFalse);
  });

  test(
      "7. once a contact's list carried a device's proof, their list without "
      'it is refused, in-band and from the log, and an honest one installs',
      () async {
    final vic = await start('vic7');
    final bob = await start('bob7');
    await introduce(vic, bob);
    final p = await provenLaptop(vic, bob, 'bob7laptop');
    final bobAccount = await bob.accountIdentity();
    final held = await bob.myFullDeviceList();
    final v = await vic.heldContactListVersion(bob.myRid);
    final row = await heldRow(vic, bob.myRid);
    expect(held.any((d) => d.pop != null), isTrue);

    final stripped = await bobAccount.signDeviceList(
        [for (final d in held) d.withPop(null)], v + 1);
    final otherX = (await ZIdentity.generate()).xPub;
    final swappedCert = (await bobAccount.signDeviceCert(
            deviceEdPub: p.laptop.cert.deviceEdPub,
            deviceXPub: otherX,
            deviceId: p.laptop.cert.deviceId))
        .withPop(held.firstWhere((d) => d.pop != null).pop);
    final swapped = await bobAccount.signDeviceList([
      for (final d in held)
        if (b64(d.deviceEdPub) == b64(p.laptop.cert.deviceEdPub))
          swappedCert
        else
          d
    ], v + 1);
    expect(await stripped.verify(), isTrue,
        reason: "well signed: Bob's account signed it");
    expect(await swapped.verify(), isFalse,
        reason: 'the old proof does not cover the new ratchet key');
    final swappedBare = await bobAccount.signDeviceList([
      for (final d in held)
        if (b64(d.deviceEdPub) == b64(p.laptop.cert.deviceEdPub))
          swappedCert.withPop(null)
        else
          d
    ], v + 1);

    final judged = vic.debugJudged = [];
    for (final (what, list) in [
      ('the proof taken off', stripped),
      ('a ratchet key swapped under the old proof', swapped),
      ('a ratchet key swapped, the proof taken off', swappedBare),
    ]) {
      // What this list's arrival is judged: Bob's root may hand Vic its own
      // current list meanwhile, and that is judged too.
      final from = judged.length;
      Iterable<({String rid, int version, bool installed})> mine() => judged
          .skip(from)
          .where((j) => j.rid == bob.myRid && j.version == v + 1);
      await sendList(bob, vic, list);
      await waitUntil(() => mine().isNotEmpty, what: '$what: judged in-band');
      expect(mine().every((j) => !j.installed), isTrue,
          reason: '$what: refused in-band');
      expect(await vic.ktInstallFromLog(bob.myRid, list), isFalse,
          reason: '$what: refused from the log');
      expect(await heldRow(vic, bob.myRid), row, reason: what);
      expect(await vic.heldContactListVersion(bob.myRid), v, reason: what);
      expect(vic.contactDevlistAlerts[bob.myRid], isNull,
          reason: '$what: refused in silence, as the floor refuses');
    }
    expect(vic.debugListedDeviceOwner(p.rid), bob.myRid);

    // Bob's own next list, carrying the proof as his root does, installs.
    final next = await ZIdentity.generate();
    await bob.addMyDevice(await bobAccount.signDeviceCert(
        deviceEdPub: next.edPub, deviceXPub: next.xPub, deviceId: 'phone2'));
    await waitUntil(() async => await vic.heldContactListVersion(bob.myRid) > v,
        what: "Vic installs Bob's honest next list");
    expect(vic.debugListedDeviceOwner(p.rid), bob.myRid);
  });

  test(
      '8. what was proven survives a restart, and goes with the last contact '
      'record of its account', () async {
    var vic = await start('vic8');
    final bob = await start('bob8');
    final mal = await start('mal8');
    await introduce(vic, bob);
    await introduce(vic, mal);
    final p = await provenLaptop(vic, bob, 'bob8laptop');
    // What a build without the rule would have installed for Mal.
    final list = await claim(mal, keysOfCert(p.laptop.cert),
        await vic.heldContactListVersion(mal.myRid) + 1);
    await vic.vault.kvPut('cdev_${mal.myRid}', jsonEncode(list.toJson()),
        sensitive: false);
    await vic.vault.kvPut('cdev_ver_${mal.myRid}', '${list.version}',
        sensitive: false);

    await stop(vic);
    vic = await start('vic8');
    expect(vic.debugProvenDevice(p.rid)?.acct,
        b64((await bob.accountIdentity()).accountEdPub));
    expect(vic.debugListedDeviceOwner(p.rid), bob.myRid,
        reason: "the held list does not take Bob's laptop at start-up");
    await waitUntil(() => linked(p.laptop.svc), what: 'the laptop connected');
    await p.laptop.svc.addContactFromCode(await vic.myContactCode());
    await heard(p.laptop.svc, vic, bob.myRid, 'after the restart');
    expect(received(vic, mal.myRid, 'after the restart'), isFalse);

    // In-band too, after the restart.
    await sendList(mal, vic,
        await claim(mal, keysOfCert(p.laptop.cert), list.version + 1));
    await refused(vic, mal.myRid);
    expect(alertOn(vic, mal.myRid), (k: 'dl_claimed', with_: bob.myRid));

    // Bob deleted: his devices are forgotten, and the alert stays, without
    // him.
    await vic.deleteContact(bob.myRid);
    expect(vic.debugProvenDevice(p.rid), isNull);
    expect(vic.debugProvenDevice(bob.myRid), isNull);
    expect(alertOn(vic, mal.myRid), (k: 'dl_claimed', with_: null));
    expect(
        devlistAlertText(AppLocalizationsEn(),
            vic.contactDevlistAlerts[mal.myRid]!, 'mal8'),
        allOf(contains('mal8'), contains('another account')));
  });

  test(
      "9. a list naming someone's linked device before they are a contact "
      "gives it up when they are added from that device's code", () async {
    final vic = await start('vic9');
    final bob = await start('bob9');
    final mal = await start('mal9');
    await introduce(vic, mal);
    // Bob's laptop, listed by Bob — whose list Vic, not yet his contact,
    // does not have. Mal lists its keys, and his list reaches Vic first.
    final laptop = await linkedTo(bob, 'bob9laptop');
    final laptopRid = await laptop.cert.routingId();
    await bob.addMyDevice(laptop.cert);
    await sendList(mal, vic,
        await claim(mal, keysOfCert(laptop.cert),
            await vic.heldContactListVersion(mal.myRid) + 1));
    await waitUntil(() => vic.debugListedDeviceOwner(laptopRid) == mal.myRid,
        what: "Mal's claim installed: the laptop is nobody's here yet");

    // Vic adds Bob from the laptop's own code: anchored to Bob's account, and
    // signed over it by the laptop's key (`pqcs`).
    await waitUntil(() => linked(laptop.svc), what: 'the laptop connected');
    await vic.addContactFromCode(await laptop.svc.myContactCode());
    expect(vic.contacts[laptopRid]!.pqcSigned, isTrue,
        reason: 'the code the laptop hands out signs its account');
    // The routing changes first and the alert is written last.
    await upTo(
        () =>
            vic.debugListedDeviceOwner(laptopRid) == null &&
            alertOn(vic, mal.myRid).k == 'dl_claimed',
        what: "Mal's claim on the laptop withdrawn, and said");
    expect(vic.debugListedDeviceOwner(laptopRid), isNull,
        reason: 'the device Vic added Bob from is not Mal\'s');
    expect(alertOn(vic, mal.myRid), (k: 'dl_claimed', with_: laptopRid));
    await laptop.svc.addContactFromCode(await vic.myContactCode());
    await heard(laptop.svc, vic, laptopRid, "Bob's laptop, as Bob");
    expect(received(vic, mal.myRid, "Bob's laptop, as Bob"), isFalse);
    await heard(mal, vic, mal.myRid, 'Mal is still a contact');
  });
}
