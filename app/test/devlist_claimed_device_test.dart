// A contact cannot claim someone else's device (PROTOCOL §3.4).
//
// A device certificate proves that an account SIGNED it, not that whoever
// holds the account holds the device key it names. So any contact can put
// another person's public keys — from their contact code, or a group's member
// list — in their own account-signed device list. Installed, that list
// mapped the other person's routing id to the claimant: inbound routing asks
// which contact a device was listed for before it asks which contact the
// device IS, so the other person's messages were decrypted against the wrong
// account — dropped, or filed under the claimant's name. A list naming a
// device already held for another account is now refused, whole.
//
// Real clients through the real relay. The claimant is a peer running
// modified code, which is the only kind that can make such a list; it sends
// it with `debugSendRawInner`.
//
// Criteria, each a test below:
//   1. a contact's list naming another contact's device — the one that
//      contact was added from — is refused whole: nothing installed, the
//      held list and its version as they were, the device still that
//      contact's here; the log's install path refuses it too; and that
//      contact's messages still arrive, from them;
//   2. a contact's list naming another contact's LINKED device, already held
//      from that contact's own list, is refused the same way, and the linked
//      device's messages still arrive as that contact's;
//   3. a contact's list naming one of MY devices — this one, or one linked
//      to it — is refused;
//   4. the refusal is said, and accuses nobody: one alert, on the chat of the
//      contact whose list was refused, naming both — in English and in
//      Spanish — and nothing on the other contact; the gossip's view of the
//      same refusal does not replace it; and deleting the other contact
//      leaves the alert without them, their routing id gone from the vault;
//   5. an honest list still installs: the claimant's next list, naming only
//      its own devices, installs and clears the alert, and the other
//      contact's own new list installs as ever;
//   6. one account added from two of its devices is not a collision: a list
//      naming the device another contact record was added from installs
//      when that record is the same account;
//   7. first come, which this does not close: a claim that arrives before
//      the real owner's list is installed at that receiver, and the owner's
//      list, arriving second, is the one refused — with the same alert, now
//      on the owner, naming the claimant;
//   8. a colliding list an earlier build already installed is held to the
//      same rule at start-up: it is not installed, and the other contact's
//      messages arrive as theirs;
//   9. two lists from two accounts naming one device, installed together,
//      leave exactly one of them holding it: the check and the write that
//      follows it are not interleaved with another account's install.
@Tags(['integration'])
@Timeout(Duration(minutes: 4))
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
  /// [stop].
  Future<ChatService> start(String name) async {
    final dir =
        dirs[name] ??= await Directory.systemTemp.createTemp('z_claim_$name');
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
  /// (`addMyDevice`).
  Future<({ChatService svc, DeviceCertificate cert})> linkedTo(
      ChatService host, String name) async {
    final account = await host.accountIdentity();
    final ml = await host.pqAccountPublic();
    final devId = await ZIdentity.generate();
    final cert = await account.signDeviceCert(
        deviceEdPub: devId.edPub, deviceXPub: devId.xPub, deviceId: name);
    final dir = dirs[name] = await Directory.systemTemp.createTemp('z_claim_$name');
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

  ({Uint8List edPub, Uint8List xPub}) keysOf(ZIdentity id) =>
      (edPub: id.edPub, xPub: id.xPub);

  ({Uint8List edPub, Uint8List xPub}) keysOfCert(DeviceCertificate c) =>
      (edPub: c.deviceEdPub, xPub: c.deviceXPub);

  /// Waits for [svc] to refuse a list from [rid] for naming a device held
  /// elsewhere: the alert that refusal raises.
  Future<void> refused(ChatService svc, String rid) => waitUntil(
      () => isSharedDeviceAlert(svc.contactDevlistAlerts[rid]),
      what: '${svc.displayName} refuses the list from $rid');

  test(
      "1. a list naming the device another contact was added from is refused "
      "whole, and that contact's messages still arrive from them", () async {
    final vic = await start('vic1');
    final bob = await start('bob1');
    final mal = await start('mal1');
    await introduce(vic, bob);
    await introduce(vic, mal);
    final rowBefore = await heldRow(vic, mal.myRid);
    final versionBefore = await vic.heldContactListVersion(mal.myRid);

    final list = await claim(mal, keysOf(bob.identity), versionBefore + 1);
    expect(await list.verify(), isTrue,
        reason: "genuinely signed by Mal's account");
    await sendList(mal, vic, list);
    await refused(vic, mal.myRid);

    expect(await heldRow(vic, mal.myRid), rowBefore,
        reason: 'nothing installed for Mal');
    expect(await vic.heldContactListVersion(mal.myRid), versionBefore);
    expect(vic.debugListedDeviceOwner(bob.myRid), isNull,
        reason: "Bob's device is not Mal's here");
    // The log's install path is the same rule.
    expect(await vic.ktInstallFromLog(mal.myRid, list), isFalse,
        reason: 'refused from the log too');
    expect(await heldRow(vic, mal.myRid), rowBefore);
    expect(vic.debugListedDeviceOwner(bob.myRid), isNull);

    // Bob is still Bob, both ways.
    await heard(bob, vic, bob.myRid, 'after the claim');
    await heard(vic, bob, vic.myRid, 'and back');
    expect(received(vic, mal.myRid, 'after the claim'), isFalse);
  });

  test(
      "2. a list naming another contact's linked device, already held, is "
      "refused, and that device's messages still arrive as theirs", () async {
    final vic = await start('vic2');
    final bob = await start('bob2');
    final mal = await start('mal2');
    await introduce(vic, bob);
    await introduce(vic, mal);
    final laptop = await linkedTo(bob, 'bob2laptop');
    await bob.addMyDevice(laptop.cert);
    final laptopRid = await laptop.cert.routingId();
    // The routing table is the install's last write, so it is what says the
    // install is done.
    await waitUntil(() => vic.debugListedDeviceOwner(laptopRid) == bob.myRid,
        what: "Vic holds Bob's list with the laptop");

    final rowBefore = await heldRow(vic, mal.myRid);
    final list = await claim(mal, keysOfCert(laptop.cert),
        await vic.heldContactListVersion(mal.myRid) + 1);
    await sendList(mal, vic, list);
    await refused(vic, mal.myRid);
    expect(await heldRow(vic, mal.myRid), rowBefore);
    expect(vic.debugListedDeviceOwner(laptopRid), bob.myRid,
        reason: "the laptop is still Bob's here");

    await waitUntil(() => linked(laptop.svc), what: 'the laptop connected');
    await laptop.svc.addContactFromCode(await vic.myContactCode());
    await heard(laptop.svc, vic, bob.myRid, "from Bob's laptop");
    expect(received(vic, mal.myRid, "from Bob's laptop"), isFalse,
        reason: 'never filed under Mal');
  });

  test('3. a list naming one of my own devices is refused', () async {
    final vic = await start('vic3');
    final mal = await start('mal3');
    await introduce(vic, mal);
    // A device linked to Vic's account; listing it is all this needs.
    final tabletId = await ZIdentity.generate();
    final tabletCert = await (await vic.accountIdentity()).signDeviceCert(
        deviceEdPub: tabletId.edPub,
        deviceXPub: tabletId.xPub,
        deviceId: 'tablet');
    await vic.addMyDevice(tabletCert);
    final rowBefore = await heldRow(vic, mal.myRid);
    final v = await vic.heldContactListVersion(mal.myRid);

    for (final (what, keys) in [
      ('this device', keysOf(vic.identity)),
      ('a device linked to it', keysOfCert(tabletCert)),
    ]) {
      await vic.acknowledgeContactDevlistAlert(mal.myRid);
      await sendList(mal, vic, await claim(mal, keys, v + 1));
      await refused(vic, mal.myRid);
      expect(
          jsonDecode(vic.contactDevlistAlerts[mal.myRid]!)['k'],
          DevlistAlertKind.sharedWithMe,
          reason: '$what is mine');
      expect(await heldRow(vic, mal.myRid), rowBefore, reason: what);
      expect(vic.debugListedDeviceOwner(await tabletCert.routingId()), isNull);
      expect(vic.debugListedDeviceOwner(vic.myRid), isNull);
    }
  });

  test(
      '4. the refusal is said, naming both and accusing neither, and outlives '
      'neither the gossip nor a deleted contact', () async {
    final vic = await start('vic4');
    final bob = await start('bob4');
    final mal = await start('mal4');
    await introduce(vic, bob);
    await introduce(vic, mal);
    await sendList(mal, vic,
        await claim(mal, keysOf(bob.identity),
            await vic.heldContactListVersion(mal.myRid) + 1));
    await refused(vic, mal.myRid);

    final stored = vic.contactDevlistAlerts[mal.myRid]!;
    expect(sharedDeviceAlertOther(stored), bob.myRid);
    String? nameOf(String r) => vic.contacts[r]?.name;
    final en = devlistAlertText(AppLocalizationsEn(), stored, 'mal4',
        nameOf: nameOf);
    final es = devlistAlertText(AppLocalizationsEs(), stored, 'mal4',
        nameOf: nameOf);
    for (final text in [en, es]) {
      expect(text, contains('mal4'));
      expect(text, contains('bob4'));
    }
    expect(en, contains('cannot tell which of them is right'),
        reason: 'the words say it does not know who is wrong');
    expect(es, isNot(en), reason: 'translated, not copied');
    expect(vic.contactDevlistAlerts[bob.myRid], isNull,
        reason: 'nothing is said against Bob');

    // The gossip's two views of the same refusal leave it standing. Mal's
    // devices claim the list Vic still holds — which on its own clears a
    // banner, "they agree"…
    await vic.debugEvaluateContact(mal.myRid);
    expect(vic.contactDevlistAlerts[mal.myRid], stored);
    // …and once Mal's client really is at the refused list, they claim a
    // version Vic never installed — on its own "the update never arrived",
    // at once with no grace.
    vic.devlistGrace = Duration.zero;
    final crafted = await (await mal.accountIdentity()).signDeviceCert(
        deviceEdPub: bob.identity.edPub,
        deviceXPub: bob.identity.xPub,
        deviceId: 'extra');
    await mal.addMyDevice(crafted); // Mal's own list now names Bob's keys
    await mal.sendText(vic.myRid, 'claiming the newer list');
    await waitUntil(
        () async => ((jsonDecode(
                        await vic.vault.kvGet('cdl_claims_${mal.myRid}') ??
                            '{}') as Map)
                    .values
                    .any((c) => (c as Map)['v'] == 2)),
        what: "Vic has seen Mal's devices claim version 2");
    await vic.debugEvaluateContact(mal.myRid);
    expect(isSharedDeviceAlert(vic.contactDevlistAlerts[mal.myRid]), isTrue,
        reason: 'the banner that names both is not replaced');
    expect(await vic.heldContactListVersion(mal.myRid), 1,
        reason: "and Mal's own broadcast of it was refused too");

    // Bob deleted: the alert stays, without him.
    await vic.deleteContact(bob.myRid);
    final after = vic.contactDevlistAlerts[mal.myRid]!;
    expect(isSharedDeviceAlert(after), isTrue);
    expect(sharedDeviceAlertOther(after), isNull);
    expect(await vic.vault.kvGet('cdl_alert_${mal.myRid}'), after);
    expect(
        devlistAlertText(AppLocalizationsEn(), after, 'mal4', nameOf: nameOf),
        allOf(contains('mal4'), contains('another account')));
    final rows = await vic.vault.db.query('kv');
    expect(rows.where((r) => '${r['k']}${r['v']}'.contains(bob.myRid)),
        isEmpty,
        reason: "Bob's routing id is gone from the vault");
  });

  test(
      '5. an honest list still installs, and clears the alert; the other '
      "contact's own new list installs as ever", () async {
    final vic = await start('vic5');
    final bob = await start('bob5');
    final mal = await start('mal5');
    await introduce(vic, bob);
    await introduce(vic, mal);
    await sendList(mal, vic,
        await claim(mal, keysOf(bob.identity),
            await vic.heldContactListVersion(mal.myRid) + 1));
    await refused(vic, mal.myRid);

    // Mal's own next list: a device of his own, honestly linked.
    final malTablet = await ZIdentity.generate();
    await mal.addMyDevice(await (await mal.accountIdentity()).signDeviceCert(
        deviceEdPub: malTablet.edPub,
        deviceXPub: malTablet.xPub,
        deviceId: 'tablet'));
    final malTabletRid = b64url(await sha256Bytes(malTablet.edPub));
    await waitUntil(() => vic.debugListedDeviceOwner(malTabletRid) == mal.myRid,
        what: "Vic installs Mal's honest list");
    expect(await vic.heldContactListVersion(mal.myRid), 2);
    expect(vic.contactDevlistAlerts[mal.myRid], isNull,
        reason: 'the refused list is superseded');

    // Bob's, likewise.
    final bobTablet = await ZIdentity.generate();
    await bob.addMyDevice(await (await bob.accountIdentity()).signDeviceCert(
        deviceEdPub: bobTablet.edPub,
        deviceXPub: bobTablet.xPub,
        deviceId: 'tablet'));
    final bobTabletRid = b64url(await sha256Bytes(bobTablet.edPub));
    await waitUntil(() => vic.debugListedDeviceOwner(bobTabletRid) == bob.myRid,
        what: "Vic installs Bob's new list");
    expect(vic.contactDevlistAlerts[bob.myRid], isNull);
  });

  test(
      '6. one account added from two of its devices is not a collision',
      () async {
    final vic = await start('vic6');
    final alice = await start('alice6');
    final laptop = await linkedTo(alice, 'alice6laptop');
    await waitUntil(() => linked(vic) && linked(alice) && linked(laptop.svc),
        what: 'all connected');
    // Vic adds Alice twice: from her phone's code and from her laptop's,
    // which names the same account (§18.7).
    await vic.addContactFromCode(await alice.myContactCode());
    await vic.addContactFromCode(await laptop.svc.myContactCode());
    final laptopRid = laptop.svc.myRid;
    expect(vic.contacts[laptopRid]!.accountEd,
        vic.contacts[alice.myRid]!.accountEd,
        reason: 'two records, one account');
    await alice.addContactFromCode(await vic.myContactCode());
    await heard(alice, vic, alice.myRid, 'hello vic6');

    // Alice lists the laptop: her list for the record made from her phone
    // names the device the other record was made from.
    await alice.addMyDevice(laptop.cert);
    await waitUntil(() => vic.debugListedDeviceOwner(laptopRid) == alice.myRid,
        what: "Vic installs Alice's list");
    expect(await vic.heldContactListVersion(alice.myRid), 2);
    expect(isSharedDeviceAlert(vic.contactDevlistAlerts[alice.myRid]), isFalse);
    expect(isSharedDeviceAlert(vic.contactDevlistAlerts[laptopRid]), isFalse);
  });

  test(
      "7. first come: a claim that arrives before the owner's list wins here, "
      "and the owner's list is refused with the alert on the owner", () async {
    final vic = await start('vic7');
    final bob = await start('bob7');
    final mal = await start('mal7');
    await introduce(vic, bob);
    await introduce(vic, mal);
    // Bob's laptop, before Bob has listed it — but its public keys already
    // known to Mal, who lists them first.
    final laptopId = await ZIdentity.generate();
    final laptopCert = await (await bob.accountIdentity()).signDeviceCert(
        deviceEdPub: laptopId.edPub,
        deviceXPub: laptopId.xPub,
        deviceId: 'laptop');
    final laptopRid = await laptopCert.routingId();
    await sendList(mal, vic,
        await claim(mal, keysOfCert(laptopCert),
            await vic.heldContactListVersion(mal.myRid) + 1));
    await waitUntil(() => vic.debugListedDeviceOwner(laptopRid) == mal.myRid,
        what: "Mal's claim installed: nothing held contradicted it");

    // Bob lists his laptop. His list is the one refused here.
    await bob.addMyDevice(laptopCert);
    await refused(vic, bob.myRid);
    expect(await vic.heldContactListVersion(bob.myRid), 1);
    expect(vic.debugListedDeviceOwner(laptopRid), mal.myRid);
    final stored = vic.contactDevlistAlerts[bob.myRid]!;
    expect(sharedDeviceAlertOther(stored), mal.myRid,
        reason: 'the alert names the other claimant');
    expect(
        devlistAlertText(AppLocalizationsEn(), stored, 'bob7',
            nameOf: (r) => vic.contacts[r]?.name),
        allOf(contains('bob7'), contains('mal7')));
    expect(isSharedDeviceAlert(vic.contactDevlistAlerts[mal.myRid]), isFalse,
        reason: 'nothing on Mal either: the receiver cannot tell who lied');
  });

  test(
      '8. a colliding list an earlier build installed is held to the same '
      'rule at start-up', () async {
    var vic = await start('vic8');
    final bob = await start('bob8');
    final mal = await start('mal8');
    await introduce(vic, bob);
    await introduce(vic, mal);
    // What a build without the rule would have installed for Mal.
    final list = await claim(mal, keysOf(bob.identity),
        await vic.heldContactListVersion(mal.myRid) + 1);
    await vic.vault.kvPut('cdev_${mal.myRid}', jsonEncode(list.toJson()),
        sensitive: false);
    await vic.vault.kvPut('cdev_ver_${mal.myRid}', '${list.version}',
        sensitive: false);

    await stop(vic);
    vic = await start('vic8');
    expect(vic.debugListedDeviceOwner(bob.myRid), isNull,
        reason: "the held list does not take Bob's device at start-up");
    await heard(bob, vic, bob.myRid, 'after the restart');
    expect(received(vic, mal.myRid, 'after the restart'), isFalse);
  });

  test(
      '9. two lists naming one device, installed together, leave one holder',
      () async {
    final vic = await start('vic9');
    final bob = await start('bob9');
    final mal = await start('mal9');
    await introduce(vic, bob);
    await introduce(vic, mal);
    final device = await ZIdentity.generate();
    final deviceRid = await device.routingId();
    final bobAcct = await bob.accountIdentity();
    final bobList = await bobAcct.signDeviceList([
      ...await bob.myFullDeviceList(),
      await bobAcct.signDeviceCert(
          deviceEdPub: device.edPub, deviceXPub: device.xPub, deviceId: 'd'),
    ], await vic.heldContactListVersion(bob.myRid) + 1);
    final malList = await claim(
        mal, keysOf(device), await vic.heldContactListVersion(mal.myRid) + 1);

    // Started together, as the log check and an in-band delivery can be.
    final results = await Future.wait([
      vic.ktInstallFromLog(bob.myRid, bobList),
      vic.ktInstallFromLog(mal.myRid, malList),
    ]);
    expect(results.where((r) => r), hasLength(1),
        reason: 'exactly one of the two is installed');
    final (holder, other) =
        results[0] ? (bob.myRid, mal.myRid) : (mal.myRid, bob.myRid);
    expect(vic.debugListedDeviceOwner(deviceRid), holder);
    expect(sharedDeviceAlertOther(vic.contactDevlistAlerts[other]), holder,
        reason: 'and the other is refused, naming the holder');
    expect(vic.contactDevlistAlerts[holder], isNull);
  });
}
