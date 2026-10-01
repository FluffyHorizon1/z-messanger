// Integration test for 7.7a device-list transparency (gossip).
//
// The scenario the ADR (docs/adr/0001-key-transparency.md) sets as the
// definition of done: an account with two honest devices (a phone that holds
// the root, and a linked laptop) has its root seed used by a THIRD, rogue
// device to publish a new device list. In case (a) the rogue publishes to the
// contact only (a split view: the owner's own devices are kept in the dark);
// in case (b) it publishes a list with the honest laptop removed. In BOTH
// cases an honest device and the contact must surface the corresponding alert.
// The control: an honest device added at the same version and distributed to
// everyone must raise nothing.
//
// The rogue holds the stolen backup, so it speaks as device #1 (the phone's
// keys) AND can sign a new device list — exactly the T1/T2/T3 attacker.
@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/system_messages.dart';
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

  // A relay per TEST, not one per file. `syncSettled` below asks the relay
  // whether it still holds anything nobody has acknowledged, and a relay
  // shared with an earlier test goes on holding that test's mail for
  // mailboxes nobody reads any more — the rogue's own device, the tablet
  // that only ever existed in a signed list — so on a shared relay that
  // question has no useful answer after the first test.
  setUp(() async {
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

  tearDown(() async {
    for (final s in services) {
      await s.transport.stop();
    }
    services.clear();
    relay.kill();
  });

  tearDownAll(() async {
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  // Short grace so the deferred (owner-echo / unconfirmed-list) checks resolve
  // quickly instead of the 8 s production default.
  const grace = Duration(milliseconds: 700);

  Future<Vault> freshVault(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_$name');
    temps.add(dir);
    return Vault.open(rootOverride: dir);
  }

  ChatService register(ChatService s) {
    s.devlistGrace = grace;
    services.add(s);
    return s;
  }

  Future<ChatService> makePrimary(String name, ZIdentity id) async {
    final vault = await freshVault(name);
    await vault.kvPut('identity', jsonEncode(id.toJson()));
    final transport =
        Transport(identity: id, serverUrl: 'ws://127.0.0.1:$port');
    return register(await ChatService.init(
        vault: vault, identity: id, displayName: name, transport: transport));
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
    return register(await ChatService.init(
        vault: vault,
        identity: devId,
        displayName: name,
        transport: transport));
  }

  // A rogue built from the stolen backup: it speaks as device #1 (the phone's
  // identity) and holds the account root, and is pre-seeded with the device
  // set + version it will publish.
  Future<ChatService> makeRogue(ZIdentity phoneId, AccountIdentity account,
      List<DeviceCertificate> myDevices, int version) async {
    final vault = await freshVault('rogue');
    await vault.kvPut('identity', jsonEncode(phoneId.toJson()));
    await vault.kvPut('account', jsonEncode(account.toJson()));
    await vault.kvPut(
        'my_devices', jsonEncode([for (final d in myDevices) d.toJson()]),
        sensitive: false);
    await vault.kvPut('my_devlist_version', '$version', sensitive: false);
    final transport =
        Transport(identity: phoneId, serverUrl: 'ws://127.0.0.1:$port');
    return register(await ChatService.init(
        vault: vault,
        identity: phoneId,
        displayName: 'phone',
        transport: transport));
  }

  // 60 seconds, not 25. A wait returns the moment its condition holds, so a
  // larger budget costs a healthy run nothing; what it buys is a loaded CI
  // runner the room to finish a delivery it would otherwise be cut off in.
  // Three attempts of this file's tests were lost to a 25-second budget on a
  // tag whose code was unchanged, and the same tag passed on a re-run.
  //
  // Every wait names what it waits for. A bare 'condition not met' from a
  // file with a dozen waits says nothing about which delivery was cut off,
  // and that is how this file went two triage passes without anyone knowing
  // what was actually timing out.
  Future<void> waitUntil(bool Function() cond,
      {Duration timeout = const Duration(seconds: 60),
      required String what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException(
            'timed out after ${timeout.inSeconds}s waiting for: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 30));
    }
  }

  List<String> texts(ChatService svc, String rid) => [
        for (final m in svc.messagesByChat[rid] ?? const [])
          if (m.kind == 'text') m.body
      ];

  /// Both links, not just one.
  ///
  /// `transport.isConnected` is the IDENTIFIED link; a sealed envelope only
  /// ever goes out on the ANONYMOUS one, and `onConnected` — which is what
  /// flushes the outbox and what re-asserts a root's device list to its own
  /// devices — fires only when both are up. Waiting on `isConnected` alone
  /// and then depending on either of those is waiting for the wrong thing,
  /// and on a loaded box the two links can come up far enough apart to
  /// matter. That is a large part of what the `retry:` on these tests was
  /// paying for.
  bool linked(ChatService s) =>
      s.transport.isConnected && s.transport.isSenderConnected;

  Future<bool> versionReaches(Future<int> Function() read, int want) async {
    // Was 15 s while the waits around it had 25 or 60, so the fixture
    // this helper guards timed out first and reported as a reasoned
    // `expect` rather than as the timeout it was.
    final deadline = DateTime.now().add(const Duration(seconds: 45));
    while (DateTime.now().isBefore(deadline)) {
      if (await read() >= want) return true;
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
    return false;
  }

  /// Envelopes the relay holds that their recipient has not acknowledged.
  /// The RAM store keeps an envelope until it is acknowledged, delivered or
  /// not, so this is zero only when everything sent so far has been taken
  /// off the relay by whoever it was for. (In Redis mode `/health` reports
  /// -1 and this never settles; these tests run the RAM store.)
  Future<int> relayUnacked() async {
    final res = await (await HttpClient()
            .getUrl(Uri.parse('http://127.0.0.1:$port/health')))
        .close();
    final body = await res.transform(utf8.decoder).join();
    return ((jsonDecode(body) as Map)['queuedEnvelopes'] as num).toInt();
  }

  /// Whether [device] has heard back on the sync session it sends on to
  /// [peer]: read from the session the app persists after every operation
  /// (`sync_session`, sealed; `kvGet` opens it).
  Future<bool> heardBackOnSync(ChatService device, ChatService peer) async {
    final raw = await device.vault.kvGet('sync_session');
    if (raw == null) return false;
    final convs = (jsonDecode(raw) as Map)['convs'] as Map;
    final conv = convs[peer.myRid] as Map?;
    final out = conv?['outboundSid'] as String?;
    if (conv == null || out == null) return false;
    return ((conv['sessions'] as Map)[out] as Map?)?['receivedAny'] == true;
  }

  /// The phone and the laptop have finished OPENING their sync channel, and
  /// nothing anyone sent is still waiting at the relay.
  ///
  /// This is what split view (a) was failing on, about one run in two. The
  /// device whose routing id sorts first opens the sync session, and until
  /// it has heard back on it, every envelope it sends there carries the
  /// session's ephemeral key (`ek`). The rogue holds the phone's identity
  /// key and takes over the phone's mailbox, so when the LAPTOP was the
  /// opener and the phone went offline inside that window, the first such
  /// envelope the rogue received — one the phone had not acknowledged yet,
  /// or the laptop's next mirror — let it re-derive the very same session
  /// (same id, same root key) and answer on it with a ratchet key of its
  /// own. The laptop followed the rogue's branch. When the honest phone came
  /// back it carried on along ITS branch of the same session, which the
  /// laptop could no longer decrypt ("authentication failed"), and the
  /// laptop's answers were undecryptable at the phone ("pq message without a
  /// shared secret"); the phone's re-asserted v2 never arrived, and the wait
  /// for the laptop's `olderList` alert timed out. When the phone was the
  /// opener, the rogue had to open a session of its own, the laptop kept
  /// the phone's beside it and went back to it when the phone spoke, and
  /// the test passed — hence one run in two. Measured by forcing the order:
  /// with the laptop as opener 4 runs in 8 failed, two of them on both
  /// attempts so that `retry: 1` would not have saved the build; with the
  /// phone as opener, none in 6.
  ///
  /// The scenario is two honest devices whose channel is long established,
  /// so the fixture now starts from that: each side has heard back on the
  /// session it sends on — nothing either sends carries `ek` any more — and
  /// the relay holds nothing unacknowledged, so no envelope from the
  /// opening is left to be redelivered to whoever next holds the phone's
  /// mailbox. Both are needed: the first stops new envelopes carrying the
  /// key, the second accounts for the ones already sent.
  Future<void> syncSettled(ChatService phone, ChatService laptop) async {
    const budget = Duration(seconds: 60);
    final deadline = DateTime.now().add(budget);
    while (true) {
      var done = await heardBackOnSync(laptop, phone) &&
          await heardBackOnSync(phone, laptop);
      if (done) {
        for (final s in [phone, laptop]) {
          if ((await s.vault.db.query('outbox', limit: 1)).isNotEmpty) {
            done = false;
            break;
          }
        }
      }
      if (done && await relayUnacked() == 0) return;
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('timed out after ${budget.inSeconds}s waiting '
            'for: the phone-laptop sync channel to finish opening, with '
            'nothing left unacknowledged at the relay');
      }
      await Future<void>.delayed(const Duration(milliseconds: 30));
    }
  }

  // Stand up the phone (root), a linked laptop, and the contact Carol, all at
  // device-list version 2 = {phone, laptop}, with the phone and laptop's sync
  // channel open in both directions (`syncSettled`). Returns the pieces the
  // scenarios build on.
  Future<
      ({
        ChatService phone,
        ChatService laptop,
        ChatService carol,
        ZIdentity phoneId,
        AccountIdentity account,
        DeviceCertificate laptopCert,
        String accountRid,
      })> bringUpAccount() async {
    final phoneId = await ZIdentity.generate();
    final phone = await makePrimary('phone', phoneId);
    final account = await phone.accountIdentity();

    final laptopId = await ZIdentity.generate();
    final laptopCert = await account.signDeviceCert(
        deviceEdPub: laptopId.edPub,
        deviceXPub: laptopId.xPub,
        deviceId: 'laptop');
    final laptop = await makeLinked(
        'laptop', laptopId, account, laptopCert, account.deviceCert);

    final carol = await makePrimary('carol', await ZIdentity.generate());

    await waitUntil(() => linked(phone) && linked(laptop) && linked(carol),
        what: 'phone, laptop and carol each up on both links');

    final accountRid = phone.myRid;
    await carol.addContactFromCode(await phone.myContactCode());
    await phone.addContactFromCode(await carol.myContactCode());
    await laptop.addContactFromCode(await carol.myContactCode());

    // Root publishes v2={phone,laptop} to Carol and self-syncs it to the laptop.
    await phone.addMyDevice(laptopCert);

    // Carol learns the laptop; the laptop learns its own account is at v2.
    expect(
        await versionReaches(() => carol.heldContactListVersion(accountRid), 2),
        isTrue,
        reason: 'Carol never received the v2 device list');
    expect(await versionReaches(() => laptop.ownDeviceListVersion(), 2), isTrue,
        reason: 'the laptop never learned it is at v2');
    // Version 2 can reach the laptop on a session the PHONE opened while the
    // laptop's own is still half-open, so it says nothing about the channel
    // the scenarios rely on; wait for that separately.
    await syncSettled(phone, laptop);
    return (
      phone: phone,
      laptop: laptop,
      carol: carol,
      phoneId: phoneId,
      account: account,
      laptopCert: laptopCert,
      accountRid: accountRid,
    );
  }

  test('split view (a): a rogue list shown only to the contact is caught',
      () async {
    final s = await bringUpAccount();
    final rogueDevId = await ZIdentity.generate();
    final rogueCert = await s.account.signDeviceCert(
        deviceEdPub: rogueDevId.edPub,
        deviceXPub: rogueDevId.xPub,
        deviceId: 'rogue');

    // The phone goes offline; the attacker takes over device #1's mailbox.
    await s.phone.transport.stop();
    // Rogue publishes v3={phone,laptop,rogue} — but ONLY to Carol (a split
    // view: rule 8 self-sync deliberately skipped).
    final rogue =
        await makeRogue(s.phoneId, s.account, [s.laptopCert, rogueCert], 3);
    await waitUntil(() => linked(rogue), what: 'the rogue up on both links');
    await rogue.addContactFromCode(await s.carol.myContactCode());
    await rogue.broadcastMyDeviceList(alsoOwnDevices: false);
    expect(
        await versionReaches(
            () => s.carol.heldContactListVersion(s.accountRid), 3),
        isTrue,
        reason: 'Carol never installed the rogue v3 list');

    // Carol echoes the (rogue) list she now holds back to the account's
    // devices. The laptop sees a version it never received and asks its root
    // for the truth — but the rogue is squatting on the root's mailbox and
    // answers with its own v3, so the laptop swallows it for now. (A rogue
    // holding device #1's keys could always have pushed that list; the split
    // view is caught the moment the honest root is heard from again.)
    await s.carol.sendText(s.accountRid, 'hey');
    await waitUntil(() => texts(s.laptop, s.carol.myRid).contains('hey'),
        what: "carol's 'hey' fanned out to the laptop");
    expect(
        await versionReaches(() => s.laptop.ownDeviceListVersion(), 3), isTrue,
        reason: 'the rogue, impersonating the root, fed the laptop its list');

    // The honest phone returns. Three independent detections follow:
    await rogue.transport.stop();
    s.phone.transport.start();
    await waitUntil(() => linked(s.phone),
        what: 'the honest phone back up on both links');
    // 1. On reconnect the phone re-asserts its honest v2 list to its own
    //    devices; the laptop holds v3 from "the root" — an honest root never
    //    regresses, so the laptop flags the newer list as signed by someone else.
    await waitUntil(() => s.laptop.ownAccountAlert != null,
        what: "the laptop's owner alert after the honest root re-asserts v2");
    // Stored as a kind and its versions, not a sentence (finding 38); the
    // words are chosen in the reader's language when the banner is drawn.
    expect(jsonDecode(s.laptop.ownAccountAlert!)['k'], OwnAlertKind.olderList,
        reason: 'the laptop did not flag the contradicting root sync');
    // 2. The phone speaks with its true (v2) claim; Carol sees device #1
    //    contradict the v3 list it was handed (a rollback on that device).
    await s.phone.sendText(s.carol.myRid, 'still me');
    await waitUntil(() => s.carol.contactDevlistAlerts[s.accountRid] != null,
        what: "carol's contact alert on the phone's v2 claim against her v3");
    expect(s.carol.contactDevlistAlerts[s.accountRid], isNotNull,
        reason: 'Carol did not flag the contradictory device list');
    // What she flagged it WITH: a kind, and no name. The sentence this used
    // to be put the contact's display name into the `kv` table unsealed
    // (`alert_storage_test.dart`), so the end-to-end check is that the real
    // alert, raised by the real path, is not prose.
    expect(isDevlistAlertBody(s.carol.contactDevlistAlerts[s.accountRid]!),
        isTrue,
        reason: 'the alert is stored as a kind: '
            '${s.carol.contactDevlistAlerts[s.accountRid]}');
    final carolDb = utf8.decode(
        File('${s.carol.vault.root.path}/z.db').readAsBytesSync(),
        allowMalformed: true);
    for (final prose in const [
      'devices disagree',
      'went backwards a version',
      "don't confirm the device list",
      'the update never arrived',
    ]) {
      expect(carolDb, isNot(contains(prose)),
          reason: 'the banner prose — which carried the contact\'s display '
              'name — is not in the database: found "$prose"');
    }
    // 3. Carol's receipt back to the phone echoes v3 — a list the root never
    //    issued and cannot explain: after the grace period the root alerts.
    await waitUntil(() => s.phone.ownAccountAlert != null,
        what: "the phone's owner alert on carol's echo of the unissued v3");
  }, timeout: const Timeout(Duration(minutes: 4)));

  test('exclusion (b): a rogue list that drops the honest device is caught',
      () async {
    final s = await bringUpAccount();
    final rogueDevId = await ZIdentity.generate();
    final rogueCert = await s.account.signDeviceCert(
        deviceEdPub: rogueDevId.edPub,
        deviceXPub: rogueDevId.xPub,
        deviceId: 'rogue');

    await s.phone.transport.stop();
    // Rogue publishes v3={phone,rogue} — the honest laptop is removed.
    final rogue = await makeRogue(s.phoneId, s.account, [rogueCert], 3);
    await waitUntil(() => linked(rogue), what: 'the rogue up on both links');
    await rogue.addContactFromCode(await s.carol.myContactCode());
    await rogue.broadcastMyDeviceList();
    expect(
        await versionReaches(
            () => s.carol.heldContactListVersion(s.accountRid), 3),
        isTrue,
        reason: 'Carol never installed the rogue v3 list');

    // Installing a list that drops the laptop, Carol sends it a removal notice
    // over the still-open pairwise session — which the rogue cannot suppress.
    await waitUntil(() => s.laptop.removedDeviceAlert != null,
        what: "carol's removal notice reaching the dropped laptop");
    expect(s.laptop.removedDeviceAlert, isNotNull,
        reason: 'the removed laptop was never told it was cut off');

    // And the contact still catches the contradiction when device #1 returns.
    await rogue.transport.stop();
    s.phone.transport.start();
    await waitUntil(() => linked(s.phone),
        what: 'the honest phone back up on both links');
    await s.phone.sendText(s.carol.myRid, 'still me');
    await waitUntil(() => s.carol.contactDevlistAlerts[s.accountRid] != null,
        what: "carol's contact alert on the phone's v2 claim against her v3");
    expect(s.carol.contactDevlistAlerts[s.accountRid], isNotNull);
  }, timeout: const Timeout(Duration(minutes: 4)));

  test('control: an honest device added and distributed to all raises nothing',
      () async {
    final s = await bringUpAccount();
    final tabletId = await ZIdentity.generate();
    final tabletCert = await s.account.signDeviceCert(
        deviceEdPub: tabletId.edPub,
        deviceXPub: tabletId.xPub,
        deviceId: 'tablet');

    // Honest enrolment: v3={phone,laptop,tablet}, broadcast to Carol AND
    // self-synced to the laptop (rule 8).
    await s.phone.addMyDevice(tabletCert);
    expect(
        await versionReaches(
            () => s.carol.heldContactListVersion(s.accountRid), 3),
        isTrue,
        reason: 'Carol never received the honest v3 device list');
    expect(
        await versionReaches(() => s.laptop.ownDeviceListVersion(), 3), isTrue,
        reason: 'the laptop never caught up to the honest v3');

    // Traffic flows both ways; the echoes now match what every device knows.
    await s.carol.sendText(s.accountRid, 'nice');
    await s.phone.sendText(s.carol.myRid, 'thanks');
    // An echo is checked when the message carrying it ARRIVES, so that is
    // where the margin below has to start. Started at the send, as it was,
    // a slow delivery on a loaded box left the negatives checking a window
    // in which nothing had been observed yet — a pass that tested nothing.
    await waitUntil(
        () =>
            texts(s.phone, s.carol.myRid).contains('nice') &&
            texts(s.laptop, s.carol.myRid).contains('nice') &&
            texts(s.carol, s.accountRid).contains('thanks'),
        what: "'nice' at the phone and the laptop, and 'thanks' at carol");

    // Give the grace window time to fire, then assert everything is quiet.
    await Future<void>.delayed(grace + const Duration(seconds: 1));
    expect(s.laptop.ownAccountAlert, isNull, reason: 'false owner alarm');
    expect(s.laptop.removedDeviceAlert, isNull, reason: 'false removal alarm');
    expect(s.phone.ownAccountAlert, isNull);
    expect(s.carol.contactDevlistAlerts[s.accountRid], isNull,
        reason: 'false contact alarm on an honest update');
  }, timeout: const Timeout(Duration(minutes: 4)));
}
