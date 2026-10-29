// A contact's device-list claims are judged in the order their devices made
// them (PROTOCOL §3.6), so nothing an honest account does makes one of its
// devices look as if it went back a version — and the banner that says a
// device did still comes up for what it is for.
//
// Every inner message carries its sender's claim about its own account's
// list (`dl`), and a receiver tells its user that a contact's device list
// went back (`dl_rollback`) when one of that contact's devices claims a
// version below one it claimed before. Someone holding the account's key and
// an older backup of it, speaking as one of its devices after that device
// has claimed the newer list, makes exactly that. Through 4.7.2 an honest
// account made it too: device_pop_test 4 failed on it once in five runs of
// the whole file — Vic shown that Bob's list had rolled back.
//
// The receiver recorded a claim as the message's last step, after its list
// (if it carried one) was installed, and its contact's own door takes the
// steps of two messages from one device in no fixed order: an install waits
// behind every other install, a `pqid` waits for nothing. Bob's version 2,
// read first, was recorded after his version 3, read next. And the sender
// stamped the `pqseal` riding ahead of a message (§18.11) with a claim read
// after the message's, then encrypted the seal first: a list recorded in
// between went out on the seal and the version before it on the message.
// The echo that shows a contact behind has the account hand its list over
// again, once a minute (§3.6); the minute was recorded only once the list
// had been signed, so an echo read meanwhile handed it over again.
//
// And the order the ratchet reads a device's messages in is not always the
// order they were sent. The relay registers a device that comes back before
// it hands over the device's queue, and what is sent to a registered device
// goes at once (`server.js`, `register` then `flush`), so a list sent while a
// backlog is being handed over is read ahead of texts sent before it — and
// the ratchet reads those after it with the keys it skipped over for them.
// It does so whether the list has been acted on by the time they arrive or
// they arrive with it, and the transport starts each as it arrives.
//
// Real clients through the real relay; no transparency log. An order the
// fault met by luck is made here with a seam: one that holds one message's
// steps once it has been read (`debugBeforeInboundActs`), one that runs
// inside a send a seal rides on (`debugBeforePqSealRides`), one that holds a
// signing of the account's own list (`debugBetweenOwnListReads`), and a
// transport that keeps what its owner sends one contact, as the relay keeps
// it while that contact is away, for the test to hand over in the order the
// relay can.
//
// Criteria, each a test below:
//   1. a contact's list whose message is read and then held, while the same
//      device's next list is read and acted on, raises nothing when it is
//      acted on after it, and is refused as the older list it is (on
//      4a716af it raises dl_rollback, as device_pop_test 4 met);
//   2. the banner still comes up for what it exists for: a backup of the
//      account from before its last list, run by someone holding it as the
//      account's own device after that device has claimed the newer list,
//      raises dl_rollback at once — with no grace to wait out, so nothing
//      else here can raise anything — and the list it hands over is refused;
//   3. a seal riding ahead of a message claims what the message claims: the
//      account's list recorded at the next version inside that send leaves
//      its device's claims, in the order the contact's ratchet reads them,
//      never going down (on 4a716af the seal claims the version after the
//      message's);
//   4. and the list a contact's echo asks for again: an echo read while the
//      list is being signed for the one before it is held back by the
//      minute, so the contact is handed that list once (on 4a716af it is let
//      through, to sign the same list again — the double re-send
//      device_pop_test 13 met one run in five);
//   5. claims are judged in the order their device sent them, not the order
//      they arrive in: a contact's list sent while their texts wait for the
//      receiver, handed over ahead of those texts and with them — each
//      started as it arrives, as the transport starts them — raises nothing
//      when the texts are read after it, out of order (on ef550b5 they raise
//      dl_rollback, which stays until the contact next writes);
//   6. and nothing either when the list has been read and acted on before
//      the texts arrive (on ef550b5 they raise dl_rollback; on 4a716af too,
//      where a claim was recorded once its message had been acted on);
//   7. a contact deleted and added back in the same run starts from
//      nothing: the banner the deleted one had and the claims behind it are
//      gone, and what their device claims from then on is judged on its own
//      (on ef550b5 the banner comes back with them, in memory, and the old
//      claims are written back with the next one);
//   8. and the banner comes up for what else it is for: two of a contact's
//      devices claiming one version under two fingerprints — a list someone
//      signed twice, one for each — raise the conflict banner (dl_conflict),
//      neither claiming the version held for them;
//   9. and so does one of their devices claiming the version held for them
//      under another fingerprint — the list handed over is not the one its
//      devices hold, a split view (T2).
@Tags(['integration'])
@Timeout(Duration(minutes: 4))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart' show DatabaseException;
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/key_transparency.dart';
import 'package:zapp/core/receipts.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:z_protocol/z_protocol.dart';

// Receipts within 300 ms rather than ADR 0028's 5 s to a minute: what is
// counted here is claims, not when a tick turns (as device_pop_test).
const promptReceipts =
    ReceiptTiming(floor: Duration.zero, ceiling: Duration(milliseconds: 300));

/// A transport that keeps what its owner sends to [heldFor] instead of
/// handing it to the relay — what the relay keeps for a device that is away
/// — so a test can hand it over in an order the relay hands things over in.
/// The owner's outbox takes each as sent. Everything else goes to the relay.
class _HoldingTransport extends Transport {
  _HoldingTransport({required super.identity, required super.serverUrl});

  String? heldFor;
  final held = <({String id, String payload})>[];

  @override
  Future<void> send(
      {required String to, required String id, required String payload}) {
    if (to == heldFor) {
      held.add((id: id, payload: payload));
      return Future<void>.value();
    }
    return super.send(to: to, id: id, payload: payload);
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  late Process relay;
  late int port;
  final dirs = <String, Directory>{};
  final live = <ChatService>[];

  // Each service runs in an error zone of its own, and so does what this
  // file asks of it ([inside]); an error raised there fails the test that
  // was running — except the one a service [stop] has shut down still has
  // in flight against the database it closed.
  final zones = <ChatService, Zone>{};
  final stopped = <ChatService>{};
  final strays = <String>[];

  Future<void> stop(ChatService svc) async {
    stopped.add(svc);
    svc.dispose();
    await svc.transport.stop();
    live.remove(svc);
    await svc.vault.db.close();
  }

  tearDown(() async {
    for (final s in live.toList()) {
      await stop(s);
    }
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
    var ok = false;
    for (var i = 0; i < 100 && !ok; i++) {
      try {
        final res = await (await HttpClient()
                .getUrl(Uri.parse('http://127.0.0.1:$port/health')))
            .close();
        await res.drain<void>();
        ok = res.statusCode == 200;
      } catch (_) {}
      if (!ok) await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    if (!ok) fail('relay did not start');
  });

  tearDownAll(() async {
    relay.kill();
    for (final d in dirs.values) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<ChatService> run(String name, Vault vault, ZIdentity id,
      {bool beforeSealingKeys = false, bool holding = false}) {
    final ready = Completer<ChatService>();
    ChatService? made;
    runZonedGuarded(() async {
      try {
        final svc = await ChatService.init(
          vault: vault,
          identity: id,
          displayName: name,
          transport: holding
              ? _HoldingTransport(
                  identity: id, serverUrl: 'ws://127.0.0.1:$port')
              : Transport(identity: id, serverUrl: 'ws://127.0.0.1:$port'),
          // The versions counted here are the ones these tests link devices
          // for; ADR 0029's one-time move to v2-only signing would land a
          // version of its own among them (as device_pop_test).
          signDevlistV2Only: false,
          receiptTiming: promptReceipts,
          ktConfig: KtConfig.off,
          debugBuildBeforeSealingKeys: beforeSealingKeys,
        );
        made = svc;
        zones[svc] = Zone.current;
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

  /// [f], run in [svc]'s zone: what it leaves running — the mirror of a
  /// message to the account's other devices, a link's history — is that
  /// service's, and fails no test by meeting the database [stop] closed.
  /// What [f] itself returns or throws comes back to the test: a future of
  /// another error zone would keep its error there, and the test would wait
  /// for it until it timed out.
  Future<T> inside<T>(ChatService svc, Future<T> Function() f) {
    final done = Completer<T>();
    zones[svc]!
        .run(() => f().then(done.complete, onError: done.completeError));
    return done.future;
  }

  Future<void> say(ChatService from, String toRid, String text) =>
      inside(from, () => from.sendText(toRid, text));

  Future<void> link(ChatService owner, DeviceCertificate cert) =>
      inside(owner, () => owner.addMyDevice(cert));

  Future<void> add(ChatService svc, String code) =>
      inside(svc, () => svc.addContactFromCode(code));

  /// A new account called [name]; [beforeSealingKeys], on a build from
  /// before 44.3; [holding], sending through a [_HoldingTransport].
  Future<ChatService> start(String name,
      {bool beforeSealingKeys = false, bool holding = false}) async {
    final dir = dirs[name] = await Directory.systemTemp.createTemp('z_ord_$name');
    final vault = await Vault.open(rootOverride: dir);
    final id = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(id.toJson()));
    return run(name, vault, id,
        beforeSealingKeys: beforeSealingKeys, holding: holding);
  }

  Future<bool> outboxEmpty(ChatService s) async =>
      (await s.vault.db.query('outbox', limit: 1)).isEmpty;

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
    await add(a, await b.myContactCode());
    await add(b, await a.myContactCode());
    await say(a, b.myRid, 'hello ${b.displayName}');
    await say(b, a.myRid, 'hello ${a.displayName}');
    await waitUntil(
        () =>
            received(a, b.myRid, 'hello ${a.displayName}') &&
            received(b, a.myRid, 'hello ${b.displayName}'),
        what: '${a.displayName} and ${b.displayName} have spoken');
  }

  /// [from] says [text] to [to], and it arrives.
  Future<void> heard(ChatService from, ChatService to, String text) async {
    await say(from, to.myRid, text);
    await waitUntil(() => received(to, from.myRid, text),
        what: '"$text" reaches ${to.displayName}');
  }

  /// A device of [owner]'s account that runs no client: a certificate its
  /// account signed over keys nobody here uses. Linking one moves the
  /// account's list a version.
  Future<DeviceCertificate> deviceOf(ChatService owner, String id) async {
    final d = await ZIdentity.generate();
    return (await owner.accountIdentity())
        .signDeviceCert(deviceEdPub: d.edPub, deviceXPub: d.xPub, deviceId: id);
  }

  /// The version [inner] claims for its sender's own account's list.
  int? claimOf(InnerMessage inner) {
    final dl = inner.data['dl'];
    return dl is Map && dl['v'] is num ? (dl['v'] as num).toInt() : null;
  }

  /// The kind of the device-list alert [svc] holds on [rid]'s chat.
  String? alertKind(ChatService svc, String rid) {
    final s = svc.contactDevlistAlerts[rid];
    return s == null ? null : (jsonDecode(s) as Map)['k'] as String?;
  }

  /// A device linked to [host]'s account, its client running: enrolled with
  /// the account's keys, and knowing the root's certificate.
  Future<({ChatService svc, DeviceCertificate cert})> linkedTo(
      ChatService host, String name) async {
    final account = await host.accountIdentity();
    final ml = await host.pqAccountPublic();
    final devId = await ZIdentity.generate();
    final cert = await account.signDeviceCert(
        deviceEdPub: devId.edPub, deviceXPub: devId.xPub, deviceId: name);
    final dir =
        dirs[name] = await Directory.systemTemp.createTemp('z_ord_$name');
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

  /// What [s]'s device claims about its own account's list from here on,
  /// written behind its back: the claim of a device whose list was signed
  /// somewhere else.
  Future<void> claimAs(ChatService s, int v, String h) async {
    await s.vault.kvPut('own_list_v', '$v', sensitive: false);
    await s.vault.kvPut('own_list_h', h, sensitive: false);
    s.forgetOwnListClaim();
  }

  /// [device], one of [account]'s, says [text] to [to], and it arrives in
  /// the account's chat.
  Future<void> speaks(ChatService device, ChatService to, ChatService account,
      String text) async {
    await say(device, to.myRid, text);
    await waitUntil(() => received(to, account.myRid, text),
        what: '"$text" from ${device.displayName} reaches ${to.displayName}');
  }

  /// Two fingerprints no list here has.
  final fpA = base64Encode(List<int>.filled(32, 0xA1));
  final fpB = base64Encode(List<int>.filled(32, 0xB2));

  /// Bob links a device (version 2) and a backup of his account is taken;
  /// he links another (version 3), and his device says so to Vic; then it
  /// goes quiet, and the backup comes up as it and says something to Vic.
  /// Returns Vic and the backup — Bob, to her — once she has read it. Vic
  /// waits an hour for a list a device claims and nobody hands her: nothing
  /// raised here can be that (§3.6), only the rollback rule's.
  Future<(ChatService, ChatService)> backupSpeaks(String n) async {
    final vic = await start('vic$n');
    final bob = await start('bob$n');
    vic.devlistGrace = const Duration(hours: 1);
    await introduce(vic, bob);
    await link(bob, await deviceOf(bob, 'tablet'));
    await waitUntil(
        () async => await vic.heldContactListVersion(bob.myRid) == 2,
        what: "Vic installs Bob's version 2");

    // Bob's backup as it stands now — the device's identity, the account's
    // root, its devices at version 2 — in someone else's hands.
    final identity = (await bob.vault.kvGet('identity'))!;
    final account = jsonEncode((await bob.accountIdentity()).toJson());
    final devices = (await bob.vault.kvGet('my_devices'))!;

    // Bob moves on, and his device says so to Vic.
    await link(bob, await deviceOf(bob, 'phone2'));
    await waitUntil(
        () async => await vic.heldContactListVersion(bob.myRid) == 3,
        what: "Vic installs Bob's version 3");
    await heard(bob, vic, 'at version 3');
    expect(vic.contactDevlistAlerts[bob.myRid], isNull);

    // Bob's device goes quiet, and the backup comes up as it.
    await stop(bob);
    final dir = dirs['bob${n}backup'] =
        await Directory.systemTemp.createTemp('z_ord_bob${n}backup');
    final vault = await Vault.open(rootOverride: dir);
    await vault.kvPut('identity', identity);
    await vault.kvPut('account', account);
    await vault.kvPut('my_devices', devices, sensitive: false);
    await vault.kvPut('my_devlist_version', '2', sensitive: false);
    final backup = await run(
        'bob${n}backup',
        vault,
        await ZIdentity.fromJson(
            (jsonDecode(identity) as Map).cast<String, Object?>()));
    expect(backup.myRid, bob.myRid, reason: "it speaks as Bob's device");
    expect(await backup.ownDeviceListVersion(), 2);
    await waitUntil(() => linked(backup), what: 'the backup connected');
    await add(backup, await vic.myContactCode());
    await say(backup, vic.myRid, 'still me');
    await waitUntil(() => received(vic, bob.myRid, 'still me'),
        what: 'Vic reads the backup, as Bob');
    return (vic, backup);
  }

  /// Vic, and Bob sending through a [_HoldingTransport]. While Vic is away
  /// Bob says two things, his list at version 1, and what he sends her waits
  /// for her, as the relay keeps it. She comes back, and while her backlog is
  /// being handed over he links a device: the list he sends her, at version
  /// 2, goes to her at once. Returns the two, what is to be handed to Vic —
  /// her backlog, then what Bob sent her while it was being handed over —
  /// and how much of it is the backlog.
  ///
  /// Whatever Bob sends her after that stays kept, for the rest of the test:
  /// what Vic shows is what she makes of these messages alone. Any later
  /// message of his, read in its place, would put his device's claims in
  /// order again, and the banner a test looks for would come and go.
  Future<(ChatService, ChatService, List<({String id, String payload})>, int)>
      listBehindBacklog(String n) async {
    final vic = await start('vic$n');
    final bob = await start('bob$n', holding: true);
    await introduce(vic, bob);
    final relayed = bob.transport as _HoldingTransport;
    relayed.heldFor = vic.myRid;
    await say(bob, vic.myRid, 'away 1');
    await say(bob, vic.myRid, 'away 2');
    await waitUntil(() => outboxEmpty(bob),
        what: "Bob's texts sent, kept for Vic");
    final backlog = relayed.held.length;
    await link(bob, await deviceOf(bob, 'tablet'));
    await waitUntil(() => outboxEmpty(bob), what: "Bob's list sent, kept");
    final handed = List.of(relayed.held);
    expect(handed.length, greaterThan(backlog));
    return (vic, bob, handed, backlog);
  }

  /// [e] handed to the device it was kept for, as the relay hands it over.
  Future<void> hand(ChatService to, ({String id, String payload}) e) =>
      inside(
          to,
          () => to.debugInbound(RelayInbound(
              id: e.id,
              from: '',
              payload: e.payload,
              serverTs: DateTime.now().millisecondsSinceEpoch)));

  /// The kinds of what [from] sends [to] from here on, in the order [to]'s
  /// ratchet reads them.
  List<String> readOrder(ChatService to, ChatService from) {
    final read = <String>[];
    to.debugOnDecrypted = (path, rid, dec) {
      if (rid == from.myRid) {
        try {
          read.add(InnerMessage.fromBytes(dec.plaintext).kind);
        } catch (_) {}
      }
      return false;
    };
    return read;
  }

  /// Vic has read Bob's list ahead of a text he sent before it, and all of
  /// it, and nothing says his device went back.
  Future<void> nothingWentBack(
      ChatService vic, ChatService bob, List<String> read) async {
    final list = read.indexOf('devlist');
    expect(list, isNonNegative, reason: 'read: $read');
    expect(list, lessThan(read.lastIndexOf('text')),
        reason: 'Vic read the list before a text sent ahead of it: $read');
    expect(received(vic, bob.myRid, 'away 1'), isTrue);
    expect(received(vic, bob.myRid, 'away 2'), isTrue);
    expect(await vic.heldContactListVersion(bob.myRid), 2);
    expect(vic.contactDevlistAlerts[bob.myRid], isNull,
        reason: 'Bob did nothing but link a device: his device claimed '
            'version 1 and then version 2, in the order he sent them');
  }

  test(
      "1. a contact's list read and held while the device's next list is "
      'acted on raises nothing when it is acted on after it', () async {
    final vic = await start('vic1');
    final bob = await start('bob1');
    await introduce(vic, bob);

    // Bob links a device: version 2. Vic reads its message, stores it, and
    // what it says waits — as a list's install waits behind another on a
    // loaded device — while Bob links another and Vic reads and acts on
    // version 3.
    final release = Completer<void>();
    addTearDown(() {
      if (!release.isCompleted) release.complete();
    });
    String? held;
    var heldActedOn = false;
    var nextActedOn = false;
    String? alertThen;
    vic.debugBeforeInboundActs = (rid, inner) async {
      if (rid != bob.myRid || held != null) return;
      if (inner.kind != 'devlist' || claimOf(inner) != 2) return;
      held = inner.mid;
      await release.future;
    };
    vic.debugInboundActedOn = (rid, inner) {
      if (rid != bob.myRid) return;
      if (inner.kind == 'devlist' && claimOf(inner) == 3) nextActedOn = true;
      if (inner.mid == held) {
        heldActedOn = true;
        // What the user is shown the moment version 2's message has been
        // acted on: before anything Bob sends afterwards can change it.
        alertThen = vic.contactDevlistAlerts[bob.myRid];
      }
    };
    await link(bob, await deviceOf(bob, 'tablet'));
    await waitUntil(() => held != null,
        what: "Vic has read Bob's version 2, and holds what it says");
    await link(bob, await deviceOf(bob, 'phone2'));
    await waitUntil(() => nextActedOn,
        what: "Vic reads and acts on Bob's version 3");
    expect(await vic.heldContactListVersion(bob.myRid), 3);
    expect(vic.contactDevlistAlerts[bob.myRid], isNull);

    release.complete();
    await waitUntil(() => heldActedOn,
        what: "Vic acts on Bob's version 2, after his version 3");
    expect(alertThen, isNull,
        reason: "Bob's device claimed version 2 and then version 3, in the "
            'order Vic read them: nothing went back');
    expect(vic.contactDevlistAlerts[bob.myRid], isNull);
    expect(await vic.heldContactListVersion(bob.myRid), 3,
        reason: 'version 2, read before version 3, is the older list');
  });

  test(
      '2. a backup of the account from before its last list, speaking as its '
      'device after that device claimed the newer one, raises dl_rollback',
      () async {
    final (vic, bob) = await backupSpeaks('2');
    await waitUntil(() => vic.contactDevlistAlerts[bob.myRid] != null,
        what: "Vic says Bob's device list went back");
    expect(alertKind(vic, bob.myRid), 'dl_rollback',
        reason: 'the same device claimed version 3 and then version 2');
    expect(await vic.heldContactListVersion(bob.myRid), 3,
        reason: 'the version 2 the backup hands over is refused');
  });

  test(
      '3. a seal riding ahead of a message claims what the message claims, '
      'so a list recorded during the send never shows the device going back',
      () async {
    final alice = await start('alice3');
    // Bob runs a build from before sealing keys (44.3): he never says he
    // holds Alice's, so the first message of hers to his device that a seal
    // may ride ahead of has one, whenever that is.
    final bob = await start('bob3', beforeSealingKeys: true);
    // Every envelope from Alice's device that claims a version, in the order
    // Bob's ratchet reads them: its kind and the version.
    final read = <({String kind, int v})>[];
    bob.debugOnDecrypted = (path, from, dec) {
      if (path == 'primary' && from == alice.myRid) {
        try {
          final m = InnerMessage.fromBytes(dec.plaintext);
          final v = claimOf(m);
          if (v != null) read.add((kind: m.kind, v: v));
        } catch (_) {}
      }
      return false;
    };
    // The first time the seal rides to Bob, Alice links a device inside that
    // send: her list is recorded at the next version after the message has
    // been decorated and before the seal is made — the order device_pop_test
    // 11 met by luck.
    var linkedInSend = false;
    alice.debugBeforePqSealRides = (rid) async {
      if (rid != bob.myRid || linkedInSend) return;
      linkedInSend = true;
      final before = (await alice.debugOwnListClaim()).$1;
      unawaited(alice.addMyDevice(await deviceOf(alice, 'tablet')));
      await waitUntil(
          () async => (await alice.debugOwnListClaim()).$1 > before,
          what: "Alice's list at the next version, inside the send");
    };
    await introduce(alice, bob);
    for (var i = 0; !linkedInSend && i < 8; i++) {
      await heard(alice, bob, 'more $i');
    }
    expect(linkedInSend, isTrue,
        reason: "Alice's seal rode ahead of a message of hers to Bob");
    await waitUntil(
        () async => await bob.heldContactListVersion(alice.myRid) == 2,
        what: "Bob installs Alice's version 2");
    await heard(alice, bob, 'at version 2');

    final seal = read.indexWhere((r) => r.kind == 'pqseal');
    expect(seal, isNonNegative, reason: 'read: $read');
    expect(read[seal].v, read[seal + 1].v,
        reason: 'the seal claims what the message behind it claims: $read');
    for (var i = 1; i < read.length; i++) {
      expect(read[i].v, greaterThanOrEqualTo(read[i - 1].v),
          reason: "in the order Bob read them, Alice's device never claimed "
              'less than it had: $read');
    }
    expect(bob.contactDevlistAlerts[alice.myRid], isNull);
  });

  test(
      "4. an echo read while the list is being signed for the one before it "
      'is held back by the minute: the contact is handed that list once',
      () async {
    final vic = await start('vic4');
    final bob = await start('bob4');
    await introduce(vic, bob);
    // Vic takes no list of Bob's: everything she sends him echoes the one she
    // held before — as when a first-come claim had her refuse it
    // (device_pop_test 13) — and each echo asks his root to hand his list over
    // again.
    vic.debugOnDecrypted = (path, from, dec) {
      if (path != 'primary' || from != bob.myRid) return false;
      try {
        return InnerMessage.fromBytes(dec.plaintext).kind == 'devlist';
      } catch (_) {
        return false;
      }
    };
    // Bob's root signs the list it hands over. The signing after the one his
    // link makes — the first re-send's — waits until the next echo has been
    // read, as a signing waits behind another for the own-list lock on a
    // loaded device.
    final release = Completer<void>();
    addTearDown(() {
      if (!release.isCompleted) release.complete();
    });
    var signings = 0;
    bob.debugBetweenOwnListReads = () async {
      if (signings++ == 1) await release.future;
    };
    bob.debugListResends = [];
    Iterable<({String rid, String? sent})> toVic() =>
        bob.debugListResends!.where((r) => r.rid == vic.myRid);
    await link(bob, await deviceOf(bob, 'tablet'));
    await say(vic, bob.myRid, 'one');
    await say(vic, bob.myRid, 'two');
    // An echo read while the first re-send's list is being signed is held
    // back by the minute — or, as through 4.7.2, let through, to wait for the
    // lock and sign the same list again.
    await waitUntil(
        () => bob.debugOwnListWaiting || toVic().any((r) => r.sent == null),
        what: "Bob's root reads an echo of Vic's while it signs the list");
    expect(bob.debugOwnListWaiting, isFalse,
        reason: 'an echo read while the list is being signed for the one '
            'before it is held back, not let through to sign it again');
    release.complete();
    await waitUntil(() => toVic().any((r) => r.sent != null),
        what: "Bob's root hands its list over again");
    expect([for (final r in toVic()) if (r.sent != null) r.sent],
        hasLength(1),
        reason: 'the same list is handed over once in a minute, however many '
            'echoes ask for it at once');
    expect(toVic().where((r) => r.sent == null), isNotEmpty);
  });

  test(
      '5. a list handed over ahead of the texts its device sent before it, '
      'and with them, raises nothing when they are read after it', () async {
    final (vic, bob, kept, backlog) = await listBehindBacklog('5');
    final read = readOrder(vic, bob);
    // What went live first, then the backlog, as the transport hands it
    // over: each started as it arrives, none waiting for the one before.
    await Future.wait([
      for (final e in [...kept.sublist(backlog), ...kept.sublist(0, backlog)])
        hand(vic, e),
    ]);
    await nothingWentBack(vic, bob, read);
  });

  test(
      '6. a list read and acted on before the texts its device sent ahead of '
      'it arrive raises nothing when they are read after it', () async {
    final (vic, bob, kept, backlog) = await listBehindBacklog('6');
    final read = readOrder(vic, bob);
    // What went live, each read and acted on in turn; then the backlog, as
    // the transport hands it over.
    for (final e in kept.sublist(backlog)) {
      await hand(vic, e);
    }
    await Future.wait([for (final e in kept.sublist(0, backlog)) hand(vic, e)]);
    await nothingWentBack(vic, bob, read);
  });

  test(
      '7. a contact deleted and added back in the same run starts from '
      'nothing: no banner and no claims of the one deleted', () async {
    final (vic, bob) = await backupSpeaks('7');
    await waitUntil(() => vic.contactDevlistAlerts[bob.myRid] != null,
        what: "Vic says Bob's device list went back");
    String? banner() => vic.contactDevlistAlerts[bob.myRid];

    // Vic deletes Bob, and adds him back from his code, in the same run.
    await inside(vic, () => vic.deleteContact(bob.myRid));
    expect(await vic.vault.kvGet('cdl_alert_${bob.myRid}'), isNull);
    expect(await vic.vault.kvGet('cdl_claims_${bob.myRid}'), isNull);
    await add(vic, await bob.myContactCode());
    expect(banner(), isNull,
        reason: 'a contact added back starts from nothing: the banner went '
            'with the one deleted');

    // They speak again. What his device claims now — version 2, as before
    // — is the first claim of his this contact has seen.
    await heard(vic, bob, 'back again');
    await heard(bob, vic, 'still me, again');
    Future<Map<String, Object?>?> stored() async {
      final s = await vic.vault.kvGet('cdl_claims_${bob.myRid}');
      return s == null ? null : (jsonDecode(s) as Map).cast<String, Object?>();
    }

    await waitUntil(() async => (await stored()) != null,
        what: "Vic writes down Bob's device's claim");
    expect((await stored())![bob.myRid], containsPair('mx', 2),
        reason: 'the highest it has claimed is the one it claims now, not '
            "the deleted contact's version 3");
    expect(banner(), isNull);
  });

  test(
      "8. two of a contact's devices claiming one version under two "
      'fingerprints raise the conflict banner', () async {
    final vic = await start('vic8');
    final bob = await start('bob8');
    // A device claiming a version nobody has handed Vic is a list on its
    // way, which she gives an hour: nothing here waits that out.
    vic.devlistGrace = const Duration(hours: 1);
    await introduce(vic, bob);
    // Two devices linked to Bob's account, their clients running: version 3.
    final laptop = await linkedTo(bob, 'bob8laptop');
    final tablet = await linkedTo(bob, 'bob8tablet');
    await link(bob, laptop.cert);
    await link(bob, tablet.cert);
    await waitUntil(
        () async => await vic.heldContactListVersion(bob.myRid) == 3,
        what: "Vic installs Bob's version 3");
    for (final d in [laptop.svc, tablet.svc]) {
      await waitUntil(() async => await d.ownDeviceListVersion() == 3,
          what: '${d.displayName} learns its account is at version 3');
      await waitUntil(() => linked(d), what: '${d.displayName} connected');
    }
    // The laptop adds Vic, and the account's other devices are told (13.7).
    await add(laptop.svc, await vic.myContactCode());
    await waitUntil(() => tablet.svc.contacts.containsKey(vic.myRid),
        what: 'the tablet has Vic, from the laptop');
    for (final d in [laptop.svc, tablet.svc]) {
      await speaks(d, vic, bob, 'from ${d.displayName}');
    }
    expect(vic.contactDevlistAlerts[bob.myRid], isNull,
        reason: 'his devices claim version 3, the list Vic holds');

    // Someone has signed a version 4 twice and given each linked device one.
    // His root goes on claiming the list it signed: a root whose claim is
    // moved past what Vic holds signs that list again when her echo shows
    // her behind, and claims it.
    await claimAs(laptop.svc, 4, fpA);
    await speaks(laptop.svc, vic, bob, 'the laptop at version 4');
    await claimAs(tablet.svc, 4, fpB);
    await speaks(tablet.svc, vic, bob, 'the tablet at version 4');
    await waitUntil(() => vic.contactDevlistAlerts[bob.myRid] != null,
        what: "Vic says Bob's devices disagree");
    expect(alertKind(vic, bob.myRid), 'dl_conflict',
        reason: 'two of his devices claim version 4 under two fingerprints');
    expect(await vic.heldContactListVersion(bob.myRid), 3);
  });

  test(
      "9. a contact's device claiming the version held for them under "
      'another fingerprint raises the conflict banner', () async {
    final vic = await start('vic9');
    final bob = await start('bob9');
    vic.devlistGrace = const Duration(hours: 1);
    await introduce(vic, bob);
    // Vic misses the list Bob's link hands her, so her next message shows
    // her behind and his root signs it again to hand it over: once in the
    // minute (§3.6). A signing records the list it signs as his device's
    // claim, and one still in flight when the claim below is written would
    // write over it — measured: a re-send asked for by an echo she sent
    // before she held the list recorded it 7 ms after the claim was
    // written. Once it has been handed over, nothing in the minute signs.
    var missed = false;
    vic.debugOnDecrypted = (path, from, dec) {
      if (missed || path != 'primary' || from != bob.myRid) return false;
      try {
        return missed =
            InnerMessage.fromBytes(dec.plaintext).kind == 'devlist';
      } catch (_) {
        return false;
      }
    };
    bob.debugListResends = [];
    await link(bob, await deviceOf(bob, 'tablet'));
    await waitUntil(() => missed, what: "Vic misses Bob's list");
    await say(vic, bob.myRid, 'anything new?');
    await waitUntil(
        () => bob.debugListResends!
            .any((r) => r.rid == vic.myRid && r.sent != null),
        what: "Bob's root hands its list over again");
    await waitUntil(
        () async => await vic.heldContactListVersion(bob.myRid) == 2,
        what: "Vic installs Bob's version 2");
    await heard(bob, vic, 'at version 2');
    expect(vic.contactDevlistAlerts[bob.myRid], isNull);

    // Bob's device holds a version 2 that is not the one Vic was handed:
    // someone with the account's key gave her one list and his devices
    // another.
    await claimAs(bob, 2, fpA);
    await heard(bob, vic, 'still at version 2');
    await waitUntil(() => vic.contactDevlistAlerts[bob.myRid] != null,
        what: "Vic says Bob's device holds another list");
    expect(alertKind(vic, bob.myRid), 'dl_conflict',
        reason: 'his device claims the version she holds under another '
            'fingerprint');
    expect(await vic.heldContactListVersion(bob.myRid), 2);
  });
}
