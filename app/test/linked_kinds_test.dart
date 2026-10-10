// Edits, timers, reactions and receipts reach every device (30.3).
//
// A linked device is a full peer (USING_Z, "Your other devices"): it has its
// own keys and its own sessions, and what one device does reaches the others
// by two doors. A contact's devices hear a person's other devices through the
// extra-device door, as that person; a person's own devices hear each other
// through self-sync (PROTOCOL §9). Both doors carried messages and
// attachments, and since 30.1 deletes, and dropped every other kind. An edit
// made on a laptop left the old text on the contact's phone; a reaction made
// there reached nobody; a timer set on the phone did not govern what the
// laptop sent; and receipts from or to a linked device went nowhere, so a
// message sent from a laptop was never marked delivered (the 2026-10-03
// analysis, P1-12).
//
// Real ChatService instances over the real relay: Alice with a phone (her
// account's root) and a laptop, Bob with the same, and Carol with a phone
// where a test needs a third person. What a modified client could send — an
// edit of someone else's message from a linked device, a mirror an honest
// device never builds — goes through the real ratchets (`debugSendRawInner`,
// `debugMirrorToMyDevices`).
//
// Exit criteria, each a test below:
//   1. an edit made on any device reaches every device of both people in a
//      1:1 chat — from the contact's laptop as the contact's, from my laptop
//      as mine, and to the editor's own other device — and the linked doors
//      keep the authorship rule: the contact's laptop cannot edit a message
//      of mine, nor a mirror from my laptop one of theirs;
//   2. the same in a group, where the rule is the stored sender: a member
//      edits their own message from any of their devices and it changes on
//      every member's every device, and a member's laptop cannot edit a
//      third member's message;
//   3. a reaction made on any device reaches every device, in a 1:1 chat and
//      in a group, as one person's — a second one from another of their
//      devices replaces the first — and none counts from someone outside the
//      group or for a message outside the conversation;
//   4. a disappearing timer set on any device is set on every device of both
//      people, and what each device sends afterwards carries it — one set on
//      the contact's laptop, one set on my phone — and a device linked after
//      the timer was set starts with it;
//   5. read receipts from and to linked devices count: the contact reading on
//      their laptop turns my message read on both my devices, my laptop
//      reading turns theirs read on both of theirs, laptop to laptop too;
//   6. what I read on one of my devices is read on the others: a message
//      from the contact's laptop counts unread as one from their phone does,
//      and a group message once on each device though a linked device holds
//      it twice; the unread count clears on my phone when I read on my
//      laptop, in a chat and in a group; the phone sends no second receipt;
//      and the counts stay clear after the phone restarts;
//   7. delivery receipts from and to linked devices count: a message sent
//      from my laptop is marked delivered on both my devices, in a chat and
//      in a group, the contact's laptop alone delivers while their phone is
//      away, and a group message waits for each member once, whichever of
//      their devices answers;
//   8. a mirror from my own device that cannot be applied is acknowledged
//      rather than left at the relay — one that names nothing, or something
//      that is not mine, and one whose handler cannot read it — and the next
//      mirror still arrives;
//   9. what a device did while another was away arrives in one burst when
//      that one comes back, and every edit, reaction, timer and read in it
//      applies after the message it names — through self-sync to my laptop,
//      and through the extra-device door to the contact's phone and laptop.
@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart' show mapEquals;
import 'package:flutter_test/flutter_test.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/models.dart';
import 'package:zapp/core/receipts.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';

/// Alice's phone and laptop, Bob's phone and laptop, and — where a test asks
/// for a third person — Carol's phone.
typedef World = ({
  ChatService aPhone,
  ChatService aLap,
  ChatService bPhone,
  ChatService bLap,
  ChatService? cPhone,
});

/// The kind of the inner message an envelope carried, on the contact and
/// extra-device paths (a self-sync envelope wraps its inner, and is not one
/// this file counts).
String? kindOf(DecryptResult dec) {
  try {
    return InnerMessage.fromBytes(dec.plaintext).kind;
  } catch (_) {
    return null;
  }
}

int now() => DateTime.now().millisecondsSinceEpoch;

// ADR 0028 holds a receipt from 5 s to a minute, at random, so the relay
// cannot pair it with the message it answers (receipt_timing_test.dart). This
// suite is about which device answers for whom, not about when a tick turns, so its devices answer
// within 300 ms, as every device did before phase 41.
const promptReceipts =
    ReceiptTiming(floor: Duration.zero, ceiling: Duration(milliseconds: 300));

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  late Process relay;
  late int port;
  final temps = <Directory>[];
  final live = <ChatService>[];
  final dirs = <String, Directory>{};

  setUpAll(() async {
    HttpOverrides.global = null;
    final serverDir =
        '${Directory.current.parent.path}${Platform.pathSeparator}server';
    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    port = probe.port;
    await probe.close();
    relay = await Process.start('node', ['server.js'],
        workingDirectory: serverDir,
        environment: {
          'PORT': '$port',
          'LOG_LEVEL': 'silent',
          'METRICS_TOKEN': 'z-apptest-metrics',
        });
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
    for (final s in live) {
      s.dispose();
      await s.transport.stop();
    }
    relay.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<Directory> dirFor(String name) async =>
      dirs[name] ??
      await Directory.systemTemp.createTemp('z_lk_').then((d) {
        temps.add(d);
        return dirs[name] = d;
      });

  /// A client named [name]; the same name again reopens the same vault.
  Future<ChatService> start(String name) async {
    final vault = await Vault.open(rootOverride: await dirFor(name));
    final stored = await vault.kvGet('identity');
    final id = stored == null
        ? await ZIdentity.generate()
        : await ZIdentity.fromJson(
            (jsonDecode(stored) as Map).cast<String, Object?>());
    if (stored == null) await vault.kvPut('identity', jsonEncode(id.toJson()));
    final svc = await ChatService.init(
        vault: vault,
        identity: id,
        displayName: name,
        transport: Transport(identity: id, serverUrl: 'ws://127.0.0.1:$port'),
        receiptTiming: promptReceipts);
    live.add(svc);
    return svc;
  }

  Future<void> stop(ChatService s) async {
    s.dispose();
    await s.transport.stop();
    live.remove(s);
    await s.vault.db.close();
  }

  Future<void> waitUntil(FutureOr<bool> Function() cond,
      {Duration timeout = const Duration(seconds: 40),
      required String what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  Future<int> metric(String name) async {
    // /metrics is token-gated (P1-14): the relay is spawned with
    // METRICS_TOKEN set to this value above.
    final req =
        await HttpClient().getUrl(Uri.parse('http://127.0.0.1:$port/metrics'));
    req.headers.set('authorization', 'Bearer z-apptest-metrics');
    final res = await req.close();
    final text = await res.transform(utf8.decoder).join();
    if (res.statusCode != 200) {
      throw StateError('/metrics answered HTTP ${res.statusCode}');
    }
    for (final line in const LineSplitter().convert(text)) {
      if (line.startsWith('$name ')) {
        return int.parse(line.substring(name.length + 1).trim());
      }
    }
    return -1;
  }

  /// Nothing left anywhere: no client has an envelope or a group fan-out row
  /// still to send, and the relay holds nothing undelivered — which, for
  /// clients that are all online, means every recipient has processed and
  /// acknowledged everything sent to it. Read three times running, because
  /// processing one envelope can queue another (a receipt).
  Future<void> quiet(List<ChatService> all,
      {required String what,
      Duration timeout = const Duration(seconds: 90)}) async {
    var calm = 0;
    await waitUntil(() async {
      for (final s in all) {
        await s.flushOutbox();
        if ((await s.vault.db.query('outbox', limit: 1)).isNotEmpty ||
            (await s.vault.db.query('group_fanout', limit: 1)).isNotEmpty) {
          calm = 0;
          return false;
        }
      }
      if (await metric('z_queued_envelopes') != 0) {
        calm = 0;
        return false;
      }
      return ++calm >= 3;
    }, timeout: timeout, what: what);
  }

  /// Clients that just added each other have finished introducing
  /// themselves (as `settled` in replies_test.dart).
  Future<void> settled(List<ChatService> all) async {
    await waitUntil(() async {
      for (final s in all) {
        for (final o in all) {
          if (identical(s, o)) continue;
          final c = s.contacts[o.myRid];
          if (c == null) continue;
          if (c.pqPub == null && c.pqCandidate == null) return false;
        }
      }
      for (final s in all) {
        if ((await s.vault.db.query('outbox', limit: 1)).isNotEmpty) {
          return false;
        }
      }
      return all.every((s) => !s.pqSendPending);
    }, what: 'the contacts settled');
  }

  Future<void> befriend(ChatService a, ChatService b) async {
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
  }

  /// A laptop linked to [main]'s account as `hostDeviceLink` enrols one — its
  /// own keys, the account's certificate for them and the account's
  /// post-quantum public key — holding [knows] as contacts from the start, as
  /// the contacts an enrolment hands over are, and then listed by [main],
  /// which tells its contacts.
  Future<ChatService> laptopOf(
      ChatService main, String name, List<ChatService> knows) async {
    final devId = await ZIdentity.generate();
    final account = await main.accountIdentity();
    final cert = await account.signDeviceCert(
        deviceEdPub: devId.edPub, deviceXPub: devId.xPub, deviceId: name);
    final vault = await Vault.open(rootOverride: await dirFor(name));
    await vault.kvPut('identity', jsonEncode(devId.toJson()));
    final enrolled = await AccountIdentity.fromEnrollment(
      accountEdPub: account.accountEdPub,
      accountMlPub: await main.pqAccountPublic(),
      deviceEdSeed: devId.edSeed,
      deviceXSeed: devId.xSeed,
      deviceId: name,
      deviceCert: cert,
    );
    await vault.kvPut('account', jsonEncode(enrolled.toJson()));
    await vault.kvPut('my_devices', jsonEncode([account.deviceCert.toJson()]),
        sensitive: false);
    final svc = await ChatService.init(
        vault: vault,
        identity: devId,
        displayName: name,
        transport:
            Transport(identity: devId, serverUrl: 'ws://127.0.0.1:$port'),
        receiptTiming: promptReceipts);
    live.add(svc);
    await waitUntil(() => svc.transport.isConnected, what: '$name connects');
    for (final k in knows) {
      // No contact request: an enrolment hands contacts over and asks nobody.
      await svc.addContactFromCode(await k.myContactCode(), requested: false);
    }
    await main.addMyDevice(cert);
    return svc;
  }

  /// Whether [svc] holds [device] as one of [owner]'s devices.
  bool holds(ChatService svc, ChatService device, ChatService owner) =>
      svc.debugListedDeviceOwner(device.myRid) == owner.myRid;

  List<ChatService> everyone(World w) =>
      [w.aPhone, w.aLap, w.bPhone, w.bLap, if (w.cPhone != null) w.cPhone!];

  /// Alice and Bob, each with a phone and a laptop, every device holding
  /// every device of the other person; with [carol], Carol's phone too, a
  /// contact of both.
  Future<World> world(String tag, {bool carol = false}) async {
    final aPhone = await start('Alice$tag');
    final bPhone = await start('Bob$tag');
    final cPhone = carol ? await start('Carol$tag') : null;
    final phones = [aPhone, bPhone, if (cPhone != null) cPhone];
    await waitUntil(() => phones.every((s) => s.transport.isConnected),
        what: 'the phones connect');
    await befriend(aPhone, bPhone);
    if (cPhone != null) {
      await befriend(aPhone, cPhone);
      await befriend(bPhone, cPhone);
    }
    await settled(phones);
    List<ChatService> others(ChatService me) =>
        [for (final p in phones) if (!identical(p, me)) p];

    final aLap = await laptopOf(aPhone, 'AliceLaptop$tag', others(aPhone));
    await waitUntil(() => others(aPhone).every((p) => holds(p, aLap, aPhone)),
        what: "Alice's contacts hold her list naming her laptop");
    final bLap = await laptopOf(bPhone, 'BobLaptop$tag', others(bPhone));
    await waitUntil(
        () => [aPhone, aLap, if (cPhone != null) cPhone]
            .every((p) => holds(p, bLap, bPhone)),
        what: "Alice's devices and Carol hold Bob's list naming his laptop");
    // Bob's laptop was listed after Alice's list went out, so it holds her
    // phone alone. Anything it says to her echoes that, and her phone hands
    // the newer list over (PROTOCOL §3.6) — a hello, which shows nothing.
    await bLap.debugSendRawInner(
        aPhone.myRid, InnerMessage.hello(newMessageId(), now()));
    await waitUntil(() => holds(bLap, aLap, aPhone),
        what: "Bob's laptop holds Alice's list naming her laptop");
    final w = (
      aPhone: aPhone,
      aLap: aLap,
      bPhone: bPhone,
      bLap: bLap,
      cPhone: cPhone,
    );
    await quiet(everyone(w), what: 'everyone has introduced themselves');
    return w;
  }

  /// A group Alice's phone makes of Bob and Carol, once every device holds
  /// it.
  Future<String> crew(World w) async {
    final gid = await w.aPhone
        .createGroup('Crew', [w.bPhone.myRid, w.cPhone!.myRid]);
    await waitUntil(
        () => [w.aLap, w.bPhone, w.bLap, w.cPhone!]
            .every((s) => s.groups.containsKey(gid)),
        what: 'the group reaches every device');
    await quiet(everyone(w), what: 'the group has settled');
    return gid;
  }

  /// The message with [body] that [svc] holds in [thread], from memory.
  ChatMessage? find(ChatService svc, String thread, String body) {
    for (final m in svc.messagesByChat[thread] ?? const <ChatMessage>[]) {
      if (m.body == body) return m;
    }
    return null;
  }

  /// Waits until every (device, thread) in [at] holds the message with
  /// [body], and returns its id — one id everywhere, chosen by its sender.
  Future<String> everywhere(
      List<(ChatService, String)> at, String body) async {
    String? mid;
    await waitUntil(() {
      for (final (s, thread) in at) {
        final m = find(s, thread, body);
        if (m == null) return false;
        mid ??= m.mid;
      }
      return true;
    }, what: '"$body" reaches every device');
    return mid!;
  }

  /// What [svc]'s screen shows for message [mid] in [thread], read back from
  /// its vault as a chat screen reads it.
  Future<ChatMessage?> shown(ChatService svc, String thread, String mid) async {
    for (final m in await svc.loadMessages(thread)) {
      if (m.mid == mid) return m;
    }
    return null;
  }

  Future<bool> showsEdit(
      ChatService svc, String thread, String mid, String body) async {
    final m = await shown(svc, thread, mid);
    return m != null && m.body == body && m.editedMs > 0;
  }

  /// Each person's reaction to [mid] as [svc] shows it: who → emoji.
  Future<Map<String, String>> reactions(
      ChatService svc, String thread, String mid) async {
    final m = await shown(svc, thread, mid);
    return {for (final r in m?.reactions ?? const []) r.senderRid: r.emoji};
  }

  /// The reaction [svc] shows as its own owner's on [mid], or null.
  Future<String?> mine(ChatService svc, String thread, String mid) async {
    final m = await shown(svc, thread, mid);
    for (final r in m?.reactions ?? const <MessageReaction>[]) {
      if (r.mine) return r.emoji;
    }
    return null;
  }

  Future<int?> status(ChatService svc, String thread, String mid) async =>
      (await shown(svc, thread, mid))?.status;

  Future<Map<String, Object?>?> row(
      ChatService svc, String thread, String mid) async {
    final r = await svc.vault.db.query('messages',
        where: 'rid = ? AND mid = ?', whereArgs: [thread, mid], limit: 1);
    return r.isEmpty ? null : r.first;
  }

  /// The system notices [svc] holds in [thread], as stored: a kind and its
  /// parameters.
  Future<List<Map<String, Object?>>> notices(
      ChatService svc, String thread) async {
    final rows = await svc.vault.db.query('messages',
        columns: ['enc_body'],
        where: "rid = ? AND kind = 'system'",
        whereArgs: [thread],
        orderBy: 'ts_ms ASC');
    final out = <Map<String, Object?>>[];
    for (final r in rows) {
      final body = await svc.vault.unseal(r['enc_body'] as String);
      if (!body.startsWith('{')) continue;
      out.add((jsonDecode(body) as Map).cast<String, Object?>());
    }
    return out;
  }

  test('1. an edit made on any device reaches every device in a chat, and '
      'only its author makes one', () async {
    final w = await world('1');
    final aRid = w.aPhone.myRid, bRid = w.bPhone.myRid;

    // Bob writes on his phone and corrects it on his laptop.
    await w.bPhone.sendText(aRid, 'meet at the statoin');
    final bMid = await everywhere(
        [(w.aPhone, bRid), (w.aLap, bRid), (w.bLap, aRid)],
        'meet at the statoin');
    expect(await w.bLap.editMessage(aRid, bMid, 'meet at the station'),
        isTrue,
        reason: "on Bob's laptop the message is his own");
    for (final (s, thread, who) in [
      (w.aPhone, bRid, "Alice's phone"),
      (w.aLap, bRid, "Alice's laptop"),
      (w.bPhone, aRid, "Bob's own phone"),
    ]) {
      await waitUntil(
          () => showsEdit(s, thread, bMid, 'meet at the station'),
          what: "$who shows the edit Bob's laptop made");
    }

    // Alice writes on her phone and corrects it on her laptop.
    await w.aPhone.sendText(bRid, 'see you at 5');
    final aMid = await everywhere(
        [(w.aLap, bRid), (w.bPhone, aRid), (w.bLap, aRid)], 'see you at 5');
    expect(await w.aLap.editMessage(bRid, aMid, 'see you at 6'), isTrue);
    for (final (s, thread, who) in [
      (w.bPhone, aRid, "Bob's phone"),
      (w.bLap, aRid, "Bob's laptop"),
      (w.aPhone, bRid, "Alice's own phone"),
    ]) {
      await waitUntil(() => showsEdit(s, thread, aMid, 'see you at 6'),
          what: "$who shows the edit Alice's laptop made");
    }

    // The linked doors keep the authorship rule. Bob's laptop, modified,
    // asks Alice's devices to edit HER message — refused, as it is from his
    // phone; and Alice's laptop, modified, mirrors an edit of BOB's message
    // to her phone — her own devices are her, not him.
    await w.bLap.debugSendRawInner(
        aRid,
        InnerMessage.edit(newMessageId(), now(),
            target: aMid, body: 'Bob was here'));
    await w.aLap.debugMirrorToMyDevices(
        threadRid: bRid,
        dir: 'out',
        inner: InnerMessage.edit(newMessageId(), now(),
            target: bMid, body: 'not what Bob said'));
    await quiet(everyone(w), what: 'the forged edits are processed');
    for (final s in [w.aPhone, w.aLap]) {
      expect((await shown(s, bRid, aMid))!.body, 'see you at 6',
          reason: "Bob's laptop cannot edit Alice's message");
    }
    expect((await shown(w.aPhone, bRid, bMid))!.body, 'meet at the station',
        reason: "a mirror from Alice's laptop cannot edit Bob's message");
  }, timeout: const Timeout(Duration(minutes: 5)));

  test("2. in a group a member edits their own message from any of their "
      "devices, everywhere, and never another member's", () async {
    final w = await world('2', carol: true);
    final c = w.cPhone!;
    final aRid = w.aPhone.myRid;
    final gid = await crew(w);

    // Bob writes on his phone and corrects it on his laptop.
    await w.bPhone.sendGroupText(gid, 'lunch at noon');
    final bMid = await everywhere(
        [for (final s in [w.aPhone, w.aLap, w.bLap, c]) (s, gid)],
        'lunch at noon');
    expect(await w.bLap.editMessage(gid, bMid, 'lunch at one'), isTrue);
    for (final s in [w.aPhone, w.aLap, c, w.bPhone]) {
      await waitUntil(() => showsEdit(s, gid, bMid, 'lunch at one'),
          what: "${s.displayName} shows the edit Bob's laptop made");
    }

    // Alice writes on her laptop and corrects it on her phone.
    await w.aLap.sendGroupText(gid, 'I will bring cake');
    final aMid = await everywhere(
        [for (final s in [w.aPhone, w.bPhone, w.bLap, c]) (s, gid)],
        'I will bring cake');
    expect(await w.aPhone.editMessage(gid, aMid, 'I will bring two cakes'),
        isTrue,
        reason: "on Alice's phone her laptop's message is her own");
    for (final s in [w.aLap, w.bPhone, w.bLap, c]) {
      await waitUntil(() => showsEdit(s, gid, aMid, 'I will bring two cakes'),
          what: "${s.displayName} shows the edit Alice's phone made");
    }

    // Carol writes; Bob's laptop, modified, asks everyone to edit HER
    // message. The stored sender is Carol, so nobody does.
    await c.sendGroupText(gid, 'count me in');
    final cMid = await everywhere(
        [for (final s in [w.aPhone, w.aLap, w.bPhone, w.bLap]) (s, gid)],
        'count me in');
    await w.bLap.debugSendRawInner(
        aRid,
        InnerMessage.edit(newMessageId(), now(),
            target: cMid, body: 'count me out', gid: gid));
    await quiet(everyone(w), what: "the forged edit of Carol's is processed");
    for (final s in [w.aPhone, w.aLap]) {
      final m = (await shown(s, gid, cMid))!;
      expect(m.body, 'count me in',
          reason: "Bob's laptop cannot edit Carol's message");
      expect(m.editedMs, 0);
    }
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('3. a reaction made on any device reaches every device as one '
      "person's, and only a member's counts", () async {
    final w = await world('3', carol: true);
    final c = w.cPhone!;
    final aRid = w.aPhone.myRid, bRid = w.bPhone.myRid, cRid = c.myRid;
    final gid = await crew(w);

    // A chat: Bob reacts on his laptop to Alice's message.
    await w.aPhone.sendText(bRid, 'photo?');
    final aMid = await everywhere(
        [(w.aLap, bRid), (w.bPhone, aRid), (w.bLap, aRid)], 'photo?');
    await w.bLap.toggleReaction(aRid, aMid, '👍');
    for (final s in [w.aPhone, w.aLap]) {
      await waitUntil(
          () async => mapEquals(await reactions(s, bRid, aMid), {bRid: '👍'}),
          what: "${s.displayName} shows Bob's reaction from his laptop");
    }
    await waitUntil(() async => await mine(w.bPhone, aRid, aMid) == '👍',
        what: "Bob's phone shows his laptop's reaction as his");
    // From his phone now: it replaces the first, one reaction per person.
    await w.bPhone.toggleReaction(aRid, aMid, '❤️');
    for (final s in [w.aPhone, w.aLap]) {
      await waitUntil(
          () async => mapEquals(await reactions(s, bRid, aMid), {bRid: '❤️'}),
          what: "${s.displayName} shows Bob's one reaction, now from his "
              'phone');
    }
    await waitUntil(() async => await mine(w.bLap, aRid, aMid) == '❤️',
        what: "Bob's laptop shows his phone's reaction as his");

    // A group: Alice reacts on her laptop to Carol's message.
    await c.sendGroupText(gid, 'new group pic');
    final cMid = await everywhere(
        [for (final s in [w.aPhone, w.aLap, w.bPhone, w.bLap]) (s, gid)],
        'new group pic');
    await w.aLap.toggleReaction(gid, cMid, '😂');
    for (final s in [w.bPhone, w.bLap, c]) {
      await waitUntil(
          () async => (await reactions(s, gid, cMid))[aRid] == '😂',
          what: "${s.displayName} shows Alice's reaction from her laptop");
    }
    await waitUntil(() async => await mine(w.aPhone, gid, cMid) == '😂',
        what: "Alice's phone shows her laptop's group reaction as hers");

    // Only a member's counts, and only for a message in the conversation:
    // Bob's laptop, modified, reacts in a group Bob is not in, and to a
    // message of Carol's to Alice.
    final pair = await w.aPhone.createGroup('Pair', [cRid]);
    await waitUntil(
        () => w.aLap.groups.containsKey(pair) && c.groups.containsKey(pair),
        what: 'the second group reaches Alice and Carol');
    await c.sendGroupText(pair, 'just us');
    final pMid =
        await everywhere([(w.aPhone, pair), (w.aLap, pair)], 'just us');
    await c.sendText(aRid, 'between us');
    final dMid = await everywhere(
        [(w.aPhone, cRid), (w.aLap, cRid)], 'between us');
    await w.bLap.debugSendRawInner(
        aRid,
        InnerMessage.reaction(newMessageId(), now(),
            target: pMid, emoji: '👀', gid: pair));
    await w.bLap.debugSendRawInner(aRid,
        InnerMessage.reaction(newMessageId(), now(), target: dMid, emoji: '👀'));
    await quiet(everyone(w), what: "Bob's laptop's forged reactions are "
        'processed');
    for (final s in [w.aPhone, w.aLap]) {
      expect(await reactions(s, pair, pMid), isEmpty,
          reason: 'Bob is not in that group');
      expect(await reactions(s, cRid, dMid), isEmpty,
          reason: "a message of Carol's to Alice is not in Bob's chat");
    }
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('4. a disappearing timer set on any device is set on every device, '
      'and governs what each sends afterwards', () async {
    final w = await world('4');
    final aRid = w.aPhone.myRid, bRid = w.bPhone.myRid;

    // Bob sets it on his laptop.
    await w.bLap.setDisappearingTimer(aRid, 3600);
    for (final (s, thread) in [
      (w.aPhone, bRid),
      (w.aLap, bRid),
      (w.bPhone, aRid),
    ]) {
      await waitUntil(() => s.contacts[thread]!.ttlSec == 3600,
          what: "${s.displayName} takes the timer Bob's laptop set");
    }
    // Each says so as the device it was set on would: Alice's devices as
    // Bob's change, his phone as his own.
    for (final s in [w.aPhone, w.aLap]) {
      expect(
          (await notices(s, bRid))
              .any((n) => n['k'] == 'ttl_set_them' && n['sec'] == 3600),
          isTrue,
          reason: '${s.displayName} says Bob set the timer');
    }
    expect(
        (await notices(w.bPhone, aRid))
            .any((n) => n['k'] == 'ttl_set_you' && n['sec'] == 3600),
        isTrue,
        reason: "Bob's phone says he set it");

    // What Alice's laptop and Bob's phone send now carries it.
    await w.aLap.sendText(bRid, 'from the laptop, for an hour');
    final m1 = await everywhere(
        [(w.aPhone, bRid), (w.bPhone, aRid), (w.bLap, aRid)],
        'from the laptop, for an hour');
    final sent1 = (await row(w.aLap, bRid, m1))!;
    expect((sent1['expire_at_ms'] as int) - (sent1['ts_ms'] as int),
        3600 * 1000,
        reason: "Alice's laptop sends with the timer Bob's laptop set");
    for (final (s, thread) in [
      (w.aPhone, bRid),
      (w.bPhone, aRid),
      (w.bLap, aRid),
    ]) {
      expect((await row(s, thread, m1))!['expire_at_ms'] as int,
          greaterThan(0),
          reason: '${s.displayName} keeps it for an hour, not for ever');
    }
    await w.bPhone.sendText(aRid, 'from the phone, for an hour');
    final m2 = await everywhere(
        [(w.aPhone, bRid), (w.aLap, bRid), (w.bLap, aRid)],
        'from the phone, for an hour');
    final sent2 = (await row(w.bPhone, aRid, m2))!;
    expect((sent2['expire_at_ms'] as int) - (sent2['ts_ms'] as int),
        3600 * 1000,
        reason: "Bob's phone sends with the timer his laptop set");

    // Alice changes it on her phone: her laptop follows, and Bob's devices.
    await w.aPhone.setDisappearingTimer(bRid, 60);
    for (final (s, thread) in [
      (w.aLap, bRid),
      (w.bPhone, aRid),
      (w.bLap, aRid),
    ]) {
      await waitUntil(() => s.contacts[thread]!.ttlSec == 60,
          what: "${s.displayName} takes the timer Alice's phone set");
    }
    await w.aLap.sendText(bRid, 'a minute');
    final m3 = await everywhere([(w.bLap, aRid)], 'a minute');
    final sent3 = (await row(w.aLap, bRid, m3))!;
    expect((sent3['expire_at_ms'] as int) - (sent3['ts_ms'] as int), 60 * 1000,
        reason: "the laptop's next message goes in a minute");
    expect((await row(w.bLap, aRid, m3))!['expire_at_ms'] as int,
        greaterThan(0));

    // A device Alice links now starts with the timer the chat has.
    final desk = await laptopOf(w.aPhone, 'AliceDesk4', [w.bPhone]);
    await waitUntil(() => desk.contacts[bRid]!.ttlSec == 60,
        what: 'the newly linked device starts with the timer');
    await desk.sendText(bRid, 'from the new device');
    final sent4 = desk.messagesByChat[bRid]!
        .lastWhere((m) => m.body == 'from the new device');
    final r4 = (await row(desk, bRid, sent4.mid))!;
    expect((r4['expire_at_ms'] as int) - (r4['ts_ms'] as int), 60 * 1000,
        reason: 'and what it sends carries it');
  }, timeout: const Timeout(Duration(minutes: 6)));

  test('5. read receipts from and to linked devices turn a message read on '
      "every device of its sender", () async {
    final w = await world('5');
    final aRid = w.aPhone.myRid, bRid = w.bPhone.myRid;

    // Alice writes from her phone; Bob reads it on his laptop.
    await w.aPhone.sendText(bRid, 'did you see this?');
    final aMid = await everywhere(
        [(w.aLap, bRid), (w.bPhone, aRid), (w.bLap, aRid)],
        'did you see this?');
    await w.bLap.markChatOpened(aRid);
    w.bLap.markChatClosed(aRid);
    for (final s in [w.aPhone, w.aLap]) {
      await waitUntil(() async => await status(s, bRid, aMid) == MsgStatus.read,
          what: '${s.displayName} shows it read on Bob\'s laptop');
    }

    // Bob writes from his phone; Alice reads it on her laptop.
    await w.bPhone.sendText(aRid, 'yes, just now');
    final bMid = await everywhere(
        [(w.aPhone, bRid), (w.aLap, bRid), (w.bLap, aRid)], 'yes, just now');
    await w.aLap.markChatOpened(bRid);
    w.aLap.markChatClosed(bRid);
    for (final s in [w.bPhone, w.bLap]) {
      await waitUntil(() async => await status(s, aRid, bMid) == MsgStatus.read,
          what: "${s.displayName} shows it read on Alice's laptop");
    }

    // Laptop to laptop: Bob writes on his, Alice reads on hers.
    await w.bLap.sendText(aRid, 'from my laptop');
    final lMid = await everywhere(
        [(w.aPhone, bRid), (w.aLap, bRid), (w.bPhone, aRid)],
        'from my laptop');
    await w.aLap.markChatOpened(bRid);
    w.aLap.markChatClosed(bRid);
    for (final s in [w.bLap, w.bPhone]) {
      await waitUntil(() async => await status(s, aRid, lMid) == MsgStatus.read,
          what: "${s.displayName} shows the laptop's message read");
    }
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('6. what I read on one of my devices is read on the others, and stays '
      'read', () async {
    final w = await world('6', carol: true);
    final c = w.cPhone!;
    final aRid = w.aPhone.myRid, bRid = w.bPhone.myRid;
    final gid = await crew(w);
    // Every read receipt Alice's devices send, as Bob's and Carol's devices
    // receive it.
    var fromPhone = 0, fromLaptop = 0;
    for (final s in [w.bPhone, w.bLap, c]) {
      s.debugOnDecrypted = (path, from, dec) {
        if (kindOf(dec) == 'read') {
          if (from == aRid) fromPhone++;
          if (from == w.aLap.myRid) fromLaptop++;
        }
        return false;
      };
    }

    // Bob writes twice from his phone and once from his laptop, and Carol
    // twice in the group: unread on both of Alice's devices, the laptop's
    // message as much as the phone's.
    for (var i = 0; i < 2; i++) {
      await w.bPhone.sendText(aRid, 'unread $i');
    }
    await w.bLap.sendText(aRid, 'unread from the laptop');
    for (var i = 0; i < 2; i++) {
      await c.sendGroupText(gid, 'group $i');
    }
    for (final s in [w.aPhone, w.aLap]) {
      await waitUntil(() => s.unread[bRid] == 3 && s.unread[gid] == 2,
          what: '${s.displayName} counts them unread');
    }
    // And still so once every copy has landed: each of Alice's devices holds
    // Carol's group messages twice over — from Carol, and mirrored by the
    // other device — and counts each once.
    await quiet(everyone(w), what: 'every copy has arrived');
    for (final s in [w.aPhone, w.aLap]) {
      expect(s.unread[bRid], 3, reason: '${s.displayName}: three from Bob');
      expect(s.unread[gid], 2,
          reason: '${s.displayName}: two from Carol, each counted once');
    }

    // Alice reads both on her laptop.
    await w.aLap.markChatOpened(bRid);
    w.aLap.markChatClosed(bRid);
    await w.aLap.markChatOpened(gid);
    w.aLap.markChatClosed(gid);
    await waitUntil(() => w.aPhone.unread[bRid] == 0,
        what: "her phone counts the chat read");
    await waitUntil(() => w.aPhone.unread[gid] == 0,
        what: 'and the group');
    final last = find(w.aPhone, bRid, 'unread 1')!.mid;
    final fromLap = find(w.aPhone, bRid, 'unread from the laptop')!.mid;
    await waitUntil(
        () async =>
            await status(w.bPhone, aRid, last) == MsgStatus.read &&
            await status(w.bLap, aRid, fromLap) == MsgStatus.read,
        what: "Bob sees his messages read, from Alice's laptop");

    // Her phone, opening the chat, has nothing left to say.
    await w.aPhone.markChatOpened(bRid);
    w.aPhone.markChatClosed(bRid);
    await w.aPhone.markChatOpened(gid);
    w.aPhone.markChatClosed(gid);
    await quiet(everyone(w), what: 'the reads have settled');
    expect(fromLaptop, greaterThan(0),
        reason: "the probe sees receipts: her laptop's reached Bob");
    expect(fromPhone, 0,
        reason: "her phone sends no receipt for what her laptop read");

    // And after a restart the counts are what they were.
    await stop(w.aPhone);
    final again = await start('Alice6');
    expect(again.unread[bRid], 0, reason: 'the chat is still read');
    expect(again.unread[gid], 0, reason: 'and so is the group');
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('7. delivery receipts from and to linked devices count', () async {
    final w = await world('7', carol: true);
    final c = w.cPhone!;
    final aRid = w.aPhone.myRid, bRid = w.bPhone.myRid, cRid = c.myRid;
    final gid = await crew(w);

    // Alice writes from her laptop, in a chat and in the group: delivered on
    // the laptop and on her phone's copy.
    await w.aLap.sendText(bRid, 'sent from the laptop');
    final lMid = await everywhere(
        [(w.aPhone, bRid), (w.bPhone, aRid), (w.bLap, aRid)],
        'sent from the laptop');
    await w.aLap.sendGroupText(gid, 'group, from the laptop');
    final glMid = await everywhere(
        [for (final s in [w.aPhone, w.bPhone, w.bLap, c]) (s, gid)],
        'group, from the laptop');
    for (final (s, thread, mid) in [
      (w.aLap, bRid, lMid),
      (w.aPhone, bRid, lMid),
      (w.aLap, gid, glMid),
      (w.aPhone, gid, glMid),
    ]) {
      await waitUntil(
          () async => (await status(s, thread, mid) ?? 0) >= MsgStatus.delivered,
          what: '${s.displayName} marks the laptop\'s message delivered');
    }

    // Bob's phone is away: his laptop alone answers for him.
    await w.bPhone.transport.stop();
    await w.aPhone.sendText(bRid, 'while your phone is off');
    final pMid = await everywhere(
        [(w.aLap, bRid), (w.bLap, aRid)], 'while your phone is off');
    await w.aPhone.sendGroupText(gid, 'group, while your phone is off');
    final gMid = await everywhere(
        [for (final s in [w.aLap, w.bLap, c]) (s, gid)],
        'group, while your phone is off');
    for (final s in [w.aPhone, w.aLap]) {
      await waitUntil(
          () async => (await status(s, bRid, pMid) ?? 0) >= MsgStatus.delivered,
          what: "${s.displayName} marks it delivered by Bob's laptop");
      await waitUntil(
          () async => (await status(s, gid, gMid) ?? 0) >= MsgStatus.delivered,
          what: '${s.displayName} marks the group message delivered');
    }
    // Each member once: Bob's laptop answered for Bob.
    final who = await w.aPhone.vault.db.rawQuery(
        'SELECT DISTINCT from_rid FROM delivery WHERE mid = ? AND thread_rid = ?',
        [gMid, gid]);
    expect({for (final r in who) r['from_rid'] as String}, {bRid, cRid});

    w.bPhone.transport.start();
    await waitUntil(() => w.bPhone.transport.isConnected,
        what: "Bob's phone is back");
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('8. a mirror that cannot be applied is acknowledged, and the next one '
      'arrives', () async {
    final w = await world('8');
    final aRid = w.aPhone.myRid, bRid = w.bPhone.myRid;
    await w.bPhone.sendText(aRid, 'from Bob');
    final bMid = await everywhere(
        [(w.aPhone, bRid), (w.aLap, bRid)], 'from Bob');

    // From Alice's laptop, modified, to her phone: an edit naming nothing,
    // an edit of Bob's message, a reaction in a group nobody holds, a timer
    // for a chat she does not have, a read naming nothing — and a leave
    // whose group id is not a string, which the phone cannot even read.
    const nowhere = 'gAAAAAAAAAAAAAAAA';
    final stranger = await (await ZIdentity.generate()).routingId();
    final mirrors = <(String, InnerMessage)>[
      (bRid, InnerMessage.edit(newMessageId(), now(),
          target: newMessageId(), body: 'nothing')),
      (bRid, InnerMessage.edit(newMessageId(), now(),
          target: bMid, body: 'not hers')),
      (nowhere, InnerMessage.reaction(newMessageId(), now(),
          target: bMid, emoji: '👍', gid: nowhere)),
      (stranger, InnerMessage.timer(newMessageId(), now(), 60)),
      (bRid, InnerMessage.read(newMessageId(), now(), [newMessageId()])),
      ('', InnerMessage(
          kind: 'gleave', mid: newMessageId(), ts: now(), data: {'gid': 5})),
    ];
    for (final (thread, inner) in mirrors) {
      await w.aLap.debugMirrorToMyDevices(
          threadRid: thread, dir: 'out', inner: inner);
    }
    await quiet(everyone(w),
        what: 'every mirror is acknowledged: nothing waits at the relay');
    final m = (await shown(w.aPhone, bRid, bMid))!;
    expect(m.body, 'from Bob');
    expect(m.editedMs, 0);
    expect(w.aPhone.contacts[bRid]!.ttlSec, 0);

    // And the channel goes on.
    await w.aLap.sendText(bRid, 'still in sync');
    await everywhere([(w.aPhone, bRid)], 'still in sync');
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('9. what was done while a device was away arrives in order when it '
      'comes back', () async {
    final w = await world('9');
    final aRid = w.aPhone.myRid, bRid = w.bPhone.myRid;
    await w.bPhone.sendText(aRid, 'are you there?');
    final q = await everywhere(
        [(w.aPhone, bRid), (w.aLap, bRid), (w.bLap, aRid)], 'are you there?');
    await quiet(everyone(w), what: 'nothing in flight');
    Future<void> handedOver(ChatService s) => waitUntil(
        () async => (await s.vault.db.query('outbox', limit: 1)).isEmpty,
        what: "${s.displayName}'s backlog is at the relay");

    // Alice's laptop is away while her phone writes, corrects it, reacts,
    // sets a timer and reads Bob's message: five mirrors wait for it at the
    // relay, and arrive together.
    await w.aLap.transport.stop();
    await w.aPhone.sendText(bRid, 'on my way');
    final mid = find(w.aPhone, bRid, 'on my way')!.mid;
    expect(await w.aPhone.editMessage(bRid, mid, 'on my way, ten minutes'),
        isTrue);
    await w.aPhone.toggleReaction(bRid, q, '👍');
    await w.aPhone.setDisappearingTimer(bRid, 300);
    await w.aPhone.markChatOpened(bRid);
    w.aPhone.markChatClosed(bRid);
    await handedOver(w.aPhone);
    w.aLap.transport.start();
    await waitUntil(
        () => showsEdit(w.aLap, bRid, mid, 'on my way, ten minutes'),
        what: "the laptop shows the phone's edit");
    await waitUntil(() async => await mine(w.aLap, bRid, q) == '👍',
        what: "the laptop shows the phone's reaction");
    await waitUntil(() => w.aLap.contacts[bRid]!.ttlSec == 300,
        what: "the laptop takes the phone's timer");
    await waitUntil(() => w.aLap.unread[bRid] == 0,
        what: 'the laptop counts what the phone read as read');

    // Both of Bob's devices are away while Alice's laptop does the same:
    // what reaches them comes by the extra-device door, in one burst.
    await w.bPhone.transport.stop();
    await w.bLap.transport.stop();
    await w.aLap.sendText(bRid, 'from the laptop');
    final lmid = find(w.aLap, bRid, 'from the laptop')!.mid;
    expect(await w.aLap.editMessage(bRid, lmid, 'from the laptop, edited'),
        isTrue);
    await w.aLap.toggleReaction(bRid, q, '❤️');
    await w.aLap.setDisappearingTimer(bRid, 600);
    await handedOver(w.aLap);
    w.bPhone.transport.start();
    w.bLap.transport.start();
    for (final s in [w.bPhone, w.bLap]) {
      await waitUntil(
          () => showsEdit(s, aRid, lmid, 'from the laptop, edited'),
          what: "${s.displayName} shows the edit Alice's laptop made");
      await waitUntil(
          () async => (await reactions(s, aRid, q))[aRid] == '❤️',
          what: "${s.displayName} shows Alice's one reaction, from her "
              'laptop');
      await waitUntil(() => s.contacts[aRid]!.ttlSec == 600,
          what: "${s.displayName} takes the timer Alice's laptop set");
    }
  }, timeout: const Timeout(Duration(minutes: 5)));
}
