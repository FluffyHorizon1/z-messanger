// An attachment belongs to the person who sent it (30.1).
//
// A file id is chosen by whoever sends the offer (PROTOCOL §7) and every
// member of a group sees every member's ids. The receiver used to key
// attachments by that id alone: an offer naming an id it already held was
// stored as a message pointing at somebody else's file, a delete of that
// message destroyed the file it pointed at, and the id was then free for a
// re-offer — so a co-member could delete Alice's attachment on Bob's device
// and put their own bytes under Alice's name, with no race at all. The
// receiver also believed whatever size and chunk count an offer declared.
//
// Three REAL ChatService instances (Alice, Bob, Mallory) over the REAL Node
// relay, in a shared group and in 1:1 chats; Mallory is a member running a
// modified client, so her hostile offers and deletes are built by hand and
// sent through her real ratchet, and her chunks through a raw relay socket.
//
// Criteria, each a test below:
//   1. Mallory's re-offer of Alice's file id in the group is refused: no
//      message, no placeholder, and Alice's message still shows Alice's
//      file, under Alice's name;
//   2. Mallory's delete of Alice's file id — an offer of her own naming it,
//      a delete of that offer, a re-offer with her own bytes — leaves
//      Alice's attachment on Bob's device, and Alice's message never shows
//      Mallory's bytes;
//   3. the same through a 1:1 chat: a contact who learned the id in a group
//      can neither show it in their own chat nor delete it from there;
//   4. Alice can still delete her own attachment for everyone, in the group
//      and in a 1:1 chat: the row, the blob and its chunks go, the message
//      stays as a tombstone;
//   5. a linked device of Alice's deleting Alice's attachment works and is
//      Alice's doing: Bob and Mallory remove it, so does Alice's own phone,
//      and the same laptop cannot delete Mallory's attachment;
//   6. backup and restore keep ownership: every attachment comes back on its
//      own message, and the restored device refuses the same attacks;
//   7. an existing vault — rows written the way earlier builds wrote them,
//      including what the attack left behind in one — opened by this build
//      keeps every attachment, shows none under the wrong message, and
//      refuses Mallory's delete of Alice's file;
//   8. an offer declaring more than the 24 MiB product limit, or a chunk
//      count its size does not imply, is refused;
//   9. a chunk outside the declared range, or carrying more or fewer bytes
//      than its index's share of the declared size, is not stored: nothing
//      assembles beyond the declared size, and a bad chunk cannot spoil a
//      good file;
//  10. a 1,000,000-chunk offer is refused, and what arrives for it is held
//      only as any unexplained chunk is (bounded); the process's RSS is
//      measured before, during and after and printed;
//  11. a reply quoting an attachment arrives quoting it, and the chat goes
//      on: the attachment lookup the quote makes runs inside the transaction
//      storing the reply, and used to wait on that transaction for ever.
@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/archive.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/models.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';

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
      await Directory.systemTemp.createTemp('z_own_').then((d) {
        temps.add(d);
        return dirs[name] = d;
      });

  /// A client named [name]; the same name again reopens the same vault.
  Future<ChatService> start(String name, {ZIdentity? identity}) async {
    final vault = await Vault.open(rootOverride: await dirFor(name));
    final stored = await vault.kvGet('identity');
    final id = identity ??
        (stored == null
            ? await ZIdentity.generate()
            : await ZIdentity.fromJson(
                (jsonDecode(stored) as Map).cast<String, Object?>()));
    if (stored == null) await vault.kvPut('identity', jsonEncode(id.toJson()));
    final svc = await ChatService.init(
        vault: vault,
        identity: id,
        displayName: name,
        transport: Transport(identity: id, serverUrl: 'ws://127.0.0.1:$port'));
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
      {Duration timeout = const Duration(seconds: 30),
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
    // METRICS_TOKEN set to this value above. A refused scrape fails loudly
    // rather than reading as a relay that never empties.
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

  /// Nothing left anywhere: no client has an envelope or a group fan-out
  /// row still to send, and the relay holds nothing undelivered — which, for
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

  /// Alice, Bob and Mallory: each a contact of the other two, and a group of
  /// all three that Alice made.
  Future<(ChatService, ChatService, ChatService, String)> trio(
      String tag) async {
    final alice = await start('Alice$tag');
    final bob = await start('Bob$tag');
    final mallory = await start('Mallory$tag');
    final all = [alice, bob, mallory];
    await waitUntil(() => all.every((s) => s.transport.isConnected),
        what: 'everyone connects');
    await befriend(alice, bob);
    await befriend(alice, mallory);
    await befriend(bob, mallory);
    await settled(all);
    final gid =
        await alice.createGroup('Crew', [bob.myRid, mallory.myRid]);
    await waitUntil(
        () => bob.groups.containsKey(gid) && mallory.groups.containsKey(gid),
        what: 'the group reaches Bob and Mallory');
    return (alice, bob, mallory, gid);
  }

  Uint8List pattern(int n, int seed) =>
      Uint8List.fromList(List<int>.generate(n, (i) => (i * seed + 7) % 251));

  /// The message called [name] in [svc]'s copy of [thread], from memory.
  ChatMessage? named(ChatService svc, String thread, String name) {
    for (final m in svc.messagesByChat[thread] ?? const <ChatMessage>[]) {
      if (m.kind == 'file' && m.body == name) return m;
    }
    return null;
  }

  /// Read back from the vault as a screen reads it: what message [mid] in
  /// [thread] shows as its attachment — null when it shows none, or one that
  /// cannot be opened.
  Future<Uint8List?> shown(ChatService svc, String thread, String mid) async {
    final list = await svc.loadMessages(thread);
    ChatMessage? m;
    for (final x in list) {
      if (x.mid == mid) m = x;
    }
    final f = m?.file;
    if (m == null || m.deleted || f == null || !f.complete) return null;
    try {
      return await svc.readAttachment(f.fid);
    } catch (_) {
      return null;
    }
  }

  /// Waits until [svc] has assembled the attachment called [name] in
  /// [thread]; returns its message.
  Future<ChatMessage> arrived(ChatService svc, String thread, String name,
      Uint8List bytes) async {
    late ChatMessage m;
    await waitUntil(() async {
      final x = named(svc, thread, name);
      final fid = x?.fid;
      if (x == null || fid == null) return false;
      try {
        if (!_same(await svc.readAttachment(fid), bytes)) return false;
      } catch (_) {
        return false;
      }
      m = x;
      return true;
    }, what: '${svc.displayName} assembles $name');
    return m;
  }

  /// Mallory's half of an attack: an offer under [fid] for HER bytes, with
  /// her own key, in the group [gid] or (null) a 1:1 chat — and the chunks
  /// that complete it, which travel outside the ratchet.
  Future<(InnerMessage, List<String>)> forged(String fid, Uint8List bytes,
      {String? gid, String name = 'mallory.bin'}) async {
    final km = FileKeyMaterial(fid: fid, fk: randomBytes(32), fn: randomBytes(16));
    final parts = splitChunks(bytes);
    final chunks = <String>[
      for (var i = 0; i < parts.length; i++) await encryptChunk(km, i, parts[i])
    ];
    final offer = InnerMessage(
        kind: gid == null ? 'file' : 'gfile',
        mid: newMessageId(),
        ts: DateTime.now().millisecondsSinceEpoch,
        data: {
          if (gid != null) 'gid': gid,
          'fid': fid,
          'name': name,
          'size': bytes.length,
          'mime': 'application/octet-stream',
          'sha256': b64(await sha256Bytes(bytes)),
          'fk': b64(km.fk),
          'fn': b64(km.fn),
          'chunks': parts.length,
        });
    return (offer, chunks);
  }

  /// Chunk envelopes straight into [to]'s mailbox, as anybody can send them:
  /// sealed, on a connection that never authenticated, the way a client
  /// sends its own — so no relay receipt is queued for a sender that is
  /// gone, and the relay's queue empties once [to] has decided on each.
  Future<void> post(ChatService to, List<String> payloads) async {
    final c = await RelayClient.connectAnonymous(
        'ws://127.0.0.1:$port', await ZIdentity.generate());
    for (final p in payloads) {
      await c.send(
          to: to.myRid,
          id: newMessageId(),
          payload: await SealedEnvelope.seal(
              toXPub: to.identity.xPub, fromRid: newMessageId(), payload: p));
    }
    await c.close();
  }

  InnerMessage del(List<String> mids, {String? gid}) =>
      InnerMessage.deleteForEveryone(
          newMessageId(), DateTime.now().millisecondsSinceEpoch,
          targets: mids, gid: gid);

  Future<List<Map<String, Object?>>> rowsFor(ChatService s, String fid) =>
      s.vault.db.query('files', where: 'fid = ?', whereArgs: [fid]);

  Future<bool> hasMessage(ChatService s, String thread, String mid) async =>
      (await s.vault.db.query('messages',
              where: 'rid = ? AND mid = ?', whereArgs: [thread, mid]))
          .isNotEmpty;

  /// Link a laptop to [main]'s account (as group_roles_sync_test links one).
  Future<ChatService> link(ChatService main, String name) async {
    final devId = await ZIdentity.generate();
    final account = await main.accountIdentity();
    final cert = await account.signDeviceCert(
        deviceEdPub: devId.edPub, deviceXPub: devId.xPub, deviceId: name);
    final vault = await Vault.open(rootOverride: await dirFor(name));
    await vault.kvPut('identity', jsonEncode(devId.toJson()));
    final enrolled = await AccountIdentity.fromEnrollment(
      accountEdPub: account.accountEdPub,
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
            Transport(identity: devId, serverUrl: 'ws://127.0.0.1:$port'));
    live.add(svc);
    await waitUntil(() => svc.transport.isConnected, what: '$name connects');
    await main.addMyDevice(cert);
    return svc;
  }

  test('1. a re-offer of somebody else\'s file id is refused', () async {
    final (alice, bob, mallory, gid) = await trio('1');
    final a = pattern(300000, 13); // three chunks
    await alice.sendGroupFile(gid, 'alice.png', a, 'image/png');
    final atBob = await arrived(bob, gid, 'alice.png', a);
    final fid = (await arrived(mallory, gid, 'alice.png', a)).fid!;
    expect(atBob.senderName, 'Alice1');

    // Mallory read Alice's id off her own copy, and offers it back as hers.
    final (offer, chunks) = await forged(fid, pattern(5000, 3), gid: gid);
    await mallory.debugSendRawInner(bob.myRid, offer);
    await post(bob, chunks);
    await quiet([alice, bob, mallory], what: "Bob has processed Mallory's offer");

    expect(await hasMessage(bob, gid, offer.mid), isFalse,
        reason: 'the offer is refused: no message and no placeholder');
    expect(await rowsFor(bob, fid), hasLength(1));
    expect((await rowsFor(bob, fid)).single['mid'], atBob.mid,
        reason: "the id is still Alice's message's");
    expect(await shown(bob, gid, atBob.mid), equals(a),
        reason: "Alice's message still shows Alice's file");
    expect(named(bob, gid, 'alice.png')?.senderName, 'Alice1');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('2. a co-member cannot delete, then replace, another\'s attachment',
      () async {
    final (alice, bob, mallory, gid) = await trio('2');
    final a = pattern(200000, 17);
    await alice.sendGroupFile(gid, 'alice.png', a, 'image/png');
    final atBob = await arrived(bob, gid, 'alice.png', a);
    final fid = (await arrived(mallory, gid, 'alice.png', a)).fid!;

    // The chain that needs no race: a message of her own that names Alice's
    // id, a delete of that message (hers, so the authorship rule allows it),
    // and the id offered again — free now, on a build that deleted by id.
    final (decoy, _) = await forged(fid, pattern(4000, 5), gid: gid);
    await mallory.debugSendRawInner(bob.myRid, decoy);
    await quiet([alice, bob, mallory], what: 'the decoy offer is processed');
    final delete = del([decoy.mid], gid: gid);
    await mallory.debugSendRawInner(bob.myRid, delete);
    await quiet([alice, bob, mallory], what: 'the delete is processed');
    final evil = pattern(6000, 11);
    final (swap, chunks) = await forged(fid, evil, gid: gid);
    await mallory.debugSendRawInner(bob.myRid, swap);
    await post(bob, chunks);
    await quiet([alice, bob, mallory], what: 'the swap is processed');

    // What Bob's screen opens for Alice's message: the file id it was shown
    // with, read as the screen reads it.
    expect(await bob.readAttachment(atBob.fid!), equals(a),
        reason: "Alice's message opens Alice's file, not Mallory's");
    expect((await rowsFor(bob, fid)).single['mid'], atBob.mid,
        reason: "the id is still held for Alice's message");
    expect(File('${bob.vault.filesDir.path}/$fid.bin').existsSync(), isTrue);
    expect(await shown(bob, gid, atBob.mid), equals(a),
        reason: "Alice's attachment is still on Bob's device, byte for byte");
    expect(await shown(bob, gid, swap.mid), isNull);
    for (final m in await bob.loadMessages(gid)) {
      if (m.file == null || m.mid == atBob.mid) continue;
      expect(await shown(bob, gid, m.mid), isNot(equals(a)),
          reason: "no other message shows Alice's file");
    }
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('3. nor through a 1:1 chat', () async {
    final (alice, bob, mallory, gid) = await trio('3');
    final a = pattern(150000, 19);
    await alice.sendGroupFile(gid, 'alice.png', a, 'image/png');
    final atBob = await arrived(bob, gid, 'alice.png', a);
    final fid = (await arrived(mallory, gid, 'alice.png', a)).fid!;

    // In her own chat with Bob: the id learned in the group, offered as a
    // file of hers, then deleted "for everyone".
    final (offer, chunks) = await forged(fid, pattern(3000, 23));
    await mallory.debugSendRawInner(bob.myRid, offer);
    await post(bob, chunks);
    await quiet([alice, bob, mallory], what: 'the 1:1 offer is processed');
    expect(await hasMessage(bob, mallory.myRid, offer.mid), isFalse,
        reason: 'an id held in another chat is refused in this one');
    expect(await shown(bob, mallory.myRid, offer.mid), isNull,
        reason: "Alice's group file never appears in Mallory's chat");

    await mallory.debugSendRawInner(bob.myRid, del([offer.mid]));
    await quiet([alice, bob, mallory], what: 'the 1:1 delete is processed');
    expect(await shown(bob, gid, atBob.mid), equals(a),
        reason: "Alice's group attachment survives a delete sent from a "
            '1:1 chat');
    expect(await rowsFor(bob, fid), hasLength(1));
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('4. Alice can still delete her own, in a group and in a 1:1 chat',
      () async {
    final (alice, bob, mallory, gid) = await trio('4');
    final g = pattern(160000, 29);
    final d = pattern(9000, 31);
    await alice.sendGroupFile(gid, 'group.png', g, 'image/png');
    await alice.sendFile(bob.myRid, 'direct.pdf', d, 'application/pdf');
    final inGroup = await arrived(bob, gid, 'group.png', g);
    final direct = await arrived(bob, alice.myRid, 'direct.pdf', d);
    await arrived(mallory, gid, 'group.png', g);

    await alice.deleteForEveryone(gid, [inGroup.mid]);
    await alice.deleteForEveryone(bob.myRid, [direct.mid]);
    await waitUntil(
        () async =>
            (await rowsFor(bob, inGroup.fid!)).isEmpty &&
            (await rowsFor(bob, direct.fid!)).isEmpty &&
            (await rowsFor(mallory, inGroup.fid!)).isEmpty,
        what: "Alice's deletes reach Bob and Mallory");
    for (final (thread, m) in [(gid, inGroup), (alice.myRid, direct)]) {
      expect(await hasMessage(bob, thread, m.mid), isTrue,
          reason: 'the message stays, as a tombstone');
      expect((await bob.loadMessages(thread))
          .firstWhere((x) => x.mid == m.mid)
          .deleted, isTrue);
      expect(File('${bob.vault.filesDir.path}/${m.fid}.bin').existsSync(),
          isFalse,
          reason: 'the blob goes with it');
      expect(
          await bob.vault.db
              .query('chunks', where: 'fid = ?', whereArgs: [m.fid]),
          isEmpty);
    }
  }, timeout: const Timeout(Duration(minutes: 3)));

  test("5. Alice's laptop deleting Alice's attachment is Alice deleting it",
      () async {
    final alice = await start('Alice5');
    final bob = await start('Bob5');
    final mallory = await start('Mallory5');
    final all = [alice, bob, mallory];
    await waitUntil(() => all.every((s) => s.transport.isConnected),
        what: 'everyone connects');
    await befriend(alice, bob);
    await befriend(alice, mallory);
    await befriend(bob, mallory);
    await settled(all);
    final laptop = await link(alice, 'AliceLaptop5');
    await waitUntil(
        () async =>
            await bob.heldContactListVersion(alice.myRid) >= 1 &&
            await mallory.heldContactListVersion(alice.myRid) >= 1,
        what: "Bob and Mallory hold Alice's device list, laptop included");
    final gid = await alice.createGroup('Crew', [bob.myRid, mallory.myRid]);
    await waitUntil(
        () => [bob, mallory, laptop].every((s) => s.groups.containsKey(gid)),
        what: "the group reaches Bob, Mallory and Alice's laptop");

    // Alice sends from her phone; Mallory sends one of her own.
    final a = pattern(200000, 37);
    final m = pattern(7000, 41);
    await alice.sendGroupFile(gid, 'alice.png', a, 'image/png');
    await mallory.sendGroupFile(gid, 'mallory.png', m, 'image/png');
    final atBob = await arrived(bob, gid, 'alice.png', a);
    await arrived(mallory, gid, 'alice.png', a);
    final onLaptop = await arrived(laptop, gid, 'alice.png', a);
    final mallorysAtBob = await arrived(bob, gid, 'mallory.png', m);
    expect(onLaptop.outgoing, isTrue, reason: "on her laptop it is her own");

    // From the laptop: everyone removes it, credited to Alice's account.
    await laptop.deleteForEveryone(gid, [onLaptop.mid]);
    await waitUntil(
        () async =>
            (await rowsFor(bob, atBob.fid!)).isEmpty &&
            (await rowsFor(mallory, atBob.fid!)).isEmpty,
        what: "the laptop's delete removes Alice's file at Bob and Mallory");
    await waitUntil(() async => (await rowsFor(alice, atBob.fid!)).isEmpty,
        what: "and on Alice's own phone, which is Alice too");
    expect((await bob.loadMessages(gid))
        .firstWhere((x) => x.mid == atBob.mid)
        .deleted, isTrue);

    // The same laptop cannot delete Mallory's: it is Alice, not Mallory.
    await laptop.debugSendRawInner(
        bob.myRid, del([mallorysAtBob.mid], gid: gid));
    await quiet([alice, bob, mallory, laptop],
        what: "Bob has processed the laptop's delete of Mallory's file");
    expect(await shown(bob, gid, mallorysAtBob.mid), equals(m),
        reason: "Alice's device cannot delete Mallory's attachment");
  }, timeout: const Timeout(Duration(minutes: 4)));

  test('6. backup and restore keep every attachment on its own message',
      () async {
    final (alice, bob, mallory, gid) = await trio('6');
    final a = pattern(180000, 43);
    final m = pattern(6000, 47);
    final d = pattern(12000, 53);
    await alice.sendGroupFile(gid, 'alice.png', a, 'image/png');
    await mallory.sendGroupFile(gid, 'mallory.png', m, 'image/png');
    await alice.sendFile(bob.myRid, 'direct.pdf', d, 'application/pdf');
    final aMsg = await arrived(bob, gid, 'alice.png', a);
    final mMsg = await arrived(bob, gid, 'mallory.png', m);
    final dMsg = await arrived(bob, alice.myRid, 'direct.pdf', d);
    final fid = (await arrived(mallory, gid, 'alice.png', a)).fid!;
    await quiet([alice, bob, mallory], what: 'nothing in flight for Bob');

    final code = await RecoveryCode.generate();
    final archive = File('${(await dirFor('archive6')).path}/bob.zbk');
    final sink = archive.openWrite();
    await BackupArchive.export(vault: bob.vault, code: code, out: sink);
    await sink.close();
    final bobId = bob.identity;
    final bobDir = await dirFor('Bob6');
    await stop(bob);
    bobDir.deleteSync(recursive: true);
    bobDir.createSync(recursive: true);
    final fresh = await Vault.open(rootOverride: bobDir);
    final summary =
        await BackupArchive.import(vault: fresh, file: archive, code: code);
    expect(summary.attachments, 3);
    await fresh.db.close();
    final revived = await start('Bob6', identity: bobId);
    await waitUntil(() => revived.transport.isConnected,
        what: 'the restored device connects');

    expect(await shown(revived, gid, aMsg.mid), equals(a));
    expect(await shown(revived, gid, mMsg.mid), equals(m));
    expect(await shown(revived, alice.myRid, dMsg.mid), equals(d));
    expect((await rowsFor(revived, fid)).single['mid'], aMsg.mid);

    // The restored device talks first, so Mallory follows it onto the new
    // session — and then tries the whole attack again.
    await revived.sendText(mallory.myRid, 'back on a new phone');
    await waitUntil(
        () => (mallory.messagesByChat[revived.myRid] ?? const <ChatMessage>[])
            .any((x) => x.body == 'back on a new phone'),
        what: 'Mallory hears from the restored device');
    final (decoy, _) = await forged(fid, pattern(4000, 59), gid: gid);
    await mallory.debugSendRawInner(revived.myRid, decoy);
    await mallory.debugSendRawInner(revived.myRid, del([decoy.mid], gid: gid));
    final (swap, chunks) = await forged(fid, pattern(5000, 61), gid: gid);
    await mallory.debugSendRawInner(revived.myRid, swap);
    await post(revived, chunks);
    await quiet([alice, revived, mallory],
        what: 'the restored device has processed the attack');
    expect(await hasMessage(revived, gid, decoy.mid), isFalse);
    expect(await hasMessage(revived, gid, swap.mid), isFalse);
    expect(await shown(revived, gid, aMsg.mid), equals(a),
        reason: "after a restore, Alice's file is still Alice's");
  }, timeout: const Timeout(Duration(minutes: 4)));

  test('7. an existing vault keeps its attachments and is protected',
      () async {
    final (alice, bob, mallory, gid) = await trio('7');
    final a1 = pattern(150000, 67);
    final a2 = pattern(8000, 71);
    await alice.sendGroupFile(gid, 'first.png', a1, 'image/png');
    await alice.sendGroupFile(gid, 'second.png', a2, 'image/png');
    final first = await arrived(bob, gid, 'first.png', a1);
    final second = await arrived(bob, gid, 'second.png', a2);
    await quiet([alice, bob, mallory], what: 'nothing in flight for Bob');

    // Rows exactly as an earlier build wrote them after Mallory's offers.
    //   * `pointer`: her offer naming Alice's FIRST id — the message row was
    //     stored, the `files` insert ignored, so the row points at Alice's.
    //   * `replaced`: the delete-then-reoffer chain already run against the
    //     SECOND: Alice's row and blob are gone, and the id is held by
    //     Mallory's re-offer, with her bytes. (Her decoy's tombstone is left
    //     out: it names no id, and an earlier build cannot load a thread that
    //     holds a tombstoned attachment at all — criterion 4 — which would
    //     hide what this criterion is about.)
    final v = bob.vault;
    final now = DateTime.now().millisecondsSinceEpoch;
    Future<void> row(String mid, String fid) async {
      await v.db.insert('messages', {
        'mid': mid,
        'rid': gid,
        'outgoing': 0,
        'kind': 'file',
        'enc_body': await v.seal(
            jsonEncode({'fid': fid, 'sn': 'Mallory7', 'sr': mallory.myRid})),
        'fid': fid,
        'ts_ms': now,
        'status': MsgStatus.delivered,
        'expire_at_ms': 0,
      });
    }
    final pointer = newMessageId();
    await row(pointer, first.fid!);
    await v.deleteBlob(second.fid!);
    await v.db.delete('files', where: 'fid = ?', whereArgs: [second.fid]);
    final evil = pattern(5000, 73);
    final replaced = newMessageId();
    await row(replaced, second.fid!);
    final keyInfo = await v.writeBlob(second.fid!, evil);
    await v.db.insert('files', {
      'fid': second.fid,
      'rid': gid,
      'mid': replaced,
      'enc_meta': await v.seal(jsonEncode({
        'name': 'evil.png',
        'size': evil.length,
        'mime': 'image/png',
        'sha256': b64(await sha256Bytes(evil)),
        'local': keyInfo,
      })),
      'complete': 1,
      'got_chunks': 1,
      'total_chunks': 1,
    });
    final filesBefore = (await v.db.query('files')).length;

    // This build opens it.
    final bobId = bob.identity;
    await stop(bob);
    final reopened = await start('Bob7', identity: bobId);
    await waitUntil(() => reopened.transport.isConnected,
        what: 'Bob is back');
    expect((await reopened.vault.db.query('files')).length, filesBefore,
        reason: 'no attachment is lost opening an existing vault');
    expect(await shown(reopened, gid, first.mid), equals(a1));
    expect(await shown(reopened, gid, pointer), isNull,
        reason: "Mallory's old message does not show Alice's file");
    expect(await shown(reopened, gid, second.mid), isNull,
        reason: "and Alice's message does not show the bytes that replaced "
            'hers before this build');
    expect(await shown(reopened, gid, replaced), equals(evil),
        reason: 'they are shown under the message that brought them');

    // Mallory deletes her old message: hers goes, Alice's file stays.
    await mallory.debugSendRawInner(reopened.myRid, del([pointer], gid: gid));
    await quiet([alice, reopened, mallory],
        what: "Bob has processed Mallory's delete");
    expect((await reopened.loadMessages(gid))
        .firstWhere((x) => x.mid == pointer)
        .deleted, isTrue,
        reason: 'her own message she may delete');
    expect(await shown(reopened, gid, first.mid), equals(a1),
        reason: "but not Alice's attachment through it");
    expect(await rowsFor(reopened, first.fid!), hasLength(1));
  }, timeout: const Timeout(Duration(minutes: 3)));

  /// Bob and a contact of his ([other], Mallory by default), settled.
  Future<(ChatService, ChatService)> pair(String tag,
      {String other = 'Mallory'}) async {
    final bob = await start('Bob$tag');
    final mallory = await start('$other$tag');
    await waitUntil(
        () => bob.transport.isConnected && mallory.transport.isConnected,
        what: 'both connect');
    await befriend(bob, mallory);
    await settled([bob, mallory]);
    return (bob, mallory);
  }

  int chunksFor(int size) =>
      size == 0 ? 1 : (size + defaultChunkSize - 1) ~/ defaultChunkSize;

  test('8. an offer is held to the size limit and to its own size', () async {
    final (bob, mallory) = await pair('8');
    const limit = 24 * 1024 * 1024;

    Future<InnerMessage> offer(int size, int chunks) async {
      final (o, _) = await forged(b64url(randomBytes(12)), Uint8List(0));
      o.data['size'] = size;
      o.data['chunks'] = chunks;
      return o;
    }

    final tooBig = await offer(limit + 1, chunksFor(limit + 1));
    final miscounted = await offer(1000, 2);
    final zeroChunks = await offer(1000, 0);
    final honest = await offer(1000, 1);
    for (final o in [tooBig, miscounted, zeroChunks, honest]) {
      await mallory.debugSendRawInner(bob.myRid, o);
    }
    await quiet([bob, mallory], what: 'Bob has processed the offers');
    expect(await rowsFor(bob, tooBig.data['fid'] as String), isEmpty,
        reason: 'more than the 24 MiB product limit');
    expect(await hasMessage(bob, mallory.myRid, tooBig.mid), isFalse);
    expect(await rowsFor(bob, miscounted.data['fid'] as String), isEmpty,
        reason: '1000 bytes is one chunk, not two');
    expect(await rowsFor(bob, zeroChunks.data['fid'] as String), isEmpty);
    expect(await rowsFor(bob, honest.data['fid'] as String), hasLength(1),
        reason: 'and an offer that adds up is still taken');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('9. a chunk must be what its offer said it would be', () async {
    final (bob, mallory) = await pair('9');

    // A chunk of a real key, at a real index, carrying the wrong amount.
    Future<String> chunkOf(FileKeyMaterial km, int idx, Uint8List b) =>
        encryptChunk(km, idx, b);

    // (a) An offer that says 1000 bytes, and a first chunk carrying 4096 —
    // with the hash of those 4096, so nothing but the size says no.
    final big = pattern(4096, 79);
    final kmA = FileKeyMaterial.generate();
    final overA = InnerMessage(
        kind: 'file',
        mid: newMessageId(),
        ts: DateTime.now().millisecondsSinceEpoch,
        data: {
          'fid': kmA.fid,
          'name': 'small.bin',
          'size': 1000,
          'mime': 'application/octet-stream',
          'sha256': b64(await sha256Bytes(big)),
          'fk': b64(kmA.fk),
          'fn': b64(kmA.fn),
          'chunks': 1,
        });
    await mallory.debugSendRawInner(bob.myRid, overA);
    await waitUntil(() async => (await rowsFor(bob, kmA.fid)).isNotEmpty,
        what: 'the 1000-byte offer is held');
    await post(bob, [
      await chunkOf(kmA, 0, big),
      await chunkOf(kmA, 1, pattern(1000, 83)), // past the declared range
    ]);

    // (b) Three honest chunks, and a short impostor for the middle one sent
    // AHEAD of the real one: it must not take the real one's place.
    final good = pattern(300000, 89);
    final kmB = FileKeyMaterial.generate();
    final parts = splitChunks(good);
    expect(parts, hasLength(3));
    final offerB = InnerMessage(
        kind: 'file',
        mid: newMessageId(),
        ts: DateTime.now().millisecondsSinceEpoch,
        data: {
          'fid': kmB.fid,
          'name': 'good.bin',
          'size': good.length,
          'mime': 'application/octet-stream',
          'sha256': b64(await sha256Bytes(good)),
          'fk': b64(kmB.fk),
          'fn': b64(kmB.fn),
          'chunks': parts.length,
        });
    await mallory.debugSendRawInner(bob.myRid, offerB);
    await waitUntil(() async => (await rowsFor(bob, kmB.fid)).isNotEmpty,
        what: 'the three-chunk offer is held');
    await post(bob, [await chunkOf(kmB, 1, pattern(1000, 97))]);
    await quiet([bob, mallory], what: 'the bad chunks are processed');
    await post(bob, [
      for (var i = 0; i < parts.length; i++) await chunkOf(kmB, i, parts[i])
    ]);
    await quiet([bob, mallory], what: 'the good chunks are processed');

    final heldA = await bob.vault.db
        .query('chunks', where: 'fid = ?', whereArgs: [kmA.fid]);
    expect(heldA, isEmpty,
        reason: 'neither the oversize chunk nor the out-of-range one is kept');
    expect((await rowsFor(bob, kmA.fid)).single['complete'], 0,
        reason: 'nothing assembled beyond the declared 1000 bytes');
    expect(await shown(bob, mallory.myRid, overA.mid), isNull);
    expect(await shown(bob, mallory.myRid, offerB.mid), equals(good),
        reason: 'the short impostor did not spoil the real file');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('10. a million-chunk offer is refused; RSS measured', () async {
    final (bob, mallory) = await pair('10');
    final km = FileKeyMaterial.generate();
    final o = InnerMessage(
        kind: 'file',
        mid: newMessageId(),
        ts: DateTime.now().millisecondsSinceEpoch,
        data: {
          'fid': km.fid,
          'name': 'million.bin',
          'size': 24 * 1024 * 1024,
          'mime': 'application/octet-stream',
          'sha256': b64(Uint8List(32)),
          'fk': b64(km.fk),
          'fn': b64(km.fn),
          'chunks': 1000000,
        });

    // What arrives for it: full-size chunks at the indices it claims.
    const sent = 100;
    final rnd = Random(7);
    final payloads = <String>[
      for (var i = 0; i < sent; i++)
        await encryptChunk(
            km,
            i,
            Uint8List.fromList(
                List<int>.generate(defaultChunkSize, (_) => rnd.nextInt(256))))
    ];

    await quiet([bob, mallory], what: 'idle before measuring');
    final before = ProcessInfo.currentRss;
    var peak = before;
    final sampler = Timer.periodic(const Duration(milliseconds: 20), (_) {
      final r = ProcessInfo.currentRss;
      if (r > peak) peak = r;
    });
    final t0 = DateTime.now();
    await mallory.debugSendRawInner(bob.myRid, o);
    await post(bob, payloads);
    await quiet([bob, mallory],
        what: 'Bob has processed the offer and chunks',
        timeout: const Duration(minutes: 3));
    sampler.cancel();
    final after = ProcessInfo.currentRss;
    final held = (await bob.vault.db
            .query('chunks', where: 'fid = ?', whereArgs: [km.fid]))
        .length;
    String mib(int b) => (b / (1024 * 1024)).toStringAsFixed(1);
    // ignore: avoid_print
    print('RSS million-chunk offer: before ${mib(before)} MiB, peak '
        '${mib(peak)} MiB (+${mib(peak - before)}), after ${mib(after)} MiB '
        '(+${mib(after - before)}); $sent chunks of $defaultChunkSize bytes, '
        '$held held, ${DateTime.now().difference(t0).inMilliseconds} ms');

    expect(await rowsFor(bob, km.fid), isEmpty,
        reason: 'a 24 MiB file is 176 chunks, not 1,000,000');
    expect(await hasMessage(bob, mallory.myRid, o.mid), isFalse);
    expect(held, lessThanOrEqualTo(ChatService.maxHeldChunks),
        reason: 'its chunks are held only as any unexplained chunk is');
  }, timeout: const Timeout(Duration(minutes: 6)));

  test('11. a reply quoting an attachment arrives, and the chat goes on',
      () async {
    final (bob, carol) = await pair('11', other: 'Carol');
    final f = pattern(4000, 101);
    await bob.sendFile(carol.myRid, 'photo.png', f, 'image/png');
    final atCarol = await arrived(carol, bob.myRid, 'photo.png', f);

    List<ChatMessage> bobsChat() =>
        bob.messagesByChat[carol.myRid] ?? const <ChatMessage>[];
    await carol.sendText(bob.myRid, 'nice photo', replyTo: atCarol.mid);
    await waitUntil(() => bobsChat().any((m) => m.body == 'nice photo'),
        what: 'the reply to the photo reaches Bob');
    expect(bobsChat().firstWhere((m) => m.body == 'nice photo').quote?.preview,
        'photo.png',
        reason: 'quoting the attachment it names');
    await carol.sendText(bob.myRid, 'and another thing');
    await waitUntil(() => bobsChat().any((m) => m.body == 'and another thing'),
        what: 'the next message from Carol reaches Bob too');
  }, timeout: const Timeout(Duration(minutes: 3)));
}

bool _same(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
