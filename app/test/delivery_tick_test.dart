// What a delivery tick is allowed to mean.
//
// Two mistakes lived in one line. The receipt handler marked a message
// delivered "wherever they live" — no scope at all — and a `mid` is plaintext
// to every member of a group, so any contact could name one and flip whatever
// it matched, including a 1:1 message to somebody else entirely. And a GROUP
// message reached the double tick on the FIRST member's receipt: a tick that
// says "they have it" while four people do not.
//
// The second one was also a published claim. Patch 13 made the relay send one
// receipt per member instead of one per message, and said so; the client went
// on collapsing them into the first.
//
// Criteria, each a test below:
//  1. a contact can only confirm messages in threads they are a party to —
//     a receipt naming somebody else's conversation does nothing;
//  2. a group message is delivered when EVERY current member has confirmed,
//     and not before;
//  3. a member who leaves is no longer someone the tick waits for, so a
//     message cannot be stuck for ever;
//  4. what recorded the confirmations goes when the message goes — a
//     disappearing message that leaves a row saying who received it and when
//     has not disappeared.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:z_protocol/z_protocol.dart';
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
      await s.transport.stop();
      await s.vault.db.close();
    }
    relay.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<ChatService> person(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_dlv_');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final me = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(me.toJson()));
    final transport =
        Transport(identity: me, serverUrl: 'ws://127.0.0.1:$port');
    final svc = await ChatService.init(
        vault: vault, identity: me, displayName: name, transport: transport);
    live.add(svc);
    for (var i = 0; i < 60 && !transport.isConnected; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    return svc;
  }

  /// Everyone talks to everyone: the shape a group needs.
  Future<void> introduce(List<ChatService> all) async {
    for (final a in all) {
      for (final b in all) {
        if (identical(a, b)) continue;
        try {
          await a.addContactFromCode(await b.myContactCode());
        } on FormatException {
          // already added
        }
      }
    }
  }

  Future<void> settle(List<ChatService> all,
      {Duration each = const Duration(milliseconds: 250), int rounds = 12}) async {
    for (var i = 0; i < rounds; i++) {
      for (final s in all) {
        await s.flushOutbox();
      }
      await Future<void>.delayed(each);
    }
  }

  /// Offline, then back: a phone in a pocket. Inbound arrives on its own
  /// socket, so a member who is merely "not flushed" is still receiving —
  /// isolating one means actually taking their link down.
  Future<void> offline(ChatService s) => s.transport.stop();
  Future<void> online(ChatService s) async {
    s.transport.start();
    for (var i = 0; i < 80 && !s.transport.isConnected; i++) {
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
  }

  Future<int> statusOf(ChatService s, String thread, String mid) async =>
      (await s.vault.db.query('messages',
              columns: ['status'],
              where: 'mid = ? AND rid = ? AND outgoing = 1',
              whereArgs: [mid, thread]))
          .single['status'] as int;

  Future<String> lastOutgoing(ChatService s, String thread) async =>
      (await s.vault.db.query('messages',
              columns: ['mid'],
              where: 'rid = ? AND outgoing = 1 AND kind IN (?, ?)',
              whereArgs: [thread, 'text', 'gtext'],
              orderBy: 'ts_ms DESC',
              limit: 1))
          .first['mid'] as String;

  test('1. a receipt for somebody else\'s conversation does nothing', () async {
    final alice = await person('Alice');
    final bob = await person('Bob');
    final mallory = await person('Mallory');
    await introduce([alice, bob, mallory]);
    await settle([alice, bob, mallory], rounds: 6);

    final bobRid = await bob.identity.routingId();
    await offline(bob); // his phone is in a pocket
    await alice.sendText(bobRid, 'for bob only');
    await settle([alice], rounds: 4);
    final mid = await lastOutgoing(alice, bobRid);
    expect(await statusOf(alice, bobRid, mid), MsgStatus.sent);

    // Mallory is a contact of Alice's and shares no thread with this message.
    // She names it anyway — which is all it ever took.
    await mallory.debugClaimDelivery(await alice.identity.routingId(), [mid]);
    await settle([mallory, alice], rounds: 8);
    expect(await statusOf(alice, bobRid, mid), MsgStatus.sent,
        reason: 'a claim about a conversation she is not in is not hers to make');

    // Bob's own receipt still works, which is the point of scoping rather
    // than removing.
    await online(bob);
    await settle([bob, alice], rounds: 10);
    expect(await statusOf(alice, bobRid, mid), MsgStatus.delivered,
        reason: "the recipient's own receipt is honoured");
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('2. a group message is delivered when every member has confirmed',
      () async {
    final alice = await person('Alice');
    final bob = await person('Bob');
    final carol = await person('Carol');
    await introduce([alice, bob, carol]);
    await settle([alice, bob, carol], rounds: 6);

    final gid = await alice.createGroup('Three', [
      await bob.identity.routingId(),
      await carol.identity.routingId(),
    ]);
    await settle([alice, bob, carol], rounds: 10);
    await offline(carol); // her phone is off
    await alice.sendGroupText(gid, 'all of you');
    await settle([alice], rounds: 4);
    final mid = await lastOutgoing(alice, gid);

    // Only Bob is listening. One of two is not "delivered".
    await settle([bob, alice], rounds: 10);
    expect(await statusOf(alice, gid, mid), MsgStatus.sent,
        reason: 'one member of two has it; the tick says two');
    final confirmers = await alice.vault.db.query('delivery',
        columns: ['from_rid'], where: 'mid = ?', whereArgs: [mid]);
    expect(confirmers.length, 1, reason: 'and the one is recorded');

    // Now Carol too.
    await online(carol);
    await settle([carol, alice], rounds: 14);
    expect(await statusOf(alice, gid, mid), MsgStatus.delivered,
        reason: 'every member has it now');
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('3. a member who leaves is not waited for', () async {
    final alice = await person('Alice');
    final bob = await person('Bob');
    final carol = await person('Carol');
    await introduce([alice, bob, carol]);
    await settle([alice, bob, carol], rounds: 6);
    final carolRid = await carol.identity.routingId();
    final gid = await alice.createGroup('Three', [
      await bob.identity.routingId(),
      carolRid,
    ]);
    await settle([alice, bob, carol], rounds: 10);
    await offline(carol);
    await alice.sendGroupText(gid, 'one of you will go quiet');
    await settle([alice, bob], rounds: 10);
    final mid = await lastOutgoing(alice, gid);
    expect(await statusOf(alice, gid, mid), MsgStatus.sent);

    // Carol never answers and is removed. The tick must not wait for her for
    // ever: a message stuck on a departed member is a worse lie than the one
    // this replaced.
    await alice.removeGroupMember(gid, carolRid);
    await settle([alice, bob], rounds: 10);
    expect(await statusOf(alice, gid, mid), MsgStatus.delivered,
        reason: 'every REMAINING member has it');
  }, timeout: const Timeout(Duration(minutes: 5)));

  test('4. what recorded the confirmations goes when the message goes',
      () async {
    final alice = await person('Alice');
    final bob = await person('Bob');
    await introduce([alice, bob]);
    await settle([alice, bob], rounds: 6);
    final bobRid = await bob.identity.routingId();
    await alice.sendText(bobRid, 'and then forget it');
    await settle([alice, bob], rounds: 10);
    final mid = await lastOutgoing(alice, bobRid);
    expect(await statusOf(alice, bobRid, mid), MsgStatus.delivered);
    expect(
        (await alice.vault.db
                .query('delivery', where: 'mid = ?', whereArgs: [mid]))
            .length,
        1);

    await alice.deleteMessage(bobRid, mid);
    expect(
        await alice.vault.db.query('delivery', where: 'mid = ?', whereArgs: [mid]),
        isEmpty,
        reason: 'a deleted message leaves no record of who received it');
  }, timeout: const Timeout(Duration(minutes: 5)));
}
