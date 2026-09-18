// ADR 0011 — contact requests: being added stops being silent.
//
// Before this, adding someone sent them a hello they DROPPED (an unknown
// sender, no session), so a connection needed both people to add each other.
// Now the add sends a signed request that surfaces on the other side as
// "someone wants to connect", to accept, decline, or block. Accepting adds
// them exactly as a scan would; the session then establishes both ways.
//
// Everything below runs offline, carrying sealed envelopes by hand.
//
// Criteria, each a test below:
//   1. adding someone sends a request that appears on their side as pending —
//      not a contact — and accepting it connects both, with messages flowing
//      and the adder's "requested" flag cleared;
//   2. declining drops the request and adds nothing;
//   3. blocking drops the request and silences every future one from that id;
//   4. a request from an id already a contact is folded (their acceptance), not
//      shown again;
//   5. deleting a contact leaves no request or block row naming them.
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

  final temps = <Directory>[];
  final services = <ChatService>[];

  tearDownAll(() async {
    for (final s in services) {
      await s.transport.stop();
    }
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<ChatService> makeClient(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_req_$name');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final identity = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(identity.toJson()));
    final svc = await ChatService.init(
      vault: vault,
      identity: identity,
      displayName: name,
      transport: Transport(identity: identity, serverUrl: 'ws://127.0.0.1:1'),
    );
    services.add(svc);
    return svc;
  }

  Future<int> carry(ChatService from, ChatService to) async {
    final rows = await from.vault.db.query('outbox',
        where: 'rid = ?', whereArgs: [to.myRid], orderBy: 'seq');
    await from.vault.db
        .delete('outbox', where: 'rid = ?', whereArgs: [to.myRid]);
    for (final r in rows) {
      await to.debugInbound(RelayInbound(
          id: r['id'] as String,
          from: '',
          payload: r['payload'] as String,
          serverTs: DateTime.now().millisecondsSinceEpoch));
    }
    return rows.length;
  }

  Future<void> settle(ChatService x, ChatService y) async {
    for (var i = 0; i < 8; i++) {
      if (await carry(x, y) + await carry(y, x) == 0) return;
    }
  }

  test('1. adding sends a request; accepting connects both ways', () async {
    final a = await makeClient('a');
    final b = await makeClient('b');

    // A adds B by (paste of) B's code. B has NOT added A.
    await a.addContactFromCode(await b.myContactCode());
    expect(a.contacts.containsKey(b.myRid), isTrue);
    expect(a.contacts[b.myRid]!.requested, isTrue,
        reason: 'A is waiting for B to accept');
    expect(b.contacts.containsKey(a.myRid), isFalse,
        reason: 'B has not been added — it is a request, not a contact');

    await settle(a, b);

    // B sees a pending request from A, and A is not yet a contact.
    expect(b.contacts.containsKey(a.myRid), isFalse);
    expect(b.requests.map((r) => r.rid), contains(a.myRid));
    expect(b.requests.single.name, 'a');

    // B accepts.
    await b.acceptRequest(a.myRid);
    expect(b.contacts.containsKey(a.myRid), isTrue,
        reason: 'accepting adds them');
    expect(b.requests, isEmpty, reason: 'the request is spent');
    expect(b.contacts[a.myRid]!.verified, isFalse,
        reason: 'added unverified, exactly as a scan would');

    await settle(a, b);

    // A stops showing "requested" once B has answered.
    expect(a.contacts[b.myRid]!.requested, isFalse);

    // And the session works both ways.
    await a.sendText(b.myRid, 'hello there');
    await settle(a, b);
    expect(b.messagesByChat[a.myRid]!.map((m) => m.body), contains('hello there'));
    await b.sendText(a.myRid, 'hi back');
    await settle(a, b);
    expect(a.messagesByChat[b.myRid]!.map((m) => m.body), contains('hi back'));
  });

  test('2. declining drops the request and adds nothing', () async {
    final a = await makeClient('a2');
    final b = await makeClient('b2');
    await a.addContactFromCode(await b.myContactCode());
    await settle(a, b);
    expect(b.requests.map((r) => r.rid), contains(a.myRid));

    await b.declineRequest(a.myRid);
    expect(b.requests, isEmpty);
    expect(b.contacts.containsKey(a.myRid), isFalse);
    expect(b.isBlocked(a.myRid), isFalse, reason: 'declined is not blocked');
  });

  test('3. blocking silences this request and future ones', () async {
    final a = await makeClient('a3');
    final b = await makeClient('b3');
    await a.addContactFromCode(await b.myContactCode());
    await settle(a, b);
    expect(b.requests.map((r) => r.rid), contains(a.myRid));

    await b.blockRequest(a.myRid);
    expect(b.requests, isEmpty);
    expect(b.isBlocked(a.myRid), isTrue);

    // A adds B again (a fresh add re-sends a request). It never surfaces.
    await a.deleteContact(b.myRid);
    await a.addContactFromCode(await b.myContactCode());
    await settle(a, b);
    expect(b.requests, isEmpty, reason: 'a blocked id is dropped in silence');
    expect(b.contacts.containsKey(a.myRid), isFalse);
  });

  test('4. a request from an existing contact is folded, not shown', () async {
    // A and B add each other (a mutual scan): each sends the other a request,
    // but each already added the other, so neither is shown a request.
    final a = await makeClient('a4');
    final b = await makeClient('b4');
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
    await settle(a, b);
    expect(a.requests, isEmpty);
    expect(b.requests, isEmpty);
    expect(a.contacts[b.myRid]!.requested, isFalse,
        reason: 'a mutual add clears both sides');
    expect(b.contacts[a.myRid]!.requested, isFalse);
    // And they can talk.
    await a.sendText(b.myRid, 'mutual');
    await settle(a, b);
    expect(b.messagesByChat[a.myRid]!.map((m) => m.body), contains('mutual'));
  });

  test('5. deleting a contact leaves no request or block naming them', () async {
    final a = await makeClient('a5');
    final b = await makeClient('b5');
    await a.addContactFromCode(await b.myContactCode());
    await settle(a, b);
    await b.acceptRequest(a.myRid);
    await settle(a, b);

    await b.deleteContact(a.myRid);
    // No table row names A.
    final tables = (await b.vault.db.rawQuery(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"))
        .map((r) => r['name'] as String);
    final hits = <String>[];
    for (final t in tables) {
      for (final row in await b.vault.db.query(t)) {
        for (final e in row.entries) {
          final v = e.value;
          if (v is String && v.contains(a.myRid)) hits.add('$t.${e.key}');
        }
      }
    }
    expect(hits, isEmpty, reason: 'no row names the deleted contact');
    expect(b.requestsByRid.containsKey(a.myRid), isFalse);
  });
}
