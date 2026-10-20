// A malformed inner message from an authenticated contact used to wedge a
// mailbox slot for the whole queue TTL (the 2026-09-14 review's finding 42).
//
// The envelope decrypts — the ratchet is fine — but the plaintext inside is a
// malformed InnerMessage (a peer's buggy or hostile client can put anything in
// a validly-encrypted envelope). Parsing it was a raw `as String` that threw a
// `TypeError`, an Error, OUTSIDE both try/catch blocks in `_onInbound`; it fell
// through to the outer catch, which returns WITHOUT acknowledging. So the relay
// redelivered the same envelope until the TTL, and — the vault write never
// having run — a restart re-decrypted the stale chain and failed the same way,
// for good.
//
// Now `InnerMessage.fromBytes` throws a `FormatException` the caller catches,
// and a malformed inner is a drop that ACKNOWLEDGES (and keeps the validly
// advanced ratchet). Everything below runs offline, carrying envelopes by hand.
//
// And (44.1, PROTOCOL §18.11) an inner that is well formed but from a later
// build: 44.3 has every device announce its sealing key in a `pqseal`, stamp
// `pqs:1` on what it sends and carry its account's `pqdc` in its `pqid`, and
// this build predates all three. The `pqseal` is acknowledged and dropped —
// the unknown kind's door, `_persistInboundKind`'s default — with nothing
// stored and the conversation going on; the `pqid` gives up its key exactly
// as one without `pqdc` does (`_onPqIdentity` reads `alg`, `pk` and `ack`);
// and the text carrying `pqs` is the text. All three are built by hand from
// today's members, so nothing here calls what 44.1 adds to the library.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:z_protocol/z_protocol.dart';

/// A transport that records every envelope id it was asked to acknowledge.
class _AckSpy extends Transport {
  _AckSpy(ZIdentity id) : super(identity: id, serverUrl: 'ws://127.0.0.1:1');
  final acked = <String>[];
  @override
  void ackReceived({required String id, required String from}) {
    acked.add(id);
    super.ackReceived(id: id, from: from);
  }
}

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

  Future<ChatService> makeClient(String name,
      {Transport Function(ZIdentity)? transportFor}) async {
    final dir = await Directory.systemTemp.createTemp('z_bad_$name');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final identity = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(identity.toJson()));
    final svc = await ChatService.init(
      vault: vault,
      identity: identity,
      displayName: name,
      transport: transportFor?.call(identity) ??
          Transport(identity: identity, serverUrl: 'ws://127.0.0.1:1'),
    );
    services.add(svc);
    return svc;
  }

  Future<int> carry(ChatService from, ChatService to) async {
    final rows = await from.vault.db.query('outbox',
        where: 'rid = ?', whereArgs: [to.myRid], orderBy: 'seq');
    await from.vault.db.delete('outbox', where: 'rid = ?', whereArgs: [to.myRid]);
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
    for (var i = 0; i < 6; i++) {
      if (await carry(x, y) + await carry(y, x) == 0) return;
    }
  }

  test('a malformed inner is acknowledged, not left wedging the mailbox',
      () async {
    final a = await makeClient('a');
    late _AckSpy bSpy;
    final b = await makeClient('b', transportFor: (id) => bSpy = _AckSpy(id));
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
    await settle(a, b);
    await a.sendText(b.myRid, 'hello');
    await settle(a, b);
    await b.sendText(a.myRid, 'hi back');
    await settle(a, b);
    expect(b.messagesByChat[a.myRid]!.map((m) => m.body), contains('hello'));
    final before = bSpy.acked.length;

    // A validly-encrypted envelope whose inner plaintext is malformed: `k` is
    // a number where a string is required.
    final bad = await a.debugSealRaw(
        b.myRid, Uint8List.fromList(utf8.encode('{"k":123,"mid":"x","ts":1}')));
    await b.debugInbound(RelayInbound(
        id: 'bad-1',
        from: '',
        payload: bad,
        serverTs: DateTime.now().millisecondsSinceEpoch));

    expect(bSpy.acked, contains('bad-1'),
        reason: 'the malformed inner must be acknowledged, or it wedges the '
            'mailbox slot for the queue TTL');
    expect(bSpy.acked.length, greaterThan(before));

    // And the mailbox is not stuck: the next valid message from a still
    // arrives, because the ratchet was persisted rather than left to re-fail.
    await a.sendText(b.myRid, 'still here');
    await settle(a, b);
    expect(b.messagesByChat[a.myRid]!.map((m) => m.body), contains('still here'),
        reason: 'a malformed inner must not stop the conversation');
  });

  test(
      "a later build's pqseal is acknowledged and dropped, and its pqid "
      'carrying pqdc and its text carrying pqs read as they read without them',
      () async {
    final a = await makeClient('qa');
    late _AckSpy bSpy;
    final b = await makeClient('qb', transportFor: (id) => bSpy = _AckSpy(id));
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());

    // Settled with every 16 384-bucket envelope a sends b left undelivered:
    // those are her post-quantum identity (§18.2), so b ends holding her
    // commitment and not her key — the state the first `pqid` he reads acts
    // on. Each row is taken off the outbox by its own `seq`, so a re-send
    // queued meanwhile is left for later rather than lost.
    bool isPqid(String p) =>
        p.startsWith('zs1.') && unb64url(p.substring(4)).length - 60 == 16384;
    Future<int> carryExcept(ChatService from, ChatService to,
        bool Function(String payload) drop) async {
      final rows = await from.vault.db.query('outbox',
          where: 'rid = ?', whereArgs: [to.myRid], orderBy: 'seq');
      for (final r in rows) {
        await from.vault.db
            .delete('outbox', where: 'seq = ?', whereArgs: [r['seq']]);
        final payload = r['payload'] as String;
        if (drop(payload)) continue;
        await to.debugInbound(RelayInbound(
            id: r['id'] as String,
            from: '',
            payload: payload,
            serverTs: DateTime.now().millisecondsSinceEpoch));
      }
      return rows.length;
    }

    Future<void> settleWithoutHerKey() async {
      for (var i = 0; i < 6; i++) {
        if (await carryExcept(a, b, isPqid) + await carry(b, a) == 0) return;
      }
    }

    await settleWithoutHerKey();
    await a.sendText(b.myRid, 'hello');
    await settleWithoutHerKey();
    await b.sendText(a.myRid, 'hi back');
    await settleWithoutHerKey();
    expect(b.messagesByChat[a.myRid]!.map((m) => m.body), contains('hello'));
    expect(b.contacts[a.myRid]!.pqCommit, isNotNull,
        reason: 'the premise: b scanned her code, so he holds her commitment');
    expect(b.contacts[a.myRid]!.pqPub, isNull,
        reason: 'and not her key: no pqid of hers has reached him');
    expect(b.assuranceWith(a.myRid), IdentityAssurance.pendingPostQuantum);

    // Each one is sent the way the client sends anything — under the
    // conversation's lock, decorated as every message is, into the outbox —
    // and only its own envelope, found by its `mid`, is handed to b: so no
    // send a's timers make meanwhile can share its ratchet step, and none (a
    // `pqid` without `pqdc` among them) can reach b before it.
    final ts = DateTime.now().millisecondsSinceEpoch;
    Future<String> deliver(InnerMessage inner) async {
      await a.sendRawInner(b.myRid, inner);
      final rows = await a.vault.db.query('outbox',
          where: 'rid = ? AND mid = ?', whereArgs: [b.myRid, inner.mid]);
      expect(rows, hasLength(1), reason: '${inner.kind}: one envelope for it');
      final row = rows.single;
      await a.vault.db
          .delete('outbox', where: 'seq = ?', whereArgs: [row['seq']]);
      final id = row['id'] as String;
      await b.debugInbound(RelayInbound(
          id: id,
          from: '',
          payload: row['payload'] as String,
          serverTs: ts));
      return id;
    }

    // A `pqid` as 44.3 sends it: the account's key and the device's `pqdc`,
    // 3 309 bytes this build has no use for — random ones, since it never
    // looks at them.
    final aPq = (await a.pqIdentity())!;
    final pqidId = await deliver(
        InnerMessage(kind: 'pqid', mid: newMessageId(), ts: ts, data: {
      'alg': 'ML-DSA-65',
      'pk': b64(aPq.publicKey.mlPub),
      'pqdc': b64(randomBytes(3309)),
    }));
    expect(bSpy.acked, contains(pqidId));
    expect(b.contacts[a.myRid]!.pqPub, aPq.publicKey.mlPub,
        reason: 'the key in a pqid carrying pqdc is matched against the '
            'commitment and established, as it is in one without');
    expect(b.assuranceWith(a.myRid), IdentityAssurance.hybrid);

    // A `pqseal`: her device's sealing key, an ML-KEM-768 key like any other.
    Future<int> rows({String? mid}) async => (await b.vault.db.query(
            'messages',
            where: mid == null ? "rid = ? AND kind != 'system'" : 'mid = ?',
            whereArgs: [mid ?? a.myRid]))
        .length;
    final storedBefore = await rows();
    final sealMid = newMessageId();
    final (_, sealEk) = pqGenerate();
    final sealId = await deliver(
        InnerMessage(kind: 'pqseal', mid: sealMid, ts: ts, data: {
      'alg': 'ML-KEM-768',
      'ek': b64(sealEk),
    }));
    expect(bSpy.acked, contains(sealId),
        reason: 'its fate is decided, so it is acknowledged (§6.8)');
    expect(await rows(mid: sealMid), 0, reason: 'nothing is stored for it');
    expect(await rows(), storedBefore, reason: 'and no message is added');
    expect(b.messagesByChat[a.myRid]!.map((m) => m.mid), isNot(contains(sealMid)));
    expect(b.assuranceWith(a.myRid), IdentityAssurance.hybrid,
        reason: 'and nothing about her changes');

    // A text stamped `pqs:1` by hand, as 44.3 stamps what it sends.
    final withPqs = InnerMessage.text(newMessageId(), ts, 'pqs rides along');
    withPqs.data['pqs'] = 1;
    expect(bSpy.acked, contains(await deliver(withPqs)));
    expect(b.messagesByChat[a.myRid]!.map((m) => m.body),
        contains('pqs rides along'),
        reason: 'a text carrying pqs is the text');

    // And the conversation goes on, every queued envelope now delivered.
    await a.sendText(b.myRid, 'and on we go');
    await settle(a, b);
    await b.sendText(a.myRid, 'still with you');
    await settle(a, b);
    expect(b.messagesByChat[a.myRid]!.map((m) => m.body),
        contains('and on we go'));
    expect(a.messagesByChat[b.myRid]!.map((m) => m.body),
        contains('still with you'));
    expect(b.contacts[a.myRid]!.pqPub, aPq.publicKey.mlPub);
  });
}
