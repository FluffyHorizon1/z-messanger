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
}
