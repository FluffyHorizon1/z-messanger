// A retried send used to arrive stripped: `retryFailedSend` rebuilt the
// message as `InnerMessage.text(mid, _now(), body)`, dropping the disappearing
// timer, the reply quote and the forwarded flag, and moving the timestamp to
// now (the 2026-09-14 review's finding 43). So a retried disappearing message
// never disappeared, a retried reply lost its quote, and a retried forward
// stopped being marked one. The row holds all of it; the retry now rebuilds
// from the row. Everything below runs offline, carrying envelopes by hand.
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
    final dir = await Directory.systemTemp.createTemp('z_retry_$name');
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

  test('a retried send keeps its timer, its reply quote and its forwarded flag',
      () async {
    final a = await makeClient('a');
    final b = await makeClient('b');
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
    await settle(a, b);
    // Something to quote: b sends a, a holds its mid.
    await b.sendText(a.myRid, 'the original');
    await settle(a, b);
    final quoted = a.messagesByChat[b.myRid]!.last.mid;

    // A disappearing reply-forward from a to b, that then "permanently fails":
    // its outbox entry is dropped and its row marked -1, as the flush would.
    await a.setDisappearingTimer(b.myRid, 60);
    await settle(a, b);
    await a.sendText(b.myRid, 'my reply', replyTo: quoted, forwarded: true);
    final mid = a.messagesByChat[b.myRid]!.last.mid;
    await a.vault.db.delete('outbox', where: 'rid = ?', whereArgs: [b.myRid]);
    await a.vault.db.update('messages', {'status': -1},
        where: 'rid = ? AND mid = ?', whereArgs: [b.myRid, mid]);

    // b has not seen it. Retry, then deliver.
    expect(b.messagesByChat[a.myRid]?.any((m) => m.mid == mid) ?? false, isFalse);
    expect(await a.retryFailedSend(b.myRid, mid), isTrue);
    await settle(a, b);

    final got = b.messagesByChat[a.myRid]!.firstWhere((m) => m.mid == mid);
    expect(got.body, 'my reply');
    expect(got.expireAtMs, greaterThan(0),
        reason: 'the disappearing timer survived the retry');
    expect(got.replyTo, quoted, reason: 'the reply quote survived the retry');
    expect(got.forwarded, isTrue, reason: 'the forwarded flag survived the retry');
  });
}
