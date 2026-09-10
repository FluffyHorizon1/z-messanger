// 15.3 — delivery receipts are sent per burst, not per message.
//
// A receipt is a full outbound send, and the receive-side measurement
// (receive_bench_test.dart) put it at 10 ms of every 25 ms receive — with
// the same per-conversation lock the next inbound message needs, so fifty
// messages arriving on reconnect meant fifty sends, in line. The 'dlv' inner
// has always carried a list of mids; now it is used as one.
//
// Exit criteria:
//
//   1. A burst of inbound messages produces ONE receipt naming all of them,
//      and the sender's ticks all turn.
//   2. A batch past its cap goes out immediately, without waiting.
//   3. A receipt with no company goes out by itself when the window closes.
@Tags(['integration'])
library;

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/models.dart';
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

  /// Offline: port 1 is never listening. Envelopes move between the two by
  /// hand, straight from one outbox into the other's inbound path.
  Future<ChatService> makeClient(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_dlv_$name');
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

  Future<List<RelayInbound>> drain(ChatService from, String toRid) async {
    final rows = await from.vault.db.query('outbox',
        where: 'rid = ?', whereArgs: [toRid], orderBy: 'created_ms ASC');
    await from.vault.db.delete('outbox', where: 'rid = ?', whereArgs: [toRid]);
    return [
      for (final r in rows)
        RelayInbound(
            id: r['id'] as String,
            from: '',
            payload: r['payload'] as String,
            serverTs: 0)
    ];
  }

  Future<void> deliver(ChatService from, ChatService to) async {
    for (final m in await drain(from, to.myRid)) {
      await to.debugInbound(m);
    }
  }

  Future<(ChatService, ChatService)> pair() async {
    final a = await makeClient('a');
    final b = await makeClient('b');
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
    // Two exchanges each way: session, device list, post-quantum offer —
    // all the one-off envelopes — go across, and their receipts with them.
    for (var i = 0; i < 2; i++) {
      await a.sendText(b.myRid, 'hi $i');
      await deliver(a, b);
      await b.flushDeliveryReceipts();
      await deliver(b, a);
      await b.sendText(a.myRid, 'hi back $i');
      await deliver(b, a);
      await a.flushDeliveryReceipts();
      await deliver(a, b);
    }
    return (a, b);
  }

  Future<int> outboxRows(ChatService svc, String rid) async => (await svc
          .vault.db
          .query('outbox', columns: ['id'], where: 'rid = ?', whereArgs: [rid]))
      .length;

  List<ChatMessage> mine(ChatService svc, String rid) =>
      (svc.messagesByChat[rid] ?? const [])
          .where((m) => m.outgoing && m.kind == 'text')
          .toList();

  test('a burst of inbound messages is acknowledged with one receipt',
      () async {
    final (a, b) = await pair();
    const n = 12;
    for (var i = 0; i < n; i++) {
      await a.sendText(b.myRid, 'burst $i');
    }
    await deliver(a, b);

    // b has received twelve and sent nothing yet: the receipts are waiting.
    expect(b.pendingDeliveryReceipts, n);
    expect(await outboxRows(b, a.myRid), 0,
        reason: 'a receipt went out per message; they should be waiting '
            'for the window');

    await b.flushDeliveryReceipts();
    expect(b.pendingDeliveryReceipts, 0);
    expect(await outboxRows(b, a.myRid), 1,
        reason: 'twelve messages, one receipt');

    // And it does what twelve would have: every one of a's messages is
    // marked delivered when the receipt lands.
    await deliver(b, a);
    final sent = mine(a, b.myRid).where((m) => m.body.startsWith('burst'));
    expect(sent.length, n);
    expect(sent.every((m) => m.status >= MsgStatus.delivered), isTrue,
        reason: 'a tick did not turn: '
            '${sent.where((m) => m.status < MsgStatus.delivered).map((m) => m.body)}');
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('a batch past its cap goes out without waiting', () async {
    final (a, b) = await pair();
    // Delivering seventy messages takes longer than the window, so left to
    // itself the timer would keep the batch small and the cap would never be
    // reached — the first version of this test passed with the cap removed.
    // The window is held shut, so only the cap can send.
    b.debugHoldDeliveryReceipts = true;
    const n = 70; // cap is 64
    for (var i = 0; i < n; i++) {
      await a.sendText(b.myRid, 'flood $i');
    }
    var worst = 0;
    for (final m in await drain(a, b.myRid)) {
      await b.debugInbound(m);
      if (b.pendingDeliveryReceipts > worst) worst = b.pendingDeliveryReceipts;
    }
    expect(worst, 63,
        reason: 'the pending set should climb to one short of the cap and '
            'then be sent; it reached $worst');
    expect(await outboxRows(b, a.myRid), 1,
        reason: 'the 64th message should have sent one batch, without a '
            'window and without a flush');
    expect(b.pendingDeliveryReceipts, n - 64);
    b.debugHoldDeliveryReceipts = false;
    await b.flushDeliveryReceipts();
    expect(await outboxRows(b, a.myRid), 2);

    // Every one of them still lands.
    await deliver(b, a);
    final sent = mine(a, b.myRid).where((m) => m.body.startsWith('flood'));
    expect(sent.length, n);
    expect(sent.every((m) => m.status >= MsgStatus.delivered), isTrue);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('a lone receipt goes out by itself when the window closes', () async {
    final (a, b) = await pair();
    await a.sendText(b.myRid, 'just one');
    await deliver(a, b);
    expect(b.pendingDeliveryReceipts, 1);
    expect(await outboxRows(b, a.myRid), 0);
    // No flush from the test: the timer does it.
    await Future<void>.delayed(
        ChatService.deliveryReceiptWindow + const Duration(milliseconds: 400));
    expect(b.pendingDeliveryReceipts, 0,
        reason: 'the window closed and the receipt is still waiting');
    expect(await outboxRows(b, a.myRid), 1);
  }, timeout: const Timeout(Duration(minutes: 2)));
}
