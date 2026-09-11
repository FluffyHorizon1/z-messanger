// After a restore from backup, everything queued at the relay while the
// device was gone arrives on a session the restored device no longer holds:
// the peer's messages, but also their delivery receipts and typing state,
// and the device cannot tell which was which. One "could not be decrypted"
// notice per envelope turned a three-row history into a column of identical
// lines. The service now keeps one notice per episode and counts, and
// re-opens the session with one hello per burst instead of one per envelope.
//
// No relay: the sender's outbox rows are handed to the receiver's inbound
// path directly (`debugInbound`), the way receive_bench_test.dart does it,
// so the order and timing of stale envelopes is exactly what the test says.
//
// Exit criteria:
//   1. three stale envelopes produce ONE notice whose count is 3, and one
//      hello — not three of each;
//   2. a message that decrypts ends the episode: a stale envelope after it
//      starts a new notice, count 1, rather than raising the old one;
//   3. the hello is rate-limited, not once-only — a stale envelope after the
//      interval sends another, so a lost hello is not the end of the story;
//   4. a notice written by an older build, with no count, still renders as
//      one message.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/system_messages.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/app_localizations_en.dart';
import 'package:zapp/l10n/system_text.dart';
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
    final dir = await Directory.systemTemp.createTemp('z_rnotice_$name');
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

  Future<List<RelayInbound>> drainOutbox(ChatService a, String toRid) async {
    final rows = await a.vault.db.query('outbox',
        where: 'rid = ?', whereArgs: [toRid], orderBy: 'created_ms ASC');
    await a.vault.db.delete('outbox', where: 'rid = ?', whereArgs: [toRid]);
    return [
      for (final r in rows)
        RelayInbound(
            id: r['id'] as String,
            from: '',
            payload: r['payload'] as String,
            serverTs: DateTime.now().millisecondsSinceEpoch)
    ];
  }

  Future<void> carry(ChatService from, ChatService to) async {
    for (final m in await drainOutbox(from, to.myRid)) {
      await to.debugInbound(m);
    }
  }

  /// Two clients who know each other and have a settled session, offline.
  Future<(ChatService, ChatService)> settledPair() async {
    final a = await makeClient('a');
    final b = await makeClient('b');
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
    await carry(a, b);
    await carry(b, a);
    for (var i = 0; i < 2; i++) {
      await a.sendText(b.myRid, 'ping $i');
      await carry(a, b);
      await b.sendText(a.myRid, 'pong $i');
      await carry(b, a);
    }
    return (a, b);
  }

  /// The device that [a] is comes back from a backup: identity and contacts
  /// kept, every session gone.
  Future<void> wipeSessions(ChatService a) async {
    await a.vault.db.delete('conversations');
    await a.reloadConversations();
  }

  List<Map<String, Object?>> notices(ChatService a, String rid) => [
        for (final m in a.messagesByChat[rid] ?? const [])
          if (m.kind == 'system' && m.body.contains(SystemKind.decryptFailed))
            (jsonDecode(m.body) as Map).cast<String, Object?>()
      ];

  test('three stale envelopes: one notice counting three, one hello', () async {
    final (a, b) = await settledPair();
    final rows = a.messagesByChat[b.myRid]!.length;

    for (var i = 0; i < 3; i++) {
      await b.sendText(a.myRid, 'while you were gone $i');
    }
    final stale = await drainOutbox(b, a.myRid);
    expect(stale, hasLength(3));

    await wipeSessions(a);
    await a.loadMessages(b.myRid);
    for (final m in stale) {
      await a.debugInbound(m);
    }

    expect(a.messagesByChat[b.myRid]!.length, rows + 1,
        reason: 'one new row for three envelopes, not three');
    expect(notices(a, b.myRid).single['n'], 3);
    expect(a.debugHellos, 1, reason: 'one hello re-opens the session');
    // What it says, rendered as the screen would render it.
    expect(
        systemText(AppLocalizationsEn(), a.messagesByChat[b.myRid]!.last.body),
        startsWith('3 messages could not be decrypted'));

    // And the stored row agrees with the loaded one.
    final stored = await a.vault.db.query('messages',
        where: 'rid = ? AND kind = ?',
        whereArgs: [b.myRid, 'system'],
        orderBy: 'ts_ms DESC');
    expect(stored, hasLength(1));
    expect(
        (jsonDecode(await a.vault.unseal(stored.single['enc_body'] as String))
            as Map)['n'],
        3);
  });

  test(
      'a message that decrypts ends the episode; the next stale one starts '
      'a new notice', () async {
    final (a, b) = await settledPair();
    a.helloMinInterval = Duration.zero;

    await b.sendText(a.myRid, 'first stale');
    await b.sendText(a.myRid, 'second stale');
    final stale = await drainOutbox(b, a.myRid);
    await wipeSessions(a);
    await a.loadMessages(b.myRid);

    await a.debugInbound(stale[0]);
    expect(notices(a, b.myRid).single['n'], 1);

    // The hello reaches Bob; he follows onto the new session and replies.
    await carry(a, b);
    await b.sendText(a.myRid, 'there you are');
    await carry(b, a);
    expect(a.messagesByChat[b.myRid]!.last.body, 'there you are',
        reason: 'the session re-opened and the reply was read');

    // A straggler from the old session, delivered late: a new episode.
    await a.debugInbound(stale[1]);
    final all = notices(a, b.myRid);
    expect(all, hasLength(2));
    expect(all.first['n'], 1, reason: 'the old notice was not raised');
    expect(all.last['n'], 1);
    expect(a.messagesByChat[b.myRid]!.last.body, contains('decrypt_failed'));
  });

  test('the hello is rate-limited, not once-only', () async {
    final (a, b) = await settledPair();
    for (var i = 0; i < 3; i++) {
      await b.sendText(a.myRid, 'stale $i');
    }
    final stale = await drainOutbox(b, a.myRid);
    await wipeSessions(a);
    await a.loadMessages(b.myRid);

    // Two together: one hello.
    await a.debugInbound(stale[0]);
    await a.debugInbound(stale[1]);
    expect(a.debugHellos, 1);

    // The interval elapses (the lost-hello case): the next stale envelope
    // sends another, and the count keeps going up on the same notice.
    a.helloMinInterval = Duration.zero;
    await a.debugInbound(stale[2]);
    expect(a.debugHellos, 2);
    expect(notices(a, b.myRid).single['n'], 3);
  });

  test('a notice from an older build, with no count, renders as one message',
      () {
    final l = AppLocalizationsEn();
    expect(systemText(l, systemBody(SystemKind.decryptFailed)),
        startsWith('A message could not be decrypted'));
    expect(systemText(l, systemBody(SystemKind.decryptFailed, {'n': 1})),
        startsWith('A message could not be decrypted'));
    expect(systemText(l, systemBody(SystemKind.decryptFailed, {'n': 2})),
        startsWith('2 messages could not be decrypted'));
  });
}
