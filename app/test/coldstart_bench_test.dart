// 15.3 — what opening the app costs, against the number of contacts.
//
// Named in the roadmap as unmeasured and left there while everything else
// on the list was measured. Measured on 2026-09-11: ChatService.init was
// linear in the contact count at ~6.3 ms per contact — 2.5 s for four
// hundred on a desktop VM, so several times that on a phone — because
// every per-contact key was read with its own query (and a miss with two),
// fifteen round trips per contact, plus one COUNT per chat for unread.
// After reading each key family once by prefix and counting unread in one
// GROUP BY: ~1.3 ms per contact, 0.5 s for four hundred. What is left is
// unsealing each contact's bundle and each conversation's ratchet state,
// which is the vault doing its job.
//
// A measurement, not an assertion — it takes a while to build four hundred
// contacts, so it is not in the ordinary sweep:
//
//     flutter test test/coldstart_bench_test.dart --tags bench
//
// The one thing it asserts is that cold start stays under a budget per
// contact, so a loader that quietly goes back to one query per contact
// fails here rather than on someone's phone.
@Tags(['bench'])
library;

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
  tearDownAll(() {
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<ChatService> makeClient(String name,
      {Directory? dir, ZIdentity? identity}) async {
    dir ??= await Directory.systemTemp.createTemp('z_cold_$name');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    identity ??= await ZIdentity.generate();
    if (await vault.kvGet('identity') == null) {
      await vault.kvPut('identity', jsonEncode(identity.toJson()));
    }
    return ChatService.init(
        vault: vault,
        identity: identity,
        displayName: name,
        transport:
            Transport(identity: identity, serverUrl: 'ws://127.0.0.1:1'));
  }

  Future<void> carry(ChatService from, ChatService to) async {
    final rows = await from.vault.db
        .query('outbox', where: 'rid = ?', whereArgs: [to.myRid]);
    await from.vault.db
        .delete('outbox', where: 'rid = ?', whereArgs: [to.myRid]);
    for (final r in rows) {
      await to.debugInbound(RelayInbound(
          id: r['id'] as String,
          from: '',
          payload: r['payload'] as String,
          serverTs: 0));
    }
  }

  test('cold start against the number of contacts', () async {
    final results = <int, int>{};
    for (final n in [10, 100, 400]) {
      final dir = await Directory.systemTemp.createTemp('z_cold_me_$n');
      temps.add(dir);
      final me = await ZIdentity.generate();
      var svc = await makeClient('me', dir: dir, identity: me);
      // n contacts, each with a settled session and one message each way.
      for (var i = 0; i < n; i++) {
        final p = await makeClient('p$i');
        await svc.addContactFromCode(await p.myContactCode());
        await p.addContactFromCode(await svc.myContactCode());
        await svc.sendText(p.myRid, 'hi');
        await carry(svc, p);
        await p.sendText(svc.myRid, 'yo');
        await carry(p, svc);
        p.dispose();
        await p.transport.stop();
      }
      await Future<void>.delayed(const Duration(seconds: 1));
      svc.dispose();
      await svc.transport.stop();
      await svc.vault.db.close();

      // The app is opened again on the same vault.
      final sw = Stopwatch()..start();
      svc = await makeClient('me', dir: dir, identity: me);
      final ms = sw.elapsedMilliseconds;
      results[n] = ms;
      expect(svc.contacts.length, n);
      // ignore: avoid_print
      print('contacts=$n  ChatService.init $ms ms  '
          '(${(ms / n).toStringAsFixed(2)} ms/contact)');
      svc.dispose();
      await svc.transport.stop();
      await svc.vault.db.close();
    }
    // Under 3 ms per contact at four hundred: measured 1.3 on this VM after
    // the fix, 6.3 before it. A regression to one query per contact per key
    // lands well above 3.
    expect(results[400]! / 400, lessThan(3.0),
        reason: 'cold start per contact, 400 contacts: $results');
  }, timeout: const Timeout(Duration(minutes: 10)));
}
