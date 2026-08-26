// Message-list paging (roadmap Phase 4.3).
//
// Seeds a thread with 50,000 messages and proves that opening it loads only
// the newest fixed-size page, quickly, and that older pages walk backwards
// with no duplicates and correct ordering — the data-layer contract behind
// smooth scrolling of huge histories.
@Tags(['integration'])
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

  late Process relay;
  late int port;
  final temps = <Directory>[];
  ChatService? svc;

  setUpAll(() async {
    HttpOverrides.global = null;
    final serverDir =
        '${Directory.current.parent.path}${Platform.pathSeparator}server';
    port = 41000 + DateTime.now().millisecondsSinceEpoch % 20000;
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
    await svc?.transport.stop();
    svc?.dispose();
    relay.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  test('a 50k-message thread pages: fast first load, clean older walks',
      () async {
    final dir = await Directory.systemTemp.createTemp('z_paging');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final identity = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(identity.toJson()));

    // Seed 50k rows in one synthetic group thread. One sealed body is reused
    // for every row (only loaded pages are ever unsealed).
    const total = 50000;
    const gid = 'gPAGINGTHREAD';
    final encBody =
        await vault.seal(jsonEncode({'b': 'hello', 'sn': 'seed'}));
    const base = 1700000000000;
    var inserted = 0;
    while (inserted < total) {
      final batch = vault.db.batch();
      final end = (inserted + 5000).clamp(0, total);
      for (var i = inserted; i < end; i++) {
        batch.insert('messages', {
          'mid': 'm$i',
          'rid': gid,
          'outgoing': i % 2,
          'kind': 'gtext',
          'enc_body': encBody,
          'ts_ms': base + i,
          'status': 2,
          'expire_at_ms': 0,
        });
      }
      await batch.commit(noResult: true);
      inserted = end;
    }

    final transport =
        Transport(identity: identity, serverUrl: 'ws://127.0.0.1:$port');
    svc = await ChatService.init(
        vault: vault, identity: identity, displayName: 'me', transport: transport);

    // First load: one page, newest messages, fast.
    final sw = Stopwatch()..start();
    final page = await svc!.loadMessages(gid);
    sw.stop();
    expect(page.length, ChatService.messagePageSize);
    expect(page.last.mid, 'm${total - 1}', reason: 'newest last');
    expect(page.first.mid, 'm${total - ChatService.messagePageSize}');
    expect(svc!.hasMoreByChat[gid], isTrue);
    expect(sw.elapsedMilliseconds, lessThan(1500),
        reason: 'first page of a 50k thread took ${sw.elapsedMilliseconds}ms');

    // Walk three older pages: sizes, uniqueness, strict ordering.
    for (var p = 0; p < 3; p++) {
      final added = await svc!.loadOlderMessages(gid);
      expect(added, ChatService.messagePageSize);
    }
    final loaded = svc!.messagesByChat[gid]!;
    expect(loaded.length, ChatService.messagePageSize * 4);
    expect(loaded.map((m) => m.mid).toSet().length, loaded.length,
        reason: 'no duplicates across pages');
    for (var i = 1; i < loaded.length; i++) {
      expect(loaded[i].ts, greaterThan(loaded[i - 1].ts),
          reason: 'strictly ascending after prepends');
    }
    expect(loaded.first.mid, 'm${total - ChatService.messagePageSize * 4}');

    // The summary still reflects the newest message.
    expect(loaded.last.mid, 'm${total - 1}');
  }, timeout: const Timeout(Duration(minutes: 3)));
}
