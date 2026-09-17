// Full ratchet state, written to disk unsealed.
//
// `vault.dart` opens by saying what it is: "Every sensitive value (message
// bodies, names, contact bundles, session state, file metadata) is encrypted
// cell-by-cell with XChaCha20-Poly1305 under the master key before it touches
// SQLite." Two `kvPut` calls passed `sensitive: false`, which is an opt-out of
// exactly that, and between them they held the session state.
//
//   `sync_session`     the self-sync ratchet with this account's own devices.
//                      The mirror carries every message the phone sends or
//                      receives.
//   `cextra_<rid>`     the ratchets with each contact's non-primary devices.
//
// Both serialise `RatchetState.toJson()`: `rk` (the root key), `dhsSeed` (the
// ratchet private seed), `cks` and `ckr` (the chain keys) and the cached
// `skipped` message keys. Base64, in a plain SQLite file. Anyone who read
// `z.db` without the vault key could decrypt the self-sync mirror and the
// traffic to every contact's linked devices, and forge mirrors back into the
// user's own devices. AUDIT_SCOPE C11 — "plaintext never touches disk" — was
// false as published.
//
// The repair is not two call sites. It is that "may this be plain?" stopped
// being a judgement made thirty times, at the moment of writing, by whoever
// was there — and became a list, in one place, that `kvPut` enforces and the
// vault applies to what is already on disk. The two keys are the bug; the
// list is the fix, and this is the test the review asked for: one that closes
// the class rather than the instance.
//
// Criteria, each a test below:
//  1. an app driven through everything that writes to the vault leaves NO
//     plaintext key that is not on the declared list — the whole class, from
//     the outside;
//  2. the ratchet state in particular is sealed, and none of the fields that
//     make it ratchet state appears anywhere in the database file;
//  3. a vault that already holds them in the clear is put right when it
//     opens, and the cleartext is gone from the file rather than sitting
//     beside the sealed copy;
//  4. and a key nobody declared cannot be written in the clear at all, so the
//     next `sensitive: false` has to be argued for in the one place the
//     argument belongs;
//  5. and no writer in `lib/` opts out for a key the list does not allow —
//     checked against the source, because criterion 4 is only met on the
//     code path that reaches the write, and for `kt_own_alert` that path was
//     a rogue publish against this account: the one alert the log exists to
//     raise threw on the way to disk, and the check pass aborted with it
//     (the 2026-09-14 review's finding 5). Forty-one call sites; one failed.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/chat_service.dart';
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
      s.dispose();
      await s.transport.stop();
    }
    relay.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<Directory> tempDir(String name) async {
    final d = await Directory.systemTemp.createTemp('z_plain_$name');
    temps.add(d);
    return d;
  }

  Future<ChatService> start(Directory dir, String name,
      {ZIdentity? identity}) async {
    final vault = await Vault.open(rootOverride: dir);
    final stored = await vault.kvGet('identity');
    final id = identity ??
        (stored == null
            ? await ZIdentity.generate()
            : await ZIdentity.fromJson(
                (jsonDecode(stored) as Map).cast<String, Object?>()));
    await vault.kvPut('identity', jsonEncode(id.toJson()));
    final svc = await ChatService.init(
        vault: vault,
        identity: id,
        displayName: name,
        transport: Transport(identity: id, serverUrl: 'ws://127.0.0.1:$port'));
    live.add(svc);
    return svc;
  }

  Future<void> waitUntil(bool Function() cond,
      {Duration timeout = const Duration(seconds: 25), String what = ''}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw StateError('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 30));
    }
  }

  /// Every key currently stored in the clear.
  Future<List<String>> plainKeysIn(Vault v) async => [
        for (final r in await v.db.query('kv', columns: ['k']))
          if ((r['k'] as String).startsWith('p:')) (r['k'] as String).substring(2)
      ];

  String rawDb(Directory dir) => utf8
      .decode(File('${dir.path}/z.db').readAsBytesSync(), allowMalformed: true);

  test('1. an app that has done everything leaves no undeclared plaintext',
      () async {
    final aliceDir = await tempDir('a');
    final alice = await start(aliceDir, 'Alice');
    final bob = await start(await tempDir('b'), 'Bob');
    await waitUntil(() => alice.transport.isConnected && bob.transport.isConnected,
        what: 'connected');
    await alice.addContactFromCode(await bob.myContactCode());
    await bob.addContactFromCode(await alice.myContactCode());
    await Future<void>.delayed(const Duration(milliseconds: 600));

    // Exercise the paths that write to the vault: a message, a reply, a
    // reaction, an attachment, a group, a relay change, the device id.
    await alice.sendText(bob.myRid, 'the first one');
    await waitUntil(() => (bob.messagesByChat[alice.myRid] ?? []).isNotEmpty,
        what: 'bob has it');
    final mid = bob.messagesByChat[alice.myRid]!.first.mid;
    await bob.sendText(alice.myRid, 'and a reply', replyTo: mid);
    await bob.toggleReaction(alice.myRid, mid, '👍');
    await alice.sendFile(bob.myRid, 'notes.csv',
        Uint8List.fromList(List<int>.filled(2048, 3)), 'text/csv');
    final gid = await alice.createGroup('Field team', [bob.myRid]);
    await alice.sendGroupText(gid, 'meeting moved');
    await alice.setDevMode(true);
    await alice.deviceId();
    await waitUntil(
        () => (alice.messagesByChat[gid] ?? []).isNotEmpty, what: 'group row');
    await Future<void>.delayed(const Duration(seconds: 2));

    for (final v in [alice.vault, bob.vault]) {
      final plain = await plainKeysIn(v);
      final undeclared = plain.where((k) => !Vault.mayBePlain(k)).toList();
      expect(undeclared, isEmpty,
          reason: 'stored in the clear and on no list: $undeclared');
      expect(plain, isNotEmpty, reason: 'and the class is in use at all');
    }
  });

  test('2. the ratchet state is sealed, field by field', () async {
    final aliceDir = await tempDir('r');
    final alice = await start(aliceDir, 'Alice');
    final bob = await start(await tempDir('rb'), 'Bob');
    await waitUntil(() => alice.transport.isConnected && bob.transport.isConnected,
        what: 'connected');
    await alice.addContactFromCode(await bob.myContactCode());
    await bob.addContactFromCode(await alice.myContactCode());
    await Future<void>.delayed(const Duration(milliseconds: 600));
    await alice.sendText(bob.myRid, 'establishes a ratchet');
    await waitUntil(() => (bob.messagesByChat[alice.myRid] ?? []).isNotEmpty,
        what: 'a session exists');
    await Future<void>.delayed(const Duration(seconds: 1));

    for (final k in ['sync_session']) {
      expect(Vault.mayBePlain(k), isFalse, reason: '$k may not be plain');
    }
    expect(Vault.mayBePlain('cextra_${bob.myRid}'), isFalse);

    // The serialised field names of RatchetState. If any of these is in the
    // file, a ratchet is in the file.
    final db = rawDb(aliceDir);
    for (final field in ['"rk"', '"dhsSeed"', '"cks"', '"ckr"', '"skipped"']) {
      expect(db, isNot(contains(field)),
          reason: 'a ratchet field is in the database in the clear: $field');
    }
  });

  test('3. a vault that already holds them in the clear is put right',
      () async {
    final dir = await tempDir('old');
    final v = await Vault.open(rootOverride: dir);
    // Exactly what a build before 2026-09-14 wrote. Through the db, because
    // `kvPut` now refuses to write it.
    const ratchet =
        '{"convs":{"dev1":{"rk":"UkVEQUNURUQ=","dhsSeed":"U0VFRA==","cks":null}}}';
    for (final k in ['p:sync_session', 'p:cextra_somerid', 'p:dev_mode']) {
      await v.db.insert('kv', {'k': k, 'v': k.startsWith('p:dev') ? '1' : ratchet});
    }
    expect(rawDb(dir), contains('dhsSeed'), reason: 'it really was in there');
    await v.db.close();

    final again = await Vault.open(rootOverride: dir);
    expect(await again.kvGet('sync_session'), ratchet,
        reason: 'the value is still readable');
    expect(await again.kvGet('cextra_somerid'), ratchet);
    expect(await again.kvGet('dev_mode'), '1', reason: 'a declared one is left');
    final plain = await plainKeysIn(again);
    expect(plain, ['dev_mode'],
        reason: 'and only the declared one is still in the clear: $plain');
    expect(rawDb(dir), isNot(contains('dhsSeed')),
        reason: 'the cleartext went with the rewrite rather than sitting '
            'beside the sealed copy');
    await again.db.close();
  });

  test('4. an undeclared key cannot be written in the clear', () async {
    final v = await Vault.open(rootOverride: await tempDir('refuse'));
    for (final k in [
      'sync_session',
      'cextra_abc',
      'identity',
      'display_name',
      'pq_seed',
      'something_new',
      'cdev_', // a prefix with nothing after it is not a member of the family
    ]) {
      await expectLater(v.kvPut(k, 'x', sensitive: false), throwsArgumentError,
          reason: k);
    }
    // And the declared ones still work, exactly and by family.
    await v.kvPut('server_url', 'wss://example', sensitive: false);
    await v.kvPut('cdev_abc', 'list', sensitive: false);
    expect(await v.kvGet('server_url'), 'wss://example');
    expect(await v.kvGet('cdev_abc'), 'list');
    await v.db.close();
  });

  test('5. every writer that opts out names a key the list allows', () async {
    // Each `kvPut(<key>, ..., sensitive: false)` in lib/: the key is a
    // literal, a literal with a routing id interpolated (a family), or a
    // `_kName` constant declared in the same file. Anything else is a call
    // this scan cannot judge, and it fails rather than passes.
    final call = RegExp(r'kvPut\(\s*([^,]+),', multiLine: true);
    final constDecl = RegExp(r"static const ([A-Za-z_]\w*) = '([^']*)';");
    var sites = 0;
    final bad = <String>[];
    for (final f in Directory('lib').listSync(recursive: true).whereType<File>()) {
      if (!f.path.endsWith('.dart')) continue;
      final src = f.readAsStringSync();
      final consts = {for (final m in constDecl.allMatches(src)) m.group(1)!: m.group(2)!};
      for (final m in call.allMatches(src)) {
        // The rest of the call, to see whether it opts out.
        final tail = src.substring(m.end, (m.end + 400).clamp(0, src.length));
        final close = tail.indexOf(');');
        final args = close < 0 ? tail : tail.substring(0, close);
        if (!args.contains('sensitive: false')) continue;
        sites++;
        final expr = m.group(1)!.trim();
        String? key;
        final lit = RegExp(r"^r?'([^']*)'$").firstMatch(expr);
        if (lit != null) {
          // `'family_$rid'` / `'family_${x.rid}'`: the family with something after.
          key = lit.group(1)!.replaceAll(RegExp(r'\$\{[^}]*\}|\$\w+'), 'x');
        } else if (consts.containsKey(expr)) {
          key = consts[expr];
        }
        if (key == null) {
          bad.add('${f.path}: cannot judge `$expr`');
        } else if (!Vault.mayBePlain(key)) {
          bad.add('${f.path}: `$expr` opts out of sealing for `$key`, which Vault.plainKeys does not allow — kvPut throws there');
        }
      }
    }
    expect(sites, greaterThan(30), reason: 'the scan found the opt-outs ($sites)');
    expect(bad, isEmpty, reason: bad.join('\n'));
  });
}
