// Transparency lookups that do not hand over the contact list (phase 35;
// ADR 0023's client policy, PROTOCOL §19.9.1, THREAT_MODEL R40) — against
// the real log (kt/server.js), filled to 2,100 labels so that it recommends
// 64 buckets, and the real relay, with every request each client makes to
// the log recorded by a proxy of its own in front of it. The rules on their
// own — what k a count of labels allows, and coming back to the front — are
// in `kt_lookup_rules_test.dart`.
//
// Criteria, each a test below:
//   1. a refresh never asks for a contact's exact label: no request a client
//      makes names a contact's label — in a path, a query or a body — while
//      that contact is checked and confirmed;
//   2. one request carries every bucket: a refresh makes one
//      `POST /kt/v1/buckets`, holding the bucket of every contact at the k
//      the log recommends, padded to sixteen;
//   3. a recommendation finer than the labels the client counted is not
//      followed: against a log whose size many versions of a few accounts
//      have inflated, a `bucketBits` of 24 is asked no finer than a bit past
//      the log's honest recommendation, from a fresh install's first refresh
//      on;
//   4. the decoy set is identical across refreshes and across a restart;
//   5. the count of buckets asked does not depend on the number of
//      contacts, up to the padding: none, one and three contacts all ask
//      sixteen; a contact added inside the asked buckets changes nothing
//      asked, and a contact removed takes no bucket away; a contact outside
//      them arrives in a block of sixteen;
//   6. a split view is still caught through the bucket path: an entry at the
//      held version with another fingerprint is a conflict that holds sends,
//      and a bucket answer with a label left out is a log fault;
//   7. a contact's new version is fetched among every entry in the asked
//      buckets the client had not seen, made up to sixteen with others from
//      them — and those are fetched when no contact moved too; a contact
//      whose entry the client had already seen is fetched with every entry
//      in the asked buckets;
//   8. no refresh at start, and none right after a contact's list changes;
//      the scheduled refresh comes at its random moment; and a contact whose
//      list has not changed since is not checked again from its screen;
//   9. the verification screen's explicit check, for a contact whose list
//      changed, is a refresh of the same shape — every bucket and decoy, no
//      label;
//  10. a log that refuses buckets is unreachable to the client, which asks
//      no label by name instead;
//  11. the schedule: never sooner than `catchUpMin` from now, so never at
//      start; a client overdue catches up between `catchUpMin` and
//      `catchUpMax`; otherwise one refresh in each window, at a moment kept
//      across a restart;
//  12. the decoy plan: padded to blocks of sixteen and stable; a bucket that
//      lost its contact stays; a coarser or finer k maps every bucket to its
//      own ancestor or descendant; a stored set that is not one is refused;
//      k is never finer than the recommendation, the signed size or the
//      ceiling the client's counts set, and the decoy buckets' counts move
//      that ceiling down at once, up a bit at a time, and not at all while
//      buckets at it hold 16 to 64;
//  13. entry decoys: the same fetch whether or not a contact needs one of
//      the entries new to the client — every new one, made up to sixteen;
//      every entry in the asked buckets when a needed one is not among them,
//      and with no last refresh; past the cap, the needed ones and a sample
//      keyed by them — the same when asked again, and two fetches that need
//      different entries never single either out by their difference;
//  14. a scheduled refresh the app slept through is not run when it wakes —
//      which would be a refresh at start by another door — but caught up
//      between `catchUpMin` and `catchUpMax` later;
//  15. the contact screen's refresh, run because a contact's list changed,
//      fetches every entry new in the asked buckets among no fewer than
//      sixteen from them — never the contact's entry alone;
//  16. a restore's first refresh fetches every entry in its buckets, as the
//      first refresh of the install it came from did: the two set side by
//      side name no contact; and it asks the same buckets, at the ceiling
//      the backup carried, without counting the log's labels again;
//  17. a window's moment the app was not running for, after a refresh in an
//      earlier window, is caught up between `catchUpMin` and `catchUpMax`
//      after the app starts — not drawn again for later in the window;
//  18. a phone used in short visits still refreshes: over thirty simulated
//      days of twelve half-minute visits, the shipped schedule runs at least
//      two refreshes a day, none sooner than `catchUpMin` after the app came
//      to the front.
@Tags(['integration'])
@Timeout(Duration(minutes: 3))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;
import 'package:provider/provider.dart';
import 'package:zapp/core/archive.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/key_transparency.dart';
import 'package:zapp/core/kt_private_lookups.dart';
import 'package:zapp/core/restore.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/ui/contact_info_screen.dart';
import 'package:zapp/ui/theme.dart';
import 'package:z_protocol/z_protocol.dart';

/// One request a client made to the log, as the proxy in front of it saw it.
class _Seen {
  final String method;
  final String path;
  final String query;
  final String body;
  final int atMs;
  _Seen(this.method, this.path, this.query, this.body, this.atMs);

  bool mentions(String needle) =>
      path.contains(needle) || query.contains(needle) || body.contains(needle);

  bool get isPublish => method == 'POST' && path == '/kt/v1/publish';
  bool get isBuckets => method == 'POST' && path == '/kt/v1/buckets';
  bool get isEntries => method == 'POST' && path == '/kt/v1/entries';

  /// The buckets a `POST /kt/v1/buckets` asked, as `prefix/bits`.
  List<String> get buckets => [
        for (final b in (jsonDecode(body) as Map)['buckets'] as List)
          '${(b as Map)['prefix']}/${b['bits']}'
      ];

  /// The indexes a `POST /kt/v1/entries` asked.
  List<int> get indexes => [
        for (final i in (jsonDecode(body) as Map)['indexes'] as List)
          (i as num).toInt()
      ];

  @override
  String toString() => '$method $path${query.isEmpty ? '' : '?$query'}';
}

/// A proxy in front of the real log that remembers every request one client
/// makes and forwards it — unchanged, unless a test tampers with it or
/// refuses it.
class _Recorder {
  final int upstream;
  final List<_Seen> seen = [];
  late final HttpServer _server;

  /// Rewrites the log's answer to a request, or leaves it (returns null).
  String? Function(_Seen req, String answer)? tamper;

  /// Answers a request itself, with this status, instead of the log.
  int? Function(_Seen req)? refuse;

  _Recorder(this.upstream);

  int get port => _server.port;

  List<_Seen> get bucketPosts => [for (final r in seen) if (r.isBuckets) r];
  List<_Seen> get entriesPosts => [for (final r in seen) if (r.isEntries) r];

  /// The log's answers to `POST /kt/v1/buckets`, as the client received
  /// them — the entries a refresh saw in its buckets, whatever happened in
  /// the log after.
  final List<String> bucketAnswers = [];

  /// Every entry index in the buckets of the last answer to a
  /// `POST /kt/v1/buckets` — one refresh's, while it asks 64 or fewer.
  Set<int> leavesAnswered() {
    final answer = bucketAnswers.last;
    return {
      for (final b in (jsonDecode(answer) as Map)['buckets'] as List)
        for (final l in (b as Map)['leaves'] as List) (l as Map)['index'] as int
    };
  }

  /// Everything but publishing: what a check asks.
  List<_Seen> get reads => [for (final r in seen) if (!r.isPublish) r];

  Future<void> start() async {
    _server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    _server.listen(_serve);
  }

  Future<void> close() => _server.close(force: true);

  Future<void> _serve(HttpRequest req) async {
    try {
      final body = await utf8.decoder.bind(req).join();
      final r = _Seen(req.method, req.uri.path, req.uri.query, body,
          DateTime.now().millisecondsSinceEpoch);
      seen.add(r);
      final refused = refuse?.call(r);
      if (refused != null) {
        req.response.statusCode = refused;
        req.response.headers.contentType = ContentType.json;
        req.response.write('{"error":"not_found","message":"refused"}');
        await req.response.close();
        return;
      }
      final target = Uri.parse('http://127.0.0.1:$upstream${req.uri}');
      final client = HttpClient();
      try {
        final out = req.method == 'POST'
            ? (await client.postUrl(target)
              ..headers.contentType = ContentType.json
              ..write(body))
            : await client.getUrl(target);
        final res = await out.close();
        var text = await utf8.decoder.bind(res).join();
        if (res.statusCode == 200) text = tamper?.call(r, text) ?? text;
        if (res.statusCode == 200 && r.isBuckets) bucketAnswers.add(text);
        req.response.statusCode = res.statusCode;
        req.response.headers.contentType = ContentType.json;
        req.response.write(text);
      } finally {
        client.close(force: true);
      }
      await req.response.close();
    } catch (_) {
      try {
        req.response.statusCode = 502;
        await req.response.close();
      } catch (_) {}
    }
  }
}

Future<int> freePort() async {
  final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final port = probe.port;
  await probe.close();
  return port;
}

Future<void> waitHealthy(int port) async {
  final deadline = DateTime.now().add(const Duration(seconds: 20));
  while (true) {
    try {
      final res = await (await HttpClient()
              .getUrl(Uri.parse('http://127.0.0.1:$port/health')))
          .close();
      await res.drain<void>();
      if (res.statusCode == 200) return;
    } catch (_) {}
    if (DateTime.now().isAfter(deadline)) fail('service on $port did not start');
    await Future<void>.delayed(const Duration(milliseconds: 100));
  }
}

String hexOf(List<int> b) =>
    [for (final x in b) x.toRadixString(16).padLeft(2, '0')].join();

/// Publishes [count] accounts nobody holds into the log on [port], so that
/// the log has enough labels to recommend buckets finer than the whole map
/// (`bucketBits` = 6 at 2,100 labels: 64 buckets of about 33). Node's
/// Ed25519 makes this a second or two.
const String _fillScript = r'''
const http = require('http');
const crypto = require('crypto');
const { makePublish, privateKeyFromSeed, rawPublicKey, sealValue } = require('./lib/log.js');
const port = +process.argv[1];
const count = +process.argv[2];
function post(body) {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(body));
    const req = http.request({ host: '127.0.0.1', port, path: '/kt/v1/publish', method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': data.length } }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => (res.statusCode === 201 ? resolve() : reject(new Error(`${res.statusCode} ${Buffer.concat(chunks)}`))));
    });
    req.on('error', reject);
    req.end(data);
  });
}
(async () => {
  let next = 0;
  async function worker() {
    while (next < count) {
      const i = next++;
      const key = privateKeyFromSeed(crypto.createHash('sha256').update(`filler:${i}`).digest());
      const pub = rawPublicKey(key);
      const p = makePublish(key, { version: 1, fp: crypto.randomBytes(16), value: sealValue(pub, Buffer.from('{}')) });
      await post({ acct: p.acct.toString('base64'), v: p.version, fp: p.fp.toString('base64'),
        value: p.value.toString('base64'), sig: p.sig.toString('base64') });
    }
  }
  await Promise.all(Array.from({ length: 8 }, worker));
  process.exit(0);
})().catch((e) => { console.error(e.message); process.exit(1); });
''';

/// Grows the log on [port]'s signed size without growing its labels:
/// [accounts] accounts publish [versions] versions of their own list each,
/// as anyone holding an account key — its operator first — may (review B of
/// 2026-10-09, finding 2; criterion 3).
const String _versionsScript = r'''
const http = require('http');
const crypto = require('crypto');
const { makePublish, privateKeyFromSeed, rawPublicKey, sealValue } = require('./lib/log.js');
const port = +process.argv[1];
const accounts = +process.argv[2];
const versions = +process.argv[3];
function post(body) {
  return new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify(body));
    const req = http.request({ host: '127.0.0.1', port, path: '/kt/v1/publish', method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': data.length } }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => (res.statusCode === 201 ? resolve() : reject(new Error(`${res.statusCode} ${Buffer.concat(chunks)}`))));
    });
    req.on('error', reject);
    req.end(data);
  });
}
(async () => {
  await Promise.all(Array.from({ length: accounts }, async (_, a) => {
    const key = privateKeyFromSeed(crypto.createHash('sha256').update(`versions:${a}`).digest());
    const value = sealValue(rawPublicKey(key), Buffer.from('{}'));
    for (let v = 1; v <= versions; v++) {
      const p = makePublish(key, { version: v, fp: crypto.randomBytes(16), value });
      await post({ acct: p.acct.toString('base64'), v: p.version, fp: p.fp.toString('base64'),
        value: p.value.toString('base64'), sig: p.sig.toString('base64') });
    }
  }));
  process.exit(0);
})().catch((e) => { console.error(e.message); process.exit(1); });
''';

/// A client with nothing in it: criterion 14 is about whether a request is
/// made at all.
class _NoHost implements KtHost {
  @override
  Future<List<KtContactInput>> ktContacts() async => const [];
  @override
  Future<KtOwnInput?> ktOwn() async => null;
  @override
  Future<bool> ktInstallFromLog(String rid, SignedDeviceList list) async =>
      false;
  @override
  void ktChanged() {}
}

/// Remembers every request and answers each with a failure.
class _CountingFetcher implements KtFetcher {
  final List<Uri> asked = [];
  @override
  Future<KtResponse> get(Uri url) async {
    asked.add(url);
    return KtResponse(500, '{}');
  }

  @override
  Future<KtResponse> post(Uri url, String jsonBody) async {
    asked.add(url);
    return KtResponse(500, '{}');
  }
}

/// A seeded source for the decoy plan's unit tests.
Uint8List Function(int) seededBytes(int seed) {
  final r = Random(seed);
  return (n) => Uint8List.fromList(List<int>.generate(n, (_) => r.nextInt(256)));
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  final root = Directory.current.parent.path;
  late Process relay;
  late int relayPort;
  late Process log;
  late int logPort;
  late Uint8List logPub;
  final logSeed =
      Uint8List.fromList(List<int>.generate(32, (i) => (i * 11 + 5) & 0xff));
  final temps = <Directory>[];
  final services = <ChatService>[];
  final recorders = <_Recorder>[];

  setUpAll(() async {
    HttpOverrides.global = null;
    relayPort = await freePort();
    relay = await Process.start('node', ['server.js'],
        workingDirectory: '$root${Platform.pathSeparator}server',
        environment: {'PORT': '$relayPort', 'LOG_LEVEL': 'silent'});
    relay.stderr.drain<void>();
    relay.stdout.drain<void>();
    await waitHealthy(relayPort);
    logPort = await freePort();
    log = await Process.start('node', ['server.js'],
        workingDirectory: '$root${Platform.pathSeparator}kt',
        environment: {
          'KT_SEED': hexOf(logSeed),
          'KT_EPHEMERAL': '1',
          'KT_PORT': '$logPort',
          // Every publish gate out of the way: the filler below is two
          // thousand first publishes from one address in a second or two.
          'PUBLISH_PER_MIN': '1000000',
          'PUBLISH_PER_MIN_TOTAL': '1000000',
          'PUBLISH_PER_ACCT_PER_DAY': '1000000',
          'PUBLISH_NEW_ACCOUNTS_PER_MIN': '1000000',
          'PUBLISH_NEW_ACCOUNTS_PER_ADDR_PER_MIN': '1000000',
        });
    log.stderr.drain<void>();
    log.stdout.drain<void>();
    await waitHealthy(logPort);
    final fill = await Process.run(
        'node', ['-e', _fillScript, '$logPort', '2100'],
        workingDirectory: '$root${Platform.pathSeparator}kt');
    expect(fill.exitCode, 0, reason: 'filling the log: ${fill.stderr}');
    final kp = await Ed25519().newKeyPairFromSeed(logSeed);
    logPub = Uint8List.fromList((await kp.extractPublicKey()).bytes);
  });

  tearDownAll(() async {
    for (final s in services) {
      s.dispose();
      await s.transport.stop();
    }
    for (final r in recorders) {
      await r.close();
    }
    relay.kill();
    log.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<void> waitUntil(FutureOr<bool> Function() cond,
      {Duration timeout = const Duration(seconds: 30),
      required String what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 30));
    }
  }

  Future<Map<String, Object?>> logGet(String path) async {
    final res = await (await HttpClient()
            .getUrl(Uri.parse('http://127.0.0.1:$logPort$path')))
        .close();
    return (jsonDecode(await utf8.decoder.bind(res).join()) as Map)
        .cast<String, Object?>();
  }

  /// The log's own answer for a label — the test harness asking, not a
  /// client: the entry's index and version, or null.
  Future<(int, int)?> logLatest(Uint8List label) async {
    final j = await logGet('/kt/v1/lookup/${hexOf(label)}');
    final e = j['entry'];
    if (e == null) return null;
    return ((e as Map)['index'] as int, e['v'] as int);
  }

  /// A client whose every request to the log goes through a recorder of its
  /// own, so what it asked is exactly what that recorder saw. [scheduled]:
  /// whether its refreshes run on their own clock (the test checks when it
  /// says so otherwise). [identity]: the identity to start with. [log]: a
  /// log other than the fixture's, as (port, key).
  Future<(ChatService, _Recorder)> start(String name,
      {Directory? dir,
      bool scheduled = false,
      ZIdentity? identity,
      (int, Uint8List)? log}) async {
    final rec = _Recorder(log?.$1 ?? logPort);
    await rec.start();
    recorders.add(rec);
    final home = dir ?? await Directory.systemTemp.createTemp('z_ktp_$name');
    if (dir == null) temps.add(home);
    final vault = await Vault.open(rootOverride: home);
    final stored = await vault.kvGet('identity');
    final id = stored == null
        ? identity ?? await ZIdentity.generate()
        : await ZIdentity.fromJson(
            (jsonDecode(stored) as Map).cast<String, Object?>());
    if (stored == null) await vault.kvPut('identity', jsonEncode(id.toJson()));
    final svc = await ChatService.init(
        vault: vault,
        identity: id,
        displayName: name,
        transport:
            Transport(identity: id, serverUrl: 'ws://127.0.0.1:$relayPort'),
        ktConfig: KtConfig(
            logUrl: 'http://127.0.0.1:${rec.port}',
            logPubB64: b64(log?.$2 ?? logPub)));
    if (!scheduled) svc.kt.scheduled = false;
    services.add(svc);
    return (svc, rec);
  }

  Future<void> stop(ChatService svc) async {
    await svc.kt.check(); // nothing in flight against a vault about to close
    services.remove(svc);
    svc.dispose();
    await svc.transport.stop();
    await svc.vault.db.close();
  }

  Future<void> befriend(ChatService a, ChatService b) async {
    await waitUntil(() => a.transport.isConnected && b.transport.isConnected,
        what: 'connected');
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
    final hi = 'hi ${b.myRid.substring(0, 6)}';
    final back = 'hi ${a.myRid.substring(0, 6)}';
    await a.sendText(b.myRid, hi);
    await b.sendText(a.myRid, back);
    await waitUntil(
        () =>
            (a.messagesByChat[b.myRid] ?? const []).any((m) => m.body == back) &&
            (b.messagesByChat[a.myRid] ?? const []).any((m) => m.body == hi),
        what: 'a first exchange');
  }

  /// One more round trip between [a] and [b]: an observable that takes the
  /// relay and both clients' inbound paths, which a test waits on before it
  /// says what did NOT happen meanwhile.
  Future<void> roundTrip(ChatService a, ChatService b, String tag) async {
    await a.sendText(b.myRid, 'ping $tag');
    await waitUntil(
        () => (b.messagesByChat[a.myRid] ?? const [])
            .any((m) => m.body == 'ping $tag'),
        what: 'ping $tag');
    await b.sendText(a.myRid, 'pong $tag');
    await waitUntil(
        () => (a.messagesByChat[b.myRid] ?? const [])
            .any((m) => m.body == 'pong $tag'),
        what: 'pong $tag');
  }

  Future<void> heldVersion(ChatService svc, String rid, int v) => waitUntil(
      () async => await svc.heldContactListVersion(rid) >= v,
      what: 'the held list reaching v$v');

  Future<void> linkLaptop(ChatService svc) async {
    final acct = await svc.accountIdentity();
    final laptop = await ZIdentity.generate();
    await svc.addMyDevice(await acct.signDeviceCert(
        deviceEdPub: laptop.edPub, deviceXPub: laptop.xPub, deviceId: 'laptop'));
  }

  Future<Uint8List> labelBytes(ChatService svc) async =>
      ktLabel((await svc.accountIdentity()).accountEdPub);

  /// The label of [svc]'s account, as hex and as base64 — the two spellings
  /// a request could carry it in.
  Future<(String, String)> labelOf(ChatService svc) async {
    final label = await labelBytes(svc);
    return (hexOf(label), b64(label));
  }

  /// A fresh identity whose account label's bucket at [bits] is ([inside])
  /// or is not in [asked] (`prefix/bits` strings).
  Future<ZIdentity> identityWhere(List<String> asked, int bits,
      {required bool inside}) async {
    final set = asked.toSet();
    while (true) {
      final id = await ZIdentity.generate();
      final p = '${ktBucketPrefix(await ktLabel(id.edPub), bits)}/$bits';
      if (set.contains(p) == inside) return id;
    }
  }

  /// Publishes [n] new accounts whose labels fall in [asked]; their indexes.
  Future<List<int>> mintInBuckets(List<String> asked, int bits, int n) async {
    final out = <int>[];
    while (out.length < n) {
      final id = await identityWhere(asked, bits, inside: true);
      final seed = id.edSeed;
      final req = await ktPublishRequest(
          accountEdSeed: seed,
          version: 1,
          fp: randomBytes(16),
          value: await ktSealValue(id.edPub, utf8.encode('{}')));
      final res = await (await HttpClient().postUrl(
              Uri.parse('http://127.0.0.1:$logPort/kt/v1/publish'))
            ..headers.contentType = ContentType.json
            ..write(jsonEncode(req)))
          .close();
      final j = jsonDecode(await utf8.decoder.bind(res).join()) as Map;
      expect(res.statusCode, 201, reason: '$j');
      out.add(j['index'] as int);
    }
    return out;
  }

  /// The log's recommendation right now, read by the harness.
  Future<int> recommendedBits() async => (await logGet('/kt/v1/sth'))['bucketBits'] as int;

  /// A log of its own for one test — [labels] accounts, and [accounts]
  /// more that publish [versions] versions each — as (port, key); stopped
  /// when the test ends.
  Future<(int, Uint8List)> anotherLog(
      {required int labels, int accounts = 0, int versions = 0}) async {
    final seed =
        Uint8List.fromList(List<int>.generate(32, (i) => (i * 13 + 7) & 0xff));
    final port = await freePort();
    final p = await Process.start('node', ['server.js'],
        workingDirectory: '$root${Platform.pathSeparator}kt',
        environment: {
          'KT_SEED': hexOf(seed),
          'KT_EPHEMERAL': '1',
          'KT_PORT': '$port',
          'PUBLISH_PER_MIN': '100000000',
          'PUBLISH_PER_MIN_TOTAL': '100000000',
          'PUBLISH_PER_ACCT_PER_DAY': '100000000',
          'PUBLISH_NEW_ACCOUNTS_PER_MIN': '100000000',
          'PUBLISH_NEW_ACCOUNTS_PER_ADDR_PER_MIN': '100000000',
        });
    addTearDown(p.kill);
    p.stderr.drain<void>();
    p.stdout.drain<void>();
    await waitHealthy(port);
    final fill = await Process.run(
        'node', ['-e', _fillScript, '$port', '$labels'],
        workingDirectory: '$root${Platform.pathSeparator}kt');
    expect(fill.exitCode, 0, reason: 'filling the log: ${fill.stderr}');
    if (accounts > 0) {
      final grow = await Process.run(
          'node', ['-e', _versionsScript, '$port', '$accounts', '$versions'],
          workingDirectory: '$root${Platform.pathSeparator}kt');
      expect(grow.exitCode, 0, reason: 'versions: ${grow.stderr}');
    }
    final kp = await Ed25519().newKeyPairFromSeed(seed);
    return (port, Uint8List.fromList((await kp.extractPublicKey()).bytes));
  }

  /// The labels in each bucket a `POST /kt/v1/buckets` asked, as the log on
  /// [port] holds them now — the harness asking, not a client.
  Future<List<int>> bucketCounts(int port, List<String> asked) async {
    final out = <int>[];
    for (final b in asked) {
      final [prefix, bits] = b.split('/');
      final res = await (await HttpClient().getUrl(Uri.parse(
              'http://127.0.0.1:$port/kt/v1/bucket?prefix=$prefix&bits=$bits')))
          .close();
      final j = jsonDecode(await utf8.decoder.bind(res).join()) as Map;
      out.add((j['leaves'] as List).length);
    }
    return out;
  }

  test('1. a refresh never asks for a contact\'s exact label', () async {
    final (alice, aliceLog) = await start('alice1');
    final (ben, _) = await start('ben1');
    final (cleo, _) = await start('cleo1');
    await befriend(alice, ben);
    await befriend(alice, cleo);
    // Each account's own list reaches the log; then Alice checks.
    await ben.kt.check();
    await cleo.kt.check();
    await alice.kt.check();
    await alice.kt.check();
    expect(alice.kt.statusOf(ben.myRid)?.state, KtContactState.confirmed,
        reason: 'Ben was checked against the log');
    expect(alice.kt.statusOf(cleo.myRid)?.state, KtContactState.confirmed,
        reason: 'and Cleo');
    final (benHex, benB64) = await labelOf(ben);
    final (cleoHex, cleoB64) = await labelOf(cleo);
    final named = [
      for (final r in aliceLog.seen)
        if (r.mentions(benHex) ||
            r.mentions(benB64) ||
            r.mentions(cleoHex) ||
            r.mentions(cleoB64))
          r
    ];
    expect(named, isEmpty,
        reason: 'no request Alice made names a contact\'s label');
  });

  test('2. one request carries every bucket', () async {
    final (dan, danLog) = await start('dan2');
    final (eve, _) = await start('eve2');
    final (fay, _) = await start('fay2');
    await befriend(dan, eve);
    await befriend(dan, fay);
    await eve.kt.check();
    await fay.kt.check();
    await dan.kt.check(); // the first: every contact's entry fetched
    danLog.seen.clear();
    await dan.kt.check();
    final posts = danLog.bucketPosts;
    expect(posts, hasLength(1), reason: 'one request per refresh');
    final asked = posts.single.buckets;
    final k = await recommendedBits();
    expect(k, 6, reason: 'the fixture: 2,100 labels, 64 buckets of about 33');
    expect(asked.every((b) => b.endsWith('/$k')), isTrue,
        reason: 'at the k the log recommends');
    expect(asked, hasLength(ktDecoyBlock), reason: 'padded to sixteen');
    for (final c in [eve, fay]) {
      expect(asked, contains('${ktBucketPrefix(await labelBytes(c), k)}/$k'),
          reason: '${c.displayName}\'s bucket is one of them');
    }
    expect(dan.kt.statusOf(eve.myRid)?.state, KtContactState.confirmed);
    expect(dan.kt.statusOf(fay.myRid)?.state, KtContactState.confirmed);
  });

  test(
      '3. a recommendation finer than the labels the client counted is not '
      'followed, however many versions the size counts', () async {
    // A log of 300 accounts, eight of which have published a thousand
    // versions each: its signed size passes 8,000 entries, which allows
    // k = 8 by ⌊log₂(size / 32)⌋, while its labels allow k = 3 — 32 to 64
    // labels a bucket. Its operator then says 24 (review B of 2026-10-09,
    // finding 2, with fewer labels and fewer versions).
    final other = await anotherLog(labels: 300, accounts: 8, versions: 1000);
    final (otherPort, _) = other;
    Future<Map<String, Object?>> ask(String path) async {
      final res = await (await HttpClient()
              .getUrl(Uri.parse('http://127.0.0.1:$otherPort$path')))
          .close();
      return (jsonDecode(await utf8.decoder.bind(res).join()) as Map)
          .cast<String, Object?>();
    }

    final health = await ask('/health');
    final honest = (await ask('/kt/v1/sth'))['bucketBits'] as int;
    expect(health['size'] as int, greaterThan(8000),
        reason: 'the versions are entries the size counts');
    expect(honest, 3, reason: 'about 300 labels: 8 buckets of 32 to 64');
    final (gil, gilLog) = await start('gil3', log: other); // a fresh install
    final (hal, _) = await start('hal3', log: other);
    await befriend(gil, hal);
    await hal.kt.check();
    gilLog.tamper = (req, answer) {
      if (req.path != '/kt/v1/sth') return null;
      final j = (jsonDecode(answer) as Map).cast<String, Object?>();
      j['bucketBits'] = 24;
      return jsonEncode(j);
    };
    final halLabel = await labelBytes(hal);
    for (var r = 1; r <= 3; r++) {
      gilLog.seen.clear();
      await gil.kt.check();
      final asked = gilLog.bucketPosts.expand((p) => p.buckets).toList();
      expect(asked, isNotEmpty, reason: 'refresh $r asked buckets');
      final k = int.parse(asked.first.split('/').last);
      final counts = await bucketCounts(otherPort, asked);
      final halBucket = '${ktBucketPrefix(halLabel, k)}/$k';
      final halCount = counts[asked.indexOf(halBucket)];
      // Printed for the record: what a bucket hid Hal among.
      // ignore: avoid_print
      print('criterion 3, refresh $r: k = $k; ${asked.length} buckets of '
          '$counts labels; Hal\'s holds $halCount');
      expect(asked.every((b) => b.endsWith('/$k')), isTrue);
      expect(k, lessThanOrEqualTo(honest + 1),
          reason: 'refresh $r: no finer than a bit past what the labels '
              'bear out, whatever the size and bucketBits say');
    }
    expect(gil.kt.statusOf(hal.myRid)?.state, KtContactState.confirmed);
  });

  test('4. the decoy set is identical across refreshes and across a restart',
      () async {
    final home = await Directory.systemTemp.createTemp('z_ktp_ida4');
    temps.add(home);
    final (ida, idaLog) = await start('ida4', dir: home);
    final (jon, _) = await start('jon4');
    await befriend(ida, jon);
    await jon.kt.check();
    await ida.kt.check();
    await ida.kt.check();
    await ida.kt.check();
    final asked = [for (final p in idaLog.bucketPosts) p.buckets];
    expect(asked, hasLength(3));
    expect(asked[1], asked[0], reason: 'the same buckets the second time');
    expect(asked[2], asked[0], reason: 'and the third');
    // A restart: a new service over the same vault.
    await stop(ida);
    final (ida2, ida2Log) = await start('ida4', dir: home);
    await waitUntil(() => ida2.transport.isConnected, what: 'reconnected');
    await ida2.kt.check();
    expect(ida2Log.bucketPosts.single.buckets, asked[0],
        reason: 'the decoys are kept, not drawn again');
    expect(ida2.kt.statusOf(jon.myRid)?.state, KtContactState.confirmed);
  });

  test(
      '5. the count of buckets asked does not depend on the number of '
      'contacts, up to the padding', () async {
    final k = await recommendedBits();
    final (kim, kimLog) = await start('kim5'); // no contacts
    final (lee, leeLog) = await start('lee5'); // one
    final (mae, maeLog) = await start('mae5'); // three
    final (ned, _) = await start('ned5');
    final (oli, _) = await start('oli5');
    final (pam, _) = await start('pam5');
    await befriend(lee, ned);
    await befriend(mae, ned);
    await befriend(mae, oli);
    await befriend(mae, pam);
    for (final s in [ned, oli, pam]) {
      await s.kt.check();
    }
    for (final s in [kim, lee, mae]) {
      await s.kt.check();
    }
    expect(kimLog.bucketPosts.single.buckets, hasLength(ktDecoyBlock));
    expect(leeLog.bucketPosts.single.buckets, hasLength(ktDecoyBlock));
    expect(maeLog.bucketPosts.single.buckets, hasLength(ktDecoyBlock),
        reason: 'none, one and three contacts all ask sixteen');
    final before = maeLog.bucketPosts.single.buckets;

    // A contact whose bucket is already asked changes nothing asked.
    final (quin, _) = await start('quin5',
        identity: await identityWhere(before, k, inside: true));
    await befriend(mae, quin);
    await quin.kt.check();
    maeLog.seen.clear();
    await mae.kt.check();
    expect(maeLog.bucketPosts.single.buckets, before,
        reason: 'a contact inside the asked buckets is invisible');
    expect(mae.kt.statusOf(quin.myRid)?.state, KtContactState.confirmed);

    // A contact removed takes no bucket away: its bucket stays, as a decoy.
    await mae.deleteContact(oli.myRid);
    maeLog.seen.clear();
    await mae.kt.check();
    expect(maeLog.bucketPosts.single.buckets, before,
        reason: 'a removal is invisible');

    // A contact outside them arrives in a block of sixteen, nothing leaving.
    final (rae, _) = await start('rae5',
        identity: await identityWhere(before, k, inside: false));
    await befriend(mae, rae);
    await rae.kt.check();
    maeLog.seen.clear();
    await mae.kt.check();
    final after = maeLog.bucketPosts.single.buckets;
    expect(after, hasLength(2 * ktDecoyBlock));
    expect(after.toSet().containsAll(before), isTrue,
        reason: 'every bucket asked before is asked still');
    expect(after,
        contains('${ktBucketPrefix(await labelBytes(rae), k)}/$k'));
    expect(mae.kt.statusOf(rae.myRid)?.state, KtContactState.confirmed);
  });

  test(
      '6. a split view is still caught through the bucket path, and a bucket '
      'with a label left out is a fault', () async {
    final (sal, salLog) = await start('sal6');
    final (tom, _) = await start('tom6');
    await befriend(sal, tom);
    await tom.kt.check();
    await sal.kt.check();
    expect(sal.kt.statusOf(tom.myRid)?.state, KtContactState.confirmed);
    // Someone holding Tom's account seed publishes a v2 his device never
    // issued; then Tom's root issues an honest v2, refused by the log as
    // stale, which reaches Sal in-band (key_transparency_test.dart 4).
    final acct = await tom.accountIdentity();
    final rogue = await ZIdentity.generate();
    final rogueList = await acct.signDeviceList([
      acct.deviceCert,
      await acct.signDeviceCert(
          deviceEdPub: rogue.edPub, deviceXPub: rogue.xPub, deviceId: 'rogue'),
    ], 2);
    final req = await ktPublishRequest(
        accountEdSeed: acct.accountEdSeed!,
        version: 2,
        fp: await rogueList.fingerprint(),
        value: await ktSealValue(
            acct.accountEdPub, utf8.encode(jsonEncode(rogueList.toJson()))));
    final post = await (await HttpClient()
            .postUrl(Uri.parse('http://127.0.0.1:$logPort/kt/v1/publish'))
          ..headers.contentType = ContentType.json
          ..write(jsonEncode(req)))
        .close();
    expect(post.statusCode, 201);
    await post.drain<void>();
    await linkLaptop(tom);
    await heldVersion(sal, tom.myRid, 2);
    await sal.kt.check();
    final s = sal.kt.statusOf(tom.myRid)!;
    expect(s.state, KtContactState.conflict, reason: 'the split view is seen');
    expect(s.logVersion, 2);
    expect(sal.kt.sendsHeld(tom.myRid), isTrue);
    await expectLater(
        sal.sendText(tom.myRid, 'held?'), throwsA(isA<KtSendHeldException>()));
    final (tomHex, tomB64) = await labelOf(tom);
    expect(
        salLog.seen.where((r) => r.mentions(tomHex) || r.mentions(tomB64)),
        isEmpty,
        reason: 'and Tom was never named');

    // A log that leaves a label out of a bucket: the fold no longer reaches
    // the root it signed, which is a fault, not a smaller bucket.
    final (uma, umaLog) = await start('uma6');
    final (vic, _) = await start('vic6');
    await befriend(uma, vic);
    await vic.kt.check();
    umaLog.tamper = (req, answer) {
      if (!req.isBuckets) return null;
      final j = (jsonDecode(answer) as Map).cast<String, Object?>();
      for (final b in j['buckets'] as List) {
        final leaves = (b as Map)['leaves'] as List;
        if (leaves.isNotEmpty) {
          leaves.removeAt(0);
          break;
        }
      }
      return jsonEncode(j);
    };
    await uma.kt.check();
    expect(uma.kt.health, KtHealth.fault);
    expect(uma.kt.fault!.reason, contains('buckets for contacts'));
    expect(uma.kt.statusOf(vic.myRid), isNull,
        reason: 'nothing was believed from it');
  });

  test(
      '7. a contact\'s new version is fetched among every unseen entry, made '
      'up to sixteen, and those are fetched when no contact moved too',
      () async {
    final k = await recommendedBits();
    final (wes, wesLog) = await start('wes7');
    final (xan, _) = await start('xan7');
    await befriend(wes, xan);
    await xan.kt.check();
    await wes.kt.check();
    await wes.kt.check(); // a baseline: everything in the buckets now seen
    final asked = wesLog.bucketPosts.last.buckets;

    // Other accounts publish into the asked buckets, and Xan links a laptop.
    final others = await mintInBuckets(asked, k, 3);
    await linkLaptop(xan);
    await heldVersion(wes, xan.myRid, 2);
    final xanLabel = await labelBytes(xan);
    await waitUntil(() async => (await logLatest(xanLabel))?.$2 == 2,
        what: 'the log holding Xan\'s v2');
    final xanIndex = (await logLatest(xanLabel))!.$1;
    wesLog.seen.clear();
    await wes.kt.check();
    final inBuckets = wesLog.leavesAnswered();
    final fetched = wesLog.entriesPosts.single.indexes;
    expect(fetched, contains(xanIndex), reason: 'Xan\'s new entry');
    expect(fetched.toSet().containsAll(others), isTrue,
        reason: 'beside every entry new to the asked buckets');
    expect(fetched, hasLength(16),
        reason: 'made up to sixteen, never Xan\'s and a few new ones alone');
    expect(inBuckets.containsAll(fetched), isTrue,
        reason: 'and every one of them from the asked buckets');
    expect(fetched, orderedEquals([...fetched]..sort()),
        reason: 'in index order, which says nothing about which is which');
    expect(wes.kt.statusOf(xan.myRid)?.state, KtContactState.confirmed);
    expect(wes.kt.statusOf(xan.myRid)?.logVersion, 2);

    // Nothing of Wes's moves; two strangers in his buckets do. They are
    // fetched all the same: a fetch is not a sign that a contact moved.
    final strangers = await mintInBuckets(asked, k, 2);
    wesLog.seen.clear();
    await wes.kt.check();
    final quiet = wesLog.entriesPosts.single.indexes;
    expect(quiet.toSet().containsAll(strangers), isTrue);
    expect(quiet, hasLength(16));
    // And with nothing new at all, nothing is fetched.
    wesLog.seen.clear();
    await wes.kt.check();
    expect(wesLog.entriesPosts, isEmpty);

    // A contact whose entry Wes has already seen, as a stranger's in one of
    // his buckets: fetched beside every entry in them, not beside a few
    // that would stand out as not new — unless it is one of the sixteen
    // this install makes a fetch up with, one chance in thirty or so, which
    // are fetched as they would be with no contact at all.
    final (yan, _) = await start('yan7',
        identity: await identityWhere(asked, k, inside: true));
    await yan.kt.check(); // in the log, in one of Wes's buckets
    await wes.kt.check(); // and seen there by Wes
    await befriend(wes, yan);
    wesLog.seen.clear();
    await wes.kt.check();
    final everyEntry = wesLog.leavesAnswered().toList()..sort();
    final yanIndex = (await logLatest(await labelBytes(yan)))!.$1;
    final all = wesLog.entriesPosts.single.indexes;
    if (all.length == 16) {
      expect(all, contains(yanIndex));
    } else {
      expect(all, everyEntry, reason: 'every entry in the asked buckets');
    }
    expect(wes.kt.statusOf(yan.myRid)?.state, KtContactState.confirmed);
  });

  test(
      '8. no refresh at start, and none right after a contact\'s list '
      'changes; the scheduled one comes at its random moment', () async {
    final t0 = DateTime.now().millisecondsSinceEpoch;
    final (yul, yulLog) = await start('yul8', scheduled: true);
    final (zed, _) = await start('zed8');
    await waitUntil(() => yul.kt.nextRefreshMs != null,
        what: 'the first refresh planned');
    expect(yul.kt.nextRefreshMs! - t0,
        greaterThanOrEqualTo(yul.kt.catchUpMin.inMilliseconds),
        reason: 'never at start');
    // That first refresh is owed — a fresh install — and comes seconds after
    // start; it is put out of the way of what follows, which is about what
    // does NOT start a refresh.
    yul.kt.catchUpMin = const Duration(hours: 1);
    yul.kt.catchUpMax = const Duration(hours: 2);
    yul.kt.scheduled = true;
    await waitUntil(
        () => (yul.kt.nextRefreshMs ?? 0) - t0 >= 3600 * 1000,
        what: 'the first refresh planned an hour off');
    await befriend(yul, zed);
    await roundTrip(yul, zed, 'a');
    expect(yulLog.reads, isEmpty,
        reason: 'started, added a contact, talked: nothing asked of the log');
    final planned = yul.kt.nextRefreshMs;

    // Zed's list changes and reaches Yul.
    await zed.kt.check();
    await linkLaptop(zed);
    await heldVersion(yul, zed.myRid, 2);
    await roundTrip(yul, zed, 'b');
    expect(yulLog.reads, isEmpty,
        reason: 'a contact\'s new list is checked at the next refresh, not now');
    expect(yul.kt.nextRefreshMs, planned,
        reason: 'and does not move the next one');

    // The schedule itself runs: overdue, it catches up between the bounds.
    yul.kt.catchUpMin = const Duration(milliseconds: 300);
    yul.kt.catchUpMax = const Duration(milliseconds: 600);
    final armed = DateTime.now().millisecondsSinceEpoch;
    yul.kt.scheduled = true;
    await waitUntil(() => yulLog.bucketPosts.isNotEmpty,
        what: 'the scheduled refresh');
    final at = yulLog.bucketPosts.first.atMs;
    expect(at - armed, greaterThanOrEqualTo(300),
        reason: 'not before its moment');
    await waitUntil(
        () => yul.kt.statusOf(zed.myRid)?.logVersion == 2,
        what: 'Zed\'s new list checked by the scheduled refresh');
    // And the next is in the next window, not straight away.
    await waitUntil(() => (yul.kt.nextRefreshMs ?? 0) > at,
        what: 'the next refresh planned');
    final w = yul.kt.checkEvery.inMilliseconds;
    expect(yul.kt.nextRefreshMs! ~/ w, at ~/ w + 1,
        reason: 'one refresh in each window');
    yul.kt.scheduled = false;
    // The contact screen asks only when the contact's list changed since a
    // refresh looked at it (criterion 9 opens the screen on one that did).
    await waitUntil(() => !yul.kt.checking, what: 'the refresh finished');
    yulLog.seen.clear();
    expect(await yul.kt.checkIfListChanged(zed.myRid), isFalse);
    expect(yulLog.seen, isEmpty, reason: 'nothing new, nothing asked');
  });

  testWidgets(
      '9. the verification screen\'s explicit check is a refresh of the same '
      'shape', (t) async {
    await t.binding.setSurfaceSize(const Size(800, 3000));
    addTearDown(() => t.binding.setSurfaceSize(null));
    late ChatService amy;
    late _Recorder amyLog;
    late ChatService bo;
    late List<String> usual;
    late String boHex, boB64;
    await t.runAsync(() async {
      (amy, amyLog) = await start('amy9');
      (bo, _) = await start('bo9');
      (boHex, boB64) = await labelOf(bo);
      await befriend(amy, bo);
      await bo.kt.check();
      await amy.kt.check();
      usual = amyLog.bucketPosts.last.buckets;
      // Bo's list changes and reaches Amy; her next refresh is hours away.
      await linkLaptop(bo);
      await heldVersion(amy, bo.myRid, 2);
      amyLog.seen.clear();
    });
    Widget wrap(Widget child) => ChangeNotifierProvider<ChatService>.value(
          value: amy,
          child: MaterialApp(
            theme: ZTheme.light(),
            localizationsDelegates: AppLocalizations.localizationsDelegates,
            supportedLocales: AppLocalizations.supportedLocales,
            home: child,
          ),
        );
    await t.pumpWidget(wrap(ContactInfoScreen(rid: bo.myRid)));
    // The refresh the screen started runs in this test's fake zone, so it is
    // pumped to its end — every write of it to the vault included — before
    // anything here touches the vault from the real one.
    final deadline = DateTime.now().add(const Duration(seconds: 30));
    while (amy.kt.statusOf(bo.myRid)?.logVersion != 2 || amy.kt.checking) {
      if (DateTime.now().isAfter(deadline)) fail('the screen never checked Bo');
      await t.runAsync(
          () => Future<void>.delayed(const Duration(milliseconds: 100)));
      await t.pump(const Duration(milliseconds: 50));
    }
    expect(amyLog.bucketPosts, hasLength(1),
        reason: 'opening the screen ran one refresh');
    expect(amyLog.bucketPosts.single.buckets, usual,
        reason: 'of the usual shape: every bucket and every decoy');
    expect(amyLog.seen.where((r) => r.mentions(boHex) || r.mentions(boB64)),
        isEmpty,
        reason: 'and not a question about Bo');
    // The screen's own post-quantum nudge, armed on the fake clock.
    final quiet = DateTime.now().add(const Duration(seconds: 30));
    while (amy.pqSendPending) {
      if (DateTime.now().isAfter(quiet)) fail('a post-quantum send stayed pending');
      await t.pump(const Duration(seconds: 1));
      await t.runAsync(
          () => Future<void>.delayed(const Duration(milliseconds: 50)));
    }
    // Both pieces of work the screen started — the refresh and the nudge —
    // have been waited out above.
    await t.pumpWidget(const SizedBox());
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('10. a log that refuses buckets is unreachable, and no label is asked',
      () async {
    final (cy, cyLog) = await start('cy10');
    final (di, _) = await start('di10');
    await befriend(cy, di);
    await di.kt.check();
    // A log from before 36.2: no bucket routes.
    cyLog.refuse = (req) => req.isBuckets ? 404 : null;
    await cy.kt.check();
    expect(cy.kt.statusOf(di.myRid), isNull, reason: 'nobody was checked');
    expect(cy.kt.lastFailMs, greaterThan(0), reason: 'a failure is recorded');
    cy.kt.unreachableAfter = Duration.zero;
    expect(cy.kt.health, KtHealth.unreachable,
        reason: 'a log that answers only its head checks nobody');
    final (diHex, diB64) = await labelOf(di);
    expect(cyLog.seen.where((r) => r.mentions(diHex) || r.mentions(diB64)),
        isEmpty,
        reason: 'and there is no falling back to asking by name');
    // The same log, answering: reachable, and Di checked.
    cyLog.refuse = null;
    cy.kt.unreachableAfter = const Duration(hours: 24);
    await cy.kt.check();
    expect(cy.kt.health, KtHealth.ok);
    expect(cy.kt.statusOf(di.myRid)?.state, KtContactState.confirmed);
  });

  test(
      '11. the schedule: never at start, a catch-up between its bounds, one '
      'refresh a window, a restart keeping its moment', () {
    const hour = 3600 * 1000;
    const every = Duration(hours: 6);
    const lo = Duration(minutes: 1);
    const hi = Duration(minutes: 10);
    final rnd = Random(35);
    final nowMs = 1791000000000;
    KtRefreshSchedule next(KtRefreshSchedule s, int at) => s.next(
        nowMs: at, every: every, catchUpMin: lo, catchUpMax: hi, random: rnd);
    for (var i = 0; i < 500; i++) {
      final now = nowMs + rnd.nextInt(48 * hour);
      // A fresh install, and one whose last refresh was a day ago.
      for (final s in [
        const KtRefreshSchedule(),
        KtRefreshSchedule(lastMs: now - 24 * hour),
      ]) {
        final n = next(s, now);
        expect(n.atMs! - now, inInclusiveRange(lo.inMilliseconds, hi.inMilliseconds),
            reason: 'overdue: a catch-up between the bounds, never at start');
      }
      // A refresh an hour ago: the next is in the next window it has not had.
      final last = now - hour;
      final n = next(KtRefreshSchedule(lastMs: last), now);
      expect(n.atMs! - now, greaterThanOrEqualTo(lo.inMilliseconds));
      final w = every.inMilliseconds;
      expect(n.atMs! ~/ w, greaterThan(last ~/ w),
          reason: 'never a second refresh in the window that had one');
      expect(n.window, n.atMs! ~/ w);
      // A restart before that moment keeps it.
      final again = next(n, now + 5 * 60 * 1000);
      if (n.atMs! >= now + 5 * 60 * 1000 + lo.inMilliseconds) {
        expect(again.atMs, n.atMs, reason: 'a restart does not draw again');
      }
    }
    // Over many windows, the moments spread over the whole window.
    final w = every.inMilliseconds;
    final offsets = <int>[];
    var s = KtRefreshSchedule(lastMs: nowMs);
    var clock = nowMs;
    for (var i = 0; i < 400; i++) {
      s = next(s, clock);
      offsets.add(s.atMs! % w);
      clock = s.atMs!;
      s = s.withLast(clock);
    }
    expect(offsets.reduce(min), lessThan(w ~/ 10));
    expect(offsets.reduce(max), greaterThan(w - w ~/ 10));
  });

  test(
      '12. the decoy plan: blocks of sixteen, stable, a bucket that lost its '
      'contact kept, a change of k mapped bucket to bucket', () {
    final labels = [for (var i = 0; i < 40; i++) seededBytes(1000 + i)(32)];
    for (final n in [0, 1, 15]) {
      final d = KtDecoys(key: Uint8List(32), pool: []);
      expect(d.plan(labels.take(n), 9, random: seededBytes(n)), hasLength(16));
    }
    // Seventeen labels in seventeen buckets: two blocks.
    final distinct = <Uint8List>[];
    final seen = <String>{};
    for (final l in labels) {
      if (seen.add(ktBucketPrefix(l, 9))) distinct.add(l);
      if (distinct.length == 17) break;
    }
    final d17 = KtDecoys(key: Uint8List(32), pool: []);
    expect(d17.plan(distinct, 9, random: seededBytes(17)), hasLength(32));
    // At k = 3 there are eight buckets: all of them, no more.
    expect(KtDecoys(key: Uint8List(32), pool: []).plan(labels.take(2), 3,
            random: seededBytes(3)),
        hasLength(8));

    // Stable: the same contacts give the same buckets, through a JSON round
    // trip as the vault keeps them.
    final d = KtDecoys(key: Uint8List(32), pool: []);
    final first = d.plan(labels.take(3), 9, random: seededBytes(5));
    final kept = KtDecoys.parse(jsonEncode(d.toJson()))!;
    expect(kept.plan(labels.take(3), 9, random: seededBytes(6)), first);
    // A contact gone: its bucket stays.
    final fewer = kept.plan(labels.take(2), 9, random: seededBytes(7));
    expect(fewer, first, reason: 'a removal asks the same buckets');
    // A coarser k and a finer one: every bucket maps to its own ancestor, or
    // to one of its own descendants, real and decoy alike.
    final finer = kept.plan(labels.take(2), 10, random: seededBytes(8));
    final up = {for (final q in finer) q.prefix};
    for (final q in first) {
      final p = ktParseBucketPrefix(q.prefix, 9)!;
      final hasChild = up.contains(ktBucketPrefix(p, 10)) ||
          up.contains(ktBucketPrefix(
              Uint8List.fromList(p)..[1] |= 0x40, 10)); // bit 9 set
      expect(hasChild, isTrue, reason: '$q has a descendant asked at k = 10');
    }
    expect(finer.length % 16, 0);
    // Not a set of decoys: refused, as a backup that is not one is.
    expect(KtDecoys.parse('{}'), isNull);
    expect(KtDecoys.parse(jsonEncode({'key': b64(Uint8List(32)), 'd': ['AAAA'], 'p': []})),
        isNull, reason: 'a decoy is 32 bytes');
    expect(KtDecoys.parse(jsonEncode({'key': b64(Uint8List(32)), 'd': [], 'k': 9, 'p': ['zz']})),
        isNull, reason: 'a prefix is hex of its length');
    // And k: the recommendation, never finer than the signed size allows,
    // never finer than the ceiling the client's own counts set.
    expect(ktRefreshBits(recommended: 9, headSize: 22094, ceiling: 24), 9);
    expect(ktRefreshBits(recommended: 24, headSize: 22094, ceiling: 24), 9);
    expect(ktRefreshBits(recommended: 9, headSize: 22094, ceiling: 7), 7);
    expect(ktRefreshBits(recommended: null, headSize: 22094, ceiling: 24), 0);
    expect(ktRefreshBits(recommended: 5, headSize: 10, ceiling: 24), 0);
    // A size of many versions allows 11; the labels counted allow 7.
    expect(ktRefreshBits(recommended: 24, headSize: 66100, ceiling: 7), 7);

    // That ceiling, from the decoy buckets' counts: the finest k at which
    // they hold sixteen labels a bucket — down to it at once, up a bit at a
    // time, and kept while buckets at it hold 16 to 64. Sixteen decoy
    // buckets of [n] labels at [k]:
    KtDecoys observed(int? ceiling, int k, int n) {
      final prefixes = <String>{};
      for (var i = 0; prefixes.length < 16; i++) {
        prefixes.add(ktBucketPrefix(seededBytes(5000 + i)(32), k));
      }
      final d = KtDecoys(
          key: Uint8List(32),
          pool: [],
          bits: k,
          asked: prefixes.toList()..sort(),
          ceiling: ceiling);
      d.observe([
        for (final p in prefixes)
          KtVerifiedBucket(KtBucketQuery.parse(p, k), [
            for (var i = 0; i < n; i++)
              KtBucketLeaf(label: Uint8List(32), index: i, version: 1)
          ])
      ], const []);
      return d;
    }

    // Asked at 11 (a size of versions), a label a bucket: 2,048 labels,
    // which fill buckets to sixteen at k = 7 — there at once.
    expect(observed(null, 11, 1).ceiling, 7);
    expect(observed(11, 11, 1).ceiling, 7);
    // Sixteen a bucket at 7, or thirty: where it is.
    expect(observed(7, 7, 16).ceiling, 7);
    expect(observed(7, 7, 30).ceiling, 7);
    // A log that grows: 64 a bucket at 7 bears out 9, and the ceiling rises
    // a bit — to 8, where buckets would hold 32, and there it stays.
    final grown = observed(7, 7, 64);
    expect(grown.ceiling, 8);
    expect(observed(grown.ceiling, 7, 64).ceiling, 8);
    // 128 a bucket at 6, with the ceiling at 6: one bit, not three.
    expect(observed(6, 6, 128).ceiling, 7);
    // And falls at once: two a bucket at 9 is 1,024 labels, k = 6.
    expect(observed(9, 9, 2).ceiling, 6);
  });

  test(
      '13. entry decoys: the same fetch whether or not a new entry is needed, '
      'every entry when a needed one is not among them, a sample past the cap '
      'keyed by what is needed', () {
    final key = Uint8List.fromList(List<int>.filled(32, 9));
    final leaves = {for (var i = 0; i < 600; i++) i * 3};
    final seen = {for (var i = 0; i < 590; i++) i * 3};
    final unseen = [for (var i = 590; i < 600; i++) i * 3];
    // Ten new, none needed: the ten, made up to sixteen from the rest.
    final quiet =
        ktEntriesToFetch(needed: {}, leaves: leaves, seen: seen, key: key);
    expect(quiet, hasLength(16));
    expect(quiet, containsAll(unseen));
    expect(leaves.containsAll(quiet), isTrue);
    expect(quiet, orderedEquals([...quiet]..sort()));
    // One of the ten needed, or two of them: the very same fetch — it says
    // nothing about whether, or which.
    for (final n in [
      {590 * 3},
      {591 * 3, 599 * 3},
    ]) {
      expect(ktEntriesToFetch(needed: n, leaves: leaves, seen: seen, key: key),
          quiet);
    }
    // One new entry alone, needed: still sixteen.
    final one = {...seen, 590 * 3};
    expect(
        ktEntriesToFetch(needed: {590 * 3}, leaves: one, seen: seen, key: key),
        hasLength(16));
    // Nothing new, nothing needed: nothing.
    expect(ktEntriesToFetch(needed: {}, leaves: seen, seen: seen, key: key),
        isEmpty);
    // A needed entry the client had seen, not among the sixteen: every entry
    // in the asked buckets.
    final old = seen.firstWhere((i) => !quiet.contains(i));
    expect(ktEntriesToFetch(needed: {old}, leaves: leaves, seen: seen, key: key),
        leaves.toList()..sort());
    // No last refresh: every entry in the asked buckets, needed or not, the
    // same for any install.
    for (final n in [<int>{}, {9}, {9, 1500}]) {
      expect(ktEntriesToFetch(needed: n, leaves: leaves, seen: null, key: key),
          leaves.toList()..sort());
    }
    // Past the cap: the needed ones and a sample, the cap in all, the same
    // when asked again for the same entries.
    final big = {for (var i = 0; i < 3000; i++) i};
    final capped = ktEntriesToFetch(
        needed: {5, 2999}, leaves: big, seen: <int>{}, key: key);
    expect(capped, hasLength(ktMaxEntries));
    expect(capped, containsAll([5, 2999]));
    expect(capped, orderedEquals([...capped]..sort()));
    expect(
        ktEntriesToFetch(
            needed: {5, 2999}, leaves: big, seen: <int>{}, key: key),
        capped);
    // Two fetches past the cap that need one entry each — a contact added
    // in a bucket already asked, twice — draw samples that have nothing to
    // do with each other, so the difference of the two never comes down to
    // the entry one of them needed (review B of 2026-10-09, probe K3).
    final rnd = Random(13);
    var singled = 0;
    var shared = 0;
    for (var t = 0; t < 100; t++) {
      final x = rnd.nextInt(3000), y = rnd.nextInt(3000);
      if (x == y) continue;
      final fx = ktEntriesToFetch(
              needed: {x}, leaves: big, seen: big, key: key)
          .toSet();
      final fy = ktEntriesToFetch(
              needed: {y}, leaves: big, seen: big, key: key)
          .toSet();
      expect(fx, contains(x));
      final onlyX = fx.difference(fy);
      if (onlyX.length == 1 && onlyX.single == x) singled++;
      shared += fx.intersection(fy).length;
    }
    expect(singled, 0, reason: 'no difference names the entry it was for');
    expect(shared / 100, lessThan(ktMaxEntries * 0.5),
        reason: 'two samples share what chance gives — a third of the cap '
            'when it is a third of the entries — not all but one');
  });

  test(
      '14. a scheduled refresh the app slept through is not run when it wakes, '
      'but caught up a moment later', () async {
    final dir = await Directory.systemTemp.createTemp('z_ktp_sleep14');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    addTearDown(() => vault.db.close());
    var slept = 0;
    final f = _CountingFetcher();
    final kt = KeyTransparency(
      vault: vault,
      host: _NoHost(),
      fetcher: f,
      config: KtConfig(logUrl: 'http://127.0.0.1:1', logPubB64: b64(Uint8List(32))),
      now: () => DateTime.now().millisecondsSinceEpoch + slept,
    );
    addTearDown(kt.dispose);
    kt.catchUpMin = const Duration(milliseconds: 300);
    kt.catchUpMax = const Duration(milliseconds: 400);
    kt.start();
    await waitUntil(() => kt.nextRefreshMs != null, what: 'a refresh planned');
    final first = kt.nextRefreshMs!;
    // The phone suspends the app for an hour before that moment; the timer
    // fires the moment the app is back.
    slept = 3600 * 1000;
    await waitUntil(() => kt.nextRefreshMs != first,
        what: 'the moment drawn again');
    final woke = kt.now();
    final second = kt.nextRefreshMs!;
    expect(f.asked, isEmpty,
        reason: 'nothing asked at the moment the app came back');
    expect(second - first, greaterThanOrEqualTo(3600 * 1000),
        reason: 'a new moment, from when it woke');
    expect(second - woke, lessThanOrEqualTo(kt.catchUpMax.inMilliseconds),
        reason: 'and a catch-up, not a moment later in the window');
    await waitUntil(() => f.asked.isNotEmpty, what: 'the catch-up run');
    kt.scheduled = false;
  });

  test(
      '15. the contact screen\'s refresh fetches every new entry among no '
      'fewer than sixteen, never the contact\'s alone', () async {
    final (amy, amyLog) = await start('amy15');
    final peers = <ChatService>[];
    for (var i = 0; i < 3; i++) {
      final (peer, _) = await start('peer15_$i');
      await befriend(amy, peer);
      await peer.kt.check();
      peers.add(peer);
    }
    await amy.kt.check();
    await amy.kt.check(); // a baseline: everything in her buckets seen
    final before = amyLog.leavesAnswered();
    final bo = peers.first;
    // Bo links a laptop: a new list, published to the log and sent in-band,
    // and nothing else new in Amy's buckets — the case where the entry new
    // to her is the contact's alone (review B of 2026-10-09, probe K4).
    await linkLaptop(bo);
    await heldVersion(amy, bo.myRid, 2);
    final boLabel = await labelBytes(bo);
    await waitUntil(() async => (await logLatest(boLabel))?.$2 == 2,
        what: 'the log holding Bo\'s v2');
    final boNew = (await logLatest(boLabel))!.$1;
    amyLog.seen.clear();
    // What ContactInfoScreen.initState runs when Amy opens Bo's screen.
    expect(await amy.kt.checkIfListChanged(bo.myRid), isTrue);
    final now = amyLog.leavesAnswered();
    final fresh = now.difference(before);
    expect(fresh, contains(boNew));
    final fetched = amyLog.entriesPosts.expand((e) => e.indexes).toList();
    expect(fetched, contains(boNew));
    expect(fetched.toSet().containsAll(fresh), isTrue,
        reason: 'every entry new in the asked buckets: $fresh');
    expect(fetched.length, greaterThanOrEqualTo(16),
        reason: 'never fewer than sixteen: $fetched');
    expect(now.containsAll(fetched), isTrue,
        reason: 'all of them from the buckets asked');
    expect(amy.kt.statusOf(bo.myRid)?.logVersion, 2);
    expect(amy.kt.statusOf(bo.myRid)?.state, KtContactState.confirmed);
  });

  test(
      '16. a restore\'s first refresh fetches every entry in its buckets, as '
      'the original\'s did, and names no contact beside it', () async {
    final home = await Directory.systemTemp.createTemp('z_ktp_rae16');
    temps.add(home);
    final (rae, raeLog) = await start('rae16', dir: home);
    final contacts = <ChatService>[];
    for (var i = 0; i < 3; i++) {
      final (peer, _) = await start('peer16_$i');
      await befriend(rae, peer);
      await peer.kt.check();
      contacts.add(peer);
    }
    final theirs = <int>{
      for (final c in contacts) (await logLatest(await labelBytes(c)))!.$1
    };
    await rae.kt.check(); // the first refresh of this install
    final asked = raeLog.bucketPosts.last.buckets;
    final f0 = raeLog.entriesPosts.expand((e) => e.indexes).toSet();
    expect(f0, raeLog.leavesAnswered(),
        reason: 'with no last refresh, every entry in the asked buckets');
    await rae.kt.check();
    for (final c in contacts) {
      expect(rae.kt.statusOf(c.myRid)?.state, KtContactState.confirmed);
    }

    // A backup; the phone lost; the backup restored on a new one.
    final code = await RecoveryCode.generate();
    final out = await Directory.systemTemp.createTemp('z_ktp_bk16');
    temps.add(out);
    final file = File(p.join(out.path, 'b.zbk'));
    final sink = file.openWrite();
    await BackupArchive.export(vault: rae.vault, code: code, out: sink);
    await sink.close();
    await stop(rae);
    home.deleteSync(recursive: true);
    final dir2 = await Directory.systemTemp.createTemp('z_ktp_rae16b');
    temps.add(dir2);
    final restored = await Vault.open(rootOverride: dir2);
    await Restore.run(
        vault: restored,
        file: file,
        secret: await code.format(),
        kind: (await Restore.identify(file)).kind,
        serverUrl: 'ws://127.0.0.1:$relayPort');
    await restored.db.close();
    final (rae2, rae2Log) = await start('rae16', dir: dir2);
    await rae2.kt.check();
    expect(rae2Log.seen.where((r) => r.method == 'GET' && r.path == '/kt/v1/bucket'),
        isEmpty,
        reason: 'the ceiling came with the backup: nothing counted again');
    expect(rae2Log.bucketPosts.single.buckets, asked,
        reason: 'the decoys came with it too');
    final fr = rae2Log.entriesPosts.expand((e) => e.indexes).toSet();
    expect(fr, rae2Log.leavesAnswered(),
        reason: 'every entry in the asked buckets, as the first refresh had');
    expect(fr.containsAll(theirs), isTrue);
    expect(f0.difference(fr).intersection(theirs), isEmpty,
        reason: 'set side by side, the two fetches name no contact');
    for (final c in contacts) {
      expect(rae2.kt.statusOf(c.myRid)?.state, KtContactState.confirmed);
    }
  });

  test(
      '17. a window\'s moment the app was not running for is caught up after '
      'it starts, not drawn again for later', () async {
    const w = 6 * 3600 * 1000;
    final dir = await Directory.systemTemp.createTemp('z_ktp_owed17');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    addTearDown(() => vault.db.close());
    // An hour into a window whose moment, drawn at ten minutes in, the app
    // was not running for; its last refresh three hours before, in the
    // window before.
    final base = (DateTime.now().millisecondsSinceEpoch ~/ w + 10) * w;
    final clock = base + 3600 * 1000;
    final real0 = DateTime.now().millisecondsSinceEpoch;
    await vault.kvPut(
        'kt_refresh',
        jsonEncode(KtRefreshSchedule(
                lastMs: base - 3 * 3600 * 1000,
                window: base ~/ w,
                atMs: base + 10 * 60 * 1000)
            .toJson()));
    final f = _CountingFetcher();
    final kt = KeyTransparency(
      vault: vault,
      host: _NoHost(),
      fetcher: f,
      config: KtConfig(logUrl: 'http://127.0.0.1:1', logPubB64: b64(Uint8List(32))),
      now: () => clock + DateTime.now().millisecondsSinceEpoch - real0,
    );
    addTearDown(kt.dispose);
    kt.catchUpMin = const Duration(seconds: 2);
    kt.catchUpMax = const Duration(seconds: 3);
    final started = kt.now();
    kt.start();
    await waitUntil(() => kt.nextRefreshMs != null, what: 'a refresh planned');
    final at = kt.nextRefreshMs! - started;
    kt.scheduled = false;
    expect(f.asked, isEmpty, reason: 'nothing at the instant it started');
    expect(at, greaterThanOrEqualTo(kt.catchUpMin.inMilliseconds));
    expect(at, lessThanOrEqualTo(kt.catchUpMax.inMilliseconds + 1000),
        reason: 'the owed refresh within catchUpMax of start, not later in '
            'the window: ${at ~/ 1000} s');
  });

  test(
      '18. a phone used in short visits still refreshes, never as it comes '
      'to the front', () async {
    // The shipped schedule (KtRefreshSchedule.next with the client's own
    // window and catch-up bounds) through a phone's day: the app is in
    // front for a visit and not otherwise, its timer frozen in between.
    // Coming to the front plans again from the clock; a moment that comes
    // while in front runs. Twelve visits of half a minute a day, at random
    // between 08:00 and 23:00, for thirty days (review B of 2026-10-09,
    // probe U4).
    final dir = await Directory.systemTemp.createTemp('z_ktp_visits18');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    addTearDown(() => vault.db.close());
    final kt = KeyTransparency(
      vault: vault,
      host: _NoHost(),
      fetcher: _CountingFetcher(),
      config: KtConfig(logUrl: 'http://127.0.0.1:1', logPubB64: b64(Uint8List(32))),
    );
    addTearDown(kt.dispose);
    const day = 24 * 3600 * 1000;
    const days = 30;
    final rnd = Random(18);
    final start0 = 1791000000000;
    var plan = const KtRefreshSchedule();
    KtRefreshSchedule next(KtRefreshSchedule s, int at) => s.next(
        nowMs: at,
        every: kt.checkEvery,
        catchUpMin: kt.catchUpMin,
        catchUpMax: kt.catchUpMax,
        random: rnd);
    final refreshes = <int>[];
    for (var d = 0; d < days; d++) {
      final opens = [
        for (var s = 0; s < 12; s++)
          start0 + d * day + 8 * 3600000 + rnd.nextInt(15 * 3600000)
      ]..sort();
      for (final open in opens) {
        final close = open + 30 * 1000;
        plan = next(plan, open);
        while (plan.atMs! <= close) {
          final at = plan.atMs!;
          expect(at - open, greaterThanOrEqualTo(kt.catchUpMin.inMilliseconds),
              reason: 'never as the app comes to the front');
          refreshes.add(at);
          plan = next(plan.withLast(at), at);
        }
      }
    }
    var gap = 0;
    for (var i = 1; i < refreshes.length; i++) {
      gap = max(gap, refreshes[i] - refreshes[i - 1]);
    }
    // Printed for the record: what "about four times a day" comes to here.
    // ignore: avoid_print
    print('criterion 18: ${refreshes.length} refreshes in $days days '
        '(${(refreshes.length / days).toStringAsFixed(2)} a day), longest gap '
        '${(gap / 3600000).toStringAsFixed(1)} h');
    expect(refreshes.length / days, greaterThanOrEqualTo(2),
        reason: 'at least two a day from twelve half-minute visits');
  });
}
