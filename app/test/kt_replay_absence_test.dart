// What a transparency log, or whatever stands between a client and it, could
// do that the client's proofs alone did not catch (the 2026-10-28 review of
// 4.7.0, findings A and B2) — against the real log's code as its operator can
// run it (kt/test/kt_operator_log.js, its clock and its map in the test's
// hands) on loopback, and, for contacts, the real relay and ChatService.
//
// A head served again (finding A). An honest log re-signs its head at least
// every ten minutes. A head served again with its `ts` not advanced used to
// be taken without its age or the witness being looked at, for as long as it
// was served, and every check said "ok".
//
// A label taken out of the map (finding B2). An honest log never takes a
// label out of its map, nor moves one back. A client that has read a label in
// the map and is shown it gone, or at an earlier entry, by a head that covers
// that entry has two heads under the log's key that cannot both be honest. It
// used to take such a contact for one who never published — sends released,
// the evidence dropped — and its own label for one not yet published, in
// silence.
//
// Criteria, each a test below:
//   1. a head served again three days after it was adopted fails the check as
//      stale: `lastOkMs` does not move and health is not ok — as a first sight
//      of the same head fails;
//   2. a head served again an hour later is put to the witness once, as a
//      first sight of it is; three days later, stale, no more than a first
//      sight of it is;
//   3. an honest log with no publishes, re-signing its head every ten minutes
//      of its clock as log.js re-signs it, stays ok through three days of
//      six-hourly checks, its witness asked once a check;
//   4. a contact in conflict, sends held, whose label the log takes out of its
//      map, growing by one real entry: a log fault naming the label, its
//      version and its entry; sends still held; the status — on disk too —
//      still the evidence it was; no other contact moved by that refresh;
//      and the head held, in memory and on disk, the one held before it, the
//      head that dropped the label beside it in the fault, not kept;
//   5. the same with the label moved back to its previous entry instead —
//      which without this would be the way round 4: unconfirmed, sends
//      released;
//   6. this account's own label, read in the map, then taken out of it — or,
//      for another account, moved back — by a head that covers it: a fault,
//      the head held the one held before that check;
// and the honest ways a label can be read as absent, none of them a fault:
//   7. a contact who has never published is unlogged refresh after refresh —
//      a verified absence each time — and confirmed once they publish, the
//      log and the label recorded with what was read;
//   8. a change of log — the address and key changed, and the history reset,
//      as Settings has it — and a status recorded under another log's key in
//      a vault whose held head did not come back: nothing compared;
//   9. a contact deleted and added back starts from nothing, and so does one
//      whose account was reset, which is another contact;
//  10. a contact whose record moves to another account (phase 33) is another
//      label: what was read of the old one is not compared with the new;
//  11. a restore: the statuses and the head it brings back raise nothing
//      against the log grown since, and are evidence there as they were here;
// and the own label's lookup, now held to the head as every other answer is:
//  12. this account's own lookup answered from another history under the
//      log's key — a head that does not extend the one held — is a log
//      fault, where it used to be read and judged as if it did.
@Tags(['integration'])
@Timeout(Duration(minutes: 3))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;
import 'package:zapp/core/archive.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/key_transparency.dart';
import 'package:zapp/core/restore.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:z_protocol/z_protocol.dart';

const int minute = 60 * 1000;
const int hour = 60 * minute;
const int day = 24 * hour;

String hexOf(List<int> b) =>
    [for (final x in b) x.toRadixString(16).padLeft(2, '0')].join();

/// A client with nobody in it: what is under test is the head.
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

/// The contacts a test gives it, as the chat service would list them, and
/// the account, when it gives one.
class _Host implements KtHost {
  final List<KtContactInput> contacts = [];
  KtOwnInput? own;
  @override
  Future<List<KtContactInput>> ktContacts() async => List.of(contacts);
  @override
  Future<KtOwnInput?> ktOwn() async => own;
  @override
  Future<bool> ktInstallFromLog(String rid, SignedDeviceList list) async =>
      false;
  @override
  void ktChanged() {}
}

/// Answers nothing: for a client that is only loaded, never checked.
class _Fails implements KtFetcher {
  @override
  Future<KtResponse> get(Uri url) async => KtResponse(500, '{}');
  @override
  Future<KtResponse> post(Uri url, String jsonBody) async =>
      KtResponse(500, '{}');
}

/// The log's code as its operator runs it (`kt/test/kt_operator_log.js`):
/// its clock and its map are lines on its stdin.
class _OperatorLog {
  _OperatorLog._(this._p);
  final Process _p;
  late final int port;
  final List<String> _said = [];

  String get url => 'http://127.0.0.1:$port';

  /// Where its witness's record is fetched — answered by the test's fetcher,
  /// never by the log.
  String get witnessUrl => '$url/witness/sth.json';

  static Future<_OperatorLog> start(String ktDir, Uint8List seed) async {
    final p = await Process.start('node', ['test/kt_operator_log.js'],
        workingDirectory: ktDir,
        environment: {'KT_SEED': hexOf(seed), 'KT_PORT': '0'});
    final log = _OperatorLog._(p);
    p.stderr.drain<void>();
    p.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen(log._said.add);
    final ready =
        await log._heard(0, (l) => l.startsWith('READY '), 'the log to serve');
    log.port = int.parse(ready.substring('READY '.length));
    return log;
  }

  Future<String> _heard(int from, bool Function(String) match, String what) async {
    final deadline = DateTime.now().add(const Duration(seconds: 20));
    while (true) {
      for (var i = from; i < _said.length; i++) {
        if (match(_said[i])) return _said[i];
      }
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('$what; the log said: ${_said.join(' | ')}');
      }
      await Future<void>.delayed(const Duration(milliseconds: 5));
    }
  }

  /// One line to the operator's hand, returning once the log has taken it.
  Future<void> tell(String line) async {
    final from = _said.length;
    _p.stdin.writeln(line);
    await _p.stdin.flush();
    final got = await _heard(
        from,
        (l) => l == 'ok $line' || l.startsWith('error $line'),
        'the log to take "$line"');
    if (got != 'ok $line') fail(got);
  }

  Future<void> stop() async {
    _p.kill();
    await _p.exitCode;
  }

  /// The log's head, as the harness reads it.
  Future<KtTreeHead> head() async =>
      KtTreeHead.fromJson((await _net.get(Uri.parse('$url/kt/v1/sth'))).json);

  /// The log's latest entry for [label], as the harness reads it: (index,
  /// version), or null.
  Future<(int, int)?> latest(Uint8List label) async {
    final r = await _net.get(Uri.parse('$url/kt/v1/lookup/${hexOf(label)}'));
    final e = r.json['entry'];
    if (e == null) return null;
    return ((e as Map)['index'] as int, e['v'] as int);
  }

  /// A publish by the account [seed] holds, of [plain] sealed at version [v]
  /// under fingerprint [fp]; the entry's index.
  Future<int> publish(Uint8List seed, Uint8List pub, int v, Uint8List fp,
      List<int> plain) async {
    final req = await ktPublishRequest(
        accountEdSeed: seed,
        version: v,
        fp: fp,
        value: await ktSealValue(pub, plain));
    final r = await _net.post(Uri.parse('$url/kt/v1/publish'), jsonEncode(req));
    expect(r.status, 201, reason: r.body);
    return (r.json['index'] as num).toInt();
  }

  /// An account nobody holds publishes its first list: the log grows by one
  /// real entry.
  Future<int> grow() async {
    final id = await ZIdentity.generate();
    return publish(id.edSeed, id.edPub, 1, randomBytes(16), utf8.encode('{}'));
  }

  final HttpKtFetcher _net = HttpKtFetcher();
}

/// The real log for everything but its witness's address, which an honest
/// witness answers: the log's head as it stands, co-signed under the key
/// pinned for it. Counts how often the witness was asked.
class _Witnessed implements KtFetcher {
  _Witnessed(this.log, this.key, this.pub);
  final _OperatorLog log;
  final SimpleKeyPair key;
  final Uint8List pub;
  final HttpKtFetcher net = HttpKtFetcher();
  int asked = 0;

  @override
  Future<KtResponse> get(Uri url) async {
    if (url.toString() != log.witnessUrl) return net.get(url);
    asked++;
    final h = await log.head();
    final sig = await Ed25519().sign(ktWitnessInput(h), keyPair: key);
    return KtResponse(
        200,
        jsonEncode({
          'sth': h.toJson(),
          'verifiedAt': h.ts,
          'size': h.size,
          'witness': {'pub': b64(pub), 'sig': b64(Uint8List.fromList(sig.bytes))},
        }));
  }

  @override
  Future<KtResponse> post(Uri url, String jsonBody) => net.post(url, jsonBody);
}

/// The log for every answer but this account's own lookup, which [other]
/// gives: another history under the same key — what a log that shows one
/// reader two histories, or whatever stands in front of it, can serve.
class _Split implements KtFetcher {
  _Split(this.log, this.other);
  final _OperatorLog log;
  final _OperatorLog other;
  final HttpKtFetcher net = HttpKtFetcher();
  int lookups = 0;

  Uri _route(Uri u) {
    if (!u.path.startsWith('/kt/v1/lookup/')) return u;
    lookups++;
    return u.replace(port: other.port);
  }

  @override
  Future<KtResponse> get(Uri url) => net.get(_route(url));

  @override
  Future<KtResponse> post(Uri url, String jsonBody) => net.post(url, jsonBody);
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

Future<Uint8List> pubOf(Uint8List seed) async => Uint8List.fromList(
    (await (await Ed25519().newKeyPairFromSeed(seed)).extractPublicKey()).bytes);

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  final root = Directory.current.parent.path;
  final ktDir = '$root${Platform.pathSeparator}kt';
  late Process relay;
  late int relayPort;
  final temps = <Directory>[];
  final vaults = <Vault>[];
  final services = <ChatService>[];
  final clients = <KeyTransparency>[];
  final logs = <_OperatorLog>[];

  // The log's key; a second log's (criterion 8); the witness's.
  final seedA =
      Uint8List.fromList(List<int>.generate(32, (i) => (i * 7 + 3) & 0xff));
  final seedB =
      Uint8List.fromList(List<int>.generate(32, (i) => (i * 5 + 1) & 0xff));
  late Uint8List pubA;
  late Uint8List pubB;
  late SimpleKeyPair witnessKey;
  late Uint8List witnessPub;

  setUpAll(() async {
    HttpOverrides.global = null;
    relayPort = await freePort();
    relay = await Process.start('node', ['server.js'],
        workingDirectory: '$root${Platform.pathSeparator}server',
        environment: {'PORT': '$relayPort', 'LOG_LEVEL': 'silent'});
    relay.stdout.drain<void>();
    relay.stderr.drain<void>();
    await waitHealthy(relayPort);
    pubA = await pubOf(seedA);
    pubB = await pubOf(seedB);
    witnessKey = await Ed25519().newKeyPairFromSeed(
        Uint8List.fromList(utf8.encode('the witness'.padRight(32, '.'))));
    witnessPub = Uint8List.fromList(
        (await witnessKey.extractPublicKey()).bytes);
  });

  tearDownAll(() async {
    for (final k in clients) {
      k.dispose();
    }
    for (final s in services) {
      s.dispose();
      await s.transport.stop();
    }
    relay.kill();
    for (final l in logs) {
      await l.stop();
    }
    for (final v in vaults) {
      try {
        await v.db.close();
      } catch (_) {}
    }
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<_OperatorLog> operatorLog({Uint8List? seed}) async {
    final l = await _OperatorLog.start(ktDir, seed ?? seedA);
    logs.add(l);
    return l;
  }

  KtConfig cfg(_OperatorLog log, {bool witness = false, Uint8List? pub}) =>
      KtConfig(
          logUrl: log.url,
          logPubB64: b64(pub ?? pubA),
          witnessUrl: witness ? log.witnessUrl : '',
          witnessPubB64: witness ? b64(witnessPub) : '');

  Future<Vault> freshVault(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_ktra_$name');
    temps.add(dir);
    final v = await Vault.open(rootOverride: dir);
    vaults.add(v);
    return v;
  }

  /// A transparency client of its own, on the clock [now].
  Future<KeyTransparency> client(
      String name, KtConfig c, KtFetcher f, int Function() now,
      {KtHost? host, Vault? vault}) async {
    final k = KeyTransparency(
        vault: vault ?? await freshVault(name),
        host: host ?? _NoHost(),
        fetcher: f,
        config: c,
        now: now);
    clients.add(k);
    return k;
  }

  Future<void> waitUntil(FutureOr<bool> Function() cond,
      {Duration timeout = const Duration(seconds: 25),
      required String what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 30));
    }
  }

  /// A chat service in [dir] (a fresh one by default) — the identity it
  /// holds, or a new one — on the relay, its log [config], refreshing when
  /// the test says so.
  Future<ChatService> start(String name, KtConfig config,
      {Directory? dir}) async {
    final home = dir ?? await Directory.systemTemp.createTemp('z_ktra_$name');
    if (dir == null) temps.add(home);
    final vault = await Vault.open(rootOverride: home);
    final stored = await vault.kvGet('identity');
    final id = stored == null
        ? await ZIdentity.generate()
        : await ZIdentity.fromJson(
            (jsonDecode(stored) as Map).cast<String, Object?>());
    if (stored == null) await vault.kvPut('identity', jsonEncode(id.toJson()));
    final svc = await ChatService.init(
        vault: vault,
        identity: id,
        displayName: name,
        transport:
            Transport(identity: id, serverUrl: 'ws://127.0.0.1:$relayPort'),
        ktConfig: config);
    svc.kt.scheduled = false;
    services.add(svc);
    return svc;
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

  Future<Uint8List> labelOf(ChatService svc) async =>
      ktLabel((await svc.accountIdentity()).accountEdPub);

  /// Until the log holds [svc]'s list at version [v] or later; its entry.
  Future<(int, int)> inLog(_OperatorLog log, ChatService svc, int v) async {
    final label = await labelOf(svc);
    (int, int)? at;
    await waitUntil(() async {
      at = await log.latest(label);
      return at != null && at!.$2 >= v;
    }, what: 'the log holding v$v for ${svc.displayName}');
    return at!;
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

  /// [ben]'s account in conflict at [alice], as key_transparency_test.dart 4
  /// makes it: someone holding Ben's seed publishes a v2 he never issued, then
  /// his own v2 reaches Alice in-band (its publish refused, the log holding
  /// v2). The status, and where Ben's v1 sits in the log.
  Future<(KtContactStatus, int)> conflict(
      ChatService alice, ChatService ben, _OperatorLog log) async {
    final (v1At, _) = await inLog(log, ben, 1);
    await alice.kt.check();
    expect(alice.kt.statusOf(ben.myRid)?.state, KtContactState.confirmed);
    final acct = await ben.accountIdentity();
    final rogue = await ZIdentity.generate();
    final rogueList = await acct.signDeviceList([
      acct.deviceCert,
      await acct.signDeviceCert(
          deviceEdPub: rogue.edPub, deviceXPub: rogue.xPub, deviceId: 'rogue'),
    ], 2);
    await log.publish(acct.accountEdSeed!, acct.accountEdPub, 2,
        await rogueList.fingerprint(), utf8.encode(jsonEncode(rogueList.toJson())));
    await linkLaptop(ben);
    await heldVersion(alice, ben.myRid, 2);
    await alice.kt.check();
    final s = alice.kt.statusOf(ben.myRid)!;
    expect(s.state, KtContactState.conflict);
    expect(s.logVersion, 2);
    expect(alice.kt.sendsHeld(ben.myRid), isTrue);
    return (s, v1At);
  }

  test('1. a head served again three days later fails as stale, as a first '
      'sight of it does', () async {
    final log = await operatorLog();
    final t0 = DateTime.now().millisecondsSinceEpoch;
    // From here the log's clock does not move: it signs a head when it grows,
    // and serves that head again to everyone who asks, however late it is.
    await log.tell('clock $t0');
    await log.grow();
    await log.grow();
    final signed = await log.head();
    expect(signed.ts, t0);
    var clock = t0 + minute;
    final kt = await client('stale1', cfg(log), HttpKtFetcher(), () => clock);
    await kt.check();
    expect(kt.health, KtHealth.ok);
    expect(kt.lastOkMs, t0 + minute);
    expect(kt.head!.ts, t0);

    // Three days on, by this device's clock, the same head served again.
    clock = t0 + 3 * day;
    await kt.check();
    expect((await log.head()).ts, t0, reason: 'the same head, served again');
    expect(kt.lastOkMs, t0 + minute,
        reason: 'until 4.7.2 a head served again was taken as current, and '
            'this was now');
    expect(kt.lastFailMs, clock, reason: 'the check failed');
    expect(kt.health, isNot(KtHealth.ok));
    expect(kt.health, KtHealth.unreachable,
        reason: 'a frozen head is a log that cannot be reached (ADR 0006)');
    expect(kt.fault, isNull, reason: 'and not a fault');
    expect(kt.head!.ts, t0, reason: 'the head held is the one adopted');

    // As a first sight of the same head, at the same moment, fails.
    final first = await client('stale1b', cfg(log), HttpKtFetcher(), () => clock);
    await first.check();
    expect(first.head, isNull);
    expect(first.lastFailMs, clock);
    expect(first.health, KtHealth.unreachable);
  });

  test('2. a head served again is put to the witness as a first sight of it '
      'is', () async {
    final log = await operatorLog();
    final t0 = DateTime.now().millisecondsSinceEpoch;
    await log.tell('clock $t0');
    await log.grow();
    await log.grow();
    var clock = t0 + minute;
    final f = _Witnessed(log, witnessKey, witnessPub);
    final kt = await client('witness2', cfg(log, witness: true), f, () => clock);
    await kt.check();
    expect(kt.health, KtHealth.ok);
    expect(f.asked, 1,
        reason: 'a first sight: asked once, for every answer of the refresh');
    expect(kt.witnessOkMs, clock);

    // An hour on, the same head served again.
    clock = t0 + hour;
    await kt.check();
    expect(f.asked, 2,
        reason: 'asked about the head served again — until 4.7.2, never, for '
            'as long as it was served');
    expect(kt.witnessOkMs, clock, reason: 'and it agreed again');
    expect(kt.health, KtHealth.ok);
    final g = _Witnessed(log, witnessKey, witnessPub);
    final first =
        await client('witness2b', cfg(log, witness: true), g, () => clock);
    await first.check();
    expect(g.asked, 1, reason: 'as a first sight of the same head is');

    // Three days on: stale before the witness is reached, both ways.
    clock = t0 + 3 * day;
    await kt.check();
    expect(f.asked, 2);
    expect(kt.health, isNot(KtHealth.ok));
    final h = _Witnessed(log, witnessKey, witnessPub);
    final third =
        await client('witness2c', cfg(log, witness: true), h, () => clock);
    await third.check();
    expect(h.asked, 0, reason: 'a first sight of a stale head asks nothing');
    expect(third.health, KtHealth.unreachable);
  });

  test('3. an honest log with no publishes stays ok for days, its witness '
      'asked once a check', () async {
    final log = await operatorLog();
    final t0 = DateTime.now().millisecondsSinceEpoch;
    await log.tell('clock $t0');
    await log.grow();
    await log.grow();
    await log.grow();
    final size = (await log.head()).size;
    var clock = t0;
    final f = _Witnessed(log, witnessKey, witnessPub);
    final kt = await client('honest3', cfg(log, witness: true), f, () => clock);
    var resigned = 0;
    for (var k = 1; k <= 12; k++) {
      final at = t0 + k * 6 * hour;
      // Between two of this device's checks the log re-signs its head as
      // log.js does — when it is ten minutes old and somebody asks: a
      // mirror, the witness, another reader — every ten minutes of its clock.
      var last = (await log.head()).ts;
      for (var t = at - 6 * hour + 10 * minute; t < at; t += 10 * minute) {
        await log.tell('clock $t');
        final ts = (await log.head()).ts;
        if (ts != last) resigned++;
        last = ts;
      }
      await log.tell('clock $at');
      clock = at;
      final before = f.asked;
      await kt.check();
      expect(kt.fault, isNull, reason: 'check $k');
      expect(kt.lastFailMs, 0, reason: 'check $k');
      expect(kt.lastOkMs, at, reason: 'check $k');
      expect(kt.health, KtHealth.ok, reason: 'check $k');
      expect(kt.head!.size, size, reason: 'no publishes');
      expect(kt.head!.ts, at, reason: 're-signed at the check, as it is for anyone');
      expect(f.asked - before, 1,
          reason: 'check $k: one question to the witness for the whole refresh '
              '— its head, its buckets and its entries answered under one head');
      expect(kt.witnessOkMs, at);
    }
    expect(resigned, 12 * 35, reason: 'the log re-signed every ten minutes');
  });

  test('4. a contact in conflict whose label the log takes out of its map is '
      'a log fault: sends stay held, and the evidence stays', () async {
    final log = await operatorLog();
    final alice = await start('alice4', cfg(log));
    final ben = await start('ben4', cfg(log));
    final cleo = await start('cleo4', cfg(log));
    await befriend(alice, ben);
    await befriend(alice, cleo);
    await inLog(log, alice, 1);
    await inLog(log, cleo, 1);
    final (s, _) = await conflict(alice, ben, log);
    final evidence = jsonEncode(s.toJson());
    expect(alice.kt.statusOf(cleo.myRid)?.state, KtContactState.confirmed);
    expect(alice.kt.statusOf(cleo.myRid)?.logVersion, 1);
    final cleoBefore = jsonEncode(alice.kt.statusOf(cleo.myRid)!.toJson());
    final okAt = alice.kt.lastOkMs;

    // Alice goes offline; Cleo links a laptop, and her v2 reaches the log
    // and not Alice: news in the next refresh's answers.
    await alice.transport.stop();
    await linkLaptop(cleo);
    await inLog(log, cleo, 2);

    // The operator takes Ben's label out of the map; the log grows by one
    // real entry, its tree consistent with every head before.
    final label = await labelOf(ben);
    await log.tell('drop ${hexOf(label)}');
    await log.grow();
    final before = alice.kt.head!;
    await alice.kt.check();
    expect(alice.kt.health, KtHealth.fault,
        reason: 'until 4.7.2: unlogged — sends released, the evidence gone, '
            'health ok');
    final reason = alice.kt.fault!.reason;
    expect(reason, contains("a contact's label ${hexOf(label).substring(0, 16)}"));
    expect(reason, contains('(v2, entry ${s.logIndex}) is missing from the map'));
    expect(alice.kt.sendsHeld(ben.myRid), isTrue);
    await expectLater(alice.sendText(ben.myRid, 'held?'),
        throwsA(isA<KtSendHeldException>()));
    expect(jsonEncode(alice.kt.statusOf(ben.myRid)!.toJson()), evidence,
        reason: 'nothing it showed is reset');
    expect(alice.kt.lastOkMs, okAt, reason: 'nothing of that refresh counts');
    // Cleo's newer list came in the same refresh's answers, and was not
    // taken: nothing new is confirmed under a log caught contradicting itself.
    expect(jsonEncode(alice.kt.statusOf(cleo.myRid)!.toJson()), cleoBefore);
    expect(await alice.heldContactListVersion(cleo.myRid), 1);
    // Nor is the head that left the label out: the one held before that
    // refresh is held, and the fault names the two.
    final dropped = await log.head();
    expect(dropped.size, greaterThan(before.size));
    expect(jsonEncode(alice.kt.head!.toJson()), jsonEncode(before.toJson()),
        reason: 'until 4.7.2 the head held was the one that dropped it');
    expect(jsonEncode(alice.kt.fault!.held!.toJson()),
        jsonEncode(before.toJson()));
    expect(alice.kt.fault!.served!.size, dropped.size);
    expect(alice.kt.fault!.served!.sameRootsAs(dropped), isTrue);

    // On disk as in memory.
    final again = await client('again4', cfg(log), _Fails(),
        () => DateTime.now().millisecondsSinceEpoch,
        vault: alice.vault);
    await again.load();
    expect(again.health, KtHealth.fault);
    expect(again.fault!.reason, reason);
    expect(jsonEncode(again.statusOf(ben.myRid)!.toJson()), evidence);
    expect(jsonEncode(again.head!.toJson()), jsonEncode(before.toJson()));
    expect(jsonEncode(again.fault!.held!.toJson()), jsonEncode(before.toJson()));
    expect(again.fault!.served!.sameRootsAs(dropped), isTrue);
  });

  test('5. a contact in conflict whose label the log moves back to its previous '
      'entry is a log fault too, not an unconfirmed list', () async {
    final log = await operatorLog();
    final alice = await start('alice5', cfg(log));
    final ben = await start('ben5', cfg(log));
    await befriend(alice, ben);
    await inLog(log, alice, 1);
    final (s, v1At) = await conflict(alice, ben, log);
    final evidence = jsonEncode(s.toJson());

    final label = await labelOf(ben);
    await log.tell('back ${hexOf(label)}');
    await log.grow();
    expect(await log.latest(label), (v1At, 1),
        reason: 'the map names his v1 entry again');
    await alice.kt.check();
    expect(alice.kt.health, KtHealth.fault,
        reason: 'until 4.7.2: held v2, log has v1 — unconfirmed, and sends '
            'released');
    expect(alice.kt.fault!.reason,
        contains("a contact's label ${hexOf(label).substring(0, 16)}"));
    expect(alice.kt.fault!.reason,
        contains('(v2, entry ${s.logIndex}) is v1, entry $v1At, in the map'));
    expect(alice.kt.sendsHeld(ben.myRid), isTrue);
    await expectLater(alice.sendText(ben.myRid, 'held?'),
        throwsA(isA<KtSendHeldException>()));
    expect(jsonEncode(alice.kt.statusOf(ben.myRid)!.toJson()), evidence);
  });

  test('6. this account\'s own label, taken out of the map or moved back after '
      'this device read it there, is a log fault', () async {
    final log = await operatorLog();
    final ben = await start('ben6', cfg(log));
    final label = await labelOf(ben);
    final (at, _) = await inLog(log, ben, 1);
    await ben.kt.check(); // reads it back in the map
    expect(ben.kt.fault, isNull);
    expect(ben.kt.health, KtHealth.ok);
    await log.tell('drop ${hexOf(label)}');
    await log.grow();
    final before = ben.kt.head!;
    await ben.kt.check();
    expect(ben.kt.health, KtHealth.fault,
        reason: 'until 4.7.2 nothing at all: no publish, since the log had '
            'acknowledged the list, and no alarm, with no entry to judge');
    final dropped = await log.head();
    expect(ben.kt.fault!.reason,
        "this account's label ${hexOf(label).substring(0, 16)} (v1, entry $at) "
        'is missing from the map at size ${dropped.size}');
    // The head that left it out is not kept; the one held before is.
    expect(dropped.size, greaterThan(before.size));
    expect(jsonEncode(ben.kt.head!.toJson()), jsonEncode(before.toJson()));
    expect(await ben.vault.kvGet('kt_head'), jsonEncode(before.toJson()),
        reason: 'and on disk');
    expect(jsonEncode(ben.kt.fault!.held!.toJson()), jsonEncode(before.toJson()));
    expect(ben.kt.fault!.served!.sameRootsAs(dropped), isTrue);

    // Moved back, for another account: Cleo's v2 read in the map, then the
    // map naming her v1 entry again.
    final cleo = await start('cleo6', cfg(log));
    final cleoLabel = await labelOf(cleo);
    final (c1, _) = await inLog(log, cleo, 1);
    await cleo.kt.check();
    await linkLaptop(cleo);
    final (c2, _) = await inLog(log, cleo, 2);
    await cleo.kt.check();
    expect(cleo.kt.fault, isNull);
    await log.tell('back ${hexOf(cleoLabel)}');
    await log.grow();
    final held = cleo.kt.head!;
    await cleo.kt.check();
    expect(cleo.kt.health, KtHealth.fault);
    expect(cleo.kt.fault!.reason,
        contains("this account's label ${hexOf(cleoLabel).substring(0, 16)} "
            '(v2, entry $c2) is v1, entry $c1, in the map'));
    final moved = await log.head();
    expect(jsonEncode(cleo.kt.head!.toJson()), jsonEncode(held.toJson()));
    expect(jsonEncode(cleo.kt.fault!.held!.toJson()), jsonEncode(held.toJson()));
    expect(cleo.kt.fault!.served!.sameRootsAs(moved), isTrue);
    expect(moved.sameRootsAs(held), isFalse);
  });

  test('7. a contact who has never published is unlogged at every refresh, '
      'and confirmed once they publish', () async {
    final log = await operatorLog();
    final alice = await start('alice7', cfg(log));
    final ben = await start('ben7', KtConfig.off);
    await befriend(alice, ben);
    for (var i = 0; i < 3; i++) {
      await alice.kt.check();
      final s = alice.kt.statusOf(ben.myRid);
      expect(s?.state, KtContactState.unlogged,
          reason: 'refresh $i: his bucket asked, and he is not in it');
      expect(alice.kt.fault, isNull);
      expect(alice.kt.health, KtHealth.ok);
      expect(s!.toJson().containsKey('lk'), isFalse,
          reason: 'nothing read of him, so nothing recorded');
    }
    expect(alice.kt.sendsHeld(ben.myRid), isFalse);

    // His log comes on: he publishes, and is confirmed — what was read
    // recorded with the log it was read in and the label it was read for.
    await ben.setKtConfig(cfg(log));
    await inLog(log, ben, 1);
    await alice.kt.check();
    final s = alice.kt.statusOf(ben.myRid)!;
    expect(s.state, KtContactState.confirmed);
    expect(alice.kt.fault, isNull);
    expect(s.toJson()['lk'], b64(pubA));
    expect(s.toJson()['lb'], b64(await labelOf(ben)));
  });

  test('8. a change of log compares nothing read under the old one', () async {
    final logA = await operatorLog();
    final logB = await operatorLog(seed: seedB);
    for (var i = 0; i < 4; i++) {
      await logB.grow();
    }
    final alice = await start('alice8', cfg(logA));
    final ben = await start('ben8', cfg(logA));
    await befriend(alice, ben);
    await inLog(logA, ben, 1);
    await alice.kt.check();
    expect(alice.kt.statusOf(ben.myRid)?.state, KtContactState.confirmed);

    // Settings: the address and the key changed. The head held is the old
    // log's, which the new one does not extend — caught there, before any
    // contact is looked at.
    await alice.kt.setConfig(cfg(logB, pub: pubB));
    await alice.kt.check();
    expect(alice.kt.health, KtHealth.fault);
    expect(alice.kt.fault!.reason, isNot(contains('label')),
        reason: 'the head, not a contact: ${alice.kt.fault!.reason}');
    // And the history reset, as Settings asks: Ben is not in the new log,
    // and nothing read of him in the old one is held against it.
    await alice.kt.resetHistory();
    await alice.kt.check();
    expect(alice.kt.fault, isNull);
    expect(alice.kt.health, KtHealth.ok);
    expect(alice.kt.statusOf(ben.myRid)?.state, KtContactState.unlogged);

    // A status read in log A, in a vault whose held head did not come back —
    // the one state a change of log is not caught by the head in — read with
    // log B configured: another log's key, so nothing is compared.
    final v = await freshVault('lost8');
    final host = _Host();
    final dan = await ZIdentity.generate();
    final fp = randomBytes(16);
    await logA.publish(dan.edSeed, dan.edPub, 1, fp, utf8.encode('{}'));
    final rid = await dan.routingId();
    host.contacts.add(KtContactInput(
        rid: rid,
        accountEdPub: dan.edPub,
        held: null,
        heldAtMs: null,
        heldVersion: 1,
        heldFpB64: b64(fp),
        primaryDeviceEdPub: dan.edPub));
    final ka = await client('lost8a', cfg(logA), HttpKtFetcher(),
        () => DateTime.now().millisecondsSinceEpoch,
        host: host, vault: v);
    await ka.check();
    final read = ka.statusOf(rid)!;
    expect(read.state, KtContactState.confirmed);
    while ((await logB.head()).size <= read.logIndex!) {
      await logB.grow();
    }
    await v.kvDelete('kt_head');
    final kb = await client('lost8b', cfg(logB, pub: pubB), HttpKtFetcher(),
        () => DateTime.now().millisecondsSinceEpoch,
        host: host, vault: v);
    await kb.load();
    expect(kb.head, isNull);
    expect(kb.statusOf(rid)?.state, KtContactState.confirmed);
    await kb.check();
    expect(kb.fault, isNull,
        reason: 'what log A showed is not evidence against log B');
    expect(kb.statusOf(rid)?.state, KtContactState.unlogged);
  });

  test('9. a contact deleted and added back starts from nothing, as does one '
      'whose account was reset', () async {
    final log = await operatorLog();
    final alice = await start('alice9', cfg(log));
    final ben = await start('ben9', cfg(log));
    await befriend(alice, ben);
    await inLog(log, ben, 1);
    await alice.kt.check();
    expect(alice.kt.statusOf(ben.myRid)?.state, KtContactState.confirmed);
    await alice.deleteContact(ben.myRid);
    expect(alice.kt.statusOf(ben.myRid), isNull);
    expect(await alice.vault.kvGet('ktc_${ben.myRid}'), isNull);

    // While he is not her contact his label leaves the map; she adds him back.
    await log.tell('drop ${hexOf(await labelOf(ben))}');
    await log.grow();
    await alice.addContactFromCode(await ben.myContactCode());
    await alice.kt.check();
    expect(alice.kt.fault, isNull,
        reason: 'nothing read of him survived his deletion');
    expect(alice.kt.statusOf(ben.myRid)?.state, KtContactState.unlogged);

    // Ben resets his account: a new identity, so a new label and a new
    // contact, not yet in the log.
    final reset = await start('ben9reset', KtConfig.off);
    await befriend(alice, reset);
    await alice.kt.check();
    expect(alice.kt.fault, isNull);
    expect(alice.kt.statusOf(reset.myRid)?.state, KtContactState.unlogged);
  });

  test('10. a contact whose record moves to another account is another '
      'label, and what was read of the old one is not compared', () async {
    final log = await operatorLog();
    // A contact made from a device whose key stood for the account (§3.5),
    // and under that key a list is in the log.
    final device = await ZIdentity.generate();
    final account = await ZIdentity.generate();
    final fp = randomBytes(16);
    await log.publish(device.edSeed, device.edPub, 1, fp, utf8.encode('{}'));
    final rid = await device.routingId();
    final host = _Host();
    KtContactInput input(Uint8List acct) => KtContactInput(
        rid: rid,
        accountEdPub: acct,
        held: null,
        heldAtMs: null,
        heldVersion: 1,
        heldFpB64: b64(fp),
        primaryDeviceEdPub: device.edPub);
    host.contacts.add(input(device.edPub));
    final kt = await client('anchor10', cfg(log), HttpKtFetcher(),
        () => DateTime.now().millisecondsSinceEpoch,
        host: host);
    await kt.check();
    expect(kt.statusOf(rid)?.state, KtContactState.confirmed);
    // The record moves to the account the device belongs to, as
    // `ChatService._reanchorFromList` moves it: another label, one the log
    // has never held.
    host.contacts[0] = input(account.edPub);
    await log.grow();
    await kt.check();
    expect(kt.fault, isNull,
        reason: "what was read of the device's label is not the account's");
    expect(kt.statusOf(rid)?.state, KtContactState.unlogged);
  });

  test('11. a restore brings back evidence that raises nothing against an '
      'honest log, and holds the log to it', () async {
    final log = await operatorLog();
    final home = await Directory.systemTemp.createTemp('z_ktra_alice11');
    temps.add(home);
    final alice = await start('alice11', cfg(log), dir: home);
    final ben = await start('ben11', cfg(log));
    await befriend(alice, ben);
    await inLog(log, ben, 1);
    await alice.kt.check();
    expect(alice.kt.statusOf(ben.myRid)?.state, KtContactState.confirmed);

    // A backup; the phone lost; the log grows; the backup restored.
    final code = await RecoveryCode.generate();
    final out = await Directory.systemTemp.createTemp('z_ktra_bk11');
    temps.add(out);
    final file = File(p.join(out.path, 'b.zbk'));
    final sink = file.openWrite();
    await BackupArchive.export(vault: alice.vault, code: code, out: sink);
    await sink.close();
    await stop(alice);
    for (var i = 0; i < 3; i++) {
      await log.grow();
    }
    final dir2 = await Directory.systemTemp.createTemp('z_ktra_alice11b');
    temps.add(dir2);
    final restored = await Vault.open(rootOverride: dir2);
    await Restore.run(
        vault: restored,
        file: file,
        secret: await code.format(),
        kind: (await Restore.identify(file)).kind,
        serverUrl: 'ws://127.0.0.1:$relayPort');
    await restored.db.close();
    final alice2 = await start('alice11', cfg(log), dir: dir2);
    expect(alice2.kt.statusOf(ben.myRid)?.state, KtContactState.confirmed,
        reason: 'the status came with the backup');
    await alice2.kt.check();
    expect(alice2.kt.fault, isNull);
    expect(alice2.kt.health, KtHealth.ok);
    expect(alice2.kt.statusOf(ben.myRid)?.state, KtContactState.confirmed);

    // What it brought back is evidence there as it was on the phone.
    final label = await labelOf(ben);
    await log.tell('drop ${hexOf(label)}');
    await log.grow();
    await alice2.kt.check();
    expect(alice2.kt.health, KtHealth.fault);
    expect(alice2.kt.fault!.reason,
        contains("a contact's label ${hexOf(label).substring(0, 16)}"));
  });

  test('12. this account\'s own lookup answered under a head that does not '
      'extend the one held is a log fault', () async {
    // The log, and another history under its key, of the same size: this
    // account's list in the one, not in the other.
    final log = await operatorLog();
    final other = await operatorLog();
    final me = await ZIdentity.generate();
    final fp = randomBytes(16);
    await log.publish(me.edSeed, me.edPub, 1, fp, utf8.encode('{}'));
    await log.grow();
    await log.grow();
    for (var i = 0; i < 3; i++) {
      await other.grow();
    }
    final held = await log.head();
    final forked = await other.head();
    expect(forked.size, held.size);
    expect(forked.sameRootsAs(held), isFalse);
    expect(await other.latest(await ktLabel(me.edPub)), isNull);

    // A linked device of that account — no seed, so nothing of its own to
    // publish — and its list v1 in the log: every answer from the log but
    // the account's own lookup, which comes from the other.
    final host = _Host()
      ..own = KtOwnInput(
          accountEdPub: me.edPub,
          version: 1,
          fpB64: b64(fp),
          listJson: null,
          accountEdSeed: null);
    final f = _Split(log, other);
    final kt = await client('own12', cfg(log), f,
        () => DateTime.now().millisecondsSinceEpoch,
        host: host);
    await kt.check();
    expect(f.lookups, 1, reason: 'the own lookup, answered by the other');
    expect(kt.health, KtHealth.fault,
        reason: 'until 4.7.2 that answer was read as if its head were the '
            'one held: this account not in the log, and nothing said');
    expect(kt.fault!.reason, 'same size ${held.size}, different roots — a fork');
    expect(kt.fault!.held!.sameRootsAs(held), isTrue);
    expect(kt.fault!.served!.sameRootsAs(forked), isTrue);
    expect(kt.head!.sameRootsAs(held), isTrue,
        reason: 'the head held is the log\'s, not the other history\'s');
  });
}
