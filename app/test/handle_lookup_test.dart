// The handle resolver (phase 38; PROTOCOL.md §21.8, "Finding and asking";
// the 2026-10-09 review of handles, findings 3 and 5): real ChatService
// instances on the real relay (server/server.js), asking the real handle
// log's code (kt/) as its operator can run it (kt/test/handle_operator_log.js)
// — filled with labels nobody can name, its signed size inflated with
// versions, or with the owner rule taken out. A fetcher in front of the log
// writes down every request and plays the operator's other part: rewriting
// the unsigned `bucketBits`, or refusing buckets as too large.
//
// Criteria, each a test below:
//   1. the clamp: with `bucketBits` rewritten to 24, a lookup in a log of
//      1,001 handles asks at the k their number bears out (4) and no finer —
//      the handle's bucket among its decoys', each once, exactly the buckets
//      this install's decoy key gives — and finds it; a log of one handle is
//      asked whole (the review's P2a);
//   2. size inflation: in a log of 301 handles whose signed size four of
//      them inflate past 4,000 with versions, and `bucketBits` rewritten to
//      24, a fresh install's estimate starts at the k the size allows (7)
//      and its lookups ask where the handles put 16 or more in a bucket on
//      average (k ≤ 4), first lookup and every one after;
//   3. too large is never narrowed: with every bucket below 24 bits refused,
//      a lookup ends unreachable having asked the handle's bucket not at all
//      and only random ones, one bit finer each, within the probe's eight
//      (the review's P2b); with the lookup's own k refused, it ends
//      unreachable having asked the same buckets and nothing finer; and an
//      estimate the log outgrew (k = 1 in a log of 1,000, refused by the log
//      itself as too large) is made again from random buckets, and the
//      handle found at k = 4 with no k between asked;
//   4. decoys: looking a handle up again asks the same buckets in the same
//      order, a restart of the app keeps them, and another handle's are its
//      own — each set exactly what the install's key gives for the label;
//   5. the estimate moves with the evidence: one the handles do not bear out
//      (7 in the inflated log) falls in one lookup to what they do; one below
//      them (0 in a log of 201) rises a bit a lookup, 0, 1, 2;
//   6. a requester remembers the owner (the review's P4): a log without the
//      owner rule names another owner and mailbox, and the requester's next
//      lookup is refused as changed (owner), with nothing to send to; looked
//      up as new, the new owner is taken; a genuine recover — the code's key
//      opening the commitment remembered — and a new inbox after it are
//      found with no question; a recover followed by a change the requester
//      never saw is refused (one record cannot tell the code's work from the
//      log's);
//   7. history: another record at a version already seen, an older version,
//      and a handle the log no longer holds (the log restarted empty under
//      its key) are each refused as changed (history);
//   8. stale heads: an answer signed more than a day ago by the requester's
//      clock fails as stale, one 23 hours old does not, and a clock three
//      days behind is no failure;
//   9. versions no honest log serves: an update at 2^53 − 1 (a thief with the
//      owner key, a log without the next-version rule) makes a lookup, the
//      owner's own change and a recover with the code fail as a bad answer —
//      a HandleException, never an ArgumentError; so does an update at a
//      version past its index + 1; a claim at version 2 is invalid;
//  10. backup and restore carry the memory: the restored device asks the
//      buckets the old one asked for a handle and refuses the owner change
//      the old one would have; a memory in an archive that is not one is
//      left out;
//  11. the screen says why: a lookup refused as changed says so — owner or
//      history — in English and Spanish, offers no request and offers to look
//      it up as new; a stale answer has words of its own;
//  12. the rules on their own: k from a count, the probe's steps, the
//      estimate's fall and one-bit rise, decoys a function of key and label
//      that nest from one k to the next — and two installs' sets for one
//      handle meeting in exactly its bucket, the residual the trust table
//      names — the leaf rule (2^53 − 1 refused at an index that would allow
//      it), what one record can follow, and the stored memory held to its
//      shape and cap;
//  13. refusing cannot raise k (the second review's P2): in a log of 301
//      handles inflated to 16,000 entries, `bucketBits` rewritten to 24, an
//      operator that answers the first random bucket honestly and, when its
//      count alone would put k above the honest 3, refuses the coarser
//      bucket asked next, gets nothing: the probe asks a fresh bucket one bit
//      finer and goes on until one holds 32, and no lookup of the handle asks
//      its bucket finer than 3 (the base took the count before the refusal
//      as the estimate, and asked at 4 or finer);
//  14. a bucket counts only under the head held when it was drawn: an
//      operator that mints 32 labels into the first random bucket on seeing
//      it asked, and answers under the head that holds them, is not counted
//      — the probe draws again and the lookup asks at the honest k (the base
//      counted the 32 and asked at the 8 the inflated size allows); and
//      within one lookup the head only grows: an older answer served again
//      after the log grew is a bad answer, while a lookup that read an older
//      head and is answered under a newer one takes it with its consistency
//      proof.
@Tags(['integration'])
@Timeout(Duration(minutes: 8))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' show Ed25519;
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;
import 'package:zapp/core/archive.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/handle_lookups.dart';
import 'package:zapp/core/handles.dart';
import 'package:zapp/core/key_transparency.dart';
import 'package:zapp/core/restore.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/l10n/app_localizations_en.dart';
import 'package:zapp/l10n/app_localizations_es.dart';
import 'package:zapp/l10n/handle_text.dart';
import 'package:zapp/ui/find_handle_screen.dart';
import 'package:zapp/ui/theme.dart';
import 'package:z_protocol/z_protocol.dart';

/// The operator's hand on the wire: the real fetcher, every URL written
/// down, and — as whoever runs the log or terminates its TLS can — the
/// unsigned `bucketBits` rewritten, or buckets refused as too large.
class _Operator implements KtFetcher {
  final _inner = HttpKtFetcher();
  final urls = <Uri>[];
  int? bucketBits;
  bool Function(KtBucketQuery q)? refuse;

  /// Called with each bucket asked, before the log answers it: the
  /// operator's moment to change the log on seeing what was asked.
  Future<void> Function(KtBucketQuery q)? onBucket;

  /// An operator that knows the honest k and waits for its chance: when a
  /// bucket's count alone would put k above it, the next bucket asked
  /// coarser than that one is refused — once.
  int? refuseAboveHonest;
  int? _armedBelow;
  int refusals = 0;

  /// Keep every answer (by path), and serve the kept one again.
  bool keep = false;
  bool replay = false;
  final kept = <String, KtResponse>{};

  static KtBucketQuery _query(Uri u) => KtBucketQuery.parse(
      u.queryParameters['prefix']!, int.parse(u.queryParameters['bits']!));

  static const _tooLarge =
      '{"error":"bucket_too_large","message":"ask for more bits"}';

  @override
  Future<KtResponse> get(Uri url) async {
    urls.add(url);
    final path = '${url.path}?${url.query}';
    if (replay && kept.containsKey(path)) return kept[path]!;
    final isBucket = url.path == '/kt/v1/bucket';
    if (isBucket) {
      final q = _query(url);
      if (refuse?.call(q) ?? false) return KtResponse(400, _tooLarge);
      final below = _armedBelow;
      if (below != null && q.bits < below) {
        _armedBelow = null;
        refusals++;
        return KtResponse(400, _tooLarge);
      }
      await onBucket?.call(q);
    }
    var r = await _inner.get(url);
    if (bucketBits != null && url.path == '/kt/v1/sth' && r.status == 200) {
      final j = (jsonDecode(r.body) as Map).cast<String, Object?>();
      j['bucketBits'] = bucketBits;
      r = KtResponse(r.status, jsonEncode(j));
    }
    final honest = refuseAboveHonest;
    if (isBucket && honest != null && r.status == 200 && refusals == 0) {
      final j = r.json;
      final count = (j['leaves'] as List).length;
      final bits = j['bits'] as int;
      if (handleBitsFor(count * (1 << bits)) > honest) _armedBelow = bits;
    }
    if (keep) kept[path] = r;
    return r;
  }

  @override
  Future<KtResponse> post(Uri url, String jsonBody) {
    urls.add(url);
    return _inner.post(url, jsonBody);
  }

}

/// A handle log run by kt/test/handle_operator_log.js.
class _Log {
  _Log(this.process, this.port, this.seed, this.pub, this.size, this.labels);
  Process process;
  final int port;
  final Uint8List seed;
  final Uint8List pub;
  final int size;
  final int labels;
  HandleConfig get config =>
      HandleConfig(logUrl: 'http://127.0.0.1:$port', logPubB64: b64(pub));
}

/// A handle's owner outside the app, publishing straight to a log as any
/// client can.
class _Owner {
  _Owner(this.handle, this.label, this.ownerSeed, this.introSeed, this.rk);
  final String handle;
  final Uint8List label;
  Uint8List ownerSeed;
  Uint8List introSeed;
  HandleRecoveryKey rk;
  int version = 0;

  Future<String> introRid() async =>
      introRoutingId((await handleIntroIdentity(introSeed)).edPub);
}

/// One lookup as the log saw it.
class _Look {
  _Look(this.found, this.error, this.asked, this.probed);
  final HandleLookup? found;
  final Object? error;

  /// The lookup's own buckets, in the order asked ...
  final List<KtBucketQuery> asked;

  /// ... and the estimate's random ones, when it made one.
  final List<KtBucketQuery> probed;

  Set<int> get bits => {for (final q in asked) q.bits};
}

Matcher failsWith(HandleFailure f) => throwsA(
    isA<HandleException>().having((e) => e.failure, 'failure', f));

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  final root = Directory.current.parent.path;
  late Process relay;
  late int relayPort;
  final logs = <_Log>[];
  final temps = <Directory>[];
  final services = <ChatService>[];
  var seeds = 0;

  String hex(List<int> b) =>
      [for (final x in b) x.toRadixString(16).padLeft(2, '0')].join();

  Future<int> freePort() async {
    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final port = probe.port;
    await probe.close();
    return port;
  }

  Future<Uint8List> pubOf(Uint8List seed) async => Uint8List.fromList(
      (await (await Ed25519().newKeyPairFromSeed(seed)).extractPublicKey())
          .bytes);

  setUpAll(() async {
    relayPort = await freePort();
    relay = await Process.start('node', ['server.js'],
        workingDirectory: '$root/server',
        environment: {'PORT': '$relayPort', 'LOG_LEVEL': 'silent'});
    relay.stdout.drain<void>();
    relay.stderr.drain<void>();
    for (var i = 0; i < 150; i++) {
      try {
        final res = await (await HttpClient()
                .getUrl(Uri.parse('http://127.0.0.1:$relayPort/health')))
            .close();
        await res.drain<void>();
        if (res.statusCode == 200) return;
      } catch (_) {}
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    fail('the relay did not start');
  });

  tearDownAll(() async {
    for (final s in services) {
      s.dispose();
      await s.transport
          .stop()
          .timeout(const Duration(seconds: 10), onTimeout: () {});
    }
    relay.kill();
    for (final l in logs) {
      l.process.kill();
    }
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<Process> spawnLog(Uint8List seed, int port,
      {int labels = 0, String? versions, bool ruleless = false,
      required Completer<List<String>> ready}) async {
    final proc = await Process.start('node', ['test/handle_operator_log.js'],
        workingDirectory: '$root/kt',
        environment: {
          'KT_SEED': hex(seed),
          'KT_PORT': '$port',
          'FILL_LABELS': '$labels',
          if (versions != null) 'FILL_VERSIONS': versions,
          if (ruleless) 'RULELESS': '1',
        });
    proc.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen((line) {
      if (line.startsWith('READY ') && !ready.isCompleted) {
        ready.complete(line.split(' '));
      }
    });
    proc.stderr.drain<void>();
    return proc;
  }

  /// A handle log of [labels] handles nobody can name, [versions] ("a:v")
  /// inflating the first a of them to version v, the owner rule taken out
  /// when [ruleless].
  Future<_Log> startLog(
      {int labels = 0, String? versions, bool ruleless = false}) async {
    final n = ++seeds;
    final seed =
        Uint8List.fromList(List<int>.generate(32, (i) => (i * 29 + n * 7 + 3) & 0xff));
    final ready = Completer<List<String>>();
    final proc = await spawnLog(seed, 0,
        labels: labels, versions: versions, ruleless: ruleless, ready: ready);
    final parts = await ready.future.timeout(const Duration(seconds: 120));
    final log = _Log(proc, int.parse(parts[1]), seed, await pubOf(seed),
        int.parse(parts[2]), int.parse(parts[3]));
    logs.add(log);
    return log;
  }

  /// The same log, stopped and started again under its key and on its port
  /// with nothing in it: a log that forgot.
  Future<void> restartEmpty(_Log log, {bool ruleless = true}) async {
    log.process.kill();
    await log.process.exitCode;
    final ready = Completer<List<String>>();
    log.process =
        await spawnLog(log.seed, log.port, ruleless: ruleless, ready: ready);
    await ready.future.timeout(const Duration(seconds: 60));
  }

  // Logs more than one test asks: started once, when first asked for.
  Future<_Log>? big, inflated, tall;
  Future<_Log> bigLog() => big ??= startLog(labels: 1000);
  Future<_Log> inflatedLog() => inflated ??= startLog(labels: 300, versions: '4:1000');
  // 301 handles and ~16,300 entries: the signed size allows k = 8 where the
  // handles bear out 3. Criterion 14 mints labels into it, so it is the last
  // to use it.
  Future<_Log> tallLog() => tall ??= startLog(labels: 300, versions: '4:4000');

  Future<(int, String)> publishTo(_Log log, HandleEntry e) async {
    final req = await HttpClient()
        .postUrl(Uri.parse('http://127.0.0.1:${log.port}/kt/v1/publish'));
    req.headers.contentType = ContentType.json;
    req.write(jsonEncode(e.toPublishJson()));
    final res = await req.close();
    return (res.statusCode, await res.transform(utf8.decoder).join());
  }

  Future<void> put(_Log log, Uint8List label, int version, HandleRecord rec,
      Uint8List ownerSeed) async {
    final e = await signHandleEntry(
        label: label, version: version, record: rec, ownerSeed: ownerSeed);
    final (st, body) = await publishTo(log, e);
    expect(st, 201, reason: body);
  }

  Future<HandleRecord> recordOf(HandleRecordKind kind, Uint8List ownerSeed,
      Uint8List introSeed, Uint8List rc) async {
    final owner = await handleKeyPublic(ownerSeed);
    final intro = await handleIntroIdentity(introSeed);
    return kind == HandleRecordKind.claim
        ? HandleRecord.claim(
            owner: owner, intro: intro.edPub, xintro: intro.xPub, pow: 16, rc: rc)
        : HandleRecord.update(
            owner: owner, intro: intro.edPub, xintro: intro.xPub, pow: 16, rc: rc);
  }

  /// [handle] claimed straight into [log], with a recovery code of its own.
  Future<_Owner> claimAt(_Log log, String handle) async {
    final label = await handleLabel(Handle.parse(handle));
    final code = await RecoveryCode.generate();
    final o = _Owner(handle, label, randomBytes(32), randomBytes(32),
        await handleRecoveryKey(code, label));
    await put(log, label, 1,
        await recordOf(HandleRecordKind.claim, o.ownerSeed, o.introSeed, o.rk.rc),
        o.ownerSeed);
    o.version = 1;
    return o;
  }

  /// A new inbox, by the owner.
  Future<void> newInbox(_Log log, _Owner o) async {
    o.introSeed = randomBytes(32);
    await put(log, o.label, o.version + 1,
        await recordOf(HandleRecordKind.update, o.ownerSeed, o.introSeed, o.rk.rc),
        o.ownerSeed);
    o.version++;
  }

  /// The recovery code used: a new owner, mailbox and code, `rsig` by the
  /// key the commitment names.
  Future<void> recoverAt(_Log log, _Owner o) async {
    final v = o.version + 1;
    final owner = randomBytes(32);
    final introSeed = randomBytes(32);
    final rk = await handleRecoveryKey(await RecoveryCode.generate(), o.label);
    final ownerPub = await handleKeyPublic(owner);
    final intro = await handleIntroIdentity(introSeed);
    final rsig = await signHandleRecovery(
        recoverySeed: o.rk.seed,
        label: o.label,
        version: v,
        owner: ownerPub,
        rc: rk.rc);
    await put(
        log,
        o.label,
        v,
        HandleRecord.recover(
            owner: ownerPub,
            intro: intro.edPub,
            xintro: intro.xPub,
            pow: 16,
            rc: rk.rc,
            rpub: o.rk.pub,
            rsig: rsig),
        owner);
    o
      ..ownerSeed = owner
      ..introSeed = introSeed
      ..rk = rk
      ..version = v;
  }

  /// The log's operator, with no rule to stop it: an update naming an owner
  /// and a mailbox of its own, signed by that owner and by no key of the
  /// handle's. Returns the operator's mailbox.
  Future<String> takeOver(_Log log, _Owner o) async {
    final owner = randomBytes(32);
    final introSeed = randomBytes(32);
    await put(log, o.label, o.version + 1,
        await recordOf(HandleRecordKind.update, owner, introSeed, randomBytes(32)),
        owner);
    o.version++;
    return introRoutingId((await handleIntroIdentity(introSeed)).edPub);
  }

  Future<ChatService> boot(String name,
      {required HandleConfig config,
      KtFetcher? fetcher,
      Vault? vault,
      ZIdentity? id,
      int? seed}) async {
    final Vault v;
    final ZIdentity identity;
    if (vault == null) {
      final d = await Directory.systemTemp.createTemp('z_hlookup_$name');
      temps.add(d);
      v = await Vault.open(rootOverride: d);
      identity = id ?? await ZIdentity.generate();
      await v.kvPut('identity', jsonEncode(identity.toJson()));
    } else {
      v = vault;
      identity = id!;
    }
    final svc = await ChatService.init(
        vault: v,
        identity: identity,
        displayName: name,
        transport:
            Transport(identity: identity, serverUrl: 'ws://127.0.0.1:$relayPort'),
        ktConfig: KtConfig.off,
        handleConfig: config,
        handleFetcher: fetcher);
    final h = svc.handles;
    if (seed != null) h.random = Random(seed);
    h.claimDelayMin = const Duration(milliseconds: 150);
    h.claimDelayMax = const Duration(milliseconds: 400);
    h.startDelayMin = const Duration(milliseconds: 50);
    h.startDelayMax = const Duration(milliseconds: 100);
    h.foregroundDelayMin = const Duration(milliseconds: 50);
    h.foregroundDelayMax = const Duration(milliseconds: 150);
    h.drainQuiet = const Duration(milliseconds: 400);
    h.drainEvery = const Duration(minutes: 30);
    services.add(svc);
    return svc;
  }

  Future<void> stop(ChatService s) async {
    services.remove(s);
    s.dispose();
    await s.transport
        .stop()
        .timeout(const Duration(seconds: 10), onTimeout: () {});
  }

  Future<void> waitUntil(FutureOr<bool> Function() cond,
      {Duration timeout = const Duration(seconds: 60),
      required String what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  /// [s] looks [handle] up through [f]: what it found or threw, the buckets
  /// the lookup asked, and the estimate's random ones apart.
  Future<_Look> look(ChatService s, _Operator f, String handle) async {
    final from = f.urls.length;
    // An estimate's bucket is the request made right after it is announced.
    final probes = <int>{};
    s.handles.debugOnProbe = (_) => probes.add(f.urls.length);
    HandleLookup? found;
    Object? error;
    try {
      found = await s.handles.find(handle);
    } catch (e) {
      error = e;
    } finally {
      s.handles.debugOnProbe = null;
    }
    final asked = <KtBucketQuery>[], probed = <KtBucketQuery>[];
    for (var i = from; i < f.urls.length; i++) {
      if (f.urls[i].path != '/kt/v1/bucket') continue;
      (probes.contains(i) ? probed : asked).add(_Operator._query(f.urls[i]));
    }
    return _Look(found, error, asked, probed);
  }

  Future<HandleLookupMemory> memoryOf(ChatService s) async =>
      HandleLookupMemory.parse((await s.vault.kvGet(handleLookupKey))!)!;

  /// An estimate set before [s] has looked anything up in [log].
  Future<void> setEstimate(ChatService s, _Log log, int bits) =>
      s.vault.kvPut(
          handleLookupKey,
          jsonEncode(HandleLookupMemory(
                  log: b64(log.pub), key: randomBytes(32), bits: bits)
              .toJson()));

  Future<Uint8List> labelOf(String handle) => handleLabel(Handle.parse(handle));

  // ---------------------------------------------------------------------------

  test('1. the clamp: a rewritten bucketBits is not followed; the bucket is '
      'asked among its decoys at the k the handles bear out', () async {
    final log = await bigLog();
    await claimAt(log, 'clara.41');
    final f = _Operator()..bucketBits = 24;
    final carol = await boot('Carol', config: log.config, fetcher: f);
    final l = await look(carol, f, '@clara.41');
    expect(l.error, isNull);
    expect(l.found!.state, HandleLookupState.found);
    final sth = await (await HttpClient()
            .getUrl(Uri.parse('http://127.0.0.1:${log.port}/kt/v1/sth')))
        .close();
    final size =
        (jsonDecode(await sth.transform(utf8.decoder).join()) as Map)['size'] as int;
    final want = handleBitsFor(size);
    expect(want, 4, reason: '⌊log₂(1,001 / 32)⌋');
    expect(l.bits, {want}, reason: 'not the 24 the operator wrote');
    final label = await labelOf('clara.41');
    final mem = await memoryOf(carol);
    expect(l.asked, handleLookupBuckets(mem.key, label, want),
        reason: 'the handle\'s bucket and its decoys\', each once, in order');
    expect(l.asked.where((q) => q.holds(label)), hasLength(1));
    expect(l.probed.first.bits, want,
        reason: 'the first estimate starts at the finest the signed size allows');
    // ignore: avoid_print
    print('LOOKUP 1: size $size, bucketBits rewritten to 24 -> estimate from '
        '${l.probed.map((q) => q.bits).toList()} bits, lookup asked '
        '${l.asked.length} buckets at ${l.bits}');

    // A log of one handle is one bucket, whatever bucketBits says.
    final tiny = await startLog();
    await claimAt(tiny, 'tia.42');
    final g = _Operator()..bucketBits = 24;
    final tom = await boot('Tom', config: tiny.config, fetcher: g);
    final t = await look(tom, g, '@tia.42');
    expect(t.found!.state, HandleLookupState.found);
    expect([...t.asked, ...t.probed].every((q) => q.bits == 0), isTrue);
  });

  test('2. size inflation: the estimate is of handles, not entries', () async {
    final log = await inflatedLog();
    await claimAt(log, 'ivy.52');
    final f = _Operator()..bucketBits = 24;
    final dan = await boot('Dan', config: log.config, fetcher: f, seed: 52);
    expect(log.labels, 300);
    expect(log.size, 300 + 4 * 999);
    final bySize = handleBitsFor(log.size + 1);
    expect(bySize, 7, reason: 'what the signed size alone would allow');
    // 301 handles put 16 or more in a bucket on average up to k = 4.
    final most = handleBitsFor(301 * 2);
    expect(most, 4);
    final ks = <Set<int>>[];
    final probes = <int>[];
    for (var i = 0; i < 3; i++) {
      final l = await look(dan, f, '@ivy.52');
      expect(l.error, isNull);
      expect(l.found!.state, HandleLookupState.found);
      ks.add(l.bits);
      probes.addAll([for (final q in l.probed) q.bits]);
    }
    // ignore: avoid_print
    print('LOOKUP 2: size ${log.size + 1}, 301 handles, bucketBits rewritten '
        'to 24 -> estimate from $probes bits, lookups asked $ks');
    expect(probes.first, bySize, reason: 'the estimate starts where the size allows');
    expect(ks.every((k) => k.single <= most), isTrue,
        reason: 'a bucket of 301 handles at k > 4 holds fewer than 16 on '
            'average — at the 7 the size allows, 2.4');
  });

  test('3. a bucket refused as too large is never narrowed to the handle\'s '
      'half', () async {
    // The review's P2b: everything below 24 bits refused.
    final tiny = await startLog();
    await claimAt(tiny, 'tess.31');
    final f = _Operator()..refuse = (q) => q.bits < 24;
    final ed = await boot('Ed', config: tiny.config, fetcher: f);
    final l = await look(ed, f, '@tess.31');
    expect(l.error, isA<HandleException>().having(
        (e) => e.failure, 'failure', HandleFailure.unreachable));
    expect(l.asked, isEmpty, reason: 'the handle\'s bucket is never asked');
    expect(l.probed.map((q) => q.bits), List.generate(handleProbeSteps, (i) => i),
        reason: 'random buckets, one bit finer at each refusal, eight at most');

    // The lookup's own k refused, after a first lookup set it.
    final log = await bigLog();
    await claimAt(log, 'fern.33');
    final g = _Operator();
    final fay = await boot('Fay', config: log.config, fetcher: g);
    final first = await look(fay, g, '@fern.33');
    expect(first.found!.state, HandleLookupState.found);
    final k = first.bits.single;
    g.refuse = (q) => q.bits == k;
    final refused = await look(fay, g, '@fern.33');
    expect(refused.error, isA<HandleException>().having(
        (e) => e.failure, 'failure', HandleFailure.unreachable));
    expect(refused.asked.toSet(), first.asked.toSet(),
        reason: 'the same buckets (asked again after the estimate was made '
            'again), and no others');
    expect(refused.asked.every((q) => q.bits == k), isTrue,
        reason: 'the handle\'s bucket nowhere finer');
    expect(refused.probed, isNotEmpty, reason: 'the estimate was made again');
    g.refuse = null;
    expect((await look(fay, g, '@fern.33')).found!.state,
        HandleLookupState.found);

    // An estimate the log outgrew: refused by the log itself, made again.
    final h = _Operator();
    final gil = await boot('Gil', config: log.config, fetcher: h);
    await setEstimate(gil, log, 1);
    final grown = await look(gil, h, '@fern.33');
    expect(grown.error, isNull);
    expect(grown.found!.state, HandleLookupState.found);
    expect(grown.bits, {1, 4},
        reason: 'the buckets at 1, refused as too large, then at 4');
    final label = await labelOf('fern.33');
    expect(grown.asked.where((q) => q.holds(label)).map((q) => q.bits), [1, 4],
        reason: 'the handle\'s bucket at each k once: no half of it alone');
    // ignore: avoid_print
    print('LOOKUP 3: all refused -> ${l.error}, asked ${l.asked.length} + '
        'probed ${l.probed.map((q) => q.bits).toList()}; own k=$k refused -> '
        '${refused.error}; stale estimate 1 -> asked bits '
        '${grown.asked.map((q) => q.bits).toList()}, probed '
        '${grown.probed.map((q) => q.bits).toList()}');
  });

  test('4. decoys: the same buckets every time for a handle, and its own for '
      'another', () async {
    final log = await bigLog();
    await claimAt(log, 'gwen.34');
    await claimAt(log, 'gabe.35');
    final f = _Operator();
    final gus = await boot('Gus', config: log.config, fetcher: f);
    final a1 = await look(gus, f, '@gwen.34');
    final a2 = await look(gus, f, '@gwen.34');
    final b = await look(gus, f, '@gabe.35');
    expect(a1.found!.state, HandleLookupState.found);
    expect(b.found!.state, HandleLookupState.found);
    expect(a2.asked, a1.asked);
    final k = a1.bits.single;
    final mem = await memoryOf(gus);
    expect(a1.asked, handleLookupBuckets(mem.key, await labelOf('gwen.34'), k));
    expect(b.asked, handleLookupBuckets(mem.key, await labelOf('gabe.35'), k));
    expect(b.asked, isNot(a1.asked));

    // The app restarted: the same buckets.
    final vault = gus.vault;
    final id = gus.identity;
    await stop(gus);
    final again = await boot('Gus', config: log.config, fetcher: f, vault: vault, id: id);
    final a3 = await look(again, f, '@gwen.34');
    expect(a3.probed, isEmpty, reason: 'the estimate was kept');
    expect(a3.asked, a1.asked);
  });

  test('5. the estimate falls at once to what the handles bear out, and rises '
      'a bit a lookup', () async {
    final log = await inflatedLog();
    await claimAt(log, 'hugo.36');
    final f = _Operator()..bucketBits = 24;
    final hal = await boot('Hal', config: log.config, fetcher: f);
    await setEstimate(hal, log, 7);
    final l1 = await look(hal, f, '@hugo.36');
    final l2 = await look(hal, f, '@hugo.36');
    expect(l1.bits, {7}, reason: 'the estimate it was given, which the size allows');
    expect(l2.bits.single, lessThanOrEqualTo(4),
        reason: 'one lookup of buckets holding ~2 handles each is enough');
    expect(l2.probed, isEmpty, reason: 'from the evidence, not a new estimate');

    final small = await startLog(labels: 200);
    await claimAt(small, 'ida.37');
    final g = _Operator();
    final ida = await boot('Ida', config: small.config, fetcher: g);
    await setEstimate(ida, small, 0);
    final ks = [
      for (var i = 0; i < 3; i++) (await look(ida, g, '@ida.37')).bits.single
    ];
    expect(ks, [0, 1, 2], reason: 'one bit a lookup: 201 handles bear out 2');
    // ignore: avoid_print
    print('LOOKUP 5: estimate 7 in a log of 302 handles -> asked '
        '${l1.bits} then ${l2.bits}; estimate 0 in a log of 201 -> asked $ks');
  });

  test('6. a requester remembers the owner: a change the rule does not '
      'explain is refused; a recovery is not', () async {
    final log = await startLog(ruleless: true);
    final frank = await claimAt(log, 'frank.61');
    final franksMailbox = await frank.introRid();
    final f = _Operator();
    final gina = await boot('Gina', config: log.config, fetcher: f);
    final before = await gina.handles.find('@frank.61');
    expect(before.state, HandleLookupState.found);
    expect(before.introRid, franksMailbox);

    // The operator names its own owner and mailbox.
    final operators = await takeOver(log, frank);
    final after = await gina.handles.find('@frank.61');
    // ignore: avoid_print
    print('LOOKUP 6: Gina resolves @frank.61 after the operator\'s update -> '
        '${after.state.name} (${after.change?.name}), mailbox ${after.introRid}'
        ' (Frank\'s $franksMailbox, the operator\'s $operators)');
    expect(after.state, HandleLookupState.changed);
    expect(after.change, HandleChange.owner);
    expect(after.introRid, isNull, reason: 'nothing to send a request to');
    await expectLater(
        gina.handles.request(after), failsWith(HandleFailure.notClaimed));
    expect((await gina.handles.find('@frank.61')).state,
        HandleLookupState.changed, reason: 'and again, until the person says');

    // Looked up as new — the person's choice — the new owner is taken.
    final asNew = await gina.handles.lookUpAsNew(after);
    expect(asNew.state, HandleLookupState.found);
    expect(asNew.introRid, operators);
    expect((await gina.handles.find('@frank.61')).state,
        HandleLookupState.found);

    // A genuine recover and a new inbox after it, each seen: no question.
    final rita = await claimAt(log, 'rita.62');
    expect((await gina.handles.find('@rita.62')).state, HandleLookupState.found);
    await recoverAt(log, rita);
    final recovered = await gina.handles.find('@rita.62');
    expect(recovered.state, HandleLookupState.found);
    expect(recovered.record!.kind, HandleRecordKind.recover);
    expect(recovered.introRid, await rita.introRid());
    await newInbox(log, rita);
    final moved = await gina.handles.find('@rita.62');
    expect(moved.state, HandleLookupState.found);
    expect(moved.introRid, await rita.introRid());

    // A recover and a new inbox after it, neither seen: one record cannot
    // tell the code's work from the log's.
    final sam = await claimAt(log, 'sam.63');
    expect((await gina.handles.find('@sam.63')).state, HandleLookupState.found);
    await recoverAt(log, sam);
    await newInbox(log, sam);
    final unseen = await gina.handles.find('@sam.63');
    expect(unseen.state, HandleLookupState.changed);
    expect(unseen.change, HandleChange.owner);
  });

  test('7. history: another record at a version seen, an older one, or none',
      () async {
    final log = await startLog(ruleless: true, labels: 4);
    final uma = await claimAt(log, 'uma.71');
    await newInbox(log, uma);
    final f = _Operator();
    final hana = await boot('Hana', config: log.config, fetcher: f);
    final seen = await hana.handles.find('@uma.71');
    expect(seen.state, HandleLookupState.found);
    expect(seen.version, 2);

    // Version 2 again, another record (an equivocation).
    await put(log, uma.label, 2,
        await recordOf(HandleRecordKind.update, uma.ownerSeed, randomBytes(32),
            uma.rk.rc),
        uma.ownerSeed);
    final twice = await hana.handles.find('@uma.71');
    expect(twice.state, HandleLookupState.changed);
    expect(twice.change, HandleChange.history);

    // An older version: a claim, by someone else.
    final other = randomBytes(32);
    await put(log, uma.label, 1,
        await recordOf(HandleRecordKind.claim, other, randomBytes(32),
            randomBytes(32)),
        other);
    final older = await hana.handles.find('@uma.71');
    expect(older.state, HandleLookupState.changed);
    expect(older.change, HandleChange.history);

    // None at all: the log, restarted empty under its key.
    await restartEmpty(log);
    final gone = await hana.handles.find('@uma.71');
    expect(gone.state, HandleLookupState.changed);
    expect(gone.change, HandleChange.history);
    expect((await hana.handles.find('@zed.79')).state,
        HandleLookupState.notFound, reason: 'a handle never seen is just absent');
  });

  test('8. a head signed more than a day ago is stale', () async {
    final log = await startLog();
    await claimAt(log, 'stan.81');
    final f = _Operator();
    final ivo = await boot('Ivo', config: log.config, fetcher: f);
    final real = ivo.handles.now;
    ivo.handles.now = () => real() + const Duration(hours: 25).inMilliseconds;
    await expectLater(
        ivo.handles.find('@stan.81'), failsWith(HandleFailure.stale));
    ivo.handles.now = () => real() + const Duration(hours: 23).inMilliseconds;
    expect((await ivo.handles.find('@stan.81')).state, HandleLookupState.found);
    ivo.handles.now = () => real() - const Duration(days: 3).inMilliseconds;
    expect((await ivo.handles.find('@stan.81')).state, HandleLookupState.found);
  });

  test('9. versions no honest log serves fail as a bad answer, never as '
      'arithmetic', () async {
    final log = await startLog(ruleless: true, labels: 2);
    final vic = await boot('Vic', config: log.config);
    final kim = await boot('Kim', config: log.config);
    final dana = await boot('Dana', config: log.config);
    final draft = await vic.handles.prepareClaim(Handle.parse('vic.91'), pow: 16);
    await vic.handles.commitClaim(draft);
    await waitUntil(() => vic.handles.own?.phase == HandlePhase.live,
        what: 'vic.91 published');
    expect((await kim.handles.find('@vic.91')).state, HandleLookupState.found);

    // A thief with Vic's owner key, and a log that does not hold it to the
    // next version: an update at 2^53 − 1.
    final thief = await handleIntroIdentity(randomBytes(32));
    await put(
        log,
        draft.label,
        handleMaxVersion,
        HandleRecord.update(
            owner: await handleKeyPublic(draft.ownerSeed),
            intro: thief.edPub,
            xintro: thief.xPub,
            pow: 16,
            rc: draft.rc),
        draft.ownerSeed);
    Object? rotated;
    try {
      await vic.handles.rotate();
    } catch (e) {
      rotated = e;
    }
    Object? recovered;
    try {
      await dana.handles.prepareRecover('vic.91', draft.code);
    } catch (e) {
      recovered = e;
    }
    // ignore: avoid_print
    print('LOOKUP 9: an update at 2^53-1 -> the owner\'s change: $rotated; '
        'a recover with the code: $recovered');
    expect(rotated, isA<HandleException>().having(
        (e) => e.failure, 'failure', HandleFailure.badAnswer));
    expect(recovered, isA<HandleException>().having(
        (e) => e.failure, 'failure', HandleFailure.badAnswer));
    await expectLater(
        kim.handles.find('@vic.91'), failsWith(HandleFailure.badAnswer));

    // A version past its index + 1.
    final wes = await claimAt(log, 'wes.92');
    await put(log, wes.label, 9,
        await recordOf(HandleRecordKind.update, wes.ownerSeed, wes.introSeed,
            wes.rk.rc),
        wes.ownerSeed);
    await expectLater(
        kim.handles.find('@wes.92'), failsWith(HandleFailure.badAnswer));

    // A claim at version 2: the rule's first entry is version 1.
    final xan = randomBytes(32);
    await put(log, await labelOf('xan.93'), 2,
        await recordOf(HandleRecordKind.claim, xan, randomBytes(32),
            randomBytes(32)),
        xan);
    expect((await kim.handles.find('@xan.93')).state, HandleLookupState.invalid);
  });

  test('10. backup and restore carry the memory', () async {
    final log = await startLog(ruleless: true, labels: 1000);
    final nina = await claimAt(log, 'nina.10');
    final f = _Operator();
    final jo = await boot('Jo', config: log.config, fetcher: f);
    final first = await look(jo, f, '@nina.10');
    expect(first.found!.state, HandleLookupState.found);

    final code = await RecoveryCode.generate();
    final file = File(p.join(
        (await Directory.systemTemp.createTemp('z_hlookup_zbk')).path, 'b.zbk'));
    temps.add(file.parent);
    final sink = file.openWrite();
    await BackupArchive.export(vault: jo.vault, code: code, out: sink);
    await sink.close();
    final dir = jo.vault.root;
    await stop(jo);
    await jo.vault.db.close();
    dir.deleteSync(recursive: true);
    dir.createSync(recursive: true);
    final vault = await Vault.open(rootOverride: dir);
    await Restore.run(
        vault: vault,
        file: file,
        secret: await code.format(),
        kind: (await Restore.identify(file)).kind,
        serverUrl: 'ws://127.0.0.1:$relayPort');
    final id = await ZIdentity.fromJson(
        (jsonDecode((await vault.kvGet('identity'))!) as Map)
            .cast<String, Object?>());
    final back = await boot('Jo', config: log.config, fetcher: f, vault: vault, id: id);
    final again = await look(back, f, '@nina.10');
    expect(again.found!.state, HandleLookupState.found);
    expect(again.probed, isEmpty, reason: 'the estimate came back');
    expect(again.asked, first.asked, reason: 'the decoy key came back');

    await takeOver(log, nina);
    final after = await back.handles.find('@nina.10');
    expect(after.state, HandleLookupState.changed,
        reason: 'what the old device found came back');
    expect(after.change, HandleChange.owner);

    // A memory that is not one stays out of the restored vault.
    final out = HandleBackup.restore({
      'kv': {
        handleLookupKey: {'log': 'x', 'key': b64(Uint8List(5))},
      }
    }, const {});
    expect(out.containsKey(handleLookupKey), isFalse);
  });

  testWidgets('11. the screen says why a lookup was refused, in both languages',
      (tester) async {
    final h = Handle.parse('frank.61');
    for (final (locale, l) in [
      (const Locale('en'), AppLocalizationsEn() as AppLocalizations),
      (const Locale('es'), AppLocalizationsEs() as AppLocalizations),
    ]) {
      var asNew = 0;
      Future<void> show(HandleChange change) async {
        await tester.pumpWidget(MaterialApp(
          debugShowCheckedModeBanner: false,
          theme: ZTheme.light(),
          locale: locale,
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: Scaffold(
              body: HandleLookupResult(
                  found: HandleLookup.debug(h, HandleLookupState.changed,
                      label: Uint8List(32), change: change),
                  busy: false,
                  sending: false,
                  onRequest: () => fail('a request was offered'),
                  onLookUpAsNew: () => asNew++)),
        ));
        await tester.pumpAndSettle();
      }

      await show(HandleChange.owner);
      expect(find.text(l.hdlFoundChangedOwner('frank.61')), findsOneWidget);
      expect(find.text(l.hdlChangedNote), findsOneWidget);
      expect(find.text(l.hdlSendRequest), findsNothing);
      await tester.tap(find.text(l.hdlLookUpAsNew));
      expect(asNew, 1);
      await show(HandleChange.history);
      expect(find.text(l.hdlFoundChangedHistory('frank.61')), findsOneWidget);
      expect(find.text(l.hdlSendRequest), findsNothing);
      expect(find.text(l.hdlLookUpAsNew), findsOneWidget);
      expect(handleFailureText(l, HandleFailure.stale), l.hdlErrStale);
    }
    expect(AppLocalizationsEs().hdlLookUpAsNew,
        isNot(AppLocalizationsEn().hdlLookUpAsNew));
  });

  test('12. the rules on their own', () async {
    expect([
      for (final n in [0, 63, 64, 127, 128, 1001, 1 << 29, 1 << 40])
        handleBitsFor(n)
    ], [0, 0, 1, 1, 2, 4, 24, 24]);

    // The probe: coarser by as much as the count fell short of 32.
    expect(handleProbeNext(7, 0), 2);
    expect(handleProbeNext(7, 2), 3);
    expect(handleProbeNext(7, 5), 4);
    expect(handleProbeNext(7, 16), 6);
    expect(handleProbeNext(7, 32), isNull);
    expect(handleProbeNext(3, 0), 0);
    expect(handleProbeNext(0, 3), isNull);

    // The evidence: falls at once, rises a bit, holds in between.
    expect(handleNextBits(7, 7, [2, 3, 1, 4]), 3,
        reason: '10 × 2^7 / 4 = 320 handles');
    expect(handleNextBits(6, 4, [40, 40]), 4, reason: 'asked coarser than held');
    expect(handleNextBits(2, 2, [500, 520, 480, 510]), 3,
        reason: 'one bit, though 2,000 handles bear out 5');
    expect(handleNextBits(4, 4, [70, 66, 80, 65]), 5);
    expect(handleNextBits(4, 4, [16, 30, 40, 63]), 4);
    expect(handleNextBits(4, 4, const []), 4);

    // Decoys: a function of key and label, each finer bucket inside the
    // coarser one.
    final key = randomBytes(32), a = randomBytes(32), b = randomBytes(32);
    expect(handleDecoyPoints(key, a), handleDecoyPoints(key, a));
    expect(handleDecoyPoints(randomBytes(32), a), isNot(handleDecoyPoints(key, a)));
    final da = handleDecoyPoints(key, a).map(b64).toSet();
    expect(handleDecoyPoints(key, b).map(b64).where(da.contains), isEmpty);
    for (var k = 0; k < ktMaxBucketBits; k++) {
      final coarse = handleLookupBuckets(key, a, k);
      for (final q in handleLookupBuckets(key, a, k + 1)) {
        final inside = ktParseBucketPrefix(q.prefix, q.bits)!;
        expect(coarse.any((c) => c.holds(inside)), isTrue);
      }
    }
    // Two installs — an account's two devices, or a reinstall without a
    // backup — ask one handle through two keys, and what their sets have in
    // common is its bucket: the residual THREAT_MODEL's trust row names.
    var exact = 0;
    for (var t = 0; t < 200; t++) {
      final mine = handleLookupBuckets(key, a, 9).map((q) => q.prefix).toSet();
      final theirs = handleLookupBuckets(randomBytes(32), a, 9)
          .map((q) => q.prefix)
          .toSet();
      final meet = mine.intersection(theirs);
      if (meet.length == 1 && meet.single == ktBucketPrefix(a, 9)) exact++;
    }
    expect(exact, greaterThan(190),
        reason: 'two keys\' decoys coincide by chance alone (3 × 3 / 512)');

    // The leaf rule.
    KtBucketLeaf leaf(int index, int version) =>
        KtBucketLeaf(label: a, index: index, version: version);
    expect(handleLeafProblem(leaf(0, 1)), isNull);
    expect(handleLeafProblem(leaf(4, 5)), isNull);
    expect(handleLeafProblem(leaf(4, 6)), isNotNull);
    expect(handleLeafProblem(leaf(3, 0)), isNotNull);
    expect(handleLeafProblem(leaf(handleMaxVersion - 2, handleMaxVersion - 1)),
        isNull);
    expect(handleLeafProblem(leaf(handleMaxVersion - 1, handleMaxVersion)),
        isNotNull, reason: 'index + 1 allows it; no version can follow it');

    // What one record can follow.
    final owner = randomBytes(32);
    final code = await RecoveryCode.generate();
    final rk = await handleRecoveryKey(code, a);
    final known = KnownHandle(
        owner: await handleKeyPublic(owner),
        rc: rk.rc,
        version: 3,
        hash: Uint8List(32),
        atMs: 0);
    Future<HandleRecord> update(Uint8List seed, Uint8List rc) async {
      final intro = await handleIntroIdentity(randomBytes(32));
      return HandleRecord.update(
          owner: await handleKeyPublic(seed),
          intro: intro.edPub,
          xintro: intro.xPub,
          pow: 16,
          rc: rc);
    }

    final same = await update(owner, rk.rc);
    final other = randomBytes(32);
    final foreign = await update(other, rk.rc);
    Future<HandleRecord> recover(HandleRecoveryKey by) async =>
        HandleRecord.recover(
            owner: await handleKeyPublic(other),
            intro: null,
            xintro: null,
            pow: 16,
            rc: randomBytes(32),
            rpub: by.pub,
            rsig: Uint8List(64));
    final h1 = Uint8List(32)..[0] = 1;
    expect(await handleKnownChange(known, version: 9, hash: h1, rec: same), isNull);
    expect(await handleKnownChange(known, version: 4, hash: h1, rec: foreign),
        HandleChange.owner);
    expect(await handleKnownChange(known, version: 5, hash: h1, rec: await recover(rk)),
        isNull, reason: 'the key the remembered commitment names');
    final wrong = await handleRecoveryKey(await RecoveryCode.generate(), a);
    expect(await handleKnownChange(known, version: 4, hash: h1, rec: await recover(wrong)),
        HandleChange.owner);
    expect(await handleKnownChange(known, version: 2, hash: h1, rec: same),
        HandleChange.history);
    expect(await handleKnownChange(known, version: 3, hash: h1, rec: same),
        HandleChange.history);
    expect(await handleKnownChange(known, version: 3, hash: Uint8List(32), rec: same),
        isNull);

    // The stored memory: its shape, and the cap.
    final m = HandleLookupMemory(log: 'L', key: randomBytes(32), bits: 5);
    for (var i = 0; i < handleKnownCap + 3; i++) {
      final l = Uint8List(32)..[0] = i & 0xff..[1] = i >> 8;
      m.remember(l, KnownHandle(owner: owner, rc: rk.rc, version: 1, hash: h1, atMs: 1000 + i));
    }
    expect(m.known, hasLength(handleKnownCap));
    expect(m.knownFor(Uint8List(32)), isNull, reason: 'the one found longest ago went');
    final back = HandleLookupMemory.parse(jsonEncode(m.toJson()))!;
    expect(back.bits, 5);
    expect(back.known, hasLength(handleKnownCap));
    expect(HandleLookupMemory.parse('{"log":"L","key":"${b64(Uint8List(31))}"}'), isNull);
    expect(HandleLookupMemory.parse('{"log":"L","key":"${b64(Uint8List(32))}","k":25}'), isNull);
    final odd = HandleLookupMemory.parse(jsonEncode({
      'log': 'L',
      'key': b64(Uint8List(32)),
      'known': {
        b64url(Uint8List(32)): {'o': b64(owner), 'rc': b64(rk.rc), 'v': 0, 'h': b64(h1), 'at': 1},
        'not-a-label': {'o': b64(owner), 'rc': b64(rk.rc), 'v': 1, 'h': b64(h1), 'at': 1},
      },
    }))!;
    expect(odd.known, isEmpty, reason: 'a version 0 and a key that is no label are left out');
  });

  test('13. refusing a bucket cannot raise k: the probe steps finer and goes '
      'on until one holds 32', () async {
    final log = await tallLog();
    await claimAt(log, 'rune.13');
    final label = await labelOf('rune.13');
    final honest = handleBitsFor(log.labels + 1);
    expect(honest, 3);
    expect(handleBitsFor(log.size + 1), 8, reason: 'what the size allows');
    // The operator's chance is a random bucket whose count alone puts k
    // above 3 — one in three at k = 8, where a bucket holds 1.2 handles on
    // average — so it waits for one across fresh installs, each with a
    // different seed and so a different first bucket; and the test waits for
    // it to have taken it.
    final lookups = <_Look>[];
    _Operator? got;
    var attempts = 0;
    for (var i = 0; i < 40 && got == null; i++) {
      final f = _Operator()
        ..bucketBits = 24
        ..refuseAboveHonest = honest;
      final s = await boot('Ron$i', config: log.config, fetcher: f, seed: 1300 + i);
      lookups.add(await look(s, f, '@rune.13'));
      await stop(s);
      attempts++;
      if (f.refusals > 0) got = f;
    }
    expect(got, isNotNull, reason: 'the operator never saw a count above honest');
    final last = lookups.last;
    // ignore: avoid_print
    print('LOOKUP 13: ${log.labels + 1} handles, size ${log.size + 1}, '
        'bucketBits rewritten to 24; the operator refused on attempt $attempts '
        '-> probed ${last.probed.map((q) => q.bits).toList()}, asked '
        '${last.asked.map((q) => q.bits).toList()}, '
        '${last.found?.state.name ?? last.error}');
    for (final l in lookups) {
      expect(l.asked.where((q) => q.holds(label)).every((q) => q.bits <= honest),
          isTrue,
          reason: 'a refusal must never put the handle\'s bucket finer than '
              'the handles bear out (§21.8: a refused bucket is asked finer '
              'with a fresh draw; the estimate is a bucket of 32)');
    }
    expect(last.found!.state, HandleLookupState.found);
    expect(last.bits, {honest});
  });

  test('14. a bucket counts only under the head held when it was drawn, and '
      'within a lookup the head only grows', () async {
    final log = await tallLog();
    await claimAt(log, 'mint.14');
    final label = await labelOf('mint.14');
    final honest = handleBitsFor(log.labels + 2);
    expect(honest, 3);

    // On seeing the first random bucket asked, the operator mints 32 labels
    // into it — as it can, holding no handle's key but its own — and
    // answers under the head that holds them.
    Uint8List within(KtBucketQuery q) {
      final p = ktParseBucketPrefix(q.prefix, q.bits)!;
      final out = randomBytes(32);
      for (var d = 0; d < q.bits; d++) {
        final mask = 1 << (7 - (d & 7));
        if (p[d >> 3] & mask != 0) {
          out[d >> 3] |= mask;
        } else {
          out[d >> 3] &= ~mask;
        }
      }
      return out;
    }

    var minted = 0;
    KtBucketQuery? mintedInto;
    final f = _Operator()..bucketBits = 24;
    f.onBucket = (q) async {
      f.onBucket = null;
      mintedInto = q;
      for (var i = 0; i < 32; i++) {
        final seed = randomBytes(32);
        await put(log, within(q), 1,
            await recordOf(HandleRecordKind.claim, seed, randomBytes(32), randomBytes(32)),
            seed);
        minted++;
      }
    };
    final mia = await boot('Mia', config: log.config, fetcher: f, seed: 14);
    final l = await look(mia, f, '@mint.14');
    // ignore: avoid_print
    print('LOOKUP 14: 32 labels minted into $mintedInto on seeing it -> '
        'probed ${l.probed.map((q) => q.bits).toList()}, asked '
        '${l.asked.map((q) => q.bits).toList()}, '
        '${l.found?.state.name ?? l.error}');
    expect(minted, 32);
    expect(mintedInto!.bits, 8, reason: 'the probe starts where the size allows');
    expect(l.error, isNull);
    expect(l.found!.state, HandleLookupState.found);
    expect(l.asked.where((q) => q.holds(label)).every((q) => q.bits <= honest),
        isTrue,
        reason: 'labels minted into a bucket on seeing it must not count');
    expect(l.probed.where((q) => q.bits == 8).length, greaterThanOrEqualTo(2),
        reason: 'the minted bucket is not counted: another is drawn at 8');

    // An older answer served again after the log grew: the lookup read the
    // newer head first, so the answer is under a head that shrank.
    final g = _Operator()..keep = true;
    final nat = await boot('Nat', config: log.config, fetcher: g, seed: 15);
    expect((await look(nat, g, '@mint.14')).found!.state, HandleLookupState.found);
    await claimAt(log, 'grow.14');
    g
      ..keep = false
      ..replay = true
      ..kept.removeWhere((path, _) => path.startsWith('/kt/v1/sth'));
    await expectLater(nat.handles.find('@mint.14'), failsWith(HandleFailure.badAnswer));

    // The other way round — an older head read first, newer answers — is a
    // log that grew during the lookup: taken, with its consistency proof.
    g
      ..kept.removeWhere((path, _) => !path.startsWith('/kt/v1/sth'))
      ..replay = false
      ..keep = true;
    final before = g.urls.length;
    expect((await look(nat, g, '@mint.14')).found!.state, HandleLookupState.found);
    await claimAt(log, 'more.14');
    g
      ..keep = false
      ..replay = true
      ..kept.removeWhere((path, _) => !path.startsWith('/kt/v1/sth'));
    final again = await look(nat, g, '@mint.14');
    expect(again.found!.state, HandleLookupState.found);
    expect(g.urls.skip(before).any((u) => u.path == '/kt/v1/consistency'), isTrue,
        reason: 'the newer head is taken only with a proof it extends the old');
  });
}
