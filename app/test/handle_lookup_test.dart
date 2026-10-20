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
//
// And the handle log's witness (phase 19, 2026-10-19). A resolver keeps no
// head between lookups, so a log that shows one reader a history it showed
// nobody else is caught only by a witness: a mirror, run by somebody else,
// that co-signs each head it verified. Each lookup's head is now held to the
// witness's record under the key pinned for it (§19.5 step 3, §21.8) — the
// reference witness's record (kt/tools/mirror.js --mode handles) over the
// real handle log, or one made here in the handle contexts:
//  15. a forked log — one key, two histories, the witness verifying the
//      other — fails the lookup as forked whether the witness's head is the
//      same size under other roots, behind with a proof that fails, or ahead
//      of a log that cannot reach it; nothing the lookup returned is kept or
//      sent (no record remembered, no request, no stamp, no `hvia_`); and
//      with no witness the same lookup takes the operator's mailbox, as the
//      base, which never asks, does;
//  16. every way a head is taken is held to it: a claim's check that a name
//      is free, at random digits too, a recovery's read, and the owner's own
//      reads — a refresh says why on the handle screen, a change is refused
//      before anything is published, a drain goes on with what the device
//      holds;
//  17. a witness behind the lookup's head (the witness service itself, over
//      loopback) and one ahead of it (the log grew between the head and the
//      question) both agree, the log proving the way between them, and the
//      agreement is recorded, sealed, with the configuration it answers;
//  18. a witness that cannot be reached, answers an error, or serves a
//      record whose co-signature or head signature does not verify, or that
//      is no record, is no verdict: the lookup goes on and the state says no
//      answer yet; a day of lookups asking without one is a witness gone
//      quiet since the first of them; an agreement ends it;
//  19. half a witness — an address, a key, a key that is not one — is
//      refused when it is set, and one held from before is never fetched;
//  20. a record co-signed by a key other than the pinned one is no agreement
//      and no verdict, one showing a fork included (§19.5: "A witness that
//      cannot be fetched, or whose record does not verify, is no verdict");
//      pinned to the key it is signed with, it counts;
//  21. a record a day old is held to consistency: consistent, the lookup goes
//      on and nothing is agreed, at the log's size and behind it; over other
//      roots it is a fork;
//  22. the build's four handle values are empty, together;
//  23. a witness off loopback stops a test process asking anything at all;
//  24. the record is fetched at most once a lookup and used again for ten
//      minutes under the same witness; fetched again after that, for
//      another witness, and after a record that did not verify; never
//      before a lookup, nor by one the log did not answer;
//  25. the witness's state belongs to the configuration it was recorded
//      under: kept across a restart, forgotten by a build that pins another
//      witness, and when Settings saves another witness, none, or another log
//      under the same one — not when it saves the same;
//  26. THE KNOWN RESIDUAL (THREAT_MODEL R50, PROTOCOL §21.8), pinned as it
//      stands so that a remedy flips it on purpose: a history that departs
//      after the witness's latest co-signed head, shown at a first lookup,
//      passes the check and counts as agreement — an update the owner rule
//      refuses, appended after the witness's head (the reference witness
//      then refuses to follow the log, and tells nobody this lookup asks),
//      and a second history under the same key begun after it; the record
//      used again for ten minutes passes the same lookup after the witness
//      has moved on, until it is fetched again, and then it is the fork;
//  27. a log that will not prove the way between its head and its witness's
//      fails the lookup — the witness behind, or ahead with the log's own
//      head not below it — as unreachable, and one that serves something
//      that is not a proof as a bad answer; nothing the lookup returned is
//      kept or sent, and the witness has been asked without an answer that
//      counts; served, the proof shows the fork (15) or the agreement (17);
//  28. a fork is kept, sealed with its configuration, until the witness
//      agrees again: Settings says so after a drain's read refused as forked
//      (the drain goes on), across a restart; a claim the log refuses as
//      taken, whose read-back is refused as forked, is held with the fork as
//      its problem rather than taken; and another witness forgets it.
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

  /// The witness: [witnessUrl] answered by [witness] — when, and only when,
  /// the client asks there — rather than by the network. What it answers is
  /// the reference witness's record ([_Witness]), or one a test made.
  String? witnessUrl;
  Future<KtResponse> Function()? witness;

  static KtBucketQuery _query(Uri u) => KtBucketQuery.parse(
      u.queryParameters['prefix']!, int.parse(u.queryParameters['bits']!));

  static const _tooLarge =
      '{"error":"bucket_too_large","message":"ask for more bits"}';

  @override
  Future<KtResponse> get(Uri url) async {
    urls.add(url);
    final w = witness;
    if (w != null && url.toString() == witnessUrl) return w();
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

/// A fetcher that never reaches the network: every URL written down, and
/// nothing answered.
class _Nowhere implements KtFetcher {
  final urls = <Uri>[];
  @override
  Future<KtResponse> get(Uri url) async {
    urls.add(url);
    return KtResponse(503, '{}');
  }

  @override
  Future<KtResponse> post(Uri url, String jsonBody) async {
    urls.add(url);
    return KtResponse(503, '{}');
  }
}

/// The operator's fetcher with every request for a consistency proof
/// refused — as a log that will not prove the way between two heads it signed
/// can refuse it — or, with [garbage], answered with something that is not a
/// proof.
class _Withholding implements KtFetcher {
  _Withholding(this.inner);
  final _Operator inner;
  final denied = <String>[];
  bool garbage = false;

  @override
  Future<KtResponse> get(Uri url) async {
    if (url.path == '/kt/v1/consistency') {
      inner.urls.add(url);
      denied.add(url.query);
      return garbage ? KtResponse(200, '{"proof":7}') : KtResponse(503, '{}');
    }
    return inner.get(url);
  }

  @override
  Future<KtResponse> post(Uri url, String jsonBody) => inner.post(url, jsonBody);
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

/// The reference witness of a handle log, `kt/tools/mirror.js --mode
/// handles`, run once at each sync: it verifies that the log's head extends
/// the one it verified last, re-derives both roots from the entries, holds
/// every entry to the owner rule, co-signs the head in the handle witness
/// context with a key of its own, and writes [record] — the record a witness
/// serves at `/sth.json` — into [dir].
class _Witness {
  _Witness(this.seed, this.pub, this.dir, this.url);
  final Uint8List seed;
  final Uint8List pub;
  final String dir;

  /// Where the client is told the record is, on loopback: answered by the
  /// test's fetcher ([_Operator.witness]), never by the network.
  final String url;

  /// The record as the witness last wrote it.
  late String record;
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
  final witnessServices = <Process>[];
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
    for (final w in witnessServices) {
      w.kill();
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
  /// when [ruleless] — under a key of its own, or under [key]'s: a second
  /// history the same operator signs.
  Future<_Log> startLog(
      {int labels = 0,
      String? versions,
      bool ruleless = false,
      Uint8List? key}) async {
    final n = ++seeds;
    final seed = key ??
        Uint8List.fromList(
            List<int>.generate(32, (i) => (i * 29 + n * 7 + 3) & 0xff));
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

  var witnesses = 0;

  /// [w] run once against [log]: the head it verified, co-signed, is
  /// [_Witness.record] — or the test fails with what the witness said, a
  /// divergence among it.
  Future<void> sync(_Witness w, _Log log) async {
    final r = await Process.run(
        'node',
        [
          'tools/mirror.js',
          '--log',
          'http://127.0.0.1:${log.port}',
          '--pub',
          b64(log.pub),
          '--dir',
          w.dir,
          '--mode',
          'handles',
          '--witness-seed-env',
          'Z_HANDLE_WITNESS_SEED',
        ],
        workingDirectory: '$root/kt',
        environment: {'Z_HANDLE_WITNESS_SEED': hex(w.seed)});
    expect(r.exitCode, 0,
        reason: 'the witness verified the log: ${r.stdout}${r.stderr}');
    w.record = File(p.join(w.dir, 'sth.json')).readAsStringSync();
  }

  /// A witness of [log] under a key of its own, synced once unless
  /// [synced] is false.
  Future<_Witness> witnessOf(_Log log, {bool synced = true}) async {
    final n = ++witnesses;
    final seed = Uint8List.fromList(
        List<int>.generate(32, (i) => (i * 53 + n * 11 + 1) & 0xff));
    final dir = await Directory.systemTemp.createTemp('z_hlookup_w');
    temps.add(dir);
    final w = _Witness(seed, await pubOf(seed), dir.path,
        'http://127.0.0.1:9/witness-$n/sth.json');
    if (synced) await sync(w, log);
    return w;
  }

  /// [w] as the witness service itself — `mirror.js --serve`, on a port of
  /// its own on loopback — following [log]: it syncs as it starts and then
  /// hourly, so it stays where it was while the test moves the log. The
  /// address of its record, once it serves one.
  Future<String> serveWitness(_Witness w, _Log log) async {
    final proc = await Process.start(
        'node',
        [
          'tools/mirror.js',
          '--log',
          'http://127.0.0.1:${log.port}',
          '--pub',
          b64(log.pub),
          '--dir',
          w.dir,
          '--mode',
          'handles',
          '--witness-seed-env',
          'Z_HANDLE_WITNESS_SEED',
          '--serve',
          '0',
          '--every',
          '3600',
        ],
        workingDirectory: '$root/kt',
        environment: {'Z_HANDLE_WITNESS_SEED': hex(w.seed)});
    witnessServices.add(proc);
    final port = Completer<int>();
    proc.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen((line) {
      final m = RegExp(r'serving on http://0\.0\.0\.0:(\d+)').firstMatch(line);
      if (m != null && !port.isCompleted) port.complete(int.parse(m.group(1)!));
    });
    proc.stderr.drain<void>();
    final url =
        'http://127.0.0.1:${await port.future.timeout(const Duration(seconds: 60))}/sth.json';
    final net = HttpKtFetcher();
    await waitUntil(() async {
      try {
        return (await net.get(Uri.parse(url))).status == 200;
      } catch (_) {
        return false;
      }
    }, what: 'the witness serving the head it verified');
    return url;
  }

  /// [log]'s current head, as it serves it.
  Future<KtTreeHead> headOf(_Log log) async => KtTreeHead.fromJson(
      (await HttpKtFetcher()
              .get(Uri.parse('http://127.0.0.1:${log.port}/kt/v1/sth')))
          .json);

  /// A head at [size] over [logRoot] and [mapRoot], signed at [ts] in the
  /// handle log's context by [log]'s own key: a head that log signed, so
  /// that only what a witness says of it is in doubt.
  Future<KtTreeHead> signedHead(_Log log,
      {required int size,
      required Uint8List logRoot,
      required Uint8List mapRoot,
      required int ts}) async {
    final unsigned = KtTreeHead(
        size: size, logRoot: logRoot, mapRoot: mapRoot, ts: ts, sig: Uint8List(64));
    final sig = await Ed25519().sign(ktHeadInput(unsigned, KtLogMode.handles),
        keyPair: await Ed25519().newKeyPairFromSeed(log.seed));
    return KtTreeHead(
        size: size,
        logRoot: logRoot,
        mapRoot: mapRoot,
        ts: ts,
        sig: Uint8List.fromList(sig.bytes));
  }

  /// [head] co-signed in the handle witness context by the key of [seed]:
  /// the record a witness under that key would serve (§19.10's shape).
  Future<String> recordFor(KtTreeHead head, Uint8List seed) async {
    final sig = await Ed25519().sign(
        ktWitnessInputFor(head, KtLogMode.handles),
        keyPair: await Ed25519().newKeyPairFromSeed(seed));
    return jsonEncode({
      'sth': head.toJson(),
      'verifiedAt': head.ts,
      'size': head.size,
      'witness': {'pub': b64(await pubOf(seed)), 'sig': b64(sig.bytes)},
    });
  }

  /// [log] with [w] as its witness: the record's address — [w]'s own, or
  /// [url] — and the key this device pins for it — [w]'s own, or [key].
  HandleConfig witnessed(_Log log, _Witness w, {String? url, Uint8List? key}) =>
      HandleConfig(
          logUrl: 'http://127.0.0.1:${log.port}',
          logPubB64: b64(log.pub),
          witnessUrl: url ?? w.url,
          witnessPubB64: b64(key ?? w.pub));

  int fetchesOf(_Operator f, String url) =>
      f.urls.where((u) => u.toString() == url).length;

  /// [f] answers [w]'s address with what [w] last wrote.
  void serve(_Operator f, _Witness w) => f
    ..witnessUrl = w.url
    ..witness = () async => KtResponse(200, w.record);

  Matcher forked() => isA<HandleException>()
      .having((e) => e.failure, 'failure', HandleFailure.forked);

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

  // ---------------------------------------------------------------------------
  // The handle log's witness (phase 19, 2026-10-19).

  test('15. a forked log: a lookup its witness contradicts is refused, and '
      'nothing it returned is sent or kept', () async {
    // One key, two histories. x is what the log shows Carol; y is what its
    // witness verified. In y @fern.21 is Fern's; in x it is a mailbox of the
    // operator's.
    final x = await startLog();
    final y = await startLog(key: x.seed);
    expect(b64(y.pub), b64(x.pub), reason: 'one operator, one key');
    await claimAt(y, 'fern.21');
    final thief = await claimAt(x, 'fern.21');
    final w = await witnessOf(y);
    final f = _Operator();
    serve(f, w);
    final carol = await boot('Carol', config: witnessed(x, w), fetcher: f);
    final label = await labelOf('fern.21');

    // The same size, under other roots.
    final same = await look(carol, f, '@fern.21');
    expect(same.error, forked(),
        reason: 'the witness verified a head of the same size with other roots');
    expect(same.found, isNull);
    expect(f.urls.where((u) => u.toString() == w.url), hasLength(1),
        reason: 'the witness was asked, once');

    // The log grows: the witness is a head behind, and the log's proof from
    // that size does not lead from the witness's root to the log's.
    await claimAt(x, 'gail.22');
    final behind = await look(carol, f, '@fern.21');
    expect(behind.error, forked(),
        reason: 'the proof from the witness\'s head does not verify');
    expect(
        f.urls.any((u) =>
            u.path == '/kt/v1/consistency' && u.query == 'first=1&second=2'),
        isTrue,
        reason: 'the log was asked to prove the way from the witness\'s head');

    // The witness ahead: y grows past x and the witness follows it. The log
    // cannot prove the way to a head this history never signed, and the head
    // it serves is smaller: a log gone back below what its witness verified.
    await claimAt(y, 'hugo.23');
    await claimAt(y, 'iris.24');
    await sync(w, y);
    final g = _Operator();
    serve(g, w);
    final cy = await boot('Cy', config: witnessed(x, w), fetcher: g);
    final ahead = await look(cy, g, '@fern.21');
    expect(ahead.error, forked(),
        reason: 'the witness verified a head the log cannot reach');
    expect(
        g.urls.any((u) =>
            u.path == '/kt/v1/consistency' && u.query == 'first=2&second=3'),
        isTrue,
        reason: 'the log was asked to prove the way to the witness\'s head');

    // Nothing either lookup returned is used, kept or sent.
    for (final s in [carol, cy]) {
      expect((await memoryOf(s)).knownFor(label), isNull,
          reason: 'no record remembered');
      expect(s.handles.outgoing, isEmpty, reason: 'no request kept');
      expect(s.handles.stampsMade, 0, reason: 'no request made');
      expect(await s.vault.kvScan('hvia_'), isEmpty);
      expect(s.handles.witnessOkMs, isNull, reason: 'and no agreement');
    }

    // What the witness is for: without one, the same lookup takes the
    // operator's record, and a request would go to its mailbox.
    final dan = await boot('Dan', config: x.config);
    final taken = await dan.handles.find('@fern.21');
    expect(taken.state, HandleLookupState.found);
    expect(taken.introRid, await thief.introRid());
    // ignore: avoid_print
    print('LOOKUP 15: x and y under one key; Carol through y\'s witness -> '
        '${same.error}, ${behind.error}, ${ahead.error}; Dan with none -> '
        '${taken.state.name}, the operator\'s mailbox');
  });

  test('16. every way a head is taken is held to the witness: a claim\'s '
      'check that a name is free, a recovery\'s read, and the owner\'s reads '
      'of its own record — at a refresh, before a change, before a drain',
      () async {
    // x is what the log shows; y, under the same key, what the witness saw.
    final x = await startLog();
    final y = await startLog(key: x.seed);
    await claimAt(y, 'yuri.61');
    final w = await witnessOf(y);

    // Dora claims in x before any witness is set; then she is given one.
    final f = _Operator();
    serve(f, w);
    final dora = await boot('Dora', config: x.config, fetcher: f);
    final draft =
        await dora.handles.prepareClaim(Handle.parse('dora.62'), pow: 16);
    await dora.handles.commitClaim(draft);
    await waitUntil(() => dora.handles.own?.phase == HandlePhase.live,
        what: 'dora.62 published');
    expect(fetchesOf(f, w.url), 0, reason: 'no witness yet, none asked');
    await dora.handles.setConfig(witnessed(x, w));

    // The owner's refresh: the record read back is refused, and the handle
    // screen's line says why. The handle is hers still.
    await dora.handles.refresh();
    expect(dora.handles.own!.problem, HandleFailure.forked.name);
    expect(handleStoredProblemText(AppLocalizationsEn(), dora.handles.own!.problem),
        AppLocalizationsEn().hdlErrForked);
    expect(dora.handles.own!.phase, HandlePhase.live);
    // A change: refused before anything is published.
    await expectLater(dora.handles.pause(), failsWith(HandleFailure.forked));
    // A drain: its read of the record is refused, and it goes on with what
    // this device holds, as it does when the log cannot be asked.
    final drains = dora.handles.drains;
    await dora.handles.drain();
    expect(dora.handles.drains, drains + 1);
    expect(dora.handles.own!.phase, HandlePhase.live);
    // Her own handle, looked up.
    await expectLater(
        dora.handles.find('@dora.62'), failsWith(HandleFailure.forked));

    // Someone else: a claim's check that a name is free, at random digits
    // too, and the read a recovery makes first.
    final carol = await boot('Carol', config: witnessed(x, w), fetcher: f);
    await expectLater(carol.handles.isAvailable(Handle.parse('kim.63')),
        failsWith(HandleFailure.forked));
    await expectLater(carol.handles.availableWithRandomDigits('kim'),
        failsWith(HandleFailure.forked));
    final code = await formatHandleRecoveryCode(await RecoveryCode.generate());
    await expectLater(carol.handles.prepareRecover('dora.62', code),
        failsWith(HandleFailure.forked));

    // Nothing was published: with no witness, x still holds dora.62 as she
    // claimed it, taking requests.
    final dan = await boot('Dan', config: x.config);
    final seen = await dan.handles.find('@dora.62');
    expect(seen.state, HandleLookupState.found);
    expect(seen.version, 1);
    expect(fetchesOf(f, w.url), greaterThanOrEqualTo(1));
  });

  test('17. a witness behind the lookup\'s head and one ahead of it both '
      'agree, and the agreement is recorded', () async {
    final log = await startLog();
    await claimAt(log, 'lena.71');

    // Behind: the witness service itself, fetched over loopback as
    // configured; the log grows by two after it verified.
    final w = await witnessOf(log, synced: false);
    final url = await serveWitness(w, log);
    final verified = (await headOf(log)).size;
    await claimAt(log, 'lars.72');
    await claimAt(log, 'lea.73');
    final f = _Operator();
    final max = await boot('Max', config: witnessed(log, w, url: url), fetcher: f);
    final before = DateTime.now().millisecondsSinceEpoch;
    expect((await max.handles.find('@lena.71')).state, HandleLookupState.found);
    expect(fetchesOf(f, url), 1, reason: 'the record, from the witness service');
    expect(
        f.urls.any((u) =>
            u.path == '/kt/v1/consistency' &&
            u.query == 'first=$verified&second=${verified + 2}'),
        isTrue,
        reason: 'the log proved the way from the witness\'s head to its own');
    expect(max.handles.witnessOkMs, greaterThanOrEqualTo(before));
    expect(max.handles.witnessState, HandleWitnessState.agreed);

    // Ahead: between the lookup's head and its question to the witness the
    // log grows by two, and the witness verifies the larger head.
    final w2 = await witnessOf(log);
    late int held;
    final g = _Operator()
      ..witnessUrl = w2.url
      ..witness = () async {
        held = (await headOf(log)).size;
        await claimAt(log, 'liv.74');
        await claimAt(log, 'lou.75');
        await sync(w2, log);
        return KtResponse(200, w2.record);
      };
    final mo = await boot('Mo', config: witnessed(log, w2), fetcher: g);
    expect((await mo.handles.find('@lena.71')).state, HandleLookupState.found);
    expect(
        g.urls.any((u) =>
            u.path == '/kt/v1/consistency' &&
            u.query == 'first=$held&second=${held + 2}'),
        isTrue,
        reason: 'the log proved its head a prefix of the witness\'s');
    expect(mo.handles.witnessState, HandleWitnessState.agreed);

    // Recorded, sealed, with the configuration it is an answer under.
    final rows = await mo.vault.db.query('kv',
        columns: ['k'], where: 'k LIKE ?', whereArgs: ['%:handle_witness_ok_ms']);
    expect(rows.map((r) => r['k']), ['s:handle_witness_ok_ms'],
        reason: 'sealed, as nothing in Vault.plainKeys is');
    final stored =
        (jsonDecode((await mo.vault.kvGet('handle_witness_ok_ms'))!) as Map)
            .cast<String, Object?>();
    expect(stored['at'], mo.handles.witnessOkMs);
    expect(stored['w'], contains(b64(w2.pub)));
  });

  test('18. a witness that cannot be reached, or whose record does not '
      'verify, is no verdict: the lookup goes on, the state says no answer '
      'yet, and a day of asking without one is a witness gone quiet', () async {
    final log = await startLog();
    final nora = await claimAt(log, 'nora.81');
    final w = await witnessOf(log);

    // Nothing listening at the address.
    final closed = 'http://127.0.0.1:${await freePort()}/sth.json';
    final f0 = _Operator();
    final pat = await boot('Pat', config: witnessed(log, w, url: closed), fetcher: f0);
    final first = await pat.handles.find('@nora.81');
    expect(first.state, HandleLookupState.found);
    expect(first.introRid, await nora.introRid());
    expect(fetchesOf(f0, closed), 1, reason: 'asked, and nothing answered');
    expect(pat.handles.witnessState, HandleWitnessState.pending);
    expect(pat.handles.witnessSinceMs, isNotNull);
    expect(pat.handles.witnessOkMs, isNull);

    // One witness, asked over a day and a hour: unreachable, an error, and
    // records that do not verify — each no verdict, and the lookup found.
    String altered(void Function(Map<String, dynamic> r) change) {
      final r = jsonDecode(w.record) as Map<String, dynamic>;
      change(r);
      return jsonEncode(r);
    }

    String flipped(String b) {
      final x = unb64(b);
      x[5] ^= 1;
      return b64(x);
    }

    final answers = <String, Future<KtResponse> Function()>{
      'unreachable': () async => throw const SocketException('refused'),
      'an error': () async => KtResponse(404, '{}'),
      'the co-signature altered': () async => KtResponse(200,
          altered((r) => r['witness']['sig'] = flipped(r['witness']['sig'] as String))),
      'the log\'s signature altered': () async => KtResponse(200,
          altered((r) => r['sth']['sig'] = flipped(r['sth']['sig'] as String))),
      'not a record': () async => KtResponse(200, '{"sth":7}'),
    };
    final f = _Operator()..witnessUrl = w.url;
    final ola = await boot('Ola', config: witnessed(log, w), fetcher: f);
    final real = ola.handles.now;
    final t0 = real() - const Duration(hours: 25).inMilliseconds;
    var at = t0;
    ola.handles.now = () => at;
    for (final e in answers.entries) {
      f.witness = e.value;
      final l = await ola.handles.find('@nora.81');
      expect(l.state, HandleLookupState.found, reason: e.key);
      expect(ola.handles.witnessState, HandleWitnessState.pending, reason: e.key);
      at += const Duration(minutes: 10).inMilliseconds;
    }
    expect(ola.handles.witnessSinceMs, t0,
        reason: 'when it began asking without an answer');
    expect(fetchesOf(f, w.url), answers.length, reason: 'none kept for reuse');

    // A day on, the same: quiet since the first question.
    at = real();
    f.witness = answers['unreachable'];
    expect((await ola.handles.find('@nora.81')).state, HandleLookupState.found);
    expect(ola.handles.witnessState, HandleWitnessState.quiet);
    expect(ola.handles.witnessQuietSinceMs, t0);

    // It answers, agreeing: the asking without an answer is over.
    serve(f, w);
    expect((await ola.handles.find('@nora.81')).state, HandleLookupState.found);
    expect(ola.handles.witnessState, HandleWitnessState.agreed);
    expect(ola.handles.witnessSinceMs, isNull);
    expect(ola.handles.witnessLastAskMs, isNull);
    expect(await ola.vault.kvGet('handle_witness_since_ms'), isNull);
  });

  test('19. half a witness is refused when it is set, and one held from '
      'before is never asked', () async {
    final log = await startLog();
    await claimAt(log, 'halle.91');
    final w = await witnessOf(log);
    final f = _Operator();
    serve(f, w);
    final url = 'http://127.0.0.1:${log.port}';
    final pub = b64(log.pub);
    final quin = await boot('Quin', config: log.config, fetcher: f);
    Future<void> refused(HandleConfig c, String reason) => expectLater(
        quin.handles.setConfig(c),
        throwsA(isA<HandleConfigInvalid>().having((e) => e.reason, 'reason', reason)));
    await refused(
        HandleConfig(logUrl: url, logPubB64: pub, witnessUrl: w.url), 'urlWithoutKey');
    await refused(HandleConfig(logUrl: url, logPubB64: pub, witnessPubB64: b64(w.pub)),
        'keyWithoutUrl');
    await refused(
        HandleConfig(
            logUrl: url,
            logPubB64: pub,
            witnessUrl: w.url,
            witnessPubB64: b64(Uint8List(31))),
        'keyNotValid');
    expect(quin.handles.config.witnessUrl, isEmpty, reason: 'nothing was taken');
    expect(await quin.vault.kvGet('handle_config'), isNull, reason: 'nor stored');

    // Half a witness held already — as a configuration reads back from the
    // vault, written before the rule or restored from an archive — is no
    // witness: the lookup goes on and its address is never asked.
    for (final (name, half) in [
      ('Rae', {'url': url, 'pub': pub, 'wurl': w.url}),
      ('Ros', {'url': url, 'pub': pub, 'wpub': b64(w.pub)}),
      ('Rui', {'url': url, 'pub': pub, 'wurl': w.url, 'wpub': 'not base64'}),
    ]) {
      final d = await Directory.systemTemp.createTemp('z_hlookup_half');
      temps.add(d);
      final v = await Vault.open(rootOverride: d);
      final id = await ZIdentity.generate();
      await v.kvPut('identity', jsonEncode(id.toJson()));
      await v.kvPut('handle_config', jsonEncode(half));
      final s = await boot(name, config: log.config, fetcher: f, vault: v, id: id);
      expect(s.handles.config.witnessUrl.isNotEmpty || s.handles.config.witnessPubB64.isNotEmpty,
          isTrue, reason: 'the half it holds, as stored');
      expect(s.handles.config.hasWitness, isFalse);
      expect((await s.handles.find('@halle.91')).state, HandleLookupState.found);
      expect(s.handles.witnessState, HandleWitnessState.none);
    }
    expect(fetchesOf(f, w.url), 0, reason: 'half a witness is never fetched');

    // Both together are one, and it is asked.
    await quin.handles.setConfig(witnessed(log, w));
    expect(quin.handles.config.hasWitness, isTrue);
    expect((await quin.handles.find('@halle.91')).state, HandleLookupState.found);
    expect(fetchesOf(f, w.url), 1);
  });

  test('20. a record co-signed by a key other than the pinned one is no '
      'agreement and no verdict, however it compares', () async {
    // PROTOCOL §19.5: "A witness that cannot be fetched, or whose record
    // does not verify, is no verdict." A record co-signed under another key
    // does not verify against the pinned one, so it is neither agreement
    // nor a fork — as kt_witness_test 4 has it for the transparency log.
    final log = await startLog();
    await claimAt(log, 'sid.20');
    final w = await witnessOf(log);
    final f = _Operator();
    serve(f, w);
    final elsewhere = await pubOf(randomBytes(32));
    final sid = await boot('Sid', config: witnessed(log, w, key: elsewhere), fetcher: f);
    expect((await sid.handles.find('@sid.20')).state, HandleLookupState.found);
    expect(fetchesOf(f, w.url), 1, reason: 'it was asked');
    expect(sid.handles.witnessOkMs, isNull, reason: 'and the answer counted for nothing');
    expect(sid.handles.witnessState, HandleWitnessState.pending);
    // The same record pinned to the key it is signed with does count: the
    // refusal above was the pin, not the record.
    final ted = await boot('Ted', config: witnessed(log, w), fetcher: f);
    expect((await ted.handles.find('@sid.20')).state, HandleLookupState.found);
    expect(ted.handles.witnessState, HandleWitnessState.agreed);

    // A record that, under its own key, shows a fork — a head of the log's
    // size under the log's key over other roots — is still no verdict
    // under another pinned key: an unpinned signer is not evidence.
    final h = await headOf(log);
    final otherSeed = randomBytes(32);
    final other = await signedHead(log,
        size: h.size,
        logRoot: randomBytes(32),
        mapRoot: randomBytes(32),
        ts: DateTime.now().millisecondsSinceEpoch);
    final g = _Operator()
      ..witnessUrl = w.url
      ..witness = () async => KtResponse(200, await recordFor(other, otherSeed));
    final una = await boot('Una', config: witnessed(log, w), fetcher: g);
    expect((await una.handles.find('@sid.20')).state, HandleLookupState.found,
        reason: 'co-signed by a key that is not the one pinned');
    expect(una.handles.witnessState, HandleWitnessState.pending);
    // Pinned to that key, it is the fork it shows.
    final uri = await boot('Uri',
        config: witnessed(log, w, key: await pubOf(otherSeed)), fetcher: g);
    await expectLater(uri.handles.find('@sid.20'), failsWith(HandleFailure.forked));
  });

  test('21. a record a day old is held to consistency, and is not agreement',
      () async {
    final log = await startLog();
    await claimAt(log, 'ursa.21');
    final w = await witnessOf(log);
    final h = await headOf(log);
    final dayOld = DateTime.now().millisecondsSinceEpoch -
        const Duration(hours: 25).inMilliseconds;
    // The log's own roots, signed by its key a day and an hour ago and
    // co-signed then by the pinned witness: a witness that stopped there,
    // or whatever stands in front of it replaying what it saw.
    final stale = await recordFor(
        await signedHead(log,
            size: h.size, logRoot: h.logRoot, mapRoot: h.mapRoot, ts: dayOld),
        w.seed);
    final f = _Operator()
      ..witnessUrl = w.url
      ..witness = () async => KtResponse(200, stale);
    final val = await boot('Val', config: witnessed(log, w), fetcher: f);
    val.handles.witnessReuse = Duration.zero;
    expect((await val.handles.find('@ursa.21')).state, HandleLookupState.found,
        reason: 'consistent with the head, so no fork to refuse');
    expect(val.handles.witnessOkMs, isNull, reason: 'but it agreed with nothing since');
    expect(val.handles.witnessState, HandleWitnessState.pending);
    expect(val.handles.witnessSinceMs, isNotNull);

    // Behind the log's head, held to the proof between them: one entry on,
    // consistent still, and still not agreement.
    await claimAt(log, 'umi.21');
    expect((await val.handles.find('@ursa.21')).state, HandleLookupState.found);
    expect(
        f.urls.any((u) =>
            u.path == '/kt/v1/consistency' &&
            u.query == 'first=${h.size}&second=${h.size + 1}'),
        isTrue);
    expect(val.handles.witnessOkMs, isNull);

    // Still checked: a day-old record at the log's size over other roots is
    // the fork it always was.
    final now = await headOf(log);
    final forkedOld = await recordFor(
        await signedHead(log,
            size: now.size,
            logRoot: randomBytes(32),
            mapRoot: randomBytes(32),
            ts: dayOld),
        w.seed);
    f.witness = () async => KtResponse(200, forkedOld);
    await expectLater(val.handles.find('@ursa.21'), failsWith(HandleFailure.forked));
  });

  test('22. the build pins no handle log and no witness: the four values are '
      'empty together', () {
    expect(
        [
          defaultHandleLogUrl,
          defaultHandleLogPub,
          defaultHandleWitnessUrl,
          defaultHandleWitnessPub
        ],
        everyElement(isEmpty),
        reason: 'pinned together, in one release, with this test changed '
            'beside them (tool/check_ga.py refuses some set and not all)');
    const c = HandleConfig.defaults;
    expect(c.enabled, isFalse);
    expect(c.hasWitness, isFalse);
    expect(c.witnessProblem, isNull, reason: 'empty is not half');
  });

  test('23. a witness off loopback stops a test process asking anything at '
      'all', () async {
    final log = await startLog();
    await claimAt(log, 'oli.23');
    final nowhere = _Nowhere();
    final wes = await boot('Wes',
        config: HandleConfig(
            logUrl: 'http://127.0.0.1:${log.port}', // loopback, as a test's log must be
            logPubB64: b64(log.pub),
            witnessUrl: 'https://handle-witness.example/sth.json',
            witnessPubB64: b64(await pubOf(randomBytes(32)))),
        fetcher: nowhere);
    expect(wes.handles.config.hasWitness, isTrue,
        reason: 'the pair is whole; its address is the problem');
    expect(wes.handles.available, isFalse);
    await expectLater(
        wes.handles.find('@oli.23'), failsWith(HandleFailure.unavailable));
    await expectLater(wes.handles.isAvailable(Handle.parse('oli.24')),
        failsWith(HandleFailure.unavailable));
    expect(wes.handles.witnessState, HandleWitnessState.none);
    expect(nowhere.urls, isEmpty,
        reason: 'a witness on the internet is a stranger this suite must not ask');
  });

  test('24. the record is fetched at most once a lookup, used again for ten '
      'minutes under the same witness, and never without a lookup', () async {
    final log = await startLog();
    await claimAt(log, 'pia.24');
    final w = await witnessOf(log);
    final f = _Operator();
    serve(f, w);
    final pia = await boot('Pia', config: witnessed(log, w), fetcher: f);
    expect(pia.handles.witnessReuse, const Duration(minutes: 10));
    expect(fetchesOf(f, w.url), 0, reason: 'nothing asked before a lookup');
    await pia.handles.find('@pia.24');
    expect(fetchesOf(f, w.url), 1);
    // A run of lookups, a claim's check among them: the one record.
    await pia.handles.find('@pia.24');
    await pia.handles.isAvailable(Handle.parse('pia.25'));
    expect(fetchesOf(f, w.url), 1);
    expect(pia.handles.witnessState, HandleWitnessState.agreed);
    // Ten minutes on, the next lookup fetches again.
    final real = pia.handles.now;
    pia.handles.now = () => real() + const Duration(minutes: 10).inMilliseconds;
    await pia.handles.find('@pia.24');
    expect(fetchesOf(f, w.url), 2);
    // Another witness is asked for itself, whatever the last one said.
    final w2 = await witnessOf(log);
    serve(f, w2);
    await pia.handles.setConfig(witnessed(log, w2));
    await pia.handles.find('@pia.24');
    expect(fetchesOf(f, w2.url), 1);
    // A record that does not verify is not kept: each lookup asks again.
    f.witness = () async => KtResponse(200, '{"sth":7}');
    pia.handles.now = () => real() + const Duration(minutes: 30).inMilliseconds;
    await pia.handles.find('@pia.24');
    await pia.handles.find('@pia.24');
    expect(fetchesOf(f, w2.url), 3);
    // A lookup the log does not answer has no head to check: the witness is
    // not asked.
    final gone = _Operator()..refuse = (_) => true;
    serve(gone, w2);
    final quill = await boot('Quill', config: witnessed(log, w2), fetcher: gone);
    await expectLater(quill.handles.find('@pia.24'), failsWith(HandleFailure.unreachable));
    expect(fetchesOf(gone, w2.url), 0);
  });

  test('25. the witness\'s state is the configuration\'s it was recorded '
      'under: kept across a restart, forgotten when the log or the witness '
      'changes', () async {
    final log = await startLog();
    await claimAt(log, 'rhea.25');
    final w = await witnessOf(log);
    final w2 = await witnessOf(log);
    final f = _Operator();
    serve(f, w);
    // As a build pins them: from the defaults, never saved.
    final rex = await boot('Rex', config: witnessed(log, w), fetcher: f);
    await rex.handles.find('@rhea.25');
    expect(rex.handles.witnessState, HandleWitnessState.agreed);
    final agreedAt = rex.handles.witnessOkMs;
    final vault = rex.vault;
    final id = rex.identity;
    await stop(rex);
    // The same build, started again: kept.
    final again = await boot('Rex', config: witnessed(log, w), fetcher: f, vault: vault, id: id);
    expect(again.handles.witnessOkMs, agreedAt);
    expect(again.handles.witnessState, HandleWitnessState.agreed);
    await stop(again);
    // A build that pins another witness, over a vault that saved no
    // configuration of its own: setConfig never runs, and the last witness's
    // answer is not this one's.
    final rebuilt = await boot('Rex', config: witnessed(log, w2), fetcher: f, vault: vault, id: id);
    expect(rebuilt.handles.witnessOkMs, isNull);
    expect(rebuilt.handles.witnessState, HandleWitnessState.pending);
    expect(await vault.kvGet('handle_witness_ok_ms'), isNull);
    expect(await vault.kvGet('handle_witness_since_ms'), isNull);

    // Saved in Settings: the same witness again keeps its answer; another
    // witness, the witness removed, or another log under the same witness
    // starts again.
    final sue = await boot('Sue', config: log.config, fetcher: f);
    await sue.handles.setConfig(witnessed(log, w));
    await sue.handles.find('@rhea.25');
    expect(sue.handles.witnessState, HandleWitnessState.agreed);
    await sue.handles.setConfig(witnessed(log, w));
    expect(sue.handles.witnessState, HandleWitnessState.agreed);
    await sue.handles.setConfig(witnessed(log, w2));
    expect(sue.handles.witnessState, HandleWitnessState.pending);
    expect(await sue.vault.kvGet('handle_witness_ok_ms'), isNull);
    serve(f, w2);
    await sue.handles.find('@rhea.25');
    expect(sue.handles.witnessState, HandleWitnessState.agreed);
    await sue.handles.setConfig(log.config);
    expect(sue.handles.witnessState, HandleWitnessState.none);
    expect(await sue.vault.kvGet('handle_witness_ok_ms'), isNull);
    await sue.handles.setConfig(witnessed(log, w2));
    await sue.handles.find('@rhea.25');
    expect(sue.handles.witnessState, HandleWitnessState.agreed);
    final elsewhere = await startLog();
    await sue.handles.setConfig(HandleConfig(
        logUrl: 'http://127.0.0.1:${elsewhere.port}',
        logPubB64: b64(elsewhere.pub),
        witnessUrl: w2.url,
        witnessPubB64: b64(w2.pub)));
    expect(sue.handles.witnessOkMs, isNull,
        reason: 'another log under the same witness');
    expect(await sue.vault.kvGet('handle_witness_ok_ms'), isNull);
  });

  test('26. the known residual: a history that departs after the witness\'s '
      'latest co-signed head passes a first lookup, and counts as agreement',
      () async {
    // THE KNOWN RESIDUAL (THREAT_MODEL R50, PROTOCOL §21.8), pinned as it
    // stands. Nothing here is a property anyone wants: a remedy — send only
    // once a record at or past the lookup's head agrees, or keep the head no
    // witness has seen and check it at the next lookup — turns these
    // expectations over on purpose.
    //
    // (a) One log, its owner rule taken out by its operator. The witness
    // verifies it with Fern's claim in it; the operator then appends an
    // update naming an owner and a mailbox of its own.
    final x = await startLog(ruleless: true);
    final fern = await claimAt(x, 'fern.26');
    final w = await witnessOf(x);
    final witnessedSize = KtWitnessRecord.fromJson(
            (jsonDecode(w.record) as Map).cast<String, Object?>())
        .head
        .size;
    final mailbox = await takeOver(x, fern);
    final f = _Operator();
    serve(f, w);
    final carol = await boot('Carol', config: witnessed(x, w), fetcher: f);
    final a = await look(carol, f, '@fern.26');
    expect(a.error, isNull,
        reason: 'the log proves the way from the witness\'s head to its own');
    expect(
        f.urls.any((u) =>
            u.path == '/kt/v1/consistency' &&
            u.query == 'first=$witnessedSize&second=${witnessedSize + 1}'),
        isTrue);
    expect(a.found!.state, HandleLookupState.found);
    expect(a.found!.introRid, mailbox, reason: 'the operator\'s mailbox');
    expect(carol.handles.witnessState, HandleWitnessState.agreed);
    // The reference witness, asked to follow the log now, refuses it (exit
    // 2, a divergence): the entry breaks the owner rule. Carol is not told.
    final r = await Process.run(
        'node',
        [
          'tools/mirror.js',
          '--log',
          'http://127.0.0.1:${x.port}',
          '--pub',
          b64(x.pub),
          '--dir',
          w.dir,
          '--mode',
          'handles',
          '--witness-seed-env',
          'Z_HANDLE_WITNESS_SEED',
        ],
        workingDirectory: '$root/kt',
        environment: {'Z_HANDLE_WITNESS_SEED': hex(w.seed)});
    expect(r.exitCode, 2, reason: '${r.stdout}${r.stderr}');

    // (b) Two histories under one key, the same up to the witness's head:
    // one claim of @gwen.26 in both, the witness verifying y at that size;
    // then x gets the operator's claim of @hal.26, and y Hal's own.
    final y1 = await startLog();
    final x1 = await startLog(key: y1.seed);
    final label = await labelOf('gwen.26');
    final rk = await handleRecoveryKey(await RecoveryCode.generate(), label);
    final gwenOwner = randomBytes(32), gwenIntro = randomBytes(32);
    final rec =
        await recordOf(HandleRecordKind.claim, gwenOwner, gwenIntro, rk.rc);
    await put(y1, label, 1, rec, gwenOwner);
    await put(x1, label, 1, rec, gwenOwner);
    expect((await headOf(x1)).sameRootsAs(await headOf(y1)), isTrue,
        reason: 'one prefix in both histories (the two entries were accepted '
            'in the same hour)');
    final w1 = await witnessOf(y1);
    final thief = await claimAt(x1, 'hal.26');
    final hal = await claimAt(y1, 'hal.26');
    final g = _Operator();
    serve(g, w1);
    final dee = await boot('Dee', config: witnessed(x1, w1), fetcher: g);
    final b = await look(dee, g, '@hal.26');
    expect(b.error, isNull, reason: 'x extends the head the witness co-signed');
    expect(b.found!.introRid, await thief.introRid(),
        reason: 'the operator\'s mailbox, not Hal\'s');
    expect(b.found!.introRid, isNot(await hal.introRid()));
    expect(dee.handles.witnessState, HandleWitnessState.agreed);
    final deeFirst = dee.handles.witnessState.name;
    // The witness follows y past that head. Dee's next lookup inside ten
    // minutes uses the record she holds, and passes again; fetched afresh —
    // ten minutes on, or by anyone else — the record is the fork.
    await sync(w1, y1);
    expect((await look(dee, g, '@hal.26')).error, isNull,
        reason: 'the record held for ten minutes is the one from before');
    final real = dee.handles.now;
    dee.handles.now = () => real() + const Duration(minutes: 10).inMilliseconds;
    final later = await look(dee, g, '@hal.26');
    expect(later.error, forked());
    final eve = await boot('Eve', config: witnessed(x1, w1), fetcher: g);
    expect((await look(eve, g, '@hal.26')).error, forked());
    // ignore: avoid_print
    print('LOOKUP 26: an owner-rule break after the witness\'s head -> '
        '${a.found!.state.name}, ${carol.handles.witnessState.name}; a second '
        'history after it -> ${b.found!.state.name}, '
        '$deeFirst (the residual); fetched again after '
        'the witness moved on -> ${later.error}');
  });

  test('27. a log that will not prove the way between its head and its '
      'witness\'s fails the lookup, and nothing it returned is kept or sent',
      () async {
    // 15's "behind" case — one key, two histories, the witness a head
    // behind the lookup's — with the operator refusing /kt/v1/consistency.
    final x = await startLog();
    final y = await startLog(key: x.seed);
    await claimAt(y, 'fern.27');
    await claimAt(x, 'fern.27');
    final w = await witnessOf(y);
    await claimAt(x, 'gail.27');
    final f = _Operator();
    serve(f, w);
    final withhold = _Withholding(f);
    final carol =
        await boot('Carol', config: witnessed(x, w), fetcher: withhold);
    final label = await labelOf('fern.27');
    await expectLater(
        carol.handles.find('@fern.27'), failsWith(HandleFailure.unreachable));
    expect(withhold.denied, ['first=1&second=2'],
        reason: 'the proof from the witness\'s head, withheld');
    expect((await memoryOf(carol)).knownFor(label), isNull,
        reason: 'no record remembered');
    expect(carol.handles.outgoing, isEmpty, reason: 'no request kept');
    expect(carol.handles.stampsMade, 0, reason: 'no request made');
    expect(await carol.vault.kvScan('hvia_'), isEmpty);
    expect(carol.handles.witnessOkMs, isNull);
    expect(carol.handles.witnessSinceMs, isNotNull,
        reason: 'asked, without an answer that counts');
    // Something in place of the proof that is not one: a bad answer.
    withhold.garbage = true;
    await expectLater(
        carol.handles.find('@fern.27'), failsWith(HandleFailure.badAnswer));
    // The proof served: the fork it is (15).
    final g = _Operator();
    serve(g, w);
    final dan = await boot('Dan', config: witnessed(x, w), fetcher: g);
    await expectLater(
        dan.handles.find('@fern.27'), failsWith(HandleFailure.forked));

    // The witness ahead: an honest log that grows between the lookup's head
    // and its question to the witness (17), the proof withheld. The log's
    // own head is not below the witness's, so no fork — and no proof, so no
    // pass either.
    final log = await startLog();
    await claimAt(log, 'lena.27');
    final w2 = await witnessOf(log);
    var grown = 0;
    final h = _Operator()
      ..witnessUrl = w2.url
      ..witness = () async {
        await claimAt(log, 'liv.${270 + grown++}');
        await sync(w2, log);
        return KtResponse(200, w2.record);
      };
    final ahead = _Withholding(h);
    final mo = await boot('Mo', config: witnessed(log, w2), fetcher: ahead);
    await expectLater(
        mo.handles.find('@lena.27'), failsWith(HandleFailure.unreachable));
    expect(ahead.denied, hasLength(1));
    expect(h.urls.where((u) => u.path == '/kt/v1/sth'), hasLength(2),
        reason: 'the lookup\'s head, then the log\'s own head beside the '
            'witness\'s');
    // The proof served: the agreement it is (17).
    final mia = await boot('Mia', config: witnessed(log, w2), fetcher: h);
    expect((await mia.handles.find('@lena.27')).state, HandleLookupState.found);
    expect(mia.handles.witnessState, HandleWitnessState.agreed);
    // ignore: avoid_print
    print('LOOKUP 27: the proof withheld behind -> unreachable, a non-proof '
        '-> bad answer, served -> forked; withheld ahead -> unreachable, '
        'served -> agreed');
  });

  test('28. a fork is kept until the witness agrees again, whichever path met '
      'it: a drain\'s read, and a claim\'s read-back, which holds the claim '
      'rather than calling it taken', () async {
    // x is what the log shows; y, under the same key, what the witness saw.
    final x = await startLog();
    final y = await startLog(key: x.seed);
    await claimAt(y, 'yuri.28');
    final w = await witnessOf(y);
    final f = _Operator();
    serve(f, w);

    // Ada claims ada.28 in x with the witness configured. Her claim is a
    // publish and takes no head; the drain it begins reads her record
    // first, and that read is refused — the drain goes on, as it does when
    // the log cannot be asked, but the fork is kept, sealed, with the
    // configuration it answers. (A drain counts itself when it ends, after
    // its read: one drain, waited for whole.)
    final ada = await boot('Ada', config: witnessed(x, w), fetcher: f);
    final before = DateTime.now().millisecondsSinceEpoch;
    final draft =
        await ada.handles.prepareClaim(Handle.parse('ada.28'), pow: 16);
    await ada.handles.commitClaim(draft);
    await waitUntil(() => ada.handles.own?.phase == HandlePhase.live,
        what: 'ada.28 published');
    await waitUntil(() => ada.handles.drains >= 1,
        what: 'the drain the publish began, gone on past its refused read');
    expect(ada.handles.own!.phase, HandlePhase.live);
    expect(ada.handles.witnessState, HandleWitnessState.forked);
    expect(ada.handles.witnessForkMs, greaterThanOrEqualTo(before));
    final rows = await ada.vault.db.query('kv',
        columns: ['k'],
        where: 'k LIKE ?',
        whereArgs: ['%:handle_witness_fork_ms']);
    expect(rows.map((r) => r['k']), ['s:handle_witness_fork_ms'],
        reason: 'sealed');
    final stored =
        (jsonDecode((await ada.vault.kvGet('handle_witness_fork_ms'))!) as Map)
            .cast<String, Object?>();
    expect(stored['at'], ada.handles.witnessForkMs);
    expect(stored['w'], contains(b64(w.pub)));
    // Kept across a restart: read back from the vault, not met again — the
    // restarted app's witness answers nothing, so its own drain's read is no
    // verdict and cannot record a fork of its own.
    final vault = ada.vault;
    final id = ada.identity;
    final forkAt = ada.handles.witnessForkMs;
    await stop(ada);
    final silent = _Operator()
      ..witnessUrl = w.url
      ..witness = () async => KtResponse(503, '{}');
    final again = await boot('Ada',
        config: witnessed(x, w), fetcher: silent, vault: vault, id: id);
    expect(again.handles.witnessForkMs, forkAt);
    expect(again.handles.witnessState, HandleWitnessState.forked);

    // Bea claims a name somebody claimed in x first. The log refuses her
    // claim as taken, and the read-back that would say whose it is meets
    // the fork: the claim is held, with the fork as its problem — not taken.
    await claimAt(x, 'bea.28');
    final bea = await boot('Bea', config: witnessed(x, w), fetcher: f);
    final d2 = await bea.handles.prepareClaim(Handle.parse('bea.28'), pow: 16);
    await bea.handles.commitClaim(d2);
    await waitUntil(() => bea.handles.own?.phase == HandlePhase.held,
        what: 'the claim held, not taken');
    expect(bea.handles.own!.problem, HandleFailure.forked.name);
    expect(bea.handles.witnessState, HandleWitnessState.forked);

    // The witness agreeing again — its key co-signing x's head now, a
    // witness that has followed x — ends the fork. (Bea, whose claim is
    // held, has no drain of her own to race this; the record she holds from
    // the read-back is not used again.)
    bea.handles.witnessReuse = Duration.zero;
    f.witness =
        () async => KtResponse(200, await recordFor(await headOf(x), w.seed));
    expect((await bea.handles.find('@bea.28')).state, HandleLookupState.found);
    expect(bea.handles.witnessState, HandleWitnessState.agreed);
    expect(bea.handles.witnessForkMs, isNull);
    expect(await bea.vault.kvGet('handle_witness_fork_ms'), isNull);

    // Another witness forgets it, as it forgets the rest (25); a drain of
    // Ada's still asking the last one cannot put it back.
    final w2 = await witnessOf(x);
    await again.handles.setConfig(witnessed(x, w2));
    expect(again.handles.witnessForkMs, isNull);
    expect(await again.vault.kvGet('handle_witness_fork_ms'), isNull);
    expect(again.handles.witnessState, isNot(HandleWitnessState.forked));
  });
}
