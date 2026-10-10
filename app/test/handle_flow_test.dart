// Handles in the app (phase 38; ADR 0015 revision 2; PROTOCOL §21), end to
// end: real ChatService instances, the real relay (server/server.js) and the
// real handle log (kt/server.js with KT_MODE=handles), both on loopback. Every
// account reaches the relay through a tap that writes down each frame of
// each connection, so what the relay saw is asserted directly.
//
// Criteria, each a test below:
//   1. a claim is published after its (test-shortened) delay, and the log
//      then holds exactly the record expected — a claim at version 1 naming
//      the device's owner and introduction keys, the difficulty asked for,
//      and the commitment of the code that was shown — and one entry more
//      than before; the code is nowhere in the vault; a claim of a handle
//      the log already holds ends `taken` and changes nothing there; free
//      digits are found at random; a cancelled claim is never published;
//   2. found by a second account, requested, filed on the owner's side "via"
//      the handle, accepted: both hold each other as contacts, unverified,
//      the requester's linked to its request by `ia` and told so in the
//      chat, and the two can talk;
//   3. an acceptance without `ia`, with one signed by any other key, or with
//      the genuine introduction key's `ia` carried by another account, is
//      never auto-linked: each is an ordinary request; the genuine one from
//      the account it names is;
//   4. a request without a valid stamp never reaches the owner — the relay
//      refuses it before storing it (its counter says so) — a requester whose
//      clock is days behind re-stamps once with the relay's day and gets
//      through (one days ahead cannot look the handle up: every answer of
//      the log's is too old by its clock), and a sender whose stamps never
//      pass stops after exactly two sends;
//   5. the account's own routing id and the introduction routing id are
//      never on one relay connection: the mailbox is drained on a connection
//      of its own that sends `intro`, registers no push and sends nothing,
//      the account's connection never sends `intro`, and requests reach the
//      mailbox only on connections that never authenticated and carry
//      nothing else (so not the requester's later envelopes to the account
//      the handle introduced);
//   6. pause: the log's record loses its introduction keys, a lookup says
//      paused, and a request is refused with nothing sent; resume restores
//      the same mailbox;
//   7. rotate: lookups find the new mailbox and requests go only there, the
//      old one is read once more without being re-flagged and gets nothing
//      new, and a request that reached it before the rotation is still
//      accepted with an acknowledgement its requester verifies;
//   8. recover on a fresh account with the code: the log's latest entry is a
//      recover naming the new owner and commitment, requests reach the new
//      account, the old code no longer recovers it and the new one does, a
//      backup code is refused by name, and the old owner sees it lost;
//   9. backup and restore keep the handle: the restored device holds the
//      same mailbox and the pending handle request, drains (re-flags) the
//      mailbox, publishes nothing, receives new requests and accepts old
//      ones with the restored key; a claim that was pending at the backup
//      comes back held and is published only when asked;
//  10. the cap: past 100 pending handle requests the oldest unseen go, and a
//      request already seen stays;
//  11. a linked device neither manages nor drains the introduction mailbox,
//      and learns the contact the primary device makes through it by
//      self-sync;
//  12. with no handle log configured — this build's defaults — every handle
//      operation says unavailable, and a test process never contacts a log
//      that is not on loopback;
//  13. envelopes that can never be handle requests (not sealed to the
//      mailbox, not requests, addressed elsewhere, sealed by someone other
//      than their signer) are acknowledged and dropped without wedging the
//      mailbox: the request behind them is filed and nothing is handed over
//      again.
@Tags(['integration'])
@Timeout(Duration(minutes: 4))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' show Ed25519;
import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;
import 'package:zapp/core/archive.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/handles.dart';
import 'package:zapp/core/key_transparency.dart';
import 'package:zapp/core/models.dart';
import 'package:zapp/core/restore.dart';
import 'package:zapp/core/system_messages.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:z_protocol/z_protocol.dart';

/// One connection through the tap, as the relay saw it.
class TapConn {
  TapConn(this.n);
  final int n;

  /// The routing id this connection authenticated as; null for one that
  /// never did (the anonymous sender link, a raw sender).
  String? authRid;
  final up = <Map<String, Object?>>[]; // client → relay
  final down = <Map<String, Object?>>[]; // relay → client
  bool get anonymous => authRid == null;
  List<String> get upTypes => [for (final f in up) '${f['t']}'];
  Iterable<Map<String, Object?>> sendsTo(String rid) =>
      up.where((f) => f['t'] == 'send' && f['to'] == rid);
}

/// A WebSocket proxy in front of the relay that writes down every frame in
/// both directions, per connection. The Host header goes through unchanged,
/// as a front passes it: a client signs its authentication over the address
/// it dialled.
class Tap {
  Tap._(this.server, this.relayPort);
  final HttpServer server;
  final int relayPort;
  final conns = <TapConn>[];
  String get url => 'ws://127.0.0.1:${server.port}';
  int sendsTo(String rid) =>
      conns.fold(0, (n, c) => n + c.sendsTo(rid).length);

  static Future<Tap> start(int relayPort) async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final tap = Tap._(server, relayPort);
    server.listen((req) async {
      final WebSocket down;
      try {
        down = await WebSocketTransformer.upgrade(req);
      } catch (_) {
        req.response.statusCode = HttpStatus.badRequest;
        await req.response.close();
        return;
      }
      final up = await WebSocket.connect('ws://127.0.0.1:$relayPort',
          headers: {'host': req.headers.value('host') ?? ''});
      final c = TapConn(tap.conns.length);
      tap.conns.add(c);
      Map<String, Object?>? parse(dynamic d) {
        if (d is! String) return null;
        try {
          final j = jsonDecode(d);
          return j is Map ? j.cast<String, Object?>() : null;
        } catch (_) {
          return null;
        }
      }

      down.listen((d) {
        final f = parse(d);
        if (f != null) {
          c.up.add(f);
          if (f['t'] == 'auth' && f['pub'] is String) {
            unawaited(sha256Bytes(base64Decode(f['pub'] as String))
                .then((h) => c.authRid = b64url(h)));
          }
        }
        up.add(d);
      }, onDone: () => up.close(), onError: (_) => up.close());
      up.listen((d) {
        final f = parse(d);
        if (f != null) c.down.add(f);
        down.add(d);
      }, onDone: () => down.close(), onError: (_) => down.close());
    });
    return tap;
  }
}

/// Answers every request with a failure, and counts them.
class _CountingFetcher implements KtFetcher {
  final urls = <Uri>[];
  @override
  Future<KtResponse> get(Uri url) async {
    urls.add(url);
    return KtResponse(500, '{}');
  }

  @override
  Future<KtResponse> post(Uri url, String jsonBody) async {
    urls.add(url);
    return KtResponse(500, '{}');
  }
}

Matcher failsWith(HandleFailure f) => throwsA(
    isA<HandleException>().having((e) => e.failure, 'failure', f));

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  final root = Directory.current.parent.path;
  const metricsToken = 'z-handles-test-metrics';
  late Process relay;
  late int relayPort;
  late Process log;
  late int logPort;
  late Uint8List logPub;
  late Tap tap;
  late Tap tapB; // the linked device's own way in (criterion 11)
  final logSeed =
      Uint8List.fromList(List<int>.generate(32, (i) => (i * 11 + 5) & 0xff));
  final temps = <Directory>[];
  final services = <ChatService>[];
  final raws = <RelayClient>[];

  Future<int> freePort() async {
    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final port = probe.port;
    await probe.close();
    return port;
  }

  Future<void> healthy(int port, String what) async {
    for (var i = 0; i < 100; i++) {
      try {
        final res = await (await HttpClient()
                .getUrl(Uri.parse('http://127.0.0.1:$port/health')))
            .close();
        await res.drain<void>();
        if (res.statusCode == 200) return;
      } catch (_) {}
      await Future<void>.delayed(const Duration(milliseconds: 100));
    }
    fail('$what did not start');
  }

  setUpAll(() async {
    relayPort = await freePort();
    relay = await Process.start('node', ['server.js'],
        workingDirectory: '$root${Platform.pathSeparator}server',
        environment: {
          'PORT': '$relayPort',
          'LOG_LEVEL': 'silent',
          'METRICS_TOKEN': metricsToken,
          // The relay paces new flags per address and `intro` frames per
          // mailbox (§21.6). Every account here comes from 127.0.0.1 and the
          // tests drain in quick succession, so paced at the defaults some
          // mailboxes would go unflagged, and this file asserts what the
          // relay does for a flagged one. `handle_inbox_test.dart` 7 is where
          // the pacing itself is tested.
          'INTRO_NEW_PER_IP_PER_MIN': '100000',
          'INTRO_PER_RID_PER_MIN': '100000',
        });
    relay.stdout.drain<void>();
    relay.stderr.drain<void>();
    await healthy(relayPort, 'the relay');
    logPort = await freePort();
    log = await Process.start('node', ['server.js'],
        workingDirectory: '$root${Platform.pathSeparator}kt',
        environment: {
          'KT_MODE': 'handles',
          'KT_SEED': [for (final b in logSeed) b.toRadixString(16).padLeft(2, '0')]
              .join(),
          'KT_EPHEMERAL': '1',
          'KT_PORT': '$logPort',
          // The publish gates are kt/test/publish_limits.test.js's business;
          // every claim and update in this file shares them.
          'PUBLISH_PER_MIN': '1000000',
          'PUBLISH_PER_MIN_TOTAL': '1000000',
          'PUBLISH_PER_ACCT_PER_DAY': '1000000',
          'PUBLISH_NEW_ACCOUNTS_PER_MIN': '1000000',
          'PUBLISH_NEW_ACCOUNTS_PER_ADDR_PER_MIN': '1000000',
        });
    log.stdout.drain<void>();
    log.stderr.drain<void>();
    await healthy(logPort, 'the handle log');
    logPub = Uint8List.fromList(
        (await (await Ed25519().newKeyPairFromSeed(logSeed)).extractPublicKey())
            .bytes);
    tap = await Tap.start(relayPort);
    tapB = await Tap.start(relayPort);
  });

  tearDownAll(() async {
    for (final s in services) {
      s.dispose();
      await s.transport
          .stop()
          .timeout(const Duration(seconds: 10), onTimeout: () {});
    }
    for (final r in raws) {
      await r.close();
    }
    await tap.server.close(force: true);
    await tapB.server.close(force: true);
    relay.kill();
    log.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  HandleConfig handleCfg() => HandleConfig(
      logUrl: 'http://127.0.0.1:$logPort', logPubB64: b64(logPub));

  Future<void> waitUntil(FutureOr<bool> Function() cond,
      {Duration timeout = const Duration(seconds: 40),
      required String what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  Future<Directory> tempDir(String name) async {
    final d = await Directory.systemTemp.createTemp('z_handles_$name');
    temps.add(d);
    return d;
  }

  /// The timings of §21.8, shortened so a claim publishes in well under a
  /// second; the periodic drain is pushed out of the way and the tests drain
  /// when they need to (criterion 11 runs the timer itself).
  void fast(ChatService s) {
    final h = s.handles;
    h.claimDelayMin = const Duration(milliseconds: 150);
    h.claimDelayMax = const Duration(milliseconds: 400);
    h.startDelayMin = const Duration(milliseconds: 50);
    h.startDelayMax = const Duration(milliseconds: 100);
    h.foregroundDelayMin = const Duration(milliseconds: 50);
    h.foregroundDelayMax = const Duration(milliseconds: 150);
    h.drainQuiet = const Duration(milliseconds: 400);
    h.drainEvery = const Duration(minutes: 30);
  }

  Future<ChatService> boot(String name,
      {ZIdentity? id,
      Vault? vault,
      Tap? via,
      HandleConfig? config,
      KtFetcher? fetcher}) async {
    final v = vault ?? await Vault.open(rootOverride: await tempDir(name));
    final identity = id ?? await ZIdentity.generate();
    if (vault == null) {
      await v.kvPut('identity', jsonEncode(identity.toJson()));
    }
    final transport =
        Transport(identity: identity, serverUrl: (via ?? tap).url);
    final svc = await ChatService.init(
        vault: v,
        identity: identity,
        displayName: name,
        transport: transport,
        ktConfig: KtConfig.off,
        handleConfig: config ?? handleCfg(),
        handleFetcher: fetcher);
    fast(svc);
    services.add(svc);
    return svc;
  }

  bool up(ChatService s) =>
      s.transport.isConnected && s.transport.isSenderConnected;

  Future<void> connected(List<ChatService> ss) => waitUntil(
      () => ss.every(up),
      what: '${ss.map((s) => s.displayName).join(', ')} connected');

  List<String> texts(ChatService s, String rid) => [
        for (final m in s.messagesByChat[rid] ?? const <ChatMessage>[])
          if (m.kind == 'text') m.body
      ];

  Future<Map<String, Object?>> logGet(String path) async {
    final res = await (await HttpClient()
            .getUrl(Uri.parse('http://127.0.0.1:$logPort$path')))
        .close();
    return (jsonDecode(await res.transform(utf8.decoder).join()) as Map)
        .cast<String, Object?>();
  }

  Future<int> logSize() async => (await logGet('/kt/v1/sth'))['size'] as int;

  /// The log's latest entry for [label], from its bucket, verified here
  /// with the protocol library alone.
  Future<KtBucketLeaf?> logLeaf(Uint8List label) async {
    final sth = await logGet('/kt/v1/sth');
    final q = KtBucketQuery.forLabel(label, sth['bucketBits'] as int);
    final v = await ktVerifyBucketAnswer(await logGet(q.path),
        asked: [q], logPub: logPub, mode: KtLogMode.handles);
    return v.buckets.single.leafFor(label);
  }

  Future<int> metric(String name) async {
    final req = await HttpClient()
        .getUrl(Uri.parse('http://127.0.0.1:$relayPort/metrics'));
    req.headers.set('authorization', 'Bearer $metricsToken');
    final res = await req.close();
    final body = await res.transform(utf8.decoder).join();
    expect(res.statusCode, 200, reason: 'the metrics scrape was refused');
    final m = RegExp('^$name (\\d+)\$', multiLine: true).firstMatch(body);
    return int.parse(m!.group(1)!);
  }

  /// Claim [handle] on [s] and wait for it to be published and its mailbox
  /// first drained (which flags it at the relay). Returns the draft: the
  /// code, the seeds, the label.
  Future<HandleClaimDraft> claim(ChatService s, String handle,
      {int pow = 16}) async {
    final draft = await s.handles.prepareClaim(Handle.parse(handle), pow: pow);
    await s.handles.commitClaim(draft);
    await waitUntil(() => s.handles.own?.phase == HandlePhase.live,
        what: '$handle published');
    await waitUntil(() => s.handles.drains >= 1,
        what: '$handle\'s mailbox drained and flagged');
    return draft;
  }

  /// [asker] holds [owner] as the contact its request to [handle] made: the
  /// contact exists and the request is no longer waited on — the last step
  /// of taking an acknowledged acceptance, after the handle is recorded and
  /// the line is in the chat.
  Future<void> linked(ChatService asker, ChatService owner, String handle) =>
      waitUntil(
          () =>
              asker.contacts.containsKey(owner.myRid) &&
              asker.handles.outgoing.every((o) => o.handle != handle),
          what: '${asker.displayName} linked to ${owner.displayName} '
              'through $handle');

  /// Drain [owner]'s mailbox until the request from [rid] is filed.
  Future<void> receives(ChatService owner, String rid) => waitUntil(
      () async {
        await owner.handles.drain();
        return owner.requestsByRid.containsKey(rid);
      },
      what: '${owner.displayName} filing the request from $rid');

  Future<RelayClient> rawSender() async {
    final c = await RelayClient.connectAnonymous(
        tap.url, await ZIdentity.generate());
    raws.add(c);
    return c;
  }

  /// A contact request from [from] to [to], sealed to [xPub] — what any
  /// client could build.
  Future<String> sealedRequest(ZIdentity from,
      {required String to, required Uint8List xPub, String? ia}) async {
    final creq = await ContactRequest.create(
        me: from, toRid: to, displayName: 'raw', ia: ia);
    return SealedEnvelope.seal(
        toXPub: xPub, fromRid: await from.routingId(), payload: creq.encode());
  }

  /// A send to an introduction mailbox with a stamp for today (and, near the
  /// relay's midnight, for its day).
  Future<void> stamped(
      RelayClient c, String introRid, String payload, int bits) async {
    final id = newMessageId();
    final env = utf8.encode(payload);
    final today = introPowDay(DateTime.now().millisecondsSinceEpoch);
    try {
      await c.send(
          to: introRid,
          id: id,
          payload: payload,
          pow: b64url(createIntroPowStamp(
              introRid: introRid, day: today, envelope: env, bits: bits)));
    } on RelayPowRequired catch (e) {
      await c.send(
          to: introRid,
          id: id,
          payload: payload,
          pow: b64url(createIntroPowStamp(
              introRid: introRid, day: e.day, envelope: env, bits: bits)));
    }
  }

  test(
      '1. a claim publishes after its delay as exactly the record expected; '
      'taken, random digits and cancel', () async {
    final ann = await boot('ann');
    await connected([ann]);
    final before = await logSize();
    final draft =
        await ann.handles.prepareClaim(Handle.parse('Ann.11'), pow: 16);
    expect(ann.handles.own, isNull, reason: 'nothing is kept before it is confirmed');
    expect(draft.code, startsWith('ZHR-'));
    await ann.handles.commitClaim(draft);
    expect(ann.handles.own!.phase, HandlePhase.pending,
        reason: 'published later, not now');
    await waitUntil(() => ann.handles.own!.phase == HandlePhase.live,
        what: 'the claim published after its delay');

    // Exactly the expected record, recomputed here from the draft alone.
    expect(draft.label, await handleLabel(Handle.parse('ann.11')));
    final intro = await handleIntroIdentity(draft.introSeed);
    final rk = await handleRecoveryKey(draft.recoveryCode, draft.label);
    final expected = HandleRecord.claim(
            owner: await handleKeyPublic(draft.ownerSeed),
            intro: intro.edPub,
            xintro: intro.xPub,
            pow: 16,
            rc: rk.rc)
        .encode();
    final leaf = (await logLeaf(draft.label))!;
    expect(leaf.version, 1);
    expect(leaf.value, expected);
    expect(leaf.ts! % handleHourMs, 0, reason: 'the log keeps the hour');
    expect(await logSize(), before + 1, reason: 'one entry: the claim');

    // The code — and the key it derives — are nowhere in the vault.
    final everything = (await ann.vault.kvScan('')).values.join('\n');
    final entropy = draft.recoveryCode.entropy;
    for (final s in [
      draft.code,
      draft.code.substring(4),
      b64(entropy),
      b64url(entropy),
      b64(rk.seed),
      b64url(rk.seed),
    ]) {
      expect(everything.contains(s), isFalse,
          reason: 'the recovery code is shown once and never stored');
    }

    // A second claim of the same handle loses, and changes nothing.
    final bea = await boot('bea');
    await connected([bea]);
    expect(await bea.handles.isAvailable(Handle.parse('ann.11')), isFalse);
    final second =
        await bea.handles.prepareClaim(Handle.parse('ann.11'), pow: 16);
    await bea.handles.commitClaim(second);
    await waitUntil(() => bea.handles.own!.phase == HandlePhase.taken,
        what: 'the later claim refused as taken');
    expect((await logLeaf(draft.label))!.value, expected);
    expect(await logSize(), before + 1);

    // Random digits: a free handle, found by looking.
    final free = await bea.handles.availableWithRandomDigits('bea');
    expect(free, isNotNull);
    expect(free!.digits, hasLength(2));
    expect(await bea.handles.isAvailable(free), isTrue);

    // A claim cancelled before its moment is never published.
    await bea.handles.cancelClaim();
    bea.handles.claimDelayMin = const Duration(minutes: 30);
    bea.handles.claimDelayMax = const Duration(minutes: 30);
    final cancelled = await bea.handles.prepareClaim(free, pow: 16);
    await bea.handles.commitClaim(cancelled);
    expect(bea.handles.own!.phase, HandlePhase.pending);
    await bea.handles.cancelClaim();
    expect(bea.handles.own, isNull);
    expect(await bea.vault.kvGet('handle'), isNull);
    expect(await logLeaf(cancelled.label), isNull);
  });

  test(
      '2. find, request, "via", accept: contacts both ways, unverified, '
      'the requester linked by ia', () async {
    final olga = await boot('Olga');
    final rick = await boot('Rick');
    await connected([olga, rick]);
    await claim(olga, 'olga.22');

    final found = await rick.handles.find('  @Olga.22 ');
    expect(found.state, HandleLookupState.found);
    expect(found.handle.canonical, 'olga.22');
    expect(found.introRid, olga.handles.own!.introRid);
    expect(found.record!.pow, 16);
    await rick.handles.request(found);
    expect(rick.handles.outgoing.single.handle, 'olga.22');

    await receives(olga, rick.myRid);
    final pending = olga.requestsByRid[rick.myRid]!;
    expect(pending.via, 'olga.22');
    expect(pending.name, 'Rick');
    expect(olga.contacts.containsKey(rick.myRid), isFalse);
    expect(olga.handles.inboundFor(rick.myRid)!.introRid,
        olga.handles.own!.introRid);

    await olga.acceptRequest(rick.myRid);
    await linked(rick, olga, 'olga.22');
    expect(olga.contacts.containsKey(rick.myRid), isTrue);
    expect(rick.requestsByRid.containsKey(olga.myRid), isFalse,
        reason: 'an acknowledged acceptance is not a request');
    expect(await rick.handleViaOf(olga.myRid), 'olga.22');
    expect(rick.handles.outgoing, isEmpty, reason: 'answered');
    expect(olga.requestsByRid, isEmpty);
    expect(olga.handles.inboundFor(rick.myRid), isNull);
    expect(rick.contacts[olga.myRid]!.verified, isFalse);
    expect(olga.contacts[rick.myRid]!.verified, isFalse);
    expect(rick.verificationWith(olga.myRid), VerificationState.unverified);
    expect(olga.verificationWith(rick.myRid), VerificationState.unverified);
    expect(
        [
          for (final m in rick.messagesByChat[olga.myRid]!)
            if (m.kind == 'system') m.body
        ],
        contains(systemBody(SystemKind.handleAccepted, {'h': 'olga.22'})));

    await rick.sendText(olga.myRid, 'found you by your handle');
    await waitUntil(
        () => texts(olga, rick.myRid).contains('found you by your handle'),
        what: 'Olga reading Rick');
    await olga.sendText(rick.myRid, 'so you did');
    await waitUntil(() => texts(rick, olga.myRid).contains('so you did'),
        what: 'Rick reading Olga');
  });

  test(
      '3. no ia, a forged ia, or a genuine ia carried by another account: '
      'never auto-linked', () async {
    final omar = await boot('Omar');
    final rita = await boot('Rita');
    await connected([omar, rita]);
    await claim(omar, 'omar.33');
    await rita.handles.request(await rita.handles.find('omar.33'));
    await receives(omar, rita.myRid);
    final waiting = rita.handles.outgoing.single;

    // Omar's app answers as one from before the acknowledgement.
    omar.handles.debugOmitAcknowledgement = true;
    await omar.acceptRequest(rita.myRid);
    await waitUntil(() => rita.requestsByRid.containsKey(omar.myRid),
        what: 'the bare acceptance filed as an ordinary request');
    expect(rita.contacts.containsKey(omar.myRid), isFalse);
    expect(rita.handles.outgoing.single.handle, 'omar.33');

    final raw = await rawSender();
    // An ia by a key that is not the introduction key.
    final mallory = await ZIdentity.generate();
    final forged = await signIntroAck(
        introSeed: randomBytes(32),
        requesterRid: rita.myRid,
        ownerAccountEdPub: mallory.edPub,
        creqId: waiting.creqIds.last);
    await raw.send(
        to: rita.myRid,
        id: newMessageId(),
        payload: await sealedRequest(mallory,
            to: rita.myRid, xPub: rita.identity.xPub, ia: forged));
    final malloryRid = await mallory.routingId();
    await waitUntil(() => rita.requestsByRid.containsKey(malloryRid),
        what: 'the forged acceptance filed as an ordinary request');
    expect(rita.contacts.containsKey(malloryRid), isFalse);

    // The genuine introduction key's ia for Rita's request — for Omar's
    // account — carried by another account.
    final genuine = await signIntroAck(
        introSeed: omar.handles.own!.introSeed,
        requesterRid: rita.myRid,
        ownerAccountEdPub: omar.identity.edPub,
        creqId: waiting.creqIds.last);
    final eve = await ZIdentity.generate();
    await raw.send(
        to: rita.myRid,
        id: newMessageId(),
        payload: await sealedRequest(eve,
            to: rita.myRid, xPub: rita.identity.xPub, ia: genuine));
    final eveRid = await eve.routingId();
    await waitUntil(() => rita.requestsByRid.containsKey(eveRid),
        what: 'the replayed acknowledgement filed as an ordinary request');
    expect(rita.contacts.containsKey(eveRid), isFalse);
    expect(rita.handles.outgoing.single.handle, 'omar.33',
        reason: 'none of those answered it');

    // The same acknowledgement from the account it names: linked.
    await raw.send(
        to: rita.myRid,
        id: newMessageId(),
        payload: await sealedRequest(omar.identity,
            to: rita.myRid, xPub: rita.identity.xPub, ia: genuine));
    await linked(rita, omar, 'omar.33');
    expect(await rita.handleViaOf(omar.myRid), 'omar.33');
    expect(rita.handles.outgoing, isEmpty);
    expect(rita.requestsByRid.containsKey(omar.myRid), isFalse);
  });

  test(
      '4. no stamp, no delivery; a clock days out re-stamps once; '
      'stamps that never pass stop after two', () async {
    final oona = await boot('Oona');
    final ahmed = await boot('Ahmed');
    final nina = await boot('Nina');
    await connected([oona, ahmed, nina]);
    await claim(oona, 'oona.44');
    final own = oona.handles.own!;
    final introRid = own.introRid;
    final xintro = (await handleIntroIdentity(own.introSeed)).xPub;

    // No stamp: refused before anything is stored.
    final refusedBefore = await metric('z_intro_pow_refused_total');
    final stranger = await ZIdentity.generate();
    final raw = await rawSender();
    RelayPowRequired? refusal;
    try {
      await raw.send(
          to: introRid,
          id: newMessageId(),
          payload: await sealedRequest(stranger, to: introRid, xPub: xintro));
    } on RelayPowRequired catch (e) {
      refusal = e;
    }
    expect(refusal, isNotNull);
    expect(refusal!.bits, 16);
    expect(await metric('z_intro_pow_refused_total'), refusedBefore + 1);
    expect(await oona.handles.drain(), 0, reason: 'nothing was stored');
    expect(oona.requestsByRid.containsKey(await stranger.routingId()), isFalse);

    // A requester whose clock is two days out. Ahead, it cannot look the
    // handle up at all: every head the log signs is two days old by its
    // clock, and refused as stale (PROTOCOL §21.8). Behind, the lookup
    // stands, and its stamp is for a day the relay does not take: the one
    // re-made for the relay's day is.
    ahmed.handles.now =
        () => DateTime.now().millisecondsSinceEpoch + 2 * 86400000;
    await expectLater(
        ahmed.handles.find('oona.44'), failsWith(HandleFailure.stale));
    ahmed.handles.now =
        () => DateTime.now().millisecondsSinceEpoch - 2 * 86400000;
    await ahmed.handles.request(await ahmed.handles.find('oona.44'));
    expect(ahmed.handles.stampsMade, 2);
    await receives(oona, ahmed.myRid);

    // A sender whose stamps can never pass: two sends, then it stops.
    nina.handles.debugStampFilter = (_) => b64url(Uint8List(16));
    final sendsBefore = tap.sendsTo(introRid);
    await expectLater(nina.handles.request(await nina.handles.find('oona.44')),
        failsWith(HandleFailure.powRefused));
    expect(nina.handles.stampsMade, 2);
    expect(tap.sendsTo(introRid), sendsBefore + 2,
        reason: 'the first send and one re-stamp, and no more');
    expect(nina.handles.outgoing, isEmpty, reason: 'nothing to wait for');
    expect(await oona.handles.drain(), 0);
    expect(oona.requestsByRid.containsKey(nina.myRid), isFalse);
  });

  test(
      '5. the account\'s routing id and the introduction routing id are never '
      'on one relay connection', () async {
    final otto = await boot('Otto');
    final ruth = await boot('Ruth');
    await connected([otto, ruth]);
    // A push token on the account, so that "the mailbox registers none" is
    // a statement about something that happens.
    otto.transport.setPushToken('otto-push-token');
    await claim(otto, 'otto.55');
    final introRid = otto.handles.own!.introRid;
    await ruth.handles.request(await ruth.handles.find('otto.55'));
    await receives(otto, ruth.myRid);
    await otto.acceptRequest(ruth.myRid);
    await linked(ruth, otto, 'otto.55');
    // And they talk, so the requester's own links carry the account's
    // traffic too.
    await ruth.sendText(otto.myRid, 'hello');
    await waitUntil(() => texts(otto, ruth.myRid).contains('hello'),
        what: 'Otto reading Ruth');
    await otto.handles.drain();

    final asOtto = tap.conns.where((c) => c.authRid == otto.myRid).toList();
    final asIntro = tap.conns.where((c) => c.authRid == introRid).toList();
    expect(asOtto, isNotEmpty);
    expect(asIntro, isNotEmpty);
    expect(asOtto.expand((c) => c.upTypes), contains('push-register'));
    for (final c in asOtto) {
      expect(c.upTypes, isNot(contains('intro')),
          reason: 'the account\'s connection never flags anything');
      expect(c.sendsTo(introRid), isEmpty);
    }
    for (final c in asIntro) {
      expect(c.upTypes.first, 'auth');
      expect(c.upTypes, contains('intro'),
          reason: 'flagged after every authentication');
      expect(c.upTypes, isNot(contains('push-register')));
      expect(c.upTypes, isNot(contains('send')),
          reason: 'the mailbox\'s connection only reads');
      expect(c.sendsTo(otto.myRid), isEmpty);
    }
    expect(asIntro.expand((c) => c.down).where((f) => f['t'] == 'msg'),
        isNotEmpty);
    expect(asIntro.expand((c) => c.upTypes), contains('recv'));
    final carriers = [
      for (final c in tap.conns)
        if (c.sendsTo(introRid).isNotEmpty) c
    ];
    expect(carriers, isNotEmpty);
    expect(carriers.every((c) => c.anonymous), isTrue,
        reason: 'a request reaches the mailbox only from a connection that '
            'never authenticated');
    for (final c in carriers) {
      expect(c.up.where((f) => f['t'] == 'send').every((f) => f['to'] == introRid),
          isTrue,
          reason: 'the connection that carries a request carries nothing '
              'else — not the requester\'s later envelopes to the account '
              'the handle introduced');
    }
    for (final c in tap.conns) {
      final touches = {
        if (c.authRid != null) c.authRid!,
        for (final f in c.up)
          if (f['t'] == 'send') '${f['to']}',
      };
      expect(touches.containsAll({otto.myRid, introRid}), isFalse,
          reason: 'connection ${c.n} carried both routing ids');
    }
  });

  test('6. pause: paused on lookup, nothing sent; resume: the same mailbox',
      () async {
    final pia = await boot('Pia');
    final ray = await boot('Ray');
    await connected([pia, ray]);
    final draft = await claim(pia, 'pia.66');
    final introRid = pia.handles.own!.introRid;
    expect((await ray.handles.find('pia.66')).state, HandleLookupState.found);

    await pia.handles.pause();
    expect(pia.handles.own!.phase, HandlePhase.paused);
    final record = HandleRecord.decode((await logLeaf(draft.label))!.value!);
    expect(record.intro, isNull);
    expect(record.xintro, isNull);
    expect(record.kind, HandleRecordKind.update);

    final sendsBefore = tap.sendsTo(introRid);
    final paused = await ray.handles.find('pia.66');
    expect(paused.state, HandleLookupState.paused);
    await expectLater(
        ray.handles.request(paused), failsWith(HandleFailure.paused));
    expect(tap.sendsTo(introRid), sendsBefore, reason: 'nothing sent');
    expect(ray.handles.outgoing, isEmpty);

    await pia.handles.resume();
    final again = await ray.handles.find('pia.66');
    expect(again.state, HandleLookupState.found);
    expect(again.introRid, introRid, reason: 'the same mailbox');
    expect(again.version, 3);
    await ray.handles.request(again);
    await receives(pia, ray.myRid);
  });

  test(
      '7. rotate: the new mailbox only; the old one gets nothing new; an old '
      'request is still acknowledged', () async {
    final rosa = await boot('Rosa');
    final abel = await boot('Abel');
    final bart = await boot('Bart');
    await connected([rosa, abel, bart]);
    await claim(rosa, 'rosa.77');
    final oldRid = rosa.handles.own!.introRid;
    await abel.handles.request(await abel.handles.find('rosa.77'));
    await receives(rosa, abel.myRid);
    expect(rosa.handles.inboundFor(abel.myRid)!.introRid, oldRid);

    final connsBefore = tap.conns.length;
    await rosa.handles.rotate();
    final newRid = rosa.handles.own!.introRid;
    expect(newRid, isNot(oldRid));
    final oldSends = tap.sendsTo(oldRid);
    // The old mailbox was read once more, and not re-flagged.
    final lastOld = tap.conns
        .skip(connsBefore)
        .where((c) => c.authRid == oldRid)
        .toList();
    expect(lastOld, isNotEmpty, reason: 'the old mailbox read once more');
    expect(lastOld.expand((c) => c.upTypes), isNot(contains('intro')));

    final found = await bart.handles.find('rosa.77');
    expect(found.introRid, newRid);
    await bart.handles.request(found);
    await receives(rosa, bart.myRid);
    expect(rosa.requestsByRid[bart.myRid]!.via, 'rosa.77');
    expect(tap.sendsTo(oldRid), oldSends, reason: 'nothing new to the old one');
    expect(tap.sendsTo(newRid), greaterThan(0));

    // Abel's request reached the old mailbox; accepting it signs with the
    // key it reached, which is the key Abel resolved.
    await rosa.acceptRequest(abel.myRid);
    await linked(abel, rosa, 'rosa.77');
    expect(await abel.handleViaOf(rosa.myRid), 'rosa.77');
  });

  test(
      '8. recover on a fresh account: the new owner in the log, requests to '
      'it, the old code spent, the old owner told', () async {
    final ada = await boot('Ada');
    final cleo = await boot('Cleo');
    final bo = await boot('Bo');
    final dora = await boot('Dora');
    await connected([ada, cleo, bo, dora]);
    final draft = await claim(ada, 'ada.88');

    final rd = await cleo.handles.prepareRecover('ada.88', draft.code);
    expect(cleo.handles.own, isNull, reason: 'nothing kept before it is published');
    await cleo.handles.commitRecover(rd);
    expect(cleo.handles.own!.phase, HandlePhase.live);
    final leaf = (await logLeaf(draft.label))!;
    final rec = HandleRecord.decode(leaf.value!);
    expect(leaf.version, 2);
    expect(rec.kind, HandleRecordKind.recover);
    expect(rec.owner, await handleKeyPublic(rd.ownerSeed));
    expect(rec.rc, rd.rc);
    expect(rec.rpub,
        (await handleRecoveryKey(draft.recoveryCode, draft.label)).pub);
    await waitUntil(() => cleo.handles.drains >= 1,
        what: 'the recovered mailbox drained');

    await bo.handles.request(await bo.handles.find('ada.88'));
    await receives(cleo, bo.myRid);
    await cleo.acceptRequest(bo.myRid);
    await linked(bo, cleo, 'ada.88');
    expect(await bo.handleViaOf(cleo.myRid), 'ada.88');

    await expectLater(dora.handles.prepareRecover('ada.88', draft.code),
        failsWith(HandleFailure.wrongCode));
    expect((await dora.handles.prepareRecover('ada.88', rd.code)).version, 2,
        reason: 'the code shown at the recovery recovers it');
    await expectLater(
        dora.handles.prepareRecover(
            'ada.88', await (await RecoveryCode.generate()).format()),
        failsWith(HandleFailure.backupCode));
    await expectLater(dora.handles.prepareRecover('ada.88', 'not a code'),
        failsWith(HandleFailure.badCode));

    await ada.handles.refresh();
    expect(ada.handles.own!.phase, HandlePhase.lost);
    await expectLater(ada.handles.pause(), failsWith(HandleFailure.lost));
  });

  test(
      '9. backup and restore keep the handle, re-flag its mailbox, publish '
      'nothing; a pending claim comes back held', () async {
    Future<(File, RecoveryCode)> backup(ChatService s, String name) async {
      final code = await RecoveryCode.generate();
      final file = File(p.join((await tempDir('${name}_zbk')).path, 'b.zbk'));
      final sink = file.openWrite();
      await BackupArchive.export(vault: s.vault, code: code, out: sink);
      await sink.close();
      return (file, code);
    }

    Future<void> lose(ChatService s) async {
      services.remove(s);
      s.dispose();
      await s.transport.stop();
      final dir = s.vault.root;
      await s.vault.db.close();
      dir.deleteSync(recursive: true);
      dir.createSync(recursive: true);
    }

    Future<ChatService> restore(Directory dir, File file, RecoveryCode code,
        String name) async {
      final vault = await Vault.open(rootOverride: dir);
      await Restore.run(
          vault: vault,
          file: file,
          secret: await code.format(),
          kind: (await Restore.identify(file)).kind,
          serverUrl: tap.url);
      final id = await ZIdentity.fromJson(
          (jsonDecode((await vault.kvGet('identity'))!) as Map)
              .cast<String, Object?>());
      final s = await boot(name, id: id, vault: vault);
      s.handles.onForeground(); // the shortened timings: drain soon
      return s;
    }

    final abe = await boot('Abe');
    final ben = await boot('Ben');
    final eli = await boot('Eli');
    await connected([abe, ben, eli]);
    await claim(abe, 'abe.99');
    final introRid = abe.handles.own!.introRid;
    await ben.handles.request(await ben.handles.find('abe.99'));
    await receives(abe, ben.myRid);
    final dir = abe.vault.root;
    final (file, code) = await backup(abe, 'abe');
    final sizeAtBackup = await logSize();
    await lose(abe);

    final connsBefore = tap.conns.length;
    final back = await restore(dir, file, code, 'Abe');
    expect(back.handles.own!.phase, HandlePhase.live);
    expect(back.handles.own!.introRid, introRid);
    expect(back.requestsByRid[ben.myRid]!.via, 'abe.99');
    await connected([back]);
    await waitUntil(() => back.handles.drains >= 1,
        what: 'the restored device draining its mailbox');
    final reflagged = tap.conns
        .skip(connsBefore)
        .where((c) => c.authRid == introRid)
        .expand((c) => c.upTypes);
    expect(reflagged, contains('intro'), reason: 're-registered at the relay');
    expect(await logSize(), sizeAtBackup,
        reason: 'a restore publishes nothing by itself');

    await eli.handles.request(await eli.handles.find('abe.99'));
    await receives(back, eli.myRid);
    await back.acceptRequest(ben.myRid);
    await linked(ben, back, 'abe.99');
    expect(await ben.handleViaOf(back.myRid), 'abe.99');

    // A claim that was waiting to be published when the backup was made.
    final pam = await boot('Pam');
    await connected([pam]);
    pam.handles.claimDelayMin = const Duration(hours: 1);
    pam.handles.claimDelayMax = const Duration(hours: 1);
    final pd = await pam.handles.prepareClaim(Handle.parse('pam.99'), pow: 16);
    await pam.handles.commitClaim(pd);
    final pamDir = pam.vault.root;
    final (pfile, pcode) = await backup(pam, 'pam');
    await lose(pam);
    final pamBack = await restore(pamDir, pfile, pcode, 'Pam');
    expect(pamBack.handles.own!.phase, HandlePhase.held);
    await connected([pamBack]);
    // Its start window is shortened to a tenth of a second: a claim that
    // came back pending would be in the log before this lookup returns.
    expect((await eli.handles.find('pam.99')).state, HandleLookupState.notFound);
    expect(await logLeaf(pd.label), isNull);
    await pamBack.handles.publishHeld();
    expect(pamBack.handles.own!.phase, HandlePhase.live);
    expect((await eli.handles.find('pam.99')).state, HandleLookupState.found);
  });

  test('10. the cap: past 100, the oldest unseen go and a seen request stays',
      () async {
    final cap = await boot('Cap');
    await connected([cap]);
    await claim(cap, 'cap.10');
    final introRid = cap.handles.own!.introRid;
    final xintro = (await handleIntroIdentity(cap.handles.own!.introSeed)).xPub;
    final raw = await rawSender();
    Future<String> one() async {
      final id = await ZIdentity.generate();
      await stamped(raw, introRid,
          await sealedRequest(id, to: introRid, xPub: xintro), 16);
      return id.routingId();
    }

    Future<void> drainAll() async {
      while (await cap.handles.drain() > 0) {}
    }

    final first = [for (var i = 0; i < 3; i++) await one()];
    await drainAll();
    expect(first.every(cap.requestsByRid.containsKey), isTrue);
    await cap.markRequestsSeen();

    final wave = [for (var i = 0; i < 101; i++) await one()];
    await drainAll();
    final held = {
      for (final r in cap.requests)
        if (r.via == 'cap.10') r.rid
    };
    expect(held, hasLength(handleInboundCap));
    expect(held.containsAll(first), isTrue,
        reason: 'the three already seen stay');
    expect(held.intersection(wave.take(4).toSet()), isEmpty,
        reason: 'the four oldest unseen went');
    expect(held.containsAll(wave.skip(4)), isTrue);
    expect(await cap.vault.db.query('requests'), hasLength(handleInboundCap));
    expect(wave.take(4).every((r) => cap.handles.inboundFor(r) == null), isTrue);
  });

  test(
      '11. a linked device neither manages nor drains the mailbox, and sees '
      'the resulting contact by self-sync', () async {
    final phone = await boot('Phone');
    final lia = await boot('Lia');
    await connected([phone, lia]);
    final account = await phone.accountIdentity();
    final devId = await ZIdentity.generate();
    final cert = await account.signDeviceCert(
        deviceEdPub: devId.edPub, deviceXPub: devId.xPub, deviceId: 'laptop');
    final vault = await Vault.open(rootOverride: await tempDir('laptop'));
    await vault.kvPut('identity', jsonEncode(devId.toJson()));
    final enrolled = await AccountIdentity.fromEnrollment(
      accountEdPub: account.accountEdPub,
      accountMlPub: await phone.pqAccountPublic(),
      deviceEdSeed: devId.edSeed,
      deviceXSeed: devId.xSeed,
      deviceId: 'laptop',
      deviceCert: cert,
    );
    await vault.kvPut('account', jsonEncode(enrolled.toJson()));
    await vault.kvPut('my_devices', jsonEncode([account.deviceCert.toJson()]),
        sensitive: false);
    final laptop = await boot('Laptop', id: devId, vault: vault, via: tapB);
    await connected([laptop]);
    await phone.addMyDevice(cert);

    for (final s in [phone, laptop]) {
      s.handles.drainEvery = const Duration(milliseconds: 600);
    }
    laptop.handles.onForeground();
    expect(laptop.handles.canManage, isFalse);
    await expectLater(laptop.handles.prepareClaim(Handle.parse('lap.11')),
        failsWith(HandleFailure.linkedDevice));

    await claim(phone, 'phone.11');
    final introRid = phone.handles.own!.introRid;
    await waitUntil(() => phone.handles.drains >= 3,
        what: 'the phone draining on its timer');
    expect(laptop.handles.drains, 0);
    expect(laptop.handles.own, isNull);
    expect(tapB.conns.where((c) => c.authRid == introRid), isEmpty,
        reason: 'the linked device never connects as the mailbox');
    expect(tapB.conns.expand((c) => c.upTypes), isNot(contains('intro')));

    await lia.handles.request(await lia.handles.find('phone.11'));
    await receives(phone, lia.myRid);
    expect(laptop.requestsByRid.containsKey(lia.myRid), isFalse);
    await phone.acceptRequest(lia.myRid);
    await waitUntil(() => laptop.contacts.containsKey(lia.myRid),
        what: 'the laptop learning the contact by self-sync');
    expect(tapB.conns.where((c) => c.authRid == introRid), isEmpty);
  });

  test(
      '12. no handle log configured: unavailable everywhere; a log off '
      'loopback is never contacted by a test', () async {
    expect(defaultHandleLogUrl, isEmpty, reason: 'this build pins no log');
    expect(defaultHandleLogPub, isEmpty);
    final una = await boot('Una', config: HandleConfig.defaults);
    expect(una.handles.available, isFalse);
    await expectLater(
        una.handles.find('alice.42'), failsWith(HandleFailure.unavailable));
    await expectLater(una.handles.prepareClaim(Handle.parse('una.12')),
        failsWith(HandleFailure.unavailable));
    await expectLater(una.handles.isAvailable(Handle.parse('una.12')),
        failsWith(HandleFailure.unavailable));
    expect(await una.handles.drain(), 0);

    final counting = _CountingFetcher();
    final far = await boot('Far',
        config: HandleConfig(
            logUrl: 'https://handles.example', logPubB64: b64(logPub)),
        fetcher: counting);
    expect(far.handles.available, isFalse);
    await expectLater(
        far.handles.find('alice.42'), failsWith(HandleFailure.unavailable));
    expect(counting.urls, isEmpty);
  });

  test(
      '13. what can never be a handle request is acknowledged and dropped; '
      'the mailbox does not wedge', () async {
    final wren = await boot('Wren');
    await connected([wren]);
    await claim(wren, 'wren.13');
    final introRid = wren.handles.own!.introRid;
    final xintro = (await handleIntroIdentity(wren.handles.own!.introSeed)).xPub;
    final raw = await rawSender();
    final mal = await ZIdentity.generate();
    final other = await (await ZIdentity.generate()).routingId();
    final good = await ZIdentity.generate();
    final junk = [
      // Not sealed to anything: bytes behind the prefix.
      'zs1.${b64url(randomBytes(200))}',
      // Sealed to the mailbox, and not a request.
      await SealedEnvelope.seal(
          toXPub: xintro, fromRid: await mal.routingId(), payload: 'hello?'),
      // A genuine request, addressed to someone else.
      await sealedRequest(mal, to: other, xPub: xintro),
      // A request whose sealed sender is not the identity that signed it.
      await SealedEnvelope.seal(
          toXPub: xintro,
          fromRid: other,
          payload: (await ContactRequest.create(
                  me: mal, toRid: introRid, displayName: 'mal'))
              .encode()),
    ];
    for (final j in junk) {
      await stamped(raw, introRid, j, 16);
    }
    await stamped(
        raw, introRid, await sealedRequest(good, to: introRid, xPub: xintro), 16);
    expect(await wren.handles.drain(), 5,
        reason: 'every envelope decided and acknowledged');
    expect(wren.requests.map((r) => r.rid), [await good.routingId()]);
    expect(wren.requestsByRid.containsKey(await mal.routingId()), isFalse);
    expect(await wren.handles.drain(), 0,
        reason: 'nothing left for the relay to hand over again');
  });
}
