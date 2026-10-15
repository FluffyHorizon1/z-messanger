// A handle's inbox under pressure (phase 38; PROTOCOL §21.6–§21.8; what an
// independent review of handles found on 2026-10-09): what the owner's app
// files from its introduction mailbox, at what difficulty it asks the relay
// to guard it, and what it does when the record in the log is no longer its
// own. Real ChatService instances, the real relay (server/server.js) and the
// real handle log (kt/server.js, KT_MODE=handles), both on loopback; where a
// relay that misbehaves or forgets is the point, a tap between the owner and
// the relay rewrites what it hands on, as the relay itself could.
//
// Criteria, each a test below:
//   1. a wave of 101 stamped requests through a public handle leaves an
//      unseen request made with the person's code pending, its sender still
//      waiting on an answer: handle requests are capped at 100 apart from
//      requests by code or link, and within that cap the oldest unseen goes
//      first (the review's probe P1);
//   2. an envelope and its stamp are filed at most once: the 20 requests
//      the cap pushed out of 120, sent again with their original stamps, are
//      not filed again — nor after the app restarts, the requests it has
//      decided being remembered in the vault (probe P1b) — while stamped
//      junk, which is no request, takes no room there: it is opened and
//      dropped again each time it comes;
//   3. the owner counts each stamp itself: an envelope the relay hands on
//      with no `pow` and `powDay`, with a stamp short of the difficulty,
//      with a `powDay` two days before the relay's day of its `ts`, or with
//      the stamp of another envelope is acknowledged and dropped, never
//      filed and never handed over again, while a request with its own
//      stamp is filed; after a raise, a stamp at the previous difficulty
//      counts for two days and not after — and an honest requester's first
//      send already carries a stamp at the record's new difficulty;
//   4. restoring a backup taken before the difficulty was raised, the first
//      drain flags the mailbox at the published difficulty — a stamp below
//      it is refused by the relay (probe P5);
//   5. restoring a backup taken before a new inbox, the restored device
//      sends no `intro` for the abandoned mailbox, reads nothing from it,
//      and holds the handle as lost with its inbox moved — until the
//      recovery code brings it back on new keys;
//   6. every drain reads the account's own record first: a handle recovered
//      onto another account is found lost by the old owner's next drain —
//      the handle screen never opened — which then neither flags nor reads
//      the mailbox; and a log answering with an older version of the record
//      makes nothing lost and does not lower the flag;
//   7. a relay that answers `intro` with `intro_full` or `rate_limited`
//      leaves the owner told that it is not guarding the inbox, and the
//      drain still reads the mailbox and counts every stamp itself: an
//      unstamped envelope the unguarding relay took is not filed, and an
//      honest request, stamped as the record asks, is.
@Tags(['integration'])
@Timeout(Duration(minutes: 6))
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
import 'package:zapp/core/restore.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:z_protocol/z_protocol.dart';

/// One connection through the tap: what its client sent, and the routing id
/// it authenticated as (null for one that never did).
class _Conn {
  String? authRid;
  final up = <Map<String, Object?>>[];
  List<String> get upTypes => [for (final f in up) '${f['t']}'];
}

/// A WebSocket proxy in front of the relay. It writes down every frame each
/// client sends, and before handing a `msg` frame down it applies whatever
/// rewrite the test registered for that envelope's id — what a relay that
/// lost a flag, or one that lies, could hand on. The Host header goes
/// through unchanged: a client signs its authentication over the address it
/// dialled.
class _Tap {
  _Tap._(this.server);
  final HttpServer server;
  final conns = <_Conn>[];
  final rewrites = <String, Map<String, Object?> Function(Map<String, Object?>)>{};
  String get url => 'ws://127.0.0.1:${server.port}';

  static Future<_Tap> start(int relayPort) async {
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    final tap = _Tap._(server);
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
      final c = _Conn();
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
        final rewrite = f != null && f['t'] == 'msg' ? tap.rewrites[f['id']] : null;
        down.add(rewrite == null ? d : jsonEncode(rewrite(f!)));
      }, onDone: () => down.close(), onError: (_) => down.close());
    });
    return tap;
  }
}

/// The real fetcher, writing down the last answer to each read; once
/// [frozen], it answers every read it has an answer for with that answer —
/// a log showing an older history, which a reader cannot tell from the
/// current one without a witness (R50). Publishes always go through.
class _ReplayFetcher implements KtFetcher {
  final _inner = HttpKtFetcher();
  final _last = <String, KtResponse>{};
  bool frozen = false;

  Future<KtResponse> _read(String key, Future<KtResponse> Function() ask) async {
    final kept = _last[key];
    if (frozen && kept != null) return kept;
    final r = await ask();
    if (!frozen) _last[key] = r;
    return r;
  }

  @override
  Future<KtResponse> get(Uri url) => _read('GET $url', () => _inner.get(url));

  @override
  Future<KtResponse> post(Uri url, String jsonBody) =>
      url.path.endsWith('/publish')
          ? _inner.post(url, jsonBody)
          : _read('POST $url $jsonBody', () => _inner.post(url, jsonBody));
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  final root = Directory.current.parent.path;
  late int relayPort;
  late Process log;
  late int logPort;
  late Uint8List logPub;
  late _Tap tap;
  final logSeed =
      Uint8List.fromList(List<int>.generate(32, (i) => (i * 7 + 29) & 0xff));
  final temps = <Directory>[];
  final services = <ChatService>[];
  final raws = <RelayClient>[];
  final relays = <Process>[];

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

  /// A relay of this file's own. New flags and `intro` frames are paced far
  /// above anything these tests do, so every mailbox they claim is flagged,
  /// unless [env] says otherwise (criterion 7 starts one that will not).
  Future<(Process, int)> startRelay(Map<String, String> env) async {
    final port = await freePort();
    final r = await Process.start('node', ['server.js'],
        workingDirectory: '$root${Platform.pathSeparator}server',
        environment: {
          'PORT': '$port',
          'LOG_LEVEL': 'silent',
          'INTRO_NEW_PER_IP_PER_MIN': '100000',
          'INTRO_PER_RID_PER_MIN': '100000',
          ...env,
        });
    r.stdout.drain<void>();
    r.stderr.drain<void>();
    relays.add(r);
    await healthy(port, 'a relay');
    return (r, port);
  }

  setUpAll(() async {
    (_, relayPort) = await startRelay(const {});
    logPort = await freePort();
    log = await Process.start('node', ['server.js'],
        workingDirectory: '$root${Platform.pathSeparator}kt',
        environment: {
          'KT_MODE': 'handles',
          'KT_SEED': [for (final b in logSeed) b.toRadixString(16).padLeft(2, '0')]
              .join(),
          'KT_EPHEMERAL': '1',
          'KT_PORT': '$logPort',
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
    tap = await _Tap.start(relayPort);
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
    for (final r in relays) {
      r.kill();
    }
    log.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  HandleConfig honest() => HandleConfig(
      logUrl: 'http://127.0.0.1:$logPort', logPubB64: b64(logPub));

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

  Future<Directory> tempDir(String name) async {
    final d = await Directory.systemTemp.createTemp('z_inbox_$name');
    temps.add(d);
    return d;
  }

  /// §21.8's timings, shortened: a claim publishes within half a second, and
  /// the periodic drain is out of the way — the tests drain when they need.
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
      String? relayUrl,
      KtFetcher? fetcher}) async {
    final v = vault ?? await Vault.open(rootOverride: await tempDir(name));
    final identity = id ?? await ZIdentity.generate();
    if (vault == null) {
      await v.kvPut('identity', jsonEncode(identity.toJson()));
    }
    final svc = await ChatService.init(
        vault: v,
        identity: identity,
        displayName: name,
        transport: Transport(identity: identity, serverUrl: relayUrl ?? tap.url),
        ktConfig: KtConfig.off,
        handleConfig: honest(),
        handleFetcher: fetcher);
    fast(svc);
    services.add(svc);
    return svc;
  }

  Future<void> connected(List<ChatService> ss) => waitUntil(
      () => ss.every(
          (s) => s.transport.isConnected && s.transport.isSenderConnected),
      what: '${ss.map((s) => s.displayName).join(', ')} connected');

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

  Future<void> drainAll(ChatService s) async {
    while (await s.handles.drain() > 0) {}
  }

  Future<RelayClient> rawSender([String? url]) async {
    final c = await RelayClient.connectAnonymous(
        url ?? 'ws://127.0.0.1:$relayPort', await ZIdentity.generate());
    raws.add(c);
    return c;
  }

  /// A contact request from a fresh identity to the mailbox [introRid],
  /// sealed to [xPub]: what anybody who resolves the handle can build.
  Future<(String rid, String payload)> stranger(
      String introRid, Uint8List xPub, String name) async {
    final id = await ZIdentity.generate();
    final creq =
        await ContactRequest.create(me: id, toRid: introRid, displayName: name);
    final payload = await SealedEnvelope.seal(
        toXPub: xPub, fromRid: await id.routingId(), payload: creq.encode());
    return (await id.routingId(), payload);
  }

  int today() => introPowDay(DateTime.now().millisecondsSinceEpoch);

  /// Every connection through the tap that authenticated has its routing
  /// id worked out (the tap hashes the key the client sent).
  bool named() => tap.conns
      .every((c) => !c.upTypes.contains('auth') || c.authRid != null);

  /// A stamp of at least [bits] for [payload] to [introRid] on [day].
  String stampFor(String introRid, String payload, int bits, {int? day}) =>
      b64url(createIntroPowStamp(
          introRid: introRid,
          day: day ?? today(),
          envelope: utf8.encode(payload),
          bits: bits));

  /// A stamp for [payload] that reaches [atLeast] bits and not [below].
  Future<String> stampBetween(
      String introRid, String payload, int atLeast, int below,
      {int? day}) async {
    final d = day ?? today();
    while (true) {
      final n = createIntroPowStamp(
          introRid: introRid,
          day: d,
          envelope: utf8.encode(payload),
          bits: atLeast);
      if (!await verifyIntroPowStamp(
          introRid: introRid,
          day: d,
          envelope: utf8.encode(payload),
          nonce: n,
          bits: below)) {
        return b64url(n);
      }
    }
  }

  /// [payload] sent to [introRid] with a stamp for the relay's day; the
  /// envelope id is returned.
  Future<String> sendStamped(
      RelayClient c, String introRid, String payload, int bits) async {
    final id = newMessageId();
    try {
      await c.send(
          to: introRid,
          id: id,
          payload: payload,
          pow: stampFor(introRid, payload, bits));
    } on RelayPowRequired catch (e) {
      await c.send(
          to: introRid,
          id: id,
          payload: payload,
          pow: stampFor(introRid, payload, bits, day: e.day));
    }
    return id;
  }

  Future<(File, RecoveryCode)> backup(ChatService s, String name) async {
    final code = await RecoveryCode.generate();
    final file = File(p.join((await tempDir('${name}_zbk')).path, 'b.zbk'));
    final sink = file.openWrite();
    await BackupArchive.export(vault: s.vault, code: code, out: sink);
    await sink.close();
    return (file, code);
  }

  /// The phone is lost: its service stops and its vault is emptied.
  Future<Directory> lose(ChatService s) async {
    services.remove(s);
    s.dispose();
    await s.transport.stop();
    final dir = s.vault.root;
    await s.vault.db.close();
    dir.deleteSync(recursive: true);
    dir.createSync(recursive: true);
    return dir;
  }

  /// [file] restored onto a new phone in [dir], and the app started there.
  Future<ChatService> restore(
      Directory dir, File file, RecoveryCode code, String name) async {
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
    await connected([s]);
    return s;
  }

  // ---------------------------------------------------------------------------

  test('1. a wave through the handle leaves a request made with the code',
      () async {
    final bob = await boot('Bob');
    final alice = await boot('Alice');
    await connected([bob, alice]);
    await claim(bob, 'bobinbox.21');

    // Alice had Bob's code: her request waits, unseen.
    await alice.addContactFromCode(await bob.myContactCode());
    await waitUntil(() => bob.requestsByRid.containsKey(alice.myRid),
        what: 'Alice\'s request by code pending at Bob');
    expect(bob.debugRequestSeen(alice.myRid), isFalse);
    expect(bob.requestsByRid[alice.myRid]!.via, isNull);

    // The wave: 101 throwaway identities through the public handle.
    final own = bob.handles.own!;
    final xPub = (await handleIntroIdentity(own.introSeed)).xPub;
    final raw = await rawSender();
    final wave = <String>[];
    for (var i = 0; i < 101; i++) {
      final (rid, payload) = await stranger(own.introRid, xPub, 'wave $i');
      wave.add(rid);
      await sendStamped(raw, own.introRid, payload, own.pow);
    }
    await drainAll(bob);

    expect(bob.requestsByRid.containsKey(alice.myRid), isTrue,
        reason: 'strangers writing to a public handle cannot push out an '
            'unseen request from someone who had the code');
    expect(alice.contacts[bob.myRid]?.requested, isTrue,
        reason: 'and Alice is still waiting on an answer that can come');
    final viaHandle = {
      for (final r in bob.requests)
        if (r.via == 'bobinbox.21') r.rid
    };
    expect(viaHandle, hasLength(100),
        reason: 'a hundred through the handle, counted apart');
    expect(viaHandle.contains(wave.first), isFalse,
        reason: 'the oldest unseen of the wave went');
    expect(viaHandle.containsAll(wave.skip(1)), isTrue);
    expect(bob.requests, hasLength(101));
  });

  test('2. an envelope and its stamp are filed once, after a restart too',
      () async {
    final owen = await boot('Owen');
    await connected([owen]);
    await claim(owen, 'oweninbox.21');
    final own = owen.handles.own!;
    final xPub = (await handleIntroIdentity(own.introSeed)).xPub;
    final raw = await rawSender();

    // Stamped requests, made once: the envelopes and stamps are kept.
    Future<List<(String rid, String payload, String pow)>> make(
        int n, String name) async {
      final made = <(String, String, String)>[];
      for (var i = 0; i < n; i++) {
        final (rid, payload) = await stranger(own.introRid, xPub, '$name $i');
        made.add((rid, payload, stampFor(own.introRid, payload, own.pow)));
      }
      return made;
    }

    Future<void> sendAll(Iterable<(String, String, String)> xs) async {
      for (final (_, payload, pow) in xs) {
        await raw.send(
            to: own.introRid, id: newMessageId(), payload: payload, pow: pow);
      }
    }

    Future<ChatService> restart(ChatService s, String name) async {
      final vault = s.vault;
      final id = s.identity;
      services.remove(s);
      s.dispose();
      await s.transport.stop();
      final back = await boot(name, id: id, vault: vault);
      await connected([back]);
      return back;
    }

    final made = await make(120, 'cycle');
    await sendAll(made);
    await drainAll(owen);
    final evicted = [
      for (final m in made)
        if (!owen.requestsByRid.containsKey(m.$1)) m
    ];
    expect(evicted, hasLength(20), reason: 'the cap kept a hundred');

    // The same envelopes and stamps again: no new work.
    await sendAll(evicted);
    await drainAll(owen);
    expect(evicted.where((m) => owen.requestsByRid.containsKey(m.$1)), isEmpty,
        reason: 'a stamp counts once: what the cap pushed out stays out');
    expect(owen.handles.droppedReplays, 20,
        reason: 'each known before it was opened');

    // The app restarts — the ledger written whole at the first request, the
    // 119 after it in the small record beside it — and the same envelopes
    // come once more.
    final again = await restart(owen, 'Owen again');
    await sendAll(evicted);
    await drainAll(again);
    expect(again.requests, hasLength(100));
    expect(evicted.where((m) => again.requestsByRid.containsKey(m.$1)), isEmpty,
        reason: 'what the drain decided is remembered in the vault');
    expect(again.handles.droppedReplays, 20);

    // Written whole every 4 from now: ten more cross it twice, and two wait
    // in the small record when the app restarts again.
    again.handles.stampJournalMax = 4;
    final more = await make(10, 'more');
    await sendAll(more);
    await drainAll(again);
    expect(more.every((m) => again.requestsByRid.containsKey(m.$1)), isTrue);
    final third = await restart(again, 'Owen third');
    await sendAll(more);
    await drainAll(third);
    expect(third.handles.droppedReplays, 10,
        reason: 'from the ledger and the record beside it, before opening');

    // Stamped junk takes no room in the ledger: it is decided again, and
    // dropped again, every time it comes.
    final junk = 'zs1.${'x' * 64}'; // sealed in form only: it opens to nothing
    for (var i = 0; i < 2; i++) {
      await raw.send(
          to: own.introRid,
          id: newMessageId(),
          payload: junk,
          pow: stampFor(own.introRid, junk, own.pow));
      expect(await third.handles.drain(), 1);
    }
    expect(third.handles.droppedReplays, 10, reason: 'junk is not a replay');
  });

  test('3. the owner counts each stamp itself', () async {
    final olga = await boot('Olga');
    await connected([olga]);
    await claim(olga, 'olgainbox.21');
    final own = olga.handles.own!;
    final xPub = (await handleIntroIdentity(own.introSeed)).xPub;
    final raw = await rawSender();

    Future<(String rid, String id, String payload)> sent(String name) async {
      final (rid, payload) = await stranger(own.introRid, xPub, name);
      final id = await sendStamped(raw, own.introRid, payload, own.pow);
      return (rid, id, payload);
    }

    // What a relay that lost the flag, or one that lies, could hand on.
    final (bare, bareId, _) = await sent('no stamp');
    tap.rewrites[bareId] = (f) => {...f}
      ..remove('pow')
      ..remove('powDay');
    final (weak, weakId, weakPayload) = await sent('weak stamp');
    final weakStamp = await stampBetween(own.introRid, weakPayload, 0, own.pow);
    tap.rewrites[weakId] = (f) => {...f, 'pow': weakStamp};
    final (old, oldId, oldPayload) = await sent('old day');
    final oldDay = today() - 2;
    final oldStamp = stampFor(own.introRid, oldPayload, own.pow, day: oldDay);
    tap.rewrites[oldId] = (f) => {...f, 'pow': oldStamp, 'powDay': oldDay};
    final (other, otherId, _) = await sent('another envelope\'s stamp');
    final (_, borrowed) = await stranger(own.introRid, xPub, 'lender');
    final lent = stampFor(own.introRid, borrowed, own.pow);
    tap.rewrites[otherId] = (f) => {...f, 'pow': lent, 'powDay': today()};
    final (good, _, _) = await sent('its own stamp');

    await drainAll(olga);
    expect(olga.requestsByRid.containsKey(good), isTrue,
        reason: 'a request with its own stamp is filed');
    for (final (rid, what) in [
      (bare, 'no stamp'),
      (weak, 'a stamp short of the difficulty'),
      (old, 'a stamp for a day the relay could not have taken it on'),
      (other, 'another envelope\'s stamp'),
    ]) {
      expect(olga.requestsByRid.containsKey(rid), isFalse,
          reason: 'never filed: $what');
    }
    expect(await olga.handles.drain(), 0,
        reason: 'each was acknowledged and dropped, not handed over again');

    // A raise: what the relay took at the old difficulty still counts for
    // two days. The tap hands a stamp of 16 or 17 bits on with each.
    final (early, earlyId, earlyPayload) = await sent('just before the raise');
    final early16 = await stampBetween(own.introRid, earlyPayload, 16, 18);
    tap.rewrites[earlyId] = (f) => {...f, 'pow': early16, 'powDay': today()};
    await olga.handles.setDifficulty(18);
    await waitUntil(() async {
      await olga.handles.drain();
      return olga.requestsByRid.containsKey(early);
    }, what: 'the stamp made for the old difficulty counted');

    // An honest requester stamps at the record's difficulty on the first
    // send, not only after a refusal.
    final rex = await boot('Rex');
    await connected([rex]);
    final sendsBefore = [
      for (final c in tap.conns)
        for (final f in c.up)
          if (f['t'] == 'send' && f['to'] == own.introRid) f
    ].length;
    await rex.handles.request(await rex.handles.find('olgainbox.21'));
    final sends = [
      for (final c in tap.conns)
        for (final f in c.up)
          if (f['t'] == 'send' && f['to'] == own.introRid) f
    ].skip(sendsBefore).toList();
    expect(sends, hasLength(1), reason: 'taken at once: no second try');
    expect(
        await verifyIntroPowStamp(
            introRid: own.introRid,
            day: today(),
            envelope: utf8.encode(sends.single['payload'] as String),
            nonce: unb64url(sends.single['pow'] as String),
            bits: 18),
        isTrue,
        reason: 'the first send carries the record\'s difficulty');
    await waitUntil(() async {
      await olga.handles.drain();
      return olga.requestsByRid.containsKey(rex.myRid);
    }, what: 'Rex\'s request filed');

    // Three days on, by this phone's clock, it does not.
    final realNow = olga.handles.now;
    olga.handles.now = () => realNow() + const Duration(days: 3).inMilliseconds;
    final (tardy, tardyId, tardyPayload) = await sent('after the grace');
    final tardy16 = await stampBetween(own.introRid, tardyPayload, 16, 18);
    tap.rewrites[tardyId] = (f) => {...f, 'pow': tardy16, 'powDay': today()};
    await drainAll(olga);
    expect(olga.requestsByRid.containsKey(tardy), isFalse,
        reason: 'two days after the raise, the old difficulty is not enough');
    olga.handles.now = realNow;
  });

  test('4. a restore of an older backup flags at the published difficulty',
      () async {
    final hal = await boot('Hal');
    await connected([hal]);
    await claim(hal, 'halinbox.21', pow: 16);
    final introRid = hal.handles.own!.introRid;
    final xPub = (await handleIntroIdentity(hal.handles.own!.introSeed)).xPub;
    final (file, code) = await backup(hal, 'hal');

    // Later the owner raises the difficulty, and the relay is told.
    await hal.handles.setDifficulty(22);
    await waitUntil(() async {
      await hal.handles.drain();
      return hal.handles.drains >= 2;
    }, what: 're-flagged at 22');
    final raw = await rawSender();
    Future<String> sixteenBits() async {
      final (_, payload) = await stranger(introRid, xPub, 'cheap');
      try {
        await raw.send(
            to: introRid,
            id: newMessageId(),
            payload: payload,
            pow: await stampBetween(introRid, payload, 16, 22));
        return 'sent';
      } on RelayPowRequired catch (e) {
        return 'pow_required(${e.bits})';
      }
    }

    expect(await sixteenBits(), 'pow_required(22)');

    // The phone is lost; the older backup comes back on a new one.
    final dir = await lose(hal);
    final back = await restore(dir, file, code, 'Hal back');
    expect(back.handles.own!.pow, 16, reason: 'what the backup held');
    await back.handles.drain(); // what the app does 3–30 s after it opens
    expect(await sixteenBits(), 'pow_required(22)',
        reason: 'the relay must not be told less work than the record asks');
    expect(back.handles.own!.pow, 22, reason: 'the record was read');
  });

  test('5. a restore from before a new inbox leaves the abandoned one alone',
      () async {
    final ivy = await boot('Ivy');
    await connected([ivy]);
    final draft = await claim(ivy, 'ivyinbox.21');
    final oldIntro = ivy.handles.own!.introRid;
    final (file, code) = await backup(ivy, 'ivy');
    await ivy.handles.rotate();
    expect(ivy.handles.own!.introRid, isNot(oldIntro));

    final dir = await lose(ivy);
    final connsBefore = tap.conns.length;
    final back = await restore(dir, file, code, 'Ivy back');
    expect(back.handles.own!.introRid, oldIntro, reason: 'what the backup held');
    await back.handles.drain();
    await waitUntil(named, what: 'every connection through the tap named');
    final fromOld = tap.conns
        .skip(connsBefore)
        .where((c) => c.authRid == oldIntro)
        .expand((c) => c.upTypes);
    expect(fromOld, isNot(contains('intro')),
        reason: 'the abandoned mailbox is not flagged again');
    expect(back.handles.own!.phase, HandlePhase.lost);
    expect(back.handles.own!.problem, 'introUnknown',
        reason: 'lost because the inbox moved, not to another owner');

    // The recovery code brings it back here, on new keys.
    final d = await back.handles.prepareRecover('ivyinbox.21', draft.code);
    await back.handles.commitRecover(d);
    expect(back.handles.own!.phase, HandlePhase.live);
    expect(back.handles.own!.introRid, isNot(oldIntro));
  });

  test('6. every drain reads the record: lost when recovered elsewhere, not '
      'when the log answers with an older version', () async {
    final jo = await boot('Jo');
    final rico = await boot('Rico');
    await connected([jo, rico]);
    final draft = await claim(jo, 'joinbox.21');
    final joIntro = jo.handles.own!.introRid;

    // The code is used on another account.
    final rd = await rico.handles.prepareRecover('joinbox.21', draft.code);
    await rico.handles.commitRecover(rd);

    // Jo's handle screen is never opened; her next drain reads the record.
    final connsBefore = tap.conns.length;
    expect(await jo.handles.drain(), 0);
    expect(jo.handles.own!.phase, HandlePhase.lost);
    expect(jo.handles.own!.problem, isNull, reason: 'another owner');
    await waitUntil(named, what: 'every connection through the tap named');
    expect(
        tap.conns.skip(connsBefore).where((c) => c.authRid == joIntro), isEmpty,
        reason: 'the mailbox is neither flagged nor read');

    // A log that answers with an older version of a record is not news.
    final replay = _ReplayFetcher();
    final kim = await boot('Kim', fetcher: replay);
    await connected([kim]);
    await claim(kim, 'kiminbox.21', pow: 16);
    replay.frozen = true; // from now on, the answers of version 1
    await kim.handles.setDifficulty(20);
    expect(kim.handles.own!.version, 2);
    await kim.handles.drain();
    expect(kim.handles.own!.phase, HandlePhase.live,
        reason: 'an older record says nothing new about the owner');
    final raw = await rawSender();
    final introRid = kim.handles.own!.introRid;
    final xPub = (await handleIntroIdentity(kim.handles.own!.introSeed)).xPub;
    final (_, payload) = await stranger(introRid, xPub, 'cheap');
    Object? refused;
    try {
      await raw.send(
          to: introRid,
          id: newMessageId(),
          payload: payload,
          pow: await stampBetween(introRid, payload, 16, 20));
    } on RelayPowRequired catch (e) {
      refused = e.bits;
    }
    expect(refused, 20, reason: 'the flag was not lowered to version 1\'s');
  });

  test('7. a relay that will not guard the inbox: the owner is told when it '
      'says so, and still counts every stamp', () async {
    final (_, port) = await startRelay(
        {'INTRO_CAP': '1', 'INTRO_PER_RID_PER_MIN': '2'});
    final url = 'ws://127.0.0.1:$port';
    final ann = await boot('Ann', relayUrl: url);
    final ben = await boot('Ben', relayUrl: url);
    await connected([ann, ben]);
    await claim(ann, 'anninbox.21'); // the one flag this relay holds
    expect(ann.handles.relayUnguarded, isFalse);
    // A full relay takes a new flag by forgetting the one least recently
    // renewed — it no longer answers `intro_full` — and tells nobody: Ann's
    // app still holds the `intro_ok` of her last drain.
    await claim(ben, 'beninbox.21');
    expect(ben.handles.relayUnguarded, isFalse,
        reason: 'a full relay takes the new flag rather than refuse it');
    expect(ann.handles.relayUnguarded, isFalse);

    // Forgotten, Ann's mailbox takes a send without a stamp.
    final own = ann.handles.own!;
    final xPub = (await handleIntroIdentity(own.introSeed)).xPub;
    final raw = await rawSender(url);
    final (rid, payload) = await stranger(own.introRid, xPub, 'free');
    await raw.send(to: own.introRid, id: newMessageId(), payload: payload);
    await drainAll(ann);
    expect(ann.requestsByRid.containsKey(rid), isFalse,
        reason: 'the drain still counts the work, and there is none');

    // Ann's frames are paced: the third in a minute is refused, and said.
    await ann.handles.drain();
    await ann.handles.drain();
    expect(ann.handles.relayUnguarded, isTrue,
        reason: 'a relay pacing the frame has not said it guards the inbox');

    // An honest request loses nothing: its stamp, made at the record's
    // difficulty, travels with it to a mailbox the relay holds no flag for.
    final cal = await boot('Cal', relayUrl: url);
    await connected([cal]);
    await cal.handles.request(await cal.handles.find('beninbox.21'));
    await waitUntil(() async {
      await ben.handles.drain();
      return ben.requestsByRid.containsKey(cal.myRid);
    }, what: 'Cal\'s stamped request filed from the unguarded mailbox');
  });
}
