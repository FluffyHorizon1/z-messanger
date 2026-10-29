// 44.4 — the app links a device by pairing v3 (PROTOCOL §10.2, ADR 0033 §3),
// and the ceremony leaves nothing on the relay.
//
// Until this release the app linked by pairing v2 (§10.1): two X25519
// ephemerals were the whole of the channel, so a recording of the rendezvous
// would give the account's whole contact list — keys, device lists, names,
// who was verified — to whoever later breaks X25519, and the new device's
// sealing key was attested only afterwards, over self-sync. And neither side
// acknowledged a frame, so each ceremony's four frames, the enrolment among
// them, stayed in relay RAM for QUEUE_TTL_HOURS (72); the upgrade rehearsal
// measured about 37 KB a link.
//
// Real `ChatService`s through a real relay on loopback. The existing device
// is `ChatService.hostDeviceLink`; the new device is `NewDeviceLink`, what
// the link screen runs, installed by `installEnrollment` as the screen
// installs it. A device on an older version is a test seam that runs the
// older ceremony (`NewDeviceLink.createAsVersion2`, `debugPairAsVersion2`),
// or the library's v1 runner.
//
// Criteria, each a test below:
//   1. a laptop linked by v3 is linked: both screens show one eight-digit
//      string, its certificate verifies under the account key, the account's
//      list names it and verifies, its `pqdc` verifies under the account's
//      ML-DSA key and is held — in the vault before its first start, which
//      draws no other sealing key — and messages flow to and from it; and
//      once everyone has gone quiet the relay holds what it held before
//      the ceremony, its four mailboxes empty;
//   2. the frames on the wire are the sizes §10.2 states: `commit-v3` 1 656
//      bytes, `reply-v3` 1 530, `open-v3` 246 for the app's twelve-character
//      device id, and `enroll-v3` the same account's `enroll-v2` with
//      `pqdc`'s 3 309 bytes more before encoding — 4 422 in the sealed
//      enrolment — beside v2's `commit-v2` of 68 and `reply-v2` of 70;
//   3. an existing device of this build meeting a new device on an older
//      version — v2's initiator, and v1's — says which version it heard and
//      which device to update, shows no digits, answers nothing and links
//      nothing;
//   4. a new device of this build meeting an existing device of the version
//      before (v2) hears nothing, says the device it is linking from may be
//      older, and keeps its code; neither side links anything;
//   5. a wrong digit comparison stops the side that makes it: an existing
//      device whose person says the digits differ sends no enrolment and
//      links nothing, and a new device whose person says so installs
//      nothing — and a spent attempt leaves the new device a new code;
//   6. an enrolment carrying the account root is refused: the link fails,
//      and the screen says so;
//   7. an enrolment whose `pqdc` does not verify is refused — the `pqdc`,
//      not the link: the laptop installs its account and holds no `pqdc`,
//      then asks its root over self-sync and holds one that verifies;
//   8. the words: each screen says which device to update, in English and
//      in Spanish, and anything else that stops a link is a failure.
@Tags(['integration'])
@Timeout(Duration(minutes: 5))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/enrollment.dart';
import 'package:zapp/core/key_transparency.dart';
import 'package:zapp/core/receipts.dart';
import 'package:zapp/core/relay_url.dart';
import 'package:zapp/core/sealing_keys.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/app_localizations_en.dart';
import 'package:zapp/l10n/app_localizations_es.dart';
import 'package:zapp/l10n/pairing_text.dart';

typedef Person = ({
  ChatService svc,
  Vault vault,
  Directory dir,
  ZIdentity id,
  String name,
});

/// A front before the relay that passes every frame through, both ways,
/// and keeps the payload of each pairing frame — what the relay carries —
/// by its kind (`k`).
class Recorder {
  final HttpServer _server;
  final frames = <String, List<String>>{};
  Recorder._(this._server);

  String get url => 'ws://127.0.0.1:${_server.port}';

  static Future<Recorder> start(String relayUrl) async {
    final r =
        Recorder._(await HttpServer.bind(InternetAddress.loopbackIPv4, 0));
    r._server.listen((req) async {
      final down = await WebSocketTransformer.upgrade(req);
      // The Host header passes through, so the relay checks each
      // authentication against the address the client dialled.
      final up = await WebSocket.connect(relayUrl,
          headers: {'host': req.headers.value('host') ?? ''});
      down.listen((d) {
        r._note(d, 'send');
        up.add(d);
      }, onDone: () => up.close(), onError: (Object _) => up.close());
      up.listen((d) {
        r._note(d, 'msg');
        down.add(d);
      }, onDone: () => down.close(), onError: (Object _) => down.close());
    });
    return r;
  }

  void _note(Object? data, String t) {
    if (data is! String) return;
    try {
      final f = jsonDecode(data);
      if (f is! Map || f['t'] != t || f['payload'] is! String) return;
      final payload = f['payload'] as String;
      final k = (jsonDecode(payload) as Map)['k'];
      if (k is String) (frames[k] ??= []).add(payload);
    } catch (_) {}
  }

  Future<void> close() => _server.close(force: true);
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  late Process relay;
  late int port;
  final temps = <Directory>[];
  final live = <Person>[];
  final en = AppLocalizationsEn();
  final es = AppLocalizationsEs();
  const metricsToken = 'z-apptest-metrics';

  setUpAll(() async {
    HttpOverrides.global = null;
    final serverDir =
        '${Directory.current.parent.path}${Platform.pathSeparator}server';
    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    port = probe.port;
    await probe.close();
    relay = await Process.start('node', ['server.js'],
        workingDirectory: serverDir,
        environment: {
          'PORT': '$port',
          'LOG_LEVEL': 'silent',
          'METRICS_TOKEN': metricsToken,
        });
    relay.stdout.drain<void>();
    relay.stderr.drain<void>();
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
    fail('relay did not start');
  });

  // Every service a test started is stopped when it ends, so nothing one
  // test left running speaks into the next.
  tearDown(() async {
    for (final x in live) {
      x.svc.dispose();
      await x.svc.transport.stop();
    }
    live.clear();
  });

  tearDownAll(() async {
    relay.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  String relayUrl() => 'ws://127.0.0.1:$port';

  Future<Directory> tempDir(String name) async {
    final d = await Directory.systemTemp.createTemp('z_ppq_$name');
    temps.add(d);
    return d;
  }

  /// A service over the vault in [dir], whose identity is the one the vault
  /// holds. The log is off: what is under test is not the log. Receipts
  /// leave within a second, so a relay that has gone quiet does so soon.
  Future<Person> boot(Directory dir, String name, {Vault? vault}) async {
    final v = vault ?? await Vault.open(rootOverride: dir);
    final id = await ZIdentity.fromJson(
        (jsonDecode((await v.kvGet('identity'))!) as Map)
            .cast<String, Object?>());
    final svc = await ChatService.init(
        vault: v,
        identity: id,
        displayName: await v.kvGet('display_name') ?? name,
        transport: Transport(identity: id, serverUrl: relayUrl()),
        ktConfig: KtConfig.off,
        receiptTiming: const ReceiptTiming(
            floor: Duration(milliseconds: 100),
            ceiling: Duration(milliseconds: 600)));
    // The production delay is hours; what is under test is not the delay.
    svc.pqListDelay = const Duration(milliseconds: 150);
    final x = (svc: svc, vault: v, dir: dir, id: id, name: name);
    live.add(x);
    return x;
  }

  Future<Person> person(String name) async {
    final dir = await tempDir(name);
    final vault = await Vault.open(rootOverride: dir);
    await vault.kvPut(
        'identity', jsonEncode((await ZIdentity.generate()).toJson()));
    await vault.kvPut('display_name', name);
    return boot(dir, name, vault: vault);
  }

  Future<void> waitUntil(bool Function() cond,
      {Duration timeout = const Duration(seconds: 45),
      required String what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  Future<void> waitFor(Future<bool> Function() cond,
      {Duration timeout = const Duration(seconds: 45),
      required String what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 60));
    }
  }

  Future<void> connected(List<Person> people) => waitUntil(
      () => people.every((x) => x.svc.transport.isConnected),
      what: 'everyone connected to the relay');

  /// [body] is in [x]'s chat [rid].
  Future<void> arrived(Person x, String rid, String body) => waitUntil(
      () => (x.svc.messagesByChat[rid] ?? []).any((m) => m.body == body),
      what: '"$body" in ${x.name}\'s chat with $rid');

  /// [a] and [b] scan each other's codes and speak both ways, and their
  /// post-quantum keys have landed.
  Future<void> pairUp(Person a, Person b) async {
    await connected([a, b]);
    await a.svc.addContactFromCode(await b.svc.myContactCode());
    await b.svc.addContactFromCode(await a.svc.myContactCode());
    await a.svc.sendText(b.svc.myRid, 'hi ${b.name}');
    await arrived(b, a.svc.myRid, 'hi ${b.name}');
    await b.svc.sendText(a.svc.myRid, 'hi ${a.name}');
    await arrived(a, b.svc.myRid, 'hi ${a.name}');
    await waitUntil(
        () =>
            a.svc.contacts[b.svc.myRid]?.numberKey != null &&
            b.svc.contacts[a.svc.myRid]?.numberKey != null &&
            !a.svc.pqSendPending &&
            !b.svc.pqSendPending,
        what: 'both post-quantum keys landed and the exchange went quiet');
  }

  /// What the relay holds: (envelopes queued, the bytes they are charged
  /// at), from its own gauges on `/metrics`, which is token-gated (P1-14).
  Future<(int, int)> held() async {
    final req =
        await HttpClient().getUrl(Uri.parse('http://127.0.0.1:$port/metrics'));
    req.headers.set('authorization', 'Bearer $metricsToken');
    final res = await req.close();
    final body = await res.transform(utf8.decoder).join();
    if (res.statusCode != 200) {
      throw StateError('/metrics answered HTTP ${res.statusCode}');
    }
    int gauge(String name) => int.parse(
        RegExp('^$name (\\d+)\$', multiLine: true).firstMatch(body)!.group(1)!);
    return (gauge('z_queued_envelopes'), gauge('z_store_bytes'));
  }

  /// Everything left in [who]'s mailbox, read without acknowledging it. A
  /// marker is posted behind whatever the mailbox holds, and the mailbox is
  /// read until the marker arrives: the relay flushes a mailbox in the order
  /// it was filled, so by then everything queued before it has arrived too.
  /// Only the marker is acknowledged, and its poster stays until the relay
  /// says so, so the look itself leaves nothing behind.
  Future<List<RelayInbound>> peek(ZIdentity who) async {
    final marker = 'z-peek-${b64url(randomBytes(9))}';
    final poster = await RelayClient.connect(relayUrl(), await ZIdentity.generate());
    final receipt = poster.delivered.firstWhere((r) => r.id == marker);
    await poster.send(to: await who.routingId(), id: marker, payload: '{}');
    final c = await RelayClient.connect(relayUrl(), who);
    final got = <RelayInbound>[];
    final sub = c.messages.listen(got.add);
    try {
      await waitUntil(() => got.any((e) => e.id == marker),
          what: 'the marker posted behind what the mailbox holds');
      final m = got.firstWhere((e) => e.id == marker);
      c.ackReceived(id: m.id, from: m.from);
      await receipt.timeout(const Duration(seconds: 10));
    } finally {
      await sub.cancel();
      await c.close();
      await poster.close();
    }
    return [
      for (final e in got)
        if (!e.id.startsWith('z-peek-')) e
    ];
  }

  /// The four mailboxes a ceremony on [code] can leave anything in: v3's
  /// two, and the older ones the existing device listens on.
  Future<List<ZIdentity>> ceremonyMailboxes(PairingCode code) async => [
        await RelayPairing.relayIdentityV3(code, 'i'),
        await RelayPairing.relayIdentityV3(code, 'r'),
        await RelayPairing.relayIdentityV2(code, 'r'),
        await RelayPairing.relayIdentity(code, 'r'),
      ];

  /// A fresh vault for a new device, holding [result] as the link screen
  /// installs it: the relay address, then the enrolment with the sealing key
  /// the ceremony ran with.
  Future<(Directory, Vault)> installed(
      String name, PairingResult result, NewDeviceLink n) async {
    final dir = await tempDir(name);
    final vault = await Vault.open(rootOverride: dir);
    await setRelayUrl(vault, relayUrl(), acceptedInsecure: true);
    await installEnrollment(vault, result, sealingKey: n.sealingKey);
    return (dir, vault);
  }

  test(
      '1. a laptop linked by v3 is linked, attested and talks, and the relay '
      'keeps nothing of the ceremony', () async {
    final before = await held();
    final alice = await person('Alice1');
    final dave = await person('Dave1');
    await pairUp(alice, dave);

    final n = await NewDeviceLink.create();
    final code = PairingCode.parse(n.code);
    String? onPhone, onLaptop;
    final hosted = alice.svc.hostDeviceLink(n.code, confirmSas: (s) async {
      onPhone = s;
      return true;
    });
    final result = await n.run(
        relayUrl: relayUrl(),
        confirm: (s) async {
          onLaptop = s;
          return true;
        });
    expect(result, isNotNull, reason: 'the laptop was enrolled');
    expect(await hosted, isTrue, reason: 'the phone linked it');
    expect(onLaptop, matches(RegExp(r'^\d{4} \d{4}$')));
    expect(onPhone, onLaptop, reason: 'one eight-digit string on both screens');

    final account = (await alice.svc.accountIdentity()).accountEdPub;
    final ml = (await alice.svc.pqAccountPublic())!;
    final mine = result!.account;
    expect(b64(mine.accountEdPub), b64(account));
    expect(await mine.deviceCert.verify(account), isTrue,
        reason: 'its certificate verifies under the account key');
    expect(mine.holdsAccountRoot, isFalse, reason: 'v3 never carries the root');
    bool attests(Uint8List? pqdc) =>
        pqdc != null &&
        deviceAttestationValid(
            accountMlPub: ml,
            accountEdPub: account,
            deviceEdPub: mine.deviceEdPub,
            deviceXPub: mine.deviceXPub,
            sealEk: n.sealingKey.ek,
            pqdc: pqdc);

    final (dir, vault) = await installed('Alice1-laptop', result, n);
    final stored = await vault.kvGet(ownPqdcKey);
    expect(attests(stored == null ? null : unb64(stored)), isTrue,
        reason: "the enrolment's pqdc verifies under the account's ML-DSA "
            'key, and is held before the first start');
    expect(await vault.kvGet(sealSeedKey), b64(n.sealingKey.seed),
        reason: 'the sealing key the ceremony bound is this device\'s');

    final laptop = await boot(dir, 'Alice1-laptop', vault: vault);
    await connected([laptop]);
    expect(b64(laptop.svc.debugSealingKey!), b64(n.sealingKey.ek),
        reason: 'its first start drew no other sealing key');
    expect(attests(laptop.svc.debugOwnPqdc), isTrue,
        reason: 'and holds a pqdc that verifies from its first start');

    // The account's list names it, and verifies.
    await waitFor(() async => await laptop.svc.ownDeviceListVersion() >= 2,
        what: "the laptop holds its account's list");
    final list = SignedDeviceList.fromJson(
        (jsonDecode((await laptop.vault.kvGet('own_list_json'))!) as Map)
            .cast<String, Object?>());
    expect(await list.verify(), isTrue);
    expect(b64(list.accountEdPub), b64(account));
    expect(
        list.devices.any((d) =>
            b64(d.deviceEdPub) == b64(mine.deviceEdPub) &&
            b64(d.deviceXPub) == b64(mine.deviceXPub)),
        isTrue,
        reason: 'the list names the laptop by the keys the digits covered');

    // Messages flow to it and from it.
    await laptop.svc.sendText(dave.svc.myRid, 'from the laptop');
    await arrived(dave, alice.svc.myRid, 'from the laptop');
    await dave.svc.sendText(alice.svc.myRid, 'to the laptop too');
    await arrived(laptop, dave.svc.myRid, 'to the laptop too');
    await arrived(alice, dave.svc.myRid, 'to the laptop too');

    // Nothing of the ceremony is left on the relay: once the three have
    // gone quiet it holds what it held before them, and the ceremony's
    // mailboxes are empty.
    await waitFor(() async => await held() == before,
        timeout: const Duration(seconds: 90),
        what: 'the relay to hold what it held before the ceremony');
    // ignore: avoid_print
    print('a link by v3 (one contact): the relay held $before before and '
        '${await held()} once all three were quiet (envelopes, bytes)');
    for (final who in await ceremonyMailboxes(code)) {
      expect(await peek(who), isEmpty,
          reason: 'a ceremony mailbox holds nothing');
    }
  });

  test('2. the frames on the wire are the sizes §10.2 states', () async {
    final alice = await person('Alice2');
    await connected([alice]);
    final rec = await Recorder.start(relayUrl());
    try {
      // v3, the new device's connection through the front.
      final n = await NewDeviceLink.create();
      final hosted =
          alice.svc.hostDeviceLink(n.code, confirmSas: (_) async => true);
      expect(await n.run(relayUrl: rec.url, confirm: (_) async => true),
          isNotNull);
      expect(await hosted, isTrue);
      // The same account, linking as the build before this one did: v2 on
      // both sides, the same enrolment but for v3's pqdc.
      alice.svc.debugPairAsVersion2 = true;
      final old = await NewDeviceLink.createAsVersion2();
      final hostedOld =
          alice.svc.hostDeviceLink(old.code, confirmSas: (_) async => true);
      expect(await old.run(relayUrl: rec.url, confirm: (_) async => true),
          isNotNull);
      expect(await hostedOld, isTrue);
    } finally {
      await rec.close();
    }
    final f = rec.frames;
    int size(String kind) => utf8.encode(f[kind]!.single).length;
    Uint8List blob(String kind) =>
        unb64((jsonDecode(f[kind]!.single) as Map)['blob'] as String);
    // ignore: avoid_print
    print('pairing frames on the wire, payload bytes: '
        '${{for (final k in f.keys) k: size(k)}}; sealed enrolment bytes: '
        'v3 ${blob('enroll-v3').length}, v2 ${blob('enroll-v2').length}');
    expect(size('commit-v3'), 1656);
    expect(size('reply-v3'), 1530);
    expect(size('open-v3'), 246, reason: "the app's device id is 12 characters");
    // pqdc is 3 309 bytes; as the enrolment's last member it is
    // `,"pqdc":"` + 4 412 characters of base64 + `"`: 4 422 more plaintext,
    // and ChaCha20-Poly1305 adds the same 28 bytes to either.
    expect(blob('enroll-v3').length - blob('enroll-v2').length, 4422,
        reason: "enroll-v3 is v2's with pqdc's 3 309 bytes more");
    expect(size('commit-v2'), 68);
    expect(size('reply-v2'), 70);
  });

  test(
      '3. an existing device of this build meeting an older new device says '
      'which version, answers nothing and links nothing', () async {
    final alice = await person('Alice3');
    await connected([alice]);
    final listBefore = await alice.svc.ownDeviceListVersion();
    for (final version in [2, 1]) {
      final String code;
      final Future<Object?> old;
      if (version == 2) {
        final n = await NewDeviceLink.createAsVersion2();
        code = n.code;
        old = n
            .run(
                relayUrl: relayUrl(),
                confirm: (_) async => true,
                timeout: const Duration(seconds: 4))
            .then<Object?>((r) => r, onError: (Object e) => e);
      } else {
        final n = await PairingInitiator.create();
        code = n.code.text;
        old = RelayPairing.runNewDevice(
                relayUrl: relayUrl(),
                n: n,
                confirm: (_) async => true,
                timeout: const Duration(seconds: 4))
            .then<Object?>((r) => r, onError: (Object e) => e);
      }
      var shown = false;
      Object? heard;
      try {
        await alice.svc.hostDeviceLink(code, confirmSas: (_) async {
          shown = true;
          return true;
        });
      } catch (e) {
        heard = e;
      }
      expect(
          heard,
          isA<PairingPeerOutdated>()
              .having((e) => e.version, 'version', version),
          reason: 'the phone names the version the new device spoke');
      expect(hostLinkFailureText(en, heard!), en.linkNewDeviceOlder(version),
          reason: 'and its screen says to update the new device');
      expect(shown, isFalse, reason: 'no digits were ever shown');
      expect(await old, isNot(isA<PairingResult>()),
          reason: 'the older device paired with nothing');
      expect(await alice.svc.linkedDevices(), isEmpty, reason: 'nothing linked');
      expect(await alice.svc.ownDeviceListVersion(), listBefore,
          reason: 'and the list never moved');
      // Nothing was answered on any mailbox the older device listens on.
      final c = PairingCode.parse(code);
      expect([
        ...await peek(await RelayPairing.relayIdentityV2(c, 'i')),
        ...await peek(await RelayPairing.relayIdentity(c, 'i')),
      ], isEmpty, reason: 'detect, do not transact');
    }
  });

  test(
      '4. a new device of this build meeting an existing device of the '
      'version before hears nothing, and says it may be older', () async {
    final alice = await person('Alice4');
    await connected([alice]);
    alice.svc.debugPairAsVersion2 = true;
    alice.svc.linkTimeout = const Duration(seconds: 8);
    final n = await NewDeviceLink.create();
    final code = n.code;
    var shown = false;
    final host = alice.svc
        .hostDeviceLink(code, confirmSas: (_) async {
          shown = true;
          return true;
        })
        .then<Object?>((r) => r, onError: (Object e) => e);
    Object? heard;
    try {
      await n.run(
          relayUrl: relayUrl(),
          confirm: (_) async {
            shown = true;
            return true;
          },
          timeout: const Duration(seconds: 4));
    } catch (e) {
      heard = e;
    }
    expect(heard, isA<PairingNoAnswer>(),
        reason: 'the older phone listens where v2 speaks: nothing answered');
    expect(newDeviceLinkFailureText(en, heard!), en.linkHostMayBeOlder,
        reason: 'and the screen says to update the device it links from');
    expect(await host, isA<TimeoutException>(),
        reason: 'the older phone heard nothing it would answer');
    expect(shown, isFalse, reason: 'no digits on either screen');
    expect(await alice.svc.linkedDevices(), isEmpty);
    expect(n.code, code,
        reason: 'nothing was spent: the same code is tried again');
  });

  test('5. a wrong digit comparison stops the side that makes it', () async {
    final alice = await person('Alice5');
    await connected([alice]);
    alice.svc.linkTimeout = const Duration(seconds: 8);
    final listBefore = await alice.svc.ownDeviceListVersion();

    // The phone's person says the digits differ.
    final n = await NewDeviceLink.create();
    final code = n.code;
    final hosted =
        alice.svc.hostDeviceLink(code, confirmSas: (_) async => false);
    Object? waited;
    try {
      await n.run(
          relayUrl: relayUrl(),
          confirm: (_) async => true,
          timeout: const Duration(seconds: 6));
    } catch (e) {
      waited = e;
    }
    expect(await hosted, isFalse, reason: 'the phone links nothing');
    expect(waited, isA<TimeoutException>(),
        reason: 'and sends no enrolment for the laptop to wait for');
    expect(await alice.svc.linkedDevices(), isEmpty);
    expect(await alice.svc.ownDeviceListVersion(), listBefore);
    expect(await peek(await RelayPairing.relayIdentityV3(
            PairingCode.parse(code), 'i')),
        isEmpty,
        reason: 'no enrolment went to the laptop');
    expect(n.code, isNot(code),
        reason: 'its KEM key spent, the next attempt is a new ceremony');

    // The laptop's person says they differ. The phone's says they match,
    // and the phone sends its enrolment, as each side acts on its own
    // comparison (§10): the laptop takes none of it.
    final m = await NewDeviceLink.create();
    final hostedToo =
        alice.svc.hostDeviceLink(m.code, confirmSas: (_) async => true);
    expect(await m.run(relayUrl: relayUrl(), confirm: (_) async => false),
        isNull,
        reason: 'a new device that says they differ installs nothing');
    await hostedToo;
  });

  test('6. an enrolment carrying the account root is refused', () async {
    final n = await NewDeviceLink.create();
    final code = PairingCode.parse(n.code);
    final root = await AccountIdentity.generate();
    // An existing device no v3 build is: it holds the code and seals the
    // account root into the enrolment, which v3 has no way to send.
    final hostile = () async {
      final r = await RelayClient.connect(
          relayUrl(), await RelayPairing.relayIdentityV3(code, 'r'));
      final inbox = <RelayInbound>[];
      final sub = r.messages.listen(inbox.add);
      Map<String, Object?> frame(String kind) => (jsonDecode(inbox
              .firstWhere((e) => (jsonDecode(e.payload) as Map)['k'] == kind)
              .payload) as Map)
          .cast<String, Object?>();
      bool has(String kind) =>
          inbox.any((e) => (jsonDecode(e.payload) as Map)['k'] == kind);
      try {
        final to =
            await (await RelayPairing.relayIdentityV3(code, 'i')).routingId();
        await waitUntil(() => has('commit-v3'), what: 'the commitment');
        final (reply, pending) =
            await PairingResponderV3.reply(frame('commit-v3'), code: code);
        await r.send(
            to: to,
            id: 'z-pair-reply',
            payload: jsonEncode({'k': 'reply-v3', ...reply}));
        await waitUntil(() => has('open-v3'), what: 'the opening');
        final session = await pending.accept(frame('open-v3'));
        final aead = Chacha20.poly1305Aead();
        final key = SecretKey(session.channelKey);
        final honest = await session.sealEnrollment(root, contacts: const []);
        final plain = (jsonDecode(utf8.decode(await aead.decrypt(
                SecretBox.fromConcatenation(honest,
                    nonceLength: 12, macLength: 16),
                secretKey: key))) as Map)
            .cast<String, Object?>()
          ..['root'] = b64(root.accountEdSeed!);
        final box = await aead.encrypt(utf8.encode(jsonEncode(plain)),
            secretKey: key, nonce: randomBytes(12));
        await r.send(
            to: to,
            id: 'z-pair-enroll',
            payload: jsonEncode(
                {'k': 'enroll-v3', 'blob': b64(box.concatenation())}));
      } finally {
        await sub.cancel();
        await r.close();
      }
    }();
    Object? refused;
    try {
      await n.run(relayUrl: relayUrl(), confirm: (_) async => true);
    } catch (e) {
      refused = e;
    }
    await hostile;
    expect(
        refused,
        isA<FormatException>().having((e) => e.message, 'message',
            'a v3 enrolment never carries the account root'),
        reason: 'the new device refuses it, so there is nothing to install');
    expect(newDeviceLinkFailureText(en, refused!), en.linkFailed('$refused'),
        reason: 'and its screen says the link failed');
  });

  test(
      '7. an enrolment whose pqdc does not verify is refused, and the device '
      'gets one that does from its root', () async {
    final alice = await person('Alice7');
    final dave = await person('Dave7');
    await pairUp(alice, dave);
    final pq = (await alice.svc.pqIdentity())!;
    final another = SealingKey.generate();
    // The account's own signature, over another sealing key's hash: what a
    // `pqdc` made for any key but this device's is.
    alice.svc.debugLinkAttestation = (s) => signDeviceAttestationFromHash(
        accountKey: pq,
        deviceEdPub: s.peerDeviceEdPub!,
        deviceXPub: s.peerDeviceXPub!,
        sk: another.hash);
    final n = await NewDeviceLink.create();
    final hosted =
        alice.svc.hostDeviceLink(n.code, confirmSas: (_) async => true);
    final result =
        await n.run(relayUrl: relayUrl(), confirm: (_) async => true);
    expect(result, isNotNull);
    expect(await hosted, isTrue);
    alice.svc.debugLinkAttestation = null;
    final sent = result!.data.pqdc;
    expect(sent, isNotNull, reason: 'the enrolment carried a pqdc');

    final (dir, vault) = await installed('Alice7-laptop', result, n);
    expect(await vault.kvGet('account'), isNotNull,
        reason: 'the link itself stands');
    expect(await vault.kvGet(ownPqdcKey), isNull,
        reason: 'the pqdc that does not verify is refused');
    expect(await vault.kvGet(sealSeedKey), b64(n.sealingKey.seed));

    // It asks its root, as a device linked before 44.4 does: its pqseal over
    // self-sync, riding what it sends while messages flow.
    final laptop = await boot(dir, 'Alice7-laptop', vault: vault);
    await connected([laptop]);
    expect(laptop.svc.debugOwnPqdc, isNull);
    final account = (await alice.svc.accountIdentity()).accountEdPub;
    final ml = (await alice.svc.pqAccountPublic())!;
    final me = result.account;
    bool attests(Uint8List? pqdc) =>
        pqdc != null &&
        deviceAttestationValid(
            accountMlPub: ml,
            accountEdPub: account,
            deviceEdPub: me.deviceEdPub,
            deviceXPub: me.deviceXPub,
            sealEk: n.sealingKey.ek,
            pqdc: pqdc);
    expect(attests(sent), isFalse, reason: 'the premise: it does not verify');
    var i = 0;
    await waitFor(() async {
      final k = i++;
      await laptop.svc.sendText(dave.svc.myRid, 'l$k');
      await alice.svc.sendText(dave.svc.myRid, 'p$k');
      await dave.svc.sendText(alice.svc.myRid, 'd$k');
      await arrived(laptop, dave.svc.myRid, 'd$k');
      await arrived(laptop, dave.svc.myRid, 'p$k');
      await arrived(alice, dave.svc.myRid, 'l$k');
      return attests(laptop.svc.debugOwnPqdc);
    }, timeout: const Duration(seconds: 90),
        what: 'the laptop holds a pqdc from its root that verifies');
    expect(b64(laptop.svc.debugOwnPqdc!), isNot(b64(sent!)));
    expect(await laptop.vault.kvGet(ownPqdcKey), b64(laptop.svc.debugOwnPqdc!));
  });

  test('8. each screen says which device to update, in both languages', () {
    for (final l in [en, es]) {
      // The existing device's screen: the new device is the older one.
      expect(hostLinkFailureText(l, const PairingPeerOutdated(2)),
          l.linkNewDeviceOlder(2));
      expect(hostLinkFailureText(l, const PairingPeerOutdated(1)),
          l.linkNewDeviceOlder(1));
      // The new device's screen: the device it links from may be older.
      expect(newDeviceLinkFailureText(l, const PairingNoAnswer()),
          l.linkHostMayBeOlder);
      // Anything else stops a link as a failure, never as a version.
      const abort = PairingAbort('the opening does not match the commitment');
      expect(hostLinkFailureText(l, abort), l.linkFailed(abort.message));
      expect(newDeviceLinkFailureText(l, abort), l.linkFailed(abort.message));
      final timeout = TimeoutException('pairing: no "commit-v3" frame arrived');
      expect(hostLinkFailureText(l, timeout), l.linkFailed('$timeout'));
    }
    // The words name the device: the one being added, on the phone; the one
    // linked from, on the new device. And each locale has its own.
    expect(en.linkNewDeviceOlder(2), contains('Update Z on that device'));
    expect(en.linkNewDeviceOlder(2), contains('pairing version 2'));
    expect(en.linkHostMayBeOlder,
        contains('update Z on the device you are linking from'));
    expect(es.linkNewDeviceOlder(2), contains('Actualiza Z en ese dispositivo'));
    expect(es.linkNewDeviceOlder(2), contains('versión 2'));
    expect(es.linkHostMayBeOlder,
        contains('actualiza Z en el dispositivo desde el que vinculas'));
    expect(es.linkNewDeviceOlder(2), isNot(en.linkNewDeviceOlder(2)));
    expect(es.linkHostMayBeOlder, isNot(en.linkHostMayBeOlder));
    expect(es.linkNewCode, isNot(en.linkNewCode));
  });
}
