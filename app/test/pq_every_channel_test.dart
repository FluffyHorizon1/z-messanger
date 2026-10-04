// Phase 26.2: every channel re-keys, and a lost offer is not forever.
//
// The post-quantum layer (PROTOCOL §17) has three moving parts that keep it
// alive after the first round trip: the initial ML-KEM offer is made again
// while nobody answers it (§17.4), the secret is rotated on an interval
// (§17.7), and — once a pair has said they hold each other's identity key —
// both screens move to one post-quantum safety number (ADR 0021). Until this
// change all three worked on a person's main chat and nowhere else:
//
//   * the self-sync channel to one's own linked devices, which carries a copy
//     of EVERY message, and the channel to a contact's other devices, were
//     built with both intervals at zero — one withheld offer at link time
//     kept them classical for good, and they never re-keyed;
//   * so was every conversation rebuilt by a rollback, until a restart — and
//     one garbage envelope from anyone triggers a rollback;
//   * a re-key offer that never arrived froze re-keying for the life of the
//     session;
//   * the history replayed to a newly linked device went out classical
//     whenever the root was the side that offers;
//   * one lost `pqack` left two people on two different numbers for good.
//
// Two real clients (three or four where devices are linked) over a real
// relay, with the intervals compressed the way pq_rekey_test.dart does. A
// lost envelope is made by the receiver's test probe (`debugOnDecrypted`),
// which discards it as though the relay had never delivered it: the sealed
// bytes on the wire cannot be told apart by kind, and withholding exactly one
// is what a relay can always do (R27).
//
// Exit criteria:
//   1. the four kinds of channel each rotate to a new post-quantum
//      generation on the interval: (a) a primary 1:1 chat, (b) the self-sync
//      channel to my own linked device, (c) the channel to a contact's other
//      device, and (d) a primary chat whose conversation a garbage envelope
//      rolled back;
//   2. an offer withheld on the self-sync channel is made again, and the
//      channel ends post-quantum;
//   3. an offer withheld on a contact's other device is made again, and that
//      channel ends post-quantum;
//   4. a re-key offer withheld for longer than the bound is abandoned, and
//      the next generation is established from a FRESH key;
//   5. the history replayed to a newly linked device goes out only once that
//      device's channel is post-quantum — every replayed envelope is mixed —
//      with the root as the side that offers, the case that always went out
//      classical;
//   6. a replay whose channel never becomes post-quantum is dropped at the
//      bound: nothing of it reaches the device, classical or otherwise;
//   7. a lost `pqack` does not leave the pair on two numbers: the next thing
//      the acknowledging side says carries the fact, and both screens move
//      to one post-quantum number;
//   8. a change to my own device list does not fork the self-sync ratchet:
//      (a) the service rebuilt for the new list carries on the session the
//      old one held, and (b) when the old one, still handling an envelope,
//      answers an offer, the new one reads what is then mixed with the
//      secret. The rebuilt service used to read its own copy from the
//      vault, and criterion 5 lost to that race in one run of three.
@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/device_sync.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:z_protocol/z_protocol.dart';

/// One envelope a probe was shown: which door it came in by, from whom, what
/// it carried, and whether its key was post-quantum.
class Seen {
  final String path;
  final String from;
  final String kind;
  final String? dir; // the self-sync envelope's `dir`, on the sync path
  final bool pq;
  final int? gen; // a `pqek` offer's generation
  final String? ek; // a `pqek` offer's key
  final DateTime at;
  Seen(this.path, this.from, this.kind, this.dir, this.pq, this.gen, this.ek)
      : at = DateTime.now();
  @override
  String toString() =>
      '$path/$kind${dir == null ? '' : '/$dir'} pq=$pq${gen == null ? '' : ' g=$gen'}';
}

Seen describe(String path, String from, DecryptResult dec) {
  final p = dec.plaintext;
  var kind = '?';
  String? dir;
  var data = const <String, Object?>{};
  try {
    if (path == 'sync' && !InnerMessage.looksLikeKind(p, 'pqek')) {
      final j = jsonDecode(utf8.decode(p)) as Map;
      dir = j['dir'] as String?;
      final inner = InnerMessage.fromBytes(base64Decode(j['inner'] as String));
      kind = inner.kind;
      data = inner.data;
    } else {
      final inner = InnerMessage.fromBytes(p);
      kind = inner.kind;
      data = inner.data;
    }
  } catch (_) {}
  return Seen(
      path,
      from,
      kind,
      dir,
      dec.postQuantum,
      kind == 'pqek' ? ((data['g'] as num?)?.toInt() ?? 0) : null,
      data['ek'] as String?);
}

/// What one client's probe saw and withheld.
class Probe {
  final seen = <Seen>[];
  final withheld = <Seen>[];
  bool Function(Seen s)? withhold;

  void attach(ChatService svc) {
    svc.debugOnDecrypted = (path, from, dec) {
      final s = describe(path, from, dec);
      final w = withhold?.call(s) ?? false;
      (w ? withheld : seen).add(s);
      return w;
    };
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  late Process relay;
  late int port;
  final temps = <Directory>[];
  final services = <ChatService>[];

  setUpAll(() async {
    final serverDir =
        '${Directory.current.parent.path}${Platform.pathSeparator}server';
    final portProbe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    port = portProbe.port;
    await portProbe.close();
    relay = await Process.start('node', ['server.js'],
        workingDirectory: serverDir,
        environment: {
          'PORT': '$port',
          'LOG_LEVEL': 'silent',
          'METRICS_TOKEN': 'z-apptest-metrics',
        });
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
    for (final s in services) {
      await s.transport.stop();
    }
    relay.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<ChatService> makeClient(String name, {ZIdentity? id}) async {
    final dir = await Directory.systemTemp.createTemp('z_pqc_$name');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final identity = id ?? await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(identity.toJson()));
    final svc = await ChatService.init(
        vault: vault,
        identity: identity,
        displayName: name,
        transport:
            Transport(identity: identity, serverUrl: 'ws://127.0.0.1:$port'));
    services.add(svc);
    return svc;
  }

  /// [phone]'s account linked onto a new install with identity [devId], as
  /// `hostDeviceLink` enrols one (the account's post-quantum public key rides
  /// along). The link is only half made: [phone] learns of the device when
  /// the test calls `addMyDevice`.
  Future<(ChatService, DeviceCertificate)> makeLinked(
      String name, ChatService phone, ZIdentity devId) async {
    final account = await phone.accountIdentity();
    final cert = await account.signDeviceCert(
        deviceEdPub: devId.edPub, deviceXPub: devId.xPub, deviceId: name);
    final myMl = await phone.pqAccountPublic();
    final dir = await Directory.systemTemp.createTemp('z_pqc_$name');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    await vault.kvPut('identity', jsonEncode(devId.toJson()));
    final enrolled = await AccountIdentity.fromEnrollment(
      accountEdPub: account.accountEdPub,
      accountMlPub: myMl,
      deviceEdSeed: devId.edSeed,
      deviceXSeed: devId.xSeed,
      deviceId: name,
      deviceCert: cert,
    );
    await vault.kvPut('account', jsonEncode(enrolled.toJson()));
    await vault.kvPut('my_devices', jsonEncode([account.deviceCert.toJson()]),
        sensitive: false);
    final svc = await ChatService.init(
        vault: vault,
        identity: devId,
        displayName: name,
        transport:
            Transport(identity: devId, serverUrl: 'ws://127.0.0.1:$port'));
    services.add(svc);
    return (svc, cert);
  }

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

  /// Two identities, the first with the LOWER routing id — the designated
  /// initiator of any pair they form, which encapsulates; the second offers.
  Future<(ZIdentity low, ZIdentity high)> orderedIds() async {
    final a = await ZIdentity.generate();
    final b = await ZIdentity.generate();
    return (await a.routingId()).compareTo(await b.routingId()) < 0
        ? (a, b)
        : (b, a);
  }

  List<String> texts(ChatService svc, String rid) => [
        for (final m in svc.messagesByChat[rid] ?? const [])
          if (m.kind == 'text') m.body
      ];

  void compress(List<ChatService> svcs, {int? rekeyMs, int? retryMs}) {
    for (final s in svcs) {
      if (rekeyMs != null) s.pqRekeyInterval = rekeyMs;
      if (retryMs != null) s.pqOfferRetry = retryMs;
    }
  }

  /// Two people who have added each other and exchanged a word, each holding
  /// the other's post-quantum identity key and a post-quantum session.
  Future<void> befriend(ChatService a, ChatService b) async {
    await waitUntil(() => a.transport.isConnected && b.transport.isConnected,
        what: '${a.displayName} and ${b.displayName} connected');
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
    await a.sendText(b.myRid, 'hi ${b.displayName}');
    await b.sendText(a.myRid, 'hi ${a.displayName}');
    await waitUntil(
        () async =>
            await a.isPostQuantumWith(b.myRid) &&
            await b.isPostQuantumWith(a.myRid) &&
            texts(a, b.myRid).contains('hi ${a.displayName}') &&
            texts(b, a.myRid).contains('hi ${b.displayName}'),
        what: '${a.displayName} and ${b.displayName} post-quantum');
  }

  /// The self-sync conversation [svc] holds with its own device [deviceRid].
  Conversation? syncConv(ChatService svc, String deviceRid) =>
      svc.debugSyncSession?.targetConversation(deviceRid);

  /// The conversation [svc] holds with [contactRid]'s other device [deviceRid].
  Conversation? extraConv(ChatService svc, String contactRid, String deviceRid) =>
      svc.debugExtraSession(contactRid)?.targetConversation(deviceRid);

  /// A phone with a contact (carol) and a linked laptop that holds carol too.
  /// [laptopId] and [carolId] let a test choose who offers on which pair.
  Future<(ChatService phone, ChatService laptop, ChatService carol)> linkedTrio(
      {ZIdentity? phoneId,
      ZIdentity? laptopId,
      ZIdentity? carolId,
      Probe? phoneProbe,
      Probe? laptopProbe,
      Probe? carolProbe}) async {
    final phone = await makeClient('phone', id: phoneId);
    final carol = await makeClient('carol', id: carolId);
    phoneProbe?.attach(phone);
    carolProbe?.attach(carol);
    await befriend(phone, carol);
    final (laptop, cert) =
        await makeLinked('laptop', phone, laptopId ?? await ZIdentity.generate());
    laptopProbe?.attach(laptop);
    await waitUntil(() => laptop.transport.isConnected,
        what: 'the laptop connected');
    await phone.addMyDevice(cert);
    // Carol fans out to the laptop once she holds the list that names it.
    await waitUntil(
        () => carol.debugListedDeviceOwner(laptop.myRid) == phone.myRid,
        what: "carol holds the phone's list naming the laptop");
    await laptop.addContactFromCode(await carol.myContactCode());
    await waitUntil(() => laptop.contacts.containsKey(carol.myRid),
        what: 'the laptop knows carol');
    return (phone, laptop, carol);
  }

  test('1a. a primary chat rotates its post-quantum secret on the interval',
      () async {
    final (lo, hi) = await orderedIds();
    final enc = await makeClient('enc1a', id: lo);
    final off = await makeClient('off1a', id: hi);
    await befriend(enc, off);
    compress([enc, off], rekeyMs: 400);
    var i = 0;
    await waitUntil(() async {
      await off.sendText(enc.myRid, 'o$i');
      await enc.sendText(off.myRid, 'e$i');
      final n = i++;
      await waitUntil(
          () =>
              texts(enc, off.myRid).contains('o$n') &&
              texts(off, enc.myRid).contains('e$n'),
          what: 'round $n delivered');
      return await enc.pqGenerationWith(off.myRid) >= 1 &&
          await off.pqGenerationWith(enc.myRid) >= 1;
    }, what: 'both ends of the primary chat at generation >= 1');
    expect(await enc.isPostQuantumWith(off.myRid), isTrue);
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('1b. the self-sync channel to my own linked device rotates too',
      () async {
    final (phone, laptop, carol) = await linkedTrio();
    compress([phone, laptop, carol], rekeyMs: 400);
    var i = 0;
    await waitUntil(() async {
      final n = i++;
      // Each device's own send is mirrored to the other: traffic both ways
      // on the self-sync channel, whichever of the two offers.
      await phone.sendText(carol.myRid, 'p$n');
      await laptop.sendText(carol.myRid, 'l$n');
      await waitUntil(
          () =>
              texts(laptop, carol.myRid).contains('p$n') &&
              texts(phone, carol.myRid).contains('l$n'),
          what: 'round $n mirrored both ways');
      final a = syncConv(phone, laptop.myRid);
      final b = syncConv(laptop, phone.myRid);
      return a != null &&
          b != null &&
          a.isPostQuantum &&
          b.isPostQuantum &&
          a.pqGeneration >= 1 &&
          b.pqGeneration >= 1;
    }, what: 'both ends of the self-sync channel at generation >= 1');
  }, timeout: const Timeout(Duration(minutes: 2)));

  test("1c. the channel to a contact's other device rotates too", () async {
    // Carol must be the side that OFFERS on her pair with the laptop: only
    // the offering side rotates, and her side of it is the session that was
    // built with no interval. The laptop's side is its primary chat with
    // her, which always had one.
    final (lo, hi) = await orderedIds();
    final (phone, laptop, carol) =
        await linkedTrio(laptopId: lo, carolId: hi);
    compress([phone, laptop, carol], rekeyMs: 400);
    var i = 0;
    await waitUntil(() async {
      final n = i++;
      await carol.sendText(phone.myRid, 'c$n'); // fans out to the laptop
      await laptop.sendText(carol.myRid, 'l$n');
      await waitUntil(
          () =>
              texts(laptop, carol.myRid).contains('c$n') &&
              texts(carol, phone.myRid).contains('l$n'),
          what: 'round $n delivered between carol and the laptop');
      final c = extraConv(carol, phone.myRid, laptop.myRid);
      return c != null &&
          c.isPostQuantum &&
          c.pqGeneration >= 1 &&
          await laptop.pqGenerationWith(carol.myRid) >= 1;
    }, what: "carol's channel to the laptop at generation >= 1");
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('1d. a primary chat that a garbage envelope rolled back still rotates',
      () async {
    final (lo, hi) = await orderedIds();
    final enc = await makeClient('enc1d', id: lo);
    final off = await makeClient('off1d', id: hi);
    await befriend(enc, off);
    // The intervals are set BEFORE the rollback and never touched again:
    // setting them re-applies them to every live conversation, which is the
    // one thing a test must not do after the rollback it is about.
    compress([enc, off], rekeyMs: 400);
    final before = off.debugConversation(enc.myRid);
    // One sealed envelope from anyone holding the offerer's code, claiming
    // to come from the encapsulator, opening a session that does not
    // decrypt. The offerer puts its conversation back from a snapshot.
    final ek = randomBytes(32);
    final garbage = base64Encode(utf8.encode(jsonEncode({
      'v': 1,
      't': 'r',
      'sid': await sessionIdFromEk(ek),
      'ek': b64(ek),
      'h': {'dh': b64(randomBytes(32)), 'n': 0, 'pn': 0},
      'n': b64(randomBytes(24)),
      'ct': b64(randomBytes(48)),
      'mac': b64(randomBytes(16)),
    })));
    final hellosBefore = off.debugHellos;
    await enc.transport.send(
        to: off.myRid,
        id: newMessageId(),
        payload: await SealedEnvelope.seal(
            toXPub: off.identity.xPub, fromRid: enc.myRid, payload: garbage));
    await waitUntil(() => off.debugHellos > hellosBefore,
        what: 'the offerer rejected the garbage and sent its repair hello');
    expect(identical(off.debugConversation(enc.myRid), before), isFalse,
        reason: 'the conversation was rebuilt from its snapshot');
    var i = 0;
    await waitUntil(() async {
      final n = i++;
      await off.sendText(enc.myRid, 'o$n');
      await enc.sendText(off.myRid, 'e$n');
      await waitUntil(
          () =>
              texts(enc, off.myRid).contains('o$n') &&
              texts(off, enc.myRid).contains('e$n'),
          what: 'round $n delivered');
      return await off.pqGenerationWith(enc.myRid) >= 1 &&
          await enc.pqGenerationWith(off.myRid) >= 1;
    }, what: 'the rolled-back offerer rotates to generation >= 1');
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('2. an offer withheld on the self-sync channel is made again',
      () async {
    final phoneProbe = Probe(), laptopProbe = Probe();
    var holding = true;
    bool hold(Seen s) => holding && s.path == 'sync' && s.kind == 'pqek';
    phoneProbe.withhold = hold;
    laptopProbe.withhold = hold;
    final (phone, laptop, carol) = await linkedTrio(
        phoneProbe: phoneProbe, laptopProbe: laptopProbe);
    compress([phone, laptop, carol], retryMs: 600);
    // Traffic on the self-sync channel while every offer on it vanishes.
    for (var n = 0; n < 2; n++) {
      await phone.sendText(carol.myRid, 'p$n');
      await laptop.sendText(carol.myRid, 'l$n');
      await waitUntil(
          () =>
              texts(laptop, carol.myRid).contains('p$n') &&
              texts(phone, carol.myRid).contains('l$n'),
          what: 'round $n mirrored both ways, classically');
    }
    expect(phoneProbe.withheld.length + laptopProbe.withheld.length,
        greaterThan(0),
        reason: 'the offer was made, and withheld');
    expect(syncConv(phone, laptop.myRid)!.isPostQuantum, isFalse);
    holding = false;
    var i = 2;
    await waitUntil(() async {
      final n = i++;
      await phone.sendText(carol.myRid, 'p$n');
      await laptop.sendText(carol.myRid, 'l$n');
      await waitUntil(
          () =>
              texts(laptop, carol.myRid).contains('p$n') &&
              texts(phone, carol.myRid).contains('l$n'),
          what: 'round $n mirrored both ways');
      return syncConv(phone, laptop.myRid)!.isPostQuantum &&
          syncConv(laptop, phone.myRid)!.isPostQuantum;
    }, what: 'the self-sync channel post-quantum after all');
    // And what it carries now is mixed: the next mirror each way.
    final mark = phoneProbe.seen.length, markL = laptopProbe.seen.length;
    await phone.sendText(carol.myRid, 'after');
    await laptop.sendText(carol.myRid, 'after too');
    await waitUntil(
        () =>
            texts(laptop, carol.myRid).contains('after') &&
            texts(phone, carol.myRid).contains('after too'),
        what: 'the last mirrors arrived');
    final mirrors = [
      ...phoneProbe.seen.skip(mark),
      ...laptopProbe.seen.skip(markL)
    ].where((s) => s.path == 'sync' && s.kind == 'text');
    expect(mirrors, isNotEmpty);
    expect(mirrors.every((s) => s.pq), isTrue, reason: '$mirrors');
  }, timeout: const Timeout(Duration(minutes: 2)));

  test("3. an offer withheld on a contact's other device is made again",
      () async {
    final (lo, hi) = await orderedIds(); // carol offers to the laptop
    final laptopProbe = Probe();
    var holding = true;
    late String carolRid;
    laptopProbe.withhold =
        (s) => holding && s.kind == 'pqek' && s.from == carolRid;
    carolRid = await hi.routingId();
    final (phone, laptop, carol) = await linkedTrio(
        laptopId: lo, carolId: hi, laptopProbe: laptopProbe);
    compress([phone, laptop, carol], retryMs: 600);
    for (var n = 0; n < 2; n++) {
      await carol.sendText(phone.myRid, 'c$n');
      await laptop.sendText(carol.myRid, 'l$n');
      await waitUntil(
          () =>
              texts(laptop, carol.myRid).contains('c$n') &&
              texts(carol, phone.myRid).contains('l$n'),
          what: 'round $n delivered, classically');
    }
    expect(laptopProbe.withheld, isNotEmpty,
        reason: "carol's offer was made, and withheld");
    expect(await laptop.isPostQuantumWith(carol.myRid), isFalse);
    holding = false;
    var i = 2;
    await waitUntil(() async {
      final n = i++;
      await carol.sendText(phone.myRid, 'c$n');
      await laptop.sendText(carol.myRid, 'l$n');
      await waitUntil(
          () =>
              texts(laptop, carol.myRid).contains('c$n') &&
              texts(carol, phone.myRid).contains('l$n'),
          what: 'round $n delivered');
      final c = extraConv(carol, phone.myRid, laptop.myRid);
      return c != null &&
          c.isPostQuantum &&
          await laptop.isPostQuantumWith(carol.myRid);
    }, what: "carol's channel to the laptop post-quantum after all");
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('4. a re-key offer withheld past the bound is abandoned for a fresh one',
      () async {
    final (lo, hi) = await orderedIds();
    final enc = await makeClient('enc4', id: lo);
    final off = await makeClient('off4', id: hi);
    final probe = Probe()..attach(enc);
    var holding = true;
    probe.withhold = (s) => holding && s.kind == 'pqek' && (s.gen ?? 0) >= 1;
    await befriend(enc, off);
    // The bound is one re-key interval: an offer nobody answered for a whole
    // interval, while the peer went on talking, is given up.
    const rekeyMs = 1500;
    compress([enc, off], rekeyMs: rekeyMs, retryMs: 300);
    var i = 0;
    Future<void> round() async {
      final n = i++;
      await off.sendText(enc.myRid, 'o$n');
      await enc.sendText(off.myRid, 'e$n');
      await waitUntil(
          () =>
              texts(enc, off.myRid).contains('o$n') &&
              texts(off, enc.myRid).contains('e$n'),
          what: 'round $n delivered');
    }

    // Every re-key offer vanishes until one made from a second key has.
    await waitUntil(() async {
      await round();
      return probe.withheld.map((s) => s.ek).toSet().length >= 2;
    }, what: 'a second, fresh re-key key offered while the first went unanswered');
    final first = probe.withheld.first;
    final fresh = probe.withheld.firstWhere((s) => s.ek != first.ek);
    expect(fresh.gen, first.gen,
        reason: 'the same generation number, which an older peer accepts');
    expect(await enc.pqGenerationWith(off.myRid), 0);
    holding = false;
    await waitUntil(() async {
      await round();
      return await enc.pqGenerationWith(off.myRid) >= 1 &&
          await off.pqGenerationWith(enc.myRid) >= 1;
    }, what: 'the next generation established');
    final accepted =
        probe.seen.firstWhere((s) => s.kind == 'pqek' && (s.gen ?? 0) >= 1);
    expect(accepted.ek, isNot(first.ek),
        reason: 'the generation came from a fresh key, not the abandoned one');
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('5. history replayed to a new device waits for its channel to be '
      'post-quantum', () async {
    // The phone offers on its pair with the laptop: the case that always
    // went out classical, since its history left before its own offer did.
    final (lo, hi) = await orderedIds();
    final laptopProbe = Probe();
    final phone = await makeClient('phone5', id: hi);
    final carol = await makeClient('carol5');
    await befriend(phone, carol);
    for (var n = 0; n < 3; n++) {
      await phone.sendText(carol.myRid, 'old p$n');
      await carol.sendText(phone.myRid, 'old c$n');
    }
    await waitUntil(() => texts(phone, carol.myRid).contains('old c2'),
        what: 'the history at the phone');
    final (laptop, cert) = await makeLinked('laptop5', phone, lo);
    laptopProbe.attach(laptop);
    await waitUntil(() => laptop.transport.isConnected,
        what: 'the laptop connected');
    await laptop.addContactFromCode(await carol.myContactCode());
    await waitUntil(() => laptop.contacts.containsKey(carol.myRid),
        what: 'the laptop knows carol');
    await phone.addMyDevice(cert); // the replay starts here
    await waitUntil(
        () =>
            texts(laptop, carol.myRid)
                .where((t) => t.startsWith('old'))
                .length >=
            6,
        what: 'the replayed history at the laptop');
    final hist = laptopProbe.seen.where((s) => s.dir == 'hist').toList();
    expect(hist, isNotEmpty);
    expect(hist.every((s) => s.pq), isTrue,
        reason: 'every replayed envelope mixed: $hist');
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('6. a replay whose channel never becomes post-quantum is dropped at '
      'the bound', () async {
    final (lo, hi) = await orderedIds();
    final laptopProbe = Probe()
      ..withhold = (s) => s.path == 'sync' && s.kind == 'pqek';
    final phone = await makeClient('phone6', id: hi);
    final carol = await makeClient('carol6');
    await befriend(phone, carol);
    await phone.sendText(carol.myRid, 'before the link');
    final (laptop, cert) = await makeLinked('laptop6', phone, lo);
    laptopProbe.attach(laptop);
    await waitUntil(() => laptop.transport.isConnected,
        what: 'the laptop connected');
    await laptop.addContactFromCode(await carol.myContactCode());
    await waitUntil(() => laptop.contacts.containsKey(carol.myRid),
        what: 'the laptop knows carol');
    phone.historySyncPqWait = const Duration(seconds: 3);
    await phone.addMyDevice(cert);
    await waitUntil(
        () async => !await phone.debugHistoryReplayPending(laptop.myRid),
        what: 'the replay is no longer waiting');
    // Quiescence: nothing queued anywhere, so nothing of the replay is still
    // on its way to the assertion below.
    await waitUntil(() async {
      for (final s in [phone, laptop, carol]) {
        if ((await s.vault.db.query('outbox', limit: 1)).isNotEmpty) {
          return false;
        }
      }
      // The relay's queued count, from /metrics (z_queued_envelopes) since
      // P1-14 trimmed /health to liveness; /metrics is token-gated and the
      // relay is spawned with METRICS_TOKEN above. A failed scrape fails
      // loudly rather than reading as an empty relay.
      final req = await HttpClient()
          .getUrl(Uri.parse('http://127.0.0.1:$port/metrics'));
      req.headers.set('authorization', 'Bearer z-apptest-metrics');
      final res = await req.close();
      final body = await res.transform(utf8.decoder).join();
      final m = RegExp(r'^z_queued_envelopes (\d+)$', multiLine: true)
          .firstMatch(body);
      if (m == null) {
        throw StateError(
            'no z_queued_envelopes on /metrics (HTTP ${res.statusCode})');
      }
      return int.parse(m.group(1)!) == 0;
    }, what: 'every outbox and the relay empty');
    expect(laptopProbe.withheld, isNotEmpty,
        reason: "the phone's offers were made, and withheld");
    expect(laptopProbe.seen.where((s) => s.dir == 'hist'), isEmpty,
        reason: 'nothing of the replay reached the laptop');
    expect(syncConv(phone, laptop.myRid)?.isPostQuantum ?? false, isFalse);
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('7. a lost pqack does not leave the pair on two numbers', () async {
    // The order is what makes the `pqack` the only carrier of the fact: the
    // side that offers adds first, so the initiator's opening hello and key
    // land, and the initiator learns the other key from an ANSWER that says
    // it holds the initiator's — which the initiator then acknowledges with a
    // `pqack`, the envelope withheld here.
    final (lo, hi) = await orderedIds();
    final i = await makeClient('init7', id: lo);
    final n = await makeClient('other7', id: hi);
    final probe = Probe()..withhold = ((s) => s.kind == 'pqack');
    probe.attach(n);
    await waitUntil(() => i.transport.isConnected && n.transport.isConnected,
        what: 'both connected');
    Future<String> classical(ChatService s, String name) async =>
        (await s.identity.bundle(displayName: name)).encode();
    await n.addContactFromCode(await classical(i, 'init7'));
    await i.addContactFromCode(await classical(n, 'other7'));
    await waitUntil(
        () =>
            probe.withheld.isNotEmpty &&
            (i.contacts[n.myRid]?.showsPostQuantumNumber ?? false) &&
            n.contacts[i.myRid]?.numberKey != null,
        what: "the initiator's pqack sent and withheld");
    // The other side has not been told its key is held, and nothing it is
    // owed will say so again: before 26.2 the two screens stayed on two
    // numbers from here on, whatever was said next. Ordinary conversation
    // afterwards.
    await i.sendText(n.myRid, 'still there?');
    await n.sendText(i.myRid, 'yes');
    await waitUntil(
        () =>
            texts(n, i.myRid).contains('still there?') &&
            texts(i, n.myRid).contains('yes'),
        what: 'the exchange delivered');
    await waitUntil(
        () =>
            n.contacts[i.myRid]!.showsPostQuantumNumber &&
            i.contacts[n.myRid]!.showsPostQuantumNumber,
        what: 'both screens on the post-quantum number');
    expect(await i.safetyNumberWith(n.myRid), await n.safetyNumberWith(i.myRid),
        reason: 'one number');
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('8a. a change to my device list leaves the self-sync session in place',
      () async {
    final phone = await makeClient('phone8');
    final (laptop, cert) =
        await makeLinked('laptop8', phone, await ZIdentity.generate());
    await waitUntil(
        () => phone.transport.isConnected && laptop.transport.isConnected,
        what: 'both connected');
    await phone.addMyDevice(cert); // self-synced to the laptop
    await waitUntil(
        () async => await laptop.vault.kvGet('own_list_json') != null,
        what: "the laptop holds its root's list");
    final before = laptop.debugSyncSession;
    expect(before, isNotNull);
    // The root's next list, as it would self-sync one: same devices, one
    // version on. Applying it rebuilds the laptop's self-sync service.
    final held = int.parse((await laptop.vault.kvGet('my_devlist_version'))!);
    final next = await (await phone.accountIdentity())
        .signDeviceList(await phone.myFullDeviceList(), held + 1);
    await laptop.debugApplyOwnDeviceList(next);
    expect(await laptop.vault.kvGet('my_devlist_version'), '${held + 1}',
        reason: 'the list was applied');
    expect(identical(laptop.debugSyncSession, before), isTrue,
        reason: 'the rebuilt service carries on the session the old one '
            'holds, not a second copy read from the vault');
  }, timeout: const Timeout(Duration(minutes: 2)));

  test('8b. a rebuilt self-sync service reads what follows an offer its '
      'predecessor answered', () async {
    // Two devices of one account, service to service: the order of steps is
    // the test's to choose, which over a relay it is not.
    final account = await AccountIdentity.generate();
    Future<(AccountIdentity, DeviceCertificate, String)> device(
        String name) async {
      final id = await ZIdentity.generate();
      final cert = await account.signDeviceCert(
          deviceEdPub: id.edPub, deviceXPub: id.xPub, deviceId: name);
      final acct = await AccountIdentity.fromEnrollment(
          accountEdPub: account.accountEdPub,
          accountMlPub: account.accountMlPub,
          deviceEdSeed: id.edSeed,
          deviceXSeed: id.xSeed,
          deviceId: name,
          deviceCert: cert);
      return (acct, cert, await cert.routingId());
    }

    Future<Vault> vaultFor(String name) async {
      final dir = await Directory.systemTemp.createTemp('z_pqc_$name');
      temps.add(dir);
      return Vault.open(rootOverride: dir);
    }

    final a = await device('a8'), b = await device('b8');
    // The lower routing id opens the channel and answers the offer; the
    // higher one offers.
    final (enc, off) = a.$3.compareTo(b.$3) < 0 ? (a, b) : (b, a);
    // Clocks long enough that nothing is said again during the test.
    const iv = PqIntervals(rekeyMs: 3600000, offerRetryMs: 3600000);
    final toEnc = <String>[], toOff = <String>[];
    final encVault = await vaultFor('enc8');
    final offSvc = DeviceSyncService(
        vault: await vaultFor('off8'),
        reliableSend: (to, payload) async => toEnc.add(payload),
        account: off.$1,
        myDevices: [enc.$2],
        pqIntervals: () => iv);
    DeviceSyncService encSvc({DeviceSyncService? replacing}) =>
        DeviceSyncService(
            vault: encVault,
            reliableSend: (to, payload) async => toOff.add(payload),
            account: enc.$1,
            myDevices: [off.$2],
            pqIntervals: () => iv,
            replacing: replacing);
    Future<void> deliver(
        List<String> queue, DeviceSyncService to, String from) async {
      final batch = [...queue];
      queue.clear();
      for (final p in batch) {
        await to.handleInbound(from, p);
      }
    }

    await offSvc.init();
    final old = encSvc();
    await old.init(); // opens the channel
    await deliver(toOff, offSvc, enc.$3); // and the offer comes back
    expect(toEnc, hasLength(1), reason: 'the offer');
    // The device list changes with the offer on its way: the new service is
    // built and ready, and the old one — which took the offer off the wire
    // first — is the one that handles it, and answers.
    final next = encSvc(replacing: old);
    await next.init();
    await deliver(toEnc, old, off.$3);
    await deliver(toOff, offSvc, enc.$3);
    expect(offSvc.isPostQuantumWith(enc.$3), isTrue,
        reason: 'the answer arrived: what the offerer sends next is mixed');
    await offSvc.mirror(
        threadRid: 'thread',
        dir: 'in',
        inner: InnerMessage(
            kind: 'text',
            mid: newMessageId(),
            ts: DateTime.now().millisecondsSinceEpoch,
            data: {'b': 'after'}));
    expect(toEnc, hasLength(1), reason: 'the mirror went out');
    final got = await next.handleInbound(off.$3, toEnc.single);
    expect(got.mirrored?.inner.data['b'], 'after',
        reason: 'the new service holds the secret the old one took on');
  }, timeout: const Timeout(Duration(minutes: 2)));
}
