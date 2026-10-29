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
//   5. a wrong digit comparison stops the link whichever side makes it: an
//      existing device whose person says the digits differ sends no
//      enrolment and links nothing; a new device whose person says so
//      installs nothing and is sent nothing of the account, and the
//      existing device, whose person said they match, links nothing
//      either, as the new device never said its person confirmed; and a
//      spent attempt leaves the new device a new code;
//   6. an enrolment carrying the account root is refused: the link fails,
//      and the screen says so;
//   7. an enrolment whose `pqdc` does not verify is refused — the `pqdc`,
//      not the link: the laptop installs its account and holds no `pqdc`,
//      then asks its root over self-sync and holds one that verifies;
//   8. the words: each screen says which device to update, in English and
//      in Spanish, and anything else that stops a link is a failure;
//   9. a device linked by v3 keeps the `pqdc` its enrolment carried: its
//      `pqseal`, which to its root is also its ask for one, brings the root
//      its sealing key, and the root sends it no other `pqdc`;
//  10. a copy of the reply that the relay delivers again while the laptop
//      holds it — as an HA relay's sweep does — says nothing: the laptop's
//      person says the digits differ and the phone's that they match, and
//      the phone sends nothing and links nothing, the reply left at the
//      relay unacknowledged;
//  11. a phone whose person confirms the digits more than its timeout after
//      the laptop's — inside the margin, while the laptop still waits, or
//      past the laptop's whole wait — sends nothing and lists nothing, and
//      the relay holds what it held before; within the timeout the laptop
//      is linked;
//  12. an enrolment that reaches the laptop after it stopped waiting is not
//      acknowledged: the phone lists nothing, and the enrolment alone waits
//      at the relay;
//  13. an enrolment the laptop cannot open — spoiled on its way — is not
//      acknowledged, and the phone lists nothing; the laptop's screen says
//      it could not open or install the account, in English and Spanish;
//  14. nor is one the laptop cannot install: the link screen installs the
//      enrolment into the vault before the ceremony acknowledges it, and an
//      install that fails part-way leaves the laptop unlisted, its screen
//      saying so in both languages, and nothing of the account in its vault
//      — no identity for its next start to take as set up;
//  15. a phone whose person confirms first, and a laptop whose person
//      confirms after the phone stopped waiting: each screen says why the
//      link stopped, nothing is linked, and the relay keeps the receipt for
//      the laptop's late acknowledgement — 192 bytes — and nothing else;
//  16. a phone that never hears the relay say it took the enrolment: one
//      whose connection closed once the enrolment had gone up says the
//      laptop did not finish — not that the connection was lost — and lists
//      nothing, the laptop having installed it; one whose connection stays
//      links the laptop on its report;
//  17. a laptop whose connection to the relay closes while it waits for the
//      enrolment says the connection was lost, at once and in both
//      languages, where it used to wait out its timer and blame the phone;
//  18. a laptop whose mailbox someone else holding the code logs in as —
//      while its person compares the digits, or before any reply — says
//      another connection took the link over, at once and in both
//      languages, and shows a new code.
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
/// by its kind (`k`). [hand], when given, says what the client is handed for
/// each frame the relay sends it: the frame, a copy of it too, another
/// frame, or nothing. [cut], when given, names the frame from the relay at
/// which that connection closes instead, both ways: the client is not
/// handed it, and the relay sees the connection go.
class Recorder {
  final HttpServer _server;
  final frames = <String, List<String>>{};
  Recorder._(this._server);

  String get url => 'ws://127.0.0.1:${_server.port}';

  static Future<Recorder> start(String relayUrl,
      {List<String> Function(String frame)? hand,
      bool Function(String frame)? cut}) async {
    final r =
        Recorder._(await HttpServer.bind(InternetAddress.loopbackIPv4, 0));
    r._server.listen((req) async {
      final down = await WebSocketTransformer.upgrade(req);
      // The Host header passes through, so the relay checks each
      // authentication against the address the client dialled.
      final up = await WebSocket.connect(relayUrl,
          headers: {'host': req.headers.value('host') ?? ''});
      var gone = false;
      down.listen((d) {
        if (gone) return;
        r._note(d, 'send');
        up.add(d);
      }, onDone: () => up.close(), onError: (Object _) => up.close());
      up.listen((d) {
        if (gone) return;
        r._note(d, 'msg');
        if (cut != null && d is String && cut(d)) {
          gone = true;
          down.close();
          up.close();
          return;
        }
        if (hand == null || d is! String) {
          down.add(d);
        } else {
          for (final f in hand(d)) {
            down.add(f);
          }
        }
      }, onDone: () {
        // The relay's own close code passes on — 4002 above all, its word
        // that another connection logged in as this one's routing id.
        final c = up.closeCode;
        down.close(c != null && c >= 3000 && c <= 4999 ? c : null);
      }, onError: (Object _) => down.close());
    });
    return r;
  }

  /// The kind (`k`) of the pairing frame a relay `msg` [frame] carries, or
  /// null for anything else.
  static String? kindOf(String frame) {
    try {
      final f = jsonDecode(frame);
      if (f is! Map || f['t'] != 'msg' || f['payload'] is! String) return null;
      final p = jsonDecode(f['payload'] as String);
      return p is Map && p['k'] is String ? p['k'] as String : null;
    } catch (_) {
      return null;
    }
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

  /// Whether [frame], from the relay, is its `sent` for the envelope [id] —
  /// its word that it took that envelope.
  static bool sentFor(String frame, String id) {
    try {
      final f = jsonDecode(frame);
      return f is Map && f['t'] == 'sent' && f['id'] == id;
    } catch (_) {
      return false;
    }
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
  // What each screen says when a link stops on time, as `app_en.arb` has
  // it, written out here so that a run against a build without these words
  // says what that build showed instead (criterion 8 holds them to the ARB).
  const phoneUnconfirmed = 'The new device did not confirm the code in '
      'time, or its person said the codes differ, so nothing was sent to it. '
      'Start again on both devices, and confirm on both within about forty '
      'seconds of each other.';
  const phoneGaveUp = 'The new device stopped waiting for this one, so '
      'nothing was sent to it. Start again on both devices, and confirm on '
      'both within about forty seconds of each other.';
  const phoneUnfinished = 'The new device did not finish linking, and this '
      'device has not added it. Start again on both devices. If the new '
      'device shows your chats anyway, it is not on your account: on it, '
      'open Settings → Wipe everything, then link it again.';
  const laptopNoEnrolment = 'Your other device did not send your account in '
      'time: its person may have said the codes differ, or confirmed too '
      'late. Start again on both devices, and confirm on both within about '
      'forty seconds of each other.';
  const laptopInstallFailed = 'This device could not open or install the '
      'account your other device sent, so it is not linked. Check that this '
      'device has space free, then start again on both devices.';
  const laptopInstallFailedEs = 'Este dispositivo no pudo abrir ni instalar '
      'la cuenta que envió tu otro dispositivo, así que no está vinculado. '
      'Comprueba que este dispositivo tiene espacio libre y vuelve a empezar '
      'en los dos dispositivos.';
  const laptopTakenOver = 'Another connection took over this link, so this '
      'device is not linked: someone else may have seen the code. Start '
      'again on both devices with the new code, and keep it to yourself. If '
      'your other device lists this one anyway, revoke it there, under '
      'Settings → Linked devices.';
  const laptopTakenOverEs = 'Otra conexión se hizo cargo de esta '
      'vinculación, así que este dispositivo no está vinculado: puede que '
      'alguien más haya visto el código. Vuelve a empezar en los dos '
      'dispositivos con el código nuevo y no se lo enseñes a nadie. Si aun '
      'así tu otro dispositivo muestra este en su lista, revócalo allí, en '
      'Ajustes → Dispositivos vinculados.';
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
  /// holds, connecting to the relay — or to [url], a front before it. The
  /// log is off: what is under test is not the log. Receipts leave within a
  /// second, so a relay that has gone quiet does so soon.
  Future<Person> boot(Directory dir, String name,
      {Vault? vault, String? url}) async {
    final v = vault ?? await Vault.open(rootOverride: dir);
    final id = await ZIdentity.fromJson(
        (jsonDecode((await v.kvGet('identity'))!) as Map)
            .cast<String, Object?>());
    final svc = await ChatService.init(
        vault: v,
        identity: id,
        displayName: await v.kvGet('display_name') ?? name,
        transport: Transport(identity: id, serverUrl: url ?? relayUrl()),
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

  Future<Person> person(String name, {String? url}) async {
    final dir = await tempDir(name);
    final vault = await Vault.open(rootOverride: dir);
    await vault.kvPut(
        'identity', jsonEncode((await ZIdentity.generate()).toJson()));
    await vault.kvPut('display_name', name);
    return boot(dir, name, vault: vault, url: url);
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

  /// What the phone's screen says for [outcome], what `hostDeviceLink`
  /// returned or threw, as `HostLinkScreen` shows it, in English.
  String phoneScreen(Object? outcome) => switch (outcome) {
        true => en.linkDone,
        false => en.linkCancelled,
        _ => hostLinkFailureText(en, outcome!),
      };

  /// What the laptop's screen says for [outcome], what `NewDeviceLink.run`
  /// returned or threw, as `NewDeviceLinkScreen` shows it, in English.
  String laptopScreen(Object? outcome) => switch (outcome) {
        PairingResult() => '(installed)',
        null => en.linkCancelled,
        _ => newDeviceLinkFailureText(en, outcome),
      };

  /// What the relay charges an envelope whose payload is [payload] against
  /// its store (`server.js`, `envelopeSize`): the payload as the store holds
  /// it, JSON-escaped, and 256 bytes for the entry around it.
  int charged(String payload) => jsonEncode(payload).length - 2 + 256;

  /// The kinds of what [left] holds, in order.
  List<Object?> kinds(List<RelayInbound> left) =>
      [for (final e in left) (jsonDecode(e.payload) as Map)['k']];

  /// [frame], a relay `msg` carrying `enroll-v3`, with one base64 character
  /// of its sealed blob changed, so the enrolment no longer opens.
  String spoiled(String frame) {
    final f = (jsonDecode(frame) as Map).cast<String, Object?>();
    final p = (jsonDecode(f['payload'] as String) as Map).cast<String, Object?>();
    final blob = p['blob'] as String;
    final i = blob.length ~/ 2;
    p['blob'] = blob.replaceRange(i, i + 1, blob[i] == 'A' ? 'B' : 'A');
    return jsonEncode({...f, 'payload': jsonEncode(p)});
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

  test('5. a wrong digit comparison stops the link whichever side makes it',
      () async {
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
        timeout: const Duration(seconds: 6),
        margin: const Duration(seconds: 1),
      );
    } catch (e) {
      waited = e;
    }
    expect(await hosted, isFalse, reason: 'the phone links nothing');
    expect(waited, isA<PairingAbort>(),
        reason: 'and sends no enrolment for the laptop to wait for');
    expect(laptopScreen(waited), laptopNoEnrolment,
        reason: "the laptop's screen says the account never came");
    expect(await alice.svc.linkedDevices(), isEmpty);
    expect(await alice.svc.ownDeviceListVersion(), listBefore);
    expect(await peek(await RelayPairing.relayIdentityV3(
            PairingCode.parse(code), 'i')),
        isEmpty,
        reason: 'no enrolment went to the laptop');
    expect(n.code, isNot(code),
        reason: 'its KEM key spent, the next attempt is a new ceremony');

    // The laptop's person says they differ, and the phone's that they
    // match. The phone waits for the laptop to say its person confirmed
    // too — its acknowledgement of the reply — and it never comes: nothing
    // of the account is sent, and nothing is linked.
    final m = await NewDeviceLink.create();
    final mCode = PairingCode.parse(m.code);
    final hostedToo = alice.svc
        .hostDeviceLink(m.code, confirmSas: (_) async => true)
        .then<Object?>((r) => r, onError: (Object e) => e);
    expect(await m.run(relayUrl: relayUrl(), confirm: (_) async => false),
        isNull,
        reason: 'a new device that says they differ installs nothing');
    final phoneToo = await hostedToo;
    expect(phoneToo, isA<PairingAbort>(),
        reason: 'and the phone, whose person said they match, links '
            'nothing: the laptop never said its person confirmed');
    expect(phoneScreen(phoneToo), phoneUnconfirmed,
        reason: "the phone's screen says the new device did not confirm");
    expect(await alice.svc.linkedDevices(), isEmpty);
    expect(await alice.svc.ownDeviceListVersion(), listBefore);
    final left = await peek(await RelayPairing.relayIdentityV3(mCode, 'i'));
    expect([for (final e in left) (jsonDecode(e.payload) as Map)['k']],
        isNot(contains('enroll-v3')),
        reason: 'no enrolment went to a device whose person refused');
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
        isA<PairingInstallFailed>().having(
            (e) => e.cause,
            'cause',
            isA<FormatException>().having((e) => e.message, 'message',
                'a v3 enrolment never carries the account root')),
        reason: 'the new device refuses it, so there is nothing to install');
    expect(newDeviceLinkFailureText(en, refused!), en.linkInstallFailed,
        reason: 'and its screen says it could not open or install the '
            'account');
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
      // Anything else stops a link as a failure, never as a version: a
      // timeout, too, in words of its own (below).
      const abort = PairingAbort('the opening does not match the commitment');
      expect(hostLinkFailureText(l, abort), l.linkFailed(abort.message));
      expect(newDeviceLinkFailureText(l, abort), l.linkFailed(abort.message));
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

    // Each way a link stops on time has words of its own on the screen it
    // stops on, and so do a timeout and a lost connection: never a raw
    // exception, in either language.
    for (final l in [en, es]) {
      expect(hostLinkFailureText(l, const PairingPeerUnconfirmed()),
          l.linkPeerUnconfirmed);
      expect(hostLinkFailureText(l, const PairingPeerGaveUp(Duration.zero)),
          l.linkPeerGaveUp);
      expect(hostLinkFailureText(l, const PairingPeerUnfinished()),
          l.linkPeerUnfinished);
      expect(newDeviceLinkFailureText(l, const PairingNoEnrolment('x')),
          l.linkNoEnrolment);
      final timeout = TimeoutException('pairing: no "open-v3" frame arrived');
      expect(hostLinkFailureText(l, timeout), l.linkTimedOut);
      expect(newDeviceLinkFailureText(l, timeout), l.linkTimedOut);
      final gone = RelayException('connection closed');
      expect(hostLinkFailureText(l, gone), l.linkConnectionLost);
      expect(newDeviceLinkFailureText(l, gone), l.linkConnectionLost);
      // An enrolment that came and did not open or install, and a mailbox
      // someone else holding the code logged in as.
      expect(
          newDeviceLinkFailureText(
              l, PairingInstallFailed(const FormatException('x'))),
          l.linkInstallFailed);
      expect(newDeviceLinkFailureText(l, const PairingTakenOver()),
          l.linkTakenOver);
      expect(hostLinkFailureText(l, const PairingTakenOver()),
          l.linkHostTakenOver);
    }
    expect(en.linkPeerUnconfirmed, phoneUnconfirmed);
    expect(en.linkPeerGaveUp, phoneGaveUp);
    expect(en.linkPeerUnfinished, phoneUnfinished);
    expect(en.linkNoEnrolment, laptopNoEnrolment);
    expect(en.linkInstallFailed, laptopInstallFailed);
    expect(es.linkInstallFailed, laptopInstallFailedEs);
    expect(en.linkTakenOver, laptopTakenOver);
    expect(es.linkTakenOver, laptopTakenOverEs);
    for (final (a, b) in [
      (es.linkPeerUnconfirmed, en.linkPeerUnconfirmed),
      (es.linkPeerGaveUp, en.linkPeerGaveUp),
      (es.linkPeerUnfinished, en.linkPeerUnfinished),
      (es.linkNoEnrolment, en.linkNoEnrolment),
      (es.linkTimedOut, en.linkTimedOut),
      (es.linkConnectionLost, en.linkConnectionLost),
      (es.linkInstallFailed, en.linkInstallFailed),
      (es.linkTakenOver, en.linkTakenOver),
      (es.linkHostTakenOver, en.linkHostTakenOver),
    ]) {
      expect(a, isNot(b), reason: 'the Spanish has words of its own');
    }
    expect(es.linkPeerGaveUp, contains('dejó de esperar'));
    // A new device that installed the account unlisted is wiped, not
    // reinstalled, and the phone names the setting as Settings shows it;
    // a new device taken over says where the phone lists its devices.
    for (final l in [en, es]) {
      expect(l.linkPeerUnfinished, contains('${l.stSettings} → ${l.stWipe}'));
      expect(l.linkHostTakenOver, contains('${l.stSettings} → ${l.stWipe}'));
      expect(l.linkTakenOver,
          contains('${l.stSettings} → ${l.stLinkedDevices}'));
    }
  });

  test(
      '9. a device linked by v3 keeps the pqdc its enrolment carried, and its '
      'root sends it no other', () async {
    final alice = await person('Alice9');
    final dave = await person('Dave9');
    await pairUp(alice, dave);
    final n = await NewDeviceLink.create();
    final hosted =
        alice.svc.hostDeviceLink(n.code, confirmSas: (_) async => true);
    final result =
        await n.run(relayUrl: relayUrl(), confirm: (_) async => true);
    expect(result, isNotNull);
    expect(await hosted, isTrue);
    final sent = result!.data.pqdc;
    expect(sent, isNotNull, reason: 'the enrolment carried a pqdc');

    final (dir, vault) = await installed('Alice9-laptop', result, n);
    final laptop = await boot(dir, 'Alice9-laptop', vault: vault);
    // The `dir` of every self-sync mirror the laptop is sent.
    final dirs = <String>[];
    laptop.svc.debugOnDecrypted = (path, from, dec) {
      if (path != 'sync') return false;
      try {
        final j = jsonDecode(utf8.decode(dec.plaintext));
        if (j is Map && j['dir'] is String) dirs.add(j['dir'] as String);
      } catch (_) {}
      return false;
    };
    await connected([laptop]);
    expect(b64(laptop.svc.debugOwnPqdc!), b64(sent!),
        reason: 'the premise: it holds the pqdc its enrolment carried');

    // Its pqseal reaches the root riding what it sends while messages flow:
    // the announcement of its sealing key, and, to a root, its ask for its
    // pqdc.
    var i = 0;
    await waitFor(() async {
      final k = i++;
      await laptop.svc.sendText(dave.svc.myRid, 'l$k');
      await dave.svc.sendText(alice.svc.myRid, 'd$k');
      await arrived(alice, dave.svc.myRid, 'l$k');
      await arrived(laptop, dave.svc.myRid, 'd$k');
      return alice.svc.debugPqSealOf(laptop.svc.myRid) != null;
    }, timeout: const Duration(seconds: 90),
        what: "the root holds the laptop's sealing key");
    expect(b64(alice.svc.debugPqSealOf(laptop.svc.myRid)!),
        b64(n.sealingKey.ek));

    // A negative check over a window: three of the root's own messages
    // reach the laptop over self-sync after the root took the pqseal. The
    // root answers a pqseal as it takes it, so an answer would be in by the
    // time the third of these is.
    for (var k = 0; k < 3; k++) {
      await alice.svc.sendText(dave.svc.myRid, 'p$k');
      await arrived(laptop, dave.svc.myRid, 'p$k');
    }
    expect(dirs, isNot(contains('pqdc')),
        reason: 'the root sent the laptop no pqdc over self-sync');
    expect(b64(laptop.svc.debugOwnPqdc!), b64(sent),
        reason: 'it holds the one its enrolment carried');
    expect(await laptop.vault.kvGet(ownPqdcKey), b64(sent));
  });

  test(
      '10. a copy of the reply delivered again while the laptop holds it '
      'says nothing: nothing is sent, nothing linked', () async {
    final alice = await person('Alice10');
    await connected([alice]);
    alice.svc.linkTimeout = const Duration(seconds: 6);
    final listBefore = await alice.svc.ownDeviceListVersion();
    // The laptop connects through a front that hands it the reply twice, as
    // an HA relay's sweep sends a mailbox that has not moved again (§12.5).
    var replies = 0;
    final tap = await Recorder.start(relayUrl(), hand: (f) {
      if (Recorder.kindOf(f) != 'reply-v3') return [f];
      replies += 2;
      return [f, f];
    });
    try {
      final n = await NewDeviceLink.create();
      final code = PairingCode.parse(n.code);
      var phoneConfirmed = false;
      final hosted = alice.svc
          .hostDeviceLink(n.code, confirmSas: (_) async => phoneConfirmed = true)
          .then<Object?>((r) => r, onError: (Object e) => e);
      final result = await n.run(
          relayUrl: tap.url,
          confirm: (_) async {
            // Both copies were handed over before the laptop sent the
            // opening the phone's digits came from.
            await waitUntil(() => replies == 2 && phoneConfirmed,
                what: 'both copies of the reply in, and the phone confirmed');
            return false;
          });
      expect(result, isNull, reason: "the laptop's person said they differ");
      final phone = await hosted;
      expect(phone, isA<PairingAbort>(),
          reason: 'the phone hears no confirmation: it sends nothing and '
              'links nothing');
      expect(phoneScreen(phone), phoneUnconfirmed);
      expect(await alice.svc.linkedDevices(), isEmpty);
      expect(await alice.svc.ownDeviceListVersion(), listBefore);
      final left = await peek(await RelayPairing.relayIdentityV3(code, 'i'));
      expect([for (final e in left) (jsonDecode(e.payload) as Map)['k']],
          ['reply-v3'],
          reason: 'the reply waits at the relay, unacknowledged, and no '
              'enrolment was sent');
    } finally {
      await tap.close();
    }
  });

  test(
      "11. a phone whose person confirms too long after the laptop's sends "
      'nothing and lists nothing; within the timeout the laptop is linked',
      () async {
    final alice = await person('Alice11');
    await connected([alice]);
    const timeout = Duration(seconds: 3), margin = Duration(seconds: 2);
    alice.svc.linkTimeout = timeout;
    alice.svc.linkMargin = margin;
    final listBefore = await alice.svc.ownDeviceListVersion();
    // The people's delays are the scenario: each stands for a person
    // deliberating, not for a wait on anything.
    for (final (after, linked) in [
      (const Duration(milliseconds: 3500), false), // inside the margin
      (const Duration(milliseconds: 5500), false), // past the laptop's wait
      (const Duration(milliseconds: 1500), true), // within the timeout
    ]) {
      final before = await held();
      final n = await NewDeviceLink.create();
      final code = PairingCode.parse(n.code);
      DateTime? laptopAt;
      final hosted = alice.svc
          .hostDeviceLink(n.code, confirmSas: (_) async {
            await waitUntil(() => laptopAt != null,
                what: "the laptop's person confirmed");
            await Future<void>.delayed(
                laptopAt!.add(after).difference(DateTime.now()));
            return true;
          })
          .then<Object?>((r) => r, onError: (Object e) => e);
      final laptop = await n
          .run(
            relayUrl: relayUrl(),
            confirm: (_) async {
              laptopAt = DateTime.now();
              return true;
            },
            timeout: timeout,
            margin: margin,
          )
          .then<Object?>((r) => r, onError: (Object e) => e);
      final phone = await hosted;
      final what = "the phone's person ${after.inMilliseconds} ms after the "
          "laptop's";
      if (linked) {
        expect(laptop, isA<PairingResult>(), reason: what);
        expect(phone, isTrue, reason: what);
        expect(await alice.svc.linkedDevices(), hasLength(1), reason: what);
        continue;
      }
      expect(phone, isA<PairingAbort>(),
          reason: '$what: the phone sends nothing and lists nothing');
      expect('$phone', contains('stopped waiting'), reason: what);
      expect(phoneScreen(phone), phoneGaveUp, reason: what);
      expect(laptop, isA<PairingAbort>(),
          reason: '$what: the laptop stopped waiting');
      expect(laptopScreen(laptop), laptopNoEnrolment, reason: what);
      expect(await alice.svc.linkedDevices(), isEmpty, reason: what);
      expect(await alice.svc.ownDeviceListVersion(), listBefore, reason: what);
      await waitFor(() async => await held() == before,
          what: '$what: the relay to hold what it held before');
      // ignore: avoid_print
      print('$what: the relay held $before before and ${await held()} after '
          '(envelopes, bytes)');
      for (final who in await ceremonyMailboxes(code)) {
        expect(await peek(who), isEmpty, reason: what);
      }
    }
  });

  test(
      '12. an enrolment that reaches the laptop after it stopped waiting is '
      'not acknowledged, and the phone lists nothing', () async {
    final alice = await person('Alice12');
    await connected([alice]);
    // The phone believes the laptop waits longer than it does — six seconds
    // and a margin of one, against the laptop's two and half of one — and
    // its person confirms three seconds after the laptop's.
    alice.svc.linkTimeout = const Duration(seconds: 6);
    alice.svc.linkMargin = const Duration(seconds: 1);
    final listBefore = await alice.svc.ownDeviceListVersion();
    final before = await held();
    final n = await NewDeviceLink.create();
    final code = PairingCode.parse(n.code);
    DateTime? laptopAt;
    final hosted = alice.svc
        .hostDeviceLink(n.code, confirmSas: (_) async {
          await waitUntil(() => laptopAt != null,
              what: "the laptop's person confirmed");
          await Future<void>.delayed(laptopAt!
              .add(const Duration(seconds: 3))
              .difference(DateTime.now()));
          return true;
        })
        .then<Object?>((r) => r, onError: (Object e) => e);
    final laptop = await n
        .run(
          relayUrl: relayUrl(),
          confirm: (_) async {
            laptopAt = DateTime.now();
            return true;
          },
          timeout: const Duration(seconds: 2),
          margin: const Duration(milliseconds: 500),
        )
        .then<Object?>((r) => r, onError: (Object e) => e);
    final phone = await hosted;
    expect(phone, isA<PairingAbort>(),
        reason: 'the phone lists nothing: the laptop never said it installed '
            'the enrolment');
    expect('$phone', contains('did not finish linking'));
    expect(phoneScreen(phone), phoneUnfinished);
    expect(laptop, isA<PairingAbort>(),
        reason: 'the laptop stopped waiting for the enrolment');
    expect(laptopScreen(laptop), laptopNoEnrolment);
    expect(await alice.svc.linkedDevices(), isEmpty);
    expect(await alice.svc.ownDeviceListVersion(), listBefore);
    final left = await peek(await RelayPairing.relayIdentityV3(code, 'i'));
    expect(kinds(left), ['enroll-v3'],
        reason: 'the enrolment waits at the relay, unacknowledged');
    final now = await held();
    // ignore: avoid_print
    print('an enrolment that came too late: the relay held $before before '
        'and $now after (envelopes, bytes)');
    expect(now, (before.$1 + 1, before.$2 + charged(left.single.payload)),
        reason: 'the enrolment alone, for QUEUE_TTL_HOURS');
  });

  test(
      '13. an enrolment the laptop cannot open is not acknowledged, and the '
      'phone lists nothing', () async {
    final alice = await person('Alice13');
    await connected([alice]);
    alice.svc.linkTimeout = const Duration(seconds: 3);
    alice.svc.linkMargin = const Duration(seconds: 1);
    final listBefore = await alice.svc.ownDeviceListVersion();
    // The laptop connects through a front that spoils the sealed blob on its
    // way: one base64 character changed.
    final tap = await Recorder.start(relayUrl(),
        hand: (f) => [Recorder.kindOf(f) == 'enroll-v3' ? spoiled(f) : f]);
    try {
      final n = await NewDeviceLink.create();
      final code = PairingCode.parse(n.code);
      final hosted = alice.svc
          .hostDeviceLink(n.code, confirmSas: (_) async => true)
          .then<Object?>((r) => r, onError: (Object e) => e);
      final laptop = await n
          .run(
            relayUrl: tap.url,
            confirm: (_) async => true,
            timeout: const Duration(seconds: 3),
            margin: const Duration(seconds: 1),
          )
          .then<Object?>((r) => r, onError: (Object e) => e);
      expect(laptop, isNot(isA<PairingResult>()),
          reason: 'the spoiled enrolment does not open');
      expect(laptopScreen(laptop), laptopInstallFailed,
          reason: "the laptop's screen says it could not open the account, "
              'in words, not in the error that stopped it');
      expect(newDeviceLinkFailureText(es, laptop!), laptopInstallFailedEs,
          reason: 'and in Spanish');
      final phone = await hosted;
      expect(phone, isA<PairingAbort>(),
          reason: 'the phone lists nothing: the laptop never said it '
              'installed the enrolment');
      expect('$phone', contains('did not finish linking'));
      expect(phoneScreen(phone), phoneUnfinished);
      expect(await alice.svc.linkedDevices(), isEmpty);
      expect(await alice.svc.ownDeviceListVersion(), listBefore);
      expect(kinds(await peek(await RelayPairing.relayIdentityV3(code, 'i'))),
          ['enroll-v3'],
          reason: 'the enrolment waits at the relay, unacknowledged');
    } finally {
      await tap.close();
    }
  });

  test(
      '14. an enrolment the laptop cannot install is not acknowledged, and '
      'the phone lists nothing', () async {
    final alice = await person('Alice14');
    await connected([alice]);
    alice.svc.linkTimeout = const Duration(seconds: 3);
    alice.svc.linkMargin = const Duration(seconds: 1);
    final listBefore = await alice.svc.ownDeviceListVersion();
    final n = await NewDeviceLink.create();
    final code = PairingCode.parse(n.code);
    final hosted = alice.svc
        .hostDeviceLink(n.code, confirmSas: (_) async => true)
        .then<Object?>((r) => r, onError: (Object e) => e);
    // The link screen installs the enrolment as the ceremony's last step,
    // as here; and here the laptop's vault refuses a write part-way through
    // it — the row for the device that linked it, which comes after the
    // account and before the contacts.
    final vault = await Vault.open(rootOverride: await tempDir('Alice14-l'));
    await vault.db.execute('CREATE TRIGGER refuse BEFORE INSERT ON kv '
        "WHEN NEW.k = 'p:my_devices' "
        "BEGIN SELECT RAISE(ABORT, 'the vault refused the write'); END");
    var installing = false;
    final laptop = await n
        .run(
          relayUrl: relayUrl(),
          confirm: (_) async => true,
          timeout: const Duration(seconds: 3),
          margin: const Duration(seconds: 1),
          install: (result) async {
            installing = true;
            await setRelayUrl(vault, relayUrl(), acceptedInsecure: true);
            await installEnrollment(vault, result, sealingKey: n.sealingKey);
          },
        )
        .then<Object?>((r) => r, onError: (Object e) => e);
    expect(installing, isTrue, reason: 'the enrolment opened, and came to '
        'be installed');
    expect('$laptop', contains('the vault refused the write'),
        reason: 'what stopped it was the install');
    // Nothing of the account is left in the vault, the identity above all:
    // a vault that holds one starts as a device that is set up. (Compared
    // with null rather than shown: it is a device's seeds.)
    expect(await vault.kvGet('identity') == null, isTrue,
        reason: 'no identity for its next start to take as set up');
    expect(await vault.kvGet('account') == null, isTrue,
        reason: 'nor the account, written before the refused row');
    expect(laptopScreen(laptop), laptopInstallFailed,
        reason: "the laptop's screen says it could not install the account, "
            'in words, not in the error that stopped it');
    expect(newDeviceLinkFailureText(es, laptop!), laptopInstallFailedEs,
        reason: 'and in Spanish');
    final phone = await hosted;
    expect(phone, isA<PairingAbort>(),
        reason: 'the phone lists nothing: the laptop never said it installed '
            'the enrolment');
    expect('$phone', contains('did not finish linking'));
    expect(phoneScreen(phone), phoneUnfinished);
    expect(await alice.svc.linkedDevices(), isEmpty);
    expect(await alice.svc.ownDeviceListVersion(), listBefore);
    expect(kinds(await peek(await RelayPairing.relayIdentityV3(code, 'i'))),
        ['enroll-v3'],
        reason: 'the enrolment waits at the relay, unacknowledged');
  });

  test(
      "15. a laptop whose person confirms after the phone stopped waiting: "
      'each screen says why, and nothing is linked', () async {
    final alice = await person('Alice15');
    await connected([alice]);
    alice.svc.linkTimeout = const Duration(seconds: 3);
    alice.svc.linkMargin = const Duration(seconds: 1);
    final listBefore = await alice.svc.ownDeviceListVersion();
    final before = await held();
    final n = await NewDeviceLink.create();
    DateTime? phoneAt;
    final hosted = alice.svc
        .hostDeviceLink(n.code, confirmSas: (_) async {
          phoneAt = DateTime.now();
          return true;
        })
        .then<Object?>((r) => r, onError: (Object e) => e);
    final laptop = await n
        .run(
          relayUrl: relayUrl(),
          confirm: (_) async {
            // The laptop's person deliberates until a second after the
            // phone, which waits three seconds, has stopped waiting.
            await waitUntil(() => phoneAt != null,
                what: "the phone's person confirmed");
            await Future<void>.delayed(phoneAt!
                .add(const Duration(seconds: 4))
                .difference(DateTime.now()));
            return true;
          },
          timeout: const Duration(seconds: 3),
          margin: const Duration(seconds: 1),
        )
        .then<Object?>((r) => r, onError: (Object e) => e);
    final phone = await hosted;
    expect(phoneScreen(phone), phoneUnconfirmed,
        reason: "the phone's person confirmed, and the laptop's had not");
    expect(laptopScreen(laptop), laptopNoEnrolment,
        reason: 'the laptop confirmed, and no account came');
    expect(await alice.svc.linkedDevices(), isEmpty);
    expect(await alice.svc.ownDeviceListVersion(), listBefore);
    // The laptop acknowledged the reply after the phone had gone, so the
    // relay's receipt for it waits for the phone's ceremony mailbox, which
    // nobody reads again, for QUEUE_TTL_HOURS: 192 bytes, as the relay
    // charges a receipt.
    final now = await held();
    // ignore: avoid_print
    print('a laptop that confirmed after the phone stopped waiting: the '
        'relay held $before before and $now after (envelopes, bytes)');
    expect(now, (before.$1 + 1, before.$2 + 192));
  });

  test(
      '16. a phone that never hears the relay take its enrolment says the '
      "laptop did not finish when its connection has gone, and links on the "
      "laptop's report when it has not", () async {
    // A front before the phone drops the relay's `sent` for the enrolment,
    // as a slow connection that takes longer than a send's twenty seconds to
    // put the enrolment up keeps it from the phone in time; the first time
    // it closes the phone's connection with it, once the enrolment has gone
    // up.
    for (final cut in [true, false]) {
      final what =
          cut ? 'its connection closed with the `sent`' : 'no `sent`';
      final rec = await Recorder.start(relayUrl(),
          hand: (f) => Recorder.sentFor(f, 'z-pair-enroll') ? const [] : [f],
          cut: cut ? (f) => Recorder.sentFor(f, 'z-pair-enroll') : null);
      try {
        final alice = await person('Alice16${cut ? 'a' : 'b'}', url: rec.url);
        await connected([alice]);
        alice.svc.linkTimeout = const Duration(seconds: 3);
        alice.svc.linkMargin = const Duration(seconds: 1);
        final n = await NewDeviceLink.create();
        final hosted = alice.svc
            .hostDeviceLink(n.code, confirmSas: (_) async => true)
            .then<Object?>((r) => r, onError: (Object e) => e);
        final laptop = await n
            .run(
              relayUrl: relayUrl(),
              confirm: (_) async => true,
              timeout: const Duration(seconds: 3),
              margin: const Duration(seconds: 1),
            )
            .then<Object?>((r) => r, onError: (Object e) => e);
        expect(laptop, isA<PairingResult>(),
            reason: '$what: the laptop installed the enrolment, and said so');
        final phone = await hosted;
        if (cut) {
          expect(phoneScreen(phone), phoneUnfinished,
              reason: '$what: the phone cannot tell whether the laptop '
                  'finished, and says what it says of any enrolment with no '
                  'report — not that the connection was lost');
          expect(await alice.svc.linkedDevices(), isEmpty, reason: what);
          continue;
        }
        expect(phone, isTrue, reason: '$what: the report links the laptop');
        expect(await alice.svc.linkedDevices(), hasLength(1), reason: what);
      } finally {
        await rec.close();
      }
    }
  });

  test(
      '17. a laptop whose connection to the relay closes while it waits for '
      'the enrolment says so at once, in both languages', () async {
    final alice = await person('Alice17');
    await connected([alice]);
    const timeout = Duration(seconds: 3), margin = Duration(seconds: 1);
    alice.svc.linkTimeout = timeout;
    alice.svc.linkMargin = margin;
    final listBefore = await alice.svc.ownDeviceListVersion();
    // The laptop connects through a front that closes its connection as the
    // enrolment comes down it.
    final tap = await Recorder.start(relayUrl(),
        cut: (f) => Recorder.kindOf(f) == 'enroll-v3');
    try {
      final n = await NewDeviceLink.create();
      final hosted = alice.svc
          .hostDeviceLink(n.code, confirmSas: (_) async => true)
          .then<Object?>((r) => r, onError: (Object e) => e);
      final waited = Stopwatch();
      final laptop = await n
          .run(
            relayUrl: tap.url,
            confirm: (_) async {
              waited.start();
              return true;
            },
            timeout: timeout,
            margin: margin,
          )
          .then<Object?>((r) => r, onError: (Object e) => e);
      waited.stop();
      expect(laptopScreen(laptop), en.linkConnectionLost,
          reason: "the laptop's own connection went: it says so, and does "
              'not blame the phone for an account that never came');
      expect(newDeviceLinkFailureText(es, laptop!), es.linkConnectionLost);
      expect(waited.elapsed, lessThan(timeout),
          reason: 'at once, and not when its wait for the enrolment, '
              '${timeout + margin}, ran out');
      final phone = await hosted;
      expect(phoneScreen(phone), phoneUnfinished,
          reason: 'the phone heard nothing installed');
      expect(await alice.svc.linkedDevices(), isEmpty);
      expect(await alice.svc.ownDeviceListVersion(), listBefore);
    } finally {
      await tap.close();
    }
  });

  test(
      '18. a laptop whose mailbox someone else holding the code logs in as '
      'says so at once, in both languages, and shows a new code', () async {
    final alice = await person('Alice18');
    await connected([alice]);
    const timeout = Duration(seconds: 3), margin = Duration(seconds: 1);
    alice.svc.linkTimeout = timeout;
    alice.svc.linkMargin = margin;
    // While the laptop's person compares the digits, and before any reply
    // has reached the laptop: the other login is in by the time the laptop
    // next looks at its mailbox.
    for (final whileComparing in [true, false]) {
      final what = whileComparing
          ? 'taken over while its person compared the digits'
          : 'taken over before any reply';
      final n = await NewDeviceLink.create();
      final code = n.code;
      final mailbox =
          await RelayPairing.relayIdentityV3(PairingCode.parse(code), 'i');
      // The laptop connects through a front that keeps what it sends, so
      // the test sees its commitment leave; the relay's close code passes
      // on.
      final tap = await Recorder.start(relayUrl());
      final comparing = Completer<void>(), loggedIn = Completer<void>();
      Future<Object?>? hosted;
      if (whileComparing) {
        hosted = alice.svc
            .hostDeviceLink(code, confirmSas: (_) async => true)
            .then<Object?>((r) => r, onError: (Object e) => e);
      }
      final waited = Stopwatch();
      final laptop = n
          .run(
            relayUrl: tap.url,
            confirm: (_) async {
              comparing.complete();
              await loggedIn.future;
              waited.start();
              return true;
            },
            timeout: timeout,
            margin: margin,
          )
          .then<Object?>((r) => r, onError: (Object e) => e);
      if (whileComparing) {
        await comparing.future;
      } else {
        await waitUntil(() => tap.frames.containsKey('commit-v3'),
            what: "$what: the laptop's commitment sent");
        waited.start();
      }
      final other = await RelayClient.connect(relayUrl(), mailbox);
      final sub = other.messages
          .listen((m) => other.ackReceived(id: m.id, from: m.from));
      loggedIn.complete();
      try {
        final outcome = await laptop;
        waited.stop();
        expect(laptopScreen(outcome), laptopTakenOver, reason: what);
        expect(newDeviceLinkFailureText(es, outcome!), laptopTakenOverEs,
            reason: what);
        expect(waited.elapsed, lessThan(timeout),
            reason: '$what: at once, and not when a wait ran out');
        expect(n.code, isNot(code),
            reason: '$what: someone else holds the code, and the next '
                'attempt is a new one');
        if (hosted != null) {
          // What §10.2 says is left: the phone took the other login's
          // acknowledgements for the laptop's word.
          final phone = await hosted;
          // ignore: avoid_print
          print('$what: the phone, on the other login\'s acknowledgements: '
              '${phone == true ? 'lists the laptop' : phone}');
        }
      } finally {
        await sub.cancel();
        await other.close();
        await tap.close();
      }
    }
  });
}
