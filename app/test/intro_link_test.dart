// Public introduction links in the app (phase 39; ADR 0032 §3–§4; PROTOCOL
// §21.9): the owner's side and the opener's, built and switched off behind
// `introLinksEnabled`. Real ChatService instances and the real relay
// (server/server.js) on loopback, every account reaching it through a tap
// that writes down each frame of each connection, so what the relay saw is
// asserted directly. No handle log is configured unless a criterion says so:
// a link needs none. Links are turned on through `ChatService.init`'s
// `introLinks`, the seam the release that turns them on does not need.
//
// Criteria, each a test below:
//   1. making: on the main device, with no handle log configured, one link
//      per account, printed at the work chosen — 16 to 24 bits, 20 unless
//      chosen — kept sealed as `intro_link`, and nothing sent: no frame, no
//      connection as its mailbox; a second link is refused, and so is a link
//      on a linked device;
//   2. the screens: Settings › Your public link, the work offered from 16 to
//      24 with 20 chosen, and once made the link, its QR, a copy of it and a
//      copy for web pages that carries rel="noreferrer"; a linked device is
//      told only the main device holds one; in both languages;
//   3. draining: §21.8's drain on a connection of its own, authenticated as
//      the link's mailbox and never the account's, flagged with the work
//      asked, never registering push and never sending, on a timer of its
//      own — the link drains, on its timer, where no handle exists;
//   4. each stamp is counted at the work printed on the link, not the work
//      asked since: asked more, the relay refuses a stamp of the printed
//      work; once it has lost the flag it takes one, and the owner files it,
//      while a request with no stamp it took then is dropped;
//   5. a request through the link is filed "via your public link" — on the
//      Requests screen too, in both languages — and accepting it sends `ia`
//      signed with the seed of the mailbox it reached, which verifies under
//      the link's intro and no other;
//   6. one cap of 100 for requests through the handle and the link
//      together: past it the oldest unseen goes, whichever door it came
//      through, and a request made with the code stays;
//   7. asking more work re-flags the mailbox at once, from the printed work
//      up to 24 and no further;
//   8. replacing: a new mailbox, drained from then on; the old one read once
//      more without `intro`, so its flag lapses, and never again; a request
//      that reached it before is still accepted with its seed — kept in the
//      link's own row and nowhere among the handle's, written with the new
//      link before that last read, so that it is there after an app killed
//      in the middle of the read is started again — which then goes; one
//      sent to it after is never filed;
//   9. withdrawing: no link, and the link's row kept with the old seed while
//      a pending request needs it; the mailbox read once more without
//      `intro` and never again; a request that reached it before is still
//      accepted with its seed, after a kill in the middle of that read too;
//      and a new link can be made after;
//  10. backup and restore: the archive carries the link as `introlink` with
//      "keep":1; a restore brings it back held — nothing connects as its
//      mailbox and nothing sent to it is filed, and Settings says so — until
//      its person says to use it again, when it is drained and what waited is
//      filed; and the seed of a link since replaced that a pending request
//      needs rides in that record and in no `handle` record, so a build that
//      knows handles but not links finds none among its handle's seeds, and
//      a restore accepts that request with `ia`;
//  11. with `introLinksEnabled` false — this build's constant — none of it is
//      reachable: no Settings row; a link the vault holds is neither loaded,
//      shown nor drained, and nothing connects as its mailbox; making one is
//      refused; a request recorded as through a link is an ordinary one; the
//      Paste and Scan tabs, a QR image and the handle search parse no link —
//      a scanned link is passed over and the code beside it read — and a
//      tapped one is ignored; nothing is sent through one; and an acceptance
//      is never matched to a request a backup says went through one;
//  12. held: a link pasted, scanned, read from a QR image, typed into the
//      handle search or tapped is put in front of its person on a screen
//      saying that whoever made it will see their name and contact code and
//      that a link verifies nothing, and nothing is sent and their app
//      opens no connection until they press Send request (another app's
//      link read in the meantime is that app's connection, not theirs) —
//      then one request, to the link's mailbox, on a connection opened for
//      it alone; with no handle log configured, and a handle that begins as
//      a link does still a handle; the Scan tab's own scanner and Open a QR
//      image driven, a stand-in camera and picker behind them;
//  13. requests through links share the outgoing list's 20 entries with
//      handles', the oldest going first whichever it is, three ids each, and
//      a link's entry is stored as its code with no handle;
//  14. on `pow_required`, one stamp more for the relay's day at the greater
//      of the printed work and the refusal's bits, then stop: a sender whose
//      stamps never pass sends twice, and a refusal asking more than 28 bits
//      is answered at the printed work;
//  15. an acceptance whose `ia` verifies under the link's intro adds the
//      owner unverified, says "accepted through their public link — compare
//      safety numbers" in both languages, and the two can talk — the link
//      made, drained, asked through and accepted with no handle log
//      configured on either side; one with no `ia`, an `ia` under another
//      key, or the genuine one carried by another account is an ordinary
//      request;
//  16. after 30 days unanswered, the waiting list and the link's own screen
//      say the link may have been replaced or withdrawn, and not before, in
//      both languages;
//  17. a client recognises its own link: its screen says so and offers no
//      Send request, and nothing is sent to it.
@Tags(['integration'])
@Timeout(Duration(minutes: 6))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:cryptography/cryptography.dart' show Ed25519;
import 'package:file_picker/file_picker.dart'
    show FilePicker, FilePickerResult, FilePickerStatus, FileType, PlatformFile;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mobile_scanner/mobile_scanner.dart'
    show
        Barcode,
        BarcodeCapture,
        CameraFacing,
        MobileScannerController,
        MobileScannerPlatform,
        MobileScannerViewAttributes,
        StartOptions,
        TorchState;
import 'package:path/path.dart' as p;
import 'package:provider/provider.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:zapp/core/app_lock.dart';
import 'package:zapp/core/archive.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/connect_invites.dart';
import 'package:zapp/core/deep_links.dart';
import 'package:zapp/core/handles.dart';
import 'package:zapp/core/intro_links.dart';
import 'package:zapp/core/key_transparency.dart';
import 'package:zapp/core/models.dart';
import 'package:zapp/core/prefs.dart';
import 'package:zapp/core/push_service.dart';
import 'package:zapp/core/restore.dart';
import 'package:zapp/core/system_messages.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/l10n/app_localizations_en.dart';
import 'package:zapp/l10n/app_localizations_es.dart';
import 'package:zapp/l10n/handle_text.dart';
import 'package:zapp/l10n/refusal_text.dart';
import 'package:zapp/l10n/system_text.dart';
import 'package:zapp/ui/add_contact_screen.dart';
import 'package:zapp/ui/find_handle_screen.dart';
import 'package:zapp/ui/intro_link_screen.dart';
import 'package:zapp/ui/invite_link_watcher.dart';
import 'package:zapp/ui/open_link_screen.dart';
import 'package:zapp/ui/requests_screen.dart';
import 'package:zapp/ui/settings_screen.dart';
import 'package:zapp/ui/theme.dart';
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

/// A WebSocket proxy in front of a relay that writes down every frame in
/// both directions, per connection, and hands each frame from the relay to
/// [rewriteDown] first, when a test sets it — what a relay that lies could
/// send. The Host header goes through unchanged: a client signs its
/// authentication over the address it dialled.
class Tap {
  Tap._(this.server, this.relayPort);
  final HttpServer server;
  final int relayPort;
  final conns = <TapConn>[];
  Map<String, Object?> Function(TapConn c, Map<String, Object?> f)?
      rewriteDown;
  String get url => 'ws://127.0.0.1:${server.port}';
  int sendsTo(String rid) =>
      conns.fold(0, (n, c) => n + c.sendsTo(rid).length);
  Iterable<TapConn> authedAs(String rid) =>
      conns.where((c) => c.authRid == rid);

  /// Every connection that authenticated has its routing id worked out (the
  /// tap hashes the key the client sent, asynchronously).
  bool get named =>
      conns.every((c) => !c.upTypes.contains('auth') || c.authRid != null);

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
        var f = parse(d);
        final rewrite = tap.rewriteDown;
        if (f != null && rewrite != null) {
          final g = rewrite(c, f);
          if (!identical(g, f)) {
            f = g;
            d = jsonEncode(g);
          }
        }
        if (f != null) c.down.add(f);
        down.add(d);
      }, onDone: () => down.close(), onError: (_) => down.close());
    });
    return tap;
  }
}

/// mobile_scanner's platform half with no camera behind it: it starts and
/// stops when asked, and what it sees is what a test shows it ([show]) — so
/// the Scan tab's own MobileScanner, and the onDetect the screen gives it,
/// run as they do on a phone.
class FakeCamera extends MobileScannerPlatform {
  final _seen = StreamController<BarcodeCapture?>.broadcast();

  /// A scanner is listening: the Scan tab is up and its camera on.
  bool get on => _seen.hasListener;

  /// A QR in front of the camera, carrying each of [raws].
  void show(List<String> raws) => _seen.add(BarcodeCapture(
      barcodes: [for (final r in raws) Barcode(rawValue: r)]));

  @override
  Stream<BarcodeCapture?> get barcodesStream => _seen.stream;
  @override
  Stream<TorchState> get torchStateStream => const Stream.empty();
  @override
  Stream<double> get zoomScaleStateStream => const Stream.empty();
  @override
  Future<MobileScannerViewAttributes> start(StartOptions startOptions) async =>
      const MobileScannerViewAttributes(
          cameraDirection: CameraFacing.back,
          currentTorchMode: TorchState.unavailable,
          size: Size(640, 480),
          numberOfCameras: 1);
  @override
  Future<void> stop() async {}
  @override
  Future<void> pause() async {}
  @override
  Future<void> updateScanWindow(Rect? window) async {}
  @override
  Widget buildCameraView() => const SizedBox();
  @override
  Future<void> dispose() async {}
}

/// The file picker handing over one image, as Android's does — a copy in the
/// app's cache, deleted when the app clears the picker's files — standing in
/// for a picture of a QR that carries [qr], which [readImage], the decoder's
/// stand-in, reads back.
class QrImagePicker extends FilePicker {
  QrImagePicker(this.cache);
  final Directory cache;
  String qr = '';
  final copies = <File>[];

  Future<String?> readImage(String path) async => File(path).readAsStringSync();

  @override
  Future<FilePickerResult?> pickFiles({
    String? dialogTitle,
    String? initialDirectory,
    FileType type = FileType.any,
    List<String>? allowedExtensions,
    Function(FilePickerStatus)? onFileLoading,
    bool allowCompression = true,
    int compressionQuality = 30,
    bool allowMultiple = false,
    bool withData = false,
    bool withReadStream = false,
    bool lockParentWindow = false,
    bool readSequential = false,
  }) async {
    final copy = File('${cache.path}/file_picker/${copies.length}/qr.png')
      ..createSync(recursive: true)
      ..writeAsStringSync(qr);
    copies.add(copy);
    return FilePickerResult(
        [PlatformFile(path: copy.path, name: 'qr.png', size: qr.length)]);
  }

  @override
  Future<bool?> clearTemporaryFiles() async {
    final d = Directory('${cache.path}/file_picker');
    if (d.existsSync()) d.deleteSync(recursive: true);
    return true;
  }
}

Matcher failsWith(HandleFailure f) => throwsA(
    isA<HandleException>().having((e) => e.failure, 'failure', f));

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  final root = Directory.current.parent.path;
  const metricsToken = 'z-intro-link-test-metrics';
  late int relayPort;
  late Process log;
  late int logPort;
  late Uint8List logPub;
  late Tap tap;
  final logSeed =
      Uint8List.fromList(List<int>.generate(32, (i) => (i * 13 + 3) & 0xff));
  final temps = <Directory>[];
  final services = <ChatService>[];
  final raws = <RelayClient>[];
  final relays = <Process>[];
  final en = AppLocalizationsEn();
  final es = AppLocalizationsEs();

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
  /// above anything these tests do, so every mailbox they drain is flagged,
  /// unless [env] says otherwise.
  Future<int> startRelay(Map<String, String> env) async {
    final port = await freePort();
    final r = await Process.start('node', ['server.js'],
        workingDirectory: '$root${Platform.pathSeparator}server',
        environment: {
          'PORT': '$port',
          'LOG_LEVEL': 'silent',
          'METRICS_TOKEN': metricsToken,
          'INTRO_NEW_PER_IP_PER_MIN': '100000',
          'INTRO_PER_RID_PER_MIN': '100000',
          ...env,
        });
    r.stdout.drain<void>();
    r.stderr.drain<void>();
    relays.add(r);
    await healthy(port, 'a relay');
    return port;
  }

  setUpAll(() async {
    HttpOverrides.global = null;
    relayPort = await startRelay(const {});
    // A handle log, for the one criterion (6) that needs a handle beside the
    // link. Every other criterion runs with none configured.
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
    tap = await Tap.start(relayPort);
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

  tearDown(() => tap.rewriteDown = null);

  HandleConfig handleLog() => HandleConfig(
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
    final d = await Directory.systemTemp.createTemp('z_link_$name');
    temps.add(d);
    return d;
  }

  /// §21.8's timings, shortened: a first drain within a fifth of a second
  /// of the foreground or of making a link, a drain that stops reading
  /// after 0.4 s of quiet, and the periodic drain out of the way — the
  /// tests drain when they need (criterion 3 runs the timer itself).
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
      bool links = true,
      HandleConfig config = HandleConfig.defaults}) async {
    final v = vault ?? await Vault.open(rootOverride: await tempDir(name));
    final identity = id ?? await ZIdentity.generate();
    if (vault == null) {
      await v.kvPut('identity', jsonEncode(identity.toJson()));
    }
    final svc = await ChatService.init(
        vault: v,
        identity: identity,
        displayName: name,
        transport:
            Transport(identity: identity, serverUrl: relayUrl ?? tap.url),
        ktConfig: KtConfig.off,
        handleConfig: config,
        // Production passes nothing, and gets the build's constant.
        introLinks: links);
    fast(svc);
    services.add(svc);
    return svc;
  }

  Future<void> connected(List<ChatService> ss) => waitUntil(
      () => ss.every(
          (s) => s.transport.isConnected && s.transport.isSenderConnected),
      what: '${ss.map((s) => s.displayName).join(', ')} connected');

  /// Make [s]'s link at [pow] and wait for its first drain, which flags its
  /// mailbox at the relay.
  Future<OwnIntroLink> made(ChatService s, {int pow = 16}) async {
    final before = s.handles.linkDrains;
    await s.handles.makeLink(pow: pow);
    await waitUntil(() => s.handles.linkDrains > before,
        what: '${s.displayName}\'s link drained and flagged');
    return s.handles.link!;
  }

  Future<RelayClient> rawSender([String? url]) async {
    final c = await RelayClient.connectAnonymous(
        url ?? tap.url, await ZIdentity.generate());
    raws.add(c);
    return c;
  }

  /// A contact request from a fresh identity to the mailbox of [link],
  /// sealed to its xintro: what anybody who has the link can build.
  Future<(ZIdentity, String payload, ContactRequest)> linkRequest(
      IntroLink link,
      {String name = 'raw'}) async {
    final id = await ZIdentity.generate();
    final creq = await ContactRequest.create(
        me: id, toRid: await link.introRid(), displayName: name);
    final payload = await SealedEnvelope.seal(
        toXPub: link.xintro, fromRid: await id.routingId(), payload: creq.encode());
    return (id, payload, creq);
  }

  int today() => introPowDay(DateTime.now().millisecondsSinceEpoch);

  String stampFor(String introRid, String payload, int bits, {int? day}) =>
      b64url(createIntroPowStamp(
          introRid: introRid,
          day: day ?? today(),
          envelope: utf8.encode(payload),
          bits: bits));

  /// A stamp for [payload] that reaches [atLeast] bits and not [below].
  Future<String> stampBetween(
      String introRid, String payload, int atLeast, int below) async {
    while (true) {
      final n = createIntroPowStamp(
          introRid: introRid,
          day: today(),
          envelope: utf8.encode(payload),
          bits: atLeast);
      if (!await verifyIntroPowStamp(
          introRid: introRid,
          day: today(),
          envelope: utf8.encode(payload),
          nonce: n,
          bits: below)) {
        return b64url(n);
      }
    }
  }

  /// [payload] to [introRid] with a stamp of [bits] for the relay's day.
  Future<void> stamped(
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
  }

  /// Drain [s]'s link until the request from [rid] is filed.
  Future<void> receives(ChatService s, String rid) => waitUntil(() async {
        await s.handles.drainLink();
        return s.requestsByRid.containsKey(rid);
      }, what: '${s.displayName} filing the request from $rid');

  /// The acceptance [owner] sent [requester], read off the wire where the tap
  /// saw it and opened with the requester's own key; null while none has
  /// gone.
  Future<ContactRequest?> acceptanceTo(
      ChatService owner, ZIdentity requester) async {
    final rid = await requester.routingId();
    for (final c in tap.conns.reversed) {
      for (final f in c.sendsTo(rid).toList().reversed) {
        final opened = await SealedEnvelope.open(
            myXSeed: requester.xSeed,
            myXPub: requester.xPub,
            blob: f['payload'] as String);
        if (opened == null || opened.fromRid != owner.myRid) continue;
        final creq = ContactRequest.tryParse(opened.payload);
        if (creq != null) return creq;
      }
    }
    return null;
  }

  /// The `ia` on that acceptance.
  Future<String?> iaSentTo(ChatService owner, ZIdentity requester) async =>
      (await acceptanceTo(owner, requester))?.ia;

  /// A contact request from [from] to [to], sealed to [xPub] — what any
  /// client could build.
  Future<String> sealedRequest(ZIdentity from,
      {required String to, required Uint8List xPub, String? ia}) async {
    final creq = await ContactRequest.create(
        me: from, toRid: to, displayName: 'raw', ia: ia);
    return SealedEnvelope.seal(
        toXPub: xPub, fromRid: await from.routingId(), payload: creq.encode());
  }

  List<String> texts(ChatService s, String rid) => [
        for (final m in s.messagesByChat[rid] ?? const <ChatMessage>[])
          if (m.kind == 'text') m.body
      ];

  /// The sends to [rid] the tap carried, in order, after the first [skip].
  List<Map<String, Object?>> sendsAfter(String rid, int skip) => [
        for (final c in tap.conns) ...c.sendsTo(rid),
      ].skip(skip).toList();

  /// Add contact, as the app shows it, over [svc] — as on Android when
  /// [picker] is given: with the Scan tab, whose camera is [FakeCamera], and
  /// Open a QR image, whose picker and decoder are [picker]'s.
  Widget addContact(ChatService svc, {Locale? locale, QrImagePicker? picker}) =>
      MultiProvider(
        providers: [
          ChangeNotifierProvider<ChatService>.value(value: svc),
          ChangeNotifierProvider<ConnectInvites>(
              create: (_) => ConnectInvites(svc)),
        ],
        child: MaterialApp(
          debugShowCheckedModeBanner: false,
          theme: ZTheme.light(),
          locale: locale,
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: picker == null
              ? const AddContactScreen()
              : AddContactScreen(
                  operatingSystem: 'android', readImage: picker.readImage),
        ),
      );

  /// The phone's camera and file picker, as [addContact] uses them, for the
  /// rest of the test: what the camera sees and what the picker hands over
  /// are the test's to say.
  Future<(FakeCamera, QrImagePicker)> cameraAndPicker(
      WidgetTester tester) async {
    final camera = FakeCamera();
    final before = MobileScannerPlatform.instance;
    MobileScannerPlatform.instance = camera;
    addTearDown(() {
      MobileScannerPlatform.instance = before;
      MobileScannerController.resetPlatformSessionOwner();
    });
    final picker = QrImagePicker((await tester.runAsync(() => tempDir('qr')))!);
    FilePicker.platform = picker;
    return (camera, picker);
  }

  Widget wrap(ChatService svc, Widget child, {Locale? locale}) =>
      ChangeNotifierProvider<ChatService>.value(
        value: svc,
        child: MaterialApp(
          debugShowCheckedModeBanner: false,
          theme: ZTheme.light(),
          locale: locale,
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: child,
        ),
      );

  /// Inside `runAsync`: pump until [cond], on real time.
  Future<void> until(WidgetTester tester, bool Function() cond, String what,
      {Duration timeout = const Duration(seconds: 20)}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 20));
      await tester.pump();
    }
  }

  /// Outside `runAsync`, in the test's own zone: pump until [cond], moving
  /// the test's clock on a frame at a time so that what animates — a tab
  /// sliding in, a route arriving or leaving — gets there, and letting real
  /// time pass between frames so that the network and the vault answer.
  Future<void> settle(WidgetTester tester, bool Function() cond, String what,
      {Duration timeout = const Duration(seconds: 40)}) async {
    final deadline = DateTime.now().add(timeout);
    await tester.pump();
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await tester.runAsync(
          () => Future<void>.delayed(const Duration(milliseconds: 40)));
      await tester.pump(const Duration(milliseconds: 16));
    }
  }

  /// The tabs of the Add contact screen on screen now.
  TabController tabsOf(WidgetTester tester) =>
      tester.widget<TabBar>(find.byType(TabBar)).controller!;

  /// Switch Add contact to the tab labelled [label], as a tap does, and
  /// wait for the switch to finish: a tab still sliding when the test ends
  /// leaves its ticker behind.
  Future<void> toTab(WidgetTester tester, String label) async {
    final tabs = tabsOf(tester);
    await tester.tap(find.text(label));
    await settle(tester, () => !tabs.indexIsChanging && tabs.animation!.value == tabs.index,
        'the $label tab');
  }

  /// Settings over [svc], with the providers the screen reads, pumped until
  /// [ready].
  Future<void> settingsOf(WidgetTester tester, ChatService svc, String what,
      {Locale? locale, required bool Function() ready}) async {
    final dir = await tempDir('prefs');
    final prefs = AppPrefs(root: dir);
    await prefs.load();
    await tester.pumpWidget(MultiProvider(
      providers: [
        ChangeNotifierProvider<ChatService>.value(value: svc),
        ChangeNotifierProvider<Transport>.value(value: svc.transport),
        ChangeNotifierProvider<PushService>.value(
            value: PushService(transport: svc.transport, vault: svc.vault)),
        ChangeNotifierProvider<AppLock>.value(
            value: AppLock(root: dir, store: MemorySecretStore())),
        ChangeNotifierProvider<AppPrefs>.value(value: prefs),
      ],
      child: MaterialApp(
        debugShowCheckedModeBanner: false,
        theme: ZTheme.light(),
        locale: locale,
        localizationsDelegates: AppLocalizations.localizationsDelegates,
        supportedLocales: AppLocalizations.supportedLocales,
        home: SettingsScreen(key: UniqueKey()),
      ),
    ));
    await until(tester, ready, what);
  }

  /// A device enrolled to an account whose root it does not hold.
  Future<ChatService> linkedDevice(String name) async {
    final dir = await tempDir(name);
    final vault = await Vault.open(rootOverride: dir);
    final me = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(me.toJson()));
    final rootId = await ZIdentity.generate();
    final account = await AccountIdentity.fromV1(rootId, deviceId: 'phone');
    final cert = await account.signDeviceCert(
        deviceEdPub: me.edPub, deviceXPub: me.xPub, deviceId: 'laptop');
    final enrolled = await AccountIdentity.fromEnrollment(
      accountEdPub: account.accountEdPub,
      deviceEdSeed: me.edSeed,
      deviceXSeed: me.xSeed,
      deviceId: 'laptop',
      deviceCert: cert,
    );
    await vault.kvPut('account', jsonEncode(enrolled.toJson()));
    return boot(name, id: me, vault: vault, relayUrl: 'ws://127.0.0.1:1');
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
      Directory dir, File file, RecoveryCode code, String name,
      {bool links = true}) async {
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
    final s = await boot(name, id: id, vault: vault, links: links);
    s.handles.onForeground(); // the shortened timings from here on
    await connected([s]);
    return s;
  }

  // ---------------------------------------------------------------------------

  test(
      '1. one link per account, made on the main device with no handle log, '
      'kept sealed, and nothing sent', () async {
    final ola = await boot('Ola');
    await connected([ola]);
    expect(ola.handles.available, isFalse, reason: 'no handle log configured');
    expect(ola.handles.canManageLink, isTrue);
    expect(ola.handles.link, isNull);
    // The work an owner may print: 16 to 24; 20 unless chosen.
    expect(introLinkDefaultPow, 20);
    expect(introLinkPowLevels, [16, 18, 20, 22, 24]);
    for (final bad in [15, 25, 28]) {
      await expectLater(
          ola.handles.makeLink(pow: bad), throwsA(isA<ArgumentError>()));
    }
    expect(ola.handles.link, isNull);

    // Made, with the timer pushed out of the way, so that what making it
    // sends is what is seen: nothing.
    ola.handles.foregroundDelayMin = const Duration(hours: 1);
    ola.handles.foregroundDelayMax = const Duration(hours: 1);
    final connsBefore = tap.conns.length;
    final framesBefore = tap.conns.fold<int>(0, (n, c) => n + c.up.length);
    await ola.handles.makeLink();
    final link = ola.handles.link!;
    expect(link.printedPow, 20, reason: 'the default');
    expect(link.askedPow, 20);
    expect(link.phase, IntroLinkPhase.live);
    expect(link.link.pow, 20);
    expect(link.introRid, await link.link.introRid());
    expect(IntroLink.parse(link.url), link.link,
        reason: 'the link it shows is one a reader takes');
    expect(link.url, startsWith('https://www.zmessengers.com/c#zi1.'));
    expect(tap.conns.length, connsBefore, reason: 'no connection opened');
    expect(tap.conns.fold<int>(0, (n, c) => n + c.up.length), framesBefore,
        reason: 'not a frame sent');
    expect(ola.handles.linkDrains, 0);

    // Kept: one sealed row, which reads back as the same link.
    final stored = (await ola.vault.kvGet(introLinkKey))!;
    final back = await OwnIntroLink.fromJson(
        (jsonDecode(stored) as Map).cast<String, Object?>());
    expect(back.link, link.link);
    expect(back.printedPow, 20);
    final rows = await ola.vault.db.query('kv',
        where: 'k IN (?, ?)',
        whereArgs: ['s:$introLinkKey', 'p:$introLinkKey']);
    expect(rows.map((r) => r['k']), ['s:$introLinkKey'],
        reason: 'one row, in the sealed class');
    for (final secret in [b64(link.seed), b64url(link.seed), '"seed"']) {
      expect('${rows.single['v']}'.contains(secret), isFalse,
          reason: 'sealed: nothing of it is in the clear in the database');
    }

    // One per account.
    await expectLater(
        ola.handles.makeLink(), failsWith(HandleFailure.alreadyHasOne));
    expect(ola.handles.link!.link, link.link);

    // A linked device holds none and makes none.
    final laptop = await linkedDevice('Laptop');
    expect(laptop.handles.canManage, isFalse);
    expect(laptop.handles.canManageLink, isFalse);
    await expectLater(
        laptop.handles.makeLink(), failsWith(HandleFailure.linkedDevice));
    expect(await laptop.vault.kvGet(introLinkKey), isNull);
  });

  testWidgets(
      '2. Settings › Your public link: the work from 16 to 24, then the link, '
      'its QR and a copy for web pages with rel="noreferrer"', (tester) async {
    await tester.binding.setSurfaceSize(const Size(800, 2400));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    final clipboard = <String>[];
    tester.binding.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, (call) async {
      if (call.method == 'Clipboard.setData') {
        clipboard.add((call.arguments as Map)['text'] as String);
      }
      return null;
    });
    addTearDown(() => tester.binding.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, null));
    await tester.runAsync(() async {
      final svc = await boot('Finn', relayUrl: 'ws://127.0.0.1:1');
      // Nothing is sent by making a link; the drain is the timer's, and
      // pushed out of this test's way.
      svc.handles.foregroundDelayMin = const Duration(hours: 1);
      svc.handles.foregroundDelayMax = const Duration(hours: 1);
      for (final (locale, l) in [
        (const Locale('en'), en as AppLocalizations),
        (const Locale('es'), es as AppLocalizations),
      ]) {
        await settingsOf(tester, svc, 'the public-link row',
            locale: locale,
            ready: () => find.text(l.plinkYourLink).evaluate().isNotEmpty);
        // Settings sets its section headers in capitals.
        expect(find.text(l.stLinkSection.toUpperCase()), findsOneWidget);
        expect(find.text(l.plinkRowNone), findsOneWidget);
        await tester.pumpWidget(
            wrap(svc, const IntroLinkScreen(), locale: locale));
        await until(tester, () => find.text(l.plinkMake).evaluate().isNotEmpty,
            'the Make button');
        expect(find.text(l.plinkIntro), findsOneWidget);
        expect(find.text(l.plinkWhatItShows), findsOneWidget);
        // 20 chosen unless the person chooses; the picker offers 16 to 24.
        expect(find.text(handlePowText(l, 20)), findsOneWidget);
        await tester.tap(find.text(l.hdlDifficulty));
        await until(tester, () => find.byType(RadioListTile<int>).evaluate().length == 5,
            'the five levels offered');
        for (final b in introLinkPowLevels) {
          expect(find.text(handlePowText(l, b)), findsWidgets);
        }
        await tester.tap(find.text(handlePowText(l, 16)).last);
        await until(tester, () => find.byType(RadioListTile<int>).evaluate().isEmpty,
            'the picker closed');
        expect(find.text(handlePowText(l, 16)), findsOneWidget);
        await tester.pumpWidget(const SizedBox());
      }
      expect(es.plinkIntro, isNot(en.plinkIntro));

      // Made from the screen, at the work chosen there.
      await tester.pumpWidget(wrap(svc, const IntroLinkScreen()));
      await until(tester, () => find.text(en.plinkMake).evaluate().isNotEmpty,
          'the Make button again');
      await tester.tap(find.text(en.hdlDifficulty));
      await until(tester, () => find.byType(RadioListTile<int>).evaluate().isNotEmpty,
          'the picker');
      await tester.tap(find.text(handlePowText(en, 22)).last);
      await until(tester, () => find.byType(RadioListTile<int>).evaluate().isEmpty,
          'the picker closed');
      await tester.tap(find.text(en.plinkMake));
      await until(tester, () => svc.handles.link != null, 'the link made');
      await until(tester, () => find.byType(QrImageView).evaluate().isNotEmpty,
          'its QR shown');
      final link = svc.handles.link!;
      expect(link.printedPow, 22);
      expect(
          find.byWidgetPredicate(
              (w) => w is Semantics && w.properties.label == en.plinkSemQr),
          findsOneWidget,
          reason: 'the QR has a screen-reader label');
      expect(
          find.byWidgetPredicate(
              (w) => w is SelectableText && w.data == link.url),
          findsOneWidget,
          reason: 'the link itself, selectable');
      expect(find.text(en.plinkNotVerification), findsOneWidget);
      expect(find.text(en.plinkWebHelp), findsOneWidget);
      await tester.tap(find.text(en.plinkCopy));
      await until(tester, () => clipboard.isNotEmpty, 'the link copied');
      expect(clipboard.last, link.url);
      await tester.tap(find.text(en.plinkCopyWeb));
      await until(tester, () => clipboard.length == 2, 'the web copy copied');
      expect(clipboard.last,
          '<a href="${link.url}" rel="noreferrer">${link.url}</a>');
      await settingsOf(tester, svc, 'the row saying it is live',
          ready: () => find.text(en.plinkRowLive).evaluate().isNotEmpty);
      await tester.pumpWidget(const SizedBox());

      // A linked device: only the main device holds one.
      final laptop = await linkedDevice('LaptopUi');
      for (final (locale, l) in [
        (const Locale('en'), en as AppLocalizations),
        (const Locale('es'), es as AppLocalizations),
      ]) {
        await tester.pumpWidget(
            wrap(laptop, const IntroLinkScreen(), locale: locale));
        await until(
            tester,
            () => find.text(l.plinkLinkedDevice).evaluate().isNotEmpty,
            'the linked-device line');
        expect(find.text(l.plinkMake), findsNothing);
      }
      await tester.pumpWidget(const SizedBox());
    });
  });

  test(
      '3. drained on a connection of its own, as the link, flagged with the '
      'work asked, never push, on a timer of its own', () async {
    final otto = await boot('Otto');
    await connected([otto]);
    // A push token on the account, so that "the link registers none" is a
    // statement about something that happens.
    otto.transport.setPushToken('otto-push-token');
    // The link's own timer, short, and no handle anywhere: what drains is
    // the link's timer alone.
    otto.handles.drainEvery = const Duration(milliseconds: 600);
    final link = await made(otto, pow: 16);
    await waitUntil(() => otto.handles.linkDrains >= 3,
        what: 'the link drained on its own timer');
    expect(otto.handles.drains, 0, reason: 'no handle, no handle drain');
    expect(otto.handles.own, isNull);
    expect(otto.handles.available, isFalse);
    await otto.handles.askMoreWork(18);
    await waitUntil(
        () => tap
            .authedAs(link.introRid)
            .expand((c) => c.up)
            .any((f) => f['t'] == 'intro' && f['pow'] == 18),
        what: 'the mailbox flagged with the work asked');
    await waitUntil(() => tap.named, what: 'every connection named');

    final asOtto = tap.authedAs(otto.myRid).toList();
    final asLink = tap.authedAs(link.introRid).toList();
    expect(asOtto, isNotEmpty);
    expect(asLink.length, greaterThanOrEqualTo(3));
    expect(asOtto.expand((c) => c.upTypes), contains('push-register'));
    for (final c in asOtto) {
      expect(c.upTypes, isNot(contains('intro')),
          reason: 'the account\'s connection never flags anything');
      expect(c.sendsTo(link.introRid), isEmpty);
    }
    for (final c in asLink) {
      expect(c.upTypes.first, 'auth');
      expect(c.upTypes, contains('intro'),
          reason: 'flagged after every authentication');
      expect(c.upTypes, isNot(contains('push-register')));
      expect(c.upTypes, isNot(contains('send')),
          reason: 'the mailbox\'s connection only reads');
      final asked = c.up.where((f) => f['t'] == 'intro').single['pow'];
      expect(asked, anyOf(16, 18), reason: 'the work asked at the time');
    }
    for (final c in tap.conns) {
      final touches = {
        if (c.authRid != null) c.authRid!,
        for (final f in c.up)
          if (f['t'] == 'send') '${f['to']}',
      };
      expect(touches.containsAll({otto.myRid, link.introRid}), isFalse,
          reason: 'connection ${c.n} carried both routing ids');
    }
    expect(otto.handles.linkRelayGuard, HandleRelayGuard.guarded);
    // Its short timer stopped: the criteria after this one count
    // connections.
    otto.handles.onBackground();
  });

  test(
      '4. each stamp counted at the printed work, not the work asked since',
      () async {
    // A relay that holds one flag: flagging another mailbox makes it forget
    // the link's, as a restart would.
    final port = await startRelay({'INTRO_CAP': '1'});
    final url = 'ws://127.0.0.1:$port';
    final pia = await boot('Pia', relayUrl: url);
    await connected([pia]);
    final link = await made(pia, pow: 16);
    await pia.handles.askMoreWork(18);
    await waitUntil(() => pia.handles.linkDrains >= 2,
        what: 're-flagged at 18');
    final raw = await rawSender(url);

    // Asked more, the relay refuses the printed work.
    final (_, cheap, _) = await linkRequest(link.link, name: 'printed');
    RelayPowRequired? refused;
    try {
      await raw.send(
          to: link.introRid,
          id: newMessageId(),
          payload: cheap,
          pow: await stampBetween(link.introRid, cheap, 16, 18));
    } on RelayPowRequired catch (e) {
      refused = e;
    }
    expect(refused?.bits, 18, reason: 'the relay asks the work asked');

    // Another mailbox flagged: the relay forgets the link's, and takes a
    // stamp of the printed work again — or none.
    final other = await RelayClient.connect(url, await ZIdentity.generate());
    raws.add(other);
    await other.intro(16);
    final (printedId, printed, _) =
        await linkRequest(link.link, name: 'printed work');
    await raw.send(
        to: link.introRid,
        id: newMessageId(),
        payload: printed,
        pow: await stampBetween(link.introRid, printed, 16, 18));
    final (bareId, bare, _) = await linkRequest(link.link, name: 'no work');
    await raw.send(to: link.introRid, id: newMessageId(), payload: bare);

    final printedRid = await printedId.routingId();
    await receives(pia, printedRid);
    expect(pia.requestsByRid[printedRid]!.viaLink, isTrue,
        reason: 'a stamp of the printed work counts, whatever was asked since');
    expect(pia.requestsByRid.containsKey(await bareId.routingId()), isFalse,
        reason: 'a request without its stamp is dropped');
    expect(pia.handles.inboxTally.unstamped, greaterThanOrEqualTo(1));
  });

  test(
      '5. filed via your public link; accepted with ia signed by the seed of '
      'the mailbox it reached', () async {
    final rosa = await boot('Rosa');
    await connected([rosa]);
    final link = await made(rosa, pow: 16);
    final raw = await rawSender();
    final (rick, payload, creq) = await linkRequest(link.link, name: 'Rick');
    final rickRid = await rick.routingId();
    final rickIn = await RelayClient.connect(tap.url, rick);
    raws.add(rickIn);
    await stamped(raw, link.introRid, payload, 16);
    await receives(rosa, rickRid);

    final pending = rosa.requestsByRid[rickRid]!;
    expect(pending.viaLink, isTrue);
    expect(pending.via, isNull);
    expect(pending.viaIntro, isTrue);
    expect(pending.name, 'Rick');
    final meta = rosa.handles.inboundFor(rickRid)!;
    expect(meta.link, isTrue);
    expect(meta.introRid, link.introRid);
    expect(rosa.contacts.containsKey(rickRid), isFalse);
    final stored = jsonDecode((await rosa.vault.kvGet('handle_in'))!) as Map;
    expect((stored['reqs'] as Map)[rickRid], containsPair('link', 1));
    expect((stored['reqs'] as Map)[rickRid], isNot(contains('h')));

    await rosa.acceptRequest(rickRid);
    expect(rosa.contacts.containsKey(rickRid), isTrue);
    String? ia;
    await waitUntil(() async => (ia = await iaSentTo(rosa, rick)) != null,
        what: 'the acceptance on the wire');
    final id = await contactRequestId(creq);
    expect(
        await verifyIntroAck(
            ia: ia!,
            introPub: link.link.intro,
            requesterRid: rickRid,
            ownerAccountEdPub: rosa.identity.edPub,
            creqId: id),
        isTrue,
        reason: 'signed with the seed of the mailbox the request reached');
    final elsewhere = await IntroLink.fromSeed(randomBytes(32), pow: 16);
    expect(
        await verifyIntroAck(
            ia: ia!,
            introPub: elsewhere.intro,
            requesterRid: rickRid,
            ownerAccountEdPub: rosa.identity.edPub,
            creqId: id),
        isFalse,
        reason: 'and under no other link\'s intro');
    expect(rosa.handles.inboundFor(rickRid), isNull, reason: 'answered');
  });

  testWidgets('5. (screens) the Requests screen says "via your public link"',
      (tester) async {
    await tester.runAsync(() async {
      final svc = await boot('Rhea', relayUrl: 'ws://127.0.0.1:1');
      final rick = await ZIdentity.generate();
      final rid = await rick.routingId();
      final creq = await ContactRequest.create(
          me: rick, toRid: 'link-mailbox', displayName: 'Rick');
      expect(
          await svc.addHandleRequest(creq,
              requesterRid: rid, handle: '', viaLink: true),
          isTrue);
      for (final (locale, l) in [
        (const Locale('en'), en as AppLocalizations),
        (const Locale('es'), es as AppLocalizations),
      ]) {
        await tester.pumpWidget(wrap(svc, const RequestsScreen(), locale: locale));
        await until(tester,
            () => find.text(l.requestsViaLink).evaluate().isNotEmpty,
            'the request shown via the link');
        expect(find.text(l.requestsWantsToConnect), findsNothing);
      }
      expect(es.requestsViaLink, isNot(en.requestsViaLink));
      await tester.pumpWidget(const SizedBox());
    });
  });

  test(
      '6. one cap of 100 for the handle and the link together; a request by '
      'code stays', () async {
    final cap = await boot('Cap', config: handleLog());
    final carl = await boot('Carl');
    await connected([cap, carl]);
    // A handle beside the link.
    final draft =
        await cap.handles.prepareClaim(Handle.parse('cap.39'), pow: 16);
    await cap.handles.commitClaim(draft);
    await waitUntil(() => cap.handles.own?.phase == HandlePhase.live,
        what: 'the handle published');
    await waitUntil(() => cap.handles.drains >= 1,
        what: 'the handle\'s mailbox drained and flagged');
    final link = await made(cap, pow: 16);
    final handleRid = cap.handles.own!.introRid;
    final handleX = (await handleIntroIdentity(cap.handles.own!.introSeed)).xPub;

    // A request made with the code, unseen: the oldest of all.
    await carl.addContactFromCode(await cap.myContactCode());
    await waitUntil(() => cap.requestsByRid.containsKey(carl.myRid),
        what: 'the request by code pending');
    expect(cap.requestsByRid[carl.myRid]!.viaIntro, isFalse);

    final raw = await rawSender();
    Future<String> viaHandle() async {
      final id = await ZIdentity.generate();
      final creq = await ContactRequest.create(
          me: id, toRid: handleRid, displayName: 'h');
      await stamped(
          raw,
          handleRid,
          await SealedEnvelope.seal(
              toXPub: handleX,
              fromRid: await id.routingId(),
              payload: creq.encode()),
          16);
      return id.routingId();
    }

    Future<String> viaLink() async {
      final (id, payload, _) = await linkRequest(link.link, name: 'l');
      await stamped(raw, link.introRid, payload, 16);
      return id.routingId();
    }

    Future<void> drainBoth() async {
      while (await cap.handles.drain() > 0 || await cap.handles.drainLink() > 0) {}
    }

    // Fifty through the handle, then fifty-one through the link: 101.
    final handled = [for (var i = 0; i < 50; i++) await viaHandle()];
    await drainBoth();
    final linked = [for (var i = 0; i < 51; i++) await viaLink()];
    await drainBoth();
    final intro = {
      for (final r in cap.requests)
        if (r.viaIntro) r.rid
    };
    expect(intro, hasLength(handleInboundCap),
        reason: 'one cap for both doors');
    expect(intro.contains(handled.first), isFalse,
        reason: 'the oldest unseen went, though it came through the handle');
    expect(intro.containsAll(handled.skip(1)), isTrue);
    expect(intro.containsAll(linked), isTrue);
    expect(cap.requestsByRid.containsKey(carl.myRid), isTrue,
        reason: 'a request made with the code is never pushed out by them');
    expect(cap.handles.inboundFor(handled.first), isNull);
    expect(await cap.vault.db.query('requests'), hasLength(handleInboundCap + 1));
  });

  test('7. asking more work re-flags at once, from the printed work up to 24',
      () async {
    final ivo = await boot('Ivo');
    await connected([ivo]);
    final link = await made(ivo, pow: 18);
    for (final bad in [16, 17, 25, 28]) {
      await expectLater(
          ivo.handles.askMoreWork(bad), throwsA(isA<ArgumentError>()));
    }
    expect(ivo.handles.link!.askedPow, 18);
    // Far from the next drain on the timer: what flags it is the asking.
    final drainsBefore = ivo.handles.linkDrains;
    await ivo.handles.askMoreWork(24);
    expect(ivo.handles.link!.askedPow, 24);
    expect(ivo.handles.link!.printedPow, 18, reason: 'the link does not change');
    await waitUntil(
        () => tap
            .authedAs(link.introRid)
            .expand((c) => c.up)
            .any((f) => f['t'] == 'intro' && f['pow'] == 24),
        what: 'the mailbox re-flagged at once');
    await waitUntil(() => ivo.handles.linkDrains > drainsBefore,
        what: 'the drain that flagged it done');
    final stored = jsonDecode((await ivo.vault.kvGet(introLinkKey))!) as Map;
    expect(stored['ask'], 24);
    expect(stored['pow'], 18);
    final raw = await rawSender();
    final (_, payload, _) = await linkRequest(link.link);
    RelayPowRequired? refused;
    try {
      await raw.send(
          to: link.introRid,
          id: newMessageId(),
          payload: payload,
          pow: await stampBetween(link.introRid, payload, 18, 24));
    } on RelayPowRequired catch (e) {
      refused = e;
    }
    expect(refused?.bits, 24);
    // And back to the printed work.
    await ivo.handles.askMoreWork(18);
    expect(ivo.handles.link!.askedPow, 18);
  });

  test(
      '8. replace: a new mailbox; the old one read once more without intro; a '
      'request it held still accepted with its seed', () async {
    final rex = await boot('Rex');
    await connected([rex]);
    final old = await made(rex, pow: 16);
    final raw = await rawSender();
    final (abel, abelPayload, abelCreq) =
        await linkRequest(old.link, name: 'Abel');
    final abelRid = await abel.routingId();
    await stamped(raw, old.introRid, abelPayload, 16);
    await receives(rex, abelRid);

    // One more waits at the old mailbox when it is replaced.
    final (cleo, cleoPayload, _) = await linkRequest(old.link, name: 'Cleo');
    await stamped(raw, old.introRid, cleoPayload, 16);
    final connsBefore = tap.conns.length;
    await rex.handles.replaceLink();
    final fresh = rex.handles.link!;
    expect(fresh.introRid, isNot(old.introRid));
    expect(fresh.printedPow, 16, reason: 'printed at the work the old one asked');
    expect(rex.requestsByRid.containsKey(await cleo.routingId()), isTrue,
        reason: 'the old mailbox was read once more');
    await waitUntil(() => tap.named, what: 'every connection named');
    final lastOld = tap.conns.skip(connsBefore).where((c) => c.authRid == old.introRid);
    expect(lastOld, hasLength(1), reason: 'read once more');
    expect(lastOld.single.upTypes, isNot(contains('intro')),
        reason: 'and not flagged: its flag lapses with its ownership');

    // The new mailbox takes requests; the old one is never read again.
    final (dora, doraPayload, _) = await linkRequest(fresh.link, name: 'Dora');
    await stamped(raw, fresh.introRid, doraPayload, 16);
    await receives(rex, await dora.routingId());
    final (eli, eliPayload, _) = await linkRequest(old.link, name: 'Eli');
    await stamped(raw, old.introRid, eliPayload, 16);
    for (var i = 0; i < 2; i++) {
      await rex.handles.drainLink();
    }
    expect(rex.requestsByRid.containsKey(await eli.routingId()), isFalse,
        reason: 'nothing sent to the old link after it was replaced is filed');
    await waitUntil(() => tap.named, what: 'every connection named');
    expect(tap.conns.skip(connsBefore).where((c) => c.authRid == old.introRid),
        hasLength(1),
        reason: 'the old mailbox is never read again');

    // Abel's request reached the old mailbox: accepted with its seed.
    await rex.acceptRequest(abelRid);
    String? ia;
    await waitUntil(() async => (ia = await iaSentTo(rex, abel)) != null,
        what: 'Abel\'s acceptance on the wire');
    expect(
        await verifyIntroAck(
            ia: ia!,
            introPub: old.link.intro,
            requesterRid: abelRid,
            ownerAccountEdPub: rex.identity.edPub,
            creqId: await contactRequestId(abelCreq)),
        isTrue);
    // The old seed is kept in the link's own row, beside the new link, and
    // not among the handle's; once Cleo's request — the last that needs it —
    // is answered, it goes, and the new link stays.
    Future<Map> row() async =>
        jsonDecode((await rex.vault.kvGet(introLinkKey))!) as Map;
    Future<Map> handleSeeds() async =>
        ((jsonDecode((await rex.vault.kvGet('handle_in'))!) as Map)['seeds']
            as Map?) ??
        const {};
    expect(((await row())['old'] as Map).containsKey(old.introRid), isTrue,
        reason: 'kept while a pending request needs it');
    expect((await handleSeeds()).containsKey(old.introRid), isFalse,
        reason: 'in the link\'s row, not among the handle\'s seeds');
    await rex.declineRequest(await cleo.routingId());
    expect((await row()).containsKey('old'), isFalse);
    expect((await row())['seed'], b64(fresh.seed));
  });

  test(
      '9. withdraw: no link; the mailbox read once more and never again; a '
      'request it held still accepted; a new link after', () async {
    final wren = await boot('Wren');
    await connected([wren]);
    final link = await made(wren, pow: 16);
    final raw = await rawSender();
    final (bo, boPayload, boCreq) = await linkRequest(link.link, name: 'Bo');
    final boRid = await bo.routingId();
    await stamped(raw, link.introRid, boPayload, 16);
    await receives(wren, boRid);
    final (cy, cyPayload, _) = await linkRequest(link.link, name: 'Cy');
    await stamped(raw, link.introRid, cyPayload, 16);

    final connsBefore = tap.conns.length;
    await wren.handles.withdrawLink();
    expect(wren.handles.link, isNull);
    // No link; the row stays, holding the withdrawn link's seed and nothing
    // else, while Bo's and Cy's requests need it.
    final row = jsonDecode((await wren.vault.kvGet(introLinkKey))!) as Map;
    expect(row.containsKey('seed'), isFalse, reason: 'no link');
    expect(((row['old'] as Map)[link.introRid] as Map)['seed'], b64(link.seed));
    final cyRid = await cy.routingId();
    expect(wren.requestsByRid.containsKey(cyRid), isTrue,
        reason: 'read once more');
    await waitUntil(() => tap.named, what: 'every connection named');
    final last = tap.conns.skip(connsBefore).where((c) => c.authRid == link.introRid);
    expect(last, hasLength(1));
    expect(last.single.upTypes, isNot(contains('intro')));
    expect(await wren.handles.drainLink(), 0, reason: 'nothing to drain');
    final (dee, deePayload, _) = await linkRequest(link.link, name: 'Dee');
    await stamped(raw, link.introRid, deePayload, 16);
    wren.handles.onForeground();
    await wren.handles.drainLink();
    expect(wren.requestsByRid.containsKey(await dee.routingId()), isFalse);
    await waitUntil(() => tap.named, what: 'every connection named');
    expect(tap.conns.skip(connsBefore).where((c) => c.authRid == link.introRid),
        hasLength(1),
        reason: 'never read again');

    await wren.acceptRequest(boRid);
    String? ia;
    await waitUntil(() async => (ia = await iaSentTo(wren, bo)) != null,
        what: 'Bo\'s acceptance on the wire');
    expect(
        await verifyIntroAck(
            ia: ia!,
            introPub: link.link.intro,
            requesterRid: boRid,
            ownerAccountEdPub: wren.identity.edPub,
            creqId: await contactRequestId(boCreq)),
        isTrue,
        reason: 'the withdrawn link\'s seed kept while Bo\'s request needed it');
    // Cy's answered too: neither a link nor a seed anyone needs, and the row
    // goes.
    expect(await wren.vault.kvGet(introLinkKey), isNotNull);
    await wren.declineRequest(cyRid);
    expect(await wren.vault.kvGet(introLinkKey), isNull);

    final again = await made(wren, pow: 16);
    expect(again.introRid, isNot(link.introRid));
  });

  // The app killed in the middle of the old mailbox's last read, after a
  // Replace (8) or a Withdraw (9): it starts again from what is on disk, and
  // a request that reached the old mailbox before is still accepted with its
  // seed (ADR 0032 §4: an old seed stays while a pending request needs it).
  for (final withdraw in [false, true]) {
    final what = withdraw ? 'withdraw' : 'replace';
    test(
        '${withdraw ? 9 : 8}. (killed) $what: the app killed during the old '
        'mailbox\'s last read keeps its seed, and the request it held is '
        'accepted with ia after the restart', () async {
      final name = withdraw ? 'KillW' : 'KillR';
      final rex = await boot(name);
      await connected([rex]);
      final old = await made(rex, pow: 16);
      final raw = await rawSender();
      final (abel, abelPayload, abelCreq) =
          await linkRequest(old.link, name: 'Abel');
      final abelRid = await abel.routingId();
      await stamped(raw, old.introRid, abelPayload, 16);
      await receives(rex, abelRid);
      expect(rex.handles.inboundFor(abelRid)!.introRid, old.introRid);

      // The last read stays open until a quiet spell: long enough here that
      // the kill lands inside it.
      rex.handles.drainQuiet = const Duration(seconds: 4);
      final connsBefore = tap.conns.length;
      final outcome =
          (withdraw ? rex.handles.withdrawLink() : rex.handles.replaceLink())
              .then((_) {}, onError: (_) {});
      await waitUntil(
          () =>
              tap.named &&
              tap.conns.skip(connsBefore).any(
                  (c) => c.authRid == old.introRid && c.down.isNotEmpty),
          what: 'the old mailbox being read once more');
      // What the disk holds now, inside the last read, is what a restart
      // starts from.
      final row = await rex.vault.kvGet(introLinkKey);
      final inbound = await rex.vault.kvGet('handle_in');

      // Killed: nothing more reaches the disk.
      services.remove(rex);
      final dir = rex.vault.root;
      rex.dispose();
      await rex.transport.stop();
      await rex.vault.db.close();
      await outcome;

      // Started again on that disk, and Abel's request accepted.
      final back = await boot(name,
          id: rex.identity, vault: await Vault.open(rootOverride: dir));
      await connected([back]);
      expect(back.requestsByRid[abelRid]?.viaLink, isTrue);
      await back.acceptRequest(abelRid);
      ContactRequest? accepted;
      await waitUntil(
          () async => (accepted = await acceptanceTo(back, abel)) != null,
          what: 'Abel\'s acceptance on the wire');
      expect(accepted!.ia, isNotNull,
          reason: 'ADR 0032 §4: an old seed stays while a pending request '
              'needs it');
      expect(
          await verifyIntroAck(
              ia: accepted!.ia!,
              introPub: old.link.intro,
              requesterRid: abelRid,
              ownerAccountEdPub: back.identity.edPub,
              creqId: await contactRequestId(abelCreq)),
          isTrue,
          reason: 'signed with the old link\'s seed');

      // The disk at the kill: the link's row, holding what replaced the link
      // — a new one, or for a withdraw none — and the old seed beside it,
      // the two written together before the last read began; and none of it
      // among the handle's seeds.
      final r = jsonDecode(row!) as Map;
      expect(((r['old'] as Map?)?[old.introRid] as Map?)?['seed'],
          b64(old.seed));
      if (withdraw) {
        expect(r.containsKey('seed'), isFalse, reason: 'no link');
        expect(back.handles.link, isNull);
      } else {
        expect(r['seed'], isNot(b64(old.seed)));
        expect(back.handles.link!.introRid, isNot(old.introRid));
      }
      final seeds = (jsonDecode(inbound!) as Map)['seeds'] as Map?;
      expect(seeds?.containsKey(old.introRid) ?? false, isFalse);
    });
  }

  test(
      '10. backup and restore: the link as "introlink", "keep":1, an old '
      'seed with it and in no handle record; restored held until its person '
      'says to use it again', () async {
    final abe = await boot('Abe');
    await connected([abe]);
    final link = await made(abe, pow: 16);
    await abe.handles.askMoreWork(18);
    final record = (await IntroLinkBackup.export(abe.vault))!;
    expect(record['t'], 'introlink');
    expect(record['keep'], 1);
    expect(record['v'], 1);
    expect(((record['kv'] as Map)[introLinkKey] as Map)['phase'], 'live');
    final (file, code) = await backup(abe, 'abe');
    final dir = await lose(abe);

    final connsBefore = tap.conns.length;
    final back = await restore(dir, file, code, 'Abe');
    final held = back.handles.link!;
    expect(held.phase, IntroLinkPhase.held);
    expect(held.link, link.link);
    expect(held.printedPow, 16);
    expect(held.askedPow, 18);
    // Something sent to it while it is held is not filed: nothing reads it.
    final raw = await rawSender();
    final (ann, payload, annCreq) = await linkRequest(link.link, name: 'Ann');
    final annRid = await ann.routingId();
    await stamped(raw, link.introRid, payload, 18);
    expect(await back.handles.drainLink(), 0);
    expect(back.handles.linkDrains, 0);
    expect(back.requestsByRid.containsKey(annRid), isFalse);
    await waitUntil(() => tap.named, what: 'every connection named');
    expect(tap.conns.skip(connsBefore).where((c) => c.authRid == link.introRid),
        isEmpty,
        reason: 'nothing connects as a held link\'s mailbox');

    // The person says to use it again.
    await back.handles.useLinkAgain();
    expect(back.handles.link!.phase, IntroLinkPhase.live);
    await receives(back, annRid);
    expect(back.requestsByRid[annRid]!.viaLink, isTrue);
    final flagged = tap.conns
        .skip(connsBefore)
        .where((c) => c.authRid == link.introRid)
        .expand((c) => c.up)
        .where((f) => f['t'] == 'intro');
    expect(flagged.map((f) => f['pow']), everyElement(18),
        reason: 'flagged with the work asked, as backed up');

    // Replaced while Ann's request waits: the old seed rides in the
    // `introlink` record, which a build that does not know it keeps as it
    // came ("keep":1), and in no `handle` record, which is where a build
    // that knows handles but not links reads its handle's seeds from.
    await back.handles.replaceLink();
    final replaced = back.handles.link!;
    final record2 = (await IntroLinkBackup.export(back.vault))!;
    expect(record2['keep'], 1);
    final row2 = (record2['kv'] as Map)[introLinkKey] as Map;
    expect(row2['seed'], b64(replaced.seed));
    expect(((row2['old'] as Map)[link.introRid] as Map)['seed'],
        b64(link.seed));
    final handleRecord = (await HandleBackup.export(back.vault))!;
    final handleIn = (handleRecord['kv'] as Map)['handle_in'] as Map;
    expect(((handleIn['reqs'] as Map)[annRid] as Map)['intro'], link.introRid,
        reason: 'the handle record carries the request');
    expect((handleIn['seeds'] as Map?) ?? const {}, isEmpty,
        reason: 'and no link\'s seed');

    // Restored again: the request accepted with `ia` under the replaced
    // link's intro, its seed read from the link's row.
    final (file2, code2) = await backup(back, 'abe2');
    final again = await restore(await lose(back), file2, code2, 'Abe');
    expect(again.handles.link!.introRid, replaced.introRid);
    expect(again.handles.link!.phase, IntroLinkPhase.held);
    expect(again.requestsByRid[annRid]?.viaLink, isTrue);
    final restoredIn =
        jsonDecode((await again.vault.kvGet('handle_in'))!) as Map;
    expect(
        ((restoredIn['seeds'] as Map?) ?? const {}).containsKey(link.introRid),
        isFalse);
    await again.acceptRequest(annRid);
    ContactRequest? accepted;
    await waitUntil(
        () async => (accepted = await acceptanceTo(again, ann)) != null,
        what: 'Ann\'s acceptance on the wire');
    expect(accepted!.ia, isNotNull,
        reason: 'the replaced link\'s seed came back with the link\'s row');
    expect(
        await verifyIntroAck(
            ia: accepted!.ia!,
            introPub: link.link.intro,
            requesterRid: annRid,
            ownerAccountEdPub: again.identity.edPub,
            creqId: await contactRequestId(annCreq)),
        isTrue);
  });

  testWidgets('10. (screens) a restored link is said to be held', (tester) async {
    await tester.binding.setSurfaceSize(const Size(800, 2400));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.runAsync(() async {
      final svc = await boot('Hal', relayUrl: 'ws://127.0.0.1:1');
      final restored = await IntroLinkBackup.restore({
        'kv': {
          introLinkKey: (await OwnIntroLink.make(randomBytes(32),
                  pow: 20, nowMs: DateTime.now().millisecondsSinceEpoch))
              .toJson()
        }
      });
      expect(
          jsonDecode(restored[introLinkKey]!), containsPair('phase', 'held'));
      await svc.vault.kvPut(introLinkKey, restored[introLinkKey]!);
      await svc.handles.load();
      expect(svc.handles.link!.phase, IntroLinkPhase.held);
      for (final (locale, l) in [
        (const Locale('en'), en as AppLocalizations),
        (const Locale('es'), es as AppLocalizations),
      ]) {
        await settingsOf(tester, svc, 'the row saying it is held',
            locale: locale,
            ready: () => find.text(l.plinkRowHeld).evaluate().isNotEmpty);
        await tester.pumpWidget(
            wrap(svc, const IntroLinkScreen(), locale: locale));
        await until(tester,
            () => find.text(l.plinkHeldBody).evaluate().isNotEmpty,
            'the held line');
        expect(find.text(l.plinkUseAgain), findsOneWidget);
        expect(find.byType(QrImageView), findsNothing,
            reason: 'nothing offers a held link to be handed out');
      }
      expect(es.plinkHeldBody, isNot(en.plinkHeldBody));
      await tester.pumpWidget(const SizedBox());
    });
  });

  testWidgets(
      '11. with introLinksEnabled false, none of it is reachable: no row, no '
      'link loaded, drained, made, parsed, opened or sent to, nothing matched',
      (tester) async {
    await tester.binding.setSurfaceSize(const Size(800, 2400));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    ChatService? svcOff;
    OwnIntroLink? linkOff;
    String? ownCodeOff;
    await tester.runAsync(() async {
      expect(introLinksEnabled, isFalse, reason: 'this build\'s constant');
      // A vault that holds a link and a request recorded as through it — a
      // restore from a build with links on — opened by this build as it ships.
      final dir = await tempDir('off');
      final vault = await Vault.open(rootOverride: dir);
      final me = await ZIdentity.generate();
      await vault.kvPut('identity', jsonEncode(me.toJson()));
      final link = await OwnIntroLink.make(randomBytes(32),
          pow: 16, nowMs: DateTime.now().millisecondsSinceEpoch);
      await vault.kvPut(introLinkKey, jsonEncode(link.toJson()));
      final svc = await ChatService.init(
          vault: vault,
          identity: me,
          displayName: 'Off',
          transport: Transport(identity: me, serverUrl: tap.url),
          ktConfig: KtConfig.off);
      services.add(svc);
      fast(svc);
      await connected([svc]);
      expect(svc.handles.linksEnabled, isFalse);
      expect(svc.handles.canManageLink, isFalse);
      expect(svc.handles.link, isNull, reason: 'not loaded');
      expect(await svc.vault.kvGet(introLinkKey), isNotNull,
          reason: 'kept, unread');
      svc.handles.onForeground();
      expect(await svc.handles.drainLink(), 0);
      expect(svc.handles.linkDrains, 0);
      expect(() => svc.handles.makeLink(), throwsStateError);

      final rick = await ZIdentity.generate();
      final rid = await rick.routingId();
      final creq = await ContactRequest.create(
          me: rick, toRid: link.introRid, displayName: 'Rick');
      await svc.addHandleRequest(creq,
          requesterRid: rid, handle: '', viaLink: true);
      await svc.handles.recordInbound(rid,
          handle: '',
          link: true,
          introRid: link.introRid,
          creqId: await contactRequestId(creq));
      services.remove(svc);
      svc.dispose();
      await svc.transport.stop();
      await svc.vault.db.close();

      // And a request a backup says this device sent through a link, with
      // the acknowledgement its owner would sign for it.
      final elsewhere = randomBytes(32);
      final sentLink = await IntroLink.fromSeed(elsewhere, pow: 16);
      final sentId = randomBytes(32);
      final reopened = await Vault.open(rootOverride: dir);
      await reopened.kvPut(
          'handle_out',
          jsonEncode([
            OutgoingHandleRequest.viaLink(
                    link: sentLink,
                    creqIds: [sentId],
                    sentMs: DateTime.now().millisecondsSinceEpoch)
                .toJson()
          ]));
      final again = await ChatService.init(
          vault: reopened,
          identity: me,
          displayName: 'Off',
          transport: Transport(identity: me, serverUrl: tap.url),
          ktConfig: KtConfig.off);
      services.add(again);
      fast(again);
      await connected([again]);
      expect(again.requestsByRid[rid]!.viaLink, isFalse,
          reason: 'with links off, nothing says "link"');
      expect(again.requestsByRid[rid]!.viaIntro, isFalse);
      expect(again.handles.outgoing, isEmpty,
          reason: 'a request through a link is not shown');
      final owner = await ZIdentity.generate();
      final ownerRid = await owner.routingId();
      final ia = await signIntroAck(
          introSeed: elsewhere,
          requesterRid: again.myRid,
          ownerAccountEdPub: owner.edPub,
          creqId: sentId);
      final raw = await rawSender();
      await raw.send(
          to: again.myRid,
          id: newMessageId(),
          payload: await sealedRequest(owner,
              to: again.myRid, xPub: again.identity.xPub, ia: ia));
      await waitUntil(() => again.requestsByRid.containsKey(ownerRid),
          what: 'the acknowledged acceptance filed as an ordinary request');
      expect(again.contacts.containsKey(ownerRid), isFalse,
          reason: 'never matched to a request through a link');

      await settingsOf(tester, again, 'Settings without a link row',
          ready: () => find.text(en.hdlYourHandle).evaluate().isNotEmpty);
      expect(find.text(en.plinkYourLink), findsNothing);
      expect(find.text(en.stLinkSection.toUpperCase()), findsNothing);
      await tester.pumpWidget(wrap(again, const RequestsScreen()));
      await until(tester,
          () => find.text(en.requestsWantsToConnect).evaluate().isNotEmpty,
          'the request shown as an ordinary one');
      expect(find.text(en.requestsViaLink), findsNothing);
      await tester.pumpWidget(const SizedBox());
      expect(introLinkInField(link.url, enabled: again.handles.linksEnabled),
          (link: null, problem: null));
      svcOff = again;
      linkOff = link;
      ownCodeOff = await again.myContactCode();
    });
    final again = svcOff!;
    final link = linkOff!;

    // No field parses a link: Paste reads it as the contact code it is not,
    // so do the Scan tab and a QR image, and the handle search, with no
    // handle log, offers no field.
    final sendsBefore = tap.sendsTo(link.introRid);
    final (camera, picker) = await cameraAndPicker(tester);
    await tester.pumpWidget(addContact(again, picker: picker));
    await settle(tester, () => find.text(en.addPaste).evaluate().isNotEmpty,
        'Add contact');
    await toTab(tester, en.addPaste);
    await tester.enterText(
        find.widgetWithText(TextField, en.addTheirCode), link.url);
    await tester.tap(find.text(en.addVerifyAndAdd));
    final notACode = contactCodeRefusalText(
        en, ContactCodeRefused(ContactCodeRefusal.invalidCode, '', ''));
    await settle(tester, () => find.text(notACode).evaluate().isNotEmpty,
        'the link refused as not a contact code');
    expect(find.byType(OpenLinkScreen), findsNothing);
    // Scanned, beside the account's own code: the link is passed over as
    // nothing the Scan tab reads, and the code beside it is read — and
    // refused as this account's own.
    await toTab(tester, en.addScan);
    await settle(tester, () => camera.on, 'the camera on');
    camera.show([link.url, ownCodeOff!]);
    final ownCode = contactCodeRefusalText(
        en, ContactCodeRefused(ContactCodeRefusal.ownCode, '', ''));
    await settle(tester, () => find.text(ownCode).evaluate().isNotEmpty,
        'the code beside the link read');
    expect(find.byType(OpenLinkScreen), findsNothing);
    // A QR image carrying the link: read, and refused as the contact code
    // it is not.
    await toTab(tester, en.addPaste);
    picker.qr = link.url;
    await tester.tap(find.text(en.addOpenImage));
    await settle(tester, () => find.text(notACode).evaluate().isNotEmpty,
        'the link in an image refused as not a contact code');
    expect(picker.copies, hasLength(1));
    expect(find.byType(OpenLinkScreen), findsNothing);
    await toTab(tester, en.addHandle);
    expect(find.text(en.hdlUnavailable), findsOneWidget);
    expect(find.widgetWithText(TextField, en.hdlFindLabel), findsNothing);
    expect(find.text(en.plinkFindAlso), findsNothing);
    await tester.pumpWidget(const SizedBox());

    await tester.runAsync(() async {
      // A tapped link is ignored, and nothing is sent through one.
      final deep = DeepLinks(ConnectInvites(again),
          introLinks: () => again.handles.linksEnabled);
      expect(await deep.handle(link.url), isNull);
      expect(deep.lastRejected, link.url);
      expect(deep.takeUnshownLink(), isNull);
      expect(() => again.handles.requestLink(link.link), throwsStateError);
      expect(tap.sendsTo(link.introRid), sendsBefore);
      await waitUntil(() => tap.named, what: 'every connection named');
      expect(tap.authedAs(link.introRid), isEmpty,
          reason: 'nothing ever connects as the link\'s mailbox');
    });
  });

  testWidgets(
      '12. held: pasted, scanned, from an image, typed into the handle search '
      'or tapped, nothing is sent until Send request', (tester) async {
    await tester.binding.setSurfaceSize(const Size(800, 2400));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    late ChatService ola, rick, other;
    late OwnIntroLink link;
    late String code, flipped;
    late int connsBefore;
    await tester.runAsync(() async {
      ola = await boot('OlaHeld');
      rick = await boot('RickHeld');
      // Another app on the relay, with a link of its own.
      other = await boot('OtherHeld');
      await connected([ola, rick, other]);
      link = await made(ola, pow: 16);
      await made(other, pow: 16);
      expect(rick.handles.available, isFalse, reason: 'no handle log');

      // What the fields take: the link as printed, its bare code, either as a
      // QR carries it or an image's decoder reads it, a copy with whitespace,
      // and a link on any page; a handle that begins as a link does is a
      // handle where handles are taken; a damaged link and a newer one are
      // said as such; and a contact code is no link's business.
      code = link.link.code;
      for (final text in [
        link.url,
        code,
        '  ${link.url}\n',
        'https://example.org/page?x=1#$code',
      ]) {
        expect(introLinkInField(text, enabled: true).link, link.link,
            reason: text);
      }
      expect(introLinkInField('zi1.42', enabled: true, handleField: true),
          (link: null, problem: null));
      expect(introLinkInField('zi1.42', enabled: true).problem,
          IntroLinkProblem.wrongLength);
      flipped = '${code.substring(0, 95)}${code[95] == 'A' ? 'B' : 'A'}';
      expect(introLinkInField(flipped, enabled: true).problem,
          IntroLinkProblem.badCheck);
      expect(introLinkInField('zi2.${code.substring(4)}', enabled: true).problem,
          IntroLinkProblem.newerVersion);
      expect(introLinkInField(await rick.myContactCode(), enabled: true),
          (link: null, problem: null));
      await waitUntil(() => tap.named, what: 'every connection named');
      connsBefore = tap.conns.length;
    });

    // Pasted: held on its screen, and nothing sent or opened.
    final (camera, picker) = await cameraAndPicker(tester);
    await tester.pumpWidget(addContact(rick, picker: picker));
    await settle(tester, () => find.text(en.addPaste).evaluate().isNotEmpty,
        'Add contact');
    await toTab(tester, en.addPaste);
    await tester.enterText(
        find.widgetWithText(TextField, en.addTheirCode), link.url);
    await tester.tap(find.text(en.addVerifyAndAdd));
    final send = find.text(en.hdlSendRequest).hitTestable();
    await settle(tester, () => send.evaluate().isNotEmpty,
        'the link held on its screen');
    expect(find.text(en.plinkOpenBody), findsOneWidget);
    expect(find.text(en.plinkOpenNote), findsOneWidget);
    // Another app on the relay reads its own link's mailbox here, inside
    // this count, as any app this file has started and left running can on
    // its own clock: criterion 8's, started again on a disk that holds a
    // live link, draws its first drain at production's 3 to 30 seconds, and
    // until 2026-10-31, when every connection through the tap was counted,
    // one that landed here failed this (Expected: <88> Actual: <89>). What
    // is counted is what Rick's app could have opened: a connection that
    // never authenticated, or one as him.
    await tester.runAsync(() async {
      await other.handles.drainLink();
      await waitUntil(() => tap.named, what: 'every connection named');
    });
    expect(
        [
          for (final c in tap.conns.skip(connsBefore))
            if (c.anonymous || c.authRid == rick.myRid) c.n
        ],
        isEmpty,
        reason: 'no connection opened');
    expect(tap.sendsTo(link.introRid), 0, reason: 'nothing sent');
    expect(rick.handles.outgoing, isEmpty);
    expect(rick.handles.stampsMade, 0);

    // Sent, once its person says so: one request, on a connection opened for
    // it alone.
    await tester.tap(send);
    await settle(
        tester,
        () =>
            find.byType(OpenLinkScreen).evaluate().isEmpty &&
            find.text(en.plinkRequestSent).evaluate().isNotEmpty,
        'the request sent and the screen closed',
        timeout: const Duration(seconds: 90));
    // (Two sends, and two connections, only if the relay's day turned as it
    // went: one stamp more for its day. The envelope is the same.)
    final carriers = [
      for (final c in tap.conns.skip(connsBefore))
        if (c.sendsTo(link.introRid).isNotEmpty) c
    ];
    expect(carriers.length, inInclusiveRange(1, 2));
    for (final c in carriers) {
      expect(c.anonymous, isTrue);
      expect(c.upTypes.where((t) => t == 'send'), hasLength(1),
          reason: 'a connection opened for that send alone');
    }
    // One request in all: nothing went before Send request, whose one press
    // sent this one.
    expect({for (final f in sendsAfter(link.introRid, 0)) f['payload']},
        hasLength(1));
    expect(rick.handles.outgoing.single.link, link.link);
    expect(rick.handles.outgoing.single.creqIds, hasLength(1));
    // The snackbar's time, so that nothing of it is left at the end.
    await tester.pump(const Duration(seconds: 5));
    await settle(tester,
        () => find.text(en.plinkRequestSent).evaluate().isEmpty, 'the snackbar gone');
    await tester.runAsync(() async {
      await receives(ola, rick.myRid);
      expect(ola.requestsByRid[rick.myRid]!.viaLink, isTrue);
    });

    // Typed into the handle search: held too, and the request already sent
    // is said.
    await toTab(tester, en.addHandle);
    expect(find.text(en.plinkFindAlso), findsOneWidget);
    expect(find.text(en.hdlUnavailable), findsOneWidget,
        reason: 'no handle log: a handle cannot be found here, a link can');
    final field = find.widgetWithText(TextField, en.hdlFindLabel);
    await tester.enterText(field, code);
    await tester.tap(find.text(en.hdlFind));
    await settle(tester, () => send.evaluate().isNotEmpty,
        'held from the handle search');
    expect(find.text(en.plinkOpenSent(0)), findsOneWidget);
    final sends = tap.sendsTo(link.introRid);
    await tester.pageBack();
    await settle(tester, () => find.byType(OpenLinkScreen).evaluate().isEmpty,
        'closed without sending');
    expect(tap.sendsTo(link.introRid), sends,
        reason: 'nothing sent without Send request');
    // A handle, with no handle log: said, and nothing opened. A damaged
    // link: said as damaged.
    await tester.enterText(field, 'zi1.42');
    await tester.tap(find.text(en.hdlFind));
    await settle(tester,
        () => find.text(en.hdlUnavailable).evaluate().length == 2,
        'handles unavailable, said for the handle typed');
    expect(find.byType(OpenLinkScreen), findsNothing);
    await tester.enterText(field, flipped);
    await tester.tap(find.text(en.hdlFind));
    await settle(tester,
        () => find.text(en.plinkErrDamaged).evaluate().isNotEmpty,
        'a damaged link said as damaged');
    expect(find.byType(OpenLinkScreen), findsNothing);

    // Scanned: the Scan tab's camera sees the link's QR — held on its screen
    // too, and nothing sent.
    await toTab(tester, en.addScan);
    await settle(tester, () => camera.on, 'the camera on');
    camera.show([link.url]);
    await settle(tester, () => send.evaluate().isNotEmpty,
        'a scanned link held on its screen');
    expect(find.text(en.plinkOpenBody), findsOneWidget);
    expect(find.text(en.plinkOpenNote), findsOneWidget);
    await tester.pageBack();
    await settle(tester, () => find.byType(OpenLinkScreen).evaluate().isEmpty,
        'the scanned link closed without sending');
    // Read from a QR image — Open a QR image on the Paste tab, the picker's
    // copy read and then deleted — held too.
    await toTab(tester, en.addPaste);
    picker.qr = link.url;
    await tester.tap(find.text(en.addOpenImage));
    await settle(tester, () => send.evaluate().isNotEmpty,
        'a link read from an image held on its screen');
    expect(find.text(en.plinkOpenBody), findsOneWidget);
    expect(picker.copies, hasLength(1));
    expect(picker.copies.single.existsSync(), isFalse,
        reason: 'the picker\'s copy deleted once read');
    await tester.pageBack();
    await settle(tester, () => find.byType(OpenLinkScreen).evaluate().isEmpty,
        'the image\'s link closed without sending');
    expect(tap.sendsTo(link.introRid), sends,
        reason: 'nothing sent from a scan or an image without Send request');
    await tester.pumpWidget(const SizedBox());

    // Tapped: held, and put in front of its person.
    final deep = DeepLinks(ConnectInvites(rick),
        introLinks: () => rick.handles.linksEnabled);
    await tester.pumpWidget(MultiProvider(
      providers: [
        ChangeNotifierProvider<ChatService>.value(value: rick),
        Provider<DeepLinks>.value(value: deep),
      ],
      child: MaterialApp(
        debugShowCheckedModeBanner: false,
        theme: ZTheme.light(),
        localizationsDelegates: AppLocalizations.localizationsDelegates,
        supportedLocales: AppLocalizations.supportedLocales,
        home: const InviteLinkWatcher(child: Scaffold(body: SizedBox())),
      ),
    ));
    await tester.pump();
    final opened = await tester.runAsync(() => deep.handle(link.url));
    expect(opened, isNull, reason: 'a public link is not an invite');
    await settle(tester, () => send.evaluate().isNotEmpty,
        'a tapped link held on its screen');
    expect(find.text(en.plinkOpenBody), findsOneWidget);
    expect(tap.sendsTo(link.introRid), sends);
    await tester.pumpWidget(const SizedBox());

    // In Spanish, the held screen says the same.
    await tester.pumpWidget(wrap(rick, OpenLinkScreen(link: link.link),
        locale: const Locale('es')));
    await settle(tester,
        () => find.text(es.hdlSendRequest).hitTestable().evaluate().isNotEmpty,
        'the held screen in Spanish');
    expect(find.text(es.plinkOpenBody), findsOneWidget);
    expect(find.text(es.plinkOpenNote), findsOneWidget);
    expect(es.plinkOpenBody, isNot(en.plinkOpenBody));
    await tester.pumpWidget(const SizedBox());
  });

  test(
      '13. the outgoing list: 20 entries for handles and links together, '
      'three ids each, a link stored as its code', () async {
    final dir = await tempDir('sam');
    final vault = await Vault.open(rootOverride: dir);
    final me = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(me.toJson()));
    // Ten requests to handles, as an earlier run of the app left them.
    final t0 = DateTime.now().millisecondsSinceEpoch - 60000;
    final earlier = [
      for (var i = 0; i < 10; i++)
        OutgoingHandleRequest(
            handle: 'hand$i.39',
            ownerPub: randomBytes(32),
            introPub: randomBytes(32),
            xintroPub: randomBytes(32),
            creqIds: [randomBytes(32)],
            sentMs: t0 + i)
    ];
    await vault.kvPut(
        'handle_out', jsonEncode([for (final o in earlier) o.toJson()]));
    final sam = await boot('Sam', id: me, vault: vault);
    await connected([sam]);
    expect(sam.handles.outgoing, hasLength(10));

    // Eleven links, whose mailboxes nobody flagged: the relay takes them.
    final links = [
      for (var i = 0; i < 11; i++)
        await IntroLink.fromSeed(randomBytes(32), pow: 16)
    ];
    for (final l in links) {
      await sam.handles.requestLink(l);
    }
    final out = sam.handles.outgoing;
    expect(out, hasLength(handleOutgoingCap));
    expect([for (final o in out) if (o.viaLink) o.link], links.reversed.toList());
    expect([for (final o in out) if (!o.viaLink) o.handle],
        [for (final o in earlier.skip(1)) o.handle].reversed.toList(),
        reason: 'the oldest went, though it was a handle\'s');

    // Three more through the first link: its three latest ids, and it is
    // the newest entry.
    final first = links.first;
    final firstId = sam.handles.outgoingFor(first)!.creqIds.single;
    for (var i = 0; i < 3; i++) {
      await sam.handles.requestLink(first);
    }
    final e = sam.handles.outgoingFor(first)!;
    expect(e.creqIds, hasLength(handleOutgoingIdsPerHandle));
    expect(e.creqIds.any((i) => constantTimeEquals(i, firstId)), isFalse,
        reason: 'the three latest');
    expect(sam.handles.outgoing.first.link, first);
    expect(sam.handles.outgoing, hasLength(handleOutgoingCap));

    // Stored as its code, with no handle and no owner key — what a build
    // from before links, which requires both, skips — and read back.
    final stored =
        (jsonDecode((await sam.vault.kvGet('handle_out'))!) as List).cast<Map>();
    final rows = [
      for (final r in stored)
        if (r.containsKey('link')) r
    ];
    expect(rows, hasLength(11));
    for (final r in rows) {
      expect(r.containsKey('h'), isFalse);
      expect(r.containsKey('owner'), isFalse);
      expect(IntroLink.parse(r['link'] as String).pow, 16);
      final back = OutgoingHandleRequest.fromJson(r.cast<String, Object?>());
      expect(back.viaLink, isTrue);
      expect(back.handle, '');
    }
  });

  test(
      '14. pow_required: one re-stamp at max(printed, bits <= 28) for the '
      'relay\'s day, then stop', () async {
    final olga = await boot('OlgaR');
    final rex = await boot('RexR');
    final nina = await boot('NinaR');
    final lia = await boot('LiaR');
    await connected([olga, rex, nina, lia]);
    final link = await made(olga, pow: 16);
    final drains = olga.handles.linkDrains;
    await olga.handles.askMoreWork(20);
    await waitUntil(() => olga.handles.linkDrains > drains,
        what: 'flagged at 20');

    // Rex's clock is two days behind, so his first stamp is for a day the
    // relay does not take: refused, with the work it asks and its day.
    rex.handles.now = () => DateTime.now().millisecondsSinceEpoch - 2 * 86400000;
    final before = tap.sendsTo(link.introRid);
    await rex.handles.requestLink(link.link);
    expect(rex.handles.stampsMade, 2);
    final sends = sendsAfter(link.introRid, before);
    expect(sends, hasLength(2));
    expect(sends[1]['payload'], sends[0]['payload'],
        reason: 'the same envelope, stamped again');
    expect(
        await verifyIntroPowStamp(
            introRid: link.introRid,
            day: today(),
            envelope: utf8.encode(sends[1]['payload'] as String),
            nonce: unb64url(sends[1]['pow'] as String),
            bits: 20),
        isTrue,
        reason: 'for the relay\'s day, at the work its refusal asked');
    await receives(olga, rex.myRid);

    // Stamps that never pass: two sends, then it stops.
    nina.handles.debugStampFilter = (_) => b64url(Uint8List(16));
    final b2 = tap.sendsTo(link.introRid);
    await expectLater(
        nina.handles
            .requestLink(link.link)
            .timeout(const Duration(seconds: 60)),
        failsWith(HandleFailure.powRefused));
    expect(nina.handles.stampsMade, 2);
    expect(tap.sendsTo(link.introRid), b2 + 2,
        reason: 'the first send and one re-stamp, and no more');
    expect(nina.handles.outgoing, isEmpty, reason: 'nothing to wait for');

    // A refusal asking more than a link may carry, from a relay that lies:
    // the one re-stamp stays at the printed work.
    tap.rewriteDown = (c, f) =>
        f['t'] == 'error' && f['code'] == 'pow_required' ? {...f, 'bits': 40} : f;
    lia.handles.now = () => DateTime.now().millisecondsSinceEpoch - 2 * 86400000;
    final b3 = tap.sendsTo(link.introRid);
    try {
      await lia.handles.requestLink(link.link).timeout(const Duration(seconds: 60));
    } on HandleException catch (e) {
      // The relay asks 20 of a stamp of 16: refused, most of the time.
      expect(e.failure, HandleFailure.powRefused);
    }
    tap.rewriteDown = null;
    expect(lia.handles.stampsMade, 2);
    final liaSends = sendsAfter(link.introRid, b3);
    expect(liaSends, hasLength(2));
    expect(
        await verifyIntroPowStamp(
            introRid: link.introRid,
            day: today(),
            envelope: utf8.encode(liaSends[1]['payload'] as String),
            nonce: unb64url(liaSends[1]['pow'] as String),
            bits: 16),
        isTrue,
        reason: 'the printed work, for the relay\'s day');
  });

  test(
      '15. an ia under the link\'s intro adds the owner unverified, said so; '
      'any other acceptance is an ordinary request', () async {
    final olga = await boot('OlgaA');
    final rick = await boot('RickA');
    final tess = await boot('TessA');
    await connected([olga, rick, tess]);
    // Made, drained, asked through and accepted with no handle log
    // configured on either side: a link needs none.
    for (final s in [olga, rick, tess]) {
      expect(s.handles.config.enabled, isFalse, reason: s.displayName);
      expect(s.handles.available, isFalse, reason: s.displayName);
    }
    final link = await made(olga, pow: 16);
    await rick.handles.requestLink(link.link);
    expect(rick.handles.outgoing.single.viaLink, isTrue);
    await receives(olga, rick.myRid);
    expect(olga.requestsByRid[rick.myRid]!.viaLink, isTrue);
    await olga.acceptRequest(rick.myRid);
    await waitUntil(
        () =>
            rick.contacts.containsKey(olga.myRid) &&
            rick.handles.outgoing.isEmpty,
        what: 'Rick holding Olga, through her link');
    expect(rick.requestsByRid.containsKey(olga.myRid), isFalse,
        reason: 'an acknowledged acceptance is not a request');
    expect(rick.contacts[olga.myRid]!.verified, isFalse);
    expect(olga.contacts[rick.myRid]!.verified, isFalse);
    expect(rick.verificationWith(olga.myRid), VerificationState.unverified);
    expect(olga.verificationWith(rick.myRid), VerificationState.unverified);
    final said = systemBody(SystemKind.introLinkAccepted);
    expect(
        [
          for (final m in rick.messagesByChat[olga.myRid]!)
            if (m.kind == 'system') m.body
        ],
        contains(said));
    expect(systemText(en, said), en.sysIntroLinkAccepted);
    expect(systemText(es, said), es.sysIntroLinkAccepted);
    expect(es.sysIntroLinkAccepted, isNot(en.sysIntroLinkAccepted));
    expect(await rick.handleViaOf(olga.myRid), isNull,
        reason: 'a link names no handle');
    await rick.sendText(olga.myRid, 'found you by your link');
    await waitUntil(
        () => texts(olga, rick.myRid).contains('found you by your link'),
        what: 'Olga reading Rick');
    await olga.sendText(rick.myRid, 'so you did');
    await waitUntil(() => texts(rick, olga.myRid).contains('so you did'),
        what: 'Rick reading Olga');

    // Tess asks too, and Olga's app answers as one from before the
    // acknowledgement: an ordinary request.
    await tess.handles.requestLink(link.link);
    await receives(olga, tess.myRid);
    final waiting = tess.handles.outgoing.single;
    olga.handles.debugOmitAcknowledgement = true;
    await olga.acceptRequest(tess.myRid);
    olga.handles.debugOmitAcknowledgement = false;
    await waitUntil(() => tess.requestsByRid.containsKey(olga.myRid),
        what: 'the bare acceptance filed as an ordinary request');
    expect(tess.contacts.containsKey(olga.myRid), isFalse);
    expect(tess.handles.outgoing.single.viaLink, isTrue);

    final raw = await rawSender();
    // An ia under another link's intro.
    final mallory = await ZIdentity.generate();
    final forged = await signIntroAck(
        introSeed: randomBytes(32),
        requesterRid: tess.myRid,
        ownerAccountEdPub: mallory.edPub,
        creqId: waiting.creqIds.last);
    await raw.send(
        to: tess.myRid,
        id: newMessageId(),
        payload: await sealedRequest(mallory,
            to: tess.myRid, xPub: tess.identity.xPub, ia: forged));
    final malloryRid = await mallory.routingId();
    await waitUntil(() => tess.requestsByRid.containsKey(malloryRid),
        what: 'the forged acceptance filed as an ordinary request');
    expect(tess.contacts.containsKey(malloryRid), isFalse);
    // The genuine ia — the link's seed, for Olga's account — carried by
    // another account.
    final genuine = await signIntroAck(
        introSeed: olga.handles.link!.seed,
        requesterRid: tess.myRid,
        ownerAccountEdPub: olga.identity.edPub,
        creqId: waiting.creqIds.last);
    final eve = await ZIdentity.generate();
    await raw.send(
        to: tess.myRid,
        id: newMessageId(),
        payload: await sealedRequest(eve,
            to: tess.myRid, xPub: tess.identity.xPub, ia: genuine));
    final eveRid = await eve.routingId();
    await waitUntil(() => tess.requestsByRid.containsKey(eveRid),
        what: 'the replayed acknowledgement filed as an ordinary request');
    expect(tess.contacts.containsKey(eveRid), isFalse);
    expect(tess.handles.outgoing.single.viaLink, isTrue,
        reason: 'none of those answered it');
    // The same acknowledgement from the account it names: linked.
    await raw.send(
        to: tess.myRid,
        id: newMessageId(),
        payload: await sealedRequest(olga.identity,
            to: tess.myRid, xPub: tess.identity.xPub, ia: genuine));
    await waitUntil(
        () =>
            tess.contacts.containsKey(olga.myRid) &&
            tess.handles.outgoing.isEmpty,
        what: 'Tess holding Olga, through her link');
  });

  testWidgets(
      '16. after 30 days unanswered, the list and the link\'s screen say it '
      'may have been replaced or withdrawn', (tester) async {
    await tester.binding.setSurfaceSize(const Size(800, 2400));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.runAsync(() async {
      final svc = await boot('Una', relayUrl: 'ws://127.0.0.1:1');
      final link = await IntroLink.fromSeed(randomBytes(32), pow: 16);
      final sent = DateTime.now().millisecondsSinceEpoch;
      await svc.vault.kvPut(
          'handle_out',
          jsonEncode([
            OutgoingHandleRequest.viaLink(
                    link: link, creqIds: [randomBytes(32)], sentMs: sent)
                .toJson()
          ]));
      await svc.handles.load();
      expect(svc.handles.outgoingFor(link), isNotNull);
      for (final (days, said) in [(29, false), (30, true), (45, true)]) {
        svc.handles.now = () => sent + days * 86400000 + 1000;
        expect(svc.handles.linkUnanswered(svc.handles.outgoingFor(link)!), said,
            reason: '$days days');
        for (final (locale, l) in [
          (const Locale('en'), en as AppLocalizations),
          (const Locale('es'), es as AppLocalizations),
        ]) {
          await tester.pumpWidget(wrap(
              svc, Scaffold(body: FindHandleView(key: UniqueKey())),
              locale: locale));
          await until(
              tester,
              () => find
                  .text(l.plinkWaitingEntry(introLinkShort(link)))
                  .evaluate()
                  .isNotEmpty,
              'the waiting list');
          expect(find.text(l.plinkUnanswered), said ? findsOneWidget : findsNothing,
              reason: '$days days, the list, ${locale.languageCode}');
          await tester.pumpWidget(wrap(
              svc, OpenLinkScreen(key: UniqueKey(), link: link),
              locale: locale));
          await until(tester,
              () => find.text(l.plinkOpenSent(days)).evaluate().isNotEmpty,
              'the link\'s screen');
          expect(find.text(l.plinkUnanswered), said ? findsOneWidget : findsNothing,
              reason: '$days days, the link\'s screen, ${locale.languageCode}');
        }
      }
      expect(es.plinkUnanswered, isNot(en.plinkUnanswered));
      await tester.pumpWidget(const SizedBox());
    });
  });

  testWidgets(
      '17. a client recognises its own link: it says so, offers no Send '
      'request, and sends nothing', (tester) async {
    await tester.runAsync(() async {
      final olga = await boot('OlgaOwn');
      await connected([olga]);
      final link = await made(olga, pow: 16);
      expect(olga.handles.isOwnMailbox(link.introRid), isTrue);
      final before = tap.sendsTo(link.introRid);
      await expectLater(olga.handles.requestLink(link.link),
          failsWith(HandleFailure.ownLink));
      expect(olga.handles.stampsMade, 0);
      expect(olga.handles.outgoing, isEmpty);
      expect(tap.sendsTo(link.introRid), before);
      expect(handleFailureText(en, HandleFailure.ownLink), en.plinkOwn);
      for (final (locale, l) in [
        (const Locale('en'), en as AppLocalizations),
        (const Locale('es'), es as AppLocalizations),
      ]) {
        await tester.pumpWidget(wrap(
            olga, OpenLinkScreen(key: UniqueKey(), link: link.link),
            locale: locale));
        await until(tester, () => find.text(l.plinkOwn).evaluate().isNotEmpty,
            'its own link recognised');
        expect(find.text(l.hdlSendRequest), findsNothing);
        expect(find.text(l.plinkOpenBody), findsNothing);
      }
      expect(es.plinkOwn, isNot(en.plinkOwn));
      await tester.pumpWidget(const SizedBox());
      expect(tap.sendsTo(link.introRid), before);
    });
  });
}
