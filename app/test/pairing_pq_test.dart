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
//      whose connection closed once the enrolment had gone up says its
//      connection dropped while it sent the account, which may or may not
//      have arrived — not that the connection was lost, nor that the laptop
//      did not finish — in both languages, and lists nothing, the laptop
//      having installed it; one whose connection stays links the laptop on
//      its report;
//  17. a laptop whose connection to the relay closes while it waits for the
//      enrolment says the connection was lost, at once and in both
//      languages, where it used to wait out its timer and blame the phone;
//  18. a laptop whose mailbox someone else holding the code logs in as —
//      while its person compares the digits, before any reply, or while its
//      first frame is still going up — says another connection took the
//      link over, at once and in both languages, and shows a new code;
//  19. a phone whose connection drops as it puts the enrolment up, before
//      the relay has it, says its connection dropped while it sent the
//      account, which may or may not have arrived, and the laptop, sent
//      nothing, names that among its reasons: neither screen blames the
//      other device alone, in either language, and nothing is linked;
//  20. a relay that cannot be reached — nothing listening, an address that
//      is not a relay, a secure connection that cannot be made — says so on
//      both screens, and a mistyped code on the phone says it is not one, in
//      both languages and with no exception text in any of them;
//  21. a phone whose mailbox someone else holding the code logs in as, while
//      its person compares the digits, says so, and closes the laptop's
//      mailbox the same way, so the laptop says so too, at once, and shows a
//      new code; the phone will not use that code again, and says why, in
//      both languages — once restarted too;
//  22. a phone asked to host a link with a code it is still hosting one with
//      — its person went back and entered the code again — stops the first
//      itself, and neither is a takeover: before the laptop has started, or
//      while the laptop's commitment is on its way, the first says it was
//      cancelled and the second links the laptop, nothing kept as spent; and
//      a first that had already sent the account runs on, and both say the
//      laptop is linked;
//  23. leaving the phone's link screen stops the attempt it started, at once,
//      and the code then links when it is entered again;
//  24. a phone whose mailbox someone else holding the code logs in as while
//      its person compares the digits is taken over however the attempt
//      then ends — its person says the digits differ, the code is entered
//      again, or its screen is left: it says another connection took the
//      link over, keeps the code as spent and closes the laptop's mailbox,
//      so the laptop says so too and shows a new code, and the call that
//      came again says the code will not be used again;
//  25. a code entered again on the phone once the link it stopped had
//      answered the laptop says at once, in both languages, that the laptop
//      needs a new code — the laptop takes no second answer — and the
//      laptop, sent nothing, names its other device's leaving the link
//      screen among its reasons, and shows a new code;
//  26. leaving the new device's link screen stops the attempt it started,
//      at once, and nothing of the attempt reaches the screen once it has
//      gone, nor moves the app on;
//  27. a code entered again on the phone once the link it stopped had
//      answered the laptop, and that attempt is over, says at once that the
//      laptop needs a new code — once restarted too — the phone keeping the
//      code by its rendezvous id, not the code itself, and logging in as the
//      code's mailbox for neither;
//  28. a code entered again on the phone once the link it answered ended
//      without a stop — its person said the digits differ, its wait for the
//      laptop's opening ran out, or its connection dropped once the relay had
//      taken its reply — says at once, in both languages, that the laptop
//      needs a new code, the phone keeping each code by its rendezvous id;
//  29. a code whose reply never reached the relay — the phone's connection
//      closed as it acknowledged the laptop's commitment — is not kept, and
//      entered again links the laptop;
//  30. a code that linked the laptop, entered again, says at once, in both
//      languages, that it has already linked a device and how to link
//      another — once restarted too — the phone keeping the code by its
//      rendezvous id under a key of its own, and logging in as the code's
//      mailbox for neither;
//  31. a link stopped on the phone while its connection to the code's
//      mailbox opens — the relay's challenge held, so the phone has not
//      answered it — ends at once, the phone closing that connection, never
//      logged in, and keeping, spending and acknowledging nothing, and the
//      code entered again links the laptop (4.9.2);
//  32. a link stopped once the phone has answered the relay's challenge,
//      the answer late on its way, and the code entered again at once: the
//      stopped link waits for the relay to welcome that connection, and
//      closes it, before the code is tried again, which links the laptop
//      with no takeover said on either device and nothing spent (4.9.2).
@Tags(['integration'])
@Timeout(Duration(minutes: 5))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/enrollment.dart';
import 'package:zapp/core/key_transparency.dart';
import 'package:zapp/core/receipts.dart';
import 'package:zapp/core/relay_url.dart';
import 'package:zapp/core/sealing_keys.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/l10n/app_localizations_en.dart';
import 'package:zapp/l10n/app_localizations_es.dart';
import 'package:zapp/l10n/pairing_text.dart';
import 'package:zapp/ui/link_device_screen.dart';
import 'package:zapp/ui/theme.dart';

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
/// handed it, and the relay sees the connection go. [cutUp] does the same
/// for a frame from the client, which never reaches the relay. [holdUp],
/// when it answers a frame from the client with a future, keeps that frame
/// from the relay — as one still going up — until the future completes,
/// then passes it on if the connection is still there — or, with
/// [passOnAfterLeaving], once the client has gone too, as TCP delivers what
/// a client sent before it closed, the relay seeing the connection go only
/// after that. [holdDown] does the same for a frame from the relay, keeping
/// it, and every frame after it on that connection, from the client; it is
/// told which connection, counting from 0 in the order they came
/// ([connections] so far). [welcomed] keeps the routing id of every login
/// the relay welcomes through it, and [left] that of every such connection
/// once the client's side of it has closed — whichever end closed it, the
/// client has taken the close by then; [closed] keeps the number of every
/// connection whose client side has closed, welcomed or not.
class Recorder {
  final HttpServer _server;
  final frames = <String, List<String>>{};
  final welcomed = <String>[];
  final left = <String>[];
  final closed = <int>{};
  var _connections = 0;
  Recorder._(this._server);

  String get url => 'ws://127.0.0.1:${_server.port}';

  /// How many connections have come through so far.
  int get connections => _connections;

  static Future<Recorder> start(String relayUrl,
      {List<String> Function(String frame)? hand,
      bool Function(String frame)? cut,
      bool Function(String frame)? cutUp,
      Future<void>? Function(String frame)? holdUp,
      bool passOnAfterLeaving = false,
      Future<void>? Function(String frame, int connection)? holdDown}) async {
    final r =
        Recorder._(await HttpServer.bind(InternetAddress.loopbackIPv4, 0));
    r._server.listen((req) async {
      final connection = r._connections++;
      final down = await WebSocketTransformer.upgrade(req);
      // The Host header passes through, so the relay checks each
      // authentication against the address the client dialled.
      final up = await WebSocket.connect(relayUrl,
          headers: {'host': req.headers.value('host') ?? ''});
      var gone = false;
      String? rid;
      var closed = false;
      void leave() {
        if (rid == null || closed) return;
        closed = true;
        r.left.add(rid!);
      }

      var pending = 0;
      var downDone = false;
      down.listen((d) {
        if (gone) return;
        if (cutUp != null && d is String && cutUp(d)) {
          gone = true;
          down.close();
          up.close();
          return;
        }
        r._note(d, 'send');
        final held = d is String ? holdUp?.call(d) : null;
        if (held != null) {
          pending++;
          held.then((_) {
            pending--;
            if (!gone && up.readyState == WebSocket.open) up.add(d);
            if (downDone && pending == 0) up.close();
          });
          return;
        }
        up.add(d);
      }, onDone: () {
        leave();
        r.closed.add(connection);
        downDone = true;
        if (passOnAfterLeaving && pending > 0) return;
        up.close();
      }, onError: (Object _) => up.close());
      var handed = Future<void>.value();
      up.listen((d) {
        if (gone) return;
        r._note(d, 'msg');
        rid ??= r._welcome(d);
        if (cut != null && d is String && cut(d)) {
          gone = true;
          down.close();
          up.close();
          return;
        }
        void pass() {
          if (hand == null || d is! String) {
            down.add(d);
          } else {
            for (final f in hand(d)) {
              down.add(f);
            }
          }
        }

        if (holdDown == null) {
          pass();
          return;
        }
        // Held, and every frame after it on this connection behind it,
        // passed on if the client is still there.
        final held = d is String ? holdDown(d, connection) : null;
        handed = handed.then((_) => held ?? Future<void>.value()).then((_) {
          if (!gone && down.readyState == WebSocket.open) pass();
        });
      }, onDone: () {
        // The relay's own close code passes on — 4002 above all, its word
        // that another connection logged in as this one's routing id. The
        // connection counts as gone once the client has closed its side
        // (above), which it does once it has taken the close.
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

  /// The routing id a relay `ready` [data] welcomes a login as, kept in
  /// [welcomed]; null for anything else.
  String? _welcome(Object? data) {
    if (data is! String) return null;
    try {
      final f = jsonDecode(data);
      if (f is Map && f['t'] == 'ready' && f['id'] is String) {
        welcomed.add(f['id'] as String);
        return f['id'] as String;
      }
    } catch (_) {}
    return null;
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

  /// Whether [frame], from a client, is its `send` of the envelope [id].
  static bool sendOf(String frame, String id) {
    try {
      final f = jsonDecode(frame);
      return f is Map && f['t'] == 'send' && f['id'] == id;
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
      'time: its person may have said the codes differ, confirmed too late '
      'or left its link screen, or it could not get your account to the '
      'relay. Start again on both devices, and confirm on both within about '
      'forty seconds of each other.';
  const laptopNoEnrolmentEs = 'Tu otro dispositivo no envió tu cuenta a '
      'tiempo: puede que allí dijeran que los códigos no coinciden, que '
      'confirmaran demasiado tarde o que salieran de su pantalla de '
      'vinculación, o que no pudiera hacer llegar tu cuenta al relay. Vuelve '
      'a empezar en los dos dispositivos y confirma en ambos con menos de '
      'unos cuarenta segundos de diferencia.';
  const phoneInterrupted = "This device's connection to the relay dropped "
      'while it was sending your account, before the new device said it had '
      'it, so this device has not added it: your account may or may not have '
      'reached the new device. Start again on both devices. If the new device '
      'shows your chats anyway, it is not on your account: on it, open '
      'Settings → Wipe everything, then link it again.';
  const phoneInterruptedEs = 'La conexión de este dispositivo con el relay '
      'se cortó mientras enviaba tu cuenta, antes de que el dispositivo nuevo '
      'dijera que la tenía, así que este no lo ha añadido: puede que tu cuenta '
      'le haya llegado o no. Vuelve a empezar en los dos dispositivos. Si aun '
      'así el dispositivo nuevo muestra tus chats, no está en tu cuenta: en '
      'él, abre Ajustes → Borrar todo y vuelve a vincularlo.';
  const relayUnreachable = 'This device could not reach the relay. Check '
      'that it is online and that the relay address is right, then start '
      'again on both devices.';
  const relayUnreachableEs = 'Este dispositivo no pudo conectar con el '
      'relay. Comprueba que tiene conexión y que la dirección del relay es '
      'correcta, y vuelve a empezar en los dos dispositivos.';
  const notACode = 'That is not a pairing code. Enter the whole code the new '
      'device shows, then try again.';
  const notACodeEs = 'Eso no es un código de emparejamiento. Introduce el '
      'código completo que muestra el dispositivo nuevo y vuelve a '
      'intentarlo.';
  const phoneTakenOver = 'Another connection took over this link, so this '
      'device has not added the new one: someone else may have seen the '
      'code, and this device will not use it again. Start again with a new '
      'code: if the new device still shows the old one, go back there and '
      'choose "Link to an existing account" again. If the new device shows '
      'your chats anyway, it is not on your account: on it, open Settings → '
      'Wipe everything, then link it again.';
  const phoneTakenOverEs = 'Otra conexión se hizo cargo de esta '
      'vinculación, así que este dispositivo no ha añadido el nuevo: puede '
      'que alguien más haya visto el código, y este dispositivo no volverá a '
      'usarlo. Vuelve a empezar con un código nuevo: si el dispositivo nuevo '
      'sigue mostrando el anterior, vuelve atrás allí y elige «Vincular a '
      'una cuenta existente» otra vez. Si aun así el dispositivo nuevo '
      'muestra tus chats, no está en tu cuenta: en él, abre Ajustes → Borrar '
      'todo y vuelve a vincularlo.';
  const codeSpent = 'This device will not use that code again: another '
      'connection took over a link with it, so someone else may have seen '
      'it. On the new device, go back and choose "Link to an existing '
      'account" again for a new code, then enter that one here.';
  const codeSpentEs = 'Este dispositivo no volverá a usar ese código: otra '
      'conexión se hizo cargo de una vinculación con él, así que puede que '
      'alguien más lo haya visto. En el dispositivo nuevo, vuelve atrás y '
      'elige «Vincular a una cuenta existente» otra vez para obtener un '
      'código nuevo, e introdúcelo aquí.';
  const codeAnswered = 'That code was used in a link that did not finish: '
      "the new device already has this device's answer to it, and will not "
      'take another. On the new device, go back and choose "Link to an '
      'existing account" again for a new code, then enter that one here.';
  const codeAnsweredEs = 'Ese código se usó en una vinculación que no '
      'terminó: el dispositivo nuevo ya tiene la respuesta de este '
      'y no aceptará otra. En el dispositivo nuevo, vuelve atrás y elige '
      '«Vincular a una cuenta existente» otra vez para obtener un código '
      'nuevo, e introdúcelo aquí.';
  const codeLinked = 'That code has already linked a device to your '
      'account. To link another device, choose "Link to an existing account" '
      'on it for a new code, then enter that one here.';
  const codeLinkedEs = 'Ese código ya vinculó un dispositivo a tu cuenta. '
      'Para vincular otro dispositivo, elige «Vincular a una cuenta '
      'existente» en él para obtener un código nuevo, e introdúcelo aquí.';
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
      // Anything else stops a link as a failure, never as a version, and
      // in one line of the reader's language with no exception text in it:
      // a broken rule of the ceremony, or something nobody expected.
      for (final other in [
        const PairingAbort('the opening does not match the commitment'),
        StateError('something nobody expected'),
      ]) {
        for (final text in [
          hostLinkFailureText(l, other),
          newDeviceLinkFailureText(l, other)
        ]) {
          expect(text, l.linkFailedOther);
          expect(text, isNot(contains('commitment')));
          expect(text, isNot(contains('nobody expected')));
        }
      }
      // A relay this device could not reach at all, on either screen: no
      // network or nothing listening, an address that is not a relay, a
      // secure connection that could not be made.
      for (final unreachable in <Object>[
        const SocketException('Connection refused'),
        const WebSocketException('was not upgraded to websocket'),
        const HandshakeException('Handshake error in client'),
        const TlsException('certificate'),
        const HttpException('Connection closed before full header'),
      ]) {
        expect(hostLinkFailureText(l, unreachable), l.linkRelayUnreachable,
            reason: '$unreachable');
        expect(newDeviceLinkFailureText(l, unreachable),
            l.linkRelayUnreachable,
            reason: '$unreachable');
      }
      // What was typed on the phone is not a pairing code; or is one the
      // phone saw taken over, and will not use again.
      expect(
          hostLinkFailureText(l, const PairingCodeInvalid('too short')),
          l.linkNotACode);
      expect(hostLinkFailureText(l, const PairingCodeSpent()),
          l.linkCodeSpent);
      // An attempt this device stopped itself, and a code entered again once
      // the attempt it stopped had answered the new device.
      expect(hostLinkFailureText(l, const PairingCancelled()),
          l.linkCancelled);
      expect(hostLinkFailureText(l, const PairingCodeAnswered()),
          l.linkCodeAnswered);
      expect(newDeviceLinkFailureText(l, const PairingCancelled()),
          l.linkCancelled);
      // Each way to a new code names the choice the new device offers, as
      // its onboarding screen words it.
      for (final words in [
        l.linkHostMayBeOlder,
        l.linkHostTakenOver,
        l.linkCodeSpent,
        l.linkCodeAnswered
      ]) {
        expect(words, contains(l.onbLinkExisting));
      }
    }
    // The pairing code's parser says so in a type of its own, and a
    // FormatException still.
    expect(() => PairingCode.parse('ABCD'),
        throwsA(isA<PairingCodeInvalid>().having(
            (e) => e, 'a FormatException', isA<FormatException>())));
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
      // The phone's own connection gone while it sent the account, and the
      // relay refusing it: neither is the new device's doing.
      expect(hostLinkFailureText(l, const PairingEnrolmentInterrupted()),
          l.linkEnrolmentInterrupted);
      expect(hostLinkFailureText(l, PairingEnrolmentRefused('store_full')),
          l.linkEnrolmentRefused);
      // A code that has already linked a device.
      expect(hostLinkFailureText(l, const PairingCodeLinked()),
          l.linkCodeLinked);
    }
    expect(en.linkPeerUnconfirmed, phoneUnconfirmed);
    expect(en.linkPeerGaveUp, phoneGaveUp);
    expect(en.linkPeerUnfinished, phoneUnfinished);
    expect(en.linkNoEnrolment, laptopNoEnrolment);
    expect(en.linkInstallFailed, laptopInstallFailed);
    expect(es.linkInstallFailed, laptopInstallFailedEs);
    expect(en.linkTakenOver, laptopTakenOver);
    expect(es.linkTakenOver, laptopTakenOverEs);
    expect(es.linkNoEnrolment, laptopNoEnrolmentEs);
    expect(en.linkEnrolmentInterrupted, phoneInterrupted);
    expect(es.linkEnrolmentInterrupted, phoneInterruptedEs);
    expect(en.linkRelayUnreachable, relayUnreachable);
    expect(es.linkRelayUnreachable, relayUnreachableEs);
    expect(en.linkNotACode, notACode);
    expect(es.linkNotACode, notACodeEs);
    expect(en.linkHostTakenOver, phoneTakenOver);
    expect(es.linkHostTakenOver, phoneTakenOverEs);
    expect(en.linkCodeSpent, codeSpent);
    expect(es.linkCodeSpent, codeSpentEs);
    expect(en.linkCodeAnswered, codeAnswered);
    expect(es.linkCodeAnswered, codeAnsweredEs);
    expect(en.linkCodeLinked, codeLinked);
    expect(es.linkCodeLinked, codeLinkedEs);
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
      (es.linkEnrolmentInterrupted, en.linkEnrolmentInterrupted),
      (es.linkEnrolmentRefused, en.linkEnrolmentRefused),
      (es.linkRelayUnreachable, en.linkRelayUnreachable),
      (es.linkNotACode, en.linkNotACode),
      (es.linkFailedOther, en.linkFailedOther),
      (es.linkCodeSpent, en.linkCodeSpent),
      (es.linkCodeAnswered, en.linkCodeAnswered),
      (es.linkCodeLinked, en.linkCodeLinked),
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
      expect(l.linkEnrolmentInterrupted,
          contains('${l.stSettings} → ${l.stWipe}'));
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
      '16. a phone that never hears the relay take its enrolment says its '
      'connection dropped while it sent the account when its connection has '
      "gone, and links on the laptop's report when it has not", () async {
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
          expect(phoneScreen(phone), phoneInterrupted,
              reason: '$what: the phone cannot tell whether the account got '
                  'through, and says its connection dropped while it sent '
                  'it — not that the laptop did not finish');
          expect(hostLinkFailureText(es, phone!), phoneInterruptedEs,
              reason: '$what: and in Spanish');
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
    // next looks at its mailbox. And while the laptop's first frame is
    // still going up: the relay closes its connection before it has taken
    // the frame, and until 2026-10-30 the laptop said only that its
    // connection was lost, and kept its code.
    for (final when in ['comparing', 'no reply', 'going up']) {
      final whileComparing = when == 'comparing';
      final what = switch (when) {
        'comparing' => 'taken over while its person compared the digits',
        'no reply' => 'taken over before any reply',
        _ => 'taken over while its first frame was still going up',
      };
      final n = await NewDeviceLink.create();
      final code = n.code;
      final mailbox =
          await RelayPairing.relayIdentityV3(PairingCode.parse(code), 'i');
      // The laptop connects through a front that keeps what it sends, so
      // the test sees its commitment leave — and, going up, keeps it from
      // the relay; the relay's close code passes on.
      final tap = await Recorder.start(relayUrl(),
          holdUp: when == 'going up'
              ? (f) => Recorder.sendOf(f, 'z-pair-commit')
                  ? Completer<void>().future
                  : null
              : null);
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

  test(
      '19. a phone whose connection drops as it puts the enrolment up says '
      'so, and the laptop names that among its reasons', () async {
    // The phone connects through a front that closes its connection as it
    // sends the enrolment: the frame never reaches the relay.
    final rec = await Recorder.start(relayUrl(),
        cutUp: (f) => Recorder.sendOf(f, 'z-pair-enroll'));
    try {
      final alice = await person('Alice19', url: rec.url);
      await connected([alice]);
      const timeout = Duration(seconds: 3), margin = Duration(seconds: 1);
      alice.svc.linkTimeout = timeout;
      alice.svc.linkMargin = margin;
      final listBefore = await alice.svc.ownDeviceListVersion();
      final n = await NewDeviceLink.create();
      final hosted = alice.svc
          .hostDeviceLink(n.code, confirmSas: (_) async => true)
          .then<Object?>((r) => r, onError: (Object e) => e);
      final laptop = await n
          .run(
            relayUrl: relayUrl(),
            confirm: (_) async => true,
            timeout: timeout,
            margin: margin,
          )
          .then<Object?>((r) => r, onError: (Object e) => e);
      final phone = await hosted;
      expect(phoneScreen(phone), phoneInterrupted,
          reason: 'the phone says its own connection dropped while it sent '
              'the account, not that the laptop did not finish');
      expect(hostLinkFailureText(es, phone!), phoneInterruptedEs);
      expect(laptopScreen(laptop), laptopNoEnrolment,
          reason: 'the laptop, sent nothing, names a dropped connection '
              "among the reasons, and not only the phone's person");
      expect(newDeviceLinkFailureText(es, laptop!), laptopNoEnrolmentEs);
      expect(await alice.svc.linkedDevices(), isEmpty);
      expect(await alice.svc.ownDeviceListVersion(), listBefore);
    } finally {
      await rec.close();
    }
  });

  test(
      '20. a relay that cannot be reached, and a code that is not one, say so '
      'on their screens in both languages, with no exception text', () async {
    // A port nothing listens on; a server that answers HTTP and is not a
    // relay; and a secure connection asked of that same plain server.
    final closed = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final deadPort = closed.port;
    await closed.close();
    final http = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    http.listen((r) {
      r.response.statusCode = 200;
      r.response.write('hello');
      r.response.close();
    });
    bool raw(String s) =>
        RegExp(r'Exception|Error|errno|pairing:').hasMatch(s);
    try {
      for (final (what, name, url) in [
        ('nothing listening', 'Alice20a', 'ws://127.0.0.1:$deadPort'),
        ('an address that is not a relay', 'Alice20b',
            'ws://127.0.0.1:${http.port}'),
        ('no secure connection to be had', 'Alice20c',
            'wss://127.0.0.1:${http.port}'),
      ]) {
        final alice = await person(name, url: url);
        final hosted = await alice.svc
            .hostDeviceLink(PairingCode.generate().text,
                confirmSas: (_) async => true)
            .then<Object?>((r) => r, onError: (Object e) => e);
        final n = await NewDeviceLink.create();
        final joined = await n
            .run(relayUrl: url, confirm: (_) async => true)
            .then<Object?>((r) => r, onError: (Object e) => e);
        final words = [
          phoneScreen(hosted),
          hostLinkFailureText(es, hosted!),
          laptopScreen(joined),
          newDeviceLinkFailureText(es, joined!),
        ];
        expect(words, [
          relayUnreachable,
          relayUnreachableEs,
          relayUnreachable,
          relayUnreachableEs
        ], reason: '$what: each screen says it could not reach the relay');
        expect(words.where(raw), isEmpty, reason: what);
      }
      // A code too short to be one, typed on the phone: nothing is sent.
      final alice = await person('Alice20d');
      final typed = await alice.svc
          .hostDeviceLink('ABCD', confirmSas: (_) async => true)
          .then<Object?>((r) => r, onError: (Object e) => e);
      expect([phoneScreen(typed), hostLinkFailureText(es, typed!)],
          [notACode, notACodeEs],
          reason: 'what was typed is not a pairing code');
    } finally {
      await http.close(force: true);
    }
  });

  test(
      '21. a phone whose mailbox someone else holding the code logs in as '
      "stops the laptop too, and will not use that code again", () async {
    final alice = await person('Alice21');
    await connected([alice]);
    const timeout = Duration(seconds: 3), margin = Duration(seconds: 1);
    alice.svc.linkTimeout = timeout;
    alice.svc.linkMargin = margin;
    final n = await NewDeviceLink.create();
    final code = n.code;
    RelayClient? other;
    final hosted = alice.svc
        .hostDeviceLink(code, confirmSas: (_) async {
          // While the phone's person compares, the other login comes in.
          other = await RelayClient.connect(relayUrl(),
              await RelayPairing.relayIdentityV3(PairingCode.parse(code), 'r'));
          return true;
        })
        .then<Object?>((r) => r, onError: (Object e) => e);
    final waited = Stopwatch();
    final laptop = await n
        .run(
          relayUrl: relayUrl(),
          confirm: (_) async {
            waited.start();
            return true;
          },
          timeout: timeout,
          margin: margin,
        )
        .then<Object?>((r) => r, onError: (Object e) => e);
    waited.stop();
    try {
      final phone = await hosted;
      expect(phoneScreen(phone), phoneTakenOver,
          reason: 'the phone says another connection took over');
      expect(hostLinkFailureText(es, phone!), phoneTakenOverEs);
      expect(laptopScreen(laptop), laptopTakenOver,
          reason: 'the laptop, closed the same way, says so too, and does '
              'not name a cause it cannot see');
      expect(newDeviceLinkFailureText(es, laptop!), laptopTakenOverEs);
      expect(waited.elapsed, lessThan(timeout),
          reason: 'at once, and not when its wait for the enrolment ran out');
      expect(n.code, isNot(code), reason: 'and it shows a new code');
      expect(await alice.svc.linkedDevices(), isEmpty);

      // The phone will not use that code again, and says why.
      final again = await alice.svc
          .hostDeviceLink(code, confirmSas: (_) async => true)
          .then<Object?>((r) => r, onError: (Object e) => e);
      expect([phoneScreen(again), hostLinkFailureText(es, again!)],
          [codeSpent, codeSpentEs]);
      // Nor once it has restarted.
      alice.svc.dispose();
      await alice.svc.transport.stop();
      live.remove(alice);
      final restarted = await boot(alice.dir, 'Alice21', vault: alice.vault);
      final later = await restarted.svc
          .hostDeviceLink(code, confirmSas: (_) async => true)
          .then<Object?>((r) => r, onError: (Object e) => e);
      expect(phoneScreen(later), codeSpent, reason: 'once restarted too');
    } finally {
      await other?.close();
    }
  });

  test(
      '22. a phone asked to host a link with a code it is still hosting one '
      'with stops the first itself, and neither is a takeover', () async {
    // The phone connects through a front that notes each login the relay
    // welcomes, so the test sees the first attempt in before the second.
    final rec = await Recorder.start(relayUrl());
    try {
      final alice = await person('Alice22', url: rec.url);
      await connected([alice]);
      const timeout = Duration(seconds: 4), margin = Duration(seconds: 1);
      alice.svc.linkTimeout = timeout;
      alice.svc.linkMargin = margin;
      var listed = 0;
      for (final when in ['not started', 'on its way', 'sent']) {
        final what = switch (when) {
          'not started' => 'the laptop not yet started',
          'on its way' => "the laptop's commitment on its way",
          _ => 'the first attempt had sent the account',
        };
        final n = await NewDeviceLink.create();
        final code = n.code;
        final mailbox = await (await RelayPairing.relayIdentityV3(
                PairingCode.parse(code), 'r'))
            .routingId();
        // The laptop connects through a front that, while its commitment is
        // on its way, keeps it from the relay until the first attempt is
        // over.
        final release = Completer<void>();
        final tap = await Recorder.start(relayUrl(),
            holdUp: when == 'on its way'
                ? (f) =>
                    Recorder.sendOf(f, 'z-pair-commit') ? release.future : null
                : null);
        final installing = Completer<void>(), goOn = Completer<void>();
        Future<Object?> laptop() => n
            .run(
              relayUrl: tap.url,
              confirm: (_) async => true,
              timeout: timeout,
              margin: margin,
              install: (_) async {
                if (when != 'sent') return;
                installing.complete();
                await goOn.future;
              },
            )
            .then<Object?>((r) => r, onError: (Object e) => e);
        Future<Object?>? joined;
        final first = alice.svc
            .hostDeviceLink(code, confirmSas: (_) async => true)
            .then<Object?>((r) => r, onError: (Object e) => e);
        if (when == 'sent') {
          joined = laptop();
          await installing.future;
        } else {
          await waitUntil(() => rec.welcomed.contains(mailbox),
              what: "$what: the first attempt logged in as the phone's "
                  'mailbox');
          if (when == 'on its way') {
            joined = laptop();
            await waitUntil(() => tap.frames.containsKey('commit-v3'),
                what: "$what: the laptop's commitment sent");
          }
        }
        // The person went back, and entered the same code again.
        final second = alice.svc
            .hostDeviceLink(code, confirmSas: (_) async => true)
            .then<Object?>((r) => r, onError: (Object e) => e);
        if (when == 'sent') {
          goOn.complete();
          expect(phoneScreen(await first), en.linkDone,
              reason: '$what: it ran on to its end, and linked the laptop');
        } else {
          expect(phoneScreen(await first), en.linkCancelled,
              reason: '$what: the first attempt says it was cancelled, not '
                  'that someone else took the link over');
          release.complete();
          joined ??= laptop();
        }
        expect(laptopScreen(await joined), '(installed)',
            reason: '$what: the laptop was not closed, and links');
        expect(phoneScreen(await second), en.linkDone,
            reason: '$what: the second attempt says the laptop is linked');
        listed++;
        expect(await alice.svc.linkedDevices(), hasLength(listed),
            reason: '$what: the laptop listed, once');
        expect(await alice.vault.kvGet('link_spent_codes'), isNull,
            reason: '$what: no code kept as one someone else took over');
        await tap.close();
      }
    } finally {
      await rec.close();
    }
  });

  /// Runs both clocks — the real one for the sockets and the vault, the
  /// test's for the timers a screen's attempt set — until [cond] holds,
  /// failing with [what] after [within].
  Future<void> drive(WidgetTester t, bool Function() cond,
      {required String what,
      Duration within = const Duration(seconds: 30)}) async {
    final deadline = DateTime.now().add(within);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        fail('not within ${within.inSeconds} s: $what');
      }
      await t.runAsync(
          () => Future<void>.delayed(const Duration(milliseconds: 50)));
      await t.pump(const Duration(milliseconds: 100));
    }
  }

  testWidgets(
      "23. leaving the phone's link screen stops the attempt it started, at "
      'once, and the code then links when it is entered again', (t) async {
    late Person alice;
    late Recorder rec;
    late NewDeviceLink n;
    late List<String> mailboxes;
    await t.runAsync(() async {
      rec = await Recorder.start(relayUrl());
      alice = await person('Alice23', url: rec.url);
      await connected([alice]);
      // An attempt left running would still be waiting when the test looks.
      alice.svc.linkTimeout = const Duration(seconds: 30);
      alice.svc.linkMargin = const Duration(seconds: 1);
      n = await NewDeviceLink.create();
      final code = PairingCode.parse(n.code);
      mailboxes = [
        for (final who in [
          await RelayPairing.relayIdentityV3(code, 'r'),
          await RelayPairing.relayIdentityV2(code, 'r'),
          await RelayPairing.relayIdentity(code, 'r'),
        ])
          await who.routingId()
      ];
    });
    await t.pumpWidget(ChangeNotifierProvider<ChatService>.value(
      value: alice.svc,
      child: MaterialApp(
        theme: ZTheme.light(),
        localizationsDelegates: AppLocalizations.localizationsDelegates,
        supportedLocales: AppLocalizations.supportedLocales,
        home: Builder(
          builder: (context) => Scaffold(
            body: TextButton(
              key: const ValueKey('open'),
              onPressed: () => Navigator.of(context).push(
                  MaterialPageRoute<void>(
                      builder: (_) => const HostLinkScreen())),
              child: const Text('open'),
            ),
          ),
        ),
      ),
    ));
    await t.tap(find.byKey(const ValueKey('open')));
    await t.pumpAndSettle();
    await t.enterText(find.byType(TextField), n.code);
    await t.tap(find.text(en.linkDeviceAction));
    await drive(t, () => rec.welcomed.contains(mailboxes.first),
        what: "the screen's attempt logged in as the phone's mailbox");
    // The person goes back.
    await t.pageBack();
    await t.pump();
    await t.pump(const Duration(milliseconds: 500));
    expect(find.byType(HostLinkScreen), findsNothing);
    // Every mailbox it had logged in as closed: the phone's first, and of
    // the two it opens after it, any the relay had welcomed. One still
    // opening is given up and never logged in; until 2026-11-01 each ran to
    // its end first, and all three closed.
    await drive(t, () {
      final opened = mailboxes.where(rec.welcomed.contains).toList();
      return opened.contains(mailboxes.first) &&
          opened.every(rec.left.contains);
    },
        within: const Duration(seconds: 10),
        what: 'the attempt the screen started stopped once the screen was '
            'left, every mailbox it had logged in as closed');

    // The person enters the same code again, and the laptop starts.
    late Future<Object?> again, joined;
    await t.runAsync(() async {
      again = alice.svc
          .hostDeviceLink(n.code, confirmSas: (_) async => true)
          .then<Object?>((r) => r, onError: (Object e) => e);
      joined = n
          .run(
            relayUrl: relayUrl(),
            confirm: (_) async => true,
            timeout: const Duration(seconds: 4),
            margin: const Duration(seconds: 1),
          )
          .then<Object?>((r) => r, onError: (Object e) => e);
    });
    Object? phone, laptop;
    var open = 2;
    unawaited(again.then((r) {
      phone = r;
      open--;
    }));
    unawaited(joined.then((r) {
      laptop = r;
      open--;
    }));
    await drive(t, () => open == 0,
        what: 'the second attempt, and the laptop, over');
    expect(phoneScreen(phone), en.linkDone,
        reason: 'the code links when it is entered again');
    expect(laptopScreen(laptop), '(installed)');
    await t.runAsync(() async {
      expect(await alice.svc.linkedDevices(), hasLength(1));
      expect(await alice.vault.kvGet('link_spent_codes'), isNull,
          reason: 'leaving the screen spent nothing');
    });
    await t.pumpWidget(const SizedBox());
    await t.runAsync(() async {
      live.remove(alice);
      alice.svc.dispose();
      await alice.svc.transport.stop();
      await rec.close();
    });
  });

  test(
      '24. a phone whose mailbox someone else holding the code logs in as '
      'while its person compares the digits is taken over however the '
      'attempt then ends', () async {
    // The phone connects through a front that notes when each of its
    // connections has closed, so the test sees the other login close the
    // phone's mailbox before the attempt ends.
    final rec = await Recorder.start(relayUrl());
    try {
      final alice = await person('Alice24', url: rec.url);
      await connected([alice]);
      const timeout = Duration(seconds: 4), margin = Duration(seconds: 1);
      alice.svc.linkTimeout = timeout;
      alice.svc.linkMargin = margin;
      for (final how in ['differ', 'again', 'left']) {
        final what = switch (how) {
          'differ' => 'its person then said the digits differ',
          'again' => 'the code then entered again',
          _ => 'its screen then left',
        };
        final n = await NewDeviceLink.create();
        final code = n.code;
        final pairing = PairingCode.parse(code);
        final mailbox =
            await (await RelayPairing.relayIdentityV3(pairing, 'r')).routingId();
        RelayClient? other;
        final leave = PairingCancel();
        Future<Object?>? again;
        final hosted = alice.svc
            .hostDeviceLink(code, cancel: leave, confirmSas: (_) async {
              // While the phone's person compares, the other login comes in,
              // and the relay closes the phone's mailbox for it.
              other = await RelayClient.connect(
                  relayUrl(), await RelayPairing.relayIdentityV3(pairing, 'r'));
              await waitUntil(() => rec.left.contains(mailbox),
                  what: "$what: the phone's mailbox closed for the other "
                      'login');
              switch (how) {
                case 'differ':
                  return false;
                case 'again':
                  again = alice.svc
                      .hostDeviceLink(code, confirmSas: (_) async => true)
                      .then<Object?>((r) => r, onError: (Object e) => e);
                default:
                  leave.cancel();
              }
              // The person is still comparing when the attempt is stopped.
              return Completer<bool>().future;
            })
            .then<Object?>((r) => r, onError: (Object e) => e);
        final waited = Stopwatch();
        final laptop = await n
            .run(
              relayUrl: relayUrl(),
              confirm: (_) async {
                waited.start();
                return true;
              },
              timeout: timeout,
              margin: margin,
            )
            .then<Object?>((r) => r, onError: (Object e) => e);
        waited.stop();
        try {
          final phone = await hosted;
          expect(phoneScreen(phone), phoneTakenOver,
              reason: '$what: the phone says another connection took over');
          expect(hostLinkFailureText(es, phone!), phoneTakenOverEs);
          expect(laptopScreen(laptop), laptopTakenOver,
              reason: '$what: the laptop, closed the same way, says so too');
          expect(newDeviceLinkFailureText(es, laptop!), laptopTakenOverEs);
          expect(waited.elapsed, lessThan(timeout),
              reason: '$what: at once, and not when its wait for the '
                  'enrolment ran out');
          expect(n.code, isNot(code), reason: '$what: and it shows a new code');
          final spent = await alice.vault.kvGet('link_spent_codes');
          expect(spent, contains(await pairing.rendezvousRoutingIdV3()),
              reason: '$what: the phone keeps the code as spent');
          if (again != null) {
            expect(phoneScreen(await again), codeSpent,
                reason: '$what: the call that came again will not use it');
          }
          expect(await alice.svc.linkedDevices(), isEmpty);
        } finally {
          await other?.close();
        }
      }
    } finally {
      await rec.close();
    }
  });

  test(
      '25. a code entered again once the link it stopped had answered the '
      'laptop says at once that the laptop needs a new code', () async {
    final alice = await person('Alice25');
    await connected([alice]);
    const timeout = Duration(seconds: 4), margin = Duration(seconds: 1);
    alice.svc.linkTimeout = timeout;
    alice.svc.linkMargin = margin;
    final n = await NewDeviceLink.create();
    final code = n.code;
    final comparing = Completer<void>();
    // The phone has answered the laptop: its person is comparing the digits
    // when they go back and enter the code again.
    final first = alice.svc
        .hostDeviceLink(code, confirmSas: (_) {
          comparing.complete();
          return Completer<bool>().future;
        })
        .then<Object?>((r) => r, onError: (Object e) => e);
    final laptop = n
        .run(
          relayUrl: relayUrl(),
          confirm: (_) async => true,
          timeout: timeout,
          margin: margin,
        )
        .then<Object?>((r) => r, onError: (Object e) => e);
    await comparing.future;
    final waited = Stopwatch()..start();
    final again = await alice.svc
        .hostDeviceLink(code, confirmSas: (_) async => true)
        .then<Object?>((r) => r, onError: (Object e) => e);
    waited.stop();
    expect(phoneScreen(await first), en.linkCancelled,
        reason: 'the link entered again stopped the first');
    expect([phoneScreen(again), hostLinkFailureText(es, again!)],
        [codeAnswered, codeAnsweredEs],
        reason: 'the laptop holds the first answer and takes no other');
    expect(waited.elapsed, lessThan(timeout),
        reason: 'at once, and not when a wait for a commitment ran out');
    final l = await laptop;
    expect([laptopScreen(l), newDeviceLinkFailureText(es, l!)],
        [laptopNoEnrolment, laptopNoEnrolmentEs],
        reason: "the laptop names its other device's leaving the link screen "
            'among its reasons');
    expect(n.code, isNot(code), reason: 'and shows a new code');
    expect(await alice.svc.linkedDevices(), isEmpty);
    expect(await alice.vault.kvGet('link_spent_codes'), isNull,
        reason: 'nobody else had the code');
  });

  testWidgets(
      "26. leaving the new device's link screen stops the attempt it "
      'started, at once, and nothing of it reaches the screen once it has '
      'gone', (t) async {
    late Recorder rec;
    late Vault vault;
    await t.runAsync(() async {
      rec = await Recorder.start(relayUrl());
      vault = await Vault.open(rootOverride: await tempDir('laptop26'));
    });
    var movedOn = 0;
    await t.pumpWidget(MaterialApp(
      theme: ZTheme.light(),
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      supportedLocales: AppLocalizations.supportedLocales,
      home: Builder(
        builder: (context) => Scaffold(
          body: TextButton(
            key: const ValueKey('open'),
            onPressed: () => Navigator.of(context).push(MaterialPageRoute<void>(
                builder: (_) => NewDeviceLinkScreen(
                    vault: vault, onDone: () async => movedOn++))),
            child: const Text('open'),
          ),
        ),
      ),
    ));
    await t.tap(find.byKey(const ValueKey('open')));
    await drive(t, () => find.byType(SelectableText).evaluate().isNotEmpty,
        what: 'the code the new device shows');
    // The relay is the test's, through the front: the developer field.
    await t.tap(find.text(en.devOptions));
    await t.pump();
    await t.enterText(find.byType(TextField), rec.url);
    final code = t.widget<SelectableText>(find.byType(SelectableText)).data!;
    late String mailbox;
    await t.runAsync(() async {
      mailbox = await (await RelayPairing.relayIdentityV3(
              PairingCode.parse(code), 'i'))
          .routingId();
    });
    await t.tap(find.text(en.linkStart));
    await drive(t, () => rec.welcomed.contains(mailbox),
        what: "the screen's attempt logged in as the new device's mailbox");
    // The person goes back.
    await t.pageBack();
    await t.pump();
    await t.pump(const Duration(milliseconds: 500));
    expect(find.byType(NewDeviceLinkScreen), findsNothing);
    await drive(t, () => rec.left.contains(mailbox),
        within: const Duration(seconds: 10),
        what: 'the attempt the screen started stopped once the screen was '
            'left, its mailbox closed');
    // A negative check over a window: for a second of both clocks after
    // the attempt closed, nothing of it reaches the screen it left — a
    // state set once it is gone fails the test — nor moves the app on.
    final until = DateTime.now().add(const Duration(seconds: 1));
    while (DateTime.now().isBefore(until)) {
      await t.runAsync(
          () => Future<void>.delayed(const Duration(milliseconds: 50)));
      await t.pump(const Duration(milliseconds: 100));
    }
    expect(movedOn, 0, reason: 'the app was not moved on');
    await t.runAsync(() async {
      expect(await vault.kvGet('identity'), isNull,
          reason: 'and nothing was installed');
    });
    await t.pumpWidget(const SizedBox());
    await t.runAsync(() async {
      await vault.db.close();
      await rec.close();
    });
  });

  test(
      '27. a code entered again once the link it stopped had answered the '
      'laptop, and that attempt is over, says at once that the laptop needs '
      'a new code', () async {
    // The phone reaches the relay through a front that notes each login.
    final rec = await Recorder.start(relayUrl());
    addTearDown(rec.close);
    final alice = await person('Alice27', url: rec.url);
    await connected([alice]);
    const timeout = Duration(seconds: 4), margin = Duration(seconds: 1);
    alice.svc.linkTimeout = timeout;
    alice.svc.linkMargin = margin;
    final n = await NewDeviceLink.create();
    final code = n.code;
    final comparing = Completer<void>();
    final leave = PairingCancel();
    // The phone has answered the laptop, and its person leaves the link
    // screen while the digits are up.
    final first = alice.svc
        .hostDeviceLink(code,
            confirmSas: (_) {
              comparing.complete();
              return Completer<bool>().future;
            },
            cancel: leave)
        .then<Object?>((r) => r, onError: (Object e) => e);
    final laptop = n
        .run(
          relayUrl: relayUrl(),
          confirm: (_) async => true,
          timeout: timeout,
          margin: margin,
        )
        .then<Object?>((r) => r, onError: (Object e) => e);
    await comparing.future;
    leave.cancel();
    expect(phoneScreen(await first), en.linkCancelled,
        reason: 'leaving the link screen stopped it');
    // That attempt is over when the person comes back and enters the code.
    final waited = Stopwatch()..start();
    final again = await alice.svc
        .hostDeviceLink(code, confirmSas: (_) async => true)
        .then<Object?>((r) => r, onError: (Object e) => e);
    waited.stop();
    expect([phoneScreen(again), hostLinkFailureText(es, again!)],
        [codeAnswered, codeAnsweredEs],
        reason: 'the laptop holds the first answer and takes no other');
    expect(waited.elapsed, lessThan(timeout),
        reason: 'at once, and not when a wait for a commitment ran out');
    // Kept by the code's rendezvous id, never the code.
    final mark = await PairingCode.parse(code).rendezvousRoutingIdV3();
    final kept = await alice.vault.kvGet('link_answered_codes');
    expect(jsonDecode(kept!), [mark]);
    expect(kept, isNot(contains(code)));
    expect(await alice.vault.kvGet('link_spent_codes'), isNull,
        reason: 'nobody else had the code');
    // And once the phone has restarted.
    alice.svc.dispose();
    await alice.svc.transport.stop();
    live.remove(alice);
    final restarted =
        await boot(alice.dir, 'Alice27', vault: alice.vault, url: rec.url);
    restarted.svc.linkTimeout = timeout;
    restarted.svc.linkMargin = margin;
    final waitedAfter = Stopwatch()..start();
    final later = await restarted.svc
        .hostDeviceLink(code, confirmSas: (_) async => true)
        .then<Object?>((r) => r, onError: (Object e) => e);
    waitedAfter.stop();
    expect(phoneScreen(later), codeAnswered, reason: 'once restarted too');
    expect(waitedAfter.elapsed, lessThan(timeout), reason: 'at once');
    final l = await laptop;
    expect([laptopScreen(l), newDeviceLinkFailureText(es, l!)],
        [laptopNoEnrolment, laptopNoEnrolmentEs],
        reason: 'the laptop, sent nothing, says why');
    expect(n.code, isNot(code), reason: 'and shows a new code');
    expect(await restarted.svc.linkedDevices(), isEmpty);
    // Neither attempt answered at once logged in as the code's mailbox: a
    // login someone else made there after the first stopped would stay.
    final box = await (await RelayPairing.relayIdentityV3(
            PairingCode.parse(code), 'r'))
        .routingId();
    expect(rec.welcomed.where((id) => id == box), hasLength(1),
        reason: 'the first attempt alone logged in as the phone\'s mailbox');
  });

  test(
      '28. a code entered again once the link it answered ended without a '
      'stop says at once that the laptop needs a new code', () async {
    // The phone reaches the relay through a front this test steers: it
    // keeps the laptop's opening from the phone, or closes the phone's
    // connection as the opening comes.
    var mode = '';
    final rec = await Recorder.start(relayUrl(),
        hand: (frame) =>
            mode == 'no opening' && Recorder.kindOf(frame) == 'open-v3'
                ? const <String>[]
                : [frame],
        cut: (frame) =>
            mode == 'dropped' && Recorder.kindOf(frame) == 'open-v3');
    addTearDown(rec.close);
    final alice = await person('Alice28', url: rec.url);
    await connected([alice]);
    const timeout = Duration(seconds: 4), margin = Duration(seconds: 1);
    alice.svc.linkTimeout = timeout;
    alice.svc.linkMargin = margin;
    final kept = <String>[];
    final laptops = <Future<Object?>>[];
    for (final (what, how, first) in <(String, String, Matcher)>[
      ('its person says the digits differ', 'differ', isFalse),
      ("its wait for the laptop's opening runs out", 'no opening',
          isA<TimeoutException>()),
      ('its connection drops once the relay has its reply', 'dropped',
          isA<RelayException>()),
    ]) {
      final n = await NewDeviceLink.create();
      final code = n.code;
      laptops.add(n
          .run(
            relayUrl: relayUrl(),
            confirm: (_) async => true,
            timeout: timeout,
            margin: margin,
          )
          .then<Object?>((r) => r, onError: (Object e) => e));
      mode = how;
      final ended = await alice.svc
          .hostDeviceLink(code, confirmSas: (_) async => how != 'differ')
          .then<Object?>((r) => r, onError: (Object e) => e);
      mode = '';
      expect(ended, first, reason: '$what: how the link ended');
      final waited = Stopwatch()..start();
      final again = await alice.svc
          .hostDeviceLink(code, confirmSas: (_) async => true)
          .then<Object?>((r) => r, onError: (Object e) => e);
      waited.stop();
      expect([phoneScreen(again), hostLinkFailureText(es, again!)],
          [codeAnswered, codeAnsweredEs],
          reason: '$what: the laptop holds that answer and takes no other');
      expect(waited.elapsed, lessThan(timeout),
          reason: '$what: at once, and not when a wait ran out');
      kept.add(await PairingCode.parse(code).rendezvousRoutingIdV3());
      final stored = await alice.vault.kvGet('link_answered_codes');
      expect(jsonDecode(stored!), kept,
          reason: '$what: kept by its rendezvous id');
      expect(stored, isNot(contains(code)));
    }
    for (final l in await Future.wait(laptops)) {
      expect(l, isNot(isA<PairingResult>()), reason: 'nothing installed');
    }
    expect(await alice.svc.linkedDevices(), isEmpty);
    expect(await alice.vault.kvGet('link_spent_codes'), isNull,
        reason: 'nobody else had a code');
  });

  test(
      '29. a code whose reply never reached the relay is not kept, and '
      'entered again links the laptop', () async {
    // The phone's connection closes as it acknowledges the laptop's
    // commitment: neither that acknowledgement nor the reply written after
    // it reaches the relay, which keeps the commitment for the next login.
    String? commitment;
    var cut = false;
    final rec = await Recorder.start(relayUrl(), hand: (frame) {
      if (Recorder.kindOf(frame) == 'commit-v3') {
        commitment = (jsonDecode(frame) as Map)['id'] as String?;
      }
      return [frame];
    }, cutUp: (frame) {
      if (cut || commitment == null) return false;
      final f = jsonDecode(frame);
      return cut = f is Map && f['t'] == 'recv' && f['id'] == commitment;
    });
    addTearDown(rec.close);
    final alice = await person('Alice29', url: rec.url);
    await connected([alice]);
    const timeout = Duration(seconds: 6), margin = Duration(seconds: 1);
    alice.svc.linkTimeout = timeout;
    alice.svc.linkMargin = margin;
    final n = await NewDeviceLink.create();
    final code = n.code;
    final dir = await tempDir('laptop29');
    final vault = await Vault.open(rootOverride: dir);
    final laptop = n
        .run(
          relayUrl: relayUrl(),
          confirm: (_) async => true,
          timeout: timeout,
          margin: margin,
          install: (r) async {
            await setRelayUrl(vault, relayUrl(), acceptedInsecure: true);
            await installEnrollment(vault, r, sealingKey: n.sealingKey);
          },
        )
        .then<Object?>((r) => r, onError: (Object e) => e);
    final first = await alice.svc
        .hostDeviceLink(code, confirmSas: (_) async => true)
        .then<Object?>((r) => r, onError: (Object e) => e);
    expect(cut, isTrue,
        reason: 'the connection closed as the phone acknowledged the '
            'commitment');
    expect(first, isA<RelayException>(), reason: 'its connection dropped');
    expect(await alice.vault.kvGet('link_answered_codes'), isNull,
        reason: 'not kept: the relay never took the reply');
    final again = await alice.svc
        .hostDeviceLink(code, confirmSas: (_) async => true)
        .then<Object?>((r) => r, onError: (Object e) => e);
    expect(again, isTrue,
        reason: 'the next attempt finds the commitment, answers it and links');
    expect(await laptop, isA<PairingResult>());
    expect(await alice.svc.linkedDevices(), hasLength(1));
    await vault.db.close();
  });

  test(
      '30. a code that linked the laptop, entered again, says at once that it '
      'has already linked a device', () async {
    // The phone reaches the relay through a front that notes each login.
    final rec = await Recorder.start(relayUrl());
    addTearDown(rec.close);
    final alice = await person('Alice30', url: rec.url);
    await connected([alice]);
    const timeout = Duration(seconds: 4), margin = Duration(seconds: 1);
    alice.svc.linkTimeout = timeout;
    alice.svc.linkMargin = margin;
    final n = await NewDeviceLink.create();
    final code = n.code;
    final dir = await tempDir('laptop30');
    final vault = await Vault.open(rootOverride: dir);
    final laptop = n
        .run(
          relayUrl: relayUrl(),
          confirm: (_) async => true,
          timeout: timeout,
          margin: margin,
          install: (r) async {
            await setRelayUrl(vault, relayUrl(), acceptedInsecure: true);
            await installEnrollment(vault, r, sealingKey: n.sealingKey);
          },
        )
        .then<Object?>((r) => r, onError: (Object e) => e);
    final linked = await alice.svc
        .hostDeviceLink(code, confirmSas: (_) async => true)
        .then<Object?>((r) => r, onError: (Object e) => e);
    expect(linked, isTrue, reason: 'the code linked the laptop');
    expect(await laptop, isA<PairingResult>());
    // The person enters the same code again.
    final waited = Stopwatch()..start();
    final again = await alice.svc
        .hostDeviceLink(code, confirmSas: (_) async => true)
        .then<Object?>((r) => r, onError: (Object e) => e);
    waited.stop();
    expect([phoneScreen(again), hostLinkFailureText(es, again!)],
        [codeLinked, codeLinkedEs],
        reason: 'it has already linked a device, and says how to link another');
    expect(waited.elapsed, lessThan(timeout),
        reason: 'at once, and not when a wait for a commitment ran out');
    // Kept by the code's rendezvous id, never the code, under its own key.
    final mark = await PairingCode.parse(code).rendezvousRoutingIdV3();
    final kept = await alice.vault.kvGet('link_linked_codes');
    expect(jsonDecode(kept!), [mark]);
    expect(kept, isNot(contains(code)));
    expect(await alice.vault.kvGet('link_answered_codes'), isNull,
        reason: 'the code finished its link');
    expect(await alice.vault.kvGet('link_spent_codes'), isNull,
        reason: 'nobody else had the code');
    // And once the phone has restarted.
    alice.svc.dispose();
    await alice.svc.transport.stop();
    live.remove(alice);
    final restarted =
        await boot(alice.dir, 'Alice30', vault: alice.vault, url: rec.url);
    restarted.svc.linkTimeout = timeout;
    restarted.svc.linkMargin = margin;
    final waitedAfter = Stopwatch()..start();
    final later = await restarted.svc
        .hostDeviceLink(code, confirmSas: (_) async => true)
        .then<Object?>((r) => r, onError: (Object e) => e);
    waitedAfter.stop();
    expect(phoneScreen(later), codeLinked, reason: 'once restarted too');
    expect(waitedAfter.elapsed, lessThan(timeout), reason: 'at once');
    expect(await restarted.svc.linkedDevices(), hasLength(1),
        reason: 'the laptop it linked is listed, and nothing more');
    // Neither call that came again logged in as the code's mailbox.
    final box = await (await RelayPairing.relayIdentityV3(
            PairingCode.parse(code), 'r'))
        .routingId();
    expect(rec.welcomed.where((id) => id == box), hasLength(1),
        reason: 'the attempt that linked alone logged in as the mailbox');
    await vault.db.close();
  });

  test(
      '31. a link stopped while the phone opens its connection to the code\'s '
      'mailbox ends at once, keeps nothing, and the code entered again links',
      () async {
    // The relay's challenge to the phone's login as the code's mailbox — the
    // first connection after Alice's own — is held for good, as on a
    // connection that stalls while it opens: the phone has nothing to
    // answer. Until 2026-11-01 the stop was seen only once the opening had
    // run to its end, up to fifteen seconds for the welcome.
    String? box;
    int? link;
    var challenged = false;
    final rec = await Recorder.start(relayUrl(), holdDown: (frame, at) {
      if (at != link) return null;
      try {
        final f = jsonDecode(frame);
        if (f is Map && f['t'] == 'challenge') {
          challenged = true;
          return Completer<void>().future;
        }
      } catch (_) {}
      return null;
    });
    addTearDown(rec.close);
    final alice = await person('Alice31', url: rec.url);
    await connected([alice]);
    const timeout = Duration(seconds: 6), margin = Duration(seconds: 1);
    alice.svc.linkTimeout = timeout;
    alice.svc.linkMargin = margin;
    final n = await NewDeviceLink.create();
    final code = n.code;
    box = await (await RelayPairing.relayIdentityV3(
            PairingCode.parse(code), 'r'))
        .routingId();
    final dir = await tempDir('laptop31');
    final vault = await Vault.open(rootOverride: dir);
    final laptop = n
        .run(
          relayUrl: relayUrl(),
          confirm: (_) async => true,
          timeout: timeout,
          margin: margin,
          install: (r) async {
            await setRelayUrl(vault, relayUrl(), acceptedInsecure: true);
            await installEnrollment(vault, r, sealingKey: n.sealingKey);
          },
        )
        .then<Object?>((r) => r, onError: (Object e) => e);
    final stop = PairingCancel();
    link = rec.connections;
    final first = alice.svc
        .hostDeviceLink(code, confirmSas: (_) async => true, cancel: stop)
        .then<Object?>((r) => r, onError: (Object e) => e);
    await waitUntil(() => challenged,
        what: "the relay's challenge to the phone's login as the code's "
            'mailbox');
    final since = Stopwatch()..start();
    stop.cancel();
    // A deadline, not a sleep.
    final out = await first.timeout(const Duration(seconds: 2),
        onTimeout: () => 'still running ${since.elapsed} after the stop');
    final took = since.elapsed;
    // ignore: avoid_print
    print('a link stopped while its connection opened: '
        '${out is PairingCancelled ? 'ended ${took.inMilliseconds} ms after '
            'the stop' : '$out'}');
    expect(out, isA<PairingCancelled>(), reason: 'the link stops');
    expect(took, lessThan(const Duration(milliseconds: 500)),
        reason: 'at once');
    await waitUntil(() => rec.closed.contains(link),
        what: 'that connection closed by the phone',
        timeout: const Duration(seconds: 2));
    expect(rec.welcomed, isNot(contains(box)),
        reason: 'never logged in as the code\'s mailbox');
    for (final key in [
      'link_answered_codes',
      'link_spent_codes',
      'link_linked_codes'
    ]) {
      expect(await alice.vault.kvGet(key), isNull,
          reason: 'nothing kept under $key');
    }
    // The person enters the same code again: the laptop's commitment was
    // left for it, unacknowledged.
    final again = await alice.svc
        .hostDeviceLink(code, confirmSas: (_) async => true)
        .then<Object?>((r) => r, onError: (Object e) => e);
    expect(again, isTrue, reason: 'the code entered again links');
    expect(await laptop, isA<PairingResult>());
    expect(await alice.svc.linkedDevices(), hasLength(1));
    await vault.db.close();
  });

  test(
      '32. a link stopped once the phone has answered the relay\'s challenge '
      'waits for the relay to welcome it, and the code entered again links '
      'with no takeover said and nothing spent', () async {
    // The phone's answer to the relay's challenge for its login as the
    // code's mailbox has gone up when the link is stopped, and reaches the
    // relay 1.5 s later — held on its way, and passed on even once the
    // phone has left, as TCP would. The code is entered again at once, and
    // that attempt's reply is held 3 s on its way up. Ending at once, as it
    // did from 2026-11-01 to 2026-11-02, the stopped link's late answer
    // logged it in after the code's next attempt had, and the relay closed
    // that attempt's connection for it: a takeover said on both devices,
    // the code spent. 4.9.1, which ran the opening to its end, linked.
    var holding = true;
    String? pub;
    var answered = false;
    final rec = await Recorder.start(relayUrl(), passOnAfterLeaving: true,
        holdUp: (frame) {
      try {
        final f = jsonDecode(frame);
        if (holding && f is Map && f['t'] == 'auth' && f['pub'] == pub) {
          answered = true;
          return Future<void>.delayed(const Duration(milliseconds: 1500));
        }
      } catch (_) {}
      if (Recorder.sendOf(frame, 'z-pair-reply')) {
        return Future<void>.delayed(const Duration(seconds: 3));
      }
      return null;
    });
    addTearDown(rec.close);
    final alice = await person('Alice32', url: rec.url);
    await connected([alice]);
    const timeout = Duration(seconds: 15), margin = Duration(seconds: 2);
    alice.svc.linkTimeout = timeout;
    alice.svc.linkMargin = margin;
    final n = await NewDeviceLink.create();
    final code = n.code;
    final mailbox =
        await RelayPairing.relayIdentityV3(PairingCode.parse(code), 'r');
    pub = b64(mailbox.edPub);
    final box = await mailbox.routingId();
    final dir = await tempDir('laptop32');
    final vault = await Vault.open(rootOverride: dir);
    final laptop = n
        .run(
          relayUrl: relayUrl(),
          confirm: (_) async => true,
          timeout: timeout,
          margin: margin,
          install: (r) async {
            await setRelayUrl(vault, relayUrl(), acceptedInsecure: true);
            await installEnrollment(vault, r, sealingKey: n.sealingKey);
          },
        )
        .then<Object?>((r) => r, onError: (Object e) => e);
    final stop = PairingCancel();
    final since = Stopwatch();
    int? firstEnded, welcomedThen;
    final first = alice.svc
        .hostDeviceLink(code, confirmSas: (_) async => true, cancel: stop)
        .then<Object?>((r) => r, onError: (Object e) => e)
        .then((r) {
      firstEnded = since.elapsedMilliseconds;
      welcomedThen = rec.welcomed.where((id) => id == box).length;
      holding = false;
      return r;
    });
    await waitUntil(() => answered,
        what: "the phone's answer to the relay's challenge going up");
    since.start();
    stop.cancel();
    final again = await alice.svc
        .hostDeviceLink(code, confirmSas: (_) async => true)
        .then<Object?>((r) => r, onError: (Object e) => e);
    final out = await first;
    final lap = await laptop;
    // ignore: avoid_print
    print('a link stopped once it had answered: ended $firstEnded ms after '
        "the stop, the code's mailbox welcomed $welcomedThen time(s) by "
        'then; the code entered again: '
        '${again is bool ? 'linked=$again' : phoneScreen(again)}, '
        '${since.elapsedMilliseconds} ms after the stop; the laptop: '
        '${lap is PairingResult ? 'linked' : laptopScreen(lap)}');
    expect(out, isA<PairingCancelled>(), reason: 'the stopped link stops');
    expect(again, isTrue,
        reason: 'the code entered again links, and is not taken over');
    expect(lap, isA<PairingResult>(),
        reason: 'the laptop links, and says no takeover');
    expect(await alice.vault.kvGet('link_spent_codes'), isNull,
        reason: 'nothing spent');
    expect(await alice.svc.linkedDevices(), hasLength(1));
    expect(welcomedThen, 1,
        reason: 'the stopped link ended once the relay had welcomed its '
            'late login, and not before');
    expect(firstEnded, lessThan(3000),
        reason: 'as the welcome came, not at the end of its time for it');
    // The stopped link's late login, and the next attempt's.
    expect(rec.welcomed.where((id) => id == box), hasLength(2));
    await vault.db.close();
  });
}
