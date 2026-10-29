// §18.9's last paragraph: what happens when the post-quantum signature does
// not arrive.
//
// A device-list signature travels as its own ~16 KB envelope on a delayed
// schedule, which makes it the single easiest thing on the wire for a relay to
// drop: it is the only envelope of that size an ordinary conversation
// produces. Dropping it leaves the list CLASSICALLY verified — everything
// keeps working, nothing fails, and the account quietly never gets the
// protection phase 13 was built for.
//
// It cannot be prevented at the network layer. It can be noticed, and the hard
// part is noticing it without crying wolf: a contact running an older v3 build
// has a post-quantum identity and simply never signs its lists, and treating
// that as an attack would train people to ignore the warning. So the sender
// says, inside the ratchet where it cannot be stripped, that it has SENT the
// signature — and only a claim with no signature behind it is a problem.
@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart' show DatabaseException;
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/system_messages.dart';
import 'package:zapp/core/models.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/alert_text.dart';
import 'package:zapp/l10n/app_localizations_en.dart';
import 'package:z_protocol/z_protocol.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  late Process relay;
  late int port;
  final temps = <Directory>[];
  final services = <ChatService>[];

  setUpAll(() async {
    HttpOverrides.global = null;
    final serverDir =
        '${Directory.current.parent.path}${Platform.pathSeparator}server';
    // An OS-assigned free port, as group_test.dart does: the clock formula
    // this replaced gave two suites starting in the same millisecond the
    // same port, and `flutter test` runs files concurrently.
    final portProbe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    port = portProbe.port;
    await portProbe.close();
    relay = await Process.start('node', ['server.js'],
        workingDirectory: serverDir,
        environment: {'PORT': '$port', 'LOG_LEVEL': 'silent'});
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

  // Each service runs in an error zone of its own. A service [restart] has
  // stopped can still have work in flight, which then fails against the
  // database [restart] closed under it; that error, from a stopped service,
  // is the one expected here and is dropped. Anything else raised inside a
  // service is kept, and fails the test that was running.
  final stopped = <ChatService>{};
  final strays = <String>[];
  tearDown(() {
    final found = [...strays];
    strays.clear();
    expect(found, isEmpty, reason: 'errors raised inside a running service');
  });

  /// [name]'s service, over the vault at [at] when given — its identity the
  /// one stored there — and in a new one otherwise, started in an error zone
  /// of its own.
  Future<ChatService> start(String name, {Directory? at}) async {
    final dir = at ?? await Directory.systemTemp.createTemp('z_sup_$name');
    if (at == null) temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final stored = await vault.kvGet('identity');
    final id = stored == null
        ? await ZIdentity.generate()
        : await ZIdentity.fromJson(
            (jsonDecode(stored) as Map).cast<String, Object?>());
    if (stored == null) {
      await vault.kvPut('identity', jsonEncode(id.toJson()));
    }
    final ready = Completer<ChatService>();
    ChatService? made;
    runZonedGuarded(() async {
      try {
        final svc = await ChatService.init(
            vault: vault,
            identity: id,
            displayName: name,
            transport:
                Transport(identity: id, serverUrl: 'ws://127.0.0.1:$port'));
        made = svc;
        svc.pqListDelay = const Duration(milliseconds: 150);
        svc.devlistGrace = const Duration(seconds: 3);
        services.add(svc);
        ready.complete(svc);
      } catch (e, st) {
        ready.completeError(e, st);
      }
    }, (e, st) {
      final svc = made;
      if (svc != null &&
          stopped.contains(svc) &&
          e is DatabaseException &&
          e.isDatabaseClosedError()) {
        return;
      }
      strays.add('$name: $e\n$st');
    });
    return ready.future;
  }

  /// [s] stopped and started again over its own vault, as the app restarts.
  Future<ChatService> restart(ChatService s) async {
    final dir = s.vault.root;
    final name = s.displayName;
    stopped.add(s);
    s.dispose();
    await s.transport.stop();
    services.remove(s);
    await s.vault.db.close();
    return start(name, at: dir);
  }

  Future<void> waitUntil(bool Function() cond,
      {Duration timeout = const Duration(seconds: 25),
      String what = ''}) async {
    final deadline = DateTime.now().add(timeout);
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 30));
    }
  }

  /// Two accounts talking, the second with a linked device so it has a list
  /// worth signing.
  Future<(ChatService, ChatService)> pairWithDevice(String a, String b,
      {PqListSuppression mode = PqListSuppression.none}) async {
    final x = await start(a);
    final y = await start(b);
    // Set BEFORE the list exists: delivery follows signing by 150 ms here, so
    // switching it afterwards would race the thing being modelled.
    y.debugSuppressPqList = mode;
    await waitUntil(() => x.transport.isConnected && y.transport.isConnected,
        what: 'connected');
    await x.addContactFromCode(await y.myContactCode());
    await y.addContactFromCode(await x.myContactCode());
    await x.sendText(y.myRid, 'hi');
    await y.sendText(x.myRid, 'hi back');
    final acct = await y.accountIdentity();
    final laptop = await ZIdentity.generate();
    await y.addMyDevice(await acct.signDeviceCert(
        deviceEdPub: laptop.edPub,
        deviceXPub: laptop.xPub,
        deviceId: 'laptop'));
    return (x, y);
  }

  test('the honest case raises nothing', () async {
    final (alice, ben) = await pairWithDevice('h1', 'h2');
    await waitUntil(
        () => alice.deviceAssuranceWith(ben.myRid) == DeviceAssurance.hybrid,
        what: 'settles');
    await Future<void>.delayed(alice.devlistGrace * 2);
    await ben.sendText(alice.myRid, 'still here');
    await Future<void>.delayed(const Duration(seconds: 1));
    expect(alice.pqListAlerts[ben.myRid], isNull);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('a contact whose client never signs its lists is NOT accused', () async {
    // The cry-wolf case, and the reason the claim exists. An older v3 build
    // has a post-quantum identity — it emits `pqid`, so its contacts reach
    // `hybrid` — and simply never signs its device lists. Nothing has been
    // suppressed and nobody is under attack; treating this as an alarm would
    // teach people that the alarm means nothing.
    final (alice, ben) =
        await pairWithDevice('o1', 'o2', mode: PqListSuppression.silent);
    // Keep talking well past the grace period: an alarm that needed silence
    // to stay quiet would not be worth much.
    for (var i = 0; i < 8; i++) {
      await ben.sendText(alice.myRid, 'hello from an older build $i');
      await Future<void>.delayed(const Duration(milliseconds: 600));
    }

    expect(alice.deviceAssuranceWith(ben.myRid), DeviceAssurance.classical,
        reason: 'honestly reported as classical…');
    expect(alice.pqListAlerts[ben.myRid], isNull,
        reason: '…but not as an attack');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('a signature dropped in flight is asked for again, not alarmed about',
      () async {
    // Most losses are innocent: a connection dropped mid-send, an outbox that
    // did not flush. Alarming on the first miss would make the alarm noise, so
    // the claim triggers a request first.
    final (alice, ben) =
        await pairWithDevice('d1', 'd2', mode: PqListSuppression.claimOnly);
    unawaited(() async {
      for (var i = 0; i < 40; i++) {
        try {
          await ben.sendText(alice.myRid, 'ping $i');
        } catch (_) {}
        await Future<void>.delayed(const Duration(milliseconds: 400));
      }
    }());
    await waitUntil(() => alice.pqListRequestsSent(ben.myRid) > 0,
        what: 'alice asks for the signature she was told about');
    // Delivery resumes, as it would when the connection recovers.
    ben.debugSuppressPqList = PqListSuppression.none;
    await waitUntil(
        () => alice.deviceAssuranceWith(ben.myRid) == DeviceAssurance.hybrid,
        what: 'the repair works');
    expect(alice.pqListAlerts[ben.myRid], isNull,
        reason: 'a loss that repairs itself is not an attack');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('a signature suppressed persistently is surfaced', () async {
    // The attack §18.9 names. Ben's client says, inside the ratchet where it
    // cannot be stripped, that it has sent the signature; Alice never receives
    // one, and asking does not help. Something between them is removing the
    // one envelope that carries post-quantum protection, and Alice is told —
    // because a list that stays classical for ever is exactly what an attacker
    // wants and exactly what looks like nothing at all.
    final (alice, ben) =
        await pairWithDevice('s1', 's2', mode: PqListSuppression.claimOnly);
    unawaited(() async {
      for (var i = 0; i < 60; i++) {
        try {
          await ben.sendText(alice.myRid, 'ping $i');
        } catch (_) {}
        await Future<void>.delayed(const Duration(milliseconds: 500));
      }
    }());
    await waitUntil(() => alice.pqListAlerts[ben.myRid] != null,
        timeout: const Duration(seconds: 40),
        what: 'alice is told the signature never arrives');
    // A kind, not a sentence: the name is not what is stored (the screen
    // supplies it), and the words are chosen in the reader's language when
    // the banner is drawn.
    expect(alice.pqListAlerts[ben.myRid],
        devlistAlertBody(DevlistAlertKind.pqSignatureMissing));
    expect(
        devlistAlertText(AppLocalizationsEn(),
            alice.pqListAlerts[ben.myRid]!, 'Ben'),
        allOf(contains('post-quantum'), contains('Ben')));
    expect(alice.deviceAssuranceWith(ben.myRid), DeviceAssurance.classical,
        reason: 'and nothing was accepted on the strength of the claim');

    // And it outlives a restart. Ben's list is held here — the claim is
    // judged over it — so the start that drops a banner raised over no list
    // (4.7.1) keeps this one, and the row it stands in.
    expect(await alice.vault.kvGet('cdev_${ben.myRid}'), isNotNull,
        reason: "the premise: Ben's list is held here");
    final alice2 = await restart(alice);
    expect(alice2.pqListAlerts[ben.myRid],
        devlistAlertBody(DevlistAlertKind.pqSignatureMissing),
        reason: 'shown again after the restart');
    expect(await alice2.vault.kvGet('pql_alert_${ben.myRid}'),
        devlistAlertBody(DevlistAlertKind.pqSignatureMissing),
        reason: 'and still kept');
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('a contact deleted and added back in the same run comes back without '
      'the banner the deleted one had', () async {
    // Raised as above. Then Alice deletes Ben and adds him back from his
    // code without restarting: the row the banner stood in went with him
    // (`pql_alert_`), and until 2026-10-29 the banner itself stayed in
    // memory and came back with him.
    final (alice, ben) =
        await pairWithDevice('s7', 's8', mode: PqListSuppression.claimOnly);
    var pinging = true;
    final pings = () async {
      for (var i = 0; pinging && i < 60; i++) {
        try {
          await ben.sendText(alice.myRid, 'ping $i');
        } catch (_) {}
        await Future<void>.delayed(const Duration(milliseconds: 500));
      }
    }();
    addTearDown(() => pinging = false);
    await waitUntil(() => alice.pqListAlerts[ben.myRid] != null,
        timeout: const Duration(seconds: 40),
        what: 'alice is told the signature never arrives');
    pinging = false;
    await pings;

    await alice.deleteContact(ben.myRid);
    expect(await alice.vault.kvGet('pql_alert_${ben.myRid}'), isNull);
    await alice.addContactFromCode(await ben.myContactCode());
    expect(alice.pqListAlerts[ben.myRid], isNull,
        reason: 'a contact added back starts from nothing');
  }, timeout: const Timeout(Duration(minutes: 3)));

  // 4.7.1: the claim judged where there is a list to judge it over. An
  // account still at list version 1 — as a new one that has never linked a
  // device is — never sends its list: a contact computes that baseline from the code,
  // and a list goes out only at a later version. Its signature arrives with
  // nothing to verify it over, and every build before this one then failed
  // the claim for good — three requests a run, each answered with a
  // 16 384-bucket `dlpq`, and the banner, on every such contact. The
  // rehearsal of 2026-10-28 found it in vaults from v3.10.1, v4.3.2 and
  // v4.6.0 alike.
  test('a contact still at list version 1, its signature arrived, is neither '
      'asked nor accused', () async {
    final x = await start('sd1');
    final y = await start('sd2');
    await waitUntil(() => x.transport.isConnected && y.transport.isConnected,
        what: 'connected');
    await x.addContactFromCode(await y.myContactCode());
    await y.addContactFromCode(await x.myContactCode());
    await x.sendText(y.myRid, 'hi');
    await y.sendText(x.myRid, 'hi back');
    // Its first list signed, as its first log check does, and so delivered.
    await y.ktOwn();
    final deadline = DateTime.now().add(const Duration(seconds: 25));
    while (await x.debugHeldPqListSignature(y.myRid) == null) {
      if (DateTime.now().isAfter(deadline)) {
        fail("the contact's signature never arrived");
      }
      await y.sendText(x.myRid, 'still here');
      await Future<void>.delayed(const Duration(milliseconds: 200));
    }
    expect(await x.vault.kvGet('cdev_${y.myRid}'), isNull,
        reason: 'a list still at version 1 is never sent');
    // Talk well past the grace: every message claims the signature.
    final until = DateTime.now().add(x.devlistGrace * 2);
    var i = 0;
    while (DateTime.now().isBefore(until)) {
      await y.sendText(x.myRid, 'claim $i');
      i++;
      await Future<void>.delayed(const Duration(milliseconds: 300));
    }
    await waitUntil(
        () => (x.messagesByChat[y.myRid] ?? const <ChatMessage>[])
            .any((m) => m.body == 'claim ${i - 1}'),
        what: 'the last claim read');
    expect(x.pqListRequestsSent(y.myRid), 0,
        reason: 'nothing asked: the signature it claims is held');
    expect(x.pqListAlerts[y.myRid], isNull,
        reason: 'and nobody accused of removing it');
    expect(await x.vault.kvGet('pql_alert_${y.myRid}'), isNull);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('a banner an earlier build raised over a contact with no list held '
      'is gone at the next start', () async {
    var x = await start('sd3');
    final y = await start('sd4');
    await waitUntil(() => x.transport.isConnected && y.transport.isConnected,
        what: 'connected');
    // x adds y and y never answers, so nothing of y's is in flight at x when
    // x stops: the vault closes under no inbound work.
    await x.addContactFromCode(await y.myContactCode());
    await waitUntil(() => y.requests.isNotEmpty,
        what: "x's request reached y, so x has nothing left to send");
    // What a build before 4.7.1 left in the vault for this contact.
    final body = devlistAlertBody(DevlistAlertKind.pqSignatureMissing);
    await x.vault.kvPut('pql_alert_${y.myRid}', body, sensitive: false);
    x = await restart(x);
    expect(x.contacts.containsKey(y.myRid), isTrue);
    expect(await x.vault.kvGet('cdev_${y.myRid}'), isNull);
    expect(x.pqListAlerts[y.myRid], isNull,
        reason: 'raised on no evidence, so not shown');
    expect(await x.vault.kvGet('pql_alert_${y.myRid}'), isNull,
        reason: 'and not kept');
  }, timeout: const Timeout(Duration(minutes: 3)));
}
