// ADR 0017 stage 2, from the transparency log's side: a log that serves an
// account's dual-signed list with its `sig` deleted gets a conflict, not a
// pinned contact.
//
// The log's operator can open any value — a value is sealed under a key
// derived from the account's PUBLIC key (§19.1) — and can write any entry,
// because a contact checks an entry's value and fingerprint, never who
// submitted it. So the operator can take the next list an account signs,
// delete its `sig`, seal what is left again and serve it at that version,
// with the fingerprint that would make it open as the account's list on a
// reader that took a lone `sig2` for a v2-only list. Had a reader taken it,
// the contact would hold, at that version, a list the account never sent and
// a fingerprint nobody else holds — and, at the floor's third level, would
// refuse every honest list from the account from then on. Real clients, the
// real relay, and the real log (kt/server.js) on loopback.
//
// Criteria, with the test that covers them below. The deletion and what it
// leaves behind are one flow, so
//   criteria 1 and 2 share a test,
//   criteria 2 and 3 share a test.
//   1. a re-sealed copy of the account's real next list, `sig` deleted, served
//      as the log's entry for that version under the fingerprint of the v2
//      input — what a reader that took a lone `sig2` for a v2-only list would
//      compute — is not installed by a contact that checks the log: its held
//      version, its held list and its floor stay as they were, and the log is
//      a conflict;
//   2. the honest dual-signed list still installs when it arrives in-band
//      afterwards — the contact is not pinned — and the log, which serves
//      another fingerprint at that version, stays a conflict;
//   3. the same deletion at the account's next version, served under the v1
//      input's fingerprint instead — what a reader that took a lone `sig2` for
//      a dual-signed list would compute — is not installed either: no
//      fingerprint the operator writes beside the stripped list makes it one.
@Tags(['integration'])
@Timeout(Duration(minutes: 4))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/key_transparency.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:z_protocol/z_protocol.dart';

Future<int> _freePort() async {
  final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final port = probe.port;
  await probe.close();
  return port;
}

Future<void> _healthy(int port) async {
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
  fail('service on $port did not start');
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  final root = Directory.current.parent.path;
  late Process relay;
  late Process log;
  late int relayPort;
  late int logPort;
  late Uint8List logPub;
  final logSeed =
      Uint8List.fromList(List<int>.generate(32, (i) => (i * 29 + 3) & 0xff));
  final dirs = <Directory>[];
  final live = <ChatService>[];

  // Each service runs in an error zone of its own; anything raised inside one
  // fails the test that was running. A service is never stopped mid-test
  // here, so no error is expected at all.
  final strays = <String>[];
  tearDown(() {
    final found = [...strays];
    strays.clear();
    expect(found, isEmpty, reason: 'errors raised inside a running service');
  });

  setUpAll(() async {
    HttpOverrides.global = null;
    relayPort = await _freePort();
    relay = await Process.start('node', ['server.js'],
        workingDirectory: '$root${Platform.pathSeparator}server',
        environment: {'PORT': '$relayPort', 'LOG_LEVEL': 'silent'});
    await _healthy(relayPort);
    logPort = await _freePort();
    log = await Process.start('node', ['server.js'],
        workingDirectory: '$root${Platform.pathSeparator}kt',
        environment: {
          'KT_SEED': [
            for (final b in logSeed) b.toRadixString(16).padLeft(2, '0')
          ].join(),
          'KT_EPHEMERAL': '1',
          'KT_PORT': '$logPort',
          // The publish gates are kt/test/publish_limits.test.js's business.
          'PUBLISH_PER_MIN': '1000000',
          'PUBLISH_PER_MIN_TOTAL': '1000000',
          'PUBLISH_PER_ACCT_PER_DAY': '1000000',
          'PUBLISH_NEW_ACCOUNTS_PER_MIN': '1000000',
        });
    log.stdout.drain<void>();
    log.stderr.drain<void>();
    await _healthy(logPort);
    final kp = await Ed25519().newKeyPairFromSeed(logSeed);
    logPub = Uint8List.fromList((await kp.extractPublicKey()).bytes);
  });

  tearDownAll(() async {
    for (final s in live.toList()) {
      s.dispose();
      await s.transport.stop();
    }
    relay.kill();
    log.kill();
    for (final d in dirs) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<ChatService> start(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_logstrip_$name');
    dirs.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final id = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(id.toJson()));
    final ready = Completer<ChatService>();
    runZonedGuarded(() async {
      try {
        final svc = await ChatService.init(
          vault: vault,
          identity: id,
          displayName: name,
          transport:
              Transport(identity: id, serverUrl: 'ws://127.0.0.1:$relayPort'),
          ktConfig: KtConfig(
              logUrl: 'http://127.0.0.1:$logPort', logPubB64: b64(logPub)),
          // Builds that dual-sign, by name: what is deleted here is the `sig`
          // of a dual-signed list, which only such a build makes, and lists
          // like that stay in the log and in contacts' hands after the
          // stage-2 signer is switched on.
          signDevlistV2Only: false,
        );
        // The log is checked when this test says so, so a status between two
        // checks is a fact the test can assert.
        svc.kt.recheckDelay = const Duration(hours: 1);
        svc.pqListDelay = const Duration(milliseconds: 150);
        live.add(svc);
        ready.complete(svc);
      } catch (e, st) {
        ready.completeError(e, st);
      }
    }, (e, st) => strays.add('$name: $e\n$st'));
    return ready.future;
  }

  Future<void> waitUntil(FutureOr<bool> Function() cond,
      {required String what,
      Duration timeout = const Duration(seconds: 30)}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  bool received(ChatService svc, String rid, String body) =>
      svc.messagesByChat[rid]?.any((m) => !m.outgoing && m.body == body) ==
      true;

  Future<void> introduce(ChatService a, ChatService b) async {
    await waitUntil(() => a.transport.isConnected && b.transport.isConnected,
        what: 'both connected');
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
    await a.sendText(b.myRid, 'hello ${b.displayName}');
    await b.sendText(a.myRid, 'hello ${a.displayName}');
    await waitUntil(
        () =>
            received(a, b.myRid, 'hello ${a.displayName}') &&
            received(b, a.myRid, 'hello ${b.displayName}'),
        what: '${a.displayName} and ${b.displayName} have spoken');
  }

  /// The list [svc] holds for [rid]'s account, as installed.
  Future<SignedDeviceList?> held(ChatService svc, String rid) async {
    final j = await svc.vault.kvGet('cdev_$rid');
    return j == null
        ? null
        : SignedDeviceList.fromJson(
            (jsonDecode(j) as Map).cast<String, Object?>());
  }

  Future<String?> floor(ChatService svc, String rid) =>
      svc.vault.kvGet('cdev_sigfloor_$rid');

  Future<void> holdsVersion(ChatService svc, String rid, int v) => waitUntil(
      () async => await svc.heldContactListVersion(rid) >= v,
      what: '${svc.displayName} holds v$v of the list');

  /// What the log serves as [acct]'s latest entry: (version, fp).
  Future<(int, String)?> logLatest(Uint8List acct) async {
    final label = await ktLabel(acct);
    final hex = [for (final b in label) b.toRadixString(16).padLeft(2, '0')]
        .join();
    final res = await (await HttpClient().getUrl(
            Uri.parse('http://127.0.0.1:$logPort/kt/v1/lookup/$hex')))
        .close();
    final j = (jsonDecode(await res.transform(utf8.decoder).join()) as Map)
        .cast<String, Object?>();
    final e = j['entry'];
    if (e is! Map) return null;
    return ((e['v'] as num).toInt(), e['fp'] as String);
  }

  test(
      '1-3. a sig-stripped copy of the account\'s next list, served by the '
      'log under either fingerprint, is a conflict: nothing installed, the '
      'floor where it was, and the honest list still installs after it',
      () async {
    final alice = await start('alice');
    final ben = await start('ben');
    await introduce(alice, ben);
    final acct = await alice.accountIdentity();

    // Alice links a laptop: version 2, dual-signed, in-band to Ben and in the
    // log. Ben's floor for her is at version 2, and the log confirms it.
    final laptop = await ZIdentity.generate();
    await alice.addMyDevice(await acct.signDeviceCert(
        deviceEdPub: laptop.edPub, deviceXPub: laptop.xPub, deviceId: 'laptop'));
    await holdsVersion(ben, alice.myRid, 2);
    await waitUntil(() async => await floor(ben, alice.myRid) == '2',
        what: 'Ben\'s floor for Alice reaches 2');
    final atTwo = (await held(ben, alice.myRid))!;
    await waitUntil(
        () async =>
            await logLatest(acct.accountEdPub) ==
            (2, b64(await atTwo.fingerprint())),
        what: 'the log holds Alice\'s v2');
    await ben.kt.check();
    expect(ben.kt.statusOf(alice.myRid)?.state, KtContactState.confirmed);

    // The account's real next list: exactly what Alice signs when she links
    // a tablet below — same devices, same version, same signatures.
    final tablet = await ZIdentity.generate();
    final tabletCert = await acct.signDeviceCert(
        deviceEdPub: tablet.edPub, deviceXPub: tablet.xPub, deviceId: 'tablet');
    final nextDevices = [...await alice.myFullDeviceList(), tabletCert];
    final next = await acct.signDeviceList(nextDevices, 3, v2Only: false);
    expect(next.sig, isNotNull);
    expect(next.sig2, isNotNull);

    // The operator's edit: `sig` deleted, the rest sealed again under the key
    // anyone holding Alice's public key derives, and served at the list's
    // version with a fingerprint of the operator's choosing. (The log's
    // publish endpoint checks a request's signature; an operator writing its
    // own storage needs none, and Alice's seed stands in for that write. Ben
    // checks the entry, never who sent it.)
    Future<void> serveStripped(SignedDeviceList list, Uint8List fp) async {
      final stripped = Map.of(list.toJson())..remove('sig');
      expect(stripped.keys, containsAll(['acct', 'ver', 'devs', 'sig2']));
      expect(stripped.containsKey('sig'), isFalse);
      final req = await ktPublishRequest(
          accountEdSeed: acct.accountEdSeed!,
          version: list.version,
          fp: fp,
          value: await ktSealValue(
              acct.accountEdPub, utf8.encode(jsonEncode(stripped))));
      final post = await (await HttpClient()
              .postUrl(Uri.parse('http://127.0.0.1:$logPort/kt/v1/publish'))
            ..headers.contentType = ContentType.json
            ..write(jsonEncode(req)))
          .close();
      expect(post.statusCode, 201);
      await post.drain<void>();
    }

    // Served under the v2 input's fingerprint: what a reader that took a lone
    // sig2 for a v2-only list would compute, and so what makes the value open
    // as Alice's list there.
    await serveStripped(next, await deviceListFingerprintV2(3, nextDevices));

    // 1. Ben checks the log and finds Alice's entry ahead of what he holds.
    await ben.kt.check();
    final s = ben.kt.statusOf(alice.myRid);
    expect(s?.logVersion, 3);
    expect(s?.state, KtContactState.conflict,
        reason: 'a value that does not open as Alice\'s list is a conflict');
    expect(await ben.heldContactListVersion(alice.myRid), 2,
        reason: 'the stripped list was not installed');
    final still = (await held(ben, alice.myRid))!;
    expect(still.version, 2);
    expect(still.sig, isNotNull, reason: 'still the dual-signed list');
    expect(b64(await still.fingerprint()), b64(await atTwo.fingerprint()));
    expect(await floor(ben, alice.myRid), '2',
        reason: 'the floor stays where the account put it');

    // 2. Alice links the tablet. Her honest v3 — dual-signed, the list the
    // operator stripped — reaches Ben in-band and installs: he is not pinned.
    await alice.addMyDevice(tabletCert);
    await holdsVersion(ben, alice.myRid, 3);
    final honest = (await held(ben, alice.myRid))!;
    expect(honest.version, 3);
    expect(honest.sig, isNotNull);
    expect(honest.sig2, isNotNull);
    expect(b64(await honest.fingerprint()), b64(await next.fingerprint()),
        reason: 'the list the operator took its copy from');
    await waitUntil(() async => await floor(ben, alice.myRid) == '3',
        what: 'Ben\'s floor for Alice follows the honest list to 3');
    // The log still serves another fingerprint for version 3 than the list
    // Ben now holds there: that stays a conflict.
    await ben.kt.check();
    expect(ben.kt.statusOf(alice.myRid)?.state, KtContactState.conflict);
    expect(ben.kt.statusOf(alice.myRid)?.logVersion, 3);

    // 3. Alice's next list after that — a desk — stripped the same way, and
    // served at version 4 under the v1 input's fingerprint: what a reader that
    // took a lone sig2 for a dual-signed list would compute. No fingerprint
    // beside it makes the stripped list one.
    final desk = await ZIdentity.generate();
    final deskCert = await acct.signDeviceCert(
        deviceEdPub: desk.edPub, deviceXPub: desk.xPub, deviceId: 'desk');
    final afterDevices = [...await alice.myFullDeviceList(), deskCert];
    final after = await acct.signDeviceList(afterDevices, 4, v2Only: false);
    await serveStripped(after, await deviceListFingerprint(4, afterDevices));
    await ben.kt.check();
    expect(ben.kt.statusOf(alice.myRid)?.logVersion, 4);
    expect(ben.kt.statusOf(alice.myRid)?.state, KtContactState.conflict);
    expect(await ben.heldContactListVersion(alice.myRid), 3,
        reason: 'the stripped list was not installed');
    expect((await held(ben, alice.myRid))!.sig, isNotNull);
    expect(await floor(ben, alice.myRid), '3');
    // And the honest one still installs.
    await alice.addMyDevice(deskCert);
    await holdsVersion(ben, alice.myRid, 4);
    final honest4 = (await held(ben, alice.myRid))!;
    expect(honest4.sig, isNotNull);
    expect(b64(await honest4.fingerprint()), b64(await after.fingerprint()));
  });
}
