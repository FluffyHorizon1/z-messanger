// 44.5 — the scanned device's link (ADR 0033 §2 and decision 3; PROTOCOL
// §18.11), and the `pqid` once more, owed per contact device.
//
// The sharpest case of a classical surface is the scanned code (R4). Someone
// who can forge Ed25519 and controls a code exchange keeps a person's account
// key and commitment, puts a device of their own in the code, and relays the
// person's genuine ML-DSA key: it matches the commitment, the contact reaches
// "post-quantum", and both people read the genuine safety number, which
// covers the two accounts and not the device. What holds is the device's
// attestation — `pqdc`, its account's ML-DSA signature over its account key,
// its two keys and its sealing key — which the device that is not theirs
// cannot make. So the device a contact was added from is checked: linked
// post-quantum when its `pqdc` verifies under their confirmed key, refused
// when it does not, and classical when none has come; and for a contact
// added on this version, the screen does not say "post-quantum" until it is
// linked (decision 3), while a contact added before keeps what it had.
//
// REAL ChatService instances over the REAL Node relay. A build from before
// 44.5 is the seam the suite uses for one (`debugBuildBefore445`, 4.8.1),
// with `debugBuildBefore481` beside it for 4.8.0, and so is one from before
// 44.3 (`debugBuildBeforeSealingKeys`). A lost envelope is made by the
// receiver's probe (`debugOnDecrypted`), which drops it as though the relay
// had never delivered it.
//
// Criteria, each a test below:
//   1. a contact added from a scanned code, both on this build, is linked
//      post-quantum once the `pqdc` and the sealing key of the device they
//      were added from have arrived under their confirmed key — on both
//      sides, kept beside the contact with the hash of that key; the contact
//      screen says so beside the number, to a screen reader too, and keeps
//      the post-quantum pill; and all of it after a restart;
//   2. a contact added on this build is not called post-quantum before that
//      link: with their device's `pqseal` withheld, their key confirmed and
//      the number compared, the pill says the device link is classical and
//      the line says the screen waits for it — and once the `pqseal` lands
//      the pill is post-quantum, the tick standing;
//   3. a `pqdc` that does not verify for the device it came from is refused,
//      recorded and said once — a line in the chat, a banner, the pill and
//      the line beside the number — through a second `pqid` from that
//      device and a restart, and never upgrades the link;
//   4. a contact's device restored onto a new sealing key, its `pqdc` lost
//      here, is judged afresh and linked again, and never refused, in the
//      order its new key and its new `pqdc` reach this device as it sends
//      them;
//   5. what was found, and that the contact was added on this build, survive
//      a restore — the link post-quantum before their device says anything
//      again — and reach a device linked later, in its enrolment; a contact
//      mirrored to that device by `cadd` is marked by that device itself,
//      and nothing found of its link travels with it;
//   6. a vault from 4.8.1 opens with every contact as it was: a verified
//      contact whose device's `pqdc` 4.8.1 held unjudged keeps its pill, its
//      tick and its number and gains the line saying it is linked
//      post-quantum; one whose app predates the attestation keeps them too,
//      with the line saying it is linked classically; and one whose held
//      `pqdc` verifies for no device of theirs is not refused — nothing an
//      older build held is evidence against a device — and keeps them too;
//   7. mixed versions raise nothing — a contact on 4.8.1, one on 4.8.0 and
//      one on a build from before 44.3, beside this build: no line about a
//      refused key or link, no device-list alert, and no `pqid` or `pqseal`
//      past the exchange's own, through more messages and a restart of all
//      four;
//   8. the `pqid` once more is owed per contact device (the re-send on, as
//      the seam has it — this build holds it): a device of theirs on a build
//      from before 44.3 when this device's `pqid` reached it does not spend
//      it — before this device holds any record of it, or once it holds one
//      for having announced its own key there — and once updated is sent it
//      once, that device alone; the device that kept it from its first
//      `pqid` is sent none, and a restart sends neither another;
//   9. the substitution itself (ADR 0033's context): a device of the
//      adversary's under each person's account key, in each person's code to
//      the other beside their genuine account key and commitment, relaying
//      their genuine ML-DSA key — so both people read one genuine number and
//      compare it — ends classical on one screen, where the device has no
//      attestation to send, and refused on the other, where it relays the
//      person's own; neither screen says "post-quantum", and both numbers
//      stand compared;
//  10. a contact's device whose stored seed no longer reads draws a new key
//      and announces it on the session it has, ahead of its next message
//      there (4.8.1): the `pqdc` held, which was of its old key and known to
//      be (read beside it on one session), goes with the old key instead of
//      being set against the new one — nothing is refused — and the link is
//      classical, the finding of the old key gone, until its `pqid` once
//      more (the re-send on, as the seam has it) brings the `pqdc` over the
//      new key, which links it again;
//  11. a contact added before 44.5 whose device link is refused afterwards —
//      its new key and then its `pqdc` on one session — gets the banner,
//      the red line and the line in the chat, its pill left as it was, as
//      decision 3 reads ("shown for the rest";
//      `pillSaysRefusedForEarlierContacts` false); and the build's own
//      answer is the one its constant holds;
//  12. with the other answer (`pillSaysRefusedForEarlierContacts` true) the
//      same refusal changes that pill too, to "Link refused";
//  13. the other order for a restored device: a `pqdc` over its new key that
//      came on a session other than the one the key held came on, before its
//      new key, waits beside the key held from before — not refused — and is
//      kept when the new key lands, though this device opened a session to
//      it in between, which links the device (the state such a `pqid`
//      leaves, built in the vaults; the session and the announcement real);
//  14. this device resets the session and then the contact's device finds
//      its stored seed unreadable: its new key, announced on the session
//      this device opened, is not set against the `pqdc` of its old key —
//      whether that `pqdc` came before the reset, with the device away, or
//      on the new session, its `pqid` answering the reset's hello — nothing
//      is refused, and its next `pqdc` links it again (4.9.0);
//  15. a contact restored from a `.zid` backup draws a new post-quantum
//      account key and a new sealing key: its `pqdc`, which came with the
//      new account key, is never refused nor checked, and the screen says
//      their post-quantum key changed — a banner and the line, the pill of a
//      contact added on this build "Device link classical" — and a reset
//      changes nothing; deleting them and adding them again from their code
//      takes the new key, and links the device post-quantum (4.9.0);
//  16. the same for a contact restored from an archive made before 2.2.4,
//      which carried no post-quantum seed: never refused, and once its
//      `pqid` comes, the screen says their post-quantum key changed;
//  17. a contact deleted and added back is linked again on the shipped
//      clock, with no six-hour wait: their device announces its key on the
//      new session at once — and so does this device, deleted and added back
//      by them (4.9.0);
//  18. a finding of the key their device held before is not said of the key
//      it holds now: left by a stop between the new key's being written and
//      its judgement, the link reads classical, not post-quantum, and the
//      next start judges it again (4.9.0);
//  19. a contact's device whose stored seed no longer reads draws a new key
//      and announces it on the session it has, and the relay loses that
//      announcement: its `pqdc` over the new key, read past the gap on the
//      session the old key came on, is not set against the old key — nothing
//      is refused, the link classical — and once this device resets the
//      session, its device announces the new key again there and the `pqdc`
//      kept links it (the state of a device whose `pqdc` had not reached
//      this one, built in the vaults; the key, the session, the loss and the
//      `pqdc` real) (4.9.0);
//  20. a one-device account's code with its X25519 key substituted — its
//      Ed25519 key, its commitment and so its number kept, what someone who
//      can forge Ed25519 and controls the exchange can hand over (ADR 0033
//      §2) — is refused for the device's genuine `pqdc`, which covers the
//      X25519 key the device holds: a root's code carries no `acct`, its
//      device key is its account's, and a key established against its
//      commitment binds that key (4.9.0, kept in 4.9.1).
@Tags(['integration'])
@Timeout(Duration(minutes: 6))
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;
import 'package:provider/provider.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart' show DatabaseException;
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/archive.dart';
import 'package:zapp/core/backup.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/enrollment.dart';
import 'package:zapp/core/key_transparency.dart';
import 'package:zapp/core/models.dart';
import 'package:zapp/core/relay_url.dart';
import 'package:zapp/core/restore.dart';
import 'package:zapp/core/sealing_keys.dart';
import 'package:zapp/core/system_messages.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/ui/contact_info_screen.dart';
import 'package:zapp/ui/theme.dart';

typedef Person = ({
  ChatService svc,
  Vault vault,
  Directory dir,
  ZIdentity id,
  String name,
});

/// One envelope a probe was shown: from whom, and the kind it carried.
class Seen {
  final String from;
  final String kind;
  final DateTime at;
  Seen(this.from, this.kind) : at = DateTime.now();
  @override
  String toString() => '$kind<-${from.substring(0, 6)}';
}

/// What one client was shown on the doors a contact's devices use, and what
/// [withhold] made it drop.
class Probe {
  final seen = <Seen>[];
  final withheld = <Seen>[];
  bool Function(Seen s)? withhold;

  void attach(ChatService svc) {
    svc.debugOnDecrypted = (path, from, dec) {
      if (path == 'sync') return false; // this account's own devices
      var kind = '?';
      try {
        kind = InnerMessage.fromBytes(dec.plaintext).kind;
      } catch (_) {}
      final s = Seen(from, kind);
      final w = withhold?.call(s) ?? false;
      (w ? withheld : seen).add(s);
      return w;
    };
  }

  int count(String from, String kind) =>
      seen.where((s) => s.from == from && s.kind == kind).length;
}

/// The system lines of kind [kind] in [svc]'s chat with [rid], as the vault
/// holds them — a chat is loaded into memory only once it is opened.
Future<int> systemLines(ChatService svc, String rid, String kind) async {
  var n = 0;
  for (final r in await svc.vault.db.query('messages',
      where: 'rid = ? AND kind = ?', whereArgs: [rid, 'system'])) {
    final body = await svc.vault.unseal(r['enc_body'] as String);
    if (!body.startsWith('{')) continue;
    if ((jsonDecode(body) as Map)['k'] == kind) n++;
  }
  return n;
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  late Process relay;
  late int port;
  final temps = <Directory>[];
  final live = <Person>[];

  setUpAll(() async {
    HttpOverrides.global = null;
    final serverDir =
        '${Directory.current.parent.path}${Platform.pathSeparator}server';
    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    port = probe.port;
    await probe.close();
    relay = await Process.start('node', ['server.js'],
        workingDirectory: serverDir,
        environment: {'PORT': '$port', 'LOG_LEVEL': 'silent'});
    relay.stdout.drain<void>();
    relay.stderr.drain<void>();
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

  final stopped = <ChatService>{};
  final strays = <String>[];
  tearDown(() {
    final found = [...strays];
    strays.clear();
    expect(found, isEmpty, reason: 'errors raised inside a running service');
  });

  /// Every service still running stopped — at the end of each test, so the
  /// next does not share the two cores with this one's clocks.
  Future<void> closeAll() async {
    for (final x in [...live]) {
      stopped.add(x.svc);
      await x.svc.transport
          .stop()
          .timeout(const Duration(seconds: 10), onTimeout: () {});
      x.svc.dispose();
      await x.vault.db.close();
    }
    live.clear();
  }

  tearDownAll(() async {
    await closeAll();
    relay.kill();
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  String relayUrl() => 'ws://127.0.0.1:$port';

  Future<Directory> tempDir(String name) async {
    final d = await Directory.systemTemp.createTemp('z_sd_$name');
    temps.add(d);
    return d;
  }

  /// A service over the vault in [dir], whose identity is the one the vault
  /// holds. The log is off and the account stays at device-list stage 1:
  /// neither is under test. [before445] and [beforeSealingKeys] start it as
  /// a build from before 44.5 (4.8.1) or from before 44.3, and [before481]
  /// with 4.8.0's rule for a `pqs:1` too; [resends] turns the `pqid` once
  /// more on, as the seam has it; [refusedPill] answers, for this service,
  /// whether a refusal changes an earlier contact's pill
  /// (`pillSaysRefusedForEarlierContacts` when null).
  Future<Person> boot(Directory dir, String name,
      {Vault? vault,
      bool before445 = false,
      bool before481 = false,
      bool beforeSealingKeys = false,
      bool resends = false,
      bool? refusedPill}) async {
    final v = vault ?? await Vault.open(rootOverride: dir);
    final id = await ZIdentity.fromJson(
        (jsonDecode((await v.kvGet('identity'))!) as Map)
            .cast<String, Object?>());
    final displayName = await v.kvGet('display_name') ?? name;
    // In an error zone of its own: a service [stop] has stopped can still
    // have work in flight, which then fails against the database [stop]
    // closed under it — that error, from a stopped service, is expected and
    // dropped. Anything else raised inside a service fails the test.
    final ready = Completer<ChatService>();
    ChatService? made;
    runZonedGuarded(() async {
      try {
        final svc = await ChatService.init(
            vault: v,
            identity: id,
            displayName: displayName,
            transport: Transport(identity: id, serverUrl: relayUrl()),
            ktConfig: KtConfig.off,
            signDevlistV2Only: false,
            debugBuildBefore445: before445,
            debugBuildBefore481: before481,
            debugBuildBeforeSealingKeys: beforeSealingKeys,
            pqdcResends: resends ? true : null,
            pillSaysRefusedForEarlier: refusedPill);
        made = svc;
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
    final svc = await ready.future;
    svc.pqListDelay = const Duration(milliseconds: 150);
    final x = (svc: svc, vault: v, dir: dir, id: id, name: name);
    live.add(x);
    return x;
  }

  Future<Person> person(String name,
      {ZIdentity? id,
      bool before445 = false,
      bool before481 = false,
      bool beforeSealingKeys = false,
      bool resends = false}) async {
    final dir = await tempDir(name);
    final vault = await Vault.open(rootOverride: dir);
    await vault.kvPut(
        'identity', jsonEncode((id ?? await ZIdentity.generate()).toJson()));
    await vault.kvPut('display_name', name);
    return boot(dir, name,
        vault: vault,
        before445: before445,
        before481: before481,
        beforeSealingKeys: beforeSealingKeys,
        resends: resends);
  }

  Future<void> stop(Person x) async {
    stopped.add(x.svc);
    await x.svc.transport.stop();
    x.svc.dispose();
    await x.vault.db.close();
    live.remove(x);
  }

  /// The app stopped and started again on the same vault, as this build
  /// unless told otherwise. [before] runs on the vault as it stands once [x]
  /// has stopped.
  Future<Person> restart(Person x,
      {bool before445 = false,
      bool before481 = false,
      bool beforeSealingKeys = false,
      bool resends = false,
      bool? refusedPill,
      Future<void> Function(Vault vault)? before}) async {
    await stop(x);
    final vault = await Vault.open(rootOverride: x.dir);
    if (before != null) await before(vault);
    return boot(x.dir, x.name,
        vault: vault,
        before445: before445,
        before481: before481,
        beforeSealingKeys: beforeSealingKeys,
        resends: resends,
        refusedPill: refusedPill);
  }

  Future<void> waitUntil(FutureOr<bool> Function() cond,
      {Duration timeout = const Duration(seconds: 45),
      required String what}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  Future<void> connected(List<Person> people) => waitUntil(
      () => people.every((x) => x.svc.transport.isConnected),
      what: 'everyone connected to the relay');

  /// [from] says [body] to [to], and it arrives.
  Future<void> say(Person from, Person to, String body) async {
    await from.svc.sendText(to.svc.myRid, body);
    await waitUntil(
        () => (to.svc.messagesByChat[from.svc.myRid] ?? [])
            .any((m) => m.body == body),
        what: '"$body" reached ${to.name}');
  }

  /// [from] sends [body] to its contact [toRid], and it arrives in [at]'s
  /// chat [atChat] — for a device that is not the one its contact was added
  /// from, whose messages land in its account's chat.
  Future<void> sendAndSee(Person from, String toRid, Person at, String atChat,
      String body) async {
    await from.svc.sendText(toRid, body);
    await waitUntil(
        () => (at.svc.messagesByChat[atChat] ?? []).any((m) => m.body == body),
        what: '"$body" reached ${at.name}');
  }

  /// [a] and [b] talk, a message each way a round, until [cond] holds;
  /// bounded, so an exchange that never completes fails saying [what].
  Future<void> talkUntil(Person a, Person b, FutureOr<bool> Function() cond,
      {required String what, int rounds = 12}) async {
    for (var i = 0; i < rounds; i++) {
      if (await cond()) return;
      await say(a, b, '${a.name} $what $i');
      await say(b, a, '${b.name} $what $i');
    }
    await waitUntil(cond, what: what);
  }

  /// [a] and [b] scan each other's codes and speak both ways, until both
  /// hold each other's post-quantum key and the exchange has gone quiet.
  Future<void> pairUp(Person a, Person b) async {
    await connected([a, b]);
    await a.svc.addContactFromCode(await b.svc.myContactCode());
    await b.svc.addContactFromCode(await a.svc.myContactCode());
    await say(a, b, 'hi ${b.name}');
    await say(b, a, 'hi ${a.name}');
    await waitUntil(
        () =>
            a.svc.contacts[b.svc.myRid]?.numberKey != null &&
            b.svc.contacts[a.svc.myRid]?.numberKey != null &&
            !a.svc.pqSendPending &&
            !b.svc.pqSendPending,
        what: 'both post-quantum keys landed and the exchange went quiet');
  }

  /// Both [a] and [b] hold each other's device linked post-quantum.
  Future<void> linkedBothWays(Person a, Person b) => talkUntil(
      a,
      b,
      () =>
          a.svc.deviceLinkWith(b.svc.myRid) == DeviceLink.attested &&
          b.svc.deviceLinkWith(a.svc.myRid) == DeviceLink.attested,
      what: 'each device linked post-quantum on the other side');

  /// A device enrolled to [phone]'s account directly — for a contact's
  /// account, where the ceremony is not what is under test.
  Future<Person> linkDirect(Person phone, String name,
      {bool beforeSealingKeys = false}) async {
    final account = await phone.svc.accountIdentity();
    final devId = await ZIdentity.generate();
    final cert = await account.signDeviceCert(
        deviceEdPub: devId.edPub, deviceXPub: devId.xPub, deviceId: name);
    final dir = await tempDir(name);
    final vault = await Vault.open(rootOverride: dir);
    await vault.kvPut('identity', jsonEncode(devId.toJson()));
    await vault.kvPut('display_name', phone.name);
    final enrolled = await AccountIdentity.fromEnrollment(
      accountEdPub: account.accountEdPub,
      accountMlPub: await phone.svc.pqAccountPublic(),
      deviceEdSeed: devId.edSeed,
      deviceXSeed: devId.xSeed,
      deviceId: name,
      deviceCert: cert,
    );
    await vault.kvPut('account', jsonEncode(enrolled.toJson()));
    await vault.kvPut('my_devices', jsonEncode([account.deviceCert.toJson()]),
        sensitive: false);
    final x =
        await boot(dir, name, vault: vault, beforeSealingKeys: beforeSealingKeys);
    await connected([x, phone]);
    await phone.svc.addMyDevice(cert);
    await waitUntil(() async => await x.svc.ownDeviceListVersion() >= 2,
        what: "$name learned its account's list");
    return x;
  }

  /// A device of [victim]'s account that [victim] never linked: what someone
  /// who can forge Ed25519 makes (ADR 0033's context) — its certificate under
  /// the account's key, beside the account's ML-DSA public key, which every
  /// contact of the account is sent. No list of the account names it, so its
  /// root signs it no `pqdc`; its code is the account's, with its own keys.
  Future<Person> forgedDevice(Person victim, String name) async {
    final account = await victim.svc.accountIdentity();
    final devId = await ZIdentity.generate();
    final cert = await account.signDeviceCert(
        deviceEdPub: devId.edPub, deviceXPub: devId.xPub, deviceId: name);
    final dir = await tempDir(name);
    final vault = await Vault.open(rootOverride: dir);
    await vault.kvPut('identity', jsonEncode(devId.toJson()));
    await vault.kvPut('display_name', victim.name);
    final enrolled = await AccountIdentity.fromEnrollment(
      accountEdPub: account.accountEdPub,
      accountMlPub: await victim.svc.pqAccountPublic(),
      deviceEdSeed: devId.edSeed,
      deviceXSeed: devId.xSeed,
      deviceId: name,
      deviceCert: cert,
    );
    await vault.kvPut('account', jsonEncode(enrolled.toJson()));
    await vault.kvPut('my_devices', jsonEncode([account.deviceCert.toJson()]),
        sensitive: false);
    final x = await boot(dir, name, vault: vault);
    await connected([x]);
    return x;
  }

  /// [phone] links a new device by the real ceremony over the relay
  /// (§10.2), which installs its enrolment and starts.
  Future<Person> link(Person phone, String name) async {
    final n = await NewDeviceLink.create();
    final hosted =
        phone.svc.hostDeviceLink(n.code, confirmSas: (_) async => true);
    final result = await n.run(relayUrl: relayUrl(), confirm: (_) async => true);
    expect(result, isNotNull, reason: 'the new device was enrolled');
    expect(await hosted, isTrue, reason: 'the phone linked it');
    final dir = await tempDir(name);
    final vault = await Vault.open(rootOverride: dir);
    await setRelayUrl(vault, relayUrl(), acceptedInsecure: true);
    await installEnrollment(vault, result!, sealingKey: n.sealingKey);
    final x = await boot(dir, name, vault: vault);
    await connected([x]);
    return x;
  }

  /// A backup of [x]'s vault: the archive file and its code.
  Future<(File, RecoveryCode)> backup(Person x) async {
    final code = await RecoveryCode.generate();
    final file =
        File(p.join((await tempDir('${x.name}_zbk')).path, 'b.zbk'));
    final sink = file.openWrite();
    await BackupArchive.export(vault: x.vault, code: code, out: sink);
    await sink.close();
    return (file, code);
  }

  /// The device is lost and a fresh install restores [file] onto the same
  /// directory, the way the onboarding screen does; [before] runs on the
  /// restored vault before it starts.
  Future<Person> lostAndRestored(Person x, File file, RecoveryCode code,
      {Future<void> Function(Vault vault)? before}) async {
    await stop(x);
    x.dir.deleteSync(recursive: true);
    x.dir.createSync(recursive: true);
    final vault = await Vault.open(rootOverride: x.dir);
    await Restore.run(
      vault: vault,
      file: file,
      secret: await code.format(),
      kind: (await Restore.identify(file)).kind,
      serverUrl: relayUrl(),
    );
    if (before != null) await before(vault);
    return boot(x.dir, x.name, vault: vault);
  }

  Widget wrap(ChatService svc, Widget child) =>
      ChangeNotifierProvider<ChatService>.value(
        value: svc,
        child: MaterialApp(
          theme: ZTheme.light(),
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: child,
        ),
      );

  /// Rebuild until [cond] holds against the widget tree, letting real work
  /// run in between; fail saying [what] if it never does.
  Future<void> settleUntil(WidgetTester t, bool Function() cond,
      {required String what}) async {
    final deadline = DateTime.now().add(const Duration(seconds: 30));
    await t.pump(const Duration(milliseconds: 50));
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        fail('the screen never showed: $what');
      }
      await t.runAsync(
          () => Future<void>.delayed(const Duration(milliseconds: 100)));
      await t.pump(const Duration(milliseconds: 50));
    }
    await t.pump(const Duration(milliseconds: 350));
  }

  /// Unmount once the screen's own work is done: the safety number it works
  /// out as it opens is on it, the spinner gone.
  Future<void> leave(WidgetTester t) async {
    await settleUntil(
        t, () => find.byType(CircularProgressIndicator).evaluate().isEmpty,
        what: 'the safety number worked out, on the screen');
    await t.pumpWidget(const SizedBox());
    await t.runAsync(
        () => Future<void>.delayed(const Duration(milliseconds: 300)));
  }

  /// [x]'s contact screen for [rid], shown and settled on [key].
  Future<void> show(WidgetTester t, Person x, String rid, String key) async {
    await t.pumpWidget(wrap(x.svc, ContactInfoScreen(rid: rid)));
    await settleUntil(
        t, () => find.byKey(ValueKey(key)).evaluate().isNotEmpty,
        what: "$key on ${x.name}'s screen");
  }

  final l = lookupAppLocalizations(const Locale('en'));

  testWidgets(
      '1. a contact added from a scanned code is linked post-quantum once its '
      'device has attested itself, on both sides, and the screen says so',
      (t) async {
    await t.binding.setSurfaceSize(const Size(800, 3000));
    addTearDown(() => t.binding.setSurfaceSize(null));
    final semantics = t.ensureSemantics();
    late Person alice, bob;
    await t.runAsync(() async {
      alice = await person('alice1');
      bob = await person('bob1');
      await pairUp(alice, bob);
      await linkedBothWays(alice, bob);
    });
    final aRid = alice.svc.myRid, bRid = bob.svc.myRid;
    for (final (x, y) in [(alice, bob), (bob, alice)]) {
      final c = x.svc.contacts[y.svc.myRid]!;
      expect(c.linkRequired, isTrue, reason: '${x.name} added them on 44.5');
      expect(c.assurance, IdentityAssurance.hybrid);
      expect(x.svc.debugPqdcOf(y.svc.myRid), y.svc.debugOwnPqdc,
          reason: "the pqdc judged is the one ${y.name}'s device holds");
      expect(x.svc.debugPqSealOf(y.svc.myRid), y.svc.sealingKey);
      final row = await t.runAsync(
          () => x.vault.kvGet('dlink_${y.svc.myRid}'));
      final kept = DeviceLinkVerdict.decode(row);
      expect(kept?.finding, DeviceLinkFinding.attested,
          reason: 'what was found is kept beside the contact');
      final sk = await t.runAsync(() => sha256Bytes(y.svc.sealingKey!));
      expect(kept!.sk, sk, reason: 'with the hash of the key it was found of');
      expect(
          await t.runAsync(() => systemLines(
              x.svc, y.svc.myRid, SystemKind.deviceLinkRefused)),
          0);
    }

    // Alice's screen of Bob, compared and confirmed: post-quantum, and the
    // link said beside the number — to a screen reader too.
    await t.runAsync(() => alice.svc.setVerified(bRid, true));
    expect(alice.svc.verificationWith(bRid), VerificationState.verified);
    await show(t, alice, bRid, 'ci-device-link-attested');
    expect(find.text(l.ciDeviceLinkAttested), findsOneWidget);
    expect(find.text(l.ciPillPq), findsOneWidget,
        reason: 'linked, a contact added on this build keeps the pill');
    expect(find.text(l.ciPillDeviceLinkClassical), findsNothing);
    expect(
        find.bySemanticsLabel(
            l.ciDeviceLinkLabel(l.ciDeviceLinkAttested)),
        findsOneWidget,
        reason: 'what the link is, said to a screen reader');
    expect(find.byKey(const ValueKey('ci-device-link-refused-banner')),
        findsNothing);
    await leave(t);

    // And after a restart of both: the same, from what was kept.
    await t.runAsync(() async {
      alice = await restart(alice);
      bob = await restart(bob);
    });
    expect(alice.svc.deviceLinkWith(bRid), DeviceLink.attested);
    expect(bob.svc.deviceLinkWith(aRid), DeviceLink.attested);
    expect(alice.svc.contacts[bRid]!.linkRequired, isTrue);
    await show(t, alice, bRid, 'ci-device-link-attested');
    expect(find.text(l.ciPillPq), findsOneWidget);
    await leave(t);
    await t.runAsync(closeAll);
    semantics.dispose();
  });

  testWidgets(
      '2. a contact added on this build is not called post-quantum before '
      'its device is linked, its number compared or not', (t) async {
    await t.binding.setSurfaceSize(const Size(800, 3000));
    addTearDown(() => t.binding.setSurfaceSize(null));
    late Person alice, bob;
    final probe = Probe();
    await t.runAsync(() async {
      alice = await person('alice2');
      bob = await person('bob2');
      probe.attach(alice.svc);
      // Every `pqseal` from Bob's device is lost on its way to Alice.
      probe.withhold = (s) => s.kind == 'pqseal';
      await pairUp(alice, bob);
      await talkUntil(
          alice,
          bob,
          () =>
              probe.withheld.any((s) => s.from == bob.svc.myRid) &&
              alice.svc.debugPqdcOf(bob.svc.myRid) != null,
          what: "Bob's pqseal withheld and his pqdc held");
    });
    final bRid = bob.svc.myRid;
    final c = alice.svc.contacts[bRid]!;
    expect(c.assurance, IdentityAssurance.hybrid,
        reason: 'the premise: their key is confirmed');
    expect(c.pqDisplay, PqDisplay.postQuantum);
    expect(c.linkRequired, isTrue);
    expect(alice.svc.debugPqSealOf(bRid), isNull,
        reason: "the premise: Bob's sealing key never arrived");
    expect(alice.svc.deviceLinkWith(bRid), DeviceLink.classical);

    await t.runAsync(() => alice.svc.setVerified(bRid, true));
    expect(alice.svc.verificationWith(bRid), VerificationState.verified);
    await show(t, alice, bRid, 'ci-device-link-classical');
    expect(find.text(l.ciPillPq), findsNothing,
        reason: '"post-quantum, verified" without the attestation');
    expect(find.text(l.ciPillDeviceLinkClassical), findsOneWidget);
    expect(find.text(l.ciDeviceLinkClassicalRequired), findsOneWidget);
    expect(
        t
            .widget<SwitchListTile>(
                find.widgetWithText(SwitchListTile, l.ciSwitchVerified))
            .value,
        isTrue,
        reason: 'the number was compared, and the tick says so');
    await leave(t);

    // Bob's device announces its key again, and this time it lands.
    await t.runAsync(() async {
      probe.withhold = null;
      bob.svc.pqOfferRetry = 300;
      await talkUntil(alice, bob,
          () => alice.svc.deviceLinkWith(bRid) == DeviceLink.attested,
          what: "Bob's device linked post-quantum once its pqseal landed");
    });
    expect(alice.svc.verificationWith(bRid), VerificationState.verified,
        reason: 'the link moves no number, so the tick stands');
    await show(t, alice, bRid, 'ci-device-link-attested');
    expect(find.text(l.ciPillPq), findsOneWidget);
    expect(find.text(l.ciPillDeviceLinkClassical), findsNothing);
    await leave(t);
    await t.runAsync(closeAll);
  });

  testWidgets(
      '3. a pqdc that does not verify for its device is refused, recorded '
      'and said once, through another pqid and a restart', (t) async {
    await t.binding.setSurfaceSize(const Size(800, 3000));
    addTearDown(() => t.binding.setSurfaceSize(null));
    late Person alice, bob;
    await t.runAsync(() async {
      alice = await person('alice3');
      bob = await person('bob3');
      // Bob's account's own signature, over his two keys and a sealing key
      // that is not his device's: what verifies for no device that announces
      // the key it holds.
      bob.svc.debugPqidAttestation = await signDeviceAttestation(
          accountKey: (await bob.svc.pqIdentity())!,
          deviceEdPub: bob.id.edPub,
          deviceXPub: bob.id.xPub,
          sealEk: SealingKey.generate().ek);
      await pairUp(alice, bob);
      await talkUntil(
          alice,
          bob,
          () =>
              alice.svc.deviceLinkWith(bob.svc.myRid) == DeviceLink.refused &&
              bob.svc.deviceLinkWith(alice.svc.myRid) == DeviceLink.attested,
          what: "Bob's device link refused, and Alice's linked at Bob's");
    });
    final aRid = alice.svc.myRid, bRid = bob.svc.myRid;
    expect(alice.svc.debugPqSealOf(bRid), bob.svc.sealingKey,
        reason: 'the premise: judged against the key his device announced');
    expect(
        await t.runAsync(() =>
            systemLines(alice.svc, bRid, SystemKind.deviceLinkRefused)),
        1,
        reason: 'said once, in the chat');
    final kept = DeviceLinkVerdict.decode(
        await t.runAsync<String?>(() => alice.vault.kvGet('dlink_$bRid')));
    expect(kept?.finding, DeviceLinkFinding.refused, reason: 'and recorded');
    // Bob's side of Alice is untouched: her pqdc is her own.
    expect(bob.svc.deviceLinkWith(aRid), DeviceLink.attested);

    await show(t, alice, bRid, 'ci-device-link-refused');
    expect(find.byKey(const ValueKey('ci-device-link-refused-banner')),
        findsOneWidget);
    expect(find.text(l.ciDeviceLinkRefusedTitle), findsOneWidget);
    expect(find.text(l.ciDeviceLinkRefusedBody('bob3')), findsOneWidget);
    expect(find.text(l.ciPillDeviceLinkRefused), findsOneWidget);
    expect(find.text(l.ciPillPq), findsNothing);
    await leave(t);

    // Bob's device sends its `pqid` again — on the new session Alice opens,
    // after a restart of his — with another pqdc that verifies for no device
    // of his: it is taken, and nothing more is said.
    late Uint8List second;
    await t.runAsync(() async {
      bob = await restart(bob);
      second = bob.svc.debugPqidAttestation = await signDeviceAttestation(
          accountKey: (await bob.svc.pqIdentity())!,
          deviceEdPub: bob.id.edPub,
          deviceXPub: bob.id.xPub,
          sealEk: SealingKey.generate().ek);
      await connected([alice, bob]);
      await alice.svc.resetSecureSession(bRid);
      await talkUntil(
          alice,
          bob,
          () {
            final held = alice.svc.debugPqdcOf(bRid);
            return held != null &&
                constantTimeEquals(held, second) &&
                !bob.svc.pqSendPending;
          },
          what: "Bob's second pqid at Alice");
    });
    expect(alice.svc.deviceLinkWith(bRid), DeviceLink.refused);
    expect(
        await t.runAsync(() =>
            systemLines(alice.svc, bRid, SystemKind.deviceLinkRefused)),
        1,
        reason: 'a refusal is said once, however often the pqdc comes');

    // And after Alice restarts.
    await t.runAsync(() async => alice = await restart(alice));
    expect(alice.svc.deviceLinkWith(bRid), DeviceLink.refused);
    expect(
        await t.runAsync(() =>
            systemLines(alice.svc, bRid, SystemKind.deviceLinkRefused)),
        1,
        reason: 'and after a restart');
    await t.runAsync(closeAll);
  });

  test(
      '4. a device restored onto a new sealing key is judged afresh and '
      'linked again, never refused', () async {
    var alice = await person('alice4');
    var bob = await person('bob4');
    final probe = Probe()..attach(alice.svc);
    await pairUp(alice, bob);
    await linkedBothWays(alice, bob);
    final bRid = bob.svc.myRid;
    final oldKey = bob.svc.sealingKey!;

    // What Alice holds of Bob's device: the key, and no `pqdc` — as when his
    // first `pqid` predated his attestation — and so nothing found yet.
    alice = await restart(alice, before: (v) async {
      final rec = SealRecord.decode(await v.kvGet('cseal_$bRid'));
      rec.devices[bRid]!.pqdc = null;
      await v.kvPut('cseal_$bRid', rec.encode());
      await v.kvDelete('dlink_$bRid');
    });
    probe.attach(alice.svc);
    expect(alice.svc.debugPqdcOf(bRid), isNull);
    expect(alice.svc.debugPqSealOf(bRid), oldKey);
    expect(alice.svc.deviceLinkWith(bRid), DeviceLink.classical);

    // Bob's phone is lost and restored from an archive that carried no
    // sealing key, as one from before 44.3 did: a new key at its first start.
    final (file, code) = await backup(bob);
    bob = await lostAndRestored(bob, file, code, before: (v) async {
      await v.kvDelete(sealSeedKey);
      await v.kvDelete(ownPqdcKey);
    });
    await connected([alice, bob]);
    final newKey = bob.svc.sealingKey!;
    expect(newKey, isNot(oldKey), reason: 'the premise: a new sealing key');
    final mark = probe.seen.length;

    // His device opens a new session — after which nothing Alice held from
    // before is set against what he says — and she opens one too. His new
    // key and the `pqdc` over it come in whichever order his device sends
    // them: under 4.8.1's rule its `pqseal` rides its first mixed message,
    // usually ahead of its `pqid` (criterion 13 holds the other order). No
    // envelope is dropped on its way: a lost announcement can leave his
    // device taking Alice's stamp, of his old key, for the new one — the
    // window PROTOCOL §18.11 names.
    var refusedOnTheWay = false;
    bob.svc.pqOfferRetry = 300;
    await say(bob, alice, 'back');
    await alice.svc.resetSecureSession(bRid);
    await talkUntil(alice, bob, () {
      if (alice.svc.deviceLinkWith(bRid) == DeviceLink.refused) {
        refusedOnTheWay = true;
      }
      return alice.svc.deviceLinkWith(bRid) == DeviceLink.attested;
    }, what: "Bob's restored device linked post-quantum");
    expect(refusedOnTheWay, isFalse);
    expect(
        probe.seen
            .skip(mark)
            .where((s) => s.from == bRid && s.kind == 'pqid'),
        isNotEmpty,
        reason: 'the premise: his new pqdc came in a pqid of his restored '
            'device');
    expect(alice.svc.debugPqSealOf(bRid), newKey);
    expect(alice.svc.contacts[bRid]!.deviceLinkVerdict!.sk,
        await sha256Bytes(newKey),
        reason: 'found of the new key');
    expect(await systemLines(alice.svc, bRid, SystemKind.deviceLinkRefused), 0,
        reason: 'a pqdc from the new session against the key from the old '
            'one is evidence of nothing');
    await closeAll();
  });

  testWidgets(
      '5. what was found and that a contact was added here survive a '
      'restore and reach a device linked later; a cadd carries neither',
      (t) async {
    await t.binding.setSurfaceSize(const Size(800, 3000));
    addTearDown(() => t.binding.setSurfaceSize(null));
    late Person alice, bob, laptop, carol;
    await t.runAsync(() async {
      alice = await person('alice5');
      bob = await person('bob5');
      await pairUp(alice, bob);
      await linkedBothWays(alice, bob);
      final (file, code) = await backup(alice);
      alice = await lostAndRestored(alice, file, code);
    });
    final bRid = bob.svc.myRid;
    // Before Bob's device has said anything to the restored one: the
    // archive carries no key of his, and the link stands on what was found.
    expect(alice.svc.debugPqSealOf(bRid), isNull,
        reason: 'the premise: no sealing key of his travels in the archive');
    expect(alice.svc.contacts[bRid]!.linkRequired, isTrue);
    expect(alice.svc.contacts[bRid]!.deviceLinkVerdict?.finding,
        DeviceLinkFinding.attested);
    expect(alice.svc.deviceLinkWith(bRid), DeviceLink.attested);
    await show(t, alice, bRid, 'ci-device-link-attested');
    expect(find.text(l.ciPillPq), findsOneWidget);
    await leave(t);

    await t.runAsync(() async {
      await connected([alice, bob]);
      laptop = await link(alice, 'laptop5');
    });
    final onLaptop = laptop.svc.contacts[bRid]!;
    expect(onLaptop.linkRequired, isTrue,
        reason: 'the enrolment carried that the phone added Bob on 44.5');
    expect(onLaptop.deviceLinkVerdict?.finding, DeviceLinkFinding.attested,
        reason: 'and what the phone found of his device');
    expect(laptop.svc.deviceLinkWith(bRid), DeviceLink.attested);

    // Carol, added on the phone once the laptop is linked, reaches the
    // laptop by `cadd`: the laptop adds her itself, and the `cadd` says
    // nothing of when she was added or of her link.
    final cadds = <Map<String, Object?>>[];
    laptop.svc.debugOnDecrypted = (path, from, dec) {
      if (path != 'sync') return false;
      try {
        final j = jsonDecode(utf8.decode(dec.plaintext)) as Map;
        final inner = InnerMessage.fromBytes(base64Decode(j['inner'] as String));
        if (inner.kind == 'cadd') cadds.add(inner.data);
      } catch (_) {}
      return false;
    };
    await t.runAsync(() async {
      carol = await person('carol5');
      await pairUp(alice, carol);
      await waitUntil(
          () => laptop.svc.contacts.containsKey(carol.svc.myRid),
          what: 'Carol mirrored to the laptop');
    });
    final cRid = carol.svc.myRid;
    final mirrored = laptop.svc.contacts[cRid]!;
    expect(mirrored.addedByDevice, isNotNull, reason: 'the premise: a cadd');
    expect(mirrored.linkRequired, isTrue,
        reason: 'added on the laptop by this build, as any add here is');
    final carried = cadds.singleWhere((d) => d['rid'] == cRid);
    expect(carried.keys.toSet(),
        everyElement(isIn(['rid', 'bundle', 'name', 'pqc', 'acct', 'cert', 'pqk'])),
        reason: 'a cadd carries the contact and nothing of the link: '
            '${carried.keys}');
    expect(alice.svc.contacts[cRid]!.linkRequired, isTrue,
        reason: 'the phone, which added her, marked her itself');
    await t.runAsync(closeAll);
  });

  testWidgets(
      '6. a vault from 4.8.1 opens with every contact as it was, and only '
      'the device-link line added: nothing it held is refused', (t) async {
    await t.binding.setSurfaceSize(const Size(800, 3000));
    addTearDown(() => t.binding.setSurfaceSize(null));
    late Person alice, bob, carol, dave;
    final numbers = <String, String>{};
    await t.runAsync(() async {
      // On 4.8.1: Alice, Bob and Dave, and Carol on a build from before
      // 44.3. Dave's device carries a `pqdc` that verifies for no device of
      // his — his account's signature over a sealing key that is not his
      // device's — which 4.8.1 keeps beside his key and judges not at all.
      alice = await person('alice6', before445: true);
      bob = await person('bob6', before445: true);
      carol = await person('carol6', beforeSealingKeys: true);
      dave = await person('dave6', before445: true);
      dave.svc.debugPqidAttestation = await signDeviceAttestation(
          accountKey: (await dave.svc.pqIdentity())!,
          deviceEdPub: dave.id.edPub,
          deviceXPub: dave.id.xPub,
          sealEk: SealingKey.generate().ek);
      for (final x in [bob, dave]) {
        await pairUp(alice, x);
        await talkUntil(
            alice,
            x,
            () =>
                alice.svc.debugPqdcOf(x.svc.myRid) != null &&
                alice.svc.debugPqSealOf(x.svc.myRid) != null,
            what: "4.8.1 holding ${x.name}'s pqdc and sealing key, unjudged");
      }
      await pairUp(alice, carol);
      for (final x in [bob, carol, dave]) {
        await alice.svc.setVerified(x.svc.myRid, true);
        numbers[x.svc.myRid] = await alice.svc.safetyNumberWith(x.svc.myRid);
      }
    });
    final bRid = bob.svc.myRid, cRid = carol.svc.myRid, dRid = dave.svc.myRid;
    for (final rid in [bRid, cRid, dRid]) {
      expect(alice.svc.verificationWith(rid), VerificationState.verified);
      expect(alice.svc.contacts[rid]!.pqDisplay, PqDisplay.postQuantum);
      expect(
          await t.runAsync(() => alice.vault.kvGet('dlreq_$rid')), isNull,
          reason: '4.8.1 records nothing of when a contact was added');
      expect(await t.runAsync(() => alice.vault.kvGet('dlink_$rid')), isNull,
          reason: 'nor of what was found');
    }
    for (final rid in [bRid, dRid]) {
      final held = jsonDecode(
          (await t.runAsync<String?>(() => alice.vault.kvGet('cseal_$rid')))!)
          as Map;
      final device = (held['d'] as Map)[rid] as Map;
      expect(device.containsKey('ef') || device.containsKey('df'), isFalse,
          reason: 'the premise: nothing 4.8.1 held says it came since a '
              'session with the device last began, so none of it is evidence '
              'against a device');
    }
    final daveSeal = alice.svc.debugPqSealOf(dRid)!;
    final davePqdc = alice.svc.debugPqdcOf(dRid)!;
    expect(
        deviceAttestationValid(
            accountMlPub: alice.svc.contacts[dRid]!.pqPub!,
            accountEdPub: alice.svc.contacts[dRid]!.accountEd,
            deviceEdPub: dave.id.edPub,
            deviceXPub: dave.id.xPub,
            sealEk: daveSeal,
            pqdc: davePqdc),
        isFalse,
        reason: "the premise: the pqdc 4.8.1 holds of Dave's device fails");

    // This build opens the vault, and judges what 4.8.1 held, once.
    await t.runAsync(() async {
      alice = await restart(alice);
      await alice.svc.debugHeldLinksJudged;
    });
    expect(alice.svc.deviceLinkWith(bRid), DeviceLink.attested,
        reason: "the pqdc 4.8.1 held, judged once");
    expect(alice.svc.deviceLinkWith(dRid), DeviceLink.classical,
        reason: 'what an older build held is evidence of nothing: not refused');
    expect(await t.runAsync(() => alice.vault.kvGet('dlink_$dRid')), isNull,
        reason: 'and nothing recorded of it');
    expect(alice.svc.debugPqdcOf(dRid), davePqdc,
        reason: 'the pqdc stays, waiting for the key it is of');
    for (final rid in [bRid, cRid, dRid]) {
      final c = alice.svc.contacts[rid]!;
      expect(c.linkRequired, isFalse, reason: 'added before 44.5');
      expect(c.pqDisplay, PqDisplay.postQuantum);
      expect(c.assurance, IdentityAssurance.hybrid);
      expect(alice.svc.verificationWith(rid), VerificationState.verified,
          reason: 'no tick lost');
      expect(await t.runAsync(() => alice.svc.safetyNumberWith(rid)),
          numbers[rid],
          reason: 'no number moved');
      expect(
          await t.runAsync(() =>
              systemLines(alice.svc, rid, SystemKind.deviceLinkRefused)),
          0);
    }
    expect(alice.svc.deviceLinkWith(cRid), DeviceLink.classical,
        reason: "Carol's app sends no attestation");

    for (final rid in [cRid, dRid]) {
      await show(t, alice, rid, 'ci-device-link-classical');
      expect(find.text(l.ciPillPq), findsOneWidget,
          reason: 'shown, not required: a contact added before keeps its pill');
      expect(find.text(l.ciDeviceLinkClassical), findsOneWidget);
      expect(find.text(l.ciPillDeviceLinkClassical), findsNothing);
      expect(find.byKey(const ValueKey('ci-device-link-refused-banner')),
          findsNothing);
      expect(find.textContaining('This is the number you compared'),
          findsOneWidget);
      await leave(t);
    }
    await show(t, alice, bRid, 'ci-device-link-attested');
    expect(find.text(l.ciPillPq), findsOneWidget);
    expect(find.text(l.ciDeviceLinkAttested), findsOneWidget);
    expect(find.textContaining('This is the number you compared'),
        findsOneWidget);
    await leave(t);
    await t.runAsync(closeAll);
  });

  test(
      '7. a 4.8.1 contact, a 4.8.0 one and one from before 44.3 beside this '
      'build raise nothing and send nothing past the exchange', () async {
    var alice = await person('alice7');
    var bob = await person('bob7', before445: true);
    var carol = await person('carol7', beforeSealingKeys: true);
    var dave = await person('dave7', before445: true, before481: true);
    final carolProbe = Probe()..attach(carol.svc);
    await pairUp(alice, bob);
    await pairUp(alice, carol);
    await pairUp(alice, dave);
    // The exchange, to its end: each of Alice and Bob, and of Alice and
    // Dave, holding the other's sealing key and having heard so, and Alice's
    // one announcement of hers at Carol, whose build reads it as a kind it
    // does not know.
    for (final (x, build) in [(bob, '4.8.1'), (dave, '4.8.0')]) {
      await talkUntil(
          alice,
          x,
          () =>
              alice.svc.deviceLinkWith(x.svc.myRid) == DeviceLink.attested &&
              x.svc.debugHoldsMySealKey(alice.svc.myRid) &&
              alice.svc.debugHoldsMySealKey(x.svc.myRid),
          what: "$build's attestation judged, and each holding the other's "
              'key');
    }
    await talkUntil(
        alice,
        carol,
        () =>
            carolProbe.count(alice.svc.myRid, 'pqseal') == 1 &&
            !alice.svc.pqSendPending,
        what: "Alice's pqseal at Carol, and the exchange with Carol quiet");
    final aRid = alice.svc.myRid, bRid = bob.svc.myRid, cRid = carol.svc.myRid;
    final dRid = dave.svc.myRid;
    expect(alice.svc.deviceLinkWith(cRid), DeviceLink.classical);

    Future<void> nothingRaised() async {
      for (final (x, rids) in [
        (alice, [bRid, cRid, dRid]),
        (bob, [aRid]),
        (carol, [aRid]),
        (dave, [aRid]),
      ]) {
        for (final rid in rids) {
          for (final kind in [
            SystemKind.deviceLinkRefused,
            SystemKind.pqMismatch,
          ]) {
            expect(await systemLines(x.svc, rid, kind), 0,
                reason: '${x.name} was told $kind about $rid');
          }
          expect(x.svc.contacts[rid]!.pqMismatch, isFalse);
          expect(x.svc.deviceLinkWith(rid), isNot(DeviceLink.refused));
        }
        expect(x.svc.pqListAlerts, isEmpty,
            reason: '${x.name} raised a device-list alert');
      }
    }

    await nothingRaised();
    // A window with nothing to say (a negative check, by design): four more
    // rounds each way send no `pqid` and no `pqseal` from anyone.
    final everyone = [alice, bob, carol, dave];
    final pqid = everyone.map((x) => x.svc.debugPqSends).toList();
    final seal = everyone.map((x) => x.svc.debugPqSealSends).toList();
    for (var i = 0; i < 4; i++) {
      await say(alice, bob, 'to bob $i');
      await say(bob, alice, 'to alice $i');
      await say(alice, carol, 'to carol $i');
      await say(carol, alice, 'from carol $i');
      await say(alice, dave, 'to dave $i');
      await say(dave, alice, 'from dave $i');
    }
    expect(everyone.map((x) => x.svc.debugPqSends).toList(), pqid,
        reason: 'no pqid past the exchange');
    expect(everyone.map((x) => x.svc.debugPqSealSends).toList(), seal,
        reason: 'no pqseal past the exchange');
    await nothingRaised();

    // All four start again, each as it was, and talk: no pqid, no pqseal.
    alice = await restart(alice);
    bob = await restart(bob, before445: true);
    carol = await restart(carol, beforeSealingKeys: true);
    dave = await restart(dave, before445: true, before481: true);
    await connected([alice, bob, carol, dave]);
    for (var i = 0; i < 3; i++) {
      await say(alice, bob, 'again bob $i');
      await say(bob, alice, 'again alice $i');
      await say(alice, carol, 'again carol $i');
      await say(carol, alice, 'again from carol $i');
      await say(alice, dave, 'again dave $i');
      await say(dave, alice, 'again from dave $i');
    }
    for (final x in [alice, bob, carol, dave]) {
      expect(x.svc.debugPqSends, 0, reason: '${x.name} sent a pqid');
      expect(x.svc.debugPqSealSends, 0, reason: '${x.name} sent a pqseal');
    }
    await nothingRaised();
    expect(alice.svc.deviceLinkWith(bRid), DeviceLink.attested);
    expect(alice.svc.deviceLinkWith(dRid), DeviceLink.attested);
    expect(pqdcResendsEnabled, isFalse, reason: 'the re-send is held');
    await closeAll();
  });

  test(
      '8. the pqid once more is owed per contact device: one from before '
      '44.3 when the pqid reached it is sent it once updated, alone',
      () async {
    // Bob's phone opens the pair (the lower routing id) and Alice adds him
    // first, so the first `pqid` of the pair is his, carrying his `pqdc`,
    // and Alice's answer reaches his phone after it has shown it reads one.
    late ZIdentity aliceId, bobId;
    do {
      aliceId = await ZIdentity.generate();
      bobId = await ZIdentity.generate();
    } while ((await bobId.routingId()).compareTo(await aliceId.routingId()) >=
        0);
    var alice = await person('alice8', id: aliceId, resends: true);
    const delay = Duration(milliseconds: 1500);
    alice.svc.pqdcResendDelay = delay;
    final bob = await person('bob8', id: bobId);
    // His laptop runs a build from before 44.3: it keeps no `pqdc`.
    var laptop = await linkDirect(bob, 'laptop8', beforeSealingKeys: true);
    final phoneProbe = Probe()..attach(bob.svc);
    var laptopProbe = Probe()..attach(laptop.svc);
    final aRid = alice.svc.myRid, bRid = bob.svc.myRid;
    final lRid = laptop.svc.myRid;

    await connected([alice, bob, laptop]);
    await alice.svc.addContactFromCode(await bob.svc.myContactCode());
    await bob.svc.addContactFromCode(await alice.svc.myContactCode());
    await waitUntil(() => laptop.svc.contacts.containsKey(aRid),
        what: 'Alice mirrored to the laptop');
    await say(alice, bob, 'hi bob');
    await say(bob, alice, 'hi alice');
    // Alice answered his `pqid`, and offered hers again once his list named
    // the laptop (§18.2): both carried her `pqdc`, the second to the laptop
    // too, which runs a build that drops it.
    await waitUntil(
        () async =>
            await alice.svc.heldContactListVersion(bRid) >= 2 &&
            alice.svc.debugPqSends >= 2 &&
            !alice.svc.pqSendPending,
        what: "Alice's answer, and her pqid again for the laptop");
    expect(alice.svc.debugPqdcSentTo(bRid), isTrue,
        reason: "the phone had shown it reads one: its own pqid's pqdc");
    expect(alice.svc.debugPqdcSentTo(lRid), isFalse,
        reason: 'a device that has not shown it reads one does not spend it');
    // Everything she sent the laptop has reached it: a message behind it
    // arrives, and a mailbox takes what it is sent in order (§12.5, 6).
    await sendAndSee(alice, bRid, laptop, aRid, 'before the update');
    expect(laptop.svc.debugPqdcOf(aRid), isNull,
        reason: "the premise: the laptop holds none of Alice's");

    // And a `pqid` goes to the laptop while Alice holds a record of it —
    // she has announced her own key there, which its build drops — that
    // still says nothing of its reading one: a third device of Bob's, from
    // before 44.3 as well, makes her offer hers again (§18.2).
    var told = 0;
    await waitUntil(() async {
      final rec = SealRecord.decode(await alice.vault.kvGet('cseal_$bRid'));
      if ((rec.devices[lRid]?.announcedMs ?? 0) > 0) return true;
      await sendAndSee(laptop, aRid, alice, bRid, 'from the old laptop $told');
      await sendAndSee(alice, bRid, laptop, aRid, 'to the old laptop ${told++}');
      return false;
    }, what: "Alice's key announced to the laptop");
    final offered = alice.svc.debugPqSends;
    await linkDirect(bob, 'tablet8', beforeSealingKeys: true);
    await waitUntil(
        () async =>
            await alice.svc.heldContactListVersion(bRid) >= 3 &&
            alice.svc.debugPqSends > offered &&
            !alice.svc.pqSendPending,
        what: 'Alice offering her pqid again, to all three');
    await sendAndSee(alice, bRid, laptop, aRid, 'after the third device');
    expect(alice.svc.debugPqdcSentTo(lRid), isFalse,
        reason: 'held of it or not, a device that has not shown it reads one '
            'does not spend it');

    // The laptop is updated, and says so: its first `pqseal` to Alice, on
    // the next message it sends her once their session is post-quantum.
    laptop = await restart(laptop);
    laptopProbe = Probe()..attach(laptop.svc);
    await connected([laptop]);
    final phoneBefore = phoneProbe.count(aRid, 'pqid');
    final updated = DateTime.now();
    for (var i = 0; i < 12 && laptop.svc.debugPqdcOf(aRid) == null; i++) {
      await sendAndSee(laptop, aRid, alice, bRid, 'from the laptop $i');
      await sendAndSee(alice, bRid, laptop, aRid, 'to the laptop $i');
    }
    await waitUntil(() => laptop.svc.debugPqdcOf(aRid) != null,
        what: "the laptop holding Alice's pqdc");
    final toLaptop = [
      for (final s in laptopProbe.seen)
        if (s.from == aRid && s.kind == 'pqid') s
    ];
    expect(toLaptop, hasLength(1), reason: 'once: $toLaptop');
    expect(toLaptop.single.at.difference(updated),
        greaterThanOrEqualTo(delay),
        reason: 'on its clock, not at the update');
    expect(laptop.svc.debugPqdcOf(aRid), alice.svc.debugOwnPqdc);
    expect(alice.svc.debugPqdcSentTo(lRid), isTrue);
    expect(phoneProbe.count(aRid, 'pqid'), phoneBefore,
        reason: 'the phone, which kept the first, is sent none');

    // Never twice: Alice starts again, and past three times the delay
    // nothing more goes to either (a negative check over a window).
    alice = await restart(alice, resends: true);
    alice.svc.pqdcResendDelay = delay;
    await connected([alice]);
    final until = DateTime.now().add(delay * 3);
    while (DateTime.now().isBefore(until)) {
      await say(alice, bob, 'quiet ${DateTime.now().millisecondsSinceEpoch}');
    }
    expect(laptopProbe.count(aRid, 'pqid'), 1);
    expect(phoneProbe.count(aRid, 'pqid'), phoneBefore);
    expect(alice.svc.debugPqSends, 0, reason: 'no pqid from the restart');
    await closeAll();
  });

  testWidgets(
      '9. a device of the adversary in each code, relaying the genuine keys: '
      'one genuine number on both screens, and neither says post-quantum',
      (t) async {
    await t.binding.setSurfaceSize(const Size(800, 3000));
    addTearDown(() => t.binding.setSurfaceSize(null));
    late Person alice, bob, forBob, forAlice;
    final numbers = <String>[];
    await t.runAsync(() async {
      alice = await person('alice9');
      bob = await person('bob9');
      await waitUntil(() => alice.svc.debugOwnPqdc != null,
          what: "Alice's own pqdc, signed at her first start");
      // Standing in for Bob to Alice, and for Alice to Bob: devices of the
      // adversary's under each account's key, never on its list.
      forBob = await forgedDevice(bob, 'forbob9');
      forAlice = await forgedDevice(alice, 'foralice9');
      // The one standing in for Alice also relays her genuine `pqdc`, which
      // any `pqid` of hers carries: it is over her device, not this one.
      forAlice.svc.debugPqidAttestation = alice.svc.debugOwnPqdc;
      await pairUp(alice, forBob);
      await pairUp(bob, forAlice);
      // Each holds the other's genuine key and the sealing key the device in
      // between announced, and they compare the number: it matches.
      await talkUntil(
          alice,
          forBob,
          () =>
              alice.svc.debugPqSealOf(forBob.svc.myRid) != null &&
              forBob.svc.debugPqSealOf(alice.svc.myRid) != null,
          what: "the sealing keys across Alice's link");
      await talkUntil(
          bob,
          forAlice,
          () =>
              bob.svc.deviceLinkWith(forAlice.svc.myRid) == DeviceLink.refused,
          what: "Alice's own pqdc refused for the device standing in for her");
      numbers
        ..add(await alice.svc.safetyNumberWith(forBob.svc.myRid))
        ..add(await bob.svc.safetyNumberWith(forAlice.svc.myRid));
      await alice.svc.setVerified(forBob.svc.myRid, true);
      await bob.svc.setVerified(forAlice.svc.myRid, true);
    });
    final viaBob = forBob.svc.myRid, viaAlice = forAlice.svc.myRid;
    // The premise, which 4.8.1 shows as "post-quantum, verified" on both
    // screens: both identities hybrid on the genuine keys, and one number.
    for (final (x, rid) in [(alice, viaBob), (bob, viaAlice)]) {
      expect(x.svc.contacts[rid]!.assurance, IdentityAssurance.hybrid);
      expect(x.svc.contacts[rid]!.pqDisplay, PqDisplay.postQuantum);
      expect(x.svc.verificationWith(rid), VerificationState.verified);
    }
    expect(numbers[0], numbers[1], reason: 'one genuine number, compared');
    final bobAccount =
        await t.runAsync<AccountIdentity>(() => bob.svc.accountIdentity());
    expect(alice.svc.contacts[viaBob]!.accountEd, bobAccount!.accountEdPub,
        reason: "Alice's contact is Bob's account");
    expect(alice.svc.debugPqdcOf(viaBob), isNull,
        reason: 'the device standing in for Bob has no attestation to send');

    expect(alice.svc.deviceLinkWith(viaBob), DeviceLink.classical);
    expect(bob.svc.deviceLinkWith(viaAlice), DeviceLink.refused);
    expect(
        await t.runAsync(() =>
            systemLines(bob.svc, viaAlice, SystemKind.deviceLinkRefused)),
        1,
        reason: 'said once');
    await show(t, alice, viaBob, 'ci-device-link-classical');
    expect(find.text(l.ciPillDeviceLinkClassical), findsOneWidget);
    expect(find.text(l.ciDeviceLinkClassicalRequired), findsOneWidget);
    expect(find.text(l.ciPillPq), findsNothing,
        reason: 'not "post-quantum": nothing vouches for this device');
    expect(find.textContaining('This is the number you compared'),
        findsOneWidget);
    await leave(t);
    await show(t, bob, viaAlice, 'ci-device-link-refused');
    expect(find.byKey(const ValueKey('ci-device-link-refused-banner')),
        findsOneWidget);
    expect(find.text(l.ciPillDeviceLinkRefused), findsOneWidget);
    expect(find.text(l.ciPillPq), findsNothing);
    await leave(t);
    await t.runAsync(closeAll);
  });

  test(
      "10. a contact's device whose stored seed no longer reads draws a new "
      'key on the sessions it has: the pqdc held, of the old key, goes with '
      'it, nothing is refused, and its next pqdc links it again', () async {
    final alice = await person('alice10');
    var bob = await person('bob10');
    await pairUp(alice, bob);
    await linkedBothWays(alice, bob);
    final aRid = alice.svc.myRid, bRid = bob.svc.myRid;
    final oldKey = bob.svc.sealingKey!;
    final before =
        SealRecord.decode(await alice.vault.kvGet('cseal_$bRid')).devices[bRid]!;
    expect(before.pqdcBound, isTrue,
        reason: 'the premise: the pqdc and the key known to be of one state '
            'of his device, so the pqdc, were it kept beside a new key, '
            'would be set against it');

    // Bob's app stops, and the seed it stored is damaged: 12 bytes, not 64.
    // His device draws a new key at its next start, keeps its sessions, and
    // announces the new key on them ahead of its next message (4.8.1). The
    // `pqid` once more is on, as the seam has it, and not due for hours yet.
    bob = await restart(bob, resends: true, before: (v) async {
      await v.kvPut(sealSeedKey, b64(randomBytes(12)));
    });
    await connected([alice, bob]);
    final newKey = bob.svc.sealingKey!;
    expect(newKey, isNot(oldKey), reason: 'the premise: a new key drawn');
    expect(bob.svc.debugPqdcSentTo(aRid), isFalse,
        reason: 'his pqdc, over the new key, owed to Alice again');
    final sessions = alice.svc.debugConversation(bRid)!.sessions.length;
    await talkUntil(alice, bob, () {
      final k = alice.svc.debugPqSealOf(bRid);
      return k != null && constantTimeEquals(k, newKey);
    }, what: "Alice holding Bob's new key");
    expect(alice.svc.debugConversation(bRid)!.sessions.length, sessions,
        reason: 'the premise: the new key came on the session held, none new');
    expect(alice.svc.debugPqdcOf(bRid), isNull,
        reason: 'the pqdc of the old key went with it');
    expect(alice.svc.deviceLinkWith(bRid), DeviceLink.classical,
        reason: 'what was found was of the old key; nothing is yet of the new');
    // The judgement the new key calls for runs once the key is written: what
    // was found of the old one goes then.
    await waitUntil(
        () => alice.svc.contacts[bRid]!.deviceLinkVerdict == null,
        what: 'the finding of the old key cleared');
    expect(await alice.vault.kvGet('dlink_$bRid'), isNull);
    expect(await systemLines(alice.svc, bRid, SystemKind.deviceLinkRefused), 0,
        reason: 'a key changed on a session held is no evidence against the '
            'pqdc from before it');

    // The `pqid` once more, made due now, brings the pqdc over the new key.
    bob.svc.pqdcResendDelay = const Duration(milliseconds: 300);
    await talkUntil(alice, bob,
        () => alice.svc.deviceLinkWith(bRid) == DeviceLink.attested,
        what: "Bob's device linked again, over its new key");
    expect(alice.svc.debugPqdcOf(bRid), bob.svc.debugOwnPqdc);
    expect(alice.svc.contacts[bRid]!.deviceLinkVerdict!.sk,
        await sha256Bytes(newKey),
        reason: 'found of the new key');
    expect(await systemLines(alice.svc, bRid, SystemKind.deviceLinkRefused), 0);
    await closeAll();
  });

  /// Alice, on 4.8.1, adds Dave, whose device's `pqdc` verifies for no device
  /// of his, and compares the number; she updates to this build — telling it
  /// [refusedPill] — and nothing 4.8.1 held is refused. Then Dave's seed no
  /// longer reads: his device draws a new key and announces it to Alice, and
  /// its `pqid` once more (the re-send on, as the seam has it) carries another
  /// such `pqdc` — a key and a `pqdc` both new since the update, so refused.
  Future<(Person, Person)> earlierContactRefused(String tag,
      {required bool? refusedPill}) async {
    var alice = await person('alice$tag', before445: true);
    var dave = await person('dave$tag');
    Future<Uint8List> wrongPqdc() async => signDeviceAttestation(
        accountKey: (await dave.svc.pqIdentity())!,
        deviceEdPub: dave.id.edPub,
        deviceXPub: dave.id.xPub,
        sealEk: SealingKey.generate().ek);
    dave.svc.debugPqidAttestation = await wrongPqdc();
    await pairUp(alice, dave);
    final dRid = dave.svc.myRid;
    await talkUntil(
        alice,
        dave,
        () =>
            alice.svc.debugPqdcOf(dRid) != null &&
            alice.svc.debugPqSealOf(dRid) != null,
        what: "4.8.1 holding Dave's pqdc and sealing key, unjudged");
    await alice.svc.setVerified(dRid, true);
    alice = await restart(alice, refusedPill: refusedPill);
    await alice.svc.debugHeldLinksJudged;
    expect(alice.svc.contacts[dRid]!.linkRequired, isFalse,
        reason: 'the premise: added before 44.5');
    expect(alice.svc.deviceLinkWith(dRid), DeviceLink.classical,
        reason: 'nothing 4.8.1 held is refused');
    dave = await restart(dave, resends: true, before: (v) async {
      await v.kvPut(sealSeedKey, b64(randomBytes(12)));
    });
    dave.svc.debugPqidAttestation = await wrongPqdc();
    await connected([alice, dave]);
    dave.svc.pqdcResendDelay = const Duration(milliseconds: 300);
    await talkUntil(alice, dave,
        () => alice.svc.deviceLinkWith(dRid) == DeviceLink.refused,
        what: "Dave's device link refused");
    expect(alice.svc.debugPqSealOf(dRid), dave.svc.sealingKey,
        reason: 'the premise: judged against the key his device announced');
    expect(await systemLines(alice.svc, dRid, SystemKind.deviceLinkRefused), 1,
        reason: 'said once, in the chat');
    expect(alice.svc.verificationWith(dRid), VerificationState.verified,
        reason: 'the tick is about the number, which nothing moved');
    return (alice, dave);
  }

  testWidgets(
      '11. a contact added before 44.5 whose device link is then refused gets '
      'the banner and the line, its pill unchanged, as decision 3 reads '
      '(pillSaysRefusedForEarlierContacts false)', (t) async {
    await t.binding.setSurfaceSize(const Size(800, 3000));
    addTearDown(() => t.binding.setSurfaceSize(null));
    late Person alice, dave;
    await t.runAsync(() async {
      (alice, dave) = await earlierContactRefused('11', refusedPill: false);
    });
    final dRid = dave.svc.myRid;
    expect(alice.svc.deviceLinkForPill(dRid), isNull,
        reason: 'the pill answers to nothing of the link');
    await show(t, alice, dRid, 'ci-device-link-refused');
    expect(find.byKey(const ValueKey('ci-device-link-refused-banner')),
        findsOneWidget);
    expect(find.text(l.ciDeviceLinkRefused), findsOneWidget);
    expect(find.text(l.ciPillPq), findsOneWidget,
        reason: 'shown, not required: the pill it had');
    expect(find.text(l.ciPillDeviceLinkRefused), findsNothing);
    await leave(t);

    // And as built: the build's own answer, which no test passes here.
    await t.runAsync(() async {
      alice = await restart(alice);
    });
    await show(t, alice, dRid, 'ci-device-link-refused');
    expect(find.text(l.ciPillDeviceLinkRefused),
        pillSaysRefusedForEarlierContacts ? findsOneWidget : findsNothing);
    expect(find.text(l.ciPillPq),
        pillSaysRefusedForEarlierContacts ? findsNothing : findsOneWidget);
    await leave(t);
    await t.runAsync(closeAll);
  });

  testWidgets(
      '12. with the other answer (pillSaysRefusedForEarlierContacts true) the '
      'same refusal takes the pill too: "Link refused"', (t) async {
    await t.binding.setSurfaceSize(const Size(800, 3000));
    addTearDown(() => t.binding.setSurfaceSize(null));
    late Person alice, dave;
    await t.runAsync(() async {
      (alice, dave) = await earlierContactRefused('12', refusedPill: true);
    });
    final dRid = dave.svc.myRid;
    expect(alice.svc.deviceLinkForPill(dRid), DeviceLink.refused);
    await show(t, alice, dRid, 'ci-device-link-refused');
    expect(find.byKey(const ValueKey('ci-device-link-refused-banner')),
        findsOneWidget);
    expect(find.text(l.ciDeviceLinkRefused), findsOneWidget);
    expect(find.text(l.ciPillDeviceLinkRefused), findsOneWidget);
    expect(find.text(l.ciPillPq), findsNothing);
    await leave(t);
    await t.runAsync(closeAll);
  });

  test(
      '13. a pqdc over a key its device has not announced here yet, come since '
      'that device last opened a session, waits beside the old key and is '
      'kept when the new one lands, a session opened to it in between, which '
      'links it', () async {
    var alice = await person('alice13');
    var bob = await person('bob13');
    await pairUp(alice, bob);
    await linkedBothWays(alice, bob);
    final aRid = alice.svc.myRid, bRid = bob.svc.myRid;
    final oldKey = bob.svc.sealingKey!;

    // Bob's phone is lost and restored onto a new key (an archive without
    // its record); his device opens a new session to Alice, and her hello on
    // one of hers is answered with his `pqid`, as in criterion 4.
    final (file, code) = await backup(bob);
    bob = await lostAndRestored(bob, file, code, before: (v) async {
      await v.kvDelete(sealSeedKey);
      await v.kvDelete(ownPqdcKey);
    });
    await connected([alice, bob]);
    final newKey = bob.svc.sealingKey!;
    expect(newKey, isNot(oldKey), reason: 'the premise: a new sealing key');
    final newSk = await sha256Bytes(newKey);
    bob.svc.pqOfferRetry = 300;
    await say(bob, alice, 'back');
    await alice.svc.resetSecureSession(bRid);
    // Found of the new key: what was found of the old one stands until then.
    await talkUntil(alice, bob, () {
      final v = alice.svc.contacts[bRid]?.deviceLinkVerdict;
      return v?.finding == DeviceLinkFinding.attested &&
          constantTimeEquals(v!.sk, newSk);
    }, what: "Bob's restored device linked, the usual way round");
    expect(alice.svc.debugPqSealOf(bRid), newKey);
    final newPqdc = alice.svc.debugPqdcOf(bRid)!;

    // The other order, which a restored device's `pqid` takes when it goes
    // before its session is mixed — beside `pqct`, which a `pqseal` never
    // rides — is built here from what that leaves: Alice holding the key
    // from before, as it came on a session of his old device's, and his new
    // `pqdc`, come on the session his restored device opened, bound to no
    // key; and Bob's device yet to announce his key to her.
    final account = keyHash((await bob.svc.pqAccountPublic())!);
    alice = await restart(alice, before: (v) async {
      final rec = SealRecord.decode(await v.kvGet('cseal_$bRid'));
      final d = rec.devices[bRid]!
        ..ek = oldKey
        ..ekSid = 'a-session-of-his-old-device'
        ..pqdc = newPqdc
        ..pqdcSid = 'the-session-his-restore-opened'
        ..pqdcBound = false
        ..pqdcAfterKey = true
        ..pqdcAccount = account;
      expect(d.pqdcBound, isFalse);
      await v.kvPut('cseal_$bRid', rec.encode());
      await v.kvDelete('dlink_$bRid');
    });
    await alice.svc.debugHeldLinksJudged;
    expect(alice.svc.debugPqSealOf(bRid), oldKey);
    expect(alice.svc.debugPqdcOf(bRid), newPqdc);
    expect(alice.svc.deviceLinkWith(bRid), DeviceLink.classical,
        reason: 'the pqdc misses the key held, which came before: it waits');
    bob = await restart(bob, before: (v) async {
      final rec = SealRecord.decode(await v.kvGet('cseal_$aRid'));
      rec.devices[aRid]!
        ..holdsMine = false
        ..announcedMs = 0;
      await v.kvPut('cseal_$aRid', rec.encode());
    });
    bob.svc.pqOfferRetry = 300;
    await connected([alice, bob]);

    // Before his key lands, Alice opens a session to his device — a reset.
    // It sets aside the key held, and keeps the `pqdc` that came since his
    // own session: one this side opens says nothing of what he sent since
    // his. The `pqid` her hello earns from him is lost on its way, so what
    // links him is the `pqdc` she kept.
    final probe = Probe()..attach(alice.svc);
    probe.withhold = (s) => s.from == bRid && s.kind == 'pqid';
    await alice.svc.resetSecureSession(bRid);

    // His device announces its key on her session; Alice keeps the pqdc,
    // and it verifies over the key that lands.
    await talkUntil(alice, bob,
        () => alice.svc.deviceLinkWith(bRid) == DeviceLink.attested,
        what: "Bob's device linked by the pqdc that came before his key");
    expect(probe.count(bRid, 'pqid'), 0,
        reason: 'the premise: no pqid of his taken on the way');
    expect(alice.svc.debugPqSealOf(bRid), newKey);
    expect(alice.svc.debugPqdcOf(bRid), newPqdc,
        reason: 'the pqdc kept across the key and her session');
    expect(alice.svc.contacts[bRid]!.deviceLinkVerdict!.sk, newSk);
    expect(await systemLines(alice.svc, bRid, SystemKind.deviceLinkRefused), 0,
        reason: 'never refused on the way');
    await closeAll();
  });

  test(
      '14. this device resets the session, then the contact device finds its '
      'stored seed unreadable: its new key is not set against the pqdc of its '
      'old one, whether that came before the reset or on its session',
      () async {
    for (final online in [false, true]) {
      final tag = online ? 'on' : 'off';
      final alice = await person('alice14$tag');
      var bob = await person('bob14$tag');
      await pairUp(alice, bob);
      await linkedBothWays(alice, bob);
      final bRid = bob.svc.myRid;
      final oldKey = bob.svc.sealingKey!;
      final oldPqdc = alice.svc.debugPqdcOf(bRid)!;
      if (online) {
        // Bob is there for the reset — his app started since it last sent
        // Alice its `pqid`, which it volunteers once a run — and Alice's
        // hello on her new session earns that `pqid`, the `pqdc` of his old
        // key, on that session.
        bob = await restart(bob);
        await connected([alice, bob]);
        final probe = Probe()..attach(alice.svc);
        await alice.svc.resetSecureSession(bRid);
        await talkUntil(alice, bob, () => probe.count(bRid, 'pqid') > 0,
            what: "Bob's pqid on the session Alice opened");
        await stop(bob);
      } else {
        // Bob is away when Alice resets: her hello waits for him.
        await stop(bob);
        await alice.svc.resetSecureSession(bRid);
      }
      // Bob starts again, and the seed his device stored no longer reads: a
      // new key, announced on the session Alice opened. The `pqid` once more
      // is on, as the seam has it, and not due for hours yet.
      final vault = await Vault.open(rootOverride: bob.dir);
      await vault.kvPut(sealSeedKey, b64(randomBytes(12)));
      bob = await boot(bob.dir, bob.name, vault: vault, resends: true);
      await connected([alice, bob]);
      final newKey = bob.svc.sealingKey!;
      expect(newKey, isNot(oldKey), reason: 'the premise: a new key drawn');
      var refusedOnTheWay = false;
      await talkUntil(bob, alice, () {
        if (alice.svc.deviceLinkWith(bRid) == DeviceLink.refused) {
          refusedOnTheWay = true;
        }
        final k = alice.svc.debugPqSealOf(bRid);
        return k != null && constantTimeEquals(k, newKey);
      }, what: "[$tag] Alice holding Bob's new key");
      expect(refusedOnTheWay, isFalse, reason: '[$tag] never refused');
      final held = alice.svc.debugPqdcOf(bRid);
      expect(held == null || !constantTimeEquals(held, oldPqdc), isTrue,
          reason: '[$tag] the pqdc of the old key is not kept beside the new');
      expect(
          alice.svc.deviceLinkWith(bRid),
          isIn([DeviceLink.classical, DeviceLink.attested]),
          reason: '[$tag] classical until a pqdc over the new key comes — '
              'which his pqid answering the reset may already have brought');
      expect(await systemLines(alice.svc, bRid, SystemKind.deviceLinkRefused),
          0, reason: '[$tag] nothing said against his device');

      // The `pqid` once more, made due now, brings the pqdc over the new key.
      bob.svc.pqdcResendDelay = const Duration(milliseconds: 300);
      await talkUntil(alice, bob, () {
        if (alice.svc.deviceLinkWith(bRid) == DeviceLink.refused) {
          refusedOnTheWay = true;
        }
        return alice.svc.deviceLinkWith(bRid) == DeviceLink.attested;
      }, what: "[$tag] Bob's device linked again, over its new key");
      expect(refusedOnTheWay, isFalse);
      expect(alice.svc.contacts[bRid]!.deviceLinkVerdict!.sk,
          await sha256Bytes(newKey));
      expect(await systemLines(alice.svc, bRid, SystemKind.deviceLinkRefused),
          0);
      await closeAll();
    }
  });

  /// What [alice] holds of the link to [bRid]'s device, for a failure's
  /// reason.
  Future<String> linkState(Person alice, String bRid) async {
    final d = SealRecord.decode(await alice.vault.kvGet('cseal_$bRid'))
        .devices[bRid];
    return 'link=${alice.svc.deviceLinkWith(bRid)} '
        'pqdc=${d?.pqdc != null} bound=${d?.pqdcBound} '
        'account=${d?.pqdcAccount == null ? '-' : b64(d!.pqdcAccount!).substring(0, 6)}';
  }

  testWidgets(
      '15. a contact restored from a .zid backup, onto a new post-quantum '
      'account key, is never refused: the screen says their key changed, and '
      'deleting and adding them again from their code links them', (t) async {
    await t.binding.setSurfaceSize(const Size(800, 3000));
    addTearDown(() => t.binding.setSurfaceSize(null));
    late Person alice, bob;
    late String aRid, bRid;
    var refusedOnTheWay = false;
    bool notRefused() {
      if (alice.svc.deviceLinkWith(bRid) == DeviceLink.refused) {
        refusedOnTheWay = true;
      }
      return true;
    }

    await t.runAsync(() async {
      alice = await person('alice15');
      bob = await person('bob15');
      await pairUp(alice, bob);
      await linkedBothWays(alice, bob);
      aRid = alice.svc.myRid;
      bRid = bob.svc.myRid;
      await alice.svc.setVerified(bRid, true);
      final oldAccount = (await bob.svc.pqAccountPublic())!;
      // Bob's phone is lost; he restores the identity backup an app before
      // 2.0.1 made, which carries no post-quantum seed and no sealing key.
      final bytes = await BackupFile.export(
        identity: bob.id,
        displayName: 'bob15',
        contactRecords: [
          {
            'bundle': bob.svc.contacts[aRid]!.bundle.toJson(),
            'name': 'alice15',
            'verified': true,
          }
        ],
        passphrase: 'correct horse battery staple',
      );
      final file = File(p.join((await tempDir('zid15')).path, 'b.zid'))
        ..writeAsBytesSync(bytes);
      await stop(bob);
      bob.dir.deleteSync(recursive: true);
      bob.dir.createSync(recursive: true);
      final vault = await Vault.open(rootOverride: bob.dir);
      await Restore.run(
        vault: vault,
        file: file,
        secret: 'correct horse battery staple',
        kind: (await Restore.identify(file)).kind,
        serverUrl: relayUrl(),
      );
      bob = await boot(bob.dir, bob.name, vault: vault);
      await connected([alice, bob]);
      bob.svc.pqOfferRetry = 300;
      final newAccount = (await bob.svc.pqAccountPublic())!;
      expect(constantTimeEquals(newAccount, oldAccount), isFalse,
          reason: 'the premise: a new post-quantum account key');
      try {
        await talkUntil(bob, alice,
            () => notRefused() &&
                alice.svc.deviceLinkWith(bRid) == DeviceLink.keyChanged,
            what: 'the key change said');
      } on TimeoutException {
        fail(await linkState(alice, bRid));
      }
      // A reset — what USING_Z says to do for a link that reads classical —
      // brings his `pqid` again, and changes nothing.
      await alice.svc.resetSecureSession(bRid);
      for (var i = 0; i < 3; i++) {
        await say(alice, bob, 'after the reset $i');
        await say(bob, alice, 'back $i');
        notRefused();
      }
    });
    expect(refusedOnTheWay, isFalse, reason: 'never refused');
    expect(alice.svc.deviceLinkWith(bRid), DeviceLink.keyChanged);
    expect(alice.svc.deviceLinkForPill(bRid), DeviceLink.keyChanged);
    expect(
        await t.runAsync(() =>
            systemLines(alice.svc, bRid, SystemKind.deviceLinkRefused)),
        0);
    expect(alice.svc.verificationWith(bRid), VerificationState.verified,
        reason: 'the number is of the key held, which nothing moved');
    await show(t, alice, bRid, 'ci-device-link-key-changed');
    expect(find.byKey(const ValueKey('ci-pq-key-changed-banner')),
        findsOneWidget);
    expect(find.text(l.ciPqKeyChangedTitle), findsOneWidget);
    expect(find.text(l.ciDeviceLinkKeyChanged), findsOneWidget);
    expect(find.text(l.ciPillDeviceLinkClassical), findsOneWidget);
    expect(find.text(l.ciPillPq), findsNothing);
    expect(find.byKey(const ValueKey('ci-device-link-refused-banner')),
        findsNothing);
    expect(find.textContaining('refused'), findsNothing,
        reason: 'nothing on the screen says refused');
    await leave(t);

    // As the banner says: deleted and added again from his code, which
    // commits to his new key, and his device is linked post-quantum.
    await t.runAsync(() async {
      await alice.svc.deleteContact(bRid);
      await alice.svc.addContactFromCode(await bob.svc.myContactCode());
      await talkUntil(alice, bob,
          () => alice.svc.deviceLinkWith(bRid) == DeviceLink.attested,
          what: 'linked again, over his new account key');
    });
    expect(alice.svc.contacts[bRid]!.pqPub,
        await t.runAsync(() => bob.svc.pqAccountPublic()));
    await t.runAsync(closeAll);
  });

  test(
      '16. a contact restored from an archive made before 2.2.4 — no '
      'post-quantum seed in it — is never refused, and once its pqid comes the '
      'screen says their key changed', () async {
    final alice = await person('alice16');
    var bob = await person('bob16');
    await pairUp(alice, bob);
    await linkedBothWays(alice, bob);
    final bRid = bob.svc.myRid;
    await alice.svc.setVerified(bRid, true);
    final (file, code) = await backup(bob);
    bob = await lostAndRestored(bob, file, code, before: (v) async {
      // What an archive from before 2.2.4 lacks: the account's post-quantum
      // seed, and — as every one from before 4.7.0 — the sealing key.
      await v.kvDelete('pq_seed');
      await v.kvDelete(sealSeedKey);
      await v.kvDelete(ownPqdcKey);
    });
    await connected([alice, bob]);
    bob.svc.pqOfferRetry = 300;
    var refusedOnTheWay = false;
    bool notRefused() {
      if (alice.svc.deviceLinkWith(bRid) == DeviceLink.refused) {
        refusedOnTheWay = true;
      }
      return true;
    }

    final newKey = bob.svc.sealingKey!;
    await talkUntil(bob, alice, () {
      notRefused();
      final k = alice.svc.debugPqSealOf(bRid);
      return k != null && constantTimeEquals(k, newKey);
    }, what: "Alice holding Bob's new sealing key");
    // His restored device holds Alice's key already, so it sends no `pqid`
    // of its own accord; Alice's reset earns one.
    await alice.svc.resetSecureSession(bRid);
    try {
      await talkUntil(alice, bob,
          () => notRefused() &&
              alice.svc.deviceLinkWith(bRid) == DeviceLink.keyChanged,
          what: 'the key change said');
    } on TimeoutException {
      fail(await linkState(alice, bRid));
    }
    expect(refusedOnTheWay, isFalse, reason: 'never refused');
    expect(await systemLines(alice.svc, bRid, SystemKind.deviceLinkRefused), 0);
    expect(alice.svc.verificationWith(bRid), VerificationState.verified);
    await closeAll();
  });

  test(
      '17. a contact deleted and added back is linked again with no six-hour '
      'wait, on the shipped clock — both ways', () async {
    final alice = await person('alice17');
    final bob = await person('bob17');
    await pairUp(alice, bob);
    await linkedBothWays(alice, bob);
    final aRid = alice.svc.myRid, bRid = bob.svc.myRid;
    expect(alice.svc.pqOfferRetry, pqOfferRetryMs);
    expect(bob.svc.pqOfferRetry, pqOfferRetryMs,
        reason: 'the premise: the shipped clock, six hours between '
            'announcements');

    // Alice deletes Bob and adds him again from his code: her new record
    // holds nothing of his device, and his device last announced its key to
    // her a moment ago.
    await alice.svc.deleteContact(bRid);
    await alice.svc.addContactFromCode(await bob.svc.myContactCode());
    try {
      await talkUntil(alice, bob,
          () => alice.svc.deviceLinkWith(bRid) == DeviceLink.attested,
          what: 'Alice linking Bob again', rounds: 6);
    } on TimeoutException {
      fail('Alice of Bob: ${await linkState(alice, bRid)} '
          'key=${alice.svc.debugPqSealOf(bRid) != null}');
    }

    // And Bob deletes Alice and adds her again.
    await bob.svc.deleteContact(aRid);
    await bob.svc.addContactFromCode(await alice.svc.myContactCode());
    try {
      await talkUntil(bob, alice,
          () => bob.svc.deviceLinkWith(aRid) == DeviceLink.attested,
          what: 'Bob linking Alice again', rounds: 6);
    } on TimeoutException {
      fail('Bob of Alice: ${await linkState(bob, aRid)} '
          'key=${bob.svc.debugPqSealOf(aRid) != null}');
    }
    expect(alice.svc.deviceLinkWith(bRid), DeviceLink.attested);
    await closeAll();
  });

  test(
      "18. a finding of the key their device held before is not said of the "
      'key it holds now, and the next start judges it again', () async {
    var alice = await person('alice18');
    final bob = await person('bob18');
    await pairUp(alice, bob);
    await linkedBothWays(alice, bob);
    final bRid = bob.svc.myRid;
    final found = alice.svc.contacts[bRid]!.deviceLinkVerdict!;
    expect(found.finding, DeviceLinkFinding.attested);

    // What a stop between the door's writing a new key and its judgement
    // leaves: the record holding the key his device announced since — its
    // seed no longer read — and the finding still the one of the old key.
    final fresh = SealingKey.generate().ek;
    alice = await restart(alice, before: (v) async {
      final rec = SealRecord.decode(await v.kvGet('cseal_$bRid'));
      rec.devices[bRid]!
        ..ek = fresh
        ..pqdc = null
        ..pqdcBound = false;
      await v.kvPut('cseal_$bRid', rec.encode());
      expect(await v.kvGet('dlink_$bRid'), isNotNull,
          reason: 'the premise: the finding of the old key kept');
    });
    expect(alice.svc.deviceLinkWith(bRid), DeviceLink.classical,
        reason: 'not post-quantum: nothing has attested the key held');
    expect(alice.svc.deviceLinkForPill(bRid), DeviceLink.classical);
    await alice.svc.debugHeldLinksJudged;
    expect(alice.svc.contacts[bRid]!.deviceLinkVerdict, isNull,
        reason: 'judged again at the start: the finding of the old key gone');
    expect(await alice.vault.kvGet('dlink_$bRid'), isNull);
    await closeAll();
  });

  test(
      '19. the relay loses the announcement of the new key a contact device '
      'drew on the sessions it has: its pqdc over that key, read past the gap, '
      'is not set against the old key, and a reset links it again', () async {
    var alice = await person('alice19');
    var bob = await person('bob19');
    await pairUp(alice, bob);
    await linkedBothWays(alice, bob);
    final bRid = bob.svc.myRid;
    final oldKey = bob.svc.sealingKey!;

    // Where Alice stands with a device whose `pqdc` has not reached her — one
    // whose app was older than 4.7 when she added them, say, and updated
    // since: its key held, from the session it came on, and nothing found.
    alice = await restart(alice, before: (v) async {
      final rec = SealRecord.decode(await v.kvGet('cseal_$bRid'));
      final d = rec.devices[bRid]!;
      expect(d.ekSid, isNotNull,
          reason: 'the premise: the session his key came on is held');
      d
        ..pqdc = null
        ..pqdcSid = null
        ..pqdcBound = false
        ..pqdcAfterKey = false
        ..pqdcAccount = null;
      await v.kvPut('cseal_$bRid', rec.encode());
      await v.kvDelete('dlink_$bRid');
    });
    await connected([alice, bob]);
    expect(alice.svc.deviceLinkWith(bRid), DeviceLink.classical);

    // Bob's app stops, and the seed it stored is damaged: his device draws a
    // new key at its next start and announces it on the session it has,
    // ahead of its next message there — and the relay loses that
    // announcement, Alice's probe dropping it unread. The `pqid` once more is
    // on, as the seam has it, and not due for hours yet.
    var lost = 0;
    alice.svc.debugOnDecrypted = (path, from, dec) {
      if (path != 'primary' || from != bRid || lost > 0) return false;
      final Uint8List? announced;
      try {
        announced = InnerMessage.fromBytes(dec.plaintext).pqSealKey;
      } catch (_) {
        return false;
      }
      if (announced == null || constantTimeEquals(announced, oldKey)) {
        return false;
      }
      lost++;
      return true;
    };
    bob = await restart(bob, resends: true, before: (v) async {
      await v.kvPut(sealSeedKey, b64(randomBytes(12)));
    });
    await connected([alice, bob]);
    final newKey = bob.svc.sealingKey!;
    expect(newKey, isNot(oldKey), reason: 'the premise: a new key drawn');
    await talkUntil(bob, alice, () => lost == 1,
        what: "Bob's announcement of his new key lost");

    // The `pqid` once more, made due now, brings the pqdc over the new key on
    // that session, past the gap the lost announcement left.
    bob.svc.pqdcResendDelay = const Duration(milliseconds: 300);
    final newPqdc = bob.svc.debugOwnPqdc!;
    Future<bool> pqdcWritten() async {
      final d = SealRecord.decode(await alice.vault.kvGet('cseal_$bRid'))
          .devices[bRid];
      return d?.pqdc != null && constantTimeEquals(d!.pqdc!, newPqdc);
    }

    await talkUntil(alice, bob, pqdcWritten,
        what: "Alice's vault holding Bob's pqdc over his new key");
    expect(constantTimeEquals(alice.svc.debugPqSealOf(bRid)!, oldKey), isTrue,
        reason: 'the premise: his announcement lost, the old key still held');
    // Judged by the door that took it, or — this — at the next start, which
    // judges every contact holding a key and a pqdc and no finding.
    alice = await restart(alice);
    await alice.svc.debugHeldLinksJudged;
    expect(alice.svc.deviceLinkWith(bRid), DeviceLink.classical,
        reason: 'a pqdc read past a gap is no evidence against the key '
            'held: ${await linkState(alice, bRid)}');
    expect(alice.svc.contacts[bRid]!.deviceLinkVerdict, isNull);
    expect(await systemLines(alice.svc, bRid, SystemKind.deviceLinkRefused), 0,
        reason: 'nothing said against his device');

    // Alice resets the session. His device, which had taken her word for
    // holding its key, announces the new one again on her new session at
    // once (4.9.0), and the pqdc kept beside the old key links it.
    await connected([alice, bob]);
    await alice.svc.resetSecureSession(bRid);
    var refusedOnTheWay = false;
    await talkUntil(alice, bob, () {
      if (alice.svc.deviceLinkWith(bRid) == DeviceLink.refused) {
        refusedOnTheWay = true;
      }
      return alice.svc.deviceLinkWith(bRid) == DeviceLink.attested;
    }, what: "Bob's device linked again, over its new key");
    expect(refusedOnTheWay, isFalse);
    expect(constantTimeEquals(alice.svc.debugPqSealOf(bRid)!, newKey), isTrue);
    expect(alice.svc.contacts[bRid]!.deviceLinkVerdict!.sk,
        await sha256Bytes(newKey));
    expect(await systemLines(alice.svc, bRid, SystemKind.deviceLinkRefused), 0);
    await closeAll();
  });

  test(
      "20. a one-device account's code with its X25519 key substituted, its "
      'Ed25519 key and commitment kept, is refused for the genuine pqdc',
      () async {
    // Bob's device, the root of an account with no other device: its own
    // pqdc, over its two keys and its sealing key, signed at its first start.
    final bob = await person('bob20');
    await waitUntil(
        () => bob.svc.debugOwnPqdc != null && bob.svc.debugSealingKey != null,
        what: "Bob's root signing its own pqdc");
    final bRid = bob.svc.myRid;
    final genuine = Uint8List.fromList(bob.svc.debugOwnPqdc!);
    final bobEk = Uint8List.fromList(bob.svc.debugSealingKey!);
    final bobMl = (await bob.svc.pqAccountPublic())!;
    expect(
        deviceAttestationValid(
            accountMlPub: bobMl,
            accountEdPub: bob.id.edPub,
            deviceEdPub: bob.id.edPub,
            deviceXPub: bob.id.xPub,
            sealEk: bobEk,
            pqdc: genuine),
        isTrue,
        reason: "the premise: Bob's genuine pqdc, for the keys his device "
            'holds');
    final pqSeed = (await bob.vault.kvGet('pq_seed'))!;
    final sealSeed = (await bob.vault.kvGet(sealSeedKey))!;
    final edSeed = Uint8List.fromList(bob.id.edSeed);
    await stop(bob);

    // The substitute: Bob's Ed25519 key, which the adversary can forge, and
    // an X25519 key of its own, relaying Bob's ML-DSA key, his sealing key
    // and his genuine pqdc. Its code is Bob's with the X25519 key replaced:
    // the same routing id, the same signed commitment, the same number.
    final subId = await ZIdentity.fromSeeds(
        edSeed: edSeed, xSeed: (await ZIdentity.generate()).xSeed);
    final dir = await tempDir('bob20x');
    final vault = await Vault.open(rootOverride: dir);
    await vault.kvPut('identity', jsonEncode(subId.toJson()));
    await vault.kvPut('display_name', 'bob20');
    await vault.kvPut('pq_seed', pqSeed);
    await vault.kvPut(sealSeedKey, sealSeed);
    final sub = await boot(dir, 'bob20', vault: vault);
    sub.svc.debugPqidAttestation = genuine;
    expect(sub.svc.myRid, bRid, reason: "the premise: Bob's routing id");
    expect(constantTimeEquals(sub.id.xPub, bob.id.xPub), isFalse,
        reason: 'the premise: another X25519 key');

    final alice = await person('alice20');
    await pairUp(alice, sub);
    final c = alice.svc.contacts[bRid]!;
    expect(c.accountEdPub, isNull,
        reason: "the premise: a root's code names no account");
    expect(constantTimeEquals(c.bundle.xPub, sub.id.xPub), isTrue,
        reason: 'the premise: Alice holds the substituted key');
    await talkUntil(alice, sub,
        () => alice.svc.deviceLinkWith(bRid) == DeviceLink.refused,
        what: 'the substituted device refused');
    expect(constantTimeEquals(alice.svc.contacts[bRid]!.pqPub!, bobMl), isTrue,
        reason: "Bob's key established, against his commitment");
    expect(constantTimeEquals(alice.svc.debugPqdcOf(bRid)!, genuine), isTrue,
        reason: 'his genuine pqdc held');
    expect(constantTimeEquals(alice.svc.debugPqSealOf(bRid)!, bobEk), isTrue,
        reason: 'beside his own sealing key');
    expect(await systemLines(alice.svc, bRid, SystemKind.deviceLinkRefused), 1,
        reason: 'said once, in the chat');
    final kept =
        DeviceLinkVerdict.decode(await alice.vault.kvGet('dlink_$bRid'));
    expect(kept?.finding, DeviceLinkFinding.refused, reason: 'and recorded');
    // And after Alice's app starts again.
    final again = await restart(alice);
    expect(again.svc.deviceLinkWith(bRid), DeviceLink.refused);
    expect(await systemLines(again.svc, bRid, SystemKind.deviceLinkRefused), 1);
    await closeAll();
  });
}
