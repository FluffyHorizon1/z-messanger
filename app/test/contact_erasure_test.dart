// Deleting a contact left them in the vault.
//
// `DATA_MAP.md`'s erasure table says of "a contact and its history":
// "Delete contact — nothing locally." `deleteContact` removed the tables —
// files, blobs, chunks, messages, delivery, outbox, conversations, contacts
// — and not one `kv` family. So `z.db` kept, keyed by the routing id that
// says whose it is and unsealed wherever the family is declared plain: the
// contact's account key and every device's public keys with the list's
// version and signature (`cdev_`), the post-quantum material (`cdev_pq_`),
// the ratchet with their linked devices (`cextra_`), the alerts, the claims,
// what the transparency log said about them (`ktc_`), and when the
// conversation was last opened — for the life of the install (the
// 2026-09-14 review's finding 8). And one of those rows bit: a contact added
// back met their own stale `cdev_ver_`, and every device list below it was
// refused as a replay.
//
// The fix is a list in one place — `ChatService.contactKvFamilies` — that
// `deleteContact` walks. A list kept by hand is how this happened, so the
// list is checked against the source here: every `kvPut` in `lib/` whose key
// is a family plus a routing id must name a family on it, and every family
// on it must be written somewhere.
//
// Everything below runs offline, carrying envelopes by hand.
//
// Criteria, each a test below:
//   1. after `deleteContact`, no row in any table and no `kv` key names the
//      contact's routing id or any of their devices' routing ids — the
//      whole vault, not a list of tables;
//   2. the family list matches the source, both ways;
//   3. a contact added back starts from nothing: a device list at a version
//      below the one held before the deletion is accepted, where the stale
//      `cdev_ver_` used to refuse it;
//   4. a send that is already in flight when the contact is deleted does not
//      commit into the sweep — the deletion waits for it and removes what it
//      wrote, rather than interleaving with it;
//   5. a send that was queued BEHIND the deletion writes nothing at all: no
//      outbox row, no conversation, nothing to their laptop.
//
// 4 and 5 are the two halves of one rule — a deleted contact is final — and
// they are what `retry: 2` on criterion 1 used to paper over. The leftovers
// varied run to run because the interleaving did: a send committing between
// the `outbox` sweep and the `conversations` one leaves a different set than
// one committing after both. Both are forced here rather than waited for.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:z_protocol/z_protocol.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  final temps = <Directory>[];
  final services = <ChatService>[];

  tearDownAll(() async {
    for (final s in services) {
      await s.transport.stop();
    }
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<ChatService> makeClient(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_erase_$name');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    final identity = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(identity.toJson()));
    final svc = await ChatService.init(
      vault: vault,
      identity: identity,
      displayName: name,
      transport: Transport(identity: identity, serverUrl: 'ws://127.0.0.1:1'),
    );
    services.add(svc);
    return svc;
  }

  Future<int> carry(ChatService from, ChatService to) async {
    final rows = await from.vault.db.query('outbox',
        where: 'rid = ?', whereArgs: [to.myRid], orderBy: 'seq');
    await from.vault.db
        .delete('outbox', where: 'rid = ?', whereArgs: [to.myRid]);
    for (final r in rows) {
      await to.debugInbound(RelayInbound(
          id: r['id'] as String,
          from: '',
          payload: r['payload'] as String,
          serverTs: DateTime.now().millisecondsSinceEpoch));
    }
    return rows.length;
  }

  Future<void> settle(ChatService x, ChatService y) async {
    for (var i = 0; i < 6; i++) {
      if (await carry(x, y) + await carry(y, x) == 0) return;
    }
  }

  /// Every value in every row of every user table that contains [needle],
  /// as `table.column`, plus every `kv` key that contains it.
  Future<List<String>> mentions(Vault v, String needle) async {
    final out = <String>[];
    final tables = (await v.db.rawQuery(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"))
        .map((r) => r['name'] as String);
    for (final t in tables) {
      for (final row in await v.db.query(t)) {
        for (final e in row.entries) {
          final val = e.value;
          if (val is String && val.contains(needle)) out.add('$t.${e.key}');
        }
      }
    }
    return out;
  }

  /// a knows b, b has a laptop a has been told about, they have talked,
  /// reacted and set a timer. Returns (a, b, laptopRid).
  Future<(ChatService, ChatService, String)> acquainted() async {
    final a = await makeClient('a');
    final b = await makeClient('b');
    await a.addContactFromCode(await b.myContactCode());
    await b.addContactFromCode(await a.myContactCode());
    await settle(a, b);
    await a.sendText(b.myRid, 'hello');
    await settle(a, b);
    await b.sendText(a.myRid, 'hello back');
    await settle(a, b);
    final ltId = await ZIdentity.generate();
    final account = await b.accountIdentity();
    final cert = await account.signDeviceCert(
        deviceEdPub: ltId.edPub, deviceXPub: ltId.xPub, deviceId: 'lt');
    await b.addMyDevice(cert);
    await settle(b, a);
    final mid = a.messagesByChat[b.myRid]!.last.mid;
    await a.toggleReaction(b.myRid, mid, '👍');
    await a.setDisappearingTimer(b.myRid, 60);
    await settle(a, b);
    await a.markChatOpened(b.myRid);
    a.markChatClosed(b.myRid);
    return (a, b, await ltId.routingId());
  }

  test('1. after deleting a contact, nothing in the vault names them', () async {
    final (a, b, laptopRid) = await acquainted();
    // The state the deletion has to remove is really there first.
    expect(await a.vault.kvGet('cdev_${b.myRid}'), isNotNull, reason: 'their device list');
    expect(await a.vault.kvGet('cdev_ver_${b.myRid}'), isNotNull);
    expect(await a.vault.kvGet('cextra_${b.myRid}'), isNotNull, reason: 'the ratchet with their laptop');
    expect(await a.vault.kvGet('last_open_${b.myRid}'), isNotNull);
    expect((await mentions(a.vault, b.myRid)).length, greaterThan(3),
        reason: 'the routing id is all over the vault before the deletion');
    expect(await mentions(a.vault, laptopRid), isNotEmpty, reason: 'and so is the laptop');

    await a.deleteContact(b.myRid);

    expect(await mentions(a.vault, b.myRid), isEmpty,
        reason: 'no table row and no kv key names the contact');
    expect(await mentions(a.vault, laptopRid), isEmpty,
        reason: 'nor their laptop');
    expect(a.contacts.containsKey(b.myRid), isFalse);
    expect(a.messagesByChat.containsKey(b.myRid), isFalse);
    // The other contact-shaped things this process holds are gone too, so a
    // message that arrives from them now is a stranger's, as it should be.
    expect(a.deviceAssuranceWith(b.myRid), DeviceAssurance.classical,
        reason: 'no assurance is remembered for a stranger');
    // No `retry:` here any more. It was added when this failed only under a
    // loaded suite and passed alone, which reads like flakiness; the release
    // build of 3.9.0 then failed it three attempts running, and the leftovers
    // named the cause — an in-flight send committing into the sweep. That is
    // criterion 4 below, forced rather than raced, so this one can go back to
    // being the plain statement it looks like.
  });

  test('2. the family list matches the source, both ways', () async {
    // Every `kvPut('<family>$rid'` / `'<family>${x.rid}'` in lib/, where the
    // key is a per-contact family. `cextra_` is written through `_saveExtra`
    // with the same shape. A family written and not listed is a row the
    // deletion misses; a family listed and never written is a line nobody
    // will keep true.
    final written = <String>{};
    final pat = RegExp(r"""kvPut\(\s*'([a-z_]+_)\$(?:\{[a-zA-Z_.!]*rid\}|rid)'""");
    for (final f in Directory('lib').listSync(recursive: true).whereType<File>()) {
      if (!f.path.endsWith('.dart')) continue;
      for (final m in pat.allMatches(f.readAsStringSync())) {
        written.add(m.group(1)!);
      }
    }
    expect(written, isNotEmpty, reason: 'the scan found the writers');
    final listed = ChatService.contactKvFamilies.toSet();
    expect(written.difference(listed), isEmpty,
        reason: 'per-contact families written in lib/ that deleteContact does not remove');
    expect(listed.difference(written), isEmpty,
        reason: 'families listed that nothing writes');
    // And every one of them is a declared plain family or sealed by
    // default: a family the vault would refuse to write is not one.
    for (final fam in listed) {
      expect(fam.endsWith('_'), isTrue, reason: '$fam is a prefix');
    }
  });

  test('3. a contact added back starts from nothing', () async {
    final (a, b, _) = await acquainted();
    // What the review found: the stale version guard. Make the held version
    // higher than anything b will send again, as a reset account or a long
    // history would; with the row surviving the deletion, b's list is
    // refused as a replay for ever after.
    await a.vault.kvPut('cdev_ver_${b.myRid}', '99', sensitive: false);
    await a.deleteContact(b.myRid);
    expect(await a.vault.kvGet('cdev_ver_${b.myRid}'), isNull);

    await a.addContactFromCode(await b.myContactCode());
    await settle(a, b);
    await a.sendText(b.myRid, 'again');
    await settle(a, b);
    await b.sendText(a.myRid, 'again back');
    await settle(b, a);
    // b's list reaches a with the linking of a second laptop, at a version
    // far below 99.
    final ltId = await ZIdentity.generate();
    final account = await b.accountIdentity();
    final cert = await account.signDeviceCert(
        deviceEdPub: ltId.edPub, deviceXPub: ltId.xPub, deviceId: 'lt2');
    await b.addMyDevice(cert);
    await settle(b, a);
    final held = await a.vault.kvGet('cdev_${b.myRid}');
    expect(held, isNotNull, reason: 'the list was installed');
    final version = (jsonDecode(held!) as Map)['ver'] as int;
    expect(version, lessThan(99), reason: 'accepted at its own version, not refused against a ghost');
    expect(a.messagesByChat[b.myRid]!.map((m) => m.body), contains('again back'));
  });

  test('4. a send in flight when the contact is deleted is swept with them',
      () async {
    final (a, b, laptopRid) = await acquainted();
    // Hold a send where a loaded machine held it: sealed, inside the send
    // lock, one step from its transaction. Without the deletion taking that
    // lock, its writes land in the middle of the sweep.
    final atCommit = Completer<void>();
    final release = Completer<void>();
    a.debugBeforeSendCommit = (rid) async {
      if (rid != b.myRid) return;
      a.debugBeforeSendCommit = null; // once; the fan-out send is not the test
      if (!atCommit.isCompleted) atCommit.complete();
      await release.future;
    };
    final inFlight = a.sendText(b.myRid, 'mid-flight when they were deleted');
    await atCommit.future;

    final deletion = a.deleteContact(b.myRid);
    // The deletion must be waiting on the lock this send holds, not running
    // through it: give it every chance to interleave if it can.
    await Future<void>.delayed(const Duration(milliseconds: 50));
    var deletionDone = false;
    unawaited(deletion.then((_) => deletionDone = true));
    await Future<void>.delayed(const Duration(milliseconds: 50));
    expect(deletionDone, isFalse,
        reason: 'the deletion waits for the send that holds the lock');

    release.complete();
    await inFlight;
    await deletion;
    // The fan-out to their laptop rides unawaited off the same send.
    await Future<void>.delayed(const Duration(milliseconds: 200));

    expect(await mentions(a.vault, b.myRid), isEmpty,
        reason: 'the envelope the send wrote was swept with the contact');
    expect(await mentions(a.vault, laptopRid), isEmpty,
        reason: 'and so was the copy addressed to their laptop');
  });

  test('5. a send queued behind the deletion writes nothing', () async {
    final (a, b, laptopRid) = await acquainted();
    // Hold the FIRST send inside the lock, start the deletion behind it, then
    // start a second send behind that. When the lock reaches the second send
    // the contact is gone: it must write nothing rather than recreate them.
    final atCommit = Completer<void>();
    final release = Completer<void>();
    a.debugBeforeSendCommit = (rid) async {
      if (rid != b.myRid) return;
      a.debugBeforeSendCommit = null;
      if (!atCommit.isCompleted) atCommit.complete();
      await release.future;
    };
    final first = a.sendText(b.myRid, 'first');
    await atCommit.future;
    final deletion = a.deleteContact(b.myRid);
    final queued = a.sendText(b.myRid, 'queued behind the deletion');
    release.complete();
    await first;
    await deletion;
    await queued; // completes; it simply has nowhere to go
    await Future<void>.delayed(const Duration(milliseconds: 200));

    expect(await mentions(a.vault, b.myRid), isEmpty,
        reason: 'a send after the deletion does not bring the contact back');
    expect(await mentions(a.vault, laptopRid), isEmpty);
    expect((await a.vault.db.query('outbox')), isEmpty,
        reason: 'nothing was queued for anyone');
    expect((await a.vault.db.query('conversations')), isEmpty,
        reason: 'and no conversation was recreated');
    expect(a.messagesByChat.containsKey(b.myRid), isFalse,
        reason: 'nor a thread put back on the home screen');
  });
}
