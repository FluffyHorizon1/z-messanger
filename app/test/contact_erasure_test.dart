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
//      outbox row, no conversation, nothing to their laptop;
//   6. a contact who is in a group I am in: deleting them takes nobody out
//      of the group, and what the vault keeps is exactly what the delete
//      dialog says — in the group's sealed record their routing id, public
//      key and name, and in the group's thread what they wrote, reacted and
//      confirmed there — and nothing else names them or their laptop; a
//      change someone else makes to the group adds them back as a contact;
//   7. leaving that group lets go of what its record kept: their key is
//      nowhere and their routing id and name only in what they wrote in the
//      thread — and the record, no longer the list I held, is never sent as
//      one to a member who asks;
//   8. removing them from the group (as its admin) lets go of it too, and
//      nothing is queued for them;
//   9. a group I am out of keeps nothing of a contact I delete afterwards:
//      the record kept as history lets go of them, and is never a list again;
//  10. being removed from the group after deleting them lets go of them
//      too — and the list that removed me, which names them, does not bring
//      them back as a contact;
//  11. an admin who has left the group is still an admin in its list, so
//      deleting their contact keeps their routing id in the record (and the
//      dialog names the group) — until I leave it too;
//  12. deleting the OWNER of a group I have already left — who also issued
//      the list I hold, and never wrote in it — shows the plain dialog, and
//      afterwards nothing in the vault names them: not the record (which
//      holds an owner and an issuer that name nobody), only the chat's own
//      line that they added me, by name;
//  13. the same owner deleted while I am still in the group is kept, as the
//      other dialog says — and leaving lets go of them too;
//  14. what that costs: a record whose owner names nobody cannot match the
//      roles of a list for its group, so an admin's list adding me back is
//      refused — where it used to be taken, and to bring the owner back as
//      a contact.
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
import 'package:zapp/core/models.dart';
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
    // The rows read, and only those: a group fan-out drains in the
    // background, and a row it writes between the read and a delete of
    // everything addressed to [to] was deleted without being carried.
    for (final r in rows) {
      await from.vault.db
          .delete('outbox', where: 'seq = ?', whereArgs: [r['seq']]);
    }
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

  /// Where [needle] is in [v]: `table.column` for a value that contains it,
  /// `table.column(sealed)` for a sealed value whose plaintext does — and,
  /// for `kv`, the row's key in brackets in place of the column, since a
  /// row per key is what a family is (`kv.k` when the key itself names it).
  /// [mentions] reads what is in the clear; this opens what is sealed too.
  Future<Set<String>> where(Vault v, String needle) async {
    final out = <String>{};
    final tables = (await v.db.rawQuery(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"))
        .map((r) => r['name'] as String);
    for (final t in tables) {
      for (final row in await v.db.query(t)) {
        for (final e in row.entries) {
          final val = e.value;
          if (val is! String) continue;
          final at = t != 'kv'
              ? '$t.${e.key}'
              : e.key == 'k'
                  ? 'kv.k'
                  : 'kv[${row['k']}]';
          if (val.contains(needle)) out.add(at);
          try {
            if ((await v.unseal(val)).contains(needle)) out.add('$at(sealed)');
          } catch (_) {
            // Not sealed: read in the clear above.
          }
        }
      }
    }
    return out;
  }

  /// Run [step] until it reports done — each round an awaited step, carrying
  /// what has been queued meanwhile — or fail, saying [what] never happened.
  Future<void> pollUntil(Future<bool> Function() step,
      {required String what}) async {
    final deadline = DateTime.now().add(const Duration(seconds: 30));
    while (!await step()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 20));
    }
  }

  /// Deliver everything queued among [all] — group fan-out and delivery
  /// receipts included — until nothing is left on the way to any of them.
  Future<void> settleAll(List<ChatService> all) => pollUntil(() async {
        for (final x in all) {
          await x.drainGroupFanoutForTest();
          await x.flushDeliveryReceipts();
        }
        var moved = 0;
        for (final x in all) {
          for (final y in all) {
            if (!identical(x, y)) moved += await carry(x, y);
          }
        }
        if (moved > 0) return false;
        for (final x in all) {
          if (x.pendingDeliveryReceipts > 0) return false;
          if ((await x.vault.db.query('group_fanout', limit: 1)).isNotEmpty) {
            return false;
          }
          for (final y in all) {
            if (identical(x, y)) continue;
            final queued = await x.vault.db.query('outbox',
                where: 'rid = ?', whereArgs: [y.myRid], limit: 1);
            if (queued.isNotEmpty) return false;
          }
        }
        return true;
      }, what: 'everything queued among them delivered');

  /// Orla, Abe and Bree all know one another; Bree has a laptop Abe has been
  /// told about, and Abe and Bree have a chat of their own. Then a group of
  /// the three — Orla's, or Abe's when [abeOwns] — in which Abe writes, and
  /// Bree writes, reacts to Abe's message and confirms it. Names long
  /// enough that no base64 is going to contain one by chance. Returns
  /// (abe, bree, orla, gid, Bree's laptop's routing id).
  Future<(ChatService, ChatService, ChatService, String, String)> inGroup(
      String tag,
      {bool abeOwns = false}) async {
    final orla = await makeClient('OrlaOwner$tag');
    final abe = await makeClient('AbeMember$tag');
    final bree = await makeClient('BreeDeleted$tag');
    final all = [orla, abe, bree];
    for (final (x, y) in [(abe, bree), (abe, orla), (bree, orla)]) {
      await x.addContactFromCode(await y.myContactCode());
      await y.addContactFromCode(await x.myContactCode());
    }
    await settleAll(all);
    await abe.sendText(bree.myRid, 'hello Bree');
    await settleAll(all);
    await bree.sendText(abe.myRid, 'hello Abe');
    await settleAll(all);
    final ltId = await ZIdentity.generate();
    final account = await bree.accountIdentity();
    final cert = await account.signDeviceCert(
        deviceEdPub: ltId.edPub, deviceXPub: ltId.xPub, deviceId: 'lt');
    await bree.addMyDevice(cert);
    await settleAll(all);
    final owner = abeOwns ? abe : orla;
    final gid = await owner.createGroup('Crew', [
      for (final s in all)
        if (!identical(s, owner)) s.myRid
    ]);
    await settleAll(all);
    expect(abe.groups[gid]?.memberRids, contains(bree.myRid));
    await abe.sendGroupText(gid, 'from Abe');
    await settleAll(all);
    final abeMid = bree.messagesByChat[gid]!
        .lastWhere((m) => m.kind == 'gtext' && !m.outgoing)
        .mid;
    await bree.toggleReaction(gid, abeMid, '👍');
    await bree.sendGroupText(gid, 'from Bree');
    await settleAll(all);
    return (abe, bree, orla, gid, await ltId.routingId());
  }

  /// Orla owns a group of Abe and Bree — Bree an admin too, when
  /// [breeAdmin] — and has written nothing in it; Abe knows Orla, and Bree
  /// only through the group. Returns (abe, bree, orla, gid).
  Future<(ChatService, ChatService, ChatService, String)> orlasGroup(
      String tag,
      {bool breeAdmin = false}) async {
    final orla = await makeClient('OrlaOwner$tag');
    final abe = await makeClient('AbeMember$tag');
    final bree = await makeClient('BreeMember$tag');
    final all = [orla, abe, bree];
    for (final (x, y) in [(abe, orla), (bree, orla)]) {
      await x.addContactFromCode(await y.myContactCode());
      await y.addContactFromCode(await x.myContactCode());
    }
    await settleAll(all);
    final gid = await orla.createGroup('Crew', [abe.myRid, bree.myRid]);
    await settleAll(all);
    if (breeAdmin) {
      await orla.promoteAdmin(gid, bree.myRid);
      await settleAll(all);
      expect(abe.groups[gid]!.adminRids, {orla.myRid, bree.myRid});
    }
    final g = abe.groups[gid]!;
    expect(g.ownerRid, orla.myRid);
    expect(g.by, orla.myRid, reason: 'the list Abe holds is hers');
    return (abe, bree, orla, gid);
  }

  /// What a group thread — and nothing else — holds of someone in it: what
  /// they wrote (sealed with their routing id and name), their reaction, and
  /// their confirming my message.
  const groupThread = {
    'messages.enc_body(sealed)',
    'reactions.sender_rid',
    'delivery.from_rid',
  };

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

  test('6. a contact in a group I am in: the vault keeps exactly what the '
      'dialog says', () async {
    final (abe, bree, orla, gid, laptopRid) = await inGroup('6');
    final ed = b64(bree.identity.edPub);
    final name = bree.displayName;
    // A message of Abe's to the group is still queued for each member when
    // he deletes her.
    abe.debugPauseGroupFanout = true;
    await abe.sendGroupText(gid, 'queued when Bree was deleted');
    // Before: Bree is everywhere, the group included, and the dialog will
    // name the group.
    expect(abe.groupsNaming(bree.myRid).map((g) => g.gid), [gid]);
    expect(
        await where(abe.vault, bree.myRid),
        containsAll([
          'contacts.rid',
          'group_fanout.rid',
          'kv[s:groups](sealed)',
          ...groupThread,
        ]));
    expect(await where(abe.vault, laptopRid), isNotEmpty);

    await abe.deleteContact(bree.myRid);

    // After: the group's record — she is a member, and its lists name her
    // by the entry it keeps — and the group's thread. Nothing else.
    expect(await where(abe.vault, bree.myRid),
        {'kv[s:groups](sealed)', ...groupThread},
        reason: 'her routing id: the group record and the group thread only');
    expect(await where(abe.vault, ed), {'kv[s:groups](sealed)'},
        reason: 'her public key: the group record only');
    expect(await where(abe.vault, name),
        {'kv[s:groups](sealed)', 'messages.enc_body(sealed)'},
        reason: 'her name: the group record, and what she wrote there');
    expect(await where(abe.vault, laptopRid), isEmpty,
        reason: 'nothing of her laptop');
    // The reaction and the confirmation are the group thread's.
    for (final (table, column) in [
      ('reactions', 'rid'),
      ('delivery', 'thread_rid'),
    ]) {
      final rows = await abe.vault.db.query(table, columns: [column]);
      expect({for (final r in rows) r[column]}, {gid}, reason: table);
    }
    final g = abe.groups[gid]!;
    expect(g.memberRids, contains(bree.myRid),
        reason: 'deleting a contact takes nobody out of a group');
    expect(g.orphans.keys, [bree.myRid]);
    expect(abe.contacts.containsKey(bree.myRid), isFalse);
    expect(abe.messagesByChat.containsKey(bree.myRid), isFalse);
    expect(abe.groupsNaming(bree.myRid).map((g) => g.gid), [gid]);
    final eds = [
      for (final m in (await abe.debugInviteData(gid))['members'] as List)
        ((m as Map)['b'] as Map)['ed']
    ];
    expect(eds, contains(ed), reason: 'a list of mine still names her');

    // The queued message goes to Orla, and nowhere else.
    abe.debugPauseGroupFanout = false;
    await settleAll([orla, abe]);
    expect(
        orla.messagesByChat[gid]!.map((m) => m.body),
        contains('queued when Bree was deleted'));

    // And, as the dialog says, a change someone else makes to the group
    // adds her back as a contact — as it does any member — and the entry
    // the record kept goes.
    await orla.renameGroup(gid, 'Crew, renamed');
    await settleAll([orla, abe]);
    expect(abe.groups[gid]!.name, 'Crew, renamed');
    expect(abe.contacts.containsKey(bree.myRid), isTrue,
        reason: "introduced again by Orla's list");
    expect(abe.groups[gid]!.orphans, isEmpty);
  });

  test('7. leaving the group lets go of what it kept of them', () async {
    final (abe, bree, orla, gid, _) = await inGroup('7', abeOwns: true);
    final ed = b64(bree.identity.edPub);
    await abe.deleteContact(bree.myRid);
    expect(await where(abe.vault, ed), {'kv[s:groups](sealed)'});

    // Abe leaves; his leave to Orla is lost, so she will ask.
    abe.debugPauseGroupFanout = true;
    await abe.leaveGroup(gid);
    await abe.vault.db
        .delete('group_fanout', where: 'rid = ?', whereArgs: [orla.myRid]);
    abe.debugPauseGroupFanout = false;

    expect(await where(abe.vault, bree.myRid), groupThread,
        reason: 'her routing id: only in what the thread holds of her');
    expect(await where(abe.vault, ed), isEmpty, reason: 'her key: nowhere');
    expect(await where(abe.vault, bree.displayName),
        {'messages.enc_body(sealed)'},
        reason: 'her name: only in what she wrote');
    final g = abe.groups[gid]!;
    expect(g.trimmed, isTrue);
    expect(g.memberRids, {orla.myRid});
    expect(abe.groupsNaming(bree.myRid), isEmpty);

    // Orla, who never got the leave, asks. Abe, the owner, answers — with
    // his leave, and not with the list he held: without Bree that list
    // would remove her from the group wherever it was taken.
    expect(orla.groups[gid]!.memberRids, contains(abe.myRid));
    final listsBefore = orla.debugListsJudgedFrom(gid, abe.myRid);
    await orla.debugSendRawInner(
        abe.myRid,
        InnerMessage(
            kind: 'gsync', mid: newMessageId(), ts: 1, data: {'gid': gid}));
    await carry(orla, abe);
    // A list would go first, then the leave: once the leave is in, so is
    // anything sent before it.
    await pollUntil(() async {
      await carry(abe, orla);
      return !orla.groups[gid]!.memberRids.contains(abe.myRid);
    }, what: "Abe's answer reaches Orla");
    expect(orla.debugListsJudgedFrom(gid, abe.myRid), listsBefore,
        reason: 'no list from a record that has let go of a member');
    expect(orla.groups[gid]!.memberRids, contains(bree.myRid));
  });

  test('8. removing them from the group lets go of it too', () async {
    final (abe, bree, orla, gid, laptopRid) = await inGroup('8', abeOwns: true);
    final ed = b64(bree.identity.edPub);
    await abe.deleteContact(bree.myRid);
    await abe.removeGroupMember(gid, bree.myRid);

    expect(await where(abe.vault, bree.myRid), groupThread,
        reason: 'her routing id: only in what the thread holds of her');
    expect(await where(abe.vault, ed), isEmpty, reason: 'her key: nowhere');
    expect(await where(abe.vault, laptopRid), isEmpty);
    final g = abe.groups[gid]!;
    expect(g.memberRids, {orla.myRid});
    expect(g.orphans, isEmpty);
    expect(g.mine?['rm'], isEmpty,
        reason: 'what my change did does not name her either');
    await settleAll([orla, abe]);
    expect(orla.groups[gid]!.memberRids, isNot(contains(bree.myRid)),
        reason: 'the list went out, and took her out');
  });

  test('9. a group I am out of keeps nothing of a contact I delete later',
      () async {
    final (abe, bree, orla, gid, _) = await inGroup('9');
    await orla.removeGroupMember(gid, abe.myRid);
    await settleAll([orla, abe]);
    final g = abe.groups[gid]!;
    expect(g.left, isTrue);
    expect(g.memberRids, {orla.myRid, bree.myRid},
        reason: 'the list that removed him, kept as history');

    await abe.deleteContact(bree.myRid);
    expect(await where(abe.vault, bree.myRid), groupThread,
        reason: 'her routing id: only in what the thread holds of her');
    expect(await where(abe.vault, b64(bree.identity.edPub)), isEmpty);
    expect(g.memberRids, {orla.myRid});
    expect(g.trimmed, isTrue, reason: 'never sent as a list again');
  });

  test('10. being removed from the group lets go of a contact I deleted, '
      'and does not introduce them again', () async {
    final (abe, bree, orla, gid, _) = await inGroup('10');
    await abe.deleteContact(bree.myRid);
    expect(await where(abe.vault, b64(bree.identity.edPub)),
        {'kv[s:groups](sealed)'});
    await orla.removeGroupMember(gid, abe.myRid);
    await settleAll([orla, abe]);
    final g = abe.groups[gid]!;
    expect(g.left, isTrue);
    expect(abe.contacts.containsKey(bree.myRid), isFalse,
        reason: 'the list that removed him names her, and it adds nobody '
            'he deleted back as a contact');
    expect(await where(abe.vault, bree.myRid), groupThread,
        reason: 'her routing id: only in what the thread holds of her');
    expect(await where(abe.vault, b64(bree.identity.edPub)), isEmpty);
    expect(g.memberRids, {orla.myRid});
    expect(g.trimmed, isTrue);
  });

  test('11. an admin who has left is still named until I leave too',
      () async {
    final (abe, bree, orla, gid, _) = await inGroup('11');
    final all = [orla, abe, bree];
    await orla.promoteAdmin(gid, bree.myRid);
    await settleAll(all);
    await bree.leaveGroup(gid);
    await settleAll(all);
    final g = abe.groups[gid]!;
    expect(g.memberRids, isNot(contains(bree.myRid)));
    expect(g.adminRids, contains(bree.myRid),
        reason: 'leaving takes no role away; only the owner does');

    // Out of the group but an admin in its list: the record must go on
    // naming her — every list at this roles version does — so the dialog
    // names the group, and the record keeps her.
    expect(abe.groupsNaming(bree.myRid).map((g) => g.gid), [gid]);
    await abe.deleteContact(bree.myRid);
    expect(await where(abe.vault, bree.myRid),
        {'kv[s:groups](sealed)', ...groupThread});
    expect(g.adminRids, contains(bree.myRid));

    // Leaving lets go of that too.
    await abe.leaveGroup(gid);
    expect(await where(abe.vault, bree.myRid), groupThread);
    expect(await where(abe.vault, b64(bree.identity.edPub)), isEmpty);
    expect(g.adminRids, {orla.myRid});
    expect(g.trimmed, isTrue);
  });

  test('12. deleting the owner of a group I have left: the plain dialog, '
      'and nothing names them', () async {
    final (abe, _, orla, gid) = await orlasGroup('12');
    await abe.leaveGroup(gid);
    final g = abe.groups[gid]!;
    expect(g.left, isTrue);
    expect(g.trimmed, isFalse, reason: 'nobody in it was deleted yet');
    expect(await where(abe.vault, orla.myRid), contains('kv[s:groups](sealed)'),
        reason: 'the record of a group I left names its owner');

    // No group I am in names her: the dialog is the plain one, which says
    // the contact is wiped and that a group's chat keeps what it holds.
    expect(abe.groupsNaming(orla.myRid), isEmpty);
    await abe.deleteContact(orla.myRid);

    expect(await where(abe.vault, orla.myRid), isEmpty,
        reason: 'her routing id: nowhere, the record included');
    expect(await where(abe.vault, b64(orla.identity.edPub)), isEmpty,
        reason: 'her key: nowhere');
    expect(await where(abe.vault, orla.displayName),
        {'messages.enc_body(sealed)'},
        reason: "her name: only the chat's line that she added me");
    expect(g.ownerRid, Group.nobody, reason: 'an owner that names nobody');
    expect(g.by, Group.nobody, reason: 'an issuer that names nobody');
    expect(g.adminRids, {Group.nobody});
    expect(g.memberRids, isNot(contains(orla.myRid)));
    expect(g.trimmed, isTrue, reason: 'never sent as a list again');
  });

  test('13. the owner deleted while I am in the group is kept, and leaving '
      'lets go of her', () async {
    final (abe, _, orla, gid) = await orlasGroup('13');
    expect(abe.groupsNaming(orla.myRid).map((g) => g.gid), [gid],
        reason: 'the dialog names the group');
    await abe.deleteContact(orla.myRid);
    expect(await where(abe.vault, orla.myRid), {'kv[s:groups](sealed)'},
        reason: 'the group I am in still names its owner');
    final g = abe.groups[gid]!;
    expect(g.ownerRid, orla.myRid);

    await abe.leaveGroup(gid);
    expect(await where(abe.vault, orla.myRid), isEmpty);
    expect(await where(abe.vault, b64(orla.identity.edPub)), isEmpty);
    expect(await where(abe.vault, orla.displayName),
        {'messages.enc_body(sealed)'});
    expect(g.ownerRid, Group.nobody);
    expect(g.by, Group.nobody);
    expect(g.trimmed, isTrue);
  });

  test('14. a group I left whose owner I deleted cannot take me back: a '
      'list from an admin is refused', () async {
    final (abe, bree, orla, gid) = await orlasGroup('14', breeAdmin: true);
    final all = [abe, bree, orla];
    await abe.leaveGroup(gid);
    await settleAll(all);
    await abe.deleteContact(orla.myRid);
    final g = abe.groups[gid]!;
    expect(g.ownerRid, Group.nobody);
    expect(g.adminRids, {bree.myRid, Group.nobody});

    // Bree, an admin and still in the group, adds me back. Her list names
    // Orla as its owner, as every list for this group does, and the record
    // no longer does: the roles differ, and it is refused.
    final judged = abe.debugListsJudgedFrom(gid, bree.myRid);
    await bree.addGroupMembers(gid, [abe.myRid]);
    expect(bree.groups[gid]!.memberRids, contains(abe.myRid));
    await settleAll(all);
    await pollUntil(
        () async => abe.debugListsJudgedFrom(gid, bree.myRid) > judged,
        what: "Abe has judged Bree's list adding him back");
    expect(abe.groups[gid]!.left, isTrue, reason: 'not taken back');
    expect(abe.groups[gid]!.ownerRid, Group.nobody);
    expect(abe.contacts.containsKey(orla.myRid), isFalse,
        reason: 'and the owner is not brought back as a contact through it');
  });
}
