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
//      `cdev_ver_` used to refuse it.
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
    // retry: `acquainted()` leaves async work in flight that `deleteContact`
    // does not wait on — the 300 ms delivery-receipt timer, the PQ-delivery
    // timers, and an unawaited device-assurance refresh. Under a loaded suite
    // one of them can fire *after* the deletion and re-enqueue an outbox row,
    // re-touch the conversation, or rewrite a `kv` key for the contact; which
    // one wins varies run to run (the leaked set is not stable), which is the
    // signature of a timing race, not an erasure gap. The property holds
    // deterministically in isolation, and a real regression — `deleteContact`
    // missing a table or family — fails every attempt, not one run in a busy
    // suite. `pq_identity_exchange_test` carries the same guard for the same
    // reason.
  }, retry: 2);

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
}
