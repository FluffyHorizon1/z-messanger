// 23.2 — a group FILE send goes through the durable fan-out like a text does.
//
// 15.3 queued text, reactions, edits and deletes through `group_fanout` and
// left `sendGroupFile` synchronous, because its fan-out carries per-recipient
// chunk payloads that "would have to be stored again per row". They are not
// stored at all now: the drain rebuilds each member's chunk rows from the
// vault blob when that member's turn comes — `chunkNonce` is derived from the
// file nonce and the index, so every rebuild is byte-identical — and commits
// them with that member's offer. The membership snapshot at queue time, which
// carries the security property, is the same one text has.
//
// Criteria, each a test below (the first four mirror group_fanout_test's):
//   1. sendGroupFile returns promptly for a large group;
//   2. every member is still served — the offer AND every chunk;
//      (Criteria 1 and 2 share a test, as in the text suite: the timing is
//      only meaningful if the same send is then shown to have reached everyone.)
//   3. a fan-out interrupted part-way is completed on the next start, and a
//      member already served is not served twice;
//   4. the file row, the message row and the fan-out rows are written together
//      or not at all; and a member's offer and chunks land together, so nobody
//      holds a key without its chunks or chunks without their key;
//   5. a member removed before the send receives neither the key nor a chunk,
//      and one removed after it still receives what was sent while they were
//      a member — the ordering the queue preserves.
//
// 48.3 (ADR 0036 §4): a group file has a budget. Every chunk goes to every
// recipient in an envelope of its own, so a file's upload is recipients ×
// chunks × 349 610 characters; from 128 MB the composer says so, and past
// 256 MB, the public relay's whole store, the file is not sent. Each a test:
//   6. the cost as computed, before anything is sealed, is recipients ×
//      chunks × 349 610 — each member, and each of my other devices — and
//      is what the drain and the mirror then stage, envelope for envelope;
//      the lines fall where the decision put them, one envelope either side;
//   7. under 128 MB the composer shows nothing, and the file goes;
//   8. from 128 MB the composer shows what the file will upload, and to how
//      many, before anything is sent: cancelled, nothing goes; sent, it does;
//   9. past 256 MB the send is refused — no row, no chunk, no blob, no
//      message stored as sent — and so is one the group outgrew while its
//      blob was being written;
//  10. and the composer tells the person why, and sends nothing;
//  11. a file to one contact is not budgeted: the same file a group of one
//      is refused goes to the contact, and the composer says nothing;
//  12. a voice message to a group that does not go — its cost cancelled,
//      or refused — is kept in the composer until it goes, and the dialogs
//      say it is a voice message.
@Tags(['integration'])
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show EventChannel, MethodChannel;
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/core/voice.dart' show voiceSampleRate;
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/l10n/app_localizations_en.dart';
import 'package:zapp/ui/chat_screen.dart';
import 'package:zapp/ui/theme.dart';
import 'package:z_protocol/z_protocol.dart';

/// The file picker, handing over [bytes] as the file the person chose.
class _HandingPicker extends FilePicker {
  Uint8List bytes = Uint8List(0);
  int picks = 0;

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
    picks++;
    return FilePickerResult(
        [PlatformFile(name: 'clip.bin', size: bytes.length, bytes: bytes)]);
  }

  @override
  Future<bool?> clearTemporaryFiles() async => true;
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  late Process relay;
  late int port;
  final temps = <Directory>[];
  final services = <ChatService>[];
  // The microphone: what a recording hears is handed to it here, once the
  // recording has started.
  MockStreamHandlerEventSink? mic;

  setUpAll(() async {
    HttpOverrides.global = null;
    // The chat screen (48.3's composer criteria) constructs an AudioRecorder,
    // whose plugin does not exist in the test shell. It is answered here: a
    // microphone the app may use, a recording whose sound a test hands to
    // [mic], and nulls for the rest.
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    messenger.setMockMethodCallHandler(
        const MethodChannel('com.llfbandit.record/messages'), (call) async {
      final args = call.arguments;
      final id = args is Map ? args['recorderId'] : null;
      switch (call.method) {
        case 'create':
          messenger.setMockStreamHandler(
              EventChannel('com.llfbandit.record/events/$id'),
              MockStreamHandler.inline(onListen: (args, events) {}));
          messenger.setMockStreamHandler(
              EventChannel('com.llfbandit.record/eventsRecord/$id'),
              MockStreamHandler.inline(onListen: (args, events) {
                mic = events;
              }));
        case 'hasPermission':
          return true;
      }
      return null;
    });
    final serverDir =
        '${Directory.current.parent.path}${Platform.pathSeparator}server';
    final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    port = probe.port;
    await probe.close();
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

  Future<ChatService> makeClient(String name,
      {Directory? dir, bool offline = false}) async {
    final d = dir ?? await Directory.systemTemp.createTemp('z_gff_$name');
    if (dir == null) temps.add(d);
    final vault = await Vault.open(rootOverride: d);
    final existing = await vault.kvGet('identity');
    final identity = existing != null
        ? await ZIdentity.fromJson(jsonDecode(existing) as Map<String, Object?>)
        : await ZIdentity.generate();
    if (existing == null) {
      await vault.kvPut('identity', jsonEncode(identity.toJson()));
    }
    final svc = await ChatService.init(
      vault: vault,
      identity: identity,
      displayName: name,
      transport: Transport(
          identity: identity,
          serverUrl: 'ws://127.0.0.1:${offline ? 1 : port}'),
    );
    services.add(svc);
    return svc;
  }

  Future<String> addPhantom(ChatService svc, String tag) async {
    final id = await ZIdentity.generate();
    final code = (await id.bundle(displayName: tag)).encode();
    await svc.addContactFromCode(code);
    return (await ContactBundle.decode(code)).routingId();
  }

  Future<int> outboxCount(ChatService svc, String rid) async {
    final rows = await svc.vault.db
        .query('outbox', columns: ['id'], where: 'rid = ?', whereArgs: [rid]);
    return rows.length;
  }

  // Big enough for several chunks, so "every chunk" means something.
  final payload = Uint8List.fromList(List.generate(300 * 1024, (i) => i % 251));
  final chunkCount = splitChunks(payload).length;
  // What one member's fan-out puts in the outbox: the offer plus the chunks.
  final perMember = 1 + chunkCount;

  test('1+2. a large group file send returns promptly, and everyone is served',
      () async {
    expect(chunkCount, greaterThan(1), reason: 'the payload spans chunks');
    final svc = await makeClient('fast');
    final rids = <String>[];
    for (var i = 0; i < 20; i++) {
      rids.add(await addPhantom(svc, 'm$i'));
    }
    final gid = await svc.createGroup('Twenty', rids);
    await svc.waitForGroupFanout(gid);
    await svc.transport.stop();
    await svc.vault.db.delete('outbox');

    final sw = Stopwatch()..start();
    await svc.sendGroupFile(gid, 'clip.bin', payload, 'application/octet-stream');
    sw.stop();
    // Before 23.2 this awaited the offer and the sealed chunks for every one
    // of twenty members; now it writes the blob, the rows and the plan, and
    // returns. The bound is loose enough for the blob write on a slow disk
    // and far below twenty members' worth of sealing.
    expect(sw.elapsedMilliseconds, lessThan(400),
        reason: 'sendGroupFile took ${sw.elapsedMilliseconds}ms for 20 '
            'members; it should record the fan-out and return, not perform it');

    await svc.waitForGroupFanout(gid);
    for (final rid in rids) {
      expect(await outboxCount(svc, rid), perMember,
          reason: 'member $rid should hold the offer and every chunk');
    }
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('3. an interrupted file fan-out is finished on the next start, once',
      () async {
    final dir = await Directory.systemTemp.createTemp('z_gff_resume');
    temps.add(dir);
    var svc = await makeClient('resume', dir: dir);
    final rids = [for (var i = 0; i < 6; i++) await addPhantom(svc, 'r$i')];
    final gid = await svc.createGroup('Six', rids);
    await svc.waitForGroupFanout(gid);
    await svc.transport.stop();
    await svc.vault.db.delete('outbox');

    svc.debugPauseGroupFanout = true;
    await svc.sendGroupFile(gid, 'clip.bin', payload, 'application/octet-stream');
    expect((await svc.vault.db.query('group_fanout')).length, rids.length,
        reason: 'every recipient recorded before any is served');
    for (final rid in rids) {
      expect(await outboxCount(svc, rid), 0,
          reason: 'nothing performed yet — the drain is paused');
    }
    await svc.transport.stop();

    // Restart onto the same vault, offline: the drain runs from init and
    // rebuilds the chunks from the blob it finds there.
    svc = await makeClient('resume2', dir: dir, offline: true);
    await svc.waitForGroupFanout(gid);
    for (final rid in rids) {
      expect(await outboxCount(svc, rid), perMember,
          reason: 'member $rid served exactly once by the resumed fan-out');
    }
    expect((await svc.vault.db.query('group_fanout')).length, 0);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('4. file, message and plan are one transaction; offer and chunks too',
      () async {
    final svc = await makeClient('atomic', offline: true);
    final rids = [for (var i = 0; i < 3; i++) await addPhantom(svc, 'a$i')];
    final gid = await svc.createGroup('Three', rids);
    await svc.waitForGroupFanout(gid);
    svc.debugPauseGroupFanout = true;

    Future<int> messages() async => (await svc.vault.db.query('messages',
            where: 'rid = ? AND outgoing = 1', whereArgs: [gid]))
        .length;
    Future<int> files() async =>
        (await svc.vault.db.query('files', where: 'rid = ?', whereArgs: [gid]))
            .length;
    Future<int> queued() async =>
        (await svc.vault.db.query('group_fanout')).length;
    final m0 = await messages();
    final f0 = await files();

    // Refuse the fan-out rows: neither the file nor the message may survive.
    await svc.vault.db
        .execute('CREATE TRIGGER no_fanout BEFORE INSERT ON group_fanout '
            'BEGIN SELECT RAISE(ABORT, \'induced\'); END');
    await expectLater(
        svc.sendGroupFile(gid, 'lost.bin', payload, 'application/octet-stream'),
        throwsA(anything));
    await svc.vault.db.execute('DROP TRIGGER no_fanout');
    expect(await messages(), m0, reason: 'no message row without its plan');
    expect(await files(), f0, reason: 'no file row without its plan');
    expect(await queued(), 0);

    // Refuse the message row: no orphan plan for a message that never was.
    await svc.vault.db
        .execute('CREATE TRIGGER no_message BEFORE INSERT ON messages '
            'BEGIN SELECT RAISE(ABORT, \'induced\'); END');
    await expectLater(
        svc.sendGroupFile(gid, 'lost2.bin', payload, 'application/octet-stream'),
        throwsA(anything));
    await svc.vault.db.execute('DROP TRIGGER no_message');
    expect(await queued(), 0);
    expect(await files(), f0);

    // Nothing induced: all three land, one plan row per member.
    await svc.sendGroupFile(gid, 'real.bin', payload, 'application/octet-stream');
    expect(await messages(), m0 + 1);
    expect(await files(), f0 + 1);
    expect(await queued(), rids.length);

    // Per member, the offer and the chunks are one transaction: refuse the
    // second outbox row for a member and that member gets NOTHING, and the
    // plan row stays so the next drain serves them whole. (The invite rows
    // from createGroup are cleared first, so the counts below are this
    // send's alone.)
    await svc.vault.db.delete('outbox');
    await svc.vault.db.execute(
        'CREATE TRIGGER one_row BEFORE INSERT ON outbox WHEN '
        '(SELECT COUNT(*) FROM outbox WHERE rid = NEW.rid) >= 1 '
        'BEGIN SELECT RAISE(ABORT, \'induced\'); END');
    svc.debugPauseGroupFanout = false;
    await svc.drainGroupFanoutForTest();
    for (final rid in rids) {
      expect(await outboxCount(svc, rid), 0,
          reason: 'member $rid must not hold a key without its chunks');
    }
    expect(await queued(), rids.length, reason: 'nothing was consumed');
    await svc.vault.db.execute('DROP TRIGGER one_row');
    await svc.drainGroupFanoutForTest();
    await svc.waitForGroupFanout(gid);
    for (final rid in rids) {
      expect(await outboxCount(svc, rid), perMember);
    }
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('5. removed before the send: no key, no chunk; removed after: served',
      () async {
    final svc = await makeClient('ordering');
    final rids = [for (var i = 0; i < 4; i++) await addPhantom(svc, 'o$i')];
    final gid = await svc.createGroup('Four', rids);
    await svc.waitForGroupFanout(gid);
    await svc.transport.stop();

    final before = rids[0];
    await svc.removeGroupMember(gid, before);
    await svc.waitForGroupFanout(gid);
    // The removal itself told them; from here on they are owed nothing.
    await svc.vault.db.delete('outbox');

    await svc.sendGroupFile(gid, 'clip.bin', payload, 'application/octet-stream');
    // Removed AFTER the send was queued: still a recipient of that send.
    final after = rids[1];
    await svc.removeGroupMember(gid, after);
    await svc.waitForGroupFanout(gid);

    expect(await outboxCount(svc, before), 0,
        reason: 'removed before the send: not the offer, not a chunk');
    expect(await outboxCount(svc, after), greaterThanOrEqualTo(perMember),
        reason: 'removed after the send was queued: the file still goes, plus '
            'the invite that removes them');
    for (final rid in rids.sublist(2)) {
      expect(await outboxCount(svc, rid), greaterThanOrEqualTo(perMember));
    }
  }, timeout: const Timeout(Duration(minutes: 3)));

  // ---- 48.3: a group file within a budget -----------------------------------

  final en = AppLocalizationsEn();
  const full = ChatService.chunkEnvelopeChars;

  /// A file of [chunks] whole chunks, every one of whose envelopes is a full
  /// chunk's, 349 610 characters.
  Uint8List wholeChunks(int chunks) => Uint8List(chunks * defaultChunkSize);

  GroupFileCost costOf(ChatService svc, int recipients, int chunks) =>
      GroupFileCost(
          recipients: recipients,
          chunks: chunks,
          noticeFrom: svc.groupFileNoticeFrom,
          limit: svc.groupFileLimit);

  /// The outbox's rows that carry a full chunk, by mailbox.
  Future<Map<String, int>> chunkRows(ChatService svc) async {
    final rows = await svc.vault.db.rawQuery(
        'SELECT rid, COUNT(*) AS n FROM outbox WHERE LENGTH(payload) = ? '
        'GROUP BY rid',
        [full]);
    return {for (final r in rows) r['rid'] as String: r['n'] as int};
  }

  /// Everything a group file's send could leave behind, counted.
  Future<Map<String, int>> traces(ChatService svc, String gid) async => {
        'fan-out rows': (await svc.vault.db.query('group_fanout')).length,
        'chunk rows': (await chunkRows(svc)).values.fold(0, (a, n) => a + n),
        'file rows': (await svc.vault.db
                .query('files', where: 'rid = ?', whereArgs: [gid]))
            .length,
        'file messages': (await svc.vault.db.query('messages',
                where: 'rid = ? AND kind = ?', whereArgs: [gid, 'file']))
            .length,
        'blobs': svc.vault.filesDir.listSync().length,
      };

  /// Another device of [svc]'s account, never started. The mirror sends it
  /// every chunk of a file [svc] sends.
  Future<void> addOwnDevice(ChatService svc, String name) async {
    final account = await svc.accountIdentity();
    final dev = await ZIdentity.generate();
    await svc.addMyDevice(await account.signDeviceCert(
        deviceEdPub: dev.edPub, deviceXPub: dev.xPub, deviceId: name));
  }

  Future<void> waitUntil(FutureOr<bool> Function() cond,
      {required String what,
      Duration timeout = const Duration(seconds: 60)}) async {
    final deadline = DateTime.now().add(timeout);
    while (!await cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await Future<void>.delayed(const Duration(milliseconds: 40));
    }
  }

  /// Pump until [cond] holds, letting real work run in between: a widget
  /// test's clock is fake, and the vault is real files and a real database.
  Future<void> settleUntil(WidgetTester t, bool Function() cond,
      {required String what}) async {
    final deadline = DateTime.now().add(const Duration(seconds: 60));
    await t.pump();
    while (!cond()) {
      if (DateTime.now().isAfter(deadline)) {
        throw TimeoutException('condition not met: $what');
      }
      await t.runAsync(
          () => Future<void>.delayed(const Duration(milliseconds: 40)));
      await t.pump(const Duration(milliseconds: 16));
    }
  }

  /// An offline person for a widget test, put away when it ends.
  Future<ChatService> offlineFor(WidgetTester t, String name) async {
    final svc = (await t.runAsync(() => makeClient(name, offline: true)))!;
    addTearDown(() => t.runAsync(() async {
          await svc.transport.stop();
          svc.dispose();
          await svc.vault.db.close();
        }));
    return svc;
  }

  /// [svc]'s chat with [rid] on screen, its composer ready, and a picker
  /// that hands over whatever the test puts in it.
  Future<_HandingPicker> openChat(
      WidgetTester t, ChatService svc, String rid) async {
    final picker = _HandingPicker();
    FilePicker.platform = picker;
    await t.pumpWidget(ChangeNotifierProvider<ChatService>.value(
      value: svc,
      child: MaterialApp(
        debugShowCheckedModeBanner: false,
        theme: ZTheme.light(),
        localizationsDelegates: AppLocalizations.localizationsDelegates,
        supportedLocales: AppLocalizations.supportedLocales,
        home: ChatScreen(rid: rid),
      ),
    ));
    await settleUntil(
        t, () => find.byTooltip(en.chatAttachFile).evaluate().isNotEmpty,
        what: 'the composer');
    return picker;
  }

  /// [label]'s button on the dialog that is up.
  Finder onDialog(String label) => find.descendant(
      of: find.byType(AlertDialog), matching: find.text(label));

  bool sentFile(ChatService svc, String rid) =>
      (svc.messagesByChat[rid] ?? const []).any((m) => m.kind == 'file');

  test(
      '6. a group file costs recipients × chunks × 349 610, worked out before '
      'anything is sealed, and that is what is staged', () async {
    final svc = await makeClient('cost', offline: true);
    final rids = [for (var i = 0; i < 3; i++) await addPhantom(svc, 'c$i')];
    final gid = await svc.createGroup('Three', rids);
    await svc.waitForGroupFanout(gid);
    await addOwnDevice(svc, 'laptop');
    await addOwnDevice(svc, 'tablet');

    // A 1 MiB photo is eight chunks, to three members and two devices.
    final photo = svc.groupFileCost(gid, 1024 * 1024);
    expect(photo.chunks, 8);
    expect(photo.recipients, 5,
        reason: 'each member, and each of my other devices, is sent every '
            'chunk in an envelope of its own');
    expect(photo.chars, 5 * 8 * 349610);
    expect(photo.notice, isFalse);
    expect(photo.refused, isFalse);

    // The lines as decided, one envelope either side: 128 MB is 366.1 full
    // chunk envelopes, and 256 MB is 732.2.
    expect(svc.groupFileNoticeFrom, 128 * 1000 * 1000);
    expect(svc.groupFileLimit, 256 * 1000 * 1000);
    expect(costOf(svc, 1, 366).notice, isFalse);
    expect(costOf(svc, 1, 367).notice, isTrue);
    expect(costOf(svc, 1, 732).refused, isFalse);
    expect(costOf(svc, 1, 733).refused, isTrue);
    // ADR 0036's own figures: a 1 MiB photo reaches 91 recipients within the
    // budget, a 24 MiB file four.
    final photoChunks = fileChunkCount(1024 * 1024);
    final largest = fileChunkCount(maxAttachmentBytes);
    expect(costOf(svc, 91, photoChunks).refused, isFalse);
    expect(costOf(svc, 92, photoChunks).refused, isTrue);
    expect(costOf(svc, 4, largest).refused, isFalse);
    expect(costOf(svc, 5, largest).refused, isTrue);

    // What is staged: a file of three whole chunks goes, in full chunk
    // envelopes, three to each member's mailbox from the drain and three to
    // each of my devices from the mirror — the cost, envelope for envelope.
    await svc.vault.db.delete('outbox');
    final file = wholeChunks(3);
    final cost = svc.groupFileCost(gid, file.length);
    expect(cost.recipients * cost.chunks, 15);
    await svc.sendGroupFile(gid, 'three.bin', file, 'application/octet-stream');
    await svc.waitForGroupFanout(gid);
    await waitUntil(
        () async => (await chunkRows(svc)).values.fold(0, (a, n) => a + n) >=
            cost.recipients * cost.chunks,
        what: 'every recipient\'s chunks staged');
    final staged = await chunkRows(svc);
    expect(staged.length, cost.recipients, reason: 'a mailbox per recipient');
    expect(staged.keys, containsAll(rids));
    expect(staged.values, everyElement(cost.chunks),
        reason: 'every chunk to every recipient');
    expect(staged.values.fold(0, (a, n) => a + n) * full, cost.chars);
  }, timeout: const Timeout(Duration(minutes: 3)));

  testWidgets('7. under 128 MB the composer shows nothing, and the file goes',
      (t) async {
    final svc = await offlineFor(t, 'quiet');
    final gid = (await t.runAsync(() async {
      final rids = [for (var i = 0; i < 3; i++) await addPhantom(svc, 'q$i')];
      final gid = await svc.createGroup('Three', rids);
      await svc.waitForGroupFanout(gid);
      return gid;
    }))!;
    svc.debugPauseGroupFanout = true; // what is queued is what is counted
    final picker = await openChat(t, svc, gid);
    // Just under the line: 122 whole chunks to three members is 366 full
    // chunk envelopes, 127 957 260 characters.
    picker.bytes = wholeChunks(122);
    final cost = svc.groupFileCost(gid, picker.bytes.length);
    expect(cost.chars, 127957260);
    expect(cost.notice, isFalse);

    await t.tap(find.byTooltip(en.chatAttachFile));
    await settleUntil(t, () => sentFile(svc, gid), what: 'the file sent');
    expect(picker.picks, 1);
    expect(find.byType(AlertDialog), findsNothing,
        reason: 'nothing to say under 128 MB');
    final queued = (await t.runAsync(
        () async => (await svc.vault.db.query('group_fanout')).length))!;
    expect(queued, 3, reason: 'queued to each member, unasked');
  });

  testWidgets(
      '8. from 128 MB the composer shows the cost, and the file goes only if '
      'the person says so', (t) async {
    final svc = await offlineFor(t, 'told');
    final gid = (await t.runAsync(() async {
      final rids = [for (var i = 0; i < 3; i++) await addPhantom(svc, 't$i')];
      final gid = await svc.createGroup('Three', rids);
      await svc.waitForGroupFanout(gid);
      return gid;
    }))!;
    svc.debugPauseGroupFanout = true;
    final picker = await openChat(t, svc, gid);
    // Just over: 123 whole chunks to three is 369 envelopes, 129 006 090
    // characters, said as about 130 MB.
    picker.bytes = wholeChunks(123);
    final cost = svc.groupFileCost(gid, picker.bytes.length);
    expect(cost.notice, isTrue);
    expect(cost.refused, isFalse);
    expect((cost.megabytes, cost.recipients), (130, 3));
    final says = en.chatGroupUploadBody(130, 3);
    expect(says, 'This file will upload about 130 MB (to 3 recipients). Each '
        'member of the group, and each of your other devices, is sent a copy '
        'of its own.');

    // Asked, and cancelled: nothing goes.
    await t.tap(find.byTooltip(en.chatAttachFile));
    await settleUntil(t, () => find.text(says).evaluate().isNotEmpty,
        what: 'the cost shown');
    expect(find.text(en.chatGroupUploadTitle), findsOneWidget);
    expect(sentFile(svc, gid), isFalse, reason: 'nothing before the answer');
    await t.tap(onDialog(en.cancel));
    await settleUntil(t, () => find.byType(AlertDialog).evaluate().isEmpty,
        what: 'the dialog gone');
    final afterCancel = (await t.runAsync(() => traces(svc, gid)))!;
    expect(sentFile(svc, gid), isFalse);
    expect(afterCancel['fan-out rows'], 0);
    expect(afterCancel['file rows'], 0);

    // Asked again, and sent: it goes.
    await t.tap(find.byTooltip(en.chatAttachFile));
    await settleUntil(t, () => find.text(says).evaluate().isNotEmpty,
        what: 'the cost shown again');
    await t.tap(onDialog(en.chatGroupUploadSend));
    await settleUntil(t, () => sentFile(svc, gid), what: 'the file sent');
    final afterSend = (await t.runAsync(() => traces(svc, gid)))!;
    expect(afterSend['fan-out rows'], 3);
    expect(afterSend['file rows'], 1);
    expect(picker.picks, 2);
  });

  test(
      '9. past 256 MB a group file is refused: no row, no chunk, no blob, no '
      'message stored as sent', () async {
    final svc = await makeClient('over', offline: true);
    final rids = [for (var i = 0; i < 5; i++) await addPhantom(svc, 'v$i')];
    final gid = await svc.createGroup('Five', rids);
    await svc.waitForGroupFanout(gid);
    await svc.vault.db.delete('outbox');
    // Paused, so that a send the budget does not stop is still only queued,
    // not staged: 308 MB is what the drain would write for it.
    svc.debugPauseGroupFanout = true;
    final before = await traces(svc, gid);

    // The largest file a build sends, 176 chunks, to five members: 880
    // envelopes, 308 MB.
    final big = Uint8List(maxAttachmentBytes);
    Object? refusal;
    try {
      await svc.sendGroupFile(gid, 'big.bin', big, 'application/octet-stream');
    } catch (e) {
      refusal = e;
    }
    expect(await traces(svc, gid), before,
        reason: 'a group file past the budget left something behind');
    expect(refusal, isA<GroupFileOverBudget>());
    final said = (refusal as GroupFileOverBudget).cost;
    expect((said.recipients, said.chunks, said.megabytes), (5, 176, 308));
    expect(sentFile(svc, gid), isFalse, reason: 'nothing on screen as sent');

    // Within the budget at the first look, and past it at the fan-out's own
    // snapshot: four members and 176 chunks are 704 envelopes, 246 MB; one
    // more device of mine, linked while the blob was written, makes 880.
    await svc.removeGroupMember(gid, rids.last);
    await svc.vault.db.delete('group_fanout');
    expect(svc.groupFileCost(gid, big.length).refused, isFalse);
    final before2 = await traces(svc, gid);
    svc.debugBeforeGroupFileQueued = () => addOwnDevice(svc, 'meanwhile');
    Object? late;
    try {
      await svc.sendGroupFile(gid, 'big.bin', big, 'application/octet-stream');
    } catch (e) {
      late = e;
    }
    svc.debugBeforeGroupFileQueued = null;
    expect(late, isA<GroupFileOverBudget>());
    expect((late as GroupFileOverBudget).cost.recipients, 5);
    expect(await traces(svc, gid), before2,
        reason: 'refused at the snapshot, its blob removed with it');
  }, timeout: const Timeout(Duration(minutes: 3)));

  testWidgets(
      '10. past 256 MB the composer says why, and nothing is sent', (t) async {
    final svc = await offlineFor(t, 'refused');
    final gid = (await t.runAsync(() async {
      final rids = [for (var i = 0; i < 5; i++) await addPhantom(svc, 'r$i')];
      final gid = await svc.createGroup('Five', rids);
      await svc.waitForGroupFanout(gid);
      return gid;
    }))!;
    svc.debugPauseGroupFanout = true;
    final picker = await openChat(t, svc, gid);
    // 147 whole chunks to five members: 735 envelopes, 256 963 350
    // characters, said as about 257 MB.
    picker.bytes = wholeChunks(147);
    final cost = svc.groupFileCost(gid, picker.bytes.length);
    expect(cost.refused, isTrue);
    expect((cost.megabytes, cost.recipients, cost.limitMegabytes),
        (257, 5, 256));
    final before = (await t.runAsync(() => traces(svc, gid)))!;
    final says = en.chatGroupUploadRefusedBody(257, 5, 256);
    expect(
        says,
        'This file would upload about 257 MB (to 5 recipients): more than the '
        '256 MB the public relay can hold for everyone at once. Nothing was '
        'sent. Send a smaller file, or send it to fewer people.');

    await t.tap(find.byTooltip(en.chatAttachFile));
    await settleUntil(t, () => find.text(says).evaluate().isNotEmpty,
        what: 'the refusal said');
    expect(find.text(en.chatGroupUploadRefusedTitle), findsOneWidget);
    expect(find.text(en.chatGroupUploadSend), findsNothing,
        reason: 'there is no sending it anyway');
    await t.tap(onDialog(en.ok));
    await settleUntil(t, () => find.byType(AlertDialog).evaluate().isEmpty,
        what: 'the refusal dismissed');
    expect(sentFile(svc, gid), isFalse);
    expect((await t.runAsync(() => traces(svc, gid)))!, before,
        reason: 'nothing written');
  });

  testWidgets(
      '11. a file to one contact is not budgeted: what a group of one is '
      'refused goes to the contact, and the composer says nothing', (t) async {
    final svc = await offlineFor(t, 'pair');
    // A limit two envelopes wide, and a notice from one, so a file of three
    // chunks is past both for any recipient.
    svc.groupFileLimit = 2 * full;
    svc.groupFileNoticeFrom = full;
    final (rid, gid) = (await t.runAsync(() async {
      final rid = await addPhantom(svc, 'only');
      final gid = await svc.createGroup('One', [rid]);
      await svc.waitForGroupFanout(gid);
      return (rid, gid);
    }))!;
    final file = wholeChunks(3);
    expect(svc.groupFileCost(gid, file.length).refused, isTrue);
    final toGroup = (await t.runAsync(() async {
      try {
        await svc.sendGroupFile(gid, 'three.bin', file, 'application/octet-stream');
        return null;
      } catch (e) {
        return e;
      }
    }));
    expect(toGroup, isA<GroupFileOverBudget>(),
        reason: 'the control: to the group of one, it is refused');

    await t.runAsync(() => svc.vault.db.delete('outbox'));
    final picker = await openChat(t, svc, rid);
    picker.bytes = file;
    await t.tap(find.byTooltip(en.chatAttachFile));
    await settleUntil(t, () => sentFile(svc, rid), what: 'the file sent');
    expect(find.byType(AlertDialog), findsNothing,
        reason: 'nothing said about a file to one contact');
    final rows = (await t.runAsync(() => chunkRows(svc)))!;
    expect(rows, {rid: 3}, reason: 'every chunk queued to the contact');
  });
  testWidgets(
      '12. a voice message to a group that does not go is kept: cancelled at '
      'its cost, or refused, it stays in the composer, said as a voice '
      'message, until it goes', (t) async {
    final svc = await offlineFor(t, 'voice');
    final gid = (await t.runAsync(() async {
      final rids = [for (var i = 0; i < 3; i++) await addPhantom(svc, 'w$i')];
      final gid = await svc.createGroup('Three', rids);
      await svc.waitForGroupFanout(gid);
      return gid;
    }))!;
    svc.debugPauseGroupFanout = true;
    // Two seconds heard: one chunk, to three members three envelopes, said
    // as about 2 MB — past a notice from one envelope.
    final heard = Uint8List(2 * 2 * voiceSampleRate);
    svc.groupFileNoticeFrom = full;
    await openChat(t, svc, gid);
    final says = en.chatGroupVoiceUploadBody(2, 3);
    expect(
        says,
        'This voice message will upload about 2 MB (to 3 recipients). Each '
        'member of the group, and each of your other devices, is sent a copy '
        'of its own.');
    final kept = find.text(en.chatVoiceHeld);

    // Recorded, sent, and its cost cancelled: nothing goes, and it is kept.
    mic = null;
    await t.tap(find.byTooltip(en.chatRecordVoice));
    await settleUntil(
        t,
        () =>
            mic != null &&
            find.text(en.chatRecordingHint).evaluate().isNotEmpty,
        what: 'recording');
    mic!.success(heard);
    await t.pump();
    await t.tap(find.byTooltip(en.chatSendVoice));
    await settleUntil(t, () => find.text(says).evaluate().isNotEmpty,
        what: 'the cost shown, as a voice message\'s');
    expect(find.text(en.chatGroupUploadBody(2, 3)), findsNothing,
        reason: 'not in a file\'s words');
    await t.tap(onDialog(en.cancel));
    await settleUntil(t, () => find.byType(AlertDialog).evaluate().isEmpty,
        what: 'the dialog gone');
    expect(kept, findsOneWidget, reason: 'cancelled, it is kept');
    expect(sentFile(svc, gid), isFalse);
    expect((await t.runAsync(() => traces(svc, gid)))!['fan-out rows'], 0);

    // Sent from where it is kept, and refused by the group's budget: still
    // kept, and the refusal says so.
    svc.groupFileLimit = 1000 * 1000;
    final refused = en.chatGroupVoiceUploadRefusedBody(2, 3, 1);
    expect(
        refused,
        'This voice message would upload about 2 MB (to 3 recipients): more '
        'than the 1 MB the public relay can hold for everyone at once. It has '
        'not been sent, and is kept here until you send it or discard it. '
        'Record a shorter one, or send it to fewer people.');
    await t.tap(find.byTooltip(en.chatSendVoice));
    await settleUntil(t, () => find.text(refused).evaluate().isNotEmpty,
        what: 'the refusal said, as a voice message\'s');
    await t.tap(onDialog(en.ok));
    await settleUntil(t, () => find.byType(AlertDialog).evaluate().isEmpty,
        what: 'the refusal dismissed');
    expect(kept, findsOneWidget, reason: 'refused, it is kept');
    expect(sentFile(svc, gid), isFalse);

    // Within the budget again, and under the notice: it goes, and is kept
    // no more.
    svc.groupFileNoticeFrom = 128 * 1000 * 1000;
    svc.groupFileLimit = 256 * 1000 * 1000;
    await t.tap(find.byTooltip(en.chatSendVoice));
    await settleUntil(t, () => sentFile(svc, gid), what: 'the voice message sent');
    await settleUntil(t, () => kept.evaluate().isEmpty, what: 'kept no more');
    expect(
        svc.messagesByChat[gid]!.singleWhere((m) => m.kind == 'file').file?.voice,
        isTrue);
    expect((await t.runAsync(() => traces(svc, gid)))!['fan-out rows'], 3,
        reason: 'queued to each member, once');
  });
}
