// 4.9.0 — the chat and group screens say what failed in the reader's words,
// never in the exception's.
//
// Until 2026-10-31 a send, a forward, a reaction, a save or a new group that
// failed put the exception itself on the screen, in English whatever the
// language — for a write the vault refused, SQLite's message, the statement
// with every value it was writing and the database's path — after the
// screen's words for what had failed ("Send failed: " and its kin), or with
// nothing before it when a file was being sent. Each failure is now a line
// of its own in the reader's language (lib/l10n/chat_text.dart): this
// device's storage refusing what was being kept, a voice message or a file
// over the most one message can carry, the camera or the photo library
// refusing Z, or one line for what was being done.
//
// Criteria, each a test below, every line read in English and in Spanish:
//   1. a text, a voice message, a file and a voice message to a group that
//      this device's storage refuses to keep each say so, and a voice
//      message, a file or a voice message to a group over the most one
//      message can carry says that, and how much it is; none is sent;
//   2. a forward and a reaction the storage refuses each say so, and a file
//      that cannot be saved says it could not be saved;
//   3. a group the storage refuses to keep says so on the new-group screen;
//   4. each action's line for each kind of failure — the storage's, the
//      camera's or the photo library's refusing Z, and anything else — and
//      none carries the exception's text;
//   5. no catch in the chat, group or CONNECT screens puts what it caught
//      into a string: their source holds no `$e`, `${e}`, `e.toString()` or
//      `e.message` for any name a catch there binds;
//   6. a group the vault refuses leaves nothing of itself behind, in memory
//      or in the vault, whichever of its writes was refused — the group,
//      its first line, its invite — and nothing after a restart: until
//      2026-11-01 it stayed in the chat list until the app stopped, and in
//      the vault when what was refused came after the group;
//   7. a message's action sheet scrolls: at 360×640, text at twice its
//      size, nothing overflows and every item can be reached, the one at
//      its foot pressed. Until 2026-11-01 it was a column that did not: it
//      overflowed by 2.5 pixels at the test's 800×600, which criterion 2
//      met on a screen 1 600 high, and at 360×640 Edit and Delete for
//      everyone were out of reach and its row of reactions overflowed.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart'
    show EventChannel, MethodChannel, PlatformException;
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart' show DatabaseException;
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/core/voice.dart' show voiceSampleRate;
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/l10n/chat_text.dart';
import 'package:zapp/ui/chat_screen.dart';
import 'package:zapp/ui/group_screens.dart';
import 'package:zapp/ui/theme.dart';

/// The file picker, handing over [bytes] as the file the person chose.
class _HandingPicker extends FilePicker {
  Uint8List bytes = Uint8List(0);

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
  }) async =>
      FilePickerResult(
          [PlatformFile(name: 'clip.bin', size: bytes.length, bytes: bytes)]);

  @override
  Future<bool?> clearTemporaryFiles() async => true;
}

/// What the person reads, in one language: whether each failure was said in
/// a line of its own, as the ARB the screens read has it, and whether any of
/// an exception's own words reached the screen. The lines are read from the
/// ARB, not from the generated class, so that this says the same of a build
/// that has no such line.
class _Reading {
  _Reading(this.t, this.lang, this.seen)
      : _arb = (jsonDecode(File('lib/l10n/app_$lang.arb').readAsStringSync())
                as Map)
            .cast<String, Object?>();

  final WidgetTester t;
  final String lang;
  final List<String> seen;
  final Map<String, Object?> _arb;

  /// An exception's own words: its type, or what dart:io, SQLite and the
  /// service put in one — what these screens showed until 2026-10-31.
  static final leak = RegExp('Exception|Bad state|errno|OS Error|sqlite|'
      'database is locked|INSERT INTO|attachment too large|'
      'no such attachment');

  /// The ARB's line [key], with [args] in it; null when it has none.
  String? line(String key, [Map<String, String> args = const {}]) {
    var s = _arb[key] as String?;
    if (s == null) return null;
    for (final a in args.entries) {
      s = s!.replaceAll('{${a.key}}', a.value);
    }
    return s;
  }

  /// The most one message can carry, as the app writes a size.
  String get limit => line('sizeMb', {
        'mb': (maxAttachmentBytes / 1024 / 1024).toStringAsFixed(1),
      })!;

  List<String> texts() => [
        for (final w in t.widgetList<Text>(find.byType(Text)))
          w.data ?? w.textSpan?.toPlainText() ?? '',
        for (final w
            in t.widgetList<SelectableText>(find.byType(SelectableText)))
          w.data ?? w.textSpan?.toPlainText() ?? '',
      ];

  /// [what] has just failed: was it said in [key]'s line, and did anything
  /// of the exception reach the screen.
  void said(String what, String key, [Map<String, String> args = const {}]) {
    final own = line(key, args);
    final shown = own != null && find.text(own).evaluate().isNotEmpty;
    final leaked = texts().where(leak.hasMatch).toList();
    seen.add('$lang, $what: ${shown ? 'its own line' : 'not its line'}; '
        'exception text: ${leaked.isEmpty ? 'none' : leaked.first}');
  }
}

/// Pump until [cond] holds, letting real work run in between: a widget
/// test's clock is fake, and the vault is real files and a real database.
Future<void> _settleUntil(WidgetTester t, bool Function() cond,
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

/// [act], and the screen let run until it says something; then what it said
/// is read ([key]'s line, with [args]) and put away, for the next.
Future<void> _fails(WidgetTester t, _Reading r, String what, String key,
    Future<void> Function() act,
    [Map<String, String> args = const {}]) async {
  await act();
  await _settleUntil(t, () => find.byType(SnackBar).evaluate().isNotEmpty,
      what: 'something said of $what');
  r.said(what, key, args);
  t
      .state<ScaffoldMessengerState>(find.byType(ScaffoldMessenger))
      .removeCurrentSnackBar();
  await t.pump();
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  final temps = <Directory>[];
  // The microphone: what a recording hears is handed to it here, once the
  // recording has started.
  MockStreamHandlerEventSink? mic;

  setUpAll(() {
    // The chat screen constructs an AudioRecorder, whose plugin does not
    // exist in the test shell. It is answered here, as group_file_fanout_test
    // answers it: a microphone the app may use, a recording whose sound a
    // test hands to [mic], and nulls for the rest.
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
  });

  tearDownAll(() {
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  /// Someone whose link is down for good, for a widget test, put away when it
  /// ends. Nothing here goes anywhere, and no socket is opened under the
  /// test's clock.
  Future<ChatService> person(WidgetTester t, String name) async {
    final svc = (await t.runAsync(() async {
      final dir = await Directory.systemTemp.createTemp('z_cgf_$name');
      temps.add(dir);
      final vault = await Vault.open(rootOverride: dir);
      final identity = await ZIdentity.generate();
      await vault.kvPut('identity', jsonEncode(identity.toJson()));
      final svc = await ChatService.init(
        vault: vault,
        identity: identity,
        displayName: name,
        transport:
            Transport(identity: identity, serverUrl: 'ws://127.0.0.1:1'),
      );
      await svc.transport.stop();
      return svc;
    }))!;
    addTearDown(() => t.runAsync(() async {
          await svc.transport.stop();
          svc.dispose();
          await svc.vault.db.close();
        }));
    return svc;
  }

  /// A contact of [svc]'s called [name], from a fresh identity's code.
  Future<String> contact(ChatService svc, String name) async {
    final id = await ZIdentity.generate();
    final code = (await id.bundle(displayName: name)).encode();
    await svc.addContactFromCode(code);
    return (await ContactBundle.decode(code)).routingId();
  }

  /// [name]'s app on the vault in [dir], outside a widget test: its
  /// identity there, or a new one, and its link down for good.
  Future<ChatService> start(Directory dir, String name) async {
    final vault = await Vault.open(rootOverride: dir);
    final held = await vault.kvGet('identity');
    final identity = held != null
        ? await ZIdentity.fromJson(
            (jsonDecode(held) as Map).cast<String, Object?>())
        : await ZIdentity.generate();
    if (held == null) {
      await vault.kvPut('identity', jsonEncode(identity.toJson()));
    }
    final svc = await ChatService.init(
      vault: vault,
      identity: identity,
      displayName: name,
      transport: Transport(identity: identity, serverUrl: 'ws://127.0.0.1:1'),
    );
    await svc.transport.stop();
    return svc;
  }

  /// [svc]'s app stopped: nothing in memory survives it.
  Future<void> stop(ChatService svc) async {
    await svc.transport.stop();
    svc.dispose();
    await svc.vault.db.close();
  }

  /// [svc]'s storage refusing every new row of [table] (that [when] holds
  /// for) from here on, as a full or locked database does.
  Future<void> refuse(ChatService svc, String table, {String? when}) =>
      svc.vault.db.execute('CREATE TEMP TRIGGER refuse_$table BEFORE INSERT '
          'ON $table ${when == null ? '' : 'WHEN $when '}'
          "BEGIN SELECT RAISE(ABORT, 'database is locked'); END");

  Widget app(ChatService svc, Widget home, Locale locale,
          {double textScale = 1}) =>
      ChangeNotifierProvider<ChatService>.value(
        value: svc,
        child: MaterialApp(
          key: UniqueKey(),
          debugShowCheckedModeBanner: false,
          theme: ZTheme.light(),
          locale: locale,
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          // The size the person set their text to, as the platform hands
          // it over.
          builder: (context, child) => MediaQuery(
            data: MediaQuery.of(context)
                .copyWith(textScaler: TextScaler.linear(textScale)),
            child: child!,
          ),
          home: home,
        ),
      );

  /// [svc]'s chat with [rid] on the screen, and marked open as opening it
  /// marks it — its last write over before anything is asked of the screen,
  /// so that none is left running when the test puts the vault away.
  Future<void> openChat(
      WidgetTester t, ChatService svc, String rid, Locale locale,
      {double textScale = 1}) async {
    var opened = false;
    void heard() {
      if (svc.openChatRid == rid) opened = true;
    }

    svc.addListener(heard);
    await t.pumpWidget(
        app(svc, ChatScreen(rid: rid), locale, textScale: textScale));
    await _settleUntil(t, () => opened, what: 'the chat marked open');
    svc.removeListener(heard);
  }

  /// Record [sound] and send it as a voice message.
  Future<void> recordAndSend(
      WidgetTester t, AppLocalizations l, Uint8List sound) async {
    mic = null;
    await t.tap(find.byTooltip(l.chatRecordVoice));
    await _settleUntil(
        t,
        () =>
            mic != null &&
            find.text(l.chatRecordingHint).evaluate().isNotEmpty,
        what: 'recording');
    mic!.success(sound);
    await t.pump();
    await t.tap(find.byTooltip(l.chatSendVoice));
  }

  testWidgets(
      '1. a message the storage refuses to keep says so, and one over the '
      'limit says that; none is sent', (t) async {
    final seen = <String>[];
    // Two seconds heard, and as much sound as one message can carry, which
    // the voice message's header then takes over it.
    final heard = Uint8List(2 * 2 * voiceSampleRate);
    final tooLong = Uint8List(maxAttachmentBytes);
    for (final lang in const ['en', 'es']) {
      final locale = Locale(lang);
      final l = lookupAppLocalizations(locale);
      final r = _Reading(t, lang, seen);
      final svc = await person(t, 'send$lang');
      late String rid, gid;
      await t.runAsync(() async {
        rid = await contact(svc, 'Pat');
        gid = await svc.createGroup('Two', [rid, await contact(svc, 'Quinn')]);
        await svc.waitForGroupFanout(gid);
        await refuse(svc, 'messages');
      });
      final picker = _HandingPicker();
      FilePicker.platform = picker;

      await t.pumpWidget(app(svc, ChatScreen(rid: rid), locale));
      await _settleUntil(
          t, () => find.byTooltip(l.chatAttachFile).evaluate().isNotEmpty,
          what: 'the composer');
      await _fails(t, r, 'a text the storage refused', 'chatFailedStorage',
          () async {
        await t.enterText(find.byType(TextField), 'Hello');
        await t.tap(find.byIcon(Icons.arrow_upward));
      });
      await _fails(t, r, 'a voice message the storage refused',
          'chatFailedStorage', () => recordAndSend(t, l, heard));
      picker.bytes = Uint8List.fromList(List.generate(4096, (i) => i % 251));
      await _fails(t, r, 'a file the storage refused', 'chatFailedStorage',
          () => t.tap(find.byTooltip(l.chatAttachFile)));
      await _fails(t, r, 'a voice message over the limit', 'chatFileTooLarge',
          () => recordAndSend(t, l, tooLong), {'limit': r.limit});
      picker.bytes = Uint8List(maxAttachmentBytes + 1);
      await _fails(t, r, 'a file over the limit', 'chatFileTooLarge',
          () => t.tap(find.byTooltip(l.chatAttachFile)), {'limit': r.limit});

      await t.pumpWidget(app(svc, ChatScreen(rid: gid), locale));
      await _settleUntil(
          t, () => find.byTooltip(l.chatRecordVoice).evaluate().isNotEmpty,
          what: 'the group\'s composer');
      await _fails(t, r, 'a voice message to a group the storage refused',
          'chatFailedStorage', () => recordAndSend(t, l, heard));
      // Kept, as a voice message to a group that does not go is (48.3):
      // discarded here, to record the next.
      await t.tap(find.byTooltip(l.chatDiscard));
      await t.pump();
      await _fails(t, r, 'a voice message to a group over the limit',
          'chatFileTooLarge', () => recordAndSend(t, l, tooLong),
          {'limit': r.limit});

      final sent = [
        for (final c in [rid, gid])
          ...?svc.messagesByChat[c]?.where((m) =>
              m.outgoing && const {'text', 'gtext', 'file'}.contains(m.kind)),
      ];
      seen.add('$lang: ${sent.isEmpty ? 'nothing' : '${sent.length}'} sent');
      await t.pumpWidget(const SizedBox());
    }

    expect(seen, [
      for (final lang in const ['en', 'es']) ...[
        for (final what in const [
          'a text the storage refused',
          'a voice message the storage refused',
          'a file the storage refused',
          'a voice message over the limit',
          'a file over the limit',
          'a voice message to a group the storage refused',
          'a voice message to a group over the limit',
        ])
          '$lang, $what: its own line; exception text: none',
        '$lang: nothing sent',
      ],
    ]);
  }, timeout: const Timeout(Duration(minutes: 3)));

  testWidgets(
      '2. a forward and a reaction the storage refuses say so, and a file '
      'that cannot be saved says it could not be', (t) async {
    // The test's own 800×600, at which a message's action sheet is a little
    // shorter than its items (criterion 7): Forward is brought into view
    // before it is pressed.
    final seen = <String>[];
    for (final lang in const ['en', 'es']) {
      final locale = Locale(lang);
      final l = lookupAppLocalizations(locale);
      final r = _Reading(t, lang, seen);
      final svc = await person(t, 'acts$lang');
      late String rid, fid;
      await t.runAsync(() async {
        rid = await contact(svc, 'Pat');
        await contact(svc, 'Quinn');
        await svc.sendText(rid, 'Hello');
        await svc.sendFile(
            rid,
            'notes.bin',
            Uint8List.fromList(List.generate(4096, (i) => i % 251)),
            'application/octet-stream');
        fid = svc.messagesByChat[rid]!
            .singleWhere((m) => m.kind == 'file')
            .fid!;
      });

      await t.pumpWidget(app(svc, ChatScreen(rid: rid), locale));
      await _settleUntil(t, () => find.text('Hello').evaluate().isNotEmpty,
          what: 'the chat');
      await t.runAsync(() async {
        await refuse(svc, 'messages');
        await refuse(svc, 'reactions');
      });
      // A sheet's items are pressed once it is up, not while it rises.
      final reply = find.text(l.chatReply).hitTestable();
      final forward = find.text(l.chatForward).hitTestable();
      final quinn = find.text('Quinn').hitTestable();
      final thumbs = find.byTooltip(l.chatReactWith('👍')).hitTestable();
      await t.longPress(find.text('Hello'));
      await _settleUntil(t, () => reply.evaluate().isNotEmpty,
          what: 'what can be done with it');
      await t.ensureVisible(find.text(l.chatForward));
      await _settleUntil(t, () => forward.evaluate().isNotEmpty,
          what: 'Forward, scrolled to');
      await t.tap(forward);
      await _settleUntil(t, () => quinn.evaluate().isNotEmpty,
          what: 'who it can go to');
      await _fails(t, r, 'a forward the storage refused', 'chatFailedStorage',
          () => t.tap(quinn));

      await t.longPress(find.text('Hello'));
      await _settleUntil(t, () => thumbs.evaluate().isNotEmpty,
          what: 'the reactions');
      await _fails(t, r, 'a reaction the storage refused', 'chatFailedStorage',
          () => t.tap(thumbs));

      // The file's sealed copy on this device is gone.
      await t.runAsync(() => svc.vault.blobFile(fid).delete());
      await _fails(t, r, 'a file that could not be saved',
          'chatSaveFailedOther', () => t.tap(find.text(l.save)));
      await t.pumpWidget(const SizedBox());
    }

    expect(seen, [
      for (final lang in const ['en', 'es'])
        for (final what in const [
          'a forward the storage refused',
          'a reaction the storage refused',
          'a file that could not be saved',
        ])
          '$lang, $what: its own line; exception text: none',
    ]);
  }, timeout: const Timeout(Duration(minutes: 3)));

  testWidgets(
      '3. a group the storage refuses to keep says so on the new-group screen',
      (t) async {
    final seen = <String>[];
    for (final lang in const ['en', 'es']) {
      final locale = Locale(lang);
      final l = lookupAppLocalizations(locale);
      final r = _Reading(t, lang, seen);
      final svc = await person(t, 'group$lang');
      await t.runAsync(() async {
        await contact(svc, 'Pat');
        await refuse(svc, 'kv', when: "NEW.k = 's:groups'");
      });

      await t.pumpWidget(app(svc, const CreateGroupScreen(), locale));
      await _settleUntil(t, () => find.text('Pat').evaluate().isNotEmpty,
          what: 'the contacts');
      await t.enterText(find.byType(TextField), 'Book club');
      await t.tap(find.text('Pat'));
      await t.pump();
      await _fails(t, r, 'a group the storage refused', 'chatFailedStorage',
          () => t.tap(find.text(l.grpCreateWithCount(1))));
      await t.pumpWidget(const SizedBox());
    }

    expect(seen, [
      for (final lang in const ['en', 'es'])
        '$lang, a group the storage refused: its own line; exception text: '
            'none',
    ]);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test(
      '4. each action has a line for each kind of failure, and none is the '
      'exception\'s', () async {
    // The storage's and the disk's refusals as they come, from a vault.
    final dir = await Directory.systemTemp.createTemp('z_cgf_kinds');
    temps.add(dir);
    final vault = await Vault.open(rootOverride: dir);
    Object? storage, disk;
    try {
      await vault.db.execute('INSERT INTO nowhere VALUES (1)');
    } catch (e) {
      storage = e;
    }
    try {
      await File('${dir.path}/gone').readAsBytes();
    } catch (e) {
      disk = e;
    }
    await vault.db.close();
    expect(storage, isA<DatabaseException>());
    expect(disk, isA<FileSystemException>());
    // image_picker's, as its Android and iOS sides raise them.
    final kinds = <String, Object>{
      'the storage': storage!,
      'the disk': disk!,
      'the camera refusing Z': PlatformException(
          code: 'camera_access_denied',
          message: 'The user did not allow camera access.'),
      'the photo library refusing Z': PlatformException(
          code: 'photo_access_denied',
          message: 'The user did not allow photo access.'),
      'no camera': PlatformException(
          code: 'no_available_camera',
          message: 'No cameras available for taking pictures.'),
      'anything else': StateError('no such attachment'),
    };

    final seen = <String>[];
    final leaked = <String>[];
    for (final lang in const ['en', 'es']) {
      final l = lookupAppLocalizations(Locale(lang));
      final lines = {
        'chatFailedStorage': l.chatFailedStorage,
        'chatAttachNoAccess': l.chatAttachNoAccess,
        'chatAttachFailed': l.chatAttachFailed,
        'chatSendFailedOther': l.chatSendFailedOther,
        'chatForwardFailedOther': l.chatForwardFailedOther,
        'chatReactionFailedOther': l.chatReactionFailedOther,
        'chatSaveFailedOther': l.chatSaveFailedOther,
        'grpCreateFailedOther': l.grpCreateFailedOther,
      };
      for (final action in ChatAction.values) {
        for (final MapEntry(key: kind, value: error) in kinds.entries) {
          final text = chatFailureText(l, action, error);
          final key = [
            for (final e in lines.entries)
              if (e.value == text) e.key
          ];
          seen.add('$lang, ${action.name}, $kind: '
              '${key.isEmpty ? 'none of its lines' : key.single}');
          final message = error is PlatformException ? error.message : null;
          if (text.contains('$error') ||
              (message != null && text.contains(message)) ||
              _Reading.leak.hasMatch(text)) {
            leaked.add('$lang, ${action.name}, $kind: $text');
          }
        }
      }
    }

    // What each action says, kind by kind, in the order of [kinds].
    const said = {
      ChatAction.send: [
        'chatFailedStorage', 'chatFailedStorage', 'chatSendFailedOther',
        'chatSendFailedOther', 'chatSendFailedOther', 'chatSendFailedOther',
      ],
      ChatAction.forward: [
        'chatFailedStorage', 'chatFailedStorage', 'chatForwardFailedOther',
        'chatForwardFailedOther', 'chatForwardFailedOther',
        'chatForwardFailedOther',
      ],
      ChatAction.react: [
        'chatFailedStorage', 'chatFailedStorage', 'chatReactionFailedOther',
        'chatReactionFailedOther', 'chatReactionFailedOther',
        'chatReactionFailedOther',
      ],
      // A pick writes nothing: the storage is not what refused it.
      ChatAction.attach: [
        'chatAttachFailed', 'chatAttachFailed', 'chatAttachNoAccess',
        'chatAttachNoAccess', 'chatAttachFailed', 'chatAttachFailed',
      ],
      // Nor does a save write to the vault: what it writes is the person's.
      ChatAction.save: [
        'chatSaveFailedOther', 'chatSaveFailedOther', 'chatSaveFailedOther',
        'chatSaveFailedOther', 'chatSaveFailedOther', 'chatSaveFailedOther',
      ],
      ChatAction.createGroup: [
        'chatFailedStorage', 'chatFailedStorage', 'grpCreateFailedOther',
        'grpCreateFailedOther', 'grpCreateFailedOther',
        'grpCreateFailedOther',
      ],
    };
    expect(seen, [
      for (final lang in const ['en', 'es'])
        for (final action in ChatAction.values)
          for (final (i, kind) in kinds.keys.indexed)
            '$lang, ${action.name}, $kind: ${said[action]![i]}',
    ]);
    expect(leaked, isEmpty);
  });

  test(
      '5. no catch in the chat, group or CONNECT screens puts what it caught '
      'into a string', () {
    final found = <String>[];
    for (final name in const [
      'chat_screen.dart',
      'group_screens.dart',
      'connect_tab.dart',
    ]) {
      final lines = File('lib/ui/$name').readAsLinesSync();
      final caught = {
        for (final m in RegExp(r'catch \((\w+)(?:,\s*(\w+))?\)')
            .allMatches(lines.join('\n'))) ...[
          m[1]!,
          if (m[2] != null) m[2]!,
        ],
      }..remove('_');
      // Every one of the three catches something: none found means the
      // pattern no longer reads them, not that they are clean.
      expect(caught, isNotEmpty, reason: '$name: no catch read');
      for (final v in caught) {
        final told = RegExp(r'\$' '$v' r'\b|\$\{' '$v' r'\b|\b' '$v'
            r'\.toString\(\)|\b' '$v' r'\.message\b');
        for (final (i, line) in lines.indexed) {
          if (line.trimLeft().startsWith('//')) continue;
          if (told.hasMatch(line)) found.add('$name:${i + 1}: ${line.trim()}');
        }
      }
    }
    expect(found, isEmpty);
  });

  test(
      '6. a group the vault refuses leaves nothing of itself behind, in '
      'memory or in the vault, whichever of its writes was refused', () async {
    final seen = <String>[];
    for (final (what, table, rows) in const [
      ('the group', 'kv', "NEW.k = 's:groups'"),
      ('its first line', 'messages', null),
      ('its invite', 'group_fanout', null),
    ]) {
      final dir = await Directory.systemTemp.createTemp('z_cgf_none');
      temps.add(dir);
      var svc = await start(dir, 'Gus');
      final rid = await contact(svc, 'Pat');
      await refuse(svc, table, when: rows);
      Object? thrown;
      try {
        await svc.createGroup('Book club', [rid]);
      } catch (e) {
        thrown = e;
      }
      // What is left of it in memory, and in the vault: Pat's thread is the
      // only one there was before.
      final memory = [
        if (svc.groups.isNotEmpty) 'the group',
        if (svc.messagesByChat.keys.any((k) => k != rid)) 'a thread',
        if (svc.unread.keys.any((k) => k != rid)) 'an unread count',
        if (svc.chatSummaries().any((c) => c.group != null))
          'a line in the chat list',
      ];
      final stored = await svc.vault.kvGet('groups');
      Future<int> count(String sql, [List<Object?> args = const []]) async =>
          (await svc.vault.db.rawQuery(sql, args)).first['n'] as int;
      final vault = [
        if (stored != null && (jsonDecode(stored) as List).isNotEmpty)
          'the group',
        if (await count('SELECT COUNT(*) AS n FROM messages WHERE rid != ?',
                [rid]) >
            0)
          'its first line',
        if (await count('SELECT COUNT(*) AS n FROM group_fanout') > 0)
          'its invite',
      ];
      await stop(svc);
      svc = await start(dir, 'Gus');
      final restarted = svc.groups.isEmpty ? 'nothing' : 'the group';
      await stop(svc);
      String said(List<String> left) =>
          left.isEmpty ? 'nothing' : left.join(', ');
      seen.add('$what refused: '
          '${thrown is DatabaseException ? 'the storage refused' : 'thrown: $thrown'}; '
          'in memory: ${said(memory)}; in the vault: ${said(vault)}; '
          'after a restart: $restarted');
    }

    expect(seen, [
      for (final what in const ['the group', 'its first line', 'its invite'])
        '$what refused: the storage refused; in memory: nothing; in the '
            'vault: nothing; after a restart: nothing',
    ]);
  });

  testWidgets(
      '7. a message\'s action sheet scrolls: at 360×640 with text at twice '
      'its size nothing overflows, and every item can be reached', (t) async {
    await t.binding.setSurfaceSize(const Size(360, 640));
    addTearDown(() => t.binding.setSurfaceSize(null));
    final seen = <String>[];
    for (final lang in const ['en', 'es']) {
      final locale = Locale(lang);
      final l = lookupAppLocalizations(locale);
      final svc = await person(t, 'sheet$lang');
      late String rid;
      await t.runAsync(() async {
        rid = await contact(svc, 'Pat');
        await svc.sendText(rid, 'Hello');
      });
      await openChat(t, svc, rid, locale, textScale: 2);
      final overflowBefore = t.takeException();
      final reply = find.text(l.chatReply).hitTestable();
      await t.longPress(find.text('Hello'));
      await _settleUntil(t, () => reply.evaluate().isNotEmpty,
          what: 'the sheet');
      // Up, and still: its rise is a few frames.
      for (var i = 0; i < 20; i++) {
        await t.pump(const Duration(milliseconds: 50));
      }
      // Every item of a message of mine: the six reactions, then the list.
      final items = <(String, Finder)>[
        for (final emoji in ChatService.quickReactions)
          (emoji, find.byTooltip(l.chatReactWith(emoji))),
        for (final label in [
          l.chatReply,
          l.chatCopyText,
          l.chatForward,
          l.chatEdit,
          l.chatDeleteForEveryone,
        ])
          (label, find.text(label)),
      ];
      final unreached = <String>[];
      for (final (what, item) in items) {
        if (item.evaluate().isNotEmpty) await t.ensureVisible(item);
        await t.pump();
        if (item.hitTestable().evaluate().isEmpty) unreached.add(what);
      }
      // The one at its foot, pressed: Delete for everyone asks first.
      final foot = find.text(l.chatDeleteForEveryone).hitTestable();
      var pressed = 'could not be pressed';
      if (foot.evaluate().isNotEmpty) {
        await t.tap(foot);
        await _settleUntil(
            t, () => find.byType(AlertDialog).evaluate().isNotEmpty,
            what: 'its question');
        pressed = 'asks first';
        await t.tap(find.descendant(
            of: find.byType(AlertDialog), matching: find.text(l.cancel)));
        await t.pump(const Duration(milliseconds: 400));
      }
      final overflow = t.takeException();
      seen.add('$lang: overflow: '
          '${overflowBefore == null && overflow == null ? 'none' : 'some'}; '
          'out of reach: ${unreached.isEmpty ? 'nothing' : unreached.join(', ')}; '
          '${l.chatDeleteForEveryone}: $pressed');
      await t.pumpWidget(const SizedBox());
    }

    expect(seen, [
      for (final lang in const ['en', 'es'])
        '$lang: overflow: none; out of reach: nothing; '
            '${lookupAppLocalizations(Locale(lang)).chatDeleteForEveryone}: '
            'asks first',
    ]);
  }, timeout: const Timeout(Duration(minutes: 3)));
}
