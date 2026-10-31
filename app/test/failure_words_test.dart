// What screens say when something they started fails: the first screen,
// Add contact, Backup and Settings (4.9.0); and the screen Z shows when it
// cannot start, the unlock screen, and a transparency log fault in Settings
// and on the home screen (4.9.0b).
//
// Each of them showed the exception it caught, in English whatever the
// reader's language: an identity or a contact the store would not take as
// "DatabaseException(error database_closed)", "Backup failed: ", "Could not
// save: " and "Could not enable: " before the error, the relay's status as
// "Offline (SocketException: Connection refused (OS Error: ...))", and a
// mistyped recovery code as the parser's English. Each says why in the
// reader's words now (`lib/l10n/failure_text.dart`), and none shows an
// exception's text. So, since 4.9.0b, do the screen Z shows when it cannot
// start ("Z could not start:" and the error), the unlock screen (the error,
// as it came), and a log fault, which showed the log client's English words
// for it (`lib/l10n/kt_fault_text.dart`): those words are the evidence, and
// Settings keeps them, untranslated, behind the fault's details.
//
// Criteria 1 to 5 drive a real screen into the failure, in English and in
// Spanish, and read the words they expect from the ARB files as they run,
// so that a build without them says what it showed instead; criterion 6
// holds every mapping to its words.
//
// Criteria, each a test below:
//   1. the first screen, on a store that refuses every write, says it could
//      not set up the identity;
//   2. a restore whose recovery code is not one says why — its length, a
//      character in no code, a typo — and one whose code does not open the
//      backup says the restore failed;
//   3. Add contact, on a store that refuses the write, says this device
//      could not add the contact;
//   4. the backup screen says a backup that could not be written, a copy
//      that could not be saved, and a code typed back, or typed to turn
//      automatic backups on, that is not one — its length;
//   5. Settings says biometric unlock could not be turned on, and why the
//      relay is offline — it cannot be reached, or this device could not
//      sign in to it;
//   6. every failure's words, in English and in Spanish, from what failed,
//      and no exception text in any of them;
//   7. the app, started on a store whose database cannot be opened, or that
//      the key this device keeps does not open, says so, in English and in
//      Spanish, and not as the error;
//   8. the unlock screen, given the passphrase of a store whose database
//      cannot be opened, says so, in English and in Spanish, and not as the
//      error;
//   9. Settings and the home screen say what a log fault is about — a log
//      gone back, an answer about this account that is no answer — in
//      English and in Spanish, with none of the log client's own words; its
//      details show those words as recorded, untranslated, and Copy carries
//      them with the heads the client compared;
//  10. every startup, unlock and log fault's words, in English and in
//      Spanish, from what failed, and a fault stored before faults had a
//      kind read as one of no kind, its words and heads as they were;
//  11. the backup screen, on a backup folder that cannot be written, says
//      the backup was not written, in English and in Spanish, and no error
//      gets past it (4.9.1);
//  12. the save dialog that a copy of the backup opens is titled in the
//      reader's language;
//  13. the backup screen, asked to turn automatic backups on or off on a
//      store that refuses, says so in English and in Spanish, and they stay
//      as they were.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:cryptography/cryptography.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/app_lock.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/key_transparency.dart';
import 'package:zapp/core/models.dart';
import 'package:zapp/core/prefs.dart';
import 'package:zapp/core/push_service.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/l10n/failure_text.dart';
import 'package:zapp/l10n/kt_fault_text.dart';
import 'package:zapp/l10n/refusal_text.dart';
import 'package:zapp/main.dart' as zmain;
import 'package:zapp/ui/add_contact_screen.dart';
import 'package:zapp/ui/backup_screen.dart';
import 'package:zapp/ui/home_screen.dart';
import 'package:zapp/ui/onboarding_screen.dart';
import 'package:zapp/ui/settings_screen.dart';
import 'package:zapp/ui/theme.dart';
import 'package:zapp/ui/unlock_screen.dart';

/// The file picker as Android's hands a pick over (file_picker 8.3.7): the
/// chosen file copied into the cache, the copy what the app is handed. A
/// save hands back [savePath], a place nothing can be written.
class FakePicker extends FilePicker {
  FakePicker(this.cache);
  final Directory cache;
  List<int> contents = const [];
  String savePath = '/nonexistent/z-failure-words/backup.zbk';

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
    final copy = File('${cache.path}/file_picker/'
        '${DateTime.now().microsecondsSinceEpoch}/backup.zbk')
      ..createSync(recursive: true)
      ..writeAsBytesSync(contents);
    return FilePickerResult([
      PlatformFile(path: copy.path, name: 'backup.zbk', size: contents.length)
    ]);
  }

  @override
  Future<bool?> clearTemporaryFiles() async => true;

  /// The title the last save dialog was opened with.
  String? savedTitle;

  @override
  Future<String?> saveFile({
    String? dialogTitle,
    String? fileName,
    String? initialDirectory,
    FileType type = FileType.any,
    List<String>? allowedExtensions,
    Uint8List? bytes,
    bool lockParentWindow = false,
  }) async {
    savedTitle = dialogTitle;
    return savePath;
  }
}

/// The OS prompt, there and refusing: what a device whose biometrics went
/// away under the app says.
class RefusingGate implements BiometricGate {
  @override
  Future<bool> get isAvailable async => true;
  @override
  Future<GateResult> authenticate(String reason) async =>
      throw PlatformException(code: 'NotAvailable', message: 'no biometrics');
}

/// No hardware key on this device.
class NoBoundKeys implements BoundKeyStore {
  @override
  Future<bool> get available async => false;
  @override
  Future<BoundBlob> seal(Uint8List secret) =>
      throw const BoundKeyException('unavailable');
  @override
  Future<Uint8List> open(BoundBlob blob) =>
      throw const BoundKeyException('unavailable');
  @override
  Future<void> forget() async {}
}

/// A transparency log on loopback that this file answers for: the head it
/// is given, the lookup answer it is given, and nothing else.
class FakeLog implements KtFetcher {
  String? sth;
  String? lookup;

  @override
  Future<KtResponse> get(Uri url) async {
    if (url.path.endsWith('/kt/v1/sth')) {
      return sth == null ? KtResponse(503, '{}') : KtResponse(200, sth!);
    }
    if (url.path.contains('/kt/v1/lookup/') && lookup != null) {
      return KtResponse(200, lookup!);
    }
    return KtResponse(404, '{}');
  }

  @override
  Future<KtResponse> post(Uri url, String body) async => KtResponse(404, '{}');
}

/// A head of [size] that [key] really signed, so only what it says is in
/// doubt.
Future<KtTreeHead> signedHead(SimpleKeyPair key,
    {required int size, required int ts}) async {
  final unsigned = KtTreeHead(
    size: size,
    logRoot: Uint8List(32)..[0] = size,
    mapRoot: Uint8List(32)..[1] = size,
    ts: ts,
    sig: Uint8List(64),
  );
  final sig = await Ed25519().sign(unsigned.signingInput, keyPair: key);
  return KtTreeHead(
    size: size,
    logRoot: unsigned.logRoot,
    mapRoot: unsigned.mapRoot,
    ts: ts,
    sig: Uint8List.fromList(sig.bytes),
  );
}

/// Pump until [cond] holds, letting real work run in between: a widget
/// test's clock is fake, and the vault is real files and a real database.
/// [step] is how far each round moves the test's clock.
Future<void> settleUntil(WidgetTester t, bool Function() cond,
    {required String what,
    Duration step = const Duration(milliseconds: 16),
    Duration timeout = const Duration(seconds: 30)}) async {
  final deadline = DateTime.now().add(timeout);
  await t.pump();
  while (!cond()) {
    if (DateTime.now().isAfter(deadline)) {
      throw TimeoutException('condition not met: $what', timeout);
    }
    await t.runAsync(
        () => Future<void>.delayed(const Duration(milliseconds: 40)));
    await t.pump(step);
  }
}

/// An exception's text on the screen: what none of these may show.
final rawText =
    RegExp(r'Exception|Error\(|errno|OS Error|Instance of|database_closed');

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final temps = <Directory>[];

  tearDownAll(() {
    for (final d in temps) {
      try {
        if (d.existsSync()) d.deleteSync(recursive: true);
      } catch (_) {}
    }
  });

  Directory temp(String name) {
    final d = Directory.systemTemp.createTempSync('z_fw_$name');
    temps.add(d);
    return d;
  }

  /// The words [key] has in [lang]'s ARB, its placeholders filled from
  /// [args]; null when the ARB has no such key.
  String? arb(String lang, String key, [Map<String, Object> args = const {}]) {
    final j = jsonDecode(File('lib/l10n/app_$lang.arb').readAsStringSync())
        as Map;
    var s = j[key] as String?;
    if (s == null) return null;
    args.forEach((k, v) => s = s!.replaceAll('{$k}', '$v'));
    return s;
  }

  /// [key]'s words in [lang], or a string no screen shows when the ARB has
  /// none, so that a build without them fails saying what it showed.
  String words(String lang, String key, [Map<String, Object> args = const {}]) =>
      arb(lang, key, args) ?? '\u0000(no words for $key)';

  Widget app(String lang, Widget home) => MaterialApp(
        locale: Locale(lang),
        debugShowCheckedModeBanner: false,
        theme: ZTheme.light(),
        localizationsDelegates: AppLocalizations.localizationsDelegates,
        supportedLocales: AppLocalizations.supportedLocales,
        home: home,
      );

  /// A service over its own vault whose relay is [relay] — a closed port
  /// unless said — with the transparency log off.
  Future<ChatService> service(String name,
      {String relay = 'ws://127.0.0.1:1'}) async {
    final vault = await Vault.open(rootOverride: temp(name));
    final id = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(id.toJson()));
    return ChatService.init(
        vault: vault,
        identity: id,
        displayName: name,
        transport: Transport(identity: id, serverUrl: relay),
        ktConfig: KtConfig.off);
  }

  Future<void> stop(WidgetTester t, ChatService svc) =>
      t.runAsync(() async {
        await svc.transport.stop();
        svc.dispose();
        try {
          await svc.vault.db.close();
        } catch (_) {}
      });

  /// The backup screen in [lang] over [svc], with one archive already in
  /// its folder so that the screen offers a copy of it once its store is
  /// open: what says it is ready. Returns the folder.
  Future<Directory> openBackup(
      WidgetTester t, String lang, ChatService svc) async {
    final l = lookupAppLocalizations(Locale(lang));
    final backups = Directory('${svc.vault.root.path}/backups');
    await t.runAsync(() async {
      await backups.create(recursive: true);
      await File('${backups.path}/z-backup-20261031-120000.zbk')
          .writeAsString('an archive');
    });
    await t.pumpWidget(ChangeNotifierProvider<ChatService>.value(
        value: svc, child: app(lang, const BackupScreen())));
    await settleUntil(
        t, () => find.text(l.backupSaveCopy).evaluate().isNotEmpty,
        what: '$lang: the backup screen, its store open');
    return backups;
  }

  /// Takes the word just said off the screen, so the next is not queued
  /// behind it.
  Future<void> dismissWord(WidgetTester t) async {
    t
        .state<ScaffoldMessengerState>(find.byType(ScaffoldMessenger))
        .removeCurrentSnackBar();
    await t.pump();
  }

  /// Creates a backup on the backup screen: the code shown, and typed back.
  Future<void> createBackup(WidgetTester t, AppLocalizations l,
      {required String what}) async {
    await t.tap(find.text(l.backupCreate));
    await settleUntil(
        t, () => find.text(l.backupCodeWritten).evaluate().isNotEmpty,
        what: '$what: the code shown');
    final shown = t
        .widget<SelectableText>(find.descendant(
            of: find.byType(AlertDialog), matching: find.byType(SelectableText)))
        .data!;
    await t.tap(find.text(l.backupCodeWritten));
    await settleUntil(
        t, () => find.text(l.backupConfirmTitle).evaluate().isNotEmpty,
        what: '$what: the code asked back');
    await t.enterText(
        find.descendant(
            of: find.byType(AlertDialog), matching: find.byType(TextField)),
        shown);
    await t.tap(find.text(l.confirm));
  }

  /// The automatic backups switch on the backup screen.
  bool autoIsOn(WidgetTester t, AppLocalizations l) => t
      .widget<SwitchListTile>(find.widgetWithText(SwitchListTile, l.backupAuto))
      .value;

  /// Flips the automatic backups switch, typing [code] when it asks for one.
  Future<void> flipAuto(WidgetTester t, AppLocalizations l,
      {String? code, required String what}) async {
    final auto = find.text(l.backupAuto);
    await t.ensureVisible(auto);
    await t.pump();
    await t.tap(auto);
    if (code == null) return;
    await settleUntil(
        t, () => find.text(l.backupAskCodeTitle).evaluate().isNotEmpty,
        what: '$what: the code asked for');
    await t.enterText(
        find.descendant(
            of: find.byType(AlertDialog), matching: find.byType(TextField)),
        code);
    await t.tap(find.text(l.backupAskCodeTurnOn));
  }

  /// A service over its own vault whose transparency log is [log], on
  /// loopback under [config]; its relay a closed port.
  Future<ChatService> ktService(
      String name, FakeLog log, KtConfig config) async {
    final vault = await Vault.open(rootOverride: temp(name));
    final id = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(id.toJson()));
    return ChatService.init(
        vault: vault,
        identity: id,
        displayName: name,
        transport: Transport(identity: id, serverUrl: 'ws://127.0.0.1:1'),
        ktConfig: config,
        ktFetcher: log);
  }

  /// The app as it starts, its store under [dir]: the platform's
  /// application-support directory, here a temp one.
  void startOn(WidgetTester t, Directory dir) {
    const pathChannel = MethodChannel('plugins.flutter.io/path_provider');
    t.binding.defaultBinaryMessenger
        .setMockMethodCallHandler(pathChannel, (call) async => dir.path);
    addTearDown(() => t.binding.defaultBinaryMessenger
        .setMockMethodCallHandler(pathChannel, null));
    // An operating system with no audio backend to load, so that no notice
    // about one sits above the screen.
    zmain.startApp(operatingSystem: 'android');
  }

  /// Where the database of the store under [z] was, a directory: SQLite
  /// cannot open it.
  Future<void> spoilDatabase(Directory z) async {
    await File('${z.path}/z.db').delete();
    await Directory('${z.path}/z.db').create();
  }

  /// Every line of text on the screen, for a failure to say what it showed.
  List<String> onScreen() => [
        for (final e in find.byType(Text).evaluate())
          if ((e.widget as Text).data case final s?) s,
      ];

  /// What a screen says: [want] shown, and no exception's text.
  Future<void> says(WidgetTester t, String want, String what,
      {Duration step = const Duration(milliseconds: 16)}) async {
    try {
      await settleUntil(
          t,
          () =>
              find.text(want).evaluate().isNotEmpty ||
              find.textContaining(rawText).evaluate().isNotEmpty,
          what: what,
          step: step);
    } on TimeoutException {
      fail('$what: not said within 30 s; the screen said ${onScreen()}');
    }
    expect(find.textContaining(rawText), findsNothing,
        reason: '$what: no exception text on the screen');
    expect(find.text(want), findsOneWidget, reason: '$what: in its words');
  }

  testWidgets(
      '1. the first screen, on a store that refuses every write, says it '
      'could not set up the identity', (t) async {
    for (final lang in ['en', 'es']) {
      final l = lookupAppLocalizations(Locale(lang));
      final vault = (await t.runAsync(() async {
        final v = await Vault.open(rootOverride: temp('create_$lang'));
        await v.db.close();
        return v;
      }))!;
      await t.pumpWidget(
          app(lang, OnboardingScreen(vault: vault, onDone: () async {})));
      await t.pump();
      await t.enterText(
          find.widgetWithText(TextField, l.onbDisplayName), 'Alice');
      await t.tap(find.text(l.onbCreateIdentity));
      await says(t, words(lang, 'onbCreateFailed'),
          '$lang: an identity the store would not take');
    }
    await t.pumpWidget(const SizedBox());
  });

  testWidgets(
      '2. a restore whose recovery code is not one says why, and one whose '
      'code does not open the backup says the restore failed', (t) async {
    // A code with one character changed, its checksum no longer matching:
    // a typo, found by the parser's own refusal.
    final (good, typo) = (await t.runAsync(() async {
      final good = await (await RecoveryCode.generate()).format();
      for (var i = good.length - 2; i > 4; i--) {
        if (good[i] == '-') continue;
        for (final c in RecoveryCode.alphabet.split('')) {
          final candidate = good.replaceRange(i, i + 1, c);
          try {
            await RecoveryCode.parse(candidate);
          } on FormatException catch (e) {
            if (e.message.contains('typo')) return (good, candidate);
          }
        }
      }
      throw StateError('no typo found');
    }))!;
    // Spanish first: where the parser's English showed through.
    for (final lang in ['es', 'en']) {
      final l = lookupAppLocalizations(Locale(lang));
      final picker = FakePicker(temp('restore_cache_$lang'))
        ..contents = utf8.encode('{"z":"zbk","v":1}\nthe rest of an archive');
      FilePicker.platform = picker;
      final vault = (await t
          .runAsync(() => Vault.open(rootOverride: temp('restore_$lang'))))!;
      await t.pumpWidget(
          app(lang, OnboardingScreen(vault: vault, onDone: () async {})));
      await t.pump();
      for (final (what, code, key, args) in [
        ('too short', 'ZBK-AAAAA', 'recoveryCodeLength',
            <String, Object>{'total': 25, 'count': 5}),
        ('a character in no code', 'U' * 25, 'recoveryCodeCharacter',
            <String, Object>{'character': 'U'}),
        ('a typo', typo, 'recoveryCodeTypo', <String, Object>{}),
        ('a code that does not open it', good, 'onbRestoreFailed',
            <String, Object>{}),
      ]) {
        final button = find.text(l.onbRestoreFromBackup);
        await t.ensureVisible(button);
        await t.pump();
        await t.tap(button);
        await settleUntil(
            t, () => find.text(l.onbRecoveryCode).evaluate().isNotEmpty,
            what: '$lang, $what: the recovery-code dialog');
        await t.enterText(
            find.descendant(
                of: find.byType(AlertDialog), matching: find.byType(TextField)),
            code);
        await t.tap(find.text(l.onbRestore));
        await settleUntil(
            t, () => find.text(l.onbRecoveryCode).evaluate().isEmpty,
            what: '$lang, $what: the dialog gone');
        await says(t, words(lang, key, args), '$lang, $what');
      }
      await t.pumpWidget(const SizedBox());
      await t.runAsync(() => vault.db.close());
    }
  });

  testWidgets(
      '3. Add contact, on a store that refuses the write, says this device '
      'could not add the contact', (t) async {
    for (final lang in ['en', 'es']) {
      final l = lookupAppLocalizations(Locale(lang));
      final svc = (await t.runAsync(() => service('Lola_$lang')))!;
      final omar = (await t.runAsync(() => service('Omar_$lang')))!;
      final code = (await t.runAsync(omar.myContactCode))!;
      await stop(t, omar);
      await t.pumpWidget(ChangeNotifierProvider<ChatService>.value(
          value: svc, child: app(lang, const AddContactScreen())));
      await t.tap(find.text(l.addPaste));
      await settleUntil(
          t, () => find.text(l.addVerifyAndAdd).evaluate().isNotEmpty,
          what: '$lang: the Paste tab');
      final tabs = t.widget<TabBar>(find.byType(TabBar)).controller!;
      await settleUntil(t, () => tabs.index == 1 && !tabs.indexIsChanging,
          what: '$lang: the switch to the Paste tab');
      // The store refuses the write from here: its database is closed, the
      // service's own connection stopped first.
      await t.runAsync(() async {
        await svc.transport.stop();
        await svc.vault.db.close();
      });
      await t.enterText(find.byType(TextField).first, code);
      await t.tap(find.text(l.addVerifyAndAdd));
      await says(t, words(lang, 'addFailedOther'),
          '$lang: a contact the store would not take');
      await t.pumpWidget(const SizedBox());
      await stop(t, svc);
    }
  });

  testWidgets(
      '4. the backup screen says a backup that could not be written, a copy '
      'that could not be saved, and a code that is not one', (t) async {
    for (final lang in ['en', 'es']) {
      final l = lookupAppLocalizations(Locale(lang));
      final picker = FakePicker(temp('backup_cache_$lang'));
      FilePicker.platform = picker;
      final svc = (await t.runAsync(() => service('Bea_$lang')))!;
      // A backup already in the folder, so that the screen offers a copy of
      // it once it has opened its store: what says it is ready.
      final backups = Directory('${svc.vault.root.path}/backups');
      await t.runAsync(() async {
        await backups.create(recursive: true);
        await File('${backups.path}/z-backup-20261031-120000.zbk')
            .writeAsString('an archive');
      });
      await t.pumpWidget(ChangeNotifierProvider<ChatService>.value(
          value: svc, child: app(lang, const BackupScreen())));
      await settleUntil(
          t, () => find.text(l.backupSaveCopy).evaluate().isNotEmpty,
          what: '$lang: the backup screen, its store open');

      /// Takes the word just said off the screen, so the next is not queued
      /// behind it.
      Future<void> dismiss() async {
        t
            .state<ScaffoldMessengerState>(find.byType(ScaffoldMessenger))
            .removeCurrentSnackBar();
        await t.pump();
      }

      /// Shows a code and types [typed] back, or the code itself.
      Future<void> create({String? typed, required String what}) async {
        await t.tap(find.text(l.backupCreate));
        await settleUntil(
            t, () => find.text(l.backupCodeWritten).evaluate().isNotEmpty,
            what: '$what: the code shown');
        final shown = t
            .widget<SelectableText>(find.descendant(
                of: find.byType(AlertDialog),
                matching: find.byType(SelectableText)))
            .data!;
        await t.tap(find.text(l.backupCodeWritten));
        await settleUntil(
            t, () => find.text(l.backupConfirmTitle).evaluate().isNotEmpty,
            what: '$what: the code asked back');
        await t.enterText(
            find.descendant(
                of: find.byType(AlertDialog), matching: find.byType(TextField)),
            typed ?? shown);
        await t.tap(find.text(l.confirm));
      }

      // (b) A copy handed to a place nothing can be written.
      await t.tap(find.text(l.backupSaveCopy));
      await says(t, words(lang, 'backupSaveFailed'),
          '$lang: a copy that could not be saved');
      await dismiss();
      // (c) The code typed back is not one: said in the dialog.
      await create(typed: 'ZBK-AAAAA', what: '$lang, a code typed back');
      await says(
          t,
          words(lang, 'recoveryCodeLength',
              <String, Object>{'total': 25, 'count': 5}),
          '$lang: a code typed back that is not one');
      await t.tap(find.text(l.back));
      await settleUntil(
          t, () => find.text(l.backupConfirmTitle).evaluate().isEmpty,
          what: '$lang: the dialog closed');
      // (a) A store that cannot be read, so no backup can be written: its
      // database closed, the service's own connection stopped first. (A
      // folder that cannot be written is criterion 11's.)
      await t.runAsync(() async {
        await svc.transport.stop();
        await svc.vault.db.close();
      });
      await create(what: '$lang, a backup that cannot be written');
      await says(t, words(lang, 'backupFailed'),
          '$lang: a backup that could not be written');
      await dismiss();
      // (d) Automatic backups asked for with a code that is not one.
      final auto = find.text(l.backupAuto);
      await t.ensureVisible(auto);
      await t.pump();
      await t.tap(auto);
      await settleUntil(
          t, () => find.text(l.backupAskCodeTitle).evaluate().isNotEmpty,
          what: '$lang: the code asked for');
      await t.enterText(
          find.descendant(
              of: find.byType(AlertDialog), matching: find.byType(TextField)),
          'ZBK-AAAAA');
      await t.tap(find.text(l.backupAskCodeTurnOn));
      await says(
          t,
          words(lang, 'recoveryCodeLength',
              <String, Object>{'total': 25, 'count': 5}),
          '$lang: a code for automatic backups that is not one');
      await t.pumpWidget(const SizedBox());
      await stop(t, svc);
    }
  });

  testWidgets(
      '5. Settings says biometric unlock could not be turned on, and why the '
      'relay is offline', (t) async {
    // A relay this build cannot sign in to: it asks for an authentication
    // this client will not give, as a relay too old for it does.
    final old = (await t.runAsync(() async {
      final s = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      s.listen((req) async {
        final ws = await WebSocketTransformer.upgrade(req);
        ws.add(jsonEncode({
          't': 'challenge',
          'nonce': b64(randomBytes(32)),
          'auth': 1,
        }));
        ws.listen((_) {}, onError: (Object _) {});
      });
      return s;
    }))!;
    addTearDown(() => t.runAsync(() => old.close(force: true)));
    for (final lang in ['en', 'es']) {
      final l = lookupAppLocalizations(Locale(lang));
      for (final (what, relay, key) in [
        ('a relay that cannot be reached', 'ws://127.0.0.1:1',
            'stRelayOfflineUnreachable'),
        ('a relay it cannot sign in to', 'ws://127.0.0.1:${old.port}',
            'stRelayOfflineRefused'),
      ]) {
        final dir = temp('settings_$lang');
        final svc = (await t.runAsync(
            () => service('Sam_$lang', relay: relay)))!;
        await t.runAsync(() async {
          final deadline = DateTime.now().add(const Duration(seconds: 20));
          while (svc.transport.lastError == null &&
              DateTime.now().isBefore(deadline)) {
            await Future<void>.delayed(const Duration(milliseconds: 20));
          }
          await svc.vault.setPassphrase('a passphrase of some length');
        });
        final prefs = AppPrefs(root: dir);
        await t.runAsync(prefs.load);
        final lock =
            AppLock(root: dir, gate: RefusingGate(), store: MemorySecretStore(),
                bound: NoBoundKeys());
        await t.pumpWidget(MultiProvider(
          providers: [
            ChangeNotifierProvider<ChatService>.value(value: svc),
            ChangeNotifierProvider<Transport>.value(value: svc.transport),
            ChangeNotifierProvider<PushService>.value(
                value: PushService(transport: svc.transport, vault: svc.vault)),
            ChangeNotifierProvider<AppLock>.value(value: lock),
            ChangeNotifierProvider<AppPrefs>.value(value: prefs),
          ],
          child: app(lang, const SettingsScreen()),
        ));
        await settleUntil(
            t, () => find.text(l.stSettings).evaluate().isNotEmpty,
            what: '$lang: the Settings screen');
        await says(t, words(lang, key), '$lang: $what');
        if (relay.endsWith(':1')) {
          // Biometric unlock, turned on where the system refuses it.
          final row = find.text(l.stBiometric);
          await t.scrollUntilVisible(row, 200,
              scrollable: find.byType(Scrollable).first);
          await t.pump();
          await t.tap(row);
          await settleUntil(
              t, () => find.text(l.stEnterPassphrase).evaluate().isNotEmpty,
              what: '$lang: the passphrase asked for');
          await t.enterText(
              find.descendant(
                  of: find.byType(AlertDialog),
                  matching: find.byType(TextField)),
              'a passphrase of some length');
          await t.tap(find.text(l.ok));
          await says(t, words(lang, 'stCouldNotEnable'),
              '$lang: biometric unlock the system refused',
              step: const Duration(milliseconds: 100));
        }
        await t.pumpWidget(const SizedBox());
        await stop(t, svc);
      }
    }
  });

  test(
      '6. every failure says why in English and in Spanish, from what failed, '
      'with no exception text', () {
    final en = lookupAppLocalizations(const Locale('en'));
    final es = lookupAppLocalizations(const Locale('es'));
    for (final l in [en, es]) {
      final shown = <String>[];
      String keep(String s) {
        shown.add(s);
        return s;
      }

      // A recovery code that is not one, wherever one is asked for.
      expect(
          keep(recoveryCodeText(
              l,
              const RecoveryCodeInvalid(RecoveryCodeProblem.length, 'x',
                  length: 5))),
          l.recoveryCodeLength(RecoveryCode.totalChars, 5));
      expect(
          keep(recoveryCodeText(
              l,
              const RecoveryCodeInvalid(RecoveryCodeProblem.character, 'x',
                  character: 'U'))),
          l.recoveryCodeCharacter('U'));
      expect(
          keep(recoveryCodeText(l,
              const RecoveryCodeInvalid(RecoveryCodeProblem.checksum, 'x'))),
          l.recoveryCodeTypo);
      expect(keep(recoveryCodeText(l, const FormatException('x'))),
          l.recoveryCodeTypo);
      // A restore: a code that is not one says why; anything else, that the
      // restore failed.
      expect(
          keep(restoreFailureText(
              l,
              const RecoveryCodeInvalid(RecoveryCodeProblem.length, 'x',
                  length: 3))),
          l.recoveryCodeLength(RecoveryCode.totalChars, 3));
      for (final other in <Object>[
        const FormatException('wrong recovery code, or the archive is damaged'),
        StateError('something nobody expected'),
      ]) {
        expect(keep(restoreFailureText(l, other)), l.onbRestoreFailed);
      }
      // Add contact: a refused code says its refusal; one that does not
      // decode, that it did not verify; anything else, that this device
      // could not add the contact.
      const refused =
          ContactCodeRefused(ContactCodeRefusal.ownCode, '', 'your own code');
      expect(keep(addContactFailureText(l, refused)),
          contactCodeRefusalText(l, refused));
      expect(keep(addContactFailureText(l, const FormatException('bad'))),
          l.addRefusedInvalidCode);
      expect(
          keep(addContactFailureText(
              l, const FileSystemException('disk full'))),
          l.addFailedOther);
      // The relay's status: none to say, one that cannot be reached at all,
      // one it reached but could not sign in to, and anything else as
      // offline.
      expect(keep(relayOfflineText(l, null)), l.stRelayOffline);
      for (final unreachable in <Object>[
        const SocketException('Connection refused'),
        const WebSocketException('was not upgraded to websocket'),
        const HandshakeException('Handshake error in client'),
        const TlsException('certificate'),
        const HttpException('Connection closed before full header'),
        TimeoutException('no challenge'),
      ]) {
        expect(keep(relayOfflineText(l, unreachable)),
            l.stRelayOfflineUnreachable,
            reason: '$unreachable');
      }
      expect(keep(relayOfflineText(l, RelayException('auth failed: x'))),
          l.stRelayOfflineRefused);
      expect(keep(relayOfflineText(l, StateError('x'))), l.stRelayOffline);
      // The words that have no cause of their own to name.
      shown.addAll([
        l.onbCreateFailed,
        l.backupFailed,
        l.backupSaveFailed,
        l.stCouldNotEnable,
      ]);
      for (final s in shown) {
        expect(s, isNot(matches(rawText)), reason: s);
        expect(s, isNot(contains('nobody expected')), reason: s);
        expect(s, isNot(contains('disk full')), reason: s);
      }
    }
    // Each language has its own words for each.
    for (final (a, b) in [
      (es.onbCreateFailed, en.onbCreateFailed),
      (es.addFailedOther, en.addFailedOther),
      (es.recoveryCodeLength(25, 5), en.recoveryCodeLength(25, 5)),
      (es.recoveryCodeCharacter('U'), en.recoveryCodeCharacter('U')),
      (es.recoveryCodeTypo, en.recoveryCodeTypo),
      (es.backupFailed, en.backupFailed),
      (es.backupSaveFailed, en.backupSaveFailed),
      (es.stCouldNotEnable, en.stCouldNotEnable),
      (es.stRelayOfflineUnreachable, en.stRelayOfflineUnreachable),
      (es.stRelayOfflineRefused, en.stRelayOfflineRefused),
    ]) {
      expect(a, isNot(b), reason: 'the Spanish has words of its own');
    }
    // The count and the character are in the words.
    for (final l in [en, es]) {
      expect(l.recoveryCodeLength(25, 7), contains('25'));
      expect(l.recoveryCodeLength(25, 7), contains('7'));
      expect(l.recoveryCodeCharacter('U'), contains('U'));
    }
  });

  testWidgets(
      '7. the app, started on a store it cannot open, says why in the '
      "reader's language and not as the error", (t) async {
    addTearDown(t.platformDispatcher.clearLocalesTestValue);
    for (final (what, spoil, key)
        in <(String, Future<void> Function(Directory), String)>[
      (
        'a store whose database cannot be opened',
        spoilDatabase,
        'startupFailedStorage',
      ),
      (
        'a store the key this device keeps does not open',
        // Another key where this device keeps its own: in a test, the file
        // the system keystore falls back to.
        (z) => File('${z.path}/.device').writeAsString(b64(randomBytes(32))),
        'startupFailedKey',
      ),
    ]) {
      final dir = temp('start');
      await t.runAsync(() async {
        final z = Directory('${dir.path}/z');
        final v = await Vault.open(rootOverride: z);
        await v.db.close();
        await spoil(z);
      });
      startOn(t, dir);
      await says(t, words('en', key), 'en: $what');
      t.platformDispatcher.localesTestValue = const [Locale('es')];
      await t.pump();
      await says(t, words('es', key), 'es: $what');
      t.platformDispatcher.clearLocalesTestValue();
      await t.pumpWidget(const SizedBox());
    }
  });

  testWidgets(
      '8. the unlock screen, given the passphrase of a store whose database '
      "cannot be opened, says so in the reader's language and not as the "
      'error', (t) async {
    addTearDown(t.platformDispatcher.clearLocalesTestValue);
    const passphrase = 'a passphrase of some length';
    final dir = temp('unlock');
    await t.runAsync(() async {
      final z = Directory('${dir.path}/z');
      final v = await Vault.open(rootOverride: z);
      await v.setPassphrase(passphrase);
      await v.db.close();
      await spoilDatabase(z);
    });
    startOn(t, dir);
    final en = lookupAppLocalizations(const Locale('en'));
    await settleUntil(
        t, () => find.byType(UnlockScreen).evaluate().isNotEmpty,
        what: 'the unlock screen');
    await t.enterText(find.byType(TextField), passphrase);
    await t.tap(find.widgetWithText(FilledButton, en.unlockTitle));
    const what = 'a store whose database cannot be opened';
    await says(t, words('en', 'unlockFailedStorage'), 'en: $what');
    t.platformDispatcher.localesTestValue = const [Locale('es')];
    await t.pump();
    await says(t, words('es', 'unlockFailedStorage'), 'es: $what');
    t.platformDispatcher.clearLocalesTestValue();
    await t.pumpWidget(const SizedBox());
  });

  testWidgets(
      '9. Settings and the home screen say what a log fault is about, and '
      "keep the log client's own words behind its details", (t) async {
    String? copied;
    t.binding.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, (call) async {
      if (call.method == 'Clipboard.setData') {
        copied = (call.arguments as Map)['text'] as String?;
      }
      return null;
    });
    addTearDown(() => t.binding.defaultBinaryMessenger
        .setMockMethodCallHandler(SystemChannels.platform, null));
    final key = (await t.runAsync(() => Ed25519().newKeyPair()))!;
    final logPub = (await t.runAsync(() async =>
        Uint8List.fromList((await key.extractPublicKey()).bytes)))!;
    final config =
        KtConfig(logUrl: 'http://127.0.0.1:9', logPubB64: b64(logPub));
    for (final (what, words0, kind, reason, heads, raise)
        in <(
      String,
      String,
      String,
      String,
      (int?, int?),
      Future<void> Function(FakeLog, ChatService),
    )>[
      (
        'a log gone back',
        'ktFaultHead',
        'head',
        'the log shrank: held size 2, served 1',
        (2, 1),
        (log, svc) async {
          final now = DateTime.now().millisecondsSinceEpoch;
          log.sth = jsonEncode(
              (await signedHead(key, size: 2, ts: now - 2000)).toJson());
          await svc.kt.check();
          log.sth = jsonEncode(
              (await signedHead(key, size: 1, ts: now - 1000)).toJson());
          await svc.kt.check();
        },
      ),
      (
        'an answer about this account that is no answer',
        'ktFaultOwnAccount',
        'ownAccount',
        'lookup for this account: lookup: sth and map are required',
        (1, null),
        (log, svc) async {
          final now = DateTime.now().millisecondsSinceEpoch;
          log.sth = jsonEncode(
              (await signedHead(key, size: 1, ts: now - 1000)).toJson());
          log.lookup = '{}';
          await svc.kt.check();
        },
      ),
    ]) {
      final log = FakeLog();
      final svc = (await t.runAsync(() async {
        final svc = await ktService('Kai_$kind', log, config);
        await raise(log, svc);
        return svc;
      }))!;
      expect(svc.kt.fault?.reason, reason, reason: '$what: the fault raised');
      // Spanish first: where the client's English showed through.
      for (final lang in ['es', 'en']) {
        final l = lookupAppLocalizations(Locale(lang));
        final dir = temp('kt_$lang');
        final prefs = AppPrefs(root: dir);
        await t.runAsync(prefs.load);
        await t.pumpWidget(MultiProvider(
          providers: [
            ChangeNotifierProvider<ChatService>.value(value: svc),
            ChangeNotifierProvider<Transport>.value(value: svc.transport),
            ChangeNotifierProvider<PushService>.value(
                value: PushService(transport: svc.transport, vault: svc.vault)),
            ChangeNotifierProvider<AppLock>.value(
                value: AppLock(root: dir, store: MemorySecretStore())),
            ChangeNotifierProvider<AppPrefs>.value(value: prefs),
          ],
          child: app(lang, const SettingsScreen()),
        ));
        await settleUntil(
            t, () => find.text(l.stSettings).evaluate().isNotEmpty,
            what: '$lang: the Settings screen');
        await t.scrollUntilVisible(find.text(l.stKtStatus), 200,
            scrollable: find.byType(Scrollable).first);
        await t.pump();
        await says(t, words(lang, words0), '$lang, $what: Settings');
        expect(find.textContaining(reason), findsNothing,
            reason: "$lang, $what: none of the client's words on the screen");
        // Its details: the client's words, as recorded, and Copy.
        final details = find.text(words(lang, 'stKtFaultDetails'));
        await t.scrollUntilVisible(details, 200,
            scrollable: find.byType(Scrollable).first);
        await t.pump();
        await t.tap(details);
        await settleUntil(t, () => find.text(reason).evaluate().isNotEmpty,
            what: '$lang, $what: its details');
        expect(find.text(words(lang, 'stKtFaultDetailsBody')), findsOneWidget);
        copied = null;
        await t.tap(find.descendant(
            of: find.byType(AlertDialog), matching: find.text(l.copy)));
        await settleUntil(t, () => copied != null,
            what: '$lang, $what: the details copied');
        final j = jsonDecode(copied!) as Map;
        expect([j['k'], j['r']], [kind, reason]);
        expect([(j['held'] as Map?)?['size'], (j['served'] as Map?)?['size']],
            [heads.$1, heads.$2],
            reason: 'with the heads the client compared');
        await t.tap(find.descendant(
            of: find.byType(AlertDialog), matching: find.text(l.ok)));
        await t.pump();
        // The home screen's alert.
        await t.pumpWidget(MultiProvider(
          providers: [
            ChangeNotifierProvider<ChatService>.value(value: svc),
            ChangeNotifierProvider<Transport>.value(value: svc.transport),
          ],
          child: app(lang, const HomeScreen()),
        ));
        await says(
            t,
            [words(lang, words0), words(lang, 'homeKtFault')].join(' '),
            '$lang, $what: the home screen');
        expect(find.textContaining(reason), findsNothing,
            reason: "$lang, $what: none of the client's words on the screen");
        await t.pumpWidget(const SizedBox());
      }
      await stop(t, svc);
    }
  });

  test(
      '10. every startup, unlock and log fault says what failed in English '
      'and in Spanish, and a fault stored before faults had a kind reads as '
      'one of no kind', () async {
    final en = lookupAppLocalizations(const Locale('en'));
    final es = lookupAppLocalizations(const Locale('es'));
    for (final l in [en, es]) {
      final checked = <(String, String)>[
        // The screen Z shows when it cannot start.
        for (final (error, want) in <(Object, String)>[
          (const VaultTooNewException(14, 13), l.vaultTooNew),
          (WrongPassphraseException(), l.startupFailedKey),
          (const FileSystemException('cannot open'), l.startupFailedStorage),
          (StateError('something nobody expected'), l.startupFailedOther),
        ])
          (startupFailureText(l, error), want),
        // The unlock screen, for what is not a wrong passphrase.
        for (final (error, want) in <(Object, String)>[
          (const FileSystemException('cannot open'), l.unlockFailedStorage),
          (PlatformException(code: 'NotAvailable'), l.unlockFailedKeystore),
          (const BoundKeyException('failed', 'detail'), l.unlockFailedKeystore),
          (StateError('something nobody expected'), l.unlockFailedOther),
        ])
          (unlockFailureText(l, error), want),
        // A log fault, by its kind; none, as one of no kind.
        for (final (kind, want) in <(KtFaultKind, String)>[
          (KtFaultKind.head, l.ktFaultHead),
          (KtFaultKind.witness, l.ktFaultWitness),
          (KtFaultKind.label, l.ktFaultLabel),
          (KtFaultKind.ownAccount, l.ktFaultOwnAccount),
          (KtFaultKind.contacts, l.ktFaultContacts),
          (KtFaultKind.other, l.ktFaultOther),
        ])
          (
            ktFaultText(l,
                KtFault(kind: kind, reason: 'the log shrank', atMs: 0)),
            want
          ),
        (ktFaultText(l, null), l.ktFaultOther),
      ];
      for (final (got, want) in checked) {
        expect(got, want);
      }
      for (final (s, _) in checked) {
        expect(s, isNot(matches(rawText)), reason: s);
        expect(s, isNot(contains('nobody expected')), reason: s);
        expect(s, isNot(contains('the log shrank')), reason: s);
      }
    }
    // Each language has its own words for each.
    for (final (a, b) in [
      (es.startupFailedKey, en.startupFailedKey),
      (es.startupFailedStorage, en.startupFailedStorage),
      (es.startupFailedOther, en.startupFailedOther),
      (es.unlockFailedStorage, en.unlockFailedStorage),
      (es.unlockFailedKeystore, en.unlockFailedKeystore),
      (es.unlockFailedOther, en.unlockFailedOther),
      (es.ktFaultHead, en.ktFaultHead),
      (es.ktFaultWitness, en.ktFaultWitness),
      (es.ktFaultLabel, en.ktFaultLabel),
      (es.ktFaultOwnAccount, en.ktFaultOwnAccount),
      (es.ktFaultContacts, en.ktFaultContacts),
      (es.ktFaultOther, en.ktFaultOther),
      (es.homeKtFault, en.homeKtFault),
    ]) {
      expect(a, isNot(b), reason: 'the Spanish has words of its own');
    }
    // A fault stored before faults had a kind, or with one this build does
    // not know: of no kind, its words as they were.
    final old = KtFault.fromJson(
        {'r': 'the log shrank: held size 2, served 1', 'at': 5});
    expect([old.kind, old.reason, old.atMs],
        [KtFaultKind.other, 'the log shrank: held size 2, served 1', 5]);
    expect(KtFault.fromJson({'k': 'newer', 'r': 'x', 'at': 1}).kind,
        KtFaultKind.other);
    // Stored and read back, every part of the evidence is as it was.
    final key = await Ed25519().newKeyPair();
    final held = await signedHead(key, size: 3, ts: 7);
    final served = await signedHead(key, size: 2, ts: 8);
    final fault = KtFault(
        kind: KtFaultKind.witness,
        reason: 'the witness saw a different head of size 3',
        held: held,
        served: served,
        atMs: 9);
    final back = KtFault.fromJson(
        (jsonDecode(jsonEncode(fault.toJson())) as Map).cast<String, Object?>());
    expect([back.kind, back.reason, back.atMs],
        [fault.kind, fault.reason, fault.atMs]);
    expect(back.held!.toJson(), held.toJson());
    expect(back.served!.toJson(), served.toJson());
  });

  testWidgets(
      '11. the backup screen, on a backup folder that cannot be written, says '
      'the backup was not written, and no error gets past it', (t) async {
    // Spanish first: either way the error was the one that escaped.
    for (final lang in ['es', 'en']) {
      final l = lookupAppLocalizations(Locale(lang));
      FilePicker.platform = FakePicker(temp('unwritable_cache_$lang'));
      final svc = (await t.runAsync(() => service('Ugo_$lang')))!;
      final backups = await openBackup(t, lang, svc);
      // The folder becomes a file, so nothing can be written in it. Until
      // 2026-10-31 the write's own open failed with nothing listening, an
      // error the test framework takes for the test's.
      await t.runAsync(() async {
        await backups.delete(recursive: true);
        await File(backups.path).writeAsString('not a folder');
      });
      await createBackup(t, l, what: '$lang, a folder that cannot be written');
      await says(t, words(lang, 'backupFailed'),
          '$lang: a backup into a folder that cannot be written');
      expect(await t.runAsync(() => File(backups.path).readAsString()),
          'not a folder',
          reason: 'nothing written in its place');
      await t.pumpWidget(const SizedBox());
      await stop(t, svc);
    }
  });

  testWidgets(
      "12. the save dialog that a copy of the backup opens is titled in the "
      "reader's language", (t) async {
    // Spanish first: where the English title showed through.
    for (final lang in ['es', 'en']) {
      final l = lookupAppLocalizations(Locale(lang));
      final picker = FakePicker(temp('title_cache_$lang'));
      FilePicker.platform = picker;
      final svc = (await t.runAsync(() => service('Tea_$lang')))!;
      await openBackup(t, lang, svc);
      await t.tap(find.text(l.backupSaveCopy));
      await settleUntil(t, () => picker.savedTitle != null,
          what: '$lang: the save dialog opened');
      expect(picker.savedTitle, words(lang, 'backupSaveDialogTitle'),
          reason: "$lang: the dialog's title in the reader's words");
      // The place the picker hands back cannot be written: the copy's end.
      await says(t, words(lang, 'backupSaveFailed'),
          '$lang: the copy, handed to a place nothing can be written');
      await t.pumpWidget(const SizedBox());
      await stop(t, svc);
    }
  });

  testWidgets(
      '13. the backup screen, asked to turn automatic backups on or off on a '
      'store that refuses, says so, and they stay as they were', (t) async {
    final code = (await t.runAsync(
        () async => (await RecoveryCode.generate()).format()))!;
    for (final lang in ['es', 'en']) {
      final l = lookupAppLocalizations(Locale(lang));
      FilePicker.platform = FakePicker(temp('auto_cache_$lang'));
      // On, on a store that refuses the code: its database closed, the
      // service's own connection stopped first. Until 2026-10-31 nothing
      // caught this, and the error went past the screen.
      final off = (await t.runAsync(() => service('Ida_$lang')))!;
      await openBackup(t, lang, off);
      await t.runAsync(() async {
        await off.transport.stop();
        await off.vault.db.close();
      });
      await flipAuto(t, l, code: code, what: '$lang, turning them on');
      await says(t, words(lang, 'backupAutoNotOn'),
          '$lang: automatic backups the store would not turn on');
      expect(autoIsOn(t, l), isFalse, reason: '$lang: they stay off');
      await t.pumpWidget(const SizedBox());
      await stop(t, off);
      // Off, on a store that refuses: on first, then the store closed.
      final on = (await t.runAsync(() => service('Ivo_$lang')))!;
      await openBackup(t, lang, on);
      await flipAuto(t, l, code: code, what: '$lang, turning them on first');
      await says(t, words(lang, 'backupAutoOn'), '$lang: automatic backups on');
      await dismissWord(t);
      await t.runAsync(() async {
        await on.transport.stop();
        await on.vault.db.close();
      });
      await flipAuto(t, l, what: '$lang, turning them off');
      await says(t, words(lang, 'backupAutoNotOff'),
          '$lang: automatic backups the store would not turn off');
      expect(autoIsOn(t, l), isTrue, reason: '$lang: they stay on');
      await t.pumpWidget(const SizedBox());
      await stop(t, on);
    }
  });
}
