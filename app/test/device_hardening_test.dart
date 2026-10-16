// Phase 42 — what the phone keeps, shows and says.
//
// Five findings from the 3 October analysis's device and localisation lists,
// each reproduced here before it was fixed:
//
//  * the recent-apps card showed the open chat, app lock or not: Z never
//    asked Android to keep its window from capture (FLAG_SECURE);
//  * the pickers' plaintext copies outlived a process killed mid-pick and
//    "Wipe everything", the restore screen left one on three of its ways
//    out, and an image pick asked the file picker for a recompressed copy,
//    which it writes to the shared Pictures folder;
//  * the warnings the service raises when a contact's code is refused — a
//    different identity, a substituted post-quantum key, a code that does
//    not verify — reached the screen as English sentences in every
//    language, and so did the OS unlock prompt's reason;
//  * the disappearing-message sweep queried a vault its owner had closed;
//  * and a release build's own error reports carried the error's text into
//    the system log — where this app's routing ids are.
//
// Nothing here can see the window flag itself: that is Android's, and a
// test on this host has no window to set it on. What is tested is the
// policy and that the app asks for the flag on the channel the activity
// answers (`MainActivity.kt`, `z/screen`), exactly when the policy says.
//
// A sixth was found after 4.2.0, planning phase 46: two of the three fields
// that take a backup's recovery code let the keyboard suggest and correct
// it, and no field that takes a secret — a passphrase, a recovery code, a
// pairing code — asked the keyboard not to learn it. A keyboard that learns
// keeps what it learned, and some back it up to an account of their own.
// Here too what is tested is the request (16); what a keyboard does with it
// is the keyboard's.
//
// Criteria 2-7, 9, 12 and 14 use nothing the base build lacks, and were run
// against 0d00a69 before anything was fixed: each failed there, except 14,
// which pins a grep that was already clean, and the parts that assert an
// absence — nothing asked of a desktop or with the setting off, no switch on
// a desktop — which held there too. Criteria 1, 8, 10, 11, 13 and 15 test
// what this change adds. Criterion 16 was run against 5a04d1f, before its
// own fix: (a) named all twelve fields, and (b) and (c) failed.
//
// Criteria, each a test below (4, 9 and 16 in parts):
//   1. the policy: the window is kept from capture exactly while the vault
//      is open, on Android, with the setting on — which it is until the
//      person turns it off — and the window is told only when that changes;
//   2. started on Android, the app asks for a secure window the moment its
//      vault opens and not before, asks for nothing with the setting off,
//      and asks for nothing on a desktop;
//   3. Settings › Security has the switch on Android, on until it is
//      turned off, the choice kept for the next start; a desktop has none;
//   4. every way out of a restore after the pick deletes the picker's copy:
//      (a) a file that is not a backup, (b) a recovery code not given,
//      (c) a cleartext relay declined;
//   5. no pick asks the file picker for a compressed copy, which on Android
//      it writes to the shared Pictures folder;
//   6. what a killed process left — a camera capture, a gallery copy, the
//      file picker's copies — is gone once the app has started on Android,
//      the image picker is asked to forget the pick, and nothing else in
//      the cache is touched;
//   7. "Wipe everything" takes the pickers' copies with the vault;
//   8. the sweep takes exactly the shapes the pickers write, never runs
//      where the temporary directory is shared, and a gallery pick's own
//      directory goes with its copy;
//   9. a refused contact code is refused as a kind, never as an English
//      sentence — its own code, someone already held, a changed
//      commitment, a code that does not verify — and (b) the add screen
//      says it in the reader's language;
//  10. every kind of refusal has words of its own, in English and Spanish;
//  11. the OS unlock prompt says what it is for in the app's language,
//      chosen from the device's languages as the screens are;
//  12. a sweep on a vault its owner closed — started after the close, or
//      with the close landing in the middle of it — ends quietly;
//  13. the sweep's timer stops itself once it finds the vault closed, and
//      "Wipe everything" stops every clock and waits for a running sweep
//      before the vault goes;
//  14. nothing in lib/ prints outside a debug-only branch — the app's and
//      the protocol library's;
//  15. a release build writes nothing of an error to the system log: not
//      its text, and not the routing id in it;
//  16. every field that takes a secret asks the keyboard to learn nothing,
//      and one that can show what it holds to suggest and correct nothing
//      too: (a) each such field in lib/ui, by what marks it, (b) what the
//      keyboard is told by the restore's recovery-code field, and (c) by the
//      unlock screen's passphrase, hidden and shown.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/app_lock.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/key_transparency.dart';
import 'package:zapp/core/models.dart';
import 'package:zapp/core/picked_file.dart';
import 'package:zapp/core/prefs.dart';
import 'package:zapp/core/push_service.dart';
import 'package:zapp/core/release_log.dart';
import 'package:zapp/core/screen_security.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/l10n/app_localizations_en.dart';
import 'package:zapp/l10n/app_localizations_es.dart';
import 'package:zapp/l10n/lock_text.dart';
import 'package:zapp/l10n/refusal_text.dart';
import 'package:zapp/main.dart' as app;
import 'package:zapp/ui/add_contact_screen.dart';
import 'package:zapp/ui/onboarding_screen.dart';
import 'package:zapp/ui/settings_screen.dart';
import 'package:zapp/ui/theme.dart';
import 'package:zapp/ui/unlock_screen.dart';

const _pathChannel = MethodChannel('plugins.flutter.io/path_provider');
const _screenChannel = MethodChannel('z/screen');
const _imagePickerChannel = MethodChannel('plugins.flutter.io/image_picker');

/// The file picker as it behaves on Android (file_picker 8.3.7,
/// `FileUtils.openFileStream` and `clearCache`): the chosen file is copied
/// into the app's cache under `file_picker/<ms>/`, the copy is what the app
/// is handed, and `clearTemporaryFiles` deletes that directory.
class CopyingPicker extends FilePicker {
  CopyingPicker(this.cache);
  final Directory cache;

  /// What the next pick hands over.
  List<int> contents = const [];
  final copies = <File>[];

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
    copies.add(copy);
    return FilePickerResult([
      PlatformFile(path: copy.path, name: 'backup.zbk', size: contents.length)
    ]);
  }

  @override
  Future<bool?> clearTemporaryFiles() async {
    final d = Directory('${cache.path}/file_picker');
    if (d.existsSync()) d.deleteSync(recursive: true);
    return true;
  }
}

/// What the two pickers leave in the cache directory on Android, by the
/// shape each one writes (image_picker_android 0.8.13+23, file_picker 8.3.7):
/// a gallery pick's copy in a directory named by a random UUID, the camera's
/// file named by a UUID and a number, a resized copy `scaled_…`, and the file
/// picker's copies under `file_picker/`. Plus what is NOT theirs and must
/// stay: other apps' and libraries' cache entries.
const _uuid = '3f6d2a9c-1b4e-4c7a-9f3e-2d8b6a1c5e70';
const pickerLeftovers = [
  '$_uuid/IMG_20261009_101500.jpg', // a gallery pick (pickMedia)
  '${_uuid}8164275309216123456.jpg', // a camera capture
  '7c1e0b5d-2a3f-4e6b-8d9c-0f1a2b3c4d5e-42.mp4', // an older Android's number
  'scaled_IMG_20261009_101500.jpg', // a resized copy
  'file_picker/1791500000000/passport.pdf', // the file picker's
];
const notPickers = [
  'flutter_engine/shader.cache',
  'notes.txt',
  'abc/IMG_1.jpg', // a directory that is not a UUID
  '3F6D2A9C-1B4E-4C7A-9F3E-2D8B6A1C5E70.jpg', // upper case: not Java's UUID
];

void plant(Directory cache) {
  for (final rel in [...pickerLeftovers, ...notPickers]) {
    File('${cache.path}/$rel')
      ..createSync(recursive: true)
      ..writeAsStringSync('plaintext $rel');
  }
}

/// A contact code with its JSON edited — what anyone holding someone's
/// PUBLIC code can produce, since nothing in it is secret.
String editCode(String code, void Function(Map<String, Object?> j) edit) {
  final prefix = code.substring(0, 4);
  final j = (jsonDecode(utf8.decode(unb64url(code.substring(4)))) as Map)
      .cast<String, Object?>();
  edit(j);
  return prefix + b64url(utf8.encode(jsonEncode(j)));
}

/// The OS prompt, passed every time, keeping what it was asked to say.
class RecordingGate implements BiometricGate {
  final reasons = <String>[];
  @override
  Future<bool> get isAvailable async => true;
  @override
  Future<GateResult> authenticate(String reason) async {
    reasons.add(reason);
    return GateResult.ok;
  }
}

/// Pump until [cond] holds, letting real work run in between: a widget
/// test's clock is fake, and the vault is real files and a real database.
Future<void> settleUntil(WidgetTester t, bool Function() cond,
    {required String what,
    Duration timeout = const Duration(seconds: 30)}) async {
  final deadline = DateTime.now().add(timeout);
  await t.pump();
  while (!cond()) {
    if (DateTime.now().isAfter(deadline)) {
      throw TimeoutException('condition not met: $what', timeout);
    }
    await t.runAsync(
        () => Future<void>.delayed(const Duration(milliseconds: 40)));
    await t.pump(const Duration(milliseconds: 16));
  }
}

/// An awaited poll on an observable, outside a widget test.
Future<void> waitUntil(FutureOr<bool> Function() cond,
    {required String what,
    Duration timeout = const Duration(seconds: 30)}) async {
  final deadline = DateTime.now().add(timeout);
  while (!await cond()) {
    if (DateTime.now().isAfter(deadline)) {
      throw TimeoutException('condition not met: $what', timeout);
    }
    await Future<void>.delayed(const Duration(milliseconds: 25));
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final en = AppLocalizationsEn();
  final temps = <Directory>[];

  tearDownAll(() {
    for (final d in temps) {
      try {
        if (d.existsSync()) d.deleteSync(recursive: true);
      } catch (_) {}
    }
  });

  Directory temp(String name) {
    final d = Directory.systemTemp.createTempSync('z_dh_$name');
    temps.add(d);
    return d;
  }

  /// A service that talks to nobody: a closed local port for a relay, and
  /// the transparency log off.
  Future<(ChatService, ZIdentity)> offline(String name,
      {Directory? dir}) async {
    final vault = await Vault.open(rootOverride: dir ?? temp(name));
    final id = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(id.toJson()));
    final svc = await ChatService.init(
        vault: vault,
        identity: id,
        displayName: name,
        transport: Transport(identity: id, serverUrl: 'ws://127.0.0.1:1'),
        ktConfig: KtConfig.off);
    return (svc, id);
  }

  /// The platform's directories for an app started under test: [support]
  /// for the vault, [cache] for what the pickers leave.
  void mockPaths(WidgetTester? t, Directory support, Directory cache) {
    final messenger = t?.binding.defaultBinaryMessenger ??
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    messenger.setMockMethodCallHandler(_pathChannel, (call) async {
      return switch (call.method) {
        'getTemporaryDirectory' => cache.path,
        _ => support.path,
      };
    });
    addTearDown(() => messenger.setMockMethodCallHandler(_pathChannel, null));
  }

  // -------------------------------------------------------------------
  // Item 1: the window, while the vault is open (the policy half)
  // -------------------------------------------------------------------

  test(
      '1. the policy: kept from capture exactly while the vault is open, on '
      'Android, with the setting on; the window is told only when that '
      'changes', () async {
    for (final platform in TargetPlatform.values) {
      for (final open in [false, true]) {
        for (final setting in [false, true]) {
          expect(
              screenSecureFor(
                  platform: platform,
                  vaultOpen: open,
                  setting: setting,
                  isWeb: false),
              platform == TargetPlatform.android && open && setting,
              reason: '${platform.name}, vault ${open ? 'open' : 'shut'}, '
                  'setting ${setting ? 'on' : 'off'}');
        }
      }
    }
    expect(
        screenSecureFor(
            platform: TargetPlatform.android,
            vaultOpen: true,
            setting: true,
            isWeb: true),
        isFalse);

    final told = <String>[];
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    messenger.setMockMethodCallHandler(ScreenSecurity.channel, (call) async {
      told.add('${call.method}:${call.arguments}');
      return null;
    });
    addTearDown(
        () => messenger.setMockMethodCallHandler(ScreenSecurity.channel, null));

    final prefs = AppPrefs(root: temp('prefs'));
    await prefs.load();
    expect(prefs.screenSecurity, isTrue, reason: 'on until it is turned off');
    final screen = ScreenSecurity(prefs, platform: TargetPlatform.android);
    final desktop = ScreenSecurity(prefs, platform: TargetPlatform.linux);
    await prefs.setScreenSecurity(false);
    await prefs.setScreenSecurity(true);
    expect(told, isEmpty, reason: 'the vault is shut: nothing to keep');

    await screen.vaultOpened();
    await desktop.vaultOpened();
    expect(told, ['secure:true'], reason: 'Android only, once');
    await screen.vaultOpened();
    expect(told, ['secure:true'], reason: 'nothing changed, nothing said');
    await prefs.setScreenSecurity(false);
    await waitUntil(() => told.length == 2,
        what: 'the window told the setting is off');
    expect(told.last, 'secure:false');
    await prefs.setScreenSecurity(true);
    await waitUntil(() => told.length == 3, what: 'and on again');
    expect(told.last, 'secure:true');

    screen.dispose();
    desktop.dispose();
    await prefs.setScreenSecurity(false);
    await pumpEventQueue();
    expect(told, hasLength(3), reason: 'a disposed controller follows nothing');
    // What was chosen is what the next start reads.
    final next = AppPrefs(root: prefs.root);
    await next.load();
    expect(next.screenSecurity, isFalse);
  });

  testWidgets(
      '2. started on Android, the app asks for a secure window the moment '
      'its vault opens and not before; on a desktop it asks for nothing',
      (t) async {
    final support = temp('support');
    final cache = temp('cache');
    mockPaths(t, support, cache);
    final asked = <String>[];
    t.binding.defaultBinaryMessenger.setMockMethodCallHandler(_screenChannel,
        (call) async {
      asked.add('${call.method}:${call.arguments}');
      return null;
    });
    addTearDown(() => t.binding.defaultBinaryMessenger
        .setMockMethodCallHandler(_screenChannel, null));

    // A vault with a passphrase, so the app starts on the unlock screen,
    // with the vault still shut.
    await t.runAsync(() async {
      final v = await Vault.open(
          rootOverride: Directory('${support.path}/z'));
      await v.setPassphrase('correct horse battery');
      await v.db.close();
    });

    app.startApp(operatingSystem: 'android');
    await settleUntil(t, () => find.byType(UnlockScreen).evaluate().isNotEmpty,
        what: 'the unlock screen');
    expect(asked, isEmpty, reason: 'the vault is not open yet');

    await t.enterText(find.byType(TextField), 'correct horse battery');
    await t.tap(find.text(en.unlockTitle));
    await settleUntil(
        t, () => find.byType(OnboardingScreen).evaluate().isNotEmpty,
        what: 'the vault open, on the first screen behind it',
        timeout: const Duration(seconds: 60));
    final android = defaultTargetPlatform == TargetPlatform.android;
    expect(asked, android ? ['secure:true'] : isEmpty,
        reason: android
            ? 'once, as the vault opened'
            : 'there is no such flag on ${defaultTargetPlatform.name}');

    final vault =
        t.widget<OnboardingScreen>(find.byType(OnboardingScreen)).vault;
    await t.runAsync(() => vault.db.close());
  },
      variant: TargetPlatformVariant(
          {TargetPlatform.android, TargetPlatform.linux}));

  testWidgets(
      '2b. started on Android with the setting turned off, the app asks for '
      'nothing', (t) async {
    final support = temp('support_off');
    mockPaths(t, support, temp('cache_off'));
    final asked = <String>[];
    t.binding.defaultBinaryMessenger.setMockMethodCallHandler(_screenChannel,
        (call) async {
      asked.add('${call.method}:${call.arguments}');
      return null;
    });
    addTearDown(() => t.binding.defaultBinaryMessenger
        .setMockMethodCallHandler(_screenChannel, null));
    // What Settings writes when the switch is turned off (criterion 3),
    // beside the vault, where the app reads its preferences at start.
    File('${support.path}/z/prefs.json')
      ..createSync(recursive: true)
      ..writeAsStringSync(
          jsonEncode({'v': 1, 'theme': 'system', 'screen': false}));

    app.startApp(operatingSystem: 'android');
    await settleUntil(
        t, () => find.byType(OnboardingScreen).evaluate().isNotEmpty,
        what: 'the first screen, the vault open');
    expect(asked, isEmpty, reason: 'the person turned it off');

    final vault =
        t.widget<OnboardingScreen>(find.byType(OnboardingScreen)).vault;
    await t.runAsync(() => vault.db.close());
  }, variant: TargetPlatformVariant.only(TargetPlatform.android));

  group('Settings', () {
    late Directory dir;
    late ChatService svc;

    setUp(() async {
      dir = temp('settings');
      (svc, _) = await offline('Finn', dir: dir);
    });

    tearDown(() async {
      await svc.transport.stop();
      svc.dispose();
      await svc.vault.db.close();
    });

    testWidgets(
        '3. Settings › Security has a screen-security switch on Android, on '
        'until it is turned off, and turning it off is kept',
        (t) async {
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
        child: MaterialApp(
          debugShowCheckedModeBanner: false,
          theme: ZTheme.light(),
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: const SettingsScreen(),
        ),
      ));
      await settleUntil(t, () => find.text(en.stSettings).evaluate().isNotEmpty,
          what: 'the Settings screen');
      // The passphrase row closes the lock rows the switch sits among, so
      // with it on screen the switch has been built if there is one.
      await t.scrollUntilVisible(find.text(en.stPassphraseOff), 200,
          scrollable: find.byType(Scrollable).first);
      final row = find.byKey(const ValueKey('screen-security'));
      if (defaultTargetPlatform != TargetPlatform.android) {
        expect(row, findsNothing, reason: 'Android has the flag; nothing else');
        return;
      }
      expect(row, findsOneWidget);
      expect(t.widget<SwitchListTile>(row).value, isTrue,
          reason: 'on until the person turns it off');
      await t.tap(row);
      await settleUntil(t, () => !t.widget<SwitchListTile>(row).value,
          what: 'the switch off');
      // Kept outside the vault, like the theme, for the next start.
      final stored = File('${dir.path}/prefs.json');
      await settleUntil(t, () {
        try {
          return (jsonDecode(stored.readAsStringSync()) as Map)['screen'] ==
              false;
        } on Object {
          return false;
        }
      }, what: 'prefs.json saying the switch is off');
    },
        variant: TargetPlatformVariant(
            {TargetPlatform.android, TargetPlatform.linux}));
  });

  // -------------------------------------------------------------------
  // Item 2: the pickers' plaintext copies
  // -------------------------------------------------------------------

  /// The first screen over a fresh vault, with a picker that copies what it
  /// hands over the way Android's does.
  Future<CopyingPicker> restoreScreen(WidgetTester t) async {
    final picker = CopyingPicker(temp('restore_cache'));
    FilePicker.platform = picker;
    final vault =
        (await t.runAsync(() => Vault.open(rootOverride: temp('restore'))))!;
    addTearDown(() => t.runAsync(() => vault.db.close()));
    await t.pumpWidget(MaterialApp(
      debugShowCheckedModeBanner: false,
      theme: ZTheme.light(),
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      supportedLocales: AppLocalizations.supportedLocales,
      home: OnboardingScreen(vault: vault, onDone: () async {}),
    ));
    await t.pump();
    return picker;
  }

  Future<void> tapRestore(WidgetTester t) async {
    final button = find.text(en.onbRestoreFromBackup);
    await t.ensureVisible(button);
    await t.pump();
    await t.tap(button);
  }

  const archive = '{"z":"zbk","v":1}\nthe rest of an archive';

  testWidgets(
      '4a. a restore from a file that is not a backup deletes the picker\'s '
      'copy', (t) async {
    final picker = await restoreScreen(t);
    picker.contents = utf8.encode('not a backup at all');
    await tapRestore(t);
    await settleUntil(t, () => find.text(en.onbNotABackup).evaluate().isNotEmpty,
        what: 'the not-a-backup message');
    await settleUntil(t, () => !picker.copies.single.existsSync(),
        what: 'the copy of a file that is not a backup deleted',
        timeout: const Duration(seconds: 5));
  });

  testWidgets(
      '4b. a restore whose recovery code is not given deletes the picker\'s '
      'copy', (t) async {
    final picker = await restoreScreen(t);
    picker.contents = utf8.encode(archive);
    await tapRestore(t);
    await settleUntil(
        t, () => find.text(en.onbRecoveryCode).evaluate().isNotEmpty,
        what: 'the recovery-code dialog');
    await t.tap(find.text(en.cancel));
    await settleUntil(
        t, () => find.text(en.onbRecoveryCode).evaluate().isEmpty,
        what: 'the dialog dismissed');
    await settleUntil(t, () => !picker.copies.single.existsSync(),
        what: 'the copy of an archive whose code was not given deleted',
        timeout: const Duration(seconds: 5));
  });

  testWidgets(
      '4c. a restore whose cleartext relay is declined deletes the picker\'s '
      'copy', (t) async {
    final picker = await restoreScreen(t);
    picker.contents = utf8.encode(archive);
    await t.tap(find.text(en.onbDevOptions));
    await t.pump();
    final relay = find.widgetWithText(TextField, en.onbRelayAddress);
    await t.ensureVisible(relay);
    await t.enterText(relay, 'ws://relay.example.com');
    await tapRestore(t);
    await settleUntil(
        t, () => find.text(en.onbRecoveryCode).evaluate().isNotEmpty,
        what: 'the recovery-code dialog');
    await t.enterText(
        find.descendant(
            of: find.byType(AlertDialog), matching: find.byType(TextField)),
        'ZBK-AAAAA-AAAAA-AAAAA-AAAAA-AAAAA');
    await t.tap(find.text(en.onbRestore));
    await settleUntil(
        t, () => find.text(en.relayInsecureTitle).evaluate().isNotEmpty,
        what: 'the cleartext-relay question');
    await t.tap(find.text(en.cancel));
    await settleUntil(
        t, () => find.text(en.relayInsecureTitle).evaluate().isEmpty,
        what: 'the question answered no');
    await settleUntil(t, () => !picker.copies.single.existsSync(),
        what: 'the copy of an archive whose relay was declined deleted',
        timeout: const Duration(seconds: 5));
  });

  test(
      '5. no pick asks the picker for a compressed copy, which on Android it '
      'writes to the shared Pictures folder', () {
    // file_picker 8.3.7 compresses an image pick by default (quality 30) and
    // writes the result with `File.createTempFile("JPEG_<time>_", ".jpg",
    // Environment.getExternalStoragePublicDirectory(DIRECTORY_PICTURES))` —
    // outside the app, in the folder the gallery shows, where nothing of the
    // app's ever deletes it. A source check, as client_review_p0_test 5 is:
    // what matters is that no call site anywhere asks for it.
    final offenders = <String>[];
    var calls = 0;
    for (final f in Directory('lib')
        .listSync(recursive: true)
        .whereType<File>()
        .where((f) => f.path.endsWith('.dart'))) {
      final src = f.readAsStringSync();
      for (final m in RegExp(r'\bpickFiles\(').allMatches(src)) {
        calls++;
        var depth = 0, i = m.end - 1;
        for (; i < src.length; i++) {
          if (src[i] == '(') depth++;
          if (src[i] == ')' && --depth == 0) break;
        }
        final args = src.substring(m.end, i);
        if (!args.contains('allowCompression: false')) {
          offenders.add('${f.path}:${src.substring(0, m.start).split('\n').length}');
        }
      }
    }
    expect(calls, greaterThanOrEqualTo(3));
    expect(offenders, isEmpty,
        reason: 'these picks leave compression on, and an image pick then '
            'writes a copy into Pictures');
  });

  testWidgets(
      '6. what a killed process left — a camera capture, a gallery copy, the '
      'file picker\'s — is gone once the app has started on Android, and '
      'nothing else in the cache is touched', (t) async {
    final support = temp('start_support');
    final cache = temp('start_cache');
    plant(cache);
    mockPaths(t, support, cache);
    final lost = <String>[];
    t.binding.defaultBinaryMessenger
        .setMockMethodCallHandler(_imagePickerChannel, (call) async {
      lost.add(call.method);
      return null; // nothing the plugin was holding
    });
    addTearDown(() => t.binding.defaultBinaryMessenger
        .setMockMethodCallHandler(_imagePickerChannel, null));

    app.startApp(operatingSystem: 'android');
    await settleUntil(
        t, () => find.byType(OnboardingScreen).evaluate().isNotEmpty,
        what: 'the first screen');
    await settleUntil(
        t,
        () => pickerLeftovers
            .every((rel) => !File('${cache.path}/$rel').existsSync()),
        what: 'every picker copy gone',
        timeout: const Duration(seconds: 10));
    for (final rel in notPickers) {
      expect(File('${cache.path}/$rel').existsSync(), isTrue,
          reason: '$rel is not a picker\'s and must stay');
    }
    expect(lost, contains('retrieve'),
        reason: 'the image picker is asked for what it kept of a pick its '
            'process died in, which also makes it forget it');

    final vault =
        t.widget<OnboardingScreen>(find.byType(OnboardingScreen)).vault;
    await t.runAsync(() => vault.db.close());
  }, variant: TargetPlatformVariant.only(TargetPlatform.android));

  test('7. "Wipe everything" takes the pickers\' copies with the vault',
      () async {
    final cache = temp('wipe_cache');
    plant(cache);
    mockPaths(null, temp('wipe_support'), cache);
    final (svc, _) = await offline('Wendy');
    addTearDown(svc.dispose);
    final root = svc.vault.root;
    debugDefaultTargetPlatformOverride = TargetPlatform.android;
    try {
      await svc.wipeEverything();
    } finally {
      debugDefaultTargetPlatformOverride = null;
    }
    expect(root.existsSync(), isFalse);
    for (final rel in pickerLeftovers) {
      expect(File('${cache.path}/$rel').existsSync(), isFalse,
          reason: '$rel outlived the wipe');
    }
    for (final rel in notPickers) {
      expect(File('${cache.path}/$rel').existsSync(), isTrue,
          reason: '$rel is not a picker\'s');
    }
  });

  test(
      '8. the sweep takes exactly the shapes the pickers write, never runs '
      'where the temporary directory is shared, and a gallery pick\'s own '
      'directory goes with its copy', () async {
    final cache = temp('shapes');
    plant(cache);
    expect(await sweepPickerCopies(cache), isEmpty,
        reason: 'everything it took, it deleted');
    for (final rel in pickerLeftovers) {
      expect(File('${cache.path}/$rel').existsSync(), isFalse, reason: rel);
    }
    for (final rel in notPickers) {
      expect(File('${cache.path}/$rel').existsSync(), isTrue, reason: rel);
    }
    // The shapes one by one, as the plugins name what they write.
    expect(isPickerCopy('file_picker', directory: true), isTrue);
    expect(isPickerCopy('file_picker', directory: false), isFalse);
    expect(isPickerCopy(_uuid, directory: true), isTrue);
    expect(isPickerCopy(_uuid, directory: false), isFalse,
        reason: 'a gallery copy is a directory of its own');
    expect(isPickerCopy('${_uuid}123.jpg', directory: false), isTrue);
    expect(isPickerCopy('$_uuid-123.mp4', directory: false), isTrue);
    expect(isPickerCopy('$_uuid.jpg', directory: false), isFalse,
        reason: 'createTempFile always puts a number before the suffix');
    expect(isPickerCopy('${_uuid}123.png', directory: false), isFalse,
        reason: 'the camera writes .jpg, and .mp4 for video');
    expect(isPickerCopy('scaled_IMG_1.jpg', directory: false), isTrue);
    expect(isPickerCopy(_uuid.toUpperCase(), directory: true), isFalse,
        reason: "Java's UUID prints in lower case");

    // Where the temporary directory is the machine's, shared with every
    // other program, there is no picker cache to sweep.
    for (final platform in [
      TargetPlatform.linux,
      TargetPlatform.windows,
      TargetPlatform.macOS,
      TargetPlatform.iOS,
      TargetPlatform.fuchsia,
    ]) {
      debugDefaultTargetPlatformOverride = platform;
      try {
        expect(await pickerCacheDir(), isNull, reason: platform.name);
      } finally {
        debugDefaultTargetPlatformOverride = null;
      }
    }

    // A gallery pick read for sending: the bytes back, the copy and the
    // directory the picker made for it gone.
    final gallery = File('${cache.path}/$_uuid/IMG_20261009_101500.jpg')
      ..createSync(recursive: true)
      ..writeAsBytesSync([1, 2, 3]);
    expect(await readAndDeletePicked(gallery), [1, 2, 3]);
    expect(gallery.parent.existsSync(), isFalse);
  });

  // -------------------------------------------------------------------
  // Item 3: what the service says, in the reader's language
  // -------------------------------------------------------------------

  test(
      '9. a refused contact code is refused as a kind, never as an English '
      'sentence', () async {
    final (ivy, _) = await offline('Ivy');
    final (jon, jonId) = await offline('Jon');
    addTearDown(() async {
      for (final s in [ivy, jon]) {
        await s.transport.stop();
        s.dispose();
        await s.vault.db.close();
      }
    });
    Future<String> refusal(String code) async {
      try {
        await ivy.addContactFromCode(code);
      } on ContactCodeRefused catch (e) {
        return e.kind.name;
      } on FormatException catch (e) {
        return 'English: ${e.message}';
      }
      return 'accepted';
    }

    expect(await refusal(await ivy.myContactCode()), 'ownCode');
    final jonCode = await jon.myContactCode();
    await ivy.addContactFromCode(jonCode);
    expect(await refusal(jonCode), 'alreadyContact');
    // Jon's identity with another post-quantum key, its commitment signed:
    // what a reset (or an attacker holding his classical key) would hand
    // over. Ivy holds the commitment from his real code.
    final other = await HybridKeyPair.fromSeeds(
        edSeed: jonId.edSeed, mlSeed: randomBytes(32));
    final changed = (await ContactBundleV3.forIdentity(
            jonId, other.publicKey,
            displayName: 'Jon'))
        .encode();
    expect(await refusal(changed), 'commitChanged');
    // Codes that do not verify: not a code at all, and Jon's own with his
    // X25519 key swapped, which the code's signature no longer covers — the
    // protocol library's "possible tampering".
    expect(await refusal('zc1.not-a-code'), 'invalidCode');
    expect(
        await refusal(
            editCode(jonCode, (j) => j['x'] = b64(randomBytes(32)))),
        'invalidCode');

    // And no refusal on this path is left a sentence: nothing between the
    // add and the end of the re-scan throws a bare FormatException.
    final src = File('lib/core/chat_service.dart').readAsStringSync();
    final path = src.substring(src.indexOf('Future<Contact> addContactFromCode('),
        src.indexOf('Future<void> _markPqcSigned('));
    expect(RegExp(r'throw (const )?FormatException\(').allMatches(path),
        isEmpty);
  });

  testWidgets(
      '9b. the add screen says a refusal in the reader\'s language, not the '
      'service\'s English', (t) async {
    final (svc, _) = (await t.runAsync(() => offline('Lola')))!;
    addTearDown(() => t.runAsync(() async {
          await svc.transport.stop();
          svc.dispose();
          await svc.vault.db.close();
        }));
    final es = (jsonDecode(File('lib/l10n/app_es.arb').readAsStringSync())
        as Map)['addRefusedOwnCode'] as String?;
    await t.pumpWidget(ChangeNotifierProvider<ChatService>.value(
      value: svc,
      child: MaterialApp(
        locale: const Locale('es'),
        debugShowCheckedModeBanner: false,
        theme: ZTheme.light(),
        localizationsDelegates: AppLocalizations.localizationsDelegates,
        supportedLocales: AppLocalizations.supportedLocales,
        home: const AddContactScreen(),
      ),
    ));
    final esL = lookupAppLocalizations(const Locale('es'));
    await t.tap(find.text(esL.addPaste));
    await settleUntil(
        t, () => find.text(esL.addVerifyAndAdd).evaluate().isNotEmpty,
        what: 'the Paste tab');
    final tabs = t.widget<TabBar>(find.byType(TabBar)).controller!;
    await settleUntil(t, () => tabs.index == 1 && !tabs.indexIsChanging,
        what: 'the switch to the Paste tab');
    final mine = (await t.runAsync(svc.myContactCode))!;
    await t.enterText(find.byType(TextField).first, mine);
    await t.tap(find.text(esL.addVerifyAndAdd));
    await settleUntil(
        t,
        () =>
            find.text('that is your own contact code').evaluate().isNotEmpty ||
            find.text(es ?? '\u0000').evaluate().isNotEmpty,
        what: 'the refusal shown');
    expect(find.text('that is your own contact code'), findsNothing,
        reason: 'the service\'s English, shown to a Spanish reader');
    expect(es, isNotNull, reason: 'no Spanish words for this refusal');
    expect(find.text(es!), findsOneWidget);
  });

  test('10. every kind of refusal has words of its own, in English and Spanish',
      () {
    final enL = AppLocalizationsEn();
    final esL = AppLocalizationsEs();
    final words = <String>{};
    for (final kind in ContactCodeRefusal.values) {
      final e = ContactCodeRefused(kind, 'Dana', 'the English, for logs');
      final inEn = contactCodeRefusalText(enL, e);
      final inEs = contactCodeRefusalText(esL, e);
      expect(words.add(inEn), isTrue,
          reason: '${kind.name} shares its words with another kind');
      expect(inEs, isNot(inEn), reason: '${kind.name} is not translated');
      expect(inEn, isNot(contains('the English, for logs')));
      final named = kind != ContactCodeRefusal.ownCode &&
          kind != ContactCodeRefusal.invalidCode;
      expect(inEn.contains('Dana'), named, reason: kind.name);
      expect(inEs.contains('Dana'), named, reason: kind.name);
    }
  });

  test(
      '11. the OS unlock prompt says what it is for in the app\'s language, '
      'chosen from the device\'s languages as the screens are', () async {
    final enL = AppLocalizationsEn();
    final esL = AppLocalizationsEs();
    final gate = RecordingGate();
    final lock =
        AppLock(root: temp('lock'), gate: gate, store: MemorySecretStore());
    expect(lock.prompts.unlock, enL.lockPromptUnlock,
        reason: 'English until it is told otherwise');
    lock.prompts = lockPromptsFor(esL);

    expect(await lock.enableScreenLock(), GateResult.ok);
    lock.lockNow();
    expect(await lock.requestUnlock(), GateResult.ok);
    final vault = await Vault.open(rootOverride: temp('lock_vault'));
    addTearDown(() => vault.db.close());
    await vault.setPassphrase('correct horse battery');
    expect(await lock.enrolBiometricUnlock(vault, 'correct horse battery'),
        isTrue);
    expect(await lock.passKeyAfterPrompt(), isNotNull);
    expect(gate.reasons, [
      esL.lockPromptEnableScreenLock,
      esL.lockPromptUnlock,
      esL.lockPromptEnableBiometric,
      esL.lockPromptUnlock,
    ]);
    final english = [
      enL.lockPromptUnlock,
      enL.lockPromptEnableScreenLock,
      enL.lockPromptEnableBiometric,
    ];
    for (final r in gate.reasons) {
      expect(english, isNot(contains(r)), reason: '"$r" is the English');
    }

    // The device's languages, resolved as MaterialApp resolves them.
    expect(deviceLocalizations(const [Locale('es', 'MX')]).localeName, 'es');
    expect(deviceLocalizations(const [Locale('fr'), Locale('es')]).localeName,
        'es');
    expect(deviceLocalizations(const [Locale('fr')]).localeName, 'en');
  });

  // -------------------------------------------------------------------
  // Item 4: the sweep and a vault its owner closed
  // -------------------------------------------------------------------

  test(
      '12. a sweep on a vault its owner closed — started after the close, '
      'or with the close landing in the middle of it — ends quietly',
      () async {
    final (a, _) = await offline('Ann');
    addTearDown(a.dispose);
    await a.transport.stop();
    // Closed without dispose(): the owner's call, and nothing made it
    // dispose first.
    await a.vault.db.close();
    await a.debugSweep();

    final (b, _) = await offline('Bea');
    await b.transport.stop();
    final sweep = b.debugSweep();
    b.dispose();
    await b.vault.db.close();
    await sweep;
  });

  test(
      '13. the sweep\'s timer stops itself once it finds the vault closed, '
      'and "Wipe everything" stops every clock and waits for a running sweep '
      'before the vault goes', () async {
    // A tick every 50 ms, in a zone that keeps whatever escapes one.
    final escaped = <Object>[];
    final svc = await runZonedGuarded(() async {
      final vault = await Vault.open(rootOverride: temp('tick'));
      final id = await ZIdentity.generate();
      await vault.kvPut('identity', jsonEncode(id.toJson()));
      return ChatService.init(
          vault: vault,
          identity: id,
          displayName: 'Tia',
          transport: Transport(identity: id, serverUrl: 'ws://127.0.0.1:1'),
          ktConfig: KtConfig.off,
          sweepEvery: const Duration(milliseconds: 50));
    }, (e, _) => escaped.add(e))!;
    addTearDown(svc.dispose);
    await svc.transport.stop();
    expect(svc.debugSweeperActive, isTrue);
    await svc.vault.db.close(); // closed, never disposed
    await waitUntil(() => !svc.debugSweeperActive,
        what: 'a tick that found the vault closed stopping the timer');
    expect(escaped, isEmpty, reason: 'nothing a tick did reached the zone');

    // "Wipe everything" with a sweep running.
    final (w, _) = await offline('Walt');
    addTearDown(w.dispose);
    final root = w.vault.root;
    final sweeping = w.debugSweep();
    await w.wipeEverything();
    await sweeping; // ended, and quietly
    expect(root.existsSync(), isFalse);
    expect(w.debugSweeperActive, isFalse, reason: 'its clock stopped first');
  });

  // -------------------------------------------------------------------
  // Item 5: what a release build writes to the system log
  // -------------------------------------------------------------------

  test(
      '14. nothing in lib/ prints outside a debug-only branch — the app\'s '
      'and the protocol library\'s', () {
    final offenders = <String>[];
    for (final root in ['lib', '../protocol/lib']) {
      for (final f in Directory(root)
          .listSync(recursive: true)
          .whereType<File>()
          .where((f) => f.path.endsWith('.dart'))) {
        final lines = f.readAsLinesSync();
        for (var i = 0; i < lines.length; i++) {
          final line = lines[i].trimLeft();
          if (line.startsWith('//')) continue;
          if (!RegExp(r'(^|[^\w.])(debugPrint|print)\(').hasMatch(line)) {
            continue;
          }
          // Gated: the nearest enclosing `if` names kDebugMode.
          var gated = false;
          for (var j = i - 1; j >= 0 && j >= i - 3; j--) {
            if (lines[j].contains('if (kDebugMode)')) gated = true;
          }
          if (!gated) offenders.add('${f.path}:${i + 1}: ${line.trim()}');
        }
      }
    }
    expect(offenders, isEmpty,
        reason: 'a print in a release build goes to the system log, which '
            'adb, the system\'s tools and every bug report can read');
  });

  test(
      '15. a release build writes nothing of an error to the system log: not '
      'its text, and not the routing id in it', () {
    final savedPrint = debugPrint;
    final savedOnError = FlutterError.onError;
    final dispatcher = PlatformDispatcher.instance;
    final savedDispatcher = dispatcher.onError;
    addTearDown(() {
      debugPrint = savedPrint;
      FlutterError.onError = savedOnError;
      dispatcher.onError = savedDispatcher;
    });
    const rid = 'u8hCw3XwA2Qm0oV1yZr6Tk'; // a routing id's shape
    final error = KtSendHeldException(rid);
    final printed = <String>[];
    void logged(void Function() body) => runZoned(body,
        zoneSpecification: ZoneSpecification(
            print: (self, parent, zone, line) => printed.add(line)));

    // The control: left to itself, the framework prints an error it caught
    // — the debug form here; a release build prints the same text, through
    // debugPrintStack (`FlutterError.dumpErrorToConsole`).
    FlutterError.resetErrorCount();
    logged(() {
      debugPrint = debugPrintSynchronously;
      FlutterError.dumpErrorToConsole(FlutterErrorDetails(exception: error));
    });
    FlutterError.resetErrorCount();
    debugPrint = savedPrint;
    expect(printed.join('\n'), contains(rid),
        reason: "an error's report carries its text");

    // Outside a release build nothing changes.
    quietReleaseLog(release: false);
    expect(identical(debugPrint, savedPrint), isTrue);
    expect(identical(FlutterError.onError, savedOnError), isTrue);
    expect(identical(dispatcher.onError, savedDispatcher), isTrue);

    // A release build: the app's own line, an error the framework caught,
    // and one nothing caught — and nothing printed.
    printed.clear();
    logged(() {
      quietReleaseLog(release: true);
      debugPrint('group fan-out to $rid failed, will retry: $error');
      FlutterError.reportError(FlutterErrorDetails(exception: error));
      expect(dispatcher.onError!(error, StackTrace.current), isTrue,
          reason: 'handled, so the engine does not print it either');
    });
    expect(printed, isEmpty);
  });

  // -------------------------------------------------------------------
  // Item 6: what the keyboard keeps
  // -------------------------------------------------------------------

  test(
      '16a. every field that takes a secret asks the keyboard to learn '
      'nothing, and one that can show what it holds to suggest and correct '
      'nothing too', () {
    // A source check, as 5 is. A passphrase field is known by obscureText;
    // a code field by the code it asks for: a backup's recovery code by its
    // `ZBK-` hint, a handle's recovery code and a pairing code by their
    // labels.
    const codeMarks = ["'ZBK-", 'l.hdlCodeLabel', 'l.linkPairingCode'];
    final secret = <String>[];
    final offenders = <String>[];
    for (final f in Directory('lib/ui')
        .listSync(recursive: true)
        .whereType<File>()
        .where((f) => f.path.endsWith('.dart'))) {
      final src = f.readAsStringSync();
      for (final m in RegExp(r'\bText(?:Form)?Field\(').allMatches(src)) {
        var depth = 0, i = m.end - 1;
        for (; i < src.length; i++) {
          if (src[i] == '(') depth++;
          if (src[i] == ')' && --depth == 0) break;
        }
        final args = src.substring(m.end, i);
        if (!args.contains('obscureText:') && !codeMarks.any(args.contains)) {
          continue;
        }
        final at =
            '${f.path}:${src.substring(0, m.start).split('\n').length}';
        secret.add(at);
        final learns = !args.contains('enableIMEPersonalizedLearning: false');
        final canShow = !args.contains('obscureText: true');
        final suggests = !args.contains('enableSuggestions: false') ||
            !args.contains('autocorrect: false');
        if (learns || (canShow && suggests)) offenders.add(at);
      }
    }
    // Twelve today: six for a passphrase, three for a backup's recovery
    // code, two for a handle's and one for a pairing code. Fewer would mean
    // the marks stopped finding them.
    expect(secret, hasLength(greaterThanOrEqualTo(12)), reason: '$secret');
    expect(offenders, isEmpty,
        reason: 'a keyboard asked nothing may learn what is typed here, and '
            'keep it');
  });

  testWidgets(
      '16b. the restore\'s recovery-code field tells the keyboard to suggest, '
      'correct and learn nothing', (t) async {
    final picker = await restoreScreen(t);
    picker.contents = utf8.encode(archive);
    await tapRestore(t);
    await settleUntil(
        t, () => find.text(en.onbRecoveryCode).evaluate().isNotEmpty,
        what: 'the recovery-code dialog');
    await t.showKeyboard(find.descendant(
        of: find.byType(AlertDialog), matching: find.byType(TextField)));
    final told = t.testTextInput.setClientArgs!;
    expect(told['autocorrect'], isFalse);
    expect(told['enableSuggestions'], isFalse);
    expect(told['enableIMEPersonalizedLearning'], isFalse);

    await t.tap(find.text(en.cancel));
    await settleUntil(
        t, () => find.text(en.onbRecoveryCode).evaluate().isEmpty,
        what: 'the dialog dismissed');
    await settleUntil(t, () => !picker.copies.single.existsSync(),
        what: 'the copy deleted, as in 4b',
        timeout: const Duration(seconds: 5));
  });

  testWidgets(
      '16c. the unlock screen\'s passphrase tells the keyboard to learn '
      'nothing while hidden, and to suggest and correct nothing once shown',
      (t) async {
    await t.pumpWidget(MaterialApp(
      debugShowCheckedModeBanner: false,
      theme: ZTheme.light(),
      localizationsDelegates: AppLocalizations.localizationsDelegates,
      supportedLocales: AppLocalizations.supportedLocales,
      home: UnlockScreen(onUnlock: (_) async {}),
    ));
    await t.showKeyboard(find.byType(TextField));
    var told = t.testTextInput.setClientArgs!;
    expect(told['obscureText'], isTrue);
    expect(told['enableIMEPersonalizedLearning'], isFalse);

    // Shown, the passphrase is plain text to the keyboard: the field's
    // configuration is sent again, and it must still ask.
    await t.tap(find.byTooltip(en.unlockShowPassphrase));
    await t.pump();
    told = t.testTextInput.setClientArgs!;
    expect(told['obscureText'], isFalse);
    expect(told['autocorrect'], isFalse);
    expect(told['enableSuggestions'], isFalse);
    expect(told['enableIMEPersonalizedLearning'], isFalse);
  });
}
