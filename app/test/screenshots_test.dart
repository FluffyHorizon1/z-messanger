// Theme screenshots (7.6 themes). Renders the main screens in BOTH palettes
// with realistic data and writes PNGs to build/screenshots/, so a change to
// the palette or a screen can be eyeballed without a device — and, as a
// side effect, proves every screen builds in light and dark mode.
//
// Real Roboto + Material Icons are loaded from the Flutter SDK cache when
// it can be found (the test shell ships them), otherwise the test still
// runs with the placeholder font.
@Tags(['screenshots'])
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart' show FontLoader, MethodChannel;
import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;
import 'package:provider/provider.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/app_lock.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/prefs.dart';
import 'package:zapp/core/push_service.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/ui/chat_screen.dart';
import 'package:zapp/ui/home_screen.dart';
import 'package:zapp/ui/lock_screen.dart';
import 'package:zapp/ui/onboarding_screen.dart';
import 'package:zapp/ui/search_screen.dart';
import 'package:zapp/ui/settings_screen.dart';
import 'package:zapp/ui/theme.dart';
import 'package:zapp/ui/unlock_screen.dart';

const _phone = Size(390, 844);
final _outDir =
    Directory(p.join(Directory.current.path, 'build', 'screenshots'));

Future<void> _loadFonts() async {
  final candidates = <String>[
    if (Platform.environment['FLUTTER_ROOT'] != null)
      p.join(Platform.environment['FLUTTER_ROOT']!, 'bin', 'cache', 'artifacts',
          'material_fonts'),
    // flutter_tester lives in bin/cache/artifacts/engine/<platform>/.
    p.normalize(p.join(
        p.dirname(Platform.resolvedExecutable), '..', '..', 'material_fonts')),
  ];
  for (final dir in candidates) {
    final roboto = File(p.join(dir, 'Roboto-Regular.ttf'));
    if (!roboto.existsSync()) continue;
    Future<ByteData> bytes(String name) async {
      final b = await File(p.join(dir, name)).readAsBytes();
      return ByteData.view(b.buffer);
    }

    final r = FontLoader('Roboto')
      ..addFont(bytes('Roboto-Regular.ttf'))
      ..addFont(bytes('Roboto-Medium.ttf'))
      ..addFont(bytes('Roboto-Bold.ttf'));
    await r.load();
    final icons = FontLoader('MaterialIcons')
      ..addFont(bytes('MaterialIcons-Regular.otf'));
    await icons.load();
    return;
  }
}

class _Fixture {
  late Directory dir;
  late Vault vault;
  late ChatService svc;
  late PushService push;
  late AppLock lock;
  late AppPrefs prefs;
  late String aliceRid, bobRid, gid;

  Future<void> setUp() async {
    dir = await Directory.systemTemp.createTemp('z_shots');
    vault = await Vault.open(rootOverride: dir);
    final identity = await ZIdentity.generate();
    await vault.kvPut('identity', jsonEncode(identity.toJson()));
    final transport =
        Transport(identity: identity, serverUrl: 'ws://127.0.0.1:1');
    svc = await ChatService.init(
        vault: vault,
        identity: identity,
        displayName: 'Finn',
        transport: transport);
    push = PushService(transport: transport, vault: vault);
    lock = AppLock(root: dir, store: MemorySecretStore());
    prefs = AppPrefs(root: dir);

    Future<String> contact(String name) async {
      final other = await ZIdentity.generate();
      final c = await svc.addContactFromCode(
          await other.bundle().then((b) => b.encode()),
          alias: name);
      return c.rid;
    }

    aliceRid = await contact('Alice');
    bobRid = await contact('Bob');
    final t0 = DateTime.now().millisecondsSinceEpoch - 3600 * 1000;
    var n = 0;
    // Messages: the seal is async, so resolve it before inserting.
    Future<void> insert(String rid, bool out, String kind, String body,
        {int status = 1, String? fid}) async {
      await vault.db.insert('messages', {
        'mid': 'm${n++}',
        'rid': rid,
        'outgoing': out ? 1 : 0,
        'kind': kind,
        'enc_body': await vault.seal(body),
        'fid': fid,
        'ts_ms': t0 + n * 60 * 1000,
        'status': status,
        'expire_at_ms': 0,
      });
    }

    await insert(aliceRid, false, 'text', 'Are we still on for the hike?');
    await insert(aliceRid, true, 'text',
        'Yes — 7am at the trailhead. I\'ll bring the map.',
        status: 3);
    await insert(aliceRid, false, 'text',
        'Perfect. Sending the permit now so you have it on your phone.');
    await vault.db.insert('files', {
      'fid': 'f1',
      'rid': aliceRid,
      'mid': 'm$n',
      'enc_meta': await vault.seal(jsonEncode({
        'name': 'trail-permit.pdf',
        'size': 184320,
        'mime': 'application/pdf',
        'sha256': '',
      })),
      'complete': 1,
      'got_chunks': 3,
      'total_chunks': 3,
    });
    await insert(aliceRid, false, 'file', jsonEncode({}), fid: 'f1');
    await insert(aliceRid, true, 'text', 'Got it, thanks!', status: 2);
    await insert(bobRid, true, 'text', 'Lunch tomorrow?', status: 1);
    await insert(bobRid, false, 'text', 'Sure, 12:30 at the usual place.');

    gid = await svc.createGroup('Field team', [aliceRid, bobRid]);
    await insert(
        gid,
        false,
        'gtext',
        jsonEncode(
            {'b': 'Penguin sightings are up this week.', 'sn': 'Alice'}));
    await insert(gid, false, 'gtext',
        jsonEncode({'b': 'Three near the north colony.', 'sn': 'Bob'}));
    await insert(gid, true, 'gtext',
        jsonEncode({'b': 'I\'ll log them in the survey tonight.'}),
        status: 1);
    for (final rid in [aliceRid, bobRid, gid]) {
      await svc.loadMessages(rid);
    }
    svc.unread[bobRid] = 1;
  }

  Future<void> tearDown() async {
    await svc.transport.stop();
    if (dir.existsSync()) dir.deleteSync(recursive: true);
  }

  Widget wrap(Widget child, ThemeMode mode, {Key? key}) => MultiProvider(
        providers: [
          ChangeNotifierProvider<ChatService>.value(value: svc),
          ChangeNotifierProvider<Transport>.value(value: svc.transport),
          ChangeNotifierProvider<PushService>.value(value: push),
          ChangeNotifierProvider<AppLock>.value(value: lock),
          ChangeNotifierProvider<AppPrefs>.value(value: prefs),
        ],
        child: MaterialApp(
          debugShowCheckedModeBanner: false,
          theme: ZTheme.light(),
          darkTheme: ZTheme.dark(),
          themeMode: mode,
          home: RepaintBoundary(key: key, child: child),
        ),
      );
}

Future<void> _snap(WidgetTester tester, GlobalKey key, String name) async {
  await tester.runAsync(() async {
    final boundary =
        key.currentContext!.findRenderObject() as RenderRepaintBoundary;
    final image = await boundary.toImage(pixelRatio: 2);
    final bytes = await image.toByteData(format: ui.ImageByteFormat.png);
    _outDir.createSync(recursive: true);
    File(p.join(_outDir.path, '$name.png'))
        .writeAsBytesSync(bytes!.buffer.asUint8List());
  });
}

Future<void> _settle(WidgetTester tester, [int frames = 8]) async {
  for (var i = 0; i < frames; i++) {
    await tester.pump(const Duration(milliseconds: 60));
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final fx = _Fixture();

  setUpAll(() async {
    // The chat screen constructs an AudioRecorder, whose plugin does not
    // exist in the test shell: answer its channel with nulls.
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(
            const MethodChannel('com.llfbandit.record/messages'),
            (call) async => null);
    await _loadFonts();
    await fx.setUp();
  });
  tearDownAll(() => fx.tearDown());

  for (final mode in [ThemeMode.dark, ThemeMode.light]) {
    final suffix = mode.name;

    Future<void> shoot(WidgetTester tester, String name, Widget screen,
        {Future<void> Function()? act}) async {
      await tester.binding.setSurfaceSize(_phone);
      tester.view.devicePixelRatio = 2.0;
      // Real shadows (the test shell otherwise draws them as solid
      // outlines); the binding insists the flag is restored per test.
      debugDisableShadows = false;
      try {
        final key = GlobalKey();
        await tester.pumpWidget(fx.wrap(screen, mode, key: key));
        await _settle(tester);
        if (act != null) await act();
        await _snap(tester, key, '$name-$suffix');
      } finally {
        debugDisableShadows = true;
      }
    }

    testWidgets('onboarding ($suffix)', (tester) async {
      await shoot(tester, 'onboarding',
          OnboardingScreen(vault: fx.vault, onDone: () async {}));
    });

    testWidgets('unlock ($suffix)', (tester) async {
      await shoot(tester, 'unlock',
          UnlockScreen(onUnlock: (_) async {}, onBiometric: () async {}));
    });

    testWidgets('lock ($suffix)', (tester) async {
      final dir = Directory.systemTemp.createTempSync('z_shots_lock');
      final lock =
          AppLock(root: dir, gate: _CancelGate(), store: MemorySecretStore())
            ..lockNow();
      await shoot(tester, 'lock',
          LockScreen(lock: lock, verifyPassphrase: (_) async => false));
      dir.deleteSync(recursive: true);
    });

    testWidgets('home ($suffix)', (tester) async {
      await shoot(tester, 'home', const HomeScreen());
    });

    testWidgets('chat ($suffix)', (tester) async {
      await shoot(tester, 'chat', ChatScreen(rid: fx.aliceRid));
    });

    testWidgets('group chat ($suffix)', (tester) async {
      await shoot(tester, 'group', ChatScreen(rid: fx.gid));
    });

    testWidgets('search ($suffix)', (tester) async {
      await shoot(tester, 'search', const SearchScreen(), act: () async {
        await tester.enterText(find.byType(TextField), 'penguin');
        await tester.pump(const Duration(milliseconds: 300)); // debounce
        // The query alternates real database I/O (needs wall-clock time)
        // with fake-zone continuations (need a pump), so interleave both.
        for (var i = 0; i < 20; i++) {
          await tester.runAsync(
              () => Future<void>.delayed(const Duration(milliseconds: 50)));
          await tester.pump(const Duration(milliseconds: 50));
        }
      });
    });

    testWidgets('settings ($suffix)', (tester) async {
      await shoot(tester, 'settings', const SettingsScreen());
    });
  }
}

class _CancelGate implements BiometricGate {
  @override
  Future<bool> get isAvailable async => true;
  @override
  Future<GateResult> authenticate(String reason) async => GateResult.cancelled;
}
