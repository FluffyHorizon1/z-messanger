// 24.1 / 24.3 — the desktop app starts whatever its audio backend does, and
// offers to read a QR image only where something can read one.
//
// P1-18: `initDesktopAudio` ran before runApp with nothing around it, and
// media_kit rethrows when it cannot load libmpv. On Linux libmpv is a system
// library — the build bundles none — so on a machine without it the process
// never drew a window. It is caught now: playback is off for the run and the
// app says what to install. Tests 1-3 were written first, against the code
// before the fix, and failed there; 1 and 2 run this host's real backend,
// which on a Linux machine without libmpv is the failure itself. The rest
// inject a backend that fails the way such a machine's does — the `load:` /
// `loadAudio:` seam — so they do not depend on what the host has installed.
//
// Criteria, each a test below:
//   1. on this host's own audio backend — the machine this was written on is
//      Linux without libmpv, the case being reproduced; one that has it just
//      loads it — the start-up audio registration does not throw;
//   2. the app's own main() reaches its first screen on this host;
//   3. the Paste tab offers "Open a QR image" only where mobile_scanner has a
//      decoder (Android, iOS, macOS), so not on this Linux host;
//   4. a backend that fails to load is caught: Linux and Windows come back
//      `unavailable`, keeping the OS so the notice names the right fix; one
//      that loads comes back `mediaKit`; every other platform, and the web,
//      is `native` and never calls the loader;
//   5. started with a failing backend, the app reaches its first screen with
//      the notice above it naming what to install, in English and in
//      Spanish, and dismissing the notice leaves that screen in place;
//   6. with the backend unavailable, a voice note's control says playback is
//      off, and tapping it explains why without reading the note or making a
//      player; with a backend it is the ordinary play control;
//   7. the QR-from-image policy: Android, iOS and macOS, where mobile_scanner
//      implements analyzeImage; not Linux, Windows or the web.
import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:qr_flutter/qr_flutter.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/desktop_audio.dart';
import 'package:zapp/core/key_transparency.dart';
import 'package:zapp/core/models.dart';
import 'package:zapp/core/qr_image.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/l10n/app_localizations_en.dart';
import 'package:zapp/l10n/app_localizations_es.dart';
import 'package:zapp/main.dart' as app;
import 'package:zapp/ui/add_contact_screen.dart';
import 'package:zapp/ui/onboarding_screen.dart';
import 'package:zapp/ui/theme.dart';
import 'package:zapp/ui/voice_widgets.dart';

/// Whether this host can load libmpv under any name media_kit tries.
bool hostHasLibmpv() {
  for (final name in ['libmpv.so', 'libmpv.so.2', 'libmpv.so.1']) {
    try {
      DynamicLibrary.open(name);
      return true;
    } catch (_) {}
  }
  return false;
}

/// A backend that fails the way media_kit's does on a Linux machine with no
/// libmpv installed: the same exception, thrown from the same call.
void noLibmpv({required bool linux, required bool windows}) =>
    throw Exception('Cannot find libmpv at the usual places.');

/// Pump until [cond] holds, letting real work run in between: a widget test's
/// clock is fake, and the app's start opens a real vault — files, and an
/// SQLite database on its own isolate — which only real time completes.
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

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final l = AppLocalizationsEn();
  const pathChannel = MethodChannel('plugins.flutter.io/path_provider');

  test('1. the start-up audio registration does not throw on this host', () {
    expect(() => initDesktopAudio(Platform.operatingSystem), returnsNormally,
        reason: 'host ${Platform.operatingSystem}, libmpv loadable: '
            '${hostHasLibmpv()}');
  });

  testWidgets('2. the app\'s own main() reaches its first screen on this host',
      (tester) async {
    final dir = await tester.runAsync(
        () => Directory.systemTemp.createTemp('z_startup'));
    addTearDown(() => dir!.deleteSync(recursive: true));
    // The app keeps its vault under the platform's application-support
    // directory; here that is a fresh temp directory, so the first screen is
    // the one a new install shows.
    tester.binding.defaultBinaryMessenger
        .setMockMethodCallHandler(pathChannel, (call) async => dir!.path);
    addTearDown(() => tester.binding.defaultBinaryMessenger
        .setMockMethodCallHandler(pathChannel, null));

    app.main();
    await settleUntil(
        tester, () => find.byType(OnboardingScreen).evaluate().isNotEmpty,
        what: 'the onboarding screen');
    expect(find.text(l.onbTagline), findsOneWidget);

    final vault =
        tester.widget<OnboardingScreen>(find.byType(OnboardingScreen)).vault;
    await tester.runAsync(() => vault.db.close());
  });

  group('the Paste tab', () {
    late Directory dir;
    late ChatService svc;

    setUp(() async {
      dir = await Directory.systemTemp.createTemp('z_qrimg');
      final vault = await Vault.open(rootOverride: dir);
      final me = await ZIdentity.generate();
      await vault.kvPut('identity', jsonEncode(me.toJson()));
      // Nothing here talks to anyone: the relay address is a closed local
      // port and the transparency log is off.
      svc = await ChatService.init(
          vault: vault,
          identity: me,
          displayName: 'Finn',
          transport: Transport(identity: me, serverUrl: 'ws://127.0.0.1:1'),
          ktConfig: KtConfig.off);
    });

    tearDown(() async {
      await svc.transport.stop();
      await svc.vault.db.close();
      if (dir.existsSync()) dir.deleteSync(recursive: true);
    });

    testWidgets(
        '3. offers "Open a QR image" only where there is a decoder — not on '
        'this host if it is Linux or Windows', (tester) async {
      await tester.pumpWidget(ChangeNotifierProvider<ChatService>.value(
        value: svc,
        child: MaterialApp(
          debugShowCheckedModeBanner: false,
          theme: ZTheme.light(),
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: const AddContactScreen(),
        ),
      ));
      await settleUntil(
          tester, () => find.byType(QrImageView).evaluate().isNotEmpty,
          what: 'my own code on the first tab');
      await tester.tap(find.text(l.addPaste));
      await settleUntil(
          tester, () => find.text(l.addVerifyAndAdd).evaluate().isNotEmpty,
          what: 'the Paste tab');
      // And the switch to it finished: a tab animation still running when
      // the test ends leaves its ticker behind for the next test.
      final tabs = tester.widget<TabBar>(find.byType(TabBar)).controller!;
      await settleUntil(tester, () => tabs.index == 1 && !tabs.indexIsChanging,
          what: 'the switch to the Paste tab');
      // mobile_scanner's analyzeImage exists on Android, iOS and macOS only.
      const decoders = {'android', 'ios', 'macos'};
      final decoder = decoders.contains(Platform.operatingSystem);
      expect(find.text(l.addOpenImage), decoder ? findsOneWidget : findsNothing,
          reason: 'on ${Platform.operatingSystem} there is '
              '${decoder ? 'a' : 'no'} decoder for the button to use');
    });
  });

  test('4. a backend that fails to load is caught, and only desktop loads one',
      () {
    for (final os in ['linux', 'windows']) {
      expect(initDesktopAudio(os, isWeb: false, load: noLibmpv),
          VoicePlayback.unavailable,
          reason: '$os: a missing libmpv is an answer, not a crash');
      expect(voicePlayback, VoicePlayback.unavailable);
      expect(voicePlaybackOs, os, reason: 'the notice names the fix for $os');
    }
    // Not only Exceptions: whatever the load throws is the same answer.
    expect(
        initDesktopAudio('linux',
            isWeb: false,
            load: ({required bool linux, required bool windows}) =>
                throw ArgumentError('libmpv.so.2: wrong ELF class')),
        VoicePlayback.unavailable);

    final asked = <({bool linux, bool windows})>[];
    void loads({required bool linux, required bool windows}) =>
        asked.add((linux: linux, windows: windows));
    expect(initDesktopAudio('linux', isWeb: false, load: loads),
        VoicePlayback.mediaKit);
    expect(initDesktopAudio('windows', isWeb: false, load: loads),
        VoicePlayback.mediaKit);
    expect(asked, [(linux: true, windows: false), (linux: false, windows: true)]);

    for (final os in ['android', 'ios', 'macos', 'fuchsia', '']) {
      expect(initDesktopAudio(os, isWeb: false, load: loads),
          VoicePlayback.native,
          reason: '$os keeps the player it has');
    }
    expect(initDesktopAudio('linux', isWeb: true, load: loads),
        VoicePlayback.native);
    expect(asked, hasLength(2),
        reason: 'nothing but Linux and Windows ever loads a backend');
  });

  testWidgets(
      '5. started with a failing backend, the app reaches its first screen '
      'and says what to install', (tester) async {
    final dir = await tester.runAsync(
        () => Directory.systemTemp.createTemp('z_startup'));
    addTearDown(() => dir!.deleteSync(recursive: true));
    tester.binding.defaultBinaryMessenger
        .setMockMethodCallHandler(pathChannel, (call) async => dir!.path);
    addTearDown(() => tester.binding.defaultBinaryMessenger
        .setMockMethodCallHandler(pathChannel, null));
    addTearDown(tester.platformDispatcher.clearLocalesTestValue);

    app.startApp(operatingSystem: 'linux', loadAudio: noLibmpv);
    await settleUntil(
        tester, () => find.byType(OnboardingScreen).evaluate().isNotEmpty,
        what: 'the onboarding screen');
    expect(find.text(l.voiceNoLibmpvLinux), findsOneWidget,
        reason: 'the first screen says why voice messages will not play');
    expect(l.voiceNoLibmpvLinux,
        allOf(contains('libmpv2'), contains('mpv-libs'), contains('restart')),
        reason: 'and names what to install, then what to do');

    // A Spanish reader gets it in Spanish, with the package names as they are.
    tester.platformDispatcher.localesTestValue = const [Locale('es')];
    await tester.pump();
    final es = AppLocalizationsEs();
    expect(find.text(es.voiceNoLibmpvLinux), findsOneWidget);
    expect(es.voiceNoLibmpvLinux, isNot(l.voiceNoLibmpvLinux));
    expect(es.voiceNoLibmpvLinux,
        allOf(contains('libmpv2'), contains('mpv-libs')));
    tester.platformDispatcher.clearLocalesTestValue();
    await tester.pump();

    // Dismissed, it goes; the screen it sat above stays as it was.
    await tester.tap(find.widgetWithText(TextButton, l.dismiss));
    await tester.pump();
    expect(find.text(l.voiceNoLibmpvLinux), findsNothing);
    expect(find.byType(OnboardingScreen), findsOneWidget);
    expect(find.text(l.onbTagline), findsOneWidget);

    final vault =
        tester.widget<OnboardingScreen>(find.byType(OnboardingScreen)).vault;
    await tester.runAsync(() => vault.db.close());
  });

  testWidgets(
      '6. with no backend a voice note says playback is off and opens nothing',
      (tester) async {
    final note = FileMeta(
        fid: 'f1',
        name: 'voice.wav',
        size: 32000,
        mime: 'audio/wav',
        sha256b64: '',
        complete: true,
        voice: true,
        durSec: 3);
    // No ChatService above the bubble: playing would have to read the note
    // through one, and that read failing would surface as the generic
    // "cannot play" notice instead of the one asserted below.
    Widget bubble() => MaterialApp(
          debugShowCheckedModeBanner: false,
          theme: ZTheme.light(),
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: Scaffold(
              body: Center(child: VoiceNoteBody(fid: 'f1', meta: note))),
        );

    for (final os in ['linux', 'windows']) {
      initDesktopAudio(os, isWeb: false, load: noLibmpv);
      await tester.pumpWidget(bubble());
      expect(find.byTooltip(l.voicePlaybackOff), findsOneWidget, reason: os);
      expect(find.byTooltip(l.voicePlay), findsNothing, reason: os);
      expect(find.byIcon(Icons.volume_off), findsOneWidget);

      await tester.tap(find.byTooltip(l.voicePlaybackOff));
      await tester.pump();
      final why = os == 'linux' ? l.voiceNoLibmpvLinux : l.voiceNoLibmpvWindows;
      expect(find.text(why), findsOneWidget,
          reason: '$os: it says why, and names the fix');
      expect(find.text(l.voiceNoPlayback), findsNothing,
          reason: 'nothing was read and no player was tried');
      // Let the snack bar go before the next round.
      await tester.pumpWidget(const SizedBox());
      await tester.pump(const Duration(seconds: 5));
    }

    // With a backend the bubble is the ordinary player again.
    initDesktopAudio('linux',
        isWeb: false, load: ({required bool linux, required bool windows}) {});
    await tester.pumpWidget(bubble());
    expect(find.byTooltip(l.voicePlay), findsOneWidget);
    expect(find.byTooltip(l.voicePlaybackOff), findsNothing);
    initDesktopAudio('android', isWeb: false);
  });

  test('7. QR-from-image is an Android, iOS and macOS policy', () {
    for (final os in ['android', 'ios', 'macos']) {
      expect(qrImageDecodeFor(os), isTrue, reason: os);
      expect(qrImageDecodeFor(os, isWeb: true), isFalse,
          reason: 'analyzeImage throws on the web');
    }
    for (final os in ['linux', 'windows', 'fuchsia', '']) {
      expect(qrImageDecodeFor(os), isFalse, reason: os);
    }
  });
}
