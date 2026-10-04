// 24.4 — the "you're behind" check, without the network.
//
// There is no in-app updater; this only tells the user a newer build exists
// (THREAT_MODEL R8, R35). What is checked here is that it is honest and quiet:
// it only ever says "behind" when a well-formed, strictly-newer version comes
// back, it asks the relay's OWN host and nowhere else, and every bad or absent
// answer is a silent not-behind rather than a prompt. The metadata posture —
// no account, no routing id, the same file for everyone — is the server's to
// serve (server/test/pages.test.js) and is asserted here as "the URL it asks
// is the relay host's /latest.json, derived from the address already dialled".
//
// Criteria, each a test below:
//  1. semver compares as versions, not strings, and a malformed version — on
//     either side — is never "behind", so a broken answer cannot nag;
//  2. the URL asked is the relay's own host, https for a wss relay and http
//     for a ws one, and a non-ws address yields no check at all;
//  3. a strictly-newer /latest.json is reported behind, carrying the version,
//     and the link to show is the app's own (ADR 0014, amended 2026-10-04);
//  4. an equal or older version is not behind;
//  5. every non-answer — a 404/unreachable (null body), a malformed body, a
//     body with no version — is not-behind, never a prompt;
//  6. the link a newer version comes with is never the one /latest.json
//     names: the relay decides whether there is something newer, not where
//     the user goes to get it;
//  7. the Settings notice shows the project's release page to an install
//     that did not come from Google Play — never a URL an earlier check left
//     behind in prefs.json;
//  8. a Google Play install is sent to its Play listing, never to the
//     release page's APK, which cannot install over it;
//  9. where the notice sends someone is decided by the installer alone —
//     Google Play's to the listing, any other or none to the release page —
//     and a check keeps no link: one an older build left in prefs.json is
//     gone at the next write.
import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:provider/provider.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/app_lock.dart';
import 'package:zapp/core/chat_service.dart';
import 'package:zapp/core/key_transparency.dart';
import 'package:zapp/core/prefs.dart';
import 'package:zapp/core/push_service.dart';
import 'package:zapp/core/transport.dart';
import 'package:zapp/core/update_check.dart';
import 'package:zapp/core/vault.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/l10n/app_localizations_en.dart';
import 'package:zapp/ui/settings_screen.dart';
import 'package:zapp/ui/theme.dart';

// Where the project's builds are published, and where Google Play lists the
// app. Written out here rather than imported: the test states which places
// the notice may send someone, independently of the code under test.
const releasesPage =
    'https://github.com/FluffyHorizon1/z-messanger/releases/latest';
const playListing =
    'https://play.google.com/store/apps/details?id=com.zmessenger.www';
// A download address a relay — or whoever answers in its name — could plant.
const planted = 'https://z-update.example/z-3.10.1.apk';

/// Pump until [cond] holds, letting real work run in between: a widget test's
/// clock is fake, and the screen reads a real vault that only real time
/// completes.
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
  const relay = 'wss://www.zmessengers.com';

  test('1. semver compares as versions, and a malformed version is never behind',
      () {
    expect(isBehind('3.6.10', '3.7.0'), isTrue);
    expect(isBehind('3.6.9', '3.6.10'), isTrue, reason: '10 > 9, not "1.0" < "9"');
    expect(isBehind('3.7.0', '3.7.0'), isFalse);
    expect(isBehind('3.7.1', '3.7.0'), isFalse);
    expect(isBehind('3.7.0', '3.7.0+165'), isFalse, reason: 'build tail ignored');
    // A version that does not parse, on either side, is never behind.
    expect(isBehind('3.7.0', 'latest'), isFalse);
    expect(isBehind('unknown', '3.7.0'), isFalse);
    expect(parseSemver('3.7.0-rc1'), [3, 7, 0]);
    expect(parseSemver('v3.7.0'), isNull);
  });

  test('2. the URL is the relay\'s own host, and a non-ws address yields no check',
      () async {
    expect(latestJsonUrl('wss://www.zmessengers.com').toString(),
        'https://www.zmessengers.com/latest.json');
    expect(latestJsonUrl('ws://127.0.0.1:8080').toString(),
        'http://127.0.0.1:8080/latest.json');
    expect(latestJsonUrl('https://example.com'), isNull);
    expect(latestJsonUrl('not a url at all'), isNull);

    // checkForUpdate on a non-ws relay must not reach out at all.
    var called = false;
    final s = await checkForUpdate(
        current: '3.7.0',
        relayUrl: 'https://example.com',
        get: (u) async {
          called = true;
          return null;
        });
    expect(called, isFalse, reason: 'a non-ws address yields no fetch');
    expect(s.behind, isFalse);
  });

  test('3. a strictly-newer latest is reported behind, with version and link',
      () async {
    Uri? asked;
    final s = await checkForUpdate(
      current: '3.6.10',
      relayUrl: relay,
      get: (u) async {
        asked = u;
        return jsonEncode({'version': '3.7.0', 'url': 'https://x/releases/latest'});
      },
    );
    expect(asked.toString(), 'https://www.zmessengers.com/latest.json',
        reason: 'it asks the relay host it was given, nowhere else');
    expect(s.behind, isTrue);
    expect(s.latest, '3.7.0');
    expect(s.url, releasesPage,
        reason: 'the link is the app\'s own, not the one in the answer');
  });

  test('4. an equal or older version is not behind', () async {
    for (final v in ['3.7.0', '3.6.9']) {
      final s = await checkForUpdate(
          current: '3.7.0',
          relayUrl: relay,
          get: (u) async => jsonEncode({'version': v}));
      expect(s.behind, isFalse, reason: 'current 3.7.0 vs latest $v');
    }
  });

  test('5. every non-answer is a silent not-behind, never a prompt', () async {
    // 404 / unreachable — the injected get returns null for both.
    final nulled = await checkForUpdate(
        current: '3.6.10', relayUrl: relay, get: (u) async => null);
    expect(nulled.behind, isFalse);
    expect(nulled.latest, isNull);

    // A body that is not JSON, and JSON with no version.
    for (final body in ['not json', '{}', '{"url":"x"}', '[]']) {
      final s = await checkForUpdate(
          current: '3.6.10', relayUrl: relay, get: (u) async => body);
      expect(s.behind, isFalse, reason: 'body: $body');
    }
  });

  test('6. the link is never the one /latest.json names', () async {
    final s = await checkForUpdate(
        current: '3.10.0',
        relayUrl: relay,
        get: (u) async => jsonEncode({'version': '3.10.1', 'url': planted}));
    expect(s.behind, isTrue,
        reason: 'whether something newer exists is still the relay\'s answer');
    expect(s.latest, '3.10.1');
    expect(s.url, isNot(planted),
        reason: 'where to get it is not: a relay that could choose the link '
            'could send every user of it to a download of its choosing');
    expect(jsonEncode(s.toJson()), isNot(contains('z-update.example')));
  });

  group('the Settings notice', () {
    late Directory dir;
    late ChatService svc;
    late PushService push;
    late AppLock lock;

    setUp(() async {
      dir = await Directory.systemTemp.createTemp('z_update');
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
      push = PushService(transport: svc.transport, vault: vault);
      lock = AppLock(root: dir, store: MemorySecretStore());
    });

    tearDown(() async {
      await svc.transport.stop();
      await svc.vault.db.close();
      if (dir.existsSync()) dir.deleteSync(recursive: true);
    });

    /// Settings as a running build of [version] shows it, with [url] left in
    /// prefs.json by an earlier check — a check made today, so none is made
    /// now. [installer] is what the platform reports installed the app.
    Future<void> openSettings(WidgetTester t,
        {required String url, String? installer}) async {
      PackageInfo.setMockInitialValues(
          appName: 'Z',
          packageName: 'com.zmessenger.www',
          version: '3.10.0',
          buildNumber: '200',
          buildSignature: '',
          installerStore: installer);
      final prefs = AppPrefs(root: dir);
      await t.runAsync(() async {
        await File('${dir.path}/prefs.json').writeAsString(jsonEncode({
          'v': 1,
          'theme': 'system',
          'upd': {
            'ts': DateTime.now().millisecondsSinceEpoch,
            'ver': '3.10.1',
            'url': url,
          },
        }));
        await prefs.load();
      });
      await t.pumpWidget(MultiProvider(
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
          localizationsDelegates: AppLocalizations.localizationsDelegates,
          supportedLocales: AppLocalizations.supportedLocales,
          home: const SettingsScreen(),
        ),
      ));
      await settleUntil(
          t,
          () => find
              .text(AppLocalizationsEn().stUpdateTitle)
              .evaluate()
              .isNotEmpty,
          what: 'the update notice in Settings');
    }

    testWidgets('7. an install not from Play is shown the release page',
        (t) async {
      await openSettings(t, url: planted);
      expect(find.text(planted), findsNothing,
          reason: 'a URL an earlier check stored is not shown');
      expect(find.text(releasesPage), findsOneWidget,
          reason: 'the app\'s own destination for a desktop build or an APK');
    });

    testWidgets('8. a Play install is sent to Play, not to the APK',
        (t) async {
      // What the official relay serves: the release page. Right for a desktop
      // build, wrong for a Play install — under Play App Signing the APK
      // there is signed with a different key and cannot install over it.
      await openSettings(t, url: releasesPage, installer: 'com.android.vending');
      expect(find.text(releasesPage), findsNothing);
      expect(find.text(playListing), findsOneWidget);
    });
  });

  test('9. the installer alone picks the link, and none is kept', () async {
    expect(updateDestination(installerStore: 'com.android.vending'),
        playListing);
    // Sideloaded from the release page (the system installer, a browser, a
    // file manager), another store, adb (null), or a desktop build (null).
    for (final other in [
      null,
      '',
      'com.google.android.packageinstaller',
      'com.android.chrome',
      'org.fdroid.fdroid',
    ]) {
      expect(updateDestination(installerStore: other), releasesPage,
          reason: 'installer $other');
    }
    final fromPlay = await checkForUpdate(
        current: '3.10.0',
        relayUrl: relay,
        installerStore: 'com.android.vending',
        get: (u) async =>
            jsonEncode({'version': '3.10.1', 'url': releasesPage}));
    expect(fromPlay.url, playListing,
        reason: 'the check hands back the same answer the notice shows');

    // A check records the version and nothing about where to get it; a link
    // an older build stored is not read back, and the next write drops it.
    final dir = await Directory.systemTemp.createTemp('z_prefs');
    addTearDown(() => dir.deleteSync(recursive: true));
    final file = File('${dir.path}/prefs.json');
    await file.writeAsString(jsonEncode({
      'v': 1,
      'theme': 'dark',
      'upd': {'ts': 1, 'ver': '3.10.1', 'url': planted},
    }));
    final prefs = AppPrefs(root: dir);
    await prefs.load();
    expect(prefs.latestVersion, '3.10.1');
    await prefs.recordUpdateCheck(atMs: 2, latestVersion: '3.10.2');
    final stored = await file.readAsString();
    expect(stored, isNot(contains('z-update.example')));
    expect(stored, isNot(contains('"url"')));
    expect((jsonDecode(stored) as Map)['upd'], {'ts': 2, 'ver': '3.10.2'});
    expect((jsonDecode(stored) as Map)['theme'], 'dark',
        reason: 'the rest of the file is untouched');
  });
}
