// continuous-b (playback): the inline video bubble and where it appears.
//
// The property that matters is not that video plays — that is hardware-gated,
// like the camera and 24.1's audio — but what the bubble does around playing:
// it decrypts nothing until asked, it hands bytes to the player only through
// the loopback server (never a file), and when the player cannot start it says
// so and leaves nothing listening. In this test environment there is no
// video_player implementation, so the failure path is the one exercised, which
// is also the one a platform without a backend takes in the field.
//
// Criteria, each a test below:
//   1. the platform policy: inline on Android only; the web and every other OS
//      keep the file card + Save;
//   2. before the user asks, the bubble shows a play control and has neither
//      read the bytes nor opened a server;
//   3. when the player cannot start, the bubble says so, and the server it
//      opened for the attempt is closed — nothing is left listening.
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/inline_video.dart';
import 'package:zapp/core/loopback_media.dart';
import 'package:zapp/core/models.dart';
import 'package:zapp/l10n/app_localizations.dart';
import 'package:zapp/l10n/app_localizations_en.dart';
import 'package:zapp/ui/theme.dart';
import 'package:zapp/ui/video_widgets.dart';

void main() {
  test('1. inline video is an Android policy', () {
    expect(inlineVideoFor('android'), isTrue);
    for (final os in ['ios', 'macos', 'linux', 'windows', 'fuchsia', '']) {
      expect(inlineVideoFor(os), isFalse, reason: os);
    }
    expect(inlineVideoFor('android', isWeb: true), isFalse);
  });

  final meta = FileMeta(
      fid: 'f1',
      name: 'clip.mp4',
      size: 12,
      mime: 'video/mp4',
      sha256b64: '',
      complete: true);

  Widget host(Widget child) => MaterialApp(
        debugShowCheckedModeBanner: false,
        theme: ZTheme.light(),
        localizationsDelegates: AppLocalizations.localizationsDelegates,
        supportedLocales: AppLocalizations.supportedLocales,
        home: Scaffold(body: Center(child: child)),
      );

  testWidgets('2. nothing is read or opened until the user presses play',
      (tester) async {
    var reads = 0;
    await tester.pumpWidget(host(VideoNoteBody(
      fid: 'f1',
      meta: meta,
      readBytes: (_, __) async {
        reads++;
        return Uint8List(12);
      },
    )));
    await tester.pump();
    expect(find.byTooltip('Play video'), findsOneWidget);
    expect(find.bySemanticsLabel('clip.mp4'), findsOneWidget,
        reason: 'the file name is the description of a video we cannot see into');
    expect(reads, 0, reason: 'lazy: decrypts on first play, not on build');
    expect(LoopbackMediaServer.openServers, 0);
  });

  testWidgets(
      '3. a player that cannot start leaves a notice and no server behind',
      (tester) async {
    var reads = 0;
    await tester.pumpWidget(host(VideoNoteBody(
      fid: 'f1',
      meta: meta,
      readBytes: (_, __) async {
        reads++;
        return Uint8List(12);
      },
    )));
    await tester.pump();
    final notice = find.text(AppLocalizationsEn().videoNoPlayback);
    // The bubble does real I/O (binds the loopback socket, reads the bytes),
    // which the test's fake clock cannot drive: run that stretch for real and
    // poll for the outcome. The server binds, the controller fails (no
    // platform implementation here), the bubble settles into its notice.
    await tester.runAsync(() async {
      await tester.tap(find.byTooltip('Play video'));
      await tester.pump();
      final deadline = DateTime.now().add(const Duration(seconds: 10));
      while (notice.evaluate().isEmpty && DateTime.now().isBefore(deadline)) {
        await Future<void>.delayed(const Duration(milliseconds: 25));
        await tester.pump();
      }
    });
    await tester.pump();
    expect(reads, 1, reason: 'the bytes were read exactly once, on demand');
    expect(notice, findsWidgets,
        reason: 'in the bubble, and as a snackbar — the same words');
    expect(find.byTooltip('Play video'), findsNothing);
    expect(LoopbackMediaServer.openServers, 0,
        reason: 'the server opened for the attempt is closed on failure');
  });
}
