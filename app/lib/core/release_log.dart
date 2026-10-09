// What a release build writes to the system log (42.5): nothing of its own.
//
// Android keeps one log for the whole device, and a release build of a
// Flutter app writes to it: Dart's `print` and Flutter's `debugPrint` are not
// stripped, the framework reports an error it caught by printing the error
// (`FlutterError.presentError`, which in a release build prints the error's
// own text and its stack), and the engine reports one nothing caught as
// "Unhandled Exception:" followed by the same text. That text is where this
// app's identifiers are: `KtSendHeldException` names the routing id whose
// sends it holds, a SQLite error quotes the arguments of the query that
// failed — routing ids, message ids — and a JSON error quotes the input it
// could not read. The log is not readable by other apps since Android 4.1,
// but it is by `adb`, by the system's own tools, and in every bug report a
// person is asked to send.
//
// Patch 48 found a `debugPrint` that named a routing id in a release build
// and made it debug-only; it was the only call in `lib/`, and
// `device_hardening_test.dart` 14 keeps it that way for the app and the
// protocol library both. What this does is the rest: in a release build,
// `debugPrint` prints nothing, and an error the framework caught or nothing
// caught is dropped rather than printed. Nothing else changes — neither the
// framework nor the engine stops the app for such an error in a release
// build, before or after. There is no crash reporter (`DATA_MAP.md`), so the
// log is not a channel this app reports through; a debug or profile build,
// which a developer reading the log is running, keeps all of it.
//
// Not covered: the log lines a plugin's own Java or Kotlin writes, and a
// `print` in a plugin's Dart code — file_picker prints the platform's message
// when a pick fails. Neither is this app's code to change.

import 'package:flutter/foundation.dart';

/// Turns the app's own logging off in a release build ([release]); a no-op
/// in a debug or profile build. Called once, first thing, by `startApp`.
void quietReleaseLog({bool release = kReleaseMode}) {
  if (!release) return;
  debugPrint = (String? message, {int? wrapWidth}) {};
  FlutterError.onError = (FlutterErrorDetails details) {};
  PlatformDispatcher.instance.onError = (Object error, StackTrace stack) => true;
}
