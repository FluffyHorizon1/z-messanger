// Handing a file to the user (9.3), on five platforms that disagree about
// what that means.
//
// `FilePicker.saveFile` has three mutually incompatible contracts:
//
//   * Android and iOS  — `bytes` is REQUIRED (it throws ArgumentError without
//     them), the plugin writes the file itself and returns a path. Writing to
//     that path again is either a second copy or, on iOS, a write into a
//     security-scoped container that is not ours.
//   * macOS            — `bytes` must be ABSENT (it throws UnsupportedError
//     if given any), and the caller writes.
//   * Linux, Windows   — the dialog only chooses a path; the caller writes.
//
// Getting this wrong is silent on the platform you happen to be testing and
// broken on the others, which is exactly what had happened: the app passed
// `bytes` everywhere and then wrote again unless it was on Android, so saving
// an attachment or an identity backup threw on macOS, and would have written
// twice on iOS the moment that target existed.
//
// So the rule lives here once, expressed as a property of the platform rather
// than as a list of `Platform.isAndroid` checks scattered through the UI, and
// the callers say what they want rather than how to get it.

import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/foundation.dart';

/// Who writes the bytes once the user has chosen where the file goes.
enum SaveStyle {
  /// The picker writes them (Android, iOS). It requires the bytes up front,
  /// so a file saved this way is held in memory in full at least once.
  pickerWrites,

  /// The picker only returns a path; we write (Linux, macOS, Windows). Large
  /// files can be streamed, and never need to be materialised.
  callerWrites,
}

/// The platforms this app targets, as data — so the policy below can be
/// tested for every one of them from a Linux test runner.
enum HostPlatform { android, ios, linux, macos, windows, other }

HostPlatform _detect() {
  if (kIsWeb) return HostPlatform.other;
  if (Platform.isAndroid) return HostPlatform.android;
  if (Platform.isIOS) return HostPlatform.ios;
  if (Platform.isLinux) return HostPlatform.linux;
  if (Platform.isMacOS) return HostPlatform.macos;
  if (Platform.isWindows) return HostPlatform.windows;
  return HostPlatform.other;
}

/// How [host] expects a save dialog to be driven.
SaveStyle saveStyleFor(HostPlatform host) =>
    host == HostPlatform.android || host == HostPlatform.ios
        ? SaveStyle.pickerWrites
        : SaveStyle.callerWrites;

/// Whether a file of [bytes] can be handed to the picker on [host]. The
/// mobile contract requires the whole file in memory, so a very large archive
/// has to reach the user another way (it stays in the app's own backup folder
/// and the UI says so) rather than being loaded and killing the process.
bool canSaveSizeOn(HostPlatform host, int bytes) =>
    saveStyleFor(host) == SaveStyle.callerWrites ||
    bytes <= FileExport.pickerMemoryLimitBytes;

/// The save dialog, injectable so tests can drive the real policy without a
/// platform channel.
typedef SavePicker = Future<String?> Function({
  required String dialogTitle,
  required String fileName,
  Uint8List? bytes,
});

Future<String?> _realPicker({
  required String dialogTitle,
  required String fileName,
  Uint8List? bytes,
}) =>
    FilePicker.platform.saveFile(
      dialogTitle: dialogTitle,
      fileName: fileName,
      bytes: bytes,
    );

/// Raised when the file is too large for the platform's save dialog. The file
/// itself is fine and still on disk — only the hand-off failed.
class SaveTooLargeException implements Exception {
  final int bytes;
  const SaveTooLargeException(this.bytes);
  @override
  String toString() =>
      'SaveTooLargeException: $bytes bytes is too large to pass through this '
      "platform's save dialog";
}

class FileExport {
  /// Above this, we refuse to load a file into memory for the mobile picker.
  /// 256 MiB is already generous for a phone; a vault bigger than that is a
  /// desktop restore or a "leave it in the app folder" case.
  static const int pickerMemoryLimitBytes = 256 * 1024 * 1024;

  static HostPlatform get host => _detect();
  static SaveStyle get style => saveStyleFor(host);

  /// Asks the user where to put [bytes] and makes sure they end up there.
  /// Returns the chosen path, or null if the user cancelled.
  static Future<String?> saveBytes({
    required String dialogTitle,
    required String fileName,
    required Uint8List bytes,
    HostPlatform? on,
    SavePicker? picker,
  }) async {
    final h = on ?? host;
    final pick = picker ?? _realPicker;
    if (!canSaveSizeOn(h, bytes.length)) {
      throw SaveTooLargeException(bytes.length);
    }
    final wantsBytes = saveStyleFor(h) == SaveStyle.pickerWrites;
    final path = await pick(
      dialogTitle: dialogTitle,
      fileName: fileName,
      bytes: wantsBytes ? bytes : null,
    );
    if (path == null) return null;
    if (!wantsBytes) await File(path).writeAsBytes(bytes, flush: true);
    return path;
  }

  /// Hands the user a file that is ALREADY on disk — the case a streamed
  /// export produces. On desktop the bytes are copied across without ever
  /// being held in memory; on mobile the platform's dialog leaves us no
  /// choice but to read them, which is what [pickerMemoryLimitBytes] guards.
  static Future<String?> saveExistingFile({
    required File source,
    required String dialogTitle,
    required String fileName,
    HostPlatform? on,
    SavePicker? picker,
  }) async {
    final h = on ?? host;
    final pick = picker ?? _realPicker;
    final length = await source.length();
    if (!canSaveSizeOn(h, length)) throw SaveTooLargeException(length);

    if (saveStyleFor(h) == SaveStyle.pickerWrites) {
      final path = await pick(
        dialogTitle: dialogTitle,
        fileName: fileName,
        bytes: await source.readAsBytes(),
      );
      return path;
    }
    final path =
        await pick(dialogTitle: dialogTitle, fileName: fileName, bytes: null);
    if (path == null) return null;
    if (File(path).absolute.path == source.absolute.path) return path;
    final sink = File(path).openWrite();
    try {
      await sink.addStream(source.openRead()); // streamed: no full copy in RAM
    } finally {
      await sink.close();
    }
    return path;
  }
}
