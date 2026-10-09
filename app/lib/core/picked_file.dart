import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:image_picker/image_picker.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

/// Read a picked file's bytes, then delete the file (continuous-b).
///
/// A picker (image_picker, and file_picker on Android) does not hand over the
/// file the user chose — it copies it into a cache directory outside the vault
/// and returns that. A copy left there is plaintext that outlives the sweeper,
/// the disappearing-message timer and "reset identity" alike, so it is deleted
/// the moment its bytes are in hand. The delete is best-effort: a failure to
/// remove the copy must not lose the bytes already read (the caller still seals
/// and sends them), and the next pick's own delete tries again.
///
/// 42.2: the delete runs whether or not the read succeeds — a copy that could
/// not be read is still a copy — and a gallery pick's own directory, which
/// image_picker makes for every pick ([sweepPickerCopies]), goes with it.
Future<Uint8List> readAndDeletePicked(File file) async {
  try {
    return await file.readAsBytes();
  } finally {
    try {
      await file.delete();
    } catch (_) {}
    final dir = file.parent;
    if (_galleryDir.hasMatch(p.basename(dir.path))) {
      try {
        await dir.delete(); // not recursive: only once it is empty
      } catch (_) {}
    }
  }
}

// What the two pickers leave directly under the app's cache directory on
// Android (`Context.getCacheDir()`, which is what path_provider's
// getTemporaryDirectory returns there), by the shape each one writes. Read
// from the plugins' own sources at the versions this app resolves —
// image_picker_android 0.8.13+23, file_picker 8.3.7 — and pinned by
// `device_hardening_test.dart`:
//
//  * a photo or video picked from the gallery is copied to
//    `<cache>/<random UUID>/<its name>` (`FileUtils.getPathFromUri`);
//  * the camera writes to `File.createTempFile(<random UUID>, ".jpg")` —
//    `<cache>/<UUID><number>.jpg`, ".mp4" for video, the number negative on
//    old Androids — and creates that file BEFORE the camera opens, so a
//    capture the person cancels leaves it too;
//  * a resized image is written as `<cache>/scaled_<name>`
//    (`ImageResizer`; this app never asks for one, but a build that did
//    would leave it in the same place);
//  * the file picker copies to `<cache>/file_picker/<ms>/<name>`
//    (`FileUtils.openFileStream`; its `clearTemporaryFiles` deletes that
//    directory, and is called after every pick).
//
// Java's UUID prints in lower case, so nothing upper-case is taken for one.
const _uuid =
    '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
final _galleryDir = RegExp('^$_uuid\$');
final _cameraFile = RegExp('^$_uuid-?[0-9]+\\.(jpg|mp4)\$');

/// Whether [name], an entry directly under the cache directory, is one of
/// the pickers' copies ([directory]: whether the entry is a directory).
bool isPickerCopy(String name, {required bool directory}) => directory
    ? name == 'file_picker' || _galleryDir.hasMatch(name)
    : _cameraFile.hasMatch(name) || name.startsWith('scaled_');

/// Where the pickers' copies are, or null where this app must not sweep.
///
/// Android only. There the temporary directory is the app's own cache,
/// which nothing but this app writes and which the system may empty at any
/// time anyway. On Linux and Windows it is the machine's shared temporary
/// directory (`/tmp`), where a UUID-named entry may be anyone's — and the
/// pickers make no copies there: the file picker hands over the file
/// itself, and the camera/gallery picker is offered on Android only.
Future<Directory?> pickerCacheDir() async {
  if (kIsWeb || defaultTargetPlatform != TargetPlatform.android) return null;
  try {
    return await getTemporaryDirectory();
  } catch (_) {
    return null;
  }
}

/// Deletes every picker copy directly under [cache] — a directory a picker
/// made, with everything in it — and nothing else. Returns the entries it
/// could not delete; empty when all went.
///
/// 42.2: a copy the delete after each pick never reached — the process
/// killed between the pick and the read (Android kills an app in the
/// background while the camera is in front of it), a capture cancelled,
/// a read that failed — used to stay for the life of the install, through
/// "Wipe everything" too, because nothing else ever looked.
Future<List<String>> sweepPickerCopies(Directory cache) async {
  final left = <String>[];
  if (!await cache.exists()) return left;
  await for (final e in cache.list(followLinks: false)) {
    final name = p.basename(e.path);
    if (!isPickerCopy(name, directory: e is Directory)) continue;
    try {
      await e.delete(recursive: true);
    } catch (_) {
      if (await e.exists()) left.add(e.path);
    }
  }
  return left;
}

/// At start, before anything can be picked: what a killed process left.
///
/// The camera/gallery picker keeps, outside the app's files, a note of a
/// pick its process died in — the copy's path, which for a gallery pick is
/// the file's own name — for `retrieveLostData` to hand back to the next
/// start. Nothing asked for it, so the note stayed with the copy. Asking
/// for it makes the plugin forget it; the copy itself goes with the rest.
/// Android only ([pickerCacheDir]); never throws.
Future<void> sweepPickersAtStart() async {
  try {
    final cache = await pickerCacheDir();
    if (cache == null) return;
    try {
      await ImagePicker().retrieveLostData();
    } catch (_) {
      // No activity yet, or nothing kept: the sweep below is what matters.
    }
    await sweepPickerCopies(cache);
  } catch (_) {
    // A sweep that cannot run now runs at the next start.
  }
}
