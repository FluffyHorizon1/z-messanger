import 'dart:io';
import 'dart:typed_data';

/// Read a picked file's bytes, then delete the file (continuous-b).
///
/// A picker (image_picker, and file_picker on Android) does not hand over the
/// file the user chose — it copies it into a cache directory outside the vault
/// and returns that. A copy left there is plaintext that outlives the sweeper,
/// the disappearing-message timer and "reset identity" alike, so it is deleted
/// the moment its bytes are in hand. The delete is best-effort: a failure to
/// remove the copy must not lose the bytes already read (the caller still seals
/// and sends them), and the next pick's own delete tries again.
Future<Uint8List> readAndDeletePicked(File file) async {
  final bytes = await file.readAsBytes();
  try {
    await file.delete();
  } catch (_) {}
  return bytes;
}
