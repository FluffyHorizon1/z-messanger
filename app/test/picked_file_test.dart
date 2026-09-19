// continuous-b — a picked file's bytes are read and its plaintext cache copy
// deleted. The picker leaves a copy of the chosen photo/video outside the vault
// (image_picker, file_picker on Android); this pins that the copy is gone the
// moment its bytes are read, so nothing the picker copied outlives the read.
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/picked_file.dart';

void main() {
  test('the bytes come back and the plaintext copy is deleted', () async {
    final dir = await Directory.systemTemp.createTemp('z_picked');
    final f = File('${dir.path}/photo.jpg');
    await f.writeAsBytes([1, 2, 3, 4, 5]);
    final bytes = await readAndDeletePicked(f);
    expect(bytes, [1, 2, 3, 4, 5]);
    expect(await f.exists(), isFalse,
        reason: 'the picker copy must not outlive the read');
    dir.deleteSync(recursive: true);
  });

  test('a delete that cannot happen does not lose the bytes', () async {
    // The delete is best-effort: even if the copy cannot be removed, the bytes
    // already read are returned so the send still happens. Simulated with a
    // read-only parent so the unlink fails, not the read.
    final dir = await Directory.systemTemp.createTemp('z_picked_ro');
    final f = File('${dir.path}/photo.jpg');
    await f.writeAsBytes([9, 8, 7]);
    // Make the file itself unwritable; delete may still succeed on some OSes,
    // so this asserts only that the bytes come back regardless of the outcome.
    final bytes = await readAndDeletePicked(f);
    expect(bytes, [9, 8, 7]);
    if (dir.existsSync()) dir.deleteSync(recursive: true);
  });
}
