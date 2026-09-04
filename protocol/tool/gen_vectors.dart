// Writes the protocol test vectors to docs/vectors/v1/ and v2/ (repo root relative).
//
//   cd protocol && dart run tool/gen_vectors.dart [output-dir]
//
// The output is deterministic: rerunning must produce byte-identical files.
// `test/vectors_test.dart` enforces that, so a protocol change that alters any
// vector fails CI until the vectors — and PROTOCOL.md — are deliberately
// updated (and the version bumped).

import 'dart:io';

import 'vectors.dart';

Future<void> main(List<String> args) async {
  final root = args.isNotEmpty
      ? args[0]
      : '${File.fromUri(Platform.script).parent.parent.parent.path}/docs/vectors';
  final all = await generateAll();
  for (final ver in all.entries) {
    final outDir = Directory('$root/${ver.key}');
    await outDir.create(recursive: true);
    for (final e in ver.value.entries) {
      final f = File('${outDir.path}/${e.key}.json');
      await f.writeAsString(encodeVectorFile(e.value));
      stdout.writeln('wrote ${f.path} (${await f.length()} bytes)');
    }
  }
}
