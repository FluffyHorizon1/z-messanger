// What a handle costs to compute here (PROTOCOL.md §21, ADR 0015): one label
// (Argon2id, 19 MiB, two passes — the price of a lookup, and of every guess
// against a mirror), and proof-of-work stamps at 16, 20 and 24 bits (the
// price of one introduction request). Run from protocol/:
//     dart run tool/handles_bench.dart               # the VM (JIT)
//     dart compile exe tool/handles_bench.dart -o /tmp/handles_bench && /tmp/handles_bench
//                                                    # AOT, what a release build runs
// A stamp's cost is geometric: the mean is 2^bits hashes, and one stamp can
// take several times that, so the rate is measured and the spread printed.
import 'dart:convert';
import 'dart:typed_data';

import 'package:z_protocol/z_protocol.dart';

Future<void> main(List<String> args) async {
  // Label: median of several, after one to warm up.
  final h = Handle.parse('alice.42');
  await handleLabel(h);
  final labelMs = <int>[];
  for (var i = 0; i < 7; i++) {
    final sw = Stopwatch()..start();
    await handleLabel(h);
    labelMs.add(sw.elapsedMilliseconds);
  }
  labelMs.sort();
  print('label (Argon2id 19 MiB, t=2, p=1): median ${labelMs[labelMs.length ~/ 2]} ms, '
      'min ${labelMs.first} ms, max ${labelMs.last} ms (7 runs)');

  final rid = await introRoutingId(await handleKeyPublic(Uint8List(32)));
  final env = utf8.encode('zs1.${'A' * 1400}');
  for (final (bits, runs) in [(16, 64), (20, 16), (24, 4)]) {
    var hashes = 0, us = 0;
    final each = <double>[];
    for (var i = 0; i < runs; i++) {
      // The search counts up from the start, so the low eight bytes of the
      // answer are how many tries it took (minus one).
      final start = Uint8List(16)..setRange(0, 8, randomBytes(8));
      final sw = Stopwatch()..start();
      final nonce = createIntroPowStamp(
          introRid: rid, day: 20734, envelope: env, bits: bits, startNonce: start);
      sw.stop();
      hashes += ByteData.sublistView(nonce, 8).getUint64(0) + 1;
      us += sw.elapsedMicroseconds;
      each.add(sw.elapsedMicroseconds / 1000);
    }
    each.sort();
    final rate = hashes / (us / 1e6);
    print('stamp $bits bits: mean ${(us / runs / 1000).toStringAsFixed(1)} ms, '
        'median ${each[each.length ~/ 2].toStringAsFixed(1)} ms, '
        'max ${each.last.toStringAsFixed(1)} ms over $runs stamps; '
        '${(rate / 1e6).toStringAsFixed(2)} M hashes/s, so 2^$bits expected = '
        '${((1 << bits) / rate * 1000).toStringAsFixed(0)} ms');
  }
}
