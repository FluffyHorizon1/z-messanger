// What Z's cryptography costs here, pure Dart, as PERFORMANCE.md quotes it.
// Run from protocol/:
//     dart run tool/crypto_bench.dart            # the VM (JIT)
//     dart compile exe tool/crypto_bench.dart -o /tmp/crypto_bench && /tmp/crypto_bench
//                                                # AOT, what a release build runs
// The app's Developer screen runs the same rows on a phone.
import 'package:z_protocol/bench.dart';

Future<void> main(List<String> args) async {
  final scale = args.isNotEmpty ? int.parse(args.first) : 1;
  final rows = await runCryptoBench(
      scale: scale, onRow: (r) => print('${r.group.padRight(22)} ${r.op.padRight(32)} ${r.perOp.padLeft(10)}  (${r.runs} runs)'));
  print('');
  print(benchTable(rows));
}
