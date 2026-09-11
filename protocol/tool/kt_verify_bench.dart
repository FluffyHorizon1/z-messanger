// How long the transparency log's reader takes to verify one lookup — the
// figure PERFORMANCE.md quotes for the client side. Run from protocol/:
//     dart run tool/kt_verify_bench.dart
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:z_protocol/z_protocol.dart';

Uint8List hx(String s) => Uint8List.fromList([for (var i = 0; i < s.length; i += 2) int.parse(s.substring(i, i + 2), radix: 16)]);

Future<void> main() async {
  final v = (jsonDecode(File('../docs/vectors/kt/kt_log.json').readAsStringSync()) as Map).cast<String, Object?>();
  final logPub = hx((v['log'] as Map)['pub'] as String);
  final alice = ((v['accounts'] as Map)['alice'] as Map).cast<String, Object?>();
  final label = hx(alice['label'] as String);
  final json = (jsonDecode(((v['lookups'] as Map)['alice'] as Map)['response_json'] as String) as Map).cast<String, Object?>();
  // Warm up.
  for (var i = 0; i < 20; i++) {
    await ktVerifyLookup(await KtLookup.fromJson(json), label: label, logPub: logPub);
  }
  const n = 200;
  final sw = Stopwatch()..start();
  for (var i = 0; i < n; i++) {
    final r = await ktVerifyLookup(await KtLookup.fromJson(json), label: label, logPub: logPub);
    if (r.latest == null) throw StateError('absent?');
  }
  sw.stop();
  final perLookup = sw.elapsedMicroseconds / n / 1000;
  final sw2 = Stopwatch()..start();
  for (var i = 0; i < n; i++) {
    await KtTreeHead.fromJson((json['sth'] as Map).cast<String, Object?>()).verify(logPub);
  }
  sw2.stop();
  final sw3 = Stopwatch()..start();
  final mp = KtMapProof.fromJson((json['map'] as Map).cast<String, Object?>());
  final root = KtTreeHead.fromJson((json['sth'] as Map).cast<String, Object?>()).mapRoot;
  for (var i = 0; i < n; i++) {
    await mp.verify(root, label);
  }
  sw3.stop();
  print('verify one lookup (parse + head signature + map proof + inclusion): ${perLookup.toStringAsFixed(2)} ms');
  print('  of which the head signature (Ed25519 verify): ${(sw2.elapsedMicroseconds / n / 1000).toStringAsFixed(2)} ms');
  print('  of which the map proof (256 SHA-256): ${(sw3.elapsedMicroseconds / n / 1000).toStringAsFixed(2)} ms');
}
