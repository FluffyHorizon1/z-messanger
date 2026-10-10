// The owner rule, Dart against the handle log's own code (PROTOCOL.md §21.4).
//
// §21.4 says the log, a mirror and a client apply one rule in one order and
// name the same refusal. An independent review (2026-10-09) ran 92 edge-case
// histories through both and found that false: 7 accepted by one side and
// refused by the other — small-order owner keys "anyone can sign" for,
// accepted by Dart and refused by Node or the reverse; versions at and past
// 2^53 that the log's replay and its mirrors took and its wire refused — and
// a taken claim with a bad signature named `taken` here and `bad_signature`
// there. This file runs the same kind of corpus, grown to every case the
// fixes are about, through the log's real code and through this library.
//
// Criteria, each a test below:
//   1. every history in the corpus `kt/test/handle_rule_cases.js` builds —
//      encodings, weak keys, signatures only one side's leniency would take,
//      versions skipped, stale, at the ceiling and past it, a recover after a
//      theft — gets from `checkHandleHistory` exactly the verdict the log
//      gives it on the wire, on replay and in a mirror: the same entry
//      refused, for the same reason (§21.4's names), or none;
//   2. the corpus is the whole of it: it holds every case the fixes name,
//      each with the verdict §21.4 now gives, so a change that made both
//      sides agree on a wrong answer is caught too.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

Uint8List _hex(String s) => Uint8List.fromList([
      for (var i = 0; i < s.length; i += 2)
        int.parse(s.substring(i, i + 2), radix: 16)
    ]);

/// The corpus, made by the log's code: `node test/handle_rule_cases.js`.
Future<List<Map<String, Object?>>> _corpus() async {
  final dir = await Directory.systemTemp.createTemp('z-handle-rule-');
  try {
    final out = '${dir.path}${Platform.pathSeparator}corpus.json';
    final r = await Process.run('node', ['test/handle_rule_cases.js', out],
        workingDirectory:
            '${Directory.current.parent.path}${Platform.pathSeparator}kt');
    if (r.exitCode != 0) {
      fail('the corpus generator failed: ${r.stdout}${r.stderr}');
    }
    final j = jsonDecode(await File(out).readAsString()) as Map;
    return [for (final c in j['cases'] as List) (c as Map).cast<String, Object?>()];
  } finally {
    await dir.delete(recursive: true);
  }
}

String _verdict(int? at, String? reason) =>
    at == null ? 'accept' : '$at $reason';

void main() {
  late List<Map<String, Object?>> cases;
  final dart = <String, String>{};

  setUpAll(() async {
    cases = await _corpus();
    for (final c in cases) {
      final entries = [
        for (final e in (c['entries'] as List).cast<Map>())
          HandleEntry(
            label: _hex(e['label'] as String),
            version: int.parse(e['v'] as String),
            value: Uint8List.fromList(base64Decode(e['value'] as String)),
            sig: Uint8List.fromList(base64Decode(e['sig'] as String)),
          )
      ];
      final v = await checkHandleHistory(entries);
      dart[c['name'] as String] = _verdict(v.refusedAt, v.reason?.name);
    }
  });

  test('1. every history: the same verdict as the log on the wire, on replay and in a mirror',
      () {
    final differ = <String>[];
    final histories = <String>{};
    var refusals = 0;
    for (final c in cases) {
      final name = c['name'] as String;
      final mine = dart[name]!;
      for (final path in ['wire', 'replay', 'mirror']) {
        final n = (c[path] as Map).cast<String, Object?>();
        final theirs = _verdict(n['refusedAt'] as int?, n['reason'] as String?);
        if (theirs != mine) {
          differ.add('$name: dart $mine | node $path $theirs');
          histories.add(name);
        }
      }
      if (mine != 'accept') refusals++;
    }
    // ignore: avoid_print
    print('handle rule: ${cases.length} histories, ${cases.length - refusals} '
        'accepted and $refusals refused; Dart and the log agree on '
        '${cases.length - histories.length} and differ on ${histories.length} '
        '(${differ.length} of ${cases.length * 3} comparisons)');
    expect(differ, isEmpty);
    expect(cases.length, greaterThanOrEqualTo(120));
  });

  test('2. the corpus holds every case the fixes name, each with the verdict §21.4 gives', () {
    const want = {
      // The version: the next one, from 1.
      'claim, update v3 (a version skipped)': '1 staleVersion',
      'claim at v2 (a claim is version 1)': '0 staleVersion',
      'claim at v = 2^53-1': '0 staleVersion',
      'claim, update at v = 2^53-1 (the theft at the ceiling)': '1 staleVersion',
      'claim, update at v = 2^53': '1 malformed',
      'claim, update at v = 2^60': '1 malformed',
      'claim, theft v2, recover v3': 'accept',
      'claim, theft v2, theft v3, recover v4': 'accept',
      'claim, theft v2, recover v2 (beaten to it)': '2 staleVersion',
      'claim, recover v3 (a version skipped)': '1 staleVersion',
      // The order: history after signatures, the version last.
      'claim, taken claim with a bad signature': '1 badSignature',
      'claim, update v9 naming the stranger, signed by the stranger': '1 ownerChanged',
      'claim, recover v2, the same recover again (replay)': '2 wrongRecoveryKey',
      // Weak keys and the one signature rule.
      'claim: owner identity, sig (R=identity, S=0)': '0 malformed',
      'claim+update: owner order2, both sigs (R=identity, S=0)': '0 malformed',
      'claim: owner identityNonCanonical, sig (R=identity, S=0)': '0 malformed',
      'claim: intro order8, signed by its owner': '0 malformed',
      'claim: xintro order8, signed by its owner': '0 malformed',
      'claim: xintro with its top bit set, signed by its owner': '0 malformed',
      'claim committing to the identity as recovery key, then anyone recovers with it': '1 malformed',
      'claim: sig with R = the identity, made by the owner (S = k·a)': '0 badSignature',
      'claim: sig with R = rB + T2, made by the owner so that x(R + kA) = x(SB)': '0 badSignature',
      'claim with S+L (malleated) signature': '0 badSignature',
      'claim: owner aB + T2, signed with R = rB, k even': 'accept',
      'claim: owner aB + T2, signed with R = rB, k odd': '0 badSignature',
      'claim: owner not a point (no x for its y)': '0 badSignature',
    };
    for (final e in want.entries) {
      expect(dart[e.key], e.value, reason: e.key);
    }
  });
}
