// The cryptography benchmark (`package:z_protocol/bench.dart`) is the one
// measurement PERFORMANCE.md's "Cryptography on the device" table and the
// app's Developer screen both run, so it has to keep producing the rows the
// table names, at every scale, with the table rendering they are quoted in.
//
// Exit criteria:
//   1. a run produces every primitive Z uses — hashing, HMAC, HKDF, the
//      AEAD, X25519, Ed25519, ML-KEM-768, ML-DSA-65, the sealed envelope,
//      Argon2id — each with a positive median and the run count it used,
//      the Argon2id line exactly once, at the smallest scale a phone would
//      pick;
//   2. the Markdown table lists one line per row under the heading given,
//      and the per-op text carries a unit at every magnitude.
import 'package:test/test.dart';
import 'package:z_protocol/bench.dart';

void main() {
  test('1. every primitive is measured, at a phone scale', () async {
    final seen = <BenchRow>[];
    final rows = await runCryptoBench(scale: 8, onRow: seen.add);
    expect(seen, rows, reason: 'onRow reports each row as it lands');
    final groups = rows.map((r) => r.group).toSet();
    for (final g in [
      'SHA-256',
      'HMAC-SHA256',
      'HKDF-SHA256',
      'XChaCha20-Poly1305',
      'X25519',
      'Ed25519',
      'ML-KEM-768',
      'ML-DSA-65 + Ed25519',
      'sealed envelope',
      'Argon2id',
    ]) {
      expect(groups, contains(g));
    }
    for (final r in rows) {
      expect(r.perOpMicros, greaterThan(0), reason: r.toString());
      expect(r.runs, greaterThanOrEqualTo(1), reason: r.toString());
    }
    final argon = rows.where((r) => r.group == 'Argon2id').toList();
    expect(argon, hasLength(1));
    expect(argon.single.runs, 1, reason: 'the slow one runs once');
    // A scale divides the run counts but never below three, so a median is
    // still a median.
    expect(rows.where((r) => r.group != 'Argon2id').every((r) => r.runs >= 3),
        isTrue);
  }, timeout: const Timeout(Duration(minutes: 3)));

  test('2. the table names every row under the heading it is given', () {
    final rows = [
      const BenchRow('SHA-256', '1 KB', 14, 50),
      const BenchRow('Ed25519', 'verify 200 B', 2480, 20),
      const BenchRow('Argon2id', '19 MiB, t=2 (passphrase unlock)', 128000, 1),
    ];
    final t = benchTable(rows, heading: 'a phone');
    final lines = t.trim().split('\n');
    expect(lines[0], '| primitive | operation | a phone |');
    expect(lines, hasLength(2 + rows.length));
    expect(lines[2], '| SHA-256 | 1 KB | 14 µs |');
    expect(lines[3], '| Ed25519 | verify 200 B | 2.48 ms |');
    expect(lines[4], '| Argon2id | 19 MiB, t=2 (passphrase unlock) | 128 ms |');
  });
}
