/// What Z's cryptography costs on the machine it runs on — the same
/// measurement whether it is taken by `tool/crypto_bench.dart` on a
/// development machine or by the app's Developer screen on a phone, so the
/// two are comparable line for line. Every primitive Z uses is timed the way
/// Z uses it: through the `cryptography` package (pure Dart in this build —
/// no platform implementation is wired in), `pqcrypto` for the post‑quantum
/// pair, and the protocol's own composites (a sealed envelope, a hybrid
/// signature) on top. Not part of the protocol; not imported by it.
///
/// Numbers are medians of repeated runs after a warm‑up, so a JIT's first
/// iterations and a phone's clock ramp do not set them. The Argon2id line is
/// one run (it is meant to be slow) and is the one a user feels directly:
/// it is the passphrase unlock.
library;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'z_protocol.dart';

/// One measured line: what was timed and the median cost of doing it once.
class BenchRow {
  final String group;
  final String op;
  final double perOpMicros;
  final int runs;
  const BenchRow(this.group, this.op, this.perOpMicros, this.runs);

  /// Milliseconds with a sensible number of digits for the magnitude.
  String get perOp {
    final ms = perOpMicros / 1000;
    if (ms >= 100) return '${ms.toStringAsFixed(0)} ms';
    if (ms >= 1) return '${ms.toStringAsFixed(2)} ms';
    return '${perOpMicros.toStringAsFixed(0)} µs';
  }

  @override
  String toString() => '$group · $op: $perOp';
}

/// Times [body] [runs] times after [warm] warm‑up runs and returns the median
/// cost of one run in microseconds.
Future<double> _median(Future<void> Function() body,
    {int runs = 20, int warm = 3}) async {
  for (var i = 0; i < warm; i++) {
    await body();
  }
  final samples = <int>[];
  final sw = Stopwatch();
  for (var i = 0; i < runs; i++) {
    sw
      ..reset()
      ..start();
    await body();
    sw.stop();
    samples.add(sw.elapsedMicroseconds);
  }
  samples.sort();
  return samples[samples.length ~/ 2].toDouble();
}

/// Runs the whole bench. [scale] divides the run counts (a phone in a hurry
/// can pass 4); the Argon2id line always runs once. [onRow] is told each row
/// as it lands, so a screen can show progress.
Future<List<BenchRow>> runCryptoBench(
    {int scale = 1, void Function(BenchRow row)? onRow}) async {
  final rows = <BenchRow>[];
  Future<void> add(String group, String op, Future<void> Function() body,
      {int runs = 20, int warm = 3}) async {
    final r = runs == 1 ? 1 : (runs ~/ scale).clamp(3, runs);
    final w = warm == 0 ? 0 : (warm ~/ scale).clamp(1, warm);
    final row = BenchRow(group, op, await _median(body, runs: r, warm: w), r);
    rows.add(row);
    onRow?.call(row);
  }

  final msg = randomBytes(200); // a short text's inner size, roughly
  final kb1 = randomBytes(1024);
  final kb64 = randomBytes(64 * 1024); // an attachment chunk is 140 KiB: ×2.2

  // --- hashing and KDFs ------------------------------------------------
  final sha = Sha256();
  await add('SHA-256', '1 KB', () => sha.hash(kb1), runs: 50, warm: 5);
  await add('SHA-256', '64 KB', () => sha.hash(kb64), runs: 20);
  final hmac = Hmac.sha256();
  final macKey = SecretKey(randomBytes(32));
  await add('HMAC-SHA256', '1 KB',
      () => hmac.calculateMac(kb1, secretKey: macKey),
      runs: 50, warm: 5);
  final hkdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
  await add(
      'HKDF-SHA256',
      '32 bytes out',
      () => hkdf.deriveKey(
          secretKey: macKey, nonce: kb1.sublist(0, 32), info: msg),
      runs: 50,
      warm: 5);

  // --- the AEAD -----------------------------------------------------------
  final aead = Xchacha20.poly1305Aead();
  final aeadKey = SecretKey(randomBytes(32));
  final nonce = randomBytes(24);
  late SecretBox box1;
  late SecretBox box64;
  await add('XChaCha20-Poly1305', 'seal 1 KB', () async {
    box1 = await aead.encrypt(kb1, secretKey: aeadKey, nonce: nonce);
  }, runs: 50, warm: 5);
  await add('XChaCha20-Poly1305', 'open 1 KB',
      () => aead.decrypt(box1, secretKey: aeadKey),
      runs: 50, warm: 5);
  await add('XChaCha20-Poly1305', 'seal 64 KB', () async {
    box64 = await aead.encrypt(kb64, secretKey: aeadKey, nonce: nonce);
  }, runs: 20);
  await add('XChaCha20-Poly1305', 'open 64 KB',
      () => aead.decrypt(box64, secretKey: aeadKey),
      runs: 20);

  // --- the classical asymmetric pair ----------------------------------
  final x = X25519();
  final xa = await x.newKeyPair();
  final xbPub = await (await x.newKeyPair()).extractPublicKey();
  await add('X25519', 'keygen', () => x.newKeyPair());
  await add('X25519', 'shared secret',
      () => x.sharedSecretKey(keyPair: xa, remotePublicKey: xbPub));
  final ed = Ed25519();
  final edKp = await ed.newKeyPair();
  final edPub = await edKp.extractPublicKey();
  late Signature sig;
  await add('Ed25519', 'keygen', () => ed.newKeyPair());
  await add('Ed25519', 'sign 200 B', () async {
    sig = await ed.sign(msg, keyPair: edKp);
  });
  await add('Ed25519', 'verify 200 B', () => ed.verify(msg, signature: sig));
  // The relay's own check of the head signature, as one figure: a device
  // list, a transparency head and a contact code each cost one of these.
  final verifyPub = SimplePublicKey(edPub.bytes, type: KeyPairType.ed25519);
  await add('Ed25519', 'verify (key from bytes)', () async {
    await ed.verify(msg,
        signature: Signature(sig.bytes, publicKey: verifyPub));
  });

  // --- the post-quantum pair (pure Dart in every build) -----------------
  final (pqSeed, pqEk) = pqGenerate();
  late Uint8List pqCt;
  await add('ML-KEM-768', 'keygen', () async => pqGenerate(), runs: 10);
  await add('ML-KEM-768', 'encapsulate', () async {
    pqCt = pqEncapsulate(pqEk).$1;
  }, runs: 10);
  await add('ML-KEM-768', 'decapsulate (from seed)',
      () async => pqDecapsulate(pqSeed, pqCt),
      runs: 10);
  final hk = await HybridKeyPair.generate();
  late HybridSignature hs;
  await add('ML-DSA-65 + Ed25519', 'keygen', () => HybridKeyPair.generate(),
      runs: 5, warm: 1);
  await add('ML-DSA-65 + Ed25519', 'sign 200 B', () async {
    hs = await hk.sign(msg);
  }, runs: 10, warm: 2);
  await add('ML-DSA-65 + Ed25519', 'verify 200 B',
      () => hybridVerify(hk.publicKey, msg, hs),
      runs: 10, warm: 2);

  // --- the protocol's composites, as the app pays them --------------------
  final id = await ZIdentity.generate();
  final rid = await id.routingId();
  final toX = Uint8List.fromList(id.xPub);
  final payload = String.fromCharCodes(List.filled(1200, 0x41));
  late String sealed;
  await add('sealed envelope', 'seal (1 024 bucket)', () async {
    sealed = await SealedEnvelope.seal(
        toXPub: toX, fromRid: rid, payload: payload);
  });
  await add('sealed envelope', 'open (1 024 bucket)', () async {
    final r = await SealedEnvelope.open(
        myXSeed: id.xSeed, myXPub: id.xPub, blob: sealed);
    if (r == null) throw StateError('open failed');
  });

  // --- the passphrase KDF: once, and the one a user waits for -------------
  final argon = Argon2id(
      memory: 19 * 1024, parallelism: 1, iterations: 2, hashLength: 32);
  await add(
      'Argon2id',
      '19 MiB, t=2 (passphrase unlock)',
      () => argon.deriveKey(
          secretKey: SecretKey(randomBytes(16)), nonce: randomBytes(16)),
      runs: 1,
      warm: 0);
  return rows;
}

/// The rows as a Markdown table, the form PERFORMANCE.md quotes.
String benchTable(List<BenchRow> rows, {String heading = 'this machine'}) {
  final b = StringBuffer()
    ..writeln('| primitive | operation | $heading |')
    ..writeln('|---|---|---:|');
  for (final r in rows) {
    b.writeln('| ${r.group} | ${r.op} | ${r.perOp} |');
  }
  return b.toString();
}
