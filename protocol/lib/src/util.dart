import 'dart:async';
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

final Random _sysRandom = Random.secure();

/// Zone key for a deterministic randomness override.
///
/// Every random draw the protocol makes (ephemeral keys, ratchet keys, nonces,
/// file keys, ids) goes through [randomBytes]. Production code never sets this
/// key, so [randomBytes] is always the OS CSPRNG. The ONLY user is the
/// test-vector generator (`tool/gen_vectors.dart`), which runs inside
/// `runZoned(..., zoneValues: {randomOverrideKey: drbg})` so that the vectors
/// in `docs/vectors/` are reproducible — the same pattern NIST KATs use
/// (a seeded DRBG in place of the RNG). The override is scoped to that zone
/// and cannot leak into or be switched on from anywhere else.
const Symbol randomOverrideKey = #z_protocol_random_override;

Uint8List randomBytes(int n) {
  final override = Zone.current[randomOverrideKey];
  if (override != null) {
    return (override as Uint8List Function(int))(n);
  }
  final b = Uint8List(n);
  for (var i = 0; i < n; i++) {
    b[i] = _sysRandom.nextInt(256);
  }
  return b;
}

String b64(List<int> bytes) => base64Encode(bytes);

/// A two-byte big-endian length, for prefixing a variable-length field that
/// is not last in a signed or committed concatenation.
Uint8List u16be(int n) {
  if (n < 0 || n > 0xffff) throw ArgumentError('u16be out of range: $n');
  return Uint8List.fromList([(n >> 8) & 0xff, n & 0xff]);
}

// RFC 4648 base32 without padding, upper case — the alphabet short codes a
// person reads aloud or types are rendered in (a pairing code, a connect
// invite). Lifted verbatim out of `pairing.dart`, where it was private, when
// a second ceremony needed the same rendering; the frozen v1 pairing vectors
// are what proves the move changed nothing.
const String _b32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

String base32Encode(Uint8List data) {
  final sb = StringBuffer();
  var buffer = 0, bits = 0;
  for (final b in data) {
    buffer = (buffer << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      sb.write(_b32Alphabet[(buffer >> bits) & 0x1f]);
    }
  }
  if (bits > 0) sb.write(_b32Alphabet[(buffer << (5 - bits)) & 0x1f]);
  return sb.toString();
}

/// Decodes, skipping anything that is not an alphabet character — so a code
/// pasted back with its dashes, spaces or a stray newline still parses.
Uint8List base32Decode(String s) {
  var buffer = 0, bits = 0;
  final out = <int>[];
  for (final ch in s.toUpperCase().codeUnits) {
    final v = _b32Alphabet.indexOf(String.fromCharCode(ch));
    if (v < 0) continue;
    buffer = (buffer << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.add((buffer >> bits) & 0xff);
    }
  }
  return Uint8List.fromList(out);
}

/// Grouped in fives and joined by dashes: `ABCDE-FGHIJ-KLMNO-P`.
String base32Groups(Uint8List data) {
  final raw = base32Encode(data);
  final groups = <String>[];
  for (var i = 0; i < raw.length; i += 5) {
    groups.add(raw.substring(i, i + 5 > raw.length ? raw.length : i + 5));
  }
  return groups.join('-');
}
Uint8List unb64(String s) => Uint8List.fromList(base64Decode(s));

String b64url(List<int> bytes) => base64UrlEncode(bytes).replaceAll('=', '');

Uint8List unb64url(String s) {
  var t = s.replaceAll('-', '+').replaceAll('_', '/');
  while (t.length % 4 != 0) {
    t += '=';
  }
  return Uint8List.fromList(base64Decode(t));
}

Uint8List concatBytes(List<List<int>> parts) {
  final total = parts.fold<int>(0, (s, p) => s + p.length);
  final out = Uint8List(total);
  var off = 0;
  for (final p in parts) {
    out.setRange(off, off + p.length, p);
    off += p.length;
  }
  return out;
}

bool constantTimeEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

Future<Uint8List> sha256Bytes(List<int> data) async {
  final h = await Sha256().hash(data);
  return Uint8List.fromList(h.bytes);
}

/// ISO/IEC 7816-4 style padding to a multiple of [blockSize]:
/// append 0x80, then zeros. Blunts message-length analysis.
Uint8List pad(List<int> data, {int blockSize = 256}) {
  final padded = ((data.length + 1 + blockSize - 1) ~/ blockSize) * blockSize;
  final out = Uint8List(padded);
  out.setRange(0, data.length, data);
  out[data.length] = 0x80;
  return out;
}

Uint8List unpad(List<int> data) {
  var i = data.length - 1;
  while (i >= 0 && data[i] == 0x00) {
    i--;
  }
  if (i < 0 || data[i] != 0x80) {
    throw const FormatException('bad padding');
  }
  return Uint8List.fromList(data.sublist(0, i));
}

/// Compact deterministic JSON encoding (keys in given order) so that bytes
/// used as AEAD associated data are stable across platforms.
String canonicalJson(Map<String, Object?> orderedMap) => jsonEncode(orderedMap);
