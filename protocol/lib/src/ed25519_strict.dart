/// The one Ed25519 verification rule a handle's signatures are held to
/// (PROTOCOL.md §21.4), and the strong-key test a handle record's keys pass.
///
/// Why not `Ed25519().verify`: `package:cryptography`'s pure-Dart verifier
/// compares the two points of the verification equation by their x
/// coordinates alone (`Ed25519Point.equals` compares x twice), so it accepts
/// whenever R + [k]A is [S]B *or* −[S]B plus the point of order 2 — which a
/// key's owner can arrange at will, and under a small-order key anybody can.
/// The handle log runs on OpenSSL, which compares R's bytes, so the two
/// disagreed: an independent review (2026-10-09) found Dart accepting
/// signatures under small-order owner keys that Node refused, and Node
/// accepting a non-canonical identity key that Dart refused.
///
/// The rule here is OpenSSL's computation with every leniency either side
/// had refused first, written out so that both sides are this text and not
/// their libraries:
///
///   * A — the key — and R — the signature's first half — are each 32 bytes
///     whose y (the sign bit cleared) is below p and is not the y of one of
///     the eight points of order dividing 8 ([handleStrongEdKey]);
///   * S — the second half — is below L;
///   * A decodes (RFC 8032 §5.1.3), k = SHA-512(R ‖ A ‖ M) mod L, and the
///     bytes of [S]B − [k]A, encoded, are R's bytes.
///
/// Pure Dart on BigInt: a few milliseconds a verification, which is what a
/// record, a history or an acknowledgement costs a client — nothing here is
/// on a hot path.
library;

import 'dart:typed_data';

import 'package:cryptography/dart.dart' show DartSha512;

final BigInt _p = (BigInt.one << 255) - BigInt.from(19);
final BigInt _l = (BigInt.one << 252) +
    BigInt.parse('27742317777372353535851937790883648493');
final BigInt _d = (BigInt.from(-121665) *
        BigInt.from(121666).modPow(_p - BigInt.two, _p)) %
    _p;
final BigInt _d2 = (_d * BigInt.two) % _p;
final BigInt _sqrtM1 =
    BigInt.two.modPow((_p - BigInt.one) ~/ BigInt.from(4), _p);

Uint8List _hex(String s) => Uint8List.fromList([
      for (var i = 0; i < s.length; i += 2)
        int.parse(s.substring(i, i + 2), radix: 16)
    ]);

/// y (little-endian, sign bit cleared) of the eight Ed25519 points of order
/// dividing 8: the identity, the point of order 2, the two of order 4 and the
/// four of order 8 (two values of y).
final List<Uint8List> _smallOrderEdY = [
  '0100000000000000000000000000000000000000000000000000000000000000',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
  '0000000000000000000000000000000000000000000000000000000000000000',
  '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
  'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
].map(_hex).toList(growable: false);

/// u (little-endian) of the X25519 points of small order, on the curve and
/// its twist: X25519 with any clamped scalar gives all zeros for each.
final List<Uint8List> _smallOrderXU = [
  '0000000000000000000000000000000000000000000000000000000000000000',
  '0100000000000000000000000000000000000000000000000000000000000000',
  'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
  '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
  'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
].map(_hex).toList(growable: false);

bool _same(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

BigInt _le(List<int> b) {
  var n = BigInt.zero;
  for (var i = b.length - 1; i >= 0; i--) {
    n = (n << 8) | BigInt.from(b[i]);
  }
  return n;
}

Uint8List _toLe(BigInt n) {
  final out = Uint8List(32);
  final mask = BigInt.from(0xff);
  for (var i = 0; i < 32; i++) {
    out[i] = (n & mask).toInt();
    n = n >> 8;
  }
  return out;
}

/// Whether the 255-bit little-endian [b] (its top bit already clear) is
/// below p = 2^255 − 19.
bool _belowP(List<int> b) {
  if (b[31] != 0x7f) return true;
  for (var i = 30; i >= 1; i--) {
    if (b[i] != 0xff) return true;
  }
  return b[0] < 0xed;
}

/// A strong Ed25519 key (§21.4): 32 bytes whose y is below p and is not the
/// y of a point of small order. That rules out every second spelling of a
/// key (an encoding at or above p, an x of zero with the sign bit set — only
/// possible at y = ±1) and every key any signature verifies under. Whether
/// the bytes are a point at all is the signature's to find out.
bool handleStrongEdKey(List<int> k) {
  if (k.length != 32) return false;
  final y = Uint8List.fromList(k);
  y[31] &= 0x7f;
  if (!_belowP(y)) return false;
  for (final s in _smallOrderEdY) {
    if (_same(s, y)) return false;
  }
  return true;
}

/// A strong X25519 key (§21.4): 32 bytes, the top bit clear, u below p, and
/// not a point of small order — a key a request sealed to would share an
/// all-zero secret with. Every key X25519 makes is one.
bool handleStrongXKey(List<int> k) {
  if (k.length != 32 || k[31] & 0x80 != 0) return false;
  if (!_belowP(k)) return false;
  for (final s in _smallOrderXU) {
    if (_same(s, k)) return false;
  }
  return true;
}

/// A point in extended coordinates: x = X/Z, y = Y/Z, xy = T/Z.
class _Pt {
  final BigInt x, y, z, t;
  const _Pt(this.x, this.y, this.z, this.t);
}

final _Pt _identity = _Pt(BigInt.zero, BigInt.one, BigInt.one, BigInt.zero);

BigInt _m(BigInt a) => a % _p; // Dart's BigInt % is never negative here

_Pt _add(_Pt p, _Pt q) {
  final a = _m((p.y - p.x) * (q.y - q.x));
  final b = _m((p.y + p.x) * (q.y + q.x));
  final c = _m(_m(p.t * _d2) * q.t);
  final d = _m(_m(p.z * BigInt.two) * q.z);
  final e = b - a, f = d - c, g = d + c, h = b + a;
  return _Pt(_m(e * f), _m(g * h), _m(f * g), _m(e * h));
}

_Pt _double(_Pt p) {
  final a = _m(p.x * p.x);
  final b = _m(p.y * p.y);
  final c = _m(BigInt.two * _m(p.z * p.z));
  final h = a + b;
  final xy = p.x + p.y;
  final e = h - _m(xy * xy);
  final g = a - b;
  final f = c + g;
  return _Pt(_m(e * f), _m(g * h), _m(f * g), _m(e * h));
}

_Pt _neg(_Pt p) => _Pt(_m(-p.x), p.y, p.z, _m(-p.t));

/// RFC 8032 §5.1.3, or null: y at or above p, no square root, or x = 0
/// with the sign bit set.
_Pt? _decode(List<int> bytes) {
  final b = Uint8List.fromList(bytes);
  final sign = b[31] >> 7;
  b[31] &= 0x7f;
  final y = _le(b);
  if (y >= _p) return null;
  final yy = _m(y * y);
  final u = _m(yy - BigInt.one);
  final v = _m(_d * yy + BigInt.one);
  final v3 = _m(_m(v * v) * v);
  final v7 = _m(_m(v3 * v3) * v);
  var x = _m(_m(u * v3) *
      _m(u * v7).modPow((_p - BigInt.from(5)) ~/ BigInt.from(8), _p));
  final vxx = _m(v * _m(x * x));
  if (vxx != u) {
    if (vxx != _m(-u)) return null;
    x = _m(x * _sqrtM1);
  }
  if (x == BigInt.zero && sign == 1) return null;
  if (x.isOdd != (sign == 1)) x = _m(-x);
  return _Pt(x, y, BigInt.one, _m(x * y));
}

Uint8List _encode(_Pt p) {
  final zi = p.z.modPow(_p - BigInt.two, _p);
  final x = _m(p.x * zi), y = _m(p.y * zi);
  final out = _toLe(y);
  if (x.isOdd) out[31] |= 0x80;
  return out;
}

final _Pt _base = () {
  final y = _m(BigInt.from(4) * BigInt.from(5).modPow(_p - BigInt.two, _p));
  final b = _toLe(y);
  return _decode(b)!;
}();

/// [s]B + [k]P, one pass over the bits of both scalars.
_Pt _doubleScalarMul(BigInt s, BigInt k, _Pt p) {
  final both = _add(_base, p);
  var r = _identity;
  final n = s.bitLength > k.bitLength ? s.bitLength : k.bitLength;
  for (var i = n - 1; i >= 0; i--) {
    r = _double(r);
    final sb = (s >> i).isOdd, kb = (k >> i).isOdd;
    if (sb && kb) {
      r = _add(r, both);
    } else if (sb) {
      r = _add(r, _base);
    } else if (kb) {
      r = _add(r, p);
    }
  }
  return r;
}

/// Whether [sig] is [pub]'s signature over [message] under the one rule
/// above. Never throws: anything that is not a valid signature is false.
bool ed25519VerifyStrict(
    List<int> pub, List<int> message, List<int> sig) {
  if (pub.length != 32 || sig.length != 64) return false;
  if (!handleStrongEdKey(pub)) return false;
  final rBytes = sig.sublist(0, 32);
  if (!handleStrongEdKey(rBytes)) return false;
  final s = _le(sig.sublist(32));
  if (s >= _l) return false;
  final a = _decode(pub);
  if (a == null) return false;
  final digest = const DartSha512()
      .hashSync([...rBytes, ...pub, ...message]).bytes;
  final k = _le(digest) % _l;
  final r = _doubleScalarMul(s, k, _neg(a));
  return _same(_encode(r), rBytes);
}
