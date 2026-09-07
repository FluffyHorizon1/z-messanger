import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'util.dart';

/// The recovery code that unlocks a backup archive (§9, `docs/BACKUP.md`).
///
/// 120 random bits written as 25 characters in five groups:
///
///     ZBK-4T7QK-9WXME-2H1RB-0YFVC-8NZ3D
///
/// **Why characters and not words.** A word list is friendlier to copy by
/// hand, but it means shipping and pinning a 2048-word list per language and
/// getting its provenance right; Crockford's base32 alphabet solves the same
/// transcription problem in the encoding instead. It omits I, L, O and U — so
/// nothing collides with 1, 0, or with itself — is case-insensitive, and on
/// input maps I and L to 1 and O to 0, which is exactly how people mis-copy
/// these characters. The last character is a checksum, so a mistyped code is
/// caught immediately rather than after a slow key derivation and a failed
/// decryption that cannot say which went wrong.
///
/// 120 bits is far beyond brute force on its own; the archive still runs the
/// code through Argon2id, which costs nothing here and covers a user who
/// brings a code from somewhere else.
class RecoveryCode {
  /// Crockford base32: 0-9 then A-Z without I, L, O, U.
  static const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

  static const entropyBytes = 15; // 120 bits -> 24 chars
  static const dataChars = 24;
  static const totalChars = 25; // + 1 checksum char
  static const groupSize = 5;

  final Uint8List entropy;
  const RecoveryCode(this.entropy);

  /// A fresh code from the system RNG.
  static Future<RecoveryCode> generate() async =>
      RecoveryCode(randomBytes(entropyBytes));

  /// The grouped, human-facing form (`ZBK-` prefix, five groups of five).
  Future<String> format() async {
    final raw = await _encode();
    final groups = <String>[];
    for (var i = 0; i < raw.length; i += groupSize) {
      groups.add(raw.substring(i, i + groupSize));
    }
    return 'ZBK-${groups.join('-')}';
  }

  /// The bytes fed to the archive's key derivation: the canonical 25
  /// characters, so formatting, case and separators cannot change the key.
  Future<Uint8List> keyMaterial() async =>
      Uint8List.fromList(utf8.encode(await _encode()));

  Future<String> _encode() async {
    final bits = StringBuffer();
    for (final b in entropy) {
      bits.write(b.toRadixString(2).padLeft(8, '0'));
    }
    final body = StringBuffer();
    for (var i = 0; i < dataChars; i++) {
      body.write(alphabet[
          int.parse(bits.toString().substring(i * 5, i * 5 + 5), radix: 2)]);
    }
    return '$body${alphabet[await _checksum(entropy)]}';
  }

  static Future<int> _checksum(Uint8List entropy) async {
    final d = await Sha256().hash(entropy);
    return d.bytes.first & 0x1f; // top 5 bits of the digest
  }

  /// Parses a typed code, tolerating case, spaces, dashes, the `ZBK` prefix
  /// and the usual I/L/O confusions. Throws [FormatException] with a reason
  /// the UI can show: the length, an impossible character, or the checksum.
  static Future<RecoveryCode> parse(String input) async {
    final cleaned = input
        .toUpperCase()
        .replaceAll(RegExp(r'^\s*ZBK\s*[-\s]?'), '')
        .replaceAll(RegExp(r'[\s\-_]'), '')
        .replaceAll('I', '1')
        .replaceAll('L', '1')
        .replaceAll('O', '0');
    if (cleaned.length != totalChars) {
      throw FormatException(
          'a recovery code is $totalChars characters; this one has '
          '${cleaned.length}');
    }
    final bits = StringBuffer();
    for (var i = 0; i < dataChars; i++) {
      final v = alphabet.indexOf(cleaned[i]);
      if (v < 0) {
        throw FormatException('"${cleaned[i]}" is not part of a recovery code');
      }
      bits.write(v.toRadixString(2).padLeft(5, '0'));
    }
    final entropy = Uint8List(entropyBytes);
    for (var i = 0; i < entropyBytes; i++) {
      entropy[i] =
          int.parse(bits.toString().substring(i * 8, i * 8 + 8), radix: 2);
    }
    final want = alphabet[await _checksum(entropy)];
    if (cleaned[dataChars] != want) {
      throw const FormatException(
          'that code has a typo — check the characters and try again');
    }
    return RecoveryCode(entropy);
  }
}
