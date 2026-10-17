/// Handles (ADR 0015 revision 2, PROTOCOL.md §21): a name someone can be
/// found by, which resolves to an **introduction mailbox** and never to the
/// account key — so R20's premise, that only someone who already holds an
/// account's key can compute its transparency label, survives a guessable
/// name.
///
/// This file is the protocol half, and nothing in it talks to the network:
///
/// * §21.1 the grammar — what a person types becomes a canonical
///   `nick.digits`, or a typed reason it is not one ([Handle.parse]);
/// * §21.2 the label the handle log is keyed by ([handleLabel]): Argon2id,
///   so a dictionary run against a mirror pays 19 MiB of memory-hard work
///   per guess rather than one SHA-256 (measured: ~21 ms of one core with a
///   native Argon2id, ~130 ms with this pure-Dart one);
/// * §21.3 the keys — the owner key that signs every entry, the introduction
///   identity (an Ed25519 key whose routing id is the mailbox, and an X25519
///   key derived from the same seed that requests are sealed to:
///   [handleIntroIdentity]), and the recovery key committed at claim and
///   shown once as a code ([handleRecoveryKey]);
/// * §21.4 the record the log holds ([HandleRecord]), its one encoding, the
///   signatures over it, and the owner rule as a pure function over any
///   history ([applyHandleEntry], [checkHandleHistory]) — the rule the log
///   enforces on the wire, a mirror on replay, and a client over whatever it
///   holds;
/// * §21.7 the proof-of-work stamp a request to an introduction mailbox
///   carries ([createIntroPowStamp]) and the acknowledgement an owner's
///   acceptance carries, signed by the introduction key ([signIntroAck]);
/// * §21.9 the public introduction link (ADR 0032): the same introduction
///   mailbox handed out directly, as a `zi1.` code, with no registry
///   between ([IntroLink]) — and its reader, which names the reason for
///   every input it refuses ([IntroLinkProblem]).
///
/// The log itself (§21.5, `kt/` in handle mode) and the relay's rules for
/// introduction mailboxes (§21.6) are implemented elsewhere; they check what
/// this file builds.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart' show DartSha256;

import 'connect.dart' show connectLinkHost;
import 'contact_request.dart';
import 'ed25519_strict.dart';
import 'identity.dart';
import 'recovery_code.dart';
import 'util.dart';

final _ed = Ed25519();

// =============================================================================
// §21.1 The grammar
// =============================================================================

const int handleNickMinLength = 3;
const int handleNickMaxLength = 20;
const int handleDigitsMinLength = 2;
const int handleDigitsMaxLength = 6;

/// Nicks no client claims, and none looks up (§21.1). The handle log cannot
/// refuse them — it sees labels, never names — so the refusal is the
/// client's, and it is made on both sides: a reserved name claimed by a
/// modified client is reachable by nobody, because no client resolves it.
///
/// The one copy in code; PROTOCOL.md §21.1 is the other.
const List<String> reservedHandleNicks = [
  'z', 'zm', 'zmessenger', 'zmessengers', 'support', 'help', 'admin', //
  'administrator', 'official', 'security', 'team', 'staff', 'mod',
  'moderator', 'system', 'root', 'everyone', 'here', 'null', 'undefined',
  'abuse', 'privacy', 'legal', 'info', 'contact', 'noreply', 'verify',
  'verified',
];

/// Why an input is not a handle — one value per thing the app can tell the
/// person to fix. When several apply, the first in the order of §21.1's
/// checks is reported.
enum HandleProblem {
  /// Nothing left once surrounding spaces and the leading `@` are removed.
  empty,

  /// A character no handle contains: anything but `a`–`z`, `0`–`9`, `_` and
  /// the one `.` — every non-ASCII character included, since there is no
  /// Unicode folding (a look-alike letter cannot be expressed at all).
  badCharacter,

  /// No `.digits` part (`alice` rather than `alice.42`), or nothing after
  /// the dot.
  missingDigits,

  /// Something other than `0`–`9` after the dot (another dot included).
  digitsNotDigits,

  /// A nick no client claims or resolves ([reservedHandleNicks]).
  reserved,

  /// Fewer than [handleNickMinLength] characters before the dot.
  nickTooShort,

  /// More than [handleNickMaxLength] characters before the dot.
  nickTooLong,

  /// The nick starts with a digit or `_`.
  nickStartsWithNonLetter,

  /// Two underscores in a row.
  nickDoubleUnderscore,

  /// The nick ends with `_`.
  nickEndsWithUnderscore,

  /// One digit after the dot (`alice.7`): a handle has at least two.
  digitsTooShort,

  /// More than [handleDigitsMaxLength] digits.
  digitsTooLong,
}

/// An input refused by the grammar, with the reason the app shows.
class HandleFormatException extends FormatException {
  final HandleProblem problem;

  /// For [HandleProblem.badCharacter]: the first character refused, as a
  /// whole code point exactly as it was typed, so the app can show it.
  final String? character;

  HandleFormatException(this.problem, {this.character})
      : super(_problemMessage(problem, character));

  static String _problemMessage(HandleProblem p, String? c) => c == null
      ? 'not a handle: ${p.name}'
      : 'not a handle: ${p.name} (U+${c.runes.first.toRadixString(16).toUpperCase().padLeft(4, '0')})';
}

bool _isAsciiSpace(int c) => c == 0x20 || (c >= 0x09 && c <= 0x0d);
bool _isLower(int c) => c >= 0x61 && c <= 0x7a;
bool _isDigit(int c) => c >= 0x30 && c <= 0x39;

/// §21.1 input normalisation, before any rule is applied: surrounding ASCII
/// whitespace removed, then ONE leading `@`, then `A`–`Z` lower-cased.
/// Nothing else changes — nothing outside ASCII is trimmed, folded or
/// lower-cased, so it stays in the string for [Handle.parse] to refuse. (A
/// Unicode-aware `toLowerCase` would turn the Kelvin sign, U+212A, into an
/// ASCII `k`: exactly the look-alike the grammar exists to keep out.)
String normaliseHandleInput(String input) {
  final u = input.codeUnits;
  var start = 0, end = u.length;
  while (start < end && _isAsciiSpace(u[start])) {
    start++;
  }
  while (end > start && _isAsciiSpace(u[end - 1])) {
    end--;
  }
  if (start < end && u[start] == 0x40 /* @ */) start++;
  final out = <int>[
    for (var i = start; i < end; i++)
      (u[i] >= 0x41 && u[i] <= 0x5a) ? u[i] + 0x20 : u[i],
  ];
  return String.fromCharCodes(out);
}

/// A handle in canonical form: `nick.digits`, ASCII.
class Handle {
  /// 3–20 characters of `[a-z0-9_]`, starting with a letter, without `__`,
  /// not ending in `_`, and not reserved.
  final String nick;

  /// 2–6 ASCII digits, compared as a string: `07` and `7` are different
  /// (and `7` is not a handle at all).
  final String digits;

  const Handle._(this.nick, this.digits);

  /// `nick.digits` — the only form that is hashed, signed or stored.
  String get canonical => '$nick.$digits';

  /// The canonical form's bytes: the password [handleLabel] hashes.
  Uint8List get canonicalBytes => Uint8List.fromList(ascii.encode(canonical));

  /// How the app writes a handle for a person: `@nick.digits`.
  String get display => '@$canonical';

  /// Parses what a person typed (§21.1): normalised by
  /// [normaliseHandleInput], then every rule checked. Throws
  /// [HandleFormatException] naming the first rule broken.
  static Handle parse(String input) {
    final s = normaliseHandleInput(input);
    if (s.isEmpty) throw HandleFormatException(HandleProblem.empty);
    for (final r in s.runes) {
      if (!(_isLower(r) || _isDigit(r) || r == 0x5f || r == 0x2e)) {
        throw HandleFormatException(HandleProblem.badCharacter,
            character: String.fromCharCode(r));
      }
    }
    final dot = s.indexOf('.');
    if (dot < 0 || dot == s.length - 1) {
      throw HandleFormatException(HandleProblem.missingDigits);
    }
    final nick = s.substring(0, dot);
    final digits = s.substring(dot + 1);
    if (!digits.codeUnits.every(_isDigit)) {
      throw HandleFormatException(HandleProblem.digitsNotDigits);
    }
    if (reservedHandleNicks.contains(nick)) {
      throw HandleFormatException(HandleProblem.reserved);
    }
    if (nick.length < handleNickMinLength) {
      throw HandleFormatException(HandleProblem.nickTooShort);
    }
    if (nick.length > handleNickMaxLength) {
      throw HandleFormatException(HandleProblem.nickTooLong);
    }
    if (!_isLower(nick.codeUnitAt(0))) {
      throw HandleFormatException(HandleProblem.nickStartsWithNonLetter);
    }
    if (nick.contains('__')) {
      throw HandleFormatException(HandleProblem.nickDoubleUnderscore);
    }
    if (nick.endsWith('_')) {
      throw HandleFormatException(HandleProblem.nickEndsWithUnderscore);
    }
    if (digits.length < handleDigitsMinLength) {
      throw HandleFormatException(HandleProblem.digitsTooShort);
    }
    if (digits.length > handleDigitsMaxLength) {
      throw HandleFormatException(HandleProblem.digitsTooLong);
    }
    return Handle._(nick, digits);
  }

  /// [parse], or null when the input is not a handle.
  static Handle? tryParse(String input) {
    try {
      return parse(input);
    } on HandleFormatException {
      return null;
    }
  }

  /// Why [input] is not a handle, or null when it is one.
  static HandleProblem? problemWith(String input) {
    try {
      parse(input);
      return null;
    } on HandleFormatException catch (e) {
      return e.problem;
    }
  }

  @override
  bool operator ==(Object other) =>
      other is Handle && other.nick == nick && other.digits == digits;

  @override
  int get hashCode => Object.hash(nick, digits);

  @override
  String toString() => display;
}

// =============================================================================
// §21.2 The label
// =============================================================================

/// The Argon2id salt, and the parameters: the vault's (OWASP's 19 MiB, two
/// passes, one lane), 32 bytes out.
const String handleLabelSalt = 'z-handle-label-v1';
const int handleLabelMemoryKib = 19456;
const int handleLabelIterations = 2;
const int handleLabelParallelism = 1;
const int handleLabelLength = 32;

/// `label = Argon2id(canonical, salt = "z-handle-label-v1", m = 19456 KiB,
/// t = 2, p = 1, 32 bytes)` — what the handle log is keyed by, and never
/// shown in the app.
///
/// Deliberately slow: measured at 127 ms (AOT) and 151 ms (JIT) on one core
/// of a 2.1 GHz Xeon (`tool/handles_bench.dart`). The memory-hard work runs
/// in a helper isolate the `cryptography` package spawns, so the calling
/// isolate only waits; a caller that wants no wait at all can run this whole
/// function in an isolate of its own — it takes and returns plain values.
Future<Uint8List> handleLabel(Handle handle) async {
  final key = await Argon2id(
    memory: handleLabelMemoryKib,
    parallelism: handleLabelParallelism,
    iterations: handleLabelIterations,
    hashLength: handleLabelLength,
  ).deriveKey(
    secretKey: SecretKey(handle.canonicalBytes),
    nonce: utf8.encode(handleLabelSalt),
  );
  return Uint8List.fromList(await key.extractBytes());
}

// =============================================================================
// §21.3 Keys
// =============================================================================

/// The Ed25519 public key of a 32-byte seed — an owner key, an introduction
/// key or a recovery key. Each is a fresh random seed (`randomBytes(32)`)
/// except the recovery key, which [handleRecoveryKey] derives.
Future<Uint8List> handleKeyPublic(Uint8List seed) async {
  if (seed.length != 32) {
    throw ArgumentError.value(seed.length, 'seed', 'an Ed25519 seed is 32 bytes');
  }
  final kp = await _ed.newKeyPairFromSeed(seed);
  return Uint8List.fromList((await kp.extractPublicKey()).bytes);
}

/// The introduction mailbox: `b64url(SHA-256(introPub))`, the routing id
/// every Ed25519 key in Z has (§2.2) — so a relay treats it like any other.
Future<String> introRoutingId(Uint8List introPub) async {
  if (introPub.length != 32) {
    throw ArgumentError.value(
        introPub.length, 'introPub', 'an Ed25519 public key is 32 bytes');
  }
  return b64url(await sha256Bytes(introPub));
}

/// The HKDF salt of the introduction mailbox's X25519 key.
const String handleIntroXSalt = 'z-handle-intro-x-v1';

/// `xintroSeed = HKDF-SHA256(ikm = introSeed, salt = "z-handle-intro-x-v1",
/// info = "", 32)`: the X25519 private key of the introduction mailbox,
/// which a request to it is sealed to (§8). Derived rather than drawn, so the
/// introduction seed is the whole introduction identity and rotating it
/// rotates both keys. Nobody but the owner can check that a record's
/// `xintro` comes from its `intro`'s seed, and nothing depends on it.
Future<Uint8List> handleIntroXSeed(Uint8List introSeed) async {
  if (introSeed.length != 32) {
    throw ArgumentError.value(
        introSeed.length, 'introSeed', 'an Ed25519 seed is 32 bytes');
  }
  final okm = await Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
    secretKey: SecretKey(introSeed),
    nonce: utf8.encode(handleIntroXSalt),
    info: const <int>[],
  );
  return Uint8List.fromList(await okm.extractBytes());
}

/// The introduction identity of one introduction seed: its `edPub` is the
/// record's `intro` (whose routing id is the mailbox, and which
/// authenticates to the relay to drain it) and its `xPub` the record's
/// `xintro` (which a request is sealed to). A [ZIdentity], so the relay
/// client and [SealedEnvelope.open] take it like any other identity.
Future<ZIdentity> handleIntroIdentity(Uint8List introSeed) async =>
    ZIdentity.fromSeeds(
        edSeed: Uint8List.fromList(introSeed),
        xSeed: await handleIntroXSeed(introSeed));

const String handleRecoverySalt = 'z-handle-recovery-v1';
const String handleRcContext = 'z-handle-rc-v1:';

/// What a handle's recovery code is printed with, in place of the backup
/// code's `ZBK`: the same alphabet, groups and checksum ([RecoveryCode]),
/// and a prefix that tells the two apart on paper.
const String handleRecoveryCodePrefix = 'ZHR';

/// The recovery key a code derives for one label. Nothing here is stored:
/// the device keeps only [rc], which is published, and the code is shown
/// once.
class HandleRecoveryKey {
  /// `HKDF-SHA256(ikm = the code's 15 bytes, salt = "z-handle-recovery-v1",
  /// info = label, 32)` — an Ed25519 seed.
  final Uint8List seed;

  /// Ed25519 public key of [seed]: `rpub` in a recover entry.
  final Uint8List pub;

  /// `SHA-256("z-handle-rc-v1:" || pub)`: the commitment a claim publishes.
  final Uint8List rc;

  HandleRecoveryKey._(this.seed, this.pub, this.rc);
}

/// `rc = SHA-256("z-handle-rc-v1:" || recoveryPub)`.
Future<Uint8List> handleRecoveryCommitment(Uint8List recoveryPub) {
  if (recoveryPub.length != 32) {
    throw ArgumentError.value(recoveryPub.length, 'recoveryPub',
        'an Ed25519 public key is 32 bytes');
  }
  return sha256Bytes(
      concatBytes([utf8.encode(handleRcContext), recoveryPub]));
}

/// The recovery key [code] derives for the handle whose label is [label].
/// The label is the HKDF info, so one code recovers one handle and says
/// nothing about any other.
Future<HandleRecoveryKey> handleRecoveryKey(
    RecoveryCode code, Uint8List label) async {
  if (code.entropy.length != RecoveryCode.entropyBytes) {
    throw ArgumentError('a recovery code is ${RecoveryCode.entropyBytes} bytes');
  }
  if (label.length != handleLabelLength) {
    throw ArgumentError.value(label.length, 'label', 'a label is 32 bytes');
  }
  final okm = await Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
    secretKey: SecretKey(code.entropy),
    nonce: utf8.encode(handleRecoverySalt),
    info: label,
  );
  final seed = Uint8List.fromList(await okm.extractBytes());
  final pub = await handleKeyPublic(seed);
  return HandleRecoveryKey._(seed, pub, await handleRecoveryCommitment(pub));
}

/// `ZHR-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`: [RecoveryCode.format] with the
/// handle prefix in place of the backup one.
Future<String> formatHandleRecoveryCode(RecoveryCode code) async {
  final backup = await code.format(); // 'ZBK-' + five groups
  return '$handleRecoveryCodePrefix-${backup.substring(4)}';
}

/// Parses a typed handle recovery code with [RecoveryCode.parse]'s rules
/// (case, spaces, dashes and the I/L/O confusions tolerated, the checksum
/// enforced), with or without the `ZHR` prefix. A code carrying the backup
/// prefix `ZBK` is refused by name rather than parsed: it is a real code,
/// for something else, and would derive a key the commitment refuses.
///
/// A prefix is recognised only on an input of exactly 25 + 3 characters
/// (separators aside), so a code whose own first characters happen to be
/// `ZHR` or `ZBK` still parses when it is typed without one.
Future<RecoveryCode> parseHandleRecoveryCode(String input) {
  final cleaned = input.toUpperCase().replaceAll(RegExp(r'[\s\-_]'), '');
  var body = cleaned;
  if (cleaned.length ==
      RecoveryCode.totalChars + handleRecoveryCodePrefix.length) {
    if (cleaned.startsWith('ZBK')) {
      throw const FormatException(
          'that is a backup recovery code; a handle has its own');
    }
    if (cleaned.startsWith(handleRecoveryCodePrefix)) {
      body = cleaned.substring(handleRecoveryCodePrefix.length);
    }
  }
  // RecoveryCode.parse takes a leading "ZBK" as its own prefix, so the body
  // is handed over behind one: a body that itself starts "ZBK" keeps it.
  return RecoveryCode.parse('ZBK-$body');
}

// =============================================================================
// §21.4 The record and the owner rule
// =============================================================================

/// A value over 1 KiB is refused (owner rule 6). A record is at most a few
/// hundred bytes, so only something that is not a record can reach it.
const int handleMaxValueBytes = 1024;
const int handlePowMinBits = 16;
const int handlePowMaxBits = 28;

const String handlePublishContext = 'z-handle-publish-v1:';
const String handleRecoverContext = 'z-handle-recover-v1:';

/// The largest version: the log is written in JavaScript, whose integers are
/// exact to 2^53 − 1 (the KT log's rule, §19).
const int handleMaxVersion = 0x1FFFFFFFFFFFFF;

enum HandleRecordKind { claim, update, recover }

/// A value that is not a canonical handle record.
class HandleRecordFormatException extends FormatException {
  HandleRecordFormatException(String reason)
      : super('not a handle record: $reason');
}

/// The value the handle log holds for a label (§21.4): canonical JSON,
/// members in exactly this order, no whitespace —
///
///     {"k":…,"owner":…,"intro":…,"xintro":…,"pow":…,"rc":…[,"rpub":…,"rsig":…]}
///
/// — byte strings `b64url` without padding. [decode] refuses anything that
/// [encode] would not have produced from what it parsed.
class HandleRecord {
  final HandleRecordKind kind;

  /// The owner key AFTER this entry.
  final Uint8List owner;

  /// The introduction key, or null: the handle is paused or retired — it
  /// resolves, and cannot be reached.
  final Uint8List? intro;

  /// The introduction mailbox's X25519 key, which a request is sealed to;
  /// null exactly when [intro] is ([handleIntroIdentity] makes the pair).
  final Uint8List? xintro;

  /// Leading zero bits the relay demands on a send to the introduction
  /// mailbox (§21.7), 16–28.
  final int pow;

  /// The recovery commitment AFTER this entry.
  final Uint8List rc;

  /// `recover` only: the recovery public key, which must hash to the rc it
  /// replaces.
  final Uint8List? rpub;

  /// `recover` only: the recovery key's signature over the new owner and rc
  /// ([handleRecoverInput]).
  final Uint8List? rsig;

  HandleRecord._(this.kind, this.owner, this.intro, this.xintro, this.pow,
      this.rc, this.rpub, this.rsig) {
    final why = _problem(kind, owner, intro, xintro, pow, rc, rpub, rsig);
    if (why != null) throw ArgumentError(why);
  }

  /// The first entry for a label: it fixes the owner and the recovery
  /// commitment.
  factory HandleRecord.claim(
          {required Uint8List owner,
          required Uint8List? intro,
          required Uint8List? xintro,
          required int pow,
          required Uint8List rc}) =>
      HandleRecord._(
          HandleRecordKind.claim, owner, intro, xintro, pow, rc, null, null);

  /// A change by the current owner — of the introduction keys (rotate them,
  /// or null both to pause or retire the handle) or the difficulty. [owner]
  /// and [rc] must be the current ones: changing either is a recover.
  factory HandleRecord.update(
          {required Uint8List owner,
          required Uint8List? intro,
          required Uint8List? xintro,
          required int pow,
          required Uint8List rc}) =>
      HandleRecord._(
          HandleRecordKind.update, owner, intro, xintro, pow, rc, null, null);

  /// A new owner and a new commitment, authorised by the recovery key the
  /// current commitment names ([rpub], [rsig] from [signHandleRecovery]).
  factory HandleRecord.recover(
          {required Uint8List owner,
          required Uint8List? intro,
          required Uint8List? xintro,
          required int pow,
          required Uint8List rc,
          required Uint8List rpub,
          required Uint8List rsig}) =>
      HandleRecord._(
          HandleRecordKind.recover, owner, intro, xintro, pow, rc, rpub, rsig);

  static String? _problem(
      HandleRecordKind kind,
      Uint8List owner,
      Uint8List? intro,
      Uint8List? xintro,
      int pow,
      Uint8List rc,
      Uint8List? rpub,
      Uint8List? rsig) {
    // Every key a strong one (§21.4, [handleStrongEdKey]): a small-order key
    // is one any signature verifies under, and an encoding at or above p is
    // a second spelling of a key.
    if (owner.length != 32) return 'owner is ${owner.length} bytes, not 32';
    if (!handleStrongEdKey(owner)) return 'owner is not a strong Ed25519 key';
    if ((intro == null) != (xintro == null)) {
      return 'intro and xintro are both present or both null';
    }
    if (intro != null && intro.length != 32) {
      return 'intro is ${intro.length} bytes, not 32';
    }
    if (intro != null && !handleStrongEdKey(intro)) {
      return 'intro is not a strong Ed25519 key';
    }
    if (xintro != null && xintro.length != 32) {
      return 'xintro is ${xintro.length} bytes, not 32';
    }
    if (xintro != null && !handleStrongXKey(xintro)) {
      return 'xintro is not a strong X25519 key';
    }
    if (pow < handlePowMinBits || pow > handlePowMaxBits) {
      return 'pow $pow is outside $handlePowMinBits..$handlePowMaxBits';
    }
    if (rc.length != 32) return 'rc is ${rc.length} bytes, not 32';
    if (kind == HandleRecordKind.recover) {
      if (rpub == null || rsig == null) return 'a recover carries rpub and rsig';
      if (rpub.length != 32) return 'rpub is ${rpub.length} bytes, not 32';
      if (!handleStrongEdKey(rpub)) return 'rpub is not a strong Ed25519 key';
      if (rsig.length != 64) return 'rsig is ${rsig.length} bytes, not 64';
    } else if (rpub != null || rsig != null) {
      return 'only a recover carries rpub and rsig';
    }
    return null;
  }

  /// The members, in the one order.
  Map<String, Object?> toJson() => {
        'k': kind.name,
        'owner': b64url(owner),
        'intro': intro == null ? null : b64url(intro!),
        'xintro': xintro == null ? null : b64url(xintro!),
        'pow': pow,
        'rc': b64url(rc),
        if (kind == HandleRecordKind.recover) 'rpub': b64url(rpub!),
        if (kind == HandleRecordKind.recover) 'rsig': b64url(rsig!),
      };

  /// The value's bytes: [toJson] as compact JSON, UTF-8 (all ASCII).
  Uint8List encode() => Uint8List.fromList(utf8.encode(canonicalJson(toJson())));

  /// Parses a value and refuses it unless re-encoding what was parsed gives
  /// back exactly [value]: no whitespace, no other member order, no extra or
  /// missing member, no `null` where a member is absent, no escape, no
  /// padded or non-canonical base64. So a record has one byte string, and
  /// the `SHA-256(value)` a signature covers names one record.
  static HandleRecord decode(List<int> value) {
    if (value.length > handleMaxValueBytes) {
      throw HandleRecordFormatException(
          '${value.length} bytes, over $handleMaxValueBytes');
    }
    final Object? j;
    try {
      j = jsonDecode(utf8.decode(value));
    } on FormatException {
      throw HandleRecordFormatException('not UTF-8 JSON');
    }
    if (j is! Map<String, Object?>) {
      throw HandleRecordFormatException('not a JSON object');
    }
    final Map<String, Object?> m = j;
    final kind = switch (m['k']) {
      'claim' => HandleRecordKind.claim,
      'update' => HandleRecordKind.update,
      'recover' => HandleRecordKind.recover,
      _ => throw HandleRecordFormatException('k is not claim, update or recover'),
    };
    final pow = m['pow'];
    if (pow is! int) throw HandleRecordFormatException('pow is not an integer');
    Uint8List? bytes(String member, {bool nullable = false}) {
      final v = m[member];
      if (v == null && nullable) return null;
      if (v is! String) {
        throw HandleRecordFormatException('$member is not a string');
      }
      try {
        return unb64url(v);
      } on FormatException {
        throw HandleRecordFormatException('$member is not base64url');
      }
    }

    // Absent and null read alike here; the re-encoding below tells them
    // apart (`intro` and `xintro` are always written, `rpub`/`rsig` only on
    // a recover).
    final recover = kind == HandleRecordKind.recover;
    final owner = bytes('owner')!;
    final intro = bytes('intro', nullable: true);
    final xintro = bytes('xintro', nullable: true);
    final rc = bytes('rc')!;
    final rpub = recover ? bytes('rpub') : null;
    final rsig = recover ? bytes('rsig') : null;
    final why = _problem(kind, owner, intro, xintro, pow, rc, rpub, rsig);
    if (why != null) throw HandleRecordFormatException(why);
    final record =
        HandleRecord._(kind, owner, intro, xintro, pow, rc, rpub, rsig);
    if (!constantTimeEquals(record.encode(), value)) {
      throw HandleRecordFormatException(
          'not the canonical encoding of what it says');
    }
    return record;
  }

  /// The introduction mailbox, or null when the handle is paused or retired.
  Future<String?> introRoutingIdOrNull() async =>
      intro == null ? null : introRoutingId(intro!);

  @override
  bool operator ==(Object other) =>
      other is HandleRecord && constantTimeEquals(other.encode(), encode());

  @override
  int get hashCode => Object.hashAll(encode());
}

/// One entry of a handle's history: what a publish sends and the log keeps.
class HandleEntry {
  final Uint8List label;
  final int version;

  /// The record's bytes, exactly as signed ([HandleRecord.encode]).
  final Uint8List value;

  /// Ed25519 by the owner key the rule names, over [handlePublishInput].
  final Uint8List sig;

  HandleEntry(
      {required this.label,
      required this.version,
      required this.value,
      required this.sig});

  /// The body of `POST /kt/v1/publish` to a handle-mode log (§21.4):
  /// the label `b64url`, the value and signature `b64` as the KT publish
  /// route already takes them.
  Map<String, Object?> toPublishJson() => {
        'label': b64url(label),
        'v': version,
        'value': b64(value),
        'sig': b64(sig),
      };
}

Uint8List _u64be(int n) {
  if (n < 0) throw ArgumentError.value(n, 'n', 'negative');
  final b = ByteData(8)..setUint64(0, n);
  return b.buffer.asUint8List();
}

/// `utf8("z-handle-publish-v1:") || label || u64be(v) || SHA-256(value)`.
Future<Uint8List> handlePublishInput(
    {required Uint8List label,
    required int version,
    required Uint8List value}) async {
  if (label.length != handleLabelLength) {
    throw ArgumentError.value(label.length, 'label', 'a label is 32 bytes');
  }
  return concatBytes([
    utf8.encode(handlePublishContext),
    label,
    _u64be(version),
    await sha256Bytes(value),
  ]);
}

/// `utf8("z-handle-recover-v1:") || label || u64be(v) || owner || rc` —
/// the new owner and the new commitment, which is what the recovery key
/// authorises.
Uint8List handleRecoverInput(
    {required Uint8List label,
    required int version,
    required Uint8List owner,
    required Uint8List rc}) {
  if (label.length != 32 || owner.length != 32 || rc.length != 32) {
    throw ArgumentError('label, owner and rc are 32 bytes each');
  }
  return concatBytes(
      [utf8.encode(handleRecoverContext), label, _u64be(version), owner, rc]);
}

/// Signs [record] as entry [version] of [label] with the owner seed. The
/// seed must be the key the record names as its owner: for a claim and an
/// update that is the owner the rule checks, and for a recover it is the
/// NEW owner, which signs the entry that installs it.
Future<HandleEntry> signHandleEntry(
    {required Uint8List label,
    required int version,
    required HandleRecord record,
    required Uint8List ownerSeed}) async {
  if (version < 1 || version > handleMaxVersion) {
    throw ArgumentError.value(version, 'version', 'not in 1..2^53-1');
  }
  final kp = await _ed.newKeyPairFromSeed(ownerSeed);
  final pub = Uint8List.fromList((await kp.extractPublicKey()).bytes);
  if (!constantTimeEquals(pub, record.owner)) {
    throw ArgumentError('the seed is not the owner the record names');
  }
  final value = record.encode();
  final sig = await _ed.sign(
      await handlePublishInput(label: label, version: version, value: value),
      keyPair: kp);
  return HandleEntry(
      label: label,
      version: version,
      value: value,
      sig: Uint8List.fromList(sig.bytes));
}

/// `rsig`: the recovery key's signature authorising [owner] and [rc] as
/// entry [version] of [label] ([handleRecoverInput]).
Future<Uint8List> signHandleRecovery(
    {required Uint8List recoverySeed,
    required Uint8List label,
    required int version,
    required Uint8List owner,
    required Uint8List rc}) async {
  final kp = await _ed.newKeyPairFromSeed(recoverySeed);
  final sig = await _ed.sign(
      handleRecoverInput(label: label, version: version, owner: owner, rc: rc),
      keyPair: kp);
  return Uint8List.fromList(sig.bytes);
}

/// Why an entry was refused. Owner-rule numbers are PROTOCOL.md §21.4's.
enum HandleRefusal {
  /// Rule 6: the value is over [handleMaxValueBytes].
  tooLarge,

  /// Not a canonical record ([HandleRecord.decode]), or a label, version or
  /// signature of the wrong shape.
  malformed,

  /// An entry for a different label inside one label's history.
  otherLabel,

  /// Rule 1: the label's first entry is not a claim.
  notClaimed,

  /// Rule 2: a claim on a label that already exists.
  taken,

  /// Rule 5: the version is not the label's next one — 1 for a claim, the
  /// current version + 1 after it.
  staleVersion,

  /// Rule 3: an update names an owner other than the current one.
  ownerChanged,

  /// Rule 3: an update changes the recovery commitment.
  rcChanged,

  /// Rule 4: a recover's `rpub` does not hash to the current commitment.
  wrongRecoveryKey,

  /// Rule 4: a recover's `rsig` does not verify under its `rpub`.
  badRecoverySignature,

  /// `sig` does not verify under the owner the record names — the claimant,
  /// the current owner (an update, which must name it), or the new owner (a
  /// recover) — by the one rule of [verifyHandleSignature].
  badSignature,
}

class HandleRefusedException implements Exception {
  final HandleRefusal reason;
  final String detail;
  HandleRefusedException(this.reason, this.detail);
  @override
  String toString() => 'HandleRefusedException(${reason.name}): $detail';
}

/// What a label's history amounts to after its last accepted entry.
class HandleState {
  final Uint8List label;
  final int version;
  final HandleRecord record;
  HandleState(this.label, this.version, this.record);

  /// The current owner key: only it may sign an update.
  Uint8List get owner => record.owner;

  /// The current recovery commitment: only its key may authorise a recover.
  Uint8List get rc => record.rc;
}

/// Whether [sig] is [pub]'s signature over [data] under the one rule of
/// §21.4 ([ed25519VerifyStrict]) — every handle signature, `sig`, `rsig`
/// and `ia`, is checked with this and nothing else.
Future<bool> verifyHandleSignature(
        Uint8List pub, Uint8List data, Uint8List sig) async =>
    ed25519VerifyStrict(pub, data, sig);

Future<bool> _verify(Uint8List pub, Uint8List data, Uint8List sig) =>
    verifyHandleSignature(pub, data, sig);

/// The owner rule (§21.4) for one entry: [current] is the state after the
/// label's earlier entries (null when there are none), and the result is
/// the state after [entry]. Throws [HandleRefusedException] — and changes
/// nothing — when the entry breaks any rule. Pure: the same inputs give the
/// same answer on a client, a mirror and the log.
///
/// The checks run in §21.4's one order, which is the log's
/// (`kt/lib/handles.js`): first everything the entry says about itself —
/// its shape, its size, its record, its signatures — then what it says
/// about the label's history, the version last of all. So the log, a mirror
/// and a client name the same refusal, and a refusal names the label's
/// version only to an entry its owner or its recovery key signed.
Future<HandleState> applyHandleEntry(
    HandleState? current, HandleEntry entry) async {
  Never refuse(HandleRefusal r, String d) => throw HandleRefusedException(r, d);

  // The entry's shape. Nothing here reads the value.
  if (entry.label.length != handleLabelLength) {
    refuse(HandleRefusal.malformed, 'the label is not 32 bytes');
  }
  if (entry.version < 1 || entry.version > handleMaxVersion) {
    refuse(HandleRefusal.malformed, 'the version is not in 1..2^53-1');
  }
  if (entry.sig.length != 64) {
    refuse(HandleRefusal.malformed, 'the signature is not 64 bytes');
  }
  // Rule 6: nothing else is read from an oversize value.
  if (entry.value.length > handleMaxValueBytes) {
    refuse(HandleRefusal.tooLarge,
        'the value is ${entry.value.length} bytes, over $handleMaxValueBytes');
  }
  final HandleRecord record;
  try {
    record = HandleRecord.decode(entry.value);
  } on HandleRecordFormatException catch (e) {
    refuse(HandleRefusal.malformed, e.message);
  }

  // Its signatures. `sig` is by the owner the record names — the claimant,
  // the current owner (an update must name it: rule 3, below), or the new
  // owner a recover installs — and a recover's `rsig` by its `rpub`.
  final publishInput = await handlePublishInput(
      label: entry.label, version: entry.version, value: entry.value);
  if (!await _verify(record.owner, publishInput, entry.sig)) {
    refuse(HandleRefusal.badSignature,
        'sig is not the signature of the owner the record names');
  }
  if (record.kind == HandleRecordKind.recover) {
    final rInput = handleRecoverInput(
        label: entry.label,
        version: entry.version,
        owner: record.owner,
        rc: record.rc);
    if (!await _verify(record.rpub!, rInput, record.rsig!)) {
      refuse(HandleRefusal.badRecoverySignature,
          'rsig does not verify under rpub over the new owner and rc');
    }
  }

  // The history.
  if (current != null && !constantTimeEquals(current.label, entry.label)) {
    refuse(HandleRefusal.otherLabel, 'an entry for another label');
  }
  // Rules 1 and 2: the first entry is a claim, and no other entry is.
  if (current == null) {
    if (record.kind != HandleRecordKind.claim) {
      refuse(HandleRefusal.notClaimed,
          'the first entry for a label is a ${record.kind.name}, not a claim');
    }
  } else if (record.kind == HandleRecordKind.claim) {
    refuse(HandleRefusal.taken, 'the label is already claimed');
  }
  switch (record.kind) {
    case HandleRecordKind.claim:
      break;
    case HandleRecordKind.update:
      // Rule 3: an update keeps the owner — so the current owner signed it —
      // and the commitment.
      if (!constantTimeEquals(record.owner, current!.owner)) {
        refuse(HandleRefusal.ownerChanged,
            'an update names another owner; changing the owner is a recover');
      }
      if (!constantTimeEquals(record.rc, current.rc)) {
        refuse(HandleRefusal.rcChanged,
            'an update changes the recovery commitment');
      }
    case HandleRecordKind.recover:
      // Rule 4: the recovery key is the one the current rc commits to.
      if (!constantTimeEquals(
          await handleRecoveryCommitment(record.rpub!), current!.rc)) {
        refuse(HandleRefusal.wrongRecoveryKey,
            'rpub is not the key the current commitment names');
      }
  }
  // Rule 5, last: the label's NEXT version — 1 for a claim, the current one
  // plus one after it. Not merely a higher one: under that rule whoever held
  // the owner key could publish one update at 2^53 − 1, and the recover the
  // code exists for, which must follow it, had no version left.
  final next = current == null ? 1 : current.version + 1;
  if (entry.version != next) {
    refuse(
        HandleRefusal.staleVersion,
        current == null
            ? 'a claim is version 1, not ${entry.version}'
            : 'the label is at version ${current.version}: the next entry is '
                '$next, not ${entry.version}');
  }
  return HandleState(Uint8List.fromList(entry.label), entry.version, record);
}

/// The verdict of the owner rule over a whole history.
class HandleHistoryVerdict {
  /// The state after the last accepted entry; null when the first entry was
  /// refused (or there were none).
  final HandleState? state;

  /// The index of the first refused entry, or null when every entry holds.
  final int? refusedAt;
  final HandleRefusal? reason;
  final String? detail;

  HandleHistoryVerdict._(this.state, this.refusedAt, this.reason, this.detail);

  bool get ok => refusedAt == null;
}

/// Runs the owner rule over [entries], in order, and stops at the first
/// refusal. A history with a refused entry in it is not one an honest log
/// could have served: a client treats the handle as unresolvable, a mirror
/// reports the log, and the log refuses to start from such a file.
Future<HandleHistoryVerdict> checkHandleHistory(
    Iterable<HandleEntry> entries) async {
  HandleState? state;
  var i = 0;
  for (final e in entries) {
    try {
      state = await applyHandleEntry(state, e);
    } on HandleRefusedException catch (x) {
      return HandleHistoryVerdict._(state, i, x.reason, x.detail);
    }
    i++;
  }
  return HandleHistoryVerdict._(state, null, null, null);
}

// =============================================================================
// §21.7 The proof-of-work stamp
// =============================================================================

const String introPowContext = 'z-intro-pow-v1:';
const int introPowNonceLength = 16;
const int _msPerDay = 86400000;

/// UTC days since the epoch: the `day` a stamp is made for.
int introPowDay(int unixMs) => (unixMs / _msPerDay).floor();

/// `utf8("z-intro-pow-v1:") || ridBytes(32) || u32be(day) || envelopeHash(32)
/// || nonce(16)` — 99 bytes, whose SHA-256 must start with the record's
/// `pow` zero bits.
Uint8List introPowInput(
    {required Uint8List ridBytes,
    required int day,
    required Uint8List envelopeHash,
    required Uint8List nonce}) {
  if (ridBytes.length != 32 || envelopeHash.length != 32) {
    throw ArgumentError('the routing id and the envelope hash are 32 bytes');
  }
  if (nonce.length != introPowNonceLength) {
    throw ArgumentError('a nonce is $introPowNonceLength bytes');
  }
  if (day < 0 || day > 0xffffffff) throw ArgumentError.value(day, 'day');
  final d = ByteData(4)..setUint32(0, day);
  return concatBytes([
    utf8.encode(introPowContext),
    ridBytes,
    d.buffer.asUint8List(),
    envelopeHash,
    nonce,
  ]);
}

/// The leading zero bits of [digest], most significant bit of byte 0 first.
int introPowZeroBits(List<int> digest) {
  var n = 0;
  for (final b in digest) {
    if (b == 0) {
      n += 8;
      continue;
    }
    var x = b;
    while (x & 0x80 == 0) {
      n++;
      x <<= 1;
    }
    break;
  }
  return n;
}

/// The 32 bytes a routing id names, or null when [rid] is not one: exactly
/// 43 characters of unpadded `b64url` that re-encode to themselves.
Uint8List? _tryRidBytes(String rid) {
  final Uint8List b;
  try {
    b = unb64url(rid);
  } on FormatException {
    return null;
  }
  return b.length == 32 && b64url(b) == rid ? b : null;
}

Uint8List _ridBytes(String rid) =>
    _tryRidBytes(rid) ??
    (throw ArgumentError.value(rid, 'rid', 'not a routing id'));

/// Finds a stamp: a 16-byte nonce whose [introPowInput] for (the mailbox
/// [introRid], [day], `SHA-256(envelope)`) hashes to at least [bits] leading
/// zero bits. [envelope] is the UTF-8 of the send frame's `payload` string,
/// exactly as sent (§21.7).
///
/// Pure and synchronous — no `await`, no shared state — so a caller runs it
/// with `Isolate.run` and the UI never waits on it. Expected work is 2^bits
/// hashes; the search starts at [startNonce] (random when omitted) and counts
/// up, and the answer is re-checked with an independent SHA-256 before it is
/// returned. A relay that refuses a stamp (`pow_required`) names its own
/// `day`; a client re-stamps once with that day (§21.7).
Uint8List createIntroPowStamp(
    {required String introRid,
    required int day,
    required List<int> envelope,
    required int bits,
    Uint8List? startNonce}) {
  if (bits < 0 || bits > 32) {
    throw ArgumentError.value(bits, 'bits', 'a stamp is made for 0..32 bits');
  }
  final rid = _ridBytes(introRid);
  const sha = DartSha256();
  final envHash = Uint8List.fromList(sha.hashSync(envelope).bytes);
  final nonce = Uint8List.fromList(
      startNonce ?? randomBytes(introPowNonceLength));
  if (nonce.length != introPowNonceLength) {
    throw ArgumentError('a nonce is $introPowNonceLength bytes');
  }
  final input = introPowInput(
      ridBytes: rid, day: day, envelopeHash: envHash, nonce: nonce);
  // 99 bytes: block 1 (bytes 0..63) never changes, so its compression is
  // done once; block 2 holds the last 35 bytes (19 of the envelope hash, then
  // the nonce at 19..34) and the padding, and is the only one hashed per try.
  final mid = Uint32List.fromList(_sha256Iv);
  final w = Uint32List(64);
  final block1 = ByteData.sublistView(input, 0, 64);
  for (var i = 0; i < 16; i++) {
    w[i] = block1.getUint32(i * 4);
  }
  _sha256Compress(mid, w);
  final block2 = Uint8List(64)..setRange(0, 35, input, 64);
  block2[35] = 0x80;
  ByteData.sublistView(block2).setUint64(56, input.length * 8);
  final b2 = ByteData.sublistView(block2);
  final fixed = Uint32List(16);
  for (var i = 0; i < 16; i++) {
    fixed[i] = b2.getUint32(i * 4);
  }
  final st = Uint32List(8);
  final mask = bits == 0 ? 0 : (0xffffffff << (32 - bits)) & 0xffffffff;
  while (true) {
    // Words 4..8 hold the nonce (bytes 19..34 of block 2).
    block2.setRange(19, 35, nonce);
    for (var i = 0; i < 16; i++) {
      w[i] = (i >= 4 && i <= 8) ? b2.getUint32(i * 4) : fixed[i];
    }
    st.setAll(0, mid);
    _sha256Compress(st, w);
    if (st[0] & mask == 0) {
      final check = sha.hashSync(introPowInput(
          ridBytes: rid, day: day, envelopeHash: envHash, nonce: nonce));
      if (introPowZeroBits(check.bytes) < bits) {
        throw StateError('stamp search and SHA-256 disagree');
      }
      return Uint8List.fromList(nonce);
    }
    // Count up, big-endian, across all sixteen bytes.
    for (var i = introPowNonceLength - 1; i >= 0; i--) {
      nonce[i] = (nonce[i] + 1) & 0xff;
      if (nonce[i] != 0) break;
    }
  }
}

/// Whether [nonce] is a stamp of at least [bits] for ([introRid], [day],
/// `SHA-256(envelope)`).
Future<bool> verifyIntroPowStamp(
    {required String introRid,
    required int day,
    required List<int> envelope,
    required Uint8List nonce,
    required int bits}) async {
  if (nonce.length != introPowNonceLength || day < 0 || day > 0xffffffff) {
    return false;
  }
  final rid = _tryRidBytes(introRid);
  if (rid == null) return false;
  final digest = await sha256Bytes(introPowInput(
      ridBytes: rid,
      day: day,
      envelopeHash: await sha256Bytes(envelope),
      nonce: nonce));
  return introPowZeroBits(digest) >= bits;
}

/// The relay's acceptance (§21.6, here so a client can check its own): a
/// stamp made for the relay's today or yesterday, by the clock [nowMs].
Future<bool> introPowAcceptable(
    {required String introRid,
    required List<int> envelope,
    required Uint8List nonce,
    required int bits,
    required int nowMs}) async {
  final today = introPowDay(nowMs);
  for (final day in [today, today - 1]) {
    if (await verifyIntroPowStamp(
        introRid: introRid,
        day: day,
        envelope: envelope,
        nonce: nonce,
        bits: bits)) {
      return true;
    }
  }
  return false;
}

const List<int> _sha256Iv = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, //
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const List<int> _sha256K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, //
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// One SHA-256 compression (FIPS 180-4 §6.2.2) of the 16 words in w[0..15]
/// into [state], in place; w[16..63] are overwritten with the schedule. Only
/// the stamp search uses it, and only because it keeps a midstate; every
/// answer it finds is re-hashed by the `cryptography` package's SHA-256.
void _sha256Compress(Uint32List state, Uint32List w) {
  for (var t = 16; t < 64; t++) {
    final x = w[t - 15], y = w[t - 2];
    final s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
    final s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
    w[t] = w[t - 16] + (s0 & 0xffffffff) + w[t - 7] + (s1 & 0xffffffff);
  }
  var a = state[0], b = state[1], c = state[2], d = state[3];
  var e = state[4], f = state[5], g = state[6], h = state[7];
  for (var t = 0; t < 64; t++) {
    final s1 = (((e >>> 6) | (e << 26)) ^
            ((e >>> 11) | (e << 21)) ^
            ((e >>> 25) | (e << 7))) &
        0xffffffff;
    final ch = (e & f) ^ ((~e) & g);
    final t1 = (h + s1 + ch + _sha256K[t] + w[t]) & 0xffffffff;
    final s0 = (((a >>> 2) | (a << 30)) ^
            ((a >>> 13) | (a << 19)) ^
            ((a >>> 22) | (a << 10))) &
        0xffffffff;
    final maj = (a & b) ^ (a & c) ^ (b & c);
    h = g;
    g = f;
    f = e;
    e = (d + t1) & 0xffffffff;
    d = c;
    c = b;
    b = a;
    a = (t1 + s0 + maj) & 0xffffffff;
  }
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
}

// =============================================================================
// §21.7 The acknowledgement
// =============================================================================

const String introAckContext = 'z-intro-ack-v1:';

/// What names one contact request (`creq`, §8.1): `SHA-256(sigInput)`, the
/// hash of exactly the bytes the requester signed — its keys, the mailbox it
/// was addressed to, its timestamp and its name. The format has no id member
/// (the app files a pending request under the requester's routing id, one per
/// requester), and these are the only bytes both ends hold identically: the
/// requester built them, and the owner verified the signature over them.
Future<Uint8List> contactRequestId(ContactRequest request) => sha256Bytes(
    ContactRequest.signingInput(request.bundle, request.toRid, request.ts));

/// `utf8("z-intro-ack-v1:") || requesterRidBytes(32) || ownerAccountEdPub(32)
/// || creqId(32)`.
Uint8List introAckInput(
    {required Uint8List requesterRidBytes,
    required Uint8List ownerAccountEdPub,
    required Uint8List creqId}) {
  if (requesterRidBytes.length != 32 ||
      ownerAccountEdPub.length != 32 ||
      creqId.length != 32) {
    throw ArgumentError('the requester, the owner and the request id are 32 '
        'bytes each');
  }
  return concatBytes([
    utf8.encode(introAckContext),
    requesterRidBytes,
    ownerAccountEdPub,
    creqId,
  ]);
}

/// `ia`: the owner's introduction key saying "the account
/// [ownerAccountEdPub] accepts the request [creqId] that [requesterRid] sent
/// to my mailbox" — `b64url(Ed25519(introSeed, introAckInput))`, carried on
/// the `creq` an acceptance sends back (§21.7).
Future<String> signIntroAck(
    {required Uint8List introSeed,
    required String requesterRid,
    required Uint8List ownerAccountEdPub,
    required Uint8List creqId}) async {
  final kp = await _ed.newKeyPairFromSeed(introSeed);
  final sig = await _ed.sign(
      introAckInput(
          requesterRidBytes: _ridBytes(requesterRid),
          ownerAccountEdPub: ownerAccountEdPub,
          creqId: creqId),
      keyPair: kp);
  return b64url(sig.bytes);
}

/// Whether [ia] is the introduction key [introPub]'s acknowledgement that the
/// account [ownerAccountEdPub] accepted the request [creqId] from
/// [requesterRid]. The requester checks it against the introduction key it
/// resolved for its pending request, and the account key the acceptance
/// itself came from.
Future<bool> verifyIntroAck(
    {required String ia,
    required Uint8List introPub,
    required String requesterRid,
    required Uint8List ownerAccountEdPub,
    required Uint8List creqId}) async {
  final Uint8List sig;
  try {
    sig = unb64url(ia);
  } on FormatException {
    return false;
  }
  final rid = _tryRidBytes(requesterRid);
  if (rid == null || ownerAccountEdPub.length != 32 || creqId.length != 32) {
    return false;
  }
  return _verify(
      introPub,
      introAckInput(
          requesterRidBytes: rid,
          ownerAccountEdPub: ownerAccountEdPub,
          creqId: creqId),
      sig);
}

// =============================================================================
// §21.9 Public introduction links (ADR 0032)
// =============================================================================

/// What a public introduction link's code starts with: `zi`, its version,
/// and `.` — which no contact code or invite starts with. A handle can
/// (`zi1.42` is one) and is still never a link: a link is 96 characters, a
/// handle at most 27.
const String introLinkPrefix = 'zi1.';

/// The context of a link's check (§21.0).
const String introLinkContext = 'z-intro-link-v1:';

/// The page a link is printed on, `https://host/c#zi1.…`. No build claims
/// `/c` for anything else, and none before 39.2 claims it at all. A reader
/// takes the code that follows a `#` whatever page it is on.
const String introLinkPath = '/c';

/// `u8(pow) || intro || xintro`.
const int introLinkBodyBytes = 65;

/// How many bytes of `SHA-256(utf8("z-intro-link-v1:") || body)` the code
/// carries after the body.
const int introLinkCheckBytes = 4;

/// What follows `zi1.`: the body and the check, 69 bytes, as base64url —
/// 92 characters, with no padding and no spare bits, so every string of 92
/// characters from the alphabet is exactly one 69-byte string.
const int introLinkEncodedLength = 92;

/// The whole code: `zi1.` and the 92.
const int introLinkCodeLength = 96;

/// The work a printed link asks when its owner chooses none: 20 bits, as a
/// handle's (ADR 0032, decision 5). A link may carry any difficulty from
/// [handlePowMinBits] to [handlePowMaxBits].
const int introLinkDefaultPow = 20;

/// Why an input is not a public introduction link (§21.9) — one value per
/// thing the app can tell the person. When several apply, the first in the
/// order the reader checks them is named.
enum IntroLinkProblem {
  /// Nothing that starts as a link does: a contact code, an invite, a
  /// handle, any other text, or nothing at all — after the `#`, if there is
  /// one. The prefix is compared exactly, so `ZI1.` is not a link either.
  notALink,

  /// `zi`, a version other than 1, and `.`: a link from a newer Z, which
  /// this build cannot read and must not guess at — the person is told to
  /// update rather than that the link is broken.
  newerVersion,

  /// A character after `zi1.` that no code holds: anything but `A`–`Z`,
  /// `a`–`z`, `0`–`9`, `-` and `_` — padding, `+` and `/` among them.
  notBase64url,

  /// The right characters, but not [introLinkEncodedLength] of them.
  wrongLength,

  /// The check does not match: the copy was damaged on its way, a
  /// character or the case of one changed. A substituted link has a check
  /// of its own; this catches only a damaged one.
  badCheck,

  /// A difficulty outside [handlePowMinBits]–[handlePowMaxBits].
  powOutOfRange,

  /// `intro` is not a strong Ed25519 key (§21.4): an acknowledgement under
  /// it could be forged by anyone.
  weakIntro,

  /// `xintro` is not a strong X25519 key (§21.4): a request sealed to it
  /// would be open to anyone who holds it, the relay first.
  weakXintro,
}

/// An input refused by [IntroLink.parse], with the reason the app shows.
class IntroLinkFormatException extends FormatException {
  final IntroLinkProblem problem;

  IntroLinkFormatException(this.problem)
      : super('not a public introduction link: ${problem.name}');
}

/// `SHA-256(utf8("z-intro-link-v1:") || body)[0..4]`: what a code carries
/// after its body, so a copy damaged on its way is refused rather than
/// read as other keys.
Uint8List introLinkCheck(List<int> body) {
  if (body.length != introLinkBodyBytes) {
    throw ArgumentError.value(
        body.length, 'body', 'a link body is $introLinkBodyBytes bytes');
  }
  final digest = const DartSha256()
      .hashSync([...utf8.encode(introLinkContext), ...body]).bytes;
  return Uint8List.fromList(digest.sublist(0, introLinkCheckBytes));
}

bool _isB64urlChar(int c) =>
    (c >= 0x41 && c <= 0x5a) || // A-Z
    (c >= 0x61 && c <= 0x7a) || // a-z
    (c >= 0x30 && c <= 0x39) || // 0-9
    c == 0x2d || // -
    c == 0x5f; // _

/// `zi`, a version other than 1 — decimal, without a leading zero — and
/// `.`: how a newer Z would start a link of its own (§21.9).
bool _startsAsNewerLink(String s) {
  if (!s.startsWith('zi')) return false;
  final dot = s.indexOf('.', 2);
  if (dot < 3) return false; // no version, or no dot
  final version = s.substring(2, dot);
  if (version.codeUnitAt(0) == 0x30) return false; // a leading zero
  return version != '1' && version.codeUnits.every(_isDigit);
}

String _trimAsciiSpace(String input) {
  final u = input.codeUnits;
  var start = 0, end = u.length;
  while (start < end && _isAsciiSpace(u[start])) {
    start++;
  }
  while (end > start && _isAsciiSpace(u[end - 1])) {
    end--;
  }
  return input.substring(start, end);
}

/// A public introduction link (ADR 0032, PROTOCOL §21.9): a handle's
/// introduction mailbox handed out directly — on a web page, in a signature,
/// as a printed QR — instead of through a handle log. What a request through
/// a handle takes from the handle's record is all it carries: the difficulty,
/// the introduction key and the key a request is sealed to.
///
///     body  = u8(pow) || intro || xintro                        65 bytes
///     check = SHA-256( utf8("z-intro-link-v1:") || body )[0..4]
///     code  = "zi1." || b64url( body || check )                 96 characters
///     link  = "https://" || host || "/c#" || code               126 at the default host
///
/// Nothing else is in it: no name, no relay, no expiry (ADR 0032, decision
/// 4), and nothing about the account, whose key arrives with the acceptance
/// (§21.7). The code rides in the fragment, which no browser sends, so the
/// page a link opens never receives it.
///
/// This is the format and its reader; what the owner's device and the
/// person who opens a link do with one are ADR 0032 §3–§4, not built here.
class IntroLink {
  /// Leading zero bits a stamp on a request through this link needs
  /// (§21.7), [handlePowMinBits]–[handlePowMaxBits].
  final int pow;

  /// The introduction key: a strong Ed25519 key (§21.4), whose routing id is
  /// the mailbox ([introRid]) and under which an acceptance's `ia` verifies.
  final Uint8List intro;

  /// The introduction mailbox's X25519 key, which a request is sealed to: a
  /// strong X25519 key (§21.4).
  final Uint8List xintro;

  IntroLink._(this.pow, this.intro, this.xintro);

  /// The link naming [intro] and [xintro] at [pow]. Throws [ArgumentError]
  /// for anything [parse] would refuse to read back, so no code is made that
  /// a reader refuses.
  factory IntroLink(
      {required int pow,
      required Uint8List intro,
      required Uint8List xintro}) {
    if (intro.length != 32 || xintro.length != 32) {
      throw ArgumentError('intro and xintro are 32 bytes each');
    }
    final why = _contentProblem(pow, intro, xintro);
    if (why != null) {
      throw ArgumentError('not a link a reader takes: ${why.name}');
    }
    return IntroLink._(
        pow, Uint8List.fromList(intro), Uint8List.fromList(xintro));
  }

  /// The link [introSeed] makes: `intro`, `xintro` and the mailbox exactly
  /// as §21.3 derives a handle's ([handleIntroIdentity]), so the owner
  /// drains it, opens its requests and signs `ia` as for a handle.
  static Future<IntroLink> fromSeed(Uint8List introSeed,
      {int pow = introLinkDefaultPow}) async {
    final id = await handleIntroIdentity(introSeed);
    return IntroLink(pow: pow, intro: id.edPub, xintro: id.xPub);
  }

  /// `u8(pow) || intro || xintro`: 65 bytes.
  Uint8List get body => Uint8List.fromList([pow, ...intro, ...xintro]);

  /// [introLinkCheck] of [body].
  Uint8List get check => introLinkCheck(body);

  /// `"zi1." || b64url(body || check)`: 96 characters.
  String get code => '$introLinkPrefix${b64url([...body, ...check])}';

  /// `https://<host>/c#<code>` — [host] the deployment's, as for an invite
  /// (§20.2): 126 characters at the default host.
  String link({String host = connectLinkHost}) =>
      'https://$host$introLinkPath#$code';

  /// The introduction mailbox: `b64url(SHA-256(intro))`, as a handle's
  /// (§21.3) — where a request through this link is sent.
  Future<String> introRid() => introRoutingId(intro);

  /// Reads a link or a bare code, as it was pasted, scanned or tapped
  /// (§21.9): surrounding ASCII whitespace trimmed, then — given a `#` —
  /// only what follows the first one, whatever page it is on. That must be
  /// `zi1.` and exactly 92 base64url characters, with no padding and no
  /// case folding, whose check matches and whose `pow`, `intro` and
  /// `xintro` a link may carry. Throws [IntroLinkFormatException] naming the
  /// first rule broken, in that order.
  static IntroLink parse(String input) {
    Never refuse(IntroLinkProblem p) => throw IntroLinkFormatException(p);
    var s = _trimAsciiSpace(input);
    final hash = s.indexOf('#');
    if (hash >= 0) s = s.substring(hash + 1);
    if (!s.startsWith(introLinkPrefix)) {
      refuse(_startsAsNewerLink(s)
          ? IntroLinkProblem.newerVersion
          : IntroLinkProblem.notALink);
    }
    final encoded = s.substring(introLinkPrefix.length);
    if (!encoded.codeUnits.every(_isB64urlChar)) {
      refuse(IntroLinkProblem.notBase64url);
    }
    if (encoded.length != introLinkEncodedLength) {
      refuse(IntroLinkProblem.wrongLength);
    }
    final raw = unb64url(encoded);
    final body = Uint8List.sublistView(raw, 0, introLinkBodyBytes);
    if (!constantTimeEquals(
        introLinkCheck(body), Uint8List.sublistView(raw, introLinkBodyBytes))) {
      refuse(IntroLinkProblem.badCheck);
    }
    final intro = Uint8List.fromList(body.sublist(1, 33));
    final xintro = Uint8List.fromList(body.sublist(33, 65));
    final why = _contentProblem(body[0], intro, xintro);
    if (why != null) refuse(why);
    return IntroLink._(body[0], intro, xintro);
  }

  /// [parse], or null when the input is not a link.
  static IntroLink? tryParse(String input) {
    try {
      return parse(input);
    } on IntroLinkFormatException {
      return null;
    }
  }

  /// Why [input] is not a link, or null when it is one.
  static IntroLinkProblem? problemWith(String input) {
    try {
      parse(input);
      return null;
    } on IntroLinkFormatException catch (e) {
      return e.problem;
    }
  }

  /// What a link's content must be, in the reader's order: the difficulty,
  /// then the two keys strong by §21.4's one rule — the rule a handle
  /// record's keys are held to.
  static IntroLinkProblem? _contentProblem(
      int pow, Uint8List intro, Uint8List xintro) {
    if (pow < handlePowMinBits || pow > handlePowMaxBits) {
      return IntroLinkProblem.powOutOfRange;
    }
    if (!handleStrongEdKey(intro)) return IntroLinkProblem.weakIntro;
    if (!handleStrongXKey(xintro)) return IntroLinkProblem.weakXintro;
    return null;
  }

  @override
  bool operator ==(Object other) =>
      other is IntroLink && constantTimeEquals(other.body, body);

  @override
  int get hashCode => Object.hashAll(body);
}
