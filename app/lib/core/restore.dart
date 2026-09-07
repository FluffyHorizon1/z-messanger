// Restoring from a file the user hands us (9.4).
//
// There are two backup artifacts in the wild: the `.zbk` archive of §9, and
// the older `.zid` identity backup, which carried the identity and contacts
// but no messages. The roadmap folds the second into the first, and this is
// what that means in practice: Z stops OFFERING `.zid`, and keeps READING it
// forever. A user restoring after losing a phone should not have to know
// which artifact they are holding, or be told that the file they carefully
// kept is the wrong kind. So they pick a file and the app works out what it
// is and asks for the matching secret.
//
// Both formats begin with a JSON object, so identifying one costs a short
// read and no key derivation — which matters, because guessing wrong would
// mean running Argon2id against the wrong secret and reporting a failure
// that says nothing useful.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import 'package:z_protocol/z_protocol.dart';

import 'archive.dart';
import 'backup.dart';
import 'vault.dart';

/// What the user handed us.
enum BackupKind {
  /// A `.zbk` archive: full history, unlocked by a recovery code.
  archive,

  /// A `.zid` identity backup: identity and contacts only, unlocked by a
  /// passphrase the user chose. Read for compatibility; never written.
  legacyIdentity,

  /// Not a Z backup, or damaged past recognition.
  unknown,
}

/// What restoring a file will and will not bring back, for the UI to say
/// BEFORE the user commits to it.
class RestorePreview {
  final BackupKind kind;

  /// Whether messages and attachments come back, or only the identity.
  bool get carriesHistory => kind == BackupKind.archive;

  /// The vault schema the archive was written at, when it says.
  final int? schema;
  final DateTime? takenAt;

  const RestorePreview(this.kind, {this.schema, this.takenAt});
}

class RestoreSummary {
  final BackupKind kind;
  final int messages;
  final int contacts;
  final int groups;
  final int attachments;
  const RestoreSummary({
    required this.kind,
    this.messages = 0,
    this.contacts = 0,
    this.groups = 0,
    this.attachments = 0,
  });
}

class Restore {
  /// The first line of either format is a JSON object; a `.zbk` header is
  /// capped at 4 KiB by the reader in `BackupArchive`, and a `.zid` is one
  /// object with no newline at all. Reading 8 KiB identifies both without
  /// loading a large archive.
  static const int _sniffBytes = 8192;

  /// Works out what [file] is. Never derives a key, never throws for an
  /// unreadable file — an unrecognised file is [BackupKind.unknown].
  static Future<RestorePreview> identify(File file) async {
    try {
      final raf = await file.open();
      List<int> head;
      try {
        head = await raf.read(_sniffBytes);
      } finally {
        await raf.close();
      }
      final nl = head.indexOf(0x0a);
      final line = nl >= 0 ? head.sublist(0, nl) : head;
      final j = jsonDecode(utf8.decode(line)) as Map<String, Object?>;
      switch (j['z']) {
        case 'zbk':
          return RestorePreview(
            BackupKind.archive,
            schema: (j['schema'] as num?)?.toInt(),
            takenAt: j['created'] is num
                ? DateTime.fromMillisecondsSinceEpoch(
                    (j['created'] as num).toInt())
                : null,
          );
        case 'backup':
          return const RestorePreview(BackupKind.legacyIdentity);
      }
    } catch (_) {
      // Not JSON, not readable, not ours.
    }
    return const RestorePreview(BackupKind.unknown);
  }

  /// Restores [file] into [vault], which must be empty. [secret] is the
  /// recovery code for an archive and the passphrase for a legacy identity
  /// backup — [identify] tells the UI which to ask for.
  ///
  /// Throws [FormatException] for a wrong secret or a damaged file, and
  /// [ArchiveIncompleteException] for a truncated archive.
  static Future<RestoreSummary> run({
    required Vault vault,
    required File file,
    required String secret,
    required BackupKind kind,
    String? serverUrl,
    void Function(ArchiveProgress)? onProgress,
  }) async {
    switch (kind) {
      case BackupKind.archive:
        final code = await RecoveryCode.parse(secret); // checksum first
        final s = await BackupArchive.import(
            vault: vault, file: file, code: code, onProgress: onProgress);
        if (serverUrl != null && serverUrl.isNotEmpty) {
          await vault.kvPut('server_url', serverUrl, sensitive: false);
        }
        return RestoreSummary(
          kind: kind,
          messages: s.messages,
          contacts: s.contacts,
          groups: s.groups,
          attachments: s.attachments,
        );
      case BackupKind.legacyIdentity:
        return _legacy(vault, await file.readAsBytes(), secret, serverUrl);
      case BackupKind.unknown:
        throw const FormatException('that file is not a Z backup');
    }
  }

  /// The `.zid` path, unchanged in what it restores: identity, name and the
  /// contacts whose bundles still verify. No messages — that format never
  /// had any, and saying so is the UI's job.
  static Future<RestoreSummary> _legacy(Vault vault, Uint8List bytes,
      String passphrase, String? serverUrl) async {
    final restored = await BackupFile.import(bytes, passphrase);
    final idJson = (restored['identity'] as Map).cast<String, Object?>();
    await vault.kvPut('identity', jsonEncode(idJson));
    await vault.kvPut('display_name', restored['name'] as String? ?? 'Me');
    if (serverUrl != null && serverUrl.isNotEmpty) {
      await vault.kvPut('server_url', serverUrl, sensitive: false);
    }
    var contacts = 0;
    for (final c in (restored['contacts'] as List?) ?? const []) {
      final rec = (c as Map).cast<String, Object?>();
      final bundle = ContactBundle.fromJson(
          (rec['bundle'] as Map).cast<String, Object?>());
      // A contact whose signature no longer verifies is not restored: the
      // file is only as trustworthy as the bundles inside it.
      if (!await bundle.verify()) continue;
      await vault.db.insert(
          'contacts',
          {
            'rid': await bundle.routingId(),
            'enc_bundle': await vault.seal(jsonEncode(bundle.toJson())),
            'enc_name': await vault.seal(rec['name'] as String? ?? '?'),
            'ttl_seconds': (rec['ttl'] as num?)?.toInt() ?? 0,
            'verified': (rec['verified'] == true) ? 1 : 0,
            'created_ms': DateTime.now().millisecondsSinceEpoch,
          },
          conflictAlgorithm: ConflictAlgorithm.replace);
      contacts++;
    }
    return RestoreSummary(kind: BackupKind.legacyIdentity, contacts: contacts);
  }
}
