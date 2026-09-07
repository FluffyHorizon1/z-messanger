// Where a backup actually goes (9.3).
//
// Two steps, deliberately separate, because they have different failure
// modes and only the first one has to succeed for the user's history to be
// safe:
//
//   1. WRITE. The archive is streamed into the app's own backup folder. This
//      never opens a dialog, never needs the user to be present, and holds
//      neither the archive nor any attachment in memory — which is what lets
//      the scheduled export of 9.5 use exactly the same path.
//   2. HAND OVER. The finished file is copied wherever the user says. This
//      needs a picker, so it needs a person, and on mobile the platform
//      makes us hold the whole file in memory (see `FileExport`).
//
// Splitting them means a backup that was taken but not yet exported is still
// a backup: it survives an app update or a reinstall-over, though not a lost
// phone, and the UI can say exactly that. It also means the relay is never
// anywhere near a backup, which `docs/BACKUP.md` states as an anti-goal
// rather than an omission.
//
// The folder sits beside the vault, and everything in it is already sealed
// under the recovery code — the archive key never touches this class. On
// iOS this directory must be excluded from iCloud backup along with the
// vault itself; see the iOS brief.

import 'dart:io';

import 'package:z_protocol/z_protocol.dart';

import 'archive.dart';
import 'file_export.dart';
import 'vault.dart';

/// One archive sitting in the app's backup folder.
class StoredBackup {
  final File file;
  final DateTime takenAt;
  final int bytes;
  const StoredBackup(this.file, this.takenAt, this.bytes);

  String get name => file.uri.pathSegments.last;
}

class BackupStore {
  /// Archives older than the newest [keep] are pruned after a successful
  /// write, so an automatic export cannot fill the device. One spare covers
  /// the case where the newest turns out to be unreadable.
  static const int keep = 2;

  static const String _prefix = 'z-backup-';
  static const String _ext = '.zbk';

  final Vault vault;
  final Directory dir;
  BackupStore._(this.vault, this.dir);

  static Future<BackupStore> open(Vault vault) async {
    final d = Directory('${vault.root.path}${Platform.pathSeparator}backups');
    if (!await d.exists()) await d.create(recursive: true);
    return BackupStore._(vault, d);
  }

  /// Streams a fresh archive into the backup folder and returns it. The file
  /// is built under a temporary name and renamed only once the terminator
  /// has been written, so a crash or a full disk leaves no half-archive that
  /// a later restore could mistake for a whole one.
  Future<StoredBackup> write({
    required RecoveryCode code,
    DateTime? now,
    void Function(ArchiveProgress)? onProgress,
  }) async {
    final at = now ?? DateTime.now();
    final stamp = '${at.year.toString().padLeft(4, '0')}'
        '${at.month.toString().padLeft(2, '0')}'
        '${at.day.toString().padLeft(2, '0')}-'
        '${at.hour.toString().padLeft(2, '0')}'
        '${at.minute.toString().padLeft(2, '0')}'
        '${at.second.toString().padLeft(2, '0')}';
    final partial = File('${dir.path}${Platform.pathSeparator}'
        '.$_prefix$stamp$_ext.partial');
    final target =
        File('${dir.path}${Platform.pathSeparator}$_prefix$stamp$_ext');

    final sink = partial.openWrite();
    try {
      await BackupArchive.export(
          vault: vault, code: code, out: sink, onProgress: onProgress);
      await sink.flush();
    } finally {
      await sink.close();
    }
    // Only now is it an archive.
    await partial.rename(target.path);
    await _prune();
    return StoredBackup(target, at, await target.length());
  }

  /// The archives on hand, newest first.
  ///
  /// Ordering comes from the stamp in the name, not from the file's mtime.
  /// Several archives can land inside one filesystem timestamp tick, and
  /// mtime is also whatever a restore or a file copy last set it to — and
  /// this order decides which archives [_prune] deletes, so getting it wrong
  /// loses the wrong backup. A name we cannot read falls back to mtime and
  /// sorts last rather than being dropped.
  Future<List<StoredBackup>> list() async {
    final out = <StoredBackup>[];
    if (!await dir.exists()) return out;
    await for (final e in dir.list()) {
      if (e is! File) continue;
      final n = e.uri.pathSegments.last;
      if (!n.startsWith(_prefix) || !n.endsWith(_ext)) continue;
      final st = await e.stat();
      out.add(StoredBackup(e, stampOf(n) ?? st.modified, st.size));
    }
    out.sort((a, b) => b.takenAt.compareTo(a.takenAt));
    return out;
  }

  /// `z-backup-YYYYMMDD-HHMMSS.zbk` -> when it was taken, or null if the
  /// name is not one of ours.
  static DateTime? stampOf(String fileName) {
    final m = RegExp(r'^' r'z-backup-' r'(\d{8})-(\d{6})' r'\.zbk$')
        .firstMatch(fileName);
    if (m == null) return null;
    final d = m.group(1)!, t = m.group(2)!;
    return DateTime.tryParse('${d.substring(0, 4)}-${d.substring(4, 6)}-'
        '${d.substring(6, 8)} ${t.substring(0, 2)}:${t.substring(2, 4)}:'
        '${t.substring(4, 6)}');
  }

  /// The most recent archive, or null if none has been taken.
  Future<StoredBackup?> latest() async {
    final all = await list();
    return all.isEmpty ? null : all.first;
  }

  Future<void> _prune() async {
    final all = await list();
    for (final old in all.skip(keep)) {
      try {
        await old.file.delete();
      } catch (_) {
        // A file we cannot delete is not worth failing a good backup over.
      }
    }
    // Abandoned partials from an interrupted run.
    if (await dir.exists()) {
      await for (final e in dir.list()) {
        if (e is File && e.uri.pathSegments.last.endsWith('.partial')) {
          try {
            if (DateTime.now().difference((await e.stat()).modified).inHours >
                1) {
              await e.delete();
            }
          } catch (_) {}
        }
      }
    }
  }

  /// Copies [backup] wherever the user chooses. Returns the destination, or
  /// null if they cancelled. Throws [SaveTooLargeException] when the
  /// platform's dialog cannot carry a file that size — the archive is still
  /// in the backup folder, which is what the caller should say.
  static Future<String?> handToUser(StoredBackup backup) =>
      FileExport.saveExistingFile(
        source: backup.file,
        dialogTitle: 'Save your Z backup',
        fileName: backup.name,
      );
}

/// Automatic re-export (9.5). Off by default, and off is the honest default:
/// a backup the user did not ask for is a copy of their history they did not
/// know existed.
///
/// **Where the recovery code lives, and why that is defensible.** An
/// automatic backup cannot stop to ask for a code, so turning this on stores
/// the code sealed in the vault. That is a real trade and worth stating
/// plainly: anyone who can open the vault can then also open every archive
/// this device wrote. But anyone who can open the vault already has the
/// plaintext history — the archive tells them nothing new. What the code
/// protects is the archive *once it has left the device*: on a memory stick,
/// in a sync folder, in someone's cloud storage. That threat is untouched by
/// keeping a copy behind the vault's own encryption.
///
/// The user is told this, can turn it off, and turning it off forgets the
/// stored code — after which automatic backups stop rather than silently
/// carrying on with a code nobody can produce.
class BackupSchedule {
  static const _kInterval = 'backup_interval_days';
  static const _kCode = 'backup_code';
  static const _kLast = 'backup_last_ms';

  final Vault vault;
  const BackupSchedule(this.vault);

  /// 0 means off.
  Future<int> intervalDays() async =>
      int.tryParse(await vault.kvGet(_kInterval) ?? '0') ?? 0;

  Future<DateTime?> lastRun() async {
    final ms = int.tryParse(await vault.kvGet(_kLast) ?? '');
    return ms == null ? null : DateTime.fromMillisecondsSinceEpoch(ms);
  }

  /// Turns automatic backup on, reusing the code the user has already
  /// written down. Storing it is what makes an unattended run possible.
  Future<void> enable({required RecoveryCode code, int everyDays = 7}) async {
    if (everyDays <= 0) throw ArgumentError('everyDays must be positive');
    await vault.kvPut(_kCode, b64(code.entropy));
    await vault.kvPut(_kInterval, '$everyDays', sensitive: false);
  }

  /// Turns it off and forgets the stored code.
  Future<void> disable() async {
    await vault.kvPut(_kInterval, '0', sensitive: false);
    await vault.kvDelete(_kCode);
  }

  Future<RecoveryCode?> storedCode() async {
    final raw = await vault.kvGet(_kCode);
    if (raw == null) return null;
    try {
      return RecoveryCode(unb64(raw));
    } catch (_) {
      return null;
    }
  }

  /// Whether a run is due at [now], given the interval and the last run.
  /// Pure, so the policy is testable without a clock or a vault.
  static bool isDue({
    required int intervalDays,
    required DateTime? lastRun,
    required DateTime now,
  }) {
    if (intervalDays <= 0) return false;
    if (lastRun == null) return true;
    return !now.isBefore(lastRun.add(Duration(days: intervalDays)));
  }

  /// Takes a backup if one is due. Returns it, or null if the schedule is
  /// off, not yet due, or the stored code has gone. Never throws for a
  /// missing code — a schedule that cannot run quietly does nothing rather
  /// than interrupting the app.
  Future<StoredBackup?> runIfDue(BackupStore store, {DateTime? now}) async {
    final at = now ?? DateTime.now();
    if (!isDue(
        intervalDays: await intervalDays(),
        lastRun: await lastRun(),
        now: at)) {
      return null;
    }
    final code = await storedCode();
    if (code == null) return null;
    final backup = await store.write(code: code, now: at);
    await vault.kvPut(_kLast, '${at.millisecondsSinceEpoch}', sensitive: false);
    return backup;
  }
}
