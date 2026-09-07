// Phase 9.3: where a backup goes, and who writes it.
//
// The policy half is pure and is checked for EVERY platform from here,
// because the bug it replaces was invisible on the platform being tested and
// broken on the other four: the app passed `bytes` to the save dialog
// everywhere and then wrote again unless it was on Android, which throws on
// macOS (the plugin rejects bytes outright) and would have written twice on
// iOS.
@Tags(['integration'])
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/archive.dart';
import 'package:zapp/core/backup_store.dart';
import 'package:zapp/core/file_export.dart';
import 'package:zapp/core/vault.dart';
import 'package:z_protocol/z_protocol.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  final temps = <Directory>[];
  tearDownAll(() {
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<Directory> tempDir(String name) async {
    final d = await Directory.systemTemp.createTemp('z_bs_$name');
    temps.add(d);
    return d;
  }

  Future<Vault> seededVault(String name, {int messages = 3}) async {
    final v = await Vault.open(rootOverride: await tempDir(name));
    await v.kvPut(
        'identity', jsonEncode((await ZIdentity.generate()).toJson()));
    await v.kvPut('display_name', 'Keeper');
    for (var i = 0; i < messages; i++) {
      await v.db.insert('messages', {
        'mid': 'm$i',
        'rid': 'peer',
        'outgoing': i.isEven ? 1 : 0,
        'kind': 'text',
        'enc_body': await v.seal('message number $i'),
        'ts_ms': 1000 + i,
        'status': 1,
        'expire_at_ms': 0,
      });
    }
    return v;
  }

  group('save policy', () {
    test('every platform is driven the way its dialog expects', () {
      // Mobile: the picker writes and demands the bytes.
      for (final h in [HostPlatform.android, HostPlatform.ios]) {
        expect(saveStyleFor(h), SaveStyle.pickerWrites, reason: '$h');
      }
      // Desktop: the dialog only picks a path. macOS is in here and not with
      // the mobile pair — passing it bytes throws UnsupportedError.
      for (final h in [
        HostPlatform.linux,
        HostPlatform.macos,
        HostPlatform.windows
      ]) {
        expect(saveStyleFor(h), SaveStyle.callerWrites, reason: '$h');
      }
    });

    test(
        'bytes are passed to the picker on exactly the platforms that need '
        'them, and the file is written exactly once', () async {
      final dir = await tempDir('policy');
      for (final h in HostPlatform.values) {
        final target = File('${dir.path}/out-${h.name}.bin');
        if (await target.exists()) await target.delete();
        Uint8List? sawBytes;
        var calls = 0;
        final path = await FileExport.saveBytes(
          dialogTitle: 't',
          fileName: 'out-${h.name}.bin',
          bytes: Uint8List.fromList([1, 2, 3, 4]),
          on: h,
          picker: ({
            required String dialogTitle,
            required String fileName,
            Uint8List? bytes,
          }) async {
            calls++;
            sawBytes = bytes;
            // Stand in for the plugin: on mobile it writes them itself.
            if (bytes != null) await target.writeAsBytes(bytes, flush: true);
            return target.path;
          },
        );
        expect(calls, 1);
        expect(path, target.path);
        if (saveStyleFor(h) == SaveStyle.pickerWrites) {
          expect(sawBytes, isNotNull,
              reason: '$h requires bytes and throws without them');
        } else {
          expect(sawBytes, isNull,
              reason: '$h rejects bytes (macOS throws on them)');
        }
        // Either way the file exists once, with the right contents.
        expect(await target.readAsBytes(), [1, 2, 3, 4], reason: '$h');
      }
    });

    test('a cancelled dialog writes nothing', () async {
      final dir = await tempDir('cancel');
      final target = File('${dir.path}/never.bin');
      final path = await FileExport.saveBytes(
        dialogTitle: 't',
        fileName: 'never.bin',
        bytes: Uint8List.fromList([9]),
        on: HostPlatform.linux,
        picker: ({
          required String dialogTitle,
          required String fileName,
          Uint8List? bytes,
        }) async =>
            null,
      );
      expect(path, isNull);
      expect(await target.exists(), isFalse);
    });

    test('an oversized file is refused on mobile, not loaded', () {
      const big = FileExport.pickerMemoryLimitBytes + 1;
      expect(canSaveSizeOn(HostPlatform.android, big), isFalse);
      expect(canSaveSizeOn(HostPlatform.ios, big), isFalse);
      // Desktop streams, so size is not the dialog's problem.
      expect(canSaveSizeOn(HostPlatform.linux, big), isTrue);
      expect(canSaveSizeOn(HostPlatform.macos, big), isTrue);
    });

    test('handing over an existing file streams it on desktop', () async {
      final dir = await tempDir('stream');
      final source = File('${dir.path}/source.zbk')
        ..writeAsBytesSync(List<int>.generate(200000, (i) => i & 0xff));
      final target = File('${dir.path}/copy.zbk');
      final path = await FileExport.saveExistingFile(
        source: source,
        dialogTitle: 't',
        fileName: 'copy.zbk',
        on: HostPlatform.linux,
        picker: ({
          required String dialogTitle,
          required String fileName,
          Uint8List? bytes,
        }) async {
          expect(bytes, isNull, reason: 'a streamed copy never loads the file');
          return target.path;
        },
      );
      expect(path, target.path);
      expect(await target.readAsBytes(), await source.readAsBytes());
    });
  });

  group('backup store', () {
    test('an archive is written, listed and re-imported', () async {
      final vault = await seededVault('write');
      final store = await BackupStore.open(vault);
      expect(await store.latest(), isNull, reason: 'nothing taken yet');

      final code = await RecoveryCode.generate();
      final stages = <String>{};
      final backup =
          await store.write(code: code, onProgress: (p) => stages.add(p.stage));
      expect(await backup.file.exists(), isTrue);
      expect(backup.bytes, greaterThan(0));
      expect(backup.name, startsWith('z-backup-'));
      expect(backup.name, endsWith('.zbk'));
      expect(stages, contains('messages'));

      expect((await store.list()).length, 1);
      expect((await store.latest())!.name, backup.name);

      // It is a real archive: it restores.
      final fresh = await Vault.open(rootOverride: await tempDir('restore'));
      final summary = await BackupArchive.import(
          vault: fresh, file: backup.file, code: code);
      expect(summary.messages, 3);
      expect(await fresh.kvGet('display_name'), 'Keeper');
      await fresh.db.close();
      await vault.db.close();
    });

    test('a half-written archive is never mistaken for a backup', () async {
      final vault = await seededVault('partial');
      final store = await BackupStore.open(vault);
      // A crashed run leaves a dot-prefixed .partial behind.
      final junk =
          File('${store.dir.path}/.z-backup-20200101-000000.zbk.partial')
            ..writeAsStringSync('half an archive');
      expect(await junk.exists(), isTrue);
      expect(await store.list(), isEmpty,
          reason: 'a partial is not a backup and must not be offered as one');
      expect(await store.latest(), isNull);
      await vault.db.close();
    });

    test('old archives are pruned so an automatic export cannot fill the disk',
        () async {
      final vault = await seededVault('prune', messages: 1);
      final store = await BackupStore.open(vault);
      final code = await RecoveryCode.generate();
      final names = <String>[];
      for (var i = 0; i < BackupStore.keep + 2; i++) {
        final b =
            await store.write(code: code, now: DateTime(2026, 1, 1, 12, 0, i));
        names.add(b.name);
      }
      final left = await store.list();
      expect(left.length, BackupStore.keep);
      // The ones kept are the newest, and the newest of all is first.
      expect(left.map((b) => b.name).toSet(),
          names.reversed.take(BackupStore.keep).toSet());
      expect(left.first.name, names.last);
      await vault.db.close();
    });

    test('a schedule is off until asked, and forgets its code when turned off',
        () async {
      final vault = await seededVault('sched', messages: 1);
      final store = await BackupStore.open(vault);
      final sched = BackupSchedule(vault);
      final code = await RecoveryCode.generate();
      final t0 = DateTime(2026, 5, 1, 8);

      // Off by default: an unattended copy of someone's history is not
      // something to switch on for them.
      expect(await sched.intervalDays(), 0);
      expect(await sched.storedCode(), isNull);
      expect(await sched.runIfDue(store, now: t0), isNull);
      expect(await store.list(), isEmpty);

      await sched.enable(code: code, everyDays: 7);
      expect(await sched.intervalDays(), 7);
      expect((await sched.storedCode())!.entropy, code.entropy);

      // First run happens immediately; the next waits out the interval.
      final first = await sched.runIfDue(store, now: t0);
      expect(first, isNotNull);
      expect(await sched.runIfDue(store, now: t0.add(const Duration(days: 6))),
          isNull);
      final second =
          await sched.runIfDue(store, now: t0.add(const Duration(days: 7)));
      expect(second, isNotNull);
      expect(second!.name, isNot(first!.name));

      // Whatever it wrote opens with the code the user wrote down.
      final fresh = await Vault.open(rootOverride: await tempDir('sched_in'));
      expect(
          (await BackupArchive.import(
                  vault: fresh, file: second.file, code: code))
              .messages,
          1);
      await fresh.db.close();

      // Off means off, and the stored code goes with it — a schedule that
      // kept the code around after being disabled would be a copy nobody
      // asked for.
      await sched.disable();
      expect(await sched.intervalDays(), 0);
      expect(await sched.storedCode(), isNull);
      expect(await sched.runIfDue(store, now: t0.add(const Duration(days: 90))),
          isNull);
      await vault.db.close();
    });

    test('the due policy is exact at the boundary', () {
      final last = DateTime(2026, 1, 1, 12);
      expect(
          BackupSchedule.isDue(
              intervalDays: 0, lastRun: null, now: DateTime(2030)),
          isFalse,
          reason: 'off is off, even having never run');
      expect(
          BackupSchedule.isDue(
              intervalDays: 7, lastRun: null, now: DateTime(2026)),
          isTrue,
          reason: 'never run yet');
      expect(
          BackupSchedule.isDue(
              intervalDays: 7,
              lastRun: last,
              now: last
                  .add(const Duration(days: 7) - const Duration(seconds: 1))),
          isFalse);
      expect(
          BackupSchedule.isDue(
              intervalDays: 7,
              lastRun: last,
              now: last.add(const Duration(days: 7))),
          isTrue);
    });

    test('ordering survives archives sharing one filesystem timestamp',
        () async {
      final vault = await seededVault('sametick', messages: 1);
      final store = await BackupStore.open(vault);
      final code = await RecoveryCode.generate();
      final names = <String>[];
      for (var i = 0; i < BackupStore.keep + 2; i++) {
        names.add(
            (await store.write(code: code, now: DateTime(2026, 3, 4, 9, 30, i)))
                .name);
      }
      // Flatten every mtime to one value, which is what a coarse filesystem —
      // or a restore that rewrote the folder — leaves behind. The stamp in
      // the name is then the only thing that can order them, and getting it
      // wrong here deletes the newest backups instead of the oldest.
      final flat = DateTime(2020, 1, 1);
      for (final f in store.dir.listSync().whereType<File>()) {
        f.setLastModifiedSync(flat);
      }
      final left = await store.list();
      expect(left.map((b) => b.name).toList(),
          names.reversed.take(BackupStore.keep).toList());
      expect(BackupStore.stampOf(names.last), DateTime(2026, 3, 4, 9, 30, 3));
      expect(BackupStore.stampOf('not-ours.zbk'), isNull);
      expect(BackupStore.stampOf('z-backup-bad-stamp.zbk'), isNull);
      await vault.db.close();
    });
  });
}
