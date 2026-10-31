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

    // Until 2026-10-31 the temporary file was opened before the archive was,
    // outside anything that would catch it: a folder that could not be
    // written failed with nothing listening, an uncaught error beside the
    // one the caller got, and a write that failed part-way left its
    // `.partial`. Here the folder is a file.
    test('a backup into a folder that cannot be written fails to its caller, '
        'and leaves nothing behind', () async {
      final vault = await seededVault('unwritable', messages: 1);
      final store = await BackupStore.open(vault);
      await store.dir.delete(recursive: true);
      await File(store.dir.path).writeAsString('not a folder');
      await expectLater(store.write(code: await RecoveryCode.generate()),
          throwsA(isA<FileSystemException>()),
          reason: 'the failure reaches the caller, and only the caller');
      expect(await File(store.dir.path).readAsString(), 'not a folder',
          reason: 'nothing was written in its place');
      await vault.db.close();
    });

    test('a backup that fails part-way leaves no partial file, and the '
        'archives already there as they were', () async {
      final vault = await seededVault('partway', messages: 2);
      final store = await BackupStore.open(vault);
      final code = await RecoveryCode.generate();
      final kept =
          await store.write(code: code, now: DateTime(2026, 1, 1, 12, 0, 0));
      final bytes = await kept.file.readAsBytes();
      // The store cannot be read from here: the archive's export fails.
      await vault.db.close();
      await expectLater(store.write(code: code), throwsA(anything));
      final left = [
        await for (final e in store.dir.list()) e.uri.pathSegments.last
      ];
      expect(left, [kept.name],
          reason: 'no .partial left, and the archive already there kept');
      expect(await kept.file.readAsBytes(), bytes,
          reason: 'its bytes as they were');
    });

    // /dev/full refuses every write with "no space left on device", as a
    // full disk does, and the next backup's temporary file is made a link to
    // it. Until 2026-10-31 a write the disk refused was reported only where
    // nothing listened, an uncaught error, and the backup then waited for
    // ever. The link stays: Dart's File.delete will not remove a link to a
    // device, and a temporary file on a real disk is a file, which the test
    // before this one sees removed.
    test('a backup onto a full disk fails to its caller, and makes no archive',
        () async {
      final vault = await seededVault('full', messages: 2);
      final store = await BackupStore.open(vault);
      final code = await RecoveryCode.generate();
      final kept =
          await store.write(code: code, now: DateTime(2026, 1, 1, 12, 0, 0));
      final bytes = await kept.file.readAsBytes();
      const link = '.z-backup-20260101-120001.zbk.partial';
      await Link('${store.dir.path}${Platform.pathSeparator}$link')
          .create('/dev/full');
      await expectLater(
          store.write(code: code, now: DateTime(2026, 1, 1, 12, 0, 1)),
          throwsA(isA<FileSystemException>().having(
              (e) => e.osError?.errorCode, 'errno', 28)),
          reason: 'the disk\'s refusal reaches the caller');
      final left = [
        await for (final e in store.dir.list()) e.uri.pathSegments.last
      ]..sort();
      expect(left, [link, kept.name]..sort(),
          reason: 'no archive made, and the one already there kept');
      expect(await kept.file.readAsBytes(), bytes,
          reason: 'its bytes as they were');
      await vault.db.close();
    },
        skip: File('/dev/full').existsSync() ? null : 'no /dev/full here',
        timeout: const Timeout(Duration(seconds: 60)));

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

    test(
        'a schedule the store refuses part-way stays as it was, off with no '
        'code or on with its code', () async {
      final vault = await seededVault('sched_refused', messages: 1);
      final sched = BackupSchedule(vault);
      final code = await RecoveryCode.generate();

      // Turning on: the code is stored, and then the store refuses the
      // interval that would turn the schedule on.
      await vault.db.execute("CREATE TRIGGER refuse_on BEFORE INSERT ON kv "
          "WHEN NEW.k = 'p:backup_interval_days' "
          "BEGIN SELECT RAISE(ABORT, 'refused'); END");
      await expectLater(
          sched.enable(code: code, everyDays: 7), throwsA(isA<Exception>()));
      expect(await sched.intervalDays(), 0);
      // Off holds no code: the one stored on the way is taken out again.
      expect(await sched.storedCode(), isNull);
      await vault.db.execute('DROP TRIGGER refuse_on');

      // Turning off: the interval is set to off, and then the store refuses
      // to forget the code.
      await sched.enable(code: code, everyDays: 7);
      await vault.db.execute("CREATE TRIGGER refuse_off BEFORE DELETE ON kv "
          "WHEN OLD.k = 's:backup_code' "
          "BEGIN SELECT RAISE(ABORT, 'refused'); END");
      await expectLater(sched.disable(), throwsA(isA<Exception>()));
      // Still on, with its code, as the screen goes on saying: not off with
      // a code kept that the screen has said nothing about.
      expect(await sched.intervalDays(), 7);
      expect((await sched.storedCode())!.entropy, code.entropy);
      await vault.db.execute('DROP TRIGGER refuse_off');
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
