// A restore that holds the whole backup in memory.
//
// `BACKUP.md` has always had a row called Streaming, and it said: "Neither
// export nor import ever holds the archive, or a whole attachment, in
// memory." The format is built for that — frames, a nonce made unique by
// construction from the frame index, 256 KiB attachment pieces — and the
// export side does walk one attachment at a time.
//
// The import side accumulated every attachment in the archive in a
// `Map<String, BytesBuilder>` and wrote none of them until the terminator had
// been read. So a restore of a vault with two hundred photographs held two
// hundred photographs at once. The failure mode is the OS killing the app
// part-way through the one operation a person runs when they have already
// lost the device, and the bigger the history the likelier it is — the
// backups that matter most are the ones this handled worst.
//
// Attachment bytes now spill to a file each as their frames arrive, and are
// sealed into the vault one at a time afterwards. One at a time is the floor,
// not a choice: a blob is a single AEAD message at rest, so sealing one means
// holding one. The claim in `BACKUP.md` now says that instead of promising
// what the at-rest format cannot give.
//
// The measurement here is process RSS around the call, which is a blunt
// instrument — so the fixture is deliberately lopsided: 30 attachments of
// 2 MiB. The old code had to hold all 60 MiB (a `BytesBuilder` that has
// doubled its way there holds rather more); the new code holds one 2 MiB
// file. The yardstick is an EXPORT of the same vault, which has always
// walked one at a time, so there is no absolute constant here to go stale.
//
// How blunt: peak RSS growth is the live set PLUS whatever garbage the VM
// has not collected yet, and both directions stream the whole archive
// through the process — roughly twice its size in short-lived allocations —
// while holding one attachment. So the number is dominated by when the VM
// last grew its heap, not by what is held. Three CI runs of identical code
// reported export 39.1 / 57.2 / 32.6 MiB and import 30.6 / 29.0 / 58.1: the
// export, which is beyond doubt one-at-a-time, once measured 0.95 of the
// whole archive. Criterion 1 is therefore tagged `bench` — `dart_test.yaml`
// already says a measurement must not let a busy machine turn a number into
// a red build, and it is the behavioural criteria below that hold the line
// in CI. Run it with:
//
//     flutter test --run-skipped --tags bench test/restore_memory_test.dart
//
// Criteria, each a test below:
//  1. (bench) importing the archive does not grow the process by more than
//     exporting it does — the half this fix changed, measured;
//  2. the bytes are on disk while it happens and nowhere afterwards: every
//     attachment's bytes are in the spill directory during the import, the
//     directory is gone when the import returns, and gone when an import
//     throws part-way through. This is what a return to accumulating in
//     memory fails, and it does not depend on an instrument;
//  3. a failed import leaves nothing behind either;
//  4. every attachment still restores byte for byte, with its metadata, and
//     an archive of many is still one import;
//  5. what the spill holds while it runs is not the attachment: every frame
//     is sealed under a key that exists only for that restore, so the one
//     exit the `finally` cannot cover — the OS killing the app mid-restore,
//     which is the very case the spill exists for — leaves ciphertext under
//     a key that died with the process, not plaintext beside a database
//     whose whole point is that attachments are sealed (the 2026-09-14
//     review's finding 7);
//  6. and a spill a dead process left behind is removed when the vault next
//     opens, which until then nothing collected: the orphan sweep walked the
//     files directory, and the spill is beside it.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:zapp/core/archive.dart';
import 'package:zapp/core/vault.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  HttpOverrides.global = null;

  final temps = <Directory>[];

  tearDownAll(() {
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<Directory> tempDir(String name) async {
    final d = await Directory.systemTemp.createTemp('z_mem_$name');
    temps.add(d);
    return d;
  }

  const attachmentCount = 30;
  const attachmentBytes = 2 * 1024 * 1024; // 60 MiB in total

  String mib(int bytes) => (bytes / (1024 * 1024)).toStringAsFixed(1);
  String totalMiB() => mib(attachmentCount * attachmentBytes);

  /// A vault holding [attachmentCount] attachments and their messages, built
  /// directly: this is about bytes, and a relay would only add time.
  Future<Vault> stockedVault(String tag) async {
    final vault = await Vault.open(rootOverride: await tempDir(tag));
    await vault.kvPut('display_name', 'Restored');
    for (var i = 0; i < attachmentCount; i++) {
      final fid = b64url(randomBytes(12));
      final bytes = Uint8List.fromList(
          List<int>.generate(attachmentBytes, (j) => (i + j) % 251));
      final keyInfo = await vault.writeBlob(fid, bytes);
      await vault.db.insert('messages', {
        'mid': 'm$i',
        'rid': 'r1',
        'outgoing': 1,
        'kind': 'file',
        'enc_body': await vault.seal(jsonEncode({'fid': fid})),
        'fid': fid,
        'ts_ms': i,
        'status': 0,
      });
      await vault.db.insert('files', {
        'fid': fid,
        'rid': 'r1',
        'mid': 'm$i',
        'enc_meta': await vault.seal(jsonEncode({
          'name': 'photo-$i.jpg',
          'size': bytes.length,
          'mime': 'image/jpeg',
          'sha256': b64(await sha256Bytes(bytes)),
          'local': keyInfo,
        })),
        'complete': 1,
        'got_chunks': 1,
        'total_chunks': 1,
      });
    }
    return vault;
  }

  /// Peak RSS growth over [body], sampled while it runs. Every frame is an
  /// await, so a periodic timer gets to look in between.
  Future<int> peakGrowth(Future<void> Function() body) async {
    // Settle first: the fixture above has just churned 80 MiB.
    await Future<void>.delayed(const Duration(milliseconds: 400));
    final base = ProcessInfo.currentRss;
    var peak = base;
    final ticker = Stream<void>.periodic(const Duration(milliseconds: 15))
        .listen((_) {
      final rss = ProcessInfo.currentRss;
      if (rss > peak) peak = rss;
    });
    await body();
    await ticker.cancel();
    final after = ProcessInfo.currentRss;
    if (after > peak) peak = after;
    return peak - base;
  }

  Future<(File, RecoveryCode)> archiveOf(Vault vault, String tag) async {
    final code = await RecoveryCode.generate();
    final file = File('${(await tempDir(tag)).path}/big.zbk');
    final sink = file.openWrite();
    await BackupArchive.export(vault: vault, code: code, out: sink);
    await sink.close();
    return (file, code);
  }

  const long = Timeout(Duration(minutes: 6));

  test('1. an import costs what an export costs, not what the archive weighs',
      () async {
    final source = await stockedVault('src1');
    final code = await RecoveryCode.generate();
    final file = File('${(await tempDir('arc1')).path}/big.zbk');
    late int written;
    // Export is the yardstick. It has always walked one attachment at a time,
    // so whatever this machine's instrument reports for it is the cost of
    // "one at a time" HERE -- no absolute constant to go stale, and no
    // assumption about how promptly a garbage collector returns pages.
    final exportGrew = await peakGrowth(() async {
      final sink = file.openWrite();
      written = await BackupArchive.export(
          vault: source, code: code, out: sink);
      await sink.close();
    });
    expect(written, greaterThan(attachmentCount));
    await source.db.close();
    expect(await file.length(), greaterThan(attachmentCount * attachmentBytes),
        reason: 'the fixture really is ${totalMiB()} MiB of attachments');

    final fresh = await Vault.open(rootOverride: await tempDir('dst1'));
    late ArchiveSummary summary;
    final importGrew = await peakGrowth(() async {
      summary =
          await BackupArchive.import(vault: fresh, file: file, code: code);
    });
    expect(summary.attachments, attachmentCount);
    // Printed whether it passes or not: when a bound like this does fail,
    // the two numbers are the whole diagnosis.
    // ignore: avoid_print
    print('peak RSS growth: export ${mib(exportGrew)} MiB, '
        'import ${mib(importGrew)} MiB, archive ${totalMiB()} MiB');
    expect(importGrew, lessThan(exportGrew),
        reason: 'import grew ${mib(importGrew)} MiB against export\'s '
            '${mib(exportGrew)}. Measured on a quiet box: 0.49 and 0.72 of '
            'the export with the fix, 1.5 with the attachments accumulated '
            'in memory instead. On a busy one either figure can reach the '
            'archive size on its own — see the note at the top of this '
            'file before reading a ratio as a regression');
    expect(importGrew, lessThan(attachmentCount * attachmentBytes),
        reason: 'and nothing like the ${totalMiB()} MiB in the archive: '
            '${mib(importGrew)} MiB. Accumulating them measured 0.98 of the '
            'archive');
    await fresh.db.close();
    // A measurement, not an assertion about behaviour: skipped by default,
    // like every other `bench` in this suite. Criterion 2 is the one that
    // fails if the attachments go back into memory.
  }, timeout: long, tags: ['bench']);

  test('2. the bytes are on disk while it happens, and gone when it is done',
      () async {
    final source = await stockedVault('src2');
    final (file, code) = await archiveOf(source, 'arc2');
    await source.db.close();

    final dir = await tempDir('dst2');
    final fresh = await Vault.open(rootOverride: dir);
    final spill = Directory('${dir.path}/restore-spill');
    var sawSpilled = 0;
    final ticker =
        Stream<void>.periodic(const Duration(milliseconds: 10)).listen((_) {
      if (!spill.existsSync()) return;
      final n = spill
          .listSync()
          .whereType<File>()
          .where((f) => f.lengthSync() > 0)
          .length;
      if (n > sawSpilled) sawSpilled = n;
    });
    await BackupArchive.import(vault: fresh, file: file, code: code);
    await ticker.cancel();

    expect(sawSpilled, attachmentCount,
        reason: 'every attachment\'s bytes were written to disk as they '
            'arrived, not accumulated in the process: the spill directory '
            'holds all $attachmentCount of them at once while the import '
            'seals them one at a time, and held $sawSpilled');
    expect(spill.existsSync(), isFalse,
        reason: 'and the spill directory does not outlive the import');
    expect(
        Directory(fresh.filesDir.path)
            .listSync()
            .whereType<File>()
            .length,
        attachmentCount,
        reason: 'while every blob is where blobs go');
    await fresh.db.close();
  }, timeout: long);

  test('3. a failed import leaves nothing behind either', () async {
    final source = await stockedVault('src3');
    final (file, code) = await archiveOf(source, 'arc3');
    await source.db.close();

    // Truncated well past the first attachments, so the import throws with
    // bytes already spilled. An archive's attachments left in a directory of
    // their own, outside the vault's `files/`, would be the same leak by
    // another route -- and one nothing would ever collect.
    final whole = await file.readAsBytes();
    final cut = File('${(await tempDir('arc3b')).path}/cut.zbk');
    await cut.writeAsBytes(whole.sublist(0, (whole.length * 2) ~/ 3));
    final dir = await tempDir('dst3');
    final doomed = await Vault.open(rootOverride: dir);
    await expectLater(BackupArchive.import(vault: doomed, file: cut, code: code),
        throwsA(isA<Exception>()));
    expect(Directory('${dir.path}/restore-spill').existsSync(), isFalse);
    await doomed.db.close();
  }, timeout: long);

  test('4. and every attachment comes back, byte for byte', () async {
    final source = await stockedVault('src4');
    final originals = <String, Uint8List>{};
    final names = <String, String>{};
    for (final r in await source.db.query('files')) {
      final fid = r['fid'] as String;
      final meta = (jsonDecode(await source.unseal(r['enc_meta'] as String))
          as Map).cast<String, Object?>();
      names[fid] = meta['name'] as String;
      originals[fid] = await source.readBlob(
          fid, (meta['local'] as Map).cast<String, Object?>());
    }
    final (file, code) = await archiveOf(source, 'arc4');
    await source.db.close();

    final fresh = await Vault.open(rootOverride: await tempDir('dst4'));
    final summary =
        await BackupArchive.import(vault: fresh, file: file, code: code);
    expect(summary.attachments, attachmentCount);
    final rows = await fresh.db.query('files');
    expect(rows, hasLength(attachmentCount));
    for (final r in rows) {
      final fid = r['fid'] as String;
      final meta = (jsonDecode(await fresh.unseal(r['enc_meta'] as String))
          as Map).cast<String, Object?>();
      expect(meta['name'], names[fid]);
      final back = await fresh.readBlob(
          fid, (meta['local'] as Map).cast<String, Object?>());
      expect(back, equals(originals[fid]), reason: '$fid came back different');
    }
    await fresh.db.close();
  }, timeout: long);

  /// True when [bytes] holds a 64-byte run of consecutive values mod 251 —
  /// the shape every stocked attachment has (`(i + j) % 251`), and the shape
  /// nothing sealed has.
  bool looksLikeAnAttachment(List<int> bytes) {
    var run = 0;
    for (var n = 1; n < bytes.length; n++) {
      run = bytes[n] == (bytes[n - 1] + 1) % 251 ? run + 1 : 0;
      if (run >= 64) return true;
    }
    return false;
  }

  test('5. the spill holds ciphertext, not the attachment', () async {
    // The detector is real: an attachment's own shape trips it, random
    // bytes do not.
    expect(looksLikeAnAttachment(List<int>.generate(8192, (j) => (3 + j) % 251)), isTrue);
    expect(looksLikeAnAttachment(randomBytes(8192)), isFalse);

    final source = await stockedVault('src5');
    final (file, code) = await archiveOf(source, 'arc5');
    await source.db.close();

    final dir = await tempDir('dst5');
    final fresh = await Vault.open(rootOverride: dir);
    final spill = Directory('${dir.path}/restore-spill');
    var looked = 0;
    var clear = 0;
    final ticker =
        Stream<void>.periodic(const Duration(milliseconds: 10)).listen((_) {
      if (!spill.existsSync()) return;
      for (final f in spill.listSync().whereType<File>()) {
        try {
          final len = f.lengthSync();
          if (len < 4096) continue;
          final raf = f.openSync();
          final head = raf.readSync(4096);
          raf.closeSync();
          looked++;
          if (looksLikeAnAttachment(head)) clear++;
        } catch (_) {}
      }
    });
    await BackupArchive.import(vault: fresh, file: file, code: code);
    await ticker.cancel();
    expect(looked, greaterThan(0), reason: 'the spill was looked at while it was there');
    expect(clear, 0,
        reason: 'of $looked looks at spill files during the import, $clear '
            'showed the attachment in the clear');
    expect(spill.existsSync(), isFalse);
    // And what was sealed on the way in is whole on the way out.
    expect((await fresh.db.query('files')).length, attachmentCount);
    await fresh.db.close();
  }, timeout: long);

  test('6. a spill a dead process left behind goes when the vault next opens',
      () async {
    final dir = await tempDir('dst6');
    final first = await Vault.open(rootOverride: dir);
    await first.db.close();
    // What a restore killed mid-way leaves: the directory, with files in it.
    final spill = Directory('${dir.path}/restore-spill')..createSync();
    File('${spill.path}/${b64url(randomBytes(12))}').writeAsBytesSync(randomBytes(65536));
    File('${spill.path}/${b64url(randomBytes(12))}').writeAsBytesSync(randomBytes(4096));
    expect(spill.listSync().length, 2);

    final again = await Vault.open(rootOverride: dir);
    expect(spill.existsSync(), isFalse,
        reason: 'the vault swept the spill on opening, files and directory');
    await again.db.close();
  }, timeout: long);
}
