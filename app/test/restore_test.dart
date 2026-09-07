// Phase 9.4: one restore path for both backup artifacts.
//
// A user who has lost a phone should not have to know whether the file they
// kept is a `.zbk` archive or the older `.zid` identity backup, nor which
// secret goes with which. They pick a file; the app identifies it and asks
// for the right thing. Identification must cost no key derivation, because
// guessing wrong would mean running Argon2id against the wrong secret and
// then reporting a failure that cannot say what actually went wrong.
@Tags(['integration'])
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/backup.dart';
import 'package:zapp/core/backup_store.dart';
import 'package:zapp/core/restore.dart';
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

  Future<Directory> tempDir(String n) async {
    final d = await Directory.systemTemp.createTemp('z_rs_$n');
    temps.add(d);
    return d;
  }

  Future<Vault> emptyVault(String n) async =>
      Vault.open(rootOverride: await tempDir(n));

  test('a .zbk is identified, previewed and restored with its code', () async {
    final source = await emptyVault('src');
    final id = await ZIdentity.generate();
    await source.kvPut('identity', jsonEncode(id.toJson()));
    await source.kvPut('display_name', 'Archived');
    await source.db.insert('messages', {
      'mid': 'm1',
      'rid': 'peer',
      'outgoing': 0,
      'kind': 'text',
      'enc_body': await source.seal('history worth keeping'),
      'ts_ms': 5000,
      'status': 2,
      'expire_at_ms': 0,
    });
    final store = await BackupStore.open(source);
    final code = await RecoveryCode.generate();
    final backup = await store.write(code: code);
    await source.db.close();

    // Identified without deriving anything, and it knows what it carries.
    final preview = await Restore.identify(backup.file);
    expect(preview.kind, BackupKind.archive);
    expect(preview.carriesHistory, isTrue);
    expect(preview.schema, greaterThan(0));
    expect(preview.takenAt, isNotNull);

    final target = await emptyVault('dst');
    final summary = await Restore.run(
      vault: target,
      file: backup.file,
      secret: await code.format(), // the grouped form the user reads out
      kind: preview.kind,
      serverUrl: 'wss://relay.example',
    );
    expect(summary.kind, BackupKind.archive);
    expect(summary.messages, 1);
    expect(await target.kvGet('display_name'), 'Archived');
    expect(await target.kvGet('server_url'), 'wss://relay.example');
    await target.db.close();
  });

  test('a .zid is still identified and restored with its passphrase', () async {
    // The old artifact keeps working: folding it into .zbk means Z stops
    // writing one, not that it stops reading one.
    final id = await ZIdentity.generate();
    final friend = await ZIdentity.generate();
    final bytes = await BackupFile.export(
      identity: id,
      displayName: 'Legacy',
      contactRecords: [
        {
          'bundle': (await friend.bundle(displayName: 'Friend')).toJson(),
          'name': 'Friend',
          'ttl': 0,
          'verified': true,
        }
      ],
      passphrase: 'correct horse battery staple',
    );
    final dir = await tempDir('zid');
    final file = File('${dir.path}/my-identity.zid')..writeAsBytesSync(bytes);

    final preview = await Restore.identify(file);
    expect(preview.kind, BackupKind.legacyIdentity);
    expect(preview.carriesHistory, isFalse,
        reason: 'the UI must be able to warn that messages are not in there');

    final vault = await emptyVault('zid_in');
    final summary = await Restore.run(
      vault: vault,
      file: file,
      secret: 'correct horse battery staple',
      kind: preview.kind,
    );
    expect(summary.kind, BackupKind.legacyIdentity);
    expect(summary.contacts, 1);
    expect(summary.messages, 0);
    expect(await vault.kvGet('display_name'), 'Legacy');
    expect((await vault.db.query('contacts')).length, 1);
    await vault.db.close();
  });

  test('a file that is not a backup is named as such, not mis-decrypted',
      () async {
    final dir = await tempDir('junk');
    for (final (name, bytes) in [
      ('photo.jpg', Uint8List.fromList([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10])),
      ('empty.zbk', Uint8List(0)),
      ('text.zbk', Uint8List.fromList(utf8.encode('not json at all'))),
      ('other.json', Uint8List.fromList(utf8.encode('{"z":"something-else"}'))),
    ]) {
      final f = File('${dir.path}/$name')..writeAsBytesSync(bytes);
      expect((await Restore.identify(f)).kind, BackupKind.unknown,
          reason: name);
    }
    final vault = await emptyVault('junk_in');
    await expectLater(
        Restore.run(
            vault: vault,
            file: File('${dir.path}/photo.jpg'),
            secret: 'anything',
            kind: BackupKind.unknown),
        throwsA(isA<FormatException>()));
    await vault.db.close();
  });

  test('a mistyped recovery code is caught before the KDF runs', () async {
    final source = await emptyVault('typo_src');
    await source.kvPut(
        'identity', jsonEncode((await ZIdentity.generate()).toJson()));
    final store = await BackupStore.open(source);
    final code = await RecoveryCode.generate();
    final backup = await store.write(code: code);
    await source.db.close();

    // Bend one character into one the checksum actually rejects. Picking a
    // replacement blindly would be flaky: roughly one substitution in 32
    // lands on a valid checksum by chance, and that one fails later, at the
    // archive's tag, instead of here.
    final typed = await code.format();
    final i = typed.length - 2; // a data character, not the checksum itself
    String? wrong;
    for (final c in RecoveryCode.alphabet.split('')) {
      if (c == typed[i]) continue;
      final candidate = typed.replaceRange(i, i + 1, c);
      try {
        await RecoveryCode.parse(candidate);
      } on FormatException {
        wrong = candidate;
        break;
      }
    }
    expect(wrong, isNotNull, reason: 'the checksum rejects some substitution');
    final vault = await emptyVault('typo_in');
    final began = DateTime.now();
    await expectLater(
        Restore.run(
            vault: vault,
            file: backup.file,
            secret: wrong!,
            kind: BackupKind.archive),
        throwsA(isA<FormatException>()));
    expect(DateTime.now().difference(began).inMilliseconds, lessThan(400),
        reason: 'Argon2id never ran');
    // Nothing was written on the way to failing.
    expect(await vault.db.query('messages'), isEmpty);
    await vault.db.close();
  });
}
