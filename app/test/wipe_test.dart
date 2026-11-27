// "Wipe everything" left the key that unlocks the vault behind, and said it
// had not.
//
// Three things were wrong, and each looks like it works:
//
//   * the storage handle was built without
//     `AndroidOptions(encryptedSharedPreferences: true)`, which every write
//     site passes. Under flutter_secure_storage 9.x that is a different
//     backing store, so the delete asked the wrong place and succeeded at
//     finding nothing there;
//   * `z_bio_passkey` — the raw Argon2id output of the user's passphrase,
//     which is what unlocks the vault — was written by `AppLock` and deleted
//     by nothing, along with the Keystore alias that seals it;
//   * and the overwrite and the delete shared one `try`, so a file whose
//     overwrite failed was never deleted either. Every per-file failure was
//     swallowed, `wipe()` returned normally, and the screen then called
//     `exit(0)` — so a `z.db` that could not be removed was left on disk
//     while the user had been told the device was clean.
//
// What is asserted below:
//   1. every key the app writes to secure storage is named by the wipe —
//      asserted against the writers rather than against a copy of the list,
//      since a list that has to be kept in step by hand is the bug;
//   2. the vault's own directory is gone, files and all;
//   3. a file that cannot be removed makes the wipe THROW rather than return,
//      because the caller ends the process on the strength of it returning;
//   4. and a file whose overwrite fails is still deleted.

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/app_lock.dart';
import 'package:zapp/core/vault.dart';

/// Makes [f] impossible to remove for this process, or says why it cannot.
/// Returns null when it is pinned.
String? _pin(File f, Directory dir) {
  try {
    final r = Process.runSync('chattr', ['+i', f.path]);
    if (r.exitCode == 0) return null;
  } on ProcessException {
    // No chattr here; fall through to the directory permission below.
  }
  final id = Process.runSync('id', ['-u']);
  if (id.exitCode == 0 && id.stdout.toString().trim() != '0') {
    final c = Process.runSync('chmod', ['500', dir.path]);
    if (c.exitCode == 0) return null;
  }
  return 'neither chattr +i nor a read-only directory can pin a file here '
      '(no chattr, or running as root)';
}

void _unpin(File f, Directory dir) {
  try {
    Process.runSync('chattr', ['-i', f.path]);
  } on ProcessException {
    // Nothing was set.
  }
  try {
    Process.runSync('chmod', ['700', dir.path]);
  } catch (_) {}
}

void main() {
  final temps = <Directory>[];
  tearDown(() {
    for (final d in temps) {
      try {
        if (d.existsSync()) d.deleteSync(recursive: true);
      } catch (_) {}
    }
    temps.clear();
  });

  Future<Vault> openVault(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_wipe_$name');
    temps.add(dir);
    return Vault.open(rootOverride: dir);
  }

  test('1. every key a writer puts in secure storage is named by the wipe',
      () {
    // The list is what the wipe deletes; these are the keys the app writes.
    // `z_bio_passkey` was the one that went missing, so the check is that no
    // writer has a key the wipe does not know about — not that the list
    // matches a second copy of itself.
    expect(Vault.secretStorageKeys, contains(AppLock.passKeyStorageKey),
        reason: "AppLock's pass key must be destroyed by a wipe");
    expect(Vault.secretStorageKeys, contains('z_device_secret'));
    expect(Vault.secretStorageKeys, contains('z_master_key'));

    // And every `z_`-prefixed literal passed to secure storage anywhere in
    // the app appears in the list. Source inspection, because the alternative
    // is remembering.
    final src = [
      File('lib/core/vault.dart').readAsStringSync(),
      File('lib/core/app_lock.dart').readAsStringSync(),
    ].join('\n');
    final keys = RegExp(r"'(z_[a-z0-9_]+)'")
        .allMatches(src)
        .map((m) => m.group(1)!)
        .toSet();
    for (final k in keys) {
      expect(Vault.secretStorageKeys, contains(k),
          reason: '$k is written somewhere and the wipe does not name it');
    }
  });

  test('2. the vault directory is gone, files and all', () async {
    final v = await openVault('gone');
    final root = v.root;
    await v.kvPut('dev_mode', '1', sensitive: false);
    final blob = File('${root.path}/files/keepme.bin')
      ..createSync(recursive: true)
      ..writeAsBytesSync(List<int>.filled(4096, 7));
    expect(blob.existsSync(), isTrue);

    await v.wipe();
    expect(root.existsSync(), isFalse, reason: 'the whole directory went');
    expect(blob.existsSync(), isFalse);
  });

  test('3. a wipe that leaves something behind throws', () async {
    final v = await openVault('stuck');
    final root = v.root;
    await v.kvPut('dev_mode', '1', sensitive: false);

    // A file the process may not remove. As root `chmod` is not enough — root
    // ignores it — so the immutable attribute, which even root is refused.
    // Where there is no `chattr` (a minimal image raises ProcessException
    // rather than returning a non-zero exit) and the user is not root, a
    // directory it cannot write to does the same job: the file inside can be
    // overwritten but not unlinked, which is the situation the wipe has to
    // report.
    final stuck = File('${root.path}/files/immutable.bin')
      ..createSync(recursive: true)
      ..writeAsBytesSync([1, 2, 3]);
    final dir = stuck.parent;
    final String? why = _pin(stuck, dir);
    addTearDown(() {
      _unpin(stuck, dir);
    });

    if (why != null) {
      // Nothing to prove the assertion against on this filesystem; say so
      // rather than passing a test that exercised nothing.
      markTestSkipped(why);
      return;
    }

    await expectLater(v.wipe(), throwsA(isA<StateError>()),
        reason: 'the caller exits the process on the strength of this');
    expect(root.existsSync(), isTrue, reason: 'and it is honest about why');
    expect(stuck.existsSync(), isTrue);
  }, skip: Platform.isWindows ? 'chattr' : null);

  test('4. a read-only file is removed rather than left behind', () async {
    final v = await openVault('ro');
    final root = v.root;
    await v.kvPut('dev_mode', '1', sensitive: false);
    final f = File('${root.path}/files/readonly.bin')
      ..createSync(recursive: true)
      ..writeAsBytesSync(List<int>.filled(64, 9));
    Process.runSync('chmod', ['400', f.path]);

    await v.wipe();
    expect(root.existsSync(), isFalse, reason: 'it all went anyway');

    // Worth being exact about what this does and does not measure. The code
    // puts the shredding overwrite and the delete in SEPARATE `try` blocks,
    // because sharing one meant a file whose overwrite failed was never
    // deleted — the worst case, since it is exactly the file something else
    // is holding open. Provoking that needs a write to fail while a delete
    // succeeds, and neither this sandbox nor CI can: both run as root, which
    // ignores the read-only bit, and the immutable attribute (criterion 3)
    // refuses the delete as well. So the separation is reasoned from the
    // failure mode rather than measured here, and removing it does not fail
    // this test — which is why the comment says so instead of the test
    // implying otherwise.
  }, skip: Platform.isWindows ? 'chmod' : null);
}
