// Tests the local passphrase-unlock feature: setting a passphrase wraps the
// (unchanged) master key so all sealed data survives; the wrong passphrase is
// rejected; removing it restores automatic open. The passphrase never leaves
// the device — this is purely local vault protection.

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/vault.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('passphrase set / lock / wrong / correct / change / remove round-trip',
      () async {
    final dir = await Directory.systemTemp.createTemp('zvault');
    const secret = '{"identity":"top-secret-seed"}';
    const pass = 'correct horse battery staple';

    // Fresh vault: no passphrase, opens automatically. Write sealed data.
    var v = await Vault.open(rootOverride: dir);
    expect(v.hasPassphrase, isFalse);
    await v.kvPut('identity', secret);
    expect(await v.kvGet('identity'), secret);

    // Turn on a passphrase, then close.
    await v.setPassphrase(pass);
    expect(v.hasPassphrase, isTrue);
    await v.db.close();

    // Inspect reports it's locked.
    final st = await Vault.inspect(rootOverride: dir);
    expect(st.exists, isTrue);
    expect(st.requiresPassphrase, isTrue);

    // Opening with no passphrase / a wrong one fails cleanly.
    await expectLater(
        Vault.open(rootOverride: dir), throwsA(isA<VaultLockedException>()));
    await expectLater(Vault.open(rootOverride: dir, passphrase: 'nope'),
        throwsA(isA<WrongPassphraseException>()));

    // Correct passphrase unlocks and the sealed data is intact.
    v = await Vault.open(rootOverride: dir, passphrase: pass);
    expect(await v.kvGet('identity'), secret);
    expect(await v.verifyPassphrase(pass), isTrue);
    expect(await v.verifyPassphrase('wrong'), isFalse);

    // Change the passphrase; old one no longer works.
    const pass2 = 'a different much longer passphrase';
    await v.setPassphrase(pass2);
    await v.db.close();
    await expectLater(Vault.open(rootOverride: dir, passphrase: pass),
        throwsA(isA<WrongPassphraseException>()));
    v = await Vault.open(rootOverride: dir, passphrase: pass2);
    expect(await v.kvGet('identity'), secret);

    // Remove the passphrase; the vault opens automatically again, data intact.
    await v.removePassphrase();
    await v.db.close();
    final st2 = await Vault.inspect(rootOverride: dir);
    expect(st2.requiresPassphrase, isFalse);
    v = await Vault.open(rootOverride: dir);
    expect(await v.kvGet('identity'), secret);
    await v.db.close();

    await dir.delete(recursive: true);
  });

  // 7.8 biometric unlock: the Argon2id output ("pass key") for the current
  // passphrase opens the vault without the passphrase; it is bound to the
  // salt, so it stops working the moment the passphrase changes.
  test('pass key opens a passphrase vault; wrong or stale keys are rejected',
      () async {
    final dir = await Directory.systemTemp.createTemp('zvault_pk');
    const secret = '{"identity":"pk-seed"}';
    const pass = 'correct horse battery staple';

    var v = await Vault.open(rootOverride: dir);
    await v.kvPut('identity', secret);
    // No passphrase yet: nothing to derive.
    await expectLater(v.passKeyFor(pass), throwsA(isA<StateError>()));

    await v.setPassphrase(pass);
    // A wrong passphrase does not yield a key at all.
    await expectLater(
        v.passKeyFor('wrong'), throwsA(isA<WrongPassphraseException>()));
    final pk = await v.passKeyFor(pass);
    expect(pk.length, 32);
    // Deterministic for the same passphrase + salt.
    expect(await v.passKeyFor(pass), pk);
    await v.db.close();

    // The pass key alone (no passphrase) opens the vault, data intact.
    v = await Vault.open(rootOverride: dir, passKey: pk);
    expect(v.hasPassphrase, isTrue);
    expect(await v.kvGet('identity'), secret);
    await v.db.close();

    // A garbage key fails exactly like a wrong passphrase.
    final bad = Uint8List.fromList(List<int>.generate(32, (i) => i));
    await expectLater(Vault.open(rootOverride: dir, passKey: bad),
        throwsA(isA<WrongPassphraseException>()));

    // Changing the passphrase (new salt) invalidates the old pass key …
    v = await Vault.open(rootOverride: dir, passphrase: pass);
    const pass2 = 'a different much longer passphrase';
    await v.setPassphrase(pass2);
    final pk2 = await v.passKeyFor(pass2);
    expect(pk2, isNot(pk));
    await v.db.close();
    await expectLater(Vault.open(rootOverride: dir, passKey: pk),
        throwsA(isA<WrongPassphraseException>()));
    // … and the freshly derived one works.
    v = await Vault.open(rootOverride: dir, passKey: pk2);
    expect(await v.kvGet('identity'), secret);

    // With the passphrase removed a leftover pass key is simply ignored.
    await v.removePassphrase();
    await v.db.close();
    v = await Vault.open(rootOverride: dir, passKey: pk2);
    expect(v.hasPassphrase, isFalse);
    expect(await v.kvGet('identity'), secret);
    await v.db.close();

    await dir.delete(recursive: true);
  });
}
