// Tests the local passphrase-unlock feature: setting a passphrase wraps the
// (unchanged) master key so all sealed data survives; the wrong passphrase is
// rejected; removing it restores automatic open. The passphrase never leaves
// the device — this is purely local vault protection.

import 'dart:io';

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
}
