// ADR 0027 (PROTOCOL §18.10): a contact code signs its post-quantum
// commitment.
//
// Until it did, nothing in a code covered `pqc`: the binding signature is
// over the X25519 key, the certificate over the device. Anyone holding a
// person's PUBLIC code — everyone they ever gave it to — could write a
// different commitment into it, and the code still decoded and verified. The
// signature is an optional member, so every build in the field still reads
// the code, and its absence is what every code issued before looks like.
//
// Criteria, each a test below:
//   1. a code built today carries `pqcs`, an Ed25519 signature by the code's
//      own key over "z-pqc-sig-v1:" || account key || commitment, and decodes
//      as signed;
//   2. a code whose commitment was rewritten with its signature kept is
//      refused, as tampered;
//   3. a code with its signature removed is the code a client before ADR
//      0027 emits, byte for byte, and decodes as an unsigned commitment;
//   4. a signature left behind with its commitment removed is refused, not
//      read as a classical code;
//   5. on a linked device's code the device signs the ACCOUNT's commitment:
//      a signature naming the device key instead, or the root device's own
//      valid signature moved into it, is refused;
//   6. a malformed signature member — the wrong type, the wrong length, bad
//      base64 — is a FormatException, never an Error;
//   7. every older reader still reads a signed code: the v1 decoder as the
//      same classical identity, and the strict `zc3.` form carries the
//      signature too;
//   8. a persisted bundle keeps its signature, and a connect ceremony reads a
//      signed code as the same identity while refusing a rewritten one.
import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

/// A code's JSON with one edit applied — what anyone holding it can make.
String edit(String code, void Function(Map<String, Object?> j) change) {
  final prefix = code.substring(0, 4);
  final j = (jsonDecode(utf8.decode(unb64url(code.substring(4)))) as Map)
      .cast<String, Object?>();
  change(j);
  return prefix + b64url(utf8.encode(jsonEncode(j)));
}

Future<void> expectRefused(String code, {required String reason}) async {
  await expectLater(scanContactCode(code), throwsA(isA<FormatException>()),
      reason: reason);
}

void main() {
  late ZIdentity root;
  late HybridKeyPair pq;
  late String code;

  setUpAll(() async {
    root = await ZIdentity.generate();
    pq = await HybridKeyPair.fromSeeds(
        edSeed: root.edSeed, mlSeed: randomBytes(32));
    code = (await ContactBundleV3.forIdentity(root, pq.publicKey,
            displayName: 'Finn'))
        .encode();
  });

  test('1. a code carries a signature over its commitment, by its own key',
      () async {
    final j = jsonDecode(utf8.decode(unb64url(code.substring(4)))) as Map;
    expect(j['pqcs'], isA<String>());
    final sig = unb64(j['pqcs'] as String);
    expect(sig.length, 64);
    final commit = await pq.publicKey.pqCommitment();
    final input = pqCommitSigningInput(root.edPub, commit);
    expect(utf8.decode(input.sublist(0, 13)), 'z-pqc-sig-v1:');
    expect(input.sublist(13, 45), root.edPub);
    expect(input.sublist(45), commit);
    expect(input.length, 77);
    final decoded = await ContactBundleV3.decode(code);
    expect(decoded.commitSigned, isTrue);
    expect(await decoded.commitSignatureValid(), isTrue);
    expect((await scanContactCode(code)).commitSigned, isTrue);
  });

  test('2. a rewritten commitment under a kept signature is refused',
      () async {
    final other = await HybridKeyPair.fromSeeds(
        edSeed: root.edSeed, mlSeed: randomBytes(32));
    final otherCommit = await other.publicKey.pqCommitment();
    await expectRefused(edit(code, (j) => j['pqc'] = b64(randomBytes(32))),
        reason: 'random commitment');
    await expectRefused(edit(code, (j) => j['pqc'] = b64(otherCommit)),
        reason: 'a real commitment to a different key of the same identity');
  });

  test('3. without its signature it is the code issued before ADR 0027',
      () async {
    final unsigned = (await ContactBundleV3.forIdentity(root, pq.publicKey,
            displayName: 'Finn', signCommitment: false))
        .encode();
    expect(edit(code, (j) => j.remove('pqcs')), unsigned,
        reason: 'byte for byte: the member is the only difference');
    final scanned = await scanContactCode(unsigned);
    expect(scanned.commitSigned, isFalse);
    expect(scanned.assurance, IdentityAssurance.pendingPostQuantum,
        reason: 'an unsigned commitment is still a commitment to a reader; '
            'what it is worth is the app\'s to decide (ADR 0027)');
    expect(scanned.v3!.pqCommit, await pq.publicKey.pqCommitment());
  });

  test('4. a signature with its commitment removed is refused', () async {
    await expectRefused(edit(code, (j) => j.remove('pqc')),
        reason: 'not read as a classical code');
    // Nor with the signature emptied as well: a member that is present is
    // never read as one that is absent.
    await expectRefused(
        edit(code, (j) {
          j.remove('pqc');
          j['pqcs'] = '';
        }),
        reason: 'still not');
  });

  test("5. a linked device signs the account's commitment, and nothing else "
      'passes', () async {
    final laptop = await ZIdentity.generate();
    final account = await AccountIdentity.fromV1(root, deviceId: 'phone');
    final cert = await account.signDeviceCert(
        deviceEdPub: laptop.edPub, deviceXPub: laptop.xPub, deviceId: 'laptop');
    final anchored = (await ContactBundleV3.forIdentity(laptop, pq.publicKey,
            displayName: 'Finn', accountEdPub: root.edPub, cert: cert))
        .encode();
    final scanned = await scanContactCode(anchored);
    expect(scanned.commitSigned, isTrue);
    expect(scanned.accountEdPub, root.edPub);

    final commit = await pq.publicKey.pqCommitment();
    final overDevice = await Ed25519().sign(
        pqCommitSigningInput(laptop.edPub, commit),
        keyPair: laptop.edKeyPair);
    await expectRefused(
        edit(anchored, (j) => j['pqcs'] = b64(overDevice.bytes)),
        reason: 'the input must name the account the code names');
    final rootSig = (jsonDecode(utf8.decode(unb64url(code.substring(4))))
        as Map)['pqcs'];
    await expectRefused(edit(anchored, (j) => j['pqcs'] = rootSig),
        reason: "the root's valid signature is not the laptop's");
  });

  test('6. a malformed signature member is a FormatException', () async {
    for (final bad in <Object?>[
      7,
      true,
      <String>[],
      b64(randomBytes(63)),
      b64(randomBytes(65)),
      '!!not base64!!',
      '',
    ]) {
      await expectLater(scanContactCode(edit(code, (j) => j['pqcs'] = bad)),
          throwsA(isA<FormatException>()),
          reason: 'pqcs = ${jsonEncode(bad)}');
    }
  });

  test('7. every older reader still reads a signed code', () async {
    final v1 = await ContactBundle.decode(code);
    expect(v1.edPub, root.edPub);
    expect(v1.xPub, root.xPub);
    expect(await v1.verify(), isTrue);
    final strict = (await ContactBundleV3.forIdentity(root, pq.publicKey,
            displayName: 'Finn'))
        .encodeStrict();
    expect(strict, startsWith('zc3.'));
    expect((await ContactBundleV3.decode(strict)).commitSigned, isTrue);
  });

  test('8. a persisted bundle keeps its signature, and a ceremony reads it',
      () async {
    final b = await ContactBundleV3.decode(code);
    final back = ContactBundleV3.fromJson(
        (jsonDecode(jsonEncode(b.toJson())) as Map).cast<String, Object?>());
    expect(back.commitSigned, isTrue);
    expect(await back.commitSignatureValid(), isTrue);

    final id = await ConnectIdentity.fromCode(code, displayName: 'Finn');
    expect(id.accountEdPub, root.edPub);
    expect(id.pqCommit, await pq.publicKey.pqCommitment());
    await expectLater(
        ConnectIdentity.fromCode(
            edit(code, (j) => j['pqc'] = b64(randomBytes(32)))),
        throwsA(isA<FormatException>()),
        reason: 'a ceremony aborts on a rewritten commitment instead of '
            'covering it with the digits');
  });
}
