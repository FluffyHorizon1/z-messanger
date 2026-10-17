// Handles, the protocol half (ADR 0015 revision 2, PROTOCOL.md §21.1–§21.4
// and §21.7): what a person types becomes a canonical handle or a reason it
// is not one; the handle's label; the owner, introduction and recovery keys;
// the record the handle log holds and the owner rule over any history of
// them; the proof-of-work stamp an introduction request carries; and the
// acknowledgement an owner's acceptance carries.
//
// Exit criteria, each asserted below:
//   1. the grammar table: every valid input maps to its canonical form, and
//      every invalid one is refused with its reason — Unicode look-alikes
//      (Cyrillic, the Kelvin sign, long s, dotted I, fullwidth forms,
//      Arabic-Indic digits, a combining accent, invisible spaces) and every
//      reserved nick, written as it is and after normalisation, included;
//   2. normalisation trims ASCII whitespace only, removes ONE leading `@`,
//      lower-cases A–Z and folds nothing else; canonical bytes are ASCII;
//   3. the label is deterministic, is Argon2id with the specification's
//      parameters, separates `42` from `042`, and computes inside an isolate
//      of the caller's;
//   4. owner and introduction keys come from seeds; the introduction
//      mailbox is b64url(SHA-256(pub)), and its X25519 key, `xintro`, is
//      HKDF of the same seed, so one seed is the whole introduction
//      identity; a recovery code survives its printed form, a backup code is
//      refused by its prefix, and the recovery key and rc are per label;
//   5. claim, update and recover records round-trip byte for byte, with the
//      members in the one order (`xintro` right after `intro`, both null on
//      a paused handle);
//   6. every encoding that is not the canonical one is refused on decode —
//      whitespace, order, an absent or extra member, an escape, a duplicate,
//      a float, out-of-range pow, padded or standard-alphabet or
//      non-canonical base64, wrong lengths, and an `intro`/`xintro` pair with
//      one null and not the other;
//   7. a claim, then the owner's updates (rotate the introduction key,
//      pause), are accepted;
//   8. a foreign update is refused: signed by another key, or naming another
//      owner;
//   9. a claim on a label that exists is refused (taken), and a first entry
//      that is not a claim is refused;
//  10. a valid recover is accepted, installs the new owner and rc, retires
//      the old owner's key, and the new owner can update;
//  11. a recover with the wrong recovery key is refused;
//  12. rc cannot change without the recovery key's rsig: a recover with no
//      rsig, a recover whose rsig covers another rc, an update that changes
//      rc, and a recover signed by the old owner are each refused;
//  13. a version that is not the label's next is refused — equal, lower, a
//      replay, one that skips, a claim at 2, and the owner key's update at
//      2^53 − 1, after which a recover had no version left — and a recover
//      at the next version after such an update is accepted;
//  14. an oversize value is refused before anything in it is read;
//  15. the history function stops at the first refusal, naming its index
//      and reason and keeping the state before it, and refuses an entry for
//      another label;
//  16. a proof-of-work stamp verifies, and is refused for another routing
//      id, another envelope, an old day and too few bits; the relay's
//      today-or-yesterday window holds; the search is deterministic from its
//      start and runs inside an isolate;
//  17. a request sealed to `xintro` opens with the introduction identity
//      and no other key, addressed to the introduction mailbox; the
//      introduction acknowledgement verifies, and is refused under another
//      introduction key, for another requester, for another owner account
//      and for another request; the request id is the hash of what the
//      requester signed, and an acceptance carrying `ia` is still a `creq`
//      an older reader accepts.
//
// The public introduction link (ADR 0032, PROTOCOL §21.9) — the same
// introduction mailbox handed out directly, as a `zi1.` code:
//  18. a link from an introduction seed names exactly the keys and the
//      mailbox §21.3 derives from it; its body is `pow || intro || xintro`,
//      65 bytes, its check the first four bytes of SHA-256 over the context
//      and the body, its code `zi1.` and 92 base64url characters — 96, no
//      padding — and its link `https://host/c#code`, 126 characters at the
//      default host; it asks 20 bits unless told otherwise, and every
//      difficulty from 16 to 28 reads back as itself;
//  19. the reader trims ASCII whitespace and nothing else, and given a `#`
//      reads only what follows it, whatever host or page it is on; it names
//      a reason for every refusal, the first broken in one order — not a
//      link (a contact code, an invite, a handle, nothing, the prefix in
//      capitals, a version written with a leading zero), a newer version, a
//      character outside base64url (padding, `+`, `/`, a space), the wrong
//      length, a check that does not match (one bit of any byte, the
//      letters' case), a difficulty outside 16–28 — and every reason is one
//      some input gets;
//  20. every weak key is refused, as `intro` and as `xintro`: each spelling
//      of a point of small order and each value at or above p, with the
//      sign bit or the top bit set or clear, and an honest `xintro` with
//      its top bit set — and a link the reader would refuse cannot be made;
//  21. a handle is never a link, nor a link a handle: the grammar refuses
//      every code and link, and the link reader every handle;
//  22. a request through a link is a request through a handle: sealed to
//      the `xintro` read from the link, opened by the seed's introduction
//      identity and no other, addressed to its mailbox and stamped for it,
//      and its acknowledgement verifies under the `intro` read from the
//      link and under no other link's.

import 'dart:convert';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

Uint8List seed(int n) => Uint8List(32)..fillRange(0, 32, n);

void main() {
  test('1. the grammar table: accepted inputs and refused ones, with reasons',
      () {
    const accepted = {
      'alice.42': 'alice.42',
      '@Alice.42': 'alice.42',
      '  @ALICE.42 ': 'alice.42',
      'alice.042': 'alice.042',
      'alice.00': 'alice.00',
      'bob_smith.07': 'bob_smith.07',
      'a1b.123456': 'a1b.123456',
      'abc.12': 'abc.12',
      'abcdefghijklmnopqrst.99': 'abcdefghijklmnopqrst.99',
      'a_b_c.12': 'a_b_c.12',
      'admins.12': 'admins.12',
      'helpdesk.12': 'helpdesk.12',
    };
    for (final e in accepted.entries) {
      expect(Handle.parse(e.key).canonical, e.value, reason: e.key);
    }
    const refused = <String, HandleProblem>{
      '': HandleProblem.empty,
      '   ': HandleProblem.empty,
      '@': HandleProblem.empty,
      '@@alice.42': HandleProblem.badCharacter,
      '@ alice.42': HandleProblem.badCharacter,
      'ali ce.42': HandleProblem.badCharacter,
      'alice-x.42': HandleProblem.badCharacter,
      'alice+x.42': HandleProblem.badCharacter,
      'alice!.42': HandleProblem.badCharacter,
      'alice.42\u00a0': HandleProblem.badCharacter, // no-break space
      '\u3000alice.42': HandleProblem.badCharacter, // ideographic space
      'alice.42\u200b': HandleProblem.badCharacter, // zero-width space
      '\ufeffalice.42': HandleProblem.badCharacter, // byte-order mark
      'f\u0456nn\u0456an.42': HandleProblem.badCharacter, // Cyrillic i, U+0456
      '\u0430dmin.12': HandleProblem.badCharacter, // Cyrillic a, U+0430
      '\u0455upport.12': HandleProblem.badCharacter, // Cyrillic s, U+0455
      '\u212aate.42': HandleProblem.badCharacter, // Kelvin sign → "k"
      '\u017fam.42': HandleProblem.badCharacter, // long s → "S"
      '\u0130nan.42': HandleProblem.badCharacter, // dotted capital I
      'al\u0131ce.42': HandleProblem.badCharacter, // dotless i
      '\uff41lice.42': HandleProblem.badCharacter, // fullwidth a
      'alice\uff0e42': HandleProblem.badCharacter, // fullwidth full stop
      'alice\u300242': HandleProblem.badCharacter, // ideographic full stop
      'alice.\u0664\u0662': HandleProblem.badCharacter, // Arabic-Indic digits
      'alice.\uff14\uff12': HandleProblem.badCharacter, // fullwidth digits
      'ali\u0301ce.42': HandleProblem.badCharacter, // combining acute
      'alice.42\u{1f600}': HandleProblem.badCharacter, // outside the BMP
      'alice': HandleProblem.missingDigits,
      'alice.': HandleProblem.missingDigits,
      'alice.4a': HandleProblem.digitsNotDigits,
      'alice.4_2': HandleProblem.digitsNotDigits,
      'alice.42.42': HandleProblem.digitsNotDigits,
      'alice.7': HandleProblem.digitsTooShort,
      'alice.1234567': HandleProblem.digitsTooLong,
      'al.42': HandleProblem.nickTooShort,
      '.42': HandleProblem.nickTooShort,
      'abcdefghijklmnopqrstu.42': HandleProblem.nickTooLong,
      '1alice.42': HandleProblem.nickStartsWithNonLetter,
      '_alice.42': HandleProblem.nickStartsWithNonLetter,
      'ali__ce.42': HandleProblem.nickDoubleUnderscore,
      'alice_.42': HandleProblem.nickEndsWithUnderscore,
    };
    for (final e in refused.entries) {
      expect(Handle.problemWith(e.key), e.value, reason: jsonEncode(e.key));
      expect(Handle.tryParse(e.key), isNull);
      expect(() => Handle.parse(e.key),
          throwsA(isA<HandleFormatException>()
              .having((x) => x.problem, 'problem', e.value)));
    }
    // The refused character is reported as typed, a whole code point.
    final kelvin = (() {
      try {
        Handle.parse('\u212aate.42');
      } on HandleFormatException catch (e) {
        return e;
      }
      return null;
    })();
    expect(kelvin!.character, '\u212a');
    try {
      Handle.parse('alice.42\u{1f600}');
      fail('accepted an emoji');
    } on HandleFormatException catch (e) {
      expect(e.character, '\u{1f600}');
    }
    // Every reserved nick, as written and as someone might type it.
    expect(reservedHandleNicks.length, 28);
    expect(reservedHandleNicks.toSet().length, 28, reason: 'no duplicates');
    for (final n in reservedHandleNicks) {
      expect(Handle.problemWith('$n.12'), HandleProblem.reserved, reason: n);
      expect(Handle.problemWith(' @${n.toUpperCase()}.123456 '),
          HandleProblem.reserved, reason: n);
    }
  });

  test('2. normalisation folds nothing outside ASCII', () {
    expect(normaliseHandleInput(' \t\n\r\f\v@AbC.42\t '), 'abc.42');
    expect(normaliseHandleInput('@@x'), '@x', reason: 'one @ only');
    expect(normaliseHandleInput('\u00a0abc.42'), '\u00a0abc.42',
        reason: 'a no-break space is not whitespace here');
    expect(normaliseHandleInput('\u212aATE.42'), '\u212aate.42',
        reason: 'only A-Z is lower-cased; the Kelvin sign stays itself');
    expect(normaliseHandleInput('\u0130NAN.42'), '\u0130nan.42');
    final h = Handle.parse('  @Bob_Smith.07 ');
    expect(h.nick, 'bob_smith');
    expect(h.digits, '07');
    expect(h.canonical, 'bob_smith.07');
    expect(h.display, '@bob_smith.07');
    expect(h.canonicalBytes, ascii.encode('bob_smith.07'));
    expect(h, Handle.parse('bob_smith.07'));
    expect(h == Handle.parse('bob_smith.007'), isFalse, reason: '07 is not 007');
    expect(Handle.parse('bob_smith.07').hashCode, h.hashCode);
  });

  test('3. the label: Argon2id with the specification\'s parameters, '
      'deterministic, and computable in an isolate', () async {
    final a = Handle.parse('alice.42');
    final sw = Stopwatch()..start();
    final l1 = await handleLabel(a);
    sw.stop();
    printOnFailure('one label took ${sw.elapsedMilliseconds} ms');
    expect(l1.length, 32);
    expect(await handleLabel(Handle.parse('@ALICE.42 ')), l1,
        reason: 'one handle, one label, however it was typed');
    final direct = await Argon2id(
            memory: 19456, parallelism: 1, iterations: 2, hashLength: 32)
        .deriveKey(
            secretKey: SecretKey(ascii.encode('alice.42')),
            nonce: utf8.encode('z-handle-label-v1'));
    expect(l1, await direct.extractBytes());
    final l042 = await handleLabel(Handle.parse('alice.042'));
    expect(l042, isNot(l1), reason: '042 is not 42');
    // The app runs it off the UI isolate: plain values in and out.
    final inIsolate = await Isolate.run(() => handleLabel(a));
    expect(inIsolate, l1);
  });

  test('4. keys from seeds, the introduction mailbox, the recovery code and '
      'key', () async {
    final pub = await handleKeyPublic(seed(1));
    final kp = await Ed25519().newKeyPairFromSeed(seed(1));
    expect(pub, (await kp.extractPublicKey()).bytes);
    expect(await introRoutingId(pub), b64url(await sha256Bytes(pub)));
    expect((await introRoutingId(pub)).length, 43);
    await expectLater(() => handleKeyPublic(Uint8List(31)), throwsArgumentError);

    // The introduction identity: Ed25519 from the seed, X25519 from HKDF of
    // the same seed — one seed, both keys, rotated together.
    final intro = await handleIntroIdentity(seed(11));
    expect(intro.edPub, await handleKeyPublic(seed(11)));
    final xk = await Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
        secretKey: SecretKey(seed(11)),
        nonce: utf8.encode('z-handle-intro-x-v1'),
        info: const <int>[]);
    expect(intro.xSeed, await xk.extractBytes());
    expect(await handleIntroXSeed(seed(11)), intro.xSeed);
    final xkp = await X25519().newKeyPairFromSeed(intro.xSeed);
    expect(intro.xPub, (await xkp.extractPublicKey()).bytes);
    expect(await intro.routingId(), await introRoutingId(intro.edPub));
    final rotated = await handleIntroIdentity(seed(12));
    expect(rotated.xPub, isNot(intro.xPub), reason: 'a new seed, a new X key');
    await expectLater(() => handleIntroXSeed(Uint8List(31)), throwsArgumentError);

    final label = await handleLabel(Handle.parse('alice.42'));
    final other = await handleLabel(Handle.parse('alice.43'));
    final code = RecoveryCode(Uint8List.fromList(List.generate(15, (i) => i * 17)));
    final printed = await formatHandleRecoveryCode(code);
    expect(printed, startsWith('ZHR-'));
    expect(printed.length, 4 + 25 + 4);
    expect((await parseHandleRecoveryCode(printed)).entropy, code.entropy);
    expect(
        (await parseHandleRecoveryCode(printed.substring(4).toLowerCase()))
            .entropy,
        code.entropy,
        reason: 'the prefix is optional, case and dashes are not significant');
    final backup = await code.format(); // the same bits as a BACKUP code
    await expectLater(() => parseHandleRecoveryCode(backup), throwsFormatException);
    // A code whose own characters begin "ZHR" or "ZBK" is not mistaken for a
    // prefix when typed without one.
    for (final lead in ['ZHR', 'ZBK']) {
      // Three characters are the first 15 bits.
      var bits = 0;
      for (final ch in lead.split('')) {
        bits = (bits << 5) | RecoveryCode.alphabet.indexOf(ch);
      }
      final c = RecoveryCode(Uint8List.fromList(
          [bits >> 7, (bits & 0x7f) << 1, ...List.filled(13, 0x5a)]));
      final bare = (await c.format()).substring(4);
      expect(bare, startsWith(lead));
      expect((await parseHandleRecoveryCode(bare)).entropy, c.entropy,
          reason: lead);
      expect(
          (await parseHandleRecoveryCode('ZHR-$bare')).entropy, c.entropy,
          reason: lead);
    }
    // A typo is still caught by the backup code's checksum.
    final typo = printed.replaceRange(printed.length - 1, printed.length,
        printed.endsWith('0') ? '1' : '0');
    await expectLater(() => parseHandleRecoveryCode(typo), throwsFormatException);

    final rk = await handleRecoveryKey(code, label);
    final hk = await Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
        secretKey: SecretKey(code.entropy),
        nonce: utf8.encode('z-handle-recovery-v1'),
        info: label);
    expect(rk.seed, await hk.extractBytes());
    expect(rk.pub, await handleKeyPublic(rk.seed));
    expect(
        rk.rc,
        await sha256Bytes(
            [...utf8.encode('z-handle-rc-v1:'), ...rk.pub]));
    expect(await handleRecoveryCommitment(rk.pub), rk.rc);
    final rkOther = await handleRecoveryKey(code, other);
    expect(rkOther.pub, isNot(rk.pub), reason: 'one code, one handle');
    expect(rkOther.rc, isNot(rk.rc));
  });

  late Fixture f;
  setUpAll(() async => f = await Fixture.make());

  test('5. records round-trip byte for byte, members in the one order',
      () async {
    for (final r in [f.claimRecord, f.rotateRecord, f.pauseRecord, f.recoverRecord]) {
      final bytes = r.encode();
      final back = HandleRecord.decode(bytes);
      expect(back.encode(), bytes);
      expect(back, r);
      expect(back.kind, r.kind);
      expect(back.pow, r.pow);
      expect(back.owner, r.owner);
      expect(back.rc, r.rc);
    }
    final text = utf8.decode(f.recoverRecord.encode());
    final order = [
      '"k"', '"owner"', '"intro"', '"xintro"', '"pow"', '"rc"', '"rpub"', //
      '"rsig"',
    ].map(text.indexOf).toList();
    expect(order, everyElement(greaterThan(0)));
    expect([...order]..sort(), order, reason: 'exactly this order');
    expect(utf8.decode(f.pauseRecord.encode()),
        contains('"intro":null,"xintro":null,'));
    expect(f.pauseRecord.xintro, isNull);
    expect(f.claimRecord.xintro, f.xA1);
    expect(utf8.decode(f.claimRecord.encode()), isNot(contains('rpub')));
    expect(f.claimRecord.encode().every((b) => b < 0x80), isTrue);
    expect(await f.pauseRecord.introRoutingIdOrNull(), isNull);
    expect(await f.claimRecord.introRoutingIdOrNull(),
        await introRoutingId(f.introA1));
    // The constructors refuse what decode would refuse.
    expect(
        () => HandleRecord.claim(owner: f.ownerA, intro: f.introA1, xintro: f.xA1, pow: 15, rc: f.rc1),
        throwsArgumentError);
    expect(
        () => HandleRecord.update(owner: Uint8List(31), intro: null, xintro: null, pow: 20, rc: f.rc1),
        throwsArgumentError);
    expect(
        () => HandleRecord.update(owner: f.ownerA, intro: f.introA1, xintro: null, pow: 20, rc: f.rc1),
        throwsArgumentError,
        reason: 'an introduction key with nothing to seal to');
    expect(
        () => HandleRecord.update(owner: f.ownerA, intro: null, xintro: f.xA1, pow: 20, rc: f.rc1),
        throwsArgumentError);
  });

  test('6. every encoding but the canonical one is refused', () {
    final canon = utf8.decode(f.claimRecord.encode());
    final j = f.claimRecord.toJson();
    final owner = j['owner'] as String;
    const alphabet =
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    final tail = alphabet[alphabet.indexOf(owner[42]) | 1];
    final withDash = ['owner', 'intro', 'xintro', 'rc']
        .map((m) => j[m] as String)
        .firstWhere((s) => s.contains(RegExp(r'[-_]')));
    final intro = j['intro'] as String, xintro = j['xintro'] as String;
    final paused = utf8.decode(f.pauseRecord.encode());
    final variants = <String, String>{
      'whitespace': canon.replaceFirst('"k":', '"k": '),
      'newline': '$canon\n',
      'byte-order mark': '\ufeff$canon',
      'order': canon.replaceFirst('{"k":"claim",', '{').replaceFirst('}', ',"k":"claim"}'),
      'intro absent': canon.replaceFirst(',"intro":"${j['intro']}"', ''),
      'extra member': canon.replaceFirst('}', ',"x":1}'),
      'rpub null on a claim': canon.replaceFirst('}', ',"rpub":null}'),
      'rpub on a claim': canon.replaceFirst('}', ',"rpub":"$owner"}'),
      'k case': canon.replaceFirst('"claim"', '"Claim"'),
      'k unknown': canon.replaceFirst('"claim"', '"transfer"'),
      'escape': canon.replaceFirst('"claim"', '"\\u0063laim"'),
      'duplicate': canon.replaceFirst('"k":"claim",', '"k":"claim","k":"claim",'),
      'pow float': canon.replaceFirst('"pow":20', '"pow":20.0'),
      'pow exponent': canon.replaceFirst('"pow":20', '"pow":2e1'),
      'pow string': canon.replaceFirst('"pow":20', '"pow":"20"'),
      'pow 15': canon.replaceFirst('"pow":20', '"pow":15'),
      'pow 29': canon.replaceFirst('"pow":20', '"pow":29'),
      'pow negative': canon.replaceFirst('"pow":20', '"pow":-20'),
      'padding': canon.replaceFirst(owner, '$owner='),
      'standard alphabet': canon.replaceFirst(
          withDash, withDash.replaceAll('-', '+').replaceAll('_', '/')),
      'unused bits set': canon.replaceFirst(owner, owner.substring(0, 42) + tail),
      'short owner': canon.replaceFirst(owner, owner.substring(0, 42)),
      'long owner': canon.replaceFirst(owner, '${owner}AAAA'),
      'rc null': canon.replaceFirst('"rc":"${j['rc']}"', '"rc":null'),
      'xintro null, intro not': canon.replaceFirst('"xintro":"$xintro"', '"xintro":null'),
      'intro null, xintro not': canon.replaceFirst('"intro":"$intro"', '"intro":null'),
      'xintro absent': canon.replaceFirst(',"xintro":"$xintro"', ''),
      'xintro before intro': canon.replaceFirst('"intro":"$intro","xintro":"$xintro"',
          '"xintro":"$xintro","intro":"$intro"'),
      'short xintro': canon.replaceFirst(xintro, xintro.substring(0, 42)),
      'paused, with an xintro': paused.replaceFirst('"xintro":null', '"xintro":"$xintro"'),
      'paused, xintro absent': paused.replaceFirst(',"xintro":null', ''),
      'array': '[$canon]',
      'not json': canon.substring(1),
      'not utf-8': '',
    };
    for (final e in variants.entries) {
      final bytes = e.key == 'not utf-8'
          ? Uint8List.fromList([...utf8.encode(canon), 0xff])
          : Uint8List.fromList(utf8.encode(e.value));
      expect(() => HandleRecord.decode(bytes),
          throwsA(isA<HandleRecordFormatException>()),
          reason: e.key);
    }
    // A recover without rsig, or with rsig of the wrong length.
    final rText = utf8.decode(f.recoverRecord.encode());
    final rsig = f.recoverRecord.toJson()['rsig'] as String;
    for (final bad in [
      rText.replaceFirst(',"rsig":"$rsig"', ''),
      rText.replaceFirst(rsig, rsig.substring(0, 43)),
      rText.replaceFirst('"rsig":"$rsig"', '"rsig":null'),
    ]) {
      expect(() => HandleRecord.decode(utf8.encode(bad)),
          throwsA(isA<HandleRecordFormatException>()));
    }
  });

  test('7. a claim and the owner\'s own updates are accepted', () async {
    final s1 = await applyHandleEntry(null, f.claim);
    expect(s1.version, 1);
    expect(s1.owner, f.ownerA);
    expect(s1.rc, f.rc1);
    final s2 = await applyHandleEntry(s1, f.rotate);
    expect(s2.record.intro, f.introA2);
    expect(s2.record.pow, 22);
    expect(s2.owner, f.ownerA);
    final s3 = await applyHandleEntry(s2, f.pause);
    expect(s3.record.intro, isNull, reason: 'paused: resolves, unreachable');
    expect(s3.version, 3);
    // The publish body is the shape the log takes.
    final body = f.claim.toPublishJson();
    expect(body.keys, ['label', 'v', 'value', 'sig']);
    expect(body['label'], b64url(f.label));
    expect(base64Decode(body['value'] as String), f.claim.value);
    expect(base64Decode(body['sig'] as String), f.claim.sig);
    expect(
        await Ed25519().verify(
            await handlePublishInput(label: f.label, version: 1, value: f.claim.value),
            signature: Signature(f.claim.sig,
                publicKey: SimplePublicKey(f.ownerA, type: KeyPairType.ed25519))),
        isTrue);
  });

  test('8. a foreign update is refused, however it is dressed', () async {
    final s1 = await applyHandleEntry(null, f.claim);
    // Keeps Alice as the owner, signed by Mallory.
    final keepsOwner = await f.raw(2,
        HandleRecord.update(owner: f.ownerA, intro: f.introM, xintro: f.xM, pow: 16, rc: f.rc1).encode(),
        f.mSeed);
    await f.expectRefused(s1, keepsOwner, HandleRefusal.badSignature);
    // Names Mallory as the owner, signed by Mallory.
    final namesM = await f.raw(2,
        HandleRecord.update(owner: f.ownerM, intro: f.introM, xintro: f.xM, pow: 16, rc: f.rc1).encode(),
        f.mSeed);
    await f.expectRefused(s1, namesM, HandleRefusal.ownerChanged);
    // Signed by Mallory under Alice's name through the public signer: the
    // library will not even produce it.
    await expectLater(
        () => signHandleEntry(
            label: f.label,
            version: 2,
            record: HandleRecord.update(owner: f.ownerA, intro: null, xintro: null, pow: 16, rc: f.rc1),
            ownerSeed: f.mSeed),
        throwsArgumentError);
  });

  test('9. a claim on a taken label, and a first entry that is not a claim, '
      'are refused', () async {
    final s1 = await applyHandleEntry(null, f.claim);
    final mClaim = await f.raw(2,
        HandleRecord.claim(owner: f.ownerM, intro: f.introM, xintro: f.xM, pow: 16, rc: f.rcM).encode(),
        f.mSeed);
    await f.expectRefused(s1, mClaim, HandleRefusal.taken);
    // Even Alice cannot claim it again.
    final again = await signHandleEntry(
        label: f.label, version: 2, record: f.claimRecord, ownerSeed: f.aSeed);
    await f.expectRefused(s1, again, HandleRefusal.taken);
    await f.expectRefused(null, f.rotate, HandleRefusal.notClaimed);
    await f.expectRefused(null, f.recover, HandleRefusal.notClaimed);
    // A claim whose signature is not by the owner it names.
    final forged = await f.raw(1, f.claimRecord.encode(), f.mSeed);
    await f.expectRefused(null, forged, HandleRefusal.badSignature);
  });

  test('10. a valid recover installs the new owner and rc and retires the old '
      'key', () async {
    final v = await checkHandleHistory([f.claim, f.rotate, f.pause, f.recover]);
    expect(v.ok, isTrue);
    expect(v.state!.owner, f.ownerB);
    expect(v.state!.rc, f.rc2);
    expect(v.state!.version, 4);
    // The new owner updates.
    final s5 = await applyHandleEntry(v.state, f.afterRecover);
    expect(s5.record.pow, 24);
    // The old owner's key is nobody now: an update naming B signed by A, and
    // one naming A signed by A.
    final byA = await f.raw(5, f.afterRecover.value, f.aSeed);
    await f.expectRefused(v.state, byA, HandleRefusal.badSignature);
    final namesA = await signHandleEntry(
        label: f.label,
        version: 5,
        record: HandleRecord.update(owner: f.ownerA, intro: f.introA1, xintro: f.xA1, pow: 20, rc: f.rc2),
        ownerSeed: f.aSeed);
    await f.expectRefused(v.state, namesA, HandleRefusal.ownerChanged);
    // Recovery works straight after the claim too (no updates needed first).
    final early = await f.recoverAt(2, f.r1, f.ownerB, f.bSeed, f.rc2);
    expect((await checkHandleHistory([f.claim, early])).ok, isTrue);
  });

  test('11. a recover with the wrong recovery key is refused', () async {
    final s = (await checkHandleHistory([f.claim, f.rotate, f.pause])).state;
    final wrong = await f.recoverAt(4, f.rM, f.ownerM, f.mSeed, f.rcM);
    await f.expectRefused(s, wrong, HandleRefusal.wrongRecoveryKey);
    // The right code for ANOTHER handle is the wrong key for this one.
    final otherLabel = await handleLabel(Handle.parse('alice.43'));
    final codeForOther = await handleRecoveryKey(f.r1Code, otherLabel);
    final rsig = await signHandleRecovery(
        recoverySeed: codeForOther.seed, label: f.label, version: 4, owner: f.ownerB, rc: f.rc2);
    final crossed = await signHandleEntry(
        label: f.label,
        version: 4,
        record: HandleRecord.recover(
            owner: f.ownerB, intro: f.introB, xintro: f.xB, pow: 20, rc: f.rc2,
            rpub: codeForOther.pub, rsig: rsig),
        ownerSeed: f.bSeed);
    await f.expectRefused(s, crossed, HandleRefusal.wrongRecoveryKey);
  });

  test('12. rc does not change without the recovery key\'s rsig', () async {
    final s = (await checkHandleHistory([f.claim, f.rotate, f.pause])).state;
    // No rsig at all.
    final rsig = f.recoverRecord.toJson()['rsig'] as String;
    final noRsig = utf8.encode(utf8
        .decode(f.recoverRecord.encode())
        .replaceFirst(',"rsig":"$rsig"', ''));
    await f.expectRefused(
        s, await f.raw(4, Uint8List.fromList(noRsig), f.bSeed), HandleRefusal.malformed);
    // An rsig the right key made, over a different rc than the record sets.
    final otherRsig = await signHandleRecovery(
        recoverySeed: f.r1.seed, label: f.label, version: 4, owner: f.ownerB, rc: f.rcM);
    final swapped = await signHandleEntry(
        label: f.label,
        version: 4,
        record: HandleRecord.recover(
            owner: f.ownerB, intro: f.introB, xintro: f.xB, pow: 20, rc: f.rc2,
            rpub: f.r1.pub, rsig: otherRsig),
        ownerSeed: f.bSeed);
    await f.expectRefused(s, swapped, HandleRefusal.badRecoverySignature);
    // ...or over the right rc at another version (a replayed authorisation).
    final otherVersion = await signHandleRecovery(
        recoverySeed: f.r1.seed, label: f.label, version: 9, owner: f.ownerB, rc: f.rc2);
    final replayed = await signHandleEntry(
        label: f.label,
        version: 4,
        record: HandleRecord.recover(
            owner: f.ownerB, intro: f.introB, xintro: f.xB, pow: 20, rc: f.rc2,
            rpub: f.r1.pub, rsig: otherVersion),
        ownerSeed: f.bSeed);
    await f.expectRefused(s, replayed, HandleRefusal.badRecoverySignature);
    // The owner cannot change rc by an update.
    final rcByUpdate = await signHandleEntry(
        label: f.label,
        version: 4,
        record: HandleRecord.update(owner: f.ownerA, intro: f.introA1, xintro: f.xA1, pow: 20, rc: f.rc2),
        ownerSeed: f.aSeed);
    await f.expectRefused(s, rcByUpdate, HandleRefusal.rcChanged);
    // A recover whose rpub and rsig are right, signed by the OLD owner.
    final byOld = await f.raw(4, f.recoverRecord.encode(), f.aSeed);
    await f.expectRefused(s, byOld, HandleRefusal.badSignature);
  });

  test('13. a version that is not the next is refused, and a recover follows '
      'any update', () async {
    final s2 = (await checkHandleHistory([f.claim, f.rotate])).state;
    final same = await signHandleEntry(
        label: f.label, version: 2, record: f.pauseRecord, ownerSeed: f.aSeed);
    await f.expectRefused(s2, same, HandleRefusal.staleVersion);
    final lower = await signHandleEntry(
        label: f.label, version: 1, record: f.pauseRecord, ownerSeed: f.aSeed);
    await f.expectRefused(s2, lower, HandleRefusal.staleVersion);
    await f.expectRefused(s2, f.rotate, HandleRefusal.staleVersion);
    // No gaps: the next version is the rule, not a higher one.
    final jump = await signHandleEntry(
        label: f.label, version: 1000, record: f.pauseRecord, ownerSeed: f.aSeed);
    await f.expectRefused(s2, jump, HandleRefusal.staleVersion);
    // The owner key's holder at the ceiling — the update that, under "higher",
    // left the recover the code exists for no version to be.
    final ceiling = await signHandleEntry(
        label: f.label, version: handleMaxVersion, record: f.pauseRecord, ownerSeed: f.aSeed);
    await f.expectRefused(s2, ceiling, HandleRefusal.staleVersion);
    // A claim is version 1.
    final claimAt2 = await signHandleEntry(
        label: f.label, version: 2, record: f.claimRecord, ownerSeed: f.aSeed);
    await f.expectRefused(null, claimAt2, HandleRefusal.staleVersion);
    // And the recover follows whatever the owner key published, at the next
    // version: after the rotate (2) and the pause (3), at 4.
    final afterTheft = await checkHandleHistory([f.claim, f.rotate, f.pause, f.recover]);
    expect(afterTheft.ok, isTrue);
    expect(afterTheft.state!.owner, f.ownerB);
    // A version of 0 or past 2^53 - 1 is not a version.
    final zero = await f.raw(0, f.claimRecord.encode(), f.aSeed);
    await f.expectRefused(null, zero, HandleRefusal.malformed);
    final huge = HandleEntry(
        label: f.label, version: 1 << 53, value: f.claim.value, sig: f.claim.sig);
    await f.expectRefused(null, huge, HandleRefusal.malformed);
  });

  test('14. an oversize value is refused before it is read', () async {
    final s1 = await applyHandleEntry(null, f.claim);
    final rotate = f.rotateRecord.encode();
    final padded = Uint8List.fromList(
        [...rotate, ...List.filled(handleMaxValueBytes + 1 - rotate.length, 0x20)]);
    await f.expectRefused(s1, await f.raw(2, padded, f.aSeed), HandleRefusal.tooLarge);
    // Over the limit is refused even when it is not JSON at all: the size is
    // looked at before the value is read — after the entry's shape, which
    // reads nothing of it, so a signature that is not 64 bytes is malformed
    // first, as the log has it (§21.4's one order).
    final junk = HandleEntry(
        label: f.label,
        version: 2,
        value: Uint8List(handleMaxValueBytes + 1),
        sig: Uint8List(64));
    await f.expectRefused(s1, junk, HandleRefusal.tooLarge);
    final junkShape = HandleEntry(
        label: f.label,
        version: 2,
        value: Uint8List(handleMaxValueBytes + 1),
        sig: Uint8List(1));
    await f.expectRefused(s1, junkShape, HandleRefusal.malformed);
    expect(() => HandleRecord.decode(Uint8List(handleMaxValueBytes + 1)),
        throwsA(isA<HandleRecordFormatException>()));
    // The largest real record is far below it.
    expect(f.recoverRecord.encode().length, lessThan(handleMaxValueBytes ~/ 2));
  });

  test('15. the history function stops at the first refusal and keeps the '
      'state before it', () async {
    final all = await checkHandleHistory(
        [f.claim, f.rotate, f.pause, f.recover, f.afterRecover]);
    expect(all.ok, isTrue);
    expect(all.state!.version, 5);
    final empty = await checkHandleHistory(const []);
    expect(empty.ok, isTrue);
    expect(empty.state, isNull);
    final mClaim = await f.raw(3,
        HandleRecord.claim(owner: f.ownerM, intro: f.introM, xintro: f.xM, pow: 16, rc: f.rcM).encode(),
        f.mSeed);
    final v = await checkHandleHistory([f.claim, f.rotate, mClaim, f.pause]);
    expect(v.ok, isFalse);
    expect(v.refusedAt, 2);
    expect(v.reason, HandleRefusal.taken);
    expect(v.detail, isNotEmpty);
    expect(v.state!.version, 2, reason: 'the state before the refusal');
    expect(v.state!.record.intro, f.introA2);
    // An entry for another label in this label's history.
    final otherLabel = await handleLabel(Handle.parse('bob_smith.07'));
    final foreign = await signHandleEntry(
        label: otherLabel, version: 2, record: f.rotateRecord, ownerSeed: f.aSeed);
    final x = await checkHandleHistory([f.claim, foreign]);
    expect(x.refusedAt, 1);
    expect(x.reason, HandleRefusal.otherLabel);
    // A label of the wrong length is malformed, wherever it is.
    final short = HandleEntry(
        label: Uint8List(31), version: 1, value: f.claim.value, sig: f.claim.sig);
    expect((await checkHandleHistory([short])).reason, HandleRefusal.malformed);
  });

  test('16. proof of work: a stamp verifies, and nothing else does', () async {
    final rid = await introRoutingId(f.introA1);
    final otherRid = await introRoutingId(f.introA2);
    const nowMs = 1791460800000; // 2026-10-08T12:00:00Z
    final day = introPowDay(nowMs);
    expect(day, 20734);
    expect(introPowDay(day * 86400000 - 1), day - 1);
    final env = utf8.encode('zs1.an-envelope-as-sent');
    final nonce = createIntroPowStamp(
        introRid: rid, day: day, envelope: env, bits: 16, startNonce: Uint8List(16));
    expect(nonce.length, 16);
    expect(
        await verifyIntroPowStamp(
            introRid: rid, day: day, envelope: env, nonce: nonce, bits: 16),
        isTrue);
    final digest = await sha256Bytes(introPowInput(
        ridBytes: unb64url(rid),
        day: day,
        envelopeHash: await sha256Bytes(env),
        nonce: nonce));
    final zeros = introPowZeroBits(digest);
    expect(zeros, greaterThanOrEqualTo(16));
    expect(digest.take(2), [0, 0]);
    // Deterministic from its start, which is what makes it a vector.
    expect(
        createIntroPowStamp(
            introRid: rid, day: day, envelope: env, bits: 16, startNonce: Uint8List(16)),
        nonce);
    Future<bool> ok({String? r, int? d, List<int>? e, int? b}) => verifyIntroPowStamp(
        introRid: r ?? rid, day: d ?? day, envelope: e ?? env, nonce: nonce, bits: b ?? 16);
    expect(await ok(r: otherRid), isFalse, reason: 'another mailbox');
    expect(await ok(e: utf8.encode('zs1.an-envelope-as-sent!')), isFalse,
        reason: 'another envelope');
    expect(await ok(d: day - 2), isFalse, reason: 'another day');
    expect(await ok(b: zeros + 1), isFalse, reason: 'too few bits');
    expect(await ok(r: 'not a routing id'), isFalse);
    // The relay's window: made today, accepted today and tomorrow (as
    // yesterday's), not the day after, and not the day before (a stamp from
    // the future).
    for (final (offset, accepted) in [(0, true), (1, true), (2, false), (-1, false)]) {
      expect(
          await introPowAcceptable(
              introRid: rid,
              envelope: env,
              nonce: nonce,
              bits: 16,
              nowMs: nowMs + offset * 86400000),
          accepted,
          reason: 'relay clock $offset days on');
    }
    // A random start, inside an isolate, as the app runs it.
    final fromIsolate = await Isolate.run(() =>
        createIntroPowStamp(introRid: rid, day: day, envelope: env, bits: 12));
    expect(
        await verifyIntroPowStamp(
            introRid: rid, day: day, envelope: env, nonce: fromIsolate, bits: 12),
        isTrue);
    // The stamp search keeps its own SHA-256 midstate; across many inputs
    // every answer is one the package's SHA-256 agrees with.
    for (var i = 0; i < 40; i++) {
      final e = utf8.encode('zs1.${'x' * (i * 13)}');
      final n = createIntroPowStamp(
          introRid: rid, day: day + i, envelope: e, bits: 8, startNonce: seed(i).sublist(0, 16));
      expect(
          await verifyIntroPowStamp(
              introRid: rid, day: day + i, envelope: e, nonce: n, bits: 8),
          isTrue,
          reason: 'input $i');
    }
    expect(() => createIntroPowStamp(introRid: rid, day: day, envelope: env, bits: 33),
        throwsArgumentError);
    expect(() => createIntroPowStamp(introRid: 'x', day: day, envelope: env, bits: 8),
        throwsArgumentError);
  });

  test('17. the request is sealed to xintro, and the acknowledgement binds '
      'the key, the requester, the account and the request', () async {
    final bob = await ZIdentity.fromSeeds(edSeed: seed(40), xSeed: seed(41));
    final alice = await ZIdentity.fromSeeds(edSeed: seed(42), xSeed: seed(43));
    final carol = await ZIdentity.fromSeeds(edSeed: seed(44), xSeed: seed(45));
    final bobRid = await bob.routingId();
    final introRid = await introRoutingId(f.introA1);
    final creq = await ContactRequest.create(
        me: bob, toRid: introRid, displayName: 'Bob', ts: 1791460800000);
    // Sealed to the record's xintro and sent to the introduction mailbox:
    // the introduction identity opens it, and no other key does.
    final sealed = await SealedEnvelope.seal(
        toXPub: f.claimRecord.xintro!, fromRid: bobRid, payload: creq.encode());
    final introId = await handleIntroIdentity(f.introA1Seed);
    final opened = await SealedEnvelope.open(
        myXSeed: introId.xSeed, myXPub: introId.xPub, blob: sealed);
    expect(opened, isNotNull);
    expect(opened!.fromRid, bobRid);
    final rotatedId = await handleIntroIdentity(f.introA2Seed);
    expect(
        await SealedEnvelope.open(
            myXSeed: rotatedId.xSeed, myXPub: rotatedId.xPub, blob: sealed),
        isNull,
        reason: 'a rotated introduction key opens nothing sealed to the old one');
    // What the owner receives is what the requester sent: one id, both ends.
    final received = ContactRequest.tryParse(opened.payload)!;
    expect(
        await received.verify(expectedTo: introRid, sealedFrom: opened.fromRid),
        isTrue);
    final id = await contactRequestId(creq);
    expect(await contactRequestId(received), id);
    expect(id,
        await sha256Bytes(ContactRequest.signingInput(creq.bundle, creq.toRid, creq.ts)));
    final second = await ContactRequest.create(
        me: bob, toRid: introRid, displayName: 'Bob', ts: 1791460800001);
    expect(await contactRequestId(second), isNot(id));

    final ia = await signIntroAck(
        introSeed: f.introA1Seed,
        requesterRid: bobRid,
        ownerAccountEdPub: alice.edPub,
        creqId: id);
    expect(unb64url(ia).length, 64);
    Future<bool> check(
            {Uint8List? key, String? requester, Uint8List? owner, Uint8List? creqId, String? sig}) =>
        verifyIntroAck(
            ia: sig ?? ia,
            introPub: key ?? f.introA1,
            requesterRid: requester ?? bobRid,
            ownerAccountEdPub: owner ?? alice.edPub,
            creqId: creqId ?? id);
    expect(await check(), isTrue);
    expect(await check(key: f.introA2), isFalse, reason: 'another introduction key');
    expect(await check(requester: await carol.routingId()), isFalse,
        reason: 'another requester');
    expect(await check(owner: carol.edPub), isFalse, reason: 'another account');
    expect(await check(creqId: await contactRequestId(second)), isFalse,
        reason: 'another request');
    // Signed by a key that is not the introduction key, over the same bytes.
    final notIntro = await signIntroAck(
        introSeed: f.introA2Seed,
        requesterRid: bobRid,
        ownerAccountEdPub: alice.edPub,
        creqId: id);
    expect(await check(sig: notIntro), isFalse, reason: 'a wrong key');
    expect(await check(sig: 'not base64!'), isFalse);
    expect(await check(sig: ia.substring(0, 40)), isFalse);

    // Carried on the creq the acceptance sends back: an optional member that
    // a reader which does not know it ignores.
    final accept = await ContactRequest.create(
        me: alice, toRid: bobRid, displayName: 'Alice', ts: 1791460860000);
    final withIa = jsonDecode(utf8.decode(base64Decode(accept.encode())))
        as Map<String, Object?>
      ..['ia'] = ia;
    final payload = base64Encode(utf8.encode(jsonEncode(withIa)));
    final parsed = ContactRequest.tryParse(payload)!;
    expect(await parsed.verify(expectedTo: bobRid), isTrue);
    expect(parsed.bundle.edPub, alice.edPub,
        reason: 'the root device key is the account key the ack names');
    expect(
        await verifyIntroAck(
            ia: withIa['ia'] as String,
            introPub: f.introA1,
            requesterRid: bobRid,
            ownerAccountEdPub: parsed.bundle.edPub,
            creqId: id),
        isTrue);
  });

  test('18. a link from a seed: the keys and the mailbox of §21.3, the body, '
      'the check, the code and the link', () async {
    final introSeed = seed(21);
    final link = await IntroLink.fromSeed(introSeed);
    expect(link.pow, introLinkDefaultPow);
    expect(introLinkDefaultPow, 20);
    final id = await handleIntroIdentity(introSeed);
    expect(link.intro, id.edPub);
    expect(link.intro, await handleKeyPublic(introSeed));
    expect(link.xintro, id.xPub);
    expect(await link.introRid(), await introRoutingId(id.edPub));
    expect(await link.introRid(), await id.routingId(),
        reason: 'the mailbox the seed drains as its identity');
    expect(link.body, [20, ...id.edPub, ...id.xPub]);
    expect(link.body, hasLength(65));
    final digest =
        await sha256Bytes([...utf8.encode('z-intro-link-v1:'), ...link.body]);
    expect(link.check, digest.sublist(0, 4));
    expect(link.code, 'zi1.${b64url([...link.body, ...link.check])}');
    expect(link.code, hasLength(96));
    expect(link.code, isNot(contains('=')));
    expect(link.link(), 'https://www.zmessengers.com/c#${link.code}');
    expect(link.link(), hasLength(126));
    expect(link.link(host: 'relay.example.org'),
        'https://relay.example.org/c#${link.code}');
    // Every difficulty a link may carry reads back as itself.
    for (var pow = handlePowMinBits; pow <= handlePowMaxBits; pow++) {
      final l = await IntroLink.fromSeed(introSeed, pow: pow);
      final back = IntroLink.parse(l.link());
      expect(back, l);
      expect(back.pow, pow);
      expect(back.intro, l.intro);
      expect(back.xintro, l.xintro);
      expect(back.code, l.code);
      expect(l.body[0], pow);
    }
    expect((await IntroLink.fromSeed(introSeed, pow: 21)).code,
        isNot(link.code));
    expect(await IntroLink.fromSeed(seed(22)), isNot(link));
    // Any seed: 92 characters of the alphabet after the prefix, read back.
    for (var i = 0; i < 50; i++) {
      final l = await IntroLink.fromSeed(randomBytes(32));
      expect(l.code, matches(RegExp(r'^zi1\.[A-Za-z0-9_-]{92}$')));
      expect(IntroLink.parse(l.code), l);
      expect(IntroLink.parse(l.link()), l);
    }
  });

  test('19. the reader: ASCII whitespace, the fragment wherever it is, and '
      'a reason for every refusal, in one order', () async {
    final l = await IntroLink.fromSeed(seed(23));
    final c = l.code, enc = c.substring(4);
    String codeOf(List<int> body) =>
        'zi1.${b64url([...body, ...introLinkCheck(body)])}';
    for (final input in [
      c,
      l.link(),
      'https://i.example.org/c#$c',
      'https://www.zmessengers.com/c?utm_source=card#$c',
      ' \t\n${l.link()}\r\n\x0b\x0c',
      'www.zmessengers.com/c#$c',
      'https://relay.example.org:8443/c#$c',
      'https://www.zmessengers.com/index.html#$c',
      '#$c',
    ]) {
      expect(IntroLink.parse(input), l, reason: input);
      expect(IntroLink.problemWith(input), isNull, reason: input);
      expect(IntroLink.tryParse(input), l, reason: input);
    }
    final invite = ConnectCode.generate();
    final refused = <String, IntroLinkProblem>{
      '': IntroLinkProblem.notALink,
      ' \t ': IntroLinkProblem.notALink,
      'https://www.zmessengers.com/c': IntroLinkProblem.notALink,
      'https://www.zmessengers.com/c#': IntroLinkProblem.notALink,
      '$c#': IntroLinkProblem.notALink,
      invite.text: IntroLinkProblem.notALink,
      invite.link(): IntroLinkProblem.notALink,
      '@alice.42': IntroLinkProblem.notALink,
      'ZI1.$enc': IntroLinkProblem.notALink,
      'Zi1.$enc': IntroLinkProblem.notALink,
      'zI1.$enc': IntroLinkProblem.notALink,
      ' $c': IntroLinkProblem.notALink,
      ' $c': IntroLinkProblem.notALink,
      'zi1$enc': IntroLinkProblem.notALink,
      'zi.$enc': IntroLinkProblem.notALink,
      'zi0.$enc': IntroLinkProblem.notALink,
      'zi01.$enc': IntroLinkProblem.notALink,
      'zix.$enc': IntroLinkProblem.notALink,
      'zi2.$enc': IntroLinkProblem.newerVersion,
      'zi9.': IntroLinkProblem.newerVersion,
      'zi10.$enc': IntroLinkProblem.newerVersion,
      'zi99999999999999999999.$enc': IntroLinkProblem.newerVersion,
      'https://www.zmessengers.com/c#zi3.$enc': IntroLinkProblem.newerVersion,
      '$c=': IntroLinkProblem.notBase64url,
      '$c==': IntroLinkProblem.notBase64url,
      'zi1.${enc.substring(0, 91)}=': IntroLinkProblem.notBase64url,
      'zi1.+${enc.substring(1)}': IntroLinkProblem.notBase64url,
      'zi1./${enc.substring(1)}': IntroLinkProblem.notBase64url,
      'zi1.${enc.substring(0, 40)} ${enc.substring(40)}':
          IntroLinkProblem.notBase64url,
      '$c ': IntroLinkProblem.notBase64url,
      '$c​': IntroLinkProblem.notBase64url,
      'https://x.example/c#$c#more': IntroLinkProblem.notBase64url,
      c.substring(0, 95): IntroLinkProblem.wrongLength,
      '${c}A': IntroLinkProblem.wrongLength,
      'zi1.': IntroLinkProblem.wrongLength,
      'zi1.$enc$enc': IntroLinkProblem.wrongLength,
      codeOf(Uint8List(65)..[0] = 0): IntroLinkProblem.powOutOfRange,
      codeOf([15, ...l.intro, ...l.xintro]): IntroLinkProblem.powOutOfRange,
      codeOf([29, ...l.intro, ...l.xintro]): IntroLinkProblem.powOutOfRange,
      codeOf([255, ...l.intro, ...l.xintro]): IntroLinkProblem.powOutOfRange,
    };
    refused.forEach((input, problem) {
      expect(IntroLink.problemWith(input), problem, reason: '"$input"');
      expect(IntroLink.tryParse(input), isNull);
      expect(
          () => IntroLink.parse(input),
          throwsA(isA<IntroLinkFormatException>()
              .having((e) => e.problem, 'problem', problem)));
    });
    // A damaged copy: one bit of any of the 69 bytes, or the case of any
    // one letter, and the check no longer matches.
    final raw = [...l.body, ...l.check];
    for (var i = 0; i < raw.length; i++) {
      final damaged = List<int>.from(raw)..[i] ^= 0x01;
      expect(IntroLink.problemWith('zi1.${b64url(damaged)}'),
          IntroLinkProblem.badCheck,
          reason: 'byte $i');
    }
    var letters = 0;
    for (var i = 0; i < enc.length; i++) {
      final ch = enc.codeUnitAt(i);
      final isUpper = ch >= 0x41 && ch <= 0x5a, isLower = ch >= 0x61 && ch <= 0x7a;
      if (!isUpper && !isLower) continue;
      letters++;
      final swapped = String.fromCharCode(isUpper ? ch + 0x20 : ch - 0x20);
      expect(
          IntroLink.problemWith(
              'zi1.${enc.substring(0, i)}$swapped${enc.substring(i + 1)}'),
          IntroLinkProblem.badCheck,
          reason: 'the case of character $i');
    }
    expect(letters, greaterThan(40));
    // One order: the first rule broken is the one named.
    final weakX = Uint8List(32); // u = 0, of small order
    final weakEd = Uint8List(32)..[0] = 1; // the identity
    expect(IntroLink.problemWith('zi2.$enc='), IntroLinkProblem.newerVersion);
    expect(IntroLink.problemWith('$c$c='), IntroLinkProblem.notBase64url,
        reason: 'the alphabet before the length');
    final pow29 = [29, ...weakEd, ...weakX];
    final badCheck = [...pow29, ...introLinkCheck(pow29)]..[68] ^= 0x80;
    expect(IntroLink.problemWith('zi1.${b64url(badCheck)}'),
        IntroLinkProblem.badCheck,
        reason: 'the check before the content');
    expect(IntroLink.problemWith(codeOf(pow29)), IntroLinkProblem.powOutOfRange,
        reason: 'the difficulty before the keys');
    expect(IntroLink.problemWith(codeOf([20, ...weakEd, ...weakX])),
        IntroLinkProblem.weakIntro,
        reason: 'intro before xintro');
    // Every reason is one some input gets.
    expect({
      ...refused.values,
      IntroLinkProblem.badCheck,
      IntroLink.problemWith(codeOf([20, ...weakEd, ...l.xintro])),
      IntroLink.problemWith(codeOf([20, ...l.intro, ...weakX])),
    }, IntroLinkProblem.values.toSet());
    final e = IntroLinkFormatException(IntroLinkProblem.badCheck);
    expect(e, isA<FormatException>());
    expect(e.message, 'not a public introduction link: badCheck');
  });

  test('20. every weak key is refused, as intro and as xintro, and no link '
      'the reader refuses can be made', () async {
    final l = await IntroLink.fromSeed(seed(25));
    String codeOf(List<int> body) =>
        'zi1.${b64url([...body, ...introLinkCheck(body)])}';
    Uint8List fromHex(String h) => Uint8List.fromList([
          for (var i = 0; i < h.length; i += 2)
            int.parse(h.substring(i, i + 2), radix: 16)
        ]);
    final p = (BigInt.one << 255) - BigInt.from(19);
    Uint8List le(BigInt n) => Uint8List.fromList([
          for (var i = 0; i < 32; i++)
            ((n >> (8 * i)) & BigInt.from(0xff)).toInt()
        ]);
    Uint8List top(Uint8List k) => Uint8List.fromList(k)..[31] |= 0x80;
    // §21.4's values as PROTOCOL.md writes them, and the 19 at or above p.
    final smallEdY = [
      '0100000000000000000000000000000000000000000000000000000000000000',
      'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
      '0000000000000000000000000000000000000000000000000000000000000000',
      '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05',
      'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a',
    ].map(fromHex);
    final smallXU = [
      '0000000000000000000000000000000000000000000000000000000000000000',
      '0100000000000000000000000000000000000000000000000000000000000000',
      'e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
      '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157',
      'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f',
    ].map(fromHex);
    final aboveP = [for (var k = 0; k < 19; k++) le(p + BigInt.from(k))];
    final weakEd = [
      for (final y in [...smallEdY, ...aboveP]) ...[y, top(y)],
    ];
    final weakX = [
      for (final u in [...smallXU, ...aboveP]) ...[u, top(u)],
      top(l.xintro),
    ];
    expect(weakEd, hasLength(48));
    expect(weakX, hasLength(49));
    for (final k in weakEd) {
      expect(IntroLink.problemWith(codeOf([20, ...k, ...l.xintro])),
          IntroLinkProblem.weakIntro,
          reason: b64url(k));
      expect(() => IntroLink(pow: 20, intro: k, xintro: l.xintro),
          throwsArgumentError);
    }
    for (final k in weakX) {
      expect(IntroLink.problemWith(codeOf([20, ...l.intro, ...k])),
          IntroLinkProblem.weakXintro,
          reason: b64url(k));
      expect(() => IntroLink(pow: 20, intro: l.intro, xintro: k),
          throwsArgumentError);
    }
    // The edges: p − 2 is an honest y (and u); p − 1 is the point of order
    // 2; p is the first value at or above p.
    final pMinus2 = le(p - BigInt.two);
    expect(handleStrongEdKey(pMinus2), isTrue);
    expect(handleStrongXKey(pMinus2), isTrue);
    expect(IntroLink.problemWith(codeOf([20, ...pMinus2, ...l.xintro])), isNull);
    expect(IntroLink.problemWith(codeOf([20, ...l.intro, ...pMinus2])), isNull);
    // Honest keys are strong: the reader refuses weak keys, not keys.
    for (var i = 0; i < 100; i++) {
      final h = await IntroLink.fromSeed(randomBytes(32));
      expect(IntroLink.problemWith(h.code), isNull);
    }
    // Making refuses whatever reading would.
    for (final pow in [0, 15, 29, 255]) {
      expect(() => IntroLink(pow: pow, intro: l.intro, xintro: l.xintro),
          throwsArgumentError,
          reason: 'pow $pow');
      await expectLater(IntroLink.fromSeed(seed(25), pow: pow),
          throwsArgumentError);
    }
    expect(
        () => IntroLink(pow: 20, intro: l.intro.sublist(0, 31), xintro: l.xintro),
        throwsArgumentError);
    expect(() => IntroLink(pow: 20, intro: l.intro, xintro: Uint8List(33)),
        throwsArgumentError);
    await expectLater(IntroLink.fromSeed(Uint8List(31)), throwsArgumentError);
    expect(() => introLinkCheck(Uint8List(64)), throwsArgumentError);
  });

  test('21. a handle is never a link, nor a link a handle', () async {
    for (var i = 0; i < 30; i++) {
      final l = await IntroLink.fromSeed(randomBytes(32));
      for (final s in [l.code, l.link(), '@${l.code}', ' ${l.code} ']) {
        expect(Handle.problemWith(s), isNotNull, reason: s);
      }
      // `zi1` reads as a nick, and the base64 after the dot is not digits —
      // or holds a character no handle does.
      expect(Handle.problemWith(l.code),
          anyOf(HandleProblem.badCharacter, HandleProblem.digitsNotDigits));
    }
    for (final h in ['alice.42', '@Alice.42', 'bob_smith.07', ' @alice.42 ']) {
      expect(IntroLink.problemWith(h), IntroLinkProblem.notALink, reason: h);
    }
    // A handle can begin as a link does — `zi1` and `zi2` are nicks like any
    // other — and is still never read as one: a link is 96 characters and a
    // handle at most 27. The reasons the reader names for such a handle are
    // a link's, so a field that takes either asks the grammar too.
    expect(Handle.parse('zi1.42').canonical, 'zi1.42');
    expect(Handle.parse('zi2.42').canonical, 'zi2.42');
    expect(IntroLink.problemWith('zi1.42'), IntroLinkProblem.wrongLength);
    expect(IntroLink.problemWith('zi2.42'), IntroLinkProblem.newerVersion);
    expect(IntroLink.problemWith('@zi1.42'), IntroLinkProblem.notALink);
    expect(
        handleNickMaxLength + 1 + handleDigitsMaxLength, lessThan(introLinkCodeLength));
  });

  test('22. a request through a link is a request through a handle', () async {
    const nowMs = 1792238400000; // 2026-10-17T12:00:00Z
    final introSeed = seed(26);
    final made = await IntroLink.fromSeed(introSeed, pow: 16);
    final held = IntroLink.parse(made.link()); // what the requester has
    final rid = await held.introRid();
    final introId = await handleIntroIdentity(introSeed);
    expect(rid, await introId.routingId());
    final bob = await ZIdentity.fromSeeds(edSeed: seed(46), xSeed: seed(47));
    final owner = await ZIdentity.fromSeeds(edSeed: seed(48), xSeed: seed(49));
    final bobRid = await bob.routingId();
    final creq = await ContactRequest.create(
        me: bob, toRid: rid, displayName: 'Bob', ts: nowMs);
    final sealed = await SealedEnvelope.seal(
        toXPub: held.xintro, fromRid: bobRid, payload: creq.encode());
    final opened = await SealedEnvelope.open(
        myXSeed: introId.xSeed, myXPub: introId.xPub, blob: sealed);
    expect(opened, isNotNull);
    expect(opened!.fromRid, bobRid);
    expect(
        await ContactRequest.tryParse(opened.payload)!
            .verify(expectedTo: rid, sealedFrom: opened.fromRid),
        isTrue);
    final otherId = await handleIntroIdentity(seed(27));
    expect(
        await SealedEnvelope.open(
            myXSeed: otherId.xSeed, myXPub: otherId.xPub, blob: sealed),
        isNull,
        reason: "another link's seed opens nothing sealed to this one");
    // Stamped for its mailbox, at the link's pow and at a raised bits.
    final day = introPowDay(nowMs);
    final env = utf8.encode(sealed);
    final otherRid = await otherId.routingId();
    for (final bits in [held.pow, 18]) {
      final nonce = createIntroPowStamp(
          introRid: rid,
          day: day,
          envelope: env,
          bits: bits,
          startNonce: Uint8List(16));
      expect(
          await verifyIntroPowStamp(
              introRid: rid, day: day, envelope: env, nonce: nonce, bits: bits),
          isTrue);
      expect(
          await verifyIntroPowStamp(
              introRid: otherRid,
              day: day,
              envelope: env,
              nonce: nonce,
              bits: bits),
          isFalse);
    }
    // The acknowledgement, under the intro read from the link.
    final id = await contactRequestId(creq);
    final ia = await signIntroAck(
        introSeed: introSeed,
        requesterRid: bobRid,
        ownerAccountEdPub: owner.edPub,
        creqId: id);
    Future<bool> ackUnder(Uint8List introPub) => verifyIntroAck(
        ia: ia,
        introPub: introPub,
        requesterRid: bobRid,
        ownerAccountEdPub: owner.edPub,
        creqId: id);
    expect(await ackUnder(held.intro), isTrue);
    for (final s in [27, 28, 29]) {
      expect(await ackUnder((await IntroLink.fromSeed(seed(s))).intro), isFalse,
          reason: "another link's intro");
    }
    // Since 2026-10-16 the sealer itself refuses an xintro of small order;
    // a second spelling of a key it seals to, and the request is one the
    // owner cannot open. The reader refuses both kinds before either is
    // offered.
    await expectLater(
        SealedEnvelope.seal(
            toXPub: Uint8List(32), fromRid: bobRid, payload: creq.encode()),
        throwsA(isA<SealRefusedException>()));
    final respelled = Uint8List.fromList(held.xintro)..[31] |= 0x80;
    final lost = await SealedEnvelope.seal(
        toXPub: respelled, fromRid: bobRid, payload: creq.encode());
    expect(
        await SealedEnvelope.open(
            myXSeed: introId.xSeed, myXPub: introId.xPub, blob: lost),
        isNull);
    expect(() => IntroLink(pow: 16, intro: held.intro, xintro: respelled),
        throwsArgumentError);
  });
}

/// One handle's keys and the entries every test starts from: Alice claims
/// alice.42, rotates her introduction key, pauses, loses her owner key and
/// recovers to owner B, then updates as B. Mallory has keys of her own.
class Fixture {
  late Uint8List label;
  late Uint8List aSeed, bSeed, mSeed, introA1Seed, introA2Seed;
  late Uint8List ownerA, ownerB, ownerM, introA1, introA2, introB, introM;

  /// The X25519 halves of the four introduction identities: each record's
  /// `xintro` beside its `intro`.
  late Uint8List xA1, xA2, xB, xM;
  late RecoveryCode r1Code;
  late HandleRecoveryKey r1, r2, rM;
  late Uint8List rc1, rc2, rcM;
  late HandleRecord claimRecord, rotateRecord, pauseRecord, recoverRecord;
  late HandleEntry claim, rotate, pause, recover, afterRecover;

  static Future<Fixture> make() async {
    final f = Fixture();
    f.label = await handleLabel(Handle.parse('alice.42'));
    f.aSeed = seed(1);
    f.bSeed = seed(2);
    f.mSeed = seed(3);
    f.introA1Seed = seed(11);
    f.introA2Seed = seed(12);
    f.ownerA = await handleKeyPublic(f.aSeed);
    f.ownerB = await handleKeyPublic(f.bSeed);
    f.ownerM = await handleKeyPublic(f.mSeed);
    f.introA1 = await handleKeyPublic(f.introA1Seed);
    f.introA2 = await handleKeyPublic(f.introA2Seed);
    f.introB = await handleKeyPublic(seed(13));
    f.introM = await handleKeyPublic(seed(14));
    f.xA1 = (await handleIntroIdentity(f.introA1Seed)).xPub;
    f.xA2 = (await handleIntroIdentity(f.introA2Seed)).xPub;
    f.xB = (await handleIntroIdentity(seed(13))).xPub;
    f.xM = (await handleIntroIdentity(seed(14))).xPub;
    f.r1Code = RecoveryCode(Uint8List(15)..fillRange(0, 15, 0x21));
    f.r1 = await handleRecoveryKey(f.r1Code, f.label);
    f.r2 = await handleRecoveryKey(RecoveryCode(Uint8List(15)..fillRange(0, 15, 0x22)), f.label);
    f.rM = await handleRecoveryKey(RecoveryCode(Uint8List(15)..fillRange(0, 15, 0x23)), f.label);
    f.rc1 = f.r1.rc;
    f.rc2 = f.r2.rc;
    f.rcM = f.rM.rc;
    f.claimRecord = HandleRecord.claim(owner: f.ownerA, intro: f.introA1, xintro: f.xA1, pow: 20, rc: f.rc1);
    f.rotateRecord = HandleRecord.update(owner: f.ownerA, intro: f.introA2, xintro: f.xA2, pow: 22, rc: f.rc1);
    f.pauseRecord = HandleRecord.update(owner: f.ownerA, intro: null, xintro: null, pow: 22, rc: f.rc1);
    f.claim = await signHandleEntry(label: f.label, version: 1, record: f.claimRecord, ownerSeed: f.aSeed);
    f.rotate = await signHandleEntry(label: f.label, version: 2, record: f.rotateRecord, ownerSeed: f.aSeed);
    f.pause = await signHandleEntry(label: f.label, version: 3, record: f.pauseRecord, ownerSeed: f.aSeed);
    f.recover = await f.recoverAt(4, f.r1, f.ownerB, f.bSeed, f.rc2);
    f.recoverRecord = HandleRecord.decode(f.recover.value);
    f.afterRecover = await signHandleEntry(
        label: f.label,
        version: 5,
        record: HandleRecord.update(owner: f.ownerB, intro: f.introB, xintro: f.xB, pow: 24, rc: f.rc2),
        ownerSeed: f.bSeed);
    return f;
  }

  /// A recover at [version] authorised by [rk], installing [owner] (whose
  /// seed signs the entry) and [rc].
  Future<HandleEntry> recoverAt(int version, HandleRecoveryKey rk,
      Uint8List owner, Uint8List ownerSeed, Uint8List rc) async {
    final rsig = await signHandleRecovery(
        recoverySeed: rk.seed, label: label, version: version, owner: owner, rc: rc);
    return signHandleEntry(
        label: label,
        version: version,
        record: HandleRecord.recover(
            owner: owner, intro: introB, xintro: xB, pow: 20, rc: rc, rpub: rk.pub, rsig: rsig),
        ownerSeed: ownerSeed);
  }

  /// [value] verbatim as entry [version], signed by [signer] — what a
  /// dishonest or broken publisher can always produce.
  Future<HandleEntry> raw(int version, Uint8List value, Uint8List signer) async {
    final input =
        await handlePublishInput(label: label, version: version, value: value);
    final sig = await Ed25519()
        .sign(input, keyPair: await Ed25519().newKeyPairFromSeed(signer));
    return HandleEntry(
        label: label, version: version, value: value, sig: Uint8List.fromList(sig.bytes));
  }

  Future<void> expectRefused(
      HandleState? state, HandleEntry e, HandleRefusal reason) async {
    try {
      await applyHandleEntry(state, e);
      fail('accepted an entry that should be refused as ${reason.name}');
    } on HandleRefusedException catch (x) {
      expect(x.reason, reason, reason: x.detail);
    }
  }
}
