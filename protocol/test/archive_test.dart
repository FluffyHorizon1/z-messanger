// The backup archive format (9.1): the recovery code's transcription
// tolerance and checksum, and the frame layer's guarantees — a wrong code
// fails closed, and a frame cannot be reordered, duplicated, truncated or
// lifted into another archive.

import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

void main() {
  group('recovery code', () {
    test('formats in groups and round-trips', () async {
      final code = await RecoveryCode.generate();
      final text = await code.format();
      expect(text, startsWith('ZBK-'));
      expect(text.split('-').length, 6); // prefix + five groups
      expect(text.replaceAll('-', '').substring(3).length,
          RecoveryCode.totalChars);
      final back = await RecoveryCode.parse(text);
      expect(back.entropy, code.entropy);
      expect(await back.keyMaterial(), await code.keyMaterial());
    });

    test('tolerates how people actually copy it', () async {
      final code = await RecoveryCode.generate();
      final canonical = await code.format();
      final messy = canonical
          .toLowerCase()
          .replaceAll('-', ' ')
          .replaceAll('0', 'o') // the classic transcription errors
          .replaceAll('1', 'l');
      final back = await RecoveryCode.parse(messy);
      expect(back.entropy, code.entropy,
          reason: 'case, spacing and O/0 L/1 confusion must not matter');
    });

    test('a typo is caught by the checksum, not by a failed decryption',
        () async {
      final code = await RecoveryCode.generate();
      final text = (await code.format()).replaceAll('-', '').substring(3);

      // A 5-bit checksum catches 31 of every 32 single-character typos, not
      // all of them, and asserting "this one particular substitution is
      // rejected" therefore fails about 3% of the time — a flake that says
      // nothing about the code when it fires. Measure the rate instead: it is
      // the actual property, it is deterministic at this sample size (775
      // substitutions, ~24 expected survivors, so 90% is many standard
      // deviations clear), and it fails loudly if the checksum is ever
      // dropped, where every one of them would sail through.
      var tried = 0, caught = 0;
      for (var i = 0; i < RecoveryCode.dataChars; i++) {
        for (final c in RecoveryCode.alphabet.split('')) {
          if (c == text[i]) continue;
          tried++;
          try {
            await RecoveryCode.parse(text.replaceRange(i, i + 1, c));
          } on FormatException {
            caught++;
          }
        }
      }
      expect(
          tried, RecoveryCode.dataChars * (RecoveryCode.alphabet.length - 1));
      expect(caught / tried, greaterThan(0.9),
          reason: 'a 5-bit checksum must catch ~31 of every 32 typos');
      // Wrong length and impossible characters are reported too.
      expect(
          () => RecoveryCode.parse('ZBK-123'), throwsA(isA<FormatException>()));
      expect(() => RecoveryCode.parse('U' * RecoveryCode.totalChars),
          throwsA(isA<FormatException>()));
    });

    test('codes are unpredictable', () async {
      final seen = <String>{};
      for (var i = 0; i < 50; i++) {
        seen.add(await (await RecoveryCode.generate()).format());
      }
      expect(seen.length, 50);
    });
  });

  group('archive frames', () {
    test('frames seal and open in place, and refuse to move', () async {
      final code = await RecoveryCode.generate();
      final salt = randomBytes(16);
      final np = randomBytes(16);
      final key = await ZArchive.deriveKey(await code.keyMaterial(), salt);
      final header = ZArchive.buildHeader(
          salt: salt, noncePrefix: np, schema: 3, createdMs: 1700000000000);
      expect(ZArchive.parseHeader(header)['schema'], 3);

      final f0 = await ZArchive.sealFrame(
          key: key,
          header: header,
          noncePrefix: np,
          index: 0,
          kind: ZArchive.kindRecord,
          payload: utf8.encode('{"t":"meta"}'));
      final f1 = await ZArchive.sealFrame(
          key: key,
          header: header,
          noncePrefix: np,
          index: 1,
          kind: ZArchive.kindBlob,
          payload: ZArchive.blobPayload('fid-1', [1, 2, 3]));

      final (k0, p0) = await ZArchive.openFrame(
          key: key, header: header, noncePrefix: np, index: 0, sealed: f0);
      expect(k0, ZArchive.kindRecord);
      expect(utf8.decode(p0), '{"t":"meta"}');
      final (k1, p1) = await ZArchive.openFrame(
          key: key, header: header, noncePrefix: np, index: 1, sealed: f1);
      expect(k1, ZArchive.kindBlob);
      final (fid, bytes) = ZArchive.parseBlobPayload(p1);
      expect(fid, 'fid-1');
      expect(bytes, [1, 2, 3]);

      // Reordering, duplicating or shifting a frame breaks the tag: the
      // index is part of the associated data.
      expect(
          () => ZArchive.openFrame(
              key: key, header: header, noncePrefix: np, index: 1, sealed: f0),
          throwsA(isA<FormatException>()));
      expect(
          () => ZArchive.openFrame(
              key: key, header: header, noncePrefix: np, index: 0, sealed: f1),
          throwsA(isA<FormatException>()));

      // A frame from another archive does not open here either, even with
      // the same key: the header is bound in.
      final otherHeader = ZArchive.buildHeader(
          salt: salt, noncePrefix: np, schema: 3, createdMs: 1700000000001);
      expect(
          () => ZArchive.openFrame(
              key: key,
              header: otherHeader,
              noncePrefix: np,
              index: 0,
              sealed: f0),
          throwsA(isA<FormatException>()));

      // A flipped byte fails closed.
      final tampered = Uint8List.fromList(f0)..[0] ^= 0x01;
      expect(
          () => ZArchive.openFrame(
              key: key,
              header: header,
              noncePrefix: np,
              index: 0,
              sealed: tampered),
          throwsA(isA<FormatException>()));
    });

    test('the wrong recovery code opens nothing and says nothing else',
        () async {
      final salt = randomBytes(16);
      final np = randomBytes(16);
      final right = await ZArchive.deriveKey(
          await (await RecoveryCode.generate()).keyMaterial(), salt);
      final wrong = await ZArchive.deriveKey(
          await (await RecoveryCode.generate()).keyMaterial(), salt);
      final header = ZArchive.buildHeader(
          salt: salt, noncePrefix: np, schema: 3, createdMs: 1);
      final f = await ZArchive.sealFrame(
          key: right,
          header: header,
          noncePrefix: np,
          index: 0,
          kind: ZArchive.kindRecord,
          payload: utf8.encode('secret'));
      expect(
          () => ZArchive.openFrame(
              key: wrong, header: header, noncePrefix: np, index: 0, sealed: f),
          throwsA(isA<FormatException>()),
          reason: 'no oracle beyond "it did not open"');
    });
  });
}
