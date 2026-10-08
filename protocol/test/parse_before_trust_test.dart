// Parse before trust: a wrong-typed field is a caught exception, not a raw
// Error that escapes the caller (the 2026-09-14 review's findings 42 and 43).
//
// A cast in an expression — `j['k'] as String` — throws a `TypeError`, which
// is an Error, not an Exception, so it escapes every `on FormatException` /
// `on RatchetDecryptException` between here and the caller and comes out raw.
// The review traced one such escape to a wedged mailbox slot and another to an
// unspent invite. These sites now type-check and throw the documented
// exception, the way `identity_v3.dart` does for a contact code.
import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:z_protocol/src/util.dart' show base32Encode;
import 'package:z_protocol/z_protocol.dart';

Uint8List _bytes(Object? json) =>
    Uint8List.fromList(utf8.encode(jsonEncode(json)));

void main() {
  group('finding 42 — InnerMessage.fromBytes', () {
    test('a valid inner still parses', () {
      final m = InnerMessage.fromBytes(
          _bytes({'k': 'text', 'mid': 'm1', 'ts': 5, 'body': 'hi'}));
      expect(m.kind, 'text');
      expect(m.mid, 'm1');
      expect(m.ts, 5);
      expect(m.data['body'], 'hi');
    });

    test('every wrong-typed field is a FormatException, never a TypeError', () {
      final bad = <Map<String, Object?>>[
        {'k': 123, 'mid': 'm', 'ts': 1}, // kind not a string
        {'k': 't', 'mid': 7, 'ts': 1}, // mid not a string
        {'k': 't', 'mid': 'm', 'ts': 'soon'}, // ts not a number
        {'k': 't', 'mid': 'm'}, // ts missing
        {'k': 't', 'mid': 'm', 'ts': 1, 'ttl': 'long'}, // ttl not a number
      ];
      for (final j in bad) {
        expect(() => InnerMessage.fromBytes(_bytes(j)),
            throwsA(isA<FormatException>()),
            reason: '$j');
      }
      expect(() => InnerMessage.fromBytes(Uint8List.fromList(utf8.encode('{'))),
          throwsA(isA<FormatException>()));
      expect(() => InnerMessage.fromBytes(_bytes([1, 2, 3])),
          throwsA(isA<FormatException>()));
    });

    // The members a receiver reads through a throwing cast — these ARE
    // rejected, because reaching them unguarded was the escaping Error.
    test('a member read through a throwing cast is a FormatException (§6.8)',
        () {
      final bad = <Map<String, Object?>>[
        {'k': 'text', 'mid': 'm', 'ts': 1, 'body': 5}, // body not a string
        {'k': 'read', 'mid': 'm', 'ts': 1, 'mids': 5}, // mids not a list
        {'k': 'read', 'mid': 'm', 'ts': 1, 'mids': [1, 2]}, // not strings
        {'k': 'dlv', 'mid': 'm', 'ts': 1, 'mids': ['ok', 7]}, // one wrong
        {'k': 'timer', 'mid': 'm', 'ts': 1, 'sec': 'soon'}, // sec not a number
        {'k': 'gmsg', 'mid': 'm', 'ts': 1, 'gid': 9, 'body': 'x'}, // gid
        {'k': 'gedit', 'mid': 'm', 'ts': 1, 'gid': 9}, // group-kind gid
        {'k': 'gdel', 'mid': 'm', 'ts': 1, 'gid': 9}, // group-kind gid
        {'k': 'greact', 'mid': 'm', 'ts': 1, 'gid': 9}, // group-kind gid
      ];
      for (final j in bad) {
        expect(() => InnerMessage.fromBytes(_bytes(j)),
            throwsA(isA<FormatException>()),
            reason: '$j');
      }
    });

    // The members a receiver is specified to IGNORE when malformed (§6.4/§6.5)
    // or that the offer reader defaults/refuses (§7) — a malformed one of
    // these must NOT drop the whole message. It parses; the tolerant reader
    // overlooks the bad member.
    test('a leniently-ignored member does not drop the message', () {
      final ok = <Map<String, Object?>>[
        {'k': 'text', 'mid': 'm', 'ts': 1, 'body': 'hi', 'rt': 9}, // bad rt
        {'k': 'react', 'mid': 'm', 'ts': 1, 'rt': 'x', 'emo': 7}, // bad emo
        {'k': 'del', 'mid': 'm', 'ts': 1, 'mids': {'x': 1}}, // del is tolerant
        {'k': 'file', 'mid': 'm', 'ts': 1, 'fid': 9, 'size': 'big'}, // offer
        {'k': 'gjoin', 'mid': 'm', 'ts': 1, 't': 5, 'go': 1}, // handler-guarded
        {'k': 'ginvite', 'mid': 'm', 'ts': 1, 'members': 'nope'}, // _parseList
      ];
      for (final j in ok) {
        expect(() => InnerMessage.fromBytes(_bytes(j)), returnsNormally,
            reason: '$j');
      }
    });

    test('a non-finite number anywhere is a FormatException, not an Error', () {
      // `1e999` decodes to a non-finite double; `.toInt()` on it throws an
      // `UnsupportedError`, which is an Error. jsonEncode cannot emit one, so
      // these are raw bytes.
      final raw = <String>[
        '{"k":"text","mid":"m","ts":1e999}', // ts
        '{"k":"text","mid":"m","ts":1,"ttl":1e999}', // ttl
        '{"k":"timer","mid":"m","ts":1,"sec":1e999}', // a kind member
        '{"k":"text","mid":"m","ts":1,"dl":{"v":1e999,"h":"x"}}', // nested
      ];
      for (final s in raw) {
        expect(
            () => InnerMessage.fromBytes(Uint8List.fromList(utf8.encode(s))),
            throwsA(isA<FormatException>()),
            reason: s);
      }
    });

    test('valid messages of every shape still parse', () {
      final good = <Map<String, Object?>>[
        {'k': 'hello', 'mid': 'm', 'ts': 1},
        {'k': 'text', 'mid': 'm', 'ts': 1, 'body': 'hi', 'rt': 'q'},
        {'k': 'read', 'mid': 'm', 'ts': 1, 'mids': ['a', 'b']},
        {'k': 'dlv', 'mid': 'm', 'ts': 1, 'mids': <String>[]},
        {'k': 'timer', 'mid': 'm', 'ts': 1, 'sec': 86400},
        {'k': 'gmsg', 'mid': 'm', 'ts': 1, 'gid': 'g', 'body': 'x'},
        {'k': 'gjoin', 'mid': 'm', 'ts': 1, 't': 'tag', 'go': 1},
        {'k': 'pqid', 'mid': 'm', 'ts': 1, 'alg': 'ML-DSA-65', 'pk': 'z', 'ack': true},
        // an unknown (forward-compat) kind passes untouched
        {'k': 'brand_new', 'mid': 'm', 'ts': 1, 'whatever': 42},
        // decorations ride on any kind
        {'k': 'text', 'mid': 'm', 'ts': 1, 'body': 'x', 'dl': {'v': 3, 'h': 'f'}},
      ];
      for (final j in good) {
        expect(() => InnerMessage.fromBytes(_bytes(j)), returnsNormally,
            reason: '$j');
      }
    });
  });

  group('finding 42 — Conversation.decrypt', () {
    test('a malformed transport payload is a RatchetDecryptException', () async {
      final a = await ZIdentity.generate();
      final b = await ZIdentity.generate();
      final conv = await Conversation.create(a, await b.bundle(),
          intervals: PqIntervals.disabled);
      // Reaches the sid check before any session lookup: a non-string sid.
      final badSid = base64Encode(_bytes({'v': 1, 't': 'r', 'sid': 123}));
      await expectLater(
          conv.decrypt(badSid), throwsA(isA<RatchetDecryptException>()));
      // Not base64 / not JSON at all.
      await expectLater(conv.decrypt('!!!not base64!!!'),
          throwsA(isA<RatchetDecryptException>()));
    });

    test('an opener with a wrong-length ephemeral key leaves no session behind',
        () async {
      final a = await ZIdentity.generate();
      final b = await ZIdentity.generate();
      final conv = await Conversation.create(a, await b.bundle(),
          intervals: PqIntervals.disabled);
      // 31 bytes, not 32: it can never open a session, and handed to the DH
      // it would throw an ArgumentError. The sid matches the key, so the
      // check it fails is the length, not the sid.
      final ek = randomBytes(31);
      final sid = await sessionIdFromEk(ek);
      final payload = base64Encode(utf8.encode(jsonEncode({
        'v': 1,
        't': 'r',
        'sid': sid,
        'ek': b64(ek),
        'h': {'dh': b64(randomBytes(32)), 'n': 0, 'pn': 0},
        'n': b64(Uint8List(24)),
        'ct': b64(Uint8List(16)),
        'mac': b64(Uint8List(16)),
      })));
      await expectLater(
          conv.decrypt(payload), throwsA(isA<RatchetDecryptException>()));
      expect(conv.sessions, isEmpty,
          reason: 'a failed opener commits no session');
    });

    test('an opener whose ratchet header is malformed leaves no session behind',
        () async {
      final a = await ZIdentity.generate();
      final b = await ZIdentity.generate();
      final conv = await Conversation.create(a, await b.bundle(),
          intervals: PqIntervals.disabled);
      // A valid 32-byte ephemeral key — so the responder session is built —
      // but a 31-byte ratchet `dh`, which makes the DH ratchet throw. The
      // session must not survive the failure (it used to, and convergence
      // could then pin outbound traffic onto it).
      final ek = randomBytes(32);
      final sid = await sessionIdFromEk(ek);
      final payload = base64Encode(utf8.encode(jsonEncode({
        'v': 1,
        't': 'r',
        'sid': sid,
        'ek': b64(ek),
        'h': {'dh': b64(randomBytes(31)), 'n': 0, 'pn': 0},
        'n': b64(Uint8List(24)),
        'ct': b64(Uint8List(16)),
        'mac': b64(Uint8List(16)),
      })));
      await expectLater(
          conv.decrypt(payload), throwsA(isA<RatchetDecryptException>()));
      expect(conv.sessions, isEmpty,
          reason: 'a session whose first message never decrypts is not kept');
    });

    test('a conversation with a genuine opener still works end to end',
        () async {
      // The guard above must not refuse a real first message.
      final a = await ZIdentity.generate();
      final b = await ZIdentity.generate();
      final ca = await Conversation.create(a, await b.bundle(),
          intervals: PqIntervals.disabled);
      final cb = await Conversation.create(b, await a.bundle(),
          intervals: PqIntervals.disabled);
      final wire = await ca.encrypt(InnerMessage.text('m1', 1, 'hello').toBytes());
      final dec = await cb.decrypt(wire);
      expect(InnerMessage.fromBytes(dec.plaintext).data['body'], 'hello');
      expect(cb.sessions, isNotEmpty, reason: 'the real session is committed');
    });
  });

  group('finding 43a — a short pairing code is FormatException, not RangeError',
      () {
    test('a code up to three bytes short says "too short"', () {
      // A full code is 10 bytes / 16 base32 chars. Decoded lengths of 8 and 9
      // passed the old `< 8` guard and then threw RangeError on sublist(0,10).
      for (final n in [0, 5, 8, 9]) {
        final short = base32Encode(Uint8List(n));
        expect(() => PairingCode.parse(short), throwsA(isA<FormatException>()),
            reason: '$n bytes must be a FormatException');
      }
      // Ten bytes is the boundary and is accepted.
      expect(PairingCode.parse(base32Encode(Uint8List(10))).secret.length, 10);
    });
  });

  group('finding 43c — ContactBundleV3 persistence keeps the account anchor',
      () {
    test('an account-anchored bundle round-trips as account-anchored',
        () async {
      final account = await AccountIdentity.generate();
      final device = await ZIdentity.generate();
      final cert = await account.signDeviceCert(
          deviceEdPub: device.edPub, deviceXPub: device.xPub, deviceId: 'lt');
      final bundle = ContactBundleV3(
        edPub: device.edPub,
        xPub: device.xPub,
        bindingSig: await device.bindingSignature(),
        pqCommit: Uint8List(32),
        declaredAccountEdPub: account.accountEdPub,
        deviceCert: cert,
      );
      expect(bundle.accountEdPub, account.accountEdPub,
          reason: 'anchored to the account, not the device');

      final back = ContactBundleV3.fromJson(
          jsonDecode(jsonEncode(bundle.toJson())) as Map<String, Object?>);
      expect(back.declaredAccountEdPub, isNotNull,
          reason: 'the account anchor survived toJson/fromJson (finding 43)');
      expect(back.accountEdPub, account.accountEdPub,
          reason: 'still the account, not degraded to the device');
      expect(back.deviceCert, isNotNull, reason: 'and its certificate');

      // A self-anchored (device) bundle stays self-anchored.
      final plain = ContactBundleV3(
        edPub: device.edPub,
        xPub: device.xPub,
        bindingSig: await device.bindingSignature(),
        pqCommit: Uint8List(32),
      );
      final plainBack = ContactBundleV3.fromJson(
          jsonDecode(jsonEncode(plain.toJson())) as Map<String, Object?>);
      expect(plainBack.declaredAccountEdPub, isNull);
      expect(plainBack.accountEdPub, device.edPub);
    });
  });
}
