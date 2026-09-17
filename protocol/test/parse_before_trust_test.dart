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
  });

  group('finding 42 — Conversation.decrypt', () {
    test('a malformed transport payload is a RatchetDecryptException', () async {
      final a = await ZIdentity.generate();
      final b = await ZIdentity.generate();
      final conv = await Conversation.create(a, await b.bundle());
      // Reaches the sid check before any session lookup: a non-string sid.
      final badSid = base64Encode(_bytes({'v': 1, 't': 'r', 'sid': 123}));
      await expectLater(
          conv.decrypt(badSid), throwsA(isA<RatchetDecryptException>()));
      // Not base64 / not JSON at all.
      await expectLater(conv.decrypt('!!!not base64!!!'),
          throwsA(isA<RatchetDecryptException>()));
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
