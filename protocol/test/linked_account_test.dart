import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

// Phase 33 — a linked device speaks for its account.
//
// Two places where a linked device used to speak only for itself: the
// enrolment that made it (PROTOCOL §10), which carried each contact as an
// account bundle and nothing more, and the contact request it sends (§8.1),
// which named the laptop as the account. Both grow OPTIONAL members, added
// after every member a reader has always read, so a device of either age
// reads what the other sends.
//
// Criteria, each a test below:
//   1. a request a linked device sends with its account anchor still
//      verifies, unchanged, for a reader that ignores the anchor, and names
//      the account — its key, its root's bundle, the device's certificate —
//      for one that reads it;
//   2. every check the anchor makes holds: a legacy record, a certificate for
//      another device or another ratchet key, a root bundle that does not
//      bind its key or is the sender's own, a certificate the root did not
//      sign, a missing or malformed member — each leaves the request the
//      device's own, still verifying;
//   3. an anchor carried over to a request it was not made for — another
//      recipient, another time — or swapped for another account that
//      certified the same device keys is refused by the anchor signature;
//   4. an enrolment sealed without the new members is byte for byte what a
//      build before them sealed, and one sealed with them opens with both
//      back as they went in;
//   5. an enrolment with the new members opens in a reader that reads only
//      what it always read, with the same contacts;
//   6. a `cstate` or `hostbundle` in a shape this build does not read is left
//      out, and the enrolment still opens.

/// A pairing session pair, derived the way both ends of §10.1 derive theirs.
Future<(PairingSession, PairingSession)> _sessions() async {
  final n = await PairingInitiatorV2.create(deviceId: 'laptop');
  final (reply, pending) = await PairingResponderV2.reply(await n.commit());
  final (open, initiator) = await n.open(reply);
  final responder = await pending.accept(open);
  return (initiator, responder);
}

Future<Uint8List> _plaintext(PairingSession s, Uint8List sealed) async =>
    Uint8List.fromList(await Chacha20.poly1305Aead().decrypt(
        SecretBox.fromConcatenation(sealed, nonceLength: 12, macLength: 16),
        secretKey: SecretKey(s.channelKey)));

void main() {
  late AccountIdentity account; // the root's
  late ZIdentity root;
  late ZIdentity laptop;
  late DeviceCertificate laptopCert;
  late ZIdentity bob;
  late String bobRid;

  setUp(() async {
    root = await ZIdentity.generate();
    account = await AccountIdentity.fromV1(root, deviceId: 'phone');
    laptop = await ZIdentity.generate();
    laptopCert = await account.signDeviceCert(
        deviceEdPub: laptop.edPub, deviceXPub: laptop.xPub, deviceId: 'laptop');
    bob = await ZIdentity.generate();
    bobRid = await bob.routingId();
  });

  Future<ContactRequest> anchored({int? ts}) async => ContactRequest.create(
      me: laptop,
      toRid: bobRid,
      displayName: 'Alice',
      ts: ts,
      root: await root.bundle(),
      cert: laptopCert);

  /// The wire request with its JSON edited as [edit] says.
  ContactRequest edited(
      ContactRequest req, void Function(Map<String, Object?> j) edit) {
    final j = (jsonDecode(utf8.decode(base64Decode(req.encode()))) as Map)
        .cast<String, Object?>();
    edit(j);
    return ContactRequest.tryParse(
        base64Encode(utf8.encode(jsonEncode(j))))!;
  }

  test('1. an anchored request verifies as before and names the account',
      () async {
    final req = await anchored();
    final wire = ContactRequest.tryParse(req.encode())!;
    expect(await wire.verify(
            expectedTo: bobRid, sealedFrom: await laptop.routingId()),
        isTrue,
        reason: 'the signature a reader from before the anchor checks');
    expect(await wire.fromRid(), await laptop.routingId());
    final a = await wire.anchor();
    expect(a, isNotNull);
    expect(b64(a!.accountEdPub), b64(account.accountEdPub));
    expect(await a.root.routingId(), await root.routingId(),
        reason: "held under the account's root routing id");
    expect(b64(a.cert.deviceEdPub), b64(laptop.edPub));
    // A reader that reads only the members it always read sees a plain
    // request from the laptop.
    final j = (jsonDecode(utf8.decode(base64Decode(req.encode()))) as Map)
        .cast<String, Object?>();
    expect(j.keys.take(6).toList(), ['v', 't', 'to', 'ts', 'bundle', 'sig']);
    // And a request from the root itself carries nothing more.
    final plain =
        await ContactRequest.create(me: root, toRid: bobRid, displayName: 'A');
    expect(await plain.anchor(), isNull);
    expect(
        (jsonDecode(utf8.decode(base64Decode(plain.encode()))) as Map).keys,
        ['v', 't', 'to', 'ts', 'bundle', 'sig']);
  });

  test('2. each check the anchor makes holds', () async {
    final req = await anchored();
    final other = await ZIdentity.generate();
    final otherAccount = await AccountIdentity.fromV1(other, deviceId: 'o');
    // Signed by the account, for a device that is not the sender — and for
    // the sender's Ed25519 key with another ratchet key.
    final elsewhere = await account.signDeviceCert(
        deviceEdPub: other.edPub, deviceXPub: other.xPub, deviceId: 'x');
    final swapped = await account.signDeviceCert(
        deviceEdPub: laptop.edPub, deviceXPub: other.xPub, deviceId: 'laptop');
    // Another account's certificate for the laptop's own keys, beside the
    // real root: one the root did not sign.
    final unsigned = await otherAccount.signDeviceCert(
        deviceEdPub: laptop.edPub, deviceXPub: laptop.xPub, deviceId: 'laptop');
    final cases = <String, ContactRequest>{
      'a legacy record': edited(req, (j) {
        (j['cert'] as Map)['legacy'] = true;
      }),
      'a certificate for another device': edited(req, (j) {
        j['cert'] = elsewhere.toJson();
      }),
      'a certificate for another ratchet key': edited(req, (j) {
        j['cert'] = swapped.toJson();
      }),
      'a certificate the root did not sign': edited(req, (j) {
        j['cert'] = unsigned.toJson();
      }),
      'a root that does not bind its key': edited(req, (j) {
        (j['root'] as Map)['x'] = b64(other.xPub);
      }),
      "the sender's own bundle as its root": edited(req, (j) {
        j['root'] = j['bundle'];
      }),
      'no anchor signature': edited(req, (j) {
        j.remove('asig');
      }),
      'a malformed anchor signature': edited(req, (j) {
        j['asig'] = 5;
      }),
      'no certificate': edited(req, (j) {
        j.remove('cert');
      }),
      'no root': edited(req, (j) {
        j.remove('root');
      }),
    };
    for (final e in cases.entries) {
      expect(await e.value.anchor(), isNull, reason: e.key);
      expect(await e.value.verify(expectedTo: bobRid), isTrue,
          reason: '${e.key}: still a request, from the device');
    }
  });

  test('3. an anchor is bound to its request and to its account', () async {
    final req = await anchored(ts: 1000);
    final r = (jsonDecode(utf8.decode(base64Decode(req.encode()))) as Map)
        .cast<String, Object?>();
    void carry(Map<String, Object?> j) {
      j['root'] = r['root'];
      j['cert'] = r['cert'];
      j['asig'] = r['asig'];
    }

    // The same anchor beside another request from the same device: another
    // time, and another recipient.
    final later = edited(
        await ContactRequest.create(
            me: laptop, toRid: bobRid, displayName: 'Alice', ts: 2000),
        carry);
    expect(await later.verify(expectedTo: bobRid), isTrue);
    expect(await later.anchor(), isNull, reason: 'another time');
    final carol = await ZIdentity.generate();
    final redirected = edited(
        await ContactRequest.create(
            me: laptop,
            toRid: await carol.routingId(),
            displayName: 'Alice',
            ts: 1000),
        carry);
    expect(await redirected.anchor(), isNull, reason: 'another recipient');
    // Another account that certified the same device keys — a certificate
    // proves the account signed it, not that it holds the device — with its
    // own root's genuine bundle: what someone passing the request on could
    // put beside it. The device never signed that account in.
    final mal = await ZIdentity.generate();
    final malAccount = await AccountIdentity.fromV1(mal, deviceId: 'm');
    final claim = await malAccount.signDeviceCert(
        deviceEdPub: laptop.edPub, deviceXPub: laptop.xPub, deviceId: 'laptop');
    final malRoot = await mal.bundle();
    final hijacked = edited(req, (j) {
      j['root'] = malRoot.toJson();
      j['cert'] = claim.toJson();
    });
    expect(await hijacked.verify(expectedTo: bobRid), isTrue);
    expect(await hijacked.anchor(), isNull,
        reason: 'the anchor signature names the account the device chose');
    expect(await req.anchor(), isNotNull, reason: 'and the real one holds');
  });

  test('4. without the new members the enrolment is what it always was',
      () async {
    final (initiator, responder) = await _sessions();
    final bobBundle =
        await AccountBundle.decode((await bob.bundle(displayName: 'Bob')).encode());
    final before = await responder.sealEnrollment(account,
        contacts: [bobBundle], includeAccountRoot: false, displayName: 'Alice');
    final cert = await responder.signedPeerCert(account);
    expect(
        utf8.decode(await _plaintext(initiator, before)),
        jsonEncode({
          'acct': b64(account.accountEdPub),
          'name': 'Alice',
          'cert': cert.toJson(),
          'hostcert': account.deviceCert.toJson(),
          'contacts': [bobBundle.toJson()],
        }),
        reason: 'the plaintext a build before phase 33 sealed, byte for byte');
    final opened = await initiator.openEnrollment(before);
    expect(opened.contactState, isNull);
    expect(opened.hostBundle, isNull);

    final state = [
      {
        'rid': bobRid,
        'bundle': (await bob.bundle()).toJson(),
        'verified': 1,
        'vsn': '00000',
        'kv': {'pqcs_': '1'},
      }
    ];
    final hostBundle = await root.bundle();
    final after = await responder.sealEnrollment(account,
        contacts: [bobBundle],
        includeAccountRoot: false,
        displayName: 'Alice',
        contactState: state,
        hostBundle: hostBundle);
    final back = await initiator.openEnrollment(after);
    expect(jsonEncode(back.contactState), jsonEncode(state));
    expect(jsonEncode(back.hostBundle!.toJson()),
        jsonEncode(hostBundle.toJson()));
    expect(back.contacts.single.toJson(), bobBundle.toJson());
  });

  test('5. a reader from before the new members opens an enrolment with them',
      () async {
    final (initiator, responder) = await _sessions();
    final bobBundle =
        await AccountBundle.decode((await bob.bundle(displayName: 'Bob')).encode());
    final sealed = await responder.sealEnrollment(account,
        contacts: [bobBundle],
        includeAccountRoot: false,
        displayName: 'Alice',
        contactState: [
          {'rid': bobRid, 'bundle': (await bob.bundle()).toJson()}
        ],
        hostBundle: await root.bundle());
    // `openEnrollment` as every build before phase 33 shipped it, verbatim
    // but for its name and receiver: it reads the members it knows.
    final j = jsonDecode(utf8.decode(await _plaintext(initiator, sealed)))
        as Map<String, Object?>;
    final old = EnrollmentData(
      accountEdPub: unb64(j['acct'] as String),
      accountEdSeed: j['root'] == null ? null : unb64(j['root'] as String),
      accountMlPub: j['pqpub'] == null ? null : unb64(j['pqpub'] as String),
      displayName: j['name'] as String?,
      deviceCert:
          DeviceCertificate.fromJson((j['cert'] as Map).cast<String, Object?>()),
      hostDeviceCert: DeviceCertificate.fromJson(
          (j['hostcert'] as Map).cast<String, Object?>()),
      contacts: [
        for (final c in (j['contacts'] as List))
          AccountBundle.fromJson((c as Map).cast<String, Object?>())
      ],
    );
    expect(old.contacts.single.toJson(), bobBundle.toJson());
    expect(old.displayName, 'Alice');
    expect(old.accountEdSeed, isNull,
        reason: '`root`, the account seed, is not confused with the root '
            "device's bundle (`hostbundle`)");
    expect(await old.deviceCert.verify(old.accountEdPub), isTrue);
  });

  test('6. new members this build cannot read are left out', () async {
    final (initiator, responder) = await _sessions();
    final bobBundle =
        await AccountBundle.decode((await bob.bundle()).encode());
    // Sealed by hand: a payload whose two optional members are in shapes no
    // build reads.
    final cert = await responder.signedPeerCert(account);
    final payload = jsonEncode({
      'acct': b64(account.accountEdPub),
      'name': 'Alice',
      'cert': cert.toJson(),
      'hostcert': account.deviceCert.toJson(),
      'contacts': [bobBundle.toJson()],
      'cstate': {'not': 'a list'},
      'hostbundle': ['not', 'a', 'bundle'],
    });
    final box = await Chacha20.poly1305Aead().encrypt(utf8.encode(payload),
        secretKey: SecretKey(responder.channelKey), nonce: randomBytes(12));
    final opened = await initiator
        .openEnrollment(Uint8List.fromList(box.concatenation()));
    expect(opened.contactState, isNull);
    expect(opened.hostBundle, isNull);
    expect(opened.contacts.single.toJson(), bobBundle.toJson());
    // A list whose records are not all records keeps the ones that are.
    final mixed = jsonEncode({
      ...jsonDecode(payload) as Map,
      'cstate': [
        5,
        {'rid': bobRid},
        {'no': 'rid'}
      ],
    });
    final box2 = await Chacha20.poly1305Aead().encrypt(utf8.encode(mixed),
        secretKey: SecretKey(responder.channelKey), nonce: randomBytes(12));
    final opened2 = await initiator
        .openEnrollment(Uint8List.fromList(box2.concatenation()));
    expect(opened2.contactState, [
      {'rid': bobRid}
    ]);
  });
}
