// Which sealed-sender bucket (§8) each kind of message actually lands in,
// measured through the whole pipeline the app uses — InnerMessage bytes →
// Double Ratchet (256-byte blocks, then a base64 JSON transport payload) →
// SealedEnvelope (JSON, padded to a bucket, base64 again).
//
// Written after ADR 0004's size table turned out to have inferred its bucket
// column from inner-message byte counts alone. The ratchet's padding and two
// layers of base64 sit between an inner message and the bucket, so the real
// boundaries are far lower than the bucket names suggest: the 1 024 bucket
// holds ONE ratchet block, i.e. an inner message of at most ~250 bytes.
//
// Exit criteria:
//   1. a short text ("ok", up to ~180 characters) seals into the 1 024
//      bucket, one of ~190 characters into 4 096, and one of ~2 000 into
//      16 384 — the boundaries docs/adr/0004 (addendum) and docs/adr/0005
//      quote, so a change to padding, encoding or framing that moves one
//      fails here instead of silently dating the documents;
//   2. a classical device list of one, two or three devices seals into the
//      4 096 bucket — the bucket of a medium text, NOT the 1 024 bucket
//      ADR 0003 and ADR 0004 claimed — so it is indistinguishable from
//      ordinary chat of that length, which is the property the ADRs need;
//   3. the account's ML-DSA public key (`pqid`) and the list-level
//      post-quantum signature (`dlpq`) each seal into the 16 384 bucket,
//      where nothing routine shorter than ~2 000 characters of text goes.
//
// Broken once on purpose: asserting the old 1 024 claim for a device list
// fails with "Expected: <1024> Actual: <4096> — 1 device(s): 496 inner bytes".
import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

Uint8List utf8b(String s) => Uint8List.fromList(utf8.encode(s));

/// A settled pairwise session (two exchanges each way, so no post-quantum
/// offer rides along with what we measure) and a sealing key for Bob.
class Pipe {
  final ZIdentity alice, bob;
  final Conversation a, b;
  final String aliceRid;
  Pipe._(this.alice, this.bob, this.a, this.b, this.aliceRid);

  static Future<Pipe> settle() async {
    final alice = await ZIdentity.generate();
    final bob = await ZIdentity.generate();
    final a =
        await Conversation.create(alice, await bob.bundle(displayName: 'Bob'));
    final b = await Conversation.create(
        bob, await alice.bundle(displayName: 'Alice'));
    for (var i = 0; i < 2; i++) {
      await b.decrypt(await a.encrypt(utf8b('hi $i')));
      await a.decrypt(await b.encrypt(utf8b('yo $i')));
    }
    return Pipe._(alice, bob, a, b, await alice.routingId());
  }

  /// Sends [m] Alice → Bob the way `ChatService._sendInner` does and returns
  /// the bucket the sealed envelope was padded to.
  Future<int> bucketOf(InnerMessage m) async {
    final wire = await a.encrypt(m.toBytes());
    final sealed = await SealedEnvelope.seal(
        toXPub: bob.xPub, fromRid: aliceRid, payload: wire);
    await b.decrypt(wire); // keep both ratchets in step
    // zs1. || b64url(ephPub 32 || nonce 12 || ciphertext(bucket) || mac 16)
    final raw = base64Url.decode(base64Url.normalize(sealed.substring(4)));
    final padded = raw.length - 32 - 12 - 16;
    expect(sealedBuckets, contains(padded),
        reason: 'a sealed body is always exactly one bucket long');
    return padded;
  }
}

InnerMessage text(String s) => InnerMessage(
    kind: 'text',
    mid: newMessageId(),
    ts: DateTime.now().millisecondsSinceEpoch,
    data: {'text': s});

Future<SignedDeviceList> listOf(AccountIdentity primary, int devices) async {
  final certs = [primary.deviceCert];
  for (var i = 1; i < devices; i++) {
    final dev = await ZIdentity.generate();
    certs.add(await primary.signDeviceCert(
        deviceEdPub: dev.edPub, deviceXPub: dev.xPub, deviceId: 'dev$i'));
  }
  return primary.signDeviceList(certs, devices);
}

void main() {
  late Pipe pipe;
  setUpAll(() async => pipe = await Pipe.settle());

  test('a short text is a 1 024-bucket envelope; ~190 characters is not',
      () async {
    expect(await pipe.bucketOf(text('ok')), 1024);
    expect(await pipe.bucketOf(text('x' * 180)), 1024,
        reason: 'one 256-byte ratchet block, the documented boundary');
    expect(await pipe.bucketOf(text('x' * 190)), 4096,
        reason: 'a second ratchet block moves the envelope up a bucket');
    expect(await pipe.bucketOf(text('x' * 1900)), 4096);
    expect(await pipe.bucketOf(text('x' * 2000)), 16384,
        reason: 'the documented upper boundary of the 4 096 bucket');
  });

  test('a classical device list of 1–3 devices shares the 4 096 bucket with '
      'a medium text', () async {
    final primary = await AccountIdentity.generate();
    for (final n in [1, 2, 3]) {
      final list = await listOf(primary, n);
      final inner = InnerMessage(
          kind: 'devlist',
          mid: newMessageId(),
          ts: DateTime.now().millisecondsSinceEpoch,
          data: {'list': jsonEncode(list.toJson())});
      expect(await pipe.bucketOf(inner), 4096,
          reason: '$n device(s): ${inner.toBytes().length} inner bytes');
    }
  });

  test('the post-quantum artefacts are the 16 384-bucket envelopes', () async {
    final key = await HybridKeyPair.generate();
    final pqid = InnerMessage.pqIdentity(
        newMessageId(), DateTime.now().millisecondsSinceEpoch, key.publicKey.mlPub);
    expect(await pipe.bucketOf(pqid), 16384,
        reason: 'pqid: ${pqid.toBytes().length} inner bytes');

    // A list signed by an account whose Ed25519 half is the hybrid key's.
    final root =
        await ZIdentity.fromSeeds(edSeed: key.edSeed, xSeed: randomBytes(32));
    final primary = await AccountIdentity.fromV1(root, deviceId: 'phone');
    final list = await listOf(primary, 2);
    final sig = await HybridDeviceListSignature.sign(accountKey: key, list: list);
    final dlpq = InnerMessage(
        kind: 'dlpq',
        mid: newMessageId(),
        ts: DateTime.now().millisecondsSinceEpoch,
        data: {'sig': jsonEncode(sig.toJson())});
    expect(await pipe.bucketOf(dlpq), 16384,
        reason: 'dlpq: ${dlpq.toBytes().length} inner bytes');
  });
}
