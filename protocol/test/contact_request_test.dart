import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

// ADR 0011 — the contact request (`creq`).
//
// Adding someone used to be silent on their side: your hello reached them, but
// with no session yet you were an unknown sender and it was dropped, so a real
// connection needed BOTH people to add each other. A request turns that drop
// into "someone wants to connect — accept or decline". It rides sealed but
// OUTSIDE the ratchet (there is none), and the sealed layer proves nothing
// about who sent it, so the request carries its own signature by the
// requester's identity key.
//
// Criteria, each asserted below:
//  1. a genuine request round-trips through its transport encoding and verifies
//     to its recipient, and the requester's routing id is the bundle's;
//  2. it is bound to ONE recipient: verifying against another routing id fails,
//     so a captured request cannot be replayed at anyone else;
//  3. the sealed sender must be the requester named by the bundle;
//  4. tampering ANY signed field — the X key, the name, the timestamp — makes
//     verification fail;
//  5. an attacker holding a victim's PUBLIC bundle but not its key cannot mint
//     a request as them: re-signing under a different key does not verify under
//     the bundle's key;
//  6. `tryParse` returns null (rather than throwing) on a file chunk or a
//     non-request payload, so the receive path can fall through cleanly.

void main() {
  late ZIdentity alice;
  late ZIdentity bob;
  late String bobRid;

  setUp(() async {
    alice = await ZIdentity.generate();
    bob = await ZIdentity.generate();
    bobRid = await bob.routingId();
  });

  test('1. a genuine request round-trips and verifies to its recipient',
      () async {
    final req =
        await ContactRequest.create(me: alice, toRid: bobRid, displayName: 'Alice');
    final wire = req.encode();
    final parsed = ContactRequest.tryParse(wire);
    expect(parsed, isNotNull);
    expect(await parsed!.verify(expectedTo: bobRid), isTrue);
    expect(await parsed.fromRid(), await alice.routingId());
    expect(parsed.bundle.displayName, 'Alice');
    // And with the sealed sender cross-checked.
    expect(
        await parsed.verify(
            expectedTo: bobRid, sealedFrom: await alice.routingId()),
        isTrue);
  });

  test('2. it is bound to one recipient', () async {
    final carol = await ZIdentity.generate();
    final req = await ContactRequest.create(me: alice, toRid: bobRid);
    final parsed = ContactRequest.tryParse(req.encode())!;
    expect(await parsed.verify(expectedTo: await carol.routingId()), isFalse);
  });

  test('3. the sealed sender must be the requester', () async {
    final mallory = await ZIdentity.generate();
    final req = await ContactRequest.create(me: alice, toRid: bobRid);
    final parsed = ContactRequest.tryParse(req.encode())!;
    expect(
        await parsed.verify(
            expectedTo: bobRid, sealedFrom: await mallory.routingId()),
        isFalse);
  });

  test('4. tampering any signed field fails verification', () async {
    final req = await ContactRequest.create(me: alice, toRid: bobRid, displayName: 'Alice');

    // A different name under the same signature.
    final renamed = ContactRequest(
      bundle: ContactBundle(
        edPub: req.bundle.edPub,
        xPub: req.bundle.xPub,
        bindingSig: req.bundle.bindingSig,
        displayName: 'Alicia',
      ),
      toRid: req.toRid,
      ts: req.ts,
      sig: req.sig,
    );
    expect(await renamed.verify(expectedTo: bobRid), isFalse);

    // A different timestamp under the same signature.
    final retimed = ContactRequest(
        bundle: req.bundle, toRid: req.toRid, ts: req.ts + 1, sig: req.sig);
    expect(await retimed.verify(expectedTo: bobRid), isFalse);

    // A swapped X key (still self-consistent bundle would need its own binding
    // sig; here the binding no longer matches, so bundle.verify fails first).
    final other = await ZIdentity.generate();
    final swappedX = ContactRequest(
      bundle: ContactBundle(
        edPub: req.bundle.edPub,
        xPub: other.xPub,
        bindingSig: req.bundle.bindingSig,
        displayName: req.bundle.displayName,
      ),
      toRid: req.toRid,
      ts: req.ts,
      sig: req.sig,
    );
    expect(await swappedX.verify(expectedTo: bobRid), isFalse);
  });

  test('5. a victim\'s public bundle cannot be minted into a request', () async {
    // Mallory holds Alice's public code (her bundle) but not her private key.
    final mallory = await ZIdentity.generate();
    final alicePublic = await alice.bundle(displayName: 'Alice');
    final ts = DateTime.now().millisecondsSinceEpoch;
    // She forges a request "from Alice" by signing Alice's input with her OWN
    // key — the only key she has.
    final forgedSig = await Ed25519().sign(
      ContactRequest.signingInput(alicePublic, bobRid, ts),
      keyPair: mallory.edKeyPair,
    );
    final forged = ContactRequest(
        bundle: alicePublic,
        toRid: bobRid,
        ts: ts,
        sig: Uint8List.fromList(forgedSig.bytes));
    // It does not verify: the signature must be by the bundle's key (Alice's),
    // which Mallory cannot produce.
    expect(await forged.verify(expectedTo: bobRid), isFalse);
    expect(
        await forged.verify(
            expectedTo: bobRid, sealedFrom: await alice.routingId()),
        isFalse);
  });

  test('6. tryParse returns null on non-requests', () {
    // A file-chunk-shaped payload.
    final chunk = base64Encode(utf8.encode(jsonEncode(
        {'v': 1, 't': 'f', 'fid': 'x', 'idx': 0, 'ct': 'AA', 'mac': 'AA'})));
    expect(ContactRequest.tryParse(chunk), isNull);
    // Garbage.
    expect(ContactRequest.tryParse('not base64 json at all'), isNull);
    expect(ContactRequest.tryParse(base64Encode(utf8.encode('{}'))), isNull);
  });
}
