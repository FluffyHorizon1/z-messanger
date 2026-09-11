// The transparency log's reader (PROTOCOL.md §19, ADR 0006), against the
// vectors the log's own implementation generated (docs/vectors/kt): every
// proof verifies under the head it was made for, every case marked
// must_refuse is refused, and the sealed value in Alice's first entry opens
// to the v1 multidevice vector's real signed list — whose fingerprint,
// computed by the code that already gossips it (§3.6), must equal the
// entry's. That last check is 7.7a's sixteen bytes meeting 7.7b's leaf.
//
// Criteria, each a test below:
//  1. the RFC 9162 verifiers accept every reference path and consistency
//     proof, and reject a wrong root, index or size;
//  2. the map proof verifies for present and absent labels and fails the
//     four ways the vectors say it must;
//  3. labels, value keys and sealed values reproduce, values open only with
//     the account's key, and Alice's list verifies with its fingerprint equal
//     to the entry's;
//  4. the publish request reproduces the vector's signature byte for byte;
//  5. heads verify, extend one another through the consistency proofs, and a
//     head under another key, a shrunk log and both forks are refused;
//  6. lookups verify to the expected latest entry (or absence), the
//     superseded-entry lookup is refused, and history items verify;
//  7. a witness record verifies with both signatures, and not with a
//     changed head.

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';

Map<String, Object?> vec(String name) =>
    (jsonDecode(File('../docs/vectors/kt/$name.json').readAsStringSync())
            as Map)
        .cast<String, Object?>();

Uint8List hx(Object? s) {
  final str = s as String;
  final out = Uint8List(str.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(str.substring(2 * i, 2 * i + 2), radix: 16);
  }
  return out;
}

List<Uint8List> hxList(Object? l) => [for (final s in l as List) hx(s)];
List<Uint8List> b64List(Object? l) => [for (final s in l as List) unb64(s as String)];
Map<String, Object?> obj(Object? m) => (m as Map).cast<String, Object?>();

void main() {
  group('log tree (RFC 9162)', () {
    final v = vec('log_tree');
    final roots = hxList(v['roots_by_size']);
    final leaves = hxList(v['leaf_hashes']);

    test('leaf hashes and every reference inclusion path', () async {
      final inputs = v['leaf_inputs'] as List;
      for (var i = 0; i < inputs.length; i++) {
        expect(await ktLeafHash(hx(inputs[i])), leaves[i]);
      }
      for (final p in v['inclusion'] as List) {
        final m = obj(p);
        final index = m['index'] as int;
        final size = m['size'] as int;
        final path = hxList(m['path']);
        expect(
            await ktVerifyInclusion(
                leafHash: leaves[index],
                index: index,
                size: size,
                root: roots[size],
                path: path),
            isTrue,
            reason: 'PATH($index, D[$size])');
        if (size > 1) {
          expect(
              await ktVerifyInclusion(
                  leafHash: leaves[index],
                  index: index,
                  size: size,
                  root: roots[size - 1],
                  path: path),
              isFalse,
              reason: 'wrong root');
          expect(
              await ktVerifyInclusion(
                  leafHash: leaves[(index + 1) % size],
                  index: index,
                  size: size,
                  root: roots[size],
                  path: path),
              isFalse,
              reason: 'wrong leaf');
          // A path is not tied to a size on its own — the head is, since
          // size and root are signed together — so the wrong size is tried
          // with that size's root.
          if (size < 8) {
            expect(
                await ktVerifyInclusion(
                    leafHash: leaves[index],
                    index: index,
                    size: size + 1,
                    root: roots[size + 1],
                    path: path),
                isFalse,
                reason: 'wrong size');
          }
        }
      }
    });

    test('every reference consistency proof, and not from the wrong root', () async {
      for (final c in v['consistency'] as List) {
        final m = obj(c);
        final first = m['first'] as int;
        final second = m['second'] as int;
        final proof = hxList(m['proof']);
        expect(
            await ktVerifyConsistency(
                first: first,
                second: second,
                firstRoot: roots[first],
                secondRoot: roots[second],
                proof: proof),
            isTrue,
            reason: 'PROOF($first, D[$second])');
        if (first > 0 && first < second) {
          expect(
              await ktVerifyConsistency(
                  first: first,
                  second: second,
                  firstRoot: roots[first - 1],
                  secondRoot: roots[second],
                  proof: proof),
              isFalse);
        }
      }
    });
  });

  group('map tree', () {
    final v = vec('map_tree');
    final root = hx(v['final_root']);

    KtMapProof proofOf(Map<String, Object?> p) {
      final leaf = p['leaf'];
      return KtMapProof(
        index: leaf == null ? null : obj(leaf)['index'] as int,
        version: leaf == null ? null : obj(leaf)['version'] as int,
        bitmap: hx(p['bitmap']),
        siblings: hxList(p['siblings']),
      );
    }

    test('the empty constants and the example leaf', () async {
      final empty = await ktMapEmpty();
      expect(empty[ktMapDepth], hx(v['empty_leaf']));
      expect(empty[0], hx(v['empty_root']));
      final ex = obj(v['example_leaf_hash']);
      expect(await ktMapLeafHash(hx(ex['label']), ex['index'] as int, ex['version'] as int),
          hx(ex['hash']));
    });

    test('presence and absence proofs verify under the final root', () async {
      var present = 0;
      for (final p in v['proofs'] as List) {
        final m = obj(p);
        expect(await proofOf(m).verify(root, hx(m['label'])), isTrue,
            reason: m['label'] as String);
        if (m['leaf'] != null) present++;
      }
      expect(present, 12);
      expect((v['proofs'] as List).length, 14);
    });

    test('the four proofs that must fail, fail', () async {
      for (final p in v['must_refuse'] as List) {
        final m = obj(p);
        expect(await proofOf(m).verify(root, hx(m['label'])), isFalse,
            reason: m['why'] as String);
      }
    });
  });

  group('the log', () {
    final v = vec('kt_log');
    final logPub = hx(obj(v['log'])['pub']);
    final accounts = obj(v['accounts']);
    final alice = obj(accounts['alice']);
    final bob = obj(accounts['bob']);
    final alicePub = hx(alice['account_ed_pub']);
    final bobPub = hx(bob['account_ed_pub']);
    final publishes = [for (final p in v['publishes'] as List) obj(p)];
    final heads = [for (final h in v['heads_by_size'] as List) KtTreeHead.fromJson(obj(h))];

    test('labels, value keys, sealed values — and Alice\'s list verifies with the entry\'s fingerprint', () async {
      expect(await ktLabel(alicePub), hx(alice['label']));
      expect(await ktLabel(bobPub), hx(bob['label']));
      expect(Uint8List.fromList(await (await ktValueKey(alicePub)).extractBytes()),
          hx(alice['value_key']));
      for (final p in publishes) {
        final pub = p['account'] == 'alice' ? alicePub : bobPub;
        final other = p['account'] == 'alice' ? bobPub : alicePub;
        final plaintext = utf8.encode(p['plaintext_json'] as String);
        final sealed = await ktSealValue(pub, plaintext, nonce: hx(p['nonce']));
        expect(sealed, hx(p['value']), reason: 'publish ${p['version']}: sealed value');
        expect(await ktOpenValue(pub, sealed), plaintext);
        expect(await ktOpenValue(other, sealed), isNull,
            reason: 'another account\'s key does not open it');
        final tampered = Uint8List.fromList(sealed);
        tampered[12] ^= 1;
        expect(await ktOpenValue(pub, tampered), isNull);
      }
      // The first entry is the v1 multidevice vector's real signed list.
      final first = publishes[0];
      final opened = await ktOpenValue(alicePub, hx(first['value']));
      final list = SignedDeviceList.fromJson(
          (jsonDecode(utf8.decode(opened!)) as Map).cast<String, Object?>());
      expect(list.accountEdPub, alicePub);
      expect(list.version, 3);
      expect(await list.verify(), isTrue, reason: 'the list verifies with the code that already exists');
      expect(await list.fingerprint(), hx(first['fingerprint']),
          reason: '§3.6\'s fingerprint equals the leaf\'s');
      expect(list.fingerprint(), completion(hx(first['fingerprint'])));
    });

    test('the publish request reproduces the vector\'s signature', () async {
      for (final p in publishes) {
        final seed = hx(p['account'] == 'alice' ? alice['account_ed_seed'] : bob['account_ed_seed']);
        final req = await ktPublishRequest(
          accountEdSeed: seed,
          version: p['version'] as int,
          fp: hx(p['fingerprint']),
          value: hx(p['value']),
        );
        expect(unb64(req['sig'] as String), hx(p['publish_sig']));
        expect(jsonEncode(req), p['request_json']);
        expect(
            await ktPublishInput(
                label: await ktLabel(p['account'] == 'alice' ? alicePub : bobPub),
                version: p['version'] as int,
                fp: hx(p['fingerprint']),
                valueHash: hx(p['value_hash'])),
            hx(p['publish_input']));
      }
    });

    test('heads verify and extend one another; a wrong key, a shrunk log and two forks are refused', () async {
      for (final h in heads) {
        expect(await h.verify(logPub), isTrue);
        expect(await h.verify(bobPub), isFalse);
      }
      expect(await KtTreeHead.fromJson(obj(obj(v['resigned_head'])['head'])).verify(logPub), isTrue);
      // Each publish's sth_after is the head at that size, and its signing
      // input is the documented bytes.
      for (var i = 0; i < publishes.length; i++) {
        final h = KtTreeHead.fromJson(obj(publishes[i]['sth_after']));
        expect(h.sameRootsAs(heads[i + 1]), isTrue);
        expect(h.signingInput, hx(publishes[i]['sth_input_after']));
      }
      // Extension through the vectors' consistency proofs.
      for (final c in v['consistency'] as List) {
        final m = obj(c);
        await ktCheckHeadExtends(
          held: heads[m['first'] as int],
          fresh: heads[m['second'] as int],
          consistency: b64List(m['proof']),
          logPub: logPub,
        );
      }
      // A first head needs no proof; the same head twice is fine.
      await ktCheckHeadExtends(held: null, fresh: heads[3], consistency: null, logPub: logPub);
      await ktCheckHeadExtends(held: heads[3], fresh: heads[3], consistency: null, logPub: logPub);
      // Missing proof for a larger head.
      await expectLater(
          ktCheckHeadExtends(held: heads[1], fresh: heads[3], consistency: null, logPub: logPub),
          throwsA(isA<KtVerifyException>()));
      // A shrunk log.
      await expectLater(
          ktCheckHeadExtends(held: heads[3], fresh: heads[2], consistency: const [], logPub: logPub),
          throwsA(predicate((e) => e is KtVerifyException && e.reason.contains('shrank'))));
      for (final m0 in v['must_refuse'] as List) {
        final m = obj(m0);
        if (m['head_json'] == null) continue;
        final fork = KtTreeHead.fromJson(obj(jsonDecode(m['head_json'] as String)));
        if (m['client_holds'] == null) {
          expect(await fork.verify(logPub), isFalse, reason: m['why'] as String);
          continue;
        }
        expect(await fork.verify(logPub), isTrue, reason: 'the fork is signed by the real key');
        final held = KtTreeHead.fromJson(obj(m['client_holds']));
        await expectLater(
            ktCheckHeadExtends(
              held: held,
              fresh: fork,
              consistency: m['consistency_from_fork'] == null ? null : b64List(m['consistency_from_fork']),
              logPub: logPub,
            ),
            throwsA(predicate((e) => e is KtVerifyException && e.reason.contains('fork'))),
            reason: m['why'] as String);
      }
    });

    test('lookups verify to the latest entry or to absence; the superseded-entry lookup is refused', () async {
      final lookups = obj(v['lookups']);
      for (final name in ['alice', 'bob', 'nobody']) {
        final l = obj(lookups[name]);
        final label = name == 'nobody' ? hx(l['label']) : hx(obj(accounts[name])['label']);
        final lookup = await KtLookup.fromJson(obj(jsonDecode(l['response_json'] as String)));
        final r = await ktVerifyLookup(lookup, label: label, logPub: logPub);
        final expect_ = obj(l['expect']);
        if (expect_['absent'] == true) {
          expect(r.absent, isTrue);
          continue;
        }
        expect(r.latest!.version, expect_['version']);
        expect(r.latest!.index, expect_['index']);
        expect(r.head.size, 3);
        // Another label with this response fails.
        await expectLater(
            ktVerifyLookup(lookup, label: hx(obj(lookups['nobody'])['label']), logPub: logPub),
            throwsA(isA<KtVerifyException>()));
        // Another key fails.
        await expectLater(ktVerifyLookup(lookup, label: label, logPub: bobPub),
            throwsA(isA<KtVerifyException>()));
      }
      for (final m0 in v['must_refuse'] as List) {
        final m = obj(m0);
        if (m['response_json'] == null) continue;
        final lookup = await KtLookup.fromJson(obj(jsonDecode(m['response_json'] as String)));
        await expectLater(
            ktVerifyLookup(lookup, label: hx(alice['label']), logPub: logPub),
            throwsA(isA<KtVerifyException>()),
            reason: m['why'] as String);
      }
      // History: every entry included under the served head.
      final h = obj(jsonDecode(obj(v['history_alice'])['response_json'] as String));
      final head = KtTreeHead.fromJson(obj(h['sth']));
      expect(await head.verify(logPub), isTrue);
      final versions = <int>[];
      for (final item in h['entries'] as List) {
        final e = await ktVerifyHistoryItem(obj(item), head: head, label: hx(alice['label']));
        versions.add(e.version);
      }
      expect(versions, (obj(v['history_alice'])['expect_versions'] as List).cast<int>());
      // An entry whose value was swapped is refused at parse time.
      final swapped = obj(jsonDecode(jsonEncode((h['entries'] as List).first)));
      obj(swapped['entry'])['value'] = b64(Uint8List(40));
      await expectLater(ktVerifyHistoryItem(swapped, head: head, label: hx(alice['label'])),
          throwsA(isA<KtVerifyException>()));
    });

    test('a witness record verifies with both signatures, and not over another head', () async {
      final w = obj(v['witness']);
      final rec = KtWitnessRecord.fromJson(obj(jsonDecode(w['record_json'] as String)));
      expect(rec.witnessPub, hx(w['witness_pub']));
      expect(ktWitnessInput(rec.head), hx(w['witness_input']));
      expect(await rec.verify(logPub), isTrue);
      expect(await rec.verify(logPub, expectedWitnessPub: rec.witnessPub), isTrue);
      expect(await rec.verify(logPub, expectedWitnessPub: bobPub), isFalse);
      expect(await rec.verify(bobPub), isFalse);
      final other = KtWitnessRecord(
          head: heads[2], witnessPub: rec.witnessPub, witnessSig: rec.witnessSig, verifiedAt: rec.verifiedAt);
      expect(await other.verify(logPub), isFalse);
    });
  });
}
