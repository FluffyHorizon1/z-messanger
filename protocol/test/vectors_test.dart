// Protocol freeze: the committed test vectors in docs/vectors/v1 must be
// reproduced exactly by the current library. Any change to a wire format, KDF
// label, padding rule or key schedule shows up here as a diff.
//
// The second group consumes the vectors the way a third party would — from
// the recorded inputs through the public API only — so the files are proven
// usable without this generator.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:z_protocol/src/util.dart' show randomOverrideKey;
import 'package:z_protocol/z_protocol.dart';

import '../tool/vectors.dart';

Directory vectorsDir([String ver = 'v1']) {
  // `dart test` runs with cwd = protocol/.
  final d = Directory('../docs/vectors/$ver');
  if (!d.existsSync()) {
    fail('vectors directory not found at ${d.absolute.path} — run '
        '`dart run tool/gen_vectors.dart`');
  }
  return d;
}

Map<String, Object?> readVectors(String suite, [String ver = 'v1']) =>
    (jsonDecode(File('${vectorsDir(ver).path}/$suite.json').readAsStringSync())
            as Map)
        .cast<String, Object?>();

void main() {
  group('frozen vectors are reproduced exactly', () {
    late Map<String, Map<String, Map<String, Object?>>> generated;
    setUpAll(() async => generated = await generateAll());

    for (final (ver, suite) in [
      ('v1', 'identity'),
      ('v1', 'handshake'),
      ('v1', 'ratchet'),
      ('v1', 'sealed_sender'),
      ('v1', 'attachments'),
      ('v1', 'multidevice'),
      ('v1', 'pairing'),
      ('v1', 'inner_messages'),
      ('v2', 'mlkem768'),
      ('v2', 'pq_ratchet'),
      ('v2', 'pq_rekey'),
    ]) {
      test('$ver/$suite', () {
        final onDisk = readVectors(suite, ver);
        // Compare through canonical JSON so the diff, if any, is readable.
        expect(
            encodeVectorFile(generated[ver]![suite]!), encodeVectorFile(onDisk),
            reason: '$ver/$suite.json differs from what the library now '
                'produces; if the change is intentional, regenerate the '
                'vectors, update PROTOCOL.md and bump the version');
      });
    }

    test('no vector file is missing or unexpected', () {
      for (final ver in generated.keys) {
        final files = vectorsDir(ver)
            .listSync()
            .whereType<File>()
            .map((f) => f.uri.pathSegments.last)
            .where((n) => n.endsWith('.json'))
            .toSet();
        expect(files, {for (final k in generated[ver]!.keys) '$k.json'},
            reason: ver);
      }
    });
  });

  group('vectors are consumable from recorded inputs alone', () {
    test('identity: seeds -> keys, routing id, contact code, safety number',
        () async {
      final v = readVectors('identity');
      for (final id in (v['identities'] as List).cast<Map>()) {
        final me = await ZIdentity.fromSeeds(
            edSeed: unhex(id['ed_seed'] as String),
            xSeed: unhex(id['x_seed'] as String));
        expect(hex(me.edPub), id['ed_pub']);
        expect(hex(me.xPub), id['x_pub']);
        expect(await me.routingId(), id['routing_id']);
        expect(hex(await me.bindingSignature()), id['binding_sig']);
        final decoded =
            await ContactBundle.decode(id['contact_code'] as String);
        expect(hex(decoded.edPub), id['ed_pub']);
      }
      final ids = {
        for (final id in (v['identities'] as List).cast<Map>())
          id['name'] as String: unhex(id['ed_pub'] as String)
      };
      for (final s in (v['safety_numbers'] as List).cast<Map>()) {
        expect(
            await safetyNumber(ids[s['a']]!, ids[s['b']]!), s['safety_number']);
      }
    });

    test('ratchet: the transcript replays exactly from seeds + recorded draws',
        () async {
      final ratchet = readVectors('ratchet');
      final identity = readVectors('identity');
      final ids = <String, ZIdentity>{};
      for (final id in (identity['identities'] as List).cast<Map>()) {
        ids[id['name'] as String] = await ZIdentity.fromSeeds(
            edSeed: unhex(id['ed_seed'] as String),
            xSeed: unhex(id['x_seed'] as String));
      }
      final alice = ids['alice']!, bob = ids['bob']!;
      final convs = {
        'alice': await Conversation.create(alice, await bob.bundle(),
            postQuantum: false),
        'bob': await Conversation.create(bob, await alice.bundle(),
            postQuantum: false),
      };
      final steps = {
        for (final s in (ratchet['steps'] as List).cast<Map>())
          s['mid'] as String: s.cast<String, Object?>()
      };
      List<Uint8List> draws(Map<String, Object?> m) => [
            for (final d in (m['random_draws'] as List).cast<String>()) unhex(d)
          ];
      for (final op in (ratchet['transcript'] as List).cast<Map>()) {
        final step = steps[op['mid'] as String]!;
        final conv = convs[op['by'] as String]!;
        if (op['op'] == 'encrypt') {
          // Same plaintext + same random draws => byte-identical payload.
          final payload = await runScripted(draws(step),
              () => conv.encrypt(unhex(step['plaintext'] as String), nowMs: 1));
          expect(payload, step['payload'], reason: 'encrypt ${op['mid']}');
        } else {
          final recv = (step['receive'] as Map).cast<String, Object?>();
          final r = await runScripted(draws(recv),
              () => conv.decrypt(step['payload'] as String, nowMs: 2));
          expect(hex(r.plaintext), step['plaintext'],
              reason: 'decrypt ${op['mid']}');
          expect(r.createdNewSession, recv['created_session']);
          final st = (recv['state_after'] as Map).cast<String, Object?>();
          final now = conv.sessions[step['sid'] as String]!.ratchet;
          expect(hex(now.rootKey), st['root_key'], reason: 'root ${op['mid']}');
          expect(now.cks == null ? null : hex(now.cks!), st['cks']);
          expect(now.ckr == null ? null : hex(now.ckr!), st['ckr']);
          expect([now.ns, now.nr, now.pn], [st['ns'], st['nr'], st['pn']]);
          expect(now.skipped.keys.toSet(), (st['skipped'] as Map).keys.toSet());
        }
      }
    });

    test('sealed sender: recipient opens every envelope', () async {
      final v = readVectors('sealed_sender');
      for (final e in (v['vectors'] as List).cast<Map>()) {
        final opened = await SealedEnvelope.open(
            myXSeed: unhex(e['to_x_seed'] as String),
            myXPub: unhex(e['to_x_pub'] as String),
            blob: e['envelope'] as String);
        expect(opened, isNotNull);
        expect(opened!.fromRid, e['from_rid']);
        expect(opened.payload, e['payload']);
      }
    });

    test('attachments: chunks decrypt with the recorded key material',
        () async {
      final v = readVectors('attachments');
      for (final c in (v['chunks'] as List).cast<Map>()) {
        final chunk = tryParseChunk(c['payload'] as String)!;
        expect(chunk.index, c['index']);
        final plain = await decryptChunk(
            fk: unhex(v['fk'] as String),
            fn: unhex(v['fn'] as String),
            fid: v['fid'] as String,
            chunk: chunk);
        expect(hex(plain), c['plaintext']);
      }
    });

    test('multidevice: certificates, account code and device list verify',
        () async {
      final v = readVectors('multidevice');
      final acct = unhex(v['account_ed_pub'] as String);
      for (final k in ['device1', 'device2']) {
        final d = (v[k] as Map).cast<String, Object?>();
        final cert = DeviceCertificate.fromJson(
            (d['json'] as Map).cast<String, Object?>());
        expect(await cert.verify(acct), isTrue, reason: k);
        expect(await cert.routingId(), d['routing_id']);
      }
      final bundle = await AccountBundle.decode(v['account_code'] as String);
      expect(bundle.devices.length, 2);
      final list = SignedDeviceList.fromJson(
          ((v['device_list'] as Map)['json'] as Map).cast<String, Object?>());
      expect(await list.verify(), isTrue);
    });

    test('pairing: both sides derive the recorded channel key and SAS',
        () async {
      final v = readVectors('pairing');
      final code =
          PairingCode(unhex((v['pairing_code'] as Map)['secret'] as String));
      expect(code.text, (v['pairing_code'] as Map)['text']);
      expect(await code.rendezvousRoutingId(),
          (v['pairing_code'] as Map)['rendezvous_routing_id']);
      final nd = (v['new_device'] as Map).cast<String, Object?>();
      final ed = (v['existing_device'] as Map).cast<String, Object?>();

      // NEW device: feed the three recorded draws (device ed seed, device x
      // seed, pairing ephemeral) in place of the RNG and it must produce the
      // recorded hello, then derive the recorded channel key + SAS from the
      // recorded reply.
      final scripted = [
        unhex(nd['device_ed_seed'] as String),
        unhex(nd['device_x_seed'] as String),
        unhex(nd['eph_seed'] as String),
      ];
      final n = await runScripted(scripted,
          () => PairingInitiator.create(code: code, deviceId: 'new-phone'));
      expect(n.hello(), nd['hello']);
      final sessionI =
          await n.complete((ed['reply'] as Map).cast<String, Object?>());
      expect(hex(sessionI.channelKey), v['channel_key']);
      expect(sessionI.sas, v['sas']);

      // EXISTING device: with the recorded ephemeral it derives the same.
      final (reply, sessionR) = await runScripted(
          [unhex(ed['eph_seed'] as String)],
          () => PairingResponder.respond(n.hello()));
      expect(reply, ed['reply']);
      expect(hex(sessionR.channelKey), v['channel_key']);
      expect(sessionR.sas, v['sas']);

      // The sealed enrollment opens under the channel key.
      final blob = unhex((v['enrollment'] as Map)['sealed'] as String);
      final data = await sessionI.openEnrollment(blob);
      expect(hex(data.accountEdPub), (v['account'] as Map)['account_ed_pub']);
      expect(hex(data.deviceCert.deviceEdPub), nd['device_ed_pub']);
      expect(await data.deviceCert.verify(data.accountEdPub), isTrue);
      expect(data.contacts.length, 1);
      final installed = await n.installFromData(data);
      expect(installed.holdsAccountRoot, isFalse);
    });
  });
}

/// Runs [body] with the protocol's random draws served from [draws] in order.
Future<T> runScripted<T>(List<Uint8List> draws, Future<T> Function() body) {
  var i = 0;
  return runZoned(body, zoneValues: {
    randomOverrideKey: (int n) {
      if (i >= draws.length) fail('more random draws than scripted');
      final d = draws[i++];
      if (d.length != n)
        fail('scripted draw $i has ${d.length} bytes, want $n');
      return d;
    }
  });
}
