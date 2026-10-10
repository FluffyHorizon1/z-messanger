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

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';
import 'package:z_protocol/src/util.dart' show concatBytes, randomOverrideKey;
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
      ('v1', 'device_pop'),
      ('v1', 'group_state'),
      ('pair-v2', 'pairing_v2'),
      ('relay-auth-v2', 'relay_auth_v2'),
      ('connect', 'connect'),
      ('connect', 'mailboxes'),
      ('connect', 'group'),
      ('connect', 'invite_v2'),
      ('v2', 'mlkem768'),
      ('v2', 'pq_ratchet'),
      ('v2', 'pq_rekey'),
      ('v3', 'mldsa65'),
      ('v3', 'contact_code_v3'),
      ('v3', 'contact_code_pqc_sig'),
      ('v3', 'device_cert_v3'),
      ('backup', 'archive'),
      ('backup', 'archive_1_1'),
      ('handles', 'handles'),
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
            postQuantum: false, intervals: PqIntervals.disabled),
        'bob': await Conversation.create(bob, await alice.bundle(),
            postQuantum: false, intervals: PqIntervals.disabled),
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

    test(
        'device_pop: the proof is the device\'s, changes no signature or '
        'fingerprint, and every alteration is refused (ADR 0022)', () async {
      final v = readVectors('device_pop');
      final md = readVectors('multidevice');
      final acct = unhex(v['account_ed_pub'] as String);
      final d2 = (v['device2'] as Map).cast<String, Object?>();
      final edSeed = unhex(d2['ed_seed'] as String);
      // The input from its formula, and the signature by the DEVICE's seed.
      final input = concatBytes([
        utf8.encode(v['context'] as String),
        acct,
        unhex(d2['device_ed_pub'] as String),
        unhex(d2['device_x_pub'] as String),
        utf8.encode(d2['device_id'] as String),
      ]);
      expect(hex(input), d2['pop_input']);
      final kp = await Ed25519().newKeyPairFromSeed(edSeed);
      expect(hex((await Ed25519().sign(input, keyPair: kp)).bytes), d2['pop']);
      final cert = DeviceCertificate.fromJson(
          (d2['cert_json'] as Map).cast<String, Object?>());
      expect(hex(cert.pop!), d2['pop']);
      expect(await cert.provesPossession(acct), isTrue);
      final bare = DeviceCertificate.fromJson(
          (d2['cert_json_without_pop'] as Map).cast<String, Object?>());
      expect(await bare.verify(acct), isTrue);
      expect(await bare.provesPossession(acct), isFalse);
      // The list, with the proof and without: the same signatures and
      // fingerprint, and without it, multidevice.json's own list.
      for (final k in ['device_list', 'device_list_v2_only']) {
        final l = (v[k] as Map).cast<String, Object?>();
        final withPop =
            SignedDeviceList.fromJson((l['json'] as Map).cast<String, Object?>());
        final without = SignedDeviceList.fromJson(
            (l['json_without_pop'] as Map).cast<String, Object?>());
        expect(await withPop.verify(), isTrue, reason: k);
        expect(await without.verify(), isTrue, reason: k);
        expect(hex(await withPop.fingerprint()), l['fingerprint'], reason: k);
        expect(hex(await without.fingerprint()), l['fingerprint'], reason: k);
        expect(jsonEncode(without.toJson()),
            jsonEncode((md[k] as Map)['json']),
            reason: '$k without the member is multidevice.json\'s');
      }
      expect((await AccountBundle.decode(v['account_code'] as String))
          .devices[1]
          .pop, isNotNull);
      // A claim by another account: without the proof it verifies and proves
      // nothing; with device 2's proof carried over it does not verify.
      final claim = (v['claim'] as Map).cast<String, Object?>();
      final claimant = unhex(claim['claimant_account_ed_pub'] as String);
      final bareClaim = SignedDeviceList.fromJson(
          (claim['json_without_pop'] as Map).cast<String, Object?>());
      expect(await bareClaim.verify(), isTrue);
      for (final dc in bareClaim.devices) {
        if (hex(dc.deviceEdPub) == d2['device_ed_pub']) {
          expect(await dc.provesPossession(claimant), isFalse);
        }
      }
      expect(
          await SignedDeviceList.fromJson(
                  (claim['json_with_pop'] as Map).cast<String, Object?>())
              .verify(),
          isFalse);
      for (final r in (v['must_refuse'] as List).cast<Map>()) {
        final l = SignedDeviceList.fromJson(
            (r['list_json'] as Map).cast<String, Object?>());
        expect(await l.verify(), isFalse, reason: r['case'] as String);
      }
      for (final r in (v['must_not_parse'] as List).cast<Map>()) {
        expect(
            () => DeviceCertificate.fromJson(
                (r['cert_json'] as Map).cast<String, Object?>()),
            throwsFormatException,
            reason: r['case'] as String);
      }
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

    test('pairing v2: the commitment, the reply and the opening replay exactly',
        () async {
      final v = readVectors('pairing_v2', 'pair-v2');
      final code =
          PairingCode(unhex((v['pairing_code'] as Map)['secret'] as String));
      expect(await code.rendezvousRoutingIdV2(),
          (v['pairing_code'] as Map)['rendezvous_routing_id']);
      final nd = (v['new_device'] as Map).cast<String, Object?>();
      final ed = (v['existing_device'] as Map).cast<String, Object?>();

      // NEW device, from the three recorded draws: the commitment it
      // publishes must be the recorded one, byte for byte.
      final n = await runScripted([
        unhex(nd['device_ed_seed'] as String),
        unhex(nd['device_x_seed'] as String),
        unhex(nd['eph_seed'] as String),
      ], () => PairingInitiatorV2.create(code: code, deviceId: 'new-phone'));
      final commit = await n.commit();
      expect({'k': 'commit-v2', ...commit}, nd['commit_frame']);

      // EXISTING device, from its recorded ephemeral: the reply, then the
      // session it derives once the opening arrives.
      final (reply, pending) = await runScripted(
          [unhex(ed['eph_seed'] as String)],
          () => PairingResponderV2.reply(commit));
      expect({'k': 'reply-v2', ...reply}, ed['reply_frame']);
      final (open, sessionI) = await n.open(reply);
      expect({'k': 'open-v2', ...open}, nd['open_frame']);
      final sessionR = await pending.accept(open);
      expect(hex(sessionI.channelKey), v['channel_key']);
      expect(hex(sessionR.channelKey), v['channel_key']);
      expect(sessionI.sas, v['sas']);
      expect(sessionR.sas, v['sas']);

      // An opening that does not match the recorded commitment is refused —
      // the property the recorded commitment exists to make checkable.
      await expectLater(
          pending.accept({...open, 'dx': open['ded']}),
          throwsA(isA<PairingAbort>()));

      // And the recorded enrollment opens, with a certificate over the
      // ratchet key the recorded SAS covered.
      final data = await sessionI
          .openEnrollment(unhex((v['enrollment'] as Map)['sealed'] as String));
      expect(hex(data.deviceCert.deviceXPub), nd['device_x_pub']);
      expect(await data.deviceCert.verify(data.accountEdPub), isTrue);
      final installed = await n.installFromData(data);
      expect(installed.holdsAccountRoot, isFalse);
    });

    test('relay auth v2: the authority is derived from the URL, and the recorded signature is over it',
        () async {
      final v = readVectors('relay_auth_v2', 'relay-auth-v2');
      final identity = readVectors('identity');
      final ids = <String, ZIdentity>{};
      for (final id in (identity['identities'] as List).cast<Map>()) {
        ids[id['name'] as String] = await ZIdentity.fromSeeds(
            edSeed: unhex(id['ed_seed'] as String),
            xSeed: unhex(id['x_seed'] as String));
      }
      for (final a in (v['relay_auth_v2'] as List).cast<Map>()) {
        final me = ids[a['identity']]!;
        expect(relayAuthority(a['url'] as String), a['authority']);
        final nonce = unhex(a['nonce'] as String);
        final msg = concatBytes([
          utf8.encode(authContextV2),
          utf8.encode(a['authority'] as String),
          nonce,
        ]);
        expect(hex(msg), a['signed_message']);
        expect(hex(await me.signAuthChallengeV2(nonce, a['authority'] as String)),
            a['sig'], reason: 'deterministic: Ed25519 has no nonce of its own');
        final ok = await Ed25519().verify(msg,
            signature: Signature(unhex(a['sig'] as String),
                publicKey: SimplePublicKey(me.edPub, type: KeyPairType.ed25519)));
        expect(ok, isTrue);
        // The same signature over any other authority is nothing: what the
        // binding is for.
        final other = concatBytes([
          utf8.encode(authContextV2),
          utf8.encode('other.example'),
          nonce,
        ]);
        expect(
            await Ed25519().verify(other,
                signature: Signature(unhex(a['sig'] as String),
                    publicKey: SimplePublicKey(me.edPub, type: KeyPairType.ed25519))),
            isFalse);
        expect((a['auth_frame'] as Map)['v'], 2);
        expect((a['challenge_frame'] as Map)['auth'], 2);
      }
      for (final n in (v['normalization'] as List).cast<Map>()) {
        expect(relayAuthority(n['url'] as String), n['authority'], reason: n['url'] as String);
      }
    });

    test('connect: the recorded ceremony replays, and the string is the pair\'s',
        () async {
      final v = readVectors('connect', 'connect');
      final cc = (v['connect_code'] as Map).cast<String, Object?>();
      final code = ConnectCode(unhex(cc['secret'] as String));
      expect(code.text, cc['text']);
      expect(code.link(), cc['link']);
      expect(await code.rendezvousRoutingId(), cc['rendezvous_routing_id']);
      // The link's secret is the printed code's secret: one invite, two
      // renderings, and the code lives in the fragment.
      expect(hex(ConnectCode.fromLink(cc['link'] as String)!.secret),
          cc['secret']);

      final parties = (v['parties'] as List).cast<Map<String, Object?>>();
      final ids = <ConnectIdentity>[];
      for (final p in parties) {
        final ci = await ConnectIdentity.fromCode(p['contact_code'] as String,
            displayName: p['display_name'] as String?);
        expect(hex(ci.accountEdPub), p['account_ed_pub']);
        expect(hex(ci.pqCommit), p['pq_commit']);
        ids.add(ci);
      }

      // Replay all four messages from the recorded ephemerals.
      final frames = (v['frames'] as Map).cast<String, Object?>();
      final inviter = await runScripted(
          [unhex((v['inviter_ephemeral'] as Map)['seed'] as String)],
          () => ConnectInviter.create(me: ids[0], code: code));
      expect({'k': 'x1', ...await inviter.commit()}, frames['commit']);
      final (reply, acceptor) = await runScripted(
          [unhex((v['acceptor_ephemeral'] as Map)['seed'] as String)],
          () => ConnectAcceptor.reply(
              (frames['commit'] as Map).cast<String, Object?>()..remove('k'),
              me: ids[1],
              code: code));
      expect(b64(unb64(reply['ephx'] as String)),
          (frames['reply'] as Map)['ephx']);
      expect(reply['c'], (frames['reply'] as Map)['c']);

      final open = await inviter.open(reply);
      final (revealB, sessionB) = await acceptor.accept(open);
      final sessionA = await inviter.complete(revealB);
      expect(sessionA.sas, v['sas']);
      expect(sessionB.sas, v['sas']);
      expect(hex(sessionA.channelKey), v['channel_key']);

      // Each side ends holding the other's code.
      expect(sessionA.peer.contactCode, parties[1]['contact_code']);
      expect(sessionB.peer.contactCode, parties[0]['contact_code']);

      // And the recorded `sas_info` is the canonical order: the two parties
      // sorted by account key, which is what makes the string a property of
      // the pair rather than of who invited whom.
      final order = (v['canonical_order'] as List).cast<String>();
      final loKey = order.first == 'inviter'
          ? parties[0]['account_ed_pub']
          : parties[1]['account_ed_pub'];
      expect(v['sas_info'] as String,
          contains(loKey as String),
          reason: 'the lower account key appears in the input');
      expect((v['sas_info'] as String).indexOf(loKey),
          lessThan((v['sas_info'] as String).indexOf(order.first == 'inviter'
              ? parties[1]['account_ed_pub'] as String
              : parties[0]['account_ed_pub'] as String)),
          reason: 'and it appears first');
    });

    test('connect: the recorded invite derives both relay mailboxes', () async {
      final v = readVectors('mailboxes', 'connect');
      final cc = (v['connect_code'] as Map).cast<String, Object?>();
      final code = ConnectCode(unhex(cc['secret'] as String));
      expect(code.text, cc['text']);
      expect(cc['relay_context'], connectRelayCtx);

      // Get this derivation wrong and both sides authenticate happily, listen
      // politely, and never meet — so it is pinned byte for byte.
      final ids = <String>{};
      for (final m in (v['mailboxes'] as List).cast<Map<String, Object?>>()) {
        final id = await mailboxIdentity(code, m['role'] as String);
        expect(hex(id.edSeed), m['ed_seed'], reason: '${m['who']} ed seed');
        expect(hex(id.xSeed), m['x_seed'], reason: '${m['who']} x seed');
        expect(hex(id.edPub), m['ed_pub'], reason: '${m['who']} ed key');
        expect(hex(id.xPub), m['x_pub'], reason: '${m['who']} x key');
        expect(await id.routingId(), m['routing_id']);
        ids.add(await id.routingId());
      }
      expect(ids.length, 2, reason: 'one mailbox per role, not one shared');

      // And no other id the same ten bytes can derive collides with them.
      final others = (v['distinct_from'] as Map).cast<String, Object?>();
      final pairing = PairingCode(code.secret);
      expect(await code.rendezvousRoutingId(), others['rendezvous']);
      expect(await pairing.rendezvousRoutingId(), others['pairing_v1']);
      expect(await pairing.rendezvousRoutingIdV2(), others['pairing_v2']);
      expect(ids.intersection(others.values.cast<String>().toSet()), isEmpty);
    });

    test('connect group: the recorded ceremony replays with the group bit',
        () async {
      final v = readVectors('group', 'connect');
      final code = ConnectCode(
          unhex((v['connect_code'] as Map)['secret'] as String));
      final parties = (v['parties'] as List).cast<Map<String, Object?>>();
      final ids = [
        for (final p in parties)
          await ConnectIdentity.fromCode(p['contact_code'] as String,
              displayName: p['display_name'] as String?)
      ];
      final frames = (v['frames'] as Map).cast<String, Object?>();
      final reveals = (v['reveals'] as Map).cast<String, Object?>();
      Map<String, Object?> frame(String k) =>
          (frames[k] as Map).cast<String, Object?>()..remove('k');

      // All four messages, from the recorded ephemerals and seal nonces.
      final inviter = await runScripted(
          [unhex((v['inviter_ephemeral'] as Map)['seed'] as String)],
          () => ConnectInviter.create(me: ids[0], code: code, group: true));
      expect({'k': 'x1', ...await inviter.commit()}, frames['commit']);
      final (reply, acceptor) = await runScripted(
          [unhex((v['acceptor_ephemeral'] as Map)['seed'] as String)],
          () => ConnectAcceptor.reply(frame('commit'),
              me: ids[1], code: code, groupAware: true));
      expect({'k': 'x2', ...reply}, frames['reply']);
      final open = await runScripted(
          [unhex(reveals['open_nonce'] as String)], () => inviter.open(reply));
      expect({'k': 'x3', ...open}, frames['open']);
      final (reveal, sessionJ) = await runScripted(
          [unhex(reveals['reveal_nonce'] as String)],
          () => acceptor.accept(open));
      expect({'k': 'x4', ...reveal}, frames['reveal']);
      final sessionA = await inviter.complete(reveal);
      expect(sessionA.sas, v['sas']);
      expect(hex(sessionA.channelKey), v['channel_key']);
      expect(sessionJ.group, isTrue, reason: 'message 3 said: a group');
      expect(sessionA.group, isTrue, reason: 'message 4 said it back');

      // The go-ahead tag (§20.6): from the recorded channel key, at both ends.
      final goAhead = (v['go_ahead'] as Map).cast<String, Object?>();
      expect(goAhead['label'], connectGoAheadLabel);
      expect(hex(await sessionA.goAheadTag()), goAhead['tag']);
      expect(hex(await sessionJ.goAheadTag()), goAhead['tag']);
      expect(b64url(await sessionJ.goAheadTag()), goAhead['tag_b64url']);

      // The plaintexts carry the member under its recorded name, as 1.
      expect(v['group_member'], connectGroupMember);
      for (final k in ['open_plaintext', 'reveal_plaintext']) {
        final m = jsonDecode(reveals[k] as String) as Map;
        expect(m[connectGroupMember], 1, reason: k);
        expect(m.keys.toSet(), {'code', 'name', connectGroupMember},
            reason: 'nothing about the group but the bit: $k');
      }

      // And a reader from before the bit replays the inviter's half of the
      // same ceremony, from the same recorded inputs, without noticing it.
      final (_, old) = await runScripted(
          [unhex((v['acceptor_ephemeral'] as Map)['seed'] as String)],
          () => ConnectAcceptor.reply(frame('commit'),
              me: ids[1], code: code));
      final (_, oldSession) = await runScripted(
          [unhex(reveals['reveal_nonce'] as String)],
          () => old.accept(frame('open')));
      expect(oldSession.sas, v['sas']);
      expect(oldSession.group, isNull);
    });

    test('connect v2: the recorded ceremony replays, bound to its secret',
        () async {
      final v = readVectors('invite_v2', 'connect');
      final cc = (v['connect_code'] as Map).cast<String, Object?>();
      final code = ConnectCode(unhex(cc['secret'] as String), version: 2);
      expect(code.text, cc['text']);
      expect(code.link(), cc['link']);
      expect((cc['text'] as String).startsWith(cc['marker'] as String), isTrue);
      for (final r in [cc['text'] as String, cc['link'] as String]) {
        final back = r.startsWith('https://')
            ? ConnectCode.fromLink(r)!
            : ConnectCode.parse(r);
        expect(back.version, 2, reason: r);
        expect(hex(back.secret), cc['secret']);
      }
      expect(ConnectCode(code.secret).text, cc['text_as_version_1']);
      expect(await code.rendezvousRoutingId(), cc['rendezvous_routing_id']);
      final key = (v['invite_key'] as Map).cast<String, Object?>();
      expect(hex(utf8.encode(connectInviteKeyCtx)), key['info']);
      expect(hex((await code.inviteKey())!), key['key']);

      // Both mailboxes, under the version-2 context, and none of them one
      // that version 1 derives from the same ten bytes.
      final ids = <String>{};
      for (final m in (v['mailboxes'] as List).cast<Map<String, Object?>>()) {
        final id = await mailboxIdentity(code, m['role'] as String);
        expect(hex(id.edSeed), m['ed_seed']);
        expect(hex(id.xSeed), m['x_seed']);
        expect(await id.routingId(), m['routing_id']);
        ids.add(await id.routingId());
      }
      final others = (v['distinct_from'] as Map).cast<String, Object?>();
      expect(others['v1_mailbox_i'],
          await (await mailboxIdentity(ConnectCode(code.secret), 'i')).routingId());
      expect(ids.intersection(others.values.cast<String>().toSet()), isEmpty);

      // All four messages from the recorded ephemerals and nonces.
      final parties = (v['parties'] as List).cast<Map<String, Object?>>();
      final who = [
        for (final p in parties)
          await ConnectIdentity.fromCode(p['contact_code'] as String,
              displayName: p['display_name'] as String?)
      ];
      final frames = (v['frames'] as Map).cast<String, Object?>();
      final reveals = (v['reveals'] as Map).cast<String, Object?>();
      Map<String, Object?> frame(String k) =>
          (frames[k] as Map).cast<String, Object?>()..remove('k');
      final iEph = unhex((v['inviter_ephemeral'] as Map)['seed'] as String);
      final rEph = unhex((v['acceptor_ephemeral'] as Map)['seed'] as String);
      final inviter = await runScripted([iEph],
          () => ConnectInviter.create(me: who[0], code: code, group: false));
      expect({'k': 'x1', ...await inviter.commit()}, frames['commit']);
      final (reply, acceptor) = await runScripted(
          [rEph],
          () => ConnectAcceptor.reply(frame('commit'),
              me: who[1], code: code, groupAware: true));
      expect({'k': 'x2', ...reply}, frames['reply']);
      final open = await runScripted(
          [unhex(reveals['open_nonce'] as String)], () => inviter.open(reply));
      expect({'k': 'x3', ...open}, frames['open']);
      final (reveal, sessionR) = await runScripted(
          [unhex(reveals['reveal_nonce'] as String)],
          () => acceptor.accept(open));
      expect({'k': 'x4', ...reveal}, frames['reveal']);
      final sessionI = await inviter.complete(reveal);
      expect(sessionI.sas, v['sas']);
      expect(sessionR.sas, v['sas']);
      expect(hex(sessionI.channelKey), v['channel_key']);
      expect(hex(await sessionR.goAheadTag()), v['go_ahead_tag']);
      final commits = (v['commitments'] as Map).cast<String, Object?>();
      expect(hex(base64Decode((frames['commit'] as Map)['c'] as String)),
          commits['inviter']);

      // Version 1's values from the same inputs are none of these, and a
      // reader of version 1 cannot run the recorded frames: it aborts.
      final v1 = (v['version_1_of_the_same_inputs'] as Map).cast<String, Object?>();
      expect(v1['channel_key'], isNot(v['channel_key']));
      expect(v1['inviter_commitment'], isNot(commits['inviter']));
      final (_, old) = await runScripted(
          [rEph],
          () => ConnectAcceptor.reply(frame('commit'),
              me: who[1], code: ConnectCode(code.secret), groupAware: true));
      await expectLater(old.accept(frame('open')), throwsA(isA<ConnectAbort>()));
    });

    test('contact code pqc signature: the recorded code verifies, and every '
        'recorded alteration is refused', () async {
      final v = readVectors('contact_code_pqc_sig', 'v3');
      expect(v['context'], pqCommitSigContext);
      final idj = (v['identity'] as Map).cast<String, Object?>();
      final me = await ZIdentity.fromSeeds(
          edSeed: unhex(idj['ed_seed'] as String),
          xSeed: unhex(idj['x_seed'] as String));
      expect(hex(me.edPub), idj['ed_pub']);
      final pqj = (v['pq'] as Map).cast<String, Object?>();
      final pq = await HybridKeyPair.fromSeeds(
          edSeed: me.edSeed, mlSeed: unhex(pqj['ml_seed'] as String));
      expect(hex(await pq.publicKey.pqCommitment()), pqj['commitment']);

      // The signing input from §18.10's formula, and the signature over it.
      final input =
          pqCommitSigningInput(me.edPub, unhex(pqj['commitment'] as String));
      expect(hex(input), v['signing_input']);
      final rebuilt = await ContactBundleV3.forIdentity(me, pq.publicKey,
          displayName: 'Finn');
      expect(hex(rebuilt.pqCommitSig!), v['pqcs']);
      expect(rebuilt.encode(), v['code']);

      final decoded = await ContactBundleV3.decode(v['code'] as String);
      expect(decoded.commitSigned, isTrue);
      expect((await scanContactCode(v['unsigned_code'] as String)).commitSigned,
          isFalse,
          reason: 'the code issued before ADR 0027 still decodes, unsigned');
      expect(
          (await scanContactCode(v['strict_code'] as String)).commitSigned,
          isTrue);
      final anchored = (v['anchored'] as Map).cast<String, Object?>();
      expect((await scanContactCode(anchored['code'] as String)).commitSigned,
          isTrue);

      final refuse = (v['must_refuse'] as Map).cast<String, Object?>();
      var n = 0;
      for (final e in refuse.entries) {
        if (e.value is! Map) continue;
        n++;
        final code = (e.value as Map)['code'] as String;
        await expectLater(scanContactCode(code), throwsA(isA<FormatException>()),
            reason: e.key);
      }
      expect(n, 6, reason: 'every recorded alteration was tried');
    });

    test('backup archive: the recorded code opens every frame of the file',
        () async {
      final v = readVectors('archive', 'backup');
      final rc = v['recovery_code'] as Map;
      final kdf = v['kdf'] as Map;
      final head = v['header'] as Map;

      // The code round-trips from its printed form — including the way a
      // person actually copies it back in.
      final parsed = await RecoveryCode.parse(rc['mangled_input'] as String);
      expect(hex(parsed.entropy), rc['entropy']);
      expect(await parsed.format(), rc['formatted']);
      expect(hex(await parsed.keyMaterial()), rc['key_material']);

      // Argon2id is a standard RFC 9106 KAT here: password, salt and
      // parameters in, the archive key out.
      final key = await ZArchive.deriveKey(
          await parsed.keyMaterial(), unhex(kdf['salt'] as String));
      expect(hex(await key.extractBytes()), kdf['key']);

      // Reading the file with nothing but the recorded bytes: header line,
      // then length-prefixed frames.
      final bytes = unhex((v['file'] as Map)['bytes'] as String);
      final nl = bytes.indexOf(0x0a);
      final header = Uint8List.fromList(bytes.sublist(0, nl));
      expect(hex(header), head['bytes']);
      final parsedHeader = ZArchive.parseHeader(header);
      expect(parsedHeader['schema'], 3);
      final np = unb64(parsedHeader['np'] as String);
      expect(hex(np), head['nonce_prefix']);

      var off = nl + 1;
      var index = 0;
      for (final f in (v['frames'] as List).cast<Map>()) {
        final len =
            ByteData.view(Uint8List.fromList(bytes).buffer).getUint32(off);
        off += 4;
        final sealed = Uint8List.fromList(bytes.sublist(off, off + len));
        off += len;
        expect(hex(sealed), '${f['ciphertext']}${f['mac']}');
        final (kind, payload) = await ZArchive.openFrame(
            key: key,
            header: header,
            noncePrefix: np,
            index: index,
            sealed: sealed);
        expect(kind, f['kind']);
        expect(hex([kind, ...payload]), f['plaintext']);
        if (kind == ZArchive.kindBlob) {
          final blob = v['blob_body'] as Map;
          final (fid, blobBytes) = ZArchive.parseBlobPayload(payload);
          expect(fid, blob['fid']);
          expect(hex(blobBytes), blob['bytes']);
        } else {
          expect(utf8.decode(payload), f['payload_json']);
        }
        index++;
      }
      expect(off, bytes.length, reason: 'the file is exactly its frames');
      expect(index, (v['frames'] as List).length);

      // …and the two failures the format exists to catch.
      await expectLater(
          ZArchive.openFrame(
              key: key,
              header: header,
              noncePrefix: np,
              index: 0,
              sealed: unhex((v['must_fail'] as Map)['frame_1_opened_at_index_0']
                  as String)),
          throwsA(isA<FormatException>()),
          reason: 'a frame moved to another index must not open');
      final wrongKey = await ZArchive.deriveKey(
          await RecoveryCode(unhex(
                  (v['must_fail'] as Map)['wrong_code_entropy'] as String))
              .keyMaterial(),
          unhex(kdf['salt'] as String));
      await expectLater(
          ZArchive.openFrame(
              key: wrongKey,
              header: header,
              noncePrefix: np,
              index: 0,
              sealed: unhex('${(v['frames'] as List).first['ciphertext']}'
                  '${(v['frames'] as List).first['mac']}')),
          throwsA(isA<FormatException>()),
          reason: 'the wrong recovery code must not open a frame');
    });

    test(
        'backup archive 1.1: a minor revision reads with the same frame '
        'layer, its records are what they say, and a newer major is refused',
        () async {
      final v = readVectors('archive_1_1', 'backup');
      final rc = v['recovery_code'] as Map;
      final kdf = v['kdf'] as Map;
      final head = v['header'] as Map;
      final parsed = await RecoveryCode.parse(rc['formatted'] as String);
      expect(hex(parsed.entropy), rc['entropy']);
      final key = await ZArchive.deriveKey(
          await parsed.keyMaterial(), unhex(kdf['salt'] as String));
      expect(hex(await key.extractBytes()), kdf['key']);

      final bytes = unhex((v['file'] as Map)['bytes'] as String);
      final nl = bytes.indexOf(0x0a);
      final header = Uint8List.fromList(bytes.sublist(0, nl));
      expect(hex(header), head['bytes']);
      final h = ZArchive.parseHeader(header);
      expect(h['v'], head['major']);
      expect(ZArchive.minorOf(h), head['minor']);
      expect(ZArchive.isNewerMajor(h), isFalse);
      final np = unb64(h['np'] as String);

      var off = nl + 1;
      var index = 0;
      final types = <String>[];
      for (final f in (v['frames'] as List).cast<Map>()) {
        final len =
            ByteData.view(Uint8List.fromList(bytes).buffer).getUint32(off);
        off += 4;
        final sealed = Uint8List.fromList(bytes.sublist(off, off + len));
        off += len;
        expect(hex(sealed), '${f['ciphertext']}${f['mac']}');
        final (kind, payload) = await ZArchive.openFrame(
            key: key,
            header: header,
            noncePrefix: np,
            index: index++,
            sealed: sealed);
        expect(kind, f['kind']);
        expect(utf8.decode(payload), f['payload_json']);
        final r = jsonDecode(utf8.decode(payload)) as Map;
        types.add(r['t'] as String);
        if (kind == ZArchive.kindEnd) {
          expect(r['records'], (v['frames'] as List).length - 1);
        }
      }
      expect(off, bytes.length, reason: 'the file is exactly its frames');
      expect(types, [
        'meta',
        'identity',
        'state',
        'contact',
        'blocked',
        'request',
        'example',
        'end',
      ]);

      // The linked device's identity names the account it belongs to, and
      // the account's certificate for it verifies: what keeps a restore from
      // making it a root of its own.
      final identity = jsonDecode(
          ((v['frames'] as List)[1] as Map)['payload_json'] as String) as Map;
      final account = await AccountIdentity.fromJson(
          (identity['account'] as Map).cast<String, Object?>());
      expect(account.holdsAccountRoot, isFalse);
      expect(await account.deviceCert.verify(account.accountEdPub), isTrue);
      expect(b64(account.deviceEdSeed),
          (identity['identity'] as Map)['edSeed']);

      // The record a reader does not know, marked to be kept.
      final kept = jsonDecode(((v['frames'] as List)[v['kept_record_index']
          as int] as Map)['payload_json'] as String) as Map;
      expect(kept[v['keep_member']], 1);

      // And the same header one major version on: refused before any key.
      final newer =
          unhex((v['must_fail'] as Map)['newer_major_header'] as String);
      expect(
          ZArchive.isNewerMajor(
              (jsonDecode(utf8.decode(newer)) as Map).cast<String, Object?>()),
          isTrue);
      expect(() => ZArchive.parseHeader(Uint8List.fromList(newer)),
          throwsA(isA<ArchiveTooNewException>()));
    });

    test('handles: the grammar, labels, keys, entries, histories, stamps and '
        'the acknowledgement replay from the recorded inputs', () async {
      final v = readVectors('handles', 'handles');

      // §21.1: every input, valid or not, through the public parser.
      final g = v['grammar'] as Map;
      expect(g['reserved'], reservedHandleNicks);
      for (final c in (g['valid'] as List).cast<Map>()) {
        final h = Handle.parse(c['input'] as String);
        expect(h.canonical, c['canonical'], reason: c['note'] as String);
        expect(h.display, c['display']);
      }
      for (final c in (g['invalid'] as List).cast<Map>()) {
        expect(Handle.problemWith(c['input'] as String)?.name, c['problem'],
            reason: c['note'] as String);
        expect(normaliseHandleInput(c['input'] as String), c['normalised']);
      }

      // §21.2: the production labels, and the small-parameter answers the
      // independent Argon2id is checked against.
      final l = v['labels'] as Map;
      final kdf = l['kdf'] as Map;
      expect([kdf['memory_kib'], kdf['iterations'], kdf['parallelism'], kdf['tag_len']],
          [handleLabelMemoryKib, handleLabelIterations, handleLabelParallelism, handleLabelLength]);
      expect(kdf['salt'], handleLabelSalt);
      for (final c in (l['production'] as List).cast<Map>()) {
        final h = Handle.parse(c['handle'] as String);
        expect(hex(h.canonicalBytes), c['password']);
        expect(hex(await handleLabel(h)), c['label']);
      }
      for (final c in (l['small_parameters'] as List).cast<Map>()) {
        final k = await Argon2id(
                memory: c['memory_kib'] as int,
                parallelism: c['parallelism'] as int,
                iterations: c['iterations'] as int,
                hashLength: c['tag_len'] as int)
            .deriveKey(
                secretKey: SecretKey(unhex(c['password'] as String)),
                nonce: unhex(c['salt'] as String));
        expect(hex(await k.extractBytes()), c['tag']);
      }

      // §21.3: keys from seeds; recovery codes from their printed form.
      final seeds = <String, Uint8List>{};
      final pubs = <String, Uint8List>{};
      for (final k in (v['keys'] as List).cast<Map>()) {
        final name = k['name'] as String;
        seeds[name] = unhex(k['seed'] as String);
        pubs[name] = await handleKeyPublic(seeds[name]!);
        expect(hex(pubs[name]!), k['pub'], reason: name);
        if (k.containsKey('routing_id')) {
          expect(await introRoutingId(pubs[name]!), k['routing_id']);
          expect(hex(unb64url(k['routing_id'] as String)), k['rid_bytes']);
          expect(k['x_hkdf_salt'], handleIntroXSalt);
          final id = await handleIntroIdentity(seeds[name]!);
          expect(hex(id.xSeed), k['x_seed']);
          expect(hex(await handleIntroXSeed(seeds[name]!)), k['x_seed']);
          expect(hex(id.xPub), k['x_pub']);
          expect(hex(id.edPub), k['pub']);
        }
      }
      final aliceLabel =
          await handleLabel(Handle.parse('alice.42'));
      for (final r in (v['recovery'] as List).cast<Map>()) {
        final code = await parseHandleRecoveryCode(r['formatted'] as String);
        expect(hex(code.entropy), r['entropy']);
        expect(await formatHandleRecoveryCode(code), r['formatted']);
        expect(hex(aliceLabel), r['hkdf_info']);
        final rk = await handleRecoveryKey(code, aliceLabel);
        expect(hex(rk.seed), r['seed']);
        expect(hex(rk.pub), r['pub']);
        expect(hex(rk.rc), r['rc']);
      }

      // §21.4: every entry's bytes, and the owner rule over every history.
      final entries = <String, HandleEntry>{};
      for (final e in (v['entries'] as List).cast<Map>()) {
        final entry = HandleEntry(
            label: unhex(e['label'] as String),
            version: e['v'] as int,
            value: unhex(e['value'] as String),
            sig: unhex(e['sig'] as String));
        entries[e['name'] as String] = entry;
        expect(utf8.decode(entry.value), e['value_text']);
        expect(
            hex(await handlePublishInput(
                label: entry.label, version: entry.version, value: entry.value)),
            e['publish_input']);
        expect(entry.toPublishJson(), e['publish_json']);
        if (e.containsKey('rsig')) {
          final r = HandleRecord.decode(entry.value);
          expect(hex(r.rsig!), e['rsig']);
          expect(
              hex(handleRecoverInput(
                  label: entry.label, version: entry.version, owner: r.owner, rc: r.rc)),
              e['recover_input']);
        }
      }
      for (final h in (v['histories'] as List).cast<Map>()) {
        final verdict = await checkHandleHistory(
            [for (final n in (h['entries'] as List).cast<String>()) entries[n]!]);
        final want = h['verdict'] as Map;
        expect(verdict.ok, want['ok'], reason: h['name'] as String);
        if (want['ok'] == true) {
          expect(verdict.state!.version, want['version']);
          expect(hex(verdict.state!.owner), want['owner']);
          expect(hex(verdict.state!.rc), want['rc']);
          final intro = verdict.state!.record.intro;
          expect(intro == null ? null : hex(intro), want['intro']);
          expect(verdict.state!.record.pow, want['pow']);
        } else {
          expect(verdict.refusedAt, want['refused_at'], reason: h['name'] as String);
          expect(verdict.reason!.name, want['reason'], reason: h['name'] as String);
        }
      }
      for (final n in (v['not_records'] as List).cast<Map>()) {
        expect(() => HandleRecord.decode(unhex(n['value'] as String)),
            throwsA(isA<HandleRecordFormatException>()),
            reason: n['why'] as String);
      }

      // §21.7: the request, sealed to xintro — re-sealed from its recorded
      // draws, and opened with the introduction identity.
      final req = v['request'] as Map;
      final introKey = (v['keys'] as List)
          .cast<Map>()
          .firstWhere((k) => k['x_pub'] == req['to_x_pub']);
      expect(
          await runScripted(
              [unhex(req['eph_seed'] as String), unhex(req['nonce'] as String)],
              () => SealedEnvelope.seal(
                  toXPub: unhex(req['to_x_pub'] as String),
                  fromRid: req['from_rid'] as String,
                  payload: req['payload'] as String)),
          req['envelope']);
      final introId = await handleIntroIdentity(unhex(introKey['seed'] as String));
      final opened = (await SealedEnvelope.open(
          myXSeed: introId.xSeed,
          myXPub: introId.xPub,
          blob: req['envelope'] as String))!;
      expect(opened.fromRid, req['from_rid']);
      expect(opened.payload, req['payload']);
      expect(await introId.routingId(), req['to_routing_id']);
      expect(
          await ContactRequest.tryParse(opened.payload)!.verify(
              expectedTo: req['to_routing_id'] as String,
              sealedFrom: opened.fromRid),
          isTrue);

      // §21.7: stamps re-found from their start, and the refusals.
      final pow = v['pow'] as Map;
      for (final s in (pow['stamps'] as List).cast<Map>()) {
        final env = utf8.encode(s['envelope'] as String);
        final nonce = createIntroPowStamp(
            introRid: s['routing_id'] as String,
            day: s['day'] as int,
            envelope: env,
            bits: s['bits'] as int,
            startNonce: unhex(s['start_nonce'] as String));
        expect(hex(nonce), s['nonce']);
        expect(b64url(nonce), s['frame_member']);
        expect(
            await verifyIntroPowStamp(
                introRid: s['routing_id'] as String,
                day: s['day'] as int,
                envelope: env,
                nonce: nonce,
                bits: s['bits'] as int),
            isTrue);
        final digest = await sha256Bytes(unhex(s['input'] as String));
        expect(hex(digest), s['digest']);
        expect(introPowZeroBits(digest), s['zero_bits']);
      }
      final first = unhex(((pow['stamps'] as List).first as Map)['nonce'] as String);
      for (final r in (pow['must_refuse'] as List).cast<Map>()) {
        expect(
            await verifyIntroPowStamp(
                introRid: r['routing_id'] as String,
                day: r['day'] as int,
                envelope: utf8.encode(r['envelope'] as String),
                nonce: first,
                bits: r['bits'] as int),
            isFalse,
            reason: r['why'] as String);
      }
      final firstStamp = (pow['stamps'] as List).first as Map;
      for (final w in (pow['acceptance_window'] as List).cast<Map>()) {
        expect(introPowDay(w['relay_now_ms'] as int), w['relay_day']);
        expect(
            await introPowAcceptable(
                introRid: firstStamp['routing_id'] as String,
                envelope: utf8.encode(firstStamp['envelope'] as String),
                nonce: first,
                bits: firstStamp['bits'] as int,
                nowMs: w['relay_now_ms'] as int),
            w['accepted']);
      }

      // §21.7: the acknowledgement, from the recorded request.
      final ack = v['intro_ack'] as Map;
      final creq = ContactRequest.tryParse(ack['creq_payload'] as String)!;
      expect(hex(ContactRequest.signingInput(creq.bundle, creq.toRid, creq.ts)),
          ack['creq_signing_input']);
      expect(hex(await contactRequestId(creq)), ack['creq_id']);
      final owner = ack['owner_account'] as Map;
      final requester = ack['requester'] as Map;
      expect(
          await signIntroAck(
              introSeed: seeds[ack['intro_key']]!,
              requesterRid: requester['routing_id'] as String,
              ownerAccountEdPub: unhex(owner['ed_pub'] as String),
              creqId: unhex(ack['creq_id'] as String)),
          ack['ia']);
      expect(
          await verifyIntroAck(
              ia: ack['ia'] as String,
              introPub: unhex(ack['intro_pub'] as String),
              requesterRid: requester['routing_id'] as String,
              ownerAccountEdPub: unhex(owner['ed_pub'] as String),
              creqId: unhex(ack['creq_id'] as String)),
          isTrue);
      for (final r in (ack['must_refuse'] as List).cast<Map>()) {
        expect(
            await verifyIntroAck(
                ia: ack['ia'] as String,
                introPub: unhex(r['intro_pub'] as String),
                requesterRid: r['requester_rid'] as String,
                ownerAccountEdPub: unhex(r['owner_account_ed_pub'] as String),
                creqId: unhex(r['creq_id'] as String)),
            isFalse,
            reason: r['why'] as String);
      }
      final accepted = ContactRequest.tryParse(ack['acceptance_payload'] as String)!;
      expect(await accepted.verify(expectedTo: requester['routing_id'] as String),
          isTrue);
      expect(hex(accepted.bundle.edPub), owner['ed_pub']);
      expect((jsonDecode(ack['acceptance_json'] as String) as Map)['ia'], ack['ia']);
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
