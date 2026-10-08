// Lookups by bucket (PROTOCOL.md §19.9, ADR 0023), the reader's side, for
// both logs `kt/` runs: the key-transparency log and the handle log (§21.5).
// The verifier phase 35 will read the key-transparency log through and
// phase 38 will resolve handles through, checked against the answers the log
// recorded in docs/vectors/kt/bucket.json and against the log itself.
//
// Criteria, each a test below:
//  1. every recorded answer verifies — both logs, k = 0, 1 and 8, and a POST
//     of three — holding exactly the labels expected, and every must_refuse
//     in the file is refused;
//  2. the pieces: a prefix has one spelling, a query holds exactly the labels
//     with its prefix, the k = 0 subtree is the map's root, an empty bucket
//     proves absence for every label in it, and a label outside a bucket is
//     refused rather than answered;
//  3. the handle log's leaves carry each label's latest record, on the hour,
//     with the owner's signature as published; a changed record, time, audit
//     path, index or signature is refused, as is either log's head in the
//     other's context;
//  4. entries by index verify in the order asked, and an entry substituted,
//     moved or cut from its proof is refused;
//  5. against the real key-transparency log (kt/server.js) on loopback:
//     publishes, then buckets at k = 0, 1 and 8 and a POST of several, every
//     label found at its latest index and version, a label never published a
//     verified absence, and its value read by index;
//  6. against the real handle log (KT_MODE=handles): a claim, an update and
//     a recover published as the handle library will publish them, each
//     label resolved by bucket to its latest record (both introduction keys
//     in it), and a foreign update and a record whose introduction key comes
//     without its X25519 key refused by the log.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';
import 'package:z_protocol/z_protocol.dart';
import 'package:z_protocol/src/util.dart' show canonicalJson, concatBytes;

Map<String, Object?> obj(Object? m) => (m as Map).cast<String, Object?>();

Map<String, Object?> vec() =>
    obj(jsonDecode(File('../docs/vectors/kt/bucket.json').readAsStringSync()));

Uint8List hx(Object? s) {
  final str = s as String;
  return Uint8List.fromList([
    for (var i = 0; i < str.length; i += 2) int.parse(str.substring(i, i + 2), radix: 16)
  ]);
}

String hexOf(List<int> b) => [for (final x in b) x.toRadixString(16).padLeft(2, '0')].join();

KtBucketQuery q(Object? asked) {
  final a = obj(asked);
  return KtBucketQuery.parse(a['prefix'] as String, a['bits'] as int);
}

Future<void> refused(Future<Object?> f, String why) async {
  try {
    await f;
  } on KtVerifyException {
    return;
  }
  fail('accepted: $why');
}

final _ed = Ed25519();

/// A label stand-in: the log never computes one (a handle's is Argon2id, §21.1).
Future<Uint8List> labelOf(String s) => sha256Bytes(utf8.encode('bucket test label: $s'));

void main() {
  group('the recorded answers', () {
    final v = vec();

    test('1. every recorded answer verifies, holds what it should, and every must_refuse is refused', () async {
      for (final (mode, part) in [(KtLogMode.kt, obj(v['kt'])), (KtLogMode.handles, obj(v['handles']))]) {
        final pub = hx(obj(part['log'])['pub']);
        for (final b in (part['buckets'] as List).map(obj)) {
          final r = await ktVerifyBucketAnswer(obj(jsonDecode(b['response_json'] as String)),
              asked: [q(b['asked'])], logPub: pub, mode: mode);
          expect([for (final l in r.buckets.single.leaves) hexOf(l.label)], b['expect_labels'],
              reason: '${mode.name} ${b['asked']}');
        }
        for (final m in (part['must_refuse'] as List).map(obj)) {
          await refused(
              ktVerifyBucketAnswer(obj(jsonDecode(m['response_json'] as String)),
                  asked: [for (final a in m['asked'] as List) q(a)], logPub: pub, mode: mode),
              '${mode.name}: ${m['why']}');
        }
      }
      final kt = obj(v['kt']);
      final pub = hx(obj(kt['log'])['pub']);
      final post = obj(kt['post_buckets']);
      final asked = [for (final a in obj(jsonDecode(post['request_json'] as String))['buckets'] as List) q(a)];
      final r = await ktVerifyBucketAnswer(obj(jsonDecode(post['response_json'] as String)),
          asked: asked, logPub: pub, mode: KtLogMode.kt);
      expect(r.buckets.length, 3);
      expect(r.recommendedBits, 0, reason: 'twenty labels: one bucket is the recommendation');
      // The same answer, asked about in another order, is not this answer.
      await refused(
          ktVerifyBucketAnswer(obj(jsonDecode(post['response_json'] as String)),
              asked: asked.reversed.toList(), logPub: pub, mode: KtLogMode.kt),
          'buckets in another order');
    });

    test('2. a prefix has one spelling; a bucket answers for its labels and for no other', () async {
      final kt = obj(v['kt']);
      final labels = [for (final l in kt['labels'] as List) hx(l)];
      // Spelling.
      expect(ktBucketPrefix(labels[0], 0), '');
      expect(ktBucketPrefix(Uint8List(32)..[0] = 0xff, 1), '8');
      expect(ktBucketPrefix(Uint8List(32)..[0] = 0xff, 6), 'fc');
      expect(ktBucketPrefix(Uint8List.fromList([0xab, 0xcd, 0xef, ...List.filled(29, 0)]), 24), 'abcdef');
      for (final (hex, bits) in [('1', 3), ('c', 1), ('00', 4), ('0', 8), ('zz', 8), ('000000a', 25), ('0', -1)]) {
        expect(ktParseBucketPrefix(hex, bits), isNull, reason: '"$hex" at $bits');
      }
      expect(() => KtBucketQuery.parse('1', 3), throwsArgumentError);
      expect(KtBucketQuery.parse('AB', 8), KtBucketQuery.parse('ab', 8));
      expect(KtBucketQuery.parse('ab', 8).path, '/kt/v1/bucket?prefix=ab&bits=8');
      expect(ktBucketsRequest([KtBucketQuery.parse('', 0)]), {
        'buckets': [
          {'prefix': '', 'bits': 0}
        ]
      });
      expect(() => ktBucketsRequest([for (var i = 0; i < 65; i++) KtBucketQuery.parse('', 0)]), throwsArgumentError);
      // A query holds exactly the labels with its prefix.
      for (final bits in [0, 1, 5, 8, 13, 24]) {
        final qq = KtBucketQuery.forLabel(labels[3], bits);
        expect(qq.holds(labels[3]), isTrue);
        for (final l in labels) {
          expect(qq.holds(l), ktBucketPrefix(l, bits) == qq.prefix);
        }
      }
      // k = 0: the subtree is the whole map, with nothing to fold.
      final b0 = obj(jsonDecode(obj((kt['buckets'] as List)[0])['response_json'] as String));
      final r0 = await ktVerifyBucketAnswer(b0, asked: [KtBucketQuery.parse('', 0)], logPub: hx(obj(kt['log'])['pub']), mode: KtLogMode.kt);
      expect(ktBucketSubtreeRoot(r0.buckets.single.leaves, 0), r0.head.mapRoot);
      expect(ktBucketFold(r0.head.mapRoot, Uint8List(32), 0, []), r0.head.mapRoot);
      // The empty bucket: every label in it is absent, provably; a label
      // outside it is refused, not answered.
      final e = obj(kt['empty_bucket']);
      final empty = await ktVerifyBucketAnswer(obj(jsonDecode(e['response_json'] as String)),
          asked: [q(e['asked'])], logPub: hx(obj(kt['log'])['pub']), mode: KtLogMode.kt);
      final bucket = empty.buckets.single;
      expect(bucket.leaves, isEmpty);
      expect(bucket.leafFor(hx(e['absent_label_example'])), isNull);
      expect(() => bucket.leafFor(labels[0]), throwsArgumentError);
      final present = r0.buckets.single.leafFor(labels[7])!;
      expect(present.version, 1);
    });

    test('3. a handle leaf is the latest record, on the hour, as signed — and nothing else passes', () async {
      final hl = obj(v['handles']);
      final pub = hx(obj(hl['log'])['pub']);
      final publishes = (hl['publishes'] as List).map(obj).toList();
      final latest = <String, Map<String, Object?>>{for (final p in publishes) p['label'] as String: p};
      final b = obj((hl['buckets'] as List)[0]);
      final json = obj(jsonDecode(b['response_json'] as String));
      final r = await ktVerifyBucketAnswer(json, asked: [q(b['asked'])], logPub: pub, mode: KtLogMode.handles);
      for (final l in r.buckets.single.leaves) {
        final p = latest[hexOf(l.label)]!;
        expect(utf8.decode(l.value!), p['record_json']);
        expect(l.version, p['version']);
        expect(l.ts! % handleHourMs, 0);
        expect(hexOf(l.sig!), p['sig']);
      }
      final recovered = r.buckets.single.leafFor(hx(publishes[3]['label']))!;
      expect(jsonDecode(utf8.decode(recovered.value!))['k'], 'update', reason: 'the label recovered, then updated by its new owner');
      expect(recovered.version, 4);
      // Mutations of one leaf, each refused.
      final leaves = (json['leaves'] as List).map(obj).toList();
      Map<String, Object?> swap(int at, Map<String, Object?> leaf) =>
          {...json, 'leaves': [for (var i = 0; i < leaves.length; i++) i == at ? leaf : leaves[i]]};
      final l0 = leaves[0];
      final record = obj(jsonDecode(utf8.decode(unb64(l0['value'] as String))));
      record['pow'] = (record['pow'] as int) == 28 ? 16 : 28;
      for (final (why, bad) in [
        ('a changed record', swap(0, {...l0, 'value': b64(utf8.encode(jsonEncode(record)))})),
        ('a ts finer than an hour', swap(0, {...l0, 'ts': (l0['ts'] as int) + 1})),
        ('a ts an hour out', swap(0, {...l0, 'ts': (l0['ts'] as int) + handleHourMs})),
        ('an audit path cut short', swap(0, {...l0, 'audit': (l0['audit'] as List).sublist(1)})),
        ('another entry\'s index', swap(0, {...l0, 'index': (leaves[1]['index'] as int)})),
        ('a 63-byte signature', swap(0, {...l0, 'sig': b64(Uint8List(63))})),
        ('no audit path', swap(0, {...l0}..remove('audit'))),
      ]) {
        await refused(ktVerifyBucketAnswer(bad, asked: [q(b['asked'])], logPub: pub, mode: KtLogMode.handles), why);
      }
      // Either log's head in the other's context.
      await refused(ktVerifyBucketAnswer(json, asked: [q(b['asked'])], logPub: pub, mode: KtLogMode.kt), 'a handle head as a KT head');
      final kt = obj(v['kt']);
      final kb = obj((kt['buckets'] as List)[0]);
      await refused(
          ktVerifyBucketAnswer(obj(jsonDecode(kb['response_json'] as String)),
              asked: [q(kb['asked'])], logPub: hx(obj(kt['log'])['pub']), mode: KtLogMode.handles),
          'a KT head as a handle head');
      final head = KtTreeHead.fromJson(obj(hl['head']));
      expect(hexOf(ktHeadInput(head, KtLogMode.handles)), hl['head_input']);
      expect(await ktVerifyHead(head, pub, KtLogMode.handles), isTrue);
      expect(await ktVerifyHead(head, pub, KtLogMode.kt), isFalse);
      // And the leaf input is the handle log's.
      final p0 = publishes[0];
      expect(
          hexOf(handleLeafInput(
              label: hx(p0['label']),
              version: p0['version'] as int,
              valueHash: hx(p0['value_hash']),
              ts: obj(obj(p0['entry'])['json'])['ts'] as int)),
          obj(p0['entry'])['leaf_input']);
    });

    test('4. entries by index verify in order, and a substitute does not', () async {
      final kt = obj(v['kt']);
      final pub = hx(obj(kt['log'])['pub']);
      final e = obj(kt['entries_by_index']);
      final asked = [for (final i in obj(jsonDecode(e['request_json'] as String))['indexes'] as List) i as int];
      final json = obj(jsonDecode(e['response_json'] as String));
      final r = await ktVerifyEntriesAnswer(json, asked: asked, logPub: pub);
      expect([for (final x in r.entries) x.index], asked);
      expect(r.total, 3);
      final items = (json['entries'] as List).map(obj).toList();
      await refused(ktVerifyEntriesAnswer({...json, 'entries': [items[1], items[0], items[2]]}, asked: asked, logPub: pub), 'reordered');
      await refused(ktVerifyEntriesAnswer({...json, 'entries': [items[0], items[0], items[2]]}, asked: asked, logPub: pub), 'one in place of another');
      final cut = {...obj(items[0]['inclusion']), 'path': (obj(items[0]['inclusion'])['path'] as List).sublist(1)};
      await refused(ktVerifyEntriesAnswer({...json, 'entries': [{...items[0], 'inclusion': cut}, items[1], items[2]]}, asked: asked, logPub: pub), 'a path cut short');
      await refused(ktVerifyEntriesAnswer({...json, 'total': 4}, asked: asked, logPub: pub), 'a total that is not what was asked');
      await refused(ktVerifyEntriesAnswer({...json, 'entries': []}, asked: asked, logPub: pub), 'nothing served');
      // A page — fewer than asked, in order — is an answer, not a fault.
      final page = await ktVerifyEntriesAnswer({...json, 'entries': items.sublist(0, 2)}, asked: asked, logPub: pub);
      expect(page.entries.length, 2);
    });
  });

  group('against the real log', () {
    final logs = <Process>[];

    /// `node kt/server.js` on a free loopback port, in memory, gates open.
    Future<String> start(List<int> seed, {String? mode}) async {
      final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      final port = probe.port;
      await probe.close();
      final p = await Process.start('node', ['server.js'],
          workingDirectory: '${Directory.current.parent.path}${Platform.pathSeparator}kt',
          environment: {
            'KT_SEED': hexOf(seed),
            'KT_EPHEMERAL': '1',
            'KT_PORT': '$port',
            if (mode != null) 'KT_MODE': mode,
            // The gates are kt/test/publish_limits.test.js's business.
            'PUBLISH_PER_MIN': '1000000',
            'PUBLISH_PER_MIN_TOTAL': '1000000',
            'PUBLISH_PER_ACCT_PER_DAY': '1000000',
            'PUBLISH_NEW_ACCOUNTS_PER_MIN': '1000000',
          });
      logs.add(p);
      p.stdout.drain<void>();
      p.stderr.drain<void>();
      final url = 'http://127.0.0.1:$port';
      await waitFor(() async {
        try {
          final res = await (await HttpClient().getUrl(Uri.parse('$url/health'))).close();
          await res.drain<void>();
          return res.statusCode == 200;
        } catch (_) {
          return false;
        }
      }, what: 'the log on $port answering /health');
      return url;
    }

    tearDownAll(() async {
      for (final p in logs) {
        p.kill();
        await p.exitCode;
      }
    });

    test('5. the key-transparency log: buckets at k = 0, 1 and 8, a POST, absence, and a value by index', () async {
      final seed = await sha256Bytes(utf8.encode('bucket test kt log'));
      final url = await start(seed);
      final pub = Uint8List.fromList((await (await _ed.newKeyPairFromSeed(seed)).extractPublicKey()).bytes);
      // Twenty accounts publish; three publish again.
      final accounts = <(Uint8List, Uint8List)>[]; // (seed, label)
      final latest = <String, (int, int)>{};
      for (var i = 0; i < 20; i++) {
        final s = await sha256Bytes(utf8.encode('bucket test account $i'));
        final kp = await _ed.newKeyPairFromSeed(s);
        final apub = Uint8List.fromList((await kp.extractPublicKey()).bytes);
        accounts.add((s, await ktLabel(apub)));
      }
      Future<void> publish(int i, int version) async {
        final (s, label) = accounts[i];
        final kp = await _ed.newKeyPairFromSeed(s);
        final apub = Uint8List.fromList((await kp.extractPublicKey()).bytes);
        final value = await ktSealValue(apub, utf8.encode('{"stand_in":$version}'));
        final body = await ktPublishRequest(accountEdSeed: s, version: version, fp: Uint8List(16), value: value);
        final res = await post('$url/kt/v1/publish', body);
        expect(res.$1, 201, reason: jsonEncode(res.$2));
        latest[hexOf(label)] = (res.$2['index'] as int, version);
      }
      for (var i = 0; i < 20; i++) {
        await publish(i, 1);
      }
      for (var i = 0; i < 3; i++) {
        await publish(i, 2);
      }
      final head = KtTreeHead.fromJson(await get('$url/kt/v1/sth'));
      expect(await ktVerifyHead(head, pub, KtLogMode.kt), isTrue);
      final target = accounts[1].$2;
      for (final bits in [0, 1, 8]) {
        final query = KtBucketQuery.forLabel(target, bits);
        final r = await ktVerifyBucketAnswer(await get('$url${query.path}'), asked: [query], logPub: pub, mode: KtLogMode.kt);
        final bucket = r.buckets.single;
        expect(bucket.leaves.length, latest.keys.where((l) => query.holds(hx(l))).length, reason: 'every label with the prefix, at $bits bits');
        for (final l in bucket.leaves) {
          expect((l.index, l.version), latest[hexOf(l.label)], reason: 'the latest entry, at $bits bits');
        }
        expect(bucket.leafFor(target)!.version, 2);
      }
      // Several under one head, a decoy among them, and a label never published.
      final nobody = await labelOf('never published');
      final asked = [KtBucketQuery.forLabel(accounts[5].$2, 4), KtBucketQuery.parse('8', 1), KtBucketQuery.forLabel(nobody, 8)];
      final r = await ktVerifyBucketAnswer((await post('$url/kt/v1/buckets', ktBucketsRequest(asked))).$2, asked: asked, logPub: pub, mode: KtLogMode.kt);
      expect(r.buckets[0].leafFor(accounts[5].$2)!.index, latest[hexOf(accounts[5].$2)]!.$1);
      expect(r.buckets[2].leafFor(nobody), isNull, reason: 'a verified absence');
      expect(r.recommendedBits, 0);
      // The value of one entry, by index, with a decoy beside it.
      final want = latest[hexOf(accounts[5].$2)]!.$1;
      final e = await ktVerifyEntriesAnswer((await post('$url/kt/v1/entries', ktEntriesRequest([7, want]))).$2, asked: [7, want], logPub: pub);
      final kp = await _ed.newKeyPairFromSeed(accounts[5].$1);
      final apub = Uint8List.fromList((await kp.extractPublicKey()).bytes);
      expect(utf8.decode((await ktOpenValue(apub, e.entries[1].value))!), '{"stand_in":1}');
      // An answer under one log's key does not verify under another's.
      await refused(
          ktVerifyBucketAnswer(await get('$url/kt/v1/bucket?prefix=&bits=0'),
              asked: [KtBucketQuery.parse('', 0)], logPub: Uint8List(32)..[0] = 1, mode: KtLogMode.kt),
          'another key');
    });

    test('6. the handle log: claims, an update and a recover, each resolved by bucket to its latest record', () async {
      final seed = await sha256Bytes(utf8.encode('bucket test handle log'));
      final url = await start(seed, mode: 'handles');
      final pub = Uint8List.fromList((await (await _ed.newKeyPairFromSeed(seed)).extractPublicKey()).bytes);
      final health = await get('$url/health');
      expect(health['mode'], 'handles');
      final owner = await _key('owner');
      final owner2 = await _key('owner 2');
      final recovery = await _key('recovery');
      final recovery2 = await _key('recovery 2');
      final stranger = await _key('stranger');
      final rc = await _rc(recovery);
      final rc2 = await _rc(recovery2);
      final mine = await labelOf('finnian.07');
      final records = <String, String>{};
      Future<(int, Map<String, Object?>)> publish(Uint8List label, int v, SimpleKeyPair by, String k,
          {required Uint8List rc, SimpleKeyPair? recoveryKey, Uint8List? introSeed, bool omitXintro = false}) async {
        final body = await _handlePublish(label, v, by, k, rc: rc, recoveryKey: recoveryKey, introSeed: introSeed, omitXintro: omitXintro);
        final res = await post('$url/kt/v1/publish', body);
        if (res.$1 == 201) records[hexOf(label)] = utf8.decode(unb64(body['value'] as String));
        return res;
      }
      expect((await publish(mine, 1, owner, 'claim', rc: rc, introSeed: await _introSeed('1'))).$1, 201);
      final others = [for (var i = 0; i < 12; i++) await labelOf('other.$i')];
      for (final l in others) {
        expect((await publish(l, 1, stranger, 'claim', rc: rc2)).$1, 201);
      }
      expect((await publish(mine, 2, owner, 'update', rc: rc)).$1, 201, reason: 'paused: intro and xintro null');
      // A foreign update: the log refuses it.
      final foreign = await publish(mine, 3, stranger, 'update', rc: rc);
      expect(foreign.$1, 403);
      expect(foreign.$2['error'], 'owner_rule');
      final taken = await publish(mine, 3, stranger, 'claim', rc: rc);
      expect((taken.$1, taken.$2['error']), (409, 'taken'));
      // An introduction key without its X25519 key (SPEC amendment 1).
      final half = await publish(mine, 3, owner, 'update', rc: rc, introSeed: await _introSeed('half'), omitXintro: true);
      expect((half.$1, half.$2['error']), (400, 'bad_record'));
      // Recovered by the code's key, to a new owner.
      expect((await publish(mine, 3, owner2, 'recover', rc: rc2, recoveryKey: recovery, introSeed: await _introSeed('3'))).$1, 201);
      // Resolve every label by its bucket.
      final head = await get('$url/kt/v1/sth');
      final bits = head['bucketBits'] as int;
      expect(bits, 0, reason: 'thirteen handles: one bucket');
      for (final label in [mine, ...others]) {
        for (final k in [bits, 1, 8]) {
          final query = KtBucketQuery.forLabel(label, k);
          final r = await ktVerifyBucketAnswer(await get('$url${query.path}'), asked: [query], logPub: pub, mode: KtLogMode.handles);
          final leaf = r.buckets.single.leafFor(label)!;
          expect(utf8.decode(leaf.value!), records[hexOf(label)]);
          expect(leaf.ts! % handleHourMs, 0);
        }
      }
      final r = await ktVerifyBucketAnswer(
          (await post('$url/kt/v1/buckets', ktBucketsRequest([KtBucketQuery.forLabel(mine, 2), KtBucketQuery.forLabel(others[3], 3)]))).$2,
          asked: [KtBucketQuery.forLabel(mine, 2), KtBucketQuery.forLabel(others[3], 3)],
          logPub: pub,
          mode: KtLogMode.handles);
      final resolved = jsonDecode(utf8.decode(r.buckets[0].leafFor(mine)!.value!)) as Map;
      expect(resolved['k'], 'recover');
      expect(resolved.keys.toList(), ['k', 'owner', 'intro', 'xintro', 'pow', 'rc', 'rpub', 'rsig']);
      expect(resolved['xintro'], isA<String>(), reason: 'recovered with a mailbox: both its keys');
      expect(resolved['owner'], b64url(await _pub(owner2)));
      expect(resolved['rc'], b64url(rc2));
      expect(r.buckets[0].leafFor(mine)!.version, 3);
      // A handle never claimed: absent, provably.
      final unclaimed = await labelOf('nobody.00');
      final q0 = KtBucketQuery.forLabel(unclaimed, 0);
      expect((await ktVerifyBucketAnswer(await get('$url${q0.path}'), asked: [q0], logPub: pub, mode: KtLogMode.handles)).buckets.single.leafFor(unclaimed), isNull);
    });
  });
}

// --- helpers --------------------------------------------------------------------------

/// Wait on [cond] — an observable, polled — for up to [timeout], or fail naming [what].
Future<void> waitFor(Future<bool> Function() cond,
    {required String what, Duration timeout = const Duration(seconds: 20)}) async {
  final until = DateTime.now().add(timeout);
  while (!await cond()) {
    if (DateTime.now().isAfter(until)) fail('timed out waiting for $what');
    await Future<void>.delayed(const Duration(milliseconds: 50));
  }
}

Future<Map<String, Object?>> get(String url) async {
  final res = await (await HttpClient().getUrl(Uri.parse(url))).close();
  final body = await res.transform(utf8.decoder).join();
  if (res.statusCode != 200) fail('GET $url: ${res.statusCode} $body');
  return obj(jsonDecode(body));
}

Future<(int, Map<String, Object?>)> post(String url, Map<String, Object?> body) async {
  final req = await HttpClient().postUrl(Uri.parse(url));
  req.headers.contentType = ContentType.json;
  req.write(jsonEncode(body));
  final res = await req.close();
  return (res.statusCode, obj(jsonDecode(await res.transform(utf8.decoder).join())));
}

Future<SimpleKeyPair> _key(String s) async =>
    _ed.newKeyPairFromSeed(await sha256Bytes(utf8.encode('bucket test key: $s')));

Future<Uint8List> _pub(SimpleKeyPair kp) async => Uint8List.fromList((await kp.extractPublicKey()).bytes);

Future<Uint8List> _introSeed(String s) => sha256Bytes(utf8.encode('bucket test intro seed: $s'));

Future<Uint8List> _rc(SimpleKeyPair recovery) async =>
    sha256Bytes(concatBytes([utf8.encode('z-handle-rc-v1:'), await _pub(recovery)]));

Uint8List _u64(int n) => (ByteData(8)..setUint64(0, n)).buffer.asUint8List();

/// A handle publish as the handle library will make one (PROTOCOL §21.5):
/// the record in its canonical encoding, `sig` by the owner it names, and
/// for a recover `rsig` by the recovery key. Test-local: the library is
/// phase 36.1's.
Future<Map<String, Object?>> _handlePublish(Uint8List label, int version, SimpleKeyPair by, String k,
    {required Uint8List rc, SimpleKeyPair? recoveryKey, Uint8List? introSeed, bool omitXintro = false}) async {
  final owner = await _pub(by);
  // Both introduction keys from one seed (SPEC amendment 1): the Ed25519 key
  // of the seed, and the X25519 key of HKDF-SHA256(seed, salt
  // "z-handle-intro-x-v1", info "", 32).
  final intro = introSeed == null ? null : await _pub(await _ed.newKeyPairFromSeed(introSeed));
  Uint8List? xintro;
  if (introSeed != null && !omitXintro) {
    final xSeed = await Hkdf(hmac: Hmac.sha256(), outputLength: 32).deriveKey(
        secretKey: SecretKey(introSeed), nonce: utf8.encode('z-handle-intro-x-v1'), info: const []);
    final xkp = await X25519().newKeyPairFromSeed(await xSeed.extractBytes());
    xintro = Uint8List.fromList((await xkp.extractPublicKey()).bytes);
  }
  final record = <String, Object?>{
    'k': k,
    'owner': b64url(owner),
    'intro': intro == null ? null : b64url(intro),
    'xintro': xintro == null ? null : b64url(xintro),
    'pow': 20,
    'rc': b64url(rc),
  };
  if (k == 'recover') {
    final rsig = await _ed.sign(
        concatBytes([utf8.encode('z-handle-recover-v1:'), label, _u64(version), owner, rc]),
        keyPair: recoveryKey!);
    record['rpub'] = b64url(await _pub(recoveryKey));
    record['rsig'] = b64url(rsig.bytes);
  }
  final value = utf8.encode(canonicalJson(record));
  final sig = await _ed.sign(
      concatBytes([utf8.encode('z-handle-publish-v1:'), label, _u64(version), await sha256Bytes(value)]),
      keyPair: by);
  return {'label': b64url(label), 'v': version, 'value': b64(value), 'sig': b64(sig.bytes)};
}
