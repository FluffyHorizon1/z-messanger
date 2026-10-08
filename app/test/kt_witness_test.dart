// A witness is an address AND a key this device pinned.
//
// The client's §19.5 step 3 asks a witness whether it saw the same head the
// log just served. That question is only worth asking of somebody who is not
// the log, and "somebody" means a key chosen in advance: the record carries
// its own `witness.pub`, so a co-signature checked against that key
// establishes nothing except that whoever answered the address could sign.
// The log's own operator can do that.
//
// Until 2026-09-14 `hasWitness` was the address alone and the pin was an
// optional argument. A self-hoster who set the address and left the key empty
// got a check that runs, shows a tick, and has zero assurance in it.
//
// Criteria, each a test below:
//  1. an address with no key cannot be saved, and the reason names the
//     consequence rather than the rule;
//  2. a key with no address cannot be saved, and neither can a key that is
//     not 32 bytes of base64;
//  3. a configuration that already holds half a witness — written before the
//     rule existed — is not consulted at all: no request is made to it;
//  4. with both pinned, a record co-signed by a DIFFERENT key is not a
//     witness agreeing: nothing is recorded and no fault is raised from it;
//  5. with both pinned, a record co-signed by the pinned key that disagrees
//     with the log about a head of the same size IS a fault;
//  6. a witness address that is not loopback stops a test process making any
//     request at all — the same rule the log's address has had since the
//     suite was found publishing to production.
//
// And a witness AHEAD of the client, against the real log (kt/server.js) on
// loopback. A witness verifies the log every few minutes and the log grows
// in between, so the head a client has just fetched can be smaller than the
// one its witness has just co-signed. That was a fault — "the log served a
// head older than the witness's", permanent until the user resets the log's
// history — raised against an honest log by one publish between two
// requests (the 2026-10-03 analysis; latent while no witness is configured,
// on every client the day one is). PROTOCOL §19.5 step 3 already said what
// to do: a consistency proof between the two sizes, in either direction.
//  7. a witness ahead because the log grew between the client's two
//     requests is not a fork: the log proves the client's head is a prefix
//     of the witness's, and nothing is raised;
//  8. a witness ahead with a head the log's history does not lead to — under
//     the log's own key, over other entries — is a fault, as a witness
//     behind the client always was;
//  9. and a log that has gone back to a smaller history than its witness
//     verified — a restored snapshot, seen from a client — is still caught:
//     it cannot prove the way to the witness's head, and its own current
//     head is smaller than it.
@Timeout(Duration(minutes: 2))
library;

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/key_transparency.dart';
import 'package:zapp/core/vault.dart';
import 'package:z_protocol/z_protocol.dart';

class _NoHost implements KtHost {
  @override
  Future<List<KtContactInput>> ktContacts() async => const [];
  @override
  Future<KtOwnInput?> ktOwn() async => null;
  @override
  Future<bool> ktInstallFromLog(String rid, SignedDeviceList list) async => false;
  @override
  void ktChanged() {}
}

/// Serves one head from the log and one record from the witness address, and
/// remembers every URL it was asked for — criterion 3 is about whether the
/// request happens at all.
class _StubFetcher implements KtFetcher {
  final List<Uri> gets = [];
  String? sth;
  String? witness;
  final String witnessUrl;

  _StubFetcher({required this.witnessUrl});

  @override
  Future<KtResponse> get(Uri url) async {
    gets.add(url);
    if (url.toString() == witnessUrl) {
      return witness == null ? KtResponse(404, '{}') : KtResponse(200, witness!);
    }
    if (url.path.endsWith('/kt/v1/sth')) {
      return sth == null ? KtResponse(503, '{}') : KtResponse(200, sth!);
    }
    return KtResponse(404, '{}');
  }

  @override
  Future<KtResponse> post(Uri url, String body) async => KtResponse(500, '{}');
}

/// The real log for everything but the witness address, which [witness]
/// answers when — and only when — the client asks it. Remembers every URL.
class _LogFetcher implements KtFetcher {
  final HttpKtFetcher net = HttpKtFetcher();
  final String witnessUrl;
  final Future<KtResponse> Function() witness;
  final List<Uri> gets = [];

  _LogFetcher(this.witnessUrl, this.witness);

  @override
  Future<KtResponse> get(Uri url) async {
    gets.add(url);
    if (url.toString() == witnessUrl) return witness();
    return net.get(url);
  }

  @override
  Future<KtResponse> post(Uri url, String body) => net.post(url, body);
}

Future<SimpleKeyPair> keyFrom(String seed) => Ed25519()
    .newKeyPairFromSeed(Uint8List.fromList(utf8.encode(seed.padRight(32, '.')).take(32).toList()));

Future<Uint8List> pubOf(SimpleKeyPair kp) async =>
    Uint8List.fromList((await kp.extractPublicKey()).bytes);

Future<Uint8List> signWith(SimpleKeyPair kp, Uint8List data) async =>
    Uint8List.fromList((await Ed25519().sign(data, keyPair: kp)).bytes);

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const witnessUrl = 'http://127.0.0.1:9/sth.json';
  const logUrl = 'http://127.0.0.1:9';
  final temps = <Directory>[];

  late SimpleKeyPair logKey;
  late SimpleKeyPair pinned;
  late SimpleKeyPair impostor;
  late Uint8List logPub;
  late Uint8List pinnedPub;
  late Uint8List impostorPub;

  setUpAll(() async {
    logKey = await keyFrom('the log');
    pinned = await keyFrom('the witness');
    impostor = await keyFrom('not the witness');
    logPub = await pubOf(logKey);
    pinnedPub = await pubOf(pinned);
    impostorPub = await pubOf(impostor);
  });

  tearDownAll(() {
    for (final d in temps) {
      if (d.existsSync()) d.deleteSync(recursive: true);
    }
  });

  Future<Vault> freshVault(String name) async {
    final dir = await Directory.systemTemp.createTemp('z_ktw_$name');
    temps.add(dir);
    return Vault.open(rootOverride: dir);
  }

  /// A head the log really signed, so only the WITNESS side is ever in doubt.
  Future<KtTreeHead> head({required int size, required int root, required int ts}) async {
    final unsigned = KtTreeHead(
      size: size,
      logRoot: Uint8List(32)..[0] = root,
      mapRoot: Uint8List(32)..[1] = root,
      ts: ts,
      sig: Uint8List(64),
    );
    return KtTreeHead(
      size: size,
      logRoot: unsigned.logRoot,
      mapRoot: unsigned.mapRoot,
      ts: ts,
      sig: await signWith(logKey, unsigned.signingInput),
    );
  }

  Future<String> record(KtTreeHead h, SimpleKeyPair by, Uint8List byPub) async => jsonEncode({
        'sth': h.toJson(),
        'verifiedAt': h.ts,
        'size': h.size,
        'witness': {
          'pub': b64(byPub),
          'sig': b64(await signWith(by, ktWitnessInput(h))),
        },
      });

  Future<KeyTransparency> service(KtConfig c, KtFetcher f, {required int now}) async {
    final v = await freshVault('svc');
    return KeyTransparency(vault: v, host: _NoHost(), fetcher: f, config: c, now: () => now);
  }

  test('1. an address with no key cannot be saved, and the reason is the consequence', () async {
    final f = _StubFetcher(witnessUrl: witnessUrl);
    final kt = await service(
        KtConfig(logUrl: logUrl, logPubB64: b64(logPub)), f, now: 1000);
    await expectLater(
      kt.setConfig(KtConfig(
          logUrl: logUrl, logPubB64: b64(logPub), witnessUrl: witnessUrl, witnessPubB64: '')),
      throwsA(isA<KtConfigInvalid>().having((e) => e.reason, 'reason', 'urlWithoutKey')),
    );
    expect(kt.config.witnessUrl, isEmpty, reason: 'and nothing was stored');
  });

  test('2. a key with no address, or a key that is not 32 bytes, cannot be saved', () async {
    final f = _StubFetcher(witnessUrl: witnessUrl);
    final kt = await service(
        KtConfig(logUrl: logUrl, logPubB64: b64(logPub)), f, now: 1000);
    await expectLater(
      kt.setConfig(KtConfig(
          logUrl: logUrl, logPubB64: b64(logPub), witnessUrl: '', witnessPubB64: b64(pinnedPub))),
      throwsA(isA<KtConfigInvalid>().having((e) => e.reason, 'reason', 'keyWithoutUrl')),
    );
    await expectLater(
      kt.setConfig(KtConfig(
          logUrl: logUrl,
          logPubB64: b64(logPub),
          witnessUrl: witnessUrl,
          witnessPubB64: b64(Uint8List(31)))),
      throwsA(isA<KtConfigInvalid>().having((e) => e.reason, 'reason', 'keyNotValid')),
    );
    // The pair, together, is fine.
    await kt.setConfig(KtConfig(
        logUrl: logUrl,
        logPubB64: b64(logPub),
        witnessUrl: witnessUrl,
        witnessPubB64: b64(pinnedPub)));
    expect(kt.config.hasWitness, isTrue);
  });

  test('3. half a witness stored before the rule existed is never asked', () async {
    final f = _StubFetcher(witnessUrl: witnessUrl);
    final h = await head(size: 4, root: 7, ts: 900);
    f.sth = jsonEncode(h.toJson());
    // Constructed directly, as a config read back from the vault would be.
    final kt = await service(
        KtConfig(logUrl: logUrl, logPubB64: b64(logPub), witnessUrl: witnessUrl),
        f,
        now: 1000);
    expect(kt.config.hasWitness, isFalse);
    await kt.check();
    expect(f.gets.map((u) => u.toString()), isNot(contains(witnessUrl)),
        reason: 'a check with no key behind it must not run at all');
    expect(kt.witnessOkMs, isNull);
    expect(kt.fault, isNull);
  });

  test('4. a record co-signed by a key that was not pinned is not a witness agreeing', () async {
    final f = _StubFetcher(witnessUrl: witnessUrl);
    final h = await head(size: 4, root: 7, ts: 900);
    f.sth = jsonEncode(h.toJson());
    // The impostor signs the very head the log served, so the record is
    // internally perfect: the only thing wrong with it is whose key it is.
    f.witness = await record(h, impostor, impostorPub);
    final kt = await service(
        KtConfig(
            logUrl: logUrl,
            logPubB64: b64(logPub),
            witnessUrl: witnessUrl,
            witnessPubB64: b64(pinnedPub)),
        f,
        now: 1000);
    await kt.check();
    expect(f.gets.map((u) => u.toString()), contains(witnessUrl), reason: 'it was asked');
    expect(kt.witnessOkMs, isNull, reason: 'and the answer counted for nothing');
    expect(kt.fault, isNull, reason: 'an unpinned signer is not evidence of a fork either');
    // The same record under the key it is actually signed with does count,
    // which is what shows the refusal above was the pin and not the record.
    final kt2 = await service(
        KtConfig(
            logUrl: logUrl,
            logPubB64: b64(logPub),
            witnessUrl: witnessUrl,
            witnessPubB64: b64(impostorPub)),
        f,
        now: 1000);
    await kt2.check();
    expect(kt2.witnessOkMs, isNotNull);
  });

  test('5. the pinned witness disagreeing about a head of the same size is a fault', () async {
    final f = _StubFetcher(witnessUrl: witnessUrl);
    final served = await head(size: 4, root: 7, ts: 900);
    final other = await head(size: 4, root: 9, ts: 900);
    f.sth = jsonEncode(served.toJson());
    f.witness = await record(other, pinned, pinnedPub);
    final kt = await service(
        KtConfig(
            logUrl: logUrl,
            logPubB64: b64(logPub),
            witnessUrl: witnessUrl,
            witnessPubB64: b64(pinnedPub)),
        f,
        now: 1000);
    await kt.check();
    expect(kt.witnessOkMs, isNotNull);
    expect(kt.fault, isNotNull);
    expect(kt.fault!.reason, contains('different head'));
  });

  test('6. a witness address off loopback stops a test process making any request', () async {
    final f = _StubFetcher(witnessUrl: 'https://witness.example/sth.json');
    f.sth = jsonEncode((await head(size: 4, root: 7, ts: 900)).toJson());
    final kt = await service(
        KtConfig(
            logUrl: logUrl, // loopback, as a test's log must be
            logPubB64: b64(logPub),
            witnessUrl: 'https://witness.example/sth.json',
            witnessPubB64: b64(pinnedPub)),
        f,
        now: 1000);
    expect(kt.config.hasWitness, isTrue, reason: 'the configuration is complete; the address is the problem');
    await kt.check();
    expect(f.gets, isEmpty,
        reason: 'a witness on the internet is a stranger this suite must not poll');
  });

  group('a witness ahead of the client, against the real log', () {
    late Process log;
    late String realLogUrl;
    final rng = Random.secure();
    Uint8List random(int n) => Uint8List.fromList(List<int>.generate(n, (_) => rng.nextInt(256)));

    setUpAll(() async {
      HttpOverrides.global = null;
      final probe = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      final port = probe.port;
      await probe.close();
      // The same key as the log above, so a head can be signed by it here
      // when a test needs one the log never served.
      final seed = utf8.encode('the log'.padRight(32, '.')).take(32);
      log = await Process.start('node', ['server.js'],
          workingDirectory: '${Directory.current.parent.path}${Platform.pathSeparator}kt',
          environment: {
            'KT_SEED': [for (final b in seed) b.toRadixString(16).padLeft(2, '0')].join(),
            'KT_EPHEMERAL': '1',
            'KT_PORT': '$port',
            // The gates are kt/test/publish_limits.test.js's business.
            'PUBLISH_PER_MIN': '1000000',
            'PUBLISH_PER_MIN_TOTAL': '1000000',
            'PUBLISH_PER_ACCT_PER_DAY': '1000000',
            'PUBLISH_NEW_ACCOUNTS_PER_MIN': '1000000',
          });
      log.stdout.drain<void>();
      log.stderr.drain<void>();
      realLogUrl = 'http://127.0.0.1:$port';
      for (var i = 0; i < 100; i++) {
        try {
          final res = await (await HttpClient().getUrl(Uri.parse('$realLogUrl/health'))).close();
          await res.drain<void>();
          if (res.statusCode == 200) return;
        } catch (_) {}
        await Future<void>.delayed(const Duration(milliseconds: 100));
      }
      fail('the log on $port did not start');
    });

    tearDownAll(() async {
      log.kill();
      await log.exitCode;
    });

    final net = HttpKtFetcher();

    /// One publish to the real log, by an account of its own.
    Future<void> publish(String who) async {
      final seed = await sha256Bytes(utf8.encode('witness ahead: $who'));
      final body = await ktPublishRequest(accountEdSeed: seed, version: 1, fp: random(16), value: random(64));
      final r = await net.post(Uri.parse('$realLogUrl/kt/v1/publish'), jsonEncode(body));
      expect(r.status, 201, reason: r.body);
    }

    Future<KtTreeHead> logHead() async => KtTreeHead.fromJson((await net.get(Uri.parse('$realLogUrl/kt/v1/sth'))).json);

    KtConfig configFor(String witness) =>
        KtConfig(logUrl: realLogUrl, logPubB64: b64(logPub), witnessUrl: witness, witnessPubB64: b64(pinnedPub));

    /// A head at [size] under the log's own key, over roots its history does
    /// not have.
    Future<KtTreeHead> forgedHead(int size) async {
      final unsigned = KtTreeHead(
          size: size,
          logRoot: random(32),
          mapRoot: random(32),
          ts: DateTime.now().millisecondsSinceEpoch,
          sig: Uint8List(64));
      return KtTreeHead(
          size: size,
          logRoot: unsigned.logRoot,
          mapRoot: unsigned.mapRoot,
          ts: unsigned.ts,
          sig: await signWith(logKey, unsigned.signingInput));
    }

    test('7. a witness ahead because the log grew is not a fork: the log proves the way there', () async {
      await publish('7-a');
      await publish('7-b');
      final witnessUrl = '$realLogUrl/witness-7/sth.json'; // answered by the fetcher; never reaches the log
      late KtTreeHead witnessed;
      final f = _LogFetcher(witnessUrl, () async {
        // Between the client's head and its question to the witness, the log
        // grows and the witness verifies the larger head. That is all it takes.
        await publish('7-c');
        await publish('7-d');
        witnessed = await logHead();
        return KtResponse(200, await record(witnessed, pinned, pinnedPub));
      });
      final kt = await service(configFor(witnessUrl), f, now: DateTime.now().millisecondsSinceEpoch);
      await kt.check();
      expect(kt.head, isNotNull);
      expect(witnessed.size, kt.head!.size + 2, reason: 'the witness was two entries ahead of the head adopted');
      expect(kt.fault, isNull,
          reason: 'until 2026-10-04: "the log served a head of size ${kt.head?.size}, older than the witness\'s ${witnessed.size}"');
      expect(kt.witnessOkMs, isNotNull, reason: 'the witness counted');
      expect(f.gets.map((u) => u.path), contains('/kt/v1/consistency'), reason: 'the log was asked to prove the way there');
    });

    test('8. a witness ahead with a head the log does not lead to is a fault', () async {
      await publish('8-a');
      final witnessUrl = '$realLogUrl/witness-8/sth.json';
      final f = _LogFetcher(witnessUrl, () async {
        // The log grows by two, so it can answer for that size; the witness's
        // head at that size is under the log's own key and over other entries.
        final base = await logHead();
        await publish('8-b');
        await publish('8-c');
        return KtResponse(200, await record(await forgedHead(base.size + 2), pinned, pinnedPub));
      });
      final kt = await service(configFor(witnessUrl), f, now: DateTime.now().millisecondsSinceEpoch);
      await kt.check();
      expect(kt.fault, isNotNull);
      expect(kt.fault!.reason, contains('is not a prefix of the'));
    });

    test('9. a log gone back below what its witness verified is still caught', () async {
      await publish('9-a');
      final current = await logHead();
      // The witness holds a head the log signed at a size the log no longer
      // has — a restored snapshot, seen from a client. The log answers at its
      // old size and cannot prove the way to the witness's head.
      final signed = await forgedHead(current.size + 3);
      final witnessUrl = '$realLogUrl/witness-9/sth.json';
      final f = _LogFetcher(witnessUrl, () async => KtResponse(200, await record(signed, pinned, pinnedPub)));
      final kt = await service(configFor(witnessUrl), f, now: DateTime.now().millisecondsSinceEpoch);
      await kt.check();
      expect(kt.fault, isNotNull);
      expect(kt.fault!.reason, contains('smaller than the ${signed.size} its witness verified'));
    });
  });
}
