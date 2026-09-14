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
import 'dart:convert';
import 'dart:io';
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

  Future<KeyTransparency> service(KtConfig c, _StubFetcher f, {required int now}) async {
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
}
