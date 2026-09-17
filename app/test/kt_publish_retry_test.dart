// A publish the log answered "not now" is kept and tried again soon.
//
// The log gates publishing (PROTOCOL §19.7): a 429 means a bucket is empty
// for the rest of the minute, and behind the shipped front — one address for
// everybody — it can be somebody else's minute. Until 2026-09-17 the client
// read 429 as any other 4xx, "malformed, a retry will not fix", and DROPPED
// the queued publish; the next check, six hours later, would find the log
// behind and queue it again. So a minute's refusal cost the account six
// hours without its list in the log, which is the delay ADR 0006's grace
// period charges that account's contacts for.
//
// No log is started here: the fetcher is scripted, because what is under
// test is what the client does with an answer, not what the log answers.
//
// Criteria, each a test below:
//   1. a 429 keeps the publish queued — in memory and in the vault, so a
//      restart keeps it too — and it is sent again after `publishRetryDelay`
//      rather than at the next check, and accepted then; and a 429 is not
//      counted as the log being unreachable, because a log at capacity is
//      reachable;
//   2. a 5xx keeps it as well, and IS counted, since the log could not take
//      it; and a 400 still clears it, since a retry would not fix a request
//      the log calls malformed.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/key_transparency.dart';
import 'package:zapp/core/vault.dart';
import 'package:z_protocol/z_protocol.dart';

class _EmptyHost implements KtHost {
  @override
  Future<List<KtContactInput>> ktContacts() async => const [];
  @override
  Future<KtOwnInput?> ktOwn() async => null;
  @override
  Future<bool> ktInstallFromLog(String rid, SignedDeviceList list) async => false;
  @override
  void ktChanged() {}
}

/// Answers each POST from a script, in order, and remembers what it saw.
class _ScriptedFetcher implements KtFetcher {
  _ScriptedFetcher(this.answers);
  final List<int> answers;
  final List<String> posts = [];
  @override
  Future<KtResponse> get(Uri url) async => KtResponse(500, '{}');
  @override
  Future<KtResponse> post(Uri url, String jsonBody) async {
    posts.add(jsonBody);
    final status = answers.isEmpty ? 500 : answers.removeAt(0);
    return KtResponse(status, status == 201 ? '{"index":0}' : '{"error":"x","message":"x"}');
  }
}

Future<KeyTransparency> ktWith(Directory dir, KtFetcher f) async {
  final vault = await Vault.open(rootOverride: dir);
  return KeyTransparency(
    vault: vault,
    host: _EmptyHost(),
    fetcher: f,
    config: KtConfig(logUrl: 'http://127.0.0.1:1', logPubB64: b64(Uint8List(32))),
  )..publishRetryDelay = const Duration(milliseconds: 100);
}

Future<void> publishOnce(KeyTransparency kt, {int version = 1}) async {
  final seed = Uint8List.fromList(List<int>.generate(32, (i) => i + 1));
  final kp = await Ed25519().newKeyPairFromSeed(seed);
  final pub = Uint8List.fromList((await kp.extractPublicKey()).bytes);
  await kt.publishOwnList(
    accountEdSeed: seed,
    accountEdPub: pub,
    version: version,
    fp: Uint8List.fromList(List<int>.filled(16, 7)),
    listJson: '{"a":"list"}',
  );
}

Future<void> settle() => Future<void>.delayed(const Duration(milliseconds: 20));

void main() {
  late Directory dir;
  setUp(() async {
    dir = await Directory.systemTemp.createTemp('z_kt_retry');
  });
  tearDown(() => dir.delete(recursive: true).catchError((_) => dir));

  test('1. a 429 keeps the publish queued and it is sent again soon, and is not a failure', () async {
    final f = _ScriptedFetcher([429, 429, 201]);
    final kt = await ktWith(dir, f);
    addTearDown(kt.dispose);
    await publishOnce(kt);
    await settle();
    expect(f.posts.length, 1, reason: 'sent once, answered 429');
    // Kept: in memory, and in the vault so a restart keeps it too.
    expect(await kt.vault.kvGet('kt_pub_pending'), isNotNull,
        reason: 'the publish stays queued — a 429 is not a refusal the log will repeat');
    expect(await kt.vault.kvGet('kt_pub_done'), isNull);
    expect(kt.lastFailMs, 0, reason: 'a log at capacity is a reachable log');

    // Tried again after the delay, not at the next check; the second 429 is
    // waited out the same way; the 201 clears it.
    await Future<void>.delayed(const Duration(milliseconds: 150));
    expect(f.posts.length, 2, reason: 'retried after publishRetryDelay');
    await Future<void>.delayed(const Duration(milliseconds: 150));
    expect(f.posts.length, 3);
    await settle();
    expect(await kt.vault.kvGet('kt_pub_pending'), isNull, reason: 'accepted, so cleared');
    expect(await kt.vault.kvGet('kt_pub_done'), '1|${b64(Uint8List.fromList(List<int>.filled(16, 7)))}');
    // And it stays cleared: no further retry fires.
    await Future<void>.delayed(const Duration(milliseconds: 150));
    expect(f.posts.length, 3, reason: 'nothing left to send');
    expect(f.posts.every((p) => (jsonDecode(p) as Map)['v'] == 1), isTrue, reason: 'the same publish every time');
  });

  test('2. a 5xx keeps it and is counted; a 400 clears it', () async {
    final f = _ScriptedFetcher([503, 201]);
    final kt = await ktWith(dir, f);
    addTearDown(kt.dispose);
    await publishOnce(kt);
    await settle();
    expect(f.posts.length, 1);
    expect(await kt.vault.kvGet('kt_pub_pending'), isNotNull, reason: 'the log could not take it; it is kept');
    expect(kt.lastFailMs, greaterThan(0), reason: 'and that is counted as a failure to reach a working log');
    await Future<void>.delayed(const Duration(milliseconds: 150));
    expect(f.posts.length, 2, reason: 'and retried');
    await settle();
    expect(await kt.vault.kvGet('kt_pub_pending'), isNull);

    // A 400 is the log saying the request itself is wrong: no retry fixes
    // that, so the queue is cleared as it always was.
    final g = _ScriptedFetcher([400]);
    final dir2 = await Directory.systemTemp.createTemp('z_kt_retry2');
    addTearDown(() => dir2.delete(recursive: true).catchError((_) => dir2));
    final kt2 = await ktWith(dir2, g);
    addTearDown(kt2.dispose);
    await publishOnce(kt2, version: 2);
    await settle();
    expect(g.posts.length, 1);
    expect(await kt2.vault.kvGet('kt_pub_pending'), isNull, reason: 'malformed is final');
    await Future<void>.delayed(const Duration(milliseconds: 150));
    expect(g.posts.length, 1, reason: 'and not retried');
  });
}
