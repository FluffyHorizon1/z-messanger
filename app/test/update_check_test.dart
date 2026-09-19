// 24.4 — the "you're behind" check, without the network.
//
// There is no in-app updater; this only tells the user a newer build exists
// (THREAT_MODEL R8, R35). What is checked here is that it is honest and quiet:
// it only ever says "behind" when a well-formed, strictly-newer version comes
// back, it asks the relay's OWN host and nowhere else, and every bad or absent
// answer is a silent not-behind rather than a prompt. The metadata posture —
// no account, no routing id, the same file for everyone — is the server's to
// serve (server/test/pages.test.js) and is asserted here as "the URL it asks
// is the relay host's /latest.json, derived from the address already dialled".
//
// Criteria, each a test below:
//  1. semver compares as versions, not strings, and a malformed version — on
//     either side — is never "behind", so a broken answer cannot nag;
//  2. the URL asked is the relay's own host, https for a wss relay and http
//     for a ws one, and a non-ws address yields no check at all;
//  3. a strictly-newer /latest.json is reported behind, carrying the version
//     and the link to show;
//  4. an equal or older version is not behind;
//  5. every non-answer — a 404/unreachable (null body), a malformed body, a
//     body with no version — is not-behind, never a prompt.
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/update_check.dart';

void main() {
  const relay = 'wss://www.zmessengers.com';

  test('1. semver compares as versions, and a malformed version is never behind',
      () {
    expect(isBehind('3.6.10', '3.7.0'), isTrue);
    expect(isBehind('3.6.9', '3.6.10'), isTrue, reason: '10 > 9, not "1.0" < "9"');
    expect(isBehind('3.7.0', '3.7.0'), isFalse);
    expect(isBehind('3.7.1', '3.7.0'), isFalse);
    expect(isBehind('3.7.0', '3.7.0+165'), isFalse, reason: 'build tail ignored');
    // A version that does not parse, on either side, is never behind.
    expect(isBehind('3.7.0', 'latest'), isFalse);
    expect(isBehind('unknown', '3.7.0'), isFalse);
    expect(parseSemver('3.7.0-rc1'), [3, 7, 0]);
    expect(parseSemver('v3.7.0'), isNull);
  });

  test('2. the URL is the relay\'s own host, and a non-ws address yields no check',
      () async {
    expect(latestJsonUrl('wss://www.zmessengers.com').toString(),
        'https://www.zmessengers.com/latest.json');
    expect(latestJsonUrl('ws://127.0.0.1:8080').toString(),
        'http://127.0.0.1:8080/latest.json');
    expect(latestJsonUrl('https://example.com'), isNull);
    expect(latestJsonUrl('not a url at all'), isNull);

    // checkForUpdate on a non-ws relay must not reach out at all.
    var called = false;
    final s = await checkForUpdate(
        current: '3.7.0',
        relayUrl: 'https://example.com',
        get: (u) async {
          called = true;
          return null;
        });
    expect(called, isFalse, reason: 'a non-ws address yields no fetch');
    expect(s.behind, isFalse);
  });

  test('3. a strictly-newer latest is reported behind, with version and link',
      () async {
    Uri? asked;
    final s = await checkForUpdate(
      current: '3.6.10',
      relayUrl: relay,
      get: (u) async {
        asked = u;
        return jsonEncode({'version': '3.7.0', 'url': 'https://x/releases/latest'});
      },
    );
    expect(asked.toString(), 'https://www.zmessengers.com/latest.json',
        reason: 'it asks the relay host it was given, nowhere else');
    expect(s.behind, isTrue);
    expect(s.latest, '3.7.0');
    expect(s.url, 'https://x/releases/latest');
  });

  test('4. an equal or older version is not behind', () async {
    for (final v in ['3.7.0', '3.6.9']) {
      final s = await checkForUpdate(
          current: '3.7.0',
          relayUrl: relay,
          get: (u) async => jsonEncode({'version': v}));
      expect(s.behind, isFalse, reason: 'current 3.7.0 vs latest $v');
    }
  });

  test('5. every non-answer is a silent not-behind, never a prompt', () async {
    // 404 / unreachable — the injected get returns null for both.
    final nulled = await checkForUpdate(
        current: '3.6.10', relayUrl: relay, get: (u) async => null);
    expect(nulled.behind, isFalse);
    expect(nulled.latest, isNull);

    // A body that is not JSON, and JSON with no version.
    for (final body in ['not json', '{}', '{"url":"x"}', '[]']) {
      final s = await checkForUpdate(
          current: '3.6.10', relayUrl: relay, get: (u) async => body);
      expect(s.behind, isFalse, reason: 'body: $body');
    }
  });
}
