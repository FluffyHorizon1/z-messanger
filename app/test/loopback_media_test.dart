// continuous-b (playback): the loopback server that hands decrypted video
// bytes to the player from memory (ADR 0018). It exists so a received video is
// never written to disk in plaintext, and since any process on the device can
// reach a localhost port, what protects the bytes is the random path and the
// server's short life — so those are what is pinned here, along with the byte
// ranges a seeking player relies on.
//
// Criteria, each a test below:
//   1. the token path serves exactly the bytes, as the given mime, marked
//      no-store and range-capable; any other path is a bare 404 and any
//      method but GET/HEAD is 405 — the port alone finds nothing;
//   2. single byte ranges are honoured per RFC 9110: `a-b`, `a-`, `-n`, an end
//      past the body clipped, and a start past the body refused with 416;
//   3. HEAD carries the headers and length and no body;
//   4. the socket is bound to the loopback interface on a random port, and
//      every server gets its own token and port;
//   5. after close(), nothing listens: the port refuses connections;
//   6. parseRange itself: no header, a multi-range and a malformed range mean
//      the whole body; a suffix longer than the body means the whole body as a
//      range; an empty body cannot satisfy any range.
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/loopback_media.dart';

Future<(HttpClientResponse, List<int>)> get(Uri u,
    {String method = 'GET', Map<String, String> headers = const {}}) async {
  final c = HttpClient();
  try {
    final req = await c.openUrl(method, u);
    headers.forEach(req.headers.set);
    final res = await req.close();
    final body = <int>[];
    await for (final chunk in res) {
      body.addAll(chunk);
    }
    return (res, body);
  } finally {
    c.close(force: true);
  }
}

void main() {
  HttpOverrides.global = null;
  final bytes = Uint8List.fromList(List.generate(10, (i) => i * 11));

  test('1. the token path serves the bytes; anything else finds nothing',
      () async {
    final s = await LoopbackMediaServer.start(bytes, 'video/mp4');
    try {
      final (res, body) = await get(s.uri);
      expect(res.statusCode, 200);
      expect(body, bytes);
      expect(res.headers.contentType?.mimeType, 'video/mp4');
      expect(res.headers.value(HttpHeaders.acceptRangesHeader), 'bytes');
      expect(res.headers.value(HttpHeaders.cacheControlHeader), 'no-store');

      final wrong = s.uri.replace(path: '/not-the-token');
      final (r404, b404) = await get(wrong);
      expect(r404.statusCode, 404);
      expect(b404, isEmpty, reason: 'a miss says nothing');

      final (r405, _) = await get(s.uri, method: 'POST');
      expect(r405.statusCode, 405);
    } finally {
      await s.close();
    }
  });

  test('2. single byte ranges are honoured, and an impossible one is 416',
      () async {
    final s = await LoopbackMediaServer.start(bytes, 'video/mp4');
    try {
      final (r1, b1) = await get(s.uri, headers: {'Range': 'bytes=0-3'});
      expect(r1.statusCode, 206);
      expect(r1.headers.value(HttpHeaders.contentRangeHeader), 'bytes 0-3/10');
      expect(b1, bytes.sublist(0, 4));

      final (r2, b2) = await get(s.uri, headers: {'Range': 'bytes=7-'});
      expect(r2.statusCode, 206);
      expect(r2.headers.value(HttpHeaders.contentRangeHeader), 'bytes 7-9/10');
      expect(b2, bytes.sublist(7));

      final (r3, b3) = await get(s.uri, headers: {'Range': 'bytes=-2'});
      expect(r3.statusCode, 206);
      expect(r3.headers.value(HttpHeaders.contentRangeHeader), 'bytes 8-9/10');
      expect(b3, bytes.sublist(8));

      final (r4, b4) = await get(s.uri, headers: {'Range': 'bytes=5-500'});
      expect(r4.statusCode, 206, reason: 'an end past the body is clipped');
      expect(r4.headers.value(HttpHeaders.contentRangeHeader), 'bytes 5-9/10');
      expect(b4, bytes.sublist(5));

      final (r5, _) = await get(s.uri, headers: {'Range': 'bytes=10-'});
      expect(r5.statusCode, 416, reason: 'a start past the body is refused');
      expect(r5.headers.value(HttpHeaders.contentRangeHeader), 'bytes */10');
    } finally {
      await s.close();
    }
  });

  test('3. HEAD carries the headers and the length, not the body', () async {
    final s = await LoopbackMediaServer.start(bytes, 'video/webm');
    try {
      final (res, body) = await get(s.uri, method: 'HEAD');
      expect(res.statusCode, 200);
      expect(res.headers.contentType?.mimeType, 'video/webm');
      expect(res.contentLength, 10);
      expect(body, isEmpty);
      final (r2, b2) =
          await get(s.uri, method: 'HEAD', headers: {'Range': 'bytes=0-3'});
      expect(r2.statusCode, 206);
      expect(r2.contentLength, 4);
      expect(b2, isEmpty);
    } finally {
      await s.close();
    }
  });

  test('4. loopback only, random port, a token of its own per server',
      () async {
    final a = await LoopbackMediaServer.start(bytes, 'video/mp4');
    final b = await LoopbackMediaServer.start(bytes, 'video/mp4');
    try {
      expect(a.uri.host, '127.0.0.1');
      expect(b.uri.host, '127.0.0.1');
      expect(a.uri.port, isNot(0));
      expect(a.uri.port, isNot(b.uri.port));
      expect(a.uri.path, isNot(b.uri.path));
      // 32 random bytes, base64url without padding: 43 characters.
      expect(a.uri.path.length, 1 + 43);
      expect(a.uri.path, matches(RegExp(r'^/[A-Za-z0-9_-]{43}$')));
      // b's token does not open a.
      final (r, _) = await get(a.uri.replace(path: b.uri.path));
      expect(r.statusCode, 404);
    } finally {
      await a.close();
      await b.close();
    }
  });

  test('5. after close(), the port refuses connections', () async {
    final s = await LoopbackMediaServer.start(bytes, 'video/mp4');
    final u = s.uri;
    final (ok, _) = await get(u);
    expect(ok.statusCode, 200);
    await s.close();
    expect(s.isRunning, isFalse);
    await expectLater(get(u), throwsA(isA<SocketException>()),
        reason: 'nothing listens once the bubble is gone');
    await s.close(); // idempotent
  });

  test('6. parseRange: what is a range and what is the whole body', () {
    expect(parseRange(null, 10), isA<FullBody>());
    expect(parseRange('bytes=0-1,3-4', 10), isA<FullBody>(),
        reason: 'a multi-range is not honoured; the whole body is fine');
    expect(parseRange('bytes=', 10), isA<FullBody>());
    expect(parseRange('bytes=x-y', 10), isA<FullBody>());
    expect(parseRange('items=0-1', 10), isA<FullBody>());
    expect(parseRange('bytes=3-1', 10), isA<FullBody>(),
        reason: 'end before start is malformed, not unsatisfiable');
    final suffix = parseRange('bytes=-50', 10);
    expect(suffix, isA<PartialBody>());
    expect((suffix as PartialBody).start, 0);
    expect(suffix.end, 9);
    expect(parseRange('bytes=0-', 0), isA<Unsatisfiable>());
    final open = parseRange('bytes=4-', 10) as PartialBody;
    expect((open.start, open.end), (4, 9));
  });
}
