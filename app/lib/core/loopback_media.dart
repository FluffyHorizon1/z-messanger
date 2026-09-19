import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

/// Serves already-decrypted media bytes to a player over `127.0.0.1`, from
/// memory, so a received video is never written to disk in plaintext — the
/// vault invariant (continuous-b playback, ADR 0018).
///
/// `video_player` can only open a URL or a file. The voice notes solve the same
/// problem through `just_audio`'s own loopback server (`MemoryAudioSource`);
/// this is the same route for a player that does not bring one. What guards
/// the bytes, since any process on the device can reach a localhost port
/// (THREAT_MODEL R36):
///
/// - bound to the loopback interface only, on a random port;
/// - one random 32-byte path per server (`Random.secure()`), and a request for
///   anything else is a bare 404 — the port alone finds nothing;
/// - a request from a non-loopback address is refused (belt and braces: the
///   socket is loopback-bound, so none can arrive);
/// - alive only while the bubble that opened it is mounted; [close] tears the
///   socket down and drops the reference to the bytes;
/// - `Cache-Control: no-store`, so a platform HTTP stack has no licence to
///   write the body to a disk cache.
///
/// Byte ranges are supported (players seek), single-range only, as RFC 9110
/// §14 describes: `206` with `Content-Range` for a satisfiable range, `416` for
/// one that is not, and the whole body for a request with no usable `Range`.
class LoopbackMediaServer {
  final Uint8List _bytes;
  final String mime;
  final String _token;
  HttpServer? _server;

  LoopbackMediaServer._(this._bytes, this.mime, this._token);

  /// Servers currently listening. A test hook: the bubble that opens one must
  /// close it on dispose and on every failure, and this is how that is proved.
  static int openServers = 0;

  /// The URL the player opens. Only meaningful while the server is running.
  Uri get uri => Uri(
      scheme: 'http',
      host: _server!.address.address,
      port: _server!.port,
      path: '/$_token');

  bool get isRunning => _server != null;

  int get length => _bytes.length;

  /// A mime the picker or the sender wrote; a malformed one must not turn a
  /// request into a half-written response, so it falls back to octet-stream.
  static ContentType _contentType(String mime) {
    try {
      return ContentType.parse(mime);
    } catch (_) {
      return ContentType.binary;
    }
  }

  static String _newToken() {
    final r = Random.secure();
    final raw = Uint8List.fromList(List.generate(32, (_) => r.nextInt(256)));
    return base64UrlEncode(raw).replaceAll('=', '');
  }

  /// Binds a fresh server on the loopback interface and starts serving
  /// [bytes] as [mime] under a new random path.
  static Future<LoopbackMediaServer> start(Uint8List bytes, String mime) async {
    final s = LoopbackMediaServer._(bytes, mime, _newToken());
    final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    s._server = server;
    openServers++;
    server.listen(s._handle, onError: (_) {}, cancelOnError: false);
    return s;
  }

  Future<void> _handle(HttpRequest req) async {
    final res = req.response;
    try {
      final remote = req.connectionInfo?.remoteAddress;
      if (remote == null || !remote.isLoopback) {
        res.statusCode = HttpStatus.forbidden;
        return;
      }
      if (req.method != 'GET' && req.method != 'HEAD') {
        res.statusCode = HttpStatus.methodNotAllowed;
        return;
      }
      if (req.uri.path != '/$_token') {
        res.statusCode = HttpStatus.notFound;
        return;
      }
      res.headers.contentType = _contentType(mime);
      res.headers.set(HttpHeaders.acceptRangesHeader, 'bytes');
      res.headers.set(HttpHeaders.cacheControlHeader, 'no-store');
      final range = parseRange(req.headers.value(HttpHeaders.rangeHeader),
          _bytes.length);
      switch (range) {
        case Unsatisfiable():
          res.statusCode = HttpStatus.requestedRangeNotSatisfiable;
          res.headers.set(
              HttpHeaders.contentRangeHeader, 'bytes */${_bytes.length}');
          return;
        case PartialBody(:final start, :final end):
          res.statusCode = HttpStatus.partialContent;
          res.headers.set(HttpHeaders.contentRangeHeader,
              'bytes $start-$end/${_bytes.length}');
          res.contentLength = end - start + 1;
          if (req.method == 'GET') {
            res.add(Uint8List.sublistView(_bytes, start, end + 1));
          }
          return;
        case FullBody():
          res.statusCode = HttpStatus.ok;
          res.contentLength = _bytes.length;
          if (req.method == 'GET') res.add(_bytes);
          return;
      }
    } catch (_) {
      // A broken pipe from a player that seeked away is not an error worth
      // surfacing; the next request is served afresh.
    } finally {
      try {
        await res.close();
      } catch (_) {}
    }
  }

  /// Stops listening and closes every connection. Idempotent. The bytes are
  /// unreachable the moment this returns.
  Future<void> close() async {
    final s = _server;
    _server = null;
    if (s != null) {
      openServers--;
      await s.close(force: true);
    }
  }
}

/// What a `Range` header asks for, against a body of `length` bytes.
sealed class RangeResult {
  const RangeResult();
}

/// No `Range` header, or one this server does not honour (a multi-range, or
/// malformed) — the whole body is served with `200`, as RFC 9110 permits.
class FullBody extends RangeResult {
  const FullBody();
}

/// A satisfiable single range; [start] and [end] are inclusive byte offsets.
class PartialBody extends RangeResult {
  final int start;
  final int end;
  const PartialBody(this.start, this.end);
}

/// A well-formed single range that lies entirely outside the body — `416`.
class Unsatisfiable extends RangeResult {
  const Unsatisfiable();
}

/// Parses a single `bytes=` range. Supports `a-b`, `a-` and `-n` (the last n
/// bytes); an `end` past the body is clipped to it, as the RFC says.
RangeResult parseRange(String? header, int length) {
  if (header == null) return const FullBody();
  final h = header.trim();
  if (!h.startsWith('bytes=')) return const FullBody();
  final spec = h.substring('bytes='.length).trim();
  if (spec.contains(',')) return const FullBody(); // multi-range: not honoured
  final dash = spec.indexOf('-');
  if (dash < 0) return const FullBody();
  final a = spec.substring(0, dash).trim();
  final b = spec.substring(dash + 1).trim();
  if (a.isEmpty && b.isEmpty) return const FullBody();
  if (length == 0) return const Unsatisfiable();
  if (a.isEmpty) {
    // suffix range: the last n bytes
    final n = int.tryParse(b);
    if (n == null || n <= 0) return const FullBody();
    final start = n >= length ? 0 : length - n;
    return PartialBody(start, length - 1);
  }
  final start = int.tryParse(a);
  if (start == null || start < 0) return const FullBody();
  if (start >= length) return const Unsatisfiable();
  if (b.isEmpty) return PartialBody(start, length - 1);
  final end = int.tryParse(b);
  if (end == null || end < start) return const FullBody();
  return PartialBody(start, end >= length ? length - 1 : end);
}
