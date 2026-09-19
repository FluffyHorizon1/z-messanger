import 'dart:convert';
import 'dart:io';

/// 24.4 — the "you're behind" check.
///
/// There is no in-app updater (that would be a code-execution channel into
/// every install — THREAT_MODEL R8); this only *tells* the user a newer build
/// exists and links them to it. It is designed to add no metadata beyond what
/// the relay already has (R35): it asks the relay's OWN host, derived from the
/// address the client already dials, over a plain GET that carries no account,
/// no routing id and no cookie — the same `/latest.json` every install gets.
/// It is not a background poll; Settings triggers it, at most once a day.

/// Parse a plain `x.y.z` (ignoring any `-pre`/`+build` tail) into [maj, min,
/// pat]. Returns null for anything that is not that shape, so a malformed
/// version — on either side — can never be read as "newer".
List<int>? parseSemver(String v) {
  final m = RegExp(r'^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$').firstMatch(v.trim());
  if (m == null) return null;
  return [int.parse(m[1]!), int.parse(m[2]!), int.parse(m[3]!)];
}

/// True only when [latest] is strictly newer than [current]. If either fails
/// to parse, the answer is false: a broken or missing answer must never nag.
bool isBehind(String current, String latest) {
  final c = parseSemver(current), l = parseSemver(latest);
  if (c == null || l == null) return false;
  for (var i = 0; i < 3; i++) {
    if (l[i] != c[i]) return l[i] > c[i];
  }
  return false;
}

/// The `/latest.json` URL for the relay the client dials: the SAME host, and a
/// scheme as protected as the relay's own — `https` for a `wss` relay, `http`
/// for a `ws` one. Returns null if [relayUrl] is not a ws/wss URL, so a
/// malformed address simply yields no check rather than reaching out anywhere
/// unexpected.
Uri? latestJsonUrl(String relayUrl) {
  final u = Uri.tryParse(relayUrl.trim());
  if (u == null || !u.hasAuthority) return null;
  final scheme = switch (u.scheme) {
    'wss' => 'https',
    'ws' => 'http',
    _ => null,
  };
  if (scheme == null) return null;
  return Uri(scheme: scheme, host: u.host, port: u.hasPort ? u.port : null, path: '/latest.json');
}

/// The outcome of a check. [behind] is the only thing the UI acts on; [latest]
/// and [url] are what it shows when [behind] is true.
class UpdateStatus {
  final String current;
  final String? latest;
  final String? url;
  final bool behind;
  const UpdateStatus(
      {required this.current, this.latest, this.url, this.behind = false});

  Map<String, Object?> toJson() =>
      {'current': current, 'latest': latest, 'url': url, 'behind': behind};
}

/// A plain, identity-free GET: no cookies, no auth, no body, a short timeout.
/// Returns the body on 200, null on anything else (including a refusal, a
/// redirect or a network error) so the caller treats every non-answer alike.
Future<String?> _defaultGet(Uri url) async {
  final client = HttpClient()..connectionTimeout = const Duration(seconds: 8);
  try {
    final req = await client.getUrl(url);
    // Nothing that identifies this install rides along.
    req.followRedirects = false;
    req.headers.removeAll(HttpHeaders.cookieHeader);
    final res = await req.close().timeout(const Duration(seconds: 8));
    if (res.statusCode != 200) {
      await res.drain<void>();
      return null;
    }
    return await res.transform(utf8.decoder).join();
  } catch (_) {
    return null;
  } finally {
    client.close(force: true);
  }
}

/// Fetch `/latest.json` from [relayUrl]'s host and compare to [current].
///
/// [get] is injectable so tests need no network. Any failure — an address that
/// is not ws/wss, an unreachable or unset endpoint, a non-200, a malformed or
/// non-semver body — returns a not-behind status: the check never turns a bad
/// answer into a prompt.
Future<UpdateStatus> checkForUpdate({
  required String current,
  required String relayUrl,
  Future<String?> Function(Uri url)? get,
}) async {
  final url = latestJsonUrl(relayUrl);
  if (url == null) return UpdateStatus(current: current);
  final body = await (get ?? _defaultGet)(url);
  if (body == null) return UpdateStatus(current: current);
  try {
    final j = (jsonDecode(body) as Map).cast<String, Object?>();
    final latest = j['version'] as String?;
    final link = j['url'] as String?;
    if (latest == null) return UpdateStatus(current: current);
    return UpdateStatus(
      current: current,
      latest: latest,
      url: link,
      behind: isBehind(current, latest),
    );
  } catch (_) {
    return UpdateStatus(current: current);
  }
}
