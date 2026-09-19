// 24.3 — reading a QR out of an image file, for platforms with no camera scan.
//
// The decode is mobile_scanner's and is platform-gated; what is pinned here is
// the wrapper's promise that it is QUIET. A decoded code comes back; a missing
// code, an empty result, or a decoder that throws (including "not implemented
// on this platform") is a null, never an exception — so the screen offering
// this on a platform where the decode may not work shows "no code found"
// instead of crashing.
import 'package:flutter_test/flutter_test.dart';
import 'package:zapp/core/qr_image.dart';

void main() {
  test('a decoded code is returned as-is', () async {
    expect(await readQrImage('img', read: (_) async => 'zc1.abc'), 'zc1.abc');
  });

  test('no code, an empty result, or a throw are all a quiet null', () async {
    expect(await readQrImage('img', read: (_) async => null), isNull);
    expect(await readQrImage('img', read: (_) async => ''), isNull);
    expect(
        await readQrImage('img',
            read: (_) async => throw UnimplementedError('no decoder here')),
        isNull);
  });
}
