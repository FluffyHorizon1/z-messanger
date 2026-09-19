import 'package:mobile_scanner/mobile_scanner.dart';

/// 24.3 — read a QR code out of an image file, for the platforms that have no
/// live camera scan (everything but Android today). The decode itself is
/// `mobile_scanner`'s and is platform‑gated — supported where MLKit/Vision is
/// (Android, iOS, macOS), unimplemented elsewhere.
///
/// The property that matters here, and the reason this wrapper exists, is that
/// it is **quiet**: no code in the image, an unreadable file, or a platform
/// with no decoder at all is a `null`, never a throw. The caller shows "no
/// code found" rather than crashing, so offering the button on a platform
/// where the decode may not work ships nothing broken.

/// How the raw text is pulled from an image path. Injectable so the wrapper's
/// graceful‑failure contract can be tested without a real decoder.
typedef RawQrRead = Future<String?> Function(String path);

Future<String?> _readViaScanner(String path) async {
  final controller = MobileScannerController();
  try {
    final capture = await controller.analyzeImage(path);
    if (capture == null || capture.barcodes.isEmpty) return null;
    return capture.barcodes.first.rawValue;
  } finally {
    await controller.dispose();
  }
}

/// Decode a QR from the image at [path], or return null. Every failure — no
/// code, an empty result, a decoder that throws or is not implemented on this
/// platform — is a quiet null.
Future<String?> readQrImage(String path, {RawQrRead? read}) async {
  try {
    final code = await (read ?? _readViaScanner)(path);
    return (code != null && code.isNotEmpty) ? code : null;
  } catch (_) {
    return null;
  }
}
