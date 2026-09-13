import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// Hand one piece of text to the platform's share sheet.
///
/// Returns false where there is no share sheet — every platform but Android
/// today, and an Android device where nothing can take an `ACTION_SEND`. The
/// caller falls back to the clipboard and says which happened, rather than
/// offering a button that sometimes does nothing.
///
/// Text only, deliberately: an invite is a bearer token (R23), and a subject
/// line would put a second copy of it in a mail header and a notification
/// preview for no benefit.
class ShareText {
  static const MethodChannel _channel = MethodChannel('z/share');

  /// Overridable so a test can assert what was handed over, and what happens
  /// when the platform says it cannot.
  @visibleForTesting
  static Future<bool> Function(String text)? debugHandler;

  static Future<bool> share(String text) async {
    if (debugHandler != null) return debugHandler!(text);
    if (text.isEmpty) return false;
    try {
      final ok = await _channel.invokeMethod<bool>('text', {'text': text});
      return ok ?? false;
    } on MissingPluginException {
      return false; // no native side on this platform
    } on PlatformException {
      return false;
    }
  }
}
