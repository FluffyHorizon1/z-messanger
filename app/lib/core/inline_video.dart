/// Where a received video plays inline (continuous-b, playback half).
///
/// Android only for now: it is the platform the capture half targets, and the
/// one whose `video_player` implementation the app ships and can be exercised
/// on hardware. Everywhere else the message keeps the file card + Save, exactly
/// as before — the platform policy is a function so the decision is testable
/// and visible, as `mediaKitAudioFor` is for 24.1. Widening it (macOS has an
/// AVFoundation implementation; iOS is the iOS track's call) is one line here.
bool inlineVideoFor(String operatingSystem, {bool isWeb = false}) =>
    !isWeb && operatingSystem == 'android';
