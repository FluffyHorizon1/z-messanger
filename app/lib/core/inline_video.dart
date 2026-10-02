/// Where a received video plays inline (continuous-b, playback half).
///
/// Android, where the capture half lives, and macOS, where `video_player` has
/// an AVFoundation implementation and the app already plays voice notes over
/// the same kind of loopback socket. Everywhere else the message keeps the
/// file card + Save, exactly as before — the platform policy is a function so
/// the decision is testable and visible, as `mediaKitAudioFor` is for 24.1.
///
/// macOS needs one thing Android does not: the sandbox refuses a listening
/// socket, loopback included, unless the build carries
/// `com.apple.security.network.server`, and until 2026-10-02 only the DEBUG
/// entitlements did (the Flutter template puts it there for the tooling). A
/// release build without it cannot open `LoopbackMediaServer` at all, and the
/// bubble falls back to its "cannot play" notice and Save — so the key in
/// `macos/Runner/Release.entitlements` and this line belong together. iOS is
/// the iOS track's call; Linux and Windows have no `video_player`
/// implementation.
bool inlineVideoFor(String operatingSystem, {bool isWeb = false}) =>
    !isWeb && (operatingSystem == 'android' || operatingSystem == 'macos');
