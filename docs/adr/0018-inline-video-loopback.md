# ADR 0018 — Inline video plays from memory over a loopback socket, never from a file

**Status:** **Accepted** (2026‑09‑19) — built (continuous‑b, playback half; 3.7.9).
Android only for now; every other platform keeps the file card + Save.
**Decides:** how a received video is played inside the chat without breaking
the vault invariant, and what that costs.

## Context

The capture half of continuous‑b (ADR 0016) lets a photo or a gallery video be
attached directly. Received videos still arrived as a file card: Save, then
open elsewhere. Playing them inline is the obvious other half, and it runs
straight into the vault invariant (C11): decrypted content is never written to
disk in plaintext.

`video_player` — the Flutter team's package, the choice made when this was
scoped — opens a **URL or a file**. It has no in‑memory source. The voice notes
(7.4) faced the same wall with `just_audio` and got over it because `just_audio`
brings its own loopback HTTP server: a `StreamAudioSource` (`MemoryAudioSource`)
is served to the native player over `127.0.0.1`, and the decrypted note travels
as bytes on a socket, never as a file. `video_player` brings no such server.

## Decision

**The app runs the loopback server itself.** `LoopbackMediaServer`
(`core/loopback_media.dart`) binds `127.0.0.1` on a random port, serves the
decrypted bytes from memory under one random 32‑byte path, supports single byte
ranges (players seek), and lives exactly as long as the bubble that opened it.
`VideoNoteBody` (`ui/video_widgets.dart`) decrypts lazily on first play, starts
a server, hands `video_player` the URL, and closes the server in `dispose` and on
every failure. `_FileBody` renders it for a complete `video/*` attachment on
Android (`inlineVideoFor`, a platform policy function like 24.1's
`mediaKitAudioFor`); the Save action stays beneath it, as it does for images.

**What guards the bytes.** A loopback port is not private to a package: on
Android any app on the device can connect to it. So what stands between another
process and the plaintext is (1) the path — 32 bytes from `Random.secure()`,
`base64url`; a request for any other path is a bare 404, so the port alone
finds nothing; (2) the lifetime — the socket exists only while the video is on
screen; (3) `Cache-Control: no-store`, so the platform's HTTP stack has no
licence to write the body to a disk cache; (4) a request from a non‑loopback
address is refused, belt and braces on a loopback‑bound socket. The voice notes
have carried exactly this shape since 7.4 through `just_audio`'s server; this
ADR is the first to write the residual down (**R36**).

**No plaintext file, ever.** The server holds a `Uint8List` and streams from it;
there is no path in its API and nothing for a sweeper to catch. That is the
invariant, and `loopback_media_test.dart` pins what it rests on rather than
asserting "nothing on disk", which no test can prove in general.

## Rejected

- **Write the decrypted video to a temp file and play that.** Every player's
  easy path, and a direct C11 violation — the picker cache leak (2.8.4) is the
  precedent for how that ends. Non‑starter, regardless of how quickly the file
  is deleted after: it exists on disk while it plays, and the OS decides what
  "deleted" means.
- **Use `media_kit` for video too** (it is already a dependency for desktop
  audio, 24.1). It can play from a custom byte stream on desktop but brings
  libmpv to Android for this one feature, which 24.1 deliberately kept off
  mobile; and its Android path also ends in a loopback or a file. Not worth the
  surface for the same residual.
- **Widen to macOS/iOS now.** macOS has an AVFoundation implementation and the
  server is platform‑neutral, so it is one line in `inlineVideoFor`; iOS is the
  iOS track's decision. Held to Android to match the capture half and to keep
  this patch to the one design point.

## Consequences

- **Supply chain.** `video_player` pulls **7 packages**: `video_player`, its
  federated `_android`, `_avfoundation`, `_web`, `_platform_interface`, and
  `html` + `csslib` (dragged in by the web implementation, unused here). No
  existing package moved. `_android` adds Kotlin/Java and ExoPlayer — a native
  media stack on the device, which is what playing a video means; no bundled
  `.so` of our own. No `android/` or `ios/` project file changed.
- **THREAT_MODEL R36** records the loopback residual for both video and voice.
- **Wire, relay, ratchet, sealing:** untouched. A video is sealed and sent as any
  file is; this is a client‑side player on already‑decrypted bytes.
- **Memory.** A playing video is held decrypted in RAM, bounded by
  `maxAttachmentBytes` (24 MiB); the same is true of a voice note or an image.

## What was verified, and what is device‑gated

- **Verified here:** the server (six criteria: token path, ranges, HEAD,
  loopback‑only/random port/token per server, dead after close, `parseRange`);
  the bubble (three: the Android policy; nothing read or opened before play; a
  player that cannot start leaves a notice and **no server behind** — this test
  caught a real hang: `video_player`'s `dispose()` never completes for a
  controller whose `initialize()` threw, so the failure path no longer waits on
  it); analyzer clean; the l10n and a11y guards (the play control announces);
  the full app suite.
- **Device‑gated (hardware, not the sandbox):** actual playback and seeking on
  an Android device — ExoPlayer against the loopback URL, including a byte‑range
  seek. The test environment has no `video_player` implementation, so the path
  exercised here is the graceful failure — which is also the path a platform
  without a backend takes in the field.
