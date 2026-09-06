# Play Console recommendations — status

What the Play Console flagged for the version-code-6 upload, what was done
about each item, and what is deliberately left alone. Re-check this list
whenever the Console shows a new recommendation; most of them are static
scans of the bundle and its libraries, so a plugin bump can add or remove
one without any change to Z's own code.

| Recommendation | Category | Status |
|---|---|---|
| Recompile with 16 KB native library alignment | Technical quality (**required** for Android 15+ targets) | **Fixed** — see below; verified by `app/tool/check_16k.sh`, which now runs in CI on every APK and AAB |
| Edge-to-edge may not display for all users | User experience | **Done** — edge-to-edge on every Android version, screens inset their own content; regression test `app/test/edge_to_edge_test.dart` |
| Improve performance with bitmap downsampling | Memory usage | **Not ours** — the two flagged classes are inside third-party libraries, on code paths Z never triggers; details below |
| Implement picture-in-picture | User experience | **Not applicable** — Z has no video playback; nothing to pin |

## 16 KB memory pages

Android 15 can run on devices with 16 KB memory pages. A native library
whose ELF `PT_LOAD` segments are only 4 KB aligned cannot be mapped there,
so the app fails to install or crashes at start, and Play refuses new
uploads that target Android 15+ without it.

Z's own native code (Flutter engine `libflutter.so`, the Dart AOT
snapshot `libapp.so`) has been aligned since Flutter 3.27. The offenders
were two libraries pulled in by the QR-scanner plugin `mobile_scanner`
5.2.3: ML Kit's `libbarhopper_v3.so` and CameraX's
`libimage_processing_util_jni.so`, both 4 KB. Upgrading to
`mobile_scanner` 7.4.0 (ML Kit barcode-scanning 17.3.0, CameraX 1.6.1)
replaced them with 16 KB-aligned builds; the Dart usage — a `MobileScanner`
widget with an `onDetect` callback — did not change. `libsqlite3.so`
(`sqlite3_flutter_libs`) was already aligned for arm64.

`app/tool/check_16k.sh <apk|aab>` lists every 64-bit library with its
alignment, checks the zip entries with `zipalign -P 16`, and fails on any
4 KB library; CI runs it on both artifacts, so a future plugin bump that
regresses this fails the build instead of the Play upload. The 32-bit
`armeabi-v7a` libraries are exempt — 16 KB pages exist on 64-bit devices
only.

To test on a real 16 KB environment: an Android 15+ emulator system image
with "16 KB page size" in its name, or a Pixel 8/9 with the developer
option *Boot with 16 KB page size*. `adb shell getconf PAGE_SIZE` reports
16384 when it is in effect.

## Edge-to-edge

Apps that target SDK 35 draw under the status and navigation bars on
Android 15+. Flutter reports those bars as `MediaQuery` padding, and most
of Z's screens were already insetting their content — `AppBar`, a
`ListView` without an explicit `padding`, `Scaffold`'s FAB placement and
the chat composer's `SafeArea` all do it themselves. Three things were
missing and are now handled:

- `ListView`s that set their own `padding` (link/linked-device screens,
  contact info, the paste-a-code tab) lose the automatic inset, so they add
  `MediaQuery.paddingOf(context).bottom` to it.
- Centred forms in a `SingleChildScrollView` (onboarding, unlock, lock)
  sit inside a `SafeArea`, so an overflowing form scrolls fully above the
  navigation bar instead of ending under it. The camera tab's caption
  likewise.
- `main.dart` calls `SystemChrome.setEnabledSystemUIMode(edgeToEdge)` with
  transparent bars on **every** Android version, so the layout is the same
  on Android 12 as on 15 rather than changing at the SDK-35 boundary (the
  Console's "call `enableEdgeToEdge()` for backward compatibility").

`app/test/edge_to_edge_test.dart` renders the unlock and lock screens in a
viewport with a simulated 48-px navigation bar and too little height, and
asserts the last element still clears the bar; removing a `SafeArea` makes
it fail.

## Bitmap downsampling

The Console names two obfuscated classes (`a3.va.a`, `i0.a.f`) that call
`BitmapFactory.decode*` without `BitmapFactory.Options`. R8 names differ
per build, so the release dex was scanned directly (`dexdump`, then the
`mapping.txt` of the same build). Every such call in Z's APK is in a
library, none in Z's code:

| Caller | Library | When it runs |
|---|---|---|
| `FlutterLocalNotificationsPlugin.getBitmapFromSource / getIconFromSource` | flutter_local_notifications | only for large icons / big-picture styles / file-based icons — Z uses the default small icon and never passes an image |
| `com.google.firebase.messaging.ImageDownload` | firebase_messaging | only for notification messages with an image — Z's pushes are content-free wake-ups (`push-register` in `docs/PROTOCOL.md` §12), never displayed by Firebase itself |
| `com.google.mlkit.vision.common.internal.ImageConvertUtils` | ML Kit barcode scanning | converting camera frames while the QR scanner is open — frames are already at camera-preview resolution |
| `androidx.camera.camera2.pipe.compat.*`, `androidx.core.graphics.drawable.IconCompat` | CameraX / AndroidX | internal |

Nothing to fix in Z; the recommendation is informational (it does not
block a release). It will clear on its own when those libraries adopt
`Options`, and the table above is what to re-check if the Console lists new
class names after a plugin bump.

## Picture-in-picture

PiP keeps a video playing in a floating window while the user does
something else. Z has no video: attachments open in the system viewer and
voice notes are audio. Adding a PiP activity would add a permission-like
capability with nothing to show in it, so the recommendation is declined
on purpose.
