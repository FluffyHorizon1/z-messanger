# Reproducible builds (14.1)

Z tells people that the operator learns nothing and that the code is what it
claims to be. The second half of that is only true if somebody outside the
project can build the app themselves and get **the same bytes** we shipped.
Until they can, "verify it yourself" means "read the source and then trust our
binary anyway", which is not the same promise.

The roadmap asked for this to be scoped as a spike first, on the grounds that
*"Dart AOT snapshot determinism and AGP build timestamps are not a given, and
the answer may be 'reproducible with a pinned toolchain image', which is worth
knowing before it is promised."* This document is that spike, measured rather
than assumed.

**The answer is better than the question expected: with one build-config
change, two independent release builds are byte-for-byte identical, signature
included.** No timestamp stripping, no `SOURCE_DATE_EPOCH`, no post-processing.

---

## What was measured

Release APK, `flutter build apk --release`, built twice — the second after a
full `flutter clean`, at a different wall-clock time.

### Before the change

| | |
|---|---|
| APK size | 80 484 043 bytes, identical both times |
| zip entries | 440, same names, **same order** |
| entry timestamps | identical |
| entry CRCs | identical |
| entry contents | identical — all 440 |
| **differing bytes** | **8 603, in 32 runs** |
| where | every one inside the APK signing block |

So the app itself — every DEX byte, the Dart AOT snapshots for all three
ABIs, every asset and resource — was already deterministic. Nothing in the
Flutter or Dart toolchain embedded a timestamp, a path or a build counter.

Inside the signing block, pair by pair:

| pair | bytes | identical? |
|---|---|---|
| v2 APK Signature Scheme | 1 394 | **yes** |
| padding | 2 195 | **yes** |
| AGP dependency metadata (`0x504b4453`) | 8 643 | **no — 8 603 bytes differ** |

The signature itself is deterministic (RSA‑2048, `SHA256withRSA`, PKCS#1 v1.5
— no randomness). The only nondeterministic thing in the entire artefact is a
blob the Android Gradle Plugin injects on its own initiative.

### The blob

AGP writes a "dependency metadata" record into the signing block: a
description of the app's dependency tree, **encrypted to a Google public key**,
with fresh randomness each build. It exists so Play can report known-vulnerable
libraries.

It is disabled in `android/app/build.gradle.kts`:

```kotlin
dependenciesInfo {
    includeInApk = false
    includeInBundle = false
}
```

Two reasons, and the second is the one that matters more here:

1. It is the *only* thing standing between this project and a reproducible
   build. Everything else was already deterministic.
2. **A messenger whose pitch is that no third party learns anything should not
   ship an encrypted phone-home blob to a third party.** What it contains is
   beside the point; nobody outside Google can read it to check, and an
   unreadable payload inside a binary we ask people to verify is exactly the
   kind of thing this project exists to not have. Play still receives the
   dependency information from the upload itself if it wants it.

### After the change

```
c.apk: 80,475,851 bytes  sha256 27b9109f1142b5dfa0376289ac7cade10eec00aac84a6f1c720f08157f3d9fc1
d.apk: 80,475,851 bytes  sha256 27b9109f1142b5dfa0376289ac7cade10eec00aac84a6f1c720f08157f3d9fc1

IDENTICAL — byte for byte, signature included.
```

Second build after `flutter clean`, minutes later. Identical.

---

## How to verify a build

```
# <path> is the ABSOLUTE directory the release was built in. Each release's
# SHA256SUMS.txt states it, read out of the APK itself; on GitHub's runners it
# is /home/runner/work/z-messanger/z. Use a container or VM where that path
# is free.
git clone https://github.com/FluffyHorizon1/z-messanger <path>
cd <path>/app
flutter build apk --release
python3 ../tool/verify_reproducible.py \
    <ours>.apk build/app/outputs/flutter-apk/app-release.apk
```

**Build at the same absolute path.** That is not decoration: `libapp.so` and
`libdartjni.so` embed the absolute build directory, so a build anywhere else
reproduces every entry in the APK except those two. This document used to say
the *name* of the directory was all that mattered and the parent was
irrelevant; that was an inference, it was wrong, and the measurement that
showed it is under
[The parent directory matters after all](#the-parent-directory-matters-after-all-2026-09-10).
Debian pins build paths in `.buildinfo` for the same reason.

### The one-line check

Comparing against a *released* APK is not the same job, because the release is
signed with a key you do not have and never will. The SHA-256 in
`SHA256SUMS.txt` therefore covers a signature you cannot reproduce — it is the
one number on the release page that an outside rebuild can never match.

So each release also publishes a **content digest**: a hash over every zip
entry — name, compression method, CRC, size and bytes — and nothing else. The APK
signing block is not an entry, so signing does not move it, and an unsigned
local rebuild of the same commit produces the same value.

```
python3 tool/verify_reproducible.py --content-digest \
    build/app/outputs/flutter-apk/app-release.apk
```

Compare that one line with the `# Content digest` comment at the foot of the
release's `SHA256SUMS.txt`. If they match, your build produced the same
archive we shipped, entry for entry. If they do not, run the two-file
comparison above against the downloaded APK and the tool will say which
entries moved.

That the digest survives signing is not asserted — it is tested.
`tool/test_verify_reproducible.py` builds a zip, inserts a genuine APK signing
block the way `apksigner` does (between the last entry and the central
directory, offsets rewritten), and checks the digest does not move; it also
checks the digest *does* move for a changed entry, a reordered archive, a
different compression method, a renamed entry whose name/content boundary
has been slid by one byte, and two entries folded into one.

### Reading a difference

Exit status 0 means identical. On a difference the tool prints **where**:
which zip entries differ and why (timestamp, CRC, content), whether anything
outside the signing block moved, and which signing-block pair is responsible.
That detail is the point — a verifier told only "different" has learned
nothing about whether the difference matters, and the usual next step is to
stop checking.

### The toolchain has to match

Reproducibility is a property of *source plus toolchain*, and a different
compiler is entitled to emit different bytes. The versions these results were
measured with:

| | |
|---|---|
| Flutter | 3.44.7 (stable), framework `84fc5cbb22` |
| Engine | `69c8c61792` / `7076f47b1d1a3a0edfd8837b17dc15be6abab661` |
| Dart | 3.12.2 |
| Gradle | 9.1.0 |
| JDK | OpenJDK 21 |
| Android compileSdk | 36 |
| Android build-tools | 35.0.0 |

14.2 should pin these in a container image and build from it, so a verifier
does not have to reconstruct them by hand.

### Memory

`android/gradle.properties` previously asked for `-Xmx8G`, which is more than
the machine it was measured on has in total, and the Gradle daemon was
OOM‑killed mid-build:

```
Memory cgroup out of memory: Killed process (java) total-vm:11965284kB, anon-rss:4950852kB
```

It is now `-Xmx3g` / `MaxMetaspaceSize=1g`, which completes a full release
build on an 8 GB machine. A build that only succeeds on a large developer
workstation is not one an outside verifier — or a stock CI runner, which is
typically 7 GB — can run, and a verification nobody can perform verifies
nothing.

---

## What the first cross-machine run found (2026-09-09)

The section above was written from a same-machine, same-path measurement, and
it said so. CI ran the cross-machine version for the first time on 2026-09-09,
and it **failed**. That result is a finding, not a broken job, and it is
recorded here in full because a reproducible-builds document that quietly
drops its first negative result is worth nothing.

```
repro-a/app-release.apk: 80,475,855 bytes  sha256 f267f10f5443e518…
repro-b/app-release.apk: 80,475,855 bytes  sha256 53d896784809a2c0…

404078 differing run(s), 6,438,215 bytes in total.
Differences reach OUTSIDE the signing block — the app content is not reproducible.

  differs: lib/arm64-v8a/libapp.so       (crc ef99c70b vs 8cd97edf, content)
  differs: lib/arm64-v8a/libdartjni.so   (crc 8304bf4f vs cb459136, content)
  differs: lib/armeabi-v7a/libapp.so     (crc bdc72381 vs a1db562d, content)
  differs: lib/armeabi-v7a/libdartjni.so (crc 83504d20 vs ff070e05, content)
  differs: lib/x86_64/libapp.so          (crc be55413f vs 9fdd2017, content)
  differs: lib/x86_64/libdartjni.so      (crc ea3009e2 vs 20e87b76, content)
```

Read it carefully, because it is more specific than "the build is not
reproducible":

* **Six entries differ; every other entry is identical.** The dex, the
  resources, the manifest, the assets and the other four native libraries all
  matched. Whatever the cause is, it is confined to the two libraries that are
  compiled during the build.
* **The APKs are exactly the same size** — 80,475,855 bytes both. That matters,
  and it is the reason the obvious explanation is not yet the answer.

### What is established, and what is still a guess

*This section is kept as it was written, because the guesses in it were wrong
in a way worth being able to look up. The answer is in the next section.*

Established, by inspecting a local build:

* `libapp.so` **does** embed its absolute build directory. The Dart AOT
  snapshot carries the source URI
  `file://<checkout>/app/.dart_tool/flutter_build/dart_plugin_registrant.dart`,
  and it is the only absolute build path in the file. So this toolchain does
  not give path-independence for free, whatever else is true.

Not established, and this is the important part:

* **The job that failed cannot say what caused it**, because it varied two
  things at once — the runner *and* the checkout directory name (`z` versus
  `a-deliberately-much-longer-checkout-directory`). That is a badly designed
  experiment, and it was mine.
* ~~The identical byte *count* argues against the path being the whole story: a
  forty-character difference in an embedded string should change the size of
  `libapp.so`, and did not change the size of anything.~~ **Wrong — see below.**
* ~~`libdartjni.so` differing is unexplained either way.~~ **Also wrong.**

### The experiment, redesigned

`.github/workflows/build.yml` builds three times instead of two:

| slot | runner | checkout path |
|---|---|---|
| a | fresh | `z` |
| b | fresh | `z` |
| c | fresh | `a-deliberately-much-longer-checkout-directory` |

**a vs b** varies only the machine. **a vs c** varies only the path. Each build
also publishes a fingerprint — a SHA-256 and the ELF build id of every `.so`,
plus the absolute paths found inside `libapp.so`.

## The answer: the path, and only the path (2026-09-09)

The three-way run settled it in one pass.

**a vs b — two different runner VMs, same checkout path — fingerprinted
identically.** Every one of the twenty-four native libraries, every SHA-256,
every ELF build id. Nothing about the machine matters.

**a vs c — same runner image, different checkout path — differed in exactly
six**, and they are the six that are *compiled during the build*:

```
arm64-v8a/libapp.so        arm64-v8a/libdartjni.so
armeabi-v7a/libapp.so      armeabi-v7a/libdartjni.so
x86_64/libapp.so           x86_64/libdartjni.so
```

Every prebuilt library — `libflutter.so`, `libsqlite3.so`, `libbarhopper_v3.so`,
`libdatastore_shared_counter.so`, `libimage_processing_util_jni.so`,
`libsurface_util_jni.so` — was byte-identical in all three.

The build ids are the tell. `arm64-v8a/libapp.so` went from
`b718850932687d08f90d3cfa231b6c0f` to `b7188509f45fb27af90d3cfa225664c1`:
the same first eight bytes and the same middle, differing in between. That is
one input changing, not a different compilation.

### Why the earlier reasoning was wrong

Two guesses above were wrong, and both were wrong for the same reason — an
assumption asserted without being checked.

**"The identical file size argues against the path."** It does not. Native
libraries in a release APK are stored *uncompressed and page-aligned*, so the
zip entry is padded out to an alignment boundary. A forty-character string
difference disappears into that padding, and the total is unchanged. The size
being equal was evidence of nothing, and treating it as evidence *against* the
obvious explanation sent the analysis the wrong way for a day.

**"`libdartjni.so` carries no embedded build path, so it is unexplained."**
The `strings` search behind that only looked for `/home`, `/Users`, `/b` and
`/buildbot` prefixes in one local artefact. It is compiled during the build
like `libapp.so`, and it tracks the path exactly as `libapp.so` does — a and b
identical, a and c different. There was never a second phenomenon to explain.

The general lesson, and it is the same one as the two-variable experiment: an
inference offered in place of a measurement should be labelled as one. Both of
these read as findings and were guesses.

## What this means for a verifier

**Cross-machine reproducibility holds.** Two people on two machines, checking
out to the same relative path, get the same bytes. That is the property this
phase was after, and it is now measured rather than hoped for.

**The build path is part of the recipe.** This is not unusual — Debian records
`Build-Path` in `.buildinfo` for exactly this reason, and a great many packages
are reproducible only at a fixed path. Z's recipe is therefore:

> ~~Check out the repository into a directory named **`z`**, and build from
> `z/app`. The parent directory does not matter; the name does, because it is
> the last component of the path that reaches the Dart AOT snapshot.~~
>
> **Corrected 2026-09-10:** build at the same **absolute** path as the
> release, which each release's `SHA256SUMS.txt` states. The struck-through
> version was never measured — every CI slot that agreed shared the same
> parent — and when it was measured it failed. See
> [The parent directory matters after all](#the-parent-directory-matters-after-all-2026-09-10).

~~A verifier who builds in `~/src/z` and one who builds in `/tmp/z` agree.~~
They do not. One who builds at any path but the release's will differ in
`libapp.so` and `libdartjni.so` and match in everything else, which the
comparison tool will tell them precisely.

**The leak is bounded, and the bound is checked.** CI asserts that a path
change moves `libapp.so` and `libdartjni.so` and *nothing else*; a seventh
library appearing there fails the build, because it would mean this section is
understating the problem.

### Closing it properly

Pinning the path is a documented workaround, not a fix. The fix is for the
snapshot not to carry an absolute path at all, and the offending string is a
generated file — `.dart_tool/flutter_build/dart_plugin_registrant.dart` —
referenced by URI. Making that relative is upstream work in the Flutter tool,
and worth filing there. Until then the recipe above is the honest position:
reproducible, at a stated path, verifiably so.

One shortcut was tried and does not work, recorded so nobody tries it again:
`flutter build apk --split-debug-info=…` moves symbols out of the snapshot,
and the hope was that the source URI went with them. Measured 2026-09-10,
same commit, `/tmp/p3/zclone`: `libapp.so` still carries
`file:///tmp/p3/zclone/app/.dart_tool/flutter_build/dart_plugin_registrant.dart`.
The URI is not debug information; it is the registrant's identity in the
snapshot.

### What this costs a verifier today

A container or VM, because the path is absolute: build at the path the
release states and the six libraries match too. A verifier who builds anywhere
else gets everything matching except `libapp.so` and `libdartjni.so`, and
`tool/verify_reproducible.py` names them, so the outcome is a known deviation
rather than a mystery. (This paragraph used to say "almost nothing" and
"a directory called `z`" — the next section is why that was wrong.)

### The parent directory matters after all (2026-09-10)

The section above — "the path, and only the path" — was right that the path
is the whole story and wrong about which part of the path. It said the parent
directory was irrelevant and only the final component reached the snapshot.
Nothing had measured that: slots a, b and d all build at
`/home/runner/work/z-messanger/z`, so every agreement CI ever saw was between
builds at the *same absolute path*, and slot c differed in the final
component and in nothing else. "The parent does not matter" was inferred from
an experiment that never varied it. That is the third time in this file an
inference has been written down as a finding, and it is the same mistake each
time.

The measurement, on a development machine, same commit, one ABI:

```
/tmp/p1/zclone/app   flutter build apk --release --target-platform android-arm64
/tmp/p2/zclone/app   the same

content digest   eedf6481b1147841…   8b9454371f37934d…   DIFFERENT
differs          lib/arm64-v8a/libapp.so
                 lib/{arm64-v8a,armeabi-v7a,x86_64}/libdartjni.so
embedded URI     file:///tmp/p1/zclone/app/.dart_tool/flutter_build/dart_plugin_registrant.dart
                 file:///tmp/p2/zclone/app/.dart_tool/flutter_build/dart_plugin_registrant.dart
```

Same leaf name, different parent, different bytes. The snapshot embeds the
full absolute URI, exactly as the earlier inspection had already shown and the
prose then reasoned its way past.

Two consequences, both acted on in the same change:

* **The recipe in every release from v2.3.8 to v2.4.7 could not be followed
  to a match.** It said "a directory named `z`"; the release APK is built at
  `/home/runner/work/z-messanger/z-messanger` (the `android` job checks out
  to the default path, not `z` — since corrected: it builds at `…/z`, the
  slots' path), and even a verifier who used `z` would have needed the
  runner's parent directories too. The release job now reads the embedded
  path out of `libapp.so` and prints *that* in `SHA256SUMS.txt`, so the
  recipe cannot again say one path while the bytes carry another.
* **The content digest changed form** at the same time: entries are now
  length-prefixed on their content as well as their name, so the encoding is
  injective by construction rather than by a CRC argument. Digests published
  before this are of the earlier form and, for the path reason above, were not
  matchable anyway. The tool at each tag computes that tag's digest.

What is unchanged: cross-machine reproducibility at one path holds, the leak
is bounded to two libraries and CI checks the bound, and the proper fix is
still upstream — a relative URI in the generated registrant.

### The last argued claim, now measured on every tag

"Signing does not disturb the content digest, so an unsigned rebuild matches
it" was tested against a synthetic signing block and never against the
release key. With the `android` job building at the slots' path, the release
job now computes the content digest of the release-signed APK and of slot
a's debug-signed APK — same commit, same absolute path, different key — and
writes the answer into `SHA256SUMS.txt`: *"Reproduced independently before
publishing: yes"* or *"NO — … see the run log"*, with the per-entry
difference in the log. Reported rather than enforced until it has been seen
to agree on a real tag; a release note that says "reproducible" and was never
checked is the overclaim this document exists to prevent.

## What has NOT been established

Stated plainly, because a reproducibility claim with unexamined edges is worse
than none — it invites people to stop looking.

* ~~Both builds were on the same machine, in the same directory.~~
  **Settled.** Two runner VMs at the same path fingerprint identically; a
  different path moves exactly two libraries. The classic failure this bullet
  predicted — "an absolute build path embedded in a binary" — is precisely
  what was found, which is some consolation for having guessed the wrong cause
  twice in between.
* **Locale and timezone are now tested, but the result is not in yet.** All
  three runners in the 2026-09-09 run shared `en_US.UTF-8` and UTC, so a leak
  there would have been invisible. A fourth slot builds at the same path under
  `Australia/Eucla` (UTC+08:45 — a quarter-hour offset, so a leaked timestamp
  is off by an amount no rounding hides) and `fr_FR.UTF-8`, and CI fails if its
  fingerprint differs from slot a's. **Until that job has run, this line
  records an expectation, not a measurement.**
* **The wall-clock time did vary between the two builds and changed nothing**,
  so no timestamp is embedded and `SOURCE_DATE_EPOCH` is not needed. Locale,
  timezone, CPU model, kernel and filesystem ordering were all constant and are
  untested.
* **Only the APK was measured.** The AAB that actually goes to Play is a
  different packaging path, and Play App Signing re-signs it with a key we do
  not hold — so for the AAB, verification necessarily compares the artefact
  *before* signing. The desktop bundles are unmeasured.
* **`flutter clean` was used between builds, not a fresh checkout.** Untracked
  state in the working tree could in principle influence a build.
* **Cross-machine reproducibility is not merely unestablished — it has been
  measured and it failed.** See the section above; this list was written before
  that run and the entry that used to sit here ("path-independence has not been
  checked") understated it.
* Only the debug signing key was exercised, because the release keystore is not
  in this environment. The signature was identical across builds with that key;
  a release key with a different algorithm (ECDSA, or RSASSA‑PSS) would sign
  nondeterministically and verification would then have to exclude the signing
  block — which `tool/verify_reproducible.py` already reports on separately for
  exactly this reason.

## Exit criterion

Phase 14's exit asks for *"a bit-identical rebuild reproduced by someone
outside the project"*. The **property** is established — two machines, one
absolute path, identical bytes — and the recipe now states that condition
correctly, which until 2026-09-10 it did not. What is still missing is the
**someone**: nobody outside the project has run it, and until the correction
nobody could have succeeded. That is not something the project can do for
itself, and it should not be quietly counted as done.

Two of the three things that were next are now done: each release publishes a
**content digest** an outside rebuild can actually match (the signed SHA-256
never could), and a fourth CI slot varies locale and timezone. What remains is
to file the embedded-path issue upstream in the Flutter tool — pinning the path
is a workaround, and the fix belongs where the absolute URI is written.

And then the part no amount of CI can supply: somebody who is not us, running
the four commands above, and saying whether the number matched.
