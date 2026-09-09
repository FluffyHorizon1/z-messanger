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
flutter build apk --release
python3 tool/verify_reproducible.py <ours>.apk build/app/outputs/flutter-apk/app-release.apk
```

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

## What has NOT been established

Stated plainly, because a reproducibility claim with unexamined edges is worse
than none — it invites people to stop looking.

* **Both builds were on the same machine, in the same directory, in the same
  container.** Genuine reproducibility means a *different* machine reproduces
  it. The classic failure is an absolute build path embedded in a binary, and
  that is specifically untested here.
  * A build from a different path, timezone and locale was attempted and
    abandoned: a cold build in a fresh directory exhausted the container
    (2 cores, 8 GB) and had not finished Kotlin compilation after 35 minutes.
    That is a limit of this container, not a result.
  * **This is the first thing 14.2 must check**, and it is cheap there: the
    same commit built in two differently-named CI workspaces.
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
* Only the debug signing key was exercised, because the release keystore is not
  in this environment. The signature was identical across builds with that key;
  a release key with a different algorithm (ECDSA, or RSASSA‑PSS) would sign
  nondeterministically and verification would then have to exclude the signing
  block — which `tool/verify_reproducible.py` already reports on separately for
  exactly this reason.

## Exit criterion

Phase 14's exit asks for *"a bit-identical rebuild reproduced by someone
outside the project"*. What exists now is the property and the tool; what is
missing is the someone. That needs 14.2's pinned build image and a published
hash per release, and it needs the path-independence check above to pass on a
machine that can finish the build.
