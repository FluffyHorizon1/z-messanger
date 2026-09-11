# GA checklist (15.5)

The conditions for calling Z 1.0, each with its real status and — where it is
not met — what specifically is missing and who can supply it.

A checklist is only worth having if it is true on the day someone decides to
ship, so the mechanical parts of this one are verified by
`tool/check_ga.py`, which runs in CI. It cannot check whether an audit
happened; it can check that this file has not drifted from the repository
around it.

**Status: NOT READY.** Three criteria are unmet — G1 waits on an engagement,
G3 on the log going live, G7 on iOS — and G2 holds but has been checked by
nobody outside the project.

---

## The criteria

| # | Criterion | Status |
|---|---|---|
| G1 | External cryptographic audit, zero open Critical/High | ❌ **not commissioned** |
| G2 | Reproducible builds, verified by someone outside the project | ⚠️ **property holds, nobody outside has checked** |
| G3 | Key transparency live | ❌ **built end to end; not deployed** |
| G4 | Encrypted backup and restore | ✅ |
| G5 | Multi-device | ✅ |
| G6 | Published threat model | ✅ |
| G7 | Platform completion (Android, iOS, Windows, macOS, Linux) | ❌ **iOS does not exist** |
| G8 | Accessibility | ✅ for the checks that exist; see the caveat |
| G9 | Localization | ✅ English and Spanish; see the caveat |

---

### G1 — External cryptographic audit ❌

The *package* is ready: `AUDIT_SCOPE.md` states thirty claims with where each
is specified and tested, `tool/audit_verify.sh` reproduces every one in a
single command, and §8.1 defines severity anchored to those claims rather than
to a generic scale.

**What is missing is the engagement**, which is the project's to commission. Phase
15's entry condition is zero open Critical/High, and that gate is the reason
this phase is gated at all.

### G2 — Reproducible builds ⚠️

Measured, and the answer is good: two CI runners building the same commit at
the same checkout path produce byte-identical native libraries, build ids
included. The build path is part of the recipe — the same **absolute** path
as the release, which each release's `SHA256SUMS.txt` states — the way Debian
records `Build-Path`, and CI asserts that a path change moves exactly two
libraries and no others.

Each release publishes a **content digest** an outside rebuild can match,
since the signed SHA-256 never could. **Until 2026-09-10 the recipe beside it
was wrong** — it said "a directory named `z`", the parent was claimed not to
matter, and that claim had never been measured. Measured, it fails: the
snapshot embeds the absolute path. No digest published from v2.3.8 to v2.4.7
could have been matched by following its own instructions. The release job now
reads the build path out of the APK and prints that. See
`REPRODUCIBLE_BUILDS.md`, "The parent directory matters after all".

**What is missing is somebody who is not us.** This is the one criterion the
project structurally cannot self-certify, and marking it ✅ on our own
authority would be the exact overclaim these documents exist to prevent.

### G3 — Key transparency ❌ — built end to end, not yet live

Written into the GA criteria at the start of phase 8 and deferred by
`adr/0001` until "a public launch with an operator committed to durable
infrastructure" — which made the criteria circular: GA required the log,
and the log's trigger was GA. **Resolved by decision in `adr/0006`**: the
log is run, and 1.0 waits on it.

What exists: the service (`kt/` — an RFC 9162 log plus a sparse map under
one signed head, publish authenticated by the account key, a mirror that
refuses a fork), PROTOCOL.md §19 with its vectors and a second
implementation, the reader in the protocol package, and the client in the
app — every state in `adr/0006`'s table driven end to end against the real
service (`key_transparency_test.dart`): confirmed, unconfirmed with the hold
past the grace period, installed from the log, conflict with the hold and
"send anyway" and the owner's alert, a fork refused, unreachable degraded.
Phase 11's three exit conditions each have a test.

What does not exist: the deployment. **This row reads ✅ when** the service
answers over TLS at `kt.zmessengers.com`; the shipped client pins its public
key (`defaultKtLogPub` in `app/lib/core/key_transparency.dart`, set at build
time — `tool/check_ga.py` refuses the tick while it is empty) with a witness
configured; a mirror run by someone other than the operator has verified a
head; and the operator's own account appears in it. `SELF_HOSTING.md`
"Running the transparency log" is the runbook, one step per condition.
Four sentences flip with it: the "not yet live" lines in `WHITEPAPER.md`
§9, `WHAT_Z_CANNOT_DO.md`, `DATA_MAP.md` "Not yet built", and R7's status
in `THREAT_MODEL.md`.

### G4 — Encrypted backup and restore ✅

`.zbk` archives, 120-bit recovery code through Argon2id, restore onto a wiped
device without ever restoring session state. Covered by `backup_test.dart`,
`restore_test.dart`, `archive_test.dart`, and a vector replayed by the Node
clean-room verifier. Claim C13.

### G5 — Multi-device ✅

Each device has its own routing id and its own ratchets; the safety number is
anchored to the account key and does not move when a device is added; a
contact offline for the whole enrollment still learns the new device. Claims
C14, C19, C21, C22.

### G6 — Published threat model ✅

`THREAT_MODEL.md` including a twenty-one-row residual-risk register, `DATA_MAP.md`
for the inventory beneath it, `WHITEPAPER.md` for the argument, and
`WHAT_Z_CANNOT_DO.md` for the version a user can act on. Claims C28, C29.

### G7 — Platform completion ❌

Android, Windows, macOS and Linux build and ship. **iOS does not exist** —
there is no `app/ios/` directory. It is separate work with its own file
ownership (`app/ios/**`, `app/macos/**`, push and app‑lock native code),
and 1.0 "on iOS" is blocked on it.

Play submission is separately gated on the maintainer: the 16 KB page-alignment
blocker is cleared, and the re-upload has not happened.

### G8 — Accessibility ✅, with a caveat worth stating

Flutter's own guidelines — tap target, labelled tap target, text contrast —
plus 2× dynamic type and an RTL pass, across both palettes, on the three
pre-account screens. Every `IconButton` in the app has a tooltip and every
`Image` is labelled or explicitly marked decorative, enforced by
`tool/check_a11y.py`.

The caveat: the guideline tests cover three of thirteen screens, because the
rest need a real vault, relay and identity to pump. The other ten are covered
breadth-first by source inspection, which catches a narrower class of fault.
**No screen reader has been run against this app by a person.** That is worth
doing before 1.0 and is not something a test replaces.

### G9 — Localization ✅, with a caveat worth stating

The foundation is in — `flutter_localizations`, `gen-l10n`, an ARB with a
description on every string, and `tool/check_l10n.py` holding the migrated
screens — **15 of 15 screens** — to zero hardcoded literals and, now,
holding every other locale to exactly the English key set with the same
placeholders and plural cases.
The service stores its sixteen kinds of system message as a kind and its
parameters (`core/system_messages.dart`), rendered through the ARB when
shown, so they read in the user's language too.

**The app ships in two languages: English and Spanish** (`app_es.arb`,
408 strings, every claim carried across — `locale_es_test.dart` checks the
plurals, the stored system messages and that no string was copied through
untranslated). Spanish was chosen because it is the second language Z's
release notes have been published in since 2.0.

The caveat: **the Spanish was translated in‑project and has not been read
by a native speaker.** The security wording — the safety‑number notices,
"there is no way to recover it", the transparency states — is the part
where a careless translation misleads someone, and it was written with
that in mind, but a review by someone who lives in the language is the
step that remains, the way a screen reader run by a person remains for G8.
It is a review, not a blocker: the criterion is that the app is localised,
and it is.

---

## What would change this page

Two things are the maintainer's, not engineering's: commission the audit
(G1) and deploy the log (G3 — the client is in). One is separate work: iOS
(G7). One is nobody's to give us — an outside rebuild (G2). Two want a
person rather than code and are not blockers: a native reader for the
Spanish (G9) and a screen reader run by hand (G8).

`check_l10n.py` keeps the localisation honest: zero literals in any screen,
and every locale complete.
