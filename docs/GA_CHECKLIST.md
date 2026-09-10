# GA checklist (15.5)

The conditions for calling Z 1.0, each with its real status and — where it is
not met — what specifically is missing and who can supply it.

A checklist is only worth having if it is true on the day someone decides to
ship, so the mechanical parts of this one are verified by
`tool/check_ga.py`, which runs in CI. It cannot check whether an audit
happened; it can check that this file has not drifted from the repository
around it.

**Status: NOT READY.** Three criteria are unmet, one of them by design
decision rather than by unfinished work.

---

## The criteria

| # | Criterion | Status |
|---|---|---|
| G1 | External cryptographic audit, zero open Critical/High | ❌ **not commissioned** |
| G2 | Reproducible builds, verified by someone outside the project | ⚠️ **property holds, nobody outside has checked** |
| G3 | Key transparency live | ❌ **not built — and see below** |
| G4 | Encrypted backup and restore | ✅ |
| G5 | Multi-device | ✅ |
| G6 | Published threat model | ✅ |
| G7 | Platform completion (Android, iOS, Windows, macOS, Linux) | ❌ **iOS does not exist** |
| G8 | Accessibility | ✅ for the checks that exist; see the caveat |
| G9 | Localization | ❌ **2 of 14 screens** |

---

### G1 — External cryptographic audit ❌

The *package* is ready: `AUDIT_SCOPE.md` states thirty claims with where each
is specified and tested, `tool/audit_verify.sh` reproduces every one in a
single command, and §8.1 defines severity anchored to those claims rather than
to a generic scale.

**What is missing is the engagement**, which is Finnian's to commission. Phase
15's entry condition is zero open Critical/High, and that gate is the reason
this phase is gated at all.

### G2 — Reproducible builds ⚠️

Measured, and the answer is good: two CI runners building the same commit at
the same checkout path produce byte-identical native libraries, build ids
included. The build path is part of the recipe — clone into a directory named
`z` — the way Debian records `Build-Path`, and CI asserts that a path change
moves exactly two libraries and no others.

Each release publishes a **content digest** an outside rebuild can match,
since the signed SHA-256 never could.

**What is missing is somebody who is not us.** This is the one criterion the
project structurally cannot self-certify, and marking it ✅ on our own
authority would be the exact overclaim these documents exist to prevent.

### G3 — Key transparency ❌ — and this needs a decision, not work

Written into the GA criteria at the start of phase 8; **not built**, and
deliberately so. `adr/0001-key-transparency.md` defers the public log to phase
11 and gates it on *"public launch with an operator committed to durable
infrastructure"* — a Merkle log, an HSM signing key, mirrors and an
independent witness, all of which are an operating commitment rather than a
sprint.

So the criteria as written contain a circular dependency: **GA requires KT,
and KT's trigger is a public launch.** One of the two has to give, and it is
not an engineering call:

* ship 1.0 without KT, with gossip-based device-list transparency (which is
  built, and which `adr/0001` argues is the right first step) — and say so
  plainly in the release; or
* commit to running the log infrastructure first, and accept that 1.0 waits
  on it.

Until that is decided this row cannot be closed by writing code, and pretending
otherwise would let the checklist quietly drop a criterion that was put there
for a reason.

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

`THREAT_MODEL.md` including a sixteen-row residual-risk register, `DATA_MAP.md`
for the inventory beneath it, `WHITEPAPER.md` for the argument, and
`WHAT_Z_CANNOT_DO.md` for the version a user can act on. Claims C28, C29.

### G7 — Platform completion ❌

Android, Windows, macOS and Linux build and ship. **iOS does not exist** —
there is no `app/ios/` directory. It is a parallel track with its own agent
and its own file ownership, and 1.0 "on iOS" is blocked on that track
delivering.

Play submission is separately gated on Finnian: the 16 KB page-alignment
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

### G9 — Localization ❌

The foundation is in — `flutter_localizations`, `gen-l10n`, an ARB with a
description on every string, and `tool/check_l10n.py` holding migrated screens
to zero hardcoded literals. **Two of fourteen screens are migrated; ~461
strings remain**, and no locale but English exists.

Z publishes release notes in six locales. Shipping an app in one is a defensible
1.0 decision, but it should be a decision rather than an oversight, and the
security wording in particular wants a translator who reads the language rather
than a machine.

---

## What would change this page

Three things are Finnian's, not engineering's: commission the audit (G1),
settle the KT-versus-launch circularity (G3), and decide whether 1.0 ships
English-only (G9). One is another track's: iOS (G7). One is nobody's to give
us — an outside rebuild (G2).

The rest is work, and it is counted rather than estimated: `check_l10n.py`
prints exactly how many strings are left.
