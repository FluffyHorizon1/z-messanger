# ADR 0017 — Mixed-version device lists: hold the fingerprint and ML-DSA at v1 while v1 signing continues

**Status:** **Accepted** (2026‑09‑19) — stage 1 built (3.7.8); stage 2 built
and switched off (2026‑09‑30, "Stage 2" below); its follow‑ups, one closed
and two open, at the end (2026‑10‑02). Amends ADR 0010.
**Decides:** what a current client reports as a device list's fingerprint, and
what input its ML‑DSA covers, while clients that predate ADR 0010 are still in
the field.

## Context

ADR 0010 (shipped 3.6.2) made the device‑list signature and its fingerprint
cover each device's X25519 ratchet key, not only its Ed25519 key and the
version — the **v2** input. To keep pre‑0010 contacts verifying, the migration
(`_migrateDeviceListToV2`) **dual‑signs**: a v1 `sig` over the old input and a
v2 `sig2` over the new one, and bumps the list version.

That left a field defect — a P0, reproduced by execution 2026‑09‑19 and present
from 3.6.1 through 3.7.5. A current client, seeing `sig2`, reported the **v2**
fingerprint and signed its account ML‑DSA over the **v2** input. A client still
on 3.5.7 **accepts** that list — the v1 `sig` is what admits it — and then
computes the **v1** fingerprint and verifies the ML‑DSA over the **v1** input,
because it has never heard of v2. Same list, same version, two fingerprints:

```
updated client fingerprint:  147d…   (v2)
3.5.7  client fingerprint:   bf7e…   (v1)   → FINGERPRINTS AGREE: False
```

A fingerprint disagreement at the same version is the one thing each side is
built to treat as an attack. The 3.5.7 contact shows *"their devices disagree
about their device list… one of them may not be theirs"*; the updated one, after
its grace, shows *"a device list your device never issued… **reset your identity
now**"* — it tells the user to destroy their account over a version skew. The
ML‑DSA half fails the same way, more quietly: assurance stays classical and a
false `pqSignatureMissing` is raised. It reaches nearly every account, because
`ktOwn()` gives even a single‑device account a baseline list to migrate.

The v1 signing input (`z‑devlist‑v1:`) is frozen and byte‑identical in 3.5.7 and
HEAD, so a current client can compute exactly what an old one does; the fix uses
that.

## Decision

**A device list reports the v1 fingerprint, and its ML‑DSA covers the v1 input,
for as long as a v1 signature is being produced for it — which today is always,
because every list is dual‑signed.** `SignedDeviceList.fingerprint()`
(`multidevice.dart`) and `_devlistSigningInputFor` (`identity_v3.dart`) both drop
their `sig2 != null ? v2 : v1` switch and return v1. Both sides of every mixed
pair then compute the same v1 fingerprint over the same bytes, and a 3.5.7 client
verifies the ML‑DSA it is handed. No wire format changes; no version handling is
added; the change is three lines of policy plus the tests and vectors that
encoded the old behaviour.

The migration is therefore **two‑staged**:

- **Stage 1 (this release).** Dual‑sign (`sig` + `sig2`) but fingerprint and sign
  the ML‑DSA at **v1**. The v2 signature is still produced and still enforced —
  see below — it just does not drive the fingerprint or the ML‑DSA input yet.
- **Stage 2 (a later release, once the v1 population is gone).** Sign **v2‑only**
  (no v1 `sig`), at which point `fingerprint()` and `_devlistSigningInputFor`
  return v2 for those v2‑only lists and the ratchet‑key commitment takes full
  effect. The downgrade floor already built for this (`cdev_sigfloor_`,
  `chat_service.dart`) is what makes refusing a re‑introduced v1 list safe then.
  This ADR does not build stage 2.

## The cost, stated plainly

Holding the **fingerprint** at v1 is close to free: the classical **v2**
signature (`sig2`) must still verify in `SignedDeviceList.verify()` or the list
is refused (`multidevice.dart`, `if (!okV2) return false;`), so a classically
forged ratchet‑key substitution is still caught at admission — the fingerprint is
only the secondary, gossip‑level check.

Holding the **ML‑DSA** at v1 has a real, bounded cost, and it was a deliberate
choice (Finnian, 2026‑09‑19, over dual‑signing the ML‑DSA): against an adversary
who has broken Ed25519 but not ML‑DSA — the §18 premise — the post‑quantum layer
no longer commits to the ratchet keys *during the transition*. This is **not a
regression below the deployed floor**: 3.5.7, the population we are staying
compatible with, never had the v2 PQ commitment at all, and today's v2 ML‑DSA
"works" only between updated clients while false‑alarming at every 3.5.7 contact.
Stage 1 trades a commitment that is broken‑and‑alarming in the mixed field for
one that is uniform and correct, and stage 2 restores the v2 commitment once the
field is uniform. The trade is temporary and reverses cleanly.

## Rejected

- **Don't bump the version in the migration (the doc's first "option 1").**
  Does not work and must not be attempted: re‑signing in place at version N still
  gives the updated client a `sig2`, so it computes v2 at N while the old client
  computes v1 at N. The mismatch moves from N+1 to N; it does not go away. Any fix
  that leaves the fingerprint flipping while v1 clients exist has this shape.
- **Teach old clients to read a mismatch as version skew (option 3).** A 3.5.7
  client is already deployed; it cannot be taught a format it never shipped.
- **Dual‑sign the ML‑DSA (add an `mlsig2` over the v2 input).** Would keep the v2
  PQ ratchet‑key commitment for updated clients *and* let old clients verify the
  v1 `mlsig` — backward‑compatible, since 3.5.7 reads only `mlsig`. Rejected for
  this hotfix: it is a signature‑format addition (~+3.3 KB per list, ML‑DSA‑65)
  and more surface than a P0 fix should carry. It remains the option if the v2 PQ
  commitment must hold through the transition; recorded here so stage 2 can weigh
  it.

## Consequences

- **Wire/relay/ratchet:** unchanged. `sig2` is still produced, still on the wire,
  still enforced in `verify()`. No new message, no version bump to the protocol.
- **Vectors regenerated.** `docs/vectors/v1/multidevice.json` (its reported
  `fingerprint` flips v2→v1; `fingerprint_v1`/`signing_input`/`signing_input_v2`
  are unchanged reference fields), `docs/vectors/v3/device_cert_v3.json` (`ml_sig`
  is now over the v1 input; notes updated), and `docs/vectors/kt/kt_log.json`
  (its embedded fingerprint tracks the multidevice vector). The clean‑room
  verifiers agree: `kt/tools/verify_vectors.py` and `kt/test/vectors.test.js`
  cross‑check the fingerprint against the **v1** signing input now.
- **The missing test is the durable fix.** `protocol/test/mixed_version_devlist_test.dart`
  builds a dual‑signed list with HEAD and asserts (1) it reports the v1
  fingerprint an old client computes, and (2) its ML‑DSA verifies over the v1
  input an old client checks. Both fail on the pre‑fix code — this is the
  reproduction — and it is honest as a single‑tree test because the v1 signing
  input is frozen and byte‑identical to 3.5.7's.
- **Stage 2 is now owed.** The v2 ratchet‑key commitment does not take effect
  until a later release signs v2‑only. That release, and the floor that guards
  it, are tracked against this ADR.

## What was verified

- **Reproduction:** the mixed‑version test fails on pre‑fix code with the exact
  fingerprint/ML‑DSA disagreement; passes after.
- **Full protocol suite** (`dart test`): green, including the updated
  `devlist_v2_test` (a dual‑signed list now keeps the v1 fingerprint; the ML‑DSA
  is held at v1 and the substitution is caught by `verify()`), `transparency_test`
  and `vectors_test`.
- **Cross‑implementation:** `kt/tools/verify_vectors.py` (Python, "344 values
  reproduced or refused") and `kt/test/vectors.test.js` (Node, 78/78) agree with
  the Dart fingerprint.
- **Full app suite:** run on this branch; the migration and the KT compare paths
  now compute v1 throughout.

## Stage 2 — built, switched off (2026‑09‑30)

The decision (Finnian, 2026‑09‑30): build stage 2 completely and ship it off.
Every client from this release on can read what stage 2 produces; none
produces it until a later release flips one constant. The text above is left
as written — it says "this ADR does not build stage 2", and on the day it was
written that was true.

**Stage 2a — every reader takes a v2‑only list (on, from this release).** A list
has one of three shapes, and only three: `{sig}` (a pre‑0010 list),
`{sig, sig2}` (stage 1, dual‑signed — both must verify, as before) or `{sig3}`
(stage 2, v2‑only). `sig3` is over the v3 input: byte for byte the v2 content —
each device's Ed25519 key, ratchet key and length‑prefixed id, in the same order
— under the context `z-devlist-v3:` instead of `z-devlist-v2:`. `verify()`
refuses any other shape before it checks a signature: no signature at all,
`sig2` alone, and `sig3` beside either of the others. A signature member that is
present is a signature: a list carrying one as `null` — or as anything but a
string — is malformed as well, and does not parse; read as absent, a `null`
member would make `{sig, sig2, "sig3": null}` dual‑signed and
`{"sig": null, sig3}` v2‑only to one reader while a reader going by the members
present refused both. Which input a list commits to is written down once, in
`SignedDeviceList.commitmentInput`, and both the fingerprint and
`_devlistSigningInputFor` take it from there:

> The fingerprint and the ML‑DSA input follow the strongest signature that is
> *alone*: v1 while a v1 signature is produced; once it is not, the input of
> the one signature the list carries.

For every list that exists today that is the stage‑1 answer, unchanged — each
carries `sig`, so each keeps the v1 fingerprint a 3.5.7 client computes and its
ML‑DSA stays checkable by one. Only a list such a client cannot read at all
commits to the v3 input, and that is where the post‑quantum commitment to the
ratchet keys returns.

**Why the sole signature has an input of its own.** A list with one signature
must not be obtainable from a list with two by taking one away. Every
dual‑signed list carries a genuine `sig2` over the v2 input. Stage 2 was first
built with `sig2` alone as the v2‑only shape, and review caught, before it was
released, what that allowed: deleting `sig` from any dual‑signed list the
account ever signed produced a list every reader verified. Deleting is within
reach of anyone who passes a list on, the log's operator included — a log value
is sealed under a key derived from the account's *public* key (§19.1), and a
contact checks an entry's value and fingerprint, never who submitted it. The
operator could serve, at the version of the account's next list, that list with
`sig` deleted under the fingerprint of the v2 input. A contact that had not yet
received the list in‑band would install it from the log: a list the account
never sent, under a fingerprint no other reader holds for that version (the
shape of the 3.7.8 P0), and — holding a list without `sig` — the floor's third
level, from which it would refuse every honest list from the account until the
account flipped. Before stage 2a the stripped list failed `verify()`, and the
most the operator got was a conflict.

So the shape is part of what is verified, and the sole signature is made over
bytes no signature made beside `sig` covers. Deleting `sig` leaves `{sig2}`,
which is refused; moving that `sig2` into `sig3` leaves a signature over the
wrong input, which is refused too; a log entry made of either is a conflict, as
before. The ML‑DSA follows: a v2‑only list's is over the v3 input, which no
ML‑DSA made for an earlier list covers — not the v1 input, and not the v2 input
that clients between ADR 0010 and ADR 0017 signed under ML‑DSA.
`HybridDeviceListSignature.verifies` checks the shape as well, because deleting
`sig` leaves the v1 input as it was: without that check the stage‑1 ML‑DSA would
still vouch for the stripped list. The context keeps the `z-devlist-vN:` form,
so the three inputs differ in one byte at the same offset and none can equal
another; "v3" counts the inputs a list is signed over, not formats of its
content.

The floor (`cdev_sigfloor_`, `_installContactDeviceList`) gains its third level.
Level 1 is ADR 0010's, applied to both signatures that cover the ratchet keys:
once a list carrying a valid `sig2` or `sig3` has been seen at version N, a
later list carrying neither is refused. Level 2: once a v2‑only list — `{sig3}`
— has been installed for an account, any list from it that carries a v1
signature — dual‑signed or v1‑only, at any version, the held one included — is
refused. Level 2 is not a second stored number: an account is at level 2 exactly
when the list held for it is `{sig3}`, because nothing at that level can replace
that list with one carrying `sig`, so the level is written in the same row as
the list and cannot drift from it — and only the account can raise it, since
only the account can sign a `sig3`. In‑band, a refusal is the existing kind —
the list is not installed, the log is told nothing, nobody is alerted — and that
is what keeps an innocent account from being accused: the gossip goes on
comparing the account's own claims with the v2‑only list still held, and they
agree. A list the log serves that the floor refuses is not silent: the log check
reports a conflict, as it does for a log entry that does not open, and that
holds sends to the account (ADR 0006's table) — as the log path did for a
refused list before stage 2. `ktInstallFromLog` now says so at the held version
too; it used to answer from the held version alone, which equals the list's
there whether the list was installed or not. Installs of one contact's list are
now serialized (their own lock), because the floor is a read‑check‑write and two
installs for one account used to be able to interleave; the older could write
last (see the commit, and `devlist_hybrid_test.dart`'s floor case).

**Stage 2b — the signer, behind one constant, off.** `devlistSignV2Only` in
`protocol/lib/src/multidevice.dart` is `false`. With it false nothing differs
from stage 1: `signDeviceList` dual‑signs, every fingerprint is v1, the
dual‑signed vectors regenerate byte for byte, and every test that existed
before passes unchanged. With it true:

- On its next start each root moves its account's list to the **next version**
  and signs it there with `sig3` alone (`_migrateDeviceListToV2Only`, modelled on
  `_migrateDeviceListToV2` and run at the same point of start‑up), then sends it
  to its own devices, its contacts and the log by the paths a new device's list
  takes. Once, by a vault flag; a linked device signs nothing.
- The bump is what the self‑monitor needs, and it is the tolerance the 0010
  migration already relied on — no new rule. The old `(version, v1 fingerprint)`
  stays what it was in the log and in `kt_own_known`; the new list lands at a
  version this device recorded as its own; nothing the log serves is a version
  this account did not issue.
- Every root moves, one that never signed past its baseline included, so a
  v2‑only list is never version 1. Version 1 is the baseline a contact computes
  for itself, over the v1 input, from the one device in the code it scanned —
  which does not carry the device id the v3 input commits to.
- Until the move has happened nothing is signed v2‑only, even with the constant
  set; and once it has, everything is, even with the constant off. The vault
  decides before the constant does: a root whose account has moved keeps signing
  `sig3` alone on any build from this release on — one that turns the constant
  back, a downgrade to this release, a post‑flip backup restored onto it — and
  only the move itself waits on the constant. Either way no version is ever
  signed both ways; a build that re‑signed the current version dual‑signed would
  give it a second fingerprint, and every contact holding the v2‑only list a
  split alarm.

The tests flip it per service — `ChatService.init(signDevlistV2Only: true)`,
observable as `debugDevlistSignV2Only` — and `signDeviceList(v2Only: true)`
produces the shape in the protocol tests and the vectors.

**The real floor for the flip.** "Once the v1 population is gone" (above) is
necessary and not sufficient. Every build before the release that carries this
section reads `sig` unconditionally when it parses a list, so a list without it
does not even parse there. To such a client a flipped account's new list does
not exist in‑band — its new devices get nothing, and after the grace the user is
told that the contact's list changed and the update never arrived — and the
account's new entry in the log "does not open or verify as this account's list",
which ADR 0006's table treats as a **conflict: sends to that account are held**
until the user chooses to send anyway. Its own linked devices on such a build
never learn the account's list at all — and raise a false own‑account alert, an
unissued list, when contacts echo the version they cannot parse: the echo is
newer than anything the device knows, the root's answer to its request does not
parse either, and the grace runs out (`_observeOwnEcho`). So the precondition is
**everyone on at least this release, linked devices included**, not merely "no
3.5.7 left". The evidence is the one `RELAY_AUTH_V1` in `server/server.js`
already waits on — the relay's `z_auth_v1_total` at zero for as long as the
operator cares to wait — for the 3.5.7 half, and `PROVENANCE.md`'s Play figures
(not the log's label count; ADR 0010's addendum) for the rest.

**The flip itself** is one line — `const bool devlistSignV2Only = true;` — and
the republish above, which this release already carries and tests. It is one
way, by design. A contact that has installed an account's v2‑only list refuses
that account's dual‑signed lists from then on, and the account does not go back
either: turning the constant off again stops roots that have not moved from
moving, and changes nothing for those that have (above). Below this release
there is no way back at all. A build older than this one cannot start on a vault
that holds a contact's v2‑only list — it parses every held list at start‑up
without catching (`_loadContactDeviceLists`), and its parser casts `sig` to a
string — so after the flip a downgrade below this release is not degraded but
unsupported.

**What the flip commit changes besides that line: the tests that pin stage 1.**
Both suites were run with the constant set to `true` (2026‑10‑02, on a scratch
copy of this release with that line flipped): protocol 231 of 238 passed; app
344 of 359 (6 skipped, 9 failed). No failure was a fault in stage 2. Each was a
test written for stage 1, or one that hangs on timing, and the flip commit
updates them with it:

- two pin the shipped value on purpose —
  `protocol/test/devlist_v2_only_test.dart` 7 and
  `app/test/devlist_v2_only_test.dart` 1;
- six sign with the default and expect a dual‑signed list —
  `protocol/test/devlist_v2_test.dart` (4) and `mixed_version_devlist_test.dart`
  (2). Each wants `v2Only: false`: stage‑1 lists stay in the field and are still
  read;
- six count versions from 1, or read `sig` from a held list —
  `app/test/key_transparency_test.dart` (5) and `devlist_distribution_test.dart`
  (1). With the signer on every root starts one version higher, a fresh one
  included (above);
- one asserts a moment early in a pairing that the account's list now takes part
  in, because every account has one from its first start and one at version 2 or
  above introduces it with the hello — `pq_upgrade_test.dart` (the offerer is
  post‑quantum a message sooner);
- one hangs on timing — `pq_identity_test.dart`: the key has arrived before the
  assertion.

That last is one of three that fail in some runs with the constant on and pass
in others. Of the two earlier runs of the same kind (2026‑10‑01), the first
failed all three and the second none; the other two want the same attention:
`devlist_pq_suppression_test.dart`'s repair case (the three requests a contact
may make for the signature are spent before the test lifts the suppression, so
the repair rests on one still being in flight) and `devlist_hybrid_test.dart`'s
floor case (which then meets level 2, and keeps testing level 1 only with Ben
started as a stage‑1 build, `signDevlistV2Only: false`). The second of those
runs also failed a test of this change's own, which has since been pinned to
dual‑signing builds — what it tests — and passes with the constant on.

The vector generator signs its stage‑1 lists with `v2Only: false` by name, so
the frozen files do not move with the constant (the freeze test passed in every
run).

**The residual while it is off** is stage 1's, unchanged: the post‑quantum layer
does not commit to the ratchet keys — against an adversary who has broken
Ed25519 and not ML‑DSA, a ratchet‑key swap on a dual‑signed list passes the
ML‑DSA check and is refused only by `sig2`, classically. The day the constant
flips, each account's next list closes it.

**Vectors and the three re‑derivations.** `v1/multidevice.json` and
`v3/device_cert_v3.json` each gain a `device_list_v2_only` entry beside the
dual‑signed one, which is byte‑identical (`kt_log.json` is untouched): the same
account's list at the next version with `sig3` alone, its v3 fingerprint (with
the v1 and v2 ones it does not report), the ML‑DSA over its v3 input, and the
lists that must be refused — no signature at all; one device's `deviceXPub`
replaced under the genuine `sig3`, which the v1 input cannot see and which here
the ML‑DSA refuses too; the dual‑signed list with `sig` deleted; its `sig2`
moved into `sig3`; every other way of combining the three signatures, each
genuine, refused for its shape alone; and each valid list with a signature
member it does not carry added as `null`, which does not parse.
`server/test/vectors.test.js` (Node), `kt/tools/verify_vectors.py` (413 values
reproduced or refused, was 344) and `protocol/tool/verify_mldsa.py` (78 checks
with dilithium‑py, was 39) each rebuild a list's inputs from its own JSON and
apply the shapes and the rule above rather than reading the recorded field;
`verify_vectors.py` also deletes `sig` from Alice's logged list and seals it
again, as an operator would, and refuses what that opens to. Each was checked to
fail when it admits `{sig2}` alone, when it reads a `null` member as absent,
when the v3 input takes the v2 context, when the rule is inverted, when a
recorded v2‑only value is corrupted, and when a tampered list is replaced by one
that verifies. The log, its mirrors and the witness treat a leaf's fingerprint
as opaque bytes and needed no change.

**Tests.** `protocol/test/devlist_v2_only_test.dart` (11): the v2‑only shape and
the two refusals, the rule for the fingerprint and for the ML‑DSA input, the
signer off by default and stage 1 reproduced byte for byte, the vectors replayed
from their recorded inputs, the eight ways of carrying the three signatures of
which exactly three verify — and the ML‑DSA check takes exactly those — the v3
input as the v2 content under its own context, and a `null` signature member,
which does not parse. `protocol/test/devlist_sig_deletion_test.dart` (3): every
genuine dual‑signed list in the vectors, the log's sealed values included,
refused with `sig` deleted; with its ML‑DSA kept, which still covers the
stripped list's v1 input and is refused all the same; and with that deleted too.
`app/test/devlist_v2_only_test.dart` (5), real clients through the real relay
and the real log: with the signer off everywhere nothing changes; with it on for
one account among contacts that are not, one republish at the next version, the
same v3 fingerprint at every contact, the ML‑DSA over the v3 input verified at
each, the log confirming throughout and the owner's monitor silent, and a second
start republishing nothing; after a v2‑only list, a dual‑signed or v1‑only list
from the account refused at a later version and at the held one — and reported
refused by the log's install path, at the held version too — its own next
v2‑only list accepted, and no alert on either side; and two installs for one
contact started together — a newer list and an older one, then a v2‑only list
and a dual‑signed one — leaving the newer list held and the floor standing; and
an account that has flipped staying flipped on a build with the signer off — its
list and claim unchanged, its current version signed again exactly as it was,
its next version v2‑only, no alert on either side.
`app/test/devlist_log_strip_test.dart` (1), through the real log: the account's
real next list with `sig` deleted, sealed again and served as the log's entry
for that version under the v2 input's fingerprint — and the next one under the
v1 input's — is a conflict at a contact, with nothing installed and its held
list and floor as they were, and the honest dual‑signed list still installs when
it arrives in‑band. The deletion tests fail against the first build of stage 2,
where a lone `sig2` verified, and pass against this one.

## Follow-ups (2026‑10‑02)

What the review of stage 2 left, and where each stands.

- **The root's own signing raced a device being linked — closed.** A root
  signs its list from two rows read one after the other, the device set and
  the version, and linking or removing a device writes them one after the
  other. A re‑send to a contact whose echo was behind — or the hello's list,
  the re‑assertion on a reconnect, the log check's baseline — caught between
  the two writes signed the version before the link with the link's device
  set, and the record of what this device issued (`kt_own_known`) was
  overwritten with it, over the genuine list the log already held at that
  version. After a restart the self‑monitor judged that genuine entry never
  issued and said so: the alarm that tells a user to reset their identity.
  It predates stage 2 (probed on 50d9786: 2 rounds in 12), and stage 2 would
  have widened it — with the signer on, every account is at version 2 from
  its first start, so every new contact's first echo is behind and is
  answered by a re‑send. Now the read–sign–record and the two writes take one
  lock, and a version keeps the fingerprint it was first recorded with: a
  root that would record a second fails loudly in a debug build and sends
  nothing in a release one, and a linked device does not adopt a second list
  at a version it holds (`PROTOCOL.md` §19.8;
  `app/test/own_list_race_test.dart`, the probe run for 24 rounds).
  `devlist_v2_only_test.dart` 10 links its device only after the restart to
  stay out of this race; it no longer has to.
- **A removal notice and the extras session — open.** The notice in
  `_installContactDeviceList` is encrypted on a contact's extras session
  under the install's lock, while the fan‑out and the inbound path work on the
  same session under the conversation's, so the two can interleave; the
  comment at the notice says how. Taking the conversation's lock inside the
  install is not the fix: it is not re‑entrant.
- **The log's install path, superseded — open.** `ktInstallFromLog` answers
  "refused" when an in‑band list replaced the log's between the install and
  its answer, which reads, until the next check, as a conflict.
