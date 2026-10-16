# ADR 0029 — A device says it can read a v2‑only device list, and an account moves when every reader has said so

**Status:** **Proposed** (2026‑10‑09) — built (phase 18.5–18.6, 4.2.0).
Adds PROTOCOL §3.7 and one sentence each to §6.2 and §9; amends ADR 0017
(the gate of stage 2b). R42 is updated in place.
**Decides:** how a device tells the devices it talks to that it can read a
v2‑only device list; when an account moves to v2‑only signing (ADR 0017 stage
2b), and on whose evidence; what happens when a device that has not said so
reads the account's lists after it has moved; and how the gate is seen without
anything leaving the device.

## Context

Two findings of the 3 October 2026 analysis (§4.5), reproduced before anything
here was written.

**P1‑2: a same‑version swap of a linked device's ratchet key is invisible
(R42).** While every list is dual‑signed (`{sig, sig2}`), its fingerprint and
its ML‑DSA signature are over the v1 input, which carries the version and the
Ed25519 keys and not the ratchet keys (ADR 0017). Someone holding the account
root's seed — or, later, a quantum computer — re‑signs `sig2` over a list with
one linked device's X25519 key replaced: it verifies, the fingerprint does not
move, the genuine ML‑DSA still verifies, the log confirms, and the laptop
silently stops receiving. Stage 2b closes it — a v2‑only list (`{sig3}`)
commits fingerprint and ML‑DSA to the v3 input, which names every ratchet key
— and stage 2b was built and switched off (`devlistSignV2Only = false`).

**P1‑3: the switch could not be thrown, because its gate could not be
measured.** ADR 0017 waited until no build that cannot read a `{sig3}` list
was left — every build before 3.9.9 throws on one — and named as evidence the
relay's `z_auth_v1_total` and `PROVENANCE.md`'s Play figures. The counter is
blind to every client since 3.5.2, which all authenticate with auth v2; the
Play figures do not exist; and the update check sends no version, by design
(ADR 0014). Meanwhile Google Play was still serving 3.9.1 in October 2026.
Throwing the switch for everyone at once would have left every Play user
unable to read any moved account's list: its new devices unreachable, its log
entry a conflict that holds sends, its linked devices on such a build raising
an alarm about their own account.

What the analysis proposed is narrower than a flag day, and measurable: an
account's lists are read by a small set of devices it already talks to inside
the end‑to‑end channel — every device of every contact, and its own linked
devices — so each of them can say whether it reads a v2‑only list, and the
account can move when all of them have.

## Decision

### 1. Every device says what it reads: `dlr`

Every inner message a device sends to a contact's device carries
`"dlr": 3` — the newest device‑list shape the sending device reads, 3 being
the v2‑only `{sig3}` list (stage 2a, every build from 3.9.9). Every self‑sync
envelope a device sends one of its own devices carries the same member beside
`thread`, `dir` and `inner`. It is stamped on every message, outside the
best‑effort decoration around it, so an updated device says so with the next
message it sends, and a device that goes back to an older build stops saying
it.

A receiver records it per **sending device**, under that device's routing id:
`dlr` at least 3, the device reads a v2‑only list; a message that carries
7.7a's claim `dl` and no `dlr`, an older build that decorates what it sends
and does not say — recorded as 0; a message that carries neither (a removal
notice, a decoration that failed) teaches nothing. A device never heard from
counts as unable to read one. The comparison is at‑least, so a later shape
can raise the number without making today's readers look old.

**Why this carrier.** The 7.7a decoration rides every inner message every
device sends, so the member costs no envelope of its own (eight bytes inside
one), comes from each device separately, authenticated by that device's own
session, and is said again by every message. The alternatives each fail one
of those:

* `hello` opens a session and repairs one. A device that updates sends no new
  hello to anyone, so an update would never be seen.
* `pqid` is sent once per contact per run, bounded, 16 KB, and stops when the
  post‑quantum identity exchange is done — the same problem, and a
  distinctive envelope.
* A member of the device‑list entry is the root's statement about its
  devices, not each device's statement about itself; the root would have to
  learn its linked devices' builds first, which is this anyway. And no
  signature covers such a member: anyone who passes a list on — a contact, the
  log's operator, who can open a value and seal it again (§19.1) — could add
  or strip it.
* The relay is where a build could be reported centrally, and that is
  telemetry: the relay learning which mailbox runs which build is exactly what
  Z does not do (ADR 0014 keeps even the update check version‑free).

It never reaches the relay: it is inside the ratchet, as `dl` and `pqh` are.
Compatible both ways: every build ignores an inner member it does not know
(§6.1) and reads the self‑sync envelope by its three members; a build of this
release reads silence as "not yet".

### 2. The gate: an account moves when every reader has said so

The root — the only device that signs the account's lists — moves the
account to v2‑only signing (ADR 0017's move, unchanged: the next version,
`sig3` alone, to its own devices, every contact and the log) the moment all of
these hold:

1. this build allows the move (`devlistSignV2Only`, the kill switch below);
2. the account has at least one linked device, and **every one** of its
   linked devices has said it reads a v2‑only list;
3. the account holds at least one contact, and **every device of every
   contact** has said so — the device the contact was added from and every
   device the contact's installed list names; a contact still waiting to
   accept a request counts, since it will read the list once it does.

It is checked at start‑up and whenever something it reads changes in its
favour: a device says it reads one, a contact is deleted, a contact's list
drops a device, a linked device is removed. A move in progress is not started
twice. Nothing is asked for and nothing extra is sent: the gate opens on
traffic that would have flowed anyway, and a linked device adds one ping to
its own devices per start and one whenever it takes a newer list from its
root (the first one names it), so a laptop switched on only to read is still
heard.

**Every linked device, not a share of them.** Each one reads the account's
lists by self‑sync. One that cannot (a build before 3.9.9) never learns its
own account's list, and — being older than ADR 0026 — raises "a list you never
issued" when contacts echo the version it cannot parse. A threshold below all
of them breaks the rest.

**A linked device, and a contact, before anything moves.** R42 needs a linked
device: a one‑device account is immune, because its contacts take its one
device's ratchet key from the code they scanned. Moving such an account buys
nothing and narrows, for good, who can read its list. And an account that has
heard from nobody has measured nothing: moving it would be the global flip
this replaces, applied to whoever it meets next.

**A contact who never speaks holds the move.** A device that has said nothing
is not assumed to be new. The account waits; the developer view (§5) shows
what it is waiting for, and a message to that contact is answered by a
delivery receipt from each of their devices, which says. A contact on an old
build holds it until they update — which is the measurement working: their
app is one that would break.

**What it cannot count.** A device that holds this account while this account
does not hold it — someone whose request is still waiting, someone the user
deleted — sends the account nothing it would read, so it is not counted. It
can still read the account's entry in the log; on a build older than 3.9.9,
after the move, it sees what §4 describes, and an accepted request makes it a
contact like any other added after the move.

### 3. The constant becomes the kill switch

`devlistSignV2Only` (`protocol/lib/src/multidevice.dart`) is now `true`, and
means: a root of this build may move once its gate is open. Setting it `false`
in a release stops every account that has not moved from moving; it never
un‑flips one that has — ADR 0017 already made the stored state decide (a
version is never signed twice into two fingerprints). The capability is said
either way; it is a fact about the build. It is no longer the library's
signing default: `AccountIdentity.signDeviceList` dual‑signs unless told
otherwise, because whether a list is v2‑only is one account's decision, made
once by its root and passed explicitly.

The immediate effect in the field is nothing: no build before this one says
`dlr`, so no account moves until every reader of it runs this release or a
later one. Accounts then move one at a time, as their last reader updates.

### 4. After the move, a reader that has not said so

A device can come to read a moved account's lists without having said it can:
a contact added later, a device a contact links on an older build, a device
this account links on one. The account does not move back. Moving back would
mean either re‑signing a version it published under a second fingerprint —
the split every contact holding the v2‑only list is built to treat as an
attack — or signing a new version with `sig` again, which every capable
contact's floor refuses (ADR 0017, level 2) and which, served by the log, is
a conflict at each of them. So:

* **Its claim is withheld from each device that has not said it reads a
  v2‑only list.** The claim (`dl`) names a list such a device may be unable
  to parse, and a build that cannot parse it turns "a claim above the list I
  hold" into "their device list changed and the update never arrived". It is
  made again with the next message once that device says it reads one. It is
  never withheld from a device that has said so: that device's record of the
  claim must not go stale, or the next list it installs would look newer than
  anything the account admits to. Before the move nothing is withheld — a
  dual‑signed list is readable by everyone. (Amended 2026‑10‑16, after
  4.2.0. As built in 4.2.0 the rule was per contact — withheld only while
  none of a contact's devices had said so — and so a device beside one that
  had, an older laptop beside an updated phone or an older phone beside an
  updated laptop, was sent the claim and raised the alarm this rule exists
  to prevent.)
* **The user is told,** on that contact's screen, once one of their devices
  has said (by what it sends) that it is an older build: their app may not
  read your device list; one older than 3.9.9 cannot reach your other devices
  and may warn them about your account until they update; nothing is wrong
  with either account. A neutral notice, not an alarm, and not shown for a
  contact just added who has not spoken yet.
* **What the older contact sees.** A build from 3.9.9 up to this one reads
  the list and sees nothing different. A build older than 3.9.9 cannot parse
  it: it holds the account's list as it was (a contact added after the move,
  the one‑device baseline from the code), so it reaches only the device it
  added the account from and does not accept messages from the account's
  other devices; and its check of the transparency log finds the account's
  entry unopenable — a conflict that holds its sends to the account until
  its user chooses "send anyway". Nothing the moved account does can prevent
  that: the entry is public and that parser throws on it. Updating to 3.9.9
  or later ends it.
* **A device this account links on an older build after the move** is the
  same case on the account's own side: from 3.9.9 it reads the list and is
  counted until it says so; older than that it cannot learn its own account's
  list, and may raise the own‑account alarm on its contacts' echoes. The root
  does not refuse the link — pairing (§10) is unchanged, and the joining
  device says nothing about its build there. Update the device.

### 5. Seen without telemetry

Settings › Transparency log, in developer mode, has a row "Device‑list
signing": whether the account's list is dual‑signed or v2‑only, "Contacts'
devices not yet capable: N", "Your other devices not yet capable: N", and what
the move waits on (both counts at zero; a linked device and a contact; the
build's switch; on a linked device, the main device). Everything in it is
counted on the device from what other devices sent it; nothing is reported
anywhere.

## Rejected

* **A flag day** — throwing the constant for everyone once some count says
  the population has moved. There is no such count, and building one is
  telemetry; and any date leaves the stragglers broken.
* **A time limit** — moving anyway after N days without every reader. It
  breaks exactly the readers that have not updated.
* **Assuming a device is capable until it says otherwise.** The builds that
  cannot read the list are the builds that cannot say anything.
* **Dual‑signing the ML‑DSA through the transition** (ADR 0017's recorded
  alternative, `mlsig2`). It would cover the ratchet keys post‑quantum for
  readers that understand it without waiting for the move, but it leaves the
  fingerprint — what gossip, the log and the self‑monitor compare — blind to
  a swap, and it is a second signature format to carry for ever. The move
  closes both at once, account by account.
* **Refusing to link an older device after the move.** It needs the joining
  device to say what it reads during pairing, a change to §10 left for when
  pairing next changes.

## Consequences

* **Wire.** One optional inner member and one optional member of the
  self‑sync envelope (§3.7); no new kind, no version bump, no vector moved:
  every file under `docs/vectors/` is untouched, and the protocol suite's
  frozen‑vector test still reproduces each byte for byte — the dual‑signed
  and v2‑only device lists included, since the library still dual‑signs by
  default and the generator names `v2Only` where it means it.
* **Invariants.** Zero knowledge at the relay: the member is inside the
  ratchet. Metadata: no envelope is added to a contact; a linked device sends
  one small envelope to its own devices per start, and one per new list from
  its root. No new trusted party: the gate is computed on the root from
  what each device said over its own authenticated session. A contact can
  only hold the move (by never saying it reads a v2‑only list) — the state
  every account is in today — or claim a capability its own app lacks, which
  harms only that contact's view of the account.
* **Storage.** Per contact, sealed, `cdl_dlr_<rid>`: what each of their
  devices last said, written only when it changes, removed with the contact.
  For the account's own devices, sealed, `own_dlr`. Neither is carried in a
  backup or an enrolment: a restored or new device learns them again from
  traffic, and a moved account stays moved from its own list.
* **Tests.** `app/test/devlist_capability_test.dart` (11 criteria, 9 tests):
  the records per device and per own device, kept across a restart; one
  contact behind holds the move, not even a restart moves it; the moment it
  says it reads the list the account moves without a restart, every reader
  installs it with the claimed fingerprint, the log confirms, no alert
  anywhere; a contact on an older build added after the move — one that reads
  the list and one that cannot — and no move back, the claim withheld, no
  alert on either side, the notice shown, the claim resumed when they update;
  the kill switch holding an open gate and not un‑flipping a moved account;
  an older laptop holding the move until it updates, and no move without a
  linked device; a list the account never issued still raising the owner's
  alarm after the move; a contact whose devices differ sent the claim on the
  one that reads the list and not on the other, either way round, with no
  alert, the copy without it keeping its timer; Settings' developer view and
  the contact's screen. Its
  criterion 1–2 in the form that runs on the base fails on `0d00a69` ("Alice
  has moved to v2‑only signing" never holds) and passes here. ADR 0017's own
  tests, which test what the move does rather than when, start their moving
  accounts with a test‑only switch that moves at the first start as the
  signer did before this gate (`debugMoveUngated`). Four files of stage‑1
  scenarios that count an account's list versions by hand
  (`alarm_evidence_test.dart`, `devlist_distribution_test.dart`,
  `devlist_transparency_test.dart`, `linked_equals_test.dart`) start their
  accounts with the switch off, as the build they were written for had it: on
  this one, an account whose readers all run it moves in the middle of them.
