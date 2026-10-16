# ADR 0026 — An alarm about your own account is raised only on evidence its key signed

**Status:** **Proposed** (2026‑10‑04) — built (phase 32, 4.0.1), for
review. Amends `PROTOCOL.md` §3.6 (the owner rule, the removal notice), §6.2
(`dlrm`, a new `pdlreq`, the `devlist` answer) and §19.8; amends ADR 0001's
rules 5 and 6 and ADR 0006's "Self‑monitoring".
**Decides:** on what the owner of an account is told that something is wrong
with it, and when a banner the owner dismissed comes back.

## Context

Four banners speak to the owner about their own account. Three of them end
in "reset your identity":

| banner | raised by, until this change |
|---|---|
| *A contact was given a device list for your account that this device never issued …* (`own_unissued`) | an echo (`pdl`, §3.6) — two numbers on any inner message — naming a list this device does not hold, unexplained after the grace |
| *Your main device published an older device list …* (`own_older`) | a list from this account's own root, over self‑sync, older than the one held |
| *This device was removed from your account …* (`own_removed`) | a removal notice (`dlrm`) — `{acct, v, h}` — naming this device's account |
| *A device list you did not issue has been published to the transparency log …* | an entry for this account in the log whose (version, fingerprint) this device never recorded |

The deep analysis of 3 October (P1‑7) ran the first and the third from a
contact's modified client: a made‑up echo, and a bare `dlrm`, each one
message long, raised them on the victim. Nothing was signed, nothing was
checked, nothing was rate‑limited, and both came back after being dismissed.
"A contact" includes every member of a group the user is in — a group adds
its unknown members as contacts so they can be decrypted (§11).

The same pattern was in the other two. The log's banner judged only the
entry's (version, fingerprint): an entry whose value does not open as one of
the account's lists — which the log's operator can put under any label
without anybody's key, since it can open values (§19.1) and the log never
serves the publish signature (§19.6) — raised it, on every account the
operator chose. And it came back at every check; that is how the own‑list
signing race (P1‑6, patch 42, fixed in 3.9.10 for new records) became a
banner at **every start** in the vaults it had already damaged, whose record
of one of their own versions it had overwritten. The older‑list banner can
only be raised by the account's own devices, but it too came back with every
re‑assertion of the same list, which a root makes at every reconnect.

A banner anyone can raise is one nobody reads, and this one tells people to
throw their identity away.

## Decision

**Evidence is a device list for this account that verifies under its key**
(§3.4: the account matches, every certificate and every signature verifies).
Only whoever holds the account seed can make one. Its identity is its
(version, fingerprint). An alarm is raised on evidence; an echo or a notice is
a claim, and a claim is at most a reason to go and get the evidence.

1. **"A list you never issued" (gossip).** An echo ahead of, or beside, what
   this device holds is a claim. The device asks the contact for the list
   behind it — `pdlreq {v, h}`, a new keyless kind — and a current contact
   answers with the list it holds for the asker's account, in an ordinary
   `devlist` (the asker tells it from a contact's own list by its `acct`).
   The alarm is raised only when that list verifies under the account's key
   and this device's own records do not explain it: not its current claim,
   not a list it signed, learned or reconciled (7), not from before it knew
   the account, and — on a linked device, which learns by self‑sync and may
   skip versions — not a version below its own that it never saw. It is
   raised after the same grace an echo always had, so a linked device's root
   can still explain an honest update it missed; the linked device still
   asks its root (`acctreq`) as before, whatever comes of the echo. An echo
   that no list backs within the grace is dropped and counted (a quiet
   diagnostic, never shown). Bounded per contact: at most three questions per
   window (ten minutes), never the same echo twice in one; an answer is
   weighed only if it is the list one of their echoes named — asked about in
   the window, or still unexplained — so only a list ahead of or beside this
   device's own can be put to it, never an old one of the account's dug up
   from the log; at most eight lists per contact per window are verified;
   and a device answers one account at most three times per window, whichever
   of its devices asks — the answer goes to all of them.

2. **"This device was removed."** Only on a list for the account that
   verifies, does not name this device, and is at a version above the one
   this device holds — so the account's own lists from before this device was
   linked, which anyone can read from the log, are not evidence; and a device
   that has learned no list of its own yet, one just linked, holds no version
   for one to be above, and is told nothing until it does. A current
   contact carries the list in the notice (`dlrm`'s new optional `list`). A
   notice without one — what every earlier build sends — is not evidence; it
   moves this device's own look at the log forward (once per window), and the
   log check hands the service the account's latest entry, opened and
   verified, every time it reads one: a removal the account published is
   found there whether or not any contact says so.

3. **"An older list from your main device."** Raised on that list (it
   verified, and only the account's own devices can send on this channel) and
   the version held: the same list re‑asserted at every reconnect is the same
   evidence.

4. **The log's banner.** Raised only on an entry that opens as this account's
   list, verifies, and carries the entry's fingerprint (§19.3). An entry that
   does not is not evidence of anything the account's key signed: recorded as
   a quiet diagnostic (`kt_own_unverified`), not shown. Nothing changes for
   the account's contacts, who still treat such an entry as a conflict and
   hold sends (`adr/0006`), and it installs no device anywhere.

5. **A dismissal is of the evidence.** Each alarm is keyed by what it was
   raised on — its kind, the list's version and fingerprint (and, for the
   older list, the version held) — and dismissing a banner records the keys it
   stood on, in the vault. The same evidence never raises the same banner
   again, across restarts; different evidence does. Evidence that arrives
   while a banner is up joins it, so that dismissing it dismisses everything
   it was showing. A banner this device clears itself — the gossip banner
   when the root's answer explains it — is cleared, not dismissed.

6. **Wire.** `pdlreq` is new and keyless; `dlrm.list` is a new optional
   member; the answer is an existing kind. An older client ignores `pdlreq`
   (§6: unknown kinds), never asks, and ignores `list`; a `devlist` carrying
   the receiver's own account's list is refused by every build that predates
   this one (it is not signed by the sender's account), which is all that an
   older device of the asking account does with the answer when it reaches
   it too — an answer goes to the whole account. The v1 vectors are
   untouched: a `dlrm` without `list` is byte for byte what it was.

7. **Vaults the own‑list race already damaged.** A mismatch at a version this
   device recorded — the log's entry at `v` under another fingerprint than
   the record's — is **reconciled quietly**, recorded beside the record
   (`kt_own_reconciled`) and not over it, only when all of these hold:

   - **it is from before this build:** the entry is inside the log head this
     device held when this build first ran on its vault, and `v` was recorded
     then (both recorded once, `kt_own_legacy`), and the log's history has
     not been reset since — a reset takes the next head without asking that
     it extend the held one, so it ends the repair. A vault this build
     creates records an empty head, so the repair never applies to it;
   - **the account's key signed it:** it opens and verifies (§19.3);
   - **it names only devices this account is known to have held:** this
     device's records (its own device, the account key, its other devices,
     the list it holds) and every device named by an entry in the log whose
     (version, fingerprint) matches its record — the fingerprint commits to
     the device set, so such an entry names exactly what this device
     recorded.

   The race only ever signed a version of the account's own devices with the
   device set of the version beside it, after the first list at that version
   had reached the log, and only before 3.9.10; its end state meets all
   three. When the reconciled entry is the log's latest and is not the list
   the root claims, the root moves to the next version with its current
   devices and publishes it, as the ADR 0010 and 0017 migrations moved, so the
   log and every contact that took the list from it converge on one list.

   **What whoever holds the root seed can still do under the rule** is no
   more than before it. The log accepts no version at or below one it holds,
   and a head that does not extend the one a client holds is a fault — the
   one way past that, a reset of the history, ends the repair — so nothing
   can enter the set the rule looks at after this build first runs:
   every list they publish from then on, and every list naming a device the
   account never held, alarms exactly as it did. What the rule silences is
   an entry they put in the log *before* this build ran, at a version this
   device had already signed differently, naming only devices the account
   had held — for instance a device the owner had just removed, published at
   the removal's version by winning the race to the log. That entry raised,
   at every start, the same banner the race was raising for the same reason,
   so it told the owner of such a vault nothing they could act on; and where
   it is still the latest entry, the root's move to the next version under
   this rule takes the device back out at every contact that took the list
   from the log, where before it stayed.

## What was rejected

- **Carry the list on every echo.** A list is a kilobyte; the echo rides on
  every inner message. It would move ordinary messages into a larger bucket
  (R1) for a check that matters only when the echo disagrees.
- **Sign the echo.** The contact is the one forging it; their signature on it
  proves only that they sent it.
- **Ask the root instead of the contact.** A split view is a list the root
  never saw; only the contact holds it. (A linked device does still ask its
  root, for the honest update it may have missed.)
- **Rate‑limit the old alarms.** A forged alarm a contact can raise once an
  hour is still a forged alarm.
- **Repair by taking the log's entry at every mismatch.** Hides a seed
  holder who wins the publish race at any version, today or later.
- **Repair by "names only devices the account held" alone,** the rule this
  repair was first sketched as. It also hides a seed holder who wins the race
  at the version that removes a stolen device, with that device in their
  list: every device in it was held. Bounding the rule to what was in the log
  before this build ran is what keeps it from being a new capability.

## Consequences

- **A contact on an earlier build cannot back an echo, so cannot raise the
  gossip banner.** A split view shown only to such contacts, and never
  published, is no longer reported to the owner by gossip. It is still caught
  by those contacts' own log check, which stops delivering to a device only
  an unconfirmed list added after a day (`adr/0006`), and by the owner's log
  check the moment it is published; and the owner's banner is again one a
  stranger to the account key cannot raise. `THREAT_MODEL.md` R46.
- **A removal told only by contacts on earlier builds** reaches the removed
  device from the log — at once, since their notice moves the check forward —
  and not at all where no log is configured.
- **An entry the log serves that does not open as the account's list** is a
  diagnostic for its owner, not a banner. Its contacts still hold sends
  against it, and see why.
- **Older‑list and log banners** that a dismissal used to clear only until the
  next reconnect or check now stay dismissed for that evidence.
- **A damaged vault whose log history is reset** before the repair has
  reconciled its entry shows the log's banner again: the repair has ended
  (7). Dismissed, it stays dismissed for that entry.
- Two existing tests published log entries whose value was not a list to
  stand for "a list the account never issued" (`key_transparency_test.dart`
  4 and 7); they now publish one, signed by the account's key, which is what
  the attack they stand for publishes.

## Exit criteria

`app/test/alarm_evidence_test.dart`, against the real relay and log: a
modified contact's forged echoes, bare and forged notices and unasked lists,
50 rounds, raise nothing and change no alarm or device‑list state, and buy
at most three questions (1); a list the account key signed and its devices
never issued still raises the banner on the root and on a linked device (2);
a genuine removal still reaches the removed device, from a contact's notice
and from the log, while a device just linked is told nothing by the lists
from before it (3a, 3b); dismissals hold for the same evidence across a
restart, and new evidence raises each banner again (4a–4c); a vault seeded
with either of the race's end states starts quietly — and where the race's
list is the log's latest, the root moves to the next version — while an
entry naming a device the account never held, and one that reached the log
after this build first ran, still alarm, and a reset of the log's history
ends the repair (5a–5e); and a log entry that does
not open is no banner for its owner and still a conflict for a contact (6).
