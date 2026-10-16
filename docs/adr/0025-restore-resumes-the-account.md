# ADR 0025 — A restored backup resumes the account: what the archive carries, what the first start signs, and what a linked device's backup is

**Status:** **Accepted** (2026‑10‑04) — built (phase 31, 4.0.1). Amends
`BACKUP.md` §2, §4.1, §5 and §6; informative text in `PROTOCOL.md` §13.
**Decides:** what a `.zbk` archive carries beyond history, the version a
restored device signs before it sends anything, what restoring a linked
device's backup does, and how the format versions itself so an older build
refuses what it would misread and keeps what it cannot read.

## Context

The documented way back from a lost phone told its user to reset their
identity. The archive carried the identity and the history and none of the
account's device‑list or transparency state, so a restored root started again
at device‑list version 1 (the 2026‑10‑03 analysis, P0‑3):

* its own log monitor found the versions it had signed before the backup —
  any account that ever linked or unlinked a device, or was migrated to the
  v2 format, has some — and reported each as *a list you did not issue*;
* each contact saw its devices claim version 1 after claiming a higher one, a
  rollback, and after a re‑link the new list landed on a version the log
  already held, so sends were held as a conflict;
* the alarms came back at every start and every six hours, and nothing in the
  app could clear them.

A backup taken on a **linked** device was worse (P1‑8): the device key, the
only key the archive carried, was read as an account root; the restored
device signed lists for a one‑device account nobody had and published them to
the log under its own key, and every contact who knew it as one of an
account's devices saw it claim lists that were not that account's.

Around them, four smaller things (the analysis's backup P2s): a restore
dropped the block list, pending requests, the push‑off preference and a
custom log configuration; it re‑opened every session an opening envelope
could re‑create, so whoever kept one could put a deleted message back on the
screen; a vault a newer build wrote was opened anyway, its version lowered,
and the newer build then failed its own migrations at every start; and an
older build restoring a newer archive skipped whatever it did not know
without a word.

## Decision

**1. The archive carries what the account needs to resume (format 1.1).** A
`state` record with the account's own device list — version, the list last
signed or learned, linked devices, its post‑quantum signature, the migration
flags — every (version, fingerprint) it knows it issued, the log's
configuration and accepted head, a root's device id, the push preference and
any own‑account alarm not dismissed; each `contact` record gains the
contact's list, floor, claims, log standing, alarms and `last_open_`; new
`blocked` and `request` records; and on a linked device the `identity`
record gains `account`. Everything is checked on restore against the shape
the code that reads it at start‑up needs — a list must verify under the
account it names — and what fails is left out. Not carried: ratchets, the
outbox and dedupe table, the publish queue, the log's timings and fault, and
*this device was removed*.

**2. Session ids travel; sessions do not.** The ids of every session — the
contact's, their other devices', the account's own devices' — are restored
as *retired* in conversations holding no session. A restored device refuses
a kept opener exactly as a live one refuses one for a session it retired
(`PROTOCOL.md` §4).

**3. The first start re‑asserts the account before it sends anything.** A
restored root reads the log (verified, at most twenty seconds), records as
its own every list in the log the archive did not know that opens and
verifies as the account's — except one the backed‑up device had already
reported — and signs one list at **max(log, held) + 1** over the devices the
archive knew that the log's newest list still names, v2‑only if the
account's list already was (`adr/0017`, whether the archive or the log says
so), then queues it to its own devices and its contacts. All of it before
the transport starts. An archive written before 1.1 holds none of this
state, so its restore takes all of it from the log — every backup taken
before this decision restores as quietly, while the log can be asked.

**4. A linked device's backup restores as that linked device.** It holds no
root, so it signs and publishes nothing, by construction. It adopts the
account's newest list from the log if that list names it, and raises *this
device was removed* if not; then it asks its root for the list.

**5. Versions.** The header's `v` is the major version, refused when unknown —
on sight, before the code is asked for ("update Z first"). `mv` is the minor
revision: new record types and members only. An unknown record type marked
`"keep":1` is stored and written back unchanged into every later archive; one
not marked is skipped. A new frame kind is a major bump.

**6. A vault from a newer build is refused, unchanged.** sqflite's downgrade
handler throws, the transaction rolls back, the version stays; every
migration step is idempotent, so a vault an older build already set back
upgrades instead of failing.

## What was rejected

* **Refusing a linked device's backup** ("link this device again; import the
  history afterwards"). It would make an archive history only, never a device
  — a real reduction of what a stolen archive and code grant — but it needs
  the root at hand, loses everything the link's history sync does not replay
  (200 messages a chat) unless a merge‑import is built, and serves worst the
  case a laptop's backup matters most for: the phone is the thing that was
  lost. The device it restores was enrolled by the root, its certificate is
  the root's, the root can remove it at any time, and it can sign nothing. A
  root's own archive already is the whole account (R6); a linked device's
  being that device is strictly less (R45).
* **Reporting every list after the backup as never issued.** That is the
  alarm this ADR exists to stop: the restored device cannot tell its lost
  phone's lists from someone else's, and the honest case is the common one.
  It reports what it can tell — a list that does not open as the account's,
  and anything after the restore.
* **Adopting the log's newest device set wholesale.** Seamless for a laptop
  linked after the backup, and exactly as seamless for a device someone else
  enrolled with the root key. A removal made after the backup is kept; an
  addition is linked again.
* **Waiting for the log without limit.** A restored device whose log is down
  would not connect at all. Twenty seconds, then the archive's version + 1;
  the conflict that can then follow is R45's (2).
* **A major bump for format 1.1.** Every build in the field already restores
  1.1 as 1.0 — what it cannot read it skips, and it was skipping it anyway —
  while a major bump would lock users of older builds out of their own
  history.

## Consequences

* An honest restore raises no alarm on the device, at any contact, or in the
  log, through any number of restarts, from a 1.1 archive or an older one
  (`app/test/restore_truth_test.dart` 1–3, 10, 11). To contacts it is a
  device‑list update; to the log, the next version.
* R45 records what remains: a list someone else signed in the window between
  backup and restore is taken as the account's; with the log unreachable a
  version signed after the backup can collide; a pre‑1.1 archive from a linked
  device still restores as a root; a 1.1 one is that device.
* `docs/vectors/backup/archive.json` is unchanged; `archive_1_1.json` pins the
  1.1 shapes and the refusal, replayed by `protocol/test/vectors_test.dart` and
  by `server/test/vectors.test.js`.
* A later phase that needs a record to survive an older build's restore and
  re‑backup (a handle key) marks it `keep`, and puts what must survive in a
  record of its own: fields added to a known record are not carried.

## Exit criteria

`app/test/restore_truth_test.dart` 1–11, against a real relay and a real log:
quiet restore and max + 1 before the transport starts (1); two restarts (2);
a log ahead of the archive (3); a linked device's backup (4); the state that
travels (5); a replayed opener (6); a newer archive refused on sight and on
import (7); a newer vault refused and an older‑build downgrade upgrading (8);
`keep` (9); an archive written before 1.1 (10); an account moved to v2‑only
signing (11).
