# ADR 0036 — Large groups: no group key at any size, at most 128 members, and a fan-out made cheaper where it costs

**Status:** **Accepted** (2026‑10‑17). Proposed the same day; Finnian's
decisions of 2026‑10‑17 answer its eight open questions — folded into the
text where it asked them, and listed under "Decisions". Roadmap phase 48
(`ROADMAP.md` lines 60, 539).
**Built:** 48.1 — the cap, and no list a frame cannot carry (PROTOCOL §11
"Size" and §11.1's size bullet; `group_management_test.dart` 4–7,
`group_invite_link_test.dart` 26). 48.2–48.5 are not built.
- **Amends:** PROTOCOL §11, §11.1, §12.5 and §7 (informative); `PERFORMANCE.md`; `THREAT_MODEL.md` (R12, R18, R29, R38, and a new register row when 48.5 lands); AUDIT_SCOPE C9; `USING_Z.md`; `WHAT_Z_CANNOT_DO.md`.
- **No wire change**, and no new vector.
- **Keeps** the standing non-goal of ADRs 0019 and 0030, no shared group key, and states its cost.

**Decides:**
- whether a group ever gets a shared key (no);
- how large a group a current client makes (128 members);
- how the fan-out spends less per envelope;
- what a group file may cost;
- what becomes of larger groups that older builds made.

## Context

Phase 48 asks whether "one encryption per member per message" should give way to a group-key schedule. The encryption is the cheap part. A member costs the sender about 22 ms (`PERFORMANCE.md:243`: fifty members on a debug VM, before the memo that halved a 1:1 send, `:393-394`). Of that, the ratchet step is **0.23 ms**, the seal ~2.0 ms (86 % of it the envelope's own X25519) and the transaction 3.94 ms (`:75-76`, `:87-91`). The rest is per envelope, and no key schedule changes how many envelopes there are:

- **The metadata rules fix the count.** N devices are N sealed envelopes to N mailboxes, each with a fresh id and ephemeral (§8, §12.2, C9's last clause). Anything the relay could see shared across them — one upload it copies, one ephemeral, one sealed ciphertext — would hand it the recipients, as the 2026‑09‑13 shared-id leak did.
- **Sends are serial.** The outbox awaits each `sent` on one link, so at an assumed 50–100 ms round trip, 128 copies take 6–13 s.
- **The first-contact gate.** Each relay instance has 120 tokens a minute for all senders (`server.js:117`). It spends one on each send to a mailbox that holds nothing and that it has not written to within the hour (`:121-124`). A refusal is `store_full`, which stops the client's whole outbox for a minute.
- **Membership changes carry everyone.** A list holds every member's bundle, about 455 bytes an entry in the sealed envelope (§11.1's figure). By my arithmetic it fits:
  - the 65 536 bucket up to about 140 members (87.5 KB to each);
  - the 262 144 bucket up to about 570 (350 KB; §11.1's "fewer than 900" assumes empty names);
  - nothing beyond that, and until 48.1 it failed silently.
- **Attachments multiply.** A file is encrypted once (§7), but each 143 360-byte chunk is sealed per member. Three base64 layers (`attachments.dart:83-91`, `sealed.dart:131-138`) make each chunk a 349 610-character envelope: 2.44 × the file, or 7.7 MB per member for a 3 MiB photo. The public relay holds 16 MiB a mailbox and 256 MB in all, so that photo, sent to about 33 offline members, fills it for everyone.

*(Built, 48.1: by the issuer's own measure, on lists of entries shaped as a real group's and a device with no other devices of its own, the frame rule first bites at 626 members with four-character names and at 550 with twenty-character ones (`group_management_test.dart` 5); a list of 128 travels as 87 466 characters, in the 65 536 bucket (4).)*

The table counts one message to each member's main device. Linked devices multiply the text rows, not the photo (`chat_service.dart:5122-5128`). Nothing measures more than one device per member (`PERFORMANCE.md:778`).

| | 50 | 128 | 256 | 900 |
|---|---:|---:|---:|---:|
| Sender time, text (~22 ms a member) | 1.1 s (measured: 1 097 ms) | 2.8 s | 5.6 s | 20 s |
| Upload, text (1 450 characters a copy, `PERFORMANCE.md:447-448`) | 73 KB | 186 KB | 371 KB | 1.3 MB |
| Upload, a 3 MiB photo | 385 MB | 985 MB | 1.97 GB | 6.9 GB |
| Upload, one add, removal or rename | 4.4 MB | 11 MB | 90 MB | not deliverable |
| Gate tokens after a quiet hour, at most | 50 | 128 | 256 | 900 |

The ceiling is not CPU:
- text is affordable to a few hundred members;
- membership changes and the gate strain at about 140;
- media breaks below fifty members on the public relay.

Three constraints come from earlier decisions:
- ADR 0019 refused a group signing key as "a shared key by another name" (0019:105-108).
- ADR 0020 refused a relay-side lobby, because "the relay would learn who is in a group by construction" (0020:70-71).
- Each channel mixes ML-KEM-768 into its message keys after the first round trip and re-keys weekly (§17.1, §17.7). A group message is as post-quantum as its channel (`USING_Z.md:324-325`), and a replacement must match that.

## Decision

### 1. No group key, at any size Z carries

§11 stays. Neither sender keys nor MLS reduces the envelopes, the round trips, the gate or the media. MLS would shrink what a membership change sends to existing members, but not what reaches a joiner (below).
- **The saving:** the ratchet step and its state write, 1–2 % of a recipient. Batching recovers the transaction share pairwise (`PERFORMANCE.md:123-133`).
- **The price:** healing after compromise (sender keys), or a party that orders commits (MLS).

### 2. A group has at most 128 members

- **Issuer rule.** A current client issues no list that adds a member when the list would then name more than 128 accounts, itself included — the cap Finnian chose on 2026‑10‑17 (question 1).
  - `createGroup`, `addGroupMembers` and the invite link's add (ADR 0020, re-checked when the go-ahead lands) refuse, and say why.
  - Removals, renames, roles and timers go out at any size, so no group freezes.
- **No list a frame cannot carry.** At any size, the issuer measures the list as it will travel and refuses one past the 262 144 bucket (§8). Until 48.1 the relay dropped such a list, and only the admin kept it. *(Built, 48.1: measured for the longest copy — a member's at its fullest header and claims, or, while the issuer's account has other devices, theirs, which carries the list in one base64 layer more inside the self-sync envelope — and refused before anything is saved or queued, the group put back as it was. So a group whose list is past the bucket already — only an older or modified build, behind a relay with a larger frame cap, can have made one — takes no list from a current client, a removal included; its members still write to it, and leave.)*
- **Receivers are unchanged** (§11.1's 1 024), and stay so: Finnian's decision of 2026‑10‑17 is never to lower that bound to the cap (question 8), so a group made by an older or modified build always loads. A list of 300 from an older build is taken, shown as over the limit, and can shrink — shrink-only, as decided (question 5). The cap binds only what is issued, so mixed-version groups converge as now.
- **Why a cap at all — the threat model.** Larger groups are cheap only if the relay is told who is in them (relay fan-out, store-once media; both rejected below), so Z does not make them. And each member is an unverified contact of every other (`_adoptGroupContacts`, `chat_service.dart:10994-11008`). Any of them can fill your mailbox (R22), send you chunks (R26) or claim a device first (§3.4); 127 strangers is plenty.
- **Why 128 — the costs.**
  - The list stays in the 65 536 bucket: a change costs 11 MB to send, against 90 MB at 256.
  - A text is about 166 envelopes at an assumed 1.3 devices a member. Once pipelined, it fits one burst of the relay's per-connection limit (240, §12.4).
  - After a quiet hour, on an otherwise idle instance, that text waits at most one retry at today's gate of 120 tokens a minute. Finnian's decision of 2026‑10‑17 raises the public relay's `NEW_MAILBOX_PER_MIN` to 240 per instance (question 3) — an edit to its Blueprint, which is his — and one minute's tokens then cover it.

The cap counts accounts; each device is still its own envelope. A broadcast with a single writer is a different feature, with its own phase and ADR (question 6).

### 3. The fan-out pays per envelope, so make each envelope cheaper

This is a client change only; nothing on the wire changes.
- **Several in flight, one per mailbox.**
  - The outbox keeps up to 32 envelopes or 2 MiB in flight on the anonymous link, paced at 64 frames a second (burst 192), under the relay's 80 (burst 240).
  - Sends refused by an error without an `id` go again (§12.2); §6.7 drops the duplicates.
  - One-per-mailbox becomes normative in §12.5, because §17.7's 72-hour drop of an old post-quantum generation relies on per-mailbox order.
- **A refusal holds its mailbox, not the outbox.**
  - `rate_limited` backs off from 1 s, doubling to the existing 60 s.
  - `store_full` holds that mailbox for the pass, as `queue_full` does. Only eight in a row, from different mailboxes, end the pass: a full store refuses everyone, the gate only fresh mailboxes.
- **Membership changes stay queued ahead of later messages** (`_sendInvite`, `chat_service.dart:9043-9049`), so the snapshot rule holds.

### 4. A group file has a budget, and stages under a bound

- **Budget.** Upload = recipients (members and my other devices) × chunks × 349 610.
  - From 128 MB, the composer shows it.
  - Past 256 MB, the public relay's whole store, it refuses (question 2, decided as drafted).
  - A 1 MiB photo can reach 91 recipients, a 24 MiB file four.
- **Staging bound.** The drain writes a member's chunk rows only while the outbox holds under 64 MiB. Nothing bounds that today.
- **The store stays as it is.** The public relay's 256 MB is left alone, and decided a month after 48.3 from `z_store_full_total` and `z_refused_total` (question 4, decided as drafted).
- **One base64 layer instead of three** would take uploads from 2.44 × the file to about 1.78 ×, but it is a wire change for every attachment: it gets its own ADR, later (question 7).

### 5. Membership integrity is untouched

Lists change only over the pairwise channel of an admin the receiver holds, under §11.1. The issuer checks the cap; no receiver rule changes.

### 6. Versions meeting

- **Nothing on the wire changes:** no kind, member, context string or bucket.
- **Vectors:** v1, v2 and v3 stay byte-identical (`group_list_digests` and `group_state.json` included), and no suite is added.
- **Older clients** ignore the cap; current clients take their lists and only shrink them (§2).
- **Pipelining** changes timing alone: R18's spread narrows, and its pattern is unchanged.

## Alternatives rejected

| | Pairwise (kept) | Sender keys, sent pairwise | MLS (RFC 9420) |
|---|---|---|---|
| Forward secrecy | per message (§5) | per message along each sender's hash chain | per message within an epoch |
| A stolen device state stops reading | after one DH round trip per pair | at each sender's next rotation | when that device itself commits |
| Post-quantum | ML-KEM per channel, re-keyed weekly | a symmetric key, as PQ as the channel it went on if sent after that channel's round trip (§17.8's rule); PQ healing at rotation only | none in RFC 9420; ML-KEM and X-Wing suites are drafts |
| A removed member | is sent nothing more | keeps old sender keys until each sender rotates | reads nothing after the remove commit |
| The relay learns | the burst (R18) | the same | the same; if it orders, the group id, epoch and commit order too |
| Linked devices | a session each (§9) | a sender key each, sent to every device | a leaf each, and a commit in every group per link or removal |
| Offline 72 h, or a relay restart | loses what expired; `gsync` heals the list | misses rotations: needs a re-request kind | misses a commit: out until re-added |
| Ordering | none | none for messages | one commit per epoch, agreed by all |
| Envelopes per message | members × devices | the same | the same |
| Dependency and audit | none new | new kinds and vectors; two paths until phase 49 | Rust via FFI, or MLS written in Dart; a second protocol to audit |

**Sender keys** (Signal's, WhatsApp's): each sender's chain and signing key go to every member pairwise, and each message is encrypted once.
- **The saving.** Without relay fan-out Z still sends N envelopes, so all it saves is the ratchet step.
- **Rotation.** Each removal costs every sender O(N) envelopes, O(N²) per group.
- **What a removed member keeps.** Per-device sealing narrows what they read. But a quantum break of the classical sealed layer on recorded envelopes (`THREAT_MODEL.md:239-240`), or the key of one current device, reopens it until rotation.

**MLS** (TreeKEM and epochs; RFC 9750's architecture) needs one commit per epoch, agreed by every member. Nothing here can supply that order:
- **A relay that orders** is the trusted orderer the non-negotiables refuse. It chooses which commit stands, a removal included.
- **An owner who orders** brings back ADR 0019's frozen group.
- **Z's (rv, ver, digest) rule** picks a winner after both lists are sent. That suits a list replaced wholesale, not epochs already used to encrypt. Fork recovery is not standardised, as far as I know.
- **The relay itself** keeps envelopes in RAM for 72 hours, so it is no ordered history either.

MLS has further costs:
- **The Welcome may not fit.** With the draft post-quantum suites (not checked here), by my estimate a Welcome carrying a 128-leaf tree runs past the largest bucket.
- **No Dart implementation.** I know of no maintained one. openmls through FFI brings a Rust toolchain, crates and a binding generator, against the pure-Dart choice (`PERFORMANCE.md:726-743`).
- **A second answer.** Its credentials would be a second answer, beside §3.4 and ADR 0022, to which devices are an account's.

**The rest:**
- **Pairwise below N, a key above.** The costs that bind stay per envelope. A group that crossed N would change its healing mid-life, and C9 would have to state both regimes.
- **Relay fan-out** (one upload plus a recipient list, as I understand Signal's multi-recipient sealed sender). The relay gets the membership with the first message (C9; ADR 0020's lobby). R18 lets a patient operator infer it after about eight messages; fan-out tells any operator at once, and the TLS front too (R44).
- **Store-once media** (one blob every member fetches): a new identifier linking the members.
- **One payload key per message, wrapped per member** (the roadmap's option (a)). For text, the payload's AEAD is 47 µs (`PERFORMANCE.md:664`), and files already work this way (§7).
- **No cap.** Lists outgrow the frame at about 570 members, silently.

## Consequences

- **PROTOCOL:** §11 "Size", §11.1's size bullet, §12.5's one-per-mailbox rule, and §7's upload per recipient (informative). §14 needs nothing.
- **Vectors:** none.
- **Tests:** in existing files, as the build plan lists, because the app's test-file count is guarded (`AUDIT_SCOPE.md:41`).
- **THREAT_MODEL:**
  - **R18:** the burst is the group, pipelined and capped.
  - **R12:** the relay sends one FCM wake per envelope queued for an offline device, uncoalesced (`server.js:4206-4222`), so Google sees R18's pattern too.
  - **R29 and "Your contact":** a group makes its members each other's contacts.
  - **R38:** the cap binds only current issuers; older or modified clients can still inflate a group to 1 024, and always will: receivers keep §11.1's bound for good, so R38 is permanent (question 8).
  - **A new register row when 48.5 lands, accepted:** group media is bounded by the relay's store, not by the client. The budget keeps one send within the public store. Two sends, or one to a group with many members offline, can still fill it, and everyone on that relay is then refused until those members drain.
- **AUDIT_SCOPE C9:** no list grows a group past 128 or exceeds a frame; a refusal holds only its own mailbox; a group file over budget writes nothing. §4 item 10 points here.
- **PERFORMANCE.md:** "Large groups (48)" measures the table; lines 221–231 corrected.
- **USING_Z, "Groups":** the cap, and the upload.
- **WHAT_Z_CANNOT_DO:** no groups past 128, and no broadcast.

## What remains

§11's properties hold at every size: forward secrecy per message, healing after a round trip, removal by omission, and post-quantum per channel. So do its costs: R18 in kind, members who are each other's contacts, an upload per member for media, and older or modified builds past the cap — for good, since receivers keep §11.1's 1 024.

## Decisions (Finnian's, 2026‑10‑17)

1. **The cap:** 128 (recommended: the list stays in the 65 536 bucket), or 256 (a change is 90 MB to send, and a quiet hour's first message waits up to about two minutes at the gate)? — **128 members** (§2).
2. **The file budget:** show the cost from 128 MB and refuse from 256 MB, or warn only? — **(default) Show the cost from 128 MB; refuse past 256 MB** (§4).
3. **The public relay's gate:** raise `NEW_MAILBOX_PER_MIN` in `render.ha.yaml` from 120 to 240 per instance, or accept a tail of one retry? — **Raise it from 120 to 240** (§2). The Blueprint edit is Finnian's, and its comment ("only if real first-contacts are being refused") gains the reason.
4. **The public relay's 256 MB store,** which bounds group media? — **(default) Leave it, and decide a month after 48.3 from `z_store_full_total` and `z_refused_total`** (§4).
5. **Groups already over 128:** shrink-only, or ask the owner to split? — **Shrink-only** (§2).
6. **Broadcast channels?** — **Their own phase and ADR** (§2).
7. **A binary chunk payload,** one base64 layer instead of three? — **Its own ADR, later** (§4).
8. **Lower the receiver's 1 024 bound to the cap,** once older builds are gone? — **Never** (a departure from the recommendation): receivers keep §11.1's bound for good, so a group made by an older or modified build always loads, and R38 is permanent (§2, Consequences).

## Build plan

Five patches. None touches the relay's code. Each code patch starts from a test that fails today, and its criteria go into existing test files.

| # | Patch | Status |
|---|---|---|
| 48.1 | The cap, and no list a frame cannot carry | **built** |
| 48.2 | Several envelopes in flight, at most one per mailbox | planned |
| 48.3 | A group file within a budget, staged under a bound | planned |
| 48.4 | Measurements | planned |
| 48.5 | The register and the claims, before any release ships 48.1–48.3 | planned; what 48.1 makes true — R38's sentence, C9's clause, WHAT_Z_CANNOT_DO and this record — written with it |
