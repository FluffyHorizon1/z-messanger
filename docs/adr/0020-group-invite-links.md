# ADR 0020 — Group invite links: a connect invite that ends in a group, not a new kind of link

**Status:** **Accepted** 2026‑10‑02 — accepted by Finnian on 2026‑09‑30 with its one
contradiction resolved (below), and built in 23.3. The build departs from the text in
four places, each backed by a test that fails without it and each for Finnian to
confirm; they, and what the build settled within the text, are under "As built".
**Decides:** how someone who is not yet a contact of anyone in a group can be brought
into it, without a directory, a shared key, a reusable token, or a link that says
which group it is for.

## Context

A member can only be added to a group by an admin who already has them as a contact —
the invite carries every member's signature‑verified bundle, and that is what lets Bob
and Carol, who never met, open a session to each other (§11). So "join my group" today
is two steps done by hand: exchange codes with the admin (scan, paste, or a CONNECT
invite), then the admin adds you. The roadmap's 23.3 asks for the one‑step version, and
names its constraint: **reuse the connect ceremony** (ADR 0009 / 0012) rather than
invent a link.

What the connect ceremony already gives, and what any group link must not lose:
- **One‑time, 24 hours**, enforced by the inviter's client; a link is a bearer token
  until it is spent, and 0012 puts that caveat on the screen.
- **A commitment round and an eight‑digit string** bound to both identities, so a
  remote add can end *verified* over a voice call.
- **Nothing about the invite in the link but the code**; the relay sees a rendezvous
  mailbox and sealed frames, not who is meeting whom.
- **Consent on both sides**: the inviter minted the link; the joiner chose to open it
  and completed the round; the resulting contact is not marked "requested".

## Decision

**A group invite link IS a connect invite, with the group remembered on the inviter's
side only.** The admin mints an ordinary one‑time connect invite and stores `gid` next
to it locally — never in the link, never in the rendezvous frames. When the ceremony
completes and the joiner is a verified‑or‑not contact exactly as after any CONNECT, the
admin's app does what the admin would have done by hand: `addGroupMembers(gid, [rid])`.
The joiner receives a normal `ginvite` and a banner — *"X added you to 'Y' from the
link you opened"* — and has Leave, as always.

- **What a bystander with the link learns:** that it is a Z connect invite. Not the group,
  not its name, not its size. A spent link is dead; a link the admin revokes before it is
  spent is dead. The 24‑hour rule is unchanged.
- **What the relay learns:** one connect ceremony (already accepted as a residual in
  0009's terms) followed, after a human‑scale delay, by a group fan‑out to N+1 mailboxes
  — the shape R18 already describes. Nothing new is stored or metered.
- **Consent.** Opening the link and completing the round *is* the joiner's consent to be
  added to whatever group the inviter had in mind — the same trust as accepting a friend's
  "I'll add you to the group" in person. The joiner's screen says, before the digits,
  that this invite is to a group as well as to a contact, so the choice is informed; the
  group's *name* is shown only after the sealed channel exists, in the invite itself. A
  joiner who dislikes the group leaves; nothing has been sent to them but the list.
- **One link, one joiner.** A reusable link would be a bearer token that anyone who ever
  saw it could replay forever — the thing 0012 warns about, made permanent. The admin
  who wants to invite five people mints five links (one tap each, or "make 5"). This is
  the trade: a group link is not a public URL, and Z should not pretend otherwise.
- **Who may mint:** anyone who may add a member — the admin today; admins per ADR 0019 if
  that is accepted. A link minted by someone who is demoted before it is spent adds
  nobody: the add is refused at every member exactly as any non‑admin's would be.

## Rejected

- **A dedicated group link (`zg…`) carrying the gid and the group name.** Reveals the
  group to anyone who sees the link, and once such a link exists people will post it —
  turning a bearer token into a directory entry. The connect invite already solves the
  hard part (a verified remote add); the group is one local field away.
- **Reusable / multi‑use links, with or without a join counter.** A replayable bearer
  token. Every "expires after N uses" scheme still admits the first N holders, whoever
  they are, and the inviter cannot tell which.
- **A relay‑side join endpoint or lobby.** A server that holds group membership — the
  relay would learn who is in a group by construction. Out on the first invariant.
- **A join request the admin approves in‑app ("knock").** Better consent UX for the
  *admin*, and it is 0011's contact request with a gid attached — so it can be added
  later as a second mode without changing this one. Not in scope: the one‑time link
  already carries the admin's consent, and the knock is a separate design.

## Decided (2026‑09‑30): one sealed bit

The Decision says both that "the joiner's screen says, before the digits, that this
invite is to a group" and that nothing about the group is in the rendezvous frames. Both
cannot hold: a client knows nothing it is not sent. **Decided: one sealed bit in the
round.** An optional member inside the inviter's sealed reveal — message 3's `blob`
(PROTOCOL §20.3) — says that a group is attached: no gid, no name, nothing else. The link
carries nothing; the relay sees the same three members of message 3 it always did, the
bit sealed inside one of them, and — measured, below — the same length. The joiner's
screen says, above the eight digits, that the invite also brings them into a group and
that they will see which one once connected.

## As built (23.3)

### The property, and how it holds for every joiner

**No joiner's identity bundle reaches a group's members unless the joiner's own client
told its person, before the digits, that the invite was to a group, and the person then
went ahead — confirmed the comparison or skipped it.** A bundle reaches the members only
inside a `ginvite` from an admin who holds it, so the property is about when the
inviter's device adds the joiner. It adds them only when all of this holds:

1. the joiner's message 4 repeated the bit — its client knows what the bit means, so it
   can have said so;
2. the joiner's **go‑ahead** for THIS ceremony has arrived: `gjoin`, a new inner kind
   that names no group, which the joiner's client sends over the pairwise session from
   the two buttons that go ahead ("they match", "we have not compared yet") on a
   comparison screen that showed the notice above the digits, with "Also join the
   group" on — and from nowhere else — carrying `go` 1 and the ceremony's **go‑ahead
   tag**, derived from the channel key, which only the two ends of that ceremony can
   compute (PROTOCOL §20.6);
3. at that moment, the link's 24 hours have not run out and the inviter's device may
   still add members to the group (`mayIssueGroupList(gid, '')`, ADR 0019).

Then it adds them by the ordinary path, `addGroupMembers` — no new add code.

* **A joiner on this build who goes ahead** is told before the digits and joins when the
  go‑ahead lands, whichever of the two people answered first (`group_invite_link_test`
  1, 2, 8).
* **A joiner on this build who stops** — "they do not match", a ceremony that aborts, or
  never answering — sends no go‑ahead. The inviter's wait ends with the link's 24 hours,
  and the group says so on the inviter's screen (7).
* **A joiner who goes ahead as a contact only** — "Also join the group" turned off —
  sends the answer with `go` 0: the inviter's wait ends at once, and its group says the
  joiner chose not to join (13).
* **A go‑ahead given on another link** — an earlier one between the same two people,
  which the inviter stopped — carries that ceremony's tag, and is read and ignored: it
  adds nobody through a later link the joiner stopped, or never answered (12). Until
  2026‑10‑03 a go‑ahead named no ceremony, and one given on an earlier link added the
  joiner through a later link they had stopped, or never answered: the first review's
  P0.
* **Stopping a ceremony touches nothing else.** The identity a stopped ceremony revealed
  is one nobody verified, and anyone holding a person's contact code — which is handed
  out — can make a ceremony reveal it. So stopping one ends that invite and nothing more;
  an answer owed from another link keeps its own tag, which no other link's wait
  accepts (12, 21). On 2026‑10‑03, for a few hours, stopping a group link also ended any
  answer the joiner still owed the identity it revealed — a way for anyone with that
  code to cancel an answer the real inviter was owed.
* **A joiner on a build from before this ADR** cannot read the bit, so its message 4 does
  not repeat it. The inviter's device knows at the digits, says so on its comparison
  screen with the group named, and after it goes ahead says it in the group: *"Jay is
  your contact, but was not added to this group: their app is too old to join from a
  link. Add them by hand."* It never waits for a go‑ahead (6). This is the only kind of
  joiner whose client cannot have told its person, and its message 4 is what says so.
* **A link thief** is a joiner like any other: told, on their own screen, and joining as
  themselves, once. The inviter's group says who joined from its link; every other
  member's group says only that the membership changed, and lists the new member by
  the name they revealed — R39.
* **A machine in the middle** that completes both legs holds both channel keys and can
  set or clear the bit on either leg. Clearing it on the joiner's leg means no notice and
  no go‑ahead: nobody is added. Setting it shows a notice the inviter never meant, and the
  go‑ahead finds nothing waiting. What it cannot do is send a go‑ahead as the joiner: the
  go‑ahead travels in the pairwise session, which only the holder of the joiner's keys
  can speak in. The only identity it can bring into the group is its own — the identity
  the digits exist to catch. Nor can it force the two legs onto one channel key: an
  ephemeral of small order, which would make every leg's key, and its tag, the same
  public constant, is refused by both sides (PROTOCOL §20.3, `connect_test` 11).

### Departures from the text accepted on 2026‑09‑30

Four places where the build does not do what was accepted, each because the accepted
version fails a test the departure passes. Each is for Finnian to confirm or overrule.

1. **"Wire: none" became one optional sealed member each way, and one inner kind that
   names no group.** Message 3's reveal carries `grp` (the bit) and message 4's repeats it;
   the answer is `gjoin`, carrying the ceremony's go‑ahead tag and the answer itself
   (`t`, `go`; PROTOCOL §20.3, §20.6, §6.2). A client that implements the bit writes
   it in **every** reveal, `0` as readily as `1`: connect frames are attributed sends
   with the JSON as their payload, not sealed envelopes padded to a bucket (§20.5), so
   the relay sees each frame's exact length, and a member written only for groups would
   have been a group invite announcing itself by eight bytes. Measured at the relay, one
   inviter's message 3 is 654 bytes as a group link and 654 as an ordinary invite
   (`connect_relay_test` 6; 650 and 650 in `group_invite_link_test` 9, for a shorter
   name); a client from before the bit sends 642 for the same identity (`connect_test`
   8) — twelve bytes that tell the relay the build at most, since names vary by more.
   The go‑ahead is a sealed envelope of 854 bytes in the 1 024‑byte bucket, a
   read receipt's (`group_invite_link_test` 9). **`group_invite_link_test` 6
   fails without the repetition** — the inviter cannot tell a client that cannot ask its
   person from one whose person has not answered yet — **and 9 fails if the bit is
   written only when set.**
2. **The joiner's consent is their go‑ahead, not the completed round.** The text has
   "opening the link and completing the round *is* the joiner's consent". The round
   completes with nobody pressing anything (`connect_invite_test` 7): message 4 goes out
   before the joiner's person has seen a thing, so completing it can prove only that the
   client could show the notice, never that the person read it and went on. **7 fails
   if the add follows the completed round** — a joiner who says the digits do not match
   is added — and so does 1's "nobody is added before the joiner goes ahead".
3. **The add waits for the go‑ahead and is judged when the go‑ahead arrives.** The text
   adds the joiner "when the ceremony completes". The build adds them when the go‑ahead
   lands — within the link's 24 hours from minting, and only if the inviter's device may
   still add members then. **4 fails without the bound** (a go‑ahead a day late adds) and
   **5 without the second check** (an admin demoted after going ahead with a joiner, and
   before that joiner's go‑ahead, adds them).
4. **A joiner whose app predates this ADR is not added from a link.** The text assumed
   every joiner's screen could say the invite was to a group. One that cannot is a
   contact only, and the inviter is told on its comparison screen and in the group (6).

### Decided while building, within the text

* **Either person may answer first.** A go‑ahead sent before the inviter has added the
  joiner arrives from a stranger and is dropped, like any envelope from someone not in
  the contact list. So the inviter's device, once it is waiting, speaks first (a
  `hello`), and the joiner's client answers every `hello` from that inviter with every
  answer it still owes them. 8 has the joiner answer first, its first go‑ahead dropped
  for certain.
* **A go‑ahead names its ceremony.** The tag is HKDF‑SHA256 of the ceremony's channel
  key, with a salt of 32 zero bytes and `z-connect-gjoin-v1` as its info, 16 bytes — a
  key of its own rather than the sealing key used as an HMAC key, as it was for a few
  hours on 2026‑10‑03: both ends compute it from the ceremony itself, nobody else can,
  and nothing about it is stored anywhere but the two devices' sealed records.
* **Each link is its own.** Both sides keep their records per link, keyed by the tag:
  two links between the same two people are two waits and two answers, neither
  replacing nor resetting the other — a go‑ahead already read stays read — and both
  add (24). When the group arrives, the joiner's answer is settled if it is the only
  one owed to that inviter; with several, the list cannot say which link it fulfils,
  so each is said, on each `hello`, until its own window ends — harmless, since an
  inviter that has added the joiner through one ignores its tag thereafter.
* **Joining is the joiner's choice at the go‑ahead.** "Also join the group" sits beside
  the buttons it changes, on unless the joiner turns it off; off, the comparison is
  answered as for any CONNECT, the joiner is a contact only, and the inviter is told
  so at once rather than a day later as a link that ran out (13).
* **Someone already a contact.** A connect ceremony refuses a peer already in the
  contact list (ADR 0012), and still does for an ordinary invite (20). On a group link
  that refusal is not applied: the identity the ceremony revealed is the one held (a
  routing id is the hash of the identity key), so the contact is used as it is — not
  replaced, and not marked as compared from afar — and the answer travels over the
  sessions that already exist. Held includes another device of the contact's account:
  one that their account's signed device list, as this device holds it, names, under
  the account key the digits covered — so a contact who opens the link on their laptop
  joins as the contact they are, their answer read from that device, and nobody holds a
  second contact for them (22). By the list, and not by the account key alone, because a
  device dropped from a list keeps the certificate its account once signed. Before
  2026‑10‑03 a joiner who had once scanned the inviter could never join from their link,
  while the inviter was told a day later that the link had run out (14); and a contact
  on another of their devices was added again, as a second contact whose answer nobody
  read. An answer interrupted after it added the contact — the app killed before the
  go‑ahead went — finishes when the person answers again, instead of meeting "already in
  your contacts" from its own add (18); it counts the record as its own only if it is
  the very record it added, so a contact deleted and added back another way in between
  is used as held, and not ticked by it (23).
* **How long each side waits.** The inviter's wait ends with the link's 24 hours from
  minting — the link's lifetime is the whole of its authority. The joiner's ends after 48
  hours from its answer, because its clock starts later than the inviter's and a phone
  that was off has the rest of the relay's queue to catch up in. The first new group
  from that inviter inside the joiner's window is the one the link promised.
* **What each screen says.** The joiner's banner is `addedFromLinkBy` — *"Owen added you
  to 'Crew' from the link you opened"* — and the inviter's group says *"Jay joined from
  your invite link"* rather than "You added Jay", which the admin did not just do. A
  joiner the link will not add is said in the inviter's group with the reason: their app
  is too old, their go‑ahead did not arrive within the link's 24 hours, they chose to
  be a contact only, the inviter stopped waiting, or this device may no longer add
  members. The inviter's comparison screen says, before it goes ahead, what going ahead
  will do — the link's own 24 hours first among the reasons it may add nobody (2).
* **The wait can be seen and stopped.** Going ahead finishes the invite, so the wait it
  starts is listed on the CONNECT tab — who, and for which group, on the inviter's
  screen only — with "Stop waiting": the link then adds nobody, the joiner stays a
  contact, and the group says so (17). It stops a go‑ahead already read and not yet
  acted on; once the add itself has begun it is too late, and the screen says so
  rather than nothing (25).
* **Each panel is its own.** The comparison panels are keyed by their invite, so with two
  group links open, answering one leaves the other's "Also join the group" as its person
  set it (19); until 2026‑10‑03 the remaining panel inherited the answered one's state.
* **Where the records live.** Both sides' records are one sealed vault cell
  (`group_links`), never leave the device, are not in a backup, and go when the contact
  is deleted: a go‑ahead from a joiner the inviter has deleted arrives from a stranger
  and is dropped, and a joiner who has deleted the inviter answers the inviter's
  `hello` with nothing (11). Deleting a contact who is already in the group is ADR
  0019's case — they stay a member — and is no business of the link's. The inviter's
  `gid` lives beside the invite in the invite store, sealed; the run, and so every
  frame, knows only the bit.
* **Where the button is.** "Invite to group by link" is on the group info screen for
  anyone `mayIssueGroupList(gid, '')` allows. The link is shown, shared and revoked on
  the CONNECT tab like any invite; a group link's card names its group, on the inviter's
  screen only. Revoking is Discard.
* **Linked devices.** Both records are per device. The device that made the link waits
  for the go‑ahead and adds — adding needs no root (ADR 0019), so a laptop can — and
  the device that opened it owes the go‑ahead and sends it; a go‑ahead or a `hello`
  that reaches another device of either account finds no record there and does
  nothing. So the device that made the link has to read the go‑ahead before the
  link's 24 hours are up. The joiner joins as an account: the list names them by the
  device whose code the ceremony revealed, every member maps that to the person (ADR
  0019: a member is an account), and the joiner's other devices take the group as any
  member's do, said as "added you" rather than "from the link you opened". The
  inviter's laptop writes no member entry for itself, and names itself in `owner` and
  `admins` by its own routing id (ADR 0019, PROTOCOL §11.1) — the id the joiner
  holds the inviter under — so a joiner who connected with the laptop holds the
  inviter as one member, with the group's roles as every member holds them, from the
  first list. Lists the inviter issues from their phone reach that joiner once it
  holds the inviter's device list, which the laptop hands on, signed by the account
  (`group_invite_link_test` 10).
* **A malformed bit aborts.** A `grp` that is not `0` or `1` is a malformed reveal, as a
  malformed name is; a message 4 that repeats a different bit from the one sent means the
  two sides disagree about what the ceremony is, and aborts it too (`connect_test` 9).

### What the relay learns, measured

As the Decision says — one ceremony, then a fan‑out — plus, for a group link, a few
envelopes of the 1 024‑byte bucket between the two people before the group's fan‑out to
N+1 mailboxes, which is the larger signal and the one R18 already records. The inviter
sends one `hello` when it starts waiting. The joiner's answer goes once, twice or three
times, by the order of things, measured (`group_invite_link_test` 16): once when the
inviter went ahead first and the joiner is the pair's designated initiator; twice when
only one of those holds; three times when the joiner answered first and the inviter
opens the session — once as the joiner answers, before the inviter is waiting, and once
for each of the inviter's two `hello`s, the opening one and the waiting one. The first
of them to arrive while the inviter waits is the one that counts; one that arrives
before the inviter holds the joiner is dropped as a stranger's. Until the group arrives
— or for 48 hours from a contact‑only answer — each further `hello` from the inviter is
answered once more. Message 3's length does not depend on the bit.

## Consequences

- **Wire:** the optional member `grp` in both sealed reveals of the connect ceremony
  (PROTOCOL §20.3) and a new inner kind, `gjoin` — naming no group; the ceremony's
  go‑ahead tag `t` and the answer `go` (§6.2, §20.6) — compatible evolution under §14: a client
  that does not know them neither writes nor reads them. `ginvite` is unchanged.
  Vectors: `connect/group.json` (a group‑flagged ceremony, both plaintexts and its
  go‑ahead tag recorded) and a `gjoin` entry appended to `v1/inner_messages.json`;
  `connect/connect.json` and `connect/mailboxes.json` are byte‑identical, and both are
  now in the freeze test's list.
- **App:** the invite store's records gain an optional local `gid`; "Invite to group by
  link" on the group info screen mints one; the CONNECT tab labels a pending group link
  with its group and revokes it with Discard; the joiner's comparison screen says, above
  the digits, that the invite also brings them into a group; the inviter's names the
  group and says whether whoever answered can join it; the joiner's has "Also join the
  group"; going ahead starts the inviter's wait or sends the joiner's answer; the
  inviter adds the joiner by `addGroupMembers` when a go‑ahead for its ceremony
  arrives; the CONNECT tab lists the inviter's waits, each with "Stop waiting". New
  `SystemKind`s, local text only: `addedFromLinkBy` for the joiner, and `linkJoined`,
  `linkTooOld`, `linkExpired`, `linkRefused`, `linkDeclined`, `linkCancelled` for the
  inviter.
- **Tests:** `app/test/group_invite_link_test.dart` (25, through the relay and a
  recording tap — the criteria of the text plus the joiner's go‑ahead, the old client, a
  joiner who stops, the measured sizes and traffic, linked devices, deletion, a go‑ahead
  bound to its ceremony, the contact‑only answer, someone already a contact, a go‑ahead
  read before a restart, the inviter's waits, an answer cut short by a killed app, each
  panel's own switch, an ordinary invite between contacts still refused, a stopped
  ceremony touching no other answer, a contact on another of their devices, a record
  that took the added one's place, two links with one person, and "Stop waiting" after
  the go‑ahead); `protocol/test/connect_test.dart` 8–11 (the bit read and repeated, the
  same length set and clear, old readers on either side unaffected, a malformed or
  contradicted bit aborting, the commitment not covering it, the go‑ahead tag derived
  from the channel key, the same at both ends of one ceremony and different for every
  other, and an ephemeral of small order refused on either side);
  `protocol/test/connect_relay_test.dart` 6 (the same through the real relay, both runs
  through storage); `vectors_test.dart` (the group vector replayed, an old reader
  included); `system_text_test.dart` (the new kinds render).
- **THREAT_MODEL:** R39 — a group link is a bearer token for one group membership; what a
  link thief can do (join that group once, visibly, as themselves) and the residuals: a
  joiner on an old build is a contact only, a joiner who stops is a contact of the
  inviter's at most, and the envelopes a join adds between the two.
