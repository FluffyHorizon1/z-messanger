# ADR 0020 — Group invite links: a connect invite that ends in a group, not a new kind of link

**Status:** **Proposed** (2026‑09‑20) — awaiting Finnian's decision before it is built (23.3).
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

## Decision (proposed)

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

## Consequences (if accepted)

- **Wire:** none. Connect frames are unchanged; `ginvite` is unchanged. The joiner's
  banner is a new `SystemKind` (`addedFromLinkBy`), local text only.
- **App:** the invite store gains an optional local `gid`; a "Invite to group by link"
  action on the group info screen (admin only) mints and shares a connect invite tagged
  with it; the CONNECT completion path, on success, adds the new contact to that group;
  the joiner's CONNECT screen states that the invite is to a group; the invite list shows
  which pending links are group links and lets the admin revoke them.
- **Tests (exit criteria):** a link minted for a group adds its joiner to that group and
  to nobody else's; a spent link cannot add a second joiner; a revoked link adds nobody;
  a link minted by a since‑demoted admin adds nobody (with 0019); the joiner's banner
  names who and which group; the link bytes contain no gid or name (a byte‑level
  assertion on the encoded invite); the joiner is not marked `requested`.
- **THREAT_MODEL:** extend the connect‑invite bearer‑token row with the group case: what
  a link thief can do is join one group once, visibly, as themselves.
