# ADR 0024 — An invite bound to its secret, an add that asks first, and requests that cannot be replayed

**Status:** **Proposed** (2026‑10‑09) — built (phase 40, unreleased). Adds
PROTOCOL §20.8 and a paragraph to §8.1; extends ADR 0009, 0011, 0012 and
0020. R23 and R25 are updated in place.
**Decides:** how the invite secret is bound into the connect ceremony — the
wire change, its version and what each client does with the other's invite;
that nothing of a ceremony leaves the joiner's device before its person says
yes; what a contact request's signed time is held to, and how many requests
are held; and what a block means for groups and invites.

## Context

Five findings of the 3 October 2026 analysis, each reproduced against real
clients over a real relay before anything here was written: criteria 1–5 of
`invite_binding_test.dart`, and criterion 7 of `connect_relay_test.dart`,
each failed on `e751133`.

**P1‑9: the relay, or the CDN in front of it, could sit in the middle of any
invite whose digits were not compared.** The invite secret derived the two
mailboxes and nothing else. The frames are plaintext JSON, the commitments
were hashes of what they committed to, and the channel key was HKDF of the
two ephemerals alone — so whoever carries the frames could replace each
side's ephemeral with one of its own, commit and reveal under identities of
its own, and hold a channel key for each leg. The reproduction did exactly
that from the tap position, knowing nothing but what the relay sees: both
sides reached the digits, each holding the relay's key under the name it
expected, and only the two strings differed. ADR 0009 and R25 had said a
skipped comparison is trust on first use "over whatever carried the link"; it
was also trust in the relay, and in Cloudflare, which terminates its TLS.

**Opening an invite link posted the joiner's contact code before anyone had
said yes.** A tapped link opened the invite and stepped it at once; the next
round sent message 4, the joiner's own code, sealed to whoever answered —
before the person had looked at anything.

**A contact request's `ts` was signed and never read**, so a request the
person had declined came back whenever the relay — which keeps every
envelope it carries for as long as it likes — handed its copy over again,
and a request two years old was as good as a fresh one. **Pending requests
were uncapped**: anyone holding a person's code could mint identities
without end and fill the list.

**A group's list made a blocked person a contact.** The list's unknown
members are adopted so the receiver can decrypt from them, and adoption did
not ask about the block list: the blocked person became a contact and could
write directly. (Listed in the analysis as unverified; reproduced here.)

## Decision

### 1. Version 2: the secret is in the keys

An invite of **version 2** binds its secret into everything the ceremony
derives (PROTOCOL §20.8):

```
inviteKey  = HKDF(secret, salt = "", info = "z-connect-invite-v2", 32)
commit     = HMAC-SHA256(inviteKey, "z-connect-commit-v2:" || eph
                                    || u16be(len(code)) || code || name)
channelKey = HKDF(dh, salt = inviteKey, info = "z-connect-channel-v2", 32)
digits     = §20.4 under "z-connect-sas-v2"
mailboxes  = §20.5 under "z-connect-relay-v2:" || role
```

The four frames have the members and the lengths they had. What changes is
that a channel key now needs the invite as well as the ephemerals. A party
that substitutes an ephemeral without the invite holds a key neither side
has: the reveal it is sent does not open, and the reveal it seals does not
open either. So the acceptor stops at message 3 — **before message 4, before
it has revealed itself to anyone** — and the inviter, whose reveal went out
sealed under a key only a holder of the invite can derive, takes no message 4
the relay can make. No bundle is exchanged, and the relay opens nothing it carried
(`connect_relay_test.dart` 7, `invite_binding_test.dart` 1,
`connect_test.dart` 13).

The commitments are keyed for a second reason. A version‑1 commitment is a
hash of an ephemeral, a contact code and a name; once message 3 has shown
the ephemeral, anyone with the frames and a list of candidate codes could
test which of them had committed. Keyed by the invite, a commitment says
nothing to anyone without it (`connect_test.dart` 14).

**Binding the KDF, not sealing the frames.** Both were open. Sealing every
frame under a key from the secret also works, and would hide the ephemerals
too — which are random and say nothing. Binding three derivations changes no
frame: the members and lengths stay what they were, so the relay cannot tell
the versions apart by size (`connect_test.dart` 12 compares all four frames
of both versions for the same two people), and the secret sits in the one
place its absence was the flaw — the channel key — rather than in a wrapper
around a ceremony that would still be unbound inside it.

**The version is in the invite, and nowhere the relay writes.** Both
renderings of a version‑2 invite start with `9` — `9ABCD-EFGHI-JKLMN-OP`,
`https://www.zmessengers.com/i#9ABCD…` — which is not in base32's
alphabet. A version read from the frames could be rewritten by the party the
version exists to keep out; a version in the link is set by the inviter and
travels outside the relay, beside the secret. `9`, because of the four
characters base32 lacks it is the one that reads as nothing else (`0` is
taken for `O`, `1` for `I`, `8` for `B`).

**The secret stays ten bytes.** Eighty bits, against an attacker who must
guess it within the invite's 24 hours, each guess costing an HKDF and an
Ed25519 key generation to check against a mailbox id — or an HMAC against a
commitment and a candidate code. A guess that succeeds after the ceremony
can open what the two reveals said, and cannot put anyone in the middle of
it. Sixteen bytes would make the code read down a phone line twenty‑seven
characters long.

### 2. Old clients and new, both ways

* **A client of this version mints version 2, and nothing else.** There is no
  fallback to version 1: ADR 0009 refused a compatibility window for a
  ceremony because the party that would choose to fall back is the one in
  the middle, and that holds here.
* **A client from before this, handed a version‑2 invite, refuses it.** Its
  parser takes base32 and separators and nothing else, so `9` is "not a
  connect code": pasted, the CONNECT tab says *"that is not a Z invite"*;
  tapped, the link is ignored and the app opens on its last screen. Nothing
  is sent, and the inviter's invite waits until it is discarded or its 24
  hours run out. The version notice (ADR 0014) is what tells that client to
  update, where the relay sets `Z_LATEST_VERSION` (`invite_binding_test.dart`
  7; `connect_test.dart` 15 holds every rendering of 200 invites to a
  verbatim copy of the old parser).
* **A client of this version, handed a version‑1 invite** — made by an older
  client — runs it as version 1, on version 1's mailboxes, exactly as it
  always ran (`invite_binding_test.dart` 8). Its comparison screen says,
  above the digits, *"This invite was made by an older version of Z. Until
  you compare the digits, even the relay could be in the middle"*
  (`connectOldInvite`, 9). The same relay that cannot complete a version‑2
  invite still completes this one, and the tests pin it as the residual it
  is (`invite_binding_test.dart` 6, `connect_relay_test.dart` 8).
* **A pending invite written before this** has no version in its record,
  reads back as version 1 and finishes as version 1. The two versions never
  share a mailbox, so neither can be made to answer, or wait on, the other
  (`connect_test.dart` 16).

### 3. The joiner's yes comes before anything leaves

An invite that arrives by tapping a link is **held**: recorded and put in
front of the person, with what connecting sends and to whom — *"Connecting
sends your contact code to whoever made this invite, and then the two of you
compare eight digits. If you were not expecting an invite, discard it."* —
and nothing of the ceremony leaves the device, not even a connection to the
relay, until they press **Connect**. Typing or pasting an invite and pressing
Open is the yes already. A held invite stays held through a restart
(`invite_binding_test.dart` 2, 10, 11; `deep_link_test.dart` 5).

The yes comes before message 2 because message 2 is the first thing that
leaves, and it already commits to the joiner's identity. Who invited them
cannot be shown before then — it arrives in message 3, which the inviter
sends only once message 2 has come — so the comparison screen remains where
a person who did not mean to reach whoever answered stops (ADR 0012).

### 4. A request's signed time is read, and the list is bounded

A request is refused, in silence, if its signed `ts` is more than **30 days**
behind this device's clock or more than **one day** ahead of it — 30 days
being ten times the relay's 72‑hour queue, so an add made on a plane still
arrives — or if it is **no newer than the last request taken in from the same
requester**. That mark is kept for a request that is pending and for one the
person declined, so the copy the relay holds cannot put a declined request
back in front of them; a NEW request from the same person, made later, is
shown, because declining is not blocking. Accepting or blocking drops the
mark (an accepted requester is a contact, whose requests fold; a blocked one
is refused before any mark is read), deleting the contact erases it, and a
mark older than 30 days goes, since the age rule refuses its request anyway
(`invite_binding_test.dart` 3, 12). PROTOCOL §8.1 states the rule.

At most **100** requests are pending. When one would be the 101st, the oldest
the person has **not seen** goes — seen meaning it was on the Requests screen
— and if every one has been seen, the newcomer goes. A flood of fresh
identities can push out only what nobody has looked at
(`invite_binding_test.dart` 4, 13). One cap for every request, whichever
door it came through — a code scanned or pasted, or a handle (§21.7 caps
handle requests at the same 100): what it bounds is one person's attention
and one table. Two caps would let a flood through one door leave the other's
untouched, but would also let the two together hold two hundred; the seen
rule is what protects the requests that matter, and it does not care about
doors. `ChatService.maxPendingRequests` is the one number.

### 5. A block holds against groups and invites

Someone this device has blocked who is named in a group's list is a member
like any other — the list is the group's, and a list of mine that dropped them
would take them out for everyone — but is **not taken in**: kept as an entry,
as a member whose contact was deleted is, never made a contact. My group
messages skip them, theirs find no session here, and the block stands
(`invite_binding_test.dart` 5). That holds for a group joined from a link
(ADR 0020): its list is applied by the same rule.

An invite whose ceremony reveals someone this device has blocked is
**refused** on that side, the moment the reveal opens: the joiner before its
own reveal goes, so a blocked inviter never learns who opened its invite
(15); the inviter at message 4, so nobody is added — not as a contact, and
not to the group a link was for (14). The inviter reveals first, so its own
identity has already gone to whoever answered; what the block withholds is
everything after.

## Rejected

* **Sealing the frames instead of binding the derivations** — section 1.
* **A version‑1 invite on request, for a friend with an old app.** It is the
  fallback ADR 0009 refused, offered as a button; an old app is told to
  update instead.
* **The version in the frames** — the relay writes them.
* **A longer secret** — section 1.
* **The joiner's yes after message 3**, once it could say who invited them:
  message 2 has left by then, committing to the joiner.
* **A cap per door** — section 4.
* **Dropping a blocked member from my copy of a group's list** — a list I
  then issued would remove them for everyone; blocking is not removing.

## Consequences

* **Wire.** Version 2 is a new ceremony beside the old one, not a member
  added to it: new context strings, the marker, and a new vector file,
  `vectors/connect/invite_v2.json`, which records every value §20.8 changes
  and, from the same inputs, what version 1 would have computed instead.
  `connect.json`, `mailboxes.json` and `group.json` are byte‑identical
  (`vectors_test.dart`). The relay changes nothing.
* **Invariants.** The relay is no longer a party a version‑2 invite trusts:
  it can drop the frames, as it can drop anything, and it cannot complete or
  open them. It learns less than before, not more — a commitment no longer
  confirms a guess. Sealed sender, the ratchet, keys at rest: untouched.
  Forward secrecy of the ceremony is the ephemerals', as before; the invite
  key adds a secret, never replaces one.
* **R23** stays: the invite is a bearer token until it is spent, and is now
  the ONLY way into a version‑2 ceremony. **R25** now says what a skipped
  comparison trusts for each version: whoever held the link, for version 2;
  that and the relay and its CDN, for version 1.
* **Storage.** One sealed vault cell, `requests_meta`: each requester's last
  request time (pending, or declined within 30 days) and which pending
  requests have been seen. It is not in a backup.

## Residuals

* **Whoever holds the link is the person you are trusting until the digits
  are compared.** Version 2 takes the relay out; it cannot take out the
  bearer — the first to open the link completes the ceremony as themselves —
  and a party that holds the link AND carries the frames (whatever carried
  the link, in league with the relay, or one that is both) can still run
  both legs, with two different strings. The digits catch both (R23, R25).
* A version‑1 invite keeps every property it had, including P1‑9. It exists
  only where an older client made one.
* A request you accepted, from someone you have since deleted, can be handed
  over again inside its 30 days and shows once more: accepting leaves no
  mark — the requester is then a contact, whose requests fold — and deleting
  a contact leaves nothing of them. Marks are not in a backup, so after a
  restore the same holds for requests you declined.
* A flood of fresh identities can push out requests you have not looked at.
* A block is by routing id, as ADR 0011's always was: a blocked person
  opening an invite from another of their devices is not recognised by it,
  and the admin of a group you share with a blocked person still sends them
  your bundle in its lists — they cannot reach you with it.

## Evidence

`app/test/invite_binding_test.dart` (15), `protocol/test/connect_test.dart`
12–16, `protocol/test/connect_relay_test.dart` 7–9, `vectors_test.dart`
(`connect/invite_v2.json` replayed, the three version‑1 files unchanged),
`deep_link_test.dart` 5. `AUDIT_SCOPE.md` C32 and C37.
