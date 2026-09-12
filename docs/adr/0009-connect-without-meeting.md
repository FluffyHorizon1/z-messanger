# ADR 0009 — Adding a contact you cannot stand next to

**Status:** **Proposed** 2026‑09‑12 — the ceremony is built (17.1); the UI,
the landing page and the trust-model consequence are not ·
**Roadmap:** Phase 17 · **Decides:** how two people who cannot meet add each
other, what a confirmed comparison is then worth, and what is deliberately
left out.

## Context

Z has no directory, no accounts and no phone numbers, so adding a contact is
the exchange of a ~370‑byte `zc1.` code. In person that rides a QR, and **the
QR is the verification**: the channel is your eyes, and nothing else is
needed.

Remotely there were three tabs — MY CODE, PASTE, SCAN — and one path: copy
your code, send it over a channel you trust, they paste it. Four things are
wrong with that, in rising order of seriousness.

1. **It is one‑directional.** A adds B only when B's code reaches A. Both
   people copy, send and paste. Two round trips of admin before a first
   message.
2. **It hands out a permanent identifier.** The `zc1.` code is your account
   identity for ever. Pasted into WhatsApp it lands in someone's cloud
   backup, their screenshots and their forwards, and it stays usable by
   anyone who ever sees it.
3. **The security advice is unfollowable.** "A channel you trust" is exactly
   what someone who has only WhatsApp does not have. The honest reading of
   the current flow is trust‑on‑first‑use over a channel an attacker may
   control.
4. **Nothing ends verified.** The contact lands at the assurance floor and
   the safety‑number comparison is a separate, later, mostly‑skipped step.

The finding that shaped this decision is that **the ceremony already
existed**. Device pairing (§10) is a one‑time short code, a rendezvous
mailbox derived from it, an ephemeral X25519 exchange and a string two humans
compare. It needs no relay change — a routing id is `SHA‑256(ed25519 pub)`, so
a keypair derived from a shared secret is a mailbox *both* sides can hold —
and it is already store‑and‑forward, because rendezvous mailboxes queue like
any others. So the work was never "design a remote add"; it was "point the
existing ceremony at a different payload, and fix the one thing that is sound
for a code on a screen in your hand and not sound for a code sent over
WhatsApp".

## Decision

A fourth way to add someone: a **one‑time invite**, and a ceremony with its
own context strings beside the pairing ones (`z-connect-*`). Four messages,
two commitments, an eight‑digit string bound to the identities being
exchanged, and both people added by one run.

```
1. inviter  → rendezvous : H("z-connect-commit-v1:" || ephI || len||code || name)
2. acceptor → rendezvous : ephA , H("z-connect-commit-v1:" || ephA || len||code || name)
3. inviter  → rendezvous : ephI , seal(channelKey, its contact code + name)
4. acceptor → rendezvous : seal(channelKey, its contact code + name)

channelKey = HKDF(dh, salt = 0×32, info = "z-connect-channel-v1")
sas        = HKDF(dh, salt = ephLo || ephHi,
                  info = "z-connect-sas-v1" || edLo || pqcLo || edHi || pqcHi) → 8 digits
```

Three properties, each a deliberate difference from §10.

**Both sides commit before either reveals.** §10's responder chose its
ephemeral *after* seeing the initiator's, and the two ephemerals were the
whole input to a six‑digit string — about 2²⁰ tries to hit a value already
read aloud. For device linking that is a corner (the code is shown on one of
your screens and typed into another); for this it is the main threat, because
the code travels over the channel we are assuming may be hostile. Here the
inviter commits first, and the acceptor commits to its own ephemeral *and its
own claimed identity* while holding only a hash — so neither can steer the
string, and a machine‑in‑the‑middle gets exactly one blind guess at eight
digits, with a wrong guess showing as a mismatch.

**The string is bound to the identities, not only to the channel.** It covers
both account Ed25519 keys and both post‑quantum commitments (§18.2), sorted
by account key so it is a property of the pair rather than of who invited
whom. A matching string therefore says what a safety‑number comparison says —
*the identity I have stored is the identity you hold*. That is what makes the
next paragraph legitimate rather than wishful.

**A confirmed comparison may mark the contact verified.** Today the in‑person
QR is the only path that ends verified. With an identity‑bound string, the
remote path can end verified too, over a voice call, without anyone reading
sixty digits: *say these eight digits to each other on a call where you
recognise their voice.* **This is the prize, and it is the part of this ADR
that is a trust‑model change rather than an engineering one** — it is the
decision to record explicitly, because it is the one a reviewer should argue
with.

If the comparison is skipped — no call available, "later" tapped — the
contact is added, usable, and **explicitly unverified**, in the words the app
already uses for that state. Nothing here may imply an unconfirmed remote add
is as good as a scan; the three existing assurance states carry it and this
adds no fourth.

**Invite lifetime: one‑time, 24 hours**, enforced by the client rather than
the relay (24 h sits well inside the mailbox's 72 h `QUEUE_TTL_HOURS`, so
expiry is a rule the inviter keeps, not a property of the store).

## Rejected

**A compatibility window for the pairing ceremony's weakness** (offer both
shapes, fall back when the peer is old). Named here because it is the pattern
v3 identity used and it is the wrong pattern for a ceremony: an attacker at
the rendezvous can *force* the fallback, so the weakness survives the whole
window for everyone rather than only for people running old builds. A
downgrade an attacker chooses is not a compatibility window. §10.1 took the
fail‑closed route instead — disjoint mailboxes, detect the old peer, never
transact with it.

**Hardening the string without a commitment round** (widen it, run it through
a memory‑hard KDF). No wire change, and old‑versus‑new is also fail‑closed
because the numbers simply differ. Rejected because it raises the *cost* of
grinding rather than removing it, and cost‑based defences erode; worse, the
failure it produces is a string *mismatch*, which is the alarm that means
"someone is in the middle" — the wrong alarm for a version skew.

**Putting the code in the link's query or path.** It goes in the
**fragment**, which no browser sends to a server, so `zmessengers.com` never
receives an invite even when the link is opened in a browser. A query
parameter would put every invite in the relay host's request logs.

**A directory, or anything that lets the relay answer "who is this person".**
Out of scope permanently, not for this phase.

## Consequences

- New context strings, a new vectors directory (`vectors/connect/`), and a
  new §20. Nothing existing computes anything differently, and there is no
  compatibility surface at all: nobody runs this ceremony today, so an older
  client never reaches those mailboxes and never sees those messages.
- Three residual‑register rows (see `THREAT_MODEL.md`): the relay sees a pair
  of ephemeral mailboxes exchange a few envelopes and go quiet; **an invite
  link is a bearer token until it is spent**, so whoever sees it first can
  complete the ceremony under the name the recipient expected — which is
  precisely the risk the comparison exists to catch, and it should be stated
  rather than buried; and a skipped comparison is trust‑on‑first‑use over
  whatever carried the link.
- `contacts.verified_sn` gains a second way to be set. Everything that reads
  it — the safety‑number prompt, the assurance badge, `_classifyVerification`
  — must treat both the same, or the badge starts meaning two things.
- Introduction by a mutually‑verified contact (17.7) and a deliberately
  separate "public invite" (17.8) are follow‑ons this decision does not
  settle. The public invite in particular must never share a button with a
  one‑time invite, because the two have opposite properties.

## Status note

17.1 — the ceremony, its seven exit criteria and its vectors — is built and
shipped in this patch. What this ADR is still *proposing* is the trust‑model
half: that a confirmed eight‑digit comparison sets `verified_sn`. The
ceremony is useful without that (it adds both people in one step over a
channel that need not be trusted); the verified state is what makes it worth
building, and it is a decision for whoever owns the trust model rather than
for whoever writes the ceremony. This record moves to **Accepted** with
"what was built rather than what was planned" when 17.3 lands, in the pattern
0006 set.
