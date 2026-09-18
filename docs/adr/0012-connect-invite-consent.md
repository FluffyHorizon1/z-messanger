# ADR 0012 — Saying who took the invite, and not calling them a request

**Status:** **Accepted** (2026‑09‑18) — built. Small by design: most of the
consent gate ADR 0009 wanted already existed.
**Decides:** what the connect completion screen tells the inviter about *who*
accepted, and how a connect‑added contact relates to ADR 0011's request state.

## Context

ADR 0009 records a residual it asked to have stated, not buried: *an invite
link is a bearer token until it is spent — whoever sees it first can complete
the ceremony and be added under the name the recipient expected.* Its answer is
the eight‑digit safety number, but that catches a **key** substitution; it does
not, on its own, make the inviter stop and ask whether the person who answered
is the person they meant to reach. A user who skips the call (the "we have not
compared yet" path) adds whoever accepted, unverified, with nothing on screen
naming the bearer‑token risk.

Two things narrowed this to a small change:

1. **The completion screen already gates the add behind an explicit choice.**
   It is not auto‑add: the user must pick "They match" (→ verified), "We have
   not compared yet" (→ unverified), or "They do not match" (→ add nobody, spend
   the invite), with the peer's name shown. The functional decline already
   exists. What was missing was the bearer‑token *framing* — every string on the
   screen spoke of key‑MITM ("someone is relaying between you"), none of "this
   may not be who you invited."
2. **ADR 0011 made `addContactFromCode` mark a new contact `requested` and send
   a request.** The connect ceremony adds through that same call, so a
   connect‑added contact briefly showed "Requested" until the peer's own
   request folded — an artefact, since the ceremony already added both sides.

## Decision

1. **State who accepted, and the bearer‑token caveat, above the digits.** A line
   names the person who actually took the invite and says whoever had the link
   could have — so if this is not who you meant to reach, stop below instead of
   adding them (`connectWhoAccepted`, en + es). The three actions are unchanged;
   "They do not match" is the stop for both a bad number and a wrong person.
2. **The connect path adds without the request state.** `addContactFromCode`
   gains `requested` (default true — a scan/paste is a one‑sided add and keeps
   ADR 0011's behaviour). The CONNECT ceremony passes `requested: false`: no
   "Requested" limbo, and no request sent (both sides are already added by the
   ceremony, so it would only fold).

## Rejected

- **A new ceremony message or wire change.** The reveal already carries the
  identity; consent is a local decision. Nothing on the wire moves.
- **Renaming "They do not match" to a generic "Stop".** Kept, so the
  safety‑number meaning stays exact; the new line points a wrong‑person user to
  it rather than overloading the label.
- **Blocking on the invite path.** A spent invite is one‑time and the peer
  holds no way to reach you unless you add them, so there is nothing for a block
  to bite on here (unlike a reusable `zc1.` code, which keeps Block under 0011).

## Consequences

- Zero‑knowledge, sealed sender, ratchet, wire protocol: **unchanged**. This is
  app wording plus one local flag.
- `THREAT_MODEL.md`'s bearer‑token residual is **reduced**: the risk is now
  stated at the moment it matters, which ADR 0009 asked for.
- `verification` is untouched — a confirmed comparison still sets `verified_sn`;
  "we have not compared yet" still lands unverified and says so.
- Tested in `connect_invite_test.dart` (criterion 4: a connect‑added contact is
  not left showing as a pending request, on both the verified and the
  unverified path; criterion 6: the new string is in both locales with a
  description).
