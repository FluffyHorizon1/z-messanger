# ADR 0007 — Sealed envelopes are sent on a connection that never authenticated

**Status:** Accepted (2026‑09‑11) · **Roadmap:** 16.1 · **Decides:** which
connection a sealed envelope leaves on, what the relay may accept before
authentication, and what the "operator cannot tell who is talking to whom"
claim means from now on.

## Context

Sealed sender (PROTOCOL.md §8) removes the sender from the envelope: the
outer frame names only the destination mailbox, and the relay stores and
delivers `zs1.` payloads with no `from`. `THREAT_MODEL.md`, `WHITEPAPER.md`
§3 and `WHAT_Z_CANNOT_DO.md` all said, on that basis, that the relay cannot
tell who sent an envelope.

Reading the relay for phase 16's metadata study showed the claim was true
of the relay's *memory* and false of its *operator*. `send` required an
authenticated connection (§12.1 said so: before `ready`, `send` is answered
with `not_authed`), and the client's one connection was authenticated as
the device — so every sealed envelope arrived on a socket whose identity
the relay process held in `state.rid`, one line away from the `send`
handler. Nothing stored named a sender; nothing running needed to be told.
An operator who added `log(state.rid, to)` had the social graph sealed
sender exists to withhold. Signal's sealed sender is delivered
*unauthenticated* for exactly this reason; Z's was not, and no document
said so.

## Decision

A sealed envelope is sent on a connection that has never authenticated.

- **Relay (§12.1).** A `send` whose payload begins with `zs1.` is accepted
  on a connection that has not authenticated, rate‑limited like any other
  frame, and acknowledged as usual; the connection owns no mailbox and
  receives nothing. A `send` of any other payload, `recv`, and
  `push-register` still need the identity they would be stamped with or act
  on. `/metrics` counts sealed envelopes that arrived on anonymous
  connections (`z_sealed_unattributable_total`); `/health` reports `sockets`
  beside `connections`.
- **Client.** `Transport` holds two links: the authenticated one, which
  owns the mailbox and carries receiving, acks, push registration and the
  few unsealed legacy sends; and an anonymous one, which sees the relay's
  challenge, does not answer it, and carries every sealed envelope. **A
  sealed envelope is never sent on the authenticated link**: when the
  anonymous link is down the send fails and the outbox retries when it is
  back. The alternative — fall back to the link that works — would leak the
  sender precisely in the moments an operator could arrange.
- **Compatibility.** A relaxation of the relay's behaviour and a compatible
  extension under §14: a client that authenticates before sending behaves
  as it always did; an old relay refuses the anonymous send with
  `not_authed`, which the client treats as connection trouble and retries —
  so a new client against an old relay does not send at all rather than
  send attributably. Roll the relay out first.

## What is still true, and what is not

The relay is not told who sent a sealed envelope: not by the envelope, and
not by the connection. It still sees the **network address** each socket
comes from, and a device's anonymous sender socket and its authenticated
mailbox socket come from the same one, open together and stay up together.
On a home or office connection an address is as good as a name; behind
carrier‑grade NAT it is shared with thousands. That is R21, and it is the
honest replacement for a claim that used to be stronger than the code.

## Considered and rejected

**Anonymous credentials for sending** (a blind token from the relay, or a
per‑recipient delivery token as Signal's sealed sender uses for abuse
control). Rejected for now: the relay's abuse control is per‑connection rate
limiting, which needs no identity; adding tokens would add a protocol and a
secret to protect for a property — "this anonymous sender is a real user" —
that per‑connection limits already give. Revisit if spam through anonymous
connections becomes real.

**Tor or a VPN inside the app.** The only thing that removes the address.
Rejected as scope: R1 and R21 both say "front it with Tor"; building that
into the client is a different product's work and a different threat
model's promise.

**Leave it and rewrite the claim.** Honest, cheaper, and worse: the fix is
one relay clause and one more socket, and the difference between "one log
line away" and "an address" is the difference between a graph and a guess.

**One socket, sends before auth.** Not possible: a socket that authenticates
is attributable for everything on it, before and after.

## Consequences

- Every device costs the relay two sockets, and the relay's tail latency
  follows the socket count: measured at ~2 000 envelopes a second, 1 000
  sockets give a p99 of ~45 ms and 2 000 sockets ~160 ms (`PERFORMANCE.md`,
  "Two sockets per device"). `SELF_HOSTING.md` sizes by sockets.
- `THREAT_MODEL.md`: the trust table's relay row, the "core guarantee"
  paragraph and the metadata paragraph now say connection and address; R21
  is new. `WHITEPAPER.md` §3 says what was true before and after.
  `AUDIT_SCOPE.md` C4 cites the relay test for the anonymous send and the
  app test that counts, from the relay's metrics, that every sealed envelope
  a conversation produces arrived unattributable.
- The finding itself is recorded as roadmap revision 36, with the rule it
  teaches: **a claim about what a party cannot learn has to be checked
  against every channel that party has, not the one the mechanism was
  designed for.** The envelope was the mechanism; the socket was the
  channel.

## References

* PROTOCOL.md §8 (sealed sender), §12.1 (anonymous connections).
* THREAT_MODEL.md R1, R21; WHITEPAPER.md §3.
* `server/test/sealed.test.js`, `app/test/anonymous_sender_test.dart`,
  `server/bench/latency.js`.
* Signal, "Sealed sender" (2018) — unidentified delivery over an
  unauthenticated request, with delivery tokens for abuse control.
