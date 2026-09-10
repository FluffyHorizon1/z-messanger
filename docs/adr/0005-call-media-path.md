# ADR 0005 — Which way a call discloses your network address

**Status:** Proposed (2026‑09‑10) — for decision before 12.2 is built ·
**Roadmap:** 12.1, 12.2, 12.4 · **Decides:** the default media path for a
1:1 call, what leaves a device before a call is accepted, what the person is
told, and what call signalling must look like on the wire.

## Context

Phase 12 carries media outside the relay. Signalling travels over the relay
as sealed envelopes (12.1); the audio itself flows either **directly**
between the two devices or through a **TURN** server (12.4). Which of those
is the default is the decision the roadmap declined to make by assumption,
because the disclosure runs the surprising way round: *direct discloses your
public IP address to the person you are talking to; TURN discloses it to
whoever runs the TURN server instead* (`DATA_MAP.md`, "Not yet built"). For a
product whose premise is not trusting infrastructure, "your contact learns
your address" looks like the wrong default, and the roadmap flagged it as the
one to think about rather than inherit.

Two facts about Z narrow the question before any option is weighed.

**There is no such thing as a call from a stranger.** A session exists only
between two people who have each added the other; an envelope from someone
you have not added has no session to decrypt it and is dropped
(`chat_service.dart`, contact add: *"if they have not added us yet this is
dropped"*). Signal connects address‑book contacts directly and relays calls
from non‑contacts by default; WhatsApp added an opt‑in "Protect IP address in
calls" in 2023 that relays everything. Neither split maps onto Z, where every
caller is someone you added — and "someone you added" ranges from a spouse to
a person added once to be in a group. The question here is only what a
*contact* learns, and when.

**The relay must not see a call as a call.** 12.1's exit criterion is that
call setup leaks *no identifiable verb* to the relay and that *declining and
missing a call are indistinguishable* to it. Every option below is measured
against that first.

## What each path discloses, and to whom

"You relay" means your device offers only relay candidates, so media between
you and the contact goes through your TURN whatever the other side does.

| who is watching | direct | you relay | both relay, different operators |
|---|---|---|---|
| **the contact** | your public address, for the length of the call | your TURN's address; nothing of yours | their TURN's address |
| **your TURN operator** | — | your address *and the contact's*, when the call started and ended, how much flowed | your address and the contact's TURN's address, when, how much |
| **the contact's TURN operator** | — | — | the contact's address and your TURN's address |
| **your network** (ISP, Wi‑Fi owner, anyone on the path) | the contact's address, and a sustained two‑way UDP flow to it | your TURN's address, and the same flow | the same |
| **the message relay** | a few sealed envelopes in ordinary buckets — nothing it can name (12.1) | the same | the same |

Three things follow.

**No path keeps the call pair from everyone.** Direct hands it to the network
on either side — a flow between two addresses. Relayed hands it to a TURN
operator — and if that is the *same* operator as the message relay, which it
is by default, the operator can join the TURN's address pair to what the
relay already sees (which routing ids connect from which addresses) and learn
**which two accounts are in a call, when, and for how long**. That is
exactly the who‑talks‑to‑whom that sealed sender exists to deny the operator
for messages. Relaying by default through the operator's own TURN would
re‑create, for calls, the metadata the rest of the design removed — for every
user, silently.

**Direct discloses less to infrastructure and more to the contact.** The
network already sees a device online and talking to *a* relay; direct adds
the peer's address. The contact learns your public address: ISP and
city‑grade location, whether you are at home, whether you are on a VPN (a VPN
user discloses the VPN's exit, which is the point of one). An IPv6 address
without privacy extensions can be stable per device, which makes it an
identifier, not just a location.

**The one thing that is surprising is disclosure to a contact, and the
answer to a surprise is to state it, not to hand the pair to an operator
instead.** The roadmap was right that "your contact learns your IP" is the
sentence a user does not expect. It is not, for this design, the larger
disclosure.

## The part that is not a choice: nothing before accept

Whatever the default, **no address of either party leaves a device until the
callee has accepted**. WebRTC as usually deployed ships ICE candidates in the
offer: the callee's client learns the caller's address, and begins revealing
its own, before anyone has answered. In that world any contact learns where
you are by ringing you, a decline discloses as much as an answer, and a
phone nobody touched discloses too. In Z:

* **The ring carries no address.** A call id, a commitment to the media key
  material, capabilities — no candidates, and no STUN request has been made
  yet. Measured, it is a 1 024‑bucket envelope, the same as a short text.
* **Candidate gathering and exchange begin on accept, on both sides.** A
  decline sends nothing that carries an address. Whether an explicit decline
  is delivered inside the ratchet at all is 12.2's product call; it is a
  1 024‑bucket envelope either way, so the relay cannot tell it from a
  receipt, and this record does not need to settle it.
* **The reflexive‑address lookup (STUN) happens at accept, not at ring.**
  Ringing someone therefore tells the operator's STUN/TURN service nothing.
  An accepted call tells it that an address it already sees on the relay is
  setting up a call now — a residual inside what 12.1 already concedes (a
  call is distinguishable from messaging by traffic analysis whatever the
  padding does), and stated here rather than left implicit.
* **The cost is latency.** Connecting starts at accept instead of during the
  ring. The expectation is half a second to two seconds before audio; it is
  listed below as something to measure, not something to assume.

The exit criterion "declining and missing are indistinguishable to the relay"
is satisfied by this alone: neither produces anything the other does not.

## Decision (proposed)

1. **Direct after accept, by default.** ICE with server‑reflexive and relay
   candidates in the usual preference order, so media goes through TURN only
   when a direct path fails. Host (LAN) candidates are sent only in an
   obfuscated form if the stack offers one (mDNS‑style), otherwise not at all
   — a private address discloses the LAN's layout for the sake of the rare
   same‑network call, and whether that call still connects without them is
   measured below.

2. **Relay is one switch away, and your switch is enough.** A global *Always
   relay calls* (Settings → Privacy) and a per‑contact *Relay calls with this
   contact* (contact screen). Either makes this device offer **only** relay
   candidates, which forces media through *your* TURN regardless of what the
   other side does or which build it runs — hiding your address from a
   contact does not need that contact's cooperation, or their client's. When
   one side relays, the other's address is seen by that side's TURN operator
   instead of by the person; when both relay through different operators, no
   single party sees both addresses.

3. **Your TURN is yours to choose, like your relay.** Default: the project's
   TURN, run as a separate service (12.4). Self‑hosters run their own;
   `SELF_HOSTING.md` gains a section when 12.4 ships. Credentials are
   short‑lived and unlinkable — a random username and an HMAC issued over the
   existing relay session, never a stable per‑account name: the relay has no
   accounts, and the TURN must not acquire one on its behalf.

4. **The path is stated every time, before and during.** Before accepting,
   the person can see which path accepting will take and can choose the other
   for this call; the exact shape — a second accept action, a one‑time
   explanation plus a persistent glyph — is 12.2's to find, the requirement
   is not. During the call the screen says *Direct*, *Relayed via <host>* or
   *Relayed by the other side*. The first direct call a person ever makes or
   takes gets a one‑time plain explanation of what the contact will learn.
   `DATA_MAP.md`'s table gains a row for the contact and a row for a TURN
   operator; the trust‑boundary table in `THREAT_MODEL.md` gains the same.

5. **Signalling is compact JSON inside the ratchet, never SDP.** Measured
   through the same pipeline as `protocol/test/sealed_bucket_test.dart`,
   with the shapes named here:

   | message | inner bytes | bucket |
   |---|---|---|
   | ring — call id, media‑key commitment, capabilities | 167 | 1 024 |
   | decline / end — call id, reason | 108 | 1 024 |
   | one trickled candidate | 138 | 1 024 |
   | description — ufrag, password, DTLS fingerprint, 2 candidates | 269 | 4 096 |
   | description, 6 candidates (host, reflexive, relay; v4 and v6) | 452 | 4 096 |
   | description, 12 candidates | 755 | 4 096 |
   | a libwebrtc‑shaped SDP offer, audio only | 1 242 | 4 096 |
   | a libwebrtc‑shaped SDP offer, audio and video | 3 270 | **16 384** |

   Ring, decline and a trickled candidate are the size of a short text; a
   description is the size of a medium one. A raw video SDP is a
   rare‑bucket envelope that says "video call" to the relay at the moment
   the call starts, which is the identifiable verb 12.1 forbids. 12.1 keeps
   every call message within the 4 096 bucket and the ring and decline in
   1 024, and adds the real shapes to `sealed_bucket_test.dart` when they
   exist, so a codec list growing past the boundary fails a test rather than
   shipping.

## Options considered and rejected

**(a) Relay by default, direct as a per‑contact opt‑in.** The roadmap's
instinct, and the first draft of this record. Rejected because the default
TURN is the operator's: it hands the operator the call pair, joinable to
routing ids through the relay's own view of connections — the who‑talks‑
to‑whom the design removed for messages, re‑introduced for calls, by
default, for everyone — in order to protect each person from a party they
chose to add. It also costs every call quality and latency; Signal's stated
reason for not relaying by default is that it "would not work well for many
people in various parts of the world".

**(b) Direct only with verified contacts, relay otherwise.** Verification
proves the key is theirs. It says nothing about whether they should learn
where you are — an abusive former partner is a fully verified contact. The
wrong proxy; the per‑contact switch is the right tool.

**(c) Direct, with candidates in the ring** (WebRTC's usual shape). Faster
to connect, and rejected without much argument: the ring discloses, the
decline discloses, and a phone that rang in an empty room discloses.

**(d) Relay always, with no direct path at all.** The simplest interface,
the worst metadata and the worst quality, and it only holds if the TURN
operator is honest about not recording pairs — "a feature that quietly needs
the relay to be honest" is on this repository's review lens as a no.

**(e) Double relay by default — each side through its own TURN.** No single
party sees the pair if the operators differ; but by default both sides use
the same project TURN, so it degenerates to (a) at twice the cost. It is
available as the effect of both sides' switches, and it is not a default.

## What must be measured before this is accepted

1. Accept‑to‑audio latency with gathering gated on accept, against
   candidates gathered during the ring, on real devices across NAT types —
   12.2's exit already demands a call across NAT on real hardware, so the
   same runs answer this.
2. Direct connection success without host candidates, and with obfuscated
   ones if the stack offers them — the same‑network and hairpin cases.
3. The signalling sizes above, re‑measured with the real shapes and pinned
   in `sealed_bucket_test.dart`.
4. What a TURN server actually writes down at its default log level. Before
   any document claims what the operator "learns", read the log.

## Consequences

* **Two new rows in the trust‑boundary table.** *Your contact* gains "learn
  your public address during a call you accepted, unless you relay"; *A
  network eavesdropper* gains "see whom you are in a direct call with, by
  address"; a new row, *A TURN operator (when you relay)*, gets the second
  column of the table above. `DATA_MAP.md`'s "Not yet built" paragraph is
  resolved by this record when it is accepted.
* **A residual, stated.** Accepting a call makes a STUN/TURN request to a
  server the operator runs, at a time the operator can see. Within 12.1's
  concession; not something the padding hides.
* **The relay is untouched**, as 12.1 requires. TURN is a separate service
  with its own credentials, and a self‑hoster who runs the relay but not a
  TURN falls back to the project's — which is a choice the settings screen
  has to show, not make.
* **The design relies on ICE doing what the switches say.** "Only relay
  candidates" must mean no host or reflexive candidate is ever sent, on
  every platform the app builds for; that is a test per platform, not a
  configuration flag read once.
* **Group calls remain anti‑scope.** Nothing here makes a mixer acceptable.

## References

* `docs/ROADMAP_8_15.md` — Phase 12, items 12.1, 12.2, 12.4 and the exit.
* `docs/DATA_MAP.md` — "Not yet built"; `docs/THREAT_MODEL.md` — trust
  boundaries.
* `docs/adr/0004-hybrid-device-list-distribution.md`, addendum, and
  `protocol/test/sealed_bucket_test.dart` — the bucket boundaries the
  signalling table depends on.
* TechCrunch, *PSA: Your chat and call apps may leak your IP address*
  (3 November 2023) — Signal's contact / non‑contact split and "Always relay
  calls", WhatsApp's "Protect IP address in calls", and the quoted cost of
  relaying by default.
