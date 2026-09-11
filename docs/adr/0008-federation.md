# ADR 0008 — Federation: people on different relays

**Status:** Accepted as a design, deferred as a build (2026‑09‑11) ·
**Roadmap:** 16.3 · **Decides:** the shape federation would take if Z had
more than one relay whose users talk to each other, what changes on the
wire, what each operator would learn, and why it is not built now.

## Context

Z has one relay per deployment. `SELF_HOSTING.md` says it plainly:
everyone you talk to must use the same relay. A self‑hoster's users can
message each other and nobody else; the public relay's users cannot reach
them. That is fine for a closed group and wrong for a public product in the
long run, and the question was raised as a phase‑16 choice: what would
letting mailboxes live on different relays cost, and in what?

Three facts about Z decide most of it before any option is weighed.

**A mailbox is a hash of a key, not a name at a host.** Routing ids carry no
relay; a relay holds a mailbox for whoever authenticates as that id. So the
question is not how to name people across relays but how a sender learns
*where* a mailbox is, and how that answer is authenticated.

**The relay holds nothing but RAM.** Anything that asks a relay to forward
to another relay asks it to hold envelopes for a peer that may be down,
which the RAM‑only design already does for an offline recipient and could
do for a down peer — but every hop is another operator who sees a
destination.

**Since 16.1 a sender's connection has no identity** (`adr/0007`). A sender
can open an anonymous connection to *any* relay and hand it a sealed
envelope; nothing about the sender's home relay is needed for that.

## The two shapes

**A. Client‑to‑many‑relays.** A contact's code (and each entry of a
device list) says which relay holds that device's mailbox. The sender
opens an anonymous link to that relay and sends the sealed envelope there
directly. Nothing travels between relays. A device holds one authenticated
link to its home relay and one anonymous link per relay its contacts use.

**B. Relay‑to‑relay forwarding.** The sender sends to its home relay
naming the recipient's mailbox and relay; the home relay forwards over a
server‑to‑server link; the recipient's relay delivers. Email's shape.

| | A. client to many relays | B. relay to relay |
|---|---|---|
| sender's home relay learns | nothing about the send at all — it never sees it | the destination mailbox and relay of every envelope its users send (plus the sender's address, as today) |
| recipient's relay learns | the sender's address and the destination mailbox (as today for a shared relay) | the sending relay and the destination mailbox; not the sender's address |
| new protocol surface | none between relays; a `relay` field the client must authenticate | a relay‑to‑relay protocol: identity, TLS, queueing for a down peer, abuse limits between relays |
| RAM‑only relay | unchanged | unchanged in kind; a home relay now also queues for down peers |
| push wake | unchanged (each mailbox's own relay) | unchanged |
| sockets per device | 1 + (relays in use) — for most people 1 + 1 | 2, as today |
| a hostile relay named in a contact code | can learn the sender's address and that they added this contact; cannot read or forge | the same, one hop further from the sender |
| a relay going down | its own mailboxes are unreachable, as today | its own mailboxes AND everything its users would send |

A is what sealed sender and anonymous connections were built for: the party
that delivers is the only party that sees the delivery, and the sender's own
operator is not in the path at all — which is *less* than a single shared
relay sees today. B puts an extra operator on every envelope and asks for
a protocol Z does not have. **If federation is built, it is A.**

## What A changes on the wire — a compatible extension

Nothing existing changes bytes. Three optional members, ignored by clients
that do not know them (§14), all covered by a signature the reader already
verifies or one it can:

1. **A relay statement**, signed by the *device* whose mailbox it names:
   ```
   input = utf8("z-relay-v1:") || u64be(ts) || utf8(url)
   sig   = Ed25519.sign(deviceEdSeed, input)
   JSON:   "rs": { "u": url, "t": ts, "s": b64(sig) }
   ```
   `ts` is the statement's issue time; a reader keeps the newest verified
   statement per device and ignores an older one, so a relay change cannot
   be rolled back by replaying an old code. `url` MUST be `wss://` (or a
   loopback/LAN `ws://`, as `relay_url.dart` already allows for testing).
   Signed by the device rather than the account because the device is the
   one that connects: a linked laptop on a different relay from the phone is
   a legitimate arrangement, and the account key is not on the laptop.
2. **In a contact code**: `zc1.` gains `rs` beside `ed`, `x`, `sig`; `zc2.`
   and `zc3.` carry `rs` inside each device certificate's JSON — the
   certificate is signed by the account, the statement by the device it is
   for, and a reader verifies both.
3. **In a signed device list** (§3.4): each `devs[]` entry carries its `rs`
   the same way. The list's signing input is unchanged (it covers the
   sorted device keys), which is deliberate: a relay is where a device
   *is*, not what it *is*, and the device is the authority on the first.

A device with no `rs` is on the reader's own relay — today's behaviour, so
every existing code and list reads as it does now. A device that changes
relay issues a new statement, self‑syncs it (§9), and the root includes it
in the next device list; contacts learn it the way they learn any list.

The client's `Transport` becomes a pool: the authenticated home link plus
anonymous links keyed by relay URL, opened on demand, closed when idle,
never used for anything but sealed sends. The outbox row gains the relay
URL the envelope is for. `flushOutbox` groups rows by relay.

## What A costs, and what it does not

* **Bigger codes.** A `wss://` URL and a 64‑byte signature add ~130 bytes
  to a code; a `zc3.` code is already at the edge of what scans well
  (`adr/0003`). A QR of a federated code needs one more error‑correction
  step or a smaller `name`. Measured before building, not after.
* **A new residual-risk row, when built.** A contact code is now an
  instruction to open a socket to a host the code's author chose. A
  hostile code points a device at a hostile relay, which then learns the
  device's address and that it added this contact — the same thing the
  public relay learns about everyone today, but chosen by an adversary.
  The app shows the relay host when a code names one that is not the
  user's own, before the contact is added.
* **More sockets.** One anonymous link per foreign relay in use. For a
  person with contacts on two relays that is three sockets instead of two;
  `PERFORMANCE.md`'s sizing rule ("count sockets") covers it.
* **Nothing for the relay operator.** The relay does not change: an
  anonymous connection from a device that "belongs" to another relay is
  indistinguishable from any other, which is the point.
* **The transparency log is unaffected.** Labels are account keys; a
  device's relay is not something the log commits to, and does not need to
  be — a wrong relay loses messages, it does not substitute a key.

## Decision

Federation, if built, is shape A, with the relay statement above. **It is
not built now**, because there is one public relay and the self‑hosted
relays that exist serve closed groups; the members are on the same relay
by construction, and a design whose cost is paid by every code and every
list should wait for the deployment that needs it. The `rs` member and the
`z-relay-v1:` context are reserved by this record so that nothing built in
the meantime takes them.

The trigger is concrete: a second relay whose users need to reach the
first's — a self‑hoster who wants to talk to the public relay's users, or
a second public relay. When it fires, the build is: the statement type and
its vectors (`protocol/`), the code and list members with a §14 note in
PROTOCOL.md, the transport pool, the outbox column, the relay‑host prompt
on adding a contact, its register row, and `SELF_HOSTING.md` losing its "same relay"
sentence.

## Considered and rejected

**Naming relays in routing ids** (`rid@host`). Rejected: a routing id is a
hash of a key and appears in every frame; a host in it would put the
mailbox's relay on every envelope's face for no reason a signed statement
does not serve better, and would change bytes that are frozen.

**A directory of mailbox → relay.** Rejected: a directory is a server that
knows who exists and where, which is the thing Z's design refuses to
build (`THREAT_MODEL.md`, "no directory, no key server"). The contact code
is the directory, one entry at a time, signed by its subject.

**Relay‑to‑relay (B) for the sender's address.** B hides the sender's
address from the recipient's relay at the cost of showing every
destination to the sender's own. That trades an address for a graph, and
the address is already the residual R21 accepts. Anyone who needs the
address hidden needs Tor under either shape.

## References

* PROTOCOL.md §2.4, §3.1, §3.4, §8, §12.1, §14.
* `adr/0007` (anonymous sender connection), `adr/0003` (code size).
* THREAT_MODEL.md R1, R21.
