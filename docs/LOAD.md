# Relay load & abuse results

Roadmap Phase 0.3. The relay is a RAM-only, zero-knowledge broker, so the
questions that matter under load are: does it **stay up**, does its **memory
stay bounded**, does it keep serving **`/health`**, and can **one abusive socket
harm another**? The executable evidence is `server/test/load.test.js` — run it
with `npm test` (it runs in the standard suite). This file records what it
drives and the representative numbers from a local run.

## What is exercised

| Case | What it does | Assertion |
|------|--------------|-----------|
| Concurrent swarm | 60 clients connect + authenticate at once | all reach `ready`; `/health.connections ≥ 60`; RSS growth bounded |
| Oversize envelope | a payload past `MAX_ENVELOPE_BYTES` (1 MB) | rejected with `too_large`; **the socket keeps working** (a normal send right after is delivered) |
| Oversize raw frame | a 2 MB raw WebSocket frame (past `maxPayload`) | only the offender's socket is closed; a bystander still receives; `/health` still 200 |
| Message flood | 600 sends fired instantly from one client | excess is `rate_limited` (token bucket: 80/s, burst 240; an acknowledgement that frees an envelope is exempt, so a device draining a backlog is never rate-limited out of emptying it — one that frees nothing is charged, `receipts.test.js` criterion 4); the connection is **not** killed |
| Reconnect storm | 100 connect → auth → close cycles | relay stays up; `/health` 200; RSS growth bounded |
| Queue overflow | 180 envelopes to an **offline** recipient (cap lowered to 100 for the test) | the first 100 are queued and stay queued; the other 80 are each refused with `queue_full`; memory does not grow with the flood, and the flood erases nothing |

## Representative results (local run)

```
concurrentClients:        60      connectionsAtPeak:   60
rssDeltaAfterSwarm:        6.6 MB
rateLimitedOfFlood:        360     (of 600 fired)
reconnectCycles:          100      rssDeltaAfterStorm:  2.5 MB
queueCap:                 100      queueLenAfter180Sends: 100
refusedOf180:              80
```

## Reading the numbers

- **Memory is bounded.** 60 simultaneous clients cost ~6.6 MB; a 100-cycle
  reconnect storm ~2.5 MB. Nothing accumulates per-connection after close.
- **Abuse is absorbed, not fatal.** A flood is shed by the rate limiter (360 of
  600 rejected) with the socket left open; an oversized frame closes only the
  offender; an oversized envelope is a clean app-level rejection that leaves the
  socket usable.
- **Queues can't exhaust RAM, and a flood can't erase a mailbox.** A
  per-recipient queue holds at its cap (100 here; `MAX_QUEUE_MSGS_PER_USER` =
  5000 in production, and independently `MAX_QUEUE_BYTES_PER_USER`, 64 MB)
  and refuses the envelope that would cross it — `error{queue_full}` to the
  sender, who keeps it and retries — rather than evicting the oldest. It
  used to evict: a sender who had been told `sent` lost the envelope
  without anyone knowing, so anyone with a routing id could clear what was
  queued for it by sending 64 MB of junk. Now the junk fills the queue,
  everything after it is refused loudly, and the queue clears when its owner
  next connects (junk fails decryption and is acked away like anything
  else). The same holds across two instances sharing a Redis, where the
  byte cap is a counter settled atomically with every push and removal
  (`queue_caps.test.js`); before, Redis mode enforced only the count.
- **A full store heals rather than deadlocks.** In Redis mode the store
  itself has a limit (`maxmemory`, `noeviction`). `full_store.test.js`
  fills a 4 MB store through the relay and checks what happens while it
  is full: a send is refused within milliseconds as `store_full` with its
  id (it used to time out, 20 s per envelope); a login still succeeds and
  still drains its mailbox (it used to fail at the presence write, so
  nobody could log in — including the one person who could have made
  room); and once the full mailbox is drained, sends succeed again and
  the heartbeat repairs presence.

## Production knobs (env)

`MAX_ENVELOPE_BYTES` (1 MB) · `MAX_QUEUE_MSGS_PER_USER` (5000) ·
`MAX_QUEUE_BYTES_PER_USER` (64 MB) · `QUEUE_TTL_HOURS` (72) ·
`RATE_PER_SEC` (80) · `RATE_BURST` (240) · `FLUSH_PAGE` (64) ·
`FLUSH_HIGH_WATER_BYTES` (1 MiB) · `ID_SLOTS` (8).

## One more shape, in its own file

A device that stops reading mid-flush is the abuse case this harness cannot
express, because it needs the socket paused rather than the frames refused:
`flush_backpressure.test.js` pauses a client's TCP socket with a backlog
waiting and watches the relay's own buffered bytes. Before the paged flush
the relay held 15.1 MB of a 19 MB backlog for that one reader; now it holds
64 KB, and against envelopes at the cap — where a page counted in entries
was still 4.8 MB — it holds 977 KB, finishing the delivery when the reader
resumes (`docs/PERFORMANCE.md`, "What a reconnect costs the relay").

Two more live beside it. `receipts.test.js` covers what an acknowledgement
costs: ten that match nothing read 1 436 bytes from the store, where the
fallback they replace read the acknowledger's whole mailbox each time.
`parity.test.js` runs one scripted scenario against the RAM coordinator and
the Redis one and compares the frames the clients receive, so the mode
production runs and the mode most of the suite exercises cannot drift apart
without a test noticing.

## Multi-instance, sustained (local run)

Roadmap Phase 25.1. The table above and `bench/latency.js` are one process,
one coordinator, every delivery local. Production is two instances sharing one
store (`render.ha.yaml`), where a delivery often has to cross from the instance
the sender is on to the one the recipient is on, over the store's pub/sub.
`server/bench/ha_load.js` drives that: N in-process relay instances against one
`redis-server` it starts itself, C devices (two sockets each, as the app holds
them) spread across the instances, every sender talking to a recipient on a
**different** instance for T seconds, a share of sends going to mailboxes
nobody holds open (so the store carries a growing backlog at the same time),
every live envelope acknowledged as it lands.

These numbers are **local, two cores, loopback, in-process instances sharing
one redis-server** — the load generator and every instance share one machine's
two cores and (by default) one Node event loop, so they are pessimistic on
latency and say nothing about throughput scaling across real cores. All of them
were taken on 2026-10-02, on one VM, from this code; the end of this section
says why the date matters. 200 devices, 1 024-bucket sealed envelopes (1 450
chars), each row one 60-second run, the creation gate raised so admission does
not distort a throughput comparison (its own effect is the next section):

```
NEW_MAILBOX_PER_MIN=100000 node bench/ha_load.js --instances N --clients 200 --seconds 60 --rate 10
```

At **~1 990 envelopes/s offered**, where the rig is not the bottleneck (the one
process holding the generator and every instance used about half a core):

| instances | delivered/s | p50 | p95 | p99 | max | /health p99 | redis peak | lost | dup |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1 795 | 3.1 ms | 8.7 | 19.4 | 50 | 6.0 ms | 22.6 MB | 0 | 0 |
| 2 | 1 795 | 3.8 ms | 11.2 | 33.5 | 79 | 5.9 ms | 22.7 MB | 0 | 0 |
| 3 | 1 795 | 3.8 ms | 12.1 | 34.1 | 75 | 6.4 ms | 22.8 MB | 0 | 0 |

The same command with `--rate 20` offers **~3 960/s**, which on this VM is the
edge of what one event loop carries for the generator and the relays together:
the generator fell behind its own schedule, the process used 0.86–0.96 of a
core, and the tail is mostly the rig's own:

| instances | offered/s | delivered/s | p50 | p95 | p99 | max | /health p99 | lost | dup |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 3 884 | 3 498 | 7.1 ms | 36.0 | 81.7 | 113 | 29.0 ms | 0 | 0 |
| 2 | 3 675 | 3 308 | 25.2 ms | 112 | 179 | 473 | 77.9 ms | 0 | 0 |
| 3 | 3 743 | 3 370 | 20.3 ms | 87.5 | 144 | 361 | 81.4 ms | 0 | 0 |

In every two- and three-instance run **every delivery crossed instances**
(`z_cross_instance_total` equalled the deliveries and `z_delivered_live_total`
was zero), which is what the rig is for. And one run with half the sends going
to offline mailboxes, for queue growth:

```
NEW_MAILBOX_PER_MIN=100000 node bench/ha_load.js --instances 2 --clients 200 --seconds 60 --rate 20 --offline 0.5
```

delivered 1 947/s live (p99 88 ms) while **116 671 envelopes piled up for 100
offline mailboxes**, taking the store from 1.31 to **210.15 MiB** of
`used_memory` — **1 877 bytes** per queued 1 024-bucket envelope, the same to the
byte as the same run on the earlier VM, and the per-envelope store cost
`CAPACITY.md` reckons with. `/health` answered every sample of every run, and
nothing was lost or duplicated in any.

**What this does show.** Cross-instance delivery works and keeps up: nothing
lost, nothing duplicated, `/health` never failed, with one instance or three.
At ~2 000/s the hop costs about 0.7 ms at the median and 14 ms at the 99th
percentile (3.1 → 3.8 ms and 19.4 → 33.5 ms from one instance to two), and a
third instance adds nothing more. The store's memory tracks the backlog at the
per-envelope cost `CAPACITY.md` uses.

**What it does not show.** Throughput *scaling*: the instances share one VM's
two cores and, in-process, one event loop, so a second instance added a hop and
no capacity. What a second instance buys — more cores, redundancy across
machines, a redeploy that drops nothing — needs separate machines behind a real
load balancer, which only infrastructure can measure. Nor are these a host's
capacity. On this VM, three runs of the one-instance rate-20 load gave a p99 of
**81.7** and **66.8 ms** for this code and **54.6 ms** for the relay as it was
before this change (Release 3.9.4, `50d9786`, driven by this bench with the
same command) — one code's runs spread further apart than the two versions
differ — and on the VM this work began on (2026-10-01) the same load measured
**21.6 ms**. At this load the host and the moment set the tail, not the code.
Pushed harder, one instance delivered **5 528/s** of 6 137/s offered at a p99
of 192 ms, losing nothing:

```
NEW_MAILBOX_PER_MIN=100000 node bench/ha_load.js --instances 1 --clients 200 --seconds 20 --rate 50
```

which is this rig's limit rather than the relay's. `--fork` runs each instance
as its own process, the closer shape to a deployment with cores to spare.

A fast smoke test (`server/test/ha_load.test.js`) runs the bench for three
seconds on two instances inside `npm test`, so the rig cannot rot; it skips
without `redis-server`, as `ha.test.js` does. The bench kills the
`redis-server` and any forked instance it started on every way out — an error,
SIGINT, SIGTERM — and prints the store's pid first so the smoke test can reap
it even if the bench itself is killed outright.

## The new-mailbox flood gate across instances (25.3)

`NewMailboxGate` rate-limits mailbox **creation** — the act a flood needs and
nobody drains (R22). It is a per-instance token bucket, so N instances admit
**N × `NEW_MAILBOX_PER_MIN`** new mailboxes a minute between them. Measured on a
cold start of 200 devices — 220 first contacts, 200 live peers and 20 offline
mailboxes — at the default allowance of 120, each run started just after the
store's minute rolled over so that it sits inside one window (an unaligned run
measures where in the minute it happened to start, which is how two earlier
runs here once looked like a match):

```
node bench/ha_load.js --instances 2 --clients 200 --seconds 20 --align-minute
NEW_MAILBOX_SHARED=on node bench/ha_load.js --instances 2 --clients 200 --seconds 20 --align-minute
node bench/ha_load.js --instances 1 --clients 200 --seconds 20 --align-minute
```

| gate | sends refused in 20 s | delivered/s |
|---|---:|---:|
| per instance, two instances (the default) | **0** | 899 |
| shared, two instances | **9 000** | 540 |
| one instance | **7 268** | 627 |

Two instances with the gate per instance admitted the whole burst — 110 first
contacts each, under each one's 120 — where one instance could not. Shared, the
two admitted 120 between them and refused the rest for the remainder of the
window. The bench does not retry a refusal; each device just sends its next
envelope on its own timer, so the count is every send by the devices whose first
contact did not fit (the app instead pauses its outbox for a minute). The shared
figure is not the single instance's because the two gates have different shapes:
the shared one is a fixed window — the allowance at once, then nothing until the
minute rolls over, and up to twice the allowance across a boundary — while the
per-instance one is a bucket refilling two a second at 120/min, which let some
forty more through within the 20 s. Every one of those refusals reached
`z_new_mailbox_refused_total` and none reached `z_store_full_total` (in Redis
mode they used to count under both).

**The decision: the shared gate exists, and it is off unless the operator turns
it on (`NEW_MAILBOX_SHARED=on`).** Unset, every instance keeps its own bucket
exactly as it did before, so nothing changes on the next deploy of the public
relay. The case each way, measured:

- **What N× buys an attacker against the byte caps: nothing in the store's
  worst case.** The store has one `maxmemory` and each mailbox one
  `MAX_QUEUE_BYTES_PER_USER` whatever N is, and a store is filled fastest by a
  few large mailboxes — `maxmemory ÷ MAX_QUEUE_BYTES_PER_USER`, sixteen on
  `render.ha.yaml` — far under even one instance's 120 a minute. What the
  creation rate alone bounds is the many-small-mailbox variant, where N× is the
  whole effect: in the run below, the flood created **10** mailboxes in its
  window with sharing on and **144** with it off.
- **What sharing costs.** A gate everybody shares is a switch whoever fills it
  holds (R32): with the window spent, every instance refuses every first
  contact. And `seen` — what makes ordinary traffic free — is each process's own
  memory, so an instance that restarts or is newly added pays first contact
  again for every recipient it re-contacts, against a window that may already
  be spent. Two instances, 100 devices, a flood of 20/s from 5 s in, instance 0
  replaced 15 s in and its 50 devices reconnected to the new one:

```
node bench/ha_load.js --instances 2 --clients 100 --seconds 40 --flood 20 --flood-after 5 --restart-after 15 --align-minute
NEW_MAILBOX_SHARED=on node bench/ha_load.js --instances 2 --clients 100 --seconds 40 --flood 20 --flood-after 5 --restart-after 15 --align-minute
```

| after the restart | per instance | shared |
|---|---:|---:|
| sends refused into existing mailboxes (mail waiting) | 0 | 0 |
| sends refused to online contacts (nothing waiting) | 0 | **5 600** |
| mailboxes the flood created in the run | 144 | 10 |

Into a mailbox that already holds mail nothing is created, so neither mode
refuses it, and the shared window does not even charge it
(`shared_admission.test.js` 5). An online contact who keeps up has no mailbox,
though, so to the restarted instance each was a first contact; with the flood
holding the shared window, every one of the 5 600 sends its devices made to
their contacts was refused for the rest of the minute, where per instance the
new instance had a full bucket of its own. Nothing the relay may know can tell
those recipients from a flood's targets: a shared record of who was written to
would put routing ids in the store, and exempting a recipient who has a presence
record would let anyone who authenticates a throwaway key create mailboxes
uncharged.

So the per-instance gate stays the default: its N× loosens a rate the byte caps
already bound, and in exchange a flood that lands on one instance cannot hold
everybody's first contacts. An operator who wants the relay-wide rate turns
sharing on knowing the trade, and sets `NEW_MAILBOX_PER_MIN` to N × the
per-instance value to keep the total it had (240 for `render.ha.yaml`'s two).
With it on, the counter is one hash of two integers for the whole relay — a
count of creations in the store's current minute, never a routing id — read by
the store's own clock (instances whose clocks disagree used to count into
different windows, N× again), handed back when a push creates nothing, and
consulted only on first contact; when it cannot be consulted, each instance
falls back to its own bucket and counts it in
`z_new_mailbox_shared_fallback_total`. `server/test/shared_admission.test.js`
pins all of it: 10 admitted between two instances with sharing on against 20
with it off, at an allowance of 10.

## Not covered here

Real-network latency and packet-loss behaviour, which wants a deployed
environment rather than an in-process harness and is tracked separately — as is
throughput scaling across real cores and machines, which the multi-instance
runs above exercise the *behaviour* of but, on one two-core box, cannot
measure the *scaling* of. Per-unit capacity costs (bytes per queued envelope,
per connection, per published list, and the formulas that turn them into a box
size) are in `docs/CAPACITY.md`. Multi-instance behaviour is also covered by
`ha.test.js`, `queue_caps.test.js`, `full_store.test.js`, `drain.test.js`,
`expiry.test.js`, `receipts.test.js`, `parity.test.js` and
`shared_admission.test.js`, each against a real `redis-server`.
