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
| Message flood | 600 sends fired instantly from one client | excess is `rate_limited` (token bucket: 80/s, burst 240; acknowledgements are exempt, so a device draining a backlog is never rate-limited out of emptying it); the connection is **not** killed |
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
`RATE_PER_SEC` (80) · `RATE_BURST` (240).

## One more shape, in its own file

A device that stops reading mid-flush is the abuse case this harness cannot
express, because it needs the socket paused rather than the frames refused:
`flush_backpressure.test.js` pauses a client's TCP socket with a 19 MB
backlog waiting and watches the relay's own buffered bytes. Before the paged
flush the relay held 15.1 MB for that one reader; now it holds 320 KB and
finishes the delivery when the reader resumes (`docs/PERFORMANCE.md`, "What
a reconnect costs the relay").

## Not covered here

Real-network latency and packet-loss behaviour, which wants a deployed
environment rather than an in-process harness and is tracked separately.
Multi-instance behaviour is covered by `ha.test.js`, `queue_caps.test.js`,
`full_store.test.js`, `drain.test.js` and `expiry.test.js`, each against a
real `redis-server`.
