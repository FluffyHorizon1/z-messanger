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
| Message flood | 600 sends fired instantly from one client | excess is `rate_limited` (token bucket: 80/s, burst 240); the connection is **not** killed |
| Reconnect storm | 100 connect → auth → close cycles | relay stays up; `/health` 200; RSS growth bounded |
| Queue overflow | 180 envelopes to an **offline** recipient (cap lowered to 100 for the test) | the offline queue is capped at 100 (oldest dropped); memory does not grow with the flood |

## Representative results (local run)

```
concurrentClients:        60      connectionsAtPeak:   60
rssDeltaAfterSwarm:        6.6 MB
rateLimitedOfFlood:        360     (of 600 fired)
reconnectCycles:          100      rssDeltaAfterStorm:  2.5 MB
queueCap:                 100      queueLenAfter180Sends: 100
```

## Reading the numbers

- **Memory is bounded.** 60 simultaneous clients cost ~6.6 MB; a 100-cycle
  reconnect storm ~2.5 MB. Nothing accumulates per-connection after close.
- **Abuse is absorbed, not fatal.** A flood is shed by the rate limiter (360 of
  600 rejected) with the socket left open; an oversized frame closes only the
  offender; an oversized envelope is a clean app-level rejection that leaves the
  socket usable.
- **Queues can't exhaust RAM.** The per-recipient ring buffer holds at the cap
  (100 here; `MAX_QUEUE_MSGS_PER_USER` = 5000 in production) and drops oldest,
  bounded independently by `MAX_QUEUE_BYTES_PER_USER` (64 MB).

## Production knobs (env)

`MAX_ENVELOPE_BYTES` (1 MB) · `MAX_QUEUE_MSGS_PER_USER` (5000) ·
`MAX_QUEUE_BYTES_PER_USER` (64 MB) · `QUEUE_TTL_HOURS` (72) ·
`RATE_PER_SEC` (80) · `RATE_BURST` (240).

## Not covered here

Multi-instance / Redis-coordinated load (roadmap Phase 4.4) and real-network
latency/packet-loss behaviour. These want a deployed environment rather than an
in-process harness and are tracked separately.
