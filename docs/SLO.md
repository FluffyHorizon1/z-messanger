# Service levels, and the alarms behind them

Roadmap Phase 25.4. Objectives an operator can actually measure from what the
services already expose — the relay's `/metrics` (`z_*`) and `/health`, the KT
log's and the witness's `/health`, and the store's own exporter — and, for
each, the alarm that tells you it is being missed. The alarm expressions are in
`server/alerts.example.yml`; the steps to take when one fires are in
`docs/SELF_HOSTING.md` ("When an alert fires"). These are **example** targets
and rules: pick numbers that match your users' expectations, and wire the rules
into your own Prometheus — nothing here reaches Render or any live system on its
own.

## What is measurable here, and what is not

The relay deliberately keeps **no per-message, per-identity record** (zero
knowledge), so there is no server-side "message delivered in X ms" stream to
build a latency SLO on the way a normal service would. What exists is:

- `/health` — a liveness probe (200, `ok:true`), answered without
  authentication, cheap, and measured answering promptly under the sustained
  load in `docs/LOAD.md` (a p99 of about 6 ms at ~2 000 deliveries a second,
  under 90 ms at the rig's limit). It **does not touch the shared store**, on
  purpose: a platform health check that failed on a store blip would restart
  every healthy instance at once. So it says the process is up and serving,
  and nothing about whether the store behind it is.
- `z_*` counters — aggregate, RAM-only, per instance: enqueues, deliveries,
  refusals of each kind, acknowledgements, a delivery-latency **histogram**,
  the health-of-the-mesh counters (`z_reflushed_total`,
  `z_presence_refresh_failed_total`, `z_body_missing_total`), and
  `z_send_internal_error_total` — sends the relay could not store or route,
  which in Redis mode is almost always the store being unreachable: the
  store-availability signal `/health` deliberately is not. `/metrics` now
  requires the `METRICS_TOKEN` bearer (P1-14; 404 without it), so the scrape
  config must send it — a scrape with no token learns nothing, by design, so
  that the counters are not a presence oracle for the internet.
- The store's own `redis_up`, `used_memory` and `maxmemory` (the Valkey/Redis
  exporter), and the KT log's and witness's `/health` (JSON, read through a
  json exporter).

The one thing that **is not** cleanly measurable in production is end-to-end
message latency split by whether the recipient was online: the delivery
histogram (`z_delivery_latency_ms`, enqueue→acknowledgement) mixes live
delivery with mail that waited, correctly, for an offline recipient to
reconnect — so its tail is dominated by how much traffic is to offline
recipients, not by relay health. End-to-end latency is what the **bench**
measures (`docs/LOAD.md`); in production, read the histogram's *fast* share as
a congestion trend and treat `/health` responsiveness as the latency SLI.

## The objectives

| # | Objective (example target) | SLI, from what exists | Error budget | Backing alarm |
|---|---|---|---|---|
| 1 | **Relay availability** ≥ 99.9%/month | `/health` returns 200 `ok:true` (blackbox `probe_success`) | 43 min/month | `RelayHealthDown` (page), `RelayMetricsUnread` (warn) |
| 2 | **Relay can store and route** ≥ 99.9%/month | the store answering (`redis_up`) and sends not answered `internal` (`z_send_internal_error_total`) — what objective 1 cannot see | 43 min/month | `RelayStoreDown` (page), `RelaySendInternalErrors` (page), `RelayStoreUnwatched` (warn) |
| 3 | **Relay stays responsive** — `/health` under 1 s | blackbox `probe_duration_seconds` — a gauge, one value per probe, so the alarm takes its worst over a window | 1%/month over 1 s | `RelayHealthSlow` (warn) |
| 4 | **No silent loss** — `z_body_missing_total` no more than a trickle | an envelope a mailbox lists whose body the store no longer holds: an evicting store (finding 14). One can be legitimate — an acknowledgement landing between a flush's two reads — so the alarm is on a rate, not on one | none past the trickle | `RelayBodyMissing` (page) |
| 5 | **The mesh delivers live** — `z_reflushed_total` and `z_presence_refresh_failed_total` near zero | a live push that went nowhere / a presence refresh that failed (`cross_instance.test.js`) | small, trend | `RelayReflushElevated`, `RelayPresenceRefreshFailing` (warn) |
| 6 | **Store headroom** — `used_memory` < 90% of `maxmemory` | the Valkey/Redis exporter | burn toward full | `RelayStoreNearFull` (warn), `RelayStoreFull` (page) |
| 7 | **KT log availability** ≥ 99.9%/month | KT `/health` 200 — `503` while the log replays at start, which is not serving; its memory beside the limit (`rssBytes`, `memLimitBytes`) is the early warning, since a log that outgrows its instance dies in that replay | 43 min/month | `KtLogDown` (page), `KtMemoryHigh` (warn, early) |
| 8 | **KT disk never surprises** — `diskFreeBytes` well above `KT_MIN_FREE_BYTES` | KT `/health` `diskFreeBytes` and `full` (entries never expire — R31, `docs/CAPACITY.md`) | lead time, not a ratio | `KtDiskLow` (warn, early), `KtLogFull` (page), `KtHealthUnread` (warn) |
| 9 | **The witness keeps up and agrees** | the witness's own `/health`: `size` (the head it has verified) against the log's `size`, `diverged`, and `stale` (nothing verified for `KT_STALE_AFTER`). Its `/sth.json` carries the size but never `diverged` | — | `KtWitnessBehind` (warn), `KtWitnessStale` (warn), `KtWitnessDiverged` (page), `KtWitnessDown` (page) |

Every alarm that reads a series some exporter has to produce has a partner
that fires when the series is **missing** — an exporter that stops, a json path
that no longer matches, `full` reported as `null` because free space could not
be read. A rule over a series that is absent is a rule that never fires, and a
quiet dashboard is then indistinguishable from a healthy one.

## The alarms that are *signals*, not SLO breaches

These `z_*` counters stay at zero in ordinary use and mean something an
operator must see, but none is an availability or latency breach — they are
the flood and mis-configuration signals the capacity work put in
(`docs/LOAD.md`, `docs/CAPACITY.md`):

- **`z_new_mailbox_refused_total` leaving zero** — the mailbox-creation gate is
  firing: a flood of first contacts, or an allowance set too low for the
  deployment's real rate of new conversations. Per instance by default; one
  relay-wide window when `NEW_MAILBOX_SHARED=on` (25.3). Counted only here —
  never also as `z_store_full_total`, which it used to be in Redis mode. See
  `RelayNewMailboxRefused`.
- **`z_new_mailbox_shared_fallback_total` leaving zero** — with sharing on, a
  creation the shared window could not decide, so the instance decided on its
  own bucket: while it lasts the relay-wide rate is N × the configured one. The
  store unreachable, or its counter unreadable. See
  `RelayNewMailboxGateFallback`.
- **`z_store_full_total` leaving zero** — the store is at `maxmemory` and
  refusing sends. It heals as mailboxes drain, but a sustained rate means the
  store is too small for the backlog (`docs/CAPACITY.md`); see
  `RelayStoreFull`.
- **`z_unowned_refused_total` leaving zero** — the first‑contact abuse limits
  are firing (P0‑4): a flood of sealed envelopes to mailboxes nobody owns has
  hit the per‑mailbox cap, the relay‑wide unowned budget, or a per‑IP minute.
  Zero in ordinary use, so any rate is a flood the limits are bounding (the
  junk clears at `QUEUE_TTL_HOURS`) or `UNOWNED_STORE_BYTES` set too low for a
  genuinely busy first‑contact rate. Owned mailboxes are unaffected. See
  `RelayUnownedRefused`.
- **`z_unowned_bytes` approaching `z_unowned_max_bytes`** — the store‑fill
  gauge for first‑contact traffic (P0‑4): what mailboxes nobody owns hold,
  against `UNOWNED_STORE_BYTES`. RAM mode counts it live; Redis mode reports
  the relay‑wide total each sweep reconciles (the same figure on every
  instance — take the max, not the sum). At the budget, unowned sends are
  refused and `z_unowned_refused_total` moves; owned mailboxes are unaffected.
- **`z_store_bytes` approaching `z_store_max_bytes`** — the single‑instance
  store‑fill gauge (both emitted only in RAM mode; Redis mode watches the
  store exporter's `used_memory` instead, SLO 6). Past the ceiling a send is
  refused `store_full` rather than the process being OOM‑killed, but the
  backlog is near its limit; see `RelayStoreFillHigh`.
- **`z_auth_v2_refused_total` rate rising** — v2 authentications verifying under
  none of the relay's names: a front rewriting `Host` (set `RELAY_AUTHORITIES`),
  or signatures made for another relay (the replay the binding stops, R33). And
  **`z_auth_v1_total`** should be watched *downward* — it is what says when
  `RELAY_AUTH_V1=off` is safe (SELF_HOSTING.md). See `RelayAuthV2Refused`.

## Watching the store without learning from it

The store-memory and store-up rules need the Valkey/Redis exporter, and two
things about it are part of the threat model rather than of monitoring. **Do
not enable its key-level options** (`--check-keys`, `--check-single-keys`,
`--check-key-groups`, `--check-streams`, `--check-single-streams`): they export
key names as labels, and this store's keys are `q:<routing id>`,
`presence:<routing id>` and `push:<routing id>` — that copies routing ids, and
who is online, into the metrics system, which is everything the relay is built
not to keep. And **the exporter holds the store's credentials**: run it on the
store's private network, with its own `/metrics` no more reachable than the
store itself (R14 already counts the store as the operator's to keep private).

## Error budgets, concretely

Availability at 99.9% is **43 minutes a month** of `/health` not answering 200,
and objective 2 is the same 43 minutes for the store behind it. A single relay
restart on deploy is seconds; the HA pair (`render.ha.yaml`) exists so a
redeploy or one instance's loss spends none of objective 1 (a client lands on
the other instance) — but both instances share one store, so a store outage
spends objective 2 for everybody at once, and `/health` stays green through it.
Spend the budgets deliberately: if one is gone, `autoDeployTrigger: "off"`
already means a human chooses each deploy, so hold non-urgent ones. The KT
log's budget is the same shape but its disk is a *one-way* resource — an
exhausted disk is not a blip that heals, so objective 8 is managed by **lead
time** (grow early on `KtDiskLow`) rather than by spending minutes.

## Reproduce the headroom numbers

The latency and `/health`-under-load figures these targets are set against come
from `docs/LOAD.md` (`server/bench/ha_load.js`), with the command beside each;
the per-unit costs behind the store and disk objectives come from
`docs/CAPACITY.md` (`server/bench/capacity.js`, `kt/bench/disk.js`). Run them
on your own hardware before committing to numbers — `docs/LOAD.md` shows the
same command moving a 99th percentile fourfold between two VMs, and a phone
network, a real load balancer and a disk that is not loopback will all move
them further.
