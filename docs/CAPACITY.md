# Capacity planning, measured

Roadmap Phase 25.2. Three things in this system have a documented ceiling: the
relay's memory (the RAM queue's `MAX_STORE_BYTES`, 192 MB, in single-instance
mode; the shared store's own `maxmemory` in Redis mode), the transparency
log's disk (`kt/`, where **entries never expire** — R31) and the log's memory,
which holds every one of those entries. This page turns them
into numbers an operator can size a box against, from costs measured here
rather than estimated. Every figure says what produced it; reproduce them on
your own hardware with the commands named.

All numbers are **local, one machine, loopback**. They are the per-unit costs
(bytes per envelope, per connection, per published list); a deployment's total
is those times its own population, and the real-network effects a rig cannot
show are listed at the end.

## The costs, measured

| Unit | Cost | How it was measured |
|------|------|---------------------|
| A queued envelope, **RAM mode** | **≈ 299 B + the payload**, in process memory | `node bench/capacity.js` — `MemoryCoordinator`, `heapUsed + external` with gc forced, at two payload sizes |
| A queued envelope, **Redis mode** | **≈ 177 B + 1.23 × the payload**, in the store | `node bench/capacity.js` — the store's own `used_memory`, two payload sizes |
| A connected device | **≈ 11 KB per socket** of relay RSS; a device is **two sockets** (§12.1, 16.1), so **≈ 22 KB** | `node bench/capacity.js` — a forked relay's own RSS across 2 000 authenticated sockets |
| A published device list | **≈ 336 B + 1.33 × the value**, on disk (base64 is ~1.33×); a real three-device list (1.1 KB sealed) is **≈ 1.8 KB** | `cd kt && node bench/disk.js` — a real `FileStore`, two value sizes |
| A published device list, in the log's memory | **≈ 2.4 KB retained, ≈ 6.5 KB of resident growth**, for the life of the process, whatever the value's size; a mirror ≈ 2.0 / 6.1 KB | `cd kt && node bench/memory.js` — a fresh process replays 22,094 real-size entries (forced GC; heap and external) |

The relay **charges** an envelope `payload.length + 256` against its byte caps
(`MAX_QUEUE_BYTES_PER_USER`, `MAX_STORE_BYTES`); that is the number the caps
enforce. The rows above are the **real footprint**, which the cap figure
approximates well in RAM mode (299 ≈ 256 + object overhead) and under-states in
Redis mode (the store keeps a list element, a hash field and a byte counter
beside the body). Size a box against the real footprint; reason about refusals
against the charge.

## (a) The relay's memory

A 1 024-bucket sealed envelope — a short text, what most traffic is — is 1 450
characters on the wire (PROTOCOL §8). So:

- **RAM mode:** ≈ 299 + 1 450 = **≈ 1.75 KB** of process memory per such
  envelope. `MAX_STORE_BYTES` (192 MiB, 201 326 592 B) is checked against the
  *charge* (payload + 256 = 1 706 B), so the queue refuses at **≈ 118 000**
  queued 1 024-bucket envelopes (201 326 592 ÷ 1 706), holding ≈ 197 MiB of
  actual process memory for them (118 000 × 1 749 B).
- **Redis mode:** ≈ 177 + 1.23 × 1 450 = **≈ 1.96 KB** per envelope in the
  store. Cross-checked by the sustained offline run in `docs/LOAD.md`, which
  held 116 671 such envelopes and took `used_memory` from 1.31 to 210.15 MiB —
  **1 877 bytes each** net of the empty-store baseline (the same to the byte
  on two different VMs), a little under the formula: the store's allocator
  slack at a large fill. Size a Redis store at **≈ 1.9 KB per queued
  1 024-bucket envelope**.

**Connections cost memory too, and at scale they dominate.** At ≈ 11 KB of
relay RSS per socket and two sockets per device, **10 000 connected devices is
≈ 220 MB of RSS before a single envelope is queued** — on a 512 MB instance,
the connection count sizes the box as much as the backlog does. This is why
`/health` reports `sockets` beside `connections` and why the sizing rule counts
sockets, not devices (`docs/PERFORMANCE.md`, "Two sockets per device").

### The formula

For a backlog of **U** recipients each holding **B** undelivered envelopes of
**S**-byte payloads, plus **D** connected devices:

```
store bytes   ≈ U × B × (177 + 1.23 × S)        (Redis mode)
RAM bytes     ≈ U × B × (299 + S) + D × 2 × 11 000   (single instance)
```

bounded, for each recipient, by `B ≤ MAX_QUEUE_MSGS_PER_USER` (5 000) and
`B × (S + 256) ≤ MAX_QUEUE_BYTES_PER_USER`, and for the whole by
`MAX_STORE_BYTES` / the store's `maxmemory` — past which a send is refused
`store_full`, not made room for.

**Worked example.** A relay for 10 000 people, of whom at a bad moment 2 000
are offline with 50 queued 1 024-bucket texts each: `2 000 × 50 × 1.88–1.96 KB
≈ 188–196 MB` in a Redis store (the measured and the formula figure). That overflows the reference deployment's 256 MB
store only if it coincides with much else, which is the point of the
per-recipient cap — one mailbox can hold at most `MAX_QUEUE_BYTES_PER_USER`, so
`render.ha.yaml` sets that to 16 MB (store ÷ 16), bounding any one recipient to
1/16 of the store and leaving an abusive or abandoned mailbox unable to crowd
out fifteen others (SELF_HOSTING.md, "Operational notes").

## (b) The transparency log's disk

The log keeps every published device list on disk for ever — that is what a
log is (R31). A publish is **≈ 336 B + 1.33 × the sealed value**; a real list
is **≈ 1.8 KB**. There is no expiry and no pruning, so the only question is how
fast the disk fills.

A gigabyte holds **≈ 555 000** real-list publishes, or **≈ 22 700** at the
32 KiB `KT_MAX_VALUE_BYTES` cap (a hundred devices). At **R** republishes per
account per year, the disk grows by `accounts × R × 1.8 KB` each year, plus a
one-time `accounts × 1.8 KB` for the first publish of each:

| accounts | first publish (one-time) | R = 1/yr | R = 4/yr | R = 12/yr |
|---:|---:|---:|---:|---:|
| 1 000 | 1.8 MB | 1.8 MB/yr | 7.2 MB/yr | 21.6 MB/yr |
| 10 000 | 18 MB | 18 MB/yr | 72 MB/yr | 216 MB/yr |
| 100 000 | 180 MB | 180 MB/yr | 721 MB/yr | 2.2 GB/yr |

**Worked example.** 100 000 accounts that each rotate a device four times a
year: `180 MB` once, then `721 MB` every year, for ever. A 10 GB disk lasts
about **thirteen years** at that rate and then stays full — so the answer is
never "a big enough disk", it is **an alarm on `diskFreeBytes`** (`/health`)
and a disk grown before the floor, plus a witness (§19.9, G3) that holds the
whole history should the operator's disk be lost. Below `KT_MIN_FREE_BYTES`
(64 MiB) the log serves reads and refuses publishes `503 log_full` rather than
meeting `ENOSPC` mid-line (SELF_HOSTING.md, "The disk is the bound").

**And its memory.** The disk holds the entries; the process holds every one
of them too, in both trees, from a replay that runs before it listens — so
the log's memory grows exactly as its disk does and never shrinks, and an
instance that is too small is killed during that replay on every start.
**Size RAM at ≈ 4 KB an entry plus 128 MiB.** Measured: 22,094 entries (the
live log, 2026-10-03) replay in ≈ 187 MiB resident, and a 512 MiB instance is
killed at **≈ 131,000** entries — measured in a 512 MiB cgroup. Until
2026-10-04 an entry cost 11.6 KB (each pinned a slab of Node's shared buffer
pool), the same 22,094 took 376 MiB, and the 512 MiB ceiling was ≈ 39,000.
`/health` reports `rssBytes` beside `memLimitBytes`; alarm at three quarters
(`KtMemoryHigh`). At 100 000 accounts that each publish four times a year the
log adds 400 000 entries a year: ≈ 1.6 GB of RAM a year, beside the 721 MB of
disk above — memory, not disk, is the first ceiling such a log meets.

## (c) Sizing the Redis store, and `noeviction`

The shared store (`render.ha.yaml`'s Key Value instance, or any Redis you run)
holds the same bytes the RAM queue would, at ≈ 1.8–2.0 KB per 1 024-bucket
envelope. Size its `maxmemory` for the backlog you expect
(`active_recipients × MAX_QUEUE_BYTES_PER_USER` worst case) and run it
**`noeviction`**, as both shipped configurations do. `noeviction` is
load-bearing, not a default: at `maxmemory` an evicting store (`allkeys-lru`)
drops whole keys, and a mailbox's bodies can go while its list stays — an
envelope whose sender was told `sent`, silently gone (the shipped compose file
ran `allkeys-lru` until 2026-09-17; `full_store.test.js` 5–6). With
`noeviction` a full store refuses a send (`store_full`, the sender retries) and
still lets logins drain, so it heals as mailboxes empty; a relay in front of a
store that evicts anyway counts what it finds missing in `z_body_missing_total`
and drops the dangling key once. **Alarm on anything but a trickle there.**

## (d) What to watch, and when to add an instance vs. raise the store

Everything here is in `/metrics` (the `z_*` surface) and `/health`; the
objectives and the exact alarm expressions are in `docs/SLO.md` and
`server/alerts.example.yml`.

- **Raise the store (or lower `MAX_QUEUE_BYTES_PER_USER`)** when `used_memory`
  / `z_store_bytes` climbs toward `maxmemory` / `MAX_STORE_BYTES`, or
  `z_store_full_total` leaves zero. The store is a shared resource one full
  mailbox at its cap cannot exhaust but many backlogged recipients can.
- **Add an instance** when a single one is CPU- or event-loop-bound: delivery
  latency and `/health` latency climbing while memory is fine. Measured
  (`docs/LOAD.md`): one in-process instance delivered **1 795 envelopes a
  second** at a 99th-percentile latency of **19 ms**, **3 498/s** at **82 ms**
  and, pushed, **5 528/s** at **192 ms**, losing nothing — and the 3 500/s
  load's tail was **22 ms** on another VM. The tail, not the throughput, is
  the signal to scale out, and it moves with the host as much as the load.
- **Watch the store from beside it, never through its keys.** The Valkey/Redis
  exporter gives `redis_up`, `used_memory` and `maxmemory`, which is all the
  rules here use. Do **not** enable its key-level options (`--check-keys`,
  `--check-single-keys`, `--check-key-groups`, `--check-streams`,
  `--check-single-streams`): they export key names as labels, and this store's
  keys are `q:<routing id>`, `presence:<routing id>` and `push:<routing id>` —
  that would copy routing ids, and who is online, into the metrics system,
  which is everything the relay is built not to keep. And the exporter holds
  the store's credentials: run it on the same private network as the store,
  with its own `/metrics` no more public than the store is.
- **A caveat this rig cannot see past.** Adding instances multiplies
  throughput only across **separate cores or machines**. The local runs put
  every instance in one or two processes on a two-core box, so N instances
  there *share* the two cores and do not add throughput — they add a
  cross-instance hop and a little tail latency (`docs/LOAD.md`). What a second
  instance buys — more cores, redundancy across machines, a rolling redeploy
  that drops nothing — is exactly what only real infrastructure shows.

## Reproduce

```bash
cd server && node bench/capacity.js      # envelope RAM + Redis, per-connection
cd kt && node bench/disk.js              # bytes on disk per published list
cd kt && node bench/memory.js            # memory per entry, log and mirror
cd server && NEW_MAILBOX_PER_MIN=100000 node bench/ha_load.js --instances 2 --clients 200 --seconds 60 --rate 20 --offline 0.5   # queue growth → store memory
```

Run them one at a time on an otherwise idle machine: two benches at once
measure each other. The sustained multi-instance numbers, and what they do and
do not show, are in `docs/LOAD.md`.
