# Self‑hosting the Z relay

The relay is intentionally trivial to run because it holds almost nothing: it
shuttles opaque ciphertext and keeps undelivered messages in **RAM only**. You
do not need a database, object storage, or backups. You *do* want TLS.

## What the relay is (and isn't)

- It is a WebSocket server that authenticates clients by an Ed25519 challenge,
  queues encrypted envelopes per recipient **in memory**, and delivers them.
- It never writes message data to disk. It can run on a read‑only filesystem.
- It cannot read messages. Everything it relays is end‑to‑end encrypted by the
  clients.
- Losing the relay (restart, crash, redeploy) only loses *undelivered* messages
  in flight; delivered messages live on the devices.

A single 1 vCPU / 512 MB instance handles a large number of users since it only
buffers transient ciphertext — start there. When you need high availability or
more throughput, run several instances that **share presence + the pending
queue through Redis** so any instance can deliver to any connected client (see
"Scaling out" below).

## Option A: Docker (recommended)

```bash
cd server
docker compose up --build -d
```

`docker-compose.yml` runs the container with `read_only: true` and **no
volumes**, so the process physically cannot persist anything. It exposes
`:8080` (plain `ws://`). Put it behind a TLS‑terminating reverse proxy (below).

## Option B: Node directly

```bash
cd server
npm install --omit=dev
PORT=8080 node server.js
```

Run it under a supervisor (systemd, pm2). Example systemd unit:

```ini
[Unit]
Description=Z relay
After=network.target

[Service]
ExecStart=/usr/bin/node /opt/z/server/server.js
Environment=PORT=8080
Environment=LOG_LEVEL=info
DynamicUser=yes
ProtectSystem=strict     # read-only filesystem — the relay needs no writes
ProtectHome=yes
NoNewPrivileges=yes
Restart=always

[Install]
WantedBy=multi-user.target
```

## Option C: a free cloud tier

`render.yaml` at the repository root describes the relay for
[Render](https://render.com): fork the repository, create a **Blueprint**
from the fork, and Render hands you a `wss://…onrender.com` address in a
couple of minutes. `deploy/fly.toml` does the same for
[Fly.io](https://fly.io) (`fly launch`, then `fly deploy`). Both terminate
TLS for you, so the address is usable in the app as it is; check
`https://<your host>/health` for `"storage":"ram-only"`.

Render's free tier sleeps after about fifteen minutes without a connection
and takes ~30 s to wake on the next one. Delivered messages are on the
devices regardless; only a message in transit at that moment waits for the
wake. Change `plan: free` to `plan: starter` in `render.yaml` to keep it
awake.

## TLS (do this for real use)

Terminate TLS at a reverse proxy and hand the relay plain `ws` on localhost.
Clients then connect with `wss://relay.example.com`.

### Caddy (automatic certificates)

```
relay.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Caddy upgrades WebSockets automatically and provisions Let's Encrypt certs.

### Nginx

```nginx
server {
    listen 443 ssl;
    server_name relay.example.com;

    ssl_certificate     /etc/letsencrypt/live/relay.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;      # keep idle WebSockets alive
    }
}
```

The relay can also serve TLS itself if you prefer, by setting `TLS_CERT` and
`TLS_KEY` — but a proxy is usually easier to operate.

## Configuration (environment variables)

| Variable | Default | Meaning |
|----------|---------|---------|
| `PORT` | `8080` | listen port |
| `HOST` | `0.0.0.0` | bind address |
| `MAX_ENVELOPE_BYTES` | `1000000` | max single encrypted frame |
| `MAX_QUEUE_BYTES_PER_USER` | `67108864` | per‑recipient queue cap (bytes); an envelope that would cross it is refused, not made room for |
| `MAX_QUEUE_MSGS_PER_USER` | `5000` | per‑recipient queue cap (count), likewise |
| `MAX_STORE_BYTES` | `201326592` | the whole RAM queue's ceiling in single‑instance mode — past it a send is refused as `store_full` rather than the process being killed. Redis mode refuses against the store's own `maxmemory` instead |
| `NEW_MAILBOX_PER_MIN` | `120` | how many mailboxes may be **created** a minute, per instance, across all senders. Charged on **first contact** with a recipient, not on an empty mailbox — a mailbox exists only while it holds unacknowledged mail, so a recipient who is online and keeping up has none when the next message arrives, and charging that emptiness charged every message (fixed 2026‑09‑14; until then the relay stopped at this number of *messages* a minute, for everyone) |
| `SEEN_MAILBOX_CAP` | `100000` | how many recipients an instance remembers having written to, so the line above can mean "first contact". A memory bound, measured at 117 bytes an entry (11.2 MiB at the default); least recently used are dropped. It is not what bounds a flood — **a send that was refused is never remembered**, so a refused flood leaves the set as it found it |
| `SEEN_MAILBOX_TTL_MIN` | `60` | and for how long a recipient stays remembered. Bounds how long a second flood can re‑use ids whose mailboxes the first one paid for. A recipient who is merely offline is unaffected: their mailbox still exists, and that is checked too |
| `QUEUE_TTL_HOURS` | `72` | drop an undelivered envelope this long after the relay accepted it — per envelope, in both modes |
| `SWEEP_INTERVAL_SECONDS` | `60` | expiry sweep cadence (a flush expires too, before it delivers) |
| `FLUSH_PAGE` | `64` | entries a flush may send before waiting for the socket to drain |
| `FLUSH_HIGH_WATER_BYTES` | `1048576` | bytes it may send before waiting — whichever of the two comes first |
| `ID_SLOTS` | `8` | sealed envelopes that may share one `id` in one mailbox (§12.2) |
| `RATE_PER_SEC` / `RATE_BURST` | `80` / `240` | per‑connection token bucket |
| `TLS_CERT` / `TLS_KEY` | — | enable built‑in TLS (paths to PEM) |
| `RELAY_AUTH_V1` | `on` | whether the unbound v1 authentication is still accepted. A v1 signature is over the challenge alone, so one obtained by any relay a user was talking to authenticated them here (R33); v2 (relay and app from 2026‑09‑17 on) signs the relay's name with it, and a client from then on never produces v1. Every v1 authentication is counted in `z_auth_v1_total`; set `off` once that has stayed at zero for as long as you care to wait — after which a client from before then cannot receive until it updates |
| `RELAY_AUTHORITIES` | — | names a v2 signature may carry besides the `Host` header the connection arrived with, comma‑separated (`relay.example`, `relay.example:8443`). Only for a front that rewrites `Host`; the shipped ones — `nginx.ha.conf`, Cloudflare, Render — pass it through, and then the header alone is right |
| `LOG_LEVEL` | `info` | `info` logs counts/timing only, never content |

**Authentication names the relay (2026‑09‑17).** A client signs its challenge
answer over the relay's authority as it dialled it — the URL's host, lower
case, with the port only when it is not the default — and the relay checks
that against the `Host` header it received. So the header has to reach the
relay as the client sent it: if you put your own proxy in front, forward
`Host` unchanged (`nginx.ha.conf` uses `proxy_set_header Host $http_host;`
— `$host`, which strips the port, would make every client on a non‑default
port fail to authenticate), or list the names you answer to in
`RELAY_AUTHORITIES`. An app from 2026‑09‑17 on refuses a relay that does not advertise the
bound form (its challenge lacks `auth: 2`) and says so in Settings → Relay
server ("relay too old"): **update the relay before the app** on a
self‑hosted deployment, or the app cannot receive until you do.

## Health & monitoring

`GET /health` returns JSON with uptime, live connection count, number of queued
envelopes, `storeBytes` in single‑instance mode (the number `MAX_STORE_BYTES`
is checked against — watch it against `queuedEnvelopes`, since the two
disagreeing is itself a fault), and `"storage":"ram-only"`. Point your uptime monitor at it. There
is deliberately no message‑level logging to monitor — the relay can't see
messages.

### After a deploy: check that the relay serving is the one you deployed

```bash
python3 tool/check_live_relay.py https://relay.example.com
#   ... and for the reference deployment, whose Blueprint it can also check:
python3 tool/check_live_relay.py https://www.zmessengers.com --blueprint render.ha.yaml
```

It reads `/health` and `/metrics` — two GETs, no credential — and compares
what comes back against the checkout it is run from: every `z_*` metric this
code emits in every mode must be live, `/health` must answer ok with
`storage: ram-only`, and in Redis mode `presenceStale` must be present and
zero. It exits 0 when the serving relay is at least this checkout, 1 when it
is behind or unhealthy, and 2 when it could not be reached — so it belongs in
a deploy script as much as at a prompt.

Run it because **a landed `server/` change is not live until someone clicks
Deploy**, and that click is the only step in the pipeline that leaves no
record. In the reference deployment (`autoDeployTrigger: "off"`, deliberately)
six releases of relay work once sat on `main` unserved for four days, and each
session that noticed worked it out by hand from a counter missing in
`/metrics`. This is that deduction, in one command, derived from the code
rather than from a list of version numbers that would go stale itself.

## Pointing clients at your relay

In the app: onboarding screen, or Settings → Relay server. Use
`wss://relay.example.com` (TLS) in production — a plain `ws://` address for
anything that is not on your own network now asks for confirmation first, and
names what it costs (the routing metadata, never the contents). A `ws://`
address on localhost, a private range or a `.local` name connects without a
word, because that is what cleartext is for. Everyone you talk to must use the
**same relay**: federation is designed and not built — if it is, a sender
will open an anonymous link to the recipient's relay directly and nothing
will travel between relays (`docs/adr/0008-federation.md`). The relay only
sees routing hashes and ciphertext, so running your own maximizes metadata
privacy too.

## What one relay carries

Measured on loopback (`docs/PERFORMANCE.md`, "The relay under load"): a
single Node process delivers ~5 000 sealed envelopes a second across 200
sockets with a median latency under 2 ms and a 99th percentile under 15 ms,
and ~2 500 a second across 1 000 sockets at a 99th percentile of ~70 ms,
losing nothing. **Count sockets, not devices: each device holds two** — its
authenticated mailbox link and the anonymous link it sends sealed envelopes
on (PROTOCOL §12.1) — and the tail latency follows the socket count: at the
same ~2 000 envelopes a second, 1 000 sockets give a 99th percentile of ~45
ms and 2 000 sockets ~160 ms. `/health` reports both (`connections` is
mailboxes, `sockets` is everything). A relay for a thousand people is one
small machine; the abuse limits below, not throughput, are what to think
about. `npm run bench:latency` in `server/` reproduces the numbers on your
own hardware.

## Scaling out (high availability)

For redundancy or higher throughput, run several relay instances behind one
load balancer. They coordinate through a **RAM‑only Redis** (`REDIS_URL`):
presence (`presence:{rid}`) and each recipient's pending queue (`q:{rid}`, a
list of entry keys in arrival order; `qe:{rid}`, the entries; `qb:{rid}`,
their bytes) live in Redis, and instances route to each other over Redis
pub/sub, so a client can land on **any** instance and still reach anyone.
An entry key is `m:<id>:<sender>` for an attributed envelope, `m:<id>` (and
`m:<id>#1`, …) for a sealed one — which carries no sender to put there —
and `r:<id>:<who acknowledged>` for a delivery receipt: the party is in the
key because an `id` is the sender's choice and identifies nothing on its own
(§12.2). No attribution reaches a key that the entry beside it did not
already hold, and a sealed envelope's key holds none.

A mailbox drains in one list read, one hash read and one small script per
acknowledgement — five thousand short envelopes in under half a second
(`docs/PERFORMANCE.md`, "Draining a mailbox"); entries queued by a relay
older than 2.7.9 are read and removed the way that relay left them, until
they expire. Redis holds only the same
opaque ciphertext — run it with no persistence so nothing touches disk.

The repo ships this ready to run:

```bash
cd server
docker compose -f docker-compose.ha.yml up --build --scale relay=3
```

That starts Redis (`--save "" --appendonly no` — RAM only, and
`--maxmemory-policy noeviction`), three relay instances (`REDIS_URL` set,
read‑only filesystem), and an nginx load balancer on `:8080` that
round‑robins WebSocket upgrades across them (`nginx.ha.conf`). Put a TLS
proxy in front for `wss://`, or point a cloud host at the same setup. Until
2026‑09‑17 the compose file ran the store `allkeys-lru`, which at
`maxmemory` evicts whole keys: a mailbox's bodies could go while its list
stayed, an envelope whose sender had been told `sent` silently gone, and
every "never evicted" below false for anyone who ran the documented command
line. It is `noeviction` now, like the Blueprint, and a relay in front of a
store that evicts anyway is no longer silent about it: an envelope a mailbox
lists whose body is gone is counted in `z_body_missing_total` and its key
dropped, once. Anything but a trickle there says the store is misconfigured.

On Render, `render.ha.yaml` at the repository root is that setup as a
Blueprint: two relay instances on paid compute (a free instance cannot run
more than one copy), Render's own load balancer in front, and a Key Value
instance with persistence off and no public access as the RAM‑only Redis.
Create it from **New → Blueprint** with the Blueprint Path set to
`render.ha.yaml`; `/health` then answers `"coordinator":"redis"` with a
different `instanceId` from one request to the next, and reports
`queuedEnvelopes` as `-1` because the total is not counted across instances.
The store is `noeviction`, as the compose file's now is, so
when it is full a send is refused — `store_full`, promptly, and the sender's
outbox keeps the message and retries on its own timer — rather than a queue
being evicted after its sender was already told "sent". A full store does
not keep anyone out: logins still succeed, queued envelopes are still
delivered and acknowledged (reads and removals are allowed when memory is
short), so the mailboxes that filled it can be drained and it heals by
itself; `/health` shows `presenceStale` while it lasts and `/metrics`
counts `z_store_full_total`. This relies on Redis 7 script flags: run
Redis 7 or newer, or Valkey (the compose file and the Blueprint do).

That healing has a precondition worth stating, because until 2026‑09‑14 it
was assumed rather than held: healing means the owner of a full mailbox
connects and drains it, and **a mailbox addressed to a routing id nobody
holds has no owner**. `to` is checked for the shape of a routing id and
nothing else — the relay cannot know which hashes name a real identity, and
is not supposed to — so anyone could fill the store with mailboxes that
would never drain, and the only floor was `QUEUE_TTL_HOURS`. Creating a
mailbox is therefore rate‑limited across all senders
(`NEW_MAILBOX_PER_MIN`), which bounds that without bounding anybody's
conversation: the allowance is spent only by first contacts. A send refused
by it is told `store_full` and retried, so an honest first message during a
flood is late rather than lost, and `z_new_mailbox_refused_total` counts
them — a number that stays at zero in ordinary use and is worth an alert.
Single‑instance mode had no global bound at all and answered the same flood
with an OOM kill; it now refuses at `MAX_STORE_BYTES`.

That paragraph was not true until 2026‑09‑14, and the way it was untrue is
worth stating because the shape recurs. The gate was charged whenever the
recipient had **no mailbox** — and a mailbox exists only while it holds
unacknowledged mail, so a recipient who is online and acknowledges each
message, as §12.5 requires, has none by the time the next one arrives. In
that steady state — the ordinary one — every message paid, and because the
gate is global to the instance the whole relay stopped at
`NEW_MAILBOX_PER_MIN` *messages* a minute, refusing `store_full` with an
empty store and `z_new_mailbox_refused_total` climbing. What is remembered
now is the recipients written to recently (`SEEN_MAILBOX_CAP`,
`SEEN_MAILBOX_TTL_MIN`), which is what "first contact" needs and what an
empty mailbox never was.

`/health` also reports `storeBytes` in single‑instance mode — the number
`MAX_STORE_BYTES` is checked against — beside `queuedEnvelopes`. (Redis mode
refuses against the store's own `maxmemory` and keeps no global counter, so
the field is absent there.) The two disagreeing is a fault in itself: TTL
expiry used to free the mail without crediting the counter, so a relay that
had once been busy refused every send for ever while reporting
`queuedEnvelopes: 0` — invisible, because nothing published the other number.

The per‑recipient caps work the same way at their own level and in
both modes: an envelope that would take a mailbox past
`MAX_QUEUE_MSGS_PER_USER` or `MAX_QUEUE_BYTES_PER_USER` is refused with
`queue_full`, never made room for (PROTOCOL §12.4). So the store can hold at
most `mailboxes in use × MAX_QUEUE_BYTES_PER_USER`, and one sender to one
offline recipient can fill at most one mailbox's cap of it: with the
defaults, 64 MB of a 256 MB store, which is why the cap is worth lowering on
a small store (`MAX_QUEUE_BYTES_PER_USER=16777216` leaves room for about
sixteen full mailboxes in 256 MB). Redis mode enforced only the count until
2026‑09‑11; the byte counter it keeps beside each list is reset whenever the
list empties, so nothing queued before that version can leave it wrong for
longer than that list is non‑empty.

To run your own instances by hand, set `REDIS_URL` (and optionally
`INSTANCE_ID`) on each `node server.js`, and front them with any WebSocket‑aware
load balancer.

**What this does and doesn't change:** still zero‑knowledge, still RAM‑only
(now including Redis), still at‑least‑once delivery with client‑side dedupe.
The one new trust element is Redis — keep it on your private network, under
your control; it never sees plaintext or keys. There is a small window right at
a client's instance‑handover where a live message may be delivered on the
client's next reconnect rather than instantly; nothing is lost (it stays queued
until acked).

## Operational notes

- **Memory** is the only real resource: worst case ≈
  `active_recipients × MAX_QUEUE_BYTES_PER_USER`, capped in RAM mode by
  `MAX_STORE_BYTES` and in Redis mode by the store's own `maxmemory` — plus,
  per device currently collecting its backlog,
  `FLUSH_HIGH_WATER_BYTES` plus one envelope in the relay process itself
  (about 3 MB at the defaults, measured — and it is a *bound*: a device on a
  slow link no longer holds its whole backlog in the relay's memory while it
  reads, which on a 512 MB instance was a handful of reconnects away from
  the whole machine — `docs/PERFORMANCE.md`, "What a reconnect costs the
  relay"). Raising `FLUSH_PAGE` does not raise that bound; raising
  `FLUSH_HIGH_WATER_BYTES` raises both it and how much the relay will let
  one socket buffer. Tune the caps for your box; keep the byte cap above one
  envelope (`MAX_ENVELOPE_BYTES` + 256) or the largest envelopes are refused
  everywhere, which the relay warns about at start. `render.ha.yaml` sets
  `MAX_QUEUE_BYTES_PER_USER` to 16 MB for exactly this reason: its store is
  256 MB, and at the 64 MB default four full mailboxes fill it — a full store
  refuses every sender until someone drains one, where a mailbox at its own
  cap refuses only its own.
- **Restarts drop in‑flight messages.** Senders keep them in their device
  outbox and the protocol re‑delivers, but schedule redeploys thoughtfully.
- **No backups needed.** There is nothing on disk to back up. That's the point.

## Running the transparency log

The log (`kt/`, PROTOCOL.md §19, `adr/0006`) is a second, separate service:
unlike the relay it **keeps state on disk** — an append‑only file of every
published device list, which is the whole point — and it has a signing key
whose public half every client pins. Run it on its own host name
(`kt.example.com`), behind the same kind of TLS front as the relay.

What it costs: no dependencies, one process, one file. Measured
(`cd kt && npm run bench`): a publish is ~1.5 ms of CPU, a lookup ~0.1 ms, a
lookup response ~4 KB at a hundred thousand accounts, and the entries file
grows by roughly the size of the sealed lists it holds (a few KB per publish,
up to ~44 KB at the default `KT_MAX_VALUE_BYTES`). What the **process** holds
is a function of the number of entries and not of their size or the file's:
replay reads a fixed window at a time and an entry keeps the byte range of
its own line rather than its value. Size the disk for the entries; size the
memory for how many accounts you expect, not how much they publish.

**The disk is the bound, and it has to be watched.** Entries never expire —
that is what a log is — so a disk fills and stays full. Nobody had multiplied
the limits through until 2026‑09‑14: at the protocol's 256 KiB value cap a
publish was up to 341 KB on disk, the Blueprint's 1 GB held 3,069 of them,
and with one address bucket for the whole internet and account keys free to
mint, that was **102 minutes to `ENOSPC`** — after which every publish got a
500 until an operator grew a disk that `/health` gave them no reason to look
at. Three things changed. This log accepts values only up to
`KT_MAX_VALUE_BYTES` (32 KiB, a hundred devices; a real list is ~1.1 KB
sealed for three) — the protocol's 256 KiB is what a *reader* must open, and
a log that accepts less says so with 413. A first publish from an account the
log has never held is charged against `PUBLISH_NEW_ACCOUNTS_PER_MIN`, the
same shape as the relay's mailbox gate: a flood needs accounts, and that is
the event worth charging; an account the log holds is never charged there.
And below `KT_MIN_FREE_BYTES` of free space the log answers publishes with
**503 `log_full`** and keeps serving reads, rather than meeting `ENOSPC`
halfway through a line. `/health` reports `diskBytes`, `diskFreeBytes` and
`full`; **alarm on `diskFreeBytes`** well above the floor and grow the disk
before it matters. At the defaults, a flood from one address needs about
fourteen hours and two thousand minted accounts to reach the floor, where it
needed a hundred minutes and a hundred and fifty — and it now ends in a log
that is read‑only and says so, not one that is down.

**Publishing is limited four ways, and the defaults assume a hostile
internet**, because the log accepts a signature from any Ed25519 key and
generating keys is free:

| `PUBLISH_PER_MIN_TOTAL` | 120 | every publish, whatever the source. The gate that stops a flood — a flood uses many accounts, so a per‑account limit does not see one |
| `PUBLISH_PER_MIN` | 30 | per source address. Only per‑**client** if `KT_CLIENT_IP_HEADER` is set (below); otherwise the TLS front is the address and this is one bucket for everybody |
| `PUBLISH_PER_ACCT_PER_DAY` | 20 | per account key, charged only once the signature verifies, so nobody can spend an account's budget but that account |
| `PUBLISH_NEW_ACCOUNTS_PER_MIN` | 10 | first publishes from accounts the log has never held, in total. Charged after the signature and only for a label the index does not have — and the index is built by accepted publishes, so a refused first publish leaves the account unknown |
| `KT_MAX_VALUE_BYTES` | 32768 | what this log accepts; at most the protocol's 262 144. Sets entries‑per‑gigabyte |
| `KT_MIN_FREE_BYTES` | 67108864 | below this much free space, publishes are refused `503 log_full` and reads continue. `/health` still answers 200 with `full: true`, so a host's health check does not restart a log whose only problem is a disk it cannot grow |
| `KT_MAX_PUBLISH_IN_FLIGHT` | 256 | publish bodies being read at once; a further one is told `503 busy` before anything is read. Not a rate — a request that finishes frees its slot in milliseconds — so it bounds memory (256 × 400 KB) against sockets held open, which the request timeout (a minute) then lets go of |
| `READ_BYTES_PER_MIN` | 33554432 | bytes of `/kt/v1/entries` a minute from one address (32 MiB — eight full pages). Over it, `429` with `retry-after`, before anything is built. Per‑client only with `KT_CLIENT_IP_HEADER`; otherwise one budget for every reader, mirrors included |
| `READ_BYTES_PER_MIN_TOTAL` | 134217728 | the same, for the whole log (128 MiB — four readers' worth). The bound on the log's own CPU and egress whoever asks |

`KT_CLIENT_IP_HEADER` (e.g. `cf-connecting-ip`) is empty by default and should
stay empty until the service is reachable **only** through the proxy that sets
it. A forwarded address is the caller's to choose unless something in front
overwrites it, and a limiter keyed on a value the caller picks is worse than
one keyed on a value they cannot.

The public deployment ran for a day with the per‑address gate keyed on the
proxy's address and nothing else: 3,853 entries from 3,579 distinct account
keys in about a hundred minutes, against a nominal thirty a minute. And until
2026‑09‑17 that gate and the total were charged before the body was read, so
behind the shipped front — one address for everybody — thirty one‑byte POSTs
a minute from anywhere, with no account and no signature, stopped every
genuine publish for the rest of the minute (measured: thirty junk requests,
all 400, then a correctly signed publish refused 429, at half a request a
second); moving the address gate alone would have left the total, which
everybody shares by construction, as the same switch at two requests a
second. **Every gate now counts publishes and none counts requests**: each is
taken after the signature verifies and given back if a later gate refuses or
the write fails, so a signature that costs nothing to make buys nothing it
did not write, and junk buys nothing at all. What a request that publishes
nothing can cost is bounded instead — the body at 400 KB, bodies being read
at once at `KT_MAX_PUBLISH_IN_FLIGHT`, and a request at the server's timeout
— and a raw flood past those is what the front is for, as for any HTTP
service; what it can no longer do is stop publishing.

**Reads are bounded by what one request can cost, and the mirrors' page by
the minute besides.** A page of entries is at most 4 MiB, a page of one
label's history 256 KiB, a lookup one entry with its proofs (~7 KB for an
ordinary list), a consistency proof a few hundred bytes. `/kt/v1/entries` —
the route a mirror pages a whole log through, and the only one that answers
a fifty‑byte request with megabytes (measured before the budget: 3.9 MiB in
176 ms, 85 000:1, stalling the event loop for 74 ms, as often as anyone
liked) — is budgeted per address and in total, and a reader over it is told
`429` with `retry-after` before anything is built; the mirror waits exactly
that long and asks again, so a first sync of a large log paces itself at the
budget rather than failing every `KT_EVERY` for ever. The routes a client's
check depends on — the head, a consistency proof, a lookup, its own label's
history — are **never refused by a budget**, on purpose: without the client
address header every reader is one address, and a budget an attacker could
spend on a route a client needs would be a cheaper denial than the one
this closes. What bounds those routes is the size of one answer. Without the
header, the per‑address read budget is one budget for every reader, your
witness included: an attacker spending it delays the witness's sync (it
retries) and touches no client.

A page of entries below the head and a consistency proof are the same answer
for as long as the log exists, and say so: `cache-control: public,
max-age=60`. That is the log's half. A CDN in front caches a JSON route only
when told to — on Cloudflare, a cache rule for `/kt/v1/entries*` and
`/kt/v1/consistency*` that honours the origin's TTL — and then a repeat of
the same page never reaches the log at all. Everything else stays
`no-store`: a lookup and a history are relative to the head they were served
under, and the head moves.

Three ways to run it, then one witness, then the client. The four conditions
under which the log counts as live are at the end; the Blueprints exist so
that reaching them is a few pastes rather than an afternoon.

### 1. Generate the signing key — on a machine you own, once

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

On a host of your own, keep it in a root‑only file:

```bash
sudo install -d -m 700 /etc/z-kt
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))" | sudo tee /etc/z-kt/seed >/dev/null
sudo chmod 600 /etc/z-kt/seed
```

On Render (option C below) it is pasted, once, into the one dashboard field
that asks for it. Either way the seed is generated by you and never goes
into a file in this repository. Back it up **offline** (a lost key means a
new log; a leaked key means a log whose heads anyone can forge — start a
new log in either case, with a new key, and ship the new pin). The public
key is printed when the service starts and is at `GET /kt/v1/pub`; that
endpoint is for reading it off once, not for clients to trust.

### 2. Run it

**Option A — Node directly**, as a system service:

```bash
sudo install -d -o z-kt -g z-kt /var/lib/z-kt
sudo cp -r kt /opt/z-kt
sudo cp kt/deploy/z-kt.service /etc/systemd/system/
sudo systemctl enable --now z-kt
journalctl -u z-kt -n 3     # "z-kt: N entries, M labels; public key …"
```

The unit runs `node server.js` as an unprivileged user with
`KT_SEED_FILE=/etc/z-kt/seed`, `KT_DATA=/var/lib/z-kt` and `KT_PORT=8085`
bound to localhost; the reverse proxy in step 3 is what the world reaches.

**Option B — Docker:**

```bash
cd kt && docker build -t z-kt .
docker run -d --name z-kt --restart unless-stopped \
  -p 127.0.0.1:8085:8085 \
  -v /etc/z-kt/seed:/etc/z-kt/seed:ro -v z-kt-data:/data \
  -e KT_SEED_FILE=/etc/z-kt/seed -e KT_DATA=/data z-kt
```

The image starts as root only to hand the data volume to its service user
and to make a private, readable copy of the root‑only seed file inside the
container, then runs as `z-kt` (`kt/docker-entrypoint.sh`). A volume
mounted from the host, or a cloud host's disk, arrives owned by root, which
is what that is for.

**Option C — Render, from a Blueprint.** `render.kt.yaml` at the repository
root describes the log for [Render](https://render.com): a Docker web
service from `kt/Dockerfile`, a persistent disk mounted at `/data` for the
entries file, and `KT_SEED` marked `sync: false`, so Render asks for it
when the Blueprint is created and it never appears in the file.

1. Dashboard → **New → Blueprint** → this repository → Blueprint Path
   `render.kt.yaml`. Render lists one service, `z-kt`, and one field to
   fill: `KT_SEED`. Paste the 64 hex characters from step 1. Deploy.
2. Logs: `z-kt: 0 entries, 0 labels; public key …` — that base64 string is
   the public key the app will pin. `curl https://z-kt-<hash>.onrender.com/kt/v1/sth`
   returns a signed head; `/health` reports the size.
3. Settings → Custom Domains → add `kt.example.com` (for the public log,
   `kt.zmessengers.com`, which is the app's default). The CNAME at your DNS
   provider and the certificate work exactly as they do for the relay
   (`render.yaml`'s notes; with Cloudflare, DNS‑only until the certificate
   shows valid).

A disk means one instance and a restart on each deploy (a few seconds;
clients retry), and it means a paid instance: about $7 a month plus the
disk. `autoDeployTrigger` is `"off"`, so a push to `main` does not redeploy
a live log — deploy at release tags from the dashboard, as the HA relay
does. Render keeps daily snapshots of the disk; the witness below is the
backup that also verifies you.

### 3. TLS

Options A and B: the same Caddy or nginx pattern as the relay, on its own
name:

```
kt.example.com {
    reverse_proxy 127.0.0.1:8085
}
```

Option C: Render terminates TLS; there is nothing to do. Either way,
`curl https://kt.example.com/kt/v1/sth` returns a signed head.

### 4. Back it up

`/var/lib/z-kt/entries.jsonl` (or `/data/entries.jsonl` on the disk) is
the log. Copy it anywhere; it is append‑only and self‑checking: a restart
replays every line and re‑verifies the **account's own signature** over it,
so a torn file, an edited one, or a line appended by anything that is not
the log is refused rather than served. A mirror (below) is a live backup
that also verifies you.

Before 2026‑09‑14 that sentence was not true, and which half was missing is
worth saying: the signature was checked once, when the publish arrived, and
then dropped. What a replay re‑checked was that the label matched the
account and the hash matched the value — both computed from fields whoever
wrote the line also chose. So anyone who could write this file could forge
an entry for any account in it, and nothing downstream could tell, because
`acct` and `sig` are never served.

What that buys is tamper evidence **on this disk**, not a property a third
party gains: a mirror still cannot check a publish signature, because it is
never given the account key to check it against (§19.6). And somebody who
can write the directory can still remove the entries and the head together
and start over — `KT_MIN_SIZE` is the floor for that, and a mirror run by
somebody else is the real answer.

A publish writes its whole line or none of it: since 2026‑09‑14 the append
loops until every byte is written and truncates back to where the line began
if it cannot, so a failure is a `500` to the sender and an unchanged file
rather than a log that never opens again. It also fsyncs the directory when
it creates the file, because fsyncing a file does not make the name that
finds it durable.

Beside it is `entries.jsonl.head.json`: the last head the log signed,
written before the publish that produced it was answered — and, since
2026‑09‑17, at the very first start, at size 0. On the way back up the log
refuses to start unless the head is signed by its own key and the entries it
replays reproduce that head's root at that size — so a truncated file, a
restored snapshot, a half-finished copy or a head somebody else wrote is
refused rather than signed as a smaller history. **Back both files up
together**; a copy of the entries without the head is a log that will start
and a copy of the head without the entries is one that will not, and the
second is the safer of the two.

The head also records the **signature boundary**: the index from which every
entry must carry the account's publish signature. Lines written before
2026‑09‑14 carry none, and the boundary used to be derived from the file —
an unsigned line was accepted while no earlier line was signed. That let a
fresh deployment, or a pre‑3.4.1 file until its first signed publish, accept
a hand‑written unsigned line naming any account's public key and serve it as
that account's latest under a head the real key signed. The boundary is
recorded now, signed under the log's key with its own context, and a fresh
log records 0 before anything can be appended. A file with entries and no
head adopts its boundary at its first start and writes it down — the one
start at which the file gets to say, which is what `KT_MIN_SIZE` and a copy
of the head are for.

That check cannot see the failure most likely to happen, which is why
`KT_MIN_SIZE` exists. If `KT_DATA` points where the disk did not mount, the
head file goes missing with the entries: the log comes up at size 0, `/health`
answers 200, and it starts signing a brand-new history with the production
key — which every client holding a head reads as a fork, permanently. Set
`KT_MIN_SIZE` to a size the log has comfortably passed and it refuses to
start instead. It is a floor rather than an expected size, so it stays true
as the log grows; raise it when convenient. `0` disables it.

A file an older build tore — a last line that starts and never finishes — is
what `tools/repair.js` is for. Stop the log first; then

```
node tools/repair.js /var/lib/z-kt/entries.jsonl          # say what it would do
node tools/repair.js /var/lib/z-kt/entries.jsonl --write  # do it
```

It removes the bytes after the file's last newline, keeps them in a
`.partial-…` file beside it, and says whether the log opens afterwards. It
will **not** touch anything else: damage inside a complete line is refused
by name, because dropping whole entries to make a log start is a rewrite of
the history rather than a repair — that case needs the backup or the mirror.

### 5. Run a witness — and have someone else run it

A witness is a full mirror of the log that co‑signs every head it has
verified and serves the last one. Every five minutes it fetches the head,
checks the signature, checks that the head extends the last one it
verified, fetches the new entries and re‑derives both roots. If the log
ever signs a history that does not extend what the witness saw — a
rewritten entry, a shrunk log, a fork — it prints `DIVERGENCE`, keeps the
old head, and stops following the log: **a witness that keeps following a
forked log is not a witness.** The head it keeps is the one every client
then checks the log against (§19.5), and the log cannot produce a
consistency proof from it. A witness run by the log's own operator proves
little; the value is in the second party, which is why the Blueprint is
written to be created under someone else's account.

`DIVERGENCE` is permanent, so it is reserved for what the log **signed**. A
dropped connection, an HTTP 502, a cache serving an empty page — those are
ordinary errors: the witness logs them, keeps its head, and tries again at
the next interval. This matters more than it sounds. A witness that cries
fork whenever a packet is lost is worse than no witness at all, because the
first real fork is then dismissed as another one of those, and the whole
point of the thing is that the one time it speaks, somebody believes it. If
you see `DIVERGENCE`, the log signed a head that does not extend what this
witness verified, and that is not something a network can cause.

A witness also repairs itself after an unclean stop. It writes the new
entries and fsyncs them, then puts the head in place, so a machine that dies
between the two leaves entries no head covers. On the next start it says how
many bytes it dropped and fetches them again — those entries sit above the
last head it verified, so nothing it has attested to is touched. The
opposite case, a file with **fewer** entries than the head, it refuses: those
are under a root the log signed, and no witness may invent them. That needs
the file back from a backup, or a fresh directory and a resync.

**As a command:**

```bash
cd kt
node tools/mirror.js --log https://kt.example.com --pub <base64 public key> --dir /var/lib/z-kt-mirror --every 300 --witness-seed-env KT_WITNESS_SEED --serve 8086
```

`--serve` answers `GET /sth.json` with the co‑signed head (the witness URL
clients are given) and `GET /health` with what the mirror knows; without it
the record is written to `<dir>/sth.json` for any static host to serve.
Every option has an environment variable (`KT_LOG_URL`, `KT_LOG_PUB`,
`KT_MIRROR_DIR`, `KT_WITNESS_SEED`, `KT_EVERY`, `KT_SERVE_PORT` or `PORT`),
which is what the Blueprint uses.

**As a Blueprint**, for the person who runs it: Dashboard → **New →
Blueprint** → this repository → Blueprint Path `render.kt-witness.yaml`.
Render asks for two values, both `sync: false`: `KT_LOG_PUB`, the log's
public key, handed over by the log's operator out of band — typing it in
is the act of pinning — and `KT_WITNESS_SEED`, 64 hex characters the
witness's operator generates on their own machine with the command in step
1. `KT_LOG_URL` is in the file (`https://kt.zmessengers.com` for the public
log; change it for another). The same image as the log runs
`node tools/mirror.js`; the disk holds the witness's own copy of every
entry, from which it can be reloaded and re‑verified. A paid instance,
like the log. When it is up, `https://z-kt-witness-<hash>.onrender.com/sth.json`
is the witness URL and the `witness.pub` inside that file is the witness's
public key; the witness's operator hands both to the log's operator for
the client build. `/health` stays 200 after a divergence, deliberately,
with `"diverged": true` — a host that restarted an "unhealthy" witness
would only make it reload the same head and diverge again.

### 6. Point clients at it

Clients ship with the log's URL and public key and the witness's URL and
public key: `KT_LOG_URL`, `KT_LOG_PUB`, `KT_WITNESS_URL` (the `/sth.json`
URL) and `KT_WITNESS_PUB` (`witness.pub` from that file) at build time, and
Settings › Transparency log on a device that uses another.

For **your own** builds either works: `--dart-define=KT_LOG_PUB=…` or the
defaults in `app/lib/core/key_transparency.dart`. For **Z's own releases**
only the second does, and `check_ga.py` enforces it — the `reproducible` job
and every outside rebuild (`REPRODUCIBLE_BUILDS.md`) build with no defines,
so a value on a build command is one the rebuild cannot reproduce, and a
value on a build command can be given to Android and not to Windows. A
self‑hosted client points at a self‑hosted log or at none; the states it
shows in each case are in `adr/0006`.

**The witness address and its key go in together, and a client with one and
not the other has no witness.** Setting `KT_WITNESS_URL` and leaving
`KT_WITNESS_PUB` empty used to give a check that appears in the app, shows a
tick, and has nothing behind it: with no key to compare against, the
co‑signature was checked against the key inside the record, so whoever
answers that address — the log's own operator included — agrees with the log
using a key nobody chose. The client now ignores a half‑set pair outright
and Settings refuses to save one, which is why they are edited on one screen
rather than two.

### What "live" means

G3 in `GA_CHECKLIST.md` reads ✅ when: the service answers over TLS at its
URL; the shipped client pins its public key and has a witness configured;
a mirror run by someone other than the operator has verified a head; and
the operator's own account appears in it. Each is one of the steps above —
with the two Blueprints, steps 2 and 5 are a Blueprint each, and what is
left is a key generated on your machine, a domain, a build, and a friend.
