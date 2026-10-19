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
`:8080` (plain `ws://`). Put it behind a TLS‑terminating reverse proxy (below)
and tell it the name clients dial — `RELAY_AUTHORITIES=relay.example.com
docker compose up --build -d` (the compose file passes it through; see
"Authentication names the relay" below). `deploy/vps-install.sh` does all of
this for one domain, Caddy included, and sets `RELAY_AUTHORITIES` to it.

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
Environment=RELAY_AUTHORITIES=relay.example.com
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
`https://<your host>/health` for `"storage":"ram-only"`. The platform's own
hostname is trusted for authentication automatically; a custom domain you add
there needs `RELAY_AUTHORITIES` set to it.

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
Run the relay with `RELAY_AUTHORITIES=relay.example.com` (and `HOST=127.0.0.1`
so it is reachable only through Caddy) — see the note under Nginx.

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
        proxy_set_header Host $http_host;          # as dialled, port included
        proxy_set_header X-Real-IP $remote_addr;   # the client's address (CLIENT_IP_HEADER=x-real-ip)
        proxy_read_timeout 3600s;      # keep idle WebSockets alive
    }
}
```

With this front, **set `RELAY_AUTHORITIES=relay.example.com`** on the relay:
v2 authentication is verified against that name and not against the `Host`
header the proxy forwards (phase 29), so the relay has to be told the name
clients dial. (Before phase 29 the relay read the name off `Host`, and a
`proxy_pass` with no `proxy_set_header Host` quietly rewrote it to
`127.0.0.1:8080`, so every client failed to authenticate; now the header is
not load‑bearing for auth, but pass it through anyway and set
`RELAY_AUTHORITIES`.) This proxy overwrites `X-Real-IP` with the address it
saw, so once the relay is reachable **only** through it (`HOST=127.0.0.1`),
set `CLIENT_IP_HEADER=x-real-ip` and the per‑IP limits are per client; while
the relay's port is reachable directly, leave it unset, since anyone could
then send the header.

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
| `NEW_MAILBOX_PER_MIN` | `120` | how many mailboxes may be **created** a minute, across all senders (since phase 29 a send the unowned limits refuse is not charged) — **per instance**, so N instances admit N× this between them, unless `NEW_MAILBOX_SHARED=on` makes it the figure for the whole relay. Charged on **first contact** with a recipient, not on an empty mailbox — a mailbox exists only while it holds unacknowledged mail, so a recipient who is online and keeping up has none when the next message arrives, and charging that emptiness charged every message (fixed 2026‑09‑14; until then the relay stopped at this number of *messages* a minute, for everyone) |
| `SEEN_MAILBOX_CAP` | `100000` | how many recipients an instance remembers having written to, so the line above can mean "first contact". A memory bound, measured at 117 bytes an entry (11.2 MiB at the default); least recently used are dropped. It is not what bounds a flood — **a send that was refused is never remembered**, so a refused flood leaves the set as it found it |
| `SEEN_MAILBOX_TTL_MIN` | `60` | and for how long a recipient stays remembered. Bounds how long a second flood can re‑use ids whose mailboxes the first one paid for. A recipient who is merely offline is unaffected: their mailbox still exists, and that is checked too |
| `NEW_MAILBOX_SHARED` | off | `on` shares the mailbox‑creation allowance across instances through the store (Redis mode; inert on a single‑instance relay, whose own gate is already relay‑wide). Off, each instance keeps its own bucket, exactly as before this setting existed. **What it rations:** creating a mailbox for a recipient who holds no mail — a send into a mailbox that exists is never charged. **Turning it on makes `NEW_MAILBOX_PER_MIN` the relay‑wide figure:** set it to N × the per‑instance value to keep the total you had (240 for two instances at the default). **What it costs:** a flood that spends the shared minute spends it for every instance — a gate everybody shares is a switch whoever fills it holds (R22, R32) — and an instance that restarts or is added pays first contact again, against that minute, for every recipient it re‑contacts; measured, a restarted instance had all 5 600 of its sends to online contacts refused while a flood held the window (`docs/LOAD.md`, 25.3). The counter is one hash of two integers for the whole relay — a count of creations in the store's current minute, never a routing id. If it cannot be read the instance falls back to its own bucket and counts it (`z_new_mailbox_shared_fallback_total`) |
| `QUEUE_TTL_HOURS` | `72` | drop an undelivered envelope this long after the relay accepted it — per envelope, in both modes |
| `SWEEP_INTERVAL_SECONDS` | `60` | expiry sweep cadence (a flush expires too, before it delivers) |
| `FLUSH_PAGE` | `64` | entries a flush may send before waiting for the socket to drain |
| `FLUSH_HIGH_WATER_BYTES` | `1048576` | bytes it may send before waiting — whichever of the two comes first |
| `ID_SLOTS` | `8` | sealed envelopes that may share one `id` in one mailbox (§12.2) |
| `RATE_PER_SEC` / `RATE_BURST` | `80` / `240` | per‑connection token bucket |
| `TLS_CERT` / `TLS_KEY` | — | enable built‑in TLS (paths to PEM) |
| `RELAY_AUTH_V1` | `on` | whether the unbound v1 authentication is still accepted. A v1 signature is over the challenge alone, so one obtained by any relay a user was talking to authenticated them here (R33); v2 (relay and app from 2026‑09‑17 on) signs the relay's name with it, and a client from then on never produces v1. Every v1 authentication is counted in `z_auth_v1_total`; set `off` once that has stayed at zero for as long as you care to wait — after which a client from before then cannot receive until it updates |
| `RELAY_AUTHORITIES` | — | the names a v2 signature is verified against, comma‑separated (`relay.example`, `relay.example:8443`) — the **only** names, never the `Host` header (phase 29, P1‑16). A public relay MUST set this to every name clients dial. `RENDER_EXTERNAL_HOSTNAME` / `FLY_APP_NAME` are added automatically on those platforms. Unset, a dialled loopback/private/`.local` name is trusted only on a connection from a loopback/private address (dev/LAN); anything else is then refused |
| `METRICS_TOKEN` | — | the bearer token `GET /metrics` requires (`Authorization: Bearer …`, constant‑time compare). **Unset → `/metrics` answers 404**, the safe default: the counters are a presence oracle, so an unauthenticated scrape must learn nothing (P1‑14). Set it to a secret and give your scraper the same value |
| `CLIENT_IP_HEADER` | — | the header a front sets to the real client address (e.g. `cf-connecting-ip`), for the per‑IP limits below. Honoured **only when set**: a forwarded header is the caller's to choose unless a front overwrites it, so unset the socket address is used instead (mirrors `kt/`'s `KT_CLIENT_IP_HEADER`). Behind a front with this unset, every client shares one address and the per‑IP limits collapse to one bucket — the relay‑wide budgets are the real bound then. **Behind a front it MUST be set** (2026‑10‑15): the limits that are enforced only with it (`MAX_CONNECTIONS_PER_IP`, `INTRO_NEW_PER_IP_PER_MIN`) are off without it, and the ones that are not become one bucket everybody shares, which whoever fills it holds against everyone — the second review of the handles fixes (2026‑10‑10) showed a stranger denying every handle owner a flag that way. The shipped blueprints (`render.yaml`, `render.ha.yaml`) leave it to the operator to set to the front's header |
| `UNOWNED_MAILBOX_BYTES` | `2097152` | the byte cap for a mailbox whose owner has never authenticated here (an *unowned* mailbox, P0‑4). Generous for a first contact; small enough that filling the store needs many mailboxes, which `NEW_MAILBOX_PER_MIN` rations. Once the recipient authenticates the mailbox is owned and `MAX_QUEUE_BYTES_PER_USER` applies |
| `UNOWNED_STORE_BYTES` | `33554432` | the whole store's budget for unowned bytes at once — a modest fraction of the store, so first‑contact traffic can never crowd out what owned mailboxes need. Past it an unowned send is refused `store_full` (counted `z_unowned_refused_total`); owned mailboxes are unaffected |
| `UNOWNED_BYTES_PER_IP_PER_MIN` | `4194304` | per‑IP budget on unowned bytes a minute, keyed on `CLIENT_IP_HEADER` or the socket address |
| `OWNED_TTL_DAYS` | `30` | how long a routing id stays *owned* after it last authenticated (Redis path; a store key `owned:{rid}` — the same shape as `q:`/`presence:`, no new identity data, survives a relay restart). RAM mode keeps it in memory, lost with the queue on restart — so until a recipient reconnects after a restart, mail to them is held to the first‑contact caps (refused `store_full` and retried by the sender past them, never lost) |
| `OWNED_CAP` | `200000` | RAM mode only: how many owned routing ids the relay remembers (≈120 bytes each), the least recently authenticated forgotten first, so throwaway identities cannot grow its memory without bound. A forgotten owner's mailbox is merely unowned again until it next authenticates — unless it is a flagged introduction mailbox, which keeps the owned caps, and its flag, while the flag is in force; its flag's shadow keeps the stamp and the intro cap, not the owned caps (`INTRO_CAP`) |
| `INTRO_MAILBOX_BYTES` | `4194304` | the byte cap for an *introduction mailbox* (phase 37, `PROTOCOL.md` §21.6) — the mailbox a handle resolves to, which its owner flags with an `intro` frame — on top of the owned caps; past it a send is refused `queue_full`. Such a mailbox also takes a send only with a proof of work at the difficulty its owner set (refusals counted `z_intro_pow_refused_total`, acceptances `z_intro_accepted_total`, flagged mailboxes `z_intro_mailboxes`), refuses an envelope over 64 KiB (`too_large`), holds a byte‑identical copy of an envelope it already holds only once (answered `sent`, counted `z_intro_duplicate_total`), and is never woken by push. **What the flag stores:** the routing id and that difficulty, one number — in Redis mode a key `intro:{rid}` beside `owned:{rid}`, with twice the `OWNED_TTL_DAYS` from the owner's last `intro` (the flag, then its shadow), surviving a relay restart but not a store that comes back empty; in RAM mode an entry in a store of flags of its own (`INTRO_CAP`), which logins never move, lost on restart (below, "What a restart forgets"). **The flag's shadow** (2026‑10‑15): for `OWNED_TTL_DAYS` after a flag lapses the mailbox still asks the stamp at the last difficulty and is still held to this cap, while the owned caps follow the owner's own logins — so a handle's mailbox whose owner has not drained for a month is not a free inbox for whoever resolved the handle, which it was (the second review of the handles fixes, 2026‑10‑10); the owner's next `intro` renews the shadow into a flag. The stamp a send carries is checked and never logged; one worth at least 16 bits — every stamp a flagged mailbox takes, and one on a send to any other mailbox — is kept with its envelope, 22 characters and the day it was good under, and handed to the owner with it (`pow`, `powDay`), whose app checks it again; what recognises a copy is the payload's SHA‑256 beside each envelope held there (in Redis mode one field `h:<hash>` of that mailbox's `qe:{rid}`), removed with the envelope |
| `INTRO_CAP` | `100000` | how many introduction mailboxes the relay keeps flagged, shadows included — in RAM a store of its own, ≈160 bytes an entry; in Redis mode the `intro:` keys, counted by the sweep. Full, it takes a **new** flag and forgets the entry least recently renewed for it, a shadow before any flag (counted `z_intro_evicted_total`; in Redis mode the sweep does the forgetting, so the store runs past the cap by what one `SWEEP_INTERVAL_SECONDS` brings). A renewal is the owner's own `intro`, sent on every drain and never stood in for by a login (until 2026‑10‑10 a RAM relay kept the flags in the owner map, and `OWNED_CAP` throwaway logins pushed them out, as an independent review of handles found on 2026‑10‑09), so flags nobody renews cycle out first. **What a flood of fresh keys can do:** push an owner's flag out once `INTRO_CAP` flags have been set since the owner's last drain — a relay‑wide rate of the cap per drain interval, about 110 fresh keys a second at the default against an owner draining every 15 minutes, and from some seven hundred client addresses at once when `CLIENT_IP_HEADER` is set (`INTRO_NEW_PER_IP_PER_MIN`) — after which the mailbox is unguarded until that owner's next drain re‑flags it; a steady `z_intro_evicted_total` is that flood. From 2026‑10‑10 to 2026‑10‑15 a full store refused new flags (`intro_full`) instead, which let whoever filled it once deny every owner a flag after a restart for a month (the second review of the handles fixes). Compare `z_intro_mailboxes` with it; raise it (memory is the only cost) to raise the flood's price |
| `INTRO_PER_RID_PER_MIN` | `6` | `intro` frames a minute from one routing id, per instance; past it `rate_limited`, and the flag stays as it was. An owner's app sends one per drain |
| `INTRO_NEW_PER_IP_PER_MIN` | `10` | **new** flags a minute from one client address, per instance — enforced **only when `CLIENT_IP_HEADER` is set**, like `MAX_CONNECTIONS_PER_IP`; past it `rate_limited`. Renewing a flag already held does not count. It is what makes filling the flag store from one address a matter of days rather than minutes. From 2026‑10‑10 to 2026‑10‑15 it was keyed on the socket's address when the header was unset, so behind the shipped proxy it was one bucket for every owner, and a stranger flagging fresh keys ten times a minute denied every honest owner the new flag a restart made them need (the second review of the handles fixes); with the header unset the relay now paces new flags by nothing but `INTRO_CAP`. **What remains:** a stranger behind the same client address as an owner — one carrier‑grade NAT, say — spends that address's minute, and the owner's NEW flag (after a restart, or a first claim) waits for the next minute the stranger leaves free; its renewals are never paced this way, and the shadow keeps a lapsed flag's guard meanwhile |
| `MAX_CONNECTIONS` | `20000` | global cap on open WebSockets this instance holds; past it a new connection is closed (1013). ≈ 11 KB RSS a socket (`docs/CAPACITY.md`), so this also sizes the box |
| `MAX_CONNECTIONS_PER_IP` | `256` | per‑IP connection cap — enforced **only when `CLIENT_IP_HEADER` is set**, since keyed on a shared front address it would cap the whole relay at one number |
| `UNAUTH_IDLE_SECONDS` | `120` | a socket that has not authenticated and has sent nothing for this long is closed. An anonymous sealed‑send socket (ADR 0007) pings every 25 s, which counts as activity, so this closes only a socket doing nothing — not an auth deadline. `0` disables |
| `DRAIN_TIMEOUT_SECONDS` | `60` | how long a flush waits for a slow reader to drain below `FLUSH_HIGH_WATER_BYTES` before terminating it (P1‑13); it reconnects and the flush restarts (at‑least‑once) |
| `SEND_BUFFER_CAP_BYTES` | `8388608` | the most the relay holds buffered and unread for one socket — replies, live deliveries, flush pages — before dropping it (P1‑13: a socket that kept sending and stopped reading grew the relay +880 MiB in 9 s). Mail stays queued until acknowledged, so a reader that resumes reconnects and is flushed again. Keep it above `2 × FLUSH_HIGH_WATER_BYTES` + `MAX_ENVELOPE_BYTES` so an honest slow reader is paged, not dropped |
| `SEND_BUFFER_TOTAL_BYTES` | `67108864` | the most ALL sockets together may hold buffered and unread (P1‑13): the per‑socket cap alone would let N non‑reading sockets hold N × it. Past this the socket holding the most is dropped first — an attacker's, filling towards its cap, before an honest slow reader, which a paged flush keeps near `FLUSH_HIGH_WATER_BYTES`. Size it with `MAX_STORE_BYTES` against the instance's memory |
| `LOG_LEVEL` | `info` | `info` logs counts/timing only, never content |
| `Z_LATEST_VERSION` | — | the newest app version you want your users prompted to update to (24.4). Set it to a plain `x.y.z` and `/latest.json` serves `{"version","url"}`; leave it unset (or non‑semver) and the route 404s, so your users are never prompted. The app checks it at most once a day when Settings is opened, against the host it already dials — no third party, nothing per‑user. The official relay does not set it yet — no Blueprint in this repository does, and its `/latest.json` answered 404 on 2026‑10‑03 — so nobody on it is prompted; a self‑hoster who does not track releases can ignore it. On the official relay, name a version only once Play serves it to everyone: an install from Play opens the Play listing (`adr/0014`), so an earlier announcement tells every Play user of an update Play does not offer, and `check_live_relay.py --play-version x.y.z` fails while it does |

**Authentication names the relay, and the relay verifies against its OWN
name — not the `Host` header (phase 29).** A client signs its challenge answer
over the relay's authority as it dialled it (the URL's host, lower case, with
the port only when it is not the default). The relay checks that against the
names in **`RELAY_AUTHORITIES`** and nothing else: it does **not** trust the
`Host` header a connection carries, because whoever opens the socket chooses
that header, so a relay that verified against it would accept a signature a
victim had been tricked into making for the attacker's name (the splice the
binding exists to stop). **So a public relay MUST set `RELAY_AUTHORITIES` to
every name clients dial** — a self‑hosted relay behind any proxy, and the
reference deployment too. On Render or Fly the platform's own hostname
(`RENDER_EXTERNAL_HOSTNAME`, `FLY_APP_NAME`) is added automatically, so a
relay reached at that address needs nothing. A relay with `RELAY_AUTHORITIES`
unset trusts only a dialled **loopback / private‑range / `.local`** name, and
only on a connection that itself comes from a loopback or private address —
the dev and LAN case, where there is no machine‑in‑the‑middle to protect. A
public name with nothing configured is refused (and counted
`z_auth_v2_refused_total`), and so is a local name presented from a public
address (a signature someone made for a LAN relay, replayed here), rather than
verified against a name the caller picked. So a relay that is fine on
`ws://192.168.1.10:8080` starts refusing everyone the moment it is put behind
a public name — set `RELAY_AUTHORITIES` then. The `Host` header no
longer needs to reach the relay for authentication, so a front may rewrite it
freely. An app from 2026‑09‑17 on refuses a relay that does not advertise the
bound form (its challenge lacks `auth: 2`) and says so in Settings → Relay
server ("relay too old"): **update the relay before the app** on a
self‑hosted deployment, or the app cannot receive until you do.

**Upgrading a relay to 4.0 or later: list every name, the `www.` one too.**
The list is matched exactly against what each client dialled, so
`zmessengers.com` does not cover `www.zmessengers.com`, nor the other way
round, and a name that is missing refuses every client that dials it with
`bad_auth`, at once, however new or old their app — no app update helps,
only the list. The app's default relay address is `wss://www.zmessengers.com`,
so the public relay's list must hold `www.zmessengers.com` as well as
`zmessengers.com` (on 2026‑10‑15 it held the bare name alone, and nobody could
log in until the other was added). The relay says what it needs in two places:
at boot it prints `v2 authentication verified against: …` — the names it
will accept, or `RELAY_AUTHORITIES unset` — and on a refusal whose connection
dialled a name that is none of those it prints that name, quoted, beside the
list it is missing from, once an hour per name, and counts it
(`z_auth_v2_refused_unknown_name_total`). A refusal on a name it does know
is a bad signature (the replay R33 stops) and is counted only.

Every deploy of a relay, then:

1. **Before:** write down every name clients dial — the app's default
   (`wss://www.zmessengers.com` for the public relay), the address installs
   from before 2026‑09‑17 still hold (`wss://zmessengers.com`), and any
   custom domain. The platform's own name (`RENDER_EXTERNAL_HOSTNAME`, or
   `<app>.fly.dev` on Fly) is added for you.
2. **Before:** compare that list with the `RELAY_AUTHORITIES` the live
   service runs, in the dashboard — not only the Blueprint, since a value set
   by hand is what runs. For the public relay, `tool/check_blueprints.py`
   holds `render.ha.yaml` to the app's two default addresses
   (`app/lib/core/relay_url.dart`); it cannot see the dashboard.
3. **After:** read the boot line, `v2 authentication verified against: …`,
   and find every name from step 1 in it.
4. **After:** confirm the relay serving is the one you deployed —
   `METRICS_TOKEN=<token> python3 tool/check_live_relay.py https://<relay>`,
   with `--blueprint render.ha.yaml` for the public relay (see "After a
   deploy" below).
5. **After:** watch `z_auth_v2_refused_unknown_name_total` stay at zero
   through the first hour of traffic; anything else comes with a log line
   naming the name the list is missing.

## Health & monitoring

`GET /health` returns JSON with liveness only — `{"ok":true,"coordinator":…,
"storage":"ram-only","push":…}` — and nothing else (phase 29, P1‑14). It is
unauthenticated, so it must reveal nothing a stranger could read as a signal:
the connection count, queued‑envelope count, store bytes, `presenceStale` and
instance id all moved to `/metrics`, because sending one envelope and watching
a counter tick there was a presence oracle. Point your uptime monitor at
`/health`. There is deliberately no message‑level logging to monitor — the
relay can't see messages.

`GET /metrics` (Prometheus text) now requires `Authorization: Bearer
<METRICS_TOKEN>`; with no token configured it answers **404** (it does not even
admit the endpoint exists). It carries the aggregate `z_*` counters, plus
`z_store_bytes`/`z_store_max_bytes` in single‑instance mode (watch the ratio —
the store‑fill gauge), `z_unowned_refused_total` (the first‑contact flood
signal), `z_presence_stale` (Redis mode), the abuse‑limit counters
`z_slow_reader_closed_total` (sockets dropped for not reading),
`z_connections_refused_total` (connection caps) and `z_idle_closed_total`
(unauthenticated sockets idle past `UNAUTH_IDLE_SECONDS`), and a
`z_relay_info` line whose labels carry the instance id, coordinator and push
state.

**Objectives, alarms, and capacity.** `docs/SLO.md` sets availability and
latency objectives you can measure from `/health` and the `z_*` metrics, with
an error budget for each; `server/alerts.example.yml` is the Prometheus rules
that back them (copy what fits — nothing there is wired into a live system);
and `docs/CAPACITY.md` turns the measured per‑envelope, per‑connection and
per‑published‑list costs into a box size, so you can tell when to raise the
store versus add an instance. The subsection below is the other half of those
rules: what to do when one fires.

### When an alert fires

Each rule in `server/alerts.example.yml` names one of these. They assume the
reference HA shape (`render.ha.yaml`); a single‑instance relay has no store
exporter, so watch `z_store_bytes` against `z_store_max_bytes` on `/metrics`
(`RelayStoreFillHigh`) in place of the Redis rules. Two
things about the store exporter are part of the threat model, not of
monitoring: never enable its key‑level options (`--check-keys` and the like —
they export `q:<routing id>` and `presence:<routing id>` as labels, routing ids
and who is online copied into the metrics system), and keep it, and its
`/metrics`, on the store's private network — it holds the store's credentials
(`docs/SLO.md`, "Watching the store without learning from it").

- **RelayHealthDown** — an instance is not answering `/health`. On the HA pair a
  client just lands on the other instance, so check which instance and whether
  it is restarting (a deploy) or wedged; redeploy it, and confirm the serving
  relay with `python3 tool/check_live_relay.py https://<host>`. If both are
  down, it is the instances, their host or the load balancer — **not the
  store**: `/health` does not touch the store, deliberately, so a store outage
  leaves it green and pages as `RelayStoreDown` instead.
- **RelayMetricsUnread** — Prometheus is not scraping the relay's `/metrics`,
  so every `z_*` alarm is blind. Fix the scrape before trusting a quiet board.
- **RelayStoreDown** (`redis_up == 0`) / **RelaySendInternalErrors**
  (`z_send_internal_error_total`) — the shared store is not answering, or the
  instances cannot reach it: every send is answered `internal` while `/health`
  stays 200. Restore the store (and the network path to it); queued mail is in
  the store's RAM, so a store that **restarted** has lost what it held — the
  senders' outboxes still have it and re‑send. One thing to know: the app treats
  `internal` as connection trouble and retries on its next reconnect, not on a
  timer, so phones may sit on unsent messages after the store is back until
  they reconnect; restarting the relay instances once the store is healthy
  forces that reconnect. **RelayStoreUnwatched** is the exporter not reporting —
  the store's alarms are blind until it is.
- **RelayHealthSlow** — `/health` is slow because the event loop is saturated,
  not because anything is wrong with the data. This is the signal to **add an
  instance** (`docs/CAPACITY.md`, "when to add an instance vs. raise the
  store"), on a box with cores to spare — more instances on the same cores do
  not help.
- **RelayBodyMissing** (`z_body_missing_total`) — envelope bodies are missing
  from under mailboxes that list them: an envelope whose sender was told
  `sent`, gone. One now and then is a race (an acknowledgement landing between
  a flush's two reads) and the rule ignores it; more than a trickle means **the
  store is not running `noeviction`.** Fix its `maxmemory-policy` (both shipped
  configs are `noeviction`; a self‑host that changed it, or an older
  `allkeys-lru` compose file, is the cause) and redeploy the store. The relay
  has already dropped the dangling keys and counted them once.
- **RelayPresenceRefreshFailing / RelayReflushElevated** — the shared store is
  unreachable or slow from the instances, so live cross‑instance delivery is
  failing and being repaired a cycle later (nothing is lost — it is delivered
  on the re‑flush). Check the store's health and the network between it and the
  instances; these clear when the store is reachable again.
- **RelayStoreNearFull / RelayStoreFull** — the backlog is approaching, or has
  reached, the store's `maxmemory`. A full store refuses sends (`store_full`,
  which senders retry) and heals as mailboxes drain, so this is urgent but not
  data loss. **Grow the store**, or lower `MAX_QUEUE_BYTES_PER_USER` so one
  recipient holds less of it (`docs/CAPACITY.md`, "Sizing the Redis store").
  `z_store_full_total` counts the store itself and nothing else — refusals by
  the mailbox‑creation gate reach senders as the same `store_full` but are
  counted as `z_new_mailbox_refused_total`; if both are climbing, suspect a
  flood of undrainable mailboxes rather than real backlog.
- **RelayNewMailboxRefused** (`z_new_mailbox_refused_total`) — the
  mailbox‑creation gate is firing. Zero in ordinary use, so this is either a
  flood of first contacts to routing ids nobody holds (R22 — the gate is doing
  its job; watch the store and let it ride, the junk expires at
  `QUEUE_TTL_HOURS`) or `NEW_MAILBOX_PER_MIN` set too low for a genuinely busy
  first‑contact rate (raise it). Per instance by default, so the count is that
  instance's; with `NEW_MAILBOX_SHARED=on` it is the whole relay's, and a flood
  holding the shared window also refuses first contacts made through an
  instance that has just restarted — a rolling redeploy during a flood is the
  worst moment to have sharing on (`docs/LOAD.md`, 25.3).
- **RelayNewMailboxGateFallback** (`z_new_mailbox_shared_fallback_total`) —
  with sharing on, the shared counter could not be read, so each instance is
  deciding on its own bucket: N× the configured rate while it lasts, never more.
  The store unreachable (see `RelayStoreDown`), or the `z:nm` hash holding
  something that is not a count — delete it and the next creation starts a
  fresh window.
- **RelayAuthV2Refused** (`z_auth_v2_refused_total`) — v2 authentications are
  verifying under none of the relay's names. Almost always a name missing from
  `RELAY_AUTHORITIES` — the `www.` form, a new domain — which shows as
  `z_auth_v2_refused_unknown_name_total` rising with it and the name in the
  log: add the name (see the authentication note above). Refusals with that
  second counter still are the replay the binding stops (R33) and need
  nothing.
- **KtLogDown / KtLogFull / KtDiskLow / KtHealthUnread** — the transparency
  log. `KtDiskLow` is the one to act on early: **entries never expire**, so the
  disk is a one‑way resource — grow it with lead time (`docs/CAPACITY.md`, the
  KT disk table). `KtLogFull` means it is already below `KT_MIN_FREE_BYTES` and
  refusing publishes while still serving reads; grow the disk now. `KtLogDown`
  is a process or host failure — restart it; it replays and re‑verifies its
  head on the way up (the log, step 4). `KtHealthUnread` means the disk figures
  are not arriving — the exporter, its mapping, or a log that reports `full:
  null` because it cannot read its own free space — and the two disk alarms are
  blind until they do (and, since 2026‑10‑04, the memory one).
- **KtMemoryHigh** — the log's resident memory is past three quarters of its
  limit. The log holds every entry in memory for its whole life, so this only
  grows: give the instance more memory before the log outgrows it, because an
  instance that runs out does not slow down — it is killed during the replay,
  on every start, until it is grown (the log's memory, "Running the
  transparency log"). A `KtLogDown` that will not clear, with `/health`
  answering `503 replaying` with `rssBytes` climbing, is this, too late.
- **KtWitnessDiverged** — the one that matters most and the rarest: the witness
  saw the log sign a head that does not extend what it verified. A network blip
  does **not** cause this (it is reserved for what the log signed). Treat it as
  a possible key compromise or a rewritten log: stop trusting new heads, get
  the witness operator and the log operator talking, and follow "Run a witness"
  — the witness keeps its last good head and the clients check against it.
  **KtWitnessDown** is the witness not answering, or its `/health` not being
  read, so a divergence would go unseen — page whoever runs it.
  **KtWitnessBehind** is the softer cousin: the witness has stopped following
  (network, or the log unreachable to it), the head is unattested until it
  catches up; check the witness and the path between it and the log.
  **KtWitnessStale** says the same from the witness's side, and sooner on a
  quiet log: nothing has verified for `KT_STALE_AFTER`. Its `/health`
  `lastError` says why — the log unreachable or past its deadline, an answer
  too large, or a head past `KT_MIRROR_MAX_ENTRIES`, which means the witness
  needs more memory and a higher ceiling, not a restart.

This is files in the repository only; wiring these rules into your Prometheus
and routing their pages is yours, as everything that touches a live system is.

### After a deploy: check that the relay serving is the one you deployed

```bash
METRICS_TOKEN=<your relay's token> python3 tool/check_live_relay.py https://relay.example.com
#   ... and for the reference deployment, whose Blueprint it can also check:
METRICS_TOKEN=<token> python3 tool/check_live_relay.py https://www.zmessengers.com --blueprint render.ha.yaml
```

It reads `/health` and `/metrics` — two GETs — and compares what comes back
against the checkout it is run from: every `z_*` metric this code emits in
every mode must be live, `/health` must answer ok with `storage: ram-only`,
and in Redis mode `z_presence_stale` must be present and zero. `/metrics` is
token‑gated now (P1‑14), so give it the relay's `METRICS_TOKEN` in the
environment (never on the command line). It exits 0 when the serving relay is
at least this checkout, 1 when it is behind or unhealthy, 2 when it could not
be reached, and 3 when the token was missing or wrong — so it belongs in a
deploy script as much as at a prompt. On a release, add `--play-version` with
the version Play serves to everyone (Play Console, production at 100%): it
then also fails while `/latest.json` announces a newer one.

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
proxy in front for `wss://`, or point a cloud host at the same setup, and give
the relays the name clients dial (`RELAY_AUTHORITIES=relay.example.com docker
compose -f docker-compose.ha.yml up …`; the compose file passes it through). Until
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
`render.ha.yaml`; `/health` then answers `"coordinator":"redis"`, and
`/metrics` (with the token) labels `z_relay_info` with a different instance id
from one request to the next and omits `z_queued_envelopes`, because the total
is not counted across instances.
The store is `noeviction`, as the compose file's now is, so
when it is full a send is refused — `store_full`, promptly, and the sender's
outbox keeps the message and retries on its own timer — rather than a queue
being evicted after its sender was already told "sent". A full store does
not keep anyone out: logins still succeed, queued envelopes are still
delivered and acknowledged (reads and removals are allowed when memory is
short), so the mailboxes that filled it can be drained and it heals by
itself; `/metrics` shows `z_presence_stale` while it lasts and counts
`z_store_full_total`. This relies on Redis 7 script flags: run
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

`/metrics` also reports `z_store_bytes` in single‑instance mode — the number
`MAX_STORE_BYTES` is checked against — beside `z_queued_envelopes` (both were
`/health` fields until phase 29). (Redis mode refuses against the store's own
`maxmemory` and keeps no global counter, so the gauge is absent there.) The
two disagreeing is a fault in itself: TTL expiry used to free the mail
without crediting the counter, so a relay that had once been busy refused
every send for ever while reporting no queued envelopes — invisible, because
nothing published the other number.

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
- **A single‑instance relay restart loses accepted‑but‑undelivered mail, for
  good.** The queue is in process RAM only (by design — nothing touches disk),
  so a restart wipes it; and the sender was already told `sent` and has
  **deleted the envelope from its outbox**, so it does not re‑send. The
  recipient simply never gets those messages (the ratchet recovers the session
  but not the dropped payload). This is the cost of the no‑disk promise on one
  box. The HA path (`render.ha.yaml`) keeps the queue in the shared store, so a
  relay **instance** restart loses nothing there — only a *store* restart does.
  Schedule single‑instance redeploys for quiet moments, or run the HA shape.
- **What a restart forgets: which mailboxes are introduction mailboxes.** A
  RAM relay keeps the flags (`INTRO_CAP`) in process memory, their shadows
  with them, so every restart — every deploy — unflags every handle's mailbox
  at once. In Redis mode they are store keys, which outlive a relay instance's
  restart but not the store's own when it keeps nothing on disk, as both
  shipped configurations run it (`render.ha.yaml`'s `persistenceMode: "off"`,
  `docker-compose.ha.yml`'s `--save "" --appendonly no`). A mailbox is flagged
  again when its owner's app next drains it, which is the next time that app
  is in the foreground (`PROTOCOL.md` §21.6, §21.8) — a new flag, which no
  stranger can refuse it: a full store forgets its least recently renewed
  entry rather than refuse, and the per‑address pace is per client address
  or off (`INTRO_CAP`, `INTRO_NEW_PER_IP_PER_MIN` above). Until then the
  relay takes sends to it with no stamp, counted against that mailbox's caps
  — the first‑contact caps, since its ownership went too — and the owner's
  app drops every one of them when it drains, because each arrives without a
  stamp (`pow`, `powDay`). Honest requests are not lost: the app stamps every
  request at the handle's difficulty, and the relay hands a stamp worth 16
  bits on with its envelope whether or not the mailbox is flagged, so they
  arrive with it and pass. The cost of a restart is the unstamped junk the
  relay holds, within the first‑contact caps, until each owner next opens the
  app. (A flag that lapses without a restart — an owner away for a month —
  costs less: its shadow keeps asking the stamp, `PROTOCOL.md` §21.6.)
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

**Memory is the other bound, and it is per entry.** Every entry is in both
trees for the life of the process, and the replay that rebuilds them from the
file runs before the log listens. Measured (`cd kt && node bench/memory.js`,
a real list's 1.1 KB value): **~2.4 KB retained and ~6.5 KB of resident
growth an entry**. The live log's size on 2026‑10‑03 (22,094 entries) replays
in ~187 MiB, and a 512 MiB instance is killed during the replay at **about
131,000 entries** (measured in a 512 MiB cgroup). Until 2026‑10‑04 that was
about 39,000: each entry's small fields were slices of Node's shared 8 KiB
buffer pool and pinned about a slab each — 11.6 KB an entry, 376 MiB for the
same 22,094. An instance that is too small does not slow down; it dies during
the replay, on every start. So **size RAM at 4 KB an entry plus 128 MiB** and
grow it with the log, as the disk. `/health` reports `rssBytes` beside
`memLimitBytes` (the container's limit, or the machine's memory): **alarm
when `rssBytes` passes three quarters of `memLimitBytes`** (`KtMemoryHigh` in
`server/alerts.example.yml`). While the log replays, `/health` answers `503`
with `{"state":"replaying","replayed":n,"rssBytes":…,"memLimitBytes":…}` and
every other route answers `503 starting`, so a slow replay — about a
millisecond an entry on a small machine — shows as one rather than as a port
that will not open; give a host's health check a start‑up grace longer than
that.

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

**Publishing is limited five ways, and the defaults assume a hostile
internet**, because the log accepts a signature from any Ed25519 key and
generating keys is free:

| `PUBLISH_PER_MIN_TOTAL` | 120 | every publish, whatever the source. The gate that stops a flood — a flood uses many accounts, so a per‑account limit does not see one. A minute of first publishes (`PUBLISH_NEW_ACCOUNTS_PER_MIN`, at most half the total) is kept back for first publishes alone, so addresses republishing their own accounts cannot hold it at zero against a new one; it still counts every publish |
| `PUBLISH_PER_MIN` | 30 | per source address. Only per‑**client** if `KT_CLIENT_IP_HEADER` is set (below); otherwise the TLS front is the address and this is one bucket for everybody |
| `PUBLISH_PER_ACCT_PER_DAY` | 20 | per account key, charged only once the signature verifies, so nobody can spend an account's budget but that account |
| `PUBLISH_NEW_ACCOUNTS_PER_MIN` | 10 | first publishes from accounts the log has never held, in total. Charged after the signature and only for a label the index does not have — and the index is built by accepted publishes, so a refused first publish leaves the account unknown |
| `PUBLISH_NEW_ACCOUNTS_PER_ADDR_PER_MIN` | a quarter of the above (3) | one address's share of the first‑publish rate, so that one client cannot take all of it and starve every new account. Behind a proxy with `KT_CLIENT_IP_HEADER` empty every request is one address, and this is then the whole log's first‑publish rate |
| `KT_MAX_VALUE_BYTES` | 32768 | what this log accepts; at most the protocol's 262 144. Sets entries‑per‑gigabyte |
| `KT_MIN_FREE_BYTES` | 67108864 | below this much free space, publishes are refused `503 log_full` and reads continue. `/health` still answers 200 with `full: true`, so a host's health check does not restart a log whose only problem is a disk it cannot grow |
| `KT_MAX_PUBLISH_IN_FLIGHT` | 256 | publish bodies being read at once; a further one is told `503 busy` before anything is read. Not a rate — a request that finishes frees its slot in milliseconds — so it bounds memory (256 × 400 KB) against sockets held open, which the request timeout (a minute) then lets go of |
| `READ_BYTES_PER_MIN` | 33554432 | bytes of `/kt/v1/entries` a minute from one address (32 MiB — eight full pages). Over it, `429` with `retry-after`, before anything is built. Per‑client only with `KT_CLIENT_IP_HEADER`; otherwise one budget for every reader, mirrors included |
| `READ_BYTES_PER_MIN_TOTAL` | 134217728 | the same, for the whole log (128 MiB — four readers' worth). The bound on the log's own CPU and egress whoever asks |

`KT_CLIENT_IP_HEADER` (e.g. `cf-connecting-ip`) is empty by default and should
stay empty until the service is reachable **only** through the proxy that sets
it. A forwarded address is the caller's to choose unless something in front
overwrites it, and a limiter keyed on a value the caller picks is worse than
one keyed on a value they cannot. **Behind Cloudflare it must then be set.**
Empty, every request arrives from Cloudflare's address and every gate above
that says "per address" is one bucket for the internet: one client publishing
thirty times a minute holds every other publish off, new accounts included
(the 2026‑10‑03 analysis). Set, each client has its own, and an IPv6 client
is keyed by its /64, since a host chooses its own last 64 bits. The reference
Blueprint ships it empty (`render.kt.yaml`); setting it on the live log is
item 1 of the housekeeping below.

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
sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin z-kt
sudo install -d -o z-kt -g z-kt /var/lib/z-kt
sudo cp -r kt /opt/z-kt
sudo cp kt/deploy/z-kt.service /etc/systemd/system/
sudo systemctl enable --now z-kt
journalctl -u z-kt -n 3     # "z-kt: N entries, M labels; public key …"
```

The unit runs `node server.js` as that unprivileged user with
`KT_DATA=/var/lib/z-kt` and `KT_PORT=8085` bound to localhost; the reverse
proxy in step 3 is what the world reaches. The seed stays root's: systemd
reads `/etc/z-kt/seed` when the unit starts and hands the service a private
copy (`LoadCredential=kt-seed:/etc/z-kt/seed`), which
`KT_SEED_FILE=%d/kt-seed` names. Until 2026‑10‑04 the unit pointed
`KT_SEED_FILE` at `/etc/z-kt/seed` itself, which the service user cannot
read, and these steps never created the user: followed exactly, they ended
in `EACCES`. `%d` needs systemd 248 or later (Debian 12, Ubuntu 22.04,
RHEL 9). On an older one, replace the unit's two credential lines with
`Environment=KT_SEED_FILE=/etc/z-kt/seed` and let the service's group read
the seed: `sudo chgrp z-kt /etc/z-kt /etc/z-kt/seed && sudo chmod 750
/etc/z-kt && sudo chmod 640 /etc/z-kt/seed`.

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
backup that also verifies you. A restored snapshot does not start until its
head is confirmed ("If the log will not start", below).

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
half-finished copy, entries restored without the head they were signed
under, or a head somebody else wrote is refused rather than signed as a
smaller history. A whole-disk snapshot passes this check: it brings back
the head it was taken with, and the two agree. What refuses it is the
head's age, or `KT_MIN_SIZE` above the snapshot's size (both below).
**Back both files up
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

Neither floor sees a **whole‑disk snapshot** restored: the head comes back
with the entries, the two agree, and both are out of date. Until 2026‑10‑04
such a log started, signed on from the snapshot's size, and every client and
witness holding a later head read the next head as a fork — under the
Blueprint's `KT_MIN_SIZE=1`, every time. Nothing on the disk can tell a
restored snapshot from a log that stopped a minute ago, but the time can: a
running log re‑records its head every ten minutes and at a clean stop, so
the head says when the log last ran, and a start whose head is older than
`KT_MAX_HEAD_AGE_MIN` (default 30; `0` turns the check off) is refused. The
refusal names the head, as `KT_CONFIRM_HEAD=<size>@<ts>`; what to check
before using it is under "If the log will not start", below. A log stopped
on purpose for longer than that — suspended, or down for maintenance — is
refused the same way, and confirmed the same way. A snapshot
restored within half an hour of being taken, and a confirmation given without
checking, still get through — a witness catches both. So does a snapshot
taken before this version first ran: a head an older build wrote was kept
current only by publishes, so the first start after upgrading does not judge
its age, and records a head that carries the promise instead.

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
Nor does it sign anything: it opens the file without the log's key, so a
file with no head beside it is left without one, and the log records its own
when it next starts. Until 2026‑10‑04 it opened the file with a throwaway
key and wrote a head signed by that, which the log then refused to start
against as a head somebody else wrote.

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

Nor can the log it watches stop it quietly. Every request has a deadline
(`KT_FETCH_TIMEOUT`, 30 s), every response a size (8 MiB), every value the
protocol's 256 KiB, and a head a ceiling on the entries it may claim
(`KT_MIRROR_MAX_ENTRIES`; by default what the machine's memory holds at 4 KB
an entry, ~98,000 on 512 MiB). Past any of them the sync fails as an
ordinary error, the head is kept, and the next sync tries again. Until
2026‑10‑04 there was none of the four: a log that accepted the connection
and never answered held the witness for ever, and one answer of whatever
size its operator chose ran it out of memory on every restart — a witness
removed without a fork ever being signed. So `/health` now also says when
the witness has stopped keeping up: `stale: true`, and `ok: false`, once
nothing has verified for `KT_STALE_AFTER` seconds (three intervals). Alarm on
it (`KtWitnessStale`); a witness that has stopped is one nobody is checking
the log against.

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
the client build. Give clients a name the witness's operator controls — that
`onrender.com` address, or a domain of their own. A name in the log
operator's domain works, but it hands the log's operator the path to its
witness: it cannot sign as the witness, but it can withhold the record, or
serve an old one, from a reader it shows a fork to. The public build's
witness is at such a name, `witness.zmessengers.com` (`THREAT_MODEL.md`
R7). `/health` stays 200 after a divergence, deliberately,
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

### Housekeeping for the public log — runbook, 2026‑10‑04

What the 2026‑10‑03 analysis found `kt.zmessengers.com` needs, in the order
to do it. None of it happens by deploying this code: each step is an
operator's change to a live system, and the Blueprint (`render.kt.yaml`)
still ships the old values.

1. **Set `KT_CLIENT_IP_HEADER=cf-connecting-ip`.** Until it is set, every
   per‑address gate is one bucket for everybody (above). One caution: a
   Render service also answers at its `onrender.com` name, where a caller
   sends any header they like. Through that door the per‑address gates are
   no stronger than with the header empty — the total and first‑publish
   gates still bound everything — and closing it takes something in front
   that the origin can check (a secret header added by a Cloudflare rule),
   which the log does not have yet.
2. **Raise `KT_MIN_SIZE`** from 1 to a size the log has comfortably passed:
   `/health`'s `size` less a margin — 20000 against the 22,094 entries of
   2026‑10‑03. It is a floor, so it stays true as the log grows.
3. **Keep an off‑box copy.** Render's daily snapshots live with the disk
   and restore all of it. Copy `entries.jsonl.head.json` and then
   `entries.jsonl` to somewhere else on a schedule — in that order: the
   head is written after its entries and the file only grows, so a copy
   made that way is never shorter than its head. The newer the copy, the
   less a restore can lose. A witness run by somebody else ("Run a
   witness", above) is the better copy, because it verifies as it goes.
4. **Rotate the log key** — about 98% of the live log is CI test identities
   published before the 2026‑09‑14 guard, and a log never forgets, so the
   only clean log is a new one: a new seed ("Generate the signing key"), a
   new service with an empty disk, and a client release that pins its
   public key. It is a release, not a setting, and where the release
   changes the pin it must also forget the old log's head
   (`KeyTransparency.resetHistory`): a client holding a head of 22,000
   entries reads a new log's first head as the log shrinking, a fault
   until the user resets it. Leave the old log running until no shipped
   client pins it.
5. **Watch its memory.** The 22,094 entries hold ~187 MiB, and the Blueprint's
   512 MB instance reaches its end at about 131,000 (above): alarm on
   `rssBytes / memLimitBytes`, and grow the instance before the log needs it.

**If the log will not start** and says its last head is old, that is the
restored‑snapshot check. Before confirming anything, find the largest head
the log has ever signed: a witness's `/health` and `sth.json`, a mirror's
`sth.json`, your monitoring's history of `/health`'s `size`. If none of them
has seen a head larger than the size in the message, start once with the
`KT_CONFIRM_HEAD=<size>@<ts>` it printed, then remove it. If any has, the
snapshot lost entries the log had already signed, and confirming it signs a
fork that every holder of a later head reports, permanently: restore a newer
copy of both files (item 3) and start again. If there is none, that history
is gone, and the honest course is item 4 — a new log and a new key, shipped
in a release — rather than a confirmation.

### What "live" means

G3 in `GA_CHECKLIST.md` reads ✅ when: the service answers over TLS at its
URL; the shipped client pins its public key and has a witness configured;
a mirror run by someone other than the operator has verified a head; and
the operator's own account appears in it. Each is one of the steps above —
with the two Blueprints, steps 2 and 5 are a Blueprint each, and what is
left is a key generated on your machine, a domain, a build, and a friend.

### Running the handle log

Handles (`adr/0015`, PROTOCOL.md §21.5) are registered in a log of their own:
the same `kt/` code and the same Docker image, started with
**`KT_MODE=handles`**. It is a **second service, with its own signing key,
its own disk and its own host name** — never the transparency log's key or
data: heads name no log, so two logs under one key would have
interchangeable heads. A handle log pointed at the transparency log's file
refuses to start and says so; the reverse refuses too, as a file it cannot
read (the transparency log's start is unchanged). `KT_MODE` unset is
the transparency log exactly as above; any value but `handles` refuses to
start.

What it holds and serves: for each handle, the records its owner published —
the owner's key, the introduction mailbox's two keys (Ed25519 and X25519),
the proof‑of‑work level, the recovery commitment — in the clear, because handles are public by design; each
entry's time only to the hour; the owner's signature; nothing else (DATA_MAP).
It holds every update to the owner rule: a publish its owner did not sign is
refused, on the wire and when the log replays its own file, and a witness of
it (below) refuses a log that accepted one. Clients find a handle with the
bucket query (§19.9), which the transparency log answers too.

Everything above about running the transparency log applies — TLS, backups,
the head file and `KT_MIN_SIZE`, `KT_MAX_HEAD_AGE_MIN`, the client‑address
header, `/health` and its alarms — with these differences:

- **Memory and disk.** A record is at most 1 KiB (~155–390 bytes in
  practice), so an entry is a ~0.6 KB line on disk; `KT_MAX_VALUE_BYTES` does
  not matter here. Measured (`node bench/memory.js`, 22,094 entries over
  11,047 handles): **1.81 KB retained an entry**, 167.9 MiB resident; what the
  owner rule keeps is per handle — 64 bytes each (720,896 bytes for 11,047),
  nothing per entry. Size it like the transparency log, at 4 KB an entry plus
  128 MiB.
- **The gates count handles.** `PUBLISH_PER_ACCT_PER_DAY` is one handle's
  publishes a day, and as many recoveries again, counted apart so that whoever
  holds a handle's owner key cannot spend its recovery; `PUBLISH_NEW_ACCOUNTS_PER_MIN` and its per‑address share
  are claims a minute — the rate at which anyone can take names. They bound
  the rate of squatting, not its total (`adr/0015`).
- **The witness.** `node tools/mirror.js --mode handles` (or `KT_MODE=handles`
  for the witness service) mirrors and co‑signs the handle log under its own
  contexts, with its own directory and its own witness key. Until someone runs
  one, the handle log is unwitnessed, as the transparency log is (G3).
- **Repairs.** `KT_MODE=handles node tools/repair.js <entries.jsonl>`, so the
  file is checked under the handle log's rules.

A Blueprint for it — **an operator action**: this repository does not ship
one, because a service's Blueprint is the operator's to create. Save it as a
file of its own in your fork (for example `render.handles.yaml`) and create it
from Dashboard → New → Blueprint, or create the same service by hand:

```yaml
services:
  - type: web
    name: z-handles
    runtime: docker
    dockerfilePath: ./kt/Dockerfile
    dockerContext: ./kt
    plan: starter               # a disk needs a paid instance
    region: frankfurt
    healthCheckPath: /health
    autoDeployTrigger: "off"    # deploy at release tags, as the transparency log
    disk:
      name: z-handles-data
      mountPath: /data
      sizeGB: 10                # ~0.6 KB an entry: millions of handles
    envVars:
      - key: KT_MODE
        value: handles          # the handle log; unset would be the transparency log
      - key: KT_SEED
        sync: false             # a NEW seed, generated on your machine — never the transparency log's
      - key: KT_DATA
        value: /data
      - key: KT_MIN_SIZE
        value: "0"              # raise to a size the log has passed, once it has one
      - key: KT_PORT
        value: "10000"
      - key: KT_HOST
        value: 0.0.0.0
      - key: PUBLISH_PER_MIN
        value: "30"
      - key: PUBLISH_PER_MIN_TOTAL
        value: "120"
      - key: PUBLISH_PER_ACCT_PER_DAY
        value: "20"             # per handle
      - key: PUBLISH_NEW_ACCOUNTS_PER_MIN
        value: "10"             # claims a minute, in total
      - key: KT_MIN_FREE_BYTES
        value: "67108864"
      - key: KT_CLIENT_IP_HEADER
        value: ""               # cf-connecting-ip once it is reachable only through Cloudflare
```

What the operator has to do, none of it done by deploying this code:

1. **Generate a new seed** for it (step 1 above), and keep it apart from the
   transparency log's.
2. **Create the service** from the Blueprint above, with its own host name
   (e.g. `handles.zmessengers.com`) and TLS, and read its public key off its
   log (`z-kt: handle log, … public key …`) or `/kt/v1/pub`.
3. **Pin that key in the app** — `defaultHandleLogUrl` and
   `defaultHandleLogPub` in `app/lib/core/handles.dart` (phase 38), or per
   device in Settings › Developer mode, then Handle service address and key;
   until then the app says handles are unavailable and reads no handle log.
4. **Set `KT_CLIENT_IP_HEADER`** as for the transparency log, once only
   Cloudflare can reach it.
5. **Find a witness operator** for it (`--mode handles`); THREAT_MODEL
   records the handle log as unwitnessed until one co‑signs (R50).
