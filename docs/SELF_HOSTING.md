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
| `QUEUE_TTL_HOURS` | `72` | drop undelivered envelopes after this |
| `SWEEP_INTERVAL_SECONDS` | `60` | expiry sweep cadence |
| `RATE_PER_SEC` / `RATE_BURST` | `80` / `240` | per‑connection token bucket |
| `TLS_CERT` / `TLS_KEY` | — | enable built‑in TLS (paths to PEM) |
| `LOG_LEVEL` | `info` | `info` logs counts/timing only, never content |

## Health & monitoring

`GET /health` returns JSON with uptime, live connection count, number of queued
envelopes, and `"storage":"ram-only"`. Point your uptime monitor at it. There
is deliberately no message‑level logging to monitor — the relay can't see
messages.

## Pointing clients at your relay

In the app: onboarding screen, or Settings → Relay server. Use
`wss://relay.example.com` (TLS) in production. Everyone you talk to must use the
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
presence (`presence:{rid}`) and each recipient's pending queue (`q:{rid}`) live
in Redis, and instances route to each other over Redis pub/sub, so a client can
land on **any** instance and still reach anyone. Redis holds only the same
opaque ciphertext — run it with no persistence so nothing touches disk.

The repo ships this ready to run:

```bash
cd server
docker compose -f docker-compose.ha.yml up --build --scale relay=3
```

That starts Redis (`--save "" --appendonly no` — RAM only), three relay
instances (`REDIS_URL` set, read‑only filesystem), and an nginx load balancer on
`:8080` that round‑robins WebSocket upgrades across them (`nginx.ha.conf`). Put
a TLS proxy in front for `wss://`, or point a cloud host at the same setup.

On Render, `render.ha.yaml` at the repository root is that setup as a
Blueprint: two relay instances on paid compute (a free instance cannot run
more than one copy), Render's own load balancer in front, and a Key Value
instance with persistence off and no public access as the RAM‑only Redis.
Create it from **New → Blueprint** with the Blueprint Path set to
`render.ha.yaml`; `/health` then answers `"coordinator":"redis"` with a
different `instanceId` from one request to the next, and reports
`queuedEnvelopes` as `-1` because the total is not counted across instances.
It differs from the compose file in one choice: the store is `noeviction`, so
when it is full a send is refused — `store_full`, promptly, and the sender's
outbox keeps the message and retries on its own timer — rather than a queue
being evicted after its sender was already told "sent". A full store does
not keep anyone out: logins still succeed, queued envelopes are still
delivered and acknowledged (reads and removals are allowed when memory is
short), so the mailboxes that filled it can be drained and it heals by
itself; `/health` shows `presenceStale` while it lasts and `/metrics`
counts `z_store_full_total`. This relies on Redis 7 script flags: run
Redis 7 or newer, or Valkey (the compose file and the Blueprint do). The per‑recipient caps work the same way at their own level and in
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
  `active_recipients × MAX_QUEUE_BYTES_PER_USER`, in RAM mode and in Redis
  mode alike. Tune the caps for your box; keep the byte cap above one
  envelope (`MAX_ENVELOPE_BYTES` + 256) or the largest envelopes are refused
  everywhere, which the relay warns about at start.
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
grows by roughly the size of the sealed lists it holds (a few KB per publish).

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
the log. Copy it anywhere; it is append‑only and self‑checking (a restart
replays and re‑verifies every line, and refuses to start on a torn or
edited file). A mirror (below) is a live backup that also verifies you.

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
URL) and `KT_WITNESS_PUB` (`witness.pub` from that file) at build time
(`--dart-define`, or the defaults in `app/lib/core/key_transparency.dart`),
and Settings › Transparency log on a device that uses another. A
self‑hosted client points at a self‑hosted log or at none; the states it
shows in each case are in `adr/0006`.

### What "live" means

G3 in `GA_CHECKLIST.md` reads ✅ when: the service answers over TLS at its
URL; the shipped client pins its public key and has a witness configured;
a mirror run by someone other than the operator has verified a head; and
the operator's own account appears in it. Each is one of the steps above —
with the two Blueprints, steps 2 and 5 are a Blueprint each, and what is
left is a key generated on your machine, a domain, a build, and a friend.
