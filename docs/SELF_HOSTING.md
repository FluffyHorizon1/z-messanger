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
| `MAX_QUEUE_BYTES_PER_USER` | `67108864` | per‑recipient RAM cap (bytes) |
| `MAX_QUEUE_MSGS_PER_USER` | `5000` | per‑recipient RAM cap (count) |
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
**same relay** (or a federated set that shares delivery — not part of v1). The
relay only sees routing hashes and ciphertext, so running your own maximizes
metadata privacy too.

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
a TLS proxy in front for `wss://`, or point Render/Fly at the same setup.

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
  `active_recipients × MAX_QUEUE_BYTES_PER_USER`. Tune the caps for your box.
- **Restarts drop in‑flight messages.** Senders keep them in their device
  outbox and the protocol re‑delivers, but schedule redeploys thoughtfully.
- **No backups needed.** There is nothing on disk to back up. That's the point.
