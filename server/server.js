#!/usr/bin/env node
/**
 * Z relay — a zero-knowledge, RAM-only message relay.
 *
 * Design guarantees:
 *   - The server NEVER writes message data to disk. Undelivered envelopes live
 *     in memory only (process RAM, or a RAM-only Redis when scaling out) and
 *     are wiped on delivery, expiry, or restart.
 *   - The server cannot read messages. Payloads are opaque end-to-end
 *     encrypted blobs produced by the clients (X25519 + Double Ratchet +
 *     XChaCha20-Poly1305). The relay sees only: routing IDs (hashes of public
 *     keys), payload sizes, and timing.
 *   - Clients authenticate with an Ed25519 challenge signature, so only the
 *     holder of a private key can drain the queue addressed to its routing ID.
 *
 * Scaling: set REDIS_URL to run several instances behind one load balancer.
 * They share presence + the pending queue through Redis pub/sub so any
 * instance can deliver to any connected client. Redis holds only the same
 * opaque ciphertext — run it RAM-only (no RDB/AOF) to keep the no-disk promise.
 *
 * There is deliberately NO database and NO payload logging in this file.
 */

'use strict';

const crypto = require('crypto');
const http = require('http');
const https = require('https');
const { WebSocketServer } = require('ws');
const { PushSender } = require('./push.js');
const { LANDING_HTML, PRIVACY_HTML } = require('./pages.js');

// ---------------------------------------------------------------------------
// Configuration (environment variables)
// ---------------------------------------------------------------------------
const CFG = {
  port: intEnv('PORT', 8080),
  host: process.env.HOST || '0.0.0.0',
  maxEnvelopeBytes: intEnv('MAX_ENVELOPE_BYTES', 1_000_000),
  maxQueueBytesPerUser: intEnv('MAX_QUEUE_BYTES_PER_USER', 64 * 1024 * 1024),
  maxQueueMsgsPerUser: intEnv('MAX_QUEUE_MSGS_PER_USER', 5000),
  queueTtlHours: intEnv('QUEUE_TTL_HOURS', 72),
  get queueTtlMs() {
    return this.queueTtlHours * 3600 * 1000;
  },
  sweepIntervalMs: intEnv('SWEEP_INTERVAL_SECONDS', 60) * 1000,
  // Push tokens live this long after their last (re)registration, in both
  // coordinators — the privacy policy promises a 30-day cap.
  pushTtlMs: intEnv('PUSH_TTL_DAYS', 30) * 24 * 3600 * 1000,
  ratePerSec: intEnv('RATE_PER_SEC', 80),
  rateBurst: intEnv('RATE_BURST', 240),
  tlsCert: process.env.TLS_CERT || null,
  tlsKey: process.env.TLS_KEY || null,
  logLevel: process.env.LOG_LEVEL || 'info', // 'silent' | 'info'
  // HA mode: when set, coordinate presence + queue through Redis.
  redisUrl: process.env.REDIS_URL || null,
  instanceId: process.env.INSTANCE_ID || crypto.randomBytes(6).toString('hex'),
};

function intEnv(name, dflt) {
  const v = parseInt(process.env[name] ?? '', 10);
  return Number.isFinite(v) ? v : dflt;
}

function log(...args) {
  if (CFG.logLevel !== 'silent') {
    console.log(new Date().toISOString(), `[${CFG.instanceId}]`, ...args);
  }
}

// ---------------------------------------------------------------------------
// Ed25519 verification with raw 32-byte public keys (no dependencies)
// ---------------------------------------------------------------------------
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function verifyEd25519(rawPub32, message, signature) {
  try {
    if (rawPub32.length !== 32 || signature.length !== 64) return false;
    const key = crypto.createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, rawPub32]),
      format: 'der',
      type: 'spki',
    });
    return crypto.verify(null, message, key, signature);
  } catch {
    return false;
  }
}

const AUTH_CONTEXT = Buffer.from('z-relay-auth-v1:', 'utf8');

function routingIdFromPub(rawPub32) {
  return crypto.createHash('sha256').update(rawPub32).digest('base64url');
}

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------
function sendJson(ws, obj) {
  if (ws && ws.readyState === ws.OPEN) {
    ws.send(JSON.stringify(obj));
    return true;
  }
  return false;
}

function entryToFrame(entry) {
  if (entry.kind === 'receipt') {
    return { t: 'delivered', id: entry.id, to: entry.from, ts: entry.ts };
  }
  // Sealed-sender envelopes carry no sender: `from` is simply absent.
  return entry.from == null
    ? { t: 'msg', id: entry.id, payload: entry.payload, ts: entry.ts }
    : { t: 'msg', id: entry.id, from: entry.from, payload: entry.payload, ts: entry.ts };
}

// ---------------------------------------------------------------------------
// Delivery metrics (RAM only, aggregate only — never per-user, never content)
// ---------------------------------------------------------------------------
const METRICS = {
  enqueuedTotal: 0,
  sealedTotal: 0,
  deliveredLiveTotal: 0,
  ackedTotal: 0,
  latencyBucketsMs: [50, 200, 1000, 5000, 30000],
  latencyCounts: [0, 0, 0, 0, 0, 0], // one per bucket + +Inf
  latencySumMs: 0,
};

function observeAck(entry) {
  METRICS.ackedTotal += 1;
  const ms = Math.max(0, Date.now() - (entry.ts || Date.now()));
  METRICS.latencySumMs += ms;
  let i = METRICS.latencyBucketsMs.findIndex((b) => ms <= b);
  if (i === -1) i = METRICS.latencyCounts.length - 1;
  METRICS.latencyCounts[i] += 1;
}

function renderMetrics(stats) {
  const L = [];
  L.push('# TYPE z_connections gauge');
  L.push(`z_connections ${stats.connections}`);
  L.push('# TYPE z_queued_envelopes gauge');
  L.push(`z_queued_envelopes ${stats.queuedEnvelopes}`);
  L.push('# TYPE z_enqueued_total counter');
  L.push(`z_enqueued_total ${METRICS.enqueuedTotal}`);
  L.push('# TYPE z_sealed_total counter');
  L.push(`z_sealed_total ${METRICS.sealedTotal}`);
  L.push('# TYPE z_delivered_live_total counter');
  L.push(`z_delivered_live_total ${METRICS.deliveredLiveTotal}`);
  L.push('# TYPE z_acked_total counter');
  L.push(`z_acked_total ${METRICS.ackedTotal}`);
  L.push('# TYPE z_delivery_latency_ms histogram');
  let cum = 0;
  METRICS.latencyBucketsMs.forEach((b, i) => {
    cum += METRICS.latencyCounts[i];
    L.push(`z_delivery_latency_ms_bucket{le="${b}"} ${cum}`);
  });
  cum += METRICS.latencyCounts[METRICS.latencyCounts.length - 1];
  L.push(`z_delivery_latency_ms_bucket{le="+Inf"} ${cum}`);
  L.push(`z_delivery_latency_ms_sum ${METRICS.latencySumMs}`);
  L.push(`z_delivery_latency_ms_count ${cum}`);
  return L.join('\n') + '\n';
}

// ---------------------------------------------------------------------------
// Coordinator: MEMORY (single instance — the default)
//
// Behaviourally identical to the original single-process relay: this is what
// the unit tests exercise, and what a lone Render/Fly instance uses.
// ---------------------------------------------------------------------------
class MemoryCoordinator {
  constructor() {
    /** routingId -> live socket */
    this.online = new Map();
    /** routingId -> {entries:[], bytes} */
    this.queues = new Map();
    /** routingId -> {token, platform, ts} — opaque FCM tokens, RAM only */
    this.pushTokens = new Map();
    this.seq = 0;
  }

  get name() {
    return 'memory';
  }

  registerPush(rid, token, platform) {
    this.pushTokens.set(rid, { token, platform, ts: Date.now() });
  }

  unregisterPush(rid) {
    this.pushTokens.delete(rid);
  }

  getPush(rid) {
    return this.pushTokens.get(rid) || null;
  }

  async register(rid, ws) {
    const prev = this.online.get(rid);
    this.online.set(rid, ws);
    return prev; // caller closes it if !== ws
  }

  async unregister(rid, ws) {
    if (this.online.get(rid) === ws) this.online.delete(rid);
  }

  _queueFor(id) {
    let q = this.queues.get(id);
    if (!q) {
      q = { entries: [], bytes: 0 };
      this.queues.set(id, q);
    }
    return q;
  }

  _enqueue(rid, entry) {
    const q = this._queueFor(rid);
    q.entries.push(entry);
    q.bytes += entry.size;
    while (
      q.entries.length > CFG.maxQueueMsgsPerUser ||
      q.bytes > CFG.maxQueueBytesPerUser
    ) {
      const dropped = q.entries.shift();
      q.bytes -= dropped.size;
    }
  }

  _removeEntry(rid, predicate) {
    const q = this.queues.get(rid);
    if (!q) return null;
    const idx = q.entries.findIndex(predicate);
    if (idx === -1) return null;
    const [entry] = q.entries.splice(idx, 1);
    q.bytes -= entry.size;
    if (q.entries.length === 0) this.queues.delete(rid);
    return entry;
  }

  async deliverEnqueue(from, to, id, payload) {
    const entry = {
      seq: ++this.seq,
      kind: 'msg',
      id,
      from, // null for sealed-sender envelopes
      payload,
      ts: Date.now(),
      size: payload.length + 256,
    };
    METRICS.enqueuedTotal += 1;
    if (from == null) METRICS.sealedTotal += 1;
    this._enqueue(to, entry);
    const target = this.online.get(to);
    const live = target ? sendJson(target, entryToFrame(entry)) : false;
    if (live) METRICS.deliveredLiveTotal += 1;
    return { queued: !live };
  }

  async ack(recipient, from, id) {
    // Sealed envelopes are acked by id alone (the relay never knew a sender);
    // legacy envelopes still match on (from, id).
    const entry = this._removeEntry(
      recipient,
      (e) =>
        e.kind === 'msg' &&
        e.id === id &&
        (from ? e.from === from : e.from == null)
    );
    if (!entry) return;
    observeAck(entry);
    if (entry.from == null) return; // sealed: receipts travel E2E instead
    const receipt = {
      seq: ++this.seq,
      kind: 'receipt',
      id,
      from: recipient, // who confirmed receipt
      ts: Date.now(),
      size: 192,
    };
    const senderWs = this.online.get(from);
    if (!(senderWs && sendJson(senderWs, entryToFrame(receipt)))) {
      this._enqueue(from, receipt);
    }
  }

  async flush(rid, ws) {
    const q = this.queues.get(rid);
    if (!q) return;
    for (const e of q.entries) sendJson(ws, entryToFrame(e));
    for (const r of q.entries.filter((e) => e.kind === 'receipt')) {
      this._removeEntry(rid, (e) => e.seq === r.seq);
    }
  }

  sweep() {
    const cutoff = Date.now() - CFG.queueTtlMs;
    for (const [rid, q] of this.queues) {
      const kept = q.entries.filter((e) => e.ts >= cutoff);
      if (kept.length !== q.entries.length) {
        q.entries = kept;
        q.bytes = kept.reduce((s, e) => s + e.size, 0);
        if (kept.length === 0) this.queues.delete(rid);
      }
    }
    const pushCutoff = Date.now() - CFG.pushTtlMs;
    for (const [rid, rec] of this.pushTokens) {
      if (rec.ts < pushCutoff) this.pushTokens.delete(rid);
    }
  }

  async heartbeat() {}

  stats() {
    let n = 0;
    for (const q of this.queues.values()) n += q.entries.length;
    return { connections: this.online.size, queuedEnvelopes: n };
  }

  async close() {}
}

// ---------------------------------------------------------------------------
// Coordinator: REDIS (horizontal scale across many instances)
//
// Presence:  presence:{rid} = instanceId (EX 60, refreshed by heartbeat)
// Queue:     q:{rid} = Redis LIST of opaque entries, TTL = QUEUE_TTL_HOURS
// Routing:   each instance subscribes to z:inst:{instanceId}; to deliver to a
//            socket on another instance we publish {op:'deliver',...} to its
//            channel. A new login elsewhere publishes {op:'kick'} so the old
//            instance drops its socket (one active connection per identity).
//
// Redis only ever holds the same base64 ciphertext the RAM queue held — no
// plaintext, no keys. Run Redis RAM-only (--save "" --appendonly no).
// ---------------------------------------------------------------------------
class RedisCoordinator {
  constructor(url, instanceId) {
    const IORedis = require('ioredis');
    this.id = instanceId;
    this.cmd = new IORedis(url, { maxRetriesPerRequest: 3, lazyConnect: false });
    this.sub = new IORedis(url, { maxRetriesPerRequest: 3, lazyConnect: false });
    this.pub = new IORedis(url, { maxRetriesPerRequest: 3, lazyConnect: false });
    this.local = new Map(); // rid -> ws on THIS instance
    this.chan = `z:inst:${this.id}`;
    for (const c of [this.cmd, this.sub, this.pub]) c.on('error', () => {});
    this.sub.subscribe(this.chan).catch(() => {});
    this.sub.on('message', (_ch, msg) => this._onPub(msg));
  }

  get name() {
    return 'redis';
  }

  _onPub(msg) {
    let m;
    try {
      m = JSON.parse(msg);
    } catch {
      return;
    }
    if (m.op === 'deliver') {
      const ws = this.local.get(m.toRid);
      if (ws) sendJson(ws, m.frame);
    } else if (m.op === 'kick') {
      const ws = this.local.get(m.rid);
      if (ws) {
        try {
          ws.close(4002, 'replaced by new connection');
        } catch {}
      }
      this.local.delete(m.rid);
    }
  }

  async register(rid, ws) {
    const prevLocal = this.local.get(rid);
    this.local.set(rid, ws);
    const owner = await this.cmd.get(`presence:${rid}`);
    if (owner && owner !== this.id) {
      // Kick the socket living on another instance.
      await this.pub.publish(`z:inst:${owner}`, JSON.stringify({ op: 'kick', rid }));
    }
    await this.cmd.set(`presence:${rid}`, this.id, 'EX', 60);
    return prevLocal;
  }

  async unregister(rid, ws) {
    if (this.local.get(rid) === ws) {
      this.local.delete(rid);
      const owner = await this.cmd.get(`presence:${rid}`);
      if (owner === this.id) await this.cmd.del(`presence:${rid}`);
    }
  }

  // Opaque FCM tokens, shared across instances. 30-day TTL; refreshed each
  // time the client registers. Holds a device push token only — no keys, no
  // message content.
  async registerPush(rid, token, platform) {
    await this.cmd.set(`push:${rid}`, JSON.stringify({ token, platform }), 'PX', CFG.pushTtlMs);
  }

  async unregisterPush(rid) {
    await this.cmd.del(`push:${rid}`);
  }

  async getPush(rid) {
    const s = await this.cmd.get(`push:${rid}`);
    if (!s) return null;
    try {
      return JSON.parse(s);
    } catch {
      return null;
    }
  }

  async _push(rid, entry) {
    const key = `q:${rid}`;
    await this.cmd.rpush(key, JSON.stringify(entry));
    await this.cmd.ltrim(key, -CFG.maxQueueMsgsPerUser, -1);
    await this.cmd.expire(key, CFG.queueTtlHours * 3600);
  }

  async deliverEnqueue(from, to, id, payload) {
    const entry = { kind: 'msg', id, from, payload, ts: Date.now() };
    METRICS.enqueuedTotal += 1;
    if (from == null) METRICS.sealedTotal += 1;
    await this._push(to, entry);
    const owner = await this.cmd.get(`presence:${to}`);
    let live = false;
    if (owner === this.id) {
      const ws = this.local.get(to);
      live = ws ? sendJson(ws, entryToFrame(entry)) : false;
    } else if (owner) {
      await this.pub.publish(
        `z:inst:${owner}`,
        JSON.stringify({ op: 'deliver', toRid: to, frame: entryToFrame(entry) })
      );
      live = true; // best-effort; entry stays queued until acked either way
    }
    if (live) METRICS.deliveredLiveTotal += 1;
    return { queued: !live };
  }

  async ack(recipient, from, id) {
    const key = `q:${recipient}`;
    const items = await this.cmd.lrange(key, 0, -1);
    let removed = null;
    for (const s of items) {
      let e;
      try {
        e = JSON.parse(s);
      } catch {
        continue;
      }
      if (
        e.kind === 'msg' &&
        e.id === id &&
        (from ? e.from === from : e.from == null)
      ) {
        await this.cmd.lrem(key, 1, s);
        removed = e;
        break;
      }
    }
    if (!removed) return;
    observeAck(removed);
    if (removed.from == null) return; // sealed: no relay receipt possible
    const receipt = { kind: 'receipt', id, from: recipient, ts: Date.now() };
    const owner = await this.cmd.get(`presence:${from}`);
    if (owner === this.id) {
      const ws = this.local.get(from);
      if (!(ws && sendJson(ws, entryToFrame(receipt)))) await this._push(from, receipt);
    } else if (owner) {
      await this.pub.publish(
        `z:inst:${owner}`,
        JSON.stringify({ op: 'deliver', toRid: from, frame: entryToFrame(receipt) })
      );
    } else {
      await this._push(from, receipt);
    }
  }

  async flush(rid, ws) {
    const key = `q:${rid}`;
    const items = await this.cmd.lrange(key, 0, -1);
    for (const s of items) {
      let e;
      try {
        e = JSON.parse(s);
      } catch {
        continue;
      }
      sendJson(ws, entryToFrame(e));
      if (e.kind === 'receipt') await this.cmd.lrem(key, 1, s);
    }
  }

  sweep() {} // Redis key TTL handles expiry.

  async heartbeat() {
    for (const rid of this.local.keys()) {
      await this.cmd.set(`presence:${rid}`, this.id, 'EX', 60);
    }
  }

  stats() {
    // Global totals aren't counted per-instance to stay cheap; report local.
    return { connections: this.local.size, queuedEnvelopes: -1 };
  }

  async close() {
    for (const c of [this.cmd, this.sub, this.pub]) {
      try {
        await c.quit();
      } catch {}
    }
  }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------
// Stable object so tests that destructure `_internal` at import time still see
// the live maps once createServer() populates them (memory coordinator only).
const _internal = { queues: null, online: null };

function createServer(opts = {}) {
  const coord =
    opts.coordinator ||
    (CFG.redisUrl
      ? new RedisCoordinator(CFG.redisUrl, CFG.instanceId)
      : new MemoryCoordinator());
  if (coord instanceof MemoryCoordinator) {
    _internal.queues = coord.queues;
    _internal.online = coord.online;
  }

  // Optional push: enabled only when a valid FCM service account is configured.
  // Tests can inject a fake via opts.pushSender; pass null to force-disable.
  const pushSender = 'pushSender' in opts ? opts.pushSender : PushSender.fromEnv();

  const requestListener = (req, res) => {
    if (req.url === '/health') {
      const s = coord.stats();
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          ok: true,
          uptimeSec: Math.floor(process.uptime()),
          instanceId: CFG.instanceId,
          coordinator: coord.name,
          connections: s.connections,
          queuedEnvelopes: s.queuedEnvelopes,
          storage: 'ram-only',
          push: pushSender ? 'enabled' : 'disabled',
        })
      );
      return;
    }
    if (req.url === '/metrics') {
      // Aggregate delivery SLIs only — no per-user data, no content, RAM only.
      res.writeHead(200, { 'content-type': 'text/plain; version=0.0.4' });
      res.end(renderMetrics(coord.stats()));
      return;
    }
    // Static pages (embedded strings — the relay still never touches disk).
    if (req.url === '/' || req.url === '/index.html') {
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'public, max-age=300',
      });
      res.end(LANDING_HTML);
      return;
    }
    if (req.url === '/privacy' || req.url === '/privacy/') {
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'public, max-age=300',
      });
      res.end(PRIVACY_HTML);
      return;
    }
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('Z relay. Zero-knowledge, RAM-only. Connect via WebSocket.\n');
  };

  let httpServer;
  if (CFG.tlsCert && CFG.tlsKey) {
    const fs = require('fs'); // used ONLY to read TLS material, never to write
    httpServer = https.createServer(
      { cert: fs.readFileSync(CFG.tlsCert), key: fs.readFileSync(CFG.tlsKey) },
      requestListener
    );
  } else {
    httpServer = http.createServer(requestListener);
  }

  const wss = new WebSocketServer({
    server: httpServer,
    maxPayload: CFG.maxEnvelopeBytes + 4096,
  });

  wss.on('connection', (ws) => {
    const state = {
      authed: false,
      rid: null,
      nonce: crypto.randomBytes(32),
      tokens: CFG.rateBurst,
      lastRefill: Date.now(),
    };
    ws.zAlive = true;

    ws.on('error', () => {
      try {
        ws.terminate();
      } catch {}
    });
    ws.on('pong', () => (ws.zAlive = true));

    sendJson(ws, { t: 'challenge', nonce: state.nonce.toString('base64') });

    ws.on('message', (data) => {
      // Rate limit (synchronous, before any async work).
      const now = Date.now();
      state.tokens = Math.min(
        CFG.rateBurst,
        state.tokens + ((now - state.lastRefill) / 1000) * CFG.ratePerSec
      );
      state.lastRefill = now;
      if (state.tokens < 1) {
        sendJson(ws, { t: 'error', code: 'rate_limited' });
        return;
      }
      state.tokens -= 1;

      let frame;
      try {
        frame = JSON.parse(data.toString('utf8'));
      } catch {
        sendJson(ws, { t: 'error', code: 'bad_json' });
        return;
      }
      handleFrame(ws, state, coord, frame, pushSender).catch(() => {
        sendJson(ws, { t: 'error', code: 'internal' });
      });
    });

    ws.on('close', () => {
      if (state.rid) coord.unregister(state.rid, ws).catch(() => {});
    });
  });

  const heartbeat = setInterval(() => {
    for (const ws of wss.clients) {
      if (ws.zAlive === false) {
        ws.terminate();
        continue;
      }
      ws.zAlive = false;
      try {
        ws.ping();
      } catch {}
    }
    coord.heartbeat().catch(() => {});
  }, 25_000);
  heartbeat.unref();

  const sweeper = setInterval(() => coord.sweep(), CFG.sweepIntervalMs);
  sweeper.unref();

  httpServer.on('close', () => {
    clearInterval(heartbeat);
    clearInterval(sweeper);
    coord.close().catch(() => {});
  });

  return { httpServer, wss, coordinator: coord };
}

async function handleFrame(ws, state, coord, frame, pushSender) {
  switch (frame.t) {
    case 'auth': {
      if (state.authed) return;
      let pub, sig;
      try {
        pub = Buffer.from(String(frame.pub), 'base64');
        sig = Buffer.from(String(frame.sig), 'base64');
      } catch {
        sendJson(ws, { t: 'error', code: 'bad_auth' });
        ws.close(4001, 'bad auth');
        return;
      }
      const msg = Buffer.concat([AUTH_CONTEXT, state.nonce]);
      if (!verifyEd25519(pub, msg, sig)) {
        sendJson(ws, { t: 'error', code: 'bad_auth' });
        ws.close(4001, 'bad auth');
        return;
      }
      state.authed = true;
      state.rid = routingIdFromPub(pub);
      const prev = await coord.register(state.rid, ws);
      if (prev && prev !== ws) {
        try {
          prev.close(4002, 'replaced by new connection');
        } catch {}
      }
      sendJson(ws, { t: 'ready', id: state.rid });
      await coord.flush(state.rid, ws);
      log('client authenticated; local connections =', coord.stats().connections);
      break;
    }

    case 'send': {
      if (!state.authed) {
        sendJson(ws, { t: 'error', code: 'not_authed' });
        return;
      }
      const to = String(frame.to || '');
      const id = String(frame.id || '');
      const payload = String(frame.payload || '');
      if (!to || !id || id.length > 64 || !payload) {
        sendJson(ws, { t: 'error', code: 'bad_send', id });
        return;
      }
      if (payload.length > CFG.maxEnvelopeBytes) {
        sendJson(ws, { t: 'error', code: 'too_large', id });
        return;
      }
      // Sealed-sender envelopes ('zs1.' prefix) are stored and delivered with
      // NO sender attribution: the recipient learns the sender only inside the
      // encrypted envelope, so a full copy of this server yields no social
      // graph. Authenticity is enforced end-to-end by the inner ratchet.
      const anon = payload.startsWith('zs1.');
      const { queued } = await coord.deliverEnqueue(
        anon ? null : state.rid,
        to,
        id,
        payload
      );
      sendJson(ws, { t: 'sent', id, queued });
      // Recipient offline and push configured? Fire a content-free wake ping.
      // Best-effort and non-blocking — never delays or fails the send.
      if (queued && pushSender) {
        const rec = await coord.getPush(to);
        if (rec && rec.token) {
          pushSender
            .sendWake(rec.token)
            .then((r) => {
              if (r && r.retiredToken) Promise.resolve(coord.unregisterPush(to)).catch(() => {});
            })
            .catch(() => {});
        }
      }
      break;
    }

    case 'push-register': {
      if (!state.authed) {
        sendJson(ws, { t: 'error', code: 'not_authed' });
        return;
      }
      const token = String(frame.token || '');
      const platform = String(frame.platform || 'unknown').slice(0, 16);
      if (!token || token.length > 4096) {
        sendJson(ws, { t: 'error', code: 'bad_push' });
        return;
      }
      await coord.registerPush(state.rid, token, platform);
      sendJson(ws, { t: 'push-ok' });
      break;
    }

    case 'push-unregister': {
      if (!state.authed) return;
      await coord.unregisterPush(state.rid);
      sendJson(ws, { t: 'push-ok' });
      break;
    }

    case 'recv': {
      if (!state.authed) return;
      // `from` absent/empty = a sealed envelope being acked by id alone.
      await coord.ack(state.rid, String(frame.from || ''), String(frame.id || ''));
      break;
    }

    case 'ping': {
      sendJson(ws, { t: 'pong', ts: Date.now() });
      break;
    }

    default:
      sendJson(ws, { t: 'error', code: 'unknown_frame' });
  }
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------
if (require.main === module) {
  const { httpServer } = createServer();
  httpServer.listen(CFG.port, CFG.host, () => {
    log(
      `Z relay listening on ${CFG.host}:${CFG.port} ` +
        `(${CFG.redisUrl ? 'HA/redis' : 'single/RAM-only'}, zero-knowledge)`
    );
  });
  const shutdown = () => {
    log('shutting down; queued envelopes are wiped with process/Redis memory');
    httpServer.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 2000).unref();
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

module.exports = {
  createServer,
  CFG,
  routingIdFromPub,
  MemoryCoordinator,
  RedisCoordinator,
  PushSender,
  _internal,
};
