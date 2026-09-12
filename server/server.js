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
const {
  ROUTES,
  SECURITY_TXT,
  FAVICON_SVG,
  FAVICON_ICO,
} = require('./pages.js');

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
  // A reconnecting device's backlog is flushed in pages, and the next page
  // waits until the socket has drained below this many bytes: a slow reader
  // costs the relay one page plus this, never its whole backlog.
  flushPage: intEnv('FLUSH_PAGE', 64),
  flushHighWaterBytes: intEnv('FLUSH_HIGH_WATER_BYTES', 1024 * 1024),
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

/**
 * Waits until the socket's buffered output is below the high-water mark
 * (or the socket is gone). A flush of a large backlog calls this between
 * pages, so what the relay holds for a slow reader is bounded by a page and
 * the mark rather than by the backlog. Resolves true while the socket is
 * still open.
 */
async function drained(ws) {
  while (ws.readyState === ws.OPEN && ws.bufferedAmount > CFG.flushHighWaterBytes) {
    await new Promise((r) => setTimeout(r, 20));
  }
  return ws.readyState === ws.OPEN;
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
  // Sealed envelopes that arrived on a connection that never authenticated —
  // the ones this process could not attribute to a sender even if it wanted
  // to. A sealed envelope on an AUTHENTICATED connection is attributable by
  // whoever runs the process (the connection has an identity), which is why
  // clients send sealed envelopes on a connection of their own (§12.1).
  sealedUnattributableTotal: 0,
  // Envelopes refused because the recipient's queue was at its cap (count or
  // bytes). Refused, not dropped: the sender is told, keeps the envelope in
  // its outbox and retries; nothing already queued is touched.
  refusedTotal: 0,
  // Sends the shared store refused for want of memory (Redis mode, the
  // store at maxmemory with noeviction): the sender is told store_full and
  // retries later; the store heals as recipients drain their mailboxes.
  storeFullTotal: 0,
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
  L.push('# TYPE z_sealed_unattributable_total counter');
  L.push(`z_sealed_unattributable_total ${METRICS.sealedUnattributableTotal}`);
  L.push('# TYPE z_refused_total counter');
  L.push(`z_refused_total ${METRICS.refusedTotal}`);
  L.push('# TYPE z_store_full_total counter');
  L.push(`z_store_full_total ${METRICS.storeFullTotal}`);
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

  /**
   * Appends an entry to a recipient's queue, or refuses it — returns false —
   * when it would take the queue past either cap. A full queue refuses the
   * newest envelope rather than evicting the oldest: the sender is told and
   * keeps the envelope in its outbox, whereas an evicted envelope was already
   * acknowledged with `sent` and would vanish without anyone knowing. That
   * also means nobody can erase what is queued for a mailbox by flooding it
   * (§12.4): a flood fills the queue and is refused from then on, loudly.
   */
  _enqueue(rid, entry) {
    const q = this._queueFor(rid);
    if (
      q.entries.length + 1 > CFG.maxQueueMsgsPerUser ||
      q.bytes + entry.size > CFG.maxQueueBytesPerUser
    ) {
      if (q.entries.length === 0) this.queues.delete(rid);
      return false;
    }
    q.entries.push(entry);
    q.bytes += entry.size;
    return true;
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
    if (!this._enqueue(to, entry)) {
      METRICS.refusedTotal += 1;
      return { queued: false, refused: true };
    }
    METRICS.enqueuedTotal += 1;
    if (from == null) METRICS.sealedTotal += 1;
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
      this._enqueue(from, receipt); // a full sender queue loses the receipt, not a message
    }
  }

  async flush(rid, ws) {
    const q = this.queues.get(rid);
    if (!q) return;
    // A snapshot: acks arriving while a page drains mutate the live array.
    const entries = q.entries.slice();
    for (let i = 0; i < entries.length; i += CFG.flushPage) {
      if (!(await drained(ws))) return;
      for (const e of entries.slice(i, i + CFG.flushPage)) {
        sendJson(ws, entryToFrame(e));
        if (e.kind === 'receipt') this._removeEntry(rid, (x) => x.seq === e.seq);
      }
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
// Queue:     q:{rid}  = Redis LIST of entry keys ("m:<id>" for an envelope,
//            "r:<id>" for a receipt), in arrival order;
//            qe:{rid} = HASH entry key -> the opaque entry itself.
//            Both TTL = QUEUE_TTL_HOURS. An acknowledgement is then one HGET
//            and one small script rather than a read of the whole mailbox:
//            until 2.7.9 the list held the entries themselves and every ack
//            read all of them back to find one (bench/drain.js — a mailbox
//            of two hundred took 170 times its size in reads to drain, and
//            one of five hundred did not finish). Elements queued by that
//            relay are still in some stores: an element that begins with
//            "{" is such an entry and is read and removed the old way.
// Routing:   each instance subscribes to z:inst:{instanceId}; to deliver to a
//            socket on another instance we publish {op:'deliver',...} to its
//            channel. A new login elsewhere publishes {op:'kick'} so the old
//            instance drops its socket (one active connection per identity).
//
// Bytes:     qb:{rid} = the sum of the entries' sizes in q:{rid}, kept beside
//            the list so the byte cap can be checked without reading it. Both
//            keys are written in one script and carry the same TTL, so they
//            expire together; the counter is reset whenever the list is empty
//            and clamped at zero, so an entry it never counted (one queued by
//            a relay older than this) cannot leave it wrong for longer than
//            the list is non-empty.
//
// Redis only ever holds the same base64 ciphertext the RAM queue held — no
// plaintext, no keys. Run Redis RAM-only (--save "" --appendonly no).
// ---------------------------------------------------------------------------

// The store at its own limit (maxmemory, noeviction — render.ha.yaml): Redis
// refuses every command that could take memory, which is the push below and
// a presence write, and allows every command that reads or frees, which is
// a flush, an ack and a removal. The scripts say so explicitly with Redis 7
// flags: the push carries none and is refused up front when the store is
// full (no half-applied script); the removal is `allow-oom` because it only
// frees. Measured on Redis 7.0 before this was written: a script without
// the flag whose first write is LREM is in fact allowed its later DECRBY —
// Redis will not stop a script that has already written — so the flag
// states a property the relay was already leaning on. Redis 7 or Valkey.
//
// KEYS[1] = q:{rid}, KEYS[2] = qe:{rid}, KEYS[3] = qb:{rid}; ARGV = the entry
// key, the entry JSON, its size, the count cap, the byte cap, the TTL in
// seconds. Returns 1 if stored, 2 if an entry with that key is already
// held (a sender retrying after a lost `sent`: nothing is stored twice and
// the retry is acknowledged), 0 if the queue is full — decided and applied
// atomically, so two instances pushing at once cannot both squeeze past
// the cap.
const REDIS_PUSH_LUA = `#!lua
if redis.call('HEXISTS', KEYS[2], ARGV[1]) == 1 then return 2 end
local len = redis.call('LLEN', KEYS[1])
local bytes = 0
if len > 0 then bytes = tonumber(redis.call('GET', KEYS[3]) or '0') end
if len + 1 > tonumber(ARGV[4]) or bytes + tonumber(ARGV[3]) > tonumber(ARGV[5]) then
  return 0
end
redis.call('RPUSH', KEYS[1], ARGV[1])
redis.call('HSET', KEYS[2], ARGV[1], ARGV[2])
if len == 0 then
  redis.call('SET', KEYS[3], ARGV[3])
else
  redis.call('INCRBY', KEYS[3], ARGV[3])
end
redis.call('EXPIRE', KEYS[1], ARGV[6])
redis.call('EXPIRE', KEYS[2], ARGV[6])
redis.call('EXPIRE', KEYS[3], ARGV[6])
return 1`;

// KEYS as above; ARGV = the entry key, its size. Removes the entry and takes
// its size off the counter, clamping at zero; an emptied list deletes all
// three keys, and an adjusted counter inherits the list's remaining TTL so
// it never outlives the list. Returns 1 if something was removed.
const REDIS_REMOVE_LUA = `#!lua flags=allow-oom
if redis.call('HDEL', KEYS[2], ARGV[1]) == 0 then return 0 end
redis.call('LREM', KEYS[1], 1, ARGV[1])
if redis.call('LLEN', KEYS[1]) == 0 then
  redis.call('DEL', KEYS[1], KEYS[2], KEYS[3])
  return 1
end
local left = redis.call('DECRBY', KEYS[3], ARGV[2])
if left < 0 then redis.call('SET', KEYS[3], '0') end
local ttl = redis.call('TTL', KEYS[1])
if ttl > 0 then redis.call('EXPIRE', KEYS[3], ttl) end
return 1`;

// The same removal for an element queued by a relay before 2.7.9: the entry
// itself sits in the list (ARGV[1] is that exact string) and nowhere else.
// Its bytes were never added to the counter — that relay kept none — so
// nothing comes off the counter here. (2.7.9 decremented anyway, which
// under-counted a mailbox during the transition and so under-enforced its
// cap; the counter was clamped at zero, and a mailbox that empties resets
// it, which is why it was only ever a transitional error.)
const REDIS_REMOVE_LEGACY_LUA = `#!lua flags=allow-oom
local n = redis.call('LREM', KEYS[1], 1, ARGV[1])
if n == 0 then return 0 end
if redis.call('LLEN', KEYS[1]) == 0 then
  redis.call('DEL', KEYS[1], KEYS[2], KEYS[3])
end
return n`;

// Per-entry expiry, from the head: KEYS as above; ARGV = the cutoff (ms
// since the epoch — an entry stamped before it has outlived QUEUE_TTL_HOURS)
// and how many entries to look at. Entries are in arrival order, so the
// walk stops at the first one that is still fresh. Handles the entry itself
// sitting in the list (a relay before 2.7.9) and a key whose body is gone.
// Returns the number removed. The keys' own TTL still expires a mailbox
// nothing has been pushed to for QUEUE_TTL_HOURS; this is for the mailbox
// that keeps receiving, whose refreshed TTL would otherwise hold its oldest
// entries for as long as anything arrived.
const REDIS_EXPIRE_LUA = `#!lua flags=allow-oom
local cutoff = tonumber(ARGV[1])
local removed = 0
local bytes = 0
for i = 1, tonumber(ARGV[2]) do
  local k = redis.call('LINDEX', KEYS[1], 0)
  if not k then break end
  local legacy = string.sub(k, 1, 1) == '{'
  local s = k
  if not legacy then s = redis.call('HGET', KEYS[2], k) end
  if not s then
    redis.call('LPOP', KEYS[1])
  else
    local ok, e = pcall(cjson.decode, s)
    if not ok or type(e) ~= 'table' or type(e.ts) ~= 'number' or e.ts >= cutoff then break end
    redis.call('LPOP', KEYS[1])
    if not legacy then redis.call('HDEL', KEYS[2], k) end
    local size = e.size
    if type(size) ~= 'number' then
      if e.kind == 'receipt' then size = 192 else size = #tostring(e.payload or '') + 256 end
    end
    -- A legacy element (the entry itself in the list) was queued by a relay
    -- that kept no counter, so its bytes were never added to one and must
    -- not be taken off it.
    if not legacy then bytes = bytes + size end
    removed = removed + 1
  end
end
if removed > 0 or redis.call('LLEN', KEYS[1]) == 0 then
  if redis.call('LLEN', KEYS[1]) == 0 then
    redis.call('DEL', KEYS[1], KEYS[2], KEYS[3])
  else
    local left = redis.call('DECRBY', KEYS[3], bytes)
    if left < 0 then redis.call('SET', KEYS[3], '0') end
  end
end
return removed`;

/** The key an entry is held under in qe:{rid} and listed under in q:{rid}. */
function entryKey(e) {
  return `${e.kind === 'receipt' ? 'r' : 'm'}:${e.id}`;
}

/** The size an entry is charged at, computed the same way in both coordinators. */
function entrySize(e) {
  if (typeof e.size === 'number') return e.size;
  return e.kind === 'receipt' ? 192 : String(e.payload || '').length + 256;
}

/** Thrown by a push the store refused for want of memory; answered `store_full`. */
class StoreFull extends Error {
  constructor() {
    super('the store is full');
  }
}

/** Redis refusing a write for want of memory ("OOM command not allowed …"). */
function isStoreFull(e) {
  return /\bOOM\b/.test(String((e && e.message) || ''));
}

class RedisCoordinator {
  constructor(url, instanceId) {
    const IORedis = require('ioredis');
    this.id = instanceId;
    this.cmd = new IORedis(url, { maxRetriesPerRequest: 3, lazyConnect: false });
    this.sub = new IORedis(url, { maxRetriesPerRequest: 3, lazyConnect: false });
    this.pub = new IORedis(url, { maxRetriesPerRequest: 3, lazyConnect: false });
    this.local = new Map(); // rid -> ws on THIS instance
    this.presenceStale = new Set(); // rids whose presence write the store refused
    this.chan = `z:inst:${this.id}`;
    for (const c of [this.cmd, this.sub, this.pub]) c.on('error', () => {});
    this.cmd.defineCommand('zQueuePush', { numberOfKeys: 3, lua: REDIS_PUSH_LUA });
    this.cmd.defineCommand('zQueueRemove', { numberOfKeys: 3, lua: REDIS_REMOVE_LUA });
    this.cmd.defineCommand('zQueueRemoveLegacy', { numberOfKeys: 3, lua: REDIS_REMOVE_LEGACY_LUA });
    this.cmd.defineCommand('zQueueExpire', { numberOfKeys: 3, lua: REDIS_EXPIRE_LUA });
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
    try {
      await this.cmd.set(`presence:${rid}`, this.id, 'EX', 60);
    } catch (e) {
      // A store at its memory limit refuses the presence write. The login
      // goes ahead anyway: this instance knows the socket, the flush that
      // follows only reads, and an ack only frees — so the one person who
      // can make room, the mailbox's owner, is not the one kept out. Until
      // the heartbeat's next write succeeds, envelopes sent to this mailbox
      // from another instance are queued rather than pushed live, and the
      // reconnect flush delivers them. Anything else is a real failure.
      if (!isStoreFull(e)) throw e;
      METRICS.storeFullTotal += 1;
      this.presenceStale.add(rid);
    }
    return prevLocal;
  }

  async unregister(rid, ws) {
    if (this.local.get(rid) === ws) {
      this.local.delete(rid);
      this.presenceStale.delete(rid);
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

  /**
   * Stores an entry; returns false when the recipient's queue is at a cap
   * (see MemoryCoordinator#_enqueue) and throws a StoreFull when the store
   * itself has no room — the caller says which to the sender. An entry
   * already held under the same key is not stored twice: the push is
   * acknowledged as if it had been, which is what a sender retrying after a
   * lost `sent` needs.
   */
  async _push(rid, entry) {
    let r;
    try {
      r = await this.cmd.zQueuePush(
        `q:${rid}`,
        `qe:${rid}`,
        `qb:${rid}`,
        entryKey(entry),
        JSON.stringify(entry),
        String(entrySize(entry)),
        String(CFG.maxQueueMsgsPerUser),
        String(CFG.maxQueueBytesPerUser),
        String(CFG.queueTtlHours * 3600)
      );
    } catch (e) {
      if (isStoreFull(e)) throw new StoreFull();
      throw e;
    }
    return r === 1 || r === 2;
  }

  /** Removes the entry held under `key` and settles the byte counter. */
  async _remove(rid, key, entry) {
    await this.cmd.zQueueRemove(`q:${rid}`, `qe:${rid}`, `qb:${rid}`, key, String(entrySize(entry)));
  }

  /** Removes an element queued by a relay before 2.7.9 (the entry itself, as the exact stored string). */
  async _removeLegacy(rid, s) {
    await this.cmd.zQueueRemoveLegacy(`q:${rid}`, `qe:${rid}`, `qb:${rid}`, s);
  }

  /**
   * Everything queued for a mailbox, in order: [{key, s, entry}] where `key`
   * is the entry's key in qe:{rid}, or null for an element a relay before
   * 2.7.9 queued (then `s` is the stored string itself). One list read and
   * one hash read, whatever the size.
   */
  async _queued(rid) {
    const elems = await this.cmd.lrange(`q:${rid}`, 0, -1);
    const keys = elems.filter((x) => !x.startsWith('{'));
    const bodies = keys.length ? await this.cmd.hmget(`qe:${rid}`, ...keys) : [];
    const byKey = new Map(keys.map((k, i) => [k, bodies[i]]));
    const out = [];
    for (const x of elems) {
      const legacy = x.startsWith('{');
      const s = legacy ? x : byKey.get(x);
      if (s == null) continue; // a key whose body is gone: removed meanwhile
      let entry;
      try {
        entry = JSON.parse(s);
      } catch {
        continue;
      }
      out.push({ key: legacy ? null : x, s, entry });
    }
    return out;
  }

  async deliverEnqueue(from, to, id, payload) {
    const entry = { kind: 'msg', id, from, payload, ts: Date.now(), size: payload.length + 256 };
    let accepted;
    try {
      accepted = await this._push(to, entry);
    } catch (e) {
      if (!(e instanceof StoreFull)) throw e;
      METRICS.storeFullTotal += 1;
      return { queued: false, storeFull: true };
    }
    if (!accepted) {
      METRICS.refusedTotal += 1;
      return { queued: false, refused: true };
    }
    METRICS.enqueuedTotal += 1;
    if (from == null) METRICS.sealedTotal += 1;
    const owner = await this.cmd.get(`presence:${to}`);
    let live = false;
    const here = this.local.get(to);
    if (owner === this.id || (!owner && here)) {
      // This instance's own sockets are authoritative: a presence write the
      // store refused (register, above) must not turn a live recipient into
      // an offline one.
      live = here ? sendJson(here, entryToFrame(entry)) : false;
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
    // Sealed envelopes are acked by id alone (the relay never knew a sender);
    // legacy attributed envelopes still match on (from, id).
    const matches = (e) => e.kind === 'msg' && e.id === id && (from ? e.from === from : e.from == null);
    const key = `m:${id}`;
    let removed = null;
    const held = await this.cmd.hget(`qe:${recipient}`, key);
    if (held != null) {
      let e;
      try {
        e = JSON.parse(held);
      } catch {
        e = null;
      }
      if (e && matches(e)) {
        await this._remove(recipient, key, e);
        removed = e;
      }
    } else {
      // Not held by key: either nothing, or an element a relay before 2.7.9
      // queued, which only a read of the list can find.
      for (const q of await this._queued(recipient)) {
        if (q.key === null && matches(q.entry)) {
          await this._removeLegacy(recipient, q.s);
          removed = q.entry;
          break;
        }
      }
    }
    if (!removed) return;
    observeAck(removed);
    if (removed.from == null) return; // sealed: no relay receipt possible
    const receipt = { kind: 'receipt', id, from: recipient, ts: Date.now(), size: 192 };
    const owner = await this.cmd.get(`presence:${from}`);
    if (owner === this.id) {
      const ws = this.local.get(from);
      if (!(ws && sendJson(ws, entryToFrame(receipt)))) await this._pushReceipt(from, receipt);
    } else if (owner) {
      await this.pub.publish(
        `z:inst:${owner}`,
        JSON.stringify({ op: 'deliver', toRid: from, frame: entryToFrame(receipt) })
      );
    } else {
      await this._pushReceipt(from, receipt);
    }
  }

  /** A receipt the store cannot hold is lost, not a message; the ack that produced it stands. */
  async _pushReceipt(rid, receipt) {
    try {
      await this._push(rid, receipt);
    } catch (e) {
      if (!(e instanceof StoreFull)) throw e;
      METRICS.storeFullTotal += 1;
    }
  }

  /** Removes entries at the head of a mailbox that have outlived QUEUE_TTL_HOURS. */
  async _expire(rid, limit = 1000) {
    return this.cmd.zQueueExpire(`q:${rid}`, `qe:${rid}`, `qb:${rid}`, String(Date.now() - CFG.queueTtlMs), String(limit));
  }

  async flush(rid, ws) {
    await this._expire(rid);
    const elems = await this.cmd.lrange(`q:${rid}`, 0, -1);
    for (let i = 0; i < elems.length; i += CFG.flushPage) {
      if (!(await drained(ws))) return;
      const page = elems.slice(i, i + CFG.flushPage);
      const keys = page.filter((x) => !x.startsWith('{'));
      const bodies = keys.length ? await this.cmd.hmget(`qe:${rid}`, ...keys) : [];
      const byKey = new Map(keys.map((k, j) => [k, bodies[j]]));
      for (const x of page) {
        const legacy = x.startsWith('{');
        const str = legacy ? x : byKey.get(x);
        if (str == null) continue; // removed meanwhile (an ack landed)
        let entry;
        try {
          entry = JSON.parse(str);
        } catch {
          continue;
        }
        sendJson(ws, entryToFrame(entry));
        if (entry.kind === 'receipt') {
          if (legacy) await this._removeLegacy(rid, str);
          else await this._remove(rid, x, entry);
        }
      }
    }
  }

  /**
   * Every SWEEP_INTERVAL_SECONDS: walk the mailboxes and expire what has
   * outlived QUEUE_TTL_HOURS at the head of each. SCAN, so the store is
   * never asked for all its keys at once; both instances sweep, which is
   * harmless — the script is idempotent.
   */
  async sweep() {
    let cursor = '0';
    do {
      const [next, keys] = await this.cmd.scan(cursor, 'MATCH', 'q:*', 'COUNT', '200');
      cursor = next;
      for (const key of keys) {
        try {
          await this._expire(key.slice(2), 200);
        } catch {
          // A store that is unreachable for a moment: the next sweep tries again.
        }
      }
    } while (cursor !== '0');
  }

  async heartbeat() {
    for (const rid of this.local.keys()) {
      try {
        await this.cmd.set(`presence:${rid}`, this.id, 'EX', 60);
        this.presenceStale.delete(rid);
      } catch (e) {
        if (!isStoreFull(e)) throw e;
        this.presenceStale.add(rid);
      }
    }
  }

  stats() {
    // Global totals aren't counted per-instance to stay cheap; report local.
    return { connections: this.local.size, queuedEnvelopes: -1, presenceStale: this.presenceStale.size };
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

  let wssRef = null; // set once the WebSocket server exists, below
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
          // Every socket, authenticated or not: a device holds two since
          // 16.1 (its mailbox link and its anonymous sender link), and the
          // socket count is what the relay's tail latency follows.
          sockets: wssRef ? wssRef.clients.size : s.connections,
          queuedEnvelopes: s.queuedEnvelopes,
          // Redis mode: sockets here whose presence the store refused to
          // write (it was full); their mail is queued, not pushed, until
          // the heartbeat's write succeeds. Absent in RAM mode.
          ...(s.presenceStale !== undefined ? { presenceStale: s.presenceStale } : {}),
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
    // The tab icon, in both formats. Served ahead of the HTML lookup because
    // neither is HTML, and cached hard — the mark changes about as often as
    // the brand does.
    if (req.url === '/favicon.svg') {
      res.writeHead(200, {
        'content-type': 'image/svg+xml',
        'cache-control': 'public, max-age=604800',
      });
      res.end(FAVICON_SVG);
      return;
    }
    if (req.url === '/favicon.ico') {
      res.writeHead(200, {
        'content-type': 'image/x-icon',
        'cache-control': 'public, max-age=604800',
        'content-length': FAVICON_ICO.length,
      });
      res.end(FAVICON_ICO);
      return;
    }
    // RFC 9116. Both paths: the well-known one is the standard, and the bare
    // one is where people actually look first. Served as text/plain, so it sits
    // ahead of the HTML page lookup rather than inside ROUTES.
    if (
      req.url === '/.well-known/security.txt' ||
      req.url === '/security.txt'
    ) {
      res.writeHead(200, {
        'content-type': 'text/plain; charset=utf-8',
        'cache-control': 'public, max-age=3600',
      });
      res.end(SECURITY_TXT);
      return;
    }
    // Static pages (embedded strings — the relay still never touches disk).
    // Every public path lives in pages.js ROUTES, so a page cannot be added
    // to the site without being reachable here, and the ad sitelinks cannot
    // point at a path that 404s.
    const pagePath = req.url.split('?')[0];
    const pageHtml = ROUTES.get(pagePath);
    if (pageHtml) {
      res.writeHead(200, {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'public, max-age=300',
      });
      res.end(pageHtml);
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
  wssRef = wss;

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
      let frame;
      try {
        frame = JSON.parse(data.toString('utf8'));
      } catch {
        sendJson(ws, { t: 'error', code: 'bad_json' });
        return;
      }
      // Rate limit (synchronous, before any async work). An acknowledgement
      // is exempt: a device draining a backlog acks as fast as it persists,
      // hundreds a second, and an ack costs the relay one hash read and one
      // small script while it frees memory. Limiting them meant the acks
      // past the burst were dropped, the entries they named stayed queued,
      // and a mailbox emptied only over several reconnects — or, at its
      // cap, never looked empty to its senders.
      if (frame.t !== 'recv') {
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

  const sweeper = setInterval(() => Promise.resolve(coord.sweep()).catch(() => {}), CFG.sweepIntervalMs);
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
      const to = String(frame.to || '');
      const id = String(frame.id || '');
      const payload = String(frame.payload || '');
      // A sealed envelope needs no authenticated sender — it carries none —
      // and accepting it only from an authenticated connection would hand
      // this process exactly the attribution the envelope was built to
      // withhold. So a connection that never authenticates may send sealed
      // envelopes (rate-limited like any other), and a client that wants
      // the relay not to know who sent what uses one. Anything else still
      // needs the identity it will be stamped with.
      const anon = payload.startsWith('zs1.');
      if (!state.authed && !anon) {
        sendJson(ws, { t: 'error', code: 'not_authed' });
        return;
      }
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
      if (anon && !state.authed) METRICS.sealedUnattributableTotal += 1;
      const { queued, refused, storeFull } = await coord.deliverEnqueue(
        anon ? null : state.rid,
        to,
        id,
        payload
      );
      if (refused) {
        // The recipient's queue is at its cap. Told, not dropped: the
        // sender keeps the envelope and retries once the recipient drains.
        sendJson(ws, { t: 'error', code: 'queue_full', id });
        return;
      }
      if (storeFull) {
        // The shared store has no room for anyone's envelope right now.
        // Told promptly, with the id, so the sender's outbox pauses and
        // retries rather than waiting out a timeout per envelope.
        sendJson(ws, { t: 'error', code: 'store_full', id });
        return;
      }
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
  if (CFG.maxQueueBytesPerUser < CFG.maxEnvelopeBytes + 256) {
    log(
      `MAX_QUEUE_BYTES_PER_USER (${CFG.maxQueueBytesPerUser}) is below one envelope ` +
        `(MAX_ENVELOPE_BYTES ${CFG.maxEnvelopeBytes} + 256): the largest envelopes will be refused`
    );
  }
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
