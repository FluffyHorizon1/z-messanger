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
  androidAssetLinks,
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
  // waits until the socket has drained below this many bytes. A page ends at
  // whichever of the two comes first — that many entries, or that many bytes
  // — so a slow reader costs the relay one envelope plus the mark, never its
  // whole backlog, at any envelope size.
  flushPage: intEnv('FLUSH_PAGE', 64),
  flushHighWaterBytes: intEnv('FLUSH_HIGH_WATER_BYTES', 1024 * 1024),
  // Two entries can share an id — two senders choosing the same one, or a
  // sender retrying after a lost `sent`. Both are stored (the RAM queue
  // always did), so the store holds up to this many per id and refuses
  // beyond, and an acknowledgement looks under this many keys.
  idSlots: intEnv('ID_SLOTS', 8),
  // How far into a mailbox an acknowledgement will look for an entry queued
  // by a relay older than 2.7.9 (the entry itself as a list element). Only
  // such entries need the search, and only until they expire.
  legacyScan: intEnv('LEGACY_SCAN', 200),
  // Push tokens live this long after their last (re)registration, in both
  // coordinators — the privacy policy promises a 30-day cap.
  pushTtlMs: intEnv('PUSH_TTL_DAYS', 30) * 24 * 3600 * 1000,
  // How many exempt acknowledgements one socket may have in the store at
  // once. The exemption is about a device draining its own backlog, which
  // does so a page at a time (FLUSH_PAGE, 64), so this is generous for the
  // case it exists for and a bound on the case it does not.
  ackInFlight: intEnv('ACK_IN_FLIGHT', 256),
  ratePerSec: intEnv('RATE_PER_SEC', 80),
  rateBurst: intEnv('RATE_BURST', 240),
  // How many mailboxes may be CREATED a minute, across all senders.
  //
  // The per-mailbox caps bound what one recipient can be made to hold; they
  // cannot bound how many recipients exist, and `to` is checked only for the
  // SHAPE of a routing id (43 base64url characters) because the relay has no
  // way to know which hashes name a real identity — nor should it. A sealed
  // envelope may be sent on a connection that never authenticated (§12.1),
  // by design. So 400 random strings and a few seconds filled a 256 MB
  // `noeviction` store, every real send got `store_full`, and it did NOT
  // heal the way R22 says: nobody owns those mailboxes, so nobody will ever
  // drain them, and the floor is QUEUE_TTL_HOURS — three days.
  //
  // Creating a mailbox is the asymmetry. An honest one belongs to somebody
  // who will connect and empty it; a flood's never drain. A rate on
  // creations bounds the attack without bounding anybody's conversation,
  // needs no counter shared between instances to be correct, and cannot
  // drift the way a count of live mailboxes does against a TTL that deletes
  // them without telling anyone.
  newMailboxPerMin: intEnv('NEW_MAILBOX_PER_MIN', 120),
  // How many routing ids this instance remembers having queued for, so the
  // admission gate above is charged on first contact rather than on an empty
  // mailbox. Measured at 117 bytes an entry, so 100 000 is 11.2 MiB.
  seenMailboxCap: intEnv('SEEN_MAILBOX_CAP', 100000),
  // And for how long. An hour means at most one token per recipient per hour,
  // against an allowance of NEW_MAILBOX_PER_MIN × 60.
  seenMailboxTtlMs: intEnv('SEEN_MAILBOX_TTL_MIN', 60) * 60000,
  // The whole RAM queue's ceiling in single-instance mode. The Redis path
  // has the store's own `noeviction` limit to refuse against; this one had
  // nothing at all, so the answer to the same flood was an OOM kill instead
  // of the documented refusal.
  maxStoreBytes: intEnv('MAX_STORE_BYTES', 192 * 1024 * 1024),
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

/** What a routing id looks like: base64url of a SHA-256, so 43 characters. */
const ROUTING_ID = /^[A-Za-z0-9_-]{43}$/;

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

/**
 * Whether a flush that has put `entries` frames and `bytes` of bodies into
 * the socket since it last waited should stop and wait now. Both bounds are
 * needed: `MAX_ENVELOPE_BYTES` is 1 MB, so FLUSH_PAGE entries can be 64 MB,
 * and a flush that checked only the count buffered a slow reader's whole
 * backlog — measured at 58 MB against a documented bound of "a page plus the
 * mark" (roadmap revision 45). What it bounds is therefore
 * FLUSH_HIGH_WATER_BYTES plus the one envelope that crossed the mark, plus
 * whatever `drained` allows to stay in the socket — a further
 * FLUSH_HIGH_WATER_BYTES — so about 3 MB at the defaults, not 64.
 */
function pageFull(entries, bytes) {
  return entries >= CFG.flushPage || bytes >= CFG.flushHighWaterBytes;
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
  // Envelopes handed to another instance over pub/sub. Not counted as
  // delivered live, because this instance cannot see whether they were:
  // the gap between this and z_delivered_live_total is the traffic whose
  // delivery depends on a presence record being true.
  crossInstanceTotal: 0,
  // Mailboxes re-flushed because a connected socket had made no progress
  // on one for a whole interval. Anything but zero means a live push was
  // lost — a stale presence record, or an instance that went away between
  // the publish and the frame — and the pass below is what recovers it.
  reflushedTotal: 0,
  // Presence refreshes that failed for a reason other than the store being
  // full. One of these used to abort the whole pass, silently.
  presenceRefreshFailedTotal: 0,
  // Sends refused because too many mailboxes were being CREATED at once.
  // Counted apart from the line above because it means something different
  // to an operator: the store is not full, and what was refused was a first
  // envelope to an address nothing had been sent to yet. Ordinary traffic
  // never touches it, so anything but zero is either a flood or a limit set
  // too low for the deployment's rate of first contacts.
  newMailboxRefusedTotal: 0,
  // Presence writes the store refused for want of memory. Counted apart
  // from the sends above: one is mail a sender must retry, the other is a
  // login that went ahead anyway and heals at the next heartbeat.
  presenceDeferredTotal: 0,
  deliveredLiveTotal: 0,
  ackedTotal: 0,
  // Acknowledgements that matched nothing in the acknowledger's mailbox.
  // A few are normal — a device that persisted an envelope and lost the
  // acknowledgement on the way retries it after the relay has already
  // removed it. A lot means either a client disagreeing with the relay about
  // what it holds, or a socket spending the relay's lookups on purpose:
  // those are charged to the rate limit, and this is how that shows up.
  ackMissTotal: 0,
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
  // Omitted rather than reported as -1 where instances share a store and no
  // instance knows the total: a gauge two instances sum to -2 is worse than
  // a gauge that is absent, which a scrape can see and say so.
  if (stats.queuedEnvelopes >= 0) {
    L.push('# TYPE z_queued_envelopes gauge');
    L.push(`z_queued_envelopes ${stats.queuedEnvelopes}`);
  }
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
  L.push('# TYPE z_cross_instance_total counter');
  L.push(`z_cross_instance_total ${METRICS.crossInstanceTotal}`);
  L.push('# TYPE z_reflushed_total counter');
  L.push(`z_reflushed_total ${METRICS.reflushedTotal}`);
  L.push('# TYPE z_presence_refresh_failed_total counter');
  L.push(`z_presence_refresh_failed_total ${METRICS.presenceRefreshFailedTotal}`);
  L.push('# TYPE z_new_mailbox_refused_total counter');
  L.push(`z_new_mailbox_refused_total ${METRICS.newMailboxRefusedTotal}`);
  L.push('# TYPE z_presence_deferred_total counter');
  L.push(`z_presence_deferred_total ${METRICS.presenceDeferredTotal}`);
  L.push('# TYPE z_delivered_live_total counter');
  L.push(`z_delivered_live_total ${METRICS.deliveredLiveTotal}`);
  L.push('# TYPE z_acked_total counter');
  L.push(`z_acked_total ${METRICS.ackedTotal}`);
  L.push('# TYPE z_ack_miss_total counter');
  L.push(`z_ack_miss_total ${METRICS.ackMissTotal}`);
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
/**
 * How many mailboxes may be created a minute, across every sender.
 *
 * A token bucket, per instance. Deliberately not a count of live mailboxes
 * shared between instances: that number drifts the moment a TTL deletes a
 * queue without running the code that would decrement it, and a bound that
 * drifts upward is a bound that eventually refuses everybody. A rate has no
 * state to be wrong about.
 */
class NewMailboxGate {
  constructor(perMinute = CFG.newMailboxPerMin, now = Date.now) {
    this.perMinute = perMinute;
    this.now = now;
    this.tokens = perMinute;
    this.at = now();
  }
  /** True if a mailbox may be created right now. */
  take() {
    const t = this.now();
    this.tokens = Math.min(this.perMinute, this.tokens + ((t - this.at) / 60000) * this.perMinute);
    this.at = t;
    if (this.tokens < 1) return false;
    this.tokens -= 1;
    return true;
  }
  /**
   * Gives back a token spent on a push that turned out to land in a mailbox
   * that already existed. Spending first and refunding after is what keeps
   * two pushes in flight at once from both spending the last allowance.
   */
  refund() {
    this.tokens = Math.min(this.perMinute, this.tokens + 1);
  }
}

/**
 * The routing ids this instance has queued for recently.
 *
 * `NewMailboxGate` exists to make creating a mailbox expensive, because that
 * is what a flood needs (§12.4, R22). It was charged whenever the recipient
 * had no queue — but a mailbox exists only while it holds unacknowledged
 * mail, and a recipient who is online and acknowledges each message, as
 * §12.5 requires, has no queue by the time the next one arrives. So the
 * steady state charged a token for EVERY message, the gate is global to the
 * instance, and the whole relay stopped at `newMailboxPerMin` messages a
 * minute. Measured before the fix: Bob online and acknowledging, 120 sends
 * accepted and every one after refused `store_full`, with zero bytes held.
 * `SELF_HOSTING.md` ("Sending into one that already exists is never charged
 * to it"), its `z_new_mailbox_refused_total` alarm and `THREAT_MODEL.md` R22
 * ("bounds the flood without bounding anybody's conversation") all described
 * the intent rather than the behaviour.
 *
 * First contact is the thing worth charging, so that is what is remembered.
 * What keeps this from simply undoing R22 is `touch`: a routing id enters the
 * set only by a send that was ACCEPTED, and a send to a routing id with no
 * mailbox is accepted only by spending a token. Membership is therefore
 * always backed by a token that was paid, and a flood that is refused leaves
 * the set exactly as it found it.
 *
 * Two bounds on top of that, neither of which is what defends against the
 * flood. `SEEN_MAILBOX_CAP` is a memory bound — measured at 117 bytes an
 * entry — and evicts least-recently-used; the cost of an eviction that
 * catches a real conversation is one token. `SEEN_MAILBOX_TTL_MIN` is a time
 * bound on ids whose mailboxes WERE paid for, so a second flood cannot use
 * them for free indefinitely after the queue TTL has emptied them. A
 * recipient who is merely offline is unaffected by either, because their
 * mailbox still exists and the queue is checked too.
 *
 * Per instance, deliberately. A shared set would be a Redis round trip on
 * every send to save at most one token per routing id per instance, and the
 * flood it defends against is charged either way.
 */
class SeenMailboxes {
  constructor(cap = CFG.seenMailboxCap, ttlMs = CFG.seenMailboxTtlMs, now = Date.now) {
    this.cap = cap;
    this.ttlMs = ttlMs;
    this.now = now;
    this.ids = new Map();
  }

  /** True if [rid] was queued for within the window. Reads only. */
  has(rid) {
    const at = this.ids.get(rid);
    return at !== undefined && this.now() - at < this.ttlMs;
  }

  /**
   * Record a send that SUCCEEDED. Nothing else may call this, and that is the
   * whole of the invariant: a routing id enters this set only by a send that
   * was accepted, and a send to a routing id with no mailbox is accepted only
   * by spending a token. So membership is always backed by a token somebody
   * actually paid.
   *
   * Recording the attempt instead broke the gate outright, and it is worth
   * writing down because it looked harmless. A flood of 200 fresh ids against
   * an allowance of 20 was refused 180 times — and marked all 200 as seen, so
   * the same flood a moment later created every one of them for nothing.
   * Measured: 200 of 200 accepted on the second pass, 180 mailboxes past the
   * allowance. Two passes and the gate was gone.
   */
  touch(rid) {
    this.ids.delete(rid); // delete+set moves it to the end
    this.ids.set(rid, this.now());
    if (this.ids.size > this.cap) {
      // A Map iterates in insertion order, so the first key is the one least
      // recently queued for.
      this.ids.delete(this.ids.keys().next().value);
    }
  }

  get size() {
    return this.ids.size;
  }
}

class MemoryCoordinator {
  constructor() {
    /** routingId -> live socket */
    this.online = new Map();
    /** routingId -> {entries:[], bytes, keys:Map<entryKey, entry>} */
    this.queues = new Map();
    /** routingId -> {token, platform, ts} — opaque FCM tokens, RAM only */
    this.pushTokens = new Map();
    this.seq = 0;
    /** Bytes held across every queue: this store's own `noeviction` limit. */
    this.bytes = 0;
    this.newMailbox = new NewMailboxGate();
    this.seen = new SeenMailboxes();
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
      // `keys` is what makes a push and an acknowledgement O(1) here and
      // keyed exactly as the Redis path keys them: the scan it replaces was
      // the same shape as the drain that turned quadratic (revision 45).
      q = { entries: [], bytes: 0, keys: new Map() };
      this.queues.set(id, q);
    }
    return q;
  }

  /**
   * Replaces a queue's entries, rebuilding its index and byte total — and
   * moving the global accumulator by the same amount.
   *
   * `this.bytes` is what `MAX_STORE_BYTES` is checked against. `_enqueue`
   * adds to it and `_removeKey` subtracts from it; this, the only removal
   * path TTL expiry takes (`_expireFor` and `sweep`), rebuilt `q.bytes` and
   * left `this.bytes` alone. So every envelope that timed out rather than
   * being acknowledged leaked its full charge, permanently: queue 192 MB into
   * mailboxes nobody drains, wait out `QUEUE_TTL_HOURS`, and the sweep frees
   * every entry while the accumulator still reads 192 MB. From then on
   * `_enqueue` refuses the first byte of every send, for everyone, until the
   * process restarts — and `/health` said `queuedEnvelopes: 0`, so nothing
   * pointed at the cause. Measured before the fix: eleven cycles at
   * `QUEUE_TTL_HOURS=0` reached `store bytes = 18840, mailboxes = 0, actual
   * queued bytes = 0`, and the next send returned `storeFull`.
   *
   * The delta is taken before `q.bytes` is overwritten, because the old total
   * is the only record of what this queue was charged.
   */
  _retain(rid, q, kept) {
    q.entries = kept;
    q.keys = new Map(kept.map((e) => [e.key, e]));
    const was = q.bytes;
    q.bytes = kept.reduce((sum, e) => sum + e.size, 0);
    this.bytes = Math.max(0, this.bytes - (was - q.bytes));
    if (kept.length === 0) this.queues.delete(rid);
  }

  /**
   * The invariant the bug above broke: the accumulator is the sum of the
   * queues. These two are how a test says so; `/health` publishes the first
   * of them through `stats()`, because a number that can drift silently is
   * one that has to be visible.
   */
  storeBytes() {
    return this.bytes;
  }

  heldBytes() {
    let n = 0;
    for (const q of this.queues.values()) n += q.bytes;
    return n;
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
    // A mailbox that does not exist yet is the expensive one to create, and
    // the only one a flood needs. Charged before anything is allocated — on
    // FIRST CONTACT, not on an empty queue: see `SeenMailboxes` for what
    // charging the empty queue did to an ordinary conversation.
    const known = this.seen.has(rid);
    if (!known && !this.queues.has(rid) && !this.newMailbox.take()) {
      METRICS.newMailboxRefusedTotal += 1;
      throw new StoreFull();
    }
    if (this.bytes + entry.size > CFG.maxStoreBytes) {
      METRICS.storeFullTotal += 1;
      throw new StoreFull();
    }
    const q = this._queueFor(rid);
    const base = entryKey(entry);
    let key = base;
    if (entryDedupes(entry)) {
      // Already there means this entry arriving twice: idempotent, exactly
      // as the Redis push script is.
      if (q.keys.has(key)) return true;
    } else {
      for (let dup = 1; q.keys.has(key); dup += 1) {
        if (dup > CFG.idSlots) {
          if (q.entries.length === 0) this.queues.delete(rid);
          return false;
        }
        key = `${base}#${dup}`;
      }
    }
    if (
      q.entries.length + 1 > CFG.maxQueueMsgsPerUser ||
      q.bytes + entry.size > CFG.maxQueueBytesPerUser
    ) {
      if (q.entries.length === 0) this.queues.delete(rid);
      return false;
    }
    entry.key = key;
    q.entries.push(entry);
    q.keys.set(key, entry);
    q.bytes += entry.size;
    this.bytes += entry.size;
    // Accepted, and only now: see `SeenMailboxes.touch`. Every other exit
    // from this method is a refusal, and a refusal must leave no trace.
    this.seen.touch(rid);
    return true;
  }

  /** Removes the entry at `key`, if any, and settles the byte total. */
  _removeKey(rid, key) {
    const q = this.queues.get(rid);
    if (!q) return null;
    const entry = q.keys.get(key);
    if (!entry) return null;
    q.keys.delete(key);
    const idx = q.entries.indexOf(entry);
    if (idx !== -1) q.entries.splice(idx, 1);
    q.bytes -= entry.size;
    this.bytes = Math.max(0, this.bytes - entry.size);
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
    try {
      if (!this._enqueue(to, entry)) {
        METRICS.refusedTotal += 1;
        return { queued: false, refused: true };
      }
    } catch (e) {
      // The store has no room, or too many mailboxes are being created at
      // once. Told promptly and with the id, as the Redis path does, so the
      // sender's outbox pauses and retries rather than waiting out a
      // timeout per envelope (PROTOCOL §12.4). Until 2026-09-14 this
      // coordinator had no such refusal at all and answered the same flood
      // with an OOM kill.
      if (e instanceof StoreFull) return { queued: false, storeFull: true };
      throw e;
    }
    METRICS.enqueuedTotal += 1;
    if (from == null) METRICS.sealedTotal += 1;
    const target = this.online.get(to);
    const live = target ? sendJson(target, entryToFrame(entry)) : false;
    if (live) METRICS.deliveredLiveTotal += 1;
    return { queued: !live };
  }

  async ack(recipient, from, id) {
    // The keys ackCandidateKeys names, tried in that order and checked the
    // same way the Redis script checks them: an attributed envelope is at
    // one key, a sealed one is acknowledged by id alone.
    const q = this.queues.get(recipient);
    let entry = null;
    if (q) {
      for (const key of ackCandidateKeys(id, from)) {
        const e = q.keys.get(key);
        if (!e || e.kind !== 'msg') continue;
        if (from ? e.from === from : typeof e.from !== 'string') {
          entry = this._removeKey(recipient, key);
          break;
        }
      }
    }
    if (!entry) return false;
    observeAck(entry);
    if (entry.from == null) return true; // sealed: receipts travel E2E instead
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
      // A full sender queue loses the receipt, not a message — and so does a
      // full store: a receipt is best-effort, and the sender keeps a grey
      // tick rather than the relay refusing an acknowledgement over it.
      try {
        this._enqueue(from, receipt);
      } catch (e) {
        if (!(e instanceof StoreFull)) throw e;
      }
    }
    return true;
  }

  /** Drops what has outlived QUEUE_TTL_HOURS from one mailbox. */
  _expireFor(rid) {
    const q = this.queues.get(rid);
    if (!q) return;
    const cutoff = Date.now() - CFG.queueTtlMs;
    const kept = q.entries.filter((e) => e.ts >= cutoff);
    if (kept.length === q.entries.length) return;
    this._retain(rid, q, kept);
  }

  async flush(rid, ws) {
    // Expire before delivering, as the Redis path does: a device returning
    // after a long absence must not be handed envelopes the documents say
    // are gone.
    this._expireFor(rid);
    const q = this.queues.get(rid);
    if (!q) return;
    // A snapshot, because acks arriving while a page drains mutate the live
    // array; but an entry acknowledged in that gap must not be sent, which
    // is what the live set is for (the Redis path gets this from re-reading
    // each page's bodies).
    const entries = q.entries.slice();
    let live = new Set(entries.map((e) => e.seq));
    let count = 0;
    let bytes = 0;
    for (const e of entries) {
      if (pageFull(count, bytes)) {
        if (!(await drained(ws))) return;
        const now = this.queues.get(rid);
        live = new Set(now ? now.entries.map((x) => x.seq) : []);
        count = 0;
        bytes = 0;
      }
      if (!live.has(e.seq)) continue;
      if (!sendJson(ws, entryToFrame(e))) return;
      count += 1;
      bytes += entrySize(e);
      if (e.kind === 'receipt') this._removeKey(rid, e.key);
    }
  }

  /**
   * Nothing to do in one process: a live delivery here is the return value
   * of `sendJson` against a socket this object holds, so `queued` is already
   * the truth and no push can have been lost on the way to another instance.
   * Present so that the two coordinators answer the same calls.
   */
  async reflushStalled() {}

  sweep() {
    const cutoff = Date.now() - CFG.queueTtlMs;
    for (const [rid, q] of this.queues) {
      const kept = q.entries.filter((e) => e.ts >= cutoff);
      if (kept.length !== q.entries.length) this._retain(rid, q, kept);
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
    return {
      connections: this.online.size,
      queuedEnvelopes: n,
      // What MAX_STORE_BYTES is actually checked against. Reported because
      // the accumulator drifting away from what is held is exactly the
      // failure that used to be invisible: `queuedEnvelopes: 0` beside a full
      // store is the shape of it.
      storeBytes: this.bytes,
    };
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
// seconds, how many slots may share an id, whether an entry already at the
// key is this entry arriving twice (entryDedupes), and whether this instance
// still has allowance to create a mailbox (NewMailboxGate). Returns 1 if
// stored or already held, 2 if storing it created the mailbox, 0 if the queue
// is full or the id has no free slot, and -1 if it would have created a
// mailbox and was not allowed to — each decided and applied atomically, so
// two instances pushing at once cannot both squeeze past the cap.
const REDIS_PUSH_LUA = `#!lua
-- Two entries can want one key. Where the relay can attribute the entry the
-- key carries the party (entryKey), so an occupied key is a retry and
-- storing nothing is right. Where it cannot -- a sealed envelope -- the key
-- is a base and the entry goes in the first free slot. Until 2.8.3 every
-- occupied key meant 'discard, answer sent', which lost mail and let the
-- first member of a group to acknowledge a message suppress every other
-- member's receipt (roadmap revision 45).
local key = ARGV[1]
if ARGV[8] == '1' then
  if redis.call('HEXISTS', KEYS[2], key) == 1 then return 1 end
else
  local dup = 0
  while redis.call('HEXISTS', KEYS[2], key) == 1 do
    dup = dup + 1
    if dup > tonumber(ARGV[7]) then return 0 end
    key = ARGV[1] .. '#' .. dup
  end
end
local len = redis.call('LLEN', KEYS[1])
-- An empty list is a mailbox that does not exist yet, which is the only kind
-- a flood needs and the only kind nobody will ever drain. Decided here rather
-- than by asking first: the script already knows, so admission costs no extra
-- round trip, and no mailbox can be created between the question and the
-- write. -1 says the send was refused for that reason and nothing else.
if len == 0 and ARGV[9] == '0' then return -1 end
local bytes = 0
if len > 0 then bytes = tonumber(redis.call('GET', KEYS[3]) or '0') end
if len + 1 > tonumber(ARGV[4]) or bytes + tonumber(ARGV[3]) > tonumber(ARGV[5]) then
  return 0
end
redis.call('RPUSH', KEYS[1], key)
redis.call('HSET', KEYS[2], key, ARGV[2])
if len == 0 then
  redis.call('SET', KEYS[3], ARGV[3])
else
  redis.call('INCRBY', KEYS[3], ARGV[3])
end
redis.call('EXPIRE', KEYS[1], ARGV[6])
redis.call('EXPIRE', KEYS[2], ARGV[6])
redis.call('EXPIRE', KEYS[3], ARGV[6])
-- 2 rather than 1 when this call is what created the mailbox, so the instance
-- knows to keep the token it spent.
if len == 0 then return 2 end
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

// The acknowledgement, entirely in the store: KEYS as above; ARGV = the base
// entry key (`m:<id>`), the sender's routing id or '' for a sealed envelope,
// and how many slots may share an id. Tries the keys ackCandidateKeys names,
// in that order, removes the first that matches, settles the counter and
// returns the entry JSON — or false. Before 2.8.3 a miss fell back to reading
// the whole mailbox into the relay and parsing it, so ten unknown
// acknowledgements against a 6 MB mailbox pulled 59 MB out of the store, and
// `recv` had just been exempted from the rate limit (roadmap revision 45).
const REDIS_ACK_LUA = `#!lua flags=allow-oom
local candidates = {}
if ARGV[2] == '' then
  -- Sealed: acknowledged by id alone, so any slot answers it.
  candidates[1] = ARGV[1]
  for dup = 1, tonumber(ARGV[3]) do
    candidates[#candidates + 1] = ARGV[1] .. '#' .. dup
  end
else
  -- Attributed: exactly one key, then the shape 2.7.9 to 2.8.2 wrote.
  candidates[1] = ARGV[1] .. ':' .. ARGV[2]
  candidates[2] = ARGV[1]
end
for i = 1, #candidates do
  local key = candidates[i]
  local s = redis.call('HGET', KEYS[2], key)
  if s then
    local ok, e = pcall(cjson.decode, s)
    -- A sealed envelope has no sender at all, so "no string there" is the
    -- test; cjson gives a JSON null as userdata, not nil.
    if ok and type(e) == 'table' and e.kind == 'msg' then
      local sealed = type(e.from) ~= 'string'
      if (ARGV[2] == '' and sealed) or (ARGV[2] ~= '' and e.from == ARGV[2]) then
        redis.call('HDEL', KEYS[2], key)
        redis.call('LREM', KEYS[1], 1, key)
        if redis.call('LLEN', KEYS[1]) == 0 then
          redis.call('DEL', KEYS[1], KEYS[2], KEYS[3])
        else
          local size = e.size
          if type(size) ~= 'number' then size = #tostring(e.payload or '') + 256 end
          local left = redis.call('DECRBY', KEYS[3], size)
          if left < 0 then redis.call('SET', KEYS[3], '0') end
          local ttl = redis.call('TTL', KEYS[1])
          if ttl > 0 then redis.call('EXPIRE', KEYS[3], ttl) end
        end
        return s
      end
    end
  end
end
return false`;

// The same, for an entry queued by a relay before 2.7.9 — the entry JSON
// itself as a list element, in no hash. ARGV = the id, the sender or '',
// how far in to look. Bounded, and in the store: the elements it searches
// are only the ones an older relay left, and only until they expire. Their
// bytes were never counted, so the counter is not touched.
const REDIS_ACK_LEGACY_LUA = `#!lua flags=allow-oom
local n = redis.call('LLEN', KEYS[1])
local limit = tonumber(ARGV[3])
if n > limit then n = limit end
for i = 0, n - 1 do
  local x = redis.call('LINDEX', KEYS[1], i)
  if x and string.sub(x, 1, 1) == '{' then
    local ok, e = pcall(cjson.decode, x)
    if ok and type(e) == 'table' and e.kind == 'msg' and e.id == ARGV[1] then
      local sealed = type(e.from) ~= 'string'
      if (ARGV[2] == '' and sealed) or (ARGV[2] ~= '' and e.from == ARGV[2]) then
        redis.call('LREM', KEYS[1], 1, x)
        if redis.call('LLEN', KEYS[1]) == 0 then
          redis.call('DEL', KEYS[1], KEYS[2], KEYS[3])
        end
        return x
      end
    end
  end
end
return false`;

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
if redis.call('LLEN', KEYS[1]) == 0 then
  redis.call('DEL', KEYS[1], KEYS[2], KEYS[3])
elseif bytes > 0 and redis.call('EXISTS', KEYS[3]) == 1 then
  -- Only adjust a counter that exists: DECRBY would create it, and a created
  -- key carries no TTL, so it outlived the list it counted (revision 45).
  local left = redis.call('DECRBY', KEYS[3], bytes)
  if left < 0 then redis.call('SET', KEYS[3], '0') end
  local ttl = redis.call('TTL', KEYS[1])
  if ttl > 0 then redis.call('EXPIRE', KEYS[3], ttl) end
end
return removed`;

/**
 * The key an entry is held under in qe:{rid} and listed under in q:{rid} —
 * one function, used by both coordinators, because a mailbox that keys its
 * entries differently in RAM and in Redis is a mailbox that loses different
 * mail in each (roadmap revision 45).
 *
 * An id is the sender's choice, so the id alone identifies nothing: two
 * senders may pick one id, and every member of a group acknowledging one
 * group message produces a receipt carrying that single id. The party the
 * entry belongs to goes in the key, so those are separate entries that
 * cannot displace each other. (Colons cannot occur in a routing id, which
 * is base64url.)
 *
 * A sealed envelope carries no sender, so `m:<id>` is a base the push
 * probes for a free slot from — see entryDedupes.
 */
function entryKey(e) {
  if (e.kind === 'receipt') return `r:${e.id}:${e.from}`;
  return typeof e.from === 'string' ? `m:${e.id}:${e.from}` : `m:${e.id}`;
}

/**
 * Whether an entry already at this key is *this* entry arriving twice.
 *
 * For anything the relay can attribute, yes: (id, party) is the whole
 * identity of the entry, so a sender retrying after a lost `sent` lands on
 * its own key again and the push is idempotent — one envelope, however many
 * retries. For a sealed envelope, no: the relay knows nothing that would
 * tell a retry from a second envelope that happens to share an id, and
 * delivering a duplicate is the safe side of that guess (the client drops
 * it on the inner id, which it can read and the relay cannot). Those go
 * into ID_SLOTS numbered slots instead.
 */
function entryDedupes(e) {
  return e.kind === 'receipt' || typeof e.from === 'string';
}

/**
 * The keys an acknowledgement may be sitting under, in the order to try
 * them. Attributed: exactly one key, plus the `m:<id>` shape a relay
 * between 2.7.9 and 2.8.2 wrote, which is still in the store until it
 * expires. Sealed: acknowledged by id alone, so any of the slots answers
 * it. Bounded either way — a miss must not turn into a mailbox read.
 */
function ackCandidateKeys(id, from) {
  if (from) return [`m:${id}:${from}`, `m:${id}`];
  const keys = [`m:${id}`];
  for (let dup = 1; dup <= CFG.idSlots; dup += 1) keys.push(`m:${id}#${dup}`);
  return keys;
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
    this.sweeping = false;
    this.beating = false;
    this.reflushing = false;
    /** rid -> mailbox length at the last re-flush check, for the pass below. */
    this.lastMailboxLen = new Map();
    // Per instance, like the rate limiter beside it. A flood arrives on one
    // socket and therefore one instance; a flood spread across N instances
    // gets N times the allowance, which is a bounded and stated degradation
    // rather than a shared counter that drifts every time a TTL deletes a
    // mailbox without telling anybody.
    this.newMailbox = new NewMailboxGate();
    this.seen = new SeenMailboxes();
    this.chan = `z:inst:${this.id}`;
    for (const c of [this.cmd, this.sub, this.pub]) c.on('error', () => {});
    this.cmd.defineCommand('zQueuePush', { numberOfKeys: 3, lua: REDIS_PUSH_LUA });
    this.cmd.defineCommand('zQueueRemove', { numberOfKeys: 3, lua: REDIS_REMOVE_LUA });
    this.cmd.defineCommand('zQueueRemoveLegacy', { numberOfKeys: 3, lua: REDIS_REMOVE_LEGACY_LUA });
    this.cmd.defineCommand('zQueueExpire', { numberOfKeys: 3, lua: REDIS_EXPIRE_LUA });
    this.cmd.defineCommand('zQueueAck', { numberOfKeys: 3, lua: REDIS_ACK_LUA });
    this.cmd.defineCommand('zQueueAckLegacy', { numberOfKeys: 3, lua: REDIS_ACK_LEGACY_LUA });
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
      // Only a socket OLDER than the registration that sent the kick. A
      // kick that has been overtaken names a socket this instance no longer
      // holds, and acting on it would close the one that replaced it and
      // then delete the entry, leaving presence naming an instance with no
      // socket. A kick with no token is from an instance that predates this
      // (or one whose store refused the counter): treated as newer, which
      // is what it used to do unconditionally.
      const token = typeof m.token === 'number' ? m.token : Infinity;
      if (ws && (ws.zReg || 0) >= token) return;
      if (ws) {
        try {
          ws.close(4002, 'replaced by new connection');
        } catch {}
      }
      this.local.delete(m.rid);
      this.presenceStale.delete(m.rid);
      this.lastMailboxLen.delete(m.rid);
    }
  }

  async register(rid, ws) {
    // A number every registration in the deployment can be ordered by.
    //
    // A kick used to say only which rid to close, so the instance receiving
    // it closed whatever it held for that rid AT THE MOMENT IT ARRIVED and
    // deleted the entry either way. A client moving A→B→A is the case that
    // breaks: B's kick for the A→B move can arrive after the move back, and
    // it then closes the socket that has just been welcomed — immediately
    // after `ready`, so the client reconnects and can re-enter the same
    // race. The deletion was worse than the close, because it also left
    // `presence:{rid}` naming an instance with no socket, so the other one
    // published deliveries into a channel that dropped them.
    //
    // The store is the only clock two instances share, so the order comes
    // from it. A registration that could not get one keeps 0: a kick then
    // closes it, which is exactly the old behaviour, and that is the right
    // way to degrade — a store under memory pressure must not stop people
    // logging in, and `register` already takes that view of the presence
    // write below.
    let token = 0;
    try {
      token = await this.cmd.incr('z:reg');
    } catch (e) {
      if (!isStoreFull(e)) throw e;
    }
    ws.zReg = token;
    const prevLocal = this.local.get(rid);
    this.local.set(rid, ws);
    const owner = await this.cmd.get(`presence:${rid}`);
    if (owner && owner !== this.id) {
      // Kick the socket living on another instance — the one that was there
      // before this registration, which is what the token names.
      await this.pub.publish(`z:inst:${owner}`, JSON.stringify({ op: 'kick', rid, token }));
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
      METRICS.presenceDeferredTotal += 1;
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
   * itself has no room, or when the entry would have created a mailbox and
   * too many were being created at once — the caller says which to the
   * sender, and both are told as `store_full`, which a client pauses and
   * retries on rather than treating as final. An attributed
   * entry already held under its key is not stored twice: the push is
   * acknowledged as if it had been, which is what a sender retrying after a
   * lost `sent` needs. A sealed one takes the next free slot instead
   * (entryDedupes).
   */
  async _push(rid, entry) {
    // The same admission rule as the memory path, and the same reasoning:
    // creating a mailbox is what a flood needs and what nobody drains. The
    // decision travels WITH the push instead of ahead of it — the script
    // already knows whether the list is empty — so an ordinary send costs
    // exactly what it cost before, and no mailbox can appear between a
    // lookup and the write that would have been told about it.
    // First contact, not an empty list — the same rule as the memory path.
    // A routing id this instance has queued for before may create a mailbox
    // without spending anything; only one it has never seen is charged.
    const known = this.seen.has(rid);
    const fresh = known ? true : this.newMailbox.take();
    const spent = !known && fresh;
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
        String(CFG.queueTtlHours * 3600),
        String(CFG.idSlots),
        entryDedupes(entry) ? '1' : '0',
        fresh ? '1' : '0'
      );
    } catch (e) {
      if (spent) this.newMailbox.refund();
      if (isStoreFull(e)) throw new StoreFull();
      throw e;
    }
    if (r === -1) {
      METRICS.newMailboxRefusedTotal += 1;
      throw new StoreFull();
    }
    // 2 means this push created the mailbox and the token is spent; anything
    // else went into one that already existed, so the allowance goes back.
    // Nothing to give back when nothing was taken.
    if (r !== 2 && spent) this.newMailbox.refund();
    const accepted = r === 1 || r === 2;
    // Only a send that landed, for the reason in `SeenMailboxes.touch`.
    if (accepted) this.seen.touch(rid);
    return accepted;
  }

  /** Removes the entry held under `key` and settles the byte counter. */
  async _remove(rid, key, entry) {
    await this.cmd.zQueueRemove(`q:${rid}`, `qe:${rid}`, `qb:${rid}`, key, String(entrySize(entry)));
  }

  /** Removes an element queued by a relay before 2.7.9 (the entry itself, as the exact stored string). */
  async _removeLegacy(rid, s) {
    await this.cmd.zQueueRemoveLegacy(`q:${rid}`, `qe:${rid}`, `qb:${rid}`, s);
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
      METRICS.crossInstanceTotal += 1;
      // And `live` stays false, which is the correction.
      //
      // It used to be set true here, on the strength of the publish having
      // resolved — which says Redis accepted the PUBLISH, and nothing about
      // whether the instance named by `presence:` still holds a socket for
      // this recipient. The receiving side drops the frame silently when it
      // does not (`_onPub`), and answers nobody. So a presence record that
      // was stale by even a second produced `queued: false` — the sender
      // told it went live, no wake push fired because that is gated on
      // `queued`, and the envelope sat in the store until the recipient
      // happened to reconnect. Nothing re-flushed a socket that was already
      // connected, so "until they reconnect" could be the full
      // QUEUE_TTL_HOURS: three days, invisible to everyone.
      //
      // Saying `queued: true` here is not a lie in the other direction: the
      // envelope IS held, and stays held until it is acknowledged, exactly
      // as the frame's comment in §12.2 describes. The live push is an
      // optimisation on top of that, and this instance cannot see whether
      // it happened. The wake push it now allows is correct in the case
      // that matters — the recipient is not really there — and harmless in
      // the case that it is, being content-free and going to a device that
      // is already awake.
      //
      // The alternative, an acknowledgement back over pub/sub with a
      // timeout, would put a second round trip on the hot path of every
      // cross-instance send to recover one bit that no client reads: the
      // Dart client discards it (`transport.dart`), and the only consumer
      // is the wake push decided here.
    }
    if (live) METRICS.deliveredLiveTotal += 1;
    return { queued: !live };
  }

  /**
   * Acknowledges one envelope. Two bounded calls at worst: the entry under
   * `m:<id>` (or the next key sharing that id), and — only if that found
   * nothing — a bounded search for an element a relay before 2.7.9 queued.
   * Neither reads the mailbox into the relay. Returns whether anything was
   * removed, which is what the rate limiter charges for: an acknowledgement
   * that matches is free, one that does not is not.
   */
  async ack(recipient, from, id) {
    const q = `q:${recipient}`;
    const qe = `qe:${recipient}`;
    const qb = `qb:${recipient}`;
    let s = await this.cmd.zQueueAck(q, qe, qb, `m:${id}`, from || '', String(CFG.idSlots));
    if (!s) s = await this.cmd.zQueueAckLegacy(q, qe, qb, id, from || '', String(CFG.legacyScan));
    if (!s) return false;
    let removed;
    try {
      removed = JSON.parse(s);
    } catch {
      return false;
    }
    observeAck(removed);
    if (removed.from == null) return true; // sealed: no relay receipt possible
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
    return true;
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

  /**
   * Expires a mailbox until nothing at its head has outlived the TTL. The
   * script looks at a bounded number of entries per call, so one call was
   * not enough for a long mailbox and the flush then delivered the rest —
   * expired envelopes included (revision 45).
   */
  async _expireAll(rid, limit = 1000) {
    for (let i = 0; i < 64; i++) {
      if ((await this._expire(rid, limit)) < limit) return;
    }
  }

  async flush(rid, ws) {
    await this._expireAll(rid);
    const elems = await this.cmd.lrange(`q:${rid}`, 0, -1);
    // What bounds the socket is the bytes that actually went into it, and an
    // element is a key: its body's size is not known until the body is read.
    // So the batch below is an I/O detail — one HMGET per FLUSH_PAGE keys —
    // and the decision to stop and wait is taken inside the loop, on real
    // sizes, by the same predicate the RAM path uses.
    let count = 0;
    let bytes = 0;
    let page = [];
    const sendPage = async () => {
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
        // A receipt is removed only if it actually went into the socket: a
        // send that failed is a receipt the client never saw.
        if (!sendJson(ws, entryToFrame(entry))) return false;
        if (entry.kind === 'receipt') {
          if (legacy) await this._removeLegacy(rid, str);
          else await this._remove(rid, x, entry);
        }
        count += 1;
        bytes += str.length;
        if (pageFull(count, bytes)) {
          if (!(await drained(ws))) return false;
          count = 0;
          bytes = 0;
        }
      }
      page = [];
      return true;
    };
    for (const x of elems) {
      page.push(x);
      if (page.length >= CFG.flushPage) {
        if (!(await sendPage())) return;
      }
    }
    if (page.length) await sendPage();
  }

  /**
   * Every SWEEP_INTERVAL_SECONDS: walk the mailboxes and expire what has
   * outlived QUEUE_TTL_HOURS at the head of each. SCAN, so the store is
   * never asked for all its keys at once; both instances sweep, which is
   * harmless — the script is idempotent.
   */
  async sweep() {
    // One sweep at a time: with many mailboxes a pass can outlast the
    // interval, and passes that overlap pile up instead of degrading.
    if (this.sweeping) return;
    this.sweeping = true;
    try {
      let cursor = '0';
      do {
        const [next, keys] = await this.cmd.scan(cursor, 'MATCH', 'q:*', 'COUNT', '200');
        cursor = next;
        for (const key of keys) {
          try {
            await this._expireAll(key.slice(2), 200);
          } catch {
            // A store that is unreachable for a moment: the next sweep tries again.
          }
        }
      } while (cursor !== '0');
    } finally {
      this.sweeping = false;
    }
  }

  /**
   * Refresh this instance's presence for every socket it holds.
   *
   * One rid at a time, and a failure costs that rid rather than the pass.
   * Until 2026-09-14 anything that was not an out-of-memory error was
   * rethrown out of the loop — a reset connection, a timeout, ioredis
   * running out of its three retries — and the call site swallows it
   * (`.catch(() => {})`), so every rid after the failing one went
   * unrefreshed with nothing said. Presence then expired at 60 s against
   * this 25 s refresh, the other instance began queueing their mail instead
   * of pushing it, and the envelope sat there: findings 16 and 19 of the
   * review are the same outage seen from two ends.
   *
   * `sweep` had this right already — a per-item catch and a re-entrancy
   * guard — and this is the same shape. The guard matters here too: with
   * many sockets a pass of sequential round trips can outlast the 25 s
   * interval, and passes that overlap pile up rather than degrade.
   */
  async heartbeat() {
    if (this.beating) return;
    this.beating = true;
    try {
      for (const rid of this.local.keys()) {
        try {
          await this.cmd.set(`presence:${rid}`, this.id, 'EX', 60);
          this.presenceStale.delete(rid);
        } catch (e) {
          if (isStoreFull(e)) {
            METRICS.presenceDeferredTotal += 1;
          } else {
            // Not the store being full: the store being unreachable, or
            // slow. Counted apart, because it means something different to
            // an operator — nothing is wrong with the data, something is
            // wrong with the connection — and because it was invisible.
            METRICS.presenceRefreshFailedTotal += 1;
          }
          this.presenceStale.add(rid);
        }
      }
    } finally {
      this.beating = false;
    }
  }

  /**
   * Deliver again to a socket that is connected and is not being drained.
   *
   * `flush` was called from exactly one place — the `auth` case, right after
   * `ready` — so the only way a queued envelope reached a connected device
   * was for that device to reconnect. A live push that went nowhere (a stale
   * presence record, an instance that went away between the publish and the
   * frame) therefore waited for a reconnect that a healthy client has no
   * reason to make, and the floor was QUEUE_TTL_HOURS: three days, with the
   * sender told `sent` and nothing anywhere saying otherwise.
   *
   * The signal is a mailbox that is not EMPTYING, not a mailbox that is
   * full. A device draining a backlog holds a non-empty mailbox for as long
   * as that takes and is working perfectly; one whose length has not moved
   * across a whole interval, while its socket is right here, is one whose
   * mail is not arriving. So the check is one `LLEN` per local socket per
   * pass — the same shape and cadence as the presence refresh beside it —
   * and only a length that has not changed since the last pass costs a
   * flush.
   *
   * That makes the worst case a re-delivery per mailbox per interval, which
   * the client already handles: delivery is at-least-once and dedupe is by
   * envelope id (§12.5). Doing nothing was the other option, and it is what
   * three days of invisible mail looked like.
   */
  async reflushStalled(flushTo) {
    if (this.reflushing) return;
    this.reflushing = true;
    try {
      for (const [rid, ws] of this.local) {
        let len;
        try {
          len = await this.cmd.llen(`q:${rid}`);
        } catch {
          continue; // the next pass asks again
        }
        const before = this.lastMailboxLen.get(rid);
        if (len === 0) {
          this.lastMailboxLen.delete(rid);
          continue;
        }
        this.lastMailboxLen.set(rid, len);
        if (before !== len) continue; // it is moving: the client is draining
        METRICS.reflushedTotal += 1;
        try {
          await flushTo(rid, ws);
        } catch {
          // A socket that has gone, or a store that is unreachable for a
          // moment. Either way the next pass tries again.
        }
      }
      // Rids that are no longer connected here stop being remembered.
      for (const rid of this.lastMailboxLen.keys()) {
        if (!this.local.has(rid)) this.lastMailboxLen.delete(rid);
      }
    } finally {
      this.reflushing = false;
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
          // What MAX_STORE_BYTES is checked against, in single-instance mode
          // (Redis refuses against the store's own maxmemory and keeps no
          // global counter, so it is absent there). Published because this
          // number drifting away from the mail actually held is a fault that
          // was otherwise invisible: TTL expiry used to free the mail without
          // crediting the counter, so a relay that had once been busy refused
          // every send for ever while reporting `queuedEnvelopes: 0`.
          ...(s.storeBytes !== undefined ? { storeBytes: s.storeBytes } : {}),
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
    // Android App Links (17.3b). Read at request time, not at start-up, so
    // setting the fingerprint is a restart of the service rather than a
    // redeploy of the code — and so its absence is a 404 rather than an
    // empty claim.
    if (req.url === '/.well-known/assetlinks.json') {
      const body = androidAssetLinks(process.env.ANDROID_CERT_SHA256);
      if (body) {
        res.writeHead(200, {
          'content-type': 'application/json; charset=utf-8',
          'cache-control': 'public, max-age=3600',
        });
        res.end(body);
        return;
      }
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
      acksInFlight: 0,
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
      // Rate limit, in two halves. This half is BEFORE the parse and costs
      // nothing: an exhausted bucket drops the frame unread, which is what
      // bounds the cost of a flood of large frames. (Between 2.7.9 and
      // 2.8.2 the whole limiter ran after the parse, because it needed the
      // frame's type to exempt an acknowledgement — so a rate-limited
      // 900 KB frame was parsed before being refused, and an
      // unauthenticated socket could spend the relay's time for free:
      // roadmap revision 45.)
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
      let frame;
      try {
        frame = JSON.parse(data.toString('utf8'));
      } catch {
        state.tokens -= 1;
        sendJson(ws, { t: 'error', code: 'bad_json' });
        return;
      }
      // And this half charges for it — unless it is a small acknowledgement
      // that matched something. A device draining a backlog acknowledges as
      // fast as it persists, hundreds a second, and each one costs the relay
      // one bounded lookup while freeing memory, so those stay free; an
      // acknowledgement that is large, or that names nothing the mailbox
      // holds, is charged like any other frame.
      //
      // The exemption bounds the RATE and not the number in flight, and
      // that distinction was the hole. The debit happens in the `.then()`,
      // so every acknowledgement that arrives in one read passes the gate
      // before any of them is charged: fifty thousand small frames in one
      // burst issued their lookups — up to two hundred and ten store calls
      // each on a miss — before the bucket moved at all.
      //
      // Charging them synchronously instead would break the thing the
      // exemption exists for, because a device draining a backlog really
      // does acknowledge faster than the bucket refills, and that is
      // correct behaviour that frees memory. So what is bounded is how many
      // may be in the store AT ONCE: past that, an acknowledgement is
      // charged like any other frame and the gate above refuses the rest
      // unread. A client draining a paged flush has about `FLUSH_PAGE` in
      // flight, far below this, and is untouched.
      const smallAck = frame.t === 'recv' && data.length <= 512 && state.acksInFlight < CFG.ackInFlight;
      if (!smallAck) state.tokens -= 1;
      if (smallAck) state.acksInFlight += 1;
      handleFrame(ws, state, coord, frame, pushSender)
        .then((free) => {
          if (smallAck) {
            state.acksInFlight -= 1;
            if (free !== true) state.tokens -= 1;
          }
        })
        .catch(() => {
          if (smallAck) {
            state.acksInFlight -= 1;
            state.tokens -= 1;
          }
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

  // And on the same cadence, deliver again to any socket that is connected
  // and whose mailbox has not moved since the last pass — a live push that
  // went nowhere. `flush` is otherwise reached only from `auth`, so before
  // this the recovery for a lost push was the recipient reconnecting.
  const reflusher = setInterval(() => {
    Promise.resolve(coord.reflushStalled((rid, ws) => coord.flush(rid, ws))).catch(() => {});
  }, CFG.sweepIntervalMs);
  reflusher.unref();

  httpServer.on('close', () => {
    clearInterval(heartbeat);
    clearInterval(sweeper);
    clearInterval(reflusher);
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
      // A mailbox is the base64url of a SHA-256, so anything else is not a
      // mailbox: refuse it rather than creating three store keys named after
      // it. (Every `to` the protocol sends is a routing id, pairing's
      // throwaway identities included — PROTOCOL §2.4, §12.2.)
      // Size first: an envelope over the cap gets `too_large` whatever else
      // is wrong with the frame, because that is the one refusal a client
      // must not retry (PROTOCOL §14).
      if (payload.length > CFG.maxEnvelopeBytes) {
        sendJson(ws, { t: 'error', code: 'too_large', id });
        return;
      }
      if (!to || !ROUTING_ID.test(to) || !id || id.length > 64 || !payload) {
        sendJson(ws, { t: 'error', code: 'bad_send', id });
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
      // What the SENDER is told, which is not always what the relay knows.
      //
      // `queued` is `!live`, so on an authenticated socket it is ordinary
      // feedback about one's own conversation. On a connection that never
      // authenticated it is something else: anyone who has ever seen a
      // contact code can send a 60-byte sealed envelope to that routing id
      // from an anonymous socket and read `queued:false` as "that person is
      // online, now". Once a minute is a 24/7 activity timeline for someone
      // with no relationship to them at all. THREAT_MODEL grants presence to
      // the relay operator (R1); it does not grant it to the internet.
      //
      // So an anonymous sender is told the envelope is held, always. It
      // costs that sender nothing real — the Dart client discards the value,
      // and clients send every sealed envelope this way (§12.1) — and the
      // push decision below still uses what actually happened, so a wake
      // ping does not start firing for recipients who are connected.
      sendJson(ws, { t: 'sent', id, queued: state.authed ? queued : true });
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
      if (!state.authed) return false;
      const ackId = String(frame.id || '');
      const ackFrom = String(frame.from || '');
      // The same bounds `send` puts on the same two fields, for the same
      // reason: both become store keys. `send` caps `id` at 64 characters
      // and requires `to` to be the shape of a routing id; `recv` checked
      // neither, so a throwaway keypair and 1 MB `id`s made the ack script
      // build nine ~1 MB keys and issue nine HGETs inside one blocking Lua
      // call — about 9 MB of hashing per frame, at 80 frames a second, on
      // the store every mailbox shares. An unbounded `from` was worse in
      // kind than in size: in RAM mode it names the mailbox a receipt is
      // enqueued to, so it could create one under any string at all.
      //
      // Refused by being ignored, not by an error: §12.5.2 says an
      // acknowledgement that names nothing the mailbox holds is answered
      // with no frame, and a client must not be able to tell the two apart.
      if (!ackId || ackId.length > 64) return false;
      if (ackFrom && !ROUTING_ID.test(ackFrom)) return false;
      // `from` absent/empty = a sealed envelope being acked by id alone.
      // The answer says whether anything was removed: the rate limiter
      // charges for an acknowledgement that names nothing, since that is
      // the one that costs a search.
      const freed = await coord.ack(state.rid, ackFrom, ackId);
      if (!freed) METRICS.ackMissTotal += 1;
      return freed;
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
