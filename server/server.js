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
  latestJson,
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
  // How long a flush will wait for a socket to drain below the high-water
  // mark before terminating it (P1-13). A reader on a slow link drains in
  // well under this; one that never does is a stuck reader holding a page of
  // the relay's memory, and is dropped (it reconnects and the flush restarts,
  // delivery being at-least-once).
  drainTimeoutMs: intEnv('DRAIN_TIMEOUT_SECONDS', 60) * 1000,
  // The most one socket may have buffered and unread before it is dropped
  // (P1-13). Must stay above what a flush legitimately leaves in a socket —
  // about 2 × FLUSH_HIGH_WATER_BYTES plus one envelope (~3 MB at the
  // defaults) — so an honest slow reader is paged, not dropped.
  sendBufferCapBytes: intEnv('SEND_BUFFER_CAP_BYTES', 8 * 1024 * 1024),
  // And the most ALL sockets together may hold that way (P1-13). The
  // per-socket cap alone bounds one socket, not the relay: N sockets that
  // stop reading would hold N × the cap. Past this, the socket holding the
  // most is dropped first — an attacker's, filling towards its cap, before an
  // honest slow reader, which a paged flush keeps near FLUSH_HIGH_WATER.
  sendBufferTotalBytes: intEnv('SEND_BUFFER_TOTAL_BYTES', 64 * 1024 * 1024),
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
  // them without telling anyone. The figure is per instance, so N instances
  // admit N × it between them, unless NEW_MAILBOX_SHARED=on makes it the
  // figure for the whole relay (below).
  newMailboxPerMin: intEnv('NEW_MAILBOX_PER_MIN', 120),
  // How many routing ids this instance remembers having queued for, so the
  // admission gate above is charged on first contact rather than on an empty
  // mailbox. Measured at 117 bytes an entry, so 100 000 is 11.2 MiB.
  seenMailboxCap: intEnv('SEEN_MAILBOX_CAP', 100000),
  // And for how long. An hour means at most one token per recipient per hour,
  // against an allowance of NEW_MAILBOX_PER_MIN × 60.
  seenMailboxTtlMs: intEnv('SEEN_MAILBOX_TTL_MIN', 60) * 60000,
  // Whether the mailbox-creation allowance is shared across instances through
  // the store (25.3). OFF unless NEW_MAILBOX_SHARED=on. Off, every instance
  // keeps its own bucket exactly as it always has, so N instances admit
  // N × NEW_MAILBOX_PER_MIN between them. On, NEW_MAILBOX_PER_MIN is the
  // relay-wide figure — set it to N × the per-instance value to keep the same
  // total — and two things change that make it an operator's decision rather
  // than a default: a flood that spends the window spends it for every
  // instance at once (a gate everybody shares is a switch whoever fills it
  // holds, R32), and an instance that restarts or is newly added pays first
  // contact again, against that shared window, for every recipient it has not
  // queued for since it started (`seen` is this process's memory and nothing
  // else may be: a shared record of who was written to would be a record of
  // routing ids in the store). Inert on a single-instance RAM relay, whose own
  // gate is already relay-wide. The shared counter is one integer per window —
  // a count of creations, never a routing id.
  newMailboxShared: (process.env.NEW_MAILBOX_SHARED || '').trim().toLowerCase() === 'on',
  // The whole RAM queue's ceiling in single-instance mode. The Redis path
  // has the store's own `noeviction` limit to refuse against; this one had
  // nothing at all, so the answer to the same flood was an OOM kill instead
  // of the documented refusal.
  maxStoreBytes: intEnv('MAX_STORE_BYTES', 192 * 1024 * 1024),
  // --- first-contact abuse limits (phase 29, THREAT_MODEL R22, P0-4) ---
  //
  // One unauthenticated socket used to fill the whole store with mailboxes
  // addressed to routing ids nobody holds (~253 frames of 1 MB in ~7 s), so
  // every send by every user got `store_full` for up to QUEUE_TTL_HOURS. The
  // per-mailbox caps bound what ONE recipient holds and the creation gate
  // rations how fast new mailboxes appear, but neither bounds the SUM a flood
  // of first contacts can hold. These do.
  //
  // A mailbox is UNOWNED until the routing id it is addressed to has
  // authenticated to this relay at least once (`register`). An unowned mailbox
  // is exactly the one nobody has proved they can drain, which is the only
  // kind a flood needs. Ownership is recorded at auth, keyed by the routing id
  // the relay already knows (no new identity information), and in the Redis
  // path it is a store key so it survives a relay restart; RAM mode keeps it
  // in a Set, which a restart loses along with the queue it would have capped.
  ownedTtlMs: intEnv('OWNED_TTL_DAYS', 30) * 24 * 3600 * 1000,
  // RAM mode only: how many owned routing ids the process remembers, the
  // least recently authenticated forgotten first (the Redis path's keys
  // expire on OWNED_TTL instead). Without a bound, throwaway identities that
  // authenticate once each would grow the relay's memory for ever; ≈120 bytes
  // an entry, so the default is ≈24 MB. A forgotten owner is merely unowned
  // again until it next authenticates.
  ownedCap: intEnv('OWNED_CAP', 200000),
  // The byte cap for ONE unowned mailbox: enough for a first contact and the
  // few messages before the recipient first connects, small enough that
  // filling the store needs many mailboxes (and NEW_MAILBOX_PER_MIN rations
  // how fast those appear). Once the recipient authenticates the mailbox is
  // owned and MAX_QUEUE_BYTES_PER_USER applies instead.
  unownedMailboxBytes: intEnv('UNOWNED_MAILBOX_BYTES', 2 * 1024 * 1024),
  // The whole store's budget for unowned bytes, across every unowned mailbox
  // at once — a modest fraction of the store, so first-contact traffic can
  // never crowd out what owned mailboxes need. Past it an unowned send is
  // refused `store_full` (counted z_unowned_refused_total) and retried; owned
  // mailboxes are unaffected. Absolute, because the Redis path has no single
  // MAX_STORE_BYTES to take a fraction of.
  unownedStoreBytes: intEnv('UNOWNED_STORE_BYTES', 32 * 1024 * 1024),
  // Per-IP budget on unowned bytes a minute, keyed on the client IP — the
  // CLIENT_IP_HEADER value when configured, else the socket address. Mirrors
  // kt's KT_CLIENT_IP_HEADER: a limiter keyed on a value the caller picks is
  // worse than none, so the header is honoured only when the operator names a
  // front known to set it. Behind a front with no header every client shares
  // one address, so this collapses to one bucket and the GLOBAL budget above
  // is what bounds the flood; set the header to make it per-client.
  unownedBytesPerIpPerMin: intEnv('UNOWNED_BYTES_PER_IP_PER_MIN', 4 * 1024 * 1024),
  // Connection caps. The global one is always on. The per-IP one engages only
  // when CLIENT_IP_HEADER is set, because keyed on a shared front address it
  // would cap the whole relay's connections at one number (the global cap is
  // the backstop for the unconfigured case).
  maxConnections: intEnv('MAX_CONNECTIONS', 20000),
  maxConnectionsPerIp: intEnv('MAX_CONNECTIONS_PER_IP', 256),
  // A socket that has not authenticated and has sent nothing for this long is
  // closed. ADR 0007: an anonymous sealed-send socket never authenticates and
  // is legitimate — but it pings every 25 s, which counts as activity, so
  // this closes only a socket doing nothing at all. Not an auth deadline.
  unauthIdleMs: intEnv('UNAUTH_IDLE_SECONDS', 120) * 1000,
  // How often the relay pings its sockets, refreshes presence, and checks the
  // idle timeout above. 25 s against the 60 s presence TTL; configurable so a
  // test can exercise the idle close without waiting on the wall clock.
  heartbeatMs: intEnv('HEARTBEAT_SECONDS', 25) * 1000,
  // The header a configured front sets to the real client address (e.g.
  // CF-Connecting-IP). Unset → the socket address is used (correct for a
  // direct relay; one bucket for everyone behind an unconfigured front).
  clientIpHeader: (process.env.CLIENT_IP_HEADER || '').trim().toLowerCase() || null,
  // The bearer token `/metrics` requires. Unset → `/metrics` answers 404 (the
  // safe default: the counters are a presence oracle, so an unauthenticated
  // scrape must learn nothing, not even that the endpoint exists). Compared in
  // constant time.
  metricsToken: process.env.METRICS_TOKEN || null,
  tlsCert: process.env.TLS_CERT || null,
  tlsKey: process.env.TLS_KEY || null,
  // Whether the unbound v1 authentication is still accepted. A v1 signature
  // is over the nonce alone, so one obtained by any relay the user was
  // talking to authenticates here (finding 13); v2 signs the relay's
  // authority with it. Kept on for clients that predate v2, counted in
  // z_auth_v1_total, and turned off (RELAY_AUTH_V1=off) once that count
  // has been zero for as long as the operator cares to wait.
  authV1: (process.env.RELAY_AUTH_V1 || 'on').trim().toLowerCase() !== 'off',
  // The names this relay answers to: the ONLY names a v2 signature is checked
  // against (P1-16). It is NOT the Host header the presenter sent — the
  // presenter controls that, so a relay that verified against it would accept
  // a signature a victim was tricked into making for the presenter's own name
  // (the splice). RELAY_AUTHORITIES is the operator's list (comma-separated,
  // host or host:port), plus any name the platform hands the process so a
  // self-hoster on a PaaS need not spell its own address out. An unconfigured
  // relay (empty list) is handled at verification time: a loopback/LAN name
  // dialled from a loopback/LAN address is trusted (no machine-in-the-middle
  // boundary to protect — the dev and test case); anything else is refused
  // until the operator lists the relay's names (`isLocalAuthority`).
  authorities: computeAuthorities(),
  logLevel: process.env.LOG_LEVEL || 'info', // 'silent' | 'info'
  // HA mode: when set, coordinate presence + queue through Redis.
  redisUrl: process.env.REDIS_URL || null,
  instanceId: process.env.INSTANCE_ID || crypto.randomBytes(6).toString('hex'),
};

function intEnv(name, dflt) {
  const v = parseInt(process.env[name] ?? '', 10);
  return Number.isFinite(v) ? v : dflt;
}

/**
 * The relay's authority as a client names it: what it dialled, lower-case,
 * with the port only when it is not the scheme's default. A client puts
 * exactly this in its Host header (Dart and Node both omit a default port
 * and lower-case the host). `RELAY_AUTHORITIES` is normalised by this too,
 * and since phase 29 those configured names — not the header — are what a v2
 * signature is verified against; the header matters only to an unconfigured
 * relay on a loopback/LAN name (`isLocalAuthority`). An IPv6 literal keeps
 * its brackets, as the header has them.
 */
function normalizeAuthority(host) {
  if (typeof host !== 'string') return '';
  const h = host.trim().toLowerCase();
  if (!h) return '';
  return h.replace(/:(80|443)$/, '');
}

/**
 * The names a v2 signature may be checked against: `RELAY_AUTHORITIES`, plus
 * whatever name the hosting platform hands the process. Render sets
 * `RENDER_EXTERNAL_HOSTNAME`; Fly sets `FLY_APP_NAME` (whose host is
 * `<app>.fly.dev`). These are the relay's own names — a client that dials the
 * platform URL directly signs one of them — so accepting them is a
 * convenience, not a loosening: nothing the presenter sends enters this set.
 */
function computeAuthorities() {
  const names = new Set();
  for (const a of (process.env.RELAY_AUTHORITIES || '').split(',')) {
    const n = normalizeAuthority(a);
    if (n) names.add(n);
  }
  const render = normalizeAuthority(process.env.RENDER_EXTERNAL_HOSTNAME || '');
  if (render) names.add(render);
  const fly = (process.env.FLY_APP_NAME || '').trim().toLowerCase();
  if (fly) names.add(normalizeAuthority(`${fly}.fly.dev`));
  return [...names];
}

/**
 * Whether a host (a name, or an address without brackets or port) is
 * loopback, private-range or `.local`: IPv4 127/8, 10/8, 172.16/12,
 * 192.168/16, 169.254/16; IPv6 ::1, fc00::/7, fe80::/10 (and the v4-mapped
 * forms); `localhost`, `*.localhost`, `*.local`. An IPv6 prefix is matched
 * only on an IPv6 literal, so a public name such as `fd.example` is not local.
 */
function isLocalHost(host) {
  if (!host) return false;
  let h = String(host).toLowerCase();
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  if (h.startsWith('::ffff:') && h.includes('.')) h = h.slice('::ffff:'.length);
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local')) return true;
  if (h.includes(':')) return h === '::1' || /^f[cd][0-9a-f]{2}:/.test(h) || /^fe[89ab][0-9a-f]:/.test(h);
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (!m) return false;
  const a = Number(m[1]);
  const b = Number(m[2]);
  return a === 127 || a === 10 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254);
}

/**
 * Whether an unconfigured relay (no `RELAY_AUTHORITIES`, no platform name)
 * may verify a v2 signature against the name a connection dialled (P1-16).
 * Both halves must be local: the dialled authority names a loopback,
 * private-range or `.local` host, AND the TCP peer is itself a loopback or
 * private address — a developer's `ws://127.0.0.1`, a LAN relay, the test
 * suite, a proxy on the same host. That is the deployment with no
 * machine-in-the-middle boundary to protect, the same boundary the app draws
 * for cleartext without a warning. A public name, or a local name presented
 * from the internet (a signature a victim made for some LAN relay, replayed
 * here), is refused rather than verified against a name the caller chose.
 */
function isLocalAuthority(authority, peerAddress) {
  if (!authority || !isLocalHost(peerAddress)) return false;
  const bracketed = /^\[([^\]]*)\](?::\d+)?$/.exec(authority);
  if (bracketed) return bracketed[1].includes(':') && isLocalHost(bracketed[1]);
  return isLocalHost(authority.replace(/:\d+$/, ''));
}

/** The address to hold responsible for a connection: the CLIENT_IP_HEADER
 * value when the operator has named a front known to set it, else the socket
 * address. A forwarded header is the caller's to choose unless something in
 * front overwrites it, so it is read only when configured (as kt/ does). */
function clientIp(req) {
  if (CFG.clientIpHeader) {
    const v = req && req.headers ? req.headers[CFG.clientIpHeader] : undefined;
    const first = (Array.isArray(v) ? v[0] : v || '').split(',')[0].trim();
    if (first && first.length <= 45 && /^[0-9a-fA-F:.]+$/.test(first)) return first;
  }
  return (req && req.socket && req.socket.remoteAddress) || 'unknown';
}

/**
 * Whether a `/metrics` request carries the configured bearer token (P1-14).
 * No token configured → never authorized (the handler then 404s, the safe
 * default). The compare hashes both sides to a fixed width and uses
 * `timingSafeEqual`, so neither the token's value nor its length leaks through
 * timing.
 */
function metricsAuthorized(req) {
  if (!CFG.metricsToken) return false;
  const h = (req && req.headers && req.headers['authorization']) || '';
  const m = /^Bearer\s+(.+)$/i.exec(Array.isArray(h) ? h[0] : h);
  const presented = m ? m[1] : '';
  const a = crypto.createHash('sha256').update(presented).digest();
  const b = crypto.createHash('sha256').update(CFG.metricsToken).digest();
  return crypto.timingSafeEqual(a, b);
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

// v1 signs the nonce alone. A nonce is the relay's, but nothing in the
// signature says WHICH relay: a relay the user was induced to connect to —
// a pasted address, an invite, a MITM on a ws:// address — could open its own
// socket to this one, hand this one's nonce to the user as its own challenge,
// and replay the signature it got back, authenticated as that device here,
// with the `ready` flush and everything queued from then on (the 2026-09-14
// review's finding 13). v2 puts the relay's authority under the signature,
// so a signature made for one relay verifies at no other. The nonce is the
// fixed-width last field, so the concatenation is unambiguous.
const AUTH_CONTEXT = Buffer.from('z-relay-auth-v1:', 'utf8');
const AUTH_CONTEXT_V2 = Buffer.from('z-relay-auth-v2:', 'utf8');

function routingIdFromPub(rawPub32) {
  return crypto.createHash('sha256').update(rawPub32).digest('base64url');
}

/** What a routing id looks like: base64url of a SHA-256, so 43 characters. */
const ROUTING_ID = /^[A-Za-z0-9_-]{43}$/;

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------
// Sockets holding more than this unread are summed against
// SEND_BUFFER_TOTAL; a socket that reads promptly never enters the set, so the
// relay-wide check costs nothing for nearly every send. The set holds at most
// SEND_BUFFER_TOTAL / HEAVY_SOCKET_BYTES live members before the budget
// starts dropping them, which bounds the cost of a check too.
const HEAVY_SOCKET_BYTES = 256 * 1024;
const heavySockets = new Set();

/** Drops a socket for not reading (P1-13), counted. */
function dropSlowReader(ws) {
  heavySockets.delete(ws);
  METRICS.slowReaderClosedTotal += 1;
  try {
    ws.terminate();
  } catch {}
}

/**
 * Over SEND_BUFFER_TOTAL: drop whichever socket holds the most. Returns true
 * when that was `ws` itself. Prunes sockets that have drained or closed.
 */
function enforceSendBudget(ws) {
  let total = 0;
  let worst = null;
  let worstBytes = -1;
  for (const w of heavySockets) {
    const b = w.readyState === w.OPEN ? w.bufferedAmount : 0;
    if (b <= HEAVY_SOCKET_BYTES) {
      heavySockets.delete(w);
      continue;
    }
    total += b;
    if (b > worstBytes) {
      worst = w;
      worstBytes = b;
    }
  }
  if (total <= CFG.sendBufferTotalBytes || !worst) return false;
  dropSlowReader(worst);
  return worst === ws;
}

function sendJson(ws, obj) {
  if (ws && ws.readyState === ws.OPEN) {
    ws.send(JSON.stringify(obj));
    // A peer that has stopped reading must not make the relay buffer for it
    // without bound (P1-13: a socket that sent frames and read none of the
    // replies took the relay +880 MiB in 9 s). Every outbound frame — a
    // reply, a live delivery, a flush page — lands here, so this is the one
    // place the caps hold for all of them: past SEND_BUFFER_CAP this socket
    // is dropped, and past SEND_BUFFER_TOTAL across all sockets the one
    // holding the most is. Nothing is lost: mail stays queued until
    // acknowledged, and a reader that resumes reconnects and is flushed
    // again (§12.5).
    const b = ws.bufferedAmount;
    if (b > CFG.sendBufferCapBytes) {
      dropSlowReader(ws);
      return false;
    }
    if (b > HEAVY_SOCKET_BYTES) {
      heavySockets.add(ws);
      if (enforceSendBudget(ws)) return false;
    }
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
 *
 * A socket that stays above the mark for `DRAIN_TIMEOUT` is TERMINATED and
 * this resolves false (P1-13): backpressure alone bounds what one slow reader
 * costs to a page plus the mark, but a socket that never drains would hold
 * that page and tie up a flush indefinitely, and many of them are a way to
 * pin the relay's memory at the bound × the connection count. The WS
 * ping/pong heartbeat catches a dead socket in ≤50 s; this catches one that
 * keeps its TCP window shut while answering pongs.
 */
async function drained(ws) {
  const deadline = Date.now() + CFG.drainTimeoutMs;
  while (ws.readyState === ws.OPEN && ws.bufferedAmount > CFG.flushHighWaterBytes) {
    if (Date.now() > deadline) {
      dropSlowReader(ws);
      return false;
    }
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
  // First-contact sends refused by an unowned-mailbox limit (P0-4): the
  // per-unowned-mailbox byte cap, the relay-wide unowned budget, or the
  // per-IP unowned rate. All reach the sender as `store_full` (retried), and
  // are counted HERE and not in z_store_full_total — the store is not full,
  // a flood of mailboxes nobody owns is being bounded. Zero in ordinary use,
  // so a non-zero rate is the flood signal the alert watches. An owned
  // mailbox never touches any of these, so honest traffic never counts here.
  unownedRefusedTotal: 0,
  // Sockets dropped for not reading (P1-13): their unread output passed
  // SEND_BUFFER_CAP, or they held the most when all sockets together passed
  // SEND_BUFFER_TOTAL, or a flush waited DRAIN_TIMEOUT for them to drain. An
  // honest client on a slow link is paged long before any of these, so a
  // steady count is somebody holding sockets open without reading them.
  slowReaderClosedTotal: 0,
  // Connections refused at MAX_CONNECTIONS or, with CLIENT_IP_HEADER set, at
  // MAX_CONNECTIONS_PER_IP — counted, because a cap that refuses in silence
  // is an outage nobody can see.
  connectionsRefusedTotal: 0,
  // Unauthenticated sockets closed for sending nothing for UNAUTH_IDLE.
  idleClosedTotal: 0,
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
  // Envelopes a mailbox listed whose BODY was not in the shared store when
  // the mailbox was flushed. One thing does this legitimately and rarely: an
  // acknowledgement landing between the list being read and the bodies
  // being fetched. The other is a store that evicted the body while the list
  // kept its key — what `allkeys-lru` does at maxmemory, and what the shipped
  // compose file ran until 2026-09-17: an envelope whose sender was told
  // `sent`, gone, with nothing counting it (the 2026-09-14 review's finding
  // 14). The dangling key is dropped so the same loss is counted once, not
  // at every login; the store must run `noeviction`, and anything but a
  // trickle here says it does not.
  bodyMissingTotal: 0,
  // Authentications that used the unbound v1 signature. What says when
  // RELAY_AUTH_V1 can be turned off: clients that predate the bound form are the only
  // honest source, and every one of these is also the shape finding 13
  // replays.
  authV1Total: 0,
  // v2 authentications that verified under none of this relay's names — a
  // client that dialled one name while the front presented another
  // (RELAY_AUTHORITIES is for that), a signature made for another relay,
  // which is the replay the binding exists to stop, or a bad signature.
  authV2RefusedTotal: 0,
  // Sends refused because too many mailboxes were being CREATED at once.
  // Counted apart from the line above because it means something different
  // to an operator: the store is not full, and what was refused was a first
  // envelope to an address nothing had been sent to yet. Ordinary traffic
  // never touches it, so anything but zero is either a flood or a limit set
  // too low for the deployment's rate of first contacts. Counted HERE and not
  // also in z_store_full_total — both refusals reach the sender as
  // `store_full`, but until 2026-10-02 the Redis path counted this one under
  // both names (RAM never did), so a flood paged as a full store.
  newMailboxRefusedTotal: 0,
  // Mailbox-creation decisions the shared gate (NEW_MAILBOX_SHARED=on) could
  // not make — its counter unreachable, or unreadable — so this instance fell
  // back to its own per-instance bucket. Each one is a moment the relay-wide
  // allowance was N × the configured one. Not counted when the store is
  // simply full: the push that follows is refused for the same want of memory
  // and counted as z_store_full_total.
  newMailboxSharedFallbackTotal: 0,
  // Sends answered `internal`: the relay could not store or route an envelope
  // for a reason it did not expect — in Redis mode, overwhelmingly the store
  // being unreachable. `/health` cannot show this, deliberately (it does not
  // touch the store, so a store blip does not get healthy instances
  // restarted), which is why it is counted: it is the availability signal
  // `/health` is not.
  sendInternalErrorTotal: 0,
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

/**
 * A per-IP budget of unowned bytes per minute (P0-4). RAM, per instance: an
 * IP-keyed limit is inherently local to the instance a socket landed on, and
 * the relay must not keep a per-address record in the shared store. Keyed on
 * whatever `clientIp` resolves — the CLIENT_IP_HEADER value when the operator
 * has named a front that sets it, else the socket address — so behind a front
 * with no header it collapses to one bucket and the relay-wide unowned budget
 * is what bounds the flood instead. A fixed window, reset lazily, pruned by
 * the sweep.
 */
class IpByteBudget {
  constructor(perMinute, now = Date.now) {
    this.perMinute = perMinute;
    this.now = now;
    this.windowMs = 60000;
    this.ips = new Map(); // ip -> { bytes, at }
  }
  _cur(ip) {
    const t = this.now();
    let e = this.ips.get(ip);
    if (!e || t - e.at >= this.windowMs) {
      e = { bytes: 0, at: t };
      this.ips.set(ip, e);
    }
    return e;
  }
  /** True if [ip] has already spent its minute's unowned allowance. Reads
   * only: an address is recorded when it is charged, never for asking. */
  over(ip) {
    const e = this.ips.get(ip);
    return !!e && this.now() - e.at < this.windowMs && e.bytes >= this.perMinute;
  }
  /** Record unowned bytes just accepted from [ip]. */
  charge(ip, bytes) {
    this._cur(ip).bytes += bytes;
  }
  /** Drop windows that have rolled over, so an idle relay forgets addresses. */
  prune() {
    const t = this.now();
    for (const [ip, e] of this.ips) {
      if (t - e.at >= this.windowMs) this.ips.delete(ip);
    }
  }
}

function renderMetrics(stats, meta = {}) {
  const L = [];
  // What `/health` used to carry and no longer does, now that `/health` is
  // liveness only and `/metrics` is behind a token (P1-14): the instance id,
  // coordinator, push state and storage, as one info line a scrape reads the
  // labels off. A quoted label value is escaped the Prometheus way.
  const lbl = (s) => String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  L.push('# TYPE z_relay_info gauge');
  L.push(
    `z_relay_info{instance="${lbl(meta.instanceId || '')}",` +
      `coordinator="${lbl(meta.coordinator || '')}",` +
      `push="${lbl(meta.push || '')}",storage="ram-only"} 1`
  );
  L.push('# TYPE z_uptime_seconds gauge');
  L.push(`z_uptime_seconds ${Math.floor(meta.uptimeSec || 0)}`);
  L.push('# TYPE z_sockets gauge');
  L.push(`z_sockets ${meta.sockets == null ? stats.connections : meta.sockets}`);
  L.push('# TYPE z_connections gauge');
  L.push(`z_connections ${stats.connections}`);
  // Omitted rather than reported as -1 where instances share a store and no
  // instance knows the total: a gauge two instances sum to -2 is worse than
  // a gauge that is absent, which a scrape can see and say so.
  if (stats.queuedEnvelopes >= 0) {
    L.push('# TYPE z_queued_envelopes gauge');
    L.push(`z_queued_envelopes ${stats.queuedEnvelopes}`);
  }
  // The store-fill gauge (P0-4): single-instance mode holds the whole queue in
  // the process, so this is the number to alarm on. Absent in Redis mode,
  // where the store's own exporter reports used_memory/maxmemory — hence
  // indented, so a relay that does not emit it is not read as "behind".
  if (stats.storeBytes !== undefined) {
    L.push('# TYPE z_store_bytes gauge');
    L.push(`z_store_bytes ${stats.storeBytes}`);
    L.push('# TYPE z_store_max_bytes gauge');
    L.push(`z_store_max_bytes ${CFG.maxStoreBytes}`);
  }
  // Unowned bytes held, and the budget (P0-4): the store-fill gauge for
  // first-contact traffic. RAM mode counts them directly; Redis mode reports
  // the relay-wide total its last sweep reconciled (absent until then), the
  // same on every instance. Conditional for the same reason as above.
  if (stats.unownedBytes !== undefined) {
    L.push('# TYPE z_unowned_bytes gauge');
    L.push(`z_unowned_bytes ${stats.unownedBytes}`);
    L.push('# TYPE z_unowned_max_bytes gauge');
    L.push(`z_unowned_max_bytes ${CFG.unownedStoreBytes}`);
  }
  // Sockets whose presence write the full store refused (Redis mode): their
  // mail is queued, not pushed, until the heartbeat repairs it. Conditional.
  if (stats.presenceStale !== undefined) {
    L.push('# TYPE z_presence_stale gauge');
    L.push(`z_presence_stale ${stats.presenceStale}`);
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
  L.push('# TYPE z_unowned_refused_total counter');
  L.push(`z_unowned_refused_total ${METRICS.unownedRefusedTotal}`);
  L.push('# TYPE z_slow_reader_closed_total counter');
  L.push(`z_slow_reader_closed_total ${METRICS.slowReaderClosedTotal}`);
  L.push('# TYPE z_connections_refused_total counter');
  L.push(`z_connections_refused_total ${METRICS.connectionsRefusedTotal}`);
  L.push('# TYPE z_idle_closed_total counter');
  L.push(`z_idle_closed_total ${METRICS.idleClosedTotal}`);
  L.push('# TYPE z_cross_instance_total counter');
  L.push(`z_cross_instance_total ${METRICS.crossInstanceTotal}`);
  L.push('# TYPE z_reflushed_total counter');
  L.push(`z_reflushed_total ${METRICS.reflushedTotal}`);
  L.push('# TYPE z_presence_refresh_failed_total counter');
  L.push(`z_presence_refresh_failed_total ${METRICS.presenceRefreshFailedTotal}`);
  L.push('# TYPE z_body_missing_total counter');
  L.push(`z_body_missing_total ${METRICS.bodyMissingTotal}`);
  L.push('# TYPE z_auth_v1_total counter');
  L.push(`z_auth_v1_total ${METRICS.authV1Total}`);
  L.push('# TYPE z_auth_v2_refused_total counter');
  L.push(`z_auth_v2_refused_total ${METRICS.authV2RefusedTotal}`);
  L.push('# TYPE z_new_mailbox_refused_total counter');
  L.push(`z_new_mailbox_refused_total ${METRICS.newMailboxRefusedTotal}`);
  L.push('# TYPE z_new_mailbox_shared_fallback_total counter');
  L.push(`z_new_mailbox_shared_fallback_total ${METRICS.newMailboxSharedFallbackTotal}`);
  L.push('# TYPE z_send_internal_error_total counter');
  L.push(`z_send_internal_error_total ${METRICS.sendInternalErrorTotal}`);
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
 * flood it defends against is charged either way — and, decisively, it would
 * be a record in the store of which routing ids were written to recently,
 * which the relay must not keep. The price is paid by NEW_MAILBOX_SHARED=on:
 * an instance that has just started remembers nobody, so it pays first
 * contact again, against the shared window, for every recipient it writes to
 * (LOAD.md, 25.3).
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
    /**
     * Envelopes held across every queue, kept in step with `bytes` at the
     * same three sites. `stats()` used to recompute this by walking every
     * live mailbox, and `stats()` runs on every unauthenticated `/health`
     * and `/metrics` and on every authentication — O(mailboxes) each, ~10 ms
     * at 200k mailboxes, an unauthenticated cost anyone could impose (the
     * 2026-09-14 review's finding 43). Now it is a counter. A drift here only
     * misreports a metric (admission uses `bytes` and the per-mailbox caps),
     * and `heldEnvelopes()` recomputes it so a test can catch one.
     */
    this.count = 0;
    this.newMailbox = new NewMailboxGate();
    this.seen = new SeenMailboxes();
    /**
     * Routing ids that have authenticated to this relay — the OWNED mailboxes
     * (P0-4) — each with when it last did, oldest first. An unowned mailbox
     * (not in this map) is the one nobody has proved they can drain, so it is
     * capped tightly and its bytes are charged against the relay-wide unowned
     * budget. Bounded by OWNED_TTL and OWNED_CAP (`_trimOwned`). A restart
     * loses it along with the queue it would have capped, so the two stay
     * consistent; the Redis path persists ownership instead.
     */
    this.owned = new Map();
    /** Bytes held across every UNOWNED mailbox: the relay-wide unowned budget
     * is checked against this, kept in step with `bytes` at the same sites. */
    this.unownedBytes = 0;
    this.unownedIp = new IpByteBudget(CFG.unownedBytesPerIpPerMin);
  }

  get name() {
    return 'memory';
  }

  /**
   * Record that [rid] has authenticated: its mailbox is OWNED from now on, so
   * its bytes stop counting against the unowned budget and it gets the full
   * per-user cap. Returns the previous ownership, so a test can see the
   * transition happen once. The decrement of the unowned total by whatever is
   * queued for it is the counterpart to `_enqueue` having added it.
   */
  claimOwner(rid, now = Date.now()) {
    const was = this.owned.delete(rid); // re-inserted below: newest last
    this.owned.set(rid, now);
    if (!was) {
      const q = this.queues.get(rid);
      if (q) this.unownedBytes = Math.max(0, this.unownedBytes - q.bytes);
      this._trimOwned(now);
    }
    return was;
  }

  /**
   * Forgets owners past OWNED_TTL, and the least recently authenticated past
   * OWNED_CAP. A forgotten owner's mailbox is unowned again, so what it holds
   * goes back into the unowned total — the counterpart of `claimOwner`.
   */
  _trimOwned(now = Date.now()) {
    for (const [rid, at] of this.owned) {
      if (this.owned.size <= CFG.ownedCap && now - at <= CFG.ownedTtlMs) break;
      this.owned.delete(rid);
      const q = this.queues.get(rid);
      if (q) this.unownedBytes += q.bytes;
    }
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
    // Authenticating proves the holder can drain this mailbox: it is owned
    // from now on (P0-4), so its queued bytes leave the unowned budget.
    this.claimOwner(rid);
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
    const removed = q.entries.length - kept.length;
    q.entries = kept;
    q.keys = new Map(kept.map((e) => [e.key, e]));
    const was = q.bytes;
    q.bytes = kept.reduce((sum, e) => sum + e.size, 0);
    const freed = was - q.bytes;
    this.bytes = Math.max(0, this.bytes - freed);
    // While the mailbox is still unowned its bytes are in the unowned total
    // too; once it is claimed at auth that total was already settled, so an
    // owned mailbox's expiry must not touch it again.
    if (!this.owned.has(rid)) this.unownedBytes = Math.max(0, this.unownedBytes - freed);
    this.count = Math.max(0, this.count - Math.max(0, removed));
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

  /** The counterpart to `heldBytes` for the envelope count: recomputed by
   * walking the queues, so a test can catch `this.count` drifting from it. */
  heldEnvelopes() {
    let n = 0;
    for (const q of this.queues.values()) n += q.entries.length;
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
    // A mailbox whose owner has never authenticated is UNOWNED (P0-4): nobody
    // has proved they can drain it, so it is held to a tight per-mailbox cap
    // and its bytes are charged against the relay-wide unowned budget, so a
    // flood of first-contact mailboxes can never crowd out what owned
    // mailboxes need. An owned mailbox skips all of this and gets the full
    // per-user cap below. The checks are refusals, so they come before
    // anything is allocated or spent and leave no trace — ahead of the
    // creation gate too, so a flood the budget refuses does not also burn the
    // NEW_MAILBOX_PER_MIN allowance every honest first contact (an owned
    // recipient's emptied mailbox included) needs; the Redis path refunds the
    // token for the same reason.
    const unowned = !this.owned.has(rid);
    if (unowned) {
      const existing = this.queues.get(rid);
      const held = existing ? existing.bytes : 0;
      if (
        this.unownedBytes + entry.size > CFG.unownedStoreBytes ||
        held + entry.size > CFG.unownedMailboxBytes
      ) {
        METRICS.unownedRefusedTotal += 1;
        throw new UnownedRefused();
      }
    }
    // A mailbox that does not exist yet is the expensive one to create, and
    // the only one a flood needs. Charged before anything is allocated — on
    // FIRST CONTACT, not on an empty queue: see `SeenMailboxes` for what
    // charging the empty queue did to an ordinary conversation.
    const known = this.seen.has(rid);
    if (!known && !this.queues.has(rid) && !this.newMailbox.take()) {
      METRICS.newMailboxRefusedTotal += 1;
      throw new NewMailboxRefused();
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
    if (unowned) this.unownedBytes += entry.size;
    this.count += 1;
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
    if (!this.owned.has(rid)) this.unownedBytes = Math.max(0, this.unownedBytes - entry.size);
    this.count = Math.max(0, this.count - 1);
    if (q.entries.length === 0) this.queues.delete(rid);
    return entry;
  }

  async deliverEnqueue(from, to, id, payload, ip) {
    const entry = {
      seq: ++this.seq,
      kind: 'msg',
      id,
      from, // null for sealed-sender envelopes
      payload,
      ts: Date.now(),
      size: envelopeSize(payload),
    };
    // Per-IP unowned budget (P0-4): one address may inject only so many bytes
    // a minute into mailboxes nobody owns. Checked only when the destination
    // is unowned, so an owned conversation is never throttled by it; charged
    // after the store accepts, so a refused send costs the IP nothing. Keyed
    // on `ip` (CLIENT_IP_HEADER value or socket address) — one bucket for
    // everyone behind an unconfigured front, where the relay-wide budget is
    // the real bound.
    const unowned = !this.owned.has(to);
    if (unowned && ip && this.unownedIp.over(ip)) {
      METRICS.unownedRefusedTotal += 1;
      return { queued: false, storeFull: true, unowned: true };
    }
    try {
      if (!this._enqueue(to, entry)) {
        METRICS.refusedTotal += 1;
        return { queued: false, refused: true };
      }
    } catch (e) {
      // The store has no room, or too many mailboxes are being created at
      // once, or an unowned limit was hit. Told promptly and with the id, as
      // the Redis path does, so the sender's outbox pauses and retries rather
      // than waiting out a timeout per envelope (PROTOCOL §12.4). Until
      // 2026-09-14 this coordinator had no such refusal at all and answered
      // the same flood with an OOM kill.
      if (e instanceof StoreFull) {
        return { queued: false, storeFull: true, unowned: e instanceof UnownedRefused };
      }
      throw e;
    }
    if (unowned && ip) this.unownedIp.charge(ip, entry.size);
    METRICS.enqueuedTotal += 1;
    if (from == null) METRICS.sealedTotal += 1;
    const target = this.online.get(to);
    const live = target ? sendJson(target, entryToFrame(entry)) : false;
    if (live) METRICS.deliveredLiveTotal += 1;
    // One process, so "offline" is simply "no socket here": wake then.
    return { queued: !live, push: !live };
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
    this.unownedIp.prune();
    this._trimOwned();
  }

  async heartbeat() {}

  stats() {
    return {
      connections: this.online.size,
      queuedEnvelopes: this.count,
      // What MAX_STORE_BYTES is actually checked against. Reported because
      // the accumulator drifting away from what is held is exactly the
      // failure that used to be invisible: `queuedEnvelopes: 0` beside a full
      // store is the shape of it.
      storeBytes: this.bytes,
      // What the relay-wide unowned budget is checked against (P0-4).
      unownedBytes: this.unownedBytes,
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
// KEYS[4] = owned:{rid} (set when the recipient has authenticated — the
// mailbox is then OWNED and skips the unowned limits), KEYS[5] = z:ub (the
// relay-wide unowned-bytes counter the sweep reconciles). ARGV gains [10] the
// per-unowned-mailbox byte cap, [11] the relay-wide unowned budget, [12]
// whether this IP has spent its minute's unowned allowance (P0-4). Returns a
// two-element array {code, unowned}: code 2 stored+created, 1 stored/existing,
// 0 queue cap, -1 new-mailbox gate, -2 an unowned limit (per-mailbox cap,
// relay-wide budget, or per-IP); `unowned` is 1 when the destination mailbox
// is unowned and something was stored, so the caller charges the per-IP
// budget for exactly what landed.
const REDIS_PUSH_LUA = `#!lua
local owned = redis.call('EXISTS', KEYS[4]) == 1
-- Two entries can want one key. Where the relay can attribute the entry the
-- key carries the party (entryKey), so an occupied key is a retry and
-- storing nothing is right. Where it cannot -- a sealed envelope -- the key
-- is a base and the entry goes in the first free slot. Until 2.8.3 every
-- occupied key meant 'discard, answer sent', which lost mail and let the
-- first member of a group to acknowledge a message suppress every other
-- member's receipt (roadmap revision 45).
local key = ARGV[1]
if ARGV[8] == '1' then
  if redis.call('HEXISTS', KEYS[2], key) == 1 then return {1, 0} end
else
  local dup = 0
  while redis.call('HEXISTS', KEYS[2], key) == 1 do
    dup = dup + 1
    if dup > tonumber(ARGV[7]) then return {0, 0} end
    key = ARGV[1] .. '#' .. dup
  end
end
local len = redis.call('LLEN', KEYS[1])
-- An empty list is a mailbox that does not exist yet, which is the only kind
-- a flood needs and the only kind nobody will ever drain. Decided here rather
-- than by asking first: the script already knows, so admission costs no extra
-- round trip, and no mailbox can be created between the question and the
-- write. -1 says the send was refused for that reason and nothing else.
if len == 0 and ARGV[9] == '0' then return {-1, 0} end
local bytes = 0
if len > 0 then bytes = tonumber(redis.call('GET', KEYS[3]) or '0') end
-- Unowned limits (P0-4): a mailbox whose owner has never authenticated is
-- held to a tight per-mailbox cap and its bytes to the relay-wide budget, and
-- one IP may inject only so much a minute. An owned mailbox skips all three.
local size = tonumber(ARGV[3])
if not owned then
  if ARGV[12] == '1' then return {-2, 1} end
  local ub = tonumber(redis.call('GET', KEYS[5]) or '0')
  if ub + size > tonumber(ARGV[11]) then return {-2, 1} end
  if bytes + size > tonumber(ARGV[10]) then return {-2, 1} end
end
if len + 1 > tonumber(ARGV[4]) or bytes + size > tonumber(ARGV[5]) then
  return {0, owned and 0 or 1}
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
-- Live increment of the relay-wide unowned total; the sweep SETs it to a true
-- recount every interval, so a per-key TTL expiry that frees unowned bytes
-- without passing through here cannot make it drift upward for longer than
-- that (the counterpart of the accumulator leak revision 45 recorded).
if not owned then redis.call('INCRBY', KEYS[5], size) end
-- 2 rather than 1 when this call is what created the mailbox, so the instance
-- knows to keep the token it spent.
if len == 0 then return {2, owned and 0 or 1} end
return {1, owned and 0 or 1}`;

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

// A key the list holds and the hash does not: drop it from the list, and
// the mailbox with it if that was the last one. KEYS as above; ARGV = the
// key. Nothing is settled against the byte counter — the body that would
// have said how much is what is missing — and the counter follows the list
// out when the list empties, or its TTL. Returns how many were removed.
const REDIS_DROP_DANGLING_LUA = `#!lua flags=allow-oom
if redis.call('HEXISTS', KEYS[2], ARGV[1]) == 1 then return 0 end
local n = redis.call('LREM', KEYS[1], 0, ARGV[1])
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
local dangling = 0
local bytes = 0
for i = 1, tonumber(ARGV[2]) do
  local k = redis.call('LINDEX', KEYS[1], 0)
  if not k then break end
  local legacy = string.sub(k, 1, 1) == '{'
  local s = k
  if not legacy then s = redis.call('HGET', KEYS[2], k) end
  if not s then
    -- A key whose body is gone: dropped, and COUNTED, because until
    -- 2026-09-17 this was the quietest of the three places an evicted
    -- envelope could disappear (the flush and the sweep both come through
    -- here first).
    redis.call('LPOP', KEYS[1])
    dangling = dangling + 1
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
return {removed, dangling}`;

// The relay-wide mailbox-creation allowance (NEW_MAILBOX_SHARED=on, 25.3),
// held in the store so N instances share one rate instead of each enforcing
// its own. KEYS[1] = z:nm, ONE hash for the whole relay: `w`, the current
// window's number, and `n`, how many mailboxes were created in it. That is
// all it holds — a count of creations, never a routing id — so the gate
// stores nothing per identity (it counts how many, not who or for whom).
// KEYS[2] = q:<rid>, the destination's list, only read. ARGV = the allowance,
// the window in seconds.
//
// A destination whose list exists is granted WITHOUT a charge (2): nothing is
// being created — the push puts the entry into a mailbox that is already
// there, under the per-mailbox caps that bound it — so charging it, then
// handing the slot back after the push said so, cost two round trips and held
// a slot that a genuine first contact could have been refused for meanwhile.
// The window is the STORE's clock (TIME), not the instance's: with the
// instance's, two instances whose clocks disagreed by more than a window
// counted into different keys and the allowance was N × again (measured: 20
// a window against 10 at a skew of three windows). A fresh window resets `n`
// as it is first touched, so nothing has to expire for the count to start
// over. Returns {1, w} for a slot taken in window w, {2, -1} for an exempt
// destination, {0, w} for a full window — and a full window changes nothing,
// so a flood's refused attempts do not inflate the count an honest first
// contact a moment later is measured against. NOT flagged allow-oom: a store
// at its memory limit refuses the script up front, the caller treats that as
// the store being full, and the push that follows is refused the same way.
const REDIS_NEWMAILBOX_LUA = `#!lua
if redis.call('EXISTS', KEYS[2]) == 1 then return {2, -1} end
local secs = tonumber(ARGV[2])
local t = redis.call('TIME')
local w = math.floor(tonumber(t[1]) / secs)
local n = 0
if tonumber(redis.call('HGET', KEYS[1], 'w') or '-1') == w then
  n = tonumber(redis.call('HGET', KEYS[1], 'n') or '0')
end
if n >= tonumber(ARGV[1]) then return {0, w} end
redis.call('HSET', KEYS[1], 'w', w, 'n', n + 1)
redis.call('EXPIRE', KEYS[1], secs * 2)
return {1, w}`;

// Give back a slot taken in window ARGV[1], when the push it was taken for did
// not create a mailbox after all — another instance created it first, or the
// envelope was refused. Only in the SAME window: a slot from a window that
// has since rolled over counted against a minute that is already over, and
// the new window's count must not be lowered for it. Never creates the hash
// (a refund after the window expired used to DECR a missing key into a
// counter with no TTL at all) and never resets its TTL (HSET keeps it).
// allow-oom because it only lowers a count — a refund must settle even when
// the store is full.
const REDIS_NEWMAILBOX_REFUND_LUA = `#!lua flags=allow-oom
if tonumber(redis.call('HGET', KEYS[1], 'w') or '-1') ~= tonumber(ARGV[1]) then return 0 end
local n = tonumber(redis.call('HGET', KEYS[1], 'n') or '0')
if n <= 0 then return 0 end
redis.call('HSET', KEYS[1], 'n', n - 1)
return 1`;

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

/**
 * What one envelope's payload is charged at: what it really occupies, plus 256
 * of object/framing overhead. Until phase 29 this was `payload.length` — UTF-16
 * code units — and a unit is not a byte in either store (relay P2):
 *
 *  - RAM: V8 keeps a string one byte a unit only while every character is
 *    ≤ U+00FF. One character above that makes the WHOLE string two bytes a
 *    unit, so a payload of ASCII plus a single 'ā' held twice what was charged
 *    — while its UTF-8 length stayed ≈ 1×, so charging UTF-8 bytes alone would
 *    not have closed it.
 *  - Redis: the store holds `JSON.stringify(entry)` as UTF-8, so a non-ASCII
 *    character is 2–3 bytes, and a quote, backslash or control character is
 *    escaped (`\"`, `\u0001`: up to six bytes for one unit).
 *
 * So the charge is the larger of the two. The honest traffic is base64 under a
 * `zs1.` prefix — printable ASCII with no quote or backslash — which is one
 * byte a unit everywhere, so a cheap test leaves its charge exactly what it
 * was (`length`); only a payload the protocol never produces pays more, and it
 * is precisely the one the caps must not under-count.
 */
const PLAIN_PAYLOAD = /^[\x20\x21\x23-\x5b\x5d-\x7e]*$/;
function envelopeSize(payload) {
  const s = String(payload || '');
  if (PLAIN_PAYLOAD.test(s)) return s.length + 256;
  const stored = Buffer.byteLength(JSON.stringify(s), 'utf8') - 2; // as the store holds it
  const heap = /[^\x00-\xff]/.test(s) ? 2 * s.length : s.length; // as V8 holds it
  return Math.max(stored, heap) + 256;
}

/** The size an entry is charged at, computed the same way in both coordinators. */
function entrySize(e) {
  if (typeof e.size === 'number') return e.size;
  return e.kind === 'receipt' ? 192 : envelopeSize(e.payload);
}

/** Thrown by a push the store refused for want of memory; answered `store_full`. */
class StoreFull extends Error {
  constructor() {
    super('the store is full');
  }
}

/**
 * Thrown by a push the mailbox-creation gate refused. Still a StoreFull, so the
 * sender is told `store_full` — the code PROTOCOL §12.4 says a client pauses
 * and retries on, which is right for a refusal that ends with the minute —
 * but kept apart so it is counted once, as
 * z_new_mailbox_refused_total, and never also as z_store_full_total. RAM mode
 * always counted it once; the Redis path counted it under both names, so a
 * flood of first contacts read as a full store.
 */
class NewMailboxRefused extends StoreFull {
  constructor() {
    super();
    this.message = 'too many mailboxes are being created';
  }
}

/**
 * Thrown by a push an unowned-mailbox limit refused (P0-4): the per-unowned
 * mailbox byte cap, the relay-wide unowned budget, or the per-IP unowned
 * rate. Still a StoreFull, so the sender is told `store_full` and retries,
 * but counted apart as z_unowned_refused_total — the store is not full, a
 * flood of first contacts to mailboxes nobody owns is being bounded.
 */
class UnownedRefused extends StoreFull {
  constructor() {
    super();
    this.message = 'the unowned-mailbox budget is full';
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
    // Per instance, like the rate limiter beside it — the gate by default, and
    // the fallback when the shared one is on and cannot be reached. N
    // instances admit N × NEW_MAILBOX_PER_MIN between them; the byte caps
    // (MAX_QUEUE_BYTES_PER_USER, the store's maxmemory) bound what a flood
    // can hold whatever N is, so the N× loosens the creation RATE and not the
    // store's worst case (LOAD.md, 25.3).
    this.newMailbox = new NewMailboxGate();
    // NEW_MAILBOX_SHARED=on makes the store's window the gate instead (see
    // REDIS_NEWMAILBOX_LUA): one relay-wide allowance per window of this
    // length, the same minute the per-instance rate is quoted over.
    this.newMailboxShared = CFG.newMailboxShared;
    this.newMailboxWindowMs = 60000;
    this.seen = new SeenMailboxes();
    // Per-IP unowned budget: RAM, per instance, like `newMailbox` beside it —
    // an address-keyed limit is local to the instance a socket landed on, and
    // the relay must not keep a per-address record in the shared store (P0-4).
    this.unownedIp = new IpByteBudget(CFG.unownedBytesPerIpPerMin);
    // The relay-wide unowned total as the last sweep reconciled it (a gauge).
    this.lastUnownedBytes = null;
    this.chan = `z:inst:${this.id}`;
    for (const c of [this.cmd, this.sub, this.pub]) c.on('error', () => {});
    this.cmd.defineCommand('zQueuePush', { numberOfKeys: 5, lua: REDIS_PUSH_LUA });
    this.cmd.defineCommand('zQueueRemove', { numberOfKeys: 3, lua: REDIS_REMOVE_LUA });
    this.cmd.defineCommand('zQueueRemoveLegacy', { numberOfKeys: 3, lua: REDIS_REMOVE_LEGACY_LUA });
    this.cmd.defineCommand('zQueueDropDangling', { numberOfKeys: 3, lua: REDIS_DROP_DANGLING_LUA });
    this.cmd.defineCommand('zQueueExpire', { numberOfKeys: 3, lua: REDIS_EXPIRE_LUA });
    this.cmd.defineCommand('zQueueAck', { numberOfKeys: 3, lua: REDIS_ACK_LUA });
    this.cmd.defineCommand('zQueueAckLegacy', { numberOfKeys: 3, lua: REDIS_ACK_LEGACY_LUA });
    this.cmd.defineCommand('zNewMailboxTake', { numberOfKeys: 2, lua: REDIS_NEWMAILBOX_LUA });
    this.cmd.defineCommand('zNewMailboxRefund', { numberOfKeys: 1, lua: REDIS_NEWMAILBOX_REFUND_LUA });
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
    // Authenticating proves the holder can drain this mailbox: record it as
    // OWNED (P0-4), so its queued bytes stop counting against the unowned
    // budget (the sweep reconciles that) and it gets the full per-user cap.
    // A store key keyed by the routing id the relay already knows — the same
    // shape as presence:/q:/push: — so it survives a relay restart and adds
    // no new identity information. Refreshed each auth with OWNED_TTL; a store
    // too full to take it just leaves the mailbox unowned a while longer,
    // which only tightens a cap, so the login is never blocked on it.
    try {
      await this.cmd.set(`owned:${rid}`, '1', 'PX', CFG.ownedTtlMs);
    } catch (e) {
      if (!isStoreFull(e)) throw e;
    }
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
   * Ask the store's relay-wide window (NEW_MAILBOX_SHARED=on) whether a push
   * to `rid` may create a mailbox. Resolves to `{ granted, window, fellBack }`:
   *
   *  - granted, `window` a number: a slot was taken in that window, to be
   *    given back with `_refundShared(window)` if the push does not create;
   *  - granted, `window` null: the destination's list already exists, so
   *    nothing is being created and nothing was charged;
   *  - not granted: the window's allowance is spent;
   *  - `fellBack`: the window could not be consulted and the caller decides on
   *    this instance's own bucket instead — fail to the per-instance rate,
   *    never open. Counted in z_new_mailbox_shared_fallback_total, except when
   *    the store is merely full: the push that follows is refused for the
   *    same want of memory, and z_store_full_total says so.
   */
  async _takeShared(rid) {
    try {
      const [code, window] = await this.cmd.zNewMailboxTake(
        'z:nm',
        `q:${rid}`,
        String(CFG.newMailboxPerMin),
        String(Math.max(1, Math.round(this.newMailboxWindowMs / 1000)))
      );
      if (code === 1) return { granted: true, window, fellBack: false };
      if (code === 2) return { granted: true, window: null, fellBack: false };
      return { granted: false, window: null, fellBack: false };
    } catch (e) {
      if (!isStoreFull(e)) METRICS.newMailboxSharedFallbackTotal += 1;
      return { granted: false, window: null, fellBack: true };
    }
  }

  /** Give back a slot taken in `window`; a no-op once that window has passed. */
  async _refundShared(window) {
    try {
      await this.cmd.zNewMailboxRefund('z:nm', String(window));
    } catch {
      // The window ends on its own; a slot that could not be handed back is
      // one creation the relay does not reuse before the minute rolls over.
    }
  }

  /**
   * Stores an entry; returns false when the recipient's queue is at a cap
   * (see MemoryCoordinator#_enqueue) and throws a StoreFull when the store
   * itself has no room — or a NewMailboxRefused, which is one, when the entry
   * would have created a mailbox and too many were being created at once.
   * Both reach the sender as `store_full`, which a client pauses and retries
   * on rather than treating as final. An attributed entry already held under
   * its key is not stored twice: the push is acknowledged as if it had been,
   * which is what a sender retrying after a lost `sent` needs. A sealed one
   * takes the next free slot instead (entryDedupes).
   */
  async _push(rid, entry, ip) {
    // Admission is charged on FIRST CONTACT only: a routing id this instance
    // has queued for recently (`seen`) creates a mailbox without spending
    // anything, so steady traffic never reaches either gate.
    //
    // Which gate: by default this instance's own bucket, exactly as it always
    // was. With NEW_MAILBOX_SHARED=on, the store's relay-wide window instead,
    // and the own bucket only when the window cannot be consulted.
    //
    // Either way the decision travels WITH the push as `fresh`: the script
    // creates a mailbox only when told it may, and puts the entry into one
    // that already exists whatever it is told, so no mailbox can appear
    // between the check and the write, and two instances cannot both squeeze
    // past the per-mailbox caps.
    const known = this.seen.has(rid);
    let fresh = known;
    let localSpent = false;
    let sharedWindow = null; // the window a shared slot was taken in, to refund
    if (!known) {
      let local = !this.newMailboxShared;
      if (!local) {
        const shared = await this._takeShared(rid);
        if (shared.fellBack) {
          local = true;
        } else {
          fresh = shared.granted;
          sharedWindow = shared.window;
        }
      }
      if (local) {
        fresh = this.newMailbox.take();
        localSpent = fresh;
      }
    }
    // The per-IP unowned allowance is a RAM check here and a flag to the
    // script, so the script decides atomically against the mailbox's
    // ownership (an owned mailbox ignores it) and nothing is stored for an IP
    // over its budget. Charged after the fact, by what actually landed.
    const ipOver = ip && this.unownedIp.over(ip) ? '1' : '0';
    let r;
    try {
      r = await this.cmd.zQueuePush(
        `q:${rid}`,
        `qe:${rid}`,
        `qb:${rid}`,
        `owned:${rid}`,
        'z:ub',
        entryKey(entry),
        JSON.stringify(entry),
        String(entrySize(entry)),
        String(CFG.maxQueueMsgsPerUser),
        String(CFG.maxQueueBytesPerUser),
        String(CFG.queueTtlHours * 3600),
        String(CFG.idSlots),
        entryDedupes(entry) ? '1' : '0',
        fresh ? '1' : '0',
        String(CFG.unownedMailboxBytes),
        String(CFG.unownedStoreBytes),
        ipOver
      );
    } catch (e) {
      if (localSpent) this.newMailbox.refund();
      if (sharedWindow !== null) await this._refundShared(sharedWindow);
      if (isStoreFull(e)) throw new StoreFull();
      throw e;
    }
    const code = Array.isArray(r) ? Number(r[0]) : Number(r);
    const unowned = Array.isArray(r) && Number(r[1]) === 1;
    if (code === -1) {
      // Told it may not create, and there was nothing to put the entry into.
      // `fresh` was false, so nothing was spent on the way here.
      METRICS.newMailboxRefusedTotal += 1;
      throw new NewMailboxRefused();
    }
    if (code === -2) {
      // An unowned-mailbox limit (per-mailbox cap, relay-wide budget, or this
      // IP's minute). Nothing was created, so give any token back.
      if (localSpent) this.newMailbox.refund();
      if (sharedWindow !== null) await this._refundShared(sharedWindow);
      METRICS.unownedRefusedTotal += 1;
      throw new UnownedRefused();
    }
    // 2 means this push created the mailbox and what was spent stays spent;
    // anything else created nothing — the mailbox already existed, or the
    // entry was refused — so the allowance goes back.
    if (code !== 2) {
      if (localSpent) this.newMailbox.refund();
      if (sharedWindow !== null) await this._refundShared(sharedWindow);
    }
    const accepted = code === 1 || code === 2;
    // Only a send that landed, for the reason in `SeenMailboxes.touch`.
    if (accepted) {
      this.seen.touch(rid);
      if (unowned && ip) this.unownedIp.charge(ip, entrySize(entry));
    }
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

  async deliverEnqueue(from, to, id, payload, ip) {
    const entry = { kind: 'msg', id, from, payload, ts: Date.now(), size: envelopeSize(payload) };
    let accepted;
    try {
      accepted = await this._push(to, entry, ip);
    } catch (e) {
      if (!(e instanceof StoreFull)) throw e;
      // A creation refusal was counted where it was decided; a store with no
      // room is a full store (counted here); an unowned-mailbox limit was
      // counted as z_unowned_refused_total. All three reach the sender as
      // store_full, which it retries (PROTOCOL §12.4).
      if (!(e instanceof NewMailboxRefused) && !(e instanceof UnownedRefused)) METRICS.storeFullTotal += 1;
      return { queued: false, storeFull: true, unowned: e instanceof UnownedRefused };
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
      // And `live` stays false: this instance cannot see whether the instance
      // named by `presence:` still held a socket, so the envelope is reported
      // held (it is, until acknowledged) and re-delivered by `reflushStalled`
      // if the live push went nowhere — the recovery that does not depend on
      // the recipient reconnecting.
      //
      // What it does NOT do any more is fire a wake push. `presence:` naming
      // any instance means the recipient is online SOMEWHERE, and waking an
      // online user's device by FCM on every message is exactly the metadata
      // leak push is meant to minimise (R12, DATA_MAP) — Google learns "this
      // device should wake" per message for a user who is already connected.
      // So the wake push is for a recipient no instance has online (`push`
      // below); the stale-presence case, where a push might have helped, is
      // covered by `reflushStalled` within one interval and then by the
      // recipient's own reconnect, at the cost of that delay rather than a
      // wake on every online user's message.
    }
    if (live) METRICS.deliveredLiveTotal += 1;
    // Wake only a recipient no instance has online: no presence record
    // anywhere and no socket here (P2 — HA cross-instance deliveries used to
    // wake online users through FCM).
    return { queued: !live, push: !owner && !here };
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
      if (!(e instanceof NewMailboxRefused)) METRICS.storeFullTotal += 1;
    }
  }

  /**
   * Removes entries at the head of a mailbox that have outlived
   * QUEUE_TTL_HOURS. Returns how many entries the call took off the head —
   * expired ones and keys whose body was gone alike, the latter counted in
   * z_body_missing_total as they are in the flush.
   */
  async _expire(rid, limit = 1000) {
    const [removed, dangling] = await this.cmd.zQueueExpire(`q:${rid}`, `qe:${rid}`, `qb:${rid}`, String(Date.now() - CFG.queueTtlMs), String(limit));
    METRICS.bodyMissingTotal += Number(dangling) || 0;
    return (Number(removed) || 0) + (Number(dangling) || 0);
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
        if (str == null) {
          // The body is not there. An acknowledgement that landed between
          // the LRANGE and the HMGET took the key out of the list already,
          // and the drop below is a no-op; a store that EVICTED the body
          // left the key listed, and until 2026-09-17 this `continue` was
          // all that happened — the envelope was gone, the key stayed to be
          // skipped at every login, the bytes were never settled, and no
          // number said so. Counted now, and the key dropped, once.
          METRICS.bodyMissingTotal += 1;
          if (!legacy) {
            try {
              await this.cmd.zQueueDropDangling(`q:${rid}`, `qe:${rid}`, `qb:${rid}`, x);
            } catch {
              // The next flush tries again; the count already stands.
            }
          }
          continue;
        }
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
    // Reconcile the relay-wide unowned-bytes counter while we are walking the
    // mailboxes anyway (P0-4): `z:ub` is incremented live by every unowned
    // push, but a per-key TTL expiry frees unowned bytes without passing
    // through any decrement, so the live counter can only drift UPWARD (refuse
    // first-contact too early — safe, not a store-fill hole). Summing the
    // qb of every mailbox that has no `owned:` marker and SETTING z:ub to it
    // each sweep bounds that drift to one interval and makes a leak
    // impossible, the way the accumulator recount does in RAM mode. A true
    // recount, so it also absorbs the claim-on-auth transition (the mailbox
    // is now owned and simply drops out of the sum) without a decrement path.
    // The SET can drop what was pushed during the walk to a mailbox already
    // counted: an under-count of at most one walk's worth of first-contact
    // traffic (itself held to the per-IP minute and NEW_MAILBOX_PER_MIN),
    // which the next sweep restores.
    let unownedSum = 0;
    let reconciled = true;
    try {
      let cursor = '0';
      do {
        const [next, keys] = await this.cmd.scan(cursor, 'MATCH', 'q:*', 'COUNT', '200');
        cursor = next;
        for (const key of keys) {
          const rid = key.slice(2);
          try {
            await this._expireAll(rid, 200);
          } catch {
            // A store that is unreachable for a moment: the next sweep tries again.
          }
          try {
            if ((await this.cmd.exists(`owned:${rid}`)) === 0) {
              unownedSum += Number(await this.cmd.get(`qb:${rid}`)) || 0;
            }
          } catch {
            // Could not read this mailbox's ownership/bytes this pass; do not
            // SET a total that is missing a mailbox (it would under-count and
            // loosen the budget). Skip the reconcile this sweep.
            reconciled = false;
          }
        }
      } while (cursor !== '0');
      if (reconciled) {
        // A TTL a few intervals long, so the counter clears itself if sweeps
        // ever stop, rather than pinning the budget shut for ever.
        await this.cmd.set('z:ub', String(unownedSum), 'PX', Math.max(60000, CFG.sweepIntervalMs * 5));
        // The store-fill gauge for the unowned budget (z_unowned_bytes):
        // relay-wide, as of this instance's last sweep, so every instance
        // reports the same figure — take the max across them, not the sum.
        this.lastUnownedBytes = unownedSum;
      }
    } catch {
      // The SCAN itself failed; leave z:ub as the live counter has it.
    } finally {
      this.sweeping = false;
    }
    this.unownedIp.prune();
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
    const out = { connections: this.local.size, queuedEnvelopes: -1, presenceStale: this.presenceStale.size };
    if (this.lastUnownedBytes != null) out.unownedBytes = this.lastUnownedBytes;
    return out;
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
      // Liveness only (P1-14). `/health` is unauthenticated — it is what a
      // platform health check hits — so it must say the process is up and
      // nothing a stranger could read as a signal. The counts, the socket
      // totals, the instance id, `presenceStale` and the store bytes all moved
      // to `/metrics`, which now needs a token: sending one envelope and
      // watching a delta there used to turn these two endpoints into a
      // presence oracle. `coordinator` and `push` stay — neither is a counter
      // or an identifier, and tooling reads them to tell a single-instance
      // relay from the HA one. `storage` stays because DATA_MAP points at it
      // as a checkable claim.
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          ok: true,
          coordinator: coord.name,
          storage: 'ram-only',
          push: pushSender ? 'enabled' : 'disabled',
        })
      );
      return;
    }
    if (req.url === '/metrics') {
      // Aggregate delivery SLIs only — no per-user data, no content, RAM only;
      // but even aggregates are a presence oracle (send one sealed envelope,
      // read the z_delivered_live_total delta), so this requires a bearer
      // token from METRICS_TOKEN, compared in constant time. Unset → 404, the
      // safe default: a relay with no token configured does not even admit the
      // endpoint exists (P1-14). The operator sets the secret and scrapes with
      // `Authorization: Bearer <token>`.
      if (!metricsAuthorized(req)) {
        if (!CFG.metricsToken) {
          res.writeHead(404, { 'content-type': 'text/plain' });
          res.end('not found\n');
          return;
        }
        res.writeHead(401, {
          'content-type': 'text/plain',
          'www-authenticate': 'Bearer realm="z-relay metrics"',
        });
        res.end('unauthorized\n');
        return;
      }
      res.writeHead(200, { 'content-type': 'text/plain; version=0.0.4' });
      res.end(
        renderMetrics(coord.stats(), {
          instanceId: CFG.instanceId,
          coordinator: coord.name,
          push: pushSender ? 'enabled' : 'disabled',
          uptimeSec: process.uptime(),
          sockets: wssRef ? wssRef.clients.size : undefined,
        })
      );
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
    // The latest published version (24.4), read at request time so setting
    // Z_LATEST_VERSION is a restart, not a redeploy, and its absence is a 404
    // rather than a claim. The client derives this URL from the relay it
    // already dials, so this answers a host the client is already talking to.
    if (req.url === '/latest.json') {
      const body = latestJson(process.env.Z_LATEST_VERSION);
      if (body) {
        res.writeHead(200, {
          'content-type': 'application/json; charset=utf-8',
          'cache-control': 'public, max-age=300',
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

  // Open sockets per client IP, for the per-IP connection cap (P1-13, review
  // finding #40). RAM, per instance — a connection cap is only about this
  // instance's sockets.
  const connsByIp = new Map();

  wss.on('connection', (ws, req) => {
    const ip = clientIp(req);
    // Connection caps (P1-13). The global one is always on: a bound on this
    // instance's sockets whatever their source, so a flood of idle
    // connections cannot exhaust file descriptors or the ~11 KB of RSS each
    // socket costs (CAPACITY.md). The per-IP one engages only when
    // CLIENT_IP_HEADER names a front that sets the real address — keyed on a
    // shared front address it would cap the whole relay's connections at one
    // number, so without the header the global cap is the backstop.
    if (wss.clients.size > CFG.maxConnections) {
      METRICS.connectionsRefusedTotal += 1;
      try {
        ws.close(1013, 'relay at capacity');
      } catch {}
      return;
    }
    const ipCount = (connsByIp.get(ip) || 0) + 1;
    if (CFG.clientIpHeader && CFG.maxConnectionsPerIp > 0 && ipCount > CFG.maxConnectionsPerIp) {
      METRICS.connectionsRefusedTotal += 1;
      try {
        ws.close(1013, 'too many connections from this address');
      } catch {}
      return;
    }
    connsByIp.set(ip, ipCount);

    const state = {
      authed: false,
      rid: null,
      ip,
      nonce: crypto.randomBytes(32),
      // What this connection dialled, as the Host header says. A v2 signature
      // is NOT verified against this (the presenter controls it) — it is kept
      // only so an unconfigured relay on a loopback/LAN name can trust the
      // dialled name, the one case with no machine-in-the-middle boundary,
      // and only when the TCP peer (`peer`, never a forwarded header) is
      // itself loopback or private.
      authority: normalizeAuthority(req && req.headers ? req.headers.host : ''),
      peer: (req && req.socket && req.socket.remoteAddress) || '',
      tokens: CFG.rateBurst,
      lastRefill: Date.now(),
      acksInFlight: 0,
    };
    ws.zAlive = true;
    // When this socket last sent a frame: the unauthenticated-idle timeout
    // (P1-13, ADR 0007) closes a socket that has neither authenticated nor
    // sent anything for UNAUTH_IDLE. An anonymous sealed-send socket is
    // legitimate and never authenticates, but it pings every 25 s, which lands
    // here as a frame — so this reclaims only a socket doing nothing at all,
    // not one sending sealed envelopes.
    ws.zLastFrame = Date.now();

    ws.on('error', () => {
      try {
        ws.terminate();
      } catch {}
    });
    ws.on('pong', () => (ws.zAlive = true));

    // `auth: 2` says this relay verifies the bound form, so a client can
    // fail with a reason against one that does not, rather than with
    // `bad_auth`; the security does not rest on it — a client signs v2
    // whatever the challenge says.
    sendJson(ws, { t: 'challenge', nonce: state.nonce.toString('base64'), auth: 2 });

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
      ws.zLastFrame = now; // activity, for the unauthenticated-idle timeout
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
          // A send the relay could not store or route — in Redis mode, the
          // store unreachable. Counted, because `/health` deliberately does not
          // touch the store and so cannot see it (z_send_internal_error_total).
          if (frame.t === 'send') METRICS.sendInternalErrorTotal += 1;
          sendJson(ws, { t: 'error', code: 'internal' });
        });
    });

    ws.on('close', () => {
      heavySockets.delete(ws);
      const n = (connsByIp.get(ip) || 1) - 1;
      if (n > 0) connsByIp.set(ip, n);
      else connsByIp.delete(ip);
      if (state.rid) coord.unregister(state.rid, ws).catch(() => {});
    });
  });

  const heartbeat = setInterval(() => {
    const now = Date.now();
    for (const ws of wss.clients) {
      // An unauthenticated socket that has sent nothing for UNAUTH_IDLE is
      // closed (P1-13). A legitimate anonymous sender pings every 25 s, which
      // refreshes zLastFrame, so this reclaims only a socket doing nothing at
      // all — it is not an auth deadline (ADR 0007).
      if (
        CFG.unauthIdleMs > 0 &&
        ws.readyState === ws.OPEN &&
        !ws.zAuthed &&
        now - (ws.zLastFrame || 0) > CFG.unauthIdleMs
      ) {
        METRICS.idleClosedTotal += 1;
        try {
          ws.close(4003, 'idle without authenticating');
        } catch {}
        continue;
      }
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
  }, CFG.heartbeatMs);
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
      let ok = false;
      if (frame.v === 2) {
        // Bound, and verified ONLY against the names this relay is configured
        // to answer to — never the Host header the presenter sent (P1-16). A
        // relay that verified against the presented Host would accept a
        // signature a victim was tricked into making for the presenter's own
        // name: dial evil.example, sign "evil.example" over the honest
        // relay's forwarded nonce, and the presenter replays it to the honest
        // relay with Host: evil.example. The honest relay's own name is not
        // evil.example, so against CFG.authorities it fails.
        let names = CFG.authorities;
        if (names.length === 0) {
          // Unconfigured: the relay was told no name. A loopback/LAN/.local
          // dialled name, on a connection that itself arrived from a loopback
          // or private address, has no machine-in-the-middle boundary to
          // protect (dev, LAN, the test suite), so the dialled name is
          // trusted; anything else is refused until the operator lists the
          // relay's names in RELAY_AUTHORITIES, rather than verify against a
          // name a presenter could choose.
          names = isLocalAuthority(state.authority, state.peer) ? [state.authority] : [];
        }
        for (const name of names) {
          if (verifyEd25519(pub, Buffer.concat([AUTH_CONTEXT_V2, Buffer.from(name, 'utf8'), state.nonce]), sig)) {
            ok = true;
            break;
          }
        }
        // Not ours under any configured name: a signature made for another
        // relay (the replay the binding stops), a front that rewrote Host
        // with no RELAY_AUTHORITIES set, or plain garbage — the relay cannot
        // tell which, and the count is the same signal.
        if (!ok) METRICS.authV2RefusedTotal += 1;
      } else if (CFG.authV1) {
        ok = verifyEd25519(pub, Buffer.concat([AUTH_CONTEXT, state.nonce]), sig);
        if (ok) METRICS.authV1Total += 1;
      }
      if (!ok) {
        sendJson(ws, { t: 'error', code: 'bad_auth' });
        ws.close(4001, 'bad auth');
        return;
      }
      state.authed = true;
      ws.zAuthed = true; // the heartbeat's idle check reads this off the socket
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
      const { refused, storeFull, push } = await coord.deliverEnqueue(
        anon ? null : state.rid,
        to,
        id,
        payload,
        state.ip
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
      // What the SENDER is told, which is not what the relay knows.
      //
      // `queued` is `!live`: whether the recipient has a socket open right
      // now. Anyone who has ever seen a contact code can send a 60-byte
      // envelope to that routing id and read `queued:false` as "that person
      // is online, now"; once a minute is a 24/7 activity timeline for
      // someone with no relationship to them at all. THREAT_MODEL grants
      // presence to the relay operator (R1); it does not grant it to the
      // internet. Until 2026-09-14 every sender was told; until 2026-09-17
      // only an anonymous one was not, on the premise that an authenticated
      // sender was asking about its own conversation — and an identity here
      // costs one generateKeyPair, so the premise held for nobody: anyone
      // could authenticate as a key of their own and ask about anyone (the
      // review's finding 12). Nor can the relay tell a relationship from a
      // stranger: a sealed envelope carries no sender, and an attributed one
      // from a stranger is acknowledged away by the recipient's client like
      // anything else, which would make the stranger a relationship.
      //
      // So every sender is told the envelope is held, always — which it is,
      // until it is acknowledged. It costs an honest sender nothing: the
      // Dart client never read the value, delivery is the peer's own receipt
      // inside the ratchet (§15.3), and the push decision below still uses
      // what actually happened, so a wake ping does not start firing for
      // recipients who are connected. The field stays in the frame for
      // older clients, at the one value that says nothing.
      sendJson(ws, { t: 'sent', id, queued: true });
      // Recipient online on NO instance and push configured? Fire a
      // content-free wake ping. `push` is the coordinator's judgement: in
      // Redis mode it is false when any instance holds the recipient's
      // presence, so an online user on another instance is not woken by FCM
      // on every message (P2) — the leak R12 bounds is for offline wakes.
      // Best-effort and non-blocking: never delays or fails the send.
      if (push && pushSender) {
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
  // Phase 29 settings an operator has to get right, said once at boot: the
  // relay's own names are public (clients dial them), the token is not.
  log(
    CFG.authorities.length
      ? `v2 authentication verified against: ${CFG.authorities.join(', ')}`
      : 'RELAY_AUTHORITIES unset: only a loopback/LAN name dialled from a loopback/LAN address ' +
          'can authenticate; set it to the name(s) clients dial'
  );
  if (!CFG.metricsToken) log('METRICS_TOKEN unset: /metrics answers 404');
  if (CFG.sendBufferCapBytes < 2 * CFG.flushHighWaterBytes + CFG.maxEnvelopeBytes) {
    log(
      `SEND_BUFFER_CAP_BYTES (${CFG.sendBufferCapBytes}) is below what a paged flush may hold ` +
        `(2 × FLUSH_HIGH_WATER_BYTES + MAX_ENVELOPE_BYTES): honest slow readers will be dropped`
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
  normalizeAuthority,
  isLocalAuthority,
  routingIdFromPub,
  MemoryCoordinator,
  RedisCoordinator,
  PushSender,
  _internal,
};
