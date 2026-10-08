#!/usr/bin/env node
'use strict';
/**
 * The key-transparency log's HTTP face. Plain node:http, no dependencies;
 * every response is JSON and every proof-bearing response carries the signed
 * tree head it is relative to. Read docs/PROTOCOL.md §19 for the meaning of
 * the fields and docs/adr/0006-key-transparency-log.md for why it is shaped
 * this way; lib/log.js for the bytes.
 *
 *   GET  /kt/v1/sth                          the current signed tree head
 *   GET  /kt/v1/consistency?first=&second=   PROOF(first, D[second]); second defaults to the head's size
 *   GET  /kt/v1/lookup/<label hex>           head + map proof + latest entry + inclusion proof
 *   GET  /kt/v1/history/<label hex>          head + a page of the label's entries, each with an inclusion
 *                                            proof, plus `total`; ?start=&count= page it
 *   GET  /kt/v1/entries?start=&count=        head + a page of entries (mirrors); count ≤ 1000
 *   POST /kt/v1/entries                      {indexes: [...]} → head + those entries, each with an
 *                                            inclusion proof, plus `total` (clients; ≤ 1000 indexes)
 *   GET  /kt/v1/bucket?prefix=&bits=         head + every label whose first `bits` bits are `prefix`,
 *                                            with the map siblings that prove none is missing (§19.9)
 *   POST /kt/v1/buckets                      {buckets: [{prefix, bits}…]} → up to 64 buckets, one head
 *   POST /kt/v1/publish                      {acct, v, fp, value, sig} → {index, sth} — see lib/log.js
 *                                            (the handle log: {label, v, value, sig} — lib/handles.js)
 *   GET  /kt/v1/pub                          the log's public key (for a first pin; clients ship it)
 *   GET  /health                             {state, size, labels, sthTs, rssBytes, memLimitBytes,
 *                                            diskBytes, diskFreeBytes, full}; while the log replays,
 *                                            503 {state: "replaying", replayed, rssBytes, memLimitBytes}
 *
 * Run it:
 *   KT_SEED=<64 hex>  KT_DATA=/var/lib/z-kt  KT_PORT=8443  node server.js
 *   KT_MIN_SIZE=<n> refuses to start if fewer than n entries replay — the
 *   floor for a data directory that did not mount, which the head file
 *   beside the entries cannot catch because it goes missing with them;
 *   KT_MAX_HEAD_AGE_MIN (default 30; 0 is off) refuses a start whose last
 *   recorded head is older than that — what a restored whole-disk snapshot
 *   looks like, head file and all — until KT_CONFIRM_HEAD=<size>@<ts> names
 *   that head, once somebody has checked nothing ever saw a larger one.
 *   KT_SEED_FILE=/etc/z-kt/seed (32 raw bytes or 64 hex) is the alternative
 *   to KT_SEED; PORT is honoured when KT_PORT is unset (a cloud host injects
 *   it); KT_EPHEMERAL=1 keeps entries in memory (development only —
 *   a restart forgets the log, which is exactly what a log must not do).
 *   KT_MODE=handles runs the HANDLE log instead (PROTOCOL §21.5): the same
 *   trees and routes, records that resolve a handle as values, the owner
 *   rule, and contexts of its own — a separate service with its own key and
 *   its own KT_DATA, never the key-transparency log's. Unset is the
 *   key-transparency log, exactly as it was; any other value refuses to
 *   start.
 *
 * Abuse: publishes pass five gates — a per-address rate (PUBLISH_PER_MIN,
 * default 30), a total rate (PUBLISH_PER_MIN_TOTAL, default 120, of which a
 * minute of first publishes is kept back for them), a per-account daily
 * ceiling (PUBLISH_PER_ACCT_PER_DAY, default 20), a first-publish rate for
 * accounts the log has never held (PUBLISH_NEW_ACCOUNTS_PER_MIN, default 10)
 * and one address's share of that (PUBLISH_NEW_ACCOUNTS_PER_ADDR_PER_MIN,
 * default a quarter of it). Every one is charged after
 * the signature verifies and only by a publish that is written: nothing
 * unsigned can spend them and nothing refused does, because a gate that a
 * request could spend is a gate that everybody shares behind an
 * unconfigured proxy, and one bucket for the internet that junk can empty
 * is a switch that stops publishing. What a request that publishes nothing
 * can cost is bounded instead: bodies at 400 KB, bodies being read at once
 * at KT_MAX_PUBLISH_IN_FLIGHT (default 256), and a request at the server's
 * timeout. The per-address gate is only per-CLIENT when KT_CLIENT_IP_HEADER
 * names a header something in front is known to set; behind an unconfigured
 * proxy every request shares one address, which is why the total gate
 * exists and why it is the one that stops a flood. A lookup is cheap — under a millisecond at a
 * hundred thousand labels — but the two paging routes were not, and saying
 * "reads are left to the reverse proxy" was the mistake: a value may be
 * 256 KiB, so `?count=1000` was ~333 MB in one string and
 * `/kt/v1/history/<label>` had no count at all, which made every label a
 * fixed URL that returns everything it has ever published, repeatable, and
 * `cache-control: no-store` means nothing in front absorbs the repeat. Both
 * are bounded in BYTES (MAX_PAGE_BYTES; MAX_HISTORY_PAGE_BYTES) as well as
 * by count, because the size of an entry is chosen by whoever published it,
 * and both report `total` so a reader can tell a page from the whole; the
 * mirrors' route is budgeted per minute besides (READ_BYTES_PER_MIN, per
 * address; READ_BYTES_PER_MIN_TOTAL), and the two answers that never change
 * — a page below the head, a consistency proof — say a cache may hold them.
 */

const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  KtLog,
  PublishError,
  MemoryStore,
  FileStore,
  privateKeyFromSeed,
  sthToJson,
  mapProofToJson,
  inclusionToJson,
  labelFor,
  bucketBits,
  bucketToJson,
  MAX_VALUE_BYTES,
  MAX_BUCKET_BITS,
  MAX_BUCKET_LEAVES,
  MAX_BUCKETS,
} = require('./lib/log.js');
const { parsePrefix } = require('./lib/smt.js');
const { modeFromEnv } = require('./lib/handles.js');

const MAX_BODY = 400 * 1024;
const MAX_PAGE = 1000;
/**
 * The body of a POST that READS — a list of buckets or of indexes. At most
 * 64 buckets or 1000 indexes, so a few kilobytes; this is room for them and
 * nothing else, and a body is never a reason to hold memory a publish has.
 */
const MAX_READ_BODY = 64 * 1024;
/**
 * The most a read route will put in one response.
 *
 * `count` alone never bounded these. A value may be 256 KiB, so 1 000 entries
 * is ~333 MB built as one `JSON.stringify` string, and `/kt/v1/history/<label>`
 * took no count at all — every version a label had ever published, at a fixed
 * URL, repeatable by anyone, behind `cache-control: no-store` so nothing in
 * front absorbs a repeat. That is the second half of a publish flood: the
 * flood does not only grow the log, it mints a permanent way to ask for all
 * of it at once.
 *
 * 4 MiB is far above any honest page — a device list is a few KB, so this is
 * hundreds of them — and far below what hurts.
 */
const MAX_PAGE_BYTES = 4 * 1024 * 1024;
/**
 * A page of one label's history is smaller, and the reason is who asks for
 * it. `/kt/v1/entries` is how a mirror pages a whole log through, and it is
 * budgeted (below); `/kt/v1/history/<label>` is what every client walks for
 * its OWN label on every check, and a route a client's check depends on is
 * never refused by a budget somebody else spent — behind a front that sets
 * no client-address header, "somebody else" is everybody. So what bounds
 * this route is the cost of one request: 256 KiB is the bound, at most a
 * few milliseconds to build, and an honest label never fills it — twenty
 * versions of a fifty-device list are 300 KB, two pages. A label that does
 * fill it is one whose owner published two hundred maximum-size versions,
 * and it pays a page at a time like everyone else.
 */
const MAX_HISTORY_PAGE_BYTES = 256 * 1024;

function json(res, status, body, extra = {}) {
  const text = JSON.stringify(body);
  const bytes = Buffer.byteLength(text);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': bytes,
    'cache-control': 'no-store',
    ...extra,
  });
  res.end(text);
  return bytes;
}

/**
 * A page of entries below the head, or a consistency proof between two
 * sizes, is the same answer for as long as the log exists — so a cache in
 * front can hold it. Sixty seconds, not for ever: the page carries the head
 * it was served under and its `total`, and a reader that has already asked
 * the log for its head is unaffected by an older one riding along (the
 * mirror hashes the entries and compares roots; the app takes only the
 * proof from a consistency answer). An EMPTY page is not marked: it is what
 * a request past the head gets, and a cache holding one for a minute would
 * hand it to the next mirror that asks from there. Everything else stays
 * `no-store` — a lookup and a history are relative to the head they were
 * served under, and the head moves.
 *
 * The header is the log's half. A CDN in front caches a JSON route only
 * when told to (Cloudflare: a cache rule for the two paths, honouring the
 * origin's TTL); SELF_HOSTING.md says so.
 */
const CACHEABLE = { 'cache-control': 'public, max-age=60' };

function fail(res, status, code, message) {
  json(res, status, { error: code, message });
}

/**
 * What the process holds and what it may, for `/health`.
 *
 * The log's memory is a function of its entries and nothing else — every
 * one of them is in both trees for the life of the process — so it grows
 * for as long as the log does, and the replay that rebuilds the trees runs
 * before anything listens. A log that outgrows its instance does not slow
 * down; it is killed during the replay, on every start, and until 2026-10-04
 * the first anyone heard of it was the crash-loop (`docs/CAPACITY.md` (b)).
 * `rssBytes` beside `size` is the per-entry figure; `memLimitBytes` is the
 * container's limit where there is one (cgroup), the machine's memory where
 * there is not, so `rssBytes / memLimitBytes` can be alarmed on as it is.
 */
function memory() {
  const total = os.totalmem();
  const limit = typeof process.constrainedMemory === 'function' ? process.constrainedMemory() : 0;
  return { rssBytes: process.memoryUsage.rss(), memLimitBytes: limit > 0 && limit < total ? limit : total };
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) {
        reject(new PublishError(413, 'too_large', `body exceeds ${limit} bytes`));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function parseLabel(hex) {
  if (typeof hex !== 'string' || !/^[0-9a-fA-F]{64}$/.test(hex)) return null;
  return Buffer.from(hex, 'hex');
}

function intParam(v, fallback) {
  if (v === null || v === undefined || v === '') return fallback;
  if (!/^\d{1,15}$/.test(v)) return NaN;
  return Number(v);
}

/**
 * One bucket a reader asked for — `{prefix, bits}` with `prefix` the hex the
 * protocol writes — as {prefix: Buffer, bits}, or null when it is not one:
 * bits 0..24, and the prefix exactly ⌈bits/4⌉ hex digits with its unused low
 * bits zero (`parsePrefix`), so that a bucket has one spelling.
 */
function bucketQuery(prefix, bits) {
  if (!Number.isInteger(bits) || bits < 0 || bits > MAX_BUCKET_BITS) return null;
  const p = parsePrefix(prefix === null || prefix === undefined ? '' : prefix, bits);
  return p ? { prefix: p, bits } : null;
}

const BUCKET_QUERY_RULE = `bits is 0..${MAX_BUCKET_BITS} and prefix is the first bits of a label as ⌈bits/4⌉ hex digits, the unused low bits zero`;

/**
 * A token bucket per key, refilled at `perWindow` tokens every `windowMs`,
 * holding at most that many.
 *
 * `cap` bounds how many keys are tracked at once. A limiter keyed on
 * something an attacker can mint — an account key, and there is no shortage
 * of those — is a map an attacker can grow, and a limiter that costs more
 * memory the harder it is pushed is not a limit. Past the cap the oldest
 * bucket is dropped, which is the right direction: the keys being dropped are
 * the ones that have not been seen recently, and a dropped key gets a fresh
 * full bucket, which is what it would have had anyway.
 */
class RateLimiter {
  constructor(perWindow, { windowMs = 60000, cap = 100000, now = Date.now } = {}) {
    this.perWindow = perWindow;
    this.windowMs = windowMs;
    this.cap = cap;
    this.now = now;
    this.buckets = new Map();
  }
  /** Gives a token back: the thing it was taken for did not happen. */
  refund(key) {
    const b = this.buckets.get(key);
    if (b) b.tokens = Math.min(this.perWindow, b.tokens + 1);
  }
  take(key) {
    return this.takeN(key, 1);
  }
  /**
   * Take one token only while more than [reserve] would be left: the part of
   * a shared bucket kept back for what must not be starved by everything
   * else. Spends nothing when it refuses, like `take`.
   */
  takeAbove(key, reserve) {
    return this.takeN(key, 1, reserve);
  }
  /** Whether a take would succeed now. Spends nothing. */
  open(key) {
    return this.takeN(key, 0);
  }
  /**
   * How long until the bucket is open again, in milliseconds; 0 when it is.
   * What a 429 puts in `retry-after`, so a well-behaved reader waits exactly
   * as long as it must and no longer.
   */
  waitMs(key, reserve = 0) {
    if (!(this.perWindow > 0)) return this.windowMs; // a limit of nothing: a window, not for ever
    const b = this.buckets.get(key);
    if (!b) return 0;
    const tokens = Math.min(this.perWindow, b.tokens + ((this.now() - b.at) / this.windowMs) * this.perWindow);
    if (tokens >= 1 + reserve) return 0;
    return Math.ceil(((1 + reserve - tokens) / this.perWindow) * this.windowMs);
  }
  /**
   * Spend [n] tokens: allowed while the bucket holds at least one, and the
   * bucket may go negative by what the request actually cost. That is the
   * right shape for a BYTE budget, where the size is only known once the
   * response is built: the request that crosses zero is served, and the
   * bucket stays shut until the window has refilled the debt.
   */
  takeN(key, n, reserve = 0) {
    const t = this.now();
    let b = this.buckets.get(key);
    if (!b) {
      if (this.buckets.size >= this.cap) {
        // Map iteration is insertion-ordered, and `take` re-inserts, so the
        // first key is the least recently created or refreshed.
        this.buckets.delete(this.buckets.keys().next().value);
      }
      b = { tokens: this.perWindow, at: t };
    } else {
      this.buckets.delete(key); // re-insert, so the order stays recency
    }
    this.buckets.set(key, b);
    b.tokens = Math.min(this.perWindow, b.tokens + ((t - b.at) / this.windowMs) * this.perWindow);
    b.at = t;
    if (b.tokens < 1 + reserve) return false;
    b.tokens -= n;
    return true;
  }
  /** Forget idle keys so the map does not grow with every visitor ever. */
  sweep() {
    const t = this.now();
    const idle = Math.max(2 * this.windowMs, 120000);
    for (const [k, b] of this.buckets) if (t - b.at > idle) this.buckets.delete(k);
  }
}

/**
 * The address to hold responsible for a request.
 *
 * `req.socket.remoteAddress` is the reverse proxy when there is one, which
 * behind Cloudflare → Render is every request: the per-address limiter was
 * keyed on a value that is the same for the entire internet, so it bound
 * nothing. Measured on the day the log went live: 3,853 entries from 3,579
 * distinct account keys in about a hundred minutes, against a nominal 30 a
 * minute.
 *
 * A forwarded header is only worth reading when something in front is known
 * to set it — otherwise the client sets it, and the limiter is keyed on a
 * value the attacker chooses, which is worse than one they cannot change.
 * So it is read only when `KT_CLIENT_IP_HEADER` names it.
 */
function clientKey(req, header) {
  if (header) {
    const v = req.headers[header];
    const first = (Array.isArray(v) ? v[0] : v || '').split(',')[0].trim();
    // A plausible address and nothing else: this value becomes a map key.
    if (first && first.length <= 45 && /^[0-9a-fA-F:.]+$/.test(first)) return clientOf(first);
  }
  return clientOf(req.socket.remoteAddress || 'unknown');
}

/**
 * What one client is, given its address: the address itself for IPv4, and
 * for IPv6 the /64 it sits in. A host is handed a /64 and picks addresses
 * inside it at will, so a limit keyed on the whole IPv6 address is one a
 * single machine can step around by changing its last 64 bits — and a
 * per-address gate it can step around is no gate. IPv4 mapped into IPv6
 * (`::ffff:a.b.c.d`, how a dual-stack socket reports an IPv4 peer) is its
 * IPv4 address. Anything that does not parse is returned as it came: it is
 * still a bounded key, and still one key.
 */
function clientOf(addr) {
  if (!addr.includes(':')) return addr;
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(addr);
  if (mapped) return mapped[1];
  const halves = addr.split('::');
  if (halves.length > 2) return addr;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  // An IPv4 tail (`64:ff9b::1.2.3.4`) is two groups.
  const width = (gs) => gs.reduce((n, g) => n + (g.includes('.') ? 2 : 1), 0);
  const missing = 8 - width(head) - width(tail);
  if (halves.length === 1 ? missing !== 0 : missing < 1) return addr;
  const groups = [...head, ...new Array(halves.length === 2 ? missing : 0).fill('0'), ...tail].slice(0, 4);
  if (!groups.every((g) => /^[0-9a-fA-F]{1,4}$/.test(g))) return addr;
  return `${groups.map((g) => parseInt(g, 16).toString(16)).join(':')}::/64`;
}

/**
 * Build the HTTP server around a log. Returns { httpServer, log }; the caller
 * listens. `publishPerMinute` is per source address.
 */
function createServer({
  log,
  publishPerMinute = 30,
  publishPerMinuteTotal = 120,
  publishPerAccountPerDay = 20,
  newAccountsPerMinute = 10,
  newAccountsPerAddressPerMinute = Math.max(1, Math.ceil(newAccountsPerMinute / 4)),
  maxValueBytes = 32 * 1024,
  minFreeBytes = 64 * 1024 * 1024,
  readBytesPerMinute = 32 * 1024 * 1024,
  readBytesPerMinuteTotal = 128 * 1024 * 1024,
  maxPublishInFlight = 256,
  requestTimeoutMs = 60_000,
  clientIpHeader = null,
  now = Date.now,
  statfs = fs.statfsSync,
}) {
  // The disk is the bound nobody multiplied through. A publish is up to
  // 341 KB on disk at the protocol's 256 KiB value cap, so the blueprint's
  // 1 GB held 3,069 of them — and with `publishPerMinute` one bucket for the
  // whole internet (no client-address header) and account keys free to mint,
  // that was 102 minutes to ENOSPC for anyone, after which every publish got
  // a 500 until an operator grew the disk that `/health` gave them no reason
  // to look at. Three things, each measured rather than guessed:
  //
  //   maxValueBytes  — what THIS log accepts, below the protocol's maximum.
  //                    A signed device list is ~1.1 KB sealed for three
  //                    devices and ~15 KB for fifty (docs/vectors/v3), so
  //                    32 KiB is a hundred devices and eight times the
  //                    entries per gigabyte. The protocol's 256 KiB is what a
  //                    READER must be able to open; a log may accept less and
  //                    says so with 413.
  //   newAccounts    — the R22 shape. What a flood needs is accounts, because
  //                    the per-account budget makes one account useless; a
  //                    first publish for a label the log has never seen is
  //                    the expensive event, and `log.hasLabel` answers it
  //                    exactly, from the index every lookup uses. An account
  //                    that has published before is never charged here.
  //   minFreeBytes   — the floor. Below it, publishes are refused 503
  //                    `log_full` and reads carry on, instead of the next
  //                    append meeting ENOSPC mid-line. `/health` publishes
  //                    the numbers so the operator sees the floor coming.
  if (!(maxValueBytes > 0 && maxValueBytes <= MAX_VALUE_BYTES)) {
    throw new Error(`maxValueBytes must be 1..${MAX_VALUE_BYTES}`);
  }
  // Three gates, because they stop three different things and the first one
  // was doing none of them.
  //
  //   client  — per source address, the one that existed. It is only a
  //             per-CLIENT limit when something in front sets a header we
  //             trust (`clientIpHeader`); behind an unconfigured proxy it is
  //             one bucket for the internet, which is what it was.
  //   total   — every publish, whatever the source. This is what actually
  //             stops a flood, and the reason is worth stating: the flood on
  //             the live log came from 3,579 distinct account keys, so a
  //             per-account limit would have let every one of them through.
  //             Keys are free; a log's disk is not.
  //   account — per account key, over a day. Not a flood control at all: it
  //             stops one account making the log its own, and it is charged
  //             only after the signature verifies, so nobody can spend an
  //             account's budget but that account.
  const limiter = new RateLimiter(publishPerMinute, { now });
  const total = new RateLimiter(publishPerMinuteTotal, { now });
  const perAccount = new RateLimiter(publishPerAccountPerDay, {
    windowMs: 24 * 60 * 60 * 1000,
    now,
  });
  const newAccounts = new RateLimiter(newAccountsPerMinute, { now });
  // First publishes again, and the two ways they were starved (the
  // 2026-10-03 analysis; `publish_limits.test.js` 10). The new-account gate
  // is one bucket for the internet, and even with `clientIpHeader` set, one
  // client's address gate (30) was three times its size (10): one client
  // could take every first publish there was, and a genuine new account
  // waited for as long as it kept asking. So one address gets a share of it
  // — a quarter, by default, so it takes four to empty it. And the total was
  // spent first-come by every publish: a few addresses republishing their
  // own accounts' lists could hold it at zero (four at the defaults, 4 × 30
  // being the total's 120), which starves first publishes by another road.
  // So the total keeps a
  // reserve that only first publishes may spend — a minute's worth of them,
  // never more than half the bucket — and still counts every publish, so it
  // bounds the disk exactly as it did. Neither is about the ORDER the gates
  // are charged in: every gate is given back when a later one refuses, so
  // which publishes get in never depended on it, only which refusal is
  // named. Behind a proxy with no `clientIpHeader`, every request is one
  // address, so this share is the whole log's first-publish rate.
  const newPerAddress = new RateLimiter(newAccountsPerAddressPerMinute, { now });
  const firstPublishReserve = Math.min(newAccountsPerMinute, Math.floor(publishPerMinuteTotal / 2));
  // Reads of `/kt/v1/entries`, in bytes: per address and in total. A page is
  // bounded at MAX_PAGE_BYTES and nothing bounded how often one could be
  // asked for: a 46-byte request returned 3.9 MiB — measured, 89,000:1 —
  // blocked the event loop for 43 ms building it, and four clients asking
  // together took an ordinary lookup from 0.7 ms to 172 ms. The budget is
  // charged by what a response actually weighed, and a reader over it is
  // told 429 with `retry-after` before anything is built; the mirror waits
  // that long and asks again, so a first sync of a large log paces itself
  // at the budget rather than failing.
  //
  // Only that route. The ones a client's check depends on — the head, a
  // consistency proof, a lookup, its own label's history — are bounded by
  // what one request can cost (a head; a proof; one entry with its proofs;
  // MAX_HISTORY_PAGE_BYTES) and are never refused by a budget, because
  // behind a front that sets no client-address header every reader is one
  // address, and a budget shared with an attacker is a switch the attacker
  // holds: eight page requests a minute would have refused every client's
  // check for the rest of it, which is a cheaper denial than the one being
  // fixed. Mirrors share that switch and retry; clients do not. `/health`,
  // `/sth` and `/pub` are not charged either: an uptime monitor and a client
  // checking the head are not what this is for.
  const reads = new RateLimiter(readBytesPerMinute, { now });
  const readsTotal = new RateLimiter(readBytesPerMinuteTotal, { now });
  // Publish bodies being read right now. Bounded, because a body is up to
  // MAX_BODY in memory while it arrives and a client decides how slowly it
  // arrives: at the default, 256 × 400 KB is the most a thousand open
  // trickling POSTs can hold. Not a rate — a request that finishes frees it
  // in milliseconds — so junk cannot spend it; only sockets held open can,
  // and the request timeout below lets go of those.
  let inFlight = 0;
  // The read routes' bodies (`POST /kt/v1/buckets`, `POST /kt/v1/entries`)
  // are counted apart from the publishes', under the same bound: a few
  // kilobytes each, but a client still decides how slowly one arrives, and
  // sharing the publishes' count would let held read bodies refuse
  // publishing with `busy` — or the reverse.
  let readsInFlight = 0;
  const handleMode = log.mode === 'handles';
  /**
   * The head as `/kt/v1/sth` serves it: the signed head, and `bucketBits`,
   * the bucket size this log recommends for its number of labels (§19.9).
   * Not signed and not a promise — a reader that asks for other buckets is
   * answered the same way — and the same JSON in a bucket answer.
   */
  const headJson = (sth) => ({ ...sthToJson(sth), bucketBits: bucketBits(log.map.size) });
  // A bucket answer is bounded by its leaves in both logs, and in the handle
  // log — where a leaf is a record, a signature and an audit path — by its
  // size as well, at the bound a label's history is held to: these are
  // routes a client's check depends on, so what bounds them is the cost of
  // one answer, never a budget somebody else can spend (`reads` below).
  const bucketLimits = { maxLeaves: MAX_BUCKET_LEAVES, maxBytes: handleMode ? MAX_HISTORY_PAGE_BYTES : Infinity };
  /** A read route's body, under its own in-flight bound; null when `busy` was answered. */
  const readBodyOf = async (req, res) => {
    if (readsInFlight >= maxPublishInFlight) {
      res.setHeader('retry-after', '1');
      fail(res, 503, 'busy', `${maxPublishInFlight} requests are already being read`);
      return null;
    }
    readsInFlight += 1;
    try {
      const body = await readBody(req, MAX_READ_BODY);
      let j;
      try {
        j = JSON.parse(body.toString('utf8'));
      } catch {
        throw new PublishError(400, 'bad_request', 'body is not JSON');
      }
      if (!j || typeof j !== 'object' || Array.isArray(j)) throw new PublishError(400, 'bad_request', 'body is not an object');
      return j;
    } finally {
      readsInFlight -= 1;
    }
  };
  const sweeper = setInterval(() => {
    limiter.sweep();
    total.sweep();
    perAccount.sweep();
    newAccounts.sweep();
    newPerAddress.sweep();
    reads.sweep();
    readsTotal.sweep();
  }, 60000);

  /** Disk state for the floor and for /health; null where there is no disk. */
  function disk() {
    const dir = log.store.dir();
    if (dir === null) return null;
    let free = null;
    try {
      const st = statfs(dir);
      free = Number(st.bavail) * Number(st.bsize);
    } catch {
      // A filesystem that cannot be asked is reported, not guessed at.
    }
    // `full` is null, not false, when free space could not be read: the
    // gate treats unknown as open, and /health shows the instrument is
    // broken rather than a reading it never took.
    return { bytes: log.store.bytesOnDisk(), free, full: free === null ? null : free < minFreeBytes };
  }
  sweeper.unref();

  // How long a request may take to arrive, whole. A publish body is at most
  // 400 KB, so a minute is generous on any link that can reach the log at
  // all; what it bounds is a socket held open with a body that never ends,
  // which is the one thing that can occupy `maxPublishInFlight`. Node
  // enforces it on a timer, so the interval is set with it: a held socket
  // is let go of within the timeout plus one interval.
  const httpServer = http.createServer(
    {
      headersTimeout: Math.min(30_000, requestTimeoutMs),
      requestTimeout: requestTimeoutMs,
      connectionsCheckingInterval: Math.max(100, Math.min(30_000, requestTimeoutMs)),
    },
    async (req, res) => {
    // Until 2026-10-04 this parse sat outside every try: an absolute-form
    // request target that URL cannot parse (`GET http://[ HTTP/1.1`) threw
    // out of this async handler as an unhandled rejection, which ends a
    // Node 22 process — one request, from anyone, and the log was down for a
    // restart and a full replay (`server.test.js`, the request target).
    let url;
    try {
      url = new URL(req.url, 'http://localhost');
    } catch {
      return fail(res, 400, 'bad_request', 'the request target is not a URL');
    }
    const p = url.pathname;
    try {
      if (req.method === 'GET') {
        res.setHeader('access-control-allow-origin', '*');
        if (p === '/health') {
          const sth = log.sth();
          const d = disk();
          // Still 200 when full: the host's health check would otherwise
          // restart a log whose only problem is a disk it cannot grow, and
          // the restart changes nothing. The alarm is on the numbers.
          return json(res, 200, {
            state: 'serving',
            ...(handleMode ? { mode: 'handles' } : {}),
            size: log.size,
            labels: log.map.size,
            sthTs: sth.ts,
            ...memory(),
            ...(d ? { diskBytes: d.bytes, diskFreeBytes: d.free, full: d.full } : {}),
          });
        }
        if (p === '/kt/v1/sth') return json(res, 200, headJson(log.sth()));
        if (p === '/kt/v1/bucket') {
          const q = bucketQuery(url.searchParams.get('prefix'), intParam(url.searchParams.get('bits'), NaN));
          if (!q) return fail(res, 400, 'bad_request', BUCKET_QUERY_RULE);
          const r = log.buckets([q], bucketLimits);
          return json(res, 200, { sth: headJson(r.sth), ...bucketToJson(r.buckets[0]) });
        }
        if (p === '/kt/v1/pub') return json(res, 200, { pub: log.publicKey.toString('base64') });
        if (p === '/kt/v1/consistency') {
          const sth = log.sth();
          const first = intParam(url.searchParams.get('first'), NaN);
          const second = intParam(url.searchParams.get('second'), sth.size);
          if (Number.isNaN(first) || Number.isNaN(second)) return fail(res, 400, 'bad_request', 'first and second are non-negative integers');
          if (second > sth.size) return fail(res, 400, 'bad_request', `second exceeds the head's size ${sth.size}`);
          const proof = log.consistency(first, second);
          return json(res, 200, { sth: sthToJson(sth), first, second, proof: proof.map((h) => h.toString('base64')) }, CACHEABLE);
        }
        if (p.startsWith('/kt/v1/lookup/')) {
          const label = parseLabel(p.slice('/kt/v1/lookup/'.length));
          if (!label) return fail(res, 400, 'bad_request', 'a label is 64 hex characters');
          const r = log.lookup(label);
          return json(res, 200, {
            sth: sthToJson(r.sth),
            map: mapProofToJson(r.map),
            entry: r.entry ? log.entryJson(r.entry) : null,
            inclusion: r.inclusion ? inclusionToJson(r.inclusion) : null,
          });
        }
        if (p.startsWith('/kt/v1/history/')) {
          const label = parseLabel(p.slice('/kt/v1/history/'.length));
          if (!label) return fail(res, 400, 'bad_request', 'a label is 64 hex characters');
          const start = intParam(url.searchParams.get('start'), 0);
          const count = intParam(url.searchParams.get('count'), MAX_PAGE);
          if (Number.isNaN(start) || Number.isNaN(count) || count < 1) return fail(res, 400, 'bad_request', 'start >= 0 and count >= 1');
          const r = log.history(label, { start, count: Math.min(count, MAX_PAGE), maxBytes: MAX_HISTORY_PAGE_BYTES });
          return json(res, 200, {
            sth: sthToJson(r.sth),
            start: r.start,
            total: r.total,
            entries: r.entries.map((x) => ({ entry: log.entryJson(x.entry), inclusion: inclusionToJson(x.inclusion) })),
          });
        }
        if (p === '/kt/v1/entries') {
          const start = intParam(url.searchParams.get('start'), 0);
          const count = intParam(url.searchParams.get('count'), 100);
          if (Number.isNaN(start) || Number.isNaN(count) || count < 1) return fail(res, 400, 'bad_request', 'start >= 0 and count >= 1');
          // The budget, checked before anything is built and charged after
          // by what was actually sent. Both buckets must be open; a 429
          // says how long until the fuller one is.
          const readKey = clientKey(req, clientIpHeader);
          if (!reads.open(readKey) || !readsTotal.open('all')) {
            const wait = Math.max(reads.waitMs(readKey), readsTotal.waitMs('all'));
            res.setHeader('retry-after', String(Math.max(1, Math.ceil(wait / 1000))));
            return fail(res, 429, 'rate_limited', `at most ${readBytesPerMinute} bytes of entries a minute from one address and ${readBytesPerMinuteTotal} in total`);
          }
          const r = log.range(start, Math.min(count, MAX_PAGE), { maxBytes: MAX_PAGE_BYTES });
          const bytes = json(
            res,
            200,
            { sth: sthToJson(r.sth), start, total: r.total, entries: r.entries.map((e) => log.entryJson(e)) },
            r.entries.length > 0 ? CACHEABLE : {}
          );
          reads.takeN(readKey, bytes);
          readsTotal.takeN('all', bytes);
          return undefined;
        }
        return fail(res, 404, 'not_found', 'no such route');
      }
      if (req.method === 'POST' && p === '/kt/v1/publish') {
        // The floor first, before any token is spent on a publish that could
        // not be written: a log that is out of room says so at once, keeps
        // answering reads, and never meets ENOSPC halfway through a line.
        const d = disk();
        if (d && d.full) {
          return fail(res, 503, 'log_full', `the log's disk has less than ${minFreeBytes} bytes free; publishing is paused until it is grown`);
        }
        // No gate before the body. There used to be two, and the reason
        // there are none is the reason finding 17 existed: a gate charged
        // before the signature is a gate junk can spend, and behind a front
        // that sets no client-address header the address gate was one
        // bucket for everybody — thirty one-byte POSTs a minute from
        // anywhere, no account, no signature, emptied it for every genuine
        // publisher (measured: 30 junk requests, all 400, then a correctly
        // signed publish refused 429, log size 0, at half a request a
        // second). Moving only that gate would have left the total gate,
        // which everybody shares by construction, as the same switch at two
        // requests a second. So every gate counts PUBLISHES, none counts
        // requests, and what a request that publishes nothing can cost is
        // bounded another way: MAX_BODY bounds the read, `maxPublishInFlight`
        // bounds how many bodies are being read at once (memory, against a
        // client that opens a thousand and trickles), and the server's
        // request timeout bounds how long one can be held open. A raw flood
        // of junk past those is what the front is for, as it is for every
        // HTTP service; what it cannot do any more is stop publishing.
        if (inFlight >= maxPublishInFlight) {
          res.setHeader('retry-after', '1');
          return fail(res, 503, 'busy', `${maxPublishInFlight} publishes are already being read`);
        }
        inFlight += 1;
        let body;
        try {
          body = await readBody(req, MAX_BODY);
        } finally {
          inFlight -= 1;
        }
        let j;
        try {
          j = JSON.parse(body.toString('utf8'));
        } catch {
          return fail(res, 400, 'bad_request', 'body is not JSON');
        }
        if (!j || typeof j !== 'object') return fail(res, 400, 'bad_request', 'body is not an object');
        // Node's base64 decoder reads the URL-safe alphabet too, so the
        // handle log's `label` (b64url, §21.5) and every other field decode
        // the same way; the lengths are the log's to check.
        const field = (name) => (typeof j[name] === 'string' ? Buffer.from(j[name], 'base64') : null);
        const req_ = handleMode
          ? { label: field('label'), version: j.v, value: field('value'), sig: field('sig') }
          : {
              acct: field('acct'),
              version: j.v,
              fp: field('fp'),
              value: field('value'),
              sig: field('sig'),
            };
        // Checked BEFORE any gate is charged: an unsigned request naming
        // somebody else's account must not be able to spend their budget,
        // and the only thing that tells the two apart is the signature.
        // `publish` checks again — it is responsible for its own input and
        // one more Ed25519 verify is microseconds.
        log.checkPublish(req_);
        // This log's own cap, under the protocol's. Checked after the
        // signature like the gates, so what it refuses is a real account's
        // oversized list and not a stranger's guess at one.
        if (req_.value.length > maxValueBytes) {
          return fail(res, 413, 'too_large', `this log accepts values of at most ${maxValueBytes} bytes`);
        }
        // The gates. Each is charged only if the publish happens: a refusal
        // by a later gate, or a write that fails, gives back everything
        // taken before it — so what a bucket counts is publishes, exactly,
        // and a signature that costs nothing to make buys nothing it did not
        // write. The order only decides which refusal is named.
        const taken = [];
        /** Take from [lim] (above [reserve]), or answer 429 and give back what was taken. */
        const gate = (lim, k, message, reserve = 0) => {
          if (lim.takeAbove(k, reserve)) {
            taken.push([lim, k]);
            return true;
          }
          for (const [l, kk] of taken) l.refund(kk);
          res.setHeader('retry-after', String(Math.max(1, Math.ceil(lim.waitMs(k, reserve) / 1000))));
          fail(res, 429, 'rate_limited', message);
          return false;
        };
        const key = clientKey(req, clientIpHeader);
        // In the handle log the gates count handles where they count
        // accounts here: one handle's publishes a day, and first publishes —
        // claims — a minute, which is what bounds how fast a squatter can
        // take names (rate, not total: ADR 0015's arithmetic).
        const acctKey = handleMode ? req_.label.toString('base64') : req_.acct.toString('base64');
        const who = handleMode ? 'handle' : 'account';
        // First contact costs a token; an account the log already holds
        // costs nothing there. `hasLabel` reads the index accepted publishes
        // build, so a refused publish cannot make an account look known.
        const fresh = !log.hasLabel(handleMode ? req_.label : labelFor(req_.acct));
        if (!gate(limiter, key, `at most ${publishPerMinute} publishes a minute from one address`)) return undefined;
        if (!gate(perAccount, acctKey, `at most ${publishPerAccountPerDay} publishes a day for one ${who}`)) return undefined;
        if (fresh) {
          if (!gate(newPerAddress, key, `at most ${newAccountsPerAddressPerMinute} new ${who}s a minute from one address`)) return undefined;
          if (!gate(newAccounts, 'all', `at most ${newAccountsPerMinute} new ${who}s a minute`)) return undefined;
        }
        if (!gate(total, 'all', `at most ${publishPerMinuteTotal} publishes a minute in total`, fresh ? 0 : firstPublishReserve)) return undefined;
        let entry;
        try {
          entry = log.publish(req_);
        } catch (e) {
          // Nothing was written, so nothing was spent.
          for (const [l, kk] of taken) l.refund(kk);
          throw e;
        }
        return json(res, 201, { index: entry.index, sth: sthToJson(log.sth()) });
      }
      if (req.method === 'POST' && p === '/kt/v1/buckets') {
        const j = await readBodyOf(req, res);
        if (j === null) return undefined;
        const list = j.buckets;
        if (!Array.isArray(list) || list.length < 1 || list.length > MAX_BUCKETS) {
          return fail(res, 400, 'bad_request', `buckets is a list of 1..${MAX_BUCKETS} {prefix, bits}`);
        }
        const qs = list.map((b) => (b && typeof b === 'object' ? bucketQuery(b.prefix, b.bits) : null));
        if (qs.some((q) => q === null)) return fail(res, 400, 'bad_request', BUCKET_QUERY_RULE);
        const r = log.buckets(qs, bucketLimits);
        return json(res, 200, { sth: headJson(r.sth), buckets: r.buckets.map(bucketToJson) });
      }
      if (req.method === 'POST' && p === '/kt/v1/entries') {
        // The by-index form of the mirrors' route: the entries a client
        // needs the values of — named by a bucket, with decoys beside them
        // (phase 35) — each with its inclusion proof under the head served,
        // which a page for a mirror does not carry because a mirror rebuilds
        // the tree. A route a client's check depends on, so it is bounded as
        // a label's history is — a thousand indexes, MAX_HISTORY_PAGE_BYTES
        // of entries, `total` so a short answer can be told from the whole —
        // and is not charged to the mirrors' budget, which every reader
        // behind an unconfigured front shares.
        const j = await readBodyOf(req, res);
        if (j === null) return undefined;
        const ix = j.indexes;
        if (!Array.isArray(ix) || ix.length < 1 || ix.length > MAX_PAGE) {
          return fail(res, 400, 'bad_request', `indexes is a list of 1..${MAX_PAGE} entry indexes`);
        }
        const r = log.entriesAt(ix, { maxBytes: MAX_HISTORY_PAGE_BYTES });
        return json(res, 200, {
          sth: sthToJson(r.sth),
          total: r.total,
          entries: r.entries.map((x) => ({ entry: log.entryJson(x.entry), inclusion: inclusionToJson(x.inclusion) })),
        });
      }
      if (req.method === 'POST') return fail(res, 404, 'not_found', 'no such route');
      return fail(res, 405, 'method_not_allowed', 'GET or POST');
    } catch (e) {
      if (e instanceof PublishError) return fail(res, e.status, e.code, e.message);
      console.error(e);
      if (!res.headersSent) return fail(res, 500, 'internal', 'internal error');
      res.destroy();
    }
  });
  httpServer.on('close', () => clearInterval(sweeper));
  return { httpServer, log };
}

function seedFromEnv() {
  if (process.env.KT_SEED) {
    const s = process.env.KT_SEED.trim();
    if (!/^[0-9a-fA-F]{64}$/.test(s)) throw new Error('KT_SEED must be 64 hex characters');
    return Buffer.from(s, 'hex');
  }
  if (process.env.KT_SEED_FILE) {
    const raw = fs.readFileSync(process.env.KT_SEED_FILE);
    if (raw.length === 32) return raw;
    const s = raw.toString('utf8').trim();
    if (/^[0-9a-fA-F]{64}$/.test(s)) return Buffer.from(s, 'hex');
    throw new Error('KT_SEED_FILE must hold 32 raw bytes or 64 hex characters');
  }
  throw new Error('set KT_SEED (64 hex) or KT_SEED_FILE; generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
}

/** KT_CONFIRM_HEAD, as a refusal prints it: `<size>@<ts>`. Null when unset. */
function confirmHeadFromEnv(v) {
  const s = (v || '').trim();
  if (!s) return null;
  const m = /^(\d{1,15})@(\d{1,16})$/.exec(s);
  if (!m) throw new Error('KT_CONFIRM_HEAD must be <size>@<ts>, exactly as the refusal printed it');
  return { size: Number(m[1]), ts: Number(m[2]) };
}

/**
 * What answers while the log replays: `GET /health` says how far it has got
 * and what it holds, and everything is 503 — the log is not serving, and a
 * host's health check should say so.
 *
 * Until 2026-10-04 nothing listened until the replay was done. A large log
 * took minutes to come up with its port closed, which a host and an uptime
 * monitor read exactly as they read a dead process; and a log that had
 * outgrown its instance was killed during the replay with nothing to show
 * for it but a restart counter. Now a slow replay is visible as one, with
 * its progress and its resident memory climbing toward the limit beside it.
 * Nothing about the log is served or signed until the replay has passed
 * every check a start makes; then this server is closed and the log's own
 * takes the port. Every response says `connection: close`, so nothing holds
 * a socket open into the gap.
 */
function replayServer(progress, mode = 'kt') {
  return http.createServer((req, res) => {
    res.setHeader('connection', 'close');
    res.setHeader('retry-after', '5');
    let p = '';
    try {
      p = new URL(req.url, 'http://localhost').pathname;
    } catch {
      // A request target URL cannot parse is not /health; it gets the 503.
    }
    if (req.method === 'GET' && p === '/health') {
      return json(res, 503, { state: 'replaying', ...(mode === 'handles' ? { mode } : {}), replayed: progress.replayed, ...memory() });
    }
    return fail(res, 503, 'starting', 'the log is replaying its entries and serves nothing until it has');
  });
}

function listen(server, port, host) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.off('error', reject);
      resolve(server.address().port);
    });
  });
}

async function main() {
  // First: a mistyped KT_MODE must not start either log under this key.
  const mode = modeFromEnv(process.env.KT_MODE);
  const seed = seedFromEnv();
  const signingKey = privateKeyFromSeed(seed);
  let store;
  if (process.env.KT_EPHEMERAL === '1') {
    store = new MemoryStore();
    console.warn('KT_EPHEMERAL=1: entries are kept in memory and a restart forgets them — development only');
  } else {
    const dir = process.env.KT_DATA || path.join(process.cwd(), 'data');
    fs.mkdirSync(dir, { recursive: true });
    store = new FileStore(path.join(dir, 'entries.jsonl'));
  }
  // A floor that lives in the environment rather than on the disk, because
  // the failure it is for is the disk going missing: an unmounted KT_DATA
  // takes the head file with it, and a log that comes up empty and starts
  // signing a fresh history with the production key puts every client that
  // holds a head into permanent fault. Set it once to a size the log has
  // passed; it is a floor, so it stays true as the log grows.
  const minSize = Number(process.env.KT_MIN_SIZE || 0);
  if (!Number.isInteger(minSize) || minSize < 0) throw new Error('KT_MIN_SIZE must be a non-negative integer');
  // And the floor the disk cannot hold for itself: a whole-disk snapshot
  // brings its head back with it. A start whose last recorded head is older
  // than this is refused until KT_CONFIRM_HEAD names that head (KtLog
  // `_checkResumed`). Minutes; 0 turns it off.
  const maxHeadAgeMin = Number(process.env.KT_MAX_HEAD_AGE_MIN || 30);
  if (!(maxHeadAgeMin >= 0)) throw new Error('KT_MAX_HEAD_AGE_MIN must be a number of minutes (0 turns the check off)');
  const confirmHead = confirmHeadFromEnv(process.env.KT_CONFIRM_HEAD);
  // KT_PORT first; then PORT, which cloud hosts inject (render.kt.yaml).
  const host = process.env.KT_HOST || '127.0.0.1';
  const progress = { replayed: 0 };
  const replaying = replayServer(progress, mode);
  const port = await listen(replaying, +(process.env.KT_PORT || process.env.PORT || 8085), host);
  console.log(`z-kt: ${mode === 'handles' ? 'the HANDLE log (KT_MODE=handles), ' : ''}replaying; GET http://${host}:${port}/health says how far`);
  const log = await KtLog.open(
    { store, signingKey, minSize, maxHeadAgeMs: maxHeadAgeMin > 0 ? maxHeadAgeMin * 60_000 : Infinity, confirmHead, mode },
    { onProgress: (n) => (progress.replayed = n) }
  );
  replaying.closeAllConnections();
  await new Promise((resolve) => replaying.close(resolve));
  const { httpServer } = createServer({
    log,
    publishPerMinute: +(process.env.PUBLISH_PER_MIN || 30),
    publishPerMinuteTotal: +(process.env.PUBLISH_PER_MIN_TOTAL || 120),
    publishPerAccountPerDay: +(process.env.PUBLISH_PER_ACCT_PER_DAY || 20),
    newAccountsPerMinute: +(process.env.PUBLISH_NEW_ACCOUNTS_PER_MIN || 10),
    ...(process.env.PUBLISH_NEW_ACCOUNTS_PER_ADDR_PER_MIN
      ? { newAccountsPerAddressPerMinute: +process.env.PUBLISH_NEW_ACCOUNTS_PER_ADDR_PER_MIN }
      : {}),
    maxValueBytes: +(process.env.KT_MAX_VALUE_BYTES || 32 * 1024),
    minFreeBytes: +(process.env.KT_MIN_FREE_BYTES || 64 * 1024 * 1024),
    readBytesPerMinute: +(process.env.READ_BYTES_PER_MIN || 32 * 1024 * 1024),
    readBytesPerMinuteTotal: +(process.env.READ_BYTES_PER_MIN_TOTAL || 128 * 1024 * 1024),
    maxPublishInFlight: +(process.env.KT_MAX_PUBLISH_IN_FLIGHT || 256),
    clientIpHeader: (process.env.KT_CLIENT_IP_HEADER || '').trim().toLowerCase() || null,
  });
  await listen(httpServer, port, host);
  // The head on disk says when the log last ran: re-recorded every
  // `resignMs` while it does, and once more at a clean stop. A head that
  // cannot be written is said, and serving goes on — the cost is only that
  // the next start may have to be confirmed.
  const keepAlive = (opts) => {
    try {
      log.keepAlive(opts);
    } catch (e) {
      console.error(`z-kt: could not record the head: ${e.message}`);
    }
  };
  const alive = setInterval(keepAlive, 60_000);
  alive.unref();
  const stop = () => {
    clearInterval(alive);
    keepAlive({ force: true });
    httpServer.close(() => {
      log.close();
      process.exit(0);
    });
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
  // Said only once a stop is a clean one: whatever reads this and stops the
  // log from then on gets the head recorded, as the next start expects.
  console.log(`z-kt: ${mode === 'handles' ? 'handle log, ' : ''}${log.size} entries, ${log.map.size} labels; public key ${log.publicKey.toString('base64')}`);
  console.log(`z-kt: listening on http://${host}:${port}`);
}

module.exports = { createServer, RateLimiter, MAX_BODY, MAX_READ_BODY, MAX_PAGE, MAX_PAGE_BYTES, MAX_HISTORY_PAGE_BYTES };

if (require.main === module) {
  main().catch((e) => {
    console.error(`z-kt: ${e.message}`);
    process.exit(1);
  });
}
