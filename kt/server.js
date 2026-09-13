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
 *   POST /kt/v1/publish                      {acct, v, fp, value, sig} → {index, sth} — see lib/log.js
 *   GET  /kt/v1/pub                          the log's public key (for a first pin; clients ship it)
 *   GET  /health                             {size, labels, sthTs}
 *
 * Run it:
 *   KT_SEED=<64 hex>  KT_DATA=/var/lib/z-kt  KT_PORT=8443  node server.js
 *   KT_SEED_FILE=/etc/z-kt/seed (32 raw bytes or 64 hex) is the alternative
 *   to KT_SEED; PORT is honoured when KT_PORT is unset (a cloud host injects
 *   it); KT_EPHEMERAL=1 keeps entries in memory (development only —
 *   a restart forgets the log, which is exactly what a log must not do).
 *
 * Abuse: publishes pass three gates — a total rate (PUBLISH_PER_MIN_TOTAL,
 * default 120), a per-address rate (PUBLISH_PER_MIN, default 30) and a
 * per-account daily ceiling (PUBLISH_PER_ACCT_PER_DAY, default 20, charged
 * only once the signature verifies) — and bodies are capped at 400 KB. The
 * per-address gate is only per-CLIENT when KT_CLIENT_IP_HEADER names a
 * header something in front is known to set; behind an unconfigured proxy
 * every request shares one address, which is why the total gate exists and
 * why it is the one that stops a flood. A lookup is cheap — under a
 * millisecond at a hundred thousand labels — but the two paging routes were
 * not, and saying "reads are left to the reverse proxy" was the mistake: a
 * value may be 256 KiB, so `?count=1000` was ~333 MB in one string and
 * `/kt/v1/history/<label>` had no count at all, which made every label a
 * fixed URL that returns everything it has ever published, repeatable, and
 * `cache-control: no-store` means nothing in front absorbs the repeat. Both
 * are now bounded in BYTES (MAX_PAGE_BYTES) as well as by count, because the
 * size of an entry is chosen by whoever published it, and both report
 * `total` so a reader can tell a page from the whole.
 */

const http = require('http');
const fs = require('fs');
const path = require('path');

const {
  KtLog,
  PublishError,
  MemoryStore,
  FileStore,
  privateKeyFromSeed,
  entryToJson,
  sthToJson,
  mapProofToJson,
  inclusionToJson,
} = require('./lib/log.js');

const MAX_BODY = 400 * 1024;
const MAX_PAGE = 1000;
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

function json(res, status, body, extra = {}) {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(text),
    'cache-control': 'no-store',
    ...extra,
  });
  res.end(text);
}

function fail(res, status, code, message) {
  json(res, status, { error: code, message });
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
  take(key) {
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
    if (b.tokens < 1) return false;
    b.tokens -= 1;
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
    if (first && first.length <= 45 && /^[0-9a-fA-F:.]+$/.test(first)) return first;
  }
  return req.socket.remoteAddress || 'unknown';
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
  clientIpHeader = null,
  now = Date.now,
}) {
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
  const sweeper = setInterval(() => {
    limiter.sweep();
    total.sweep();
    perAccount.sweep();
  }, 60000);
  sweeper.unref();

  const httpServer = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const p = url.pathname;
    try {
      if (req.method === 'GET') {
        res.setHeader('access-control-allow-origin', '*');
        if (p === '/health') {
          const sth = log.sth();
          return json(res, 200, { size: log.size, labels: log.map.size, sthTs: sth.ts });
        }
        if (p === '/kt/v1/sth') return json(res, 200, sthToJson(log.sth()));
        if (p === '/kt/v1/pub') return json(res, 200, { pub: log.publicKey.toString('base64') });
        if (p === '/kt/v1/consistency') {
          const sth = log.sth();
          const first = intParam(url.searchParams.get('first'), NaN);
          const second = intParam(url.searchParams.get('second'), sth.size);
          if (Number.isNaN(first) || Number.isNaN(second)) return fail(res, 400, 'bad_request', 'first and second are non-negative integers');
          if (second > sth.size) return fail(res, 400, 'bad_request', `second exceeds the head's size ${sth.size}`);
          const proof = log.consistency(first, second);
          return json(res, 200, { sth: sthToJson(sth), first, second, proof: proof.map((h) => h.toString('base64')) });
        }
        if (p.startsWith('/kt/v1/lookup/')) {
          const label = parseLabel(p.slice('/kt/v1/lookup/'.length));
          if (!label) return fail(res, 400, 'bad_request', 'a label is 64 hex characters');
          const r = log.lookup(label);
          return json(res, 200, {
            sth: sthToJson(r.sth),
            map: mapProofToJson(r.map),
            entry: r.entry ? entryToJson(r.entry) : null,
            inclusion: r.inclusion ? inclusionToJson(r.inclusion) : null,
          });
        }
        if (p.startsWith('/kt/v1/history/')) {
          const label = parseLabel(p.slice('/kt/v1/history/'.length));
          if (!label) return fail(res, 400, 'bad_request', 'a label is 64 hex characters');
          const start = intParam(url.searchParams.get('start'), 0);
          const count = intParam(url.searchParams.get('count'), MAX_PAGE);
          if (Number.isNaN(start) || Number.isNaN(count) || count < 1) return fail(res, 400, 'bad_request', 'start >= 0 and count >= 1');
          const r = log.history(label, { start, count: Math.min(count, MAX_PAGE), maxBytes: MAX_PAGE_BYTES });
          return json(res, 200, {
            sth: sthToJson(r.sth),
            start: r.start,
            total: r.total,
            entries: r.entries.map((x) => ({ entry: entryToJson(x.entry), inclusion: inclusionToJson(x.inclusion) })),
          });
        }
        if (p === '/kt/v1/entries') {
          const start = intParam(url.searchParams.get('start'), 0);
          const count = intParam(url.searchParams.get('count'), 100);
          if (Number.isNaN(start) || Number.isNaN(count) || count < 1) return fail(res, 400, 'bad_request', 'start >= 0 and count >= 1');
          const r = log.range(start, Math.min(count, MAX_PAGE), { maxBytes: MAX_PAGE_BYTES });
          return json(res, 200, { sth: sthToJson(r.sth), start, total: r.total, entries: r.entries.map(entryToJson) });
        }
        return fail(res, 404, 'not_found', 'no such route');
      }
      if (req.method === 'POST' && p === '/kt/v1/publish') {
        // Before the body is read, both cheap gates: a 400 KB read is not
        // free, and moving the limit after the parse would have traded a
        // limiter that bound nothing for a limiter that bound nothing until
        // after the expensive part.
        if (!total.take('all')) {
          return fail(res, 429, 'rate_limited', `at most ${publishPerMinuteTotal} publishes a minute in total`);
        }
        const key = clientKey(req, clientIpHeader);
        if (!limiter.take(key)) return fail(res, 429, 'rate_limited', `at most ${publishPerMinute} publishes a minute from one address`);
        const body = await readBody(req, MAX_BODY);
        let j;
        try {
          j = JSON.parse(body.toString('utf8'));
        } catch {
          return fail(res, 400, 'bad_request', 'body is not JSON');
        }
        if (!j || typeof j !== 'object') return fail(res, 400, 'bad_request', 'body is not an object');
        const field = (name) => (typeof j[name] === 'string' ? Buffer.from(j[name], 'base64') : null);
        const req_ = {
          acct: field('acct'),
          version: j.v,
          fp: field('fp'),
          value: field('value'),
          sig: field('sig'),
        };
        // Checked BEFORE the per-account gate is charged: an unsigned request
        // naming somebody else's account must not be able to spend their
        // budget, and the only thing that tells the two apart is the
        // signature. `publish` checks again — it is responsible for its own
        // input and one more Ed25519 verify is microseconds.
        log.checkPublish(req_);
        if (!perAccount.take(req_.acct.toString('base64'))) {
          return fail(
            res,
            429,
            'rate_limited',
            `at most ${publishPerAccountPerDay} publishes a day for one account`
          );
        }
        const entry = log.publish(req_);
        return json(res, 201, { index: entry.index, sth: sthToJson(log.sth()) });
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

function main() {
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
  const log = new KtLog({ store, signingKey });
  const { httpServer } = createServer({
    log,
    publishPerMinute: +(process.env.PUBLISH_PER_MIN || 30),
    publishPerMinuteTotal: +(process.env.PUBLISH_PER_MIN_TOTAL || 120),
    publishPerAccountPerDay: +(process.env.PUBLISH_PER_ACCT_PER_DAY || 20),
    clientIpHeader: (process.env.KT_CLIENT_IP_HEADER || '').trim().toLowerCase() || null,
  });
  // KT_PORT first; then PORT, which cloud hosts inject (render.kt.yaml).
  const port = +(process.env.KT_PORT || process.env.PORT || 8085);
  const host = process.env.KT_HOST || '127.0.0.1';
  httpServer.listen(port, host, () => {
    console.log(`z-kt: ${log.size} entries, ${log.map.size} labels; public key ${log.publicKey.toString('base64')}`);
    console.log(`z-kt: listening on http://${host}:${port}`);
  });
  const stop = () => {
    httpServer.close(() => {
      log.close();
      process.exit(0);
    });
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

module.exports = { createServer, RateLimiter, MAX_BODY, MAX_PAGE, MAX_PAGE_BYTES };

if (require.main === module) {
  try {
    main();
  } catch (e) {
    console.error(`z-kt: ${e.message}`);
    process.exit(1);
  }
}
