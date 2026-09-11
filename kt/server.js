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
 *   GET  /kt/v1/history/<label hex>          head + every entry for the label, each with an inclusion proof
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
 * Abuse: publishes are limited per source address (PUBLISH_PER_MIN, default
 * 30) and bodies to 400 KB; reads are cheap (a lookup is under a millisecond
 * at a hundred thousand labels) and are left to the reverse proxy in front.
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

/** A token bucket per key, refilled at `perMinute` tokens a minute, holding at most that many. */
class RateLimiter {
  constructor(perMinute, now = Date.now) {
    this.perMinute = perMinute;
    this.now = now;
    this.buckets = new Map();
  }
  take(key) {
    const t = this.now();
    let b = this.buckets.get(key);
    if (!b) {
      b = { tokens: this.perMinute, at: t };
      this.buckets.set(key, b);
    }
    b.tokens = Math.min(this.perMinute, b.tokens + ((t - b.at) / 60000) * this.perMinute);
    b.at = t;
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
  }
  /** Forget idle addresses so the map does not grow with every visitor ever. */
  sweep() {
    const t = this.now();
    for (const [k, b] of this.buckets) if (t - b.at > 120000) this.buckets.delete(k);
  }
}

/**
 * Build the HTTP server around a log. Returns { httpServer, log }; the caller
 * listens. `publishPerMinute` is per source address.
 */
function createServer({ log, publishPerMinute = 30, now = Date.now }) {
  const limiter = new RateLimiter(publishPerMinute, now);
  const sweeper = setInterval(() => limiter.sweep(), 60000);
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
          const r = log.history(label);
          return json(res, 200, {
            sth: sthToJson(r.sth),
            entries: r.entries.map((x) => ({ entry: entryToJson(x.entry), inclusion: inclusionToJson(x.inclusion) })),
          });
        }
        if (p === '/kt/v1/entries') {
          const start = intParam(url.searchParams.get('start'), 0);
          const count = intParam(url.searchParams.get('count'), 100);
          if (Number.isNaN(start) || Number.isNaN(count) || count < 1) return fail(res, 400, 'bad_request', 'start >= 0 and count >= 1');
          const r = log.range(start, Math.min(count, MAX_PAGE));
          return json(res, 200, { sth: sthToJson(r.sth), start, entries: r.entries.map(entryToJson) });
        }
        return fail(res, 404, 'not_found', 'no such route');
      }
      if (req.method === 'POST' && p === '/kt/v1/publish') {
        const key = req.socket.remoteAddress || 'unknown';
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
        const entry = log.publish({
          acct: field('acct'),
          version: j.v,
          fp: field('fp'),
          value: field('value'),
          sig: field('sig'),
        });
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
  const { httpServer } = createServer({ log, publishPerMinute: +(process.env.PUBLISH_PER_MIN || 30) });
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

module.exports = { createServer, RateLimiter, MAX_BODY, MAX_PAGE };

if (require.main === module) {
  try {
    main();
  } catch (e) {
    console.error(`z-kt: ${e.message}`);
    process.exit(1);
  }
}
