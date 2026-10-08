#!/usr/bin/env node
'use strict';

/**
 * What the proof of work in front of an introduction mailbox costs (phase 37,
 * PROTOCOL §21.6), in this Node on this machine:
 *
 *   - the relay's check of one stamp: `introStamp` from server.js, the
 *     function the relay runs on a send to a flagged mailbox — one SHA-256
 *     over the envelope and two over 99 bytes (today and yesterday) — at
 *     envelope sizes from a contact request's to the 64 KiB an introduction
 *     mailbox takes at most (a larger one is refused before anything is
 *     hashed), beside the 99-byte hash alone and the envelope hash alone;
 *   - a sender's search for a stamp at 16, 20 and 24 bits: the prefix hashed
 *     once, then one SHA-256 per nonce, as a sender in Node would; the hash
 *     rate measured, and real searches timed.
 *
 *   node bench/intro_pow.js [trials16] [trials20] [trials24]
 *
 * Nothing here touches a network or a store. A search's length is geometric
 * (its standard deviation is its mean), so a few trials say little on their
 * own; the hash rate, and 2^bits divided by it, is the figure to quote.
 */

const crypto = require('crypto');
const { introStamp } = require('../server.js');

const CONTEXT = Buffer.from('z-intro-pow-v1:', 'utf8');
const DAY_MS = 86400000;

function zeroBits(h) {
  let n = 0;
  for (const b of h) {
    if (b !== 0) return n + Math.clz32(b) - 24;
    n += 8;
  }
  return n;
}
function prefix(rid, payload, day) {
  const d = Buffer.alloc(4);
  d.writeUInt32BE(day);
  const env = crypto.createHash('sha256').update(payload, 'utf8').digest();
  return Buffer.concat([CONTEXT, Buffer.from(rid, 'base64url'), d, env]);
}
function nsPerOp(fn, minMs = 400) {
  for (let i = 0; i < 200; i++) fn(); // warm up
  let n = 0;
  const t0 = process.hrtime.bigint();
  let elapsed = 0n;
  const budget = BigInt(minMs) * 1000000n;
  while (elapsed < budget) {
    for (let i = 0; i < 50; i++) fn();
    n += 50;
    elapsed = process.hrtime.bigint() - t0;
  }
  return Number(elapsed) / n;
}
const us = (ns) => (ns / 1000).toFixed(ns < 10000 ? 2 : 1);

function relaySide() {
  const rid = crypto.randomBytes(32).toString('base64url');
  const pow = crypto.randomBytes(16).toString('base64url');
  const fixed = crypto.randomBytes(99);
  console.log('Relay: checking one stamp (introStamp — the envelope hash plus two 99-byte hashes)');
  console.log(`  SHA-256 over 99 bytes alone             ${us(nsPerOp(() => crypto.createHash('sha256').update(fixed).digest()))} µs`);
  console.log(`  a stamp that is not 22 b64url characters ${us(nsPerOp(() => introStamp(rid, 'zs1.x', 'not a stamp')))} µs (refused before any hash)`);
  for (const [label, size] of [['1 KiB', 1024], ['4 KiB', 4096], ['16 KiB', 16384], ['64 KiB (the most it takes)', 65536]]) {
    const payload = 'zs1.' + crypto.randomBytes(Math.ceil((size * 3) / 4)).toString('base64url').slice(0, size - 4);
    const envHash = nsPerOp(() => crypto.createHash('sha256').update(payload, 'utf8').digest(), size >= 65536 ? 800 : 400);
    const whole = nsPerOp(() => introStamp(rid, payload, pow), size >= 65536 ? 800 : 400);
    // For scale: what the relay already spends on every send frame of this
    // size before it looks at anything in it.
    const frame = JSON.stringify({ t: 'send', id: 'x', to: rid, payload, pow });
    const parse = nsPerOp(() => JSON.parse(frame), size >= 65536 ? 800 : 400);
    console.log(
      `  envelope ${label.padEnd(27)} envelope hash ${us(envHash).padStart(7)} µs, whole check ${us(whole).padStart(7)} µs` +
        `   (JSON.parse of the frame: ${us(parse).padStart(7)} µs)`
    );
  }
}

function hashRate(base, ms = 1500) {
  const nonce = crypto.randomBytes(16);
  let n = 0;
  const t0 = process.hrtime.bigint();
  const budget = BigInt(ms) * 1000000n;
  while (process.hrtime.bigint() - t0 < budget) {
    for (let i = 0; i < 1000; i++) {
      nonce.writeUInt32BE(n++ >>> 0, 12);
      base.copy().update(nonce).digest();
    }
  }
  return n / (Number(process.hrtime.bigint() - t0) / 1e9);
}

function search(base, bits) {
  const nonce = crypto.randomBytes(16);
  for (let i = 0; ; i++) {
    nonce.writeUInt32BE(i >>> 0, 12);
    if (zeroBits(base.copy().update(nonce).digest()) >= bits) return { nonce, tries: i + 1 };
  }
}

function senderSide(trials) {
  const rid = crypto.randomBytes(32).toString('base64url');
  const payload = 'zs1.' + crypto.randomBytes(3000).toString('base64url'); // a contact request's size
  const day = Math.floor(Date.now() / DAY_MS);
  const base = crypto.createHash('sha256').update(prefix(rid, payload, day));
  const rate = hashRate(base);
  console.log(`Sender: searching for a stamp (prefix hashed once, one SHA-256 per nonce): ${(rate / 1e6).toFixed(2)} M hashes/s on one core`);
  for (const bits of [16, 20, 24]) {
    const n = trials[bits];
    const times = [];
    let tries = 0;
    for (let i = 0; i < n; i++) {
      const t0 = process.hrtime.bigint();
      const r = search(base, bits);
      times.push(Number(process.hrtime.bigint() - t0) / 1e6);
      tries += r.tries;
      // What the relay would say about it: at least the bits searched for.
      const got = introStamp(rid, payload, r.nonce.toString('base64url'), day * DAY_MS + 1).bits;
      if (got < bits) throw new Error(`a ${bits}-bit search produced a stamp the relay rates at ${got}`);
    }
    times.sort((a, b) => a - b);
    const mean = times.reduce((s, x) => s + x, 0) / n;
    const expected = (2 ** bits / rate) * 1000;
    console.log(
      `  ${bits} bits: expected ${expected < 1000 ? expected.toFixed(0) + ' ms' : (expected / 1000).toFixed(1) + ' s'} (2^${bits} / rate); ` +
        `${n} searches: mean ${mean < 1000 ? mean.toFixed(0) + ' ms' : (mean / 1000).toFixed(1) + ' s'}, ` +
        `median ${times[Math.floor(n / 2)] < 1000 ? times[Math.floor(n / 2)].toFixed(0) + ' ms' : (times[Math.floor(n / 2)] / 1000).toFixed(1) + ' s'}, ` +
        `${(tries / n / 2 ** bits).toFixed(2)} × 2^${bits} tries on average`
    );
  }
}

const [t16, t20, t24] = process.argv.slice(2).map(Number);
relaySide();
senderSide({ 16: t16 || 40, 20: t20 || 10, 24: t24 || 3 });
