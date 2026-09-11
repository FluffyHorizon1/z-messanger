#!/usr/bin/env node
'use strict';
// What a key-transparency lookup costs — the numbers docs/adr/0006 and
// docs/PROTOCOL.md §19 quote. A measurement, not a test; run it deliberately:
//
//     node bench/proofs.js                 # 1 000, 10 000 and 100 000 labels
//     LABELS=1000000 node bench/proofs.js  # one size (slow: ~1 min per 100k publishes)
//
// For each population it publishes one entry per label plus a second entry
// for a tenth of them (so the log is 1.1× the label count), then measures:
// build time; head signing; a lookup's map-proof sibling count and
// inclusion-path length; the JSON size of a lookup response (what a phone
// downloads to verify one contact); a mirror page; and the wall-clock cost of
// a publish and a lookup once the log is that big. Everything in-process, so
// the numbers are the log's own, not the network's.

const crypto = require('crypto');
const { KtLog, MemoryStore, labelFor, privateKeyFromSeed, rawPublicKey, sealValue, makePublish, entryToJson, sthToJson, mapProofToJson, inclusionToJson } = require('../lib/log.js');

const sizes = process.env.LABELS ? [Number(process.env.LABELS)] : [1000, 10000, 100000];
const logKey = privateKeyFromSeed(crypto.randomBytes(32));

// One sealed list stands in for every account's: 4 classical devices is
// ~1.6 KB of JSON; the value is what a phone downloads, so its size matters
// only for the response-size figure, which is reported with the value's
// share broken out.
const sampleList = Buffer.alloc(1600, 0x41);

function hr() {
  return Number(process.hrtime.bigint()) / 1e6;
}

function lookupJson(r) {
  return JSON.stringify({
    sth: sthToJson(r.sth),
    map: mapProofToJson(r.map),
    entry: r.entry ? entryToJson(r.entry) : null,
    inclusion: r.inclusion ? inclusionToJson(r.inclusion) : null,
  });
}

for (const n of sizes) {
  const log = new KtLog({ store: new MemoryStore(), signingKey: logKey });
  const accounts = [];
  const t0 = hr();
  for (let i = 0; i < n; i++) {
    // Account keys are what makes labels random; generating 100k Ed25519
    // pairs is most of the build time and is charged to the accounts, not
    // the log, so it is timed separately.
    const key = privateKeyFromSeed(crypto.randomBytes(32));
    accounts.push({ key, pub: rawPublicKey(key) });
  }
  const t1 = hr();
  const publishes = accounts.map((a) => makePublish(a.key, { version: 1, fp: crypto.randomBytes(16), value: sealValue(a.pub, sampleList) }));
  const t2 = hr();
  for (const p of publishes) log.publish(p);
  for (let i = 0; i < n; i += 10) {
    log.publish(makePublish(accounts[i].key, { version: 2, fp: crypto.randomBytes(16), value: sealValue(accounts[i].pub, sampleList) }));
  }
  const t3 = hr();
  const sth = log.sth();
  const t4 = hr();

  // Lookups over a sample of labels, including updated ones.
  const sample = [];
  for (let i = 0; i < 200; i++) sample.push(accounts[Math.floor((i / 200) * n)]);
  let siblings = 0;
  let maxSiblings = 0;
  let pathLen = 0;
  let bytes = 0;
  let valueBytes = 0;
  const l0 = hr();
  for (const a of sample) {
    const r = log.lookup(labelFor(a.pub));
    siblings += r.map.siblings.length;
    maxSiblings = Math.max(maxSiblings, r.map.siblings.length);
    pathLen += r.inclusion.path.length;
    const j = lookupJson(r);
    bytes += j.length;
    valueBytes += JSON.stringify(entryToJson(r.entry).value).length;
  }
  const l1 = hr();
  // A publish once the log is this big.
  const extra = accounts[7];
  const p0 = hr();
  log.publish(makePublish(extra.key, { version: 3, fp: crypto.randomBytes(16), value: sealValue(extra.pub, sampleList) }));
  const p1 = hr();
  const sth2 = log.sth();
  const p2 = hr();
  const page = JSON.stringify(log.range(0, 500).entries.map(entryToJson)).length;

  console.log(`labels ${n}  entries ${log.size}`);
  console.log(`  build: keys ${(t1 - t0).toFixed(0)} ms, seal+sign ${(t2 - t1).toFixed(0)} ms, publish ${(t3 - t2).toFixed(0)} ms (${((t3 - t2) / log.size).toFixed(3)} ms/entry), first head ${(t4 - t3).toFixed(1)} ms`);
  console.log(`  lookup: ${((l1 - l0) / sample.length).toFixed(3)} ms; map siblings avg ${(siblings / sample.length).toFixed(1)} max ${maxSiblings}; inclusion path ${(pathLen / sample.length).toFixed(1)}; response ${(bytes / sample.length).toFixed(0)} B of which value ${(valueBytes / sample.length).toFixed(0)} B`);
  console.log(`  publish at this size: ${(p1 - p0).toFixed(2)} ms, then a new head ${(p2 - p1).toFixed(2)} ms (log root ${sth2.logRoot.equals(sth.logRoot) ? 'unchanged?!' : 'changed'})`);
  console.log(`  mirror page of 500 entries: ${(page / 1024).toFixed(0)} KB`);
}
