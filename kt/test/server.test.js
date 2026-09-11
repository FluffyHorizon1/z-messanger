'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');

const { verifyInclusion, verifyConsistency } = require('../lib/merkle.js');
const { verifyMapProof } = require('../lib/smt.js');
const {
  KtLog,
  MemoryStore,
  labelFor,
  leafHashOf,
  verifySth,
  sealValue,
  makePublish,
  privateKeyFromSeed,
  rawPublicKey,
  entryFromJson,
  sthFromJson,
  mapProofFromJson,
  inclusionFromJson,
} = require('../lib/log.js');
const { createServer, RateLimiter, MAX_BODY } = require('../server.js');

const logKey = privateKeyFromSeed(crypto.createHash('sha256').update('server log seed').digest());

function account(name) {
  const key = privateKeyFromSeed(crypto.createHash('sha256').update(`acct:${name}`).digest());
  return { key, pub: rawPublicKey(key), label: labelFor(rawPublicKey(key)) };
}

function publishJson(acct, v) {
  const value = sealValue(acct.pub, Buffer.from(`list ${v}`, 'utf8'));
  const fp = crypto.createHash('sha256').update(`fp:${v}`).digest().subarray(0, 16);
  const p = makePublish(acct.key, { version: v, fp, value });
  return { acct: p.acct.toString('base64'), v: p.version, fp: p.fp.toString('base64'), value: p.value.toString('base64'), sig: p.sig.toString('base64') };
}

async function start(opts = {}) {
  const log = new KtLog({ store: new MemoryStore(), signingKey: logKey });
  const { httpServer } = createServer({ log, ...opts });
  await new Promise((res) => httpServer.listen(0, '127.0.0.1', res));
  const base = `http://127.0.0.1:${httpServer.address().port}`;
  const get = async (p) => {
    const r = await fetch(base + p);
    return { status: r.status, body: await r.json(), headers: r.headers };
  };
  const post = async (p, body) => {
    const r = await fetch(base + p, { method: 'POST', body: typeof body === 'string' ? body : JSON.stringify(body), headers: { 'content-type': 'application/json' } });
    return { status: r.status, body: await r.json() };
  };
  const stop = async () => {
    httpServer.closeAllConnections();
    await new Promise((res) => httpServer.close(res));
  };
  return { log, base, get, post, stop };
}

test('the routes: publish, sth, lookup, history, entries, consistency, pub, health', async () => {
  const s = await start();
  try {
    const alice = account('alice');
    const bob = account('bob');
    const empty = await s.get('/kt/v1/sth');
    assert.equal(empty.status, 200);
    assert.equal(empty.body.size, 0);
    assert.equal(empty.headers.get('cache-control'), 'no-store');
    assert.equal(empty.headers.get('access-control-allow-origin'), '*');
    const pub = await s.get('/kt/v1/pub');
    const logPub = Buffer.from(pub.body.pub, 'base64');
    assert.ok(logPub.equals(s.log.publicKey));
    assert.ok(verifySth(sthFromJson(empty.body), logPub));

    const p1 = await s.post('/kt/v1/publish', publishJson(alice, 1));
    assert.equal(p1.status, 201, JSON.stringify(p1.body));
    assert.equal(p1.body.index, 0);
    assert.equal(p1.body.sth.size, 1);
    assert.equal((await s.post('/kt/v1/publish', publishJson(bob, 1))).body.index, 1);
    assert.equal((await s.post('/kt/v1/publish', publishJson(alice, 2))).body.index, 2);
    // Refusals carry their code.
    const stale = await s.post('/kt/v1/publish', publishJson(alice, 2));
    assert.equal(stale.status, 409);
    assert.equal(stale.body.error, 'stale_version');
    const forged = publishJson(alice, 3);
    forged.sig = publishJson(bob, 3).sig;
    const bad = await s.post('/kt/v1/publish', forged);
    assert.equal(bad.status, 403);
    assert.equal(bad.body.error, 'bad_signature');
    assert.equal((await s.post('/kt/v1/publish', 'not json')).status, 400);
    assert.equal((await s.post('/kt/v1/publish', '[1,2]')).status, 400);
    assert.equal((await s.post('/kt/v1/publish', { acct: 5 })).status, 400);
    assert.equal((await s.post('/kt/v1/publish', { ...publishJson(alice, 3), v: '3' })).status, 400);

    const look = await s.get(`/kt/v1/lookup/${alice.label.toString('hex')}`);
    assert.equal(look.status, 200);
    const sth = sthFromJson(look.body.sth);
    assert.ok(verifySth(sth, logPub));
    assert.equal(sth.size, 3);
    const map = mapProofFromJson(look.body.map);
    assert.deepEqual(map.leaf, { index: 2, version: 2 });
    assert.ok(verifyMapProof({ root: sth.mapRoot, label: alice.label, ...map }));
    const entry = entryFromJson(look.body.entry);
    assert.equal(entry.version, 2);
    assert.equal(look.body.entry.acct, undefined, 'acct is never served');
    const inc = inclusionFromJson(look.body.inclusion);
    assert.ok(verifyInclusion({ leafHash: leafHashOf(entry), index: inc.index, size: inc.size, root: sth.logRoot, path: inc.path }));

    const absent = await s.get(`/kt/v1/lookup/${account('nobody').label.toString('hex')}`);
    assert.equal(absent.status, 200);
    assert.equal(absent.body.entry, null);
    assert.equal(absent.body.inclusion, null);
    assert.ok(verifyMapProof({ root: sth.mapRoot, label: account('nobody').label, ...mapProofFromJson(absent.body.map) }));
    assert.equal((await s.get('/kt/v1/lookup/zz')).status, 400);
    assert.equal((await s.get('/kt/v1/lookup/')).status, 400);

    const hist = await s.get(`/kt/v1/history/${alice.label.toString('hex')}`);
    assert.deepEqual(hist.body.entries.map((x) => x.entry.v), [1, 2]);
    for (const x of hist.body.entries) {
      const e = entryFromJson(x.entry);
      const i = inclusionFromJson(x.inclusion);
      assert.ok(verifyInclusion({ leafHash: leafHashOf(e), index: i.index, size: i.size, root: sthFromJson(hist.body.sth).logRoot, path: i.path }));
    }

    const page = await s.get('/kt/v1/entries?start=1&count=5');
    assert.deepEqual(page.body.entries.map((e) => e.index), [1, 2]);
    assert.equal((await s.get('/kt/v1/entries')).body.entries.length, 3);
    assert.equal((await s.get('/kt/v1/entries?start=x')).status, 400);
    assert.equal((await s.get('/kt/v1/entries?count=0')).status, 400);
    assert.equal((await s.get('/kt/v1/entries?start=99')).body.entries.length, 0);

    const cons = await s.get('/kt/v1/consistency?first=1');
    assert.equal(cons.status, 200);
    assert.equal(cons.body.first, 1);
    assert.equal(cons.body.second, 3);
    assert.ok(verifyConsistency({ first: 1, second: 3, firstRoot: sthFromJson(p1.body.sth).logRoot, secondRoot: sth.logRoot, proof: cons.body.proof.map((h) => Buffer.from(h, 'base64')) }));
    assert.equal((await s.get('/kt/v1/consistency')).status, 400);
    assert.equal((await s.get('/kt/v1/consistency?first=2&second=1')).status, 400);
    assert.equal((await s.get('/kt/v1/consistency?first=0&second=9')).status, 400);

    const health = await s.get('/health');
    assert.equal(health.body.size, 3);
    assert.equal(health.body.labels, 2);
    assert.equal((await s.get('/nope')).status, 404);
    assert.equal((await s.post('/kt/v1/sth', {})).status, 404);
    const put = await fetch(s.base + '/kt/v1/sth', { method: 'PUT' });
    assert.equal(put.status, 405);
  } finally {
    await s.stop();
  }
});

test('publishes are limited per address; reads are not', async () => {
  const s = await start({ publishPerMinute: 3 });
  try {
    const a = account('rate');
    for (let v = 1; v <= 3; v++) assert.equal((await s.post('/kt/v1/publish', publishJson(a, v))).status, 201);
    const fourth = await s.post('/kt/v1/publish', publishJson(a, 4));
    assert.equal(fourth.status, 429);
    assert.equal(fourth.body.error, 'rate_limited');
    for (let i = 0; i < 10; i++) assert.equal((await s.get('/kt/v1/sth')).status, 200);
  } finally {
    await s.stop();
  }
  // The bucket refills at the stated rate.
  let t = 0;
  const rl = new RateLimiter(3, () => t);
  assert.ok(rl.take('a') && rl.take('a') && rl.take('a'));
  assert.ok(!rl.take('a'));
  assert.ok(rl.take('b'), 'another address has its own bucket');
  t = 20_000; // one token back after a third of a minute
  assert.ok(rl.take('a'));
  assert.ok(!rl.take('a'));
  t = 200_000;
  rl.sweep();
  assert.equal(rl.buckets.size, 0);
});

test('an oversized body is refused before it is parsed', async () => {
  const s = await start();
  try {
    const r = await fetch(s.base + '/kt/v1/publish', { method: 'POST', body: Buffer.alloc(MAX_BODY + 1, 0x20), headers: { 'content-type': 'application/json' } }).catch((e) => e);
    // The server destroys the socket once the limit is crossed; depending on
    // timing the client sees a 413 or a reset. Either way nothing was published.
    if (!(r instanceof Error)) assert.equal(r.status, 413);
    assert.equal(s.log.size, 0);
    assert.equal((await s.get('/health')).body.size, 0);
  } finally {
    await s.stop();
  }
});
