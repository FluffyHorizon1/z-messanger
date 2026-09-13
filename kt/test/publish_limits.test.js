// The limiter was keyed on a value that is the same for the whole internet.
//
// `kt/server.js` limited publishes per source address, and the address it
// used was `req.socket.remoteAddress` — which behind Cloudflare → Render is
// the proxy, on every request. So the gate that was supposed to bind one
// client bound everybody together at one bucket, which is to say it bound
// nothing: measured on the day the log went live, 35–175 publishes a minute
// against a nominal 30, and 3,853 entries from 3,579 distinct account keys in
// about a hundred minutes, while the relay beside it saw four envelopes.
//
// Keying on the signed `acct` instead is the obvious repair and it is not
// sufficient, which is the part worth being exact about: the flood used 3,579
// DIFFERENT accounts, and a per-account limit lets every one of them through.
// Ed25519 keys are free. A log's disk is not.
//
// So there are three gates now, stopping three different things:
//
//   total    every publish, whatever the source — the one that actually
//            stops a flood, and the only one that works when there is no
//            trusted proxy header to identify a client with;
//   address  per source address, the one that existed; genuinely per-client
//            only when something in front is known to set a header;
//   account  per account key per day, charged only once the signature
//            verifies, so nobody can spend an account's budget but that
//            account. Not a flood control: a limit on one account making the
//            log its own.
//
// What is asserted below:
//   1. a flood from many accounts through one proxy address is stopped, which
//      is the case that was live — and reads are never charged for it;
//   2. an unsigned publish naming somebody else's account cannot spend that
//      account's budget, because the signature is checked before the gate;
//   3. a forwarded client address is honoured only when one is configured,
//      and a client-supplied one is otherwise ignored — a limiter keyed on a
//      value the caller picks is worse than one keyed on a value it cannot;
//   4. the buckets are bounded: a limiter keyed on something an attacker can
//      mint must not be a map an attacker can grow.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const {
  KtLog,
  MemoryStore,
  labelFor,
  sealValue,
  makePublish,
  privateKeyFromSeed,
  rawPublicKey,
} = require('../lib/log.js');
const { createServer, RateLimiter } = require('../server.js');

const logKey = privateKeyFromSeed(crypto.createHash('sha256').update('limits log seed').digest());

function account(name) {
  const key = privateKeyFromSeed(crypto.createHash('sha256').update(`acct:${name}`).digest());
  return { key, pub: rawPublicKey(key), label: labelFor(rawPublicKey(key)) };
}

function publishJson(acct, v) {
  const value = sealValue(acct.pub, Buffer.from(`list ${v}`, 'utf8'));
  const fp = crypto.createHash('sha256').update(`fp:${v}`).digest().subarray(0, 16);
  const p = makePublish(acct.key, { version: v, fp, value });
  return {
    acct: p.acct.toString('base64'),
    v: p.version,
    fp: p.fp.toString('base64'),
    value: p.value.toString('base64'),
    sig: p.sig.toString('base64'),
  };
}

async function start(opts = {}) {
  const log = new KtLog({ store: new MemoryStore(), signingKey: logKey });
  const { httpServer } = createServer({ log, ...opts });
  await new Promise((res) => httpServer.listen(0, '127.0.0.1', res));
  const base = `http://127.0.0.1:${httpServer.address().port}`;
  const post = async (body, headers = {}) => {
    const r = await fetch(base + '/kt/v1/publish', {
      method: 'POST',
      body: JSON.stringify(body),
      headers: { 'content-type': 'application/json', ...headers },
    });
    return { status: r.status, body: await r.json() };
  };
  const get = async (p) => {
    const r = await fetch(base + p);
    return { status: r.status, body: await r.json() };
  };
  const stop = async () => {
    httpServer.closeAllConnections();
    await new Promise((res) => httpServer.close(res));
  };
  return { log, post, get, stop };
}

test('1. a flood of fresh accounts from one address is stopped', async () => {
  // Every publish is genuine: a different account, correctly signed, first
  // version. Nothing about any one of them is refusable — which is the shape
  // the live flood had, and the reason a per-account gate does not see it.
  const s = await start({ publishPerMinuteTotal: 5, publishPerMinute: 1000 });
  try {
    let accepted = 0;
    let refused = 0;
    for (let i = 0; i < 25; i++) {
      const r = await s.post(publishJson(account(`flood-${i}`), 1));
      if (r.status === 201) accepted += 1;
      else {
        assert.equal(r.status, 429);
        assert.equal(r.body.error, 'rate_limited');
        refused += 1;
      }
    }
    assert.equal(accepted, 5, 'exactly the total allowance got in');
    assert.equal(refused, 20);
    assert.equal(s.log.size, 5, 'and the log grew by that and no more');
    // Reads are not charged for somebody else's flood.
    for (let i = 0; i < 10; i++) assert.equal((await s.get('/kt/v1/sth')).status, 200);
  } finally {
    await s.stop();
  }
});

test('2. an unsigned publish cannot spend another account budget', async () => {
  const s = await start({ publishPerAccountPerDay: 2 });
  try {
    const victim = account('victim');
    const attacker = account('attacker');
    // Attacker's own signature over their own request, with the victim's
    // account swapped in: the label no longer matches the key, so the
    // signature fails, and it must fail BEFORE anything is charged.
    for (let i = 0; i < 20; i++) {
      const forged = publishJson(attacker, i + 1);
      forged.acct = victim.pub.toString('base64');
      const r = await s.post(forged);
      assert.equal(r.status, 403, 'refused as unsigned, not as rate-limited');
      assert.equal(r.body.error, 'bad_signature');
    }
    // The victim's own budget is untouched.
    assert.equal((await s.post(publishJson(victim, 1))).status, 201);
    assert.equal((await s.post(publishJson(victim, 2))).status, 201);
    const third = await s.post(publishJson(victim, 3));
    assert.equal(third.status, 429, 'and the daily ceiling is theirs to spend');
    assert.equal(third.body.error, 'rate_limited');
  } finally {
    await s.stop();
  }
});

test('3. a forwarded address counts only when one is configured', async () => {
  // Unconfigured: the header is the caller's to choose, so it is ignored and
  // every caller shares the socket's address.
  {
    const s = await start({ publishPerMinute: 2, publishPerMinuteTotal: 1000 });
    try {
      let accepted = 0;
      for (let i = 0; i < 6; i++) {
        const r = await s.post(publishJson(account(`hdr-off-${i}`), 1), {
          'cf-connecting-ip': `10.0.0.${i}`,
        });
        if (r.status === 201) accepted += 1;
      }
      assert.equal(accepted, 2, 'a header nobody vouches for buys nothing');
    } finally {
      await s.stop();
    }
  }
  // Configured: the header names the client, and each one has its own bucket.
  {
    const s = await start({
      publishPerMinute: 2,
      publishPerMinuteTotal: 1000,
      clientIpHeader: 'cf-connecting-ip',
    });
    try {
      let accepted = 0;
      for (let i = 0; i < 6; i++) {
        const r = await s.post(publishJson(account(`hdr-on-${i}`), 1), {
          'cf-connecting-ip': `10.0.0.${i}`,
        });
        if (r.status === 201) accepted += 1;
      }
      assert.equal(accepted, 6, 'six clients, two each');
      // And a value that is not an address is not used as a key.
      const junk = await s.post(publishJson(account('hdr-junk'), 1), {
        'cf-connecting-ip': 'not an address at all',
      });
      assert.equal(junk.status, 201);
    } finally {
      await s.stop();
    }
  }
});

test('4. the buckets are bounded however many keys arrive', () => {
  let t = 0;
  const rl = new RateLimiter(1, { cap: 100, now: () => t });
  for (let i = 0; i < 5000; i++) assert.ok(rl.take(`key-${i}`), 'a fresh key gets a fresh bucket');
  assert.ok(rl.buckets.size <= 100, `tracked ${rl.buckets.size} keys against a cap of 100`);
  // The cap drops the least recently seen, not the busiest: a key that keeps
  // being used keeps its bucket, and its refusal.
  const busy = new RateLimiter(1, { cap: 10, now: () => t });
  assert.ok(busy.take('busy'));
  for (let i = 0; i < 100; i++) {
    busy.take(`other-${i}`);
    assert.ok(!busy.take('busy'), `'busy' kept its empty bucket after ${i + 1} others`);
  }
  // And it refills on the stated window rather than on the number of keys.
  t = 60_000;
  assert.ok(busy.take('busy'));
});
