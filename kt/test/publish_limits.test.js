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
//
// And the disk, from the 2026-09-14 review, which multiplied the limits
// together where nobody had: a publish is up to 341 KB on disk at the
// protocol's value cap, a 1 GB disk holds 3,069 of them, and with one
// address bucket for the whole internet that was 102 minutes to ENOSPC —
// after which every publish got a 500 until an operator grew a disk that
// `/health` gave them no reason to look at.
//   5. a FIRST publish for an account the log has never seen is charged
//      against its own allowance, an account the log holds is not — and an
//      account whose first publish was refused is still unknown, because the
//      index the gate asks is built only by publishes that were accepted;
//      a publish that fails after the tokens were taken gives them back;
//   6. below a floor of free space the log refuses to publish, says why with
//      503 rather than failing mid-write with 500, keeps answering reads, and
//      reports the disk in /health — where the floor is visible before it is
//      reached;
//   7. this log accepts values only up to its own cap, well under the
//      protocol's 256 KiB, because a real device list is a kilobyte and the
//      cap is what sets entries-per-gigabyte; the cap cannot be set above
//      the protocol's maximum;
//   8. the address gate is spent only by a publish that happens. It used to
//      be charged before the body was read, and behind a front with no
//      client-address header the address is everybody — so thirty one-byte
//      POSTs a minute from anywhere emptied the per-address bucket for every
//      genuine publisher (finding 17: measured, all 400, then a signed
//      publish 429, at half a request a second). It is taken after the
//      signature now, and given back when the publish is refused after it —
//      by the account's daily ceiling, by the new-account gate — because a
//      shared address must not be spendable with signatures either, and a
//      signature costs nothing. The total gate — which everybody shares by
//      construction, so moving only the address gate would have left it as
//      the same switch at two requests a second — counts publishes now too;
//   9. and what a request that publishes nothing can cost is bounded some
//      other way, since no gate counts requests any more: bodies being read
//      at once are capped, which sockets held open can occupy and a request
//      that finishes never does, because a rate is a switch and a bound on
//      concurrency is not.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  KtLog,
  MemoryStore,
  FileStore,
  labelFor,
  sealValue,
  makePublish,
  privateKeyFromSeed,
  rawPublicKey,
  MAX_VALUE_BYTES,
} = require('../lib/log.js');
const { createServer, RateLimiter } = require('../server.js');

const logKey = privateKeyFromSeed(crypto.createHash('sha256').update('limits log seed').digest());

function account(name) {
  const key = privateKeyFromSeed(crypto.createHash('sha256').update(`acct:${name}`).digest());
  return { key, pub: rawPublicKey(key), label: labelFor(rawPublicKey(key)) };
}

function publishJson(acct, v, plaintext = `list ${v}`) {
  const value = sealValue(acct.pub, Buffer.from(plaintext, 'utf8'));
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

async function start(opts = {}, { store = new MemoryStore() } = {}) {
  const log = new KtLog({ store, signingKey: logKey });
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
  return { log, post, get, stop, base };
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

test('5. a first publish for a new account is charged; a known account is not', async () => {
  const s = await start({ newAccountsPerMinute: 3, publishPerMinute: 1000, publishPerMinuteTotal: 1000 });
  try {
    let accepted = 0;
    const refusedAccounts = [];
    for (let i = 0; i < 10; i++) {
      const a = account(`new-${i}`);
      const r = await s.post(publishJson(a, 1));
      if (r.status === 201) accepted += 1;
      else {
        assert.equal(r.status, 429);
        assert.match(r.body.message, /new accounts a minute/);
        refusedAccounts.push(a);
      }
    }
    assert.equal(accepted, 3, 'exactly the new-account allowance got in');
    assert.equal(refusedAccounts.length, 7);

    // A refused first publish left the account unknown: the gate asks the
    // index that only accepted publishes build, so a refusal cannot make an
    // account look like one the log already holds.
    for (const a of refusedAccounts) assert.equal(s.log.hasLabel(a.label), false);

    // An account the log holds publishes again without touching the gate,
    // however many times, with the allowance exhausted.
    const known = account('new-0');
    for (let v = 2; v <= 6; v++) {
      assert.equal((await s.post(publishJson(known, v))).status, 201, `v${v} from a known account`);
    }

  } finally {
    await s.stop();
  }

  // A publish that fails after the tokens are taken gives them back — the
  // new-account token and the address token both. One of each in the
  // allowance; the first fresh account's write fails; the next fresh
  // account is accepted — which is only possible if both refunds happened.
  const s2 = await start({ newAccountsPerMinute: 1, publishPerMinute: 1, publishPerMinuteTotal: 1000 });
  try {
    const realPublish = s2.log.publish.bind(s2.log);
    s2.log.publish = () => {
      throw new Error('disk gone');
    };
    const doomed = account('doomed');
    assert.equal((await s2.post(publishJson(doomed, 1))).status, 500, 'the write failed');
    assert.equal(s2.log.hasLabel(doomed.label), false, 'nothing was written');
    s2.log.publish = realPublish;
    assert.equal((await s2.post(publishJson(account('next'), 1))).status, 201,
      'the tokens the failed write took were given back');
    const after = await s2.post(publishJson(account('after'), 1));
    assert.equal(after.status, 429, 'and only those — each allowance is one');
    assert.match(after.body.message, /from one address/, 'the address gate is the first of the two to say so');
  } finally {
    await s2.stop();
  }
});

test('6. below the free-space floor the log pauses publishing and says so', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'z-kt-floor-'));
  let free = 10 * 1024 * 1024; // what the fake filesystem reports
  const s = await start(
    {
      minFreeBytes: 1024 * 1024,
      statfs: () => ({ bavail: BigInt(free / 4096), bsize: BigInt(4096) }),
      publishPerMinute: 1000,
      publishPerMinuteTotal: 1000,
    },
    { store: new FileStore(path.join(dir, 'entries.jsonl')) }
  );
  try {
    const a = account('floor');
    assert.equal((await s.post(publishJson(a, 1))).status, 201, 'room to write');
    const h1 = (await s.get('/health')).body;
    assert.equal(h1.full, false);
    assert.equal(h1.diskFreeBytes, free);
    assert.ok(h1.diskBytes > 0, 'the file has a size and /health reports it');
    assert.equal(h1.diskBytes, fs.statSync(path.join(dir, 'entries.jsonl')).size);

    free = 512 * 1024; // the disk fills
    const r = await s.post(publishJson(a, 2));
    assert.equal(r.status, 503, 'refused before anything is written, not 500 halfway through');
    assert.equal(r.body.error, 'log_full');
    assert.equal(s.log.size, 1, 'nothing was appended');
    // Reads carry on: a full log is still a log.
    assert.equal((await s.get('/kt/v1/sth')).status, 200);
    assert.equal((await s.get(`/kt/v1/lookup/${a.label.toString('hex')}`)).status, 200);
    const h2 = (await s.get('/health')).body;
    assert.equal(h2.full, true, 'and /health says so');
    assert.equal(h2.diskFreeBytes, free);

    free = 10 * 1024 * 1024; // the disk is grown
    assert.equal((await s.post(publishJson(a, 2))).status, 201, 'and publishing resumes on its own');
  } finally {
    await s.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('7. the log accepts values only up to its own cap, under the protocol maximum', async () => {
  const s = await start({ maxValueBytes: 2048, publishPerMinute: 1000, publishPerMinuteTotal: 1000 });
  try {
    const a = account('big');
    // Well under the protocol's 256 KiB, over this log's 2 KiB.
    const r = await s.post(publishJson(a, 1, 'x'.repeat(4096)));
    assert.equal(r.status, 413);
    assert.equal(r.body.error, 'too_large');
    assert.match(r.body.message, /2048/);
    assert.equal(s.log.size, 0);
    assert.equal((await s.post(publishJson(a, 1, 'x'.repeat(1024)))).status, 201);
  } finally {
    await s.stop();
  }
  // A cap above the protocol's maximum is a configuration error, not a wider
  // log: readers are only obliged to open 256 KiB.
  assert.throws(
    () => createServer({ log: new KtLog({ store: new MemoryStore(), signingKey: logKey }), maxValueBytes: MAX_VALUE_BYTES + 1 }),
    /maxValueBytes/
  );
});

test('8. the address gate is spent only by a publish that happens', async () => {
  // The shipped shape: no client-address header, so one address for all.
  const s = await start({ publishPerMinute: 30, publishPerMinuteTotal: 1000 });
  try {
    for (let i = 0; i < 30; i++) {
      const r = await fetch(`${s.base}/kt/v1/publish`, { method: 'POST', body: 'x' });
      assert.equal(r.status, 400);
    }
    assert.equal((await s.post(publishJson(account('genuine'), 1))).status, 201,
      'thirty junk requests did not spend the address the genuine one shares');
    // A well-formed request with a bad signature is junk too.
    const bad = publishJson(account('forger'), 1);
    bad.sig = Buffer.alloc(64, 7).toString('base64');
    for (let i = 0; i < 30; i++) assert.equal((await s.post(bad)).status, 403);
    assert.equal((await s.post(publishJson(account('genuine-2'), 1))).status, 201);
  } finally {
    await s.stop();
  }
  // Signed and refused is not a publish either. Four accepted publishes
  // fill this address; the refusals in between — an account past its day,
  // five minted accounts past the new-account gate — leave it alone, and
  // the FIFTH accepted one is what the address refuses. Every gate below
  // the address is charged after it, so a refusal there gives the address
  // its token back; the count the address ends on is the count of publishes
  // that happened, exactly.
  const r = await start({ publishPerMinute: 4, publishPerMinuteTotal: 1000, newAccountsPerMinute: 2, publishPerAccountPerDay: 2 });
  try {
    const a = account('first');
    const b = account('second');
    assert.equal((await r.post(publishJson(a, 1))).status, 201, 'one');
    assert.equal((await r.post(publishJson(b, 1))).status, 201, 'two — and the new-account gate is now spent');
    assert.equal((await r.post(publishJson(a, 2))).status, 201, 'three');
    const ceiling = await r.post(publishJson(a, 3));
    assert.equal(ceiling.status, 429);
    assert.match(ceiling.body.message, /a day for one account/, "the account's own ceiling, and the address token goes back");
    for (let i = 0; i < 5; i++) {
      const refused = await r.post(publishJson(account(`minted-${i}`), 1));
      assert.equal(refused.status, 429);
      assert.match(refused.body.message, /new accounts/, 'the new-account gate, and the address token goes back');
    }
    assert.equal((await r.post(publishJson(b, 2))).status, 201, 'four: six refusals spent nothing');
    const fifth = await r.post(publishJson(b, 3));
    assert.equal(fifth.status, 429);
    assert.match(fifth.body.message, /from one address/, 'the address gate, spent by exactly the four publishes that happened');
    assert.equal(r.log.size, 4);
  } finally {
    await r.stop();
  }
  // Nor the total gate, which everybody shares by construction: moving only
  // the address gate would have left this one as the same switch at two
  // requests a second. Junk at the total's rate, then a genuine publish.
  const t = await start({ publishPerMinute: 1000, publishPerMinuteTotal: 5 });
  try {
    for (let i = 0; i < 50; i++) await fetch(`${t.base}/kt/v1/publish`, { method: 'POST', body: 'x' });
    assert.equal((await t.post(publishJson(account('after-junk'), 1))).status, 201, 'fifty junk requests spent nothing of the total');
    // And five publishes that happened spend it, junk or no junk in between.
    for (let i = 1; i < 5; i++) assert.equal((await t.post(publishJson(account(`filler-${i}`), 1))).status, 201);
    for (let i = 0; i < 50; i++) await fetch(`${t.base}/kt/v1/publish`, { method: 'POST', body: 'x' });
    const sixth = await t.post(publishJson(account('sixth'), 1));
    assert.equal(sixth.status, 429);
    assert.match(sixth.body.message, /in total/);
    assert.equal(t.log.size, 5);
  } finally {
    await t.stop();
  }
});

test('9. what a request that publishes nothing can cost is bounded: bodies being read at once', async () => {
  // No gate counts requests any more, so the cost of junk has to be bounded
  // some other way. A body is up to MAX_BODY in memory while it arrives, and
  // the sender decides how slowly: a thousand POSTs that never finish would
  // be a thousand buffers. Two may be in flight here; a third is told 503
  // busy at once, before anything is read; and the moment one finishes —
  // as junk, refused — the slot is free again. A rate would have been a
  // switch (criterion 8); a bound on concurrency is spent only by sockets
  // held open, which a request that finishes never is.
  const net = require('node:net');
  const s = await start({ maxPublishInFlight: 2 });
  try {
    const port = Number(new URL(s.base).port);
    const open = (bytes) =>
      new Promise((resolve, reject) => {
        const sock = net.connect(port, '127.0.0.1', () => {
          sock.write(`POST /kt/v1/publish HTTP/1.1\r\nhost: x\r\ncontent-length: ${bytes}\r\ncontent-type: application/json\r\n\r\n{`);
          resolve(sock);
        });
        sock.on('error', reject);
      });
    const finish = (sock) =>
      new Promise((resolve) => {
        let text = '';
        sock.on('data', (d) => {
          text += d.toString();
          if (/\r\n\r\n/.test(text)) {
            sock.destroy();
            resolve(Number(text.match(/^HTTP\/1\.1 (\d+)/)[1]));
          }
        });
        sock.end('x'.repeat(9)); // completes the declared length; not JSON
      });
    // Two bodies, each announced as ten bytes and one byte sent.
    const a = await open(10);
    const b = await open(10);
    await new Promise((r) => setTimeout(r, 100));
    const third = await s.post(publishJson(account('third'), 1));
    assert.equal(third.status, 503, 'a third body is not read while two are being read');
    assert.equal(third.body.error, 'busy');
    // A read is not what this bounds.
    assert.equal((await s.get('/kt/v1/sth')).status, 200);
    // The two finish — as junk, so as 400s — and the slots are free.
    assert.equal(await finish(a), 400);
    assert.equal(await finish(b), 400);
    assert.equal((await s.post(publishJson(account('after'), 1))).status, 201, 'the slot a finished request held is free, whatever it was');
  } finally {
    await s.stop();
  }
  // A body that never finishes is let go of by the request timeout, and
  // its slot with it: one slot, one socket that sends a byte and stops.
  const t = await start({ maxPublishInFlight: 1, requestTimeoutMs: 400 });
  try {
    const port = Number(new URL(t.base).port);
    const held = await new Promise((resolve, reject) => {
      const sock = net.connect(port, '127.0.0.1', () => {
        sock.write('POST /kt/v1/publish HTTP/1.1\r\nhost: x\r\ncontent-length: 10\r\n\r\n{');
        resolve(sock);
      });
      sock.on('error', reject);
    });
    held.on('error', () => {});
    await new Promise((r) => setTimeout(r, 100));
    assert.equal((await t.post(publishJson(account('waiting'), 1))).status, 503, 'the one slot is held');
    await new Promise((r) => setTimeout(r, 900));
    assert.equal((await t.post(publishJson(account('waiting'), 1))).status, 201, 'and given up on, so the slot is free without the sender doing anything');
    held.destroy();
  } finally {
    await t.stop();
  }
});
