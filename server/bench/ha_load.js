#!/usr/bin/env node
// The relay under sustained load as several instances sharing one store —
// the shape the public deployment runs (render.ha.yaml: two instances, one
// Key Value) and the one no bench measured. bench/latency.js is one process,
// one coordinator, every delivery local; the numbers PERFORMANCE.md quotes
// from it say nothing about what a delivery costs when it has to cross
// instances over the store's pub/sub, what the store's memory does under a
// backlog, or whether /health keeps answering while all of that is going on.
//
// This starts a private redis-server on a free port (RAM only, as the
// deployment runs it), N relay instances against it, and C devices spread
// round-robin across the instances. A device is two sockets, as it is in the
// app since 16.1: an authenticated one that owns a mailbox and an anonymous
// one it sends sealed envelopes on (§12.1). For T seconds every device sends
// at a steady rate to a device whose mailbox is on a DIFFERENT instance —
// cross-instance delivery is the point — and a share of its sends go to
// mailboxes nobody holds open, so the store carries a growing backlog at the
// same time. Every live envelope is acknowledged when it lands, as §12.5
// requires, so the drain path is paid per envelope too. A refused send is not
// retried: the device simply sends its next envelope on its own timer.
//
// Measured: offered, accepted and delivered rates; end-to-end latency from
// `send` to the recipient's `msg` frame (one clock, in-process); refusals by
// kind, and by what they were addressed to; what the store holds
// (`used_memory`) before, at peak and after; the relay processes' RSS and CPU;
// and /health's own latency, sampled twice a second throughout, because a
// relay that delivers but cannot answer its health check is one the platform
// will restart.
//
// Two shapes for the mailbox-creation gate (25.3), off by default:
//   --flood R          one more anonymous socket, on the last instance, sends
//                      R envelopes a second to fresh routing ids nobody holds —
//                      the R22 flood, which spends the creation allowance —
//                      starting --flood-after seconds in (default 0), so the
//                      devices' own mailboxes can exist before it begins;
//   --restart-after S  S seconds in, instance 0 is replaced by a fresh one (a
//                      new process would have no `seen` either) and its devices
//                      reconnect to it, as they would to a redeployed instance;
//   --align-minute     start just after the store's minute rolls over, so a
//                      run of under a minute sits inside one shared-gate window.
// Refusals are then reported by destination — a live contact ("peer"), a
// mailbox that already holds mail ("offline"), a flood target ("flood") — and
// before and after the restart.
//
// A measurement, not a test. Run it deliberately:
//
//     node bench/ha_load.js --instances 2 --clients 200 --seconds 60
//     node bench/ha_load.js --instances 3 --clients 200 --seconds 60 --offline 0.5
//     node bench/ha_load.js --instances 2 --clients 200 --seconds 60 --fork
//     NEW_MAILBOX_SHARED=on node bench/ha_load.js --instances 2 --clients 100 \
//         --seconds 40 --flood 20 --restart-after 15 --align-minute
//
// By default the instances run in THIS process, the way ha.test.js starts
// them — one event loop for every instance and the load generator, so the
// tail latency is the whole rig's and the figures are pessimistic. `--fork`
// runs each instance as its own process, which is what a deployment is and
// the only way to attribute RSS and CPU to an instance; on a two-core box the
// processes then compete for cores instead of for one loop. Say which was run
// beside any number taken from here. Prints a table and one `HA_LOAD {...}`
// JSON line; `--json` prints only the line. The redis-server it starts is
// killed on every way out — an error, SIGINT, SIGTERM — and its pid is printed
// to stderr first (`HA_LOAD_REDIS_PID`) so a caller can reap it after SIGKILL.
'use strict';

const crypto = require('crypto');
const http = require('http');
const net = require('net');
const { spawn, fork } = require('child_process');
const WebSocket = require('ws');

// The bound form (PROTOCOL §12.1): the relay's authority — what was dialled,
// as the Host header says it — under the signature with the nonce.
const AUTH_CONTEXT = Buffer.from('z-relay-auth-v2:', 'utf8');
const authority = (ws) => Buffer.from(new URL(ws.url).host.toLowerCase().replace(/:(80|443)$/, ''), 'utf8');

// ---------------------------------------------------------------------------
// Whatever this process started is stopped however it ends.
// ---------------------------------------------------------------------------
const REAP = new Set(); // child processes to kill on the way out
function reapAll() {
  for (const p of REAP) {
    try {
      p.kill('SIGKILL');
    } catch {}
  }
  REAP.clear();
}
process.on('exit', reapAll);
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    reapAll();
    process.exit(sig === 'SIGINT' ? 130 : 143);
  });
}

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------
const FLAGS = ['fork', 'json', 'child', 'align-minute'];
function parseArgs(argv) {
  const o = {
    instances: 2,
    clients: 200,
    seconds: 60,
    rate: 5, // sends per second per device, well under RATE_PER_SEC (80)
    offline: 0.1, // share of sends addressed to mailboxes nobody holds open
    bucket: 1024, // the sealed-sender bucket (§8) the envelopes are sized to
    maxmemory: '', // e.g. 256mb — the store's own limit, noeviction, as deployed
    flood: 0, // envelopes a second to fresh routing ids, from one more socket
    'flood-after': 0, // seconds into the load before the flood starts
    'restart-after': 0, // seconds in: replace instance 0 with a fresh one
    fork: false,
    json: false,
    child: false,
    'align-minute': false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const key = a.startsWith('--') ? a.slice(2) : null;
    if (key === null) throw new Error(`unexpected argument ${a}`);
    if (FLAGS.includes(key)) {
      o[key] = true;
      continue;
    }
    if (!(key in o)) throw new Error(`unknown option --${key}`);
    const v = argv[++i];
    if (v === undefined) throw new Error(`--${key} needs a value`);
    o[key] = key === 'maxmemory' ? v : Number(v);
    if (key !== 'maxmemory' && !Number.isFinite(o[key])) throw new Error(`--${key}: not a number: ${v}`);
  }
  if (o.instances < 1) throw new Error('--instances must be at least 1');
  if (o.clients < 2 || o.clients < o.instances) throw new Error('--clients must be at least 2 and at least --instances');
  if (o.offline < 0 || o.offline >= 1) throw new Error('--offline is a share of sends, 0 ≤ share < 1');
  if (o['restart-after'] && (o.fork || o.instances < 2)) throw new Error('--restart-after needs two or more in-process instances');
  if (o['restart-after'] && o['restart-after'] >= o.seconds) throw new Error('--restart-after must fall inside --seconds');
  return o;
}

// The relay logs a line per authentication; two hundred of them would bury
// the table. Set before server.js is required, since CFG reads it then.
if (process.env.LOG_LEVEL === undefined) process.env.LOG_LEVEL = 'silent';
// /metrics needs a bearer token now (default-404, P1-14); set one before
// server.js is required so every instance (in-process and forked, which
// inherits this env) accepts the scrapes below, and send it on httpGet.
if (process.env.METRICS_TOKEN === undefined) process.env.METRICS_TOKEN = 'z-bench-metrics-token';

// ---------------------------------------------------------------------------
// What a sealed envelope of a given bucket is on the wire: "zs1." and the
// base64url of ephPub(32) || nonce(12) || bucket || mac(16) (PROTOCOL §8).
// The 1 024 bucket is 1 450 characters, the size latency.js has always used.
// ---------------------------------------------------------------------------
function wireChars(bucket) {
  const n = bucket + 60;
  const tail = [0, 2, 3][n % 3];
  return 4 + Math.floor(n / 3) * 4 + tail;
}

function sealedPayload(bucket) {
  const chars = wireChars(bucket) - 4;
  // The relay sees only the prefix and the length, so random content will do.
  return 'zs1.' + crypto.randomBytes(Math.ceil((chars * 3) / 4) + 3).toString('base64url').slice(0, chars);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function makeIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const rawPub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  return { privateKey, rawPub, rid: crypto.createHash('sha256').update(rawPub).digest('base64url') };
}

function freePort() {
  return new Promise((res, rej) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const p = s.address().port;
      s.close(() => res(p));
    });
    s.on('error', rej);
  });
}

/** Waits until something accepts TCP connections on the port (the store booting). */
async function waitForPort(port, ms = 5000) {
  const deadline = Date.now() + ms;
  for (;;) {
    const ok = await new Promise((resolve) => {
      const s = net.connect(port, '127.0.0.1');
      s.once('connect', () => (s.destroy(), resolve(true)));
      s.once('error', () => resolve(false));
    });
    if (ok) return;
    if (Date.now() > deadline) throw new Error(`nothing listening on ${port} after ${ms} ms`);
    await sleep(25);
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function percentile(sorted, p) {
  if (sorted.length === 0) return NaN;
  return sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
}

function summarize(values) {
  const s = values.slice().sort((a, b) => a - b);
  return {
    n: s.length,
    p50: percentile(s, 50),
    p95: percentile(s, 95),
    p99: percentile(s, 99),
    max: s.length ? s[s.length - 1] : NaN,
  };
}

function httpGet(port, p) {
  return new Promise((resolve, reject) => {
    const t0 = process.hrtime.bigint();
    http
      .get({ host: '127.0.0.1', port, path: p, headers: { authorization: `Bearer ${process.env.METRICS_TOKEN}` } }, (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => resolve({ status: res.statusCode, body, ms: Number(process.hrtime.bigint() - t0) / 1e6 }));
      })
      .on('error', reject);
  });
}

function metric(body, name) {
  const m = body.match(new RegExp(`^${name} (\\d+)$`, 'm'));
  return m ? Number(m[1]) : 0;
}

const METRIC_NAMES = [
  'z_enqueued_total',
  'z_delivered_live_total',
  'z_cross_instance_total',
  'z_acked_total',
  'z_ack_miss_total',
  'z_refused_total',
  'z_store_full_total',
  'z_new_mailbox_refused_total',
  'z_new_mailbox_shared_fallback_total',
  'z_send_internal_error_total',
  'z_reflushed_total',
  'z_body_missing_total',
  'z_presence_refresh_failed_total',
];

/** What a send's id says it was addressed to. */
function destinationOf(id) {
  if (id.startsWith('f')) return 'flood';
  if (id.startsWith('o')) return 'offline';
  return 'peer';
}

// ---------------------------------------------------------------------------
// A device: one authenticated socket (the mailbox) and one anonymous socket
// (the sender), the way the app holds them.
// ---------------------------------------------------------------------------
class Socket {
  constructor(port, onFrame) {
    this.ws = new WebSocket(`ws://127.0.0.1:${port}`);
    this.ws.on('error', () => {});
    this.pending = [];
    this.waiters = [];
    this.ws.on('message', (d) => {
      let f;
      try {
        f = JSON.parse(d.toString());
      } catch {
        return;
      }
      if (onFrame(f)) return;
      const i = this.waiters.findIndex((w) => w.pred(f));
      if (i !== -1) this.waiters.splice(i, 1)[0].resolve(f);
      else this.pending.push(f);
    });
  }
  get isOpen() {
    return this.ws.readyState === WebSocket.OPEN;
  }
  next(pred, timeoutMs = 10000) {
    const i = this.pending.findIndex(pred);
    if (i !== -1) return Promise.resolve(this.pending.splice(i, 1)[0]);
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('timeout waiting for a frame')), timeoutMs);
      this.waiters.push({ pred, resolve: (f) => (clearTimeout(t), resolve(f)) });
    });
  }
  send(o) {
    this.ws.send(JSON.stringify(o));
  }
  async open() {
    await new Promise((res, rej) => {
      this.ws.once('open', res);
      this.ws.once('error', rej);
    });
    return this.next((f) => f.t === 'challenge');
  }
  async auth(identity) {
    const ch = await this.open();
    const sig = crypto.sign(null, Buffer.concat([AUTH_CONTEXT, authority(this.ws), Buffer.from(ch.nonce, 'base64')]), identity.privateKey);
    this.send({ t: 'auth', v: 2, pub: identity.rawPub.toString('base64'), sig: sig.toString('base64') });
    await this.next((f) => f.t === 'ready');
  }
  close() {
    try {
      this.ws.terminate();
    } catch {}
  }
}

// ---------------------------------------------------------------------------
// Instances: in this process (default) or one process each (--fork)
// ---------------------------------------------------------------------------
async function startOneInProcess(url, id) {
  const { createServer, RedisCoordinator } = require('../server.js');
  const coordinator = new RedisCoordinator(url, id);
  const srv = createServer({ coordinator, pushSender: null });
  const port = await freePort();
  await new Promise((r) => srv.httpServer.listen(port, '127.0.0.1', r));
  return {
    id,
    port,
    // One process, so one RSS and one CPU figure: reported once, under
    // `process`, and attributed to nobody in particular.
    stat: async () => null,
    stop: async () => {
      for (const ws of srv.wss.clients) ws.terminate();
      srv.httpServer.close();
      await coordinator.close();
    },
  };
}

async function startOneForked(url, id) {
  const child = fork(__filename, ['--child'], {
    env: { ...process.env, REDIS_URL: url, INSTANCE_ID: id, LOG_LEVEL: 'silent' },
    stdio: ['ignore', 'ignore', 'inherit', 'ipc'],
  });
  REAP.add(child);
  const port = await new Promise((resolve, reject) => {
    child.once('message', (m) => (m && m.port ? resolve(m.port) : reject(new Error('child sent no port'))));
    child.once('exit', (code) => reject(new Error(`instance ${id} exited with ${code} before listening`)));
  });
  return {
    id,
    port,
    stat: () =>
      new Promise((resolve) => {
        const onMsg = (m) => {
          if (m && m.op === 'stat') {
            child.off('message', onMsg);
            resolve(m);
          }
        };
        child.on('message', onMsg);
        child.send({ op: 'stat' });
      }),
    stop: async () => {
      try {
        child.send({ op: 'quit' });
      } catch {}
      await new Promise((r) => {
        const t = setTimeout(() => (child.kill('SIGKILL'), r()), 2000);
        child.once('exit', () => (clearTimeout(t), r()));
      });
      REAP.delete(child);
    },
  };
}

/** The forked instance: one relay, one coordinator, answering stat requests over IPC. */
async function childMain() {
  const { createServer, RedisCoordinator, CFG } = require('../server.js');
  // A parent that dies — however it dies — closes the IPC channel; an
  // instance left listening on its own would hold the store open.
  process.on('disconnect', () => process.exit(0));
  const coordinator = new RedisCoordinator(CFG.redisUrl, CFG.instanceId);
  const srv = createServer({ coordinator, pushSender: null });
  await new Promise((r) => srv.httpServer.listen(0, '127.0.0.1', r));
  const cpu0 = process.cpuUsage();
  process.on('message', async (m) => {
    if (!m) return;
    if (m.op === 'stat') {
      const mem = process.memoryUsage();
      const cpu = process.cpuUsage(cpu0);
      process.send({ op: 'stat', rss: mem.rss, heapUsed: mem.heapUsed, cpuMs: (cpu.user + cpu.system) / 1000 });
    } else if (m.op === 'quit') {
      for (const ws of srv.wss.clients) ws.terminate();
      srv.httpServer.close();
      await coordinator.close();
      process.exit(0);
    }
  });
  process.send({ port: srv.httpServer.address().port });
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------
async function run(o) {
  const IORedis = require('ioredis');
  const { CFG } = require('../server.js');
  const redisPort = await freePort();
  const args = ['--port', String(redisPort), '--save', '', '--appendonly', 'no', '--bind', '127.0.0.1'];
  if (o.maxmemory) args.push('--maxmemory', o.maxmemory, '--maxmemory-policy', 'noeviction');
  const redis = spawn('redis-server', args, { stdio: 'ignore' });
  REAP.add(redis);
  process.stderr.write(`HA_LOAD_REDIS_PID ${redis.pid}\n`);
  const url = `redis://127.0.0.1:${redisPort}`;
  const instances = [];
  const devices = [];
  const extraSockets = [];
  let raw = null;
  try {
    await waitForPort(redisPort);
    raw = new IORedis(url);
    const usedMemory = async () => Number(/used_memory:(\d+)/.exec(await raw.info('memory'))[1]);
    const commands = async () => Number(/total_commands_processed:(\d+)/.exec(await raw.info('stats'))[1]);
    const startOne = (id) => (o.fork ? startOneForked(url, id) : startOneInProcess(url, id));
    for (let i = 0; i < o.instances; i++) instances.push(await startOne(`inst${i}`));

    // Devices. Device c has both its sockets on instance c mod N; its live
    // peer is the next device whose mailbox is on another instance (any
    // device, when there is only one). Offline mailboxes are identities that
    // never connect — the backlog case.
    const payload = sealedPayload(o.bucket);
    const sentAt = new Map(); // id -> hrtime, for live sends only
    const latencies = [];
    let delivered = 0;
    let dupes = 0;
    const refusals = new Map(); // code -> count
    let restartedAt = null; // Date.now() of the restart, once it has happened
    const refusalsBy = {
      before: { peer: 0, offline: 0, flood: 0 },
      after: { peer: 0, offline: 0, flood: 0 },
    };
    let accepted = 0;
    let offlineAccepted = 0;
    let floodAccepted = 0;
    let skipped = 0; // sends not made: the device's socket was reconnecting
    const landed = (f) => {
      const t0 = sentAt.get(f.id);
      if (t0 !== undefined) {
        latencies.push(Number(process.hrtime.bigint() - t0) / 1e6);
        sentAt.delete(f.id);
        delivered += 1;
      } else {
        dupes += 1; // at-least-once: a re-flush handed it over twice
      }
    };
    const onSenderFrame = (f) => {
      if (f.t === 'sent') {
        const to = destinationOf(f.id);
        if (to === 'offline') offlineAccepted += 1;
        else if (to === 'flood') floodAccepted += 1;
        else accepted += 1;
        return true;
      }
      if (f.t === 'error') {
        refusals.set(f.code, (refusals.get(f.code) || 0) + 1);
        if (f.id) {
          refusalsBy[restartedAt === null ? 'before' : 'after'][destinationOf(f.id)] += 1;
          sentAt.delete(f.id); // refused, so never delivered: not a loss
        }
        return true;
      }
      return false;
    };
    /** Opens (or reopens) a device's two sockets on an instance. */
    const connect = async (d, inst) => {
      const recv = new Socket(inst.port, (f) => {
        if (f.t !== 'msg') return false;
        landed(f);
        recv.send({ t: 'recv', id: f.id }); // sealed: acknowledged by id alone (§12.5)
        return true;
      });
      await recv.auth(d.identity);
      const send = new Socket(inst.port, onSenderFrame);
      await send.open();
      d.inst = inst;
      d.recv = recv;
      d.send = send;
    };
    for (let c = 0; c < o.clients; c++) {
      const d = { c, identity: makeIdentity(), seq: 0 };
      await connect(d, instances[c % instances.length]);
      devices.push(d);
    }
    for (const d of devices) {
      let t = (d.c + 1) % devices.length;
      if (o.instances > 1) while (devices[t].inst === d.inst) t = (t + 1) % devices.length;
      d.peer = devices[t];
    }
    const offlineCount = o.offline > 0 ? Math.max(1, Math.round(o.clients * o.offline)) : 0;
    const offline = Array.from({ length: offlineCount }, () => makeIdentity().rid);
    let flooder = null;
    if (o.flood > 0) {
      flooder = new Socket(instances[instances.length - 1].port, onSenderFrame);
      await flooder.open();
      extraSockets.push(flooder);
    }

    // Presence written, both sockets up, nothing in flight: the baseline. With
    // --align-minute, wait for the store's minute to roll over (on loopback the
    // store's clock is this machine's) so the run sits inside one window.
    await sleep(200);
    if (o['align-minute']) {
      const [s] = await raw.time();
      const left = 60 - (Number(s) % 60);
      if (left < 59) await sleep(left * 1000 + 300);
    }
    const startSecond = Number((await raw.time())[0]) % 60;
    const healthSamples = [];
    let healthFailures = 0;
    const loopLag = [];
    const memBefore = await usedMemory();
    const cmdBefore = await commands();
    let memPeak = memBefore;
    let rssPeak = process.memoryUsage().rss;
    const cpu0 = process.cpuUsage();

    // Steady load: every device on its own timer at the offered rate.
    let offered = 0;
    let offlineOffered = 0;
    let floodOffered = 0;
    const start = Date.now();
    const timers = devices.map((d) =>
      setInterval(() => {
        if (!d.send.isOpen) {
          skipped += 1;
          return;
        }
        const s = d.seq++;
        // Every (1/offline)th send goes to a mailbox nobody holds open; the
        // pattern is deterministic so two runs offer the same mix.
        const toOffline = offlineCount > 0 && Math.floor(s * o.offline) !== Math.floor((s + 1) * o.offline);
        if (toOffline) {
          offlineOffered += 1;
          d.send.send({ t: 'send', to: offline[(d.c + s) % offlineCount], id: `o${d.c}-${s}`, payload });
        } else {
          const id = `${d.c}-${s}`;
          sentAt.set(id, process.hrtime.bigint());
          offered += 1;
          d.send.send({ t: 'send', to: d.peer.identity.rid, id, payload });
        }
      }, 1000 / o.rate)
    );
    let floodStart = null;
    if (flooder) {
      let n = 0;
      floodStart = setTimeout(() => {
        timers.push(
          setInterval(() => {
            if (!flooder.isOpen) return;
            floodOffered += 1;
            flooder.send({ t: 'send', to: crypto.randomBytes(32).toString('base64url'), id: `f${n++}`, payload });
          }, 1000 / o.flood)
        );
      }, o['flood-after'] * 1000);
    }

    // Twice a second: one instance's /health, round-robin, timed; the store's
    // memory; this process's RSS; and how late the 500 ms timer itself fired,
    // which is what the event loop looks like from inside.
    let tick = 0;
    let lastTick = process.hrtime.bigint();
    const sampler = setInterval(async () => {
      const now = process.hrtime.bigint();
      loopLag.push(Number(now - lastTick) / 1e6 - 500);
      lastTick = now;
      const inst = instances[tick++ % instances.length];
      try {
        const h = await httpGet(inst.port, '/health');
        if (h.status === 200 && JSON.parse(h.body).ok === true) healthSamples.push(h.ms);
        else healthFailures += 1;
      } catch {
        healthFailures += 1;
      }
      try {
        memPeak = Math.max(memPeak, await usedMemory());
      } catch {}
      rssPeak = Math.max(rssPeak, process.memoryUsage().rss);
    }, 500);

    let reconnectMs = null;
    if (o['restart-after']) {
      await sleep(o['restart-after'] * 1000);
      // Instance 0 goes away and a fresh one takes its place — a new process
      // with a new instance id, its own bucket full and its `seen` empty —
      // and the devices that were on it reconnect, as after a redeploy.
      const t0 = Date.now();
      const old = instances[0];
      const moving = devices.filter((d) => d.inst === old);
      restartedAt = Date.now();
      await old.stop();
      instances[0] = await startOne('inst0-restarted');
      for (const d of moving) {
        d.recv.close();
        d.send.close();
        await connect(d, instances[0]);
      }
      reconnectMs = Date.now() - t0;
      await sleep((o.seconds - o['restart-after']) * 1000 - reconnectMs);
    } else {
      await sleep(o.seconds * 1000);
    }
    if (floodStart) clearTimeout(floodStart);
    timers.forEach(clearInterval);
    // Let the tail drain, then stop sampling.
    await sleep(1000);
    clearInterval(sampler);
    const elapsed = (Date.now() - start - 1000) / 1000;
    const cpu = process.cpuUsage(cpu0);

    const memAfter = await usedMemory();
    const cmdAfter = await commands();
    const rssAfter = process.memoryUsage().rss;
    // The z_* counters are process-wide in server.js, so in-process instances
    // all report the same numbers from /metrics: read once, for all of them.
    // Forked instances each count their own, and the totals are their sum.
    const perInstance = [];
    const totals = {};
    for (const name of METRIC_NAMES) totals[name] = 0;
    for (const [i, inst] of instances.entries()) {
      const stat = await inst.stat();
      // connections/sockets/presenceStale moved from /health to /metrics with
      // P1-14 (/health is liveness only). Read them off the one /metrics
      // scrape below rather than a second endpoint.
      const m = await httpGet(inst.port, '/metrics');
      const row = {
        id: inst.id,
        connections: metric(m.body, 'z_connections'),
        sockets: metric(m.body, 'z_sockets'),
        presenceStale: metric(m.body, 'z_presence_stale'),
      };
      if (o.fork || i === 0) {
        for (const name of METRIC_NAMES) {
          const v = metric(m.body, name);
          totals[name] += v;
          if (o.fork) row[name] = v;
        }
      }
      if (stat) {
        row.rssMB = +(stat.rss / 1048576).toFixed(1);
        row.heapMB = +(stat.heapUsed / 1048576).toFixed(1);
        row.cpuCores = +(stat.cpuMs / 1000 / (elapsed + 1)).toFixed(2);
      }
      perInstance.push(row);
    }

    // What the offline mailboxes hold, so queue growth is a number and not an
    // inference from the store's memory.
    let offlineQueued = 0;
    for (const rid of offline) offlineQueued += await raw.llen(`q:${rid}`);

    const lat = summarize(latencies);
    const health = summarize(healthSamples);
    const lag = summarize(loopLag);
    return {
      label: `local, two cores, loopback, ${o.fork ? 'one process per instance' : 'in-process instances'} sharing one redis-server`,
      instances: o.instances,
      fork: o.fork,
      clients: o.clients,
      sockets: o.clients * 2,
      seconds: o.seconds,
      ratePerDevice: o.rate,
      bucket: o.bucket,
      wireChars: wireChars(o.bucket),
      offlineShare: o.offline,
      offlineMailboxes: offlineCount,
      newMailboxShared: CFG.newMailboxShared,
      newMailboxPerMin: CFG.newMailboxPerMin,
      startSecondOfMinute: startSecond,
      offeredLive: offered,
      acceptedLive: accepted,
      deliveredLive: delivered,
      deliveredPerSec: +(delivered / elapsed).toFixed(0),
      offeredPerSec: +((offered + offlineOffered) / elapsed).toFixed(0),
      lostLive: sentAt.size, // accepted for a live recipient, no `msg` by the end of the tail
      duplicates: dupes,
      skipped,
      offeredOffline: offlineOffered,
      acceptedOffline: offlineAccepted,
      offlineQueued,
      flood: { rate: o.flood, afterSec: o['flood-after'], offered: floodOffered, accepted: floodAccepted },
      restart: o['restart-after'] ? { afterSec: o['restart-after'], reconnectMs } : null,
      refusals: Object.fromEntries(refusals),
      refusalsBy,
      latencyMs: { p50: +lat.p50.toFixed(2), p95: +lat.p95.toFixed(2), p99: +lat.p99.toFixed(2), max: +lat.max.toFixed(2) },
      healthMs: { n: health.n, p50: +health.p50.toFixed(2), p99: +health.p99.toFixed(2), max: +health.max.toFixed(2), failures: healthFailures },
      loopLagMs: { p50: +lag.p50.toFixed(1), p99: +lag.p99.toFixed(1), max: +lag.max.toFixed(1) },
      // The relays' own counters, summed over the instances (forked) or read
      // once (in-process, where they are one set of counters for the process).
      relayMetrics: totals,
      redis: {
        usedMemoryBeforeMB: +(memBefore / 1048576).toFixed(2),
        usedMemoryPeakMB: +(memPeak / 1048576).toFixed(2),
        usedMemoryAfterMB: +(memAfter / 1048576).toFixed(2),
        commandsPerSec: +((cmdAfter - cmdBefore) / (elapsed + 1)).toFixed(0),
      },
      process: {
        rssPeakMB: +(rssPeak / 1048576).toFixed(1),
        rssAfterMB: +(rssAfter / 1048576).toFixed(1),
        cpuCores: +((cpu.user + cpu.system) / 1e6 / (elapsed + 1)).toFixed(2),
        holds: o.fork ? 'the load generator only' : 'the load generator and every instance',
      },
      perInstance,
    };
  } finally {
    // Tear down whatever was started — on success and on any failure alike:
    // sockets, instances, the store.
    for (const d of devices) {
      if (d.recv) d.recv.close();
      if (d.send) d.send.close();
    }
    for (const s of extraSockets) s.close();
    for (const inst of instances) {
      try {
        await inst.stop();
      } catch {}
    }
    if (raw) {
      try {
        await raw.quit();
      } catch {}
    }
    redis.kill('SIGKILL');
    REAP.delete(redis);
  }
}

function printTable(r) {
  const L = [];
  L.push(`${r.label}`);
  L.push(
    `instances ${r.instances}  devices ${r.clients} (${r.sockets} sockets)  ${r.seconds} s at ${r.ratePerDevice}/s per device  ` +
      `envelopes of the ${r.bucket} bucket (${r.wireChars} chars)  offline share ${r.offlineShare} (${r.offlineMailboxes} mailboxes)`
  );
  L.push(
    `mailbox-creation gate: ${r.newMailboxShared ? 'SHARED' : 'per instance'}, NEW_MAILBOX_PER_MIN ${r.newMailboxPerMin}  ` +
      `(load started at second ${r.startSecondOfMinute} of the store's minute)`
  );
  L.push(
    `offered ${r.offeredPerSec}/s  delivered live ${r.deliveredLive} (${r.deliveredPerSec}/s)  lost ${r.lostLive}  duplicates ${r.duplicates}  ` +
      `queued for offline ${r.acceptedOffline} (held at the end: ${r.offlineQueued})`
  );
  L.push(`refusals ${Object.keys(r.refusals).length ? JSON.stringify(r.refusals) : 'none'}`);
  if (r.flood.rate || r.restart) {
    L.push(
      `refusals by destination  before${r.restart ? ' the restart' : ''}: ${JSON.stringify(r.refusalsBy.before)}` +
        (r.restart ? `  after: ${JSON.stringify(r.refusalsBy.after)}  (instance 0 replaced at ${r.restart.afterSec} s, devices back in ${r.restart.reconnectMs} ms; ${r.skipped} sends skipped meanwhile)` : '')
    );
    if (r.flood.rate) L.push(`flood: ${r.flood.rate}/s to fresh routing ids from ${r.flood.afterSec} s in, ${r.flood.offered} offered, ${r.flood.accepted} mailboxes created`);
  }
  L.push(`latency ms: p50 ${r.latencyMs.p50}  p95 ${r.latencyMs.p95}  p99 ${r.latencyMs.p99}  max ${r.latencyMs.max}`);
  L.push(
    `/health ms (${r.healthMs.n} samples): p50 ${r.healthMs.p50}  p99 ${r.healthMs.p99}  max ${r.healthMs.max}  failures ${r.healthMs.failures}   ` +
      `loop lag ms: p50 ${r.loopLagMs.p50}  p99 ${r.loopLagMs.p99}  max ${r.loopLagMs.max}`
  );
  L.push(
    `redis used_memory MB: before ${r.redis.usedMemoryBeforeMB}  peak ${r.redis.usedMemoryPeakMB}  after ${r.redis.usedMemoryAfterMB}   commands/s ${r.redis.commandsPerSec}`
  );
  L.push(`process (${r.process.holds}): rss peak ${r.process.rssPeakMB} MB  after ${r.process.rssAfterMB} MB  cpu ${r.process.cpuCores} cores`);
  const short = (c) => c.replace(/^z_/, '').replace(/_total$/, '');
  L.push(
    `relay counters${r.fork ? ' (summed over the instances)' : ' (one set for the process)'}: ` +
      METRIC_NAMES.map((n) => `${short(n)} ${r.relayMetrics[n]}`).join('  ')
  );
  L.push('');
  const cols = ['id', 'connections', 'sockets', 'presenceStale'];
  if (r.fork) cols.push('z_enqueued_total', 'z_delivered_live_total', 'z_cross_instance_total', 'z_acked_total', 'z_refused_total', 'z_store_full_total', 'z_reflushed_total', 'rssMB', 'heapMB', 'cpuCores');
  L.push(cols.map(short).join('  '));
  for (const row of r.perInstance) L.push(cols.map((c) => String(row[c] ?? '')).join('  '));
  return L.join('\n');
}

if (require.main === module) {
  const o = parseArgs(process.argv.slice(2));
  if (o.child) {
    childMain().catch((e) => {
      console.error(e);
      process.exit(1);
    });
  } else {
    run(o)
      .then((r) => {
        if (!o.json) console.log(printTable(r));
        console.log('HA_LOAD ' + JSON.stringify(r));
        process.exit(0);
      })
      .catch((e) => {
        console.error(e);
        process.exit(1); // the 'exit' handler reaps what is left
      });
  }
}

module.exports = { run, parseArgs, wireChars };
