#!/usr/bin/env node
'use strict';
/**
 * Mirror (and witness) the key-transparency log from the command line.
 *
 *   node tools/mirror.js --log https://kt.zmessengers.com --pub <base64> --dir ./mirror
 *   node tools/mirror.js ... --witness-seed-env KT_WITNESS_SEED   # co-sign heads
 *   node tools/mirror.js ... --every 300                          # keep going
 *   node tools/mirror.js ... --serve 8086                         # and serve sth.json
 *
 * Every option has an environment variable, so a deployment can carry the
 * whole configuration without a command line (render.kt-witness.yaml):
 * KT_LOG_URL, KT_LOG_PUB, KT_MIRROR_DIR, KT_EVERY, KT_WITNESS_SEED (the seed
 * itself; --witness-seed-env names a different variable), KT_SERVE_PORT
 * (or PORT, which cloud hosts inject).
 *
 * Exit status: 0 the head verified as an extension of the last one (and was
 * written to <dir>/sth.json); 2 the log DIVERGED — it signed a history that
 * does not extend what this mirror saw, or entries that do not hash to its
 * head — and nothing was written; 1 anything else (unreachable, bad
 * arguments, a corrupt mirror directory). With --every, a divergence stops
 * the loop: a witness that keeps following a forked log is not a witness.
 *
 * With --serve the tool is the witness service: it answers GET /sth.json
 * with the last head it verified and co-signed — the URL a client is given
 * as its witness — and GET /health with what it knows. It keeps going
 * (--every defaults to 300), needs a witness key (a served head that nobody
 * co-signed attests nothing), and on a divergence it stops following the
 * log but keeps serving the last head it verified: that head is exactly
 * what a client needs to catch the fork, since the log can no longer
 * produce a consistency proof from it. /health then says so, and stays
 * 200 — a host that restarted an "unhealthy" witness would only make it
 * reload the same head and diverge again.
 *
 * The public key to pin comes from the log's operator out of band (it is also
 * at GET /kt/v1/pub, which is fine for a first look and no good as a pin).
 */

const http = require('http');

const { Mirror, Divergence } = require('../lib/mirror.js');
const { privateKeyFromSeed } = require('../lib/log.js');

function parseArgs(argv, env) {
  const o = {
    log: env.KT_LOG_URL,
    pub: env.KT_LOG_PUB,
    dir: env.KT_MIRROR_DIR,
    every: env.KT_EVERY !== undefined ? Number(env.KT_EVERY) : undefined,
    witnessSeedEnv: env.KT_WITNESS_SEED !== undefined ? 'KT_WITNESS_SEED' : undefined,
    serve: env.KT_SERVE_PORT !== undefined ? Number(env.KT_SERVE_PORT) : env.PORT !== undefined ? Number(env.PORT) : undefined,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => {
      if (i + 1 >= argv.length) throw new Error(`${a} needs a value`);
      return argv[++i];
    };
    if (a === '--log') o.log = next();
    else if (a === '--pub') o.pub = next();
    else if (a === '--dir') o.dir = next();
    else if (a === '--witness-seed-env') o.witnessSeedEnv = next();
    else if (a === '--every') o.every = Number(next());
    else if (a === '--serve') o.serve = Number(next());
    else if (a === '--help' || a === '-h') o.help = true;
    else throw new Error(`unknown argument ${a}`);
  }
  if (o.serve !== undefined && o.every === undefined) o.every = 300;
  if (o.every === undefined) o.every = 0;
  return o;
}

function usage() {
  console.error(
    'usage: node tools/mirror.js --log URL --pub BASE64 --dir DIR [--witness-seed-env NAME] [--every SECONDS] [--serve PORT]\n' +
      '       (or KT_LOG_URL, KT_LOG_PUB, KT_MIRROR_DIR, KT_WITNESS_SEED, KT_EVERY, KT_SERVE_PORT in the environment)'
  );
}

/** The witness service: the last verified, co-signed head, and what the mirror knows. */
function serveWitness(mirror, port, state) {
  const server = http.createServer((req, res) => {
    const url = (req.url || '/').split('?')[0];
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { allow: 'GET, HEAD' });
      res.end();
      return;
    }
    if (url === '/sth.json') {
      let record;
      try {
        record = mirror.record();
      } catch {
        res.writeHead(503, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'no verified head yet' }) + '\n');
        return;
      }
      res.writeHead(200, {
        'content-type': 'application/json',
        'cache-control': 'public, max-age=60',
        'access-control-allow-origin': '*',
      });
      res.end(JSON.stringify(record) + '\n');
      return;
    }
    if (url === '/health') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          ok: !state.diverged,
          size: mirror.head ? mirror.head.size : 0,
          verifiedAt: state.verifiedAt,
          lastSyncAt: state.lastSyncAt,
          lastError: state.lastError,
          diverged: state.diverged,
          log: mirror.logUrl,
        }) + '\n'
      );
      return;
    }
    if (url === '/') {
      res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
      res.end(`Z transparency-log witness for ${mirror.logUrl}. GET /sth.json for the last co-signed head, /health for state.\n`);
      return;
    }
    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found\n');
  });
  return new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(port, '0.0.0.0', () => resolve(server));
  });
}

async function main() {
  let o;
  try {
    o = parseArgs(process.argv.slice(2), process.env);
  } catch (e) {
    console.error(e.message);
    usage();
    return 1;
  }
  if (o.help || !o.log || !o.pub || !o.dir) {
    usage();
    return o.help ? 0 : 1;
  }
  const logPub = Buffer.from(o.pub, 'base64');
  if (logPub.length !== 32) {
    console.error('--pub must be the log\'s 32-byte Ed25519 public key, base64');
    return 1;
  }
  let witnessKey = null;
  if (o.witnessSeedEnv) {
    const hex = (process.env[o.witnessSeedEnv] || '').trim();
    if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
      console.error(`${o.witnessSeedEnv} must hold a 64-hex Ed25519 seed`);
      return 1;
    }
    witnessKey = privateKeyFromSeed(Buffer.from(hex, 'hex'));
  }
  if (!(o.every >= 0)) {
    console.error('--every must be a number of seconds');
    return 1;
  }
  if (o.serve !== undefined && !(Number.isInteger(o.serve) && o.serve >= 0 && o.serve < 65536)) {
    console.error('--serve must be a port');
    return 1;
  }
  if (o.serve !== undefined && !witnessKey) {
    console.error('--serve needs a witness key (KT_WITNESS_SEED, or --witness-seed-env): a served head nobody co-signed attests nothing');
    return 1;
  }

  let mirror;
  try {
    mirror = new Mirror({ dir: o.dir, logUrl: o.log, logPub, witnessKey }).load();
  } catch (e) {
    console.error(`mirror: ${e.message}`);
    return 1;
  }

  const state = { diverged: false, verifiedAt: null, lastSyncAt: null, lastError: null };
  let server = null;
  if (o.serve !== undefined) {
    try {
      server = await serveWitness(mirror, o.serve, state);
    } catch (e) {
      console.error(`mirror: cannot serve: ${e.message}`);
      return 1;
    }
    console.log(`mirror: serving on http://0.0.0.0:${server.address().port} (/sth.json, /health)`);
    const stop = () => {
      server.close(() => process.exit(0));
      setTimeout(() => process.exit(0), 2000).unref();
    };
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
  }

  for (;;) {
    if (!state.diverged) {
      try {
        const r = await mirror.sync();
        state.lastSyncAt = Date.now();
        state.verifiedAt = state.lastSyncAt;
        state.lastError = null;
        console.log(`mirror: verified head of size ${r.to} (was ${r.from}); log root ${r.head.logRoot.toString('base64')}`);
      } catch (e) {
        state.lastSyncAt = Date.now();
        state.lastError = e.message;
        if (e instanceof Divergence) {
          console.error(`mirror: DIVERGENCE — ${e.message}`);
          console.error('mirror: the stored head was kept; the log has signed a history that does not extend it');
          if (!server) return 2;
          state.diverged = true;
          console.error('mirror: still serving the last verified head; no longer following the log');
        } else {
          console.error(`mirror: ${e.message}`);
          if (!o.every) return 1;
        }
      }
    }
    if (!o.every) return 0;
    await new Promise((res) => setTimeout(res, o.every * 1000));
  }
}

main().then(
  (code) => process.exit(code),
  (e) => {
    console.error(e);
    process.exit(1);
  }
);
