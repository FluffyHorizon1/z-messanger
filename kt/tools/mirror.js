#!/usr/bin/env node
'use strict';
/**
 * Mirror (and witness) the key-transparency log from the command line.
 *
 *   node tools/mirror.js --log https://kt.zmessengers.com --pub <base64> --dir ./mirror
 *   node tools/mirror.js ... --witness-seed-env KT_WITNESS_SEED   # co-sign heads
 *   node tools/mirror.js ... --every 300                          # keep going
 *
 * Exit status: 0 the head verified as an extension of the last one (and was
 * written to <dir>/sth.json); 2 the log DIVERGED — it signed a history that
 * does not extend what this mirror saw, or entries that do not hash to its
 * head — and nothing was written; 1 anything else (unreachable, bad
 * arguments, a corrupt mirror directory). With --every, a divergence stops
 * the loop: a witness that keeps following a forked log is not a witness.
 *
 * The public key to pin comes from the log's operator out of band (it is also
 * at GET /kt/v1/pub, which is fine for a first look and no good as a pin).
 */

const { Mirror, Divergence } = require('../lib/mirror.js');
const { privateKeyFromSeed } = require('../lib/log.js');

function parseArgs(argv) {
  const o = { every: 0 };
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
    else if (a === '--help' || a === '-h') o.help = true;
    else throw new Error(`unknown argument ${a}`);
  }
  return o;
}

function usage() {
  console.error('usage: node tools/mirror.js --log URL --pub BASE64 --dir DIR [--witness-seed-env NAME] [--every SECONDS]');
}

async function main() {
  let o;
  try {
    o = parseArgs(process.argv.slice(2));
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

  let mirror;
  try {
    mirror = new Mirror({ dir: o.dir, logUrl: o.log, logPub, witnessKey }).load();
  } catch (e) {
    console.error(`mirror: ${e.message}`);
    return 1;
  }
  for (;;) {
    try {
      const r = await mirror.sync();
      console.log(`mirror: verified head of size ${r.to} (was ${r.from}); log root ${r.head.logRoot.toString('base64')}`);
    } catch (e) {
      if (e instanceof Divergence) {
        console.error(`mirror: DIVERGENCE — ${e.message}`);
        console.error('mirror: the stored head was kept; the log has signed a history that does not extend it');
        return 2;
      }
      console.error(`mirror: ${e.message}`);
      if (!o.every) return 1;
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
