'use strict';
// A key-transparency log as its operator can run it, for the app's
// transparency-client tests (app/test/kt_replay_absence_test.dart). Not a
// test itself: the real kt/ code, served on loopback by server.js's
// createServer, with two things only its operator has a hand on, each a line
// on stdin:
//
//   clock <ms>        the log's clock — what it stamps entries with and signs
//                     heads at — from now on. A head is re-signed as log.js
//                     re-signs one, when the last is `resignMs` (ten minutes)
//                     old by this clock: moved a little at a time, an honest
//                     log goes through days of re-signing with no publish;
//                     not moved, it goes on serving the one head it signed,
//                     however late the reader's own clock says it is. Until
//                     the first such line, the clock is the machine's;
//   drop <label hex>  the label taken out of the map, as its operator can
//                     take it out. The log tree and the label's history are
//                     left as they are, and so is the head already signed: the
//                     next publish grows the log by one real entry, under a
//                     head whose map no longer holds the label;
//   back <label hex>  the same, with the label's map leaf moved back to its
//                     previous entry instead.
//
// Each line is answered "ok <line>" on stdout once it has taken effect, or
// "error <line>: <why>". Env: KT_SEED (64 hex), KT_PORT (0 for any). Prints
// "READY <port>" once it serves. The publish gates are open: they are not
// what is tested.
const readline = require('readline');
const { KtLog, MemoryStore, privateKeyFromSeed } = require('../lib/log.js');
const { SparseMerkleMap } = require('../lib/smt.js');
const { createServer } = require('../server.js');

let clock = null;
const now = () => (clock === null ? Date.now() : clock);

const seed = Buffer.from(process.env.KT_SEED, 'hex');
const log = new KtLog({ store: new MemoryStore(), signingKey: privateKeyFromSeed(seed), now });

/** The map rebuilt, every label's leaf as [leafFor] gives it, or left out where it gives null. */
function remap(leafFor) {
  const next = new SparseMerkleMap();
  for (const [hex, leaf] of log.map.values) {
    const to = leafFor(hex, leaf);
    if (to) next.set(Buffer.from(hex, 'hex'), to.index, to.version);
  }
  log.map = next;
}

function apply(line) {
  const [cmd, arg] = line.trim().split(/\s+/);
  if (cmd === 'clock') {
    const ms = Number(arg);
    if (!Number.isInteger(ms) || ms < 0) throw new Error('a clock is whole milliseconds');
    clock = ms;
    return;
  }
  const label = String(arg || '').toLowerCase();
  if (!log.map.values.has(label)) throw new Error('the map holds no such label');
  if (cmd === 'drop') {
    remap((hex, leaf) => (hex === label ? null : leaf));
    return;
  }
  if (cmd === 'back') {
    const indexes = log.byLabel.get(label) || [];
    if (indexes.length < 2) throw new Error('the label has no earlier entry');
    const prev = log.entries[indexes[indexes.length - 2]];
    remap((hex, leaf) => (hex === label ? { index: prev.index, version: prev.version } : leaf));
    return;
  }
  throw new Error(`not a command: ${cmd}`);
}

const { httpServer } = createServer({
  log,
  now,
  publishPerMinute: 1e9,
  publishPerMinuteTotal: 1e9,
  publishPerAccountPerDay: 1e9,
  newAccountsPerMinute: 1e9,
  newAccountsPerAddressPerMinute: 1e9,
});
httpServer.listen(Number(process.env.KT_PORT || 0), '127.0.0.1', () => {
  readline.createInterface({ input: process.stdin }).on('line', (line) => {
    try {
      apply(line);
      console.log(`ok ${line.trim()}`);
    } catch (e) {
      console.log(`error ${line.trim()}: ${e.message}`);
    }
  });
  console.log(`READY ${httpServer.address().port}`);
});
