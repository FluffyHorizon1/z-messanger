'use strict';
// A handle log as its operator can run it, for the app's resolver tests
// (app/test/handle_lookup_test.dart). Not a test itself: the real kt/ code,
// served on loopback by server.js's createServer, with
//
//   FILL_LABELS=n      n claims made before it serves, of labels nobody can
//                      name (label i is SHA-256("z-fill:" + i)), each by an
//                      owner key of its own: a log with n handles in it;
//   FILL_VERSIONS=a:v  the first a of them then updated until each is at
//                      version v: a·(v − 1) entries more and not one label
//                      more, the inflation of the signed size anyone holding
//                      owner keys — the operator first — gets for a publish;
//   RULELESS=1         the owner rule taken out, as its operator can take it
//                      out: any entry in the one encoding and signed by the
//                      owner its record names is accepted, whoever held the
//                      label before and at whatever version (1..2^53 − 1, the
//                      wire's bounds). The log a mirror exists to catch.
//
// Env: KT_SEED (64 hex), KT_PORT. Prints "READY <port> <size> <labels>"
// once it serves. The publish gates are open: they are not what is tested.
const crypto = require('crypto');
const h = require('../lib/handles.js');
const { KtLog, MemoryStore, privateKeyFromSeed } = require('../lib/log.js');
const { createServer } = require('../server.js');

if (process.env.RULELESS === '1') {
  // The history half of the rule, gone from the publish path (log.js calls
  // it through the module object) and from `_apply` (`_ownerRule`); the
  // entry's own checks — shape, size, record, signatures — stay.
  h.ownerRuleTransition = (prev, rec) => ({ owner: rec.owner, rc: rec.rc });
  KtLog.prototype._ownerRule = function (prev, entry) {
    const rec = h.checkEntry(entry);
    return { owner: rec.owner, rc: rec.rc };
  };
}

const sha = (s) => crypto.createHash('sha256').update(s).digest();
const seed = Buffer.from(process.env.KT_SEED, 'hex');
const log = new KtLog({ store: new MemoryStore(), signingKey: privateKeyFromSeed(seed), mode: 'handles' });

const labels = Number(process.env.FILL_LABELS || 0);
const [inflated, versions] = (process.env.FILL_VERSIONS || '0:1').split(':').map(Number);
const rc = sha('z-fill-rc');
const owners = [];
for (let i = 0; i < labels; i++) {
  owners.push(privateKeyFromSeed(sha(`z-fill-owner:${i}`)));
  log.publish(h.makeHandlePublish({ label: sha(`z-fill:${i}`), version: 1, ownerKey: owners[i], k: 'claim', pow: 20, rc }));
}
for (let i = 0; i < Math.min(inflated, labels); i++) {
  for (let v = 2; v <= versions; v++) {
    log.publish(h.makeHandlePublish({ label: sha(`z-fill:${i}`), version: v, ownerKey: owners[i], k: 'update', pow: 20, rc }));
  }
}

const { httpServer } = createServer({
  log,
  publishPerMinute: 1e9,
  publishPerMinuteTotal: 1e9,
  publishPerAccountPerDay: 1e9,
  newAccountsPerMinute: 1e9,
  newAccountsPerAddressPerMinute: 1e9,
});
httpServer.listen(Number(process.env.KT_PORT || 0), '127.0.0.1', () => {
  console.log(`READY ${httpServer.address().port} ${log.size} ${log.map.size}`);
});
