#!/usr/bin/env node
'use strict';
/**
 * Generate docs/vectors/kt/*.json — the known answers for the key
 * transparency log (docs/PROTOCOL.md §19), from fixed seeds. Every random
 * value is derived from a string, Ed25519 signing is deterministic, and the
 * clock is fixed, so the output is a pure function of this file and lib/;
 * kt/test/vectors.test.js regenerates and compares (the freeze), and the
 * Dart and Python verifiers consume the files.
 *
 *   node tools/gen_vectors.js            # from kt/
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const { hashLeaf, MerkleLog } = require('../lib/merkle.js');
const { DEPTH, EMPTY, SparseMerkleMap, mapLeafHash } = require('../lib/smt.js');
const {
  KtLog,
  MemoryStore,
  labelFor,
  leafInput,
  leafHashOf,
  sthInput,
  publishInput,
  witnessInput,
  valueKey,
  sealValue,
  openValue,
  makePublish,
  privateKeyFromSeed,
  rawPublicKey,
  sign,
  entryToJson,
  sthToJson,
  mapProofToJson,
  inclusionToJson,
} = require('../lib/log.js');

const OUT = path.join(__dirname, '..', '..', 'docs', 'vectors', 'kt');
const hex = (b) => Buffer.from(b).toString('hex');
const seed = (s) => crypto.createHash('sha256').update(`z-kt-vectors:${s}`).digest();

// --- log_tree.json -----------------------------------------------------------

function logTree() {
  // The certificate-transparency-go reference leaves: any RFC 9162
  // implementation reproduces these roots, so a verifier that fails here is
  // wrong about the RFC, not about Z.
  const leaves = ['', '00', '10', '2021', '3031', '40414243', '5051525354555657', '606162636465666768696a6b6c6d6e6f'];
  const log = new MerkleLog();
  const roots = [hex(log.root)];
  for (const l of leaves) {
    log.append(hashLeaf(Buffer.from(l, 'hex')));
    roots.push(hex(log.root));
  }
  const inclusion = [];
  for (let n = 1; n <= 8; n++) for (let m = 0; m < n; m++) inclusion.push({ index: m, size: n, path: log.inclusionProof(m, n).map(hex) });
  const consistency = [];
  for (let m = 0; m <= 8; m++) for (let n = m; n <= 8; n++) consistency.push({ first: m, second: n, proof: log.consistencyProof(m, n).map(hex) });
  return {
    suite: 'kt_log_tree',
    description:
      'The append-only log tree is RFC 9162 §2.1 over SHA-256, unchanged: leaf hash SHA-256(0x00 || input), node hash SHA-256(0x01 || left || right), the empty tree SHA-256 of nothing. ' +
      'The eight leaves and nine roots are the certificate-transparency-go reference data (merkle/rfc6962 tests). ' +
      'inclusion[] gives PATH(m, D[n]) for every m < n <= 8 and consistency[] gives PROOF(m, D[n]) for every m <= n <= 8; a verifier must accept each against the listed roots and reject any proof against another root, index or size.',
    leaf_inputs: leaves,
    leaf_hashes: leaves.map((l) => hex(hashLeaf(Buffer.from(l, 'hex')))),
    roots_by_size: roots,
    inclusion,
    consistency,
  };
}

// --- map_tree.json -----------------------------------------------------------

function mapTree() {
  const labels = [];
  for (let i = 0; i < 12; i++) labels.push(seed(`map-label-${i}`));
  const absent = [seed('map-absent-0'), seed('map-absent-1')];
  const m = new SparseMerkleMap();
  const steps = [];
  const ops = [
    [0, 0, 1], [1, 1, 1], [2, 2, 1], [0, 3, 2], // an update
    [3, 4, 1], [4, 5, 1], [5, 6, 1], [6, 7, 1], [7, 8, 1], [8, 9, 1], [9, 10, 1], [10, 11, 1], [11, 12, 1],
    [4, 13, 7], // another update
  ];
  for (const [li, index, version] of ops) {
    m.set(labels[li], index, version);
    steps.push({ label: hex(labels[li]), index, version, root_after: hex(m.root) });
  }
  const proofs = [];
  const proofOf = (label) => {
    const p = m.proof(label);
    return { label: hex(label), leaf: p.leaf ? { index: p.leaf.index, version: p.leaf.version } : null, bitmap: hex(p.bitmap), siblings: p.siblings.map(hex) };
  };
  for (const l of labels) proofs.push(proofOf(l));
  for (const l of absent) proofs.push(proofOf(l));
  const good = m.proof(labels[0]);
  const wrongLeaf = { label: hex(labels[0]), leaf: { index: good.leaf.index, version: good.leaf.version + 1 }, bitmap: hex(good.bitmap), siblings: good.siblings.map(hex), why: 'the version is not what the map holds' };
  const claimedAbsent = { label: hex(labels[0]), leaf: null, bitmap: hex(good.bitmap), siblings: good.siblings.map(hex), why: 'the label is present; an absence proof for it cannot hash to the root' };
  const siblingDropped = { label: hex(labels[0]), leaf: { index: good.leaf.index, version: good.leaf.version }, bitmap: hex(good.bitmap), siblings: good.siblings.slice(1).map(hex), why: 'the bitmap announces more siblings than are given' };
  const staleAbsent = (() => {
    const fresh = new SparseMerkleMap();
    for (let i = 0; i < 11; i++) fresh.set(labels[i], i, 1);
    const p = fresh.proof(labels[11]);
    return { label: hex(labels[11]), leaf: null, bitmap: hex(p.bitmap), siblings: p.siblings.map(hex), why: 'an absence proof made before the label was added, checked against the final root' };
  })();
  return {
    suite: 'kt_map_tree',
    description:
      'The map tree: a sparse Merkle tree of depth 256 over 32-byte labels. leaf(label, index, version) = SHA-256(0x10 || label || u64be(index) || u64be(version)); node = SHA-256(0x11 || left || right); ' +
      'the empty leaf is SHA-256(0x12) and the empty subtree at depth d is node(empty(d+1), empty(d+1)). Bit d of the label (MSB first) chooses the branch at depth d. ' +
      'A proof is a 32-byte bitmap (bit d set when the sibling at depth d is not the empty subtree) plus those siblings in depth order; a proof of absence ends in the empty leaf. ' +
      'steps[] sets labels in order with the root after each (two are updates); proofs[] are the compressed proofs under the final root for every label and two absent ones; must_refuse[] must fail against that root.',
    empty_leaf: hex(EMPTY[DEPTH]),
    empty_root: hex(EMPTY[0]),
    example_leaf_hash: { label: hex(labels[0]), index: 3, version: 2, hash: hex(mapLeafHash(labels[0], 3, 2)) },
    steps,
    final_root: hex(m.root),
    proofs,
    must_refuse: [wrongLeaf, claimedAbsent, siblingDropped, staleAbsent],
  };
}

// --- kt_log.json -------------------------------------------------------------

function ktLog() {
  const logSeed = seed('log');
  const logKey = privateKeyFromSeed(logSeed);
  const witnessSeed = seed('witness');
  const witnessKey = privateKeyFromSeed(witnessSeed);

  // Alice is the v1 multidevice vector's account, so the sealed value here is
  // that file's real signed device list (version 3, fingerprint 147d6e6f…):
  // a client that opens it gets a list it can verify with the code it
  // already has, and the fingerprint it computes must equal the entry's.
  const md = JSON.parse(fs.readFileSync(path.join(OUT, '..', 'v1', 'multidevice.json'), 'utf8'));
  const alice = { name: 'alice', seed: Buffer.from(md.account_ed_seed, 'hex') };
  alice.key = privateKeyFromSeed(alice.seed);
  alice.pub = rawPublicKey(alice.key);
  if (hex(alice.pub) !== md.account_ed_pub) throw new Error('v1/multidevice.json account key does not reproduce');
  const aliceList = JSON.stringify(md.device_list.json);
  const aliceFp = Buffer.from(md.device_list.fingerprint, 'hex');
  const bob = { name: 'bob', seed: seed('acct:bob') };
  bob.key = privateKeyFromSeed(bob.seed);
  bob.pub = rawPublicKey(bob.key);

  let t = 1_800_000_000_000;
  const now = () => t;
  const log = new KtLog({ store: new MemoryStore(), signingKey: logKey, resignMs: 60_000, now });

  const accounts = {};
  for (const a of [alice, bob]) {
    accounts[a.name] = {
      account_ed_seed: hex(a.seed),
      account_ed_pub: hex(a.pub),
      label: hex(labelFor(a.pub)),
      label_input: hex(Buffer.concat([Buffer.from('z-kt-label-v1:', 'utf8'), a.pub])),
      value_key: hex(valueKey(a.pub)),
    };
  }

  // The publishes, in order. Bob's lists are stand-ins (no v1 vector for him).
  const plan = [
    { who: alice, version: 3, fp: aliceFp, list: aliceList },
    { who: bob, version: 1, fp: seed('fp:bob:1').subarray(0, 16), list: '{"acct":"' + bob.pub.toString('base64') + '","ver":1,"devs":[],"sig":"","note":"a stand-in; the log does not read values"}' },
    { who: alice, version: 4, fp: seed('fp:alice:4').subarray(0, 16), list: '{"stand_in":"alice v4"}' },
  ];
  const publishes = [];
  const heads = [sthToJson(log.sth())];
  const consistency = [];
  plan.forEach((p, i) => {
    const nonce = seed(`nonce:${i}`).subarray(0, 12);
    const plaintext = Buffer.from(p.list, 'utf8');
    const value = sealValue(p.who.pub, plaintext, nonce);
    if (!openValue(p.who.pub, value).equals(plaintext)) throw new Error('seal/open');
    const req = makePublish(p.who.key, { version: p.version, fp: p.fp, value });
    const label = labelFor(p.who.pub);
    const valueHash = crypto.createHash('sha256').update(value).digest();
    t += 1000;
    const entry = log.publish(req);
    const sth = log.sth();
    heads.push(sthToJson(sth));
    if (log.size >= 2) consistency.push({ first: log.size - 1, second: log.size, proof: log.consistency(log.size - 1, log.size).map((h) => h.toString('base64')) });
    publishes.push({
      account: p.who.name,
      version: p.version,
      fingerprint: hex(p.fp),
      plaintext_json: p.list,
      nonce: hex(nonce),
      value: hex(value),
      value_hash: hex(valueHash),
      publish_input: hex(publishInput({ label, version: p.version, fp: p.fp, valueHash })),
      publish_sig: hex(req.sig),
      request_json: JSON.stringify({ acct: req.acct.toString('base64'), v: req.version, fp: req.fp.toString('base64'), value: req.value.toString('base64'), sig: req.sig.toString('base64') }),
      entry: { index: entry.index, ts: entry.ts, leaf_input: hex(leafInput(entry)), leaf_hash: hex(leafHashOf(entry)), json: entryToJson(entry) },
      sth_after: sthToJson(sth),
      sth_input_after: hex(sthInput(sth)),
    });
  });
  consistency.push({ first: 1, second: 3, proof: log.consistency(1, 3).map((h) => h.toString('base64')) });
  consistency.push({ first: 0, second: 3, proof: [] });

  // Lookups under the final head, as the API serves them.
  const lookups = {};
  for (const [name, a] of [['alice', alice], ['bob', bob]]) {
    const r = log.lookup(labelFor(a.pub));
    lookups[name] = {
      response_json: JSON.stringify({ sth: sthToJson(r.sth), map: mapProofToJson(r.map), entry: entryToJson(r.entry), inclusion: inclusionToJson(r.inclusion) }),
      expect: { version: r.entry.version, index: r.entry.index },
    };
  }
  const nobody = seed('acct:nobody');
  const nobodyPub = rawPublicKey(privateKeyFromSeed(nobody));
  const rn = log.lookup(labelFor(nobodyPub));
  lookups.nobody = {
    account_ed_pub: hex(nobodyPub),
    label: hex(labelFor(nobodyPub)),
    response_json: JSON.stringify({ sth: sthToJson(rn.sth), map: mapProofToJson(rn.map), entry: null, inclusion: null }),
    expect: { absent: true },
  };
  const h = log.history(labelFor(alice.pub));
  const history = {
    response_json: JSON.stringify({ sth: sthToJson(h.sth), entries: h.entries.map((x) => ({ entry: entryToJson(x.entry), inclusion: inclusionToJson(x.inclusion) })) }),
    expect_versions: h.entries.map((x) => x.entry.version),
  };

  // A re-signed head with no growth: same roots, later ts, a different signature.
  t += 120_000;
  const resigned = sthToJson(log.sth());

  // The witness co-signature over the final head.
  const finalSth = log.sth();
  const witness = {
    witness_seed: hex(witnessSeed),
    witness_pub: hex(rawPublicKey(witnessKey)),
    over_sth: sthToJson(finalSth),
    witness_input: hex(witnessInput(finalSth)),
    sig: hex(sign(witnessKey, witnessInput(finalSth))),
    record_json: JSON.stringify({ sth: sthToJson(finalSth), verifiedAt: t, size: finalSth.size, witness: { pub: rawPublicKey(witnessKey).toString('base64'), sig: sign(witnessKey, witnessInput(finalSth)).toString('base64') } }),
  };

  // What must be refused.
  const mustRefuse = [];
  {
    const stale = makePublish(alice.key, { version: 4, fp: seed('fp:alice:4').subarray(0, 16), value: sealValue(alice.pub, Buffer.from('{"stand_in":"again"}'), seed('nonce:stale').subarray(0, 12)) });
    mustRefuse.push({ why: 'version 4 does not exceed the version the log holds for the label (4)', http: 409, code: 'stale_version', request_json: JSON.stringify({ acct: stale.acct.toString('base64'), v: 4, fp: stale.fp.toString('base64'), value: stale.value.toString('base64'), sig: stale.sig.toString('base64') }) });
    const forged = makePublish(alice.key, { version: 5, fp: seed('fp:alice:5').subarray(0, 16), value: sealValue(alice.pub, Buffer.from('{"stand_in":"v5"}'), seed('nonce:forged').subarray(0, 12)) });
    const bobSig = sign(bob.key, publishInput({ label: labelFor(alice.pub), version: 5, fp: forged.fp, valueHash: crypto.createHash('sha256').update(forged.value).digest() }));
    mustRefuse.push({ why: 'signed by a key that is not the account key', http: 403, code: 'bad_signature', request_json: JSON.stringify({ acct: forged.acct.toString('base64'), v: 5, fp: forged.fp.toString('base64'), value: forged.value.toString('base64'), sig: bobSig.toString('base64') }) });
    const edited = makePublish(alice.key, { version: 5, fp: seed('fp:alice:5').subarray(0, 16), value: forged.value });
    const wrongFp = Buffer.from(edited.fp);
    wrongFp[0] ^= 1;
    mustRefuse.push({ why: 'the fingerprint was changed after signing', http: 403, code: 'bad_signature', request_json: JSON.stringify({ acct: edited.acct.toString('base64'), v: 5, fp: wrongFp.toString('base64'), value: edited.value.toString('base64'), sig: edited.sig.toString('base64') }) });
    // A head whose signature is not the log's.
    const wrongHead = { ...sthToJson(finalSth), sig: sign(witnessKey, sthInput(finalSth)).toString('base64') };
    mustRefuse.push({ why: 'a tree head signed by some other key than the pinned log key', head_json: JSON.stringify(wrongHead) });
    // A lookup whose map proof claims the old entry as latest.
    const r = log.lookup(labelFor(alice.pub));
    const old = log.entries[0];
    const mp = mapProofToJson(r.map);
    mp.leaf = { index: 0, v: 3 };
    mustRefuse.push({ why: 'a lookup presenting the superseded entry (index 0, v3) as latest: the map proof does not hash to the head', response_json: JSON.stringify({ sth: sthToJson(r.sth), map: mp, entry: entryToJson(old), inclusion: inclusionToJson(log._inclusion(0, r.sth.size)) }) });
    // The fork: a second log, same key, a different third entry.
    // Its clock replays the honest log's, so the first two leaves are identical.
    let ft = 1_800_000_000_000;
    const fork = new KtLog({ store: new MemoryStore(), signingKey: logKey, resignMs: 60_000, now: () => ft });
    for (let i = 0; i < 2; i++) {
      const p = plan[i];
      ft += 1000;
      fork.publish(makePublish(p.who.key, { version: p.version, fp: p.fp, value: sealValue(p.who.pub, Buffer.from(p.list, 'utf8'), seed(`nonce:${i}`).subarray(0, 12)) }));
    }
    if (!fork.sth().logRoot.equals(Buffer.from(heads[2].logRoot, 'base64'))) throw new Error('the fork must share the honest prefix');
    ft += 1000;
    fork.publish(makePublish(alice.key, { version: 40, fp: seed('fp:alice:40').subarray(0, 16), value: sealValue(alice.pub, Buffer.from('{"stand_in":"fork"}'), seed('nonce:fork').subarray(0, 12)) }));
    const forkSameSize = fork.sth();
    ft += 1000;
    fork.publish(makePublish(alice.key, { version: 41, fp: seed('fp:alice:41').subarray(0, 16), value: sealValue(alice.pub, Buffer.from('{"stand_in":"fork 2"}'), seed('nonce:fork2').subarray(0, 12)) }));
    const forkGrown = fork.sth();
    mustRefuse.push({
      why: 'a fork: the same log key signs a size-3 head whose third entry differs from the honest one. A client holding the honest size-3 head must refuse it: same size, different roots. (A client that had only seen size 2 could not tell — both are honest extensions of what it holds; that is what mirrors and witnesses are for.)',
      client_holds: heads[3],
      head_json: JSON.stringify(sthToJson(forkSameSize)),
    });
    mustRefuse.push({
      why: 'the same fork, grown to size 4: its PROOF(3,4) must fail against the honest size-3 root, so a client holding the honest head does not follow it',
      client_holds: heads[3],
      head_json: JSON.stringify(sthToJson(forkGrown)),
      consistency_from_fork: fork.consistency(3, 4).map((h) => h.toString('base64')),
    });
  }

  return {
    suite: 'kt_log',
    description:
      'The key transparency log end to end (§19): labels, value keys and sealed values, publish signatures, leaf inputs, signed tree heads, consistency proofs, the lookup and history responses as the API serves them, a witness co-signature, and the cases that must be refused. ' +
      'Alice is the v1 multidevice vector\'s account; her first entry seals that file\'s real signed device list (version 3), so a client that opens the value can verify the list and must find its fingerprint equal to the entry\'s. The clock is fixed (ts values are part of the leaves).',
    contexts: { label: 'z-kt-label-v1:', leaf: 'z-kt-leaf-v1:', sth: 'z-kt-sth-v1:', publish: 'z-kt-publish-v1:', witness: 'z-kt-witness-v1:', value_salt: 'z-kt-value-v1', value_info: 'value' },
    log: { seed: hex(logSeed), pub: hex(log.publicKey) },
    accounts,
    empty_head: heads[0],
    publishes,
    heads_by_size: heads,
    consistency,
    lookups,
    history_alice: history,
    resigned_head: { note: 'the same size and roots 120 s later: a fresh timestamp and signature, nothing else', head: resigned },
    witness,
    must_refuse: mustRefuse,
  };
}

function main() {
  fs.mkdirSync(OUT, { recursive: true });
  const files = { 'log_tree.json': logTree(), 'map_tree.json': mapTree(), 'kt_log.json': ktLog() };
  for (const [name, obj] of Object.entries(files)) {
    fs.writeFileSync(path.join(OUT, name), JSON.stringify(obj, null, 1) + '\n');
  }
  return files;
}

module.exports = { generate: () => ({ 'log_tree.json': logTree(), 'map_tree.json': mapTree(), 'kt_log.json': ktLog() }), OUT };

if (require.main === module) {
  const files = main();
  for (const name of Object.keys(files)) console.log(`wrote ${path.join(OUT, name)}`);
}
