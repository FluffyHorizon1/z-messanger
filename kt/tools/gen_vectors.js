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
const { DEPTH, EMPTY, SparseMerkleMap, mapLeafHash, prefixHex, parsePrefix } = require('../lib/smt.js');
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
  bucketBits,
  bucketToJson,
  verifyBucketAnswer,
  handleEntryToJson,
} = require('../lib/log.js');
const handles = require('../lib/handles.js');

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
  // that file's real signed device list (version 3). Its fingerprint is the v1
  // one, held there while v1 signing continues even though the list carries sig2
  // (ADR 0017, the mixed-version fix — a not-yet-migrated client computes v1 and
  // both sides must agree): a client that opens it gets a list it can verify with
  // the code it already has, and the fingerprint it computes must equal the
  // entry's. Derived from the multidevice vector below, so it tracks that fix.
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

// --- bucket.json ---------------------------------------------------------------

/**
 * Lookups by bucket (§19.9) for both logs, and the handle log itself (§21.5):
 * answers exactly as the routes serve them, with the cases a reader must
 * refuse; the handle log's publishes byte for byte (records, signing inputs,
 * signatures); and the publishes its owner rule refuses, with the status
 * and code. Every answer is checked here with `verifyBucketAnswer` before it
 * is written, and every must_refuse is checked to fail.
 */
function bucket() {
  // As the server serves a bucket answer: the head with `bucketBits`, then the bucket(s).
  const headOf = (log, sth) => ({ ...sthToJson(sth), bucketBits: bucketBits(log.map.size) });
  const answer = (log, asked) => {
    const r = log.buckets(asked.map((a) => ({ prefix: parsePrefix(a.prefix, a.bits), bits: a.bits })));
    if (asked.length === 1) return { sth: headOf(log, r.sth), ...bucketToJson(r.buckets[0]) };
    return { sth: headOf(log, r.sth), buckets: r.buckets.map(bucketToJson) };
  };
  const check = (mode, log, asked, json) => verifyBucketAnswer({ mode, logPub: log.publicKey, asked, json });
  const refuse = (mode, log, why, asked, json) => {
    let ok = false;
    try {
      check(mode, log, asked, json);
      ok = true;
    } catch {}
    if (ok) throw new Error(`must_refuse verified: ${why}`);
    return { why, asked, response_json: JSON.stringify(json) };
  };

  // The key-transparency log: twenty accounts, three republished.
  let t = 1_800_000_000_000;
  const ktLogKey = privateKeyFromSeed(seed('bucket:kt-log'));
  const kt = new KtLog({ store: new MemoryStore(), signingKey: ktLogKey, resignMs: 60_000, now: () => t });
  const accts = [];
  for (let i = 0; i < 20; i++) {
    const key = privateKeyFromSeed(seed(`bucket:acct:${i}`));
    accts.push({ key, pub: rawPublicKey(key) });
  }
  const ktPublish = (a, v) =>
    makePublish(a.key, { version: v, fp: seed(`bucket:fp:${v}`).subarray(0, 16), value: sealValue(a.pub, Buffer.from(`{"stand_in":${v}}`), seed(`bucket:nonce:${v}`).subarray(0, 12)) });
  for (const a of accts) {
    t += 1000;
    kt.publish(ktPublish(a, 1));
  }
  for (const a of accts.slice(0, 3)) {
    t += 1000;
    kt.publish(ktPublish(a, 2));
  }
  const target = labelFor(accts[0].pub);
  const ktBuckets = [0, 1, 8].map((bits) => {
    const asked = [{ prefix: prefixHex(target, bits), bits }];
    const json = answer(kt, asked);
    const v = check('kt', kt, asked, json);
    return { asked: asked[0], response_json: JSON.stringify(json), expect_labels: v.buckets[0].leaves.map((l) => hex(l.label)) };
  });
  // A bucket no label of the log falls in (four bits under the target's
  // first byte, flipped), and the absence it proves.
  const emptyAsked = (() => {
    for (let b = 0; b < 256; b++) {
      const p = Buffer.alloc(32);
      p[0] = b;
      const a = [{ prefix: prefixHex(p, 8), bits: 8 }];
      if (kt.map.bucket(parsePrefix(a[0].prefix, 8), 8).leaves.length === 0) return a;
    }
    throw new Error('no empty bucket');
  })();
  const emptyJson = answer(kt, emptyAsked);
  check('kt', kt, emptyAsked, emptyJson);
  const postAsked = [
    { prefix: prefixHex(target, 2), bits: 2 },
    { prefix: prefixHex(labelFor(accts[5].pub), 4), bits: 4 },
    emptyAsked[0],
  ];
  const postJson = answer(kt, postAsked);
  check('kt', kt, postAsked, postJson);
  const byIndex = kt.entriesAt([21, 4, 0]);
  const entriesJson = {
    sth: sthToJson(byIndex.sth),
    total: byIndex.total,
    entries: byIndex.entries.map((x) => ({ entry: entryToJson(x.entry), inclusion: inclusionToJson(x.inclusion) })),
  };

  // What a reader must refuse, on the k = 1 bucket and the k = 8 one.
  const ktRefuse = [];
  {
    const asked = [ktBuckets[1].asked];
    const base = JSON.parse(ktBuckets[1].response_json);
    const L = base.leaves;
    ktRefuse.push(refuse('kt', kt, 'a label left out of the bucket', asked, { ...base, leaves: L.filter((_, i) => i !== 2) }));
    const forged = Buffer.from(L[1].label, 'base64');
    forged[31] ^= 1;
    const added = [...L, { label: forged.toString('base64'), index: 0, version: 1 }].sort((a, b) => Buffer.compare(Buffer.from(a.label, 'base64'), Buffer.from(b.label, 'base64')));
    ktRefuse.push(refuse('kt', kt, 'a label added to the bucket', asked, { ...base, leaves: added }));
    ktRefuse.push(refuse('kt', kt, 'a version that is not the map\'s', asked, { ...base, leaves: L.map((l, i) => (i === 0 ? { ...l, version: l.version + 1 } : l)) }));
    ktRefuse.push(refuse('kt', kt, 'two leaves out of label order', asked, { ...base, leaves: [L[1], L[0], ...L.slice(2)] }));
    ktRefuse.push(refuse('kt', kt, 'the sibling dropped', asked, { ...base, siblings: [] }));
    const other = { prefix: base.prefix === '0' ? '8' : '0', bits: 1 };
    ktRefuse.push(refuse('kt', kt, 'the answer for the other half, presented as this one', [other], base));
    const k8 = JSON.parse(ktBuckets[2].response_json);
    const reSigned = { ...k8, sth: { ...k8.sth, sig: sign(ktLogKey, handles.sthInput(sthFromJsonLocal(k8.sth))).toString('base64') } };
    ktRefuse.push(refuse('kt', kt, 'a head the log key signed in the HANDLE log\'s context', [ktBuckets[2].asked], reSigned));
  }

  // The handle log: one label claimed, updated, recovered and updated again;
  // one claimed by somebody else; nine more claims. Labels are stand-ins —
  // the log never computes one (a label is Argon2id of a handle, §21.1).
  t = 1_800_000_123_456;
  const hLogKey = privateKeyFromSeed(seed('bucket:handle-log'));
  const hl = new KtLog({ store: new MemoryStore(), signingKey: hLogKey, resignMs: 60_000, now: () => t, mode: 'handles' });
  const k = (s) => privateKeyFromSeed(seed(`bucket:handle:${s}`));
  const keys = { owner: k('owner'), owner2: k('owner2'), recovery: k('recovery'), recovery2: k('recovery2'), other: k('other'), stranger: k('stranger') };
  // An introduction mailbox's two keys come from one seed (SPEC amendment 1).
  const introSeed = (s) => seed(`bucket:handle:intro:${s}`);
  const rc = handles.rcOf(rawPublicKey(keys.recovery));
  const rc2 = handles.rcOf(rawPublicKey(keys.recovery2));
  const A = seed('bucket:handle-label:finnian.07');
  const B = seed('bucket:handle-label:someone.4242');
  const plan = [
    { label: A, version: 1, ownerKey: keys.owner, k: 'claim', introSeed: introSeed('a1'), pow: 20, rc },
    { label: B, version: 1, ownerKey: keys.other, k: 'claim', introSeed: introSeed('b1'), pow: 16, rc: handles.rcOf(rawPublicKey(k('other-recovery'))) },
    { label: A, version: 2, ownerKey: keys.owner, k: 'update', intro: null, pow: 20, rc },
    { label: A, version: 3, ownerKey: keys.owner2, k: 'recover', introSeed: introSeed('a3'), pow: 24, rc: rc2, recoveryKey: keys.recovery },
    { label: A, version: 4, ownerKey: keys.owner2, k: 'update', introSeed: introSeed('a4'), pow: 28, rc: rc2 },
  ];
  for (let i = 0; i < 9; i++) plan.push({ label: seed(`bucket:handle-label:more.${i}`), version: 1, ownerKey: keys.other, k: 'claim', introSeed: introSeed(`m${i}`), pow: 18, rc });
  const publishes = plan.map((p) => {
    t += 23 * 60 * 1000; // 23 minutes apart: several to an hour, and the hour is all that is kept
    const req = handles.makeHandlePublish(p);
    const entry = hl.publish(req);
    const rec = handles.parseRecord(req.value);
    const o = {
      label: hex(p.label),
      version: p.version,
      k: p.k,
      record_json: req.value.toString('utf8'),
      value_hash: hex(entry.valueHash),
      publish_input: hex(handles.publishInput({ label: p.label, version: p.version, valueHash: entry.valueHash })),
      sig: hex(req.sig),
      request_json: JSON.stringify(handles.handlePublishJson(req)),
      ...(p.introSeed ? { intro_seed: hex(p.introSeed) } : {}),
      accepted_ms: t,
      entry: { json: handleEntryToJson(hl.withValue(entry)), leaf_input: hex(handles.leafInput(entry)), leaf_hash: hex(hl.tree.leaves[entry.index]) },
    };
    if (p.k === 'recover') {
      o.recover_input = hex(handles.recoverInput({ label: p.label, version: p.version, owner: rec.owner, rc: rec.rc }));
      o.rpub = hex(rec.rpub);
      o.rsig = hex(rec.rsig);
    }
    return o;
  });
  const hBuckets = [0, 1, 8].map((bits) => {
    const asked = [{ prefix: prefixHex(A, bits), bits }];
    const json = answer(hl, asked);
    const v = check('handles', hl, asked, json);
    return { asked: asked[0], response_json: JSON.stringify(json), expect_labels: v.buckets[0].leaves.map((l) => hex(l.label)) };
  });
  const hRefuse = [];
  {
    const asked = [hBuckets[2].asked];
    const base = JSON.parse(hBuckets[2].response_json);
    const at = base.leaves.findIndex((l) => Buffer.from(l.label, 'base64').equals(A));
    const swap = (leaf) => ({ ...base, leaves: base.leaves.map((l, i) => (i === at ? leaf : l)) });
    const L = base.leaves[at];
    const changed = JSON.parse(Buffer.from(L.value, 'base64').toString());
    changed.pow = 16;
    hRefuse.push(refuse('handles', hl, 'the record changed (pow 28 → 16): it is not the entry the log tree holds at its index', asked, swap({ ...L, value: Buffer.from(JSON.stringify(changed)).toString('base64') })));
    hRefuse.push(refuse('handles', hl, 'a ts that is not a whole hour', asked, swap({ ...L, ts: L.ts + 1 })));
    hRefuse.push(refuse('handles', hl, 'the audit path cut short', asked, swap({ ...L, audit: L.audit.slice(0, -1) })));
    hRefuse.push(refuse('handles', hl, 'an older record of the label (version 2) in place of the latest', asked, swap({ ...L, ...(() => {
      const e = hl.withValue(hl.entries[2]);
      return { index: 2, version: 2, value: e.value.toString('base64'), ts: e.ts, sig: e.sig.toString('base64'), audit: hl.tree.inclusionProof(2, hl.size).map((x) => x.toString('base64')) };
    })() })));
    const reSigned = { ...base, sth: { ...base.sth, sig: sign(hLogKey, sthInput(sthFromJsonLocal(base.sth))).toString('base64') } };
    hRefuse.push(refuse('handles', hl, 'a head the handle log key signed in the KEY-TRANSPARENCY context', asked, reSigned));
  }
  // What the owner rule refuses, on the wire, after the plan.
  const rule = [];
  const attempt = (why, p, req = handles.makeHandlePublish(p)) => {
    try {
      hl.publish(req);
    } catch (e) {
      rule.push({ why, http: e.status, code: e.code, request_json: JSON.stringify(handles.handlePublishJson(req)) });
      return;
    }
    throw new Error(`the owner rule accepted: ${why}`);
  };
  const resign = (req, by) => ({ ...req, sig: sign(by, handles.publishInput({ label: req.label, version: req.version, valueHash: crypto.createHash('sha256').update(req.value).digest() })) });
  attempt('a claim on a held label', { label: A, version: 9, ownerKey: keys.stranger, k: 'claim', rc });
  attempt('an update naming the stranger as owner', { label: A, version: 5, ownerKey: keys.stranger, k: 'update', rc: rc2 });
  attempt('an update naming the owner, signed by the stranger', null, resign(handles.makeHandlePublish({ label: A, version: 5, ownerKey: keys.owner2, k: 'update', rc: rc2 }), keys.stranger));
  attempt('an update changing the recovery commitment', { label: A, version: 5, ownerKey: keys.owner2, k: 'update', rc });
  attempt('an update by the owner the recover replaced', { label: A, version: 5, ownerKey: keys.owner, k: 'update', rc });
  attempt('an update before any claim', { label: seed('bucket:handle-label:nobody.00'), version: 1, ownerKey: keys.stranger, k: 'update', rc });
  attempt('a recover with the spent recovery key', { label: A, version: 5, ownerKey: keys.stranger, k: 'recover', rc, recoveryKey: keys.recovery });
  attempt('a recover signed by the old owner for the new', null, resign(handles.makeHandlePublish({ label: A, version: 5, ownerKey: keys.stranger, k: 'recover', rc, recoveryKey: keys.recovery2 }), keys.owner2));
  attempt('a version that does not exceed the label\'s', { label: A, version: 4, ownerKey: keys.owner2, k: 'update', rc: rc2 });
  {
    const good = handles.makeHandlePublish({ label: A, version: 5, ownerKey: keys.owner2, k: 'update', rc: rc2 });
    const spaced = Buffer.from(good.value.toString().replace(',"pow"', ', "pow"'));
    attempt('a record that is not its canonical encoding (a space)', null, resign({ ...good, value: spaced }, keys.owner2));
  }
  attempt('an introduction key without its X25519 key (intro set, xintro null)', {
    label: A,
    version: 5,
    ownerKey: keys.owner2,
    k: 'update',
    intro: handles.introKeys(introSeed('a5')).intro,
    xintro: null,
    rc: rc2,
  });

  const hHead = hl.sth();
  return {
    suite: 'kt_bucket',
    description:
      'Lookups by bucket (PROTOCOL §19.9) for the key-transparency log and the handle log, and the handle log itself (§21.5). A bucket is every label whose first `bits` bits are `prefix` ' +
      '(⌈bits/4⌉ hex digits, unused low bits zero); its answer carries the head, the leaves in label order and the map siblings from depth bits-1 up to 0. A reader recomputes the depth-`bits` ' +
      'subtree from the leaves with the map leaf hash and the empty subtrees of §19.2, folds it up through the siblings by the prefix\'s bits, and compares it with the head\'s mapRoot after verifying ' +
      'the head under the pinned key in the log\'s own context. Handle-log leaves also carry the record (value), ts (a whole hour), the owner\'s sig and the audit path of the entry at index, which ' +
      'verifies the handle leaf under logRoot. Every response_json is a response as served; every must_refuse must fail. The handle labels are stand-ins (the log never computes a label); ' +
      'owner_rule_refusals are publishes the log refuses, with the status and code it answers.',
    contexts: {
      handle_leaf: 'z-handle-leaf-v1:',
      handle_sth: 'z-handle-sth-v1:',
      handle_witness: 'z-handle-witness-v1:',
      handle_publish: 'z-handle-publish-v1:',
      handle_recover: 'z-handle-recover-v1:',
      handle_rc: 'z-handle-rc-v1:',
      handle_intro_x_salt: 'z-handle-intro-x-v1',
    },
    kt: {
      log: { seed: hex(seed('bucket:kt-log')), pub: hex(kt.publicKey) },
      labels: accts.map((a) => hex(labelFor(a.pub))),
      buckets: ktBuckets,
      empty_bucket: { asked: emptyAsked[0], response_json: JSON.stringify(emptyJson), absent_label_example: hex(Buffer.concat([parsePrefix(emptyAsked[0].prefix, 8).subarray(0, 1), seed('bucket:absent').subarray(1)])) },
      post_buckets: { request_json: JSON.stringify({ buckets: postAsked }), response_json: JSON.stringify(postJson) },
      entries_by_index: { request_json: JSON.stringify({ indexes: [21, 4, 0] }), response_json: JSON.stringify(entriesJson) },
      must_refuse: ktRefuse,
    },
    handles: {
      log: { seed: hex(seed('bucket:handle-log')), pub: hex(hl.publicKey) },
      keys: Object.fromEntries(Object.entries(keys).map(([name, key]) => [name, { pub: hex(rawPublicKey(key)) }])),
      seeds: Object.fromEntries(Object.keys(keys).map((name) => [name, hex(seed(`bucket:handle:${name}`))])),
      rc: hex(rc),
      rc_after_recover: hex(rc2),
      publishes,
      head: sthToJson(hHead),
      head_input: hex(handles.sthInput(hHead)),
      buckets: hBuckets,
      must_refuse: hRefuse,
      owner_rule_refusals: rule,
    },
  };
}

/** sthFromJson without the log module's export list, for the re-signed must_refuse heads. */
function sthFromJsonLocal(j) {
  return { size: j.size, logRoot: Buffer.from(j.logRoot, 'base64'), mapRoot: Buffer.from(j.mapRoot, 'base64'), ts: j.ts };
}

function generate() {
  return { 'log_tree.json': logTree(), 'map_tree.json': mapTree(), 'kt_log.json': ktLog(), 'bucket.json': bucket() };
}

function main() {
  fs.mkdirSync(OUT, { recursive: true });
  const files = generate();
  for (const [name, obj] of Object.entries(files)) {
    fs.writeFileSync(path.join(OUT, name), JSON.stringify(obj, null, 1) + '\n');
  }
  return files;
}

module.exports = { generate, OUT };

if (require.main === module) {
  const files = main();
  for (const name of Object.keys(files)) console.log(`wrote ${path.join(OUT, name)}`);
}
