'use strict';

// Cross-implementation verification of the Z protocol test vectors
// (docs/vectors/v1). This file shares NO code with the Dart protocol library
// or with the relay: every primitive and every construction is re-implemented
// here from docs/PROTOCOL.md on top of Node's built-in `crypto` only. If the
// Dart library and this file agree on every vector, the spec is implementable
// from the document alone — which is the point of Phase 5.1.
//
// Run: `npm test` (from server/). Requires Node >= 20 (Ed25519, X25519, HKDF
// and chacha20-poly1305 are all built in; XChaCha20 is derived below).

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const VECTORS_DIR = path.join(__dirname, '..', '..', 'docs', 'vectors', 'v1');
const load = (name) => JSON.parse(fs.readFileSync(path.join(VECTORS_DIR, `${name}.json`), 'utf8'));

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------
const hex = (b) => Buffer.from(b).toString('hex');
const unhex = (s) => Buffer.from(s, 'hex');
const b64 = (b) => Buffer.from(b).toString('base64');
const unb64 = (s) => Buffer.from(s, 'base64');
const b64url = (b) => Buffer.from(b).toString('base64url'); // no padding
const unb64url = (s) => Buffer.from(s, 'base64url');
const utf8 = (s) => Buffer.from(s, 'utf8');
const cat = (...parts) => Buffer.concat(parts.map((p) => Buffer.from(p)));
const sha256 = (b) => crypto.createHash('sha256').update(b).digest();
const hmac = (key, data) => crypto.createHmac('sha256', key).update(data).digest();
const hkdf = (ikm, salt, info, len) =>
  Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, len));

// ---------------------------------------------------------------------------
// Ed25519 / X25519 with raw 32-byte keys (DER wrappers are constant prefixes)
// ---------------------------------------------------------------------------
const P8_ED = unhex('302e020100300506032b657004220420');
const P8_X = unhex('302e020100300506032b656e04220420');
const SPKI_ED = unhex('302a300506032b6570032100');
const SPKI_X = unhex('302a300506032b656e032100');

const edPriv = (seed) => crypto.createPrivateKey({ key: cat(P8_ED, seed), format: 'der', type: 'pkcs8' });
const edPubKey = (raw) => crypto.createPublicKey({ key: cat(SPKI_ED, raw), format: 'der', type: 'spki' });
const xPriv = (seed) => crypto.createPrivateKey({ key: cat(P8_X, seed), format: 'der', type: 'pkcs8' });
const xPubKey = (raw) => crypto.createPublicKey({ key: cat(SPKI_X, raw), format: 'der', type: 'spki' });
const rawPub = (keyObj) => crypto.createPublicKey(keyObj).export({ format: 'der', type: 'spki' }).subarray(-32);

const edPub = (seed) => rawPub(edPriv(seed));
const xPub = (seed) => rawPub(xPriv(seed));
const edSign = (seed, msg) => crypto.sign(null, msg, edPriv(seed));
const edVerify = (pub, msg, sig) => crypto.verify(null, msg, edPubKey(pub), sig);
const x25519 = (seed, pub) => crypto.diffieHellman({ privateKey: xPriv(seed), publicKey: xPubKey(pub) });

// ---------------------------------------------------------------------------
// AEADs: ChaCha20-Poly1305 (built in) and XChaCha20-Poly1305 (HChaCha20 here)
// ---------------------------------------------------------------------------
function chachaSeal(key, nonce12, plain, aad) {
  const c = crypto.createCipheriv('chacha20-poly1305', key, nonce12, { authTagLength: 16 });
  if (aad) c.setAAD(aad, { plaintextLength: plain.length });
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return { ct, mac: c.getAuthTag() };
}

function chachaOpen(key, nonce12, ct, mac, aad) {
  const d = crypto.createDecipheriv('chacha20-poly1305', key, nonce12, { authTagLength: 16 });
  if (aad) d.setAAD(aad, { plaintextLength: ct.length });
  d.setAuthTag(mac);
  return Buffer.concat([d.update(ct), d.final()]);
}

// HChaCha20 (draft-irtf-cfrg-xchacha): 20 ChaCha rounds over the initial
// state, output = words 0..3 and 12..15 (no feed-forward addition).
function hchacha20(key, nonce16) {
  const s = new Uint32Array(16);
  s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
  for (let i = 0; i < 8; i++) s[4 + i] = key.readUInt32LE(4 * i);
  for (let i = 0; i < 4; i++) s[12 + i] = nonce16.readUInt32LE(4 * i);
  const rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
  const qr = (a, b, c, d) => {
    s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl(s[d] ^ s[a], 16);
    s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl(s[b] ^ s[c], 12);
    s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl(s[d] ^ s[a], 8);
    s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl(s[b] ^ s[c], 7);
  };
  for (let i = 0; i < 10; i++) {
    qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15);
    qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14);
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i++) out.writeUInt32LE(s[i], 4 * i);
  for (let i = 0; i < 4; i++) out.writeUInt32LE(s[12 + i], 16 + 4 * i);
  return out;
}

function xchachaKeyNonce(key, nonce24) {
  const sub = hchacha20(key, nonce24.subarray(0, 16));
  const n12 = cat(Buffer.alloc(4), nonce24.subarray(16, 24));
  return [sub, n12];
}
const xchachaSeal = (key, nonce24, plain, aad) => chachaSeal(...xchachaKeyNonce(key, nonce24), plain, aad);
const xchachaOpen = (key, nonce24, ct, mac, aad) => chachaOpen(...xchachaKeyNonce(key, nonce24), ct, mac, aad);

// ---------------------------------------------------------------------------
// Padding rules from the spec
// ---------------------------------------------------------------------------
// ISO/IEC 7816-4: append 0x80 then zeros to a multiple of 256 (always adds).
function pad7816(data, block = 256) {
  const total = Math.ceil((data.length + 1) / block) * block;
  const out = Buffer.alloc(total);
  data.copy(out);
  out[data.length] = 0x80;
  return out;
}
function unpad7816(data) {
  let i = data.length - 1;
  while (i >= 0 && data[i] === 0) i--;
  assert.equal(data[i], 0x80, 'bad 7816-4 padding');
  return data.subarray(0, i);
}
// Sealed sender: uint32be(len) || plain || zeros, to the smallest bucket.
const SEALED_BUCKETS = [1024, 4096, 16384, 65536, 262144, 1120 * 1024];
function padSealed(plain) {
  const needed = plain.length + 4;
  const bucket = SEALED_BUCKETS.find((b) => b >= needed) ?? needed;
  const out = Buffer.alloc(bucket);
  out.writeUInt32BE(plain.length, 0);
  plain.copy(out, 4);
  return out;
}
function unpadSealed(padded) {
  const len = padded.readUInt32BE(0);
  assert.ok(len <= padded.length - 4);
  return padded.subarray(4, 4 + len);
}

// ---------------------------------------------------------------------------
// Fixtures shared across suites
// ---------------------------------------------------------------------------
const identity = load('identity');
const who = Object.fromEntries(identity.identities.map((i) => [i.name, i]));
const routingId = (edPubRaw) => b64url(sha256(edPubRaw));

// ===========================================================================
test('identity: keys, routing ids, binding signature, contact code', () => {
  for (const id of identity.identities) {
    const edSeed = unhex(id.ed_seed), xSeed = unhex(id.x_seed);
    assert.equal(hex(edPub(edSeed)), id.ed_pub, `${id.name} ed pub`);
    assert.equal(hex(xPub(xSeed)), id.x_pub, `${id.name} x pub`);
    assert.equal(routingId(unhex(id.ed_pub)), id.routing_id, `${id.name} routing id`);
    const msg = cat(utf8('z-bind-v1:'), unhex(id.x_pub));
    assert.equal(hex(msg), id.binding_message);
    assert.equal(hex(edSign(edSeed, msg)), id.binding_sig, `${id.name} binding sig (deterministic)`);
    assert.ok(edVerify(unhex(id.ed_pub), msg, unhex(id.binding_sig)));
    // Contact code: "zc1." + base64url(utf8(json)); a decoder parses the JSON
    // and verifies the binding signature — it never compares bytes.
    assert.ok(id.contact_code.startsWith('zc1.'));
    const j = JSON.parse(unb64url(id.contact_code.slice(4)).toString('utf8'));
    assert.deepEqual(j, JSON.parse(id.contact_code_json));
    assert.equal(j.v, 1);
    assert.equal(hex(unb64(j.ed)), id.ed_pub);
    assert.equal(hex(unb64(j.x)), id.x_pub);
    assert.equal(hex(unb64(j.sig)), id.binding_sig);
    assert.equal(j.name, id.display_name);
  }
});

test('identity: safety numbers', () => {
  for (const s of identity.safety_numbers) {
    const a = unhex(who[s.a].ed_pub), b = unhex(who[s.b].ed_pub);
    const [lo, hi] = Buffer.compare(a, b) < 0 ? [a, b] : [b, a];
    assert.equal(hex(lo), s.lo_ed_pub);
    assert.equal(hex(hi), s.hi_ed_pub);
    const okm = hkdf(cat(lo, hi), utf8('z-safety-v1'), utf8('display'), 60);
    assert.equal(hex(okm), s.hkdf_okm);
    const groups = [];
    for (let g = 0; g < 12; g++) {
      let acc = 0;
      for (let i = 0; i < 5; i++) acc = (acc * 256 + okm[g * 5 + i]) % 100000;
      groups.push(String(acc).padStart(5, '0'));
    }
    assert.equal(groups.join(' '), s.safety_number);
  }
});

test('identity: relay auth challenge/response', () => {
  for (const a of identity.relay_auth) {
    const id = who[a.identity];
    const nonce = unb64(a.challenge_frame.nonce);
    assert.equal(hex(nonce), a.nonce);
    const msg = cat(utf8('z-relay-auth-v1:'), nonce);
    assert.equal(hex(msg), a.signed_message);
    assert.equal(hex(edSign(unhex(id.ed_seed), msg)), a.sig);
    assert.ok(edVerify(unb64(a.auth_frame.pub), msg, unb64(a.auth_frame.sig)));
    assert.equal(a.auth_frame.t, 'auth');
    assert.equal(a.ready_frame.id, routingId(unb64(a.auth_frame.pub)));
  }
});

// ===========================================================================
test('handshake: X3DH-style SK, AD and session id', () => {
  const h = load('handshake');
  const A = who[h.initiator], B = who[h.responder];
  const ekSeed = unhex(h.ek_seed);
  assert.equal(hex(xPub(ekSeed)), h.ek_pub);
  const dh1 = x25519(unhex(A.x_seed), unhex(B.x_pub));
  const dh2 = x25519(ekSeed, unhex(B.x_pub));
  assert.equal(hex(dh1), h.dh1);
  assert.equal(hex(dh2), h.dh2);
  // Responder's mirror computation.
  assert.equal(hex(x25519(unhex(B.x_seed), unhex(A.x_pub))), h.dh1);
  assert.equal(hex(x25519(unhex(B.x_seed), unhex(h.ek_pub))), h.dh2);
  const ikm = cat(Buffer.alloc(32, 0xff), dh1, dh2);
  assert.equal(hex(ikm), h.ikm);
  assert.equal(hex(hkdf(ikm, Buffer.alloc(32), utf8('Z-X3DH-v1'), 32)), h.sk);
  const adInput = cat(utf8('Z-AD-v1'), unhex(A.ed_pub), unhex(B.ed_pub));
  assert.equal(hex(adInput), h.ad_input);
  assert.equal(hex(sha256(adInput)), h.ad);
  assert.equal(b64url(sha256(unhex(h.ek_pub))).slice(0, 22), h.sid);
});

// ===========================================================================
// An independent Double Ratchet, written from PROTOCOL.md §4, with the
// randomness injected from the vector's recorded draws.
// ===========================================================================
const kdfRk = (rk, dh) => {
  const out = hkdf(dh, rk, utf8('Z-RK-v1'), 64);
  return [out.subarray(0, 32), out.subarray(32)];
};
const kdfCk = (ck) => [hmac(ck, Buffer.from([1])), hmac(ck, Buffer.from([2]))];
// v2 (§17): optional members are appended in this fixed order; a header
// without them encodes exactly as in v1.
const headerBytes = (h) =>
  utf8(`{"dh":"${h.dh}","n":${h.n},"pn":${h.pn}`
    + (h.pq ? ',"pq":1' : '')
    + (h.pqg ? `,"pqg":${h.pqg}` : '') // 7.5b: generation, omitted when 0
    + (h.pqct ? `,"pqct":"${h.pqct}"` : '') + '}');
// v2 message-key mixing: HKDF(ikm = mk, salt = K, info = "Z-PQ-MK-v2").
const pqMix = (mk, K) => hkdf(mk, K, utf8('Z-PQ-MK-v2'), 32);
// 7.5b: the secret to mix for a message tagged with generation g (0 when the
// header omits pqg), or null if this side holds no secret for it.
function pqSecretFor(pq, g) {
  if (pq && pq.k && g === (pq.gen || 0)) return pq.k;
  if (pq && pq.oldK != null && g === pq.oldGen) return pq.oldK;
  return null;
}

function makeSession(ad) {
  return { rootKey: null, dhsSeed: null, dhsPub: null, dhrPub: null, cks: null, ckr: null, ns: 0, nr: 0, pn: 0, ad, skipped: new Map() };
}

function drEncrypt(s, plaintext, nonce, pq) {
  assert.ok(s.cks, 'sending chain not initialised');
  const [mk0, next] = kdfCk(s.cks);
  const mixed = pq && pq.k;
  const mk = mixed ? pqMix(mk0, pq.k) : mk0;
  const header = { dh: b64(s.dhsPub), n: s.ns, pn: s.pn };
  if (mixed) header.pq = 1;
  if (mixed && (pq.gen || 0) > 0) header.pqg = pq.gen; // 7.5b
  if (mixed && !pq.acked && pq.ct) header.pqct = b64(pq.ct);
  const { ct, mac } = xchachaSeal(mk, nonce, pad7816(plaintext), cat(s.ad, headerBytes(header)));
  s.cks = next;
  s.ns += 1;
  return { header, nonce, ct, mac, mk };
}

function drDhStep(s, theirPub, newSeed) {
  s.pn = s.ns; s.ns = 0; s.nr = 0;
  s.dhrPub = theirPub;
  [s.rootKey, s.ckr] = kdfRk(s.rootKey, x25519(s.dhsSeed, theirPub));
  s.dhsSeed = newSeed; s.dhsPub = xPub(newSeed);
  [s.rootKey, s.cks] = kdfRk(s.rootKey, x25519(s.dhsSeed, theirPub));
}

function drSkip(s, until) {
  if (!s.ckr) return;
  assert.ok(until - s.nr <= 512, 'too many skipped');
  while (s.nr < until) {
    const [mk, next] = kdfCk(s.ckr);
    s.skipped.set(`${b64(s.dhrPub)}|${s.nr}`, mk);
    s.ckr = next;
    s.nr += 1;
  }
}

function drDecrypt(s, msg, draws, pq) {
  const aad = cat(s.ad, headerBytes(msg.header));
  // v2: a message flagged pq needs the shared secret; a header ciphertext
  // establishes it on the offering side (decapsulation is delegated to the
  // Python verifier — here the vector's K is used, see the v2 test).
  const g = msg.header.pqg || 0; // 7.5b generation (0 when absent)
  const use = (mk0) => (msg.header.pq ? pqMix(mk0, pqSecretFor(pq, g)) : mk0);
  if (msg.header.pq) assert.ok(pqSecretFor(pq, g) != null, 'pq message without a shared secret');
  // The peer proves it holds the CURRENT generation's secret only when the
  // message is of that generation (an in-flight older one does not count).
  const ackIfCurrent = () => { if (msg.header.pq && g === (pq.gen || 0)) pq.acked = true; };
  const key = `${msg.header.dh}|${msg.header.n}`;
  if (s.skipped.has(key)) {
    const mk = s.skipped.get(key); s.skipped.delete(key);
    const plain = unpad7816(xchachaOpen(use(mk), msg.nonce, msg.ct, msg.mac, aad));
    ackIfCurrent();
    return plain;
  }
  const theirPub = unb64(msg.header.dh);
  if (!s.dhrPub || !s.dhrPub.equals(theirPub)) {
    drSkip(s, msg.header.pn);
    drDhStep(s, theirPub, draws.shift());
  }
  drSkip(s, msg.header.n);
  const [mk, next] = kdfCk(s.ckr);
  const plain = unpad7816(xchachaOpen(use(mk), msg.nonce, msg.ct, msg.mac, aad));
  ackIfCurrent();
  s.ckr = next; s.nr += 1;
  return plain;
}

function stateHex(s) {
  return {
    root_key: hex(s.rootKey), dhs_seed: hex(s.dhsSeed), dhs_pub: hex(s.dhsPub),
    dhr_pub: s.dhrPub ? hex(s.dhrPub) : null, cks: s.cks ? hex(s.cks) : null, ckr: s.ckr ? hex(s.ckr) : null,
    ns: s.ns, nr: s.nr, pn: s.pn,
    skipped: Object.fromEntries([...s.skipped].map(([k, v]) => [k, hex(v)])),
  };
}

test('ratchet: full transcript replays byte-for-byte (both roles)', () => {
  const r = load('ratchet');
  const A = who[r.initiator], B = who[r.responder];
  const steps = Object.fromEntries(r.steps.map((s) => [s.mid, s]));
  assert.equal(r.steps.length, 6);
  assert.equal(r.transcript.length, 12);
  assert.equal(r.transcript.filter((o) => o.op === 'decrypt' && steps[o.mid].receive.dh_ratchet_step).length, 3, 'three DH ratchet steps');
  assert.ok(r.steps.some((s) => Object.keys(s.receive.state_after.skipped).length > 0), 'out-of-order case present');
  const conv = { alice: { sessions: {}, receivedAny: false }, bob: { sessions: {} } };

  for (const op of r.transcript) {
    const step = steps[op.mid];
    const draws = (op.op === 'encrypt' ? step.random_draws : step.receive.random_draws).map(unhex);
    const plaintext = unhex(step.plaintext);
    const me = conv[op.by];

    if (op.op === 'encrypt') {
      let sess = me.sessions[step.sid];
      let ekPub = null;
      if (!sess) {
        // Initiator opens the session: draws = ekSeed, dhsSeed, nonce.
        assert.equal(op.by, r.initiator);
        const ekSeed = draws.shift();
        ekPub = xPub(ekSeed);
        assert.equal(hex(ekPub), r.handshake.ek_pub);
        const dh1 = x25519(unhex(A.x_seed), unhex(B.x_pub));
        const dh2 = x25519(ekSeed, unhex(B.x_pub));
        const sk = hkdf(cat(Buffer.alloc(32, 0xff), dh1, dh2), Buffer.alloc(32), utf8('Z-X3DH-v1'), 32);
        assert.equal(hex(sk), r.handshake.sk);
        const ad = sha256(cat(utf8('Z-AD-v1'), unhex(A.ed_pub), unhex(B.ed_pub)));
        assert.equal(hex(ad), r.handshake.ad);
        sess = makeSession(ad);
        sess.dhsSeed = draws.shift();
        sess.dhsPub = xPub(sess.dhsSeed);
        sess.dhrPub = unhex(B.x_pub);
        [sess.rootKey, sess.cks] = kdfRk(sk, x25519(sess.dhsSeed, sess.dhrPub));
        assert.equal(hex(sess.rootKey), r.initiator_init.root_key);
        assert.equal(hex(sess.cks), r.initiator_init.cks);
        sess.ekPub = ekPub; sess.initiator = true;
        me.sessions[step.sid] = sess;
        assert.equal(b64url(sha256(ekPub)).slice(0, 22), step.sid);
      }
      assert.equal(hex(sess.cks), step.ck_before);
      const m = drEncrypt(sess, plaintext, draws.shift());
      assert.equal(draws.length, 0, 'all draws consumed');
      assert.equal(hex(m.mk), step.mk);
      assert.equal(hex(sess.cks), step.ck_after);
      assert.deepEqual(m.header, step.header);
      assert.equal(hex(headerBytes(m.header)), step.header_bytes);
      assert.equal(hex(m.ct), step.ciphertext);
      assert.equal(hex(m.mac), step.mac);
      // Transport payload: exact JSON key order, then base64.
      const payload = { v: 1, t: 'r', sid: step.sid };
      if (sess.initiator && !me.receivedAny) payload.ek = b64(sess.ekPub);
      Object.assign(payload, { h: m.header, n: b64(m.nonce), ct: b64(m.ct), mac: b64(m.mac) });
      assert.equal('ek' in payload, step.ek_attached);
      assert.equal(JSON.stringify(payload), step.payload_json);
      assert.equal(b64(utf8(JSON.stringify(payload))), step.payload);
      assert.deepEqual(stateHex(sess), step.sender_state_after);
    } else {
      const j = JSON.parse(unb64(step.payload).toString('utf8'));
      assert.equal(j.v, 1); assert.equal(j.t, 'r');
      let sess = me.sessions[j.sid];
      if (!sess) {
        // Responder accepts from the attached ek.
        assert.ok(j.ek, 'first message must carry ek');
        assert.equal(b64url(sha256(unb64(j.ek))).slice(0, 22), j.sid);
        const my = who[op.by], their = who[op.by === 'alice' ? 'bob' : 'alice'];
        const dh1 = x25519(unhex(my.x_seed), unhex(their.x_pub));
        const dh2 = x25519(unhex(my.x_seed), unb64(j.ek));
        const sk = hkdf(cat(Buffer.alloc(32, 0xff), dh1, dh2), Buffer.alloc(32), utf8('Z-X3DH-v1'), 32);
        assert.equal(hex(sk), r.handshake.sk);
        sess = makeSession(sha256(cat(utf8('Z-AD-v1'), unhex(their.ed_pub), unhex(my.ed_pub))));
        sess.rootKey = sk; sess.dhsSeed = unhex(my.x_seed); sess.dhsPub = unhex(my.x_pub);
        me.sessions[j.sid] = sess;
        assert.equal(step.receive.created_session, true);
      }
      const msg = { header: j.h, nonce: unb64(j.n), ct: unb64(j.ct), mac: unb64(j.mac) };
      const before = stateHex(sess);
      if (step.receive.state_before) assert.deepEqual(before, step.receive.state_before);
      const plain = drDecrypt(sess, msg, draws);
      assert.equal(draws.length, 0, 'all draws consumed');
      assert.equal(hex(plain), step.plaintext);
      assert.equal(plain.toString('utf8'), step.inner_json);
      me.receivedAny = true;
      assert.deepEqual(stateHex(sess), step.receive.state_after);
      if (step.receive.dh_ratchet_step) {
        const d = step.receive.dh_ratchet_step;
        assert.equal(hex(sess.dhsPub), d.new_dhs_pub);
        assert.equal(hex(sess.rootKey), d.root_key_2);
      }
    }
  }
});

// ===========================================================================
test('sealed sender: envelopes seal and open exactly', () => {
  const v = load('sealed_sender');
  assert.deepEqual(v.buckets, SEALED_BUCKETS);
  for (const e of v.vectors) {
    const ephSeed = unhex(e.eph_seed), ephPub = xPub(ephSeed), toPub = unhex(e.to_x_pub);
    assert.equal(hex(ephPub), e.eph_pub);
    const shared = x25519(ephSeed, toPub);
    assert.equal(hex(shared), e.shared);
    assert.equal(hex(x25519(unhex(e.to_x_seed), ephPub)), e.shared, 'recipient side');
    const info = cat(utf8('z-sealed-v1'), ephPub, toPub);
    assert.equal(hex(info), e.hkdf_info);
    const key = hkdf(shared, Buffer.alloc(0), info, 32);
    assert.equal(hex(key), e.key);
    const inner = JSON.stringify({ f: e.from_rid, p: e.payload });
    assert.equal(inner, e.inner_json);
    const padded = padSealed(utf8(inner));
    assert.equal(padded.length, e.bucket);
    const nonce = unhex(e.nonce);
    const { ct, mac } = chachaSeal(key, nonce, padded, utf8(e.aad));
    assert.equal(hex(sha256(ct)), e.ciphertext_sha256);
    assert.equal(hex(mac), e.mac);
    const envelope = 'zs1.' + b64url(cat(ephPub, nonce, ct, mac));
    assert.equal(envelope, e.envelope, `${e.name}: envelope string`);
    // Open as the recipient.
    const raw = unb64url(e.envelope.slice(4));
    const k2 = hkdf(x25519(unhex(e.to_x_seed), raw.subarray(0, 32)), Buffer.alloc(0),
      cat(utf8('z-sealed-v1'), raw.subarray(0, 32), toPub), 32);
    const plain = unpadSealed(chachaOpen(k2, raw.subarray(32, 44), raw.subarray(44, raw.length - 16), raw.subarray(raw.length - 16), utf8('z-sealed-v1')));
    assert.deepEqual(JSON.parse(plain.toString('utf8')), { f: e.from_rid, p: e.payload });
    // Wrong recipient: authentication must fail.
    const wrong = who[e.wrong_recipient];
    const k3 = hkdf(x25519(unhex(wrong.x_seed), raw.subarray(0, 32)), Buffer.alloc(0),
      cat(utf8('z-sealed-v1'), raw.subarray(0, 32), unhex(wrong.x_pub)), 32);
    assert.throws(() => chachaOpen(k3, raw.subarray(32, 44), raw.subarray(44, raw.length - 16), raw.subarray(raw.length - 16), utf8('z-sealed-v1')));
  }
});

// ===========================================================================
test('attachments: chunk AEAD, nonce layout and payload', () => {
  const v = load('attachments');
  assert.equal(v.fid, b64url(unhex(v.fid_bytes)));
  const fk = unhex(v.fk), fn = unhex(v.fn);
  for (const c of v.chunks) {
    const nonce = Buffer.alloc(24);
    fn.copy(nonce);
    nonce.writeBigUInt64LE(BigInt(c.index), 16);
    assert.equal(hex(nonce), c.nonce, `chunk ${c.index} nonce`);
    assert.equal(c.aad, `z-file-v1:${v.fid}`);
    const { ct, mac } = xchachaSeal(fk, nonce, unhex(c.plaintext), utf8(c.aad));
    assert.equal(hex(ct), c.ciphertext);
    assert.equal(hex(mac), c.mac);
    const payload = JSON.stringify({ v: 1, t: 'f', fid: v.fid, idx: c.index, ct: b64(ct), mac: b64(mac) });
    assert.equal(payload, c.payload_json);
    assert.equal(b64(utf8(payload)), c.payload);
    assert.equal(hex(xchachaOpen(fk, nonce, ct, mac, utf8(c.aad))), c.plaintext);
  }
  const se = v.split_example;
  const lens = [];
  for (let off = 0; off < se.file_len; off += se.chunk_size) lens.push(Math.min(se.chunk_size, se.file_len - off));
  assert.deepEqual(lens, se.chunk_lens);
});

// ===========================================================================
const certInput = (ded, dx, id) => cat(utf8('z-device-cert-v1:'), ded, dx, utf8(id));

// A signed device list (§3.4) as a reader takes it, from the list's JSON and
// nothing else. It has one of three shapes, and only three: `sig` alone
// (before ADR 0010), `sig` and `sig2` (dual-signed, stage 1), or `sig3` alone
// (v2-only, ADR 0017 stage 2). A signature member that is present is a
// signature: one present with any other value, null included, makes the list
// malformed. Any other combination — `sig2` alone, which is
// what deleting `sig` from a dual-signed list leaves; `sig3` beside another
// signature; none — is refused before a signature is checked. Each signature
// is over its own input: `sig` over v1, `sig2` over v2, `sig3` over v3, which
// is the v2 content under its own context, `z-devlist-v3:`, so that no `sig2`
// can stand alone. What the list commits to — the input its fingerprint is
// taken over and its ML-DSA is made over — follows the strongest signature
// that is alone: the v1 input while `sig` is carried, the v3 input once `sig3`
// is alone.
const u16 = (n) => Buffer.from([(n >> 8) & 0xff, n & 0xff]);
const devlistV1Input = (l) => cat(utf8('z-devlist-v1:'), utf8(`${l.ver}:`),
  ...l.devs.map((d) => unb64(d.ded)).sort(Buffer.compare));
const devlistV2Content = (context, l) => cat(utf8(context), utf8(`${l.ver}:`),
  ...[...l.devs].sort((p, q) => Buffer.compare(unb64(p.ded), unb64(q.ded)))
    .flatMap((d) => [unb64(d.ded), unb64(d.dx), u16(Buffer.byteLength(d.id)), utf8(d.id)]));
const devlistV2Input = (l) => devlistV2Content('z-devlist-v2:', l);
const devlistV3Input = (l) => devlistV2Content('z-devlist-v3:', l);
const devlistShape = (l) => ['sig', 'sig2', 'sig3'].filter((k) => k in l).join('+');
const devlistShapes = new Set(['sig', 'sig+sig2', 'sig3']);
const devlistCommitted = (l) => (devlistShape(l) === 'sig3' ? devlistV3Input(l) : devlistV1Input(l));
const devlistFingerprint = (l) => sha256(devlistCommitted(l)).subarray(0, 16);
const devlistSigMembersWellFormed = (l) =>
  ['sig', 'sig2', 'sig3'].every((k) => !(k in l) || typeof l[k] === 'string');
function devlistAdmitted(l, acctPub) {
  if (!devlistSigMembersWellFormed(l)) return false;
  if (!devlistShapes.has(devlistShape(l))) return false;
  if (!unb64(l.acct).equals(acctPub) || l.devs.length === 0) return false;
  for (const d of l.devs) {
    if (!edVerify(acctPub, certInput(unb64(d.ded), unb64(d.dx), d.id), unb64(d.sig))) return false;
  }
  if ('sig' in l && !edVerify(acctPub, devlistV1Input(l), unb64(l.sig))) return false;
  if ('sig2' in l && !edVerify(acctPub, devlistV2Input(l), unb64(l.sig2))) return false;
  if ('sig3' in l && !edVerify(acctPub, devlistV3Input(l), unb64(l.sig3))) return false;
  return true;
}
// Every signature [l] carries is genuine over its own input — what makes a
// list refused for its shape refused for nothing else.
const devlistSigsGenuine = (l, acctPub) =>
  (!('sig' in l) || edVerify(acctPub, devlistV1Input(l), unb64(l.sig))) &&
  (!('sig2' in l) || edVerify(acctPub, devlistV2Input(l), unb64(l.sig2))) &&
  (!('sig3' in l) || edVerify(acctPub, devlistV3Input(l), unb64(l.sig3)));

test('multidevice: device certificates, zc2 account code, signed device list', () => {
  const v = load('multidevice');
  const acctSeed = unhex(v.account_ed_seed), acctPub = unhex(v.account_ed_pub);
  assert.equal(hex(edPub(acctSeed)), v.account_ed_pub);
  assert.equal(v.account_id, routingId(acctPub));
  // Device #1's Ed25519 key IS the account key.
  assert.equal(v.device1.device_ed_pub, v.account_ed_pub);
  assert.equal(v.device1.device_id, b64url(unhex(v.device1.device_id_bytes)));
  for (const d of [v.device1, v.device2]) {
    assert.equal(hex(edPub(unhex(d.ed_seed))), d.device_ed_pub);
    assert.equal(hex(xPub(unhex(d.x_seed))), d.device_x_pub);
    const input = certInput(unhex(d.device_ed_pub), unhex(d.device_x_pub), d.device_id);
    assert.equal(hex(input), d.signing_input);
    assert.equal(hex(edSign(acctSeed, input)), d.sig);
    assert.ok(edVerify(acctPub, input, unhex(d.sig)));
    assert.equal(d.routing_id, routingId(unhex(d.device_ed_pub)));
    assert.deepEqual(d.json, { ded: b64(unhex(d.device_ed_pub)), dx: b64(unhex(d.device_x_pub)), id: d.device_id, sig: b64(unhex(d.sig)) });
  }
  // Account code.
  assert.ok(v.account_code.startsWith('zc2.'));
  const code = JSON.parse(unb64url(v.account_code.slice(4)).toString('utf8'));
  assert.deepEqual(code, JSON.parse(v.account_code_json));
  assert.equal(code.v, 2);
  assert.equal(hex(unb64(code.acct)), v.account_ed_pub);
  assert.equal(code.devs.length, 2);
  for (const d of code.devs) {
    assert.ok(edVerify(acctPub, certInput(unb64(d.ded), unb64(d.dx), d.id), unb64(d.sig)), `cert ${d.id}`);
  }
  // Signed device list: keys sorted lexicographically regardless of input order.
  const dl = v.device_list;
  const eds = [unhex(v.device1.device_ed_pub), unhex(v.device2.device_ed_pub)].sort(Buffer.compare);
  const input = cat(utf8('z-devlist-v1:'), utf8(`${dl.version}:`), ...eds);
  assert.equal(hex(input), dl.signing_input);
  assert.equal(hex(edSign(acctSeed, input)), dl.sig);
  assert.ok(edVerify(acctPub, input, unhex(dl.sig)));
  assert.equal(dl.json.ver, dl.version);
  assert.equal(hex(unb64(dl.json.sig)), dl.sig);
  // ADR 0010: the list also carries sig2, the account's Ed25519 over the v2
  // input — the same order of devices, each contributing ded || dx ||
  // u16be(len(id)) || id — so the signature covers the ratchet keys too.
  const u16be = (n) => Buffer.from([(n >> 8) & 0xff, n & 0xff]);
  const dcerts = [v.device1, v.device2]
    .map((x) => ({
      ded: unhex(x.device_ed_pub),
      dx: unhex(x.device_x_pub),
      id: x.device_id,
    }))
    .sort((a, b) => Buffer.compare(a.ded, b.ded));
  const inputV2 = cat(utf8('z-devlist-v2:'), utf8(`${dl.version}:`),
    ...dcerts.flatMap((d) => [d.ded, d.dx, u16be(Buffer.byteLength(d.id)), utf8(d.id)]));
  assert.equal(hex(inputV2), dl.signing_input_v2, 'v2 signing input');
  assert.equal(hex(edSign(acctSeed, inputV2)), dl.sig2, 'sig2');
  assert.ok(edVerify(acctPub, inputV2, unhex(dl.sig2)));
  assert.equal(hex(unb64(dl.json.sig2)), dl.sig2);
  // 7.7a device-list fingerprint: SHA-256(signing_input)[0..16], over the v1
  // input for as long as a v1 signature is produced — which is always today.
  // It briefly followed the format the list was signed under, but a v2
  // fingerprint and a v1 one for the same list is the disagreement a
  // not-yet-updated contact reads as an attack, so both sides compute v1 and
  // fingerprint_v1 holds the same value. sig2 is still signed, carried and
  // verified above; only what is gossiped and compared reverted.
  assert.equal(hex(sha256(input).subarray(0, 16)), dl.fingerprint_v1);
  assert.equal(hex(sha256(input).subarray(0, 16)), dl.fingerprint);
  // The same, by the rule a reader applies to any list: it carries `sig`, so
  // it commits to the v1 input.
  assert.ok(devlistAdmitted(dl.json, acctPub), 'a reader admits the dual-signed list');
  assert.equal(hex(devlistFingerprint(dl.json)), dl.fingerprint);

  // ADR 0017 stage 2: the account's list at the next version, v2-only —
  // `sig3` alone. Rebuilt from its JSON: it commits to the v3 input, the v2
  // content under its own context, and the fingerprint a reader reports — and
  // a log leaf carries — is SHA-256 of that, not of the v1 or v2 input.
  const v2o = v.device_list_v2_only;
  assert.equal(devlistShape(v2o.json), 'sig3', 'sig3 and nothing else on the wire');
  assert.equal(v2o.json.ver, v2o.version);
  assert.equal(v2o.version, dl.version + 1, 'republished at the next version');
  assert.deepEqual(v2o.json.devs, dl.json.devs, 'over the same devices');
  assert.ok(devlistAdmitted(v2o.json, acctPub), 'a reader admits it on sig3 alone');
  assert.equal(hex(devlistCommitted(v2o.json)), v2o.signing_input_v3);
  assert.equal(devlistV3Input(v2o.json).subarray(0, 13).toString(), 'z-devlist-v3:');
  assert.ok(devlistV3Input(v2o.json).subarray(13).equals(devlistV2Input(v2o.json).subarray(13)),
    'the v3 input is the v2 content under a context of its own');
  assert.equal(hex(edSign(acctSeed, devlistV3Input(v2o.json))), v2o.sig3, 'sig3 reproduced');
  assert.equal(hex(devlistFingerprint(v2o.json)), v2o.fingerprint);
  assert.equal(hex(sha256(devlistV1Input(v2o.json)).subarray(0, 16)), v2o.v1_fingerprint_not_reported);
  assert.equal(hex(sha256(devlistV2Input(v2o.json)).subarray(0, 16)), v2o.v2_fingerprint_not_reported);
  assert.equal(new Set([v2o.fingerprint, v2o.v1_fingerprint_not_reported,
    v2o.v2_fingerprint_not_reported]).size, 3, 'three inputs, three fingerprints');
  const mr = v2o.must_refuse;
  // Refused: no signature at all.
  const bare = mr.no_signature_json;
  assert.equal(devlistShape(bare), '');
  assert.ok(!devlistAdmitted(bare, acctPub), 'a list with no signature is refused');
  // Refused: second-device's ratchet key replaced by the attacker's, its
  // certificate re-signed by the account key, the genuine sig3 kept. The
  // attacker's key is derived here from its recorded seed.
  const sw = mr.swapped_ratchet_key;
  assert.equal(hex(xPub(unhex(sw.attacker_x_seed))), sw.attacker_x_pub);
  const moved = sw.json.devs.find((d) => d.id === sw.device_id);
  assert.equal(hex(unb64(moved.dx)), sw.attacker_x_pub);
  assert.ok(edVerify(acctPub, certInput(unb64(moved.ded), unb64(moved.dx), moved.id), unb64(moved.sig)),
    'the substituted certificate is itself well signed');
  assert.equal(sw.json.sig3, v2o.json.sig3, 'the genuine sig3, replayed');
  assert.ok(!devlistAdmitted(sw.json, acctPub), 'a replaced deviceXPub is refused');
  assert.equal(hex(devlistCommitted(sw.json)), sw.signing_input_v3);
  assert.equal(hex(devlistFingerprint(sw.json)), sw.fingerprint);
  assert.notEqual(sw.fingerprint, v2o.fingerprint, 'the v3 fingerprint moves with the key');
  assert.ok(devlistV1Input(sw.json).equals(devlistV1Input(v2o.json)),
    'which a v1 fingerprint could not have seen');
  // Refused: the dual-signed list above with `sig` deleted — made here from
  // that list and compared with the recorded one. The sig2 left behind is
  // genuine and verifies over its own input; only the shape refuses it.
  const stripped = { ...dl.json };
  delete stripped.sig;
  assert.deepEqual(stripped, mr.sig_stripped_json, 'the recorded list is dl.json without sig');
  assert.equal(devlistShape(stripped), 'sig2');
  assert.ok(devlistSigsGenuine(stripped, acctPub), 'its sig2 is genuine');
  assert.ok(!devlistAdmitted(stripped, acctPub), 'a dual-signed list with sig deleted is refused');
  // Refused: the same sig2 moved into sig3, where it would have to be over
  // the v3 input.
  const relabelled = mr.sig2_as_sig3_json;
  assert.equal(relabelled.sig3, dl.json.sig2);
  assert.equal(devlistShape(relabelled), 'sig3');
  assert.ok(!devlistAdmitted(relabelled, acctPub), 'a sig2 presented as sig3 is refused');
  // Refused: every other combination of the three, each signature genuine,
  // so each list is refused for its shape and for nothing else.
  assert.deepEqual(mr.other_shapes.map((s) => s.shape).sort(),
    ['sig+sig2+sig3', 'sig+sig3', 'sig2', 'sig2+sig3']);
  for (const s of mr.other_shapes) {
    assert.equal(devlistShape(s.json), s.shape);
    assert.ok(devlistSigsGenuine(s.json, acctPub), `every signature in {${s.shape}} is genuine`);
    assert.ok(!devlistAdmitted(s.json, acctPub), `a {${s.shape}} list is refused`);
  }
  // Refused: a valid list with a signature member added as null. Read as
  // absent, every one of them would be admitted — which is why present means
  // a signature, and a null member makes the list malformed.
  assert.equal(mr.null_members.length, 5);
  assert.ok(mr.null_members.some((s) => s.member === 'sig3' && 'sig' in s.json && 'sig2' in s.json),
    '{sig, sig2, "sig3": null} is among them');
  assert.ok(mr.null_members.some((s) => s.member === 'sig' && 'sig3' in s.json),
    '{"sig": null, sig3} is among them');
  for (const s of mr.null_members) {
    assert.ok(s.member in s.json && s.json[s.member] === null, `a null ${s.member}`);
    assert.ok(!devlistSigMembersWellFormed(s.json), `a null ${s.member} is not a signature`);
    assert.ok(!devlistAdmitted(s.json, acctPub), `a list with a null ${s.member} is refused`);
    const readAsAbsent = { ...s.json };
    delete readAsAbsent[s.member];
    assert.ok(devlistAdmitted(readAsAbsent, acctPub),
      `with the null ${s.member} read as absent it would have been admitted`);
  }
  // Legacy zc1 read as a one-device account.
  const legacy = v.legacy_zc1_as_account;
  const lj = JSON.parse(unb64url(legacy.contact_code.slice(4)).toString('utf8'));
  assert.equal(hex(unb64(lj.ed)), legacy.account_ed_pub);
  assert.equal(legacy.device_id, 'legacy-v1');
  assert.equal(legacy.legacy, true);
});

// ===========================================================================
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32(buf) {
  let bits = 0, acc = 0, out = '';
  for (const b of buf) {
    acc = (acc << 8) | b; bits += 8;
    while (bits >= 5) { bits -= 5; out += B32[(acc >> bits) & 31]; }
  }
  if (bits > 0) out += B32[(acc << (5 - bits)) & 31];
  return out;
}

test('pairing: code, rendezvous, relay identities, channel key, SAS, enrollment', () => {
  const v = load('pairing');
  const secret = unhex(v.pairing_code.secret);
  const text = base32(secret).match(/.{1,5}/g).join('-');
  assert.equal(text, v.pairing_code.text);
  const rin = cat(utf8('z-pair-rendezvous-v1:'), secret);
  assert.equal(hex(rin), v.pairing_code.rendezvous_input);
  assert.equal(b64url(sha256(rin)), v.pairing_code.rendezvous_routing_id);
  for (const role of ['i', 'r']) {
    const ri = v.relay_identities[role];
    assert.equal(ri.hkdf_info, `z-pair-relay:${role}`);
    const okm = hkdf(secret, Buffer.alloc(0), utf8(ri.hkdf_info), 64);
    assert.equal(hex(okm), ri.hkdf_okm);
    assert.equal(hex(okm.subarray(0, 32)), ri.ed_seed);
    assert.equal(hex(okm.subarray(32)), ri.x_seed);
    assert.equal(hex(edPub(okm.subarray(0, 32))), ri.ed_pub);
    assert.equal(ri.routing_id, routingId(unhex(ri.ed_pub)));
  }
  const nd = v.new_device, ed = v.existing_device;
  assert.equal(hex(edPub(unhex(nd.device_ed_seed))), nd.device_ed_pub);
  assert.equal(hex(xPub(unhex(nd.device_x_seed))), nd.device_x_pub);
  assert.equal(hex(xPub(unhex(nd.eph_seed))), nd.eph_pub);
  assert.deepEqual(nd.hello, { ephx: b64(unhex(nd.eph_pub)), ded: b64(unhex(nd.device_ed_pub)), dx: b64(unhex(nd.device_x_pub)), id: nd.device_id });
  assert.equal(hex(xPub(unhex(ed.eph_seed))), ed.eph_pub);
  assert.deepEqual(ed.reply, { ephx: b64(unhex(ed.eph_pub)) });
  const dh = x25519(unhex(nd.eph_seed), unhex(ed.eph_pub));
  assert.equal(hex(dh), v.dh);
  assert.equal(hex(x25519(unhex(ed.eph_seed), unhex(nd.eph_pub))), v.dh);
  const channelKey = hkdf(dh, Buffer.alloc(32), utf8('z-pair-channel-v1'), 32);
  assert.equal(hex(channelKey), v.channel_key);
  const [lo, hi] = [unhex(nd.eph_pub), unhex(ed.eph_pub)].sort(Buffer.compare);
  assert.equal(hex(cat(lo, hi)), v.sas_salt);
  const sasInfo = cat(utf8('z-pair-sas-v1'), unhex(nd.device_ed_pub));
  assert.equal(hex(sasInfo), v.sas_info);
  const okm = hkdf(dh, cat(lo, hi), sasInfo, 8);
  assert.equal(hex(okm), v.sas_okm);
  const n = (((okm[0] << 24) | (okm[1] << 16) | (okm[2] << 8) | okm[3]) >>> 0) & 0x7fffffff;
  const digits = String(n % 1000000).padStart(6, '0');
  assert.equal(`${digits.slice(0, 3)} ${digits.slice(3)}`, v.sas);
  // Enrollment blob: ChaCha20-Poly1305, nonce(12) || ct || mac(16), no AAD.
  const en = v.enrollment;
  const sealed = unhex(en.sealed);
  assert.equal(hex(sealed.subarray(0, 12)), en.nonce);
  const plain = chachaOpen(channelKey, sealed.subarray(0, 12), sealed.subarray(12, sealed.length - 16), sealed.subarray(sealed.length - 16), null);
  assert.equal(plain.toString('utf8'), en.plaintext);
  const j = JSON.parse(en.plaintext);
  assert.equal(hex(unb64(j.acct)), v.account.account_ed_pub);
  assert.equal(j.root, undefined, 'account root withheld');
  const cin = certInput(unhex(nd.device_ed_pub), unhex(nd.device_x_pub), nd.device_id);
  assert.equal(hex(cin), en.new_device_cert_signing_input);
  assert.equal(hex(unb64(j.cert.sig)), en.new_device_cert_sig);
  assert.ok(edVerify(unhex(v.account.account_ed_pub), cin, unb64(j.cert.sig)));
  assert.equal(hex(edSign(unhex(v.account.account_ed_seed), cin)), en.new_device_cert_sig);
  assert.deepEqual(j.hostcert, v.account.device_cert_json);
  assert.equal(j.contacts.length, 1);
  assert.deepEqual(en.enroll_frame, { k: 'enroll', blob: b64(sealed) });
});

// ===========================================================================
const INNER_SCHEMA = {
  hello: [],
  text: ['body'],
  timer: ['sec'],
  read: ['mids'],
  file: ['fid', 'name', 'size', 'mime', 'sha256', 'fk', 'fn', 'chunks'],
  dlv: ['mids'],
  devlist: ['list'],
  ginvite: ['gid', 'name', 'ver', 'members'],
  gmsg: ['gid', 'body'],
  gfile: ['gid', 'fid', 'name', 'size', 'mime', 'sha256', 'fk', 'fn', 'chunks'],
  gleave: ['gid'],
  dlrm: ['acct', 'v', 'h'], // 7.7a device-list removal notice
  react: ['rt', 'emo'], // 8.1b reaction; 'rt' names the target message
  greact: ['gid', 'rt', 'emo'],
  edit: ['rt', 'body'], // 8.1c edit of the sender's own message
  gedit: ['gid', 'rt', 'body'],
  del: ['mids'], // 8.1c delete-for-everyone of the sender's own messages
  gdel: ['gid', 'mids'],
  gsync: ['gid'], // ADR 0019: a member asking for what it lacks — keyless
  gjoin: ['t', 'go'], // ADR 0020: a joiner's answer to a group invite link; names no group
};

// §11.1: a routing id as `owner` and `admins` carry one — 43 base64url
// characters, never empty.
const RID = /^[A-Za-z0-9_-]{43}$/;

test('inner messages: every kind parses with its required fields', () => {
  const v = load('inner_messages');
  const seen = new Set();
  for (const m of v.vectors) {
    assert.equal(hex(utf8(m.json)), m.bytes);
    const j = JSON.parse(m.json);
    assert.equal(j.k, m.kind);
    assert.equal(typeof j.mid, 'string');
    assert.equal(typeof j.ts, 'number');
    for (const f of INNER_SCHEMA[m.kind]) assert.ok(f in j, `${m.kind} needs ${f}`);
    // 7.7a: the optional device-list claim/echo, where present, are {v, h}.
    for (const k of ['dl', 'pdl']) {
      if (k in j) {
        assert.equal(typeof j[k].v, 'number', `${k}.v`);
        assert.equal(typeof j[k].h, 'string', `${k}.h`);
      }
    }
    // 7.4: a voice-note offer flags voice:true with a numeric duration.
    if ('voice' in j) {
      assert.equal(j.voice, true);
      assert.equal(typeof j.dur, 'number');
    }
    // 8.1b: a reaction is a bounded badge — one target, one short emoji,
    // never a second text channel.
    if (j.k === 'react' || j.k === 'greact') {
      assert.equal(typeof j.emo, 'string');
      assert.ok(j.emo.length <= 32, 'emoji stays a badge');
      assert.ok(![...j.emo].some((c) => c.codePointAt(0) < 0x20), 'no control chars');
      assert.ok(typeof j.rt === 'string' && j.rt.length <= 64, 'target is an id');
      assert.ok(!('body' in j), 'a reaction carries no text');
    }
    // 8.1c: a delete names ids only, and a bounded number of them.
    if (j.k === 'del' || j.k === 'gdel') {
      assert.ok(Array.isArray(j.mids) && j.mids.length > 0, 'mids is a list');
      assert.ok(j.mids.length <= 256, 'bounded');
      for (const m2 of j.mids) {
        assert.ok(typeof m2 === 'string' && m2.length <= 64, 'an id');
      }
    }
    // §11.1: a list's roles, where it carries them, are routing ids and a
    // whole roles version — the owner among the admins.
    if (j.k === 'ginvite' && 'owner' in j) {
      assert.ok(RID.test(j.owner), 'owner is a routing id');
      assert.ok(Array.isArray(j.admins) && j.admins.every((a) => RID.test(a)));
      assert.ok(j.admins.includes(j.owner), 'the owner is an admin');
      assert.ok(Number.isInteger(j.rv) && j.rv >= 0, 'rv is a whole number');
    }
    // §6.2: `gsync` says which group and nothing else.
    if (j.k === 'gsync') {
      assert.deepEqual(Object.keys(j).sort(), ['gid', 'k', 'mid', 'ts']);
    }
    // §6.2, ADR 0020: `gjoin` names no group at all — only the receiver
    // knows which group its link was for. It carries the ceremony's go-ahead
    // tag, sixteen bytes as unpadded base64url, and the answer: 1 to join,
    // 0 to stay a contact only.
    if (j.k === 'gjoin') {
      assert.deepEqual(Object.keys(j).sort(), ['go', 'k', 'mid', 't', 'ts']);
      assert.ok(/^[A-Za-z0-9_-]{22}$/.test(j.t), 't is 16 bytes, base64url');
      assert.equal(Buffer.from(j.t, 'base64url').length, 16);
      assert.ok(j.go === 0 || j.go === 1, 'go is 0 or 1');
    }
    // A forward marker is a boolean flag, never a provenance claim about who
    // originally wrote the message.
    if ('fw' in j) {
      assert.equal(j.fw, true);
      assert.ok(!('from' in j) && !('origin' in j), 'no attributed origin');
    }
    // 8.1: a reply carries the quoted message's id and nothing else of it —
    // in particular no copy of the quoted text.
    if ('rt' in j) {
      assert.ok(
        ['text', 'file', 'gmsg', 'gfile', 'react', 'greact', 'edit', 'gedit']
          .includes(j.k),
        'rt names a target only on a content kind, reaction or edit');
      assert.equal(typeof j.rt, 'string');
      assert.ok(j.rt.length > 0 && j.rt.length <= 64, 'rt is an id, not a payload');
      assert.ok(!('rtbody' in j) && !('quote' in j), 'no quoted text on the wire');
    }
    assert.equal(m.padded_len, Math.ceil((utf8(m.json).length + 1) / 256) * 256);
    seen.add(m.kind);
  }
  assert.deepEqual([...seen].sort(), Object.keys(INNER_SCHEMA).sort());
  const s = JSON.parse(v.sync_envelope.json);
  assert.deepEqual(Object.keys(s), ['thread', 'dir', 'inner']);
  assert.equal(JSON.parse(unb64(s.inner).toString('utf8')).k, 'text');
});

// §11.1: the digest that ranks two lists at one (rv, ver), re-derived from
// the section's words: the compact JSON of [gid, name, ver, rv, owner,
// admins, members] — each as the list carries it, null where it leaves it
// out; admins sorted; members replaced by their entries' `ed` strings,
// sorted — strings sorted by UTF-16 code unit (what `sort()` does) and
// escaped as JSON.stringify escapes them, which is the escaping §11.1 pins
// (`"` and `\`, the five short control escapes, \u00xx for the rest below
// U+0020 and for an unpaired surrogate, nothing else); then SHA-256 over the
// UTF-8 and unpadded base64url. One of the three lists needs every escape.
test('group list digests: canonical JSON and SHA-256, from §11.1 alone', () => {
  const v = load('inner_messages');
  assert.equal(v.group_list_digests.length, 3);
  for (const d of v.group_list_digests) {
    const l = JSON.parse(d.list);
    const members = (Array.isArray(l.members) ? l.members : [])
      .filter((m) => m && typeof m.b === 'object' && m.b && typeof m.b.ed === 'string')
      .map((m) => m.b.ed)
      .sort();
    const admins = Array.isArray(l.admins)
      ? l.admins.filter((a) => typeof a === 'string').sort()
      : null;
    const canonical = JSON.stringify([
      l.gid ?? null,
      l.name ?? null,
      l.ver ?? null,
      l.rv ?? null,
      l.owner ?? null,
      admins,
      members,
    ]);
    assert.equal(canonical, d.canonical);
    assert.equal(hex(utf8(canonical)), d.canonical_hex);
    assert.equal(b64url(sha256(utf8(canonical))), d.digest);
  }
});

// ===========================================================================
// v2 — post-quantum hybrid (§17). The ML-KEM operations themselves are
// verified by protocol/tool/verify_mlkem.py (kyber-py); this replay takes the
// shared secret K and ciphertext c from the vector and checks everything
// built on them: the pqek offer message, the header extension, the
// message-key mixing, when the ciphertext rides and when it stops.
// ===========================================================================
const V2_DIR = path.join(__dirname, '..', '..', 'docs', 'vectors', 'v2');
const loadV2 = (name) => JSON.parse(fs.readFileSync(path.join(V2_DIR, `${name}.json`), 'utf8'));

test('v2 mlkem768: vector file is well-formed (values checked by kyber-py)', () => {
  const v = loadV2('mlkem768');
  assert.equal(v.suite, 'mlkem768');
  assert.equal(v.vectors.length, 10);
  for (const x of v.vectors) {
    assert.equal(unhex(x.ek).length, 1184);
    assert.equal(unhex(x.dk).length, 2400);
    assert.equal(unhex(x.c).length, 1088);
    assert.equal(unhex(x.K).length, 32);
    assert.notEqual(x.K, x.K_bad, 'implicit rejection yields a different secret');
    assert.notEqual(x.c, x.c_bad);
  }
});

test('v2 pq_ratchet: the upgrade transcript replays byte-for-byte on both sides', () => {
  const r = loadV2('pq_ratchet');
  assert.equal(r.mix_info, 'Z-PQ-MK-v2');
  const K = unhex(r.encapsulation.K), C = unhex(r.encapsulation.c);
  const EK = unhex(r.offer.ek);
  assert.equal(EK.length, 1184); assert.equal(C.length, 1088); assert.equal(K.length, 32);
  const encName = r.encapsulator, offName = r.offerer;
  const E = who[encName], O = who[offName];
  // Roles follow routing-id order: the encapsulator is the lower routing id.
  assert.ok(E.routing_id < O.routing_id, 'encapsulator is the designated initiator');

  const conv = {
    [encName]: { sessions: {}, receivedAny: false, pq: { k: null, ct: null, acked: false } },
    [offName]: { sessions: {}, receivedAny: false, pq: { k: null, ct: null, acked: false, dkSeed: null } },
  };
  const other = (n) => (n === encName ? offName : encName);
  let offerSeen = false;

  const encryptWith = (me, meName, sess, plaintext, draws, sidExpected) => {
    const m = drEncrypt(sess, plaintext, draws.shift(), me.pq);
    const payload = { v: 1, t: 'r', sid: sidExpected };
    if (sess.initiator && !me.receivedAny) payload.ek = b64(sess.ekPub);
    Object.assign(payload, { h: m.header, n: b64(m.nonce), ct: b64(m.ct), mac: b64(m.mac) });
    return { m, payloadStr: b64(utf8(JSON.stringify(payload))) };
  };

  const openSession = (me, meName, j) => {
    // Responder accepts from the attached ek (same as v1).
    assert.ok(j.ek, 'first message must carry ek');
    const my = who[meName], their = who[other(meName)];
    const dh1 = x25519(unhex(my.x_seed), unhex(their.x_pub));
    const dh2 = x25519(unhex(my.x_seed), unb64(j.ek));
    const sk = hkdf(cat(Buffer.alloc(32, 0xff), dh1, dh2), Buffer.alloc(32), utf8('Z-X3DH-v1'), 32);
    const sess = makeSession(sha256(cat(utf8('Z-AD-v1'), unhex(their.ed_pub), unhex(my.ed_pub))));
    sess.rootKey = sk; sess.dhsSeed = unhex(my.x_seed); sess.dhsPub = unhex(my.x_pub);
    me.sessions[j.sid] = sess;
    return sess;
  };

  for (const step of r.steps) {
    const me = conv[step.by];
    const draws = step.random_draws.map(unhex);
    if (step.op === 'encrypt') {
      let sess = me.sessions[step.sid];
      if (!sess) {
        // Encapsulator opens the session: draws = ekSeed, dhsSeed, nonce.
        assert.equal(step.by, encName);
        const their = who[other(step.by)], my = who[step.by];
        const ekSeed = draws.shift();
        const ekPub = xPub(ekSeed);
        const dh1 = x25519(unhex(my.x_seed), unhex(their.x_pub));
        const dh2 = x25519(ekSeed, unhex(their.x_pub));
        const sk = hkdf(cat(Buffer.alloc(32, 0xff), dh1, dh2), Buffer.alloc(32), utf8('Z-X3DH-v1'), 32);
        sess = makeSession(sha256(cat(utf8('Z-AD-v1'), unhex(my.ed_pub), unhex(their.ed_pub))));
        sess.dhsSeed = draws.shift(); sess.dhsPub = xPub(sess.dhsSeed);
        sess.dhrPub = unhex(their.x_pub);
        [sess.rootKey, sess.cks] = kdfRk(sk, x25519(sess.dhsSeed, sess.dhrPub));
        sess.ekPub = ekPub; sess.initiator = true;
        me.sessions[step.sid] = sess;
        assert.equal(b64url(sha256(ekPub)).slice(0, 22), step.sid);
      }
      assert.deepEqual(me.pq.k ? hex(me.pq.k) : null, step.pq_before.k, `pq state before ${step.label}`);
      const { m, payloadStr } = encryptWith(me, step.by, sess, unhex(step.plaintext), draws, step.sid);
      assert.equal(draws.length, 0, 'all draws consumed');
      assert.deepEqual(m.header, step.header, step.label);
      assert.equal(hex(headerBytes(m.header)), step.header_bytes);
      assert.equal(payloadStr, step.payload, `payload ${step.label}`);
      assert.equal(hex(sess.cks), step.ck_after);
    } else {
      const j = JSON.parse(unb64(step.payload).toString('utf8'));
      let sess = me.sessions[j.sid] || openSession(me, step.by, j);
      const msg = { header: j.h, nonce: unb64(j.n), ct: unb64(j.ct), mac: unb64(j.mac) };
      if (msg.header.pqct && !me.pq.k) {
        // Offerer: decapsulation delegated to kyber-py; the vector's K is the
        // decapsulation of exactly this ciphertext.
        assert.equal(step.by, offName);
        assert.ok(me.pq.dkSeed, 'offer must precede a ciphertext');
        assert.equal(hex(unb64(msg.header.pqct)), r.encapsulation.c, 'header pqct is the recorded c');
        me.pq.k = K; me.pq.dkSeed = null;
      }
      const plain = drDecrypt(sess, msg, draws, me.pq);
      me.receivedAny = true;
      assert.equal(hex(plain), step.plaintext, step.label);

      // Encapsulator receiving the offer: encapsulate (delegated) → K, c.
      if (step.by === encName && !me.pq.k && plain.toString('utf8').startsWith('{"k":"pqek"')) {
        const inner = JSON.parse(plain.toString('utf8'));
        assert.equal(inner.alg, 'ML-KEM-768');
        assert.equal(hex(unb64(inner.ek)), r.offer.ek, 'offered ek');
        assert.equal(r.offer.inner_json, plain.toString('utf8'));
        const m32 = draws.shift(); // Encaps_internal randomness m (checked by kyber-py)
        assert.equal(hex(m32), r.encapsulation.m);
        me.pq.k = K; me.pq.ct = C; me.pq.acked = false;
        offerSeen = true;
      }
      // Offerer making its offer after first contact: pqGenerate(64) +
      // newMessageId(16) + the offer's encryption nonce(24).
      if (step.offer_payload) {
        assert.equal(step.by, offName);
        const seed = draws.shift(); const mid = draws.shift();
        assert.equal(hex(seed), r.offer.dk_seed, 'offer seed');
        me.pq.dkSeed = seed;
        const offerInner = utf8(JSON.stringify({ k: 'pqek', mid: b64url(mid), ts: 2, alg: 'ML-KEM-768', ek: b64(EK) }));
        assert.equal(offerInner.toString('utf8'), r.offer.inner_json);
        const { payloadStr } = encryptWith(me, step.by, sess, offerInner, draws, j.sid);
        assert.equal(payloadStr, step.offer_payload, 'offer payload');
      }
      assert.equal(draws.length, 0, `all draws consumed in ${step.label}`);
      assert.equal(me.pq.k ? hex(me.pq.k) : null, step.pq_after.k, `pq k after ${step.label}`);
      assert.equal(me.pq.acked, step.pq_after.acked, `acked after ${step.label}`);
      assert.equal(Boolean(me.pq.k), step.is_post_quantum);
    }
  }
  assert.ok(offerSeen);
  assert.ok(conv[encName].pq.acked && conv[offName].pq.k.equals(K));
});

test('v2 pq_rekey: the re-key transcript replays with generation tracking', () => {
  const r = loadV2('pq_rekey');
  assert.equal(r.suite, 'pq_rekey');
  const encName = r.encapsulator, offName = r.offerer;
  const E = who[encName], O = who[offName];
  assert.ok(E.routing_id < O.routing_id, 'encapsulator is the designated initiator');

  const K0 = unhex(r.gen0_secret);
  const K1 = unhex(r.rekey.K), C1 = unhex(r.rekey.c), EK1 = unhex(r.rekey.ek);
  assert.notEqual(r.rekey.K, r.gen0_secret, 'the secret must rotate');
  // Generation-0 ciphertext: the first mixed encrypt that carries pqct without
  // a pqg field.
  const C0 = unb64(r.steps.find(
    (s) => s.op === 'encrypt' && s.header.pqct && !s.header.pqg).header.pqct);

  const conv = {
    [encName]: { sessions: {}, receivedAny: false, pq: { k: null, ct: null, acked: false } },
    [offName]: { sessions: {}, receivedAny: false, pq: { k: null, ct: null, acked: false, dkSeed: null } },
  };
  const other = (n) => (n === encName ? offName : encName);

  const encryptWith = (me, meName, sess, plaintext, draws, sid) => {
    const m = drEncrypt(sess, plaintext, draws.shift(), me.pq);
    const payload = { v: 1, t: 'r', sid };
    if (sess.initiator && !me.receivedAny) payload.ek = b64(sess.ekPub);
    Object.assign(payload, { h: m.header, n: b64(m.nonce), ct: b64(m.ct), mac: b64(m.mac) });
    return { m, payloadStr: b64(utf8(JSON.stringify(payload))) };
  };
  const openSession = (me, meName, j) => {
    assert.ok(j.ek, 'first message must carry ek');
    const my = who[meName], their = who[other(meName)];
    const dh1 = x25519(unhex(my.x_seed), unhex(their.x_pub));
    const dh2 = x25519(unhex(my.x_seed), unb64(j.ek));
    const sk = hkdf(cat(Buffer.alloc(32, 0xff), dh1, dh2), Buffer.alloc(32), utf8('Z-X3DH-v1'), 32);
    const sess = makeSession(sha256(cat(utf8('Z-AD-v1'), unhex(their.ed_pub), unhex(my.ed_pub))));
    sess.rootKey = sk; sess.dhsSeed = unhex(my.x_seed); sess.dhsPub = unhex(my.x_pub);
    me.sessions[j.sid] = sess;
    return sess;
  };
  // The KEM secret/ciphertext a side ends up with when it establishes gen g.
  const kemK = (g) => (g === 0 ? K0 : K1);
  const kemC = (g) => (g === 0 ? C0 : C1);

  for (const step of r.steps) {
    if (step.op === 'rekey_offer') {
      const me = conv[step.by];
      assert.equal(step.by, offName);
      const draws = step.random_draws.map(unhex);
      const seed = draws.shift(), mid = draws.shift();
      assert.equal(hex(seed), r.rekey.dk_seed, 'rekey offer seed');
      me.pq.dkSeed = seed;
      const sid = Object.keys(me.sessions)[0];
      const offerInner = utf8(JSON.stringify(
        { k: 'pqek', mid: b64url(mid), ts: 3, alg: 'ML-KEM-768', ek: b64(EK1), g: 1 }));
      const { payloadStr } = encryptWith(me, step.by, me.sessions[sid], offerInner, draws, sid);
      assert.equal(payloadStr, step.payload, 'rekey offer payload');
      assert.equal(draws.length, 0, 'all draws consumed (rekey offer)');
      continue;
    }
    const me = conv[step.by];
    const draws = step.random_draws.map(unhex);
    if (step.op === 'encrypt') {
      let sess = me.sessions[step.sid];
      if (!sess) {
        assert.equal(step.by, encName);
        const their = who[other(step.by)], my = who[step.by];
        const ekSeed = draws.shift();
        const ekPub = xPub(ekSeed);
        const dh1 = x25519(unhex(my.x_seed), unhex(their.x_pub));
        const dh2 = x25519(ekSeed, unhex(their.x_pub));
        const sk = hkdf(cat(Buffer.alloc(32, 0xff), dh1, dh2), Buffer.alloc(32), utf8('Z-X3DH-v1'), 32);
        sess = makeSession(sha256(cat(utf8('Z-AD-v1'), unhex(my.ed_pub), unhex(their.ed_pub))));
        sess.dhsSeed = draws.shift(); sess.dhsPub = xPub(sess.dhsSeed);
        sess.dhrPub = unhex(their.x_pub);
        [sess.rootKey, sess.cks] = kdfRk(sk, x25519(sess.dhsSeed, sess.dhrPub));
        sess.ekPub = ekPub; sess.initiator = true;
        me.sessions[step.sid] = sess;
      }
      const { m, payloadStr } = encryptWith(me, step.by, sess, unhex(step.plaintext), draws, step.sid);
      assert.equal(draws.length, 0, `all draws consumed (${step.label})`);
      assert.deepEqual(m.header, step.header, step.label);
      assert.equal(hex(headerBytes(m.header)), step.header_bytes, `header bytes ${step.label}`);
      assert.equal(payloadStr, step.payload, `payload ${step.label}`);
    } else {
      const j = JSON.parse(unb64(step.payload).toString('utf8'));
      const sess = me.sessions[j.sid] || openSession(me, step.by, j);
      const msg = { header: j.h, nonce: unb64(j.n), ct: unb64(j.ct), mac: unb64(j.mac) };
      const g = msg.header.pqg || 0;
      // Offerer establishes generation g from a header ciphertext.
      if (msg.header.pqct && pqSecretFor(me.pq, g) == null) {
        assert.equal(step.by, offName);
        assert.equal(hex(unb64(msg.header.pqct)), hex(kemC(g)), 'header pqct is the recorded c');
        if (me.pq.k != null) { me.pq.oldGen = me.pq.gen || 0; me.pq.oldK = me.pq.k; }
        me.pq.k = kemK(g); me.pq.gen = g; me.pq.dkSeed = null; me.pq.acked = false;
      }
      const plain = drDecrypt(sess, msg, draws, me.pq);
      me.receivedAny = true;
      assert.equal(hex(plain), step.plaintext, step.label);
      // Encapsulator accepts an offer (initial gen 0 or a re-key gen 1).
      if (step.by === encName && plain.toString('utf8').startsWith('{"k":"pqek"')) {
        const inner = JSON.parse(plain.toString('utf8'));
        const ig = inner.g || 0;
        assert.equal(inner.alg, 'ML-KEM-768');
        if (ig === 1) assert.equal(hex(unb64(inner.ek)), r.rekey.ek, 'gen1 offered ek');
        draws.shift(); // Encaps_internal randomness m (checked by kyber-py)
        if (me.pq.k != null) { me.pq.oldGen = me.pq.gen || 0; me.pq.oldK = me.pq.k; }
        me.pq.k = kemK(ig); me.pq.ct = kemC(ig); me.pq.gen = ig; me.pq.acked = false;
      }
      // Offerer making its initial (generation-0) offer after first contact.
      if (step.offer_payload) {
        assert.equal(step.by, offName);
        const seed = draws.shift(), mid = draws.shift();
        assert.equal(hex(seed), r.gen0_offer.dk_seed, 'gen0 offer seed');
        me.pq.dkSeed = seed;
        const inner = utf8(JSON.stringify(
          { k: 'pqek', mid: b64url(mid), ts: 2, alg: 'ML-KEM-768', ek: r.gen0_offer.ek_b64 }));
        assert.equal(inner.toString('utf8'), r.gen0_offer.inner_json, 'gen0 offer inner');
        const { payloadStr } = encryptWith(me, step.by, me.sessions[j.sid], inner, draws, j.sid);
        assert.equal(payloadStr, step.offer_payload, 'gen0 offer payload');
      }
      assert.equal(draws.length, 0, `all draws consumed (${step.label})`);
      assert.equal(me.pq.k ? hex(me.pq.k) : null, step.pq_after.k, `pq k after ${step.label}`);
      assert.equal((me.pq.gen || 0), (step.pq_after.gen || 0), `pq gen after ${step.label}`);
      if (step.pq_after.old_k) {
        assert.equal(hex(me.pq.oldK), step.pq_after.old_k, `pq old_k after ${step.label}`);
      }
      assert.equal(step.pq_generation, me.pq.k ? (me.pq.gen || 0) : 0, `generation ${step.label}`);
    }
  }
  // Both sides end on generation 1 with the rotated secret.
  assert.equal(conv[encName].pq.gen, 1);
  assert.ok(conv[offName].pq.k.equals(K1) && conv[encName].pq.k.equals(K1));
  assert.ok(conv[encName].pq.acked, 'gen-1 ciphertext acknowledged');
});

// ===========================================================================
// Backup archive (§9). Node has no Argon2id, so the key is taken from the
// vector — the KDF step is a standard RFC 9106 KAT (password, salt, m/t/p,
// tag length, output are all recorded) that any Argon2id implementation can
// reproduce, and the Dart suite checks it on every run. Everything BUILT on
// that key is re-derived here from the recorded bytes with no shared code:
// the nonce, the associated data, the frame layout and the two failures the
// format exists to catch.
// ===========================================================================
const BK_DIR = path.join(__dirname, '..', '..', 'docs', 'vectors', 'backup');
const loadBk = (name) => JSON.parse(fs.readFileSync(path.join(BK_DIR, `${name}.json`), 'utf8'));

const u64be = (n) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };

test('backup archive: every frame opens at its own index and nowhere else', () => {
  const v = loadBk('archive');
  const key = unhex(v.kdf.key);
  const file = unhex(v.file.bytes);
  assert.equal(file.length, v.file.len);
  assert.equal(hex(sha256(file)), v.file.sha256);

  // Header: a plaintext JSON line, terminated by \n.
  const nl = file.indexOf(0x0a);
  const header = file.subarray(0, nl);
  assert.equal(hex(header), v.header.bytes);
  const h = JSON.parse(header.toString('utf8'));
  assert.equal(h.z, 'zbk');
  assert.equal(h.v, 1);
  assert.equal(h.kdf, 'argon2id');
  assert.equal(h.m, v.kdf.memory_kib);
  assert.equal(h.t, v.kdf.iterations);
  assert.equal(h.p, v.kdf.parallelism);
  assert.equal(hex(Buffer.from(h.salt, 'base64')), v.kdf.salt);
  const np = Buffer.from(h.np, 'base64');
  assert.equal(hex(np), v.header.nonce_prefix);

  // Frames: [u32be len][ciphertext || mac], nonce = np || u64be(i),
  // aad = header || u64be(i).
  let off = nl + 1;
  let i = 0;
  let records = 0;
  let sawEnd = false;
  const sealedAll = [];
  for (const f of v.frames) {
    const len = file.readUInt32BE(off); off += 4;
    const sealed = file.subarray(off, off + len); off += len;
    sealedAll.push(sealed);
    assert.equal(hex(sealed), f.ciphertext + f.mac, `frame ${i} bytes`);
    const nonce = cat(np, u64be(i));
    assert.equal(hex(nonce), f.nonce, `frame ${i} nonce`);
    const plain = xchachaOpen(key, nonce,
      sealed.subarray(0, sealed.length - 16),
      sealed.subarray(sealed.length - 16),
      cat(header, u64be(i)));
    assert.equal(hex(plain), f.plaintext, `frame ${i} plaintext`);
    assert.equal(plain[0], f.kind, `frame ${i} kind byte`);
    const body = plain.subarray(1);
    if (f.kind === v.frame_kinds.blob) {
      const idLen = body[0];
      assert.equal(body.subarray(1, 1 + idLen).toString('utf8'), v.blob_body.fid);
      assert.equal(hex(body.subarray(1 + idLen)), v.blob_body.bytes);
    } else {
      assert.equal(body.toString('utf8'), f.payload_json, `frame ${i} json`);
      const rec = JSON.parse(f.payload_json);
      if (f.kind === v.frame_kinds.end) { sawEnd = true; assert.equal(rec.records, records); }
      else records++;
    }
    i++;
  }
  assert.equal(off, file.length, 'the file is exactly its frames');
  assert.ok(sawEnd, 'the archive ends with a terminator');

  // A frame lifted to another index must not open: the index is in both the
  // nonce and the aad, so reordering and duplication are detected.
  assert.equal(hex(sealedAll[1]), v.must_fail.frame_1_opened_at_index_0);
  assert.throws(() => xchachaOpen(key, cat(np, u64be(0)),
    sealedAll[1].subarray(0, sealedAll[1].length - 16),
    sealedAll[1].subarray(sealedAll[1].length - 16),
    cat(header, u64be(0))));

  // …and neither does the right frame under a key that is not this archive's.
  const notTheKey = sha256(utf8('not the archive key'));
  assert.throws(() => xchachaOpen(notTheKey, cat(np, u64be(0)),
    sealedAll[0].subarray(0, sealedAll[0].length - 16),
    sealedAll[0].subarray(sealedAll[0].length - 16),
    cat(header, u64be(0))));
});

test('backup archive 1.1: the minor revision opens with the same frame layer, and a newer major is not this format', () => {
  const v = loadBk('archive_1_1');
  const key = unhex(v.kdf.key);
  const file = unhex(v.file.bytes);
  assert.equal(file.length, v.file.len);
  assert.equal(hex(sha256(file)), v.file.sha256);

  // Header: same line, one more member. A reader of major 1 reads `mv`; one
  // that predates it ignores it, which is what makes the revision minor.
  const nl = file.indexOf(0x0a);
  const header = file.subarray(0, nl);
  assert.equal(hex(header), v.header.bytes);
  const h = JSON.parse(header.toString('utf8'));
  assert.equal(h.z, 'zbk');
  assert.equal(h.v, 1);
  assert.equal(h.v, v.header.major);
  assert.equal(h.mv, 1);
  assert.equal(h.mv, v.header.minor);
  assert.equal(hex(Buffer.from(h.salt, 'base64')), v.kdf.salt);
  const np = Buffer.from(h.np, 'base64');
  assert.equal(hex(np), v.header.nonce_prefix);

  // Frames exactly as in 1.0: nonce = np || u64be(i), aad = header || u64be(i).
  let off = nl + 1;
  const types = [];
  let records = 0;
  for (let i = 0; i < v.frames.length; i++) {
    const f = v.frames[i];
    const len = file.readUInt32BE(off); off += 4;
    const sealed = file.subarray(off, off + len); off += len;
    assert.equal(hex(sealed), f.ciphertext + f.mac, `frame ${i} bytes`);
    const nonce = cat(np, u64be(i));
    assert.equal(hex(nonce), f.nonce, `frame ${i} nonce`);
    const plain = xchachaOpen(key, nonce,
      sealed.subarray(0, sealed.length - 16),
      sealed.subarray(sealed.length - 16),
      cat(header, u64be(i)));
    assert.equal(hex(plain), f.plaintext, `frame ${i} plaintext`);
    assert.equal(plain[0], f.kind, `frame ${i} kind byte`);
    const body = plain.subarray(1).toString('utf8');
    assert.equal(body, f.payload_json, `frame ${i} json`);
    const rec = JSON.parse(body);
    types.push(rec.t);
    if (f.kind === v.frame_kinds.end) assert.equal(rec.records, records);
    else records++;
  }
  assert.equal(off, file.length, 'the file is exactly its frames');
  assert.deepEqual(types,
    ['meta', 'identity', 'state', 'contact', 'blocked', 'request', 'example', 'end']);

  // The linked device's identity carries its account — the account key and
  // this device's certificate, never the account's seed — and the
  // certificate is the account's Ed25519 signature over the device's keys.
  const id = JSON.parse(v.frames[1].payload_json);
  assert.equal(id.account.accountEdSeed, undefined);
  const cert = id.account.deviceCert;
  const certOk = crypto.verify(null,
    cat(utf8('z-device-cert-v1:'), Buffer.from(cert.ded, 'base64'),
      Buffer.from(cert.dx, 'base64'), utf8(cert.id)),
    edPubKey(Buffer.from(id.account.accountEdPub, 'base64')),
    Buffer.from(cert.sig, 'base64'));
  assert.ok(certOk, "the account's certificate for the device verifies");

  // A record no reader knows, marked to be carried.
  const kept = JSON.parse(v.frames[v.kept_record_index].payload_json);
  assert.equal(kept[v.keep_member], 1);

  // The same header one major on is not this format.
  const newer = JSON.parse(unhex(v.must_fail.newer_major_header).toString('utf8'));
  assert.equal(newer.z, 'zbk');
  assert.ok(newer.v > h.v, 'a newer major is refused by a reader of this one');
});

test('backup archive: the recovery code decodes to the recorded entropy', () => {
  const v = loadBk('archive');
  const A = v.recovery_code.alphabet;
  assert.equal(A, '0123456789ABCDEFGHJKMNPQRSTVWXYZ');
  assert.equal(A.length, 32);
  for (const c of 'ILOU') assert.ok(!A.includes(c), `${c} is excluded`);

  // Normalise the printed form the way a reader must: drop the prefix and
  // separators, upper-case, fold the confusable letters onto digits.
  const canonical = v.recovery_code.mangled_input
    .toUpperCase().replace(/^\s*ZBK\s*[-\s]?/, '').replace(/[\s\-_]/g, '')
    .replace(/[IL]/g, '1').replace(/O/g, '0');
  assert.equal(canonical, v.recovery_code.canonical);
  assert.equal(canonical.length, 25);
  assert.equal(hex(utf8(canonical)), v.recovery_code.key_material);

  // 24 data characters are 120 bits, big-endian; the 25th is the checksum.
  let bits = '';
  for (let i = 0; i < 24; i++) bits += A.indexOf(canonical[i]).toString(2).padStart(5, '0');
  const entropy = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  assert.equal(hex(entropy), v.recovery_code.entropy);
  assert.equal(canonical[24], A[sha256(entropy)[0] & 0x1f], 'checksum character');
});

// ===========================================================================
// v3 — hybrid signatures (§13.1). Node has no ML-DSA, so the post-quantum
// half is checked by protocol/tool/verify_mldsa.py (dilithium-py, an
// unrelated FIPS 204 implementation). What Node CAN check independently is
// everything built around it: the classical half of the hybrid signature,
// with its own Ed25519; the ADR-0003 commitment, with its own SHA-256; and
// that the recorded sizes are the FIPS 204 ones rather than whatever the
// Dart library happened to produce.
// ===========================================================================
const V3_DIR = path.join(__dirname, '..', '..', 'docs', 'vectors', 'v3');
const loadV3 = (name) => JSON.parse(fs.readFileSync(path.join(V3_DIR, `${name}.json`), 'utf8'));

test('v3 mldsa65: sizes, the classical half, and the commitment', () => {
  const v = loadV3('mldsa65');
  assert.equal(v.suite, 'mldsa65');
  assert.equal(v.algorithm, 'Ed25519+ML-DSA-65');
  // FIPS 204 Table 2 for ML-DSA-65.
  assert.equal(v.public_key_bytes, 1952);
  assert.equal(v.signature_bytes, 3309);
  assert.equal(hex(unhex(v.deterministic_rnd)), '00'.repeat(32));

  assert.equal(v.vectors.length, 4);
  for (const [i, x] of v.vectors.entries()) {
    assert.equal(unhex(x.pk).length, 1952, `vector ${i} pk`);
    assert.equal(unhex(x.sk).length, 4032, `vector ${i} sk`);
    assert.equal(unhex(x.signature).length, 3309, `vector ${i} sig`);
    assert.equal(unhex(x.seed).length, 32, `vector ${i} seed`);
    // The tampered signature really is a one-byte change, so the vector is
    // exercising a flipped bit rather than a differently-shaped object.
    const good = unhex(x.signature), bent = unhex(x.tampered_signature);
    assert.equal(good.length, bent.length);
    let diff = 0;
    for (let b = 0; b < good.length; b++) if (good[b] !== bent[b]) diff++;
    assert.equal(diff, 1, `vector ${i} tamper is exactly one byte`);
    assert.equal(x.message_hex, hex(utf8(x.message)));
  }

  // The hybrid construction: Node verifies the Ed25519 half itself.
  const h = v.hybrid;
  assert.equal(unhex(h.ed_pub).length, 32);
  assert.equal(unhex(h.ml_pub).length, 1952);
  assert.equal(unhex(h.ed_sig).length, 64);
  assert.equal(unhex(h.ml_sig).length, 3309);
  assert.ok(edVerify(unhex(h.ed_pub), utf8(h.message), unhex(h.ed_sig)),
    'the classical half of the hybrid signature verifies');
  assert.ok(!edVerify(unhex(h.ed_pub), utf8(h.message + '!'), unhex(h.ed_sig)),
    'and does not verify a different message');

  // The commitment a zc3. contact code carries in place of the 1952-byte key
  // (ADR 0003): SHA-256 over a domain separator and the key.
  assert.equal(h.commit_context, 'z-pqid-v3:');
  assert.equal(hex(sha256(cat(utf8(h.commit_context), unhex(h.ml_pub)))),
    h.pq_commitment, 'pq commitment');
  // It is domain-separated: a bare hash of the key is a different value.
  assert.notEqual(hex(sha256(unhex(h.ml_pub))), h.pq_commitment);
});

test('v3 contact_code_v3: the code parses, binds, and commits — checked here '
  + 'with Node\'s own crypto', () => {
  const v = loadV3('contact_code_v3');
  assert.equal(v.suite, 'contact_code_v3');
  assert.equal(v.prefix, 'zc3.');
  assert.equal(v.commit_context, 'z-pqid-v3:');

  // The emitted code is a prefix plus base64url JSON, and it stays scannable
  // — the point of the whole design, since the key it commits to is 1952
  // bytes. It declares v1 and carries the commitment as an extra member, so
  // a client that predates v3 reads the classical identity and ignores it
  // (PROTOCOL §14). That is what let emission switch on without a flag day.
  assert.ok(v.code.startsWith('zc1.'), 'the emitted code is v1-shaped');
  assert.equal(v.code.length, v.code_len);
  assert.ok(v.code_len < 400, 'a v3 code must stay QR-sized');
  const json = unb64url(v.code.slice(4)).toString('utf8');
  assert.equal(json, v.code_json);
  const c = JSON.parse(json);
  assert.equal(c.v, 1, 'declares v1, so an older decoder accepts it');
  assert.ok(typeof c.pqc === 'string', 'and carries the commitment anyway');

  // The strict zc3. form exists, carries the same commitment, and is exactly
  // what an older client CANNOT read — which is why it is not emitted.
  const strict = JSON.parse(unb64url(v.strict_code.slice(4)).toString('utf8'));
  assert.ok(v.strict_code.startsWith('zc3.'));
  assert.equal(strict.v, 3);
  assert.equal(strict.pqc, c.pqc, 'both forms commit to the same key');
  assert.equal(strict.ed, c.ed);

  // 18.7: the same account emitted by a LINKED device. Checked here with this
  // file's own Ed25519, so the three-way agreement covers the anchoring rule
  // and not just the commitment.
  const a = v.anchored;
  const ac = JSON.parse(unb64url(a.code.slice(4)).toString('utf8'));
  assert.equal(a.code.length, a.code_len);
  assert.ok(a.code_len < 800, 'an anchored code still scans');
  assert.equal(unb64url(a.code.slice(4)).toString('utf8'), a.code_json);
  assert.equal(ac.v, 1, 'still v1-shaped, so an older client reads it');

  // The code describes the DEVICE…
  assert.equal(ac.ed, a.device_ed);
  assert.equal(ac.x, a.device_x);
  assert.ok(edVerify(unb64(ac.ed), cat(utf8('z-bind-v1:'), unb64(ac.x)),
    unb64(ac.sig)), 'the binding signature is the device\'s own');
  // …and names the ACCOUNT, with that account's certificate for the device.
  assert.equal(ac.acct, a.account_ed);
  assert.notEqual(ac.acct, ac.ed, 'the two are different keys here');
  assert.deepEqual(ac.cert, a.cert);
  assert.ok(edVerify(unb64(ac.acct),
    certInput(unb64(ac.cert.ded), unb64(ac.cert.dx), ac.cert.id),
    unb64(ac.cert.sig)), 'the certificate is signed by the named account');
  // The check that stops a stranger holding a genuine certificate of that
  // account and presenting it beside their own keys.
  assert.equal(ac.cert.ded, ac.ed, 'the certificate is FOR this device');
  assert.equal(ac.cert.dx, ac.x);
  assert.ok(!ac.cert.legacy, 'a legacy record cannot anchor a code');
  // One account, one identity: the commitment is the same one the root's own
  // code carries.
  assert.equal(ac.pqc, c.pqc, 'the commitment is the account\'s');

  // Every field in the code matches the recorded identity.
  const id = v.identity;
  assert.equal(hex(unb64(c.ed)), id.ed_pub);
  assert.equal(hex(unb64(c.x)), id.x_pub);
  assert.equal(hex(unb64(c.sig)), id.binding_sig);
  assert.equal(hex(unb64(c.pqc)), v.pq.commitment);

  // The binding signature covers the X25519 key, verified with Node's Ed25519.
  assert.ok(edVerify(unb64(c.ed), cat(utf8('z-bind-v1:'), unb64(c.x)),
    unb64(c.sig)), 'binding signature');
  assert.equal(b64url(sha256(unb64(c.ed))), id.routing_id, 'routing id');

  // The commitment, recomputed independently: SHA-256 over the context and
  // the ML-DSA public key. This is the only thing standing between a scanned
  // code and a substituted post-quantum key.
  assert.equal(hex(sha256(cat(utf8(v.commit_context), unhex(v.pq.ml_pub)))),
    v.pq.commitment, 'pq commitment');

  // …and a different ML-DSA key under the same classical identity produces a
  // different commitment, so it cannot satisfy this code.
  assert.equal(hex(sha256(cat(utf8(v.commit_context),
    unhex(v.must_refuse.ml_pub)))), v.must_refuse.commitment);
  assert.notEqual(v.must_refuse.commitment, v.pq.commitment,
    'a substituted key must not satisfy the commitment');

  // The in-band delivery carries exactly the committed key.
  const inner = JSON.parse(v.pqid_inner.json);
  assert.equal(inner.k, 'pqid');
  assert.equal(inner.alg, 'ML-DSA-65');
  assert.equal(hex(unb64(inner.pk)), v.pq.ml_pub);
  assert.equal(hex(sha256(cat(utf8(v.commit_context), unb64(inner.pk)))),
    v.pq.commitment, 'the delivered key satisfies the scanned commitment');
});

// ADR 0027 (PROTOCOL §18.10): the commitment's signature, judged here from
// the section's rule alone. A code without `pqcs` is unsigned (every code
// issued before); one with it must carry `pqc`, a 64-byte signature, and
// verify under `ed` over the context, the ACCOUNT key (`acct`, else `ed`) and
// the commitment — anything else is refused.
function pqcsVerdict(code) {
  let j;
  try {
    j = JSON.parse(unb64url(code.slice(4)).toString('utf8'));
  } catch {
    return 'malformed';
  }
  if (!('pqcs' in j)) return 'unsigned';
  if (typeof j.pqcs !== 'string' || typeof j.pqc !== 'string') return 'refuse';
  const sig = unb64(j.pqcs);
  if (sig.length !== 64) return 'refuse';
  const anchor = unb64(typeof j.acct === 'string' ? j.acct : j.ed);
  const input = cat(utf8('z-pqc-sig-v1:'), anchor, unb64(j.pqc));
  return edVerify(unb64(j.ed), input, sig) ? 'signed' : 'refuse';
}

test('v3 contact_code_pqc_sig: the commitment\'s signature, re-derived and '
  + 'checked with Node\'s own Ed25519', () => {
  const v = loadV3('contact_code_pqc_sig');
  assert.equal(v.suite, 'contact_code_pqc_sig');
  assert.equal(v.context, 'z-pqc-sig-v1:');

  // The identity and the commitment, from the recorded seeds and key.
  const id = v.identity;
  assert.equal(hex(edPub(unhex(id.ed_seed))), id.ed_pub);
  assert.equal(hex(xPub(unhex(id.x_seed))), id.x_pub);
  assert.equal(hex(sha256(cat(utf8('z-pqid-v3:'), unhex(v.pq.ml_pub)))),
    v.pq.commitment, 'the commitment is the ADR 0003 one');

  // The signing input from the formula, and the signature: Ed25519 is
  // deterministic (RFC 8032), so signing it here reproduces the bytes.
  const input = cat(utf8(v.context), unhex(id.ed_pub), unhex(v.pq.commitment));
  assert.equal(input.length, 77, 'fixed width: 13 + 32 + 32');
  assert.equal(hex(input), v.signing_input);
  assert.equal(hex(edSign(unhex(id.ed_seed), input)), v.pqcs);

  // The code carries exactly that, and the rule above says signed.
  assert.equal(v.code.length, v.code_len);
  assert.ok(v.code_len < 520, 'a root device\'s code is ~500 characters');
  const c = JSON.parse(unb64url(v.code.slice(4)).toString('utf8'));
  assert.equal(JSON.stringify(c), v.code_json);
  assert.equal(c.v, 1, 'still a v1 code to every older reader');
  assert.equal(hex(unb64(c.pqcs)), v.pqcs);
  assert.equal(hex(unb64(c.pqc)), v.pq.commitment);
  assert.ok(edVerify(unb64(c.ed), cat(utf8('z-bind-v1:'), unb64(c.x)),
    unb64(c.sig)), 'the binding signature is untouched');
  assert.equal(pqcsVerdict(v.code), 'signed');

  // Compatibility: the code without `pqcs` is the code issued before ADR
  // 0027, member for member and in order, and it is merely unsigned.
  const unsigned = JSON.parse(unb64url(v.unsigned_code.slice(4)).toString('utf8'));
  const minus = { ...c };
  delete minus.pqcs;
  assert.equal(JSON.stringify(unsigned), JSON.stringify(minus));
  assert.equal(pqcsVerdict(v.unsigned_code), 'unsigned');
  const strict = JSON.parse(unb64url(v.strict_code.slice(4)).toString('utf8'));
  assert.equal(strict.v, 3);
  assert.equal(strict.pqcs, c.pqcs, 'the strict form carries it too');
  assert.equal(pqcsVerdict(v.strict_code), 'signed');

  // A linked device's code: the DEVICE signs, over the ACCOUNT's key.
  const a = v.anchored;
  const ac = JSON.parse(unb64url(a.code.slice(4)).toString('utf8'));
  assert.equal(a.code.length, a.code_len);
  assert.equal(hex(unb64(ac.ed)), a.device_ed);
  assert.equal(hex(edPub(unhex(a.device_ed_seed))), a.device_ed);
  assert.equal(hex(unb64(ac.acct)), a.account_ed);
  const ain = cat(utf8(v.context), unb64(ac.acct), unb64(ac.pqc));
  assert.equal(hex(ain), a.signing_input);
  assert.equal(hex(edSign(unhex(a.device_ed_seed), ain)), a.pqcs);
  assert.equal(pqcsVerdict(a.code), 'signed');
  assert.equal(ac.pqc, c.pqc, 'one account, one commitment');

  // Every recorded alteration is refused by the same rule.
  const refused = Object.entries(v.must_refuse)
    .filter(([, e]) => e && typeof e === 'object' && 'code' in e);
  assert.equal(refused.length, 6);
  for (const [name, e] of refused) {
    assert.equal(pqcsVerdict(e.code), 'refuse', name);
  }
  // The rewritten commitment is a real one, to another key: not noise.
  assert.equal(unhex(v.must_refuse.other_commitment).length, 32);
  assert.notEqual(v.must_refuse.other_commitment, v.pq.commitment);
  const rewritten = JSON.parse(unb64url(v.must_refuse.pqc_rewritten.code.slice(4))
    .toString('utf8'));
  assert.equal(hex(unb64(rewritten.pqc)), v.must_refuse.other_commitment);
  assert.equal(rewritten.pqcs, c.pqcs, 'the signature was kept as it was');
});

test('v3 device_cert_v3: both halves cover the same input, and the classical '
  + 'half alone is not enough', () => {
  const v = loadV3('device_cert_v3');
  assert.equal(v.suite, 'device_cert_v3');
  assert.equal(v.signing_context, 'z-device-cert-v1:');

  // The signing input is the v2 one, unchanged: context || dev_ed || dev_x ||
  // device_id. Both algorithms attest to exactly these bytes, which is what
  // makes it impossible to hold a valid pair over different devices.
  const dev = v.device;
  const input = cat(utf8(v.signing_context), unhex(dev.ed_pub),
    unhex(dev.x_pub), utf8(dev.device_id));
  assert.equal(hex(input), v.signing_input, 'signing input');
  assert.equal(b64url(sha256(unhex(dev.ed_pub))), dev.routing_id);

  // Node verifies the classical half itself.
  const acct = v.account;
  assert.ok(edVerify(unhex(acct.ed_pub), input, unhex(v.cert.ed_sig)),
    'genuine certificate: classical half verifies');
  assert.equal(unhex(v.cert.ml_sig).length, 3309);
  assert.equal(unhex(acct.ml_pub).length, 1952);

  // The forged record: its Ed25519 half is GENUINE over this device — Node
  // confirms that independently — and only the post-quantum half gives it
  // away. This is the exit criterion for the phase, and the reason a
  // classical-only check can no longer gate anything.
  assert.ok(edVerify(unhex(acct.ed_pub), input, unhex(v.must_refuse.ed_sig)),
    'the forgery really does pass a classical-only check');
  assert.notEqual(v.must_refuse.ml_sig, v.cert.ml_sig,
    'and differs only in the half that cannot be forged');

  // A hybrid certificate is ~3.4 KB, which is why it cannot ride in a QR or
  // in a device list that must stay inside the 1024-byte padding bucket.
  assert.ok(v.cert.json_bytes > 3000, 'hybrid certificates are large');

  // 18.9 / ADR 0004: what actually travels to a contact is one ML-DSA
  // signature over the device LIST. Recomputed here from the list itself, so
  // a third implementation checks the *set* is what was signed rather than
  // taking the recorded input on trust.
  const dl = v.device_list;
  const list = JSON.parse(dl.list_json);
  const eds = list.devs.map(d => unb64(d.ded))
    .sort((p, q) => Buffer.compare(p, q));
  const listInput = cat(utf8('z-devlist-v1:'), utf8(`${list.ver}:`), ...eds);
  assert.equal(hex(listInput), dl.signing_input,
    'the post-quantum half covers exactly 3.4\'s signing input');
  assert.ok(edVerify(unb64(list.acct), listInput, unb64(list.sig)),
    'and the classical half covers the same bytes');
  assert.equal(unhex(dl.ml_sig).length, 3309);
  assert.deepEqual(JSON.parse(dl.sig_json).mlsig, b64(unhex(dl.ml_sig)));

  // The attack the shape exists for: a SUBSET of the genuine list. It is
  // classically perfect — every certificate in it is untouched and verifies
  // against the account key — so a per-certificate post-quantum half would
  // have caught nothing. The list-level input differs, which is what does.
  const ex = JSON.parse(dl.must_refuse.excluded_list_json);
  assert.ok(ex.devs.length < list.devs.length, 'it is a strict subset');
  for (const d of ex.devs) {
    assert.ok(edVerify(unb64(ex.acct),
      certInput(unb64(d.ded), unb64(d.dx), d.id), unb64(d.sig)),
      'every certificate left in it is genuine');
  }
  const exEds = ex.devs.map(d => unb64(d.ded)).sort((p, q) => Buffer.compare(p, q));
  const exInput = cat(utf8('z-devlist-v1:'), utf8(`${ex.ver}:`), ...exEds);
  assert.equal(hex(exInput), dl.must_refuse.excluded_signing_input);
  assert.notEqual(hex(exInput), hex(listInput),
    'a different membership is a different signing input');
  assert.ok(edVerify(unb64(ex.acct), exInput, unb64(ex.sig)),
    'and it is classically signed — which is the whole problem');

  // A rollback is caught the same way: the version is inside the input.
  const rb = JSON.parse(dl.must_refuse.rolled_back_list_json);
  assert.notEqual(rb.ver, list.ver);
  const rbEds = rb.devs.map(d => unb64(d.ded)).sort((p, q) => Buffer.compare(p, q));
  assert.equal(hex(cat(utf8('z-devlist-v1:'), utf8(`${rb.ver}:`), ...rbEds)),
    dl.must_refuse.rolled_back_signing_input);
  assert.notEqual(dl.must_refuse.rolled_back_signing_input, dl.signing_input);

  // The size claim behind choosing one signature over the list: it does not
  // grow with the device set.
  assert.ok(dl.sig_json_bytes < 4600 && dl.sig_json_bytes > 4400,
    'one constant-size artefact, whatever the device count');

  // ADR 0017 stage 2: the list at version 4, v2-only (`sig3` alone), and the
  // account's ML-DSA over it. Node has no ML-DSA, so dilithium-py checks the
  // signature itself (protocol/tool/verify_mldsa.py); what Node checks is
  // everything classical about the same objects. The rule picks the input:
  // this list is `sig3` alone, so it commits to — and the ML-DSA is recorded
  // over — the v3 input, which is what sig3 is over too.
  const acctEd = unhex(v.account.ed_pub);
  assert.ok(devlistAdmitted(list, acctEd), 'the stage-1 list, by the same rule');
  assert.equal(hex(devlistCommitted(list)), dl.signing_input,
    'which commits to the v1 input — what its ML-DSA is over');
  const s2 = v.device_list_v2_only;
  const l2 = JSON.parse(s2.list_json);
  assert.equal(devlistShape(l2), 'sig3');
  assert.equal(l2.ver, list.ver + 1);
  assert.deepEqual(l2.devs, list.devs);
  assert.ok(devlistAdmitted(l2, acctEd), 'admitted on sig3 alone');
  assert.equal(hex(devlistCommitted(l2)), s2.signing_input_v3,
    'commits to the v3 input, which the ML-DSA is recorded over');
  assert.equal(hex(devlistV1Input(l2)), s2.v1_signing_input);
  assert.equal(hex(devlistV2Input(l2)), s2.v2_signing_input);
  assert.equal(new Set([s2.signing_input_v3, s2.v1_signing_input, s2.v2_signing_input]).size, 3);
  assert.equal(hex(devlistFingerprint(l2)), s2.fingerprint);
  const sj2 = JSON.parse(s2.sig_json);
  assert.equal(sj2.mlsig, b64(unhex(s2.ml_sig)));
  assert.equal(sj2.ver, l2.ver);
  assert.equal(hex(unb64(sj2.acct)), v.account.ed_pub);
  assert.equal(unhex(s2.ml_sig).length, 3309);
  assert.notEqual(s2.ml_sig, dl.ml_sig, 'not the stage-1 signature');
  const r2 = s2.must_refuse;
  const swl = JSON.parse(r2.swapped_list_json);
  const swd = swl.devs.find((d) => d.id === r2.swapped_device_id);
  assert.equal(hex(unb64(swd.dx)), r2.swapped_x_pub);
  assert.ok(edVerify(acctEd, certInput(unb64(swd.ded), unb64(swd.dx), swd.id), unb64(swd.sig)),
    'the substituted certificate is itself well signed');
  assert.equal(swl.sig3, l2.sig3, 'the genuine sig3, replayed');
  assert.ok(!devlistAdmitted(swl, acctEd), 'refused: sig3 does not cover the new key');
  assert.equal(hex(devlistCommitted(swl)), r2.swapped_signing_input_v3);
  assert.equal(hex(devlistFingerprint(swl)), r2.swapped_fingerprint);
  assert.notEqual(r2.swapped_fingerprint, s2.fingerprint);
  // The stage-1 list with `sig` deleted. Its sig2 is genuine, and its v1
  // input — over which dl.ml_sig is made — is exactly the stage-1 list's, so
  // that ML-DSA still verifies over it (dilithium-py checks that): neither
  // signature can refuse it, and the shape does.
  const strippedList = JSON.parse(r2.sig_stripped_list_json);
  const mine = { ...list };
  delete mine.sig;
  assert.deepEqual(strippedList, mine, 'the recorded list is list_json without sig');
  assert.ok(devlistSigsGenuine(strippedList, acctEd), 'its sig2 is genuine');
  assert.equal(hex(devlistV1Input(strippedList)), dl.signing_input,
    'and its v1 input is the one the stage-1 ML-DSA is over');
  assert.ok(!devlistAdmitted(strippedList, acctEd), 'refused: {sig2} is not one of the shapes');

  // Safety number v2: twelve five-digit groups, different from v1 for the
  // same pair, so the one-time change cannot be mistaken for a substitution.
  const sn = v.safety_number_v2;
  assert.equal(sn.context, 'z-safety-v2');
  assert.equal(sn.value.split(' ').length, 12);
  assert.ok(sn.value.split(' ').every((g) => /^[0-9]{5}$/.test(g)));
  assert.notEqual(sn.value, sn.v1_value_for_comparison);
});

// ===========================================================================
// Handles (§21, ADR 0015 revision 2). Node has no Argon2id, and its BLAKE2b
// gives 64 bytes and nothing shorter, while Argon2id's tag is BLAKE2b with a
// 32-byte output (a different parameter block, not a truncation). So both
// are written here from RFC 7693 and RFC 9106 and checked first against
// those RFCs' own test vectors, and then every label in the file is
// re-derived with them — the production-parameter ones included, at 19 MiB
// and two passes each. The rest is §21 on Node's own Ed25519, SHA-256 and
// HKDF.
// ===========================================================================
const HD_DIR = path.join(__dirname, '..', '..', 'docs', 'vectors', 'handles');
const loadHd = (name) => JSON.parse(fs.readFileSync(path.join(HD_DIR, `${name}.json`), 'utf8'));

// --- BLAKE2b (RFC 7693), unkeyed, any output length 1..64. BigInt: Argon2id
// calls it a few dozen times per hash, so clarity wins over speed here.
const B2B_MASK = (1n << 64n) - 1n;
const B2B_IV = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];
const B2B_SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
  [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
  [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
  [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
  [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
  [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];
const b2bRotr = (x, n) => ((x >> BigInt(n)) | (x << BigInt(64 - n))) & B2B_MASK;

function blake2b(input, outLen) {
  assert.ok(outLen >= 1 && outLen <= 64);
  const h = B2B_IV.slice();
  h[0] ^= 0x01010000n ^ BigInt(outLen); // digest length, no key, fanout = depth = 1
  const blocks = Math.max(1, Math.ceil(input.length / 128));
  for (let bi = 0; bi < blocks; bi++) {
    const block = Buffer.alloc(128);
    input.copy(block, 0, bi * 128, Math.min(input.length, (bi + 1) * 128));
    const m = [];
    for (let i = 0; i < 16; i++) m.push(block.readBigUInt64LE(8 * i));
    const last = bi === blocks - 1;
    const t = BigInt(last ? input.length : (bi + 1) * 128);
    const v = h.concat(B2B_IV);
    v[12] ^= t & B2B_MASK;
    v[13] ^= t >> 64n;
    if (last) v[14] ^= B2B_MASK;
    const G = (a, b, c, d, x, y) => {
      v[a] = (v[a] + v[b] + x) & B2B_MASK; v[d] = b2bRotr(v[d] ^ v[a], 32);
      v[c] = (v[c] + v[d]) & B2B_MASK; v[b] = b2bRotr(v[b] ^ v[c], 24);
      v[a] = (v[a] + v[b] + y) & B2B_MASK; v[d] = b2bRotr(v[d] ^ v[a], 16);
      v[c] = (v[c] + v[d]) & B2B_MASK; v[b] = b2bRotr(v[b] ^ v[c], 63);
    };
    for (let r = 0; r < 12; r++) {
      const s = B2B_SIGMA[r % 10];
      G(0, 4, 8, 12, m[s[0]], m[s[1]]); G(1, 5, 9, 13, m[s[2]], m[s[3]]);
      G(2, 6, 10, 14, m[s[4]], m[s[5]]); G(3, 7, 11, 15, m[s[6]], m[s[7]]);
      G(0, 5, 10, 15, m[s[8]], m[s[9]]); G(1, 6, 11, 12, m[s[10]], m[s[11]]);
      G(2, 7, 8, 13, m[s[12]], m[s[13]]); G(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (let i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
  }
  const out = Buffer.alloc(64);
  h.forEach((w, i) => out.writeBigUInt64LE(w, 8 * i));
  return out.subarray(0, outLen);
}

// --- Argon2id (RFC 9106, version 0x13). A block is 128 64-bit words held as
// 256 uint32 halves, little-endian: word k is [2k] (low) and [2k+1] (high).
const le32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };

/** H' (RFC 9106 §3.3), the variable-length hash over BLAKE2b. */
function argon2HPrime(x, T) {
  const input = Buffer.concat([le32(T), x]);
  if (T <= 64) return blake2b(input, T);
  const r = Math.ceil(T / 32) - 2;
  const out = [];
  let v = blake2b(input, 64);
  out.push(v.subarray(0, 32));
  for (let i = 2; i <= r; i++) { v = blake2b(v, 64); out.push(v.subarray(0, 32)); }
  out.push(blake2b(v, T - 32 * r));
  return Buffer.concat(out);
}

/** a = a + b + 2·lo32(a)·lo32(b) mod 2^64 (fBlaMka), on words a, b of B. */
function argon2BlaMka(B, a, b) {
  const al = B[2 * a], ah = B[2 * a + 1], bl = B[2 * b], bh = B[2 * b + 1];
  // lo32(a)·lo32(b) as 64 bits, from 16-bit halves so every partial is < 2^32.
  const xl = al & 0xffff, xh = al >>> 16, yl = bl & 0xffff, yh = bl >>> 16;
  const ll = xl * yl, lh = xl * yh, hl = xh * yl, hh = xh * yh;
  const mid = (ll >>> 16) + (lh & 0xffff) + (hl & 0xffff);
  const pl = (((mid & 0xffff) << 16) | (ll & 0xffff)) >>> 0;
  const ph = (hh + (lh >>> 16) + (hl >>> 16) + (mid >>> 16)) >>> 0;
  const dl = (pl << 1) >>> 0, dh = ((ph << 1) | (pl >>> 31)) >>> 0; // doubled
  const lo = al + bl + dl; // below 3·2^32: exact
  B[2 * a] = lo >>> 0;
  B[2 * a + 1] = (ah + bh + dh + Math.floor(lo / 4294967296)) >>> 0;
}
/** d = rotr64(d ^ a, n). */
function argon2XorRotr(B, d, a, n) {
  const l = (B[2 * d] ^ B[2 * a]) >>> 0, h = (B[2 * d + 1] ^ B[2 * a + 1]) >>> 0;
  let nl, nh;
  if (n === 32) { nl = h; nh = l; }
  else if (n < 32) { nl = (l >>> n) | (h << (32 - n)); nh = (h >>> n) | (l << (32 - n)); }
  else { const k = n - 32; nl = (h >>> k) | (l << (32 - k)); nh = (l >>> k) | (h << (32 - k)); }
  B[2 * d] = nl >>> 0; B[2 * d + 1] = nh >>> 0;
}
function argon2GB(B, a, b, c, d) {
  argon2BlaMka(B, a, b); argon2XorRotr(B, d, a, 32);
  argon2BlaMka(B, c, d); argon2XorRotr(B, b, c, 24);
  argon2BlaMka(B, a, b); argon2XorRotr(B, d, a, 16);
  argon2BlaMka(B, c, d); argon2XorRotr(B, b, c, 63);
}
/** The permutation P over the sixteen words w[0..15] (BLAKE2b's round, no message). */
function argon2P(B, w) {
  argon2GB(B, w[0], w[4], w[8], w[12]); argon2GB(B, w[1], w[5], w[9], w[13]);
  argon2GB(B, w[2], w[6], w[10], w[14]); argon2GB(B, w[3], w[7], w[11], w[15]);
  argon2GB(B, w[0], w[5], w[10], w[15]); argon2GB(B, w[1], w[6], w[11], w[12]);
  argon2GB(B, w[2], w[7], w[8], w[13]); argon2GB(B, w[3], w[4], w[9], w[14]);
}
// RFC 9106 §3.5: the block as an 8×8 matrix of 16-byte registers; P on each
// row (words 16i..16i+15), then on each column (registers i, i+8, …, i+56).
const ARGON2_ROWS = [], ARGON2_COLS = [];
for (let i = 0; i < 8; i++) {
  ARGON2_ROWS.push(Array.from({ length: 16 }, (_, k) => 16 * i + k));
  ARGON2_COLS.push(Array.from({ length: 16 }, (_, k) => 2 * i + 16 * (k >> 1) + (k & 1)));
}
const argon2R = new Uint32Array(256), argon2Q = new Uint32Array(256);
/** out = G(X, Y), or out ^= G(X, Y) on a pass after the first (version 0x13). */
function argon2G(X, Y, out, xorInto) {
  for (let i = 0; i < 256; i++) argon2R[i] = X[i] ^ Y[i];
  argon2Q.set(argon2R);
  for (const w of ARGON2_ROWS) argon2P(argon2Q, w);
  for (const w of ARGON2_COLS) argon2P(argon2Q, w);
  if (xorInto) for (let i = 0; i < 256; i++) out[i] ^= argon2Q[i] ^ argon2R[i];
  else for (let i = 0; i < 256; i++) out[i] = argon2Q[i] ^ argon2R[i];
}

function argon2id({ password, salt, secret = Buffer.alloc(0), ad = Buffer.alloc(0), m, t, p, T }) {
  const H0 = blake2b(Buffer.concat([
    le32(p), le32(T), le32(m), le32(t), le32(0x13), le32(2 /* Argon2id */),
    le32(password.length), password, le32(salt.length), salt,
    le32(secret.length), secret, le32(ad.length), ad,
  ]), 64);
  const blocks = 4 * p * Math.floor(m / (4 * p));
  const q = blocks / p; // columns per lane
  const seg = q / 4; // four slices
  const mem = new Uint32Array(256 * blocks);
  const at = (lane, col) => mem.subarray(256 * (lane * q + col), 256 * (lane * q + col + 1));
  const load = (buf, dst) => { for (let i = 0; i < 256; i++) dst[i] = buf.readUInt32LE(4 * i); };
  for (let l = 0; l < p; l++) {
    load(argon2HPrime(Buffer.concat([H0, le32(0), le32(l)]), 1024), at(l, 0));
    load(argon2HPrime(Buffer.concat([H0, le32(1), le32(l)]), 1024), at(l, 1));
  }
  const zero = new Uint32Array(256), input = new Uint32Array(256), addr = new Uint32Array(256);
  const nextAddresses = () => { input[12]++; argon2G(zero, input, addr, false); argon2G(zero, addr, addr, false); };
  for (let pass = 0; pass < t; pass++) {
    for (let slice = 0; slice < 4; slice++) {
      for (let l = 0; l < p; l++) {
        // Argon2id: data-independent addressing for the first half of the
        // first pass (Argon2i), data-dependent after it (Argon2d).
        const independent = pass === 0 && slice < 2;
        if (independent) {
          input.fill(0);
          input[0] = pass; input[2] = l; input[4] = slice; input[6] = blocks; input[8] = t; input[10] = 2;
        }
        const first = pass === 0 && slice === 0 ? 2 : 0;
        if (independent && first === 2) nextAddresses();
        for (let j = first; j < seg; j++) {
          const col = slice * seg + j;
          const prev = col === 0 ? q - 1 : col - 1;
          let J1, J2;
          if (independent) {
            if (j % 128 === 0) nextAddresses();
            J1 = addr[2 * (j % 128)]; J2 = addr[2 * (j % 128) + 1];
          } else {
            const pb = at(l, prev);
            J1 = pb[0]; J2 = pb[1];
          }
          const refLane = pass === 0 && slice === 0 ? l : J2 % p;
          const done = pass === 0 ? slice * seg : 3 * seg;
          const W = refLane === l ? done + j - 1 : done - (j === 0 ? 1 : 0);
          const x = (BigInt(J1) * BigInt(J1)) >> 32n;
          const rel = W - 1 - Number((BigInt(W) * x) >> 32n);
          const start = pass === 0 ? 0 : ((slice + 1) * seg) % q;
          argon2G(at(l, prev), at(refLane, (start + rel) % q), at(l, col), pass > 0);
        }
      }
    }
  }
  const C = Buffer.alloc(1024);
  for (let i = 0; i < 256; i++) {
    let w = 0;
    for (let l = 0; l < p; l++) w ^= at(l, q - 1)[i];
    C.writeUInt32LE(w >>> 0, 4 * i);
  }
  return argon2HPrime(C, T);
}

test('handles: BLAKE2b and Argon2id as written here reproduce RFC 7693 and RFC 9106', () => {
  // RFC 7693 Appendix A, and the 32-byte variant Argon2id's tag uses.
  assert.equal(hex(blake2b(utf8('abc'), 64)),
    'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923');
  assert.equal(hex(blake2b(utf8('abc'), 32)), 'bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319');
  assert.equal(hex(blake2b(Buffer.alloc(0), 32)), '0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8');
  // Node's own BLAKE2b-512 wherever both apply: every block-boundary case.
  for (const n of [0, 1, 127, 128, 129, 255, 256, 257, 1000]) {
    const x = Buffer.from(Array.from({ length: n }, (_, i) => (i * 31 + 7) & 0xff));
    assert.equal(hex(blake2b(x, 64)), crypto.createHash('blake2b512').update(x).digest('hex'), `length ${n}`);
  }
  // RFC 9106 §5.3: Argon2id with a secret and associated data, four lanes.
  assert.equal(hex(argon2id({
    password: Buffer.alloc(32, 1), salt: Buffer.alloc(16, 2), secret: Buffer.alloc(8, 3),
    ad: Buffer.alloc(12, 4), m: 32, t: 3, p: 4, T: 32,
  })), '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659');
});

test('handles: every label, at small parameters and at the production ones', () => {
  const v = loadHd('handles');
  const kdf = v.labels.kdf;
  // §21.2's parameters, from the text rather than the file.
  assert.deepEqual([kdf.salt, kdf.memory_kib, kdf.iterations, kdf.parallelism, kdf.tag_len, kdf.version],
    ['z-handle-label-v1', 19456, 2, 1, 32, 19]);
  for (const c of v.labels.small_parameters) {
    assert.equal(hex(argon2id({
      password: unhex(c.password), salt: unhex(c.salt), m: c.memory_kib, t: c.iterations, p: c.parallelism, T: c.tag_len,
    })), c.tag, JSON.stringify(c));
  }
  for (const c of v.labels.production) {
    assert.equal(c.password, hex(utf8(c.handle)), 'the password is the canonical handle');
    assert.equal(hex(argon2id({
      password: utf8(c.handle), salt: utf8('z-handle-label-v1'), m: 19456, t: 2, p: 1, T: 32,
    })), c.label, c.handle);
  }
});

// §21.1, from the text: trim ASCII whitespace, ONE leading "@", A-Z
// lower-cased and nothing else folded; then the checks in the order given,
// the first that fails naming the reason.
const HANDLE_RESERVED = ['z', 'zm', 'zmessenger', 'zmessengers', 'support', 'help', 'admin',
  'administrator', 'official', 'security', 'team', 'staff', 'mod', 'moderator', 'system', 'root',
  'everyone', 'here', 'null', 'undefined', 'abuse', 'privacy', 'legal', 'info', 'contact',
  'noreply', 'verify', 'verified'];
function normaliseHandle(s) {
  const ws = (c) => c === 0x20 || (c >= 0x09 && c <= 0x0d);
  let a = 0, b = s.length;
  while (a < b && ws(s.charCodeAt(a))) a++;
  while (b > a && ws(s.charCodeAt(b - 1))) b--;
  let x = s.slice(a, b);
  if (x.startsWith('@')) x = x.slice(1);
  return x.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32));
}
function handleProblem(input) {
  const s = normaliseHandle(input);
  if (s === '') return 'empty';
  if (!/^[a-z0-9_.]+$/.test(s)) return 'badCharacter';
  const dot = s.indexOf('.');
  if (dot < 0 || dot === s.length - 1) return 'missingDigits';
  const nick = s.slice(0, dot), digits = s.slice(dot + 1);
  if (!/^[0-9]+$/.test(digits)) return 'digitsNotDigits';
  if (HANDLE_RESERVED.includes(nick)) return 'reserved';
  if (nick.length < 3) return 'nickTooShort';
  if (nick.length > 20) return 'nickTooLong';
  if (!/^[a-z]/.test(nick)) return 'nickStartsWithNonLetter';
  if (nick.includes('__')) return 'nickDoubleUnderscore';
  if (nick.endsWith('_')) return 'nickEndsWithUnderscore';
  if (digits.length < 2) return 'digitsTooShort';
  if (digits.length > 6) return 'digitsTooLong';
  return null;
}

test('handles: the grammar, from §21.1 alone', () => {
  const g = loadHd('handles').grammar;
  assert.deepEqual(g.reserved, HANDLE_RESERVED);
  for (const c of g.valid) {
    assert.equal(handleProblem(c.input), null, c.note);
    assert.equal(normaliseHandle(c.input), c.canonical, c.note);
    assert.equal(c.display, `@${c.canonical}`);
  }
  let lookalikes = 0;
  for (const c of g.invalid) {
    assert.equal(handleProblem(c.input), c.problem, `${JSON.stringify(c.input)}: ${c.note}`);
    assert.equal(normaliseHandle(c.input), c.normalised);
    if (/[^\x00-\x7f]/.test(c.input)) lookalikes++;
  }
  assert.ok(lookalikes >= 10, 'the file carries the non-ASCII cases');
  for (const n of HANDLE_RESERVED) {
    assert.ok(g.invalid.some((c) => c.input === `${n}.12` && c.problem === 'reserved'), n);
  }
});

// Crockford base32 as §21.3 reuses it from the backup code: 24 data
// characters (120 bits, big-endian) and a checksum character.
function crockfordEntropy(printed) {
  const A = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  const canonical = printed.toUpperCase().replace(/^ZHR-/, '').replace(/-/g, '');
  assert.equal(canonical.length, 25);
  let bits = '';
  for (let i = 0; i < 24; i++) bits += A.indexOf(canonical[i]).toString(2).padStart(5, '0');
  const entropy = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  assert.equal(canonical[24], A[sha256(entropy)[0] & 0x1f], 'checksum character');
  return { canonical, entropy };
}

test('handles: keys, introduction identities, recovery codes and commitments', () => {
  const v = loadHd('handles');
  const label = unhex(v.labels.production.find((c) => c.handle === 'alice.42').label);
  for (const k of v.keys) {
    assert.equal(hex(edPub(unhex(k.seed))), k.pub, k.name);
    if (k.name.startsWith('intro')) {
      assert.equal(k.routing_id, b64url(sha256(unhex(k.pub))));
      assert.equal(k.rid_bytes, hex(sha256(unhex(k.pub))));
      // The X25519 half from the same seed: HKDF, then used as the private key.
      assert.equal(k.x_hkdf_salt, 'z-handle-intro-x-v1');
      const xs = hkdf(unhex(k.seed), utf8('z-handle-intro-x-v1'), Buffer.alloc(0), 32);
      assert.equal(hex(xs), k.x_seed, k.name);
      assert.equal(hex(xPub(xs)), k.x_pub, k.name);
    }
  }
  for (const r of v.recovery) {
    assert.ok(r.formatted.startsWith('ZHR-'), 'the handle prefix, not the backup one');
    const { canonical, entropy } = crockfordEntropy(r.formatted);
    assert.equal(canonical, r.canonical);
    assert.equal(hex(entropy), r.entropy);
    assert.equal(r.hkdf_info, hex(label));
    const seed = hkdf(entropy, utf8('z-handle-recovery-v1'), label, 32);
    assert.equal(hex(seed), r.seed);
    assert.equal(hex(edPub(seed)), r.pub);
    assert.equal(r.rc_input, hex(cat(utf8('z-handle-rc-v1:'), edPub(seed))));
    assert.equal(hex(sha256(unhex(r.rc_input))), r.rc);
  }
});

// §21.4: a record is read only if re-encoding what was read gives back the
// same bytes — members in the one order (k, owner, intro, xintro, pow, rc,
// then rpub and rsig on a recover), b64url without padding, nothing else.
// Returns null for anything that is not a record.
function decodeHandleRecord(value) {
  if (value.length > 1024) return null;
  let j;
  try { j = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(value)); } catch { return null; }
  if (j === null || typeof j !== 'object' || Array.isArray(j)) return null;
  if (!['claim', 'update', 'recover'].includes(j.k)) return null;
  const bytes = (s, n) => (typeof s === 'string' && unb64url(s).length === n ? unb64url(s) : undefined);
  const r = {
    k: j.k, owner: bytes(j.owner, 32), intro: j.intro === null ? null : bytes(j.intro, 32),
    xintro: j.xintro === null ? null : bytes(j.xintro, 32), pow: j.pow, rc: bytes(j.rc, 32),
  };
  if (r.k === 'recover') { r.rpub = bytes(j.rpub, 32); r.rsig = bytes(j.rsig, 64); }
  if (r.owner === undefined || r.intro === undefined || r.xintro === undefined || r.rc === undefined) return null;
  // The introduction mailbox's two keys come and go together (Amendment 1).
  if ((r.intro === null) !== (r.xintro === null)) return null;
  if (r.k === 'recover' && (r.rpub === undefined || r.rsig === undefined)) return null;
  if (!Number.isInteger(r.pow) || r.pow < 16 || r.pow > 28) return null;
  const again = {
    k: r.k, owner: b64url(r.owner), intro: r.intro === null ? null : b64url(r.intro),
    xintro: r.xintro === null ? null : b64url(r.xintro), pow: r.pow, rc: b64url(r.rc),
  };
  if (r.k === 'recover') { again.rpub = b64url(r.rpub); again.rsig = b64url(r.rsig); }
  return Buffer.from(JSON.stringify(again), 'utf8').equals(value) ? r : null;
}

const edOk = (pub, msg, sig) => { try { return edVerify(pub, msg, sig); } catch { return false; } };

/** The owner rule, §21.4, in its order. Returns the new state, or { refused }. */
function applyHandleEntry(state, e) {
  const no = (refused) => ({ refused });
  if (e.value.length > 1024) return no('tooLarge');
  if (e.label.length !== 32 || !Number.isInteger(e.v) || e.v < 1 || e.v > Number.MAX_SAFE_INTEGER
    || e.sig.length !== 64) return no('malformed');
  const r = decodeHandleRecord(e.value);
  if (r === null) return no('malformed');
  if (state && !state.label.equals(e.label)) return no('otherLabel');
  if (!state && r.k !== 'claim') return no('notClaimed');
  if (state && r.k === 'claim') return no('taken');
  if (state && e.v <= state.v) return no('staleVersion');
  const publishInput = cat(utf8('z-handle-publish-v1:'), e.label, u64be(e.v), sha256(e.value));
  if (r.k === 'claim' && !edOk(r.owner, publishInput, e.sig)) return no('badSignature');
  if (r.k === 'update') {
    if (!r.owner.equals(state.owner)) return no('ownerChanged');
    if (!r.rc.equals(state.rc)) return no('rcChanged');
    if (!edOk(state.owner, publishInput, e.sig)) return no('badSignature');
  }
  if (r.k === 'recover') {
    if (!sha256(cat(utf8('z-handle-rc-v1:'), r.rpub)).equals(state.rc)) return no('wrongRecoveryKey');
    const recoverInput = cat(utf8('z-handle-recover-v1:'), e.label, u64be(e.v), r.owner, r.rc);
    if (!edOk(r.rpub, recoverInput, r.rsig)) return no('badRecoverySignature');
    if (!edOk(r.owner, publishInput, e.sig)) return no('badSignature');
  }
  return { label: e.label, v: e.v, owner: r.owner, rc: r.rc, intro: r.intro, pow: r.pow };
}

test('handles: every entry\'s bytes, and the owner rule over every history, from §21.4 alone', () => {
  const v = loadHd('handles');
  const pubOf = Object.fromEntries(v.keys.map((k) => [k.name, unhex(k.pub)]));
  const entries = {};
  for (const e of v.entries) {
    const entry = { label: unhex(e.label), v: e.v, value: unhex(e.value), sig: unhex(e.sig) };
    entries[e.name] = entry;
    assert.equal(e.value_text, entry.value.toString('utf8'));
    assert.equal(e.value_sha256, hex(sha256(entry.value)));
    const pi = cat(utf8('z-handle-publish-v1:'), entry.label, u64be(e.v), sha256(entry.value));
    assert.equal(hex(pi), e.publish_input, e.name);
    assert.ok(edOk(pubOf[e.signer], pi, entry.sig), `${e.name}: signed by ${e.signer}`);
    // The body a handle-mode log takes: label b64url, value and sig b64.
    assert.deepEqual(e.publish_json, { label: b64url(entry.label), v: e.v, value: b64(entry.value), sig: b64(entry.sig) });
    if (e.rsig) {
      const r = decodeHandleRecord(entry.value);
      assert.equal(hex(r.rsig), e.rsig);
      const ri = cat(utf8('z-handle-recover-v1:'), entry.label, u64be(e.v), r.owner, r.rc);
      assert.equal(hex(ri), e.recover_input);
      assert.ok(edOk(r.rpub, ri, r.rsig));
    }
  }
  for (const h of v.histories) {
    let state = null;
    let refusedAt = null, reason = null;
    for (const [i, name] of h.entries.entries()) {
      const next = applyHandleEntry(state, entries[name]);
      if (next.refused) { refusedAt = i; reason = next.refused; break; }
      state = next;
    }
    if (h.verdict.ok) {
      assert.equal(refusedAt, null, `${h.name}: refused ${reason}`);
      assert.equal(state.v, h.verdict.version);
      assert.equal(hex(state.owner), h.verdict.owner);
      assert.equal(hex(state.rc), h.verdict.rc);
      assert.equal(state.intro === null ? null : hex(state.intro), h.verdict.intro);
      assert.equal(state.pow, h.verdict.pow);
    } else {
      assert.equal(refusedAt, h.verdict.refused_at, h.name);
      assert.equal(reason, h.verdict.reason, h.name);
    }
  }
  assert.ok(v.histories.some((h) => h.verdict.ok) && v.histories.filter((h) => !h.verdict.ok).length >= 15);
  for (const n of v.not_records) {
    assert.equal(decodeHandleRecord(unhex(n.value)), null, n.why);
  }
  // Every valid entry's record does decode, so the refusals above are not a
  // decoder that refuses everything.
  for (const name of ['claim', 'update_rotate', 'update_pause', 'recover', 'update_after_recover']) {
    assert.notEqual(decodeHandleRecord(entries[name].value), null, name);
  }
});

test('handles: proof-of-work stamps, and every stamp a relay refuses', () => {
  const p = loadHd('handles').pow;
  assert.equal(p.context, 'z-intro-pow-v1:');
  const u32be = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
  const digestFor = (rid, day, envelope, nonce) =>
    sha256(cat(utf8('z-intro-pow-v1:'), unb64url(rid), u32be(day), sha256(utf8(envelope)), nonce));
  const zeroBits = (d) => {
    let n = 0;
    for (const byte of d) { if (byte === 0) { n += 8; continue; } n += Math.clz32(byte) - 24; break; }
    return n;
  };
  for (const s of p.stamps) {
    assert.equal(unb64url(s.routing_id).length, 32);
    assert.equal(hex(unb64url(s.routing_id)), s.rid_bytes);
    assert.equal(s.day, Math.floor(p.now_ms / 86400000));
    assert.equal(hex(sha256(utf8(s.envelope))), s.envelope_sha256);
    const nonce = unhex(s.nonce);
    assert.equal(nonce.length, 16);
    assert.equal(s.frame_member, b64url(nonce));
    const d = digestFor(s.routing_id, s.day, s.envelope, nonce);
    assert.equal(hex(d), s.digest);
    assert.equal(zeroBits(d), s.zero_bits);
    assert.ok(zeroBits(d) >= s.bits, `${s.bits} bits`);
  }
  const first = p.stamps[0];
  for (const r of p.must_refuse) {
    const d = digestFor(r.routing_id, r.day, r.envelope, unhex(first.nonce));
    assert.equal(hex(d), r.digest, r.why);
    assert.ok(zeroBits(d) < r.bits, r.why);
  }
  // Accepted for the relay's today or yesterday, by the relay's clock.
  for (const w of p.acceptance_window) {
    const today = Math.floor(w.relay_now_ms / 86400000);
    assert.equal(today, w.relay_day);
    const ok = [today, today - 1].some((day) =>
      zeroBits(digestFor(first.routing_id, day, first.envelope, unhex(first.nonce))) >= first.bits);
    assert.equal(ok, w.accepted, `relay day ${today}`);
  }
});

test('handles: the request sealed to xintro, and the acknowledgement and who it does not vouch for', () => {
  const v = loadHd('handles');
  const a = v.intro_ack;
  // The request travels as a §8 envelope sealed to the record's xintro and
  // addressed to its intro routing id: re-sealed here from the recorded
  // draws, opened with the introduction seed's X25519 half, and refused by
  // the rotated key's.
  const q = v.request;
  const introKey = v.keys.find((k) => k.x_pub === q.to_x_pub);
  const claimRecord = decodeHandleRecord(unhex(v.entries.find((e) => e.name === 'claim').value));
  assert.equal(hex(claimRecord.xintro), q.to_x_pub, 'sealed to the xintro the record names');
  assert.equal(b64url(claimRecord.intro), b64url(unhex(introKey.pub)));
  assert.equal(q.to_routing_id, b64url(sha256(claimRecord.intro)), 'addressed to its intro routing id');
  const toPub = unhex(q.to_x_pub), ephSeed = unhex(q.eph_seed), ephPub = xPub(ephSeed);
  const sealKey = hkdf(x25519(ephSeed, toPub), Buffer.alloc(0), cat(utf8('z-sealed-v1'), ephPub, toPub), 32);
  const { ct, mac } = chachaSeal(sealKey, unhex(q.nonce),
    padSealed(utf8(JSON.stringify({ f: q.from_rid, p: q.payload }))), utf8('z-sealed-v1'));
  assert.equal('zs1.' + b64url(cat(ephPub, unhex(q.nonce), ct, mac)), q.envelope);
  const openWith = (xSeedHex) => {
    const raw = unb64url(q.envelope.slice(4));
    const xs = unhex(xSeedHex);
    const k = hkdf(x25519(xs, raw.subarray(0, 32)), Buffer.alloc(0), cat(utf8('z-sealed-v1'), raw.subarray(0, 32), xPub(xs)), 32);
    return JSON.parse(unpadSealed(chachaOpen(k, raw.subarray(32, 44), raw.subarray(44, raw.length - 16),
      raw.subarray(raw.length - 16), utf8('z-sealed-v1'))).toString('utf8'));
  };
  assert.deepEqual(openWith(introKey.x_seed), { f: q.from_rid, p: q.payload });
  assert.throws(() => openWith(v.keys.find((k) => k.name === 'intro_a2').x_seed), 'the rotated key opens nothing');
  assert.equal(q.payload, a.creq_payload, 'the request the acknowledgement answers');
  const u16be = (n) => Buffer.from([(n >> 8) & 0xff, n & 0xff]);
  const creqInput = (j) => {
    const to = utf8(j.to), name = utf8(j.bundle.name ?? '');
    return cat(utf8('z-contact-request-v1:'), unb64(j.bundle.ed), unb64(j.bundle.x),
      u16be(to.length), to, u64be(j.ts), u16be(name.length), name);
  };
  // The request, as §8.1 defines it: its signing input and its id.
  const creq = JSON.parse(unb64(a.creq_payload).toString('utf8'));
  assert.equal(creq.t, 'creq');
  assert.equal(hex(creqInput(creq)), a.creq_signing_input);
  assert.ok(edOk(unb64(creq.bundle.ed), creqInput(creq), unb64(creq.sig)));
  assert.equal(hex(unb64(creq.bundle.ed)), a.requester.ed_pub);
  assert.equal(a.requester.routing_id, b64url(sha256(unb64(creq.bundle.ed))));
  assert.equal(creq.to, b64url(sha256(unhex(a.intro_pub))), 'addressed to the introduction mailbox');
  assert.equal(a.creq_id, hex(sha256(creqInput(creq))));
  // The acknowledgement over (requester, owner account, request).
  assert.equal(hex(edPub(unhex(a.owner_account.ed_seed))), a.owner_account.ed_pub);
  const ackInput = cat(utf8('z-intro-ack-v1:'), unb64url(a.requester.routing_id), unhex(a.owner_account.ed_pub), unhex(a.creq_id));
  assert.equal(hex(ackInput), a.ack_input);
  assert.ok(edOk(unhex(a.intro_pub), ackInput, unb64url(a.ia)));
  for (const r of a.must_refuse) {
    const input = cat(utf8('z-intro-ack-v1:'), unb64url(r.requester_rid), unhex(r.owner_account_ed_pub), unhex(r.creq_id));
    assert.ok(!edOk(unhex(r.intro_pub), input, unb64url(a.ia)), r.why);
  }
  // It rides on the creq the acceptance sends back, as a member §8.1's
  // signature does not cover and an older reader ignores.
  const acc = JSON.parse(unb64(a.acceptance_payload).toString('utf8'));
  assert.equal(JSON.stringify(acc), a.acceptance_json);
  assert.equal(acc.ia, a.ia);
  assert.equal(acc.to, a.requester.routing_id);
  assert.ok(edOk(unb64(acc.bundle.ed), creqInput(acc), unb64(acc.sig)), 'still a genuine creq');
  assert.equal(hex(unb64(acc.bundle.ed)), a.owner_account.ed_pub, 'from the account the ack names');
});
