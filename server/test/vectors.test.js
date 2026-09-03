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
const headerBytes = (h) => utf8(`{"dh":"${h.dh}","n":${h.n},"pn":${h.pn}}`);

function makeSession(ad) {
  return { rootKey: null, dhsSeed: null, dhsPub: null, dhrPub: null, cks: null, ckr: null, ns: 0, nr: 0, pn: 0, ad, skipped: new Map() };
}

function drEncrypt(s, plaintext, nonce) {
  assert.ok(s.cks, 'sending chain not initialised');
  const [mk, next] = kdfCk(s.cks);
  const header = { dh: b64(s.dhsPub), n: s.ns, pn: s.pn };
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

function drDecrypt(s, msg, draws) {
  const aad = cat(s.ad, headerBytes(msg.header));
  const key = `${msg.header.dh}|${msg.header.n}`;
  if (s.skipped.has(key)) {
    const mk = s.skipped.get(key); s.skipped.delete(key);
    return unpad7816(xchachaOpen(mk, msg.nonce, msg.ct, msg.mac, aad));
  }
  const theirPub = unb64(msg.header.dh);
  if (!s.dhrPub || !s.dhrPub.equals(theirPub)) {
    drSkip(s, msg.header.pn);
    drDhStep(s, theirPub, draws.shift());
  }
  drSkip(s, msg.header.n);
  const [mk, next] = kdfCk(s.ckr);
  const plain = unpad7816(xchachaOpen(mk, msg.nonce, msg.ct, msg.mac, aad));
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
};

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
    assert.equal(m.padded_len, Math.ceil((utf8(m.json).length + 1) / 256) * 256);
    seen.add(m.kind);
  }
  assert.deepEqual([...seen].sort(), Object.keys(INNER_SCHEMA).sort());
  const s = JSON.parse(v.sync_envelope.json);
  assert.deepEqual(Object.keys(s), ['thread', 'dir', 'inner']);
  assert.equal(JSON.parse(unb64(s.inner).toString('utf8')).k, 'text');
});
