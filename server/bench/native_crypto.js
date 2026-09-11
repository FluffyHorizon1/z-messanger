#!/usr/bin/env node
// The same primitives as protocol/tool/crypto_bench.dart, through OpenSSL —
// a stand-in, on the same machine, for what a platform implementation would
// cost (Android's Conscrypt is BoringSSL, Apple's CryptoKit is corecrypto;
// both are compiled code of the same kind). Z runs none of this: its
// cryptography is pure Dart, and this file exists so PERFORMANCE.md can say
// by how much. Run: node bench/native_crypto.js
'use strict';

const crypto = require('crypto');

function median(fn, runs = 200, warm = 20) {
  for (let i = 0; i < warm; i++) fn();
  const t = [];
  for (let i = 0; i < runs; i++) {
    const s = process.hrtime.bigint();
    fn();
    t.push(Number(process.hrtime.bigint() - s) / 1000);
  }
  t.sort((a, b) => a - b);
  return t[t.length >> 1];
}
function fmt(us) {
  const ms = us / 1000;
  if (ms >= 100) return `${ms.toFixed(0)} ms`;
  if (ms >= 1) return `${ms.toFixed(2)} ms`;
  return `${us.toFixed(0)} µs`;
}

const rows = [];
const add = (group, op, fn, runs) => rows.push([group, op, fmt(median(fn, runs))]);

const msg = crypto.randomBytes(200);
const kb1 = crypto.randomBytes(1024);
const kb64 = crypto.randomBytes(65536);

add('SHA-256', '1 KB', () => crypto.hash('sha256', kb1, 'buffer'));
add('SHA-256', '64 KB', () => crypto.hash('sha256', kb64, 'buffer'));
const macKey = crypto.randomBytes(32);
add('HMAC-SHA256', '1 KB', () => crypto.createHmac('sha256', macKey).update(kb1).digest());
add('HKDF-SHA256', '32 bytes out', () => crypto.hkdfSync('sha256', macKey, kb1.subarray(0, 32), msg, 32));

// OpenSSL has ChaCha20-Poly1305 (12-byte nonce); XChaCha20 adds one HChaCha20
// block on top, which is a rounding error at these sizes.
const aeadKey = crypto.randomBytes(32);
const nonce = crypto.randomBytes(12);
function seal(pt) {
  const c = crypto.createCipheriv('chacha20-poly1305', aeadKey, nonce, { authTagLength: 16 });
  const ct = Buffer.concat([c.update(pt), c.final()]);
  return { ct, tag: c.getAuthTag() };
}
function open({ ct, tag }) {
  const d = crypto.createDecipheriv('chacha20-poly1305', aeadKey, nonce, { authTagLength: 16 });
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}
const box1 = seal(kb1);
const box64 = seal(kb64);
add('ChaCha20-Poly1305', 'seal 1 KB', () => seal(kb1));
add('ChaCha20-Poly1305', 'open 1 KB', () => open(box1));
add('ChaCha20-Poly1305', 'seal 64 KB', () => seal(kb64));
add('ChaCha20-Poly1305', 'open 64 KB', () => open(box64));

const xa = crypto.generateKeyPairSync('x25519');
const xb = crypto.generateKeyPairSync('x25519');
add('X25519', 'keygen', () => crypto.generateKeyPairSync('x25519'));
add('X25519', 'shared secret', () => crypto.diffieHellman({ privateKey: xa.privateKey, publicKey: xb.publicKey }));

const ed = crypto.generateKeyPairSync('ed25519');
const sig = crypto.sign(null, msg, ed.privateKey);
const edPubRaw = ed.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
const SPKI = Buffer.from('302a300506032b6570032100', 'hex');
add('Ed25519', 'keygen', () => crypto.generateKeyPairSync('ed25519'));
add('Ed25519', 'sign 200 B', () => crypto.sign(null, msg, ed.privateKey));
add('Ed25519', 'verify 200 B', () => crypto.verify(null, msg, ed.publicKey, sig));
add('Ed25519', 'verify (key from bytes)', () =>
  crypto.verify(null, msg, crypto.createPublicKey({ key: Buffer.concat([SPKI, edPubRaw]), format: 'der', type: 'spki' }), sig)
);

console.log(`node ${process.version}, ${process.versions.openssl}`);
console.log('');
console.log('| primitive | operation | OpenSSL, this machine |');
console.log('|---|---|---:|');
for (const [g, o, v] of rows) console.log(`| ${g} | ${o} | ${v} |`);
