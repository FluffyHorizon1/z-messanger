'use strict';
/**
 * A mirror: a full, independently verified copy of the log, and therefore
 * the strongest kind of witness. It keeps every entry and the last head it
 * verified, and on each sync it
 *
 *   1. fetches the log's current head and checks the log's signature;
 *   2. checks the new head extends the last one — same size means same
 *      roots; a larger size means a consistency proof that verifies; a
 *      smaller size is a log that shrank;
 *   3. fetches the new entries, appends them to its own trees, and checks
 *      that the log root AND the map root it computed are the ones the log
 *      signed;
 *   4. only then writes the entries and the head to disk, co-signing the
 *      head with its witness key if it has one.
 *
 * Any failure in 2 or 3 is a DIVERGENCE — the log has signed a history that
 * is not an extension of the one this mirror saw, or entries that do not
 * hash to what it signed — and the mirror refuses to move: it keeps the old
 * head, reports, and exits non-zero. The same checks, minus the full copy,
 * are what every client does with its own last head (docs/PROTOCOL.md §19.5).
 *
 * A witness co-signature is `Ed25519(witness_sk, "z-kt-witness-v1:" || sthInput)`;
 * `sth.json` is what a witness serves, from any static host.
 */

const fs = require('fs');
const path = require('path');

const { MerkleLog, verifyConsistency } = require('./merkle.js');
const { SparseMerkleMap } = require('./smt.js');
const {
  labelFor,
  leafHashOf,
  sthToJson,
  sthFromJson,
  entryToJson,
  entryFromJson,
  verifySth,
  witnessInput,
  sign,
  rawPublicKey,
} = require('./log.js');

class Divergence extends Error {
  constructor(message, detail = {}) {
    super(message);
    this.detail = detail;
  }
}

async function defaultFetchJson(url) {
  const res = await fetch(url, { headers: { accept: 'application/json' } });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
}

class Mirror {
  /**
   * @param {object} o
   * @param {string} o.dir         where entries.jsonl and sth.json live
   * @param {string} o.logUrl      e.g. https://kt.zmessengers.com
   * @param {Buffer} o.logPub      the log's pinned 32-byte public key
   * @param {crypto.KeyObject} [o.witnessKey]  co-sign heads with this key
   * @param {(url: string) => Promise<object>} [o.fetchJson]
   * @param {number} [o.pageSize]
   * @param {() => number} [o.now]
   */
  constructor({ dir, logUrl, logPub, witnessKey = null, fetchJson = defaultFetchJson, pageSize = 500, now = Date.now }) {
    this.dir = dir;
    this.logUrl = logUrl.replace(/\/+$/, '');
    this.logPub = logPub;
    this.witnessKey = witnessKey;
    this.fetchJson = fetchJson;
    this.pageSize = pageSize;
    this.now = now;
    this.entriesFile = path.join(dir, 'entries.jsonl');
    this.sthFile = path.join(dir, 'sth.json');
    this.tree = new MerkleLog();
    this.map = new SparseMerkleMap();
    this.entries = [];
    this.latestVersion = new Map(); // label hex → version
    /** the last head this mirror verified, or null before the first sync */
    this.head = null;
    this.poisoned = false;
  }

  /** Read what is on disk and check it against itself. */
  load() {
    fs.mkdirSync(this.dir, { recursive: true });
    let text = '';
    try {
      text = fs.readFileSync(this.entriesFile, 'utf8');
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
    }
    for (const line of text.split('\n')) {
      if (line === '') continue;
      this._append(entryFromJson(JSON.parse(line)));
    }
    try {
      const j = JSON.parse(fs.readFileSync(this.sthFile, 'utf8'));
      this.head = sthFromJson(j.sth);
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
      this.head = null;
    }
    if (this.head) {
      if (!verifySth(this.head, this.logPub)) throw new Error(`${this.sthFile}: the stored head is not signed by the pinned log key`);
      if (this.head.size !== this.entries.length) throw new Error(`${this.sthFile}: head size ${this.head.size}, ${this.entries.length} entries on disk`);
      if (!this.tree.root.equals(this.head.logRoot) || !this.map.root.equals(this.head.mapRoot)) {
        throw new Error(`${this.dir}: the entries on disk do not hash to the stored head`);
      }
    } else if (this.entries.length !== 0) {
      throw new Error(`${this.dir}: entries without a head`);
    }
    return this;
  }

  _append(e) {
    if (e.index !== this.entries.length) throw new Divergence(`entry ${e.index} where ${this.entries.length} was expected`);
    const key = e.label.toString('hex');
    const prev = this.latestVersion.get(key);
    if (prev !== undefined && !(e.version > prev)) {
      throw new Divergence(`entry ${e.index}: version ${e.version} does not exceed ${prev} for its label`);
    }
    this.tree.append(leafHashOf(e));
    this.map.set(e.label, e.index, e.version);
    this.entries.push(e);
    this.latestVersion.set(key, e.version);
  }

  /**
   * One sync. Resolves to { from, to, head } when the log's head verified
   * as an extension of the last one; rejects with Divergence when it did
   * not (the mirror is then `poisoned` and must be re-created from disk),
   * or with an ordinary Error when the log could not be reached.
   */
  async sync() {
    if (this.poisoned) throw new Error('this mirror diverged; load a fresh one');
    const from = this.entries.length;
    const sthJ = await this.fetchJson(`${this.logUrl}/kt/v1/sth`);
    const sth = sthFromJson(sthJ);
    if (!verifySth(sth, this.logPub)) throw new Divergence('the head is not signed by the pinned log key');
    try {
      if (sth.size < from) throw new Divergence(`the log shrank: it had ${from} entries, its head now says ${sth.size}`, { from, to: sth.size });
      if (sth.size === from) {
        if (this.head && (!sth.logRoot.equals(this.head.logRoot) || !sth.mapRoot.equals(this.head.mapRoot))) {
          throw new Divergence(`same size ${from}, different roots`, { from, to: sth.size });
        }
        if (!this.head && from === 0) {
          // The empty log: nothing to fetch, but the roots must be the empty ones.
          if (!sth.logRoot.equals(this.tree.root) || !sth.mapRoot.equals(this.map.root)) throw new Divergence('an empty head with non-empty roots');
        }
      } else {
        if (from > 0) {
          const c = await this.fetchJson(`${this.logUrl}/kt/v1/consistency?first=${from}&second=${sth.size}`);
          if (c.first !== from || c.second !== sth.size || !Array.isArray(c.proof)) throw new Divergence('consistency: wrong shape');
          const proof = c.proof.map((h) => Buffer.from(h, 'base64'));
          if (!verifyConsistency({ first: from, second: sth.size, firstRoot: this.head.logRoot, secondRoot: sth.logRoot, proof })) {
            throw new Divergence(`the head of size ${sth.size} does not extend the head of size ${from}`, { from, to: sth.size });
          }
        }
        let next = from;
        while (next < sth.size) {
          const count = Math.min(this.pageSize, sth.size - next);
          const page = await this.fetchJson(`${this.logUrl}/kt/v1/entries?start=${next}&count=${count}`);
          if (!Array.isArray(page.entries) || page.entries.length === 0) throw new Divergence(`the log served no entries from ${next} though its head says ${sth.size}`);
          for (const j of page.entries) {
            if (next >= sth.size) break;
            let e;
            try {
              e = entryFromJson(j);
            } catch (err) {
              throw new Divergence(`entry ${next}: ${err.message}`);
            }
            this._append(e);
            next++;
          }
        }
        if (!this.tree.root.equals(sth.logRoot)) throw new Divergence(`the entries do not hash to the signed log root at size ${sth.size}`, { from, to: sth.size });
        if (!this.map.root.equals(sth.mapRoot)) throw new Divergence(`the entries do not give the signed map root at size ${sth.size}`, { from, to: sth.size });
      }
    } catch (e) {
      if (e instanceof Divergence) this.poisoned = true;
      throw e;
    }
    // Verified: persist the new entries, then the head.
    if (sth.size > from) {
      const lines = this.entries.slice(from).map((e) => JSON.stringify(entryToJson(e)) + '\n').join('');
      const fd = fs.openSync(this.entriesFile, 'a');
      try {
        fs.writeSync(fd, lines);
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
    }
    const record = { sth: sthToJson(sth), verifiedAt: this.now(), size: sth.size };
    if (this.witnessKey) {
      record.witness = {
        pub: rawPublicKey(this.witnessKey).toString('base64'),
        sig: sign(this.witnessKey, witnessInput(sth)).toString('base64'),
      };
    }
    const tmp = `${this.sthFile}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(record, null, 2) + '\n');
    fs.renameSync(tmp, this.sthFile);
    this.head = sth;
    return { from, to: sth.size, head: sth };
  }

  /** The witness view: what a client fetches from a witness URL. */
  record() {
    return JSON.parse(fs.readFileSync(this.sthFile, 'utf8'));
  }

  /** For tests and tools: the label of an account key, so a mirror can answer "is this account in the log?". */
  static labelFor(acctPub) {
    return labelFor(acctPub);
  }
}

module.exports = { Mirror, Divergence };
