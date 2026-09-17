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
 *
 * Two rules govern everything below, and both are about the difference
 * between a log that misbehaved and a network that did.
 *
 *   A. DIVERGENCE IS PERMANENT, SO IT IS RESERVED FOR SIGNED EVIDENCE. A
 *      mirror that diverges stops following the log for ever (`--serve` keeps
 *      answering with the last head it verified). That is the correct answer
 *      to a log which signed a history it cannot have, and the wrong answer
 *      to a dropped connection, an HTTP 502, or a CDN error page: a witness
 *      that cries fork on packet loss is worse than no witness, because the
 *      first real fork is then dismissed as another one of those. So a
 *      response whose SHAPE is wrong — a consistency object with the wrong
 *      fields, a page with no entries — is an ordinary error and the mirror
 *      tries again. Only something the log SIGNED, or entries that fail to
 *      reproduce what it signed, poisons it.
 *
 *   B. A SYNC BEGINS FROM THE STATE THE LAST VERIFIED HEAD DESCRIBES. The
 *      in-memory trees cannot be cheaply rewound — undoing a page means
 *      rebuilding them, which is seconds at seven thousand entries and grows
 *      — so nothing is appended until every page has been fetched, and a
 *      commit that cannot be written rereads the directory rather than
 *      carrying state no head covers. Before 2026-09-14 neither held: one
 *      dropped connection mid-pagination left `entries` ahead of both the
 *      disk and the head, and the NEXT sync asked the log to prove
 *      consistency from a size this mirror had never had a head for. The log
 *      cannot, so the mirror reported a fork and latched.
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
  EntryShapeError,
  verifySth,
  witnessInput,
  sign,
  rawPublicKey,
} = require('./log.js');

/** How much of the entries file is read at a time while replaying. */
const REPLAY_WINDOW = 1024 * 1024;

/**
 * The part of an entry the trees need: everything `leafHashOf` and the map
 * read, and nothing else. The value is on disk; keeping it in memory as well
 * is what made a witness cost the size of its file.
 */
function leafOf(e) {
  return { index: e.index, label: e.label, version: e.version, fp: e.fp, valueHash: e.valueHash, ts: e.ts };
}

/** Write every byte or throw: `fs.writeSync` may write a prefix and return. */
function writeAll(fd, bytes, name) {
  let put = 0;
  while (put < bytes.length) {
    const n = fs.writeSync(fd, bytes, put, bytes.length - put);
    if (!(n > 0)) throw new Error(`${name}: wrote ${put + n} of ${bytes.length} bytes`);
    put += n;
  }
}

class Divergence extends Error {
  constructor(message, detail = {}) {
    super(message);
    this.detail = detail;
  }
}

/**
 * The longest a 429 can make one page wait, and how many times one page is
 * asked for before the sync is given up. The log's budget refills a page in
 * seconds; sixty is a `retry-after` from something else in front, and past
 * that the right move is the next scheduled sync, not a socket held open.
 */
const RETRY_AFTER_MAX_MS = 60_000;
const RETRIES_PER_PAGE = 20;

/**
 * A fetch that honours `retry-after`. The log budgets `/kt/v1/entries` in
 * bytes a minute and answers 429 when a reader is over it, saying how long
 * until it is not; a first sync of a large log is over it by design after a
 * few pages, and a mirror that took a 429 for a failure would drop the pages
 * it had, sync again five minutes later, and never finish. So it waits, as
 * long as it is told, and asks again — a bounded number of times, then the
 * sync fails like any other transport error and the next one starts over.
 * Every other status is what it was: an error, this sync's.
 *
 * `fetch` and `sleep` are injectable so the waiting can be tested without
 * waiting.
 */
function makeFetchJson({ fetch: fetchImpl = fetch, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), retries = RETRIES_PER_PAGE } = {}) {
  return async function fetchJson(url) {
    for (let attempt = 0; ; attempt++) {
      const res = await fetchImpl(url, { headers: { accept: 'application/json' } });
      if (res.ok) return res.json();
      if (res.status === 429 && attempt < retries) {
        await sleep(retryAfterMs(res.headers.get('retry-after')));
        continue;
      }
      throw new Error(`${url}: HTTP ${res.status}`);
    }
  };
}

/** `retry-after` in milliseconds: delta-seconds, bounded; a second when absent or unreadable. */
function retryAfterMs(header) {
  const s = Number(header);
  if (!Number.isFinite(s) || s < 1) return 1000;
  return Math.min(RETRY_AFTER_MAX_MS, Math.ceil(s) * 1000);
}

const defaultFetchJson = makeFetchJson();

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
    /** where a sync spools the pages it has fetched, before any is believed */
    this.spoolFile = path.join(dir, 'entries.jsonl.incoming');
    this.tree = new MerkleLog();
    this.map = new SparseMerkleMap();
    this.entries = [];
    this.latestVersion = new Map(); // label hex → version
    /** the last head this mirror verified, or null before the first sync */
    this.head = null;
    this.poisoned = false;
    /** set when a commit failed and the disk could not be re-read; see rule B */
    this.needsReload = false;
    /** bytes `load` dropped from the end of entries.jsonl, if any */
    this.repaired = 0;
  }

  /**
   * Read what is on disk and check it against itself.
   *
   * The head is read FIRST, because it is signed by the log and it is the
   * authority on how many of the lines that follow count. `sync` fsyncs the
   * entries and only then renames `sth.json` into place, so a machine that
   * dies between the two leaves entries the stored head does not cover — and
   * before 2026-09-14 that directory could not be opened again by anything,
   * with no repair path: `head size 9, 13 entries on disk`, for ever.
   *
   * Those surplus lines are dropped. Nothing is lost by it and nothing is
   * rewritten: they sit ABOVE the last head this mirror verified, so they are
   * not part of any history it has attested to, and the next sync fetches
   * them again and checks them against a signed root before they are believed.
   * That is exactly why `tools/repair.js` refuses to do the same thing to the
   * LOG's own file — there, a dropped line is history the log has signed, and
   * a tool that trims it is a tool that rewrites what a log exists to fix.
   *
   * The other direction — fewer entries than the head — is not repairable
   * here and still refuses. Those entries are under a signed root; they
   * cannot be re-derived from anything in this directory.
   */
  load() {
    fs.mkdirSync(this.dir, { recursive: true });
    this.repaired = 0;
    try {
      const raw = fs.readFileSync(this.sthFile, 'utf8');
      let j;
      try {
        j = JSON.parse(raw);
      } catch (e) {
        // The head file exists but does not parse. With the durable write in
        // `sync` below (temp file, fsync, atomic rename, dir fsync) a crash
        // there can no longer leave a torn head; a head that is unreadable
        // anyway is corruption this mirror cannot verify against, and it will
        // NOT silently discard the entries it was trusted to keep (a mirror is
        // the history the log might lose — G3). It says so, distinctly from
        // the honest no-head case below, which a `SyntaxError` (no `.code`)
        // used to fall into as a raw rethrow with no context.
        throw new Error(
          `${this.sthFile}: the stored head does not parse (${e.message}). ` +
            `It is the head this mirror verified against; restore it from a ` +
            `backup, or re-initialise the mirror from the log if its history ` +
            `is safe elsewhere.`
        );
      }
      this.head = sthFromJson(j.sth);
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
      this.head = null;
    }
    if (this.head && !verifySth(this.head, this.logPub)) {
      throw new Error(`${this.sthFile}: the stored head is not signed by the pinned log key`);
    }
    const want = this.head ? this.head.size : 0;

    // A sync that died between spooling a delta and committing it leaves the
    // spool behind. It was never verified, so it is nothing.
    try {
      fs.unlinkSync(this.spoolFile);
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
    }

    // The file is read a window at a time and an entry keeps its leaf
    // fields, not its value — the two things `kt/lib/log.js` fixed for the
    // log on 2026-09-13 and this file did not get until 2026-09-17. It read
    // the whole file into one buffer and kept every sealed value in
    // `this.entries` for the life of the process: measured on a 16 MiB
    // directory, 12.5 MiB retained where the log's replay retains 0.5. A
    // witness on a starter instance mirroring a log whose file has passed
    // instance memory then OOMs on `load()`, permanently, because the file
    // it cannot read is the file it must read to start.
    let at = 0; // bytes consumed by the lines that count
    let fileSize = 0;
    let fd = null;
    try {
      fd = fs.openSync(this.entriesFile, 'r');
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
    }
    if (fd !== null) {
      try {
        fileSize = fs.fstatSync(fd).size;
        const buf = Buffer.allocUnsafe(REPLAY_WINDOW);
        let rest = Buffer.alloc(0);
        let restAt = 0;
        let read = 0;
        let done = false;
        while (!done && this.entries.length < want) {
          const n = fs.readSync(fd, buf, 0, REPLAY_WINDOW, read);
          read += n;
          if (n === 0) break;
          rest = rest.length === 0 ? Buffer.from(buf.subarray(0, n)) : Buffer.concat([rest, buf.subarray(0, n)]);
          let from = 0;
          while (this.entries.length < want) {
            const nl = rest.indexOf(0x0a, from);
            if (nl < 0) break;
            const line = rest.subarray(from, nl);
            from = nl + 1;
            at = restAt + from;
            if (line.length === 0) continue;
            this._append(leafOf(entryFromJson(JSON.parse(line.toString('utf8')))));
          }
          rest = Buffer.from(rest.subarray(from));
          restAt += from;
          done = n < REPLAY_WINDOW && rest.length === 0;
        }
      } finally {
        fs.closeSync(fd);
      }
    }

    if (this.head) {
      if (this.entries.length !== want) {
        throw new Error(
          `${this.sthFile}: head size ${want}, ${this.entries.length} entries on disk. ` +
          `Entries below the head are covered by a root the log signed and cannot be ` +
          `rebuilt from this directory — restore the file, or delete the directory and ` +
          `mirror the log from the start.`);
      }
      if (at < fileSize) {
        // The crash window. Drop the surplus and fsync, so this is a repair
        // and not a decision taken again on every start.
        this.repaired = fileSize - at;
        const wfd = fs.openSync(this.entriesFile, 'r+');
        try {
          fs.ftruncateSync(wfd, at);
          fs.fsyncSync(wfd);
        } finally {
          fs.closeSync(wfd);
        }
      }
      if (!this.tree.root.equals(this.head.logRoot) || !this.map.root.equals(this.head.mapRoot)) {
        throw new Error(`${this.dir}: the entries on disk do not hash to the stored head`);
      }
    } else if (fileSize !== 0) {
      // No head means nothing here has ever been verified, so there is no
      // authority to repair against. Refusing is the only honest answer.
      throw new Error(`${this.dir}: entries without a head`);
    }
    this.needsReload = false;
    return this;
  }

  /** Discard everything in memory and read the directory again. */
  _reload() {
    this.tree = new MerkleLog();
    this.map = new SparseMerkleMap();
    this.entries = [];
    this.latestVersion = new Map();
    this.head = null;
    return this.load();
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
    // Rule B. The only state a sync may build on is the state the last
    // verified head describes. A commit that could not be written leaves
    // memory ahead of it; the disk is the authority, so read it again.
    if (this.needsReload || this.entries.length !== (this.head ? this.head.size : 0)) this._reload();
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
          // Rule A: a malformed response is what a proxy, a captive portal or
          // a 502 page produces. It says nothing about what the log signed,
          // so it is an ordinary error and the mirror asks again.
          if (c.first !== from || c.second !== sth.size || !Array.isArray(c.proof)) {
            throw new Error(`consistency: wrong shape from ${this.logUrl} (first=${c.first}, second=${c.second})`);
          }
          const proof = c.proof.map((h) => Buffer.from(h, 'base64'));
          if (!verifyConsistency({ first: from, second: sth.size, firstRoot: this.head.logRoot, secondRoot: sth.logRoot, proof })) {
            throw new Divergence(`the head of size ${sth.size} does not extend the head of size ${from}`, { from, to: sth.size });
          }
        }
        // Rule B: every page is fetched before ANY of it is appended.
        // `_append` mutates three structures and none of them rewinds
        // cheaply — undoing a page means rebuilding, which measured ~7 s at
        // seven thousand entries and grows with the log — so the rule is
        // that nothing is mutated while a network can still interrupt.
        // The cost is holding the delta twice for the length of the fetch,
        // and the delta is on its way into `this.entries` regardless.
        // Fetched pages go to a spool file, one page at a time, and what
        // memory keeps is the leaf fields: a first sync of a 1 GB log used
        // to hold the whole delta in `fetched`, values included, which
        // together with `load` reading the file whole was finding 19 — a
        // witness that cannot start on the instance the Blueprint gives it.
        // The spool is nothing until every page is in hand and both roots
        // have matched; a fetch that fails or a divergence just deletes it.
        const fetched = [];
        const spool = fs.openSync(this.spoolFile, 'w');
        let next = from;
        try {
        while (next < sth.size) {
          const count = Math.min(this.pageSize, sth.size - next);
          const page = await this.fetchJson(`${this.logUrl}/kt/v1/entries?start=${next}&count=${count}`);
          if (!Array.isArray(page.entries) || page.entries.length === 0) {
            // Rule A again: an empty page is a broken response, not a fork.
            throw new Error(`the log served no entries from ${next} though its head says ${sth.size}`);
          }
          const lines = [];
          for (const j of page.entries) {
            if (next >= sth.size) break;
            let e;
            try {
              e = entryFromJson(j);
            } catch (err) {
              // Two different things come out of `entryFromJson`, and the
              // comment here used to claim it was one. A malformed element —
              // `null`, a short label, a missing field — is what a cache or
              // an error page produces and is rule A's transport failure: an
              // ordinary error, and the mirror asks again. A value that does
              // not hash to its commitment is content the log served under a
              // head it signed, and that is a divergence. Until 2026-09-17
              // both were `Divergence`, so a proxy could stop a witness
              // following the log for ever with one bad element — the thing
              // 3.3.9 was released to stop.
              if (err instanceof EntryShapeError) {
                throw new Error(`entry ${next} from ${this.logUrl} is malformed: ${err.message}`);
              }
              throw new Divergence(`entry ${next}: ${err.message}`);
            }
            lines.push(JSON.stringify(entryToJson(e)) + '\n');
            fetched.push(leafOf(e));
            next++;
          }
          writeAll(spool, Buffer.from(lines.join(''), 'utf8'), this.spoolFile);
        }
        fs.fsyncSync(spool);
        } finally {
          fs.closeSync(spool);
        }
        for (const e of fetched) this._append(e);
        if (!this.tree.root.equals(sth.logRoot)) throw new Divergence(`the entries do not hash to the signed log root at size ${sth.size}`, { from, to: sth.size });
        if (!this.map.root.equals(sth.mapRoot)) throw new Divergence(`the entries do not give the signed map root at size ${sth.size}`, { from, to: sth.size });
      }
    } catch (e) {
      if (e instanceof Divergence) this.poisoned = true;
      this._dropSpool();
      throw e;
    }
    // Verified: persist the new entries, then the head. Either both land or
    // neither does. A half-commit is what leaves the directory unloadable —
    // `load` repairs that case now — and, in the running process, memory
    // holding entries no head covers, which is rule B's whole subject.
    if (sth.size > from) {
      // The spool holds exactly the lines that were verified. Copy it onto
      // the end of the entries file a window at a time — never the whole
      // delta in memory — and only then drop it.
      const fd = fs.openSync(this.entriesFile, 'a');
      const at = fs.fstatSync(fd).size;
      let src = null;
      try {
        src = fs.openSync(this.spoolFile, 'r');
        // The same partial-write rule as the log's own append, and for the
        // same reason: `fs.writeSync` may write a prefix and return how much
        // without throwing, and a mirror whose file ends mid-line cannot be
        // loaded again. Write it all or leave the file as it was.
        const buf = Buffer.allocUnsafe(REPLAY_WINDOW);
        let off = 0;
        for (;;) {
          const n = fs.readSync(src, buf, 0, REPLAY_WINDOW, off);
          if (n === 0) break;
          writeAll(fd, buf.subarray(0, n), this.entriesFile);
          off += n;
        }
        fs.fsyncSync(fd);
      } catch (e) {
        try {
          fs.ftruncateSync(fd, at);
          fs.fsyncSync(fd);
        } catch {}
        if (src !== null) fs.closeSync(src);
        fs.closeSync(fd);
        this._dropSpool();
        // The comment here used to say the entries would simply be re-fetched
        // next time. They would not: `from` is `this.entries.length`, which
        // this sync has already advanced, so the next one asked for a
        // consistency proof from a size no head covered. Rule B, restated.
        this._recover();
        throw e;
      }
      fs.closeSync(src);
      fs.closeSync(fd);
      this._dropSpool();
    }
    const record = { sth: sthToJson(sth), verifiedAt: this.now(), size: sth.size };
    if (this.witnessKey) {
      record.witness = {
        pub: rawPublicKey(this.witnessKey).toString('base64'),
        sig: sign(this.witnessKey, witnessInput(sth)).toString('base64'),
      };
    }
    try {
      // Durable and atomic, the way the log writes its own head (`log.js`
      // `atomicWrite`): write a temp file, fsync it, rename over the real one,
      // then fsync the directory so the rename is on disk too. `writeFileSync`
      // + `renameSync` did neither, so a crash could leave `sth.json` torn or
      // the rename un-flushed — the head unreadable while the entries stood
      // (the 2026-09-14 review's finding 43).
      const tmp = `${this.sthFile}.tmp`;
      const buf = Buffer.from(JSON.stringify(record, null, 2) + '\n', 'utf8');
      const fd = fs.openSync(tmp, 'w');
      try {
        let put = 0;
        while (put < buf.length) {
          const n = fs.writeSync(fd, buf, put, buf.length - put);
          if (!(n > 0)) {
            throw new Error(`${tmp}: wrote ${put + n} of ${buf.length} bytes`);
          }
          put += n;
        }
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      fs.renameSync(tmp, this.sthFile);
      this._syncDir();
    } catch (e) {
      // The entries are on disk and the head is not: the crash window, reached
      // without a crash. `load` drops the surplus, which is what `_recover`
      // runs, so the process carries on from the head it last verified.
      this._recover();
      throw e;
    }
    this.head = sth;
    return { from, to: sth.size, head: sth };
  }

  /** fsync the directory holding sth.json, so the rename onto it is durable. */
  _syncDir() {
    let dfd;
    try {
      dfd = fs.openSync(path.dirname(this.sthFile), 'r');
    } catch {
      return; // not every platform lets a directory be opened; the file is synced
    }
    try {
      fs.fsyncSync(dfd);
    } catch {
      // EINVAL on filesystems that do not support it — nothing to do here.
    } finally {
      fs.closeSync(dfd);
    }
  }

  /** The spool is nothing until it is committed; afterwards it is nothing again. */
  _dropSpool() {
    try {
      fs.unlinkSync(this.spoolFile);
    } catch {}
  }

  /**
   * Put memory back to what the disk says, without ever masking the error
   * that made it necessary. If the directory itself cannot be read, the flag
   * makes the next `sync` try again rather than build on a state no head
   * describes.
   */
  _recover() {
    try {
      this._reload();
    } catch {
      this.needsReload = true;
    }
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

module.exports = { Mirror, Divergence, makeFetchJson, retryAfterMs };
