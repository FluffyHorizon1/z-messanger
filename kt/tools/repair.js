#!/usr/bin/env node
'use strict';
/**
 * Drops a trailing partial line from a log's entries file — and nothing else.
 *
 * A log whose last line has no newline cannot be opened at all: `readAll`
 * refuses it as a torn write, which is the right refusal, and before
 * 2026-09-14 there was no way back from it. `append` now writes the whole
 * line or truncates back to where it started, so a file damaged this way is
 * one written by an older build, or by a machine that died between the write
 * and the fsync.
 *
 * What it will do: if there are bytes after the file's last newline, remove
 * exactly those bytes. Nothing else is a repair. A line that is complete but
 * wrong — an edited value, a missing entry, a version that went backwards —
 * is not damage this tool can undo, and silently dropping such a line would
 * be a tool that rewrites history to make a log start, which is the opposite
 * of what a log is for. Those it names and refuses.
 *
 * It does not write unless asked. The default is to say what it would do.
 *
 *   node tools/repair.js /var/lib/z-kt/entries.jsonl          # report only
 *   node tools/repair.js /var/lib/z-kt/entries.jsonl --write  # do it
 *
 * Stop the log first: it holds the file open for append, and a repair under
 * a running log would be undone by the next publish.
 */
const fs = require('fs');
const path = require('path');

const { KtLog, FileStore, privateKeyFromSeed } = require('../lib/log.js');

/**
 * The file's last newline, or -1. Read backwards in windows so a large log
 * costs a few kilobytes rather than its own size — the same reason the
 * replay reads forwards in windows.
 */
function lastNewline(fd, size) {
  const win = 64 * 1024;
  const buf = Buffer.allocUnsafe(win);
  for (let end = size; end > 0; ) {
    const at = Math.max(0, end - win);
    const n = fs.readSync(fd, buf, 0, end - at, at);
    const i = buf.subarray(0, n).lastIndexOf(0x0a);
    if (i >= 0) return at + i;
    end = at;
  }
  return -1;
}

function main(argv) {
  const args = argv.slice(2);
  const write = args.includes('--write');
  const file = args.find((a) => !a.startsWith('-'));
  if (!file) {
    console.error('usage: repair.js <entries.jsonl> [--write]');
    return 2;
  }
  if (!fs.existsSync(file)) {
    console.error(`${file}: no such file`);
    return 2;
  }
  const size = fs.statSync(file).size;
  if (size === 0) {
    console.log(`${file}: empty; nothing to repair`);
    return 0;
  }

  const fd = fs.openSync(file, 'r');
  let nl;
  try {
    nl = lastNewline(fd, size);
  } finally {
    fs.closeSync(fd);
  }
  const tail = size - (nl + 1);
  if (tail === 0) {
    console.log(`${file}: ${size} bytes, ends at a line boundary — no partial line to drop.`);
    console.log('If it still refuses to open, the damage is inside a complete line and this tool');
    console.log('will not touch it: a repair that drops whole entries is a rewrite of the history.');
    return 1;
  }

  const at = nl + 1;
  console.log(`${file}: ${size} bytes, last newline at ${nl}.`);
  console.log(`A partial line of ${tail} byte(s) follows it — written, never finished.`);
  if (!write) {
    console.log(`Would truncate to ${at} bytes. Re-run with --write to do it.`);
    return 0;
  }

  // Keep what is being removed, so a repair is never the only copy of it.
  const keep = `${file}.partial-${Date.now()}`;
  const rfd = fs.openSync(file, 'r');
  try {
    const buf = Buffer.allocUnsafe(tail);
    let got = 0;
    while (got < tail) {
      const n = fs.readSync(rfd, buf, got, tail - got, at + got);
      if (n === 0) break;
      got += n;
    }
    fs.writeFileSync(keep, buf.subarray(0, got));
  } finally {
    fs.closeSync(rfd);
  }

  const wfd = fs.openSync(file, 'r+');
  try {
    fs.ftruncateSync(wfd, at);
    fs.fsyncSync(wfd);
  } finally {
    fs.closeSync(wfd);
  }
  let dfd;
  try {
    dfd = fs.openSync(path.dirname(path.resolve(file)), 'r');
    fs.fsyncSync(dfd);
  } catch {
    // not every platform lets a directory be opened
  } finally {
    if (dfd !== undefined) fs.closeSync(dfd);
  }
  console.log(`Truncated to ${at} bytes; the dropped bytes are in ${keep}.`);

  // And say whether it worked, which is the only answer the operator wants.
  // A throwaway key: replaying checks the file, and nothing here is served.
  try {
    const log = new KtLog({ store: new FileStore(file), signingKey: privateKeyFromSeed(Buffer.alloc(32, 1)) });
    console.log(`It opens: ${log.size} entries, ${log.map.size} labels.`);
    log.close();
    return 0;
  } catch (e) {
    console.error(`It still does not open: ${e.message}`);
    return 1;
  }
}

if (require.main === module) process.exit(main(process.argv));
module.exports = { main, lastNewline };
