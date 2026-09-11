#!/usr/bin/env node
// What delaying, jittering or padding the traffic would buy against a relay
// that clusters mailboxes by WHEN they light up together — the study behind
// THREAT_MODEL.md R18 (groups) and R19 (a person's devices), 16.2.
//
// The relay sees one thing per delivery: (mailbox, time). A group message
// is one copy per member, enqueued within ~100 ms of each other (measured:
// 64–135 ms for five members). The question is how many group messages a
// relay needs to see before it can name the group's mailboxes, and how that
// number moves if each copy is delayed by a random amount up to D, or if
// every mailbox is kept busy with cover traffic.
//
// A simulation, seeded, with the measured constants as inputs — not a
// measurement of the relay, which cannot tell us what an attacker would do
// with its logs. Run it:
//
//     node bench/patterns.js                 # the table in THREAT_MODEL.md
//     N=2000 DAYS=7 node bench/patterns.js   # bigger population, longer watch
//
// The population: N mailboxes; G groups of S members; every mailbox also
// receives ordinary 1:1 traffic at BACKGROUND deliveries per day (unrelated
// to any group), which is what the group's co-activations have to stand out
// against. Each group sends K messages at random moments over DAYS days.
//
// The attacker: for every pair of mailboxes, count how often a delivery to
// one falls within W of a delivery to the other, where W covers the whole
// jitter (the attacker knows D — the honest assumption). Two independent
// mailboxes co-activate by chance at a rate the attacker can compute from
// their delivery counts, so for any count threshold T the attacker can
// also compute how many pairs will pass it by chance. The attacker picks
// the smallest T at which chance passes are under 5 % of the pairs flagged,
// and flags every pair at or above it. Precision and recall are then
// measured against the real groups. Nothing about K, S, or which mailboxes
// are in groups is given to the attacker.
//
// Two mitigations are modelled. JITTER: every copy is held back by a
// uniform random delay in [0, D]. COVER: every mailbox additionally receives
// C dummy deliveries a day from random senders — the relay cannot tell a
// dummy from a real envelope, so this raises the background every real
// pair must stand out from.
'use strict';

const N = +(process.env.N || 600);
const DAYS = +(process.env.DAYS || 3);
let GROUPS = +(process.env.NGROUPS || 20); // NGROUPS: bash owns GROUPS
let SIZE = +(process.env.SIZE || 5);
let ALL_MEMBERS = false;
const SPREAD_S = 0.1; // measured burst spread, seconds (R18: 64–135 ms)
const T_SEC = DAYS * 86400;

let seed = 0x9e3779b9;
// mulberry32: small and seeded, so a cell is reproducible. (It replaced a
// xorshift32 that was suspected, while the chance model was off by half,
// of correlating the Poisson streams; checked afterwards, it was not — the
// half was the window measure below, and either generator matches
// n_a·n_b·2W/T within noise.)
function rand() {
  seed = (seed + 0x6d2b79f5) >>> 0;
  let t = seed;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
function randExp(rate) {
  return -Math.log(1 - rand()) / rate;
}

/** Sort parallel (times, boxes) arrays by time. */
function sortEvents(times, boxes) {
  const n = times.length;
  const idx = new Uint32Array(n);
  for (let k = 0; k < n; k++) idx[k] = k;
  idx.sort((x, y) => times[x] - times[y]);
  const st = new Float64Array(n);
  const sb = new Int32Array(n);
  for (let k = 0; k < n; k++) {
    st[k] = times[idx[k]];
    sb[k] = boxes[idx[k]];
  }
  return { times: st, boxes: sb };
}

/** Independent per-mailbox traffic at `perDay` deliveries a day, sorted once. */
function background(perDay) {
  const times = [];
  const boxes = [];
  const rate = perDay / 86400;
  if (rate > 0) {
    for (let m = 0; m < N; m++) {
      let t = randExp(rate);
      while (t < T_SEC) {
        times.push(t);
        boxes.push(m);
        t += randExp(rate);
      }
    }
  }
  return sortEvents(times, boxes);
}

/** Group traffic: K messages per group, one copy per member (but the sender), jittered; sorted. */
function groupTraffic(k, jitterS) {
  const times = [];
  const boxes = [];
  for (let g = 0; g < GROUPS; g++) {
    for (let i = 0; i < k; i++) {
      const t0 = rand() * T_SEC;
      // A group message reaches every member but its sender; a person's own
      // devices (ALL_MEMBERS, the R19 table) all receive every message.
      const sender = ALL_MEMBERS ? -1 : Math.floor(rand() * SIZE);
      for (let m = 0; m < SIZE; m++) {
        if (m === sender) continue;
        times.push(t0 + rand() * SPREAD_S + rand() * jitterS);
        boxes.push(g * SIZE + m);
      }
    }
  }
  return sortEvents(times, boxes);
}

/** Linear merge of two sorted event lists. */
function merge(a, b) {
  const n = a.times.length + b.times.length;
  const times = new Float64Array(n);
  const boxes = new Int32Array(n);
  let i = 0;
  let j = 0;
  let k = 0;
  while (i < a.times.length || j < b.times.length) {
    if (j >= b.times.length || (i < a.times.length && a.times[i] <= b.times[j])) {
      times[k] = a.times[i];
      boxes[k++] = a.boxes[i++];
    } else {
      times[k] = b.times[j];
      boxes[k++] = b.boxes[j++];
    }
  }
  return { times, boxes };
}

function isLinked(a, b) {
  return a < GROUPS * SIZE && b < GROUPS * SIZE && Math.floor(a / SIZE) === Math.floor(b / SIZE);
}

/**
 * Pair co-activation counts within W, as a flat N×N array (upper triangle).
 * A sliding window over the sorted events when windows are sparse; when
 * they are not (a long jitter over busy mailboxes), time is cut into bins
 * of width W and a pair co-activates when both are active in the same or
 * an adjacent bin — within 2W rather than W, which favours the attacker
 * slightly and keeps the count tractable.
 */
function coactivations(ev, W) {
  const n = ev.times.length;
  const co = new Uint32Array(N * N);
  const perWindow = (n / T_SEC) * W;
  // The window's measure for the chance expectation: an exact |Δt| ≤ W
  // catches n_a·n_b·2W/T pairs; same-or-adjacent bins of width W catch
  // n_a·n_b·3W/T. The attacker's model must use the one the count used —
  // the first version used 2W for both and flagged half the population.
  co.windowMeasure = 2 * W;
  if (perWindow < 100) {
    let lo = 0;
    for (let i = 0; i < n; i++) {
      const t = ev.times[i];
      const m = ev.boxes[i];
      while (ev.times[lo] < t - W) lo++;
      for (let j = lo; j < i; j++) {
        const mj = ev.boxes[j];
        if (mj === m) continue;
        co[m < mj ? m * N + mj : mj * N + m]++;
      }
    }
    return co;
  }
  co.windowMeasure = 3 * W;
  const bins = Math.ceil(T_SEC / W);
  const words = (bins + 31) >> 5;
  const sets = new Uint32Array(N * words);
  for (let i = 0; i < n; i++) {
    const bin = Math.min(bins - 1, Math.floor(ev.times[i] / W));
    sets[ev.boxes[i] * words + (bin >> 5)] |= 1 << (bin & 31);
  }
  // b's bins smeared to neighbours: b | b<<1 | b>>1, across word boundaries.
  const smear = new Uint32Array(words);
  const pop = (x) => {
    x -= (x >>> 1) & 0x55555555;
    x = (x & 0x33333333) + ((x >>> 2) & 0x33333333);
    return (((x + (x >>> 4)) & 0x0f0f0f0f) * 0x01010101) >>> 24;
  };
  for (let b = 0; b < N; b++) {
    const ob = b * words;
    for (let w = 0; w < words; w++) {
      const v = sets[ob + w];
      const prev = w > 0 ? sets[ob + w - 1] : 0;
      const next = w + 1 < words ? sets[ob + w + 1] : 0;
      smear[w] = v | (v << 1) | (prev >>> 31) | (v >>> 1) | (next << 31);
    }
    for (let a = 0; a < b; a++) {
      const oa = a * words;
      let c = 0;
      for (let w = 0; w < words; w++) c += pop(sets[oa + w] & smear[w]);
      co[a * N + b] = c;
    }
  }
  return co;
}

/** One trial: returns {precision, recall, threshold}. */
function trial(bg, k, jitterS) {
  const ev = merge(bg, groupTraffic(k, jitterS));
  const n = ev.times.length;
  const counts = new Uint32Array(N);
  for (let i = 0; i < n; i++) counts[ev.boxes[i]]++;
  const W = jitterS + SPREAD_S;
  const co = coactivations(ev, W);
  // One pass over the pairs: how many pass each threshold, how many of those
  // are linked, and a histogram of the chance expectation so the attacker's
  // expected false passes at each threshold is a sum over the histogram.
  const MAXT = 1024;
  const flaggedAtLeast = new Float64Array(MAXT + 2);
  const tpAtLeast = new Float64Array(MAXT + 2);
  const muHist = new Map(); // n_a·n_b → number of pairs with that product
  for (let a = 0; a < N; a++) {
    const ca = counts[a];
    for (let b = a + 1; b < N; b++) {
      const c = Math.min(MAXT + 1, co[a * N + b]);
      if (c > 0) {
        flaggedAtLeast[c]++;
        if (isLinked(a, b)) tpAtLeast[c]++;
      }
      // Keyed by the exact product of the two counts: rounding the
      // expectation to three decimals sent every small one to zero, and a
      // pair with a chance expectation of 0.007 is exactly the pair that
      // passes T=1 by accident, forty at a time across a quiet population.
      const key = ca * counts[b];
      muHist.set(key, (muHist.get(key) || 0) + 1);
    }
  }
  for (let t = MAXT; t >= 1; t--) {
    flaggedAtLeast[t] += flaggedAtLeast[t + 1];
    tpAtLeast[t] += tpAtLeast[t + 1];
  }
  const linkedPairs = (GROUPS * SIZE * (SIZE - 1)) / 2;
  // Expected chance passes at every threshold at once: for each distinct
  // expectation, one pass down the Poisson tail.
  const expFalse = new Float64Array(MAXT + 2);
  for (const [key, cnt] of muHist) {
    const mu = (key * co.windowMeasure) / T_SEC;
    let p = Math.exp(-mu);
    let cdf = p; // P(X < 1)
    for (let T = 1; T <= MAXT; T++) {
      const tail = Math.max(0, 1 - cdf);
      if (tail < 1e-12) break;
      expFalse[T] += cnt * tail;
      p *= mu / T;
      cdf += p;
    }
  }
  for (let T = 1; T <= MAXT; T++) {
    const flagged = flaggedAtLeast[T];
    if (flagged === 0) break;
    if (expFalse[T] <= 0.05 * flagged) {
      return { threshold: T, precision: tpAtLeast[T] / flagged, recall: tpAtLeast[T] / linkedPairs };
    }
  }
  return { threshold: Infinity, precision: 0, recall: 0 };
}

/**
 * The smallest K at which the attacker gets ≥ 95 % recall at ≥ 95 % precision
 * in at least two of three runs — the repetition is what keeps one lucky or
 * unlucky draw from moving a cell.
 */
function messagesNeeded(bg, jitterS) {
  for (const k of [1, 2, 3, 5, 8, 12, 20, 30, 50, 80, 120, 200, 300, 500, 1000, 2000]) {
    let passes = 0;
    for (let rep = 0; rep < 3; rep++) {
      const r = trial(bg, k, jitterS);
      if (r.recall >= 0.95 && r.precision >= 0.95) passes++;
    }
    if (passes >= 2) return k;
  }
  return Infinity;
}

/** 2000 → "2 000"; Infinity → ">2 000" (the study stops there). */
function fmtK(k) {
  if (k === Infinity) return '>2 000';
  return k >= 1000 ? `${Math.floor(k / 1000)} ${String(k % 1000).padStart(3, '0')}` : `${k}`;
}

const columns = [
  ['quiet (5/day)', 5],
  ['busy (50/day)', 50],
  ['busy + cover 100/day', 150],
  ['busy + cover 1 000/day', 1050],
];
console.log(`population ${N} mailboxes, ${GROUPS} groups of ${SIZE}, watched for ${DAYS} days; burst spread ${SPREAD_S * 1000} ms; the attacker knows the jitter`);
console.log('');
console.log('Group messages the relay needs to see before it names ≥95% of group pairs at ≥95% precision:');
console.log('');
console.log(`| jitter D | ${columns.map((c) => c[0]).join(' | ')} |`);
console.log(`|---|${columns.map(() => '---:').join('|')}|`);
const t0 = Date.now();
for (const jitter of [0, 1, 10, 60, 600, 3600]) {
  const cells = [];
  for (const [, perDay] of columns) {
    seed = (0x9e3779b9 + jitter * 7 + perDay * 13) >>> 0;
    const bg = background(perDay);
    cells.push(fmtK(messagesNeeded(bg, jitter)));
  }
  const label = jitter === 0 ? 'none' : jitter < 60 ? `${jitter} s` : jitter < 3600 ? `${jitter / 60} min` : `${jitter / 3600} h`;
  console.log(`| ${label} | ${cells.join(' | ')} |`);
}
console.log('');
// R19: a person's two devices. Every message the person sends or receives
// reaches both mailboxes within tens of milliseconds (measured 15–53 ms), so
// the pair co-activates on EVERY message — groups of two, and K is simply
// how many messages the person has exchanged. Fifty a day is an ordinary
// day; the table says how many days of ordinary use a jitter on the mirror
// would buy.
GROUPS = 50;
SIZE = 2;
ALL_MEMBERS = true;
console.log(`A person's two devices (${GROUPS} such pairs among ${N} mailboxes): messages exchanged before the relay pairs them, and at 50 a day, how long that is:`);
console.log('');
console.log('| mirror jitter D | quiet (5/day) | busy (50/day) | busy + cover 1 000/day |');
console.log('|---|---:|---:|---:|');
for (const jitter of [0, 1, 10, 60, 600]) {
  const cells = [];
  for (const perDay of [5, 50, 1050]) {
    seed = (0x51ed270b + jitter * 7 + perDay * 13) >>> 0;
    const bg = background(perDay);
    const k = messagesNeeded(bg, jitter);
    const d = k / 50;
    const howLong = k === Infinity ? '' : d < 1 ? ` (${Math.max(1, Math.round(d * 24))} h)` : ` (${d.toFixed(d < 10 ? 1 : 0)} d)`;
    cells.push(fmtK(k) + howLong);
  }
  const label = jitter === 0 ? 'none' : jitter < 60 ? `${jitter} s` : `${jitter / 60} min`;
  console.log(`| ${label} | ${cells.join(' | ')} |`);
}
console.log('');
console.log(`cover traffic per device: 100/day ≈ ${Math.round((100 * 1450) / 1024)} KB/day; 1 000/day ≈ ${Math.round(((1000 * 1450) / 1024 / 1024) * 10) / 10} MB/day (sent and received). A jitter of D delays every group message by up to D for every recipient.`);
console.log(`(${((Date.now() - t0) / 1000).toFixed(0)} s)`);
