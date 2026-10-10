'use strict';
// One owner rule, one order, three paths (PROTOCOL §21.4, §21.5): the log on
// the wire, the log replaying its own file, and a mirror holding what it
// replicates to the rule must refuse the same entry for the same reason —
// the corpus `handle_rule_cases.js` builds, which the Dart library is held
// to as well (`protocol/test/handle_rule_diff_test.dart`).
//
// Until 2026-10-10 they did not: the replay and the mirror bounded a version
// only from below, so a history with a version past 2^53 − 1 replayed and
// mirrored where the wire refused it; and each path checked "higher" rather
// than "next", which let the holder of an owner key publish one update at
// 2^53 − 1 and leave the recovery code no version to recover at.
//
// Criteria, each a test below:
//   1. every case — encodings, weak keys, signatures only one side's leniency
//      would take, versions skipped, stale, at the ceiling and past it, a
//      recover after a theft — gets the same verdict on the wire, on replay
//      and in a mirror: the same entry refused, with the same code and the
//      same reason, or none;
//   2. the verdicts are §21.4's: the cases the fixes are about each refused
//      (or accepted) as the rule now says, so three paths agreeing on a wrong
//      answer would fail here too.

const test = require('node:test');
const assert = require('node:assert/strict');

const { buildCases, verdicts } = require('./handle_rule_cases.js');

const show = (v) => (v.refusedAt === null ? 'accept' : `${v.refusedAt} ${v.reason} (${v.code})`);

let all;
function cases() {
  if (!all) all = buildCases().map((c) => ({ name: c.name, ...verdicts(c.entries) }));
  return all;
}

test('1. the wire, the replay and a mirror give every history the same verdict', () => {
  const differ = [];
  for (const c of cases()) {
    if (show(c.wire) !== show(c.replay) || show(c.wire) !== show(c.mirror)) {
      differ.push(`${c.name}: wire ${show(c.wire)} | replay ${show(c.replay)} | mirror ${show(c.mirror)}`);
    }
    for (const v of [c.wire, c.replay, c.mirror]) {
      if (v.refusedAt !== null) assert.ok(v.reason && v.code, `${c.name}: a refusal names its code and reason (${v.message})`);
    }
  }
  const refused = cases().filter((c) => c.wire.refusedAt !== null).length;
  console.log(`        ${cases().length} histories, ${cases().length - refused} accepted and ${refused} refused; the three paths differ on ${differ.length}`);
  assert.deepEqual(differ, []);
  assert.ok(cases().length >= 120);
});

test('2. the verdicts are the rule\'s: next versions, the one order, strong keys, one signature rule', () => {
  const want = {
    'claim, update v3 (a version skipped)': '1 staleVersion (stale_version)',
    'claim at v2 (a claim is version 1)': '0 staleVersion (stale_version)',
    'claim, update at v = 2^53-1 (the theft at the ceiling)': '1 staleVersion (stale_version)',
    'claim, update at v = 2^53': '1 malformed (bad_request)',
    'claim, update at v = 2^60': '1 malformed (bad_request)',
    'claim, theft v2, recover v3': 'accept',
    'claim, theft v2, theft v3, recover v4': 'accept',
    'claim, theft v2, recover v2 (beaten to it)': '2 staleVersion (stale_version)',
    'claim, taken claim with a bad signature': '1 badSignature (bad_signature)',
    'claim, update v9 naming the stranger, signed by the stranger': '1 ownerChanged (owner_rule)',
    'claim, recover v2, the same recover again (replay)': '2 wrongRecoveryKey (bad_recovery)',
    'claim: owner identity, sig (R=identity, S=0)': '0 malformed (bad_record)',
    'claim+update: owner order2, both sigs (R=identity, S=0)': '0 malformed (bad_record)',
    'claim: owner identityNonCanonical, sig (R=identity, S=0)': '0 malformed (bad_record)',
    'claim: xintro order8, signed by its owner': '0 malformed (bad_record)',
    'claim committing to the identity as recovery key, then anyone recovers with it': '1 malformed (bad_record)',
    'claim: sig with R = the identity, made by the owner (S = k·a)': '0 badSignature (bad_signature)',
    'claim: sig with R = rB + T2, made by the owner so that x(R + kA) = x(SB)': '0 badSignature (bad_signature)',
    'claim with S+L (malleated) signature': '0 badSignature (bad_signature)',
  };
  const byName = new Map(cases().map((c) => [c.name, c]));
  for (const [name, verdict] of Object.entries(want)) {
    assert.ok(byName.has(name), `the corpus has "${name}"`);
    assert.equal(show(byName.get(name).wire), verdict, name);
  }
});
