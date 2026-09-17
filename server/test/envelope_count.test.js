'use strict';

// `stats().queuedEnvelopes` used to be recomputed by walking every live
// mailbox, and `stats()` runs on every unauthenticated `/health` and
// `/metrics` and on every authentication — O(mailboxes) each, ~10 ms at 200k
// mailboxes, a cost anyone could impose without an account (the 2026-09-14
// review's finding 43). It is a running counter now, kept in step with the
// byte total at the same three sites (enqueue, remove, retain). A counter can
// drift from what it counts, so this pins it against `heldEnvelopes()`, which
// recomputes it the old way — the same shape `heldBytes()` guards `bytes`.

const test = require('node:test');
const assert = require('node:assert');
const { MemoryCoordinator, CFG } = require('../server.js');

function entry(id, size, ageMs = 0) {
  return {
    seq: 0,
    kind: 'msg',
    id,
    from: null,
    payload: 'x'.repeat(size),
    ts: Date.now() - ageMs,
    size,
  };
}

test('queuedEnvelopes is an O(1) counter that matches the queues through enqueue, ack and sweep', () => {
  const c = new MemoryCoordinator();
  const eq = (n, why) => {
    assert.strictEqual(c.stats().queuedEnvelopes, n, why);
    assert.strictEqual(c.stats().queuedEnvelopes, c.heldEnvelopes(),
      'the counter equals a full recount of the queues');
  };

  eq(0, 'empty');

  const e1 = entry('a', 100);
  const e2 = entry('b', 100);
  const stale = entry('c', 100, CFG.queueTtlMs + 1000);
  assert.ok(c._enqueue('r1', e1));
  assert.ok(c._enqueue('r1', e2));
  assert.ok(c._enqueue('r2', stale));
  eq(3, 'three enqueued across two mailboxes');

  // Acknowledge one (the _removeKey path).
  c._removeKey('r1', e1.key);
  eq(2, 'one acknowledged');

  // The sweep expires the stale one (the _retain path), and forgets r2.
  c.sweep();
  eq(1, 'the stale envelope expired');
  assert.strictEqual(c.queues.has('r2'), false, 'the emptied mailbox is gone');

  // Acknowledge the last; the counter returns to zero, not below it.
  c._removeKey('r1', e2.key);
  eq(0, 'all gone');
});
