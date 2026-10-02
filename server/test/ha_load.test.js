'use strict';

// The multi-instance load bench (bench/ha_load.js) is a measurement and is
// not run by the suite at its measuring length; this runs it at the shortest
// length that still exercises every path it measures, so that a change to
// the relay or to the bench cannot leave docs/LOAD.md quoting a rig that no
// longer starts. Three seconds, two instances, ten devices: enough to see
// deliveries that crossed instances, a backlog held for a mailbox nobody
// holds open, and /health answering throughout.
//
// What is asserted:
//   1. the bench runs to completion and prints its JSON line, with two
//      instances and every device's two sockets connected to them;
//   2. every live envelope it sent was delivered, and none was refused —
//      the ten devices are far under every cap and rate — and each delivery
//      crossed instances, which is what the rig exists to measure: the
//      relays' own counter of hand-overs equals what the recipients saw;
//   3. the offline share was queued and is still held by the store at the
//      end, since nobody drains it, and /health answered every sample.
//
// Skips itself where `redis-server` or `ioredis` is missing, as ha.test.js does.

const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { spawnSync } = require('child_process');

function hasRedisServer() {
  return spawnSync('redis-server', ['--version']).status === 0;
}
function hasIoredis() {
  try {
    require.resolve('ioredis');
    return true;
  } catch {
    return false;
  }
}
const SKIP = !hasRedisServer() || !hasIoredis();

test('the multi-instance bench runs for three seconds on two instances and delivers across them', { skip: SKIP && 'redis-server/ioredis unavailable' }, (t) => {
  const bench = path.join(__dirname, '..', 'bench', 'ha_load.js');
  const r = spawnSync(process.execPath, [bench, '--instances', '2', '--clients', '10', '--seconds', '3', '--json'], {
    encoding: 'utf8',
    timeout: 60_000, // then SIGTERM, on which the bench kills its own store
  });
  // And if it could not — killed outright — the store it started is reaped
  // here, by the pid it printed before anything else, so a failed run does
  // not leave a redis-server behind on a shared machine.
  const pid = /HA_LOAD_REDIS_PID (\d+)/.exec(r.stderr || '');
  if (pid) {
    try {
      process.kill(Number(pid[1]), 'SIGKILL');
    } catch {} // ESRCH: the bench had already stopped it, as it should
  }
  assert.strictEqual(r.status, 0, `the bench exited ${r.status} (${r.signal || 'no signal'}):\n${r.stderr}`);
  const line = r.stdout.split('\n').find((l) => l.startsWith('HA_LOAD '));
  assert.ok(line, `no HA_LOAD line in:\n${r.stdout}`);
  const s = JSON.parse(line.slice('HA_LOAD '.length));

  // 1. The rig it says it is.
  assert.strictEqual(s.instances, 2);
  assert.strictEqual(s.clients, 10);
  assert.strictEqual(s.perInstance.length, 2);
  for (const inst of s.perInstance) {
    assert.strictEqual(inst.connections, 5, `${inst.id} holds five mailboxes`);
    assert.strictEqual(inst.sockets, 10, `${inst.id} holds ten sockets: a mailbox link and a sender link per device`);
  }

  // 2. Everything offered to a live recipient arrived, once, across instances.
  assert.ok(s.offeredLive > 0, 'the bench sent something');
  assert.strictEqual(s.acceptedLive, s.offeredLive, 'every live send was accepted');
  assert.strictEqual(s.deliveredLive, s.offeredLive, `${s.deliveredLive} of ${s.offeredLive} delivered`);
  assert.strictEqual(s.lostLive, 0);
  assert.deepStrictEqual(s.refusals, {}, 'nothing was refused');
  assert.strictEqual(s.relayMetrics.z_cross_instance_total, s.deliveredLive, 'every delivery was handed to the other instance');
  assert.strictEqual(s.relayMetrics.z_delivered_live_total, 0, 'and none was local');
  assert.strictEqual(s.relayMetrics.z_acked_total, s.deliveredLive, 'and every one was acknowledged by its recipient');
  assert.ok(s.latencyMs.p50 > 0 && s.latencyMs.p99 >= s.latencyMs.p50, `latency ${JSON.stringify(s.latencyMs)}`);

  // 3. The backlog is held, and the health check kept answering.
  assert.ok(s.offeredOffline > 0, 'some sends went to mailboxes nobody holds open');
  assert.strictEqual(s.acceptedOffline, s.offeredOffline);
  assert.strictEqual(s.offlineQueued, s.acceptedOffline, 'the store still holds what nobody drained');
  assert.ok(s.redis.usedMemoryAfterMB > s.redis.usedMemoryBeforeMB, 'the store grew by the backlog');
  assert.strictEqual(s.healthMs.failures, 0);
  assert.ok(s.healthMs.n >= 4, `${s.healthMs.n} health samples in three seconds`);
  t.diagnostic(`${s.deliveredLive} delivered across instances, p50 ${s.latencyMs.p50} ms, p99 ${s.latencyMs.p99} ms; /health p99 ${s.healthMs.p99} ms`);
});
