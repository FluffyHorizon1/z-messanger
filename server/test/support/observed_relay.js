'use strict';
/**
 * Test support, never a deployment: the relay, built by the same
 * `createServer` that `node server.js` uses and listening on loopback, with an
 * observer standing where its operator — or anyone terminating its TLS
 * (THREAT_MODEL.md R41, R44) — stands, and a push sender that records wake
 * pings instead of calling Google.
 *
 * The app's tests spawn this instead of `server.js` when they need to see
 * what the relay sees: which mailbox each envelope is addressed to and when
 * it arrived, when each is written to its recipient's socket, and what a
 * device asks the relay to do with its push token. Every observation is one
 * line on stdout, `OBS <json>`:
 *
 *   ready         {rid, at}                  a device authenticated as `rid`
 *   accept        {to, id, at, bytes, anon}  a `send` the relay took (`at`:
 *                                            when its frame arrived; `anon`:
 *                                            on a connection that never
 *                                            authenticated)
 *   deliver       {to, id, at, bytes}        a `msg` frame written to the
 *                                            mailbox owner's socket
 *   push-register {rid, at}                  a token registered for `rid`
 *   push-unregister {rid, at}                `rid` asked the relay to forget it
 *   push-ok       {rid, at}                  the relay's answer to either
 *   wake          {token, at}                a wake ping the relay sent
 *
 * Nothing in `server.js` changes for this, and nothing here can be turned on
 * in a deployment: it wraps the `ws` library's own socket methods in this
 * process only. Payloads are never printed — only their length.
 *
 * Not a test file: `npm test` runs `test/*.test.js`, and
 * `tool/check_audit_scope.py` counts `server/test/*.js`; this lives below both.
 */
const WebSocket = require('ws');
const { createServer, CFG } = require('../../server.js');

const obs = (ev) => process.stdout.write(`OBS ${JSON.stringify(ev)}\n`);

// Every frame the relay sends goes through `sendJson` → `ws.send(string)`.
const send = WebSocket.prototype.send;
WebSocket.prototype.send = function observedSend(data, ...rest) {
  try {
    if (typeof data === 'string') outbound(this, data);
  } catch {
    // An observer must never change what the relay does.
  }
  return send.call(this, data, ...rest);
};

function outbound(ws, text) {
  const head = text.slice(0, 16);
  if (!/^\{"t":"(msg|ready|sent|push-ok)"/.test(head)) return;
  const f = JSON.parse(text);
  const at = Date.now();
  switch (f.t) {
    case 'ready':
      ws.zObsRid = f.id;
      obs({ ev: 'ready', rid: f.id, at });
      break;
    case 'msg':
      if (ws.zObsRid) {
        obs({ ev: 'deliver', to: ws.zObsRid, id: f.id, at, bytes: String(f.payload || '').length });
      }
      break;
    case 'sent': {
      const pending = ws.zObsSends && ws.zObsSends.get(f.id);
      if (pending) {
        ws.zObsSends.delete(f.id);
        obs({ ev: 'accept', ...pending });
      }
      break;
    }
    case 'push-ok':
      obs({ ev: 'push-ok', rid: ws.zObsRid || null, at });
      break;
    default:
      break;
  }
}

function inbound(ws, data) {
  let f;
  try {
    f = JSON.parse(data.toString('utf8'));
  } catch {
    return;
  }
  const at = Date.now();
  if (f.t === 'send' && typeof f.id === 'string' && typeof f.to === 'string') {
    if (!ws.zObsSends) ws.zObsSends = new Map();
    ws.zObsSends.set(f.id, {
      to: f.to,
      id: f.id,
      at,
      bytes: String(f.payload || '').length,
      anon: !ws.zObsRid,
    });
  } else if (f.t === 'push-register') {
    obs({ ev: 'push-register', rid: ws.zObsRid || null, at });
  } else if (f.t === 'push-unregister') {
    obs({ ev: 'push-unregister', rid: ws.zObsRid || null, at });
  }
}

const pushSender = {
  async sendWake(token) {
    obs({ ev: 'wake', token, at: Date.now() });
    return { ok: true, status: 200, retiredToken: false };
  },
};

const { httpServer, wss } = createServer({ pushSender });
// Registered after the relay's own `connection` handler, so the relay has
// already attached its `message` listener when this one is added: both see
// every frame, the relay first.
wss.on('connection', (ws) => ws.on('message', (data) => inbound(ws, data)));
httpServer.listen(CFG.port, '127.0.0.1');
const stop = () => httpServer.close(() => process.exit(0));
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
