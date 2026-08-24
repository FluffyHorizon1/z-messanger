'use strict';
/**
 * FCM HTTP v1 "wake ping" sender for the Z relay.
 *
 * Sends a CONTENT-FREE, high-priority data message to a device's FCM token so
 * the app can wake, reconnect, and drain its end-to-end-encrypted queue. The
 * push carries no message text and no sender identity — only {type:"z-wake"}.
 * The relay stays zero-knowledge; Google (FCM) sees only that a token was
 * pinged and when, which is the unavoidable cost of mobile push. The relay's
 * per-identity FCM token is exactly the "opaque push token" the Zero-Trust
 * plan already permits as server state.
 *
 * Credentials: a Firebase service-account JSON, provided via the environment
 * variable FCM_SERVICE_ACCOUNT (either the JSON itself, or a path to a file).
 * If it is unset/invalid, push is simply disabled and the relay behaves exactly
 * as before.
 *
 * No new dependencies: the OAuth2 access token is minted by signing a JWT with
 * Node's crypto and exchanging it at Google's token endpoint via global fetch.
 */
const crypto = require('crypto');

const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const SCOPE = 'https://www.googleapis.com/auth/firebase.messaging';

function b64url(buf) {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

class PushSender {
  /**
   * @param {object} sa   parsed service-account JSON (client_email, private_key, project_id)
   * @param {object} opts { fetchImpl } — injectable for tests
   */
  constructor(sa, opts = {}) {
    if (!sa || !sa.client_email || !sa.private_key || !sa.project_id) {
      throw new Error('invalid service account: need client_email, private_key, project_id');
    }
    this.sa = sa;
    this.projectId = sa.project_id;
    this._fetch = opts.fetchImpl || globalThis.fetch;
    this._token = null; // { accessToken, expEpochMs }
    this.endpoint = `https://fcm.googleapis.com/v1/projects/${this.projectId}/messages:send`;
  }

  /** Mint (and cache ~1h) an OAuth2 access token scoped to FCM. */
  async _accessToken(nowMs = Date.now()) {
    if (this._token && this._token.expEpochMs - 60_000 > nowMs) {
      return this._token.accessToken;
    }
    const iat = Math.floor(nowMs / 1000);
    const exp = iat + 3600;
    const header = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
    const claim = b64url(
      JSON.stringify({ iss: this.sa.client_email, scope: SCOPE, aud: TOKEN_URL, iat, exp })
    );
    const signingInput = `${header}.${claim}`;
    const signature = b64url(crypto.sign('RSA-SHA256', Buffer.from(signingInput), this.sa.private_key));
    const jwt = `${signingInput}.${signature}`;

    const res = await this._fetch(TOKEN_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=' + encodeURIComponent(jwt),
    });
    if (!res.ok) throw new Error(`oauth token exchange failed: ${res.status}`);
    const json = await res.json();
    this._token = {
      accessToken: json.access_token,
      expEpochMs: nowMs + (json.expires_in ? json.expires_in * 1000 : 3600_000),
    };
    return this._token.accessToken;
  }

  /**
   * Send a content-free wake ping to one device token.
   * @returns {Promise<{ok:boolean, status:number, retiredToken:boolean}>}
   *          retiredToken=true means FCM reports the token permanently dead
   *          (caller should drop it from the registry).
   */
  async sendWake(fcmToken, nowMs = Date.now()) {
    const accessToken = await this._accessToken(nowMs);
    const body = JSON.stringify({
      message: {
        token: fcmToken,
        // DATA-ONLY (no "notification" block): the app's background handler is
        // invoked and decides what to show. No content or sender travels here.
        data: { type: 'z-wake' },
        android: { priority: 'high' },
        apns: { headers: { 'apns-priority': '10' }, payload: { aps: { 'content-available': 1 } } },
      },
    });
    const res = await this._fetch(this.endpoint, {
      method: 'POST',
      headers: { authorization: `Bearer ${accessToken}`, 'content-type': 'application/json' },
      body,
    });
    if (res.ok) return { ok: true, status: res.status, retiredToken: false };
    // 404 UNREGISTERED or 400 invalid-argument for a dead token → retire it.
    return { ok: false, status: res.status, retiredToken: res.status === 404 || res.status === 400 };
  }

  /** Build from FCM_SERVICE_ACCOUNT (JSON string or file path). Null if absent/invalid. */
  static fromEnv(env = process.env, opts = {}) {
    const raw = env.FCM_SERVICE_ACCOUNT;
    if (!raw) return null;
    let text = raw;
    if (!raw.trim().startsWith('{')) {
      try {
        text = require('fs').readFileSync(raw, 'utf8');
      } catch {
        return null;
      }
    }
    let sa;
    try {
      sa = JSON.parse(text);
    } catch {
      return null;
    }
    try {
      return new PushSender(sa, opts);
    } catch {
      return null;
    }
  }
}

module.exports = { PushSender };
