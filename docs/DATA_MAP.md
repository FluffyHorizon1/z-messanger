# Data map

Every piece of data Z creates: what it is, where it lives, who can read it, and
when it goes away.

A threat model argues about capabilities. This is the inventory underneath it —
the thing you check a claim against when the claim is "the operator learns
nothing". It is also what a data-protection question needs answering from, and
what an auditor should be able to read in one sitting.

Structured as **what** · **where** · **who can read it** · **how long**.

---

## On your device

The vault is a SQLite database sealed cell-by-cell with XChaCha20-Poly1305.
The key lives in the OS keystore (Keychain / Keystore / DPAPI / libsecret),
optionally behind an app passphrase. "Sealed" below means the individual cell
is encrypted, not merely that the file sits in an encrypted directory.

| What | Where | Who can read it | How long |
|---|---|---|---|
| Message bodies, attachment metadata, reactions | `messages`, `files` — sealed cells | You, once the OS user and any passphrase are unlocked | Until deleted, or until a disappearing-message timer fires |
| Attachment bytes | Files on disk, encrypted under a per-file key held in the vault | Same | Until deleted with the message |
| Your identity keys (Ed25519, X25519 seeds) | `kv`, sealed | Same | Life of the install, or until an identity reset |
| Your account's post-quantum seed (32 bytes, ML-DSA) | `kv` key `pq_seed`, sealed | Same | Same |
| Contacts: keys, display name, routing id, when added | `contacts.enc_bundle`, `contacts.enc_name` (both sealed), `contacts.rid`, `contacts.created_ms` | Same | Until the contact is deleted |
| Which number you compared, and when a tick was earned | `contacts.verified_sn` | Same | Until re-verified or the contact is deleted |
| Which of your devices added a contact | `contacts.added_by` | Same | Same |
| A contact's account key and the certificate for the device you scanned (§18.7) | `contacts.acct_ed`, `contacts.dev_cert` | Same | Until the contact is deleted |
| A contact's post-quantum commitment and, once accepted, their key | `contacts.pq_commit`; `contacts.enc_pq_pub`, sealed | Same | Same |
| A per-contact disappearing-message timer | `contacts.ttl_seconds` | Same | Same |
| A refused post-quantum key, once one has been refused | `contacts.pq_mismatch` | Same | Until the contact is deleted — deliberately durable |
| Ratchet state (chain keys) | `conversations.enc_state`, sealed | Same | Rolling; old keys are dropped as chains advance |
| Message keys held for out-of-order arrivals (cap 1 536) | `conversations.enc_skipped`, sealed | Same | Until the late message arrives, or the cap evicts the oldest |
| Contacts' device lists and their post-quantum signatures, and when each list arrived | `kv` keys `cdev_*`, `cdev_pq_*`, `cdev_at_*` | Same | Until replaced by a newer version |
| The transparency log's last accepted head, any fault, and per contact what the log says (state, the log's version and fingerprint, the confirmed device set, any held devices) | `kv` keys `kt_*`, `ktc_*` | Same | Until the next check replaces it, or the log's history is reset in Settings |
| Your own published device lists (version → fingerprint) and a publish waiting for the log | `kv` keys `kt_own_known`, `kt_pub_pending` | Same | Life of the install; the pending publish until the log acknowledges it |
| Undelivered outbound messages | `outbox`, sealed payloads | Same | Until acknowledged by the relay |
| Group messages still to be encrypted for each member | `group_fanout`, sealed payload | Same | Until every member's copy is queued — survives a restart so a half-finished fan-out resumes |
| Group membership and metadata | `kv` key `groups`, sealed | Same | Until you leave or delete the group |
| Backup archives you create (`.zbk`) | Wherever you saved them | Anyone with the file **and** the recovery code | Until you delete them — Z does not manage their lifetime |

**Deliberately not stored anywhere:** your contacts' phone numbers or email
addresses (Z never asks), a password for anything server-side (there is no
account), any analytics, and any crash reporter. There is no telemetry
endpoint in the app.

## In the relay's memory

The relay never writes to disk. `storage: 'ram-only'` in `/health` is a claim
you can check against `server/server.js` — the only `fs` use in it reads TLS
material.

Since 2026‑09‑11 the public relay is **two instances sharing one RAM‑only
key‑value store** (`render.ha.yaml`; Valkey with persistence off, reachable
only on the host's private network, no public address), so "the relay's
memory" is now two processes' RAM plus the store's. What lives where is in
the table; what changes for you is retention, not exposure: **a relay
restart or redeploy no longer loses the queue** — the queue is in the store
— and a *store* restart is what wipes it. Nothing is written to disk in
either place, and the store holds exactly the items below, in exactly the
same opaque form.

| What | Where | Who can read it | How long |
|---|---|---|---|
| Queued ciphertext envelopes, and per mailbox how many and how many bytes (the caps, §12.4) | RAM — or a RAM‑only Redis the instances share: per mailbox a list of entry keys, a hash of the entries, and their byte count. An attributed envelope's key names its sender, a sealed one's names nobody, and neither key holds anything the entry beside it did not (`SELF_HOSTING.md`, "Scaling out") | The operator sees opaque bytes and their padded size — not content; for a sealed envelope, not the sender either | Until delivered, until `QUEUE_TTL_HOURS` (72) after the relay accepted **that envelope**, or until the process (or the store) restarts — never evicted to make room |
| Which routing ids are connected, and the network address of every socket — the authenticated mailbox socket and the anonymous sender socket a device also holds (§12.1) | RAM — and, with several instances, *which instance* holds each mailbox's socket, in the store (`presence:{rid}`, 60 s, refreshed while connected) | Operator | While connected; the store's copy expires within a minute of the socket closing |
| That a sealed envelope arrived on an anonymous socket — never which identity sent it | RAM, transiently | Operator; nothing ties the socket to a routing id but its address (R21) | Duration of the send |
| Which routing id an envelope is addressed to, and when | RAM, transiently | Operator | Duration of delivery |
| Push tokens (FCM), if push is enabled | RAM — or the store, so any instance can wake a device (`push:{rid}`) | Operator, and Google when a push is sent | Until expiry (`PUSH_TTL_DAYS`, 30) or a store restart |
| Aggregate counters (`/metrics`) | RAM, per instance — each instance counts its own work and `/health` reports its own sockets. Counts only: envelopes, refusals of each kind, acknowledgements that matched and that did not (`z_ack_miss_total`), delivery latency buckets — no routing id appears in any of them | Anyone who can reach `/metrics` | Until that instance restarts |

**Not held by the relay at any point:** message content, sender identity
(sealed sender), display names, group membership, contact lists, any key
material, or any log of who talked to whom. Restarting everything loses
everything, which is the intended behaviour rather than a limitation — and
with a shared store that now takes restarting the store, not just the
relay.

## At third parties

| Who | What they get | Why | Avoidable? |
|---|---|---|---|
| **Google (FCM)** | That a device with token T should wake. No content, no sender, no conversation | Waking a sleeping Android device requires the platform push service | Yes — push is optional; without it the app fetches when opened |
| **Google (Play)** | Install/update telemetry Play collects for any app; and Play App Signing holds the key that signs the APK | A condition of distributing through Play | Sideload a release build, verified per `PROVENANCE.md` |
| **Apple (APNs)** | The equivalent of FCM, when the iOS client ships | Same | Same |
| **The relay host** | Whatever the relay's operator sees, above, plus IP addresses at the TLS layer. The public deployment also has the host running the shared store, on its own private network — the same opaque bytes, no persistence, no public address, and the same party, so this is one hosting provider rather than two | Someone has to run the relay, and running more than one instance of it needs somewhere to share the queue | Yes — self-host (`SELF_HOSTING.md`), as one instance or several |
| **Sigstore / Rekor** | The public transparency-log record of each release attestation. No user data | Provenance is only meaningful if it is public | No, and it should not be — publicity is the point |
| **The transparency log's operator** (`kt.zmessengers.com`, once live) | At publish: your account's public key, the version and fingerprint of your device list, and the list itself sealed under a key only your contacts can derive. At lookup: which labels this device asks about — its contacts' — and the IP address at the TLS layer. A mirror or witness sees labels and ciphertext only | The log is how a device list handed to one contact and not another becomes visible (`adr/0006`); the operator has to see a publish to accept it | Yes — point Settings › Transparency log at a self-hosted log, or at none (in-band verification only, as before the log) |

The app makes no other network calls. It contacts the relay you configure,
the transparency log you configure (HTTPS, a few requests per contact every
six hours, none when no log is set), and, if push is on, the platform push
service. There is no CDN, no fonts fetched at
runtime, no analytics SDK, no advertising identifier, and — since 14.1 — no
dependency-metadata blob in the APK either.

## What leaves your device, and in what shape

| Leaving | Shape on the wire | Visible to the relay |
|---|---|---|
| A message | Sealed envelope, padded to one of six buckets | Its recipient, its arrival time, its bucket |
| An attachment | Chunks sealed under a per-file key, padded | Same, per chunk |
| Your device list | An inner message inside the ratchet, 4 096 bucket | Indistinguishable from a chat message of ~190–1 900 characters |
| Your post-quantum device-list signature | Its own inner message, 16 384 bucket, on a delayed schedule (`adr/0004`) | A ~16 KB envelope at an unrelated time — see R2 in `THREAT_MODEL.md` |
| Your post-quantum identity key | An inner message, 16 384 bucket, early in a new conversation | A ~16 KB envelope, as a text of 2 000+ characters would be (`adr/0004`, addendum) |
| A read receipt / typing state | Inner message, 1 024 bucket | Same as any short message (up to ~180 characters) |

## Erasure

| To remove | Do this | What survives |
|---|---|---|
| One message, everywhere | Delete for everyone | Nothing on honest clients; a malicious client can keep anything it received |
| A contact and its history | Delete contact | Nothing locally. Their copy is theirs |
| Everything on this device | Uninstall, or reset identity in Settings | Backups you made yourself; whatever your contacts hold |
| Your presence on the relay | Stop connecting | Nothing — the relay holds no account, and the record that you were connected expires within a minute |

There is no "delete my account" request to send, because there is no account to
delete: no server-side record exists to be erased. That is a stronger position
than a deletion policy, and it is worth stating in those terms when someone
asks the GDPR question — the lawful-basis conversation is short when the
processor holds ciphertext addressed to a hash, in memory, and forgets it on
delivery, on expiry (`QUEUE_TTL_HOURS`, 72), or when that memory goes.

## Not yet built

Named here so this document does not silently go stale as the roadmap moves:

* **Calls (phase 12)** will add a media path, and its data map depends on an
  open decision: peer-to-peer discloses the caller's IP **to the callee**,
  while TURN discloses it **to the operator** instead. Neither is free, the
  choice is not ours to make quietly, and this table gains a row either way.
  `adr/0005` proposes the answer — direct after accept by default, nothing
  before accept, relay one switch away — with a table of who sees what on
  each path; the rows land here when it is accepted.
* **The transparency log is built and not yet live** (`adr/0006`). Its row
  above describes the view it will have; until it runs, the client is inert
  and no request is made.

---

*Generated by hand and checked against the schema in `app/lib/core/vault.dart`
(schema 9) and the relay in `server/server.js`. If a column is added to either
without a row appearing here, this document is wrong — which is the sort of
thing an audit should catch.*
