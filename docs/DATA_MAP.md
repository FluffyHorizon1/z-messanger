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
| Contacts' device lists and their post-quantum signatures | `kv` keys `cdev_*`, `cdev_pq_*` | Same | Until replaced by a newer version |
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

| What | Where | Who can read it | How long |
|---|---|---|---|
| Queued ciphertext envelopes | RAM | The operator sees opaque bytes and their padded size — not content, not sender | Until delivered, or until the process restarts |
| Which routing ids are connected | RAM | Operator | While connected |
| Which routing id an envelope is addressed to, and when | RAM, transiently | Operator | Duration of delivery |
| Push tokens (FCM), if push is enabled | RAM | Operator, and Google when a push is sent | Until expiry or restart |
| Aggregate counters (`/metrics`) | RAM | Anyone who can reach `/metrics` | Until restart |

**Not held by the relay at any point:** message content, sender identity
(sealed sender), display names, group membership, contact lists, any key
material, or any log of who talked to whom. A restart loses everything, which
is the intended behaviour rather than a limitation.

## At third parties

| Who | What they get | Why | Avoidable? |
|---|---|---|---|
| **Google (FCM)** | That a device with token T should wake. No content, no sender, no conversation | Waking a sleeping Android device requires the platform push service | Yes — push is optional; without it the app fetches when opened |
| **Google (Play)** | Install/update telemetry Play collects for any app; and Play App Signing holds the key that signs the APK | A condition of distributing through Play | Sideload a release build, verified per `PROVENANCE.md` |
| **Apple (APNs)** | The equivalent of FCM, when the iOS client ships | Same | Same |
| **The relay host** | Whatever the relay's operator sees, above, plus IP addresses at the TLS layer | Someone has to run the relay | Yes — self-host (`SELF_HOSTING.md`) |
| **Sigstore / Rekor** | The public transparency-log record of each release attestation. No user data | Provenance is only meaningful if it is public | No, and it should not be — publicity is the point |

The app makes no other network calls. It contacts the relay you configure and,
if push is on, the platform push service. There is no CDN, no fonts fetched at
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
| Your presence on the relay | Stop connecting | Nothing — the relay holds no account and forgets on restart |

There is no "delete my account" request to send, because there is no account to
delete: no server-side record exists to be erased. That is a stronger position
than a deletion policy, and it is worth stating in those terms when someone
asks the GDPR question — the lawful-basis conversation is short when the
processor holds ciphertext addressed to a hash and forgets it on restart.

## Not yet built

Named here so this document does not silently go stale as the roadmap moves:

* **Calls (phase 12)** will add a media path, and its data map depends on an
  open decision: peer-to-peer discloses the caller's IP **to the callee**,
  while TURN discloses it **to the operator** instead. Neither is free, the
  choice is not ours to make quietly, and this table gains a row either way.
* **Key transparency (phase 11, `adr/0001`)** would add a log service holding
  public key material and inclusion proofs — no message content, but a new
  third party with a new view.

---

*Generated by hand and checked against the schema in `app/lib/core/vault.dart`
(schema 9) and the relay in `server/server.js`. If a column is added to either
without a row appearing here, this document is wrong — which is the sort of
thing an audit should catch.*
