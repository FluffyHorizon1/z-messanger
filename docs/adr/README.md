# Architecture decision records

One file per decision that changes the security model, the wire format or
the operating model. Numbered in order of acceptance; superseded records
stay in place with their status updated.

| # | Decision | Status |
|---|---|---|
| [0001](0001-key-transparency.md) | Key transparency: device‑list transparency by gossip first, public log later | Accepted 2026‑09‑04 |
| [0003](0003-pq-identity-qr.md) | Post‑quantum identity: the QR carries a commitment, the ML‑DSA half travels in‑session | Accepted 2026‑09‑07 |
| [0004](0004-hybrid-device-list-distribution.md) | Post‑quantum device lists: the account signs the LIST, because per‑certificate halves do not authenticate the set | Accepted 2026‑09‑08 · addendum 2026‑09‑10 (bucket column measured; decision unchanged) |
| [0005](0005-call-media-path.md) | Calls: direct after accept by default, nothing before accept, relay one switch away — because relaying through the operator's TURN hands it who‑calls‑whom | **Proposed** 2026‑09‑10 — awaiting decision before 12.2 |
| [0006](0006-key-transparency-log.md) | The public transparency log: an RFC 9162 log plus a sparse map under one signed head, values sealed to the account's contacts, a mirror as witness, and what a client does with every answer it can get — G3 defined precisely enough to tick | Accepted 2026‑09‑11 |
| [0007](0007-anonymous-sender-connection.md) | Sealed envelopes are sent on a connection that never authenticated — the relay was being handed the sender by the socket while the envelope withheld it; what remains is an address (R21) | Accepted 2026‑09‑11 |
| [0008](0008-federation.md) | Federation, if ever: client‑to‑many‑relays with a device‑signed relay statement in codes and lists — no relay‑to‑relay protocol, no directory; deferred until a second relay needs it, the members reserved | Accepted as a design 2026‑09‑11 · build deferred |
| [0010](0010-device-list-signing-input.md) | The device‑list signature and its fingerprint must cover the devices' ratchet keys — the post‑quantum half signs the same bytes as the classical one, which are the version and the Ed keys only; the decision to make is the migration | **Proposed** 2026‑09‑12 — cheapest before G3 |
