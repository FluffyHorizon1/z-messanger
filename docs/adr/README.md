# Architecture decision records

One file per decision that changes the security model, the wire format or
the operating model. Numbered in order of acceptance; superseded records
stay in place with their status updated.

| # | Decision | Status |
|---|---|---|
| [0001](0001-key-transparency.md) | Key transparency: device‑list transparency by gossip first, public log later | Accepted 2026‑09‑04 |
| [0003](0003-pq-identity-qr.md) | Post‑quantum identity: the QR carries a commitment, the ML‑DSA half travels in‑session | Accepted 2026‑09‑07 |
| [0004](0004-hybrid-device-list-distribution.md) | Post‑quantum device lists: the account signs the LIST, because per‑certificate halves do not authenticate the set | Accepted 2026‑09‑08 |
