#!/usr/bin/env python3
"""Independent check of docs/vectors/kt — the key transparency log's known
answers — written from docs/PROTOCOL.md §19 and nothing in kt/lib.

Two implementations that share no code and agree on every byte is the
standard the rest of the protocol is held to (verify_mlkem.py,
verify_mldsa.py, the Node clean-room verifier); this is the log's turn. The
Merkle hashing is RFC 9162 re-typed from the RFC, the map tree from §19.2,
the leaf, head, publish and witness inputs from §19.3–19.6; Ed25519,
ChaCha20-Poly1305 and HKDF come from `cryptography`.

    pip install cryptography
    python3 kt/tools/verify_vectors.py          # from the repo root

Exit status 0 = every value reproduced and every must_refuse case refused;
anything else prints the first problem and exits 1.
"""
import base64
import hashlib
import json
import os
import sys

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.exceptions import InvalidSignature, InvalidTag
except ImportError:  # pragma: no cover
    print("cryptography is required: pip install cryptography", file=sys.stderr)
    sys.exit(2)

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DIR = os.path.join(ROOT, "docs", "vectors", "kt")

checks = 0


def eq(got, want, what):
    global checks
    if got != want:
        print(f"MISMATCH {what}\n  ours: {got}\n  file: {want}", file=sys.stderr)
        sys.exit(1)
    checks += 1


def ok(cond, what):
    global checks
    if not cond:
        print(f"FAILED {what}", file=sys.stderr)
        sys.exit(1)
    checks += 1


def sha256(*parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def u64be(n):
    return n.to_bytes(8, "big")


def b64(s):
    return base64.b64decode(s)


# --- RFC 9162 log tree --------------------------------------------------------

def leaf_hash(inp):
    return sha256(b"\x00", inp)


def node_hash(left, right):
    return sha256(b"\x01", left, right)


def largest_pow2_below(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaves):
    n = len(leaves)
    if n == 0:
        return sha256()
    if n == 1:
        return leaves[0]
    k = largest_pow2_below(n)
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


def verify_inclusion(leaf, index, size, root, path):
    """RFC 9162 §2.1.3.2."""
    if not (0 <= index < size):
        return False
    fn, sn, r = index, size - 1, leaf
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not (fn & 1 or fn == 0):
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(first, second, first_root, second_root, proof):
    """RFC 9162 §2.1.4.2."""
    if first > second:
        return False
    if first == second:
        return proof == [] and first_root == second_root
    if first == 0:
        return proof == []
    if not proof:
        return False
    p = list(proof)
    if first & (first - 1) == 0:
        p = [first_root] + p
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = p[0]
    for c in p[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while not (fn & 1 or fn == 0):
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0


# --- §19.2 map tree -------------------------------------------------------------

DEPTH = 256


def map_leaf(label, index, version):
    return sha256(b"\x10", label, u64be(index), u64be(version))


def map_node(left, right):
    return sha256(b"\x11", left, right)


EMPTY = [None] * (DEPTH + 1)
EMPTY[DEPTH] = sha256(b"\x12")
for _d in range(DEPTH - 1, -1, -1):
    EMPTY[_d] = map_node(EMPTY[_d + 1], EMPTY[_d + 1])


def bit(b, d):
    return (b[d >> 3] >> (7 - (d & 7))) & 1


def map_root(entries):
    """The slow, obviously-correct root: recurse on the label set at every depth."""
    def rec(depth, items):
        if not items:
            return EMPTY[depth]
        if depth == DEPTH:
            assert len(items) == 1
            label, (index, version) = items[0]
            return map_leaf(label, index, version)
        left = [it for it in items if bit(it[0], depth) == 0]
        right = [it for it in items if bit(it[0], depth) == 1]
        return map_node(rec(depth + 1, left), rec(depth + 1, right))
    return rec(0, list(entries.items()))


def verify_map_proof(root, label, leaf, bitmap, siblings):
    if len(label) != 32 or len(bitmap) != 32:
        return False
    if sum(bit(bitmap, d) for d in range(DEPTH)) != len(siblings):
        return False
    h = map_leaf(label, leaf["index"], leaf["version"]) if leaf else EMPTY[DEPTH]
    s = len(siblings) - 1
    for d in range(DEPTH - 1, -1, -1):
        if bit(bitmap, d):
            sib = siblings[s]
            s -= 1
        else:
            sib = EMPTY[d + 1]
        h = map_node(h, sib) if bit(label, d) == 0 else map_node(sib, h)
    return h == root


# --- §19.3–19.6 the log -----------------------------------------------------------

def label_for(acct_pub):
    return sha256(b"z-kt-label-v1:", acct_pub)


def value_key(acct_pub):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"z-kt-value-v1", info=b"value").derive(acct_pub)


def seal_value(acct_pub, nonce, plaintext):
    return nonce + ChaCha20Poly1305(value_key(acct_pub)).encrypt(nonce, plaintext, label_for(acct_pub))


def open_value(acct_pub, value):
    try:
        return ChaCha20Poly1305(value_key(acct_pub)).decrypt(value[:12], value[12:], label_for(acct_pub))
    except InvalidTag:
        return None


def leaf_input(label, version, fp, value_hash, ts):
    return b"z-kt-leaf-v1:" + label + u64be(version) + fp + value_hash + u64be(ts)


def sth_input(h):
    return b"z-kt-sth-v1:" + u64be(h["size"]) + b64(h["logRoot"]) + b64(h["mapRoot"]) + u64be(h["ts"])


def publish_input(label, version, fp, value_hash):
    return b"z-kt-publish-v1:" + label + u64be(version) + fp + value_hash


def ed_verify(pub, msg, sig):
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except InvalidSignature:
        return False


def verify_sth(h, log_pub):
    return ed_verify(log_pub, sth_input(h), b64(h["sig"]))


def entry_leaf_hash(e):
    return leaf_hash(leaf_input(b64(e["label"]), e["v"], b64(e["fp"]), b64(e["valueHash"]), e["ts"]))


# --- the three files -----------------------------------------------------------------

def check_log_tree():
    with open(os.path.join(DIR, "log_tree.json"), encoding="utf-8") as f:
        v = json.load(f)
    leaves = [leaf_hash(bytes.fromhex(x)) for x in v["leaf_inputs"]]
    eq([x.hex() for x in leaves], v["leaf_hashes"], "leaf hashes")
    roots = [bytes.fromhex(r) for r in v["roots_by_size"]]
    for n in range(0, 9):
        eq(mth(leaves[:n]).hex(), v["roots_by_size"][n], f"root at size {n}")
    for p in v["inclusion"]:
        path = [bytes.fromhex(x) for x in p["path"]]
        ok(verify_inclusion(leaves[p["index"]], p["index"], p["size"], roots[p["size"]], path), f"PATH({p['index']}, D[{p['size']}])")
        if p["size"] > 1:
            ok(not verify_inclusion(leaves[p["index"]], p["index"], p["size"], roots[p["size"] - 1], path), "inclusion against the wrong root refused")
    for c in v["consistency"]:
        proof = [bytes.fromhex(x) for x in c["proof"]]
        ok(verify_consistency(c["first"], c["second"], roots[c["first"]], roots[c["second"]], proof), f"PROOF({c['first']}, D[{c['second']}])")
        if 0 < c["first"] < c["second"]:
            ok(not verify_consistency(c["first"], c["second"], roots[c["first"] - 1], roots[c["second"]], proof), "consistency from the wrong first root refused")


def check_map_tree():
    with open(os.path.join(DIR, "map_tree.json"), encoding="utf-8") as f:
        v = json.load(f)
    eq(EMPTY[DEPTH].hex(), v["empty_leaf"], "empty leaf")
    eq(EMPTY[0].hex(), v["empty_root"], "empty root")
    ex = v["example_leaf_hash"]
    eq(map_leaf(bytes.fromhex(ex["label"]), ex["index"], ex["version"]).hex(), ex["hash"], "example leaf hash")
    entries = {}
    for s in v["steps"]:
        entries[bytes.fromhex(s["label"])] = (s["index"], s["version"])
        eq(map_root(entries).hex(), s["root_after"], f"map root after setting {s['label'][:8]}…")
    root = bytes.fromhex(v["final_root"])
    eq(map_root(entries).hex(), v["final_root"], "final map root")
    for p in v["proofs"]:
        label = bytes.fromhex(p["label"])
        ok(verify_map_proof(root, label, p["leaf"], bytes.fromhex(p["bitmap"]), [bytes.fromhex(x) for x in p["siblings"]]), f"map proof for {p['label'][:8]}…")
        if p["leaf"]:
            eq((p["leaf"]["index"], p["leaf"]["version"]), entries[label], "proof leaf equals the map's value")
        else:
            ok(label not in entries, "absence proof is for an absent label")
    for p in v["must_refuse"]:
        ok(not verify_map_proof(root, bytes.fromhex(p["label"]), p["leaf"], bytes.fromhex(p["bitmap"]), [bytes.fromhex(x) for x in p["siblings"]]), f"must refuse: {p['why']}")


def check_kt_log():
    with open(os.path.join(DIR, "kt_log.json"), encoding="utf-8") as f:
        v = json.load(f)
    c = v["contexts"]
    eq(c["label"], "z-kt-label-v1:", "label context")
    eq(c["leaf"], "z-kt-leaf-v1:", "leaf context")
    eq(c["sth"], "z-kt-sth-v1:", "sth context")
    eq(c["publish"], "z-kt-publish-v1:", "publish context")
    eq(c["witness"], "z-kt-witness-v1:", "witness context")
    log_seed = bytes.fromhex(v["log"]["seed"])
    log_key = Ed25519PrivateKey.from_private_bytes(log_seed)
    log_pub = log_key.public_key().public_bytes_raw()
    eq(log_pub.hex(), v["log"]["pub"], "log public key from seed")

    keys = {}
    for name, a in v["accounts"].items():
        k = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(a["account_ed_seed"]))
        pub = k.public_key().public_bytes_raw()
        eq(pub.hex(), a["account_ed_pub"], f"{name}: public key from seed")
        eq((b"z-kt-label-v1:" + pub).hex(), a["label_input"], f"{name}: label input")
        eq(label_for(pub).hex(), a["label"], f"{name}: label")
        eq(value_key(pub).hex(), a["value_key"], f"{name}: value key")
        keys[name] = (k, pub)

    # Replay the publishes: seal, sign, build the leaf, and re-derive every head.
    leaves = []
    entries = {}
    heads = v["heads_by_size"]
    eq(sha256().hex(), b64(heads[0]["logRoot"]).hex(), "empty head log root")
    eq(EMPTY[0].hex(), b64(heads[0]["mapRoot"]).hex(), "empty head map root")
    ok(verify_sth(heads[0], log_pub), "empty head signature")
    for i, p in enumerate(v["publishes"]):
        k, pub = keys[p["account"]]
        label = label_for(pub)
        nonce = bytes.fromhex(p["nonce"])
        plaintext = p["plaintext_json"].encode("utf-8")
        value = seal_value(pub, nonce, plaintext)
        eq(value.hex(), p["value"], f"publish {i}: sealed value")
        eq(open_value(pub, value), plaintext, f"publish {i}: value opens")
        other = keys["bob" if p["account"] == "alice" else "alice"][1]
        ok(open_value(other, value) is None, f"publish {i}: another account's key does not open it")
        vh = sha256(value)
        eq(vh.hex(), p["value_hash"], f"publish {i}: value hash")
        fp = bytes.fromhex(p["fingerprint"])
        pi = publish_input(label, p["version"], fp, vh)
        eq(pi.hex(), p["publish_input"], f"publish {i}: publish input")
        eq(k.sign(pi).hex(), p["publish_sig"], f"publish {i}: publish signature (deterministic Ed25519)")
        req = json.loads(p["request_json"])
        eq(b64(req["acct"]), pub, f"publish {i}: request acct")
        eq(req["v"], p["version"], f"publish {i}: request v")
        eq(b64(req["fp"]), fp, f"publish {i}: request fp")
        eq(b64(req["value"]), value, f"publish {i}: request value")
        ok(ed_verify(pub, pi, b64(req["sig"])), f"publish {i}: request signature verifies")
        e = p["entry"]
        li = leaf_input(label, p["version"], fp, vh, e["ts"])
        eq(li.hex(), e["leaf_input"], f"publish {i}: leaf input")
        eq(leaf_hash(li).hex(), e["leaf_hash"], f"publish {i}: leaf hash")
        eq(e["index"], i, f"publish {i}: index")
        ej = e["json"]
        eq(b64(ej["label"]), label, f"publish {i}: entry label")
        eq(ej["v"], p["version"], f"publish {i}: entry v")
        eq(b64(ej["valueHash"]), vh, f"publish {i}: entry valueHash")
        eq(ej["ts"], e["ts"], f"publish {i}: entry ts")
        ok("acct" not in ej, f"publish {i}: the public entry never carries acct")
        eq(entry_leaf_hash(ej).hex(), e["leaf_hash"], f"publish {i}: leaf hash from the public entry")
        leaves.append(leaf_hash(li))
        entries[label] = (i, p["version"])
        h = p["sth_after"]
        eq(h, heads[i + 1], f"publish {i}: sth_after is heads_by_size[{i + 1}]")
        eq(h["size"], i + 1, f"head {i + 1}: size")
        eq(b64(h["logRoot"]).hex(), mth(leaves).hex(), f"head {i + 1}: log root re-derived")
        eq(b64(h["mapRoot"]).hex(), map_root(entries).hex(), f"head {i + 1}: map root re-derived")
        eq(sth_input(h).hex(), p["sth_input_after"], f"head {i + 1}: sth input")
        eq(log_key.sign(sth_input(h)).hex(), b64(h["sig"]).hex(), f"head {i + 1}: signature")
    # Alice's first entry is the v1 multidevice vector's real signed list.
    with open(os.path.join(DIR, "..", "v1", "multidevice.json"), encoding="utf-8") as f:
        md = json.load(f)
    first = v["publishes"][0]
    eq(json.loads(first["plaintext_json"]), md["device_list"]["json"], "alice v3: the sealed list is the v1 vector's signed list")
    eq(first["fingerprint"], md["device_list"]["fingerprint"], "alice v3: fp is the v1 vector's fingerprint")
    eq(sha256(bytes.fromhex(md["device_list"]["signing_input"]))[:16].hex(), first["fingerprint"], "alice v3: fp = SHA-256(signing input)[0..16]")

    for c in v["consistency"]:
        ok(verify_consistency(c["first"], c["second"], b64(heads[c["first"]]["logRoot"]), b64(heads[c["second"]]["logRoot"]), [b64(x) for x in c["proof"]]), f"PROOF({c['first']}, {c['second']})")

    for name, l in v["lookups"].items():
        r = json.loads(l["response_json"])
        ok(verify_sth(r["sth"], log_pub), f"lookup {name}: head signature")
        label = bytes.fromhex(l["label"] if name == "nobody" else v["accounts"][name]["label"])
        m = r["map"]
        leaf = None if m["leaf"] is None else {"index": m["leaf"]["index"], "version": m["leaf"]["v"]}
        ok(verify_map_proof(b64(r["sth"]["mapRoot"]), label, leaf, b64(m["bitmap"]), [b64(x) for x in m["siblings"]]), f"lookup {name}: map proof")
        if l["expect"].get("absent"):
            ok(leaf is None and r["entry"] is None, f"lookup {name}: absent")
            continue
        eq(leaf, {"index": l["expect"]["index"], "version": l["expect"]["version"]}, f"lookup {name}: latest")
        e = r["entry"]
        inc = r["inclusion"]
        ok(verify_inclusion(entry_leaf_hash(e), inc["index"], inc["size"], b64(r["sth"]["logRoot"]), [b64(x) for x in inc["path"]]), f"lookup {name}: inclusion")
        eq(inc["size"], r["sth"]["size"], f"lookup {name}: proved at the head served")
        eq(sha256(b64(e["value"])).hex(), b64(e["valueHash"]).hex(), f"lookup {name}: value hash")
        pub = keys[name][1]
        latest = [p for p in v["publishes"] if p["account"] == name][-1]
        eq(open_value(pub, b64(e["value"])), latest["plaintext_json"].encode("utf-8"), f"lookup {name}: value opens to the latest list")

    h = json.loads(v["history_alice"]["response_json"])
    eq([x["entry"]["v"] for x in h["entries"]], v["history_alice"]["expect_versions"], "history: versions")
    for x in h["entries"]:
        ok(verify_inclusion(entry_leaf_hash(x["entry"]), x["inclusion"]["index"], x["inclusion"]["size"], b64(h["sth"]["logRoot"]), [b64(y) for y in x["inclusion"]["path"]]), "history: inclusion")

    rs = v["resigned_head"]["head"]
    ok(verify_sth(rs, log_pub), "re-signed head verifies")
    eq((rs["size"], rs["logRoot"], rs["mapRoot"]), (heads[-1]["size"], heads[-1]["logRoot"], heads[-1]["mapRoot"]), "re-signed head: same size and roots")
    ok(rs["ts"] > heads[-1]["ts"] and rs["sig"] != heads[-1]["sig"], "re-signed head: later ts, different signature")

    w = v["witness"]
    wk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(w["witness_seed"]))
    eq(wk.public_key().public_bytes_raw().hex(), w["witness_pub"], "witness public key")
    wi = b"z-kt-witness-v1:" + sth_input(w["over_sth"])
    eq(wi.hex(), w["witness_input"], "witness input")
    eq(wk.sign(wi).hex(), w["sig"], "witness signature")
    rec = json.loads(w["record_json"])
    ok(verify_sth(rec["sth"], log_pub), "witness record: log signature")
    ok(ed_verify(b64(rec["witness"]["pub"]), b"z-kt-witness-v1:" + sth_input(rec["sth"]), b64(rec["witness"]["sig"])), "witness record: co-signature")

    held_versions = {label_for(pub): ver for (k, pub), ver in zip(keys.values(), [0, 0])}  # placeholder, replaced below
    latest_version = {}
    for p in v["publishes"]:
        latest_version[p["account"]] = p["version"]
    for m in v["must_refuse"]:
        why = m["why"]
        if "request_json" in m:
            req = json.loads(m["request_json"])
            acct = b64(req["acct"])
            label = label_for(acct)
            vh = sha256(b64(req["value"]))
            sig_ok = ed_verify(acct, publish_input(label, req["v"], b64(req["fp"]), vh), b64(req["sig"]))
            if m["code"] == "bad_signature":
                ok(not sig_ok, f"must refuse: {why}")
            elif m["code"] == "stale_version":
                ok(sig_ok, "stale publish is otherwise well-formed")
                name = [n for n, (k, pub) in keys.items() if pub == acct][0]
                ok(req["v"] <= latest_version[name], f"must refuse: {why}")
            else:
                ok(False, f"unknown code {m['code']}")
        elif "response_json" in m:
            r = json.loads(m["response_json"])
            mm = r["map"]
            leaf = {"index": mm["leaf"]["index"], "version": mm["leaf"]["v"]}
            ok(not verify_map_proof(b64(r["sth"]["mapRoot"]), bytes.fromhex(v["accounts"]["alice"]["label"]), leaf, b64(mm["bitmap"]), [b64(x) for x in mm["siblings"]]), f"must refuse: {why}")
        elif "client_holds" in m:
            held = m["client_holds"]
            fork = json.loads(m["head_json"])
            ok(verify_sth(fork, log_pub), "the fork is signed by the real log key")
            if fork["size"] == held["size"]:
                ok(fork["logRoot"] != held["logRoot"] and fork["mapRoot"] != held["mapRoot"], f"must refuse: {why}")
            else:
                ok(not verify_consistency(held["size"], fork["size"], b64(held["logRoot"]), b64(fork["logRoot"]), [b64(x) for x in m["consistency_from_fork"]]), f"must refuse: {why}")
        elif "head_json" in m:
            ok(not verify_sth(json.loads(m["head_json"]), log_pub), f"must refuse: {why}")
        else:
            ok(False, f"unrecognised must_refuse case: {why}")
    del held_versions


def main():
    check_log_tree()
    check_map_tree()
    check_kt_log()
    print(f"docs/vectors/kt: {checks} values reproduced or refused by an independent implementation")
    return 0


if __name__ == "__main__":
    sys.exit(main())
