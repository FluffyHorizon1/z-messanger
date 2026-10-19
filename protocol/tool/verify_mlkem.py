#!/usr/bin/env python3
"""Independent check of the ML-KEM-768 values in docs/vectors/v2 and
docs/vectors/intro-key.

The Dart reference implementation uses package:pqcrypto for ML-KEM. This
script re-derives every KEM value in the v2 vector files with kyber-py — an
unrelated pure-Python implementation of FIPS 203 that is validated upstream
against the NIST known-answer tests — so the vectors, and therefore the
library, are checked against a second implementation with no shared code.

    pip install kyber-py==1.2.0
    python3 protocol/tool/verify_mlkem.py            # from the repo root

Exit status 0 = every value reproduced; anything else prints the first
mismatch and exits 1. CI runs this next to the Dart and Node verifiers.
"""
import json
import os
import sys

try:
    from kyber_py.ml_kem import ML_KEM_768
except ImportError:  # pragma: no cover
    print("kyber-py is required: pip install kyber-py==1.2.0", file=sys.stderr)
    sys.exit(2)

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
V2 = os.path.join(ROOT, "docs", "vectors", "v2")


def unhex(s):
    return bytes.fromhex(s)


def fail(msg):
    print("MISMATCH:", msg)
    sys.exit(1)


def check_kats():
    doc = json.load(open(os.path.join(V2, "mlkem768.json")))
    assert doc["suite"] == "mlkem768"
    n = 0
    for v in doc["vectors"]:
        ek, dk = ML_KEM_768._keygen_internal(unhex(v["d"]), unhex(v["z"]))
        if ek.hex() != v["ek"]:
            fail(f"vector {n}: ek")
        if dk.hex() != v["dk"]:
            fail(f"vector {n}: dk")
        K, c = ML_KEM_768._encaps_internal(ek, unhex(v["m"]))
        if c.hex() != v["c"]:
            fail(f"vector {n}: c")
        if K.hex() != v["K"]:
            fail(f"vector {n}: K")
        if ML_KEM_768.decaps(dk, c).hex() != v["K"]:
            fail(f"vector {n}: decaps")
        # Implicit rejection: the flipped ciphertext must yield exactly K_bad.
        if ML_KEM_768.decaps(dk, unhex(v["c_bad"])).hex() != v["K_bad"]:
            fail(f"vector {n}: implicit rejection")
        n += 1
    return n


def check_transcript():
    doc = json.load(open(os.path.join(V2, "pq_ratchet.json")))
    assert doc["suite"] == "pq_ratchet"
    seed = unhex(doc["offer"]["dk_seed"])
    ek, dk = ML_KEM_768._keygen_internal(seed[:32], seed[32:])
    if ek.hex() != doc["offer"]["ek"]:
        fail("transcript: offer ek")
    if dk.hex() != doc["offer"]["dk"]:
        fail("transcript: offer dk")
    inner = json.loads(doc["offer"]["inner_json"])
    if inner.get("k") != "pqek" or inner.get("alg") != "ML-KEM-768":
        fail("transcript: offer inner message shape")
    import base64
    if base64.b64decode(inner["ek"]) != ek:
        fail("transcript: offer inner ek")
    enc = doc["encapsulation"]
    K, c = ML_KEM_768._encaps_internal(ek, unhex(enc["m"]))
    if c.hex() != enc["c"] or K.hex() != enc["K"]:
        fail("transcript: encapsulation")
    if ML_KEM_768.decaps(dk, c).hex() != enc["K"]:
        fail("transcript: decapsulation")
    # The ciphertext in the first pq header must be this c, and the pq state
    # both sides end up with must hold this K.
    first = next(s for s in doc["steps"]
                 if s["op"] == "encrypt" and s["header"].get("pqct"))
    if base64.b64decode(first["header"]["pqct"]) != c:
        fail("transcript: header pqct")
    for s in doc["steps"]:
        for key in ("pq_before", "pq_after"):
            k = s[key].get("k")
            if k is not None and k != enc["K"]:
                fail(f"transcript: pq state K in step '{s['label']}'")
    return len(doc["steps"])


def check_rekey():
    import base64
    doc = json.load(open(os.path.join(V2, "pq_rekey.json")))
    assert doc["suite"] == "pq_rekey"
    rk = doc["rekey"]
    # The second-generation keypair is reproduced from the recorded seed …
    seed = unhex(rk["dk_seed"])
    ek, dk = ML_KEM_768._keygen_internal(seed[:32], seed[32:])
    if ek.hex() != rk["ek"] or dk.hex() != rk["dk"]:
        fail("rekey: generation-1 keypair")
    # … and the re-key offer inner (recovered from the encapsulator's decrypt
    # step) carries exactly this ek, tagged as generation 1.
    dec = next(s for s in doc["steps"]
               if s["op"] == "decrypt" and s["label"].startswith(
                   "encapsulator receives re-key"))
    inner = json.loads(bytes.fromhex(dec["plaintext"]).decode())
    if inner.get("k") != "pqek" or inner.get("g") != 1:
        fail("rekey: offer inner shape")
    if base64.b64decode(inner["ek"]) != ek:
        fail("rekey: offer inner ek")
    # Generation-1 encapsulation reproduces the recorded ciphertext and secret.
    K, c = ML_KEM_768._encaps_internal(ek, unhex(rk["m"]))
    if c.hex() != rk["c"] or K.hex() != rk["K"]:
        fail("rekey: generation-1 encapsulation")
    if ML_KEM_768.decaps(dk, c).hex() != rk["K"]:
        fail("rekey: generation-1 decapsulation")
    if rk["K"] == doc["gen0_secret"]:
        fail("rekey: secret did not rotate")
    # The new ciphertext must appear in a pqg=1 header.
    hdr = next(s for s in doc["steps"]
               if s["op"] == "encrypt" and s["header"].get("pqg") == 1
               and s["header"].get("pqct"))
    if base64.b64decode(hdr["header"]["pqct"]) != c:
        fail("rekey: generation-1 header pqct")
    return len(doc["steps"])


def check_intro_key():
    """ADR 0033 addendum A (docs/vectors/intro-key): every sealing key from
    its seed, an introduction mailbox's seed from its introduction seed by
    HKDF (RFC 5869, written here with hmac), and FIPS 203 §7.2's input check:
    kyber-py's encapsulation refuses exactly the keys the file says fail."""
    import hashlib
    import hmac

    def hkdf(ikm, salt, info, n):
        prk = hmac.new(salt, ikm, hashlib.sha256).digest()
        out, t, i = b"", b"", 1
        while len(out) < n:
            t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
            out += t
            i += 1
        return out[:n]

    doc = json.load(open(os.path.join(ROOT, "docs", "vectors", "intro-key",
                                      "intro_key.json")))
    assert doc["suite"] == "intro_key"
    n = 0
    for d in doc["devices"]:
        seed = unhex(d["seal_seed"])
        ek, dk = ML_KEM_768._keygen_internal(seed[:32], seed[32:])
        if ek.hex() != d["ek"]:
            fail(f"intro-key {d['name']}: ek")
        if dk.hex() != d["dk"]:
            fail(f"intro-key {d['name']}: dk")
        if hashlib.sha256(ek).hexdigest() != d["sk"]:
            fail(f"intro-key {d['name']}: sk")
        # It is a key that encapsulates, and decapsulates what it takes.
        K, c = ML_KEM_768._encaps_internal(ek, bytes(32))
        if ML_KEM_768.decaps(dk, c) != K:
            fail(f"intro-key {d['name']}: round trip")
        n += 1
    intro = doc["devices"][-1]
    kseed = hkdf(unhex(intro["ed_seed"]), b"z-handle-intro-k-v1", b"", 64)
    if kseed.hex() != intro["seal_seed"]:
        fail("intro-key: kintroSeed = HKDF(introSeed, 'z-handle-intro-k-v1', '', 64)")

    def encapsulates(ek):
        try:
            ML_KEM_768._encaps_internal(ek, bytes(32))
            return True
        except ValueError:
            return False

    for m in doc["modulus_check"]:
        if encapsulates(unhex(m["ek"])) != m["valid"]:
            fail(f"intro-key modulus check: {m['name']}")
        n += 1
    for a in doc["acceptance"]:
        ek = unhex(a["ek"])
        if a["verdict"] == "keyEncoding" and encapsulates(ek):
            fail(f"intro-key acceptance {a['name']}: kyber-py takes the key")
        if a["verdict"] in ("accepted", "notTheCodesKey", "badSignature",
                            "wrongMailbox") and not encapsulates(ek):
            fail(f"intro-key acceptance {a['name']}: kyber-py refuses the key")
    return n


if __name__ == "__main__":
    n = check_kats()
    m = check_transcript()
    r = check_rekey()
    k = check_intro_key()
    print(f"ok: {n} ML-KEM-768 known-answer vectors, the {m}-step v2 "
          f"transcript, the {r}-step re-key transcript and {k} introduction-"
          f"key values reproduced by kyber-py")


def check_sealed_v2():
    """44.1, ADR 0033 §5 (docs/vectors/sealed-v2): the KEM half of every zs2.
    envelope — the recipient's sealing key from its seed, each envelope's
    (K, ct) = Encaps_internal(ek, m) and Decaps back to K, and the K a
    recipient derives for what it must refuse: another encapsulation in place
    of the envelope's, a zs1. body read as a zs2. one (implicit rejection),
    and the envelope decapsulated with another device's sealing key. The rest
    of each envelope is replayed by server/test/vectors.test.js."""
    import base64
    import hashlib

    def b64url(s):
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

    doc = json.load(open(os.path.join(ROOT, "docs", "vectors", "sealed-v2",
                                      "sealed_v2.json")))
    assert doc["suite"] == "sealed_v2"
    to = doc["recipient"]
    seed = unhex(to["seal_seed"])
    ek, dk = ML_KEM_768._keygen_internal(seed[:32], seed[32:])
    if ek.hex() != to["seal_ek"] or dk.hex() != to["seal_dk"]:
        fail("sealed-v2: the recipient's sealing key from its seed")
    if hashlib.sha256(ek).hexdigest() != to["sk"]:
        fail("sealed-v2: sk")
    wseed = unhex(doc["wrong_recipient"]["seal_seed"])
    wek, wdk = ML_KEM_768._keygen_internal(wseed[:32], wseed[32:])
    if wek.hex() != doc["wrong_recipient"]["seal_ek"]:
        fail("sealed-v2: the other device's sealing key from its seed")
    n = 0
    by_name = {}
    for v in doc["vectors"]:
        K, c = ML_KEM_768._encaps_internal(ek, unhex(v["m"]))
        if c.hex() != v["kem_ct"] or K.hex() != v["K"]:
            fail(f"sealed-v2 {v['name']}: Encaps_internal(ek, m)")
        if ML_KEM_768.decaps(dk, c) != K:
            fail(f"sealed-v2 {v['name']}: Decaps")
        if hashlib.sha256(c).hexdigest() != v["kem_ct_sha256"]:
            fail(f"sealed-v2 {v['name']}: SHA-256(ct)")
        if "envelope" in v and b64url(v["envelope"][4:])[32:1120] != c:
            fail(f"sealed-v2 {v['name']}: ct is bytes 32..1120 of the body")
        by_name[v["name"]] = v
        n += 1
    refusals = {r["name"]: r for r in doc["must_refuse"]}
    s = refusals["kem_ct_swapped"]
    K, c = ML_KEM_768._encaps_internal(ek, unhex(s["m"]))
    if c.hex() != s["kem_ct"] or K.hex() != s["K"]:
        fail("sealed-v2 kem_ct_swapped: the other encapsulation")
    if K.hex() == by_name["bucket_1024"]["K"]:
        fail("sealed-v2 kem_ct_swapped: the same K")
    if b64url(s["envelope"][4:])[32:1120] != c:
        fail("sealed-v2 kem_ct_swapped: the ciphertext in the envelope")
    z = refusals["zs1_body_under_zs2"]
    misread = b64url(z["envelope"][4:])[32:1120]
    if misread.hex() != z["kem_ct"]:
        fail("sealed-v2 zs1_body_under_zs2: what a zs2. reader takes for ct")
    if ML_KEM_768.decaps(dk, misread).hex() != z["K"]:
        fail("sealed-v2 zs1_body_under_zs2: implicit rejection")
    adv = doc["classical_adversary"]
    oseed = unhex(adv["seal_seed"])
    if oseed != wseed:
        fail("sealed-v2: the adversary's sealing key is the other device's")
    of = by_name[adv["envelope_of"]]
    if ML_KEM_768.decaps(wdk, unhex(of["kem_ct"])).hex() != adv["K"]:
        fail("sealed-v2 classical adversary: implicit rejection under another key")
    if adv["K"] == of["K"]:
        fail("sealed-v2 classical adversary: another key decapsulated to K")
    return n


if __name__ == "__main__":
    s = check_sealed_v2()
    print(f"ok: the KEM half of {s} zs2. envelopes (sealed-v2), and the K a "
          f"recipient derives for a swapped ciphertext, for a zs1. body read "
          f"as zs2. and under another device's sealing key, reproduced by "
          f"kyber-py")


def check_pair_connect_v3():
    """44.1, ADR 0033 §3 and §4 (docs/vectors/pair-v3/pairing_v3.json and
    docs/vectors/connect/invite_v3.json): each ceremony's fresh ML-KEM-768
    key from its recorded seed, the encapsulation (K, ct) = Encaps_internal(ek,
    m) from its recorded randomness and Decaps back to K, the same ek and ct
    in the first two frames, and every device's sealing key from its seed with
    sk = SHA-256(ek) where a code or an opening carries it. The rest of each
    file is replayed by server/test/vectors.test.js."""
    import base64
    import hashlib

    vec = os.path.join(ROOT, "docs", "vectors")
    pair = json.load(open(os.path.join(vec, "pair-v3", "pairing_v3.json")))
    assert pair["suite"] == "pairing_v3"
    conn = json.load(open(os.path.join(vec, "connect", "invite_v3.json")))
    assert conn["suite"] == "connect_invite_v3"
    n = 0
    for name, doc, first, second in (
            ("pairing v3", pair, pair["new_device"]["commit_frame"],
             pair["existing_device"]["reply_frame"]),
            ("connect v3", conn, conn["frames"]["commit"],
             conn["frames"]["reply"])):
        kem = doc["kem"]
        seed = unhex(kem["seed"])
        ek, dk = ML_KEM_768._keygen_internal(seed[:32], seed[32:])
        if ek.hex() != kem["ek"]:
            fail(f"{name}: ek from its seed")
        if dk.hex() != kem["dk"]:
            fail(f"{name}: dk from its seed")
        K, c = ML_KEM_768._encaps_internal(ek, unhex(kem["m"]))
        if c.hex() != kem["ct"]:
            fail(f"{name}: ct = Encaps(ek; m)")
        if K.hex() != kem["K"]:
            fail(f"{name}: K = Encaps(ek; m)")
        if ML_KEM_768.decaps(dk, c) != K:
            fail(f"{name}: Decaps(dk, ct) = K")
        if base64.b64decode(first["ek"]) != ek:
            fail(f"{name}: the first frame offers ek")
        if base64.b64decode(second["ct"]) != c:
            fail(f"{name}: the second frame carries ct")
        n += 1

    nd = pair["new_device"]
    seals = [("pairing v3 new device", nd["seal_seed"], nd["seal_ek"],
              nd["sk"])]
    seals += [(f"connect v3 {p['role']}", p["seal_seed"], p["seal_ek"],
               p["sk"]) for p in conn["parties"]]
    for who, seed_hex, ek_hex, sk_hex in seals:
        seed = unhex(seed_hex)
        ek, _ = ML_KEM_768._keygen_internal(seed[:32], seed[32:])
        if ek.hex() != ek_hex:
            fail(f"{who}: the sealing key from its seed")
        if sk_hex is not None and hashlib.sha256(ek).hexdigest() != sk_hex:
            fail(f"{who}: sk = SHA-256(ek)")
        n += 1
    # The pairing opening carries sk; each connect reveal carries its
    # device's sealing key as pqseal.
    if base64.b64decode(nd["open_frame"]["sk"]).hex() != nd["sk"]:
        fail("pairing v3: the opening's sk")
    for plain, p in ((conn["reveals"]["open_plaintext"], conn["parties"][0]),
                     (conn["reveals"]["reveal_plaintext"],
                      conn["parties"][1])):
        if base64.b64decode(json.loads(plain)["pqseal"]).hex() != p["seal_ek"]:
            fail(f"connect v3 {p['role']}: the reveal's pqseal")
    return n


if __name__ == "__main__":
    p = check_pair_connect_v3()
    print(f"ok: {p} pairing v3 and CONNECT v3 KEM values (each ceremony's "
          f"key, encapsulation and decapsulation, and every sealing key with "
          f"its sk) reproduced by kyber-py")
