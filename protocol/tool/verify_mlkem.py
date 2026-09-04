#!/usr/bin/env python3
"""Independent check of the ML-KEM-768 values in docs/vectors/v2.

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


if __name__ == "__main__":
    n = check_kats()
    m = check_transcript()
    r = check_rekey()
    print(f"ok: {n} ML-KEM-768 known-answer vectors, the {m}-step v2 "
          f"transcript and the {r}-step re-key transcript reproduced by "
          f"kyber-py")
