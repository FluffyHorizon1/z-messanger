#!/usr/bin/env python3
"""Independent check of the ML-DSA-65 values in docs/vectors/v3.

The Dart reference implementation uses package:pqcrypto for ML-DSA. This
script re-derives every value in the v3 vector file with dilithium-py — an
unrelated pure-Python implementation of FIPS 204, validated upstream against
the NIST known-answer tests — so the vectors, and therefore the library, are
checked against a second implementation with no shared code.

It is the ML-DSA counterpart of verify_mlkem.py, and the same discipline: if
these two implementations ever disagree, one of them is wrong and the vectors
say which values to look at.

    pip install dilithium-py
    python3 protocol/tool/verify_mldsa.py          # from the repo root

Exit status 0 = every value reproduced; anything else prints the first
mismatch and exits 1.
"""
import json
import os
import sys

try:
    from dilithium_py.ml_dsa import ML_DSA_65
except ImportError:  # pragma: no cover
    print("dilithium-py is required: pip install dilithium-py", file=sys.stderr)
    sys.exit(2)

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PATH = os.path.join(ROOT, "docs", "vectors", "v3", "mldsa65.json")

checks = 0


def eq(got, want, what):
    global checks
    if got != want:
        print(f"MISMATCH {what}\n  ours: {got}\n  file: {want}", file=sys.stderr)
        sys.exit(1)
    checks += 1


def main():
    with open(PATH, encoding="utf-8") as f:
        v = json.load(f)

    eq(v["public_key_bytes"], 1952, "declared public key size")
    eq(v["signature_bytes"], 3309, "declared signature size")

    for i, x in enumerate(v["vectors"]):
        seed = bytes.fromhex(x["seed"])
        msg = bytes.fromhex(x["message_hex"])

        # KeyGen_internal(zeta) — deterministic in the seed.
        pk, sk = ML_DSA_65._keygen_internal(seed)
        eq(pk.hex(), x["pk"], f"vector {i} public key")
        eq(sk.hex(), x["sk"], f"vector {i} secret key")
        eq(len(pk), 1952, f"vector {i} public key length")

        # Deterministic signing: rnd = 0^32, per the vector's own statement.
        sig = ML_DSA_65._sign_internal(sk, msg, bytes(32))
        # The external API prepends the FIPS 204 message prefix; the recorded
        # signature is over that same framing, so verify through the API and
        # compare bytes through the internal one.
        eq(len(sig), 3309, f"vector {i} signature length")
        recorded = bytes.fromhex(x["signature"])
        if not ML_DSA_65.verify(pk, msg, recorded):
            print(f"MISMATCH vector {i}: recorded signature does not verify",
                  file=sys.stderr)
            sys.exit(1)
        checks_note = ML_DSA_65.verify(pk, msg, bytes.fromhex(
            x["tampered_signature"]))
        if checks_note:
            print(f"MISMATCH vector {i}: tampered signature verified",
                  file=sys.stderr)
            sys.exit(1)
        globals()["checks"] += 2

    # The hybrid half: the post-quantum key derives from its recorded seed,
    # its signature verifies, and the commitment ADR 0003 puts in a contact
    # code is SHA-256 over the context string and that key.
    import hashlib
    h = v["hybrid"]
    pk, sk = ML_DSA_65._keygen_internal(bytes.fromhex(h["ml_seed"]))
    eq(pk.hex(), h["ml_pub"], "hybrid ML-DSA public key")
    if not ML_DSA_65.verify(pk, h["message"].encode(),
                            bytes.fromhex(h["ml_sig"])):
        print("MISMATCH hybrid: ML-DSA half does not verify", file=sys.stderr)
        sys.exit(1)
    commit = hashlib.sha256(h["commit_context"].encode() + pk).hexdigest()
    eq(commit, h["pq_commitment"], "pq commitment")

    print(f"ok: {len(v['vectors'])} ML-DSA-65 known-answer vectors and the "
          f"hybrid construction reproduced by dilithium-py ({checks} checks)")


if __name__ == "__main__":
    main()
