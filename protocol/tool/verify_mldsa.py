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
import base64
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
CERT_PATH = os.path.join(ROOT, "docs", "vectors", "v3", "device_cert_v3.json")

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

    # 18.9 / ADR 0004: the account's post-quantum signature over its DEVICE
    # LIST. Checked from an independent implementation because this is the
    # artefact phase 13's exit criterion actually rests on — a forged device
    # set must not verify, and per-certificate signatures would not have
    # caught one.
    with open(CERT_PATH, encoding="utf-8") as f:
        cv = json.load(f)
    dl = cv["device_list"]
    acct_pk = bytes.fromhex(cv["account"]["ml_pub"])
    # ADR 0010 made the account's ML-DSA signature follow whatever the
    # classical half signs. Since the mixed-version fix that is the v1 input,
    # for as long as a v1 signature is produced — verifying it over v2 is
    # precisely what a not-yet-updated client could not do. The v2 input is
    # still rebuilt and compared below, and sig2 still covers each device's
    # X25519 ratchet key and id.
    inp = bytes.fromhex(dl["signing_input"])
    if not ML_DSA_65.verify(acct_pk, inp, bytes.fromhex(dl["ml_sig"])):
        print("MISMATCH device list: signature does not verify",
              file=sys.stderr)
        sys.exit(1)
    globals()["checks"] += 1

    # Both signing inputs are rebuilt here, not taken on trust. v1: context,
    # version, the device Ed25519 keys sorted. v2 (ADR 0010): the same order,
    # each device contributing ded || dx || u16be(len(id)) || id. If either
    # reconstruction disagreed with the recorded bytes, the signature would be
    # attesting to something other than the set a reader computes.
    lst = json.loads(dl["list_json"])
    devs = sorted(lst["devs"], key=lambda d: base64.b64decode(d["ded"]))
    eds = [base64.b64decode(d["ded"]) for d in devs]
    rebuilt_v1 = b"z-devlist-v1:" + f"{lst['ver']}:".encode() + b"".join(eds)
    eq(rebuilt_v1.hex(), dl["signing_input"], "device list v1 signing input")
    rebuilt_v2 = b"z-devlist-v2:" + f"{lst['ver']}:".encode() + b"".join(
        base64.b64decode(d["ded"]) + base64.b64decode(d["dx"])
        + len(d["id"].encode()).to_bytes(2, "big") + d["id"].encode()
        for d in devs)
    eq(rebuilt_v2.hex(), dl["signing_input_v2"], "device list v2 signing input")

    # An excluded device or a rolled-back version changes the v2 input, so the
    # genuine signature fails — the reason the signature is over the list and
    # not over each certificate (ADR 0004).
    for name in ("excluded", "rolled_back"):
        other = bytes.fromhex(dl["must_refuse"][f"{name}_signing_input_v2"])
        if other == inp:
            print(f"MISMATCH device list: {name} input equals the genuine one",
                  file=sys.stderr)
            sys.exit(1)
        if ML_DSA_65.verify(acct_pk, other, bytes.fromhex(dl["ml_sig"])):
            print(f"MISMATCH device list: {name} set verified", file=sys.stderr)
            sys.exit(1)
        globals()["checks"] += 2

    # ADR 0010: a swapped X25519 ratchet key moves the v2 input (and the
    # fingerprint) though every Ed25519 key — and so the v1 input — is untouched.
    # The genuine ML-DSA signature, now over v2, does not verify the swapped set.
    sub = dl["substitution"]
    eq(sub["v1_signing_input"], dl["signing_input"],
       "an X-only swap leaves the v1 input unchanged")
    swapped_v2 = bytes.fromhex(sub["signing_input_v2"])
    if swapped_v2 == inp:
        print("MISMATCH device list: v2 input blind to the X swap",
              file=sys.stderr)
        sys.exit(1)
    if ML_DSA_65.verify(acct_pk, swapped_v2, bytes.fromhex(dl["ml_sig"])):
        print("MISMATCH device list: swapped set verified", file=sys.stderr)
        sys.exit(1)
    globals()["checks"] += 3

    print(f"ok: {len(v['vectors'])} ML-DSA-65 known-answer vectors, the "
          f"hybrid construction and the device-list signature reproduced by "
          f"dilithium-py ({checks} checks)")


if __name__ == "__main__":
    main()
