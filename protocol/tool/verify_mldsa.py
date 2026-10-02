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

    # ADR 0017: WHICH input the ML-DSA is over is decided by the list itself.
    # A list has one of three shapes — {sig}, {sig, sig2} or {sig3} — and any
    # other is refused before a signature is looked at. It commits to the
    # strongest signature that is alone: the v1 input while it carries sig,
    # the v3 input (the v2 content under "z-devlist-v3:") once sig3 is alone.
    # Applied here to each list's own JSON rather than read from the recorded
    # field, so a vector that labelled the wrong input would be caught.
    def v1_input(l):
        return b"z-devlist-v1:" + f"{l['ver']}:".encode() + b"".join(
            sorted(base64.b64decode(d["ded"]) for d in l["devs"]))

    def v2_content(context, l):
        return context + f"{l['ver']}:".encode() + b"".join(
            base64.b64decode(d["ded"]) + base64.b64decode(d["dx"])
            + len(d["id"].encode()).to_bytes(2, "big") + d["id"].encode()
            for d in sorted(l["devs"], key=lambda d: base64.b64decode(d["ded"])))

    def v2_input(l):
        return v2_content(b"z-devlist-v2:", l)

    def v3_input(l):
        return v2_content(b"z-devlist-v3:", l)

    def shape(l):
        return "+".join(k for k in ("sig", "sig2", "sig3") if k in l)

    def committed(l):
        return v3_input(l) if shape(l) == "sig3" else v1_input(l)

    VALID_SHAPES = ("sig", "sig+sig2", "sig3")

    def well_formed(l):
        """A signature member that is present is a signature (§3.4)."""
        return all(isinstance(l[k], str) for k in ("sig", "sig2", "sig3") if k in l)

    def pq_admitted(l, ml_sig):
        """What a reader's post-quantum check takes (§18.9): a well-formed
        list in one of the three shapes, whose committed input the ML-DSA
        verifies over."""
        return (well_formed(l) and shape(l) in VALID_SHAPES
                and ML_DSA_65.verify(acct_pk, committed(l), ml_sig))

    def refuse(cond, what):
        if cond:
            print(f"MISMATCH {what}", file=sys.stderr)
            sys.exit(1)
        globals()["checks"] += 1

    # The stage-1 list carries `sig`: the rule gives the v1 input, which is
    # what its signature verified over above.
    eq(committed(lst).hex(), dl["signing_input"],
       "stage-1 list: the rule gives the v1 input")
    dl_ml = bytes.fromhex(dl["ml_sig"])
    refuse(not pq_admitted(lst, dl_ml),
           "stage-1 list: its ML-DSA is not taken over the input it commits to")

    # A stage-2 list: the account's list at version 4 with `sig3` alone, and
    # its ML-DSA — over the v3 input, which names each device's ratchet key.
    c2 = cv["device_list_v2_only"]
    l2 = json.loads(c2["list_json"])
    ml2 = bytes.fromhex(c2["ml_sig"])
    eq(shape(l2), "sig3", "v2-only list: sig3 alone")
    eq(l2["ver"], lst["ver"] + 1, "v2-only list: the next version")
    in2 = committed(l2)
    eq(in2.hex(), c2["signing_input_v3"], "v2-only list: the rule gives the v3 input")
    eq(in2[:13], b"z-devlist-v3:", "v2-only list: the v3 context")
    eq(in2[13:], v2_input(l2)[13:], "v2-only list: the v3 input is the v2 content")
    eq(v1_input(l2).hex(), c2["v1_signing_input"], "v2-only list: its v1 input")
    eq(v2_input(l2).hex(), c2["v2_signing_input"], "v2-only list: its v2 input")
    refuse(not pq_admitted(l2, ml2),
           "v2-only list: its ML-DSA is not taken over the v3 input")
    refuse(pq_admitted(l2, dl_ml),
           "v2-only list: the stage-1 ML-DSA is taken for it")
    refuse(ML_DSA_65.verify(acct_pk, v1_input(l2), ml2),
           "v2-only list: the ML-DSA verifies over the v1 input, so the rule "
           "was not what signed it")
    refuse(ML_DSA_65.verify(acct_pk, v2_input(l2), ml2),
           "v2-only list: the ML-DSA verifies over the v2 input, which ML-DSAs "
           "made for earlier lists were also over")
    refuse(ML_DSA_65.verify(acct_pk, in2, bytes.fromhex(dl["ml_sig"])),
           "v2-only list: the stage-1 signature covers it")
    eq(hashlib.sha256(in2).hexdigest()[:32], c2["fingerprint"],
       "v2-only list: fingerprint = SHA-256(v3 input)[0..16]")
    eq(json.loads(c2["sig_json"])["mlsig"],
       base64.b64encode(ml2).decode(), "v2-only list: sig_json carries ml_sig")
    # The ratchet-key swap again, at this version: in stage 1 the ML-DSA could
    # not see it; over the v3 input it refuses it.
    r2 = c2["must_refuse"]
    sw = json.loads(r2["swapped_list_json"])
    eq(shape(sw), "sig3", "swapped v2-only list: sig3 alone")
    moved = [d for d in sw["devs"] if d["id"] == r2["swapped_device_id"]][0]
    eq(base64.b64decode(moved["dx"]).hex(), r2["swapped_x_pub"],
       "swapped v2-only list: the replaced ratchet key")
    in_sw = committed(sw)
    eq(in_sw.hex(), r2["swapped_signing_input_v3"],
       "swapped v2-only list: the rule gives its v3 input")
    refuse(in_sw == in2, "swapped v2-only list: v3 input blind to the swap")
    refuse(v1_input(sw) != v1_input(l2),
           "swapped v2-only list: the swap moved the v1 input too")
    refuse(pq_admitted(sw, ml2),
           "swapped v2-only list: the genuine ML-DSA is taken for it")
    eq(hashlib.sha256(in_sw).hexdigest()[:32], r2["swapped_fingerprint"],
       "swapped v2-only list: its fingerprint")

    # The stage-1 list with `sig` deleted. What the ML-DSA half does with it:
    # the deletion leaves the v1 input exactly as it was, so the stage-1
    # ML-DSA KEPT beside it still verifies over those bytes — the post-quantum
    # signature cannot tell a stripped list from the one it was made for, and
    # with it DELETED there is nothing post-quantum to check at all. Either
    # way the list is refused for its shape, {sig2}, before any signature: that
    # is the only check that can refuse it, and the one this verifies.
    st = json.loads(r2["sig_stripped_list_json"])
    eq(st, {k: x for k, x in lst.items() if k != "sig"},
       "sig-stripped list: device_list without sig")
    eq(shape(st), "sig2", "sig-stripped list: {sig2}")
    eq(v1_input(st).hex(), dl["signing_input"],
       "sig-stripped list: its v1 input is the stage-1 list's")
    refuse(not ML_DSA_65.verify(acct_pk, committed(st), dl_ml),
           "sig-stripped list: the kept stage-1 ML-DSA should still verify over "
           "the input the list would commit to, which the deletion leaves as it "
           "was")
    refuse(pq_admitted(st, dl_ml),
           "sig-stripped list: taken with its own ML-DSA — only its shape, "
           "{sig2}, can refuse it, and here it did not")
    refuse(ML_DSA_65.verify(acct_pk, v3_input(st), dl_ml),
           "sig-stripped list: the stage-1 ML-DSA verifies over its v3 input")

    # A null signature member: the list is malformed, and the post-quantum
    # check takes it no more than verify() does — though its ML-DSA verifies
    # over the input the list would otherwise commit to. The last case keeps
    # the members of a dual-signed list, so by the members present it is a
    # valid shape and only this rule refuses it.
    sig2_nulled = dict(lst)
    sig2_nulled["sig2"] = None
    for base, ml, nulled, member in (
            (lst, dl_ml, {**lst, "sig3": None}, "sig3"),
            (l2, ml2, {**l2, "sig": None}, "sig"),
            (lst, dl_ml, sig2_nulled, "sig2")):
        absent = {k: x for k, x in nulled.items() if x is not None}
        refuse(not ML_DSA_65.verify(acct_pk, committed(absent), ml),
               f"null {member}: the genuine ML-DSA should verify over the input "
               f"the list commits to with the null read as absent")
        refuse(well_formed(nulled),
               f"a null {member} member taken for a signature")
        refuse(pq_admitted(nulled, ml),
               f"a list with a null {member} member is taken by the ML-DSA check")
    eq(shape(sig2_nulled), "sig+sig2",
       "a null sig2 beside sig: a valid shape by the members present")

    print(f"ok: {len(v['vectors'])} ML-DSA-65 known-answer vectors, the "
          f"hybrid construction and the device-list signatures (dual-signed "
          f"and v2-only, and the dual-signed list with its sig deleted) "
          f"reproduced or refused by dilithium-py ({checks} checks)")


if __name__ == "__main__":
    main()
