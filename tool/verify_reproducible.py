#!/usr/bin/env python3
"""Compare two Android artefacts and say precisely how they differ.

The point of a reproducible build is that somebody who does not trust us can
build the app themselves and check they got what we shipped. That check is
worth nothing if its only output is "different" — a verifier who sees that has
learned nothing about whether the difference matters, and the usual outcome is
that they shrug and stop checking. So this prints exactly what differs and
where: which zip entries, which bytes, and whether anything outside the APK
signing block moved at all.

Usage:
    python3 tool/verify_reproducible.py a.apk b.apk
    python3 tool/verify_reproducible.py --ignore-signing-block a.apk b.apk

Exit status is 0 when the two files are byte-for-byte identical, 1 when they
differ, 2 when something could not be read. See docs/REPRODUCIBLE_BUILDS.md
for the build procedure these are expected to come from.

`--ignore-signing-block` succeeds when everything OUTSIDE the APK signing
block matches — that is, when the app is identical and only the signature is
not. Two machines that have never signed an Android build before each generate
their own debug key, so their signatures differ for a reason that says nothing
about the build; and a release key using a randomised algorithm (ECDSA,
RSASSA-PSS) signs differently every time by design. Neither is evidence about
the app. Use this mode when comparing builds from different machines, and the
plain mode when comparing builds that were signed with the same key.
"""

import hashlib
import struct
import sys
import zipfile

APK_SIG_MAGIC = b"APK Sig Block 42"

# Pair IDs seen in an APK signing block. The unnamed ones are printed in hex.
BLOCK_IDS = {
    0x7109871A: "v2 APK Signature Scheme",
    0xF05368C0: "v3 APK Signature Scheme",
    0x1B93AD61: "v3.1 APK Signature Scheme",
    0x42726577: "padding",
    0x6DFF800D: "source stamp",
    0x504B4453: "AGP dependency metadata (see docs/REPRODUCIBLE_BUILDS.md)",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def signing_block(data: bytes):
    """(start, end) of the APK signing block, or None if there is not one.

    Layout: uint64 size | pairs | uint64 size | 16-byte magic. The trailing
    size counts everything after the leading size field, magic included.
    """
    magic = data.rfind(APK_SIG_MAGIC)
    if magic < 8:
        return None
    size = struct.unpack("<Q", data[magic - 8 : magic])[0]
    start = magic + 16 - size - 8
    if start < 0 or struct.unpack("<Q", data[start : start + 8])[0] != size:
        return None
    return start, magic + 16


def walk_pairs(data: bytes, start: int, end: int):
    """Yield (id, offset, length) for each pair in the signing block."""
    off = start + 8
    limit = end - 24  # trailing size + magic
    while off < limit:
        length = struct.unpack("<Q", data[off : off + 8])[0]
        if length == 0 or off + 8 + length > limit + 8:
            return
        pair_id = struct.unpack("<I", data[off + 8 : off + 12])[0]
        yield pair_id, off, length
        off += 8 + length


def differing_runs(a: bytes, b: bytes, block: int = 1 << 16):
    """Byte ranges where the two differ.

    Blockwise, because comparing 80 MB one byte at a time in Python takes
    minutes and a verification tool nobody waits for is one nobody runs. Whole
    blocks are compared at C speed; only blocks that differ are scanned.
    """
    runs = []
    n = min(len(a), len(b))
    for base in range(0, n, block):
        top = min(base + block, n)
        if a[base:top] == b[base:top]:
            continue
        i = base
        while i < top:
            if a[i] != b[i]:
                j = i
                while j < top and a[j] != b[j]:
                    j += 1
                # Join a run that ran up to the previous block boundary.
                if runs and runs[-1][1] == i:
                    runs[-1] = (runs[-1][0], j)
                else:
                    runs.append((i, j))
                i = j
            else:
                i += 1
    return runs


def compare_entries(pa: str, pb: str) -> int:
    """Per-entry comparison. Returns the number of entries that differ."""
    with zipfile.ZipFile(pa) as za, zipfile.ZipFile(pb) as zb:
        na = [i.filename for i in za.infolist()]
        nb = [i.filename for i in zb.infolist()]
        only_a = [n for n in na if n not in set(nb)]
        only_b = [n for n in nb if n not in set(na)]
        for n in only_a:
            print(f"  only in {pa}: {n}")
        for n in only_b:
            print(f"  only in {pb}: {n}")
        if na != nb and not only_a and not only_b:
            print("  entry ORDER differs (same names) — the zip was written "
                  "in a different sequence")
        ia = {i.filename: i for i in za.infolist()}
        ib = {i.filename: i for i in zb.infolist()}
        bad = len(only_a) + len(only_b)
        for n in na:
            if n not in ib:
                continue
            reasons = []
            if ia[n].date_time != ib[n].date_time:
                reasons.append(f"timestamp {ia[n].date_time} vs {ib[n].date_time}")
            if ia[n].CRC != ib[n].CRC:
                reasons.append(f"crc {ia[n].CRC:08x} vs {ib[n].CRC:08x}")
            if za.read(n) != zb.read(n):
                reasons.append("content")
            if reasons:
                bad += 1
                print(f"  differs: {n} ({', '.join(reasons)})")
        return bad


def main(argv) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    flags = {a for a in argv[1:] if a.startswith("--")}
    ignore_sig = "--ignore-signing-block" in flags
    if len(args) != 2 or flags - {"--ignore-signing-block"}:
        print(__doc__)
        return 2
    pa, pb = args[0], args[1]
    try:
        a = open(pa, "rb").read()
        b = open(pb, "rb").read()
    except OSError as e:
        print(f"cannot read: {e}")
        return 2

    print(f"{pa}: {len(a):,} bytes  sha256 {sha256(a)}")
    print(f"{pb}: {len(b):,} bytes  sha256 {sha256(b)}")

    if a == b:
        print("\nIDENTICAL — byte for byte, signature included.")
        return 0

    print("\nDIFFERENT. What follows is where.\n")
    if len(a) != len(b):
        print(f"Sizes differ by {abs(len(a) - len(b)):,} bytes.\n")

    runs = differing_runs(a, b)
    total = sum(j - i for i, j in runs)
    print(f"{len(runs)} differing run(s), {total:,} bytes in total.")

    sa, sb = signing_block(a), signing_block(b)
    if sa and sb:
        lo = min(r[0] for r in runs)
        hi = max(r[1] for r in runs)
        inside = sa[0] <= lo and hi <= sa[1]
        print(f"APK signing block: bytes {sa[0]:,}..{sa[1]:,}")
        print("All differences are inside the signing block."
              if inside else
              "Differences reach OUTSIDE the signing block — the app content "
              "itself is not reproducible.")
        if ignore_sig and inside:
            print("\nThe app is IDENTICAL; only the signature differs, which "
                  "--ignore-signing-block was asked to allow.")
            return 0
        print("\nSigning block, pair by pair:")
        pairs_a = list(walk_pairs(a, *sa))
        pairs_b = {pid: (off, ln) for pid, off, ln in walk_pairs(b, *sb)}
        for pid, off, ln in pairs_a:
            name = BLOCK_IDS.get(pid, f"unknown 0x{pid:08x}")
            if pid not in pairs_b:
                print(f"  {name}: present here, absent there")
                continue
            off_b, ln_b = pairs_b[pid]
            same = a[off : off + 8 + ln] == b[off_b : off_b + 8 + ln_b]
            print(f"  {name}: {ln:,} bytes, "
                  f"{'identical' if same else 'DIFFERS'}")
        print()

    if not sa or not sb or not (sa[0] <= min(r[0] for r in runs)
                                and max(r[1] for r in runs) <= sa[1]):
        print("Per-entry comparison:")
        n = compare_entries(pa, pb)
        if n == 0:
            print("  every entry is identical — the difference is in the zip "
                  "container itself (ordering, alignment or extra fields)")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
