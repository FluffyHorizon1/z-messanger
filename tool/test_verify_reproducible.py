#!/usr/bin/env python3
"""Tests for tool/verify_reproducible.py.

The interesting one is `--content-digest`, whose entire reason to exist is a
claim that is easy to state and easy to get wrong: *signing an APK does not
change its content digest*. If that is false the number published with a
release is useless, and worse than useless, because a verifier would read a
mismatch as tampering.

So it is tested by actually signing — inserting a real APK signing block into
a zip the way apksigner does, between the last local entry and the central
directory, with the offsets rewritten — and checking the digest does not move.

    python3 tool/test_verify_reproducible.py
"""

import hashlib
import io
import os
import struct
import sys
import tempfile
import zipfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verify_reproducible import content_digest, signing_block  # noqa: E402

APK_SIG_MAGIC = b"APK Sig Block 42"


def make_zip(path, entries):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            z.writestr(name, data)


def insert_signing_block(path, out, payload=b"\x01" * 1024):
    """Insert an APK signing block, as apksigner does.

    Layout: uint64 size | pairs | uint64 size | 16-byte magic, where the size
    counts everything after the leading field. It goes immediately before the
    central directory, and the EOCD's central-directory offset moves by the
    length inserted.
    """
    data = bytearray(open(path, "rb").read())

    eocd = data.rfind(b"PK\x05\x06")
    assert eocd != -1, "no EOCD"
    cd_off = struct.unpack("<I", data[eocd + 16 : eocd + 20])[0]

    pair = struct.pack("<Q", 4 + len(payload)) + struct.pack("<I", 0x7109871A) + payload
    size = len(pair) + 8 + 16          # pairs + trailing size + magic
    block = struct.pack("<Q", size) + pair + struct.pack("<Q", size) + APK_SIG_MAGIC

    data[cd_off:cd_off] = block
    struct.pack_into("<I", data, eocd + len(block) + 16, cd_off + len(block))
    open(out, "wb").write(bytes(data))


def main():
    failures = []

    def check(name, cond, detail=""):
        print(f"  {'ok  ' if cond else 'FAIL'}  {name}")
        if not cond:
            failures.append(f"{name}{': ' + detail if detail else ''}")

    with tempfile.TemporaryDirectory() as d:
        plain = os.path.join(d, "app.apk")
        signed = os.path.join(d, "app-signed.apk")
        other = os.path.join(d, "other.apk")

        entries = [
            ("AndroidManifest.xml", b"<manifest/>"),
            ("classes.dex", b"dex\n" + b"A" * 5000),
            ("lib/arm64-v8a/libapp.so", b"ELF" + b"B" * 20000),
        ]
        make_zip(plain, entries)
        insert_signing_block(plain, signed)

        # The premise: these really are different files.
        raw_plain = open(plain, "rb").read()
        raw_signed = open(signed, "rb").read()
        check("signing changes the file", raw_plain != raw_signed)
        check("the signed file has a signing block", signing_block(raw_signed) is not None)
        check("the unsigned file does not", signing_block(raw_plain) is None)
        check("zipfile can still read the signed archive",
              [i.filename for i in zipfile.ZipFile(signed).infolist()]
              == [n for n, _ in entries])

        # The claim.
        check("signing does NOT change the content digest",
              content_digest(plain) == content_digest(signed),
              f"{content_digest(plain)[:16]} vs {content_digest(signed)[:16]}")

        # It would be a poor digest if it never changed. One byte of one entry:
        changed = [(n, (v + b"!") if n == "classes.dex" else v) for n, v in entries]
        make_zip(other, changed)
        check("a changed entry DOES change it",
              content_digest(plain) != content_digest(other))

        # Order is part of what reproducibility means.
        make_zip(other, list(reversed(entries)))
        check("reordering entries DOES change it",
              content_digest(plain) != content_digest(other))

        # A renamed entry with identical bytes must not collide — this is why
        # the name is length-prefixed rather than concatenated.
        make_zip(other, [("AndroidManifest.xm", b"l<manifest/>")] + entries[1:])
        check("a shifted name/content boundary does NOT collide",
              content_digest(plain) != content_digest(other))

        # The mirror image: two entries folded into one whose bytes are the
        # first entry's content followed by what the second entry contributes
        # to the stream. Without a content length the stream would read the
        # same either way and only the CRC would tell them apart.
        a, b = entries[0], entries[1]
        folded = (a[1] + struct.pack("<I", len(b[0])) + b[0].encode()
                  + struct.pack("<IIQ", zipfile.ZIP_DEFLATED,
                                zlib.crc32(b[1]), len(b[1])) + b[1])
        make_zip(other, [(a[0], folded)] + entries[2:])
        check("folding two entries into one does NOT collide",
              content_digest(plain) != content_digest(other))

        # Compression method is part of the build's output.
        with zipfile.ZipFile(other, "w", zipfile.ZIP_STORED) as z:
            for n, v in entries:
                z.writestr(n, v)
        check("a different compression method DOES change it",
              content_digest(plain) != content_digest(other))

        # Stability: same input, same answer.
        check("the digest is stable across runs",
              content_digest(plain) == content_digest(plain))

    print()
    if failures:
        print(f"{len(failures)} failure(s):")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("all content-digest properties hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
