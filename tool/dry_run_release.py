#!/usr/bin/env python3
"""Run the release job's shell, here, against a staged release.

`AUDIT_SCOPE.md` C26 says the attestation path "has still never executed", and
that is true of more than the attestation: the three `run:` steps before it —
collecting the artefacts, computing the content digest, and comparing that
digest against an independently signed build — are reachable only from a
pushed tag, so the first time they run is the moment a version number has
already been spent. That job has failed on its first tagged build once
already (a missing `actions/checkout`, two steps before it would have attested
anything), and `tool/check_workflow.py` exists because of it.

This runs the same shell. It reads the step bodies OUT OF THE WORKFLOW rather
than restating them, so there is one copy and a drift between the two is not
possible; it stages a workspace shaped like the one a tagged run produces; and
it checks what comes out. Four passes:

  1. a normal release — every artefact present, the reproducibility slot
     matching;
  2. a slot that does NOT match — the step must report it, write the
     disagreement into SHA256SUMS.txt, and still succeed, because that is a
     finding to publish rather than a reason to withhold a release;
  3. no APK — the step must refuse, loudly, rather than publish a release
     with no number an outside rebuild can check;
  4. two embedded build paths in libapp.so — the step must refuse rather than
     pick one and state a recipe that does not reproduce;
  5. two artefacts sharing a basename — the copy into `release/` flattens, so
     a collision would silently publish one of them and list it as though
     nothing had been lost.

What it does NOT do is attest anything: Sigstore needs a real OIDC token from
a real runner, so `actions/attest-build-provenance` remains the one step only
a tag can exercise. Everything it depends on now runs here.

Usage:  python3 tool/dry_run_release.py [-v]
Exit:   0 all passes behaved; 1 otherwise.
"""

import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML not installed; skipping release dry run")
    sys.exit(0)

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "build.yml"
CHECKOUT = "/home/runner/work/z-messanger/z-messanger"
BUILD_URI = f"file://{CHECKOUT}/app/.dart_tool/flutter_build/dart_plugin_registrant.dart"

VERBOSE = "-v" in sys.argv[1:]


def steps():
    """The release job's `run:` bodies, in order, from the workflow itself."""
    job = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["release"]
    out = [(s.get("name", f"step {i}"), s["run"])
           for i, s in enumerate(job["steps"]) if "run" in s]
    if not out:
        raise SystemExit("the release job has no run: steps — has it been rewritten?")
    for name, body in out:
        if "${{" in body:
            raise SystemExit(
                f"step {name!r} interpolates a workflow expression; this dry run "
                f"executes the body verbatim and cannot stand in for it")
    return out


def fake_so(uris) -> bytes:
    """An ELF-ish blob carrying [uris] where the Dart snapshot carries its own.

    `strings -a` is what the workflow reads it with, and `strings` does not
    care whether the file is an ELF — but writing a real ELF header keeps
    `readelf` (used by the reproducible job on the same artefact) from
    complaining if this fixture is ever reused there.
    """
    header = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + struct.pack("<HH", 3, 183)
    body = b"".join(b"\x00" + u.encode() + b"\x00" for u in uris)
    return header + b"\x00" * 32 + b"some unrelated strings here\x00" + body


def make_apk(path: Path, uris=(BUILD_URI,), extra=b"") -> None:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", "<manifest/>")
        z.writestr("classes.dex", "dex" + "x" * 512)
        z.writestr("lib/arm64-v8a/libapp.so", fake_so(uris))
        z.writestr("lib/arm64-v8a/libflutter.so", b"flutter" + b"y" * 256)
        if extra:
            z.writestr("extra", extra)


APK_SIG_MAGIC = b"APK Sig Block 42"


def sign(src: Path, dst: Path, payload=b"\x01" * 1024) -> None:
    """Insert an APK signing block, as apksigner does.

    uint64 size | pairs | uint64 size | 16-byte magic, immediately before the
    central directory, with the EOCD's central-directory offset moved by the
    length inserted — the same fixture `tool/test_verify_reproducible.py`
    uses, because an archive whose EOCD offset was not corrected is one no
    zip reader will open, which is a different test from this one.
    """
    data = bytearray(src.read_bytes())
    eocd = data.rfind(b"PK\x05\x06")
    if eocd == -1:
        raise SystemExit("fixture has no EOCD")
    cd_off = struct.unpack("<I", data[eocd + 16:eocd + 20])[0]
    pair = struct.pack("<Q", 4 + len(payload)) + struct.pack("<I", 0x7109871A) + payload
    size = len(pair) + 8 + 16
    block = struct.pack("<Q", size) + pair + struct.pack("<Q", size) + APK_SIG_MAGIC
    data[cd_off:cd_off] = block
    struct.pack_into("<I", data, eocd + len(block) + 16, cd_off + len(block))
    dst.write_bytes(bytes(data))


def stage(tmp: Path, *, with_apk=True, uris=(BUILD_URI,), slot_matches=True,
          collide=False) -> Path:
    ws = tmp / "ws"
    if ws.exists():
        shutil.rmtree(ws)
    (ws / "dist").mkdir(parents=True)
    # `actions/checkout` with sparse-checkout: tool
    (ws / "tool").mkdir()
    for f in ("verify_reproducible.py",):
        shutil.copy(ROOT / "tool" / f, ws / "tool" / f)

    (ws / "dist" / "z-android").mkdir()
    if with_apk:
        make_apk(ws / "dist" / "z-android" / "unsigned.apk", uris=uris)
        sign(ws / "dist" / "z-android" / "unsigned.apk",
             ws / "dist" / "z-android" / "app-release.apk")
        (ws / "dist" / "z-android" / "unsigned.apk").unlink()
    (ws / "dist" / "z-android" / "app-release.aab").write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    for name, asset in (("z-linux-x64", "z-linux-x64.tar.gz"),
                        ("z-windows-x64", "z-windows-x64.zip"),
                        ("z-macos", "z-macos.zip")):
        (ws / "dist" / name).mkdir()
        (ws / "dist" / name / asset).write_bytes(name.encode() * 64)
    if collide:
        # Two platforms shipping a file of the same name, from different
        # trees — one `flutter build apk --split-per-abi` away from real.
        (ws / "dist" / "z-macos" / "z-linux-x64.tar.gz").write_bytes(b"not the same file")

    # The reproducibility slot: the same commit, debug-signed, so its ENTRIES
    # match the release APK's and its bytes do not.
    (ws / "repro-a").mkdir()
    if with_apk:
        make_apk(ws / "repro-a" / "plain.apk", uris=uris,
                 extra=b"" if slot_matches else b"a different build")
        # A different (debug) key means a different signing block and so a
        # different file hash — with identical zip entries when the build
        # matched, which is the whole question the comparison asks.
        sign(ws / "repro-a" / "plain.apk", ws / "repro-a" / "app-release.apk",
             payload=b"\x02" * 768)
        (ws / "repro-a" / "plain.apk").unlink()
    (ws / "repro-a" / "fingerprint-a.txt").write_text("libapp.so deadbeef\n")
    return ws


def run(ws: Path, name: str, body: str, out_file: Path):
    env = dict(os.environ, GITHUB_OUTPUT=str(out_file), GITHUB_WORKSPACE=str(ws))
    p = subprocess.run(["bash", "-e", "-o", "pipefail", "-c", body],
                       cwd=ws, env=env, capture_output=True, text=True)
    if VERBOSE:
        print(f"--- {name} (exit {p.returncode})\n{p.stdout}{p.stderr}")
    return p


def check(results, label, ok, detail=""):
    results.append((label, ok, detail))
    print(f"  {'pass' if ok else 'FAIL'}  {label}" + (f"  — {detail}" if detail and not ok else ""))


def main() -> int:
    bodies = steps()
    print(f"release job: {len(bodies)} run steps, read from "
          f"{WORKFLOW.relative_to(ROOT)}")
    results = []
    with tempfile.TemporaryDirectory(prefix="z-dry-release-") as td:
        tmp = Path(td)
        out_file = tmp / "gh_output"

        # 1. A normal release.
        print("\n1. a normal release")
        ws = stage(tmp)
        out_file.write_text("")
        failed = None
        for name, body in bodies:
            p = run(ws, name, body, out_file)
            if p.returncode != 0:
                failed = (name, p.stdout + p.stderr)
                break
        check(results, "every step succeeds", failed is None,
              f"{failed[0]} exited non-zero: {failed[1][-400:]}" if failed else "")
        if failed is None:
            sums = (ws / "release" / "SHA256SUMS.txt").read_text()
            for asset in ("app-release.apk", "z-linux-x64.tar.gz",
                          "z-windows-x64.zip", "z-macos.zip"):
                check(results, f"SHA256SUMS lists {asset}", asset in sums)
            check(results, "a content digest is published",
                  "# Content digest of app-release.apk: " in sums)
            check(results, "the recipe names the path the bytes were built at",
                  CHECKOUT in sums, sums)
            check(results, "and says the digest was reproduced independently",
                  "Reproduced independently before publishing: yes" in sums, sums)
            check(results, "the step reports it to the workflow too",
                  "reproduced=yes" in out_file.read_text())
            check(results, "no reproducibility slot became a release asset",
                  not list((ws / "release").glob("fingerprint-*")))

        # 2. A slot that disagrees: reported, published, not fatal.
        print("\n2. the reproducibility slot disagrees")
        ws = stage(tmp, slot_matches=False)
        out_file.write_text("")
        codes = [run(ws, n, b, out_file).returncode for n, b in bodies]
        check(results, "the release is still produced", all(c == 0 for c in codes),
              f"exit codes {codes}")
        if all(c == 0 for c in codes):
            sums = (ws / "release" / "SHA256SUMS.txt").read_text()
            check(results, "and says so, in the file people read",
                  "Reproduced independently before publishing: NO" in sums, sums)
            check(results, "and in the workflow output",
                  "reproduced=no" in out_file.read_text())

        # 3. No APK: refuse rather than publish a number nobody can check.
        #
        # Asserted against the DIGEST step by name, not against "some step
        # failed": with a silent skip restored there, the step after it dies
        # on the same missing file, and "some step failed" would call that a
        # pass while the release published without the one number an outside
        # rebuild can check.
        print("\n3. the APK is missing")
        ws = stage(tmp, with_apk=False)
        out_file.write_text("")
        run(ws, *bodies[0], out_file)  # the other artefacts still collect
        digest = run(ws, *bodies[1], out_file)
        check(results, "the digest step itself refuses", digest.returncode != 0,
              f"exit {digest.returncode}")
        check(results, "and says why, rather than skipping quietly",
              "refusing to publish" in (digest.stdout + digest.stderr),
              digest.stdout + digest.stderr)

        # 4. Two embedded build paths: refuse rather than state a recipe that
        #    does not reproduce.
        print("\n4. libapp.so carries two build paths")
        ws = stage(tmp, uris=(BUILD_URI, BUILD_URI.replace("/z-messanger/z", "/z-messanger/y")))
        out_file.write_text("")
        run(ws, *bodies[0], out_file)
        digest = run(ws, *bodies[1], out_file)
        check(results, "the digest step refuses", digest.returncode != 0,
              f"exit {digest.returncode}")
        check(results, "and prints the paths it found",
              "expected exactly one embedded build URI"
              in (digest.stdout + digest.stderr), digest.stdout + digest.stderr)

        # 5. A basename collision: refuse rather than publish one of them.
        print("\n5. two artefacts share a name")
        ws = stage(tmp, collide=True)
        out_file.write_text("")
        first = run(ws, *bodies[0], out_file)
        check(results, "the collect step refuses", first.returncode != 0,
              first.stdout + first.stderr)
        check(results, "and names them rather than publishing one of them",
              "share a name and would collapse" in (first.stdout + first.stderr)
              and "z-linux-x64.tar.gz" in (first.stdout + first.stderr),
              first.stdout + first.stderr)

    bad = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(bad)}/{len(results)} checks passed")
    if bad:
        print("the release job's shell does not behave as the release "
              "documents say it does:")
        for label, _, detail in bad:
            print(f"  - {label}: {detail[:600]}")
        return 1
    print("the release job's shell behaves as PROVENANCE.md describes, on a "
          "staged release. The attestation step itself still needs a real tag.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
