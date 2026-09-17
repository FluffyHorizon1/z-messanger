#!/usr/bin/env python3
"""Does `release-verify` actually refuse the releases it was written for?

`tool/dry_run_release.py` rehearses the release job's shell. It cannot
rehearse this one: it reads `["jobs"]["release"]` and executes every `run:`
body it finds there, so a `gh` call placed in that job would be run by the
guard itself -- against this repository, on the day a token reached the test
job's environment. `release-verify` is a separate job for that reason, and
being a separate job put it outside the only rehearsal this workflow had.

Four tagged releases have now failed in the upload step, and the reason six
incomplete drafts accumulated unnoticed is that nothing ever asked whether
the release a job produced was the release it was for. A guard written for
that, and never itself exercised, would be the same mistake one level up.

So this pulls the step's shell OUT OF `build.yml` -- there is one copy, and
editing the workflow changes what is tested here -- stubs `gh` with fixtures
for a release's JSON, its asset list and its `SHA256SUMS.txt`, and runs the
real body under the real bash against the shapes that have actually
occurred, plus the ones that would make it lie:

  1. a complete release passes;
  2. v3.5.3's real asset table -- three of nine -- fails, naming every
     missing file rather than the first;
  3. an asset left in `starter` state fails, which is the case the action
     itself is blind to (it matches by name and never reads `state`);
  4. a zero-byte asset fails;
  5. a size that is not a number fails. This one is the reason the check
     exists in the shape it does: `[ "$size" -le 0 ]` on a non-numeric value
     is a bash syntax error, and a syntax error in an `elif` CONDITION is
     not something `set -e` catches -- the branch is false, the loop
     continues, and the step prints the all-clear over a release it could
     not read;
  6. a manifest with no digest lines fails on the count rather than looping
     over nothing and passing;
  7. a manifest that GREW fails too -- a release that gained an artefact
     nobody accounted for is as much a finding as one that lost a file;
  8. an asset whose name GitHub rewrote (a space becomes a dot, the original
     kept in `label`) is found, not reported missing. The action matches
     name, dotted name or label; a checker that compared `.name` alone would
     fail a release that is complete;
  9. a release that is already published when this runs fails, because then
     something published around the gate and the gate is decoration.

`jq` is not optional and a missing one is not a skip: every case below would
report "no release found" without it, which reads like a finding and is not.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML is not installed, so the step body could not be read out of "
          "build.yml and nothing below tested the shipped text.\n"
          "Install it (python3 -m pip install PyYAML).", file=sys.stderr)
    sys.exit(1)

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "build.yml"
JOB = "release-verify"
REPO = "FluffyHorizon1/z-messanger"
TAG = "v9.9.9"

ASSETS = [
    "app-arm64-v8a-release.apk", "app-armeabi-v7a-release.apk",
    "app-release.aab", "app-release.apk", "app-x86_64-release.apk",
    "z-linux-x64.tar.gz", "z-macos.zip", "z-windows-x64.zip",
]


def body() -> str:
    """The one `run:` body of the verify job, read from the workflow."""
    doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    job = doc["jobs"].get(JOB)
    if job is None:
        raise SystemExit(
            f"`{JOB}` is not a job in build.yml any more. If it was renamed, "
            f"rename it here; if it was folded into `release`, read "
            f"tool/dry_run_release.py's docstring first -- that job's `run:` "
            f"steps are executed by a guard that runs on every push.")
    runs = [s for s in job["steps"] if "run" in s]
    if len(runs) != 1:
        raise SystemExit(f"`{JOB}` has {len(runs)} run steps; this expects 1.")
    src = runs[0]["run"]
    if "${{" in src:
        raise SystemExit(
            f"`{JOB}`'s shell interpolates a workflow expression; this "
            f"rehearsal executes the body verbatim and cannot stand in for "
            f"it. Pass the value through `env:` instead.")
    return src


def manifest(names: list[str], trailer: bool = True) -> str:
    out = "".join(f"{i:064x}  {n}\n" for i, n in enumerate(names, 1))
    if trailer:
        out += ("# Content digest of app-release.apk: " + "0" * 64 + "\n"
                "#\n# Reproduced independently before publishing: yes\n")
    return out


def asset(name: str, *, state: str = "uploaded", size: int | str = 1024,
          label: str | None = None) -> dict:
    return {"id": abs(hash(name)) % 100000, "name": name, "label": label,
            "state": state, "size": size}


def stage(tmp: Path, *, present: list[dict], sums: str, draft: bool = True,
          have_release: bool = True) -> Path:
    """A fixture directory plus a `gh` on PATH that serves it."""
    ws = tmp / "ws"
    if ws.exists():
        shutil.rmtree(ws)
    (ws / "bin").mkdir(parents=True)
    fx = ws / "fx"
    fx.mkdir()
    sums_asset = asset("SHA256SUMS.txt", size=len(sums))
    assets = present + [sums_asset]
    (fx / "releases.json").write_text(json.dumps(
        [{"id": 4242, "tag_name": TAG, "draft": draft}] if have_release else []))
    (fx / "release.json").write_text(json.dumps(
        {"id": 4242, "tag_name": TAG, "draft": draft}))
    (fx / "assets.json").write_text(json.dumps(assets))
    (fx / "sums.txt").write_text(sums)
    (fx / "sums_id").write_text(str(sums_asset["id"]))

    gh = ws / "bin" / "gh"
    gh.write_text(f'''#!/usr/bin/env python3
import subprocess, sys
FX = {str(fx)!r}
a = sys.argv[1:]
if a and a[0] == "api":
    a = a[1:]
jqf = None
if "--jq" in a:
    i = a.index("--jq"); jqf = a[i + 1]; del a[i:i + 2]
a = [x for x in a if x not in ("--paginate",)]
while "-H" in a:
    i = a.index("-H"); del a[i:i + 2]
while "-X" in a:
    i = a.index("-X"); del a[i:i + 2]
path = a[0] if a else ""
if path.endswith("/releases?per_page=100"):
    src = FX + "/releases.json"
elif path.endswith("/assets"):
    src = FX + "/assets.json"
elif "/releases/assets/" in path:
    sys.stdout.write(open(FX + "/sums.txt").read()); sys.exit(0)
else:
    src = FX + "/release.json"
data = open(src).read()
if jqf:
    sys.exit(subprocess.run(["jq", "-r", jqf], input=data,
                            text=True).returncode)
sys.stdout.write(data)
''')
    gh.chmod(0o755)
    return ws


def run(ws: Path, src: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PATH"] = f"{ws / 'bin'}:{env['PATH']}"
    env["GITHUB_REPOSITORY"] = REPO
    env["GITHUB_REF_NAME"] = TAG
    env["GH_TOKEN"] = "not-a-token"
    return subprocess.run(["bash", "-c", src], cwd=ws, env=env,
                          capture_output=True, text=True)


def main() -> int:
    if shutil.which("jq") is None:
        print("jq is not installed. Every case below would fail for that "
              "reason and read like a finding, so this refuses rather than "
              "reporting on nothing.", file=sys.stderr)
        return 1
    src = body()
    results: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        results.append((name, ok, detail))

    full = [asset(n) for n in ASSETS]
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)

        r = run(stage(tmp, present=full, sums=manifest(ASSETS)), src)
        check("1. a complete draft passes", r.returncode == 0,
              (r.stdout + r.stderr)[-300:])
        check("   and says what it counted",
              "8 listed files" in r.stdout and "still a draft" in r.stdout,
              r.stdout[-200:])

        # v3.5.3 as it actually stands: three of nine.
        kept = ["app-arm64-v8a-release.apk", "app-x86_64-release.apk",
                "z-linux-x64.tar.gz"]
        r = run(stage(tmp, present=[asset(n) for n in kept],
                      sums=manifest(ASSETS)), src)
        gone = [n for n in ASSETS if n not in kept]
        check("2. v3.5.3's real asset table is refused", r.returncode != 0)
        check("   and every missing file is named, not just the first",
              all(f"MISSING  {n}" in r.stderr for n in gone),
              r.stderr[-400:])

        bad = [asset(n) for n in ASSETS]
        bad[3] = asset("app-release.apk", state="starter", size=0)
        r = run(stage(tmp, present=bad, sums=manifest(ASSETS)), src)
        check("3. an asset left in `starter` state is refused",
              r.returncode != 0 and "NOT UPLOADED" in r.stderr,
              r.stderr[-300:])

        bad = [asset(n) for n in ASSETS]
        bad[2] = asset("app-release.aab", size=0)
        r = run(stage(tmp, present=bad, sums=manifest(ASSETS)), src)
        check("4. a zero-byte asset is refused",
              r.returncode != 0 and "EMPTY" in r.stderr, r.stderr[-300:])

        for weird in (None, "not-a-number"):
            bad = [asset(n) for n in ASSETS]
            bad[2] = asset("app-release.aab", size=weird)
            r = run(stage(tmp, present=bad, sums=manifest(ASSETS)), src)
            check(f"5. a size of {weird!r} is refused, not stepped over",
                  r.returncode != 0 and "UNREADABLE SIZE" in r.stderr,
                  (r.stdout + r.stderr)[-300:])

        r = run(stage(tmp, present=full, sums="# nothing but a comment\n"), src)
        check("6. a manifest with no digest lines is refused",
              r.returncode != 0 and "lists 0 files" in r.stderr,
              r.stderr[-300:])

        grown = ASSETS + ["app-riscv64-release.apk"]
        r = run(stage(tmp, present=[asset(n) for n in grown],
                      sums=manifest(grown)), src)
        check("7. a manifest that grew is refused too",
              r.returncode != 0 and "lists 9 files" in r.stderr,
              r.stderr[-300:])

        # GitHub rewrites a space to a dot and keeps the original as `label`.
        spaced = [a for a in ASSETS if a != "z-macos.zip"] + ["z macos.zip"]
        present = [asset(n) for n in spaced if n != "z macos.zip"]
        present.append(asset("z.macos.zip", label="z macos.zip"))
        r = run(stage(tmp, present=present, sums=manifest(spaced)), src)
        check("8. a name GitHub rewrote is found, not reported missing",
              r.returncode == 0, (r.stdout + r.stderr)[-300:])

        r = run(stage(tmp, present=full, sums=manifest(ASSETS), draft=False),
                src)
        check("9. a release already published when this runs is refused",
              r.returncode != 0 and "nothing was gated" in r.stderr,
              r.stderr[-300:])

        r = run(stage(tmp, present=full, sums=manifest(ASSETS),
                      have_release=False), src)
        check("   and so is a tag with no release at all",
              r.returncode != 0 and "no release for" in r.stderr,
              r.stderr[-300:])

    bad = [r for r in results if not r[1]]
    for name, ok, detail in results:
        print(f"  {'pass' if ok else 'FAIL'}  {name}"
              + (f"\n        {detail}" if not ok and detail else ""))
    print(f"\n{len(results) - len(bad)}/{len(results)} checks passed")
    if bad:
        return 1
    print("release-verify refuses every release it was written to refuse, "
          "and passes the one it was not.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
