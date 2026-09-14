#!/usr/bin/env python3
"""Check that every CI job which uses a repository file actually checks one out.

Written the day a tagged release failed on:

    python3: can't open file '.../release/../tool/verify_reproducible.py'

The `release` job had always been pure downloads and uploads, so it had no
`actions/checkout`. Adding one step that ran a script from `tool/` was enough
to break it, and nothing said so until a tag was pushed — the most expensive
moment to find out, because the version number is already spent.

Two rules, both mechanical:

  1. A job whose `run:` steps reference a tracked directory must contain an
     `actions/checkout` step.
  2. That checkout must come BEFORE any `download-artifact`, because checkout
     cleans the workspace before writing and would delete what was downloaded.
     This one is not hypothetical either: it is the order the fix had to use.

  3. A job that PUBLISHES — creates a release, or attests provenance — must
     download artifacts by name. An unnamed `download-artifact` takes every
     artifact of the run, so anything any job uploads becomes a release asset
     unless somebody remembers to add it to a deny-list. Nobody did for the
     README screenshots, and twelve releases shipped them.

  4. A third-party action — anything not under `actions/` — is pinned to a
     40-character commit SHA, not to a tag. A tag is a pointer its owner can
     move: whoever controls `v2` controls what runs here. That mattered most
     in `release`, which holds `contents: write`, `id-token: write` and
     `attestations: write` — a token that can publish a release and mint a
     Sigstore attestation saying this repository produced bytes it did not.
     The version stays beside the pin as a comment, because a SHA alone tells
     a reader nothing about what it is.

  5. The workflow declares top-level `permissions`. Without one every job
     gets the repository's default token, including the job that runs
     `npm install`, `dart pub get`, `flutter pub get` and three
     `pip install`s — install-time code from third-party registries, holding
     a token it has no use for.

None of these rules is clever. All are the kind of thing a person is certain
they will remember and then does not.
"""

import re
import sys
from pathlib import Path

SHA40 = re.compile(r"[0-9a-f]{40}")

try:
    import yaml
except ImportError:
    # Not a skip. A check that goes green when its dependency is missing is
    # a check that reports on nothing, and this one is read as evidence:
    # `audit_verify.sh` prints "Every suite passed" with it in the list, and
    # CI shows a tick. Until 2026-09-14 all three of the YAML-reading guards
    # did exactly that, and the workflow never installed PyYAML — it relied
    # on the runner image happening to ship it, which is a dependency nobody
    # declared and nobody would notice losing.
    print(
        "PyYAML is not installed, so this cannot check every CI job that uses repo files checks one out.\n"
        "Install it (python3 -m pip install PyYAML) — a green run without it "
        "would mean nothing.",
        file=sys.stderr,
    )
    sys.exit(1)

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"

# Top-level directories that only exist if the repository is checked out.
TRACKED = ("tool/", "docs/", "protocol/", "app/", "server/", "scripts/", "kt/")

# Actions whose presence makes a job a publishing job: what it downloads,
# other people receive.
PUBLISHERS = ("softprops/action-gh-release", "actions/attest-build-provenance")


def uses_repo_files(step) -> str | None:
    """The first tracked path a step's script mentions, if any."""
    run = step.get("run")
    if not isinstance(run, str):
        return None
    for line in run.splitlines():
        line = line.strip()
        if line.startswith("#"):
            continue
        for d in TRACKED:
            # Match the directory as a path component: `tool/x`, `../tool/x`,
            # `$GITHUB_WORKSPACE/tool/x`. Not `mytool/`.
            if re.search(rf"(?:^|[\s/'\"=]){re.escape(d)}", line):
                return d
    return None


def main() -> int:
    problems = []
    checked = 0

    for wf in sorted(WORKFLOWS.glob("*.y*ml")):
        doc = yaml.safe_load(wf.read_text())
        # Rule 5: a default that is never written down is the one that is
        # wrong when nobody is looking.
        top = doc.get("permissions")
        if top is None:
            problems.append(
                f"{wf.name}: no top-level `permissions:`, so every job runs "
                f"with the repository's default token — including the one "
                f"that installs packages from four registries. Declare the "
                f"least it needs (`contents: read`) and let a job that needs "
                f"more say so itself."
            )
        for job_name, job in (doc.get("jobs") or {}).items():
            steps = job.get("steps") or []
            checked += 1

            checkout_at = next(
                (i for i, s in enumerate(steps)
                 if isinstance(s.get("uses"), str)
                 and s["uses"].startswith("actions/checkout")),
                None,
            )
            download_at = next(
                (i for i, s in enumerate(steps)
                 if isinstance(s.get("uses"), str)
                 and s["uses"].startswith("actions/download-artifact")),
                None,
            )

            needs = next(
                ((i, d) for i, s in enumerate(steps)
                 if (d := uses_repo_files(s))),
                None,
            )

            if needs and checkout_at is None:
                i, d = needs
                name = steps[i].get("name") or f"step {i}"
                problems.append(
                    f"{wf.name}: job `{job_name}` runs `{name}`, which uses "
                    f"`{d}` — but the job never checks the repository out. It "
                    f"will fail with 'No such file', and if the job only runs "
                    f"on a tag, it will fail there."
                )
            elif needs and checkout_at is not None and needs[0] < checkout_at:
                problems.append(
                    f"{wf.name}: job `{job_name}` uses `{needs[1]}` before its "
                    f"checkout step."
                )

            if checkout_at is not None and download_at is not None \
                    and download_at < checkout_at:
                problems.append(
                    f"{wf.name}: job `{job_name}` downloads artifacts before "
                    f"checking out. `actions/checkout` cleans the workspace "
                    f"first, so it deletes what was just downloaded."
                )

            for i, s in enumerate(steps):
                uses = s.get("uses")
                if not isinstance(uses, str) or uses.startswith("actions/"):
                    continue
                ref = uses.split("@", 1)[1] if "@" in uses else ""
                if not SHA40.fullmatch(ref):
                    problems.append(
                        f"{wf.name}: job `{job_name}` step {i} uses "
                        f"`{uses}`, which is not pinned to a commit. A tag is "
                        f"a pointer its owner can move, so whoever controls "
                        f"`{ref or 'that ref'}` controls what runs here — and "
                        f"in a publishing job that is a token which can cut a "
                        f"release. Pin the 40-hex commit and keep the version "
                        f"as a trailing comment."
                    )

            publishes = any(
                isinstance(s.get("uses"), str) and s["uses"].startswith(PUBLISHERS)
                for s in steps)
            if publishes:
                for i, s in enumerate(steps):
                    uses = s.get("uses")
                    if not (isinstance(uses, str)
                            and uses.startswith("actions/download-artifact")):
                        continue
                    w = s.get("with") or {}
                    if not (w.get("name") or w.get("pattern")):
                        problems.append(
                            f"{wf.name}: job `{job_name}` publishes, but step "
                            f"{i} downloads artifacts without a `name` or "
                            f"`pattern`. That takes EVERY artifact of the run, "
                            f"so whatever any job uploads becomes a release "
                            f"asset. Name what the release consists of."
                        )

    print(f"jobs checked: {checked}")
    if problems:
        print(f"\n{len(problems)} problem(s):\n")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("every job that uses repository files checks one out, in the right order; "
          "publishing jobs name what they download.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
