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

Neither rule is clever. Both are the kind of thing a person is certain they
will remember and then does not.
"""

import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML not installed; skipping workflow check")
    sys.exit(0)

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"

# Top-level directories that only exist if the repository is checked out.
TRACKED = ("tool/", "docs/", "protocol/", "app/", "server/", "scripts/")


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

    print(f"jobs checked: {checked}")
    if problems:
        print(f"\n{len(problems)} problem(s):\n")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("every job that uses repository files checks one out, in the right order.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
