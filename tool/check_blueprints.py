#!/usr/bin/env python3
"""Every render*.yaml at the repository root describes a live system, and a
Blueprint is applied by clicking, not by review. This holds each one to the
handful of properties a wrong click cannot undo:

  * no literal secret — a key marked as one (KT_SEED, KT_WITNESS_SEED,
    FCM_SERVICE_ACCOUNT, anything ending in _SEED/_KEY/_SECRET/_TOKEN) is
    `sync: false` (set in the dashboard) or `generateValue: true`, never a
    `value:` in a file that lives in a public repository;
  * a web service has a health check path, and it is one the service answers;
  * a service with a persistent disk mounts it where its data variable
    points (KT_DATA or KT_MIRROR_DIR), runs one instance, and is on a paid
    plan — a free instance cannot carry a disk, and the Blueprint would be
    refused at creation with a message about the plan rather than the disk;
  * the Dockerfile it names exists, and a dockerCommand names a file that
    exists in that context;
  * the three values YAML 1.1 reads as booleans when bare — off, on, yes,
    no — are quoted wherever Render expects a string (autoDeployTrigger,
    persistenceMode), because a bare `off` arrives as `false` and the
    service auto-deploys on every push to main.

Written with render.kt.yaml and render.kt-witness.yaml, when a log with a
signing key joined the relay in the set of things a Blueprint can create.

Which Blueprints, and where, is not left to a glob. The first version matched
`render*.yaml` at the repository root and only there, and zero matches exited
0 — so renaming the four to `.yml` reported `blueprints checked: 0` and
success, and the likelier case, moving `render.kt-witness.yaml` under
`deploy/` because SELF_HOSTING tells operators to type the Blueprint Path by
hand, would have left `KT_WITNESS_SEED: value: <literal>` in a public file
with the guard reporting `blueprints checked: 3` and exit 0. Keeping a secret
out of a public file is the one thing this script exists for. So the four
Blueprints the documents point people at are NAMED here, found wherever
they are, and missing is a failure; anything else that looks like a
Blueprint is checked too.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

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
        "PyYAML is not installed, so this cannot check every Blueprint keeps its secrets out of the file.\n"
        "Install it (python3 -m pip install PyYAML) — a green run without it "
        "would mean nothing.",
        file=sys.stderr,
    )
    sys.exit(1)

ROOT = Path(__file__).resolve().parent.parent

SECRET_KEY = re.compile(r"(_SEED|_KEY|_SECRET|_TOKEN|_PASSWORD|SERVICE_ACCOUNT)$")
# Keys that end like a secret and are not one: a public key is a pin, not a
# secret, and it is still kept out of the file (sync: false) for a different
# reason — entering it is the act of pinning — so it need not be listed here.
NOT_SECRET = set()
DATA_VARS = ("KT_DATA", "KT_MIRROR_DIR")
BOOL_TRAPS = ("autoDeployTrigger", "persistenceMode")
FREE_PLANS = ("free",)
HEALTH_PATHS = {"/health"}


def raw_value(text: str, key: str) -> list[str]:
    """The bare text after `key:` on each line that sets it (to see quoting)."""
    return [m.group(1).strip() for m in re.finditer(rf"^\s*{key}:\s*(.*?)\s*(#.*)?$", text, re.M)]


def check(path: Path) -> list[str]:
    problems: list[str] = []
    text = path.read_text()
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:  # pragma: no cover - a broken file is the finding
        return [f"{path.name}: does not parse: {e}"]
    if not isinstance(doc, dict) or not isinstance(doc.get("services"), list):
        return [f"{path.name}: no `services:` list"]

    for key in BOOL_TRAPS:
        for v in raw_value(text, key):
            if v.lower() in ("off", "on", "yes", "no"):
                problems.append(
                    f"{path.name}: `{key}: {v}` is unquoted; YAML 1.1 reads it as a "
                    f"boolean, and Render then sees `{str(v.lower() in ('on', 'yes')).lower()}` "
                    f"rather than the word. Quote it."
                )

    for svc in doc["services"]:
        name = svc.get("name", "?")
        where = f"{path.name}: service `{name}`"
        env = svc.get("envVars") or []
        for e in env:
            key = str(e.get("key", ""))
            if SECRET_KEY.search(key) and key not in NOT_SECRET and "value" in e:
                problems.append(
                    f"{where}: `{key}` has a literal value. A secret goes in the "
                    f"dashboard (`sync: false`) or is generated there "
                    f"(`generateValue: true`); this file is public."
                )
        if svc.get("type") == "web":
            hc = svc.get("healthCheckPath")
            if not hc:
                problems.append(f"{where}: a web service needs `healthCheckPath`.")
            elif hc not in HEALTH_PATHS:
                problems.append(f"{where}: `healthCheckPath: {hc}` is not a path the services answer ({', '.join(sorted(HEALTH_PATHS))}).")
        disk = svc.get("disk")
        if disk:
            mount = disk.get("mountPath")
            pointed = {str(e.get("value")) for e in env if e.get("key") in DATA_VARS and "value" in e}
            if not mount:
                problems.append(f"{where}: `disk` has no `mountPath`.")
            elif not pointed:
                problems.append(f"{where}: has a disk at `{mount}` but no {' or '.join(DATA_VARS)} pointing at it.")
            elif mount not in pointed:
                problems.append(f"{where}: disk mounted at `{mount}` but the data variable says {sorted(pointed)}.")
            if str(svc.get("plan", "free")).lower() in FREE_PLANS:
                problems.append(f"{where}: a disk needs a paid plan; `plan: {svc.get('plan', 'free')}` cannot carry one.")
            if int(svc.get("numInstances", 1) or 1) != 1:
                problems.append(f"{where}: a service with a disk runs one instance; `numInstances` says {svc.get('numInstances')}.")
        df = svc.get("dockerfilePath")
        if df:
            if not (ROOT / df).exists():
                problems.append(f"{where}: `dockerfilePath: {df}` does not exist.")
            ctx = ROOT / (svc.get("dockerContext") or ".")
            cmd = svc.get("dockerCommand")
            if cmd:
                parts = str(cmd).split()
                script = next((p for p in parts if p.endswith(".js") or p.endswith(".sh")), None)
                if script and not (ctx / script).exists():
                    problems.append(f"{where}: `dockerCommand` names `{script}`, which is not in `{svc.get('dockerContext') or '.'}`.")
    return problems


# The Blueprints SELF_HOSTING.md tells people to create. A rename or a move
# does not take one out of this check; deleting one is a finding.
EXPECTED = ("render.yaml", "render.ha.yaml", "render.kt.yaml", "render.kt-witness.yaml")

# Directories that are not the repository's own files.
PRUNE = {"node_modules", ".git", "build", ".dart_tool", ".gradle", "Pods"}


def blueprints() -> list[Path]:
    """Every render*.yaml or .yml under the repository, wherever it sits."""
    out = []
    for f in ROOT.rglob("render*.y*ml"):
        if any(part in PRUNE for part in f.relative_to(ROOT).parts):
            continue
        out.append(f)
    return sorted(out)


def main() -> int:
    files = blueprints()
    problems: list[str] = []
    stems = {f.name: f for f in files}
    for name in EXPECTED:
        # Found by name with either extension, anywhere.
        alt = name[:-len(".yaml")] + ".yml"
        if name not in stems and alt not in stems:
            problems.append(
                f"{name} is not anywhere in the repository. SELF_HOSTING.md "
                f"points operators at it; if it moved, it was found wherever "
                f"it went, so this means it is gone."
            )
    for f in files:
        problems.extend(check(f))
    print(f"blueprints checked: {len(files)}")
    if not files:
        # Unreachable while EXPECTED holds, and kept anyway: a floor that
        # depends on another check is a floor that goes when it does.
        problems.append("no Blueprints found at all; the check ran over nothing.")
    if problems:
        print(f"\n{len(problems)} problem(s):\n")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("every Blueprint keeps its secrets out of the file, checks its health, and mounts its disk where its data lives.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
