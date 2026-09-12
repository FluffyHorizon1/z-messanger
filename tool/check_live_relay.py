#!/usr/bin/env python3
"""Is the relay that is serving the one this checkout describes?

    python3 tool/check_live_relay.py https://zmessengers.com --blueprint render.ha.yaml

A landed `server/` change is not live until someone clicks Manual Deploy
(`render.ha.yaml` sets `autoDeployTrigger: "off"` on purpose — main moves many
times a day and a relay is a live system). That click is the one step in the
pipeline with no record, and it went un-noticed for four days across three
sessions: each of them worked out by hand, from a missing counter in
`/metrics`, that the deployed relay was still the cutover build and that six
releases of relay work were sitting on main unserved.

So this asks the two endpoints the relay already answers and compares what
comes back against THIS CHECKOUT, deriving what to expect from the code rather
than from a table of versions that would itself go stale:

  * every `z_*` metric `renderMetrics` emits UNCONDITIONALLY must appear in
    the live `/metrics` — one that does not is a counter this code has and the
    running process does not, which is exactly what "the deploy is behind"
    looks like from outside. Both sides are read from their `# TYPE` lines, so
    a histogram counts once rather than as its three sample series, and a
    gauge the code emits only in one mode (`z_queued_envelopes`, absent where
    instances share a store) is reported rather than demanded;
  * `/health` must answer ok;
  * with `--blueprint`, the `coordinator` must be the one that Blueprint
    configures (`render.ha.yaml` wires REDIS_URL, so a relay answering
    "memory" is not running it) and its `numInstances` is compared with what
    two calls see. Without the flag the two are printed and not asserted —
    the metric comparison above is the part that is true of ANY relay, and a
    self-hoster running one instance in RAM mode is not misconfigured;
  * two calls are made, so `instanceId` is sampled twice and reported: with
    several instances the ids may differ, and a single id is not a failure.

  * `presenceStale` must be present in Redis mode and zero, and `storage`
    must be `ram-only`, whatever Blueprint is or is not named.

Exit status is 0 when the live relay is at least this checkout, 1 when it is
behind or unhealthy, 2 when it could not be reached or the arguments are
wrong. Reading `/health` and
`/metrics` is a GET a builder may make; nothing here deploys, and nothing here
needs a credential.
"""
from __future__ import annotations

import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "server" / "server.js"
BLUEPRINT = ROOT / "render.ha.yaml"
TIMEOUT = 15


def emitted_metrics(src: str) -> tuple[list[str], list[str]]:
    """The metric names this checkout writes: (always, only-in-some-modes).

    A `# TYPE` push at the function's own indentation is unconditional; one
    indented further sits inside an `if` (today: `z_queued_envelopes`, which
    is omitted where no instance knows the total). Demanding a conditional
    metric of a live relay would make this cry wolf, which is worse than not
    checking at all.
    """
    always: set[str] = set()
    conditional: set[str] = set()
    for m in re.finditer(r"^(\s*)L\.push\('# TYPE (z_[a-z_]+) ", src, re.M):
        (conditional if len(m.group(1)) > 2 else always).add(m.group(2))
    return sorted(always), sorted(conditional - always)


def blueprint_expectations(text: str) -> dict[str, object]:
    """What the Blueprint says the deployment is. Deliberately shallow: the
    two facts that change what a healthy answer looks like."""
    out: dict[str, object] = {}
    if re.search(r"^\s*-\s*key:\s*REDIS_URL\s*$", text, re.M):
        out["coordinator"] = "redis"
    m = re.search(r"^\s*numInstances:\s*(\d+)\s*$", text, re.M)
    if m:
        out["instances"] = int(m.group(1))
    return out


def get(url: str) -> str:
    req = urllib.request.Request(url, headers={"user-agent": "z-check-live-relay"})
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=ssl.create_default_context()) as r:
        return r.read().decode("utf-8", "replace")


def main(argv: list[str]) -> int:
    args = argv[1:]
    blueprint: Path | None = None
    if "--blueprint" in args:
        i = args.index("--blueprint")
        if i + 1 >= len(args):
            print("--blueprint needs a path", file=sys.stderr)
            return 2
        blueprint = Path(args[i + 1])
        if not blueprint.is_absolute():
            blueprint = ROOT / blueprint
        if not blueprint.exists():
            print(f"{args[i + 1]}: no such Blueprint", file=sys.stderr)
            return 2
        del args[i : i + 2]
    if len(args) != 1:
        print("usage: check_live_relay.py <base-url> [--blueprint render.ha.yaml]",
              file=sys.stderr)
        return 2
    base = args[0].rstrip("/")
    if not SERVER.exists():
        print(f"{SERVER.relative_to(ROOT)}: missing — run this from the repository", file=sys.stderr)
        return 2

    want, conditional = emitted_metrics(SERVER.read_text(encoding="utf-8"))
    if not want:
        print(f"{SERVER.relative_to(ROOT)}: no '# TYPE z_' lines found — has renderMetrics moved?",
              file=sys.stderr)
        return 2
    expect = (
        blueprint_expectations(blueprint.read_text(encoding="utf-8"))
        if blueprint is not None
        else {}
    )

    try:
        health_raw = get(f"{base}/health")
        metrics_raw = get(f"{base}/metrics")
        second_health_raw = get(f"{base}/health")
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError) as e:
        print(f"{base}: not reachable ({e})", file=sys.stderr)
        return 2

    try:
        health = json.loads(health_raw)
        health2 = json.loads(second_health_raw)
    except json.JSONDecodeError:
        print(f"{base}/health did not answer JSON:\n{health_raw[:200]}", file=sys.stderr)
        return 1

    # The live side is read from its `# TYPE` lines too, so the two sets are
    # the same kind of thing.
    live = sorted(set(re.findall(r"^# TYPE (z_[a-z_]+) ", metrics_raw, re.M)))
    if not live:
        print(f"{base}/metrics has no '# TYPE z_' lines:\n{metrics_raw[:200]}", file=sys.stderr)
        return 1
    missing = [m for m in want if m not in live]
    extra = [m for m in live if m not in want]

    ids = {health.get("instanceId"), health2.get("instanceId")}
    ids.discard(None)

    print(f"relay      {base}")
    print(f"health     ok={health.get('ok')} uptime={health.get('uptimeSec')}s "
          f"coordinator={health.get('coordinator')} storage={health.get('storage')} "
          f"push={health.get('push')}")
    print(f"instances  {len(ids)} seen in two calls: {', '.join(sorted(ids)) or 'none reported'}"
          + (f" (Blueprint says {expect['instances']})" if "instances" in expect else ""))
    if blueprint is None:
        print("blueprint  not compared — pass --blueprint render.ha.yaml for the "
              "public deployment")
    print(f"metrics    {len(live)} live, {len(want)} emitted by this checkout in every mode")
    if extra:
        print(f"           ahead of this checkout: {', '.join(extra)}")
    for m in conditional:
        print(f"           {m}: emitted only in some modes, {'live' if m in live else 'absent'}")

    problems: list[str] = []
    if health.get("ok") is not True:
        problems.append(f"/health does not answer ok: {health_raw[:200]}")
    if missing:
        problems.append(
            "the live relay does not emit " + ", ".join(missing)
            + " — this checkout does, so the deployed build is BEHIND it "
              "(click Manual Deploy on the relay service)"
        )
    if "coordinator" in expect and health.get("coordinator") != expect["coordinator"]:
        problems.append(
            f"coordinator is {health.get('coordinator')!r}; render.ha.yaml wires "
            f"{expect['coordinator']!r} — this is not that Blueprint's service"
        )
    if health.get("coordinator") == "redis":
        if "presenceStale" not in health:
            problems.append("Redis mode but /health has no presenceStale (pre-2.7.9 relay)")
        elif health.get("presenceStale"):
            problems.append(
                f"presenceStale={health['presenceStale']}: that many sockets have no presence "
                "record, so their mail is queued rather than pushed — the store was full when "
                "they logged in, and the heartbeat has not repaired it yet"
            )
    if health.get("storage") != "ram-only":
        problems.append(f"storage is {health.get('storage')!r}, not 'ram-only'")

    if problems:
        print()
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print(f"\n{len(problems)} problem(s).", file=sys.stderr)
        return 1
    print("\nthe serving relay is at least this checkout, and healthy")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
