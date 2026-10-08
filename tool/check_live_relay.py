#!/usr/bin/env python3
"""Is the relay that is serving the one this checkout describes?

    python3 tool/check_live_relay.py https://www.zmessengers.com --blueprint render.ha.yaml

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
  * two /metrics scrapes are made, so the instance id (now a `z_relay_info`
    label, since P1-14 took it off `/health`) is sampled twice and reported:
    with several instances the ids may differ, and a single id is not a
    failure.

  * `presenceStale` (now the `z_presence_stale` gauge) must be present in
    Redis mode and zero, and `/health` `storage` must be `ram-only`, whatever
    Blueprint is or is not named.

`/metrics` now needs a bearer token (P1-14, default-404 without one). This
reads it from the `METRICS_TOKEN` environment variable — pass the same secret
the relay has — and sends it. **Never run this against a live URL** (the hard
rule): its test drives it against a relay it starts itself.

Exit status is 0 when the live relay is at least this checkout, 1 when it is
behind or unhealthy, 2 when it could not be reached or the arguments are
wrong, and 3 when `/metrics` answered 401/404 because the token was missing or
wrong. Reading `/health` and `/metrics` is a GET a builder may make; nothing
here deploys.
"""
from __future__ import annotations

import json
import os
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
METRICS_TOKEN = os.environ.get("METRICS_TOKEN", "")


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


def get(url: str, token: str = "") -> str:
    headers = {"user-agent": "z-check-live-relay"}
    if token:
        headers["authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=ssl.create_default_context()) as r:
        return r.read().decode("utf-8", "replace")


def label(body: str, metric: str, key: str) -> str | None:
    """Read one label off an info metric line (e.g. z_relay_info{instance="…"})."""
    m = re.search(rf'^{metric}\{{([^}}]*)\}}', body, re.M)
    if not m:
        return None
    lm = re.search(rf'{key}="([^"]*)"', m.group(1))
    return lm.group(1) if lm else None


def metric_value(body: str, name: str) -> int | None:
    """The value of a bare gauge/counter line, or None if absent."""
    m = re.search(rf"^{name} (\d+)$", body, re.M)
    return int(m.group(1)) if m else None


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

    if not METRICS_TOKEN:
        print("METRICS_TOKEN is not set — /metrics needs the relay's bearer token "
              "(P1-14). Set it in the environment to the secret the relay has; this "
              "tool never takes it on the command line and must never be run against a "
              "live URL.", file=sys.stderr)
        return 3

    try:
        health_raw = get(f"{base}/health")
        second_health_raw = get(f"{base}/health")
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError) as e:
        print(f"{base}: not reachable ({e})", file=sys.stderr)
        return 2
    try:
        metrics_raw = get(f"{base}/metrics", METRICS_TOKEN)
    except urllib.error.HTTPError as e:
        if e.code in (401, 404):
            print(f"{base}/metrics answered {e.code}: the METRICS_TOKEN is wrong, or the "
                  "relay has none configured (P1-14). Nothing could be checked.", file=sys.stderr)
            return 3
        print(f"{base}/metrics: {e}", file=sys.stderr)
        return 2
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        print(f"{base}: not reachable ({e})", file=sys.stderr)
        return 2

    try:
        health = json.loads(health_raw)
        json.loads(second_health_raw)
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

    # The instance id is now a z_relay_info label (P1-14 took it off /health);
    # a second /metrics scrape samples it again, so several instances show up.
    try:
        metrics_raw2 = get(f"{base}/metrics", METRICS_TOKEN)
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError):
        metrics_raw2 = metrics_raw
    ids = {label(metrics_raw, "z_relay_info", "instance"),
           label(metrics_raw2, "z_relay_info", "instance")}
    ids.discard(None)
    ids.discard("")
    presence_stale = metric_value(metrics_raw, "z_presence_stale")

    print(f"relay      {base}")
    print(f"health     ok={health.get('ok')} coordinator={health.get('coordinator')} "
          f"storage={health.get('storage')} push={health.get('push')}")
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
        if presence_stale is None:
            problems.append("Redis mode but /metrics has no z_presence_stale (pre-phase-29 relay)")
        elif presence_stale:
            problems.append(
                f"z_presence_stale={presence_stale}: that many sockets have no presence "
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
