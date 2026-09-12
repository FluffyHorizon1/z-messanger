#!/usr/bin/env python3
"""Tests for tool/check_live_relay.py, against a real relay and against a
stub that lies.

The checker's whole value is that it says "the deploy is behind" when and only
when it is, so the two cases worth pinning are a relay that IS this checkout
(it must pass) and one that is missing a counter this code emits (it must
fail, and name the counter). The first runs the actual `server/server.js` on a
free port; the second is a stub serving a `/metrics` with one `# TYPE` line
removed, which is exactly the shape the stale deployment had.

The third case is the one that would have made the tool useless: the relay
emits two metrics conditionally or as a histogram, and a naive comparison
would report them missing against a perfectly current relay. The real-relay
case covers it — it runs in RAM mode, and the Redis-only shape is asserted
from the stub.

    python3 tool/test_check_live_relay.py
"""

import http.server
import json
import re
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "tool" / "check_live_relay.py"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_checker(url: str, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(CHECKER), url, *extra],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        timeout=120,
    )


def wait_for(url_port: int, path: str = "/health", tries: int = 100) -> bool:
    import urllib.error
    import urllib.request

    for _ in range(tries):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{url_port}{path}", timeout=1):
                return True
        except (urllib.error.URLError, OSError):
            time.sleep(0.1)
    return False


def stub(health: dict, metrics: str) -> tuple[str, http.server.HTTPServer]:
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path == "/health":
                body = json.dumps(health).encode()
                ctype = "application/json"
            elif self.path == "/metrics":
                body = metrics.encode()
                ctype = "text/plain; version=0.0.4"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("content-type", ctype)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):  # quiet
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{srv.server_port}", srv


def main() -> int:
    failures = []

    def check(name: str, cond: bool, detail: str = "") -> None:
        print(("  ok   " if cond else "  FAIL ") + name + (f"\n         {detail}" if not cond and detail else ""))
        if not cond:
            failures.append(name)

    # ---- 1. the real relay, from this checkout ----
    print("a relay built from this checkout")
    port = free_port()
    env_server = ROOT / "server"
    proc = subprocess.Popen(
        ["node", "server.js"],
        cwd=str(env_server),
        env={**__import__("os").environ, "PORT": str(port), "LOG_LEVEL": "error"},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        if not wait_for(port):
            print("  SKIP  the relay did not start (node or its modules missing)")
        else:
            r = run_checker(f"http://127.0.0.1:{port}")
            check("passes against a relay that is this checkout", r.returncode == 0,
                  r.stdout + r.stderr)
            check("and says so", "at least this checkout" in r.stdout, r.stdout)
            # In RAM mode the conditional gauge IS emitted, and the histogram
            # must not be reported as missing either.
            check("no false 'behind' from the histogram or the mode-specific gauge",
                  "BEHIND" not in r.stdout + r.stderr, r.stdout + r.stderr)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    # ---- 2. a relay missing a counter this checkout emits ----
    print("a relay that is behind this checkout")
    src = (ROOT / "server" / "server.js").read_text(encoding="utf-8")
    emitted = sorted(
        {
            m.group(2)
            for m in re.finditer(r"^(\s*)L\.push\('# TYPE (z_[a-z_]+) ", src, re.M)
            if len(m.group(1)) <= 2
        }
    )
    dropped = "z_ack_miss_total" if "z_ack_miss_total" in emitted else emitted[-1]
    body = "".join(f"# TYPE {m} counter\n{m} 0\n" for m in emitted if m != dropped)
    url, srv = stub(
        {
            "ok": True,
            "uptimeSec": 99,
            "instanceId": "stale0",
            "coordinator": "redis",
            "connections": 0,
            "queuedEnvelopes": -1,
            "presenceStale": 0,
            "storage": "ram-only",
            "push": "enabled",
        },
        body,
    )
    try:
        r = run_checker(url)
        check("fails", r.returncode == 1, r.stdout + r.stderr)
        check(f"and names {dropped}", dropped in r.stderr, r.stderr)
        check("and says what to click", "Manual Deploy" in r.stderr, r.stderr)
        check("does not demand the mode-specific gauge of a Redis relay",
              "z_queued_envelopes" not in r.stderr, r.stderr)
    finally:
        srv.shutdown()

    # ---- 3. a relay whose store was full when someone logged in ----
    print("a relay with sockets whose presence write was refused")
    url, srv = stub(
        {
            "ok": True,
            "uptimeSec": 99,
            "instanceId": "x",
            "coordinator": "redis",
            "connections": 3,
            "queuedEnvelopes": -1,
            "presenceStale": 2,
            "storage": "ram-only",
            "push": "enabled",
        },
        "".join(f"# TYPE {m} counter\n{m} 0\n" for m in emitted),
    )
    try:
        r = run_checker(url)
        check("fails", r.returncode == 1, r.stdout + r.stderr)
        check("and explains what queued rather than pushed means",
              "queued rather than pushed" in r.stderr, r.stderr)
    finally:
        srv.shutdown()

    # ---- 4. the wrong coordinator for this Blueprint ----
    print("a relay in RAM mode where the named Blueprint wires a store")
    url, srv = stub(
        {"ok": True, "uptimeSec": 1, "instanceId": "x", "coordinator": "memory",
         "connections": 0, "queuedEnvelopes": 0, "storage": "ram-only", "push": "disabled"},
        "".join(f"# TYPE {m} counter\n{m} 0\n" for m in emitted),
    )
    try:
        r = run_checker(url, "--blueprint", "render.ha.yaml")
        check("fails", r.returncode == 1, r.stdout + r.stderr)
        check("and says it is not that Blueprint's service",
              "not that Blueprint" in r.stderr, r.stderr)
    finally:
        srv.shutdown()

    # ---- 5. nothing there ----
    print("nothing listening")
    r = run_checker(f"http://127.0.0.1:{free_port()}")
    check("exits 2 rather than 1 — unreachable is not the same as behind",
          r.returncode == 2, r.stdout + r.stderr)

    print()
    if failures:
        print(f"{len(failures)} failure(s): {', '.join(failures)}", file=sys.stderr)
        return 1
    print("check_live_relay: all cases pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
