#!/usr/bin/env python3
"""Per-call overhead of the stdio proxy: round-trip of a tools/call straight to a fake MCP server vs through Warrantgate.
Both talk to the same trivial upstream, so the difference is the gateway (policy, audit append with fsync, process hop).
"""
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(__file__)
ROOT = os.path.join(HERE, "..")
sys.path.insert(0, os.path.join(ROOT, "src"))
from warrantgate import tokens  # noqa: E402

KEY = b"latency-key-latency-key-latency-0"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 1500


def measure(cmd, env=None):
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1, env=env)
    lat = []
    for i in range(N + 100):
        msg = {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": "fs.read_file", "arguments": {"path": f"/work/src/f{i % 50}.py"}}}
        t = time.perf_counter()
        p.stdin.write(json.dumps(msg) + "\n"); p.stdin.flush()
        out = json.loads(p.stdout.readline())
        dt = (time.perf_counter() - t) * 1000
        assert out["id"] == i and not out["result"].get("isError"), out
        if i >= 100:   # first 100 are warm-up
            lat.append(dt)
    p.stdin.close(); p.wait(timeout=10)
    lat.sort()
    return lat


def q(l, f):
    return l[min(len(l) - 1, int(len(l) * f))]


with tempfile.TemporaryDirectory() as d:
    keyf = os.path.join(d, "k"); open(keyf, "wb").write(KEY)
    fake = os.path.join(ROOT, "tests", "fake_mcp_server.py")
    tok = tokens.mint(KEY, "coder", ["read", "write", "exec"])
    env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "src"))
    direct = measure([sys.executable, fake])
    proxied = measure([sys.executable, "-m", "warrantgate", "proxy", "--policy", os.path.join(ROOT, "policies", "default.toml"), "--key-file", keyf, "--token", tok,
                       "--audit", os.path.join(d, "a.log"), "--", sys.executable, fake], env=env)
print(f"{N} sequential tools/call round trips each (closed loop, one machine, audit log fsync on every call)")
print(f"direct to upstream: p50 {q(direct, .5):.3f} ms  p99 {q(direct, .99):.3f} ms")
print(f"through Warrantgate: p50 {q(proxied, .5):.3f} ms  p99 {q(proxied, .99):.3f} ms")
print(f"overhead: p50 +{q(proxied, .5) - q(direct, .5):.3f} ms  p99 +{q(proxied, .99) - q(direct, .99):.3f} ms")
