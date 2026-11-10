"""MCP stdio proxy: sits between an MCP client and an upstream MCP server and judges every tools/call.

MCP's stdio transport is newline-delimited JSON-RPC. Everything except tools/call passes through untouched. A denied
call gets a JSON-RPC result with isError=true (so the agent can read why) and is never forwarded. Tool outputs from the
upstream are fed back to the gateway so session state (injection, secret reads) is current.
"""
import json
import subprocess
import sys
import threading

from .gateway import Gateway


def run_proxy(gw: Gateway, token: str, upstream_cmd: list[str], session_id: str, client_in=sys.stdin, client_out=sys.stdout, origin=None):
    up = subprocess.Popen(upstream_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
    out_lock = threading.Lock()
    pending: dict = {}   # request id -> (tool, args)

    def to_client(msg):
        with out_lock:
            client_out.write(json.dumps(msg) + "\n")
            client_out.flush()

    def from_upstream():
        for line in up.stdout:
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            info = pending.pop(msg.get("id"), None) if "id" in msg and "method" not in msg else None
            if info:
                text = "".join(c.get("text", "") for c in msg.get("result", {}).get("content", []) if isinstance(c, dict))
                gw.result(session_id, info[0], info[1], text)
            to_client(msg)

    t = threading.Thread(target=from_upstream, daemon=True)
    t.start()

    def handle(line):
        try:
            msg = json.loads(line)
        except ValueError:
            return
        if msg.get("method") == "tools/call":
            p = msg.get("params", {})
            tool, args = p.get("name", ""), p.get("arguments", {}) or {}
            out = gw.call(session_id, token, tool, args, origin)
            if not out.allowed:
                to_client({"jsonrpc": "2.0", "id": msg.get("id"), "result": {"isError": True, "content": [
                    {"type": "text", "text": f"Blocked by Warrantgate ({out.action}, rule {out.rule}): {out.reason}"}]}})
                return
            pending[msg.get("id")] = (tool, args)
        up.stdin.write(line if line.endswith("\n") else line + "\n")
        up.stdin.flush()

    workers = []
    for line in client_in:
        if line.strip():
            # a held call blocks on a human; handle each request on its own thread so other traffic keeps flowing
            w = threading.Thread(target=handle, args=(line,), daemon=True)
            w.start()
            workers.append(w)
    for w in workers:
        w.join(timeout=5)
    try:
        up.stdin.close()
    except OSError:
        pass
    t.join(timeout=5)
    up.wait(timeout=5)
