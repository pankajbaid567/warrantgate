"""Command line: python -m warrantgate <command>

  mint     --key-file F --agent coder --scopes read,write,exec     print a token
  proxy    --policy P --key-file F --token T --audit LOG -- upstream-cmd...   stdio MCP proxy
  verify   --key-file F LOG                                         check the audit log chain and anchor
  approve  --db DB [--approver NAME]                                 interactive approval queue
"""
import argparse
import sys

from . import audit as audit_mod
from . import tokens
from .approvals import ApprovalQueue
from .gateway import Gateway
from .policy import Policy
from .proxy import run_proxy


def key_from(path):
    with open(path, "rb") as f:
        k = f.read().strip()
    if len(k) < 16:
        sys.exit("key file must hold at least 16 bytes")
    return k


def main(argv=None):
    ap = argparse.ArgumentParser(prog="warrantgate")
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("mint")
    m.add_argument("--key-file", required=True); m.add_argument("--agent", required=True)
    m.add_argument("--scopes", required=True); m.add_argument("--ttl", type=int, default=3600)
    p = sub.add_parser("proxy")
    p.add_argument("--policy", required=True); p.add_argument("--key-file", required=True); p.add_argument("--token", required=True)
    p.add_argument("--audit", required=True); p.add_argument("--db", default=":memory:"); p.add_argument("--session", default="s1")
    p.add_argument("--approval-timeout", type=float, default=300); p.add_argument("upstream", nargs=argparse.REMAINDER)
    v = sub.add_parser("verify")
    v.add_argument("--key-file", required=True); v.add_argument("log")
    a = sub.add_parser("approve")
    a.add_argument("--db", required=True); a.add_argument("--approver", default="human")
    ns = ap.parse_args(argv)
    if ns.cmd == "mint":
        print(tokens.mint(key_from(ns.key_file), ns.agent, ns.scopes.split(","), ns.ttl))
    elif ns.cmd == "verify":
        r = audit_mod.verify(ns.log, key_from(ns.key_file))
        print(("OK" if r.ok else "TAMPERED") + f": {r.records} records" + ("" if r.ok else f": {r.reason} (record {r.bad_seq})"))
        return 0 if r.ok else 1
    elif ns.cmd == "proxy":
        up = ns.upstream[1:] if ns.upstream and ns.upstream[0] == "--" else ns.upstream
        key = key_from(ns.key_file)
        gw = Gateway(Policy.load(ns.policy), key, audit_mod.AuditLog(ns.audit, key), ApprovalQueue(ns.db), ns.approval_timeout)
        run_proxy(gw, ns.token, up, ns.session)
    elif ns.cmd == "approve":
        q = ApprovalQueue(ns.db)
        print("waiting for held calls (Ctrl-C to stop)")
        import time
        while True:
            r = q.claim_next(ns.approver, 120)
            if not r:
                time.sleep(0.5); continue
            print(f"\n[{r['agent']}] {r['tool']} {r['args']}\n  held because: {r['reason']}")
            ans = input("approve? [y/N] ").strip().lower() == "y"
            print("decided" if q.decide(r["id"], ns.approver, ans) else "too late (expired or taken)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
