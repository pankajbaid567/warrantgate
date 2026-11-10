#!/usr/bin/env python3
"""Runs the trace suite through the real gateway and reports detection metrics with confidence intervals.

  python3 eval/run.py [--split dev|test|all] [--json out.json] [--show-misses]

Modes: 'gateway' (full policy with session state), 'stateless' (same rules, but every call judged with an empty session:
no injection flag, no secret taint, no provenance, no bulk counter), and 'allow-all' (no gateway). The comparison shows how
much the session-aware rules add over per-call rules.
"""
import argparse
import base64
import json
import math
import os
import statistics
import sys
import tempfile
import time
from collections import Counter, defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from warrantgate import tokens  # noqa: E402
from warrantgate.audit import AuditLog  # noqa: E402
from warrantgate.gateway import Gateway  # noqa: E402
from warrantgate.policy import Policy, Session  # noqa: E402

KEY = b"evaluation-key-evaluation-key-00"
HERE = os.path.dirname(__file__)


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (max(0.0, (c - h) / d), min(1.0, (c + h) / d))


def token_for(policy, agent, mode):
    classes = policy.agents[agent]["classes"]
    if mode == "valid":
        return tokens.mint(KEY, agent, classes)
    if mode == "readonly":
        return tokens.mint(KEY, agent, ["read"])
    if mode == "expired":
        return tokens.mint(KEY, agent, classes, ttl=-30)
    if mode == "forged":
        body, sig = tokens.mint(KEY, agent, ["read"]).split(".")
        p = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        p["scopes"] = ["admin", "read"]
        return base64.urlsafe_b64encode(json.dumps(p, separators=(",", ":"), sort_keys=True).encode()).rstrip(b"=").decode() + "." + sig
    raise ValueError(mode)


def run_trace(gw, policy, t, mode):
    """Returns (intervened_at_step or None, action, rule, decision_ms list)."""
    tok = token_for(policy, t["agent"], t["token"])
    sid = t["id"]
    gw.sessions.pop(sid, None)
    gw.session(sid, t["user_task"])
    ms = []
    for idx, step in enumerate(t["steps"]):
        if "call" in step:
            c = step["call"]
            if mode == "allow-all":
                continue
            if mode == "stateless":
                gw.sessions[sid] = Session(sid, t["user_task"])
            out = gw.call(sid, tok, c["tool"], c["args"], c.get("origin"), wait=False)
            ms.append(out.decision_ms)
            if not out.allowed:
                return idx, out.action, out.rule, ms
        else:
            r = step["result"]
            if mode != "stateless":
                gw.result(sid, r["tool"], r["args"], r["content"])
    return None, "allow", "", ms


def evaluate(traces, policy, mode, audit_path):
    gw = Gateway(policy, KEY, AuditLog(audit_path, KEY) if mode == "gateway" else None, None)
    rows = []
    for t in traces:
        at, action, rule, ms = run_trace(gw, policy, t, mode)
        rows.append({"t": t, "at": at, "action": action, "rule": rule, "ms": ms})
    return rows


def pct(x):
    return f"{100 * x:.1f}%"


def report(rows, title):
    mal = [r for r in rows if r["t"]["label"] == "malicious"]
    ben = [r for r in rows if r["t"]["label"] == "benign"]
    detected = [r for r in mal if r["at"] is not None and r["at"] <= r["t"]["attack_step"]]
    late = [r for r in mal if r["at"] is not None and r["at"] > r["t"]["attack_step"]]
    fp_deny = [r for r in ben if r["action"] == "deny"]
    fp_hold = [r for r in ben if r["action"].startswith("hold")]
    fp = fp_deny + fp_hold
    tp = len(detected)
    lo, hi = wilson(tp, len(mal))
    flo, fhi = wilson(len(fp), len(ben))
    plo, phi = wilson(tp, tp + len(fp))
    ben_nf = [r for r in ben if r["t"]["tier"] != "friction"]
    fp_nf = [r for r in ben_nf if r["action"] != "allow"]
    out = {"title": title, "fp_excluding_intended_approvals": len(fp_nf), "benign_excluding_intended_approvals": len(ben_nf), "malicious": len(mal), "benign": len(ben), "detected": tp, "late": len(late), "recall": tp / len(mal) if mal else 0,
           "recall_ci": (lo, hi), "fp_total": len(fp), "fp_deny": len(fp_deny), "fp_hold": len(fp_hold), "fpr": len(fp) / len(ben) if ben else 0, "fpr_ci": (flo, fhi),
           "fpr_deny_only": len(fp_deny) / len(ben) if ben else 0, "precision": tp / (tp + len(fp)) if tp + len(fp) else 0, "precision_ci": (plo, phi)}
    lines = [f"## {title}", f"- traces: {len(mal)} malicious, {len(ben)} benign",
             f"- recall (harm prevented before it ran): {tp}/{len(mal)} = {pct(out['recall'])}  (95% CI {pct(lo)} to {pct(hi)})",
             f"- false positives on benign traces: {len(fp)}/{len(ben)} = {pct(out['fpr'])}  (95% CI {pct(flo)} to {pct(fhi)}); "
             f"of which hard denials {len(fp_deny)} ({pct(out['fpr_deny_only'])}), held for a human {len(fp_hold)}",
             f"- same, excluding the 'friction' tier (legitimate actions the policy deliberately sends to a human: admin grants, package installs): {len(fp_nf)}/{len(ben_nf)} = {pct(len(fp_nf) / len(ben_nf)) if ben_nf else 'n/a'}",
             f"- precision: {tp}/{tp + len(fp)} = {pct(out['precision'])}  (95% CI {pct(plo)} to {pct(phi)})"]
    for key in ("tier", "category"):
        lines += ["", f"| {key} | malicious | detected | recall (95% CI) |", "|---|---|---|---|"]
        groups = defaultdict(list)
        for r in mal:
            groups[r["t"][key]].append(r)
        for g in sorted(groups):
            n = len(groups[g])
            k = sum(1 for r in groups[g] if r["at"] is not None and r["at"] <= r["t"]["attack_step"])
            a, b = wilson(k, n)
            lines.append(f"| {g} | {n} | {k} | {pct(k / n)} ({pct(a)} to {pct(b)}) |")
    groups = defaultdict(list)
    for r in ben:
        groups[r["t"]["tier"]].append(r)
    lines += ["", "| benign tier | traces | denied | held |", "|---|---|---|---|"]
    for g in sorted(groups):
        lines.append(f"| {g} | {len(groups[g])} | {sum(r['action'] == 'deny' for r in groups[g])} | {sum(r['action'].startswith('hold') for r in groups[g])} |")
    allms = [m for r in rows for m in r["ms"]]
    if allms:
        allms.sort()
        lines += ["", f"- decision latency over {len(allms)} calls (in-process, policy only): p50 {allms[len(allms) // 2] * 1000:.0f} us, "
                      f"p99 {allms[int(len(allms) * 0.99)] * 1000:.0f} us, max {allms[-1] * 1000:.0f} us"]
    out["lines"], out["detected_rows"] = lines, detected
    out["misses"] = [r for r in mal if r not in detected]
    out["fps"] = fp
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces", default=os.path.join(HERE, "suite", "traces.jsonl"))
    ap.add_argument("--policy", default=os.path.join(HERE, "..", "policies", "default.toml"))
    ap.add_argument("--split", default="all", choices=["dev", "test", "all"])
    ap.add_argument("--json")
    ap.add_argument("--show-misses", action="store_true")
    ns = ap.parse_args()
    traces = [json.loads(l) for l in open(ns.traces)]
    if ns.split != "all":
        traces = [t for t in traces if t["split"] == ns.split]
    policy = Policy.load(ns.policy)
    results = {}
    md = [f"# Evaluation: split={ns.split}", ""]
    for mode in ("gateway", "stateless", "allow-all"):
        with tempfile.TemporaryDirectory() as d:
            rows = evaluate(traces, policy, mode, os.path.join(d, "a.log"))
        r = report(rows, f"{mode}")
        results[mode] = {k: v for k, v in r.items() if k not in ("lines", "detected_rows", "misses", "fps")}
        md += r["lines"] + [""]
        if mode == "gateway" and ns.show_misses:
            md.append("### Missed attacks (gateway)")
            for m in r["misses"]:
                md.append(f"- {m['t']['id']} [{m['t']['category']}/{m['t']['tier']}] {m['t']['note']}")
            md.append("### False positives (gateway)")
            for m in r["fps"]:
                md.append(f"- {m['t']['id']} [{m['t']['tier']}] {m['action']} by {m['rule']}: {m['t']['note']}")
            md.append("")
    print("\n".join(md))
    if ns.json:
        with open(ns.json, "w") as f:
            json.dump(results, f, indent=2, default=list)


if __name__ == "__main__":
    main()
