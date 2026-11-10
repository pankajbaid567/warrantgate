#!/usr/bin/env python3
"""Injects deliberate bugs into a scratch copy and checks the unit tests catch each. A surviving mutant is a test hole.
Every patch asserts its target exists. Usage: python3 scripts/mutation_check.py"""
import shutil, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRATCH = ROOT / ".mutants"


def sub(path, old, new):
    t = path.read_text()
    if old not in t:
        raise SystemExit(f"mutation target not found in {path.name}: {old[:60]!r}")
    path.write_text(t.replace(old, new, 1))


MUTANTS = [
    # (Deleting the explicit prev-hash comparison is an EQUIVALENT mutant: the record hash already covers the previous hash,
    #  so the chain is still caught. It survived the first run and was replaced by this one.)
    ("audit anchor signature not verified", "src/warrantgate/audit.py", 'if not hmac.compare_digest(a.get("mac", ""), _anchor_mac(key, a.get("seq", -1), a.get("hash", ""))):', 'if False:'),
    ("audit anchor (truncation check) removed", "src/warrantgate/audit.py", 'if a["seq"] != n or a["hash"] != prev:', 'if False:'),
    ("token signature not compared", "src/warrantgate/tokens.py", "if not hmac.compare_digest(expected, _unb64(sig)):", "if False:"),
    ("path traversal check removed", "src/warrantgate/policy.py", """if ".." in str(raw).split("/"):""", "if False:"),
    ("confused-deputy intersection removed", "src/warrantgate/policy.py", "effective.append(ocfg)", "pass"),
    ("exfiltration-after-secret rule removed", "src/warrantgate/policy.py", "if session.secret_taint:\n            ok =", "if False:\n            ok ="),
    ("approval leases ignored (two approvers get one request)", "src/warrantgate/approvals.py", "AND (lease_until IS NULL OR lease_until < ?)", "AND (1 OR ? > 0)"),
    ("token cannot narrow scope (gateway ignores token scopes)", "src/warrantgate/gateway.py", "if cls is not None and cls not in granted:", "if False:"),
]


def main():
    caught = 0
    for n, (name, rel, old, new) in enumerate(MUTANTS, 1):
        if SCRATCH.exists():
            shutil.rmtree(SCRATCH)
        shutil.copytree(ROOT, SCRATCH, ignore=shutil.ignore_patterns(".git", ".mutants", "__pycache__", "suite"))
        sub(SCRATCH / rel, old, new)
        p = subprocess.run([sys.executable, "-W", "ignore", "-m", "unittest", "discover", "-s", "tests", "-t", "."], cwd=SCRATCH, capture_output=True, text=True, timeout=600)
        failed = [l.split()[1] for l in p.stderr.splitlines() if l.startswith(("FAIL:", "ERROR:"))]
        ok = p.returncode != 0
        caught += ok
        print(f"mutant {n}: {name}: {'CAUGHT' if ok else 'SURVIVED'} {', '.join(failed[:3])}", flush=True)
    shutil.rmtree(SCRATCH, ignore_errors=True)
    print(f"\n{caught}/{len(MUTANTS)} mutants caught")
    sys.exit(0 if caught == len(MUTANTS) else 1)


if __name__ == "__main__":
    main()
