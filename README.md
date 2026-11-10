# Warrantgate

**A gateway between an AI agent and its MCP tools: per-agent tokens, policy, human approval, a tamper-evident audit log, and a measured attack suite.** Pure Python standard library.

A warrant is the signed permission an agent must hold before it acts. The point of the project is the **evaluation**: the headline is a measured detection rate on a stated suite with its limits, not a claim of security.

## What was measured
Details and caveats: [docs/evaluation.md](docs/evaluation.md). 374 labelled traces (192 malicious across prompt injection, data exfiltration, privilege escalation, confused deputy; 182 benign including deliberately suspicious-looking ones), split into dev and held-out test.

On the **held-out test split** (114 malicious, 115 benign):
- **78.9% of attacks stopped before the harmful call ran** (90/114, 95% CI 70.6 to 85.4). **100% of easy and medium** attacks, **29% of the hard tier** that was written to evade the policy.
- **24.3% of benign runs were interrupted** (all held for a human, none hard-denied); 16.3% excluding actions the policy deliberately sends to a human.
- Per-call rules alone (no session state) stop 65.8%, so the session-aware rules add about 13 points, for about 15 points more interference.
- Policy decision p50 13 us, p99 68 us in-process. Through the stdio proxy: about **+3.5 ms p50, +9.6 ms p99** per tool call, mostly the audit log's fsync.
- Audit log: edit, delete, reorder, duplicate, truncate and forged-anchor tampering are all detected. 27 tests; **8 of 8** injected bugs caught.

**Read the limits.** The suite is synthetic and written by the policy's author, so it is circular; traces are re-instantiations of about 36 templates, so the confidence intervals are too narrow; no real agent or model was used; the Cairn integration is not done.

## How it works
`agent --MCP/stdio--> warrantgate proxy --> upstream MCP server`. Every `tools/call` is checked: token (can only narrow scope), then the policy (hard rules deny; otherwise a risk score allows or holds for a human), with session memory of what tool output contained. Held calls go to a SQLite approval queue with leases. Every decision is appended to a hash-chained, HMAC-anchored audit log. Blocked calls return an error result the agent can read and are never forwarded. See [docs/architecture.md](docs/architecture.md).

## Use it
No install needed: prefix commands with `PYTHONPATH=src`, or `pip install -e .` to get a `warrantgate` command.
```bash
export PYTHONPATH=src
python3 -m warrantgate mint --key-file key.txt --agent coder --scopes read,write,exec
python3 -m warrantgate proxy --policy policies/default.toml --key-file key.txt --token "$TOKEN" \
    --audit audit.log --db approvals.db -- <your upstream MCP server command>
python3 -m warrantgate approve --db approvals.db        # a human decides held calls
python3 -m warrantgate verify --key-file key.txt audit.log
```
Edit `policies/default.toml` for your own agents, paths, domains and patterns. Python 3.11 or newer.

## Reproduce
```bash
python3 -W ignore -m unittest discover -s tests -t .      # 27 tests
python3 eval/run.py --split test --show-misses            # held-out results, misses and false positives listed
python3 eval/latency.py                                   # proxy overhead
python3 scripts/mutation_check.py                         # 8 mutants
```

## What this is not
Not a complete agent framework and not a security guarantee. Detection is heuristic and an attacker who knows the rules can evade them. Only `tools/call` over stdio is intercepted (no HTTP transport yet). Not tested against a real agent.
