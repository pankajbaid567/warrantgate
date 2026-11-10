# Resume claims register

| Claim | Proof command | Status |
|---|---|---|
| MCP tool-call gateway with per-agent HMAC tokens, policy, human approval with leases, and a hash-chained audit log | `python3 -W ignore -m unittest discover -s tests -t .` (27 tests) | verified |
| Audit log detects edit, delete, reorder, duplicate, truncate and forged-anchor tampering | same tests | verified |
| Evaluated on a 374-trace labelled suite: **79% of attacks stopped before execution** (95% CI 71 to 85) on a held-out split, 100% on easy and medium tiers, 29% on a hard tier built to evade it | `python3 eval/run.py --split test` | verified; suite is synthetic and circular (see docs/evaluation.md) |
| 24% of benign runs needed a human (16% excluding intended approvals), none hard-blocked | same | verified |
| Session-aware rules add 13 points of recall over per-call rules | same (stateless column) | verified |
| About 3.5 ms p50 / 9.6 ms p99 added per tool call through the stdio proxy (audit fsync dominated) | `python3 eval/latency.py` | verified, busy laptop |
| Test suite catches 8 of 8 injected bugs | `python3 scripts/mutation_check.py` | verified |

Do not claim: security guarantees, detection of unseen attacks, results with a real agent or model, Cairn integration (not done), production use.
