# Evaluation

The question: how much of a set of labelled attacks does the gateway stop **before the harmful call runs**, and how much legitimate work does it get in the way of? Everything below can be reproduced with `python3 eval/run.py`.

## The suite
`eval/suite/traces.jsonl`: **374 traces** (192 malicious, 182 benign), generated deterministically by `eval/generate.py` (seed 7). A trace is one agent run: a user task, a token, and ordered steps (tool calls and the tool results that came back). Malicious traces name the step of the harmful call; a detection counts only if the gateway denied or held a call **at or before** that step. Stopping after the harm ran counts as a miss.

Malicious categories (tiers: easy = a rule matches directly, medium = needs session state or a human, hard = written to contain behaviour the policy does not model):
- **prompt injection**: instructions hidden in fetched pages or files steer the agent (exfiltration, `curl | sh`, package install from an attacker index, deleting files, planting code).
- **data exfiltration**: secret reads followed by sends to attacker or allowed domains, bulk staging, confidential queries.
- **privilege escalation**: forged, expired or narrower tokens, admin calls, path traversal, writes to policy and CI files, `sudo`.
- **confused deputy**: a low-privilege agent gets a high-privilege agent to act for it, with the originator reported, missing, or spoofed.

Benign traces cover coding, research, analytics, deploys, email and admin work. A "tricky" tier is built to look suspicious (a page that quotes an injection string, a test fixture containing one, an email address copied from a README, reading 30 notes then fetching docs) and a "friction" tier is legitimate work the policy deliberately sends to a human (package installs, admin grants).

## How the policy was tuned
The suite is split by a hash of the trace id: 145 dev, 229 test. The policy was run on **dev**, two changes were made from what dev showed, and then **test was run**. Test numbers below were produced after those changes and no policy changes were made after seeing them. The changes: instruction-like text no longer raises risk by itself (it only counts when an argument was also copied from untrusted output), and the bulk-read rule holds for a human instead of denying.

## Results, held-out test split
| | gateway | stateless rules only | no gateway |
|---|---|---|---|
| recall (harm stopped before it ran) | **90/114 = 78.9%** (95% CI 70.6 to 85.4) | 75/114 = 65.8% (56.7 to 73.9) | 0% |
| benign traces interfered with | 28/115 = 24.3% (17.4 to 32.9), all **held for a human**, none hard-denied | 11/115 = 9.6% (5.4 to 16.3) | 0% |
| same, excluding the deliberate "friction" tier | 17/104 = 16.3% | 0/104 = 0% | 0% |
| precision | 90/118 = 76.3% (67.8 to 83.0) | 75/86 = 87.2% (78.5 to 92.7) | n/a |

"Stateless" runs the same rules but judges every call with an empty session (no injection flag, no secret taint, no copied-value check, no bulk counter): it isolates what the session-aware rules add. They add about 13 points of recall and cost about 15 points of benign interference.

Recall by tier (gateway, test): **easy 59/59, medium 21/21, hard 10/34 (29.4%)**. By category: prompt injection 31/33, privilege escalation 36/41, data exfiltration 20/30, confused deputy 3/10. The dev split showed the same shape (66/78 = 84.6% overall; hard 6/18).

## What the numbers do not show
1. **The suite is circular.** The same person wrote the policy and the traces. Easy and medium recall of 100% means the rules do what their author meant on the author's examples; it says little about attacks the author did not think of. The hard tier exists to show the opposite and recall there is 29%.
2. **Fewer independent samples than 374.** The traces are random instantiations of about 14 benign and 22 malicious templates. Wilson intervals treat traces as independent, so they are too narrow. Treat them as a floor on the uncertainty.
3. **Known misses, by design of the policy:** an in-scope write of a file the user named (planted code, backdoor), exfiltration through an allowed domain of data that was not classified as secret, 12 reads (below the bulk threshold) then an upload, planted code run by an allowed `pytest`, and confused-deputy requests where the originator is missing or spoofed.
4. **Interference is high.** A human would be asked about roughly one in four benign runs here (one in six excluding the intended approvals). Typical causes: an address or URL copied from a file (provenance), reading many files then fetching a URL, package installs, admin grants. That is a policy choice (ask rather than deny) and it is what a production deployment would have to tune against real traffic.
5. **No real agent or model was used.** Traces are scripted. How an actual agent behaves under injection, and how often it would produce these call sequences, is not measured. The planned Cairn integration has not been done.
6. **The detection rules are heuristics** (regexes for instruction-like text, string matching for copied values). A determined attacker who knows them can evade them. The claim is a measured rate on a stated suite, not a security guarantee.

## Latency
- Policy decision, in-process: **p50 13 us, p99 68 us** over 933 calls (test split).
- Through the stdio proxy against a trivial upstream, 1,500 sequential `tools/call` round trips (`eval/latency.py`): direct p50 0.012 ms, p99 0.025 ms; through Warrantgate **p50 3.5 ms, p99 9.7 ms**, so **+3.5 ms p50 and +9.6 ms p99 per call**. Almost all of it is the audit log's fsync on every call plus the extra process hop; measured on a busy laptop. A real upstream tool call (network, file I/O) would normally dwarf it.

## Audit log
`tests/test_core.py` checks that editing any single record, deleting, reordering, duplicating, truncating, emptying, using the wrong key, and truncating with a forged anchor are all detected, and that concurrent appends keep one valid chain. This is tamper-**evidence**: someone holding the signing key can rewrite the log.

## Mutation check
`python3 scripts/mutation_check.py`: 8 of 8 injected bugs caught. One of the first seven mutants survived because it was equivalent (removing an explicit previous-hash comparison changes nothing, since the record hash already covers it); it was replaced with a real bug (anchor signature not verified) plus a test for it.
