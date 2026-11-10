# Design decisions

- **ADR-000 Name.** Warrantgate: a warrant is the signed permission an agent must hold before it acts. GitHub search 2026-11-10: 0 repos with the name; adjacent tool-call firewalls exist, so the differentiator is the evaluation, not the idea.
- **ADR-001 Python, standard library only** (`tomllib`, `sqlite3`, `hmac`). No dependency to audit and the project runs anywhere with Python 3.11+.
- **ADR-002 Deny, hold, or allow; never silently modify.** Ambiguous cases go to a human (hold) rather than being denied, because a false deny blocks work with no recourse. The cost shows up as measured interference.
- **ADR-003 Session-aware rules.** Per-call rules cannot see "this value came from a web page" or "secrets were read earlier". The evaluation compares both and shows what the session state adds.
- **ADR-004 Tool output is data, never instructions.** The gateway never follows anything in a tool result; it only uses results to update suspicion.
- **ADR-005 Tamper-evident, not tamper-proof.** Hash chain plus a signed anchor detects edits, deletions, reordering and truncation by anyone without the key. It does not stop a key holder.
- **ADR-006 Leases for approvals.** The same pattern as a job queue: claim for a lease, decide before it ends, otherwise it returns to the pool, so a crashed approver does not strand a request.
- **ADR-007 Honest evaluation over impressive numbers.** Held-out split, a baseline without session state, a hard tier built to fail, confidence intervals, and a limits section that says the suite is circular.
