# Warrantgate

**An MCP / agent tool-call gateway: policy, human approval, tamper-evident audit log, and a measured attack suite.** Working name; checked on GitHub 2026-11-10 (0 repos with this name; adjacent projects exist, such as tool-call firewalls with a few stars, so the differentiator must be the evaluation, not the idea). Status: **planned**.

A warrant is the signed permission an agent must hold before it acts.

## Why (JD coverage)
Atlassian (MCP, agentic AI preferred in its 2027 intern posting), Amazon, GenAI GCC roles (64% of new GCC roles need AI, data or automation skills). The research wants "AI systems with evaluation, not a wrapper".

## Scope (v1, to be confirmed in the plan)
- Sits between an agent and MCP servers (stdio and HTTP): allow, deny, or hold a tool call for approval by policy and risk score.
- Hash-chained audit log (verifiable), approval queue (reuse TaskFlow leases), per-agent tokens.
- **Evaluation harness**: a labelled suite of benign and malicious tool-call traces (prompt injection, data exfiltration, privilege escalation, confused deputy); report block precision/recall, false-positive rate on benign traces, latency overhead.
- Cairn integration as the realistic target workload.

## Non-goals
Being a complete agent framework; claiming security guarantees. The claim is a measured detection rate on a stated suite, with limits.

## Proof targets (set up front, not results)
Precision/recall with confidence intervals on a suite of at least 300 traces; p99 overhead per call; audit log verification and tamper test.

## Reuses
Cairn (MCP server and agent tokens, evaluation tooling), Resilient TaskFlow (approval queue with leases), Pitbook (claims register, deterministic harness).

## Risks
Same-niche projects exist; a weak or circular evaluation would make it a wrapper. Suite construction must be documented and honest about its bias.
