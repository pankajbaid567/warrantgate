# Architecture

```
 agent (MCP client) --JSON-RPC over stdio--> [ Warrantgate proxy ] --JSON-RPC--> upstream MCP server
                                                  |    ^
                                  tools/call -----+    +---- tool result (fed back to the session)
                                                  v
                                   Gateway: token -> policy -> allow | deny | hold
                                         |            |              |
                                  audit log     session state   approval queue (SQLite, leases)
                               (hash chain +    (injection flag,     ^
                                signed anchor)   secret taint,       |
                                                 copied values)   human approver
```

- **Tokens** (`tokens.py`): HMAC-signed `{agent, scopes, exp}`. A token can only narrow what the policy grants the agent, never widen it.
- **Policy** (`policy.py`, `policies/default.toml`): tool classes (read, write, exec, egress, admin); per-agent classes, path prefixes, egress and email domains, table lists. Hard rules deny (unknown tool, class out of scope, path traversal or outside scope or sensitive, protected write, dangerous shell, non-allowlisted destination, exfiltration after a secret read). Otherwise a risk score decides between allow and hold. When one agent acts for another, the effective scope is the intersection of both (confused-deputy defence).
- **Session state**: tool results update it. Instruction-like text sets an "injected" flag; a read of a sensitive path or confidential table sets "secret taint"; values (URLs, emails, paths, commands) found in tool output are remembered so a later call whose arguments were copied from output, and not from the user's task, can be flagged.
- **Approval queue** (`approvals.py`): SQLite. An approver atomically claims the oldest pending request for a lease; an expired lease returns it to the pool; undecided requests expire and count as denials.
- **Audit log** (`audit.py`): every decision is a JSON line chained by SHA-256, with a small HMAC-signed anchor holding the latest sequence and hash so truncation is detectable. `python -m warrantgate verify` checks it.
- **Proxy** (`proxy.py`): MCP stdio transport (newline-delimited JSON-RPC). Only `tools/call` is judged; a blocked call returns an error result the agent can read and is never forwarded.
