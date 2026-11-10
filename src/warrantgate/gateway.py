"""The gateway core: token check, policy decision, approval, audit. Transport-independent (stdio proxy and HTTP use it)."""
import threading
import time
from dataclasses import dataclass

from . import tokens
from .approvals import ApprovalQueue
from .audit import AuditLog
from .policy import Decision, Policy, Session


@dataclass
class Outcome:
    allowed: bool
    action: str           # allow | hold-approved | hold-denied | hold-expired | deny
    rule: str
    reason: str
    decision_ms: float = 0.0


class Gateway:
    def __init__(self, policy: Policy, token_key: bytes, audit: AuditLog | None = None, approvals: ApprovalQueue | None = None,
                 approval_timeout: float = 300):
        self.policy, self.key, self.audit, self.approvals = policy, token_key, audit, approvals
        self.approval_timeout = approval_timeout
        self.sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def session(self, sid: str, user_task: str = "") -> Session:
        with self._lock:
            s = self.sessions.get(sid)
            if s is None:
                s = self.sessions[sid] = Session(sid, user_task)
            return s

    def _log(self, **event):
        if self.audit:
            self.audit.append(event)

    def decide(self, sid: str, token: str, tool: str, args: dict, origin: str | None = None) -> tuple[Decision, str]:
        """Policy decision only (no waiting for a human). Returns (decision, agent)."""
        sess = self.session(sid)
        try:
            claims = tokens.verify(self.key, token)
        except tokens.TokenError as e:
            return Decision("deny", "invalid-token", f"token rejected: {e}"), "?"
        agent = claims["agent"]
        cfg = self.policy.agents.get(agent, {})
        # a token may only narrow what the policy gives the agent, never widen it
        granted = set(claims.get("scopes", []))
        cls = self.policy.tools.get(tool)
        if cls is not None and cls not in granted:
            return Decision("deny", "token-scope", f"token for '{agent}' does not grant {cls} tools"), agent
        return self.policy.decide(sess, agent, tool, args, origin), agent

    def call(self, sid: str, token: str, tool: str, args: dict, origin: str | None = None, wait: bool = True) -> Outcome:
        t0 = time.perf_counter()
        d, agent = self.decide(sid, token, tool, args, origin)
        ms = (time.perf_counter() - t0) * 1000
        if d.action == "allow":
            self._log(kind="call", session=sid, agent=agent, tool=tool, args=args, origin=origin, decision="allow", rule=d.rule, risk=d.risk)
            return Outcome(True, "allow", d.rule, d.reason, ms)
        if d.action == "deny":
            self._log(kind="call", session=sid, agent=agent, tool=tool, args=args, origin=origin, decision="deny", rule=d.rule, reason=d.reason)
            return Outcome(False, "deny", d.rule, d.reason, ms)
        # hold
        if self.approvals is None or not wait:
            self._log(kind="call", session=sid, agent=agent, tool=tool, args=args, origin=origin, decision="hold", rule=d.rule, reason=d.reason, risk=d.risk)
            return Outcome(False, "hold-denied", d.rule, d.reason + " (no approver available)", ms)
        rid = self.approvals.submit(sid, agent, tool, args, d.reason, self.approval_timeout)
        self._log(kind="hold", session=sid, agent=agent, tool=tool, args=args, approval=rid, rule=d.rule, reason=d.reason, risk=d.risk)
        status = self.approvals.wait(rid, self.approval_timeout)
        self._log(kind="approval", session=sid, approval=rid, status=status)
        if status == "approved":
            return Outcome(True, "hold-approved", d.rule, d.reason, ms)
        return Outcome(False, "hold-expired" if status == "expired" else "hold-denied", d.rule, d.reason, ms)

    def result(self, sid: str, tool: str, args: dict, content: str):
        """Feed a tool's output back so later decisions can use what the session has seen."""
        self.policy.observe_result(self.session(sid), tool, args, content)
        self._log(kind="result", session=sid, tool=tool, bytes=len(content or ""))
