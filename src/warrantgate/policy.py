"""The decision engine. A call is judged against the agent's scope, hard rules, and what the session has seen so far.

Order: token -> scope (effective scope = intersection when acting for another agent) -> class rules -> risk score.
Hard rules deny. Otherwise the risk score decides between allow and hold (human approval).
"""
import posixpath
import re
import tomllib
from dataclasses import dataclass, field
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s\"'<>)]+")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
PATH_RE = re.compile(r"(?<![\w.])/(?:[\w.\-]+/)*[\w.\-]+")
CMD_RE = re.compile(r"(?:^|\n)\s*[$>]\s*(.+)")


@dataclass
class Decision:
    action: str            # allow | hold | deny
    rule: str              # short stable id of the deciding rule
    reason: str
    risk: float = 0.0


@dataclass
class Session:
    """What the gateway remembers about one agent run."""
    id: str
    user_task: str = ""
    injected: bool = False
    secret_taint: bool = False
    secret_snippets: list = field(default_factory=list)
    untrusted_values: set = field(default_factory=set)
    distinct_reads: set = field(default_factory=set)
    trusted_values: set = field(default_factory=set)

    def __post_init__(self):
        self.trusted_values = extract_values(self.user_task)


def extract_values(text: str) -> set:
    vals = set()
    for m in URL_RE.findall(text or ""):
        vals.add(m.rstrip(".,;"))
        host = urlparse(m).hostname
        if host:
            vals.add(host)
    vals.update(EMAIL_RE.findall(text or ""))
    vals.update(p for p in PATH_RE.findall(text or "") if len(p) > 4)
    vals.update(c.strip() for c in CMD_RE.findall(text or ""))
    return vals


def _walk_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _walk_strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _walk_strings(v)


class Policy:
    def __init__(self, data: dict):
        self.d = data
        self.tools = data["tools"]
        self.risk = data["risk"]
        s = data["sensitive"]
        self.sensitive = [re.compile(p) for p in s["path_patterns"]]
        self.protected_write = [re.compile(p) for p in s["protected_write_patterns"]]
        self.confidential_tables = set(s["confidential_tables"])
        self.exec_deny = [re.compile(p) for p in data["exec"]["deny_patterns"]]
        self.safe_prefixes = tuple(data["exec"]["safe_prefixes"])
        self.injection = [re.compile(p) for p in data["injection"]["patterns"]]
        self.bulk_limit = data["bulk"]["distinct_reads_before_egress"]
        self.agents = data["agents"]

    @classmethod
    def load(cls, path: str):
        with open(path, "rb") as f:
            return cls(tomllib.load(f))

    # ------------------------------------------------------------------ result handling
    def observe_result(self, session: Session, tool: str, args: dict, content: str):
        """Update the session from a tool's output. Output is data, never instructions."""
        content = content or ""
        if any(p.search(content) for p in self.injection):
            session.injected = True
        session.untrusted_values |= extract_values(content)
        if self._is_confidential_source(tool, args):
            session.secret_taint = True
            if content.strip():
                session.secret_snippets.append(content)

    def _is_confidential_source(self, tool: str, args: dict) -> bool:
        if tool == "db.query":
            sql = str(args.get("sql", "")).lower()
            return any(re.search(rf"\b{t}\b", sql) for t in self.confidential_tables)
        path = args.get("path")
        return isinstance(path, str) and any(p.search(path) for p in self.sensitive)

    # ------------------------------------------------------------------ decisions
    def decide(self, session: Session, agent: str, tool: str, args: dict, origin: str | None = None) -> Decision:
        cls = self.tools.get(tool)
        if cls is None:
            return Decision("deny", "unknown-tool", f"tool '{tool}' is not registered")
        cfg = self.agents.get(agent)
        if cfg is None:
            return Decision("deny", "unknown-agent", f"agent '{agent}' has no policy")
        effective = [cfg]
        if origin and origin != agent:
            ocfg = self.agents.get(origin)
            if ocfg is None:
                return Decision("deny", "unknown-origin", f"request originates from unknown agent '{origin}'")
            effective.append(ocfg)  # confused-deputy defence: the caller may use only what BOTH agents may use
        for c in effective:
            if cls not in c.get("classes", []):
                who = "originating agent" if c is not cfg else "agent"
                return Decision("deny", "class-not-in-scope", f"{who} is not allowed to use {cls} tools ({tool})")

        if cls in ("read", "write") and tool.startswith("fs."):
            d = self._check_path(session, effective, tool, cls, args)
            if d:
                return d
        if tool == "db.query":
            d = self._check_query(effective, args)
            if d:
                return d
        if cls == "exec":
            d = self._check_exec(args)
            if d:
                return d
        if cls == "egress":
            d = self._check_egress(session, cfg, effective, tool, args)
            if d:
                return d
        if cls == "admin" and any(c.get("admin_requires_approval") for c in effective):
            return Decision("hold", "admin-needs-approval", f"{tool} always needs a human", 1.0)

        risk = self.risk["base"][cls]
        reasons = [f"base {risk:.2f} for {cls}"]
        if cls != "read" and self._provenance(session, args):
            risk += self.risk["provenance_bonus"]
            reasons.append("argument copied from untrusted tool output")
            if session.injected:  # instruction-like text alone is not evidence (fixtures and blog posts quote it); combined with a copied value it is
                risk += self.risk["injected_bonus"]
                reasons.append("and the session saw instruction-like content")
        if session.secret_taint and cls in ("write", "exec"):
            risk += self.risk["secret_bonus"]
            reasons.append("session has read confidential data")
        if tool.startswith("fs.") and cls == "read":
            session.distinct_reads.add(args.get("path"))
        risk = min(risk, 1.0)
        if risk >= self.risk["hold_at"]:
            return Decision("hold", "risk-score", "; ".join(reasons), risk)
        return Decision("allow", "allowed", "; ".join(reasons), risk)

    # ------------------------------------------------------------------ rule helpers
    def _norm(self, p) -> str | None:
        if not isinstance(p, str) or not p or "\x00" in p:
            return None
        return posixpath.normpath(p if p.startswith("/") else "/" + p)

    def _check_path(self, session, effective, tool, cls, args):
        raw = args.get("path")
        path = self._norm(raw)
        if path is None:
            return Decision("deny", "bad-path", "missing or malformed path")
        if ".." in str(raw).split("/"):
            return Decision("deny", "path-traversal", f"path '{raw}' uses '..'")
        for c in effective:
            if not any(path.startswith(pre) for pre in c.get("paths", [])):
                return Decision("deny", "path-outside-scope", f"{path} is outside the allowed paths")
        if any(p.search(path) for p in self.sensitive):
            if not all(any(path.startswith(sp) for sp in c.get("secret_paths", [])) for c in effective):
                return Decision("deny", "sensitive-path", f"{path} matches a sensitive path pattern")
        if cls == "write" and any(p.search(path) for p in self.protected_write):
            return Decision("deny", "protected-write", f"{path} is a protected configuration path")
        return None

    def _check_query(self, effective, args):
        sql = str(args.get("sql", ""))
        if re.search(r"(?i)\b(insert|update|delete|drop|alter|grant|truncate)\b", sql):
            return Decision("deny", "db-write", "only read-only queries are allowed")
        used = set(re.findall(r"(?i)\b(?:from|join)\s+([a-z_][\w]*)", sql))
        for c in effective:
            allowed = set(c.get("tables", []))
            if allowed and not used <= allowed:
                return Decision("deny", "table-not-in-scope", f"tables {sorted(used - allowed)} are not allowed")
            if not allowed and used:
                return Decision("deny", "table-not-in-scope", "this agent may not query tables")
        return None

    def _check_exec(self, args):
        cmd = str(args.get("command", ""))
        for p in self.exec_deny:
            if p.search(cmd):
                return Decision("deny", "dangerous-command", f"command matches deny pattern {p.pattern[:40]}")
        if cmd.startswith(self.safe_prefixes) and not re.search(r"[;&|`$<>\n]", cmd):
            return None
        return Decision("hold", "unreviewed-command", "shell command is not on the safe list", 0.9)

    def _check_egress(self, session, cfg, effective, tool, args):
        targets = []
        if tool == "email.send":
            to = args.get("to", "")
            targets = [(a.split("@")[-1].lower(), "email_domains") for a in ([to] if isinstance(to, str) else list(to))]
        elif tool == "git.push":
            targets = [("github.com", "egress_domains")]
        else:
            host = urlparse(str(args.get("url", ""))).hostname
            if not host:
                return Decision("deny", "bad-url", "missing or malformed url")
            targets = [(host.lower(), "egress_domains")]
        for host, key in targets:
            for c in effective:
                if host not in [h.lower() for h in c.get(key, [])]:
                    return Decision("deny", "egress-not-allowlisted", f"{host} is not an allowed destination")
        if session.secret_taint:
            ok = all(h in [x.lower() for x in cfg.get("secret_ok_domains", [])] for h, _ in targets)
            if not ok:
                return Decision("deny", "exfiltration-after-secret-read", "this session read confidential data; sending anything out is blocked")
        if len(session.distinct_reads) >= self.bulk_limit:
            return Decision("hold", "bulk-read-then-egress", f"{len(session.distinct_reads)} distinct files were read before sending data out", 0.8)
        if self._provenance(session, args) and session.injected:
            return Decision("deny", "injected-destination", "destination or content came from instruction-like untrusted output")
        return None

    def _provenance(self, session, args) -> bool:
        """True if some argument value was taken from untrusted tool output and was not given by the user."""
        for s in _walk_strings(args):
            for v in extract_values(s) | {s}:
                if v in session.untrusted_values and v not in session.trusted_values and len(v) > 6:
                    return True
        return False
