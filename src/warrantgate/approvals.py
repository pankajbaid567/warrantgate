"""Human-approval queue in SQLite with leases.

A held call is a row. An approver claims the oldest pending row for a lease period (atomically, so two approvers never
get the same one); a claim that is not decided before the lease expires goes back to the pool. Requests nobody decides
within their deadline become 'expired', which the gateway treats as a denial.
"""
import json
import sqlite3
import threading
import time
import uuid


class ApprovalQueue:
    def __init__(self, path: str = ":memory:"):
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=30)
        self._lock = threading.Lock()
        self._db.execute("PRAGMA journal_mode=WAL") if path != ":memory:" else None
        self._db.execute("""CREATE TABLE IF NOT EXISTS approvals (
            id TEXT PRIMARY KEY, session TEXT, agent TEXT, tool TEXT, args TEXT, reason TEXT,
            status TEXT NOT NULL DEFAULT 'pending', created REAL, deadline REAL,
            lease_owner TEXT, lease_until REAL, decided_by TEXT, decided_at REAL)""")

    def _tx(self):
        return _Tx(self._db, self._lock)

    def submit(self, session: str, agent: str, tool: str, args: dict, reason: str, timeout: float = 300) -> str:
        rid, now = uuid.uuid4().hex, time.time()
        with self._tx() as db:
            db.execute("INSERT INTO approvals (id,session,agent,tool,args,reason,created,deadline) VALUES (?,?,?,?,?,?,?,?)",
                       (rid, session, agent, tool, json.dumps(args, sort_keys=True), reason, now, now + timeout))
        return rid

    def claim_next(self, owner: str, lease: float = 60):
        """Atomically lease the oldest undecided request to `owner`, or return None."""
        now = time.time()
        with self._tx() as db:
            db.execute("UPDATE approvals SET status='expired' WHERE status='pending' AND deadline < ?", (now,))
            row = db.execute("""SELECT id FROM approvals WHERE status='pending' AND (lease_until IS NULL OR lease_until < ?)
                                ORDER BY created LIMIT 1""", (now,)).fetchone()
            if not row:
                return None
            db.execute("UPDATE approvals SET lease_owner=?, lease_until=? WHERE id=?", (owner, now + lease, row[0]))
            return self._get(db, row[0])

    def decide(self, rid: str, approver: str, approve: bool) -> bool:
        """Records a decision. Only the current lease holder, or anyone if there is no live lease, may decide a pending request."""
        now = time.time()
        with self._tx() as db:
            cur = db.execute("""UPDATE approvals SET status=?, decided_by=?, decided_at=?
                                WHERE id=? AND status='pending' AND deadline >= ?
                                  AND (lease_owner IS NULL OR lease_owner=? OR lease_until < ?)""",
                             ("approved" if approve else "denied", approver, now, rid, now, approver, now))
            return cur.rowcount == 1

    def status(self, rid: str) -> str:
        now = time.time()
        with self._tx() as db:
            db.execute("UPDATE approvals SET status='expired' WHERE id=? AND status='pending' AND deadline < ?", (rid, now))
            r = db.execute("SELECT status FROM approvals WHERE id=?", (rid,)).fetchone()
        return r[0] if r else "unknown"

    def wait(self, rid: str, timeout: float, poll: float = 0.05) -> str:
        end = time.time() + timeout
        while time.time() < end:
            s = self.status(rid)
            if s != "pending":
                return s
            time.sleep(poll)
        return self.status(rid)

    def pending(self):
        with self._tx() as db:
            return [self._row(r) for r in db.execute("SELECT * FROM approvals WHERE status='pending' ORDER BY created")]

    def _get(self, db, rid):
        cur = db.execute("SELECT * FROM approvals WHERE id=?", (rid,))
        return self._row(cur.fetchone(), cur.description)

    @staticmethod
    def _row(r, desc=None):
        cols = ["id", "session", "agent", "tool", "args", "reason", "status", "created", "deadline", "lease_owner", "lease_until", "decided_by", "decided_at"]
        d = dict(zip(cols, r))
        d["args"] = json.loads(d["args"])
        return d


class _Tx:
    def __init__(self, db, lock):
        self.db, self.lock = db, lock

    def __enter__(self):
        self.lock.acquire()
        self.db.execute("BEGIN IMMEDIATE")
        return self.db

    def __exit__(self, et, ev, tb):
        try:
            self.db.execute("ROLLBACK" if et else "COMMIT")
        finally:
            self.lock.release()
