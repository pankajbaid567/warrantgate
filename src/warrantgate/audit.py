"""Hash-chained audit log.

Each line is {"seq", "ts", "prev", "event", "hash"} with hash = SHA-256(prev + canonical JSON of seq, ts, event).
Changing, deleting or reordering a record breaks the chain at that point. Truncating the tail would not, so every
append also rewrites a small anchor file (seq + hash) signed with an HMAC key; verification checks the last record
against it. Someone who holds the signing key can rewrite everything: this is tamper-EVIDENCE, not tamper-proofing.
"""
import hashlib
import hmac
import json
import os
import threading
import time
from dataclasses import dataclass

GENESIS = "0" * 64


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _hash(prev: str, seq: int, ts: float, event: dict) -> str:
    return hashlib.sha256((prev + _canon({"seq": seq, "ts": ts, "event": event})).encode()).hexdigest()


def _anchor_mac(key: bytes, seq: int, h: str) -> str:
    return hmac.new(key, f"{seq}:{h}".encode(), hashlib.sha256).hexdigest()


@dataclass
class Verdict:
    ok: bool
    records: int
    reason: str = ""
    bad_seq: int | None = None


class AuditLog:
    def __init__(self, path: str, key: bytes):
        self.path, self.anchor_path, self.key = path, path + ".anchor", key
        self._lock = threading.Lock()
        self.seq, self.head = 0, GENESIS
        if os.path.exists(path):
            v = verify(path, key)
            if not v.ok:
                raise ValueError(f"audit log failed verification: {v.reason} (seq {v.bad_seq})")
            with open(path, "r", encoding="utf-8") as f:
                last = None
                for last in f:
                    pass
            if last:
                r = json.loads(last)
                self.seq, self.head = r["seq"], r["hash"]

    def append(self, event: dict) -> dict:
        with self._lock:
            seq, ts = self.seq + 1, round(time.time(), 6)
            h = _hash(self.head, seq, ts, event)
            rec = {"seq": seq, "ts": ts, "prev": self.head, "event": event, "hash": h}
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(_canon(rec) + "\n")
                f.flush()
                os.fsync(f.fileno())
            tmp = self.anchor_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"seq": seq, "hash": h, "mac": _anchor_mac(self.key, seq, h)}, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.anchor_path)
            self.seq, self.head = seq, h
            return rec


def verify(path: str, key: bytes) -> Verdict:
    prev, n = GENESIS, 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                n += 1
                try:
                    r = json.loads(line)
                except ValueError:
                    return Verdict(False, n - 1, "unparseable record", n)
                if r.get("seq") != n:
                    return Verdict(False, n - 1, f"sequence gap or reorder: expected {n}, found {r.get('seq')}", n)
                if r.get("prev") != prev:
                    return Verdict(False, n - 1, "chain broken: previous hash does not match", n)
                if _hash(prev, r["seq"], r["ts"], r["event"]) != r.get("hash"):
                    return Verdict(False, n - 1, "record content does not match its hash", n)
                prev = r["hash"]
    except FileNotFoundError:
        return Verdict(False, 0, "log file missing")
    try:
        with open(path + ".anchor", "r", encoding="utf-8") as f:
            a = json.load(f)
    except (FileNotFoundError, ValueError):
        return Verdict(False, n, "anchor missing or unreadable (cannot rule out truncation)")
    if not hmac.compare_digest(a.get("mac", ""), _anchor_mac(key, a.get("seq", -1), a.get("hash", ""))):
        return Verdict(False, n, "anchor signature invalid")
    if a["seq"] != n or a["hash"] != prev:
        return Verdict(False, n, f"log ends at record {n} but the signed anchor says {a['seq']}: truncated or extended", n)
    return Verdict(True, n)
