"""Per-agent tokens: base64url(json payload) + "." + base64url(HMAC-SHA256). No third-party JWT library."""
import base64
import hashlib
import hmac
import json
import time


class TokenError(Exception):
    pass


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def mint(key: bytes, agent: str, scopes, ttl: int = 3600, now: float | None = None) -> str:
    payload = {"agent": agent, "scopes": sorted(scopes), "exp": int((now if now is not None else time.time()) + ttl)}
    body = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    return body + "." + _b64(hmac.new(key, body.encode(), hashlib.sha256).digest())


def verify(key: bytes, token: str, now: float | None = None) -> dict:
    """Returns the payload, or raises TokenError (bad shape, bad signature, expired)."""
    try:
        body, sig = token.split(".")
        expected = hmac.new(key, body.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _unb64(sig)):
            raise TokenError("bad signature")
        payload = json.loads(_unb64(body))
    except TokenError:
        raise
    except Exception as e:  # malformed anything
        raise TokenError("malformed token") from e
    if payload.get("exp", 0) < (now if now is not None else time.time()):
        raise TokenError("expired")
    return payload
