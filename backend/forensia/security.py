"""Transport hardening for the local api service (THREAT_MODEL gates 1-3, 12).

- Per-session token, generated in memory at startup (never written to disk, never in argv).
- Host-header allowlist (anti DNS-rebinding).
- Exact-origin CORS (set by the server factory, not a localhost regex).
"""

from __future__ import annotations

import secrets

from fastapi import Header, HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def allowed_hosts(port: int) -> set[str]:
    return {f"127.0.0.1:{port}", f"localhost:{port}"}


class HostHeaderMiddleware(BaseHTTPMiddleware):
    """Reject any request whose Host header is not our exact loopback host:port."""

    def __init__(self, app, hosts: set[str]) -> None:
        super().__init__(app)
        self._hosts = hosts

    async def dispatch(self, request: Request, call_next):
        host = request.headers.get("host", "")
        if host not in self._hosts:
            return JSONResponse({"detail": "bad host header"}, status_code=403)
        return await call_next(request)


def require_token(request: Request, x_forensia_token: str = Header(default="")) -> None:
    """Constant-time check of the per-session token on protected routes."""
    expected = getattr(request.app.state, "token", None)
    if not expected or not secrets.compare_digest(x_forensia_token, expected):
        raise HTTPException(status_code=401, detail="invalid or missing session token")
