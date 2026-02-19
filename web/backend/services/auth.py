"""Azure Container Apps built-in authentication middleware.

When deployed behind Azure Container Apps with Entra ID authentication enabled,
the platform injects identity headers into every request:
  - X-MS-CLIENT-PRINCIPAL-NAME: user's email/UPN
  - X-MS-CLIENT-PRINCIPAL-ID: user's object ID
  - X-MS-CLIENT-PRINCIPAL: base64-encoded claims

In local development (AUTH_ENABLED=false), auth is bypassed.
"""
import base64
import json
from dataclasses import dataclass
from typing import Optional

from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from ..config import settings


@dataclass
class UserIdentity:
    name: str
    object_id: str
    claims: dict


def get_user_identity(request: Request) -> Optional[UserIdentity]:
    """Extract user identity from Azure Container Apps auth headers."""
    name = request.headers.get("X-MS-CLIENT-PRINCIPAL-NAME")
    oid = request.headers.get("X-MS-CLIENT-PRINCIPAL-ID", "")
    principal = request.headers.get("X-MS-CLIENT-PRINCIPAL", "")

    if not name:
        return None

    claims = {}
    if principal:
        try:
            decoded = base64.b64decode(principal)
            claims = json.loads(decoded)
        except (ValueError, json.JSONDecodeError):
            pass

    return UserIdentity(name=name, object_id=oid, claims=claims)


class AuthMiddleware(BaseHTTPMiddleware):
    """Middleware that enforces Entra ID authentication when AUTH_ENABLED=true."""

    async def dispatch(self, request: Request, call_next):
        # Skip auth for health check and WebSocket upgrade
        if request.url.path in ("/health", "/ws/logs"):
            return await call_next(request)

        # Skip auth for static files
        if not request.url.path.startswith("/api"):
            return await call_next(request)

        if settings.auth_enabled:
            identity = get_user_identity(request)
            if not identity:
                raise HTTPException(status_code=401, detail="Authentication required")
            request.state.user = identity
        else:
            request.state.user = None

        return await call_next(request)
