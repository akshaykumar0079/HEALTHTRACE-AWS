"""Role-based access (docs/privacy-and-retention.md).

Roles, lowest to highest:

* ``viewer``   read incidents, timelines, logs;
* ``operator`` + acknowledge / investigate / resolve / reopen / pin / mute, run simulations;
* ``admin``    + notification settings, test notifications, AWS tests, retention.

A caller proves its role with the ``X-Operator-Token`` header: ``VIEWER_TOKEN``,
``OPERATOR_TOKEN`` or ``ADMIN_TOKEN``. Tokens are compared in constant time and
never logged. With no tokens configured and auth not required (local
development) every caller acts as ``local`` with all rights, and the security
status endpoint says so loudly. In production (or ``REQUIRE_OPERATOR_TOKEN``)
missing configuration closes the controls instead of opening them.

Responses: no/invalid token -> 401; valid token but too low a role -> 403.
"""

from __future__ import annotations

import hmac
import logging
from dataclasses import dataclass
from typing import Optional

from fastapi import Header, HTTPException, Request

logger = logging.getLogger(__name__)

ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2}

PERMISSIONS: dict[str, list[str]] = {
    "viewer": ["view incidents, timelines, events, simulation results"],
    "operator": ["acknowledge, investigate, resolve, reopen, pin and mute incidents", "run simulations"],
    "admin": ["change notification settings", "send test notifications", "run retention cleanup", "AWS tests"],
}


@dataclass(frozen=True)
class Caller:
    role: str          # viewer | operator | admin
    actor: str         # name written to the audit log
    authenticated: bool
    open_access: bool  # True when no auth is configured (local development)


def _match(candidate: Optional[str], expected: str) -> bool:
    return bool(candidate and expected) and hmac.compare_digest(candidate.encode(), expected.encode())


def resolve_caller(settings, token: Optional[str]) -> Optional[Caller]:
    """The caller for this token, or None when the token is missing/invalid
    but one is required."""
    if _match(token, settings.admin_token):
        return Caller("admin", "admin", True, False)
    if _match(token, settings.operator_token):
        # Without a separate ADMIN_TOKEN the operator token also holds admin rights.
        return Caller("admin" if not settings.admin_token else "operator", "operator", True, False)
    if _match(token, settings.viewer_token):
        return Caller("viewer", "viewer", True, False)
    return None


def configured_tokens(settings) -> bool:
    return bool(settings.operator_token or settings.admin_token or settings.viewer_token)


def read_requires_auth(settings) -> bool:
    return bool(settings.require_view_auth or settings.viewer_token)


def caller_for(request: Request, token: Optional[str]) -> Caller:
    settings = request.app.state.pipeline.settings
    found = resolve_caller(settings, token)
    if found is not None:
        return found
    if token:  # a token was sent but matches nothing
        logger.warning("rejected request with an invalid token to %s %s", request.method, request.url.path)
    if not configured_tokens(settings):
        # Nothing configured: closed in production, open for local development.
        if settings.auth_required:
            return Caller("viewer", "anonymous", False, False)
        return Caller("admin", "local", False, True)
    return Caller("viewer", "anonymous", False, False)


def read_access(request: Request, x_operator_token: Optional[str] = Header(default=None)) -> Caller:
    """Router-level dependency: reads need a token only when VIEWER_TOKEN is set
    or REQUIRE_VIEW_AUTH=true. Health checks are always open."""
    settings = request.app.state.pipeline.settings
    caller = caller_for(request, x_operator_token)
    if request.url.path.endswith("/health"):
        return caller
    if read_requires_auth(settings) and not caller.authenticated:
        raise HTTPException(status_code=401, detail="authentication required to view data")
    return caller


def require_role(minimum: str):
    def dependency(request: Request, x_operator_token: Optional[str] = Header(default=None)) -> str:
        settings = request.app.state.pipeline.settings
        caller = caller_for(request, x_operator_token)
        if caller.open_access:
            return caller.actor
        if not configured_tokens(settings) and settings.auth_required:
            raise HTTPException(status_code=403, detail="operator access is not configured on this server")
        if not caller.authenticated:
            raise HTTPException(status_code=401, detail="operator token required")
        if ROLE_RANK[caller.role] < ROLE_RANK[minimum]:
            logger.warning("role %s denied %s %s (needs %s)", caller.role, request.method, request.url.path, minimum)
            raise HTTPException(status_code=403, detail=f"{minimum} role required")
        return caller.actor

    return dependency


require_operator = require_role("operator")
require_admin = require_role("admin")
