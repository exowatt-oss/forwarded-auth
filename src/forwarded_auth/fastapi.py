"""FastAPI integration for ``forwarded-auth``.

Two affordances:

- ``current_user`` — a FastAPI dependency returning the current
  ``User`` or ``None`` if the request didn't carry a verifiable
  identity.
- ``require_user`` — like ``current_user`` but raises
  ``HTTPException(401)`` if no user is present.

Both dependencies only ever convert :class:`InvalidIdentityToken` (a
bad/missing bearer) into a 401 or ``None``. A :class:`ConfigurationError`
(a misconfigured deployment — missing issuer/audience/email-domain
allowlist for the selected mode) deliberately propagates uncaught,
surfacing as FastAPI's default 500 — misconfiguration is an operator
bug, not a caller's failed auth attempt, and should fail loudly. Call
``Settings.validate()`` at app startup to catch it before the first
real request instead.
"""

from __future__ import annotations

import logging

from fastapi import HTTPException, Request, status

from forwarded_auth._jwks import InvalidIdentityToken
from forwarded_auth._user import User, user_from_headers

_logger = logging.getLogger(__name__)


def current_user(request: Request) -> User | None:
    """FastAPI dependency: returns the current ``User`` or ``None``.

    Use for endpoints that work with or without auth. Swallows
    :class:`InvalidIdentityToken` (returning ``None``) so a misbehaving
    caller doesn't take down an optional-auth endpoint — surfacing "your
    token didn't verify" is ``require_user``'s job.
    """
    try:
        return user_from_headers(dict(request.headers))
    except InvalidIdentityToken as exc:
        _logger.info("Identity token verification failed on optional-auth route: %s", exc)
        return None


def require_user(request: Request) -> User:
    """FastAPI dependency: returns the current ``User`` or raises 401.

    Use as ``Depends(require_user)`` on routes that require an
    authenticated user. Raises ``HTTPException(401)`` both when no
    identity is present and when a bearer was present but failed
    verification — the verification reason is logged at warning level
    for operator triage, but the response body only ever says
    "Authentication required" (never echo the failure reason to a
    caller probing the surface).
    """
    try:
        user = user_from_headers(dict(request.headers))
    except InvalidIdentityToken as exc:
        _logger.warning("Identity token verification failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required"
        ) from exc
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required"
        )
    return user
