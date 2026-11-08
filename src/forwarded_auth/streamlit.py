"""Streamlit integration for ``forwarded-auth``.

Streamlit doesn't have request middleware in the FastAPI sense — every
script run is a single request, and headers are exposed via
``st.context.headers``. The helpers here read them and either return
the user or short-circuit the script with ``st.stop()``.

- ``current_user()`` — return the current ``User`` or ``None``.
- ``require_user()`` — return the user, or ``st.error`` + ``st.stop()``.
- ``render_profile_widget()`` — render the "Signed in as ··· Sign out"
  pill in the top-right of the page.

All three only ever convert :class:`InvalidIdentityToken` (a bad/missing
bearer) into ``None``/a stopped script. A :class:`ConfigurationError`
(a misconfigured deployment) propagates uncaught — Streamlit renders
its own exception page — by design; call ``Settings.validate()`` once
at the top of your app to catch it before rendering anything.
"""

from __future__ import annotations

import logging

import streamlit as st

from forwarded_auth._jwks import InvalidIdentityToken
from forwarded_auth._settings import Settings
from forwarded_auth._user import User, user_from_headers
from forwarded_auth.widget import profile_widget_html

_logger = logging.getLogger(__name__)


def _request_headers() -> dict[str, str]:
    """Lift ``st.context.headers`` to a plain dict. Requires
    Streamlit >= 1.37 (``st.context``); older versions used
    ``_get_websocket_headers`` and are not supported."""
    if not hasattr(st, "context") or not hasattr(st.context, "headers"):
        return {}
    return dict(st.context.headers)


def current_user(*, settings: Settings | None = None) -> User | None:
    """Return the current ``User``, or ``None`` if the request didn't
    carry a verifiable identity or a bearer was present but failed
    verification. Swallows :class:`InvalidIdentityToken` — surfacing
    "your token didn't verify" is ``require_user``'s job."""
    try:
        return user_from_headers(_request_headers(), settings=settings)
    except InvalidIdentityToken as exc:
        _logger.info("Identity token verification failed in current_user: %s", exc)
        return None


def require_user(*, settings: Settings | None = None) -> User:
    """Return the user, or render an error and stop the script.

    Use at the top of any page that requires auth:

        from forwarded_auth.streamlit import require_user
        user = require_user()
        st.title(f"Welcome, {user.display_name}")
    """
    try:
        user = user_from_headers(_request_headers(), settings=settings)
    except InvalidIdentityToken as exc:
        _logger.warning("Identity token verification failed in require_user: %s", exc)
        user = None
    if user is None:
        st.error(
            "Not authenticated. This app expects to run behind an auth proxy "
            "that forwards a verified identity. If you're seeing this in "
            "production, check your proxy/issuer configuration. For local "
            'development, see the README\'s "none" mode / dev-escape options.'
        )
        st.stop()
    return user


def render_profile_widget(
    redirect_to: str | None = None, *, settings: Settings | None = None
) -> None:
    """Render the "Signed in as <email> · Sign out" widget.

    No-op when there's no user — keeps local dev friction-free without
    forcing apps to branch on ``current_user() is None``.
    """
    user = current_user(settings=settings)
    if user is None:
        return
    st.markdown(
        profile_widget_html(user, redirect_to=redirect_to, settings=settings),
        unsafe_allow_html=True,
    )
