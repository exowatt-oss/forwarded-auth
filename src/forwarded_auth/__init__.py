"""Typed ``User`` from identity headers forwarded by an auth proxy.

Background: a common deployment shape puts an auth proxy (oauth2-proxy,
etc.) in front of an app behind a reverse proxy configured for
``forward_auth``. After a successful sign-in, the proxy populates
identity headers on the upstream request (email, user id, preferred
username) plus an ``Authorization: Bearer <id_token>`` header carrying
the raw token.

This library verifies that bearer token's signature against the
issuer's JWKS, parses the claims into a typed ``User``, and gives you
a profile widget, a logout-URL helper, and FastAPI/Streamlit/MCP
integrations. It never trusts the identity headers on their own by
default — see the README's "Security model" section.

Three integration paths:

- **FastAPI**: ``from forwarded_auth.fastapi import current_user, require_user``
- **Streamlit**: ``from forwarded_auth.streamlit import (current_user,
  require_user, render_profile_widget)``
- **Anything else**: ``from forwarded_auth import user_from_headers`` and
  pass whatever request-headers mapping you have. Catch
  ``InvalidIdentityToken`` and 401 if a bearer was present but failed
  verification.
"""

from forwarded_auth._jwks import InvalidIdentityToken
from forwarded_auth._settings import (
    MODE_FORWARDED,
    MODE_NONE,
    MODE_OIDC,
    VALID_MODES,
    ConfigurationError,
    Settings,
    configure,
    get_settings,
)
from forwarded_auth._user import (
    AUTH_HEADER_BEARER_PREFIX,
    User,
    dev_user,
    user_from_headers,
    verify_id_token,
    verify_token,
)
from forwarded_auth.logout import default_logout_redirect, logout_url
from forwarded_auth.widget import profile_widget_html

__all__ = [
    "AUTH_HEADER_BEARER_PREFIX",
    "MODE_FORWARDED",
    "MODE_NONE",
    "MODE_OIDC",
    "VALID_MODES",
    "ConfigurationError",
    "InvalidIdentityToken",
    "Settings",
    "User",
    "configure",
    "default_logout_redirect",
    "dev_user",
    "get_settings",
    "logout_url",
    "profile_widget_html",
    "user_from_headers",
    "verify_id_token",
    "verify_token",
]

__version__ = "0.1.1"
