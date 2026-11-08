"""Logout URL helper.

There is no default host — a generic library can't guess where your
auth proxy's sign-out endpoint lives. The default ``logout_url_base``
is a *relative* path (``/oauth2/sign_out``, oauth2-proxy's standard
default route) that works when the auth proxy is mounted on the same
host as your app (the common reverse-proxy shape). Set
``FORWARDED_AUTH_LOGOUT_URL_BASE`` to an absolute URL if your auth
proxy lives on a different host — see ``docs/oauth2-proxy-caddy.md``
for a worked example.
"""

from __future__ import annotations

import urllib.parse

from forwarded_auth._settings import Settings, get_settings


def default_logout_redirect(settings: Settings | None = None) -> str:
    """The URL ``logout_url()`` redirects to when no override is
    passed. A function (not a constant) so apps/tests can introspect
    or override without monkey-patching a module attribute."""
    settings = settings or get_settings()
    return settings.default_logout_redirect


def logout_url(redirect_to: str | None = None, *, settings: Settings | None = None) -> str:
    """Return the configured logout URL, with ``redirect_to`` (or the
    configured default) URL-encoded into the ``rd`` query param —
    oauth2-proxy's convention, and a reasonable one for most auth
    proxies that support a post-logout redirect.

    Drop this into a "Sign out" link:

        <a href="{logout_url()}">Sign out</a>

    Validating that ``redirect_to`` is a safe, same-site target is the
    auth proxy's job, not this library's — configure your proxy's own
    redirect allowlist (e.g. oauth2-proxy's ``--whitelist-domain``) so
    an attacker-supplied ``redirect_to`` can't be used for an open
    redirect after logout.
    """
    settings = settings or get_settings()
    rd = redirect_to or settings.default_logout_redirect
    return f"{settings.logout_url_base}?rd={urllib.parse.quote(rd, safe='')}"
