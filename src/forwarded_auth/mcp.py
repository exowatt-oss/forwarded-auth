"""Centralized FastMCP transport-security helper.

Background: FastMCP ships a DNS-rebinding guard
(``TransportSecuritySettings.enable_dns_rebinding_protection``) that
checks the inbound ``Host:`` header against an ``allowed_hosts`` list.
FastMCP's own default list is loopback-only, so an MCP server hosted behind any
reverse proxy that preserves the inbound Host header returns a
**421 Misdirected Request** on every public request unless the app's
own public hostname(s) are in that list.

``build_transport_security()`` reads the configured trusted hostnames
(``FORWARDED_AUTH_TRUSTED_HOSTNAMES``, comma-separated) and returns a
ready-to-use ``TransportSecuritySettings``. Loopback/testserver entries
are added only in ``mode=none`` (local dev) or when
``FORWARDED_AUTH_ALLOW_LOOPBACK_HOSTS`` is explicitly true; in
forwarded/oidc mode they are never added by default:

    from mcp.server.fastmcp import FastMCP
    from forwarded_auth.mcp import build_transport_security

    mcp = FastMCP("my-app", transport_security=build_transport_security())

Lazy import of ``mcp.server.transport_security``: that package is only
needed by apps that actually expose an MCP surface, so it is not a
base runtime dependency of this package (install the ``mcp`` extra).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from forwarded_auth._settings import MODE_NONE, Settings, _warn_once, get_settings

if TYPE_CHECKING:  # pragma: no cover — typing-only import
    from mcp.server.transport_security import TransportSecuritySettings

_DEV_ALLOWED_HOSTS = (
    "127.0.0.1:*",
    "localhost:*",
    "[::1]:*",
    "testserver",
)

_DEV_ALLOWED_ORIGINS = (
    "http://127.0.0.1:*",
    "http://localhost:*",
    "http://[::1]:*",
)


def loopback_allowed(settings: Settings) -> bool:
    """True if the loopback/testserver allowlist entries apply: an explicit
    ``allow_loopback_hosts`` wins; otherwise only ``mode=none``."""
    if settings.allow_loopback_hosts is not None:
        return settings.allow_loopback_hosts
    return settings.mode == MODE_NONE


def build_transport_security(
    extra_allowed_hosts: list[str] | None = None,
    extra_allowed_origins: list[str] | None = None,
    *,
    settings: Settings | None = None,
) -> TransportSecuritySettings:
    """Build a ``TransportSecuritySettings`` covering this app's trusted
    hostnames.

    Each hostname from ``Settings.trusted_hostnames`` contributes:

    - ``<host>`` and ``<host>:*`` to ``allowed_hosts`` (the bare form
      covers the default-port case; the ``:*`` wildcard form covers any
      other port suffix — FastMCP's matcher treats them as distinct).
    - ``https://<host>`` to ``allowed_origins``.

    Args:
        extra_allowed_hosts: Additional hosts to allow on top of the
            configured list.
        extra_allowed_origins: Additional origins, same shape.
        settings: Explicit settings; defaults to :func:`get_settings`.

    Returns:
        A ``TransportSecuritySettings`` ready to pass to
        ``FastMCP(..., transport_security=...)``.
        ``enable_dns_rebinding_protection`` is always ``True`` —
        disabling it defeats the whole point of the guard.

    Raises:
        ImportError: if the ``mcp`` package isn't installed. Install
            the optional extra: ``forwarded-auth[mcp]``.
    """
    try:
        from mcp.server.transport_security import TransportSecuritySettings
    except ImportError as exc:  # pragma: no cover — exercised in tests via meta-path block
        raise ImportError(
            "forwarded_auth.mcp.build_transport_security() requires the MCP SDK. "
            "Install the optional extra: `uv add 'forwarded-auth[mcp]'` "
            "(or `pip install 'forwarded-auth[mcp]'`)."
        ) from exc

    settings = settings or get_settings()

    allowed_hosts: list[str] = []
    allowed_origins: list[str] = []
    if loopback_allowed(settings):
        allowed_hosts.extend(_DEV_ALLOWED_HOSTS)
        allowed_origins.extend(_DEV_ALLOWED_ORIGINS)
        if settings.mode != MODE_NONE:
            _warn_once(
                "mcp_loopback_opt_in",
                "forwarded_auth.mcp: loopback/testserver hosts and http://localhost origins "
                "are allowed in mode=%s (FORWARDED_AUTH_ALLOW_LOOPBACK_HOSTS=true). Not for "
                "a production MCP endpoint.",
                settings.mode,
            )

    for host in settings.trusted_hostnames:
        allowed_hosts.append(host)
        allowed_hosts.append(f"{host}:*")
        allowed_origins.append(f"https://{host}")

    if extra_allowed_hosts:
        allowed_hosts.extend(extra_allowed_hosts)
    if extra_allowed_origins:
        allowed_origins.extend(extra_allowed_origins)

    if not allowed_hosts:
        _warn_once(
            "mcp_no_allowed_hosts",
            "forwarded_auth.mcp: no allowed hosts (FORWARDED_AUTH_TRUSTED_HOSTNAMES is empty "
            "and loopback hosts are not enabled), so every MCP request will be "
            "rejected. Set FORWARDED_AUTH_TRUSTED_HOSTNAMES to this app's public hostname(s).",
        )

    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
    )


__all__ = ["build_transport_security", "loopback_allowed"]
