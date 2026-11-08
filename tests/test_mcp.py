from __future__ import annotations

import sys

import pytest

from forwarded_auth._settings import Settings
from forwarded_auth.mcp import build_transport_security


def test_default_allows_only_loopback_and_testserver() -> None:
    settings = build_transport_security(settings=Settings())
    assert "testserver" in settings.allowed_hosts
    assert "127.0.0.1:*" in settings.allowed_hosts
    assert "app.example.com" not in settings.allowed_hosts


def test_configured_hostnames_are_added() -> None:
    settings = build_transport_security(settings=Settings(trusted_hostnames=("app.example.com",)))
    assert "app.example.com" in settings.allowed_hosts
    assert "app.example.com:*" in settings.allowed_hosts
    assert "https://app.example.com" in settings.allowed_origins


def test_multiple_hostnames() -> None:
    settings = build_transport_security(
        settings=Settings(trusted_hostnames=("a.example.com", "b.example.com"))
    )
    assert "a.example.com" in settings.allowed_hosts
    assert "b.example.com" in settings.allowed_hosts


def test_extra_hosts_and_origins_appended() -> None:
    settings = build_transport_security(
        extra_allowed_hosts=["custom.example.com"],
        extra_allowed_origins=["https://custom.example.com"],
        settings=Settings(),
    )
    assert "custom.example.com" in settings.allowed_hosts
    assert "https://custom.example.com" in settings.allowed_origins


def test_dns_rebinding_protection_always_enabled() -> None:
    settings = build_transport_security(settings=Settings())
    assert settings.enable_dns_rebinding_protection is True


def test_missing_mcp_sdk_raises_actionable_import_error(monkeypatch: pytest.MonkeyPatch) -> None:
    # `sys.modules[name] = None` is the standard way to force Python's
    # import machinery to raise ImportError for that module, simulating
    # the MCP SDK not being installed, without uninstalling it for the
    # rest of the suite.
    monkeypatch.setitem(sys.modules, "mcp.server.transport_security", None)
    with pytest.raises(ImportError, match="forwarded-auth\\[mcp\\]"):
        build_transport_security(settings=Settings())
