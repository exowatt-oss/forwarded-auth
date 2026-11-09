from __future__ import annotations

import sys

import pytest

from forwarded_auth._settings import Settings
from forwarded_auth.mcp import build_transport_security

_LOOPBACK_HOSTS = {"127.0.0.1:*", "localhost:*", "[::1]:*", "testserver"}
_LOOPBACK_ORIGINS = {"http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"}


def _none_mode(**kw: object) -> Settings:
    return Settings(mode="none", allow_insecure_none_mode=True, **kw)  # type: ignore[arg-type]


def test_forwarded_mode_default_adds_no_loopback_hosts_or_origins() -> None:
    settings = build_transport_security(settings=Settings(trusted_hostnames=("app.example.com",)))
    assert _LOOPBACK_HOSTS.isdisjoint(settings.allowed_hosts)
    assert _LOOPBACK_ORIGINS.isdisjoint(settings.allowed_origins)
    assert settings.allowed_hosts == ["app.example.com", "app.example.com:*"]
    assert settings.allowed_origins == ["https://app.example.com"]


def test_oidc_mode_default_adds_no_loopback() -> None:
    settings = build_transport_security(settings=Settings(mode="oidc"))
    assert settings.allowed_hosts == []
    assert settings.allowed_origins == []


def test_forwarded_mode_with_nothing_configured_is_empty_and_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    from forwarded_auth._settings import _reset_warned_for_tests

    _reset_warned_for_tests()
    with caplog.at_level("WARNING"):
        settings = build_transport_security(settings=Settings())
    assert settings.allowed_hosts == []
    assert settings.allowed_origins == []
    assert "every MCP request will be rejected" in caplog.text


def test_none_mode_adds_loopback_and_testserver() -> None:
    settings = build_transport_security(settings=_none_mode())
    assert _LOOPBACK_HOSTS <= set(settings.allowed_hosts)
    assert _LOOPBACK_ORIGINS <= set(settings.allowed_origins)


def test_explicit_opt_in_adds_loopback_in_forwarded_mode() -> None:
    settings = build_transport_security(
        settings=Settings(trusted_hostnames=("app.example.com",), allow_loopback_hosts=True)
    )
    assert _LOOPBACK_HOSTS <= set(settings.allowed_hosts)
    assert _LOOPBACK_ORIGINS <= set(settings.allowed_origins)
    assert "app.example.com" in settings.allowed_hosts


def test_explicit_opt_out_drops_loopback_even_in_none_mode() -> None:
    settings = build_transport_security(settings=_none_mode(allow_loopback_hosts=False))
    assert _LOOPBACK_HOSTS.isdisjoint(settings.allowed_hosts)
    assert _LOOPBACK_ORIGINS.isdisjoint(settings.allowed_origins)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, None),
        ("", None),
        ("  ", None),
        ("true", True),
        ("1", True),
        ("false", False),
        ("0", False),
    ],
)
def test_allow_loopback_env_is_tristate(
    monkeypatch: pytest.MonkeyPatch, raw: str | None, expected: bool | None
) -> None:
    if raw is None:
        monkeypatch.delenv("FORWARDED_AUTH_ALLOW_LOOPBACK_HOSTS", raising=False)
    else:
        monkeypatch.setenv("FORWARDED_AUTH_ALLOW_LOOPBACK_HOSTS", raw)
    assert Settings.from_env().allow_loopback_hosts is expected


def test_forwarded_mode_rejects_localhost_origin_end_to_end() -> None:
    """The production default must not let `Origin: http://localhost:*` through."""
    from mcp.server.transport_security import TransportSecurityMiddleware

    ts = build_transport_security(settings=Settings(trusted_hostnames=("app.example.com",)))
    mw = TransportSecurityMiddleware(ts)
    assert mw._validate_host("app.example.com") is True
    assert mw._validate_origin("https://app.example.com") is True
    assert mw._validate_origin("http://localhost:3000") is False
    assert mw._validate_host("localhost:8000") is False
    assert mw._validate_host("testserver") is False


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


def test_missing_origin_passes_and_missing_host_fails() -> None:
    """Documents FastMCP's behaviour under our settings: a non-browser client with
    no Origin passes the Origin check, but a request with no Host never passes."""
    from mcp.server.transport_security import TransportSecurityMiddleware

    ts = build_transport_security(settings=Settings(trusted_hostnames=("app.example.com",)))
    mw = TransportSecurityMiddleware(ts)
    assert mw._validate_origin(None) is True
    assert mw._validate_host(None) is False


def test_extra_hosts_alone_suppress_the_empty_warning(caplog: pytest.LogCaptureFixture) -> None:
    from forwarded_auth._settings import _reset_warned_for_tests

    _reset_warned_for_tests()
    with caplog.at_level("WARNING"):
        build_transport_security(extra_allowed_hosts=["custom.example.com"], settings=Settings())
    assert "every MCP request will be rejected" not in caplog.text


def test_opt_in_outside_none_mode_warns(caplog: pytest.LogCaptureFixture) -> None:
    from forwarded_auth._settings import _reset_warned_for_tests

    _reset_warned_for_tests()
    with caplog.at_level("WARNING"):
        build_transport_security(settings=Settings(allow_loopback_hosts=True))
    assert "Not for a production MCP endpoint" in caplog.text
