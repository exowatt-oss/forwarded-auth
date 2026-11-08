from __future__ import annotations

from forwarded_auth._settings import Settings, configure
from forwarded_auth.logout import default_logout_redirect, logout_url


def test_default_logout_url_is_relative_with_no_default_host() -> None:
    url = logout_url(settings=Settings())
    assert url == "/oauth2/sign_out?rd=%2F"


def test_logout_url_with_custom_redirect() -> None:
    url = logout_url("/my-page?x=1", settings=Settings())
    assert url == "/oauth2/sign_out?rd=%2Fmy-page%3Fx%3D1"


def test_logout_url_with_configured_absolute_base() -> None:
    settings = Settings(
        logout_url_base="https://auth.example.com/oauth2/sign_out",
        default_logout_redirect="https://app.example.com/",
    )
    assert logout_url(settings=settings) == (
        "https://auth.example.com/oauth2/sign_out?rd=https%3A%2F%2Fapp.example.com%2F"
    )


def test_default_logout_redirect_reads_settings() -> None:
    assert default_logout_redirect(Settings(default_logout_redirect="/home")) == "/home"


def test_logout_url_uses_global_settings_when_configured() -> None:
    configure(Settings(logout_url_base="/custom/sign-out", default_logout_redirect="/landing"))
    try:
        assert logout_url() == "/custom/sign-out?rd=%2Flanding"
    finally:
        configure(None)
