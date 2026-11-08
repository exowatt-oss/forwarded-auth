from __future__ import annotations

from forwarded_auth._settings import Settings
from forwarded_auth._user import User
from forwarded_auth.widget import profile_widget_html


def test_widget_html_contains_email_and_signout_link() -> None:
    user = User(email="alice@example.com", name="Alice", user_id="1")
    html = profile_widget_html(user, settings=Settings())
    assert "alice@example.com" in html
    assert "Sign out" in html
    assert "forwarded-auth-widget" in html


def test_widget_escapes_email() -> None:
    user = User(email='alice"><script>@example.com', name="Alice", user_id="1")
    html = profile_widget_html(user, settings=Settings())
    assert "<script>" not in html


def test_widget_respects_redirect_to() -> None:
    user = User(email="alice@example.com", name="Alice", user_id="1")
    html = profile_widget_html(user, redirect_to="/post-logout", settings=Settings())
    assert "%2Fpost-logout" in html


def test_widget_uses_configured_logout_base() -> None:
    user = User(email="alice@example.com", name="Alice", user_id="1")
    settings = Settings(logout_url_base="https://auth.example.com/oauth2/sign_out")
    html = profile_widget_html(user, settings=settings)
    assert "https://auth.example.com/oauth2/sign_out" in html
