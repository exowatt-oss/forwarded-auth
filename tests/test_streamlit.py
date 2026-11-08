"""Tests for the Streamlit integration.

Streamlit's runtime (``st.context.headers``, ``st.error``, ``st.stop``)
only works inside a real Streamlit script run. Rather than spinning one
up, we install a stand-in ``streamlit`` module before importing
``forwarded_auth.streamlit`` — enough to verify the integration's own
logic (header pulling, user-vs-stop branching, widget rendering)
without a Streamlit install at test time.
"""

from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

import pytest

from forwarded_auth._settings import MODE_NONE, ConfigurationError, Settings

from .conftest import JwksTestServer, make_token_claims


@pytest.fixture
def streamlit_module():
    fake = types.ModuleType("streamlit")
    fake.context = types.SimpleNamespace(headers={})
    fake.error = MagicMock()
    fake.stop = MagicMock(side_effect=SystemExit)
    fake.markdown = MagicMock()
    sys.modules["streamlit"] = fake

    sys.modules.pop("forwarded_auth.streamlit", None)
    import forwarded_auth as _parent

    if hasattr(_parent, "streamlit"):
        delattr(_parent, "streamlit")

    yield fake

    sys.modules.pop("streamlit", None)
    sys.modules.pop("forwarded_auth.streamlit", None)
    if hasattr(_parent, "streamlit"):
        delattr(_parent, "streamlit")


def _settings(jwks_server: JwksTestServer, **overrides: object) -> Settings:
    base = dict(
        issuer=jwks_server.issuer,
        audience=("my-client",),
        jwks_url=jwks_server.jwks_uri,
        allowed_email_domains=frozenset({"*"}),
    )
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


def test_current_user_reads_from_st_context_headers(
    streamlit_module, jwks_server: JwksTestServer
) -> None:
    import forwarded_auth.streamlit as fa_streamlit

    claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
    token = jwks_server.mint_token("kid-primary", claims)
    streamlit_module.context.headers = {"Authorization": f"Bearer {token}"}

    user = fa_streamlit.current_user(settings=_settings(jwks_server))
    assert user is not None
    assert user.email == "alice@example.com"


def test_current_user_none_mode_returns_dev_user(streamlit_module) -> None:
    import forwarded_auth.streamlit as fa_streamlit

    streamlit_module.context.headers = {}
    settings = Settings(mode=MODE_NONE, allow_insecure_none_mode=True)
    user = fa_streamlit.current_user(settings=settings)
    assert user is not None
    assert user.email == "dev@localhost"


def test_current_user_swallows_invalid_token(streamlit_module, jwks_server: JwksTestServer) -> None:
    import forwarded_auth.streamlit as fa_streamlit

    streamlit_module.context.headers = {"Authorization": "Bearer garbage"}
    user = fa_streamlit.current_user(settings=_settings(jwks_server))
    assert user is None


def test_require_user_returns_user_when_present(
    streamlit_module, jwks_server: JwksTestServer
) -> None:
    import forwarded_auth.streamlit as fa_streamlit

    claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
    token = jwks_server.mint_token("kid-primary", claims)
    streamlit_module.context.headers = {"Authorization": f"Bearer {token}"}

    user = fa_streamlit.require_user(settings=_settings(jwks_server))
    assert user.email == "alice@example.com"
    streamlit_module.error.assert_not_called()
    streamlit_module.stop.assert_not_called()


def test_require_user_stops_script_when_absent(
    streamlit_module, jwks_server: JwksTestServer
) -> None:
    import forwarded_auth.streamlit as fa_streamlit

    streamlit_module.context.headers = {}
    with pytest.raises(SystemExit):
        fa_streamlit.require_user(settings=_settings(jwks_server))
    streamlit_module.error.assert_called_once()
    streamlit_module.stop.assert_called_once()


def test_require_user_stops_script_on_invalid_token(
    streamlit_module, jwks_server: JwksTestServer
) -> None:
    import forwarded_auth.streamlit as fa_streamlit

    streamlit_module.context.headers = {"Authorization": "Bearer garbage"}
    with pytest.raises(SystemExit):
        fa_streamlit.require_user(settings=_settings(jwks_server))
    streamlit_module.error.assert_called_once()


def test_render_profile_widget_noop_without_user(
    streamlit_module, jwks_server: JwksTestServer
) -> None:
    import forwarded_auth.streamlit as fa_streamlit

    streamlit_module.context.headers = {}
    fa_streamlit.render_profile_widget(settings=_settings(jwks_server))
    streamlit_module.markdown.assert_not_called()


def test_render_profile_widget_renders_html(streamlit_module, jwks_server: JwksTestServer) -> None:
    import forwarded_auth.streamlit as fa_streamlit

    claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
    token = jwks_server.mint_token("kid-primary", claims)
    streamlit_module.context.headers = {"Authorization": f"Bearer {token}"}

    fa_streamlit.render_profile_widget(settings=_settings(jwks_server))
    streamlit_module.markdown.assert_called_once()
    html_arg = streamlit_module.markdown.call_args.args[0]
    assert "alice@example.com" in html_arg
    assert "Sign out" in html_arg


def test_request_headers_missing_context_returns_empty(streamlit_module) -> None:
    import forwarded_auth.streamlit as fa_streamlit

    del streamlit_module.context
    assert fa_streamlit._request_headers() == {}


def test_require_user_propagates_configuration_error_uncaught(
    streamlit_module, jwks_server: JwksTestServer
) -> None:
    import forwarded_auth.streamlit as fa_streamlit

    # A bearer IS present, but allowed_email_domains isn't configured: a
    # misconfiguration, not a failed auth attempt -- must not be swallowed
    # into st.error()/st.stop().
    claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
    token = jwks_server.mint_token("kid-primary", claims)
    streamlit_module.context.headers = {"Authorization": f"Bearer {token}"}
    settings = Settings(issuer=jwks_server.issuer, audience=("my-client",))
    with pytest.raises(ConfigurationError):
        fa_streamlit.require_user(settings=settings)
    streamlit_module.error.assert_not_called()
    streamlit_module.stop.assert_not_called()


def test_current_user_propagates_configuration_error_uncaught(
    streamlit_module, jwks_server: JwksTestServer
) -> None:
    import forwarded_auth.streamlit as fa_streamlit

    claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
    token = jwks_server.mint_token("kid-primary", claims)
    streamlit_module.context.headers = {"Authorization": f"Bearer {token}"}
    settings = Settings(issuer=jwks_server.issuer, audience=("my-client",))
    with pytest.raises(ConfigurationError):
        fa_streamlit.current_user(settings=settings)
