from __future__ import annotations

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from forwarded_auth._settings import ConfigurationError, Settings, configure
from forwarded_auth.fastapi import current_user, require_user

from .conftest import JwksTestServer, make_token_claims


def _build_app() -> FastAPI:
    app = FastAPI()

    @app.get("/optional")
    def optional_route(user=Depends(current_user)):  # noqa: B008
        return {"email": user.email if user else None}

    @app.get("/required")
    def required_route(user=Depends(require_user)):  # noqa: B008
        return {"email": user.email}

    return app


def _settings(jwks_server: JwksTestServer, **overrides: object) -> Settings:
    base = dict(
        issuer=jwks_server.issuer,
        audience=("my-client",),
        jwks_url=jwks_server.jwks_uri,
        allowed_email_domains=frozenset({"*"}),
    )
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


class TestCurrentUser:
    def test_no_auth_header_returns_none(self, jwks_server: JwksTestServer) -> None:
        configure(_settings(jwks_server))
        client = TestClient(_build_app())
        resp = client.get("/optional")
        assert resp.status_code == 200
        assert resp.json() == {"email": None}

    def test_valid_bearer_returns_user(self, jwks_server: JwksTestServer) -> None:
        configure(_settings(jwks_server))
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        token = jwks_server.mint_token("kid-primary", claims)
        client = TestClient(_build_app())
        resp = client.get("/optional", headers={"Authorization": f"Bearer {token}"})
        assert resp.json() == {"email": "alice@example.com"}

    def test_invalid_bearer_swallowed_as_none(self, jwks_server: JwksTestServer) -> None:
        configure(_settings(jwks_server))
        client = TestClient(_build_app())
        resp = client.get("/optional", headers={"Authorization": "Bearer garbage"})
        assert resp.status_code == 200
        assert resp.json() == {"email": None}


class TestRequireUser:
    def test_no_auth_header_is_401(self, jwks_server: JwksTestServer) -> None:
        configure(_settings(jwks_server))
        client = TestClient(_build_app())
        resp = client.get("/required")
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Authentication required"

    def test_invalid_bearer_is_401_with_generic_detail(self, jwks_server: JwksTestServer) -> None:
        configure(_settings(jwks_server))
        client = TestClient(_build_app())
        resp = client.get("/required", headers={"Authorization": "Bearer garbage"})
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Authentication required"
        assert "garbage" not in resp.text

    def test_valid_bearer_returns_user(self, jwks_server: JwksTestServer) -> None:
        configure(_settings(jwks_server))
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        token = jwks_server.mint_token("kid-primary", claims)
        client = TestClient(_build_app())
        resp = client.get("/required", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json() == {"email": "alice@example.com"}


class TestConfigurationErrorPropagation:
    def test_missing_config_propagates_uncaught_from_required_route(
        self, jwks_server: JwksTestServer
    ) -> None:
        # No allowed_email_domains configured: a misconfiguration, not a
        # failed auth attempt — must NOT be swallowed into a 401.
        configure(Settings(issuer=jwks_server.issuer, audience=("my-client",)))
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        token = jwks_server.mint_token("kid-primary", claims)
        client = TestClient(_build_app(), raise_server_exceptions=True)
        with pytest.raises(ConfigurationError):
            client.get("/required", headers={"Authorization": f"Bearer {token}"})

    def test_missing_config_propagates_uncaught_from_optional_route(
        self, jwks_server: JwksTestServer
    ) -> None:
        configure(Settings(issuer=jwks_server.issuer, audience=("my-client",)))
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        token = jwks_server.mint_token("kid-primary", claims)
        client = TestClient(_build_app(), raise_server_exceptions=True)
        with pytest.raises(ConfigurationError):
            client.get("/optional", headers={"Authorization": f"Bearer {token}"})
