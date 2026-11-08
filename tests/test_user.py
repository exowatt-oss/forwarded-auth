from __future__ import annotations

import logging

import pytest

from forwarded_auth._jwks import InvalidIdentityToken
from forwarded_auth._settings import (
    MODE_FORWARDED,
    MODE_NONE,
    MODE_OIDC,
    ConfigurationError,
    Settings,
)
from forwarded_auth._user import (
    AUTH_HEADER_BEARER_PREFIX,
    User,
    dev_user,
    user_from_headers,
    verify_id_token,
    verify_token,
)

from .conftest import JwksTestServer, make_additional_issuer_claims, make_token_claims


def _forwarded_settings(jwks_server: JwksTestServer, **overrides: object) -> Settings:
    base = dict(
        issuer=jwks_server.issuer,
        audience=("my-client",),
        jwks_url=jwks_server.jwks_uri,
        allowed_email_domains=frozenset({"*"}),
    )
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


class TestForwardedMode:
    def test_valid_bearer_builds_user(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        token = jwks_server.mint_token("kid-primary", claims)
        headers = {"Authorization": f"Bearer {token}"}
        user = user_from_headers(headers, settings=_forwarded_settings(jwks_server))
        assert user == User(
            email="alice@example.com",
            name="Alice Example",
            user_id="1234567890",
            bearer_token=token,
            picture="https://example.com/avatar.jpg",
        )

    def test_no_bearer_no_proxy_headers_returns_none(self, jwks_server: JwksTestServer) -> None:
        assert user_from_headers({}, settings=_forwarded_settings(jwks_server)) is None

    def test_invalid_bearer_raises(self, jwks_server: JwksTestServer) -> None:
        headers = {"Authorization": "Bearer not-a-real-jwt"}
        with pytest.raises(InvalidIdentityToken):
            user_from_headers(headers, settings=_forwarded_settings(jwks_server))

    def test_spoofed_email_header_with_valid_token_rejected(
        self, jwks_server: JwksTestServer
    ) -> None:
        claims = make_token_claims(
            iss=jwks_server.issuer, aud="my-client", email="alice@example.com"
        )
        token = jwks_server.mint_token("kid-primary", claims)
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Auth-Request-Email": "ceo@example.com",
        }
        with pytest.raises(InvalidIdentityToken, match="does not match"):
            user_from_headers(headers, settings=_forwarded_settings(jwks_server))

    def test_matching_email_header_is_fine(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(
            iss=jwks_server.issuer, aud="my-client", email="alice@example.com"
        )
        token = jwks_server.mint_token("kid-primary", claims)
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Auth-Request-Email": "alice@example.com",
        }
        user = user_from_headers(headers, settings=_forwarded_settings(jwks_server))
        assert user is not None
        assert user.email == "alice@example.com"

    def test_spoofed_headers_without_jwt_rejected_by_default(
        self, jwks_server: JwksTestServer
    ) -> None:
        headers = {
            "X-Auth-Request-Email": "ceo@example.com",
            "X-Auth-Request-User": "evil-sub",
        }
        # No Authorization header at all: strict default refuses to trust
        # the headers alone.
        assert user_from_headers(headers, settings=_forwarded_settings(jwks_server)) is None

    def test_wrong_audience_raises(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="someone-elses-client")
        token = jwks_server.mint_token("kid-primary", claims)
        headers = {"Authorization": f"Bearer {token}"}
        with pytest.raises(InvalidIdentityToken, match="audience"):
            user_from_headers(headers, settings=_forwarded_settings(jwks_server))

    def test_wrong_issuer_raises(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(iss="https://not-trusted.invalid", aud="my-client")
        token = jwks_server.mint_token("kid-primary", claims)
        headers = {"Authorization": f"Bearer {token}"}
        with pytest.raises(InvalidIdentityToken, match="issuer"):
            user_from_headers(headers, settings=_forwarded_settings(jwks_server))

    def test_expired_token_raises(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(
            iss=jwks_server.issuer,
            aud="my-client",
            exp_offset=-10,
            nbf_offset=-120,
            iat_offset=-120,
        )
        token = jwks_server.mint_token("kid-primary", claims)
        headers = {"Authorization": f"Bearer {token}"}
        with pytest.raises(InvalidIdentityToken, match="expired"):
            user_from_headers(headers, settings=_forwarded_settings(jwks_server))

    def test_email_domain_allowlist_rejects_outside_domain(
        self, jwks_server: JwksTestServer
    ) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client", email="alice@evil.com")
        token = jwks_server.mint_token("kid-primary", claims)
        headers = {"Authorization": f"Bearer {token}"}
        settings = _forwarded_settings(
            jwks_server, allowed_email_domains=frozenset({"example.com"})
        )
        with pytest.raises(InvalidIdentityToken, match="allowlist"):
            user_from_headers(headers, settings=settings)

    def test_email_domain_allowlist_accepts_inside_domain(
        self, jwks_server: JwksTestServer
    ) -> None:
        claims = make_token_claims(
            iss=jwks_server.issuer, aud="my-client", email="alice@example.com"
        )
        token = jwks_server.mint_token("kid-primary", claims)
        headers = {"Authorization": f"Bearer {token}"}
        settings = _forwarded_settings(
            jwks_server, allowed_email_domains=frozenset({"example.com"})
        )
        user = user_from_headers(headers, settings=settings)
        assert user is not None

    def test_no_name_falls_back_to_preferred_username_header(
        self, jwks_server: JwksTestServer
    ) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client", name=None, picture=None)
        token = jwks_server.mint_token("kid-primary", claims)
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Auth-Request-Preferred-Username": "alice-handle",
        }
        user = user_from_headers(headers, settings=_forwarded_settings(jwks_server))
        assert user is not None
        assert user.name == "alice-handle"

    def test_no_name_no_header_falls_back_to_email(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client", name=None, picture=None)
        token = jwks_server.mint_token("kid-primary", claims)
        headers = {"Authorization": f"Bearer {token}"}
        user = user_from_headers(headers, settings=_forwarded_settings(jwks_server))
        assert user is not None
        assert user.name == "alice@example.com"
        assert user.display_name == "alice@example.com"

    def test_missing_email_claim_returns_none(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        del claims["email"]
        token = jwks_server.mint_token("kid-primary", claims)
        headers = {"Authorization": f"Bearer {token}"}
        assert user_from_headers(headers, settings=_forwarded_settings(jwks_server)) is None

    def test_misconfigured_missing_issuer_raises_configuration_error(self) -> None:
        settings = Settings(audience=("x",))
        headers = {"Authorization": "Bearer whatever"}
        with pytest.raises(ConfigurationError):
            user_from_headers(headers, settings=settings)

    def test_is_bot_false_for_ordinary_user(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        token = jwks_server.mint_token("kid-primary", claims)
        headers = {"Authorization": f"Bearer {token}"}
        user = user_from_headers(headers, settings=_forwarded_settings(jwks_server))
        assert user is not None
        assert user.is_bot is False


class TestOidcMode:
    def test_valid_bearer_builds_user_via_discovery(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        token = jwks_server.mint_token("kid-primary", claims)
        settings = Settings(
            mode=MODE_OIDC,
            issuer=jwks_server.issuer,
            audience=("my-client",),
            allowed_email_domains=frozenset({"*"}),
        )
        headers = {"Authorization": f"Bearer {token}"}
        user = user_from_headers(headers, settings=settings)
        assert user is not None
        assert user.email == "alice@example.com"

    def test_no_bearer_returns_none_no_proxy_assumed(self, jwks_server: JwksTestServer) -> None:
        settings = Settings(
            mode=MODE_OIDC,
            issuer=jwks_server.issuer,
            audience=("my-client",),
            allowed_email_domains=frozenset({"*"}),
        )
        assert user_from_headers({}, settings=settings) is None

    def test_derives_userinfo_url_from_discovery_when_unset(
        self, jwks_server: JwksTestServer
    ) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client", name=None, picture=None)
        token = jwks_server.mint_token("kid-primary", claims)
        jwks_server.userinfo_response = {
            "sub": claims["sub"],
            "name": "Discovered Name",
            "picture": "https://example.com/discovered.jpg",
        }
        settings = Settings(
            mode=MODE_OIDC,
            issuer=jwks_server.issuer,
            audience=("my-client",),
            allowed_email_domains=frozenset({"*"}),
            access_token_headers=("X-Forwarded-Access-Token",),
        )
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Forwarded-Access-Token": "some-access-token",
        }
        user = user_from_headers(headers, settings=settings)
        assert user is not None
        assert user.name == "Discovered Name"
        assert user.picture == "https://example.com/discovered.jpg"


class TestAdditionalIssuer:
    def _settings(self, jwks_server: JwksTestServer, additional_issuer: str) -> Settings:
        return Settings(
            issuer="https://primary-issuer.invalid",
            audience=("primary-aud",),
            jwks_url="http://127.0.0.1:1/jwks",
            allowed_email_domains=frozenset({"*"}),
            additional_issuer=additional_issuer,
            additional_issuer_jwks_url=jwks_server.jwks_uri,
            additional_issuer_audience="svc-aud",
        )

    def test_matching_issuer_routes_to_additional_verifier(
        self, jwks_server: JwksTestServer
    ) -> None:
        claims = make_additional_issuer_claims(iss=jwks_server.issuer, aud="svc-aud")
        token = jwks_server.mint_token("kid-primary", claims)
        settings = self._settings(jwks_server, jwks_server.issuer)
        headers = {"Authorization": f"Bearer {token}"}
        user = user_from_headers(headers, settings=settings)
        assert user == User(
            email="owner@example.com",
            name="owner",
            user_id="owner@example.com",
            bearer_token=token,
            actor="svc-worker-1",
            scope="read:things",
        )
        assert user.is_bot is True

    def test_other_issuer_falls_through_to_primary_and_fails_closed(
        self, jwks_server: JwksTestServer
    ) -> None:
        # Token issued by neither the primary nor the additional issuer:
        # should attempt primary verification and fail (unreachable JWKS
        # in this settings fixture), never silently succeed.
        claims = make_token_claims(iss="https://someone-else.invalid", aud="primary-aud")
        token = jwks_server.mint_token("kid-primary", claims)
        settings = self._settings(jwks_server, jwks_server.issuer)
        headers = {"Authorization": f"Bearer {token}"}
        with pytest.raises(InvalidIdentityToken):
            user_from_headers(headers, settings=settings)

    def test_missing_additional_audience_raises(self, jwks_server: JwksTestServer) -> None:
        claims = make_additional_issuer_claims(iss=jwks_server.issuer, aud="svc-aud")
        token = jwks_server.mint_token("kid-primary", claims)
        settings = Settings(
            issuer="https://primary-issuer.invalid",
            audience=("primary-aud",),
            allowed_email_domains=frozenset({"*"}),
            additional_issuer=jwks_server.issuer,
            additional_issuer_jwks_url=jwks_server.jwks_uri,
            additional_issuer_audience=None,
        )
        headers = {"Authorization": f"Bearer {token}"}
        with pytest.raises(InvalidIdentityToken, match="AUDIENCE"):
            user_from_headers(headers, settings=settings)

    def test_empty_allowlist_raises_configuration_error_not_silent_admit(
        self, jwks_server: JwksTestServer
    ) -> None:
        """An empty `allowed_email_domains` must never silently admit every
        domain on the additional-issuer path -- it must fail closed with
        `ConfigurationError` before the token is even verified, the same
        as the primary-issuer path already requires."""
        claims = make_additional_issuer_claims(
            iss=jwks_server.issuer, aud="svc-aud", sub="owner@totally-unrelated-domain.example"
        )
        token = jwks_server.mint_token("kid-primary", claims)
        settings = Settings(
            issuer="https://primary-issuer.invalid",
            audience=("primary-aud",),
            jwks_url="http://127.0.0.1:1/jwks",
            allowed_email_domains=frozenset(),
            additional_issuer=jwks_server.issuer,
            additional_issuer_jwks_url=jwks_server.jwks_uri,
            additional_issuer_audience="svc-aud",
        )
        headers = {"Authorization": f"Bearer {token}"}
        with pytest.raises(ConfigurationError, match="ALLOWED_EMAIL_DOMAINS"):
            user_from_headers(headers, settings=settings)


class TestTrustedProxyHeaders:
    def test_disabled_by_default_even_with_headers_present(
        self, jwks_server: JwksTestServer
    ) -> None:
        headers = {
            "X-Forwarded-User-Email": "bob@example.com",
            "X-Forwarded-User-Id": "bob-id",
        }
        assert user_from_headers(headers, settings=_forwarded_settings(jwks_server)) is None

    def test_enabled_builds_user_from_proxy_headers(self, jwks_server: JwksTestServer) -> None:
        settings = _forwarded_settings(jwks_server, trust_proxy_headers=True)
        headers = {
            "X-Forwarded-User-Email": "bob@example.com",
            "X-Forwarded-User-Id": "bob-id",
            "X-Forwarded-User-Name": "Bob",
        }
        user = user_from_headers(headers, settings=settings)
        assert user == User(email="bob@example.com", name="Bob", user_id="bob-id")

    def test_enabled_without_email_header_falls_through(self, jwks_server: JwksTestServer) -> None:
        settings = _forwarded_settings(jwks_server, trust_proxy_headers=True)
        assert user_from_headers({}, settings=settings) is None

    def test_enabled_without_domains_configured_raises_configuration_error(
        self, jwks_server: JwksTestServer
    ) -> None:
        settings = _forwarded_settings(
            jwks_server, trust_proxy_headers=True, allowed_email_domains=frozenset()
        )
        headers = {"X-Forwarded-User-Email": "bob@example.com"}
        with pytest.raises(ConfigurationError, match="ALLOWED_EMAIL_DOMAINS"):
            user_from_headers(headers, settings=settings)

    def test_enabled_rejects_email_outside_allowlist(self, jwks_server: JwksTestServer) -> None:
        settings = _forwarded_settings(
            jwks_server,
            trust_proxy_headers=True,
            allowed_email_domains=frozenset({"example.com"}),
        )
        headers = {"X-Forwarded-User-Email": "bob@evil.com"}
        with pytest.raises(InvalidIdentityToken, match="allowlist"):
            user_from_headers(headers, settings=settings)

    def test_enabled_accepts_email_inside_allowlist(self, jwks_server: JwksTestServer) -> None:
        settings = _forwarded_settings(
            jwks_server,
            trust_proxy_headers=True,
            allowed_email_domains=frozenset({"example.com"}),
        )
        headers = {"X-Forwarded-User-Email": "bob@example.com"}
        user = user_from_headers(headers, settings=settings)
        assert user is not None
        assert user.email == "bob@example.com"

    def test_enabling_warns_once_per_process(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING):
            Settings(trust_proxy_headers=True, allowed_email_domains=frozenset({"*"}))
            Settings(trust_proxy_headers=True, allowed_email_domains=frozenset({"*"}))
        warnings = [r for r in caplog.records if "trust_proxy_headers=True is active" in r.message]
        assert len(warnings) == 1


class TestLegacyHeaderOnlyDevEscape:
    def test_require_jwt_false_trusts_headers_without_bearer(
        self, jwks_server: JwksTestServer
    ) -> None:
        settings = _forwarded_settings(jwks_server, require_jwt=False)
        headers = {"X-Auth-Request-Email": "dev@example.com"}
        user = user_from_headers(headers, settings=settings)
        assert user is not None
        assert user.email == "dev@example.com"

    def test_require_jwt_false_falls_back_on_invalid_bearer(
        self, jwks_server: JwksTestServer
    ) -> None:
        settings = _forwarded_settings(jwks_server, require_jwt=False)
        headers = {
            "Authorization": "Bearer not-a-real-jwt",
            "X-Auth-Request-Email": "dev@example.com",
        }
        user = user_from_headers(headers, settings=settings)
        assert user is not None
        assert user.email == "dev@example.com"

    def test_require_jwt_true_does_not_fall_back(self, jwks_server: JwksTestServer) -> None:
        settings = _forwarded_settings(jwks_server, require_jwt=True)
        headers = {
            "Authorization": "Bearer not-a-real-jwt",
            "X-Auth-Request-Email": "dev@example.com",
        }
        with pytest.raises(InvalidIdentityToken):
            user_from_headers(headers, settings=settings)

    def test_require_jwt_false_no_email_header_returns_none(
        self, jwks_server: JwksTestServer
    ) -> None:
        settings = _forwarded_settings(jwks_server, require_jwt=False)
        assert user_from_headers({}, settings=settings) is None


class TestNoneMode:
    def test_bare_none_mode_requires_second_ack(self) -> None:
        with pytest.raises(ConfigurationError, match="FORWARDED_AUTH_ALLOW_INSECURE_NONE_MODE"):
            Settings(mode=MODE_NONE)

    def test_returns_fixed_dev_user(self) -> None:
        settings = Settings(mode=MODE_NONE, allow_insecure_none_mode=True)
        user = user_from_headers({"Authorization": "Bearer irrelevant"}, settings=settings)
        assert user == User(email="dev@localhost", name="Local Dev User", user_id="dev@localhost")

    def test_ignores_headers_entirely(self) -> None:
        settings = Settings(mode=MODE_NONE, allow_insecure_none_mode=True)
        headers = {"X-Auth-Request-Email": "someone-else@example.com"}
        user = user_from_headers(headers, settings=settings)
        assert user is not None
        assert user.email == "dev@localhost"

    def test_configurable_dev_user(self) -> None:
        settings = Settings(
            mode=MODE_NONE,
            allow_insecure_none_mode=True,
            dev_user_email="me@localhost",
            dev_user_name="Me",
        )
        user = dev_user(settings)
        assert user.email == "me@localhost"
        assert user.name == "Me"

    def test_logs_loud_warning_once_at_construction(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING):
            settings = Settings(mode=MODE_NONE, allow_insecure_none_mode=True)
            dev_user(settings)
        assert any("mode=none" in record.message for record in caplog.records)


class TestRequireEmailVerified:
    def test_unverified_email_rejected_by_default(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        claims["email_verified"] = False
        token = jwks_server.mint_token("kid-primary", claims)
        headers = {"Authorization": f"Bearer {token}"}
        with pytest.raises(InvalidIdentityToken, match="email_verified"):
            user_from_headers(headers, settings=_forwarded_settings(jwks_server))

    def test_missing_email_verified_claim_rejected_by_default(
        self, jwks_server: JwksTestServer
    ) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        del claims["email_verified"]
        token = jwks_server.mint_token("kid-primary", claims)
        headers = {"Authorization": f"Bearer {token}"}
        with pytest.raises(InvalidIdentityToken, match="email_verified"):
            user_from_headers(headers, settings=_forwarded_settings(jwks_server))

    def test_string_true_is_accepted(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        claims["email_verified"] = "True"
        token = jwks_server.mint_token("kid-primary", claims)
        headers = {"Authorization": f"Bearer {token}"}
        user = user_from_headers(headers, settings=_forwarded_settings(jwks_server))
        assert user is not None

    def test_disabled_check_accepts_unverified_email(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        claims["email_verified"] = False
        token = jwks_server.mint_token("kid-primary", claims)
        headers = {"Authorization": f"Bearer {token}"}
        settings = _forwarded_settings(jwks_server, require_email_verified=False)
        user = user_from_headers(headers, settings=settings)
        assert user is not None


class TestCustomHeaderNamesCrossCheck:
    def test_spoofed_custom_email_header_rejected(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(
            iss=jwks_server.issuer, aud="my-client", email="alice@example.com"
        )
        token = jwks_server.mint_token("kid-primary", claims)
        settings = _forwarded_settings(jwks_server, email_header="X-Custom-Email")
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Custom-Email": "ceo@example.com",
        }
        with pytest.raises(InvalidIdentityToken, match="does not match"):
            user_from_headers(headers, settings=settings)

    def test_matching_custom_email_header_is_fine(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(
            iss=jwks_server.issuer, aud="my-client", email="alice@example.com"
        )
        token = jwks_server.mint_token("kid-primary", claims)
        settings = _forwarded_settings(jwks_server, email_header="X-Custom-Email")
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Custom-Email": "alice@example.com",
        }
        user = user_from_headers(headers, settings=settings)
        assert user is not None
        assert user.email == "alice@example.com"

    def test_default_header_name_is_ignored_once_custom_name_configured(
        self, jwks_server: JwksTestServer
    ) -> None:
        # Spoofing the DEFAULT header name no longer matters once a custom
        # name is configured -- only the configured name is checked.
        claims = make_token_claims(
            iss=jwks_server.issuer, aud="my-client", email="alice@example.com"
        )
        token = jwks_server.mint_token("kid-primary", claims)
        settings = _forwarded_settings(jwks_server, email_header="X-Custom-Email")
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Auth-Request-Email": "ceo@example.com",
        }
        user = user_from_headers(headers, settings=settings)
        assert user is not None
        assert user.email == "alice@example.com"


class TestMultipleIssuersEndToEnd:
    def test_accepts_bearer_from_second_configured_issuer(
        self, jwks_server: JwksTestServer
    ) -> None:
        claims = make_token_claims(iss="https://alt-issuer.invalid", aud="my-client")
        token = jwks_server.mint_token("kid-primary", claims)
        settings = _forwarded_settings(
            jwks_server, issuer=f"{jwks_server.issuer},https://alt-issuer.invalid"
        )
        headers = {"Authorization": f"Bearer {token}"}
        user = user_from_headers(headers, settings=settings)
        assert user is not None
        assert user.email == "alice@example.com"

    def test_discovery_still_uses_first_issuer(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        token = jwks_server.mint_token("kid-primary", claims)
        settings = _forwarded_settings(
            jwks_server,
            issuer=f"{jwks_server.issuer},https://alt-issuer.invalid",
            jwks_url=None,
        )
        headers = {"Authorization": f"Bearer {token}"}
        user = user_from_headers(headers, settings=settings)
        assert user is not None


class TestRequireJwtFalseConfigurationFallback:
    def test_missing_config_with_require_jwt_false_falls_back_to_headers(
        self, jwks_server: JwksTestServer
    ) -> None:
        # No issuer/audience/domains configured at all, but require_jwt is
        # False and a bearer IS present: must fall back to the legacy
        # header path instead of crashing with an unhandled
        # ConfigurationError (a 500 for every request).
        settings = Settings(require_jwt=False)
        headers = {
            "Authorization": "Bearer not-a-real-jwt",
            "X-Auth-Request-Email": "dev@example.com",
        }
        user = user_from_headers(headers, settings=settings)
        assert user is not None
        assert user.email == "dev@example.com"

    def test_missing_config_with_require_jwt_true_raises(self) -> None:
        settings = Settings(require_jwt=True)
        headers = {"Authorization": "Bearer not-a-real-jwt"}
        with pytest.raises(ConfigurationError):
            user_from_headers(headers, settings=settings)


class TestVerifyToken:
    def test_verify_token_returns_claims(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        token = jwks_server.mint_token("kid-primary", claims)
        settings = _forwarded_settings(jwks_server)
        result = verify_token(token, settings=settings)
        assert result["email"] == "alice@example.com"

    def test_verify_token_raises_on_bad_token(self, jwks_server: JwksTestServer) -> None:
        settings = _forwarded_settings(jwks_server)
        with pytest.raises(InvalidIdentityToken):
            verify_token("garbage", settings=settings)

    def test_verify_token_rejects_unverified_email(self, jwks_server: JwksTestServer) -> None:
        """BLOCKER regression check: `verify_token`/`verify_id_token` must
        apply the same `require_email_verified` check `user_from_headers`
        applies, not just signature/audience/issuer -- a caller using the
        raw-claims API must not get a weaker guarantee."""
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        claims["email_verified"] = False
        token = jwks_server.mint_token("kid-primary", claims)
        settings = _forwarded_settings(jwks_server)
        with pytest.raises(InvalidIdentityToken, match="email_verified"):
            verify_token(token, settings=settings)

    def test_verify_token_rejects_email_outside_domain_allowlist(
        self, jwks_server: JwksTestServer
    ) -> None:
        """BLOCKER regression check: `verify_token` must also apply the
        email-domain allowlist, not just signature/audience/issuer."""
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client", email="alice@evil.com")
        token = jwks_server.mint_token("kid-primary", claims)
        settings = _forwarded_settings(
            jwks_server, allowed_email_domains=frozenset({"example.com"})
        )
        with pytest.raises(InvalidIdentityToken, match="allowlist"):
            verify_token(token, settings=settings)

    def test_verify_id_token_rejects_unverified_email(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        claims["email_verified"] = False
        token = jwks_server.mint_token("kid-primary", claims)
        settings = _forwarded_settings(jwks_server)
        with pytest.raises(InvalidIdentityToken, match="email_verified"):
            verify_id_token(token, settings=settings)

    def test_verify_id_token_is_compatible_alias(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        token = jwks_server.mint_token("kid-primary", claims)
        settings = _forwarded_settings(jwks_server)
        result = verify_id_token(token, settings=settings)
        assert result["email"] == "alice@example.com"

    def test_verify_id_token_jwks_uri_override_is_deprecated(
        self, jwks_server: JwksTestServer
    ) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        token = jwks_server.mint_token("kid-primary", claims)
        settings = Settings(
            mode=MODE_FORWARDED,
            issuer=jwks_server.issuer,
            audience=("my-client",),
            allowed_email_domains=frozenset({"*"}),
        )
        with pytest.warns(DeprecationWarning):
            result = verify_id_token(token, jwks_uri=jwks_server.jwks_uri, settings=settings)
        assert result["email"] == "alice@example.com"


class TestDeprecatedApiParity:
    def test_gateway_scope_is_deprecated_alias_for_scope(self, jwks_server: JwksTestServer) -> None:
        claims = make_additional_issuer_claims(iss=jwks_server.issuer, aud="svc-aud")
        token = jwks_server.mint_token("kid-primary", claims)
        settings = Settings(
            issuer="https://primary-issuer.invalid",
            audience=("primary-aud",),
            jwks_url="http://127.0.0.1:1/jwks",
            allowed_email_domains=frozenset({"*"}),
            additional_issuer=jwks_server.issuer,
            additional_issuer_jwks_url=jwks_server.jwks_uri,
            additional_issuer_audience="svc-aud",
        )
        headers = {"Authorization": f"Bearer {token}"}
        user = user_from_headers(headers, settings=settings)
        assert user is not None
        with pytest.warns(DeprecationWarning):
            assert user.gateway_scope == user.scope == "read:things"

    def test_auth_header_bearer_prefix_reexported(self) -> None:
        assert AUTH_HEADER_BEARER_PREFIX == "Bearer "

    def test_user_from_headers_jwks_uri_kwarg_is_deprecated(
        self, jwks_server: JwksTestServer
    ) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        token = jwks_server.mint_token("kid-primary", claims)
        settings = Settings(
            issuer=jwks_server.issuer,
            audience=("my-client",),
            allowed_email_domains=frozenset({"*"}),
        )
        headers = {"Authorization": f"Bearer {token}"}
        with pytest.warns(DeprecationWarning):
            user = user_from_headers(headers, settings=settings, jwks_uri=jwks_server.jwks_uri)
        assert user is not None
        assert user.email == "alice@example.com"
