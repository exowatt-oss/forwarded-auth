from __future__ import annotations

import logging

import pytest

from forwarded_auth._settings import (
    MODE_FORWARDED,
    MODE_NONE,
    MODE_OIDC,
    ConfigurationError,
    Settings,
    configure,
    get_settings,
)


def test_defaults_are_neutral() -> None:
    settings = Settings()
    assert settings.mode == MODE_FORWARDED
    assert settings.issuer is None
    assert settings.audience == ()
    assert settings.allowed_email_domains == frozenset()
    assert settings.require_email_verified is True
    assert settings.email_header == "X-Auth-Request-Email"
    assert settings.require_jwt is True
    assert settings.trust_proxy_headers is False
    assert settings.logout_url_base == "/oauth2/sign_out"
    assert settings.dev_user_email == "dev@localhost"
    assert settings.allow_insecure_none_mode is False


def test_from_env_reads_everything(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORWARDED_AUTH_MODE", "oidc")
    monkeypatch.setenv("FORWARDED_AUTH_ISSUER", "https://issuer.example.com")
    monkeypatch.setenv("FORWARDED_AUTH_AUDIENCE", "client-a, client-b")
    monkeypatch.setenv("FORWARDED_AUTH_ALLOWED_EMAIL_DOMAINS", "Example.com, other.ORG")
    monkeypatch.setenv("FORWARDED_AUTH_REQUIRE_EMAIL_VERIFIED", "false")
    monkeypatch.setenv("FORWARDED_AUTH_REQUIRE_JWT", "false")
    monkeypatch.setenv("FORWARDED_AUTH_TRUST_PROXY_HEADERS", "true")
    monkeypatch.setenv("FORWARDED_AUTH_TRUSTED_HOSTNAMES", "app.example.com,app2.example.com")

    settings = Settings.from_env()
    assert settings.mode == "oidc"
    assert settings.issuer == "https://issuer.example.com"
    assert settings.audience == ("client-a", "client-b")
    assert settings.allowed_email_domains == frozenset({"example.com", "other.org"})
    assert settings.require_email_verified is False
    assert settings.require_jwt is False
    assert settings.trust_proxy_headers is True
    assert settings.trusted_hostnames == ("app.example.com", "app2.example.com")


def test_from_env_reads_allow_insecure_none_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORWARDED_AUTH_MODE", "none")
    monkeypatch.setenv("FORWARDED_AUTH_ALLOW_INSECURE_NONE_MODE", "1")
    settings = Settings.from_env()
    assert settings.mode == MODE_NONE
    assert settings.allow_insecure_none_mode is True


def test_get_settings_reads_env_fresh_each_call(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORWARDED_AUTH_ISSUER", "https://a.example.com")
    assert get_settings().issuer == "https://a.example.com"
    monkeypatch.setenv("FORWARDED_AUTH_ISSUER", "https://b.example.com")
    assert get_settings().issuer == "https://b.example.com"


def test_configure_overrides_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FORWARDED_AUTH_ISSUER", "https://a.example.com")
    configure(Settings(issuer="https://override.example.com"))
    assert get_settings().issuer == "https://override.example.com"
    configure(None)
    assert get_settings().issuer == "https://a.example.com"


def test_require_forwarded_or_oidc_config_fails_closed_on_missing_issuer() -> None:
    settings = Settings(audience=("x",), allowed_email_domains=frozenset({"*"}))
    with pytest.raises(ConfigurationError, match="FORWARDED_AUTH_ISSUER"):
        settings.require_forwarded_or_oidc_config()


def test_require_forwarded_or_oidc_config_fails_closed_on_missing_audience() -> None:
    settings = Settings(issuer="https://issuer.example.com", allowed_email_domains=frozenset({"*"}))
    with pytest.raises(ConfigurationError, match="FORWARDED_AUTH_AUDIENCE"):
        settings.require_forwarded_or_oidc_config()


def test_require_forwarded_or_oidc_config_fails_closed_on_missing_domains() -> None:
    settings = Settings(issuer="https://issuer.example.com", audience=("x",))
    with pytest.raises(ConfigurationError, match="FORWARDED_AUTH_ALLOWED_EMAIL_DOMAINS"):
        settings.require_forwarded_or_oidc_config()


def test_require_forwarded_or_oidc_config_passes_with_wildcard_domains() -> None:
    settings = Settings(
        issuer="https://issuer.example.com",
        audience=("client",),
        allowed_email_domains=frozenset({"*"}),
    )
    issuers, audience = settings.require_forwarded_or_oidc_config()
    assert issuers == ("https://issuer.example.com",)
    assert audience == ("client",)


def test_require_forwarded_or_oidc_config_splits_comma_separated_issuers() -> None:
    settings = Settings(
        issuer="https://accounts.google.com, accounts.google.com",
        audience=("client",),
        allowed_email_domains=frozenset({"*"}),
    )
    issuers, _audience = settings.require_forwarded_or_oidc_config()
    assert issuers == ("https://accounts.google.com", "accounts.google.com")


class TestIssuerListValidation:
    def test_empty_after_split_raises(self) -> None:
        settings = Settings(issuer=" , ", audience=("x",), allowed_email_domains=frozenset({"*"}))
        with pytest.raises(ConfigurationError, match="no issuer after splitting"):
            settings.require_forwarded_or_oidc_config()

    def test_first_entry_must_be_https_or_loopback(self) -> None:
        settings = Settings(
            issuer="accounts.google.com",
            audience=("x",),
            allowed_email_domains=frozenset({"*"}),
        )
        with pytest.raises(ConfigurationError, match="must be an https"):
            settings.require_forwarded_or_oidc_config()

    def test_bare_host_alias_accepted_as_second_entry(self) -> None:
        settings = Settings(
            issuer="https://accounts.google.com,accounts.google.com",
            audience=("x",),
            allowed_email_domains=frozenset({"*"}),
        )
        issuers, _ = settings.require_forwarded_or_oidc_config()
        assert issuers == ("https://accounts.google.com", "accounts.google.com")

    def test_plain_http_non_loopback_first_entry_rejected(self) -> None:
        settings = Settings(
            issuer="http://issuer.example.com",
            audience=("x",),
            allowed_email_domains=frozenset({"*"}),
        )
        with pytest.raises(ConfigurationError, match="must be an https"):
            settings.require_forwarded_or_oidc_config()

    def test_loopback_http_first_entry_accepted(self) -> None:
        settings = Settings(
            issuer="http://127.0.0.1:9999",
            audience=("x",),
            allowed_email_domains=frozenset({"*"}),
        )
        issuers, _ = settings.require_forwarded_or_oidc_config()
        assert issuers == ("http://127.0.0.1:9999",)


class TestAllowedEmailDomainsNormalization:
    def test_mixed_case_is_lowercased(self) -> None:
        settings = Settings(allowed_email_domains=frozenset({"Example.COM", "Other.Org"}))
        assert settings.allowed_email_domains == frozenset({"example.com", "other.org"})

    def test_wildcard_alone_is_fine(self) -> None:
        settings = Settings(allowed_email_domains=frozenset({"*"}))
        assert settings.allowed_email_domains == frozenset({"*"})

    def test_wildcard_mixed_with_domains_raises(self) -> None:
        with pytest.raises(ConfigurationError, match="cannot be combined"):
            Settings(allowed_email_domains=frozenset({"*", "example.com"}))


class TestNoneModeRejectsJwksUrl:
    def test_none_mode_combined_with_jwks_url_rejected(self) -> None:
        with pytest.raises(ConfigurationError, match="cannot be combined"):
            Settings(
                mode=MODE_NONE,
                allow_insecure_none_mode=True,
                jwks_url="https://issuer.example.com/jwks",
            )


class TestModeValidation:
    def test_unknown_mode_raises(self) -> None:
        with pytest.raises(ConfigurationError, match="not a supported mode"):
            Settings(mode="bogus")

    def test_forwarded_and_oidc_are_valid(self) -> None:
        Settings(mode=MODE_FORWARDED)
        Settings(mode=MODE_OIDC)


class TestNoneModeGuards:
    def test_bare_none_mode_without_ack_raises(self) -> None:
        with pytest.raises(ConfigurationError, match="FORWARDED_AUTH_ALLOW_INSECURE_NONE_MODE"):
            Settings(mode=MODE_NONE)

    def test_none_mode_with_ack_succeeds(self) -> None:
        settings = Settings(mode=MODE_NONE, allow_insecure_none_mode=True)
        assert settings.mode == MODE_NONE

    def test_none_mode_combined_with_issuer_rejected(self) -> None:
        with pytest.raises(ConfigurationError, match="cannot be combined"):
            Settings(mode=MODE_NONE, allow_insecure_none_mode=True, issuer="https://x.example.com")

    def test_none_mode_combined_with_trust_proxy_headers_rejected(self) -> None:
        with pytest.raises(ConfigurationError, match="cannot be combined"):
            Settings(mode=MODE_NONE, allow_insecure_none_mode=True, trust_proxy_headers=True)

    def test_none_mode_warns_once_per_process(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING):
            Settings(mode=MODE_NONE, allow_insecure_none_mode=True)
            Settings(mode=MODE_NONE, allow_insecure_none_mode=True)
        none_mode_warnings = [r for r in caplog.records if "mode=none is active" in r.message]
        assert len(none_mode_warnings) == 1


class TestRequireJwtFalseWarning:
    def test_warns_once_per_process(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING):
            Settings(require_jwt=False)
            Settings(require_jwt=False)
        warnings = [r for r in caplog.records if "require_jwt=False is active" in r.message]
        assert len(warnings) == 1

    def test_require_jwt_true_does_not_warn(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING):
            Settings(require_jwt=True)
        assert not any("require_jwt=False" in r.message for r in caplog.records)


class TestValidate:
    def test_validate_raises_on_default_forwarded_settings(self) -> None:
        with pytest.raises(ConfigurationError):
            Settings().validate()

    def test_validate_passes_fully_configured_forwarded_settings(self) -> None:
        Settings(
            issuer="https://issuer.example.com",
            audience=("client",),
            allowed_email_domains=frozenset({"*"}),
        ).validate()

    def test_validate_allows_require_jwt_false_with_no_issuer(self) -> None:
        Settings(require_jwt=False).validate()

    def test_validate_passes_none_mode(self) -> None:
        Settings(mode=MODE_NONE, allow_insecure_none_mode=True).validate()

    def test_validate_raises_on_additional_issuer_without_audience(self) -> None:
        settings = Settings(
            issuer="https://issuer.example.com",
            audience=("client",),
            allowed_email_domains=frozenset({"*"}),
            additional_issuer="https://svc-issuer.example.com",
        )
        with pytest.raises(ConfigurationError, match="FORWARDED_AUTH_ADDITIONAL_ISSUER_AUDIENCE"):
            settings.validate()

    def test_validate_raises_on_additional_issuer_without_domains_even_with_require_jwt_false(
        self,
    ) -> None:
        settings = Settings(
            require_jwt=False,
            additional_issuer="https://svc-issuer.example.com",
            additional_issuer_audience="svc-aud",
        )
        with pytest.raises(ConfigurationError, match="FORWARDED_AUTH_ALLOWED_EMAIL_DOMAINS"):
            settings.validate()

    def test_validate_passes_additional_issuer_with_domains_and_require_jwt_false(self) -> None:
        Settings(
            require_jwt=False,
            additional_issuer="https://svc-issuer.example.com",
            additional_issuer_audience="svc-aud",
            allowed_email_domains=frozenset({"*"}),
        ).validate()

    def test_validate_raises_on_trust_proxy_headers_without_domains(self) -> None:
        settings = Settings(require_jwt=False, trust_proxy_headers=True)
        with pytest.raises(ConfigurationError, match="FORWARDED_AUTH_ALLOWED_EMAIL_DOMAINS"):
            settings.validate()

    def test_validate_passes_trust_proxy_headers_with_domains(self) -> None:
        Settings(
            require_jwt=False,
            trust_proxy_headers=True,
            allowed_email_domains=frozenset({"example.com"}),
        ).validate()
