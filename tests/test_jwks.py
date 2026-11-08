from __future__ import annotations

import time

import pytest

from forwarded_auth import _jwks
from forwarded_auth._jwks import (
    InvalidIdentityToken,
    decode_unverified,
    discover_jwks_url,
    discover_userinfo_url,
    enforce_email_domain,
    peek_unverified_issuer,
    verify_additional_issuer_token,
    verify_jwt,
)

from .conftest import JwksTestServer, make_additional_issuer_claims, make_token_claims


class TestVerifyJwt:
    def test_valid_token_verifies(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        token = jwks_server.mint_token("kid-primary", claims)
        result = verify_jwt(
            token, issuer=jwks_server.issuer, audience=["my-client"], jwks_url=jwks_server.jwks_uri
        )
        assert result["email"] == "alice@example.com"
        assert result["sub"] == "1234567890"

    def test_wrong_audience_rejected(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="other-client")
        token = jwks_server.mint_token("kid-primary", claims)
        with pytest.raises(InvalidIdentityToken, match="audience"):
            verify_jwt(
                token,
                issuer=jwks_server.issuer,
                audience=["my-client"],
                jwks_url=jwks_server.jwks_uri,
            )

    def test_wrong_issuer_rejected(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(iss="https://not-the-issuer.invalid", aud="my-client")
        token = jwks_server.mint_token("kid-primary", claims)
        with pytest.raises(InvalidIdentityToken, match="issuer"):
            verify_jwt(
                token,
                issuer=jwks_server.issuer,
                audience=["my-client"],
                jwks_url=jwks_server.jwks_uri,
            )

    def test_expired_token_rejected(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(
            iss=jwks_server.issuer,
            aud="my-client",
            exp_offset=-10,
            nbf_offset=-120,
            iat_offset=-120,
        )
        token = jwks_server.mint_token("kid-primary", claims)
        with pytest.raises(InvalidIdentityToken, match="expired"):
            verify_jwt(
                token,
                issuer=jwks_server.issuer,
                audience=["my-client"],
                jwks_url=jwks_server.jwks_uri,
            )

    def test_not_yet_valid_token_rejected(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(
            iss=jwks_server.issuer, aud="my-client", nbf_offset=120, iat_offset=120
        )
        token = jwks_server.mint_token("kid-primary", claims)
        with pytest.raises(InvalidIdentityToken, match="not yet valid"):
            verify_jwt(
                token,
                issuer=jwks_server.issuer,
                audience=["my-client"],
                jwks_url=jwks_server.jwks_uri,
            )

    def test_unknown_kid_rejected(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        token = jwks_server.mint_token("kid-secondary", claims)  # not published
        with pytest.raises(InvalidIdentityToken, match="JWKS key lookup failed"):
            verify_jwt(
                token,
                issuer=jwks_server.issuer,
                audience=["my-client"],
                jwks_url=jwks_server.jwks_uri,
            )

    def test_signature_mismatch_rejected(self, jwks_server: JwksTestServer) -> None:
        import jwt as pyjwt
        from cryptography.hazmat.primitives.asymmetric import rsa

        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        # Sign with a key that was never registered at all, but claim the
        # published "kid-primary" kid header -- the signature will not
        # verify against the JWKS-published public key for that kid.
        forged_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token = pyjwt.encode(claims, forged_key, algorithm="RS256", headers={"kid": "kid-primary"})
        with pytest.raises(InvalidIdentityToken, match="signature mismatch"):
            verify_jwt(
                token,
                issuer=jwks_server.issuer,
                audience=["my-client"],
                jwks_url=jwks_server.jwks_uri,
            )

    def test_empty_token_rejected(self) -> None:
        with pytest.raises(InvalidIdentityToken, match="empty token"):
            verify_jwt(
                "",
                issuer="https://issuer.example.com",
                audience=["x"],
                jwks_url="https://jwks.example.com",
            )

    def test_no_audience_rejected(self) -> None:
        with pytest.raises(InvalidIdentityToken, match="no accepted audience"):
            verify_jwt(
                "abc.def.ghi",
                issuer="https://issuer.example.com",
                audience=[],
                jwks_url="https://jwks.example.com",
            )

    def test_unreachable_jwks_fails_closed(self) -> None:
        claims = {"iss": "https://x.invalid", "aud": "c", "sub": "1", "exp": int(time.time()) + 60}
        import jwt as pyjwt
        from cryptography.hazmat.primitives.asymmetric import rsa

        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token = pyjwt.encode(claims, priv, algorithm="RS256", headers={"kid": "k1"})
        with pytest.raises(InvalidIdentityToken):
            verify_jwt(
                token,
                issuer="https://x.invalid",
                audience=["c"],
                jwks_url="http://127.0.0.1:1/jwks",  # nothing listens here
            )

    def test_jwks_url_resolved_via_discovery_when_unset(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        token = jwks_server.mint_token("kid-primary", claims)
        result = verify_jwt(token, issuer=jwks_server.issuer, audience=["my-client"], jwks_url=None)
        assert result["email"] == "alice@example.com"


class TestDiscovery:
    def test_discover_jwks_url(self, jwks_server: JwksTestServer) -> None:
        assert discover_jwks_url(jwks_server.issuer) == jwks_server.jwks_uri

    def test_discover_userinfo_url(self, jwks_server: JwksTestServer) -> None:
        assert discover_userinfo_url(jwks_server.issuer) == f"{jwks_server.issuer}/userinfo"

    def test_discovery_cached(self, jwks_server: JwksTestServer) -> None:
        discover_jwks_url(jwks_server.issuer)
        count_after_first = jwks_server.request_count
        discover_jwks_url(jwks_server.issuer)
        assert jwks_server.request_count == count_after_first  # second call hit the cache

    def test_discovery_of_unreachable_issuer_raises(self) -> None:
        with pytest.raises(InvalidIdentityToken, match="discovery fetch failed"):
            discover_jwks_url("http://127.0.0.1:1")


class TestEmailDomainAllowlist:
    def test_noop_when_unset(self) -> None:
        enforce_email_domain({"email": "anyone@anywhere.com"}, frozenset())

    def test_rejects_outside_domain(self) -> None:
        with pytest.raises(InvalidIdentityToken, match="not in the allowlist"):
            enforce_email_domain({"email": "alice@evil.com"}, frozenset({"example.com"}))

    def test_accepts_inside_domain(self) -> None:
        enforce_email_domain({"email": "alice@example.com"}, frozenset({"example.com"}))

    def test_rejects_missing_email_when_configured(self) -> None:
        with pytest.raises(InvalidIdentityToken, match="no usable email claim"):
            enforce_email_domain({}, frozenset({"example.com"}))


class TestAdditionalIssuer:
    def test_valid_token_verifies(self, jwks_server: JwksTestServer) -> None:
        claims = make_additional_issuer_claims(iss=jwks_server.issuer, aud="svc-aud")
        token = jwks_server.mint_token("kid-primary", claims)
        result = verify_additional_issuer_token(
            token,
            issuer=jwks_server.issuer,
            jwks_url=jwks_server.jwks_uri,
            audience="svc-aud",
            actor_claim="act",
            scope_claim="scope",
            max_lifetime_s=300,
        )
        assert result["sub"] == "owner@example.com"
        assert result["act"] == "svc-worker-1"

    def test_non_rs256_rejected(self, jwks_server: JwksTestServer) -> None:
        import jwt as pyjwt

        token = pyjwt.encode({"a": "b"}, "secret", algorithm="HS256")
        with pytest.raises(InvalidIdentityToken, match="RS256"):
            verify_additional_issuer_token(
                token,
                issuer=jwks_server.issuer,
                jwks_url=jwks_server.jwks_uri,
                audience="svc-aud",
                actor_claim="act",
                scope_claim="scope",
                max_lifetime_s=300,
            )

    def test_missing_actor_rejected(self, jwks_server: JwksTestServer) -> None:
        claims = make_additional_issuer_claims(iss=jwks_server.issuer, aud="svc-aud", actor=None)
        token = jwks_server.mint_token("kid-primary", claims)
        with pytest.raises(InvalidIdentityToken, match="act"):
            verify_additional_issuer_token(
                token,
                issuer=jwks_server.issuer,
                jwks_url=jwks_server.jwks_uri,
                audience="svc-aud",
                actor_claim="act",
                scope_claim="scope",
                max_lifetime_s=300,
            )

    def test_overlong_lifetime_rejected(self, jwks_server: JwksTestServer) -> None:
        claims = make_additional_issuer_claims(
            iss=jwks_server.issuer, aud="svc-aud", exp_offset=3600
        )
        token = jwks_server.mint_token("kid-primary", claims)
        with pytest.raises(InvalidIdentityToken, match="lifetime exceeds"):
            verify_additional_issuer_token(
                token,
                issuer=jwks_server.issuer,
                jwks_url=jwks_server.jwks_uri,
                audience="svc-aud",
                actor_claim="act",
                scope_claim="scope",
                max_lifetime_s=300,
            )

    def test_audience_mismatch_rejected(self, jwks_server: JwksTestServer) -> None:
        claims = make_additional_issuer_claims(iss=jwks_server.issuer, aud="wrong-aud")
        token = jwks_server.mint_token("kid-primary", claims)
        with pytest.raises(InvalidIdentityToken):
            verify_additional_issuer_token(
                token,
                issuer=jwks_server.issuer,
                jwks_url=jwks_server.jwks_uri,
                audience="svc-aud",
                actor_claim="act",
                scope_claim="scope",
                max_lifetime_s=300,
            )


class TestUnverifiedHelpers:
    def test_decode_unverified_returns_claims(self) -> None:
        import jwt as pyjwt

        token = pyjwt.encode({"email": "a@b.com"}, "secret", algorithm="HS256")
        assert decode_unverified(token)["email"] == "a@b.com"

    def test_decode_unverified_empty_on_garbage(self) -> None:
        assert decode_unverified("not-a-jwt") == {}

    def test_decode_unverified_empty_string(self) -> None:
        assert decode_unverified("") == {}

    def test_peek_unverified_issuer(self) -> None:
        import jwt as pyjwt

        token = pyjwt.encode({"iss": "https://x.example.com"}, "secret", algorithm="HS256")
        assert peek_unverified_issuer(token) == "https://x.example.com"

    def test_peek_unverified_issuer_none_on_garbage(self) -> None:
        assert peek_unverified_issuer("garbage") is None


class TestForcedRefreshRateLimit:
    def test_unknown_kid_rate_limited_no_extra_fetch_within_window(
        self, jwks_server: JwksTestServer
    ) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        token = jwks_server.mint_token("kid-secondary", claims)  # not published

        with pytest.raises(InvalidIdentityToken):
            verify_jwt(
                token,
                issuer=jwks_server.issuer,
                audience=["my-client"],
                jwks_url=jwks_server.jwks_uri,
            )
        count_after_first = jwks_server.request_count

        # Retrying immediately (well within the 60s cooldown) must not
        # trigger another forced refresh.
        with pytest.raises(InvalidIdentityToken):
            verify_jwt(
                token,
                issuer=jwks_server.issuer,
                audience=["my-client"],
                jwks_url=jwks_server.jwks_uri,
            )
        assert jwks_server.request_count == count_after_first

    def test_key_rotation_picked_up_after_cooldown_elapses(
        self, jwks_server: JwksTestServer
    ) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        token = jwks_server.mint_token("kid-secondary", claims)  # not published yet

        with pytest.raises(InvalidIdentityToken):
            verify_jwt(
                token,
                issuer=jwks_server.issuer,
                audience=["my-client"],
                jwks_url=jwks_server.jwks_uri,
            )

        # Simulate a key-rotation event server-side, and simulate the
        # forced-refresh cooldown having elapsed (rather than sleeping 60s
        # of wall-clock time in a test).
        jwks_server.published_kids.append("kid-secondary")
        _jwks._last_forced_refresh[jwks_server.jwks_uri] = time.time() - 61.0

        result = verify_jwt(
            token, issuer=jwks_server.issuer, audience=["my-client"], jwks_url=jwks_server.jwks_uri
        )
        assert result["sub"] == claims["sub"]

    def test_allow_forced_refresh_is_per_jwks_url(self) -> None:
        assert _jwks._allow_forced_refresh("https://a.example.com/jwks") is True
        assert _jwks._allow_forced_refresh("https://a.example.com/jwks") is False
        # A different URL has its own independent cooldown.
        assert _jwks._allow_forced_refresh("https://b.example.com/jwks") is True


class TestSecureUrlEnforcement:
    def test_https_issuer_required_for_discovery(self) -> None:
        with pytest.raises(InvalidIdentityToken, match="https"):
            discover_jwks_url("http://not-loopback.example.com")

    def test_http_loopback_issuer_allowed_for_discovery(self, jwks_server: JwksTestServer) -> None:
        # jwks_server.issuer is http://127.0.0.1:<port> -- loopback, allowed.
        assert discover_jwks_url(jwks_server.issuer) == jwks_server.jwks_uri

    def test_non_http_scheme_rejected(self) -> None:
        with pytest.raises(InvalidIdentityToken, match="http"):
            discover_jwks_url("file:///etc/passwd")

    def test_explicit_jwks_url_must_be_https_or_loopback(self) -> None:
        claims = {"iss": "https://x.invalid", "aud": "c", "sub": "1@x.com"}
        import jwt as pyjwt
        from cryptography.hazmat.primitives.asymmetric import rsa

        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token = pyjwt.encode(claims, priv, algorithm="RS256", headers={"kid": "k1"})
        with pytest.raises(InvalidIdentityToken, match="https"):
            verify_jwt(
                token,
                issuer="https://x.invalid",
                audience=["c"],
                jwks_url="http://jwks.not-loopback.example.com/jwks",
            )


class TestDiscoveryIssuerMatch:
    def test_mismatched_discovery_issuer_rejected(self, jwks_server: JwksTestServer) -> None:
        # The test server always reports its own canonical issuer string in
        # the discovery doc. Asking under an equivalent-but-different
        # issuer string (trailing slash resolves to the same `.well-known`
        # URL) must still be rejected as a mismatch.
        with pytest.raises(InvalidIdentityToken, match="does not match"):
            discover_jwks_url(f"{jwks_server.issuer}/")


class TestMultipleIssuers:
    def test_accepts_token_from_any_configured_issuer(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        token = jwks_server.mint_token("kid-primary", claims)
        result = verify_jwt(
            token,
            issuer=(jwks_server.issuer, "https://some-other-issuer.invalid"),
            audience=["my-client"],
            jwks_url=jwks_server.jwks_uri,
        )
        assert result["email"] == "alice@example.com"

    def test_rejects_token_from_issuer_outside_the_configured_set(
        self, jwks_server: JwksTestServer
    ) -> None:
        claims = make_token_claims(iss="https://not-configured.invalid", aud="my-client")
        token = jwks_server.mint_token("kid-primary", claims)
        with pytest.raises(InvalidIdentityToken, match="issuer"):
            verify_jwt(
                token,
                issuer=(jwks_server.issuer, "https://some-other-issuer.invalid"),
                audience=["my-client"],
                jwks_url=jwks_server.jwks_uri,
            )

    def test_discovery_uses_first_issuer_entry(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        token = jwks_server.mint_token("kid-primary", claims)
        # jwks_url=None forces discovery, which must resolve off the FIRST
        # issuer entry -- a bogus second entry must not break it.
        result = verify_jwt(
            token,
            issuer=(jwks_server.issuer, "bogus-second-issuer"),
            audience=["my-client"],
            jwks_url=None,
        )
        assert result["email"] == "alice@example.com"


class TestRequiredClaims:
    def test_missing_sub_rejected(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        del claims["sub"]
        token = jwks_server.mint_token("kid-primary", claims)
        with pytest.raises(InvalidIdentityToken, match="required claim"):
            verify_jwt(
                token,
                issuer=jwks_server.issuer,
                audience=["my-client"],
                jwks_url=jwks_server.jwks_uri,
            )

    def test_missing_iat_rejected(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        del claims["iat"]
        token = jwks_server.mint_token("kid-primary", claims)
        with pytest.raises(InvalidIdentityToken, match="required claim"):
            verify_jwt(
                token,
                issuer=jwks_server.issuer,
                audience=["my-client"],
                jwks_url=jwks_server.jwks_uri,
            )


class TestForgedTokens:
    def test_alg_none_rejected(self, jwks_server: JwksTestServer) -> None:
        import base64
        import json as _json

        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        header = base64.urlsafe_b64encode(
            _json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=")
        payload = base64.urlsafe_b64encode(_json.dumps(claims).encode()).rstrip(b"=")
        forged = (header + b"." + payload + b".").decode()
        with pytest.raises(InvalidIdentityToken):
            verify_jwt(
                forged,
                issuer=jwks_server.issuer,
                audience=["my-client"],
                jwks_url=jwks_server.jwks_uri,
            )

    def test_hs256_public_key_confusion_rejected(self, jwks_server: JwksTestServer) -> None:
        import base64
        import hashlib
        import hmac as hmac_module
        import json as _json

        from cryptography.hazmat.primitives import serialization

        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        # Forge an HS256 token "signed" using the issuer's own PUBLIC key
        # bytes as the HMAC secret -- the classic alg-confusion attack.
        # PyJWT's own `encode()` now refuses to build this (it detects a
        # PEM/asymmetric-looking HMAC key and raises `InvalidKeyError`), so
        # the JWS is built by hand here to prove `verify_jwt` has its OWN,
        # independent defence: it always passes a single explicit
        # `algorithms=["RS256"]`, so an HS256-signed token is rejected
        # outright regardless of the signature or the key used to make it.
        pub_pem = (
            jwks_server.keys_by_kid["kid-primary"]
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

        def _b64url(data: bytes) -> bytes:
            return base64.urlsafe_b64encode(data).rstrip(b"=")

        header = _b64url(_json.dumps({"alg": "HS256", "typ": "JWT", "kid": "kid-primary"}).encode())
        payload = _b64url(_json.dumps(claims).encode())
        signing_input = header + b"." + payload
        signature = _b64url(hmac_module.new(pub_pem, signing_input, hashlib.sha256).digest())
        forged = (signing_input + b"." + signature).decode()

        with pytest.raises(InvalidIdentityToken):
            verify_jwt(
                forged,
                issuer=jwks_server.issuer,
                audience=["my-client"],
                jwks_url=jwks_server.jwks_uri,
            )


class TestAdditionalIssuerHardening:
    def test_missing_sub_raises_invalid_identity_token_not_keyerror(
        self, jwks_server: JwksTestServer
    ) -> None:
        claims = make_additional_issuer_claims(iss=jwks_server.issuer, aud="svc-aud")
        del claims["sub"]
        token = jwks_server.mint_token("kid-primary", claims)
        with pytest.raises(InvalidIdentityToken, match="required claim"):
            verify_additional_issuer_token(
                token,
                issuer=jwks_server.issuer,
                jwks_url=jwks_server.jwks_uri,
                audience="svc-aud",
                actor_claim="act",
                scope_claim="scope",
                max_lifetime_s=300,
            )

    def test_non_email_shaped_sub_rejected(self, jwks_server: JwksTestServer) -> None:
        claims = make_additional_issuer_claims(
            iss=jwks_server.issuer, aud="svc-aud", sub="not-an-email"
        )
        token = jwks_server.mint_token("kid-primary", claims)
        with pytest.raises(InvalidIdentityToken, match="email address"):
            verify_additional_issuer_token(
                token,
                issuer=jwks_server.issuer,
                jwks_url=jwks_server.jwks_uri,
                audience="svc-aud",
                actor_claim="act",
                scope_claim="scope",
                max_lifetime_s=300,
            )

    def test_sub_domain_outside_allowlist_rejected(self, jwks_server: JwksTestServer) -> None:
        claims = make_additional_issuer_claims(
            iss=jwks_server.issuer, aud="svc-aud", sub="owner@evil.com"
        )
        token = jwks_server.mint_token("kid-primary", claims)
        with pytest.raises(InvalidIdentityToken, match="allowlist"):
            verify_additional_issuer_token(
                token,
                issuer=jwks_server.issuer,
                jwks_url=jwks_server.jwks_uri,
                audience="svc-aud",
                actor_claim="act",
                scope_claim="scope",
                max_lifetime_s=300,
                allowed_email_domains=frozenset({"example.com"}),
            )

    def test_sub_domain_inside_allowlist_accepted(self, jwks_server: JwksTestServer) -> None:
        claims = make_additional_issuer_claims(
            iss=jwks_server.issuer, aud="svc-aud", sub="owner@example.com"
        )
        token = jwks_server.mint_token("kid-primary", claims)
        result = verify_additional_issuer_token(
            token,
            issuer=jwks_server.issuer,
            jwks_url=jwks_server.jwks_uri,
            audience="svc-aud",
            actor_claim="act",
            scope_claim="scope",
            max_lifetime_s=300,
            allowed_email_domains=frozenset({"example.com"}),
        )
        assert result["sub"] == "owner@example.com"


class TestRequiredClaimsExtended:
    """Round-2 review: lock in the remaining `required_claims` members
    that `TestRequiredClaims` above didn't individually exercise -- a
    mutation that dropped any ONE of them from `_DEFAULT_REQUIRED_CLAIMS`
    would otherwise still pass the full suite."""

    def test_missing_exp_rejected(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        del claims["exp"]
        token = jwks_server.mint_token("kid-primary", claims)
        with pytest.raises(InvalidIdentityToken, match="required claim"):
            verify_jwt(
                token,
                issuer=jwks_server.issuer,
                audience=["my-client"],
                jwks_url=jwks_server.jwks_uri,
            )

    def test_missing_iss_rejected(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        del claims["iss"]
        token = jwks_server.mint_token("kid-primary", claims)
        with pytest.raises(InvalidIdentityToken, match="required claim"):
            verify_jwt(
                token,
                issuer=jwks_server.issuer,
                audience=["my-client"],
                jwks_url=jwks_server.jwks_uri,
            )

    def test_missing_aud_rejected(self, jwks_server: JwksTestServer) -> None:
        claims = make_token_claims(iss=jwks_server.issuer, aud="my-client")
        del claims["aud"]
        token = jwks_server.mint_token("kid-primary", claims)
        with pytest.raises(InvalidIdentityToken, match="required claim"):
            verify_jwt(
                token,
                issuer=jwks_server.issuer,
                audience=["my-client"],
                jwks_url=jwks_server.jwks_uri,
            )


class TestDiscoveryDocumentAdvertisingInsecureUrls:
    """A compromised or misconfigured discovery document must not be
    able to redirect verification to an attacker-controlled JWKS or
    userinfo endpoint just because the discovery document itself was
    fetched over a trusted issuer's https URL."""

    def test_discovery_advertising_http_jwks_uri_rejected(
        self, jwks_server: JwksTestServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        evil_doc = {
            "issuer": jwks_server.issuer,
            "jwks_uri": "http://evil.example/jwks",
            "userinfo_endpoint": f"{jwks_server.issuer}/userinfo",
        }
        monkeypatch.setattr(_jwks, "_fetch_discovery_document", lambda issuer: evil_doc)
        with pytest.raises(InvalidIdentityToken, match="https"):
            discover_jwks_url(jwks_server.issuer)

    def test_discovery_advertising_http_userinfo_endpoint_rejected(
        self, jwks_server: JwksTestServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        evil_doc = {
            "issuer": jwks_server.issuer,
            "jwks_uri": jwks_server.jwks_uri,
            "userinfo_endpoint": "http://evil.example/userinfo",
        }
        monkeypatch.setattr(_jwks, "_fetch_discovery_document", lambda issuer: evil_doc)
        with pytest.raises(InvalidIdentityToken, match="https"):
            discover_userinfo_url(jwks_server.issuer)


class TestAdditionalIssuerAudienceList:
    def test_token_aud_as_list_rejected_even_if_it_contains_the_audience(
        self, jwks_server: JwksTestServer
    ) -> None:
        """PyJWT's own `audience=[...]` check accepts a token whose `aud`
        is a list as long as ANY entry matches -- so a token minted with
        `aud: ["svc", "other"]` would sail through `verify_jwt` alone.
        The additional-issuer path tightens this with its own exact-match
        check (`claims.get("aud") != audience`); this locks that in with
        a real multi-entry `aud` list, not just a wrong single value."""
        claims = make_additional_issuer_claims(iss=jwks_server.issuer)
        claims["aud"] = ["svc", "other"]
        token = jwks_server.mint_token("kid-primary", claims)
        with pytest.raises(InvalidIdentityToken, match="exactly match"):
            verify_additional_issuer_token(
                token,
                issuer=jwks_server.issuer,
                jwks_url=jwks_server.jwks_uri,
                audience="svc",
                actor_claim="act",
                scope_claim="scope",
                max_lifetime_s=300,
            )


class TestDiscoveryFailureCaching:
    def test_discovery_failure_is_cached_and_not_refetched_within_window(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = []

        def fake_fetch(issuer: str) -> dict[str, object]:
            calls.append(issuer)
            raise InvalidIdentityToken("discovery fetch failed (simulated outage)")

        monkeypatch.setattr(_jwks, "_fetch_discovery_document", fake_fetch)

        with pytest.raises(InvalidIdentityToken, match="simulated outage"):
            discover_jwks_url("https://flaky-issuer.invalid")
        with pytest.raises(InvalidIdentityToken, match="simulated outage"):
            discover_jwks_url("https://flaky-issuer.invalid")

        # Without the failure cache, the second call would re-attempt the
        # fetch (and, against a real unreachable host, pay another full
        # 5s HTTP timeout per request during an IdP outage).
        assert len(calls) == 1

    def test_discovery_failure_cache_expires_after_30s(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = []

        def fake_fetch(issuer: str) -> dict[str, object]:
            calls.append(issuer)
            raise InvalidIdentityToken("still down")

        monkeypatch.setattr(_jwks, "_fetch_discovery_document", fake_fetch)

        with pytest.raises(InvalidIdentityToken):
            discover_jwks_url("https://flaky-issuer.invalid")
        assert len(calls) == 1

        # Simulate the 30s failure-cache window having elapsed.
        with _jwks._discovery_cache._lock:
            issuer, (exc, _expiry) = next(iter(_jwks._discovery_cache._failures.items()))
            _jwks._discovery_cache._failures[issuer] = (exc, time.time() - 1.0)

        with pytest.raises(InvalidIdentityToken):
            discover_jwks_url("https://flaky-issuer.invalid")
        assert len(calls) == 2  # retried after the failure cache expired


class TestSecureUrlCredentialsAndHostname:
    def test_url_with_embedded_credentials_rejected(self) -> None:
        with pytest.raises(InvalidIdentityToken, match="embedded credentials"):
            discover_jwks_url("https://user:pass@issuer.example.com")

    def test_url_with_no_hostname_rejected(self) -> None:
        with pytest.raises(InvalidIdentityToken, match="hostname"):
            discover_jwks_url("https:///well-known")
