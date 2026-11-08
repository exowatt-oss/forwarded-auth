"""Shared test fixtures: a local JWKS/OIDC-discovery/userinfo server
backed by a controllable RSA keypair set, and claim builders.

No test needs network access to a real provider — every verification
path is exercised against this local server.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import urlparse

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from forwarded_auth import _jwks, _settings, _userinfo


@dataclass
class JwksTestServer:
    """A local HTTPServer serving a controllable JWKS + OIDC discovery
    document + a stub userinfo endpoint, all from one RSA keypair set.

    Two-key fixture: publishes two ``kid`` slots so tests can exercise
    the "signed by a key NOT in the JWKS" (unknown kid) case.
    """

    server: HTTPServer
    thread: threading.Thread
    keys_by_kid: dict[str, rsa.RSAPrivateKey] = field(default_factory=dict)
    published_kids: list[str] = field(default_factory=list)
    request_count: int = 0
    userinfo_response: dict[str, Any] | None = None
    userinfo_status: int = 200

    @property
    def issuer(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    @property
    def jwks_uri(self) -> str:
        return f"{self.issuer}/jwks"

    def _build_jwks(self) -> dict[str, Any]:
        keys = []
        for kid in self.published_kids:
            priv = self.keys_by_kid[kid]
            jwk = json.loads(RSAAlgorithm.to_jwk(priv.public_key()))
            jwk["kid"] = kid
            jwk["use"] = "sig"
            jwk["alg"] = "RS256"
            keys.append(jwk)
        return {"keys": keys}

    def _build_discovery(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "jwks_uri": self.jwks_uri,
            "userinfo_endpoint": f"{self.issuer}/userinfo",
            "authorization_endpoint": f"{self.issuer}/authorize",
            "token_endpoint": f"{self.issuer}/token",
        }

    def add_key(self, kid: str, publish: bool = True) -> rsa.RSAPrivateKey:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.keys_by_kid[kid] = priv
        if publish and kid not in self.published_kids:
            self.published_kids.append(kid)
        return priv

    def unpublish_key(self, kid: str) -> None:
        if kid in self.published_kids:
            self.published_kids.remove(kid)

    def mint_token(self, kid: str, claims: dict[str, Any], *, alg: str = "RS256") -> str:
        priv = self.keys_by_kid[kid]
        return jwt.encode(claims, priv, algorithm=alg, headers={"kid": kid})

    def shutdown(self) -> None:
        try:
            self.server.server_close()
        except Exception:  # noqa: BLE001
            pass
        self.server.shutdown()
        self.thread.join(timeout=5)


def _make_handler(test_server: JwksTestServer):
    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            test_server.request_count += 1
            path = urlparse(self.path).path
            if path in {"/jwks", "/.well-known/jwks.json"}:
                self._send_json(200, test_server._build_jwks())
            elif path == "/.well-known/openid-configuration":
                self._send_json(200, test_server._build_discovery())
            elif path == "/userinfo":
                if test_server.userinfo_response is None:
                    self.send_error(404)
                else:
                    self._send_json(test_server.userinfo_status, test_server.userinfo_response)
            else:
                self.send_error(404)

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_: Any) -> None:
            """Silence the default per-request stderr log."""

    return _Handler


@pytest.fixture
def jwks_server() -> Iterator[JwksTestServer]:
    test_server = JwksTestServer.__new__(JwksTestServer)
    test_server.keys_by_kid = {}
    test_server.published_kids = []
    test_server.request_count = 0
    test_server.userinfo_response = None
    test_server.userinfo_status = 200
    handler_cls = _make_handler(test_server)
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    test_server.server = server
    test_server.thread = threading.Thread(target=server.serve_forever, daemon=True)
    test_server.add_key("kid-primary", publish=True)
    test_server.add_key("kid-secondary", publish=False)
    test_server.thread.start()
    _jwks._reset_jwks_clients_for_tests()
    _jwks._reset_discovery_cache_for_tests()
    try:
        yield test_server
    finally:
        _jwks._reset_jwks_clients_for_tests()
        _jwks._reset_discovery_cache_for_tests()
        test_server.shutdown()


@pytest.fixture(autouse=True)
def _reset_settings_and_caches() -> Iterator[None]:
    """Clear the programmatic settings override, caches, and every
    ``FORWARDED_AUTH_*`` env var before and after each test, so tests
    are order-independent and never leak into each other."""
    _settings._reset_for_tests()
    _settings._reset_warned_for_tests()
    _userinfo._reset_cache_for_tests()
    _jwks._reset_jwks_clients_for_tests()
    _jwks._reset_discovery_cache_for_tests()
    _jwks._reset_forced_refresh_for_tests()
    try:
        yield
    finally:
        _settings._reset_for_tests()
        _settings._reset_warned_for_tests()
        _userinfo._reset_cache_for_tests()
        _jwks._reset_jwks_clients_for_tests()
        _jwks._reset_discovery_cache_for_tests()
        _jwks._reset_forced_refresh_for_tests()


def make_token_claims(
    *,
    email: str = "alice@example.com",
    aud: str = "test-client-id",
    iss: str = "https://example-issuer.invalid",
    sub: str = "1234567890",
    name: str | None = "Alice Example",
    picture: str | None = "https://example.com/avatar.jpg",
    exp_offset: int = 3600,
    nbf_offset: int = -60,
    iat_offset: int = -60,
) -> dict[str, Any]:
    """Build an ID-token-shaped claims dict. Tests override individual
    fields to exercise wrong-aud / wrong-iss / expired / etc. paths."""
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": iss,
        "aud": aud,
        "sub": sub,
        "email": email,
        "email_verified": True,
        "iat": now + iat_offset,
        "nbf": now + nbf_offset,
        "exp": now + exp_offset,
    }
    if name is not None:
        claims["name"] = name
    if picture is not None:
        claims["picture"] = picture
    return claims


def make_additional_issuer_claims(
    *,
    sub: str = "owner@example.com",
    aud: str = "additional-issuer-client",
    iss: str = "https://additional-issuer.invalid",
    actor: str | None = "svc-worker-1",
    scope: str | None = "read:things",
    exp_offset: int = 120,
    iat_offset: int = 0,
) -> dict[str, Any]:
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": iss,
        "aud": aud,
        "sub": sub,
        "iat": now + iat_offset,
        "exp": now + exp_offset,
    }
    if actor is not None:
        claims["act"] = actor
    if scope is not None:
        claims["scope"] = scope
    return claims
