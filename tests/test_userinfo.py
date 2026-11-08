from __future__ import annotations

from forwarded_auth._userinfo import remember_profile, resolve_profile

from .conftest import JwksTestServer


class TestObserveAndCache:
    def test_cached_value_served_without_network(self, jwks_server: JwksTestServer) -> None:
        remember_profile("sub-1", "Alice", "https://example.com/a.jpg")
        name, picture = resolve_profile(
            "sub-1", None, userinfo_url=f"{jwks_server.issuer}/userinfo", disabled=False
        )
        assert (name, picture) == ("Alice", "https://example.com/a.jpg")
        assert jwks_server.request_count == 0

    def test_remember_noop_without_sub(self) -> None:
        remember_profile(None, "Alice", None)  # must not raise


class TestNetworkFallback:
    def test_resolves_from_userinfo_endpoint(self, jwks_server: JwksTestServer) -> None:
        jwks_server.userinfo_response = {
            "sub": "sub-2",
            "name": "Bob",
            "picture": "https://x/b.jpg",
        }
        name, picture = resolve_profile(
            "sub-2",
            "some-access-token",
            userinfo_url=f"{jwks_server.issuer}/userinfo",
            disabled=False,
        )
        assert (name, picture) == ("Bob", "https://x/b.jpg")

    def test_caches_after_network_call(self, jwks_server: JwksTestServer) -> None:
        jwks_server.userinfo_response = {"sub": "sub-3", "name": "Carol", "picture": None}
        resolve_profile(
            "sub-3", "tok", userinfo_url=f"{jwks_server.issuer}/userinfo", disabled=False
        )
        count_after_first = jwks_server.request_count
        resolve_profile(
            "sub-3", "tok", userinfo_url=f"{jwks_server.issuer}/userinfo", disabled=False
        )
        assert jwks_server.request_count == count_after_first  # second call hit the cache

    def test_mismatched_sub_in_response_is_ignored(self, jwks_server: JwksTestServer) -> None:
        jwks_server.userinfo_response = {"sub": "someone-else", "name": "Mallory"}
        name, picture = resolve_profile(
            "sub-4", "tok", userinfo_url=f"{jwks_server.issuer}/userinfo", disabled=False
        )
        assert (name, picture) == (None, None)

    def test_missing_sub_in_response_is_ignored(self, jwks_server: JwksTestServer) -> None:
        jwks_server.userinfo_response = {"name": "No Sub Here"}
        name, picture = resolve_profile(
            "sub-5", "tok", userinfo_url=f"{jwks_server.issuer}/userinfo", disabled=False
        )
        assert (name, picture) == (None, None)

    def test_disabled_skips_network_call(self, jwks_server: JwksTestServer) -> None:
        jwks_server.userinfo_response = {"sub": "sub-6", "name": "Should Not Appear"}
        name, picture = resolve_profile(
            "sub-6", "tok", userinfo_url=f"{jwks_server.issuer}/userinfo", disabled=True
        )
        assert (name, picture) == (None, None)
        assert jwks_server.request_count == 0

    def test_no_access_token_skips_network_call(self, jwks_server: JwksTestServer) -> None:
        name, picture = resolve_profile(
            "sub-7", None, userinfo_url=f"{jwks_server.issuer}/userinfo", disabled=False
        )
        assert (name, picture) == (None, None)
        assert jwks_server.request_count == 0

    def test_no_sub_skips_network_call(self, jwks_server: JwksTestServer) -> None:
        name, picture = resolve_profile(
            None, "tok", userinfo_url=f"{jwks_server.issuer}/userinfo", disabled=False
        )
        assert (name, picture) == (None, None)
        assert jwks_server.request_count == 0

    def test_no_userinfo_url_skips_network_call(self) -> None:
        name, picture = resolve_profile("sub-8", "tok", userinfo_url=None, disabled=False)
        assert (name, picture) == (None, None)

    def test_endpoint_error_fails_open_without_caching(self, jwks_server: JwksTestServer) -> None:
        jwks_server.userinfo_response = None  # 404s
        name, picture = resolve_profile(
            "sub-9", "tok", userinfo_url=f"{jwks_server.issuer}/userinfo", disabled=False
        )
        assert (name, picture) == (None, None)
        # Not cached: a subsequent healthy response should still resolve.
        jwks_server.userinfo_response = {"sub": "sub-9", "name": "Dana"}
        name, picture = resolve_profile(
            "sub-9", "tok", userinfo_url=f"{jwks_server.issuer}/userinfo", disabled=False
        )
        assert (name, picture) == ("Dana", None)
