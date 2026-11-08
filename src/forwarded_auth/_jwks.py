"""JWT verification against a trusted issuer's JWKS, with optional OIDC
discovery.

This is the library's defence-in-depth against identity-header spoofing:
anything with network reach to an app that trusts proxy-forwarded headers
unconditionally could set those headers and authenticate as anyone. By
cryptographically verifying the forwarded bearer token against the
configured issuer's JWKS on every request, the app can be sure the
identity came from a real sign-in through the trusted issuer, not from a
spoofer sitting between the proxy and the app (or skipping the proxy
entirely).

Three verification paths share this module's primitives:

- **forwarded mode** — verify the bearer the auth proxy forwarded,
  against ``Settings.issuer`` / ``Settings.jwks_url``.
- **oidc mode** — the same verification, driven entirely by OIDC
  discovery off ``Settings.issuer`` (no proxy headers involved).
- **additional issuer** — a second, independently configured trusted
  issuer for short-lived, audience-bound tokens (e.g. a machine/service
  caller), verified against its own isolated JWKS cache.

``InvalidIdentityToken`` is raised on any verification failure. Callers
are expected to surface a 401 — never fall back to trusting headers
alone when this is raised.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from typing import Any

import jwt
from jwt import PyJWKClient

_logger = logging.getLogger(__name__)

_HTTP_TIMEOUT_S = 5.0

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})

_FORCED_REFRESH_COOLDOWN_S = 60.0

# How long a *failed* OIDC discovery fetch is cached before being retried.
# Deliberately much shorter than the success-path `discovery_cache_ttl_s`
# (which defaults to 3600s): a transient IdP outage must not make the NEXT
# request pay the same 5s HTTP timeout, but it also must not be treated as
# cached-good for a full hour once the IdP recovers.
_DISCOVERY_FAILURE_CACHE_TTL_S = 30.0


class InvalidIdentityToken(Exception):
    """Raised when a forwarded or directly-presented bearer token fails
    verification (signature, expiry, issuer, audience, or domain-allowlist
    checks all raise this).

    Caught at the framework boundary and surfaced as a 401. The
    ``reason`` string is operator-readable, intended for structured
    logs; it is **not** constant-time and callers should not echo it
    verbatim in a response body (a generic "Authentication required" is
    the right thing to show a caller probing the surface).
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# --- OIDC discovery cache -----------------------------------------------


class _DiscoveryCache:
    """Process-wide cache of ``{issuer}/.well-known/openid-configuration``
    documents, keyed by issuer, with a configurable TTL.

    Also caches a FAILED fetch for :data:`_DISCOVERY_FAILURE_CACHE_TTL_S`
    and re-raises the cached :class:`InvalidIdentityToken` on every call
    within that window, instead of re-attempting the (5s-timeout) HTTP
    fetch on every single request. Without this, an IdP outage turns
    every request against this issuer into a 5s wait instead of a fast
    failure.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, tuple[dict[str, Any], float]] = {}
        self._failures: dict[str, tuple[InvalidIdentityToken, float]] = {}

    def get(self, issuer: str, ttl_s: float) -> dict[str, Any]:
        now = time.time()
        with self._lock:
            cached = self._entries.get(issuer)
            if cached is not None and now < cached[1]:
                return cached[0]
            failure = self._failures.get(issuer)
            if failure is not None and now < failure[1]:
                raise failure[0]
        try:
            document = _fetch_discovery_document(issuer)
        except InvalidIdentityToken as exc:
            with self._lock:
                self._failures[issuer] = (exc, now + _DISCOVERY_FAILURE_CACHE_TTL_S)
            raise
        with self._lock:
            self._entries[issuer] = (document, now + ttl_s)
            self._failures.pop(issuer, None)
        return document

    def reset(self) -> None:
        with self._lock:
            self._entries.clear()
            self._failures.clear()


_discovery_cache = _DiscoveryCache()


def _is_loopback_host(hostname: str | None) -> bool:
    return bool(hostname) and hostname.lower() in _LOOPBACK_HOSTS


def _require_secure_url(url: str, *, label: str) -> None:
    """Fail closed on anything but ``https://`` (or plain ``http://`` to
    a loopback host — ``localhost``/``127.0.0.1``/``::1``, so tests and
    local dev can keep using a local HTTP server). Rejects any other
    scheme outright (``file:``, etc.), bare host-only values, URLs with
    no hostname at all, and URLs carrying embedded ``user:pass@`` style
    credentials (a sign of a copy-pasted/SSRF-crafted URL, never a
    legitimate issuer/JWKS/userinfo endpoint)."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise InvalidIdentityToken(
            f"{label} must be an http(s) URL, got {url!r} (scheme {parsed.scheme!r})"
        )
    if not parsed.hostname:
        raise InvalidIdentityToken(f"{label} must have a hostname, got {url!r}")
    if parsed.username or parsed.password:
        raise InvalidIdentityToken(f"{label} must not contain embedded credentials, got {url!r}")
    if parsed.scheme == "http" and not _is_loopback_host(parsed.hostname):
        raise InvalidIdentityToken(
            f"{label} must use https:// except for a loopback host, got {url!r}"
        )


def _fetch_discovery_document(issuer: str) -> dict[str, Any]:
    _require_secure_url(issuer, label="issuer")
    url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_S) as resp:  # noqa: S310
            body = resp.read()
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise InvalidIdentityToken(f"OIDC discovery fetch failed for {issuer!r}: {exc}") from exc
    try:
        parsed = json.loads(body)
    except ValueError as exc:
        raise InvalidIdentityToken(f"OIDC discovery document was not JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise InvalidIdentityToken("OIDC discovery document was not a JSON object")
    doc_issuer = parsed.get("issuer")
    if doc_issuer != issuer:
        raise InvalidIdentityToken(
            f"OIDC discovery document issuer {doc_issuer!r} does not match configured "
            f"issuer {issuer!r}"
        )
    return parsed


def discover_jwks_url(issuer: str, *, ttl_s: float = 3600.0) -> str:
    """Resolve ``issuer``'s ``jwks_uri`` via OIDC discovery (cached)."""
    document = _discovery_cache.get(issuer, ttl_s)
    jwks_uri = document.get("jwks_uri")
    if not isinstance(jwks_uri, str) or not jwks_uri:
        raise InvalidIdentityToken(f"OIDC discovery document for {issuer!r} has no jwks_uri")
    _require_secure_url(jwks_uri, label="discovered jwks_uri")
    return jwks_uri


def discover_userinfo_url(issuer: str, *, ttl_s: float = 3600.0) -> str | None:
    """Resolve ``issuer``'s ``userinfo_endpoint`` via OIDC discovery
    (cached). Returns ``None`` if the provider doesn't advertise one."""
    document = _discovery_cache.get(issuer, ttl_s)
    endpoint = document.get("userinfo_endpoint")
    if not (isinstance(endpoint, str) and endpoint):
        return None
    _require_secure_url(endpoint, label="discovered userinfo_endpoint")
    return endpoint


def _reset_discovery_cache_for_tests() -> None:
    _discovery_cache.reset()


# --- JWKS client cache ---------------------------------------------------

_jwks_lock = threading.Lock()
_jwks_clients: dict[str, PyJWKClient] = {}
_last_forced_refresh: dict[str, float] = {}


def _get_jwks_client(jwks_url: str, *, ttl_s: float = 3600.0) -> PyJWKClient:
    """Return the process-wide ``PyJWKClient`` for ``jwks_url``, cached
    by URL so distinct issuers (or a test pointing at a local server)
    never share state."""
    with _jwks_lock:
        client = _jwks_clients.get(jwks_url)
        if client is None:
            client = PyJWKClient(jwks_url, cache_jwk_set=True, lifespan=ttl_s, cache_keys=False)
            _jwks_clients[jwks_url] = client
        return client


def _allow_forced_refresh(jwks_url: str) -> bool:
    """Rate-limit the forced-refresh-on-unknown-kid path to at most once
    per JWKS URL per :data:`_FORCED_REFRESH_COOLDOWN_S`. Without this, a
    caller presenting a token with a bogus/unknown ``kid`` on every
    request would force a JWKS refetch on every single request — a
    cheap way to hammer the issuer's JWKS endpoint. Inside the cooldown
    window, an unknown kid simply fails (no network call); key rotation
    is still picked up, just at most once per window."""
    now = time.time()
    with _jwks_lock:
        last = _last_forced_refresh.get(jwks_url, 0.0)
        if now - last < _FORCED_REFRESH_COOLDOWN_S:
            return False
        _last_forced_refresh[jwks_url] = now
        return True


def _reset_forced_refresh_for_tests() -> None:
    with _jwks_lock:
        _last_forced_refresh.clear()


def _get_signing_key(client: PyJWKClient, kid: str | None, jwks_url: str) -> jwt.PyJWK:
    """Find ``kid``, explicitly refetching the JWKS on a miss — but at
    most once per ``jwks_url`` per :data:`_FORCED_REFRESH_COOLDOWN_S`
    (see :func:`_allow_forced_refresh`). PyJWT 2.15+ added a cooldown
    after every fetch, so a cold lookup's initial fetch would otherwise
    start that cooldown and ``PyJWKClient.get_signing_key``'s historical
    forced-refresh-on-miss behaviour would no longer fire. Using the
    lower-level public APIs keeps rotation behaviour (a refresh on an
    unknown kid, rate-limited) stable across PyJWT versions.

    Note: because the forced refresh is rate-limited to once per
    ``jwks_url`` per :data:`_FORCED_REFRESH_COOLDOWN_S`, a newly rotated
    key can take up to that long (60s) to be picked up if the first
    request bearing its ``kid`` lands right after a just-exhausted
    cooldown window. This is intentional (it's what closes the
    unrate-limited forced-refresh-per-request DoS this cooldown exists
    for) and relies on providers publishing a new key in their JWKS
    some time before issuing tokens signed with it, as OIDC key
    rotation guidance generally recommends."""
    signing_key = client.match_kid(client.get_signing_keys(), kid)
    if signing_key is None and _allow_forced_refresh(jwks_url):
        signing_key = client.match_kid(client.get_signing_keys(refresh=True), kid)
    if signing_key is None:
        raise jwt.exceptions.PyJWKClientError(f'Unable to find a signing key that matches: "{kid}"')
    return signing_key


def _reset_jwks_clients_for_tests() -> None:
    with _jwks_lock:
        _jwks_clients.clear()


# --- allowlist ------------------------------------------------------------


def enforce_email_domain(claims: Mapping[str, Any], allowed_domains: frozenset[str]) -> None:
    """Reject a verified token whose ``email`` claim is outside
    ``allowed_domains``. No-op when ``allowed_domains`` is empty, or is
    exactly the explicit wildcard ``{"*"}`` — both mean "no domain
    restriction", but ``Settings.require_forwarded_or_oidc_config()``
    requires one of those to be an explicit operator choice (comma-
    separated domains, or literally ``"*"``) rather than a silent
    default for the primary verification path; this function stays
    permissive on an empty set so it also works for callers (like the
    additional-issuer path) that pass it through unconditionally."""
    if not allowed_domains or allowed_domains == frozenset({"*"}):
        return
    email = claims.get("email")
    if not isinstance(email, str) or "@" not in email:
        raise InvalidIdentityToken(
            "email-domain allowlist is configured but token has no usable email claim"
        )
    domain = email.rsplit("@", 1)[-1].lower()
    if domain not in allowed_domains:
        raise InvalidIdentityToken(f"email domain {domain!r} is not in the allowlist")


# --- primary verification --------------------------------------------------


_DEFAULT_REQUIRED_CLAIMS: tuple[str, ...] = ("exp", "iat", "iss", "aud", "sub")


def verify_jwt(
    token: str,
    *,
    issuer: str | Sequence[str],
    audience: Sequence[str],
    jwks_url: str | None = None,
    jwks_cache_ttl_s: float = 3600.0,
    discovery_cache_ttl_s: float = 3600.0,
    leeway: float = 10.0,
    required_claims: Sequence[str] = _DEFAULT_REQUIRED_CLAIMS,
) -> dict[str, Any]:
    """Verify ``token``'s RS256 signature and standard claims against
    ``issuer``'s JWKS (resolved via OIDC discovery if ``jwks_url`` is
    not given). Returns the decoded claims on success; raises
    :class:`InvalidIdentityToken` on any failure.

    ``issuer`` may be a single issuer string, or a sequence of issuer
    strings a token's ``iss`` claim is allowed to match (e.g. to accept
    both ``https://accounts.google.com`` and bare
    ``accounts.google.com``). When it's a sequence, the FIRST entry is
    the one used for OIDC discovery (when ``jwks_url`` is unset) and for
    the https/loopback scheme check below — the other entries are only
    ever compared against the token's claim, never used to build a URL.

    ``leeway`` tolerates small clock skew between the issuer and this
    process on the time-bound claims (``exp``/``nbf``/``iat``).

    ``required_claims`` are passed to PyJWT's ``options={"require": ...}``
    — a token missing any of them is rejected outright, regardless of
    whether this library would otherwise have checked that claim.
    """
    if not token:
        raise InvalidIdentityToken("empty token")
    if not audience:
        raise InvalidIdentityToken("no accepted audience configured")

    issuers = (issuer,) if isinstance(issuer, str) else tuple(issuer)
    if not issuers:
        raise InvalidIdentityToken("no issuer configured")
    primary_issuer = issuers[0]
    _require_secure_url(primary_issuer, label="issuer")

    resolved_jwks_url = jwks_url or discover_jwks_url(primary_issuer, ttl_s=discovery_cache_ttl_s)
    _require_secure_url(resolved_jwks_url, label="jwks_url")
    client = _get_jwks_client(resolved_jwks_url, ttl_s=jwks_cache_ttl_s)

    try:
        unverified_header = jwt.get_unverified_header(token)
        signing_key = _get_signing_key(client, unverified_header.get("kid"), resolved_jwks_url)
    except jwt.exceptions.PyJWKClientError as exc:
        _logger.warning("JWKS key lookup failed: %s", exc)
        raise InvalidIdentityToken(f"JWKS key lookup failed: {exc}") from exc
    except jwt.exceptions.DecodeError as exc:
        raise InvalidIdentityToken(f"malformed token header: {exc}") from exc
    except Exception as exc:  # pragma: no cover - defensive
        _logger.warning("Unexpected error fetching JWKS key: %s", exc)
        raise InvalidIdentityToken(f"JWKS fetch failed: {exc}") from exc

    try:
        return jwt.decode(
            token,
            key=signing_key.key,
            algorithms=["RS256"],
            audience=list(audience),
            issuer=issuers[0] if len(issuers) == 1 else list(issuers),
            leeway=leeway,
            options={"require": list(required_claims)},
        )
    except jwt.MissingRequiredClaimError as exc:
        raise InvalidIdentityToken(f"missing required claim: {exc}") from exc
    except jwt.ExpiredSignatureError as exc:
        raise InvalidIdentityToken(f"token expired: {exc}") from exc
    except jwt.InvalidAudienceError as exc:
        raise InvalidIdentityToken(f"audience mismatch: {exc}") from exc
    except jwt.InvalidIssuerError as exc:
        raise InvalidIdentityToken(f"issuer mismatch: {exc}") from exc
    except jwt.ImmatureSignatureError as exc:
        raise InvalidIdentityToken(f"token not yet valid: {exc}") from exc
    except jwt.InvalidSignatureError as exc:
        raise InvalidIdentityToken(f"signature mismatch: {exc}") from exc
    except jwt.PyJWTError as exc:
        raise InvalidIdentityToken(f"token verification failed: {exc}") from exc


def decode_unverified(token: str) -> dict[str, Any]:
    """Decode a token's claims WITHOUT verifying the signature. Used
    only on the explicit dev-mode header-trust path — never on a
    production verification path. Returns ``{}`` on any decode failure;
    never raises."""
    if not token:
        return {}
    try:
        return jwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_aud": False,
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
                "verify_iss": False,
            },
        )
    except jwt.PyJWTError as exc:
        _logger.debug("Failed to decode forwarded token: %s", exc)
        return {}
    except Exception as exc:  # pragma: no cover - defensive
        _logger.debug("Unexpected error decoding forwarded token: %s", exc)
        return {}


def peek_unverified_issuer(token: str) -> str | None:
    """Return a token's unverified ``iss`` claim, or ``None`` on any
    decode failure. Used only to *select* which configured issuer
    should verify a token — the selected issuer's verifier still does
    full signature/claim verification."""
    claims = decode_unverified(token)
    issuer = claims.get("iss")
    return issuer if isinstance(issuer, str) and issuer else None


def verify_additional_issuer_token(
    token: str,
    *,
    issuer: str,
    jwks_url: str,
    audience: str,
    actor_claim: str,
    scope_claim: str,
    max_lifetime_s: float,
    jwks_cache_ttl_s: float = 3600.0,
    leeway: float = 10.0,
    allowed_email_domains: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Verify a token from the configurable *additional trusted issuer*
    (the generalised form of a short-lived, audience-bound second-issuer
    path for machine/service callers). On top of :func:`verify_jwt`'s
    signature/issuer/audience checks, this additionally requires:

    - RS256 only (checked on the unverified header before any network
      call, to fail fast on an obviously-wrong token shape)
    - ``iss``/``aud``/``sub``/``iat``/``exp``/``actor_claim`` all present
      (enforced via PyJWT's ``options={"require": ...}``, so a token
      missing any of them is rejected outright rather than reaching the
      manual checks below with a ``None``)
    - ``sub`` is a non-empty string shaped like an email address
      (contains exactly one ``@``, with a non-empty local and domain
      part) -- this path's ``sub`` becomes ``User.email``, so a
      malformed value would corrupt every downstream identity decision
    - ``sub``'s domain is in ``allowed_email_domains`` (same allowlist
      semantics as :func:`enforce_email_domain`: empty or ``{"*"}``
      means no restriction)
    - ``iat`` and ``exp`` present and numeric, with
      ``exp - iat <= max_lifetime_s`` -- these tokens are meant to be
      short-lived; a long-lived one is treated as misconfigured
      upstream and rejected
    - a non-empty value for ``actor_claim`` with no whitespace -- every
      identity on this path is a machine acting for an owner, and
      without an actor it would be indistinguishable from a human
      identity to anything downstream that branches on ``User.actor``

    Returns the verified claims dict. Raises :class:`InvalidIdentityToken`
    on any failure -- never ``KeyError``/``AssertionError``: a missing or
    malformed ``sub`` is a 401, not a 500.
    """
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.exceptions.DecodeError as exc:
        raise InvalidIdentityToken(f"malformed token header: {exc}") from exc
    if unverified_header.get("alg") != "RS256":
        raise InvalidIdentityToken("additional-issuer token algorithm must be RS256")

    claims = verify_jwt(
        token,
        issuer=issuer,
        audience=[audience],
        jwks_url=jwks_url,
        jwks_cache_ttl_s=jwks_cache_ttl_s,
        leeway=leeway,
        required_claims=("iss", "aud", "sub", "iat", "exp", actor_claim),
    )

    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub:
        raise InvalidIdentityToken("additional-issuer token missing a usable sub claim")
    local_part, _, domain_part = sub.partition("@")
    if not local_part or not domain_part or "@" in domain_part:
        raise InvalidIdentityToken("additional-issuer token sub must look like an email address")
    enforce_email_domain({"email": sub}, allowed_email_domains)

    if claims.get("aud") != audience:
        # PyJWT's `audience=[...]` accepts a token whose `aud` matches ANY
        # entry in the list; this path only ever passes one value, so
        # require an exact match rather than widening the contract.
        raise InvalidIdentityToken("additional-issuer audience must exactly match configuration")

    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    numeric_types = (int, float)
    if (
        isinstance(issued_at, bool)
        or not isinstance(issued_at, numeric_types)
        or isinstance(expires_at, bool)
        or not isinstance(expires_at, numeric_types)
    ):
        raise InvalidIdentityToken("additional-issuer token iat and exp must be numeric")
    if expires_at - issued_at > max_lifetime_s:
        raise InvalidIdentityToken(f"additional-issuer token lifetime exceeds {max_lifetime_s}s")

    actor = claims.get(actor_claim)
    if not isinstance(actor, str) or not actor or any(ch.isspace() for ch in actor):
        raise InvalidIdentityToken(
            f"additional-issuer token {actor_claim!r} must be a non-empty string without whitespace"
        )

    return claims
