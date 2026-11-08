"""``User`` dataclass + header-to-``User`` parsing. Framework-agnostic.

Strict-default security posture: ``user_from_headers`` requires a
verified bearer JWT on every request unless the operator has explicitly
selected a less strict mode (``mode="none"`` for local dev, or
``require_jwt=False`` as an explicit escape valve). The library never
trusts proxy-forwarded identity headers (``X-Auth-Request-*`` or
similar) without that verification by default, because on most
deployments anything with direct network reach to the app can set
arbitrary headers and authenticate as anyone if the app trusts them
unconditionally.
"""

from __future__ import annotations

import logging
import warnings
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from forwarded_auth._jwks import (
    InvalidIdentityToken,
    decode_unverified,
    discover_userinfo_url,
    peek_unverified_issuer,
    verify_additional_issuer_token,
    verify_jwt,
)
from forwarded_auth._jwks import (
    enforce_email_domain as _enforce_email_domain,
)
from forwarded_auth._settings import (
    ENV_ALLOWED_EMAIL_DOMAINS,
    MODE_NONE,
    MODE_OIDC,
    ConfigurationError,
    Settings,
    get_settings,
    with_settings,
)
from forwarded_auth._userinfo import remember_profile, resolve_profile

_logger = logging.getLogger(__name__)

BEARER_PREFIX = "Bearer "
# Public re-export name (see forwarded_auth.__init__); `BEARER_PREFIX` stays
# for internal use within this module.
AUTH_HEADER_BEARER_PREFIX = BEARER_PREFIX


@dataclass(frozen=True, slots=True)
class User:
    """An authenticated user, populated from a verified bearer token (or,
    in dev/legacy modes, from forwarded identity headers alone).

    ``email``, ``name``, and ``user_id`` are guaranteed non-empty when
    this object exists. ``bearer_token``, ``picture``, ``actor``, and
    ``scope`` are optional.

    ``user_from_headers`` returns ``None`` when the request can't be
    authenticated, and raises :class:`InvalidIdentityToken` when a
    bearer is present but fails verification — see its docstring for
    the full decision tree.

    ``actor`` / ``scope`` are populated only for identities verified
    against the configurable *additional trusted issuer* (short-lived,
    audience-bound machine/service tokens) — see
    ``Settings.additional_issuer``. Both are ``None`` for every other
    identity.
    """

    email: str
    name: str
    user_id: str
    bearer_token: str | None = None
    picture: str | None = None
    actor: str | None = None
    scope: str | None = None

    @property
    def is_bot(self) -> bool:
        """Whether a signed machine actor is present. Never infer this
        from the shape of the owner's email — only a verified
        additional-issuer token sets ``actor``."""
        return self.actor is not None

    @property
    def gateway_scope(self) -> str | None:
        """Deprecated alias for :attr:`scope`, kept for API parity with
        the internal predecessor library this package was generalised
        from. Use :attr:`scope` instead."""
        warnings.warn(
            "User.gateway_scope is deprecated; use User.scope instead",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.scope

    @property
    def display_name(self) -> str:
        """Best-effort human-readable name, falling back to email."""
        return self.name or self.email


def _header_lookup(headers: Mapping[str, str], name: str) -> str | None:
    """Case-insensitive single-header lookup. Different frameworks
    normalize header casing differently (FastAPI/Starlette lowercase
    everything; Streamlit's ``st.context.headers`` keeps original
    case), so this covers both plus an unordered-dict fallback scan."""
    direct = headers.get(name)
    if direct:
        return direct
    lower = headers.get(name.lower())
    if lower:
        return lower
    target = name.lower()
    for k, v in headers.items():
        if k.lower() == target and v:
            return v
    return None


def _extract_bearer(headers: Mapping[str, str], authorization_header: str) -> str | None:
    auth = _header_lookup(headers, authorization_header)
    if not auth or not auth.startswith(BEARER_PREFIX):
        return None
    bearer = auth[len(BEARER_PREFIX) :].strip()
    return bearer or None


def _extract_access_token(headers: Mapping[str, str], header_names: tuple[str, ...]) -> str | None:
    for header_name in header_names:
        raw = _header_lookup(headers, header_name)
        if raw:
            stripped = raw.strip()
            if stripped:
                return stripped
    return None


def dev_user(settings: Settings) -> User:
    """The fixed local-development user for ``mode="none"``.

    The loud "no verification" warning is logged once per process by
    ``Settings.__post_init__`` (not on every call here) — see
    ``Settings.allow_insecure_none_mode`` and the README's "Modes"
    section. This mode must never be mistaken for a verified identity,
    and should never run in production."""
    return User(
        email=settings.dev_user_email,
        name=settings.dev_user_name or settings.dev_user_email,
        user_id=settings.dev_user_id or settings.dev_user_email,
    )


def _effective_userinfo_url(settings: Settings, issuer: str | None) -> str | None:
    """Resolve the userinfo endpoint to use for profile-claim recovery:
    the explicitly configured URL if set, else — in ``oidc`` mode, with
    a known issuer — the ``userinfo_endpoint`` OIDC discovery advertises
    for that issuer. Returns ``None`` (disabling the network fallback,
    not the cache) when neither is available or discovery fails."""
    if settings.userinfo_url:
        return settings.userinfo_url
    if settings.mode != MODE_OIDC or not issuer:
        return None
    try:
        return discover_userinfo_url(issuer, ttl_s=settings.discovery_cache_ttl_s)
    except InvalidIdentityToken:
        return None


def _build_user_from_verified_claims(
    claims: Mapping[str, Any],
    bearer: str,
    headers: Mapping[str, str],
    settings: Settings,
    *,
    issuer: str | None = None,
) -> User | None:
    """Construct a ``User`` from verified primary-issuer claims,
    cross-checking the configured email header against the token's
    ``email`` claim when the header is present.

    Returns ``None`` when the token has no usable ``email`` claim.
    Raises :class:`InvalidIdentityToken` if a present email header
    disagrees with the verified token's email — that is a spoofing
    attempt (the attacker holds a valid token for one address but set
    the header to another), which this cross-check closes — or if
    ``settings.require_email_verified`` is true and the token's
    ``email_verified`` claim isn't ``True``/``"true"``.
    """
    token_email = claims.get("email")
    if not isinstance(token_email, str) or not token_email:
        return None

    _enforce_user_claim_policy(claims, settings)

    header_email = _header_lookup(headers, settings.email_header)
    if header_email and header_email != token_email:
        raise InvalidIdentityToken(
            f"{settings.email_header} header does not match verified token email"
        )

    token_sub = claims.get("sub")
    sub_str = token_sub if isinstance(token_sub, str) and token_sub else None
    user_id = sub_str or (_header_lookup(headers, settings.user_header) or token_email)

    raw_name = claims.get("name")
    token_name = raw_name if isinstance(raw_name, str) and raw_name else None
    raw_picture = claims.get("picture")
    token_picture = raw_picture if isinstance(raw_picture, str) and raw_picture else None

    if token_name is not None or token_picture is not None:
        remember_profile(sub_str, token_name, token_picture)
        resolved_name, resolved_picture = token_name, token_picture
    else:
        access_token = _extract_access_token(headers, settings.access_token_headers)
        resolved_name, resolved_picture = resolve_profile(
            sub_str,
            access_token,
            userinfo_url=_effective_userinfo_url(settings, issuer),
            disabled=settings.disable_userinfo_fallback,
        )

    header_name = _header_lookup(headers, settings.preferred_username_header)
    name = resolved_name or header_name or token_email

    return User(
        email=token_email,
        name=name,
        user_id=user_id,
        bearer_token=bearer,
        picture=resolved_picture or None,
    )


def _enforce_user_claim_policy(claims: Mapping[str, Any], settings: Settings) -> None:
    """Apply the primary-issuer identity policy that every caller which
    trusts verified claims must enforce: ``require_email_verified`` and
    the email-domain allowlist (:func:`_enforce_email_domain`). Shared
    by :func:`_build_user_from_verified_claims` (building a ``User``
    from ``user_from_headers``) and :func:`verify_token`/
    :func:`verify_id_token` (returning raw verified claims directly) so
    a caller using the lower-level ``verify_token`` API gets the same
    fail-closed posture instead of silently skipping both checks.

    Raises :class:`InvalidIdentityToken` if ``require_email_verified``
    is true and the token's ``email_verified`` claim isn't
    ``True``/``"true"``, or if the token's email domain is outside
    ``settings.allowed_email_domains``.
    """
    if settings.require_email_verified:
        email_verified = claims.get("email_verified")
        is_verified = email_verified is True or (
            isinstance(email_verified, str) and email_verified.strip().lower() == "true"
        )
        if not is_verified:
            raise InvalidIdentityToken(
                "token's email_verified claim is not true; refusing to trust an unverified "
                "email address (set require_email_verified=False to override)"
            )
    _enforce_email_domain(claims, settings.allowed_email_domains)


def _build_user_from_additional_issuer_claims(
    claims: Mapping[str, Any], bearer: str, settings: Settings
) -> User:
    """Construct a ``User`` from a verified additional-issuer token.
    Identity is entirely claim-backed: ``sub`` is the owner's email,
    ``actor_claim`` identifies the machine acting for that owner.
    Proxy-forwarded identity headers are intentionally ignored on this
    path — the token is the sole source of truth. ``sub``'s presence
    and email shape were already validated (and its domain enforced)
    by :func:`verify_additional_issuer_token`, so this is a plain
    string here — never a ``KeyError``/``AssertionError`` surprise."""
    sub = claims["sub"]
    local_part = sub.rpartition("@")[0]

    raw_actor = claims.get(settings.additional_issuer_actor_claim)
    actor = raw_actor if isinstance(raw_actor, str) and raw_actor else None
    raw_scope = claims.get(settings.additional_issuer_scope_claim)
    scope = raw_scope if isinstance(raw_scope, str) and raw_scope else None

    return User(
        email=sub,
        name=local_part or sub,
        user_id=sub,
        bearer_token=bearer,
        actor=actor,
        scope=scope,
    )


def _build_user_from_proxy_headers(headers: Mapping[str, str], settings: Settings) -> User | None:
    """Construct a ``User`` from the configurable trusted-upstream-proxy
    header set (the generalised form of a second proxy hop that
    authenticates out-of-band and relays identity as headers instead of
    a bearer). Only ever reached when ``Settings.trust_proxy_headers``
    is enabled by the caller — see ``user_from_headers``."""
    raw_email = _header_lookup(headers, settings.proxy_email_header)
    email = raw_email.strip() if raw_email else ""
    if not email:
        return None
    _enforce_email_domain({"email": email}, settings.allowed_email_domains)
    raw_user_id = _header_lookup(headers, settings.proxy_user_header)
    user_id = raw_user_id.strip() if raw_user_id else ""
    raw_name = _header_lookup(headers, settings.proxy_name_header)
    name = raw_name.strip() if raw_name else ""
    return User(
        email=email,
        name=name or email,
        user_id=user_id or email,
    )


def _build_user_from_headers_legacy(headers: Mapping[str, str], settings: Settings) -> User | None:
    """Legacy header-only path. Reached only when ``require_jwt=False``
    — never on a production code path. Trusts the configured email
    header outright and only decodes the bearer (unverified) for
    cosmetic name/picture."""
    email = _header_lookup(headers, settings.email_header)
    if not email:
        return None
    bearer = _extract_bearer(headers, settings.authorization_header)
    claims = decode_unverified(bearer) if bearer else {}
    claim_name = claims.get("name")
    claim_picture = claims.get("picture")
    header_name = _header_lookup(headers, settings.preferred_username_header)
    name = (
        (claim_name if isinstance(claim_name, str) and claim_name else None) or header_name or email
    )
    user_id = _header_lookup(headers, settings.user_header) or email
    picture = claim_picture if isinstance(claim_picture, str) and claim_picture else None
    return User(email=email, name=name, user_id=user_id, bearer_token=bearer, picture=picture)


def user_from_headers(
    headers: Mapping[str, str],
    *,
    settings: Settings | None = None,
    jwks_uri: str | None = None,
) -> User | None:
    """Build a ``User`` from a request-headers mapping, or return
    ``None`` if the request can't be authenticated.

    Decision tree (settings resolved from env unless passed explicitly):

    - ``mode="none"``: always returns the fixed dev user (headers are
      ignored). ``Settings.__post_init__`` already logged a loud
      once-per-process warning when this mode was configured.
    - A bearer is present under ``settings.authorization_header``:
      - if ``Settings.additional_issuer`` is configured and the
        token's unverified ``iss`` matches it, verifies against that
        issuer's JWKS and builds a machine/actor identity;
      - otherwise verifies against the primary issuer
        (``mode="forwarded"``/``"oidc"``, both via :mod:`forwarded_auth._jwks`).
      - A verification failure raises :class:`InvalidIdentityToken`,
        UNLESS ``require_jwt=False``, in which case it falls back to
        the unverified legacy header path (dev only). The same
        fallback applies if the primary-issuer config itself is
        missing (:class:`ConfigurationError`) while ``require_jwt`` is
        false — see ``Settings.validate`` for the startup-time check
        apps should prefer over discovering this at request time.
    - No bearer present:
      - if ``trust_proxy_headers`` is enabled, tries the configured
        proxy header set;
      - else if ``require_jwt=False``, falls back to the legacy header
        path;
      - else returns ``None``.

    The library NEVER silently falls through to a less-verified path
    when a bearer IS present but fails verification and ``require_jwt``
    is true — that would reopen exactly the header-spoofing gap this
    library exists to close. A :class:`ConfigurationError` with
    ``require_jwt=True`` also propagates uncaught (surfaces as a 500 by
    design — a misconfigured deployment should fail loudly, not quietly
    accept unverified traffic).

    ``jwks_uri`` is a deprecated override of ``settings.jwks_url``, kept
    for API parity with the internal predecessor library; pass
    ``settings=Settings(..., jwks_url=...)`` instead.
    """
    settings = settings or get_settings()
    if jwks_uri is not None:
        warnings.warn(
            "user_from_headers(jwks_uri=...) is deprecated; configure "
            "FORWARDED_AUTH_JWKS_URL or pass settings=Settings(jwks_url=...) instead",
            DeprecationWarning,
            stacklevel=2,
        )
        settings = with_settings(settings, jwks_url=jwks_uri)

    if settings.mode == MODE_NONE:
        return dev_user(settings)

    bearer = _extract_bearer(headers, settings.authorization_header)

    if bearer is None:
        if settings.trust_proxy_headers:
            if not settings.allowed_email_domains:
                raise ConfigurationError(
                    f"{ENV_ALLOWED_EMAIL_DOMAINS} is unset; trust_proxy_headers requires a "
                    "configured email-domain allowlist — see Settings.validate()"
                )
            proxy_user = _build_user_from_proxy_headers(headers, settings)
            if proxy_user is not None:
                return proxy_user
        if not settings.require_jwt:
            return _build_user_from_headers_legacy(headers, settings)
        return None

    try:
        if (
            settings.additional_issuer
            and peek_unverified_issuer(bearer) == settings.additional_issuer
        ):
            jwks_url = settings.additional_issuer_jwks_url or (
                f"{settings.additional_issuer.rstrip('/')}/.well-known/jwks.json"
            )
            if not settings.additional_issuer_audience:
                raise InvalidIdentityToken(
                    "FORWARDED_AUTH_ADDITIONAL_ISSUER_AUDIENCE is unset; cannot verify "
                    "additional-issuer audience"
                )
            if not settings.allowed_email_domains:
                raise ConfigurationError(
                    f"{ENV_ALLOWED_EMAIL_DOMAINS} is unset; the additional-issuer path always "
                    "requires a configured email-domain allowlist, to decide which verified "
                    "sub/email domains to admit — see Settings.validate()"
                )
            claims = verify_additional_issuer_token(
                bearer,
                issuer=settings.additional_issuer,
                jwks_url=jwks_url,
                audience=settings.additional_issuer_audience,
                actor_claim=settings.additional_issuer_actor_claim,
                scope_claim=settings.additional_issuer_scope_claim,
                max_lifetime_s=settings.additional_issuer_max_lifetime_s,
                jwks_cache_ttl_s=settings.jwks_cache_ttl_s,
                allowed_email_domains=settings.allowed_email_domains,
            )
            return _build_user_from_additional_issuer_claims(claims, bearer, settings)

        issuers, audience = settings.require_forwarded_or_oidc_config()
        claims = verify_jwt(
            bearer,
            issuer=issuers,
            audience=audience,
            jwks_url=settings.jwks_url,
            jwks_cache_ttl_s=settings.jwks_cache_ttl_s,
            discovery_cache_ttl_s=settings.discovery_cache_ttl_s,
        )
        primary_issuer = issuers[0]
    except (InvalidIdentityToken, ConfigurationError):
        if not settings.require_jwt:
            _logger.debug(
                "JWT verify failed or primary-issuer config is incomplete, but "
                "require_jwt=False; falling back to header trust"
            )
            return _build_user_from_headers_legacy(headers, settings)
        raise

    return _build_user_from_verified_claims(
        claims, bearer, headers, settings, issuer=primary_issuer
    )


def verify_token(token: str, *, settings: Settings | None = None) -> dict[str, Any]:
    """Verify ``token`` against the configured primary issuer/audience
    ("forwarded"/"oidc" mode) and return its verified claims dict.
    Raises :class:`InvalidIdentityToken` on any verification failure,
    and :class:`ConfigurationError` if the primary-issuer config is
    incomplete.

    Most apps should use :func:`user_from_headers` (or the FastAPI/
    Streamlit helpers) instead — they also handle proxy headers and the
    additional-issuer path. This function DOES apply the same
    ``require_email_verified`` and email-domain-allowlist checks those
    paths apply (via the same shared :func:`_enforce_user_claim_policy`
    helper) before returning claims, so a caller relying on this lower-
    level API gets the same fail-closed posture rather than a raw,
    unfiltered claims dict. Call this directly only when you already
    have a bearer token on hand and want its verified claims rather
    than a ``User``.
    """
    settings = settings or get_settings()
    issuers, audience = settings.require_forwarded_or_oidc_config()
    claims = verify_jwt(
        token,
        issuer=issuers,
        audience=audience,
        jwks_url=settings.jwks_url,
        jwks_cache_ttl_s=settings.jwks_cache_ttl_s,
        discovery_cache_ttl_s=settings.discovery_cache_ttl_s,
    )
    _enforce_user_claim_policy(claims, settings)
    return claims


def verify_id_token(
    token: str,
    *,
    jwks_uri: str | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Deprecated name for :func:`verify_token`, kept for API parity
    with the internal predecessor library. ``jwks_uri``, if given,
    overrides ``settings.jwks_url`` for this call (also deprecated —
    prefer ``settings=Settings(jwks_url=...)``).

    Note the internal predecessor library's ``verify_id_token`` also
    accepted an ``audience=`` keyword (the OAuth client_id(s) to
    accept). This public function does NOT — the accepted audience is
    always resolved from ``settings.audience`` (``FORWARDED_AUTH_AUDIENCE``),
    the same as every other verification path in this library, so the
    audience check can never be forgotten or passed inconsistently on
    one call site. See the README/CHANGELOG for this deliberate API
    divergence."""
    if jwks_uri is not None:
        warnings.warn(
            "verify_id_token(jwks_uri=...) is deprecated; configure FORWARDED_AUTH_JWKS_URL "
            "or pass settings=Settings(jwks_url=...) instead",
            DeprecationWarning,
            stacklevel=2,
        )
        settings = with_settings(settings or get_settings(), jwks_url=jwks_uri)
    return verify_token(token, settings=settings)
