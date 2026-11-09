"""Configuration: a ``Settings`` object, loaded from ``FORWARDED_AUTH_*``
env vars by default, or built/overridden programmatically.

Design goal: **fail closed**. A misconfiguration (missing issuer, missing
audience, missing email-domain allowlist, an invalid mode) must raise,
never silently authenticate or silently skip verification.
``allowed_email_domains`` has no permissive default: it is *required*
for ``forwarded``/``oidc`` mode, either as a comma-separated domain
list or the explicit literal ``"*"`` (any verified email) — an operator
must make that choice out loud, it is never the quiet default.

Three ways to configure, in priority order:

1. ``configure(Settings(...))`` — programmatic override, highest priority.
   Mainly for tests and for apps that want typed config instead of env
   vars.
2. ``FORWARDED_AUTH_*`` environment variables — read fresh on every
   ``get_settings()`` call (no import-time caching), so a test that
   ``monkeypatch.setenv(...)`` takes effect immediately and a process
   that reloads its env (e.g. a redeploy) doesn't need a restart to pick
   up a logout-URL change.
3. Built-in defaults — all neutral, assume *no* Exowatt or other vendor
   service. See each field's docstring below.
"""

from __future__ import annotations

import logging
import os
import threading
import urllib.parse
from dataclasses import dataclass, field, replace

_logger = logging.getLogger(__name__)

MODE_FORWARDED = "forwarded"
MODE_OIDC = "oidc"
MODE_NONE = "none"
VALID_MODES = frozenset({MODE_FORWARDED, MODE_OIDC, MODE_NONE})

# --- env var names -----------------------------------------------------

ENV_MODE = "FORWARDED_AUTH_MODE"

ENV_ISSUER = "FORWARDED_AUTH_ISSUER"
ENV_JWKS_URL = "FORWARDED_AUTH_JWKS_URL"
ENV_AUDIENCE = "FORWARDED_AUTH_AUDIENCE"
ENV_ALLOWED_EMAIL_DOMAINS = "FORWARDED_AUTH_ALLOWED_EMAIL_DOMAINS"
ENV_REQUIRE_EMAIL_VERIFIED = "FORWARDED_AUTH_REQUIRE_EMAIL_VERIFIED"
ENV_ALLOW_INSECURE_NONE_MODE = "FORWARDED_AUTH_ALLOW_INSECURE_NONE_MODE"

ENV_EMAIL_HEADER = "FORWARDED_AUTH_EMAIL_HEADER"
ENV_USER_HEADER = "FORWARDED_AUTH_USER_HEADER"
ENV_PREFERRED_USERNAME_HEADER = "FORWARDED_AUTH_PREFERRED_USERNAME_HEADER"
ENV_AUTHORIZATION_HEADER = "FORWARDED_AUTH_AUTHORIZATION_HEADER"

ENV_REQUIRE_JWT = "FORWARDED_AUTH_REQUIRE_JWT"

ENV_USERINFO_URL = "FORWARDED_AUTH_USERINFO_URL"
ENV_DISABLE_USERINFO_FALLBACK = "FORWARDED_AUTH_DISABLE_USERINFO_FALLBACK"
ENV_ACCESS_TOKEN_HEADERS = "FORWARDED_AUTH_ACCESS_TOKEN_HEADERS"

ENV_ADDITIONAL_ISSUER = "FORWARDED_AUTH_ADDITIONAL_ISSUER"
ENV_ADDITIONAL_ISSUER_JWKS_URL = "FORWARDED_AUTH_ADDITIONAL_ISSUER_JWKS_URL"
ENV_ADDITIONAL_ISSUER_AUDIENCE = "FORWARDED_AUTH_ADDITIONAL_ISSUER_AUDIENCE"
ENV_ADDITIONAL_ISSUER_ACTOR_CLAIM = "FORWARDED_AUTH_ADDITIONAL_ISSUER_ACTOR_CLAIM"
ENV_ADDITIONAL_ISSUER_SCOPE_CLAIM = "FORWARDED_AUTH_ADDITIONAL_ISSUER_SCOPE_CLAIM"
ENV_ADDITIONAL_ISSUER_MAX_LIFETIME_S = "FORWARDED_AUTH_ADDITIONAL_ISSUER_MAX_LIFETIME_S"

ENV_TRUST_PROXY_HEADERS = "FORWARDED_AUTH_TRUST_PROXY_HEADERS"
ENV_PROXY_EMAIL_HEADER = "FORWARDED_AUTH_PROXY_EMAIL_HEADER"
ENV_PROXY_USER_HEADER = "FORWARDED_AUTH_PROXY_USER_HEADER"
ENV_PROXY_NAME_HEADER = "FORWARDED_AUTH_PROXY_NAME_HEADER"

ENV_TRUSTED_HOSTNAMES = "FORWARDED_AUTH_TRUSTED_HOSTNAMES"
ENV_ALLOW_LOOPBACK_HOSTS = "FORWARDED_AUTH_ALLOW_LOOPBACK_HOSTS"

ENV_DEV_USER_EMAIL = "FORWARDED_AUTH_DEV_USER_EMAIL"
ENV_DEV_USER_NAME = "FORWARDED_AUTH_DEV_USER_NAME"
ENV_DEV_USER_ID = "FORWARDED_AUTH_DEV_USER_ID"

ENV_LOGOUT_URL_BASE = "FORWARDED_AUTH_LOGOUT_URL_BASE"
ENV_DEFAULT_LOGOUT_REDIRECT = "FORWARDED_AUTH_DEFAULT_LOGOUT_REDIRECT"

ENV_DISCOVERY_CACHE_TTL_S = "FORWARDED_AUTH_DISCOVERY_CACHE_TTL_S"
ENV_JWKS_CACHE_TTL_S = "FORWARDED_AUTH_JWKS_CACHE_TTL_S"


_PRIMARY_ISSUER_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def _is_valid_primary_issuer_url(value: str) -> bool:
    """Whether ``value`` is usable to build the OIDC discovery/JWKS
    request URL for the primary (first) entry of a comma-separated
    issuer list: ``https://`` always, or plain ``http://`` only for a
    loopback host (tests/local dev). A bare hostname alias like
    ``accounts.google.com`` fails this check — it's only ever accepted
    as a LATER entry in the issuer list (see
    ``Settings.require_forwarded_or_oidc_config``), never the first.
    """
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme == "https":
        return bool(parsed.hostname)
    if parsed.scheme == "http":
        return (parsed.hostname or "").lower() in _PRIMARY_ISSUER_LOOPBACK_HOSTS
    return False


class ConfigurationError(Exception):
    """Raised when the resolved settings can't support the requested
    operation. Always fail closed: raise here rather than falling back
    to an unauthenticated or unverified path."""


def _truthy(raw: str | None) -> bool:
    return (raw or "").strip().lower() in {"true", "1", "yes"}


def _tristate(raw: str | None) -> bool | None:
    """Unset/blank -> None (use the mode-derived default); otherwise a bool."""
    if raw is None or not raw.strip():
        return None
    return _truthy(raw)


def _split_csv(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return ()
    return tuple(p.strip() for p in raw.split(",") if p.strip())


_warn_lock = threading.Lock()
_warned_once: set[str] = set()


def _warn_once(key: str, message: str, *args: object) -> None:
    """Log ``message`` at WARNING level the first time ``key`` is seen in
    this process, and silently no-op every time after. Used for
    standing security-posture warnings (``mode=none``,
    ``require_jwt=False``) that must be loud once, not spammy on every
    request."""
    with _warn_lock:
        if key in _warned_once:
            return
        _warned_once.add(key)
    _logger.warning(message, *args)


def _reset_warned_for_tests() -> None:
    with _warn_lock:
        _warned_once.clear()


@dataclass(frozen=True)
class Settings:
    """Immutable configuration snapshot. Build with :func:`from_env` or
    construct directly for programmatic configuration (tests, apps that
    prefer typed config over env vars)."""

    # Mode. "forwarded" (default): verify a bearer JWT forwarded by an
    # auth proxy (oauth2-proxy, etc.) against `issuer` + `jwks_url` (or
    # OIDC discovery off `issuer`). "oidc": validate a bearer JWT
    # directly from any OIDC provider via discovery, no proxy headers
    # needed. "none": fixed dev user, local use only, must be explicit.
    mode: str = MODE_FORWARDED

    # Primary trusted issuer. Required (fail closed) for "forwarded" and
    # "oidc" modes. No default — there is no neutral default issuer.
    issuer: str | None = None
    # JWKS endpoint for `issuer`. If unset, resolved via OIDC discovery
    # (`{issuer}/.well-known/openid-configuration`) at verify time.
    jwks_url: str | None = None
    # Accepted audience(s) (the OAuth/OIDC client_id a token was minted
    # for). Required (fail closed) for "forwarded" and "oidc" modes.
    audience: tuple[str, ...] = ()
    # Lower-cased email-domain allowlist. REQUIRED for "forwarded"/"oidc"
    # mode — there is no permissive default. Set to the literal `{"*"}`
    # (env: `FORWARDED_AUTH_ALLOWED_EMAIL_DOMAINS=*`) to explicitly allow
    # any verified email, or to a comma-separated domain list to
    # restrict sign-in to your org's domain(s). Left empty here only so
    # `Settings()` is constructible for modes/tests that don't need it;
    # `require_forwarded_or_oidc_config()` raises if it's still empty
    # when actually used.
    allowed_email_domains: frozenset[str] = field(default_factory=frozenset)

    # Whether a verified token's `email_verified` claim must be `True`
    # (or the case-insensitive string `"true"`) to be accepted. True
    # (default, fail closed): an issuer that forwards an unverified
    # email address must not silently grant access to it. Applies to
    # the main issuer path ("forwarded" and "oidc" modes).
    require_email_verified: bool = True

    # Identity header names an auth proxy populates. Defaults match
    # oauth2-proxy's standard `forward_auth` headers — generic, not
    # specific to any deployment.
    email_header: str = "X-Auth-Request-Email"
    user_header: str = "X-Auth-Request-User"
    preferred_username_header: str = "X-Auth-Request-Preferred-Username"
    authorization_header: str = "Authorization"

    # Security posture. True (default): every identity must be backed by
    # a verified JWT; headers alone are never trusted. Set False only for
    # local development — see `docs/oauth2-proxy-caddy.md` and the
    # README security-model section.
    require_jwt: bool = True

    # Userinfo fallback (profile-claim recovery for refresh tokens that
    # omit name/picture). Unset `userinfo_url` disables the network call
    # (the observe-and-cache layer still runs); "oidc" mode derives the
    # userinfo endpoint from discovery when this is unset.
    userinfo_url: str | None = None
    disable_userinfo_fallback: bool = False
    access_token_headers: tuple[str, ...] = (
        "X-Auth-Request-Access-Token",
        "X-Forwarded-Access-Token",
    )

    # Optional additional trusted issuer for short-lived, audience-bound
    # machine/service tokens (the generalised form of a "gateway" second
    # issuer). Unset `additional_issuer` disables the feature entirely;
    # it never affects the primary-issuer path.
    additional_issuer: str | None = None
    additional_issuer_jwks_url: str | None = None
    additional_issuer_audience: str | None = None
    additional_issuer_actor_claim: str = "act"
    additional_issuer_scope_claim: str = "scope"
    additional_issuer_max_lifetime_s: float = 300.0

    # Trusted upstream proxy header set: an opt-in, fail-closed path for
    # a second proxy hop that authenticates out-of-band and strips the
    # bearer before forwarding (e.g. a gateway that terminates its own
    # OAuth and relays a verified identity as headers instead of a JWT).
    # Off by default. See README "Security model".
    trust_proxy_headers: bool = False
    proxy_email_header: str = "X-Forwarded-User-Email"
    proxy_user_header: str = "X-Forwarded-User-Id"
    proxy_name_header: str = "X-Forwarded-User-Name"

    # Hostnames this app is reachable at, for `forwarded_auth.mcp`'s
    # DNS-rebinding allowlist. Comma-separated. Empty = no public host
    # (only loopback, and only when loopback is allowed; see below).
    trusted_hostnames: tuple[str, ...] = ()

    # Whether `forwarded_auth.mcp` adds the loopback/testserver entries
    # (`localhost:*`, `127.0.0.1:*`, `[::1]:*`, `testserver` and the
    # matching `http://` origins) to the DNS-rebinding allowlist.
    # None (the default) = only in mode=none (local dev). In
    # forwarded/oidc mode they are added only when this is explicitly
    # True (e.g. a test suite or a loopback-only deployment), so a
    # production MCP endpoint never accepts `Origin: http://localhost:*`
    # by default.
    allow_loopback_hosts: bool | None = None

    # "none" mode's fixed dev user.
    dev_user_email: str = "dev@localhost"
    dev_user_name: str = "Local Dev User"
    dev_user_id: str = "dev@localhost"

    # Second, explicit acknowledgement required to use mode=none at all
    # (on top of selecting `mode="none"` itself). This mode disables
    # all request verification and returns a fixed user to every
    # caller; requiring a second opt-in env var makes it much harder to
    # land in production by a copy-pasted/forgotten dev `.env`. See
    # README "Modes".
    allow_insecure_none_mode: bool = False

    # Logout URL. No default host (neutral) — the default is a relative
    # path, which works when the auth proxy is mounted on the same host
    # as the app. Set `logout_url_base` to an absolute URL if your
    # deployment serves auth from a different host.
    logout_url_base: str = "/oauth2/sign_out"
    default_logout_redirect: str = "/"

    # Cache lifetimes.
    discovery_cache_ttl_s: float = 3600.0
    jwks_cache_ttl_s: float = 3600.0

    def __post_init__(self) -> None:
        """Structural validation that applies regardless of how this
        ``Settings`` was built (``from_env``, programmatic, or a test
        constructing it directly) — fail closed immediately rather
        than at first use.

        Mode-*value* requirements (e.g. "forwarded" needing an issuer)
        are intentionally NOT checked here — see
        :meth:`require_forwarded_or_oidc_config`, called lazily at the
        point of use so e.g. "none" mode never has to satisfy
        "forwarded" mode's requirements.
        """
        if self.mode not in VALID_MODES:
            raise ConfigurationError(
                f"{ENV_MODE}={self.mode!r} is not a supported mode; must be one of "
                f"{sorted(VALID_MODES)!r}"
            )
        if self.allowed_email_domains:
            normalized_domains = frozenset(d.lower() for d in self.allowed_email_domains)
            if "*" in normalized_domains and len(normalized_domains) > 1:
                wildcard = "*"
                raise ConfigurationError(
                    f"{ENV_ALLOWED_EMAIL_DOMAINS}={wildcard!r} means allow any verified email "
                    "and cannot be combined with other domains in the same list — set it to "
                    "either the literal wildcard alone, or a plain comma-separated domain list"
                )
            if normalized_domains != self.allowed_email_domains:
                # frozen dataclass: __setattr__ is blocked, so normalize via
                # object.__setattr__ directly — the only time this instance's
                # fields are mutated after construction.
                object.__setattr__(self, "allowed_email_domains", normalized_domains)
        if self.mode == MODE_NONE:
            if (
                self.issuer
                or self.audience
                or self.additional_issuer
                or self.trust_proxy_headers
                or self.jwks_url
            ):
                raise ConfigurationError(
                    "mode=none cannot be combined with issuer/audience/jwks_url/"
                    "additional_issuer/trust_proxy_headers — those settings imply real "
                    "verification, which mode=none never performs"
                )
            if not self.allow_insecure_none_mode:
                raise ConfigurationError(
                    f"mode=none disables all request verification and requires a second, "
                    f"explicit acknowledgement: set {ENV_ALLOW_INSECURE_NONE_MODE}=1 (or "
                    f"Settings(allow_insecure_none_mode=True)). Never set this in production."
                )
            _warn_once(
                "mode_none",
                "forwarded_auth: mode=none is active — every request returns the fixed dev "
                "user %r with NO verification. This must never run in production.",
                self.dev_user_email,
            )
        if not self.require_jwt:
            _warn_once(
                "require_jwt_false",
                "forwarded_auth: require_jwt=False is active — identity headers are trusted "
                "without a verified JWT whenever one isn't present or doesn't verify. This is "
                "a dev-only escape valve; never set it in production.",
            )
        if self.trust_proxy_headers:
            _warn_once(
                "trust_proxy_headers",
                "forwarded_auth: trust_proxy_headers=True is active — a request with no bearer "
                "token will be authenticated solely from proxy-forwarded identity headers. "
                "This is safe ONLY behind a proxy hop that strips any client-supplied copy of "
                "those headers before setting its own; see docs/oauth2-proxy-caddy.md.",
            )

    @classmethod
    def from_env(cls) -> Settings:
        """Build a ``Settings`` from ``FORWARDED_AUTH_*`` env vars,
        falling back to the dataclass defaults for anything unset.

        Does not validate mode-specific requirements (e.g. "forwarded"
        needing an issuer) — that happens lazily, at the point of use,
        so that e.g. "none" mode never has to satisfy "forwarded" mode's
        requirements.
        """
        mode = os.environ.get(ENV_MODE, MODE_FORWARDED).strip().lower() or MODE_FORWARDED

        audience_raw = os.environ.get(ENV_AUDIENCE)
        audience = _split_csv(audience_raw) if audience_raw is not None else ()

        domains_raw = os.environ.get(ENV_ALLOWED_EMAIL_DOMAINS, "")
        allowed_email_domains = frozenset(d.lower() for d in _split_csv(domains_raw))

        access_token_headers_raw = os.environ.get(ENV_ACCESS_TOKEN_HEADERS)
        access_token_headers = (
            _split_csv(access_token_headers_raw)
            if access_token_headers_raw is not None
            else cls.access_token_headers
        )

        return cls(
            mode=mode,
            issuer=os.environ.get(ENV_ISSUER) or None,
            jwks_url=os.environ.get(ENV_JWKS_URL) or None,
            audience=audience,
            allowed_email_domains=allowed_email_domains,
            email_header=os.environ.get(ENV_EMAIL_HEADER, cls.email_header),
            user_header=os.environ.get(ENV_USER_HEADER, cls.user_header),
            preferred_username_header=os.environ.get(
                ENV_PREFERRED_USERNAME_HEADER, cls.preferred_username_header
            ),
            authorization_header=os.environ.get(ENV_AUTHORIZATION_HEADER, cls.authorization_header),
            require_jwt=_truthy(os.environ.get(ENV_REQUIRE_JWT, "true")),
            require_email_verified=_truthy(os.environ.get(ENV_REQUIRE_EMAIL_VERIFIED, "true")),
            userinfo_url=os.environ.get(ENV_USERINFO_URL) or None,
            disable_userinfo_fallback=_truthy(os.environ.get(ENV_DISABLE_USERINFO_FALLBACK)),
            access_token_headers=access_token_headers,
            additional_issuer=os.environ.get(ENV_ADDITIONAL_ISSUER) or None,
            additional_issuer_jwks_url=os.environ.get(ENV_ADDITIONAL_ISSUER_JWKS_URL) or None,
            additional_issuer_audience=os.environ.get(ENV_ADDITIONAL_ISSUER_AUDIENCE) or None,
            additional_issuer_actor_claim=os.environ.get(
                ENV_ADDITIONAL_ISSUER_ACTOR_CLAIM, cls.additional_issuer_actor_claim
            ),
            additional_issuer_scope_claim=os.environ.get(
                ENV_ADDITIONAL_ISSUER_SCOPE_CLAIM, cls.additional_issuer_scope_claim
            ),
            additional_issuer_max_lifetime_s=float(
                os.environ.get(
                    ENV_ADDITIONAL_ISSUER_MAX_LIFETIME_S,
                    str(cls.additional_issuer_max_lifetime_s),
                )
            ),
            trust_proxy_headers=_truthy(os.environ.get(ENV_TRUST_PROXY_HEADERS)),
            proxy_email_header=os.environ.get(ENV_PROXY_EMAIL_HEADER, cls.proxy_email_header),
            proxy_user_header=os.environ.get(ENV_PROXY_USER_HEADER, cls.proxy_user_header),
            proxy_name_header=os.environ.get(ENV_PROXY_NAME_HEADER, cls.proxy_name_header),
            trusted_hostnames=_split_csv(os.environ.get(ENV_TRUSTED_HOSTNAMES)),
            allow_loopback_hosts=_tristate(os.environ.get(ENV_ALLOW_LOOPBACK_HOSTS)),
            dev_user_email=os.environ.get(ENV_DEV_USER_EMAIL, cls.dev_user_email),
            dev_user_name=os.environ.get(ENV_DEV_USER_NAME, cls.dev_user_name),
            dev_user_id=os.environ.get(ENV_DEV_USER_ID, cls.dev_user_id),
            allow_insecure_none_mode=_truthy(os.environ.get(ENV_ALLOW_INSECURE_NONE_MODE)),
            logout_url_base=os.environ.get(ENV_LOGOUT_URL_BASE, cls.logout_url_base),
            default_logout_redirect=os.environ.get(
                ENV_DEFAULT_LOGOUT_REDIRECT, cls.default_logout_redirect
            ),
            discovery_cache_ttl_s=float(
                os.environ.get(ENV_DISCOVERY_CACHE_TTL_S, str(cls.discovery_cache_ttl_s))
            ),
            jwks_cache_ttl_s=float(os.environ.get(ENV_JWKS_CACHE_TTL_S, str(cls.jwks_cache_ttl_s))),
        )

    def require_forwarded_or_oidc_config(self) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """Validate and return ``(issuers, audience)`` for "forwarded" /
        "oidc" mode. ``issuers`` is one-or-more trusted issuer strings
        (``FORWARDED_AUTH_ISSUER`` may be a comma-separated list, e.g.
        to accept both ``https://accounts.google.com`` and bare
        ``accounts.google.com`` — see ``docs/oauth2-proxy-caddy.md``);
        the FIRST entry is the one used for OIDC discovery and userinfo
        derivation.

        Raises :class:`ConfigurationError` (fail closed) if the issuer,
        audience, or email-domain allowlist is missing — this library
        never silently skips verification, or silently admits every
        verified email, because the operator forgot to set a variable.
        """
        if not self.issuer:
            raise ConfigurationError(
                f"{ENV_ISSUER} is unset; cannot verify tokens without a trusted issuer"
            )
        if not self.audience:
            raise ConfigurationError(f"{ENV_AUDIENCE} is unset; cannot verify a token's audience")
        if not self.allowed_email_domains:
            raise ConfigurationError(
                f"{ENV_ALLOWED_EMAIL_DOMAINS} is unset; cannot decide which verified emails to "
                f'admit. Set it to a comma-separated domain list, or explicitly to "*" to '
                "allow any verified email — this library never defaults to admitting everyone."
            )
        issuers = tuple(p.strip() for p in self.issuer.split(",") if p.strip())
        if not issuers:
            raise ConfigurationError(
                f"{ENV_ISSUER} is set but contains no issuer after splitting on commas and "
                "stripping whitespace"
            )
        if not _is_valid_primary_issuer_url(issuers[0]):
            raise ConfigurationError(
                f"{ENV_ISSUER}'s first entry {issuers[0]!r} must be an https:// URL (or an "
                "http:// loopback URL for local dev) — it is the one used to build the OIDC "
                "discovery/JWKS request. A bare-host alias like 'accounts.google.com' (no "
                "scheme) is only accepted as a LATER entry in a comma-separated list, never "
                "the first."
            )
        return issuers, self.audience

    def validate(self) -> None:
        """Eagerly validate this configuration for the configured mode.
        Call this at app startup (e.g. in a FastAPI ``lifespan`` or
        before a Streamlit app serves its first page) to turn a
        misconfiguration into a startup failure instead of a 500 on
        the first real request.

        ``__post_init__`` already validates structure that doesn't
        depend on mode (an unknown mode, a none-mode combined with
        verification settings, the none-mode acknowledgement). This
        method additionally validates the mode-specific requirements:
        "forwarded"/"oidc" need issuer + audience + email-domain
        allowlist, UNLESS ``require_jwt=False`` (the explicit dev-only
        escape valve), in which case a missing issuer is fine — the
        app runs on the legacy header-only path instead of failing.

        Raises :class:`ConfigurationError` on any other problem.
        """
        if self.mode in (MODE_FORWARDED, MODE_OIDC):
            if self.issuer or self.require_jwt:
                self.require_forwarded_or_oidc_config()
        if self.additional_issuer:
            if not self.additional_issuer_audience:
                raise ConfigurationError(
                    f"{ENV_ADDITIONAL_ISSUER_AUDIENCE} is unset; cannot verify additional-issuer "
                    "audience"
                )
            if not self.allowed_email_domains:
                raise ConfigurationError(
                    f"{ENV_ALLOWED_EMAIL_DOMAINS} is unset; the additional-issuer path always "
                    "requires a configured email-domain allowlist (even when "
                    f"{ENV_REQUIRE_JWT}=false), because its verified sub/email claim is never "
                    "otherwise domain-restricted"
                )
        if self.trust_proxy_headers and not self.allowed_email_domains:
            raise ConfigurationError(
                f"{ENV_ALLOWED_EMAIL_DOMAINS} is unset; trust_proxy_headers always requires a "
                "configured email-domain allowlist, because a proxy-supplied identity has no "
                "other domain restriction"
            )


_lock = threading.Lock()
_override: Settings | None = None


def configure(settings: Settings | None) -> None:
    """Install a programmatic ``Settings`` override, or clear it (pass
    ``None``) to go back to reading ``FORWARDED_AUTH_*`` env vars."""
    global _override
    with _lock:
        _override = settings


def get_settings() -> Settings:
    """Return the active settings: the programmatic override if one was
    installed via :func:`configure`, else a fresh read of
    ``FORWARDED_AUTH_*`` env vars (not cached, so tests that
    ``monkeypatch.setenv`` see the change immediately)."""
    with _lock:
        if _override is not None:
            return _override
    return Settings.from_env()


def with_settings(base: Settings, **changes: object) -> Settings:
    """Convenience: ``dataclasses.replace`` without importing it everywhere."""
    return replace(base, **changes)  # type: ignore[arg-type]


def _reset_for_tests() -> None:
    configure(None)
