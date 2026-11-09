# Changelog

All notable changes are recorded here. Nothing has been tagged/released
yet — this package has not had a public release, so everything below is
one coherent "Unreleased" history, not a diff between two shipped
versions.

## Unreleased

Generalised from an internal Exowatt library (product-specific
integrations were removed as part of that generalisation — see
"Deliberate divergences" below), then hardened through two rounds of
independent pre-release security review before the first public tag.

### Core

- `forwarded`, `oidc`, and `none` modes, configured via `FORWARDED_AUTH_*`
  env vars or a programmatic `Settings` object.
- JWT verification against a configurable trusted issuer's JWKS, with
  optional OIDC discovery.
- An optional, independently configured *additional trusted issuer* for
  short-lived, audience-bound machine/service tokens.
- An opt-in, fail-closed *trusted upstream proxy header set* for a
  second proxy hop that authenticates out of band — see
  `docs/oauth2-proxy-caddy.md` for the required header-stripping config
  at that first proxy hop.
- FastAPI, Streamlit, and MCP transport-security integrations. The MCP
  DNS-rebinding allowlist adds loopback/testserver hosts and `http://`
  loopback origins only in `none` mode or when
  `FORWARDED_AUTH_ALLOW_LOOPBACK_HOSTS` is explicitly true, never by
  default in `forwarded`/`oidc` mode (pre-release review finding).
- Fail-closed configuration throughout: a missing issuer/audience/
  email-domain allowlist raises `ConfigurationError` rather than
  silently skipping verification or admitting every verified email.

### Security review fixes

- **Email-domain allowlist is no longer permissive by default.**
  `FORWARDED_AUTH_ALLOWED_EMAIL_DOMAINS` is required for `forwarded`/
  `oidc` mode, for the additional-issuer path whenever
  `FORWARDED_AUTH_ADDITIONAL_ISSUER` is set (even if
  `FORWARDED_AUTH_REQUIRE_JWT=false`), and for
  `FORWARDED_AUTH_TRUST_PROXY_HEADERS` — set it to a domain list, or
  explicitly to `*` to allow any verified email. An unset allowlist
  raises `ConfigurationError` instead of silently admitting everyone;
  previously the additional-issuer and trusted-proxy-header paths could
  reach their verification/checks with an empty allowlist and admit any
  domain because `enforce_email_domain` deliberately no-ops on an empty
  set (right for a caller that explicitly means "no restriction", wrong
  when nobody set the allowlist at all).
- **`email_verified` and the email-domain allowlist are enforced on the
  `verify_token()`/`verify_id_token()` raw-claims API, not just
  `user_from_headers()`.** Both paths now share one helper
  (`_enforce_user_claim_policy`) so the checks can't be present on one
  call site and silently missing on the other, as they previously were
  on `verify_token`/`verify_id_token`.
- **`allowed_email_domains` is normalised to lower-case** on every
  `Settings` construction (not just `from_env`, which already
  lower-cased), and the literal wildcard `*` can no longer be combined
  with other domains in the same list — `ConfigurationError` either
  way.
- **`FORWARDED_AUTH_ISSUER`'s first entry must be `https://` (or an
  `http://` loopback URL for local dev)** — it's the one used to build
  the OIDC discovery/JWKS request. A bare-host alias like
  `accounts.google.com` is only accepted as a LATER entry in a
  comma-separated issuer list, never the first; an issuer string that
  is non-empty but contains no issuer after splitting on commas (e.g.
  just `","`) now also raises `ConfigurationError` instead of reaching
  verification with an empty issuer list.
- **`mode=none` requires a second, explicit acknowledgement**
  (`FORWARDED_AUTH_ALLOW_INSECURE_NONE_MODE=1`) on top of selecting the
  mode itself, and can no longer be combined with issuer/audience/
  jwks_url/additional-issuer/trust-proxy-headers settings. The "no
  verification" warning (and the `require_jwt=false` and new
  `trust_proxy_headers=true` warnings) logs once per process instead of
  once per request.
- **Unknown mode values raise `ConfigurationError`** instead of being
  accepted silently.
- Main verification path requires `exp`/`iat`/`iss`/`aud`/`sub` to be
  present (PyJWT `options={"require": [...]}`), on top of the
  signature/audience/issuer checks already performed.
- **JWKS forced-refresh-on-unknown-kid is rate-limited** to at most once
  per JWKS URL per 60 seconds, closing a way to force a refetch of the
  issuer's JWKS on every single request. One consequence worth knowing:
  a newly rotated key can take up to 60s to be picked up if the first
  request bearing its `kid` lands right after a just-exhausted cooldown
  window — intentional, and relies on providers publishing a key before
  issuing tokens signed with it (standard OIDC rotation guidance).
- **Additional-issuer path hardened**: `iss`/`aud`/`sub`/`iat`/`exp`/the
  actor claim are all required via JWT options; a missing or malformed
  `sub` raises `InvalidIdentityToken` (never a bare `assert` or
  `KeyError`); `sub` must be email-shaped; its domain is checked
  against the (now-required, see above) email-domain allowlist; and the
  token's `aud` must *exactly* match the configured audience — a list
  like `aud: ["svc", "other"]` is rejected even though PyJWT's own
  audience check would accept it (any-entry match), because this path
  only ever configures one audience value.
- **OIDC discovery hardened**: the discovery document's `issuer` must
  exactly match the configured issuer; the issuer, JWKS URL, discovered
  `jwks_uri`, and discovered userinfo endpoint must all be `https://`
  except for loopback hosts (`localhost`/`127.0.0.1`/`::1`, for tests
  and local dev); any other URL scheme, a URL with no hostname, or a
  URL carrying embedded `user:pass@` credentials is rejected — this
  closes a discovery document that is itself fetched from a trusted
  issuer but advertises an attacker-controlled `jwks_uri`/
  `userinfo_endpoint` (e.g. `http://evil.example/jwks`).
- **A failed OIDC discovery fetch is cached for 30 seconds** and
  re-raised on subsequent calls within that window, instead of
  re-attempting the (5s-timeout) HTTP fetch on every single request —
  an IdP outage no longer makes every request pay that timeout.
- **`FORWARDED_AUTH_ISSUER` accepts a comma-separated list** of trusted
  issuers (e.g. both `https://accounts.google.com` and bare
  `accounts.google.com`); discovery and userinfo derivation use the
  first entry — see `docs/oauth2-proxy-caddy.md`.
- **`trust_proxy_headers`'s proxy-supplied email is checked against the
  email-domain allowlist** the same as the primary- and
  additional-issuer paths (previously unchecked — any proxy-supplied
  domain was accepted outright once this escape valve was enabled).
- **`require_jwt=False` with no issuer configured** falls back to the
  legacy header-only path instead of crashing with an unhandled
  `ConfigurationError`. `Settings.validate()` lets an app check its
  configuration eagerly at startup instead of discovering a problem on
  the first request (where it still surfaces as a 500, by design).
- `oidc` mode derives the userinfo endpoint from OIDC discovery when
  `FORWARDED_AUTH_USERINFO_URL` is unset, instead of just documenting
  that it would.
- API-parity additions: a deprecated, read-only `User.gateway_scope`
  property (alias for `scope`); public `verify_token()` /
  `verify_id_token()` functions for verifying a bearer token directly
  (outside the headers-based `user_from_headers` flow) — unlike the
  internal predecessor library's `verify_id_token`, these do **not**
  take an `audience=` keyword, since the accepted audience is always
  resolved from `Settings.audience`; a deprecated `jwks_uri=` override
  kwarg on `user_from_headers`; `forwarded_auth.AUTH_HEADER_BEARER_PREFIX`
  re-exported at the top level.
- Packaging: `src/forwarded_auth/py.typed` is shipped in the wheel.
- Tests throughout, including forged `alg: none` and HS256/public-
  key-confusion rejection, JWKS-rotation pickup vs. the rate limit,
  `ConfigurationError` propagation through the FastAPI/Streamlit
  helpers, the full `required_claims` set (`exp`/`iss`/`aud`/`iat`/`sub`
  individually), insecure-discovery-document rejection, the
  additional-issuer exact-audience check, and the discovery
  failure cache.

### Deliberate divergences from the internal predecessor library

No hardcoded provider defaults; product-specific integrations were
dropped entirely; a field was renamed to the generic `scope`; a
vendor-specific second-issuer header path was generalised into the
configurable trusted-proxy-header set above; `verify_id_token()` no
longer takes an `audience=` keyword (see above).
