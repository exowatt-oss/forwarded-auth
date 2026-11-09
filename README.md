# forwarded-auth

Typed `User` from identity headers forwarded by an auth proxy (oauth2-proxy,
or any provider via OIDC), with JWKS/OIDC signature verification for
FastAPI, Streamlit, and MCP apps.

![Status: maintained](https://img.shields.io/badge/status-maintained-brightgreen) ![License: Apache--2.0](https://img.shields.io/badge/license-Apache--2.0-blue)

Created at [Exowatt](https://exowatt.com).

## Status

Maintained.

## Install

```sh
uv add forwarded-auth
# or, with a framework integration:
uv add 'forwarded-auth[fastapi]'
uv add 'forwarded-auth[streamlit]'
uv add 'forwarded-auth[mcp]'
```

## Usage / Quickstart

### FastAPI

```python
from fastapi import Depends, FastAPI
from forwarded_auth.fastapi import require_user

app = FastAPI()


@app.get("/me")
def me(user=Depends(require_user)):
    return {"email": user.email, "name": user.display_name}
```

### Streamlit

```python
import streamlit as st
from forwarded_auth.streamlit import require_user, render_profile_widget

render_profile_widget()
user = require_user()
st.title(f"Welcome, {user.display_name}")
```

### MCP (FastMCP transport security)

```python
from mcp.server.fastmcp import FastMCP
from forwarded_auth.mcp import build_transport_security

mcp = FastMCP("my-app", transport_security=build_transport_security())
```

In `forwarded`/`oidc` mode, set `FORWARDED_AUTH_TRUSTED_HOSTNAMES` to the
app's public hostname(s); with it empty, every MCP request is rejected.
Loopback hosts are allowed only in `none` mode or with
`FORWARDED_AUTH_ALLOW_LOOPBACK_HOSTS=true` (e.g. a test suite).

### Anything else

```python
from forwarded_auth import InvalidIdentityToken, user_from_headers

try:
    user = user_from_headers(request_headers)
except InvalidIdentityToken:
    return 401
if user is None:
    return 401
```

Have a bearer token directly (no headers/proxy involved)? Use
`forwarded_auth.verify_token(token)` instead, which returns the
verified claims dict straight from the configured primary issuer. It
applies the same `require_email_verified` and email-domain-allowlist
checks `user_from_headers` does before returning claims. The deprecated
alias `verify_id_token(token)` behaves identically; unlike the internal
predecessor library this was generalised from, it does **not** take an
`audience=` keyword — the accepted audience always comes from
`Settings.audience` (`FORWARDED_AUTH_AUDIENCE`), the same as every other
verification path here.

Run locally with no proxy in front by setting `FORWARDED_AUTH_MODE=none`
**and** `FORWARDED_AUTH_ALLOW_INSECURE_NONE_MODE=1` (see
[Modes](#modes) below).

## Configuration

Everything is configured via `FORWARDED_AUTH_*` environment variables, or
programmatically with `forwarded_auth.configure(Settings(...))`. No
variable here defaults to an Exowatt (or any other vendor's) service —
every default is either empty, a generic oauth2-proxy header name, or a
relative path.

| Variable | Default | Meaning |
|---|---|---|
| `FORWARDED_AUTH_MODE` | `forwarded` | `forwarded` \| `oidc` \| `none` |
| `FORWARDED_AUTH_ISSUER` | _(unset)_ | Trusted token issuer. Required for `forwarded`/`oidc` modes. May be a comma-separated list of issuers to accept (e.g. Google's `https://accounts.google.com` and bare `accounts.google.com`); the FIRST entry is used for OIDC discovery. |
| `FORWARDED_AUTH_JWKS_URL` | _(unset)_ | JWKS endpoint. If unset, resolved via OIDC discovery off the issuer. |
| `FORWARDED_AUTH_AUDIENCE` | _(unset)_ | Accepted audience(s), comma-separated. Required for `forwarded`/`oidc` modes. |
| `FORWARDED_AUTH_ALLOWED_EMAIL_DOMAINS` | _(none — required)_ | Comma-separated email-domain allowlist, or the literal `*` to explicitly allow any verified email. **Required** for `forwarded`/`oidc` mode — see [Security model](#security-model). |
| `FORWARDED_AUTH_REQUIRE_EMAIL_VERIFIED` | `true` | Reject a token whose `email_verified` claim isn't `true`. |
| `FORWARDED_AUTH_EMAIL_HEADER` | `X-Auth-Request-Email` | oauth2-proxy-style identity header name. |
| `FORWARDED_AUTH_USER_HEADER` | `X-Auth-Request-User` | |
| `FORWARDED_AUTH_PREFERRED_USERNAME_HEADER` | `X-Auth-Request-Preferred-Username` | |
| `FORWARDED_AUTH_AUTHORIZATION_HEADER` | `Authorization` | Header carrying the `Bearer <token>`. |
| `FORWARDED_AUTH_REQUIRE_JWT` | `true` | `false` is a dev-only escape valve: trust headers without a verified JWT. |
| `FORWARDED_AUTH_USERINFO_URL` | _(unset)_ | Userinfo endpoint for profile-claim recovery. `oidc` mode derives it via OIDC discovery's `userinfo_endpoint` if unset. |
| `FORWARDED_AUTH_DISABLE_USERINFO_FALLBACK` | `false` | Opt out of the network userinfo call (the cache-only layer still runs). |
| `FORWARDED_AUTH_ACCESS_TOKEN_HEADERS` | `X-Auth-Request-Access-Token,X-Forwarded-Access-Token` | Where to look for a forwarded access token for the userinfo fallback. |
| `FORWARDED_AUTH_ADDITIONAL_ISSUER` | _(unset)_ | Optional second trusted issuer for short-lived, audience-bound machine tokens. |
| `FORWARDED_AUTH_ADDITIONAL_ISSUER_JWKS_URL` | `{issuer}/.well-known/jwks.json` | |
| `FORWARDED_AUTH_ADDITIONAL_ISSUER_AUDIENCE` | _(unset)_ | Required once `ADDITIONAL_ISSUER` is set. |
| `FORWARDED_AUTH_ADDITIONAL_ISSUER_ACTOR_CLAIM` | `act` | Claim naming the machine acting for the token's `sub` (owner). |
| `FORWARDED_AUTH_ADDITIONAL_ISSUER_SCOPE_CLAIM` | `scope` | |
| `FORWARDED_AUTH_ADDITIONAL_ISSUER_MAX_LIFETIME_S` | `300` | Reject additional-issuer tokens with a longer `exp - iat`. |
| `FORWARDED_AUTH_TRUST_PROXY_HEADERS` | `false` | Opt-in, fail-closed: trust a second, bearer-stripping proxy hop's identity headers. Requires `FORWARDED_AUTH_ALLOWED_EMAIL_DOMAINS` to be set (the proxy-supplied email is checked against it) and logs a loud warning once per process; see [oauth2-proxy-caddy.md](docs/oauth2-proxy-caddy.md) for the required header-stripping config at the first proxy hop. |
| `FORWARDED_AUTH_PROXY_EMAIL_HEADER` | `X-Forwarded-User-Email` | |
| `FORWARDED_AUTH_PROXY_USER_HEADER` | `X-Forwarded-User-Id` | |
| `FORWARDED_AUTH_PROXY_NAME_HEADER` | `X-Forwarded-User-Name` | |
| `FORWARDED_AUTH_TRUSTED_HOSTNAMES` | _(empty)_ | Comma-separated hostnames for `forwarded_auth.mcp`'s DNS-rebinding allowlist. Required for an MCP endpoint in `forwarded`/`oidc` mode: with it empty, every MCP request is rejected. |
| `FORWARDED_AUTH_ALLOW_LOOPBACK_HOSTS` | _(unset = only in `none` mode)_ | Add `localhost:*`, `127.0.0.1:*`, `[::1]:*`, `testserver` and the matching `http://` origins to the MCP allowlist. Unset: added in `none` mode only, never in `forwarded`/`oidc`. Set `true` for a test suite or a loopback-only deployment; `false` to drop them even in `none` mode. |
| `FORWARDED_AUTH_DEV_USER_EMAIL` | `dev@localhost` | `none` mode's fixed user. |
| `FORWARDED_AUTH_DEV_USER_NAME` | `Local Dev User` | |
| `FORWARDED_AUTH_DEV_USER_ID` | `dev@localhost` | |
| `FORWARDED_AUTH_ALLOW_INSECURE_NONE_MODE` | `false` | Second, explicit acknowledgement required to use `mode=none` at all (on top of selecting the mode itself). See [Modes](#modes). |
| `FORWARDED_AUTH_LOGOUT_URL_BASE` | `/oauth2/sign_out` | No default host — relative path works when the proxy shares the app's host. |
| `FORWARDED_AUTH_DEFAULT_LOGOUT_REDIRECT` | `/` | |
| `FORWARDED_AUTH_DISCOVERY_CACHE_TTL_S` | `3600` | OIDC discovery-document cache lifetime. |
| `FORWARDED_AUTH_JWKS_CACHE_TTL_S` | `3600` | JWKS cache lifetime. |

See `docs/oauth2-proxy-caddy.md` for a worked example of these set for a
real deployment (using placeholder hostnames).

## Modes

- **`forwarded`** (default): verify a bearer token forwarded by an auth
  proxy, against `FORWARDED_AUTH_ISSUER` + JWKS (direct or via
  discovery). Cross-checks the identity headers against the verified
  token.
- **`oidc`**: validate a bearer JWT directly from any OIDC provider via
  `{issuer}/.well-known/openid-configuration` discovery + JWKS. No proxy
  headers needed — use this when your app receives bearer tokens
  directly from a client rather than through a `forward_auth`-style proxy.
- **`none`**: a fixed, configurable dev user, for local development
  only. Disables ALL request verification, so selecting it takes TWO
  explicit steps: `FORWARDED_AUTH_MODE=none` AND
  `FORWARDED_AUTH_ALLOW_INSECURE_NONE_MODE=1`. It also can't be combined
  with `FORWARDED_AUTH_ISSUER`/`FORWARDED_AUTH_AUDIENCE`/`FORWARDED_AUTH_JWKS_URL`/
  `FORWARDED_AUTH_ADDITIONAL_ISSUER`/`FORWARDED_AUTH_TRUST_PROXY_HEADERS`
  — those imply real verification, which this mode never performs.
  Logs a loud warning once per process (not per request). Never deploy
  a production app in this mode.

## Security model

**Threat model: the proxy-header trust boundary.** This library's whole
purpose is to let an app trust identity headers that a *proxy in front
of it* sets, without trusting them unconditionally. That only holds if:

- **your app is reachable ONLY through that proxy** — no direct path to
  the app's port/socket from anywhere an attacker could reach (another
  tenant on the same host, a misconfigured load balancer, a debug port
  left open). If the app is directly reachable, anyone can set
  `X-Auth-Request-Email: anyone@anywhere.com` themselves and skip the
  proxy entirely;
- **your proxy strips any inbound copy of those headers** before adding
  its own — a client that sends `X-Auth-Request-Email` itself must not
  have it survive to the app as if the proxy had set it.

Verifying the forwarded bearer token's RS256 signature against the
issuer's published JWKS on every request is this library's own,
independent layer on top of that boundary: the headers are, at most, a
convenience cross-check against the verified token, never the proof of
identity by themselves (unless you explicitly opt out — see below). A
bearer that IS present but fails verification always raises
`InvalidIdentityToken` and is surfaced as a 401 — it is never silently
treated as a missing token and waved through on headers alone.

**Fail closed.** A misconfiguration (missing issuer, missing audience,
missing email-domain allowlist, an unsupported mode) raises
`ConfigurationError` rather than silently skipping verification or
authenticating anyway. There is no permissive default left in this
library: `FORWARDED_AUTH_ALLOWED_EMAIL_DOMAINS` must be set explicitly
— to a domain list, or to `*` to deliberately allow any verified email
— for `forwarded`/`oidc` mode. Call `Settings.validate()` at app
startup to catch a misconfiguration before the first real request
instead of on it (where it still surfaces as a 500, by design — see
the FastAPI/Streamlit integration docstrings).

**`FORWARDED_AUTH_REQUIRE_JWT=false`**, **`FORWARDED_AUTH_TRUST_PROXY_HEADERS=true`**,
and **`FORWARDED_AUTH_MODE=none`** (which additionally requires
`FORWARDED_AUTH_ALLOW_INSECURE_NONE_MODE=1`) are all explicit, documented
escape valves — the first for local development without a real proxy in
front, the second for a specific deployment shape (a second proxy hop
that authenticates out-of-band and relays identity as headers instead
of a bearer, stripping `Authorization` before forwarding), the third
for running with zero verification at all. Neither `require_jwt` nor
`trust_proxy_headers` is ever implied by another setting; all three
default to the strict/off posture, and `mode=none`, `require_jwt=false`
and `trust_proxy_headers=true` each log a loud warning once per process.

## Prerequisites

None — this package has no proprietary runtime dependencies. PyJWT and
`cryptography` are ordinary open-source PyPI packages.

## License

Original code is licensed under [Apache-2.0](LICENSE). See [NOTICE](NOTICE)
for attribution.

## Contributing

See [CONTRIBUTING](https://github.com/exowatt-oss/.github/blob/main/CONTRIBUTING.md).
Contributions require DCO sign-off (`git commit -s`); no CLA is required.

## Security

Please report vulnerabilities privately using [GitHub private vulnerability
reporting](https://github.com/exowatt-oss/forwarded-auth/security/advisories/new),
or contact software@exowatt.com. See the [security policy](https://github.com/exowatt-oss/.github/blob/main/SECURITY.md);
do not open a public issue.
