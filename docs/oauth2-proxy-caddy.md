# Using behind oauth2-proxy + Caddy

This is a worked example of one common deployment shape: Caddy terminates
TLS and delegates per-request auth to [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/)
via `forward_auth`, oauth2-proxy signs the user in against Google, and
your app (behind Caddy) sees the forwarded identity headers plus a
verified bearer token.

This page uses `example.com` throughout — replace it with your own
domain. **None of this is a default** in `forwarded-auth` itself; it's
one configuration you can apply.

## Caddyfile

```caddyfile
app.example.com {
    forward_auth auth.example.com:4180 {
        uri /oauth2/auth
        copy_headers X-Auth-Request-Email X-Auth-Request-User X-Auth-Request-Preferred-Username Authorization
    }
    reverse_proxy localhost:8000
}

auth.example.com {
    reverse_proxy localhost:4180
}
```

The `copy_headers` directive is what makes `Authorization` (the Google
ID token) reach your app — without it you'd only get the identity
headers, and `forwarded-auth`'s strict default refuses to trust those
alone.

## oauth2-proxy flags

```text
--provider=google
--client-id=<your-oauth-client-id>.apps.googleusercontent.com
--client-secret=<your-oauth-client-secret>
--email-domain=example.com
--set-authorization-header=true
--set-xauthrequest=true
--cookie-domain=.example.com
--whitelist-domain=.example.com
--upstream=http://localhost:8000
```

- `--set-authorization-header=true` is what makes oauth2-proxy forward
  `Authorization: Bearer <id_token>` upstream — the bearer
  `forwarded-auth` verifies.
- `--set-xauthrequest=true` populates `X-Auth-Request-{Email,User,Preferred-Username}`
  — used only as a cross-check against the verified token, never trusted
  alone.
- `--email-domain=example.com` restricts sign-in at the proxy; the
  library's own `FORWARDED_AUTH_ALLOWED_EMAIL_DOMAINS` is a second,
  independent check on the verified token (defence-in-depth — an app
  shouldn't rely solely on the proxy's own domain restriction never
  being bypassed or misconfigured).

## App environment

```dotenv
FORWARDED_AUTH_MODE=forwarded
FORWARDED_AUTH_ISSUER=https://accounts.google.com
FORWARDED_AUTH_AUDIENCE=<your-oauth-client-id>.apps.googleusercontent.com
FORWARDED_AUTH_ALLOWED_EMAIL_DOMAINS=example.com
FORWARDED_AUTH_LOGOUT_URL_BASE=https://auth.example.com/oauth2/sign_out
FORWARDED_AUTH_DEFAULT_LOGOUT_REDIRECT=https://app.example.com/
```

`forwarded-auth` resolves Google's JWKS automatically via OIDC
discovery off `https://accounts.google.com` — you don't need to set
`FORWARDED_AUTH_JWKS_URL` unless you want to pin it explicitly.

**Google's dual issuer form.** Some Google-issued ID tokens carry
`iss: accounts.google.com` (no scheme) rather than
`https://accounts.google.com`, depending on token age/flow. Accept both
by setting a comma-separated issuer list instead of a single value:

```dotenv
FORWARDED_AUTH_ISSUER=https://accounts.google.com,accounts.google.com
```

The FIRST entry (`https://accounts.google.com`) is the one used for
OIDC discovery; the bare second entry only widens which `iss` claim
values are accepted on an already-verified token's signature check —
it is never used to build a URL, so it's exempt from the library's
otherwise-strict https-or-loopback requirement on issuer/JWKS URLs.

## Local development

Run the app directly (no oauth2-proxy in front) with:

```dotenv
FORWARDED_AUTH_MODE=none
FORWARDED_AUTH_ALLOW_INSECURE_NONE_MODE=1
```

Both variables are required — `mode=none` alone raises
`ConfigurationError`, by design (see the README's "Security model").

This returns a fixed dev user (`dev@localhost` by default — see
`FORWARDED_AUTH_DEV_USER_EMAIL`) and logs a loud warning once per process. Never set this in production.

## Trusted upstream proxy header set (FORWARDED_AUTH_TRUST_PROXY_HEADERS)

This is a different deployment shape from everything above: a SECOND
proxy hop that authenticates out-of-band (its own OAuth flow, a
service mesh sidecar, etc.) and relays identity to your app as
`X-Forwarded-User-*` headers instead of a bearer JWT, stripping
`Authorization` before forwarding. `forwarded-auth` trusts those
headers directly when `FORWARDED_AUTH_TRUST_PROXY_HEADERS=1` -- there
is no token for it to verify on this path, so the entire trust
boundary rests on the proxy's network path to the app being sealed,
and the proxy's own headers never being overridable by the client.

The first hop MUST strip any client-supplied copy of the headers it is
about to set, or a client can set e.g. `X-Forwarded-User-Email` itself
and skip the proxy's authentication step entirely -- this is the same
spoofing risk `FORWARDED_AUTH_REQUIRE_JWT` exists to close for the
bearer-token path, just one hop further out. In Caddy, strip BOTH
header families this library recognises (`X-Forwarded-User-*` for this
trusted-proxy path, `X-Auth-Request-*` for the oauth2-proxy path above)
before setting your own:

```caddyfile
app.example.com {
    reverse_proxy localhost:4180 {
        # Strip any client-supplied copy before oauth2-proxy (or
        # whatever sits here) sets its own trusted values.
        header_up -X-Forwarded-User-Email
        header_up -X-Forwarded-User-Id
        header_up -X-Forwarded-User-Name
        header_up -X-Auth-Request-Email
        header_up -X-Auth-Request-User
        header_up -X-Auth-Request-Preferred-Username
    }
}
```

`FORWARDED_AUTH_ALLOWED_EMAIL_DOMAINS` is still required on this path
-- the proxy-supplied email is checked against it, the same as the
primary-issuer and additional-issuer paths -- and enabling
`trust_proxy_headers` logs a loud once-per-process warning, the same
as `mode=none`/`require_jwt=false`.
