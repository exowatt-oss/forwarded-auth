"""Profile-claim recovery for bearer tokens that omit ``name``/``picture``
(e.g. after a refresh-token grant on some providers).

Some OIDC providers' refresh-token grant drops profile claims from the
``id_token`` after the first login — only the stable identity claims
(``sub``, ``email``, ...) survive. This module supplies ``name`` /
``picture`` in that case via two cooperating, fail-open mechanisms:

1. **Observe-and-cache (no network).** Whenever a verified token DOES
   carry the profile claims, :func:`remember_profile` stashes them in a
   process-wide cache keyed by ``sub``. A later claim-poor token for the
   same ``sub`` reuses the cached value with no network call.
2. **userinfo fallback (network, opt-in by configuration).** When the
   cache is cold and both a configured userinfo URL and a forwarded
   access token are available, :func:`resolve_profile` calls the
   userinfo endpoint and caches the result.

Both layers fail open: any error returns ``(None, None)`` and the
caller falls back to its own header/email chain. This module never
raises, never treats the cache as a load-bearing identity source
(``email``/``sub`` are always derived from the verified token), and
never blocks a request beyond a short HTTP timeout.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from typing import Any

_logger = logging.getLogger(__name__)

_USERINFO_TIMEOUT_S = 3.0
_PROFILE_CACHE_TTL_S = 6 * 3600.0
_PROFILE_CACHE_MAX_ENTRIES = 1024

_cache_lock = threading.Lock()
_profile_cache: dict[str, tuple[str | None, str | None, float]] = {}


def _normalize(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _sweep_locked(now: float) -> None:
    expired = [k for k, (_, _, expiry) in _profile_cache.items() if now >= expiry]
    for k in expired:
        _profile_cache.pop(k, None)
    if len(_profile_cache) > _PROFILE_CACHE_MAX_ENTRIES:
        ordered = sorted(_profile_cache.items(), key=lambda kv: kv[1][2])
        drop_count = len(ordered) - (_PROFILE_CACHE_MAX_ENTRIES // 2)
        for k, _ in ordered[:drop_count]:
            _profile_cache.pop(k, None)


def remember_profile(sub: str | None, name: str | None, picture: str | None) -> None:
    """Stash a freshly-observed profile in the cache, keyed by ``sub``.
    No-op when ``sub`` is falsy."""
    if not sub:
        return
    now = time.time()
    with _cache_lock:
        _profile_cache[sub] = (_normalize(name), _normalize(picture), now + _PROFILE_CACHE_TTL_S)
        if len(_profile_cache) > _PROFILE_CACHE_MAX_ENTRIES:
            _sweep_locked(now)


def _lookup_cached(sub: str) -> tuple[str | None, str | None] | None:
    with _cache_lock:
        entry = _profile_cache.get(sub)
        if entry is None:
            return None
        name, picture, expiry = entry
        if time.time() >= expiry:
            _profile_cache.pop(sub, None)
            return None
        return name, picture


def _fetch_userinfo(userinfo_url: str, access_token: str) -> dict[str, Any]:
    """GET ``userinfo_url`` with the forwarded access token. Returns the
    parsed JSON body, or ``{}`` on any failure. Never raises."""
    req = urllib.request.Request(
        userinfo_url,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=_USERINFO_TIMEOUT_S) as resp:  # noqa: S310
            body = resp.read()
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        _logger.debug("userinfo fetch failed: %s", exc)
        return {}
    try:
        parsed = json.loads(body)
    except (ValueError, TypeError) as exc:
        _logger.debug("userinfo response was not JSON: %s", exc)
        return {}
    return parsed if isinstance(parsed, dict) else {}


def resolve_profile(
    sub: str | None,
    access_token: str | None,
    *,
    userinfo_url: str | None,
    disabled: bool,
) -> tuple[str | None, str | None]:
    """Return the best-known ``(name, picture)`` for ``sub``.

    Priority: non-expired cache hit; else a userinfo call (if ``sub``,
    ``access_token``, and ``userinfo_url`` are all present and
    ``disabled`` is false), cross-checked against ``sub`` and cached;
    else ``(None, None)``. Always fails open.
    """
    if sub:
        cached = _lookup_cached(sub)
        if cached is not None:
            return cached

    if not sub or not access_token or not userinfo_url or disabled:
        return None, None

    userinfo = _fetch_userinfo(userinfo_url, access_token)
    if not userinfo:
        # Transient failure: don't cache, so a healthy retry isn't
        # suppressed for the TTL.
        return None, None

    userinfo_sub = userinfo.get("sub")
    if not (isinstance(userinfo_sub, str) and userinfo_sub == sub):
        _logger.warning(
            "userinfo response missing or mismatched sub for forwarded access "
            "token; skipping enrichment to avoid misattribution"
        )
        return None, None

    name = _normalize(userinfo.get("name"))
    picture = _normalize(userinfo.get("picture"))
    remember_profile(sub, name, picture)
    return name, picture


def _reset_cache_for_tests() -> None:
    with _cache_lock:
        _profile_cache.clear()
