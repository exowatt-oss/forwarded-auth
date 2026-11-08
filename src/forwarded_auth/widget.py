"""Profile widget: a small "Signed in as <email> · Sign out" affordance
apps can drop into their UI.

Renders as a self-contained HTML+CSS snippet. Class names use a unique
``forwarded-auth-widget`` prefix so they can't collide with the host
page's styles — drop-in safe for any app.
"""

from __future__ import annotations

import html

from forwarded_auth._settings import Settings
from forwarded_auth._user import User
from forwarded_auth.logout import logout_url

_WIDGET_CSS = """
.forwarded-auth-widget {
  position: fixed;
  top: 8px;
  right: 8px;
  background: rgba(20, 20, 28, 0.85);
  color: #f5f5f5;
  padding: 6px 14px;
  border-radius: 999px;
  font: 13px / 1.4 system-ui, -apple-system, "Segoe UI", sans-serif;
  display: inline-flex;
  gap: 12px;
  align-items: center;
  z-index: 99999;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.25);
}
.forwarded-auth-widget__user {
  font-weight: 500;
}
.forwarded-auth-widget__signout {
  color: #ffd54f;
  text-decoration: none;
  border-bottom: 1px dotted #ffd54f;
}
.forwarded-auth-widget__signout:hover {
  color: #fff;
  border-bottom-color: #fff;
}
"""


def profile_widget_html(
    user: User,
    *,
    redirect_to: str | None = None,
    settings: Settings | None = None,
) -> str:
    """Render a self-contained HTML+CSS snippet for the profile widget.

    Displays ``user.email`` (not ``user.display_name``) on purpose:
    email is unambiguous and stable, while the display name can be a
    short handle or empty. Embedding multiple times on the same page is
    harmless — duplicate ``<style>`` blocks don't conflict and the
    widget is positioned absolutely, not flow-relative.
    """
    safe_email = html.escape(user.email)
    safe_url = html.escape(logout_url(redirect_to, settings=settings), quote=True)
    return (
        f"<style>{_WIDGET_CSS}</style>"
        f'<div class="forwarded-auth-widget">'
        f'<span class="forwarded-auth-widget__user">{safe_email}</span>'
        f'<a class="forwarded-auth-widget__signout" href="{safe_url}">Sign out</a>'
        f"</div>"
    )
