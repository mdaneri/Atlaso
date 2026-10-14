"""Classify deliberate browser navigation, including service-worker forwarding."""

from fastapi import Request

LOGIN_FORM_EXPIRED_KEY = "login_form_expired"


def is_browser_navigation(request: Request) -> bool:
    """Recognize documents without treating background fetches as navigation.

    Args:
        request: Incoming request with browser fetch metadata.
    """
    if request.headers.get("Authorization") or request.headers.get("X-Requested-With"):
        return False
    accept = request.headers.get("Accept", "").lower()
    if ("application/json" in accept or "application/problem+json" in accept) and "text/html" not in accept:
        return False
    mode = request.headers.get("Sec-Fetch-Mode", "").strip().lower()
    if mode == "navigate":
        return True
    if mode:
        # fetch(event.request) loses navigation metadata. Only the worker's
        # navigation branch supplies this marker; ordinary fetches stay errors.
        return (
            mode == "same-origin"
            and request.headers.get("X-Atlaso-Browser-Navigation") == "1"
            and "text/html" in accept
        )
    return "text/html" in accept or not accept or accept == "*/*"
