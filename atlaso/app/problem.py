"""Render consistent problem responses and browser-login redirects."""

from urllib.parse import urlencode
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse

from atlaso.app.browser_requests import LOGIN_FORM_EXPIRED_KEY, is_browser_navigation
from atlaso.app.ui_routes import (
    MANAGEMENT_UI_ROOT,
    PUBLIC_UI_ROOT,
    management_ui_path,
    public_ui_path,
    safe_depot_login_next,
    safe_management_return_path,
    safe_public_return_path,
)


def redacted_request_path(path: str) -> str:
    """Return a path safe for responses and operational logging.

    Args:
        path: Original request path to sanitize.
    """
    if path.startswith("/pxe/esxi/ks/"):
        return "/pxe/esxi/ks/[redacted].cfg"
    if path.startswith("/pxe/esxi/claim/"):
        return "/pxe/esxi/claim/[redacted].ipxe"
    return path


def should_redirect_to_login(request: Request, exc: HTTPException) -> bool:
    """Return whether redirect to login.

    Args:
        request: Incoming HTTP request.
        exc: Exception that caused the operation to fail.
    """
    if exc.status_code != 401 or exc.detail != "Authentication required":
        return False
    if not is_browser_navigation(request):
        return False
    path = request.url.path
    return (
        path == MANAGEMENT_UI_ROOT or path.startswith(f"{MANAGEMENT_UI_ROOT}/")
        or path == PUBLIC_UI_ROOT or path.startswith(f"{PUBLIC_UI_ROOT}/")
        # The established management return-target contract also admits its
        # authenticated certificate downloads outside the browser namespace.
        or safe_management_return_path(path) == path
    )


def problem_response(
    *,
    status_code: int,
    title: str,
    detail: str,
    request: Request,
    error_code: str,
) -> JSONResponse:
    """Return problem response.

    Args:
        status_code: HTTP status code for the response.
        title: Title supplied by the caller.
        detail: Detail supplied by the caller.
        request: Incoming HTTP request.
        error_code: Error code supplied by the caller.
    """
    request_id = getattr(request.state, "request_id", None) or f"req_{uuid4().hex[:12]}"
    return JSONResponse(
        status_code=status_code,
        content={
            "type": f"https://atlaso.internal/errors/{error_code.lower().replace('_', '-')}",
            "title": title,
            "status": status_code,
            "detail": detail,
            "instance": redacted_request_path(str(request.url.path)),
            "error_code": error_code,
            "request_id": request_id,
        },
    )


def install_problem_handlers(app: FastAPI) -> None:
    """Handle install problem handlers.

    Args:
        app: App consumed by install problem handlers.
    """
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse | RedirectResponse:
        """Return http exception handler.

        Args:
            request: Incoming HTTP request.
            exc: Exception that caused the operation to fail.
        """
        login_defaults = {
            management_ui_path("/login"): MANAGEMENT_UI_ROOT,
            public_ui_path("/login"): public_ui_path("/terminal"),
            public_ui_path("/ca/login"): public_ui_path("/ca"),
            public_ui_path("/ca/requests/login"): public_ui_path("/ca/requests"),
            "/PROD/login": "/PROD/",
        }
        if (
            exc.status_code == 403 and exc.detail == "Invalid CSRF token"
            and request.method == "POST" and request.url.path in login_defaults
            and is_browser_navigation(request)
        ):
            # Reject the original submission. The following GET issues fresh
            # CSRF state; never authenticate or replay the submitted credentials.
            request.session[LOGIN_FORM_EXPIRED_KEY] = True
            target = login_defaults[request.url.path]
            login_path = request.url.path
            if request.url.path == management_ui_path("/login"):
                form = await request.form()
                target = safe_management_return_path(str(form.get("next") or ""))
                if target.split("?", 1)[0] == request.url.path:
                    target = MANAGEMENT_UI_ROOT
            elif request.url.path == "/PROD/login":
                form = await request.form()
                target = safe_depot_login_next(str(form.get("next") or ""))
                if target.split("?", 1)[0] == "/PROD/login":
                    target = "/PROD/"
            elif request.url.path == public_ui_path("/ca/requests/login"):
                login_path = public_ui_path("/ca/requests")
            return RedirectResponse(
                f"{login_path}?{urlencode({'next': target}, safe='/')}", status_code=303,
            )
        if should_redirect_to_login(request, exc):
            target = request.url.path
            if request.url.query:
                target = f"{target}?{request.url.query}"
            public_plane = (
                getattr(request.state, "ui_plane", "") == "public"
                or target == PUBLIC_UI_ROOT
                or target.startswith(f"{PUBLIC_UI_ROOT}/")
            )
            if public_plane:
                login_path = public_ui_path("/login")
                target = safe_public_return_path(target, default="/terminal")
                if target.startswith(public_ui_path("/terminal/")):
                    target = public_ui_path("/terminal")
            else:
                login_path = management_ui_path("/login")
                target = safe_management_return_path(target)
            if request.method not in {"GET", "HEAD"}:
                target = public_ui_path("/terminal") if public_plane else MANAGEMENT_UI_ROOT
            return RedirectResponse(f"{login_path}?{urlencode({'next': target}, safe='/')}", status_code=303)
        title = "Unauthorized" if exc.status_code == 401 else "Request failed"
        return problem_response(
            status_code=exc.status_code,
            title=title,
            detail=str(exc.detail),
            request=request,
            error_code="HTTP_ERROR",
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        """Return validation exception handler.

        Args:
            request: Incoming HTTP request.
            exc: Exception that caused the operation to fail.
        """
        return problem_response(
            status_code=422,
            title="Validation error",
            detail="Invalid request payload",
            request=request,
            error_code="VALIDATION_ERROR",
        )
