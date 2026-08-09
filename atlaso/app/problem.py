"""Render consistent problem responses and browser-login redirects."""

from uuid import uuid4
from urllib.parse import quote

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse


def should_redirect_to_login(request: Request, exc: HTTPException) -> bool:
    """Return whether redirect to login.

    Args:
        request: Incoming HTTP request.
        exc: Exception that caused the operation to fail.
    """
    if exc.status_code != 401 or exc.detail != "Authentication required":
        return False
    path = request.url.path
    return not (
        path == "/openapi.json"
        or path.startswith("/api/")
        or path in {"/api/docs", "/api/redoc"}
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
            "instance": str(request.url.path),
            "error_code": error_code,
            "request_id": request_id,
        },
    )


def install_problem_handlers(app: FastAPI) -> None:
    """Handle install problem handlers."""
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse | RedirectResponse:
        """Return http exception handler.

        Args:
            request: Incoming HTTP request.
            exc: Exception that caused the operation to fail.
        """
        if should_redirect_to_login(request, exc):
            target = request.url.path
            if request.url.query:
                target = f"{target}?{request.url.query}"
            return RedirectResponse(f"/login?next={quote(target, safe='/?=&%')}", status_code=303)
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
