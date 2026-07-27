from __future__ import annotations

from base64 import b64decode
from collections import OrderedDict, deque
from datetime import datetime, timezone
from html import escape
from secrets import token_urlsafe
from time import monotonic
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import select
from sqlalchemy.orm import Session

from atlaso.app.audit import record_audit
from atlaso.app.config import get_settings
from atlaso.app.database import get_db
from atlaso.app.models import (
    OidcAuthorizationTransaction,
    OidcClient,
    OidcGroupMapping,
    OidcSigningKey,
    utcnow,
)
from atlaso.app.services.identity_credentials import verify_credentials
from atlaso.app.schemas import (
    OidcClientCreate,
    OidcClientCreated,
    OidcClientEnabledUpdate,
    OidcClientUpdate,
    OidcClientResponse,
    OidcClientSecretRotated,
    OidcGroupMappingCreate,
    OidcGroupMappingResponse,
    OidcGroupMappingUpdate,
    OidcProviderSettingsResponse,
    OidcProviderSettingsUpdate,
    OidcIntegrationExport,
    OidcSigningKeyResponse,
    OidcSubjectResponse,
)
from atlaso.app.security import Identity, require_scope
from atlaso.app.services.oidc import (
    OIDC_AUTHORIZATION_FLOW_AVAILABLE,
    OidcConfigurationError,
    OidcConflictError,
    create_client,
    create_group_mapping,
    discovery_document,
    delete_retired_signing_key,
    enabled_login_organizations,
    ensure_provider_settings,
    generate_signing_key,
    get_client,
    group_mapping_to_dict,
    issuer_endpoint_urls,
    integration_export,
    jwks_document,
    list_clients,
    list_group_mappings,
    list_subjects,
    normalize_issuer_url,
    oidc_client_to_dict,
    provider_validation_errors,
    begin_authorization,
    client_by_public_id,
    identity_from_source,
    issue_authorization_code,
    issue_tokens,
    redeem_authorization_code,
    resolve_login_source,
    scoped_identity_claims,
    validate_bearer_token,
    validate_userinfo_claims,
    validate_all_mapping_contexts,
    update_group_mapping,
    update_client,
    verify_client_secret,
    rotate_client_secret,
    signing_key_to_dict,
)


public_router = APIRouter(prefix="/identity", tags=["OpenID Connect"])
admin_router = APIRouter(prefix="/api/v1/oidc", tags=["OIDC Provider"])


def _public_configuration_error(exc: OidcConfigurationError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


def _group_mapping_error_detail() -> str:
    return (
        "Review the group source, client scope, and external name; "
        "the mapping is not valid in its effective context."
    )


@public_router.get("/.well-known/openid-configuration", response_model=None)
def get_openid_configuration(
    request: Request, db: Session = Depends(get_db)
) -> JSONResponse:
    try:
        document = discovery_document(db)
    except OidcConfigurationError as exc:
        raise _public_configuration_error(exc) from exc
    if not _identity_https(request):
        raise HTTPException(status_code=400, detail="HTTPS is required.")
    return JSONResponse(document, headers={"Cache-Control": "public, max-age=300"})


@public_router.get("/jwks", response_model=None)
def get_oidc_jwks(request: Request, db: Session = Depends(get_db)) -> JSONResponse:
    try:
        document = jwks_document(db)
    except OidcConfigurationError as exc:
        raise _public_configuration_error(exc) from exc
    if not _identity_https(request):
        raise HTTPException(status_code=400, detail="HTTPS is required.")
    return JSONResponse(document, headers={"Cache-Control": "public, max-age=300"})


OIDC_SESSION_COOKIE = "atlaso_oidc_session"
OIDC_SESSION_MAX_AGE_SECONDS = 12 * 60 * 60
OIDC_LOGIN_ATTEMPTS = 5
OIDC_LOGIN_WINDOW_SECONDS = 60
OIDC_LOGIN_BUCKET_LIMIT = 4096
_OIDC_LOGIN_BUCKETS: OrderedDict[str, deque[float]] = OrderedDict()


def _identity_https(request: Request) -> bool:
    """Trust forwarded HTTPS only from the loopback management proxy."""
    if request.url.scheme == "https":
        return True
    forwarded = request.headers.get("x-forwarded-proto", "").lower() == "https"
    peer = request.client.host if request.client else ""
    return forwarded and peer in {"127.0.0.1", "::1", "localhost"}


def _no_store(response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def _oidc_error(redirect_uri: str | None, error: str, state_value: str = "") -> Response:
    if redirect_uri:
        query = urlencode({"error": error, **({"state": state_value} if state_value else {})})
        return _no_store(
            RedirectResponse(
                f"{redirect_uri}{'&' if '?' in redirect_uri else '?'}{query}",
                status_code=303,
            )
        )
    return _no_store(JSONResponse({"error": error}, status_code=400))


def _session_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(get_settings().secret_key, salt="atlaso-oidc-browser-v1")


def _load_oidc_session(request: Request) -> dict[str, object] | None:
    value = request.cookies.get(OIDC_SESSION_COOKIE, "")
    if not value:
        return None
    try:
        payload = _session_serializer().loads(value, max_age=OIDC_SESSION_MAX_AGE_SECONDS)
    except (BadSignature, SignatureExpired):
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("sid"), str):
        return None
    return payload


def _anonymous_oidc_session() -> dict[str, object]:
    return {"sid": token_urlsafe(32), "csrf": token_urlsafe(32)}


def _set_oidc_cookie(response: Response, session: dict[str, object]) -> None:
    response.set_cookie(
        OIDC_SESSION_COOKIE,
        _session_serializer().dumps(session),
        max_age=OIDC_SESSION_MAX_AGE_SECONDS,
        path="/identity",
        secure=True,
        httponly=True,
        samesite="lax",
    )


def _clear_oidc_cookie(response: Response) -> None:
    response.delete_cookie(
        OIDC_SESSION_COOKIE,
        path="/identity",
        secure=True,
        httponly=True,
        samesite="lax",
    )


def _login_bucket_key(
    *, client_id: str, source: str, organization_id: int | None, username: str
) -> str:
    return f"{client_id}:{source}:{organization_id or 0}:{username.strip().casefold()}"


def _login_throttled(
    *, client_id: str, source: str, organization_id: int | None, username: str
) -> bool:
    now = monotonic()
    key = _login_bucket_key(
        client_id=client_id,
        source=source,
        organization_id=organization_id,
        username=username,
    )
    attempts = _OIDC_LOGIN_BUCKETS.setdefault(key, deque())
    while attempts and attempts[0] <= now - OIDC_LOGIN_WINDOW_SECONDS:
        attempts.popleft()
    if len(attempts) >= OIDC_LOGIN_ATTEMPTS:
        _OIDC_LOGIN_BUCKETS.move_to_end(key)
        return True
    return False


def _record_login_failure(
    *, client_id: str, source: str, organization_id: int | None, username: str
) -> None:
    now = monotonic()
    key = _login_bucket_key(
        client_id=client_id,
        source=source,
        organization_id=organization_id,
        username=username,
    )
    attempts = _OIDC_LOGIN_BUCKETS.setdefault(key, deque())
    while attempts and attempts[0] <= now - OIDC_LOGIN_WINDOW_SECONDS:
        attempts.popleft()
    attempts.append(now)
    _OIDC_LOGIN_BUCKETS.move_to_end(key)
    while len(_OIDC_LOGIN_BUCKETS) > OIDC_LOGIN_BUCKET_LIMIT:
        _OIDC_LOGIN_BUCKETS.popitem(last=False)


def _session_identity(db: Session, session: dict[str, object]):
    source = session.get("source")
    source_record_id = session.get("source_id")
    organization_id = session.get("organization_id")
    if not isinstance(source, str) or not isinstance(source_record_id, int):
        return None
    if organization_id is not None and not isinstance(organization_id, int):
        return None
    return identity_from_source(
        db,
        source=source,
        source_record_id=source_record_id,
        organization_id=organization_id,
    )


def _registered_error_target(
    db: Session, client_id: str, redirect_uri: str
) -> tuple[str | None, OidcClient | None]:
    client = client_by_public_id(db, client_id)
    if client is None or not client.enabled:
        return None, None
    registered = {item.uri for item in client.redirect_uris if item.kind == "redirect"}
    return (redirect_uri if redirect_uri in registered else None), client


def _authorize_request(
    request: Request, db: Session, params: dict[str, str]
) -> OidcAuthorizationTransaction | Response:
    if not _identity_https(request):
        return _oidc_error(None, "invalid_request")
    redirect_uri, _client = _registered_error_target(
        db, params.get("client_id", ""), params.get("redirect_uri", "")
    )
    state_value = params.get("state", "")
    if {"request", "request_uri", "claims", "registration"} & params.keys():
        return _oidc_error(redirect_uri, "invalid_request", state_value)
    if params.get("response_type") != "code":
        return _oidc_error(redirect_uri, "unsupported_response_type", state_value)
    if params.get("response_mode", "query") != "query":
        return _oidc_error(redirect_uri, "unsupported_response_mode", state_value)
    if params.get("code_challenge_method") != "S256":
        return _oidc_error(redirect_uri, "invalid_request", state_value)
    max_age_value = params.get("max_age")
    if max_age_value is not None and not max_age_value.isdigit():
        return _oidc_error(redirect_uri, "invalid_request", state_value)
    prompt = params.get("prompt", "login")
    if prompt not in {"none", "login"}:
        return _oidc_error(redirect_uri, "invalid_request", state_value)
    session = _load_oidc_session(request) or _anonymous_oidc_session()
    try:
        return begin_authorization(
            db,
            client_id=params.get("client_id", ""),
            redirect_uri=params.get("redirect_uri", ""),
            scope=params.get("scope", ""),
            state=state_value,
            nonce=params.get("nonce", ""),
            code_challenge=params.get("code_challenge", ""),
            browser_session_id=str(session["sid"]),
            prompt=prompt,
            max_age=int(max_age_value) if max_age_value is not None else None,
            login_hint=params.get("login_hint", ""),
        )
    except OidcConfigurationError:
        return _oidc_error(redirect_uri, "invalid_request", state_value)


def _authorize_login_page(
    db: Session,
    transaction: OidcAuthorizationTransaction,
    session: dict[str, object],
    *,
    error: str = "",
    status_code: int = 200,
    selected_source: str = "",
) -> HTMLResponse:
    client = db.get(OidcClient, transaction.oidc_client_id)
    if client is None:
        return _no_store(HTMLResponse("Authorization request unavailable.", status_code=400))
    error_html = f'<p role="alert">{escape(error)}</p>' if error else ""
    if client.organization_id is not None:
        organization_name = (
            client.organization.name
            if client.organization is not None
            else "Configured organization"
        )
        source_html = (
            '<p><strong>Organization:</strong> '
            + escape(organization_name)
            + "</p>"
        )
    else:
        options = [
            '<option value="">Select an identity source</option>',
            (
                '<option value="local"'
                + (" selected" if selected_source == "local" else "")
                + ">Local</option>"
            ),
        ]
        for organization in enabled_login_organizations(db):
            value = f"managed_ldap:{organization.id}"
            options.append(
                f'<option value="{value}"'
                + (" selected" if selected_source == value else "")
                + f">{escape(organization.name)}</option>"
            )
        source_html = (
            '<label>Organization <select name="source" required>'
            + "".join(options)
            + "</select></label>"
        )
    response = HTMLResponse(
        '<!doctype html><html><head><meta charset="utf-8"><title>Atlaso identity</title>'
        "</head><body><main><h1>Sign in</h1>"
        + error_html
        + '<form method="post" action="/identity/authorize">'
        + f'<input type="hidden" name="transaction" value="{escape(transaction.transaction_id)}">'
        + f'<input type="hidden" name="csrf" value="{escape(str(session["csrf"]))}">'
        + source_html
        + '<label>Username <input name="username" value="'
        + escape(transaction.login_hint, quote=True)
        + '" autocomplete="username" required></label>'
        + '<label>Password <input name="password" type="password" autocomplete="current-password" required></label>'
        + '<button type="submit">Sign in</button></form></main></body></html>',
        status_code=status_code,
    )
    _set_oidc_cookie(response, session)
    return _no_store(response)


@public_router.get("/authorize", response_model=None, operation_id="oidcAuthorizeGet")
async def authorize_get(request: Request, db: Session = Depends(get_db)) -> Response:
    outcome = _authorize_request(request, db, dict(request.query_params))
    if isinstance(outcome, Response):
        return outcome
    transaction = outcome
    db.commit()
    session = _load_oidc_session(request) or {
        "sid": transaction.browser_session_id,
        "csrf": token_urlsafe(32),
    }
    if session.get("sid") != transaction.browser_session_id:
        session = {"sid": transaction.browser_session_id, "csrf": token_urlsafe(32)}
    if transaction.prompt == "none":
        identity = _session_identity(db, session)
        auth_time_value = session.get("auth_time")
        if identity is None or not isinstance(auth_time_value, int):
            return _oidc_error(transaction.redirect_uri, "login_required", transaction.state)
        if (
            transaction.max_age is not None
            and int(utcnow().timestamp()) - auth_time_value > transaction.max_age
        ):
            return _oidc_error(transaction.redirect_uri, "login_required", transaction.state)
        try:
            state_value = transaction.state
            redirect_uri = transaction.redirect_uri
            raw_code = issue_authorization_code(
                db,
                transaction=transaction,
                identity=identity,
                request_browser_session_id=str(session["sid"]),
                authenticated_browser_session_id=str(session["sid"]),
                auth_time=datetime.fromtimestamp(auth_time_value, timezone.utc),
            )
            db.commit()
        except OidcConfigurationError:
            return _oidc_error(transaction.redirect_uri, "login_required", transaction.state)
        query = urlencode({"code": raw_code, "state": state_value})
        response = RedirectResponse(
            f"{redirect_uri}{'&' if '?' in redirect_uri else '?'}{query}",
            status_code=303,
        )
        _set_oidc_cookie(response, session)
        return _no_store(response)
    return _authorize_login_page(db, transaction, session)


@public_router.post("/authorize", response_model=None, operation_id="oidcAuthorizePost")
async def authorize_post(request: Request, db: Session = Depends(get_db)) -> Response:
    if not _identity_https(request):
        return _oidc_error(None, "invalid_request")
    form = await request.form()
    transaction = db.execute(
        select(OidcAuthorizationTransaction).where(
            OidcAuthorizationTransaction.transaction_id == str(form.get("transaction", ""))
        )
    ).scalar_one_or_none()
    if transaction is None:
        return _oidc_error(None, "invalid_request")
    session = _load_oidc_session(request)
    if (
        session is None
        or session.get("sid") != transaction.browser_session_id
        or not isinstance(session.get("csrf"), str)
        or form.get("csrf") != session.get("csrf")
    ):
        return _oidc_error(transaction.redirect_uri, "access_denied", transaction.state)
    client = db.get(OidcClient, transaction.oidc_client_id)
    if client is None or not client.enabled:
        return _oidc_error(transaction.redirect_uri, "invalid_request", transaction.state)
    selected_source = str(form.get("source", ""))
    try:
        source, organization_id = resolve_login_source(
            db,
            client=client,
            selection=selected_source,
        )
    except OidcConfigurationError:
        return _authorize_login_page(
            db,
            transaction,
            session,
            error="Select Local or an available organization.",
            status_code=400,
            selected_source=selected_source,
        )
    username = str(form.get("username", ""))
    if _login_throttled(
        client_id=client.client_id,
        source=source,
        organization_id=organization_id,
        username=username,
    ):
        return _authorize_login_page(
            db,
            transaction,
            session,
            error="Sign-in temporarily limited. Try again shortly.",
            status_code=429,
            selected_source=selected_source,
        )
    identity = verify_credentials(
        db,
        source=source,
        organization_id=organization_id,
        username=username,
        password=str(form.get("password", "")),
    )
    if identity is None:
        _record_login_failure(
            client_id=client.client_id,
            source=source,
            organization_id=organization_id,
            username=username,
        )
        return _authorize_login_page(
            db,
            transaction,
            session,
            error="Invalid username or password.",
            status_code=401,
            selected_source=selected_source,
        )
    auth_time = utcnow()
    authenticated_session: dict[str, object] = {
        "sid": token_urlsafe(32),
        "csrf": token_urlsafe(32),
        "source": identity.source,
        "source_id": identity.source_record_id,
        "organization_id": identity.organization_id,
        "auth_time": int(auth_time.timestamp()),
    }
    try:
        state_value = transaction.state
        redirect_uri = transaction.redirect_uri
        raw_code = issue_authorization_code(
            db,
            transaction=transaction,
            identity=identity,
            request_browser_session_id=str(session["sid"]),
            authenticated_browser_session_id=str(authenticated_session["sid"]),
            auth_time=auth_time,
        )
        db.commit()
    except OidcConfigurationError:
        return _oidc_error(transaction.redirect_uri, "access_denied", transaction.state)
    query = urlencode({"code": raw_code, "state": state_value})
    response = RedirectResponse(
        f"{redirect_uri}{'&' if '?' in redirect_uri else '?'}{query}", status_code=303
    )
    _set_oidc_cookie(response, authenticated_session)
    return _no_store(response)


def _basic_client(request: Request, db: Session) -> OidcClient | None:
    header = request.headers.get("authorization", "")
    if not header.startswith("Basic "):
        return None
    try:
        raw = b64decode(header[6:], validate=True).decode("utf-8")
        client_id, secret = raw.split(":", 1)
    except (ValueError, UnicodeDecodeError):
        return None
    client = client_by_public_id(db, client_id)
    if (
        client is None
        or not client.enabled
        or (client.organization is not None and not client.organization.enabled)
        or client.token_endpoint_auth_method != "client_secret_basic"
        or not verify_client_secret(client.client_secret_hash, secret)
    ):
        return None
    return client


@public_router.post("/token", response_model=None, operation_id="oidcToken")
async def token(request: Request, db: Session = Depends(get_db)) -> Response:
    if not _identity_https(request):
        return _oidc_error(None, "invalid_request")
    client = _basic_client(request, db)
    form = await request.form()
    if client is None:
        return _no_store(
            JSONResponse(
                {"error": "invalid_client"},
                status_code=401,
                headers={"WWW-Authenticate": "Basic"},
            )
        )
    if form.get("grant_type") != "authorization_code":
        return _no_store(
            JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
        )
    if set(form.keys()) - {"grant_type", "code", "redirect_uri", "code_verifier"}:
        return _no_store(JSONResponse({"error": "invalid_request"}, status_code=400))
    try:
        code = redeem_authorization_code(
            db,
            raw_code=str(form.get("code", "")),
            client=client,
            redirect_uri=str(form.get("redirect_uri", "")),
            verifier=str(form.get("code_verifier", "")),
        )
        payload = issue_tokens(db, code=code, client=client)
        db.commit()
        return _no_store(JSONResponse(payload))
    except OidcConfigurationError:
        db.rollback()
        return _no_store(JSONResponse({"error": "invalid_grant"}, status_code=400))


def _bearer_value(request: Request) -> str:
    header = request.headers.get("authorization", "")
    return header[7:] if header.startswith("Bearer ") else ""


async def _userinfo_response(request: Request, db: Session) -> Response:
    if not _identity_https(request):
        return _oidc_error(None, "invalid_request")
    try:
        claims = validate_bearer_token(db, _bearer_value(request), expected_typ="at+jwt")
        _subject, identity, client = validate_userinfo_claims(db, claims)
        scope_value = claims.get("scope")
        if not isinstance(scope_value, str) or "openid" not in scope_value.split():
            raise OidcConfigurationError("Invalid token.")
        identity_claims = scoped_identity_claims(
            db,
            client=client,
            identity=identity,
            scopes=scope_value,
        )
    except OidcConfigurationError:
        return _no_store(
            JSONResponse(
                {"error": "invalid_token"},
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )
        )
    return _no_store(JSONResponse({"sub": claims["sub"], **identity_claims}))


@public_router.get("/userinfo", response_model=None, operation_id="oidcUserInfoGet")
async def userinfo_get(request: Request, db: Session = Depends(get_db)) -> Response:
    return await _userinfo_response(request, db)


@public_router.post("/userinfo", response_model=None, operation_id="oidcUserInfoPost")
async def userinfo_post(request: Request, db: Session = Depends(get_db)) -> Response:
    return await _userinfo_response(request, db)


async def _logout_response(request: Request, db: Session) -> Response:
    if not _identity_https(request):
        return _oidc_error(None, "invalid_request")
    params = dict(request.query_params)
    if request.method == "POST":
        params.update({key: str(value) for key, value in (await request.form()).items()})
    uri = params.get("post_logout_redirect_uri", "")
    state_value = params.get("state", "")
    response: Response
    hint = params.get("id_token_hint", "")
    claims: dict[str, object] | None = None
    if hint:
        try:
            claims = validate_bearer_token(db, hint, expected_typ="JWT")
        except OidcConfigurationError:
            claims = None
    if hint and claims is None:
        response = JSONResponse({"error": "invalid_request"}, status_code=400)
    elif uri:
        client = (
            client_by_public_id(db, str(claims.get("aud") or ""))
            if claims is not None
            else None
        )
        registered = (
            {item.uri for item in client.redirect_uris if item.kind == "post_logout"}
            if client is not None and client.enabled
            else set()
        )
        if uri not in registered:
            response = JSONResponse({"error": "invalid_request"}, status_code=400)
        else:
            location = uri
            if state_value:
                location += ("&" if "?" in uri else "?") + urlencode({"state": state_value})
            response = RedirectResponse(location, status_code=303)
    else:
        response = Response(status_code=204)
    _clear_oidc_cookie(response)
    return _no_store(response)


@public_router.get("/logout", response_model=None, operation_id="oidcLogoutGet")
async def logout_get(request: Request, db: Session = Depends(get_db)) -> Response:
    return await _logout_response(request, db)


@public_router.post("/logout", response_model=None, operation_id="oidcLogoutPost")
async def logout_post(request: Request, db: Session = Depends(get_db)) -> Response:
    return await _logout_response(request, db)


def _provider_response(db: Session) -> OidcProviderSettingsResponse:
    provider = ensure_provider_settings(db)
    errors = provider_validation_errors(db, provider)
    try:
        urls = issuer_endpoint_urls(provider.issuer_url)
    except OidcConfigurationError:
        urls = {
            "discovery_url": "",
            "authorization_endpoint": "",
            "token_endpoint": "",
            "userinfo_endpoint": "",
            "jwks_uri": "",
            "end_session_endpoint": "",
        }
    return OidcProviderSettingsResponse(
        enabled=provider.enabled,
        issuer_url=provider.issuer_url,
        access_token_lifetime_seconds=provider.access_token_lifetime_seconds,
        id_token_lifetime_seconds=provider.id_token_lifetime_seconds,
        authorization_code_lifetime_seconds=provider.authorization_code_lifetime_seconds,
        clock_skew_seconds=provider.clock_skew_seconds,
        signing_key_overlap_seconds=provider.signing_key_overlap_seconds,
        authorization_flow_available=OIDC_AUTHORIZATION_FLOW_AVAILABLE,
        valid=not errors,
        validation_errors=errors,
        discovery_url=urls["discovery_url"],
        authorization_endpoint=urls["authorization_endpoint"],
        token_endpoint=urls["token_endpoint"],
        userinfo_endpoint=urls["userinfo_endpoint"],
        jwks_uri=urls["jwks_uri"],
        end_session_endpoint=urls["end_session_endpoint"],
    )


@admin_router.get("/provider", response_model=OidcProviderSettingsResponse)
def get_oidc_provider_settings(
    _identity: Identity = Depends(require_scope("admin:all")),
    db: Session = Depends(get_db),
) -> OidcProviderSettingsResponse:
    return _provider_response(db)


@admin_router.put("/provider", response_model=OidcProviderSettingsResponse)
def update_oidc_provider_settings(
    payload: OidcProviderSettingsUpdate,
    request: Request,
    identity: Identity = Depends(require_scope("admin:all")),
    db: Session = Depends(get_db),
) -> OidcProviderSettingsResponse:
    if payload.enabled and not OIDC_AUTHORIZATION_FLOW_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "This build contains the OIDC protocol skeleton only. "
                "The provider cannot be enabled until the Authorization Code flow is available."
            ),
        )
    provider = ensure_provider_settings(db)
    previous_issuer = provider.issuer_url
    try:
        provider.issuer_url = normalize_issuer_url(payload.issuer_url)
    except OidcConfigurationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
    provider.enabled = payload.enabled
    provider.access_token_lifetime_seconds = payload.access_token_lifetime_seconds
    provider.id_token_lifetime_seconds = payload.id_token_lifetime_seconds
    provider.authorization_code_lifetime_seconds = payload.authorization_code_lifetime_seconds
    provider.clock_skew_seconds = payload.clock_skew_seconds
    provider.signing_key_overlap_seconds = payload.signing_key_overlap_seconds
    provider.updated_at = utcnow()
    db.add(provider)
    db.flush()
    errors = provider_validation_errors(db, provider)
    if payload.enabled and errors:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="OIDC provider readiness validation failed: " + " ".join(errors),
        )
    if previous_issuer != provider.issuer_url:
        record_audit(
            db,
            actor=identity.username,
            action="change_oidc_issuer",
            resource_type="oidc_provider",
            resource_id=str(provider.id),
            detail=f"issuer={provider.issuer_url}",
            request_id=getattr(request.state, "request_id", None),
        )
    else:
        record_audit(
            db,
            actor=identity.username,
            action="update_oidc_provider",
            resource_type="oidc_provider",
            resource_id=str(provider.id),
            request_id=getattr(request.state, "request_id", None),
        )
    return _provider_response(db)


@admin_router.get("/signing-keys", response_model=list[OidcSigningKeyResponse])
def get_oidc_signing_keys(
    _identity: Identity = Depends(require_scope("admin:all")),
    db: Session = Depends(get_db),
) -> list[OidcSigningKeyResponse]:
    rows = db.execute(select(OidcSigningKey).order_by(OidcSigningKey.created_at.desc())).scalars().all()
    return [OidcSigningKeyResponse(**signing_key_to_dict(row)) for row in rows]


@admin_router.post(
    "/signing-keys",
    response_model=OidcSigningKeyResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_oidc_signing_key(
    request: Request,
    identity: Identity = Depends(require_scope("admin:all")),
    db: Session = Depends(get_db),
) -> OidcSigningKeyResponse:
    try:
        row, _previous = generate_signing_key(db, rotate=False)
    except OidcConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    record_audit(
        db,
        actor=identity.username,
        action="generate_oidc_signing_key",
        resource_type="oidc_signing_key",
        resource_id=str(row.id),
        detail=f"kid={row.kid}; algorithm={row.algorithm}",
        request_id=getattr(request.state, "request_id", None),
    )
    return OidcSigningKeyResponse(**signing_key_to_dict(row))


@admin_router.post("/signing-keys/rotate", response_model=OidcSigningKeyResponse)
def rotate_oidc_signing_key(
    request: Request,
    identity: Identity = Depends(require_scope("admin:all")),
    db: Session = Depends(get_db),
) -> OidcSigningKeyResponse:
    row, previous = generate_signing_key(db, rotate=True)
    action = "rotate_oidc_signing_key" if previous is not None else "generate_oidc_signing_key"
    detail = f"kid={row.kid}; algorithm={row.algorithm}"
    if previous is not None:
        detail += f"; retired_kid={previous.kid}; publish_until={previous.publish_until.isoformat()}"
    record_audit(
        db,
        actor=identity.username,
        action=action,
        resource_type="oidc_signing_key",
        resource_id=str(row.id),
        detail=detail,
        request_id=getattr(request.state, "request_id", None),
    )
    return OidcSigningKeyResponse(**signing_key_to_dict(row))


@admin_router.delete(
    "/signing-keys/{key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="deleteRetiredOidcSigningKey",
)
def delete_oidc_signing_key(
    key_id: int,
    request: Request,
    identity: Identity = Depends(require_scope("admin:all")),
    db: Session = Depends(get_db),
) -> Response:
    row = db.get(OidcSigningKey, key_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OIDC signing key not found.")
    kid = row.kid
    try:
        delete_retired_signing_key(db, row)
    except OidcConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    record_audit(
        db,
        actor=identity.username,
        action="delete_retired_oidc_signing_key",
        resource_type="oidc_signing_key",
        resource_id=str(key_id),
        detail=f"kid={kid}",
        request_id=getattr(request.state, "request_id", None),
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@admin_router.get("/clients", response_model=list[OidcClientResponse])
def get_oidc_clients(
    _identity: Identity = Depends(require_scope("admin:all")),
    db: Session = Depends(get_db),
) -> list[OidcClientResponse]:
    return [OidcClientResponse(**oidc_client_to_dict(row)) for row in list_clients(db)]


@admin_router.get(
    "/group-mappings",
    response_model=list[OidcGroupMappingResponse],
    operation_id="listOidcGroupMappings",
)
def get_oidc_group_mappings(
    _identity: Identity = Depends(require_scope("admin:all")),
    db: Session = Depends(get_db),
) -> list[OidcGroupMappingResponse]:
    return [
        OidcGroupMappingResponse(**group_mapping_to_dict(row))
        for row in list_group_mappings(db)
    ]


@admin_router.post(
    "/group-mappings",
    response_model=OidcGroupMappingResponse,
    status_code=status.HTTP_201_CREATED,
    operation_id="createOidcGroupMapping",
)
def create_oidc_group_mapping(
    payload: OidcGroupMappingCreate,
    request: Request,
    identity: Identity = Depends(require_scope("admin:all")),
    db: Session = Depends(get_db),
) -> OidcGroupMappingResponse:
    try:
        row = create_group_mapping(
            db,
            source_type=payload.source_type,
            local_role=payload.local_role,
            ldap_group_id=payload.ldap_group_id,
            oidc_client_id=payload.oidc_client_id,
            external_group_name=payload.external_group_name,
        )
    except OidcConflictError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except OidcConfigurationError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    record_audit(
        db,
        actor=identity.username,
        action="create_oidc_group_mapping",
        resource_type="oidc_group_mapping",
        resource_id=str(row.id),
        detail=(
            f"source_type={row.source_type}; organization_id={row.organization_id or 'local'}; "
            f"client_id={row.oidc_client_id or 'default'}"
        ),
        request_id=getattr(request.state, "request_id", None),
    )
    return OidcGroupMappingResponse(**group_mapping_to_dict(row))


@admin_router.patch(
    "/group-mappings/{mapping_id}",
    response_model=OidcGroupMappingResponse,
    operation_id="updateOidcGroupMapping",
)
def update_oidc_group_mapping(
    mapping_id: int,
    payload: OidcGroupMappingUpdate,
    request: Request,
    identity: Identity = Depends(require_scope("admin:all")),
    db: Session = Depends(get_db),
) -> OidcGroupMappingResponse:
    row = db.get(OidcGroupMapping, mapping_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="OIDC group mapping not found.",
        )
    try:
        row = update_group_mapping(
            db,
            row=row,
            oidc_client_id=payload.oidc_client_id,
            external_group_name=payload.external_group_name,
        )
    except OidcConflictError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except OidcConfigurationError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    record_audit(
        db,
        actor=identity.username,
        action="update_oidc_group_mapping",
        resource_type="oidc_group_mapping",
        resource_id=str(row.id),
        detail=(
            f"source_type={row.source_type}; organization_id={row.organization_id or 'local'}; "
            f"client_id={row.oidc_client_id or 'default'}"
        ),
        request_id=getattr(request.state, "request_id", None),
    )
    return OidcGroupMappingResponse(**group_mapping_to_dict(row))


@admin_router.delete(
    "/group-mappings/{mapping_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    operation_id="deleteOidcGroupMapping",
)
def delete_oidc_group_mapping(
    mapping_id: int,
    request: Request,
    identity: Identity = Depends(require_scope("admin:all")),
    db: Session = Depends(get_db),
) -> Response:
    row = db.get(OidcGroupMapping, mapping_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="OIDC group mapping not found.",
        )
    source_type = row.source_type
    organization_id = row.organization_id
    client_id = row.oidc_client_id
    try:
        db.delete(row)
        db.flush()
        validate_all_mapping_contexts(db)
    except OidcConfigurationError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=_group_mapping_error_detail(),
        ) from None
    record_audit(
        db,
        actor=identity.username,
        action="delete_oidc_group_mapping",
        resource_type="oidc_group_mapping",
        resource_id=str(mapping_id),
        detail=(
            f"source_type={source_type}; organization_id={organization_id or 'local'}; "
            f"client_id={client_id or 'default'}"
        ),
        request_id=getattr(request.state, "request_id", None),
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@admin_router.get("/subjects", response_model=list[OidcSubjectResponse])
def get_oidc_subjects(
    _identity: Identity = Depends(require_scope("admin:all")),
    db: Session = Depends(get_db),
) -> list[OidcSubjectResponse]:
    return [OidcSubjectResponse(**row) for row in list_subjects(db)]


@admin_router.post(
    "/clients",
    response_model=OidcClientCreated,
    status_code=status.HTTP_201_CREATED,
)
def create_oidc_client(
    payload: OidcClientCreate,
    request: Request,
    identity: Identity = Depends(require_scope("admin:all")),
    db: Session = Depends(get_db),
) -> OidcClientCreated:
    try:
        row, raw_secret = create_client(
            db,
            name=payload.name,
            organization_id=payload.organization_id,
            redirect_uris=payload.redirect_uris,
            post_logout_redirect_uris=payload.post_logout_redirect_uris,
            allowed_scopes=payload.allowed_scopes,
            allow_loopback_redirects=payload.allow_loopback_redirects,
            access_token_lifetime_seconds=payload.access_token_lifetime_seconds,
            id_token_lifetime_seconds=payload.id_token_lifetime_seconds,
            authorization_code_lifetime_seconds=payload.authorization_code_lifetime_seconds,
            enabled=payload.enabled,
        )
    except OidcConfigurationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
    record_audit(
        db,
        actor=identity.username,
        action="create_oidc_client",
        resource_type="oidc_client",
        resource_id=str(row.id),
        detail=f"client_id={row.client_id}; organization_id={row.organization_id or 'unbound'}",
        request_id=getattr(request.state, "request_id", None),
    )
    return OidcClientCreated(
        client=OidcClientResponse(**oidc_client_to_dict(row)),
        client_secret=raw_secret,
    )


@admin_router.put(
    "/clients/{client_record_id}",
    response_model=OidcClientResponse,
    operation_id="updateOidcClient",
)
def update_oidc_client(
    client_record_id: int,
    payload: OidcClientUpdate,
    request: Request,
    identity: Identity = Depends(require_scope("admin:all")),
    db: Session = Depends(get_db),
) -> OidcClientResponse:
    try:
        row = get_client(db, client_record_id)
        row = update_client(
            db,
            row=row,
            name=payload.name,
            organization_id=payload.organization_id,
            redirect_uris=payload.redirect_uris,
            post_logout_redirect_uris=payload.post_logout_redirect_uris,
            allowed_scopes=payload.allowed_scopes,
            allow_loopback_redirects=payload.allow_loopback_redirects,
            access_token_lifetime_seconds=payload.access_token_lifetime_seconds,
            id_token_lifetime_seconds=payload.id_token_lifetime_seconds,
            authorization_code_lifetime_seconds=payload.authorization_code_lifetime_seconds,
            enabled=payload.enabled,
        )
    except OidcConfigurationError as exc:
        db.rollback()
        status_code = (
            status.HTTP_404_NOT_FOUND
            if str(exc) == "OIDC client not found."
            else status.HTTP_422_UNPROCESSABLE_CONTENT
        )
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc
    record_audit(
        db,
        actor=identity.username,
        action="update_oidc_client",
        resource_type="oidc_client",
        resource_id=str(row.id),
        detail=f"client_id={row.client_id}; organization_id={row.organization_id or 'unbound'}",
        request_id=getattr(request.state, "request_id", None),
    )
    return OidcClientResponse(**oidc_client_to_dict(row))


@admin_router.get(
    "/clients/{client_record_id}/integration-export",
    response_model=OidcIntegrationExport,
    operation_id="exportOidcClientIntegration",
)
def export_oidc_client_integration(
    client_record_id: int,
    request: Request,
    identity: Identity = Depends(require_scope("admin:all")),
    db: Session = Depends(get_db),
) -> OidcIntegrationExport:
    try:
        row = get_client(db, client_record_id)
    except OidcConfigurationError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    record_audit(
        db,
        actor=identity.username,
        action="export_oidc_client_integration",
        resource_type="oidc_client",
        resource_id=str(row.id),
        detail=f"client_id={row.client_id}",
        request_id=getattr(request.state, "request_id", None),
    )
    return OidcIntegrationExport(**integration_export(db, row))


@admin_router.post(
    "/clients/{client_record_id}/secret/rotate",
    response_model=OidcClientSecretRotated,
)
def rotate_oidc_client_secret(
    client_record_id: int,
    request: Request,
    identity: Identity = Depends(require_scope("admin:all")),
    db: Session = Depends(get_db),
) -> OidcClientSecretRotated:
    try:
        row = get_client(db, client_record_id)
    except OidcConfigurationError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    raw_secret = rotate_client_secret(db, row)
    record_audit(
        db,
        actor=identity.username,
        action="rotate_oidc_client_secret",
        resource_type="oidc_client",
        resource_id=str(row.id),
        detail=f"client_id={row.client_id}",
        request_id=getattr(request.state, "request_id", None),
    )
    return OidcClientSecretRotated(client_id=row.client_id, client_secret=raw_secret)


@admin_router.patch("/clients/{client_record_id}/enabled", response_model=OidcClientResponse)
def set_oidc_client_enabled(
    client_record_id: int,
    payload: OidcClientEnabledUpdate,
    request: Request,
    identity: Identity = Depends(require_scope("admin:all")),
    db: Session = Depends(get_db),
) -> OidcClientResponse:
    try:
        row = get_client(db, client_record_id)
    except OidcConfigurationError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    row.enabled = payload.enabled
    row.updated_at = utcnow()
    db.add(row)
    db.flush()
    record_audit(
        db,
        actor=identity.username,
        action="enable_oidc_client" if payload.enabled else "disable_oidc_client",
        resource_type="oidc_client",
        resource_id=str(row.id),
        detail=f"client_id={row.client_id}",
        request_id=getattr(request.state, "request_id", None),
    )
    return OidcClientResponse(**oidc_client_to_dict(row))


@admin_router.delete("/clients/{client_record_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_oidc_client(
    client_record_id: int,
    request: Request,
    identity: Identity = Depends(require_scope("admin:all")),
    db: Session = Depends(get_db),
) -> Response:
    try:
        row = get_client(db, client_record_id)
    except OidcConfigurationError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    public_client_id = row.client_id
    db.delete(row)
    db.flush()
    record_audit(
        db,
        actor=identity.username,
        action="delete_oidc_client",
        resource_type="oidc_client",
        resource_id=str(client_record_id),
        detail=f"client_id={public_client_id}",
        request_id=getattr(request.state, "request_id", None),
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
