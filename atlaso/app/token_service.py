from sqlalchemy.orm import Session

from atlaso.app.audit import record_audit
from atlaso.app.config import Settings
from atlaso.app.models import ApiToken, User, utcnow
from atlaso.app.schemas import ApiTokenCreate, ApiTokenCreated, ApiTokenResponse
from atlaso.app.security import (
    ALL_SCOPES,
    create_jwt,
    default_expiration,
    hash_token,
    primary_role,
    roles_allow_scopes,
    user_roles,
    normalize_roles,
    scopes_from_string,
)
from fastapi import HTTPException
from uuid import uuid4


def token_to_response(token: ApiToken) -> ApiTokenResponse:
    return ApiTokenResponse(
        id=token.id,
        jti=token.jti,
        name=token.name,
        description=token.description,
        owner_user_id=token.owner_user_id,
        owner_username=token.owner_username,
        token_type=token.token_type,
        role=token.role,
        roles=normalize_roles([token.role]),
        scopes=sorted(scopes_from_string(token.scopes)),
        created_at=token.created_at,
        expires_at=token.expires_at,
        last_used_at=token.last_used_at,
        revoked_at=token.revoked_at,
        revoked_by=token.revoked_by,
        enabled=token.enabled,
        signing_key_id=token.signing_key_id,
    )


def create_token_for_user(
    db: Session,
    *,
    user: User,
    create: ApiTokenCreate,
    settings: Settings,
    actor: str,
) -> ApiTokenCreated:
    requested = set(create.scopes)
    unknown_scopes = requested - ALL_SCOPES
    if unknown_scopes:
        raise HTTPException(status_code=422, detail=f"Unknown scopes: {', '.join(sorted(unknown_scopes))}")
    roles = user_roles(user)
    if not roles_allow_scopes(roles, requested):
        raise HTTPException(status_code=403, detail="Requested scopes exceed the user's role")
    expires_at = create.expires_at or default_expiration(settings)
    if expires_at <= utcnow():
        raise HTTPException(status_code=422, detail="expires_at must be in the future")
    jti = uuid4().hex
    raw_token = create_jwt(
        subject=user.username,
        role=primary_role(roles),
        roles=roles,
        scopes=sorted(requested),
        jti=jti,
        expires_at=expires_at,
        settings=settings,
    )
    token = ApiToken(
        jti=jti,
        name=create.name,
        description=create.description,
        owner_user_id=user.id,
        owner_username=user.username,
        role=primary_role(roles),
        scopes=" ".join(sorted(requested)),
        expires_at=expires_at,
        token_hash=hash_token(raw_token),
        signing_key_id="local-hs256",
    )
    db.add(token)
    db.commit()
    db.refresh(token)
    record_audit(
        db,
        actor=actor,
        action="create_api_token",
        resource_type="api_token",
        resource_id=str(token.id),
        detail=f"Created API token {token.name}",
    )
    return ApiTokenCreated(token=token_to_response(token), raw_token=raw_token)
