from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi import Path as ApiPath
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from atlaso.app.audit import record_audit
from atlaso.app.config import Settings, get_settings
from atlaso.app.database import get_db
from atlaso.app.models import ApiToken, User, utcnow
from atlaso.app.openapi import DocumentedAPIRoute
from atlaso.app.schemas import (
    ApiTokenCreate,
    ApiTokenCreated,
    ApiTokenResponse,
    IdentityResponse,
)
from atlaso.app.security import Identity, require_scope
from atlaso.app.token_service import create_token_for_user, token_to_response

Endpoint = Callable[..., Any]


@dataclass(frozen=True)
class IdentityApiRouter:
    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_router() -> IdentityApiRouter:
    """Build current-identity and API-token lifecycle transports."""
    router = APIRouter(prefix="/api/v1", route_class=DocumentedAPIRoute)

    @router.get(
        "/auth/me",
        response_model=IdentityResponse,
        tags=["Auth"],
        operation_id="getCurrentIdentity",
    )
    def get_me(
        identity: Annotated[Identity, Depends(require_scope("read:dashboard"))],
    ) -> IdentityResponse:
        """Get Current Identity.

        Requires the `read:dashboard` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
        """
        return IdentityResponse(
            username=identity.username,
            role=identity.role,
            roles=identity.roles,
            scopes=sorted(identity.scopes),
            auth_type=identity.auth_type,
        )

    @router.get(
        "/api-tokens",
        response_model=list[ApiTokenResponse],
        tags=["API Tokens"],
        operation_id="listApiTokens",
    )
    def list_api_tokens(
        identity: Annotated[Identity, Depends(require_scope("read:dashboard"))],
        db: Session = Depends(get_db),
    ) -> list[ApiTokenResponse]:
        """List Api Tokens.

        Requires the `read:dashboard` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        query = select(ApiToken).order_by(desc(ApiToken.created_at))
        if not identity.has_role("admin"):
            query = query.where(ApiToken.owner_user_id == identity.user_id)
        return [token_to_response(token) for token in db.execute(query).scalars().all()]

    @router.post(
        "/api-tokens",
        response_model=ApiTokenCreated,
        status_code=201,
        tags=["API Tokens"],
        operation_id="createApiToken",
    )
    def create_api_token(
        payload: ApiTokenCreate,
        identity: Annotated[Identity, Depends(require_scope("read:dashboard"))],
        db: Session = Depends(get_db),
        settings: Settings = Depends(get_settings),
    ) -> ApiTokenCreated:
        """Create Api Token.

        Requires the `read:dashboard` API scope. The operation changes saved Atlaso application state;
        any appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
            settings: Current Atlaso settings used to configure the operation.
        """
        user = db.get(User, identity.user_id)
        if not user:
            raise HTTPException(status_code=404, detail="Current user not found")
        return create_token_for_user(
            db, user=user, create=payload, settings=settings, actor=identity.username
        )

    @router.get(
        "/api-tokens/{token_id}",
        response_model=ApiTokenResponse,
        tags=["API Tokens"],
        operation_id="getApiToken",
    )
    def get_api_token(
        token_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the token record addressed by this operation."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("read:dashboard"))],
        db: Session = Depends(get_db),
    ) -> ApiTokenResponse:
        """Get Api Token.

        Requires the `read:dashboard` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            token_id: Stable identifier of the associated token resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        token = db.get(ApiToken, token_id)
        if not token or (
            not identity.has_role("admin") and token.owner_user_id != identity.user_id
        ):
            raise HTTPException(status_code=404, detail="API token not found")
        return token_to_response(token)

    def revoke_token(
        db: Session, token: ApiToken, identity: Identity
    ) -> ApiTokenResponse:
        """Return revoke token.

        Args:
            db: Active database session.
            token: Token supplied by the caller.
            identity: Authenticated identity authorizing the request.
        """
        token.enabled = False
        token.revoked_at = utcnow()
        token.revoked_by = identity.username
        db.add(token)
        db.commit()
        db.refresh(token)
        record_audit(
            db,
            actor=identity.username,
            action="revoke_api_token",
            resource_type="api_token",
            resource_id=str(token.id),
            detail=f"Revoked API token {token.name}",
        )
        return token_to_response(token)

    @router.delete(
        "/api-tokens/{token_id}",
        status_code=204,
        tags=["API Tokens"],
        operation_id="deleteApiToken",
    )
    def delete_api_token(
        token_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the token record addressed by this operation."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("read:dashboard"))],
        db: Session = Depends(get_db),
    ) -> Response:
        """Delete Api Token.

        Requires the `read:dashboard` API scope. Removal or revocation takes effect in Atlaso
        application state; appliance host changes remain subject to the documented apply boundary for
        the resource.

        Args:
            token_id: Stable identifier of the associated token resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        token = db.get(ApiToken, token_id)
        if not token or (
            not identity.has_role("admin") and token.owner_user_id != identity.user_id
        ):
            raise HTTPException(status_code=404, detail="API token not found")
        revoke_token(db, token, identity)
        return Response(status_code=204)

    @router.post(
        "/api-tokens/{token_id}/revoke",
        response_model=ApiTokenResponse,
        tags=["API Tokens"],
        operation_id="revokeApiToken",
    )
    def revoke_api_token(
        token_id: Annotated[
            int,
            ApiPath(
                description="Unique identifier of the token record addressed by this operation."
            ),
        ],
        identity: Annotated[Identity, Depends(require_scope("read:dashboard"))],
        db: Session = Depends(get_db),
    ) -> ApiTokenResponse:
        """Revoke Api Token.

        Requires the `read:dashboard` API scope. The operation changes saved Atlaso application state;
        any appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            token_id: Stable identifier of the associated token resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        token = db.get(ApiToken, token_id)
        if not token or (
            not identity.has_role("admin") and token.owner_user_id != identity.user_id
        ):
            raise HTTPException(status_code=404, detail="API token not found")
        return revoke_token(db, token, identity)

    endpoints: dict[str, Endpoint] = {
        "get_me": get_me,
        "list_api_tokens": list_api_tokens,
        "create_api_token": create_api_token,
        "get_api_token": get_api_token,
        "revoke_token": revoke_token,
        "delete_api_token": delete_api_token,
        "revoke_api_token": revoke_api_token,
    }
    return IdentityApiRouter(router=router, endpoints=endpoints)
