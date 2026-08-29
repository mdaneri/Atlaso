"""Own Certificate Authority and vSphere Key Provider management UI transports."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from fastapi import (
    APIRouter,
    Depends,
    Form,
    HTTPException,
    Request,
)
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atlaso.app.audit import record_audit
from atlaso.app.database import get_db
from atlaso.app.models import (
    CaCertificate,
    CaProfile,
    VsphereKeyProvider,
    VsphereTrustedVcenter,
    VsphereTrustedVcenterCertificate,
    utcnow,
)
from atlaso.app.secrets import decrypt_secret
from atlaso.app.security import (
    Identity,
    authenticate_user,
    consume_browser_session_expired_notice,
    end_browser_session,
    get_session_identity,
    require_session_identity,
    start_browser_session,
)
from atlaso.app.services.ca import (
    ca_certificate_can_delete,
    ca_certificate_can_edit,
    ca_certificate_to_dict,
    ca_profile_to_dict,
    ensure_root_ca_material,
    join_multiline,
    safe_certificate_name,
    split_multiline,
    validate_ca_certificate_request,
)
from atlaso.app.services.dnsmasq import (
    split_addresses,
    split_interfaces,
)
from atlaso.app.services.kms import (
    KMS_DEFAULT_CONFIG_PATH,
    KMS_DEFAULT_DATABASE_PATH,
)
from atlaso.app.services.vsphere_key_providers import (
    authenticated_provider_counts,
    certificate_to_dict,
    mark_provider_desired_changed,
    parse_public_certificate,
    provider_requires_appliance_apply,
    provider_rows,
    provider_to_dict,
    runtime_status_snapshot,
    trusted_vcenter_to_dict,
    usable_certificates,
)
from atlaso.app.services.vsphere_key_providers import (
    normalize_service_hostname as normalize_vsphere_service_hostname,
)
from atlaso.app.services.vsphere_key_providers import (
    normalize_vcenter_hostname as normalize_vsphere_vcenter_hostname,
)
from atlaso.app.ui_routes import (
    MANAGEMENT_UI_ROOT,
    PUBLIC_UI_ROOT,
    management_ui_path,
    public_ui_path,
    safe_public_return_path,
)

Endpoint = Callable[..., Any]


@dataclass(frozen=True)
class CertificateTrustUiDependencies:
    """Provide facade-owned helpers and ordered public/protocol routers."""

    public_router: APIRouter
    protocol_router: APIRouter
    appliance_apply_status: Endpoint
    ca_context: Endpoint
    ca_request_context: Endpoint
    ensure_ca_state: Endpoint
    ensure_dns_for_ca_portal: Endpoint
    ensure_dns_for_kms: Endpoint
    get_ca_settings_row: Endpoint
    get_kms_settings_row: Endpoint
    grid_error_response: Endpoint
    grid_request: Endpoint
    grid_saved_response: Endpoint
    kms_context: Endpoint
    normalize_dns_hostname: Endpoint
    primary_listen_address: Endpoint
    primary_listen_interface: Endpoint
    public_ca_context: Endpoint
    public_portal_links_context: Endpoint
    public_ui_request_allowed: Endpoint
    render: Endpoint
    request_public_service_route_allowed: Endpoint
    require_certificate_workflow_identity: Endpoint
    require_management_ui_request: Endpoint
    resolve_service_bind_targets: Endpoint
    verify_csrf: Endpoint


@dataclass(frozen=True)
class CertificateTrustUiRouters:
    """Return ordered management routers and compatibility endpoint exports."""

    ca_router: APIRouter
    kms_router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_routers(
    dependencies: CertificateTrustUiDependencies,
) -> CertificateTrustUiRouters:
    """Build Certificate Authority and vSphere Key Provider UI transports.

    Args:
        dependencies: Facade-provided transport dependencies.
    """
    appliance_apply_status = dependencies.appliance_apply_status
    ca_context = dependencies.ca_context
    ca_request_context = dependencies.ca_request_context
    ensure_ca_state = dependencies.ensure_ca_state
    ensure_dns_for_ca_portal = dependencies.ensure_dns_for_ca_portal
    ensure_dns_for_kms = dependencies.ensure_dns_for_kms
    get_ca_settings_row = dependencies.get_ca_settings_row
    get_kms_settings_row = dependencies.get_kms_settings_row
    grid_error_response = dependencies.grid_error_response
    grid_request = dependencies.grid_request
    grid_saved_response = dependencies.grid_saved_response
    kms_context = dependencies.kms_context
    normalize_dns_hostname = dependencies.normalize_dns_hostname
    primary_listen_address = dependencies.primary_listen_address
    primary_listen_interface = dependencies.primary_listen_interface
    public_ca_context = dependencies.public_ca_context
    public_portal_links_context = dependencies.public_portal_links_context
    public_ui_request_allowed = dependencies.public_ui_request_allowed
    render = dependencies.render
    request_public_service_route_allowed = (
        dependencies.request_public_service_route_allowed
    )
    require_certificate_workflow_identity = (
        dependencies.require_certificate_workflow_identity
    )
    require_management_ui_request = dependencies.require_management_ui_request
    resolve_service_bind_targets = dependencies.resolve_service_bind_targets
    verify_csrf = dependencies.verify_csrf
    ca_router = APIRouter(
        prefix=MANAGEMENT_UI_ROOT, dependencies=[Depends(require_management_ui_request)]
    )
    kms_router = APIRouter(
        prefix=MANAGEMENT_UI_ROOT, dependencies=[Depends(require_management_ui_request)]
    )
    public_router = dependencies.public_router
    protocol_router = dependencies.protocol_router

    @ca_router.get(
        "/certificate-authority", response_class=HTMLResponse, response_model=None
    )
    def certificate_authority_page(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the certificate authority page endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        return render(
            request,
            "certificate_authority.html",
            {
                "identity": identity,
                **ca_context(db),
                "appliance_apply_status": appliance_apply_status(db, "ca"),
            },
        )

    @public_router.get("/ca", response_class=HTMLResponse, response_model=None)
    def public_ca_page(
        request: Request,
        identity: Identity | None = Depends(get_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the public ca page endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        if not public_ui_request_allowed(request, db, "/ca"):
            raise HTTPException(
                status_code=404,
                detail="CA public service is not available on this interface",
            )
        return render(
            request, "ca_public.html", {"identity": identity, **public_ca_context(db)}
        )

    def ca_public_login_response(
        request: Request,
        *,
        error: str | None = None,
        status_code: int = 200,
        db: Session | None = None,
    ) -> HTMLResponse:
        """Return ca public login response.

        Args:
            request: Incoming HTTP request.
            error: Public-safe error detail to record or return.
            status_code: HTTP status code for the response.
            db: Active database session.
        """
        return render(
            request,
            "ca_request_login.html",
            {
                "error": error,
                "return_to": public_ui_path("/ca"),
                "login_action": public_ui_path("/ca/login"),
                "portal_title": "Atlaso CA",
                "portal_subtitle": "Public trust portal",
                "back_href": public_ui_path("/ca"),
                "back_label": "Cancel",
                **(public_portal_links_context(db) if db else {}),
            },
            status_code=status_code,
        )

    def authenticate_ca_portal_session(
        request: Request,
        db: Session,
        *,
        username: str,
        password: str,
        csrf: str,
        next_path: str,
        failure_response,
    ) -> RedirectResponse | HTMLResponse:
        """Return authenticate ca portal session.

        Args:
            request: Incoming HTTP request.
            db: Active database session.
            username: Account name used for authentication or lookup.
            password: Password supplied for the immediate authenticated operation.
            csrf: Validated CSRF token authorizing the request.
            next_path: Filesystem path for the next.
            failure_response: Failure response supplied by the caller.
        """
        verify_csrf(request, csrf)
        user = authenticate_user(db, username, password)
        if not user:
            record_audit(
                db,
                actor=username,
                action="ca_request_portal_login_failed",
                resource_type="auth",
                success=False,
            )
            return failure_response(
                request, error="Invalid username or password", status_code=401
            )
        start_browser_session(request, db, user)
        record_audit(
            db,
            actor=user.username,
            action="ca_request_portal_login",
            resource_type="auth",
        )
        return RedirectResponse(next_path, status_code=303)

    @public_router.get("/ca/login", response_class=HTMLResponse, response_model=None)
    def ca_public_login_page(
        request: Request, db: Session = Depends(get_db)
    ) -> HTMLResponse:
        """Handle the ca public login page endpoint.

        Args:
            request: Incoming HTTP request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        if not public_ui_request_allowed(request, db, "/ca"):
            raise HTTPException(
                status_code=404,
                detail="CA public service is not available on this interface",
            )
        return ca_public_login_response(
            request,
            error=consume_browser_session_expired_notice(request),
            db=db,
        )

    @public_router.post("/ca/login", response_model=None)
    def ca_public_login(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
        csrf: str = Form(...),
        next: str = Form(PUBLIC_UI_ROOT + "/ca"),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse:
        """Handle the ca public login endpoint.

        Args:
            request: Incoming HTTP request.
            username: Account name used for authentication or lookup.
            password: Password supplied for the immediate authenticated operation.
            csrf: Validated CSRF token authorizing the request.
            next: Relative destination requested after authentication.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        if not public_ui_request_allowed(request, db, "/ca"):
            raise HTTPException(
                status_code=404,
                detail="CA public service is not available on this interface",
            )
        return_to = safe_public_return_path(next, default="/ca")
        if return_to != public_ui_path("/ca"):
            return_to = public_ui_path("/ca")
        return authenticate_ca_portal_session(
            request,
            db,
            username=username,
            password=password,
            csrf=csrf,
            next_path=return_to,
            failure_response=lambda failed_request, *, error=None, status_code=200: (
                ca_public_login_response(
                    failed_request,
                    error=error,
                    status_code=status_code,
                    db=db,
                )
            ),
        )

    def public_root_ca_response(db: Session, *, bundle: bool = False) -> Response:
        """Return public root ca response.

        Args:
            db: Active database session.
            bundle: Bundle supplied by the caller.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        settings = get_ca_settings_row(db)
        if not settings.root_certificate_pem:
            raise HTTPException(
                status_code=404, detail="Root CA certificate is not available"
            )
        filename = "atlaso-ca-bundle.pem" if bundle else "atlaso-root-ca.pem"
        return Response(
            settings.root_certificate_pem.encode("utf-8"),
            media_type="application/x-pem-file",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @protocol_router.get("/ca/downloads/root-ca.pem", response_model=None)
    def download_public_root_ca(
        request: Request,
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the download public root ca endpoint.

        Args:
            request: Incoming HTTP request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        if not request_public_service_route_allowed(db, request, "ca"):
            raise HTTPException(
                status_code=404,
                detail="CA public service is not available on this interface",
            )
        return public_root_ca_response(db)

    @protocol_router.get("/ca/downloads/ca-bundle.pem", response_model=None)
    def download_public_ca_bundle(
        request: Request,
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the download public ca bundle endpoint.

        Args:
            request: Incoming HTTP request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        if not request_public_service_route_allowed(db, request, "ca"):
            raise HTTPException(
                status_code=404,
                detail="CA public service is not available on this interface",
            )
        return public_root_ca_response(db, bundle=True)

    @ca_router.get("/ca/requests", response_class=HTMLResponse, response_model=None)
    def ca_requests_page(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the ca requests page endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        require_certificate_workflow_identity(identity)
        return render(
            request,
            "ca_requests.html",
            {"identity": identity, **ca_request_context(db)},
        )

    def ca_request_portal_login_response(
        request: Request,
        *,
        error: str | None = None,
        status_code: int = 200,
        db: Session | None = None,
    ) -> HTMLResponse:
        """Return ca request portal login response.

        Args:
            request: Incoming HTTP request.
            error: Public-safe error detail to record or return.
            status_code: HTTP status code for the response.
            db: Active database session.
        """
        return render(
            request,
            "ca_request_login.html",
            {
                "error": error,
                "return_to": public_ui_path("/ca/requests"),
                **(public_portal_links_context(db) if db else {}),
            },
            status_code=status_code,
        )

    @public_router.get("/ca/requests", response_class=HTMLResponse, response_model=None)
    def ca_portal_requests_page(
        request: Request,
        identity: Identity | None = Depends(get_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the ca portal requests page endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        if not public_ui_request_allowed(request, db, "/ca/requests"):
            raise HTTPException(
                status_code=404,
                detail="CA public service is not available on this interface",
            )
        if identity is None:
            return ca_request_portal_login_response(
                request,
                error=consume_browser_session_expired_notice(request),
                db=db,
            )
        require_certificate_workflow_identity(identity)
        return render(
            request,
            "ca_request_portal.html",
            {"identity": identity, **ca_request_context(db)},
        )

    @public_router.post("/ca/requests/login", response_model=None)
    def ca_request_portal_login(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
        csrf: str = Form(...),
        next: str = Form(PUBLIC_UI_ROOT + "/ca/requests"),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse:
        """Handle the ca request portal login endpoint.

        Args:
            request: Incoming HTTP request.
            username: Account name used for authentication or lookup.
            password: Password supplied for the immediate authenticated operation.
            csrf: Validated CSRF token authorizing the request.
            next: Relative destination requested after authentication.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        if not public_ui_request_allowed(request, db, "/ca/requests"):
            raise HTTPException(
                status_code=404,
                detail="CA public service is not available on this interface",
            )
        return authenticate_ca_portal_session(
            request,
            db,
            username=username,
            password=password,
            csrf=csrf,
            next_path=safe_public_return_path(next, default="/ca/requests"),
            failure_response=lambda failed_request, *, error=None, status_code=200: (
                ca_request_portal_login_response(
                    failed_request,
                    error=error,
                    status_code=status_code,
                    db=db,
                )
            ),
        )

    @public_router.post("/ca/requests/logout", response_model=None)
    def ca_request_portal_logout(
        request: Request,
        csrf: str = Form(...),
        next: str = Form(PUBLIC_UI_ROOT + "/ca/requests"),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Handle the ca request portal logout endpoint.

        Args:
            request: Incoming HTTP request.
            csrf: Validated CSRF token authorizing the request.
            next: Relative destination requested after authentication.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        end_browser_session(request, db)
        return RedirectResponse(
            safe_public_return_path(next, default="/ca/requests"), status_code=303
        )

    def _stage_ca_certificate_request(
        db: Session,
        *,
        common_name: str,
        profile_id: str,
        subject_alt_names: str,
        ip_addresses: str,
        description: str,
        csr_text: str,
    ) -> CaCertificate:
        """Return stage ca certificate request.

        Args:
            db: Active database session.
            common_name: Certificate subject common name.
            profile_id: Identifier of the profile.
            subject_alt_names: Subject alt names supplied by the caller.
            ip_addresses: Ip addresses supplied by the caller.
            description: Human-readable description of the resource.
            csr_text: Csr text supplied by the caller.
        """
        certificate = CaCertificate(
            common_name=common_name.strip(),
            profile_id=parse_ca_profile_id(profile_id),
            subject_alt_names=join_multiline(split_multiline(subject_alt_names)),
            ip_addresses=join_multiline(split_multiline(ip_addresses)),
            status="csr-staged" if csr_text.strip() else "planned",
            description=description or None,
            csr_text=csr_text.strip() or None,
            enabled=True,
        )
        db.add(certificate)
        db.commit()
        return certificate

    def _revoke_ca_certificate(
        db: Session, *, certificate_id: int, actor: str, reason: str
    ) -> CaCertificate:
        """Return revoke ca certificate.

        Args:
            db: Active database session.
            certificate_id: Identifier of the certificate.
            actor: Authenticated identity attributed to the audit record.
            reason: Reason supplied by the caller.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        certificate = db.get(CaCertificate, certificate_id)
        if not certificate:
            raise HTTPException(status_code=404, detail="CA certificate not found")
        if certificate.status != "issued" or not certificate.serial_number:
            raise HTTPException(
                status_code=400,
                detail="Only issued certificates with a serial number can be revoked.",
            )
        certificate.status = "revoked"
        certificate.revoked_at = utcnow()
        certificate.revoked_by = actor
        certificate.revocation_reason = reason.strip() or "operator requested"
        db.add(certificate)
        db.commit()
        return certificate

    @ca_router.post("/ca/requests", response_model=None)
    def submit_ca_request_from_portal(
        request: Request,
        common_name: str = Form(...),
        profile_id: str = Form(""),
        subject_alt_names: str = Form(""),
        ip_addresses: str = Form(""),
        description: str = Form(""),
        csr_text: str = Form(""),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse:
        """Handle the submit ca request from portal endpoint.

        Args:
            request: Incoming HTTP request.
            common_name: Certificate subject common name.
            profile_id: Identifier of the profile.
            subject_alt_names: Subject alt names supplied by the caller.
            ip_addresses: Ip addresses supplied by the caller.
            description: Human-readable description of the resource.
            csr_text: Csr text supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        require_certificate_workflow_identity(identity)
        verify_csrf(request, csrf)
        if not common_name.strip():
            return render(
                request,
                "ca_requests.html",
                {
                    "identity": identity,
                    **ca_request_context(db),
                    "form_error": "Common name is required.",
                },
                status_code=422,
            )
        certificate = _stage_ca_certificate_request(
            db,
            common_name=common_name,
            profile_id=profile_id,
            subject_alt_names=subject_alt_names,
            ip_addresses=ip_addresses,
            description=description,
            csr_text=csr_text,
        )
        record_audit(
            db,
            actor=identity.username,
            action="submit_ca_certificate_request",
            resource_type="ca_certificate",
            resource_id=str(certificate.id),
        )
        return RedirectResponse("/ca/requests", status_code=303)

    @public_router.post("/ca/requests", response_model=None)
    def submit_ca_request_from_portal_alias(
        request: Request,
        common_name: str = Form(...),
        profile_id: str = Form(""),
        subject_alt_names: str = Form(""),
        ip_addresses: str = Form(""),
        description: str = Form(""),
        csr_text: str = Form(""),
        csrf: str = Form(...),
        identity: Identity | None = Depends(get_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse:
        """Handle the submit ca request from portal alias endpoint.

        Args:
            request: Incoming HTTP request.
            common_name: Certificate subject common name.
            profile_id: Identifier of the profile.
            subject_alt_names: Subject alt names supplied by the caller.
            ip_addresses: Ip addresses supplied by the caller.
            description: Human-readable description of the resource.
            csr_text: Csr text supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        if not public_ui_request_allowed(request, db, "/ca/requests"):
            raise HTTPException(
                status_code=404,
                detail="CA public service is not available on this interface",
            )
        if identity is None:
            return ca_request_portal_login_response(request, status_code=401)
        require_certificate_workflow_identity(identity)
        verify_csrf(request, csrf)
        if not common_name.strip():
            return render(
                request,
                "ca_request_portal.html",
                {
                    "identity": identity,
                    **ca_request_context(db),
                    "form_error": "Common name is required.",
                },
                status_code=422,
            )
        certificate = _stage_ca_certificate_request(
            db,
            common_name=common_name,
            profile_id=profile_id,
            subject_alt_names=subject_alt_names,
            ip_addresses=ip_addresses,
            description=description,
            csr_text=csr_text,
        )
        record_audit(
            db,
            actor=identity.username,
            action="submit_ca_certificate_request",
            resource_type="ca_certificate",
            resource_id=str(certificate.id),
        )
        return RedirectResponse(public_ui_path("/ca/requests"), status_code=303)

    @ca_router.post("/ca/certificates/{certificate_id}/revoke", response_model=None)
    def revoke_ca_certificate_from_portal(
        request: Request,
        certificate_id: int,
        reason: str = Form("operator requested"),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse:
        """Handle the revoke ca certificate from portal endpoint.

        Args:
            request: Incoming HTTP request.
            certificate_id: Identifier of the certificate.
            reason: Reason supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        require_certificate_workflow_identity(identity)
        verify_csrf(request, csrf)
        certificate = _revoke_ca_certificate(
            db, certificate_id=certificate_id, actor=identity.username, reason=reason
        )
        record_audit(
            db,
            actor=identity.username,
            action="revoke_ca_certificate",
            resource_type="ca_certificate",
            resource_id=str(certificate.id),
        )
        return RedirectResponse("/ca/requests", status_code=303)

    @public_router.post(
        "/ca/requests/certificates/{certificate_id}/revoke", response_model=None
    )
    def revoke_ca_certificate_from_portal_alias(
        request: Request,
        certificate_id: int,
        reason: str = Form("operator requested"),
        csrf: str = Form(...),
        identity: Identity | None = Depends(get_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse:
        """Handle the revoke ca certificate from portal alias endpoint.

        Args:
            request: Incoming HTTP request.
            certificate_id: Identifier of the certificate.
            reason: Reason supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        if not public_ui_request_allowed(request, db, "/ca/requests"):
            raise HTTPException(
                status_code=404,
                detail="CA public service is not available on this interface",
            )
        if identity is None:
            return ca_request_portal_login_response(request, status_code=401)
        require_certificate_workflow_identity(identity)
        verify_csrf(request, csrf)
        certificate = _revoke_ca_certificate(
            db, certificate_id=certificate_id, actor=identity.username, reason=reason
        )
        record_audit(
            db,
            actor=identity.username,
            action="revoke_ca_certificate",
            resource_type="ca_certificate",
            resource_id=str(certificate.id),
        )
        return RedirectResponse(public_ui_path("/ca/requests"), status_code=303)

    @protocol_router.get(
        "/certificate-authority/downloads/root-ca.pem", response_model=None
    )
    def download_root_ca(
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the download root ca endpoint.

        Args:
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        ensure_ca_state(db)
        settings = get_ca_settings_row(db)
        if not settings.root_certificate_pem:
            changed = ensure_root_ca_material(settings)
            if changed:
                db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="download_ca_root_certificate",
            resource_type="ca",
            resource_id=str(settings.id),
        )
        return Response(
            settings.root_certificate_pem.encode("utf-8"),
            media_type="application/x-pem-file",
            headers={
                "Content-Disposition": 'attachment; filename="atlaso-root-ca.pem"'
            },
        )

    @protocol_router.get(
        "/certificate-authority/downloads/ca-bundle.pem", response_model=None
    )
    def download_ca_bundle(
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the download ca bundle endpoint.

        Args:
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        ensure_ca_state(db)
        settings = get_ca_settings_row(db)
        if not settings.root_certificate_pem:
            changed = ensure_root_ca_material(settings)
            if changed:
                db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="download_ca_bundle",
            resource_type="ca",
            resource_id=str(settings.id),
        )
        return Response(
            settings.root_certificate_pem.encode("utf-8"),
            media_type="application/x-pem-file",
            headers={
                "Content-Disposition": 'attachment; filename="atlaso-ca-bundle.pem"'
            },
        )

    def get_exportable_ca_certificate(
        db: Session, certificate_id: int
    ) -> CaCertificate:
        """Return exportable ca certificate.

        Args:
            db: Active database session.
            certificate_id: Identifier of the certificate.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        ensure_ca_state(db)
        certificate = db.get(CaCertificate, certificate_id)
        if not certificate:
            raise HTTPException(status_code=404, detail="CA certificate not found")
        if certificate.status != "issued" or not certificate.certificate_pem:
            raise HTTPException(
                status_code=404, detail="CA certificate has not been issued"
            )
        return certificate

    @protocol_router.get(
        "/certificate-authority/certificates/{certificate_id}/downloads/certificate.pem",
        response_model=None,
    )
    def download_ca_certificate(
        certificate_id: int,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the download ca certificate endpoint.

        Args:
            certificate_id: Identifier of the certificate.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        certificate = get_exportable_ca_certificate(db, certificate_id)
        record_audit(
            db,
            actor=identity.username,
            action="download_ca_certificate",
            resource_type="ca_certificate",
            resource_id=str(certificate.id),
        )
        filename = f"{safe_certificate_name(certificate.common_name)}.crt"
        return Response(
            certificate.certificate_pem.encode("utf-8"),
            media_type="application/x-pem-file",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @protocol_router.get(
        "/certificate-authority/certificates/{certificate_id}/downloads/chain.pem",
        response_model=None,
    )
    def download_ca_certificate_chain(
        certificate_id: int,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the download ca certificate chain endpoint.

        Args:
            certificate_id: Identifier of the certificate.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        certificate = get_exportable_ca_certificate(db, certificate_id)
        chain = certificate.chain_pem or certificate.certificate_pem
        record_audit(
            db,
            actor=identity.username,
            action="download_ca_certificate_chain",
            resource_type="ca_certificate",
            resource_id=str(certificate.id),
        )
        filename = f"{safe_certificate_name(certificate.common_name)}-chain.pem"
        return Response(
            chain.encode("utf-8"),
            media_type="application/x-pem-file",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @protocol_router.get(
        "/certificate-authority/certificates/{certificate_id}/downloads/private-key.pem",
        response_model=None,
    )
    def download_ca_certificate_private_key(
        certificate_id: int,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Handle the download ca certificate private key endpoint.

        Args:
            certificate_id: Identifier of the certificate.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        certificate = get_exportable_ca_certificate(db, certificate_id)
        if not certificate.private_key_encrypted:
            raise HTTPException(
                status_code=404,
                detail="No Atlaso-generated private key is available for this certificate",
            )
        private_key = decrypt_secret(certificate.private_key_encrypted)
        record_audit(
            db,
            actor=identity.username,
            action="download_ca_certificate_private_key",
            resource_type="ca_certificate",
            resource_id=str(certificate.id),
        )
        filename = f"{safe_certificate_name(certificate.common_name)}.key"
        return Response(
            private_key.encode("utf-8"),
            media_type="application/x-pem-file",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @ca_router.post("/certificate-authority/settings", response_model=None)
    def update_ca_settings_from_ui(
        request: Request,
        enabled: str | None = Form(None),
        portal_hostname: str = Form(""),
        listen_interfaces: list[str] = Form(default_factory=list),
        listen_addresses: list[str] = Form(default_factory=list),
        listen_interfaces_present: str | None = Form(None),
        listen_addresses_present: str | None = Form(None),
        root_common_name: str = Form(...),
        organization: str = Form(...),
        organizational_unit: str = Form(""),
        country: str = Form("US"),
        state: str = Form(""),
        locality: str = Form(""),
        key_algorithm: str = Form("RSA"),
        key_size: int = Form(4096),
        digest_algorithm: str = Form("sha256"),
        root_valid_days: int = Form(3650),
        intermediate_valid_days: int = Form(1825),
        publish_crl: str | None = Form(None),
        ocsp_enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the update ca settings from ui endpoint.

        Args:
            request: Incoming HTTP request.
            enabled: Whether the requested behavior is enabled.
            portal_hostname: Portal hostname supplied by the caller.
            listen_interfaces: Interfaces on which the service should listen.
            listen_addresses: Addresses on which the service should listen.
            listen_interfaces_present: Whether the caller supplied listen interfaces.
            listen_addresses_present: Whether the caller supplied listen addresses.
            root_common_name: Root common name supplied by the caller.
            organization: Managed identity organization affected by the operation.
            organizational_unit: Organizational unit supplied by the caller.
            country: Country supplied by the caller.
            state: Lifecycle or job state to persist.
            locality: Locality supplied by the caller.
            key_algorithm: Key algorithm supplied by the caller.
            key_size: Key size supplied by the caller.
            digest_algorithm: Digest algorithm supplied by the caller.
            root_valid_days: Root valid days supplied by the caller.
            intermediate_valid_days: Intermediate valid days supplied by the caller.
            publish_crl: Publish crl supplied by the caller.
            ocsp_enabled: Ocsp enabled supplied by the caller.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        settings = get_ca_settings_row(db)
        previous_portal_hostname = settings.portal_hostname
        selected_interfaces, selected_addresses = resolve_service_bind_targets(
            db,
            listen_interfaces,
            listen_addresses,
            current_interface=settings.listen_interface,
            current_address=settings.listen_address,
            listen_interfaces_present=listen_interfaces_present,
            listen_addresses_present=listen_addresses_present,
        )
        settings.enabled = enabled == "on"
        settings.portal_hostname = normalize_dns_hostname(
            portal_hostname.strip() or settings.portal_hostname
        )
        settings.listen_interface = selected_interfaces
        settings.listen_address = selected_addresses
        settings.root_common_name = root_common_name.strip()
        settings.organization = organization.strip()
        settings.organizational_unit = organizational_unit.strip()
        settings.country = country.strip().upper()
        settings.state = state.strip()
        settings.locality = locality.strip()
        settings.key_algorithm = key_algorithm.strip().upper()
        settings.key_size = key_size
        settings.digest_algorithm = digest_algorithm.strip().lower()
        settings.root_valid_days = root_valid_days
        settings.intermediate_valid_days = intermediate_valid_days
        settings.publish_crl = publish_crl == "on"
        settings.ocsp_enabled = ocsp_enabled == "on"
        settings.storage_path = settings.storage_path.strip() or "/etc/atlaso/ca"
        settings.updated_at = utcnow()
        ensure_dns_for_ca_portal(
            db, settings, identity.username, previous_hostname=previous_portal_hostname
        )
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="update_ca_settings",
            resource_type="ca",
            resource_id=str(settings.id),
        )
        if request.headers.get("X-Atlaso-Autosave") == "1":
            db.refresh(settings)
            context = ca_context(db)
            return JSONResponse(
                {
                    "status": "saved",
                    "updated_at": settings.updated_at.isoformat(),
                    "enabled": settings.enabled,
                    "portal_hostname": settings.portal_hostname,
                    "listen_interfaces": split_interfaces(settings.listen_interface),
                    "listen_addresses": split_addresses(settings.listen_address),
                    "validation_errors": context["ca_validation_errors"],
                    "config_preview": context["ca_config_preview"],
                    "apply_payload": context["ca_apply_payload"],
                }
            )
        return RedirectResponse("/certificate-authority", status_code=303)

    def parse_ca_profile_id(raw_value: str | int | None) -> int | None:
        """Parse ca profile id.

        Args:
            raw_value: Candidate raw value to parse.


        Returns:
            The parsed ca profile id.
        """
        if raw_value in {None, "", "None", "unassigned"}:
            return None
        return int(raw_value)

    @ca_router.post("/certificate-authority/profiles", response_model=None)
    def create_ca_profile_from_ui(
        request: Request,
        name: str = Form(...),
        certificate_type: str = Form("server"),
        validity_days: int = Form(825),
        key_algorithm: str = Form("RSA"),
        key_size: int = Form(2048),
        key_usage: str = Form("digitalSignature,keyEncipherment"),
        extended_key_usage: str = Form("serverAuth"),
        san_required: str | None = Form(None),
        description: str = Form(""),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse | JSONResponse:
        """Handle the create ca profile from ui endpoint.

        Args:
            request: Incoming HTTP request.
            name: Name of the target object.
            certificate_type: Certificate type supplied by the caller.
            validity_days: Validity days supplied by the caller.
            key_algorithm: Key algorithm supplied by the caller.
            key_size: Key size supplied by the caller.
            key_usage: Key usage supplied by the caller.
            extended_key_usage: Extended key usage supplied by the caller.
            san_required: San required supplied by the caller.
            description: Human-readable description of the resource.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        profile = CaProfile(
            name=name.strip(),
            certificate_type=certificate_type.strip(),
            validity_days=validity_days,
            key_algorithm=key_algorithm.strip().upper(),
            key_size=key_size,
            key_usage=key_usage.strip(),
            extended_key_usage=extended_key_usage.strip(),
            san_required=san_required == "on",
            description=description or None,
            enabled=enabled == "on",
        )
        db.add(profile)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            detail = f"CA profile {name} already exists."
            return grid_error_response(
                request,
                detail=detail,
                status_code=409,
                template_name="certificate_authority.html",
                context={"identity": identity, **ca_context(db), "form_error": detail},
            )
        record_audit(
            db,
            actor=identity.username,
            action="create_ca_profile",
            resource_type="ca_profile",
            resource_id=str(profile.id),
        )
        return grid_saved_response(
            request,
            redirect_url="/certificate-authority",
            resource_name="profile",
            resource=ca_profile_to_dict(profile),
        )

    @ca_router.post(
        "/certificate-authority/profiles/{profile_id}/edit", response_model=None
    )
    def edit_ca_profile_from_ui(
        request: Request,
        profile_id: int,
        name: str = Form(...),
        certificate_type: str = Form("server"),
        validity_days: int = Form(825),
        key_algorithm: str = Form("RSA"),
        key_size: int = Form(2048),
        key_usage: str = Form("digitalSignature,keyEncipherment"),
        extended_key_usage: str = Form("serverAuth"),
        san_required: str | None = Form(None),
        description: str = Form(""),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse | JSONResponse:
        """Handle the edit ca profile from ui endpoint.

        Args:
            request: Incoming HTTP request.
            profile_id: Identifier of the profile.
            name: Name of the target object.
            certificate_type: Certificate type supplied by the caller.
            validity_days: Validity days supplied by the caller.
            key_algorithm: Key algorithm supplied by the caller.
            key_size: Key size supplied by the caller.
            key_usage: Key usage supplied by the caller.
            extended_key_usage: Extended key usage supplied by the caller.
            san_required: San required supplied by the caller.
            description: Human-readable description of the resource.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        profile = db.get(CaProfile, profile_id)
        if not profile:
            raise HTTPException(status_code=404, detail="CA profile not found")
        profile.name = name.strip()
        profile.certificate_type = certificate_type.strip()
        profile.validity_days = validity_days
        profile.key_algorithm = key_algorithm.strip().upper()
        profile.key_size = key_size
        profile.key_usage = key_usage.strip()
        profile.extended_key_usage = extended_key_usage.strip()
        profile.san_required = san_required == "on"
        profile.description = description or None
        profile.enabled = enabled == "on"
        profile.updated_at = utcnow()
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            detail = f"CA profile {name} already exists."
            return grid_error_response(
                request,
                detail=detail,
                status_code=409,
                template_name="certificate_authority.html",
                context={"identity": identity, **ca_context(db), "form_error": detail},
            )
        record_audit(
            db,
            actor=identity.username,
            action="update_ca_profile",
            resource_type="ca_profile",
            resource_id=str(profile.id),
        )
        return grid_saved_response(
            request,
            redirect_url="/certificate-authority",
            resource_name="profile",
            resource=ca_profile_to_dict(profile),
        )

    @ca_router.post(
        "/certificate-authority/profiles/{profile_id}/delete", response_model=None
    )
    def delete_ca_profile_from_ui(
        request: Request,
        profile_id: int,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | Response:
        """Handle the delete ca profile from ui endpoint.

        Args:
            request: Incoming HTTP request.
            profile_id: Identifier of the profile.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        profile = db.get(CaProfile, profile_id)
        if not profile:
            raise HTTPException(status_code=404, detail="CA profile not found")
        for certificate in (
            db.execute(
                select(CaCertificate).where(CaCertificate.profile_id == profile_id)
            )
            .scalars()
            .all()
        ):
            certificate.profile_id = None
        db.delete(profile)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_ca_profile",
            resource_type="ca_profile",
            resource_id=str(profile_id),
        )
        if grid_request(request):
            return Response(status_code=204)
        return RedirectResponse("/certificate-authority", status_code=303)

    @ca_router.post("/certificate-authority/certificates", response_model=None)
    def create_ca_certificate_from_ui(
        request: Request,
        common_name: str = Form(...),
        profile_id: str = Form(""),
        subject_alt_names: str = Form(""),
        ip_addresses: str = Form(""),
        description: str = Form(""),
        csr_text: str = Form(""),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the create ca certificate from ui endpoint.

        Args:
            request: Incoming HTTP request.
            common_name: Certificate subject common name.
            profile_id: Identifier of the profile.
            subject_alt_names: Subject alt names supplied by the caller.
            ip_addresses: Ip addresses supplied by the caller.
            description: Human-readable description of the resource.
            csr_text: Csr text supplied by the caller.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        try:
            parsed_profile_id = parse_ca_profile_id(profile_id)
        except TypeError, ValueError:
            raise HTTPException(
                status_code=422, detail="Select an enabled CA profile."
            ) from None
        profile = (
            db.get(CaProfile, parsed_profile_id)
            if parsed_profile_id is not None
            else None
        )
        validation_errors = validate_ca_certificate_request(
            profile=profile,
            common_name=common_name,
            subject_alt_names=subject_alt_names,
            ip_addresses=ip_addresses,
        )
        if validation_errors:
            raise HTTPException(status_code=422, detail=" ".join(validation_errors))
        normalized_csr = csr_text.strip()
        certificate = CaCertificate(
            common_name=common_name.strip(),
            profile_id=parsed_profile_id,
            subject_alt_names=join_multiline(split_multiline(subject_alt_names)),
            ip_addresses=join_multiline(split_multiline(ip_addresses)),
            status="csr-staged" if normalized_csr else "planned",
            description=description or None,
            csr_text=normalized_csr or None,
            enabled=enabled == "on",
        )
        db.add(certificate)
        db.commit()
        db.refresh(certificate)
        record_audit(
            db,
            actor=identity.username,
            action="create_ca_certificate_request",
            resource_type="ca_certificate",
            resource_id=str(certificate.id),
        )
        return grid_saved_response(
            request,
            redirect_url="/certificate-authority",
            resource_name="certificate",
            resource=ca_certificate_to_dict(certificate),
        )

    @ca_router.post(
        "/certificate-authority/certificates/{certificate_id}/edit", response_model=None
    )
    def edit_ca_certificate_from_ui(
        request: Request,
        certificate_id: int,
        common_name: str = Form(...),
        profile_id: str = Form(""),
        subject_alt_names: str = Form(""),
        ip_addresses: str = Form(""),
        description: str = Form(""),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the edit ca certificate from ui endpoint.

        Args:
            request: Incoming HTTP request.
            certificate_id: Identifier of the certificate.
            common_name: Certificate subject common name.
            profile_id: Identifier of the profile.
            subject_alt_names: Subject alt names supplied by the caller.
            ip_addresses: Ip addresses supplied by the caller.
            description: Human-readable description of the resource.
            enabled: Whether the requested behavior is enabled.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        certificate = db.get(CaCertificate, certificate_id)
        if not certificate:
            raise HTTPException(
                status_code=404, detail="CA certificate request not found"
            )
        if not ca_certificate_can_edit(certificate):
            raise HTTPException(
                status_code=409,
                detail="Only unissued manual certificate requests can be edited.",
            )
        try:
            parsed_profile_id = parse_ca_profile_id(profile_id)
        except TypeError, ValueError:
            raise HTTPException(
                status_code=422, detail="Select an enabled CA profile."
            ) from None
        profile = (
            db.get(CaProfile, parsed_profile_id)
            if parsed_profile_id is not None
            else None
        )
        validation_errors = validate_ca_certificate_request(
            profile=profile,
            common_name=common_name,
            subject_alt_names=subject_alt_names,
            ip_addresses=ip_addresses,
        )
        if validation_errors:
            raise HTTPException(status_code=422, detail=" ".join(validation_errors))
        certificate.common_name = common_name.strip()
        certificate.profile_id = parsed_profile_id
        certificate.subject_alt_names = join_multiline(
            split_multiline(subject_alt_names)
        )
        certificate.ip_addresses = join_multiline(split_multiline(ip_addresses))
        certificate.description = description or None
        certificate.enabled = enabled == "on"
        db.commit()
        db.refresh(certificate)
        record_audit(
            db,
            actor=identity.username,
            action="update_ca_certificate_request",
            resource_type="ca_certificate",
            resource_id=str(certificate.id),
        )
        return grid_saved_response(
            request,
            redirect_url="/certificate-authority",
            resource_name="certificate",
            resource=ca_certificate_to_dict(certificate),
        )

    @ca_router.post(
        "/certificate-authority/certificates/{certificate_id}/delete",
        response_model=None,
    )
    def delete_ca_certificate_from_ui(
        request: Request,
        certificate_id: int,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | Response:
        """Handle the delete ca certificate from ui endpoint.

        Args:
            request: Incoming HTTP request.
            certificate_id: Identifier of the certificate.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.

        Raises:
            HTTPException: If the request cannot be fulfilled.
        """
        verify_csrf(request, csrf)
        certificate = db.get(CaCertificate, certificate_id)
        if not certificate:
            raise HTTPException(
                status_code=404, detail="CA certificate request not found"
            )
        if not ca_certificate_can_delete(certificate):
            raise HTTPException(
                status_code=409,
                detail="Service-owned certificates must be managed from their owning service.",
            )
        db.delete(certificate)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_ca_certificate_request",
            resource_type="ca_certificate",
            resource_id=str(certificate_id),
        )
        if grid_request(request):
            return Response(status_code=204)
        return RedirectResponse("/certificate-authority", status_code=303)

    @kms_router.get(
        "/vsphere-key-providers", response_class=HTMLResponse, response_model=None
    )
    def kms_page(
        request: Request,
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> HTMLResponse:
        """Handle the kms page endpoint.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        return render(
            request,
            "kms.html",
            {
                "identity": identity,
                **kms_context(db),
                "appliance_apply_status": appliance_apply_status(db, "kms"),
            },
        )

    @kms_router.get(
        "/vsphere-key-providers/server-certificate.pem", response_model=None
    )
    def download_vsphere_key_provider_server_chain(
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> Response:
        """Download the public appliance-wide KMIP server certificate chain.

        Args:
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            Public PEM certificate-chain attachment.
        """
        certificate = (
            db.execute(
                select(CaCertificate)
                .where(CaCertificate.managed_owner == "kms:server")
                .order_by(CaCertificate.id.desc())
            )
            .scalars()
            .first()
        )
        if certificate is None or not certificate.certificate_pem:
            raise HTTPException(
                status_code=404,
                detail="The public server certificate chain is not available.",
            )
        chain = certificate.chain_pem or certificate.certificate_pem
        record_audit(
            db,
            actor=identity.username,
            action="download_vsphere_key_provider_server_chain",
            resource_type="vsphere_key_provider_settings",
            resource_id="server-certificate",
            detail="public_chain=true",
        )
        return Response(
            chain.encode("utf-8"),
            media_type="application/x-pem-file",
            headers={
                "Cache-Control": "no-store",
                "Content-Disposition": 'attachment; filename="atlaso-kmip-server-chain.pem"',
            },
        )

    @kms_router.post("/vsphere-key-providers/settings", response_model=None)
    def update_kms_settings_from_ui(
        request: Request,
        enabled: str | None = Form(None),
        listen_interfaces: list[str] = Form(default_factory=list),
        listen_addresses: list[str] = Form(default_factory=list),
        listen_interfaces_present: str | None = Form(None),
        listen_addresses_present: str | None = Form(None),
        port: int = Form(5696),
        hostname: str = Form(""),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | JSONResponse:
        """Handle the update kms settings from ui endpoint.

        Args:
            request: Incoming HTTP request.
            enabled: Whether the requested behavior is enabled.
            listen_interfaces: Interfaces on which the service should listen.
            listen_addresses: Addresses on which the service should listen.
            listen_interfaces_present: Whether the caller supplied listen interfaces.
            listen_addresses_present: Whether the caller supplied listen addresses.
            port: TCP or UDP port of the target service.
            hostname: DNS hostname of the target resource.
            csrf: Validated CSRF token authorizing the request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.

        Returns:
            The endpoint response.
        """
        verify_csrf(request, csrf)
        settings = get_kms_settings_row(db)
        previous_hostname = settings.hostname
        selected_interfaces, selected_addresses = resolve_service_bind_targets(
            db,
            listen_interfaces,
            listen_addresses,
            current_interface=settings.listen_interface,
            current_address=settings.listen_address,
            listen_interfaces_present=listen_interfaces_present,
            listen_addresses_present=listen_addresses_present,
        )
        settings.enabled = enabled == "on"
        settings.backend = "atlaso-kmip"
        settings.listen_interface = selected_interfaces
        settings.listen_address = selected_addresses
        settings.port = port
        try:
            settings.hostname = normalize_vsphere_service_hostname(
                hostname.strip() or settings.hostname
            )
        except ValueError:
            raise HTTPException(
                status_code=422,
                detail="vSphere Key Provider hostname must be a valid fully qualified DNS name.",
            ) from None
        settings.server_certificate = settings.hostname
        settings.ca_certificate_path = (
            settings.ca_certificate_path.strip() or "/etc/atlaso/ca/root.crt"
        )
        settings.database_path = KMS_DEFAULT_DATABASE_PATH
        settings.config_path = KMS_DEFAULT_CONFIG_PATH
        settings.require_client_cert = True
        settings.allow_register = False
        settings.allow_destroy = False
        settings.updated_at = utcnow()
        if settings.enabled:
            ensure_dns_for_kms(
                db, settings, identity.username, previous_hostname=previous_hostname
            )
            ensure_ca_state(db)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="update_kms_settings",
            resource_type="kms",
            resource_id=str(settings.id),
        )
        if request.headers.get("X-Atlaso-Autosave") == "1":
            context = kms_context(db)
            saved_settings = context["kms_settings"]
            return JSONResponse(
                {
                    "status": "saved",
                    "updated_at": saved_settings.updated_at.isoformat(),
                    "enabled": saved_settings.enabled,
                    "listen_interface": primary_listen_interface(
                        saved_settings.listen_interface
                    ),
                    "listen_address": primary_listen_address(
                        saved_settings.listen_address
                    ),
                    "listen_interfaces": split_interfaces(
                        saved_settings.listen_interface
                    ),
                    "listen_addresses": split_addresses(saved_settings.listen_address),
                    "port": saved_settings.port,
                    "hostname": saved_settings.hostname,
                    "server_certificate": saved_settings.server_certificate,
                    "valid": not context["kms_validation_errors"],
                    "validation_errors": context["kms_validation_errors"],
                    "config_path": KMS_DEFAULT_CONFIG_PATH,
                    "config_preview": context["kms_config_preview"],
                }
            )
        return RedirectResponse(
            management_ui_path("/vsphere-key-providers"), status_code=303
        )

    def _vsphere_grid_error(
        request: Request,
        identity: Identity,
        db: Session,
        detail: str,
        status_code: int = 409,
    ) -> HTMLResponse | JSONResponse:
        """Return a consistent provider-management browser error.

        Args:
            request: Incoming HTTP request.
            identity: Authenticated identity authorizing the request.
            db: Active database session.
            detail: Public error detail.
            status_code: HTTP status code returned to the browser.
        """
        return grid_error_response(
            request,
            detail=detail,
            status_code=status_code,
            template_name="kms.html",
            context={
                "identity": identity,
                **kms_context(db),
                "appliance_apply_status": appliance_apply_status(db, "kms"),
                "form_error": detail,
            },
        )

    @kms_router.post("/vsphere-key-providers/providers", response_model=None)
    def create_vsphere_provider_from_ui(
        request: Request,
        name: str = Form(...),
        description: str = Form(""),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse | JSONResponse:
        """Create a provider namespace from the shared browser wizard.

        Args:
            request: Incoming HTTP request.
            name: Unique provider name.
            description: Operator-facing provider purpose.
            enabled: Submitted desired-state enablement.
            csrf: Validated CSRF token.
            identity: Authenticated identity authorizing the request.
            db: Active database session.
        """
        verify_csrf(request, csrf)
        provider = VsphereKeyProvider(
            id=str(uuid4()),
            name=name.strip(),
            description=description.strip(),
            enabled=enabled == "on",
        )
        db.add(provider)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return _vsphere_grid_error(
                request, identity, db, "Provider name already exists."
            )
        record_audit(
            db,
            actor=identity.username,
            action="create_vsphere_key_provider",
            resource_type="vsphere_key_provider",
            resource_id=provider.id,
            detail=f"name={provider.name}; enabled={provider.enabled}",
        )
        refreshed = next(item for item in provider_rows(db) if item.id == provider.id)
        return grid_saved_response(
            request,
            redirect_url=management_ui_path("/vsphere-key-providers"),
            resource_name="provider",
            resource=provider_to_dict(refreshed),
        )

    @kms_router.post(
        "/vsphere-key-providers/providers/{provider_id}/edit", response_model=None
    )
    def edit_vsphere_provider_from_ui(
        request: Request,
        provider_id: str,
        name: str = Form(...),
        description: str = Form(""),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse | JSONResponse:
        """Update a provider namespace from the shared browser wizard.

        Args:
            request: Incoming HTTP request.
            provider_id: Immutable provider UUID.
            name: Unique provider name.
            description: Operator-facing provider purpose.
            enabled: Submitted desired-state enablement.
            csrf: Validated CSRF token.
            identity: Authenticated identity authorizing the request.
            db: Active database session.
        """
        verify_csrf(request, csrf)
        provider = db.get(VsphereKeyProvider, provider_id)
        if provider is None:
            raise HTTPException(
                status_code=404, detail="vSphere Key Provider not found."
            )
        provider.name = name.strip()
        provider.description = description.strip()
        provider.enabled = enabled == "on"
        provider.updated_at = utcnow()
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return _vsphere_grid_error(
                request, identity, db, "Provider name already exists."
            )
        record_audit(
            db,
            actor=identity.username,
            action="update_vsphere_key_provider",
            resource_type="vsphere_key_provider",
            resource_id=provider.id,
            detail=f"name={provider.name}; enabled={provider.enabled}",
        )
        refreshed = next(item for item in provider_rows(db) if item.id == provider.id)
        return grid_saved_response(
            request,
            redirect_url=management_ui_path("/vsphere-key-providers"),
            resource_name="provider",
            resource=provider_to_dict(refreshed),
        )

    @kms_router.post(
        "/vsphere-key-providers/providers/{provider_id}/delete", response_model=None
    )
    def delete_vsphere_provider_from_ui(
        request: Request,
        provider_id: str,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse | JSONResponse | Response:
        """Delete an applied-disabled, detached, verified-empty provider namespace.

        Args:
            request: Incoming HTTP request.
            provider_id: Immutable provider UUID.
            csrf: Validated CSRF token.
            identity: Authenticated identity authorizing the request.
            db: Active database session.
        """
        verify_csrf(request, csrf)
        provider = next(
            (item for item in provider_rows(db) if item.id == provider_id), None
        )
        if provider is None:
            raise HTTPException(
                status_code=404, detail="vSphere Key Provider not found."
            )
        if provider.enabled or provider.trusted_vcenters:
            return _vsphere_grid_error(
                request,
                identity,
                db,
                "Disable the provider and detach every trusted vCenter before deletion.",
            )
        if provider_requires_appliance_apply(provider):
            return _vsphere_grid_error(
                request,
                identity,
                db,
                "Apply the disabled and detached provider state before deletion.",
            )
        snapshot = runtime_status_snapshot()
        counts = authenticated_provider_counts(snapshot, provider.id)
        if counts is None or counts.get("total") != 0:
            return _vsphere_grid_error(
                request,
                identity,
                db,
                "Authenticated zero-key runtime evidence is required before deletion.",
            )
        name = provider.name
        db.delete(provider)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_vsphere_key_provider",
            resource_type="vsphere_key_provider",
            resource_id=provider_id,
            detail=f"name={name}; verified_empty=true",
        )
        if grid_request(request):
            return Response(status_code=204)
        return RedirectResponse(
            management_ui_path("/vsphere-key-providers"), status_code=303
        )

    def _vsphere_vcenter_row(
        db: Session, provider_id: str, vcenter_id: str
    ) -> VsphereTrustedVcenter:
        """Return a browser provider-scoped vCenter record.

        Args:
            db: Active database session.
            provider_id: Immutable provider UUID.
            vcenter_id: Immutable trusted-vCenter UUID.
        """
        provider = next(
            (item for item in provider_rows(db) if item.id == provider_id), None
        )
        if provider is None:
            raise HTTPException(
                status_code=404, detail="vSphere Key Provider not found."
            )
        vcenter = next(
            (item for item in provider.trusted_vcenters if item.id == vcenter_id), None
        )
        if vcenter is None:
            raise HTTPException(status_code=404, detail="Trusted vCenter not found.")
        return vcenter

    def _attach_vsphere_public_certificate(
        db: Session,
        vcenter: VsphereTrustedVcenter,
        certificate_pem: str,
    ) -> VsphereTrustedVcenterCertificate | None:
        """Attach optional public PEM input to a trusted vCenter.

        Args:
            db: Active database session.
            vcenter: Provider-scoped trusted-vCenter record.
            certificate_pem: Optional public X.509 PEM certificate.
        """
        if not certificate_pem.strip():
            return None
        parsed = parse_public_certificate(certificate_pem)
        certificate = VsphereTrustedVcenterCertificate(
            id=str(uuid4()),
            trusted_vcenter_id=vcenter.id,
            source="uploaded_public",
            **parsed,
        )
        db.add(certificate)
        return certificate

    @kms_router.post("/vsphere-key-providers/trusted-vcenters", response_model=None)
    def create_vsphere_vcenter_from_ui(
        request: Request,
        provider_id: str = Form(...),
        name: str = Form(...),
        hostname: str = Form(""),
        description: str = Form(""),
        certificate_pem: str = Form(""),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse | JSONResponse:
        """Create a trusted vCenter and its initial public certificate.

        Args:
            request: Incoming HTTP request.
            provider_id: Immutable provider UUID.
            name: Unique trusted-vCenter name within the provider.
            hostname: Operational vCenter hostname label.
            description: Operator-facing trusted-vCenter purpose.
            certificate_pem: Initial public X.509 PEM certificate.
            enabled: Submitted desired-state enablement.
            csrf: Validated CSRF token.
            identity: Authenticated identity authorizing the request.
            db: Active database session.
        """
        verify_csrf(request, csrf)
        provider = db.get(VsphereKeyProvider, provider_id)
        if provider is None:
            raise HTTPException(
                status_code=404, detail="vSphere Key Provider not found."
            )
        try:
            vcenter = VsphereTrustedVcenter(
                id=str(uuid4()),
                provider_id=provider.id,
                name=name.strip(),
                hostname=normalize_vsphere_vcenter_hostname(hostname),
                description=description.strip(),
                enabled=enabled == "on",
            )
            db.add(vcenter)
            db.flush()
            certificate = _attach_vsphere_public_certificate(
                db, vcenter, certificate_pem
            )
            if vcenter.enabled and certificate is None:
                raise ValueError(
                    "An enabled trusted vCenter requires a current public client certificate."
                )
            mark_provider_desired_changed(provider)
            db.commit()
        except ValueError:
            db.rollback()
            return _vsphere_grid_error(
                request,
                identity,
                db,
                "The trusted vCenter details or public certificate are invalid.",
                400,
            )
        except IntegrityError:
            db.rollback()
            return _vsphere_grid_error(
                request,
                identity,
                db,
                "Trusted vCenter name or certificate fingerprint is already assigned.",
            )
        record_audit(
            db,
            actor=identity.username,
            action="create_vsphere_trusted_vcenter",
            resource_type="vsphere_trusted_vcenter",
            resource_id=vcenter.id,
            detail=f"provider_id={provider.id}; name={vcenter.name}; enabled={vcenter.enabled}; public_certificate={bool(certificate)}",
        )
        refreshed = _vsphere_vcenter_row(db, provider.id, vcenter.id)
        return grid_saved_response(
            request,
            redirect_url=management_ui_path("/vsphere-key-providers"),
            resource_name="trusted_vcenter",
            resource=trusted_vcenter_to_dict(refreshed),
            extra={
                "certificates": [
                    certificate_to_dict(item) for item in refreshed.certificates
                ]
            },
        )

    @kms_router.post(
        "/vsphere-key-providers/trusted-vcenters/{vcenter_id}/edit", response_model=None
    )
    def edit_vsphere_vcenter_from_ui(
        request: Request,
        vcenter_id: str,
        provider_id: str = Form(...),
        name: str = Form(...),
        hostname: str = Form(""),
        description: str = Form(""),
        certificate_pem: str = Form(""),
        enabled: str | None = Form(None),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse | JSONResponse:
        """Update a trusted vCenter and optionally add one public certificate.

        Args:
            request: Incoming HTTP request.
            vcenter_id: Immutable trusted-vCenter UUID.
            provider_id: Immutable owning provider UUID.
            name: Unique trusted-vCenter name within the provider.
            hostname: Operational vCenter hostname label.
            description: Operator-facing trusted-vCenter purpose.
            certificate_pem: Optional replacement public X.509 PEM certificate.
            enabled: Submitted desired-state enablement.
            csrf: Validated CSRF token.
            identity: Authenticated identity authorizing the request.
            db: Active database session.
        """
        verify_csrf(request, csrf)
        vcenter = db.get(VsphereTrustedVcenter, vcenter_id)
        if vcenter is None:
            raise HTTPException(status_code=404, detail="Trusted vCenter not found.")
        if vcenter.provider_id != provider_id:
            return _vsphere_grid_error(
                request,
                identity,
                db,
                "A trusted vCenter cannot move between provider namespaces.",
            )
        try:
            vcenter.name = name.strip()
            vcenter.hostname = normalize_vsphere_vcenter_hostname(hostname)
            vcenter.description = description.strip()
            vcenter.enabled = enabled == "on"
            vcenter.updated_at = utcnow()
            certificate = _attach_vsphere_public_certificate(
                db, vcenter, certificate_pem
            )
            if vcenter.enabled and not vcenter.certificates and certificate is None:
                raise ValueError(
                    "An enabled trusted vCenter requires a current public client certificate."
                )
            mark_provider_desired_changed(vcenter.provider)
            db.commit()
        except ValueError:
            db.rollback()
            return _vsphere_grid_error(
                request,
                identity,
                db,
                "The trusted vCenter details or public certificate are invalid.",
                400,
            )
        except IntegrityError:
            db.rollback()
            return _vsphere_grid_error(
                request,
                identity,
                db,
                "Trusted vCenter name or certificate fingerprint is already assigned.",
            )
        record_audit(
            db,
            actor=identity.username,
            action="update_vsphere_trusted_vcenter",
            resource_type="vsphere_trusted_vcenter",
            resource_id=vcenter.id,
            detail=f"provider_id={provider_id}; name={vcenter.name}; enabled={vcenter.enabled}; public_certificate_added={bool(certificate)}",
        )
        refreshed = _vsphere_vcenter_row(db, provider_id, vcenter.id)
        return grid_saved_response(
            request,
            redirect_url=management_ui_path("/vsphere-key-providers"),
            resource_name="trusted_vcenter",
            resource=trusted_vcenter_to_dict(refreshed),
            extra={
                "certificates": [
                    certificate_to_dict(item) for item in refreshed.certificates
                ]
            },
        )

    @kms_router.post(
        "/vsphere-key-providers/trusted-vcenters/{vcenter_id}/delete",
        response_model=None,
    )
    def delete_vsphere_vcenter_from_ui(
        request: Request,
        vcenter_id: str,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse | JSONResponse | Response:
        """Delete a disabled trusted vCenter after certificate retirement.

        Args:
            request: Incoming HTTP request.
            vcenter_id: Immutable trusted-vCenter UUID.
            csrf: Validated CSRF token.
            identity: Authenticated identity authorizing the request.
            db: Active database session.
        """
        verify_csrf(request, csrf)
        vcenter = db.get(VsphereTrustedVcenter, vcenter_id)
        if vcenter is None:
            raise HTTPException(status_code=404, detail="Trusted vCenter not found.")
        provider_id = vcenter.provider_id
        if vcenter.enabled or vcenter.certificates:
            return _vsphere_grid_error(
                request,
                identity,
                db,
                "Disable the trusted vCenter and retire every certificate before deletion.",
            )
        name = vcenter.name
        mark_provider_desired_changed(vcenter.provider)
        db.delete(vcenter)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_vsphere_trusted_vcenter",
            resource_type="vsphere_trusted_vcenter",
            resource_id=vcenter_id,
            detail=f"provider_id={provider_id}; name={name}",
        )
        if grid_request(request):
            return Response(status_code=204)
        return RedirectResponse(
            management_ui_path("/vsphere-key-providers"), status_code=303
        )

    @kms_router.post(
        "/vsphere-key-providers/trusted-vcenters/{vcenter_id}/certificates",
        response_model=None,
    )
    def add_vsphere_certificate_from_ui(
        request: Request,
        vcenter_id: str,
        provider_id: str = Form(...),
        certificate_pem: str = Form(...),
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse | JSONResponse:
        """Add one public certificate to an existing trusted vCenter.

        Args:
            request: Incoming HTTP request.
            vcenter_id: Immutable trusted-vCenter UUID.
            provider_id: Immutable owning provider UUID.
            certificate_pem: Current public X.509 PEM certificate.
            csrf: Validated CSRF token.
            identity: Authenticated identity authorizing the request.
            db: Active database session.
        """
        verify_csrf(request, csrf)
        vcenter = _vsphere_vcenter_row(db, provider_id, vcenter_id)
        try:
            certificate = _attach_vsphere_public_certificate(
                db, vcenter, certificate_pem
            )
            if certificate is None:
                raise ValueError("A public certificate is required.")
            mark_provider_desired_changed(vcenter.provider)
            db.commit()
        except ValueError:
            db.rollback()
            return _vsphere_grid_error(
                request, identity, db, "The public certificate is invalid.", 400
            )
        except IntegrityError:
            db.rollback()
            return _vsphere_grid_error(
                request, identity, db, "Certificate fingerprint is already assigned."
            )
        record_audit(
            db,
            actor=identity.username,
            action="add_vsphere_trusted_certificate",
            resource_type="vsphere_trusted_certificate",
            resource_id=certificate.id,
            detail=f"provider_id={provider_id}; trusted_vcenter_id={vcenter_id}; public_certificate=true",
        )
        refreshed = _vsphere_vcenter_row(db, provider_id, vcenter_id)
        stored = next(
            item for item in refreshed.certificates if item.id == certificate.id
        )
        return grid_saved_response(
            request,
            redirect_url=management_ui_path("/vsphere-key-providers"),
            resource_name="certificate",
            resource=certificate_to_dict(stored),
        )

    @kms_router.post(
        "/vsphere-key-providers/trusted-vcenters/{vcenter_id}/certificates/{certificate_id}/delete",
        response_model=None,
    )
    def retire_vsphere_certificate_from_ui(
        request: Request,
        vcenter_id: str,
        certificate_id: str,
        csrf: str = Form(...),
        identity: Identity = Depends(require_session_identity),
        db: Session = Depends(get_db),
    ) -> RedirectResponse | HTMLResponse | JSONResponse | Response:
        """Retire one exact public certificate trust assignment.

        Args:
            request: Incoming HTTP request.
            vcenter_id: Immutable trusted-vCenter UUID.
            certificate_id: Immutable public-certificate UUID.
            csrf: Validated CSRF token.
            identity: Authenticated identity authorizing the request.
            db: Active database session.
        """
        verify_csrf(request, csrf)
        vcenter = db.get(VsphereTrustedVcenter, vcenter_id)
        if vcenter is None:
            raise HTTPException(status_code=404, detail="Trusted vCenter not found.")
        provider_id = vcenter.provider_id
        certificate = next(
            (item for item in vcenter.certificates if item.id == certificate_id), None
        )
        if certificate is None:
            raise HTTPException(status_code=404, detail="Certificate not found.")
        usable = usable_certificates(vcenter)
        if vcenter.enabled and certificate in usable and len(usable) <= 1:
            return _vsphere_grid_error(
                request,
                identity,
                db,
                "Disable the trusted vCenter before retiring its last usable certificate.",
            )
        mark_provider_desired_changed(vcenter.provider)
        db.delete(certificate)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="retire_vsphere_trusted_certificate",
            resource_type="vsphere_trusted_certificate",
            resource_id=certificate_id,
            detail=f"provider_id={provider_id}; trusted_vcenter_id={vcenter_id}",
        )
        if grid_request(request):
            return Response(status_code=204)
        return RedirectResponse(
            management_ui_path("/vsphere-key-providers"), status_code=303
        )

    return CertificateTrustUiRouters(
        ca_router=ca_router,
        kms_router=kms_router,
        endpoints={
            "certificate_authority_page": certificate_authority_page,
            "public_ca_page": public_ca_page,
            "ca_public_login_response": ca_public_login_response,
            "authenticate_ca_portal_session": authenticate_ca_portal_session,
            "ca_public_login_page": ca_public_login_page,
            "ca_public_login": ca_public_login,
            "public_root_ca_response": public_root_ca_response,
            "download_public_root_ca": download_public_root_ca,
            "download_public_ca_bundle": download_public_ca_bundle,
            "ca_requests_page": ca_requests_page,
            "ca_request_portal_login_response": ca_request_portal_login_response,
            "ca_portal_requests_page": ca_portal_requests_page,
            "ca_request_portal_login": ca_request_portal_login,
            "ca_request_portal_logout": ca_request_portal_logout,
            "_stage_ca_certificate_request": _stage_ca_certificate_request,
            "_revoke_ca_certificate": _revoke_ca_certificate,
            "submit_ca_request_from_portal": submit_ca_request_from_portal,
            "submit_ca_request_from_portal_alias": submit_ca_request_from_portal_alias,
            "revoke_ca_certificate_from_portal": revoke_ca_certificate_from_portal,
            "revoke_ca_certificate_from_portal_alias": revoke_ca_certificate_from_portal_alias,
            "download_root_ca": download_root_ca,
            "download_ca_bundle": download_ca_bundle,
            "get_exportable_ca_certificate": get_exportable_ca_certificate,
            "download_ca_certificate": download_ca_certificate,
            "download_ca_certificate_chain": download_ca_certificate_chain,
            "download_ca_certificate_private_key": download_ca_certificate_private_key,
            "update_ca_settings_from_ui": update_ca_settings_from_ui,
            "parse_ca_profile_id": parse_ca_profile_id,
            "create_ca_profile_from_ui": create_ca_profile_from_ui,
            "edit_ca_profile_from_ui": edit_ca_profile_from_ui,
            "delete_ca_profile_from_ui": delete_ca_profile_from_ui,
            "create_ca_certificate_from_ui": create_ca_certificate_from_ui,
            "edit_ca_certificate_from_ui": edit_ca_certificate_from_ui,
            "delete_ca_certificate_from_ui": delete_ca_certificate_from_ui,
            "kms_page": kms_page,
            "download_vsphere_key_provider_server_chain": download_vsphere_key_provider_server_chain,
            "update_kms_settings_from_ui": update_kms_settings_from_ui,
            "_vsphere_grid_error": _vsphere_grid_error,
            "create_vsphere_provider_from_ui": create_vsphere_provider_from_ui,
            "edit_vsphere_provider_from_ui": edit_vsphere_provider_from_ui,
            "delete_vsphere_provider_from_ui": delete_vsphere_provider_from_ui,
            "_vsphere_vcenter_row": _vsphere_vcenter_row,
            "_attach_vsphere_public_certificate": _attach_vsphere_public_certificate,
            "create_vsphere_vcenter_from_ui": create_vsphere_vcenter_from_ui,
            "edit_vsphere_vcenter_from_ui": edit_vsphere_vcenter_from_ui,
            "delete_vsphere_vcenter_from_ui": delete_vsphere_vcenter_from_ui,
            "add_vsphere_certificate_from_ui": add_vsphere_certificate_from_ui,
            "retire_vsphere_certificate_from_ui": retire_vsphere_certificate_from_ui,
        },
    )
