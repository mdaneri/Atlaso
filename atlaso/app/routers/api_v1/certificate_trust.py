"""Own Certificate Authority and vSphere Key Provider API v1 transports."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Annotated, Any
from uuid import UUID, uuid4

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    Response,
    status,
)
from fastapi import Path as ApiPath
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atlaso.app.audit import record_audit
from atlaso.app.database import get_db
from atlaso.app.models import (
    CaCertificate,
    VsphereKeyProvider,
    VsphereTrustedVcenter,
    VsphereTrustedVcenterCertificate,
    utcnow,
)
from atlaso.app.openapi import DocumentedAPIRoute
from atlaso.app.schemas import SettingsUpdate as SettingsUpdate
from atlaso.app.schemas import (
    VsphereKeyProviderCreate,
    VsphereKeyProviderResponse,
    VsphereKeyProviderSettingsResponse,
    VsphereKeyProviderSettingsUpdate,
    VsphereKeyProviderUpdate,
    VsphereProviderHealthResponse,
    VsphereProviderLifecycleCountsResponse,
    VsphereProviderReadinessResponse,
    VsphereServerCertificateResponse,
    VsphereTrustedCertificateCreate,
    VsphereTrustedCertificateResponse,
    VsphereTrustedVcenterCreate,
    VsphereTrustedVcenterResponse,
    VsphereTrustedVcenterUpdate,
)
from atlaso.app.security import (
    Identity,
    require_scope,
)
from atlaso.app.services.appliance_settings import (
    APPLIANCE_SETTINGS_STAGED_CONFIG_PATH as APPLIANCE_SETTINGS_STAGED_CONFIG_PATH,
)
from atlaso.app.services.appliance_settings import normalize_fqdn as normalize_fqdn
from atlaso.app.services.appliance_settings import (
    normalize_multiline_values as normalize_multiline_values,
)
from atlaso.app.services.appliance_settings import (
    web_terminal_interfaces_to_json as web_terminal_interfaces_to_json,
)
from atlaso.app.services.dnsmasq import (
    split_addresses,
    split_interfaces,
)
from atlaso.app.services.kms import KMS_DEFAULT_CONFIG_PATH, join_csv
from atlaso.app.services.vsphere_key_providers import (
    authenticated_provider_counts,
    certificate_to_dict,
    mark_provider_desired_changed,
    normalize_service_hostname,
    normalize_vcenter_hostname,
    parse_public_certificate,
    provider_requires_appliance_apply,
    provider_rows,
    provider_to_dict,
    runtime_status_snapshot,
    trusted_vcenter_to_dict,
    usable_certificates,
    validate_provider_state,
)

Endpoint = Callable[..., Any]


@dataclass(frozen=True)
class CertificateTrustApiDependencies:
    """Provide facade-owned helpers without importing the compatibility facade."""

    get_kms_settings_row: Endpoint
    service_bind_options: Endpoint


@dataclass(frozen=True)
class CertificateTrustApiRouter:
    """Return the configured router and compatibility endpoint exports."""

    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_router(
    dependencies: CertificateTrustApiDependencies,
) -> CertificateTrustApiRouter:
    """Build Certificate Authority and vSphere Key Provider API transports."""
    router = APIRouter(prefix="/api/v1", route_class=DocumentedAPIRoute)
    get_kms_settings_row = dependencies.get_kms_settings_row
    service_bind_options = dependencies.service_bind_options

    def _normalize_vsphere_service_hostname(value: str) -> str:
        """Return a canonical fully qualified DNS name for the shared listener.

        Args:
            value: Candidate public listener hostname.

        Returns:
            Canonical lowercase fully qualified DNS name.
        """
        try:
            return normalize_service_hostname(value)
        except ValueError:
            raise HTTPException(
                status_code=422,
                detail="vSphere Key Provider hostname must be a valid fully qualified DNS name.",
            ) from None

    def _normalize_vsphere_vcenter_hostname(value: str) -> str:
        """Return a canonical optional vCenter IP address or fully qualified DNS name.

        Args:
            value: Candidate trusted-vCenter network identifier.

        Returns:
            Canonical IP address or lowercase fully qualified DNS name, or an empty string.
        """
        try:
            return normalize_vcenter_hostname(value)
        except ValueError:
            raise HTTPException(
                status_code=422,
                detail="Trusted vCenter hostname must be an IP address or valid fully qualified DNS name.",
            ) from None

    def _normalize_vsphere_listener_values(
        payload: VsphereKeyProviderSettingsUpdate,
        db: Session,
    ) -> tuple[list[str], list[str], str]:
        """Validate and normalize public listener settings before saving desired state.

        Args:
            payload: Submitted appliance-wide listener desired state.
            db: Active database session used to resolve current service bind targets.

        Returns:
            Deduplicated interface names, canonical IP addresses, and canonical hostname.
        """
        available = {
            str(option["name"]): [
                str(address) for address in option.get("addresses", [])
            ]
            for option in service_bind_options(db)
        }
        interfaces: list[str] = []
        for raw_interface in payload.listen_interfaces:
            interface = raw_interface.strip()
            if interface not in available:
                raise HTTPException(
                    status_code=422,
                    detail="Listener interfaces must be available addressed access or VLAN interfaces.",
                )
            if interface not in interfaces:
                interfaces.append(interface)

        addresses = list(
            dict.fromkeys(
                address for interface in interfaces for address in available[interface]
            )
        )

        if payload.enabled and not interfaces:
            raise HTTPException(
                status_code=422,
                detail="At least one listener interface is required while the service is enabled.",
            )
        if payload.enabled and not addresses:
            raise HTTPException(
                status_code=422,
                detail="At least one listener address is required while the service is enabled.",
            )
        return (
            interfaces,
            addresses,
            _normalize_vsphere_service_hostname(payload.hostname),
        )

    def _vsphere_provider(db: Session, provider_id: str) -> VsphereKeyProvider:
        """Return one provider graph or raise a public not-found error.

        Args:
            db: Active database session.
            provider_id: Immutable provider UUID.
        """
        try:
            canonical_id = str(UUID(provider_id))
        except ValueError as exc:
            raise HTTPException(
                status_code=404, detail="vSphere Key Provider not found."
            ) from exc
        provider = next(
            (item for item in provider_rows(db) if item.id == canonical_id), None
        )
        if provider is None:
            raise HTTPException(
                status_code=404, detail="vSphere Key Provider not found."
            )
        return provider

    def _vsphere_vcenter(
        db: Session,
        provider_id: str,
        vcenter_id: str,
    ) -> VsphereTrustedVcenter:
        """Return one provider-scoped vCenter or raise a public not-found error.

        Args:
            db: Active database session.
            provider_id: Immutable provider UUID.
            vcenter_id: Immutable trusted-vCenter UUID.
        """
        provider = _vsphere_provider(db, provider_id)
        try:
            canonical_id = str(UUID(vcenter_id))
        except ValueError as exc:
            raise HTTPException(
                status_code=404, detail="Trusted vCenter not found."
            ) from exc
        vcenter = next(
            (item for item in provider.trusted_vcenters if item.id == canonical_id),
            None,
        )
        if vcenter is None:
            raise HTTPException(status_code=404, detail="Trusted vCenter not found.")
        return vcenter

    def _vsphere_settings_response(db: Session) -> VsphereKeyProviderSettingsResponse:
        """Return the appliance-wide listener settings and secret-free validation.

        Args:
            db: Active database session.
        """
        settings = get_kms_settings_row(db)
        providers = provider_rows(db)
        errors = validate_provider_state(providers) if settings.enabled else []
        if settings.enabled and not split_interfaces(settings.listen_interface):
            errors.append(
                "At least one listener interface is required while the service is enabled."
            )
        if settings.enabled and not split_addresses(settings.listen_address):
            errors.append(
                "At least one listener address is required while the service is enabled."
            )
        return VsphereKeyProviderSettingsResponse(
            enabled=settings.enabled,
            listen_interfaces=split_interfaces(settings.listen_interface),
            listen_addresses=split_addresses(settings.listen_address),
            port=settings.port,
            hostname=settings.hostname,
            updated_at=settings.updated_at,
            valid=not errors,
            validation_errors=errors,
            config_path=KMS_DEFAULT_CONFIG_PATH,
        )

    @router.get(
        "/vsphere-key-providers/settings",
        response_model=VsphereKeyProviderSettingsResponse,
        tags=["vSphere Key Providers"],
        operation_id="getVsphereKeyProviderSettings",
    )
    def get_vsphere_key_provider_settings(
        identity: Annotated[Identity, Depends(require_scope("read:kms"))],
        db: Session = Depends(get_db),
    ) -> VsphereKeyProviderSettingsResponse:
        """Get appliance-wide vSphere Key Provider listener settings.

        Requires the `read:kms` API scope. The response describes saved desired state and never returns
        runtime credentials, client private keys, or operational key identifiers.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return _vsphere_settings_response(db)

    @router.patch(
        "/vsphere-key-providers/settings",
        response_model=VsphereKeyProviderSettingsResponse,
        tags=["vSphere Key Providers"],
        operation_id="updateVsphereKeyProviderSettings",
    )
    def update_vsphere_key_provider_settings(
        payload: VsphereKeyProviderSettingsUpdate,
        identity: Annotated[Identity, Depends(require_scope("write:kms"))],
        db: Session = Depends(get_db),
    ) -> VsphereKeyProviderSettingsResponse:
        """Update saved listener desired state without mutating the appliance host.

        Requires the `write:kms` API scope. Enforcement remains exclusively in global Appliance Apply.

        Args:
            payload: Validated listener desired state.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        interfaces, addresses, hostname = _normalize_vsphere_listener_values(
            payload, db
        )
        settings = get_kms_settings_row(db)
        settings.enabled = payload.enabled
        settings.listen_interface = join_csv(interfaces)
        settings.listen_address = join_csv(addresses)
        settings.port = payload.port
        settings.hostname = hostname
        settings.server_certificate = settings.hostname
        settings.backend = "atlaso-kmip"
        settings.require_client_cert = True
        settings.allow_register = False
        settings.allow_destroy = False
        settings.updated_at = utcnow()
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="update_vsphere_key_provider_settings",
            resource_type="vsphere_key_provider_settings",
            resource_id=str(settings.id),
            detail=f"enabled={settings.enabled}; port={settings.port}; hostname={settings.hostname}",
        )
        return _vsphere_settings_response(db)

    @router.get(
        "/vsphere-key-providers/server-certificate",
        response_model=VsphereServerCertificateResponse,
        tags=["vSphere Key Providers"],
        operation_id="getVsphereKeyProviderServerCertificate",
    )
    def get_vsphere_key_provider_server_certificate(
        identity: Annotated[Identity, Depends(require_scope("read:kms"))],
        db: Session = Depends(get_db),
    ) -> VsphereServerCertificateResponse:
        """Download the public appliance-wide KMIP server certificate chain.

        Requires the `read:kms` API scope. Only public X.509 material and metadata are returned.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        settings = get_kms_settings_row(db)
        certificate = (
            db.execute(
                select(CaCertificate)
                .where(CaCertificate.managed_owner == "kms:server")
                .order_by(CaCertificate.id.desc())
            )
            .scalars()
            .first()
        )
        return VsphereServerCertificateResponse(
            available=bool(certificate and certificate.certificate_pem),
            hostname=settings.hostname,
            fingerprint_sha256=certificate.fingerprint if certificate else "",
            certificate_pem=certificate.certificate_pem if certificate else "",
            chain_pem=certificate.chain_pem if certificate else "",
            expires_at=certificate.expires_at if certificate else None,
        )

    @router.get(
        "/vsphere-key-providers",
        response_model=list[VsphereKeyProviderResponse],
        tags=["vSphere Key Providers"],
        operation_id="listVsphereKeyProviders",
    )
    def list_vsphere_key_providers(
        identity: Annotated[Identity, Depends(require_scope("read:kms"))],
        db: Session = Depends(get_db),
    ) -> list[VsphereKeyProviderResponse]:
        """List logical provider namespaces and redacted trust counts.

        Requires the `read:kms` API scope. Operational key identifiers and wrapped-key metadata are not
        part of this management API.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return [
            VsphereKeyProviderResponse(**provider_to_dict(item))
            for item in provider_rows(db)
        ]

    @router.post(
        "/vsphere-key-providers",
        response_model=VsphereKeyProviderResponse,
        status_code=status.HTTP_201_CREATED,
        tags=["vSphere Key Providers"],
        operation_id="createVsphereKeyProvider",
    )
    def create_vsphere_key_provider(
        payload: VsphereKeyProviderCreate,
        identity: Annotated[Identity, Depends(require_scope("write:kms"))],
        db: Session = Depends(get_db),
    ) -> VsphereKeyProviderResponse:
        """Create an isolated provider namespace with an immutable UUID.

        Requires the `write:kms` API scope. The saved namespace is enforced only by global Appliance Apply.

        Args:
            payload: Validated provider fields.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        provider = VsphereKeyProvider(
            id=str(uuid4()),
            name=payload.name.strip(),
            description=payload.description.strip(),
            enabled=payload.enabled,
        )
        db.add(provider)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409, detail="Provider name already exists."
            ) from exc
        record_audit(
            db,
            actor=identity.username,
            action="create_vsphere_key_provider",
            resource_type="vsphere_key_provider",
            resource_id=provider.id,
            detail=f"name={provider.name}; enabled={provider.enabled}",
        )
        return VsphereKeyProviderResponse(
            **provider_to_dict(_vsphere_provider(db, provider.id))
        )

    @router.get(
        "/vsphere-key-providers/{provider_id}",
        response_model=VsphereKeyProviderResponse,
        tags=["vSphere Key Providers"],
        operation_id="getVsphereKeyProvider",
    )
    def get_vsphere_key_provider(
        provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
        identity: Annotated[Identity, Depends(require_scope("read:kms"))],
        db: Session = Depends(get_db),
    ) -> VsphereKeyProviderResponse:
        """Get one logical provider namespace.

        Requires the `read:kms` API scope. The response contains redacted trust counts only.

        Args:
            provider_id: Immutable provider UUID.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return VsphereKeyProviderResponse(
            **provider_to_dict(_vsphere_provider(db, provider_id))
        )

    @router.patch(
        "/vsphere-key-providers/{provider_id}",
        response_model=VsphereKeyProviderResponse,
        tags=["vSphere Key Providers"],
        operation_id="updateVsphereKeyProvider",
    )
    def update_vsphere_key_provider(
        provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
        payload: VsphereKeyProviderUpdate,
        identity: Annotated[Identity, Depends(require_scope("write:kms"))],
        db: Session = Depends(get_db),
    ) -> VsphereKeyProviderResponse:
        """Update a provider name, description, or saved enabled state.

        Requires the `write:kms` API scope. The immutable provider UUID is never replaced.

        Args:
            provider_id: Immutable provider UUID.
            payload: Validated mutable provider fields.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        provider = _vsphere_provider(db, provider_id)
        for key, value in payload.model_dump(exclude_none=True).items():
            setattr(provider, key, value.strip() if isinstance(value, str) else value)
        provider.updated_at = utcnow()
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409, detail="Provider name already exists."
            ) from exc
        record_audit(
            db,
            actor=identity.username,
            action="update_vsphere_key_provider",
            resource_type="vsphere_key_provider",
            resource_id=provider.id,
            detail=f"name={provider.name}; enabled={provider.enabled}",
        )
        return VsphereKeyProviderResponse(
            **provider_to_dict(_vsphere_provider(db, provider.id))
        )

    @router.delete(
        "/vsphere-key-providers/{provider_id}",
        status_code=status.HTTP_204_NO_CONTENT,
        tags=["vSphere Key Providers"],
        operation_id="deleteVsphereKeyProvider",
    )
    def delete_vsphere_key_provider(
        provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
        identity: Annotated[Identity, Depends(require_scope("write:kms"))],
        db: Session = Depends(get_db),
    ) -> Response:
        """Delete a disabled, detached, verified-empty provider namespace.

        Requires the `write:kms` API scope. The disabled and detached state must complete global
        Appliance Apply before authenticated runtime evidence of zero operational keys can authorize
        deletion; unavailable evidence fails closed.

        Args:
            provider_id: Immutable provider UUID.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        provider = _vsphere_provider(db, provider_id)
        if provider.enabled or provider.trusted_vcenters:
            raise HTTPException(
                status_code=409,
                detail="Disable the provider and detach every trusted vCenter before deletion.",
            )
        if provider_requires_appliance_apply(provider):
            raise HTTPException(
                status_code=409,
                detail="Apply the disabled and detached provider state before deletion.",
            )
        snapshot = runtime_status_snapshot()
        counts = authenticated_provider_counts(snapshot, provider.id)
        if counts is None or counts.get("total") != 0:
            raise HTTPException(
                status_code=409,
                detail="Authenticated zero-key runtime evidence is required before deletion.",
            )
        name = provider.name
        db.delete(provider)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_vsphere_key_provider",
            resource_type="vsphere_key_provider",
            resource_id=provider.id,
            detail=f"name={name}; verified_empty=true",
        )
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @router.get(
        "/vsphere-key-providers/{provider_id}/trusted-vcenters",
        response_model=list[VsphereTrustedVcenterResponse],
        tags=["vSphere Key Providers"],
        operation_id="listVsphereTrustedVcenters",
    )
    def list_vsphere_trusted_vcenters(
        provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
        identity: Annotated[Identity, Depends(require_scope("read:kms"))],
        db: Session = Depends(get_db),
    ) -> list[VsphereTrustedVcenterResponse]:
        """List trusted vCenters scoped to one provider.

        Requires the `read:kms` API scope. The response contains no credentials or private key material.

        Args:
            provider_id: Immutable provider UUID.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        provider = _vsphere_provider(db, provider_id)
        return [
            VsphereTrustedVcenterResponse(**trusted_vcenter_to_dict(item))
            for item in provider.trusted_vcenters
        ]

    @router.post(
        "/vsphere-key-providers/{provider_id}/trusted-vcenters",
        response_model=VsphereTrustedVcenterResponse,
        status_code=status.HTTP_201_CREATED,
        tags=["vSphere Key Providers"],
        operation_id="createVsphereTrustedVcenter",
    )
    def create_vsphere_trusted_vcenter(
        provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
        payload: VsphereTrustedVcenterCreate,
        identity: Annotated[Identity, Depends(require_scope("write:kms"))],
        db: Session = Depends(get_db),
    ) -> VsphereTrustedVcenterResponse:
        """Create a provider-scoped trusted-vCenter record.

        Requires the `write:kms` API scope. Public certificates are assigned through the certificate subresource.

        Args:
            provider_id: Immutable provider UUID.
            payload: Validated trusted-vCenter fields.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        provider = _vsphere_provider(db, provider_id)
        item = VsphereTrustedVcenter(
            id=str(uuid4()),
            provider_id=provider.id,
            name=payload.name.strip(),
            hostname=_normalize_vsphere_vcenter_hostname(payload.hostname),
            description=payload.description.strip(),
            enabled=payload.enabled,
        )
        db.add(item)
        mark_provider_desired_changed(provider)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail="Trusted vCenter name already exists for this provider.",
            ) from exc
        record_audit(
            db,
            actor=identity.username,
            action="create_vsphere_trusted_vcenter",
            resource_type="vsphere_trusted_vcenter",
            resource_id=item.id,
            detail=f"provider_id={provider.id}; name={item.name}; enabled={item.enabled}",
        )
        return VsphereTrustedVcenterResponse(
            **trusted_vcenter_to_dict(_vsphere_vcenter(db, provider.id, item.id))
        )

    @router.get(
        "/vsphere-key-providers/{provider_id}/trusted-vcenters/{vcenter_id}",
        response_model=VsphereTrustedVcenterResponse,
        tags=["vSphere Key Providers"],
        operation_id="getVsphereTrustedVcenter",
    )
    def get_vsphere_trusted_vcenter(
        provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
        vcenter_id: Annotated[
            str, ApiPath(description="Immutable trusted-vCenter UUID.")
        ],
        identity: Annotated[Identity, Depends(require_scope("read:kms"))],
        db: Session = Depends(get_db),
    ) -> VsphereTrustedVcenterResponse:
        """Get one provider-scoped trusted vCenter.

        Requires the `read:kms` API scope. The response exposes public X.509 material only.

        Args:
            provider_id: Immutable provider UUID.
            vcenter_id: Immutable trusted-vCenter UUID.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return VsphereTrustedVcenterResponse(
            **trusted_vcenter_to_dict(_vsphere_vcenter(db, provider_id, vcenter_id))
        )

    @router.patch(
        "/vsphere-key-providers/{provider_id}/trusted-vcenters/{vcenter_id}",
        response_model=VsphereTrustedVcenterResponse,
        tags=["vSphere Key Providers"],
        operation_id="updateVsphereTrustedVcenter",
    )
    def update_vsphere_trusted_vcenter(
        provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
        vcenter_id: Annotated[
            str, ApiPath(description="Immutable trusted-vCenter UUID.")
        ],
        payload: VsphereTrustedVcenterUpdate,
        identity: Annotated[Identity, Depends(require_scope("write:kms"))],
        db: Session = Depends(get_db),
    ) -> VsphereTrustedVcenterResponse:
        """Update provider-scoped trusted-vCenter metadata and enabled state.

        Requires the `write:kms` API scope.

        Args:
            provider_id: Immutable provider UUID.
            vcenter_id: Immutable trusted-vCenter UUID.
            payload: Validated mutable trusted-vCenter fields.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        item = _vsphere_vcenter(db, provider_id, vcenter_id)
        for key, value in payload.model_dump(exclude_none=True).items():
            setattr(item, key, value.strip() if isinstance(value, str) else value)
        item.hostname = _normalize_vsphere_vcenter_hostname(item.hostname)
        item.updated_at = utcnow()
        mark_provider_desired_changed(item.provider)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409,
                detail="Trusted vCenter name already exists for this provider.",
            ) from exc
        record_audit(
            db,
            actor=identity.username,
            action="update_vsphere_trusted_vcenter",
            resource_type="vsphere_trusted_vcenter",
            resource_id=item.id,
            detail=f"provider_id={provider_id}; name={item.name}; enabled={item.enabled}",
        )
        return VsphereTrustedVcenterResponse(
            **trusted_vcenter_to_dict(_vsphere_vcenter(db, provider_id, item.id))
        )

    @router.delete(
        "/vsphere-key-providers/{provider_id}/trusted-vcenters/{vcenter_id}",
        status_code=status.HTTP_204_NO_CONTENT,
        tags=["vSphere Key Providers"],
        operation_id="deleteVsphereTrustedVcenter",
    )
    def delete_vsphere_trusted_vcenter(
        provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
        vcenter_id: Annotated[
            str, ApiPath(description="Immutable trusted-vCenter UUID.")
        ],
        identity: Annotated[Identity, Depends(require_scope("write:kms"))],
        db: Session = Depends(get_db),
    ) -> Response:
        """Delete a disabled trusted vCenter after every certificate is retired.

        Requires the `write:kms` API scope.

        Args:
            provider_id: Immutable provider UUID.
            vcenter_id: Immutable trusted-vCenter UUID.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        item = _vsphere_vcenter(db, provider_id, vcenter_id)
        if item.enabled or item.certificates:
            raise HTTPException(
                status_code=409,
                detail="Disable the trusted vCenter and retire every certificate before deletion.",
            )
        name = item.name
        mark_provider_desired_changed(item.provider)
        db.delete(item)
        db.commit()
        record_audit(
            db,
            actor=identity.username,
            action="delete_vsphere_trusted_vcenter",
            resource_type="vsphere_trusted_vcenter",
            resource_id=vcenter_id,
            detail=f"provider_id={provider_id}; name={name}",
        )
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @router.get(
        "/vsphere-key-providers/{provider_id}/trusted-vcenters/{vcenter_id}/certificates",
        response_model=list[VsphereTrustedCertificateResponse],
        tags=["vSphere Key Providers"],
        operation_id="listVsphereTrustedVcenterCertificates",
    )
    def list_vsphere_trusted_vcenter_certificates(
        provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
        vcenter_id: Annotated[
            str, ApiPath(description="Immutable trusted-vCenter UUID.")
        ],
        identity: Annotated[Identity, Depends(require_scope("read:kms"))],
        db: Session = Depends(get_db),
    ) -> list[VsphereTrustedCertificateResponse]:
        """List exact public certificates assigned to a trusted vCenter.

        Requires the `read:kms` API scope. Only public certificate material and parsed metadata are returned.

        Args:
            provider_id: Immutable provider UUID.
            vcenter_id: Immutable trusted-vCenter UUID.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        item = _vsphere_vcenter(db, provider_id, vcenter_id)
        return [
            VsphereTrustedCertificateResponse(**certificate_to_dict(cert))
            for cert in item.certificates
        ]

    @router.post(
        "/vsphere-key-providers/{provider_id}/trusted-vcenters/{vcenter_id}/certificates",
        response_model=VsphereTrustedCertificateResponse,
        status_code=status.HTTP_201_CREATED,
        tags=["vSphere Key Providers"],
        operation_id="createVsphereTrustedVcenterCertificate",
    )
    def create_vsphere_trusted_vcenter_certificate(
        provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
        vcenter_id: Annotated[
            str, ApiPath(description="Immutable trusted-vCenter UUID.")
        ],
        payload: VsphereTrustedCertificateCreate,
        identity: Annotated[Identity, Depends(require_scope("write:kms"))],
        db: Session = Depends(get_db),
    ) -> VsphereTrustedCertificateResponse:
        """Assign one current public X.509 client certificate to a trusted vCenter.

        Requires the `write:kms` API scope. Private-key blocks, expired certificates, malformed input,
        and fingerprints already assigned anywhere in the appliance are rejected.

        Args:
            provider_id: Immutable provider UUID.
            vcenter_id: Immutable trusted-vCenter UUID.
            payload: One public PEM certificate.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        item = _vsphere_vcenter(db, provider_id, vcenter_id)
        try:
            parsed = parse_public_certificate(payload.certificate_pem)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        certificate = VsphereTrustedVcenterCertificate(
            id=str(uuid4()),
            trusted_vcenter_id=item.id,
            source="uploaded_public",
            **parsed,
        )
        db.add(certificate)
        mark_provider_desired_changed(item.provider)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(
                status_code=409, detail="Certificate fingerprint is already assigned."
            ) from exc
        record_audit(
            db,
            actor=identity.username,
            action="add_vsphere_trusted_certificate",
            resource_type="vsphere_trusted_certificate",
            resource_id=certificate.id,
            detail=f"provider_id={provider_id}; trusted_vcenter_id={vcenter_id}; public_certificate=true",
        )
        refreshed = _vsphere_vcenter(db, provider_id, vcenter_id)
        stored = next(
            cert for cert in refreshed.certificates if cert.id == certificate.id
        )
        return VsphereTrustedCertificateResponse(**certificate_to_dict(stored))

    @router.get(
        "/vsphere-key-providers/{provider_id}/trusted-vcenters/{vcenter_id}/certificates/{certificate_id}",
        response_model=VsphereTrustedCertificateResponse,
        tags=["vSphere Key Providers"],
        operation_id="getVsphereTrustedVcenterCertificate",
    )
    def get_vsphere_trusted_vcenter_certificate(
        provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
        vcenter_id: Annotated[
            str, ApiPath(description="Immutable trusted-vCenter UUID.")
        ],
        certificate_id: Annotated[
            str, ApiPath(description="Immutable public certificate UUID.")
        ],
        identity: Annotated[Identity, Depends(require_scope("read:kms"))],
        db: Session = Depends(get_db),
    ) -> VsphereTrustedCertificateResponse:
        """Get one exact public certificate record.

        Requires the `read:kms` API scope. The response exposes public X.509 material only.

        Args:
            provider_id: Immutable provider UUID.
            vcenter_id: Immutable trusted-vCenter UUID.
            certificate_id: Immutable public certificate UUID.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        item = _vsphere_vcenter(db, provider_id, vcenter_id)
        certificate = next(
            (cert for cert in item.certificates if cert.id == certificate_id), None
        )
        if certificate is None:
            raise HTTPException(status_code=404, detail="Certificate not found.")
        return VsphereTrustedCertificateResponse(**certificate_to_dict(certificate))

    @router.delete(
        "/vsphere-key-providers/{provider_id}/trusted-vcenters/{vcenter_id}/certificates/{certificate_id}",
        status_code=status.HTTP_204_NO_CONTENT,
        tags=["vSphere Key Providers"],
        operation_id="deleteVsphereTrustedVcenterCertificate",
    )
    def delete_vsphere_trusted_vcenter_certificate(
        provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
        vcenter_id: Annotated[
            str, ApiPath(description="Immutable trusted-vCenter UUID.")
        ],
        certificate_id: Annotated[
            str, ApiPath(description="Immutable public certificate UUID.")
        ],
        identity: Annotated[Identity, Depends(require_scope("write:kms"))],
        db: Session = Depends(get_db),
    ) -> Response:
        """Retire one public certificate trust assignment.

        Requires the `write:kms` API scope. The last usable certificate of an enabled trusted vCenter
        cannot be retired until that record is disabled.

        Args:
            provider_id: Immutable provider UUID.
            vcenter_id: Immutable trusted-vCenter UUID.
            certificate_id: Immutable public certificate UUID.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        item = _vsphere_vcenter(db, provider_id, vcenter_id)
        certificate = next(
            (cert for cert in item.certificates if cert.id == certificate_id), None
        )
        if certificate is None:
            raise HTTPException(status_code=404, detail="Certificate not found.")
        usable = usable_certificates(item)
        if item.enabled and certificate in usable and len(usable) <= 1:
            raise HTTPException(
                status_code=409,
                detail="Disable the trusted vCenter before retiring its last usable public certificate.",
            )
        mark_provider_desired_changed(item.provider)
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
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @router.get(
        "/vsphere-key-providers/{provider_id}/readiness",
        response_model=VsphereProviderReadinessResponse,
        tags=["vSphere Key Providers"],
        operation_id="getVsphereKeyProviderReadiness",
    )
    def get_vsphere_key_provider_readiness(
        provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
        identity: Annotated[Identity, Depends(require_scope("read:kms"))],
        db: Session = Depends(get_db),
    ) -> VsphereProviderReadinessResponse:
        """Evaluate one provider's saved desired-state readiness.

        Requires the `read:kms` API scope. This operation performs no host mutation.

        Args:
            provider_id: Immutable provider UUID.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        provider = _vsphere_provider(db, provider_id)
        reasons = validate_provider_state([provider]) if provider.enabled else []
        return VsphereProviderReadinessResponse(
            provider_id=provider.id,
            ready=not reasons,
            reasons=reasons,
            requires_appliance_apply=provider_requires_appliance_apply(provider),
        )

    @router.get(
        "/vsphere-key-providers/{provider_id}/health",
        response_model=VsphereProviderHealthResponse,
        tags=["vSphere Key Providers"],
        operation_id="getVsphereKeyProviderHealth",
    )
    def get_vsphere_key_provider_health(
        provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
        identity: Annotated[Identity, Depends(require_scope("read:kms"))],
        db: Session = Depends(get_db),
    ) -> VsphereProviderHealthResponse:
        """Return redacted shared-daemon and authenticated store health.

        Requires the `read:kms` API scope. Raw helper errors and operational key identifiers are never returned.

        Args:
            provider_id: Immutable provider UUID.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        provider = _vsphere_provider(db, provider_id)
        snapshot = runtime_status_snapshot()
        return VsphereProviderHealthResponse(
            provider_id=provider.id,
            desired_state="enabled" if provider.enabled else "disabled",
            runtime_state=str(snapshot.get("runtime_state", "not-reported")),
            store_status=str(snapshot.get("store_status", "not-reported")),
            observed_at=utcnow(),
        )

    @router.get(
        "/vsphere-key-providers/{provider_id}/lifecycle-counts",
        response_model=VsphereProviderLifecycleCountsResponse,
        tags=["vSphere Key Providers"],
        operation_id="getVsphereKeyProviderLifecycleCounts",
    )
    def get_vsphere_key_provider_lifecycle_counts(
        provider_id: Annotated[str, ApiPath(description="Immutable provider UUID.")],
        identity: Annotated[Identity, Depends(require_scope("read:kms"))],
        db: Session = Depends(get_db),
    ) -> VsphereProviderLifecycleCountsResponse:
        """Return authenticated redacted lifecycle counts for one provider namespace.

        Requires the `read:kms` API scope. Unavailable runtime evidence is represented by null counts,
        never fabricated zeroes.

        Args:
            provider_id: Immutable provider UUID.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        provider = _vsphere_provider(db, provider_id)
        snapshot = runtime_status_snapshot()
        counts = authenticated_provider_counts(snapshot, provider.id)
        available = isinstance(counts, dict) and all(
            isinstance(counts.get(key), int)
            for key in ("pre_active", "active", "total")
        )
        return VsphereProviderLifecycleCountsResponse(
            provider_id=provider.id,
            status="available" if available else "not-reported",
            pre_active=counts.get("pre_active") if available else None,
            active=counts.get("active") if available else None,
            total=counts.get("total") if available else None,
            observed_at=utcnow(),
        )

    async def placeholder(
        identity: Annotated[Identity, Depends(require_scope("read:ca"))],
        resource: Annotated[
            str,
            Query(
                description="Stable scaffolded resource name returned by this compatibility endpoint."
            ),
        ] = "ca",
    ) -> dict[str, str]:
        """Return scaffolded Certificate Authority API status.

        Requires the `read:ca` API scope. This read-only compatibility endpoint
        reports dry-run scaffold state and does not change saved desired state or
        appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            resource: Stable compatibility resource name.
        """
        return {"resource": resource, "status": "scaffolded", "mode": "dry-run"}

    router.add_api_route(
        "/ca/status",
        placeholder,
        methods=["GET"],
        response_model=dict[str, str],
        summary="Get CA status",
        description=(
            "Return the scaffolded CA API status.\n\nRequires the `read:ca` API "
            "scope. This read-only compatibility endpoint reports dry-run scaffold "
            "state and does not change saved desired state or appliance runtime state."
        ),
        response_description="Current scaffolded CA status and dry-run mode.",
        tags=["CA"],
        operation_id="getCAStatus",
    )

    return CertificateTrustApiRouter(
        router=router,
        endpoints={
            "_normalize_vsphere_service_hostname": _normalize_vsphere_service_hostname,
            "_normalize_vsphere_vcenter_hostname": _normalize_vsphere_vcenter_hostname,
            "_normalize_vsphere_listener_values": _normalize_vsphere_listener_values,
            "_vsphere_provider": _vsphere_provider,
            "_vsphere_vcenter": _vsphere_vcenter,
            "_vsphere_settings_response": _vsphere_settings_response,
            "get_vsphere_key_provider_settings": get_vsphere_key_provider_settings,
            "update_vsphere_key_provider_settings": update_vsphere_key_provider_settings,
            "get_vsphere_key_provider_server_certificate": get_vsphere_key_provider_server_certificate,
            "list_vsphere_key_providers": list_vsphere_key_providers,
            "create_vsphere_key_provider": create_vsphere_key_provider,
            "get_vsphere_key_provider": get_vsphere_key_provider,
            "update_vsphere_key_provider": update_vsphere_key_provider,
            "delete_vsphere_key_provider": delete_vsphere_key_provider,
            "list_vsphere_trusted_vcenters": list_vsphere_trusted_vcenters,
            "create_vsphere_trusted_vcenter": create_vsphere_trusted_vcenter,
            "get_vsphere_trusted_vcenter": get_vsphere_trusted_vcenter,
            "update_vsphere_trusted_vcenter": update_vsphere_trusted_vcenter,
            "delete_vsphere_trusted_vcenter": delete_vsphere_trusted_vcenter,
            "list_vsphere_trusted_vcenter_certificates": list_vsphere_trusted_vcenter_certificates,
            "create_vsphere_trusted_vcenter_certificate": create_vsphere_trusted_vcenter_certificate,
            "get_vsphere_trusted_vcenter_certificate": get_vsphere_trusted_vcenter_certificate,
            "delete_vsphere_trusted_vcenter_certificate": delete_vsphere_trusted_vcenter_certificate,
            "get_vsphere_key_provider_readiness": get_vsphere_key_provider_readiness,
            "get_vsphere_key_provider_health": get_vsphere_key_provider_health,
            "get_vsphere_key_provider_lifecycle_counts": get_vsphere_key_provider_lifecycle_counts,
            "placeholder": placeholder,
        },
    )
