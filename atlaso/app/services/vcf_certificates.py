"""Durable native certificate operations with single-use, actor-bound review.

Only public material and credential references are persisted. Every native write
is checkpointed before dispatch and uncertain writes are never automatically retried.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import socket
import time
from dataclasses import asdict
from typing import Any, Protocol
from urllib.parse import urlsplit
from uuid import uuid4

from cryptography import x509
from itsdangerous import BadData, URLSafeTimedSerializer
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atlaso.app.audit import record_audit
from atlaso.app.config import get_settings
from atlaso.app.database import SessionLocal
from atlaso.app.models import (
    CaCertificate,
    CaProfile,
    CaSettings,
    Job,
    Setting,
    User,
    VaultEntry,
    utcnow,
)
from atlaso.app.secrets import decrypt_secret
from atlaso.app.security import user_roles
from atlaso.app.services import ca
from atlaso.app.services.network_objects import acquire_network_objects_write_lock
from atlaso.app.services.vcf_certificate_discovery import (
    healthy_services,
    names_from_certificate,
    standalone_vcenter,
    supported_version,
)
from atlaso.app.services.vcf_certificate_material import (
    CertificateMaterialError,
    ProductProfile,
    certificate_metadata,
    public_chain_pem,
    validate_issued_certificate,
    validate_product_csr,
    validate_profile,
)
from atlaso.app.services.vcf_certificate_remote import (
    Credentials,
    NativeAdapter,
    PinnedHTTPS,
    RemoteError,
    Target,
)
from atlaso.app.services.vcf_certificate_sddc import SddcAdapter

JOB_TYPE = "vcf-appliance-certificate"
PREFIX = "vcf_cert_op:"
REVIEW_SECONDS = 600
READINESS_SECONDS = 900


class CertificateOperationError(ValueError):
    """Sanitized refusal suitable for the management browser."""


class TaskDispatcher(Protocol):
    def add_task(self, func: Any, *args: Any, **kwargs: Any) -> Any:
        """Schedule the admitted callback after its browser response.

        Args:
            func: Synchronous certificate-operation worker to schedule.
            *args: Positional callback arguments supplied by the caller.
            **kwargs: Keyword callback arguments supplied by the caller.
        """
        ...


def _json(value: Any) -> str:
    """Serialize public operation values deterministically.

    Args:
        value: Candidate native value to normalize or validate.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _digest(value: Any) -> str:
    """Hash the canonical public operation representation.

    Args:
        value: Candidate native value to normalize or validate.
    """
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _metadata(cert: x509.Certificate) -> dict[str, Any]:
    """Convert parsed certificate metadata to durable public JSON fields.

    Args:
        cert: Parsed public appliance certificate.
    """
    return dict(json.loads(_json(asdict(certificate_metadata(cert)))))


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(
        get_settings().secret_key, salt="vcf-appliance-certificate-v1"
    )


def _target(values: dict[str, Any]) -> tuple[str, Target]:
    """Validate the requested product, endpoint, and confirmed TLS fingerprint.

    Args:
        values: Validated browser workflow input values.
    """
    product = str(values.get("product", ""))
    host = str(values.get("address", "")).strip().lower().rstrip(".").strip("[]")
    if (
        product not in {"srm", "vcenter", "sddc"}
        or not host
        or len(host) > 253
        or not re.fullmatch(r"[a-z0-9.:-]+", host)
    ):
        raise CertificateOperationError(
            "Select a product and enter its hostname or IP address without a URL."
        )
    try:
        target = Target(
            host,
            int(values.get("port", 443)),
            str(values.get("confirmed_tls_fingerprint") or "0" * 64),
        )
    except TypeError, ValueError:
        raise CertificateOperationError(
            "Enter a valid port and SHA-256 TLS fingerprint."
        ) from None
    return product, target


def _reference(db: Session, values: dict[str, Any]) -> dict[str, Any]:
    """Resolve a vault selection or a request-local manual credential reference.

    Args:
        db: Database session holding operation records and target reservations.
        values: Validated browser workflow input values.
    """
    vault, entry_id = (
        values.get("credential_vault_id"),
        values.get("credential_entry_id"),
    )
    if vault in (None, "") and entry_id in (None, ""):
        username, password = values.get("username"), values.get("password")
        if (
            not isinstance(username, str)
            or not isinstance(password, str)
            or not username.strip()
            or not password
            or len(username) > 180
            or len(password.encode()) > 4096
            or any(ord(c) < 32 for c in username + password)
        ):
            raise CertificateOperationError(
                "Enter request-local administrator credentials."
            )
        return {"mode": "manual", "username": username.strip()}
    try:
        selected_entry, selected_vault = int(str(entry_id)), int(str(vault))
        entry = db.scalar(
            select(VaultEntry).where(
                VaultEntry.id == selected_entry, VaultEntry.vault_id == selected_vault
            )
        )
    except TypeError, ValueError:
        raise CertificateOperationError("Choose a valid vault credential.") from None
    if entry is None or not entry.username:
        raise CertificateOperationError("Choose a vault credential with a username.")
    return {
        "mode": "vault",
        "vault_id": entry.vault_id,
        "entry_id": entry.id,
        "username": entry.username,
        "revision": _digest([entry.encrypted_value, str(entry.updated_at)]),
    }


def _credentials(
    db: Session, values: dict[str, Any], reference: dict[str, Any]
) -> Credentials:
    """Resolve credentials only when the inspected reference still matches.

    Args:
        db: Database session holding operation records and target reservations.
        values: Validated browser workflow input values.
        reference: Persisted credential reference without a password.
    """
    if _reference(db, values) != reference:
        raise CertificateOperationError("Credential selection changed; inspect again.")
    if reference["mode"] == "manual":
        return Credentials(reference["username"], str(values["password"]))
    entry = db.get(VaultEntry, reference["entry_id"])
    if entry is None:
        raise CertificateOperationError("The selected credential no longer exists.")
    return Credentials(reference["username"], decrypt_secret(entry.encrypted_value))


def _profile(profile: CaProfile) -> dict[str, Any]:
    """Project the product-relevant CA profile properties.

    Args:
        profile: Existing CA profile whose product requirements are checked.
    """
    return {
        "id": profile.id,
        "name": profile.name,
        "validity_days": profile.validity_days,
        "key_algorithm": profile.key_algorithm,
        "key_size": profile.key_size,
        "key_usage": profile.key_usage,
        "extended_key_usage": profile.extended_key_usage,
        "san_required": profile.san_required,
        "enabled": profile.enabled,
    }


def _ready_ca(
    db: Session, product: str, profile_id: int | None = None
) -> tuple[CaSettings, list[CaProfile]]:
    """Require an existing ready CA and product-compatible certificate profiles.

    Args:
        db: Database session holding operation records and target reservations.
        product: Detected appliance product identifier.
        profile_id: Identifier of the existing product-specific CA profile.
    """
    settings = db.scalar(select(CaSettings).order_by(CaSettings.id))
    if (
        settings is None
        or not settings.enabled
        or not settings.root_certificate_pem
        or not settings.root_private_key_encrypted
    ):
        raise CertificateOperationError(
            "Prepare an existing ready CA before certificate replacement."
        )
    root = x509.load_pem_x509_certificate(settings.root_certificate_pem.encode())
    public_chain_pem(settings.root_certificate_pem.encode(), root)
    profiles = []
    for profile in db.scalars(select(CaProfile).order_by(CaProfile.id)):
        try:
            validate_profile(
                ProductProfile(
                    profile.name,
                    profile.enabled,
                    frozenset(ca.split_multiline(profile.key_usage.replace(",", "\n"))),
                    frozenset(
                        ca.split_multiline(
                            profile.extended_key_usage.replace(",", "\n")
                        )
                    ),
                    profile.certificate_type,
                    profile.key_algorithm,
                    profile.key_size,
                    profile.san_required,
                ),
                product,
            )
        except CertificateMaterialError:
            continue
        profiles.append(profile)
    if profile_id is not None and not any(p.id == profile_id for p in profiles):
        raise CertificateOperationError(
            "Choose an enabled product-specific RSA profile with the required usages."
        )
    return settings, profiles


def _ca_snapshot(db: Session, product: str, profile_id: int) -> dict[str, Any]:
    """Capture issuing CA identity for later review revalidation.

    Args:
        db: Database session holding operation records and target reservations.
        product: Detected appliance product identifier.
        profile_id: Identifier of the existing product-specific CA profile.
    """
    settings, profiles = _ready_ca(db, product, profile_id)
    return {
        "root": _metadata(
            x509.load_pem_x509_certificate(settings.root_certificate_pem.encode())
        ),
        "profile": _profile(next(p for p in profiles if p.id == profile_id)),
    }


def _probe(target: Target) -> dict[str, Any]:
    """Read public TLS identity without sending administrator credentials.

    Args:
        target: Confirmed appliance endpoint and connection identity.
    """
    public = PinnedHTTPS(target).probe()
    return {
        "fingerprint": public["sha256"],
        "certificate": _metadata(
            x509.load_pem_x509_certificate(public["certificate_pem"].encode())
        ),
    }


def _confirmed(values: dict[str, Any], target: Target) -> None:
    """Require explicit confirmation of the exact presented certificate.

    Args:
        values: Validated browser workflow input values.
        target: Confirmed appliance endpoint and connection identity.
    """
    if values.get("confirmed") is not True or not values.get(
        "confirmed_tls_fingerprint"
    ):
        raise CertificateOperationError(
            "Confirm the target TLS fingerprint before authentication."
        )
    if _probe(target)["fingerprint"] != target.fingerprint:
        raise CertificateOperationError(
            "TLS identity changed. Independently confirm the target again."
        )


def _state(
    db: Session, operation_id: str, actor: str
) -> tuple[Setting, dict[str, Any]]:
    """Load an operation only for its submitting administrator.

    Args:
        db: Database session holding operation records and target reservations.
        operation_id: Stable identifier of the actor-bound certificate operation.
        actor: Submitting administrator username.
    """
    if not re.fullmatch(r"[a-f0-9]{32}", operation_id):
        raise CertificateOperationError("Certificate operation not found.")
    row = db.scalar(select(Setting).where(Setting.key == PREFIX + operation_id))
    if row is None:
        raise CertificateOperationError("Certificate operation not found.")
    state = json.loads(row.value)
    if state["actor"] != actor:
        raise CertificateOperationError(
            "This operation belongs to another administrator."
        )
    return row, state


def _save(db: Session, row: Setting, state: dict[str, Any]) -> None:
    """Persist a public checkpoint and synchronize its task progress.

    Args:
        db: Database session holding operation records and target reservations.
        row: Persistent public operation Setting row.
        state: Public operation checkpoint and reviewed inputs.
    """
    stages = {
        "queued_preparation": 0,
        "csr_dispatch_pending": 25,
        "csr_task_submitted": 35,
        "csr_received": 55,
        "certificate_issued": 70,
        "validation_dispatch_pending": 75,
        "validation_task_submitted": 80,
        "certificate_prepared": 100,
        "queued_installation": 0,
        "root_import_dispatch_pending": 20,
        "installation_dispatch_pending": 40,
        "verifying_readiness": 65,
        "verified": 100,
        "reconciled_verified": 100,
    }
    state["progress_percent"] = stages.get(
        state["checkpoint"], state.get("progress_percent", 0)
    )
    job = db.get(Job, state.get("job_id")) if state.get("job_id") else None
    if job is not None and job.status in {"pending", "running"}:
        job.progress_percent = state["progress_percent"]
    row.value, row.updated_at = _json(state), utcnow()
    db.commit()


def _actor(db: Session, actor: str) -> None:
    """Require the submitting account to remain enabled and administrative.

    Args:
        db: Database session holding operation records and target reservations.
        actor: Submitting administrator username.
    """
    user = db.scalar(select(User).where(User.username == actor))
    if user is None or not user.enabled or "admin" not in user_roles(user):
        raise CertificateOperationError(
            "The submitting administrator is no longer authorized."
        )


def operation_status(db: Session, actor: str, operation_id: str) -> dict[str, Any]:
    """Return public progress and independently recorded verification outcomes.

    Args:
        db: Database session holding operation records and target reservations.
        actor: Submitting administrator username.
        operation_id: Stable identifier of the actor-bound certificate operation.
    """
    _, state = _state(db, operation_id, actor)
    result: dict[str, Any] = {
        key: state[key]
        for key in (
            "operation_id",
            "state",
            "checkpoint",
            "job_id",
            "progress_percent",
            "error",
            "product",
            "address",
            "port",
            "confirmed_tls_fingerprint",
            "profile_id",
            "names",
            "current_certificate",
            "replacement_certificate",
            "issuer",
            "trust_changes",
            "recovery_reference",
            "verification",
            "product_info",
            "native_csr_task_id",
            "native_validation_id",
            "native_install_task_id",
        )
        if key in state
    }
    if "credential_reference" in state:
        reference = state["credential_reference"]
        result["credential_reference"] = {
            key: reference[key]
            for key in ("mode", "username", "vault_id", "entry_id")
            if key in reference
        }
    if state["product"] == "sddc":
        result["domain_id"] = state["product_info"]["domain_id"]
    return result


def _names(values: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    """Require the native appliance names to match the reviewed SAN set.

    Args:
        values: Validated browser workflow input values.
        expected: Expected accepted value or response used by the assertion.
    """
    names: dict[str, Any] = {"common_name": str(values.get("common_name", "")).strip()}
    for key in ("dns_names", "ip_addresses"):
        items = values.get(key)
        if (
            not isinstance(items, list)
            or not all(isinstance(x, str) for x in items)
            or len(items) > 64
            or len(set(items)) != len(items)
        ):
            raise CertificateOperationError(
                "Enter a bounded list of unique discovered target names."
            )
        names[key] = sorted(items)
    if names != expected:
        raise CertificateOperationError(
            "Names must match native identity and discovered SANs. Correct native identity before preparation."
        )
    return names


def _locks(product: str, target: Target, identity: str) -> list[str]:
    """Build durable reservations for the target address and native identity.

    Args:
        product: Detected appliance product identifier.
        target: Confirmed appliance endpoint and connection identity.
        identity: Authenticated administrator identity supplied by the session dependency.
    """
    addresses = sorted(
        {
            str(item[4][0])
            for item in socket.getaddrinfo(
                target.host, target.port, type=socket.SOCK_STREAM
            )
        }
    )
    if not addresses:
        raise CertificateOperationError("The target could not be resolved.")
    return [
        "vcf_cert_lock:" + _digest([product, value])
        for value in [
            "identity:" + identity,
            *("address:" + address for address in addresses),
        ]
    ]


def _release(db: Session, state: dict[str, Any]) -> None:
    """Release only reservations still owned by this operation.

    Args:
        db: Database session holding operation records and target reservations.
        state: Public operation checkpoint and reviewed inputs.
    """
    db.execute(
        delete(Setting).where(
            Setting.key.in_(state["reservation_keys"]),
            Setting.value == state["operation_id"],
        )
    )


def _native(
    target: Target, product: str, info: dict[str, Any] | None = None
) -> NativeAdapter:
    """Construct the product-specific adapter with its reviewed identity binding.

    Args:
        target: Confirmed appliance endpoint and connection identity.
        product: Detected appliance product identifier.
        info: Public native discovery metadata.
    """
    if product == "sddc":
        native = SddcAdapter(target)
        if info is not None:
            native.configure_binding(info)
        return native
    return NativeAdapter(target, product)


def _inspect(
    db: Session, product: str, target: Target, credentials: Credentials
) -> dict[str, Any]:
    """Discover native identity, topology, permissions, and certificate prerequisites.

    Args:
        db: Database session holding operation records and target reservations.
        product: Detected appliance product identifier.
        target: Confirmed appliance endpoint and connection identity.
        credentials: Request-local administrator credentials, never persisted.
    """
    settings, profiles = _ready_ca(db, product)
    with _native(target, product) as native:
        if product == "srm" and credentials.username != "admin":
            raise CertificateOperationError(
                "Use SRM's native appliance administrator account, admin."
            )
        native.login(credentials)
        info = native.product_info()
        if not isinstance(info, dict) or not supported_version(product, info):
            raise CertificateOperationError(
                "Select a natively detected SRM or standalone vCenter 8.x or later, or initialized SDDC Manager 9.x."
            )
        if product in {"vcenter", "sddc"} and not native.vcenter_permissions(
            credentials
        ):
            raise CertificateOperationError(
                "Use an explicitly assigned SDDC Manager administrator account."
                if product == "sddc"
                else "The selected account requires CertificateManagement.Manage and CertificateManagement.Administer on this standalone vCenter."
            )
        native.current_certificate()
        served = PinnedHTTPS(target).probe()
        if served["sha256"] != target.fingerprint:
            raise CertificateOperationError(
                "The target certificate changed during discovery."
            )
        cert = x509.load_pem_x509_certificate(served["certificate_pem"].encode())
        if product == "srm":
            identity = str(info.get("hostname", ""))
            if identity in {"", "localhost", "localhost.localdomain"}:
                raise CertificateOperationError(
                    "Configure SRM's supported FQDN and DNS before preparation."
                )
            dns = native.srm_dns_settings()
            if dns.get("hostname") != identity:
                raise CertificateOperationError(
                    "SRM network identity is still changing. Reconcile native DNS first."
                )
            try:
                native._request("GET", "/appliance/configuration-manager/configuration")
            except RemoteError as exc:
                if str(exc) != "Appliance API returned HTTP 404":
                    raise
            else:
                raise CertificateOperationError(
                    "Registered SRM needs a coordinated native workflow. This standalone workflow requires an unregistered appliance."
                )
            clock = native._request("GET", "/appliance/settings/time")
            observed = clock.get("current_time")
            if (
                not isinstance(observed, (int, float))
                or abs(observed / 1000 - time.time()) > 300
            ):
                raise CertificateOperationError(
                    "Correct the native time source; the appliance clock differs by more than five minutes."
                )
            version = str(info["appliance_version"])
            topology = "Unregistered standalone appliance"
        elif product == "sddc":
            identity = str(info["identity"])
            version = str(info["version"])
            topology = "SDDC Manager's own resource in management domain " + str(
                info["domain_id"]
            )
        else:
            registrations = native.vcenter_registrations()
            if not standalone_vcenter(native.vcenter_ha(), registrations):
                raise CertificateOperationError(
                    "Linked vCenters, configured HA and unknown topology require the coordinated native product workflow."
                )
            # OS hostname can still be 'localhost' on an IP-PNID installation.
            # Use the native Lookup Service's registered vCenter SDK identity.
            endpoints = [
                urlsplit(url) for url in registrations[0]["endpoints"].split(",")
            ]
            identities = {
                endpoint.hostname
                for endpoint in endpoints
                if endpoint.scheme == "https"
                and endpoint.path == "/sdk"
                and not endpoint.username
                and not endpoint.password
                and endpoint.hostname
            }
            if len(identities) != 1:
                raise CertificateOperationError(
                    "Native vCenter registered identity is ambiguous."
                )
            identity = next(iter(identities))
            observed_clock = native._request("GET", "/api/appliance/system/time")
            observed = (
                observed_clock.get("seconds_since_epoch")
                if isinstance(observed_clock, dict)
                else None
            )
            if (
                not isinstance(observed, (int, float))
                or abs(observed - time.time()) > 300
            ):
                raise CertificateOperationError(
                    "Correct the native time source; the appliance clock differs by more than five minutes."
                )
            version = str(info["version"])
            topology = "Standalone vCenter; no VCHA configuration"
        if len(identity) > 253 or not re.fullmatch(r"[a-zA-Z0-9.:-]+", identity):
            raise CertificateOperationError(
                "Native appliance identity is not a valid hostname or IP address."
            )
        names = asdict(names_from_certificate(cert, product, identity))
        names["dns_names"], names["ip_addresses"] = (
            sorted(names["dns_names"]),
            sorted(names["ip_addresses"]),
        )
        try:
            target_addresses = {
                str(item[4][0])
                for item in socket.getaddrinfo(
                    target.host, target.port, type=socket.SOCK_STREAM
                )
            }
            for name in names["dns_names"]:
                resolved = {
                    str(item[4][0])
                    for item in socket.getaddrinfo(
                        name, target.port, type=socket.SOCK_STREAM
                    )
                }
                if not resolved.intersection(target_addresses):
                    raise CertificateOperationError(
                        "A discovered DNS SAN does not resolve to this appliance. Correct DNS before preparation."
                    )
        except OSError:
            raise CertificateOperationError(
                "A discovered DNS SAN cannot be resolved from Atlaso. Correct DNS before preparation."
            ) from None
        health = native.health()
        if not healthy_services(product, health):
            raise CertificateOperationError(
                "Restore native appliance and automatic service health before preparing a certificate."
            )
        if product == "srm":
            # Native metadata links and descriptions are not task evidence.
            health = {
                "list": [
                    {
                        "id": item["id"],
                        "name": item.get("name", item["id"]),
                        "startup_type": item["startup_type"],
                        "is_running": item["is_running"],
                    }
                    for item in _srm_service_rows(health)
                ]
            }
    return {
        "target": target.host,
        "product_info": {
            "product": product,
            "version": version,
            "identity": identity,
            **(
                {key: info[key] for key in ("role", "domain_id", "resource_id")}
                if product == "sddc"
                else {}
            ),
        },
        "identity": identity,
        "names": names,
        "current_certificate": _metadata(cert),
        "profiles": [{"id": p.id, "name": p.name} for p in profiles],
        "baseline_health": health,
        "prerequisites": [
            {
                "label": "Native APIs",
                "ok": True,
                "detail": "Authenticated read capabilities available. Native operations enforce CSR and installation privileges.",
            },
            {"label": "Topology", "ok": True, "detail": topology},
            {
                "label": "Product profile",
                "ok": bool(profiles),
                "detail": "Choose an enabled validated RSA profile.",
            },
        ],
        "supported": bool(profiles),
        "issuer_fingerprint": settings.root_fingerprint,
    }


def _srm_service_rows(health: Any) -> list[dict[str, Any]]:
    """Normalize the same service variants accepted by the native health check.

    Args:
        health: Native service health response.
    """
    rows = health.get("list", []) if isinstance(health, dict) else health
    normalized = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        service_id = item.get("id", item.get("service_name"))
        running = item.get("is_running")
        if running is None and isinstance(item.get("service_status"), str):
            running = item["service_status"].casefold() == "running"
        if (
            not isinstance(service_id, str)
            or not isinstance(item.get("startup_type"), str)
            or not isinstance(running, bool)
        ):
            continue
        normalized.append(
            {
                "id": service_id,
                "name": item.get("name", service_id),
                "startup_type": item["startup_type"],
                "is_running": running,
            }
        )
    return normalized


def _enqueue(db: Session, state: dict[str, Any], action: str) -> Job:
    """Create a durable task before scheduling its certificate worker.

    Args:
        db: Database session holding operation records and target reservations.
        state: Public operation checkpoint and reviewed inputs.
        action: Checkpoint or audit action being recorded.
    """
    job = Job(
        id="job_" + uuid4().hex[:12],
        type=JOB_TYPE,
        status="pending",
        created_by=state["actor"],
        task_config_json=_json(
            {"operation_id": state["operation_id"], "action": action}
        ),
    )
    db.add(job)
    state["job_id"], state["progress_percent"] = job.id, 0
    return job


def _revision(state: dict[str, Any]) -> str:
    """Bind approval to the exact reviewed public inputs and identities.

    Args:
        state: Public operation checkpoint and reviewed inputs.
    """
    return _digest(
        {
            key: state[key]
            for key in (
                "product_info",
                "names",
                "credential_reference",
                "ca_snapshot",
                "current_certificate",
                "replacement_certificate",
                "recovery_reference",
            )
        }
    )


def dispatch(
    db: Session,
    actor: str,
    operation: str,
    values: dict[str, Any],
    background_tasks: TaskDispatcher,
) -> dict[str, Any]:
    """Read native state or queue a single acknowledged mutation attempt.

    Args:
        db: Database session holding operation records and target reservations.
        actor: Submitting administrator username.
        operation: Requested certificate workflow action.
        values: Validated browser workflow input values.
        background_tasks: Request-owned scheduler for admitted certificate jobs.
    """
    try:
        return _dispatch(db, actor, operation, values, background_tasks)
    except (RemoteError, CertificateMaterialError) as exc:
        raise CertificateOperationError(str(exc)) from None
    except (ValueError, TypeError, KeyError, StopIteration) as exc:
        if isinstance(exc, CertificateOperationError):
            raise
        raise CertificateOperationError(
            "Native response or inputs are incomplete. Correct prerequisites and inspect again."
        ) from None


def _dispatch(
    db: Session,
    actor: str,
    operation: str,
    values: dict[str, Any],
    background_tasks: TaskDispatcher,
) -> dict[str, Any]:
    """Admit and execute an actor-bound browser workflow action.

    Args:
        db: Database session holding operation records and target reservations.
        actor: Submitting administrator username.
        operation: Requested certificate workflow action.
        values: Validated browser workflow input values.
        background_tasks: Request-owned scheduler for admitted certificate jobs.
    """
    _actor(db, actor)
    product, target = _target(values)
    if operation == "probe":
        return _probe(target)
    if operation != "reconcile":
        _confirmed(values, target)
    elif values.get("confirmed") is not True:
        raise CertificateOperationError(
            "Confirm the operation's recorded target before reconciliation."
        )
    reference = _reference(db, values)
    credentials = _credentials(db, values, reference)
    record_audit(
        db,
        actor=actor,
        action="use_vcf_certificate_credentials",
        resource_type=JOB_TYPE,
        detail=_json(
            {
                "operation": operation,
                "target": target.host,
                "credential_mode": reference["mode"],
                "vault_entry_id": reference.get("entry_id"),
            }
        ),
    )
    if operation == "inspect":
        result = _inspect(db, product, target, credentials)
        result.pop("baseline_health", None)
        return result
    if operation == "prepare":
        if (
            values.get("acknowledged") is not True
            or values.get("recovery_ready") is not True
        ):
            raise CertificateOperationError(
                "Acknowledge target-side key/CSR preparation, no external pending CSR, and a supported recovery point first."
            )
        recovery = str(values.get("recovery_reference", "")).strip()
        if (
            not recovery
            or len(recovery) > 500
            or any(ord(c) < 32 for c in recovery)
            or "://" in recovery
        ):
            raise CertificateOperationError(
                "Enter a supported recovery reference without credentials or URLs."
            )
        inspection = _inspect(db, product, target, credentials)
        names = _names(values, inspection["names"])
        profile_id = int(values.get("profile_id", 0))
        ca_snapshot = _ca_snapshot(db, product, profile_id)
        operation_id = uuid4().hex
        keys = _locks(product, target, inspection["identity"])
        state = {
            "operation_id": operation_id,
            "actor": actor,
            "product": product,
            "address": target.host,
            "port": target.port,
            "confirmed_tls_fingerprint": target.fingerprint,
            "credential_reference": reference,
            "identity": inspection["identity"],
            "product_info": inspection["product_info"],
            "names": names,
            "profile_id": profile_id,
            "ca_snapshot": ca_snapshot,
            "current_certificate": inspection["current_certificate"],
            "baseline_health": inspection["baseline_health"],
            "recovery_reference": recovery,
            "reservation_keys": keys,
            "state": "preparing",
            "checkpoint": "queued_preparation",
            "verification": {
                "installation": False,
                "exact_served_certificate": False,
                "strict_tls": False,
                "authenticated_login": False,
                "health": False,
            },
        }
        acquire_network_objects_write_lock(db)
        for key in keys:
            db.add(Setting(key=key, value=operation_id))
        row = Setting(key=PREFIX + operation_id, value="")
        db.add(row)
        job = _enqueue(db, state, "prepare")
        row.value = _json(state)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise CertificateOperationError(
                "Another operation reserves this target. Reconcile it before preparing another CSR."
            ) from None
        background_tasks.add_task(run_job, job.id, _manual(values, reference))
        return operation_status(db, actor, operation_id)
    operation_id = str(values.get("operation_id", ""))
    row, state = _state(db, operation_id, actor)
    if (
        state["product"],
        state["address"],
        state["port"],
        state["confirmed_tls_fingerprint"],
        state["credential_reference"],
    ) != (product, target.host, target.port, target.fingerprint, reference):
        raise CertificateOperationError(
            "Target or credential identity changed since preparation."
        )
    if operation == "reconcile":
        active_job = db.get(Job, state["job_id"])
        if (
            state["state"] in {"preparing", "installing"}
            and active_job
            and active_job.status in {"pending", "running"}
        ):
            return operation_status(db, actor, operation_id)
        return _reconcile(db, row, state, credentials)
    if state["state"] != "prepared":
        raise CertificateOperationError(
            "Prepare successfully before reviewing or installing. Reconcile interrupted operations first."
        )
    if operation == "review":
        _names(values, state["names"])
        reviewed_revision = _revision(state)
        _revalidate(db, state, credentials)
        # Native reads can be slow. Serialize the nonce write with execute and
        # reload after admission so those reads cannot restore stale checkpoints.
        acquire_network_objects_write_lock(db)
        db.refresh(row)
        state = json.loads(row.value)
        if state["state"] != "prepared" or _revision(state) != reviewed_revision:
            raise CertificateOperationError(
                "Operation changed during review. Reconcile or review its current state again."
            )
        nonce = secrets.token_hex(24)
        state["review_nonce"] = nonce
        token = _serializer().dumps(
            {
                "actor": actor,
                "operation_id": operation_id,
                "nonce": nonce,
                "revision": _revision(state),
            }
        )
        _save(db, row, state)
        return {
            "operation_id": operation_id,
            "token": token,
            "review": {
                "target": f"{state['address']} (port {state['port']})",
                "current_certificate": state["current_certificate"],
                "replacement_certificate": state["replacement_certificate"],
                "issuer": state["issuer"],
                "issuer_fingerprint_sha256": state["ca_snapshot"]["root"][
                    "fingerprint_sha256"
                ],
                "profile": state["ca_snapshot"]["profile"]["name"],
                "domain_id": state["product_info"].get("domain_id"),
                "resource_id": state["product_info"].get("resource_id"),
                "names": state["names"]["dns_names"] + state["names"]["ip_addresses"],
                "trust_changes": state["trust_changes"],
                "interruption": "Appliance management and dependent services may restart. Monitor this task for up to fifteen minutes.",
                "recovery_reference": state["recovery_reference"],
            },
        }
    if operation != "execute" or values.get("acknowledged") is not True:
        raise CertificateOperationError(
            "Approve the exact reviewed installation and trust changes explicitly."
        )
    try:
        approval = _serializer().loads(
            str(values.get("token", "")), max_age=REVIEW_SECONDS
        )
    except BadData:
        raise CertificateOperationError(
            "Review expired or is invalid. Review the prepared certificate again."
        ) from None
    acquire_network_objects_write_lock(db)
    db.refresh(row)
    state = json.loads(row.value)
    if (
        state["state"] != "prepared"
        or not state.get("review_nonce")
        or approval
        != {
            "actor": actor,
            "operation_id": operation_id,
            "nonce": state["review_nonce"],
            "revision": _revision(state),
        }
    ):
        raise CertificateOperationError(
            "Review was already used or this operation changed."
        )
    _revalidate(db, state, credentials)
    state.pop("review_nonce")
    state["state"], state["checkpoint"] = "installing", "queued_installation"
    job = _enqueue(db, state, "install")
    _save(db, row, state)
    background_tasks.add_task(run_job, job.id, _manual(values, reference))
    return operation_status(db, actor, operation_id)


def _manual(values: dict[str, Any], reference: dict[str, Any]) -> dict[str, Any] | None:
    """Extract manual credentials for this request without retaining them.

    Args:
        values: Validated browser workflow input values.
        reference: Persisted credential reference without a password.
    """
    return (
        {"username": values["username"], "password": values["password"]}
        if reference["mode"] == "manual"
        else None
    )


def _revalidate(db: Session, state: dict[str, Any], credentials: Credentials) -> None:
    """Recheck identity, prerequisites, CA, and reviewed certificate before a write.

    Args:
        db: Database session holding operation records and target reservations.
        state: Public operation checkpoint and reviewed inputs.
        credentials: Request-local administrator credentials, never persisted.
    """
    target = Target(state["address"], state["port"], state["confirmed_tls_fingerprint"])
    latest = _inspect(db, state["product"], target, credentials)
    if (
        any(
            latest[key] != state[key]
            for key in ("identity", "product_info", "names", "current_certificate")
        )
        or _ca_snapshot(db, state["product"], state["profile_id"])
        != state["ca_snapshot"]
    ):
        raise CertificateOperationError(
            "Target, topology, names, CA or profile changed. Reconcile before another review."
        )
    _material(db, state)
    if state["product"] == "sddc":
        with _native(target, "sddc", state["product_info"]) as native:
            assert isinstance(native, SddcAdapter)
            native.login(credentials)
            if (
                native.wait_csr(state["native_csr_task_id"], time.monotonic() + 30)
                != state["csr_pem"]
            ):
                raise CertificateOperationError(
                    "SDDC Manager's pending CSR changed. Preserve this operation and reconcile native state."
                )


def _material(db: Session, state: dict[str, Any]) -> tuple[str, str]:
    """Validate the operation certificate against its CSR and issuing CA.

    Args:
        db: Database session holding operation records and target reservations.
        state: Public operation checkpoint and reviewed inputs.
    """
    certificate = db.get(CaCertificate, state["certificate_id"])
    settings, _ = _ready_ca(db, state["product"], state["profile_id"])
    if (
        certificate is None
        or certificate.status != "issued"
        or not certificate.enabled
        or certificate.private_key_encrypted
        or certificate.csr_text != state["csr_pem"]
    ):
        raise CertificateOperationError(
            "This operation's public CSR certificate is unavailable or changed."
        )
    root = x509.load_pem_x509_certificate(settings.root_certificate_pem.encode())
    leaf = validate_issued_certificate(
        state["csr_pem"].encode(),
        certificate.certificate_pem.encode(),
        state["product"],
        set(state["names"]["dns_names"]),
        set(state["names"]["ip_addresses"]),
        root,
    )
    if (
        "replacement_certificate" in state
        and _metadata(leaf) != state["replacement_certificate"]
    ):
        raise CertificateOperationError(
            "The issued certificate changed after preparation."
        )
    return certificate.certificate_pem, public_chain_pem(
        settings.root_certificate_pem.encode(), root
    ).decode()


def _csr_spec(state: dict[str, Any], settings: CaSettings) -> dict[str, Any]:
    """Build the native product-specific target-owned CSR request.

    Args:
        state: Public operation checkpoint and reviewed inputs.
        settings: Current appliance CA configuration.
    """
    names = state["names"]
    if state["product"] == "sddc":
        info = state["product_info"]
        return {
            "csrGenerationSpec": {
                "country": settings.country,
                "state": settings.state or "Lab",
                "locality": settings.locality or "Lab",
                "organization": settings.organization or "Atlaso",
                "organizationUnit": settings.organizational_unit or "Infrastructure",
                "keySize": str(state["ca_snapshot"]["profile"]["key_size"]),
                "keyAlgorithm": "RSA",
            },
            "resources": [
                {
                    "resourceId": info["resource_id"],
                    "fqdn": info["identity"],
                    "type": "SDDC_MANAGER",
                    "sans": sorted(set(names["dns_names"] + names["ip_addresses"])),
                }
            ],
        }
    if state["product"] == "srm":
        return {
            "common_name": names["common_name"],
            "organization": settings.organization or "Atlaso",
            "organization_unit": settings.organizational_unit,
            "country": settings.country,
            "fqdn": ",".join(names["dns_names"]),
            "ip": ",".join(names["ip_addresses"]),
        }
    return {
        "common_name": names["common_name"],
        "key_size": state["ca_snapshot"]["profile"]["key_size"],
        "organization": settings.organization or "Atlaso",
        "organization_unit": "",
        "country": settings.country,
        "locality": settings.locality or "Lab",
        "state_or_province": settings.state or "Lab",
        "email_address": "",
        "subject_alt_name": sorted(set(names["dns_names"] + names["ip_addresses"])),
    }


def run_job(job_id: str, manual_values: dict[str, Any] | None = None) -> None:
    """Dispatch one mutation attempt, retaining unresolved target reservations.

    Args:
        job_id: Durable task identifier for this certificate operation.
        manual_values: Request-local manual credentials, never written to task state.
    """
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        if job is None or job.type != JOB_TYPE or job.status != "pending":
            return
        plan = json.loads(job.task_config_json)
        row, state = _state(db, plan["operation_id"], job.created_by)
        job.status, job.started_at = "running", utcnow()
        db.commit()
        try:
            _actor(db, state["actor"])
            reference = state["credential_reference"]
            values = manual_values or {
                "credential_vault_id": reference.get("vault_id"),
                "credential_entry_id": reference.get("entry_id"),
            }
            credentials = _credentials(db, values, reference)
            target = Target(
                state["address"], state["port"], state["confirmed_tls_fingerprint"]
            )
            if plan["action"] == "prepare":
                latest = _inspect(db, state["product"], target, credentials)
                if (
                    any(
                        latest[key] != state[key]
                        for key in (
                            "identity",
                            "product_info",
                            "names",
                            "current_certificate",
                        )
                    )
                    or _ca_snapshot(db, state["product"], state["profile_id"])
                    != state["ca_snapshot"]
                ):
                    raise CertificateOperationError(
                        "Preparation prerequisites changed after acknowledgement."
                    )
                settings, _ = _ready_ca(db, state["product"], state["profile_id"])
                spec = _csr_spec(state, settings)
                with _native(target, state["product"], state["product_info"]) as native:
                    native.login(credentials)
                    _actor(db, state["actor"])
                    state["checkpoint"] = "csr_dispatch_pending"
                    _save(db, row, state)
                    if isinstance(native, SddcAdapter):
                        state["native_csr_task_id"] = native.start_csr(spec)
                        state["checkpoint"] = "csr_task_submitted"
                        _save(db, row, state)
                        csr_pem = native.wait_csr(
                            state["native_csr_task_id"],
                            time.monotonic() + READINESS_SECONDS,
                        )
                    else:
                        csr_pem = native.generate_csr(spec)
                    state["csr_pem"], state["checkpoint"] = csr_pem, "csr_received"
                    _save(db, row, state)
                _issue(db, row, state)
                if state["product"] == "sddc":
                    _sddc_validation(db, row, state, credentials)
                job.status = "succeeded"
            else:
                _revalidate(db, state, credentials)
                leaf, root = _material(db, state)
                if state["product"] == "sddc":
                    _sddc_validation(db, row, state, credentials, installing=True)
                with _native(target, state["product"], state["product_info"]) as native:
                    native.login(credentials)
                    _actor(db, state["actor"])
                    if state["product"] == "vcenter":
                        state["checkpoint"] = "root_import_dispatch_pending"
                        _save(db, row, state)
                        native.import_and_verify_root(
                            root, state["ca_snapshot"]["root"]["fingerprint_sha256"]
                        )
                    state["checkpoint"] = "installation_dispatch_pending"
                    _save(db, row, state)
                    try:
                        if isinstance(native, SddcAdapter):
                            state["native_install_task_id"] = native.start_install(
                                leaf, [root]
                            )
                            _save(db, row, state)
                        else:
                            native.install_csr(leaf, [root])
                            state["verification"]["installation"] = True
                    except RemoteError:
                        # A dropped response may mean installation completed.
                        # Verify the result; never repeat the remote write.
                        pass
                    native.session = None
                state["checkpoint"] = "verifying_readiness"
                _save(db, row, state)
                deadline = time.monotonic() + READINESS_SECONDS
                while time.monotonic() < deadline:
                    _actor(db, state["actor"])
                    if _verify(state, credentials, root, deadline):
                        state["state"], state["checkpoint"] = "succeeded", "verified"
                        _release(db, state)
                        job.status = "succeeded"
                        break
                    _save(db, row, state)
                    time.sleep(5)
                else:
                    raise CertificateOperationError(
                        "Readiness did not complete within fifteen minutes. Reconcile without repeating installation. Use the reviewed recovery point for native repair."
                    )
        except Exception as exc:  # noqa: BLE001 - every unexpected worker failure must preserve remote uncertainty.
            db.rollback()
            row, state = _state(db, plan["operation_id"], job.created_by)
            state["state"] = "needs_recovery"
            state["error"] = (
                str(exc)
                if isinstance(
                    exc,
                    (CertificateOperationError, CertificateMaterialError, RemoteError),
                )
                else "Operation interrupted. Reconcile before retrying; native writes may have occurred."
            )
            job = db.get(Job, job_id)
            if job is not None:
                job.status, job.error = "failed", state["error"]
        finally:
            state["progress_percent"] = 100
            row.value = _json(state)
            if job is not None:
                job.finished_at, job.progress_percent = utcnow(), 100
                job.result = _json(
                    {
                        "operation_id": state["operation_id"],
                        "state": state["state"],
                        "verification": state["verification"],
                    }
                )
            record_audit(
                db,
                actor=state["actor"],
                action="vcf_certificate_" + plan["action"],
                resource_type=JOB_TYPE,
                resource_id=job_id,
                success=state["state"] in {"prepared", "succeeded"},
                detail=_json(
                    {
                        "operation_id": state["operation_id"],
                        "checkpoint": state["checkpoint"],
                        "verification": state["verification"],
                    }
                ),
                post_commit_best_effort=True,
            )
            db.commit()


def _issue(db: Session, row: Setting, state: dict[str, Any]) -> None:
    """Issue the captured CSR through the admitted shared CA writer.

    Args:
        db: Database session holding operation records and target reservations.
        row: Persistent public operation Setting row.
        state: Public operation checkpoint and reviewed inputs.
    """
    csr_pem = state["csr_pem"]
    csr = validate_product_csr(
        csr_pem.encode(),
        state["product"],
        set(state["names"]["dns_names"]),
        set(state["names"]["ip_addresses"]),
    )
    common_names = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if len(common_names) != 1 or common_names[0].value != state["names"]["common_name"]:
        raise CertificateOperationError(
            "Native CSR common name differs from the reviewed identity."
        )
    acquire_network_objects_write_lock(db)
    settings, profiles = _ready_ca(db, state["product"], state["profile_id"])
    if _ca_snapshot(db, state["product"], state["profile_id"]) != state["ca_snapshot"]:
        raise CertificateOperationError(
            "CA or profile changed after CSR generation. Reconcile the captured CSR."
        )
    certificate = CaCertificate(
        common_name=state["names"]["common_name"],
        profile_id=state["profile_id"],
        subject_alt_names="\n".join(state["names"]["dns_names"]),
        ip_addresses="\n".join(state["names"]["ip_addresses"]),
        csr_text=csr_pem,
        status="csr-staged",
        enabled=True,
        description="Native appliance certificate operation " + state["operation_id"],
    )
    db.add(certificate)
    db.flush()
    if not ca.issue_certificate(settings, profiles, certificate):
        raise CertificateOperationError(
            "The shared CA did not issue this operation's CSR."
        )
    state["certificate_id"] = certificate.id
    leaf, root = _material(db, state)
    state.update(
        replacement_certificate=_metadata(
            x509.load_pem_x509_certificate(leaf.encode())
        ),
        issuer=x509.load_pem_x509_certificate(root.encode()).subject.rfc4514_string(),
        trust_changes=[
            "Ensure the reviewed root chain is in vCenter's trusted root store before replacing Machine SSL."
            if state["product"] == "vcenter"
            else "Install the reviewed server certificate and issuer chain. Client and peer trust must be configured separately."
        ],
        state="preparing" if state["product"] == "sddc" else "prepared",
        checkpoint="certificate_issued"
        if state["product"] == "sddc"
        else "certificate_prepared",
    )
    state.pop("error", None)
    _save(db, row, state)


def _sddc_validation(
    db: Session,
    row: Setting,
    state: dict[str, Any],
    credentials: Credentials,
    *,
    installing: bool = False,
) -> None:
    """Validate the exact issued material natively without repeating certificate writes.

    Args:
        db: Database session holding operation records and target reservations.
        row: Persistent public operation Setting row.
        state: Public operation checkpoint and reviewed inputs.
        credentials: Request-local administrator credentials, never persisted.
        installing: Whether the worker is performing reviewed replacement.
    """
    leaf, root = _material(db, state)
    target = Target(state["address"], state["port"], state["confirmed_tls_fingerprint"])
    with _native(target, "sddc", state["product_info"]) as native:
        assert isinstance(native, SddcAdapter)
        native.login(credentials)
        if not state.get("native_validation_id"):
            state["checkpoint"] = "validation_dispatch_pending"
            _save(db, row, state)
            state["native_validation_id"] = native.start_validation(leaf, [root])
            state["checkpoint"] = "validation_task_submitted"
            _save(db, row, state)
        native.wait_validation(
            state["native_validation_id"], time.monotonic() + READINESS_SECONDS
        )
    state["state"] = "installing" if installing else "prepared"
    state["checkpoint"] = (
        "queued_installation" if installing else "certificate_prepared"
    )
    state.pop("error", None)
    _save(db, row, state)


def _verify(
    state: dict[str, Any],
    credentials: Credentials,
    root: str,
    deadline: float | None = None,
) -> bool:
    """Verify fresh TLS, exact leaf, authentication, and native health separately.

    Args:
        state: Public operation checkpoint and reviewed inputs.
        credentials: Request-local administrator credentials, never persisted.
        root: Reviewed public CA root certificate.
        deadline: Absolute monotonic deadline bounding remote work.
    """
    expected = state["replacement_certificate"]["fingerprint_sha256"].lower()
    try:
        target = Target(
            state["identity"],
            state["port"],
            expected,
            connect_host=state["address"],
            strict_tls=True,
            ca_pem=root,
            deadline=deadline,
        )
        served = PinnedHTTPS(target).probe()
        if served["sha256"] != expected:
            return False
        state["verification"].update(
            exact_served_certificate=True, strict_tls=True, installation=True
        )
        with _native(target, state["product"], state["product_info"]) as native:
            native.login(credentials)
            state["verification"]["authenticated_login"] = True
            state["verification"]["health"] = healthy_services(
                state["product"], native.health(), state["baseline_health"]
            )
            if (
                isinstance(native, SddcAdapter)
                and state.get("native_install_task_id")
                and not native.task_complete(state["native_install_task_id"])
            ):
                return False
        return state["verification"]["health"] is True
    except RemoteError, ValueError, KeyError:
        return False


def _reconcile(
    db: Session, row: Setting, state: dict[str, Any], credentials: Credentials
) -> dict[str, Any]:
    """Resolve recorded remote state without blindly repeating uncertain writes.

    Args:
        db: Database session holding operation records and target reservations.
        row: Persistent public operation Setting row.
        state: Public operation checkpoint and reviewed inputs.
        credentials: Request-local administrator credentials, never persisted.
    """
    checkpoint = state["checkpoint"]
    if state["state"] == "succeeded":
        return operation_status(db, state["actor"], state["operation_id"])
    if state["state"] == "prepared":
        _revalidate(db, state, credentials)
        return operation_status(db, state["actor"], state["operation_id"])
    if checkpoint == "queued_preparation":
        # No worker crossed the durable pre-dispatch checkpoint.
        state["state"], state["checkpoint"] = "failed", "reconciled_not_dispatched"
        _release(db, state)
        _save(db, row, state)
        return operation_status(db, state["actor"], state["operation_id"])
    if state["product"] == "sddc" and checkpoint == "csr_task_submitted":
        target = Target(
            state["address"], state["port"], state["confirmed_tls_fingerprint"]
        )
        with _native(target, "sddc", state["product_info"]) as native:
            assert isinstance(native, SddcAdapter)
            native.login(credentials)
            state["csr_pem"] = native.wait_csr(
                state["native_csr_task_id"], time.monotonic() + 30
            )
            state["checkpoint"] = "csr_received"
            _save(db, row, state)
        checkpoint = "csr_received"
    if checkpoint == "csr_received" and state.get("csr_pem"):
        _issue(db, row, state)  # Reuse the captured CSR; no remote regeneration.
        if state["product"] == "sddc":
            _sddc_validation(db, row, state, credentials)
        return operation_status(db, state["actor"], state["operation_id"])
    if state["product"] == "sddc" and checkpoint in {
        "certificate_issued",
        "validation_task_submitted",
        "validation_dispatch_pending",
    }:
        _revalidate(db, state, credentials)
        _sddc_validation(db, row, state, credentials)
        return operation_status(db, state["actor"], state["operation_id"])
    if checkpoint in {"queued_installation", "root_import_dispatch_pending"}:
        # The install checkpoint was never reached. Readback and a new review
        # can resume without repeating an uncertain replacement.
        _revalidate(db, state, credentials)
        state["state"], state["checkpoint"] = "prepared", "certificate_prepared"
        state.pop("review_nonce", None)
        state.pop("error", None)
        _save(db, row, state)
        return operation_status(db, state["actor"], state["operation_id"])
    if "replacement_certificate" in state:
        _, root = _material(db, state)
        if _verify(state, credentials, root):
            state["state"], state["checkpoint"] = "succeeded", "reconciled_verified"
            state.pop("error", None)
            _release(db, state)
            _save(db, row, state)
            return operation_status(db, state["actor"], state["operation_id"])
    raise CertificateOperationError(
        "Remote state remains unresolved; the reservation is retained. Do not regenerate the CSR or repeat replacement. Inspect the native appliance and use its supported recovery procedure, retaining the public CSR and task history."
    )


def recover_interrupted_jobs(db: Session) -> int:
    """Retain reservations and public checkpoints after an Atlaso restart.

    Args:
        db: Database session holding operation records and target reservations.
    """
    jobs = list(
        db.scalars(
            select(Job).where(
                Job.type == JOB_TYPE, Job.status.in_(["pending", "running"])
            )
        )
    )
    for job in jobs:
        try:
            plan = json.loads(job.task_config_json)
            row, state = _state(db, plan["operation_id"], job.created_by)
        except (CertificateOperationError, ValueError, TypeError, KeyError):
            # A retained Job may predate preservation of runtime Settings, or
            # its public state may be damaged. Do not block appliance startup
            # or release any surviving target reservation without evidence.
            job.status = "failed"
            job.error = (
                "Certificate operation records are missing or invalid. "
                "Surviving reservations are retained. Inspect native appliance "
                "state and task history before any CSR or replacement retry."
            )
            job.finished_at = utcnow()
            continue
        state.update(
            state="needs_recovery",
            error="Atlaso restarted. Reconcile this recorded operation before another CSR or installation.",
        )
        row.value = _json(state)
        job.status, job.error, job.finished_at = "failed", state["error"], utcnow()
    db.commit()
    return len(jobs)
