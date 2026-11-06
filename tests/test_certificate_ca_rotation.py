"""Contract tests for ordinary CA rotation on an admitted management listener."""

from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/interop"))
import certificate_ca_rotation as rotation  # noqa: E402 - Interop module uses sibling imports.

_ADDRESS = "192.168.77.30"
_MAC = "00:50:56:2a:11:22"
_OLD_ID = 41
_NEW_ID = 42
_JOB_ID = "ca-rotation-job-7"
_PASSWORD = "synthetic-password-marker"
_HTML_MARKER = "synthetic-html-marker"
_TASK_MARKER = "synthetic-task-private-result"


def _public_certificate(common_name: str, *, address: str | None = None) -> tuple[str, str]:
    """Create an ephemeral public certificate fixture and its normalized digest."""
    key = ed25519.Ed25519PrivateKey.generate()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
    )
    not_before = datetime(2025, 1, 1, tzinfo=UTC)
    not_after = datetime(2035, 1, 1, tzinfo=UTC)
    if hasattr(builder, "not_valid_before_utc"):
        builder = builder.not_valid_before_utc(not_before).not_valid_after_utc(not_after)
    else:
        builder = builder.not_valid_before(not_before.replace(tzinfo=None)).not_valid_after(
            not_after.replace(tzinfo=None)
        )
    if address:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(address))]),
            critical=False,
        )
    certificate = builder.sign(key, algorithm=None)
    pem = certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
    digest = hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()
    return pem, digest


class RotationClient:
    """Stateful fake HTTP and pinned TLS client for one management listener."""

    def __init__(self) -> None:
        self.url = f"https://{_ADDRESS}"
        self.connect_ip = _ADDRESS
        self.root_pem, self.root_sha256 = _public_certificate("synthetic root")
        self.changed_root_pem, _ = _public_certificate("changed synthetic root")
        self.old_pem, self.old_sha256 = _public_certificate("old management", address=_ADDRESS)
        self.new_pem, self.new_sha256 = _public_certificate("replacement management", address=_ADDRESS)
        self.old_status = "issued"
        self.old_owner = "appliance:https"
        self.old_can_revoke = True
        self.old_can_replace = False
        self.new_status = "absent"
        self.has_management_owner = True
        self.duplicate_management_owner = False
        self.web_terminal_enabled = False
        self.web_terminal_interfaces: list[str] = []
        self.address = _ADDRESS
        self.expected_old_served = True
        self.final_served_old_leaf = False
        self.malformed_original_pem = False
        self.baseline_pending = False
        self.review_variant = "valid"
        self.task_status = "succeeded"
        self.task_type = "appliance-apply"
        self.task_dry_run = False
        self.change_root_after_task = False
        self.change_address_after_task = False
        self.change_terminal_after_task = False
        self.task_completed = False
        self.mutations: list[str] = []
        self.request_calls: list[tuple[str, dict[str, Any] | None]] = []
        self.json_calls: list[tuple[str, dict[str, Any] | None]] = []
        self.submit_form: dict[str, Any] | None = None

    def _physical_row(self) -> dict[str, Any]:
        address = "192.168.77.31" if self.task_completed and self.change_address_after_task else self.address
        return {
            "id": 1,
            "name": "eth0",
            "role": "management",
            "ipv4_method": "static",
            "ip_cidr": f"{address}/24",
            "host_ip_cidr": None,
            "ipv6_enabled": False,
            "ipv6_method": "disabled",
            "mac_address": _MAC,
            "admin_up": True,
        }

    def _certificate_rows(self) -> list[dict[str, Any]]:
        rows = []
        if self.has_management_owner:
            rows.append(
                {
                    "id": _OLD_ID,
                    "managed_owner": self.old_owner,
                    "status": self.old_status,
                    "enabled": self.old_status == "issued",
                    "fingerprint": self.old_sha256,
                    "can_export_certificate": self.old_status == "issued",
                }
            )
        if self.duplicate_management_owner:
            rows.append(
                {
                    "id": 90,
                    "managed_owner": "appliance:https",
                    "status": "issued",
                    "enabled": True,
                    "fingerprint": "9" * 64,
                    "can_export_certificate": True,
                }
            )
        if self.new_status != "absent":
            rows.append(
                {
                    "id": _NEW_ID,
                    "managed_owner": "appliance:https",
                    "status": "issued" if self.new_status == "issued" else self.new_status,
                    "enabled": self.new_status == "issued",
                    "fingerprint": self.new_sha256,
                    "can_export_certificate": self.new_status == "issued",
                }
            )
        if self.old_status == "revoked" and self.old_owner.startswith("retired-revoked:"):
            rows[0]["managed_owner"] = self.old_owner
        return rows

    def _interfaces_html(self) -> str:
        payload = html.escape(json.dumps([self._physical_row()]), quote=True)
        return (
            f'<table id="physical-interfaces-table" data-interfaces="{payload}" data-csrf="csrf-public">'
            f"{_HTML_MARKER}</table>"
        )

    def _settings_html(self) -> str:
        enabled = self.web_terminal_enabled
        if self.task_completed and self.change_terminal_after_task:
            enabled = not enabled
        checked = " checked" if enabled else ""
        interfaces = self.web_terminal_interfaces
        if self.task_completed and self.change_terminal_after_task:
            interfaces = ["eth0"] if enabled else []
        terminal_rows = "".join(
            f'<input name="web_terminal_interfaces" value="{html.escape(value, quote=True)}">'
            for value in interfaces
        )
        return (
            f'<input name="web_terminal_enabled"{checked}>'
            f"{terminal_rows}<textarea name=\"external_dns_servers\">192.0.2.53</textarea>{_HTML_MARKER}"
        )

    def _certificate_authority_html(self) -> str:
        payload = html.escape(json.dumps(self._certificate_rows()), quote=True)
        return f'<table id="ca-certificates-table" data-certificates="{payload}">{_HTML_MARKER}</table>'

    def _requests_html(self) -> str:
        rows = [
            {
                "id": _OLD_ID,
                "status": self.old_status,
                "can_revoke": self.old_can_revoke,
                "can_replace": self.old_can_replace,
            }
        ]
        payload = html.escape(json.dumps(rows), quote=True)
        return f'<table id="ca-requests-table" data-rows="{payload}" data-csrf="csrf-requests">'

    def request(
        self,
        path: str,
        form: dict[str, Any] | None = None,
        *,
        accept: str | None = None,
    ) -> tuple[int, str]:
        self.request_calls.append((path, form))
        if form is not None and path.endswith(f"/{_OLD_ID}/revoke"):
            self.mutations.append("revoke")
            self.old_status = "revoked"
            self.old_owner = f"retired-revoked:{_OLD_ID}"
            self.old_can_revoke = False
            self.old_can_replace = True
            return 200, "{}"
        if form is not None and path.endswith(f"/{_OLD_ID}/replace"):
            self.mutations.append("replace")
            self.new_status = "planned"
            return 200, "{}"
        if path == "/ui/management/physical-interfaces":
            return 200, self._interfaces_html()
        if path == "/ui/management/settings":
            return 200, self._settings_html()
        if path == "/ui/management/certificate-authority":
            # The production inventory GET reconciles and issues planned rows
            # before serializing them, independently of global Apply.
            if self.new_status == "planned":
                self.new_status = "issued"
            return 200, self._certificate_authority_html()
        if path == "/certificate-authority/downloads/root-ca.pem":
            return 200, self.changed_root_pem if self.task_completed and self.change_root_after_task else self.root_pem
        if path == f"/certificate-authority/certificates/{_OLD_ID}/downloads/certificate.pem":
            return 200, "malformed public certificate" if self.malformed_original_pem else self.old_pem
        if path == f"/certificate-authority/certificates/{_NEW_ID}/downloads/certificate.pem":
            return 200, self.new_pem
        if path == "/ui/management/ca/requests":
            return 200, self._requests_html()
        raise AssertionError(f"Unexpected fake HTTP request: {path}")

    def json(self, path: str, form: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
        self.json_calls.append((path, form))
        if path == "/ui/management/appliance-apply/review":
            if self.baseline_pending:
                return 200, {
                    "active_task": None,
                    "units": [{"id": "network", "changed": True, "valid": True}],
                    "pending_count": 1,
                    "initial_apply_required": False,
                }
            return 200, {"active_task": None, "units": [], "pending_count": 0, "initial_apply_required": False}
        if path.startswith("/ui/management/appliance-apply/review?"):
            selected_by_query = parse_qs(urlsplit(path).query).get("selected_units")
            if selected_by_query != ["ca"]:
                raise AssertionError("CA rotation review must select only the CA root.")
            rows = [
                {"id": "ca", "changed": True, "selected": True, "valid": True},
                {"id": "appliance_settings", "changed": False, "selected": True, "valid": True},
                {"id": "public_services", "changed": False, "selected": True, "valid": True},
            ]
            if self.review_variant == "missing_public_services":
                rows[-1]["selected"] = False
            elif self.review_variant == "wrong_order":
                rows[0], rows[1] = rows[1], rows[0]
            elif self.review_variant == "unrelated_changed":
                rows.append({"id": "network", "changed": True, "selected": False, "valid": True})
            elif self.review_variant == "invalid_selected":
                rows[1]["valid"] = False
            return 200, {
                "active_task": None,
                "plan_error": None,
                "requested_units": ["ca"],
                "plan_token": "synthetic-plan-token",
                "units": rows,
            }
        if path == "/ui/management/appliance-apply":
            self.mutations.append("submit")
            self.submit_form = dict(form or {})
            return 202, {"job_id": _JOB_ID, "status_url": f"/tasks/{_JOB_ID}/status"}
        if path == f"/tasks/{_JOB_ID}/status":
            self.task_completed = True
            if self.task_status == "succeeded":
                self.new_status = "issued"
                self.old_owner = f"retired-revoked:{_OLD_ID}"
                self.old_status = "revoked"
            return 200, {
                "task": {
                    "id": _JOB_ID,
                    "type": self.task_type,
                    "status": self.task_status,
                    "dry_run": self.task_dry_run,
                    "result": _TASK_MARKER,
                }
            }
        raise AssertionError(f"Unexpected fake JSON request: {path}")

    def interface(self, name: str) -> tuple[dict[str, Any], str]:
        assert name == "eth0"
        return self._physical_row(), "csrf-public"

    def tls_identity(self) -> dict[str, Any]:
        use_old = not self.task_completed or self.final_served_old_leaf
        return {
            "sha256": self.old_sha256 if use_old else self.new_sha256,
            "ip_sans": [_ADDRESS],
        }


def _exercise(client: RotationClient, *, expected_root_sha256: str | None = None) -> dict[str, Any]:
    return rotation.exercise_ca_rotation(
        client,
        certificate_id=_OLD_ID,
        expected_web_terminal=client.web_terminal_enabled,
        username="synthetic-operator",
        password=_PASSWORD,
        expected_root_sha256=expected_root_sha256 or client.root_sha256,
        interface_name="eth0",
        expected_mac=_MAC,
        expected_address=_ADDRESS,
    )


@pytest.mark.parametrize(
    ("enabled", "interfaces"),
    [(False, []), (False, ["eth0"]), (True, ["eth0"])],
)
def test_exercise_ca_rotation_revokes_replaces_reviews_and_proves_served_leaf(
    enabled: bool, interfaces: list[str],
) -> None:
    client = RotationClient()
    client.web_terminal_enabled = enabled
    client.web_terminal_interfaces = interfaces

    evidence = _exercise(client)

    assert client.mutations == ["revoke", "replace", "submit"]
    assert evidence["original_certificate_id"] == _OLD_ID
    assert evidence["replacement_certificate_id"] == _NEW_ID
    assert evidence["root_sha256"] == client.root_sha256
    assert evidence["original_leaf_sha256"] == client.old_sha256
    assert evidence["replacement_leaf_sha256"] == client.new_sha256
    assert evidence["served_leaf_sha256"] == client.new_sha256
    assert evidence["web_terminal_enabled"] is enabled
    assert evidence["review_requested_units"] == ["ca"]
    assert evidence["review_selected_units"] == ["ca", "appliance_settings", "public_services"]
    assert evidence["task_id"] == _JOB_ID and evidence["task_status"] == "succeeded"
    assert client.submit_form == {
        "csrf": "csrf-public",
        "reviewed_plan": "synthetic-plan-token",
        "requested_units": ["ca"],
        "selected_units": ["ca", "appliance_settings", "public_services"],
    }
    assert set(evidence) == {
        "schema",
        "interface",
        "address",
        "mac",
        "web_terminal_enabled",
        "root_sha256",
        "original_certificate_id",
        "original_leaf_sha256",
        "replacement_certificate_id",
        "replacement_leaf_sha256",
        "served_leaf_sha256",
        "review_requested_units",
        "review_selected_units",
        "task_id",
        "task_status",
    }
    public_evidence = json.dumps(evidence)
    assert _PASSWORD not in public_evidence
    assert _HTML_MARKER not in public_evidence
    assert _TASK_MARKER not in public_evidence
    assert "PRIVATE KEY" not in public_evidence
    assert client.old_pem not in public_evidence and client.new_pem not in public_evidence


@pytest.mark.parametrize(
    ("defect", "expected_web_terminal", "reason"),
    [
        ("pending", False, "requires_clean_applied_baseline"),
        ("missing_owner", False, None),
        ("ambiguous_owner", False, None),
        ("malformed_public_pem", False, "public_certificate_download_invalid"),
        ("address_mismatch", False, "management_address_binding_mismatch"),
        ("web_terminal_mismatch", True, "web_terminal_state_mismatch"),
    ],
)
def test_preflight_refusal_does_not_mutate_or_emit_evidence(
    defect: str,
    expected_web_terminal: bool,
    reason: str | None,
) -> None:
    client = RotationClient()
    if defect == "pending":
        client.baseline_pending = True
    elif defect == "missing_owner":
        client.has_management_owner = False
    elif defect == "ambiguous_owner":
        client.duplicate_management_owner = True
    elif defect == "malformed_public_pem":
        client.malformed_original_pem = True
    elif defect == "address_mismatch":
        client.address = "192.168.77.31"
    elif defect == "web_terminal_mismatch":
        client.web_terminal_enabled = False

    with pytest.raises(rotation.Refusal) as caught:
        rotation.exercise_ca_rotation(
            client,
            certificate_id=_OLD_ID,
            expected_web_terminal=expected_web_terminal,
            username="synthetic-operator",
            password=_PASSWORD,
            expected_root_sha256=client.root_sha256,
            interface_name="eth0",
            expected_mac=_MAC,
            expected_address=_ADDRESS,
        )
    if reason:
        assert reason in str(caught.value)

    assert client.mutations == []


def test_receipt_pinned_root_mismatch_refuses_before_revocation() -> None:
    """Require the authenticated root PEM to match the admission digest before mutation."""
    client = RotationClient()

    with pytest.raises(rotation.Refusal, match="root_ca_receipt_pin_mismatch"):
        _exercise(client, expected_root_sha256="f" * 64)

    assert client.mutations == []


@pytest.mark.parametrize(
    ("review_variant", "reason"),
    [
        ("missing_public_services", "ca_consumer_replay_missing"),
        ("wrong_order", "ca_consumer_order_invalid"),
        ("unrelated_changed", "ca_only_pending_scope_mismatch"),
        ("invalid_selected", "ca_only_review_invalid"),
    ],
)
def test_ca_review_refusal_never_submits_or_rolls_back_rotation(review_variant: str, reason: str) -> None:
    client = RotationClient()
    client.review_variant = review_variant

    with pytest.raises(rotation.Refusal, match=reason):
        _exercise(client)

    assert client.mutations == ["revoke", "replace"]
    assert client.mutations.count("revoke") == 1
    assert client.mutations.count("replace") == 1
    assert "submit" not in client.mutations


@pytest.mark.parametrize(
    ("defect", "reason"),
    [
        ("failed_task", "ca_apply_task_failed"),
        ("running_task", "ca_apply_task_failed"),
        ("wrong_task_type", "ca_apply_task_failed"),
        ("dry_run_task", "ca_apply_task_failed"),
        ("changed_address", "management_address_binding_mismatch"),
        ("changed_web_terminal", "web_terminal_state_mismatch"),
        ("changed_root", "root_ca_changed_during_apply"),
        ("old_served_leaf", "served_management_certificate_mismatch"),
    ],
)
def test_post_submit_failure_preserves_task_evidence_without_retry_or_rollback(
    monkeypatch: pytest.MonkeyPatch,
    defect: str,
    reason: str,
) -> None:
    client = RotationClient()
    if defect == "failed_task":
        client.task_status = "failed"
    elif defect == "changed_address":
        client.change_address_after_task = True
    elif defect == "changed_web_terminal":
        client.change_terminal_after_task = True
    elif defect == "old_served_leaf":
        client.final_served_old_leaf = True
    elif defect == "wrong_task_type":
        monkeypatch.setattr(
            rotation,
            "wait_task",
            lambda *_args: ({"id": _JOB_ID, "type": "certificate-export", "status": "succeeded"}, client),
        )
    elif defect == "dry_run_task":
        client.task_dry_run = True
    elif defect == "changed_root":
        client.change_root_after_task = True
    elif defect == "running_task":
        monkeypatch.setattr(
            rotation,
            "wait_task",
            lambda *_args: ({"id": _JOB_ID, "status": "running"}, client),
        )

    with pytest.raises(rotation.Refusal, match=reason):
        _exercise(client)

    assert client.mutations == ["revoke", "replace", "submit"]
    assert client.mutations.count("submit") == 1
    assert client.mutations.count("revoke") == 1
    assert client.mutations.count("replace") == 1


def test_replacement_admission_uses_real_inventory_issuance(client) -> None:
    """Reconcile a real supported replacement before the native runner reviews Apply.

    Args:
        client: Isolated appliance HTTP application and database fixture.
    """
    from sqlalchemy import select

    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaCertificate
    from tests.routers.ui.helpers import login

    with SessionLocal() as db:
        ui.get_ca_settings_row(db).enabled = True
        db.commit()
        assert ui.ensure_ca_state(db) == []
        original = db.scalar(select(CaCertificate).where(CaCertificate.managed_owner == "appliance:https"))
        original_id, original_fingerprint = original.id, original.fingerprint
        assert original.status == "issued" and original_fingerprint

    login(client)
    requests = client.get("/ui/management/ca/requests")
    assert requests.status_code == 200
    projection = rotation._CertificateRequestsProjection()
    projection.feed(requests.text)
    assert projection.csrf
    for action in ("revoke", "replace"):
        response = client.post(
            f"/ui/management/ca/certificates/{original_id}/{action}",
            data={"csrf": projection.csrf, "reason": "operator requested"},
            follow_redirects=False,
        )
        assert response.status_code == 303
    with SessionLocal() as db:
        successor = db.scalar(select(CaCertificate).where(CaCertificate.managed_owner == "appliance:https"))
        successor_id = successor.id
        assert successor_id != original_id and successor.status == "planned"

    class InventoryClient:
        """Use actual inventory and certificate routes without native transport."""

        def request(self, path):
            """Read one public projection through the authenticated application.

            Args:
                path: Inventory or public leaf path selected by the production runner.
            """
            response = client.get(path)
            assert response.status_code == 200
            return response.status_code, response.text

    observed_id, fingerprint = rotation._replacement_certificate(InventoryClient(), original_id, original_fingerprint)
    assert observed_id == successor_id and fingerprint != original_fingerprint
    with SessionLocal() as db:
        successor = db.get(CaCertificate, successor_id)
        assert successor.status == "issued" and successor.fingerprint == fingerprint
