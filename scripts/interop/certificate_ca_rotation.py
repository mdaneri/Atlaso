"""Exercise ordinary authenticated CA rotation for appliance management HTTPS.

This module deliberately accepts an already admitted appliance client. It does not
discover a fixture, establish authentication, acquire credentials, or retry a
mutation. A refusal after revocation preserves the fixture for explicit review.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import ssl
from html.parser import HTMLParser
from typing import Any, cast

from certificate_handoff_native import (
    Page,
    Refusal,
    clean_baseline,
    evidence_values,
    same_mac,
    saved_fields,
    selected_management_certificate,
    wait_task,
)
from certificate_peer_transport import PeerTransportRefusal
from time_source_guest import apply_review_fields, apply_review_path


class _SettingsProjection(HTMLParser):
    """Read only the public Web Terminal controls from Appliance Settings."""

    def __init__(self) -> None:
        super().__init__()
        self.web_terminal_enabled = False
        self.web_terminal_enabled_seen = False
        self.web_terminal_interfaces: list[str] = []

    def handle_starttag(self, tag: str, attributes: list[tuple[str, str | None]]) -> None:
        values = dict(attributes)
        if tag != "input":
            return
        name = values.get("name")
        if name == "web_terminal_enabled":
            self.web_terminal_enabled_seen = True
            self.web_terminal_enabled = "checked" in values
        elif name == "web_terminal_interfaces":
            value = values.get("value")
            if value:
                self.web_terminal_interfaces.append(value)


class _CertificateRequestsProjection(HTMLParser):
    """Read the server-rendered certificate action rows and their CSRF token."""

    def __init__(self) -> None:
        super().__init__()
        self.rows: list[dict[str, Any]] = []
        self.csrf = ""

    def handle_starttag(self, tag: str, attributes: list[tuple[str, str | None]]) -> None:
        values = dict(attributes)
        if values.get("id") == "ca-requests-table":
            raw_rows = values.get("data-rows")
            raw_csrf = values.get("data-csrf")
            if not raw_rows or not raw_csrf:
                raise Refusal("certificate_request_projection_invalid")
            try:
                rows = json.loads(raw_rows)
            except (TypeError, ValueError):
                raise Refusal("certificate_request_projection_invalid") from None
            if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
                raise Refusal("certificate_request_projection_invalid")
            self.rows = rows
            self.csrf = raw_csrf


def _managed_certificate_rows(client: Any) -> list[dict[str, Any]]:
    """Return only inventory rows owned by the dedicated management listener."""
    _, body = client.request("/ui/management/certificate-authority")
    rows = cast(Any, Page)(body).certificates
    managed = [row for row in rows if isinstance(row, dict) and row.get("managed_owner") == "appliance:https"]
    if len(managed) != 1:
        raise Refusal("management_certificate_inventory_ambiguous")
    return managed


def _public_pem_sha256(client: Any, path: str) -> str:
    """Download one public PEM certificate and return its normalized DER digest."""
    _, pem = client.request(path)
    if (not pem.startswith("-----BEGIN CERTIFICATE-----")
            or "PRIVATE KEY" in pem
            or pem.count("-----BEGIN CERTIFICATE-----") != 1
            or pem.count("-----END CERTIFICATE-----") != 1):
        raise Refusal("public_certificate_download_invalid")
    try:
        der = ssl.PEM_cert_to_DER_cert(pem)
    except (ValueError, ssl.SSLError):
        raise Refusal("public_certificate_download_invalid") from None
    return hashlib.sha256(der).hexdigest()


def _root_sha256(client: Any) -> str:
    """Read the authenticated public root certificate identity."""
    return _public_pem_sha256(client, "/certificate-authority/downloads/root-ca.pem")


def _settings_projection(client: Any, *, expected_web_terminal: bool, interface_name: str) -> list[str]:
    """Require clean desired Web Terminal state to match the expected fixture."""
    _, body = client.request("/ui/management/settings")
    projection = _SettingsProjection()
    projection.feed(body)
    if (not projection.web_terminal_enabled_seen
            or projection.web_terminal_enabled is not expected_web_terminal):
        raise Refusal("web_terminal_state_mismatch")
    interfaces = projection.web_terminal_interfaces
    if expected_web_terminal:
        # The management listener is mandatory. This acceptance fixture has one
        # appliance NIC, so an additional terminal address would exceed scope.
        if interfaces != [interface_name]:
            raise Refusal("web_terminal_interface_scope_mismatch")
    elif interfaces not in ([], [interface_name]):
        raise Refusal("web_terminal_interface_scope_mismatch")
    return interfaces


def _management_identity(
    client: Any,
    *,
    interface_name: str | None,
    expected_mac: str | None,
    expected_address: str | None,
) -> tuple[dict[str, Any], str, str]:
    """Require the single static IPv4 management identity bound to this client."""
    _, body = client.request("/ui/management/physical-interfaces")
    page = cast(Any, Page)(body)
    management = [row for row in page.rows if isinstance(row, dict) and row.get("role") == "management"]
    if len(management) != 1 or not page.csrf:
        raise Refusal("management_interface_identity_ambiguous")
    row = management[0]
    name = str(row.get("name") or "")
    if not name or (interface_name is not None and name != interface_name):
        raise Refusal("management_interface_identity_mismatch")
    fields = cast(Any, saved_fields)(row)
    if fields.get("ipv4_method") != "static" or fields.get("ipv6_enabled") is not False:
        raise Refusal("management_interface_static_ipv4_required")
    try:
        address = str(ipaddress.ip_interface(str(fields.get("ip_cidr") or "")).ip)
    except ValueError:
        raise Refusal("management_interface_address_invalid") from None
    connected_address = str(ipaddress.IPv4Address(client.connect_ip))
    if address != connected_address or (expected_address is not None and address != expected_address):
        raise Refusal("management_address_binding_mismatch")
    mac = str(row.get("mac_address") or "")
    if not mac or (expected_mac is not None and not cast(Any, same_mac)(mac, expected_mac)):
        raise Refusal("management_mac_binding_mismatch")
    return row, address, mac


def _request_row(client: Any, certificate_id: int) -> tuple[dict[str, Any], str]:
    """Read one certificate action row and its CSRF value."""
    _, body = client.request("/ui/management/ca/requests")
    projection = _CertificateRequestsProjection()
    projection.feed(body)
    matches = [row for row in projection.rows if row.get("id") == certificate_id]
    if len(matches) != 1 or not projection.csrf:
        raise Refusal("certificate_request_row_missing")
    return matches[0], projection.csrf


def _require_inventory_leaf(client: Any, certificate_id: int) -> dict[str, Any]:
    """Require the sole active management row to be issued and exportable."""
    cast(Any, selected_management_certificate)(client, certificate_id)
    row = _managed_certificate_rows(client)[0]
    fingerprint = str(row.get("fingerprint") or "").lower()
    if (row.get("id") != certificate_id or row.get("status") != "issued"
            or row.get("enabled") is not True or row.get("can_export_certificate") is not True
            or not re.fullmatch(r"[0-9a-f]{64}", fingerprint)):
        raise Refusal("management_certificate_not_issued")
    return {"id": certificate_id, "fingerprint": fingerprint}


def _assert_served_matches_inventory(client: Any, certificate_id: int, address: str) -> str:
    """Require strict peer TLS and the authenticated public PEM to match inventory."""
    inventory = _require_inventory_leaf(client, certificate_id)
    pem_fingerprint = _public_pem_sha256(
        client, f"/certificate-authority/certificates/{certificate_id}/downloads/certificate.pem"
    )
    served = client.tls_identity()
    served_fingerprint = str(served.get("sha256") or "").lower()
    served_addresses = served.get("ip_sans")
    if (pem_fingerprint != inventory["fingerprint"]
            or served_fingerprint != inventory["fingerprint"]
            or not isinstance(served_addresses, list)
            or address not in served_addresses):
        raise Refusal("served_management_certificate_mismatch")
    return str(inventory["fingerprint"])


def _replacement_certificate(client: Any, original_id: int, original_fingerprint: str) -> tuple[int, str]:
    """Admit the successor issued by the ordinary inventory reconciliation.

    Args:
        client: Already admitted authenticated appliance client.
        original_id: Revoked management certificate retained in history.
        original_fingerprint: Served management leaf observed before revocation.
    """
    _, body = client.request("/ui/management/certificate-authority")
    inventory = cast(Any, Page)(body).certificates
    historical = [row for row in inventory if row.get("id") == original_id]
    if (len(historical) != 1 or historical[0].get("status") != "revoked"
            or historical[0].get("managed_owner") != f"retired-revoked:{original_id}"):
        raise Refusal("revoked_certificate_history_unverified")
    successors = [row for row in inventory if row.get("managed_owner") == "appliance:https"]
    if len(successors) != 1:
        raise Refusal("replacement_certificate_ambiguous")
    replacement_id = successors[0].get("id")
    if (type(replacement_id) is not int or replacement_id <= 0 or replacement_id == original_id
            or successors[0].get("status") != "issued"):
        raise Refusal("replacement_certificate_invalid")
    fingerprint = _require_inventory_leaf(client, replacement_id)["fingerprint"]
    public_fingerprint = _public_pem_sha256(
        client, f"/certificate-authority/certificates/{replacement_id}/downloads/certificate.pem",
    )
    if fingerprint == original_fingerprint or fingerprint != public_fingerprint:
        raise Refusal("replacement_certificate_identity_mismatch")
    return replacement_id, fingerprint


def _review_ca_only(client: Any) -> tuple[dict[str, Any], list[str]]:
    """Admit only a clean CA change and its two already-applied consumers."""
    path = cast(Any, apply_review_path)("/ui/management/appliance-apply/review", ["ca"])
    _, review = client.json(path)
    rows = review.get("units")
    if (review.get("active_task") is not None or review.get("plan_error")
            or review.get("requested_units") != ["ca"] or not isinstance(rows, list)):
        raise Refusal("ca_only_review_invalid")
    by_id = {row.get("id"): row for row in rows if isinstance(row, dict)}
    if len(by_id) != len(rows):
        raise Refusal("ca_only_review_invalid")
    changed = {unit_id for unit_id, row in by_id.items() if row.get("changed") is True}
    if changed != {"ca"}:
        raise Refusal("ca_only_pending_scope_mismatch")
    expected_selected = {"ca", "appliance_settings", "public_services"}
    selected_rows = [row for row in rows if row.get("selected") is True]
    selected = [str(row.get("id") or "") for row in selected_rows]
    if set(selected) != expected_selected or len(selected) != len(expected_selected):
        raise Refusal("ca_consumer_replay_missing")
    positions = {unit_id: selected.index(unit_id) for unit_id in expected_selected}
    if not (positions["ca"] < positions["appliance_settings"]
            and positions["ca"] < positions["public_services"]):
        raise Refusal("ca_consumer_order_invalid")
    if any(row.get("valid") is not True for row in selected_rows):
        raise Refusal("ca_only_review_invalid")
    try:
        fields = cast(Any, apply_review_fields)(review)
    except ValueError:
        raise Refusal("ca_only_review_invalid") from None
    field_selected = [value for key, value in fields if key == "selected_units"]
    if field_selected != selected:
        raise Refusal("ca_only_review_invalid")
    return review, selected


def exercise_ca_rotation(
    client: Any,
    *,
    certificate_id: int,
    expected_root_sha256: str,
    expected_web_terminal: bool,
    username: str,
    password: str,
    interface_name: str | None = None,
    expected_mac: str | None = None,
    expected_address: str | None = None,
) -> dict[str, Any]:
    """Replace and natively activate the managed management HTTPS leaf.

    Args:
        client: Already admitted, authenticated client with pinned peer transport.
        certificate_id: Original issued appliance:https certificate ID from admission.
        expected_root_sha256: DER SHA-256 digest of the receipt-pinned public CA.
        expected_web_terminal: Whether Web Terminal is part of the clean baseline.
        username: Authenticated appliance user for bounded task polling.
        password: In-memory authenticated appliance password for task polling.
        interface_name: Optional admitted management interface name.
        expected_mac: Optional admitted management MAC address.
        expected_address: Optional admitted management IPv4 address.

    Returns:
        A bounded allowlisted public acceptance record.

    Raises:
        Refusal: If admission, replacement, Apply review, or runtime verification fails.
    """
    try:
        cast(Any, clean_baseline)(client)
        row, address, mac = _management_identity(
            client,
            interface_name=interface_name,
            expected_mac=expected_mac,
            expected_address=expected_address,
        )
        interface = str(row.get("name") or "")
        web_terminal_interfaces = _settings_projection(
            client, expected_web_terminal=expected_web_terminal, interface_name=interface
        )
        if expected_web_terminal and web_terminal_interfaces != [interface]:
            raise Refusal("web_terminal_interface_scope_mismatch")
        root_sha256 = _root_sha256(client)
        expected_root_sha256 = expected_root_sha256.lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected_root_sha256) or root_sha256 != expected_root_sha256:
            raise Refusal("root_ca_receipt_pin_mismatch")
        original_leaf_sha256 = _assert_served_matches_inventory(client, certificate_id, address)

        request_row, csrf = _request_row(client, certificate_id)
        if request_row.get("status") != "issued" or request_row.get("can_revoke") is not True:
            raise Refusal("management_certificate_not_revocable")
        client.request(
            f"/ui/management/ca/certificates/{certificate_id}/revoke",
            {"csrf": csrf, "reason": "operator requested"},
        )
        revoked_row, csrf = _request_row(client, certificate_id)
        if revoked_row.get("status") != "revoked" or revoked_row.get("can_replace") is not True:
            raise Refusal("management_certificate_revocation_unverified")
        client.request(
            f"/ui/management/ca/certificates/{certificate_id}/replace",
            {"csrf": csrf},
        )

        replacement_id, staged_leaf_sha256 = _replacement_certificate(client, certificate_id, original_leaf_sha256)
        if _root_sha256(client) != root_sha256:
            raise Refusal("root_ca_changed_before_apply")

        review, selected_units = _review_ca_only(client)
        _, physical_body = client.request("/ui/management/physical-interfaces")
        csrf = cast(Any, Page)(physical_body).csrf
        if not csrf:
            raise Refusal("apply_csrf_missing")
        form = {
            "csrf": csrf,
            "reviewed_plan": review["plan_token"],
            "requested_units": review["requested_units"],
            "selected_units": selected_units,
        }
        status, submission = client.json("/ui/management/appliance-apply", form)
        if status != 202:
            raise Refusal("ca_apply_not_admitted")
        job_id = submission.get("job_id")
        status_path = submission.get("status_url")
        if (not isinstance(job_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", job_id)
                or status_path not in (f"/tasks/{job_id}/status", f"/ui/management/tasks/{job_id}/status")):
            raise Refusal("ca_apply_task_identity_invalid")
        task, _ = cast(Any, wait_task)([client], status_path, username, password)
        if (task.get("id") != job_id or task.get("type") != "appliance-apply"
                or task.get("status") != "succeeded"
                or True in cast(Any, evidence_values)(task, "dry_run")):
            raise Refusal("ca_apply_task_failed")

        cast(Any, clean_baseline)(client)
        final_row, final_address, final_mac = _management_identity(
            client,
            interface_name=interface,
            expected_mac=mac,
            expected_address=address,
        )
        if cast(Any, saved_fields)(final_row) != cast(Any, saved_fields)(row) or final_mac != mac or final_address != address:
            raise Refusal("management_interface_changed_during_ca_apply")
        final_interfaces = _settings_projection(
            client, expected_web_terminal=expected_web_terminal, interface_name=interface
        )
        if final_interfaces != web_terminal_interfaces:
            raise Refusal("web_terminal_state_changed_during_ca_apply")
        if _root_sha256(client) != root_sha256:
            raise Refusal("root_ca_changed_during_apply")
        replacement_leaf_sha256 = _assert_served_matches_inventory(client, int(replacement_id), address)
        if replacement_leaf_sha256 != staged_leaf_sha256:
            raise Refusal("replacement_certificate_changed_during_apply")
        return {
            "schema": 1,
            "interface": interface,
            "address": address,
            "mac": mac,
            "web_terminal_enabled": expected_web_terminal,
            "root_sha256": root_sha256,
            "original_certificate_id": certificate_id,
            "original_leaf_sha256": original_leaf_sha256,
            "replacement_certificate_id": replacement_id,
            "replacement_leaf_sha256": replacement_leaf_sha256,
            "served_leaf_sha256": replacement_leaf_sha256,
            "review_requested_units": ["ca"],
            "review_selected_units": selected_units,
            "task_id": job_id,
            "task_status": "succeeded",
        }
    except Refusal:
        raise
    except (PeerTransportRefusal, OSError, ValueError, TypeError, KeyError, AttributeError, RuntimeError):
        # Keep parser, transport, and library diagnostics out of native evidence.
        raise Refusal("ca_rotation_failed") from None
