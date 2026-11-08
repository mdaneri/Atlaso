"""Normal-UI operations for separately admitted console-only functional tests.

No resource admission or formal certificate/address-control proof is implemented
here. The caller owns the original console/source/runtime admission and must
durably record every public checkpoint before acknowledging it. Unknown outcomes
never trigger submission replay or automatic restoration.
"""

from __future__ import annotations

import hashlib
import http.client
import http.cookies
import re
import urllib.parse
from collections.abc import Callable
from html.parser import HTMLParser
from typing import Any

from scripts.interop.certificate_dual_stack_guest import (
    GuestRefusal,
    NumericHTTPSConnection,
    json_loads_unique,
    public_bytes,
)

PROTECTED = frozenset({"network", "ca", "firewall", "appliance_settings", "public_services"})
ALLOWED_UNITS = PROTECTED | {"dnsmasq"}
FIELDS = (
    "role", "mode", "ipv4_method", "ip_cidr", "gateway", "ipv6_enabled",
    "ipv6_cidr", "ipv6_gateway", "mtu", "admin_state",
    "check_duplicate_ip_addresses", "access_management_ui_enabled",
)
REVIEW_KEYS = frozenset({
    "units", "pending_count", "execution_count", "requested_units", "plan_token",
    "plan_error", "initial_apply_required", "active_task",
})
UNIT_KEYS = frozenset({
    "id", "label", "page_url", "summary", "valid", "validation_errors",
    "validation_warnings", "connection_warnings", "config_path", "config_preview",
    "config_diff", "snapshot_hash", "network_candidate_preview", "network_candidate_diff",
    "network_candidate_valid", "network_candidate_validation_errors",
    "forces_network_selection", "forces_wan_selection", "has_baseline", "changed",
    "selected", "required_dependency", "dependency_reason", "requires_dns_selection",
    "requires_network_selection", "format_volumes",
})


class InterfacePage(HTMLParser):
    """Read only the normal UI CSRF token and serialized interface inventory."""

    def __init__(self, body: str) -> None:
        """Parse one bounded authenticated page without exposing its private token.

        Args:
            body: Normal management UI response held only in memory.
        """
        super().__init__()
        self.csrf = ""
        self.rows: list[dict[str, Any]] = []
        self.feed(body)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Read the existing UI's successful fields and physical-interface projection.

        Args:
            tag: HTML element name.
            attrs: Original element attributes.
        """
        values = dict(attrs)
        if tag == "input" and values.get("name") == "csrf":
            self.csrf = values.get("value") or ""
        if values.get("id") == "physical-interfaces-table":
            raw = json_loads_unique(values.get("data-interfaces") or "")
            if not isinstance(raw, list) or not all(isinstance(row, dict) for row in raw):
                raise GuestRefusal("authenticated_interface_inventory_invalid")
            self.rows = raw
            self.csrf = values.get("data-csrf") or self.csrf


class UIClient:
    """One pinned numeric origin with private in-memory cookies and CSRF values."""

    def __init__(self, connection: Callable[[], NumericHTTPSConnection]) -> None:
        """Use an independently admitted exact-origin connection factory.

        Args:
            connection: Fresh CA/IP-SAN/console-leaf verified connection factory.
        """
        self.connection = connection
        self.cookies: dict[str, str] = {}
        self.private_markers: set[str] = set()

    def request(
        self, path: str, form: list[tuple[str, str]] | None = None
    ) -> tuple[int, str, bytes]:
        """Make one normal UI request without redirect, proxy, retry or origin fallback.

        Args:
            path: Explicit same-origin management or protocol path.
            form: Successful normal-UI fields; credentials and tokens remain private.
        """
        if not path.startswith("/") or path.startswith("//") or any(char in path for char in "\r\n#"):
            raise GuestRefusal("request_path_invalid")
        parsed = urllib.parse.urlsplit(path)
        if parsed.scheme or parsed.netloc:
            raise GuestRefusal("request_origin_invalid")
        connection = self.connection()
        body = None if form is None else urllib.parse.urlencode(form).encode()
        headers = {"Accept": "application/json, text/html"}
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{key}={value}" for key, value in self.cookies.items())
        if form is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            connection.request("GET" if form is None else "POST", path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read(524_289)
            if len(raw) > 524_288:
                raise GuestRefusal("ui_response_too_large")
            for key, value in response.getheaders():
                if key.lower() == "set-cookie":
                    cookie = http.cookies.SimpleCookie()
                    cookie.load(value)
                    for name, item in cookie.items():
                        self.cookies[name] = item.value
                        if item.value:
                            self.private_markers.add(item.value)
            # Location is never followed. Each next request uses a fixed admitted path.
            return response.status, response.getheader("Location") or "", raw
        finally:
            connection.close()

    def read_json(self, path: str) -> dict[str, Any]:
        """Read one normal JSON projection, refusing login redirects or malformed data.

        Args:
            path: Exact admitted read-only endpoint.
        """
        status, _, raw = self.request(path)
        if status != 200:
            raise GuestRefusal("authenticated_json_unavailable")
        value = json_loads_unique(raw)
        if not isinstance(value, dict):
            raise GuestRefusal("authenticated_json_invalid")
        return value

    def login(self, password: str) -> None:
        """Authenticate the existing admin account with private in-memory material.

        Args:
            password: Existing concealed value supplied by the bounded SDK consumer.
        """
        status, _, raw = self.request("/ui/management/login")
        page = InterfacePage(raw.decode("utf-8", "strict"))
        if status != 200 or not page.csrf:
            raise GuestRefusal("login_csrf_missing")
        self.private_markers.update({password, page.csrf})
        status, _, _ = self.request(
            "/ui/management/login",
            [("username", "admin"), ("password", password), ("csrf", page.csrf)],
        )
        if status not in (200, 303):
            raise GuestRefusal("admin_login_refused")
        self.interfaces()

    def interfaces(self) -> InterfacePage:
        """Read the authenticated physical-interface UI and its current CSRF."""
        status, _, raw = self.request("/ui/management/physical-interfaces")
        page = InterfacePage(raw.decode("utf-8", "strict"))
        if status != 200 or not page.csrf or not page.rows:
            raise GuestRefusal("authenticated_interface_inventory_missing")
        self.private_markers.add(page.csrf)
        return page


def interface_fields(row: dict[str, Any]) -> dict[str, Any]:
    """Capture only public desired fields from the normal UI projection.

    Args:
        row: One MAC- and interface-bound physical-interface row.
    """
    result = {key: "" if row.get(key) is None else row[key] for key in FIELDS}
    result["admin_state"] = "up" if row.get("admin_up") else "down"
    return result


def selected_interface(client: UIClient, name: str, mac: str) -> tuple[dict[str, Any], str]:
    """Bind the normal UI row to the independently observed interface/MAC.

    Args:
        client: Current pinned authenticated UI session.
        name: Original admitted interface name.
        mac: Original admitted colon-separated MAC.
    """
    if re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac) is None:
        raise GuestRefusal("original_mac_invalid")
    page = client.interfaces()
    rows = [row for row in page.rows if row.get("name") == name]
    if len(rows) != 1 or str(rows[0].get("mac_address", "")).replace("-", ":").lower() != mac:
        raise GuestRefusal("interface_identity_changed")
    return rows[0], page.csrf


def save_interface(
    client: UIClient, name: str, mac: str, expected: dict[str, Any], desired: dict[str, Any],
    checkpoint: Callable[[str, dict[str, Any]], None],
) -> dict[str, Any]:
    """Save exactly one reviewed desired record through the existing UI endpoint.

    No Apply is submitted. A lost or unexpected response leaves Save outcome
    unknown; read back before another Save or restoration, never replay this call.

    Args:
        client: Admitted exact-origin authenticated UI session.
        name: Original admitted interface name.
        mac: Original admitted MAC.
        expected: Full public pre-Save desired fields, not a partial patch.
        desired: Full approved replacement fields.
        checkpoint: Controller acknowledgement after durable public intent storage.
    """
    if set(expected) != set(FIELDS) or set(desired) != set(FIELDS):
        raise GuestRefusal("complete_interface_fields_required")
    row, csrf = selected_interface(client, name, mac)
    if interface_fields(row) != expected or type(row.get("id")) is not int:
        raise GuestRefusal("desired_interface_baseline_changed")
    intent = {"schema": 1, "kind": "test-only-desired-save-intent", "test_only": True,
              "formal_acceptance": False, "interface": name, "mac": mac,
              "row_id": row["id"], "before": expected, "after": desired}
    public_bytes(intent)
    assert_public_review(intent, client.private_markers)
    checkpoint("save_intent", intent)
    form = [(key, str(value).lower() if isinstance(value, bool) else str(value))
            for key, value in desired.items()]
    form = [(key, ("on" if desired[key] else "off") if key == "access_management_ui_enabled" else value)
            for key, value in form]
    form.append(("csrf", csrf))
    try:
        status, _, _ = client.request(f"/ui/management/physical-interfaces/{row['id']}/edit", form)
    except (OSError, ValueError, http.client.HTTPException):
        raise GuestRefusal("save_outcome_unknown_read_only_reconcile") from None
    if status not in (200, 303):
        raise GuestRefusal("save_outcome_unknown_read_only_reconcile")
    current, _ = selected_interface(client, name, mac)
    if interface_fields(current) != desired:
        raise GuestRefusal("save_readback_mismatch_no_replay")
    return {**intent, "kind": "desired_save_readback", "verified": True}



def assert_public_review(value: object, private_markers: set[str]) -> None:
    """Refuse a public checkpoint that contains private session or key material.

    This is a final defensive check, not authority to publish arbitrary responses.
    Only the exact selected-unit public review schema may reach this function.

    Args:
        value: Schema-projected review, retaining complete selected previews.
        private_markers: In-memory password, cookie, CSRF and private plan-token values.
    """
    if isinstance(value, str):
        if (re.search(r"-----BEGIN [^-]*PRIVATE KEY-----", value)
                or re.search(r"[a-z]+://[^\s/]*@", value, re.IGNORECASE)
                or any(marker and marker in value for marker in private_markers)):
            raise GuestRefusal("public_review_contains_private_material")
    elif isinstance(value, dict):
        for key, child in value.items():
            assert_public_review(key, private_markers)
            assert_public_review(child, private_markers)
    elif isinstance(value, list):
        for child in value:
            assert_public_review(child, private_markers)


def validate_public_apply_review(review: dict[str, Any]) -> None:
    """Require the complete selected public plan with the server's typed semantics.

    Args:
        review: Public server review after private token and unselected-body removal.
    """
    if (set(review) != REVIEW_KEYS - {"plan_token"}
            or review["active_task"] is not None or review["plan_error"] != ""
            or review["initial_apply_required"] is not False
            or type(review["pending_count"]) is not int or review["pending_count"] < 0
            or type(review["execution_count"]) is not int or review["execution_count"] < len(PROTECTED)
            or not isinstance(review["requested_units"], list)
            or not all(isinstance(item, str) for item in review["requested_units"])
            or len(review["requested_units"]) != len(set(review["requested_units"]))
            or not PROTECTED <= set(review["requested_units"]) <= ALLOWED_UNITS
            or not isinstance(review["units"], list) or not review["units"]):
        raise GuestRefusal("complete_public_review_required")
    selected: set[str] = set()
    identifiers: set[str] = set()
    changed = 0
    boolean_fields = {"valid", "changed", "selected", "has_baseline", "required_dependency",
                      "forces_network_selection", "forces_wan_selection", "requires_dns_selection",
                      "requires_network_selection"}
    for unit in review["units"]:
        if (not isinstance(unit, dict) or not isinstance(unit.get("id"), str)
                or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", unit["id"]) is None
                or unit["id"] in identifiers or type(unit.get("selected")) is not bool):
            raise GuestRefusal("complete_public_review_required")
        identifiers.add(unit["id"])
        keys = UNIT_KEYS if unit["selected"] else {"id", "label", "changed", "valid", "selected"}
        if (set(unit) != keys or not isinstance(unit["label"], str) or not unit["label"]
                or any(type(unit[key]) is not bool for key in boolean_fields & keys)):
            raise GuestRefusal("complete_public_review_required")
        changed += int(unit["changed"])
        if not unit["selected"]:
            if unit["changed"]:
                raise GuestRefusal("unselected_pending_unit")
            continue
        selected.add(unit["id"])
        text_fields = {"page_url", "config_path", "config_preview", "config_diff", "dependency_reason"}
        list_fields = {"summary", "validation_errors", "validation_warnings", "connection_warnings",
                       "network_candidate_validation_errors"}
        if (unit["id"] not in ALLOWED_UNITS or unit["valid"] is not True or unit["has_baseline"] is not True
                or unit["format_volumes"] != [] or not isinstance(unit["format_volumes"], list)
                or any(not isinstance(unit[key], str) for key in text_fields)
                or any(not isinstance(unit[key], list) or not all(isinstance(item, str) for item in unit[key])
                       for key in list_fields)
                or unit["validation_errors"] or unit["network_candidate_validation_errors"]
                or not isinstance(unit["snapshot_hash"], str)
                or re.fullmatch(r"[0-9a-f]{64}", unit["snapshot_hash"]) is None):
            raise GuestRefusal("complete_public_review_required")
        candidate = [unit[key] for key in ("network_candidate_preview", "network_candidate_diff", "network_candidate_valid")]
        if (candidate != [None, None, None]
                and not (isinstance(candidate[0], str) and isinstance(candidate[1], str) and candidate[2] is True)):
            raise GuestRefusal("complete_public_review_required")
    if (not set(review["requested_units"]) <= selected or not PROTECTED <= selected
            or review["execution_count"] != len(selected) or review["pending_count"] != changed):
        raise GuestRefusal("complete_public_review_required")


def prepare_review(client: UIClient, roots: list[str]) -> tuple[dict[str, Any], list[tuple[str, str]]]:
    """Read and retain a complete server-expanded protected handoff review in memory.

    Args:
        client: Admitted authenticated UI session.
        roots: Explicit admitted roots; all five protected units are mandatory.
    """
    if len(roots) != len(set(roots)) or not PROTECTED.issubset(roots) or not set(roots) <= ALLOWED_UNITS:
        raise GuestRefusal("protected_apply_roots_required")
    path = "/ui/management/appliance-apply/review?" + urllib.parse.urlencode(
        [("selected_units", unit) for unit in roots]
    )
    review = client.read_json(path)
    if set(review) != REVIEW_KEYS or review["active_task"] or review["plan_error"] or review["initial_apply_required"]:
        raise GuestRefusal("protected_review_unavailable")
    returned_roots = review["requested_units"]
    if (not isinstance(returned_roots, list) or not all(isinstance(root, str) for root in returned_roots)
            or len(returned_roots) != len(set(returned_roots)) or set(returned_roots) != set(roots)
            or not isinstance(review["plan_token"], str) or not review["plan_token"]):
        raise GuestRefusal("protected_review_selection_changed")
    units = review["units"]
    if not isinstance(units, list) or not units:
        raise GuestRefusal("protected_review_units_invalid")
    identifiers = [unit.get("id") for unit in units if isinstance(unit, dict)]
    if (len(identifiers) != len(units) or not all(isinstance(item, str) for item in identifiers)
            or len(set(identifiers)) != len(identifiers)):
        raise GuestRefusal("protected_review_units_invalid")
    selected = []
    for unit in units:
        if set(unit) != UNIT_KEYS or type(unit["selected"]) is not bool or type(unit["changed"]) is not bool:
            raise GuestRefusal("protected_review_schema_changed")
        if unit["changed"] and unit["id"] not in ALLOWED_UNITS:
            raise GuestRefusal("unrelated_pending_unit")
        if unit["selected"]:
            if unit["id"] not in ALLOWED_UNITS or unit["valid"] is not True or unit["has_baseline"] is not True or unit["format_volumes"]:
                raise GuestRefusal("protected_review_scope_invalid")
            selected.append(unit["id"])
    if (not PROTECTED.issubset(selected) or type(review["execution_count"]) is not int
            or review["execution_count"] != len(selected)):
        raise GuestRefusal("complete_protected_handoff_required")
    fields = [("reviewed_plan", review["plan_token"])]
    fields += [("requested_units", unit) for unit in returned_roots]
    fields += [("selected_units", unit) for unit in selected]
    client.private_markers.add(review["plan_token"])
    public_review = {key: value for key, value in review.items() if key != "plan_token"}
    # Full selected previews/diffs are required. Unselected configuration bodies
    # are outside consent and may contain unrelated private material.
    public_review["units"] = [
        unit if unit["selected"] else {key: unit[key] for key in ("id", "label", "changed", "valid", "selected")}
        for unit in units
    ]
    validate_public_apply_review(public_review)
    assert_public_review(public_review, client.private_markers)
    public_bytes(public_review)
    return public_review, fields


def submit_once(
    client: UIClient, roots: list[str], checkpoint: Callable[[str, dict[str, Any]], None]
) -> dict[str, Any]:
    """Submit one reviewed global Apply and return without polling or restoration.

    The checkpoint must publish and durably retain the complete sanitized expanded
    review and intent before acknowledging. Cookies, CSRF and plan token never
    enter that public checkpoint. A caller must durably preserve the returned
    original job receipt before a separate read-only status operation.

    Args:
        client: Admitted authenticated UI session.
        roots: Explicit approved roots, including every protected handoff unit.
        checkpoint: Durable-intent controller acknowledgement; failure prohibits POST.
    """
    review, fields = prepare_review(client, roots)
    page = client.interfaces()
    public_intent = {
        "schema": 1, "kind": "test-only-protected-apply-intent",
        "test_only": True, "formal_acceptance": False,
        "review": review, "review_sha256": hashlib.sha256(public_bytes(review)).hexdigest(),
    }
    checkpoint("apply_intent", public_intent)
    try:
        status, _, raw = client.request("/ui/management/appliance-apply", [("csrf", page.csrf), *fields])
        result = json_loads_unique(raw)
        job = result.get("job_id") if isinstance(result, dict) else None
        path = result.get("status_url") if isinstance(result, dict) else None
        if (status != 202 or not isinstance(job, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", job) is None
                or path not in (f"/tasks/{job}/status", f"/ui/management/tasks/{job}/status")):
            raise GuestRefusal("apply_outcome_unknown_read_only_reconcile")
    except (OSError, ValueError, http.client.HTTPException):
        raise GuestRefusal("apply_outcome_unknown_read_only_reconcile") from None
    receipt = {
        "schema": 1, "kind": "test-only-original-apply-job", "test_only": True,
        "formal_acceptance": False, "job_id": job, "status_url": path,
        "intent_sha256": hashlib.sha256(public_bytes(public_intent)).hexdigest(),
        "HTTP_status": 202, "automatic_poll_or_restore": False,
    }
    assert_public_review(receipt, client.private_markers)
    return receipt


def read_apply_status_once(
    client: UIClient, receipt: dict[str, Any], *, durable_receipt_sha256: str,
) -> dict[str, Any]:
    """Read one original Apply job only after its durable controller acknowledgement.

    This never submits, cancels, retries, changes origin or restores configuration.
    The controller must fsync the original receipt before supplying its digest.
    A terminal status alone is not evidence of runtime readiness or acceptance.

    Args:
        client: Admitted exact-origin authenticated UI session.
        receipt: Original public receipt returned by the one-shot submission.
        durable_receipt_sha256: Digest acknowledged after original receipt storage.
    """
    keys = {"schema", "kind", "test_only", "formal_acceptance", "job_id", "status_url",
            "intent_sha256", "HTTP_status", "automatic_poll_or_restore"}
    job = receipt.get("job_id")
    if (set(receipt) != keys or type(receipt.get("schema")) is not int or receipt["schema"] != 1
            or receipt.get("kind") != "test-only-original-apply-job"
            or receipt.get("test_only") is not True or receipt.get("formal_acceptance") is not False
            or type(receipt.get("HTTP_status")) is not int or receipt["HTTP_status"] != 202
            or receipt.get("automatic_poll_or_restore") is not False
            or not isinstance(job, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", job) is None
            or receipt.get("status_url") not in (f"/tasks/{job}/status", f"/ui/management/tasks/{job}/status")
            or not isinstance(receipt.get("intent_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", receipt["intent_sha256"]) is None
            or durable_receipt_sha256 != hashlib.sha256(public_bytes(receipt)).hexdigest()):
        raise GuestRefusal("original_durable_job_receipt_required")
    # Keep the original receipt URL immutable. The legacy GET redirects, so the
    # no-redirect client must derive the canonical read from the validated job.
    response = client.read_json(f"/ui/management/tasks/{job}/status")
    task = response.get("task")
    if (not isinstance(task, dict) or task.get("id") != job or task.get("type") != "appliance-apply"
            or not isinstance(task.get("status"), str)
            or task["status"] not in {"pending", "running", "succeeded", "failed", "cancelled"}):
        raise GuestRefusal("original_apply_task_identity_changed")
    result = {
        "schema": 1, "kind": "test-only-task-status", "test_only": True,
        "formal_acceptance": False, "job_id": job, "status_url": receipt["status_url"],
        "task_type": "appliance-apply", "status": task["status"],
        "original_job_receipt_sha256": durable_receipt_sha256,
    }
    assert_public_review(result, client.private_markers)
    return result
