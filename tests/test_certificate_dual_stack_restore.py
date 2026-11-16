"""Exercise baseline capture against normal UI projections over synthetic HTTP."""

from __future__ import annotations

import copy
import hashlib
import html
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from jinja2 import Environment, StrictUndefined, select_autoescape

from scripts.interop.certificate_dual_stack_guest import GuestRefusal, public_bytes
from scripts.interop.certificate_dual_stack_restore import capture_restoration_baseline
from scripts.interop.certificate_dual_stack_ui import UIClient

_MAC = "02:00:00:00:00:01"
_PATHS = [
    "/ui/management/appliance-apply/review",
    "/ui/management/physical-interfaces",
    "/ui/management/dns",
]
_REVIEW = {
    "units": [], "pending_count": 0, "execution_count": 0, "requested_units": [],
    "plan_token": "synthetic-private-plan", "plan_error": "", "initial_apply_required": False, "active_task": None,
}
_ROW = {
    "id": 13, "name": "eth1", "mac_address": _MAC, "role": "access", "mode": "access", "ipv4_method": "static",
    "ip_cidr": "192.0.2.20/24", "gateway": None, "ipv6_enabled": True, "ipv6_cidr": "fd00:1084::20/64",
    "ipv6_gateway": "", "mtu": 1500, "admin_state": "up", "admin_up": True,
    "check_duplicate_ip_addresses": True, "access_management_ui_enabled": True,
    "host_ipv4_gateway": "192.0.2.1", "host_ip_cidr": "192.0.2.99/24",
}


@pytest.fixture
def dns_form() -> str:
    """Render the current DNS settings form with synthetic desired values."""
    template = Path("atlaso/app/templates/dns.html").read_text(encoding="utf-8")
    start = template.index('<form class="form-stack" action="{{ management_ui_root }}/dns/settings"')
    form = template[start:template.index("</form>", start) + len("</form>")]
    return Environment(
        autoescape=select_autoescape(default_for_string=True), undefined=StrictUndefined,
    ).from_string(form).render(
        management_ui_root="/ui/management", csrf_token="synthetic-private-dns", selected_dns_interfaces=["eth1", "eth2"],
        available_interfaces=[{"name": "eth1", "label": "Synthetic one"}], selected_dns_addresses=["192.0.2.20"],
        observed_dhcp_upstream_servers=["192.0.2.53"], upstream_servers="192.0.2.53\r\nfd00:1084::53",
        conditional_forwarders="corp.example=192.0.2.54", dns_record_groups=[],
        dns_settings=SimpleNamespace(
            enabled=True, cache_size=150, expand_hosts=False, authoritative=True, authoritative_server="ns.example",
            authoritative_contact="hostmaster.example", authoritative_ttl=120, authoritative_serial=2026110801,
            authoritative_refresh=600, authoritative_retry=60, authoritative_expire=3600,
            dnssec_enabled=True, rebind_protection_enabled=False, rebind_domain_exemptions="example",
            query_logging_mode="off",
        ),
    )


class _Transport:
    """Serve three ordered observations through the real UI client."""

    def __init__(self, dns_form: str) -> None:
        """Initialize three independent synthetic UI responses.

        Args:
            dns_form: Rendered normal DNS settings form.
        """
        self.reviews = [copy.deepcopy(_REVIEW) for _ in range(3)]
        self.rows = [copy.deepcopy(_ROW) for _ in range(3)]
        self.forms = [dns_form] * 3
        self.requests: list[tuple[str, str]] = []
        self.status: dict[int, int] = {}
        self.client = UIClient(self.connection)

    def connection(self) -> Any:
        """Return a synthetic connection with bounded response reads."""
        return SimpleNamespace(
            request=lambda method, path, **_kwargs: self.requests.append((method, path)),
            getresponse=self.response, close=lambda: None,
        )

    def response(self) -> Any:
        """Return the requested normal page and synthetic private session cookie."""
        index = len(self.requests) - 1
        observation, page = divmod(index, 3)
        assert self.requests[-1] == ("GET", _PATHS[page])
        if page == 0:
            body = json.dumps(self.reviews[observation])
        elif page == 1:
            rows = html.escape(json.dumps([self.rows[observation]]), quote=True)
            body = (
                f'<div id="physical-interfaces-table" data-csrf="synthetic-private-interface" '
                f'data-interfaces="{rows}"></div>'
            )
        else:
            body = self.forms[observation]
        return SimpleNamespace(
            status=self.status.get(index, 200),
            read=lambda limit: body.encode()[:limit],
            getheaders=lambda: [("Set-Cookie", "session=synthetic-private-cookie")],
            getheader=lambda _name: "/ui/management/login",
        )


def test_capture_exact_public_projections_and_checkpoint_copy(dns_form: str) -> None:
    """Keep the nullable original and canonical browser views independent.

    Args:
        dns_form: Rendered existing DNS settings form.
    """
    transport = _Transport(dns_form)
    stored: list[dict[str, Any]] = []

    def checkpoint(value: dict[str, Any]) -> None:
        """Verify the six preceding reads and mutate only the publisher's copy.

        Args:
            value: Independent public checkpoint payload.
        """
        assert transport.requests == [("GET", path) for path in _PATHS * 2]
        stored.append(copy.deepcopy(value))
        value["dns_settings"]["listen_interfaces"].append("publisher-edit")
        value["original_row"]["gateway"] = "publisher-edit"

    result = capture_restoration_baseline(transport.client, "eth1", _MAC, checkpoint)
    assert transport.requests == [("GET", path) for path in _PATHS * 3]
    assert stored == [result]
    assert result["original_row"]["gateway"] is None
    assert result["browser_fields"]["gateway"] == ""
    assert "host_ipv4_gateway" not in result["original_row"]
    assert result["dns_settings"]["listen_interfaces"] == ["eth1", "eth2"]
    assert result["dns_settings"]["listen_interfaces_present"] == "1"
    assert result["dns_settings"]["expand_hosts"] is False
    assert result["dns_settings"]["enabled"] is True
    assert result["dns_settings"]["upstream_servers"] == "192.0.2.53\nfd00:1084::53"
    assert result["dns_settings"]["authoritative_ttl"] == 120
    assert set(result["dns_settings"]).isdisjoint({"listen_addresses", "domains", "authoritative_serial"})
    assert "kind" not in result and result["test_only"] and result["consistency_only"]
    assert result["native_acceptance"] is False and result["formal_acceptance"] is False
    assert b"synthetic-private" not in public_bytes(result)
    assert result["projection_sha256"] == {
        key: hashlib.sha256(public_bytes(result[key])).hexdigest()
        for key in ("review", "original_row", "browser_fields", "dns_settings")
    }
    result["dns_settings"]["listen_interfaces"].clear()
    assert stored[0]["dns_settings"]["listen_interfaces"] == ["eth1", "eth2"]


def test_private_tokens_and_derived_display_do_not_affect_digests(dns_form: str) -> None:
    """Compare two captures with identical desired settings and different private controls.

    Args:
        dns_form: Rendered existing DNS settings form.
    """
    first = _Transport(dns_form)
    second = _Transport(dns_form.replace("synthetic-private-dns", "rotated-dns-token")
                        .replace("2026110801", "2026110802").replace("192.0.2.20", "192.0.2.21"))
    for index, review in enumerate(second.reviews):
        review["plan_token"] = f"rotated-plan-{index}"
    assert capture_restoration_baseline(first.client, "eth1", _MAC, lambda _: None) == (
        capture_restoration_baseline(second.client, "eth1", _MAC, lambda _: None)
    )


@pytest.mark.parametrize(("field", "value"), [
    ("active_task", {"status": "running"}), ("active_task", {"status": "pending"}),
    ("initial_apply_required", True), ("pending_count", False), ("pending_count", 1),
    ("execution_count", 1), ("requested_units", ["dnsmasq"]), ("units", [{"id": "other"}]),
])
def test_dirty_default_review_stops_before_checkpoint(dns_form: str, field: str, value: Any) -> None:
    """Refuse nonempty or incorrectly typed review state at the first GET.

    Args:
        dns_form: Rendered existing DNS settings form.
        field: Review field changed by this case.
        value: Dirty or malformed field value.
    """
    transport = _Transport(dns_form)
    transport.reviews[0][field] = value
    with pytest.raises(GuestRefusal, match="^restoration_baseline_unavailable$"):
        capture_restoration_baseline(transport.client, "eth1", _MAC, lambda _: pytest.fail("Unexpected checkpoint"))
    assert transport.requests == [("GET", _PATHS[0])]


@pytest.mark.parametrize(("field", "value"), [
    ("id", True), ("mac_address", "02:00:00:00:00:02"), ("mtu", "1500"), ("admin_up", 1),
    ("ipv6_cidr", "192.0.2.20/24"), ("ip_cidr", {"secret": "synthetic"}),
])
def test_invalid_original_interface_stops_before_dns(dns_form: str, field: str, value: Any) -> None:
    """Reject identity and desired-field drift before publishing.

    Args:
        dns_form: Rendered existing DNS settings form.
        field: Original row field changed by this case.
        value: Malformed or unexpected field value.
    """
    transport = _Transport(dns_form)
    transport.rows[0][field] = value
    with pytest.raises(GuestRefusal, match="^restoration_baseline_unavailable$"):
        capture_restoration_baseline(transport.client, "eth1", _MAC, lambda _: pytest.fail("Unexpected checkpoint"))
    assert transport.requests == [("GET", path) for path in _PATHS[:2]]


@pytest.mark.parametrize(("old", "new"), [
    ('method="post"', 'method="get"'),
    ('name="enabled"', 'name="unknown"'),
    ('name="expand_hosts"', 'name="expand_hosts" disabled'),
    ('name="enabled"', 'name="enabled" value'),
    ('name="csrf"', 'name="csrf" name="duplicate"'),
    ('name="csrf"', 'name="csrf" form="other"'),
    ('name="listen_interfaces_present" value="1"', 'name="listen_addresses_present" value="1"'),
    ('value="queries-extra" ', 'value="queries-extra" selected '),
    ('name="authoritative_contact"', 'type="password" name="authoritative_contact"'),
    ('value="hostmaster.example"', 'value="synthetic-private-plan"'),
    ('name="upstream_servers"', 'name="upstream_servers" disabled'),
    ('name="upstream_servers"', 'name="upstream_servers" dirname="domains"'),
    ('<fieldset class=', '<fieldset disabled class='),
    ('corp.example=192.0.2.54', "x" * 16_385),
])
def test_dns_form_refuses_ambiguous_or_private_controls(dns_form: str, old: str, new: str) -> None:
    """Reject controls outside the supported exact settings projection.

    Args:
        dns_form: Rendered existing DNS settings form.
        old: Original template output fragment.
        new: Malformed or private replacement.
    """
    assert old in dns_form
    transport = _Transport(dns_form.replace(old, new, 1))
    with pytest.raises(GuestRefusal, match="^restoration_baseline_unavailable$"):
        capture_restoration_baseline(transport.client, "eth1", _MAC, lambda _: pytest.fail("Unexpected checkpoint"))
    assert transport.requests == [("GET", path) for path in _PATHS]


@pytest.mark.parametrize("decoration", ["duplicate", "external", "inert", "datalist"])
def test_dns_form_ownership_is_unambiguous(dns_form: str, decoration: str) -> None:
    """Reject duplicate forms, externally associated controls, and inert forms.

    Args:
        dns_form: Rendered existing DNS settings form.
        decoration: Ambiguous or inert form scenario.
    """
    if decoration == "duplicate":
        dns_form += dns_form
    elif decoration == "external":
        dns_form = '<input form="settings" name="listen_interfaces" value="eth3">' + dns_form.replace(
            "<form ", '<form id="settings" ', 1,
        )
    elif decoration == "inert":
        dns_form = f"<template>{dns_form}</template>"
    else:
        dns_form = f"<datalist>{dns_form}</datalist>"
    transport = _Transport(dns_form)
    with pytest.raises(GuestRefusal, match="^restoration_baseline_unavailable$"):
        capture_restoration_baseline(transport.client, "eth1", _MAC, lambda _: pytest.fail("Unexpected checkpoint"))


@pytest.mark.parametrize("observation", [1, 2])
@pytest.mark.parametrize("page", ["interface", "dns"])
def test_drift_preserves_only_any_original_checkpoint(dns_form: str, observation: int, page: str) -> None:
    """Refuse either prepublication or postpublication observation drift.

    Args:
        dns_form: Rendered existing DNS settings form.
        observation: Changed second or final observation index.
        page: Page containing changed desired state.
    """
    transport = _Transport(dns_form)
    if page == "interface":
        transport.rows[observation]["gateway"] = ""
    else:
        transport.forms[observation] = dns_form.replace("ns.example", "ns2.example")
    stored: list[dict[str, Any]] = []
    reason = "restoration_baseline_unavailable" if observation == 1 else "restoration_checkpoint_uncertain"
    with pytest.raises(GuestRefusal, match=f"^{reason}$"):
        capture_restoration_baseline(transport.client, "eth1", _MAC, stored.append)
    assert len(stored) == observation - 1
    assert transport.requests == [("GET", path) for path in _PATHS * (observation + 1)]
    if stored:
        assert stored[0]["original_row"]["gateway"] is None
        assert stored[0]["dns_settings"]["authoritative_server"] == "ns.example"


def test_publisher_exception_stops_at_six_reads(dns_form: str) -> None:
    """Preserve a publication attempt and hide its exception detail.

    Args:
        dns_form: Rendered existing DNS settings form.
    """
    transport = _Transport(dns_form)
    stored: list[dict[str, Any]] = []

    def uncertain(value: dict[str, Any]) -> None:
        """Simulate an exception after the publisher retained its payload.

        Args:
            value: Original independent checkpoint copy.
        """
        stored.append(value)
        raise OSError("synthetic-private-publisher-detail")

    with pytest.raises(GuestRefusal, match="^restoration_checkpoint_uncertain$"):
        capture_restoration_baseline(transport.client, "eth1", _MAC, uncertain)
    assert len(stored) == 1
    assert transport.requests == [("GET", path) for path in _PATHS * 2]


@pytest.mark.parametrize("index", [0, 1, 2, 6, 7, 8])
def test_redirect_stops_without_replay(dns_form: str, index: int) -> None:
    """Refuse redirects from any initial or final page without following the location.

    Args:
        dns_form: Rendered existing DNS settings form.
        index: Exact GET index that returns a redirect.
    """
    transport = _Transport(dns_form)
    transport.status[index] = 307
    stored: list[dict[str, Any]] = []
    reason = "restoration_checkpoint_uncertain" if index >= 6 else "restoration_baseline_unavailable"
    with pytest.raises(GuestRefusal, match=f"^{reason}$"):
        capture_restoration_baseline(transport.client, "eth1", _MAC, stored.append)
    assert len(stored) == int(index >= 6)
    assert transport.requests == [("GET", path) for path in (_PATHS * 3)[:index + 1]]
