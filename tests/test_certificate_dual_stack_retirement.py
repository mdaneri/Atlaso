"""Synthetic complete dual-stack consistency checks; never native retirement proof."""

from __future__ import annotations

import copy
import hashlib
import json
from types import SimpleNamespace
from typing import Any

import pytest

from scripts.interop import certificate_dual_stack_guest as guest
from scripts.interop import certificate_dual_stack_retirement as retirement
from scripts.interop.certificate_dual_stack_channel import validate_public_payload
from scripts.interop.certificate_dual_stack_contract import ContractRefusal
from scripts.interop.certificate_dual_stack_guest import GuestRefusal, public_bytes
from tests.test_certificate_dual_stack_inventory import BOOT_ID, complete_payload

TARGETS = {4: "192.0.2.10", 6: "fd00:1084:1077::10"}


def payload_fixture() -> dict[str, Any]:
    """Create supported complete raw rows with unrelated active dual-stack state."""
    payload = complete_payload()
    rows = payload["observations"]
    for index, row in enumerate(rows["addresses"]["raw"]):
        row["addr_info"][0]["local"] = f"192.0.2.{20 + index * 10}"
    for family, network, active in ((4, "192.0.2.0/24", "192.0.2.20"),
                                    (6, "fd00:1084:1077::/64", "fd00:1084:1077::20")):
        rows[f"routes{family}"]["raw"] = [
            {"dst": network, "prefsrc": active, "dev": "eth1", "table": "main",
             "protocol": "kernel", "scope": "link", "flags": []},
            {"dst": "default", "dev": "eth1", "table": 100, "metric": 100},
        ]
        rows[f"rules{family}"]["raw"] = [
            {"priority": 0, "src": "all", "table": "local"},
            {"priority": 100, "src": "192.0.2.0" if family == 4 else "fd00:1084:1077::",
             "srclen": 24 if family == 4 else 64, "table": 100},
            {"priority": 32766, "src": "all", "table": "main"},
        ]
    rows["listeners"]["raw"] = [
        "LISTEN 0 128 192.0.2.20:443 0.0.0.0:*",
        "LISTEN 0 128 [fd00:1084:1077::20]:443 [::]:*",
        "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*",
    ]
    return payload


def read(payload: dict[str, Any], family: int = 4) -> dict[str, Any]:
    """Interpret public synthetic data for one explicit retired host.

    Args:
        payload: Complete original synthetic raw inventory.
        family: Explicit target family, excluding opposite-family filtering.
    """
    return retirement.retirement_consistency(payload, boot_id=BOOT_ID, family=family, address=TARGETS[family], port=443)


@pytest.mark.parametrize("family", [4, 6])
def test_native_detail_producers_preserve_ordinary_link_metadata(monkeypatch: pytest.MonkeyPatch, family: int) -> None:
    """Exercise the real collector with representative synthetic detailed JSON output.

    Args:
        monkeypatch: Replaces only command and boot-file reads, never runs native tools.
        family: Retired target family; both link/address producers remain complete.
    """
    rows = payload_fixture()["observations"]
    details = {
        "mtu": 1500, "qdisc": "fq_codel", "linkmode": "DEFAULT", "group": "default",
        "txqlen": 1000, "link_type": "ether", "broadcast": "ff:ff:ff:ff:ff:ff",
        "promiscuity": 0, "allmulti": 0, "min_mtu": 68, "max_mtu": 9000,
        "num_tx_queues": 4, "num_rx_queues": 4, "gso_max_size": 65536,
        "gso_max_segs": 65535, "tso_max_size": 65536, "tso_max_segs": 65535,
        "gro_max_size": 65536, "gso_ipv4_max_size": 65536, "gro_ipv4_max_size": 65536,
        "parentbus": "pci", "parentdev": "0000:02:00.0", "permaddr": "00:0c:29:11:22:aa",
    }
    for row in rows["links"]["raw"] + rows["addresses"]["raw"]:
        row.update(details)
    rows["links"]["raw"][0]["inet6_addr_gen_mode"] = "eui64"
    rows["links"]["raw"][1]["flags"] = ["NO-CARRIER", "BROADCAST", "MULTICAST", "UP"]
    commands = []
    stdout = {
        tuple(row["argv"]): (
            "\n".join(row["raw"]) if name == "listeners" else json.dumps(row["raw"])
        ).encode()
        for name, row in rows.items()
    }

    def collect(command: tuple[str, ...], **_options: object) -> SimpleNamespace:
        """Return fixture bytes only for the exact original producer command.

        Args:
            command: Actual collector argument tuple.
            **_options: Bounded subprocess options supplied by the collector.
        """
        commands.append(command)
        return SimpleNamespace(stdout=stdout[command], stderr=b"", returncode=0)

    monkeypatch.setattr(guest.subprocess, "run", collect)
    monkeypatch.setattr(guest.Path, "read_text", lambda *_args, **_kwargs: BOOT_ID + "\n")
    payload = guest.native_inventory()
    assert commands[:2] == [
        ("ip", "-j", "-details", "link", "show"),
        ("ip", "-j", "-details", "address", "show"),
    ]
    assert payload["observations"] == rows
    digest = hashlib.sha256(public_bytes(payload)).hexdigest()
    assert read(payload, family)["payload_sha256"] == digest
    assert payload["observations"] == rows


@pytest.mark.parametrize("producer", ["links", "addresses"])
@pytest.mark.parametrize(("field", "value"), [
    ("promiscuity", True), ("min_mtu", -1), ("num_rx_queues", 2**32),
    ("gso_max_size", "65536"), ("tso_max_segs", 1.0),
    ("inet6_addr_gen_mode", "0x09"), ("parentdev", {"local": "192.0.2.10"}),
    ("permaddr", "192.0.2.10"),
])
def test_malformed_detail_fields_do_not_establish_absence(producer: str, field: str, value: Any) -> None:
    """Require exact typed detail fields from either producer, on every interface.

    Args:
        producer: Complete detailed link or address inventory.
        field: Supported metadata field carrying a malformed value.
        value: Synthetic malformed value, including types that must not coerce.
    """
    payload = payload_fixture()
    payload["observations"][producer]["raw"][1][field] = value
    with pytest.raises(GuestRefusal, match="^retirement_address_metadata_invalid$"):
        read(payload)


@pytest.mark.parametrize("family", [4, 6])
def test_complete_consistency_preserves_raw_state_and_cannot_mint_a_proof(family: int) -> None:
    """Defaults and broad connected selectors do not prove ownership or acceptance.

    Args:
        family: Exact target family, while every producer remains present.
    """
    payload = payload_fixture()
    original = copy.deepcopy(payload)
    result = read(payload, family)
    assert payload == original
    assert result["payload_sha256"] == hashlib.sha256(public_bytes(original)).hexdigest()
    assert result["exact_address_references_absent"] is True
    assert result["consistency_only"] is True and result["test_only"] is True
    assert result["formal_acceptance"] is False and result["native_acceptance"] is False
    assert result["requires_authenticated_producer"] is True
    assert result["requires_owned_handoff_route_admission"] is True
    assert result["requires_positive_path_and_tcp_nonacceptance"] is True
    assert result["inventory_rows"] == {name: len(row["raw"]) for name, row in original["observations"].items()}
    with pytest.raises(GuestRefusal, match="^public_action_schema_invalid$"):
        validate_public_payload(result)


@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("field", ["dst", "from", "src", "prefsrc", "gateway", "nexthop", "via"])
def test_all_table_route_references_refuse(family: int, field: str) -> None:
    """Find exact references on non-main routes and inside every nexthop.

    Args:
        family: Retired numeric host family.
        field: Supported route field carrying an explicit reference.
    """
    payload = payload_fixture()
    target = TARGETS[family]
    route: dict[str, Any] = {"dst": "default", "table": 12345}
    if field == "nexthop":
        route["nexthops"] = [{"dev": "eth1", "gateway": "192.0.2.1" if family == 4 else "fd00:1084:1077::1"},
                              {"dev": "eth2", "gateway": target}]
    elif field == "via":
        route["via"] = {"family": "inet" if family == 4 else "inet6", "host": target}
    else:
        route[field] = target
    payload["observations"][f"routes{family}"]["raw"].append(route)
    with pytest.raises(GuestRefusal, match="^retired_address_still_referenced$"):
        read(payload, family)


@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("key", ["src", "dst"])
def test_exact_native_rule_selectors_refuse(family: int, key: str) -> None:
    """Source and destination rules retain independent family-specific lengths.

    Args:
        family: Exact retired numeric family.
        key: Native source or destination selector to populate.
    """
    payload = payload_fixture()
    rule = {"priority": 123, "src": "all", key: TARGETS[family], key + "len": 32 if family == 4 else 128}
    payload["observations"][f"rules{family}"]["raw"].append(rule)
    with pytest.raises(GuestRefusal, match="^retired_address_still_referenced$"):
        read(payload, family)


@pytest.mark.parametrize("family", [4, 6])
def test_cross_family_via_is_inspected(family: int) -> None:
    """Do not discard the other route family when an explicit via names the target.

    Args:
        family: Family of the retired next-hop host.
    """
    payload = payload_fixture()
    payload["observations"][f"routes{6 if family == 4 else 4}"]["raw"].append({
        "dst": "default", "via": {"family": "inet" if family == 4 else "inet6", "host": TARGETS[family]},
    })
    with pytest.raises(GuestRefusal, match="^retired_address_still_referenced$"):
        read(payload, family)


@pytest.mark.parametrize("producer", ["addresses", "listeners", "routes6", "rules6"])
def test_ipv4_mapped_references_are_not_hidden_in_ipv6(producer: str) -> None:
    """Retain mapped IPv4 references across every supported IPv6 representation.

    Args:
        producer: Complete producer containing a synthetic mapped reference.
    """
    payload = payload_fixture()
    rows = payload["observations"][producer]["raw"]
    mapped = "::ffff:192.0.2.10"
    if producer == "addresses":
        rows[1]["addr_info"].append({"family": "inet6", "local": mapped, "prefixlen": 128})
    elif producer == "listeners":
        rows.append(f"LISTEN 0 128 [{mapped}]:443 [::]:*")
    elif producer == "routes6":
        rows.append({"dst": mapped, "table": "local"})
    else:
        rows.append({"priority": 123, "src": mapped})
    with pytest.raises(GuestRefusal, match="^retired_address_still_referenced$"):
        read(payload)


@pytest.mark.parametrize("family", [4, 6])
def test_retired_address_on_another_interface_refuses(family: int) -> None:
    """An address remains a reference even on a different or inactive interface.

    Args:
        family: Family to add to the second complete interface row.
    """
    payload = payload_fixture()
    payload["observations"]["addresses"]["raw"][1]["addr_info"].append({
        "family": "inet" if family == 4 else "inet6", "local": TARGETS[family],
        "prefixlen": 32 if family == 4 else 128, "deprecated": True,
    })
    with pytest.raises(GuestRefusal, match="^retired_address_still_referenced$"):
        read(payload, family)


@pytest.mark.parametrize("endpoint", ["0.0.0.0:443", "[::]:443", "*:443"])
def test_management_wildcard_remains_unknown(endpoint: str) -> None:
    """No wildcard listener becomes positive retirement absence.

    Args:
        endpoint: Supported unresolved wildcard representation.
    """
    payload = payload_fixture()
    payload["observations"]["listeners"]["raw"].append(f"LISTEN 0 128 {endpoint} 0.0.0.0:*")
    with pytest.raises(GuestRefusal, match="^retirement_listener_scope_unknown$"):
        read(payload)


@pytest.mark.parametrize("route", [
    {"dst": "default", "nhid": 1}, {"dst": "default", "encap": {}},
    {"dst": "default", "type": "nat"}, {"dst": "default", "from": "::/0", "src": "::/0"},
    {"dst": "192.0.2.0/24"}, {"dst": "default", "tos": "0x100"},
    {"dst": "default", "nexthops": []}, {"dst": "default", "nexthops": [{"dev": "eth1", "nhid": 5}]},
    {"dst": "default", "via": {"family": "inet6", "host": "fd00::1", "extra": "hidden"}},
    {"dst": "default", "flags": ["unknown"]}, {"dst": "default", "metric": True},
])
def test_unsupported_unrelated_route_prevents_zero_projection(route: dict[str, Any]) -> None:
    """Malformed rows in the other family cannot be silently filtered away.

    Args:
        route: Complete synthetic unsupported IPv6 route row.
    """
    payload = payload_fixture()
    payload["observations"]["routes6"]["raw"].append(route)
    with pytest.raises(GuestRefusal, match="^retirement_(route_unsupported|metadata_invalid|numeric_family_changed|nexthops_invalid|via_invalid)$"):
        read(payload)


@pytest.mark.parametrize("rule", [
    {"priority": 1}, {"priority": 1, "src": "all", "not": None},
    {"priority": 1, "src": "all", "from": "all"},
    {"priority": 1, "src": "all", "nat": "192.0.2.10"},
    {"priority": 1, "src": "all", "srclen": 1},
    {"priority": 1, "src": "all", "dstlen": True},
    {"priority": 1, "src": "all", "dstlen": 24},
    {"priority": 1, "src": "fd00::", "srclen": 129},
    {"priority": 1, "src": "192.0.2.1"},
])
def test_unsupported_unrelated_rule_prevents_zero_projection(rule: dict[str, Any]) -> None:
    """Unknown aliases and nonnumeric or invalid lengths refuse in every table.

    Args:
        rule: Malformed synthetic IPv6 native rule row.
    """
    payload = payload_fixture()
    payload["observations"]["rules6"]["raw"].append(rule)
    with pytest.raises(GuestRefusal, match="^retirement_(rule_unsupported|rule_selector_invalid|numeric_family_changed)$"):
        read(payload)


@pytest.mark.parametrize("where", ["peer", "linkinfo", "broadcast", "flags"])
def test_additional_address_metadata_is_never_discarded(where: str) -> None:
    """Unknown peers/tunnels and malformed address metadata cannot establish absence.

    Args:
        where: Synthetic unknown or malformed address-bearing field.
    """
    payload = payload_fixture()
    if where == "linkinfo":
        payload["observations"]["links"]["raw"][1][where] = {"info_data": {"local": TARGETS[4]}}
    else:
        info = payload["observations"]["addresses"]["raw"][1]["addr_info"][0]
        info[where] = TARGETS[4] if where in {"peer", "broadcast"} else ["unknown"]
    expected = "retired_address_still_referenced" if where == "broadcast" else "retirement_address_(state_unsupported|metadata_invalid)"
    with pytest.raises(GuestRefusal, match="^" + expected + "$"):
        read(payload)


def test_valid_other_action_is_not_native_inventory() -> None:
    """A schema-valid canary must refuse before any inventory-key access."""
    payload = {"schema": 1, "kind": "test-only-public-canary", "test_only": True,
               "formal_acceptance": False, "challenge": "public-test-only"}
    validate_public_payload(payload)
    with pytest.raises(GuestRefusal, match="^complete_native_inventory_required$"):
        read(payload)


@pytest.mark.parametrize("change", ["boot", "producer", "row-bound", "hop-bound"])
def test_complete_original_inventory_bounds_are_required(change: str) -> None:
    """Refuse producer loss, boot drift and oversized inventories without truncation.

    Args:
        change: Exact complete-source or finite-bound violation.
    """
    payload = payload_fixture()
    reason = "complete_native_inventory_required"
    if change == "boot":
        payload["boot_id"] = "ffffffff-ffff-ffff-ffff-ffffffffffff"
        reason = "original_native_boot_required"
    elif change == "producer":
        del payload["observations"]["routes6"]
    elif change == "row-bound":
        payload["observations"]["routes4"]["raw"] = [{}] * (retirement.MAX_ROWS + 1)
    else:
        payload["observations"]["routes6"]["raw"].append({"dst": "default", "nexthops": [{"dev": "eth1"}] * 257})
        reason = "retirement_nexthops_invalid"
    with pytest.raises(GuestRefusal, match="^" + reason + "$"):
        read(payload)


@pytest.mark.parametrize("family,address,port", [(True, TARGETS[4], 443), (4, TARGETS[6], 443),
                                                (6, "fe80::1%eth1", 443), (4, TARGETS[4], True)])
def test_input_endpoint_remains_exact(family: Any, address: Any, port: Any) -> None:
    """No family coercion, scoped target or boolean port becomes a retirement fact.

    Args:
        family: Invalid declared family.
        address: Invalid or mismatched target host.
        port: Invalid explicit port.
    """
    with pytest.raises(ContractRefusal, match="^tls_endpoint_invalid$"):
        retirement.retirement_consistency(payload_fixture(), boot_id=BOOT_ID, family=family, address=address, port=port)
