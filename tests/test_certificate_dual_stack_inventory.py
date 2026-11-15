"""Synthetic family-aware inventory checks; never native or formal acceptance."""

from __future__ import annotations

import copy
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.interop import certificate_dual_stack_guest as guest  # noqa: E402 - Local interop module.
from scripts.interop import certificate_dual_stack_inventory as inventory  # noqa: E402 - Local interop module.
from scripts.interop.certificate_dual_stack_contract import ContractRefusal  # noqa: E402 - Local interop module.

BOOT_ID = "01234567-89ab-cdef-0123-456789abcdef"
INTERFACE = "eth1"
MAC = "00:0c:29:11:22:33"
IPV4_CIDR = "192.168.167.20/24"
IPV6_CIDR = "fd00:1084:1077::20/64"


def complete_payload() -> dict[str, Any]:
    """Build all seven command observations from public synthetic rows."""
    ipv4 = {
        "family": "inet", "local": "192.168.167.20", "prefixlen": 24,
        "scope": "global", "flags": ["permanent"],
        "valid_life_time": 4_294_967_295, "preferred_life_time": 4_294_967_295,
    }
    ipv6 = {
        "family": "inet6", "local": "fd00:1084:1077::20", "prefixlen": 64,
        "scope": "global", "flags": ["permanent"],
        "valid_life_time": "forever", "preferred_life_time": "forever",
    }
    links = [
        {
            "ifname": "eth1", "ifindex": 2, "address": MAC,
            "operstate": "UP", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
        },
        {
            "ifname": "eth2", "ifindex": 3, "address": "00:0c:29:44:55:66",
            "operstate": "UP", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
        },
    ]
    addresses = [
        {"ifname": "eth1", "ifindex": 2, "address": MAC, "addr_info": [ipv4, ipv6]},
        {
            "ifname": "eth2", "ifindex": 3, "address": "00:0c:29:44:55:66",
            "addr_info": [
                {
                    "family": "inet", "local": "192.168.167.30", "prefixlen": 24,
                    "scope": "global", "flags": ["permanent"],
                    "valid_life_time": 4_294_967_295, "preferred_life_time": 4_294_967_295,
                },
                {
                    "family": "inet6", "local": "fd00:1084:1077::30", "prefixlen": 64,
                    "scope": "global", "flags": ["permanent"],
                    "valid_life_time": "forever", "preferred_life_time": "forever",
                },
            ],
        },
    ]
    raw_by_name: dict[str, list[Any]] = {
        "links": links,
        "addresses": addresses,
        "routes4": [{"dst": "default", "dev": "eth1", "table": 254, "fixture": "keep-routes4"}],
        "routes6": [{"dst": "default", "dev": "eth1", "table": 254, "fixture": "keep-routes6"}],
        "rules4": [{"priority": 100, "table": 254, "fixture": "keep-rules4"}],
        "rules6": [{"priority": 100, "table": 254, "fixture": "keep-rules6"}],
        "listeners": [
            "LISTEN 0 128 0.0.0.0:443 0.0.0.0:*",
            "LISTEN 0 128 [::ffff:192.168.167.20]:443 [::]:*",
        ],
    }
    return {
        "schema": 1,
        "kind": "dual-stack-native-raw-observation",
        "test_only": True,
        "formal_acceptance": False,
        "boot_id": BOOT_ID,
        "monotonic_ns": 123,
        "observations": {
            name: {"argv": list(command), "exit_code": 0, "raw": raw_by_name[name]}
            for name, command in guest.NATIVE_COMMANDS
        },
    }


def test_complete_payload_retains_every_interface_and_address_row() -> None:
    """Preserve both families on every interface, including the original raw row."""
    payload = complete_payload()

    rows = inventory.address_inventory(payload, boot_id=BOOT_ID)

    assert {(row["interface"], row["family"], row["address"]) for row in rows} == {
        ("eth1", 4, "192.168.167.20"),
        ("eth1", 6, "fd00:1084:1077::20"),
        ("eth2", 4, "192.168.167.30"),
        ("eth2", 6, "fd00:1084:1077::30"),
    }
    assert all(row["raw"] in payload["observations"]["addresses"]["raw"][
        0 if row["interface"] == "eth1" else 1
    ]["addr_info"] for row in rows)


def test_static_dual_stack_facts_preserve_raw_routes_rules_and_acceptance_boundary() -> None:
    """Report consistency only while leaving all route/rule evidence untouched."""
    payload = complete_payload()
    raw_routes_and_rules = {
        name: copy.deepcopy(payload["observations"][name]["raw"])
        for name in ("routes4", "routes6", "rules4", "rules6")
    }

    facts = inventory.static_address_consistency(
        payload, boot_id=BOOT_ID, interface=INTERFACE, mac=MAC,
        cidrs=[IPV4_CIDR, IPV6_CIDR],
    )

    assert [fact["observation"]["family"] for fact in facts] == [4, 6]
    assert all(fact["static_consistency_only"] is True for fact in facts)
    assert all(fact["test_only"] is True and fact["formal_acceptance"] is False for fact in facts)
    assert {
        name: payload["observations"][name]["raw"]
        for name in raw_routes_and_rules
    } == raw_routes_and_rules


@pytest.mark.parametrize(
    ("binding", "expected_reason"),
    [
        ({"boot_id": "ffffffff-ffff-ffff-ffff-ffffffffffff"}, "original_native_boot_required"),
        ({"interface": "eth0"}, "active_native_interface_required"),
        ({"mac": "00:0c:29:aa:bb:cc"}, "active_native_interface_required"),
    ],
)
def test_boot_interface_and_mac_binding_mismatches_refuse(
    binding: dict[str, str], expected_reason: str,
) -> None:
    """Refuse facts that do not match original boot, interface, or MAC bindings.

    Args:
        binding: One synthetic original-binding mismatch.
        expected_reason: Fixed refusal reason expected from the inventory reader.
    """
    arguments: dict[str, Any] = {
        "boot_id": BOOT_ID, "interface": INTERFACE, "mac": MAC,
        "cidrs": [IPV4_CIDR, IPV6_CIDR],
    }
    arguments.update(binding)

    with pytest.raises(guest.GuestRefusal, match="^" + expected_reason + "$"):
        inventory.static_address_consistency(complete_payload(), **arguments)


def test_expected_address_duplicated_on_another_nic_refuses() -> None:
    """Do not accept an expected host address when a second NIC also reports it."""
    payload = complete_payload()
    duplicate = copy.deepcopy(payload["observations"]["addresses"]["raw"][0]["addr_info"][0])
    payload["observations"]["addresses"]["raw"][1]["addr_info"].append(duplicate)

    with pytest.raises(guest.GuestRefusal, match="^static_address_missing_or_duplicated$"):
        inventory.static_address_consistency(
            payload, boot_id=BOOT_ID, interface=INTERFACE, mac=MAC,
            cidrs=[IPV4_CIDR, IPV6_CIDR],
        )


@pytest.mark.parametrize("producer", ["links", "addresses", "routes4", "routes6", "rules4", "rules6", "listeners"])
def test_missing_complete_producer_refuses(producer: str) -> None:
    """Require all seven successful producer records before interpreting any inventory.

    Args:
        producer: One required public inventory producer to remove.
    """
    payload = complete_payload()
    del payload["observations"][producer]

    with pytest.raises(guest.GuestRefusal, match="^complete_native_inventory_required$"):
        inventory.address_inventory(payload, boot_id=BOOT_ID)


def test_missing_interface_from_address_inventory_refuses() -> None:
    """Do not infer completeness when one link has no matching address row."""
    payload = complete_payload()
    payload["observations"]["addresses"]["raw"].pop()

    with pytest.raises(guest.GuestRefusal, match="^complete_interface_inventory_required$"):
        inventory.address_inventory(payload, boot_id=BOOT_ID)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("local", "not-an-ip-address"),
        ("family", "inet6"),
        ("prefixlen", -1),
        ("prefixlen", 33),
        ("prefixlen", True),
    ],
)
def test_invalid_native_address_family_or_prefix_refuses(field: str, value: Any) -> None:
    """Reject malformed, wrong-family, and out-of-range raw address facts.

    Args:
        field: Raw address field to replace.
        value: Invalid synthetic field value.
    """
    payload = complete_payload()
    payload["observations"]["addresses"]["raw"][0]["addr_info"][0][field] = value

    with pytest.raises(guest.GuestRefusal, match="^native_address_inventory_invalid$"):
        inventory.address_inventory(payload, boot_id=BOOT_ID)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("dynamic", True),
        ("temporary", True),
        ("tentative", True),
        ("dadfailed", True),
        ("deprecated", True),
        ("secondary", True),
        ("tentative", 1),
        ("dadfailed", "true"),
        ("dynamic", 0),
        ("deprecated", None),
        ("flags", ["dynamic"]),
        ("valid_life_time", 0),
        ("preferred_life_time", 4_294_967_296),
    ],
)
def test_nonstatic_or_invalid_lifetime_address_refuses(field: str, value: Any) -> None:
    """Refuse dynamic, transient, tentative, failed-DAD, or invalid lifetime facts.

    Args:
        field: Raw address property to replace.
        value: Synthetic disqualifying or invalid property value.
    """
    payload = complete_payload()
    payload["observations"]["addresses"]["raw"][0]["addr_info"][1][field] = value

    with pytest.raises((guest.GuestRefusal, ContractRefusal)):
        inventory.static_address_consistency(
            payload, boot_id=BOOT_ID, interface=INTERFACE, mac=MAC,
            cidrs=[IPV4_CIDR, IPV6_CIDR],
        )


def test_wildcard_and_ipv4_mapped_listeners_remain_explicit_facts() -> None:
    """Keep unresolved wildcard and mapped IPv4 listener rows in the result."""
    endpoints = inventory.listener_inventory(complete_payload())

    assert endpoints[0].wildcard is True
    assert endpoints[0].family == 4 and endpoints[0].address == "0.0.0.0"
    assert endpoints[1].family == 6
    assert endpoints[1].address == "::ffff:192.168.167.20"
    assert endpoints[1].mapped_ipv4 == "192.168.167.20"


@pytest.mark.parametrize(
    "row",
    [
        "LISTEN 0 128 192.168.167.20:443",
        "LISTEN x 128 192.168.167.20:443 0.0.0.0:*",
        "ESTAB 0 128 192.168.167.20:443 0.0.0.0:*",
        "LISTEN 0 128 host.example:443 0.0.0.0:*",
        "LISTEN 0 128 [2001:db8::20]:70000 [::]:*",
    ],
)
def test_invalid_ss_row_refuses_the_complete_listener_inventory(row: str) -> None:
    """Refuse malformed listener output instead of returning only valid earlier rows.

    Args:
        row: Malformed synthetic ``ss -H -ltn`` row.
    """
    payload = complete_payload()
    payload["observations"]["listeners"]["raw"].append(row)

    with pytest.raises((guest.GuestRefusal, ContractRefusal)):
        inventory.listener_inventory(payload)
