"""Deterministic contracts, not execution evidence, for dual-stack fixture work."""

from __future__ import annotations

import sys
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "interop"))
import certificate_dual_stack_contract as contract  # noqa: E402 - Local interop module.


def fixture_plan() -> dict[str, Any]:
    """Return synthetic declared fixture inputs without resource authority."""
    return {
        "ipv4_network": "192.0.2.0/24",
        "ipv6_network": "fd00:1084:1077::/64",
        "main_ipv4": "192.0.2.10/24",
        "main_ipv6": "fd00:1084:1077::10/64",
        "candidate_ipv4": "192.0.2.11/24",
        "candidate_ipv6": "fd00:1084:1077::11/64",
        "peer_ipv4": "192.0.2.20/24",
        "peer_ipv6": "fd00:1084:1077::20/64",
    }


def observation(family: int = 6) -> dict[str, Any]:
    """Return synthetic normalized facts, not authenticated native output.

    Args:
        family: Family to describe with its explicit DAD contract.
    """
    return {
        "schema": 1,
        "kind": "static-fixture-observation",
        "interface": "eth0",
        "mac": "02:00:00:00:00:10",
        "operstate": "UP",
        "carrier": True,
        "family": family,
        "address": "192.0.2.10" if family == 4 else "fd00:1084:1077::10",
        "prefixlen": 24 if family == 4 else 64,
        "source": "static",
        "flags": ["permanent"],
        "dad_state": "not_applicable" if family == 4 else "complete",
        "valid_lifetime": "forever",
        "preferred_lifetime": "forever",
    }


def validate(value: Any, **expected: Any) -> None:
    """Validate normalized consistency without adding native admission.

    Args:
        value: Synthetic observation under test.
        expected: Explicit expected-value overrides.
    """
    arguments = {
        "expected_interface": "eth0",
        "expected_mac": "02:00:00:00:00:10",
        "expected_cidr": "fd00:1084:1077::10/64",
    }
    arguments.update(expected)
    return contract.validate_static_observation(value, **arguments)


def test_planning_includes_reciprocal_ipv6_change_and_restoration() -> None:
    """Require both families to change while preserving the other family."""
    steps = contract.plan_steps(**fixture_plan())
    assert [(step.name, step.ipv4_cidr, step.ipv6_cidr) for step in steps] == [
        ("active_ipv4", "192.0.2.10/24", None),
        ("add_ipv6", "192.0.2.10/24", "fd00:1084:1077::10/64"),
        ("replace_ipv4", "192.0.2.11/24", "fd00:1084:1077::10/64"),
        ("restore_ipv4", "192.0.2.10/24", "fd00:1084:1077::10/64"),
        ("replace_ipv6", "192.0.2.10/24", "fd00:1084:1077::11/64"),
        ("restore_ipv6", "192.0.2.10/24", "fd00:1084:1077::10/64"),
    ]
    with pytest.raises(FrozenInstanceError):
        steps[0].name = "native-pass"


def test_planning_normalizes_equivalent_ipv6_text() -> None:
    """Canonicalize numeric IPv6 text without changing fixture membership."""
    plan = fixture_plan()
    plan["main_ipv6"] = "fd00:1084:1077:0:0:0:0:10/64"
    assert contract.plan_steps(**plan)[1].ipv6_cidr == "fd00:1084:1077::10/64"


@pytest.mark.parametrize("family", [4, 6])
def test_matching_default_route_prefixes_are_not_fixture_networks(family: int) -> None:
    """Refuse a default-route prefix even when every host uses that prefix.

    Args:
        family: Family whose fixture and all corresponding hosts use a zero prefix.
    """
    plan = fixture_plan()
    plan[f"ipv{family}_network"] = "0.0.0.0/0" if family == 4 else "::/0"
    for owner in ("main", "candidate", "peer"):
        key = f"{owner}_ipv{family}"
        plan[key] = plan[key].split("/")[0] + "/0"
    with pytest.raises(contract.ContractRefusal, match="^fixture_prefix_invalid$"):
        contract.plan_steps(**plan)


@pytest.mark.parametrize(("field", "value"), [
    ("ipv4_network", True),
    ("ipv4_network", "192.0.2.1/24"),
    ("ipv4_network", "0.0.0.0/0"),
    ("ipv4_network", "fd00:1084:1077::/64"),
    ("ipv6_network", "fe80::/64"),
    ("ipv6_network", "ff00::/64"),
    ("ipv6_network", "fd00:1084:1077::%eth0/64"),
    ("ipv6_network", "192.0.2.0/24"),
    ("main_ipv4", False),
    ("main_ipv4", "not-an-address"),
    ("main_ipv4", "192.0.2.0/24"),
    ("main_ipv4", "192.0.2.255/24"),
    ("main_ipv4", "192.0.2.10/25"),
    ("candidate_ipv4", "192.0.3.11/24"),
    ("candidate_ipv4", "192.0.2.10/24"),
    ("peer_ipv4", "192.0.2.11/24"),
    ("main_ipv6", "fd00:1084:1077::/64"),
    ("main_ipv6", "fd00:1084:1077::10%eth0/64"),
    ("main_ipv6", "::ffff:192.0.2.10/64"),
    ("main_ipv6", "::1/64"),
    ("main_ipv6", "fe80::10/64"),
    ("main_ipv6", "ff02::10/64"),
    ("main_ipv6", "fd00:1084:1077::10/128"),
    ("candidate_ipv6", "fd00:1084:1078::11/64"),
    ("candidate_ipv6", "fd00:1084:1077::10/64"),
    ("peer_ipv6", "fd00:1084:1077::11/64"),
])
def test_plan_refuses_ambiguous_unusable_or_duplicate_hosts(field: str, value: Any) -> None:
    """Refuse malformed fixtures without reproducing caller input in errors.

    Args:
        field: Fixture input to replace.
        value: Invalid normalized or address value.
    """
    plan = fixture_plan()
    plan[field] = value
    with pytest.raises(contract.ContractRefusal) as failure:
        contract.plan_steps(**plan)
    assert str(failure.value) in {
        "fixture_prefix_invalid", "fixture_address_invalid", "fixture_addresses_must_differ",
    }


@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("lifetime", [1, 4_294_967_295, "forever"])
def test_valid_normalized_facts_return_no_execution_receipt(family: int, lifetime: Any) -> None:
    """A consistent fixture input produces no native acceptance document.

    Args:
        family: IP family under test.
        lifetime: Usable bounded lifetime.
    """
    value = observation(family)
    value["valid_lifetime"] = lifetime
    value["preferred_lifetime"] = lifetime
    cidr = "192.0.2.10/24" if family == 4 else "fd00:1084:1077::10/64"
    assert validate(value, expected_cidr=cidr) is None


@pytest.mark.parametrize(("field", "value"), [
    ("schema", True), ("schema", 2), ("kind", "native-pass"),
    ("interface", "eth1"), ("mac", "02:00:00:00:00:20"),
    ("mac", "00:00:00:00:00:00"), ("mac", "01:00:00:00:00:10"),
    ("mac", "caller-input-must-not-be-echoed"),
    ("operstate", "UNKNOWN"), ("operstate", "DOWN"),
    ("carrier", 1), ("carrier", False), ("source", "dhcp"),
    ("family", True), ("family", 4), ("prefixlen", True), ("prefixlen", 128),
    ("address", "fd00:1084:1077::11"), ("address", "fd00:1084:1077::10%eth0"),
    ("dad_state", "unknown"), ("dad_state", "tentative"), ("dad_state", "failed"),
    ("dad_state", "not_applicable"), ("flags", ["tentative"]), ("flags", ["dadfailed"]),
    ("flags", ["optimistic"]), ("flags", ["nodad"]), ("flags", ["deprecated"]),
    ("flags", ["temporary"]), ("flags", ["dynamic"]), ("flags", ["unknown"]),
    ("flags", ["permanent", "permanent"]), ("flags", [True]),
    ("flags", {"permanent": True}),
    ("valid_lifetime", 0), ("valid_lifetime", -1), ("valid_lifetime", True),
    ("valid_lifetime", 4_294_967_296), ("valid_lifetime", 10**400),
    ("valid_lifetime", "FOREVER"), ("valid_lifetime", 1.0),
    ("preferred_lifetime", 0), ("preferred_lifetime", False),
])
def test_observation_requires_explicit_usable_static_ownership(field: str, value: Any) -> None:
    """Reject uncertain ownership, DAD, liveness, provenance or lifetime facts.

    Args:
        field: Normalized field to replace.
        value: Invalid synthetic fact.
    """
    sample = observation()
    sample[field] = value
    with pytest.raises(contract.ContractRefusal, match="^static_observation_invalid$"):
        validate(sample)


@pytest.mark.parametrize("preferred", [2, "forever"])
def test_preferred_lifetime_cannot_outlive_valid_lifetime(preferred: Any) -> None:
    """Reject internally contradictory normalized lifetimes.

    Args:
        preferred: Preferred lifetime greater than the valid lifetime.
    """
    sample = observation()
    sample.update(valid_lifetime=1, preferred_lifetime=preferred)
    with pytest.raises(contract.ContractRefusal, match="^static_observation_invalid$"):
        validate(sample)


def test_unknown_or_missing_fields_do_not_become_default_active_facts() -> None:
    """Require an exact normalized record without inventing missing evidence."""
    for sample in ({}, {**observation(), "native_pass": True}, None):
        with pytest.raises(contract.ContractRefusal, match="^static_observation_invalid$"):
            validate(sample)
    for key in observation():
        sample = observation()
        del sample[key]
        with pytest.raises(contract.ContractRefusal, match="^static_observation_invalid$"):
            validate(sample)


@pytest.mark.parametrize(("key", "value"), [
    ("expected_interface", "eth0;caller-input"),
    ("expected_mac", "caller-input-must-not-be-echoed"),
    ("expected_cidr", "caller-input-must-not-be-echoed"),
    ("expected_cidr", "fe80::10/64"),
    ("expected_cidr", "::ffff:192.0.2.10/64"),
])
def test_invalid_expected_binding_has_a_fixed_refusal(key: str, value: str) -> None:
    """Invalid expected selectors cannot create a passing normalized record.

    Args:
        key: Expected selector to replace.
        value: Invalid synthetic expected binding.
    """
    with pytest.raises(contract.ContractRefusal, match="^static_observation_invalid$"):
        validate(observation(), **{key: value})
