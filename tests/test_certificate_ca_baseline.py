"""Tests for selecting an ordinary CA baseline from its admitted receipts."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/interop"))
import certificate_ca_baseline as baseline  # noqa: E402 - Interop module uses sibling imports.


def test_legacy_static_baseline_is_default_and_keeps_peer_binding() -> None:
    """Keep existing static plans on the same original address."""
    plan = {"baseline_address": "192.168.77.30", "peer_transport": {"baseline_address": "192.168.77.30"}}

    assert baseline.baseline_mode(plan) == "static"
    assert baseline.baseline_address(plan) == "192.168.77.30"


def test_dhcp_baseline_requires_trusted_ordinary_rotation_and_exact_fixture_lease() -> None:
    """Select only the fixed lease named by the ordinary rotation plan and fixture."""
    plan = {
        "ordinary_ca_baseline_mode": "dhcp",
        "trust_model": "trusted-host",
        "scenario": "ordinary-ca-rotation",
        "current_address": "192.168.77.10",
    }
    fixture = {"lease_address": "192.168.77.10"}

    assert baseline.baseline_mode(plan) == "dhcp"
    assert baseline.baseline_address(plan, fixture) == "192.168.77.10"
    with pytest.raises(ValueError, match="ordinary_ca_dhcp_lease_mismatch"):
        baseline.baseline_address(plan, {"lease_address": "192.168.77.11"})


@pytest.mark.parametrize(
    "plan",
    [
        {"ordinary_ca_baseline_mode": "DHCP"},
        {"ordinary_ca_baseline_mode": True},
        {"ordinary_ca_baseline_mode": "dhcp", "trust_model": "legacy", "scenario": "ordinary-ca-rotation"},
        {"ordinary_ca_baseline_mode": "dhcp", "trust_model": "trusted-host", "scenario": "address-handoff"},
    ],
)
def test_invalid_mode_or_scenario_refuses(plan: dict[str, object]) -> None:
    """Reject unknown modes and DHCP outside its admitted trusted scenario.

    Args:
        plan: Candidate plan whose mode or scenario is intentionally invalid.
    """
    with pytest.raises(ValueError, match="ordinary_ca_baseline_mode_invalid"):
        baseline.baseline_mode(plan)
