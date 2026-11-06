"""Bind the original NTP fixture LAN to the observed host topology."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts/interop"))
import ntp_cold_start_native as native  # noqa: E402 - Local interop entrypoint.


@pytest.fixture
def admission(monkeypatch):
    """Stop after the public fixture/host binding, before any VM or credential read."""
    plan = {
        "schema": 1, "kind": "ntp-cold-start-native-plan", "trust_model": "trusted-host",
        "repository": "mdaneri/Atlaso", "pr": 1121, "task_id": "synthetic-ntp-task",
        "source_commit": "1" * 40, "resource_source_commit": "1" * 40,
        "current_address": "192.168.77.10", "baseline_address": "192.168.77.30",
        "static_candidate_address": "192.168.77.40", "negative_address": "192.168.77.11",
        "peer_address": "192.168.77.1", "private_subnet": "192.168.77.0/24",
        "peer_fixture": {"path": "fixture-receipt"},
        "appliance_ownership": {"sha256": "a" * 64}, "peer_ownership": {"sha256": "b" * 64},
        "peer_identity": {"path": "next-check"},
        "trusted_host": {
            "appliance_vmx": "synthetic-appliance.vmx", "peer_vmx": "synthetic-peer.vmx",
            "segment_name": "owned-ntp", "segment_id": "original-segment",
            "segment_receipt": {"path": "original-lan.json", "sha256": "c" * 64},
        },
    }
    fixture = {
        "schema": 1, "kind": "ntp-cold-start-peer-fixture",
        **{key: plan[key] for key in ("repository", "pr", "task_id", "source_commit")},
        "appliance_ownership_sha256": "a" * 64, "peer_ownership_sha256": "b" * 64,
        "appliance_vmx": "synthetic-appliance.vmx", "peer_vmx": "synthetic-peer.vmx",
        "private_network": "lan:owned-ntp", "lan_segment_id": "original-segment",
        "lan_segment_receipt": "original-lan.json", "lan_segment_receipt_sha256": "c" * 64,
    }
    monkeypatch.setattr(native, "reviewed_source", lambda _: None)

    def receipt(reference):
        if reference == plan["peer_fixture"]:
            return fixture
        raise LookupError("reached_next_original_identity_check")

    monkeypatch.setattr(native, "bound_json", receipt)
    return plan, fixture


@pytest.mark.parametrize("field", [
    "appliance_vmx", "peer_vmx", "private_network", "lan_segment_id",
    "lan_segment_receipt", "lan_segment_receipt_sha256",
])
def test_original_fixture_cannot_substitute_another_observed_lan(admission, field):
    """A valid separate host receipt cannot replace the fixture's original binding."""
    plan, fixture = admission
    fixture[field] = "different-original-binding"
    with pytest.raises(native.Refusal, match="original_binding_invalid"):
        native.admit_plan(plan)


def test_matching_original_fixture_proceeds_to_the_next_identity_check(admission):
    """The strict cross-binding admits the honest producer's matching fields."""
    plan, _ = admission
    with pytest.raises(LookupError, match="reached_next_original_identity_check"):
        native.admit_plan(json.loads(json.dumps(plan)))
