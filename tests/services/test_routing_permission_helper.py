"""Reject unsupported routing policy at the independent privileged validator."""

import pytest

from tests.test_appliance_helper import load_helper_module, wan_config_text


@pytest.mark.parametrize("policy,family,valid", [("deny", "4", True), ("allow", "0", True),
                                                ("automatic", "4", True), ("permit", "4", False),
                                                ("deny", "6", False), ("deny", "false", False)])
def test_helper_validates_routing_policy_and_scope(tmp_path, policy, family, valid):
    """The helper checks policy enums and the common configured family.

    Args:
        tmp_path: Owned test output directory.
        policy: Requested forwarding decision.
        family: Serialized family selection.
        valid: Whether both endpoints support that request.
    """
    helper = load_helper_module()
    path = tmp_path / "wan.conf"
    path.write_text(wan_config_text() + f"\n[routing_rules]\nrouting=Override\n  enabled=true\n  source_interface=eth2\n  destination_interface=eth1.20\n  policy={policy}\n  ip_family={family}\n  priority=100\n", encoding="utf-8")
    errors = helper._wan_config_errors(path)
    assert (not errors) is valid, errors
