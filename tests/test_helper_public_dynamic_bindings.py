"""Public nginx bindings follow verified DHCP/SLAAC addresses during handoff."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.test_helper_generated_dns_handoff import load_helper_module


def _network_file(tmp_path: Path, *, ipv4_method: str = "dhcp", ipv6_enabled: bool = True,
                  ipv6_cidr: str = "") -> Path:
    path = tmp_path / "candidate.conf"
    path.write_text(
        "[physical_interfaces]\n"
        "interface=eth9\n"
        "role=access\n"
        "mode=access\n"
        "admin_state=up\n"
        f"ipv4_method={ipv4_method}\n"
        f"ipv6_enabled={'true' if ipv6_enabled else 'false'}\n"
        f"ipv6_cidr={ipv6_cidr}\n",
        encoding="utf-8",
    )
    return path


def _dual_stack_observation() -> dict:
    return {
        "complete": True,
        "links": [{
            "name": "eth9",
            "configured": True,
            "address_inventory_complete": True,
            "addresses": [
                {"address": "198.51.100.20", "scope": "global", "state": "assigned", "source": "DHCPv4"},
                {"address": "2001:db8::20", "scope": "global", "state": "assigned", "source": "SLAAC"},
            ],
        }],
    }


def test_public_bindings_project_dual_stack_addresses_and_preserve_other_text():
    helper = load_helper_module()
    original = (
        "# keep comment mentioning 192.0.2.10:80\n"
        "server {\n"
        "    listen 192.0.2.10:80;\n"
        "    listen 192.0.2.10:8443 ssl;\n"
        "    listen [2001:db8::10]:443 ssl http2;\n"
        "    listen [2001:db8::10]:9443;\n"
        "    listen 192.0.2.100:80;\n"
        "    proxy_pass http://192.0.2.10:8080;\n"
        "}\n"
    )
    bindings = [
        {"interface": "eth9", "old_address": "192.0.2.10"},
        {"interface": "eth9", "old_address": "2001:db8::10"},
    ]

    rewritten, moves = helper._project_management_handoff_public_bindings(
        original, bindings, _dual_stack_observation(),
    )

    assert rewritten == original.replace(
        "listen 192.0.2.10:", "listen 198.51.100.20:",
    ).replace("listen [2001:db8::10]:", "listen [2001:db8::20]:")
    assert "# keep comment mentioning 192.0.2.10:80" in rewritten
    assert "proxy_pass http://192.0.2.10:8080;" in rewritten
    assert {tuple(move[key] for key in ("interface", "old_address", "new_address")) for move in moves} == {
        ("eth9", "192.0.2.10", "198.51.100.20"),
        ("eth9", "2001:db8::10", "2001:db8::20"),
    }


def test_public_binding_projection_is_noop_without_bindings():
    helper = load_helper_module()
    content = "server {\n    listen 192.0.2.10:443 ssl;\n}\n"
    assert helper._project_management_handoff_public_bindings(content, [], {}) == (content, [])


@pytest.mark.parametrize(
    ("observation", "error"),
    [
        ({"complete": False, "links": []}, "incomplete"),
        ({"complete": True, "links": []}, "observed"),
        ({"complete": True, "links": [{"name": "eth9", "configured": False,
                                           "address_inventory_complete": True, "addresses": []}]}, "observed"),
        ({"complete": True, "links": [{"name": "eth9", "configured": True,
                                           "address_inventory_complete": False, "addresses": []}]}, "observed"),
    ],
)
def test_public_binding_projection_rejects_untrusted_observation(observation, error):
    helper = load_helper_module()
    with pytest.raises(ValueError, match=error):
        helper._project_management_handoff_public_bindings(
            "server { listen 192.0.2.10:443 ssl; }\n",
            [{"interface": "eth9", "old_address": "192.0.2.10"}],
            observation,
        )


def test_public_binding_projection_rejects_ambiguous_or_unusable_family_addresses():
    helper = load_helper_module()
    ambiguous = _dual_stack_observation()
    ambiguous["links"][0]["addresses"].append(
        {"address": "198.51.100.21", "scope": "global", "state": "assigned"},
    )
    with pytest.raises(ValueError, match="ambiguous"):
        helper._project_management_handoff_public_bindings(
            "server { listen 192.0.2.10:443 ssl; }\n",
            [{"interface": "eth9", "old_address": "192.0.2.10"}], ambiguous,
        )

    not_global = _dual_stack_observation()
    not_global["links"][0]["addresses"][0]["scope"] = "link"
    with pytest.raises(ValueError, match="missing or ambiguous"):
        helper._project_management_handoff_public_bindings(
            "server { listen 192.0.2.10:443 ssl; }\n",
            [{"interface": "eth9", "old_address": "192.0.2.10"}], not_global,
        )


@pytest.mark.parametrize(
    ("observed", "selected"),
    [
        (
            [
                {"address": "2001:db8::20", "scope": "global", "state": "assigned", "source": "NDisc"},
                {"address": "2001:db8::10", "scope": "global", "state": "assigned", "source": "NDisc"},
                {"address": "2001:db8::30", "scope": "global", "state": "assigned", "source": "NDisc"},
            ],
            "2001:db8::20",
        ),
        (
            [
                {"address": "2001:db8::30", "scope": "global", "state": "assigned", "source": "NDisc"},
                {"address": "2001:db8::40", "scope": "global", "state": "assigned", "source": "NDisc"},
            ],
            "2001:db8::30",
        ),
    ],
    ids=["old-address-later-in-native-order", "old-address-disappeared"],
)
def test_public_binding_projection_uses_native_order_for_multiple_slaac_addresses(observed, selected):
    """SLAAC projection matches networking's first assigned global address convention.

    Multiple valid SLAAC addresses are expected when temporary/privacy addresses
    coexist with stable addresses. The native observation order matches the
    effective address selected by Network inventory and must remain decisive.

    Args:
        observed: Ordered native addresses reported for the candidate interface.
        selected: Address expected to back the projected listener.
    """
    helper = load_helper_module()
    observation = _dual_stack_observation()
    observation["links"][0]["addresses"] = observed
    content = "server {\n    listen [2001:db8::10]:8443 ssl;\n}\n"

    rewritten, moves = helper._project_management_handoff_public_bindings(
        content,
        [{"interface": "eth9", "old_address": "2001:db8::10"}],
        observation,
    )

    assert f"listen [{selected}]:8443 ssl;" in rewritten
    assert moves == [{
        "interface": "eth9", "old_address": "2001:db8::10", "new_address": selected,
    }]


def test_public_binding_projection_requires_old_listener_to_be_present():
    helper = load_helper_module()
    with pytest.raises(ValueError, match="listener is missing"):
        helper._project_management_handoff_public_bindings(
            "server { listen 192.0.2.99:443 ssl; }\n",
            [{"interface": "eth9", "old_address": "192.0.2.10"}],
            _dual_stack_observation(),
        )


@pytest.mark.parametrize(
    ("network_kwargs", "binding", "error"),
    [
        ({"ipv4_method": "static"}, {"interface": "eth9", "old_address": "192.0.2.10"}, "dynamic"),
        ({"ipv6_enabled": False}, {"interface": "eth9", "old_address": "2001:db8::10"}, "dynamic"),
        ({"ipv6_enabled": True, "ipv6_cidr": "2001:db8::9/64"},
         {"interface": "eth9", "old_address": "2001:db8::10"}, "dynamic"),
        ({}, {"interface": "eth8", "old_address": "192.0.2.10"}, "dynamic Network"),
    ],
)
def test_public_binding_validator_requires_dynamic_candidate_family(tmp_path, network_kwargs, binding, error):
    helper = load_helper_module()
    network = _network_file(tmp_path, **network_kwargs)
    with pytest.raises(ValueError, match=error):
        helper._validate_management_handoff_public_bindings([binding], network)


def test_public_binding_validator_accepts_ipv4_dhcp_and_ipv6_slaac(tmp_path):
    helper = load_helper_module()
    network = _network_file(tmp_path)
    bindings = [
        {"interface": "eth9", "old_address": "192.0.2.10"},
        {"interface": "eth9", "old_address": "2001:db8::10"},
    ]
    assert helper._validate_management_handoff_public_bindings(bindings, network) == bindings
