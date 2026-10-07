"""Test reverse-proxy publication metadata and generated listener intent."""

from copy import deepcopy

import pytest

from atlaso.app.services.reverse_proxy_publication import (
    directory_entries,
    firewall_rules,
    render_proxy_servers,
    transport_manifest,
    validated_snapshot,
)


def proxy_payload(*, proxy_id: int = 10) -> dict:
    """Return one representative public reverse-proxy desired-state snapshot."""
    return {
        "id": proxy_id,
        "name": "Example portal",
        "hostname": "portal.example.test",
        "description": "Example application",
        "enabled": True,
        "scheme": "https",
        "port": 8443,
        "redirect_http": True,
        "redirect_port": 8080,
        "body_limit": 16_777_216,
        "public_listing": True,
        "managed_dns": False,
        "listeners": [
            {"interface": "eth1", "address": "192.0.2.10"},
            {"interface": "vlan20", "address": "2001:db8::10"},
        ],
        "connect_timeout": 5,
        "read_timeout": 60,
        "send_timeout": 60,
        "routes": [
            {
                "id": 101,
                "position": 0,
                "path_prefix": "/app/",
                "upstream_scheme": "https",
                "upstream_host": "app.example.test",
                "upstream_port": 9443,
                "path_behavior": "preserve",
                "trust_mode": "fingerprint",
                "fingerprint": "ab" * 32,
            },
            {
                "id": 102,
                "position": 1,
                "path_prefix": "/socket/",
                "upstream_scheme": "http",
                "upstream_host": "192.0.2.20",
                "upstream_port": 8080,
                "path_behavior": "strip",
                "trust_mode": "trusted_ca",
                "fingerprint": "",
            },
        ],
    }


def test_transport_manifest_is_deterministic_and_tracks_upstream_policy_and_exclusions():
    """Bind each immutable generation to ordered routes and forbidden local addresses."""
    proxy = proxy_payload()
    other = proxy_payload(proxy_id=11)
    forbidden = ["2001:db8::10", "192.0.2.10", "192.0.2.10"]

    first = transport_manifest([proxy, other], forbidden)
    reordered = transport_manifest([deepcopy(other), deepcopy(proxy)], list(reversed(forbidden)))

    assert first == reordered
    assert first["forbidden_addresses"] == ["192.0.2.10", "2001:db8::10"]
    assert [route["socket_id"] for route in first["routes"]] == [
        "10-101", "10-102", "11-101", "11-102",
    ]
    assert first["routes"][0]["probe_host"] == "portal.example.test"
    assert first["routes"][0]["probe_path"] == "/app/"
    assert first["routes"][1]["probe_host"] == "portal.example.test"
    assert first["routes"][1]["probe_path"] == "/"

    changed_host = deepcopy(proxy)
    changed_host["routes"][0]["upstream_host"] = "new-app.example.test"
    changed_trust = deepcopy(proxy)
    changed_trust["routes"][0]["fingerprint"] = "cd" * 32
    changed_probe_path = deepcopy(proxy)
    changed_probe_path["routes"][0]["path_prefix"] = "/other/"
    changed_exclusions = transport_manifest([proxy], ["192.0.2.11", "2001:db8::10"])

    assert transport_manifest([changed_host], forbidden)["generation"] != transport_manifest([proxy], forbidden)["generation"]
    assert transport_manifest([changed_trust], forbidden)["generation"] != transport_manifest([proxy], forbidden)["generation"]
    assert transport_manifest([changed_probe_path], forbidden)["generation"] != transport_manifest([proxy], forbidden)["generation"]
    assert changed_exclusions["generation"] != transport_manifest([proxy], forbidden)["generation"]


def test_proxy_renderer_keeps_exact_host_custom_redirect_and_route_metadata():
    """Render only selected host/listener pairs and preserve managed proxy headers."""
    proxy = proxy_payload()
    manifest = transport_manifest([proxy], ["192.0.2.10", "2001:db8::10"])

    rendered = render_proxy_servers([proxy], manifest)

    assert rendered.count("server_name portal.example.test;") == 4
    assert rendered.count("if ($http_host = '') { return 404; }") == 4
    assert "listen 192.0.2.10:8443 ssl;" in rendered
    assert "listen [2001:db8::10]:8443 ssl;" in rendered
    assert "listen 192.0.2.10:8080;" in rendered
    assert "listen [2001:db8::10]:8080;" in rendered
    assert "if ($host != portal.example.test) { return 404; }" in rendered
    assert "if ($ssl_server_name !~* ^portal\\.example\\.test$) { return 421; }" in rendered
    assert "return 308 https://portal.example.test:8443$request_uri;" in rendered
    generation_root = f"/run/atlaso-rp/{manifest['generation']}"
    assert f"proxy_pass http://unix:{generation_root}/10-101.sock;" in rendered
    assert f"proxy_pass http://unix:{generation_root}/10-102.sock:/;" in rendered
    assert "proxy_set_header Host $host;" in rendered
    assert "proxy_set_header X-Real-IP $remote_addr;" in rendered
    assert "proxy_set_header X-Forwarded-For $remote_addr;" in rendered
    assert "proxy_set_header Upgrade $http_upgrade;" in rendered
    assert "proxy_set_header Connection $atlaso_reverse_proxy_connection;" in rendered
    assert "proxy_set_header Authorization" not in rendered
    assert "auth_basic" not in rendered
    assert "location / { return 404; }" in rendered


def test_public_directory_visibility_is_independent_of_dns_and_listener_scoped():
    """List opted-in routes only on the selected address regardless of DNS ownership."""
    proxy = proxy_payload()

    without_managed_dns = directory_entries([proxy], "192.0.2.10")
    proxy["managed_dns"] = True
    with_managed_dns = directory_entries([proxy], "192.0.2.10")

    assert with_managed_dns == without_managed_dns
    assert [entry["href"] for entry in without_managed_dns] == [
        "https://portal.example.test:8443/app/",
        "https://portal.example.test:8443/socket/",
    ]
    assert directory_entries([proxy], "192.0.2.99") == []

    proxy["public_listing"] = False
    assert directory_entries([proxy], "192.0.2.10") == []


@pytest.mark.parametrize("mutation", ["proxy_header", "pin", "reserved", "extra_server"])
def test_publication_rejects_changed_directives_or_manifest(mutation):
    """The privileged publication boundary accepts only canonical proxy intent."""
    proxy = proxy_payload()
    manifest = transport_manifest([proxy], ["192.0.2.10", "2001:db8::10"])
    rendered = render_proxy_servers([proxy], manifest)
    assert validated_snapshot(rendered) == ([proxy], manifest)
    if mutation == "proxy_header":
        changed = rendered.replace("proxy_set_header X-Forwarded-For $remote_addr;", "proxy_set_header X-Forwarded-For $http_x_forwarded_for;")
    elif mutation == "pin":
        changed = rendered.replace('"fingerprint":"' + "ab" * 32, '"fingerprint":"' + "cd" * 32, 1)
    elif mutation == "reserved":
        changed = rendered.replace("location ~*", "location ^~", 1)
    else:
        changed = rendered + "server { listen 0.0.0.0:80; location / { return 200; } }\n"
    with pytest.raises(ValueError):
        validated_snapshot(changed)


def test_firewall_rules_are_exact_ipv4_ipv6_listener_and_redirect_admissions():
    """Generate only TCP rules for each enabled listener address and selected port."""
    proxy = proxy_payload()
    disabled = proxy_payload(proxy_id=12)
    disabled["enabled"] = False

    rules = firewall_rules([proxy, disabled])

    assert len(rules) == 4
    assert [
        (rule.interface_name, rule.destination, rule.destination_port)
        for rule in rules
    ] == [
        ("eth1", "192.0.2.10/32", "8443"),
        ("eth1", "192.0.2.10/32", "8080"),
        ("vlan20", "2001:db8::10/128", "8443"),
        ("vlan20", "2001:db8::10/128", "8080"),
    ]
    assert all(rule.direction == "input" and rule.action == "accept" for rule in rules)
    assert all(rule.protocol == "tcp" and rule.source == "any" and rule.enabled for rule in rules)
