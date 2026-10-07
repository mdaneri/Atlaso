"""Test reverse-proxy publication metadata and generated listener intent."""

import json
from copy import deepcopy

import pytest

from atlaso.app.services.reverse_proxy_publication import (
    INTENT_MARKER,
    MANIFEST_MARKER,
    METADATA_CHUNK_SIZE,
    directory_entries,
    firewall_rules,
    render_proxy_servers,
    retire_obsolete_proxy_certificates,
    transport_manifest,
    validated_snapshot,
)


@pytest.mark.parametrize("retirement", ["disabled", "http", "deleted"])
def test_obsolete_proxy_ca_owners_discard_keys_without_touching_other_owners(retirement):
    """Retire only obsolete proxy owners and preserve manual and active material."""
    from atlaso.app.models import CaCertificate
    from tests.services.test_reverse_proxies import create_db

    engine, db = create_db()
    try:
        retired = CaCertificate(common_name="old.example.test", managed_owner="reverse_proxy:10:https", enabled=True,
                                private_key_encrypted="opaque-test-key")
        active = CaCertificate(common_name="active.example.test", managed_owner="reverse_proxy:11:https", enabled=True,
                               private_key_encrypted="active-test-key")
        manual = CaCertificate(common_name="manual.example.test", managed_owner="", enabled=True,
                               private_key_encrypted="manual-test-key")
        db.add_all([retired, active, manual])
        db.flush()
        old = proxy_payload()
        if retirement == "disabled":
            old["enabled"] = False
        elif retirement == "http":
            old["scheme"] = "http"
        snapshots = [proxy_payload(proxy_id=11)] + ([] if retirement == "deleted" else [old])
        assert retire_obsolete_proxy_certificates(db, snapshots)
        assert not retired.enabled and retired.private_key_encrypted == ""
        assert active.enabled and active.private_key_encrypted == "active-test-key"
        assert manual.enabled and manual.private_key_encrypted == "manual-test-key"
        assert not retire_obsolete_proxy_certificates(db, snapshots)
    finally:
        db.close()
        engine.dispose()


@pytest.mark.parametrize("retirement", ["disabled", "http", "deleted"])
def test_normal_ca_reconciliation_retires_proxy_keys_and_scoped_issuance_preserves_them(client, retirement):
    """Exercise real CA issuance, retirement, and the management-only boundary."""
    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import CaCertificate, CaSettings, ReverseProxy
    from atlaso.app.services.ca import render_ca_apply_payload
    from atlaso.app.ui import ensure_ca_state

    with SessionLocal() as db:
        settings = db.scalar(select(CaSettings))
        settings.enabled = True
        proxy = ReverseProxy(name="Certificate lifecycle", hostname="ca-proxy.example.test", scheme="https", port=8443,
                             enabled=True, listeners=[{"interface": "eth1", "address": "192.0.2.10"}])
        db.add(proxy)
        db.commit()
        owner = f"reverse_proxy:{proxy.id}:https"
        assert ensure_ca_state(db) == []
        certificate = db.scalar(select(CaCertificate).where(CaCertificate.managed_owner == owner))
        assert certificate.enabled and certificate.private_key_encrypted.startswith("fernet:v1:")
        issued_key = certificate.private_key_encrypted
        if retirement == "deleted":
            db.delete(proxy)
        elif retirement == "http":
            proxy.scheme = "http"
        else:
            proxy.enabled = False
        db.commit()
        assert ensure_ca_state(db, managed_owners={"appliance:https"}) == []
        db.refresh(certificate)
        assert certificate.enabled and certificate.private_key_encrypted == issued_key
        assert ensure_ca_state(db) == []
        db.refresh(certificate)
        assert not certificate.enabled and certificate.private_key_encrypted == ""
        assert json.loads(render_ca_apply_payload(settings, [certificate], include_private_keys=False))["certificates"] == []
        assert ensure_ca_state(db) == []
        db.refresh(certificate)
        assert not certificate.enabled and certificate.private_key_encrypted == ""


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


@pytest.mark.parametrize(("route_count", "proxy_count"), [(10, 1), (64, 1), (64, 4)])
def test_large_publication_metadata_uses_bounded_comments(route_count, proxy_count):
    """Multi-route intent must fit nginx's lexer and retain exact validation."""
    proxy = proxy_payload()
    proxy["listeners"] = proxy["listeners"][:1]
    route = proxy["routes"][0]
    proxy["routes"] = [dict(route, id=100 + index, position=index,
                            path_prefix=f"/application-{index}/")
                       for index in range(route_count)]
    proxies = []
    for proxy_index in range(proxy_count):
        item = deepcopy(proxy)
        item["id"] += proxy_index
        item["name"] = f"Portal {proxy_index}"
        item["hostname"] = f"portal-{proxy_index}.example.test"
        for route in item["routes"]:
            route["id"] += 100 * proxy_index
        proxies.append(item)
    manifest = transport_manifest(proxies, ["192.0.2.10", "2001:db8::10"])
    rendered = render_proxy_servers(proxies, manifest)
    lines = rendered.splitlines(keepends=True)
    metadata = [line for line in lines if line.startswith((MANIFEST_MARKER, INTENT_MARKER))]
    assert len(metadata) > 2
    assert all(len(line.encode("ascii")) <= METADATA_CHUNK_SIZE + len(MANIFEST_MARKER) + 1
               for line in metadata)
    assert validated_snapshot(rendered) == (proxies, manifest)
    # Dropped, duplicated, or reordered fragments must never admit a new config.
    fragment_index = next(index for index, line in enumerate(lines) if line.startswith(INTENT_MARKER))
    for changed in (lines[:fragment_index] + lines[fragment_index + 1:],
                    lines[:fragment_index] + [lines[fragment_index]] + lines[fragment_index:],
                    lines[:fragment_index] + [lines[fragment_index + 1], lines[fragment_index]]
                    + lines[fragment_index + 2:]):
        with pytest.raises(ValueError):
            validated_snapshot("".join(changed))


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
