"""Generated service DNS publication during protected management handoff."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

HELPER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "appliance" / "atlaso-helper"


def load_helper_module():
    loader = importlib.machinery.SourceFileLoader("atlaso_helper_generated_dns", str(HELPER_PATH))
    spec = importlib.util.spec_from_loader("atlaso_helper_generated_dns", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _staged_file(directory: Path, name: str, text: str = "candidate\n") -> Path:
    """Write and return a staged file beneath the supplied directory.

    Args:
        directory: Directory where the staged test file is created.
        name: Filename for the staged configuration.
        text: Text content written to the staged test file.
    """
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(text, encoding="utf-8")
    return path


def _manifest_payload(paths: dict[str, Path]) -> dict:
    """Build a management-handoff manifest from its staged paths.

    Args:
        paths: Manifest path entries to serialize.
    """
    return {
        "schema_version": 1,
        "job_id": "job_dns853abc",
        "network_config_path": str(paths["network"]),
        "firewall_config_path": str(paths["firewall"]),
        "appliance_settings_config_path": str(paths["settings"]),
        "public_services_config_path": str(paths["public"]),
        "previous_management_interfaces": ["eth0"],
        "previous_management_addresses": ["192.0.2.10"],
        "dnsmasq_config_path": str(paths["dnsmasq"]),
        "service_dns_config_path": str(paths["service_dns"]),
    }


def test_service_dns_manifest_path_requires_staged_file_and_dns_rollback_snapshot(monkeypatch, tmp_path):
    """Verify service DNS publication requires a staged file and rollback snapshot.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
        tmp_path: Pytest fixture providing an isolated temporary filesystem root.
    """
    helper = load_helper_module()
    roots = {name: tmp_path / name for name in ("network", "firewall", "settings", "public", "dnsmasq", "handoff")}
    monkeypatch.setattr(helper, "NETWORK_APPLY_DIR", roots["network"])
    monkeypatch.setattr(helper, "FIREWALL_APPLY_DIR", roots["firewall"])
    monkeypatch.setattr(helper, "APPLIANCE_SETTINGS_APPLY_DIR", roots["settings"])
    monkeypatch.setattr(helper, "PUBLIC_SERVICES_APPLY_DIR", roots["public"])
    monkeypatch.setattr(helper, "DNSMASQ_APPLY_DIR", roots["dnsmasq"])
    monkeypatch.setattr(helper, "MANAGEMENT_HANDOFF_APPLY_DIR", roots["handoff"])
    paths = {
        "network": _staged_file(roots["network"], "candidate.network"),
        "firewall": _staged_file(roots["firewall"], "candidate.nft"),
        "settings": _staged_file(roots["settings"], "candidate.json"),
        "public": _staged_file(roots["public"], "candidate.conf"),
        "dnsmasq": _staged_file(roots["dnsmasq"], "candidate.conf"),
        "service_dns": _staged_file(roots["dnsmasq"], "service-dns.conf"),
    }
    manifest = _staged_file(roots["handoff"], "atlaso-management-handoff.json", json.dumps(_manifest_payload(paths)))

    loaded = helper._load_management_handoff_manifest(helper._validate_management_handoff_manifest_path(str(manifest)))
    assert loaded["service_dns_config_path"] == str(paths["service_dns"].resolve())

    for invalid_service_path, error in (
        (str(tmp_path / "outside.conf"), "must be staged under"),
        (str(roots["dnsmasq"] / "missing.conf"), "does not exist"),
    ):
        invalid_paths = {**paths, "service_dns": Path(invalid_service_path)}
        manifest.write_text(json.dumps(_manifest_payload(invalid_paths)), encoding="utf-8")
        with pytest.raises(ValueError, match=error):
            helper._load_management_handoff_manifest(manifest)

    payload = _manifest_payload(paths)
    payload.pop("dnsmasq_config_path")
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="requires the DNS/DHCP rollback snapshot"):
        helper._load_management_handoff_manifest(manifest)


@pytest.mark.parametrize(("public_dynamic", "depot_dynamic"), [(False, False), (True, False), (False, True)])
def test_service_dns_publication_follows_final_readiness_and_failure_rolls_back(monkeypatch, tmp_path, capsys, public_dynamic, depot_dynamic):
    """Defer generated DNS until readiness and restore the captured handoff on failure.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
        tmp_path: Pytest fixture providing an isolated temporary filesystem root.
        capsys: Pytest fixture for capturing output written during the operation.
        public_dynamic: Whether the public listener uses a dynamically assigned address.
        depot_dynamic: Whether the depot listener uses a dynamically assigned address.
    """
    helper = load_helper_module()
    events: list[str] = []
    runtime = tmp_path / "runtime"
    prior_network = _staged_file(runtime, "10-atlaso.network", "previous network\n")
    prior_dns = _staged_file(runtime, "atlaso-dnsmasq.conf", "previous DNS\n")
    network_backup = _staged_file(tmp_path / "backups", "network.bin", "previous network\n")
    dns_backup = _staged_file(tmp_path / "backups", "dns.bin", "previous DNS\n")
    state = {
        "job_id": "job_dns853abc",
        "previous_management_interfaces": ["eth0"],
        "previous_management_addresses": ["192.0.2.10"],
        "previous_https_enabled": False,
        "previous_management_public_port": 80,
        "candidate_management_interface": "eth1",
        "dnsmasq_included": True,
        "snapshots": [
            {"path": str(prior_network), "backup": str(network_backup), "existed": True, "mode": 0o600, "uid": 0, "gid": 0},
            {"path": str(prior_dns), "backup": str(dns_backup), "existed": True, "mode": 0o600, "uid": 0, "gid": 0},
        ],
    }
    candidate_dns = _staged_file(tmp_path / "dnsmasq", "candidate.conf")
    service_dns = _staged_file(tmp_path / "dnsmasq", "service-dns.conf")
    candidate_firewall = _staged_file(tmp_path / "firewall", "candidate.nft", "table inet atlaso { chain input { } }\n")
    previous_firewall = _staged_file(runtime, "previous.nft", "prior firewall\n")
    public_candidate = _staged_file(
        tmp_path / "public", "candidate.conf",
        "# Managed by Atlaso. Local changes may be overwritten.\nserver {\n    listen 192.0.2.20:443 ssl;\n}\n",
    )
    depot_site = _staged_file(runtime, "vcf-offline-depot.conf", _managed_depot_site())
    depot_backup = _staged_file(tmp_path / "backups", "depot.bin", depot_site.read_text(encoding="utf-8"))
    if depot_dynamic:
        depot_metadata = depot_site.stat()
        state["snapshots"].append({
            "path": str(depot_site), "backup": str(depot_backup), "existed": True,
            "mode": depot_metadata.st_mode & 0o777, "uid": depot_metadata.st_uid, "gid": depot_metadata.st_gid,
        })
        state["listener_service_states"] = {
            "vcf_offline_depot": {"active": True, "enabled": True, "enabled_state": "enabled"},
        }
        monkeypatch.setattr(helper, "VCF_DEPOT_SITE_PATH", depot_site)
        monkeypatch.setattr(helper, "_management_handoff_listener_unit_state", lambda _unit: {"active": True, "enabled": True})
    monkeypatch.setattr(helper, "FIREWALL_CONFIG_PATH", previous_firewall)
    monkeypatch.setattr(helper, "FIREWALL_APPLY_DIR", tmp_path / "firewall")
    monkeypatch.setattr(helper, "NAT_RUNTIME_CONFIG_PATH", tmp_path / "runtime" / "nat.conf")

    ready_calls = 0

    def readiness(addresses, *_args, **_kwargs):
        """Return the configured readiness result for the handoff.

        Args:
            addresses: Effective addresses observed for the interface.
            *_args: Positional arguments accepted by the wrapped operation.
            **_kwargs: Keyword arguments accepted by the wrapped operation.
        """
        nonlocal ready_calls
        if addresses in (["192.0.2.21"], ["198.51.100.10"]):
            ready_calls += 1
            events.append("candidate-readiness" if ready_calls == 1 else "final-readiness")
        else:
            events.append("old-readiness")
        return {"stable_samples": 3}

    def dnsmasq_apply(_action, args):
        """Record or reject the dnsmasq action requested by the helper.

        Args:
            _action: DNS publication action requested by the code under test.
            args: Positional arguments supplied to the wrapped operation.
        """
        if args[0] == str(candidate_dns):
            events.append("candidate-dns-apply")
            prior_dns.write_text("candidate DNS\n", encoding="utf-8")
            return 0
        assert args[0] == str(service_dns)
        events.append("service-dns-publication")
        prior_dns.write_text("published service DNS\n", encoding="utf-8")
        return 1

    def restore_snapshot(restored_state):
        """Record the handoff snapshot restored during recovery.

        Args:
            restored_state: Captured handoff state restored during rollback.
        """
        restored.append(restored_state)
        for snapshot in restored_state["snapshots"]:
            helper._restore_management_handoff_snapshot(snapshot)
        return {"old_path_ready": True}

    restored: list[dict] = []
    monkeypatch.setattr(helper, "_recover_management_front_door", lambda **_kwargs: 0)
    monkeypatch.setattr(helper, "_network_identity_preflight", lambda _path: None)
    monkeypatch.setattr(helper, "_network_detection_preflight", lambda _path: None)
    monkeypatch.setattr(helper, "_route_domain_ingress_desired_rules", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(helper, "_snapshot_management_handoff", lambda _payload: state)
    monkeypatch.setattr(helper, "_management_handoff_readiness", readiness)
    monkeypatch.setattr(helper, "_install_management_holdovers", lambda *_args: [])
    monkeypatch.setattr(helper, "_write_management_handoff_state", lambda *_args: None)
    monkeypatch.setattr(helper, "_scope_management_handoff_old_listener", lambda *_args: None)
    monkeypatch.setattr(helper, "_management_handoff_pending_dhcp_interface", lambda _payload: "")
    monkeypatch.setattr(helper, "_management_handoff_public_certificate", lambda *_args: None)
    monkeypatch.setattr(helper, "_management_handoff_validate_public_tls_holdover", lambda *_args: None)
    monkeypatch.setattr(helper, "_management_handoff_previous_public_tls_addresses", lambda *_args: set())
    monkeypatch.setattr(helper, "_management_handoff_candidate_firewall_rules", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(helper, "_management_handoff_firewall_text", lambda candidate, *_args, **_kwargs: candidate)
    monkeypatch.setattr(helper, "_transition_source_guard", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(helper, "_stage_candidate_ingress_guards", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(helper, "_retire_legacy_source_rules", lambda *_args: None)
    monkeypatch.setattr(helper, "_apply_management_candidate_network", lambda *_args: events.append("candidate-network") or prior_network.write_text("candidate network\n", encoding="utf-8"))
    initial_observation = {"complete": True, "phase_address": "192.0.2.21", "links": [{
        "name": "eth9", "configured": True, "address_inventory_complete": True,
        "addresses": [{"address": "192.0.2.21", "state": "assigned", "scope": "global"}],
    }]}
    final_observation = {"complete": True, "phase_address": "198.51.100.10", "links": [{
        "name": "eth9", "configured": True, "address_inventory_complete": True,
        "addresses": [{"address": "198.51.100.10", "state": "assigned", "scope": "global"}],
    }]}
    observations = iter(
        [initial_observation, initial_observation, final_observation] if public_dynamic
        else [initial_observation, initial_observation, initial_observation]
    )
    monkeypatch.setattr(helper, "_wait_network_addresses", lambda *_args, **_kwargs: next(observations))
    monkeypatch.setattr(helper, "_management_handoff_resolve_pending_dhcp", lambda *_args: None)
    monkeypatch.setattr(helper, "_wait_management_handoff_routes", lambda *_args: None)
    monkeypatch.setattr(helper, "_apply_route_domain_ingress", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(helper, "_install_route_domain_intent", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(helper, "_reconcile_route_domains", lambda: None)
    monkeypatch.setattr(
        helper, "_management_handoff_addresses",
        lambda *_args, **kwargs: [
            kwargs["address_observation"]["phase_address"]
            if public_dynamic and kwargs.get("address_observation") else "198.51.100.10"
        ],
    )
    monkeypatch.setattr(helper, "_management_handoff_candidate_ca", lambda *_args: None)
    monkeypatch.setattr(helper, "_management_handoff_upstream_readiness", lambda: {"stable_samples": 3})
    monkeypatch.setattr(helper, "_management_handoff_protocol_holdover", lambda *_args: "")
    monkeypatch.setattr(helper, "_management_handoff_initial_listener_addresses", lambda addresses, *_args, **_kwargs: addresses)
    monkeypatch.setattr(helper, "_load_appliance_settings_config", lambda _path: {
        "management_https_enabled": public_dynamic,
        "management_https_port": 443,
        "management_https_cert_path": str(tmp_path / "management.crt"),
        "management_https_key_path": str(tmp_path / "management.key"),
        "management_public_http_port": 80,
        "management_interface": "eth1",
        "resolver_mode": "external",
        "resolver_servers": ["192.0.2.53"],
    })
    monkeypatch.setattr(helper, "_ca_managed_path", lambda value, _label: Path(value))
    monkeypatch.setattr(helper, "_configure_management_handoff_resolver", lambda _payload: events.append("resolver") or subprocess.CompletedProcess([], 0))
    management_publications = 0

    def configure_management(*_args, **_kwargs):
        """Return the controlled management configuration result.

        Args:
            *_args: Positional arguments accepted by the wrapped operation.
            **_kwargs: Keyword arguments accepted by the wrapped operation.
        """
        nonlocal management_publications
        management_publications += 1
        events.append(f"management-nginx-publication-{management_publications}")
        return (0, None)

    monkeypatch.setattr(helper, "_configure_atlaso_management_https", configure_management)
    if depot_dynamic:
        depot_projections = 0
        original_project_depot = helper._project_management_handoff_depot_listeners

        def project_depot(content, moves):
            """Project listener address moves into the depot configuration.

            Args:
                content: Candidate configuration text to inspect or rewrite.
                moves: Validated listener address moves to apply.
            """
            nonlocal depot_projections
            depot_projections += 1
            events.append(f"depot-projection-{depot_projections}")
            return original_project_depot(content, moves)

        depot_move = {
            "service": "vcf_offline_depot", "old_address": "192.0.2.10",
            "new_address": "198.51.100.10", "interface": "eth9",
        }
        monkeypatch.setattr(helper, "_resolve_management_handoff_listener_moves", lambda _payload, _observation: [depot_move])
        monkeypatch.setattr(helper, "_project_management_handoff_depot_listeners", project_depot)
        monkeypatch.setattr(
            helper, "_verify_management_handoff_depot_runtime",
            lambda _content, _moves: events.append("depot-runtime-readiness"),
        )
    monkeypatch.setattr(helper, "_handle_public_services", lambda *_args, **_kwargs: 0)
    final_management_tls_addresses: list[list[str]] = []

    def render_management(_settings, *_args, **kwargs):
        """Capture the final dedicated TLS listener set.

        Args:
            _settings: Management settings passed to the renderer.
            *_args: Positional arguments accepted by the wrapped operation.
            **kwargs: Keyword arguments forwarded to the wrapped operation.
        """
        https_addresses = kwargs.get("https_listen_addresses")
        if https_addresses is not None:
            final_management_tls_addresses.append(https_addresses)
        return "server {}\n"

    monkeypatch.setattr(helper, "_management_nginx_config", render_management)

    def publish_final(_management, public):
        """Verify final dynamic sockets before allowing native publication.

        Args:
            _management: Final management listener configuration.
            public: Final public listener state to publish.
        """
        assert "listen 198.51.100.10:443 ssl;" in public
        assert "listen 192.0.2.20:443 ssl;" not in public
        events.append("public-final-publication")
        return 0

    monkeypatch.setattr(helper, "_management_handoff_publish_final_sites", publish_final)
    monkeypatch.setattr(helper, "_nginx_test_command", lambda: subprocess.CompletedProcess([], 0))
    monkeypatch.setattr(helper, "_management_handoff_final_source_holds", lambda *_args: [])
    monkeypatch.setattr(helper, "_handle_network", lambda *_args, **_kwargs: 0)
    monkeypatch.setattr(helper, "_parse_network_config", lambda _path: ([], [], []))
    monkeypatch.setattr(helper, "_management_handoff_previous_link_interfaces", lambda _state: set())
    monkeypatch.setattr(helper, "_link_exists", lambda _name: False)
    monkeypatch.setattr(helper, "_verify_management_handoff_migrated_defaults", lambda *_args: None)
    monkeypatch.setattr(helper, "_wait_and_retire_transition_routes", lambda *_args: None)
    monkeypatch.setattr(helper, "_handle_dnsmasq", dnsmasq_apply)
    monkeypatch.setattr(
        helper, "_apply_management_handoff_listener_address_moves",
        lambda *_args: events.append("listener-address-refresh") or [],
    )
    monkeypatch.setattr(helper, "_handle_firewall", lambda *_args: 0)
    monkeypatch.setattr(helper, "_clear_management_handoff_state", lambda **_kwargs: events.append("clear-rollback-state"))
    monkeypatch.setattr(helper, "_restore_management_handoff", restore_snapshot)
    monkeypatch.setattr(helper.os, "chown", lambda *_args: None, raising=False)
    monkeypatch.setattr(helper, "_fsync_file", lambda *_args: None)
    monkeypatch.setattr(helper, "_fsync_directory", lambda *_args: None)

    result = helper._apply_management_handoff({
        "network_config_path": "candidate-network",
        "firewall_config_path": str(candidate_firewall),
        "appliance_settings_config_path": "candidate-settings",
        "public_services_config_path": str(public_candidate),
        "public_dynamic_bindings": [{"interface": "eth9", "old_address": "192.0.2.20"}] if public_dynamic else [],
        "listener_address_moves": [{
            "service": "vcf_offline_depot", "old_address": "192.0.2.10",
            "new_address": "198.51.100.10", "interface": "eth9",
        }] if depot_dynamic else [],
        "dnsmasq_config_path": str(candidate_dns),
        "service_dns_config_path": str(service_dns),
    })

    assert result == 1
    assert events.index("candidate-readiness") < events.index("final-readiness")
    assert events.index("candidate-dns-apply") < events.index("candidate-readiness")
    assert events.index("final-readiness") < events.index("listener-address-refresh")
    assert events.index("listener-address-refresh") < events.index("service-dns-publication")
    if public_dynamic:
        assert events.index("public-final-publication") < events.index("final-readiness")
        assert final_management_tls_addresses
        assert all("198.51.100.10" not in addresses for addresses in final_management_tls_addresses)
    assert restored == [state]
    assert state["dnsmasq_included"] is True
    if depot_dynamic:
        assert events.index("depot-projection-2") < events.index("management-nginx-publication-1")
        assert events.index("depot-projection-3") < events.index("management-nginx-publication-2")
        assert events.index("final-readiness") < events.index("depot-runtime-readiness")
        assert events.index("depot-runtime-readiness") < events.index("service-dns-publication")
        assert depot_site.read_text(encoding="utf-8") == _managed_depot_site()
    assert prior_network.read_text(encoding="utf-8") == "previous network\n"
    assert prior_dns.read_text(encoding="utf-8") == "previous DNS\n"
    failure = json.loads(capsys.readouterr().err.splitlines()[-1])
    assert failure["management_handoff"] == "rolled back"
    assert failure["failing_layer"] == "generated service DNS publication"



def test_listener_move_manifest_rejects_unbounded_or_unowned_mappings(monkeypatch, tmp_path):
    """Verify listener-move manifests reject unbounded or unowned mappings.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
        tmp_path: Pytest fixture providing an isolated temporary filesystem root.
    """
    helper = load_helper_module()
    roots = {name: tmp_path / name for name in ("network", "firewall", "settings", "public", "dnsmasq", "handoff")}
    for name, constant in (
        ("network", "NETWORK_APPLY_DIR"), ("firewall", "FIREWALL_APPLY_DIR"),
        ("settings", "APPLIANCE_SETTINGS_APPLY_DIR"), ("public", "PUBLIC_SERVICES_APPLY_DIR"),
        ("dnsmasq", "DNSMASQ_APPLY_DIR"), ("handoff", "MANAGEMENT_HANDOFF_APPLY_DIR"),
    ):
        monkeypatch.setattr(helper, constant, roots[name])
    paths = {
        name: _staged_file(roots.get(name, roots["dnsmasq"]), filename)
        for name, filename in (
            ("network", "candidate.network"), ("firewall", "candidate.nft"),
            ("settings", "candidate.json"), ("public", "candidate.conf"),
            ("dnsmasq", "candidate.conf"), ("service_dns", "service-dns.conf"),
        )
    }
    paths["network"].write_text(
        "[physical_interfaces]\ninterface=eth1\nipv4_method=dhcp\n", encoding="utf-8",
    )
    manifest = _staged_file(
        roots["handoff"], "atlaso-management-handoff.json",
        json.dumps(_manifest_payload(paths)),
    )
    valid_move = {
        "service": "ntpd", "old_address": "192.0.2.10",
        "new_address": "192.0.2.10", "interface": "eth1",
    }
    for moves in (
        [{"service": "arbitrary", **{k: v for k, v in valid_move.items() if k != "service"}}],
        [{**valid_move, "new_address": "2001:db8::10"}],
        [{**valid_move, "interface": "eth9"}],
        [{**valid_move, "config_path": str(tmp_path / "outside")}],
        [valid_move, valid_move],
        [valid_move] * 33,
    ):
        payload = _manifest_payload(paths)
        payload["listener_address_moves"] = moves
        manifest.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(ValueError):
            helper._load_management_handoff_manifest(manifest)


def test_listener_moves_rebind_narrow_configs_and_restore_files_and_units(monkeypatch, tmp_path):
    """Verify listener moves rebind only selected configs and restore files and units on failure.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
        tmp_path: Pytest fixture providing an isolated temporary filesystem root.
    """
    helper = load_helper_module()
    old, new = "192.0.2.10", "198.51.100.20"
    network = _staged_file(
        tmp_path, "candidate.network",
        "[physical_interfaces]\ninterface=eth1\nipv4_method=dhcp\n",
    )
    paths = {
        "ntpd": _staged_file(
            tmp_path, "ntp.conf",
            f"# Atlaso NTP enabled: true\n{helper.NTP_TIME_MODE_PREFIX} ntp_server\n"
            f"# Atlaso NTP listen addresses: {old}\ninterface ignore wildcard\n"
            f"interface listen {old}\nserver time.example.test\n",
        ),
        "ldap_dropin": _staged_file(
            tmp_path, "ldap.conf",
            f'[Service]\nExecStart=/usr/sbin/slapd -h "ldapi:/// ldaps://{old}:636/ ldap://{old}:389/"\n'
            f'Environment="SLAPD_URLS=ldapi:/// ldaps://{old}:636/ ldap://{old}:389/"\n',
        ),
        "ldap_sysconfig": _staged_file(
            tmp_path, "slapd",
            f'SLAPD_URLS="ldapi:/// ldaps://{old}:636/ ldap://{old}:389/"\n',
        ),
        "kms": _staged_file(
            tmp_path, "kms.json",
            json.dumps({"listen": {"addresses": [old], "port": 5696}, "tls": {"private_key_path": "keep"}}),
        ),
    }
    for constant, path in (
        ("NTP_CONFIG_PATH", paths["ntpd"]),
        ("LDAP_SYSTEMD_DROPIN_PATH", paths["ldap_dropin"]),
        ("LDAP_SYSCONFIG_PATH", paths["ldap_sysconfig"]),
        ("KMS_CONFIG_PATH", paths["kms"]),
    ):
        monkeypatch.setattr(helper, constant, path)
    before = {name: path.read_bytes() for name, path in paths.items()}
    snapshots = []
    for index, path in enumerate(paths.values()):
        backup = _staged_file(tmp_path / "backups", f"{index}.bin")
        backup.write_bytes(path.read_bytes())
        metadata = path.stat()
        snapshots.append({
            "path": str(path), "backup": str(backup), "existed": True,
            "mode": metadata.st_mode & 0o777, "uid": metadata.st_uid, "gid": metadata.st_gid,
        })
    units = {"ntpd.service": True, "slapd.service": True, "atlaso-kmip.service": True}
    enabled = {"ntpd.service": True, "slapd.service": False, "atlaso-kmip.service": True}

    def run(command, **_kwargs):
        """Return the controlled result for the command under test.

        Args:
            command: Command argument list passed to the mocked process runner.
            **_kwargs: Keyword arguments accepted by the wrapped operation.
        """
        if command[0] == "ss":
            listener = next(
                line.split()[2] for line in paths["ntpd"].read_text(encoding="utf-8").splitlines()
                if line.startswith("interface listen ")
            )
            return subprocess.CompletedProcess(command, 0, f"UNCONN 0 0 {listener}:123 0.0.0.0:*\n", "")
        if command[0] != "systemctl":
            return subprocess.CompletedProcess(command, 0, "", "")
        operation, unit = command[1], command[-1]
        if operation == "is-active":
            active = units.get(unit, False)
            return subprocess.CompletedProcess(command, 0 if active else 3, "active\n" if active else "inactive\n", "")
        if operation == "is-enabled":
            is_enabled = enabled.get(unit, False)
            return subprocess.CompletedProcess(command, 0 if is_enabled else 1, "enabled\n" if is_enabled else "disabled\n", "")
        if operation == "stop":
            units[unit] = False
        elif operation == "restart":
            units[unit] = True
        return subprocess.CompletedProcess(command, 0, "", "")

    class Connected:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            """Close the mock socket after its context manager exits.

            Args:
                *_args: Positional arguments accepted by the wrapped operation.
            """
            return False

    monkeypatch.setattr(helper, "_run", run)
    monkeypatch.setattr(helper, "_write_management_handoff_state", lambda *_args: None)
    monkeypatch.setattr(helper, "_ntpd_guard", lambda _phase: 0)
    monkeypatch.setattr(helper, "_ntpd_client_packet_guard_status", lambda *_args: {"active": True})
    monkeypatch.setattr(helper.socket, "create_connection", lambda *_args, **_kwargs: Connected())
    monkeypatch.setattr(helper.os, "chown", lambda *_args: None, raising=False)
    monkeypatch.setattr(helper, "_fsync_directory", lambda *_args: None)
    monkeypatch.setattr(helper, "_fsync_file", lambda *_args: None)
    moves = [
        {"service": service, "old_address": old, "new_address": old, "interface": "eth1"}
        for service in ("ntpd", "ldap", "kms")
    ]
    payload = {"network_config_path": str(network), "listener_address_moves": moves}
    states = {
        "ntpd": {"active": True, "enabled": True, "enabled_state": "enabled"},
        "ldap": {"active": True, "enabled": False, "enabled_state": "disabled"},
        "kms": {"active": True, "enabled": True, "enabled_state": "enabled"},
    }
    state = {"snapshots": snapshots, "listener_service_states": states}
    observation = {
        "complete": True,
        "links": [{
            "name": "eth1", "configured": True, "address_inventory_complete": True,
            "addresses": [{
                "address": new, "scope": "global", "state": "assigned", "source": "DHCPv4",
            }],
        }],
    }
    ambiguous = {
        **observation,
        "links": [{
            **observation["links"][0],
            "addresses": [
                *observation["links"][0]["addresses"],
                {"address": "198.51.100.21", "scope": "global", "state": "assigned"},
            ],
        }],
    }
    with pytest.raises(ValueError, match="ambiguous"):
        helper._resolve_management_handoff_listener_moves(payload, ambiguous)

    effective = helper._apply_management_handoff_listener_address_moves(payload, state, observation)
    assert {move["new_address"] for move in effective} == {new}
    assert f"interface listen {new}" in paths["ntpd"].read_text(encoding="utf-8")
    assert f"# Atlaso NTP listen addresses: {new}" in paths["ntpd"].read_text(encoding="utf-8")
    assert new in paths["ldap_dropin"].read_text(encoding="utf-8")
    assert new in paths["ldap_sysconfig"].read_text(encoding="utf-8")
    kms = json.loads(paths["kms"].read_text(encoding="utf-8"))
    assert kms["listen"] == {"addresses": [new], "port": 5696}
    assert kms["tls"] == {"private_key_path": "keep"}

    for snapshot in snapshots:
        helper._restore_management_handoff_snapshot(snapshot)
    helper._restore_management_handoff_listener_services(state, [])
    assert {name: path.read_bytes() for name, path in paths.items()} == before
    assert units == {unit: True for unit in units}


@pytest.mark.parametrize("service", ["ntpd", "ldap", "kms"])
def test_slaac_listener_moves_select_native_effective_address_with_multiple_globals(tmp_path, service):
    """Verify SLAAC listener moves select the native effective address when several globals exist.

    Args:
        tmp_path: Pytest fixture providing an isolated temporary filesystem root.
        service: Service whose listener behavior or configuration is under test.
    """
    helper = load_helper_module()
    network = tmp_path / "candidate.conf"
    network.write_text(
        "[physical_interfaces]\ninterface=eth9\nadmin_state=up\n"
        "ipv4_method=dhcp\nipv6_enabled=true\n",
        encoding="utf-8",
    )
    move = {"service": service, "old_address": "2001:db8::10",
            "new_address": "2001:db8::10", "interface": "eth9"}
    payload = {"network_config_path": str(network), "listener_address_moves": [move]}
    observation = {"complete": True, "links": [{
        "name": "eth9", "configured": True, "address_inventory_complete": True,
        "addresses": [
            {"address": "2001:db8::30", "scope": "global", "state": "checking"},
            {"address": "2001:db8:2::20", "scope": "global", "state": "assigned"},
            {"address": "2001:db8::10", "scope": "global", "state": "assigned"},
        ],
    }]}
    assert helper._resolve_management_handoff_listener_moves(payload, observation) == [
        {**move, "new_address": "2001:db8:2::20"},
    ]


def test_ldap_listener_rewrite_brackets_ipv6_and_requires_exact_match():
    helper = load_helper_module()
    original = "ldaps://[2001:db8::10]:636/"
    assert helper._rewrite_ldap_listener_text(
        original, "2001:db8::10", "2001:db8::20",
    ) == "ldaps://[2001:db8::20]:636/"
    with pytest.raises(ValueError, match="old address"):
        helper._rewrite_ldap_listener_text("ldaps://192.0.2.99:636/", "192.0.2.10", "192.0.2.20")


def test_listener_rollback_attempts_remaining_services_after_one_failure(monkeypatch):
    """A failed listener restoration cannot skip the other prior runtimes.

    Args:
        monkeypatch: Isolated native adapter substitutions.
    """
    helper = load_helper_module()
    calls = []

    def run(command):
        """Return the controlled result for the command under test.

        Args:
            command: Command argument list passed to the mocked process runner.
        """
        calls.append(command)
        return SimpleNamespace(returncode=1 if command[-1] == "ntpd.service" else 0)

    monkeypatch.setattr(helper, "_run", run)
    monkeypatch.setattr(helper, "_ntpd_guard", lambda _phase: 0)
    monkeypatch.setattr(helper, "_management_handoff_listener_unit_state", lambda _unit: {"active": False, "enabled": False})
    state = {"listener_service_states": {
        "ntpd": {"active": False, "enabled": False, "enabled_state": "disabled"},
        "kms": {"active": False, "enabled": False, "enabled_state": "disabled"},
    }}
    with pytest.raises(ValueError, match="ntpd"):
        helper._restore_management_handoff_listener_services(state, [])
    assert ["systemctl", "stop", "atlaso-kmip.service"] in calls


def _managed_depot_site() -> str:
    return (
        "# Managed by Atlaso. Local changes may be overwritten.\n"
        "# Desired HTTPS endpoint for the VCF Offline Depot.\n"
        "# Listen addresses: 192.0.2.10, 2001:db8::10\n"
        "# Atlaso VCF Offline Depot unauthenticated access: false\n"
        "# Atlaso VCF Offline Depot user: depot-operator\n"
        "server {\n"
        "  listen 192.0.2.10:8443 ssl;\n"
        "  listen [2001:db8::10]:9443 ssl http2;\n"
        "  server_name depot.atlaso.internal;\n"
        "  ssl_certificate /etc/atlaso/depot.pem;\n"
        "  ssl_certificate_key /etc/atlaso/depot.key;\n"
        "  auth_basic \"VCF Depot\";\n"
        "  auth_basic_user_file /etc/atlaso/nginx/htpasswd/vcf-offline-depot.htpasswd;\n"
        "}\n"
    )


def test_depot_listener_projection_changes_only_managed_addresses_and_preserves_ports():
    helper = load_helper_module()
    original = _managed_depot_site()
    moves = [
        {"service": "vcf_offline_depot", "old_address": "192.0.2.10", "new_address": "198.51.100.20"},
        {"service": "vcf_offline_depot", "old_address": "2001:db8::10", "new_address": "2001:db8::20"},
    ]

    projected = helper._project_management_handoff_depot_listeners(original, moves)

    expected = original.replace(
        "# Listen addresses: 192.0.2.10, 2001:db8::10",
        "# Listen addresses: 198.51.100.20, 2001:db8::20",
    ).replace(
        "listen 192.0.2.10:8443 ssl;", "listen 198.51.100.20:8443 ssl;",
    ).replace(
        "listen [2001:db8::10]:9443 ssl http2;", "listen [2001:db8::20]:9443 ssl http2;",
    )
    assert projected == expected
    assert "auth_basic \"VCF Depot\";" in projected
    assert "ssl_certificate_key /etc/atlaso/depot.key;" in projected


def test_depot_listener_runtime_proof_checks_custom_ipv4_ipv6_ports_and_unchanged_moves(monkeypatch):
    """Verify depot listener runtime proof checks configured IPv4 and IPv6 ports and unchanged moves.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
    """
    helper = load_helper_module()
    calls = []

    class Connected:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            """Close the mock socket after its context manager exits.

            Args:
                *_args: Positional arguments accepted by the wrapped operation.
            """
            return False

    monkeypatch.setattr(
        helper.socket, "create_connection",
        lambda endpoint, **_kwargs: calls.append(endpoint) or Connected(),
    )
    content = helper._project_management_handoff_depot_listeners(
        _managed_depot_site(), [
            {"service": "vcf_offline_depot", "old_address": "192.0.2.10", "new_address": "192.0.2.10"},
            {"service": "vcf_offline_depot", "old_address": "2001:db8::10", "new_address": "2001:db8::10"},
        ],
    )

    helper._verify_management_handoff_depot_runtime(content, [
        {"service": "vcf_offline_depot", "old_address": "192.0.2.10", "new_address": "192.0.2.10"},
        {"service": "vcf_offline_depot", "old_address": "2001:db8::10", "new_address": "2001:db8::10"},
    ])

    assert calls == [("192.0.2.10", 8443), ("2001:db8::10", 9443)]


def test_depot_listener_runtime_proof_fails_when_a_port_is_unreachable(monkeypatch):
    """Verify depot listener runtime proof fails when a configured port is unreachable.

    Args:
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
    """
    helper = load_helper_module()
    clock = iter((0.0, 1.0, 6.0))
    attempts = []

    def fail_connect(endpoint, **_kwargs):
        """Raise the configured connection failure for the endpoint probe.

        Args:
            endpoint: Socket endpoint being probed.
            **_kwargs: Keyword arguments accepted by the wrapped operation.
        """
        attempts.append(endpoint)
        raise OSError("connection refused")

    monkeypatch.setattr(helper.socket, "create_connection", fail_connect)
    monkeypatch.setattr(helper.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(helper.time, "sleep", lambda _delay: None)

    with pytest.raises(ValueError, match="socket is not ready"):
        helper._verify_management_handoff_depot_runtime(_managed_depot_site(), [
            {"service": "vcf_offline_depot", "old_address": "192.0.2.10", "new_address": "192.0.2.10"},
        ])
    assert attempts == [("192.0.2.10", 8443)]


def test_depot_listener_site_is_part_of_handoff_rollback_snapshot(tmp_path, monkeypatch):
    """Verify handoff rollback snapshots include the depot listener site.

    Args:
        tmp_path: Pytest fixture providing an isolated temporary filesystem root.
        monkeypatch: Pytest fixture for replacing dependencies with controlled test doubles.
    """
    helper = load_helper_module()
    site = _staged_file(tmp_path, "vcf-offline-depot.conf", _managed_depot_site())
    monkeypatch.setattr(helper, "VCF_DEPOT_SITE_PATH", site)

    paths = helper._management_handoff_runtime_paths({
        "listener_address_moves": [{
            "service": "vcf_offline_depot", "old_address": "192.0.2.10", "new_address": "198.51.100.20",
        }],
    })

    assert paths.count(site) == 1
