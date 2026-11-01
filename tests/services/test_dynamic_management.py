"""Exercise applied native management admission and publication without network mutation."""

from copy import deepcopy

import pytest

from atlaso.app.services.dynamic_management import native_management_addresses


def fixture_observation():
    """Return complete identity-bound IPv4LL native evidence."""
    row = {"name": "eth0", "mac": "02:00:00:00:10:77", "role": "management", "mode": "access",
           "admin_state": "up", "ipv4_method": "dhcp", "ipv6_enabled": "false",
           "ipv4_link_local_fallback_enabled": "true"}
    record = {"address": "169.254.20.10", "cidr": "169.254.20.10/16", "scope": "link", "state": "assigned", "source": "IPv4LL"}
    link = {"name": "eth0", "mac": row["mac"], "ethernet": True, "up": True, "carrier": True,
            "configured": True, "address_inventory_complete": True, "addresses": [record]}
    return row, {"complete": True, "links": [link], "conflicts": []}


@pytest.mark.parametrize("change", ["carrier", "identity", "tentative", "foreign", "opt-out", "duplicate", "incomplete", "access"])
def test_apipa_admission_requires_applied_native_ownership(change):
    """Reject stale or unowned address candidates without widening ordinary service bindings.

    Args:
        change: One invalid native or applied-policy prerequisite.
    """
    row, observation = fixture_observation()
    assert native_management_addresses(row, observation)["apipa_addresses"] == ["169.254.20.10"]
    link = observation["links"][0]
    if change == "carrier":
        link["carrier"] = False
    elif change == "identity":
        link["mac"] = "02:00:00:00:10:78"
    elif change == "tentative":
        link["addresses"][0]["state"] = "checking"
    elif change == "foreign":
        link["addresses"][0]["source"] = "static"
    elif change == "opt-out":
        row["ipv4_link_local_fallback_enabled"] = "false"
    elif change == "duplicate":
        observation["links"].append({**deepcopy(link), "name": "eth1", "mac": "02:00:00:00:10:78"})
    elif change == "incomplete":
        observation["complete"] = False
    elif change == "access":
        row["role"] = "access"
    assert native_management_addresses(row, observation)["apipa_addresses"] == []


def test_lease_later_retires_fallback_from_management_projection():
    """Prefer a native lease during the short networkd IPv4LL withdrawal overlap."""
    row, observation = fixture_observation()
    observation["links"][0]["addresses"].append({"address": "192.168.50.10", "cidr": "192.168.50.10/24",
                                                 "scope": "global", "source": "DHCPv4", "state": "assigned"})
    result = native_management_addresses(row, observation)
    assert result == {"addresses": ["192.168.50.10"], "apipa_addresses": [], "ipv4_state": "dhcp-ready"}


@pytest.mark.parametrize("duplicate", [False, True])
def test_handoff_rechecks_live_setup_ownership(tmp_path, monkeypatch, duplicate):
    """A fresh receipt cannot authorize a newly duplicated native address.

    Args:
        tmp_path: Receipted task-owned public receipt fixture.
        monkeypatch: Model root-only metadata and fresh native observations.
        duplicate: Whether another interface has since acquired the address.
    """
    import json
    import stat
    from datetime import datetime, timezone
    from pathlib import Path
    from types import SimpleNamespace

    from tests.test_appliance_helper import load_helper_module

    helper = load_helper_module()
    row, observation = fixture_observation()
    path = tmp_path / "publication.json"
    path.write_text(json.dumps({"phase": "ready", "observed_at": datetime.now(timezone.utc).isoformat(),
                               "interface": row["name"], "mac": row["mac"], "apipa_addresses": ["169.254.20.10"]}))
    if duplicate:
        observation["links"].append({**deepcopy(observation["links"][0]), "name": "eth1"})
    original_lstat = Path.lstat
    def metadata(item):
        """Return admitted root metadata solely for this fixture's receipt and parent.

        Args:
            item: Filesystem path inspected by the guarded helper.
        """
        if item in (path, tmp_path):
            return SimpleNamespace(st_mode=(stat.S_IFDIR | 0o755) if item == tmp_path else (stat.S_IFREG | 0o644),
                                   st_uid=0, st_nlink=1, st_size=path.stat().st_size)
        return original_lstat(item)
    monkeypatch.setattr(Path, "lstat", metadata)
    monkeypatch.setattr(helper, "DYNAMIC_MANAGEMENT_PUBLICATION_PATH", path)
    monkeypatch.setattr(helper, "_network_address_observation", lambda: observation)
    assert helper._published_ipv4ll_address("169.254.20.10") is not duplicate


def test_setup_nginx_excludes_public_protocols_and_nonlocal_clients():
    """Scope APIPA to management paths, exact sockets and link-local client sources."""
    from pathlib import Path

    from tests.test_appliance_helper import load_helper_module

    helper = load_helper_module()
    text = helper._management_nginx_config({"fqdn": "core.atlaso.internal", "management_https_enabled": True},
                Path("/etc/atlaso/https/certs/core.pem"), Path("/etc/atlaso/https/certs/core.key"),
                listen_addresses=["169.254.20.10"])
    assert "listen 169.254.20.10:443 ssl default_server" in text
    assert 'if ($remote_addr !~ "^169\\.254\\.") { return 403; }' in text
    assert "location ^~ /ui/management/" in text
    assert "location ^~ /api/v1/" in text
    for dependency in ("/manifest.webmanifest", "/service-worker.js", "/favicon.ico"):
        assert f"location = {dependency}" in text
    assert "location / { return 404; }" in text
    for protocol in ("/identity", "/PROD/", "/pxe/", "/registry"):
        assert protocol not in text
    excluded = helper._management_nginx_config({"fqdn": "core.atlaso.internal", "management_https_enabled": True},
                listen_addresses=["169.254.20.10", "127.0.0.1"], https_listen_addresses=[])
    assert " ssl" not in excluded
    assert "listen 169.254.20.10:80" in excluded


def test_publication_timer_is_bounded_and_reuses_existing_runtime(tmp_path, monkeypatch):
    """Install only fixed root-owned observer units using an isolated systemd directory.

    Args:
        tmp_path: Receipted task-owned generated directory.
        monkeypatch: Replace service controls and directory sync without touching the host.
    """
    import subprocess

    from tests.test_appliance_helper import load_helper_module

    helper = load_helper_module()
    monkeypatch.setattr(helper, "DYNAMIC_MANAGEMENT_UNIT_DIR", tmp_path)
    monkeypatch.setattr(helper, "_fsync_file", lambda _path: None)
    monkeypatch.setattr(helper, "_fsync_directory", lambda _path: None)
    calls = []
    monkeypatch.setattr(helper, "_run", lambda command, **_kwargs: (calls.append(command), subprocess.CompletedProcess(command, 0))[1])
    helper._install_dynamic_management_service()
    service = (tmp_path / "atlaso-dynamic-management.service").read_text()
    assert "python -I -m atlaso.dynamic_management" in service
    assert "TimeoutStartSec=90" in service
    assert "KillMode=control-group" in service
    assert "OnUnitInactiveSec=5" in (tmp_path / "atlaso-dynamic-management.timer").read_text()
    assert not any("restart" in command for command in calls)


def test_disabling_only_fallback_requires_native_withdrawal(tmp_path, monkeypatch):
    """Do not report an opt-out applied while a networkd-owned fallback remains active.

    Args:
        tmp_path: Receipted task-owned staged Network intent.
        monkeypatch: Replace bounded native observations.
    """
    from tests.test_appliance_helper import load_helper_module

    helper = load_helper_module()
    path = tmp_path / "network.conf"
    path.write_text("[physical_interfaces]\ninterface=eth0\n  ipv4_method=dhcp\n  admin_state=up\n  ipv6_enabled=false\n  ipv4_link_local_fallback_enabled=false\n")
    _, observation = fixture_observation()
    monkeypatch.setattr(helper, "_network_address_observation", lambda: observation)
    monkeypatch.setattr(helper, "_retain_network_conflicts", lambda *_args: None)
    token = helper._IPV4LL_DISABLE_ONLY_LINKS.set(frozenset({"eth0"}))
    try:
        with pytest.raises(ValueError, match="withdrawal"):
            helper._wait_network_addresses(path, attempts=1)
        observation["links"][0]["addresses"] = []
        assert helper._wait_network_addresses(path, attempts=1) == observation
    finally:
        helper._IPV4LL_DISABLE_ONLY_LINKS.reset(token)


@pytest.mark.parametrize("first_boot", [False, True])
def test_tls_publication_and_later_lease_use_applied_identity(client, tmp_path, monkeypatch, first_boot):
    """Publish real signed leaves across APIPA, DHCP and carrier loss with isolated host seams.

    Args:
        client: Isolated application/database fixture.
        tmp_path: Receipted task-owned native configuration fixtures.
        monkeypatch: Replace host operations while retaining real certificate issuance and database behavior.
        first_boot: Freeze published first-boot identity before an explicit Settings Apply exists.
    """
    import json
    import subprocess
    from contextlib import nullcontext

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from sqlalchemy import select

    from atlaso import dynamic_management as publisher
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import (
        CaCertificate,
        CaProfile,
        CaSettings,
        PhysicalInterface,
        Setting,
    )
    from atlaso.app.services.ca import (
        CA_SERVER_PROFILE_NAME,
        ManagedCertificateSpec,
        ensure_default_ca_profiles,
        ensure_managed_certificate_rows,
        ensure_root_ca_material,
        issue_certificate,
        render_ca_apply_payload,
    )
    from atlaso.app.services.dynamic_management import BASELINES_KEY
    from atlaso.app.services.networking import render_network_config
    from tests.test_appliance_helper import load_helper_module

    helper_module = load_helper_module()
    site = tmp_path / "management.conf"
    cert_path, key_path = tmp_path / "management.pem", tmp_path / "management.key"
    row, observation = fixture_observation()
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        interface.mac_address = row["mac"]
        interface.ipv4_method, interface.ip_cidr, interface.ipv6_enabled = "dhcp", None, False
        interface.mode, interface.role, interface.admin_state = "access", "management", "up"
        ca = db.scalar(select(CaSettings))
        ca.enabled = True
        ensure_root_ca_material(ca)
        root_fingerprint = ca.root_fingerprint
        ensure_default_ca_profiles(db)
        profiles = list(db.scalars(select(CaProfile)))
        spec = ManagedCertificateSpec("appliance:https", "applied.atlaso.internal", ["applied.atlaso.internal"], [],
                                     CA_SERVER_PROFILE_NAME, "Management", str(cert_path), str(key_path), "")
        ensure_managed_certificate_rows(db, settings=ca, profiles=profiles, specs=[spec])
        leaf = db.scalar(select(CaCertificate).where(CaCertificate.managed_owner == "appliance:https"))
        issue_certificate(ca, profiles, leaf)
        settings = {"fqdn": "applied.atlaso.internal", "management_interface": "eth0", "management_ip": "",
                    "management_https_enabled": True, "management_https_cert_path": str(cert_path),
                    "management_https_key_path": str(key_path), "web_terminal_enabled": False, "web_terminal_addresses": []}
        baseline = {"network": {"config_preview": render_network_config(interfaces=[interface], vlans=[])},
                    "ca": {"config_preview": render_ca_apply_payload(ca, [leaf], include_private_keys=False, profiles=profiles)}}
        if not first_boot:
            baseline["appliance_settings"] = {"config_preview": json.dumps(settings)}
        else:
            leaf.common_name = "pending.atlaso.internal"
        saved = db.scalar(select(Setting).where(Setting.key == BASELINES_KEY))
        if saved is None:
            db.add(Setting(key=BASELINES_KEY, value=json.dumps(baseline)))
        else:
            saved.value = json.dumps(baseline)
        db.commit()

    publications = []
    receipts = []
    helper = {"_network_transaction_lock": nullcontext, "_network_transaction_state": lambda: {},
              "MANAGEMENT_HANDOFF_STATE_PATH": tmp_path / "absent-state", "_console_bootstrap_is_idle": lambda: True,
              "_recover_management_front_door": lambda **_kwargs: 0, "_network_address_observation": lambda: observation,
              "NGINX_MANAGEMENT_SITE_PATH": site, "NGINX_PUBLIC_SERVICES_SITE_PATH": tmp_path / "absent-public-site",
              "_management_nginx_config": helper_module._management_nginx_config,
              "_ca_managed_path": lambda value, _label: type(cert_path)(value),
              "_run": lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0)}

    def publish_config(payload, **kwargs):
        """Capture exact scoped listener publication after its simulated readiness gate.

        Args:
            payload: Applied Settings identity, independent of pending desired state.
            **kwargs: Explicit verified HTTP/HTTPS listener scopes.
        """
        publications.append((dict(payload), kwargs))
        site.write_text(helper_module._management_nginx_config(payload, cert_path, key_path, **kwargs))
        return 0, None

    helper["_configure_atlaso_management_https"] = publish_config
    helper["_install_nginx_site"] = lambda path, text: (path.write_text(text), 0)[1]
    bootstrap = {"recovery_root_matches_baseline": lambda _db: True,
                 "MARKER_PATH": tmp_path / "first-boot-complete", "COMPLETION_MARKER_TEXT": "complete",
                 "read_regular_text": lambda *_args, **_kwargs: "complete",
                 "write_secret_text_atomic": lambda path, text: path.write_text(text),
                 "write_text_atomic": lambda path, text, **_kwargs: path.write_text(text),
                 "record_ca_publication_baseline": lambda *args, **kwargs: receipts.append(kwargs)}
    monkeypatch.setattr(publisher, "write_publication", lambda value: receipts.append(deepcopy(value)))
    monkeypatch.setattr(publisher, "read_publication", lambda _db: next((item for item in reversed(receipts) if item.get("phase") == "ready"), {}))
    monkeypatch.setattr(publisher.ssl, "get_server_certificate", lambda *_args, **_kwargs: x509.load_pem_x509_certificate(
        cert_path.read_bytes()).public_bytes(serialization.Encoding.PEM).decode())
    publisher.reconcile(helper, bootstrap)
    assert receipts[-1]["apipa_addresses"] == ["169.254.20.10"]
    assert publications[-1][0]["fqdn"] == "applied.atlaso.internal"
    first = x509.load_pem_x509_certificate(cert_path.read_bytes())
    assert str(first.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.IPAddress)[0]) == "169.254.20.10"
    observation["links"][0]["addresses"] = [{"address": "192.168.50.10", "cidr": "192.168.50.10/24",
                                                 "scope": "global", "source": "DHCPv4", "state": "assigned"}]
    bootstrap["recovery_root_matches_baseline"] = lambda _db: False
    with pytest.raises(ValueError, match="pending CA root"):
        publisher.reconcile(helper, bootstrap)
    assert receipts[-1]["addresses"] == ["169.254.20.10"]
    bootstrap["recovery_root_matches_baseline"] = lambda _db: True
    helper["_configure_atlaso_management_https"] = lambda *_args, **_kwargs: (1, None)
    with pytest.raises(ValueError, match="failed readiness"):
        publisher.reconcile(helper, bootstrap)
    assert receipts[-1]["addresses"] == ["169.254.20.10"]
    helper["_configure_atlaso_management_https"] = publish_config
    publisher.reconcile(helper, bootstrap)
    assert receipts[-1]["addresses"] == ["192.168.50.10"]
    assert receipts[-1]["apipa_addresses"] == []
    assert "169.254.20.10" not in site.read_text()
    with SessionLocal() as db:
        assert db.scalar(select(CaSettings)).root_fingerprint == root_fingerprint
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        assert interface.host_ip_cidr == "192.168.50.10/24"
        assert interface.ip_cidr is None
    observation["links"][0]["carrier"] = False
    publisher.reconcile(helper, bootstrap)
    assert receipts[-1]["phase"] == "withdrawn"
    assert "192.168.50.10" not in site.read_text()
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        assert interface.host_ip_cidr is None
        assert interface.host_ip_cidrs == []


@pytest.mark.parametrize("change", ["none", "expired", "future", "network", "settings", "identity", "withdrawn"])
def test_publication_receipt_is_fresh_and_bound_to_applied_inputs(client, tmp_path, monkeypatch, change):
    """Reject stale or superseded receipts even when filesystem ownership is independently admitted.

    Args:
        client: Isolated database fixture.
        tmp_path: Receipted task-owned generated fixture directory.
        monkeypatch: Model Linux root metadata on the Windows test host.
        change: The receipt prerequisite to invalidate.
    """
    import json
    import stat
    from datetime import datetime, timedelta, timezone
    from pathlib import Path
    from types import SimpleNamespace

    from sqlalchemy import select

    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface
    from atlaso.app.services import dynamic_management as admission

    path = tmp_path / "publication.json"
    with SessionLocal() as db:
        identity = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        value = {"phase": "ready", "observed_at": datetime.now(timezone.utc).isoformat(),
                 "interface": identity.name, "mac": identity.mac_address,
                 "network_digest": admission.snapshot_digest(admission.applied_snapshots(db).get("network")),
                 "settings_digest": admission.snapshot_digest(admission.applied_snapshots(db).get("appliance_settings")),
                 "addresses": ["169.254.20.10"], "apipa_addresses": ["169.254.20.10"]}
        if change in {"expired", "future"}:
            value["observed_at"] = (datetime.now(timezone.utc) + timedelta(seconds=-30 if change == "expired" else 30)).isoformat()
        elif change in {"network", "settings"}:
            value[change + "_digest"] = "superseded"
        elif change == "identity":
            value["mac"] = "02:00:00:00:10:78"
        elif change == "withdrawn":
            value["phase"] = "withdrawn"
        path.write_text(json.dumps(value))
        original_lstat = Path.lstat
        monkeypatch.setattr(Path, "lstat", lambda item: SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
                            if item == tmp_path else original_lstat(item))
        monkeypatch.setattr(admission, "PUBLICATION_PATH", path)
        monkeypatch.setattr(admission.os, "fstat", lambda _fd: SimpleNamespace(
            st_mode=stat.S_IFREG | 0o644, st_uid=0, st_size=path.stat().st_size, st_nlink=1))
        assert bool(admission.read_publication(db)) == (change == "none")


def test_console_uses_only_ready_setup_receipt_for_apipa_url(client, monkeypatch):
    """Display the proven APIPA CIDR and no gateway without accepting raw link-local URLs.

    Args:
        client: Isolated seeded database fixture.
        monkeypatch: Replace host status and the independently tested receipt reader.
    """
    import subprocess

    from sqlalchemy import select

    from atlaso.app import appliance_console as console
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface
    from atlaso.app.services import dynamic_management as admission

    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        interface.ipv4_method, interface.ip_cidr, interface.host_ip_cidr = "dhcp", None, None
        interface.role, interface.mode = "management", "access"
        db.commit()
    receipt = {"interface": "eth0", "ipv4_state": "apipa", "apipa_addresses": ["169.254.20.10"],
               "urls": ["https://169.254.20.10:443/ui/management/"]}
    monkeypatch.setattr(admission, "read_publication", lambda _db: receipt)
    monkeypatch.setattr(console, "_appliance_service_statuses", lambda *_args, **_kwargs: ())
    monkeypatch.setattr(console, "_run", lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "", ""))
    status = console.load_console_status()
    assert status.ipv4_cidr == "169.254.20.10/16"
    assert status.ipv4_acquisition == "APIPA fallback"
    assert status.gateway == ""
    assert status.urls == tuple(receipt["urls"])
    receipt.clear()
    assert all("169.254." not in url for url in console.load_console_status().urls)


@pytest.mark.parametrize("ipv6", ["disabled", "static", "automatic"])
def test_bootstrap_identity_preserves_ipv6_mode(client, tmp_path, monkeypatch, ipv6):
    """Retain the root-owned first-boot IPv6 decision before the first Network baseline.

    Args:
        client: Isolated appliance inventory.
        tmp_path: Receipted task-owned bootstrap network fixture.
        monkeypatch: Model admitted Linux root ownership on Windows.
        ipv6: Initial IPv6 mode that fallback must preserve.
    """
    import stat
    from pathlib import Path
    from types import SimpleNamespace

    from atlaso import dynamic_management as publisher
    from atlaso.app.database import SessionLocal

    path = tmp_path / "bootstrap.network"
    policy = "IPv6AcceptRA=no\nLinkLocalAddressing=no\n" if ipv6 == "disabled" else (
        "IPv6AcceptRA=no\nLinkLocalAddressing=yes\n[Address]\nAddress=2001:db8::10/64\n"
        if ipv6 == "static" else "IPv6AcceptRA=yes\nLinkLocalAddressing=yes\n")
    path.write_text("# Atlaso IPv4LL fallback enabled=false\n[Match]\nName=eth0\n[Network]\nDHCP=ipv4\n" + policy)
    original_lstat = Path.lstat
    monkeypatch.setattr(Path, "lstat", lambda item: SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_size=path.stat().st_size)
                        if item == path else original_lstat(item))
    monkeypatch.setattr(publisher, "BOOTSTRAP_NETWORK_PATH", path)
    with SessionLocal() as db:
        row = publisher.bootstrap_row(db, {})
    assert row["ipv4_link_local_fallback_enabled"] == "false"
    assert row["ipv6_enabled"] == ("false" if ipv6 == "disabled" else "true")
    assert row["ipv6_cidr"] == ("2001:db8::10/64" if ipv6 == "static" else "")
