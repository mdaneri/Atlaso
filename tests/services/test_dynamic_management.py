"""Exercise applied native management admission and publication without network mutation."""

from copy import deepcopy

import pytest

from atlaso.app.services.dynamic_management import native_management_addresses


def _observer_recovery_fixture(tmp_path, monkeypatch):
    """Prepare real front-door recovery with isolated files and database admission.

    Args:
        tmp_path: Owned public snapshot and live-activation fixture namespace.
        monkeypatch: Replace privileged effects, retaining actual journal recovery.
    """
    import subprocess
    from contextlib import contextmanager

    from atlaso import dynamic_management as publisher
    from tests.test_appliance_helper import (
        load_helper_module,
        patch_appliance_settings_nginx_paths,
    )

    module = load_helper_module()
    paths = patch_appliance_settings_nginx_paths(monkeypatch, module, tmp_path)
    site = paths["management_site"]
    site.parent.mkdir(parents=True, exist_ok=True)
    site.write_text("previous front door\n", encoding="utf-8")
    dropin = tmp_path / "systemd" / "management.conf"
    monkeypatch.setattr(module, "ATLASO_SERVICE_HTTPS_DROPIN_PATH", dropin)
    monkeypatch.setattr(module.os, "chown", lambda *_args: None, raising=False)
    monkeypatch.setattr(module, "_run", lambda command: subprocess.CompletedProcess(command, 0, "", ""))
    monkeypatch.setattr(module, "_nginx_test_command", lambda: subprocess.CompletedProcess([], 0, "", ""))
    monkeypatch.setattr(module, "_reload_nginx", lambda: 0)
    tracked = (site, paths["include"], paths["main"], dropin)
    module._persist_management_front_door_state(tracked)
    for path in tracked:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("live candidate " + path.name, encoding="utf-8")
    state = {"native_locked": False, "recoveries": [], "publications": [], "module": module,
             "site": site, "tracked": {path: path.read_bytes() for path in tracked},
             "journal": module.MANAGEMENT_FRONT_DOOR_STATE_PATH.read_bytes(),
             "backups": {path.name: path.read_bytes() for path in module.MANAGEMENT_FRONT_DOOR_BACKUP_DIR.iterdir()}}

    @contextmanager
    def native_lock():
        """Model only the scoped native lock; real SQLite admission stays independent."""
        assert not state["native_locked"]
        state["native_locked"] = True
        try:
            yield
        finally:
            state["native_locked"] = False

    def recover(*, quiet=False):
        """Run the actual durable restore and cleanup against synthetic paths.

        Args:
            quiet: Preserve the production recovery call's output selection.
        """
        state["recoveries"].append(True)
        return module._recover_management_front_door(quiet=quiet)

    helper = {"_network_transaction_lock": native_lock, "_network_transaction_state": lambda: {},
              "MANAGEMENT_HANDOFF_STATE_PATH": tmp_path / "no-network-handoff", "_console_bootstrap_is_idle": lambda: True,
              "_recover_management_front_door": recover, "_network_address_observation": lambda: {"complete": False}}
    # Recovery precedes this short non-publishing branch; no host reads, CA or UI imports.
    monkeypatch.setattr(publisher, "applied_snapshots", lambda _db: {})
    monkeypatch.setattr(publisher, "bootstrap_row", lambda _db, _observation: {"role": "management", "ipv4_method": "static"})
    monkeypatch.setattr(publisher, "write_publication", lambda value: state["publications"].append(value))
    return publisher, helper, state


def _assert_live_front_door_unchanged(state):
    """Require a live activation's files, journal and backups to remain untouched.

    Args:
        state: Synthetic original bytes and the actual recovery module.
    """
    module = state["module"]
    assert state["recoveries"] == []
    assert {path: path.read_bytes() for path in state["tracked"]} == state["tracked"]
    assert module.MANAGEMENT_FRONT_DOOR_STATE_PATH.read_bytes() == state["journal"]
    assert {path.name: path.read_bytes() for path in module.MANAGEMENT_FRONT_DOOR_BACKUP_DIR.iterdir()} == state["backups"]
    assert not state["native_locked"]


@pytest.mark.parametrize("status", ["pending", "running"])
@pytest.mark.parametrize("timing", ["already-active", "during-observation"])
def test_observer_never_recovers_a_live_settings_apply(client, tmp_path, monkeypatch, status, timing):
    """Active Settings Apply retains its actual prepared journal and candidate files.

    Args:
        client: Initialized isolated SQLite application database.
        tmp_path: Owned synthetic live activation and original journal.
        monkeypatch: Isolate native operations while retaining real database admission.
        status: Apply state that must block recovery.
        timing: Existing job or a submission before the observer takes writer admission.
    """
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import Job

    publisher, helper, state = _observer_recovery_fixture(tmp_path, monkeypatch)

    def submit():
        """Persist the live worker's ordinary Apply ownership before admission."""
        with SessionLocal() as db:
            db.add(Job(id="live-settings-apply", type="appliance-apply", status=status, created_by="test"))
            db.commit()

    def observation():
        """Submit during the read-only native observation, before writer admission."""
        submit()
        return {"complete": False}

    if timing == "already-active":
        submit()
    else:
        helper["_network_address_observation"] = observation
    publisher.reconcile(helper, {})
    _assert_live_front_door_unchanged(state)
    assert state["publications"] == []


@pytest.mark.parametrize("status", ["succeeded", "failed"])
def test_observer_recovers_only_under_retained_writer_admission(client, tmp_path, monkeypatch, status):
    """A terminal job allows genuine recovery while another writer is excluded.

    Args:
        client: Initialized isolated SQLite database.
        tmp_path: Owned interrupted front-door journal and runtime files.
        monkeypatch: Isolate native effects while using real writer contention.
        status: Terminal Apply state which no longer owns the activation.
    """
    from sqlalchemy.exc import OperationalError

    from atlaso.app.database import SessionLocal, engine
    from atlaso.app.models import Job

    publisher, helper, state = _observer_recovery_fixture(tmp_path, monkeypatch)
    with SessionLocal() as db:
        db.add(Job(id="terminal-settings-apply", type="appliance-apply", status=status, created_by="test"))
        db.commit()
    actual_recover = helper["_recover_management_front_door"]

    def checked_recover(*, quiet=False):
        """Require the same SQLite writer boundary during snapshot restoration.

        Args:
            quiet: Production recovery output selection.
        """
        assert state["native_locked"]
        with engine.connect() as other:
            other.exec_driver_sql("PRAGMA busy_timeout=0")
            with pytest.raises(OperationalError, match="locked"):
                other.exec_driver_sql("UPDATE settings SET value=value WHERE 0")
        return actual_recover(quiet=quiet)

    helper["_recover_management_front_door"] = checked_recover
    publisher.reconcile(helper, {})
    assert state["recoveries"] == [True]
    assert state["site"].read_text(encoding="utf-8") == "previous front door\n"
    assert not state["module"].MANAGEMENT_FRONT_DOOR_STATE_PATH.exists()
    assert not state["module"].MANAGEMENT_FRONT_DOOR_BACKUP_DIR.exists()
    assert not state["native_locked"]
    with engine.connect() as other:
        other.exec_driver_sql("PRAGMA busy_timeout=0")
        other.exec_driver_sql("UPDATE settings SET value=value WHERE 0")


def test_observer_failed_recovery_releases_admission_and_retains_journal(client, tmp_path, monkeypatch):
    """An actual restore failure leaves recovery evidence while releasing all locks.

    Args:
        client: Initialized isolated SQLite database.
        tmp_path: Owned interrupted activation fixture.
        monkeypatch: Fail only the isolated nginx configuration check.
    """
    import subprocess

    from atlaso.app.database import engine

    publisher, helper, state = _observer_recovery_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(state["module"], "_nginx_test_command", lambda: subprocess.CompletedProcess([], 1, "", ""))
    with pytest.raises(ValueError, match="previous management publication requires recovery"):
        publisher.reconcile(helper, {})
    assert state["recoveries"] == [True]
    assert state["module"].MANAGEMENT_FRONT_DOOR_STATE_PATH.exists()
    assert state["module"].MANAGEMENT_FRONT_DOOR_BACKUP_DIR.exists()
    assert not state["native_locked"]
    with engine.connect() as other:
        other.exec_driver_sql("PRAGMA busy_timeout=0")
        other.exec_driver_sql("UPDATE settings SET value=value WHERE 0")


def test_observer_writer_admission_failure_cannot_touch_front_door(client, tmp_path, monkeypatch):
    """Refused writer admission precedes every recovery mutation.

    Args:
        client: Initialized isolated SQLite application.
        tmp_path: Owned synthetic live front-door state.
        monkeypatch: Refuse the observer's writer gate before querying ownership.
    """
    publisher, helper, state = _observer_recovery_fixture(tmp_path, monkeypatch)

    def busy(_db):
        """Refuse writer admission before any recovery side effect.

        Args:
            _db: Actual new observer database session.
        """
        raise RuntimeError("synthetic writer admission busy")

    monkeypatch.setattr(publisher, "acquire_network_objects_write_lock", busy)
    with pytest.raises(RuntimeError, match="writer admission busy"):
        publisher.reconcile(helper, {})
    _assert_live_front_door_unchanged(state)


def fixture_observation():
    """Return complete identity-bound IPv4LL native evidence."""
    row = {"name": "eth0", "mac": "02:00:00:00:10:77", "role": "management", "mode": "access",
           "admin_state": "up", "ipv4_method": "dhcp", "ipv6_enabled": "false",
           "ipv4_link_local_fallback_enabled": "true"}
    record = {"address": "169.254.20.10", "cidr": "169.254.20.10/16", "scope": "link", "state": "assigned", "source": "IPv4LL"}
    link = {"name": "eth0", "mac": row["mac"], "ethernet": True, "up": True, "carrier": True,
            "configured": True, "address_inventory_complete": True, "addresses": [record]}
    return row, {"complete": True, "links": [link], "conflicts": []}


@pytest.mark.parametrize("change", ["none", "fingerprint", "key", "address", "hostname", "expired", "future", "missing-san"])
def test_published_tls_pair_requires_applied_identity(tmp_path, change):
    """Pending desired state cannot substitute an unverified installed TLS identity.

    Args:
        tmp_path: Owned isolated certificate fixture directory.
        change: One installed-pair or published-identity prerequisite to invalidate.
    """
    from datetime import datetime, timedelta, timezone
    from ipaddress import ip_address

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    from atlaso.dynamic_management import published_pair_matches

    now = datetime.now(timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "applied.atlaso.internal")])
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(now + timedelta(minutes=5) if change == "future" else now - timedelta(days=1))
               .not_valid_after(now - timedelta(seconds=1) if change == "expired" else now + timedelta(days=1)))
    if change != "missing-san":
        builder = builder.add_extension(x509.SubjectAlternativeName([
            x509.DNSName("pending.atlaso.internal" if change == "hostname" else "applied.atlaso.internal"),
            x509.IPAddress(ip_address("192.0.2.20" if change == "address" else "169.254.20.10")),
        ]), critical=False)
    public = builder.sign(key, hashes.SHA256())
    cert_path, key_path = tmp_path / "leaf.crt", tmp_path / "leaf.key"
    cert_path.write_bytes(public.public_bytes(serialization.Encoding.PEM))
    installed_key = ec.generate_private_key(ec.SECP256R1()) if change == "key" else key
    key_path.write_bytes(installed_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    fingerprint = "0" * 64 if change == "fingerprint" else public.fingerprint(hashes.SHA256()).hex()
    assert published_pair_matches(fingerprint, {"169.254.20.10"}, "applied.atlaso.internal", cert_path, key_path) == (change == "none")


def test_observer_bootstrap_utilities_do_not_import_ui(tmp_path, monkeypatch):
    """Keep steady observer startup independent of the large UI/schema import graph.

    Args:
        tmp_path: Owned public bootstrap marker fixture.
        monkeypatch: Replace the UI module with a failing import boundary.
    """
    import runpy
    import sys
    from pathlib import Path
    from types import ModuleType

    unavailable = ModuleType("atlaso.app.ui")

    def reject_ui_attribute(name):
        """Reject an eagerly requested UI binding.

        Args:
            name: Attribute that would force the cold UI import.
        """
        raise AssertionError(f"marker-only bootstrap requested UI attribute {name}")

    unavailable.__getattr__ = reject_ui_attribute
    monkeypatch.setitem(sys.modules, "atlaso.app.ui", unavailable)
    bootstrap = runpy.run_path(str(Path(__file__).resolve().parents[2] / "scripts/appliance/atlaso-bootstrap-https"))
    marker = tmp_path / "complete"
    marker.write_text(bootstrap["COMPLETION_MARKER_TEXT"])
    assert bootstrap["read_regular_text"](marker, maximum_size=256) == bootstrap["COMPLETION_MARKER_TEXT"]


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


@pytest.mark.parametrize("change", ["none", "carrier", "identity", "tentative", "opt-out", "duplicate", "incomplete", "access"])
def test_protected_handoff_admits_new_native_fallback_without_prior_publication(tmp_path, monkeypatch, change):
    """Use captured Network identity while the observer is excluded by active Apply.

    Args:
        tmp_path: Owned candidate Network fixture root.
        monkeypatch: Isolate native commands and prior-publication access.
        change: Native or policy prerequisite invalidated after the positive control.
    """
    from tests.test_appliance_helper import load_helper_module

    helper = load_helper_module()
    row, observation = fixture_observation()
    path = tmp_path / "candidate.network"
    path.write_text("captured Network fixture\n")
    monkeypatch.setattr(helper, "_parse_network_config", lambda _path: ([row], [], []))
    monkeypatch.setattr(helper, "_published_ipv4ll_address", lambda _value: pytest.fail("new candidates have no observer publication"))
    settings = {"management_interface": "eth0", "management_ip": "", "web_terminal_enabled": False}
    helper._management_handoff_resolve_pending_dhcp(settings, "eth0", observation, network_path=path)
    assert settings["management_ip"] == "169.254.20.10"
    assert helper._management_handoff_addresses(path, address_observation=observation, discovery_attempts=1) == ["169.254.20.10"]
    if change == "none":
        return
    link = observation["links"][0]
    if change == "carrier":
        link["carrier"] = False
    elif change == "identity":
        link["mac"] = "02:00:00:00:10:78"
    elif change == "tentative":
        link["addresses"][0]["state"] = "checking"
    elif change == "opt-out":
        row["ipv4_link_local_fallback_enabled"] = "false"
    elif change == "duplicate":
        observation["links"].append({**deepcopy(link), "name": "eth1", "mac": "02:00:00:00:10:78"})
    elif change == "incomplete":
        observation["complete"] = False
    elif change == "access":
        row["role"] = "access"
    settings["management_ip"] = ""
    with pytest.raises(ValueError):
        helper._management_handoff_resolve_pending_dhcp(settings, "eth0", observation, network_path=path)
    assert settings["management_ip"] == ""


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
    assert helper._published_ipv4ll_address("169.254.20.10", expected_interface="eth0", expected_mac=row["mac"]) is not duplicate
    assert not helper._published_ipv4ll_address("169.254.20.10", expected_interface="eth1", expected_mac=row["mac"])
    assert not helper._published_ipv4ll_address("169.254.20.10", expected_interface="eth0", expected_mac="02:00:00:00:10:78")


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
    assert text.count("  client_max_body_size 1g;") == 1
    assert text.count("location = /ui/management/vcf-helper/sddc-manager/ovas/upload {") == 1
    assert text.count("  client_max_body_size 16g;") == 1
    for protocol in ("/identity", "/PROD/", "/pxe/", "/registry"):
        assert protocol not in text
    excluded = helper._management_nginx_config({"fqdn": "core.atlaso.internal", "management_https_enabled": True},
                listen_addresses=["169.254.20.10", "127.0.0.1"], https_listen_addresses=[])
    assert " ssl" not in excluded
    assert "listen 169.254.20.10:80" in excluded


@pytest.mark.parametrize("https", [False, True])
def test_setup_nginx_proxies_exact_terminal_websocket_dependency(https):
    """Keep the terminal ticket's WebSocket reachable without exposing other paths.

    Args:
        https: Render the applied management listener's protocol.
    """
    from pathlib import Path

    from tests.test_appliance_helper import load_helper_module

    helper = load_helper_module()
    text = helper._ipv4ll_setup_nginx_server(
        {"fqdn": "core.atlaso.internal", "management_https_enabled": https},
        "169.254.20.10", Path("/etc/atlaso/https/certs/core.pem"),
        Path("/etc/atlaso/https/certs/core.key"), http_allowed=not https,
    )
    location = "  location = /terminal/ws {"
    assert location in text
    websocket = text.split(location, 1)[1].split("\n  }", 1)[0]
    assert "proxy_pass http://127.0.0.1:8000;" in websocket
    assert "proxy_http_version 1.1;" in websocket
    assert "proxy_set_header Upgrade $http_upgrade;" in websocket
    assert 'proxy_set_header Connection "upgrade";' in websocket
    assert "proxy_set_header X-Atlaso-Listener-Address $server_addr;" in websocket
    assert f"proxy_set_header X-Forwarded-Proto {'https' if https else 'http'};" in websocket
    guard = 'if ($remote_addr !~ "^169\\.254\\.") { return 403; }'
    assert text.index(guard) < text.index(location)
    assert "location ^~ /terminal/" not in text
    assert "location /terminal/" not in text
    assert "location / { return 404; }" in text


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


@pytest.mark.parametrize("invalid", [
    "none", "missing-proof", "expired", "future", "captured-mac", "observed-mac", "helper-mac", "interface",
    "candidate", "ambiguous", "disabled", "admin-down", "mode", "role", "static", "unconfigured", "incomplete",
    "inventory", "no-carrier", "link-down", "ethernet", "tentative", "foreign", "scope", "cidr", "duplicate", "dhcp", "stale-generic",
])
def test_apipa_handoff_refresh_and_settings_acknowledgement(monkeypatch, invalid):
    """Acknowledge newly acquired native fallback while the observer cannot publish.

    Args:
        monkeypatch: Supply helper readback and isolated in-memory Apply state.
        invalid: Captured policy, native identity or helper evidence prerequisite to invalidate.
    """
    import json
    from datetime import datetime, timedelta, timezone
    from types import SimpleNamespace

    from atlaso.app import ui
    from atlaso.app.services import dynamic_management as admission
    row, observation = fixture_observation()
    mac = row["mac"]
    observation["observed_at"] = datetime.now(timezone.utc).isoformat()
    interface = SimpleNamespace(mac_address=mac, host_ip_cidr="192.0.2.10/24", host_ip_cidrs=["192.0.2.10/24"])
    observed = SimpleNamespace(name="eth0", mac_address=mac, host_dhcp_ip_cidr=None, host_ip_cidr=None, host_ip_cidrs=[])
    db = SimpleNamespace(scalar=lambda _statement: interface, flush=lambda: None)
    evidence = {"candidate_addresses": ["169.254.20.10"]}
    link = observation["links"][0]
    record = link["addresses"][0]
    if invalid in {"expired", "future"}:
        observation["observed_at"] = (datetime.now(timezone.utc) + timedelta(seconds=-121 if invalid == "expired" else 30)).isoformat()
    elif invalid == "captured-mac":
        row["mac"] = "02:00:00:00:10:78"
    elif invalid == "observed-mac":
        observed.mac_address = "02:00:00:00:10:78"
    elif invalid == "helper-mac":
        link["mac"] = "02:00:00:00:10:78"
    elif invalid == "interface":
        link["name"] = "eth1"
    elif invalid == "candidate":
        evidence["candidate_addresses"] = ["169.254.20.11"]
    elif invalid == "ambiguous":
        link["addresses"].append({**record, "address": "169.254.20.11", "cidr": "169.254.20.11/16"})
        evidence["candidate_addresses"].append("169.254.20.11")
    elif invalid == "disabled":
        row["ipv4_link_local_fallback_enabled"] = "false"
    elif invalid == "admin-down":
        row["admin_state"] = "down"
    elif invalid in {"mode", "role"}:
        row[invalid] = "unused" if invalid == "mode" else "access"
    elif invalid == "static":
        row["ip_cidr"] = "192.0.2.10/24"
    elif invalid == "unconfigured":
        link["configured"] = False
    elif invalid == "incomplete":
        observation["complete"] = False
    elif invalid in {"inventory", "no-carrier", "link-down", "ethernet"}:
        link[{"inventory": "address_inventory_complete", "no-carrier": "carrier", "link-down": "up", "ethernet": "ethernet"}[invalid]] = False
    elif invalid in {"tentative", "foreign", "scope", "cidr", "dhcp"}:
        key, value = {"tentative": ("state", "checking"), "foreign": ("source", "static"), "scope": ("scope", "global"),
                      "cidr": ("cidr", "169.254.20.10/24"), "dhcp": ("source", "DHCPv4")}[invalid]
        record[key] = value
    elif invalid == "duplicate":
        observation["links"].append({**deepcopy(link), "name": "eth1", "mac": "02:00:00:00:10:78"})
    elif invalid == "stale-generic":
        interface.host_ip_cidr = "169.254.20.10/16"
    if invalid not in {"missing-proof", "stale-generic"}:
        evidence["management_address_observation"] = observation
    # The observer is excluded while a protected handoff/Apply is active. A
    # stale prior publication cannot be a prerequisite or substitute for proof.
    monkeypatch.setattr(admission, "read_publication", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(ui, "acquire_network_objects_write_lock", lambda _db: None)
    monkeypatch.setattr(ui, "discover_host_physical_interfaces", lambda **_kwargs: [observed])
    preview = "[physical_interfaces]\ninterface=eth0\n" + "".join(f"{key}={value}\n" for key, value in row.items() if key != "name")
    captured = {"management_interface": "eth0", "management_ip": "", "management_ip_cidr": "",
                "web_terminal_enabled": True, "web_terminal_addresses": ["198.51.100.10"], "root_ssh_enabled": False}
    unit = ui.make_appliance_apply_unit(unit_id="appliance_settings", label="Appliance Settings", page_url="/settings",
        context={}, summary=[], validation_errors=[], config_path="/var/lib/atlaso/apply/settings.json",
        config_preview=json.dumps(captured), baseline=None)
    original = unit["snapshot_hash"]

    def acknowledge():
        """Follow the protected-handoff caller's exact completion sequence."""
        ui.refresh_management_handoff_dynamic_observations(db, preview, evidence)
        ui.baseline_management_handoff_dhcp_settings(db, unit, preview, evidence)

    if invalid != "none":
        with pytest.raises(RuntimeError, match="confirm|captured"):
            acknowledge()
        if invalid != "observed-mac":
            with pytest.raises(RuntimeError, match="confirm|captured"):
                ui.baseline_management_handoff_dhcp_settings(db, unit, preview, evidence)
        assert unit["snapshot_hash"] == original
        assert interface.host_ip_cidr == ("169.254.20.10/16" if invalid == "stale-generic" else "192.0.2.10/24")
        return
    acknowledge()
    resolved = json.loads(unit["raw_config_preview"])
    assert resolved["management_ip"] == "169.254.20.10"
    assert resolved["management_ip_cidr"] == "169.254.20.10/16"
    assert resolved["web_terminal_addresses"] == ["169.254.20.10", "198.51.100.10"]
    assert resolved["root_ssh_enabled"] is False
    assert unit["snapshot_hash"] != original
    assert interface.host_ip_cidr is None
    assert interface.host_ip_cidrs == []


@pytest.mark.parametrize("oversized", ["none", "links", "addresses"])
def test_handoff_native_readback_preserves_identity_and_refuses_truncation(oversized):
    """The bounded helper projection retains the exact fallback admission inputs.

    Args:
        oversized: Inventory bound to exceed, or a complete ordinary observation.
    """
    from tests.test_appliance_helper import load_helper_module

    helper = load_helper_module()
    row, observation = fixture_observation()
    if oversized == "links":
        observation["links"] *= 257
    elif oversized == "addresses":
        observation["links"][0]["addresses"] *= 33
    projected = helper._management_handoff_service_address_observation(observation)
    assert projected["complete"] is (oversized == "none")
    assert bool(native_management_addresses(row, projected)["apipa_addresses"]) is (oversized == "none")


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


@pytest.mark.parametrize("first_boot,renamed,warmup_carrier_loss,transition_intent", [
    (first, renamed, carrier, "prepared") for first in (False, True) for renamed in (False, True) for carrier in (False, True)
] + [(False, False, False, "planned"), (False, False, False, "unchanged")])
def test_tls_publication_and_later_lease_use_applied_identity(client, tmp_path, monkeypatch, first_boot, renamed, warmup_carrier_loss, transition_intent):
    """Publish real signed leaves across APIPA, DHCP and carrier loss with isolated host seams.

    Args:
        client: Isolated application/database fixture.
        tmp_path: Receipted task-owned native configuration fixtures.
        monkeypatch: Replace host operations while retaining real certificate issuance and database behavior.
        first_boot: Freeze published first-boot identity before an explicit Settings Apply exists.
        renamed: Preserve the original Settings name while reconciling the applied NIC through its MAC-bound alias.
        warmup_carrier_loss: Withdraw carrier while slow publication helpers initialize outside the writer transaction.
        transition_intent: Preserve an issued or unissued pending leaf, or advance only an unchanged applied leaf.
    """
    import hashlib
    import json
    import runpy
    import stat
    import subprocess
    from contextlib import contextmanager
    from datetime import datetime, timedelta, timezone
    from pathlib import Path
    from types import SimpleNamespace

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
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
    from atlaso.app.secrets import decrypt_secret
    from atlaso.app.services import dynamic_management as admission
    from atlaso.app.services.ca import (
        CA_CLIENT_PROFILE_NAME,
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
    current_name = "ens33" if renamed else "eth0"
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
        earlier_key = decrypt_secret(leaf.private_key_encrypted)
        settings = {"fqdn": "applied.atlaso.internal", "management_interface": "eth0", "management_ip": "",
                    "management_https_enabled": True, "management_https_cert_path": str(cert_path),
                    "management_https_key_path": str(key_path), "web_terminal_enabled": False, "web_terminal_addresses": []}
        baseline = {"network": {"config_preview": render_network_config(interfaces=[interface], vlans=[])},
                    "ca": {"config_preview": render_ca_apply_payload(ca, [leaf], include_private_keys=False, profiles=profiles),
                           "summary": []}}
        if not first_boot:
            baseline["appliance_settings"] = {"config_preview": json.dumps(settings)}
        else:
            leaf.common_name = "pending.atlaso.internal"
        if renamed:
            baseline["network"]["physical_interface_aliases"] = {"eth0": current_name}
            interface.name = current_name
            observation["links"][0]["name"] = current_name
        saved = db.scalar(select(Setting).where(Setting.key == BASELINES_KEY))
        if saved is None:
            db.add(Setting(key=BASELINES_KEY, value=json.dumps(baseline)))
        else:
            saved.value = json.dumps(baseline)
        db.commit()

    publications = []
    receipts = []
    startup_pending = [True]
    upstream_checks = []
    network_lock_held = [False]

    @contextmanager
    def network_transaction_lock():
        """Model native admission independently of the real SQLite writer."""
        assert not network_lock_held[0]
        network_lock_held[0] = True
        try:
            yield
        finally:
            network_lock_held[0] = False

    def upstream_readiness(**kwargs):
        """Let application startup and console audits write while waiting for HTTP.

        Args:
            **kwargs: Exact applied loopback upstream endpoint.
        """
        from atlaso.app.appliance_console import record_console_shell

        assert not network_lock_held[0], "upstream startup must be able to acquire native admission"
        record_console_shell("open")
        upstream_checks.append(kwargs)
        startup_pending[0] = False

    helper = {"_network_transaction_lock": network_transaction_lock, "_network_transaction_state": lambda: {},
              "MANAGEMENT_HANDOFF_STATE_PATH": tmp_path / "absent-state", "_console_bootstrap_is_idle": lambda: True,
              "_recover_management_front_door": lambda **_kwargs: 0, "_network_address_observation": lambda: observation,
              "NGINX_MANAGEMENT_SITE_PATH": site, "NGINX_PUBLIC_SERVICES_SITE_PATH": tmp_path / "absent-public-site",
              "_management_nginx_config": helper_module._management_nginx_config,
              "_management_handoff_upstream_readiness": upstream_readiness,
              "_ca_managed_path": lambda value, _label: type(cert_path)(value),
              "_run": lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0)}

    def publish_config(payload, **kwargs):
        """Capture exact scoped listener publication after its simulated readiness gate.

        Args:
            payload: Applied Settings identity, independent of pending desired state.
            **kwargs: Explicit verified HTTP/HTTPS listener scopes.
        """
        if startup_pending[0]:
            # The real web startup must finish its own database writes before
            # answering the helper's readiness probe. Model that dependency
            # with a second real SQLite connection, not a mocked writer lock.
            upstream_readiness()
        writer = kwargs.pop("material_writer", None)
        if writer is not None:
            writer()
        publications.append((dict(payload), kwargs))
        site.write_text(helper_module._management_nginx_config(payload, cert_path, key_path, **kwargs).rstrip() + "\n", newline="\n")
        return 0, None

    helper["_configure_atlaso_management_https"] = publish_config
    installs = []
    activation_failure = [False]
    service_active = [True]
    install_completed = []

    def install_site(path, text):
        """Model a written site even when activation fails, requiring a later retry.

        Args:
            path: Owned synthetic nginx site.
            text: Expected withdrawal configuration.
        """
        installs.append(text)
        path.write_text(text)
        if activation_failure[0]:
            return 1
        service_active[0] = True
        install_completed.append(datetime.now(timezone.utc))
        return 0

    helper["_install_nginx_site"] = install_site
    helper["_run"] = lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0 if service_active[0] else 1)
    ui_prepared = []

    def prepare_ui():
        """Require an independent SQLite writer to remain available during cold imports."""
        if not ui_prepared:
            with SessionLocal() as audit_db:
                publisher.acquire_network_objects_write_lock(audit_db)
                audit_db.commit()
            ui_prepared.append(True)
            if warmup_carrier_loss:
                observation["links"][0]["carrier"] = False

    def root_matches(_db):
        """Mirror the bootstrap's lazy import before its protected root comparison.

        Args:
            _db: Existing publication writer, which must not own the first import.
        """
        prepare_ui()
        return True

    bootstrap = {"_ui_functions": prepare_ui, "recovery_root_matches_baseline": root_matches,
                 "MARKER_PATH": tmp_path / "first-boot-complete", "COMPLETION_MARKER_TEXT": "complete",
                 "read_regular_text": lambda *_args, **_kwargs: "complete",
                 "write_secret_text_atomic": lambda path, text: path.write_text(text),
                 "write_text_atomic": lambda path, text, **_kwargs: path.write_text(text),
                 "record_ca_publication_baseline": runpy.run_path("scripts/appliance/atlaso-bootstrap-https")["record_ca_publication_baseline"]}
    publication_path = tmp_path / "publication.json"
    original_lstat, original_fstat = Path.lstat, admission.os.fstat
    monkeypatch.setattr(admission, "PUBLICATION_PATH", publication_path)
    monkeypatch.setattr(Path, "lstat", lambda path: SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
                        if path == tmp_path else original_lstat(path))

    def published_metadata(descriptor):
        """Model only the owned publication's Linux root metadata on Windows.

        Args:
            descriptor: Actual open file descriptor, retaining native identity checks.
        """
        metadata = original_fstat(descriptor)
        if publication_path.exists():
            current = publication_path.stat()
            if (metadata.st_dev, metadata.st_ino) == (current.st_dev, current.st_ino):
                return SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_size=current.st_size, st_nlink=1)
        return metadata

    def retain_publication(value):
        """Exercise the real receipt reader against an isolated public JSON file.

        Args:
            value: Public applied checkpoint to retain for observation and readback.
        """
        receipts.append(deepcopy(value))
        publication_path.write_text(json.dumps(value))

    monkeypatch.setattr(admission.os, "fstat", published_metadata)
    monkeypatch.setattr(publisher, "write_publication", retain_publication)
    monkeypatch.setattr(publisher.ssl, "get_server_certificate", lambda *_args, **_kwargs: x509.load_pem_x509_certificate(
        cert_path.read_bytes()).public_bytes(serialization.Encoding.PEM).decode())
    publisher.reconcile(helper, bootstrap)
    assert ui_prepared == [True]
    assert upstream_checks == [{"upstream_host": "127.0.0.1", "upstream_port": 8000}]
    if warmup_carrier_loss:
        assert publications == []
        assert receipts[-1]["phase"] == "withdrawn"
        count = len(installs)
        publisher.reconcile(helper, bootstrap)
        assert len(installs) == count
        return
    assert receipts[-1]["apipa_addresses"] == ["169.254.20.10"]
    assert publications[-1][0]["fqdn"] == "applied.atlaso.internal"
    assert publications[-1][0]["management_interface"] == current_name
    first = x509.load_pem_x509_certificate(cert_path.read_bytes())
    assert str(first.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.IPAddress)[0]) == "169.254.20.10"
    checks_before_fast_path = len(upstream_checks)
    publisher.reconcile(helper, bootstrap)
    assert len(upstream_checks) == checks_before_fast_path

    # A normal UI review can issue a pending leaf for the future static
    # addresses while this applied IPv4LL listener remains unchanged. Refreshing
    # its publication must neither overwrite that desired leaf nor deploy it.
    with SessionLocal() as db:
        leaf = db.scalar(select(CaCertificate).where(CaCertificate.managed_owner == "appliance:https"))
        original_leaf = {column.key: getattr(leaf, column.key) for column in CaCertificate.__table__.columns}
        ca = db.scalar(select(CaSettings))
        profiles = list(db.scalars(select(CaProfile)))
        pending = ManagedCertificateSpec(
            "appliance:https", "pending.atlaso.internal", ["pending.atlaso.internal"],
            ["169.254.20.10", "192.0.2.20", "fd00:1084:1077::20"],
            CA_SERVER_PROFILE_NAME, leaf.description, str(tmp_path / "pending.pem"), str(tmp_path / "pending.key"), leaf.chain_path,
        )
        ensure_managed_certificate_rows(db, settings=ca, profiles=profiles, specs=[pending])
        assert issue_certificate(ca, profiles, leaf)
        db.commit()
        pending_fingerprint = leaf.fingerprint
        pending_certificate_pem = leaf.certificate_pem
        pending_addresses = leaf.ip_addresses
        pending_key_digest = hashlib.sha256(leaf.private_key_encrypted.encode()).hexdigest()
    installed_before = [hashlib.sha256(path.read_bytes()).hexdigest() for path in (cert_path, key_path)]
    publications_before = len(publications)
    publisher.reconcile(helper, bootstrap)
    with SessionLocal() as db:
        leaf = db.scalar(select(CaCertificate).where(CaCertificate.managed_owner == "appliance:https"))
        assert leaf.fingerprint == pending_fingerprint
        assert leaf.ip_addresses == pending_addresses
        assert hashlib.sha256(leaf.private_key_encrypted.encode()).hexdigest() == pending_key_digest
    assert len(publications) == publications_before
    assert len(upstream_checks) == checks_before_fast_path
    assert [hashlib.sha256(path.read_bytes()).hexdigest() for path in (cert_path, key_path)] == installed_before
    assert receipts[-1]["leaf_fingerprint"] == first.fingerprint(hashes.SHA256()).hex()

    # Unrelated Apply can exclude the observer longer than the public receipt's
    # TTL. Expiry must withdraw public admission without authorizing replacement
    # of an independently unchanged installed pair or the pending desired leaf.
    expired = json.loads(publication_path.read_text())
    expired["observed_at"] = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    publication_path.write_text(json.dumps(expired))
    with SessionLocal() as db:
        assert admission.read_publication(db) == {}
    publisher.reconcile(helper, bootstrap)
    with SessionLocal() as db:
        leaf = db.scalar(select(CaCertificate).where(CaCertificate.managed_owner == "appliance:https"))
        assert leaf.fingerprint == pending_fingerprint
        assert leaf.ip_addresses == pending_addresses
        assert hashlib.sha256(leaf.private_key_encrypted.encode()).hexdigest() == pending_key_digest
        assert admission.read_publication(db)["leaf_fingerprint"] == first.fingerprint(hashes.SHA256()).hex()
    assert len(publications) == publications_before
    assert len(upstream_checks) == checks_before_fast_path
    assert [hashlib.sha256(path.read_bytes()).hexdigest() for path in (cert_path, key_path)] == installed_before
    # Reboot removes /run, but the actual acknowledged CA baseline, installed
    # pair and applied native listener survive. Reconstruct only after proving
    # those independently; never use the pending desired leaf as applied proof.
    publication_path.unlink()
    with SessionLocal() as db:
        assert admission.read_publication(db) == {}
    publisher.reconcile(helper, bootstrap)
    with SessionLocal() as db:
        leaf = db.scalar(select(CaCertificate).where(CaCertificate.managed_owner == "appliance:https"))
        assert leaf.common_name == "pending.atlaso.internal"
        assert leaf.cert_path == str(tmp_path / "pending.pem")
        assert leaf.key_path == str(tmp_path / "pending.key")
        assert leaf.fingerprint == pending_fingerprint
        assert leaf.ip_addresses == pending_addresses
        assert hashlib.sha256(leaf.private_key_encrypted.encode()).hexdigest() == pending_key_digest
        assert admission.read_publication(db)["leaf_fingerprint"] == first.fingerprint(hashes.SHA256()).hex()
    assert len(publications) == publications_before
    assert len(upstream_checks) == checks_before_fast_path
    assert [hashlib.sha256(path.read_bytes()).hexdigest() for path in (cert_path, key_path)] == installed_before
    if not first_boot and not renamed:
        # Missing checkpoints cannot promote a mismatched baseline, a drifted
        # site or an inactive/different served leaf. Refuse normal repair here
        # through its existing pending-root guard, proving recovery cannot skip it.
        with SessionLocal() as db:
            baseline_text = db.scalar(select(Setting).where(Setting.key == BASELINES_KEY)).value
        site_bytes = site.read_bytes()
        for mismatch in ("fingerprint", "hostname", "cert_path", "key_path", "duplicate", "missing", "site", "inactive", "served"):
            publication_path.unlink(missing_ok=True)
            mismatched = json.loads(baseline_text)
            ca_payload = json.loads(mismatched["ca"]["config_preview"])
            applied_leaf = next(item for item in ca_payload["certificates"] if item["managed_owner"] == "appliance:https")
            if mismatch in {"fingerprint", "hostname", "cert_path", "key_path"}:
                applied_leaf["common_name" if mismatch == "hostname" else mismatch] = "mismatched"
            elif mismatch == "duplicate":
                ca_payload["certificates"].append(dict(applied_leaf))
            elif mismatch == "missing":
                ca_payload["certificates"] = []
            mismatched["ca"]["config_preview"] = json.dumps(ca_payload)
            with SessionLocal() as db:
                db.scalar(select(Setting).where(Setting.key == BASELINES_KEY)).value = json.dumps(mismatched)
                db.commit()
            if mismatch == "site":
                site.write_text("drifted site")
            with monkeypatch.context() as guards:
                guards.setitem(bootstrap, "recovery_root_matches_baseline", lambda _db: False)
                if mismatch == "inactive":
                    guards.setitem(helper, "_run", lambda *_args, **_kwargs: subprocess.CompletedProcess([], 1))
                elif mismatch == "served":
                    guards.setattr(publisher.ssl, "get_server_certificate", lambda *_args, **_kwargs: pending_certificate_pem)
                with pytest.raises(ValueError, match="pending CA root|active management TLS identity"):
                    publisher.reconcile(helper, bootstrap)
            with SessionLocal() as db:
                assert admission.read_publication(db) == {}
                leaf = db.scalar(select(CaCertificate).where(CaCertificate.managed_owner == "appliance:https"))
                assert leaf.common_name == "pending.atlaso.internal"
                assert leaf.fingerprint == pending_fingerprint
                assert hashlib.sha256(leaf.private_key_encrypted.encode()).hexdigest() == pending_key_digest
                db.scalar(select(Setting).where(Setting.key == BASELINES_KEY)).value = baseline_text
                db.commit()
            site.write_bytes(site_bytes)
        # Successful recovery must not import cold UI helpers under either lock.
        with monkeypatch.context() as guards:
            def refuse_cold_import():
                """Fail if unchanged recovery attempts a slow locked import."""
                raise AssertionError("unchanged reboot recovery imported UI")

            guards.setitem(bootstrap, "_ui_functions", refuse_cold_import)
            guards.setitem(bootstrap, "recovery_root_matches_baseline", lambda _db: refuse_cold_import())
            publisher.reconcile(helper, bootstrap)
        assert len(publications) == publications_before
        assert [hashlib.sha256(path.read_bytes()).hexdigest() for path in (cert_path, key_path)] == installed_before
    with SessionLocal() as db:
        leaf = db.scalar(select(CaCertificate).where(CaCertificate.managed_owner == "appliance:https"))
        publication_path.unlink()
        leaf.status = "revoked"
        db.commit()
    with pytest.raises(ValueError, match="unavailable or revoked"):
        publisher.reconcile(helper, bootstrap)
    assert len(publications) == publications_before
    assert [hashlib.sha256(path.read_bytes()).hexdigest() for path in (cert_path, key_path)] == installed_before
    with SessionLocal() as db:
        leaf = db.scalar(select(CaCertificate).where(CaCertificate.managed_owner == "appliance:https"))
        # Restore only this synthetic desired row so the separate key-repair,
        # lease-change and carrier-loss cases below retain their original setup.
        for key, value in original_leaf.items():
            setattr(leaf, key, value)
        db.commit()
    key_path.write_text(earlier_key)
    before_repair = len(publications)
    publisher.reconcile(helper, bootstrap)
    assert len(publications) == before_repair + 1
    assert publisher.published_pair_matches(receipts[-1]["leaf_fingerprint"], {"169.254.20.10"},
                                            "applied.atlaso.internal", cert_path, key_path)
    observation["links"][0]["addresses"] = [{"address": "192.168.50.10", "cidr": "192.168.50.10/24",
                                                 "scope": "global", "source": "DHCPv4", "state": "assigned"}]
    # A retained checkpoint cannot protect pending intent when the native
    # address changes. Keep the complete desired row across failure, successful
    # lease publication and the later retirement of the old listener's SAN.
    with SessionLocal() as db:
        leaf = db.scalar(select(CaCertificate).where(CaCertificate.managed_owner == "appliance:https"))
        ca = db.scalar(select(CaSettings))
        profiles = list(db.scalars(select(CaProfile)))
        if transition_intent == "prepared":
            pending = ManagedCertificateSpec(
                pending.owner, pending.common_name, pending.dns_names, pending.ip_addresses,
                CA_CLIENT_PROFILE_NAME, pending.description, pending.cert_path, pending.key_path, pending.chain_path,
            )
            ensure_managed_certificate_rows(db, settings=ca, profiles=profiles, specs=[pending])
            assert issue_certificate(ca, profiles, leaf)
        elif transition_intent == "planned":
            # Public issued material can still match the applied baseline while
            # unissued SAN intent is pending in the same row.
            leaf.ip_addresses += "\n192.0.2.99"
            leaf.status = "planned"
        db.commit()
        db.refresh(leaf)
        pending_transition = {column.key: getattr(leaf, column.key) for column in CaCertificate.__table__.columns}

    def assert_pending_transition():
        """Read the complete persisted pending intent independently after each observer transaction."""
        with SessionLocal() as check_db:
            desired = check_db.scalar(select(CaCertificate).where(CaCertificate.managed_owner == "appliance:https"))
            for field, expected in pending_transition.items():
                actual = getattr(desired, field)
                if field == "private_key_encrypted":
                    assert hashlib.sha256(actual.encode()).hexdigest() == hashlib.sha256(expected.encode()).hexdigest()
                else:
                    assert actual == expected, field

    def assert_verified_transition():
        """Advance ordinary desired material only after proven publication, retaining prepared intent."""
        if transition_intent == "unchanged" and not first_boot:
            with SessionLocal() as check_db:
                desired = check_db.scalar(select(CaCertificate).where(CaCertificate.managed_owner == "appliance:https"))
                assert desired.fingerprint == receipts[-1]["leaf_fingerprint"]
                assert publisher.installed_pair_matches(desired, cert_path, key_path)
        else:
            assert_pending_transition()

    bootstrap["recovery_root_matches_baseline"] = lambda _db: False
    with pytest.raises(ValueError, match="pending CA root"):
        publisher.reconcile(helper, bootstrap)
    assert_pending_transition()
    assert receipts[-1]["addresses"] == ["169.254.20.10"]
    bootstrap["recovery_root_matches_baseline"] = lambda _db: True
    helper["_configure_atlaso_management_https"] = lambda *_args, **_kwargs: (1, None)
    with pytest.raises(ValueError, match="failed readiness"):
        publisher.reconcile(helper, bootstrap)
    assert_pending_transition()
    assert receipts[-1]["addresses"] == ["169.254.20.10"]
    helper["_configure_atlaso_management_https"] = publish_config
    publisher.reconcile(helper, bootstrap)
    assert_verified_transition()
    assert receipts[-1]["addresses"] == ["192.168.50.10"]
    assert receipts[-1]["apipa_addresses"] == []
    assert "169.254.20.10" not in site.read_text()
    publisher.reconcile(helper, bootstrap)
    assert_verified_transition()
    published_leaf = x509.load_pem_x509_certificate(cert_path.read_bytes())
    assert {str(value) for value in published_leaf.extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value.get_values_for_type(x509.IPAddress)} == {"192.168.50.10"}
    with SessionLocal() as db:
        applied_ca = json.loads(admission.applied_snapshots(db)["ca"]["config_preview"])
        assert next(item for item in applied_ca["certificates"] if item["managed_owner"] == "appliance:https")["fingerprint"] == receipts[-1]["leaf_fingerprint"]
    with SessionLocal() as db:
        assert db.scalar(select(CaSettings)).root_fingerprint == root_fingerprint
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == current_name))
        assert interface.host_ip_cidr == "192.168.50.10/24"
        assert interface.ip_cidr is None
    observation["links"][0]["carrier"] = False
    publisher.reconcile(helper, bootstrap)
    assert receipts[-1]["phase"] == "withdrawn"
    assert "192.168.50.10" not in site.read_text()
    assert datetime.fromisoformat(receipts[-1]["observed_at"]) >= install_completed[-1]
    count = len(installs)
    for _ in range(3):
        publisher.reconcile(helper, bootstrap)
    assert len(installs) == count
    site.write_text("drifted site")
    publisher.reconcile(helper, bootstrap)
    assert len(installs) == count + 1
    service_active[0] = False
    publisher.reconcile(helper, bootstrap)
    assert len(installs) == count + 2
    site.write_text("another drift")
    activation_failure[0] = True
    with pytest.raises(ValueError, match="could not be withdrawn"):
        publisher.reconcile(helper, bootstrap)
    assert "site_digest" not in receipts[-1]
    activation_failure[0] = False
    publisher.reconcile(helper, bootstrap)
    assert len(installs) == count + 4
    publisher.reconcile(helper, bootstrap)
    assert len(installs) == count + 4
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == current_name))
        assert interface.host_ip_cidr is None
        assert interface.host_ip_cidrs == []


@pytest.mark.parametrize("change", ["ready", "unavailable", "upstream", "https", "apply", "carrier"])
def test_http_publication_readmits_after_unlocked_upstream_wait(client, tmp_path, monkeypatch, change):
    """Allow real startup/audit writes while retaining fresh atomic activation admission.

    Args:
        client: Initialized isolated SQLite application.
        tmp_path: Owned synthetic native files.
        monkeypatch: Replace native effects, retaining real database transactions.
        change: Readiness failure or concurrent applied/native change during the unlocked wait.
    """
    import json
    from contextlib import contextmanager

    from sqlalchemy import select
    from sqlalchemy.exc import OperationalError

    from atlaso import dynamic_management as publisher
    from atlaso.app.appliance_console import record_console_shell
    from atlaso.app.database import SessionLocal, engine
    from atlaso.app.models import Job, PhysicalInterface, Setting
    from atlaso.app.services.dynamic_management import BASELINES_KEY
    from atlaso.app.services.networking import render_network_config

    row, observation = fixture_observation()
    settings = {"fqdn": "applied.atlaso.internal", "management_interface": "eth0",
                "management_https_enabled": False, "management_http_port": 8099}
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        interface.mac_address = row["mac"]
        interface.role, interface.mode, interface.admin_state = "management", "access", "up"
        interface.ipv4_method, interface.ip_cidr, interface.ipv6_enabled = "dhcp", None, False
        baselines = {"network": {"config_preview": render_network_config(interfaces=[interface], vlans=[])},
                     "appliance_settings": {"config_preview": json.dumps(settings)}}
        saved = db.scalar(select(Setting).where(Setting.key == BASELINES_KEY))
        if saved is None:
            db.add(Setting(key=BASELINES_KEY, value=json.dumps(baselines)))
        else:
            saved.value = json.dumps(baselines)
        db.commit()

    network_locked = [False]
    activated = []
    publications = []
    site = tmp_path / "management.conf"

    @contextmanager
    def native_lock():
        """Track exclusive native admission separately from SQLite admission."""
        assert not network_locked[0]
        network_locked[0] = True
        try:
            yield
        finally:
            network_locked[0] = False

    def wait_upstream(**kwargs):
        """Model web startup requiring both native admission and an audit transaction.

        Args:
            **kwargs: Endpoint from applied Settings, including the legacy backend port field.
        """
        assert kwargs == {"upstream_host": "127.0.0.1", "upstream_port": 8099}
        with native_lock():
            record_console_shell("open")
        if change == "unavailable":
            raise ValueError("upstream unavailable")
        if change == "carrier":
            observation["links"][0]["carrier"] = False
        if change in {"upstream", "https", "apply"}:
            with SessionLocal() as db:
                if change == "apply":
                    db.add(Job(id="concurrent-apply", type="appliance-apply", created_by="test"))
                else:
                    settings.update({"management_http_port": 8100} if change == "upstream" else {"management_https_enabled": True})
                    baselines["appliance_settings"]["config_preview"] = json.dumps(settings)
                    db.scalar(select(Setting).where(Setting.key == BASELINES_KEY)).value = json.dumps(baselines)
                db.commit()

    def activate(payload, **_kwargs):
        """Require both writer and native admission through the actual activation.

        Args:
            payload: Fresh applied Settings selected after the unlocked wait.
            **_kwargs: Verified native listener scopes.
        """
        assert network_locked[0]
        with engine.connect() as other:
            other.exec_driver_sql("PRAGMA busy_timeout=0")
            with pytest.raises(OperationalError, match="locked"):
                other.exec_driver_sql("UPDATE settings SET value=value WHERE 0")
        activated.append(payload)
        site.write_text("owned listener")
        return 0, None

    helper = {"_network_transaction_lock": native_lock, "_network_transaction_state": lambda: {},
              "MANAGEMENT_HANDOFF_STATE_PATH": tmp_path / "absent-handoff", "_console_bootstrap_is_idle": lambda: True,
              "_recover_management_front_door": lambda **_kwargs: 0, "_network_address_observation": lambda: observation,
              "NGINX_PUBLIC_SERVICES_SITE_PATH": tmp_path / "absent-public-site", "NGINX_MANAGEMENT_SITE_PATH": site,
              "_management_handoff_upstream_readiness": wait_upstream, "_configure_atlaso_management_https": activate,
              "_management_nginx_config": lambda *_args, **_kwargs: "withdrawn listener",
              "_install_nginx_site": lambda path, value: (path.write_text(value), 0)[1]}
    monkeypatch.setattr(publisher, "read_observer_checkpoint", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(publisher, "write_publication", lambda value: publications.append(value))
    if change in {"unavailable", "upstream", "https"}:
        with pytest.raises(ValueError, match="unavailable|changed during publication preparation"):
            publisher.reconcile(helper, {})
    else:
        publisher.reconcile(helper, {})
    assert len(activated) == (1 if change == "ready" else 0)
    if change == "ready":
        assert publications[-1]["phase"] == "ready"
    elif change == "carrier":
        assert publications[-1]["phase"] == "withdrawn"
    else:
        assert publications == []
        assert not site.exists()
    # A failed or deferred preflight must release every transaction as well.
    record_console_shell("close")


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

    from atlaso.app import ui
    from atlaso.app.database import SessionLocal
    from atlaso.app.models import PhysicalInterface
    from atlaso.app.services import dynamic_management as admission

    path = tmp_path / "publication.json"
    with SessionLocal() as db:
        identity = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        identity.ipv4_method, identity.ip_cidr, identity.host_ip_cidr = "dhcp", None, None
        identity.host_ip_cidrs = []
        identity.ipv6_enabled = False
        db.commit()
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
        assert bool(admission.read_observer_checkpoint(db)) == (change in {"none", "expired"})
        context = ui.appliance_settings_context(db, reconcile_dns=False)
        settings_payload = json.loads(context["appliance_settings_config_preview"])
        assert settings_payload["management_ip"] == ("169.254.20.10" if change == "none" else "")
        setup_terminal = [option for option in context["web_terminal_interface_options"] if option["name"] == identity.name]
        assert bool(setup_terminal) == (change == "none")
        if setup_terminal:
            assert setup_terminal[0]["addresses"] == ["169.254.20.10"]
        ordinary, _dns = ui.management_dhcp_dns_context([identity], [])
        assert not ordinary.get("ip")
        assert identity.host_ip_cidr is None
        assert identity.host_ip_cidrs == []


@pytest.mark.parametrize("change", ["none", "expired", "future", "network", "settings", "identity", "nonempty", "phase", "apipa-only", "ready-empty"])
def test_withdrawal_checkpoint_is_private_fresh_and_bound(client, tmp_path, monkeypatch, change):
    """Addressless observer checkpoints never become publicly usable management bindings.

    Args:
        client: Isolated appliance database.
        tmp_path: Owned synthetic publication path.
        monkeypatch: Model root-owned Linux metadata on the test platform.
        change: Freshness, applied identity or withdrawal shape to invalidate.
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

    path = tmp_path / "withdrawn.json"
    with SessionLocal() as db:
        identity = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth0"))
        value = {"phase": "withdrawn", "observed_at": datetime.now(timezone.utc).isoformat(),
                 "interface": identity.name, "mac": identity.mac_address, "addresses": [], "apipa_addresses": [],
                 "network_digest": admission.snapshot_digest(admission.applied_snapshots(db).get("network")),
                 "settings_digest": admission.snapshot_digest(admission.applied_snapshots(db).get("appliance_settings"))}
        if change in {"expired", "future"}:
            value["observed_at"] = (datetime.now(timezone.utc) + timedelta(seconds=-30 if change == "expired" else 30)).isoformat()
        elif change in {"network", "settings"}:
            value[change + "_digest"] = "superseded"
        elif change == "identity":
            value["mac"] = "02:00:00:00:10:78"
        elif change == "nonempty":
            value["addresses"] = ["169.254.20.10"]
        elif change == "phase":
            value["phase"] = "pending"
        elif change == "apipa-only":
            value["apipa_addresses"] = ["169.254.20.10"]
        elif change == "ready-empty":
            value["phase"] = "ready"
        path.write_text(json.dumps(value))
        original_lstat = Path.lstat
        monkeypatch.setattr(Path, "lstat", lambda item: SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
                            if item == tmp_path else original_lstat(item))
        monkeypatch.setattr(admission, "PUBLICATION_PATH", path)
        monkeypatch.setattr(admission.os, "fstat", lambda _fd: SimpleNamespace(
            st_mode=stat.S_IFREG | 0o644, st_uid=0, st_size=path.stat().st_size, st_nlink=1))
        assert admission.read_publication(db) == {}
        assert admission.publication_bindings(db) == []
        assert bool(admission.read_publication(db, include_withdrawn=True)) == (change == "none")
        assert bool(admission.read_observer_checkpoint(db, include_withdrawn=True)) == (change in {"none", "expired"})


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
