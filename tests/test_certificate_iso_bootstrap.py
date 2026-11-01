from __future__ import annotations

import hashlib
import json
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/interop"))
import certificate_iso_bootstrap as bootstrap  # noqa: E402 - Reviewed interop entrypoint.


@pytest.mark.parametrize("review,reason", [
    ({"active_task": {"id": "running"}}, "already_active"),
    ({"units": [{"id": "ldap", "changed": True}]}, "unrelated_pending"),
])
def test_bootstrap_refuses_active_apply_or_unrelated_pending_changes(review, reason):
    client = SimpleNamespace(json=lambda _path: (200, review))
    with pytest.raises(bootstrap.Refusal, match=reason):
        bootstrap.initial_review(client)


def test_sudo_read_confines_password_to_stdin_and_discards_errors():
    import io

    calls = {}

    class Channel:
        def settimeout(self, _value):
            pass

        def exec_command(self, value):
            calls["command"] = value

        def sendall(self, value):
            calls["stdin"] = value

        def shutdown_write(self):
            pass

        def makefile(self, _mode):
            return io.BytesIO(b'{"state":"proven-absent"}')

        def makefile_stderr(self, _mode):
            return io.BytesIO(b"sensitive diagnostic")

        def recv_exit_status(self):
            return 1

        def close(self):
            calls["closed"] = True

    channel = Channel()
    session = SimpleNamespace(transport=SimpleNamespace(open_session=lambda **_kw: channel))
    password = "synthetic-concealed-value"
    with pytest.raises(bootstrap.Refusal, match="^bootstrap_guest_readback_failed$"):
        bootstrap.sudo_read(session, "python3 -c public_probe", password)
    assert password not in calls["command"]
    assert calls["stdin"] == (password + "\n").encode()
    assert calls["closed"] is True


def test_unknown_bootstrap_apply_retains_original_and_forbids_automatic_retry(tmp_path, monkeypatch):
    ca = b"-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n"
    plan = {
        "trust_model": "trusted-host", "interface": "eth0", "current_address": "192.0.2.10",
        "baseline_address": "192.0.2.30", "task_id": "task", "source_commit": "a" * 40,
        "deployed_commit": "b" * 40, "pr": 1085, "vmx_path": "owned.vmx", "mac": "00:50:56:aa:bb:cc",
        "appliance_user": "admin", "appliance_ssh_host_key": "public-pin", "ca_path": "public-ca.pem",
        "ca_sha256": hashlib.sha256(ca).hexdigest(), "appliance_ownership": {"sha256": "c" * 64},
        "peer_fixture": {"sha256": "d" * 64}, "peer_identity": {"sha256": "e" * 64},
        "peer_transport": {"host": "192.0.2.1", "user": "alpine", "ssh_public_key": "public-key",
                           "ssh_host_key": "public-pin", "private_subnet": "192.0.2.0/24"},
    }
    monkeypatch.setattr(bootstrap, "admit_output", lambda *args: None)
    monkeypatch.setattr(bootstrap, "admit_fixture", lambda _plan: {
        "lease_address": "192.0.2.10", "appliance_vmx": "owned.vmx", "appliance_mac": plan["mac"], "peer_cidr": "192.0.2.1/24"})
    monkeypatch.setattr(bootstrap, "bound_json", lambda _ref: {"phase": "original-installation-vm-created", "source_commit": "a" * 40})
    monkeypatch.setattr(bootstrap, "inspect_trusted_host", lambda _plan: {})

    @contextmanager
    def monitor(*args):
        yield SimpleNamespace(check=lambda: None)

    class Session:
        def __init__(self, *args):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def command(self, _command):
            return ca

    fields = {name: "" for name in bootstrap.saved_fields.__globals__["FIELDS"]}
    fields.update(role="management", ipv4_method="dhcp", ipv6_enabled=False)

    class Client:
        def __init__(self, *args, **kwargs):
            pass

        def login(self, *args):
            pass

        def json(self, _path):
            return 200, {"units": []}

        def interface(self, _name):
            return dict(fields, mac_address=plan["mac"]), "public-csrf-placeholder"

        def tls_identity(self):
            return {"sha256": "f" * 64, "ip_sans": [plan["current_address"]]}

    monkeypatch.setattr(bootstrap, "watched_topology", monitor)
    monkeypatch.setattr(bootstrap, "PinnedPeerTransport", Session)
    monkeypatch.setattr(bootstrap, "PinnedApplianceSession", Session)
    monkeypatch.setattr(bootstrap, "verify_peer_isolation", lambda _peer: {})
    monkeypatch.setattr(bootstrap, "guest_identity", lambda *args: {
        "app_service": {}, "route_snapshot": {}, "helper_sha256": "a" * 64, "wheel_sha256": "b" * 64})
    monkeypatch.setattr(bootstrap, "tls_name", lambda *args: plan["current_address"])
    monkeypatch.setattr(bootstrap, "Client", Client)
    monkeypatch.setattr(bootstrap, "dns_baseline", lambda _client: {})
    calls = []
    monkeypatch.setattr(bootstrap, "edit", lambda *args: calls.append("edit"))

    def submit(_client):
        calls.append("submit")
        raise OSError("connection lost after possible submission")

    monkeypatch.setattr(bootstrap, "submit", submit)
    secret = "synthetic-concealed-value"
    inspected = bootstrap.setup(plan, tmp_path, secret, execute=False)
    assert inspected["stage"] == "inspected_no_mutation"
    assert calls == []
    assert (tmp_path / "inspection-result.json").is_file()
    assert not (tmp_path / "source.json").exists()
    assert not (tmp_path / "original-state.json").exists()
    with pytest.raises(OSError):
        bootstrap.setup(plan, tmp_path, secret, execute=True)
    assert calls == ["edit", "submit"]
    assert (tmp_path / "original-state.json").is_file()
    result = json.loads((tmp_path / "bootstrap-result.json").read_text())
    assert result["success"] is False
    assert result["recovery"] == "preserve_unknown_apply_do_not_resubmit"
    assert not (tmp_path / "rewired-runtime.json").exists()
    assert all(secret not in path.read_text() for path in tmp_path.glob("*.json"))
