from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import sysconfig
import threading
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/interop"))
import certificate_iso_bootstrap as bootstrap  # noqa: E402 - Reviewed interop entrypoint.


def test_guest_python_transport_preserves_multiline_docstrings_and_quotes(tmp_path):
    """Run the exact encoded command argument through a native Python process.

    Args:
        tmp_path: Unrelated directory used as the subprocess working directory.
    """
    program = ('"""A multiline probe.\nSQL uses both \'single\' and "double" quotes.\n"""\n'
               'import json\nprint(json.dumps({"query": "type = \'table\'", "line": "a\\nb"}))\n')
    command = bootstrap.guest_python_command(program)
    assert command.isascii() and "\n" not in command and "\r" not in command
    arguments = shlex.split(command)
    assert arguments[:4] == ["/opt/atlaso/.venv/bin/python", "-B", "-I", "-c"]
    result = subprocess.run([sys.executable, *arguments[1:]], cwd=tmp_path,
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"query": "type = 'table'", "line": "a\nb"}


@pytest.mark.parametrize("late_stop_failure", [False, True])
def test_bootstrap_monitor_propagates_sticky_failure_on_context_exit(monkeypatch, late_stop_failure):
    """Reject sampled drift and failed watcher joins after the final synchronous check.

    Args:
        monkeypatch: Replace only the native background observer.
        late_stop_failure: Whether failure appears during shutdown instead of sampling.
    """
    failed = threading.Event()
    def stop():
        """Model the sticky marker set by an unjoined watcher."""
        if late_stop_failure:
            failed.set()
    monitor = SimpleNamespace(start=lambda: None, stop=stop, failed=failed)
    monkeypatch.setattr(bootstrap, "TrustedHostMonitor", lambda *args: monitor)
    with pytest.raises(bootstrap.Refusal, match="bootstrap_topology_observation_failed"):
        with bootstrap.watched_topology({}, {}):
            if not late_stop_failure:
                failed.set()


def test_bootstrap_imports_through_the_actual_isolated_wrapper_launcher(tmp_path: Path) -> None:
    """Exercise the wrapper's real runpy bootstrap without pytest's import path.

    Args:
        tmp_path: Unrelated working directory containing a hostile sibling name.
    """
    root = Path(__file__).resolve().parents[1]
    wrapper = (root / "scripts/windows/vmware/Atlaso.SourceSnapshot.psm1").read_text()
    function = wrapper.split("function New-AtlasoCertificatePythonArguments {", 1)[1]
    matches = re.findall(r"^\s*\$bootstrap = '([^'\r\n]+)'\s*$", function, re.MULTILINE)
    assert len(matches) == 1
    assert "return @('-I', '-S', '-B', '-c', $bootstrap, $sitePackages, $ScriptPath)" in function
    (tmp_path / "certificate_handoff_native.py").write_text("raise AssertionError('untrusted cwd import')\n")
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("ATLASO_NATIVE_") and key not in {"PYTHONPATH", "PYTHONHOME"}}
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-B", "-c", matches[0], sysconfig.get_path("purelib"),
         str(root / "scripts/interop/certificate_iso_bootstrap.py"), "--help"],
        cwd=tmp_path, env=environment, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "--preflight-only" in result.stdout
    assert "--execute" in result.stdout


@pytest.mark.parametrize("review,reason", [
    ({"active_task": {"id": "running"}}, "already_active"),
    ({"units": [{"id": "ldap", "changed": True}]}, "unrelated_pending"),
])
def test_bootstrap_refuses_active_apply_or_unrelated_pending_changes(review, reason):
    """Reject an active Apply or pending changes outside the bootstrap plan.

    Args:
        review: Synthetic management review payload to admit or reject.
        reason: Expected refusal marker for that payload.
    """
    client = SimpleNamespace(json=lambda _path: (200, review))
    with pytest.raises(bootstrap.Refusal, match=reason):
        bootstrap.initial_review(client)


def test_sudo_read_confines_password_to_stdin_and_discards_errors():
    import io

    calls = {}

    class Channel:
        def settimeout(self, _value):
            """Accept the requested timeout for the fake SSH channel.

            Args:
                _value: Timeout value requested by the bootstrap reader.
            """
            pass

        def exec_command(self, value):
            """Capture the guest command issued to the channel.

            Args:
                value: Command string to execute through sudo.
            """
            calls["command"] = value

        def sendall(self, value):
            """Capture bytes sent to the channel's standard input.

            Args:
                value: Standard-input bytes sent by the caller.
            """
            calls["stdin"] = value

        def shutdown_write(self):
            pass

        def makefile(self, _mode):
            """Return fixed public probe output.

            Args:
                _mode: Stream mode requested by the SSH client.
            """
            return io.BytesIO(b'{"state":"proven-absent"}')

        def makefile_stderr(self, _mode):
            """Return synthetic stderr to verify it is discarded.

            Args:
                _mode: Stream mode requested for stderr.
            """
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
    """Keep the original state and refuse retry after an Apply outcome is unknown.

    Args:
        tmp_path: Isolated directory for generated evidence records.
        monkeypatch: Replacements for guest, transport, and management operations.
    """
    ca = b"-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n"
    plan = {
        "trust_model": "trusted-host", "interface": "eth0", "current_address": "192.0.2.10",
        "baseline_address": "192.0.2.30", "static_candidate_address": "192.0.2.40",
        "task_id": "task", "source_commit": "a" * 40,
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
        """Provide a no-drift topology monitor for the simulated bootstrap.

        Args:
            *args: Plan and baseline snapshot passed by the bootstrap flow.
        """
        yield SimpleNamespace(check=lambda: None)

    class Session:
        def __init__(self, *args):
            """Create a fake pinned SSH session.

            Args:
                *args: Connection arguments supplied by the bootstrap flow.
            """
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            """Close the fake context-managed session.

            Args:
                *args: Context-manager exception details, if any.
            """
            pass

        def command(self, _command):
            """Return the public CA bytes for the fake guest readback.

            Args:
                _command: Pinned read-only command issued to the appliance.
            """
            return ca

    fields = {name: "" for name in bootstrap.saved_fields.__globals__["FIELDS"]}
    fields.update(role="management", ipv4_method="dhcp", ipv6_enabled=False)

    class Client:
        def __init__(self, *args, **kwargs):
            """Create a fake management client.

            Args:
                *args: Positional connection arguments supplied by bootstrap.
                **kwargs: Keyword connection options supplied by bootstrap.
            """
            pass

        def login(self, *args):
            """Accept the bootstrap login attempt.

            Args:
                *args: Login arguments supplied by the bootstrap flow.
            """
            pass

        def json(self, _path):
            """Return a clean management review payload.

            Args:
                _path: Management API path requested by the client.
            """
            return 200, {"units": []}

        def interface(self, _name):
            """Return the synthetic interface settings and CSRF value.

            Args:
                _name: Interface name requested for readback.
            """
            return dict(fields, mac_address=plan["mac"]), "public-csrf-placeholder"

        def tls_identity(self):
            return {"sha256": "f" * 64, "ip_sans": [plan["current_address"]]}

    monkeypatch.setattr(bootstrap, "watched_topology", monitor)
    monkeypatch.setattr(bootstrap, "PinnedPeerTransport", Session)
    monkeypatch.setattr(bootstrap, "PinnedApplianceSession", Session)
    monkeypatch.setattr(bootstrap, "verify_peer_isolation", lambda _peer: {})
    monkeypatch.setattr(bootstrap, "verify_peer_tunnel_scope", lambda _peer, addresses: {})
    monkeypatch.setattr(bootstrap, "guest_identity", lambda *args: {
        "app_service": {}, "route_snapshot": {}, "helper_sha256": "a" * 64, "wheel_sha256": "b" * 64})
    monkeypatch.setattr(bootstrap, "tls_name", lambda *args: plan["current_address"])
    monkeypatch.setattr(bootstrap, "Client", Client)
    monkeypatch.setattr(bootstrap, "dns_baseline", lambda _client: {})
    calls = []
    monkeypatch.setattr(bootstrap, "edit", lambda *args: calls.append("edit"))

    def submit(_client):
        """Simulate a connection loss after a possible Apply submission.

        Args:
            _client: Management client whose Apply request was submitted.
        """
        calls.append("submit")
        raise OSError("connection lost after possible submission")

    monkeypatch.setattr(bootstrap, "submit", submit)
    secret = "synthetic-concealed-value"
    def refuse_scope(_peer, addresses):
        """Model a peer that denies the future static candidate tunnel.

        Args:
            _peer: Admitted peer whose effective policy is being checked.
            addresses: All addresses needed across the handoff.
        """
        assert addresses == ["192.0.2.10", "192.0.2.30", "192.0.2.40"]
        raise bootstrap.RetirementRefusal("peer_tunnel_policy_invalid")

    monkeypatch.setattr(bootstrap, "verify_peer_tunnel_scope", refuse_scope)
    rejected = tmp_path / "scope-rejected"
    rejected.mkdir()
    with pytest.raises(bootstrap.RetirementRefusal, match="peer_tunnel_policy_invalid"):
        bootstrap.setup(plan, rejected, secret, execute=True)
    assert calls == []
    assert not (rejected / "mutation-started.json").exists()
    monkeypatch.setattr(bootstrap, "verify_peer_tunnel_scope", lambda _peer, addresses: {})
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

    @contextmanager
    def failed_on_exit(*args):
        """Simulate drift during the last TLS readback.

        Args:
            *args: Admitted plan and initial topology.
        """
        yield SimpleNamespace(check=lambda: None)
        raise bootstrap.Refusal("bootstrap_topology_observation_failed")

    def successful_edit(_client, _interface, changed, _mac):
        """Model a completed desired-state update before the late observer failure.

        Args:
            _client: Authenticated management client.
            _interface: Management interface name.
            changed: New static baseline fields.
            _mac: Original appliance MAC.
        """
        fields.update(changed)

    monkeypatch.setattr(bootstrap, "watched_topology", failed_on_exit)
    monkeypatch.setattr(bootstrap, "edit", successful_edit)
    monkeypatch.setattr(bootstrap, "submit", lambda _client: ("job-test", "/status/test"))
    monkeypatch.setattr(bootstrap, "wait_task", lambda *args: ({"status": "succeeded"}, None))
    monkeypatch.setattr(bootstrap, "clean_baseline", lambda _client: None)
    late = tmp_path / "late-topology-failure"
    late.mkdir()
    with pytest.raises(bootstrap.Refusal, match="bootstrap_topology_observation_failed"):
        bootstrap.setup(plan, late, secret, execute=True)
    terminal = json.loads((late / "bootstrap-result.json").read_text())
    assert terminal["success"] is False
    assert terminal["recovery"] == "preserve_original_state_and_reconcile"
    assert not (late / "proof-plan.json").exists()
