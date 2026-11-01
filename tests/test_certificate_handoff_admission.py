"""Ensure certificate inspection refuses mutable peer evidence before authentication."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "interop"))
import certificate_handoff_native as handoff  # noqa: E402 - Local interop import after path setup.


def test_inspect_admits_before_credential_or_peer_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Handle test inspect admits before credential or peer connection for certificate handoff verification.

    Args:
        tmp_path: Pytest-owned temporary directory.
        monkeypatch: Pytest fixture for isolated test overrides."""
    plan_path = tmp_path / "plan.json"
    evidence_path = tmp_path / "evidence.json"
    plan_path.write_text(json.dumps({"pr": 871, "source_commit": "a" * 40, "scenario": "static-success"}))
    monkeypatch.setattr(sys, "argv", ["handoff", "--plan", str(plan_path), "--evidence", str(evidence_path)])
    monkeypatch.setattr(handoff, "admit_execution", lambda plan: (_ for _ in ()).throw(handoff.Refusal("peer_original_identity_mismatch")))
    monkeypatch.setattr(handoff, "admin_password", lambda: pytest.fail("admin credential read before admission"))
    monkeypatch.setattr(handoff, "PinnedPeerTransport", lambda *args: pytest.fail("network before admission"))
    with pytest.raises(SystemExit, match="1"):
        handoff.main()
    evidence = json.loads(evidence_path.read_text())
    assert evidence["success"] is False
    assert evidence["failure"] == "peer_original_identity_mismatch"


def test_live_address_ownership_precedes_http_login(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A changed private-LAN claim must stop before the admin password is sent.

    Args:
        tmp_path: Pytest-owned temporary directory.
        monkeypatch: Pytest fixture for isolated test overrides.
    """
    plan_path = tmp_path / "plan.json"
    evidence_path = tmp_path / "evidence.json"
    plan_path.write_text(json.dumps({
        "pr": 871, "source_commit": "a" * 40, "scenario": "static-success",
        "peer_transport": {"host": "peer", "user": "tester", "ssh_host_key": "key",
                           "ssh_public_key": "ssh-ed25519 " + "A" * 44, "private_subnet": "192.168.77.0/24",
                           "baseline_address": "192.168.77.10"},
    }))
    monkeypatch.setattr(sys, "argv", ["handoff", "--plan", str(plan_path), "--evidence", str(evidence_path)])
    monkeypatch.setattr(handoff, "admit_execution", lambda _plan: {})
    monkeypatch.setattr(handoff, "admin_password", lambda: "test-admin-password")

    class Peer:
        def __init__(self, *_args):
            """Create a test-only peer transport.

            Args:
                *_args: Ignored transport constructor arguments.
            """
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            """Close the test-only peer transport.

            Args:
                *_args: Ignored context-manager exit arguments.
            """
            pass

    monkeypatch.setattr(handoff, "PinnedPeerTransport", Peer)
    monkeypatch.setattr(handoff, "admit_private_receipts", lambda _plan: (_ for _ in ()).throw(
        handoff.PeerProofRefusal("live ownership changed")))
    monkeypatch.setattr(handoff, "Client", lambda *_args, **_kwargs: pytest.fail("HTTP client before live ownership"))
    with pytest.raises(SystemExit, match="1"):
        handoff.main()
    assert json.loads(evidence_path.read_text())["failure"] == "private_live_preflight_unproven"


def test_admin_bridge_consumes_only_admin_password(monkeypatch: pytest.MonkeyPatch) -> None:
    """Require the appliance bridge to consume only its designated password.

    Args:
        monkeypatch: Pytest fixture for isolated test overrides."""
    monkeypatch.setenv("ATLASO_NATIVE_ADMIN", "admin-password-123")
    assert handoff.admin_password() == "admin-password-123"


def test_admission_git_child_has_no_credential_bridge(monkeypatch: pytest.MonkeyPatch) -> None:
    """The head check must not pass either plaintext bridge value to Git.

    Args:
        monkeypatch: Isolated environment and Git subprocess replacement.
    """
    monkeypatch.setenv("ATLASO_NATIVE_ADMIN", "dummy-admin-password")
    monkeypatch.setenv("ATLASO_NATIVE_PEER", "dummy-peer-password")
    observed = []

    def refuse_after_environment_check(_command, **kwargs):
        """Stop after recording the Git child's scrubbed environment.

        Args:
            _command: Git invocation arguments, unused by this assertion.
            **kwargs: Subprocess options containing the child environment.
        """
        observed.append(kwargs["env"])
        raise RuntimeError("stop before reading plan artifacts")

    monkeypatch.setattr(handoff.subprocess, "run", refuse_after_environment_check)
    with pytest.raises(RuntimeError, match="stop before reading plan artifacts"):
        handoff.admit_execution({"deployed_commit": "a" * 40})
    assert len(observed) == 1
    assert "ATLASO_NATIVE_ADMIN" not in observed[0]
    assert "ATLASO_NATIVE_PEER" not in observed[0]


def test_interface_edit_accepts_vmware_mac_spelling_only_for_same_device() -> None:
    """The VMX uses hyphens while the authenticated UI inventory uses colons."""
    class Client:
        def __init__(self) -> None:
            self.posts: list[tuple[str, dict]] = []

        def interface(self, _name: str) -> tuple[dict, str]:
            """Handle interface for certificate handoff verification.

            Args:
                _name:  name used by this operation."""
            return {"id": 4, "mac_address": "00:50:56:AA:BB:CC"}, "csrf-value"

        def request(self, path: str, form: dict) -> None:
            """Handle request for certificate handoff verification.

            Args:
                path: Path to the resource being inspected.
                form: Form fields submitted to the appliance."""
            self.posts.append((path, form))

    client = Client()
    handoff.edit(client, "eth0", {"access_management_ui_enabled": False}, "00-50-56-aa-bb-cc")
    assert client.posts == [(
        "/ui/management/physical-interfaces/4/edit",
        {"access_management_ui_enabled": "off", "csrf": "csrf-value"},
    )]
    with pytest.raises(handoff.Refusal, match="interface_mac_changed"):
        handoff.edit(client, "eth0", {"access_management_ui_enabled": False}, "00-50-56-aa-bb-cd")
    assert len(client.posts) == 1


@pytest.mark.parametrize("changed", ["task_id", "vmx_path", "source_commit", "digest"])
def test_predeployment_snapshot_must_belong_to_exact_runtime(changed: str) -> None:
    """A clean snapshot from another lab cannot authorize this VM's mutation.

    Args:
        changed: Changed used by this operation."""
    plan = {"task_id": "task-a", "vmx_path": "owned-a.vmx",
            "predeployment_evidence": {"sha256": "a" * 64}}
    ownership = {"source_commit": "b" * 40}
    source = {"task_id": "task-a", "vmx_path": "owned-a.vmx", "source_commit": "b" * 40}
    runtime = {"predeployment_sha256": "a" * 64}
    handoff.admit_predeployment_binding(plan, ownership, source, runtime)
    if changed == "digest":
        runtime["predeployment_sha256"] = "c" * 64
    elif changed == "source_commit":
        source[changed] = "c" * 40
    else:
        source[changed] = "other"
    with pytest.raises(handoff.Refusal, match="predeployment_runtime_binding_mismatch"):
        handoff.admit_predeployment_binding(plan, ownership, source, runtime)


def test_trusted_host_source_and_deployed_commits_are_distinct_bindings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A trusted-host plan checks the reviewed source head separately from deployed code."""
    source_commit = "a" * 40
    deployed_commit = "b" * 40
    assert source_commit != deployed_commit

    class StopAfterHeadCheck(Exception):
        pass

    monkeypatch.setattr(
        handoff.subprocess, "run",
        lambda *_args, **_kwargs: type("Result", (), {"stdout": source_commit + "\n"})(),
    )

    def stop_at_original_receipt(_reference):
        raise StopAfterHeadCheck()

    monkeypatch.setattr(handoff, "bound_json", stop_at_original_receipt)
    plan = {
        "trust_model": "trusted-host", "source_commit": source_commit,
        "deployed_commit": deployed_commit, "vm_creation_intent": {},
    }
    with pytest.raises(StopAfterHeadCheck):
        handoff.admit_execution(plan)


def test_unrelated_resource_source_commit_fails_before_receipt_read_or_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A resource source outside the harness ancestry is rejected before receipt admission."""
    current_head = "a" * 40
    resource_source = "b" * 40
    calls: list[list[str]] = []

    def git_run(command, **_kwargs):
        calls.append(command)
        if command[-2:] == ["rev-parse", "HEAD"]:
            return type("Result", (), {"stdout": current_head + "\n", "returncode": 0})()
        return type("Result", (), {"stdout": "", "returncode": 1})()

    monkeypatch.setattr(handoff.subprocess, "run", git_run)
    monkeypatch.setattr(handoff, "bound_json", lambda _ref: pytest.fail("receipt read before ancestry admission"))
    plan = {
        "trust_model": "trusted-host", "source_commit": current_head,
        "resource_source_commit": resource_source, "deployed_commit": "c" * 40,
    }
    with pytest.raises(handoff.Refusal, match="resource_source_not_reviewed_ancestor"):
        handoff.admit_execution(plan)
    assert len(calls) == 2
    assert calls[1][-3:] == ["--is-ancestor", resource_source, current_head]


def test_reviewed_resource_source_ancestor_allows_initial_receipt_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid original resource ancestor passes the gate before the first receipt is read."""
    current_head = "a" * 40
    resource_source = "b" * 40

    class StopAtReceiptRead(Exception):
        pass

    calls: list[list[str]] = []

    def git_run(command, **_kwargs):
        calls.append(command)
        if command[-2:] == ["rev-parse", "HEAD"]:
            return type("Result", (), {"stdout": current_head + "\n", "returncode": 0})()
        return type("Result", (), {"stdout": "", "returncode": 0})()

    monkeypatch.setattr(handoff.subprocess, "run", git_run)

    def stop_at_receipt(_reference):
        raise StopAtReceiptRead()

    monkeypatch.setattr(handoff, "bound_json", stop_at_receipt)
    plan = {
        "trust_model": "trusted-host", "source_commit": current_head,
        "resource_source_commit": resource_source, "deployed_commit": "c" * 40,
        "vm_creation_intent": {},
    }
    with pytest.raises(StopAtReceiptRead):
        handoff.admit_execution(plan)
    assert len(calls) == 2
    assert calls[1][-3:] == ["--is-ancestor", resource_source, current_head]


def test_topology_drift_blocks_desired_http_edit_before_request() -> None:
    """A changed host topology prevents the protected HTTP write from reaching the opener."""
    checked: list[str] = []

    def topology_guard() -> None:
        checked.append("drift")
        raise handoff.HostRefusal("trusted_host_topology_changed")

    class Peer:
        pass

    Peer.topology_guard = staticmethod(topology_guard)

    class Opener:
        def open(self, *_args, **_kwargs):
            pytest.fail("HTTP desired-state edit reached the network after topology drift")

    client = handoff.Client.__new__(handoff.Client)
    client.url = "https://192.168.77.30"
    client.peer = Peer()
    client.opener = Opener()
    with pytest.raises(handoff.HostRefusal, match="trusted_host_topology_changed"):
        client.request("/ui/management/settings", {"hostname": "changed"})
    assert checked == ["drift"]
