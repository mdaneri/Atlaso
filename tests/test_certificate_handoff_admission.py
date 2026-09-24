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
    monkeypatch.setattr(handoff, "peer_password", lambda: pytest.fail("peer credential read before admission"))
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
        "peer_transport": {"host": "peer", "user": "tester", "ssh_host_key": "key", "private_subnet": "192.168.77.0/24",
                           "baseline_address": "192.168.77.10"},
    }))
    monkeypatch.setattr(sys, "argv", ["handoff", "--plan", str(plan_path), "--evidence", str(evidence_path)])
    monkeypatch.setattr(handoff, "admit_execution", lambda _plan: {})
    monkeypatch.setattr(handoff, "admin_password", lambda: "test-admin-password")
    monkeypatch.setattr(handoff, "peer_password", lambda: "test-peer-password")

    class Peer:
        def __init__(self, *_args):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

    monkeypatch.setattr(handoff, "PinnedPeerTransport", Peer)
    monkeypatch.setattr(handoff, "admit_private_receipts", lambda _plan: (_ for _ in ()).throw(
        handoff.PeerProofRefusal("live ownership changed")))
    monkeypatch.setattr(handoff, "Client", lambda *_args, **_kwargs: pytest.fail("HTTP client before live ownership"))
    with pytest.raises(SystemExit, match="1"):
        handoff.main()
    assert json.loads(evidence_path.read_text())["failure"] == "private_live_preflight_unproven"


def test_peer_credential_is_independent_of_admin(monkeypatch: pytest.MonkeyPatch) -> None:
    """Handle test peer credential is independent of admin for certificate handoff verification.

    Args:
        monkeypatch: Pytest fixture for isolated test overrides."""
    monkeypatch.setenv("ATLASO_NATIVE_ADMIN", "admin-password-123")
    monkeypatch.setenv("ATLASO_NATIVE_PEER", "peer-password-456")
    assert handoff.peer_password() == "peer-password-456"
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
