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


def test_peer_credential_is_independent_of_admin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ATLASO_NATIVE_ADMIN", "admin-password-123")
    monkeypatch.setenv("ATLASO_NATIVE_PEER", "peer-password-456")
    assert handoff.peer_password() == "peer-password-456"
    assert handoff.admin_password() == "admin-password-123"
