"""Exercise the CA rotation scenario through the bounded handoff entrypoint."""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/interop"))
import certificate_handoff_native as handoff  # noqa: E402 - Interop module uses sibling imports.

_PASSWORD = "entrypoint-synthetic-password"
_MAC = "00:50:56:2a:11:22"
_ADDRESS = "192.168.77.30"


def _ca_pem() -> tuple[str, str]:
    """Create a public test CA PEM and its normalized DER digest."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "entrypoint fixture CA")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now.replace(tzinfo=None))
        .not_valid_after(now.replace(tzinfo=None).replace(year=now.year + 1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    der = certificate.public_bytes(serialization.Encoding.DER)
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"), hashlib.sha256(der).hexdigest()


def _plan(ca_path: Path, **changes: object) -> dict:
    """Return a minimal trusted-host rotation plan for main-level contract tests."""
    plan = {
        "pr": 1118,
        "source_commit": "a" * 40,
        "scenario": "ordinary-ca-rotation",
        "trust_model": "trusted-host",
        "expected_web_terminal": False,
        "management_certificate_id": 41,
        "interface": "eth0",
        "mac": _MAC,
        "url": f"https://{_ADDRESS}",
        "ca_path": str(ca_path),
        "username": "synthetic-operator",
        "appliance_user": "root",
        "appliance_ssh_host_key": "ssh-ed25519 synthetic-key",
        "peer_transport": {
            "host": "192.168.77.20",
            "user": "fixture-peer",
            "ssh_public_key": "ssh-ed25519 synthetic-public-key",
            "ssh_host_key": "ssh-ed25519 synthetic-host-key",
            "private_subnet": "192.168.77.0/24",
            "baseline_address": _ADDRESS,
        },
        "address_evidence": {"sha256": "b" * 64},
    }
    plan.update(changes)
    return plan


def _write_inputs(tmp_path: Path, plan: dict) -> tuple[Path, Path]:
    """Write the temporary JSON plan and return its path and evidence destination."""
    plan_path = tmp_path / "plan.json"
    evidence_path = tmp_path / "evidence.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    return plan_path, evidence_path


@pytest.mark.parametrize(
    ("changes", "expected_failure"),
    [
        ({"scenario": "unrecognized-scenario"}, "plan_contract"),
        ({"trust_model": "independent"}, None),
        ({"expected_web_terminal": 1}, "plan_contract"),
        ({"management_certificate_id": True}, "plan_contract"),
        ({"management_certificate_id": 0}, "plan_contract"),
        ({"interface": "eth1"}, "plan_contract"),
        ({"pr": True}, None),
    ],
)
def test_rotation_entrypoint_guards_run_before_credentials_or_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changes: dict, expected_failure: str | None,
) -> None:
    """Reject malformed rotation identity before any authentication or transport setup."""
    pem, _ = _ca_pem()
    ca_path = tmp_path / "root-ca.pem"
    ca_path.write_text(pem, encoding="ascii")
    plan_path, evidence_path = _write_inputs(tmp_path, _plan(ca_path, **changes))
    monkeypatch.setattr(sys, "argv", ["handoff", "--plan", str(plan_path), "--evidence", str(evidence_path)])
    calls: list[str] = []

    def admission(_plan):
        calls.append("admission")
        raise handoff.Refusal("admission reached")

    monkeypatch.setattr(handoff, "admit_execution", admission)
    monkeypatch.setattr(handoff, "admin_password", lambda: pytest.fail("credentials read before rotation admission"))
    monkeypatch.setattr(handoff, "PinnedPeerTransport", lambda *_args, **_kwargs: pytest.fail("peer network before admission"))
    with pytest.raises(SystemExit, match="1"):
        handoff.main()

    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    if expected_failure:
        assert evidence["failure"] == expected_failure
        assert calls == []
    else:
        assert evidence["failure"]
        assert calls == []


def test_trusted_host_positive_pr_inspect_is_admitted_without_credentials_or_peer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An admitted trusted-host positive-PR plan can stop before credentials and transport."""
    pem, _ = _ca_pem()
    ca_path = tmp_path / "root-ca.pem"
    ca_path.write_text(pem, encoding="ascii")
    plan_path, evidence_path = _write_inputs(tmp_path, _plan(ca_path))
    monkeypatch.setattr(
        sys, "argv", ["handoff", "--plan", str(plan_path), "--evidence", str(evidence_path), "--preflight-only"],
    )
    admitted: list[dict] = []
    monkeypatch.setattr(handoff, "admit_execution", lambda plan: admitted.append(plan) or {"admitted": True})
    monkeypatch.setattr(handoff, "admin_password", lambda: pytest.fail("inspect-only read credentials"))
    monkeypatch.setattr(handoff, "PinnedPeerTransport", lambda *_args, **_kwargs: pytest.fail("inspect-only opened peer"))

    handoff.main()

    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert len(admitted) == 1 and admitted[0]["pr"] == 1118
    assert evidence["success"] is True
    assert evidence["stage"] == "admitted_no_credentials_or_network"


@pytest.mark.parametrize("outcome", ["refusal", "success", "topology_failure"])
def test_execute_pins_root_preserves_original_and_handles_rotation_outcomes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    outcome: str,
) -> None:
    """Persist original evidence and preserve the fixture across refusal or topology loss."""
    pem, root_sha256 = _ca_pem()
    ca_path = tmp_path / "root-ca.pem"
    ca_path.write_text(pem, encoding="ascii")
    plan = _plan(ca_path)
    plan_path, evidence_path = _write_inputs(tmp_path, plan)
    fixture = tmp_path / "fixture.marker"
    fixture.write_bytes(b"unchanged fixture bytes")
    initial_fixture = fixture.read_bytes()
    monkeypatch.setattr(sys, "argv", ["handoff", "--plan", str(plan_path), "--evidence", str(evidence_path), "--execute"])
    monkeypatch.setattr(handoff, "admit_execution", lambda _plan: {"admitted": True})
    monkeypatch.setattr(handoff, "admin_password", lambda: _PASSWORD)
    monkeypatch.setattr(handoff, "bound_json", lambda _reference: {"trusted_host_topology": {"interfaces": []}})
    monkeypatch.setattr(handoff, "admit_private_receipts", lambda _plan: ({"fixture": "admitted"}, {}))
    monkeypatch.setattr(handoff, "read_private_native", lambda *_args: {"trusted_host_topology": {"interfaces": []}})
    monkeypatch.setattr(handoff, "inspect_trusted_host", lambda _plan: {"interfaces": []})
    monkeypatch.setattr(handoff, "assert_same_topology", lambda *_args: None)

    class Peer:
        def __init__(self, *_args, **_kwargs):
            self.topology_guard = None

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    class Monitor:
        def __init__(self, *_args):
            self.observations = []
            self.has_failed = False
            self.failed = SimpleNamespace(is_set=lambda: self.has_failed)

        def start(self):
            return None

        def check(self):
            return None

        def stop(self):
            self.has_failed = outcome == "topology_failure"

    class Appliance:
        def __init__(self, *_args):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    class Client:
        def __init__(self, *_args, **_kwargs):
            pass

        def login(self, *_args):
            return None

        def interface(self, _name):
            return {"mac_address": _MAC, "role": "management"}, "csrf"

        def tls_identity(self):
            return {"sha256": "old-leaf", "ip_sans": [_ADDRESS]}

    monkeypatch.setattr(handoff, "PinnedPeerTransport", Peer)
    monkeypatch.setattr(handoff, "TrustedHostMonitor", Monitor)
    monkeypatch.setattr(handoff, "PinnedApplianceSession", Appliance)
    monkeypatch.setattr(handoff, "Client", Client)
    monkeypatch.setattr(handoff, "saved_fields", lambda _row: {
        "role": "management", "ipv6_enabled": False, "ipv4_method": "static", "ip_cidr": f"{_ADDRESS}/24",
    })
    monkeypatch.setattr(handoff, "clean_baseline", lambda _client: None)
    monkeypatch.setattr(handoff, "dns_baseline", lambda _client: {"servers": []})
    monkeypatch.setattr(handoff, "selected_management_certificate", lambda *_args: {
        "id": 41, "fingerprint": "c" * 64,
    })
    monkeypatch.setattr(handoff, "hashlib", hashlib)
    invocations: list[dict] = []

    def exercise_rotation(client, **kwargs):
        assert client.__class__ is Client
        original = json.loads(Path(str(evidence_path) + ".original.json").read_text(encoding="utf-8"))
        assert original["original_certificate"]["id"] == 41
        assert original["ca_sha256"] == hashlib.sha256(ca_path.read_bytes()).hexdigest()
        invocations.append(kwargs)
        if outcome == "refusal":
            raise handoff.Refusal("ca_rotation_failed")
        return {"schema": 1, "task_status": "succeeded"}

    monkeypatch.setitem(sys.modules, "certificate_ca_rotation", SimpleNamespace(exercise_ca_rotation=exercise_rotation))
    monkeypatch.setattr(handoff, "restore_original", lambda *_args, **_kwargs: pytest.fail("rotation refusal triggered rollback"))

    if outcome == "success":
        handoff.main()
    else:
        with pytest.raises(SystemExit, match="1"):
            handoff.main()

    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    assert len(invocations) == 1
    assert invocations[0]["certificate_id"] == 41
    assert invocations[0]["expected_root_sha256"] == root_sha256
    assert invocations[0]["interface_name"] == "eth0"
    assert invocations[0]["expected_mac"] == _MAC
    assert invocations[0]["expected_address"] == _ADDRESS
    assert invocations[0]["expected_web_terminal"] is False
    if outcome == "success":
        assert evidence["success"] is True
        assert evidence["stage"] == "ordinary_ca_rotation_verified"
        assert "recovery" not in evidence
    elif outcome == "refusal":
        assert evidence["failure"] == "ca_rotation_failed"
        assert evidence["recovery"] == "preserve_fixture_and_original_inputs_do_not_resubmit"
    else:
        assert evidence["success"] is False
        assert evidence["failure"] == "trusted_host_topology_changed"
        assert evidence["recovery"] == "preserve_fixture_and_original_inputs_do_not_resubmit"
    assert fixture.read_bytes() == initial_fixture
    public_evidence = json.dumps(evidence)
    assert _PASSWORD not in public_evidence
    if outcome == "refusal":
        assert "ca_rotation_failed" in public_evidence
