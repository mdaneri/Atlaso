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
    """Return a minimal trusted-host plan for main-level contract tests.

    Args:
        ca_path: Public test CA bundle path.
        **changes: Plan fields overridden for this contract case.
    """
    plan = {
        "pr": 1118,
        "source_commit": "a" * 40,
        "deployed_commit": "a" * 40,
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
    """Write the temporary JSON plan and return its path and evidence destination.

    Args:
        tmp_path: Pytest-owned ordinary-file directory.
        plan: Public entrypoint input plan.
    """
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
        ({"deployed_commit": "c" * 40}, "plan_contract"),
        ({"ordinary_ca_baseline_mode": True}, "plan_contract"),
        ({"ordinary_ca_baseline_mode": "unexpected"}, "plan_contract"),
        ({"interface": "eth1"}, "plan_contract"),
        ({"pr": True}, None),
    ],
)
def test_rotation_entrypoint_guards_run_before_credentials_or_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changes: dict, expected_failure: str | None,
) -> None:
    """Reject malformed identity before authentication or transport setup.

    Args:
        tmp_path: Pytest-owned directory for plan and evidence.
        monkeypatch: Replace process arguments and credential/network boundaries.
        changes: Plan mutations for this parametrized case.
        expected_failure: Public refusal stage, or ``None`` when admission is reached.
    """
    pem, _ = _ca_pem()
    ca_path = tmp_path / "root-ca.pem"
    ca_path.write_text(pem, encoding="ascii")
    plan_path, evidence_path = _write_inputs(tmp_path, _plan(ca_path, **changes))
    monkeypatch.setattr(sys, "argv", ["handoff", "--plan", str(plan_path), "--evidence", str(evidence_path)])
    calls: list[str] = []

    def admission(_plan):
        """Record the plan admission boundary.

        Args:
            _plan: Input plan provided to admission.
        """
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
    """An admitted positive-PR plan stops before credentials and transport.

    Args:
        tmp_path: Pytest-owned directory for the plan and public evidence.
        monkeypatch: Replace process arguments, admission, and credential/network boundaries.
    """
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
    """Persist original evidence and preserve the fixture across refusal or topology loss.

    Args:
        tmp_path: Pytest-owned directory for receipts and fixture bytes.
        monkeypatch: Replace provider, peer, appliance, and task boundaries.
        outcome: Rotation refusal, success, or trusted-host topology loss.
    """
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
        """No-network private peer transport double."""

        def __init__(self, *_args, **_kwargs):
            """Accept selected peer identity arguments.

            Args:
                *_args: Positional peer selectors.
                **_kwargs: Optional transport settings.
            """
            self.topology_guard = None

        def __enter__(self):
            """Enter the synthetic peer context."""
            return self

        def __exit__(self, *_args):
            """Exit the synthetic peer context.

            Args:
                *_args: Context manager exit details.
            """
            return None

    class Monitor:
        """Synthetic trusted-host topology monitor."""

        def __init__(self, *_args):
            """Bind the monitor to the original plan and topology.

            Args:
                *_args: Original plan and topology selectors.
            """
            self.observations = []
            self.has_failed = False
            self.failed = SimpleNamespace(is_set=lambda: self.has_failed)

        def start(self):
            """Start the synthetic monitor."""
            return None

        def check(self):
            """Accept the unchanged synthetic topology."""
            return None

        def stop(self):
            """Stop the monitor and expose the selected topology outcome."""
            self.has_failed = outcome == "topology_failure"

    class Appliance:
        """No-network appliance-session double."""

        def __init__(self, *_args):
            """Accept the pinned peer and appliance selectors.

            Args:
                *_args: Peer, address, and appliance identity arguments.
            """
            pass

        def __enter__(self):
            """Enter the synthetic appliance context."""
            return self

        def __exit__(self, *_args):
            """Exit the synthetic appliance context.

            Args:
                *_args: Context manager exit details.
            """
            return None

    class Client:
        """Authenticated no-network management client double."""

        def __init__(self, *_args, **_kwargs):
            """Accept the receipt-selected URL and transport selectors.

            Args:
                *_args: HTTPS and peer selectors.
                **_kwargs: Optional pinned connection settings.
            """
            pass

        def login(self, *_args):
            """Accept the synthetic in-memory login.

            Args:
                *_args: Authentication values.
            """
            return None

        def interface(self, _name):
            """Return the original management interface.

            Args:
                _name: Requested interface name.
            """
            return {"mac_address": _MAC, "role": "management"}, "csrf"

        def tls_identity(self):
            """Return the original public leaf and selected address SAN."""
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
        """Record the one rotation call and return synthetic task evidence.

        Args:
            client: Authenticated no-network management client.
            **kwargs: Explicit interface, certificate, root, and address selectors.
        """
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


def _run_ordinary_entrypoint_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    mode: str,
    final_native_changed: bool = False,
    overlay: bool = False,
) -> tuple[dict, list[dict], list[dict], list[dict], int | None]:
    """Run a no-network ordinary-CA entrypoint fixture through the real main flow.

    Args:
        tmp_path: Pytest-owned directory for plan and evidence files.
        monkeypatch: Replace only providers, transport, and active guest measurement boundaries.
        mode: Static or DHCP original management baseline.
        final_native_changed: Change the final native observation after successful Apply.
        overlay: Enable and optionally change the active payload measurement between reads.
    """
    pem, root_sha256 = _ca_pem()
    ca_path = tmp_path / "root-ca.pem"
    ca_path.write_text(pem, encoding="ascii")
    lease = "192.168.77.10"
    address = lease if mode == "dhcp" else _ADDRESS
    extra = {"url": f"https://{address}"}
    if mode == "dhcp":
        extra.update(ordinary_ca_baseline_mode="dhcp", current_address=lease)
    if overlay:
        extra.update(iso_wheel_deployment={"path": str(tmp_path / "overlay.json"), "sha256": "f" * 64},
                     wheel_sha256="d" * 64, helper_sha256="c" * 64)
    plan = _plan(ca_path, **extra)
    plan_path, evidence_path = _write_inputs(tmp_path, plan)
    monkeypatch.setattr(sys, "argv", ["handoff", "--plan", str(plan_path), "--evidence", str(evidence_path), "--execute"])
    monkeypatch.setattr(handoff, "admit_execution", lambda _plan: {"admitted": True})
    monkeypatch.setattr(handoff, "admin_password", lambda: _PASSWORD)
    reservation = {
        "schema": 1, "kind": "certificate-private-address-proof",
        "phase": "dhcp-baseline-preflight" if mode == "dhcp" else "static-baseline-preflight",
        "trusted_host_topology": {"interfaces": []}, "baseline_address": address,
        "appliance_mac": _MAC, "address_ownership_state": "trusted-host-controlled",
    }
    fixture = {"lease_address": lease}
    monkeypatch.setattr(handoff, "bound_json", lambda _reference: reservation)
    monkeypatch.setattr(handoff, "admit_private_receipts", lambda _plan: (fixture, {}))
    native_reads: list[dict] = []

    def read_native(_plan, _fixture, _peer, _appliance):
        """Return the receipt-bound live observation and optional final drift.

        Args:
            _plan: Admitted certificate acceptance plan.
            _fixture: Original peer fixture used for live observation.
            _peer: No-network peer test double.
            _appliance: No-network appliance test double.
        """
        native_reads.append(dict(reservation))
        if final_native_changed and len(native_reads) == 2:
            return dict(reservation, baseline_address="192.168.77.11", dhcp_reservation="192.168.77.11")
        return dict(reservation)

    monkeypatch.setattr(handoff, "read_private_native", read_native)
    monkeypatch.setattr(handoff, "inspect_trusted_host", lambda _plan: {"interfaces": []})
    monkeypatch.setattr(handoff, "assert_same_topology", lambda *_args: None)

    class Peer:
        """No-network private transport context manager."""

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            """Accept the already admitted peer selectors.

            Args:
                *_args: Pinned peer selectors passed by the entrypoint.
                **_kwargs: Optional authentication mode selected by the peer plan.
            """
            self.topology_guard = None

        def __enter__(self) -> Peer:
            return self

        def __exit__(self, *_args: object) -> None:
            """Close the no-network peer double.

            Args:
                *_args: Context manager exit details.
            """

    class Monitor:
        """No-drift trusted-host monitor for the fixture."""

        def __init__(self, *_args: object) -> None:
            """Bind the test monitor to the original topology.

            Args:
                *_args: Original task plan and topology snapshot.
            """
            self.observations: list[dict] = []
            self.failed = SimpleNamespace(is_set=lambda: False)

        def start(self) -> None:
            """Start the synthetic observer."""

        def check(self) -> None:
            """Accept the unchanged synthetic topology."""

        def stop(self) -> None:
            """Stop the synthetic observer."""

    class Appliance:
        """No-network pinned appliance session double."""

        def __init__(self, *_args: object) -> None:
            """Accept the admitted address and pinned appliance identity.

            Args:
                *_args: Peer, address, username, password, and host key selectors.
            """

        def __enter__(self) -> Appliance:
            return self

        def __exit__(self, *_args: object) -> None:
            """Close the synthetic appliance session.

            Args:
                *_args: Context manager exit details.
            """

    class Client:
        """Authenticated no-network client double at the receipt-selected address."""

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            """Accept the entrypoint's HTTPS and peer selectors.

            Args:
                *_args: URL, CA path, and selected peer transport.
                **_kwargs: Pinned connection address supplied by the entrypoint.
            """

        def login(self, *_args: object) -> None:
            """Accept the bounded synthetic login.

            Args:
                *_args: In-memory authentication values.
            """

        def interface(self, _name: str) -> tuple[dict, str]:
            """Return the original management interface and public CSRF token.

            Args:
                _name: Requested native interface name.
            """
            return {"mac_address": _MAC, "role": "management"}, "csrf"

        def tls_identity(self) -> dict[str, object]:
            """Return the unchanged public leaf and selected address SAN."""
            return {"sha256": "old-leaf", "ip_sans": [address]}

    monkeypatch.setattr(handoff, "PinnedPeerTransport", Peer)
    monkeypatch.setattr(handoff, "TrustedHostMonitor", Monitor)
    monkeypatch.setattr(handoff, "PinnedApplianceSession", Appliance)
    monkeypatch.setattr(handoff, "Client", Client)
    monkeypatch.setattr(handoff, "saved_fields", lambda _row: {
        "role": "management", "ipv6_enabled": False,
        "ipv4_method": "dhcp" if mode == "dhcp" else "static",
        "ip_cidr": "" if mode == "dhcp" else f"{address}/24",
        "gateway": "" if mode == "dhcp" else None,
    })
    monkeypatch.setattr(handoff, "clean_baseline", lambda _client: None)
    monkeypatch.setattr(handoff, "dns_baseline", lambda _client: {"servers": []})
    monkeypatch.setattr(handoff, "selected_management_certificate", lambda *_args: {
        "id": 41, "fingerprint": "c" * 64,
    })
    monkeypatch.setattr(handoff, "restore_original", lambda *_args, **_kwargs: pytest.fail("CA rotation was replayed"))
    rotation_calls: list[dict] = []

    def exercise_rotation(_client, **kwargs: object) -> dict[str, object]:
        """Record the one controlled CA exercise and return its task evidence.

        Args:
            _client: Authenticated no-network management client.
            **kwargs: Explicit mode, interface, certificate, and receipt selectors.
        """
        rotation_calls.append(kwargs)
        return {"schema": 1, "task_status": "succeeded", "mode": mode}

    guest_reads: list[dict[str, str]] = []

    def guest_identity(*_args: object) -> dict[str, str]:
        """Return the measured active wheel/helper identity for the overlay check.

        Args:
            *_args: Pinned appliance session, plan, and in-memory password.
        """
        value = {"wheel_sha256": plan.get("wheel_sha256", "d" * 64),
                 "helper_sha256": plan.get("helper_sha256", "c" * 64)}
        guest_reads.append(value)
        if overlay and len(guest_reads) == 2:
            return {**value, "wheel_sha256": "0" * 64}
        return value

    monkeypatch.setitem(sys.modules, "certificate_ca_rotation", SimpleNamespace(exercise_ca_rotation=exercise_rotation))
    monkeypatch.setitem(sys.modules, "certificate_iso_bootstrap", SimpleNamespace(guest_identity=guest_identity))
    exit_code: int | None = None
    try:
        handoff.main()
    except SystemExit as exc:
        exit_code = int(exc.code)
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    return evidence, rotation_calls, native_reads, guest_reads, exit_code


def test_dhcp_entrypoint_passes_mode_and_rechecks_live_ownership_after_rotation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pass the admitted DHCP lease through CA rotation and record final re-observation.

    Args:
        tmp_path: Pytest-owned directory for plan and terminal evidence.
        monkeypatch: Replace all provider, network, and guest-measurement boundaries.
    """
    evidence, calls, native_reads, _guest_reads, exit_code = _run_ordinary_entrypoint_case(
        tmp_path, monkeypatch, mode="dhcp",
    )

    assert exit_code is None
    assert len(calls) == 1
    assert calls[0]["management_mode"] == "dhcp"
    assert calls[0]["expected_address"] == "192.168.77.10"
    assert len(native_reads) == 2
    assert evidence["post_ca_dhcp_observation"] == {
        "phase": "after-ca-rotation", "address": "192.168.77.10",
        "mac": _MAC, "lease_state": "unexpired-original-mac-lease",
    }
    assert evidence["success"] is True


def test_dhcp_entrypoint_preserves_ca_result_when_final_native_ownership_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retain successful Apply evidence and refuse success when the DHCP lease changes.

    Args:
        tmp_path: Pytest-owned directory for plan and terminal evidence.
        monkeypatch: Replace all provider, network, and guest-measurement boundaries.
    """
    evidence, calls, native_reads, _guest_reads, exit_code = _run_ordinary_entrypoint_case(
        tmp_path, monkeypatch, mode="dhcp", final_native_changed=True,
    )

    assert exit_code == 1
    assert len(calls) == 1
    assert len(native_reads) == 2
    assert evidence["failure"] == "post_ca_dhcp_ownership_changed"
    assert evidence["ordinary_ca_rotation"]["task_status"] == "succeeded"
    assert evidence["recovery"] == "preserve_fixture_and_original_inputs_do_not_resubmit"
    assert evidence["success"] is False


def test_overlay_payload_is_rechecked_after_ca_task_and_late_change_refuses_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Preserve CA task evidence but refuse if the active wheel changes after Apply.

    Args:
        tmp_path: Pytest-owned directory for plan and terminal evidence.
        monkeypatch: Replace all provider, network, and active-payload measurement boundaries.
    """
    evidence, calls, _native_reads, guest_reads, exit_code = _run_ordinary_entrypoint_case(
        tmp_path, monkeypatch, mode="static", overlay=True,
    )

    assert exit_code == 1
    assert len(calls) == 1
    assert len(guest_reads) == 2
    assert evidence["failure"] == "post_ca_deployed_payload_changed"
    assert evidence["ordinary_ca_rotation"]["task_status"] == "succeeded"
    assert evidence["recovery"] == "preserve_fixture_and_original_inputs_do_not_resubmit"
    assert evidence["success"] is False
