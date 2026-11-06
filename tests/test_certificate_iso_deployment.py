"""Receipt-bound tests for deploying a PR wheel onto an original ISO fixture."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/interop"))
import certificate_iso_deployment as deployment  # noqa: E402 - Interop module uses sibling imports.
import certificate_peer_proof as peer_proof  # noqa: E402 - Receipt reader uses the pinned sibling module.

from scripts.installation import content_inspection

_ISO_SHA256 = "a" * 64
_ORIGINAL_COMMIT = "b" * 40
_DEPLOYED_COMMIT = "c" * 40
_MAC = "00:0c:29:12:34:56"
_HOST_KEY = "SHA256:" + base64.b64encode(b"k" * 32).decode("ascii").rstrip("=")
_WHEEL_SHA256 = "d" * 64
_PAYLOAD_SHA256 = "e" * 64
_MACHINE_ID_SHA256 = "f" * 64
_DEPLOYMENT_DIR = "atlaso-certificate-deploy-0123456789abcdef0123456789abcdef"
_WHEEL_FILENAME = "atlaso-1.2.4.whl"
_REMOTE_WHEEL = f"/tmp/{_DEPLOYMENT_DIR}/{_WHEEL_FILENAME}"


def _digest(payload: bytes) -> str:
    """Return the lowercase SHA-256 digest of a receipt payload.

    Args:
        payload: Exact bytes written into a receipt file.
    """
    return hashlib.sha256(payload).hexdigest()


def _write_json(path: Path, value: dict[str, Any]) -> dict[str, str]:
    """Write one ordinary receipt and return its digest-bound reference.

    Args:
        path: Absolute pytest-owned receipt path.
        value: Public receipt object to serialize canonically.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    path.write_bytes(payload)
    return {"path": str(path), "sha256": _digest(payload)}


def _original_report(expected: dict[str, Any], *, measurement: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build a real schema-valid original ISO inspection report.

    Args:
        expected: Public original software expectation from the media validator.
        measurement: Optional exact report values that override the valid defaults.
    """
    value = {
        "schema": 1, "machine_id_sha256": _MACHINE_ID_SHA256, "host_key_sha256": _HOST_KEY,
        "version": expected["version"], "source_commit": expected["source_commit"],
        "wheel_sha256": expected["wheel_sha256"], "wheel_payload_sha256": "1" * 64,
        "installed_payload_sha256": "1" * 64, "verified_payload_files": 21,
    }
    value.update(measurement or {})
    return value


def _network_report(*, address: str = "192.168.77.30", interface: str = "eth0", mac: str = _MAC) -> dict[str, Any]:
    """Build a schema-valid host-only network observation.

    Args:
        address: Observed native interface IPv4 address.
        interface: Observed native management interface name.
        mac: Original VMX-bound adapter MAC address.
    """
    return {
        "schema": 1, "kind": "network", "iso_sha256": _ISO_SHA256,
        "interface": interface, "mac": mac, "address": address, "prefixlen": 24,
        "certificate_sha256": "2" * 64, "default_routes_absent": True,
    }


def _assets_expected() -> dict[str, Any]:
    """Return an existing-validator-compatible original asset expectation."""
    return {
        "schema": 1, "kind": "assets", "iso_sha256": _ISO_SHA256,
        "environment_verifier_sha256": "3" * 64,
        "source_digest": "4" * 64, "source_file_count": 8,
        "trust_names": ["atlaso-release-test.pem"], "trust_digest": "5" * 64,
        "omitted_sources": sorted(content_inspection._VMWARE_SOURCES), "deployed_file_count": 10,
    }


def _assets_report(expected: dict[str, Any]) -> dict[str, Any]:
    """Return the public asset report accepted by the real content validator.

    Args:
        expected: Original ISO-bound assets expectation.
    """
    return {
        "schema": 1, "kind": "assets", "iso_sha256": expected["iso_sha256"],
        "source_digest": expected["source_digest"], "source_file_count": expected["source_file_count"],
        "deployed_files": expected["deployed_file_count"], "trust_digest": expected["trust_digest"],
        "trust_keys": len(expected["trust_names"]),
    }


def _measurement(*, machine_id_sha256: str = _MACHINE_ID_SHA256, payload_sha256: str = _PAYLOAD_SHA256,
                 interface: str = "eth0", mac: str = _MAC, address: str = "192.168.77.30") -> dict[str, Any]:
    """Return the exact active payload report shape.

    Args:
        machine_id_sha256: Original machine identity digest.
        payload_sha256: Matching wheel and installed active payload digest.
        interface: Measured management interface.
        mac: Measured adapter MAC address.
        address: Independently observed native management address.
    """
    return {
        "schema": 1, "wheel_payload_sha256": payload_sha256,
        "installed_payload_sha256": payload_sha256, "verified_payload_files": 21,
        "wheel_sha256": _WHEEL_SHA256, "helper_sha256": "2" * 64,
        "interface": interface, "mac": mac, "address": address,
        "version": "1.2.4", "machine_id_sha256": machine_id_sha256,
    }


def _receipt_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, defect: str | None = None) -> tuple[
    dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any], bytes,
]:
    """Create actual bound receipts while mocking only source/media boundaries.

    Args:
        tmp_path: Pytest-owned directory for ordinary receipt files.
        monkeypatch: Replace ISO parsing and immutable Git reads only.
        defect: Optional independent receipt defect for refusal tests.
    """
    archive = b"synthetic deterministic source archive bytes"
    probe = b"original ISO-bound payload inspector bytes"
    expected = {
        "schema": 1, "iso_sha256": _ISO_SHA256, "version": "1.2.3",
        "source_commit": _ORIGINAL_COMMIT, "release_manifest_sha256": "7" * 64,
        "software_verifier_sha256": "8" * 64, "payload_inspector_sha256": _digest(probe),
        "wheel_sha256": "0" * 64, "installer_source_commit": "1" * 40,
        "helper_sha256": "2" * 64,
    }
    assets = _assets_expected()
    monkeypatch.setattr(deployment, "deployment_inputs", lambda _path, _sha: (expected, assets))
    def git_bytes(_repository: Path, *arguments: str) -> bytes:
        """Return only the admitted immutable source values requested by the module.

        Args:
            _repository: Original task worktree selected by the receipt.
            *arguments: Fixed Git operation and immutable source selectors.
        """
        if arguments == ("rev-parse", "HEAD"):
            return (_DEPLOYED_COMMIT + "\n").encode()
        if arguments == ("archive", "--format=zip", _DEPLOYED_COMMIT):
            return archive
        if arguments == ("show", _DEPLOYED_COMMIT + ":scripts/interop/routing_deployment_inspection.py"):
            return probe
        raise AssertionError(arguments)

    monkeypatch.setattr(deployment, "_git_bytes", git_bytes)
    original_intent = {"schema": 1, "kind": "original-intent", "task_id": "task"}
    intent_ref = _write_json(tmp_path / "appliance-intent.json", original_intent)
    ownership = {
        "schema": 1, "kind": "vm", "phase": "original-installation-vm-created",
        "task_id": "task", "repository": "mdaneri/Atlaso", "pull_request_number": 1118,
        "vmx_path": str(tmp_path / "appliance" / "appliance.vmx"),
        "worktree": str(tmp_path / "source"),
        "installation_iso": {"path": str(tmp_path / "original.iso"), "sha256": _ISO_SHA256},
    }
    owner_ref = _write_json(tmp_path / "appliance-ownership.json", ownership)
    boot_ref = _write_json(tmp_path / "installed-boot.json", {"schema": 1, "phase": "installation-boot-without-media"})
    installed = _original_report(expected)
    installed_ref = _write_json(tmp_path / "installed-inspection.json", installed)
    plan: dict[str, Any] = {
        "schema": 1, "trust_model": "trusted-host", "task_id": "task", "repository": "mdaneri/Atlaso",
        "pr": 1118, "source_commit": _DEPLOYED_COMMIT, "deployed_commit": _DEPLOYED_COMMIT,
        "mac": _MAC, "appliance_vmx": ownership["vmx_path"], "worktree": ownership["worktree"],
        "appliance_intent": intent_ref, "appliance_ownership": owner_ref,
        "appliance_installed_boot": boot_ref, "installed_inspection": installed_ref,
    }
    original_references = {
        key: deployment.reference_binding(plan[key])
        for key in ("appliance_intent", "appliance_ownership", "appliance_installed_boot", "installed_inspection")
    }
    build = {
        "schema": 1, "kind": "certificate-pr-wheel-build", "repository": "mdaneri/Atlaso",
        "pr": 1118, "task_id": "task", "source_commit": _DEPLOYED_COMMIT,
        "source_guards_verified": True, "wheel_sha256": _WHEEL_SHA256,
        "wheel_filename": _WHEEL_FILENAME, "wheel_size": 12345,
        "version": "1.2.4", "archive_sha256": _digest(archive),
    }
    if defect == "wheel_digest":
        build["wheel_sha256"] = "not-a-digest"
    build_ref = _write_json(tmp_path / "build.json", build)
    network = _network_report(interface="eth1" if defect == "interface" else "eth0")
    if defect == "network":
        network["address"] = "192.168.78.30"
    network_ref = _write_json(tmp_path / "network.json", network)
    measured = _measurement(
        machine_id_sha256="0" * 64 if defect == "machine" else _MACHINE_ID_SHA256,
        payload_sha256="a" * 64 if defect == "payload" else _PAYLOAD_SHA256,
        interface="eth1" if defect == "interface" else "eth0",
        mac="00:0c:29:12:34:57" if defect == "mac" else _MAC,
    )
    if defect == "payload":
        measured["installed_payload_sha256"] = "9" * 64
    deployment_receipt: dict[str, Any] = {
        "schema": 1, "kind": "certificate-iso-pr-wheel-deployment",
        "repository": "mdaneri/Atlaso", "pr": 1118, "task_id": "task",
        "source_commit": _DEPLOYED_COMMIT, "status": "succeeded",
        "whole_job_quiescent": True, "vmx_path": ownership["vmx_path"],
        "original_software_source_commit": _ORIGINAL_COMMIT,
        "installer_source_commit": expected["installer_source_commit"], "host_key_sha256": _HOST_KEY,
        "original_references": original_references,
        "build_receipt": build_ref, "remote_wheel": _REMOTE_WHEEL,
        "network_inspection": network_ref, "network_binding": {"subnet": "192.168.77.0", "prefixlen": 24},
        "mac": _MAC, "measurement": measured, "assets_report": _assets_report(assets),
    }
    if defect == "task":
        deployment_receipt["task_id"] = "other-task"
    elif defect == "pr":
        deployment_receipt["pr"] = 9999
    elif defect == "head":
        deployment_receipt["source_commit"] = "d" * 40
    elif defect == "failed":
        deployment_receipt["status"] = "failed"
    elif defect == "not_quiescent":
        deployment_receipt["whole_job_quiescent"] = False
    elif defect == "ssh_pin":
        deployment_receipt["host_key_sha256"] = "SHA256:" + base64.b64encode(b"z" * 32).decode("ascii").rstrip("=")
    elif defect == "original_references":
        deployment_receipt["original_references"]["appliance_intent"]["sha256"] = "f" * 64
    elif defect == "wheel_path":
        deployment_receipt["remote_wheel"] = "/tmp/../etc/atlaso.whl"
    elif defect == "wheel_filename":
        deployment_receipt["remote_wheel"] = f"/tmp/{_DEPLOYMENT_DIR}/atlaso-9.9.9.whl"
    elif defect == "assets":
        deployment_receipt["assets_report"]["deployed_files"] += 1
    if defect == "network_binding":
        deployment_receipt["network_binding"]["subnet"] = "192.168.78.0"
    if defect == "mac":
        deployment_receipt["mac"] = "00:0c:29:12:34:57"
    intent_keys = (
        "schema", "repository", "pr", "task_id", "source_commit", "vmx_path", "original_references",
        "build_receipt", "remote_wheel", "host_key_sha256", "network_inspection", "network_binding", "mac",
    )
    intent = {"kind": "certificate-iso-pr-wheel-deployment-intent",
              **{key: copy.deepcopy(deployment_receipt[key]) for key in intent_keys}}
    intent_ref = _write_json(tmp_path / "deployment-intent.json", intent)
    deployment_receipt["deployment_intent"] = intent_ref
    if defect == "archive":
        build["archive_sha256"] = "f" * 64
        build_ref = _write_json(tmp_path / "build.json", build)
        deployment_receipt["build_receipt"] = build_ref
        intent["build_receipt"] = build_ref
        intent_ref = _write_json(tmp_path / "deployment-intent.json", intent)
        deployment_receipt["deployment_intent"] = intent_ref
    receipt_ref = _write_json(tmp_path / "deployment.json", deployment_receipt)
    plan["iso_wheel_deployment"] = receipt_ref
    context = deployment.original_context(plan)
    return plan, context, deployment_receipt, build, expected, probe


def test_admit_deployment_uses_real_reports_and_preserves_original_iso_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Admit a fully bound PR wheel while retaining original ISO and machine reports.

    Args:
        tmp_path: Pytest-owned directory for original and deployment receipts.
        monkeypatch: Replace ISO parsing and immutable Git read boundaries only.
    """
    plan, context, receipt, build, expected, probe = _receipt_fixture(tmp_path, monkeypatch)

    admitted = deployment.admit_deployment(plan, context=context)

    assert admitted is not None
    assert admitted["status"] == "succeeded"
    assert admitted["build"]["wheel_sha256"] == build["wheel_sha256"]
    assert admitted["original"]["expected"]["source_commit"] == _ORIGINAL_COMMIT
    assert admitted["original"]["installed"]["wheel_sha256"] == expected["wheel_sha256"]
    assert admitted["measurement"]["wheel_sha256"] == _WHEEL_SHA256
    assert deployment.asset_program(context) == content_inspection.guest_content_program(context["assets"])
    assert deployment.payload_program(expected, _REMOTE_WHEEL, "192.168.77.30").startswith(
        "/opt/atlaso/.venv/bin/python -I -B -c "
    )
    assert probe == b"original ISO-bound payload inspector bytes"


@pytest.mark.parametrize(
    ("defect", "reason"),
    [
        ("task", "iso_deployment_receipt_binding_mismatch"),
        ("pr", "iso_deployment_receipt_binding_mismatch"),
        ("head", "iso_deployment_receipt_binding_mismatch"),
        ("ssh_pin", "iso_deployment_receipt_binding_mismatch"),
        ("failed", "iso_deployment_receipt_binding_mismatch"),
        ("not_quiescent", "iso_deployment_receipt_binding_mismatch"),
        ("original_references", "iso_deployment_original_receipt_mismatch"),
        ("archive", "iso_deployment_source_archive_mismatch"),
        ("wheel_digest", "iso_deployment_build_binding_mismatch"),
        ("wheel_path", "iso_deployment_remote_wheel_path_invalid"),
        ("wheel_filename", "iso_deployment_remote_wheel_binding_mismatch"),
        ("payload", "iso_deployment_active_payload_mismatch"),
        ("interface", "iso_deployment_active_identity_mismatch"),
        ("mac", "iso_deployment_network_observation_mismatch"),
        ("network", "iso_deployment_network_observation_mismatch"),
        ("network_binding", "iso_deployment_network_observation_mismatch"),
        ("machine", "iso_deployment_active_identity_mismatch"),
        ("assets", "iso_deployment_original_assets_changed"),
    ],
)
def test_admit_deployment_refuses_independent_receipt_and_measurement_defects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, defect: str, reason: str,
) -> None:
    """Refuse each independent source, identity, network, payload, or asset mismatch.

    Args:
        tmp_path: Pytest-owned directory for ordinary receipt files.
        monkeypatch: Replace ISO parsing and immutable Git read boundaries only.
        defect: Independent invalid deployment receipt or measurement field.
        reason: Expected fixed public refusal category.
    """
    plan, context, _receipt, _build, _expected, _probe = _receipt_fixture(tmp_path, monkeypatch, defect=defect)

    with pytest.raises(deployment.Refusal, match=reason):
        deployment.admit_deployment(plan, context=context)


def test_optional_deployment_absence_keeps_the_legacy_iso_path() -> None:
    """Keep the original signed-wheel path when no overlay receipt is selected."""
    assert deployment.admit_deployment({"task_id": "task"}) is None


def test_deployment_receipt_file_is_required_and_digest_bound(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Refuse a missing or changed deployment receipt file.

    Args:
        tmp_path: Pytest-owned directory for receipt fixtures.
        monkeypatch: Replace only original ISO media parsing.
    """
    plan, context, _receipt, _build, _expected, _probe = _receipt_fixture(tmp_path, monkeypatch)
    receipt_path = Path(plan["iso_wheel_deployment"]["path"])
    receipt_path.write_text("{}", encoding="utf-8")
    with pytest.raises(peer_proof.Refusal, match="receipt_digest_changed"):
        deployment.admit_deployment(plan, context=context)

    plan, context, receipt, _build, _expected, _probe = _receipt_fixture(tmp_path / "second", monkeypatch)
    Path(plan["iso_wheel_deployment"]["path"]).unlink()
    with pytest.raises(peer_proof.Refusal, match="unsafe_receipt_reference"):
        deployment.admit_deployment(plan, context=context)
