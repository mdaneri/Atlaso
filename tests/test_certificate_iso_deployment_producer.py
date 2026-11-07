"""Exercise receipt production before and after an offline ISO wheel deployment."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pycdlib
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts/interop"))
import certificate_iso_deployment as deployment  # noqa: E402 - Interop module uses sibling imports.
import certificate_iso_transport as transport  # noqa: E402 - Exercise the producer's actual child admission.

from scripts.interop.certificate_peer_proof import bound_json, publish  # noqa: E402 - Real public receipt helpers.
from tests.test_certificate_iso_deployment import (  # noqa: E402 - Reuse the existing admitted receipt fixture.
    _DEPLOYED_COMMIT,
    _DEPLOYMENT_DIR,
    _HOST_KEY,
    _MAC,
    _ORIGINAL_COMMIT,
    _WHEEL_FILENAME,
    _assets_report,
    _digest,
    _measurement,
    _network_report,
    _original_report,
    _receipt_fixture,
    _write_json,
)

_REQUIREMENTS = ("packaging>=24", "cryptography==50.0.0")
_ARCHIVE = b"immutable reviewed source archive"
_PROBE = b"original ISO-bound payload inspector bytes"


def _wheel_bytes(version: str, requirements: tuple[str, ...] = _REQUIREMENTS) -> bytes:
    """Build a bounded Atlaso wheel metadata fixture.

    Args:
        version: Public version recorded in the wheel metadata.
        requirements: Exact application dependencies declared by the wheel.
    """
    from io import BytesIO

    stream = BytesIO()
    with zipfile.ZipFile(stream, "w") as wheel:
        metadata = "\n".join(("Metadata-Version: 2.1", "Name: atlaso", f"Version: {version}",
                              *(f"Requires-Dist: {item}" for item in requirements), "", ""))
        wheel.writestr(f"atlaso-{version}.dist-info/METADATA", metadata.encode())
    return stream.getvalue()


def _write_mini_iso(path: Path) -> tuple[str, str, dict[str, str]]:
    """Create a real Rock Ridge ISO carrying the original manifest and wheelhouse.

    Args:
        path: Pytest-owned destination for the small ISO fixture.

    Returns:
        The ISO digest, release-manifest digest, and signed wheelhouse inventory.
    """
    dependency = b"signed offline dependency wheel"
    dependency_name = "packaging-24.2-py3-none-any.whl"
    dependency_digest = hashlib.sha256(dependency).hexdigest()
    inventory = {dependency_name: dependency_digest}
    manifest = json.dumps({
        "content_hashes": {f"wheelhouse/cp314/{dependency_name}": dependency_digest},
    }, sort_keys=True, separators=(",", ":")).encode()
    original_wheel = _wheel_bytes("1.2.3")
    source = json.dumps({"application_wheel": "atlaso-1.2.3.whl"}, sort_keys=True).encode()

    source_root = path.parent / "iso-source"
    source_root.mkdir()
    files = {
        "release-manifest.json": manifest,
        "virtualization-source.json": source,
        "atlaso-1.2.3.whl": original_wheel,
        dependency_name: dependency,
    }
    file_paths: dict[str, Path] = {}
    for name, payload in files.items():
        item = source_root / name
        item.write_bytes(payload)
        file_paths[name] = item

    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, joliet=3, rock_ridge="1.09")
    for directory, rr_name in (
        ("/ATLASO", "atlaso"),
        ("/ATLASO/SOFTWARE", "software"),
        ("/ATLASO/SOFTWARE/WHEELHOUSE", "wheelhouse"),
        ("/ATLASO/SOFTWARE/WHEELHOUSE/CP314", "cp314"),
    ):
        iso.add_directory(iso_path=directory, rr_name=rr_name)
    iso.add_file(str(file_paths["release-manifest.json"]), iso_path="/ATLASO/SOFTWARE/RELEASE_MANIFEST.JSON;1",
                 rr_name="release-manifest.json")
    iso.add_file(str(file_paths["virtualization-source.json"]), iso_path="/ATLASO/SOFTWARE/VIRTUALIZATION_SOURCE.JSON;1",
                 rr_name="virtualization-source.json")
    iso.add_file(str(file_paths["atlaso-1.2.3.whl"]), iso_path="/ATLASO/SOFTWARE/ATLASO_1_2_3.WHL;1",
                 rr_name="atlaso-1.2.3.whl")
    iso.add_file(str(file_paths[dependency_name]),
                 iso_path="/ATLASO/SOFTWARE/WHEELHOUSE/CP314/PACKAGING_24_2_PY3_NONE_ANY.WHL;1",
                 rr_name=dependency_name)
    iso.write(str(path))
    iso.close()
    return hashlib.sha256(path.read_bytes()).hexdigest(), hashlib.sha256(manifest).hexdigest(), inventory


def _producer_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[
    dict[str, Any], dict[str, Any], dict[str, Any], Path, Path, dict[str, str], bytes, bytes,
]:
    """Extend the shared admission fixture with the producer's original-state receipts.

    Args:
        tmp_path: Pytest-owned root for source, media, and receipt files.
        monkeypatch: Replace immutable Git output and bind the task identity.

    Returns:
        The plan, native admission, admitted context, ISO path, dependency directory,
        exact signed wheel inventory, candidate wheel bytes, and reviewed archive bytes.
    """
    plan, _context, _receipt, _build, expected, _probe = _receipt_fixture(tmp_path, monkeypatch)
    monkeypatch.setenv("CODEX_THREAD_ID", "task")
    source = tmp_path / "source"
    source.mkdir()
    appliance = tmp_path / "appliance"
    appliance.mkdir()
    backup = tmp_path / "original-vmx-backup.bin"
    backup.write_bytes(b"exact original backed-up VMX bytes")
    iso_path = tmp_path / "original.iso"
    iso_sha256, release_sha256, inventory = _write_mini_iso(iso_path)

    # The existing fixture's public validator result is closure-bound; update it in place.
    deployment_inputs = deployment.deployment_inputs
    original_expected, original_assets = deployment_inputs(Path("unused"), "0" * 64)
    original_expected.update({
        "iso_sha256": iso_sha256,
        "release_manifest_sha256": release_sha256,
        "wheel_sha256": hashlib.sha256(_wheel_bytes("1.2.3")).hexdigest(),
    })
    original_assets["iso_sha256"] = iso_sha256
    monkeypatch.setattr(deployment, "deployment_inputs", lambda _path, _sha: (original_expected, original_assets))

    ownership = bound_json(plan["appliance_ownership"])
    ownership.update({
        "output_directory": str(appliance),
        "worktree": str(source),
        "installation_iso": {"path": str(iso_path), "sha256": iso_sha256},
    })
    ownership_ref = _write_json(tmp_path / "appliance-ownership.json", ownership)
    plan["appliance_ownership"] = ownership_ref
    plan["appliance_vmx"] = ownership["vmx_path"]
    plan["worktree"] = str(source)

    original_expected["iso_sha256"] = iso_sha256
    installed = _original_report(original_expected)
    installed_ref = _write_json(tmp_path / "installed-inspection.json", installed)
    plan["installed_inspection"] = installed_ref

    def original_record(path: str, phase: str, **extra: Any) -> dict[str, str]:
        """Publish one bound original appliance transition record.

        Args:
            path: Filename for the original receipt under the fixture root.
            phase: Installation lifecycle phase sealed into the record.
            **extra: Phase-specific public facts included in the receipt.
        """
        value = {
            "schema": 1,
            "phase": phase,
            "task_id": "task",
            "repository": "mdaneri/Atlaso",
            "pull_request_number": 1118,
            "source_commit": _ORIGINAL_COMMIT,
            "vmx_path": ownership["vmx_path"],
            "output_directory": str(appliance),
            **extra,
        }
        return _write_json(tmp_path / path, value)

    intent_ref = original_record("appliance-intent.json", "installation-pending")
    plan["appliance_intent"] = intent_ref
    baseline_ref = original_record("disk-baseline.json", "installation-disk-baseline")
    plan["appliance_disk_baseline"] = baseline_ref
    boot_ref = original_record(
        "installed-boot.json", "installation-boot-without-media", after_sha256="9" * 64,
    )
    plan["appliance_installed_boot"] = boot_ref

    plan["deployment_network_binding"] = {"subnet": "192.168.77.0", "prefixlen": 24, "vmnet": "vmnet9"}
    network = _network_report()
    network["iso_sha256"] = iso_sha256
    network_ref = _write_json(tmp_path / "network.json", network)
    plan["deployment_network_inspection"] = network_ref
    transition = {
        "schema": 1,
        "kind": "certificate-iso-host-only-transition",
        "task_id": "task",
        "source_commit": _DEPLOYED_COMMIT,
        "repository": "mdaneri/Atlaso",
        "pr": 1118,
        "vmx_path": ownership["vmx_path"],
        "ownership": deployment.reference_binding(ownership_ref),
        "boot": deployment.reference_binding(boot_ref),
        "backup_path": str(backup),
        "backup_sha256": hashlib.sha256(backup.read_bytes()).hexdigest(),
        "boot_configuration_sha256": "9" * 64,
        "stopped_vm_verified": True,
        "unselected_disk_unchanged": True,
        "vmnet": "vmnet9",
    }
    plan["host_only_transition"] = _write_json(tmp_path / "host-only-transition.json", transition)
    plan["source_commit"] = _DEPLOYED_COMMIT
    plan["deployed_commit"] = _DEPLOYED_COMMIT
    plan["mac"] = _MAC

    def git_bytes(_repository: Path, *arguments: str) -> bytes:
        """Return fixed public Git facts for the original and deployed commits.

        Args:
            _repository: Original task source path selected by the receipt.
            *arguments: Immutable Git operation and public commit selectors.
        """
        if arguments == ("rev-parse", "HEAD"):
            return (_DEPLOYED_COMMIT + "\n").encode()
        if arguments == ("status", "--porcelain=v1", "--untracked-files=all"):
            return b""
        if arguments == ("branch", "--show-current"):
            return b"codex/certificate-deployment-producer\n"
        if len(arguments) == 3 and arguments[0] == "merge-base":
            return (arguments[2] + "\n").encode()
        if arguments == ("archive", "--format=zip", _DEPLOYED_COMMIT):
            return _ARCHIVE
        if arguments == ("show", _DEPLOYED_COMMIT + ":scripts/interop/routing_deployment_inspection.py"):
            return _PROBE
        raise AssertionError(arguments)

    monkeypatch.setattr(deployment, "_git_bytes", git_bytes)
    native = {
        "VmxPath": ownership["vmx_path"],
        "OriginalReceiptPath": ownership_ref["path"],
        "OriginalReceiptSha256": ownership_ref["sha256"],
        "BaselineReceiptPath": baseline_ref["path"],
        "BaselineReceiptSha256": baseline_ref["sha256"],
        "BootReceiptPath": boot_ref["path"],
        "BootReceiptSha256": boot_ref["sha256"],
        "Network": {"Mac": _MAC, "Subnet": "192.168.77.0", "PrefixLength": 24},
    }
    context = deployment.prepare_context(plan, native)
    dependency_directory = tmp_path / "offline-wheels"
    dependency_directory.mkdir()
    for filename in inventory:
        (dependency_directory / filename).write_bytes(b"signed offline dependency wheel")
    candidate = _wheel_bytes("1.2.4")
    return plan, native, context, iso_path, dependency_directory, inventory, candidate, _ARCHIVE


def test_prepare_context_admits_clean_source_and_original_host_only_transition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Admit a clean reviewed source with bound native baseline and backed-up transition.

    Args:
        tmp_path: Pytest-owned root for source, media, and receipt fixtures.
        monkeypatch: Replace immutable Git output and bind the task identity.
    """
    _plan, _native, context, _iso_path, _directory, _inventory, _candidate, _archive = _producer_fixture(
        tmp_path, monkeypatch,
    )

    assert context["network"]["address"] == "192.168.77.30"
    assert context["native"]["Network"]["Subnet"] == "192.168.77.0"
    assert context["ownership"]["installation_iso"]["sha256"] == context["expected"]["iso_sha256"]


def test_inspect_cli_publishes_only_the_original_read_only_admission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Publish a read-only inspection receipt without preparing a deployment request.

    Args:
        tmp_path: Pytest-owned root for source, media, plan, and output files.
        monkeypatch: Replace immutable Git output, task identity, and command-line arguments.
    """
    plan, native, _context, _iso_path, _directory, _inventory, _candidate, _archive = _producer_fixture(
        tmp_path, monkeypatch,
    )
    plan_path = tmp_path / "inspect-plan.json"
    native_path = tmp_path / "inspect-native.json"
    output = tmp_path / "inspect-output"
    output.mkdir()
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    native_path.write_text(json.dumps(native), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [
        "certificate_iso_deployment", "inspect", "--plan", str(plan_path), "--output-root", str(output),
        "--native-admission", str(native_path),
    ])

    assert deployment.main() == 0

    receipt = bound_json(deployment._reference(output / "inspection.json"))
    assert receipt["kind"] == "certificate-iso-wheel-deployment-inspection"
    assert receipt["source_commit"] == _DEPLOYED_COMMIT
    assert receipt["original_software_source_commit"] == _ORIGINAL_COMMIT
    assert receipt["host_key_sha256"] == _HOST_KEY
    assert not (output / "request.json").exists()


@pytest.mark.parametrize(
    ("defect", "reason"),
    [
        ("foreign_head", "iso_deployment_clean_task_source_required"),
        ("dirty_source", "iso_deployment_clean_task_source_required"),
        ("foreign_ancestor", "iso_deployment_original_source_not_ancestor"),
        ("native_baseline", "iso_deployment_native_admission_mismatch"),
        ("transition", "iso_deployment_original_host_only_transition_invalid"),
    ],
)
def test_prepare_context_refuses_unbound_source_or_original_appliance_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, defect: str, reason: str,
) -> None:
    """Refuse source, baseline, ancestry, or backup-transition changes before deployment.

    Args:
        tmp_path: Pytest-owned root for source, media, and receipt fixtures.
        monkeypatch: Replace immutable Git output and bind the task identity.
        defect: Independent source or original-appliance mutation to exercise.
        reason: Expected fixed refusal category.
    """
    plan, native, _context, _iso_path, _directory, _inventory, _candidate, _archive = _producer_fixture(
        tmp_path, monkeypatch,
    )
    original_git = deployment._git_bytes

    def git_bytes(repository: Path, *arguments: str) -> bytes:
        """Alter only the Git fact selected by the refusal case.

        Args:
            repository: Original task source path selected by the receipt.
            *arguments: Immutable Git operation and public commit selectors.
        """
        if defect == "foreign_head" and arguments == ("rev-parse", "HEAD"):
            return ("d" * 40 + "\n").encode()
        if defect == "dirty_source" and arguments == ("status", "--porcelain=v1", "--untracked-files=all"):
            return b" M source.py\n"
        if defect == "foreign_ancestor" and len(arguments) == 3 and arguments[0] == "merge-base":
            return ("e" * 40 + "\n").encode()
        return original_git(repository, *arguments)

    monkeypatch.setattr(deployment, "_git_bytes", git_bytes)
    if defect == "native_baseline":
        native["BaselineReceiptSha256"] = "0" * 64
    if defect == "transition":
        transition = bound_json(plan["host_only_transition"])
        transition["vmnet"] = "vmnet8"
        plan["host_only_transition"] = _write_json(tmp_path / "changed-transition.json", transition)

    with pytest.raises(deployment.Refusal, match=reason):
        deployment.prepare_context(plan, native)


def test_admit_offline_wheels_accepts_the_exact_iso_signed_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Admit the complete signed wheelhouse when candidate requirements are unchanged.

    Args:
        tmp_path: Pytest-owned root for source, ISO, and wheelhouse files.
        monkeypatch: Replace immutable Git output and bind the task identity.
    """
    _plan, _native, context, _iso_path, directory, inventory, candidate, _archive = _producer_fixture(
        tmp_path, monkeypatch,
    )

    assert deployment.admit_offline_wheels(context, candidate, directory) == inventory


@pytest.mark.parametrize("defect", ["missing", "extra", "changed", "requirements"])
def test_admit_offline_wheels_refuses_incomplete_or_incompatible_dependencies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, defect: str,
) -> None:
    """Refuse a changed signed inventory or application dependency declaration.

    Args:
        tmp_path: Pytest-owned root for source, ISO, and wheelhouse files.
        monkeypatch: Replace immutable Git output and bind the task identity.
        defect: Missing, extra, changed wheel or changed application requirement.
    """
    _plan, _native, context, _iso_path, directory, _inventory, candidate, _archive = _producer_fixture(
        tmp_path, monkeypatch,
    )
    if defect == "missing":
        next(directory.iterdir()).unlink()
    elif defect == "extra":
        (directory / "unexpected-1.0-py3-none-any.whl").write_bytes(b"unexpected dependency")
    elif defect == "changed":
        next(directory.iterdir()).write_bytes(b"changed signed wheel")
    else:
        candidate = _wheel_bytes("1.2.4", ("packaging>=24", "cryptography==99.0.0"))

    with pytest.raises(deployment.Refusal):
        deployment.admit_offline_wheels(context, candidate, directory)


def _prepare_args(tmp_path: Path, plan: dict[str, Any], native: dict[str, Any], candidate: bytes,
                  archive: bytes, dependency_directory: Path) -> argparse.Namespace:
    """Write the producer's public inputs and return its argument namespace.

    Args:
        tmp_path: Pytest-owned root for producer inputs and output receipts.
        plan: Bound original ISO plan selected by the task owner.
        native: Fresh canonical native admission result.
        candidate: Exact candidate wheel bytes to validate and publish.
        archive: Immutable reviewed Git archive bytes supplied to the builder path.
        dependency_directory: Original ISO-signed runtime wheel inventory.
    """
    output = tmp_path / "producer-output"
    output.mkdir()
    plan_path = tmp_path / "producer-plan.json"
    native_path = tmp_path / "native-admission.json"
    wheel_path = tmp_path / _WHEEL_FILENAME
    archive_path = tmp_path / "reviewed-source.zip"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    native_path.write_text(json.dumps(native), encoding="utf-8")
    wheel_path.write_bytes(candidate)
    archive_path.write_bytes(archive)
    return argparse.Namespace(
        plan=plan_path,
        native_admission=native_path,
        output_root=output,
        source_root=Path(plan["worktree"]),
        wheel=wheel_path,
        source_archive=archive_path,
        runtime_dependency_directory=dependency_directory,
        snapshot_sha256="9" * 64,
        snapshot_file_count=42,
    )


def test_prepare_publishes_bound_build_intent_and_deployer_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Publish the build, immutable deployment intent, and complete deployer request.

    Args:
        tmp_path: Pytest-owned root for producer inputs and output receipts.
        monkeypatch: Replace immutable Git output and bind the task identity.
    """
    plan, native, _context, _iso_path, directory, _inventory, candidate, archive = _producer_fixture(
        tmp_path, monkeypatch,
    )
    args = _prepare_args(tmp_path, plan, native, candidate, archive, directory)

    from scripts.completed_task_files import WindowsFiles

    @contextmanager
    def admit_test_directory(_self: WindowsFiles, _path: Path, *, directory: bool = False):
        """Supply the Win32 identity shape while exercising real producer publishing.

        Args:
            _path: Producer output directory whose platform identity is observed.
            directory: Whether the producer expects a directory identity.
            _self: Windows identity adapter used by the producer.
        """
        assert _path == args.output_root
        assert directory is True
        yield None, (1, 2, 3), None

    # The producer's ownership serialization is portable; its native directory
    # handle is exercised by the separate Windows deployment-output tests.
    monkeypatch.setattr(WindowsFiles, "__init__", lambda _self: None)
    monkeypatch.setattr(WindowsFiles, "opened", admit_test_directory)

    deployment.prepare(args)

    output = args.output_root
    build = bound_json(deployment._reference(output / "build.json"))
    intent = bound_json(deployment._reference(output / "intent.json"))
    request = bound_json(deployment._reference(output / "request.json"))
    assert build["kind"] == "certificate-pr-wheel-build"
    assert build["source_guards_verified"] is True and build["offline_wheels"]
    assert intent["kind"] == "certificate-iso-pr-wheel-deployment-intent"
    assert intent["build_receipt"] == deployment._reference(output / "build.json")
    assert request["kind"] == "certificate-iso-wheel-deployment-request"
    assert request["wheel_sha256"] == hashlib.sha256(candidate).hexdigest()
    assert request["host_address"] == "192.168.77.30"
    assert request["remote_wheel"] == intent["remote_wheel"]
    assert Path(request["remote_directory"]).as_posix().startswith("/var/tmp/atlaso-certificate-deploy-")
    child_args = argparse.Namespace(
        host=request["host_address"], user="admin", remote_dir=request["remote_directory"],
        remote_wheel=request["remote_wheel"], local_wheel=str(args.wheel),
        fixture_source_root=str(args.source_root), trusted_host_key="", reset_vault_entries=False,
        local_helper="", local_console_manager="", local_boot_installer="",
    )
    assert transport.admit_request(output / "request.json", deployment._reference(output / "request.json")["sha256"],
                                   child_args) == request
    assert request["original_inspection"]["source_commit"] == _ORIGINAL_COMMIT
    assert request["source_snapshot_sha256"] == "9" * 64
    assert request["output_root_identity"] == "00000001:0000000200000003"
    assert request["preflight_command"].startswith("/opt/atlaso/.venv/bin/python")


def test_prepare_late_identity_failure_preserves_build_and_intent_without_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Preserve already published intent when native output identity admission fails late.

    Args:
        tmp_path: Pytest-owned root for producer inputs and output receipts.
        monkeypatch: Replace immutable Git output, task identity, and the final identity boundary.
    """
    plan, native, _context, _iso_path, directory, _inventory, candidate, archive = _producer_fixture(
        tmp_path, monkeypatch,
    )
    args = _prepare_args(tmp_path, plan, native, candidate, archive, directory)

    class BrokenWindowsFiles:
        @contextmanager
        def opened(self, _path: Path, *, directory: bool = False):
            """Fail before the request can claim a native output identity.

            Args:
                _path: Producer output directory whose identity cannot be admitted.
                directory: Whether the requested object must be a directory.
            """
            assert directory is True
            raise OSError("synthetic native identity refusal")
            yield None

    monkeypatch.setattr("scripts.completed_task_files.WindowsFiles", BrokenWindowsFiles)
    with pytest.raises(OSError, match="synthetic native identity refusal"):
        deployment.prepare(args)

    assert (args.output_root / "build.json").is_file()
    assert (args.output_root / "intent.json").is_file()
    assert not (args.output_root / "request.json").exists()
    assert not (args.output_root / "deployment.json").exists()


def _finish_files(output: Path, plan: dict[str, Any], context: dict[str, Any],
                  owner_result: dict[str, Any] | None = None) -> None:
    """Create bounded predeployment outputs consumed by the finishing producer.

    Args:
        output: Existing pytest-owned producer output root.
        plan: Bound original ISO plan retained by the task owner.
        context: Freshly admitted original state for this invocation.
        owner_result: Optional retained child result, defaulting to successful quiescence.
    """
    build = {
        "schema": 1, "kind": "certificate-pr-wheel-build", "repository": "mdaneri/Atlaso", "pr": 1118,
        "task_id": "task", "source_commit": _DEPLOYED_COMMIT, "source_guards_verified": True,
        "wheel_sha256": "d" * 64, "wheel_filename": _WHEEL_FILENAME, "wheel_size": 12345,
        "version": "1.2.4", "archive_sha256": _digest(_ARCHIVE),
    }
    publish(output / "build.json", build)
    references = {key: deployment.reference_binding(plan[key]) for key in (
        "appliance_intent", "appliance_ownership", "appliance_installed_boot", "installed_inspection",
    )}
    remote = f"/var/tmp/{_DEPLOYMENT_DIR}/{_WHEEL_FILENAME}"
    intent = {
        "schema": 1, "kind": "certificate-iso-pr-wheel-deployment-intent", "repository": "mdaneri/Atlaso",
        "pr": 1118, "task_id": "task", "source_commit": _DEPLOYED_COMMIT,
        "vmx_path": context["ownership"]["vmx_path"], "mac": _MAC,
        "host_key_sha256": _HOST_KEY, "original_references": references,
        "build_receipt": deployment._reference(output / "build.json"), "remote_wheel": remote,
        "network_inspection": deployment.reference_binding(plan["deployment_network_inspection"]),
        "network_binding": {key: plan["deployment_network_binding"][key] for key in ("subnet", "prefixlen")},
    }
    publish(output / "intent.json", intent)
    publish(output / "native-before.json", context["native"])
    publish(output / "live-inspection.json", {
        "measurement": _measurement(), "assets_report": _assets_report(context["assets"]),
    })
    publish(output / "deployer-exited.json", owner_result or {
        "whole_job_quiescent": True, "exit_code": 0, "source_guards_verified": True,
    })


def test_finish_deployment_publishes_success_only_after_quiescent_readback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Publish a terminal deployment receipt after admitted readback and child quiescence.

    Args:
        tmp_path: Pytest-owned root for source, media, and producer output receipts.
        monkeypatch: Replace immutable Git output and bind the task identity.
    """
    plan, native, context, _iso_path, _directory, _inventory, _candidate, _archive = _producer_fixture(
        tmp_path, monkeypatch,
    )
    output = tmp_path / "finish-output"
    output.mkdir()
    _finish_files(output, plan, context)
    plan_path = tmp_path / "finish-plan.json"
    native_path = tmp_path / "finish-native.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    native_path.write_text(json.dumps(native), encoding="utf-8")

    deployment.finish_deployment(argparse.Namespace(plan=plan_path, native_admission=native_path, output_root=output))

    receipt = bound_json(deployment._reference(output / "deployment.json"))
    assert receipt["status"] == "succeeded" and receipt["whole_job_quiescent"] is True
    assert receipt["original_software_source_commit"] == _ORIGINAL_COMMIT
    assert receipt["deployment_intent"] == deployment._reference(output / "intent.json")
    admitted = deployment.admit_deployment(
        {**plan, "iso_wheel_deployment": deployment._reference(output / "deployment.json")},
        context=context,
    )
    assert admitted is not None and admitted["measurement"] == _measurement()


@pytest.mark.parametrize("owner_result", [
    {"whole_job_quiescent": False, "exit_code": 0, "source_guards_verified": True},
    {"whole_job_quiescent": True, "exit_code": 1, "source_guards_verified": True},
    {"whole_job_quiescent": True, "exit_code": 0, "source_guards_verified": False},
])
def test_finish_deployment_refuses_late_child_failure_without_success_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, owner_result: dict[str, Any],
) -> None:
    """Refuse a child that failed or remained active without publishing a success receipt.

    Args:
        tmp_path: Pytest-owned root for source, media, and producer output receipts.
        monkeypatch: Replace immutable Git output and bind the task identity.
        owner_result: Public retained child result with one failed terminal condition.
    """
    plan, native, context, _iso_path, _directory, _inventory, _candidate, _archive = _producer_fixture(
        tmp_path, monkeypatch,
    )
    output = tmp_path / "finish-output"
    output.mkdir()
    _finish_files(output, plan, context, owner_result)
    plan_path = tmp_path / "finish-plan.json"
    native_path = tmp_path / "finish-native.json"
    plan_path.write_text(json.dumps(plan), encoding="utf-8")
    native_path.write_text(json.dumps(native), encoding="utf-8")

    with pytest.raises(deployment.Refusal, match="iso_deployment_owner_not_quiescent"):
        deployment.finish_deployment(argparse.Namespace(plan=plan_path, native_admission=native_path, output_root=output))

    assert not (output / "deployment.json").exists()
