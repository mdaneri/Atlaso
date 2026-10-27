"""Public, media-bound checks for installed offline ISO content."""

import ast
import base64
import contextlib
import csv
import hashlib
import importlib.util
import io
import json
import os
import re
import shlex
import stat
import sys
import tarfile
import zlib
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from scripts import verify_virtualization_guest_wheel
from scripts.installation import content_inspection


def _inventory(value):
    """Encode a public synthetic inventory in the guest report format.

    Args:
        value: Inventory or manifest value to encode.
    """
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return base64.b64encode(zlib.compress(raw, 9)).decode()


def _expectation(kind):
    """Create a small, well-formed expectation without host or guest state.

    Args:
        kind: Content kind or scenario exercised by the test.
    """
    common = {"schema": 1, "kind": kind, "iso_sha256": "a" * 64}
    extras = {
        "assets": {
            "environment_verifier_sha256": "b" * 64,
            "source_digest": "c" * 64,
            "source_file_count": 3,
            "deployed_file_count": 5,
            "omitted_sources": sorted(content_inspection._VMWARE_SOURCES),
            "trust_names": ["atlaso-release-test.pem"],
            "trust_digest": "d" * 64,
        },
        "python": {
            "software_verifier_sha256": "e" * 64,
            "environment_verifier_sha256": "b" * 64,
            "release_manifest_sha256": "f" * 64,
            "version": "1.2.3",
            "source_commit": "1" * 40,
            "wheel_sha256": "2" * 64,
        },
        "powercli": {
            "powercli_script_sha256": "3" * 64,
            "powercli_lock_sha256": "4" * 64,
            "module_count": 2,
        },
        "rpm": {
            "package_state_sha256": "5" * 64,
            "filesystem_sha256": content_inspection.PHOTON_FILESYSTEM_SHA256,
            "systemd_sha256": content_inspection.PHOTON_SYSTEMD_SHA256,
            "audit_sha256": content_inspection.PHOTON_AUDIT_SHA256,
            "rpcbind_sha256": content_inspection.PHOTON_RPCBIND_SHA256,
            "allowed_inventory": _inventory({
                "linux": ["6.1-1.ph5", "x86_64"],
                "python3": ["3.14-2.ph5", "x86_64"],
                "optional-tool": ["1.0-1.ph5", "noarch"],
                "pip": ["26.2.1-1.ph5", "noarch"],
                "filesystem": ["1.1-11.ph5", "x86_64"],
                "systemd": ["257.13-5.ph5", "x86_64"],
            }),
            "required_packages": _inventory(["linux", "python3"]),
        },
        "notices": {
            "notice_generator_sha256": "6" * 64,
            "notice_config_sha256": "7" * 64,
            "notice_lock_sha256": "8" * 64,
            "version": "1.2.3",
        },
    }
    return {**common, **extras[kind]}


def _report(kind, **changes):
    """Create a passing public synthetic report for one content kind.

    Args:
        kind: Content kind or scenario exercised by the test.
        **changes: Additional keyword arguments passed to the test double.
    """
    values = {
        "assets": {
            "source_digest": "c" * 64,
            "source_file_count": 3,
            "deployed_files": 5,
            "trust_digest": "d" * 64,
            "trust_keys": 1,
        },
        "python": {
            "python_payload_sha256": "9" * 64,
            "python_files": 8,
            "python_distributions": 2,
            "python_external_files": 0,
        },
        "powercli": {"powercli_lock_sha256": "4" * 64, "module_count": 2},
        "rpm": {
            "installed_inventory": _inventory({
                "linux": ["6.1-1.ph5", "x86_64"],
                "python3": ["3.14-2.ph5", "x86_64"],
            }),
            "firmware_verified": True,
            "rpm_files_verified": True,
            "package_state_verified": True,
            "runtime_proc_verified": True,
            "runtime_run_verified": True,
            "runtime_login_metadata_verified": True,
            "runtime_mail_spool_verified": True,
            "runtime_journal_metadata_verified": True,
            "runtime_audit_metadata_verified": True,
            "runtime_rpcbind_metadata_verified": True,
            "runtime_media_directories_absent": 0,
        },
        "notices": {"notices_sha256": "a" * 64, "notice_inputs_verified": True},
    }
    return {
        "schema": 1,
        "kind": kind,
        "iso_sha256": "a" * 64,
        **{**values[kind], **changes},
    }


def _runtime_fixture_helper():
    """Return only declared runtime proof fields for unrelated adapter fixtures."""
    fields = {name: True for name in ("runtime_proc_verified", "runtime_run_verified",
                                      "runtime_login_metadata_verified", "runtime_mail_spool_verified")}
    return SimpleNamespace(__file__="verify-photon-package-state.py",
                           INSTALLATION_FILESYSTEM_SHA256=content_inspection.PHOTON_FILESYSTEM_SHA256,
                           INSTALLATION_SYSTEMD_SHA256=content_inspection.PHOTON_SYSTEMD_SHA256,
                           INSTALLATION_AUDIT_SHA256=content_inspection.PHOTON_AUDIT_SHA256,
                           INSTALLATION_RPCBIND_SHA256=content_inspection.PHOTON_RPCBIND_SHA256,
                           verify_installation_metadata=lambda *_checksums: {**fields, "runtime_journal_metadata_verified": True,
                                                                            "runtime_audit_metadata_verified": True,
                                                                            "runtime_rpcbind_metadata_verified": True})


def _decode_guest_program(command):
    """Decode the bounded source embedded in a generated guest command.

    Args:
        command: Command argument vector passed to the simulated process.
    """
    compressed = re.search(r'(b64|b85)decode\("([^"\r\n]+)"\)', command)
    assert compressed is not None
    return zlib.decompress(getattr(base64, compressed[1] + "decode")(compressed[2])).decode()


def _prepare_fixture():
    """Build a minimal manifest whose source bytes are all independently bound."""
    provision = b'run_tdnf "Build-only package removal" --noautoremove remove linux-firmware\n'
    lock = json.dumps({"schema_version": 2, "modules": {"VMware.PowerCLI": "13.3.0"}}).encode()
    sources = {
        "source/image/common/scripts/provision-atlaso.sh": provision,
        "source/scripts/verify_virtualization_guest_wheel.py": Path(
            verify_virtualization_guest_wheel.__file__
        ).read_bytes(),
        "source/image/common/powershell/powercli-lock.json": lock,
        "source/image/common/scripts/verify-photon-package-state.py": Path("image/common/scripts/verify-photon-package-state.py").read_bytes(),
    }
    all_files = {
        **sources,
        "source/image/common/powershell/provision-powercli.ps1": b"# PowerCLI validation fixture\n",
        "source/scripts/generate_third_party_notices.py": b"# Notice generator fixture\n",
        "source/scripts/third_party_notices.json": b"{}\n",
        "source/requirements-appliance.lock": b"# Public lock fixture\n",
        "software/requirements-appliance.lock": b"# Authenticated software dependency lock\n",
        "source/image/common/update-trust/atlaso-release-test.pem": b"public test key\n",
        "source/scripts/example.py": b"print('installed')\n",
        "rpms/linux.rpm": b"public RPM fixture A",
        "rpms/python3.rpm": b"public RPM fixture B",
    }
    records = [
        {"path": name, "sha256": hashlib.sha256(data).hexdigest()}
        for name, data in all_files.items()
    ]
    rpms = [
        {
            "file": f"{name}.rpm",
            "name": name,
            "version": version,
            "architecture": "x86_64",
            "sha256": hashlib.sha256(all_files[f"rpms/{name}.rpm"]).hexdigest(),
        }
        for name, version in (("linux", "6.1-1.ph5"), ("python3", "3.14-2.ph5"))
    ]
    # The admitted binary is represented only by its public digest in this
    # manifest fixture; prepare_content_inputs never reads RPM payload bytes.
    records.append({"path": "rpms/filesystem.rpm", "sha256": content_inspection.PHOTON_FILESYSTEM_SHA256})
    rpms.append({"file": "filesystem.rpm", "name": "filesystem", "version": "1.1-11.ph5", "architecture": "x86_64",
                 "sha256": content_inspection.PHOTON_FILESYSTEM_SHA256})
    records.append({"path": "rpms/systemd.rpm", "sha256": content_inspection.PHOTON_SYSTEMD_SHA256})
    rpms.append({"file": "systemd.rpm", "name": "systemd", "version": "257.13-5.ph5", "architecture": "x86_64",
                 "sha256": content_inspection.PHOTON_SYSTEMD_SHA256})
    records.append({"path": "rpms/audit.rpm", "sha256": content_inspection.PHOTON_AUDIT_SHA256})
    rpms.append({"file": "audit.rpm", "name": "audit", "version": "4.1.3-3.ph5", "architecture": "x86_64",
                 "sha256": content_inspection.PHOTON_AUDIT_SHA256})
    records.append({"path": "rpms/rpcbind.rpm", "sha256": content_inspection.PHOTON_RPCBIND_SHA256})
    rpms.append({"file": "rpcbind.rpm", "name": "rpcbind", "version": "1.2.6-6.ph5", "architecture": "x86_64",
                 "sha256": content_inspection.PHOTON_RPCBIND_SHA256})
    manifest = {
        "files": records,
        "packages": ["linux", "linux-firmware", "python3"],
        "rpm_inventory": rpms,
    }
    base = {
        "iso_sha256": "a" * 64,
        "release_manifest_sha256": "f" * 64,
        "version": "1.2.3",
        "source_commit": "1" * 40,
        "wheel_sha256": "2" * 64,
        "software_verifier_sha256": "e" * 64,
    }
    return base, manifest, sources


def _write_synthetic_wheel(path, members):
    """Write a tiny wheel with a real RECORD for the shared verifier.

    Args:
        path: Filesystem path used by the isolated fixture.
        members: Wheel member paths and bytes to write.
    """
    rows = []
    for name, content in members.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).decode().rstrip("=")
        rows.append((name, f"sha256={digest}", str(len(content))))
    dist_info = next(name.rsplit("/", 1)[0] for name in members if name.endswith(".dist-info/METADATA"))
    rows.append((f"{dist_info}/RECORD", "", ""))
    output = io.StringIO(newline="")
    csv.writer(output, lineterminator="\n").writerows(rows)
    with ZipFile(path, "w", ZIP_DEFLATED) as archive:
        for name, content in members.items():
            archive.writestr(name, content)
        archive.writestr(f"{dist_info}/RECORD", output.getvalue())


def _site_archive(path, records, wheel_members, *, corrupt=False, extra=False):
    """Archive the signed wheel members as installed site-packages files.

    Args:
        path: Filesystem path used by the isolated fixture.
        records: Source-bound installed file records.
        wheel_members: Wheel member paths and bytes for the archive.
        corrupt: Whether to alter a recorded file hash.
        extra: Whether to add an unrecorded installed file.
    """
    with tarfile.open(path, "w") as archive:
        emitted = 0
        for members in wheel_members:
            for name, content in members.items():
                if name not in records:
                    continue
                if corrupt and emitted == 0:
                    content += b"tampered"
                info = tarfile.TarInfo(name)
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
                emitted += 1
        if extra:
            content = b"unexpected"
            info = tarfile.TarInfo("rogue.py")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))


def test_shared_python_payload_verifier_accepts_exact_wheels_and_rejects_drift(tmp_path):
    """Exercise the real RECORD comparator used by installed Python inspection.

    Args:
        tmp_path: Pytest temporary directory for isolated filesystem fixtures.
    """
    app_members = {
        "atlaso/__init__.py": b"VERSION = '1.2.3'\n",
        "atlaso-1.2.3.dist-info/METADATA": b"Name: atlaso\nVersion: 1.2.3\n",
    }
    dependency_members = {
        "sampledep-1.0.dist-info/METADATA": b"Name: sampledep\nVersion: 1.0\n",
    }
    app_wheel = tmp_path / "atlaso-1.2.3-py3-none-any.whl"
    dependency_wheel = tmp_path / "sampledep-1.0-py3-none-any.whl"
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    _write_synthetic_wheel(app_wheel, app_members)
    _write_synthetic_wheel(wheelhouse / dependency_wheel.name, dependency_members)

    records, distributions = verify_virtualization_guest_wheel._expected_environment(
        app_wheel, wheelhouse, hashlib.sha256(app_wheel.read_bytes()).hexdigest()
    )
    exact = tmp_path / "exact.tar"
    _site_archive(exact, records, [app_members, dependency_members])
    verify_virtualization_guest_wheel._verify_site_packages_archive(exact, records, distributions)

    corrupt = tmp_path / "corrupt.tar"
    _site_archive(corrupt, records, [app_members, dependency_members], corrupt=True)
    with pytest.raises(SystemExit, match="does not match"):
        verify_virtualization_guest_wheel._verify_site_packages_archive(corrupt, records, distributions)

    extra = tmp_path / "extra.tar"
    _site_archive(extra, records, [app_members, dependency_members], extra=True)
    with pytest.raises(SystemExit, match="unexpected file"):
        verify_virtualization_guest_wheel._verify_site_packages_archive(extra, records, distributions)


def test_prepare_content_inputs_binds_expectations_to_admitted_files():
    """Derive package closure and source digests from manifest-admitted bytes."""
    base, manifest, sources = _prepare_fixture()

    expectations = content_inspection.prepare_content_inputs(base, manifest, sources)

    assert [item["kind"] for item in expectations] == list(content_inspection.KINDS)
    rpm = expectations[3]
    assert json.loads(zlib.decompress(base64.b64decode(rpm["required_packages"]))) == [
        "linux",
        "python3",
    ]
    allowed = json.loads(zlib.decompress(base64.b64decode(rpm["allowed_inventory"])))
    assert allowed == {
        "audit": ["4.1.3-3.ph5", "x86_64"],
        "filesystem": ["1.1-11.ph5", "x86_64"],
        "linux": ["6.1-1.ph5", "x86_64"],
        "python3": ["3.14-2.ph5", "x86_64"],
        "rpcbind": ["1.2.6-6.ph5", "x86_64"],
        "systemd": ["257.13-5.ph5", "x86_64"],
    }
    assert expectations[0]["source_file_count"] == 10
    assert expectations[4]["notice_lock_sha256"] == hashlib.sha256(
        b"# Authenticated software dependency lock\n"
    ).hexdigest()
    assert expectations[2]["powercli_lock_sha256"] == hashlib.sha256(
        sources["source/image/common/powershell/powercli-lock.json"]
    ).hexdigest()


def test_notices_refuse_missing_release_lock():
    """Do not replace a missing signed software lock with the checkout lock."""
    base, manifest, sources = _prepare_fixture()
    manifest["files"] = [item for item in manifest["files"] if item["path"] != "software/requirements-appliance.lock"]
    with pytest.raises(ValueError, match="admitted signed software lock"):
        content_inspection.prepare_content_inputs(base, manifest, sources)


@pytest.mark.parametrize("defect", [None, "changed", "missing"])
def test_notice_lock_authentication(tmp_path, defect):
    """Use only the media-bound software lock before reading installed inventories.

    Args:
        tmp_path: Isolated symbolic source and software paths.
        defect: Missing or altered software lock to reject.
    """
    raw = b"authlib==1.8.0\n"
    expected = _expectation("notices")
    expected["notice_lock_sha256"] = hashlib.sha256(raw).hexdigest()
    software = tmp_path / "software"
    generated = ast.parse(_decode_guest_program(content_inspection.guest_content_program(
        expected, atlaso_root=tmp_path / "source", software_root=software,
    )))
    outer = next(node for node in generated.body if isinstance(node, ast.Try))
    outer.body = [node for node in outer.body if not isinstance(node, ast.FunctionDef)
                  or node.name not in {"checked", "read", "run"}]
    reads, commands = [], []

    def read(path, _maximum):
        """Expose only the selected release lock, never the checkout lock.

        Args:
            path: Requested dependency lock path.
            _maximum: Read limit passed by the adapter.
        """
        assert path == software / "requirements-appliance.lock"
        reads.append(path)
        if defect == "missing":
            raise FileNotFoundError("private missing lock details")
        return b"private changed lock bytes" if defect else raw

    def run(arguments):
        """Stop at the inventory boundary after successful lock authentication.

        Args:
            arguments: Inventory command selected by the adapter.
        """
        commands.append(arguments)
        raise ValueError("private inventory boundary")

    namespace = {"read": read, "run": run, "checked": lambda path, _key: (Path(path), b"admitted")}
    with contextlib.redirect_stdout(io.StringIO()) as output:
        exec(compile(ast.Module(body=[outer], type_ignores=[]), "<notice-lock-fixture>", "exec"), namespace)
    stage = "inputs" if defect else "inventory"
    assert output.getvalue() == f"ATLASO-INSPECTION-FAILED:system-notices-{stage}\n"
    assert reads == [software / "requirements-appliance.lock"]
    assert len(commands) == (0 if defect else 1)


@pytest.mark.parametrize("tamper", ["source-bytes", "file-hash"])
def test_prepare_content_inputs_rejects_source_not_bound_to_manifest(tamper):
    """A claimed shared source cannot drift from the admitted ISO inventory.

    Args:
        tamper: Source mutation used to test rejection.
    """
    base, manifest, sources = _prepare_fixture()
    if tamper == "source-bytes":
        sources["source/image/common/scripts/provision-atlaso.sh"] += b"# changed\n"
    else:
        manifest["files"][0]["sha256"] = "0" * 64

    with pytest.raises(ValueError, match="source differs"):
        content_inspection.prepare_content_inputs(base, manifest, sources)


@pytest.mark.parametrize("package", ["filesystem", "systemd", "audit", "rpcbind"])
def test_prepare_content_inputs_refuses_unreviewed_runtime_profile(package):
    """A different authenticated RPM cannot inherit the known mutable profile.

    Args:
        package: Package whose native runtime metadata profile is changed.
    """
    base, manifest, sources = _prepare_fixture()
    next(item for item in manifest["files"] if item["path"] == f"rpms/{package}.rpm")["sha256"] = "0" * 64
    next(item for item in manifest["rpm_inventory"] if item["name"] == package)["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="reviewed runtime metadata profile"):
        content_inspection.prepare_content_inputs(base, manifest, sources)


@pytest.mark.parametrize("package", ["filesystem", "systemd", "audit", "rpcbind"])
def test_guest_program_refuses_unreviewed_runtime_profile(package):
    """Unknown runtime profiles stop preparation before any guest command exists.

    Args:
        package: Package whose native runtime metadata profile is changed.
    """
    expected = _expectation("rpm")
    expected[f"{package}_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="runtime metadata profile is not admitted"):
        content_inspection.guest_content_program(expected)


def test_rpm_guest_loader_admits_only_original_helper_bytes(monkeypatch, tmp_path):
    """Execute the real generated loader, including imports and byte admission.

    Args:
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        tmp_path: Pytest temporary directory for isolated filesystem fixtures.
    """
    root = tmp_path / "atlaso"
    member = "image/common/scripts/verify-photon-package-state.py"
    helper = root / member
    helper.parent.mkdir(parents=True)
    original = b"def public_fixture():\n return 'verified'\n"
    helper.write_bytes(original)
    expected = _expectation("rpm")
    expected["package_state_sha256"] = hashlib.sha256(original).hexdigest()
    # Keep the real loader test independent of the host's temporary path length;
    # the live command uses the short fixed /opt/atlaso path and its normal bound.
    monkeypatch.chdir(tmp_path)
    command = content_inspection.guest_content_program(expected, atlaso_root=Path("atlaso"))
    outer = ast.parse(_decode_guest_program(command)).body[0]
    start = next(i for i, node in enumerate(outer.body)
                 if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
                 and node.value.value == "system-rpm-helper")
    namespace = {}
    monkeypatch.setattr(os, "O_NOFOLLOW", getattr(os, "O_NOFOLLOW", 0), raising=False)
    exec(compile(ast.Module(body=outer.body[:start], type_ignores=[]), "<real-rpm-loader>", "exec"), namespace)
    admitted = namespace["load"](member, "package_state_sha256", "_public_fixture")
    assert admitted.public_fixture() == "verified"
    helper.write_bytes(b"raise AssertionError('changed helper must not execute')\n")
    with pytest.raises(ValueError):
        namespace["load"](member, "package_state_sha256", "_changed_fixture")


def test_prepare_content_inputs_requires_original_shared_photon_contract():
    """Even admitted media must provide the helper contract used by the adapter."""
    base, manifest, sources = _prepare_fixture()
    member = content_inspection.SOURCE_MEMBERS[3]
    sources[member] += b"\n# different public helper contract\n"
    next(item for item in manifest["files"] if item["path"] == member)["sha256"] = hashlib.sha256(sources[member]).hexdigest()
    with pytest.raises(ValueError, match="original shared Photon runtime contract"):
        content_inspection.prepare_content_inputs(base, manifest, sources)


@pytest.mark.parametrize("kind", content_inspection.KINDS)
def test_validate_content_report_accepts_only_expected_public_measurements(kind):
    """Valid reports retain their exact media identity and expected fields.

    Args:
        kind: Content kind or scenario exercised by the test.
    """
    expected = _expectation(kind)

    result = content_inspection.validate_content_report(
        json.dumps(_report(kind), separators=(",", ":")).encode(), expected
    )

    assert result["kind"] == kind
    assert result["iso_sha256"] == expected["iso_sha256"]
    assert "installed_inventory" not in result
    if kind == "rpm":
        assert result["installed_rpms"] == 2
        assert len(result["rpm_inventory_sha256"]) == 64


@pytest.mark.parametrize("kind", content_inspection.KINDS)
@pytest.mark.parametrize("defect", ["extra-field", "wrong-media", "wrong-schema", "bool-schema"])
def test_validate_content_report_rejects_unbound_or_unknown_fields(kind, defect):
    """Reports fail closed on schema extensions and identity mismatches.

    Args:
        kind: Content kind or scenario exercised by the test.
        defect: Report defect to introduce.
    """
    value = _report(kind)
    if defect == "extra-field":
        value["private_path"] = "/guest/path"
    elif defect == "wrong-media":
        value["iso_sha256"] = "b" * 64
    elif defect == "wrong-schema":
        value["schema"] = 2
    else:
        value["schema"] = True

    with pytest.raises(ValueError):
        content_inspection.validate_content_report(
            json.dumps(value, separators=(",", ":")).encode(), _expectation(kind)
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"firmware_verified": False},
        {"rpm_files_verified": False},
        {"package_state_verified": False},
        {"runtime_proc_verified": False},
        {"runtime_run_verified": False},
        {"runtime_login_metadata_verified": False},
        {"runtime_mail_spool_verified": False},
        {"runtime_journal_metadata_verified": False},
        {"runtime_audit_metadata_verified": False},
        {"runtime_rpcbind_metadata_verified": False},
        {"runtime_media_directories_absent": True},
        {"runtime_media_directories_absent": 3},
        {"installed_inventory": _inventory({"linux": ["wrong", "x86_64"], "python3": ["3.14-2.ph5", "x86_64"]})},
        {"installed_inventory": _inventory({"linux": ["6.1-1.ph5", "aarch64"], "python3": ["3.14-2.ph5", "x86_64"]})},
        {"installed_inventory": _inventory({"linux": "6.1-1.ph5", "python3": ["3.14-2.ph5", "x86_64"]})},
        {"installed_inventory": _inventory({"linux": ["6.1-1.ph5", "x86_64"], "python3": ["3.14-2.ph5", "x86_64"], "rogue": ["1.0", "noarch"]})},
        {"installed_inventory": _inventory({"linux": ["6.1-1.ph5", "x86_64"]})},
    ],
    ids=["firmware", "rpm-files", "package-state", "runtime-proc", "runtime-run", "runtime-login-metadata", "runtime-mail-spool", "runtime-journal-metadata", "runtime-audit-metadata", "runtime-rpcbind-metadata", "boolean-missing-directories", "too-many-missing-directories", "changed-identity", "wrong-architecture", "malformed-identity", "extra-package", "missing-package"],
)
def test_validate_content_report_rejects_unverified_rpm_closure(changes):
    """The installed RPM identities must satisfy the signed allowed closure.

    Args:
        changes: Values that intentionally alter the report or fixture.
    """
    with pytest.raises(ValueError):
        content_inspection.validate_content_report(
            json.dumps(_report("rpm", **changes), separators=(",", ":")).encode(),
            _expectation("rpm"),
        )


@pytest.mark.parametrize(
    ("kind", "changes"),
    [
        ("assets", {"source_file_count": True}),
        ("assets", {"deployed_files": 4}),
        ("assets", {"deployed_files": 0}),
        ("assets", {"trust_keys": 100001}),
        ("python", {"python_files": False}),
        ("powercli", {"module_count": 0}),
        ("notices", {"notice_inputs_verified": False}),
        ("python", {"python_payload_sha256": "z" * 64}),
    ],
    ids=["bool-count", "wrong-deployed-count", "zero-count", "large-count", "python-bool", "module-count", "notices-failed", "bad-digest"],
)
def test_validate_content_report_rejects_failed_or_malformed_checks(kind, changes):
    """Booleans cannot masquerade as counts, and check failures stay failures.

    Args:
        kind: Content kind or scenario exercised by the test.
        changes: Values that intentionally alter the report or fixture.
    """
    with pytest.raises(ValueError):
        content_inspection.validate_content_report(
            json.dumps(_report(kind, **changes), separators=(",", ":")).encode(),
            _expectation(kind),
        )


@pytest.mark.parametrize("kind", content_inspection.KINDS)
def test_guest_content_program_uses_bounded_ascii_console_command(kind, tmp_path):
    """Generated console payload uses injectable fixture paths and a hard size cap.

    Args:
        kind: Content kind or scenario exercised by the test.
        tmp_path: Pytest temporary directory for isolated filesystem fixtures.
    """
    atlaso = Path("atlaso") if kind == "rpm" else tmp_path / "atlaso"
    software = tmp_path / "software"
    temporary = tmp_path / "runtime"
    site = tmp_path / "site-packages"
    command = content_inspection.guest_content_program(
        _expectation(kind),
        atlaso_root=atlaso,
        software_root=software,
        temporary_root=temporary,
        site_root=site,
    )

    assert command.isascii()
    assert len(command) <= 3500
    assert "/opt/atlaso/.venv/bin/python -B -I -c 'exec(" in command
    program = _decode_guest_program(command)
    argv = shlex.split(command)
    assert argv[:4] == ["/opt/atlaso/.venv/bin/python", "-B", "-I", "-c"]
    assert len(argv) == 5
    decoded = []
    # Execute only the transport wrapper; capture its inner exec argument so
    # no guest program or filesystem access runs on the host.
    exec(compile(argv[4], "<quoted-console-transport>", "exec"), {"exec": decoded.append})
    assert decoded == [program.encode()]
    assert repr(str(atlaso)) in program
    if kind != "rpm":
        assert repr(str(software)) in program
        assert repr(str(temporary)) in program
    if kind == "python":
        assert repr(str(site)) in program
    if kind == "rpm":
        for package in ("FILESYSTEM", "SYSTEMD", "AUDIT", "RPCBIND"):
            assert f"h.INSTALLATION_{package}_SHA256" in program
            assert f"e[\"{package.lower()}_sha256\"]" not in program
        constants = [
            node.value
            for node in ast.walk(ast.parse(program))
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        ]
        assert "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n" in constants
        assert "\t" in constants


@pytest.mark.parametrize(
    ("kind", "first_path"),
    [
        ("assets", Path("/etc/atlaso/installation-profile")),
        ("python", Path("/fixture/atlaso/image/common/scripts/verify-template-software.py")),
        ("powercli", Path("/fixture/atlaso/image/common/powershell/provision-powercli.ps1")),
        ("rpm", Path("/fixture/atlaso/image/common/scripts/verify-photon-package-state.py")),
        ("notices", Path("/fixture/atlaso/scripts/generate_third_party_notices.py")),
    ],
)
def test_guest_program_bootstraps_and_reaches_first_read(kind, first_path, monkeypatch, tmp_path):
    """Run generated source only until an intercepted first guest file read.

    Args:
        kind: Content kind or scenario exercised by the test.
        first_path: Expected path of the first attempted guest read.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        tmp_path: Pytest temporary directory for isolated filesystem fixtures.
    """
    command = content_inspection.guest_content_program(
        _expectation(kind),
        atlaso_root="/fixture/atlaso",
        software_root=tmp_path / "software",
        temporary_root=tmp_path / "runtime",
        site_root=tmp_path / "site-packages",
    )
    program = _decode_guest_program(command)
    observed = []

    def stop_before_read(path, *_args, **_kwargs):
        """Record the intended file and stop before touching the filesystem.

        Args:
            path: Filesystem path used by the isolated fixture.
            *_args: Additional positional arguments passed to the test double.
            **_kwargs: Additional keyword arguments passed to the test double.
        """
        observed.append(Path(path))
        raise OSError("synthetic boundary: no guest filesystem access")

    output = io.StringIO()
    monkeypatch.setattr(os, "O_NOFOLLOW", 0, raising=False)
    monkeypatch.setattr(os, "open", stop_before_read)
    with contextlib.redirect_stdout(output):
        exec(program, {})

    assert observed == [first_path]
    marker = {
        "assets": "system-assets-profile",
        "python": "system-python-helpers",
        "rpm": "system-rpm-helper",
        "notices": "system-notices-inputs",
    }.get(kind, f"system-{kind}")
    assert output.getvalue().splitlines() == [f"ATLASO-INSPECTION-FAILED:{marker}"]


@pytest.mark.parametrize(
    ("failure_phase", "expected_stage"),
    [
        ("helper", "system-rpm-helper"),
        ("package-state", "system-rpm-package-state"),
        ("inventory", "system-rpm-inventory"),
        ("files", "system-rpm-files"),
        ("firmware", "system-rpm-firmware"),
    ],
)
def test_generated_rpm_program_reports_only_fixed_phase_on_failure(
    failure_phase, expected_stage, capsys, tmp_path
):
    """Run the actual generated RPM AST with safe failing command stubs.

    Args:
        failure_phase: Command phase where the test injects a failure.
        expected_stage: Expected fixed public diagnostic stage.
        capsys: Pytest fixture for capturing public output.
        tmp_path: Pytest temporary directory for isolated filesystem fixtures.
    """
    command = content_inspection.guest_content_program(
        _expectation("rpm"),
        atlaso_root=Path("atlaso"),
        software_root=tmp_path / "software",
        temporary_root=tmp_path / "runtime",
    )
    generated = ast.parse(_decode_guest_program(command))
    outer = next(node for node in generated.body if isinstance(node, ast.Try))
    outer.body = [
        node
        for node in outer.body
        if not isinstance(node, ast.FunctionDef) or node.name not in {"checked", "run", "load"}
    ]
    sentinel = "private-rpm-diagnostic-sentinel"

    def checked(path, _key):
        """Admit only the checked helper bytes before the generated command runs.

        Args:
            path: Filesystem path used by the isolated fixture.
            _key: Expected source key used for helper admission.
        """
        if failure_phase == "helper":
            raise SystemExit(sentinel)
        return Path(path), b"verified public helper bytes"

    def run(arguments, _timeout=60):
        """Return synthetic command output or inject the selected failure.

        Args:
            arguments: Command argument vector supplied to the stub.
            _timeout: Timeout passed to the command stub.
        """
        command_parts = [str(part) for part in arguments]
        if failure_phase == "package-state" and any(Path(part).name == "verify-photon-package-state.py" for part in command_parts):
            raise SystemExit(sentinel)
        if failure_phase == "inventory" and "-qa" in command_parts:
            raise SystemExit(sentinel)
        if failure_phase == "files" and "-Va" in command_parts:
            raise SystemExit(sentinel)
        if failure_phase == "firmware" and "linux-firmware" in command_parts:
            raise SystemExit(sentinel)
        if "-qa" in command_parts:
            return b"example\t1-1\tx86_64\n"
        return b""

    def load(path, key, _name):
        """Preserve the real loader's checksum admission in the phase fixture.

        Args:
            path: Helper source path passed to the loader.
            key: Expected digest key passed to the loader.
            _name: Private module name supplied by the generated command.
        """
        checked(path, key)
        return _runtime_fixture_helper()

    namespace = {"checked": checked, "run": run, "load": load}
    isolated = ast.Module(body=[outer], type_ignores=[])
    with contextlib.redirect_stdout(io.StringIO()) as output:
        exec(compile(isolated, "<generated-rpm-program>", "exec"), namespace)

    assert output.getvalue().splitlines() == [
        f"ATLASO-INSPECTION-FAILED:{expected_stage}"
    ]
    captured = capsys.readouterr()
    assert sentinel not in captured.out
    assert sentinel not in captured.err


@pytest.mark.parametrize(
    ("owner_output", "owner_name", "verify_path", "metadata_mode", "expected_stage"),
    [
        (
            b"pip\n",
            "pip",
            "/usr/lib/python3.14/site-packages/pip/_internal/commands/list.py",
            None,
            "system-rpm-files-package-" + hashlib.sha256(b"pip").hexdigest(),
        ),
        (
            b"private-unknown-package\n",
            "private-unknown-package",
            "/var/lib/private/service.db",
            None,
            "system-rpm-files-package-"
            + hashlib.sha256(b"private-unknown-package").hexdigest(),
        ),
        (b"", "", "/var/lib/private/service.db", None, "system-rpm-files"),
        (
            b"private invalid owner\n",
            "private invalid owner",
            "/var/lib/private/service.db",
            None,
            "system-rpm-files",
        ),
        (
            b"filesystem\n",
            "filesystem",
            "/root",
            stat.S_IFDIR | 0o700,
            "system-rpm-files-package-"
            + hashlib.sha256(b"filesystem").hexdigest()
            + f"-entry{content_inspection.RPM_DIAGNOSTIC_PATHS.index('/root')}-d0700-v.......T.",
        ),
        (
            b"filesystem\n",
            "filesystem",
            "/usr/local/share/man/man8",
            -1,
            "system-rpm-files-package-"
            + hashlib.sha256(b"filesystem").hexdigest()
            + f"-entry{content_inspection.RPM_DIAGNOSTIC_PATHS.index('/usr/local/share/man/man8')}-missing-v.......T.",
        ),
        (
            b"systemd\n",
            "systemd",
            "/var/log/journal",
            stat.S_IFDIR | 0o2755,
            "system-rpm-files-package-"
            + hashlib.sha256(b"systemd").hexdigest()
            + f"-entry{content_inspection.RPM_DIAGNOSTIC_PATHS.index('/var/log/journal')}-d2755-v.......T.",
        ),
        (
            b"systemd\n",
            "systemd",
            "/var/log/journal/remote",
            stat.S_IFDIR | 0o2755,
            "system-rpm-files-package-"
            + hashlib.sha256(b"systemd").hexdigest()
            + f"-entry{content_inspection.RPM_DIAGNOSTIC_PATHS.index('/var/log/journal/remote')}-d2755-v.......T.",
        ),
        (
            b"audit\n",
            "audit",
            "/var/log/audit",
            stat.S_IFDIR | 0o700,
            "system-rpm-files-package-"
            + hashlib.sha256(b"audit").hexdigest()
            + f"-entry{content_inspection.RPM_DIAGNOSTIC_PATHS.index('/var/log/audit')}-d0700-v.......T.",
        ),
        (
            b"audit\n",
            "audit",
            "/var/log/audit/private-record.log",
            None,
            "system-rpm-files-package-" + hashlib.sha256(b"audit").hexdigest(),
        ),
        (
            b"rpcbind\n",
            "rpcbind",
            "/var/lib/rpcbind",
            stat.S_IFDIR | 0o755,
            "system-rpm-files-package-"
            + hashlib.sha256(b"rpcbind").hexdigest()
            + f"-entry{content_inspection.RPM_DIAGNOSTIC_PATHS.index('/var/lib/rpcbind')}-d0755-v.......T.",
        ),
        (
            b"rpcbind\n",
            "rpcbind",
            "/var/lib/rpcbind/private-state",
            None,
            "system-rpm-files-package-" + hashlib.sha256(b"rpcbind").hexdigest(),
        ),
    ],
    ids=["known-owner-candidate", "unknown-owner-candidate", "empty-owner", "invalid-owner", "fixed-root-metadata", "fixed-missing-entry", "journal-metadata", "remote-journal-metadata", "audit-directory-metadata", "private-audit-file", "rpcbind-directory-metadata", "private-rpcbind-file"],
)
def test_generated_rpm_file_diagnostic_keeps_owner_candidates_private(
    owner_output, owner_name, verify_path, metadata_mode, expected_stage,
    capsys, monkeypatch, tmp_path
):
    """Private diagnostics fingerprint valid owner names without exposing them.

    Args:
        owner_output: Stubbed RPM owner-query output.
        owner_name: Package owner identity returned by the stub.
        verify_path: Verifier path used to trigger diagnostics.
        metadata_mode: Mode bits returned by the isolated metadata probe.
        expected_stage: Expected fixed public diagnostic stage.
        capsys: Pytest fixture for capturing public output.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
        tmp_path: Pytest temporary directory for isolated filesystem fixtures.
    """
    command = content_inspection.guest_content_program(
        _expectation("rpm"),
        atlaso_root=Path("atlaso"),
        software_root=tmp_path / "software",
        temporary_root=tmp_path / "runtime",
    )
    generated = ast.parse(_decode_guest_program(command))
    outer = next(node for node in generated.body if isinstance(node, ast.Try))
    outer.body = [
        node
        for node in outer.body
        if not isinstance(node, ast.FunctionDef) or node.name not in {"checked", "run", "load"}
    ]
    sentinel = b"private-rpm-file-path-and-stderr-sentinel"
    verify_output = f".......T. {verify_path}\n".encode()
    lstat_calls = []
    namespace = {}

    def safe_lstat(path):
        """Expose metadata only for the expected public diagnostic path.

        Args:
            path: Filesystem path used by the isolated fixture.
        """
        name = Path(path).as_posix()
        lstat_calls.append(name)
        if name == verify_path and metadata_mode is not None:
            if metadata_mode == -1:
                raise FileNotFoundError()
            return SimpleNamespace(st_mode=metadata_mode)
        raise AssertionError("diagnostic attempted metadata access outside its fixed path")

    monkeypatch.setattr(Path, "lstat", safe_lstat)

    def checked(path, _key):
        """Admit the fixture helper without reading its host path.

        Args:
            path: Filesystem path used by the isolated fixture.
            _key: Expected source key used for helper admission.
        """
        return Path(path), b"verified public helper bytes"

    def run(arguments, _timeout=60):
        """Return synthetic RPM output or inject the selected failure.

        Args:
            arguments: Command argument vector supplied to the stub.
            _timeout: Timeout passed to the command stub.
        """
        command_parts = [str(part) for part in arguments]
        if "-Va" in command_parts:
            result = SimpleNamespace(
                stdout=verify_output,
                stderr=sentinel,
                returncode=1,
            )
            raise namespace["PrivateCommandFailure"](result)
        if "-qf" in command_parts:
            return owner_output
        if "-qa" in command_parts:
            return b"example\t1-1\tx86_64\n"
        return b""

    namespace.update(checked=checked, run=run, load=lambda *_args: _runtime_fixture_helper())
    isolated = ast.Module(body=[outer], type_ignores=[])
    with contextlib.redirect_stdout(io.StringIO()) as output:
        exec(compile(isolated, "<generated-rpm-file-diagnostic>", "exec"), namespace)

    assert output.getvalue().splitlines() == [
        f"ATLASO-INSPECTION-FAILED:{expected_stage}"
    ]
    assert sentinel.decode() not in output.getvalue()
    assert verify_output.decode() not in output.getvalue()
    if owner_name:
        assert owner_name not in output.getvalue()
    assert verify_path not in output.getvalue()
    assert lstat_calls == ([verify_path] if metadata_mode is not None else [])
    captured = capsys.readouterr()
    assert sentinel.decode() not in captured.out
    assert sentinel.decode() not in captured.err


@pytest.mark.parametrize(
    ("rows", "returncode", "stderr", "mount", "mode", "uid", "gid", "failure"),
    [
        ("......G.. /var/lib/rpcbind\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, None),
        ("......G.. /var/lib/rpcbind\n", 1, b"", "rpcrace", stat.S_IFDIR | 0o555, 0, 0, "runtime"),
        (".M....G.. /var/lib/rpcbind\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, "files"),
        (".....UG.. /var/lib/rpcbind\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, "files"),
        ("..5...G.. /var/lib/rpcbind\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, "files"),
        ("missing /var/lib/rpcbind\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, "files"),
        ("......G.. /var/lib/rpcbind/private-state\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, "files"),
        (".M....... /proc\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, None),
        (".M....... /var/log/audit\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, None),
        (".M....... /var/log/audit\n", 1, b"", "auditrace", stat.S_IFDIR | 0o555, 0, 0, "runtime"),
        (".M5...... /var/log/audit\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, "files"),
        (".M...U... /var/log/audit\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, "files"),
        (".M....G.. /var/log/audit\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, "files"),
        ("missing /var/log/audit\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, "files"),
        (".M....G.. /var/log/journal\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, None),
        (".M....... /var/log/journal\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, None),
        ("......G.. /var/log/journal\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, None),
        (".M....G.. /var/log/journal\n", 1, b"", "journalrace", stat.S_IFDIR | 0o555, 0, 0, "runtime"),
        (".M5...G.. /var/log/journal\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, "files"),
        (".M...UG.. /var/log/journal\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, "files"),
        (".M....G.. /var/log/journal/remote\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, "files"),
        ("missing /var/log/journal\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, "files"),
        (".M....G.. /var/log/journal\n", 1, b"private-error", "proc", stat.S_IFDIR | 0o555, 0, 0, "files"),
        ("", 0, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, None),
        ("SM5...GT. /var/log/btmp\nSM5...GT. /var/log/wtmp\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, None),
        ("SM5..UGT. /var/log/btmp\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, "files"),
        ("SM5...GTP /var/log/btmp\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, "files"),
        ("SM5...GT. /var/log/private-fixture\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, "files"),
        ("missing /var/log/btmp\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, "files"),
        ("SM5...GT. /var/log/btmp\n", 1, b"", "logmode", stat.S_IFDIR | 0o555, 0, 0, "runtime"),
        ("SM5...GT. /var/log/btmp\n", 1, b"", "loguid", stat.S_IFDIR | 0o555, 0, 0, "runtime"),
        ("SM5...GT. /var/log/btmp\n", 1, b"", "loggid", stat.S_IFDIR | 0o555, 0, 0, "runtime"),
        ("SM5...GT. /var/log/btmp\n", 1, b"", "loglink", stat.S_IFDIR | 0o555, 0, 0, "runtime"),
        ("SM5...GT. /var/log/btmp\n", 1, b"", "logsymlink", stat.S_IFDIR | 0o555, 0, 0, "runtime"),
        ("", 0, b"", "lograce", stat.S_IFDIR | 0o555, 0, 0, "runtime"),
        ("missing /run/media/cdrom\nmissing /run/media/floppy\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, None),
        ("missing /run/media/cdrom\n", 1, b"", "presentmedia", stat.S_IFDIR | 0o555, 0, 0, "files"),
        ("missing /run/media/other\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, "files"),
        ("..5...... /run/media/cdrom\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, "files"),
        (".M....... /proc\n..5...... /usr/bin/managed\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, "files"),
        ("..5...... /proc\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, "files"),
        (".M....... /proc/sys\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, "files"),
        ("missing /proc\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, "files"),
        (".M....... /proc\n", 1, b"private-error", "proc", stat.S_IFDIR | 0o555, 0, 0, "files"),
        (".M....... /proc\n", 2, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, "files"),
        ("", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 0, "files"),
        (".M....... /proc\n", 1, b"", "tmpfs", stat.S_IFDIR | 0o555, 0, 0, "runtime"),
        (".M....... /proc\n", 1, b"", "duplicate", stat.S_IFDIR | 0o555, 0, 0, "runtime"),
        (".M....... /proc\n", 1, b"", "subroot", stat.S_IFDIR | 0o555, 0, 0, "runtime"),
        (".M....... /proc\n", 1, b"", "absent", stat.S_IFDIR | 0o555, 0, 0, "runtime"),
        ("missing /run/media/cdrom\n", 1, b"", "wrongrun", stat.S_IFDIR | 0o555, 0, 0, "runtime"),
        ("missing /run/media/cdrom\n", 1, b"", "missingrun", stat.S_IFDIR | 0o555, 0, 0, "runtime"),
        ("missing /run/media/cdrom\n", 1, b"", "runmode", stat.S_IFDIR | 0o555, 0, 0, "runtime"),
        ("missing /run/media/cdrom\n", 1, b"", "runuid", stat.S_IFDIR | 0o555, 0, 0, "runtime"),
        (".M....... /proc\n", 1, b"", "proc", stat.S_IFDIR | 0o700, 0, 0, "runtime"),
        (".M....... /proc\n", 1, b"", "proc", stat.S_IFREG | 0o555, 0, 0, "runtime"),
        (".M....... /proc\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 1, 0, "runtime"),
        (".M....... /proc\n", 1, b"", "proc", stat.S_IFDIR | 0o555, 0, 1, "runtime"),
    ],
)
def test_rpm_runtime_proc_check_retains_package_failures(
    rows, returncode, stderr, mount, mode, uid, gid, failure, monkeypatch
):
    """Reconcile only a proven proc mount's mode, retaining every other failure.

    Args:
        rows: Synthetic mountinfo rows to inspect.
        returncode: Status returned by the simulated command.
        stderr: Private command error bytes to ensure they stay hidden.
        mount: Mount metadata returned by the runtime fixture.
        mode: File or directory mode in the simulated metadata.
        uid: Owner ID in the simulated metadata.
        gid: Group ID in the simulated metadata.
        failure: Failure condition injected into the isolated operation.
        monkeypatch: Pytest fixture for replacing controlled dependencies.
    """
    generated = ast.parse(_decode_guest_program(
        content_inspection.guest_content_program(_expectation("rpm"))
    ))
    outer = next(node for node in generated.body if isinstance(node, ast.Try))
    outer.body = [node for node in outer.body if not isinstance(node, ast.FunctionDef)
                  or node.name not in {"checked", "run", "read", "load"}]
    monkeypatch.setitem(sys.modules, "grp", SimpleNamespace(getgrnam=lambda name: SimpleNamespace(gr_gid=22)))
    spec = importlib.util.spec_from_file_location("_iso_runtime_fixture", "image/common/scripts/verify-photon-package-state.py")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    namespace = {}
    firmware_checked = False
    root = "/private-subroot" if mount == "subroot" else "/"
    filesystem = "tmpfs" if mount == "tmpfs" else "proc"
    mountinfo = f"28 1 0:5 {root} /proc rw,nosuid,nodev,noexec - {filesystem} proc rw\n"
    if mount == "duplicate":
        mountinfo *= 2
    if mount == "absent":
        mountinfo = "28 1 0:5 / /private-fixture rw - proc proc rw\n"
    if mount != "missingrun":
        run_type = "ext4" if mount == "wrongrun" else "tmpfs"
        mountinfo += f"29 1 0:6 / /run rw - {run_type} tmpfs rw\n"

    def read(path, limit):
        """Provide the synthetic mount table to the generated runtime check.

        Args:
            path: Filesystem path used by the isolated fixture.
            limit: Maximum bytes accepted by the bounded reader.
        """
        assert path.as_posix() == "/proc/self/mountinfo"
        assert limit == 1048576
        return mountinfo.encode()

    def checked(path, _key):
        """Admit the fixture helper without reading its host path.

        Args:
            path: Filesystem path used by the isolated fixture.
            _key: Expected source key used for helper admission.
        """
        return Path(path), b"verified public helper bytes"

    def run(arguments, _timeout=60):
        """Return synthetic verification output for the generated RPM command.

        Args:
            arguments: Command argument vector supplied to the stub.
            _timeout: Timeout passed to the command stub.
        """
        nonlocal firmware_checked
        if "-V" in arguments and "linux-firmware" in arguments:
            firmware_checked = True
        if "-Va" in arguments and returncode:
            raise namespace["PrivateCommandFailure"](SimpleNamespace(
                stdout=rows.encode(), stderr=stderr, returncode=returncode
            ))
        if "-qa" in arguments:
            return b"filesystem\t1.1-11.ph5\tx86_64\nlinux\t6.1-1.ph5\tx86_64\npython3\t3.14-2.ph5\tx86_64\n"
        if "-qf" in arguments:
            return b"filesystem\n"
        return b""

    def lstat(path):
        """Expose metadata for the isolated runtime paths.

        Args:
            path: Filesystem path used by the isolated fixture.
        """
        name = path.as_posix()
        if name in {"/var/log/btmp", "/var/log/wtmp"}:
            native_mode = 0o660 if name.endswith("/btmp") else 0o664
            if mount == "logmode":
                native_mode = 0o666
            entry_type = stat.S_IFLNK if mount == "logsymlink" else stat.S_IFREG
            return SimpleNamespace(st_mode=entry_type | native_mode, st_nlink=2 if mount == "loglink" else 1,
                                   st_uid=int(mount == "loguid"), st_gid=0 if mount == "loggid" or (mount == "lograce" and firmware_checked) else 22)
        if name == "/var/mail":
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o1755, st_uid=0, st_gid=34)
        if name == "/run":
            return SimpleNamespace(st_mode=stat.S_IFDIR | (0o700 if mount == "runmode" else 0o755), st_uid=int(mount == "runuid"), st_gid=0)
        if name in {"/run/media/cdrom", "/run/media/floppy"}:
            if mount == "presentmedia":
                return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
            raise FileNotFoundError()
        assert name == "/proc"
        return SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=gid)

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(helper, "_read_installation_mountinfo", lambda: mountinfo)
    journal_checks = []

    def verify_journal(checksum):
        """Return or reject the native policy boundary for this generated command.

        Args:
            checksum: Media-admitted systemd package checksum.
        """
        assert checksum == content_inspection.PHOTON_SYSTEMD_SHA256
        journal_checks.append(checksum)
        if mount == "journalrace" and firmware_checked:
            raise ValueError("private journal policy drift")
        return {"runtime_journal_metadata_verified": True}

    audit_checks = []

    def verify_audit(checksum):
        """Require native audit metadata before and after package verification.

        Args:
            checksum: Pinned audit checksum passed to the shared verifier.
        """
        assert checksum == helper.INSTALLATION_AUDIT_SHA256
        audit_checks.append(checksum)
        if mount == "auditrace" and firmware_checked:
            raise ValueError("private audit policy drift")
        return {"runtime_audit_metadata_verified": True}

    rpc_checks = []

    def verify_rpc(checksum):
        """Require exact native RPC ownership proof before and after comparison.

        Args:
            checksum: Media-admitted rpcbind RPM checksum.
        """
        assert checksum == helper.INSTALLATION_RPCBIND_SHA256
        rpc_checks.append(checksum)
        if mount == "rpcrace" and firmware_checked:
            raise ValueError("private RPC directory drift")
        return {"runtime_rpcbind_metadata_verified": True}

    monkeypatch.setattr(helper, "verify_installation_rpcbind_metadata", verify_rpc)
    monkeypatch.setattr(helper, "verify_installation_audit_metadata", verify_audit)
    monkeypatch.setattr(helper, "verify_installation_journal_metadata", verify_journal)
    namespace.update(read=read, checked=checked, run=run, load=lambda *_args: helper)
    with contextlib.redirect_stdout(io.StringIO()) as output:
        exec(compile(ast.Module(body=[outer], type_ignores=[]), "<rpm-proc-fixture>", "exec"), namespace)
    actual = output.getvalue()
    assert "private-" not in actual
    if failure:
        assert actual.startswith(f"ATLASO-INSPECTION-FAILED:system-rpm-{failure}")
        assert "ATLASO-INSPECTION:" not in actual
    else:
        encoded = re.fullmatch(r"ATLASO-INSPECTION:([A-Za-z0-9+/=]+):END\n", actual)
        assert encoded is not None
        report = content_inspection.validate_content_report(
            base64.b64decode(encoded[1]), _expectation("rpm")
        )
        assert report["runtime_proc_verified"] is True
        assert report["runtime_run_verified"] is True
        assert report["runtime_login_metadata_verified"] is True
        assert report["runtime_mail_spool_verified"] is True
        assert report["runtime_journal_metadata_verified"] is True
        assert len(journal_checks) == 2
        assert report["runtime_audit_metadata_verified"] is True
        assert len(audit_checks) == 2
        assert report["runtime_rpcbind_metadata_verified"] is True
        assert len(rpc_checks) == 2
        assert report["runtime_media_directories_absent"] == rows.count("missing /run/media/")
        assert report["rpm_files_verified"] is True


def test_rpm_diagnostic_packages_returns_exact_source_inventory_names():
    """Host diagnostic attribution receives names only from admitted RPM inputs."""
    expected = _expectation("rpm")

    assert content_inspection.rpm_diagnostic_packages(expected) == [
        "filesystem",
        "linux",
        "optional-tool",
        "pip",
        "python3",
        "systemd",
    ]


def test_rpm_public_registry_matches_console_privacy_bound():
    """Keep the cross-language public-index boundary aligned with its registry."""
    source = (Path(__file__).resolve().parents[1] / "scripts/windows/vmware/invoke-installation-iso-test.ps1").read_text()
    match = re.search(r"entryDiagnostic.Groups\['index'\].Value -ge ([0-9]+)", source)
    assert match is not None
    assert int(match[1]) == len(content_inspection.RPM_DIAGNOSTIC_PATHS)


@pytest.mark.parametrize("kind", ["assets", "python", "powercli", "notices"])
def test_rpm_diagnostic_packages_omits_names_for_non_rpm_checks(kind):
    """Other content kinds cannot receive RPM ownership candidates.

    Args:
        kind: Content kind or scenario exercised by the test.
    """
    assert content_inspection.rpm_diagnostic_packages(_expectation(kind)) == []


def test_rpm_diagnostic_packages_rejects_invalid_rpm_expectation():
    """The host allowlist is not derived from an incomplete RPM expectation."""
    expected = _expectation("rpm")
    del expected["allowed_inventory"]

    with pytest.raises(ValueError):
        content_inspection.rpm_diagnostic_packages(expected)


@pytest.mark.parametrize(
    ("error", "record_names", "expected_stage"),
    [
        (
            "installed wheel member does not match: package.py",
            ("package.py",),
            "system-python-changed-" + hashlib.sha256(b"package.py").hexdigest(),
        ),
        (
            "installed wheel member does not match: private-sentinel.py "
            "private-python-classifier-sentinel",
            (),
            "system-python-changed",
        ),
        ("installed wheel member is missing: package.py", (), "system-python-missing"),
        (
            "guest site-packages contains an unexpected file: __pycache__/module.cpython-314.pyc",
            (),
            "system-python-bytecode",
        ),
        (
            "guest site-packages contains an unexpected file: __pycache__/module.txt",
            (),
            "system-python-extra",
        ),
        ("private-python-classifier-sentinel", (), "system-python-files"),
    ],
    ids=["changed-known", "changed-unknown-private", "missing", "bytecode", "other-pycache-extra", "unknown"],
)
def test_generated_python_classifier_uses_stages_without_exposing_checker_errors(
    error, record_names, expected_stage, capsys, tmp_path
):
    """Execute only the generated try node that classifies the shared checker.

    Args:
        error: Private checker error raised by the generated classifier node.
        record_names: Source-bound paths that can receive a fingerprint.
        expected_stage: Expected fixed public diagnostic stage.
        capsys: Pytest fixture for capturing public output.
        tmp_path: Pytest temporary directory for isolated filesystem fixtures.
    """
    command = content_inspection.guest_content_program(
        _expectation("python"),
        atlaso_root=Path("atlaso"),
        software_root=tmp_path / "software",
        temporary_root=tmp_path / "runtime",
        site_root=tmp_path / "site-packages",
    )
    generated = ast.parse(_decode_guest_program(command))

    def checks_shared_site_archive(node):
        """Locate the generated shared archive verifier call.

        Args:
            node: Generated AST node for the shared verifier call.
        """
        return any(
            isinstance(statement, ast.Expr)
            and isinstance(statement.value, ast.Call)
            and isinstance(statement.value.func, ast.Attribute)
            and statement.value.func.attr == "_verify_site_packages_archive"
            for statement in node.body
        )

    candidates = [
        node
        for node in ast.walk(generated)
        if isinstance(node, ast.Try) and checks_shared_site_archive(node)
    ]
    assert len(candidates) == 1

    class Checker:
        def _verify_site_packages_archive(self, *_args):
            """Raise the private checker error used by the classification test.

            Args:
                *_args: Additional positional arguments passed to the test double.
            """
            raise SystemExit(error)

    isolated = ast.Module(body=[candidates[0]], type_ignores=[])
    namespace = {
        "h": Checker(),
        "archive": object(),
        "records": {name: ("a" * 64, 1) for name in record_names},
        "distributions": set(),
        "stage": "system-python-files",
        "PurePosixPath": PurePosixPath,
        "hashlib": hashlib,
    }
    with pytest.raises(SystemExit):
        exec(compile(isolated, "<generated-python-classifier>", "exec"), namespace)

    assert namespace["stage"] == expected_stage
    assert namespace["stage"] in {
        "system-python-files",
        "system-python-bytecode",
        "system-python-extra",
        "system-python-changed",
        "system-python-missing",
    } or re.fullmatch(r"system-python-changed-[0-9a-f]{64}", namespace["stage"])
    captured = capsys.readouterr()
    assert error not in captured.out
    assert error not in captured.err


@pytest.mark.parametrize("encoded", [
    base64.b64encode(zlib.compress(b"x" * 140_000)).decode(),
    base64.b64encode(zlib.compress(b"{}") + b"trailing").decode(),
])
def test_rpm_inventory_decoder_rejects_bombs_and_trailing_data(encoded):
    """Compressed guest inventories have strict decoded and stream bounds.

    Args:
        encoded: Compressed inventory bytes to validate.
    """
    expected = _expectation("rpm")
    expected["allowed_inventory"] = encoded
    value = _report("rpm")

    with pytest.raises(ValueError):
        content_inspection.validate_content_report(
            json.dumps(value, separators=(",", ":")).encode(), expected
        )


def test_report_size_is_bounded():
    """Oversized console output is rejected before JSON interpretation."""
    with pytest.raises(ValueError, match="report exceeds"):
        content_inspection.validate_content_report(
            b" " * 4097, _expectation("notices")
        )
