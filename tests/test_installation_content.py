"""Public, media-bound checks for installed offline ISO content."""

import ast
import base64
import contextlib
import csv
import hashlib
import io
import json
import os
import re
import tarfile
import zlib
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from scripts import verify_virtualization_guest_wheel
from scripts.installation import content_inspection


def _inventory(value):
    """Encode a public synthetic inventory in the guest report format."""
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return base64.b64encode(zlib.compress(raw, 9)).decode()


def _expectation(kind):
    """Create a small, well-formed expectation without host or guest state."""
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
            "allowed_inventory": _inventory({
                "linux": ["6.1-1.ph5", "x86_64"],
                "python3": ["3.14-2.ph5", "x86_64"],
                "optional-tool": ["1.0-1.ph5", "noarch"],
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
    """Create a passing public synthetic report for one content kind."""
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
        },
        "notices": {"notices_sha256": "a" * 64, "notice_inputs_verified": True},
    }
    return {
        "schema": 1,
        "kind": kind,
        "iso_sha256": "a" * 64,
        **{**values[kind], **changes},
    }


def _decode_guest_program(command):
    """Decode the bounded source embedded in a generated guest command."""
    compressed = re.search(r'b64decode\("([A-Za-z0-9+/=]+)"\)', command)
    assert compressed is not None
    return zlib.decompress(base64.b64decode(compressed.group(1))).decode()


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
    }
    all_files = {
        **sources,
        "source/image/common/powershell/provision-powercli.ps1": b"# PowerCLI validation fixture\n",
        "source/image/common/scripts/verify-photon-package-state.py": b"# RPM state fixture\n",
        "source/scripts/generate_third_party_notices.py": b"# Notice generator fixture\n",
        "source/scripts/third_party_notices.json": b"{}\n",
        "source/requirements-appliance.lock": b"# Public lock fixture\n",
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
    """Write a tiny wheel with a real RECORD for the shared verifier."""
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
    """Archive the signed wheel members as installed site-packages files."""
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
    """Exercise the real RECORD comparator used by installed Python inspection."""
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
        "linux": ["6.1-1.ph5", "x86_64"],
        "python3": ["3.14-2.ph5", "x86_64"],
    }
    assert expectations[0]["source_file_count"] == 10
    assert expectations[2]["powercli_lock_sha256"] == hashlib.sha256(
        sources["source/image/common/powershell/powercli-lock.json"]
    ).hexdigest()


@pytest.mark.parametrize("tamper", ["source-bytes", "file-hash"])
def test_prepare_content_inputs_rejects_source_not_bound_to_manifest(tamper):
    """A claimed shared source cannot drift from the admitted ISO inventory."""
    base, manifest, sources = _prepare_fixture()
    if tamper == "source-bytes":
        sources["source/image/common/scripts/provision-atlaso.sh"] += b"# changed\n"
    else:
        manifest["files"][0]["sha256"] = "0" * 64

    with pytest.raises(ValueError, match="source differs"):
        content_inspection.prepare_content_inputs(base, manifest, sources)


@pytest.mark.parametrize("kind", content_inspection.KINDS)
def test_validate_content_report_accepts_only_expected_public_measurements(kind):
    """Valid reports retain their exact media identity and expected fields."""
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
    """Reports fail closed on schema extensions and identity mismatches."""
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
        {"installed_inventory": _inventory({"linux": ["wrong", "x86_64"], "python3": ["3.14-2.ph5", "x86_64"]})},
        {"installed_inventory": _inventory({"linux": ["6.1-1.ph5", "aarch64"], "python3": ["3.14-2.ph5", "x86_64"]})},
        {"installed_inventory": _inventory({"linux": "6.1-1.ph5", "python3": ["3.14-2.ph5", "x86_64"]})},
        {"installed_inventory": _inventory({"linux": ["6.1-1.ph5", "x86_64"], "python3": ["3.14-2.ph5", "x86_64"], "rogue": ["1.0", "noarch"]})},
        {"installed_inventory": _inventory({"linux": ["6.1-1.ph5", "x86_64"]})},
    ],
    ids=["firmware", "rpm-files", "package-state", "changed-identity", "wrong-architecture", "malformed-identity", "extra-package", "missing-package"],
)
def test_validate_content_report_rejects_unverified_rpm_closure(changes):
    """The installed RPM identities must satisfy the signed allowed closure."""
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
    """Booleans cannot masquerade as counts, and check failures stay failures."""
    with pytest.raises(ValueError):
        content_inspection.validate_content_report(
            json.dumps(_report(kind, **changes), separators=(",", ":")).encode(),
            _expectation(kind),
        )


@pytest.mark.parametrize("kind", content_inspection.KINDS)
def test_guest_content_program_uses_bounded_ascii_console_command(kind, tmp_path):
    """Generated console payload uses injectable fixture paths and a hard size cap."""
    atlaso = tmp_path / "atlaso"
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
    assert repr(str(atlaso)) in program
    assert repr(str(software)) in program
    assert repr(str(temporary)) in program
    if kind == "python":
        assert repr(str(site)) in program
    if kind == "rpm":
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
    """Run generated source only until an intercepted first guest file read."""
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
        """Record the intended file and stop before touching the filesystem."""
        observed.append(Path(path))
        raise OSError("synthetic boundary: no guest filesystem access")

    output = io.StringIO()
    monkeypatch.setattr(os, "O_NOFOLLOW", 0, raising=False)
    monkeypatch.setattr(os, "open", stop_before_read)
    with contextlib.redirect_stdout(output):
        exec(program, {})

    assert observed == [first_path]
    marker = {"assets": "system-assets-profile", "python": "system-python-helpers"}.get(kind, f"system-{kind}")
    assert output.getvalue().splitlines() == [f"ATLASO-INSPECTION-FAILED:{marker}"]


@pytest.mark.parametrize("encoded", [
    base64.b64encode(zlib.compress(b"x" * 140_000)).decode(),
    base64.b64encode(zlib.compress(b"{}") + b"trailing").decode(),
])
def test_rpm_inventory_decoder_rejects_bombs_and_trailing_data(encoded):
    """Compressed guest inventories have strict decoded and stream bounds."""
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
