"""Tests for authenticated, complete development ISO readback."""

from __future__ import annotations

import base64
import hashlib
import io
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pycdlib
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pycdlib import pycdlibexception

from scripts.installation import readback
from scripts.installation.manifest import (
    DEVELOPMENT_KEY_ID,
    PHOTON_INSTALLER_SHA256,
    SOURCE_ISO_SHA512,
    canonical_json,
)

_INSTALLER = "a" * 40
_SOFTWARE = "b" * 40
_VERSION = "1.2.3"
_PUBLIC_TEST_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
_RELEASE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))


def test_readback_preserves_repeated_relocated_directory_names(tmp_path: Path) -> None:
    """Read distinct deep PowerCLI-style paths and their original file bytes.

    Args:
        tmp_path: Isolated destination for the real Rock Ridge fixture.
    """
    image = pycdlib.PyCdlib()
    image.new(interchange_level=3, rock_ridge="1.09")
    image.add_directory(iso_path="/ATLASO", rr_name="atlaso")
    expected = {}
    for branch in ("first", "second"):
        directory = f"software/{branch}/version/package/services/metadata/core-properties"
        _add_directory(image, directory)
        path = directory + "/identity.txt"
        parts = PurePosixPath(path).parts
        components = [hashlib.sha256(PurePosixPath(*parts[:n]).as_posix().encode()).hexdigest()[:16].upper()
                      for n in range(1, len(parts) + 1)]
        raw = branch.encode()
        image.add_fp(io.BytesIO(raw), len(raw), iso_path="/ATLASO/" + "/".join(components) + ";1",
                     rr_name="identity.txt")
        expected[path] = raw
    output = tmp_path / "relocated.iso"
    image.write(str(output))
    image.close()
    image = pycdlib.PyCdlib()
    image.open(str(output))
    try:
        files, directories = readback._all_payload_paths(image)
        assert files == set(expected)
        assert all(path.rsplit("/", 1)[0] in directories for path in expected)
        software = readback._IsoSoftwarePath(image)
        actual = {str(member.relative_to(software)): member.read_bytes()
                  for member in software.rglob("*") if member.is_file()}
        assert actual == {path.removeprefix("software/"): raw for path, raw in expected.items()}
    finally:
        image.close()


def test_readback_still_rejects_duplicate_rock_ridge_names() -> None:
    """Reject actual duplicate child names rather than silently deduplicating."""
    child = SimpleNamespace(is_dot=lambda: False, is_dotdot=lambda: False,
                            rock_ridge=SimpleNamespace(name=lambda: b"duplicate"))
    root = SimpleNamespace(extent_location=lambda: 1, children=[child, child])
    file = SimpleNamespace(is_symlink=lambda: False, is_dir=lambda: False)
    image = SimpleNamespace(get_record=lambda **kw: root if kw["rr_path"] == "/atlaso" else file)
    with pytest.raises(ValueError, match="duplicate paths"):
        readback._all_payload_paths(image)


@pytest.mark.parametrize("symlink", [False, True])
def test_readback_rejects_directory_aliases_and_symlinks(symlink: bool) -> None:
    """Keep relocation traversal bounded and reject links outside the logical tree.

    Args:
        symlink: Whether the child is a symlink rather than a directory alias.
    """
    child = SimpleNamespace(is_dot=lambda: False, is_dotdot=lambda: False,
                            rock_ridge=SimpleNamespace(name=lambda: b"alias"))
    root = SimpleNamespace(extent_location=lambda: 1, children=[child])
    alias = SimpleNamespace(is_symlink=lambda: symlink, is_dir=lambda: True,
                            extent_location=lambda: 1)
    image = SimpleNamespace(get_record=lambda **kw: root if kw["rr_path"] == "/atlaso" else alias)
    with pytest.raises(ValueError, match="symbolic link" if symlink else "aliased directories"):
        readback._all_payload_paths(image)


@pytest.fixture(autouse=True)
def trusted_source_fixture(monkeypatch, tmp_path):
    """Supply independent fixture trust and source bytes, distinct from media.

    Args:
        monkeypatch: Pytest patcher for the independent trusted-source lookup.
        tmp_path: Isolated directory for the fixture trust key.
    """
    key = _RELEASE_KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    trust = tmp_path / "trusted-release.pem"
    trust.write_bytes(key)
    monkeypatch.setattr(readback, "_trusted_sources", lambda repository, commit: {
        "scripts/installation/installer.py": b"installer bytes",
        "image/common/scripts/provision-atlaso.sh": b"provision bytes",
        "image/common/update-trust/atlaso-release-2026-01.pem": key,
    })
    return trust


def _envelope(key: Ed25519PrivateKey, document: bytes, key_id: str, *, algorithm: bool) -> bytes:
    """Create a deterministic detached fixture signature.

    Args:
        key: Private fixture key that signs the document.
        document: Canonical manifest bytes to sign.
        key_id: Identifier embedded in the detached signature.
        algorithm: Whether to include the algorithm field in the envelope.
    """
    value = {"schema_version": 1, "key_id": key_id, "signature": base64.b64encode(key.sign(document)).decode("ascii")}
    if algorithm:
        value["algorithm"] = "ed25519"
    return canonical_json(value)


def _add_directory(image: pycdlib.PyCdlib, relative: str) -> None:
    """Add a Rock Ridge path using the production hashed ISO identifiers.

    Args:
        image: ISO builder receiving the directory entries.
        relative: Slash-separated path relative to the Atlaso ISO root.
    """
    parent = PurePosixPath()
    for part in PurePosixPath(relative).parts:
        parent /= part
        components = [
            hashlib.sha256(PurePosixPath(*parent.parts[:index]).as_posix().encode()).hexdigest()[:16].upper()
            for index in range(1, len(parent.parts) + 1)
        ]
        iso_path = "/ATLASO/" + "/".join(components)
        try:
            image.add_directory(iso_path=iso_path, rr_name=part)
        except pycdlibexception.PyCdlibInvalidInput:
            # The path is shared with a previously added fixture member.
            image.get_record(rr_path="/atlaso/" + parent.as_posix())


def _build_iso(path: Path, *, tamper: bool = False, extra: bool = False,
               bad_signature: bool = False, software_tamper: bool = False, guest_payload: bool = False) -> str:
    """Create a tiny complete and signed development media fixture.

    Args:
        path: Destination for the generated ISO.
        tamper: Whether to alter an RPM after recording its manifest digest.
        extra: Whether to add an unlisted payload file.
        bad_signature: Whether to sign the manifest with an untrusted key.
        software_tamper: Whether to change a release-signed software member.
        guest_payload: Whether to include a captured guest-tools companion file.
    """
    wheel = b"public wheel bytes"
    dependency = b"public dependency wheel bytes"
    selected = {
        "packages/atlaso-1.2.3-py3-none-any.whl": wheel,
        "wheelhouse/cp314/fixture-1-py3-none-any.whl": dependency,
        "wheelhouse/cp314/requirements-wheelhouse.lock": (
            "fixture==1 --hash=sha256:" + hashlib.sha256(dependency).hexdigest() + "\n").encode(),
        "requirements-appliance.lock": b"fixture==1\n",
        "bundle-metadata.json": b"{}\n",
    }
    release = canonical_json(
        {
            "schema_version": 2,
            "kind": "atlaso-release",
            "version": _VERSION,
            "git_commit": _SOFTWARE,
            "signing_key_id": "atlaso-release-2026-01",
            "supported_python_abis": ["cp314"],
            "content_hashes": {name: hashlib.sha256(raw).hexdigest() for name, raw in selected.items()},
            "bundle": {"sha256": "c" * 64},
        }
    )
    release_signature = _envelope(_RELEASE_KEY, release, "atlaso-release-2026-01", algorithm=False)
    release_key = _RELEASE_KEY.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    source = canonical_json(
        {
            "schema_version": 1,
            "kind": "atlaso-virtualization-source",
            "version": _VERSION,
            "source_commit": _SOFTWARE,
            "source_software_tag": "v" + _VERSION,
            "release_manifest_sha256": hashlib.sha256(release).hexdigest(),
            "application_wheel": "packages/atlaso-1.2.3-py3-none-any.whl",
            "application_wheel_sha256": hashlib.sha256(wheel).hexdigest(),
            "release_bundle_sha256": "c" * 64,
            "python_abi": "cp314",
        }
    )
    files = {
        "software/release-manifest.json": release,
        "software/release-manifest.json.sig": release_signature,
        "software/virtualization-source.json": source,
        "software/packages/atlaso-1.2.3-py3-none-any.whl": wheel,
        **{"software/" + name: raw for name, raw in selected.items()},
        "source/scripts/installation/installer.py": b"installer bytes",
        "source/image/common/scripts/provision-atlaso.sh": b"provision bytes",
        "source/image/common/update-trust/atlaso-release-2026-01.pem": release_key,
        "rpms/linux-fixture.rpm": b"authenticated RPM bytes",
        "powercli/fixture.psm1": b"module bytes",
        "tdnf.conf": b"[main]\n",
    }
    if software_tamper:
        # The public development key can re-sign the outer inventory but cannot
        # authorize bytes different from the independent production signature.
        files["software/wheelhouse/cp314/fixture-1-py3-none-any.whl"] = b"substituted dependency"
    if guest_payload:
        files["guest-tools/qemu/atlaso-qemu-guest-agent.rpm"] = b"captured agent fixture"
        files["guest-tools/SHA256SUMS"] = b"captured checksum fixture"
    rpm_digest = hashlib.sha256(files["rpms/linux-fixture.rpm"]).hexdigest()
    records = [
        {"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        for name, data in sorted(files.items())
    ]
    manifest = {
        "schema": 1,
        "architecture": "x86_64",
        "version": _VERSION,
        "source_commit": _INSTALLER,
        "signing_key_id": DEVELOPMENT_KEY_ID,
        "development": {"schema": 1, "software_source_commit": _SOFTWARE, "non_production": True},
        "photon_installer": "2.2",
        "photon_installer_sha256": PHOTON_INSTALLER_SHA256,
        "photon_iso_sha512": SOURCE_ISO_SHA512,
        "packages": ["linux"],
        "files": records,
        "rpm_inventory": [
            {"file": "linux-fixture.rpm", "name": "linux", "version": "6.1-1.ph5", "architecture": "x86_64", "sha256": rpm_digest}
        ],
    }
    manifest_raw = canonical_json(manifest)
    signer = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64))) if bad_signature else _PUBLIC_TEST_KEY
    detached = _envelope(signer, manifest_raw, DEVELOPMENT_KEY_ID, algorithm=True)
    payload = {**files, "payload-manifest.json": manifest_raw, "payload-manifest.json.sig": detached}
    if tamper:
        payload["rpms/linux-fixture.rpm"] = b"tampered bytes"
    if extra:
        payload["unexpected.bin"] = b"unsigned extra"

    image = pycdlib.PyCdlib()
    image.new(interchange_level=3, rock_ridge="1.09")
    image.add_directory("/ATLASO", rr_name="atlaso")
    directories = sorted(
        {PurePosixPath(name).parent.as_posix() for name in payload if PurePosixPath(name).parent.as_posix() != "."}
        | {
            ancestor.as_posix()
            for name in payload
            for ancestor in PurePosixPath(name).parents
            if ancestor.as_posix() != "."
        },
        key=lambda value: (len(PurePosixPath(value).parts), value),
    )
    for directory in directories:
        _add_directory(image, directory)
    for name, data in sorted(payload.items()):
        item = PurePosixPath(name)
        path_ids = [hashlib.sha256(PurePosixPath(*item.parts[:index]).as_posix().encode()).hexdigest()[:16].upper() for index in range(1, len(item.parts))]
        path_ids.append(hashlib.sha256(item.as_posix().encode()).hexdigest()[:16].upper())
        stream = io.BytesIO(data)
        image.add_fp(stream, len(data), iso_path="/ATLASO/" + "/".join(path_ids) + ";1", rr_name=item.name)
    image.write(str(path))
    image.close()
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read(path: Path, checksum: str) -> dict[str, object]:
    """Invoke full readback with the independently selected identities.

    Args:
        path: ISO image to authenticate and inspect.
        checksum: Independently admitted SHA-256 digest for the ISO.
    """
    return readback.full_readback(
        path,
        checksum,
        installer_commit=_INSTALLER,
        software_commit=_SOFTWARE,
        software_version=_VERSION,
        trust_key=path.parent / "trusted-release.pem",
    )


def test_full_readback_authenticates_all_payload_bytes_and_separate_identities(tmp_path: Path) -> None:
    """Return only compact provenance after every signed payload member passes.

    Args:
        tmp_path: Isolated destination for the signed ISO fixture.
    """
    image = tmp_path / "development.iso"
    checksum = _build_iso(image)

    result = _read(image, checksum)

    assert result["result"] == "passed"
    assert result["iso_sha256"] == checksum
    assert result["installer_source_commit"] == _INSTALLER
    assert result["software_source_commit"] == _SOFTWARE
    assert result["software_version"] == _VERSION
    assert result["payload_file_count"] == 16
    assert result["rpm_count"] == 1
    assert result["rpm_native_transaction_retested"] is False
    assert set(result) <= {
        "schema", "result", "kind", "iso_sha256", "installer_source_commit", "software_source_commit",
        "software_version", "payload_file_count", "payload_bytes", "rpm_count",
            "authenticated_manifest_sha256", "rpm_native_transaction_retested", "installer_source_archive_verified",
            "captured_input_inventory_verified",
            "captured_input_inventory_sha256",
    }


def test_readback_rejects_outer_resigned_software_with_wrong_production_content(tmp_path: Path) -> None:
    """Reject software bytes that conflict with the independently signed release.

    Args:
        tmp_path: Isolated destination for the tampered ISO fixture.
    """
    image = tmp_path / "development.iso"
    checksum = _build_iso(image, software_tamper=True)
    with pytest.raises(ValueError, match="complete authenticated contract"):
        _read(image, checksum)


def test_readback_does_not_trust_a_media_supplied_software_key(tmp_path: Path) -> None:
    """Require host trust instead of a key supplied inside the ISO.

    Args:
        tmp_path: Isolated destination for the ISO and substituted host key.
    """
    image = tmp_path / "development.iso"
    checksum = _build_iso(image)
    independent_key = Ed25519PrivateKey.from_private_bytes(bytes(range(2, 34)))
    (tmp_path / "trusted-release.pem").write_bytes(independent_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    with pytest.raises(ValueError, match="independent host trust"):
        _read(image, checksum)


def test_readback_requires_source_bytes_to_match_the_claimed_commit(tmp_path: Path, monkeypatch) -> None:
    """Reject source archive bytes that differ from the claimed commit.

    Args:
        tmp_path: Isolated destination for the signed ISO fixture.
        monkeypatch: Pytest patcher for the trusted source lookup.
    """
    image = tmp_path / "development.iso"
    checksum = _build_iso(image)
    monkeypatch.setattr(readback, "_trusted_sources", lambda repository, commit: {"different.py": b"different"})
    with pytest.raises(ValueError, match="source bytes differ"):
        _read(image, checksum)


@pytest.mark.parametrize("tamper,extra,bad_signature", [(True, False, False), (False, True, False), (False, False, True)])
def test_full_readback_rejects_tampered_extra_or_unauthenticated_payload(
    tmp_path: Path, tamper: bool, extra: bool, bad_signature: bool
) -> None:
    """A checksum over the ISO alone does not bless unsigned payload contents.

    Args:
        tmp_path: Isolated destination for the invalid ISO fixture.
        tamper: Whether to modify a manifest-listed RPM after signing.
        extra: Whether to add an unlisted file to the media.
        bad_signature: Whether the payload signature uses an untrusted key.
    """
    image = tmp_path / "invalid.iso"
    checksum = _build_iso(image, tamper=tamper, extra=extra, bad_signature=bad_signature)

    with pytest.raises(ValueError):
        _read(image, checksum)


def test_full_readback_rejects_wrong_media_digest_and_software_identity(tmp_path: Path) -> None:
    """Bind readback to the independently selected media and release identities.

    Args:
        tmp_path: Isolated destination for the signed ISO fixture.
    """
    image = tmp_path / "development.iso"
    checksum = _build_iso(image)
    with pytest.raises(ValueError, match="admitted digest"):
        _read(image, "0" * 64)
    with pytest.raises(ValueError, match="software identity"):
        readback.full_readback(
            image,
            checksum,
            installer_commit=_INSTALLER,
            software_commit="c" * 40,
            software_version=_VERSION,
        )


@pytest.mark.parametrize("substitute", [False, True])
def test_full_readback_binds_relocated_guest_tools_to_original_capture(tmp_path, substitute):
    """Moving retained payloads outside the RPM repo must preserve original capture hashes.

    Args:
        tmp_path: Isolated ISO fixture root.
        substitute: Whether the supplied original capture describes different agent bytes.
    """
    image = tmp_path / "development.iso"
    checksum = _build_iso(image, guest_payload=True)
    capture = {"rpms": [
        {"path": "linux-fixture.rpm", "sha256": hashlib.sha256(b"authenticated RPM bytes").hexdigest()},
        {"path": "guest-tools/qemu/atlaso-qemu-guest-agent.rpm", "sha256": hashlib.sha256(b"changed" if substitute else b"captured agent fixture").hexdigest()},
        {"path": "guest-tools/SHA256SUMS", "sha256": hashlib.sha256(b"captured checksum fixture").hexdigest()},
    ], "powercli": [{"path": "fixture.psm1", "sha256": hashlib.sha256(b"module bytes").hexdigest()}]}
    arguments = dict(installer_commit=_INSTALLER, software_commit=_SOFTWARE, software_version=_VERSION,
                     trust_key=tmp_path / "trusted-release.pem", capture_inventory=capture)
    if substitute:
        with pytest.raises(ValueError, match="complete captured input identities"):
            readback.full_readback(image, checksum, **arguments)
    else:
        assert readback.full_readback(image, checksum, **arguments)["captured_input_inventory_verified"] is True
