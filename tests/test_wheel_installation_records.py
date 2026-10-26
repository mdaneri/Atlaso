"""Scheme-aware records for files installed from signed Python wheels."""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import re
import stat
from pathlib import Path
from zipfile import ZipFile, ZipInfo

import pytest

from scripts import verify_virtualization_guest_wheel as verifier

INTERPRETER = "/opt/atlaso/.venv/bin/python"


def _canonical(name: str) -> str:
    """Return the wheel distribution spelling used by dist-info paths."""
    return re.sub(r"[-_.]+", "_", name).lower()


def _wheel(
    path: Path,
    name: str,
    version: str,
    members: dict[str, bytes],
    requires: tuple[str, ...] = (),
    *,
    duplicate_record_self: bool = False,
    member_modes: dict[str, int] | None = None,
) -> Path:
    """Write one minimal wheel with valid metadata and a hashed RECORD."""
    canonical = _canonical(name)
    dist_info = f"{canonical}-{version}.dist-info"
    metadata = (
        "Metadata-Version: 2.4\n"
        f"Name: {name}\n"
        f"Version: {version}\n"
        + "".join(f"Requires-Dist: {requirement}\n" for requirement in requires)
    ).encode()
    payload = {**members, f"{dist_info}/METADATA": metadata}
    rows = []
    for member, content in payload.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).decode().rstrip("=")
        rows.append((member, f"sha256={digest}", str(len(content))))
    record_name = f"{dist_info}/RECORD"
    self_rows = [(record_name, "", "")]
    if duplicate_record_self:
        self_rows.append((record_name, "", ""))
    output = io.StringIO(newline="")
    csv.writer(output, lineterminator="\n").writerows([*rows, *self_rows])
    with ZipFile(path, "w") as archive:
        for member, content in payload.items():
            info = ZipInfo(member)
            if member_modes and member in member_modes:
                info.create_system = 3
                info.external_attr = member_modes[member] << 16
            archive.writestr(info, content)
        archive.writestr(record_name, output.getvalue())
    return path


def _app(tmp_path: Path, requires: tuple[str, ...] = ()) -> Path:
    """Create a minimal Atlaso wheel required by the shared environment parser."""
    return _wheel(
        tmp_path / "atlaso-1.2.3-py3-none-any.whl",
        "Atlaso",
        "1.2.3",
        {"atlaso/__init__.py": b"__version__ = '1.2.3'\n"},
        requires,
    )


def _environment(tmp_path: Path, app_requires: tuple[str, ...] = ()):
    """Create the required Atlaso wheel and an initially empty wheelhouse."""
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    app = _app(tmp_path, app_requires)
    return app, wheelhouse, hashlib.sha256(app.read_bytes()).hexdigest()


def _read(app: Path, wheelhouse: Path, digest: str):
    """Resolve scheme-aware installed records through the shared API."""
    return verifier._expected_installation(app, wheelhouse, digest)


def _data_path(name: str, version: str, category: str, member: str) -> str:
    """Build one wheel data-directory member name."""
    return f"{_canonical(name)}-{version}.data/{category}/{member}"


def test_nested_vendor_record_is_payload_not_a_distribution(tmp_path: Path):
    """Vendored metadata stays byte-bound without granting generated-file exemptions."""
    app, wheelhouse, digest = _environment(tmp_path)
    nested = "sample_dep/_vendor/vendor-2.0.dist-info/RECORD"
    content = b"signed embedded metadata\n"
    _wheel(wheelhouse / "sample_dep-1.0-py3-none-any.whl", "sample-dep", "1.0", {nested: content})

    site, distributions, _external = _read(app, wheelhouse, digest)

    assert site[nested] == (hashlib.sha256(content).hexdigest(), len(content))
    assert distributions == {"atlaso-1.2.3.dist-info", "sample_dep-1.0.dist-info"}


def test_wheel_root_cannot_be_recorded_as_a_file(tmp_path: Path):
    """A root directory alias cannot become an immutable file destination."""
    app, wheelhouse, digest = _environment(tmp_path)
    _wheel(wheelhouse / "sample_dep-1.0-py3-none-any.whl", "sample-dep", "1.0", {".": b"invalid"})

    with pytest.raises(SystemExit):
        _read(app, wheelhouse, digest)


@pytest.mark.parametrize(
    ("scheme", "member", "content", "installed"),
    [
        (
            "headers",
            "api.h",
            b"#define SAMPLE 1\n",
            "include/site/python3.14/sample-dep/api.h",
        ),
        ("data", "share/sample_dep/catalog.bin", b"catalog\x00data", "share/sample_dep/catalog.bin"),
        ("scripts", "sample-tool", b"#!/usr/bin/env python\nprint('ok')\n", "bin/sample-tool"),
    ],
)
def test_expected_installation_maps_all_supported_external_schemes(
    tmp_path: Path, scheme: str, member: str, content: bytes, installed: str
):
    """Header, data, and script entries map to bounded venv-relative targets."""
    app, wheelhouse, digest = _environment(tmp_path)
    name, version = "sample-dep", "1.0"
    path = _data_path(name, version, scheme, member)
    _wheel(wheelhouse / "sample_dep-1.0-py3-none-any.whl", name, version, {path: content})

    site, distributions, external = _read(app, wheelhouse, digest)

    assert "sample_dep-1.0.dist-info" in distributions
    assert installed in external
    record = external[installed]
    assert record[0] == hashlib.sha256(content).hexdigest()
    assert record[1] == len(content)
    verifier._verify_external_payload(content, record, (INTERPRETER,))
    with pytest.raises(SystemExit):
        verifier._verify_external_payload(content + b"tampered", record, (INTERPRETER,))
    if scheme == "headers":
        assert site["atlaso/__init__.py"][1] > 0
    if scheme == "scripts":
        assert record[2] in (b"", "")


@pytest.mark.parametrize("first_line", [b"#!python\n", b"#!pythonw\n"])
def test_external_script_verifier_allows_only_exact_installer_rewrite(
    tmp_path: Path, first_line: bytes
):
    """The original wheel digest is retained while only the shebang is rewritten."""
    app, wheelhouse, digest = _environment(tmp_path)
    original = first_line + b"print('from wheel')\n"
    source = _data_path("script-owner", "2.0", "scripts", "tool")
    _wheel(
        wheelhouse / "script_owner-2.0-py3-none-any.whl",
        "script-owner",
        "2.0",
        {source: original},
    )
    _site, _distributions, external = _read(app, wheelhouse, digest)
    record = external["bin/tool"]

    rewritten = f"#!{INTERPRETER}\n".encode() + original.split(b"\n", 1)[1]
    verifier._verify_external_payload(rewritten, record, (INTERPRETER,))
    with pytest.raises(SystemExit):
        verifier._verify_external_payload(
            b"#!/bin/sh\n" + original.split(b"\n", 1)[1], record, (INTERPRETER,)
        )
    with pytest.raises(SystemExit):
        verifier._verify_external_payload(
            b"#!/tmp/other-python\n" + original.split(b"\n", 1)[1],
            record,
            (INTERPRETER,),
        )
    with pytest.raises(SystemExit):
        verifier._verify_external_payload(rewritten + b"tampered", record, (INTERPRETER,))


@pytest.mark.parametrize(
    ("scheme", "member"),
    [
        ("headers", "../escape.h"),
        ("headers", "/absolute.h"),
        ("headers", "./noncanonical.h"),
        ("unknown", "file.bin"),
        ("data", "../outside"),
        ("scripts", "../outside"),
    ],
)
def test_expected_installation_rejects_unsafe_or_unknown_scheme_paths(
    tmp_path: Path, scheme: str, member: str
):
    """Only canonical paths under recognized wheel schemes are admitted."""
    app, wheelhouse, digest = _environment(tmp_path)
    path = _data_path("sample-dep", "1.0", scheme, member)
    _wheel(
        wheelhouse / "sample_dep-1.0-py3-none-any.whl",
        "sample-dep",
        "1.0",
        {path: b"payload"},
    )

    with pytest.raises(SystemExit):
        _read(app, wheelhouse, digest)


@pytest.mark.parametrize(
    "members",
    [
        {
            "sample_dep-1.0.data/headers/site/python3.14/sample_dep/x.h": b"a",
            "sample_dep-1.0.data/headers/site/python3.14/sample_dep/x.h/../x.h": b"b",
        },
        {
            "sample_dep-1.0.data/purelib/sample_dep/data.bin": b"same-target",
            "sample_dep-1.0.data/data/lib/python3.14/site-packages/sample_dep/data.bin": b"same-target",
        },
        {
            "sample_dep-1.0.data/data/bin/python": b"reserved runtime target",
        },
    ],
    ids=["duplicate-or-traversal", "site-data-collision", "reserved-runtime-path"],
)
def test_expected_installation_rejects_duplicate_colliding_and_reserved_targets(
    tmp_path: Path, members: dict[str, bytes]
):
    """Different wheel paths cannot shadow one installed target or runtime file."""
    app, wheelhouse, digest = _environment(tmp_path)
    _wheel(wheelhouse / "sample_dep-1.0-py3-none-any.whl", "sample-dep", "1.0", members)

    with pytest.raises(SystemExit):
        _read(app, wheelhouse, digest)


def test_legacy_site_only_parser_remains_strict_for_external_records(tmp_path: Path):
    """Legacy site-only APIs never silently discard a wheel's external payload."""
    app, wheelhouse, digest = _environment(tmp_path)
    source = _data_path("sample-dep", "1.0", "headers", "site/python3.14/sample_dep/x.h")
    dependency = _wheel(
        wheelhouse / "sample_dep-1.0-py3-none-any.whl",
        "sample-dep",
        "1.0",
        {source: b"header"},
    )

    with pytest.raises(SystemExit):
        verifier._wheel_records(dependency)
    with pytest.raises(SystemExit):
        verifier._expected_environment(app, wheelhouse, digest)


def test_expected_installation_rejects_cross_wheel_site_data_target_collision(
    tmp_path: Path,
):
    """A .data/data target cannot shadow the active site-packages tree."""
    app, wheelhouse, digest = _environment(tmp_path)
    _wheel(
        wheelhouse / "first_lib-1.0-py3-none-any.whl",
        "first-lib",
        "1.0",
        {"sample_dep/shared.py": b"site payload\n"},
    )
    data_target = _data_path(
        "second-lib",
        "1.0",
        "data",
        "lib/python3.14/site-packages/sample_dep/shared.py",
    )
    _wheel(
        wheelhouse / "second_lib-1.0-py3-none-any.whl",
        "second-lib",
        "1.0",
        {data_target: b"data payload\n"},
    )

    with pytest.raises(SystemExit):
        _read(app, wheelhouse, digest)


def test_expected_installation_rejects_repeated_record_self_entry(tmp_path: Path):
    """RECORD may contain exactly one unhashed self-entry."""
    app, wheelhouse, digest = _environment(tmp_path)
    _wheel(
        wheelhouse / "sample_dep-1.0-py3-none-any.whl",
        "sample-dep",
        "1.0",
        {"sample_dep/__init__.py": b""},
        duplicate_record_self=True,
    )

    with pytest.raises(SystemExit):
        _read(app, wheelhouse, digest)


@pytest.mark.parametrize(
    "entry_mode", [stat.S_IFLNK | 0o777, stat.S_IFDIR | 0o755], ids=["symlink", "directory"]
)
def test_expected_installation_rejects_recorded_non_regular_zip_members(
    tmp_path: Path, entry_mode: int
):
    """A RECORD row cannot bless a symlink or directory ZIP member as a file."""
    app, wheelhouse, digest = _environment(tmp_path)
    member = "sample_dep/payload.bin"
    _wheel(
        wheelhouse / "sample_dep-1.0-py3-none-any.whl",
        "sample-dep",
        "1.0",
        {member: b"recorded payload"},
        member_modes={member: entry_mode},
    )

    with pytest.raises(SystemExit):
        _read(app, wheelhouse, digest)


def test_expected_installation_accepts_regular_zip_member_with_mode_zero(
    tmp_path: Path,
):
    """A ZIP entry without Unix file-type bits remains a normal wheel file."""
    app, wheelhouse, digest = _environment(tmp_path)
    member = "sample_dep/payload.bin"
    _wheel(
        wheelhouse / "sample_dep-1.0-py3-none-any.whl",
        "sample-dep",
        "1.0",
        {member: b"recorded payload"},
        member_modes={member: 0},
    )

    site, _distributions, _external = _read(app, wheelhouse, digest)

    assert site[member][1] == len(b"recorded payload")


def test_identical_cross_wheel_external_records_are_deduplicated(tmp_path: Path):
    """Identical installed bytes shared by distributions produce one record."""
    app, wheelhouse, digest = _environment(tmp_path)
    content = b"common header\n"
    for name, version in (("first-lib", "1.0"), ("second-lib", "2.0")):
        path = _data_path(name, version, "data", "share/shared/common.h")
        _wheel(
            wheelhouse / f"{_canonical(name)}-{version}-py3-none-any.whl",
            name,
            version,
            {path: content},
        )

    _site, _distributions, external = _read(app, wheelhouse, digest)

    assert list(external) == ["share/shared/common.h"]
    assert external["share/shared/common.h"][0] == hashlib.sha256(content).hexdigest()


@pytest.mark.parametrize(
    ("owner", "base", "requires"),
    [
        ("aaa-owner", "zzz-base", "zzz-base==1.0"),
        ("zzz-owner", "aaa-base", "aaa-base (==1.0)"),
    ],
)
def test_unique_exact_dependent_wins_external_collision_independent_of_filename_order(
    tmp_path: Path, owner: str, base: str, requires: str
):
    """A direct exact pin selects the dependent's bytes in either sort order."""
    app, wheelhouse, digest = _environment(
        tmp_path, (f"{owner}==2.0",)
    )
    target = "bin/shared-api"
    owner_source = _data_path(owner, "2.0", "scripts", "shared-api")
    base_source = _data_path(base, "1.0", "scripts", "shared-api")
    owner_bytes, base_bytes = b"owner version\n", b"base version\n"
    _wheel(
        wheelhouse / f"{_canonical(owner)}-2.0-py3-none-any.whl",
        owner,
        "2.0",
        {owner_source: owner_bytes},
        (requires,),
    )
    _wheel(
        wheelhouse / f"{_canonical(base)}-1.0-py3-none-any.whl",
        base,
        "1.0",
        {base_source: base_bytes},
    )

    _site, _distributions, external = _read(app, wheelhouse, digest)

    assert external[target][0] == hashlib.sha256(owner_bytes).hexdigest()
    assert len(external) == 1


@pytest.mark.parametrize(
    "scenario", ["unrelated", "conditional", "extra", "cycle", "ambiguous-owner"]
)
def test_external_collision_requires_one_unconditional_exact_owner(
    tmp_path: Path, scenario: str
):
    """Ambiguous, conditional, extras, and cyclic edges cannot pick a winner."""
    owner_requires = {
        "unrelated": (),
        "conditional": ("base-lib==1.0; python_version < '4'",),
        "extra": ("base-lib[headers]==1.0",),
        "cycle": ("base-lib==1.0",),
        "ambiguous-owner": ("base-lib==1.0",),
    }[scenario]
    base_requires = ("owner-lib==2.0",) if scenario == "cycle" else ()
    app_requires = (
        ("owner-lib==2.0", "other-owner==2.0")
        if scenario == "ambiguous-owner"
        else ("owner-lib==2.0",)
    )
    app, wheelhouse, digest = _environment(tmp_path, app_requires)
    target = "share/shared/catalog.bin"
    definitions = [
        ("owner-lib", "2.0", b"owner", owner_requires),
        ("base-lib", "1.0", b"base", base_requires),
    ]
    if scenario == "ambiguous-owner":
        definitions.append(("other-owner", "2.0", b"other", ("base-lib==1.0",)))
    for name, version, content, requires in definitions:
        source = _data_path(name, version, "data", target)
        _wheel(
            wheelhouse / f"{_canonical(name)}-{version}-py3-none-any.whl",
            name,
            version,
            {source: content},
            requires,
        )

    with pytest.raises(SystemExit):
        _read(app, wheelhouse, digest)


@pytest.mark.parametrize(
    "wheels",
    [
        (("1.0", "py3-none-any"), ("1.0", "cp314-cp314-linux_x86_64")),
        (("1.0", "py3-none-any"), ("2.0", "cp314-cp314-linux_x86_64")),
    ],
)
def test_duplicate_distribution_identity_is_rejected(
    tmp_path: Path, wheels: tuple[tuple[str, str], tuple[str, str]]
):
    """One environment cannot admit multiple wheel identities for one project."""
    app, wheelhouse, digest = _environment(tmp_path)
    for version, tag in wheels:
        _wheel(
            wheelhouse / f"duplicate_lib-{version}-{tag}.whl",
            "duplicate-lib",
            version,
            {"duplicate_lib/__init__.py": f"VERSION = {version!r}\n".encode()},
        )

    with pytest.raises(SystemExit):
        _read(app, wheelhouse, digest)
