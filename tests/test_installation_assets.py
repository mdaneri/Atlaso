from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from scripts.installation import assets


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_small_iso_is_copied_as_one_asset_and_reassembled(tmp_path: Path) -> None:
    source = tmp_path / "source.iso"
    package = tmp_path / "package"
    package.mkdir()
    output = tmp_path / "restored.iso"
    source.write_bytes(b"offline image")

    manifest = assets.split_iso(source, package)
    assets.verify_and_reassemble(manifest, package, output)

    assert manifest == {
        "schema": 1,
        "iso": {"name": "source.iso", "size": 13, "sha256": _sha(b"offline image")},
        "assets": [{"name": "source.iso", "size": 13, "sha256": _sha(b"offline image")}],
    }
    assert output.read_bytes() == source.read_bytes()


def test_empty_iso_is_a_valid_single_asset(tmp_path: Path) -> None:
    source = tmp_path / "empty.iso"
    package = tmp_path / "package"
    package.mkdir()
    source.touch()

    manifest = assets.split_iso(source, package)

    assert manifest["iso"]["size"] == 0
    assert manifest["assets"][0]["size"] == 0
    assets.verify_and_reassemble(manifest, package, tmp_path / "restored.iso")
    assert (tmp_path / "restored.iso").read_bytes() == b""


def test_large_iso_parts_are_ordered_and_reassemble_exactly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(assets, "GITHUB_ASSET_LIMIT", 8)
    source = tmp_path / "large.iso"
    package = tmp_path / "package"
    package.mkdir()
    output = tmp_path / "restored.iso"
    source.write_bytes(b"abcdefghijk")

    manifest = assets.split_iso(source, package, part_bytes=4)

    assert [entry["name"] for entry in manifest["assets"]] == [
        "large.iso.part0001",
        "large.iso.part0002",
        "large.iso.part0003",
    ]
    assert [entry["size"] for entry in manifest["assets"]] == [4, 4, 3]
    assets.verify_and_reassemble(manifest, package, output)
    assert output.read_bytes() == source.read_bytes()


def test_iso_at_asset_limit_is_split(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(assets, "GITHUB_ASSET_LIMIT", 4)
    source = tmp_path / "at-limit.iso"
    package = tmp_path / "package"
    package.mkdir()
    source.write_bytes(b"four")

    manifest = assets.split_iso(source, package, part_bytes=4)

    assert [entry["name"] for entry in manifest["assets"]] == ["at-limit.iso.part0001"]
    assert source.read_bytes() == b"four"


@pytest.mark.parametrize("part_bytes", [0, -1, assets.MAX_PART_BYTES + 1, True])
def test_split_rejects_invalid_part_size(tmp_path: Path, part_bytes: int) -> None:
    source = tmp_path / "source.iso"
    package = tmp_path / "package"
    package.mkdir()
    source.write_bytes(b"x")

    with pytest.raises(ValueError, match="part_bytes"):
        assets.split_iso(source, package, part_bytes=part_bytes)


def test_split_does_not_overwrite_existing_asset(tmp_path: Path) -> None:
    source = tmp_path / "same.iso"
    package = tmp_path / "package"
    package.mkdir()
    source.write_bytes(b"source")
    existing = package / source.name
    existing.write_bytes(b"keep")

    with pytest.raises(FileExistsError):
        assets.split_iso(source, package)

    assert existing.read_bytes() == b"keep"


def test_reassembly_does_not_overwrite_existing_output(tmp_path: Path) -> None:
    source = tmp_path / "source.iso"
    package = tmp_path / "package"
    package.mkdir()
    source.write_bytes(b"source")
    manifest = assets.split_iso(source, package)
    output = tmp_path / "restored.iso"
    output.write_bytes(b"keep")

    with pytest.raises(FileExistsError):
        assets.verify_and_reassemble(manifest, package, output)

    assert output.read_bytes() == b"keep"


def test_reassembly_verifies_every_part_before_creating_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(assets, "GITHUB_ASSET_LIMIT", 4)
    source = tmp_path / "large.iso"
    package = tmp_path / "package"
    package.mkdir()
    source.write_bytes(b"abcdefgh")
    manifest = assets.split_iso(source, package, part_bytes=4)
    (package / "large.iso.part0002").write_bytes(b"bad!")
    output = tmp_path / "restored.iso"

    with pytest.raises(ValueError, match="checksum or size mismatch"):
        assets.verify_and_reassemble(manifest, package, output)

    assert not output.exists()


def test_reassembly_removes_only_its_incomplete_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(assets, "GITHUB_ASSET_LIMIT", 4)
    source = tmp_path / "large.iso"
    package = tmp_path / "package"
    package.mkdir()
    source.write_bytes(b"abcdefgh")
    manifest = assets.split_iso(source, package, part_bytes=4)
    original_open = assets._open_regular
    calls = 0

    def mutate_after_preflight(path: Path):
        nonlocal calls
        calls += 1
        if calls == 3:
            (package / "large.iso.part0001").write_bytes(b"evil")
        return original_open(path)

    monkeypatch.setattr(assets, "_open_regular", mutate_after_preflight)
    output = tmp_path / "restored.iso"

    with pytest.raises(ValueError, match="changed after verification"):
        assets.verify_and_reassemble(manifest, package, output)

    assert not output.exists()


def test_reassembly_rejects_traversal_duplicates_missing_and_extra_entries(tmp_path: Path) -> None:
    package = tmp_path / "package"
    package.mkdir()
    source = tmp_path / "image.iso"
    source.write_bytes(b"image")
    manifest = assets.split_iso(source, package)
    output = tmp_path / "restored.iso"

    for mutate in (
        lambda value: value["assets"][0].update(name="../image.iso"),
        lambda value: value["assets"][0].update(name="C:image.iso"),
        lambda value: value["assets"][0].update(name="image.iso\nextra"),
        lambda value: value["assets"].append(dict(value["assets"][0])),
        lambda value: value.update(extra=True),
        lambda value: value["assets"].clear(),
    ):
        altered = {"schema": 1, "iso": dict(manifest["iso"]), "assets": [dict(x) for x in manifest["assets"]]}
        mutate(altered)
        with pytest.raises(ValueError):
            assets.verify_and_reassemble(altered, package, output)
        assert not output.exists()


def test_reassembly_rejects_extra_split_manifest_part(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(assets, "GITHUB_ASSET_LIMIT", 4)
    source = tmp_path / "image.iso"
    package = tmp_path / "package"
    package.mkdir()
    source.write_bytes(b"abcdefgh")
    manifest = assets.split_iso(source, package, part_bytes=4)
    manifest["assets"].append(dict(manifest["assets"][-1], name="image.iso.part0003"))

    with pytest.raises(ValueError, match="sizes do not match"):
        assets.verify_and_reassemble(manifest, package, tmp_path / "restored.iso")


@pytest.mark.skipif(not hasattr(os, "link"), reason="hard links are unavailable")
def test_reassembly_rejects_hard_linked_assets(tmp_path: Path) -> None:
    package = tmp_path / "package"
    package.mkdir()
    source = tmp_path / "image.iso"
    source.write_bytes(b"image")
    manifest = assets.split_iso(source, package)
    os.link(package / "image.iso", package / "alias")

    with pytest.raises(ValueError, match="single-link"):
        assets.verify_and_reassemble(manifest, package, tmp_path / "restored.iso")


def test_reassembly_rejects_symlinked_ancestry(tmp_path: Path) -> None:
    package = tmp_path / "package"
    package.mkdir()
    source = tmp_path / "image.iso"
    source.write_bytes(b"image")
    manifest = assets.split_iso(source, package)
    linked = tmp_path / "linked"
    linked.symlink_to(package, target_is_directory=True)

    with pytest.raises(ValueError, match="symbolic links"):
        assets.verify_and_reassemble(manifest, linked, tmp_path / "restored.iso")
