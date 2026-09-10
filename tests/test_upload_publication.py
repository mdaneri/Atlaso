"""Prove overwrite consent and publication preserve existing artifacts."""

import asyncio

import pytest

from atlaso.app.services.upload_publication import (
    PublicationConflict,
    UploadPublication,
    revision,
)
from atlaso.app.services.vcf_sddc_upload import SddcUploadError, store_sddc_ova_upload
from tests.test_vcf_sddc_deployment import write_ova
from tests.test_vcf_sddc_upload import chunks


def test_changed_destination_and_unconfirmed_race_preserve_winner(tmp_path):
    """Reject stale consent and create-if-absent races.

    Args:
        tmp_path: Isolated artifact directory.
    """
    destination = tmp_path / "existing.iso"
    staged = tmp_path / "staged"
    staged.write_bytes(b"new")
    for original in (None, b"old"):
        destination.unlink(missing_ok=True)
        if original is not None:
            destination.write_bytes(original)
        publication = UploadPublication(destination, revision(destination))
        destination.write_bytes(b"concurrent winner")
        with pytest.raises(PublicationConflict):
            with publication.publish(staged, destination):
                pytest.fail("Stale consent must not publish")
        assert destination.read_bytes() == b"concurrent winner"


@pytest.mark.parametrize("audit_failure", [False, True])
def test_validated_ova_overwrite_and_audit_rollback(tmp_path, audit_failure):
    """Replace only validated media and retain the old OVA if auditing fails.

    Args:
        tmp_path: Isolated artifact directory.
        audit_failure: Whether audit persistence should reject publication.
    """
    root = tmp_path / "component"
    root.mkdir()
    destination = root / "existing.ova"
    destination.write_bytes(b"previous OVA")
    source = tmp_path / "source.ova"
    write_ova(source)
    publication = UploadPublication(destination, revision(destination))

    def audit(result):
        """Simulate the existing audit callback.

        Args:
            result: Published artifact metadata.
        """
        assert result["filename"] == destination.name
        if audit_failure:
            raise RuntimeError("Database unavailable")

    operation = store_sddc_ova_upload(chunks(source.read_bytes()), destination.name,
                                      root=root, publication=publication, on_publish=audit)
    if audit_failure:
        with pytest.raises(SddcUploadError, match="audited"):
            asyncio.run(operation)
    else:
        asyncio.run(operation)
    assert destination.read_bytes() == (b"previous OVA" if audit_failure else source.read_bytes())
    assert not list(tmp_path.glob(".sddc-upload-*"))


def test_invalid_ova_keeps_existing_artifact(tmp_path):
    """Validation failure must not touch the approved existing file.

    Args:
        tmp_path: Isolated artifact directory.
    """
    destination = tmp_path / "existing.ova"
    destination.write_bytes(b"old")
    publication = UploadPublication(destination, revision(destination))
    with pytest.raises(SddcUploadError, match="validation"):
        asyncio.run(store_sddc_ova_upload(chunks(b"invalid"), destination.name,
                                          root=tmp_path, publication=publication))
    assert destination.read_bytes() == b"old"


@pytest.mark.parametrize("audit_failure", [False, True])
def test_link_cleanup_failure_preserves_publication_outcome(tmp_path, monkeypatch, caplog, audit_failure):
    """Cleanup tries both links without replacing success or the original failure.

    Args:
        tmp_path: Private publication root.
        monkeypatch: Fixture injecting backup cleanup failure.
        caplog: Captured fixed cleanup warning.
        audit_failure: Whether the consuming operation rejects publication.
    """
    from pathlib import Path

    destination = tmp_path / "existing.iso"
    destination.write_bytes(b"old")
    staged = tmp_path / "staged"
    staged.write_bytes(b"new")
    publication = UploadPublication(destination, revision(destination))
    actual_unlink = Path.unlink
    attempts = []

    def failed_backup_cleanup(path, *args, **kwargs):
        """Fail only backup-link cleanup while recording both attempts.

        Args:
            path: Private link being removed.
            *args: Positional filesystem arguments.
            **kwargs: Keyword filesystem arguments.
        """
        attempts.append(path.name)
        if path.name.endswith(".previous"):
            raise OSError("private backup path")
        return actual_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", failed_backup_cleanup)

    def publish():
        """Run the consuming operation within the real publication boundary."""
        with publication.publish(staged, destination):
            if audit_failure:
                raise ValueError("original rejection")

    if audit_failure:
        with pytest.raises(ValueError, match="original rejection"):
            publish()
    else:
        publish()
    assert destination.read_bytes() == (b"old" if audit_failure else b"new")
    assert attempts == ["staged.previous", "staged.publish"]
    assert "Upload publication link cleanup could not be completed." in caplog.text
    assert "private backup path" not in caplog.text


@pytest.mark.parametrize("kind", ["iso", "vcfdt"])
def test_caller_staging_unlink_failure_preserves_success(tmp_path, monkeypatch, kind):
    """Both media services return success and metadata after a failed staging unlink.

    Args:
        tmp_path: Isolated upload root.
        monkeypatch: Fixture replacing filesystem cleanup.
        kind: Media storage service to exercise.
    """
    import io
    from pathlib import Path
    from types import SimpleNamespace

    from starlette.datastructures import UploadFile

    from atlaso.app import ui
    from atlaso.app.services import esxi_pxe
    from tests.test_ui import make_vcfdt_archive

    root = tmp_path / "uploads"
    root.mkdir()
    filename = "test.iso" if kind == "iso" else "vcf-download-tool-9.1.0.test.tar.gz"
    source = tmp_path / filename
    if kind == "iso":
        source.write_bytes(b"new ISO")
    else:
        make_vcfdt_archive(source)
    data = source.read_bytes()
    destination = root / filename
    destination.write_bytes(b"previous media")
    publication = UploadPublication(destination, revision(destination))
    upload = UploadFile(io.BytesIO(data), filename=filename)
    actual_unlink = Path.unlink
    attempted = []

    def fail_staging(path, *args, **kwargs):
        """Inject failure only for the caller-owned original staging link.

        Args:
            path: File being removed.
            *args: Positional filesystem arguments.
            **kwargs: Keyword filesystem arguments.
        """
        if path.name.endswith((".uploading", ".upload")):
            attempted.append(path)
            raise OSError("private staging location")
        return actual_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_staging)
    if kind == "iso":
        monkeypatch.setattr(esxi_pxe, "ESXI_INSTALLER_ISO_ROOT", root)
        result = asyncio.run(esxi_pxe.store_installer_iso_upload(upload, max_bytes=1024, publication=publication))
        assert result["relative_path"] == filename
    else:
        monkeypatch.setattr(ui, "VCF_DEPOT_UPLOAD_DIR", root)
        settings = SimpleNamespace(tool_archive_path="old", tool_version="old")
        result = ui.store_uploaded_vcf_depot_archive(settings, upload, publication=publication)
        assert result == filename
        assert settings.tool_archive_path == str(destination)
        assert settings.tool_version == ""
    assert destination.read_bytes() == data
    assert len(attempted) == 1
