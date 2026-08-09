"""Test vcf sddc deployment behavior."""

import hashlib
import io
import tarfile
from pathlib import Path

import pytest

from atlaso.app.services.vcf_sddc_deployment import (
    VcfSddcDeploymentError,
    _ensure_datastore_free_space,
    _lease_imported_entity,
    _upload_member,
    inspect_ova,
    normalize_disk_provisioning,
    ova_inventory,
    validate_ova_manifest,
)


OVF = b"""<?xml version="1.0"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1">
  <References><File ovf:id="file0" ovf:href="disk.vmdk" ovf:size="4" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"/></References>
  <NetworkSection><Network ovf:name="Network 1" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"/></NetworkSection>
  <VirtualSystem ovf:id="vm" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"><Name>SDDC-Test</Name>
    <ProductSection>
      <Property ovf:key="ROOT_PASSWORD" ovf:type="string" ovf:userConfigurable="true" ovf:password="true"><Label>Root password</Label><Description>One-time root password.</Description></Property>
      <Property ovf:key="hidden" ovf:type="string" ovf:value="internal"/>
      <Property ovf:key="vami.hostname" ovf:type="string" ovf:userConfigurable="true"><Label>FQDN</Label></Property>
    </ProductSection>
  </VirtualSystem>
</Envelope>
"""
DISK = b"disk"


def write_ova(path: Path, *, corrupt_manifest: bool = False) -> None:
    """Persist ova.

    Args:
        path: Filesystem or URL path to read, validate, or update.
        corrupt_manifest: Corrupt manifest supplied by the caller.
    """
    ovf_digest = hashlib.sha256(OVF).hexdigest()
    disk_digest = "0" * 64 if corrupt_manifest else hashlib.sha256(DISK).hexdigest()
    manifest = f"SHA256(test.ovf)= {ovf_digest}\nSHA256(disk.vmdk)= {disk_digest}\n".encode()
    with tarfile.open(path, "w") as archive:
        for name, body in (("test.ovf", OVF), ("test.mf", manifest), ("disk.vmdk", DISK)):
            info = tarfile.TarInfo(name)
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))


def test_inspect_ova_exposes_only_user_configurable_properties(tmp_path):
    """Verify that inspect ova exposes only user configurable properties.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    ova = tmp_path / "SDDC.OVA"
    write_ova(ova)
    descriptor = inspect_ova(ova, root=tmp_path)

    assert descriptor.vm_name == "SDDC-Test"
    assert descriptor.networks == ["Network 1"]
    assert descriptor.files == [{"id": "file0", "href": "disk.vmdk", "size_bytes": 4}]
    assert [item.key for item in descriptor.properties] == ["ROOT_PASSWORD", "vami.hostname"]
    assert descriptor.properties[0].password is True
    validate_ova_manifest(descriptor)
    assert ova_inventory(root=tmp_path)[0]["filename"] == "SDDC.OVA"


def test_ova_path_and_manifest_validation_are_strict(tmp_path):
    """Verify that ova path and manifest validation are strict.

    Args:
        tmp_path: Temporary directory provided by pytest for isolated filesystem state.
    """
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.ova"
    write_ova(outside)
    with pytest.raises(VcfSddcDeploymentError, match="inside"):
        inspect_ova(outside, root=root)

    corrupt = root / "corrupt.ova"
    write_ova(corrupt, corrupt_manifest=True)
    descriptor = inspect_ova(corrupt, root=root)
    with pytest.raises(VcfSddcDeploymentError, match="manifest validation failed"):
        validate_ova_manifest(descriptor)


def test_nfc_upload_uses_stream_vmdk_post(monkeypatch):
    """Verify that nfc upload uses stream vmdk post.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
    """
    class Response:
        """Represent response.

        Attributes:
            status: Current lifecycle or operation status.
        """
        status = 200

        def read(self, _size=-1):
            """Return operation.

            Args:
                _size: Size supplied to the test scenario.
            """
            return b""

    class Connection:
        """Represent connection.

        Attributes:
            instances: Instances captured or supplied by this test helper.
            host: Host captured or supplied by this test helper.
            port: Port captured or supplied by this test helper.
            method: Method captured or supplied by this test helper.
            target: Target captured or supplied by this test helper.
            headers: Headers captured or supplied by this test helper.
            body: Body captured or supplied by this test helper.
        """
        instances = []

        def __init__(self, host, port, **_kwargs):
            """Initialize the connection.

            Args:
                host: Host supplied to the test scenario.
                port: Network port contacted, validated, or configured by the operation.
                **_kwargs: Additional keyword arguments accepted by the callable.
            """
            self.host = host
            self.port = port
            self.method = ""
            self.target = ""
            self.headers = {}
            self.body = b""
            Connection.instances.append(self)

        def putrequest(self, method, target):
            """Handle putrequest.

            Args:
                method: Method supplied to the test scenario.
                target: Target resource or location affected by the operation.
            """
            self.method = method
            self.target = target

        def putheader(self, name, value):
            """Handle putheader.

            Args:
                name: Stable name identifying the resource or operation.
                value: Candidate value consumed by putheader.
            """
            self.headers[name] = value

        def endheaders(self):
            """Handle endheaders."""
            pass

        def send(self, chunk):
            """Handle send.

            Args:
                chunk: Chunk supplied to the test scenario.
            """
            self.body += chunk

        def getresponse(self):
            """Return getresponse."""
            return Response()

        def close(self):
            """Handle close."""
            pass

    class Lease:
        """Represent lease.

        Attributes:
            progress: Progress captured or supplied by this test helper.
        """
        def __init__(self):
            """Initialize the lease."""
            self.progress = []

        def HttpNfcLeaseProgress(self, percent):
            """Handle http nfc lease progress.

            Args:
                percent: Percent supplied to the test scenario.
            """
            self.progress.append(percent)

    monkeypatch.setattr("http.client.HTTPConnection", Connection)
    lease = Lease()

    _upload_member(
        "http://*/nfc/disk1.vmdk?dcPath=ha-datacenter",
        io.BytesIO(b"vmdk"),
        4,
        endpoint="192.0.2.10",
        name="disk1.vmdk",
        transferred=[0],
        total=4,
        lease=lease,
        progress=None,
    )

    connection = Connection.instances[0]
    assert connection.host == "192.0.2.10"
    assert connection.method == "POST"
    assert connection.target == "/nfc/disk1.vmdk?dcPath=ha-datacenter"
    assert connection.headers["Content-Length"] == "4"
    assert connection.headers["Content-Type"] == "application/x-vnd.vmware-streamVmdk"
    assert connection.body == b"vmdk"
    assert lease.progress == [99]


def test_disk_provisioning_and_datastore_free_space_validation():
    """Verify that disk provisioning and datastore free space validation."""
    assert normalize_disk_provisioning("") == "thin"
    assert normalize_disk_provisioning("thick") == "thick"
    with pytest.raises(VcfSddcDeploymentError, match="thin or thick"):
        normalize_disk_provisioning("eagerZeroedThick")

    class Summary:
        """Represent summary.

        Attributes:
            freeSpace: Freespace captured or supplied by this test helper.
        """
        freeSpace = 1024

    class Datastore:
        """Represent datastore.

        Attributes:
            name: Operator-facing name of the resource.
            summary: Summary captured or supplied by this test helper.
        """
        name = "tiny-datastore"
        summary = Summary()

    with pytest.raises(VcfSddcDeploymentError, match="tiny-datastore"):
        _ensure_datastore_free_space(Datastore(), 2048)


def test_imported_entity_is_captured_before_lease_completion():
    """Verify that imported entity is captured before lease completion."""
    class Vm:
        """Represent vm.

        Attributes:
            name: Operator-facing name of the resource.
        """
        name = "sddcm"

    class Info:
        """Represent info.

        Attributes:
            entity: Entity captured or supplied by this test helper.
        """
        entity = Vm()

    class Lease:
        """Represent lease.

        Attributes:
            info: Info captured or supplied by this test helper.
        """
        info = Info()

        def HttpNfcLeaseComplete(self):
            """Handle http nfc lease complete."""
            self.info = None

    lease = Lease()
    vm = _lease_imported_entity(lease)
    lease.HttpNfcLeaseComplete()

    assert vm.name == "sddcm"
    with pytest.raises(VcfSddcDeploymentError, match="imported VM reference"):
        _lease_imported_entity(lease)
