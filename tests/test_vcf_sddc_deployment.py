"""Test vcf sddc deployment behavior."""

import hashlib
import io
import tarfile
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace

import pytest

from atlaso.app.services.vcf_sddc_deployment import (
    VcfSddcDeploymentError,
    VcfSddcPostImportError,
    _ensure_datastore_free_space,
    _lease_imported_entity,
    _ovf_environment_from_vmx,
    _ovf_environment_xml,
    _parse_vsphere_ovf_descriptor,
    _read_persisted_ovf_environment,
    _standalone_ovf_properties,
    _upload_member,
    _verify_guestinfo_ovf_environment,
    _verify_imported_ovf_environment,
    complete_property_mapping,
    deploy_ova,
    inspect_ova,
    normalize_disk_provisioning,
    ova_inventory,
    validate_ova_manifest,
)

OVF_PLATFORM = {"Kind": "VMware ESXi", "Version": "9.1.0", "Vendor": "VMware, Inc.", "Locale": "en"}

OVF = b"""<?xml version="1.0"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1">
  <References><File ovf:id="file0" ovf:href="disk.vmdk" ovf:size="4" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"/></References>
  <NetworkSection><Network ovf:name="Network 1" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"/></NetworkSection>
  <VirtualSystem ovf:id="vm" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"><Name>SDDC-Test</Name>
    <ProductSection>
      <Product>VCF Installer</Product><Version>9.1.0</Version>
      <Property ovf:key="ROOT_PASSWORD" ovf:type="string" ovf:userConfigurable="true" ovf:password="true"><Label>Root password</Label><Description>One-time root password.</Description></Property>
      <Property ovf:key="hidden" ovf:type="string" ovf:value="internal"/>
      <Property ovf:key="vami.hostname" ovf:type="string" ovf:userConfigurable="true" ovf:value="sddc.example.test"><Label>FQDN</Label></Property>
    </ProductSection>
    <VirtualHardwareSection ovf:transport="com.vmware.guestInfo"/>
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


def test_vsphere_descriptor_controls_properties_defaults_options_and_warnings(tmp_path):
    """Use the target parser as the authoritative deployable-property contract.

    Args:
        tmp_path: Temporary directory used to build the fixture OVA.
    """
    ova = tmp_path / "SDDC.OVA"
    write_ova(ova)
    descriptor = inspect_ova(ova, root=tmp_path)
    parsed = SimpleNamespace(
        error=[],
        warning=[SimpleNamespace(localizedMessage="Ignored default sddc.example.test")],
        property=[
            SimpleNamespace(id="ROOT_PASSWORD", type="password", label="Root", description="Secret", defaultValue="", userConfigurable=True),
            SimpleNamespace(id="vami.hostname", type="string", label="FQDN", description="Host", defaultValue="", userConfigurable=True),
            SimpleNamespace(id="target_only", type="string", label="Target only", description="Target property", defaultValue="enabled", userConfigurable=None),
            SimpleNamespace(id="hidden", type="string", label="Hidden", description="System", defaultValue="internal", userConfigurable=False),
        ],
        deploymentOption=[SimpleNamespace(key="small", label="Small", description="Lab footprint")],
        defaultDeploymentOption="small",
        defaultEntityName="Target-SDDC",
    )
    manager = SimpleNamespace(ParseDescriptor=lambda _text, params: parsed)
    authoritative = _parse_vsphere_ovf_descriptor(
        SimpleNamespace(ovfManager=manager),
        descriptor,
        deployment_option="small",
        property_values={"vami.hostname": "sddc.example.test"},
    )

    assert [item.key for item in authoritative.properties] == ["ROOT_PASSWORD", "vami.hostname", "target_only"]
    assert authoritative.properties[0].password is True
    assert authoritative.properties[1].default == ""
    assert authoritative.default_deployment_option == "small"
    assert authoritative.selected_deployment_option == "small"
    assert authoritative.deployment_options[0].description == "Lab footprint"
    assert "sddc.example.test" not in " ".join(authoritative.warnings)
    submitted = {
        "ROOT_PASSWORD": "one-time-secret",
        "vami.hostname": "",
        "target_only": "enabled",
    }
    assert complete_property_mapping(authoritative, submitted) == submitted
    with pytest.raises(VcfSddcDeploymentError, match="changed after review") as missing:
        complete_property_mapping(authoritative, {"ROOT_PASSWORD": "one-time-secret", "vami.hostname": ""})
    assert "target_only" in str(missing.value)
    assert "one-time-secret" not in str(missing.value)
    with pytest.raises(VcfSddcDeploymentError, match="changed after review") as unknown:
        complete_property_mapping(authoritative, {**submitted, "unknown": "value"})
    assert "unknown" in str(unknown.value)


def test_imported_ovf_verification_requires_all_keys_and_transport():
    """Reject an imported VM that lost metadata or guest environment transport."""
    descriptor = SimpleNamespace(ovf_environment_transports=["com.vmware.guestInfo", "iso"])
    complete_vm = SimpleNamespace(
        config=SimpleNamespace(
            vAppConfig=SimpleNamespace(
                property=[
                    SimpleNamespace(id="ROOT_PASSWORD", value="secret"),
                    SimpleNamespace(id="vami.hostname", value="sddc.example.test"),
                ],
                ovfEnvironmentTransport=["com.vmware.guestInfo"],
            )
        )
    )
    evidence = _verify_imported_ovf_environment(
        complete_vm,
        descriptor,
        {"ROOT_PASSWORD": "secret", "vami.hostname": "sddc.example.test"},
    )
    assert evidence == {
        "property_keys": ["ROOT_PASSWORD", "vami.hostname"],
        "transports": ["com.vmware.guestInfo"],
    }

    incomplete_vm = SimpleNamespace(
        config=SimpleNamespace(
            vAppConfig=SimpleNamespace(
                property=[SimpleNamespace(id="ROOT_PASSWORD")],
                ovfEnvironmentTransport=[],
            )
        )
    )
    with pytest.raises(VcfSddcDeploymentError, match="vami.hostname"):
        _verify_imported_ovf_environment(
            incomplete_vm,
            descriptor,
            {"ROOT_PASSWORD": "secret", "vami.hostname": "sddc.example.test"},
        )

    rewritten_vm = SimpleNamespace(
        config=SimpleNamespace(
            vAppConfig=SimpleNamespace(
                property=[
                    SimpleNamespace(id="ROOT_PASSWORD", value="rewritten-secret"),
                    SimpleNamespace(id="vami.hostname", value="sddc.example.test"),
                ],
                ovfEnvironmentTransport=["com.vmware.guestInfo"],
            )
        )
    )
    with pytest.raises(VcfSddcDeploymentError, match="ROOT_PASSWORD") as mismatch:
        _verify_imported_ovf_environment(
            rewritten_vm,
            descriptor,
            {"ROOT_PASSWORD": "secret", "vami.hostname": "sddc.example.test"},
        )
    assert "secret" not in str(mismatch.value)


@pytest.mark.parametrize(
    ("api_type", "expected_host", "complete_metadata", "failure_mode"),
    [
        ("HostAgent", True, True, ""),
        ("VirtualCenter", False, True, ""),
        ("HostAgent", True, False, ""),
        ("VirtualCenter", False, False, ""),
        ("HostAgent", True, True, "reconfigure"),
        ("HostAgent", True, False, "rollback"),
        ("HostAgent", True, True, "cancel-reconfigure"),
        ("HostAgent", True, True, "cancel-readback"),
        ("VirtualCenter", False, True, "cancel-readback"),
        ("HostAgent", True, True, "cancel-reconfigure-off"),
        ("HostAgent", True, True, "cancel-readback-off"),
        ("VirtualCenter", False, True, "cancel-readback-off"),
        ("HostAgent", True, True, "spec-error"),
    ],
)
def test_deploy_ova_binds_standalone_host_and_preserves_vcenter_automatic_placement(
    tmp_path,
    monkeypatch,
    api_type,
    expected_host,
    complete_metadata,
    failure_mode,
):
    """Pass complete mappings and deterministic direct-ESXi placement through import.

    Args:
        tmp_path: Temporary directory used to build the fixture OVA.
        monkeypatch: Pytest helper used to isolate vSphere integration boundaries.
        api_type: VMware endpoint API type exercised by this parameter set.
        expected_host: Whether import placement must bind the standalone host.
        complete_metadata: Whether the imported VM retains valid OVF metadata.
        failure_mode: Optional VMware configuration or rollback failure.
    """
    from pyVmomi import vim

    ova = tmp_path / "SDDC.OVA"
    write_ova(ova)
    descriptor = inspect_ova(ova, root=tmp_path)
    host = SimpleNamespace(_moId="host-1")
    datastore = SimpleNamespace(_moId="datastore-1", name="datastore", summary=SimpleNamespace(freeSpace=10**12))
    network = SimpleNamespace(_moId="network-1")
    captured = {}

    class Task:
        """Represent an immediately successful vSphere task."""

        info = SimpleNamespace(state="success", result=None, error=None)

    class Vm:
        """Represent the exact lease-created VM."""

        _moId = "vm-595"
        name = "sddc-test"
        runtime = SimpleNamespace(powerState="poweredOff")
        guest = SimpleNamespace(ipAddress="192.0.2.10")
        config = SimpleNamespace(
            vAppConfig=SimpleNamespace(
                property=[
                    SimpleNamespace(id="ROOT_PASSWORD", value="one-time-secret"),
                    SimpleNamespace(id="vami.hostname", value="target.example.test"),
                ],
                ovfEnvironmentTransport=["com.vmware.guestInfo"] if complete_metadata else [],
            ) if api_type == "VirtualCenter" else None,
            extraConfig=[],
        )

        def Reload(self):
            """Record a fresh VM readback."""
            captured["reloaded"] = True

        def ReconfigVM_Task(self, spec):
            """Persist or deliberately discard the guest-info environment.

            Args:
                spec: Requested virtual-machine configuration change.
            """
            captured["reconfigured"] = True
            if failure_mode == "reconfigure":
                raise RuntimeError(spec.extraConfig[0].value)
            self.config.extraConfig = list(spec.extraConfig) if complete_metadata else []
            return Task()

        def PowerOnVM_Task(self):
            """Ensure verification completed before any power-on."""
            assert captured["reloaded"] is True
            if api_type == "HostAgent":
                assert self.config.extraConfig
            captured["powered_on"] = True
            return Task()

        def Destroy_Task(self):
            """Return a successful destroy task."""
            captured["destroyed"] = True
            if failure_mode == "rollback":
                raise RuntimeError("controlled rollback failure")
            return Task()

    vm = Vm()

    class Lease:
        """Represent a ready push-mode lease."""

        state = "ready"
        error = None
        info = SimpleNamespace(entity=vm, deviceUrl=[])

        def HttpNfcLeaseComplete(self):
            """Complete the lease."""
            self.state = "done"

        def HttpNfcLeaseAbort(self):
            """Abort the lease."""
            self.state = "error"

    lease = Lease()

    class Pool:
        """Capture ImportVApp placement."""

        _moId = "resgroup-1"

        def ImportVApp(self, import_spec, folder, selected_host):
            """Return the prepared lease.

            Args:
                import_spec: VMware import specification under test.
                folder: Destination folder supplied to the import call.
                selected_host: Explicit standalone host or automatic placement.
            """
            captured["import_spec"] = import_spec
            captured["folder"] = folder
            captured["import_host"] = selected_host
            return lease

    pool = Pool()
    parsed = SimpleNamespace(
        error=[],
        warning=[],
        property=[
            SimpleNamespace(id="ROOT_PASSWORD", type="password", label="Root", description="Secret", defaultValue="", userConfigurable=True),
            SimpleNamespace(id="vami.hostname", type="string", label="FQDN", description="Host", defaultValue="target.example.test", userConfigurable=True),
        ],
        deploymentOption=[SimpleNamespace(key="small", label="Small", description="Lab")],
        defaultDeploymentOption="small",
        defaultEntityName="sddc-test",
    )

    class OvfManager:
        """Capture target parse and import-spec inputs."""

        def ParseDescriptor(self, _text, _params):
            """Return the authoritative target contract.

            Args:
                _text: OVF descriptor text supplied to VMware.
                _params: VMware descriptor parsing parameters.
            """
            return parsed

        def CreateImportSpec(self, _text, _pool, _datastore, params):
            """Return an import spec with one sanitized warning.

            Args:
                _text: OVF descriptor text supplied to VMware.
                _pool: Destination resource pool.
                _datastore: Destination datastore.
                params: VMware import parameters under test.
            """
            captured["params"] = params
            if failure_mode == "spec-error":
                return SimpleNamespace(error=[SimpleNamespace(localizedMessage="Rejected one-time-secret and default-only-secret")], importSpec=None)
            return SimpleNamespace(
                error=[],
                warning=[SimpleNamespace(localizedMessage="Accepted one-time-secret for ROOT_PASSWORD and default-only-secret")],
                fileItem=[],
                importSpec=SimpleNamespace(configSpec=SimpleNamespace(vAppConfig=SimpleNamespace(
                    property=[SimpleNamespace(info=item) for item in parsed.property] + [SimpleNamespace(info=SimpleNamespace(id="hidden", defaultValue="default-only-secret"))],
                    ovfEnvironmentTransport=[],
                ))),
            )

    content = SimpleNamespace(
        about=SimpleNamespace(apiType=api_type, version="9.1.0", vendor="VMware, Inc."),
        ovfManager=OvfManager(),
    )
    service_instance = SimpleNamespace(RetrieveContent=lambda: content)
    monkeypatch.setattr("atlaso.app.services.vcf_sddc_deployment.connect_vsphere", lambda *_args, **_kwargs: service_instance)
    monkeypatch.setattr("pyVim.connect.Disconnect", lambda _instance: None)

    def walk(_content, vim_types):
        """Return only the requested inventory objects.

        Args:
            _content: Connected vSphere service content.
            vim_types: Inventory object types requested by the deployment.
        """
        if vim_types == [vim.VirtualMachine]:
            return []
        if vim_types == [vim.HostSystem]:
            return [host]
        return []

    monkeypatch.setattr("atlaso.app.services.vcf_sddc_deployment._walk_inventory", walk)

    def find(_content, _vim_type, _object_id, label):
        """Resolve the bounded test destination.

        Args:
            _content: Connected vSphere service content.
            _vim_type: Inventory type requested by the deployment.
            _object_id: Managed-object identifier requested by the deployment.
            label: Human-readable destination category.
        """
        return {"resource pool": pool, "datastore": datastore, "network": network}[label]

    monkeypatch.setattr("atlaso.app.services.vcf_sddc_deployment._find_object", find)
    monkeypatch.setattr(vim.OvfManager, "NetworkMapping", lambda **values: SimpleNamespace(**values))
    monkeypatch.setattr(vim.OvfManager, "CreateImportSpecParams", lambda **values: SimpleNamespace(**values))
    monkeypatch.setattr(vim, "KeyValue", lambda **values: SimpleNamespace(**values))
    def deploy():
        """Run the deployment against the exact prepared target fixture."""
        return deploy_ova(
            descriptor,
            endpoint="esxi.example.test",
            username="administrator",
            password="vsphere-secret",
            resource_pool_id="resgroup-1",
            datastore_id="datastore-1",
            network_ids={"Network 1": "network-1"},
            vm_name="sddc-test",
            property_values={"ROOT_PASSWORD": "one-time-secret", "vami.hostname": "target.example.test"},
            deployment_option="small",
            power_on=not failure_mode.endswith("-off"),
            cancelled=lambda: bool(
                (failure_mode.startswith("cancel-reconfigure") and captured.get("reconfigured"))
                or (failure_mode.startswith("cancel-readback") and captured.get("reloaded"))
            ),
        )
    if failure_mode == "spec-error":
        with pytest.raises(VcfSddcDeploymentError, match="rejected the standalone OVA import specification") as caught:
            deploy()
        assert "one-time-secret" not in str(caught.value)
        assert "default-only-secret" not in str(caught.value)
        assert "import_host" not in captured
        return
    if failure_mode.startswith("cancel-"):
        with pytest.raises(VcfSddcPostImportError, match="cancelled") as caught:
            deploy()
        assert caught.value.vm_result["vm_id"] == vm._moId
        assert "powered_on" not in captured
        assert "destroyed" not in captured
        assert vm.runtime.powerState == "poweredOff"
        return
    if failure_mode:
        error_type = VcfSddcPostImportError if failure_mode == "rollback" else VcfSddcDeploymentError
        with pytest.raises(error_type) as caught:
            deploy()
        assert "one-time-secret" not in str(caught.value)
        assert "<" not in str(caught.value)
        assert captured["destroyed"] is True
        assert "powered_on" not in captured
        if failure_mode == "rollback":
            assert caught.value.vm_result["vm_id"] == vm._moId
        return
    if not complete_metadata:
        with pytest.raises(VcfSddcDeploymentError, match="exact incomplete VM was removed"):
            deploy()
        assert captured["destroyed"] is True
        assert "powered_on" not in captured
        return
    result = deploy()

    mapping = {item.key: item.value for item in captured["params"].propertyMapping}
    assert mapping == {"ROOT_PASSWORD": "one-time-secret", "vami.hostname": "target.example.test"}
    assert captured["params"].deploymentOption == "small"
    assert (getattr(captured["params"], "hostSystem", None) is host) is expected_host
    assert (captured["import_host"] is host) is expected_host
    assert "one-time-secret" not in " ".join(result["warnings"])
    assert result["api_type"] == api_type
    assert result["ovf_verification"]["transports"] == ["com.vmware.guestInfo"]
    if api_type == "HostAgent":
        assert "default-only-secret" not in " ".join(result["warnings"])
        assert captured["reconfigured"] is True
        assert captured["reloaded"] is True
        assert result["ovf_verification"]["source"] == "guestinfo.ovfEnv"
        assert vm.config.vAppConfig is None
    else:
        assert "reconfigured" not in captured
    assert "destroyed" not in captured
    assert captured["powered_on"] is True


def test_standalone_environment_preserves_qualified_keys_and_reviewed_empty_values(tmp_path):
    """Use import metadata for namespace qualification without replacing reviewed values.

    Args:
        tmp_path: Isolated fixture directory.
    """
    ova = tmp_path / "test.ova"
    write_ova(ova)
    descriptor = inspect_ova(ova, root=tmp_path)
    rows = [
        SimpleNamespace(id="ROOT_PASSWORD", value="", defaultValue="", classId="", instanceId=""),
        SimpleNamespace(id="ip0", value="", defaultValue="default-address", classId="vami", instanceId="SDDC-Manager"),
        SimpleNamespace(id="hidden", value="", defaultValue="internal", classId="", instanceId=""),
    ]
    spec = SimpleNamespace(configSpec=SimpleNamespace(vAppConfig=SimpleNamespace(property=[SimpleNamespace(info=row) for row in rows])))
    values = {"ROOT_PASSWORD": 'secret<&"\t\nvalue', "ip0": ""}
    properties = _standalone_ovf_properties(spec, descriptor, values)
    assert properties == {"ROOT_PASSWORD": values["ROOT_PASSWORD"], "vami.ip0.SDDC-Manager": "", "hidden": "internal"}
    payload = _ovf_environment_xml(properties, platform=OVF_PLATFORM)
    environment = ET.fromstring(payload)
    assert [child.tag.rsplit("}", 1)[-1] for child in environment] == ["PlatformSection", "PropertySection"]
    assert {child.tag.rsplit("}", 1)[-1]: child.text for child in environment[0]} == OVF_PLATFORM
    vm = SimpleNamespace(Reload=lambda: None, config=SimpleNamespace(extraConfig=[SimpleNamespace(key="guestinfo.ovfEnv", value=payload)]))
    result = _verify_guestinfo_ovf_environment(vm, properties, platform=OVF_PLATFORM)
    assert result["property_keys"] == ["ROOT_PASSWORD", "hidden", "vami.ip0.SDDC-Manager"]
    assert values["ROOT_PASSWORD"] not in str(result)
    spec.configSpec.vAppConfig.property.append(SimpleNamespace(info=rows[1]))
    with pytest.raises(VcfSddcDeploymentError, match="ambiguous"):
        _standalone_ovf_properties(spec, descriptor, values)


@pytest.mark.parametrize("damage", ["transport", "metadata", "unidentified", "omitted"])
def test_standalone_environment_rejects_incomplete_import_contract(damage):
    """Reject unsupported specifications before creating a VM or uploading disks.

    Args:
        damage: Missing part of the target-generated import contract.
    """
    descriptor = SimpleNamespace(ovf_environment_transports=["com.vmware.guestInfo"])
    info = SimpleNamespace(id="ROOT_PASSWORD", classId="", instanceId="")
    spec = SimpleNamespace(configSpec=SimpleNamespace(vAppConfig=SimpleNamespace(property=[SimpleNamespace(info=info)])))
    if damage == "transport":
        descriptor.ovf_environment_transports = ["iso"]
    elif damage == "metadata":
        spec.configSpec.vAppConfig = None
    elif damage == "unidentified":
        info.id = ""
    else:
        info.id = "different"
    with pytest.raises(VcfSddcDeploymentError) as caught:
        _standalone_ovf_properties(spec, descriptor, {"ROOT_PASSWORD": "secret-value"})
    assert "secret-value" not in str(caught.value)


@pytest.mark.parametrize("damage", ["missing", "mismatch", "duplicate", "namespace", "malformed", "dtd", "oversized", "platform_missing", "platform_duplicate", "platform_order", "platform_value"])
def test_guestinfo_verification_rejects_incomplete_or_ambiguous_documents(damage):
    """Reject malformed or changed readback without disclosing serialized secrets.

    Args:
        damage: Specific corruption applied to the persisted guest environment.
    """
    properties = {"ROOT_PASSWORD": "secret<&value", "vami.ip0.SDDC-Manager": ""}
    root = ET.fromstring(_ovf_environment_xml(properties, platform=OVF_PLATFORM))
    section = root[1]
    if damage == "missing":
        section.remove(section[0])
    elif damage == "mismatch":
        section[0].set("{http://schemas.dmtf.org/ovf/environment/1}value", "different")
    elif damage == "duplicate":
        section.append(ET.fromstring(ET.tostring(section[0])))
    elif damage == "namespace":
        root.tag = "Environment"
    elif damage == "platform_missing":
        root.remove(root[0])
    elif damage == "platform_duplicate":
        root.insert(0, ET.fromstring(ET.tostring(root[0])))
    elif damage == "platform_order":
        root.append(root[0])
        root.remove(root[0])
    elif damage == "platform_value":
        root[0][1].text = "different-version"
    payload = ET.tostring(root, encoding="unicode")
    if damage == "malformed":
        payload = payload[:-5]
    elif damage == "dtd":
        payload = '<!DOCTYPE Environment [<!ENTITY x "secret">]>' + payload
    elif damage == "oversized":
        payload = " " * (128 * 1024 + 1)
    vm = SimpleNamespace(Reload=lambda: None, config=SimpleNamespace(extraConfig=[SimpleNamespace(key="guestinfo.ovfEnv", value=payload)]))
    with pytest.raises(VcfSddcDeploymentError) as caught:
        _verify_guestinfo_ovf_environment(vm, properties, platform=OVF_PLATFORM)
    assert "secret" not in str(caught.value)


def test_guestinfo_empty_api_value_requires_verified_persisted_xml():
    """Accept masked API values only when the independently stored XML matches."""
    properties = {"ROOT_PASSWORD": 'sensitive<&"|é', "vami.ip0.SDDC-Manager": ""}
    payload = _ovf_environment_xml(properties, platform=OVF_PLATFORM)
    encoded = payload.replace("|", "|7C").replace('"', "|22").encode("utf-8")
    vmx = b'guestinfo.ovfEnv = "' + encoded + b'"\n'
    vm = SimpleNamespace(Reload=lambda: None, config=SimpleNamespace(extraConfig=[SimpleNamespace(key="guestinfo.ovfEnv", value="")]))
    result = _verify_guestinfo_ovf_environment(vm, properties, platform=OVF_PLATFORM, read_persisted=lambda: _ovf_environment_from_vmx(vmx))
    assert result["readback"] == "datastore-vmx"
    assert "sensitive" not in str(result)
    with pytest.raises(VcfSddcDeploymentError, match="complete reviewed"):
        _verify_guestinfo_ovf_environment(vm, {"ROOT_PASSWORD": "other"}, platform=OVF_PLATFORM, read_persisted=lambda: _ovf_environment_from_vmx(vmx))


@pytest.mark.parametrize("vmx", [b'', b'guestinfo.ovfEnv = "a"\nguestinfo.ovfenv = "b"', b'guestinfo.ovfEnv = "|zz"', b'guestinfo.ovfEnv = "|ff"', b'x' * (1024 * 1024 + 1)], ids=["missing", "duplicate", "escape", "encoding", "oversize"])
def test_persisted_environment_rejects_ambiguous_or_invalid_vmx(vmx):
    """Reject unsafe persisted representations before parsing their XML.

    Args:
        vmx: Invalid bounded configuration input.
    """
    with pytest.raises(VcfSddcDeploymentError):
        _ovf_environment_from_vmx(vmx)


@pytest.mark.parametrize("fault", ["", "pin", "redirect", "path", "oversize", "deadline", "cancel"])
@pytest.mark.parametrize("fingerprint_style", ["plain", "colon"])
def test_persisted_environment_read_is_pinned_bounded_and_same_host(monkeypatch, fault, fingerprint_style):
    """Never send a session cookie to an unconfirmed or redirected endpoint.

    Args:
        monkeypatch: Isolated transport replacement.
        fault: Failed trust, response, or path constraint.
        fingerprint_style: Plain hexadecimal or the colon-separated UI representation.
    """
    from pyVmomi import vim

    captured = []
    elapsed = [0.0]
    read_count = [0]
    monkeypatch.setattr("atlaso.app.services.vcf_sddc_deployment.time.monotonic", lambda: elapsed[0])
    certificate = b"confirmed-certificate"
    payload = b'guestinfo.ovfEnv = "safe"\n' if fault != "oversize" else b'x' * (1024 * 1024 + 1)

    class Datacenter:
        """Represent the sole datacenter on this standalone endpoint."""
        name = "ha-datacenter"

    class Connection:
        """Capture transport order without networking or credential output."""
        def __init__(self, endpoint, port, **kwargs):
            """Require the selected endpoint and a bounded timeout.

            Args:
                endpoint: Selected host.
                port: Selected HTTPS port.
                **kwargs: Connection controls.
            """
            assert (endpoint, port, kwargs["timeout"]) == ("esxi.example.test", 443, 30)
            self.sock = SimpleNamespace(getpeercert=lambda **_kwargs: certificate, settimeout=lambda value: None)

        def connect(self):
            """Record the TLS connection before any HTTP request."""
            captured.append("connect")

        def request(self, method, target, headers):
            """Record only the method and safe URL.

            Args:
                method: HTTP method.
                target: Same-host resource path.
                headers: Session authentication header.
            """
            assert headers == {"Cookie": "session-secret"}
            captured.append((method, target))

        def getresponse(self):
            """Return a bounded response or an untrusted redirect."""
            offset = [0]
            def read(limit):
                """Enforce the caller's byte bound.

                Args:
                    limit: Maximum returned bytes.
                """
                assert 0 < limit <= 65536
                read_count[0] += 1
                if fault == "deadline":
                    elapsed[0] += 0.5
                    return b'x'
                chunk = payload[offset[0]:offset[0] + limit]
                offset[0] += len(chunk)
                return chunk
            return SimpleNamespace(status=302 if fault == "redirect" else 200, read1=read)

        def close(self):
            """Always release the transport."""
            captured.append("close")

    monkeypatch.setattr(vim, "Datacenter", Datacenter)
    monkeypatch.setattr("atlaso.app.services.vcf_sddc_deployment.http.client.HTTPSConnection", Connection)
    si = SimpleNamespace(_stub=SimpleNamespace(cookie="session-secret"), RetrieveContent=lambda: SimpleNamespace(rootFolder=SimpleNamespace(childEntity=[Datacenter()])))
    vm = SimpleNamespace(runtime=SimpleNamespace(powerState="poweredOff"), config=SimpleNamespace(files=SimpleNamespace(vmPathName="[store] ../vm.vmx" if fault == "path" else "[store] task vm/vm.vmx")))
    fingerprint = hashlib.sha256(certificate).hexdigest()
    if fingerprint_style == "colon":
        fingerprint = ":".join(fingerprint[index:index + 2] for index in range(0, len(fingerprint), 2)).upper()
    def read():
        """Read the selected VMX using the confirmed certificate pin."""
        return _read_persisted_ovf_environment(vm, si, SimpleNamespace(name="store"), endpoint="esxi.example.test", port=443, expected_fingerprint="incorrect" if fault == "pin" else fingerprint, cancelled=lambda: fault == "cancel" and read_count[0] > 0)
    if fault:
        with pytest.raises(VcfSddcDeploymentError) as caught:
            read()
        assert "session-secret" not in str(caught.value)
        if fault == "deadline":
            assert elapsed[0] == 30
            assert read_count[0] == 60
        if fault == "cancel":
            assert "cancelled" in str(caught.value)
            assert read_count[0] == 1
        if fault in {"pin", "path"}:
            assert not any(isinstance(entry, tuple) for entry in captured)
    else:
        assert read() == "safe"
        assert captured == ["connect", ("GET", "/folder/task%20vm/vm.vmx?dcPath=ha-datacenter&dsName=store"), "close"]
