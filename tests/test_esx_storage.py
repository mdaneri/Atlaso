"""Test esx storage behavior."""

import importlib.machinery
import importlib.util
import json
import subprocess
from pathlib import Path, PurePosixPath

import pytest

from atlaso.app.models import EsxNfsShare, EsxStorageSettings, EsxStorageVolume
from atlaso.app.services.esx_storage import (
    StorageInterface,
    desired_dns_records,
    firewall_rule_specs,
    format_authorization,
    normalize_disk_inventory_entry,
    powercli_connection_command,
    render_manifest,
    share_paths_overlap,
    validate_mounted_volume_path,
)

HELPER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "appliance" / "atlaso-helper"


def load_helper_module():
    """Return helper module."""
    loader = importlib.machinery.SourceFileLoader("atlaso_esx_storage_helper", str(HELPER_PATH))
    spec = importlib.util.spec_from_loader("atlaso_esx_storage_helper", loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def state(*, families: str = "ipv4\nipv6", ipv4_clients: str = "192.168.87.11/32", ipv6_clients: str = "2001:db8:87::11/128"):
    """Return state.

    Args:
        families: Families supplied to the test scenario.
        ipv4_clients: Ipv4 clients supplied to the test scenario.
        ipv6_clients: Ipv6 clients supplied to the test scenario.
    """
    settings = EsxStorageSettings(enabled=True, hostname="nfs.atlaso.internal")
    settings.id = 1
    volume = EsxStorageVolume(
        name="esx-data",
        source_type="blank_disk",
        stable_device_id="/dev/disk/by-id/wwn-0x1234",
        capacity_bytes=10 * 1024**3,
        mount_path="/mnt/atlaso-esx-storage/esx-data",
    )
    volume.id = 1
    share = EsxNfsShare(
        datastore_name="esx-datastore",
        volume_id=1,
        relative_path="datastores/esx",
        preferred_nfs_version="4.1",
        interface_name="storage.87",
        address_families=families,
        ipv4_clients=ipv4_clients,
        ipv6_clients=ipv6_clients,
        enabled=True,
    )
    share.id = 1
    interfaces = {
        "storage.87": StorageInterface(
            "storage.87",
            ("192.168.87.254/24",),
            ("2001:db8:87::fe/64",),
        )
    }
    return settings, [volume], [share], interfaces


def render(**kwargs):
    """Render operation.

    Args:
        **kwargs: Additional keyword arguments accepted by the callable.


    Returns:
        The render result.
    """
    settings, volumes, shares, interfaces = state(**kwargs)
    return render_manifest(settings, volumes, shares, interfaces, dns_enabled=True, dns_naming_mode="ip")


def test_dual_stack_share_renders_equal_family_endpoints_and_commands():
    """Verify that dual stack share renders equal family endpoints and commands."""
    manifest = render()
    share = manifest["shares"][0]

    assert manifest["validation"]["errors"] == []
    assert share["listeners"] == {"ipv4": ["192.168.87.254"], "ipv6": ["2001:db8:87::fe"]}
    assert share["target_hostnames"]["ipv4"] == ["nfs-192-168-87-254.atlaso.internal"]
    assert share["target_hostnames"]["ipv6"] == ["nfs-2001-db8-87-0-0-0-0-fe.atlaso.internal"]
    assert "--hosts=nfs-192-168-87-254.atlaso.internal" in share["connection_commands"]["ipv4"][0]
    assert "--hosts=nfs-2001-db8-87-0-0-0-0-fe.atlaso.internal" in share["connection_commands"]["ipv6"][0]
    assert share["powercli_commands"]["ipv4"] == [
        "New-Datastore -Nfs -VMHost $vmHost -Name 'esx-datastore' "
        "-NfsHost 'nfs-192-168-87-254.atlaso.internal' -Path '/esx-datastore' "
        "-FileSystemVersion 'NFS41'"
    ]
    assert share["powercli_commands"]["ipv6"] == [
        "New-Datastore -Nfs -VMHost $vmHost -Name 'esx-datastore' "
        "-NfsHost 'nfs-2001-db8-87-0-0-0-0-fe.atlaso.internal' -Path '/esx-datastore' "
        "-FileSystemVersion 'NFS41'"
    ]


def test_powercli_command_escapes_single_quoted_values():
    """Verify that powercli command escapes single quoted values."""
    command = powercli_connection_command(
        version="3",
        hostname="nfs.example.test",
        remote_path="/srv/atlaso/esx-storage/team's-data",
        datastore_name="team's-data",
    )

    assert "-Name 'team''s-data'" in command
    assert "-Path '/srv/atlaso/esx-storage/team''s-data'" in command
    assert "-FileSystemVersion 'NFS'" in command


def test_ipv4_only_and_ipv6_only_do_not_create_implicit_fallback():
    """Verify that ipv4 only and ipv6 only do not create implicit fallback."""
    ipv4 = render(families="ipv4")
    ipv6 = render(families="ipv6")

    assert ipv4["shares"][0]["listeners"]["ipv6"] == []
    assert ipv4["shares"][0]["connection_commands"]["ipv6"] == []
    assert ipv4["shares"][0]["powercli_commands"]["ipv6"] == []
    assert ipv6["shares"][0]["listeners"]["ipv4"] == []
    assert ipv6["shares"][0]["connection_commands"]["ipv4"] == []
    assert ipv6["shares"][0]["powercli_commands"]["ipv4"] == []


def test_mixed_family_client_allowlist_is_rejected():
    """Verify that mixed family client allowlist is rejected."""
    manifest = render(ipv4_clients="2001:db8::10/128")
    assert any("does not match the enabled IPV4 family" in message for message in manifest["validation"]["errors"])


def test_empty_client_lists_explicitly_allow_any_client_per_enabled_family():
    """Verify that empty client lists explicitly allow any client per enabled family."""
    manifest = render(ipv4_clients="", ipv6_clients="")
    share = manifest["shares"][0]

    assert manifest["validation"]["errors"] == []
    assert share["clients"] == {"ipv4": ["0.0.0.0/0"], "ipv6": ["::/0"]}
    assert {rule["source_expression"] for rule in firewall_rule_specs(manifest)} == {
        "ip saddr 0.0.0.0/0",
        "ip6 saddr ::/0",
    }


def test_dns_records_include_canonical_alias_and_both_address_families():
    """Verify that dns records include canonical alias and both address families."""
    records = desired_dns_records(render())
    assert records[:2] == [{
        "hostname": "nfs.atlaso.internal",
        "record_type": "A",
        "address": "192.168.87.254",
    }, {
        "hostname": "nfs.atlaso.internal",
        "record_type": "AAAA",
        "address": "2001:db8:87::fe",
    }]
    assert {record["record_type"] for record in records} == {"A", "AAAA"}


def test_firewall_rules_are_family_specific_and_match_preferred_protocol():
    """Verify that firewall rules are family specific and match preferred protocol."""
    manifest = render()
    rules = firewall_rule_specs(manifest)
    assert {rule["source_expression"] for rule in rules} == {
        "ip saddr 192.168.87.11/32",
        "ip6 saddr 2001:db8:87::11/128",
    }
    assert {rule["ports"] for rule in rules} == {"2049"}

    manifest["shares"][0]["preferred_nfs_version"] = "3"
    assert {rule["ports"] for rule in firewall_rule_specs(manifest)} == {"111,20048,2049"}


def test_blank_disk_inventory_rejects_every_destructive_risk_and_claim():
    """Verify that blank disk inventory rejects every destructive risk and claim."""
    eligible = normalize_disk_inventory_entry(
        {
            "stable_device_id": "/dev/disk/by-id/wwn-0x1234",
            "device_path": "/dev/sdb",
            "type": "disk",
            "size_bytes": 1024,
        }
    )
    rejected = normalize_disk_inventory_entry(
        {
            "stable_device_id": "/dev/disk/by-id/wwn-0x5678",
            "device_path": "/dev/sda",
            "type": "disk",
            "partitions": ["/dev/sda1"],
            "filesystem_type": "ext4",
            "mount_path": "/",
            "holders": ["dm-0"],
            "os_related": True,
        },
        claimed_ids={"/dev/disk/by-id/wwn-0x5678"},
    )

    assert eligible["eligible"] is True
    assert rejected["eligible"] is False
    assert "operating-system disk" in rejected["eligibility_reason"]
    assert "already claimed" in rejected["eligibility_reason"]


def test_mounted_ext4_inventory_rejects_vcf_backup_and_depot_mounts():
    """Verify that mounted ext4 inventory rejects vcf backup and depot mounts.

    Raises:
        AssertionError: If an expected invariant is not satisfied.
    """
    for mount_path, owner in [
        ("/mnt/atlaso-vcf-backups", "VCF Backups"),
        ("/mnt/atlaso-vcf-offline-depot", "VCF Offline Depot / VCFDT"),
        ("/mnt/atlaso-vcf-offline-depot/PROD", "VCF Offline Depot / VCFDT"),
    ]:
        candidate = normalize_disk_inventory_entry(
            {
                "candidate_type": "mounted_ext4",
                "filesystem_type": "ext4",
                "filesystem_uuid": f"uuid-{owner}",
                "mount_path": mount_path,
            }
        )

        assert candidate["eligible"] is False
        assert f"reserved for {owner}" in candidate["eligibility_reason"]

        try:
            validate_mounted_volume_path(mount_path)
        except ValueError as exc:
            assert owner in str(exc)
        else:
            raise AssertionError(f"reserved mount {mount_path} was accepted")


def test_mounted_ext4_inventory_requires_boot_safe_whole_disk_contract():
    """Require stable whole-disk identity and persistent UUID mounting."""
    eligible = normalize_disk_inventory_entry(
        {
            "candidate_type": "mounted_ext4",
            "stable_device_id": "/dev/disk/by-id/wwn-0x1234",
            "device_path": "/dev/sdd",
            "type": "disk",
            "filesystem_type": "ext4",
            "filesystem_uuid": "existing-uuid",
            "mount_path": "/mnt/existing-ext4",
            "mount_paths": ["/mnt/existing-ext4"],
            "writable_mount_paths": ["/mnt/existing-ext4"],
            "persistent_uuid_mount": True,
        }
    )
    read_only_mount = normalize_disk_inventory_entry(
        {
            "candidate_type": "mounted_ext4",
            "stable_device_id": "/dev/disk/by-id/wwn-0x1234",
            "device_path": "/dev/sdd",
            "type": "disk",
            "filesystem_type": "ext4",
            "filesystem_uuid": "existing-uuid",
            "mount_path": "/mnt/existing-ext4",
            "mount_paths": ["/mnt/existing-ext4"],
            "writable_mount_paths": [],
            "persistent_uuid_mount": True,
        }
    )
    additionally_mounted = normalize_disk_inventory_entry(
        {
            "candidate_type": "mounted_ext4",
            "stable_device_id": "/dev/disk/by-id/wwn-0x1234",
            "device_path": "/dev/sdd",
            "type": "disk",
            "filesystem_type": "ext4",
            "filesystem_uuid": "existing-uuid",
            "mount_path": "/mnt/existing-ext4",
            "mount_paths": ["/mnt/existing-ext4", "/mnt/unrelated"],
            "writable_mount_paths": ["/mnt/existing-ext4", "/mnt/unrelated"],
            "persistent_uuid_mount": True,
        }
    )
    incompatible = normalize_disk_inventory_entry(
        {
            "candidate_type": "mounted_ext4",
            "stable_device_id": "UUID=partition-uuid",
            "device_path": "/dev/sdd1",
            "type": "part",
            "filesystem_type": "ext4",
            "filesystem_uuid": "partition-uuid",
            "mount_path": "/mnt/partition-ext4",
        }
    )

    assert eligible["eligible"] is True
    assert read_only_mount["eligible"] is False
    assert "selected mount is read-only" in read_only_mount["eligibility_reason"]
    assert additionally_mounted["eligible"] is False
    assert "unexpected additional mounts" in additionally_mounted["eligibility_reason"]
    assert incompatible["eligible"] is False
    assert "not a whole disk" in incompatible["eligibility_reason"]
    assert "not persisted by UUID" in incompatible["eligibility_reason"]


def test_desired_state_rejects_existing_volume_on_vcf_managed_mount():
    """Verify that desired state rejects existing volume on vcf managed mount."""
    settings, volumes, shares, interfaces = state()
    volumes[0].source_type = "mounted_ext4"
    volumes[0].stable_device_id = ""
    volumes[0].mount_path = "/mnt/atlaso-vcf-backups"

    manifest = render_manifest(settings, volumes, shares, interfaces, dns_enabled=True)

    assert any("reserved for VCF Backups" in error for error in manifest["validation"]["errors"])


def test_format_authorization_is_job_manifest_and_device_bound():
    """Verify that format authorization is job manifest and device bound."""
    manifest = render()
    authorization = format_authorization(
        job_id="job-123",
        manifest=manifest,
        volume=manifest["volumes"][0],
        confirmation="FORMAT esx-data",
    )
    assert authorization["job_id"] == "job-123"
    assert authorization["stable_device_id"] == "/dev/disk/by-id/wwn-0x1234"
    assert len(authorization["manifest_sha256"]) == 64


def test_export_paths_reject_root_children_and_siblings_remain_valid():
    """Verify that export paths reject root children and siblings remain valid."""
    assert share_paths_overlap("datastores", "datastores/esx") is True
    assert share_paths_overlap("datastores/esx-a", "datastores/esx-b") is False


def test_helper_requires_job_scoped_format_authorization_for_apply():
    """Verify that helper requires job scoped format authorization for apply."""
    helper = load_helper_module()
    manifest = render()
    assert helper._esx_storage_manifest_errors(manifest, require_authorization=False) == []
    assert helper._esx_storage_manifest_errors(manifest, require_authorization=True) == [
        "volume esx-data is missing job-scoped format authorization"
    ]

    manifest["format_authorizations"] = [
        format_authorization(
            job_id="job-123",
            manifest=manifest,
            volume=manifest["volumes"][0],
            confirmation="FORMAT esx-data",
        )
    ]
    assert helper._esx_storage_manifest_errors(manifest, require_authorization=True) == []


def test_helper_rejects_existing_volume_on_vcf_managed_mount():
    """Verify that helper rejects existing volume on vcf managed mount."""
    helper = load_helper_module()
    manifest = render()
    manifest["volumes"][0].update(
        {
            "source_type": "mounted_ext4",
            "stable_device_id": "",
            "mount_path": "/mnt/atlaso-vcf-offline-depot",
            "requires_format": False,
        }
    )

    assert "existing volume esx-data mount path is reserved for VCF Offline Depot / VCFDT" in helper._esx_storage_manifest_errors(manifest)


def test_helper_blank_disk_revalidation_rejects_partition_mount_lvm_raid_and_os_relationship():
    """Verify that helper blank disk revalidation rejects partition mount lvm raid and os relationship."""
    helper = load_helper_module()
    errors = helper._esx_storage_blank_disk_errors(
        {
            "type": "disk",
            "stable_device_id": "/dev/disk/by-id/wwn-test",
            "partitions": ["/dev/sdb1"],
            "filesystem_type": "ext4",
            "mount_path": "/mnt/data",
            "swap": True,
            "lvm": True,
            "raid": True,
            "holders": ["dm-0"],
            "os_related": True,
            "read_only": False,
        }
    )
    assert errors == [
        "has partitions",
        "has a filesystem",
        "is mounted",
        "is swap",
        "belongs to LVM",
        "belongs to RAID",
        "has holders",
        "is related to the operating-system disk",
    ]


def test_helper_inventory_prefers_uuid_mount_and_keeps_all_mountpoints(monkeypatch, tmp_path: Path):
    """Verify that helper inventory prefers uuid mount and keeps all mountpoints.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Pytest-provided isolated filesystem root.
    """
    helper = load_helper_module()
    lsblk_payload = {
        "blockdevices": [{
            "name": "sdd",
            "kname": "sdd",
            "path": "/dev/sdd",
            "type": "disk",
            "size": 20 * 1024**3,
            "model": "VMware Virtual S",
            "fstype": "ext4",
            "uuid": "3f832583-beec-4be7-969c-92519ea77273",
            "label": "lf-ad26e4d9384f",
            "mountpoints": [
                "/srv/atlaso/esx-storage/vmware-nfs3",
                "/mnt/operator existing-ext4",
            ],
        }]
    }
    monkeypatch.setattr(helper, "_command_path", lambda command: f"/usr/bin/{command}")
    def run(command):
        """Return deterministic lsblk or findmnt output for inventory.

        Args:
            command: Helper subprocess argument list.
        """
        if "--mountpoint" in command:
            return subprocess.CompletedProcess(command, 0, stdout="rw,relatime\n", stderr="")
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(lsblk_payload), stderr="")

    monkeypatch.setattr(helper, "_run", run)
    monkeypatch.setattr(
        helper,
        "_esx_storage_by_id_map",
        lambda: {"/dev/sdd": "/dev/disk/by-id/atlaso-path-pci-0000_03_00_0-scsi-0_0_3_0"},
    )
    monkeypatch.setattr(helper, "_esx_storage_os_devices", lambda: set())
    fstab = tmp_path / "fstab"
    fstab.write_text(
        "UUID=3f832583-beec-4be7-969c-92519ea77273 /mnt/operator\\040existing-ext4 ext4 defaults 0 2\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(helper, "ESX_STORAGE_FSTAB_PATH", fstab)

    disk = helper._esx_storage_inventory()[0]

    assert disk["mount_path"] == "/mnt/operator existing-ext4"
    assert disk["mount_paths"] == [
        "/srv/atlaso/esx-storage/vmware-nfs3",
        "/mnt/operator existing-ext4",
    ]
    assert disk["persistent_uuid_mount"] is True
    assert disk["writable_mount_paths"] == disk["mount_paths"]


def test_helper_fstab_field_encoding_round_trips_spaces_and_backslashes():
    """Keep generated fstab fields parseable without changing their paths."""
    helper = load_helper_module()
    value = "/mnt/operator data\\archive"

    encoded = helper._esx_storage_fstab_escape_field(value)

    assert encoded == "/mnt/operator\\040data\\134archive"
    assert helper._esx_storage_fstab_decode_field(encoded) == value


@pytest.mark.parametrize(
    ("options", "expected"),
    [("defaults", True), ("defaults,ro", False), ("ro,rw", True), ("rw,ro", False)],
)
def test_helper_requires_one_writable_persistent_uuid_mount(
    monkeypatch, tmp_path: Path, options: str, expected: bool
):
    """Require one unambiguous writable fstab entry for an existing disk.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Pytest-provided isolated filesystem root.
        options: Candidate fstab mount options.
        expected: Whether the persistent mount contract should pass.
    """
    helper = load_helper_module()
    fstab = tmp_path / "fstab"
    fstab.write_text(f"UUID=existing /mnt/existing ext4 {options} 0 2\n", encoding="utf-8")
    monkeypatch.setattr(helper, "ESX_STORAGE_FSTAB_PATH", fstab)

    assert helper._esx_storage_uuid_fstab_entry_exists("existing", "/mnt/existing") is expected
    if expected:
        fstab.write_text(fstab.read_text(encoding="utf-8") * 2, encoding="utf-8")
        assert helper._esx_storage_uuid_fstab_entry_exists("existing", "/mnt/existing") is False


def test_helper_requires_additional_esx_bind_mount_to_be_managed(monkeypatch, tmp_path: Path):
    """Exempt an additional ESX bind target only inside the managed fstab block.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Pytest-provided isolated filesystem root.
    """
    helper = load_helper_module()
    fstab = tmp_path / "fstab"
    bind_mount = "/srv/atlaso/esx-storage/existing"
    managed_entry = f"/mnt/existing/share {bind_mount} none bind,nofail 0 0"
    entry = {
        "type": "disk",
        "stable_device_id": "/dev/disk/by-id/wwn-existing",
        "filesystem_type": "ext4",
        "filesystem_uuid": "existing-uuid",
        "mount_paths": ["/mnt/existing", bind_mount],
        "writable_mount_paths": ["/mnt/existing", bind_mount],
        "partitions": [],
        "holders": [],
        "os_related": False,
        "read_only": False,
        "persistent_uuid_mount": True,
    }
    monkeypatch.setattr(helper, "ESX_STORAGE_FSTAB_PATH", fstab)
    fstab.write_text(
        f"{helper.ESX_STORAGE_FSTAB_BEGIN}\n{managed_entry}\n{helper.ESX_STORAGE_FSTAB_END}\n",
        encoding="utf-8",
    )

    assert helper._esx_storage_mounted_disk_errors(entry, mount_path=PurePosixPath("/mnt/existing")) == []

    fstab.write_text(f"{managed_entry}\n", encoding="utf-8")
    assert helper._esx_storage_mounted_disk_errors(
        entry, mount_path=PurePosixPath("/mnt/existing")
    ) == ["has unexpected additional mounts"]


def test_helper_rejects_mounted_ext4_without_boot_contract():
    """Reject mounted ext4 inventory that cannot pass the boot-time allowlist."""
    helper = load_helper_module()

    errors = helper._esx_storage_mounted_disk_errors(
        {
            "type": "part",
            "stable_device_id": "UUID=existing-uuid",
            "filesystem_type": "ext4",
            "filesystem_uuid": "existing-uuid",
            "mount_paths": ["/mnt/existing-ext4"],
            "writable_mount_paths": ["/mnt/existing-ext4"],
            "partitions": [],
            "holders": [],
            "os_related": False,
            "read_only": False,
            "persistent_uuid_mount": False,
        },
        mount_path=PurePosixPath("/mnt/existing-ext4"),
    )

    assert errors == [
        "not a whole disk",
        "missing stable /dev/disk/by-id identity",
        "is not persisted by UUID in /etc/fstab",
    ]


@pytest.mark.parametrize(
    ("mount_paths", "writable_mount_paths", "expected"),
    [
        (
            ["/mnt/existing-ext4", "/mnt/unrelated"],
            ["/mnt/existing-ext4", "/mnt/unrelated"],
            "has unexpected additional mounts",
        ),
        (["/mnt/existing-ext4"], [], "selected mount is read-only"),
    ],
)
def test_helper_rejects_mounted_ext4_state_that_cannot_pass_boot(
    mount_paths: list[str], writable_mount_paths: list[str], expected: str
):
    """Keep apply-time mounted-disk admission consistent with boot checks.

    Args:
        mount_paths: Active mount targets reported for the disk.
        writable_mount_paths: Active mount targets with the read-write option.
        expected: Exact admission error expected for the unsafe state.
    """
    helper = load_helper_module()
    entry = {
        "type": "disk",
        "stable_device_id": "/dev/disk/by-id/wwn-existing",
        "filesystem_type": "ext4",
        "filesystem_uuid": "existing-uuid",
        "mount_paths": mount_paths,
        "writable_mount_paths": writable_mount_paths,
        "partitions": [],
        "holders": [],
        "os_related": False,
        "read_only": False,
        "persistent_uuid_mount": True,
    }

    assert helper._esx_storage_mounted_disk_errors(
        entry, mount_path=PurePosixPath("/mnt/existing-ext4")
    ) == [expected]


def test_helper_preserves_validated_disk_claims_after_apply_succeeds(monkeypatch, tmp_path: Path):
    """Verify that removed attached disks retain boot claims after apply succeeds.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Pytest-provided isolated filesystem root.
    """
    helper = load_helper_module()
    allowlist = tmp_path / "esx-storage-disks.conf"
    allowlist.write_text("old-uuid\t/dev/disk/by-id/old\t/mnt/old\n", encoding="utf-8")
    monkeypatch.setattr(helper, "ESX_STORAGE_DISK_ALLOWLIST_PATH", allowlist)
    new_claim = "new-uuid\t/dev/disk/by-id/new\t/mnt/new"

    helper._esx_storage_write_disk_allowlist([new_claim], preserve_existing=True)

    assert allowlist.read_text(encoding="utf-8").splitlines() == [
        "old-uuid\t/dev/disk/by-id/old\t/mnt/old",
        new_claim,
    ]
    helper._esx_storage_write_disk_allowlist([new_claim], preserve_existing=True)
    assert allowlist.read_text(encoding="utf-8").splitlines() == [
        "old-uuid\t/dev/disk/by-id/old\t/mnt/old",
        new_claim,
    ]


def test_helper_preserves_each_formatted_disk_mount_until_apply_succeeds(monkeypatch, tmp_path: Path):
    """Verify that a later format failure retains earlier UUID mount contracts.

    Args:
        monkeypatch: Pytest fixture used to replace dependencies for the test.
        tmp_path: Pytest-provided isolated filesystem root.
    """
    helper = load_helper_module()
    fstab = tmp_path / "fstab"
    fstab.write_text(
        "UUID=os-root / ext4 defaults 0 1\n"
        f"{helper.ESX_STORAGE_FSTAB_BEGIN}\n"
        "UUID=old /mnt/old ext4 defaults,nofail 0 2\n"
        "/mnt/old/share /srv/atlaso/esx-storage/old none bind,nofail 0 0\n"
        f"{helper.ESX_STORAGE_FSTAB_END}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(helper, "ESX_STORAGE_FSTAB_PATH", fstab)
    existing = helper._esx_storage_managed_disk_fstab_lines()
    new_line = "UUID=new /mnt/new ext4 defaults,nofail,x-systemd.device-timeout=30 0 2"

    helper._esx_storage_replace_managed_fstab(list(dict.fromkeys([*existing, new_line])))

    assert helper._esx_storage_managed_fstab_lines() == [
        "UUID=old /mnt/old ext4 defaults,nofail 0 2",
        new_line,
    ]
    assert "UUID=os-root / ext4 defaults 0 1" in fstab.read_text(encoding="utf-8")


def test_helper_rejects_retained_mount_path_owned_by_another_uuid():
    """Prevent a removed disk from satisfying a replacement volume's mount."""
    helper = load_helper_module()
    retained = [
        "UUID=old-uuid /mnt/atlaso-esx-storage/reused\\040name ext4 defaults,nofail 0 2"
    ]
    mount_path = Path("/mnt/atlaso-esx-storage/reused name")

    with pytest.raises(ValueError, match="retained for a different filesystem"):
        helper._esx_storage_reject_retained_mount_collision(
            retained,
            filesystem_uuid="new-uuid",
            mount_path=mount_path,
        )

    helper._esx_storage_reject_retained_mount_collision(
        retained,
        filesystem_uuid="old-uuid",
        mount_path=mount_path,
    )


def test_helper_initialized_disk_retry_accepts_expected_mount_among_bind_mounts():
    """Verify that helper initialized disk retry accepts expected mount among bind mounts."""
    helper = load_helper_module()
    entry = {
        "filesystem_type": "ext4",
        "filesystem_label": "lf-ad26e4d9384f",
        "filesystem_uuid": "3f832583-beec-4be7-969c-92519ea77273",
        "partitions": [],
        "mount_paths": [
            "/srv/atlaso/esx-storage/vmware-nfs3",
            "/mnt/atlaso-esx-storage/vmware-esx-data",
        ],
        "holders": [],
        "os_related": False,
    }

    assert helper._esx_storage_disk_is_initialized(
        entry,
        label="lf-ad26e4d9384f",
        mount_path=PurePosixPath("/mnt/atlaso-esx-storage/vmware-esx-data"),
    )
    assert not helper._esx_storage_disk_is_initialized(
        entry,
        label="lf-wrong-label",
        mount_path=PurePosixPath("/mnt/atlaso-esx-storage/vmware-esx-data"),
    )
