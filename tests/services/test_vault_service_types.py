"""Verify service classification uses component metadata rather than credential contents."""

import pytest

from atlaso.app.services.vault_service_types import (
    VAULT_SERVICE_TYPE_LABELS,
    legacy_vault_service_type,
    normalize_vault_service_type,
    vault_entry_display_name,
    vault_service_from_deployment_path,
    vault_service_from_resource,
)


@pytest.mark.parametrize("resource, expected", [
    ("VCENTER", "vcenter"), ("ESXI", "esx"), ("NSXT_MANAGER", "nsx"),
    ("NSXT_EDGE", "nsx"), ("VROPS", "operations"), ("VRA", "automation"),
    ("VRLI", "log_insight"), ("VRSLCM", "lifecycle_manager"), ("WSA", "identity_manager"),
    ("NSX_ALB", "load_balancer"), ("VXRAIL_MANAGER", "vxrail_manager"),
    ("BACKUP", "backup"), ("PSC", "psc"), ("SDDC_MANAGER", "sddc_manager"),
    ("unsupported-vendor-component", "unknown"), ("", "unknown"),
])
def test_vendor_resource_service_mapping(resource, expected):
    """Keep product labels explicit for supported and unknown vendor resources.

    Args:
        resource: Vendor resource type.
        expected: Expected canonical vault service.
    """
    assert vault_service_from_resource(resource) == expected
    assert expected in VAULT_SERVICE_TYPE_LABELS


@pytest.mark.parametrize("path, expected", [
    (("vcenterSpec", "rootVcenterPassword"), "vcenter"),
    (("hostSpecs", "arbitrary.example.test", "credentials", "password"), "esx"),
    (("nsxtSpec", "nsxtAdminPassword"), "nsx"),
    (("vcfOperationsSpec", "nodes", "node.example.test", "rootUserPassword"), "operations"),
    (("vcfOperationsSpec", "adminUserPassword"), "operations"),
    (("vcfAutomationSpec", "adminUserPassword"), "automation"),
    (("vcfOperationsCollectorSpec", "rootUserPassword"), "operations_collector"),
    (("vspClusterSpec", "systemUserPassword", "admin@vsp.local"), "services_runtime"),
    (("sddcManagerSpec", "localUserPassword"), "sddc_manager"),
    (("components", "vcenterSpec", "password"), "unknown"),
    (("operations.example.test", "password"), "unknown"),
    ((), "unknown"),
])
def test_deployment_service_uses_component_container_not_hostname(path, expected):
    """Avoid inferring a product from a resource-provided path label or hostname.

    Args:
        path: Deployment password path.
        expected: Expected canonical vault service.
    """
    assert vault_service_from_deployment_path(path) == expected


@pytest.mark.parametrize("source, description, expected", [
    ("sddc_manager", "Imported SDDC Manager VCENTER credential for arbitrary.example.test.", "vcenter"),
    ("sddc_manager", "Imported SDDC Manager NSXT_MANAGER credential for arbitrary.example.test.", "nsx"),
    ("vcf_installer", "Imported VCF Installer password from vcfOperationsSpec.adminUserPassword.", "operations"),
    ("vcf_installer", "Deployment-time password from vcfAutomationSpec.adminUserPassword; may be stale after rotation.", "automation"),
    ("vcf_installer", "Deployment-time password from vspClusterSpec.systemUserPassword.admin@vsp.local; may be stale after rotation.", "services_runtime"),
    ("manual", "Imported SDDC Manager VCENTER credential for operations.example.test.", "unknown"),
    ("sddc_manager", "My vCenter password", "unknown"),
    ("vcf_installer", "Operations at ops.example.test", "unknown"),
])
def test_legacy_labels_require_known_import_metadata(source, description, expected):
    """Backfill only recognized import formats, leaving edited prose and manual entries unknown.

    Args:
        source: Stored import source.
        description: Stored non-secret entry description.
        expected: Expected service recovered from historical metadata.
    """
    assert legacy_vault_service_type(source_type=source, secret_type="vcf_password", description=description) == expected


def test_service_choice_is_validated_without_echoing_untrusted_input():
    """Accept canonical choices and reject unsupported text with a fixed error."""
    assert normalize_vault_service_type(" Operations ") == "operations"
    assert normalize_vault_service_type("") == "unknown"
    with pytest.raises(ValueError, match=r"^Choose a supported vault service\.$"):
        normalize_vault_service_type("<script>untrusted-service</script>")


@pytest.mark.parametrize("service, username, uris, expected", [
    ("operations", "admin", ("https://ops01.example.test",), "operations.ops01.admin"),
    ("automation", "admin", ("https://auto-vip.example.test",), "automation.auto_vip.admin"),
    ("vcenter", "administrator@vsphere.local", ("https://vc01.example.test",), "vcenter.vc01.administrator_vsphere_local"),
    ("nsx", "root", ("ssh://nsx01.example.test",), "nsx.nsx01.root"),
    ("operations", "root", ("ssh://192.0.2.21",), "operations.192_0_2_21.root"),
    ("operations", "root", ("ssh://[2001:db8::21]",), "operations.2001_db8_21.root"),
    ("unsupported", "admin", (), "unknown.admin"),
    ("operations", "", (), "vcf.imported.id_fixture"),
    ("operations", "admin", ("https://[bad", "https://user:password@wrong.example.test", "https://ops01.example.test"), "operations.ops01.admin"),
])
def test_imported_names_are_readable_metadata_not_new_keys(service, username, uris, expected):
    """Use safe account and endpoint labels while retaining an exact-key fallback.

    Args:
        service: Source-derived service identifier.
        username: Non-secret account metadata.
        uris: Source or operator endpoint associations.
        expected: Readable name or original key when metadata is absent.
    """
    assert vault_entry_display_name(key="vcf.imported.id_fixture", service_type=service, username=username, uris=uris) == expected


def test_display_names_do_not_decrypt_or_mutate_existing_keys(monkeypatch):
    """Keep manual names and script identities intact even when imported names coincide.

    Args:
        monkeypatch: Fixture preventing any password decryption during metadata rendering.
    """
    from atlaso.app.models import VaultEntry
    from atlaso.app.services import vaults

    def reject_decryption(*_args):
        """Fail if metadata rendering attempts password decryption.

        Args:
            *_args: Arguments supplied to the decryption function being guarded.
        """
        raise AssertionError("Display metadata must never decrypt a password")

    monkeypatch.setattr(vaults, "decrypt_secret", reject_decryption)
    for source in ("manual", "sddc_manager", "vcf_installer"):
        entry = VaultEntry(key="vcf.imported.id_existing", username="admin", source_type=source,
                           service_type="operations", encrypted_value="unchanged-ciphertext", uris_json='["https://ops01.example.test"]')
        before = (entry.key, entry.encrypted_value, entry.uris_json)
        metadata = vaults.vault_entry_metadata(entry)
        assert metadata["display_name"] == (entry.key if source == "manual" else "operations.ops01.admin")
        assert metadata["key"] == entry.key
        assert (entry.key, entry.encrypted_value, entry.uris_json) == before


def test_discovery_redacts_before_normalizing_readable_names():
    """Prevent case folding from exposing a secret repeated in source metadata."""
    from atlaso.app.services.vcf_vault_import import VcfPasswordCandidate

    candidate = VcfPasswordCandidate(candidate_id="stable-source", key="vcf.imported.id_fixture",
                                    description="Source credential", secret_type="vcf_password",
                                    username="FixturePassword", resource_name="ops01.example.test",
                                    value="FixturePassword", service_type="operations",
                                    uris=("https://ops01.example.test",))
    metadata = candidate.sanitized()
    assert metadata["display_name"] == "operations.ops01.redacted"
    assert "fixturepassword" not in str(metadata).lower()
