"""Verify service classification uses component metadata rather than credential contents."""

import pytest

from atlaso.app.services.vault_service_types import (
    VAULT_SERVICE_TYPE_LABELS,
    legacy_vault_service_type,
    normalize_vault_service_type,
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
