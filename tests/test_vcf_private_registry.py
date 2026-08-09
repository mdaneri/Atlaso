"""Test vcf private registry behavior."""

from atlaso.app.models import VcfPrivateRegistrySettings, VcfRegistryBundle
from atlaso.app.services.vcf_private_registry import (
    render_harbor_config,
    render_imgpkg_relocation_preview,
    validate_vcf_registry_state,
)


def test_vcf_private_registry_harbor_preview_redacts_secrets():
    """Verify that vcf private registry harbor preview redacts secrets."""
    settings = VcfPrivateRegistrySettings(
        hostname="registry.atlaso.internal",
        listen_interface="eth2",
        listen_address="192.168.50.1",
        harbor_project="vcf-supervisor-services",
        robot_account="robot$vcf-supervisor-services",
    )

    preview = render_harbor_config(settings)

    assert "hostname: registry.atlaso.internal" in preview
    assert "harbor_admin_password: <provisioned-by-atlaso-helper>" in preview
    assert "robot$vcf-supervisor-services" in preview
    assert "password123" not in preview.lower()
    assert "token" not in preview.lower()


def test_vcf_private_registry_relocation_preview_uses_imgpkg():
    """Verify that vcf private registry relocation preview uses imgpkg."""
    settings = VcfPrivateRegistrySettings(
        hostname="registry.atlaso.internal",
        harbor_project="vcf-supervisor-services",
    )
    bundles = [
        VcfRegistryBundle(
            name="service-a",
            source_reference="projects.registry.vmware.com/vcf/service-a:1.0.0",
            target_reference="",
            enabled=True,
        )
    ]

    preview = render_imgpkg_relocation_preview(settings, bundles)

    assert "imgpkg copy -b projects.registry.vmware.com/vcf/service-a:1.0.0" in preview
    assert "--to-repo registry.atlaso.internal/vcf-supervisor-services/service-a" in preview


def test_vcf_private_registry_validation_errors_and_warnings():
    """Verify that vcf private registry validation errors and warnings."""
    settings = VcfPrivateRegistrySettings(
        enabled=True,
        hostname="registry.atlaso.local",
        listen_interface="eth9",
        listen_address="not-an-ip",
        port=70000,
        harbor_project="Bad Project",
        storage_path="relative/path",
        config_path="/etc/atlaso/harbor/harbor.yml",
        ca_bundle_path="/etc/atlaso/ca/ca-bundle.pem",
        server_certificate="",
        robot_account="",
    )
    bundles = [
        VcfRegistryBundle(name="dupe", source_reference="", enabled=True),
        VcfRegistryBundle(name="dupe", source_reference="source", enabled=True),
    ]

    errors, warnings = validate_vcf_registry_state(settings, bundles, {"eth2"}, set())

    assert "Listen interface eth9 is not configured as an access physical or VLAN interface with an IP address." in errors
    assert "Listen address not-an-ip is not a valid IP address." in errors
    assert "Registry HTTPS port must be between 1 and 65535." in errors
    assert "Harbor project must use lowercase letters, numbers, dots, underscores, or hyphens." in errors
    assert "Registry storage path must be an absolute Linux path." in errors
    assert "Server certificate name is required." in errors
    assert "Robot account name is required." in errors
    assert "Supervisor Service bundle dupe is duplicated." in errors
    assert "Supervisor Service bundle dupe needs a source reference before relocation." in errors
    assert any(".local" in warning for warning in warnings)
