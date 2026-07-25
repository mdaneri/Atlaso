import io
import tarfile

from labfoundry.app.models import User, VcfDepotDownloadProfile, VcfOfflineDepotSettings
from labfoundry.app.services.vcf_offline_depot import (
    VCF_DEPOT_COMPONENTS,
    VCF_DEPOT_ESX_DISABLED_PLATFORMS,
    generate_vcf_software_depot_id,
    parse_software_depot_id,
    render_nginx_depot_config,
    render_vcfdt_command_preview,
    validate_vcf_depot_state,
    vcf_depot_application_properties_from_tool,
    vcf_depot_profile_start_blocker,
    vcfdt_commands_for_profile,
)


def depot_http_user(*, enabled: bool = True) -> User:
    return User(id=1, username="vcf-depot", role="viewer", enabled=enabled)


def test_vcf_depot_start_requires_correct_credential_kind_without_blocking_apply(tmp_path):
    archive = tmp_path / "vcf-download-tool-9.1.0.test.tar.gz"
    archive.write_bytes(b"not-a-real-archive")
    settings = VcfOfflineDepotSettings(
        enabled=True,
        hostname="depot.labfoundry.internal",
        listen_interface="eth2",
        listen_address="192.168.50.1",
        port=443,
        server_certificate="depot.labfoundry.internal",
        depot_store_path="/mnt/labfoundry-vcf-offline-depot",
        tool_archive_path=str(archive),
        tool_version="9.1.0",
        config_path="/etc/labfoundry/nginx/sites.d/vcf-offline-depot.conf",
        http_user_id=1,
    )
    user = depot_http_user()
    profiles = [
        VcfDepotDownloadProfile(name="install", profile_type="binaries", sku="VCF", vcf_version="9.1.0", binary_type="INSTALL", enabled=True),
        VcfDepotDownloadProfile(name="metadata", profile_type="metadata", enabled=True),
        VcfDepotDownloadProfile(name="esx", profile_type="esx", enabled=True),
    ]

    errors, warnings = validate_vcf_depot_state(settings, profiles, {"eth2"}, users=[user])
    assert errors == []
    assert warnings == []
    assert "download token or activation code" in vcf_depot_profile_start_blocker(profiles[0])
    assert "download token or activation code" in vcf_depot_profile_start_blocker(profiles[1])
    assert "activation code" in vcf_depot_profile_start_blocker(profiles[2])

    errors, _warnings = validate_vcf_depot_state(
        settings,
        profiles,
        {"eth2"},
        download_token_present=True,
        activation_code_present=True,
        users=[user],
    )
    assert errors == []
    assert vcf_depot_profile_start_blocker(profiles[0], download_token_present=True, activation_code_present=True) == ""
    assert vcf_depot_profile_start_blocker(profiles[1], download_token_present=True, activation_code_present=True) == ""
    assert vcf_depot_profile_start_blocker(profiles[2], download_token_present=True, activation_code_present=True) == ""

    errors, _warnings = validate_vcf_depot_state(
        settings,
        profiles,
        {"eth2"},
        activation_code_present=True,
        users=[user],
    )
    assert errors == []
    assert vcf_depot_profile_start_blocker(profiles[0], activation_code_present=True) == ""
    assert vcf_depot_profile_start_blocker(profiles[1], activation_code_present=True) == ""
    assert vcf_depot_profile_start_blocker(profiles[2], activation_code_present=True) == ""


def test_vcf_depot_application_properties_does_not_scan_uploaded_tool_archive(tmp_path):
    archive = tmp_path / "vcf-download-tool-9.1.0.test.tar.gz"
    properties = b"spring.profiles.active=depot\nlcm.depot.adapter.host=archive.example.test\n"
    with tarfile.open(archive, "w:gz") as bundle:
        info = tarfile.TarInfo("conf/application-prodv2.properties")
        info.size = len(properties)
        bundle.addfile(info, io.BytesIO(properties))
    settings = VcfOfflineDepotSettings(tool_archive_path=str(archive))

    content, source = vcf_depot_application_properties_from_tool(settings)

    assert source == "LabFoundry default"
    assert "archive.example.test" not in content
    assert "lcm.depot.adapter.host=dl.broadcom.com" in content


def test_vcf_depot_application_properties_skips_nested_archive_members(tmp_path):
    archive = tmp_path / "vcf-download-tool-9.1.0.test.tar.gz"
    properties = b"spring.profiles.active=depot\nlcm.depot.adapter.host=nested-archive.example.test\n"
    with tarfile.open(archive, "w:gz") as bundle:
        info = tarfile.TarInfo("vcf-download-tool-9.1.0/conf/application-prodv2.properties")
        info.size = len(properties)
        bundle.addfile(info, io.BytesIO(properties))
    settings = VcfOfflineDepotSettings(tool_archive_path=str(archive))

    content, source = vcf_depot_application_properties_from_tool(settings)

    assert source == "LabFoundry default"
    assert "nested-archive.example.test" not in content
    assert "lcm.depot.adapter.host=dl.broadcom.com" in content


def test_vcf_depot_application_properties_falls_back_when_archive_member_is_missing(tmp_path, monkeypatch):
    archive = tmp_path / "vcf-download-tool-9.1.0.test.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        payload = b"9.1.0"
        info = tarfile.TarInfo("vcf-download-tool-9.1.0/conf/tool-version.txt")
        info.size = len(payload)
        bundle.addfile(info, io.BytesIO(payload))
    settings = VcfOfflineDepotSettings(tool_archive_path=str(archive))
    monkeypatch.setattr("labfoundry.app.services.vcf_offline_depot.VCF_DEPOT_EXTRACT_DIR", tmp_path / "missing-extract")

    content, source = vcf_depot_application_properties_from_tool(settings)

    assert source == "LabFoundry default"
    assert "lcm.depot.adapter.host=dl.broadcom.com" in content


def test_vcf_depot_validation_uses_documented_component_catalog(tmp_path):
    archive = tmp_path / "vcf-download-tool-9.1.0.test.tar.gz"
    archive.write_bytes(b"not-a-real-archive")
    settings = VcfOfflineDepotSettings(
        enabled=True,
        hostname="depot.labfoundry.internal",
        listen_interface="eth2",
        listen_address="192.168.50.1",
        port=443,
        server_certificate="depot.labfoundry.internal",
        depot_store_path="/mnt/labfoundry-vcf-offline-depot",
        tool_archive_path=str(archive),
        tool_version="9.1.0",
        config_path="/etc/labfoundry/nginx/sites.d/vcf-offline-depot.conf",
        http_user_id=1,
    )
    assert VCF_DEPOT_COMPONENTS["VRA"] == "VCF Automation"
    assert VCF_DEPOT_COMPONENTS["VCF_OBSERVABILITY_DATA_PLATFORM"] == "Observability Data Platform"
    assert len(VCF_DEPOT_COMPONENTS) == 32

    errors, _warnings = validate_vcf_depot_state(
        settings,
        [
            VcfDepotDownloadProfile(
                name="invalid-component",
                profile_type="binaries",
                sku="VCF",
                vcf_version="9.1.0",
                binary_type="INSTALL",
                component="NOT_A_COMPONENT",
                enabled=True,
            )
        ],
        {"eth2"},
        download_token_present=True,
        users=[depot_http_user()],
    )

    assert any("unsupported component NOT_A_COMPONENT" in error for error in errors)


def test_vcf_depot_validation_uses_esx_disabled_platform_catalog(tmp_path):
    archive = tmp_path / "vcf-download-tool-9.1.0.test.tar.gz"
    archive.write_bytes(b"not-a-real-archive")
    settings = VcfOfflineDepotSettings(
        enabled=True,
        hostname="depot.labfoundry.internal",
        listen_interface="eth2",
        listen_address="192.168.50.1",
        port=443,
        server_certificate="depot.labfoundry.internal",
        depot_store_path="/mnt/labfoundry-vcf-offline-depot",
        tool_archive_path=str(archive),
        tool_version="9.1.0",
        config_path="/etc/labfoundry/nginx/sites.d/vcf-offline-depot.conf",
        http_user_id=1,
    )
    assert VCF_DEPOT_ESX_DISABLED_PLATFORMS == (
        "esxio-9.1-INTL",
        "armEsx-9.1-INTL",
        "embeddedEsx-8.0-INTL",
        "embeddedEsx-7.0-INTL",
        "embeddedEsx-9.0-INTL",
        "embeddedEsx-9.1-INTL",
        "esxio-8.0-INTL",
        "esxio-9.0-INTL",
        "embeddedEsx-6.7-INT",
    )

    errors, _warnings = validate_vcf_depot_state(
        settings,
        [
            VcfDepotDownloadProfile(
                name="esx",
                profile_type="esx",
                disabled_platforms="\n".join(VCF_DEPOT_ESX_DISABLED_PLATFORMS),
                enabled=True,
            )
        ],
        {"eth2"},
        activation_code_present=True,
        users=[depot_http_user()],
    )
    assert errors == []

    errors, _warnings = validate_vcf_depot_state(
        settings,
        [
            VcfDepotDownloadProfile(
                name="esx",
                profile_type="esx",
                disabled_platforms="embeddedEsx-5.5-INTL",
                enabled=True,
            )
        ],
        {"eth2"},
        activation_code_present=True,
    )
    assert any("unsupported disabled platform embeddedEsx-5.5-INTL" in error for error in errors)


def test_vcf_depot_validation_allows_https_only_without_vcfdt_upload():
    settings = VcfOfflineDepotSettings(
        enabled=True,
        hostname="depot.labfoundry.internal",
        listen_interface="eth2",
        listen_address="192.168.50.1",
        port=443,
        server_certificate="depot.labfoundry.internal",
        depot_store_path="/mnt/labfoundry-vcf-offline-depot",
        config_path="/etc/labfoundry/nginx/sites.d/vcf-offline-depot.conf",
        http_user_id=1,
    )

    errors, warnings = validate_vcf_depot_state(settings, [], {"eth2"}, users=[depot_http_user()])

    assert errors == []
    assert warnings == []


def test_vcf_depot_validation_requires_user_unless_unauthenticated_access_is_enabled():
    settings = VcfOfflineDepotSettings(
        enabled=True,
        hostname="depot.labfoundry.internal",
        listen_interface="eth2",
        listen_address="192.168.50.1",
        port=443,
        server_certificate="depot.labfoundry.internal",
        depot_store_path="/mnt/labfoundry-vcf-offline-depot",
        config_path="/etc/labfoundry/nginx/sites.d/vcf-offline-depot.conf",
    )

    errors, warnings = validate_vcf_depot_state(settings, [], {"eth2"})

    assert warnings == []
    assert any("Select a VCF Offline Depot HTTP user" in error for error in errors)

    settings.allow_unauthenticated_access = True
    errors, warnings = validate_vcf_depot_state(settings, [], {"eth2"})

    assert errors == []
    assert warnings == []


def test_vcf_depot_nginx_config_renders_labfoundry_auth_request_by_default():
    settings = VcfOfflineDepotSettings(
        enabled=True,
        hostname="depot.labfoundry.internal",
        listen_interface="eth2",
        listen_address="192.168.50.1",
        port=443,
        http_user=depot_http_user(),
        server_certificate="depot.labfoundry.internal",
        depot_store_path="/mnt/labfoundry-vcf-offline-depot",
    )

    config = render_nginx_depot_config(settings)

    assert "# LabFoundry VCF Offline Depot user: vcf-depot" in config
    assert "satisfy any;" in config
    assert 'auth_basic "VCF Offline Depot";' in config
    assert "auth_basic_user_file /etc/labfoundry/nginx/htpasswd/vcf-offline-depot.htpasswd;" in config
    assert "proxy_set_header X-LabFoundry-Depot-Basic-User $remote_user;" in config
    assert "location = /PROD/" in config
    assert "location ^~ /static/" in config
    assert "location = /favicon.ico" in config
    assert "location = /manifest.webmanifest" in config
    assert "location = /service-worker.js" in config
    assert "location = /ca" not in config
    assert "location ^~ /ca/" not in config
    assert "location = /requests" not in config
    assert "location ^~ /requests/" not in config
    assert "auth_request /_labfoundry_depot_auth;" in config
    assert "proxy_pass http://127.0.0.1:8000/PROD/auth-failure;" in config
    assert "error_page 401 = /_labfoundry_depot_login;" in config
    assert "proxy_pass http://127.0.0.1:8000;" in config
    assert "alias /mnt/labfoundry-vcf-offline-depot/PROD/$1;" in config

    settings.allow_unauthenticated_access = True
    open_config = render_nginx_depot_config(settings)

    assert "# LabFoundry VCF Offline Depot unauthenticated access: true" in open_config
    assert "auth_basic" not in open_config
    assert "auth_request /_labfoundry_depot_auth;" not in open_config


def test_vcf_depot_validation_rejects_management_role_interfaces():
    settings = VcfOfflineDepotSettings(
        enabled=True,
        hostname="depot.labfoundry.internal",
        listen_interface="eth0",
        listen_address="192.168.49.1",
        port=443,
        server_certificate="depot.labfoundry.internal",
        depot_store_path="/mnt/labfoundry-vcf-offline-depot",
        config_path="/etc/labfoundry/nginx/sites.d/vcf-offline-depot.conf",
        http_user_id=1,
    )

    errors, warnings = validate_vcf_depot_state(settings, [], {"eth2"}, management_interface_names={"eth0"}, users=[depot_http_user()])

    assert warnings == []
    assert any("Listen interface eth0 uses the management role" in error for error in errors)


def test_vcf_depot_parses_generated_software_depot_id():
    assert parse_software_depot_id("Software Depot ID: 8c9506c6-7bdf-44d5-b2e9-50d829d66b99\n") == "8c9506c6-7bdf-44d5-b2e9-50d829d66b99"
    assert parse_software_depot_id("Use activation code for software depot id LF-DEPOT-9-1-001\n") == "LF-DEPOT-9-1-001"
    assert parse_software_depot_id("vcf-download-tool configuration generate --software-depot-id\n") == ""


def test_vcf_depot_generates_software_depot_id_from_extracted_tool(tmp_path, monkeypatch):
    archive_path = tmp_path / "vcf-download-tool-9.1.0.test.tar.gz"
    payload = b"placeholder executable"
    with tarfile.open(archive_path, "w:gz") as archive:
        info = tarfile.TarInfo("bin/vcf-download-tool")
        info.mode = 0o644
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))

    def fake_run(command, **kwargs):
        assert command[0] == str((tmp_path / "active-tool" / "bin" / "vcf-download-tool").resolve())
        assert kwargs["cwd"] == str((tmp_path / "active-tool" / "bin").resolve())
        assert kwargs["input"] == "Y\n"
        return type("Completed", (), {"returncode": 0, "stdout": "Software Depot ID: 8c9506c6-7bdf-44d5-b2e9-50d829d66b99\n", "stderr": ""})()

    monkeypatch.setattr("labfoundry.app.services.vcf_offline_depot.subprocess.run", fake_run)
    result = generate_vcf_software_depot_id(archive_path, extraction_dir=tmp_path / "active-tool")

    assert result.success is True
    assert result.software_depot_id == "8c9506c6-7bdf-44d5-b2e9-50d829d66b99"
    assert result.error == ""


def test_vcf_depot_software_depot_id_generation_handles_truncated_archive(tmp_path):
    archive_path = tmp_path / "vcf-download-tool-9.1.0.test.tar.gz"
    archive_path.write_bytes(b"\x1f\x8b\x08\x00truncated")

    result = generate_vcf_software_depot_id(archive_path, extraction_dir=tmp_path / "active-tool")

    assert result.success is False
    assert "archive appears incomplete or invalid" in result.error


def test_vcf_depot_command_preview_uses_staged_secret_paths():
    settings = VcfOfflineDepotSettings(
        hostname="depot.labfoundry.internal",
        depot_store_path="/mnt/labfoundry-vcf-offline-depot",
        tool_archive_path="vcfDownloadTool/vcf-download-tool-9.1.0.test.tar.gz",
        tool_version="9.1.0",
    )
    profiles = [
        VcfDepotDownloadProfile(
            name="upgrade",
            profile_type="binaries",
            sku="VCF",
            vcf_version="9.1.0",
            binary_type="UPGRADE",
            upgrades_only=True,
            component="VRA",
            component_version="9.1.0.0100",
            enabled=True,
        ),
        VcfDepotDownloadProfile(
            name="esx",
            profile_type="esx",
            disabled_platforms="esxio-9.1-INTL\narmEsx-9.1-INTL",
            enabled=True,
        ),
    ]

    preview = render_vcfdt_command_preview(settings, profiles)

    assert "vcf-download-tool configuration get --software-depot-id" not in preview
    assert "vcf-download-tool binaries list" not in preview
    assert "vcf-download-tool binaries download" in preview
    assert "--depot-store=/mnt/labfoundry-vcf-offline-depot" in preview
    assert "VCFDT_HOME=/var/lib/labfoundry/vcfDownloadTool/active-tool" in preview
    assert "--depot-download-token-file=/var/lib/labfoundry/vcfDownloadTool/active-tool/secrets/download-token.txt" in preview
    assert "--component=VRA" in preview
    assert "--component-version=9.1.0.0100" in preview
    assert "vcf-download-tool esx configuration -D esxio-9.1-INTL -D armEsx-9.1-INTL" in preview
    assert "--depot-download-activation-code-file=/var/lib/labfoundry/vcfDownloadTool/active-tool/secrets/activation-code.txt" in preview
    assert '> "${VCFDT_HOME}/conf/esxUserConfig.json"' in preview
    assert '"disabledPlatforms": [' in preview
    assert '"esxio-9.1-INTL"' in preview
    assert "obtu.telemetry.config=DISABLE" in preview


def test_vcf_depot_download_profiles_use_activation_code_when_no_token_is_staged():
    settings = VcfOfflineDepotSettings(
        hostname="depot.labfoundry.internal",
        depot_store_path="/mnt/labfoundry-vcf-offline-depot",
        tool_archive_path="vcfDownloadTool/vcf-download-tool-9.1.0.test.tar.gz",
        tool_version="9.1.0",
    )
    profile = VcfDepotDownloadProfile(
        name="activation-only",
        profile_type="binaries",
        sku="VCF",
        vcf_version="9.1.0",
        binary_type="INSTALL",
        enabled=True,
    )

    commands = vcfdt_commands_for_profile(settings, profile, download_token_present=False, activation_code_present=True)

    assert commands[0][0:3] == ["vcf-download-tool", "binaries", "download"]
    assert "--depot-download-activation-code-file=/var/lib/labfoundry/vcfDownloadTool/active-tool/secrets/activation-code.txt" in commands[0]
    assert "--depot-download-token-file=/var/lib/labfoundry/vcfDownloadTool/active-tool/secrets/download-token.txt" not in commands[0]


def test_vcf_depot_command_preview_supports_patch_only_profiles():
    settings = VcfOfflineDepotSettings(
        hostname="depot.labfoundry.internal",
        depot_store_path="/mnt/labfoundry-vcf-offline-depot",
        tool_archive_path="vcfDownloadTool/vcf-download-tool-9.1.0.test.tar.gz",
        tool_version="9.1.0",
    )
    profiles = [
        VcfDepotDownloadProfile(
            name="VCF 9.1 EP01 patches",
            profile_type="binaries",
            sku="VCF",
            vcf_version="9.1.0",
            binary_type="UPGRADE",
            patches_only=True,
            component_version="9.1.0.0100",
            enabled=True,
        )
    ]

    preview = render_vcfdt_command_preview(settings, profiles, vmware_ceip_enabled=True)

    assert "--patches-only" in preview
    assert "--upgrades-only" not in preview
    assert "--component-version=9.1.0.0100" in preview
    assert "obtu.telemetry.config=ENABLE" in preview
    assert "Telemetry choice is not provided" not in preview


def test_vcf_depot_nginx_preview_uses_ca_paths_and_static_file_directives():
    settings = VcfOfflineDepotSettings(
        enabled=True,
        hostname="depot.labfoundry.internal",
        listen_address="192.168.50.1",
        port=443,
        depot_store_path="/mnt/labfoundry-vcf-offline-depot",
    )

    preview = render_nginx_depot_config(
        settings,
        certificate_path="/etc/labfoundry/vcf-offline-depot/certs/depot.crt",
        key_path="/etc/labfoundry/vcf-offline-depot/certs/depot.key",
    )

    assert "listen 192.168.50.1:443 ssl;" in preview
    assert "# VCF endpoint: https://depot.labfoundry.internal/PROD/" in preview
    assert "root /mnt/labfoundry-vcf-offline-depot;" not in preview
    assert "location = / {" in preview
    assert "proxy_pass http://127.0.0.1:8000;" in preview
    assert "location ^~ /static/" in preview
    assert "location = /favicon.ico" in preview
    assert "location = /manifest.webmanifest" in preview
    assert "location = /service-worker.js" in preview
    assert "location = /ca" not in preview
    assert "location ^~ /ca/" not in preview
    assert "location = /requests" not in preview
    assert "location ^~ /requests/" not in preview
    assert "location = /PROD" in preview
    assert "return 301 /PROD/;" in preview
    assert "location = /PROD/login" in preview
    assert "location = /PROD/logout" in preview
    assert "location = /_labfoundry_depot_auth" in preview
    assert "location = /PROD/" in preview
    assert "location ~ ^/PROD/.*/$" in preview
    assert "location ~ ^/PROD/(?!login$|logout$|auth-check$)(.+[^/])$" in preview
    assert "alias /mnt/labfoundry-vcf-offline-depot/PROD/$1;" in preview
    assert "location /" in preview
    assert "return 404;" in preview
    assert "sendfile on;" in preview
    assert "autoindex off;" in preview
    assert "default_type application/octet-stream;" in preview
    assert "ssl_certificate /etc/labfoundry/vcf-offline-depot/certs/depot.crt;" in preview
    assert "ssl_certificate_key /etc/labfoundry/vcf-offline-depot/certs/depot.key;" in preview
    assert "BEGIN PRIVATE KEY" not in preview


def test_vcf_depot_nginx_preview_brackets_ipv6_listeners():
    settings = VcfOfflineDepotSettings(
        enabled=True,
        hostname="depot.labfoundry.internal",
        listen_address="192.168.50.1\nfd87::254",
        port=443,
        depot_store_path="/mnt/labfoundry-vcf-offline-depot",
    )

    preview = render_nginx_depot_config(settings)

    assert "listen 192.168.50.1:443 ssl;" in preview
    assert "listen [fd87::254]:443 ssl;" in preview
    assert "listen fd87::254:443 ssl;" not in preview
