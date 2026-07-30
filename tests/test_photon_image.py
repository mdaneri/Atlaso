from pathlib import Path

import hashlib
import importlib.util
import json
import struct
import sys
import zipfile


def load_lifecycle_runner():
    path = Path("scripts/interop/lifecycle_test.py")
    spec = importlib.util.spec_from_file_location("lifecycle_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["lifecycle_test"] = module
    spec.loader.exec_module(module)
    return module


def sha256(path: str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def test_photon_image_installs_fixed_size_atlaso_grub_branding():
    background = Path("image/common/boot/grub/atlaso.png").read_bytes()
    photon_logo = Path("image/common/boot/grub/photon-os-logo.png").read_bytes()
    theme = Path("image/common/boot/grub/theme.txt").read_text(encoding="utf-8")
    installer = Path("scripts/appliance/atlaso-install-boot-branding").read_text(encoding="utf-8")
    provision = Path("image/common/scripts/provision-atlaso.sh").read_text(encoding="utf-8")
    deploy = Path("scripts/windows/vmware/deploy-wheel.ps1").read_text(encoding="utf-8")

    assert background[:8] == b"\x89PNG\r\n\x1a\n"
    assert struct.unpack(">II", background[16:24]) == (640, 480)
    assert photon_logo[:8] == b"\x89PNG\r\n\x1a\n"
    assert 'desktop-image: "atlaso.png"' in theme
    assert "Powered by Photon OS" not in theme  # Copy is rendered into the fixed background.
    assert "set theme=/grub2/themes/atlaso/theme.txt" in installer
    assert 'menuentry " "' in installer
    assert "atlaso-backup" in installer
    assert '"$ATLASO_HOME/bin/atlaso-install-boot-branding"' in provision
    assert "SkipBootBrandingSync" in deploy
    assert "/opt/atlaso/bin/atlaso-install-boot-branding" in deploy
    assert '"${SshUser}@${IpAddress}:$remoteBootThemePath"' in deploy
    assert '"${SshUser}@${IpAddress}:$remoteBootBackgroundPath"' in deploy


def test_inventory_linux_release_package_is_reproducible_and_deployable(tmp_path):
    path = Path("scripts/build_inventory_linux_package.py")
    spec = importlib.util.spec_from_file_location("build_inventory_linux_package", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    source = tmp_path / "source"
    (source / "legal-info").mkdir(parents=True)
    kernel = b"kernel"
    initrd = b"initrd"
    (source / "bzImage").write_bytes(kernel)
    (source / "rootfs.cpio.gz").write_bytes(initrd)
    (source / "legal-info/LICENSE").write_text("license\n", encoding="utf-8")
    (source / "manifest.json").write_text(
        json.dumps(
            {
                "kind": "atlaso-inventory-linux",
                "schema_version": 1,
                "version": "2026.05.1",
                "artifacts": {
                    "bzImage": hashlib.sha256(kernel).hexdigest(),
                    "rootfs.cpio.gz": hashlib.sha256(initrd).hexdigest(),
                },
            }
        ),
        encoding="utf-8",
    )
    first = module.package_inventory_linux(source, tmp_path / "first")
    second = module.package_inventory_linux(source, tmp_path / "second")
    assert hashlib.sha256(first.read_bytes()).digest() == hashlib.sha256(second.read_bytes()).digest()
    with zipfile.ZipFile(first) as package:
        assert {"manifest.json", "bzImage", "rootfs.cpio.gz", "legal-info/LICENSE"} <= set(package.namelist())

    deploy = Path("scripts/windows/vmware/deploy-wheel.ps1").read_text(encoding="utf-8")
    release = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
    assert "SkipInventoryLinuxSync" in deploy
    assert "[AllowEmptyString()][string[]]$Arguments" in deploy
    assert "Installed Atlaso Inventory Linux" in deploy
    assert (
        "install -d -o atlaso -g atlaso -m 0755 "
        "/var/lib/atlaso/pxe/media /var/lib/atlaso/pxe/uploads"
    ) in deploy
    restore_trap = deploy.index("trap restore_services_on_exit EXIT")
    stop_writers = deploy.index("systemctl stop atlaso-worker.service atlaso.service")
    media_preflight = deploy.index("Atlaso media path must not be a symlink")
    media_install = deploy.index(
        "install -d -o atlaso -g atlaso -m 0755 "
        "/var/lib/atlaso/pxe/media /var/lib/atlaso/pxe/uploads"
    )
    inventory_install = deploy.index(
        'if [ -n "$inventory_linux_package" ]; then'
    )
    disarm_trap = deploy.rindex("trap - EXIT")
    worker_active = deploy.index("systemctl is-active atlaso-worker.service")
    readiness_complete = deploy.index(
        'echo "Atlaso service restarted and loopback OpenAPI is reachable."'
    )
    assert restore_trap < stop_writers < media_preflight < media_install < inventory_install
    assert worker_active < disarm_trap < readiness_complete
    assert 'if [ "$atlaso_was_active" = "true" ]; then' in deploy
    assert 'if [ "$worker_was_active" = "true" ]; then' in deploy
    assert "systemctl stop atlaso.service" in deploy
    assert "systemctl stop atlaso-worker.service" in deploy
    assert "target.parent.is_symlink()" in deploy
    assert "target.is_symlink()" in deploy
    assert "installed_artifact.is_symlink()" in deploy
    assert "installed_manifest_path.is_symlink()" in deploy
    assert 'target / name for name in ("bzImage", "rootfs.cpio.gz", "manifest.json")' in deploy
    assert "owned_path.is_symlink()" in deploy
    assert "follow_symlinks=False" in deploy
    assert 'target.rglob("*")' not in deploy
    provision = Path("image/common/scripts/provision-atlaso.sh").read_text(
        encoding="utf-8"
    )
    assert (
        'install -d -o atlaso -g atlaso -m 0755 '
        '"$INVENTORY_MEDIA_DIR" "$INVENTORY_TARGET_DIR"'
        in provision
    )
    assert (
        'install -o atlaso -g atlaso -m 0644 "$INVENTORY_SOURCE_DIR/$artifact"'
        in provision
    )
    assert "command -v gpg" in deploy
    assert "tdnf -y install gnupg" in deploy
    assert "Build Inventory Linux package" in release
    assert "--inventory-package" in release
    build = Path("image/inventory-linux/build.sh").read_text(encoding="utf-8")
    assert 'buildroot_version="2026.05.1"' in build
    assert 'package_version="2026.05.1+3"' in build
    assert '"version": "${package_version}"' in build
    init = Path(
        "image/inventory-linux/external/overlay/etc/init.d/S99atlaso-inventory"
    ).read_text(encoding="utf-8")
    assert "atlaso.boot_mac=*" in init
    assert 'candidate_mac="$(cat "${candidate_path}/address"' in init
    assert 'udhcpc -i "${candidate}"' in init
    assert 'grep -q " dev ${candidate}' in init
    assert "for candidate_path in /sys/class/net/*" in init
    assert init.index("udhcpc -i") < init.index("/usr/bin/atlaso-inventory")
    assert 'installed_manifest.get("kind") != "atlaso-network-boot-media"' in deploy
    assert 'installed_manifest.get("environment") != "inventory"' in deploy


def test_inventory_linux_retries_uncertain_reboot_acknowledgments():
    client = Path(
        "image/inventory-linux/external/overlay/usr/bin/atlaso-inventory"
    ).read_text(encoding="utf-8")

    assert 'pending_reboot_id=""' in client
    assert 'pending_reboot_id="${command_id}"' in client
    assert "commands/${pending_reboot_id}/acknowledge" in client
    assert client.index("commands/${pending_reboot_id}/acknowledge") < client.index(
        "reboot -f"
    )


def test_inventory_linux_retries_capacity_responses_with_bounded_backoff():
    client = Path(
        "image/inventory-linux/external/overlay/usr/bin/atlaso-inventory"
    ).read_text(encoding="utf-8")

    assert "--write-out '%{http_code}'" in client
    assert '[ "${report_status}" != "503" ]' in client
    assert '[ "${report_attempt}" -ge 6 ]' in client
    assert "sleep $((report_attempt * 2))" in client
    assert "response body" not in client


def test_photon_provisioning_management_network_matches_eth0_only():
    script = Path("image/common/scripts/provision-atlaso.sh").read_text(encoding="utf-8")
    main = Path("atlaso/app/main.py").read_text(encoding="utf-8")
    seed = Path("atlaso/app/seed.py").read_text(encoding="utf-8")

    assert 'ATLASO_MGMT_INTERFACE="${ATLASO_MGMT_INTERFACE:-eth0}"' in script
    assert 'printf \'Name=%s\\n\\n\' "$ATLASO_MGMT_INTERFACE"' in script
    assert "Name=eth* en*" not in script
    assert "rm -f /etc/systemd/network/50-static-en.network /etc/systemd/network/99-dhcp-en.network" in script
    assert "seed_initial_data(db, include_examples=not appliance_mode, appliance_mode=appliance_mode)" in main
    assert "ensure_ca_state(db)" in main
    assert main.index("refresh_startup_host_inventory(db, environment=settings.environment)") < main.index("ensure_ca_state(db)")
    assert "if include_examples:" in seed
    assert "management_https_enabled=appliance_mode" in seed
    assert 'install -d -o atlaso -g atlaso -m 0700 "$ATLASO_STATE/vcfDownloadTool/active-tool/secrets"' in script


def test_photon_provisioning_installs_default_nginx_management_proxy():
    script = Path("image/common/scripts/provision-atlaso.sh").read_text(encoding="utf-8")
    bootstrap = Path("scripts/appliance/atlaso-bootstrap-https").read_text(encoding="utf-8")
    systemd_unit = Path("image/hyperv/systemd/atlaso.service").read_text(encoding="utf-8")
    worker_unit = Path("image/common/systemd/atlaso-worker.service").read_text(encoding="utf-8")
    sudoers = Path("image/hyperv/sudoers.d/atlaso-helper").read_text(encoding="utf-8")
    docs = Path("image/hyperv/README.md").read_text(encoding="utf-8")
    root_docs = Path("docs/reference/full-technical-reference.md").read_text(encoding="utf-8")

    assert 'run_tdnf "Photon appliance package installation"' in script
    assert "nginx" in script
    assert "gnupg" in script
    assert "ntpsec" in script
    assert "python3-ntp" in script
    assert "systemctl disable --now ntpd.service" in script
    assert "systemctl disable --now systemd-timesyncd.service" in script
    assert "systemctl disable --now chronyd.service" in script
    assert '"$ATLASO_STATE/apply/ntpd"' in script
    assert "openldap-servers" in script
    assert "nfs-utils" in script and "rpcbind" in script
    assert "99-atlaso-disk-identity.rules" in script
    assert 'IMPORT{builtin}="path_id"' in script
    assert 'SYMLINK+="disk/by-id/atlaso-path-$env{ID_PATH_TAG}"' in script
    assert "powershell" in script
    assert "VCF.PowerCLI" in script
    assert "9.1.0.25380678" in script
    assert "Connect-VIServer" in script
    assert "Set-PowerCLIConfiguration -ParticipateInCeip $false -Scope AllUsers -Confirm:$false" in script
    assert "Get-PowerCLIConfiguration -Scope AllUsers" in script
    assert "ATLASO_POWERCLI_MODULE_SOURCE" in script
    assert "chmod 0755 /usr/local/share/powershell /usr/local/share/powershell/Modules" in script
    assert "chmod -R a+rX,go-w /usr/local/share/powershell/Modules" in script
    assert "ipxe" in script
    assert "syslinux" in script
    assert "IPXE_BOOTLOADER_SOURCE_DIR=\"$ATLASO_HOME/third_party/ipxe/bootloaders\"" in script
    assert "IPXE_BOOTLOADER_TARGET_DIR=\"$ATLASO_STATE/pxe/bootloaders\"" in script
    assert "staging bundled iPXE bootloaders" in script
    assert '"$IPXE_BOOTLOADER_TARGET_DIR/undionly.kpxe"' in script
    assert '"$IPXE_BOOTLOADER_TARGET_DIR/snponly.efi"' in script
    assert 'BOOTSTRAP_SHELL="${ATLASO_BOOTSTRAP_ADMIN_SHELL:-/usr/bin/pwsh}"' in script
    assert 'ln -sfn "$ATLASO_HOME/.venv/bin/atlaso-vault" /usr/local/bin/atlaso-vault' in script
    assert 'ln -sfn "$ATLASO_HOME/.venv/bin/atlaso-vault" /usr/bin/atlaso-vault' in script
    assert '"$ATLASO_HOME/image/common/powershell/atlaso-vault-profile.ps1"' in script
    profile = Path("image/common/powershell/atlaso-vault-profile.ps1").read_text(encoding="utf-8")
    assert "function global:Get-AtlasoVault" in profile
    assert "/opt/atlaso/.venv/bin/atlaso-vault" in profile
    assert '--shell "$BOOTSTRAP_SHELL"' in script
    assert "touch /etc/shells" in script
    assert 'grep -qxF "$BOOTSTRAP_SHELL" /etc/shells' in script
    assert "atlaso-bootstrap-admin" in script
    assert "$BOOTSTRAP_USERNAME ALL=(ALL) ALL" in script
    assert "visudo -cf /etc/sudoers.d/atlaso-bootstrap-admin" in script
    assert (
        'sudo -H -u "$BOOTSTRAP_USERNAME" env -u PSModulePath '
        'ATLASO_POWERCLI_VERSION="$ATLASO_POWERCLI_VERSION"'
    ) in script
    assert "is not available to the bootstrap administrator" in script
    assert 'chmod 0711 "$ATLASO_STATE"' in script
    assert 'chown "$BOOTSTRAP_USERNAME:$(id -gn "$BOOTSTRAP_USERNAME")" "$ATLASO_STATE/users/$BOOTSTRAP_USERNAME"' in script
    assert 'chmod 0750 "$ATLASO_STATE/users/$BOOTSTRAP_USERNAME"' in script
    assert "UMask=0027" in systemd_unit
    assert "--host 127.0.0.1 --port 8000" in systemd_unit
    assert "--host 0.0.0.0" not in systemd_unit
    assert "configuring first-boot Atlaso management nginx bootstrap" in script
    assert "install -d -o root -g root -m 0755 /etc/nginx/conf.d" in script
    assert "/etc/nginx/conf.d/atlaso.conf" in script
    assert "/etc/atlaso/nginx/sites.d/management.conf" in bootstrap
    assert "rm -f /etc/nginx/conf.d/default.conf /etc/nginx/conf.d/default_server.conf" in script
    assert "atlaso-bootstrap-https" in script
    assert "atlaso-bootstrap-https.service" in script
    assert "ExecStart=/opt/atlaso/.venv/bin/python /opt/atlaso/bin/atlaso-bootstrap-https" in script
    assert "EnvironmentFile=/etc/atlaso/atlaso.env" in script
    assert "After=network-online.target atlaso-data-disks.service atlaso-vmware-ovf-customize.service" in script
    assert "Wants=network-online.target atlaso-data-disks.service" in script
    assert "ConditionPathExists=!/var/lib/atlaso/first-boot-https.applied" in script
    assert '"$ATLASO_HOME/.venv/bin/python" "$ATLASO_HOME/bin/atlaso-bootstrap-https"' not in script
    assert "sync_host_physical_interfaces(db)" in bootstrap
    assert bootstrap.index("sync_host_physical_interfaces(db)") < bootstrap.index("ensure_ca_state(db)")
    assert 'str(HELPER_PATH), "ca", action, str(CA_STAGED_CONFIG_PATH), "--real"' in bootstrap
    assert 'for db_file in state_path.glob("atlaso.db*")' in bootstrap
    assert 'shutil.chown(db_file, user="atlaso", group="atlaso")' in bootstrap
    assert 'for path in [ca_apply_path, *ca_apply_path.rglob("*")]' in bootstrap
    assert 'listen 80 default_server;' in bootstrap
    assert "location = /ca/downloads/root-ca.pem {" in bootstrap
    assert "location = /ca/downloads/ca-bundle.pem {" in bootstrap
    assert 'return 308 https://$host$request_uri;' in bootstrap
    assert "location / {{\n    return 308 https://$host$request_uri;" in bootstrap
    assert 'listen 443 ssl default_server;' in bootstrap
    assert 'ssl_certificate {cert_path};' in bootstrap
    assert 'ssl_certificate_key {key_path};' in bootstrap
    assert "client_max_body_size 1g;" in bootstrap
    assert "client_max_body_size 512m;" not in bootstrap
    assert "proxy_pass http://127.0.0.1:8000;" in bootstrap
    assert "proxy_set_header Host $host;" in bootstrap
    assert "proxy_set_header X-Real-IP $remote_addr;" in bootstrap
    assert "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;" in bootstrap
    assert "proxy_set_header X-Forwarded-Proto https;" in bootstrap
    assert "proxy_set_header X-Forwarded-Proto http;" in bootstrap
    assert "proxy_set_header Upgrade $http_upgrade;" in bootstrap
    assert "nginx -t" in script
    assert "systemctl enable --now nginx" in script
    assert 'ATLASO_DRY_RUN_SYSTEM_ADAPTERS="${ATLASO_DRY_RUN_SYSTEM_ADAPTERS:-true}"' in script
    assert 'ATLASO_MGMT_SOURCE_CIDR="${ATLASO_MGMT_SOURCE_CIDR:-}"' in script
    assert 'ATLASO_MGMT_USES_DHCP=false' in script
    assert 'ATLASO_APPLIANCE_EXTERNAL_DNS_SERVERS=$(if [ "$ATLASO_MGMT_USES_DHCP" = "true" ]; then printf \'\'; else printf \'%s\' "$ATLASO_MGMT_DNS" | tr \' \' \',\'; fi)' in script
    assert 'if [ "$ATLASO_MGMT_USES_DHCP" != "true" ] && [ -n "$ATLASO_MGMT_DNS" ]; then' in script
    assert 'ip -4 -o addr show dev "$ATLASO_MGMT_INTERFACE" scope global' in script
    assert 'DETECTED_MGMT_ADDRESS' in script
    assert "ipaddress.ip_interface(sys.argv[1]).network" in script
    assert "printf '\\nATLASO_MANAGEMENT_SOURCE_CIDR=%s\\n' \"$ATLASO_MGMT_SOURCE_CIDR\" >>/etc/atlaso/atlaso.env" in script
    assert 'log_step "system adapter dry-run mode: $ATLASO_DRY_RUN_SYSTEM_ADAPTERS"' in script
    assert "ATLASO_DRY_RUN_SYSTEM_ADAPTERS=$ATLASO_DRY_RUN_SYSTEM_ADAPTERS" in script
    assert 'ATLASO_MGMT_ACCESS_RULE="    ip saddr $ATLASO_MGMT_SOURCE_CIDR tcp dport { 22, 80, 443 } accept comment \\"Atlaso management access\\""' in script
    assert 'ATLASO_MGMT_ACCESS_RULE="    iifname \\"$ATLASO_MGMT_INTERFACE\\" tcp dport { 22, 80, 443 } accept comment \\"Atlaso management access\\""' in script
    assert "$ATLASO_MGMT_ACCESS_RULE" in script
    assert 'install -o root -g root -m 0440 "$ATLASO_HOME/$ATLASO_IMAGE_ASSET_DIR/sudoers.d/atlaso-helper" /etc/sudoers.d/atlaso-helper' in script
    assert 'sed -i \'s/\\r$//\'' in script
    assert '"$ATLASO_HOME/bin/atlaso-install-boot-branding"' in script
    assert "/etc/systemd/system/atlaso-worker.service" in script
    assert 'useradd --system --gid atlaso-automation' in script
    assert 'systemctl enable atlaso-worker.service' in script
    assert "RuntimeDirectory=atlaso-automation-vaults" in worker_unit
    assert "RuntimeDirectoryMode=0700" in worker_unit
    assert "atlaso ALL=(root) NOPASSWD: /opt/atlaso/bin/atlaso-helper *" in sudoers
    assert "atlaso-root-login.conf" in script
    assert "PermitRootLogin no" in script
    assert "HTTPS/443" in docs
    assert "HTTP/80 redirects to HTTPS" in docs
    assert "proxying HTTPS/443 to" in root_docs
    assert "-PipGlobalIndex" in root_docs
    assert "-PipGlobalIndexUrl" in root_docs
    assert "Leave both options empty to keep" in root_docs
    assert "standard pip behavior" in root_docs


def test_photon_provisioning_prepares_attached_data_disks():
    provision = Path("image/common/scripts/provision-atlaso.sh").read_text(encoding="utf-8")
    mount_script = Path("scripts/appliance/atlaso-mount-data-disks").read_text(encoding="utf-8")
    hyperv_unit = Path("image/hyperv/systemd/atlaso.service").read_text(encoding="utf-8")
    vmware_unit = Path("image/vmware-workstation/systemd/atlaso.service").read_text(encoding="utf-8")
    hyperv_docs = Path("image/hyperv/README.md").read_text(encoding="utf-8")
    vmware_docs = Path("image/vmware-workstation/README.md").read_text(encoding="utf-8")
    root_docs = Path("docs/reference/full-technical-reference.md").read_text(encoding="utf-8")

    assert 'run_tdnf "Photon appliance package installation"' in provision
    assert "e2fsprogs" in provision
    assert "atlaso-mount-data-disks" in provision
    assert "atlaso-data-disks.service" in provision
    assert "systemctl enable atlaso-data-disks.service" in provision
    assert "Before=atlaso-bootstrap-https.service atlaso.service" in provision

    assert "ATLASO_DEPOT" in mount_script
    assert "ATLASO_BKUP" in mount_script
    assert "/mnt/atlaso-vcf-offline-depot" in mount_script
    assert "/mnt/atlaso-vcf-backups" in mount_script
    assert 'mkfs.ext4 -F -L "$label" "$disk"' in mount_script
    assert "UUID=%s %s ext4 defaults,nofail,x-systemd.device-timeout=30s 0 2" in mount_script
    assert "findmnt -n -o SOURCE /" in mount_script
    assert "No blank data disk available" in mount_script

    assert "After=network-online.target atlaso-data-disks.service atlaso-bootstrap-https.service" in hyperv_unit
    assert "Wants=network-online.target atlaso-data-disks.service atlaso-bootstrap-https.service" in hyperv_unit
    assert "After=network-online.target atlaso-data-disks.service atlaso-bootstrap-https.service" in vmware_unit
    assert "Wants=network-online.target atlaso-data-disks.service atlaso-bootstrap-https.service" in vmware_unit

    assert "atlaso-data-disks.service" in root_docs
    assert "atlaso-data-disks.service" in hyperv_docs
    assert "atlaso-data-disks.service" in vmware_docs
    assert "Format and mount" not in hyperv_docs


def test_bundled_ipxe_bootloaders_have_provenance_and_expected_hashes():
    readme = Path("third_party/ipxe/README.md").read_text(encoding="utf-8")
    copying = Path("third_party/ipxe/COPYING").read_text(encoding="utf-8")
    gpl = Path("third_party/ipxe/COPYING.GPLv2").read_text(encoding="utf-8")
    undionly_licence = Path("third_party/ipxe/bootloaders/undionly.kpxe.licence").read_text(encoding="utf-8")
    snponly_licence = Path("third_party/ipxe/bootloaders/snponly.efi.licence").read_text(encoding="utf-8")

    assert Path("third_party/ipxe/bootloaders/source-commit.txt").read_text(encoding="utf-8").strip() == "bbd7821bd42da5456ee068a471ef73d525ea26a1"
    assert sha256("third_party/ipxe/bootloaders/undionly.kpxe") == "b2ff1718908401bd71d5f84d433ec5c2e73fe563866ad904d0c3fa3d9ce67c0b"
    assert sha256("third_party/ipxe/bootloaders/snponly.efi") == "a3fec333e4ae52c33b3ef8b140422a16019c4d7aa63a13f8ac3c95079fad0715"
    assert sha256("third_party/ipxe/bootloaders/undionly.kpxe.licence") == "4c06a9f1384900fa50c68042795e11d1939bbee3b76f4b692f7655c99d3026d8"
    assert sha256("third_party/ipxe/bootloaders/snponly.efi.licence") == "04369e5a91dc2cfb5c86ca6a1db031897ceb349c46f8f5c06c4a8e7bdc6ab5f8"
    assert "make -j2 bin/undionly.kpxe bin-x86_64-efi/snponly.efi" in readme
    assert "GPL version 2 (or, at your option, any later version)" in undionly_licence
    assert "GPL version 2 (or, at your option, any later version)" in snponly_licence
    assert "make bin/xxxxxxx.yyy.licence" in copying
    assert "GNU GENERAL PUBLIC LICENSE" in gpl


def test_packer_templates_stage_shared_appliance_assets():
    for template_path in (
        Path("image/hyperv/atlaso-photon.pkr.hcl"),
        Path("image/vmware-workstation/atlaso-photon.pkr.hcl"),
    ):
        template = template_path.read_text(encoding="utf-8")

        assert 'source      = "../common/boot"' in template
        assert 'destination = "/tmp/atlaso-src/image/common/boot"' in template
        assert 'source      = "../common/powershell"' in template
        assert 'destination = "/tmp/atlaso-src/image/common/powershell"' in template


def test_photon_kickstart_uses_deterministic_build_time_sshd_service():
    build_module = Path("scripts/windows/common/Atlaso.PhotonImage.psm1").read_text(encoding="utf-8")

    disable_socket = "'systemctl disable sshd.socket'"
    enable_service = "'systemctl enable sshd.service'"
    assert disable_socket in build_module
    assert enable_service in build_module
    assert "'systemctl enable sshd'" not in build_module
    assert build_module.index(disable_socket) < build_module.index(enable_service)


def test_packer_build_uses_atlaso_management_network_by_default():
    template = Path("image/hyperv/atlaso-photon.pkr.hcl").read_text(encoding="utf-8")
    docs = Path("image/hyperv/README.md").read_text(encoding="utf-8")
    root_docs = Path("docs/reference/full-technical-reference.md").read_text(encoding="utf-8")
    wrapper = Path("scripts/windows/hyperv/build-photon-image.ps1").read_text(encoding="utf-8")
    build_module = Path("scripts/windows/common/Atlaso.PhotonImage.psm1").read_text(encoding="utf-8")
    gitignore = Path(".gitignore").read_text(encoding="utf-8")

    assert 'default = "Atlaso-Mgmt"' in template
    assert 'default     = "192.168.49.30/24"' in template
    assert 'default     = "255.255.255.0"' in template
    assert 'default     = "192.168.49.254"' in template
    assert 'variable "iso_contains_kickstart"' in template
    assert 'variable "dry_run_system_adapters"' in template
    assert 'variable "pip_global_index"' in template
    assert 'description = "Optional pip global.index value. Empty keeps default pip behavior."' in template
    assert 'variable "pip_global_index_url"' in template
    assert 'description = "Optional pip global.index-url value. Empty keeps default pip behavior."' in template
    assert 'builder_static_dns_text      = join(" ", var.builder_static_dns)' in template
    assert 'dry_run_system_adapters_text = var.dry_run_system_adapters ? "true" : "false"' in template
    assert '"ATLASO_DRY_RUN_SYSTEM_ADAPTERS=${local.dry_run_system_adapters_text}"' in template
    assert '"ATLASO_MGMT_DNS=${local.builder_static_dns_text}"' in template
    assert '"ATLASO_PIP_GLOBAL_INDEX=${var.pip_global_index}"' in template
    assert '"ATLASO_PIP_GLOBAL_INDEX_URL=${var.pip_global_index_url}"' in template
    assert "Iso_contains_kickstart must be true" in template
    assert "secondary_iso_images" not in template
    assert "boot_command" not in template
    assert "boot_keygroup_interval" not in template
    assert "Packer should not race" in template
    assert "http_content" not in template
    assert "http_port_min" not in template
    assert 'default = "Default Switch"' not in template
    assert "build-photon-image.ps1" in root_docs
    assert "create-switches.ps1" in docs
    assert "builder_static_ip=192.168.49.30/24" in docs
    assert "discovers the host's active IPv4 DNS" in docs
    assert "atlaso-photon-with-kickstart.iso" in docs
    assert "Using remastered Photon ISO" in docs
    assert "without Packer typing boot commands" in docs
    assert "-PipGlobalIndex" in docs
    assert "-PipGlobalIndexUrl" in docs
    assert "Omit both pip options for standard/default pip behavior." in docs
    assert "[string]$SshPassword = 'PhotonBuild01!'" in wrapper
    assert "[string]$BootstrapAdminPassword = 'VMware01!'" in wrapper
    assert "[string]$SshPassword = 'VMware01!'" not in wrapper
    assert "[string[]]$BuilderStaticDns = @()" in wrapper
    assert "[string]$PipGlobalIndex = ''" in wrapper
    assert "[string]$PipGlobalIndexUrl = ''" in wrapper
    assert "Join-Path $PSScriptRoot '..\\common\\Atlaso.PhotonImage.psm1'" in wrapper
    assert "Join-Path $PSScriptRoot '..\\..\\..\\image\\hyperv'" in wrapper
    assert "function Get-AtlasoHostIpv4DnsServers" in build_module
    assert "Get-DnsClientServerAddress -AddressFamily IPv4" in build_module
    assert "Using host IPv4 DNS for Photon builder/appliance" in build_module
    assert "falling back to public DNS" in build_module
    assert "create_photon_kickstart_iso.py" in build_module
    assert "Using remastered Photon ISO" in build_module
    assert "Packer will boot a single DVD with embedded photon-ks.json and a GRUB auto-install entry." in build_module
    assert "Write-AtlasoPackerVarFile" in build_module
    assert "Using Packer var-file" in build_module
    assert "[ValidateSet('cleanup', 'abort', 'ask', 'run-cleanup-provisioner')]" in wrapper
    assert "[string]$PackerOnError = 'cleanup'" in wrapper
    assert "[switch]$KeepExistingOutput" in wrapper
    assert "[switch]$EnableRealSystemAdapters" in wrapper
    assert "Packer build will replace any existing output directory for this build." in build_module
    assert "$packerArgs += '-force'" in build_module
    assert '$packerArgs += "-on-error=$PackerOnError"' in build_module
    assert "'-var-file', $varFilePath" in build_module
    assert "builder_static_dns       = $BuilderStaticDns" in build_module
    assert "pip_global_index         = $PipGlobalIndex" in build_module
    assert "pip_global_index_url     = $PipGlobalIndexUrl" in build_module
    assert "dry_run_system_adapters  = -not $EnableRealSystemAdapters" in build_module
    assert "UseHttpKickstartFallback" not in wrapper
    assert "/image/hyperv/build" in gitignore
    remaster_helper = Path("scripts/interop/create_photon_kickstart_iso.py").read_text(encoding="utf-8")
    assert "iso.add_file" in remaster_helper
    assert 'rr_name="photon-ks.json"' in remaster_helper
    assert "GRUB_BOOT_CONFIG" in remaster_helper
    assert "GRUB_CONFIG_TARGETS" in remaster_helper
    assert '"/BOOT/GRUB2/GRUB.CFG;1"' in remaster_helper
    assert "ks=cdrom:/photon-ks.json" in remaster_helper
    assert "photon.media=cdrom" in remaster_helper
    assert '"/EFI/BOOT/GRUB.CFG;1"' in remaster_helper
    assert '"/BOOT/GRUB2/GRUB.CFG;1", "grub.cfg"' in remaster_helper
    assert '"/EFI/BOOT/GRUB.CFG;1", "grub.cfg"' in remaster_helper
    assert "iso.add_fp" in remaster_helper
    assert "iso.rm_file" in remaster_helper
    assert "Could not embed Atlaso GRUB config" in remaster_helper


def test_photon_image_optional_pip_global_index_configuration():
    wrapper = Path("scripts/windows/hyperv/build-photon-image.ps1").read_text(encoding="utf-8")
    build_module = Path("scripts/windows/common/Atlaso.PhotonImage.psm1").read_text(encoding="utf-8")
    template = Path("image/hyperv/atlaso-photon.pkr.hcl").read_text(encoding="utf-8")
    vmware_template = Path("image/vmware-workstation/atlaso-photon.pkr.hcl").read_text(encoding="utf-8")
    script = Path("image/common/scripts/provision-atlaso.sh").read_text(encoding="utf-8")

    assert "[string[]]$BuilderStaticDns = @()" in wrapper
    assert "[string]$PipGlobalIndex = ''" in wrapper
    assert "[string]$PipGlobalIndexUrl = ''" in wrapper
    assert "Join-Path $PSScriptRoot '..\\common\\Atlaso.PhotonImage.psm1'" in wrapper
    assert "pip_global_index         = $PipGlobalIndex" in build_module
    assert "pip_global_index_url     = $PipGlobalIndexUrl" in build_module

    assert 'variable "pip_global_index" {\n  type        = string\n  default     = ""' in template
    assert 'variable "pip_global_index_url" {\n  type        = string\n  default     = ""' in template
    assert '"ATLASO_PIP_GLOBAL_INDEX=${var.pip_global_index}"' in template
    assert '"ATLASO_PIP_GLOBAL_INDEX_URL=${var.pip_global_index_url}"' in template

    assert 'ATLASO_PIP_GLOBAL_INDEX="${ATLASO_PIP_GLOBAL_INDEX:-}"' in script
    assert 'ATLASO_PIP_GLOBAL_INDEX_URL="${ATLASO_PIP_GLOBAL_INDEX_URL:-}"' in script
    assert 'PIP_CACHE_DIR="${PIP_CACHE_DIR:-/var/cache/atlaso-pip}"' in script
    assert "write_pip_config() {" in script
    assert 'printf \'index = %s\\n\' "$ATLASO_PIP_GLOBAL_INDEX"' in script
    assert 'printf \'index-url = %s\\n\' "$ATLASO_PIP_GLOBAL_INDEX_URL"' in script
    assert 'printf \'cache-dir = %s\\n\' "$PIP_CACHE_DIR"' in script
    assert 'write_pip_config /etc/pip.conf' in script
    assert 'python3 -m venv "$ATLASO_RELEASE_DIR/.venv"' in script
    assert (
        'python3 "$ATLASO_HOME/scripts/version.py" project-get --root "$ATLASO_HOME"'
        in script
    )
    assert "sed -n 's/^version" not in script
    assert 'ATLASO_RELEASE_DIR="$ATLASO_HOME/releases/bootstrap-$ATLASO_RELEASE_VERSION"' in script
    assert '"$ATLASO_RELEASE_DIR/bundle-metadata.json"' in script
    assert 'ln -sfn "releases/bootstrap-$ATLASO_RELEASE_VERSION" "$ATLASO_HOME/current"' in script
    assert 'ln -sfn "current/.venv" "$ATLASO_HOME/.venv"' in script
    assert 'write_pip_config "$ATLASO_HOME/.venv/pip.conf"' in script
    assert '--requirement "$ATLASO_HOME/requirements-appliance.lock"' in script
    assert 'pip install --no-deps "$ATLASO_HOME"' in script
    assert "/etc/atlaso/update-trust.d" in script
    assert 'trust_source_dir="$ATLASO_HOME/image/common/update-trust"' in script
    assert 'for trust_key in "$trust_source_dir"/*.pem' in script
    for packer_template in (template, vmware_template):
        assert 'source      = "../../requirements-appliance.lock"' in packer_template
        assert 'destination = "/tmp/atlaso-src/requirements-appliance.lock"' in packer_template
        assert 'source      = "../../scripts/generate_third_party_notices.py"' in packer_template
        assert 'destination = "/tmp/atlaso-src/scripts/generate_third_party_notices.py"' in packer_template
        assert 'source      = "../../scripts/third_party_notices.json"' in packer_template
        assert 'destination = "/tmp/atlaso-src/scripts/third_party_notices.json"' in packer_template
        assert 'source      = "../../scripts/version.py"' in packer_template
        assert 'destination = "/tmp/atlaso-src/scripts/version.py"' in packer_template
        assert 'source      = "../../scripts/run_tdnf_with_progress.py"' in packer_template
        assert 'destination = "/tmp/atlaso-src/scripts/run_tdnf_with_progress.py"' in packer_template
        assert 'source      = "../common/update-trust"' in packer_template
        assert 'destination = "/tmp/atlaso-src/image/common/update-trust"' in packer_template
    assert "Atlaso release trust source directory is missing" in script
    assert "No Atlaso release trust keys were staged" in script
    assert 'openssl pkey -pubin -in "$trust_key" -text -noout' in script
    assert "*ED25519*" in script
    assert 'export PIP_DISABLE_PIP_VERSION_CHECK=1' in script
    assert 'export PIP_INDEX_URL="$ATLASO_PIP_GLOBAL_INDEX_URL"' in script
    assert "pip install --upgrade pip setuptools wheel" not in script
    assert "packages.vcfd.broadcom.net/artifactory" not in wrapper
    assert "packages.vcfd.broadcom.net/artifactory" not in template
    assert "packages.vcfd.broadcom.net/artifactory" not in script
    assert 'TDNF_PROGRESS_RUNNER="$ATLASO_SRC/scripts/run_tdnf_with_progress.py"' in script
    assert 'run_tdnf "Photon package metadata refresh" makecache' in script
    assert 'run_tdnf "Photon OS update" update' in script
    assert 'run_tdnf "Photon appliance package installation"' in script
    assert 'run_tdnf "Photon OS update verification" update' in script
    assert "\ntdnf -y update" not in script


def test_vmware_builder_uses_nat_gateway_dns_by_default():
    wrapper = Path("scripts/windows/vmware/build-photon-image.ps1").read_text(encoding="utf-8")
    docs = Path("image/vmware-workstation/README.md").read_text(encoding="utf-8")

    assert "[string]$SshPassword = 'PhotonBuild01!'" in wrapper
    assert "[string]$BootstrapAdminPassword = 'VMware01!'" in wrapper
    assert "[string]$SshPassword = 'VMware01!'" not in wrapper
    assert "$builderDnsWasPassed = $PSBoundParameters.ContainsKey('BuilderStaticDns')" in wrapper
    assert "-not $builderDnsWasPassed -and $BuilderStaticDns.Count -eq 0 -and $management.Type -eq 'nat'" in wrapper
    assert "$BuilderStaticDns = @($managementGateway)" in wrapper
    assert "Using VMware NAT gateway DNS for Photon builder" in wrapper
    assert "Photon builder temporary SSH address" in wrapper
    assert "gateway DNS proxy" in docs
    assert "copying unrelated host" in docs
    assert "servers into the Photon kickstart" in docs


def test_lifecycle_hyperv_script_uses_separate_vm_set_by_default():
    script = Path("scripts/windows/hyperv/run-lifecycle-test.ps1").read_text(encoding="utf-8")
    wrapper = Path("scripts/windows/hyperv/invoke-lifecycle-test.ps1").read_text(encoding="utf-8")
    runner = Path("scripts/interop/lifecycle_test.py").read_text(encoding="utf-8")

    assert "[string]$LabName = 'AtlasoLifecycle'" in script
    assert "[string]$ApplianceUrl = ''" in script
    assert '$ApplianceUrl = "https://${ApplianceIPAddress}"' in script
    assert "'--appliance-url', $ApplianceUrl" in script
    assert '"http://${ApplianceIPAddress}:8000"' not in script
    assert "[string]$ApplianceUrl = ''" in wrapper
    assert '"https://${ApplianceIPAddress}"' in wrapper
    assert '"http://${ApplianceIPAddress}:8000"' not in wrapper
    assert "'-ApplianceUrl', $effectiveApplianceUrl" in wrapper
    assert 'parser.add_argument("--appliance-url", default="https://192.168.49.1")' in runner
    assert "[string]$SiteInterface = 'eth1.12'" in script
    assert "[string]$SiteCidr = '192.168.12.1/24'" in script
    assert "[int]$SiteVlanId = 12" in script
    assert "$applianceName = \"$LabName-Appliance\"" in script
    assert "$clientAName = \"$LabName-ClientA\"" in script
    assert "$clientBName = \"$LabName-ClientB\"" in script
    assert "$pxeClientName = \"$LabName-PxeBoot\"" in script
    assert "New-LifecyclePxeVm -Name $pxeClientName -SwitchName 'Atlaso-SiteA'" in script
    assert "Invoke-PxeBootSmoke -Name $pxeClientName -MacAddress $pxeClientMac" in script
    assert "[string]$EsxIsoPath = ''" in script
    assert "[string]$EsxIsoPath = ''" in wrapper
    assert "'-EsxIsoPath', $EsxIsoPath" in wrapper
    assert "--pxe-test-mode" in runner
    assert "--pxe-client-mac" in runner
    assert "--pxe-installer-iso-path" in runner
    assert "[string]$SignedReleaseRepositoryUrl = ''" in script
    assert "[string]$SignedReleaseRepositoryUrl = ''" in wrapper
    assert "'--signed-release-repository-url', $SignedReleaseRepositoryUrl" in script
    assert "'-SignedReleaseRepositoryUrl', $SignedReleaseRepositoryUrl" in wrapper
    assert "signed_release_update_check" in runner
    assert '"signed-release-update-check"' in runner
    assert '"schema_sha256"' in runner
    assert 'transaction.get("rolled_back") is not True' in runner
    assert '"esxi_pxe"' in runner
    assert "configure-esxi-pxe" in runner
    assert "Refusing to use reserved VM name" in script
    assert "@('Atlaso', 'Atlaso-Photon-Builder')" in script
    assert "image\\hyperv\\clients\\alpine-cloud\\atlaso-tiny-linux-client.vhdx" in script
    assert "Running lifecycle appliance VM(s) may already own ${ApplianceIPAddress}" in script
    assert "-CleanupVmsOnly" in script


def test_create_atlaso_test_vm_wrapper_is_safe_and_simple():
    script = Path("scripts/windows/hyperv/create-atlaso-test-vm.ps1").read_text(encoding="utf-8")
    vm_script = Path("scripts/windows/hyperv/create-atlaso-vm.ps1").read_text(encoding="utf-8")
    docs = Path("image/hyperv/README.md").read_text(encoding="utf-8")

    assert "[string]$Name = 'Atlaso'" in script
    assert "[switch]$Redeploy" in script
    assert "[switch]$ResetDataDisks" in script
    assert "[switch]$SkipLabNetworkAdapters" in script
    assert "[int]$SiteVlanId = 12" in script
    assert "[int]$TaggedVlanId = 50" in script
    assert "[switch]$WaitForIp" in script
    assert "Find-LatestApplianceVhdx" in script
    assert "Remove-ExistingDataDisks" in script
    assert "Atlaso-Depot.vhdx" in script
    assert "Atlaso-Backups.vhdx" in script
    assert "Refusing to remove OS disk as a data disk" in script
    assert "create-switches.ps1" in script
    assert "create-atlaso-vm.ps1" in script
    assert "-SkipLabNetworkAdapters:$SkipLabNetworkAdapters" in script
    assert "-SiteVlanId $SiteVlanId" in script
    assert "-TaggedVlanId $TaggedVlanId" in script
    assert "start-atlaso-vm.ps1" in script
    assert "get-atlaso-vm-ip.ps1" in script
    assert "VM already exists: $Name. Pass -Redeploy" in script
    assert "Remove-VM -Name $Name -Force" in script
    assert "Run this script from an elevated PowerShell session." not in script
    assert "create-atlaso-test-vm.ps1 -WaitForIp" in docs
    assert "`-Redeploy` to remove and recreate only that VM" in docs
    assert "first adapter management-only on `Atlaso-Mgmt`" in docs
    assert "second adapter is `Services`" in docs
    assert "`Atlaso-Services` switch" in docs
    assert "`SiteA` on" in docs and "`Atlaso-SiteA` as trunk VLAN 12" in docs
    assert "`Trunk`" in docs and "`Atlaso-Trunk`" in docs and "VLAN 50" in docs
    assert "WAN-Test` on `Atlaso-SiteB` as" in docs
    assert "`/var/lib/atlaso/users/<admin>` with `/usr/bin/pwsh`" in docs
    assert "`powershell` package" in docs
    assert "[switch]$SkipLabNetworkAdapters" in vm_script
    assert "[int]$SiteVlanId = 12" in vm_script
    assert "[int]$TaggedVlanId = 50" in vm_script
    assert "[string]$ServiceSwitchName = 'Atlaso-Services'" in vm_script
    assert "Add-ServiceNetworkAdapter" in vm_script
    assert "Add-VMNetworkAdapter -VMName $VMName -Name 'Services' -SwitchName $SwitchName" in vm_script
    assert "Set-VMNetworkAdapterVlan -VMName $VMName -VMNetworkAdapterName 'Services' -Untagged" in vm_script
    assert "Add-LabNetworkAdapters" in vm_script
    assert "Add-VMNetworkAdapter -VMName $VMName -Name 'SiteA' -SwitchName 'Atlaso-SiteA'" in vm_script
    assert "Set-VMNetworkAdapterVlan -VMName $VMName -VMNetworkAdapterName 'SiteA' -Trunk -AllowedVlanIdList \"$SiteTag\" -NativeVlanId 0" in vm_script
    assert "Add-VMNetworkAdapter -VMName $VMName -Name 'Trunk' -SwitchName 'Atlaso-Trunk'" in vm_script
    assert "Set-VMNetworkAdapterVlan -VMName $VMName -VMNetworkAdapterName 'Trunk' -Trunk -AllowedVlanIdList \"$TaggedVlanTag\" -NativeVlanId 0" in vm_script
    assert "Add-VMNetworkAdapter -VMName $VMName -Name 'WAN-Test' -SwitchName 'Atlaso-SiteB'" in vm_script


def test_windows_script_names_use_provider_tokens():
    script_paths = {
        path.relative_to("scripts/windows").as_posix()
        for path in Path("scripts/windows").rglob("*.ps1")
    }
    root_scripts = {path.name for path in Path("scripts/windows").glob("*.ps1")}

    old_vmware_token = "vmware-" + "workstation"
    old_names = {
        f"build-photon-{old_vmware_token}-image.ps1",
        f"create-atlaso-{old_vmware_token}-test-vm.ps1",
        f"invoke-{old_vmware_token}-lifecycle-test.ps1",
        f"prepare-{old_vmware_token}-networks.ps1",
        "prepare-" + "tiny-linux-client.ps1",
        "get-atlaso-" + "vm-ip.ps1",
        "start-atlaso-" + "vm.ps1",
        "stop-atlaso-" + "vm.ps1",
    }
    assert root_scripts == set()
    assert script_paths.isdisjoint(old_names)

    assert "common/Atlaso.PhotonImage.psm1" not in script_paths
    assert "hyperv/build-photon-image.ps1" in script_paths
    assert "hyperv/create-atlaso-test-vm.ps1" in script_paths
    assert "hyperv/create-atlaso-vm.ps1" in script_paths
    assert "hyperv/invoke-lifecycle-test.ps1" in script_paths
    assert "hyperv/prepare-tiny-linux-client.ps1" in script_paths
    assert "hyperv/get-atlaso-vm-ip.ps1" in script_paths
    assert "hyperv/start-atlaso-vm.ps1" in script_paths
    assert "hyperv/stop-atlaso-vm.ps1" in script_paths
    assert "vmware/build-photon-image.ps1" in script_paths
    assert "vmware/create-atlaso-test-vm.ps1" in script_paths
    assert "vmware/create-atlaso-vm.ps1" in script_paths
    assert "vmware/invoke-lifecycle-test.ps1" in script_paths
    assert "vmware/prepare-networks.ps1" in script_paths
    assert "vmware/prepare-tiny-linux-client.ps1" in script_paths
    assert "vmware/get-atlaso-vm-ip.ps1" in script_paths
    assert "vmware/start-atlaso-vm.ps1" in script_paths
    assert "vmware/stop-atlaso-vm.ps1" in script_paths
    assert "vmware/remove-atlaso-vm.ps1" in script_paths
    assert "vmware/remove-lifecycle-vms.ps1" in script_paths
    assert "vmware/reset-atlaso-vm.ps1" in script_paths
    assert "vmware/set-test-nics.ps1" in script_paths


def test_create_atlaso_vmware_test_vm_wrapper_uses_common_helpers():
    script = Path("scripts/windows/vmware/create-atlaso-test-vm.ps1").read_text(encoding="utf-8")
    vm_script = Path("scripts/windows/vmware/create-atlaso-vm.ps1").read_text(encoding="utf-8")
    nics_script = Path("scripts/windows/vmware/set-test-nics.ps1").read_text(encoding="utf-8")
    build_script = Path("scripts/windows/vmware/build-photon-image.ps1").read_text(encoding="utf-8")
    packer_template = Path("image/vmware-workstation/atlaso-photon.pkr.hcl").read_text(encoding="utf-8")
    docs = Path("image/vmware-workstation/README.md").read_text(encoding="utf-8")

    assert "[string]$Name = 'Atlaso-VMware'" in script
    assert "[switch]$Redeploy" in script
    assert "[switch]$SkipLabNetworkAdapters" in script
    assert "[switch]$IncludeLabNetworkAdapters" in script
    assert "[switch]$ResetDataDisks" in script
    assert "[switch]$WaitForIp" in script
    assert "[switch]$TrustRootCa" in script
    assert "[int]$TimeoutSeconds = 300" in script
    assert "Install-ApplianceRootCa" in script
    assert "Waiting up to $TimeoutSeconds seconds for the Atlaso root CA" in script
    assert "Atlaso root CA is not ready; retrying in $PollSeconds seconds." in script
    assert "-TimeoutSec $requestTimeoutSeconds" in script
    assert "Install-ApplianceRootCa -IpAddress $ip -Name $Name -TimeoutSeconds $TimeoutSeconds" in script
    assert "Write-ConnectionSummary" in script
    assert "Write-SummaryRow" in script
    assert "-ForegroundColor Cyan" in script
    assert "-ForegroundColor DarkGray" in script
    assert "http://$IpAddress/ca/downloads/root-ca.pem" in script
    assert "-SkipCertificateCheck" not in script
    assert "Cert:\\CurrentUser\\Root" in script
    assert "certutil.exe -user -delstore Root $staleRoot.Thumbprint" in script
    assert "certutil.exe -f -user -addstore Root $rootCerPath" in script
    assert "if ($TrustRootCa -and $NoStart)" in script
    assert "if (-not $NoStart -and -not $WhatIfPreference)" in script
    assert "if (($WaitForIp -or $TrustRootCa) -and -not $NoStart -and -not $WhatIfPreference)" in script
    assert 'Write-SummaryRow -Label "Console URL:" -Value "https://$IpAddress/"' in script
    assert 'Write-SummaryRow -Label "API URL:" -Value "https://$IpAddress/openapi.json"' in script
    assert 'Write-SummaryRow -Label "Swagger URL:" -Value "https://$IpAddress/api/docs"' in script
    assert 'Write-SummaryRow -Label "Root CA URL:" -Value "http://$IpAddress/ca/downloads/root-ca.pem"' in script
    assert 'Write-SummaryRow -Label "SSH:" -Value "ssh admin@$IpAddress"' in script
    assert 'Write-SummaryRow -Label "Lab DNS:"' in script
    assert "Windows DNS for lab FQDNs" in script
    assert "pass -TrustRootCa to trust this appliance root CA" in script
    assert "Pass -WaitForIp to print the HTTPS console" in script
    assert "-ValueColor Yellow" in script
    assert "[string]$ManagementNetwork = 'VMnet8'" in script
    assert "[string]$ManagementNetwork = 'VMnet8'" in vm_script
    assert "[string]$ManagementNetwork = 'VMnet8'" in nics_script
    assert "prepare-networks.ps1" in script
    assert "create-atlaso-vm.ps1" in script
    assert "start-atlaso-vm.ps1" in script
    assert "get-atlaso-vm-ip.ps1" in script
    assert "remove-atlaso-vm.ps1" in script
    assert "Find-LatestApplianceVmx" in script
    assert "image\\vmware-workstation\\output" in script
    assert "image\\vmware-workstation\\test-vms\\$Name" in script
    assert "$effectiveSkipLabNetworkAdapters = -not $IncludeLabNetworkAdapters" in script
    assert "Atlaso-Depot.vmdk" in script
    assert "Atlaso-Backups.vmdk" in script
    assert '"disk.EnableUUID"          = "TRUE"' in packer_template
    assert "Refusing to reset VMware data disk outside the VM output directory" in script
    assert "vmrun.exe was not found" in vm_script
    assert "vmware-vdiskmanager.exe was not found" in vm_script
    assert "vmrun $($Arguments -join ' ') failed" in vm_script
    assert "New-DataVmdk" in vm_script
    assert "Set-VmxScsiDisk" in vm_script
    assert "disk.EnableUUID" in vm_script
    assert "scsi0:$Unit" in vm_script
    assert "set-test-nics.ps1" in vm_script
    assert '"$prefix.vnet"' in nics_script
    assert "if ($Vmnet -match '^(?i)vmnet(\\d+)$')" in nics_script
    assert '$Vmnet = "VMnet$($Matches[1])"' in nics_script
    assert "$prefix.virtualDev" in nics_script
    assert "vmxnet3" in nics_script
    assert "Join-Path $PSScriptRoot '..\\common\\Atlaso.PhotonImage.psm1'" in build_script
    assert "Join-Path $PSScriptRoot '..\\..\\..\\image\\vmware-workstation'" in build_script
    assert "[string]$ServiceVmnetName = 'VMnet1'" in build_script
    assert "service_vmnet_name = $ServiceVmnetName" in build_script
    assert "Using VMware services network $ServiceVmnetName" in build_script
    assert "prepare-networks.ps1" in build_script
    assert "Resolve-WorkstationVmrunPath -Path $VmrunPath" in build_script
    assert "Resolve-WorkstationOutputDirectory -PackerDirectory $PackerDirectory -OutputDirectory $OutputDirectory" in build_script
    assert "Unregister-ExistingWorkstationTemplate" in build_script
    assert "'unregister', $resolvedVmx" in build_script
    assert "Refusing to unregister VMware template outside the configured image output directory" in build_script
    assert 'variable "service_vmnet_name"' in packer_template
    assert '"ethernet1.present"        = "TRUE"' in packer_template
    assert '"ethernet1.vnet"           = var.service_vmnet_name' in packer_template
    assert '"ethernet1.virtualDev"     = "vmxnet3"' in packer_template
    assert 'guest_os_type        = "vmware-photon-64"' in packer_template
    assert 'disk_adapter_type    = "pvscsi"' in packer_template
    assert '"sata0:0.present" = "FALSE"' in packer_template
    assert "-TrustRootCa" in docs
    assert "removes stale" in docs
    assert "connection summary" in docs
    assert "Windows DNS for lab FQDNs" in docs
    assert "Add-DnsClientNrptRule" in docs
    assert "Swagger URL" in docs
    assert "root certificate URL" in docs
    assert "ssh admin@<appliance-ip>" in docs
    assert "`vmxnet3` adapter" in docs
    assert "`-ServiceVmnetName`" in docs


def test_vmware_deploy_wheel_supports_password_backed_noninteractive_deploy():
    script = Path("scripts/windows/vmware/deploy-wheel.ps1").read_text(encoding="utf-8")
    readme = Path("docs/reference/full-technical-reference.md").read_text(encoding="utf-8")

    assert "[string]$SshPassword = $env:ATLASO_DEPLOY_SSH_PASSWORD" in script
    assert "function Initialize-PasswordDeployPythonPath" in script
    assert "Preparing temporary Paramiko runtime from local deployment wheels" in script
    assert "'--no-index'" in script
    assert "'--find-links', $wheelDirectory" in script
    assert "'--target', $dependencyDirectory" in script
    assert "$env:PYTHONPATH" in script
    assert "function Invoke-PasswordBackedDeploy" in script
    assert "import paramiko" in script
    assert 'sys.stdout.reconfigure(errors="replace")' in script
    assert "--local-worker-service" in script
    assert '--local-trust-key", action="append"' in script
    assert '--remote-trust-key", action="append"' in script
    assert "At least one matched local and remote Atlaso release trust key is required." in script
    assert "image\\common\\update-trust" in script
    assert "No Atlaso release trust keys found under" in script
    assert "install -d -o root -g root -m 0755 /etc/atlaso/update-trust.d" in script
    assert 'install -o root -g root -m 0644 "$trust_key_path" "/etc/atlaso/update-trust.d/$trust_key_name"' in script
    assert "openssl pkey -pubin" in script
    assert "Atlaso release trust key is not Ed25519" in script
    assert "--local-runtime-dependency" in script
    assert "'authlib-*.whl'" in script
    assert "'joserfc-*.whl'" in script
    assert "Matched local and remote runtime dependency wheels are required." in script
    assert '"$python" -m pip install --force-reinstall --no-deps "$runtime_dependency_path"' in script
    assert '"$python" -m pip install --force-reinstall --no-deps "$wheel"' in script
    assert "systemctl enable atlaso-worker.service" in script
    assert "systemctl restart atlaso-worker.service" in script
    assert "systemctl is-active atlaso-worker.service" in script
    assert "ATLASO_DEPLOY_SSH_PASSWORD" in script
    assert "client.set_missing_host_key_policy(paramiko.AutoAddPolicy())" in script
    assert "allow_agent=False" in script
    assert "look_for_keys=False" in script
    assert "sudo -S -p '' sh" in script
    assert "sanitized(stdout_text, password)" in script
    assert "if (-not $SshPassword) {" in script
    assert "Test-RequiredCommand -Name 'scp'" in script
    assert "Invoke-PasswordBackedDeploy `" in script
    assert "-SshPassword '<admin-password>'" in readme
    assert "temporary deployment directory" in readme
    assert "global Python" in readme
    assert "When using `-SkipBuild`, keep" in readme
    assert "Without a" in readme
    assert "`scp`/`ssh` key or agent workflow" in readme


def test_lifecycle_hyperv_script_does_not_cleanup_without_explicit_flag():
    script = Path("scripts/windows/hyperv/run-lifecycle-test.ps1").read_text(encoding="utf-8")

    assert "[switch]$CleanupCreatedLab" in script
    assert "if ($CleanupCreatedLab)" in script
    assert "Lifecycle VMs were left in place" in script
    assert "Remove-VM -Name $name -Force" in script
    assert "Remove-VM -Name 'Atlaso'" not in script


def test_lifecycle_single_command_wrapper_prepares_runs_and_cleans_up_by_default():
    script = Path("scripts/windows/hyperv/invoke-lifecycle-test.ps1").read_text(encoding="utf-8")

    assert "DefaultParameterSetName = 'Run'" in script
    assert "ParameterSetName = 'PrepareNetworks'" in script
    assert "ParameterSetName = 'CleanupNetworks'" in script
    assert "ParameterSetName = 'CleanupVms'" in script
    assert "[string]$AdminPassword = 'VMware01!'" in script
    assert "[string]$ApplianceSshUser = 'admin'" in script
    assert "[string]$SshPassword = 'VMware01!'" in script
    assert "[string]$VcfBackupPassword = 'VMware01!Test'" in script
    assert "'-VcfBackupPassword', $VcfBackupPassword" in script
    assert "[string]$SiteInterface = 'eth1.12'" in script
    assert "[string]$SiteCidr = '192.168.12.1/24'" in script
    assert "[int]$SiteVlanId = 12" in script
    assert "prepare-tiny-linux-client.ps1" in script
    assert "Find-LatestApplianceVhdx" in script
    assert "run-lifecycle-test.ps1" in script
    assert "$arguments += '-CleanupCreatedLab'" in script
    assert "[switch]$KeepVms" in script
    assert "[switch]$PrepareNetworksOnly" in script
    assert "[switch]$CleanupNetworksOnly" in script
    assert "[switch]$CleanupVmsOnly" in script
    assert "remove-lifecycle-networks.ps1" in script
    assert "remove-lifecycle-vms.ps1" in script
    assert "AtlasoLifecycle-$(Get-Date -Format 'yyyyMMddHHmmss')" in script
    assert "$singlePurposeActions" not in script


def test_lifecycle_cleanup_scripts_are_scoped_to_atlaso_assets():
    switch_script = Path("scripts/windows/hyperv/create-switches.ps1").read_text(encoding="utf-8")
    network_script = Path("scripts/windows/hyperv/remove-lifecycle-networks.ps1").read_text(encoding="utf-8")
    vm_script = Path("scripts/windows/hyperv/remove-lifecycle-vms.ps1").read_text(encoding="utf-8")

    assert "Atlaso-Services" in switch_script
    assert "Atlaso-Mgmt-NAT" in network_script
    assert "Atlaso-Mgmt" in network_script
    assert "Atlaso-Services" in network_script
    assert "Atlaso-SiteA" in network_script
    assert "Get-VMNetworkAdapter -All" in network_script
    assert "Refusing to remove switch" in network_script
    assert "AtlasoLifecycle*" in vm_script
    assert "Atlaso-Photon-Builder" in vm_script
    assert "Refusing VM cleanup" in vm_script
    assert "Remove-VM -Name $vm.Name -Force" in vm_script


def test_vmware_lifecycle_cleanup_only_removes_existing_lifecycle_vms():
    wrapper = Path("scripts/windows/vmware/invoke-lifecycle-test.ps1").read_text(encoding="utf-8")
    cleanup_script = Path("scripts/windows/vmware/remove-lifecycle-vms.ps1").read_text(encoding="utf-8")
    docs = Path("docs/reference/vmware-workstation-lifecycle-testing.md").read_text(encoding="utf-8")

    assert "ParameterSetName = 'CleanupVms'" in wrapper
    assert "remove-lifecycle-vms.ps1" in wrapper
    assert "run-lifecycle-test.ps1" in wrapper
    cleanup_block = wrapper.split("if ($PSCmdlet.ParameterSetName -eq 'CleanupVms') {\n    &", 1)[1].split("return", 1)[0]
    assert "remove-lifecycle-vms.ps1" in cleanup_block
    assert "run-lifecycle-test.ps1" not in cleanup_block
    assert "ApplianceVmxPath" not in cleanup_block
    assert "ClientVmdkPath" not in cleanup_block
    assert "CleanupCreatedLab" not in cleanup_block
    assert "Refusing VM cleanup for prefix '$LabName'" in cleanup_script
    assert "AtlasoWorkstationLifecycle" in cleanup_script
    assert "test-results\\vmware-workstation-lifecycle" in cleanup_script
    assert "vmrun.exe was not found" in cleanup_script
    assert "Get-VmxDisplayName" in cleanup_script
    assert "Refusing to remove VM outside Workstation lifecycle results" in cleanup_script
    assert "Remove-Item -LiteralPath $candidate.Directory -Recurse -Force" in cleanup_script
    assert "-CleanupVmsOnly" in docs


def test_lifecycle_hyperv_script_finds_alpine_ips_and_pins_plink_hostkeys():
    script = Path("scripts/windows/hyperv/run-lifecycle-test.ps1").read_text(encoding="utf-8")

    assert "[string]$ApplianceSshUser = 'admin'" in script
    assert "Get-NetNeighbor -AddressFamily IPv4" in script
    assert "ConvertTo-HyphenMac" in script
    assert "Wait-GuestIPv4 -Name $clientAName" in script
    assert "function Test-TcpPort" in script
    assert "Get-PlinkHostKey" in script
    assert "$applianceHostKey = Get-PlinkHostKey -HostName $ApplianceIPAddress" in script
    assert "(Get-Date).AddMinutes(4)" in script
    assert "$ErrorActionPreference = 'Continue'" in script
    assert "Timed out waiting for SSH host key" in script
    assert "Set-VMNetworkAdapterVlan -VMName $applianceName -VMNetworkAdapterName 'SiteA' -Trunk" in script
    assert "Set-VMNetworkAdapterVlan -VMName $clientAName -VMNetworkAdapterName 'SiteA-Test' -Access -VlanId $SiteVlanId" in script
    assert "Appliance-Mgmt-Test" in script
    assert "'--appliance-ssh-hostkey'" in script
    assert "'--client-a-hostkey'" in script
    assert "'--client-b-hostkey'" in script


def test_lifecycle_vmware_script_supports_routing_wan_only_and_esxi_pxe_install():
    wrapper = Path("scripts/windows/vmware/invoke-lifecycle-test.ps1").read_text(encoding="utf-8")
    runner = Path("scripts/windows/vmware/run-lifecycle-test.ps1").read_text(encoding="utf-8")

    assert "[switch]$RoutingWanOnly" in wrapper
    assert "[switch]$OidcOnly" in wrapper
    assert "[switch]$FullEsxiPxeInstall" in wrapper
    assert "[string]$PxeInstallerIsoPath = ''" in wrapper
    assert "$effectiveSkipBackupRestoreTest = [bool]($SkipBackupRestoreTest -or $RoutingWanOnly -or $OidcOnly)" in wrapper
    assert "if ($OidcOnly) { $arguments += '-OidcOnly' }" in wrapper
    assert "if ($RoutingWanOnly) { $arguments += '-RoutingWanOnly' }" in wrapper
    assert "if ($FullEsxiPxeInstall) { $arguments += '-FullEsxiPxeInstall' }" in wrapper
    assert "if ($PxeInstallerIsoPath) { $arguments += @('-PxeInstallerIsoPath', $PxeInstallerIsoPath) }" in wrapper
    assert "-OidcOnly, -RoutingWanOnly, and -FullEsxiPxeInstall are mutually exclusive." in wrapper

    assert "function Get-GuestIPv4ViaGuestOps" in runner
    assert "function Invoke-VmrunBounded" in runner
    assert "vmrun timed out after $TimeoutSeconds seconds" in runner
    assert "function Get-GuestIPv4FromHostNeighbor" in runner
    assert "function Get-VmxEthernetMacAddress" in runner
    assert "Get-NetNeighbor -AddressFamily IPv4" in runner
    assert "ip -4 -br addr" in runner
    assert "'copyFileFromGuestToHost', $Path, $guestOutput, $hostOutput" in runner
    assert "'getGuestIPAddress', $Path" in runner
    assert "-TimeoutSeconds 15" in runner
    assert "function Get-PlinkHostKey" in runner
    assert "function Test-ApplianceOpenApi" in runner
    assert "& $curl.Source -k -f -sS $Url" in runner
    assert "ServerCertificateValidationCallback = { $true }" in runner
    assert "$applianceHostKey = Get-PlinkHostKey -HostName $ApplianceIPAddress" in runner
    assert "'--appliance-ssh-hostkey', $applianceHostKey" in runner
    assert "'--client-a-hostkey', $clientAHostKey" in runner
    assert "function Sync-ApplianceHelperScript" in runner
    assert "scripts\\appliance\\atlaso-helper" in runner
    assert "copyFileFromHostToGuest $ApplianceVmx $localHelper $guestTemp" in runner
    assert "install -o root -g root -m 0755 $quotedTemp /opt/atlaso/bin/atlaso-helper" in runner
    assert "function Sync-ApplianceApplicationWheel" in runner
    assert "python -m pip wheel $repoRoot --no-deps -w $wheelRoot" in runner
    assert "pip install --force-reinstall --no-deps $quotedWheel" in runner
    assert "systemctl restart atlaso.service" in runner
    assert "$applianceWheelPath = Sync-ApplianceApplicationWheel -ApplianceVmx $applianceVmx" in runner
    assert "function Register-WorkstationVm" in runner
    assert "$resolvedVmrun @Arguments" in runner
    assert "ws register $Path" in runner
    assert "ws unregister $Path" in runner
    assert "Register-WorkstationVm -Path $Path" in runner
    assert "function New-EsxiPxeVm" in runner
    assert "[string]$PxeClientIPAddress = ''" in runner
    assert "[int]$EsxiInstallProbeDelaySeconds = 300" in runner
    assert "Waiting $EsxiInstallProbeDelaySeconds seconds before probing ESXi guest operations." in runner
    assert "esxi_probe_delay_seconds = $EsxiInstallProbeDelaySeconds" in runner
    assert "if ($PxeClientIPAddress)" in runner
    assert "@('--pxe-client-ip', $PxeClientIPAddress)" in runner
    assert "$Vmnet.StartsWith('lan:')" in runner
    assert "if ($Vmnet -match '^(?i)vmnet(\\d+)$')" in runner
    assert '$Vmnet = "VMnet$($Matches[1])"' in runner
    assert "function Resolve-LanSegmentId" in runner
    assert "pref.namedPVNs$nextIndex.name" in runner
    assert "connectionType\" -Value 'pvn'" in runner
    assert "$prefix.pvnID" in runner
    assert "Remove-VmxValue -Path $Path -Key \"$prefix.vnet\"" in runner
    assert "sata0:0.deviceType = \"disk\"" in runner
    assert "sata0:1.deviceType = \"cdrom-image\"" in runner
    assert "Set-VmxNetworkAdapter -Path $vmxPath -Index $index -Vmnet $Networks[$index] -VirtualDev 'e1000'" in runner
    assert "firmware = \"efi\"" in runner
    assert "uefi.secureBoot.enabled = \"FALSE\"" in runner
    assert "vhv.enable = \"FALSE\"" in runner
    assert "& $vdiskManager -c -s 32GB -a pvscsi -t 0 $diskTarget" in runner
    assert 'virtualHW.version = "22"' in runner
    assert 'pciBridge0.present = "TRUE"' in runner
    assert 'pciBridge4.virtualDev = "pcieRootPort"' in runner
    assert 'pciBridge7.functions = "8"' in runner
    assert 'vmci0.present = "TRUE"' in runner
    assert 'virtualHW.productCompatibility = "hosted"' in runner
    assert 'tools.syncTime = "FALSE"' in runner
    assert 'floppy0.present = "FALSE"' in runner
    assert 'guestOS = "vmkernel9"' in runner
    assert 'scsi0.virtualDev = "pvscsi"' in runner
    assert "Set-VmxNetworkAdapter -Path $vmxPath -Index 0 -Vmnet $Network -StaticMac $MacAddress -VirtualDev 'vmxnet3'" in runner
    assert "function Resolve-ApplianceEsxiIsoPath" in runner
    assert "copyFileFromHostToGuest $ApplianceVmx $localIso.Path $guestTemp" in runner
    assert "'--routing-wan-only'" in runner
    assert "'--pxe-test-mode', $(if ($FullEsxiPxeInstall) { 'esxi' } else { 'linux' })" in runner
    assert "Add-LifecycleResultStep -ResultDirectory $initialResultRoot -Name 'esxi-pxe-install-check' -Status 'passed'" in runner


def test_lifecycle_hyperv_script_seeds_alpine_clients_for_ssh():
    script = Path("scripts/windows/hyperv/run-lifecycle-test.ps1").read_text(encoding="utf-8")

    assert "[string]$ClientSshUser = 'alpine'" in script
    assert "New-CloudInitSeedIso" in script
    assert "create_nocloud_seed_iso.py" in script
    assert "Add-VMDvdDrive" in script
    assert "pycdlib" in script
    assert "ssh-keygen" not in script
    assert "Client SSH access requires -SshPassword or an existing -SshKeyPath." in script


def test_nocloud_seed_helper_writes_client_cloud_init_contract():
    script = Path("scripts/interop/create_nocloud_seed_iso.py").read_text(encoding="utf-8")

    assert 'vol_ident="cidata"' in script
    assert "ssh_authorized_keys:" in script
    assert 'parser.add_argument("--public-key", default="")' in script
    assert "Either --public-key or --password is required" in script
    assert "openssl" in script
    assert "sshpass" in script
    assert "chrony-nts" in script
    assert "atlaso-refresh-test-dhcp" in script
    assert "joliet_path=f\"/{name}\"" in script


def test_prepare_tiny_linux_client_downloads_verifies_and_converts_alpine():
    script = Path("scripts/windows/hyperv/prepare-tiny-linux-client.ps1").read_text(encoding="utf-8")

    assert "dl-cdn.alpinelinux.org/alpine/latest-stable/releases/cloud" in script
    assert "generic_alpine-3.24.1-x86_64-uefi-cloudinit-r0.qcow2" in script
    assert "Get-FileHash -Algorithm SHA512" in script
    assert "qemu-img convert -p -f qcow2 -O vhdx -o subformat=dynamic" in script
    assert "atlaso-tiny-linux-client.vhdx" in script


def test_lifecycle_runner_plan_includes_ca_and_global_apply_units():
    module = load_lifecycle_runner()
    args = module.parse_args(
        [
            "--password",
            "test",
            "--plan-only",
        ]
    )

    plan = module.lifecycle_plan(args)

    assert plan["apply_units"] == [
        "local_users",
        "network",
        "firewall",
        "wan",
            "dnsmasq",
            "esxi_pxe",
            "esx_storage",
            "ca",
        "ntpd",
        "kms",
        "ldap",
        "appliance_settings",
        "vcf_backups",
        "vcf_offline_depot",
        "public_services",
    ]
    assert plan["interfaces"]["vlan"]["name"] == "eth2.50"
    assert plan["interfaces"]["client_ca_request"]["name"] == "eth3"
    assert plan["interfaces"]["client_ca_request"]["ip_cidr"] == "192.168.49.20/24"
    assert any("CA desired state" in check and "client-side verification" in check for check in plan["checks"])
    assert any("Alpine chrony-nts authenticated synchronization" in check for check in plan["checks"])
    assert "VCF Backup desired state, local user sync, SFTP listener, and client probe" in plan["checks"]
    assert "VCF Offline Depot browser login, curl/wget Basic auth, and Local Users password rotation" in plan["checks"]
    assert any("Managed LDAP desired state" in check for check in plan["checks"])
    assert plan["pxe_boot"]["enabled"] is False
    assert plan["pxe_boot"]["mode"] == "linux"


def test_lifecycle_runner_uses_supported_network_roles():
    script = Path("scripts/interop/lifecycle_test.py").read_text(encoding="utf-8")

    assert '"mode": "access", "role": "access"' in script
    assert '"mode": "trunk", "role": "unused"' in script
    assert 'role="access"' in script
    assert '"role": "lab"' not in script
    assert '"role": "trunk"' not in script


def test_lifecycle_runner_supports_alpine_doas_and_plink_hostkeys():
    script = Path("scripts/interop/lifecycle_test.py").read_text(encoding="utf-8")

    assert "--client-a-hostkey" in script
    assert "--client-b-hostkey" in script
    assert '"-hostkey", hostkey' in script
    assert "command -v doas" in script
    assert "ip route replace {wan.network} via {site_ip} dev eth1" in script
    assert "traceroute -n {wan_peer_ip}" in script


def test_lifecycle_runner_covers_ca_vcf_backups_wan_noise_and_console_summary():
    script = Path("scripts/interop/lifecycle_test.py").read_text(encoding="utf-8")

    assert "direct_dns_a_query_command" in script
    assert "base64 -d | python3 -" in script
    assert '"dnsmasq": "test -f /etc/atlaso/dnsmasq.d/atlaso.conf && getent hosts interop-appliance.atlaso.internal"' not in script
    assert "--vcf-backup-password" in script
    assert "--client-ca-request-interface" in script
    assert "configure_management_https" in script
    assert "management_https_check" in script
    assert "apply-appliance-settings-unit" in script
    assert "HTTP management endpoint should redirect after HTTPS apply" in script
    assert "https_request_unverified" in script
    assert "configure-vcf-backups" in script
    assert "configure-kms" in script
    assert '"/kms/clients"' in script
    assert '"name": "vcf-management"' in script
    assert "Hyper-V lifecycle KMIP client" in script
    assert "atlaso-kms.service" in script
    assert "kms_files" in script
    assert "kms_service" in script
    assert "kms_tls" in script
    assert '"local_console"' in script
    assert "systemctl is-active atlaso-console.service" in script
    assert "systemctl is-enabled getty@tty1.service" in script
    assert "systemctl show getty@tty2.service" in script
    assert '\\"maintenance_isolation\\": false' in script
    assert "apply-kms-unit" in script
    assert "Appliance apply task failed" in script
    assert "/etc/atlaso/kms/clients/certs/vcf-management.crt" in script
    assert "/etc/atlaso/kms/clients/vcf-management.crt" not in script
    assert "missing $path" in script
    assert "stderr:" in script
    assert "stdout:" in script
    assert "vcf-backup-client-check" in script
    assert "sshpass -p" in script
    assert "redact_text" in script
    assert '"local_users", "network", "firewall", "wan", "dnsmasq", "esxi_pxe", "vcf_backups"' in script
    assert "certificate_summary" in script
    assert "root_ca" in script
    assert "ca-client-certificate-request" in script
    assert "ca-client-certificate-check" in script
    assert "create_client_csr" in script
    assert '"listen_interfaces_present": "1"' in script
    assert '"listen_interfaces": [args.site_interface]' in script
    assert "ca_request_url" in script
    assert "Cookie: " in script
    assert "--connect-timeout 10 --max-time 30" in script
    assert "except subprocess.TimeoutExpired" in script
    assert "SSH command timed out after 120 seconds." in script
    assert "VCF KMIP client" in script
    assert "verify_certificate_signed_by_root" in script
    assert "client_a_download" in script
    assert "-o /dev/null -w '%{http_code}'" in script
    assert "apply-connectivity-units" in script
    assert "apply-ca-unit" in script
    assert "configure-ntp" in script
    assert "apply-ntp-unit" in script
    assert "ntp-client-checks" in script
    assert '"ntp_settings" not in data or "chrony_settings" in data' in script
    assert "tc qdisc show dev {args.wan_interface} | grep netem | grep delay | grep 25ms" in script
    assert "Lifecycle summary" in script
    assert "Result JSON:" in script


def test_lifecycle_runner_summarizes_apply_validation_html():
    module = load_lifecycle_runner()
    summary = module.summarize_html_response(
        """
        <!doctype html>
        <html>
          <body>
            <aside>Atlaso navigation noise</aside>
            <div class="alert error">Resolve validation errors before submitting appliance changes.</div>
            <article>
              <strong>Certificate Authority</strong>
              <div class="alert error"><div>CA service requires at least one listen interface.</div></div>
            </article>
          </body>
        </html>
        """
    )

    assert summary.startswith("Resolve validation errors before submitting appliance changes.")
    assert "CA service requires at least one listen interface." in summary
    assert "doctype" not in summary.lower()


def test_lifecycle_roadmap_splits_pester_and_pytest_ownership():
    doc = Path("docs/reference/hyperv-lifecycle-testing.md").read_text(encoding="utf-8")

    assert "Invoke-Pester tests/pester/HyperVLifecycle.Tests.ps1" in doc
    assert "Python appliance and guest assertions must remain pytest-covered" in doc
    assert "scripts/interop/lifecycle_test.py" in doc
