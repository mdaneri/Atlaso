from pathlib import Path

import hashlib
import importlib.util
import struct
import sys


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


def test_photon_image_installs_fixed_size_labfoundry_grub_branding():
    background = Path("image/common/boot/grub/labfoundry.png").read_bytes()
    photon_logo = Path("image/common/boot/grub/photon-os-logo.png").read_bytes()
    theme = Path("image/common/boot/grub/theme.txt").read_text(encoding="utf-8")
    installer = Path("scripts/appliance/labfoundry-install-boot-branding").read_text(encoding="utf-8")
    provision = Path("image/common/scripts/provision-labfoundry.sh").read_text(encoding="utf-8")
    deploy = Path("scripts/windows/vmware/deploy-wheel.ps1").read_text(encoding="utf-8")

    assert background[:8] == b"\x89PNG\r\n\x1a\n"
    assert struct.unpack(">II", background[16:24]) == (640, 480)
    assert photon_logo[:8] == b"\x89PNG\r\n\x1a\n"
    assert 'desktop-image: "labfoundry.png"' in theme
    assert "Powered by Photon OS" not in theme  # Copy is rendered into the fixed background.
    assert "set theme=/grub2/themes/labfoundry/theme.txt" in installer
    assert 'menuentry " "' in installer
    assert "labfoundry-backup" in installer
    assert '"$LABFOUNDRY_HOME/bin/labfoundry-install-boot-branding"' in provision
    assert "SkipBootBrandingSync" in deploy
    assert "/opt/labfoundry/bin/labfoundry-install-boot-branding" in deploy
    assert '"${SshUser}@${IpAddress}:$remoteBootThemePath"' in deploy
    assert '"${SshUser}@${IpAddress}:$remoteBootBackgroundPath"' in deploy


def test_photon_provisioning_management_network_matches_eth0_only():
    script = Path("image/common/scripts/provision-labfoundry.sh").read_text(encoding="utf-8")
    main = Path("labfoundry/app/main.py").read_text(encoding="utf-8")
    seed = Path("labfoundry/app/seed.py").read_text(encoding="utf-8")

    assert 'LABFOUNDRY_MGMT_INTERFACE="${LABFOUNDRY_MGMT_INTERFACE:-eth0}"' in script
    assert 'printf \'Name=%s\\n\\n\' "$LABFOUNDRY_MGMT_INTERFACE"' in script
    assert "Name=eth* en*" not in script
    assert "rm -f /etc/systemd/network/50-static-en.network /etc/systemd/network/99-dhcp-en.network" in script
    assert "seed_initial_data(db, include_examples=not appliance_mode, appliance_mode=appliance_mode)" in main
    assert "ensure_ca_state(db)" in main
    assert main.index("refresh_startup_host_inventory(db, environment=settings.environment)") < main.index("ensure_ca_state(db)")
    assert "if include_examples:" in seed
    assert "management_https_enabled=appliance_mode" in seed
    assert 'install -d -o labfoundry -g labfoundry -m 0700 "$LABFOUNDRY_STATE/vcfDownloadTool/active-tool/secrets"' in script


def test_photon_provisioning_installs_default_nginx_management_proxy():
    script = Path("image/common/scripts/provision-labfoundry.sh").read_text(encoding="utf-8")
    bootstrap = Path("scripts/appliance/labfoundry-bootstrap-https").read_text(encoding="utf-8")
    systemd_unit = Path("image/hyperv/systemd/labfoundry.service").read_text(encoding="utf-8")
    sudoers = Path("image/hyperv/sudoers.d/labfoundry-helper").read_text(encoding="utf-8")
    docs = Path("image/hyperv/README.md").read_text(encoding="utf-8")
    root_docs = Path("README.md").read_text(encoding="utf-8")

    assert "tdnf -y install" in script and "nginx" in script
    assert "tdnf -y install" in script and "ntpsec" in script
    assert "tdnf -y install" in script and "python3-ntp" in script
    assert "systemctl disable --now ntpd.service" in script
    assert "systemctl disable --now systemd-timesyncd.service" in script
    assert "systemctl disable --now chronyd.service" in script
    assert '"$LABFOUNDRY_STATE/apply/ntpd"' in script
    assert "tdnf -y install" in script and "openldap-servers" in script
    assert "tdnf -y install" in script and "nfs-utils" in script and "rpcbind" in script
    assert "99-labfoundry-disk-identity.rules" in script
    assert 'IMPORT{builtin}="path_id"' in script
    assert 'SYMLINK+="disk/by-id/labfoundry-path-$env{ID_PATH_TAG}"' in script
    assert "tdnf -y install" in script and "powershell" in script
    assert "VCF.PowerCLI" in script
    assert "9.1.0.25380678" in script
    assert "Connect-VIServer" in script
    assert "Set-PowerCLIConfiguration -ParticipateInCeip $false -Scope AllUsers -Confirm:$false" in script
    assert "Get-PowerCLIConfiguration -Scope AllUsers" in script
    assert "LABFOUNDRY_POWERCLI_MODULE_SOURCE" in script
    assert "chmod 0755 /usr/local/share/powershell /usr/local/share/powershell/Modules" in script
    assert "chmod -R a+rX,go-w /usr/local/share/powershell/Modules" in script
    assert "tdnf -y install" in script and "ipxe" in script
    assert "tdnf -y install" in script and "syslinux" in script
    assert "IPXE_BOOTLOADER_SOURCE_DIR=\"$LABFOUNDRY_HOME/third_party/ipxe/bootloaders\"" in script
    assert "IPXE_BOOTLOADER_TARGET_DIR=\"$LABFOUNDRY_STATE/pxe/bootloaders\"" in script
    assert "staging bundled iPXE bootloaders" in script
    assert '"$IPXE_BOOTLOADER_TARGET_DIR/undionly.kpxe"' in script
    assert '"$IPXE_BOOTLOADER_TARGET_DIR/snponly.efi"' in script
    assert 'BOOTSTRAP_SHELL="${LABFOUNDRY_BOOTSTRAP_ADMIN_SHELL:-/usr/bin/pwsh}"' in script
    assert '--shell "$BOOTSTRAP_SHELL"' in script
    assert "touch /etc/shells" in script
    assert 'grep -qxF "$BOOTSTRAP_SHELL" /etc/shells' in script
    assert "labfoundry-bootstrap-admin" in script
    assert "$BOOTSTRAP_USERNAME ALL=(ALL) ALL" in script
    assert "visudo -cf /etc/sudoers.d/labfoundry-bootstrap-admin" in script
    assert (
        'sudo -H -u "$BOOTSTRAP_USERNAME" env -u PSModulePath '
        'LABFOUNDRY_POWERCLI_VERSION="$LABFOUNDRY_POWERCLI_VERSION"'
    ) in script
    assert "is not available to the bootstrap administrator" in script
    assert 'chmod 0711 "$LABFOUNDRY_STATE"' in script
    assert 'chown "$BOOTSTRAP_USERNAME:$(id -gn "$BOOTSTRAP_USERNAME")" "$LABFOUNDRY_STATE/users/$BOOTSTRAP_USERNAME"' in script
    assert 'chmod 0750 "$LABFOUNDRY_STATE/users/$BOOTSTRAP_USERNAME"' in script
    assert "UMask=0027" in systemd_unit
    assert "--host 127.0.0.1 --port 8000" in systemd_unit
    assert "--host 0.0.0.0" not in systemd_unit
    assert "configuring first-boot LabFoundry management nginx bootstrap" in script
    assert "install -d -o root -g root -m 0755 /etc/nginx/conf.d" in script
    assert "/etc/nginx/conf.d/labfoundry.conf" in script
    assert "/etc/labfoundry/nginx/sites.d/management.conf" in bootstrap
    assert "rm -f /etc/nginx/conf.d/default.conf /etc/nginx/conf.d/default_server.conf" in script
    assert "labfoundry-bootstrap-https" in script
    assert "labfoundry-bootstrap-https.service" in script
    assert "ExecStart=/opt/labfoundry/.venv/bin/python /opt/labfoundry/bin/labfoundry-bootstrap-https" in script
    assert "EnvironmentFile=/etc/labfoundry/labfoundry.env" in script
    assert "After=network-online.target labfoundry-data-disks.service labfoundry-vmware-ovf-customize.service" in script
    assert "Wants=network-online.target labfoundry-data-disks.service" in script
    assert "ConditionPathExists=!/var/lib/labfoundry/first-boot-https.applied" in script
    assert '"$LABFOUNDRY_HOME/.venv/bin/python" "$LABFOUNDRY_HOME/bin/labfoundry-bootstrap-https"' not in script
    assert "sync_host_physical_interfaces(db)" in bootstrap
    assert bootstrap.index("sync_host_physical_interfaces(db)") < bootstrap.index("ensure_ca_state(db)")
    assert 'str(HELPER_PATH), "ca", action, str(CA_STAGED_CONFIG_PATH), "--real"' in bootstrap
    assert 'for db_file in state_path.glob("labfoundry.db*")' in bootstrap
    assert 'shutil.chown(db_file, user="labfoundry", group="labfoundry")' in bootstrap
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
    assert 'LABFOUNDRY_DRY_RUN_SYSTEM_ADAPTERS="${LABFOUNDRY_DRY_RUN_SYSTEM_ADAPTERS:-true}"' in script
    assert 'LABFOUNDRY_MGMT_SOURCE_CIDR="${LABFOUNDRY_MGMT_SOURCE_CIDR:-}"' in script
    assert 'LABFOUNDRY_MGMT_USES_DHCP=false' in script
    assert 'LABFOUNDRY_APPLIANCE_EXTERNAL_DNS_SERVERS=$(if [ "$LABFOUNDRY_MGMT_USES_DHCP" = "true" ]; then printf \'\'; else printf \'%s\' "$LABFOUNDRY_MGMT_DNS" | tr \' \' \',\'; fi)' in script
    assert 'if [ "$LABFOUNDRY_MGMT_USES_DHCP" != "true" ] && [ -n "$LABFOUNDRY_MGMT_DNS" ]; then' in script
    assert 'ip -4 -o addr show dev "$LABFOUNDRY_MGMT_INTERFACE" scope global' in script
    assert 'DETECTED_MGMT_ADDRESS' in script
    assert "ipaddress.ip_interface(sys.argv[1]).network" in script
    assert "printf '\\nLABFOUNDRY_MANAGEMENT_SOURCE_CIDR=%s\\n' \"$LABFOUNDRY_MGMT_SOURCE_CIDR\" >>/etc/labfoundry/labfoundry.env" in script
    assert 'log_step "system adapter dry-run mode: $LABFOUNDRY_DRY_RUN_SYSTEM_ADAPTERS"' in script
    assert "LABFOUNDRY_DRY_RUN_SYSTEM_ADAPTERS=$LABFOUNDRY_DRY_RUN_SYSTEM_ADAPTERS" in script
    assert 'LABFOUNDRY_MGMT_ACCESS_RULE="    ip saddr $LABFOUNDRY_MGMT_SOURCE_CIDR tcp dport { 22, 80, 443 } accept comment \\"LabFoundry management access\\""' in script
    assert 'LABFOUNDRY_MGMT_ACCESS_RULE="    iifname \\"$LABFOUNDRY_MGMT_INTERFACE\\" tcp dport { 22, 80, 443 } accept comment \\"LabFoundry management access\\""' in script
    assert "$LABFOUNDRY_MGMT_ACCESS_RULE" in script
    assert 'install -o root -g root -m 0440 "$LABFOUNDRY_HOME/$LABFOUNDRY_IMAGE_ASSET_DIR/sudoers.d/labfoundry-helper" /etc/sudoers.d/labfoundry-helper' in script
    assert 'sed -i \'s/\\r$//\'' in script
    assert '"$LABFOUNDRY_HOME/bin/labfoundry-install-boot-branding"' in script
    assert "/etc/systemd/system/labfoundry-worker.service" in script
    assert 'useradd --system --gid labfoundry-automation' in script
    assert 'systemctl enable labfoundry-worker.service' in script
    assert "labfoundry ALL=(root) NOPASSWD: /opt/labfoundry/bin/labfoundry-helper *" in sudoers
    assert "labfoundry-root-login.conf" in script
    assert "PermitRootLogin no" in script
    assert "HTTPS/443" in docs
    assert "HTTP/80 redirects to HTTPS" in docs
    assert "proxying HTTPS/443 to" in root_docs
    assert "-PipGlobalIndex" in root_docs
    assert "-PipGlobalIndexUrl" in root_docs
    assert "Leave both options empty to keep" in root_docs
    assert "standard pip behavior" in root_docs


def test_photon_provisioning_prepares_attached_data_disks():
    provision = Path("image/common/scripts/provision-labfoundry.sh").read_text(encoding="utf-8")
    mount_script = Path("scripts/appliance/labfoundry-mount-data-disks").read_text(encoding="utf-8")
    hyperv_unit = Path("image/hyperv/systemd/labfoundry.service").read_text(encoding="utf-8")
    vmware_unit = Path("image/vmware-workstation/systemd/labfoundry.service").read_text(encoding="utf-8")
    hyperv_docs = Path("image/hyperv/README.md").read_text(encoding="utf-8")
    vmware_docs = Path("image/vmware-workstation/README.md").read_text(encoding="utf-8")
    root_docs = Path("README.md").read_text(encoding="utf-8")

    assert "tdnf -y install" in provision and "e2fsprogs" in provision
    assert "labfoundry-mount-data-disks" in provision
    assert "labfoundry-data-disks.service" in provision
    assert "systemctl enable labfoundry-data-disks.service" in provision
    assert "Before=labfoundry-bootstrap-https.service labfoundry.service" in provision

    assert "LABFOUNDRY_DEPOT" in mount_script
    assert "LABFOUNDRY_BKUP" in mount_script
    assert "/mnt/labfoundry-vcf-offline-depot" in mount_script
    assert "/mnt/labfoundry-vcf-backups" in mount_script
    assert 'mkfs.ext4 -F -L "$label" "$disk"' in mount_script
    assert "UUID=%s %s ext4 defaults,nofail,x-systemd.device-timeout=30s 0 2" in mount_script
    assert "findmnt -n -o SOURCE /" in mount_script
    assert "No blank data disk available" in mount_script

    assert "After=network-online.target labfoundry-data-disks.service labfoundry-bootstrap-https.service" in hyperv_unit
    assert "Wants=network-online.target labfoundry-data-disks.service labfoundry-bootstrap-https.service" in hyperv_unit
    assert "After=network-online.target labfoundry-data-disks.service labfoundry-bootstrap-https.service" in vmware_unit
    assert "Wants=network-online.target labfoundry-data-disks.service labfoundry-bootstrap-https.service" in vmware_unit

    assert "labfoundry-data-disks.service" in root_docs
    assert "labfoundry-data-disks.service" in hyperv_docs
    assert "labfoundry-data-disks.service" in vmware_docs
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


def test_packer_templates_stage_shared_boot_branding_assets():
    for template_path in (
        Path("image/hyperv/labfoundry-photon.pkr.hcl"),
        Path("image/vmware-workstation/labfoundry-photon.pkr.hcl"),
    ):
        template = template_path.read_text(encoding="utf-8")

        assert 'source      = "../common/boot"' in template
        assert 'destination = "/tmp/labfoundry-src/image/common/boot"' in template


def test_packer_build_uses_labfoundry_management_network_by_default():
    template = Path("image/hyperv/labfoundry-photon.pkr.hcl").read_text(encoding="utf-8")
    docs = Path("image/hyperv/README.md").read_text(encoding="utf-8")
    root_docs = Path("README.md").read_text(encoding="utf-8")
    wrapper = Path("scripts/windows/hyperv/build-photon-image.ps1").read_text(encoding="utf-8")
    build_module = Path("scripts/windows/common/LabFoundry.PhotonImage.psm1").read_text(encoding="utf-8")
    gitignore = Path(".gitignore").read_text(encoding="utf-8")

    assert 'default = "LabFoundry-Mgmt"' in template
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
    assert '"LABFOUNDRY_DRY_RUN_SYSTEM_ADAPTERS=${local.dry_run_system_adapters_text}"' in template
    assert '"LABFOUNDRY_MGMT_DNS=${local.builder_static_dns_text}"' in template
    assert '"LABFOUNDRY_PIP_GLOBAL_INDEX=${var.pip_global_index}"' in template
    assert '"LABFOUNDRY_PIP_GLOBAL_INDEX_URL=${var.pip_global_index_url}"' in template
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
    assert "labfoundry-photon-with-kickstart.iso" in docs
    assert "Using remastered Photon ISO" in docs
    assert "without Packer typing boot commands" in docs
    assert "-PipGlobalIndex" in docs
    assert "-PipGlobalIndexUrl" in docs
    assert "Omit both pip options for standard/default pip behavior." in docs
    assert "[string]$SshPassword = 'VMware01!'" in wrapper
    assert "[string]$BootstrapAdminPassword = 'VMware01!'" in wrapper
    assert "[string[]]$BuilderStaticDns = @()" in wrapper
    assert "[string]$PipGlobalIndex = ''" in wrapper
    assert "[string]$PipGlobalIndexUrl = ''" in wrapper
    assert "Join-Path $PSScriptRoot '..\\common\\LabFoundry.PhotonImage.psm1'" in wrapper
    assert "Join-Path $PSScriptRoot '..\\..\\..\\image\\hyperv'" in wrapper
    assert "function Get-LabFoundryHostIpv4DnsServers" in build_module
    assert "Get-DnsClientServerAddress -AddressFamily IPv4" in build_module
    assert "Using host IPv4 DNS for Photon builder/appliance" in build_module
    assert "falling back to public DNS" in build_module
    assert "create_photon_kickstart_iso.py" in build_module
    assert "Using remastered Photon ISO" in build_module
    assert "Packer will boot a single DVD with embedded photon-ks.json and a GRUB auto-install entry." in build_module
    assert "Write-LabFoundryPackerVarFile" in build_module
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
    assert "Could not embed LabFoundry GRUB config" in remaster_helper


def test_photon_image_optional_pip_global_index_configuration():
    wrapper = Path("scripts/windows/hyperv/build-photon-image.ps1").read_text(encoding="utf-8")
    build_module = Path("scripts/windows/common/LabFoundry.PhotonImage.psm1").read_text(encoding="utf-8")
    template = Path("image/hyperv/labfoundry-photon.pkr.hcl").read_text(encoding="utf-8")
    vmware_template = Path("image/vmware-workstation/labfoundry-photon.pkr.hcl").read_text(encoding="utf-8")
    script = Path("image/common/scripts/provision-labfoundry.sh").read_text(encoding="utf-8")

    assert "[string[]]$BuilderStaticDns = @()" in wrapper
    assert "[string]$PipGlobalIndex = ''" in wrapper
    assert "[string]$PipGlobalIndexUrl = ''" in wrapper
    assert "Join-Path $PSScriptRoot '..\\common\\LabFoundry.PhotonImage.psm1'" in wrapper
    assert "pip_global_index         = $PipGlobalIndex" in build_module
    assert "pip_global_index_url     = $PipGlobalIndexUrl" in build_module

    assert 'variable "pip_global_index" {\n  type        = string\n  default     = ""' in template
    assert 'variable "pip_global_index_url" {\n  type        = string\n  default     = ""' in template
    assert '"LABFOUNDRY_PIP_GLOBAL_INDEX=${var.pip_global_index}"' in template
    assert '"LABFOUNDRY_PIP_GLOBAL_INDEX_URL=${var.pip_global_index_url}"' in template

    assert 'LABFOUNDRY_PIP_GLOBAL_INDEX="${LABFOUNDRY_PIP_GLOBAL_INDEX:-}"' in script
    assert 'LABFOUNDRY_PIP_GLOBAL_INDEX_URL="${LABFOUNDRY_PIP_GLOBAL_INDEX_URL:-}"' in script
    assert 'PIP_CACHE_DIR="${PIP_CACHE_DIR:-/var/cache/labfoundry-pip}"' in script
    assert "write_pip_config() {" in script
    assert 'printf \'index = %s\\n\' "$LABFOUNDRY_PIP_GLOBAL_INDEX"' in script
    assert 'printf \'index-url = %s\\n\' "$LABFOUNDRY_PIP_GLOBAL_INDEX_URL"' in script
    assert 'printf \'cache-dir = %s\\n\' "$PIP_CACHE_DIR"' in script
    assert 'write_pip_config /etc/pip.conf' in script
    assert 'python3 -m venv "$LABFOUNDRY_RELEASE_DIR/.venv"' in script
    assert (
        'python3 "$LABFOUNDRY_HOME/scripts/version.py" project-get --root "$LABFOUNDRY_HOME"'
        in script
    )
    assert "sed -n 's/^version" not in script
    assert 'LABFOUNDRY_RELEASE_DIR="$LABFOUNDRY_HOME/releases/bootstrap-$LABFOUNDRY_RELEASE_VERSION"' in script
    assert '"$LABFOUNDRY_RELEASE_DIR/bundle-metadata.json"' in script
    assert 'ln -sfn "releases/bootstrap-$LABFOUNDRY_RELEASE_VERSION" "$LABFOUNDRY_HOME/current"' in script
    assert 'ln -sfn "current/.venv" "$LABFOUNDRY_HOME/.venv"' in script
    assert 'write_pip_config "$LABFOUNDRY_HOME/.venv/pip.conf"' in script
    assert '--requirement "$LABFOUNDRY_HOME/requirements-appliance.lock"' in script
    assert 'pip install --no-deps "$LABFOUNDRY_HOME"' in script
    assert "/etc/labfoundry/update-trust.d" in script
    assert 'trust_source_dir="$LABFOUNDRY_HOME/image/common/update-trust"' in script
    assert 'for trust_key in "$trust_source_dir"/*.pem' in script
    for packer_template in (template, vmware_template):
        assert 'source      = "../../scripts/version.py"' in packer_template
        assert 'destination = "/tmp/labfoundry-src/scripts/version.py"' in packer_template
        assert 'source      = "../common/update-trust"' in packer_template
        assert 'destination = "/tmp/labfoundry-src/image/common/update-trust"' in packer_template
    assert "LabFoundry release trust source directory is missing" in script
    assert "No LabFoundry release trust keys were staged" in script
    assert 'openssl pkey -pubin -in "$trust_key" -text -noout' in script
    assert "*ED25519*" in script
    assert 'export PIP_DISABLE_PIP_VERSION_CHECK=1' in script
    assert 'export PIP_INDEX_URL="$LABFOUNDRY_PIP_GLOBAL_INDEX_URL"' in script
    assert "pip install --upgrade pip setuptools wheel" not in script
    assert "packages.vcfd.broadcom.net/artifactory" not in wrapper
    assert "packages.vcfd.broadcom.net/artifactory" not in template
    assert "packages.vcfd.broadcom.net/artifactory" not in script


def test_vmware_builder_uses_nat_gateway_dns_by_default():
    wrapper = Path("scripts/windows/vmware/build-photon-image.ps1").read_text(encoding="utf-8")
    docs = Path("image/vmware-workstation/README.md").read_text(encoding="utf-8")

    assert "$builderDnsWasPassed = $PSBoundParameters.ContainsKey('BuilderStaticDns')" in wrapper
    assert "-not $builderDnsWasPassed -and $BuilderStaticDns.Count -eq 0 -and $management.Type -eq 'nat'" in wrapper
    assert "$BuilderStaticDns = @($managementGateway)" in wrapper
    assert "Using VMware NAT gateway DNS for Photon builder" in wrapper
    assert "Photon builder temporary SSH address" in wrapper
    assert "gateway DNS proxy" in docs
    assert "copying unrelated host" in docs
    assert "DNS servers into the Photon kickstart" in docs


def test_lifecycle_hyperv_script_uses_separate_vm_set_by_default():
    script = Path("scripts/windows/hyperv/run-lifecycle-test.ps1").read_text(encoding="utf-8")
    wrapper = Path("scripts/windows/hyperv/invoke-lifecycle-test.ps1").read_text(encoding="utf-8")
    runner = Path("scripts/interop/lifecycle_test.py").read_text(encoding="utf-8")

    assert "[string]$LabName = 'LabFoundryLifecycle'" in script
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
    assert "New-LifecyclePxeVm -Name $pxeClientName -SwitchName 'LabFoundry-SiteA'" in script
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
    assert "@('LabFoundry', 'LabFoundry-Photon-Builder')" in script
    assert "image\\hyperv\\clients\\alpine-cloud\\labfoundry-tiny-linux-client.vhdx" in script
    assert "Running lifecycle appliance VM(s) may already own ${ApplianceIPAddress}" in script
    assert "-CleanupVmsOnly" in script


def test_create_labfoundry_test_vm_wrapper_is_safe_and_simple():
    script = Path("scripts/windows/hyperv/create-labfoundry-test-vm.ps1").read_text(encoding="utf-8")
    vm_script = Path("scripts/windows/hyperv/create-labfoundry-vm.ps1").read_text(encoding="utf-8")
    docs = Path("image/hyperv/README.md").read_text(encoding="utf-8")

    assert "[string]$Name = 'LabFoundry'" in script
    assert "[switch]$Redeploy" in script
    assert "[switch]$ResetDataDisks" in script
    assert "[switch]$SkipLabNetworkAdapters" in script
    assert "[int]$SiteVlanId = 12" in script
    assert "[int]$TaggedVlanId = 50" in script
    assert "[switch]$WaitForIp" in script
    assert "Find-LatestApplianceVhdx" in script
    assert "Remove-ExistingDataDisks" in script
    assert "LabFoundry-Depot.vhdx" in script
    assert "LabFoundry-Backups.vhdx" in script
    assert "Refusing to remove OS disk as a data disk" in script
    assert "create-switches.ps1" in script
    assert "create-labfoundry-vm.ps1" in script
    assert "-SkipLabNetworkAdapters:$SkipLabNetworkAdapters" in script
    assert "-SiteVlanId $SiteVlanId" in script
    assert "-TaggedVlanId $TaggedVlanId" in script
    assert "start-labfoundry-vm.ps1" in script
    assert "get-labfoundry-vm-ip.ps1" in script
    assert "VM already exists: $Name. Pass -Redeploy" in script
    assert "Remove-VM -Name $Name -Force" in script
    assert "Run this script from an elevated PowerShell session." not in script
    assert "create-labfoundry-test-vm.ps1 -WaitForIp" in docs
    assert "pass `-Redeploy` to remove and recreate only that VM" in docs
    assert "first adapter management-only on `LabFoundry-Mgmt`" in docs
    assert "`Services` on the dedicated `LabFoundry-Services` switch" in docs
    assert "`SiteA` on" in docs and "`LabFoundry-SiteA` as trunk VLAN 12" in docs
    assert "`Trunk` on `LabFoundry-Trunk` as trunk" in docs and "VLAN 50" in docs
    assert "WAN-Test` on `LabFoundry-SiteB` as" in docs
    assert "`/var/lib/labfoundry/users/<admin>` with `/usr/bin/pwsh`" in docs
    assert "`powershell` package" in docs
    assert "[switch]$SkipLabNetworkAdapters" in vm_script
    assert "[int]$SiteVlanId = 12" in vm_script
    assert "[int]$TaggedVlanId = 50" in vm_script
    assert "[string]$ServiceSwitchName = 'LabFoundry-Services'" in vm_script
    assert "Add-ServiceNetworkAdapter" in vm_script
    assert "Add-VMNetworkAdapter -VMName $VMName -Name 'Services' -SwitchName $SwitchName" in vm_script
    assert "Set-VMNetworkAdapterVlan -VMName $VMName -VMNetworkAdapterName 'Services' -Untagged" in vm_script
    assert "Add-LabNetworkAdapters" in vm_script
    assert "Add-VMNetworkAdapter -VMName $VMName -Name 'SiteA' -SwitchName 'LabFoundry-SiteA'" in vm_script
    assert "Set-VMNetworkAdapterVlan -VMName $VMName -VMNetworkAdapterName 'SiteA' -Trunk -AllowedVlanIdList \"$SiteTag\" -NativeVlanId 0" in vm_script
    assert "Add-VMNetworkAdapter -VMName $VMName -Name 'Trunk' -SwitchName 'LabFoundry-Trunk'" in vm_script
    assert "Set-VMNetworkAdapterVlan -VMName $VMName -VMNetworkAdapterName 'Trunk' -Trunk -AllowedVlanIdList \"$TaggedVlanTag\" -NativeVlanId 0" in vm_script
    assert "Add-VMNetworkAdapter -VMName $VMName -Name 'WAN-Test' -SwitchName 'LabFoundry-SiteB'" in vm_script


def test_windows_script_names_use_provider_tokens():
    script_paths = {
        path.relative_to("scripts/windows").as_posix()
        for path in Path("scripts/windows").rglob("*.ps1")
    }
    root_scripts = {path.name for path in Path("scripts/windows").glob("*.ps1")}

    old_vmware_token = "vmware-" + "workstation"
    old_names = {
        f"build-photon-{old_vmware_token}-image.ps1",
        f"create-labfoundry-{old_vmware_token}-test-vm.ps1",
        f"invoke-{old_vmware_token}-lifecycle-test.ps1",
        f"prepare-{old_vmware_token}-networks.ps1",
        "prepare-" + "tiny-linux-client.ps1",
        "get-labfoundry-" + "vm-ip.ps1",
        "start-labfoundry-" + "vm.ps1",
        "stop-labfoundry-" + "vm.ps1",
    }
    assert root_scripts == set()
    assert script_paths.isdisjoint(old_names)

    assert "common/LabFoundry.PhotonImage.psm1" not in script_paths
    assert "hyperv/build-photon-image.ps1" in script_paths
    assert "hyperv/create-labfoundry-test-vm.ps1" in script_paths
    assert "hyperv/create-labfoundry-vm.ps1" in script_paths
    assert "hyperv/invoke-lifecycle-test.ps1" in script_paths
    assert "hyperv/prepare-tiny-linux-client.ps1" in script_paths
    assert "hyperv/get-labfoundry-vm-ip.ps1" in script_paths
    assert "hyperv/start-labfoundry-vm.ps1" in script_paths
    assert "hyperv/stop-labfoundry-vm.ps1" in script_paths
    assert "vmware/build-photon-image.ps1" in script_paths
    assert "vmware/create-labfoundry-test-vm.ps1" in script_paths
    assert "vmware/create-labfoundry-vm.ps1" in script_paths
    assert "vmware/invoke-lifecycle-test.ps1" in script_paths
    assert "vmware/prepare-networks.ps1" in script_paths
    assert "vmware/prepare-tiny-linux-client.ps1" in script_paths
    assert "vmware/get-labfoundry-vm-ip.ps1" in script_paths
    assert "vmware/start-labfoundry-vm.ps1" in script_paths
    assert "vmware/stop-labfoundry-vm.ps1" in script_paths
    assert "vmware/remove-labfoundry-vm.ps1" in script_paths
    assert "vmware/remove-lifecycle-vms.ps1" in script_paths
    assert "vmware/reset-labfoundry-vm.ps1" in script_paths
    assert "vmware/set-test-nics.ps1" in script_paths


def test_create_labfoundry_vmware_test_vm_wrapper_uses_common_helpers():
    script = Path("scripts/windows/vmware/create-labfoundry-test-vm.ps1").read_text(encoding="utf-8")
    vm_script = Path("scripts/windows/vmware/create-labfoundry-vm.ps1").read_text(encoding="utf-8")
    nics_script = Path("scripts/windows/vmware/set-test-nics.ps1").read_text(encoding="utf-8")
    build_script = Path("scripts/windows/vmware/build-photon-image.ps1").read_text(encoding="utf-8")
    packer_template = Path("image/vmware-workstation/labfoundry-photon.pkr.hcl").read_text(encoding="utf-8")
    docs = Path("image/vmware-workstation/README.md").read_text(encoding="utf-8")

    assert "[string]$Name = 'LabFoundry-VMware'" in script
    assert "[switch]$Redeploy" in script
    assert "[switch]$SkipLabNetworkAdapters" in script
    assert "[switch]$IncludeLabNetworkAdapters" in script
    assert "[switch]$ResetDataDisks" in script
    assert "[switch]$WaitForIp" in script
    assert "[switch]$TrustRootCa" in script
    assert "[int]$TimeoutSeconds = 300" in script
    assert "Install-ApplianceRootCa" in script
    assert "Waiting up to $TimeoutSeconds seconds for the LabFoundry root CA" in script
    assert "LabFoundry root CA is not ready; retrying in $PollSeconds seconds." in script
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
    assert "create-labfoundry-vm.ps1" in script
    assert "start-labfoundry-vm.ps1" in script
    assert "get-labfoundry-vm-ip.ps1" in script
    assert "remove-labfoundry-vm.ps1" in script
    assert "Find-LatestApplianceVmx" in script
    assert "image\\vmware-workstation\\output" in script
    assert "image\\vmware-workstation\\test-vms\\$Name" in script
    assert "$effectiveSkipLabNetworkAdapters = -not $IncludeLabNetworkAdapters" in script
    assert "LabFoundry-Depot.vmdk" in script
    assert "LabFoundry-Backups.vmdk" in script
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
    assert "Join-Path $PSScriptRoot '..\\common\\LabFoundry.PhotonImage.psm1'" in build_script
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
    assert "adds a second `vmxnet3` adapter on `-ServiceVmnetName`" in docs


def test_vmware_deploy_wheel_supports_password_backed_noninteractive_deploy():
    script = Path("scripts/windows/vmware/deploy-wheel.ps1").read_text(encoding="utf-8")
    readme = Path("README.md").read_text(encoding="utf-8")

    assert "[string]$SshPassword = $env:LABFOUNDRY_DEPLOY_SSH_PASSWORD" in script
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
    assert "At least one matched local and remote LabFoundry release trust key is required." in script
    assert "image\\common\\update-trust" in script
    assert "No LabFoundry release trust keys found under" in script
    assert "install -d -o root -g root -m 0755 /etc/labfoundry/update-trust.d" in script
    assert 'install -o root -g root -m 0644 "$trust_key_path" "/etc/labfoundry/update-trust.d/$trust_key_name"' in script
    assert "openssl pkey -pubin" in script
    assert "LabFoundry release trust key is not Ed25519" in script
    assert "--local-runtime-dependency" in script
    assert "'authlib-*.whl'" in script
    assert "'joserfc-*.whl'" in script
    assert "Matched local and remote runtime dependency wheels are required." in script
    assert '"$python" -m pip install --force-reinstall --no-deps "$runtime_dependency_path"' in script
    assert '"$python" -m pip install --force-reinstall --no-deps "$wheel"' in script
    assert "systemctl enable labfoundry-worker.service" in script
    assert "systemctl restart labfoundry-worker.service" in script
    assert "systemctl is-active labfoundry-worker.service" in script
    assert "LABFOUNDRY_DEPLOY_SSH_PASSWORD" in script
    assert "client.set_missing_host_key_policy(paramiko.AutoAddPolicy())" in script
    assert "allow_agent=False" in script
    assert "look_for_keys=False" in script
    assert "sudo -S -p '' sh" in script
    assert "sanitized(stdout_text, password)" in script
    assert "if (-not $SshPassword) {" in script
    assert "Test-RequiredCommand -Name 'scp'" in script
    assert "Invoke-PasswordBackedDeploy `" in script
    assert "-SshPassword '<admin-password>'" in readme
    assert "does not modify the global Python environment" in readme
    assert "When using `-SkipBuild`, keep" in readme
    assert "Without a password, it preserves the original" in readme
    assert "`scp`/`ssh` key or agent workflow." in readme


def test_lifecycle_hyperv_script_does_not_cleanup_without_explicit_flag():
    script = Path("scripts/windows/hyperv/run-lifecycle-test.ps1").read_text(encoding="utf-8")

    assert "[switch]$CleanupCreatedLab" in script
    assert "if ($CleanupCreatedLab)" in script
    assert "Lifecycle VMs were left in place" in script
    assert "Remove-VM -Name $name -Force" in script
    assert "Remove-VM -Name 'LabFoundry'" not in script


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
    assert "LabFoundryLifecycle-$(Get-Date -Format 'yyyyMMddHHmmss')" in script
    assert "$singlePurposeActions" not in script


def test_lifecycle_cleanup_scripts_are_scoped_to_labfoundry_assets():
    switch_script = Path("scripts/windows/hyperv/create-switches.ps1").read_text(encoding="utf-8")
    network_script = Path("scripts/windows/hyperv/remove-lifecycle-networks.ps1").read_text(encoding="utf-8")
    vm_script = Path("scripts/windows/hyperv/remove-lifecycle-vms.ps1").read_text(encoding="utf-8")

    assert "LabFoundry-Services" in switch_script
    assert "LabFoundry-Mgmt-NAT" in network_script
    assert "LabFoundry-Mgmt" in network_script
    assert "LabFoundry-Services" in network_script
    assert "LabFoundry-SiteA" in network_script
    assert "Get-VMNetworkAdapter -All" in network_script
    assert "Refusing to remove switch" in network_script
    assert "LabFoundryLifecycle*" in vm_script
    assert "LabFoundry-Photon-Builder" in vm_script
    assert "Refusing VM cleanup" in vm_script
    assert "Remove-VM -Name $vm.Name -Force" in vm_script


def test_vmware_lifecycle_cleanup_only_removes_existing_lifecycle_vms():
    wrapper = Path("scripts/windows/vmware/invoke-lifecycle-test.ps1").read_text(encoding="utf-8")
    cleanup_script = Path("scripts/windows/vmware/remove-lifecycle-vms.ps1").read_text(encoding="utf-8")
    docs = Path("docs/vmware-workstation-lifecycle-testing.md").read_text(encoding="utf-8")

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
    assert "LabFoundryWorkstationLifecycle" in cleanup_script
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
    assert "[switch]$FullEsxiPxeInstall" in wrapper
    assert "[string]$PxeInstallerIsoPath = ''" in wrapper
    assert "$effectiveSkipBackupRestoreTest = [bool]($SkipBackupRestoreTest -or $RoutingWanOnly)" in wrapper
    assert "if ($RoutingWanOnly) { $arguments += '-RoutingWanOnly' }" in wrapper
    assert "if ($FullEsxiPxeInstall) { $arguments += '-FullEsxiPxeInstall' }" in wrapper
    assert "if ($PxeInstallerIsoPath) { $arguments += @('-PxeInstallerIsoPath', $PxeInstallerIsoPath) }" in wrapper
    assert "-RoutingWanOnly and -FullEsxiPxeInstall are mutually exclusive." in wrapper

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
    assert "$applianceHostKey = Get-PlinkHostKey -HostName $ApplianceIPAddress" in runner
    assert "'--appliance-ssh-hostkey', $applianceHostKey" in runner
    assert "'--client-a-hostkey', $clientAHostKey" in runner
    assert "function Sync-ApplianceHelperScript" in runner
    assert "scripts\\appliance\\labfoundry-helper" in runner
    assert "copyFileFromHostToGuest $ApplianceVmx $localHelper $guestTemp" in runner
    assert "install -o root -g root -m 0755 $quotedTemp /opt/labfoundry/bin/labfoundry-helper" in runner
    assert "function Sync-ApplianceApplicationWheel" in runner
    assert "python -m pip wheel $repoRoot --no-deps -w $wheelRoot" in runner
    assert "pip install --force-reinstall --no-deps $quotedWheel" in runner
    assert "systemctl restart labfoundry.service" in runner
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
    assert "labfoundry-refresh-test-dhcp" in script
    assert "joliet_path=f\"/{name}\"" in script


def test_prepare_tiny_linux_client_downloads_verifies_and_converts_alpine():
    script = Path("scripts/windows/hyperv/prepare-tiny-linux-client.ps1").read_text(encoding="utf-8")

    assert "dl-cdn.alpinelinux.org/alpine/latest-stable/releases/cloud" in script
    assert "generic_alpine-3.24.1-x86_64-uefi-cloudinit-r0.qcow2" in script
    assert "Get-FileHash -Algorithm SHA512" in script
    assert "qemu-img convert -p -f qcow2 -O vhdx -o subformat=dynamic" in script
    assert "labfoundry-tiny-linux-client.vhdx" in script


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
    assert '"dnsmasq": "test -f /etc/labfoundry/dnsmasq.d/labfoundry.conf && getent hosts interop-appliance.labfoundry.internal"' not in script
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
    assert "labfoundry-kms.service" in script
    assert "kms_files" in script
    assert "kms_service" in script
    assert "kms_tls" in script
    assert '"local_console"' in script
    assert "systemctl is-active labfoundry-console.service" in script
    assert "systemctl is-enabled getty@tty1.service" in script
    assert "systemctl show getty@tty2.service" in script
    assert '\\"maintenance_isolation\\": false' in script
    assert "apply-kms-unit" in script
    assert "Appliance apply task failed" in script
    assert "/etc/labfoundry/kms/clients/certs/vcf-management.crt" in script
    assert "/etc/labfoundry/kms/clients/vcf-management.crt" not in script
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
            <aside>LabFoundry navigation noise</aside>
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
    doc = Path("docs/hyperv-lifecycle-testing.md").read_text(encoding="utf-8")

    assert "Invoke-Pester tests/pester/HyperVLifecycle.Tests.ps1" in doc
    assert "Python appliance and guest assertions must remain pytest-covered" in doc
    assert "scripts/interop/lifecycle_test.py" in doc
