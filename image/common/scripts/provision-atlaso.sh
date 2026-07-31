#!/bin/sh
set -eu

ATLASO_SRC="${ATLASO_SRC:-/tmp/atlaso-src}"
ATLASO_HOME="${ATLASO_HOME:-/opt/atlaso}"
ATLASO_STATE="${ATLASO_STATE:-/var/lib/atlaso}"
ATLASO_LOG="${ATLASO_LOG:-/var/log/atlaso}"
ATLASO_MGMT_ADDRESS="${ATLASO_MGMT_ADDRESS:-192.168.49.1/24}"
ATLASO_MGMT_GATEWAY="${ATLASO_MGMT_GATEWAY:-192.168.49.254}"
ATLASO_MGMT_SOURCE_CIDR="${ATLASO_MGMT_SOURCE_CIDR:-}"
ATLASO_MGMT_DNS="${ATLASO_MGMT_DNS:-1.1.1.1 9.9.9.9}"
ATLASO_MGMT_INTERFACE="${ATLASO_MGMT_INTERFACE:-eth0}"
ATLASO_MGMT_IPV4_METHOD="${ATLASO_MGMT_IPV4_METHOD:-}"
ATLASO_MGMT_USES_DHCP=false
if [ "$ATLASO_MGMT_ADDRESS" = "dhcp" ] || [ "$ATLASO_MGMT_IPV4_METHOD" = "dhcp" ]; then
  ATLASO_MGMT_USES_DHCP=true
fi
ATLASO_DRY_RUN_SYSTEM_ADAPTERS="${ATLASO_DRY_RUN_SYSTEM_ADAPTERS:-true}"
ATLASO_GUEST_PLATFORM="${ATLASO_GUEST_PLATFORM:-hyperv}"
ATLASO_IMAGE_ASSET_DIR="${ATLASO_IMAGE_ASSET_DIR:-image/hyperv}"
ATLASO_PIP_GLOBAL_INDEX="${ATLASO_PIP_GLOBAL_INDEX:-}"
ATLASO_PIP_GLOBAL_INDEX_URL="${ATLASO_PIP_GLOBAL_INDEX_URL:-}"
ATLASO_POWERCLI_MODULE_SOURCE="${ATLASO_POWERCLI_MODULE_SOURCE:-}"
ATLASO_POWERCLI_VERSION="${ATLASO_POWERCLI_VERSION:-9.1.0.25380678}"
BOOTSTRAP_USERNAME="${ATLASO_BOOTSTRAP_ADMIN_USERNAME:-admin}"
BOOTSTRAP_PASSWORD="${ATLASO_BOOTSTRAP_ADMIN_PASSWORD:-}"
BOOTSTRAP_SHELL="${ATLASO_BOOTSTRAP_ADMIN_SHELL:-/usr/bin/pwsh}"
PIP_CACHE_DIR="${PIP_CACHE_DIR:-/var/cache/atlaso-pip}"
TDNF_PROGRESS_RUNNER="$ATLASO_SRC/scripts/run_tdnf_with_progress.py"

log_step() {
  printf '\n==> Atlaso appliance: %s\n' "$1"
}

write_pip_config() {
  path="$1"

  if [ -z "$ATLASO_PIP_GLOBAL_INDEX" ] && [ -z "$ATLASO_PIP_GLOBAL_INDEX_URL" ]; then
    return
  fi

  install -d -o root -g root -m 0755 "$(dirname "$path")"
  {
    printf '[global]\n'
    if [ -n "$ATLASO_PIP_GLOBAL_INDEX" ]; then
      printf 'index = %s\n' "$ATLASO_PIP_GLOBAL_INDEX"
    fi
    if [ -n "$ATLASO_PIP_GLOBAL_INDEX_URL" ]; then
      printf 'index-url = %s\n' "$ATLASO_PIP_GLOBAL_INDEX_URL"
    fi
    printf 'cache-dir = %s\n' "$PIP_CACHE_DIR"
  } >"$path"
  chmod 0644 "$path"
}

run_tdnf() {
  label="$1"
  shift
  python3 "$TDNF_PROGRESS_RUNNER" \
    --label "$label" \
    --cache-dir /var/cache/tdnf \
    -- \
    tdnf -y "$@"
}

if [ -z "$BOOTSTRAP_PASSWORD" ]; then
  echo "ATLASO_BOOTSTRAP_ADMIN_PASSWORD is required for appliance provisioning" >&2
  exit 2
fi
if [ ! -r "$TDNF_PROGRESS_RUNNER" ]; then
  echo "TDNF progress runner is missing from staged Atlaso sources: $TDNF_PROGRESS_RUNNER" >&2
  exit 2
fi

log_step "system adapter dry-run mode: $ATLASO_DRY_RUN_SYSTEM_ADAPTERS"
log_step "guest platform: $ATLASO_GUEST_PLATFORM"

log_step "refreshing Photon package metadata"
tdnf -y clean all || true
run_tdnf "Photon package metadata refresh" makecache

log_step "applying Photon OS updates"
run_tdnf "Photon OS update" update

log_step "installing Photon appliance packages"
GUEST_INTEGRATION_PACKAGES=""
case "$ATLASO_GUEST_PLATFORM" in
  hyperv)
    GUEST_INTEGRATION_PACKAGES="hyper-v"
    ;;
  vmware)
    GUEST_INTEGRATION_PACKAGES="open-vm-tools"
    ;;
  *)
    echo "Unsupported ATLASO_GUEST_PLATFORM: $ATLASO_GUEST_PLATFORM" >&2
    exit 2
    ;;
esac
run_tdnf "Photon appliance package installation" \
  install python3 python3-pip python3-devel python3-virtualenv python3-curses python3-ntp sudo openssh-server curl rsync tar gzip shadow e2fsprogs sqlite procps-ng gnupg $GUEST_INTEGRATION_PACKAGES nftables dnsmasq ntpsec nfs-utils rpcbind openldap openldap-servers ipxe syslinux nginx powershell

log_step "installing VCF PowerCLI $ATLASO_POWERCLI_VERSION"
export ATLASO_POWERCLI_VERSION
if [ -n "$ATLASO_POWERCLI_MODULE_SOURCE" ]; then
  if [ ! -d "$ATLASO_POWERCLI_MODULE_SOURCE" ]; then
    echo "ATLASO_POWERCLI_MODULE_SOURCE must be a directory containing an offline PowerShell module bundle" >&2
    exit 2
  fi
  install -d -o root -g root -m 0755 /usr/local/share/powershell/Modules
  cp -R "$ATLASO_POWERCLI_MODULE_SOURCE"/. /usr/local/share/powershell/Modules/
else
  if [ "$(awk '$2 == "/tmp" { print $3; exit }' /proc/mounts)" = "tmpfs" ]; then
    log_step "expanding build-time /tmp tmpfs to 4 GiB for VCF PowerCLI"
    mount -o remount,size=4G /tmp
  fi
  pwsh -NoLogo -NoProfile -NonInteractive -Command \
    '$ErrorActionPreference = "Stop"; Set-PSRepository -Name PSGallery -InstallationPolicy Trusted; try { Install-Module -Name VCF.PowerCLI -RequiredVersion $env:ATLASO_POWERCLI_VERSION -Repository PSGallery -Scope AllUsers -Force -AllowClobber -AcceptLicense -Confirm:$false } finally { Set-PSRepository -Name PSGallery -InstallationPolicy Untrusted }'
fi
chmod 0755 /usr/local/share/powershell /usr/local/share/powershell/Modules
chmod -R a+rX,go-w /usr/local/share/powershell/Modules
pwsh -NoLogo -NoProfile -NonInteractive -Command \
  '$ErrorActionPreference = "Stop"; $module = Get-Module -Name VCF.PowerCLI -ListAvailable | Where-Object Version -eq $env:ATLASO_POWERCLI_VERSION | Select-Object -First 1; if (-not $module) { throw "VCF.PowerCLI $env:ATLASO_POWERCLI_VERSION is not installed" }; Import-Module $module.Path -Force; Set-PowerCLIConfiguration -ParticipateInCeip $false -Scope AllUsers -Confirm:$false | Out-Null; $configured = Get-PowerCLIConfiguration -Scope AllUsers; if ([bool]$configured.ParticipateInCEIP) { throw "VCF.PowerCLI CEIP default was not disabled" }; if (-not (Get-Command Connect-VIServer -ErrorAction SilentlyContinue)) { throw "Connect-VIServer is not available" }; Write-Host "VCF.PowerCLI $($module.Version) verified with appliance-wide CEIP disabled"'

log_step "verifying Photon OS updates after package install"
run_tdnf "Photon OS update verification" update

log_step "leaving only Photon NTPsec available for desired-state activation"
systemctl disable --now ntpd.service 2>/dev/null || true
systemctl disable --now systemd-timesyncd.service 2>/dev/null || true
systemctl disable --now chronyd.service 2>/dev/null || true

log_step "leaving ESX NFS services disabled until global appliance apply"
systemctl disable --now nfs-server.service 2>/dev/null || true
systemctl disable --now rpcbind.service rpcbind.socket 2>/dev/null || true

log_step "installing stable virtual-disk identity policy"
install -d -o root -g root -m 0755 /etc/udev/rules.d
cat > /etc/udev/rules.d/99-atlaso-disk-identity.rules <<'EOF'
# Some virtual SCSI controllers do not expose a serial/WWN. Preserve a stable
# controller-path identity under /dev/disk/by-id so Atlaso never claims a
# transient /dev/sdX name. Native serial/WWN identities remain preferred.
SUBSYSTEM=="block", ENV{DEVTYPE}=="disk", ENV{ID_SERIAL}=="", IMPORT{builtin}="path_id", ENV{ID_PATH_TAG}=="?*", SYMLINK+="disk/by-id/atlaso-path-$env{ID_PATH_TAG}"
EOF
udevadm control --reload-rules
udevadm trigger --subsystem-match=block --action=add

log_step "disabling systemd SSH-over-vsock auto generator"
if [ "$ATLASO_GUEST_PLATFORM" = "hyperv" ]; then
  install -d -o root -g root -m 0755 /etc/systemd/system-generators
  ln -sfn /dev/null /etc/systemd/system-generators/systemd-ssh-generator
fi

if ! getent group atlaso >/dev/null 2>&1; then
  groupadd --system atlaso
fi

if ! id atlaso >/dev/null 2>&1; then
  useradd --system --gid atlaso --home-dir "$ATLASO_STATE" --shell /sbin/nologin atlaso
fi
if ! getent group atlaso-automation >/dev/null 2>&1; then
  groupadd --system atlaso-automation
fi
if ! id atlaso-automation >/dev/null 2>&1; then
  useradd --system --gid atlaso-automation --home-dir "$ATLASO_STATE/automation" --shell /sbin/nologin atlaso-automation
fi
if ! getent group atlaso-kmip >/dev/null 2>&1; then
  groupadd --system atlaso-kmip
fi
if ! id atlaso-kmip >/dev/null 2>&1; then
  useradd --system --gid atlaso-kmip --home-dir "$ATLASO_STATE/kmip" --shell /sbin/nologin atlaso-kmip
fi
usermod -a -G atlaso-automation atlaso

install -d -o root -g root -m 0755 "$ATLASO_HOME"
install -d -o atlaso -g atlaso -m 0750 "$ATLASO_STATE"
install -d -o atlaso -g atlaso -m 0750 "$ATLASO_STATE/apply/firewall"
install -d -o atlaso -g atlaso -m 0750 "$ATLASO_STATE/apply/dnsmasq"
install -d -o atlaso -g atlaso -m 0750 "$ATLASO_STATE/apply/kms"
install -d -o atlaso -g atlaso -m 0750 "$ATLASO_STATE/apply/ldap"
install -d -o atlaso -g atlaso -m 0750 "$ATLASO_STATE/apply/local-users"
install -d -o atlaso -g atlaso -m 0750 "$ATLASO_STATE/apply/ntpd"
install -d -o atlaso -g atlaso -m 0750 "$ATLASO_STATE/apply/esx-storage"
install -d -o atlaso -g atlaso -m 0750 "$ATLASO_STATE/apply/vcf-backups"
install -d -o atlaso -g atlaso -m 0750 "$ATLASO_STATE/apply/vcf-offline-depot"
install -d -o atlaso -g atlaso -m 0750 "$ATLASO_STATE/vcfDownloadTool/active-tool"
install -d -o atlaso -g atlaso -m 0700 "$ATLASO_STATE/vcfDownloadTool/active-tool/secrets"
install -d -o atlaso -g atlaso -m 0750 "$ATLASO_STATE/dnsmasq"
install -d -o atlaso-kmip -g atlaso-kmip -m 0700 "$ATLASO_STATE/kmip"
install -d -o atlaso -g atlaso -m 0700 "$ATLASO_STATE/ldap/recovery"
install -d -o root -g root -m 0755 "$ATLASO_STATE/users"
install -d -o atlaso -g atlaso-automation -m 0750 "$ATLASO_STATE/automation"
install -d -o atlaso -g atlaso-automation -m 0750 "$ATLASO_STATE/automation/scripts"
install -d -o atlaso-automation -g atlaso-automation -m 0750 "$ATLASO_STATE/automation/runs"
install -d -o atlaso -g atlaso -m 0750 "$ATLASO_LOG"
install -d -o root -g root -m 0755 /mnt/atlaso-esx-storage /srv/atlaso/esx-storage /etc/exports.d /etc/nfs.conf.d
install -d -o atlaso-kmip -g atlaso-kmip -m 0700 "$ATLASO_LOG/kmip"
install -d -o root -g root -m 0755 /etc/atlaso
install -d -o root -g root -m 0755 /etc/atlaso/dnsmasq.d
install -d -o root -g atlaso-kmip -m 0750 /etc/atlaso/kmip
install -d -o root -g atlaso-kmip -m 0750 /etc/atlaso/kmip/certs
install -d -o root -g root -m 0755 /etc/atlaso/kmip/clients/certs
install -d -o root -g root -m 0755 /etc/atlaso/ldap/tls
install -d -o root -g root -m 0755 /etc/atlaso/nginx/sites.d
install -d -o root -g root -m 0755 /etc/atlaso/ssh/authorized_keys
install -d -o root -g root -m 0755 /etc/ssh/sshd_config.d
install -d -o root -g root -m 0755 /etc/systemd/network
install -d -o root -g root -m 0755 /usr/local/lib/atlaso
install -d -o root -g root -m 0755 /mnt/atlaso-vcf-backups
install -d -o root -g root -m 0755 /mnt/atlaso-vcf-registry
install -d -o atlaso -g atlaso -m 0755 /mnt/atlaso-vcf-offline-depot

if ! id "$BOOTSTRAP_USERNAME" >/dev/null 2>&1; then
  useradd --home-dir "$ATLASO_STATE/users/$BOOTSTRAP_USERNAME" --create-home --shell "$BOOTSTRAP_SHELL" "$BOOTSTRAP_USERNAME"
else
  usermod --shell "$BOOTSTRAP_SHELL" "$BOOTSTRAP_USERNAME"
fi
touch /etc/shells
grep -qxF "$BOOTSTRAP_SHELL" /etc/shells || printf '%s\n' "$BOOTSTRAP_SHELL" >>/etc/shells
printf '%s:%s\n' "$BOOTSTRAP_USERNAME" "$BOOTSTRAP_PASSWORD" | chpasswd
cat >/etc/sudoers.d/atlaso-bootstrap-admin <<EOF
# Managed by Atlaso image provisioning. Bootstrap appliance administrator.
$BOOTSTRAP_USERNAME ALL=(ALL) ALL
EOF
chmod 0440 /etc/sudoers.d/atlaso-bootstrap-admin
visudo -cf /etc/sudoers.d/atlaso-bootstrap-admin
sudo -H -u "$BOOTSTRAP_USERNAME" env -u PSModulePath ATLASO_POWERCLI_VERSION="$ATLASO_POWERCLI_VERSION" \
  pwsh -NoLogo -NoProfile -NonInteractive -Command \
  '$ErrorActionPreference = "Stop"; $module = Get-Module -Name VCF.PowerCLI -ListAvailable | Where-Object Version -eq $env:ATLASO_POWERCLI_VERSION | Select-Object -First 1; if (-not $module) { throw "VCF.PowerCLI $env:ATLASO_POWERCLI_VERSION is not available to the bootstrap administrator" }; Import-Module $module.Path -Force; $configured = Get-PowerCLIConfiguration -Scope AllUsers; if ([bool]$configured.ParticipateInCEIP) { throw "VCF.PowerCLI CEIP default is not disabled for the bootstrap administrator" }; if (-not (Get-Command Connect-VIServer -ErrorAction SilentlyContinue)) { throw "Connect-VIServer is not available to the bootstrap administrator" }; Write-Host "VCF.PowerCLI $($module.Version) verified as $([Environment]::UserName) with appliance-wide CEIP disabled"'

cat >/etc/atlaso/build-info <<EOF
build_time_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
photon_release=$(cat /etc/photon-release 2>/dev/null || true)
kernel=$(uname -r)
python=$(python3 --version 2>&1)
powershell=$(pwsh -NoLogo -NoProfile -NonInteractive -Command '$PSVersionTable.PSVersion.ToString()')
powercli=$(pwsh -NoLogo -NoProfile -NonInteractive -Command '(Get-Module -Name VCF.PowerCLI -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1).Version.ToString()')
package_update=tdnf -y update completed during image provisioning
final_mgmt_address=$ATLASO_MGMT_ADDRESS
final_mgmt_gateway=$ATLASO_MGMT_GATEWAY
final_mgmt_interface=$ATLASO_MGMT_INTERFACE
EOF
chmod 0644 /etc/atlaso/build-info

rm -f /etc/sudoers.d/90-atlaso-build

log_step "syncing Atlaso application files"
rsync -a --delete \
  --exclude ".git" \
  --exclude ".venv" \
  --exclude ".pytest_cache" \
  --exclude "data" \
  --exclude "test-results" \
  "$ATLASO_SRC"/ "$ATLASO_HOME"/

install -d -o root -g root -m 0755 "$ATLASO_HOME/bin"

IPXE_BOOTLOADER_SOURCE_DIR="$ATLASO_HOME/third_party/ipxe/bootloaders"
IPXE_BOOTLOADER_TARGET_DIR="$ATLASO_STATE/pxe/bootloaders"
if [ -f "$IPXE_BOOTLOADER_SOURCE_DIR/undionly.kpxe" ] && [ -f "$IPXE_BOOTLOADER_SOURCE_DIR/snponly.efi" ]; then
  log_step "staging bundled iPXE bootloaders"
  install -d -o root -g root -m 0755 "$IPXE_BOOTLOADER_TARGET_DIR"
  install -o root -g root -m 0644 "$IPXE_BOOTLOADER_SOURCE_DIR/undionly.kpxe" "$IPXE_BOOTLOADER_TARGET_DIR/undionly.kpxe"
  install -o root -g root -m 0644 "$IPXE_BOOTLOADER_SOURCE_DIR/snponly.efi" "$IPXE_BOOTLOADER_TARGET_DIR/snponly.efi"
else
  echo "Bundled iPXE bootloaders are missing from $IPXE_BOOTLOADER_SOURCE_DIR" >&2
  echo "Expected undionly.kpxe and snponly.efi so ESXi PXE apply can validate on first boot." >&2
  exit 2
fi

INVENTORY_SOURCE_DIR="$ATLASO_HOME/image/inventory-linux/output"
INVENTORY_MANIFEST="$INVENTORY_SOURCE_DIR/manifest.json"
if [ ! -r "$INVENTORY_MANIFEST" ]; then
  echo "Bundled Atlaso Inventory Linux manifest is missing: $INVENTORY_MANIFEST" >&2
  exit 2
fi
INVENTORY_VERSION="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["version"])' "$INVENTORY_MANIFEST")"
INVENTORY_MEDIA_DIR="$ATLASO_STATE/pxe/media/inventory"
INVENTORY_TARGET_DIR="$INVENTORY_MEDIA_DIR/$INVENTORY_VERSION"
log_step "staging bundled Atlaso Inventory Linux $INVENTORY_VERSION"
install -d -o atlaso -g atlaso -m 0755 "$INVENTORY_MEDIA_DIR" "$INVENTORY_TARGET_DIR"
for artifact in bzImage rootfs.cpio.gz manifest.json; do
  install -o atlaso -g atlaso -m 0644 "$INVENTORY_SOURCE_DIR/$artifact" "$INVENTORY_TARGET_DIR/$artifact"
done
if [ ! -d "$INVENTORY_SOURCE_DIR/legal-info" ]; then
  echo "Bundled Atlaso Inventory Linux legal-info is missing." >&2
  exit 2
fi
install -d -o root -g root -m 0755 /usr/share/doc/atlaso/inventory-linux
rsync -a --delete "$INVENTORY_SOURCE_DIR/legal-info/" /usr/share/doc/atlaso/inventory-linux/
python3 - "$INVENTORY_TARGET_DIR" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
for name, expected in manifest["artifacts"].items():
    actual = hashlib.sha256((root / name).read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f"Atlaso Inventory Linux artifact digest mismatch: {name}")
PY

log_step "installing Atlaso Python environment"
install -d -o root -g root -m 0755 "$PIP_CACHE_DIR"
install -d -o root -g root -m 0755 "$ATLASO_HOME/releases"
if ! ATLASO_RELEASE_VERSION="$(
  python3 "$ATLASO_HOME/scripts/version.py" project-get --root "$ATLASO_HOME"
)"; then
  echo "Could not determine Atlaso release version from staged repository metadata" >&2
  exit 2
fi
ATLASO_RELEASE_DIR="$ATLASO_HOME/releases/bootstrap-$ATLASO_RELEASE_VERSION"
install -d -o root -g root -m 0755 "$ATLASO_RELEASE_DIR"
write_pip_config /etc/pip.conf
export HOME=/root
export PIP_CACHE_DIR
export PIP_DISABLE_PIP_VERSION_CHECK=1
if [ -n "$ATLASO_PIP_GLOBAL_INDEX_URL" ]; then
  export PIP_INDEX_URL="$ATLASO_PIP_GLOBAL_INDEX_URL"
fi

python3 -m venv "$ATLASO_RELEASE_DIR/.venv"
ATLASO_BOOTSTRAP_PYTHON_ABI="$(python3 -c 'import sys; print(f"cp{sys.version_info.major}{sys.version_info.minor}")')"
printf '{\n  "schema_version": 1,\n  "version": "%s",\n  "bootstrap": true,\n  "supported_python_abis": ["%s"]\n}\n' \
  "$ATLASO_RELEASE_VERSION" "$ATLASO_BOOTSTRAP_PYTHON_ABI" >"$ATLASO_RELEASE_DIR/bundle-metadata.json"
ln -sfn "releases/bootstrap-$ATLASO_RELEASE_VERSION" "$ATLASO_HOME/current"
ln -sfn "current/.venv" "$ATLASO_HOME/.venv"
write_pip_config "$ATLASO_HOME/.venv/pip.conf"
"$ATLASO_HOME/.venv/bin/python" -m pip install \
  --require-hashes \
  --requirement "$ATLASO_HOME/requirements-appliance.lock"
"$ATLASO_HOME/.venv/bin/python" -m pip install --no-deps "$ATLASO_HOME"
install -d -o root -g root -m 0755 /usr/local/bin
ln -sfn "$ATLASO_HOME/.venv/bin/atlaso-vault" /usr/local/bin/atlaso-vault
ln -sfn "$ATLASO_HOME/.venv/bin/atlaso-vault" /usr/bin/atlaso-vault
POWERSHELL_HOME="$(dirname "$(readlink -f "$(command -v pwsh)")")"
install -o root -g root -m 0644 \
  "$ATLASO_HOME/image/common/powershell/atlaso-vault-profile.ps1" \
  "$ATLASO_HOME/bin/atlaso-vault-profile.ps1"
touch "$POWERSHELL_HOME/profile.ps1"
if ! grep -qxF ". '/opt/atlaso/bin/atlaso-vault-profile.ps1'" "$POWERSHELL_HOME/profile.ps1"; then
  printf "\n. '/opt/atlaso/bin/atlaso-vault-profile.ps1'\n" >>"$POWERSHELL_HOME/profile.ps1"
fi
chown root:root "$POWERSHELL_HOME/profile.ps1"
chmod 0644 "$POWERSHELL_HOME/profile.ps1"
"$ATLASO_HOME/.venv/bin/python" "$ATLASO_HOME/scripts/check_photon_compatibility.py"
printf 'vcf_sdk=%s\n' "$("$ATLASO_HOME/.venv/bin/python" -c 'from importlib.metadata import version; print(version("vcf-sdk"))')" >>/etc/atlaso/build-info

log_step "writing third-party notices"
NOTICE_RPM_INVENTORY="$(mktemp)"
rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{LICENSE}\t%{URL}\n' | LC_ALL=C sort >"$NOTICE_RPM_INVENTORY"
install -d -o root -g root -m 0755 /usr/share/doc/atlaso
"$ATLASO_HOME/.venv/bin/python" "$ATLASO_HOME/scripts/generate_third_party_notices.py" \
  --version "$ATLASO_RELEASE_VERSION" \
  --output /usr/share/doc/atlaso/THIRD_PARTY_NOTICES.md \
  --lock "$ATLASO_HOME/requirements-appliance.lock" \
  --python-environment "$ATLASO_HOME/.venv" \
  --rpm-inventory "$NOTICE_RPM_INVENTORY"
rm -f "$NOTICE_RPM_INVENTORY"
chmod 0644 /usr/share/doc/atlaso/THIRD_PARTY_NOTICES.md

SECRET_KEY="$("$ATLASO_HOME/.venv/bin/python" -c 'import secrets; print(secrets.token_urlsafe(48))')"
SECRETS_KEY="$("$ATLASO_HOME/.venv/bin/python" -c 'import secrets; print(secrets.token_urlsafe(48))')"
cat >/etc/atlaso/atlaso.env <<EOF
ATLASO_ENVIRONMENT=appliance
ATLASO_DATABASE_URL=sqlite:////var/lib/atlaso/atlaso.db
ATLASO_SECRET_KEY=$SECRET_KEY
ATLASO_SECRETS_KEY=$SECRETS_KEY
ATLASO_BOOTSTRAP_ADMIN_USERNAME=$BOOTSTRAP_USERNAME
ATLASO_BOOTSTRAP_ADMIN_PASSWORD=$BOOTSTRAP_PASSWORD
ATLASO_DRY_RUN_SYSTEM_ADAPTERS=$ATLASO_DRY_RUN_SYSTEM_ADAPTERS
ATLASO_CONSOLE_REFRESH_SECONDS=5
ATLASO_REPOSITORY_PATH=/mnt/atlaso-vcf-offline-depot
ATLASO_VCF_BACKUP_PATH=/mnt/atlaso-vcf-backups
ATLASO_APPLIANCE_MANAGEMENT_CIDR=$ATLASO_MGMT_ADDRESS
ATLASO_APPLIANCE_EXTERNAL_DNS_SERVERS=$(if [ "$ATLASO_MGMT_USES_DHCP" = "true" ]; then printf ''; else printf '%s' "$ATLASO_MGMT_DNS" | tr ' ' ','; fi)
EOF
chmod 0640 /etc/atlaso/atlaso.env
chown root:atlaso /etc/atlaso/atlaso.env

install -o root -g root -m 0644 "$ATLASO_HOME/$ATLASO_IMAGE_ASSET_DIR/systemd/atlaso.service" /etc/systemd/system/atlaso.service
install -o root -g root -m 0644 "$ATLASO_HOME/image/common/systemd/atlaso-console.service" /etc/systemd/system/atlaso-console.service
install -o root -g root -m 0644 "$ATLASO_HOME/image/common/systemd/atlaso-worker.service" /etc/systemd/system/atlaso-worker.service
install -d -o root -g root -m 0755 /etc/systemd/system.conf.d
install -o root -g root -m 0644 "$ATLASO_HOME/image/common/systemd/atlaso-console-manager.conf" /etc/systemd/system.conf.d/atlaso-console.conf
install -o root -g root -m 0755 "$ATLASO_HOME/scripts/appliance/atlaso-helper" "$ATLASO_HOME/bin/atlaso-helper"
install -o root -g root -m 0755 "$ATLASO_HOME/scripts/appliance/atlaso-install-boot-branding" "$ATLASO_HOME/bin/atlaso-install-boot-branding"
install -o root -g root -m 0755 "$ATLASO_HOME/scripts/appliance/atlaso-mount-data-disks" "$ATLASO_HOME/bin/atlaso-mount-data-disks"
install -o root -g root -m 0755 "$ATLASO_HOME/scripts/appliance/atlaso-bootstrap-https" "$ATLASO_HOME/bin/atlaso-bootstrap-https"
trust_source_dir="$ATLASO_HOME/image/common/update-trust"
if [ ! -d "$trust_source_dir" ]; then
  echo "Atlaso release trust source directory is missing: $trust_source_dir" >&2
  exit 1
fi
install -d -o root -g root -m 0755 /etc/atlaso/update-trust.d
trust_key_count=0
for trust_key in "$trust_source_dir"/*.pem; do
  [ -f "$trust_key" ] || continue
  if ! trust_key_details="$(openssl pkey -pubin -in "$trust_key" -text -noout 2>/dev/null)"; then
    echo "Atlaso release trust key is not a valid public key: $trust_key" >&2
    exit 1
  fi
  case "$trust_key_details" in
    *ED25519*) ;;
    *)
      echo "Atlaso release trust key is not Ed25519: $trust_key" >&2
      exit 1
      ;;
  esac
  install -o root -g root -m 0644 "$trust_key" "/etc/atlaso/update-trust.d/$(basename "$trust_key")"
  trust_key_count=$((trust_key_count + 1))
done
if [ "$trust_key_count" -eq 0 ]; then
  echo "No Atlaso release trust keys were staged under $trust_source_dir" >&2
  exit 1
fi
if [ "$ATLASO_GUEST_PLATFORM" = "vmware" ]; then
  install -o root -g root -m 0755 "$ATLASO_HOME/scripts/appliance/atlaso-vmware-ovf-customize.py" "$ATLASO_HOME/bin/atlaso-vmware-ovf-customize.py"
  install -o root -g root -m 0644 "$ATLASO_HOME/$ATLASO_IMAGE_ASSET_DIR/systemd/atlaso-vmware-ovf-customize.service" /etc/systemd/system/atlaso-vmware-ovf-customize.service
fi
install -o root -g root -m 0440 "$ATLASO_HOME/$ATLASO_IMAGE_ASSET_DIR/sudoers.d/atlaso-helper" /etc/sudoers.d/atlaso-helper
sed -i 's/\r$//' /etc/systemd/system/atlaso.service /etc/systemd/system/atlaso-worker.service /etc/systemd/system/atlaso-console.service /etc/systemd/system.conf.d/atlaso-console.conf "$ATLASO_HOME/bin/atlaso-helper" "$ATLASO_HOME/bin/atlaso-install-boot-branding" "$ATLASO_HOME/bin/atlaso-mount-data-disks" "$ATLASO_HOME/bin/atlaso-bootstrap-https" /etc/sudoers.d/atlaso-helper
if [ "$ATLASO_GUEST_PLATFORM" = "vmware" ]; then
  sed -i 's/\r$//' "$ATLASO_HOME/bin/atlaso-vmware-ovf-customize.py" /etc/systemd/system/atlaso-vmware-ovf-customize.service
fi
visudo -cf /etc/sudoers.d/atlaso-helper

chown -R root:root "$ATLASO_HOME"
chmod 0755 /opt "$ATLASO_HOME"
find "$ATLASO_HOME/atlaso" "$ATLASO_HOME/scripts" "$ATLASO_HOME/image" -type d -exec chmod 0755 {} +
find "$ATLASO_HOME/atlaso" "$ATLASO_HOME/scripts" "$ATLASO_HOME/image" -type f -exec chmod 0644 {} +
find "$ATLASO_RELEASE_DIR/.venv" -type d -exec chmod 0755 {} +
find "$ATLASO_RELEASE_DIR/.venv" -type f -exec chmod u+rw,go+r {} +
find "$ATLASO_RELEASE_DIR/.venv/bin" -type f -exec chmod a+rx {} +
chmod 0755 "$ATLASO_HOME/bin" "$ATLASO_HOME/bin/atlaso-helper" "$ATLASO_HOME/bin/atlaso-install-boot-branding"
"$ATLASO_HOME/bin/atlaso-install-boot-branding" \
  "$ATLASO_HOME/image/common/boot/grub/theme.txt" \
  "$ATLASO_HOME/image/common/boot/grub/atlaso.png"
cat >/etc/ssh/sshd_config.d/atlaso-root-login.conf <<'EOF'
# Managed by Atlaso. Local changes may be overwritten by Appliance Settings apply.
PermitRootLogin no
EOF
chmod 0644 /etc/ssh/sshd_config.d/atlaso-root-login.conf
cat >/etc/systemd/system/atlaso-data-disks.service <<'EOF'
[Unit]
Description=Prepare Atlaso data disks
After=systemd-udev-settle.service
Wants=systemd-udev-settle.service
Before=atlaso-bootstrap-https.service atlaso.service

[Service]
Type=oneshot
ExecStart=/opt/atlaso/bin/atlaso-mount-data-disks
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 /etc/systemd/system/atlaso-data-disks.service
cat >/etc/systemd/system/atlaso-bootstrap-https.service <<'EOF'
[Unit]
Description=Bootstrap Atlaso first-boot HTTPS front door
After=network-online.target atlaso-data-disks.service atlaso-vmware-ovf-customize.service
Wants=network-online.target atlaso-data-disks.service
Before=nginx.service atlaso.service
ConditionPathExists=!/var/lib/atlaso/first-boot-https.applied

[Service]
Type=oneshot
EnvironmentFile=/etc/atlaso/atlaso.env
ExecStart=/opt/atlaso/.venv/bin/python /opt/atlaso/bin/atlaso-bootstrap-https
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 /etc/systemd/system/atlaso-bootstrap-https.service
chown -R atlaso:atlaso "$ATLASO_STATE" "$ATLASO_LOG"
chmod 0711 "$ATLASO_STATE"
if id "$BOOTSTRAP_USERNAME" >/dev/null 2>&1 && [ -d "$ATLASO_STATE/users/$BOOTSTRAP_USERNAME" ]; then
  chown "$BOOTSTRAP_USERNAME:$(id -gn "$BOOTSTRAP_USERNAME")" "$ATLASO_STATE/users/$BOOTSTRAP_USERNAME"
  chmod 0750 "$ATLASO_STATE/users/$BOOTSTRAP_USERNAME"
fi

log_step "configuring final appliance management network"
{
  printf '[Match]\n'
  printf 'Name=%s\n\n' "$ATLASO_MGMT_INTERFACE"
  printf '[Network]\n'
  if [ "$ATLASO_MGMT_USES_DHCP" = "true" ]; then
    printf 'DHCP=ipv4\n'
  else
    printf 'Address=%s\n' "$ATLASO_MGMT_ADDRESS"
    if [ -n "$ATLASO_MGMT_GATEWAY" ]; then
      printf 'Gateway=%s\n' "$ATLASO_MGMT_GATEWAY"
    fi
    for dns_server in $ATLASO_MGMT_DNS; do
      printf 'DNS=%s\n' "$dns_server"
    done
  fi
} >/etc/systemd/network/00-atlaso-mgmt.network
chmod 0644 /etc/systemd/network/00-atlaso-mgmt.network
rm -f /etc/systemd/network/50-static-en.network /etc/systemd/network/99-dhcp-en.network

if [ "$ATLASO_MGMT_USES_DHCP" != "true" ] && [ -n "$ATLASO_MGMT_DNS" ]; then
  {
    for dns_server in $ATLASO_MGMT_DNS; do
      printf 'nameserver %s\n' "$dns_server"
    done
  } >/etc/resolv.conf
  chmod 0644 /etc/resolv.conf
fi

log_step "configuring first-boot Atlaso management nginx bootstrap"
install -d -o root -g root -m 0755 /etc/nginx/conf.d
rm -f /etc/nginx/conf.d/default.conf /etc/nginx/conf.d/default_server.conf
cat >/etc/nginx/conf.d/atlaso.conf <<'EOF'
# Managed by Atlaso. Local changes may be overwritten.
include /etc/atlaso/nginx/sites.d/*.conf;
EOF
chmod 0644 /etc/nginx/conf.d/atlaso.conf
if [ -f /etc/nginx/nginx.conf ] &&
  ! grep -Eq 'include[[:space:]]+/etc/nginx/conf\.d/\*\.conf;' /etc/nginx/nginx.conf &&
  ! grep -Fq '/etc/nginx/conf.d/atlaso.conf' /etc/nginx/nginx.conf; then
  python3 - <<'PY'
from pathlib import Path

path = Path("/etc/nginx/nginx.conf")
text = path.read_text(encoding="utf-8")
start = text.find("http")
brace = text.find("{", start)
if start >= 0 and brace >= 0:
    depth = 1
    index = brace + 1
    while index < len(text):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                include = "\n    # Managed by Atlaso. Local changes may be overwritten.\n    include /etc/nginx/conf.d/atlaso.conf;\n"
                text = text[:index].rstrip() + include + text[index:]
                path.write_text(text, encoding="utf-8")
                break
        index += 1
PY
fi
nginx -t

log_step "enabling appliance services"
systemctl daemon-reexec
systemctl daemon-reload
systemctl enable systemd-networkd
systemctl enable systemd-resolved || true
systemctl enable sshd
if [ "$ATLASO_GUEST_PLATFORM" = "hyperv" ]; then
  systemctl enable --now hv_kvp_daemon || true
  systemctl enable --now hv_fcopy_daemon || true
  systemctl enable --now hv_vss_daemon || true
elif [ "$ATLASO_GUEST_PLATFORM" = "vmware" ]; then
  systemctl enable --now vmtoolsd || true
  systemctl enable atlaso-vmware-ovf-customize.service
fi
systemctl enable atlaso-data-disks.service
systemctl enable atlaso-bootstrap-https.service
systemctl enable atlaso
systemctl enable atlaso-worker.service
systemctl mask getty@tty1.service
systemctl mask --force ctrl-alt-del.target
systemctl enable atlaso-console.service
systemctl enable --now nginx

log_step "configuring Atlaso nftables firewall"
if [ -z "$ATLASO_MGMT_SOURCE_CIDR" ]; then
  DETECTED_MGMT_ADDRESS="$(ip -4 -o addr show dev "$ATLASO_MGMT_INTERFACE" scope global 2>/dev/null | awk 'NR == 1 { print $4 }')"
  if [ -n "$DETECTED_MGMT_ADDRESS" ]; then
    ATLASO_MGMT_SOURCE_CIDR="$(python3 -c 'import ipaddress, sys; print(ipaddress.ip_interface(sys.argv[1]).network)' "$DETECTED_MGMT_ADDRESS")"
  fi
fi
if [ -z "$ATLASO_MGMT_SOURCE_CIDR" ] && [ "$ATLASO_MGMT_ADDRESS" != "dhcp" ]; then
  ATLASO_MGMT_SOURCE_CIDR="$(python3 -c 'import ipaddress, sys; print(ipaddress.ip_interface(sys.argv[1]).network)' "$ATLASO_MGMT_ADDRESS")"
fi
if [ -n "$ATLASO_MGMT_SOURCE_CIDR" ]; then
  printf '\nATLASO_MANAGEMENT_SOURCE_CIDR=%s\n' "$ATLASO_MGMT_SOURCE_CIDR" >>/etc/atlaso/atlaso.env
  ATLASO_MGMT_ACCESS_RULE="    ip saddr $ATLASO_MGMT_SOURCE_CIDR tcp dport { 22, 80, 443 } accept comment \"Atlaso management access\""
else
  ATLASO_MGMT_ACCESS_RULE="    iifname \"$ATLASO_MGMT_INTERFACE\" tcp dport { 22, 80, 443 } accept comment \"Atlaso management access\""
fi
install -d -o root -g root -m 0755 /etc/atlaso/nftables.d
cat >/etc/atlaso/nftables.d/atlaso.nft <<EOF
# Managed by Atlaso. Local changes may be overwritten.
# nftables firewall state for Photon OS appliance images.
flush ruleset
table inet atlaso {
  chain input {
    type filter hook input priority filter; policy drop;
    iifname "lo" accept comment "Atlaso loopback"
    ct state established,related accept comment "Atlaso established traffic"
$ATLASO_MGMT_ACCESS_RULE
    meta l4proto icmp accept comment "Atlaso ICMP diagnostics"
    meta l4proto ipv6-icmp accept comment "Atlaso IPv6 ICMP diagnostics"
  }
  chain forward {
    type filter hook forward priority filter; policy drop;
    ct state established,related accept comment "Atlaso established traffic"
    meta l4proto icmp accept comment "Atlaso ICMP diagnostics"
    meta l4proto ipv6-icmp accept comment "Atlaso IPv6 ICMP diagnostics"
  }
  chain output {
    type filter hook output priority filter; policy accept;
    ct state established,related accept comment "Atlaso established traffic"
    meta l4proto icmp accept comment "Atlaso ICMP diagnostics"
    meta l4proto ipv6-icmp accept comment "Atlaso IPv6 ICMP diagnostics"
  }
}
EOF
chmod 0644 /etc/atlaso/nftables.d/atlaso.nft
cat >/etc/systemd/system/atlaso-firewall.service <<'EOF'
[Unit]
Description=Atlaso nftables firewall
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f /etc/atlaso/nftables.d/atlaso.nft
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now atlaso-firewall.service
if command -v iptables >/dev/null 2>&1; then
  iptables -P INPUT ACCEPT || true
  iptables -P FORWARD ACCEPT || true
  iptables -P OUTPUT ACCEPT || true
  iptables -F || true
  iptables -X || true
fi
systemctl disable --now iptables || true

log_step "running Photon compatibility check"
"$ATLASO_HOME/.venv/bin/python" "$ATLASO_HOME/scripts/check_photon_compatibility.py"
