#!/bin/sh
set -eu

LABFOUNDRY_SRC="${LABFOUNDRY_SRC:-/tmp/labfoundry-src}"
LABFOUNDRY_HOME="${LABFOUNDRY_HOME:-/opt/labfoundry}"
LABFOUNDRY_STATE="${LABFOUNDRY_STATE:-/var/lib/labfoundry}"
LABFOUNDRY_LOG="${LABFOUNDRY_LOG:-/var/log/labfoundry}"
LABFOUNDRY_MGMT_ADDRESS="${LABFOUNDRY_MGMT_ADDRESS:-192.168.49.1/24}"
LABFOUNDRY_MGMT_GATEWAY="${LABFOUNDRY_MGMT_GATEWAY:-192.168.49.254}"
LABFOUNDRY_MGMT_SOURCE_CIDR="${LABFOUNDRY_MGMT_SOURCE_CIDR:-}"
LABFOUNDRY_MGMT_DNS="${LABFOUNDRY_MGMT_DNS:-1.1.1.1 9.9.9.9}"
LABFOUNDRY_MGMT_INTERFACE="${LABFOUNDRY_MGMT_INTERFACE:-eth0}"
LABFOUNDRY_MGMT_IPV4_METHOD="${LABFOUNDRY_MGMT_IPV4_METHOD:-}"
LABFOUNDRY_MGMT_USES_DHCP=false
if [ "$LABFOUNDRY_MGMT_ADDRESS" = "dhcp" ] || [ "$LABFOUNDRY_MGMT_IPV4_METHOD" = "dhcp" ]; then
  LABFOUNDRY_MGMT_USES_DHCP=true
fi
LABFOUNDRY_DRY_RUN_SYSTEM_ADAPTERS="${LABFOUNDRY_DRY_RUN_SYSTEM_ADAPTERS:-true}"
LABFOUNDRY_GUEST_PLATFORM="${LABFOUNDRY_GUEST_PLATFORM:-hyperv}"
LABFOUNDRY_IMAGE_ASSET_DIR="${LABFOUNDRY_IMAGE_ASSET_DIR:-image/hyperv}"
LABFOUNDRY_PIP_GLOBAL_INDEX="${LABFOUNDRY_PIP_GLOBAL_INDEX:-}"
LABFOUNDRY_PIP_GLOBAL_INDEX_URL="${LABFOUNDRY_PIP_GLOBAL_INDEX_URL:-}"
LABFOUNDRY_POWERCLI_MODULE_SOURCE="${LABFOUNDRY_POWERCLI_MODULE_SOURCE:-}"
LABFOUNDRY_POWERCLI_VERSION="${LABFOUNDRY_POWERCLI_VERSION:-9.1.0.25380678}"
BOOTSTRAP_USERNAME="${LABFOUNDRY_BOOTSTRAP_ADMIN_USERNAME:-admin}"
BOOTSTRAP_PASSWORD="${LABFOUNDRY_BOOTSTRAP_ADMIN_PASSWORD:-}"
BOOTSTRAP_SHELL="${LABFOUNDRY_BOOTSTRAP_ADMIN_SHELL:-/usr/bin/pwsh}"
PIP_CACHE_DIR="${PIP_CACHE_DIR:-/var/cache/labfoundry-pip}"
TDNF_PROGRESS_RUNNER="$LABFOUNDRY_SRC/scripts/run_tdnf_with_progress.py"

log_step() {
  printf '\n==> LabFoundry appliance: %s\n' "$1"
}

write_pip_config() {
  path="$1"

  if [ -z "$LABFOUNDRY_PIP_GLOBAL_INDEX" ] && [ -z "$LABFOUNDRY_PIP_GLOBAL_INDEX_URL" ]; then
    return
  fi

  install -d -o root -g root -m 0755 "$(dirname "$path")"
  {
    printf '[global]\n'
    if [ -n "$LABFOUNDRY_PIP_GLOBAL_INDEX" ]; then
      printf 'index = %s\n' "$LABFOUNDRY_PIP_GLOBAL_INDEX"
    fi
    if [ -n "$LABFOUNDRY_PIP_GLOBAL_INDEX_URL" ]; then
      printf 'index-url = %s\n' "$LABFOUNDRY_PIP_GLOBAL_INDEX_URL"
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
  echo "LABFOUNDRY_BOOTSTRAP_ADMIN_PASSWORD is required for appliance provisioning" >&2
  exit 2
fi
if [ ! -r "$TDNF_PROGRESS_RUNNER" ]; then
  echo "TDNF progress runner is missing from staged LabFoundry sources: $TDNF_PROGRESS_RUNNER" >&2
  exit 2
fi

log_step "system adapter dry-run mode: $LABFOUNDRY_DRY_RUN_SYSTEM_ADAPTERS"
log_step "guest platform: $LABFOUNDRY_GUEST_PLATFORM"

log_step "refreshing Photon package metadata"
tdnf -y clean all || true
run_tdnf "Photon package metadata refresh" makecache

log_step "applying Photon OS updates"
run_tdnf "Photon OS update" update

log_step "installing Photon appliance packages"
GUEST_INTEGRATION_PACKAGES=""
case "$LABFOUNDRY_GUEST_PLATFORM" in
  hyperv)
    GUEST_INTEGRATION_PACKAGES="hyper-v"
    ;;
  vmware)
    GUEST_INTEGRATION_PACKAGES="open-vm-tools"
    ;;
  *)
    echo "Unsupported LABFOUNDRY_GUEST_PLATFORM: $LABFOUNDRY_GUEST_PLATFORM" >&2
    exit 2
    ;;
esac
run_tdnf "Photon appliance package installation" \
  install python3 python3-pip python3-devel python3-virtualenv python3-curses python3-ntp sudo openssh-server curl rsync tar gzip shadow e2fsprogs sqlite procps-ng $GUEST_INTEGRATION_PACKAGES nftables dnsmasq ntpsec nfs-utils rpcbind openldap openldap-servers ipxe syslinux nginx powershell

log_step "installing VCF PowerCLI $LABFOUNDRY_POWERCLI_VERSION"
export LABFOUNDRY_POWERCLI_VERSION
if [ -n "$LABFOUNDRY_POWERCLI_MODULE_SOURCE" ]; then
  if [ ! -d "$LABFOUNDRY_POWERCLI_MODULE_SOURCE" ]; then
    echo "LABFOUNDRY_POWERCLI_MODULE_SOURCE must be a directory containing an offline PowerShell module bundle" >&2
    exit 2
  fi
  install -d -o root -g root -m 0755 /usr/local/share/powershell/Modules
  cp -R "$LABFOUNDRY_POWERCLI_MODULE_SOURCE"/. /usr/local/share/powershell/Modules/
else
  pwsh -NoLogo -NoProfile -NonInteractive -Command \
    '$ErrorActionPreference = "Stop"; Set-PSRepository -Name PSGallery -InstallationPolicy Trusted; try { Install-Module -Name VCF.PowerCLI -RequiredVersion $env:LABFOUNDRY_POWERCLI_VERSION -Repository PSGallery -Scope AllUsers -Force -AllowClobber -AcceptLicense -Confirm:$false } finally { Set-PSRepository -Name PSGallery -InstallationPolicy Untrusted }'
fi
chmod 0755 /usr/local/share/powershell /usr/local/share/powershell/Modules
chmod -R a+rX,go-w /usr/local/share/powershell/Modules
pwsh -NoLogo -NoProfile -NonInteractive -Command \
  '$ErrorActionPreference = "Stop"; $module = Get-Module -Name VCF.PowerCLI -ListAvailable | Where-Object Version -eq $env:LABFOUNDRY_POWERCLI_VERSION | Select-Object -First 1; if (-not $module) { throw "VCF.PowerCLI $env:LABFOUNDRY_POWERCLI_VERSION is not installed" }; Import-Module $module.Path -Force; Set-PowerCLIConfiguration -ParticipateInCeip $false -Scope AllUsers -Confirm:$false | Out-Null; $configured = Get-PowerCLIConfiguration -Scope AllUsers; if ([bool]$configured.ParticipateInCEIP) { throw "VCF.PowerCLI CEIP default was not disabled" }; if (-not (Get-Command Connect-VIServer -ErrorAction SilentlyContinue)) { throw "Connect-VIServer is not available" }; Write-Host "VCF.PowerCLI $($module.Version) verified with appliance-wide CEIP disabled"'

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
cat > /etc/udev/rules.d/99-labfoundry-disk-identity.rules <<'EOF'
# Some virtual SCSI controllers do not expose a serial/WWN. Preserve a stable
# controller-path identity under /dev/disk/by-id so LabFoundry never claims a
# transient /dev/sdX name. Native serial/WWN identities remain preferred.
SUBSYSTEM=="block", ENV{DEVTYPE}=="disk", ENV{ID_SERIAL}=="", IMPORT{builtin}="path_id", ENV{ID_PATH_TAG}=="?*", SYMLINK+="disk/by-id/labfoundry-path-$env{ID_PATH_TAG}"
EOF
udevadm control --reload-rules
udevadm trigger --subsystem-match=block --action=add

log_step "disabling systemd SSH-over-vsock auto generator"
if [ "$LABFOUNDRY_GUEST_PLATFORM" = "hyperv" ]; then
  install -d -o root -g root -m 0755 /etc/systemd/system-generators
  ln -sfn /dev/null /etc/systemd/system-generators/systemd-ssh-generator
fi

if ! getent group labfoundry >/dev/null 2>&1; then
  groupadd --system labfoundry
fi

if ! id labfoundry >/dev/null 2>&1; then
  useradd --system --gid labfoundry --home-dir "$LABFOUNDRY_STATE" --shell /sbin/nologin labfoundry
fi
if ! getent group labfoundry-automation >/dev/null 2>&1; then
  groupadd --system labfoundry-automation
fi
if ! id labfoundry-automation >/dev/null 2>&1; then
  useradd --system --gid labfoundry-automation --home-dir "$LABFOUNDRY_STATE/automation" --shell /sbin/nologin labfoundry-automation
fi
usermod -a -G labfoundry-automation labfoundry

install -d -o root -g root -m 0755 "$LABFOUNDRY_HOME"
install -d -o labfoundry -g labfoundry -m 0750 "$LABFOUNDRY_STATE"
install -d -o labfoundry -g labfoundry -m 0750 "$LABFOUNDRY_STATE/apply/firewall"
install -d -o labfoundry -g labfoundry -m 0750 "$LABFOUNDRY_STATE/apply/dnsmasq"
install -d -o labfoundry -g labfoundry -m 0750 "$LABFOUNDRY_STATE/apply/kms"
install -d -o labfoundry -g labfoundry -m 0750 "$LABFOUNDRY_STATE/apply/ldap"
install -d -o labfoundry -g labfoundry -m 0750 "$LABFOUNDRY_STATE/apply/local-users"
install -d -o labfoundry -g labfoundry -m 0750 "$LABFOUNDRY_STATE/apply/ntpd"
install -d -o labfoundry -g labfoundry -m 0750 "$LABFOUNDRY_STATE/apply/esx-storage"
install -d -o labfoundry -g labfoundry -m 0750 "$LABFOUNDRY_STATE/apply/vcf-backups"
install -d -o labfoundry -g labfoundry -m 0750 "$LABFOUNDRY_STATE/apply/vcf-offline-depot"
install -d -o labfoundry -g labfoundry -m 0750 "$LABFOUNDRY_STATE/vcfDownloadTool/active-tool"
install -d -o labfoundry -g labfoundry -m 0700 "$LABFOUNDRY_STATE/vcfDownloadTool/active-tool/secrets"
install -d -o labfoundry -g labfoundry -m 0750 "$LABFOUNDRY_STATE/dnsmasq"
install -d -o labfoundry -g labfoundry -m 0750 "$LABFOUNDRY_STATE/kms"
install -d -o labfoundry -g labfoundry -m 0700 "$LABFOUNDRY_STATE/ldap/recovery"
install -d -o root -g root -m 0755 "$LABFOUNDRY_STATE/users"
install -d -o labfoundry -g labfoundry-automation -m 0750 "$LABFOUNDRY_STATE/automation"
install -d -o labfoundry -g labfoundry-automation -m 0750 "$LABFOUNDRY_STATE/automation/scripts"
install -d -o labfoundry-automation -g labfoundry-automation -m 0750 "$LABFOUNDRY_STATE/automation/runs"
install -d -o labfoundry -g labfoundry -m 0750 "$LABFOUNDRY_LOG"
install -d -o root -g root -m 0755 /mnt/labfoundry-esx-storage /srv/labfoundry/esx-storage /etc/exports.d /etc/nfs.conf.d
install -d -o labfoundry -g labfoundry -m 0750 "$LABFOUNDRY_LOG/kms"
install -d -o root -g root -m 0755 /etc/labfoundry
install -d -o root -g root -m 0755 /etc/labfoundry/dnsmasq.d
install -d -o root -g root -m 0755 /etc/labfoundry/kms
install -d -o root -g root -m 0755 /etc/labfoundry/kms/policies
install -d -o root -g root -m 0755 /etc/labfoundry/ldap/tls
install -d -o root -g root -m 0755 /etc/pykmip
install -d -o root -g root -m 0755 /etc/labfoundry/nginx/sites.d
install -d -o root -g root -m 0755 /etc/labfoundry/ssh/authorized_keys
install -d -o root -g root -m 0755 /etc/ssh/sshd_config.d
install -d -o root -g root -m 0755 /etc/systemd/network
install -d -o root -g root -m 0755 /usr/local/lib/labfoundry
install -d -o root -g root -m 0755 /mnt/labfoundry-vcf-backups
install -d -o root -g root -m 0755 /mnt/labfoundry-vcf-registry
install -d -o labfoundry -g labfoundry -m 0755 /mnt/labfoundry-vcf-offline-depot

if ! id "$BOOTSTRAP_USERNAME" >/dev/null 2>&1; then
  useradd --home-dir "$LABFOUNDRY_STATE/users/$BOOTSTRAP_USERNAME" --create-home --shell "$BOOTSTRAP_SHELL" "$BOOTSTRAP_USERNAME"
else
  usermod --shell "$BOOTSTRAP_SHELL" "$BOOTSTRAP_USERNAME"
fi
touch /etc/shells
grep -qxF "$BOOTSTRAP_SHELL" /etc/shells || printf '%s\n' "$BOOTSTRAP_SHELL" >>/etc/shells
printf '%s:%s\n' "$BOOTSTRAP_USERNAME" "$BOOTSTRAP_PASSWORD" | chpasswd
cat >/etc/sudoers.d/labfoundry-bootstrap-admin <<EOF
# Managed by LabFoundry image provisioning. Bootstrap appliance administrator.
$BOOTSTRAP_USERNAME ALL=(ALL) ALL
EOF
chmod 0440 /etc/sudoers.d/labfoundry-bootstrap-admin
visudo -cf /etc/sudoers.d/labfoundry-bootstrap-admin
sudo -H -u "$BOOTSTRAP_USERNAME" env -u PSModulePath LABFOUNDRY_POWERCLI_VERSION="$LABFOUNDRY_POWERCLI_VERSION" \
  pwsh -NoLogo -NoProfile -NonInteractive -Command \
  '$ErrorActionPreference = "Stop"; $module = Get-Module -Name VCF.PowerCLI -ListAvailable | Where-Object Version -eq $env:LABFOUNDRY_POWERCLI_VERSION | Select-Object -First 1; if (-not $module) { throw "VCF.PowerCLI $env:LABFOUNDRY_POWERCLI_VERSION is not available to the bootstrap administrator" }; Import-Module $module.Path -Force; $configured = Get-PowerCLIConfiguration -Scope AllUsers; if ([bool]$configured.ParticipateInCEIP) { throw "VCF.PowerCLI CEIP default is not disabled for the bootstrap administrator" }; if (-not (Get-Command Connect-VIServer -ErrorAction SilentlyContinue)) { throw "Connect-VIServer is not available to the bootstrap administrator" }; Write-Host "VCF.PowerCLI $($module.Version) verified as $([Environment]::UserName) with appliance-wide CEIP disabled"'

cat >/etc/labfoundry/build-info <<EOF
build_time_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
photon_release=$(cat /etc/photon-release 2>/dev/null || true)
kernel=$(uname -r)
python=$(python3 --version 2>&1)
powershell=$(pwsh -NoLogo -NoProfile -NonInteractive -Command '$PSVersionTable.PSVersion.ToString()')
powercli=$(pwsh -NoLogo -NoProfile -NonInteractive -Command '(Get-Module -Name VCF.PowerCLI -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1).Version.ToString()')
package_update=tdnf -y update completed during image provisioning
final_mgmt_address=$LABFOUNDRY_MGMT_ADDRESS
final_mgmt_gateway=$LABFOUNDRY_MGMT_GATEWAY
final_mgmt_interface=$LABFOUNDRY_MGMT_INTERFACE
EOF
chmod 0644 /etc/labfoundry/build-info

rm -f /etc/sudoers.d/90-labfoundry-build

log_step "syncing LabFoundry application files"
rsync -a --delete \
  --exclude ".git" \
  --exclude ".venv" \
  --exclude ".pytest_cache" \
  --exclude "data" \
  --exclude "test-results" \
  "$LABFOUNDRY_SRC"/ "$LABFOUNDRY_HOME"/

install -d -o root -g root -m 0755 "$LABFOUNDRY_HOME/bin"

IPXE_BOOTLOADER_SOURCE_DIR="$LABFOUNDRY_HOME/third_party/ipxe/bootloaders"
IPXE_BOOTLOADER_TARGET_DIR="$LABFOUNDRY_STATE/pxe/bootloaders"
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

log_step "installing LabFoundry Python environment"
install -d -o root -g root -m 0755 "$PIP_CACHE_DIR"
install -d -o root -g root -m 0755 "$LABFOUNDRY_HOME/releases"
if ! LABFOUNDRY_RELEASE_VERSION="$(
  python3 "$LABFOUNDRY_HOME/scripts/version.py" project-get --root "$LABFOUNDRY_HOME"
)"; then
  echo "Could not determine LabFoundry release version from staged repository metadata" >&2
  exit 2
fi
LABFOUNDRY_RELEASE_DIR="$LABFOUNDRY_HOME/releases/bootstrap-$LABFOUNDRY_RELEASE_VERSION"
install -d -o root -g root -m 0755 "$LABFOUNDRY_RELEASE_DIR"
write_pip_config /etc/pip.conf
export HOME=/root
export PIP_CACHE_DIR
export PIP_DISABLE_PIP_VERSION_CHECK=1
if [ -n "$LABFOUNDRY_PIP_GLOBAL_INDEX_URL" ]; then
  export PIP_INDEX_URL="$LABFOUNDRY_PIP_GLOBAL_INDEX_URL"
fi

python3 -m venv "$LABFOUNDRY_RELEASE_DIR/.venv"
LABFOUNDRY_BOOTSTRAP_PYTHON_ABI="$(python3 -c 'import sys; print(f"cp{sys.version_info.major}{sys.version_info.minor}")')"
printf '{\n  "schema_version": 1,\n  "version": "%s",\n  "bootstrap": true,\n  "supported_python_abis": ["%s"]\n}\n' \
  "$LABFOUNDRY_RELEASE_VERSION" "$LABFOUNDRY_BOOTSTRAP_PYTHON_ABI" >"$LABFOUNDRY_RELEASE_DIR/bundle-metadata.json"
ln -sfn "releases/bootstrap-$LABFOUNDRY_RELEASE_VERSION" "$LABFOUNDRY_HOME/current"
ln -sfn "current/.venv" "$LABFOUNDRY_HOME/.venv"
write_pip_config "$LABFOUNDRY_HOME/.venv/pip.conf"
"$LABFOUNDRY_HOME/.venv/bin/python" -m pip install \
  --require-hashes \
  --requirement "$LABFOUNDRY_HOME/requirements-appliance.lock"
"$LABFOUNDRY_HOME/.venv/bin/python" -m pip install --no-deps "$LABFOUNDRY_HOME"
"$LABFOUNDRY_HOME/.venv/bin/python" "$LABFOUNDRY_HOME/scripts/check_photon_compatibility.py"
printf 'vcf_sdk=%s\n' "$("$LABFOUNDRY_HOME/.venv/bin/python" -c 'from importlib.metadata import version; print(version("vcf-sdk"))')" >>/etc/labfoundry/build-info

log_step "writing third-party notices"
NOTICE_RPM_INVENTORY="$(mktemp)"
rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{LICENSE}\t%{URL}\n' | LC_ALL=C sort >"$NOTICE_RPM_INVENTORY"
install -d -o root -g root -m 0755 /usr/share/doc/labfoundry
"$LABFOUNDRY_HOME/.venv/bin/python" "$LABFOUNDRY_HOME/scripts/generate_third_party_notices.py" \
  --version "$LABFOUNDRY_RELEASE_VERSION" \
  --output /usr/share/doc/labfoundry/THIRD_PARTY_NOTICES.md \
  --lock "$LABFOUNDRY_HOME/requirements-appliance.lock" \
  --python-environment "$LABFOUNDRY_HOME/.venv" \
  --rpm-inventory "$NOTICE_RPM_INVENTORY"
rm -f "$NOTICE_RPM_INVENTORY"
chmod 0644 /usr/share/doc/labfoundry/THIRD_PARTY_NOTICES.md

SECRET_KEY="$("$LABFOUNDRY_HOME/.venv/bin/python" -c 'import secrets; print(secrets.token_urlsafe(48))')"
SECRETS_KEY="$("$LABFOUNDRY_HOME/.venv/bin/python" -c 'import secrets; print(secrets.token_urlsafe(48))')"
cat >/etc/labfoundry/labfoundry.env <<EOF
LABFOUNDRY_ENVIRONMENT=appliance
LABFOUNDRY_DATABASE_URL=sqlite:////var/lib/labfoundry/labfoundry.db
LABFOUNDRY_SECRET_KEY=$SECRET_KEY
LABFOUNDRY_SECRETS_KEY=$SECRETS_KEY
LABFOUNDRY_BOOTSTRAP_ADMIN_USERNAME=$BOOTSTRAP_USERNAME
LABFOUNDRY_BOOTSTRAP_ADMIN_PASSWORD=$BOOTSTRAP_PASSWORD
LABFOUNDRY_DRY_RUN_SYSTEM_ADAPTERS=$LABFOUNDRY_DRY_RUN_SYSTEM_ADAPTERS
LABFOUNDRY_CONSOLE_REFRESH_SECONDS=5
LABFOUNDRY_REPOSITORY_PATH=/mnt/labfoundry-vcf-offline-depot
LABFOUNDRY_VCF_BACKUP_PATH=/mnt/labfoundry-vcf-backups
LABFOUNDRY_APPLIANCE_MANAGEMENT_CIDR=$LABFOUNDRY_MGMT_ADDRESS
LABFOUNDRY_APPLIANCE_EXTERNAL_DNS_SERVERS=$(if [ "$LABFOUNDRY_MGMT_USES_DHCP" = "true" ]; then printf ''; else printf '%s' "$LABFOUNDRY_MGMT_DNS" | tr ' ' ','; fi)
EOF
chmod 0640 /etc/labfoundry/labfoundry.env
chown root:labfoundry /etc/labfoundry/labfoundry.env

install -o root -g root -m 0644 "$LABFOUNDRY_HOME/$LABFOUNDRY_IMAGE_ASSET_DIR/systemd/labfoundry.service" /etc/systemd/system/labfoundry.service
install -o root -g root -m 0644 "$LABFOUNDRY_HOME/image/common/systemd/labfoundry-console.service" /etc/systemd/system/labfoundry-console.service
install -o root -g root -m 0644 "$LABFOUNDRY_HOME/image/common/systemd/labfoundry-worker.service" /etc/systemd/system/labfoundry-worker.service
install -d -o root -g root -m 0755 /etc/systemd/system.conf.d
install -o root -g root -m 0644 "$LABFOUNDRY_HOME/image/common/systemd/labfoundry-console-manager.conf" /etc/systemd/system.conf.d/labfoundry-console.conf
install -o root -g root -m 0755 "$LABFOUNDRY_HOME/scripts/appliance/labfoundry-helper" "$LABFOUNDRY_HOME/bin/labfoundry-helper"
install -o root -g root -m 0755 "$LABFOUNDRY_HOME/scripts/appliance/labfoundry-install-boot-branding" "$LABFOUNDRY_HOME/bin/labfoundry-install-boot-branding"
install -o root -g root -m 0755 "$LABFOUNDRY_HOME/scripts/appliance/labfoundry-mount-data-disks" "$LABFOUNDRY_HOME/bin/labfoundry-mount-data-disks"
install -o root -g root -m 0755 "$LABFOUNDRY_HOME/scripts/appliance/labfoundry-bootstrap-https" "$LABFOUNDRY_HOME/bin/labfoundry-bootstrap-https"
trust_source_dir="$LABFOUNDRY_HOME/image/common/update-trust"
if [ ! -d "$trust_source_dir" ]; then
  echo "LabFoundry release trust source directory is missing: $trust_source_dir" >&2
  exit 1
fi
install -d -o root -g root -m 0755 /etc/labfoundry/update-trust.d
trust_key_count=0
for trust_key in "$trust_source_dir"/*.pem; do
  [ -f "$trust_key" ] || continue
  if ! trust_key_details="$(openssl pkey -pubin -in "$trust_key" -text -noout 2>/dev/null)"; then
    echo "LabFoundry release trust key is not a valid public key: $trust_key" >&2
    exit 1
  fi
  case "$trust_key_details" in
    *ED25519*) ;;
    *)
      echo "LabFoundry release trust key is not Ed25519: $trust_key" >&2
      exit 1
      ;;
  esac
  install -o root -g root -m 0644 "$trust_key" "/etc/labfoundry/update-trust.d/$(basename "$trust_key")"
  trust_key_count=$((trust_key_count + 1))
done
if [ "$trust_key_count" -eq 0 ]; then
  echo "No LabFoundry release trust keys were staged under $trust_source_dir" >&2
  exit 1
fi
if [ "$LABFOUNDRY_GUEST_PLATFORM" = "vmware" ]; then
  install -o root -g root -m 0755 "$LABFOUNDRY_HOME/scripts/appliance/labfoundry-vmware-ovf-customize.py" "$LABFOUNDRY_HOME/bin/labfoundry-vmware-ovf-customize.py"
  install -o root -g root -m 0644 "$LABFOUNDRY_HOME/$LABFOUNDRY_IMAGE_ASSET_DIR/systemd/labfoundry-vmware-ovf-customize.service" /etc/systemd/system/labfoundry-vmware-ovf-customize.service
fi
install -o root -g root -m 0440 "$LABFOUNDRY_HOME/$LABFOUNDRY_IMAGE_ASSET_DIR/sudoers.d/labfoundry-helper" /etc/sudoers.d/labfoundry-helper
sed -i 's/\r$//' /etc/systemd/system/labfoundry.service /etc/systemd/system/labfoundry-worker.service /etc/systemd/system/labfoundry-console.service /etc/systemd/system.conf.d/labfoundry-console.conf "$LABFOUNDRY_HOME/bin/labfoundry-helper" "$LABFOUNDRY_HOME/bin/labfoundry-install-boot-branding" "$LABFOUNDRY_HOME/bin/labfoundry-mount-data-disks" "$LABFOUNDRY_HOME/bin/labfoundry-bootstrap-https" /etc/sudoers.d/labfoundry-helper
if [ "$LABFOUNDRY_GUEST_PLATFORM" = "vmware" ]; then
  sed -i 's/\r$//' "$LABFOUNDRY_HOME/bin/labfoundry-vmware-ovf-customize.py" /etc/systemd/system/labfoundry-vmware-ovf-customize.service
fi
visudo -cf /etc/sudoers.d/labfoundry-helper

chown -R root:root "$LABFOUNDRY_HOME"
chmod 0755 /opt "$LABFOUNDRY_HOME"
find "$LABFOUNDRY_HOME/labfoundry" "$LABFOUNDRY_HOME/scripts" "$LABFOUNDRY_HOME/image" -type d -exec chmod 0755 {} +
find "$LABFOUNDRY_HOME/labfoundry" "$LABFOUNDRY_HOME/scripts" "$LABFOUNDRY_HOME/image" -type f -exec chmod 0644 {} +
find "$LABFOUNDRY_RELEASE_DIR/.venv" -type d -exec chmod 0755 {} +
find "$LABFOUNDRY_RELEASE_DIR/.venv" -type f -exec chmod u+rw,go+r {} +
find "$LABFOUNDRY_RELEASE_DIR/.venv/bin" -type f -exec chmod a+rx {} +
chmod 0755 "$LABFOUNDRY_HOME/bin" "$LABFOUNDRY_HOME/bin/labfoundry-helper" "$LABFOUNDRY_HOME/bin/labfoundry-install-boot-branding"
"$LABFOUNDRY_HOME/bin/labfoundry-install-boot-branding" \
  "$LABFOUNDRY_HOME/image/common/boot/grub/theme.txt" \
  "$LABFOUNDRY_HOME/image/common/boot/grub/labfoundry.png"
cat >/etc/ssh/sshd_config.d/labfoundry-root-login.conf <<'EOF'
# Managed by LabFoundry. Local changes may be overwritten by Appliance Settings apply.
PermitRootLogin no
EOF
chmod 0644 /etc/ssh/sshd_config.d/labfoundry-root-login.conf
cat >/etc/systemd/system/labfoundry-data-disks.service <<'EOF'
[Unit]
Description=Prepare LabFoundry data disks
After=systemd-udev-settle.service
Wants=systemd-udev-settle.service
Before=labfoundry-bootstrap-https.service labfoundry.service

[Service]
Type=oneshot
ExecStart=/opt/labfoundry/bin/labfoundry-mount-data-disks
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 /etc/systemd/system/labfoundry-data-disks.service
cat >/etc/systemd/system/labfoundry-bootstrap-https.service <<'EOF'
[Unit]
Description=Bootstrap LabFoundry first-boot HTTPS front door
After=network-online.target labfoundry-data-disks.service labfoundry-vmware-ovf-customize.service
Wants=network-online.target labfoundry-data-disks.service
Before=nginx.service labfoundry.service
ConditionPathExists=!/var/lib/labfoundry/first-boot-https.applied

[Service]
Type=oneshot
EnvironmentFile=/etc/labfoundry/labfoundry.env
ExecStart=/opt/labfoundry/.venv/bin/python /opt/labfoundry/bin/labfoundry-bootstrap-https
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 /etc/systemd/system/labfoundry-bootstrap-https.service
chown -R labfoundry:labfoundry "$LABFOUNDRY_STATE" "$LABFOUNDRY_LOG"
chmod 0711 "$LABFOUNDRY_STATE"
if id "$BOOTSTRAP_USERNAME" >/dev/null 2>&1 && [ -d "$LABFOUNDRY_STATE/users/$BOOTSTRAP_USERNAME" ]; then
  chown "$BOOTSTRAP_USERNAME:$(id -gn "$BOOTSTRAP_USERNAME")" "$LABFOUNDRY_STATE/users/$BOOTSTRAP_USERNAME"
  chmod 0750 "$LABFOUNDRY_STATE/users/$BOOTSTRAP_USERNAME"
fi

log_step "configuring final appliance management network"
{
  printf '[Match]\n'
  printf 'Name=%s\n\n' "$LABFOUNDRY_MGMT_INTERFACE"
  printf '[Network]\n'
  if [ "$LABFOUNDRY_MGMT_USES_DHCP" = "true" ]; then
    printf 'DHCP=ipv4\n'
  else
    printf 'Address=%s\n' "$LABFOUNDRY_MGMT_ADDRESS"
    if [ -n "$LABFOUNDRY_MGMT_GATEWAY" ]; then
      printf 'Gateway=%s\n' "$LABFOUNDRY_MGMT_GATEWAY"
    fi
    for dns_server in $LABFOUNDRY_MGMT_DNS; do
      printf 'DNS=%s\n' "$dns_server"
    done
  fi
} >/etc/systemd/network/00-labfoundry-mgmt.network
chmod 0644 /etc/systemd/network/00-labfoundry-mgmt.network
rm -f /etc/systemd/network/50-static-en.network /etc/systemd/network/99-dhcp-en.network

if [ "$LABFOUNDRY_MGMT_USES_DHCP" != "true" ] && [ -n "$LABFOUNDRY_MGMT_DNS" ]; then
  {
    for dns_server in $LABFOUNDRY_MGMT_DNS; do
      printf 'nameserver %s\n' "$dns_server"
    done
  } >/etc/resolv.conf
  chmod 0644 /etc/resolv.conf
fi

log_step "configuring first-boot LabFoundry management nginx bootstrap"
install -d -o root -g root -m 0755 /etc/nginx/conf.d
rm -f /etc/nginx/conf.d/default.conf /etc/nginx/conf.d/default_server.conf
cat >/etc/nginx/conf.d/labfoundry.conf <<'EOF'
# Managed by LabFoundry. Local changes may be overwritten.
include /etc/labfoundry/nginx/sites.d/*.conf;
EOF
chmod 0644 /etc/nginx/conf.d/labfoundry.conf
if [ -f /etc/nginx/nginx.conf ] &&
  ! grep -Eq 'include[[:space:]]+/etc/nginx/conf\.d/\*\.conf;' /etc/nginx/nginx.conf &&
  ! grep -Fq '/etc/nginx/conf.d/labfoundry.conf' /etc/nginx/nginx.conf; then
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
                include = "\n    # Managed by LabFoundry. Local changes may be overwritten.\n    include /etc/nginx/conf.d/labfoundry.conf;\n"
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
if [ "$LABFOUNDRY_GUEST_PLATFORM" = "hyperv" ]; then
  systemctl enable --now hv_kvp_daemon || true
  systemctl enable --now hv_fcopy_daemon || true
  systemctl enable --now hv_vss_daemon || true
elif [ "$LABFOUNDRY_GUEST_PLATFORM" = "vmware" ]; then
  systemctl enable --now vmtoolsd || true
  systemctl enable labfoundry-vmware-ovf-customize.service
fi
systemctl enable labfoundry-data-disks.service
systemctl enable labfoundry-bootstrap-https.service
systemctl enable labfoundry
systemctl enable labfoundry-worker.service
systemctl mask getty@tty1.service
systemctl mask --force ctrl-alt-del.target
systemctl enable labfoundry-console.service
systemctl enable --now nginx

log_step "configuring LabFoundry nftables firewall"
if [ -z "$LABFOUNDRY_MGMT_SOURCE_CIDR" ]; then
  DETECTED_MGMT_ADDRESS="$(ip -4 -o addr show dev "$LABFOUNDRY_MGMT_INTERFACE" scope global 2>/dev/null | awk 'NR == 1 { print $4 }')"
  if [ -n "$DETECTED_MGMT_ADDRESS" ]; then
    LABFOUNDRY_MGMT_SOURCE_CIDR="$(python3 -c 'import ipaddress, sys; print(ipaddress.ip_interface(sys.argv[1]).network)' "$DETECTED_MGMT_ADDRESS")"
  fi
fi
if [ -z "$LABFOUNDRY_MGMT_SOURCE_CIDR" ] && [ "$LABFOUNDRY_MGMT_ADDRESS" != "dhcp" ]; then
  LABFOUNDRY_MGMT_SOURCE_CIDR="$(python3 -c 'import ipaddress, sys; print(ipaddress.ip_interface(sys.argv[1]).network)' "$LABFOUNDRY_MGMT_ADDRESS")"
fi
if [ -n "$LABFOUNDRY_MGMT_SOURCE_CIDR" ]; then
  printf '\nLABFOUNDRY_MANAGEMENT_SOURCE_CIDR=%s\n' "$LABFOUNDRY_MGMT_SOURCE_CIDR" >>/etc/labfoundry/labfoundry.env
  LABFOUNDRY_MGMT_ACCESS_RULE="    ip saddr $LABFOUNDRY_MGMT_SOURCE_CIDR tcp dport { 22, 80, 443 } accept comment \"LabFoundry management access\""
else
  LABFOUNDRY_MGMT_ACCESS_RULE="    iifname \"$LABFOUNDRY_MGMT_INTERFACE\" tcp dport { 22, 80, 443 } accept comment \"LabFoundry management access\""
fi
install -d -o root -g root -m 0755 /etc/labfoundry/nftables.d
cat >/etc/labfoundry/nftables.d/labfoundry.nft <<EOF
# Managed by LabFoundry. Local changes may be overwritten.
# nftables firewall state for Photon OS appliance images.
flush ruleset
table inet labfoundry {
  chain input {
    type filter hook input priority filter; policy drop;
    iifname "lo" accept comment "LabFoundry loopback"
    ct state established,related accept comment "LabFoundry established traffic"
$LABFOUNDRY_MGMT_ACCESS_RULE
    meta l4proto icmp accept comment "LabFoundry ICMP diagnostics"
    meta l4proto ipv6-icmp accept comment "LabFoundry IPv6 ICMP diagnostics"
  }
  chain forward {
    type filter hook forward priority filter; policy drop;
    ct state established,related accept comment "LabFoundry established traffic"
    meta l4proto icmp accept comment "LabFoundry ICMP diagnostics"
    meta l4proto ipv6-icmp accept comment "LabFoundry IPv6 ICMP diagnostics"
  }
  chain output {
    type filter hook output priority filter; policy accept;
    ct state established,related accept comment "LabFoundry established traffic"
    meta l4proto icmp accept comment "LabFoundry ICMP diagnostics"
    meta l4proto ipv6-icmp accept comment "LabFoundry IPv6 ICMP diagnostics"
  }
}
EOF
chmod 0644 /etc/labfoundry/nftables.d/labfoundry.nft
cat >/etc/systemd/system/labfoundry-firewall.service <<'EOF'
[Unit]
Description=LabFoundry nftables firewall
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f /etc/labfoundry/nftables.d/labfoundry.nft
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now labfoundry-firewall.service
if command -v iptables >/dev/null 2>&1; then
  iptables -P INPUT ACCEPT || true
  iptables -P FORWARD ACCEPT || true
  iptables -P OUTPUT ACCEPT || true
  iptables -F || true
  iptables -X || true
fi
systemctl disable --now iptables || true

log_step "running Photon compatibility check"
"$LABFOUNDRY_HOME/.venv/bin/python" "$LABFOUNDRY_HOME/scripts/check_photon_compatibility.py"
