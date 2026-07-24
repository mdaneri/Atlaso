# LabFoundry Photon OS Hyper-V Image

This directory contains the first real-OS appliance image path for LabFoundry.
It builds a Photon OS 5.0 Hyper-V VHDX and provisions the FastAPI control plane
as a systemd service behind nginx. The first-boot management front door is
CA-backed HTTPS/443, reverse-proxied to uvicorn on `127.0.0.1:8000`.
HTTP/80 redirects to HTTPS and does not serve management UI or API content.

## Host Prerequisites

- Windows host with Hyper-V enabled.
- Run Packer from an elevated PowerShell session or as a user in the
  `Hyper-V Administrators` group.
- Packer `>= 1.10`.
- LabFoundry Hyper-V lab switches created before the build:

```powershell
powershell.exe -ExecutionPolicy Bypass -File scripts/windows/hyperv/create-switches.ps1
```

The Packer builder uses `LabFoundry-Mgmt` by default. The script assigns the
host-side switch adapter `192.168.49.254/24` and creates
`LabFoundry-Mgmt-NAT`, which gives the temporary builder VM outbound internet
access for `tdnf update`.

## Build Inputs

Photon publishes the ISO and checksum from the Photon OS download page. The
current LabFoundry build target uses the Photon OS 5.0 GA full ISO:

```powershell
powershell.exe -ExecutionPolicy Bypass `
  -File scripts/windows/hyperv/build-photon-image.ps1 `
  -IsoUrl "https://packages.vmware.com/photon/5.0/GA/iso/photon-5.0-dde71ec57.x86_64.iso" `
  -IsoChecksum "sha512:6a7a258399a258da742032987c043ab25503698d35edafaf1ae000f12127da1a161d8b84caa17fd8f23d129e81e1faa7ab087c20ab9229772a643f8f9475305f" `
  -SshPassword "<one-time-build-root-password>" `
  -BootstrapAdminPassword "<initial-labfoundry-admin-password>"
```

By default, the temporary builder VM uses `LabFoundry-Mgmt` with
`builder_static_ip=192.168.49.30/24`, `builder_static_netmask=255.255.255.0`,
and `builder_static_gateway=192.168.49.254`. When `builder_static_ip` is set,
the template automatically uses it as Packer's SSH target. Override those
variables only when the management subnet is intentionally different. When
`-BuilderStaticDns` is omitted, the wrapper discovers the host's active IPv4 DNS
servers and uses them for both the temporary Photon builder and the final
appliance management interface. This is the preferred Hyper-V Server 2025 path
when public resolvers such as `1.1.1.1` are blocked upstream. Pass
`-BuilderStaticDns <server1>,<server2>` only when the builder VM should use a
specific resolver set.

The wrapper renders `photon-ks.json`, embeds it into
`image/hyperv/build/kickstart/labfoundry-photon-with-kickstart.iso`, and passes
that single remastered Photon ISO to Packer. The remastered ISO also replaces
the UEFI GRUB config with a LabFoundry auto-install entry, so Photon boots with
`ks=cdrom:/photon-ks.json` without Packer typing boot commands. This avoids the
Windows Server 2025 early-installer networking failure mode, the fragile
two-DVD Hyper-V path, and boot-menu timing races.
Build runs pass Packer's `-force` flag by default so the fixed output directory
can be rebuilt in one command. Use `-OutputDirectory <path>` to keep multiple
artifacts or `-KeepExistingOutput` when you want Packer to fail instead of
replacing an existing output directory.
By default, failed builds still use Packer's normal cleanup behavior. To keep
the temporary builder VM for debugging, add `-PackerOnError abort`; to choose at
failure time, use `-PackerOnError ask`.

The wrapper leaves pip's index configuration untouched by default. When the
builder can reach Python packages only through an internal mirror, add
`-PipGlobalIndex` or `-PipGlobalIndexUrl`; each option is optional and only
sets the matching pip key when non-empty. Provisioning writes the resulting
configuration to both `/etc/pip.conf` and the LabFoundry virtual environment's
`pip.conf`, and exports `PIP_INDEX_URL` for the provisioning process before
installing or upgrading Python packages. Virtualenv pip commands therefore use
the same mirror as system pip:

```powershell
powershell.exe -ExecutionPolicy Bypass `
  -File scripts/windows/hyperv/build-photon-image.ps1 `
  -IsoUrl "<photon-5.0-iso-url>" `
  -IsoChecksum "<packer-checksum>" `
  -PipGlobalIndex "https://packages.vcfd.broadcom.net/artifactory/api/pypi/upstream-pypi-virtual/pypi" `
  -PipGlobalIndexUrl "https://packages.vcfd.broadcom.net/artifactory/api/pypi/upstream-pypi-virtual/simple"
```

Omit both pip options for standard/default pip behavior.
Image provisioning uses Photon's installed pip inside the LabFoundry virtual
environment and does not upgrade pip as a separate bootstrap step, so transient
public PyPI release downloads do not block the appliance build before the actual
LabFoundry package install begins.

The wrapper keeps `LABFOUNDRY_DRY_RUN_SYSTEM_ADAPTERS=true` by default so a
first-boot image records host-mutation command intent instead of changing
Photon services. For a disposable demo or lifecycle image that should really
apply nginx, dnsmasq, nftables, networkd, and other host changes, add
`-EnableRealSystemAdapters` to the build command.

Use single quotes around passwords that contain PowerShell metacharacters:

```powershell
-var 'ssh_password=<one-time-build-root-password>'
-var 'bootstrap_admin_password=<initial-labfoundry-admin-password>'
```

`ssh_password` is for the temporary installer/root credentials used during the
image build. `bootstrap_admin_password` is the initial LabFoundry web login
password for `admin`. If `bootstrap_admin_password` is omitted, the build falls
back to `ssh_password` for compatibility with early appliance images.

Provisioned appliances install `python3-curses` and run the root-owned
`labfoundry-console.service` exclusively on `/dev/tty1`. Provisioning masks only
`getty@tty1.service`; switching to tty2 or a later virtual terminal starts the
normal Photon login flow. The recovery console edits only management IPv4/IPv6,
DNS, persistent Firewall state, and reversible service
isolation. The normal 80x30 display includes boot and runtime state for the
appliance services, including Firewall desired state. F3 and F4 each require a
fresh Photon root-password check before opening `top` or an audited root Bash
session, and exiting either restores the appliance screen. Installed images use
a 640x480 LabFoundry GRUB theme with the official Photon OS logo while preserving
the existing timeout, kernel arguments, and Photon boot implementation.
See [Local appliance console](../../docs/appliance-console.md).

If Packer prints `Using SSH communicator to connect: <ip>` and waits even
though the VM is reachable, test the exact same credentials from the Windows
host:

```powershell
ssh root@<photon-builder-ip>
```

The Packer communicator uses the temporary `labfoundry-build` user, port `22`,
password authentication, and a longer SSH timeout to allow Photon installation
and reboot to finish. Provisioning removes the temporary sudoers entry before
the image is finalized.

Use `-var "switch_name=<switch>"` only if the replacement switch has a host
adapter IP and internet access. The LabFoundry private service/site/trunk
switches are intended for the finished appliance VM, not for the Packer
installer VM.

Packer logs a line like `Host IP for the HyperV machine: 192.168.49.254`. That
is the Windows host-side `LabFoundry-Mgmt` address used for the kickstart HTTP
URL; it is not the Photon guest SSH address. The default Photon builder guest
address is `192.168.49.30`.

The build updates Photon packages during provisioning. On June 21, 2026, the
Photon 5.0 updates repo exposed `python3` as `3.14.5-2.ph5`; keep the image
builder on the updated repo stream rather than relying only on the GA ISO
package set.

If the VM stops at the Photon license agreement or disk selection screen, the
builder did not load the kickstart file. Stop the build, make sure this
directory is current, and rerun `scripts/windows/hyperv/build-photon-image.ps1`.
The wrapper should print `Using remastered Photon ISO`, and the Packer log
should wait for SSH without printing `Typing the boot command...`. If Photon
shows the EULA, the ISO did not include the LabFoundry GRUB auto-install entry,
or the raw `packer build .` path or an old wrapper was used. Raw
`packer build .` is intentionally blocked unless `iso_contains_kickstart=true`
is provided so this failure mode stops before a VM is created.

If Photon installs and SSH works from the Windows host but Packer remains at
`Waiting for SSH to become available`, query the IPv4 reported by Hyper-V:

```powershell
powershell.exe -ExecutionPolicy Bypass -File ..\..\scripts\windows\hyperv\get-labfoundry-vm-ip.ps1 `
  -Name LabFoundry-Photon-Builder `
  -SwitchName "LabFoundry-Mgmt"
```

Then verify SSH:

```powershell
ssh root@<photon-vm-ip>
```

The Packer template sets `ssh_host` to the static builder address by default.
If you override networking and SSH is reachable but Packer still does not
detect the guest IP, stop the build and rerun with a queried `ssh_host`:

```powershell
$photonVmIp = powershell.exe -ExecutionPolicy Bypass -File ..\..\scripts\windows\hyperv\get-labfoundry-vm-ip.ps1 `
  -Name LabFoundry-Photon-Builder `
  -SwitchName "LabFoundry-Mgmt"

powershell.exe -ExecutionPolicy Bypass `
  -File ..\..\scripts\windows\hyperv\build-photon-image.ps1 `
  -SshHost "$photonVmIp" `
  -IsoUrl "https://packages.vmware.com/photon/5.0/GA/iso/photon-5.0-dde71ec57.x86_64.iso" `
  -IsoChecksum "sha512:6a7a258399a258da742032987c043ab25503698d35edafaf1ae000f12127da1a161d8b84caa17fd8f23d129e81e1faa7ab087c20ab9229772a643f8f9475305f" `
  -SshPassword "<one-time-build-root-password>" `
  -BootstrapAdminPassword "<initial-labfoundry-admin-password>"
```

The helper reads the current Photon guest IPv4 from Hyper-V and filters out the
host-side management switch address.

Photon's Hyper-V guest integration package is `hyper-v`. The kickstart and
provisioning scripts install it and enable `hv_kvp_daemon`, `hv_fcopy_daemon`,
and `hv_vss_daemon` so Hyper-V can report guest metadata such as IP addresses.
Do not install `open-vm-tools` in this Hyper-V image; the VMware Workstation
image path owns VMware guest tools. Keep the `ssh_host` override as a fallback
for early build runs where the guest IP is visible manually before Hyper-V
reports it to Packer.

## What Provisioning Installs

- Photon packages updated from the configured Photon 5.0 repositories, with a
  second `tdnf -y update` pass after required appliance packages are installed.
- `labfoundry` system user.
- `/opt/labfoundry` application install.
- `/etc/labfoundry/labfoundry.env` production environment file.
- `/etc/labfoundry/build-info` recording build time, Photon release, kernel,
  Python, and the package update marker.
- A masked `systemd-ssh-generator` so Photon does not try to advertise or bind
  automatic SSH-over-AF_VSOCK sockets on Hyper-V. Normal TCP SSH remains
  provided by `sshd`. Root SSH login starts disabled through the
  LabFoundry-owned `labfoundry-root-login.conf` drop-in and can be enabled from
  Appliance Settings, then enforced through global appliance apply.
- `/var/lib/labfoundry` durable SQLite state.
- `/var/log/labfoundry` local service logs.
- Fixed appliance mounts under `/mnt/labfoundry-vcf-*`.
- `/etc/systemd/system/labfoundry.service`.
- `/etc/systemd/system/labfoundry-firewall.service` loading the nftables
  management firewall.
- `dnsmasq` for the shared DNS/DHCP appliance service.
- `ipxe` and `syslinux` for ESXi PXE bootstrap support. Provisioning also stages LabFoundry's bundled iPXE first-stage files, `undionly.kpxe` and `snponly.efi`, under `/var/lib/labfoundry/pxe/bootloaders` because the Photon package stream may not ship those filenames.
  TFTP.
- `/opt/labfoundry/bin/labfoundry-helper` constrained appliance helper.
- `/etc/sudoers.d/labfoundry-helper` permitting the service user to run only
  the constrained helper binary as root.

The generated appliance keeps `LABFOUNDRY_DRY_RUN_SYSTEM_ADAPTERS=true` until
each helper-backed apply unit is reviewed and promoted.
Provisioning writes both `LABFOUNDRY_SECRET_KEY` and
`LABFOUNDRY_SECRETS_KEY`; the latter encrypts CA root and leaf private-key
material stored in the LabFoundry database and must be preserved for settings
backup portability.
Appliance Update is runtime maintenance and stays separate from desired-state
`/appliance-apply`. It stages
`/var/lib/labfoundry/apply/appliance-update/labfoundry-update.json` and uses
`labfoundry-helper appliance-update` for Photon OS, PowerShell modules, and
signed LabFoundry releases. Provisioning installs the named Ed25519 trust keys
under `/etc/labfoundry/update-trust.d` and creates the versioned
`/opt/labfoundry/releases/<version>` layout with `current` and `.venv`
compatibility symlinks. Release updates verify signed channel and release
manifests, build from a hash-locked offline ABI wheelhouse, atomically switch
the release, and restore the previous release and SQLite snapshot on failure.
Manual and scheduled checks/installations retain one parent task with separate
LabFoundry Release, PowerShell Modules, and Photon OS child steps; failed
earlier streams leave Photon explicitly skipped instead of ambiguously pending.
The Packer build explicitly stages `image/common/update-trust` and fails if no
valid public key is available, so a completed image cannot silently reject the
published signed channels as untrusted.
Photon updates fail closed when their candidate Python ABI is not in the active
release. Candidate discovery uses the Photon-supported
`tdnf repoquery python3` form. Photon maintenance never performs automatic RPM
rollback or reboot.
Pass `-SignedReleaseRepositoryUrl https://<fixture>/updates` to
`scripts/windows/hyperv/invoke-lifecycle-test.ps1` to add a signed preview
upgrade and deliberately broken development-channel rollback. The fixture
contract and database/service assertions are documented in
[`docs/appliance-update.md`](../../docs/appliance-update.md).
The image also enables `labfoundry-worker.service`, which owns queued updates,
VCF Offline Depot downloads, five-field cron/one-time schedules, and unprivileged
managed-script execution.
Firewall desired state is nftables-backed. Provisioning installs nftables,
loads `/etc/labfoundry/nftables.d/labfoundry.nft`, and disables the older
Photon iptables service so LabFoundry has a single firewall owner.

DNS/DHCP desired state is dnsmasq-backed. Real `/appliance-apply` stages the
rendered config under `/var/lib/labfoundry/apply/dnsmasq/`, validates it with
`dnsmasq --test`, installs `/etc/labfoundry/dnsmasq.d/labfoundry.conf`, and
reloads or restarts `dnsmasq` through `labfoundry-helper`.
The rendered config uses `/var/lib/labfoundry/dnsmasq/dhcp.leases` for DHCP
leases, and the helper exposes only that allowlisted lease readback path.
DHCP scopes should bind to access physical interfaces with IP CIDR or enabled
VLAN interfaces with IP CIDR, not trunk or addressless physical interfaces.
ESXi PXE boot settings add dnsmasq TFTP and DHCP bootfile options for the
guide-aligned flow: first-stage `undionly.kpxe` or `snponly.efi`, then
second-stage `pxelinux.0` or `mboot.efi` when DHCP detects iPXE. Optional
native UEFI HTTP clients receive the generated absolute `mboot.efi` URL. The
generated TFTP files, extracted ESXi installer HTTP tree, per-host `boot.cfg`
files, and dedicated static PXE HTTP listener are written only by global
appliance apply. Apply DNS/DHCP, ESXi PXE, and Firewall together when boot
settings change.

Certificate Authority desired state is LabFoundry CA-backed. Real
`/appliance-apply` stages `/var/lib/labfoundry/apply/ca/labfoundry-ca.json`,
validates the staged CA/certificate payload through `labfoundry-helper`, and
writes public CA bundles plus service certificate/key files under
`/etc/labfoundry`. Private keys are encrypted in the database with
`LABFOUNDRY_SECRETS_KEY`; previews, jobs, and logs must remain redacted.

KMS / KMIP desired state is PyKMIP-backed for lab compatibility testing. Real
`/appliance-apply` stages `/var/lib/labfoundry/apply/kms/pykmip.conf`,
requires an enabled healthy CA with issued KMS server/client certificates,
installs `/etc/labfoundry/kms/pykmip.conf` and `/etc/pykmip/server.conf`, and
manages `labfoundry-kms.service`. The service launches PyKMIP through
LabFoundry's compatibility wrapper for current Photon Python streams. The KMS
listener binds to the IP derived from the selected access physical interface or
enabled VLAN. Disabling KMS stops and disables the service while preserving
`/var/lib/labfoundry/kms/pykmip.db`.

Local Users desired state is Photon OS account-backed. Real `/appliance-apply`
stages `/var/lib/labfoundry/apply/local-users/labfoundry-users.json`, validates
LabFoundry-owned local usernames, creates or updates enabled users under
`/var/lib/labfoundry/users` with the per-user desired shell, removes disabled or
removed managed users with `userdel -r`, applies staged unlock requests with
`passwd -u` and `faillock --reset`, writes the desired PAM/pwquality password
policy, and sends in-memory pending passwords to `chpasswd` over stdin. Password
previews, job results, and logs should show only status and counts.
`labfoundry.service` preserves
`LABFOUNDRY_HELPER_USE_SYSTEMD_RUN=1` through sudo so account-mutating helper
commands can run as transient systemd units outside the control-plane service
sandbox while still using the constrained helper allowlist.
Nginx owns the public management front door. Appliance Settings apply writes
`/etc/nginx/conf.d/labfoundry.conf`,
`/etc/labfoundry/nginx/sites.d/management.conf`, and a loopback-only
`labfoundry.service` override. Fresh appliances run
`labfoundry-bootstrap-https.service` on deployed-VM first boot to enable the
integrated CA, issue the managed `appliance:https` certificate, and start with nginx
redirecting public HTTP/80 to HTTPS/443 while reverse-proxying HTTPS to uvicorn
on `127.0.0.1:8000`. The root CA is not baked into the reusable image. When HTTPS is disabled, including after factory reset plus
apply, nginx can serve public HTTP/80 as a plain reverse proxy to the same
loopback upstream, but that is not the first-boot appliance posture. The helper disables
the retired `labfoundry-http-redirect.service` if present, reloads
nginx/systemd, and schedules a short delayed `labfoundry.service` restart so the
global apply job can finish before uvicorn moves behind nginx.

Appliance Settings also owns the root SSH login switch. The image provisions
`/etc/ssh/sshd_config.d/labfoundry-root-login.conf` with `PermitRootLogin no`;
global appliance apply rewrites that LabFoundry-owned drop-in, validates
`sshd`, and restarts `sshd` when the operator enables or disables root SSH.

Provisioning creates the bootstrap admin OS account under
`/var/lib/labfoundry/users/<admin>` with `/usr/bin/pwsh` and sets the same
bootstrap password used for the initial web login, so the admin account exists
on Photon before first appliance apply. The image installs Photon's
`powershell` package for this shell, installs system-wide VCF PowerCLI
`9.1.0.25380678`, disables and verifies PowerCLI CEIP participation at
`AllUsers` scope, verifies the module and `Connect-VIServer` from the
unprivileged bootstrap administrator's PowerShell session, installs
`vcf-sdk==9.1.0.0` in the LabFoundry virtualenv, and grants the bootstrap admin
normal password-backed sudo through `/etc/sudoers.d/labfoundry-bootstrap-admin`.
The system PowerShell module tree remains root-owned and writable only by root,
while every local `/usr/bin/pwsh` user can read and import its modules.

VCF Backups desired state is OpenSSH-backed. Provisioning leaves the default
`vcf-backup` account absent from Photon OS until Local Users apply creates it.
When VCF Backup desired state is off, LabFoundry keeps the default `vcf-backup`
user disabled so the next Local Users apply removes the Photon OS account.
Real `/appliance-apply` stages the rendered drop-in under
`/var/lib/labfoundry/apply/vcf-backups/`, validates that it is a
LabFoundry-rendered `Match User` config for an existing OS account, installs
`/etc/ssh/sshd_config.d/labfoundry-vcf-backups.conf`, prepares the fixed
`/mnt/labfoundry-vcf-backups` chroot and `/backups` upload directory, and
restarts `sshd` through `labfoundry-helper`. Firewall apply still owns the
selected interface and port allow rule. Apply Local Users first when the
selected SFTP user is new, disabled/enabled, has a pending password, changes shell, or has an unlock request.

The firewall preview derives LabFoundry-managed service allow rules from
enabled service listener desired state, including management, DNS, DHCP, KMS,
NTPsec, VCF Backup, VCF Offline Depot, and VCF Private Registry listeners. DHCP VLAN
moves or service listener moves should be applied with the changed Firewall
unit when `/appliance-apply` shows it pending.

Before shutdown, provisioning resets the exported appliance image from the
temporary Packer builder network to the LabFoundry management network:

- appliance address: `192.168.49.1/24`;
- appliance interface: `eth0`;
- host-side `LabFoundry-Mgmt` address: `192.168.49.254/24`;
- default gateway: `192.168.49.254`.

The generated `00-labfoundry-mgmt.network` matches only `eth0`. Provisioning
removes the Photon installer's broad `50-static-en.network` and
`99-dhcp-en.network` defaults so non-management NICs remain opt-in through
LabFoundry desired state and global appliance apply.

The Hyper-V switch script configures the host-side management address and NAT so
the final appliance can reach Photon repositories when the Windows host has
internet access.

Windows NAT for the management switch is configured with:

```powershell
New-NetIPAddress -InterfaceAlias "vEthernet (LabFoundry-Mgmt)" -IPAddress 192.168.49.254 -PrefixLength 24
New-NetNat -Name LabFoundry-Mgmt-NAT -InternalIPInterfaceAddressPrefix 192.168.49.0/24
```

Use `scripts/windows/hyperv/create-switches.ps1` instead of running those by
hand; it creates or repairs the address/NAT and prints the resulting summary.

Packer uploads only the files required for appliance installation: the
`labfoundry` package, packaging metadata, appliance helper scripts, the Photon
compatibility check, systemd unit, and sudoers template. It intentionally does
not upload `.git`, test artifacts, caches, or development virtual environments
into the builder VM.

## Boot The VHDX

After Packer completes, create and start the test appliance VM with the wrapper:

```powershell
powershell.exe -ExecutionPolicy Bypass -File scripts/windows/hyperv/create-labfoundry-test-vm.ps1 -WaitForIp
```

The wrapper finds the latest appliance VHDX under `image/hyperv/output`,
prepares the LabFoundry Hyper-V switches, creates `LabFoundry`, starts it, and
prints the management IP when `-WaitForIp` is used. If `LabFoundry` already
exists, pass `-Redeploy` to remove and recreate only that VM, or pass `-Name`
to create a separate test VM.

The sample VM keeps the first adapter management-only on `LabFoundry-Mgmt`.
The second adapter is `Services` on the dedicated `LabFoundry-Services` switch
as untagged service traffic for DNS, DHCP, CA, depot, PXE, KMS, and other
LabFoundry-managed services. The wrapper also adds `SiteA` on
`LabFoundry-SiteA` as trunk VLAN 12, `Trunk` on `LabFoundry-Trunk` as trunk
VLAN 50, and `WAN-Test` on `LabFoundry-SiteB` as untagged WAN test traffic.
Pass `-SkipLabNetworkAdapters` only when you intentionally need a
management-only VM.

For a clean appliance data start, also pass `-ResetDataDisks`. The wrapper
removes the default Depot and Backups data VHDX files next to the selected OS
disk, then lets `create-labfoundry-vm.ps1` create fresh empty data disks:

```powershell
powershell.exe -ExecutionPolicy Bypass -File scripts/windows/hyperv/create-labfoundry-test-vm.ps1 -Redeploy -ResetDataDisks -WaitForIp
```

The finished appliance VM gets two additional dynamic VHDX data disks by
default:

- `LabFoundry-Depot.vhdx`, intended for `/mnt/labfoundry-vcf-offline-depot`;
- `LabFoundry-Backups.vhdx`, intended for `/mnt/labfoundry-vcf-backups`.

Use `create-switches.ps1`, `create-labfoundry-vm.ps1`, and
`start-labfoundry-vm.ps1` directly only when you need to control each step by
hand.

The default data disks are dynamic 500 GB VHDX files stored next to the OS
VHDX. Override them with `-DepotVhdxPath`, `-BackupVhdxPath`,
`-DepotDiskSizeBytes`, or `-BackupDiskSizeBytes` when needed. On first boot,
`labfoundry-data-disks.service` formats blank attached data disks, labels them
as `LABFOUNDRY_DEPOT` and `LABFOUNDRY_BKUP`, writes `/etc/fstab`, and mounts
them before the LabFoundry control plane starts.

## Appliance Smoke Checks

Inside the Photon VM:

```bash
python3 --version
cat /etc/labfoundry/build-info
ip addr show
tdnf check-update || true
systemctl status labfoundry --no-pager
journalctl -u labfoundry -n 100 --no-pager
curl -fsS http://127.0.0.1:8000/openapi.json >/dev/null
curl -fsS http://127.0.0.1:8000/api/v1/dashboard >/dev/null || true
```

From the host, verify the management URL, login, reboot persistence, and that
`/appliance-apply` still records dry-run command intent before any real adapter
execution is enabled.

If the VM console prints
`systemd-ssh-generator: Failed to query local AF_VSOCK CID: Cannot assign requested address`,
the appliance is hitting systemd's automatic SSH-over-vsock discovery path.
LabFoundry does not use SSH-over-vsock, and current image provisioning masks
that generator while keeping regular TCP SSH available. On an already-built VM,
apply the same cleanup as root and reboot:

```bash
install -d -o root -g root -m 0755 /etc/systemd/system-generators
ln -sfn /dev/null /etc/systemd/system-generators/systemd-ssh-generator
systemctl daemon-reload
reboot
```
