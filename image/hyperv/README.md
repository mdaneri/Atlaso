# Atlaso Photon OS Hyper-V Image

This directory contains the first real-OS appliance image path for Atlaso. It builds a Photon OS 5.0 Hyper-V VHDX and
provisions the FastAPI control plane as a systemd service behind nginx. The first-boot management front door is
CA-backed HTTPS/443, reverse-proxied to uvicorn on `127.0.0.1:8000`. HTTP/80 redirects to HTTPS and does not serve
management UI or API content.

## Host Prerequisites

- Windows host with Hyper-V enabled.
- PowerShell 7.4 or newer (`pwsh`). Earlier PowerShell releases and Windows PowerShell 5.1 (`powershell.exe`) are not
  supported.
- WSL 2 installed and initialized before provisioning the default `Atlaso-Build` image-build distribution. See
  [Windows image-build WSL environment](../../docs/contribute/windows-image-build-wsl.md).
- Run Packer from an elevated PowerShell 7 session or as a user in the `Hyper-V Administrators` group.
- Packer `>= 1.10`.
- Atlaso Hyper-V lab switches created before the build:

```powershell
pwsh -ExecutionPolicy Bypass -File scripts/windows/hyperv/create-switches.ps1
```

The Packer builder uses `Atlaso-Mgmt` by default. The script assigns the host-side switch adapter `192.168.49.254/24`
and creates `Atlaso-Mgmt-NAT`, which gives the temporary builder VM outbound internet access for `tdnf update`.

Before a build, run `python scripts/check_deployment_assets.py --mode packer` from the repository root. The protected
validator inventories both Packer templates, checks formatting, initializes their plugins, verifies the exact selected
binaries, and performs the same full validation used by the wrappers with the required remastered-ISO guard enabled.
The Hyper-V template pins `github.com/hashicorp/hyperv` to `1.1.5`. The supported wrapper runs `packer init` and
`scripts/check_packer_plugins.py` before validation or build, so an empty plugin directory and a warm cache must select
that same reviewed version. Update the HCL pin, tests, and this documentation together when reviewing a plugin update.

## Build Inputs

Photon publishes the ISO and checksum from the Photon OS download page. The current Atlaso build target uses the Photon
OS 5.0 GA full ISO:

```powershell
pwsh -ExecutionPolicy Bypass `
  -File scripts/windows/hyperv/build-photon-image.ps1 `
  -IsoUrl "https://packages.vmware.com/photon/5.0/GA/iso/photon-5.0-dde71ec57.x86_64.iso" `
  -IsoChecksum "sha512:6a7a258399a258da742032987c043ab25503698d35edafaf1ae000f12127da1a161d8b84caa17fd8f23d129e81e1faa7ab087c20ab9229772a643f8f9475305f" `
  -SshPassword "<one-time-build-root-password>" `
  -BootstrapAdminPassword "<initial-atlaso-admin-password>"
```

By default, the temporary builder VM uses `Atlaso-Mgmt` with `builder_static_ip=192.168.49.30/24`,
`builder_static_netmask=255.255.255.0`, and `builder_static_gateway=192.168.49.254`. When `builder_static_ip` is set,
the template automatically uses it as Packer's SSH target. Override those variables only when the management subnet is
intentionally different. When `-BuilderStaticDns` is omitted, the wrapper discovers the host's active IPv4 DNS servers
and uses them for both the temporary Photon builder and the final appliance management interface. This is the preferred
Hyper-V Server 2025 path when public resolvers such as `1.1.1.1` are blocked upstream. Pass
`-BuilderStaticDns <server1>,<server2>` only when the builder VM should use a specific resolver set.

The wrapper renders `photon-ks.json` through `New-AtlasoPhotonKickstart` in the shared
`scripts/windows/common/Atlaso.PhotonImage.psm1` module, embeds it into
`image/hyperv/build/kickstart/atlaso-photon-with-kickstart.iso`, and passes that single remastered Photon ISO to Packer.
That generator is the only kickstart source for both Hyper-V and VMware; the focused image tests invoke it and parse
each provider's generated JSON. The remastered ISO also replaces the UEFI GRUB config with an Atlaso auto-install entry,
so Photon boots with `ks=cdrom:/photon-ks.json` without Packer typing boot commands. This
avoids the Windows Server 2025 early-installer networking failure mode, the fragile two-DVD Hyper-V path, and boot-menu
timing races. Build runs pass Packer's `-force` flag by default so the fixed output directory can be rebuilt in one
command. Use `-OutputDirectory <path>` to keep multiple artifacts or `-KeepExistingOutput` when you want Packer to fail
instead of replacing an existing output directory. By default, failed builds still use Packer's normal cleanup behavior.
To keep the temporary builder VM for debugging, add `-PackerOnError abort`; to choose at failure time, use
`-PackerOnError ask`.

The wrapper treats `-SshPassword` as opaque credential data. Apostrophes and common PowerShell or POSIX shell
metacharacters are encoded before the generated kickstart and Packer shell boundaries, decoded directly to standard
input, and never evaluated as shell syntax. Quote the PowerShell argument for the caller's shell as usual; Atlaso does
not add character exclusions for those printable password values.

The wrapper does not build or embed Inventory Linux. New templates leave it uninstalled so an administrator can use
**Download latest** to retrieve the signed independent release when needed. Contributors building Inventory Linux
itself use `scripts/windows/common/Build-AtlasoInventoryLinux.ps1` and its `-WslDistribution <name>` option.

The wrapper leaves pip's index configuration untouched by default. When the builder can reach Python packages only
through an internal mirror, add `-PipGlobalIndex` or `-PipGlobalIndexUrl`; each option is optional and only sets the
matching pip key when non-empty. Provisioning writes the resulting configuration to both `/etc/pip.conf` and the Atlaso
virtual environment's `pip.conf`, and exports `PIP_INDEX_URL` for the provisioning process before installing or
upgrading Python packages. Virtualenv pip commands therefore use the same mirror as system pip:

```powershell
pwsh -ExecutionPolicy Bypass `
  -File scripts/windows/hyperv/build-photon-image.ps1 `
  -IsoUrl "<photon-5.0-iso-url>" `
  -IsoChecksum "<packer-checksum>" `
  -PipGlobalIndex "https://packages.vcfd.broadcom.net/artifactory/api/pypi/upstream-pypi-virtual/pypi" `
  -PipGlobalIndexUrl "https://packages.vcfd.broadcom.net/artifactory/api/pypi/upstream-pypi-virtual/simple"
```

Omit both pip options for standard/default pip behavior. Image provisioning uses Photon's installed pip inside the
Atlaso virtual environment and does not upgrade pip as a separate bootstrap step, so transient public PyPI release
downloads do not block the appliance build before the actual Atlaso package install begins. The Packer template stages
`requirements-appliance.lock` with the application source so bootstrap dependency installation retains hash verification
instead of falling back to unpinned packages. It also stages the third-party notice generator, vendored-component
inventory, and Inventory Linux README used by that inventory as mandatory build inputs rather than skipping notice
generation when any input is missing. The shared
PowerShell profile is staged with the other common image assets so provisioning can install the interactive
`Get-AtlasoVault` helper. Notice lock verification inventories only top-level virtual-environment distributions and
ignores package-internal vendored metadata.

The wrapper keeps `ATLASO_DRY_RUN_SYSTEM_ADAPTERS=true` by default so a first-boot image records host-mutation command
intent instead of changing Photon services. For a disposable demo or lifecycle image that should really apply nginx,
dnsmasq, nftables, networkd, and other host changes, add `-EnableRealSystemAdapters` to the build command.

Use single quotes around passwords that contain PowerShell metacharacters:

```powershell
-var 'ssh_password=<one-time-build-root-password>'
-var 'bootstrap_admin_password=<initial-atlaso-admin-password>'
```

`ssh_password` is for the temporary installer/root credentials used during the image build. `bootstrap_admin_password`
is the initial Atlaso web login password for `admin`; it is a separate credential.

Provisioned appliances install `python3-curses` and run the root-owned `atlaso-console.service` exclusively on
`/dev/tty1`. Provisioning masks only `getty@tty1.service`; switching to tty2 or a later virtual terminal starts the
normal Photon login flow. The recovery console edits only management IPv4/IPv6, DNS, persistent Firewall state, and
reversible service isolation. The normal 80x30 display includes boot and runtime state for the appliance services,
including Firewall desired state. F3 and F4 each require a fresh Photon root-password check before opening `top` or an
audited root Bash session, and exiting either restores the appliance screen. Installed images use a 640x480 Atlaso GRUB
theme with the official Photon OS logo while preserving the existing timeout, kernel arguments, and Photon boot
implementation. See [Local appliance console](../../docs/appliance-console.md).

If Packer prints `Using SSH communicator to connect: <ip>` and waits even though the VM is reachable, test the exact
same credentials from the Windows host:

```powershell
ssh root@<photon-builder-ip>
```

The Packer communicator uses the temporary `atlaso-build` user, port `22`, password authentication, and a longer SSH
timeout to allow Photon installation and reboot to finish. Provisioning removes the temporary sudoers entry before the
image is finalized.

Use `-var "switch_name=<switch>"` only if the replacement switch has a host adapter IP and internet access. The Atlaso
private service/site/trunk switches are intended for the finished appliance VM, not for the Packer installer VM.

Packer logs a line like `Host IP for the HyperV machine: 192.168.49.254`. That is the Windows host-side `Atlaso-Mgmt`
address used for the kickstart HTTP URL; it is not the Photon guest SSH address. The default Photon builder guest
address is `192.168.49.30`.

The build updates Photon packages during provisioning. On June 21, 2026, the Photon 5.0 updates repo exposed `python3`
as `3.14.5-2.ph5`; keep the image builder on the updated repo stream rather than relying only on the GA ISO package set.

If the VM stops at the Photon license agreement or disk selection screen, the builder did not load the kickstart file.
Stop the build, make sure this directory is current, and rerun `scripts/windows/hyperv/build-photon-image.ps1`. The
wrapper should print `Using remastered Photon ISO`, and the Packer log should wait for SSH without printing
`Typing the boot command...`. If Photon shows the EULA, the ISO did not include the Atlaso GRUB auto-install entry, or
the raw `packer build .` path or an old wrapper was used. Raw `packer build .` is intentionally blocked unless
`iso_contains_kickstart=true` is provided so this failure mode stops before a VM is created.

If Photon installs and SSH works from the Windows host but Packer remains at `Waiting for SSH to become available`,
query the IPv4 reported by Hyper-V:

```powershell
pwsh -ExecutionPolicy Bypass -File ..\..\scripts\windows\hyperv\get-atlaso-vm-ip.ps1 `
  -Name Atlaso-Photon-Builder `
  -SwitchName "Atlaso-Mgmt"
```

Then verify SSH:

```powershell
ssh root@<photon-vm-ip>
```

The Packer template sets `ssh_host` to the static builder address by default. If you override networking and SSH is
reachable but Packer still does not detect the guest IP, stop the build and rerun with a queried `ssh_host`:

```powershell
$photonVmIp = pwsh -ExecutionPolicy Bypass -File ..\..\scripts\windows\hyperv\get-atlaso-vm-ip.ps1 `
  -Name Atlaso-Photon-Builder `
  -SwitchName "Atlaso-Mgmt"

pwsh -ExecutionPolicy Bypass `
  -File ..\..\scripts\windows\hyperv\build-photon-image.ps1 `
  -SshHost "$photonVmIp" `
  -IsoUrl "https://packages.vmware.com/photon/5.0/GA/iso/photon-5.0-dde71ec57.x86_64.iso" `
  -IsoChecksum "sha512:6a7a258399a258da742032987c043ab25503698d35edafaf1ae000f12127da1a161d8b84caa17fd8f23d129e81e1faa7ab087c20ab9229772a643f8f9475305f" `
  -SshPassword "<one-time-build-root-password>" `
  -BootstrapAdminPassword "<initial-atlaso-admin-password>"
```

The helper reads the current Photon guest IPv4 from Hyper-V and filters out the host-side management switch address.

Photon's Hyper-V guest integration package is `hyper-v`. The kickstart and provisioning scripts install it and enable
`hv_kvp_daemon`, `hv_fcopy_daemon`, and `hv_vss_daemon` so Hyper-V can report guest metadata such as IP addresses. Do
not install `open-vm-tools` in this Hyper-V image; the VMware Workstation image path owns VMware guest tools. Keep the
`ssh_host` override as a fallback for early build runs where the guest IP is visible manually before Hyper-V reports it
to Packer.

## What Provisioning Installs

- Photon packages updated from the configured Photon 5.0 repositories, with a second `tdnf -y update` pass after
  required appliance packages are installed.
- `atlaso` system user.
- `/opt/atlaso` application install.
- `/etc/atlaso/atlaso.env` production environment file.
- `/etc/atlaso/build-info` recording build time, Photon release, kernel, Python, and the package update marker.
- A masked `systemd-ssh-generator` so Photon does not try to advertise or bind automatic SSH-over-AF_VSOCK sockets on
  Hyper-V. Normal TCP SSH remains provided by `sshd`. Root SSH login starts disabled through the Atlaso-owned
  `atlaso-root-login.conf` drop-in and can be enabled from Appliance Settings, then enforced through global appliance
  apply.
- `/var/lib/atlaso` durable SQLite state.
- `/var/log/atlaso` local service logs.
- Fixed appliance mounts under `/mnt/atlaso-vcf-*`.
- `/etc/systemd/system/atlaso.service`.
- `/etc/systemd/system/atlaso-firewall.service` loading the nftables management firewall.
- `dnsmasq` for the shared DNS/DHCP appliance service.
- `ipxe` and `syslinux` for Network Boot bootstrap support. Provisioning also stages Atlaso's bundled iPXE first-stage
  files, `undionly.kpxe` and `snponly.efi`, under `/var/lib/atlaso/pxe/bootloaders` because the Photon package stream
  may not ship those filenames. TFTP.
- `/opt/atlaso/bin/atlaso-helper` constrained appliance helper.
- `/etc/sudoers.d/atlaso-helper` permitting the service user to run only the constrained helper binary as root.

The generated appliance keeps `ATLASO_DRY_RUN_SYSTEM_ADAPTERS=true` until each helper-backed apply unit is reviewed and
promoted. Provisioning writes both `ATLASO_SECRET_KEY` and `ATLASO_SECRETS_KEY`; the latter encrypts CA root and leaf
private-key material stored in the Atlaso database and must be preserved for settings backup portability. Appliance
Update is runtime maintenance and stays separate from desired-state `/ui/management/appliance-apply`. It stages
`/var/lib/atlaso/apply/appliance-update/atlaso-update.json` and uses `atlaso-helper appliance-update` for Photon OS,
PowerShell modules, and signed Atlaso releases. Provisioning installs the named Ed25519 trust keys under
`/etc/atlaso/update-trust.d` and creates the versioned `/opt/atlaso/releases/<version>` layout with `current` and
`.venv` compatibility symlinks. Release updates verify signed channel and release manifests, build from a hash-locked
offline ABI wheelhouse, atomically switch the release, and restore the previous release and SQLite snapshot on failure.
Manual and scheduled checks/installations retain one parent task with separate Atlaso Release, PowerShell Modules, and
Photon OS child steps; failed earlier streams leave Photon explicitly skipped instead of ambiguously pending. The Packer
build explicitly stages `image/common/update-trust` and fails if no valid public key is available, so a completed image
cannot silently reject the published signed channels as untrusted. Photon updates fail closed when their candidate
Python ABI is not in the active release. Candidate discovery uses the Photon-supported `tdnf repoquery python3` form.
Photon maintenance never performs automatic RPM rollback or reboot. Pass
`-SignedReleaseRepositoryUrl https://<fixture>/updates` to `scripts/windows/hyperv/invoke-lifecycle-test.ps1` to add a
signed preview upgrade and deliberately broken development-channel rollback. The fixture contract and database/service
assertions are documented in [`docs/appliance-update.md`](../../docs/appliance-update.md). The image also enables
`atlaso-worker.service`, which owns queued updates, VCF Offline Depot downloads, five-field cron/one-time schedules, and
unprivileged managed-script execution. Firewall desired state is nftables-backed. Provisioning installs nftables, loads
`/etc/atlaso/nftables.d/atlaso.nft`, and disables the older Photon iptables service so Atlaso has a single firewall
owner.

DNS/DHCP desired state is dnsmasq-backed. Real `/ui/management/appliance-apply` stages the rendered config under
`/var/lib/atlaso/apply/dnsmasq/`, validates it with `dnsmasq --test`, installs `/etc/atlaso/dnsmasq.d/atlaso.conf`, and
reloads or restarts `dnsmasq` through `atlaso-helper`. The rendered config uses `/var/lib/atlaso/dnsmasq/dhcp.leases`
for DHCP leases, and the helper exposes only that allowlisted lease readback path. DHCP scopes should bind to access
physical interfaces with IP CIDR or enabled VLAN interfaces with IP CIDR, not trunk or addressless physical interfaces.
Network Boot settings add dnsmasq TFTP and DHCP bootfile options for the guide-aligned flow: first-stage
`undionly.kpxe` or `snponly.efi`, then second-stage `pxelinux.0` or `mboot.efi` when DHCP detects iPXE. Optional native
UEFI HTTP clients receive the generated absolute `mboot.efi` URL. The generated TFTP files, extracted ESXi installer
HTTP tree, per-host `boot.cfg` files, and dedicated static PXE HTTP listener are written only by global appliance apply.
The image build also produces and stages the pinned Buildroot-based Atlaso
Inventory Linux initramfs under
`/var/lib/atlaso/pxe/media/inventory/<version>`. Unknown hosts enter the generic
HTTP menu and default to this read-only RAM environment. Apply DNS/DHCP,
Network Boot (`esxi_pxe` internally), and Firewall together when boot settings
change.

Certificate Authority desired state is Atlaso CA-backed. Real `/ui/management/appliance-apply` stages
`/var/lib/atlaso/apply/ca/atlaso-ca.json`, validates the staged CA/certificate payload through `atlaso-helper`, and
writes public CA bundles plus service certificate/key files under `/etc/atlaso`. Private keys are encrypted in the
database with `ATLASO_SECRETS_KEY`; previews, jobs, and logs must remain redacted.

KMS / KMIP desired state is PyKMIP-backed for lab compatibility testing. Real `/ui/management/appliance-apply` stages
`/var/lib/atlaso/apply/kms/pykmip.conf`, requires an enabled healthy CA with issued KMS server/client certificates,
installs `/etc/atlaso/kms/pykmip.conf` and `/etc/pykmip/server.conf`, and manages `atlaso-kms.service`. The service
launches PyKMIP through Atlaso's compatibility wrapper for current Photon Python streams. The KMS listener binds to the
IP derived from the selected access physical interface or enabled VLAN. Disabling KMS stops and disables the service
while preserving `/var/lib/atlaso/kms/pykmip.db`.

Local Users desired state is Photon OS account-backed. Real `/ui/management/appliance-apply` stages
`/var/lib/atlaso/apply/local-users/atlaso-users.json`, validates Atlaso-owned local usernames, creates or updates
enabled users under `/var/lib/atlaso/users` with the per-user desired shell, removes disabled or removed managed users
with `userdel -r`, applies staged unlock requests with `passwd -u` and `faillock --reset`, writes the desired
PAM/pwquality password policy, and sends in-memory pending passwords to `chpasswd` over stdin. Password previews, job
results, and logs should show only status and counts. `atlaso.service` preserves `ATLASO_HELPER_USE_SYSTEMD_RUN=1`
through sudo so account-mutating helper commands can run as transient systemd units outside the control-plane service
sandbox while still using the constrained helper allowlist. Nginx owns the public management front door. Appliance
Settings apply writes `/etc/nginx/conf.d/atlaso.conf`, `/etc/atlaso/nginx/sites.d/management.conf`, and a loopback-only
`atlaso.service` override. Fresh appliances run `atlaso-bootstrap-https.service` on deployed-VM first boot to enable the
integrated CA, issue the managed `appliance:https` certificate, and start with nginx redirecting public HTTP/80 to
HTTPS/443 while reverse-proxying HTTPS to uvicorn on `127.0.0.1:8000`. The root CA is not baked into the reusable image.
When HTTPS is disabled, including after the dedicated complete factory-reset transaction, nginx can serve public
HTTP/80 as a plain reverse proxy to the same loopback upstream, but that is not the first-boot appliance posture. The
helper proves the Atlaso loopback upstream before publishing the candidate, daemon-reloads systemd without restarting
the active worker, then validates and reloads nginx. Consecutive post-activation loopback and management front-door
readiness checks must pass; otherwise the helper restores the previous nginx and systemd files and keeps the known-good
management front door active.

Before uvicorn starts, `atlaso.service` asks the constrained helper to resume a durable
`/var/lib/atlaso-privileged/factory-reset/request.json` marker. An interrupted complete reset therefore finishes before
the
management plane becomes available; an appliance without a marker takes the no-op path.

Appliance Settings also owns the root SSH login switch. The image provisions
`/etc/ssh/sshd_config.d/atlaso-root-login.conf` with `PermitRootLogin no`; global appliance apply rewrites that
Atlaso-owned drop-in, validates `sshd`, and restarts `sshd` when the operator enables or disables root SSH.

Provisioning creates the bootstrap admin OS account under `/var/lib/atlaso/users/<admin>` with `/usr/bin/pwsh` and sets
the same bootstrap password used for the initial web login, so the admin account exists on Photon before first appliance
apply. The image installs Photon's `powershell` package for this shell, installs system-wide VCF PowerCLI
`9.1.0.25380678`, disables and verifies PowerCLI CEIP participation at `AllUsers` scope, verifies the module and
`Connect-VIServer` from the unprivileged bootstrap administrator's PowerShell session, installs `vcf-sdk==9.1.0.0` in
the Atlaso virtualenv, and grants the bootstrap admin normal password-backed sudo through
`/etc/sudoers.d/atlaso-bootstrap-admin`. The system PowerShell module tree remains root-owned and writable only by root,
while every local `/usr/bin/pwsh` user can read and import its modules. Before a PSGallery install, the shared
provisioner expands Photon's build-time `/tmp` tmpfs to 4 GiB so dependency extraction does not exhaust its default
capacity; the deployed appliance returns to Photon's normal `/tmp` sizing after reboot.

VCF Backups desired state is OpenSSH-backed. Provisioning leaves the default `vcf-backup` account absent from Photon OS
until Local Users apply creates it. When VCF Backup desired state is off, Atlaso keeps the default `vcf-backup` user
disabled so the next Local Users apply removes the Photon OS account. Real `/ui/management/appliance-apply` stages the rendered
drop-in under `/var/lib/atlaso/apply/vcf-backups/`, validates that it is a Atlaso-rendered `Match User` config for an
existing OS account, installs `/etc/ssh/sshd_config.d/atlaso-vcf-backups.conf`, prepares the fixed
`/mnt/atlaso-vcf-backups` chroot and `/backups` upload directory, and restarts `sshd` through `atlaso-helper`. Firewall
apply still owns the selected interface and port allow rule. Apply Local Users first when the selected SFTP user is new,
disabled/enabled, has a pending password, changes shell, or has an unlock request.

The firewall preview derives Atlaso-managed service allow rules from enabled service listener desired state, including
management, DNS, DHCP, KMS, NTPsec, VCF Backup, VCF Offline Depot, and VCF Private Registry listeners. DHCP VLAN moves
or service listener moves should be applied with the changed Firewall unit when `/ui/management/appliance-apply` shows
it pending.

Before shutdown, provisioning resets the exported appliance image from the temporary Packer builder network to the
Atlaso management network:

- appliance address: `192.168.49.1/24`;
- appliance interface: `eth0`;
- host-side `Atlaso-Mgmt` address: `192.168.49.254/24`;
- default gateway: `192.168.49.254`.

The generated `00-atlaso-mgmt.network` matches only `eth0`. Provisioning removes the Photon installer's broad
`50-static-en.network` and `99-dhcp-en.network` defaults so non-management NICs remain opt-in through Atlaso desired
state and global appliance apply.

The Hyper-V switch script configures the host-side management address and NAT so the final appliance can reach Photon
repositories when the Windows host has internet access.

Windows NAT for the management switch is configured with:

```powershell
New-NetIPAddress -InterfaceAlias "vEthernet (Atlaso-Mgmt)" -IPAddress 192.168.49.254 -PrefixLength 24
New-NetNat -Name Atlaso-Mgmt-NAT -InternalIPInterfaceAddressPrefix 192.168.49.0/24
```

Use `scripts/windows/hyperv/create-switches.ps1` instead of running those by hand; it creates or repairs the address/NAT
and prints the resulting summary.

Packer uploads only the files required for appliance installation: the `atlaso` package, packaging metadata, appliance
helper scripts, the Photon compatibility check, systemd unit, sudoers template, shared udev disk-identity rule, and
Hyper-V data-disk policy. The shared provisioner validates and installs both disk-policy inputs from the staged source
tree before the application sync populates `/opt/atlaso`. It intentionally does not upload `.git`, test artifacts,
caches, or development virtual environments into the builder VM.

## Boot The VHDX

After Packer completes, create and start the test appliance VM with the wrapper:

```powershell
pwsh -ExecutionPolicy Bypass -File scripts/windows/hyperv/create-atlaso-test-vm.ps1 -WaitForIp
```

The wrapper finds the latest appliance VHDX under `image/hyperv/output`, prepares the Atlaso Hyper-V switches, creates
`Atlaso`, starts it, and prints the management IP when `-WaitForIp` is used. If `Atlaso` already exists, pass
`-Redeploy` to remove and recreate only that VM, or pass `-Name` to create a separate test VM.

The sample VM keeps the first adapter management-only on `Atlaso-Mgmt`. The second adapter is `Services` on the
dedicated `Atlaso-Services` switch as untagged service traffic for DNS, DHCP, CA, depot, PXE, KMS, and other
Atlaso-managed services. The wrapper also adds `SiteA` on `Atlaso-SiteA` as trunk VLAN 12, `Trunk` on `Atlaso-Trunk` as
trunk VLAN 50, and `WAN-Test` on `Atlaso-SiteB` as untagged WAN test traffic. Pass `-SkipLabNetworkAdapters` only when
you intentionally need a management-only VM.

For a clean appliance data start, also pass `-ResetDataDisks`. The wrapper removes the default Depot and Backups data
VHDX files next to the selected OS disk, then lets `create-atlaso-vm.ps1` create fresh empty data disks:

```powershell
pwsh -ExecutionPolicy Bypass -File scripts/windows/hyperv/create-atlaso-test-vm.ps1 -Redeploy -ResetDataDisks -WaitForIp
```

The finished appliance VM gets two additional dynamic VHDX data disks by default:

- `Atlaso-Depot.vhdx`, intended for `/mnt/atlaso-vcf-offline-depot`;
- `Atlaso-Backups.vhdx`, intended for `/mnt/atlaso-vcf-backups`.

Use `create-switches.ps1`, `create-atlaso-vm.ps1`, and `start-atlaso-vm.ps1` directly only when you need to control each
step by hand.

The data disks are fixed-size dynamic 500 GiB VHDX files stored next to the OS VHDX by default. Override their paths
with `-DepotVhdxPath` or `-BackupVhdxPath`; the size parameters reject any value other than 500 GiB. The deployment
helper assigns the depot to SCSI controller 0 location 1 and backups to location 2. On first boot,
`atlaso-data-disks.service` requires those exact guest-visible SCSI identities, their topology-derived
`atlaso-path-*` links, and exact capacities before formatting either disk. Missing, extra, reordered, ambiguous, or
mismatched disks fail closed before `mkfs`. Correctly labeled ext4 disks remain idempotent, are written to `/etc/fstab`
by UUID, and mount before the Atlaso control plane starts. After both fixed disks are initialized, additional disks are
accepted only as positively identified Atlaso-managed ESX Storage volumes; claimed existing ext4 disks require stable
whole-disk identity, UUID-backed fstab persistence, and a root-owned claim. Disk-preflight failure blocks nginx, the
HTTPS bootstrap, Atlaso control plane, and worker.

## Appliance Smoke Checks

Inside the Photon VM:

```bash
python3 --version
cat /etc/atlaso/build-info
ip addr show
tdnf check-update || true
systemctl status atlaso --no-pager
journalctl -u atlaso -n 100 --no-pager
curl -fsS http://127.0.0.1:8000/openapi.json >/dev/null
curl -fsS http://127.0.0.1:8000/api/v1/dashboard >/dev/null || true
```

From the host, verify the management URL, login, reboot persistence, and that `/ui/management/appliance-apply` still
records dry-run
command intent before any real adapter execution is enabled.

If the VM console prints `systemd-ssh-generator: Failed to query local AF_VSOCK CID: Cannot assign requested address`,
the appliance is hitting systemd's automatic SSH-over-vsock discovery path. Atlaso does not use SSH-over-vsock, and
current image provisioning masks that generator while keeping regular TCP SSH available. On an already-built VM, apply
the same cleanup as root and reboot:

```bash
install -d -o root -g root -m 0755 /etc/systemd/system-generators
ln -sfn /dev/null /etc/systemd/system-generators/systemd-ssh-generator
systemctl daemon-reload
reboot
```
