# Atlaso Photon OS VMware Workstation Image

The base image includes Python `vcf-sdk==9.1.0.0` and system-wide `VCF.PowerCLI==9.1.0.25380678`. Provisioning fails if
PowerCLI cannot import or `Connect-VIServer` is unavailable to the unprivileged bootstrap administrator. Provisioning
also disables and verifies PowerCLI CEIP participation at `AllUsers` scope; Appliance Settings can change that central
preference after deployment without product-specific prompts. The system module tree remains root-owned and writable
only by root, while every local `/usr/bin/pwsh` user can read and import its modules. Set
`ATLASO_POWERCLI_MODULE_SOURCE` to a pre-staged module directory for offline image builds; otherwise PSGallery is used.
Before a PSGallery install, the shared provisioner expands Photon's build-time `/tmp` tmpfs to 4 GiB so PowerCLI's
dependency extraction does not exhaust the default memory-backed temporary filesystem. The deployed appliance returns
to Photon's normal `/tmp` sizing after reboot.

The current Photon package installs the PowerShell executable and system-wide profile under
`/usr/share/powershell`. The shared provisioner also recognizes the reviewed legacy
`/opt/microsoft/powershell/7` layout. It resolves the executable by canonical filesystem identity, requires root-owned
non-writable profile ancestry, promotes the checked-in profile to a root-owned runtime source, and atomically installs
the root-owned mode-`0644` Atlaso profile. Any other layout, directory symlink, writable ancestry, unsafe source, or
existing profile symlink fails the image build instead of being followed.
If an update moves `pwsh` between the two admitted homes, the provisioner and wheel deployer remove the inactive
profile only when its directory chain and exact Atlaso-owned bytes, ownership, and mode are proven; otherwise they fail
closed and preserve the unexpected content.

This target builds the canonical Photon OS 5.0 VMware Workstation VMX/VMDK appliance. Its validated payload is also the
source for the unchanged KVM and Proxmox VE OVA import and the converted Hyper-V ZIP. Fresh appliances enable the
integrated CA on deployed-VM first boot, serve the management console/API over CA-backed HTTPS/443, and keep
management HTTP/80 redirect-only. Network Boot remains the only served HTTP payload.

## Prerequisites

- PowerShell 7.4 or newer (`pwsh`). Earlier PowerShell releases and Windows PowerShell 5.1 (`powershell.exe`) are not
  supported.
- WSL 2 installed and initialized before provisioning the default `Atlaso-Build` image-build distribution. See
  [Windows image-build WSL environment](../../docs/contribute/windows-image-build-wsl.md).
- VMware Workstation Pro with `vmrun.exe` available under `C:\Program Files\VMware\VMware Workstation`.
- VMware Workstation's bundled OVF Tool with `ovftool.exe` available under
  `C:\Program Files\VMware\VMware Workstation\OVFTool` when exporting OVF/OVA artifacts.
- Packer `>= 1.10`.
- `qemu-img` when preparing the tiny Alpine lifecycle client VMDK or exporting portable virtualization artifacts.
- Photon OS 5.0 ISO URL and checksum.
- At least 70 GiB free on the filesystem holding the Packer output. Final zero-filling temporarily expands both sparse
  payload VMDKs before compaction reclaims the zeroed blocks.

The template uses the Packer VMware Desktop plugin:

```hcl
source = "github.com/vmware/vmware"
version = "= 2.1.5"
```

The supported wrapper runs `packer init` and `scripts/check_packer_plugins.py` before validation or build. The exact
`2.1.5` pin therefore resolves the same reviewed binary from an empty plugin directory or a warm cache. For a manual
template check from this directory, run `packer init .` and then
`python ../../scripts/check_packer_plugins.py .`. Update the HCL pin, tests, and this documentation together when
reviewing a plugin update.

From the repository root, `python scripts/check_deployment_assets.py --mode packer` performs that initialization plus
exact selected-binary verification, formatting, and full wrapper-equivalent validation for the VMware Workstation
template. Canonical CI runs the same protected inventory on its Windows Packer runner.

## Build

Use the wrapper instead of raw `packer build`; it creates the remastered Photon ISO with `photon-ks.json` and the Atlaso
GRUB auto-install entry. The original Photon source ISO is cached under `image/common/source`; only the remastered
kickstart ISO is written under this image directory as a temporary sensitive artifact. The wrapper removes it and
verifies its absence after the bounded Packer validation or build exits, including failure paths. `-PrepareIsoOnly` is
rejected because retaining that ISO would retain a reusable build credential. A fresh build starts with an empty
task-owned cleanup ledger; the remaster helper records each unique partial path before writing and records the final
path only after replacement preflight succeeds. `New-AtlasoPhotonKickstart` in
`scripts/windows/common/Atlaso.PhotonImage.psm1` is the only kickstart source. Focused image tests parse its VMware JSON
output and validate the installer, package, and guest-service contract.
At shutdown, Packer schedules the root-only image finalizer from `/opt/atlaso/bin`, the same boundary as other
Atlaso-owned Photon helpers. Packer retains its SSH communicator while it polls for poweroff, so the detached finalizer
captures the exact disposable build-account UID, gives only that UID a bounded graceful termination window, and uses a
bounded forced termination only for survivors. It then verifies the session is gone, removes the temporary build
account and authorization, deletes both its staged source and installed copy, syncs the filesystem, and powers off.
Workstation builds show the VMware console by default so boot/install progress is visible; pass `-Headless` for
unattended runs. For the default GUI build, the wrapper first repairs any exact missing Atlaso registration inside the
configured output scope while the Workstation UI is closed, then starts or reuses a responsive Workstation UI before
Packer invokes `vmrun`. The later full output cleanup retains its existing checked post-network-preflight boundary.
Starting the UI as a separate process prevents the Workstation GUI start transition from retaining Packer's redirected
output handles after the builder is already running. Do not replace this ordering with an arbitrary delay or a raw
`packer build` invocation. If Workstation was already open and a scoped stale registration needs repair, the wrapper
still fails with the exact close-the-UI diagnostic instead of weakening inventory safety.

The wrapper emits sanitized startup heartbeats until Packer reaches SSH provisioning. Each heartbeat binds diagnostics
to the expected builder VMX filesystem identity and distinguishes missing or replaced output, an unavailable provider,
a VM that is not running, closed TCP/22, a stalled Workstation start handoff, and pending SSH authentication. The
default `-PackerStartupTimeoutSeconds 2700` matches Packer's 45-minute SSH communicator allowance and bounds the
interval from monitored Packer process start to SSH provisioning, including failures before the VMX or power-on phase
exists; `-PackerHeartbeatSeconds 30` controls the heartbeat interval. When `-SshHost` is explicit, TCP/22 diagnostics
probe that Packer communicator endpoint instead of the temporary static builder address. A timeout terminates only the
Packer process tree and
routes `-PackerOnError cleanup` through the checked exact-root cleanup. `-KeepExistingOutput` protects an output root
that existed before this invocation, and an ordinary replacement does not become parent-cleanup-owned until the child
durably claims it immediately before checked removal. A newly created partial root is still removed after a proven
outer timeout.
Other failure modes preserve the builder artifacts for diagnosis. Raw Packer debug-log environment variables are
removed from the monitored child because those
logs bypass output redaction. Console lines that can contain generated connection credentials are redacted before they
are displayed. Workstation may atomically rewrite the VMX during power-on; the monitor accepts a new file identity only
when exact provider inventory proves that the expected VMX path is the running builder.

The shared provisioner stages `pyproject.toml` with `scripts/version.py`, parses `[project].version` as
TOML, and requires the repository's strict `X.Y.Z` release format before it creates
`/opt/atlaso/releases/bootstrap-<version>`. If that metadata is missing, unreadable, malformed, or invalid, the build
log reports the specific version-policy error. After installation, the provisioner requires `/opt/atlaso` itself to
remain the exact physical installation root, then resolves the complete compatibility chain and requires
`/opt/atlaso/current` to identify that exact physical bootstrap release,
`/opt/atlaso/.venv` to identify its exact physical virtual environment, and the interpreter's CPython 3.14 `purelib`
to identify that environment's physical `site-packages`. Broken, redirected, wrong-version, or escaping links fail with
bounded actual/expected path diagnostics; services continue to use the supported `/opt/atlaso/.venv` compatibility
path. The remastered kickstart disables `sshd.socket` and enables
`sshd.service`. Photon must not enable both conflicting units: the normal daemon provides deterministic
password-authenticated SSH for Packer after the installed-system boot. The Photon root/build password remains separate
from the Atlaso web bootstrap administrator password. The shared wrapper encodes that build credential before every
kickstart or Packer shell boundary and decodes it only to standard input, so apostrophes and common PowerShell or POSIX
shell metacharacters remain credential data instead of executable syntax. The template also stages
`requirements-appliance.lock` with the
application source so bootstrap dependency installation retains hash verification instead of falling back to unpinned
packages. It stages the third-party notice generator, vendored-component inventory, and Inventory Linux README used by
that inventory as mandatory build inputs rather than skipping notice generation when any input is missing. The shared
PowerShell profile is staged with the other common
image assets so provisioning can install the interactive `Get-AtlasoVault` helper. Notice lock verification inventories
only top-level virtual-environment distributions and ignores package-internal vendored metadata. Long TDNF operations
emit compact 30-second heartbeats with elapsed time and cache size instead of streaming terminal progress redraws
through Packer. Successful operations report their duration. Failures preserve a nonzero TDNF exit status and replay a
normalized, bounded output tail; a zero-status transcript that reports a TDNF error or disabled repository is promoted
to fatal exit status 1. The zero-status error scan streams the transcript line by line so long successful transactions
do not require another full in-memory copy after TDNF exits.
Before that first refresh, the shared provisioner validates the stock Photon 5 updates definition, `gpgcheck=1`, and
one of the repository-pinned byte serializations of its installed 4096-bit RPM signing key. It then probes bounded
metadata from the exact current
`packages.broadcom.com/photon/$releasever/...` endpoint, and atomically replaces the retired GA repository layout.
Unexpected sources, disabled GPG checks, missing or substituted key material, redirects, unreachable metadata, and
malformed metadata all fail the build before TDNF runs.
Photon 5.0 packages the C and C++ compiler front ends together as `gcc`. The image requests and later removes that one
build-only package; it does not request the unavailable `gcc-c++` name used by distributions that split the front ends.
It also treats `binutils` and `linux-api-headers` as build-only because Photon packages the assembler, linker, and Linux
userspace headers separately from the compiler. The QEMU configuration probe includes GLib before it checks native type
sizes; without `linux-api-headers`, the missing `linux/limits.h` compile error is otherwise reported as a misleading GLib
metadata mismatch. A configure failure prints only the bounded tail of QEMU's Meson log and never dumps the guest
environment. Packer invokes the shared provisioner through `sudo -E`, but the QEMU RPM builder replaces the preserved
communicator `HOME` and pip cache with root-owned, mode-`0700` directories inside one identity-bound invocation root
before `configure` can start `mkvenv`. It clears inherited `PIP_*` and `XDG_CONFIG_HOME` values, pins pip to the
generated root-owned configuration, and then restores only the admitted index without echoing it. Exit cleanup
removes only that invocation root. The RPM builder copies QEMU 10.2's linked guest agent from its `build/qga` target
directory.
Because that Atlaso-built RPM is not a repository-signed package, the provisioner downloads its `glib` and `systemd`
runtime dependency closure in a separate signature-checked Photon transaction, then stages the pinned local RPM
directly. No transaction bypasses repository GPG checks, and the completed root-owned offline closure remains bound by
its generated SHA-256 manifest.

Packer also stages the shared udev disk-identity rule and virtualization data-disk policy. The shared provisioner validates
and installs both from the staged source tree before the application sync populates `/opt/atlaso`, so this early
disk-safety setup never depends on files that have not been copied yet.
Directory uploads for shared scripts and provider-neutral guest agents target paths beneath
`/tmp/atlaso-src/image/common`. The initial staging command creates only that parent; pre-creating either exact upload
destination would make Packer nest the source directory and leave the provisioner without its expected assets.

```powershell
pwsh -ExecutionPolicy Bypass `
  -File scripts/windows/vmware/build-photon-image.ps1 `
  -PullRequestNumber <number> `
  -IsoUrl "https://packages.vmware.com/photon/5.0/GA/iso/photon-5.0-dde71ec57.x86_64.iso" `
  -IsoChecksum "sha512:<checksum>"
```

Task builds require an open same-repository pull request whose head branch and commit exactly match the checkout. The
wrapper derives `Atlaso-PR-<number>-Photon-Builder-VMware[-<collision-safe-suffix>]`; use `-CollisionSuffix` when one
PR owns multiple simultaneous builders. That exact identity becomes the Packer `vm_name`, Workstation `displayName`,
output-directory leaf, VMX filename/path, address-reservation identity, startup diagnostic identity, sibling ownership
manifest, provenance identity, cleanup target, and reported evidence. Missing, malformed, fork-owned, stale-head,
generic, or differently owned identities fail before provider or target-output mutation. Protected release production
uses a distinct deterministic version-and-commit builder identity, optionally extended by workflow run ID.

`-SshPassword` and `-BootstrapAdminPassword` accept only `SecureString` values and remain independently authoritative.
When either is omitted, the wrapper verifies the exact Atlaso 1Password Environment selected by an explicit
`-OnePasswordEnvironmentId` or by the checkout-local, Git-ignored
`.atlaso-local/onepassword-environment-id` file, then retrieves only the corresponding concealed
`DEFAULT_ROOT_PASSWORD` or `DEFAULT_ADMIN_PASSWORD` through the bounded Windows 1Password SDK bridge. A custom
single-line selector file may be passed with `-EnvironmentIdFile`; the legacy `-OnePasswordEnvironmentIdFile` spelling
is an alias. The wrapper uses the single account returned by the local 1Password CLI and the highest compatible
CPython 3.10 through 3.13 runtime registered with the Windows launcher. Discovery accepts current Python Install Manager
inventory selectors such as `-V:3.13[-64]` while retaining legacy launcher and vendor-tagged runtime support; known x86
runtimes and unsupported versions remain ineligible. Pass `-OnePasswordAccount` or
`-OnePasswordPython` only to override that deterministic discovery. Zero or multiple accounts and a missing compatible
runtime fail closed before image mutation.

There are no interactive prompts, caller-environment fallbacks, repository password defaults, or local `.env` inputs.
Missing, ambiguous, non-concealed, invalid, unauthorized, or timed-out 1Password state fails with sanitized guidance
before VMware network preparation, output cleanup, ISO remastering, Packer initialization, or other image mutation.
The retrieval bridge returns only current-user DPAPI ciphertext to the PowerShell parent. That parent starts the whole
plaintext-consuming image workflow as a separately bounded PowerShell child, passes credentials only through a second
current-user DPAPI bundle, and verifies removal of both task-owned roots. Only the child unwraps validated
`SecureString` values at the kickstart and Packer serialization boundary. The wrapper places the kickstart, remastered
ISO, and secret-bearing Packer variable file inside that exact task-owned root, so parent cleanup still removes and
verifies them after a whole-tree timeout kills the child before its normal `finally` blocks can run.
The credential bridge, immutable source snapshot, Packer workspace, remastered ISO, cleanup marker, and VMware
builder-address release handoff all live beneath checkout-local `.atlaso-local/photon-image-build-state`. An explicit
`-BuildStateRoot` is accepted only as a strict non-reparse-point descendant of the exact task repository. The wrapper
never creates new task build state through Windows `TEMP`, `LocalApplicationData`, a profile directory, or a different
volume. The address allocator retains one non-task-owned per-user lock and ledger under `LocalApplicationData` so
concurrent worktrees cannot reserve the same VMware address. Recovery may read and retire an exact pre-migration marker
or matching address handoff from former roots, but it never adopts them for a new task handoff or touches another
repository or canonical builder identity.
`-ImageBuildTimeoutSeconds` bounds the whole child and defaults to six hours.
If Windows cannot prove whole-tree termination, the wrapper retains the root plus a non-secret checkout-local cleanup
marker and fails closed. Restart Windows and rerun the wrapper; the changed boot identity proves the prior tree is
inactive, allowing exact-root cleanup and marker removal before any new credential access or image mutation.
Immediately before recursive recovery deletion, the wrapper revalidates the complete admitted parent and cleanup-root
ancestry and refuses any junction, symbolic link, or other reparse point introduced after marker admission.
The shared SDK bridge uses the same boot-bound recovery rule. Both marker types are write-through flushed and
atomically renamed before a plaintext child starts. After root removal, the wrapper flushes deletion metadata through
the root parent's Windows directory handle on that same volume before it durably records root absence and a retired
tombstone in the marker. A crash therefore cannot preserve marker retirement while resurrecting credential-bearing
files from a different volume.

The wrapper does not build or embed Inventory Linux. New templates leave it uninstalled so an administrator can use
**Download latest** to retrieve the signed independent release when needed. Contributors building Inventory Linux
itself use `scripts/windows/common/Build-AtlasoInventoryLinux.ps1` and its `-WslDistribution <name>` option.

Before `packer build -force` replaces the Workstation output directory, the wrapper routes every in-root VMX through the
checked cleanup module. The module validates the exact non-reparse-point output root, captures its filesystem identity
and contents, stops running targets, and uses checked `vmrun deleteVM` only for existing registered targets. It detaches
VMDKs resolved outside the exact root before provider deletion so shared depot, backup, and other external disks remain
protected. A new or replaced root entry blocks recursive removal, and any failed provider transition preserves the
remaining artifacts. Already-stopped and already-unregistered targets are idempotent.

Unrelated Workstation library state is not a cleanup prerequisite. `inventory.vmls` is read only for an exact in-scope
registration and for the exceptional stale Atlaso row whose VMX is already missing. With the Workstation UI closed, that
narrow fallback removes only the scoped stale record after a byte comparison and leaves unrelated malformed, missing,
or inconsistent registrations untouched.

For lifecycle/demo images that should use real appliance adapters:

```powershell
pwsh -ExecutionPolicy Bypass `
  -File scripts/windows/vmware/build-photon-image.ps1 `
  -PullRequestNumber <number> `
  -IsoUrl "<photon-iso-url-or-path>" `
  -IsoChecksum "<packer-checksum>" `
  -EnableRealSystemAdapters
```

The built VMX keeps the first adapter on `-VmnetName` as management-only and adds a second `vmxnet3` adapter on
`-ServiceVmnetName` for service traffic. The service network defaults to Workstation's built-in host-only `VMnet1`. The
Packer creates a 40 GiB Photon OS disk and a sparse 20 GiB Atlaso system-content disk. Provisioning formats the second
disk as `ATLASO_SYSTEM`, mounts it by UUID, and places `/opt/atlaso` plus the appliance-wide PowerShell modules there.
The remastered Photon kickstart discovers the install target by its exact VMware SCSI `0:0:0` topology instead of an
enumeration-dependent `/dev/sdX` name. Before formatting the system-content disk, provisioning resolves the complete
root block-device dependency chain, requires the Photon root disk at `0:0:0`, requires the blank 20 GiB system disk at
`0:1:0`, and requires exactly those two payload disks. A missing, ambiguous, reversed, mislabeled, or capacity-mismatched
layout fails the image build before it can become a reusable artifact.
The two 500 GiB application data disks remain empty OVF declarations, so the reusable builder contains no large blank
data-disk payloads. After compatibility validation, the build removes the QEMU build toolchain with TDNF dependency
auto-removal disabled. It then requires valid `/etc/os-release` and `/etc/photon-release` files, verifies TDNF's
effective `distroverpkg` RPM (the explicit setting or Photon's `photon-release` default) plus the Photon, RPM, TDNF,
Python, PowerShell, and VMware guest-agent runtime packages,
and performs a fatal cache cleanup, repository refresh, and final Photon update before checking that runtime state
again. The post-update check re-resolves the installed `pwsh` runtime home and reinstalls Atlaso's global profile there,
retires a safely identified Atlaso profile from the inactive supported home, then rewrites build information with the
kernel selected by Photon's default boot entry and the final PowerShell,
PowerCLI, and VCF SDK versions. The final PowerCLI proof runs as the bootstrap administrator and requires
`Connect-VIServer`, not merely a root-owned module import. Only then does it clear build caches and staged sources. It
fails before writing build information if the default boot entry or its kernel image cannot be resolved. It
repeats and verifies the SSH host-key and machine-ID scrub after the final package
transaction so package scriptlets cannot leave reusable build-time identity behind, then zero-fills free blocks on both
payload filesystems while
retaining a 512 MiB safety reserve, delete the fill files, request TRIM, and let Packer compact both payload VMDKs.
Zero-filling makes compaction deterministic even when the VMware virtual disks do not advertise discard. After a
successful build, the wrapper writes a schema-v3 provenance
JSON file beside the VMX. Before any Workstation, ISO, Packer, output, or image mutation, the parent requires a
completely clean checkout,
archives its exact commit into the invocation-owned sensitive-build root, removes the build identity's write access,
and launches the bounded child from that snapshot. The exact HCL template and every Packer file and shell source resolve
beneath the protected snapshot instead of the operator checkout. The
wrapper verifies the deterministic full-snapshot file-count and SHA-256 inventory before Packer and again before
provenance emission. The wrapper records the exact source commit, tracked-source state, immutable snapshot identity,
and the verified role, SCSI unit,
virtual capacity, SHA-256 hash, and byte size for the VMX and both VMDKs. Test-VM cloning and OVF export require that
exact role-bound provenance plus the matching builder identity, output leaf, VMX filename, and `displayName`, so an
older unproven image or a later reversed/tampered/differently owned payload is rejected before cloning or export output
replacement. A sibling `*.builder-identity.json` ownership manifest must prove the same repository, pull request,
branch, canonical name, and suffix before checked replacement can advance it to a newer exact head. Retained reuse
still requires the exact commit, and a legacy generic or differently owned builder is never adopted automatically.
Moving `HEAD`, editing tracked files, or adding untracked inputs after snapshot admission through the supported wrapper
cannot change the admitted build inputs; a dirty or ambiguous checkout fails before Workstation, ISO, Packer, or output
mutation. The Windows producer remains a trusted build boundary: snapshot ACLs and the independent commit re-export
protect ordinary workflow consistency, but do not claim to sandbox a process already running with the producer's own
Windows identity. Protected hosted finalization retains its independent artifact and source-binding checks without
claiming to authenticate the entire filesystem of a compromised producer.

## Networking

The default Workstation builder and lifecycle scripts expect:

- management: `VMnet8`, with the Atlaso appliance address assigned by DHCP by default
- services: `VMnet1`
- SiteA: `VMnet2`
- WAN/SiteB: `VMnet3`
- trunk-like validation segment: `VMnet4`

Validate the current Workstation network inventory with:

```powershell
pwsh -ExecutionPolicy Bypass `
  -File scripts/windows/vmware/prepare-networks.ps1 `
  -PlanOnly
```

The build wrapper reads the selected VMware network before rendering Packer variables. For NAT/host-only vmnets it uses
`vmrun -T ws listHostNetworks`; for bridged `vmnet0` it falls back to the active Windows IPv4 interface, or the
interface named by `-BridgedInterfaceAlias`. Unless overridden, it atomically selects the first free address from host
offsets `.30` through `.49` for the temporary Photon builder and uses DHCP for the completed appliance management
address. Before publishing a reservation, it reads the exact selected subnet from VMware's `vmnetdhcp.conf` and rejects
the pool when any address overlaps a VMware dynamic range or fixed address. Automatic selection skips gateway and host
interface addresses while trying the remaining pool; an explicitly requested excluded address fails closed. It also
excludes addresses held by another Atlaso reservation, reported by a running Workstation guest, or present in the
Windows neighbor table; ping is not used as free-address proof. The per-user ledger serializes concurrent worktrees and
binds each reservation to the exact task
worktree, source commit, branch, process, Windows boot identity, output root, VM name, and VMX path. A dead owner remains
reserved for the rest of the same Windows boot because a surviving descendant could still start the VM. After a host
restart proves that process tree gone, recovery also requires the exact VM to be inactive and its address unobserved;
an active or observed stale address remains reserved while the allocator tries another pool candidate.
The non-secret release handoff lives beneath the task worktree instead of the host-shared allocation registry or
temporary credential directory.
If cleanup retains a running VM, stop that VM and rerun the wrapper; startup retries every exact pending handoff before
allocating another address, skips handoffs whose exact owner process is still active, and deletes a handoff only after
its ledger release succeeds. A dead same-boot owner remains reserved unless the controlling parent proves complete
process-tree termination; otherwise recovery waits for a host-restart boundary. The child durably publishes recoverable
release intent before ledger admission, then uses write-through replacement and directory-metadata flushing for both
records. Parent cleanup can therefore release the exact pre-VM reservation after proven child-tree termination.
Bridged admission also excludes all IPv4 addresses on the selected Windows interface. `-SkipNetworkCheck` skips topology
preparation but still performs read-only management-vmnet discovery so DHCP state and exclusions cannot become unknown;
when not explicitly overridden, its builder mask, gateway, NAT DNS, and any static final-management gateway also come
from that discovered vmnet.
Validation-only and ISO-preparation runs create no VM and therefore do not reserve a builder address. Actual image builds
reject an explicitly empty `-BuilderStaticIp` instead of falling back to unreserved DHCP.

Use `-BuilderAddressPoolStartOffset` and `-BuilderAddressPoolEndOffset` to select another bounded pool. An explicit
`-BuilderStaticIp` is a one-address pool and must pass the same VMware DHCP, fixed-address, observation, and reservation
checks. For NAT vmnets, the wrapper points the temporary builder at the VMware NAT gateway DNS proxy, normally host
offset `.2`, instead of copying unrelated host DNS servers into the Photon kickstart. Pass `-BuilderStaticGateway` and
`-BuilderStaticDns` only when a different builder address plan is intentional. Pass `-FinalMgmtAddress` and
`-FinalMgmtGateway` only when a static final management address is intentional. Pass `-ServiceVmnetName` only when the
second appliance NIC should attach to a different Workstation network.

Create or adjust missing lifecycle vmnets in VMware Virtual Network Editor. The scripts intentionally do not rewrite
global Workstation vmnet configuration because `vnetlib.exe` behavior is version-sensitive and can affect unrelated VMs.

## Local Wheel Deploy

After a code change that does not require rebuilding the Photon image, deploy a fresh Atlaso wheel to a running VMware
test appliance with:

```powershell
.\scripts\windows\vmware\deploy-wheel.ps1 -IpAddress 192.168.167.10
```

For the password-backed path, first authenticate the local 1Password desktop integration, verify that exactly one
Environment named `Atlaso` exists, and confirm that it contains the concealed `DEFAULT_ADMIN_PASSWORD` variable without
reading its value. Copy that Environment's opaque ID, identify the approved 1Password account name or ID, and select an
explicit CPython 3.10 through 3.13 executable for the supported Windows SDK bridge:

```powershell
.\scripts\windows\vmware\deploy-wheel.ps1 `
  -IpAddress 192.168.167.10 `
  -OnePasswordEnvironmentId '<atlaso-environment-id>' `
  -OnePasswordAccount '<account-name-or-id>' `
  -OnePasswordPython '<path-to-python-3.13.exe>'
```

The supported 1Password Python SDK uses desktop authorization and a locked, offline SDK/Paramiko runtime. The
[canonical VMware Workstation workflow](../../docs/reference/full-technical-reference.md#vmware-workstation-workflow)
documents its isolation, dependency, failure, and host-trust boundaries. The 1Password CLI is not part of this
password-deployment path, and the concealed password is not placed in the deployment process environment. Do not set
`DEFAULT_ADMIN_PASSWORD`, pass a password argument, create a local `.env` file, or use the retired
`ATLASO_DEPLOY_SSH_PASSWORD` fallback.

The wrapper sources the guest-neutral Atlaso service unit from `image/common/systemd/atlaso.service`, matching the
canonical image provisioning and release-bundle inputs.

When the IP should be resolved from VMware Tools, pass the VMX path as a named argument:

```powershell
.\scripts\windows\vmware\deploy-wheel.ps1 `
  -VmxPath "image\vmware-workstation\test-vms\Atlaso-PR-<number>-test-vm\Atlaso-PR-<number>-test-vm.vmx"
```

Do not pipe the VMX path or put the `.vmx` path on a line by itself; PowerShell will try to run that file and report a
pipeline/document execution error. The helper builds `python -m pip wheel . -w dist`, uploads the newest `atlaso-*.whl`
with `scp`, installs it into `/opt/atlaso/.venv`, syncs `scripts/appliance/atlaso-helper` to
`/opt/atlaso/bin/atlaso-helper`, installs the VMware `atlaso.service` unit with its pre-start management-front-door and
factory-reset recovery hooks, synchronizes every checked-in public release key from `image/common/update-trust` into
`/etc/atlaso/update-trust.d`, builds and installs the locally verified Inventory Linux package, restores virtualenv
permissions, restarts `atlaso.service`, and verifies `/openapi.json`
from inside the guest and from the Windows host. The helper and trust-key syncs are required because those root-owned
files live outside the Python virtualenv and are not updated by `pip install`. Build Inventory Linux first or pass
`-SkipInventoryLinuxSync` only for a code-only deployment that intentionally leaves the appliance package unchanged.
If the app takes longer to become reachable after restart, pass `-ReadinessTimeoutSeconds 120`.

`deploy-wheel.ps1` remains a development-only live-patching path. Production Appliance Update uses signed GitHub release
bundles, retained ABI-specific wheelhouses, `/opt/atlaso/releases/<version>`, and transactional rollback; it does not
use this direct wheel deployment path. Manual and scheduled checks/installations retain one parent task with separate
Atlaso Release, PowerShell Modules, and Photon OS child steps so failures and skipped Photon work remain independently
visible. The Packer build explicitly stages `image/common/update-trust` and fails when no valid public release key is
available.

The `atlaso.service` pre-start hooks first ask the constrained helper to restore any interrupted ordinary
management-front-door activation under `/var/lib/atlaso-privileged/management-front-door`, then resume a durable
`/var/lib/atlaso-privileged/factory-reset/request.json` marker before uvicorn starts. A front-door activation or reset
interrupted by power loss therefore returns to its validated recovery path before exposing the management control
plane; only an appliance without either marker takes the no-op path.

## OVF / OVA Export

After a VMware image build, export a deployable OVF folder and OVA archive:

```powershell
pwsh -ExecutionPolicy Bypass `
  -File scripts/windows/vmware/export-ovf.ps1 `
  -SourceVmxPath image/vmware-workstation/output/Atlaso-PR-<number>-Photon-Builder-VMware/Atlaso-PR-<number>-Photon-Builder-VMware.vmx `
  -Name Atlaso-Photon `
  -Force
```

`-SourceVmxPath` is mandatory for low-level export. The exporter consumes its proven builder identity and provenance;
it does not guess a legacy generic VMX. The `-Name` value remains the consumer-facing OVF/OVA product identity and
must not inherit the transient pull-request number.

The export script runs OVF Tool, adds Atlaso vApp properties and appliance network mappings to the OVF descriptor,
regenerates the manifest, and packages the folder as an OVA unless `-NoOva` is passed. The descriptor preserves the OS
and Atlaso system-content VMDKs, then declares a 500 GiB empty VCF Offline Depot disk and a 500 GiB empty VCF Backups
disk. ESXi creates the latter two disks during deployment without payload files. The exporter requires exactly four
ordered disks, requires file-backed payloads for the first two, uses VMware Paravirtual SCSI, and removes the build-time
CD-ROM device. On first boot, the independent Atlaso `tty1` console and OVF management-network validation start before
data-disk discovery. After networking validates, `atlaso-data-disks.service` ignores the formatted system-content disk
and resolves `/` through its complete block-device dependency tree. The service requires exactly one physical OS disk,
then requires the two data disks at SCSI units 2 and 3 to expose topology-derived `atlaso-path-*` identities and exact
500 GiB capacities. It completes an all-disk preflight before formatting either disk and fails closed for any missing,
extra, reordered, ambiguous, or mismatched device. Verified blank disks become ext4 volumes labeled
`ATLASO_DEPOT` and `ATLASO_BKUP`; correctly labeled ext4 disks are never reformatted. The service writes their UUIDs to
`/etc/fstab` and mounts them at `/mnt/atlaso-vcf-offline-depot` and `/mnt/atlaso-vcf-backups`. The descriptor exposes
those fixed volumes while allowing only positively identified Atlaso-managed ESX Storage disks after initialization;
claimed existing ext4 whole disks require UUID-backed fstab persistence and a root-owned Atlaso claim.
The descriptor exposes two network mappings for
vSphere/ESXi import: `Atlaso Management Network` for the first adapter, which remains management-only as `eth0`, and
`Atlaso Services Network` for the second adapter used by DNS, DHCP, CA, depot, PXE, KMS, and other Atlaso-managed
services.

Supported OVF Tool exports declare disabled Secure Boot with
`vmw:key="bootOptions.efiSecureBootEnabled" vmw:value="false"`. Atlaso validates that normalized descriptor before it
writes `atlaso-provenance.json`; the compatibility spelling `uefi.secureBoot.enabled` is accepted only when every
present supported declaration is explicitly false. Missing, enabled, malformed, or conflicting declarations fail the
export before provenance, manifest, OVA packaging, or publication can claim a usable artifact.

To upload the deployable OVF package to an existing stable GitHub Release, authenticate GitHub CLI and select release
publication:

```powershell
pwsh -ExecutionPolicy Bypass `
  -File scripts/windows/vmware/export-ovf.ps1 `
  -Release
```

To target an existing GitHub prerelease instead, check out its exact annotated `vX.Y.Z-<prerelease>` tag and run:

```powershell
pwsh -ExecutionPolicy Bypass `
  -File scripts/windows/vmware/export-ovf.ps1 `
  -Prerelease
```

Stable mode derives `vX.Y.Z` from synchronized repository metadata. Prerelease mode requires exactly one annotated
SemVer prerelease tag at `HEAD` whose `X.Y.Z` core matches that metadata. Both modes require the tag to identify the
clean checked-out commit, resolve the destination repository from the checkout, and require an existing published,
non-draft GitHub Release whose stable or prerelease classification matches the selected mode. The exporter only appends
the verified OVF asset set; it never creates, retags, publishes, or reclassifies the GitHub Release.

Publication replaces the generated local OVF output before uploading. That implicit replacement applies only when
`-OutputDirectory` is omitted and the target is the canonical `image/vmware-workstation/ovf/<Name>` destination. An
explicitly supplied existing destination, including that same canonical path, requires `-Force`. Recursive replacement
is always limited to a strict descendant of `image/vmware-workstation/ovf`; filesystem, repository, image, VMware image,
OVF-root, external, and reparse-point targets are refused even with `-Force`. A new external destination may receive an
export because no existing tree is removed, but rerunning against it requires choosing a repository-owned output
destination instead.

Every OVF asset is checked against GitHub's less-than-2-GiB per-asset boundary before upload. The descriptor, manifest,
and both payload VMDKs are uploaded as one set. A retry verifies every existing asset byte-for-byte and refuses partial
or different assets instead of overwriting them. The OVA is also uploaded when it fits; an oversized OVA is omitted
with a warning because it combines both otherwise deployable VMDKs into one archive. Publication also requires a clean
checkout whose `HEAD` is the locally available annotated release tag, a byte-matching build provenance record, and a
destination-repository tag resolving to the same commit. Release recovery parses the OVF and revalidates the two
file-backed payload disks plus the two empty 500 GiB data disks before accepting existing assets.

The protected portable-artifact release workflow owns publication of the complete cross-hypervisor set. It waits for
the VMware, Proxmox, KVM, and Hyper-V smoke jobs for the exact protected-main commit, stages the versioned import
helpers and Hyper-V ZIP, enforces the same per-asset size limit, and publishes the signed artifact index.

The OVF properties are intended for vSphere/ESXi import:

| Category            | Property                  | Required | Description                                                                                                      |
| ------------------- | ------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------- |
| Management network  | `atlaso.cidr`             | no       | Static management IPv4 CIDR for `eth0`, for example `192.168.10.10/24`; blank uses DHCPv4.                       |
| Management network  | `atlaso.gateway`          | no       | Required with static IPv4; must be on-link for the CIDR and differ from the management address.                  |
| Management network  | `atlaso.ipv6_enabled`     | no       | Boolean, default `false`. Enables management IPv6.                                                               |
| Management network  | `atlaso.ipv6_cidr`        | no       | Blank while IPv6 is enabled uses RA/SLAAC; a value selects static IPv6.                                          |
| Management network  | `atlaso.ipv6_gateway`     | no       | Optional with static IPv6; accepts an on-link or link-local address that differs from the management address.    |
| Management network  | `atlaso.dns_servers`      | no       | Optional resolver IPs separated by commas, spaces, or new lines. Blank DHCP deployments keep lease-provided DNS. |
| Appliance identity  | `atlaso.fqdn`             | yes      | Appliance FQDN applied to Photon OS and Atlaso desired state.                                                    |
| Initial credentials | `atlaso.admin_password`   | yes      | Initial Atlaso web `admin` password.                                                                             |
| Initial credentials | `atlaso.root_password`    | yes      | Photon root console password. Root SSH remains disabled by default.                                              |
| Initial credentials | `atlaso.root_ssh_enabled` | no       | Boolean, default `false`. Enables root password SSH immediately on first boot.                                   |

On first boot from an OVF/OVA deployment, `atlaso-vmware-ovf-customize` reads those properties through VMware Tools
before Atlaso starts. A blank IPv4 CIDR writes `DHCP=ipv4`; a supplied CIDR and gateway configure static IPv4. IPv6 can
be disabled, automatic through RA/SLAAC, or static. Every supplied management gateway is also written to the Atlaso
environment before the service starts, so the seeded Physical Interfaces desired state, Network preview, initial
baseline, and later Appliance Apply retain the same IPv4 and IPv6 default-route intent. The customizer also writes
family-correct firewall access, resolver
overrides when supplied, hostname, root password, optional root SSH state, and bootstrap admin password once, then
records a redacted marker under `/var/lib/atlaso`. Passwords are consumed as deployment inputs and are not printed in
the marker or customization log. After all first-boot configuration succeeds, the customizer writes a redacted pending
marker, clears the consumed OVF environment through VMware Tools, and atomically promotes the pending file to the
applied marker. This removes raw-clone credentials from the host-side `guestinfo.ovfEnv` VMX setting while keeping a
power interruption between scrub and promotion recoverable on the next boot. A failed scrub remains unmarked and is
retried from pending success with the initialization lock held and the network-review handshake cleared. Cleanup writes
an explicit empty string through `vmware-rpctool` or `vmtoolsd`; a cleanup failure never returns to DHCP review because
the management state already applied. VMware Tools can read the cleared value back as the exact `""` sentinel; Atlaso
normalizes that representation to answered-empty before confirmation. Mutation failures identify only a bounded,
non-secret initialization layer in
the customization log. The pending file and its parent directory are synchronized before the external credential scrub;
all preceding host filesystem mutations are synchronized before pending success is recorded, and the applied-marker
promotion synchronizes the directory again. The early tty1 console is restarted after clone-specific appliance secret
rotation and before the initialization lock is removed, so it cannot retain baked keys in process memory. If a raw clone
accidentally reuses a disk whose applied marker already exists, the customizer
does not reapply the injected credentials, but it does clear the injected OVF environment before its marker early exit so
those plaintext values cannot remain in the cloned VMX. Inconclusive VMware RPC reads are retried rather than treated as
proof of an empty property. Applied-marker cleanup also requires 30 consecutive successful empty reads before unlocking
tty1, so delayed clone properties are scrubbed. Raw-clone injection carries a non-secret deployment identifier; if a
source was interrupted with only a pending marker, a different injected identifier invalidates that stale pending state
before the clone applies its own properties. A nonempty ID-less OVF environment is also applied instead of promoting
pending source state, so
release OVA redeployment remains safe. Pending recovery requires 30 consecutive successful empty guestinfo reads, and
applies properties that appear during that confirmation window. Use only pristine, never-booted image outputs as clone
sources.

When VMware Tools answers successfully but returns no envelope, the customizer requires 30 consecutive empty reads
before classifying the boot as non-OVF. It writes the durable
`/var/lib/atlaso/vmware-no-ovf-initialization.applied` marker, removes any initialization/review handshake, logs
**No OVF deployment properties supplied; using image defaults.**, and lets the ordinary console and appliance services
continue. An unanswered Tools channel never contributes to that confirmation. Malformed XML, present-but-incomplete
properties, and invalid properties remain fail-closed. The marker makes reboot idempotent, but a later nonempty envelope
durably replaces the non-OVF classification and enters the normal OVF validation/customization path.

The customizer validates IPv4, IPv6, gateway, and DNS relationships before any host mutation. Interface and gateway
addresses must be usable unicast values rather than unspecified, loopback, multicast, or reserved addresses. If
validation fails, the
Atlaso `tty1` console displays **First-time initialization — Network configuration requires review**, prepopulates only
non-secret OVF values, and accepts a corrected network configuration. Networkd, data-disk initialization, HTTPS
bootstrap, and Atlaso remain held until the correction passes the same shared validation and applies successfully. The
applied marker is absent until success, so another console correction remains possible without redeploying the OVA.
A root-owned lock staged in the VMware image disables ordinary privileged tty1 actions until the deployment root
password applies. Non-network properties validate before network recovery is offered, and a later boot clears stale
handshake files when the applied marker proves customization finished.

If an administrator later corrects management networking from the tty1 console, Atlaso explicitly regenerates Network
and Firewall state from the corrected CIDR, retries an unfinished first-boot HTTPS bootstrap, applies Appliance
Settings, validates nginx, restores nginx and Atlaso when needed, and proves stable loopback readiness for the applied
HTTP-only or HTTPS management mode before the console reports success. Check
`https://<management-address>/openapi.json` when HTTPS is enabled or `http://<management-address>/openapi.json` in
HTTP-only mode.

The OVF descriptor stores these as unqualified property IDs inside the `atlaso` product class. ESXi qualifies them once
in the guest OVF environment as `atlaso.<property>`; do not repeat the class prefix in each property ID.

## Lifecycle

Run the Workstation lifecycle wrapper after building an appliance VM:

```powershell
pwsh -ExecutionPolicy Bypass `
  -File scripts/windows/vmware/invoke-lifecycle-test.ps1 `
  -PullRequestNumber <number>
```

The wrapper writes evidence under the canonical
`test-results/vmware-workstation-lifecycle/Atlaso-PR-<number>-lifecycle-<collision-safe-suffix>` directory and records
absolute VMX evidence in `vmware-identity.json`. Unless `-ApplianceIPAddress` is passed, it waits for VMware Tools to
report the DHCP management address and records it in `discovered-appliance.json` before running HTTP and SSH probes. It
keeps the Python appliance assertions provider-neutral.

Pass `-PlanOnly` to print the selected VMX, client VMDK, vmnets, and result path without creating VMs.

## Boot A Test Appliance

Store the exact `Atlaso` Environment ID once in the checkout-local configuration file. The `.atlaso-local` directory is
ignored by Git, the prompt is masked, and the command does not print the ID:

```powershell
$atlasoLocal = Join-Path (git rev-parse --show-toplevel) '.atlaso-local'
New-Item -ItemType Directory -Path $atlasoLocal -Force | Out-Null
$atlasoEnvironmentId = Read-Host 'Paste the Atlaso Environment ID' -MaskInput
try {
    [System.IO.File]::WriteAllText(
        (Join-Path $atlasoLocal 'onepassword-environment-id'),
        $atlasoEnvironmentId
    )
}
finally {
    Remove-Variable atlasoEnvironmentId -ErrorAction SilentlyContinue
}
```

Create and start a normal Workstation test appliance from the latest built VMX without passing the ID each time:

```powershell
pwsh -ExecutionPolicy Bypass `
  -File scripts/windows/vmware/create-atlaso-test-vm.ps1 `
  -PullRequestNumber <number> `
  -Redeploy `
  -ResetDataDisks `
  -TrustRootCa
```

Before preparing networks, removing an existing target, or creating the VM, the wrapper resolves the current Windows
user's existing `.ssh/id_ed25519.pub` and validates it as one canonical Ed25519 public key. First boot installs exactly
that key for `admin` and a separate development-only passwordless-sudo drop-in. Pass
`-SshPublicKeyPath <path-to-existing-ed25519-public-key>` to select another public key, or
`-SkipSshKeyProvisioning` to retain the prior password-backed SSH and sudo behavior; those options cannot be combined.
The wrapper fails early for a missing, malformed, multiline, non-Ed25519, or unbounded SSH key and never generates or
copies an SSH private key. Root SSH stays disabled, and the Workstation lifecycle runner and exported OVF/OVA
properties do not
receive this test-only access. Complete factory reset removes the development key and sudoers drop-in. Verify and
approve the appliance SSH host key once from the wrapper's host-derived output. After startup it prints the exact
public Ed25519 host key and SHA-256 fingerprint from test-only VMware guest-info for explicit `known_hosts`
verification; the wrapper never trusts unauthenticated `ssh-keyscan` output. Subsequent local Codex and Copilot tasks
under the same Windows user can use ordinary key/agent
authentication and `sudo -n` without the 1Password bridge.

The wrapper requires the cloned Photon OS and Atlaso system-content VMDKs at SCSI units 0 and 1, then creates fresh
Depot and Backups data VMDKs at units 2 and 3 when needed. `-ResetDataDisks` removes those data VMDKs before recreating
them only when their canonical paths are strict, non-reparse-point descendants of the selected VM output directory.
Both creation-size arguments accept only `500GB`; an explicitly reused data VMDK must also expose an exact 500 GiB
virtual capacity in its descriptor or deployment stops before cloning the target VM.
Before cloning, the wrapper verifies the source VMX and both payload bytes against schema-v3 build provenance, including
the immutable source-snapshot inventory identity and matching builder identity. After
the full clone, it revalidates the PVSCSI unit assignments and exact 40 GiB/20 GiB payload capacities before it creates
or attaches either data disk. Do not repair an ambiguous or reversed source by swapping filenames or formatting a disk;
rebuild it through the supported wrapper.
`-Redeploy` requires the exact named VMX and exactly one well-formed, matching `displayName`; a missing, malformed,
duplicate, or mismatched target preserves the
directory and returns an actionable failure. Cleanup checks the running and registered Workstation inventories by
Windows filesystem identity, stops through checked `vmrun` when needed, and completes all final state and VMX-set
preflights before checked `vmrun deleteVM` removes registered targets. Preflight failures preserve all artifacts;
provider deletion or postcondition failures preserve the remaining artifacts and return failure. Stale library-row
cleanup holds a write-excluding inventory handle through its final byte comparison and atomic replacement.
Every started normal test clone must pass unique-address readiness before the wrapper reports it ready. The wrapper
injects an explicit normal-test marker independently of optional SSH key provisioning; after applying the hostname, the
guest uses that marker to publish its actual value through VMware Tools. The check binds the exact running VMX, its
`ethernet0` MAC, the injected and guest-published hostnames, VMware Tools' IPv4 result, and the Windows neighbor entry
for that host-facing address. It also requires an address answer from every running Workstation VM; incomplete guest
evidence retries rather than being treated as unique. VMware Tools may serialize the hostname either directly or with
one matching pair of surrounding double quotes; readiness removes only that provider representation and rejects
unbalanced, nested, or embedded quote forms as ambiguous. If another VM reports the same address, the hostname differs,
or the neighbor entry maps to another running VM's MAC, the wrapper stops before printing SSH or HTTPS endpoints and names
the relevant conflicting identity evidence. Immediately before returning readiness, it re-lists the running inventory
and rechecks the target address; a concurrent VM start, stop, or target-address change restarts the proof.

The required development-signer cleanup power-cycles the exact clone after encrypted import so the host can scrub the
powered-off VMX. Because VMware runtime guest-info does not survive that stop/start, the applied-marker boot republishes
the normal test VM's current hostname and regenerated Ed25519 host key from inside the guest. The durable marker's
explicit normal-test flag limits this reboot behavior to the test-only identity channel; ordinary appliances do not
publish it. A republish failure keeps readiness closed rather than trusting host-generated or stale evidence.

The wrapper reports a guest-initialization timeout separately after it has proved the stable VMX, MAC, Tools address,
running inventory, and Windows neighbor tuple. That diagnostic includes the injected hostname, whether the guest
published a hostname, and the last allowlisted bounded first-boot stage when available; it does not relabel the failure
as an address-discovery timeout or print arbitrary guest-info. An address or reachable SSH or HTTPS endpoint is not
complete identity-bound readiness. Use the exact clone's local console to inspect first boot, and rebuild an outdated or
unfixed source image before redeploying. The hostname and HTTPS/application gates remain mandatory.

For recovery, leave the failed clone running only while using its local console, then either stop the named conflicting
VM or assign the clone a unique management address. A task-specific DHCP reservation must target the exact MAC printed
in the failure; a static address must be changed and applied from the clone's console before retrying readiness. Re-run
`get-atlaso-vm-ip.ps1 -VmxPath <exact-vmx> -ExpectedHostname <first-boot-fqdn>` to prove the corrected identity, or
redeploy the normal test VM. Review and update `known_hosts` explicitly only after comparing the wrapper's published
Ed25519 key and SHA-256 fingerprint; these scripts never change normal SSH `known_hosts` automatically.

Pass `-IncludeLabNetworkAdapters` only after `VMnet2`, `VMnet3`, and `VMnet4` exist for the
SiteA, WAN/SiteB, and trunk-like lifecycle networks. `-TrustRootCa` downloads the deployed root CA, requires its SHA-256
fingerprint to match the checked-in `development-trust/atlaso-development-root-ca.pem`, and adds that exact certificate
to the current-user Trusted Root store only when it is not already trusted. It never deletes unrelated roots based on
their subject. Normal VMware test VMs share this development-only root, but each first boot generates a unique
`appliance:https` key, serial, certificate, and FQDN/IP SAN set. Lifecycle VMs, Hyper-V VMs, reusable image output, and
exported OVF/OVA appliances continue to generate their own roots and never receive this development signer.

Real normal-test-VM creation requires the exact `Atlaso` 1Password Environment ID. The wrapper prefers an explicit
`-OnePasswordEnvironmentId` override and otherwise reads `.atlaso-local/onepassword-environment-id`, which Git ignores.
It verifies the ID against the repository's non-secret SHA-256 pin before invoking `op`. That Environment must contain
one concealed `ATLASO_DEVELOPMENT_ROOT_CA_PRIVATE_KEY` matching the checked-in certificate plus exactly one concealed
`DEFAULT_ADMIN_PASSWORD` and `DEFAULT_ROOT_PASSWORD`. The Environments-enabled beta CLI under
`C:\Program Files\1Password CLI` must support `op run --environment`. The wrapper validates that capability and
cryptographically verifies the retrieved key against the checked-in certificate before network preparation, redeploy
cleanup, or cloning. A bounded child removes the inherited signer variable
immediately and stages the signer only as canonical base64 PKCS#8 DER through the normal-wrapper guest-info field. The
complete assignment remains below VMware's 4,096-character VMX line boundary, and first boot reconstructs standard
PKCS#8 PEM before staging. `-TimeoutSeconds` bounds each
`op`/secret-child
process tree; a timeout enters signer scrub and VM rollback only after whole-tree termination is proven. Boot-bound
marker phases also cover VM start and artifact removal. If termination cannot be proven, the wrapper leaves the VM and
VMX untouched, or keeps reused disks quarantined during removal, until a Windows host restart proves the child tree is
gone. First boot writes it mode
`0600`, proves guest-info scrub, encrypts it with that VM's unique `ATLASO_SECRETS_KEY`, and deletes the staging file.
Provider selection commits its durable marker before the potentially long offline guest-agent closure cleanup. The data
disk readiness unit owns that retryable cleanup as a mandatory 15-minute pre-start gate, allowing VMware customization
and signer scrub to proceed concurrently without admitting data disks or Atlaso before cleanup succeeds. Its 20-minute
unit deadline reserves five additional minutes for formatting and mounting. The host retains at least 25 minutes for
encrypted-import proof so cleanup, disk preparation, and subsequent bootstrap startup cannot cause false rollback.
Cleanup mode
erases only the offline closure; portable KVM and Hyper-V first-boot access survives until the next boot. While the
wrapper waits
for scrub and encrypted-import proof, it reads only a bounded non-secret first-boot stage; timeout diagnostics report
that fixed stage or state that provider selection or customizer startup did not complete.
Every post-staging VMware operation has its own process-tree deadline. Before staging, the wrapper records a non-secret
per-user cleanup marker through a Windows write-through atomic rename, so the marker reaches disk before the VMX signer
assignment. The wrapper publishes the marker path to rollback only after that rename succeeds. A failure before any
credential or signer child starts preserves the original error and rolls back only invocation-owned VM artifacts;
normal GUI and headless starts launch `vmrun` without redirected standard streams. The short-lived PowerShell launcher
therefore remains the only writer to the bounded wrapper pipes; detached `vmware.exe` and `vmware-vmx.exe` descendants
cannot retain them after the launcher exits. Root-process and redirected-stream completion are independently bounded,
and an unexpected retained writer fails closed while preserving diagnostics already copied from the root launcher.
Before removal it durably records the exact stopped VMX, quarantine path, and host-boot ownership. A failed fallback
publication preserves the VM without launching removal, while durable child-active or unproven state remains
fail-closed across same-boot reruns. An interrupted rollback blocks later normal-VM creation
until the exact marked VM is stopped, its VMX signer
value is scrubbed, its artifacts are removed, and preserved data disks are restored. This
recovery runs before 1Password preflight and resumes from a durable stopped/scrubbed phase if VM removal completed
before data-disk restoration. It never restores quarantined disks while the removal child might still delete them. The
rollback preflight rejects configured data disks that repeat the same descriptor, hard-linked alias, or shared extent
by filesystem identity, before persisting a plan that could move one file twice. First
boot also durably scrubs plaintext staging when encrypted import fails. `-NoStart` is rejected because a powered-off VM
would retain
the signer before consumption. The wrapper never prints the signer or places it in arguments, logs, markers, lifecycle
artifacts, or exports. After successful encrypted import, the wrapper uses only a bounded graceful VM stop before
powered-off VMX scrub and restart; it never falls back to hard power-off and preserves the retryable marker when that
graceful stop is unproven. Successful import or rollback write-through transitions the marker to a non-actionable tombstone
before deletion; a tombstone that reappears after a crash is deleted without touching its VM.

Waiting is enabled by default and verifies the shared root before printing the management summary. Mandatory
unique-address readiness still runs when `-WaitForIp:$false` opts out of root verification. The wrapper waits up to five
minutes
for the first-boot CA endpoint, retrying transient connection and service-readiness failures. Pass
`-TimeoutSeconds <seconds>` to adjust the secret-child, IP-discovery, and CA-readiness deadlines. Partial downloads are
removed best-effort between retries through .NET file APIs, including when the current user's temporary directory
contains a dotted profile name or a valid DOS 8.3 short-path representation. Cleanup cannot replace the original
readiness error or stop the retry loop. After unique-address readiness succeeds, the wrapper prints a connection summary
with the verified VMX, management MAC, hostname, HTTPS console URL, Swagger URL, OpenAPI URL, root certificate URL,
`ssh admin@<appliance-ip>` command, and—when development key
provisioning is enabled—the host-derived Ed25519 public key plus SHA-256 fingerprint.

Both this wrapper and the Workstation lifecycle runner inject a complete `guestinfo.ovfEnv` document into a raw cloned
VMX before power-on. The default document selects IPv4 DHCP, leaves resolver overrides blank, keeps IPv6 and root SSH
disabled, and supplies the required appliance identity and first-boot credentials. The normal test wrapper alone adds
the internal development administrator public-key and public development-root properties; the lifecycle runner omits
both. The signing key uses a separate test-wrapper-only guest-info value and is not an OVF property. After regenerating
machine identity, the customizer publishes the VM's public Ed25519 SSH host key through the separate
`guestinfo.atlaso.test_vm_ssh_host_ed25519_public_key` value after wire-format validation. This gives raw Workstation
clones the same fail-closed initialization contract as an OVA deployment instead of leaving the customizer waiting for
properties
that only an OVF deployment normally supplies. A generated non-secret deployment identifier distinguishes each raw
clone attempt during pending-marker crash recovery. For ordinary creation, the wrapper discovers the single local
1Password CLI account and the highest compatible CPython 3.10 through 3.13 runtime registered with the Windows
launcher, including bracketed architecture selectors emitted by the current Python Install Manager. Legacy launcher
and vendor-tagged registrations remain supported, while x86 and unsupported Python versions remain ineligible.
`-OnePasswordAccount` and `-OnePasswordPython` remain explicit overrides. When `-AdminPassword` or
`-RootPassword` is omitted, the wrapper independently retrieves only that
credential's exact concealed default through the supported 1Password SDK desktop integration. An explicitly supplied
`SecureString` remains authoritative for that credential, so either password can be overridden without changing the
other. SDK preparation, authorization, Environment access, uniqueness, concealment, or validation failure stops before
network preparation, redeploy cleanup, disk reset, or cloning. `-WhatIf` does not prepare the SDK, authorize 1Password,
or retrieve credentials. Caller environment variables, repository defaults, local `.env` files, and interactive
password prompts are never credential sources.

Plaintext exists only inside bounded credential children. The parent receives current-user DPAPI ciphertext, stages a
DPAPI-protected complete OVF bundle into the exact newly created VMX through a second bounded child, and removes the
temporary isolated runtime. Before that staging child starts, the wrapper durably records child-active recovery state;
an unproven process-tree termination blocks cleanup or redeploy until a later host boot can prove the child is gone.
Passwords are never placed in process arguments, caller-controlled environment, logs,
output, markers, test evidence, documentation, or GitHub surfaces. The guestinfo-backed VMX setting remains only until
successful first-boot consumption clears it. Raw-clone credentials must be at least 12 characters and cannot contain
leading, trailing, XML control, or non-XML characters that would change during OVF attribute parsing.

### Development root CA rotation

Treat compromise of any normal VMware test VM as compromise of the shared development signer. Rotate it by generating
one new 4096-bit RSA/SHA-256 self-signed `Atlaso Development Root CA`, replacing the checked-in public PEM and the
matching concealed `ATLASO_DEVELOPMENT_ROOT_CA_PRIVATE_KEY` in the exact `Atlaso` 1Password Environment as one
coordinated change, then redeploy every normal test VM. Remove the retired certificate from Windows trust explicitly
after verifying no retained test VM depends on it. Never reuse this root outside local normal-VM testing.

The VM's first virtual terminal runs the Atlaso recovery console; tty2 and later terminals retain Photon login prompts.
Its normal 80x30 layout includes boot and runtime state for the appliance services, including Firewall desired state. F3
and F4 each require a fresh Photon root password before opening `top` or an audited root Bash session. Exiting either
process restores and physically redraws the appliance screen. Installed VMs use a 640x480 Atlaso GRUB theme with the
official Photon OS logo; wheel deployment can synchronize the boot branding but never reboots the appliance
automatically. See [Local appliance console](../../docs/appliance-console.md).

### Windows DNS for lab FQDNs

When browsing or testing lab services from the Windows host, use the Atlaso DNS listener as the resolver for the
appliance-managed lab domain. The namespace should match the DNS/DHCP domain configured in Atlaso, and the name server
should be the appliance DNS listen address on the lab network. For example, if the lab domain is `atlaso.internal` and
DNS listens on `192.168.87.200`, run PowerShell as Administrator:

```powershell
# Remove existing NRPT rules for atlaso.internal
Get-DnsClientNrptRule |
  Where-Object { $_.Namespace -eq ".atlaso.internal" } |
  Remove-DnsClientNrptRule -Force

# Add the correct rule
Add-DnsClientNrptRule `
  -Namespace ".atlaso.internal" `
  -NameServers "192.168.87.200"

# Clear Windows DNS cache
Clear-DnsClientCache
```

Verify the active NRPT rule:

```powershell
Get-DnsClientNrptRule |
  Where-Object { $_.Namespace -eq ".atlaso.internal" }
```

Then test name resolution and browse with the service FQDN:

```powershell
Resolve-DnsName depot.atlaso.internal
```

Open Edge with the FQDN, for example `http://depot.atlaso.internal/`. If Edge still reports
`DNS_PROBE_FINISHED_NXDOMAIN`, open `edge://net-internals/#dns` and click `Clear host cache`.

On first boot, `atlaso-data-disks.service` verifies the fixed SCSI units, stable topology identities, exact 500 GiB
capacities, and exact platform disk set before formatting the assigned blank VMDKs. It fails before `mkfs` on missing,
extra, reordered, ambiguous, or mismatched disks. Correctly labeled ext4 volumes remain untouched; both volumes are
mounted by UUID at `/mnt/atlaso-vcf-offline-depot` and `/mnt/atlaso-vcf-backups` before the control plane starts. Once
both are initialized, only positively identified Atlaso-managed ESX Storage disks may join the platform disk set.
Disk-preflight failure blocks nginx, the HTTPS bootstrap, Atlaso control plane, and worker.

## Fidelity Notes

Workstation vmnets are isolated layer-2 segments. They are useful for appliance management, SiteA, WAN, and trunk-like
separation. Tagged-trunk acceptance requires a compatible upstream virtual-network configuration; record that topology
with the lifecycle evidence instead of treating a portable target as a second canonical lab.
