---
title: Offline installation ISO build and verification
description: Prepare, verify, and release the planned signed Atlaso installation ISO.
audience:
  - contributor
  - maintainer
status: roadmap
---

# Offline installation ISO build and verification

This reference records the build and release path for
[issue #542](https://github.com/mdaneri/Atlaso/issues/542). The development ISO from source commit
`7df968dc3079f3e7cf09655e248d961b8bc05c9d` completed two independent disconnected Auto installations through the default
serial path in VMware, inspected with host source `9337eb391f4500ae3ae557b672074bba4abc79a8`.
Both booted without media, passed root/admin authentication and account challenges, matched all five installed-content
measurements, and preserved their unselected disks. Public machine and SSH identities differed between installations;
the first VM retained its identity across a later network boot. Three later certificate-pinned host OpenAPI samples
passed, while an initial failed API probe and broader installer acceptance remain under investigation. Physical
SATA/NVMe and wired-Ethernet acceptance remains outstanding. This VM result does not establish physical-platform
support or complete issue acceptance.

The installation image reuses the pinned Photon 5.0 ISO and Photon installer 2.2. Remastering preserves the source EFI
boot image and native installer flow. The Atlaso deployment source comes from an immutable Git archive at the
selected full commit. The signed software release, its exact application wheel, locked CPython wheelhouse, shared
provisioning inputs, PowerCLI modules, trust material, notices, firmware, and a signed offline Photon RPM repository
are embedded and inventoried. Dependency closure is resolved during authorized ISO preparation; installation does
not use network package repositories. Shared provisioning explicitly installs `iproute2` for the console and diagnostics;
the final package-state verifier requires it. The complete captured RPM closure must include its dependencies.
The boot package selection includes Photon’s native `initramfs` package and
its resolved dependencies. Installation requires the kernel and initrd selected by Photon’s GRUB environment to
exist before applying chosen credentials or reporting completion.

Installation requires at least one hardware-backed Ethernet adapter. The installer checks before disk selection and
again immediately before partitioning. A disconnected cable, missing DHCP lease, or unavailable Internet does not
block this offline installation. Add a VMware network adapter before booting a test VM; a loopback or software bridge
alone does not satisfy the requirement.

During installation the active console displays Photon's native progress bar, counting completed installation stages.
Stages have different durations; package and Atlaso software installation can take substantially longer than other
steps. The bar reaches completion only after the native sequence, boot checks, account configuration, and unmounts
succeed. In the VM window, use **Alt+F2** for detailed installer/provisioner output and **Alt+F1** to return to progress.
Serial sessions keep their selected console; the progress screen identifies a private `/run/atlaso-install-*` log
directory when a second virtual terminal is unavailable. Logs are volatile and contain no chosen account passwords.

The installed appliance enables real system adapters (`ATLASO_DRY_RUN_SYSTEM_ADAPTERS=false`), so global Appliance
Apply executes the reviewed helper operations. Completion refuses a missing, simulated, or ambiguous persisted setting.
This does not automatically apply pending configuration during installation. Existing appliances installed with an
older ISO retain their original setting; producing a replacement ISO does not modify them.

Auto and Custom both offer named **SFTP backup storage** and **VCFDT depot storage** screens before destructive review.
Keep the default to preserve an existing service partition or shared storage. Other choices explicitly assign a
compatible Custom `/mnt/` partition, or an otherwise unused disk as a full-disk ext4 partition at the fixed service
mount. The installer does not infer roles from capacity, order, labels, or old filesystems. A previously selected disk
cannot also be chosen for whole-disk replacement, and the two roles cannot take the same partition. Returning Back
discards tentative choices; all selected identities and mount layouts still require the complete No-default review.
These choices create the installation layout only; they do not enable the SFTP or depot service or expose credentials.

The shared boot-branding installer handles both native Photon kernel paths. The root-only Auto layout uses
`/boot/$photon_linux` and points GRUB at `/boot/grub2/themes/atlaso/theme.txt`; a Custom layout with a separate `/boot`
uses `/$photon_linux` and `/grub2/themes/atlaso/theme.txt`. Theme files remain under `/boot/grub2/themes/atlaso` in
both layouts. Custom layouts must use ext4 for the boot filesystem; see [Choose disks and layout](../getting-started/physical-installation.md#choose-disks-and-layout).
The installed boot entry is labeled **Atlaso Appliance**, including GRUB's text fallback; it must not be a blank entry.

Use the existing VMware build and lifecycle process for admitted Photon builders and VM validation. Do not create a
parallel Hyper-V or KVM image pipeline. Capture RPM dependencies during preparation on the authorized Photon builder;
do not restart or repurpose a consumed template to produce capture inputs. `capture-rpms` requires an absent absolute
output directory. Task workspaces, temporary content, and validation output must stay under a configured permitted
root. Receipt resource ownership and source/task identity before creating disposable roots, as required by the
[completed-task cleanup policy](../contribute/completed-task-cleanup.md). Keep release signing inside the protected
hosted workflow.

## Prepare inputs

Use the full source commit and exact software version being prepared. Select an absent destination for each newly
created output. Begin from authorized builder preparation state and capture the resolved, signed Photon RPM closure
and required firmware:

```text
python scripts/build_installation_iso.py capture-rpms --output <absent-absolute-directory>
```

Prepare the candidate from that closure, the exact signed software payload, and the PowerCLI modules accepted by the
existing `Validate` mode of `image/common/powershell/provision-powercli.ps1`:

```text
python scripts/build_installation_iso.py prepare --commit <FULL-SOURCE-SHA> --version <X.Y.Z> --payload <absent-directory> --software <verified-software-directory> --rpms <captured-rpm-directory> --powercli <validated-powercli-directory>
```

The preparation stage binds the source files to the selected commit and records the software, RPM, firmware, and
PowerCLI inventories. Keep its unsigned candidate in the private task workspace; it is not a release artifact. For
controlled transfer, package the candidate and split oversized input archives into an existing empty destination
directory:

```text
python scripts/build_installation_iso.py pack-inputs --payload <candidate-directory> --output <absent-archive.tar.gz>
python scripts/build_installation_iso.py split-inputs --archive <input-archive.tar.gz> --output <existing-empty-directory>
```

Input packaging does not grant signing authority. The protected `installation-prerelease.yml` workflow independently
validates the candidate before loading signing material. Besides authenticating every RPM, validation tests the entire
candidate as an RPM transaction against a fresh database containing only the admitted trust keys. All requirements,
RPM capability requirements, and conflicts must pass with scripts, triggers, and plugins disabled. No host-installed
package database or network repository can supply a missing dependency. An unsupported host RPM capability or
incomplete closure stops validation. This check does not replace disconnected installation and reboot acceptance.

The workflow then signs the candidate, assembles the ISO, and stages the signed installation assets in the existing hidden
`installation-vX.Y.Z-rc.N` draft. This staging run leaves the release as a draft. Installation artifacts remain
separate from software-update and virtualization release assets. The signed release index covers the ISO manifest
and assets; phase one requires Secure Boot disabled. ARM support is a possible second phase and is not included in
the x86-64 release contract.

## Development-only VMware test image

The existing PR builder accepts `-CaptureInstallationRpms` to download the resolved Photon RPM closure and installed
PowerCLI modules. Pass an existing, empty, creation-receipted `-InstallationCaptureDirectory` and its original
`-InstallationCaptureRootIdentity`. Keep this directory separate from the VM output: Packer removes temporary archive
files from the VM output during cleanup. The capture directory preserves `installation-rpms.tar` and
`installation-powercli.tar` for independent verification and ISO assembly. This option is rejected for release builders.
Capture staging uses `/var/tmp` so it does not consume the guest's `/tmp` memory filesystem during shared provisioning.
Use `-Headless` for unattended capture without opening the Workstation console. Independently validate all captured
inputs before assembly; capturing files alone does not establish a successful appliance build.

Refresh the complete captured dependency closure when refreshing ISO contents, together with the eligible signed
Atlaso software bundle and its locked CPython wheelhouse. Packages absent from current official Photon metadata require
a fresh capture; do not suppress package admission or replace individual packages without verifying the complete set.

PowerCLI input can also be prepared with the existing locked module installer in a receipted task directory:

```powershell
pwsh -NoProfile -File image/common/powershell/provision-powercli.ps1 `
  -Mode Install -ModuleRoot <TASK-OWNED-POWERCLI-DIRECTORY>
```

For installer work on a pull-request commit, use the explicit development builder. It requires a clean checkout at the
exact PR `HEAD`; the separately supplied software directory must be a signed main release, with its version and
main-reachable source commit passed independently. Reuse the already captured Photon RPM directory, validated
PowerCLI modules, pinned Photon 5.0 source ISO, and verified software release. Put all paths under the configured,
receipted task roots, and select absent payload and ISO destinations plus an existing empty private scratch directory:

```powershell
python scripts/build_development_installation_iso.py `
  --commit <PR-HEAD-SHA> `
  --software-version <MAIN-RELEASE-VERSION> `
  --software-commit <MAIN-RELEASE-SHA> `
  --software <VERIFIED-MAIN-RELEASE-DIRECTORY> `
  --rpms <CAPTURED-PHOTON-RPM-DIRECTORY> `
  --powercli <VALIDATED-POWERCLI-DIRECTORY> `
  --payload <ABSENT-DEVELOPMENT-PAYLOAD-DIRECTORY> `
  --scratch <EXISTING-EMPTY-PRIVATE-DIRECTORY> `
  --source-iso <PINNED-PHOTON-5.0-ISO> `
  --output <ABSENT-DEVELOPMENT-ISO-PATH>
```

This builder uses the distinct `atlaso-installation-development-public-test` key identity. Its deterministic Ed25519
fixture seed is public test data (`bytes(range(32))`, bytes `00` through `1f`); it is not a credential or release
authority and is never stored as a secret. The production signer and default production verifier continue to require
the production key identity. Production finalization runs only from `main`, uses its checked-out workflow tools, and
retains the protected signing environment and main-release admission checks. The development initrd accepts the test
identity only when its explicit development
marker is present. The resulting image is for VMware testing only and starts the installer in the VMware window
by default (`console=tty0`). Open the fresh VM with its ISO attached and power on; no GRUB edit is needed.
The five-second GRUB menu offers **VM window (tty0)** and **Serial (ttyS0, 115200)** entries. Use the arrow keys
and Enter to choose the installer console. Each entry selects exactly one kernel console. When serial initialization
succeeds, the boot menu accepts input and displays output on both the VM window and COM1 at 115200 baud, 8N1;
otherwise the native console remains available.
Native logger propagation and Python prints are isolated from the progress terminal; detailed output remains available
on the separate terminal or in the private volatile log.
The VM-window installer keeps the kernel's detected terminal size; only the serial harness uses a fixed 80×25 size.
Concealed account fields accept printable ASCII characters and preserve spaces exactly. Rejected password input is
cleared before retrying. **Go Back** on confirmation returns to the first password field for that account; **Go Back**
on the first admin field returns to the full disk review and requires a new **Yes** (the default remains **No**).
**Go Back** on the first root field returns to admin password entry and discards collected passwords. No disk writes
occur during these setup screens. Explicitly declining the disk review still cancels installation.
**Go Back** from Custom partitioning returns to disk/layout selection and discards the abandoned partition plan.
For the automated serial-console harness, add `--serial-console` to the development build command to make the serial
entry the default; both entries remain available. The build result's `console` field records that default as
`graphical` or `serial`, not a later operator selection. Retain the default, actual selected entry and exact ISO
digest so validation for one console mode is not reported as validation of the other. Neither image is publishable
as an Atlaso release or establishes production or physical-hardware acceptance.

Boot-time signature verification reuses the `cryptography` package already included in the pinned Photon initrd;
that initrd removes the OpenSSL command-line executable. The downloadable verifier retains its existing OpenSSL path.

RPM repository generation explicitly uses gzip metadata so the pinned Photon initrd can read it, regardless of the
build host’s default compression format. Repository configuration uses UTF-8 with LF line endings for Photon TDNF.
The installed runtime uses the same current Photon 4096-bit RPM key as the shared repository initializer, with
signature checking enabled. Legacy keys remain available to the pinned native installer where required.

The VMware harness initializes its RTC from host UTC (`rtc.diffFromUTC = "0"`) because Photon reads the hardware clock
as UTC. Verify that the host clock is correct before starting a disconnected installation. A clock behind the RPM
signature creation time can cause native package verification to reject an otherwise authentic package; retain signature
checks and correct the clock before retrying with a fresh installation fixture.

The VMware harness creates an isolated EFI VM with one disconnected E1000 Ethernet adapter, two blank SCSI disks,
and a private serial
console. Its VMX configuration uses UTF-8 to preserve non-ASCII worktree, ISO, and output paths.
The serial reader recognizes the native menu's overwrite-mode reset and nonmoving character-set shifts when
reconstructing visible disk rows. Unsupported modes still invalidate cursor certainty; a supported reset does not
erase that uncertainty or authorize a guessed cursor-position reply.
Hash the generated ISO and use the exact owning pull request number. `Probe` checks that the native Photon disk
selection screen exposes both blank fixture disks, and `Cancel` checks cancellation before disk writes. `Auto` exercises
the single-disk Auto installation path. Reboot, persistence, and Appliance Update checks remain separate follow-up tests:

Fresh VM creation requires 74 GiB free on its host volume: the 64 GiB target, 4 GiB unselected disk,
4 GiB memory backing, and 2 GiB overhead. Sparse disks grow during installation, so their initial file sizes do not
establish sufficient host capacity. An installed-VM boot or inspection resume reserves 6 GiB for new memory backing
and overhead; it does not reserve space for arbitrary future guest disk growth.

When the source volume lacks this capacity, a maintainer may explicitly approve a separate development VM root.
Keep the configured Codex worktree root, source checkout, credentials, VNC client, and durable `.task-ownership`
records in their original locations. Do not repurpose `OwnershipRoot`, move an existing VM, use a junction, or adopt
an existing directory. The controlling task must create the approved empty root exclusively with the existing
`CreateAndPinOrdinaryDirectoryPath` lifecycle helper and publish its original native identity in the creation callback,
before using the directory. Preserve that receipt and its SHA-256 outside all VM removal roots.

The internal schema-1 root receipt uses phase `installation-validation-root-created` and kind `artifact`. It binds
the task, repository, branch, source commit, worktree path and native identity, PR/local identity, approved root path
and native identity, creation time, and supported artifact-root cleanup descriptor. Every operation validates the
receipt, source ancestry, directory identities and output containment, retaining native pins through the operation.
Only canonical installation-ISO VMs may use this development path. Ordinary VM output rules stay unchanged.

Pass `-ValidationRootReceiptPath <ORIGINAL-ROOT-RECEIPT>` and
`-ValidationRootReceiptSha256 <CREATION-TIME-SHA256>` with the same output directory on every console, boot,
resume, verification and cleanup operation. The bounded consumer forwards them to each lifecycle phase; VM records
also bind the original root receipt. Missing, changed, mismatched or reconstructed provenance refuses the operation.
Delete each VM with its existing receipt-bound cleanup operation before releasing the empty validation root.

```powershell
$isoSha256 = (Get-FileHash -LiteralPath <DEVELOPMENT-ISO-PATH> -Algorithm SHA256).Hash.ToLowerInvariant()
.\scripts\windows\vmware\invoke-installation-iso-test.ps1 `
  -IsoPath <DEVELOPMENT-ISO-PATH> `
  -IsoSha256 $isoSha256 `
  -OutputDirectory <ABSENT-VM-OUTPUT-DIRECTORY> `
  -PullRequestNumber <OWNING-PR-NUMBER> `
  -Scenario Probe
```

Run `-Scenario Cancel` and `-Scenario Auto` in separate receipt-bound VM roots, following the VMware lifecycle
procedure for each. `Auto` obtains administrator and root credentials through the existing supported Atlaso
credential bridge and sends them only to concealed installer prompts; do not put passwords in command lines or logs.
`CancelReview` selects the target and accepts the default **No** at the native **Erase selected disks?** confirmation.
The same confirmation displays the selected disks and proposed layout; no typed acknowledgement is required.
Large disk-identity summaries and custom layouts use native review pages before that final confirmation. `Insufficient`
selects the fixture's four-GiB disk and requires the exact capacity refusal for that disk before consent. Both
scenarios use no credentials and compare both disks with their pre-boot baselines after stopping the VM.
The native capacity dialog identifies the selected disk and its size. The console test reads all four complete message
rows inside the native panel border and still requires the exact selected disk and byte count. Enter returns to explicit
disk selection;
Escape cancels before credentials or disk writes.
`CustomCancel` opens the native partition editor, requires its complete empty-layout refusal, then uses **Go Back**.
It obtains no credentials and compares both stopped disks. `CustomAliasProbe` submits `/srv` in the native **Create New**
form and requires the complete `Use /var/srv; /srv is a symlink.` refusal, including its native wrapped display and
the form controls. It then stops the VM and compares both disks; it sends no credentials or erasure consent.
The public observer requires the whole message across adjacent display rows within that form. Its numeric cursor
parser remains unchanged and does not assign widths to unknown characters.
`CustomReboot` creates one remaining-size `ext4` root
partition on the fixture's selected 64-GiB disk through the native **Create New** form. Before consent it requires
the complete review: that exact disk, only the native 10-MiB EFI partition and remaining-size root, the full erasure
warning, and the default-No instruction. Additional disks or partitions, paged or incomplete reviews, and different
filesystems fail this deliberately narrow scenario. The four-GiB disk remains independently unselected.
Each public Custom phase has a 90-second limit clipped to the original overall deadline. Fixed phase checkpoints
identify an incomplete native state without printing console contents or extending the test.
Use a fresh receipt-bound VM directory for each scenario, with the same ISO identity and validation-root selectors
as `Probe`. For a full Custom install, replace `-Scenario Probe` with `-Scenario CustomReboot` and append
`-InspectInstalled -InspectContent -InspectionPythonPath <ABSOLUTE-PREPARED-PYTHON-EXECUTABLE>`.
It uses the existing concealed credential bridge, media-free reboot, root/admin challenges and content checks below.
These scenarios provide automation for their stated fixtures; adding them does not establish native or physical
acceptance, multi-disk Custom coverage, Update persistence, or rollback coverage.
`MultiProbe` and `CustomMultiReboot` select an explicit three-disk fixture: the original 64-GiB boot/root disk,
the original 4-GiB unselected disk, and an 8-GiB selected data disk. Creation requires **82 GiB** of host free space;
the original two-disk gate remains **74 GiB**. The fixed profile is recorded in both original VM and baseline
receipts before use. Existing operations derive it from those sealed receipts; missing legacy profile fields admit
only the original two-disk recipe. Profiles are never inferred from a current VMX or transferred between VMs.
`MultiProbe` obtains no credentials and verifies all three stopped disks against their original baselines.
`CustomMultiReboot` creates a remaining-size `ext4` root on the 64-GiB disk and a remaining-size `ext4` `/var/srv` on the
8-GiB disk. Its complete review must identify exactly those two disks and the native EFI/root/data partitions before
Yes. The 4-GiB disk remains independently unselected and is compared after installation and media-free reboot.
Use a fresh receipt-bound directory and `-Scenario CustomMultiReboot` with the same inspection options as above.
The Custom editor rejects symlink mount targets from the authenticated Photon `filesystem` RPM before consent.
For example, `/srv` is a native alias for `/var/srv`; enter `/var/srv` explicitly so the reviewed path matches the
installed filesystem. Reserved live-system paths and noncanonical paths are also refused.
Cancellation checks include every selected disk as well as the unselected disk. A mismatched profile, missing disk,
extra disk or partition, changed path or size, truncated review, or additional device fails admission.
Creation records a separate disk-baseline receipt before first boot. Retain both original receipt paths and their
creation-time hashes from the console driver's ownership output. The console runner automatically verifies disks
within its process deadline. To repeat verification afterward:

```powershell
.\scripts\windows\vmware\test-installation-iso.ps1 -Mode Verify `
  -OutputDirectory <EXACT-VM-OUTPUT-DIRECTORY> -PullRequestNumber <OWNING-PR-NUMBER> `
  -OriginalReceiptPath <ORIGINAL-RECEIPT> -OriginalReceiptSha256 <ORIGINAL-RECEIPT-SHA256> `
  -BaselineReceiptPath <BASELINE-RECEIPT> -BaselineReceiptSha256 <BASELINE-RECEIPT-SHA256>
```

### Background VNC console checks

The built-in Workstation VNC server can be controlled with a command-line client without using the host keyboard or
mouse. Keep the original VM and disk-baseline receipts. Configure only that stopped VM, use an unused port bound
exclusively to `127.0.0.1`, and verify the live listener belongs to its exact VMX. Keep the fixture's sole E1000 adapter
disconnected (`ethernet0.startConnected = "FALSE"`); console admission refuses a connected adapter or extra adapters.
Use the default graphical development ISO for this path; it selects `console=tty0` without an override. On images
built with `--serial-console`, select **VM window (tty0)** from the boot menu and record that non-default selection.
Historical serial images without this menu require a one-boot GRUB edit
to use `console=tty0` for a graphical test; record that override rather than claiming default graphical startup.

For an initial installer password field, `VncCredential` reuses the bounded SDK bridge, source/runtime pins, native
provider verifier and concealed-field byte encoder. Its optional client is VNCDoTool **1.4.2**, installed with its
dependencies into an isolated, creation-receipted task virtual environment under the seven-day package-age policy.
Record the original client package inventory with `Get-AtlasoSourceSnapshotInventory` from
`Atlaso.SourceSnapshot.psm1`. Ordinary application installs do not require this client. The frame tests require its
optional Pillow dependency and are run in the prepared validation environment.
Set `TMP` and `TEMP` to an existing, creation-receipted task temporary root before invoking the consumer. The SDK bridge
finishes its durable marker publication and cleanup before VNC source/runtime pins are held; the pins and frame checks
still precede credential transmission.

First observe and capture the **empty, concealed password prompt** through the receipt-bound VNC connection. Review
its account label and input focus, retain the image's SHA-256, and identify only its single input-row rectangle.
Never admit a shell, ordinary text field, or arbitrary unreviewed screenshot. The adapter compares the complete live
screen outside that small rectangle before requesting stdin and again before typing. It clears any previous retry
text, checks the frame again, and submits only the selected SDK value. Passwords never enter arguments, environment
variables, screenshots, ordinary files or diagnostic output. An unexpected frame, peer, source or runtime refuses
submission; do not replace the recorded digest merely to make a refusal pass.
Each screen check uses a fresh read-only VNC connection because the pinned client waits on empty updates from an
unchanged VMware screen. All key events stay on the original admitted connection, with the client's native Shift
option enabled for uppercase and shifted ASCII symbols.

```powershell
.\scripts\windows\vmware\invoke-installation-iso-test.ps1 `
  -Scenario VncCredential -TimeoutSeconds 600 `
  -IsoPath <ORIGINAL-ISO-PATH> -IsoSha256 <ORIGINAL-ISO-SHA256> `
  -OutputDirectory <EXACT-VM-OUTPUT-DIRECTORY> -PullRequestNumber <OWNING-PR-NUMBER> `
  -CollisionSuffix <ORIGINAL-SUFFIX> `
  -OriginalReceiptPath <ORIGINAL-RECEIPT> -OriginalReceiptSha256 <ORIGINAL-RECEIPT-SHA256> `
  -BaselineReceiptPath <BASELINE-RECEIPT> -BaselineReceiptSha256 <BASELINE-RECEIPT-SHA256> `
  -VncAccount admin -VncPort <LOOPBACK-PORT> `
  -VncScreenPath <REVIEWED-EMPTY-FIELD-PNG> -VncScreenSha256 <RECORDED-PNG-SHA256> `
  -VncFieldRectangle <X0,Y0,X1,Y1> -VncPythonPath <ISOLATED-VENV-PYTHON> `
  -VncRuntimeSha256 <ORIGINAL-SITE-INVENTORY-SHA256> -VncRuntimeFileCount <ORIGINAL-FILE-COUNT>
```

`AdmitConsole` in `test-installation-iso.ps1` provides the existing running VM's read-only admission for this operation.
It requires the initial connected ISO, original receipts, persistent identity, exact disk bindings, isolated EFI
configuration and exact running provider. It neither stops the VM nor verifies logical disk contents. Continue to use
`Verify` after stopping or cancelling, and preserve the separate disk-comparison result.

After the VNC-driven installation completes, stop that exact VM with the owning verifier and release the initial
private serial-pipe controller. Use `BootInstalled` on the same original VM and baseline selectors to create the
existing media-disconnection receipt, reboot without the ISO, and run the ordinary root/admin challenges. Add
`-InspectInstalled -InspectionPythonPath <PREPARED-INSPECTION-PYTHON>` for the existing identity and application
payload checks. Preserve the emitted boot receipt and its creation-time digest for later `LoginInstalled` resumes.
This scenario creates no replacement VM and does not repeat disk partitioning or password collection.

### Installed-system checks

Use `-Scenario AutoReboot` in a fresh VM root to install, stop, disconnect the installation CD drive, and boot the
installed system. This development image enables the standard password-protected `serial-getty@ttyS0` service only
after verifying the development signing identity, non-production marker, and VMware platform. It also invokes the
shared boot-branding helper's explicit development option to add GRUB serial output and the `ttyS0` kernel console.
Production images keep their existing boot console and do not enable this test login service. The runner rechecks
its private pipe peer before sending either chosen password
to ordinary Linux login; it records only fixed success checkpoints, never the console stream.
Login troubleshooting reports only fixed PAM and shell-stage categories. These diagnostics neither expose console
contents nor establish successful authentication; the account-identity challenge must still pass.
Initial installation also reports fixed disk-selection/completion phases and known boot categories. During
provisioning, only stage labels admitted from the checked-in provisioner are forwarded, once per recognized stage;
raw console messages remain private. A launcher failure stops the wait instead of consuming the whole test deadline.
An observed Python failure or incomplete capacity refusal keeps its fixed public classification when the overall
wait expires before fragmented output completes.
Startup uses the same bounded cursor-only parser as login, answering a terminal-position query only after observed
controls establish its position. This permits a startup profile to finish its terminal sizing before disk selection.
At a login deadline, fixed categories distinguish no activity, control-only activity, and unrecognized activity without
printing the bytes or their length. Login timeout, session failure, and shell-prompt candidates are diagnostic categories;
they do not satisfy the account-identity challenge.
The serial adapter reuses the installer console parser to track its 25-row, 80-column cursor across login steps.
It answers supported cursor-position requests only when the observed controls establish the position, including
Photon's full-screen login-profile probe. Fragmented controls and save/restore sequences retain their ordering.
Unknown positions or unsupported cursor modes receive no invented coordinates. Persistent state contains only
cursor and control-parser metadata, with a 64-query session ceiling and absolute deadlines; console contents remain
private and temporary.
The adapter recognizes the native `screen` terminal's single nonprivate `CSI 34 h/l` control as
[normal cursor visibility](https://www.gnu.org/software/screen/manual/screen.html#Control-Sequences).
This control does not move the cursor or restore certainty lost to another unsupported mode or unknown character width.
The fixed `cursor-position-query` diagnostic identifies requests without proving authentication; a shell can display
its prompt before finishing terminal initialization. The separate account-identity challenge must still pass.
For the administrator's PowerShell shell, the adapter waits for the cursor handshake after the prompt before sending
that challenge. Prompt bytes alone do not establish terminal readiness.
PowerShell commands use carriage return for ordinary Enter; the Unix .NET console treats line feed as Ctrl+Enter.

To retry login diagnostics on a retained installed VM, use `-Scenario LoginInstalled` with the same ISO identity and
existing VM directory. Supply `-OriginalReceiptPath`, `-OriginalReceiptSha256`, `-BaselineReceiptPath`,
`-BaselineReceiptSha256`, `-BootReceiptPath`, and `-BootReceiptSha256` from the original live creation/boot output.
The runner verifies and stops that exact VM, checks the unselected disk, and recreates its private pipe server with
the existing restrictive ACL and provider-peer proof. The owning harness's `ResumeInstalled` mode repeats admission,
requires the original disconnected-media boot receipt, publishes an immutable resume receipt before starting, and
preserves the VMX and disks. It uses the existing concealed credential consumer and login challenges. Retain the
reported resume receipt with the original selectors, and use the ordinary receipt-bound `Verify` mode after a failed
or interrupted attempt. This path does not repeat installation or grant authority to adopt another VM.

Add `-InspectInstalled -InspectionPythonPath <ABSOLUTE-PYTHON-EXECUTABLE>` to `AutoReboot` or `LoginInstalled`
to measure public machine identities and application wheel equality. Use an existing Python environment with the
locked ISO build dependencies. Before retrieving credentials or starting the VM, the adapter authenticates the original
ISO checksum and derives its software and helper expectations. After the root account challenge, it reuses the staged
software verifier and installed wheel inspector, returning only a bounded public report. Inspection commands preserve
Linux guest paths on Windows hosts. Development installations retain the authenticated software set under
`/var/lib/atlaso/installation-inspection/software`; Photon's installer
mounts `/tmp` as temporary memory, so the provisioning stage there cannot serve as post-reboot evidence. Production
images do not retain this development inspection copy. Older development VMs without the persistent copy require
a rebuilt ISO and a fresh receipt-owned installation for payload inspection. Missing staged software,
changed helpers, unexpected report fields, or different application bytes fail the check.

Keep each report with that VM's original creation and resume receipts. Compare two resumes of the same VM for identity
stability, and compare separately installed, receipt-owned VMs for identity uniqueness. These checks read the public
machine ID and Ed25519 public host key; they do not read private keys or appliance secrets. Application wheel equality
does not establish equality of all installed RPMs, PowerShell modules, trust material, or notices. Network isolation
remains in effect by default, so this option alone does not establish host-facing API or Appliance Update acceptance.

Add `-InspectContent` alongside `-InspectInstalled` to run five additional checks against that same original ISO:

- **Assets:** compare copied source, deployed shared files, their ownership/modes, and public update trust keys.
- **Python:** reuse the signed software verifier and locked wheel-environment inspector to compare installed
  dependency file bytes, including relocated headers, scripts and data, rejecting missing, changed, or unexpected files.
- **PowerCLI:** run the existing provisioning script in `Validate` mode against its original lock and module root.
- **RPMs:** reuse Photon package-state validation, require installed package identities to belong to the ISO closure,
  verify nonconfiguration, nonghost package files without plugins or verification scripts, and verify firmware files.
- **Notices:** regenerate the notices from the original source inputs and installed package inventories in RAM,
  then compare them with the installed document.

Offline notices use the authenticated software release's dependency lock, matching the installed wheelhouse.
The development installer's source commit may have a newer lock; that checkout lock does not replace the selected
software release's dependency set. Missing or changed signed lock inputs fail instead of using another repository.

For a subsequent resume, append these options to the receipt-bound `LoginInstalled` invocation above:

```powershell
  -InspectInstalled -InspectContent -InspectionPythonPath <ABSOLUTE-PREPARED-PYTHON-EXECUTABLE>
```

The adapter authenticates every helper against the admitted media before credential retrieval. Each check returns
only a bounded public measurement; failure stops the inspection. Temporary Python archives and generated notices
stay under `/run` and are removed on normal exit. This mode does not run provisioning, connect package repositories,
or change installed content. RPM configuration files and ghost entries are outside its file comparison, and application
or dependency equality alone does not prove whole-system equality. Keep the five results with the original VM receipts.

Required installed RPMs reflect shared provisioning's final cleanup. The checksum-pinned native
`python3-pip-26.2.1-1.ph5` requires `python3-setuptools-80.9.0-5.ph5`; removing that build package also removes system pip.
The adapter excludes system pip from the required installed set only when the original cleanup explicitly removes
setuptools and both admitted RPM checksums match this reviewed pair. A different pair fails preparation pending review.
Both RPMs remain in the admitted media inventory. The protected application Python environment, installed RPM
identities, firmware, files and native runtime metadata retain their separate mandatory checks.

The RPM check reuses the shared Photon package-state verifier to measure runtime metadata. The live `/proc` mount
must be one root-owned proc filesystem mounted at `/proc`,
with its filesystem root `/` and directory mode `0555`. That kernel mount shadows the package's empty `0755` directory.
Only the exact mode-only discrepancy for `/proc` is reconciled after this proof. Other paths, missing entries, changed
file digests, additional verification flags, command errors and stderr still fail; files beneath `/proc` are not exempt.
The two empty media-mount directories declared by the admitted Photon filesystem RPM, `/run/media/cdrom` and
`/run/media/floppy`, may be absent after reboot only when `/run` is independently proven to be one root-owned tmpfs
with filesystem root `/` and mode `0755`, and each reported directory is absent at inspection. The report records this
absence count. Other missing paths and changes to existing entries still fail.
The profile is bound to the exact admitted filesystem RPM checksum; a different RPM requires review before inspection.
Its initially empty `btmp` and `wtmp` login records are mutable. The inspector follows Photon's native systemd tmpfiles
policy: both must be ordinary, single-link files owned by root and group `utmp`, with modes `0660` and `0664`
respectively. Their record contents remain private. Only size, digest, mode, group and modification-time discrepancies
for those two records are reconciled after that metadata proof; missing records, changed owners, links and other paths
still fail. Immutable packaged files retain their byte and metadata comparison.
The same RPM's post-transaction script sets `/var/mail` to mode `1755`, uid `0`, gid `34`, while its archive declares
mode `1775`. The shared verifier requires exactly that native post-transaction directory metadata before reconciling
its mode-only RPM discrepancy. Changed owners, groups, entry types or other verification flags still fail.
The systemd journal-directory profile is separately bound to the exact admitted systemd RPM and its native
`/usr/lib/tmpfiles.d/systemd.conf` checksum. That policy must remain a root-owned, single-link ordinary file with
mode `0644`. Before and after package verification, `/var/log/journal` must be a directory owned by root and
`systemd-journal`, with mode `2755`, exactly as the native tmpfiles rule specifies. Only mode and group discrepancies
for that directory are reconciled after this proof. Missing entries, owner or digest changes, descendants, other
verification flags and different policy bytes still fail. Journal contents remain private and are not inspected.
The audit-directory profile similarly requires the exact admitted audit RPM and its native
`/usr/lib/tmpfiles.d/audit.conf` checksum. The policy must be an ordinary single-link root:root file with mode `0640`.
Before and after package verification, `/var/log/audit` must be a root:root directory with mode `0700`, as its
native tmpfiles rule requires. Only that directory's mode-only RPM discrepancy is reconciled. Missing entries,
owner or group changes, different file types, altered policy bytes and other verification flags still fail.
Audit records and child paths are not read.
Fixed public failure diagnostics may identify the packaged `/var/lib/rpcbind` directory's type, mode and RPM
verification flags. Its contents and child names remain private, and this diagnostic does not reconcile a discrepancy.
The separate rpcbind profile binds its exact admitted RPM checksum and initial-install script, which changes that
directory from root:root to root:sys. The shared verifier requires a real directory with uid 0, sys gid 2 and mode
`0755` before and after package comparison. Only its group-only discrepancy is reconciled; owner, mode, type,
digest and other flags still fail. No state files or children are inspected.
The OpenSSH server profile reuses the same directory validator for its pinned initial-install script. It requires
only the real privilege-separation directory at `/usr/share/empty.sshd` to have uid 0, sys gid 2 and mode
`0711` before and after comparison. Only that directory's group-only RPM discrepancy is reconciled;
missing entries, changed ownership or permissions, child paths and other flags still fail. SSH keys are never read.
The initial OpenLDAP profile binds its exact admitted server RPM and native service-unit bytes. It reuses the
runtime mount and public-policy readers, requires the native root-owned `/var/run -> ../run` alias over verified
tmpfs, and requires `slapd.service` to be loaded, inactive, dead and disabled. Only the absent volatile
`/var/run/openldap` directory is reconciled, before and after comparison. Atlaso's existing LDAP helper creates
its runtime directory when LDAP is enabled. A running or enabled service, changed unit or mount, present entry,
private child, or other verification flag fails this initial-installation profile. No LDAP data or configuration is read.
The kernel-index profile binds the exact Linux, kmod and kmod-binary RPMs. It first admits the complete public module
namespace from original package metadata before reading file contents, then compares all 1,235 immutable directory
and file records through retained, no-follow descriptors. Missing, extra, linked or changed inputs fail.
The current profile pins Linux `6.12.113-6.ph5`, with 37,950,548 immutable input bytes. Its complete native RPM-header
audit retains the same 1,235 records and eleven generated index paths; kmod and kmod-binary inputs are unchanged.
After ordinary RPM file verification, the profile invokes the authenticated `kmod` executable as `depmod`, selecting
its native compatibility entry point with explicit input, configuration and output selectors. It writes only to
private, descriptor-pinned scratch directories on verified
`/run` tmpfs. All eleven generated indexes must match the installed bytes, ownership and permissions. Native binary,
library, alias, configuration, filesystem and input identities are checked across execution; the proof repeats after
the remaining firmware and metadata checks. Nonempty depmod overrides are refused without reading their contents.
Only size, digest and modification-time flags for those eleven fixed generated paths are reconciled after this proof.
Scratch creation and native output stay anchored to retained RAM directory descriptors. Successful proof removes only
the verified files and empty creation-owned directories; failures preserve scratch for the receipt-bound VM stop.
Missing indexes, other flags, private paths, changed module bytes and unsuccessful native generation still fail.
This profile requires a freshly rebuilt ISO and installation for live acceptance; the earlier module-alias diagnostic
and focused fixtures do not establish successful native derivation on an installed host.
The host checks those package pins before generating the console command, which reuses the authenticated shared
helper's constants to keep the transport within its fixed size limit.
The shared Photon verifier is authenticated against the original media and must match the host's supported contract.
A changed verifier requires a rebuilt development ISO and fresh receipt-owned installation; do not replace it in an
old VM to force acceptance. Keep the older results bound to their original media.

The Python check follows the wheel [installation schemes](https://packaging.python.org/en/latest/specifications/binary-distribution-format/).
It checks relocated files as well as `site-packages` and permits only the declared `#!python`/`#!pythonw` interpreter
rewrite for wheel scripts. Identical shared files can be deduplicated. Different shared bytes require one final owner
proven by unconditional, exactly pinned dependency metadata and pip's
[dependency-first installation order](https://pip.pypa.io/en/stable/cli/pip_install/#installation-order).
Unrelated, ambiguous or cyclic competing owners fail. No check accepts either of two conflicting hashes arbitrarily.
The existing strict virtualization verifier remains unchanged; the ISO inspector explicitly selects the extended
shared inventory helper. A changed helper contract requires a rebuilt development ISO and a fresh receipt-owned
installation. Preserve previous results rather than replacing installed helpers to force a check to pass.
Shared provisioning clears generated package bytecode after its final compatibility and account checks. The inspector
continues to reject unexpected executable caches instead of omitting them from the comparison.
If an immutable Python file differs, its failure category may include the SHA-256 of its original wheel member name.
This identifies a public, media-bound source record for diagnosis; installed file contents and raw checker errors
remain private. It does not permit changed bytes or establish a successful comparison.
The signed-software provisioning path reinstalls the locked dependency wheels, including pip: Photon's initial virtual
environment can contain a differently patched wheel with the same version. Version equality alone does not satisfy
the signed payload comparison.
RPM failures distinguish helper admission, package-state checks, inventory, package files, and firmware. Notice
failures distinguish source inputs, inventory, generation, and comparison. These fixed categories keep command output
private and retain the original verification requirements.
For an RPM file failure, a package identifier can be reported only after its name matches the original media inventory.
The identifier hashes that public package name. Fixed public filesystem entries can also be identified by their index
in the checked-in public path registry, entry type and permission mode. Arbitrary paths, file contents and raw
verification errors stay private, and the check still fails.
The registry also includes the public `/var/log/journal` and `/var/log/journal/remote` directories from the
admitted systemd RPM and `/var/log/audit` from the admitted audit RPM. Only directory metadata is reported;
journal and audit records remain private. Differences are not accepted by this registry.
Known entries may also include the nine fixed RPM verification flags. The RPM command uses Python's standard Base85
transport to keep the complete public registry within the existing console limit; encoded data is checked for safe
quoting, and reports retain their existing Base64 format. Other inspection commands retain their existing transport.
The reader admits up to 5,464 Base64 characters for a report while enforcing the producer's unchanged 4,096-byte
decoded limit. This accommodates the complete RPM inventory; schema, media identity, and every content check remain
mandatory after transport decoding.
Host content-validation failures expose fixed exit codes through the bounded runner, without printing the private
report or validator errors. Codes `20`–`23` identify report size, schema/media identity, inventory encoding/shape, and
RPM expectation shape respectively. Codes `24`–`27` identify missing required RPMs, unadmitted RPM identities,
incomplete native verification, and invalid absent-directory counts. Codes `28`–`31` identify malformed JSON, Base64,
Unicode, and oversized CLI inputs. Other failures retain generic code `2`; every nonzero result stops inspection.
For code `24`, the console driver separately reports zero-based positions in the admitted, sorted required-package
list, then rethrows the original failure. This diagnostic does not emit guest package names, private inventory or
console bytes, and does not establish successful RPM validation.
The registry includes the two EFI files from the admitted `shim-signed` RPM. Their type, mode and verification flags
can identify boot-file discrepancies without reading private console output. This diagnostic does not accept a changed
boot file or relax the RPM comparison.
The admitted OpenLDAP server package contributes only its public service unit and two declared directories to this
registry. Their fixed indices can identify missing entries, modes and verification flags. LDAP databases, configuration
values and private children are never read or emitted, and the diagnostic does not accept a discrepancy.
The pinned Linux package's `/boot/linux-6.12.113-6.ph5.cfg` and `/lib/modules/6.12.113-6.ph5/modules.alias` are also
fixed public diagnostic entries. Only their indices, types, modes and RPM verification flags can be reported;
contents stay private and any discrepancy still fails. The native kernel install script runs `depmod`; the diagnostic
does not treat that fact alone as proof of correct generated indexes.

The EFI profile separately binds both the admitted `shim-signed` and `grub2-efi-image` RPMs and their three boot files'
hashes, sizes and modification times. It authenticates and reuses
the shared installed-layout verifier to check recorded filesystem UUIDs, then requires a single root-owned VFAT mount
at `/boot/efi`, with filesystem root `/`, native file/directory masks `0022`, and no nested mounts. All three files
must be ordinary single-link root:root files on that same filesystem, mode `0755`, with unchanged bytes and exact
native two-second timestamps. Metadata is stable while each file is read, and the complete proof runs before and after RPM
comparison. Only those files' mode and timestamp discrepancies are reconciled; other flags, paths and changed bytes
still fail. These checks follow [Linux's VFAT mount masks](https://cdn.kernel.org/doc/html/latest/filesystems/vfat.html)
and [FAT timestamp encoding](https://github.com/torvalds/linux/blob/v6.1/fs/fat/misc.c).

Use `-CollisionSuffix inspection-a` and `-CollisionSuffix inspection-b` for two fresh installations in separate
canonical VM directories. The wrappers reuse the shared identity helper to preserve the PR number while giving each
VM a distinct name. Supply the same suffix with that VM's original receipt selectors for every subsequent login,
verification, boot, or cleanup operation; omit it only for an original VM created without a suffix.

The `BootInstalled` harness mode reuses original VM and disk-baseline admission, stopped-provider checks, logical
disk comparison, and source pins. It requires the original isolated EFI device configuration, publishes an immutable
`installation-boot` transition receipt before editing the VMX through its retained writer, disables only the existing
CD drive, verifies readback, and starts the same VM. It preserves disk paths, network isolation, cleanup identity,
and private serial endpoint. Retain the reported transition path and creation-time SHA-256 alongside the original
selectors. After this transition, repeat `-Mode Verify` with `-BootReceiptPath` and `-BootReceiptSha256` as well as
the original and baseline selectors. Verification refuses disconnected media without the bound transition receipt.
On interruption, preserve the VM and receipts; do not recreate the VM, reconnect media, or reconstruct ownership
from current files. A partially written or ambiguous configuration requires maintainer recovery.

Verification stops only the identity-checked VM, preserves its artifacts, and compares the unselected disk with its
pre-boot baseline using `qemu-img compare`. Add `-VerifyTarget` after cancellation to compare the target disk too.
The development `Probe` and `Cancel` scenarios passed earlier. A disconnected `Auto` installation also completed in
the receipt-bound VM for source commit `960621fdd0e6c1babcc707e2ca0ca2896539876e`. After stopping the VM,
receipt-bound verification confirmed the unselected disk's logical contents matched its pre-boot baseline. Fresh
machine identity uniqueness and application wheel equality subsequently passed on two independent installations from
the source commit recorded above. Later host-facing `/openapi.json` measurements are recorded in
[Acceptance status](#acceptance-status); Appliance Update success and rollback persistence, and physical acceptance
remain outstanding. A serial-enabled boot attempt exposed a missing
initramfs package. After adding its resolved RPM
closure, the corrected development image completed disconnected installation and booted without media through systemd
to the root login/password prompts. After correcting shell readiness and PowerShell Enter handling, the retained
installation passed both chosen-password login and separate root/admin identity challenges. The receipt-bound
post-reboot comparison confirmed the unselected disk was unchanged. The console runner accepts
Photon's bracketed root prompts, colon-path prompts, and Bash fallback prompts after removing terminal colors/titles.
It refuses password-change conversations before submitting a shell command and still requires a separate
account-identity challenge.
Earlier capacity-refusal and planned-layout cancellation scenarios passed with both fixture disks unchanged.
Do not infer reboot or persistence results from a completed installation run.

Publication is a separate, explicit workflow dispatch after the exact ISO has been validated. The maintainer supplies
`publish=true` and `validated_iso_sha256` for the ISO whose disconnected UEFI installation, reboot, Appliance Update
success and rollback persistence, and unselected-disk preservation were tested. The workflow requires that checksum
to match the signed draft index before publishing, then downloads and verifies the published assets again. The
development ISO has completed disconnected Auto installation, boot without media, chosen-account login challenges,
and the unselected-disk comparison. Public identity uniqueness, application wheel equality and all five bounded
installed-content checks also passed. Later host-facing API measurements are recorded below; Appliance Update checks
remain outstanding, so these results do not establish
full installer acceptance or authorize publication. Do not publish or describe the installer as validated before the
remaining acceptance evidence exists.

### Preserve an old system-content label and recover an interrupted installation

`OldLabelReboot` uses a fixed 64-GiB target and a genuinely unselected 4-GiB disk. Before the first baseline or boot,
the owning creator builds a real `ext4` filesystem labelled `ATLASO_SYSTEM`, with a fixed public test UUID and benign
sentinel. Its original VM receipt seals the seed plan; the baseline records the verified filesystem identity, sentinel
and raw-image digests. Cancellation and installation retain their original comparison rules. A stopped logical
comparison against that baseline also proves that the old filesystem, UUID and sentinel survived unchanged.

This optional Windows fixture requires an existing WSL distribution with Python 3, `mke2fs`, `debugfs`, `e2fsck`, and
`blkid`, plus the existing native `qemu-img` dependency. It records the actual filesystem-tool paths and binary hashes.
It formats only a newly created regular image inside the original owned VM directory; it uses no host block devices,
loop mounts or host-network changes. The raw seed and sentinel are retained there for the normal receipt-bound owning
cleanup. Creation reserves **78 GiB**, including the additional 4-GiB raw image; ordinary two-disk and MultiDisk gates
remain 74 and 82 GiB. Existing-VM recovery retains its separate 6-GiB allowance.

Use the ordinary ISO/root inputs shown above with one absent VM directory and:

```powershell
  -Scenario OldLabelReboot -TimeoutSeconds 3600 `
  -InspectInstalled -InspectContent -InspectionPythonPath <ABSOLUTE-PREPARED-PYTHON-EXECUTABLE>
```

For a controlled recovery test, create a separate fresh fixture with `-Scenario OldLabelInterrupted`. The canonical
console driver selects the target, confirms replacement and supplies the ordinary concealed account fields. It stops
the owned VM only after observing the public `Starting Atlaso provisioning` checkpoint on the progress console.
This follows native partitioning, base OS/bootloader setup, and input staging, immediately before the shared provisioner
starts. It does not assert that a provisioner package transaction has started. Detailed logs stay on their separate
terminal/private log. It compares the unselected disk and emits an immutable **Installer
interruption receipt**. The target may have been written; this is an interruption result, never installation success.
Previously sealed receipts retain their original `installing Photon appliance packages` stage; recovery accepts either
explicit supported checkpoint without rewriting old receipts or extending their original consumers.

Retain the original VM, baseline and interruption receipt paths and their emitted digests outside the VM root. Use the
same output directory and collision suffix for a distinct recovery invocation:

```powershell
  -Scenario RecoverOldLabelReboot -TimeoutSeconds 3600 `
  -OriginalReceiptPath <ORIGINAL-VM-RECEIPT> -OriginalReceiptSha256 <ORIGINAL-DIGEST> `
  -BaselineReceiptPath <ORIGINAL-BASELINE> -BaselineReceiptSha256 <ORIGINAL-BASELINE-DIGEST> `
  -InterruptionReceiptPath <ORIGINAL-INTERRUPTION-RECEIPT> -InterruptionReceiptSha256 <EMITTED-DIGEST> `
  -InspectInstalled -InspectContent -InspectionPythonPath <ABSOLUTE-PREPARED-PYTHON-EXECUTABLE>
```

Recovery admits the original interruption, filesystem seed and stopped unselected comparison before obtaining
credentials. It starts the original connected ISO and requires a fresh target selection and erase confirmation before
reinstalling. It then uses the existing media-free boot, both account challenges, all five strict content checks and
stopped unselected comparison. Preserve both original invocations and their original deadlines; never restart an
expired consumer or recreate a baseline from a partially installed disk. These finite scenarios do not imply recovery
from arbitrary hardware faults, successful Appliance Update rollback, certificate address control, or physical support.

### Inspect a separately admitted host-only connection

Finish disconnected installation, media removal, account and content checks before this separate network phase.
Preserve the original VM, baseline and boot receipts and the stopped unselected-disk comparison. Before changing the
owned VM's adapter, record the exact VMX identity, current source, selected existing host-only vmnet and backed-up
configuration transition in durable task evidence. Use the supported Workstation configuration tool on the stopped,
receipt-bound VM. This phase does not create or change host networks, configure a CA, or issue certificates.

For a subsequent receipt-bound `LoginInstalled` invocation, use:

```powershell
  -InspectInstalled -InspectNetwork -InspectionVmnet <EXISTING-HOST-ONLY-VMNET> -InspectionPythonPath <ABSOLUTE-PREPARED-PYTHON-EXECUTABLE>
```

Before submitting a console password, the driver uses the separate read-only `AdmitNetwork` mode. It requires the
original installed-boot selectors, unchanged disk and private-pipe identities, disconnected ISO, exactly one
`e1000` adapter, and a current native `vmrun listHostNetworks` entry identifying the selected vmnet as host-only with
DHCP. NAT, extra adapters, ambiguous MAC assignments, and non-private subnets fail admission. Initial `AdmitConsole`
keeps its original requirement for an isolated installer with connected media.

After ordinary installed identity verification, the guest reads one private IPv4 address and the existing HTTPS leaf
certificate through the owned serial console. It reads family-unspecified `ip` address JSON, retaining link-layer MAC
fields omitted by `ip -4`, and explicitly selects only IPv4 address records. Both IPv4 and IPv6 default routes must be
absent. The host validator
requires the observed MAC, subnet and prefix to match native admission before printing a bounded public record.
Missing addressing or HTTPS readiness fails at a fixed public stage; console text and private key material stay private.

Use the observed address and leaf digest with the signed installed software version to read host-facing OpenAPI:

```text
python -B -m scripts.installation.inspection probe-openapi --address <OBSERVED-PRIVATE-IPV4> --certificate-sha256 <CONSOLE-OBSERVED-LEAF-SHA256> --version <INSTALLED-SOFTWARE-VERSION>
```

The driver first admits API readiness in a separate 60-second bounded child with a fixed 45-second readiness window.
TLS alone can be available while nginx still returns a boot-time HTTP 502. Readiness retries only HTTP 502, 503, and
504; every attempt verifies the original console-observed leaf before sending HTTP. Certificate, version, JSON,
and other response failures remain immediate refusals, and a late response never satisfies readiness.
The driver then runs the strict probe three times through the bounded process runner with a 30-second deadline before
its final VM stop. A standalone diagnostic invocation also requires that same bounded runner. It verifies the exact console-observed
TLS leaf before sending an unauthenticated `GET /openapi.json`, bounds the JSON body, and requires HTTP 200 and the
expected software version. Retain the three consecutive successful measurements with the network observation and original
VM selectors. This uses the existing leaf as a lab pin without changing host CA trust. It does not establish certificate
handoff address-control acceptance. Finish with owning `Verify`, retain the stopped disk comparison, and restore the
original absent-adapter configuration before returning the VM to isolated inspection.

## Verify a release

Get the public verification key from an independently trusted Atlaso repository checkout. Do not trust a copy of the
key obtained only from the release assets being verified. Use Python 3.11 or newer with OpenSSL available. The
verifier first checks the signed installation artifact index against the selected version and full source commit,
then checks each asset’s size and SHA-256 checksum. When the ISO is split, it verifies every ordered part and the
reconstructed ISO.

From a source checkout, run:

```text
python scripts/verify_installation_iso.py --assets <release-assets-directory> --trust-key image/common/update-trust/atlaso-release-2026-01.pem --version <X.Y.Z> --commit <FULL-SOURCE-SHA> --scratch <existing-private-directory> [--output <absent-iso-path>]
```

The release also contains `verify-installation.pyz`, which accepts the same options and requires Python 3.11 or newer
and OpenSSL. For example:

```text
python verify-installation.pyz --assets <release-assets-directory> --trust-key <independently-trusted-public-key.pem> --version <X.Y.Z> --commit <FULL-SOURCE-SHA> --scratch <existing-private-directory> [--output <absent-iso-path>]
```

`--scratch` must name an existing private directory. Omit `--output` to verify assets without reconstruction; when
requested, the ISO destination must be absent. Compare the reported version and source commit with the release you
intended to use before writing the verified ISO to removable media.

## Acceptance status

The generated release index reports physical hardware acceptance as pending until SATA/NVMe and wired-Ethernet results
are recorded. Native VM evidence alone does not establish physical support or complete issue #542. The development
VMware path supports receipt-bound blank-disk ISO and installer-console tests. Probe, Cancel, capacity refusal,
and disconnected Auto installations have passed. Two independently installed VMs booted without media,
authenticated both chosen account passwords, passed separate root/admin challenges, matched the ISO-bound application
wheel, and preserved their unselected disks. Earlier media source `151b76dbe63db5c7acfb83861e5f5b4b957d30be` lacked RPMs
providing `ip` and `ss`; its installed-system results remain partial evidence. The corrected source
`7df968dc3079f3e7cf09655e248d961b8bc05c9d` includes `iproute2` from a fresh complete capture of 244 RPMs. Its two fresh
default-serial installations, inspected with host source `9337eb391f4500ae3ae557b672074bba4abc79a8`, produced identical
five-part content measurements: 1,318 copied source files, 20 deployed shared assets, 66 Python distributions,
37 PowerCLI modules, 220 installed RPMs, native runtime/file/firmware and module-index verification, and reproduced
notices. Their signed application software was 0.9.465. Both account challenges passed after media-free boots;
machine and SSH identities were unique between the installations.

The first VM subsequently retained its identity and application measurement across a host-only network boot. Its
initial native host API probe failed; a later unchanged probe succeeded, followed by three consecutive bounded,
certificate-pinned OpenAPI responses with HTTP 200, version 0.9.465, 162 paths, and identical response digests.
These measurements establish steady-state host API access. A subsequent fresh-boot diagnostic reproduced the first
probe failure and recorded 25 consecutive certificate-matched HTTP 502 responses while TLS was already available.
The host driver now waits separately for a valid API before its three strict samples. Native validation with host
source `3182f9ed7d86cabae911cea6e681b69e41714dd6` recovered on readiness attempt 18, followed by three strict HTTP 200
samples with the expected version, 162 paths, and identical response and leaf digests. The adapter was
restored to its absent state after owning stopped-disk verification. A separate capacity diagnostic found all four
exact refusal lines inside native panel borders, which the earlier host reader incorrectly compared as full rows;
both disks remained unchanged. A fresh native capacity run with host source `cebf4ffbf3af0127cf96a166d69fe891affe1828`
passed the complete refusal check and verified both stopped disks unchanged. Retain the earlier failed run.

One fresh single-selected-disk Custom installation with host source `95f4669f32c9399b72f8be02b233014ebe74b84a` and
the same immutable `7df968dc3` media passed its complete native review, media-free reboot, root/admin authentication
and account challenges, all five content checks, and stopped unselected-disk comparison. Its content measurements
equalled both earlier Auto installations, while machine and SSH identities differed. This is single-root Custom
evidence; it does not establish multi-disk Custom or physical acceptance.

A fresh host `4c9638772` multi-disk run admitted its complete two-disk plan, then failed during the native filesystem
RPM transaction with error 1525. Its `/srv` mount conflicts with the authenticated RPM's `/srv -> var/srv` alias;
the original failed VM, receipts and stopped unselected-disk comparison are retained. This is a failed installation,
not multi-disk acceptance. The updated alias check and canonical `/var/srv` fixture require new development media.

Final acceptance requires source-bound multi-disk Custom, controlled-fault and old-label preservation evidence,
plus Appliance Update/rollback, certificate address-control and representative physical results.
Do not describe the installer as validated
or claim physical support while these gates are
outstanding. Secure Boot is disabled for phase one; this reference makes no Secure Boot or ARM support claim.

An earlier extended content run matched all 1,299 copied source files, 20 deployed shared assets and the public
update trust key. Its Python check exposed unsupported wheel installation schemes in the older shared inspector;
that run does not establish installed dependency equality. Retain it as partial evidence with its original media
checksum and stopped-VM disk verification.

For disk selection, concealed initial credentials, first-boot networking, and recovery guidance, see
[Physical installation](../getting-started/physical-installation.md).
