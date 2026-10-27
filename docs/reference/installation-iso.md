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
`353be9d4cb12d8116530e89b2147ca19154b0a7a` completed two independent disconnected Auto installations in VMware.
Both booted without media, passed root/admin authentication and account challenges, matched the application wheel,
and preserved their unselected disks. Public machine and SSH identities differed between installations and stayed
stable across two resumes of the first VM. These VNC installations used a one-time `console=tty0` boot override;
the default serial installer path and broader installed-system acceptance remain in progress. Physical
SATA/NVMe and wired-Ethernet acceptance remains outstanding. This VM result does not establish physical-platform
support or complete issue acceptance.

The installation image reuses the pinned Photon 5.0 ISO and Photon installer 2.2. Remastering preserves the source EFI
boot image and native installer flow. The Atlaso deployment source comes from an immutable Git archive at the
selected full commit. The signed software release, its exact application wheel, locked CPython wheelhouse, shared
provisioning inputs, PowerCLI modules, trust material, notices, firmware, and a signed offline Photon RPM repository
are embedded and inventoried. Dependency closure is resolved during authorized ISO preparation; installation does
not use network package repositories. The boot package selection includes Photon’s native `initramfs` package and
its resolved dependencies. Installation requires the kernel and initrd selected by Photon’s GRUB environment to
exist before applying chosen credentials or reporting completion.

The shared boot-branding installer handles both native Photon kernel paths. The root-only Auto layout uses
`/boot/$photon_linux` and points GRUB at `/boot/grub2/themes/atlaso/theme.txt`; a Custom layout with a separate `/boot`
uses `/$photon_linux` and `/grub2/themes/atlaso/theme.txt`. Theme files remain under `/boot/grub2/themes/atlaso` in
both layouts. Custom layouts must use ext4 for the boot filesystem; see [Choose disks and layout](../getting-started/physical-installation.md#choose-disks-and-layout).

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
marker is present. The resulting image is for VMware testing only: it uses the serial installer console on `ttyS0`,
is not publishable as an Atlaso release, and does not establish production or physical-hardware acceptance.

Boot-time signature verification reuses the `cryptography` package already included in the pinned Photon initrd;
that initrd removes the OpenSSL command-line executable. The downloadable verifier retains its existing OpenSSL path.

RPM repository generation explicitly uses gzip metadata so the pinned Photon initrd can read it, regardless of the
build host’s default compression format. Repository configuration uses UTF-8 with LF line endings for Photon TDNF.
The installed runtime uses the same current Photon 4096-bit RPM key as the shared repository initializer, with
signature checking enabled. Legacy keys remain available to the pinned native installer where required.

The VMware harness creates an isolated EFI VM with no network adapters, two blank SCSI disks, and a private serial
console. Its VMX configuration uses UTF-8 to preserve non-ASCII worktree, ISO, and output paths.
Hash the generated ISO and use the exact owning pull request number. `Probe` checks that the native Photon disk
selection screen exposes both blank fixture disks, and `Cancel` checks cancellation before disk writes. `Auto` exercises
the single-disk Auto installation path. Reboot, persistence, and Appliance Update checks remain separate follow-up tests:

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
The native capacity dialog identifies the selected disk and its size. Enter returns to explicit disk selection;
Escape cancels before credentials or disk writes.
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
exclusively to `127.0.0.1`, and verify the live listener belongs to its exact VMX. Keep the VM's network adapters absent.
The development ISO selects `ttyS0`; for a graphical-console test, edit only that boot's GRUB kernel arguments to use
`console=tty0`. Record this override with the result; it does not validate the default serial startup path.

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
remains in effect, so this option does not establish host-facing API or Appliance Update acceptance.

Add `-InspectContent` alongside `-InspectInstalled` to run five additional checks against that same original ISO:

- **Assets:** compare copied source, deployed shared files, their ownership/modes, and public update trust keys.
- **Python:** reuse the signed software verifier and locked wheel-environment inspector to compare installed
  dependency file bytes, including relocated headers, scripts and data, rejecting missing, changed, or unexpected files.
- **PowerCLI:** run the existing provisioning script in `Validate` mode against its original lock and module root.
- **RPMs:** reuse Photon package-state validation, require installed package identities to belong to the ISO closure,
  verify nonconfiguration, nonghost package files without plugins or verification scripts, and verify firmware files.
- **Notices:** regenerate the notices from the original source inputs and installed package inventories in RAM,
  then compare them with the installed document.

For a subsequent resume, append these options to the receipt-bound `LoginInstalled` invocation above:

```powershell
  -InspectInstalled -InspectContent -InspectionPythonPath <ABSOLUTE-PREPARED-PYTHON-EXECUTABLE>
```

The adapter authenticates every helper against the admitted media before credential retrieval. Each check returns
only a bounded public measurement; failure stops the inspection. Temporary Python archives and generated notices
stay under `/run` and are removed on normal exit. This mode does not run provisioning, connect package repositories,
or change installed content. RPM configuration files and ghost entries are outside its file comparison, and application
or dependency equality alone does not prove whole-system equality. Keep the five results with the original VM receipts.

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
the source commit recorded above. Broader payload equality, the host-facing `/openapi.json`, Appliance Update success
and rollback persistence, and physical acceptance remain outstanding. A serial-enabled boot attempt exposed a missing
initramfs package. After adding its resolved RPM
closure, the corrected development image completed disconnected installation and booted without media through systemd
to the root login/password prompts. After correcting shell readiness and PowerShell Enter handling, the retained
installation passed both chosen-password login and separate root/admin identity challenges. The receipt-bound
post-reboot comparison confirmed the unselected disk was unchanged. The console runner accepts
Photon's bracketed root prompts, colon-path prompts, and Bash fallback prompts after removing terminal colors/titles.
It refuses password-change conversations before submitting a shell command and still requires a separate
account-identity challenge.
The capacity-refusal and planned-layout cancellation scenarios passed with both fixture disks unchanged.
Do not infer reboot or persistence results from a completed installation run.

Publication is a separate, explicit workflow dispatch after the exact ISO has been validated. The maintainer supplies
`publish=true` and `validated_iso_sha256` for the ISO whose disconnected UEFI installation, reboot, Appliance Update
success and rollback persistence, and unselected-disk preservation were tested. The workflow requires that checksum
to match the signed draft index before publishing, then downloads and verifies the published assets again. The
development ISO has completed disconnected Auto installation, boot without media, chosen-account login challenges,
and the unselected-disk comparison. Public identity uniqueness and application wheel equality also passed. Full payload
equality and Appliance Update checks remain
unrecorded, so this result does not establish
full installer acceptance or authorize publication. Do not publish or describe the installer as validated before the
remaining acceptance evidence exists.

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
wheel, and preserved their unselected disks. Public identities were unique between them and stable across resumes
of the first VM. Broader installed-content equality, host-facing OpenAPI, disconnected update/rollback, custom/fault
scenarios, preservation of disks carrying old Atlaso labels, and the default serial installer boot path remain
outstanding. Do not describe the installer as validated or claim physical support while these gates are
outstanding. Secure Boot is disabled for phase one; this reference makes no Secure Boot or ARM support claim.

The first extended content run also matched all 1,299 copied source files, 20 deployed shared assets and the public
update trust key. Its Python check exposed unsupported wheel installation schemes in the older shared inspector;
that run does not establish installed dependency equality. Retain it as partial evidence with its original media
checksum and stopped-VM disk verification.

For disk selection, concealed initial credentials, first-boot networking, and recovery guidance, see
[Physical installation](../getting-started/physical-installation.md).
