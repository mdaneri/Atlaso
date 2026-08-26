<#
.SYNOPSIS
Create or redeploy the normal Atlaso VMware Workstation test appliance.

.DESCRIPTION
Clones the latest or explicitly selected Workstation appliance, attaches the fixed
data disks and requested lab adapters, injects the complete first-boot environment,
waits for the management address by default, and verifies the shared development
root CA. -TrustRootCa remains the explicit opt-in for changing Windows trust.

By default the wrapper validates the current Windows user's existing
.ssh/id_ed25519.pub before any cleanup or VM mutation, then provisions that public
key for the bootstrap administrator with test-only passwordless sudo. It never
creates or reads a private key. Use -SkipSshKeyProvisioning to retain the prior
password-backed development behavior.

After the VM starts, the wrapper reads the normal test VM's Ed25519 SSH host
public key through VMware guest-info and prints the exact key plus its SHA-256
fingerprint for explicit known_hosts verification.

.PARAMETER Name
VMware display name and default output-folder name for the test appliance.

.PARAMETER ApplianceVmxPath
Optional built appliance VMX to clone; the newest build output is selected by default.

.PARAMETER OutputDirectory
Optional exact destination directory for the cloned test VM.

.PARAMETER VmrunPath
Optional VMware vmrun executable override.

.PARAMETER ManagementNetwork
VMnet used by the management adapter.

.PARAMETER SiteANetwork
VMnet used by the optional Site A lab adapter.

.PARAMETER SiteBNetwork
VMnet used by the optional Site B lab adapter.

.PARAMETER TrunkNetwork
VMnet used by the optional trunk lab adapter.

.PARAMETER VdiskManagerPath
Optional VMware virtual-disk manager executable override.

.PARAMETER DepotVmdkPath
Optional exact path for the persistent depot data disk.

.PARAMETER BackupVmdkPath
Optional exact path for the persistent backup data disk.

.PARAMETER DepotDiskSize
Capacity used when creating or resetting the depot disk.

.PARAMETER BackupDiskSize
Capacity used when creating or resetting the backup disk.

.PARAMETER Redeploy
Safely remove and recreate only the exact named test VM.

.PARAMETER SkipLabNetworkAdapters
Create only the management adapter.

.PARAMETER IncludeLabNetworkAdapters
Explicitly include the complete lab adapter set.

.PARAMETER ResetDataDisks
Recreate the exact managed depot and backup disks after safety validation.

.PARAMETER NoStart
Unsupported for normal test VMs because first boot must consume and scrub the
shared development signing key.

.PARAMETER SkipNetworkPrepare
Use existing VMware networks without running network preparation.

.PARAMETER WaitForIp
Verify the development root CA and print the connection summary after mandatory
unique-address readiness succeeds. Enabled by default; opt out with -WaitForIp:$false.

.PARAMETER TrustRootCa
Explicitly trust the checked-in development root CA for the current Windows user.
An exact existing trust entry is reused without reimport.

.PARAMETER OnePasswordEnvironmentId
Opaque ID of the exact Atlaso 1Password Environment containing the concealed
ATLASO_DEVELOPMENT_ROOT_CA_PRIVATE_KEY variable. Required for real creation.

.PARAMETER FirstBootFqdn
Optional first-boot appliance FQDN override.

.PARAMETER AdminPassword
Initial Atlaso and Photon bootstrap administrator password.

.PARAMETER RootPassword
Initial Photon root console password.

.PARAMETER RootSshEnabled
Enable password-backed root SSH for this test VM; disabled by default.

.PARAMETER SshPublicKeyPath
Optional path to an existing Ed25519 public key. The current Windows user's
.ssh/id_ed25519.pub is the default.

.PARAMETER SkipSshKeyProvisioning
Skip the development administrator public key and passwordless-sudo provisioning.
Cannot be combined with -SshPublicKeyPath.

.PARAMETER TimeoutSeconds
Bounded wait used for the 1Password child, management-address discovery, and
root-CA readiness.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Name = 'Atlaso-VMware',
    [string]$ApplianceVmxPath = '',
    [string]$OutputDirectory = '',
    [string]$VmrunPath = '',
    [string]$ManagementNetwork = 'VMnet8',
    [string]$SiteANetwork = 'VMnet2',
    [string]$SiteBNetwork = 'VMnet3',
    [string]$TrunkNetwork = 'VMnet4',
    [string]$VdiskManagerPath = '',
    [string]$DepotVmdkPath = '',
    [string]$BackupVmdkPath = '',
    [string]$DepotDiskSize = '500GB',
    [string]$BackupDiskSize = '500GB',
    [switch]$Redeploy,
    [switch]$SkipLabNetworkAdapters,
    [switch]$IncludeLabNetworkAdapters,
    [switch]$ResetDataDisks,
    [switch]$NoStart,
    [switch]$SkipNetworkPrepare,
    [switch]$WaitForIp = $true,
    [switch]$TrustRootCa,
    [string]$OnePasswordEnvironmentId = '',
    [string]$FirstBootFqdn = '',
    [string]$AdminPassword = 'VMware01!Test',
    [string]$RootPassword = 'VMware01!Test',
    [switch]$RootSshEnabled,
    [string]$SshPublicKeyPath = '',
    [switch]$SkipSshKeyProvisioning,
    [ValidateRange(1, 3600)][int]$TimeoutSeconds = 300
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Atlaso.WorkstationFirstBoot.ps1')
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationCleanup.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Atlaso.VmwarePayload.psm1') -Force

<#
.SYNOPSIS
Resolve the 1Password CLI used for the development-CA bridge.

.PARAMETER CandidatePaths
Optional exact fallback executable paths used when PowerShell command discovery
does not include WinGet links.

.PARAMETER PackageRoot
Optional WinGet package root used when its executable link is unavailable.
#>
function Resolve-OnePasswordCliPath {
    param(
        [string[]]$CandidatePaths = @(
            (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Microsoft\WinGet\Links\op.exe'),
            (Join-Path ([Environment]::GetFolderPath('ProgramFiles')) '1Password CLI\op.exe')
        ),
        [string]$PackageRoot = (
            Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Microsoft\WinGet\Packages'
        )
    )

    $command = Get-Command op.exe -ErrorAction SilentlyContinue
    if (-not $command) {
        $command = Get-Command op -ErrorAction SilentlyContinue
    }
    if (-not $command) {
        foreach ($candidate in $CandidatePaths) {
            if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
                return (Resolve-Path -LiteralPath $candidate).Path
            }
        }
        if ($PackageRoot -and (Test-Path -LiteralPath $PackageRoot -PathType Container)) {
            $packageCandidates = @(Get-ChildItem -LiteralPath $PackageRoot -Directory |
                Where-Object { $_.Name -like 'AgileBits.1Password.CLI_*' } |
                ForEach-Object { Join-Path $_.FullName 'op.exe' } |
                Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
            if ($packageCandidates.Count -eq 1) {
                return (Resolve-Path -LiteralPath $packageCandidates[0]).Path
            }
            if ($packageCandidates.Count -gt 1) {
                throw 'Multiple 1Password CLI package executables were found; repair WinGet links or pass a single supported CLI on PATH.'
            }
        }
        throw 'The 1Password CLI (op.exe) is required for normal VMware test VM creation.'
    }
    return $command.Source
}

<#
.SYNOPSIS
Validate the opaque 1Password Environment ID and CLI Environment support.

.PARAMETER EnvironmentId
Opaque ID copied from the exact Atlaso 1Password Environment.

.PARAMETER OpPath
Resolved 1Password CLI executable path.

.PARAMETER ExpectedEnvironmentIdSha256
Pinned SHA-256 identity of the exact Atlaso Environment. The override exists
only so focused tests can exercise the guard without publishing the real ID.

.PARAMETER TimeoutSeconds
Positive deadline for the 1Password CLI capability probe.
#>
function Assert-OnePasswordDevelopmentCaBridge {
    param(
        [Parameter(Mandatory = $true)][string]$EnvironmentId,
        [Parameter(Mandatory = $true)][string]$OpPath,
        [string]$ExpectedEnvironmentIdSha256 = '1A0524FE2054BD148983E0AA9F755CC6ED575F88985256AFA802EA9CB5D782A4',
        [ValidateRange(1, 3600)][int]$TimeoutSeconds = 30
    )

    if ($EnvironmentId -notmatch '^[A-Za-z0-9_-]{8,128}$') {
        throw 'OnePasswordEnvironmentId is required and must be the opaque ID of the exact Atlaso Environment.'
    }
    $environmentIdDigest = [System.Security.Cryptography.SHA256]::HashData(
        [System.Text.Encoding]::UTF8.GetBytes($EnvironmentId)
    )
    $expectedEnvironmentIdDigest = [Convert]::FromHexString($ExpectedEnvironmentIdSha256)
    if (-not [System.Security.Cryptography.CryptographicOperations]::FixedTimeEquals(
            $environmentIdDigest,
            $expectedEnvironmentIdDigest
        )) {
        throw 'OnePasswordEnvironmentId does not identify the exact Atlaso Environment.'
    }
    if ($env:ATLASO_DEVELOPMENT_ROOT_CA_PRIVATE_KEY) {
        throw 'ATLASO_DEVELOPMENT_ROOT_CA_PRIVATE_KEY must come only from the exact 1Password Environment bridge.'
    }
    $runHelp = Invoke-AtlasoBoundedProcess `
        -FilePath $OpPath `
        -ArgumentList @('run', '--help') `
        -TimeoutSeconds $TimeoutSeconds `
        -Action 'The 1Password Environment capability probe'
    if ([string]::IsNullOrWhiteSpace($runHelp) -or $runHelp -notlike '*--environment*') {
        throw 'The installed 1Password CLI does not support op run --environment. Install the Environments-enabled CLI and retry.'
    }
}

<#
.SYNOPSIS
Run the bounded development-CA secret child under 1Password.

.PARAMETER EnvironmentId
Opaque ID of the exact Atlaso 1Password Environment.

.PARAMETER OpPath
Resolved 1Password CLI executable path.

.PARAMETER Action
Validate the signer or stage it in the newly created VMX.

.PARAMETER CertificatePath
Exact checked-in public development root certificate path.

.PARAMETER VmxPath
Exact new normal-test-VM VMX path for the Stage action.

.PARAMETER TimeoutSeconds
Positive deadline after which the complete op/secret-child process tree is
terminated so the caller can enter signer scrub and VM rollback.
#>
function Invoke-OnePasswordDevelopmentCaChild {
    param(
        [Parameter(Mandatory = $true)][string]$EnvironmentId,
        [Parameter(Mandatory = $true)][string]$OpPath,
        [Parameter(Mandatory = $true)][ValidateSet('Validate', 'Stage')][string]$Action,
        [Parameter(Mandatory = $true)][string]$CertificatePath,
        [string]$VmxPath = '',
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds
    )

    $powerShellPath = (Get-Process -Id $PID).Path
    $childPath = Join-Path $PSScriptRoot 'Invoke-AtlasoDevelopmentCaSecret.ps1'
    $arguments = @(
        'run', '--environment', $EnvironmentId, '--',
        $powerShellPath, '-NoProfile', '-NonInteractive', '-File', $childPath,
        '-Action', $Action, '-CertificatePath', $CertificatePath
    )
    if ($Action -eq 'Stage') {
        $arguments += @('-VmxPath', $VmxPath)
    }
    Invoke-AtlasoBoundedProcess `
        -FilePath $OpPath `
        -ArgumentList $arguments `
        -TimeoutSeconds $TimeoutSeconds `
        -Action "The bounded 1Password development-CA $Action child" | Out-Null
}

<#
.SYNOPSIS
Resolve VMware vmrun for guest-info scrub verification and rollback.

.PARAMETER Path
Optional explicit vmrun executable path.
#>
function Resolve-TestVmVmrunPath {
    param([string]$Path)

    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            throw "vmrun.exe not found: $Path"
        }
        return (Resolve-Path -LiteralPath $Path).Path
    }
    foreach ($candidate in @(
            'C:\Program Files\VMware\VMware Workstation\vmrun.exe',
            'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
        )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }
    $command = Get-Command vmrun -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    throw 'vmrun.exe was not found. Install VMware Workstation Pro or pass -VmrunPath.'
}

<#
.SYNOPSIS
Capture every in-directory file in one pre-existing data VMDK for rollback.

.PARAMETER DiskPath
Configured depot or backup VMDK path.

.PARAMETER OutputDirectory
Exact new VM artifact directory that recursive rollback may remove.
#>
function Get-AtlasoRollbackDataDiskState {
    param(
        [Parameter(Mandatory = $true)][string]$DiskPath,
        [Parameter(Mandatory = $true)][string]$OutputDirectory
    )

    if (-not (Test-Path -LiteralPath $DiskPath -PathType Leaf)) {
        return $null
    }
    $resolvedDiskPath = (Resolve-Path -LiteralPath $DiskPath).Path
    $resolvedOutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
    if (-not (Test-AtlasoStrictDescendantPath -ParentPath $resolvedOutputDirectory -ChildPath $resolvedDiskPath)) {
        return $null
    }
    Assert-AtlasoStrictDescendantPath `
        -ParentPath $resolvedOutputDirectory `
        -ChildPath $resolvedDiskPath `
        -FailureMessage 'Refusing to preserve a rollback data disk outside the exact VM directory'

    $componentPaths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $null = $componentPaths.Add($resolvedDiskPath)
    $stream = [System.IO.File]::OpenRead($resolvedDiskPath)
    try {
        $buffer = [byte[]]::new([Math]::Min([int64]1MB, $stream.Length))
        $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
    }
    finally {
        $stream.Dispose()
    }
    $descriptor = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead)
    $extentMatches = [regex]::Matches(
        $descriptor,
        '(?im)(?:^|[\r\n\x00])\s*RW\s+\d+\s+\S+(?:\s+"(?<file>[^"\r\n\x00]+)")?'
    )
    foreach ($extentMatch in $extentMatches) {
        $extentFile = $extentMatch.Groups['file'].Value
        if ([string]::IsNullOrWhiteSpace($extentFile)) {
            continue
        }
        $extentPath = if ([System.IO.Path]::IsPathFullyQualified($extentFile)) {
            [System.IO.Path]::GetFullPath($extentFile)
        }
        else {
            [System.IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $resolvedDiskPath) $extentFile))
        }
        # External extents are outside the recursive VM-artifact deletion and
        # must remain untouched. Every referenced in-directory extent is
        # identity-bound and moved with its descriptor.
        if (-not (Test-AtlasoStrictDescendantPath `
                    -ParentPath $resolvedOutputDirectory `
                    -ChildPath $extentPath)) {
            continue
        }
        Assert-AtlasoStrictDescendantPath `
            -ParentPath $resolvedOutputDirectory `
            -ChildPath $extentPath `
            -FailureMessage 'Refusing to preserve a rollback VMDK extent through an unsafe path'
        if (-not (Test-Path -LiteralPath $extentPath -PathType Leaf)) {
            throw "A reused in-directory VMware data-disk extent is missing: $extentPath"
        }
        $null = $componentPaths.Add((Resolve-Path -LiteralPath $extentPath).Path)
    }

    foreach ($componentPath in $componentPaths) {
        [pscustomobject]@{
            Path = $componentPath
            RelativePath = [System.IO.Path]::GetRelativePath($resolvedOutputDirectory, $componentPath)
            Identity = [Atlaso.WorkstationFileIdentity]::Get($componentPath)
            QuarantinePath = ''
        }
    }
}

<#
.SYNOPSIS
Capture non-overlapping rollback state for every configured VMware data disk.

.PARAMETER DiskPaths
Configured depot and backup VMDK paths.

.PARAMETER OutputDirectory
Exact new VM artifact directory that recursive rollback may remove.
#>
function Get-AtlasoRollbackDataDiskStates {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$DiskPaths,
        [Parameter(Mandatory = $true)][string]$OutputDirectory
    )

    $states = [System.Collections.Generic.List[object]]::new()
    $identityOwners = [System.Collections.Generic.Dictionary[string, string]]::new(
        [System.StringComparer]::Ordinal
    )
    foreach ($diskPath in $DiskPaths) {
        foreach ($state in @(Get-AtlasoRollbackDataDiskState `
                    -DiskPath $diskPath `
                    -OutputDirectory $OutputDirectory)) {
            $existingPath = ''
            if ($identityOwners.TryGetValue($state.Identity, [ref]$existingPath)) {
                throw "Configured VMware rollback data disks overlap at one filesystem object: $($state.Path) and $existingPath"
            }
            $identityOwners.Add($state.Identity, $state.Path)
            $states.Add($state)
        }
    }
    return $states.ToArray()
}

<#
.SYNOPSIS
Move pre-existing data disks outside a failed VM's recursive cleanup root.

.PARAMETER DataDiskStates
Captured in-directory VMDK component paths and filesystem identities.

.PARAMETER QuarantineDirectory
Fresh sibling directory used only while the new VM artifacts are removed.
#>
function Move-AtlasoRollbackDataDisksToQuarantine {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$DataDiskStates,
        [Parameter(Mandatory = $true)][string]$QuarantineDirectory
    )

    if ($DataDiskStates.Count -eq 0) {
        return
    }
    if (Test-Path -LiteralPath $QuarantineDirectory) {
        throw "Refusing an existing rollback quarantine directory: $QuarantineDirectory"
    }
    New-Item -ItemType Directory -Path $QuarantineDirectory | Out-Null
    foreach ($state in $DataDiskStates) {
        if ([Atlaso.WorkstationFileIdentity]::Get($state.Path) -ne $state.Identity) {
            throw "A pre-existing VMware data disk changed identity before rollback; it was preserved in place: $($state.Path)"
        }
        $quarantinePath = Join-Path $QuarantineDirectory $state.RelativePath
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $quarantinePath) | Out-Null
        Move-Item -LiteralPath $state.Path -Destination $quarantinePath
        $state.QuarantinePath = $quarantinePath
        if (
            (Test-Path -LiteralPath $state.Path) -or
            [Atlaso.WorkstationFileIdentity]::Get($quarantinePath) -ne $state.Identity
        ) {
            throw "A pre-existing VMware data disk could not be proven in rollback quarantine: $($state.Path)"
        }
    }
}

<#
.SYNOPSIS
Restore pre-existing data disks after failed-VM artifact cleanup.

.PARAMETER DataDiskStates
Captured VMDK components whose non-empty quarantine paths must be restored.

.PARAMETER QuarantineDirectory
Exact invocation-owned sibling quarantine directory.
#>
function Restore-AtlasoRollbackDataDisksFromQuarantine {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$DataDiskStates,
        [Parameter(Mandatory = $true)][string]$QuarantineDirectory
    )

    foreach ($state in $DataDiskStates) {
        if (-not $state.QuarantinePath) {
            continue
        }
        if (Test-Path -LiteralPath $state.Path) {
            throw "Refusing to overwrite a path while restoring a pre-existing VMware data disk: $($state.Path)"
        }
        if ([Atlaso.WorkstationFileIdentity]::Get($state.QuarantinePath) -ne $state.Identity) {
            throw "A quarantined VMware data disk changed identity and was preserved for manual recovery: $($state.QuarantinePath)"
        }
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $state.Path) | Out-Null
        Move-Item -LiteralPath $state.QuarantinePath -Destination $state.Path
        if ([Atlaso.WorkstationFileIdentity]::Get($state.Path) -ne $state.Identity) {
            throw "A restored VMware data disk failed identity verification: $($state.Path)"
        }
        $state.QuarantinePath = ''
    }
    if (Test-Path -LiteralPath $QuarantineDirectory) {
        if (@(Get-ChildItem -LiteralPath $QuarantineDirectory -File -Recurse -Force).Count -gt 0) {
            throw "Rollback quarantine still contains files and was preserved: $QuarantineDirectory"
        }
        Remove-Item -LiteralPath $QuarantineDirectory -Recurse -Force
    }
}

<#
.SYNOPSIS
Stop the exact failed normal test VM when it is still running.

.PARAMETER VmxPath
Exact new VMX owned by the current invocation.

.PARAMETER VmrunPath
Resolved VMware vmrun executable path.

.PARAMETER TimeoutSeconds
Positive per-operation deadline for discovery, stop, and stopped-state proof.
#>
function Stop-AtlasoTestVmForRollback {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [ValidateRange(1, 3600)][int]$TimeoutSeconds = 30
    )

    $resolvedVmxPath = (Resolve-Path -LiteralPath $VmxPath).Path
    $targetIdentity = [Atlaso.WorkstationFileIdentity]::Get($resolvedVmxPath)
    $runningText = Invoke-AtlasoBoundedVmrun `
        -VmrunPath $VmrunPath `
        -ArgumentList @('-T', 'ws', 'list') `
        -TimeoutSeconds $TimeoutSeconds `
        -Action 'Discover VMware Workstation running state during rollback'
    $runningPaths = @(ConvertFrom-AtlasoVmrunListOutput -Output @($runningText -split '\r?\n'))
    $runningTargets = @($runningPaths | Where-Object {
            Test-AtlasoTestVmRunningPathMatchesIdentity `
                -RunningPath $_.Trim() `
                -TargetIdentity $targetIdentity
        })
    if ($runningTargets.Count -eq 0) {
        return
    }
    Invoke-AtlasoBoundedVmrun `
        -VmrunPath $VmrunPath `
        -ArgumentList @('-T', 'ws', 'stop', $runningTargets[0], 'hard') `
        -TimeoutSeconds $TimeoutSeconds `
        -Action 'Stop the failed normal test VM during rollback' | Out-Null
    $runningText = Invoke-AtlasoBoundedVmrun `
        -VmrunPath $VmrunPath `
        -ArgumentList @('-T', 'ws', 'list') `
        -TimeoutSeconds $TimeoutSeconds `
        -Action 'Verify the failed normal test VM stopped during rollback'
    $runningPaths = @(ConvertFrom-AtlasoVmrunListOutput -Output @($runningText -split '\r?\n'))
    foreach ($runningPath in $runningPaths) {
        if (Test-AtlasoTestVmRunningPathMatchesIdentity `
                -RunningPath $runningPath.Trim() `
                -TargetIdentity $targetIdentity) {
            throw 'The failed normal test VM remained running during rollback.'
        }
    }
}

<#
.SYNOPSIS
Match one running VMware VMX path to the rollback target by file identity.

.PARAMETER RunningPath
Fully qualified VMX path reported by VMware Workstation.

.PARAMETER TargetIdentity
Stable filesystem identity captured from the invocation-owned VMX.
#>
function Test-AtlasoTestVmRunningPathMatchesIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$RunningPath,
        [Parameter(Mandatory = $true)][string]$TargetIdentity
    )

    if (-not [System.IO.Path]::IsPathFullyQualified($RunningPath)) {
        return $false
    }
    if (-not (Test-Path -LiteralPath $RunningPath -PathType Leaf)) {
        return $false
    }
    try {
        return [Atlaso.WorkstationFileIdentity]::Get($RunningPath) -eq $TargetIdentity
    }
    catch {
        throw "Running VMware VMX filesystem identity cannot be resolved during rollback: $RunningPath"
    }
}

<#
.SYNOPSIS
Return the per-user durable development-CA cleanup marker directory.
#>
function Get-AtlasoDevelopmentCaCleanupMarkerRoot {
    return Join-Path `
        ([Environment]::GetFolderPath('LocalApplicationData')) `
        'Atlaso\vmware-development-ca-cleanup'
}

<#
.SYNOPSIS
Return a stable identity for the current Windows host boot.
#>
function Get-AtlasoHostBootIdentity {
    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop |
    Select-Object -First 1
    if ($null -eq $operatingSystem -or $null -eq $operatingSystem.LastBootUpTime) {
        throw 'The Windows host boot identity could not be determined.'
    }
    return ([DateTimeOffset]$operatingSystem.LastBootUpTime).ToUniversalTime().Ticks.ToString(
        [System.Globalization.CultureInfo]::InvariantCulture
    )
}

<#
.SYNOPSIS
Atomically rename one cleanup-marker file with Windows write-through durability.

.PARAMETER SourcePath
Exact flushed temporary marker file.

.PARAMETER DestinationPath
Exact durable marker path in the same directory.

.PARAMETER Replace
Replace the existing destination during a validated marker-phase transition.
#>
function Move-AtlasoDurableCleanupMarkerFile {
    param(
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$DestinationPath,
        [switch]$Replace
    )

    if (-not $IsWindows) {
        throw 'Durable development-CA cleanup-marker rename requires Windows.'
    }
    $resolvedSourcePath = (Resolve-Path -LiteralPath $SourcePath).Path
    $resolvedDestinationPath = [System.IO.Path]::GetFullPath($DestinationPath)
    if (-not $resolvedSourcePath.Equals(
            [System.IO.Path]::GetFullPath($SourcePath),
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
        throw "Development-CA cleanup-marker source identity is ambiguous: $SourcePath"
    }
    if (-not ('Atlaso.WorkstationDurableFile' -as [type])) {
        Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;

namespace Atlaso
{
    public static class WorkstationDurableFile
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool MoveFileEx(string existingPath, string newPath, uint flags);
    }
}
'@
    }
    # MOVEFILE_WRITE_THROUGH makes the rename wait for on-disk completion;
    # phase replacement additionally uses MOVEFILE_REPLACE_EXISTING.
    [uint32]$flags = 0x00000008
    if ($Replace) {
        $flags = $flags -bor 0x00000001
    }
    if (-not [Atlaso.WorkstationDurableFile]::MoveFileEx(
            $resolvedSourcePath,
            $resolvedDestinationPath,
            $flags
        )) {
        $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw [System.ComponentModel.Win32Exception]::new(
            $errorCode,
            "Development-CA cleanup-marker write-through rename failed"
        )
    }
    if (
        (Test-Path -LiteralPath $resolvedSourcePath) -or
        -not (Test-Path -LiteralPath $resolvedDestinationPath -PathType Leaf)
    ) {
        throw "Development-CA cleanup-marker write-through rename could not be proven: $resolvedDestinationPath"
    }
}

<#
.SYNOPSIS
Persist rollback ownership before the shared development signer is staged.

.PARAMETER VmxPath
Exact invocation-owned normal-test-VM VMX path.

.PARAMETER Name
Expected VMware display name used by guarded artifact cleanup.

.PARAMETER OutputDirectory
Exact invocation-owned VM artifact directory.

.PARAMETER DataDiskStates
Pre-existing data-disk identities that destructive retry must preserve.

.PARAMETER MarkerRoot
Per-user marker directory; override only for focused tests.
#>
function New-AtlasoDevelopmentCaCleanupMarker {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$DataDiskStates,
        [string]$MarkerRoot = (Get-AtlasoDevelopmentCaCleanupMarkerRoot)
    )

    $resolvedVmxPath = (Resolve-Path -LiteralPath $VmxPath).Path
    $resolvedOutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
    Assert-AtlasoStrictDescendantPath `
        -ParentPath $resolvedOutputDirectory `
        -ChildPath $resolvedVmxPath `
        -FailureMessage 'Refusing to record development-CA cleanup outside the exact VM directory'
    if (-not (Test-Path -LiteralPath $MarkerRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $MarkerRoot -Force | Out-Null
    }
    Assert-AtlasoStrictDescendantPath `
        -ParentPath (Split-Path -Parent $MarkerRoot) `
        -ChildPath $MarkerRoot `
        -FailureMessage 'Refusing a development-CA marker directory through a reparse point'
    $markerId = [guid]::NewGuid().ToString('N')
    $markerPath = Join-Path $MarkerRoot "$markerId.json"
    $temporaryPath = Join-Path $MarkerRoot "$markerId.tmp"
    # Keep preserved data on the VM artifact volume so quarantine uses a
    # same-volume rename and retains the recorded filesystem identity.
    $quarantineDirectory = Join-Path `
        (Split-Path -Parent $resolvedOutputDirectory) `
        ".atlaso-development-ca-cleanup-$markerId"
    $payload = [ordered]@{
        Schema = 2
        Phase = 'secret-child-active'
        HostBootIdentity = (Get-AtlasoHostBootIdentity)
        Name = $Name
        VmxPath = $resolvedVmxPath
        VmxIdentity = [Atlaso.WorkstationFileIdentity]::Get($resolvedVmxPath)
        OutputDirectory = $resolvedOutputDirectory
        QuarantineDirectory = $quarantineDirectory
        CreatedUtc = [DateTimeOffset]::UtcNow.ToString('O')
        DataDisks = @(
            foreach ($state in $DataDiskStates) {
                [ordered]@{
                    Path = $state.Path
                    RelativePath = $state.RelativePath
                    Identity = $state.Identity
                }
            }
        )
    }
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        ($payload | ConvertTo-Json -Depth 4 -Compress)
    )
    try {
        $stream = [System.IO.FileStream]::new(
            $temporaryPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None,
            4096,
            [System.IO.FileOptions]::WriteThrough
        )
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }
        # The signer-bearing VMX may be flushed immediately after this returns;
        # require the marker directory entry itself to reach disk first.
        Move-AtlasoDurableCleanupMarkerFile `
            -SourcePath $temporaryPath `
            -DestinationPath $markerPath
        return $markerPath
    }
    finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    }
}

<#
.SYNOPSIS
Durably advance one development-CA cleanup marker phase.

.PARAMETER MarkerPath
Exact invocation marker whose phase must advance.

.PARAMETER ExpectedPhase
Current phase required before replacement.

.PARAMETER Phase
Next cleanup phase proven by the caller.
#>
function Set-AtlasoDevelopmentCaCleanupMarkerPhase {
    param(
        [Parameter(Mandatory = $true)][string]$MarkerPath,
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'secret-child-active',
            'staged',
            'vm-start-child-active',
            'stopped-vmx-scrubbed',
            'removal-child-active',
            'retired'
        )]
        [string]$ExpectedPhase,
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'staged',
            'vm-start-child-active',
            'stopped-vmx-scrubbed',
            'removal-child-active',
            'retired'
        )]
        [string]$Phase
    )

    $resolvedMarkerPath = (Resolve-Path -LiteralPath $MarkerPath).Path
    $item = Get-Item -LiteralPath $resolvedMarkerPath -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -gt 32768) {
        throw "Development-CA cleanup marker is unsafe: $resolvedMarkerPath"
    }
    try {
        $payload = Get-Content -LiteralPath $resolvedMarkerPath -Raw | ConvertFrom-Json
    }
    catch {
        throw "Development-CA cleanup marker is invalid: $resolvedMarkerPath"
    }
    $validTransition = switch ($ExpectedPhase) {
        'secret-child-active' { $Phase -cin @('staged', 'stopped-vmx-scrubbed') }
        'staged' { $Phase -cin @('vm-start-child-active', 'stopped-vmx-scrubbed', 'retired') }
        'vm-start-child-active' { $Phase -cin @('staged', 'stopped-vmx-scrubbed') }
        'stopped-vmx-scrubbed' { $Phase -cin @('removal-child-active', 'retired') }
        'removal-child-active' { $Phase -ceq 'stopped-vmx-scrubbed' }
        default { $false }
    }
    if ($payload.Schema -ne 2 -or $payload.Phase -cne $ExpectedPhase -or -not $validTransition) {
        throw "Development-CA cleanup marker phase did not match the required transition: $resolvedMarkerPath"
    }
    $payload.Phase = $Phase
    $temporaryPath = "$resolvedMarkerPath.$([guid]::NewGuid().ToString('N')).tmp"
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        ($payload | ConvertTo-Json -Depth 4 -Compress)
    )
    try {
        $stream = [System.IO.FileStream]::new(
            $temporaryPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None,
            4096,
            [System.IO.FileOptions]::WriteThrough
        )
        try {
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush($true)
        }
        finally {
            $stream.Dispose()
        }
        Move-AtlasoDurableCleanupMarkerFile `
            -SourcePath $temporaryPath `
            -DestinationPath $resolvedMarkerPath `
            -Replace
    }
    finally {
        Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
    }
}

<#
.SYNOPSIS
Durably retire and remove an exact development-CA cleanup marker.

.PARAMETER MarkerPath
Exact invocation marker to remove.
#>
function Remove-AtlasoDevelopmentCaCleanupMarker {
    param([Parameter(Mandatory = $true)][string]$MarkerPath)

    if (Test-Path -LiteralPath $MarkerPath -PathType Leaf) {
        $marker = Read-AtlasoDevelopmentCaCleanupMarker `
            -MarkerPath $MarkerPath `
            -MarkerRoot (Split-Path -Parent $MarkerPath)
        if ($marker.Phase -cne 'retired') {
            if ($marker.Phase -notin @('staged', 'stopped-vmx-scrubbed')) {
                throw "Development-CA cleanup marker cannot be safely retired from phase $($marker.Phase): $MarkerPath"
            }
            # A write-through tombstone makes a post-delete resurrection
            # non-actionable after successful import or rollback completion.
            Set-AtlasoDevelopmentCaCleanupMarkerPhase `
                -MarkerPath $marker.MarkerPath `
                -ExpectedPhase $marker.Phase `
                -Phase retired
        }
        Remove-Item -LiteralPath $MarkerPath -Force
    }
    if (Test-Path -LiteralPath $MarkerPath) {
        throw "Development-CA cleanup marker removal could not be proven: $MarkerPath"
    }
}

<#
.SYNOPSIS
Load and validate one durable development-CA cleanup marker.

.PARAMETER MarkerPath
Exact marker file discovered below the per-user marker root.

.PARAMETER MarkerRoot
Expected marker parent directory.
#>
function Read-AtlasoDevelopmentCaCleanupMarker {
    param(
        [Parameter(Mandatory = $true)][string]$MarkerPath,
        [Parameter(Mandatory = $true)][string]$MarkerRoot
    )

    Assert-AtlasoStrictDescendantPath `
        -ParentPath $MarkerRoot `
        -ChildPath $MarkerPath `
        -FailureMessage 'Refusing a development-CA cleanup marker outside the exact marker root'
    $item = Get-Item -LiteralPath $MarkerPath -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -gt 32768) {
        throw "Development-CA cleanup marker is unsafe: $MarkerPath"
    }
    try {
        $marker = Get-Content -LiteralPath $MarkerPath -Raw | ConvertFrom-Json
    }
    catch {
        throw "Development-CA cleanup marker is invalid and blocks new VM creation: $MarkerPath"
    }
    if (
        $marker.Schema -ne 2 -or
        $marker.Phase -notin @(
            'secret-child-active',
            'staged',
            'vm-start-child-active',
            'stopped-vmx-scrubbed',
            'removal-child-active',
            'retired'
        ) -or
        [string]::IsNullOrWhiteSpace([string]$marker.HostBootIdentity) -or
        [string]::IsNullOrWhiteSpace([string]$marker.Name) -or
        ([string]$marker.Name).Length -gt 128 -or
        $marker.Name -match '[\x00-\x1F]' -or
        -not [System.IO.Path]::IsPathFullyQualified([string]$marker.VmxPath) -or
        -not [System.IO.Path]::IsPathFullyQualified([string]$marker.OutputDirectory) -or
        -not [System.IO.Path]::IsPathFullyQualified([string]$marker.QuarantineDirectory) -or
        $marker.VmxIdentity -notmatch '^[0-9A-F]{8}:[0-9A-F]{16}$'
    ) {
        throw "Development-CA cleanup marker fields are invalid and block new VM creation: $MarkerPath"
    }
    [long]$markerBootTicks = 0
    if (
        $marker.HostBootIdentity -notmatch '^[0-9]{1,19}$' -or
        -not [long]::TryParse(
            [string]$marker.HostBootIdentity,
            [System.Globalization.NumberStyles]::None,
            [System.Globalization.CultureInfo]::InvariantCulture,
            [ref]$markerBootTicks
        ) -or
        $markerBootTicks -le 0
    ) {
        throw "Development-CA cleanup marker host boot identity is invalid: $MarkerPath"
    }
    $resolvedVmxPath = [System.IO.Path]::GetFullPath([string]$marker.VmxPath)
    $resolvedOutputDirectory = [System.IO.Path]::GetFullPath([string]$marker.OutputDirectory)
    $resolvedQuarantineDirectory = [System.IO.Path]::GetFullPath([string]$marker.QuarantineDirectory)
    $markerId = [System.IO.Path]::GetFileNameWithoutExtension($MarkerPath)
    $expectedQuarantineDirectory = Join-Path `
        (Split-Path -Parent $resolvedOutputDirectory) `
        ".atlaso-development-ca-cleanup-$markerId"
    if (-not $resolvedQuarantineDirectory.Equals(
            [System.IO.Path]::GetFullPath($expectedQuarantineDirectory),
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
        throw "Development-CA cleanup quarantine identity is invalid: $MarkerPath"
    }
    if ($marker.Phase -ceq 'retired') {
        # The tombstone may reappear after a non-durable delete, but it must
        # never recover the VM or data paths as an actionable cleanup record.
        return [pscustomobject]@{
            MarkerPath = (Resolve-Path -LiteralPath $MarkerPath).Path
            Name = [string]$marker.Name
            VmxPath = $resolvedVmxPath
            OutputDirectory = $resolvedOutputDirectory
            DataDisks = @()
            QuarantineDirectory = $resolvedQuarantineDirectory
            HostBootIdentity = $markerBootTicks.ToString(
                [System.Globalization.CultureInfo]::InvariantCulture
            )
            Phase = 'retired'
            ArtifactsRemoved = $false
        }
    }
    Assert-AtlasoStrictDescendantPath `
        -ParentPath $resolvedOutputDirectory `
        -ChildPath $resolvedVmxPath `
        -FailureMessage 'Marked development-CA VMX is outside its exact artifact directory'
    $artifactsRemoved = -not (Test-Path -LiteralPath $resolvedOutputDirectory)
    if ($artifactsRemoved) {
        if ($marker.Phase -notin @('stopped-vmx-scrubbed', 'removal-child-active')) {
            throw "The marked VM artifacts disappeared before stopped-VM proof; preserve the marker for manual review: $MarkerPath"
        }
    }
    else {
        if (-not (Test-Path -LiteralPath $resolvedVmxPath -PathType Leaf)) {
            if ($marker.Phase -notin @('stopped-vmx-scrubbed', 'removal-child-active')) {
                throw "The marked VMX disappeared before stopped-VM proof; preserve the marker for manual review: $MarkerPath"
            }
            $allowedRestoredPaths = @(
                foreach ($disk in @($marker.DataDisks)) {
                    if (-not [System.IO.Path]::IsPathFullyQualified([string]$disk.Path)) {
                        throw "Development-CA cleanup data-disk path is invalid: $MarkerPath"
                    }
                    [System.IO.Path]::GetFullPath([string]$disk.Path)
                }
            )
            foreach ($remainingFile in @(Get-ChildItem -LiteralPath $resolvedOutputDirectory -File -Recurse -Force)) {
                if (-not ($allowedRestoredPaths | Where-Object {
                            $_.Equals($remainingFile.FullName, [System.StringComparison]::OrdinalIgnoreCase)
                        })) {
                    throw "Unexpected files remain after marked VM removal; preserve the marker for manual review: $($remainingFile.FullName)"
                }
            }
            $artifactsRemoved = $true
        }
        elseif ([Atlaso.WorkstationFileIdentity]::Get($resolvedVmxPath) -cne $marker.VmxIdentity) {
            throw "The marked VMX changed filesystem identity; preserve it for manual review: $MarkerPath"
        }
    }
    return [pscustomobject]@{
        MarkerPath = (Resolve-Path -LiteralPath $MarkerPath).Path
        Name = [string]$marker.Name
        VmxPath = $resolvedVmxPath
        OutputDirectory = $resolvedOutputDirectory
        DataDisks = @($marker.DataDisks)
        QuarantineDirectory = $resolvedQuarantineDirectory
        HostBootIdentity = $markerBootTicks.ToString(
            [System.Globalization.CultureInfo]::InvariantCulture
        )
        Phase = [string]$marker.Phase
        ArtifactsRemoved = $artifactsRemoved
    }
}

<#
.SYNOPSIS
Retry every interrupted development-CA rollback before another VM mutation.

.PARAMETER VmrunPath
Resolved VMware vmrun executable used for bounded scrub and stop proof.

.PARAMETER TimeoutSeconds
Positive per-operation deadline.

.PARAMETER MarkerRoot
Per-user marker directory; override only for focused tests.
#>
function Invoke-PendingAtlasoDevelopmentCaCleanup {
    param(
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds,
        [string]$MarkerRoot = (Get-AtlasoDevelopmentCaCleanupMarkerRoot)
    )

    if (-not (Test-Path -LiteralPath $MarkerRoot -PathType Container)) {
        return
    }
    Assert-AtlasoStrictDescendantPath `
        -ParentPath (Split-Path -Parent $MarkerRoot) `
        -ChildPath $MarkerRoot `
        -FailureMessage 'Refusing a development-CA marker directory through a reparse point'
    $unexpectedFiles = @(Get-ChildItem -LiteralPath $MarkerRoot -File -Force | Where-Object Extension -ne '.json')
    if ($unexpectedFiles.Count -gt 0) {
        throw "Unexpected development-CA cleanup state blocks new VM creation: $($unexpectedFiles[0].FullName)"
    }
    foreach ($markerFile in @(Get-ChildItem -LiteralPath $MarkerRoot -File -Filter '*.json' -Force)) {
        $marker = Read-AtlasoDevelopmentCaCleanupMarker `
            -MarkerPath $markerFile.FullName `
            -MarkerRoot $MarkerRoot
        if ($marker.Phase -ceq 'retired') {
            Remove-AtlasoDevelopmentCaCleanupMarker -MarkerPath $marker.MarkerPath
            continue
        }
        if (
            $marker.Phase -in @(
                'secret-child-active',
                'vm-start-child-active',
                'removal-child-active'
            ) -and
            (Get-AtlasoHostBootIdentity) -ceq $marker.HostBootIdentity
        ) {
            throw "Development-CA cleanup is deferred until a Windows host restart proves the unbounded process tree is gone: $($marker.MarkerPath)"
        }
        $quarantineDirectory = $marker.QuarantineDirectory
        $dataDiskStates = @(
            foreach ($disk in $marker.DataDisks) {
                if (
                    -not [System.IO.Path]::IsPathFullyQualified([string]$disk.Path) -or
                    [string]::IsNullOrWhiteSpace([string]$disk.RelativePath) -or
                    [System.IO.Path]::IsPathRooted([string]$disk.RelativePath) -or
                    ([string]$disk.RelativePath).StartsWith('..') -or
                    $disk.Identity -notmatch '^[0-9A-F]{8}:[0-9A-F]{16}$'
                ) {
                    throw "Development-CA cleanup data-disk state is invalid: $($marker.MarkerPath)"
                }
                Assert-AtlasoStrictDescendantPath `
                    -ParentPath $marker.OutputDirectory `
                    -ChildPath ([string]$disk.Path) `
                    -FailureMessage 'Marked rollback data disk is outside the exact VM directory'
                $quarantinePath = Join-Path $quarantineDirectory ([string]$disk.RelativePath)
                $state = [pscustomobject]@{
                    Path = [string]$disk.Path
                    RelativePath = [string]$disk.RelativePath
                    Identity = [string]$disk.Identity
                    QuarantinePath = ''
                }
                if (Test-Path -LiteralPath $state.Path -PathType Leaf) {
                    if ([Atlaso.WorkstationFileIdentity]::Get($state.Path) -cne $state.Identity) {
                        throw "A marked rollback data disk changed identity: $($state.Path)"
                    }
                }
                elseif (Test-Path -LiteralPath $quarantinePath -PathType Leaf) {
                    if ([Atlaso.WorkstationFileIdentity]::Get($quarantinePath) -cne $state.Identity) {
                        throw "A quarantined rollback data disk changed identity: $quarantinePath"
                    }
                    $state.QuarantinePath = $quarantinePath
                }
                else {
                    throw "A marked rollback data disk is missing from both safe locations: $($state.Path)"
                }
                $state
            }
        )
        if (-not $marker.ArtifactsRemoved) {
            try {
                Clear-AtlasoWorkstationDevelopmentRootCaRuntimePrivateKey `
                    -VmxPath $marker.VmxPath `
                    -VmrunPath $VmrunPath `
                    -TimeoutSeconds $TimeoutSeconds
            }
            catch {
                # A powered-off guest rejects runtime writes. Stop proof and the
                # powered-off VMX scrub below remain authoritative in that case.
            }
            Stop-AtlasoTestVmForRollback `
                -VmxPath $marker.VmxPath `
                -VmrunPath $VmrunPath `
                -TimeoutSeconds $TimeoutSeconds
            Clear-AtlasoWorkstationDevelopmentRootCaPrivateKey -VmxPath $marker.VmxPath
            if ($marker.Phase -in @('secret-child-active', 'staged', 'vm-start-child-active')) {
                # Publish stopped/scrubbed proof before artifact removal. A
                # later retry may then safely resume data restoration even
                # when the VMX and its artifact root are already absent.
                Set-AtlasoDevelopmentCaCleanupMarkerPhase `
                    -MarkerPath $marker.MarkerPath `
                    -ExpectedPhase $marker.Phase `
                    -Phase stopped-vmx-scrubbed
                $marker.Phase = 'stopped-vmx-scrubbed'
            }
        }
        try {
            $statesToMove = @($dataDiskStates | Where-Object { -not $_.QuarantinePath })
            if ($statesToMove.Count -gt 0) {
                if (-not (Test-Path -LiteralPath $quarantineDirectory -PathType Container)) {
                    New-Item -ItemType Directory -Path $quarantineDirectory | Out-Null
                }
                Assert-AtlasoStrictDescendantPath `
                    -ParentPath (Split-Path -Parent $marker.OutputDirectory) `
                    -ChildPath $quarantineDirectory `
                    -FailureMessage 'Refusing rollback quarantine through a reparse point'
                foreach ($state in $statesToMove) {
                    $quarantinePath = Join-Path $quarantineDirectory $state.RelativePath
                    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $quarantinePath) | Out-Null
                    Move-Item -LiteralPath $state.Path -Destination $quarantinePath
                    $state.QuarantinePath = $quarantinePath
                    if ([Atlaso.WorkstationFileIdentity]::Get($quarantinePath) -cne $state.Identity) {
                        throw "A marked rollback data disk failed quarantine identity proof: $quarantinePath"
                    }
                }
            }
            if (-not $marker.ArtifactsRemoved) {
                $powerShellPath = (Get-Process -Id $PID).Path
                if ($marker.Phase -ceq 'stopped-vmx-scrubbed') {
                    # Commit the boot-bound child-active phase before launch so
                    # an unproven removal tree can never race disk restoration.
                    Set-AtlasoDevelopmentCaCleanupMarkerPhase `
                        -MarkerPath $marker.MarkerPath `
                        -ExpectedPhase stopped-vmx-scrubbed `
                        -Phase removal-child-active
                    $marker.Phase = 'removal-child-active'
                }
                try {
                    Invoke-AtlasoBoundedProcess `
                        -FilePath $powerShellPath `
                        -ArgumentList @(
                            '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
                            (Join-Path $PSScriptRoot 'remove-atlaso-vm.ps1'),
                            '-VmxPath', $marker.VmxPath,
                            '-VmrunPath', $VmrunPath,
                            '-ExpectedName', $marker.Name,
                            '-Confirm:$false'
                        ) `
                        -TimeoutSeconds $TimeoutSeconds `
                        -Action 'Remove the exact failed normal test VM during persisted cleanup' | Out-Null
                }
                catch {
                    if ($_.Exception.Data['AtlasoProcessTreeTerminationUnproven'] -eq $true) {
                        throw
                    }
                    Set-AtlasoDevelopmentCaCleanupMarkerPhase `
                        -MarkerPath $marker.MarkerPath `
                        -ExpectedPhase removal-child-active `
                        -Phase stopped-vmx-scrubbed
                    $marker.Phase = 'stopped-vmx-scrubbed'
                    throw
                }
                Set-AtlasoDevelopmentCaCleanupMarkerPhase `
                    -MarkerPath $marker.MarkerPath `
                    -ExpectedPhase removal-child-active `
                    -Phase stopped-vmx-scrubbed
                $marker.Phase = 'stopped-vmx-scrubbed'
            }
            Restore-AtlasoRollbackDataDisksFromQuarantine `
                -DataDiskStates $dataDiskStates `
                -QuarantineDirectory $quarantineDirectory
            Remove-AtlasoDevelopmentCaCleanupMarker -MarkerPath $marker.MarkerPath
        }
        catch {
            $cleanupFailure = $_
            if ($cleanupFailure.Exception.Data['AtlasoProcessTreeTerminationUnproven'] -eq $true) {
                throw "$($cleanupFailure.Exception.Message) Preserved data remains in $quarantineDirectory and the durable cleanup marker remains at $($marker.MarkerPath); restart Windows before retrying cleanup."
            }
            try {
                Restore-AtlasoRollbackDataDisksFromQuarantine `
                    -DataDiskStates $dataDiskStates `
                    -QuarantineDirectory $quarantineDirectory
            }
            catch {
                throw "$($cleanupFailure.Exception.Message) Preserved data remains in $quarantineDirectory and the durable cleanup marker remains at $($marker.MarkerPath)."
            }
            throw "$($cleanupFailure.Exception.Message) The durable cleanup marker remains for the next bounded retry: $($marker.MarkerPath)"
        }
    }
}

<#
.SYNOPSIS
Find the most recently written built Workstation appliance VMX.

.PARAMETER RepoRoot
The Atlaso repository root containing image/vmware-workstation/output.
#>
function Find-LatestApplianceVmx {
    param([string]$RepoRoot)

    $outputRoot = Join-Path $RepoRoot 'image\vmware-workstation\output'
    if (-not (Test-Path -LiteralPath $outputRoot)) {
        throw "VMware Workstation output directory not found: $outputRoot. Build the image first or pass -ApplianceVmxPath."
    }

    $selected = Get-ChildItem -LiteralPath $outputRoot -Recurse -Filter '*.vmx' -File |
    Sort-Object -Property LastWriteTime -Descending |
    Select-Object -First 1
    if (-not $selected) {
        throw "No appliance VMX found under $outputRoot. Build the Workstation image first or pass -ApplianceVmxPath."
    }
    return $selected.FullName
}

<#
.SYNOPSIS
Wait for and verify the shared Atlaso development root CA.

.PARAMETER IpAddress
The running appliance management IPv4 address.

.PARAMETER TimeoutSeconds
The total readiness deadline.

.PARAMETER PollSeconds
The delay between transient readiness failures.

.PARAMETER ExpectedCertificatePath
Exact checked-in public development root certificate path.

.PARAMETER TrustRootCa
Whether to add the exact development root to current-user Windows trust.
#>
function Install-ApplianceRootCa {
    param(
        [Parameter(Mandatory = $true)][string]$IpAddress,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][string]$ExpectedCertificatePath,
        [switch]$TrustRootCa,
        [int]$PollSeconds = 5
    )

    $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    $temporaryToken = [guid]::NewGuid().ToString('N')
    $rootPemPath = [System.IO.Path]::Combine($tempRoot, "atlaso-$temporaryToken-root-ca.pem")
    $rootUrl = "http://$IpAddress/ca/downloads/root-ca.pem"
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $downloaded = $false
    $lastError = ''
    Write-Host "Waiting up to $TimeoutSeconds seconds for the Atlaso root CA at $rootUrl"
    do {
        $remainingSeconds = [Math]::Max(1, [int][Math]::Ceiling(($deadline - (Get-Date)).TotalSeconds))
        $requestTimeoutSeconds = [Math]::Min(10, $remainingSeconds)
        try {
            Invoke-WebRequest `
                -Uri $rootUrl `
                -UseBasicParsing `
                -TimeoutSec $requestTimeoutSeconds `
                -OutFile $rootPemPath
            $downloaded = $true
            break
        }
        catch {
            $lastError = $_.Exception.Message
            try {
                # File.Delete is idempotent for a missing file and safely handles valid dotted/short Windows paths.
                [System.IO.File]::Delete($rootPemPath)
            }
            catch {
                # Best-effort cleanup must never mask the CA readiness error that triggered this retry.
            }
            if ((Get-Date) -lt $deadline) {
                Write-Host "Atlaso root CA is not ready; retrying in $PollSeconds seconds." -ForegroundColor DarkGray
                Start-Sleep -Seconds $PollSeconds
            }
        }
    } while ((Get-Date) -lt $deadline)

    if (-not $downloaded) {
        throw "Timed out after $TimeoutSeconds seconds waiting for the Atlaso root CA at $rootUrl. Last error: $lastError"
    }

    try {
        $downloadedPem = Get-Content -LiteralPath $rootPemPath -Raw
        $downloadedCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem(
            $downloadedPem
        )
        $expectedPem = Get-Content -LiteralPath $ExpectedCertificatePath -Raw
        $expectedCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem(
            $expectedPem
        )
        $downloadedFingerprint = [Convert]::ToHexString(
            [System.Security.Cryptography.SHA256]::HashData($downloadedCertificate.RawData)
        )
        $expectedFingerprint = [Convert]::ToHexString(
            [System.Security.Cryptography.SHA256]::HashData($expectedCertificate.RawData)
        )
        if ($downloadedFingerprint -ne $expectedFingerprint) {
            throw "The VM root CA fingerprint does not match the checked-in Atlaso development root CA. Expected $expectedFingerprint; received $downloadedFingerprint."
        }
        Write-Host "Verified Atlaso development root CA fingerprint: $expectedFingerprint"

        $alreadyTrusted = [bool](Get-ChildItem Cert:\CurrentUser\Root | Where-Object {
                [Convert]::ToHexString(
                    [System.Security.Cryptography.SHA256]::HashData($_.RawData)
                ) -eq $expectedFingerprint
            } | Select-Object -First 1)
        if ($TrustRootCa -and -not $alreadyTrusted) {
            $rootCerPath = [System.IO.Path]::Combine($tempRoot, "atlaso-$temporaryToken-development-root-ca.cer")
            [System.IO.File]::WriteAllBytes(
                $rootCerPath,
                $expectedCertificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
            )
            try {
                certutil.exe -f -user -addstore Root $rootCerPath | Out-Host
                if ($LASTEXITCODE -ne 0) {
                    throw 'Failed to import the Atlaso development root CA into the current-user Trusted Root store.'
                }
                $alreadyTrusted = [bool](Get-ChildItem Cert:\CurrentUser\Root | Where-Object {
                        [Convert]::ToHexString(
                            [System.Security.Cryptography.SHA256]::HashData($_.RawData)
                        ) -eq $expectedFingerprint
                    } | Select-Object -First 1)
                if (-not $alreadyTrusted) {
                    throw 'The Atlaso development root CA import completed without an exact Trusted Root readback.'
                }
            }
            finally {
                [System.IO.File]::Delete($rootCerPath)
            }
        }
        if ($TrustRootCa -and $alreadyTrusted) {
            Write-Host "Atlaso development root CA is trusted for the current user: $($expectedCertificate.Thumbprint)"
        }
        return [pscustomobject]@{
            Fingerprint = $expectedFingerprint
            Trusted     = $alreadyTrusted
        }
    }
    finally {
        [System.IO.File]::Delete($rootPemPath)
        if ($downloadedCertificate) {
            $downloadedCertificate.Dispose()
        }
        if ($expectedCertificate) {
            $expectedCertificate.Dispose()
        }
    }
}

<#
.SYNOPSIS
Print the normal test appliance connection endpoints and authentication state.

.PARAMETER IpAddress
The running appliance management IPv4 address.

.PARAMETER Name
The Workstation VM display name.

.PARAMETER VmxPath
The exact created VMX path.

.PARAMETER RootCaTrusted
Whether this run installed the appliance root CA for the current Windows user.

.PARAMETER SshKeyProvisioned
Whether this run injected development key access and passwordless sudo.

.PARAMETER MacAddress
Verified management NIC MAC address from the exact VMX.

.PARAMETER Hostname
First-boot hostname bound into the readiness evidence.
#>
function Write-ConnectionSummary {
    param(
        [Parameter(Mandatory = $true)][string]$IpAddress,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][bool]$RootCaTrusted,
        [Parameter(Mandatory = $true)][bool]$SshKeyProvisioned,
        [Parameter(Mandatory = $true)][string]$MacAddress,
        [Parameter(Mandatory = $true)][string]$Hostname
    )

    <#
    .SYNOPSIS
    Write one aligned connection-summary row.

    .PARAMETER Label
    The operator-facing row label.

    .PARAMETER Value
    The row value.

    .PARAMETER ValueColor
    The console color used for the value.
    #>
    function Write-SummaryRow {
        param(
            [Parameter(Mandatory = $true)][string]$Label,
            [Parameter(Mandatory = $true)][string]$Value,
            [System.ConsoleColor]$ValueColor = [System.ConsoleColor]::Green
        )
        Write-Host "  $($Label.PadRight(12))" -ForegroundColor DarkGray -NoNewline
        Write-Host $Value -ForegroundColor $ValueColor
    }

    Write-Host ""
    Write-Host "Atlaso VMware appliance connection summary" -ForegroundColor Cyan
    Write-SummaryRow -Label "Name:" -Value $Name -ValueColor White
    Write-SummaryRow -Label "VMX:" -Value $VmxPath -ValueColor Gray
    Write-SummaryRow -Label "MAC:" -Value $MacAddress -ValueColor Gray
    Write-SummaryRow -Label "Hostname:" -Value $Hostname -ValueColor White
    Write-SummaryRow -Label "Console URL:" -Value "https://$IpAddress/"
    Write-SummaryRow -Label "API URL:" -Value "https://$IpAddress/openapi.json"
    Write-SummaryRow -Label "Swagger URL:" -Value "https://$IpAddress/api/docs"
    Write-SummaryRow -Label "Root CA URL:" -Value "http://$IpAddress/ca/downloads/root-ca.pem"
    Write-SummaryRow -Label "SSH:" -Value "ssh admin@$IpAddress"
    if ($SshKeyProvisioned) {
        Write-SummaryRow -Label "SSH auth:" -Value "host Ed25519 key; test-only passwordless sudo" -ValueColor Green
    }
    else {
        Write-SummaryRow -Label "SSH auth:" -Value "password-backed; key provisioning explicitly skipped" -ValueColor Yellow
    }
    if ($RootCaTrusted) {
        Write-SummaryRow -Label "HTTPS trust:" -Value "Atlaso root CA imported for current user" -ValueColor Green
    }
    else {
        Write-SummaryRow -Label "HTTPS trust:" -Value "pass -TrustRootCa to trust this appliance root CA" -ValueColor Yellow
    }
    Write-SummaryRow -Label "Lab DNS:" -Value "see image\vmware-workstation\README.md > Windows DNS for lab FQDNs" -ValueColor Yellow
    Write-Host ""
}

if (-not $WhatIfPreference -and [string]::IsNullOrWhiteSpace($OnePasswordEnvironmentId)) {
    throw 'OnePasswordEnvironmentId is required for normal VMware test VM creation. Copy the opaque ID from the exact Atlaso 1Password Environment and pass it with -OnePasswordEnvironmentId.'
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
$developmentRootCaCertificatePath = Join-Path $repoRoot 'image\vmware-workstation\development-trust\atlaso-development-root-ca.pem'
$developmentRootCaCertificatePem = Get-Content -LiteralPath $developmentRootCaCertificatePath -Raw
$developmentRootCaFingerprint = Get-AtlasoDevelopmentRootCaFingerprint `
    -CertificatePath $developmentRootCaCertificatePath
$resolvedOpPath = ''
$resolvedVmrunPath = ''
if (-not $WhatIfPreference) {
    # Recovery consumes no 1Password material. Run it first so revoked or
    # rotated credentials cannot strand an earlier plaintext-staging failure.
    $resolvedVmrunPath = Resolve-TestVmVmrunPath -Path $VmrunPath
    Invoke-PendingAtlasoDevelopmentCaCleanup `
        -VmrunPath $resolvedVmrunPath `
        -TimeoutSeconds ([Math]::Min($TimeoutSeconds, 30))
}
if ($NoStart) {
    throw '-NoStart is not supported for normal test VMs because first boot must consume and scrub the shared development signing key.'
}
if (-not $WhatIfPreference) {
    $resolvedOpPath = Resolve-OnePasswordCliPath
    Assert-OnePasswordDevelopmentCaBridge `
        -EnvironmentId $OnePasswordEnvironmentId `
        -OpPath $resolvedOpPath `
        -TimeoutSeconds ([Math]::Min($TimeoutSeconds, 30))
    # The secret child validates the checked-in certificate, CA constraints,
    # expiry, signature, and private-key match before any network or VM mutation.
    Invoke-OnePasswordDevelopmentCaChild `
        -EnvironmentId $OnePasswordEnvironmentId `
        -OpPath $resolvedOpPath `
        -Action Validate `
        -CertificatePath $developmentRootCaCertificatePath `
        -TimeoutSeconds $TimeoutSeconds
}

# Key input validation intentionally precedes network preparation, cleanup, disk
# reset, and cloning so an authentication setup error preserves every existing VM.
if ($SkipSshKeyProvisioning -and $PSBoundParameters.ContainsKey('SshPublicKeyPath')) {
    throw 'Pass either -SshPublicKeyPath or -SkipSshKeyProvisioning, not both.'
}
$developmentAdminSshPublicKey = ''
$resolvedSshPublicKeyPath = ''
if (-not $SkipSshKeyProvisioning) {
    $resolvedSshPublicKey = Resolve-AtlasoWorkstationAdminSshPublicKey -Path $SshPublicKeyPath
    $developmentAdminSshPublicKey = $resolvedSshPublicKey.PublicKey
    $resolvedSshPublicKeyPath = $resolvedSshPublicKey.Path
}

if (-not $FirstBootFqdn) {
    $FirstBootFqdn = New-AtlasoWorkstationFqdn -Name $Name
}
$firstBootOvfEnvironment = New-AtlasoWorkstationOvfEnvironment `
    -Fqdn $FirstBootFqdn `
    -AdminPassword $AdminPassword `
    -RootPassword $RootPassword `
    -RootSshEnabled:$RootSshEnabled `
    -NormalTestVm `
    -DevelopmentAdminSshPublicKey $developmentAdminSshPublicKey `
    -DevelopmentRootCaCertificatePem $developmentRootCaCertificatePem

if ($SkipLabNetworkAdapters -and $IncludeLabNetworkAdapters) {
    throw "Pass either -SkipLabNetworkAdapters or -IncludeLabNetworkAdapters, not both."
}
$effectiveSkipLabNetworkAdapters = -not $IncludeLabNetworkAdapters
if ($SkipLabNetworkAdapters) {
    $effectiveSkipLabNetworkAdapters = $true
}

if (-not $ApplianceVmxPath) {
    $ApplianceVmxPath = Find-LatestApplianceVmx -RepoRoot $repoRoot
}
$resolvedSourceVmx = (Resolve-Path -LiteralPath $ApplianceVmxPath).Path
Assert-AtlasoVmwarePayloadProvenance -VmxPath $resolvedSourceVmx | Out-Null

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repoRoot "image\vmware-workstation\test-vms\$Name"
}
$resolvedOutputDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
$targetVmx = Join-Path $resolvedOutputDirectory "$Name.vmx"
$resolvedDepotVmdkPath = if ($DepotVmdkPath) {
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DepotVmdkPath)
}
else {
    Join-Path $resolvedOutputDirectory 'Atlaso-Depot.vmdk'
}
$resolvedBackupVmdkPath = if ($BackupVmdkPath) {
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($BackupVmdkPath)
}
else {
    Join-Path $resolvedOutputDirectory 'Atlaso-Backups.vmdk'
}

if ((Test-Path -LiteralPath $targetVmx) -and -not $Redeploy) {
    throw "VM already exists: $targetVmx. Pass -Redeploy to remove and recreate it, or pass -Name/-OutputDirectory for a new test VM."
}

if (-not $SkipNetworkPrepare) {
    & (Join-Path $PSScriptRoot 'prepare-networks.ps1') `
        -VmrunPath $VmrunPath `
        -ManagementNetwork $ManagementNetwork `
        -SiteANetwork $SiteANetwork `
        -SiteBNetwork $SiteBNetwork `
        -TrunkNetwork $TrunkNetwork `
        -ManagementOnly:$effectiveSkipLabNetworkAdapters
    if (-not $?) {
        throw "VMware Workstation network validation failed. Plain test VM creation uses management only by default; pass -IncludeLabNetworkAdapters only after VMnet2, VMnet3, and VMnet4 exist."
    }
}

if ((Test-Path -LiteralPath $resolvedOutputDirectory) -and $Redeploy) {
    if (-not (Test-Path -LiteralPath $targetVmx -PathType Leaf)) {
        throw "Refusing redeploy cleanup because the expected Atlaso VMX is missing: $targetVmx. Choose the correct -Name/-OutputDirectory or remove the directory manually after reviewing its contents."
    }
    if ($PSCmdlet.ShouldProcess($targetVmx, 'Remove existing Atlaso Workstation test VM')) {
        & (Join-Path $PSScriptRoot 'remove-atlaso-vm.ps1') `
            -VmxPath $targetVmx `
            -VmrunPath $VmrunPath `
            -ExpectedName $Name `
            -Confirm:$false
    }
}

if ($ResetDataDisks) {
    foreach ($diskPath in @($resolvedDepotVmdkPath, $resolvedBackupVmdkPath)) {
        if (-not (Test-Path -LiteralPath $diskPath)) {
            continue
        }
        $resolvedDiskPath = (Resolve-Path -LiteralPath $diskPath).Path
        Assert-AtlasoStrictDescendantPath `
            -ParentPath $resolvedOutputDirectory `
            -ChildPath $resolvedDiskPath `
            -FailureMessage 'Refusing to reset VMware data disk outside the VM output directory'
        if ($PSCmdlet.ShouldProcess($resolvedDiskPath, 'Remove existing Atlaso VMware data disk')) {
            Remove-Item -LiteralPath $resolvedDiskPath -Force
            Write-Host "Removed existing data disk: $resolvedDiskPath"
        }
    }
}

$rollbackDataDiskStates = @()
if (Test-Path -LiteralPath $resolvedOutputDirectory -PathType Container) {
    # Reject the same descriptor, a hard-linked alias, or any shared extent
    # before the marker can persist a rollback plan that moves a file twice.
    $rollbackDataDiskStates = @(Get-AtlasoRollbackDataDiskStates `
            -DiskPaths @($resolvedDepotVmdkPath, $resolvedBackupVmdkPath) `
            -OutputDirectory $resolvedOutputDirectory)
}

$createdThisInvocation = $false
$developmentCaCleanupMarkerPath = ''
if ($PSCmdlet.ShouldProcess($targetVmx, "Create Atlaso Workstation test VM from $resolvedSourceVmx")) {
    & (Join-Path $PSScriptRoot 'create-atlaso-vm.ps1') `
        -Name $Name `
        -ApplianceVmxPath $resolvedSourceVmx `
        -OutputDirectory $resolvedOutputDirectory `
        -VmrunPath $VmrunPath `
        -VdiskManagerPath $VdiskManagerPath `
        -DepotVmdkPath $resolvedDepotVmdkPath `
        -BackupVmdkPath $resolvedBackupVmdkPath `
        -DepotDiskSize $DepotDiskSize `
        -BackupDiskSize $BackupDiskSize `
        -ManagementNetwork $ManagementNetwork `
        -SiteANetwork $SiteANetwork `
        -SiteBNetwork $SiteBNetwork `
        -TrunkNetwork $TrunkNetwork `
        -SkipLabNetworkAdapters:$effectiveSkipLabNetworkAdapters
    if (-not $?) {
        throw "Atlaso VMware Workstation VM creation failed."
    }
    Set-AtlasoWorkstationOvfEnvironment -VmxPath $targetVmx -OvfEnvironment $firstBootOvfEnvironment
    $createdThisInvocation = $true
}

if (-not $createdThisInvocation -and -not $WhatIfPreference) {
    Write-Host 'Normal test VM creation was not approved; no development signing key was staged.' -ForegroundColor Yellow
    return
}

if (-not $WhatIfPreference) {
    try {
        # The durable, non-secret marker is committed before the signer is
        # staged. Any interruption thereafter blocks subsequent wrappers until
        # the exact failed VM is stopped and its VMX signer assignment scrubbed.
        $developmentCaCleanupMarkerPath = New-AtlasoDevelopmentCaCleanupMarker `
            -VmxPath $targetVmx `
            -Name $Name `
            -OutputDirectory $resolvedOutputDirectory `
            -DataDiskStates $rollbackDataDiskStates
        try {
            Invoke-OnePasswordDevelopmentCaChild `
                -EnvironmentId $OnePasswordEnvironmentId `
                -OpPath $resolvedOpPath `
                -Action Stage `
                -CertificatePath $developmentRootCaCertificatePath `
                -VmxPath $targetVmx `
                -TimeoutSeconds $TimeoutSeconds
        }
        catch {
            $stageFailure = $_
            if ($stageFailure.Exception.Data['AtlasoProcessTreeTerminationUnproven'] -ne $true) {
                Set-AtlasoDevelopmentCaCleanupMarkerPhase `
                    -MarkerPath $developmentCaCleanupMarkerPath `
                    -ExpectedPhase secret-child-active `
                    -Phase staged
            }
            throw $stageFailure
        }
        # Only a returned child proves that it can no longer rewrite the VMX.
        Set-AtlasoDevelopmentCaCleanupMarkerPhase `
            -MarkerPath $developmentCaCleanupMarkerPath `
            -ExpectedPhase secret-child-active `
            -Phase staged
        $powerShellPath = (Get-Process -Id $PID).Path
        # Persist the boot-bound phase before starting VMware. If bounded
        # termination cannot be proven, rollback must not race a surviving
        # child that can still start the signer-bearing VM.
        Set-AtlasoDevelopmentCaCleanupMarkerPhase `
            -MarkerPath $developmentCaCleanupMarkerPath `
            -ExpectedPhase staged `
            -Phase vm-start-child-active
        try {
            Invoke-AtlasoBoundedProcess `
                -FilePath $powerShellPath `
                -ArgumentList @(
                    '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
                    (Join-Path $PSScriptRoot 'start-atlaso-vm.ps1'),
                    '-VmxPath', $targetVmx,
                    '-VmrunPath', $resolvedVmrunPath,
                    '-Mode', 'gui'
                ) `
                -TimeoutSeconds $TimeoutSeconds `
                -Action 'Start the normal test VM after development-signer staging' | Out-Null
        }
        catch {
            $startFailure = $_
            if ($startFailure.Exception.Data['AtlasoProcessTreeTerminationUnproven'] -ne $true) {
                Set-AtlasoDevelopmentCaCleanupMarkerPhase `
                    -MarkerPath $developmentCaCleanupMarkerPath `
                    -ExpectedPhase vm-start-child-active `
                    -Phase staged
            }
            throw $startFailure
        }
        Set-AtlasoDevelopmentCaCleanupMarkerPhase `
            -MarkerPath $developmentCaCleanupMarkerPath `
            -ExpectedPhase vm-start-child-active `
            -Phase staged
        Wait-AtlasoWorkstationDevelopmentRootCaPrivateKeyScrub `
            -VmxPath $targetVmx `
            -VmrunPath $resolvedVmrunPath `
            -TimeoutSeconds $TimeoutSeconds
        Wait-AtlasoWorkstationDevelopmentRootCaImportProof `
            -VmxPath $targetVmx `
            -VmrunPath $resolvedVmrunPath `
            -ExpectedFingerprint $developmentRootCaFingerprint `
            -TimeoutSeconds $TimeoutSeconds
        Remove-AtlasoDevelopmentCaCleanupMarker `
            -MarkerPath $developmentCaCleanupMarkerPath
        $developmentCaCleanupMarkerPath = ''
    }
    catch {
        $failure = $_
        if ($developmentCaCleanupMarkerPath) {
            try {
                $cleanupMarker = Read-AtlasoDevelopmentCaCleanupMarker `
                    -MarkerPath $developmentCaCleanupMarkerPath `
                    -MarkerRoot (Get-AtlasoDevelopmentCaCleanupMarkerRoot)
            }
            catch {
                throw "$($failure.Exception.Message) The secret-child cleanup marker could not be verified, so no VM or VMX rollback was attempted. Marker error: $($_.Exception.Message)"
            }
            if ($cleanupMarker.Phase -in @('secret-child-active', 'vm-start-child-active')) {
                throw "$($failure.Exception.Message) The durable cleanup marker remains at $developmentCaCleanupMarkerPath; no VM or VMX rollback was attempted. Restart Windows, then rerun the wrapper so the new host boot can prove the child process tree is gone before cleanup."
            }
        }
        if ($createdThisInvocation -and (Test-Path -LiteralPath $targetVmx -PathType Leaf)) {
            $rollbackErrors = [System.Collections.Generic.List[string]]::new()
            $quarantineDirectory = ''
            $runtimeSignerScrubbed = $false
            $runtimeSignerScrubError = ''
            $stopped = $false
            $vmxSignerScrubError = ''
            try {
                $rollbackVmrunPath = Resolve-TestVmVmrunPath -Path $VmrunPath
                try {
                    # Runtime scrub precedes stop discovery so a vmrun list/stop
                    # failure cannot strand the shared signer in a running VM.
                    Clear-AtlasoWorkstationDevelopmentRootCaRuntimePrivateKey `
                        -VmxPath $targetVmx `
                        -VmrunPath $rollbackVmrunPath `
                        -TimeoutSeconds ([Math]::Min($TimeoutSeconds, 30))
                    $runtimeSignerScrubbed = $true
                }
                catch {
                    $runtimeSignerScrubError = $_.Exception.Message
                }
                try {
                    Stop-AtlasoTestVmForRollback `
                        -VmxPath $targetVmx `
                        -VmrunPath $rollbackVmrunPath `
                        -TimeoutSeconds ([Math]::Min($TimeoutSeconds, 30))
                    $stopped = $true
                }
                catch {
                    $rollbackErrors.Add($_.Exception.Message)
                }
                if (-not $stopped) {
                    if (-not $runtimeSignerScrubbed) {
                        $rollbackErrors.Add($runtimeSignerScrubError)
                    }
                    throw 'The failed normal test VM could not be proven stopped; destructive rollback was skipped.'
                }
                try {
                    # Powered-off VMX scrub is defense in depth after runtime
                    # readback and remains necessary when the VM never started.
                    Clear-AtlasoWorkstationDevelopmentRootCaPrivateKey -VmxPath $targetVmx
                }
                catch {
                    $vmxSignerScrubError = $_.Exception.Message
                }
                if ($vmxSignerScrubError) {
                    $rollbackErrors.Add($vmxSignerScrubError)
                    throw 'The powered-off development signer could not be proven scrubbed; destructive rollback was deferred.'
                }
                if ($developmentCaCleanupMarkerPath) {
                    Set-AtlasoDevelopmentCaCleanupMarkerPhase `
                        -MarkerPath $developmentCaCleanupMarkerPath `
                        -ExpectedPhase staged `
                        -Phase stopped-vmx-scrubbed
                }
                if ($rollbackDataDiskStates.Count -gt 0) {
                    $quarantineDirectory = Join-Path `
                        (Split-Path -Parent $resolvedOutputDirectory) `
                        ".atlaso-development-ca-cleanup-$([System.IO.Path]::GetFileNameWithoutExtension($developmentCaCleanupMarkerPath))"
                    Move-AtlasoRollbackDataDisksToQuarantine `
                        -DataDiskStates $rollbackDataDiskStates `
                        -QuarantineDirectory $quarantineDirectory
                }
                if ($developmentCaCleanupMarkerPath) {
                    Set-AtlasoDevelopmentCaCleanupMarkerPhase `
                        -MarkerPath $developmentCaCleanupMarkerPath `
                        -ExpectedPhase stopped-vmx-scrubbed `
                        -Phase removal-child-active
                }
                try {
                    Invoke-AtlasoBoundedProcess `
                        -FilePath (Get-Process -Id $PID).Path `
                        -ArgumentList @(
                            '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
                            (Join-Path $PSScriptRoot 'remove-atlaso-vm.ps1'),
                            '-VmxPath', $targetVmx,
                            '-VmrunPath', $rollbackVmrunPath,
                            '-ExpectedName', $Name,
                            '-Confirm:$false'
                        ) `
                        -TimeoutSeconds $TimeoutSeconds `
                        -Action 'Remove the exact failed normal test VM during rollback' | Out-Null
                }
                catch {
                    $removalFailure = $_
                    if (
                        $developmentCaCleanupMarkerPath -and
                        $removalFailure.Exception.Data['AtlasoProcessTreeTerminationUnproven'] -ne $true
                    ) {
                        Set-AtlasoDevelopmentCaCleanupMarkerPhase `
                            -MarkerPath $developmentCaCleanupMarkerPath `
                            -ExpectedPhase removal-child-active `
                            -Phase stopped-vmx-scrubbed
                    }
                    throw $removalFailure
                }
                if ($developmentCaCleanupMarkerPath) {
                    Set-AtlasoDevelopmentCaCleanupMarkerPhase `
                        -MarkerPath $developmentCaCleanupMarkerPath `
                        -ExpectedPhase removal-child-active `
                        -Phase stopped-vmx-scrubbed
                }
            }
            catch {
                $rollbackErrors.Add($_.Exception.Message)
            }
            finally {
                $removalTreeUnproven = (
                    $developmentCaCleanupMarkerPath -and
                    (Test-Path -LiteralPath $developmentCaCleanupMarkerPath -PathType Leaf) -and
                    (Read-AtlasoDevelopmentCaCleanupMarker `
                        -MarkerPath $developmentCaCleanupMarkerPath `
                        -MarkerRoot (Get-AtlasoDevelopmentCaCleanupMarkerRoot)).Phase -ceq 'removal-child-active'
                )
                if ($quarantineDirectory -and -not $removalTreeUnproven) {
                    try {
                        Restore-AtlasoRollbackDataDisksFromQuarantine `
                            -DataDiskStates $rollbackDataDiskStates `
                            -QuarantineDirectory $quarantineDirectory
                    }
                    catch {
                        $rollbackErrors.Add($_.Exception.Message)
                    }
                }
            }
            if ($rollbackErrors.Count -eq 0 -and $developmentCaCleanupMarkerPath) {
                try {
                    Remove-AtlasoDevelopmentCaCleanupMarker `
                        -MarkerPath $developmentCaCleanupMarkerPath
                    $developmentCaCleanupMarkerPath = ''
                }
                catch {
                    $rollbackErrors.Add($_.Exception.Message)
                }
            }
            if ($rollbackErrors.Count -gt 0) {
                $quarantineHint = if ($quarantineDirectory) {
                    " Preserved data may remain at $quarantineDirectory."
                }
                else {
                    ''
                }
                throw "$($failure.Exception.Message) Automatic rollback also failed; do not use the VM and retry cleanup for only $targetVmx after verifying ownership.$quarantineHint Rollback error: $($rollbackErrors -join ' | ')"
            }
        }
        throw $failure
    }
}

$readinessIdentity = $null
if (-not $WhatIfPreference) {
    # Prove exact VMX, NIC, hostname, and host-facing address ownership before
    # printing ready state or any connection endpoint.
    $readinessIdentity = & (Join-Path $PSScriptRoot 'get-atlaso-vm-ip.ps1') `
        -VmxPath $targetVmx `
        -ExpectedHostname $FirstBootFqdn `
        -VmrunPath $resolvedVmrunPath `
        -TimeoutSeconds $TimeoutSeconds `
        -PassThruIdentity
    if (-not $? -or $null -eq $readinessIdentity) {
        throw 'Normal test VM unique-address readiness did not return verified identity evidence.'
    }
    Write-Host "Atlaso Workstation test VM ready: $Name"
}
else {
    Write-Host "Atlaso Workstation test VM prepared without readiness proof: $Name"
}
Write-Host "Appliance VMX: $targetVmx"
if ($resolvedSshPublicKeyPath) {
    Write-Host "Development SSH access: admin key from $resolvedSshPublicKeyPath with test-only passwordless sudo"
}
else {
    Write-Host 'Development SSH access: key provisioning skipped; password-backed sudo remains required.'
}

if (-not $SkipSshKeyProvisioning -and -not $WhatIfPreference) {
    $sshHostKey = Get-AtlasoWorkstationSshHostKey `
        -VmxPath $targetVmx `
        -VmrunPath $VmrunPath `
        -TimeoutSeconds $TimeoutSeconds
    Write-Host "SSH host public key: $($sshHostKey.PublicKey)"
    Write-Host "SSH host key fingerprint: $($sshHostKey.Fingerprint)"
}

if (($WaitForIp -or $TrustRootCa) -and $readinessIdentity) {
    $ip = $readinessIdentity.IPAddress
    if ($WaitForIp) {
        Write-Host "Management IP: $ip"
    }
    $rootCaStatus = Install-ApplianceRootCa `
        -IpAddress $ip `
        -TimeoutSeconds $TimeoutSeconds `
        -ExpectedCertificatePath $developmentRootCaCertificatePath `
        -TrustRootCa:$TrustRootCa
    Write-ConnectionSummary `
        -IpAddress $ip `
        -Name $Name `
        -VmxPath $targetVmx `
        -RootCaTrusted ([bool]$rootCaStatus.Trusted) `
        -SshKeyProvisioned (-not [bool]$SkipSshKeyProvisioning) `
        -MacAddress $readinessIdentity.MacAddress `
        -Hostname $readinessIdentity.Hostname
}
elseif ($readinessIdentity) {
    Write-Host 'Management wait and development-root verification were explicitly disabled with -WaitForIp:$false.' -ForegroundColor DarkGray
}
