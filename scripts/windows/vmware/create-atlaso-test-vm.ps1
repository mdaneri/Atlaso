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
ATLASO_DEVELOPMENT_ROOT_CA_PRIVATE_KEY, DEFAULT_ADMIN_PASSWORD, and
DEFAULT_ROOT_PASSWORD variables. When omitted, the wrapper reads the single-line
.atlaso-local\onepassword-environment-id file from the checkout.

.PARAMETER OnePasswordAccount
Optional 1Password account name or ID approved for desktop SDK authorization
when either first-boot credential is omitted. The single CLI account is used
when this selector is omitted.

.PARAMETER OnePasswordPython
Optional CPython 3.10 through 3.13 executable used by the supported Windows
1Password SDK bridge. The highest compatible Windows-registered runtime is used
when this selector is omitted.

.PARAMETER EnvironmentIdFile
Optional path to a single-line local Environment ID file. The checkout-local,
Git-ignored .atlaso-local\onepassword-environment-id file is the default. The
legacy OnePasswordEnvironmentIdFile name remains available as an alias.

.PARAMETER FirstBootFqdn
Optional first-boot appliance FQDN override.

.PARAMETER AdminPassword
Initial Atlaso and Photon bootstrap administrator password. When omitted, the
bounded SDK child retrieves DEFAULT_ADMIN_PASSWORD from the exact Environment.

.PARAMETER RootPassword
Initial Photon root console password. When omitted, the bounded SDK child
retrieves DEFAULT_ROOT_PASSWORD from the exact Environment.

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
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingPlainTextForPassword',
    'OnePasswordEnvironmentId',
    Justification = 'Opaque Environment identifier; bounded children retrieve concealed values.'
)]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingPlainTextForPassword',
    'OnePasswordAccount',
    Justification = 'Desktop authorization account identifier, not an account password.'
)]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingPlainTextForPassword',
    'OnePasswordPython',
    Justification = 'Path to the approved Python interpreter, not a password.'
)]
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
    [switch]$WaitForIp,
    [switch]$TrustRootCa,
    [string]$OnePasswordEnvironmentId = '',
    [string]$OnePasswordAccount = '',
    [string]$OnePasswordPython = '',
    [Alias('OnePasswordEnvironmentIdFile')]
    [string]$EnvironmentIdFile = '',
    [string]$FirstBootFqdn = '',
    [SecureString]$AdminPassword,
    [SecureString]$RootPassword,
    [switch]$RootSshEnabled,
    [string]$SshPublicKeyPath = '',
    [switch]$SkipSshKeyProvisioning,
    [ValidateRange(1, 3600)][int]$TimeoutSeconds = 300
)

$ErrorActionPreference = 'Stop'

# Preserve the established default-enabled and bare-switch interface without a
# default-true switch declaration, which PowerShell cannot distinguish safely.
$waitForIpEnabled = if ($PSBoundParameters.ContainsKey('WaitForIp')) {
    [bool]$WaitForIp
} else {
    $true
}

. (Join-Path $PSScriptRoot 'Atlaso.WorkstationFirstBoot.ps1')
Import-Module (Join-Path $PSScriptRoot 'Atlaso.OnePasswordCredentials.psm1') -Force
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

.PARAMETER CommandResolver
Command-discovery callback. Tests may replace discovery without overriding the
built-in Get-Command cmdlet.
#>
function Resolve-OnePasswordCliPath {
    param(
        [string[]]$CandidatePaths = @(
            (Join-Path ([Environment]::GetFolderPath('ProgramFiles')) '1Password CLI\op.exe'),
            (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Microsoft\WinGet\Links\op.exe')
        ),
        [string]$PackageRoot = (
            Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Microsoft\WinGet\Packages'
        ),
        [scriptblock]$CommandResolver = {
            param($Name)
            Get-Command $Name -ErrorAction SilentlyContinue
        }
    )

    return Resolve-AtlasoOnePasswordCliPath `
        -CandidatePaths $CandidatePaths `
        -PackageRoot $PackageRoot `
        -CommandResolver $CommandResolver
}

<#
.SYNOPSIS
Resolve the exact Atlaso 1Password Environment ID without printing it.

.PARAMETER EnvironmentId
Optional explicit opaque Environment ID supplied by the operator.

.PARAMETER EnvironmentIdFile
Optional path to the single-line local Environment ID file.

.PARAMETER RepositoryRoot
Atlaso checkout root containing the default .atlaso-local configuration.
#>
function Resolve-OnePasswordDevelopmentCaEnvironmentId {
    param(
        [string]$EnvironmentId = '',
        [string]$EnvironmentIdFile = '',
        [Parameter(Mandatory = $true)][string]$RepositoryRoot
    )

    return Resolve-AtlasoOnePasswordEnvironmentId `
        -EnvironmentId $EnvironmentId `
        -EnvironmentIdFile $EnvironmentIdFile `
        -RepositoryRoot $RepositoryRoot `
        -ConsumerDescription 'normal VMware test VM creation'
}

<#
.SYNOPSIS
Validate the opaque Environment ID and require an Environments-enabled beta CLI.

.PARAMETER EnvironmentId
Opaque ID copied from the exact Atlaso 1Password Environment.

.PARAMETER OpPath
Resolved 1Password CLI executable path.

.PARAMETER ExpectedEnvironmentIdSha256
Pinned SHA-256 identity of the exact Atlaso Environment. The override exists
only so focused tests can exercise the guard without publishing the real ID.

.PARAMETER TimeoutSeconds
Positive deadline for the CLI capability probe.
#>
function Assert-OnePasswordDevelopmentCaBridge {
    param(
        [Parameter(Mandatory = $true)][string]$EnvironmentId,
        [Parameter(Mandatory = $true)][string]$OpPath,
        [string]$ExpectedEnvironmentIdSha256 = 'FE14B62FB2D23460202299784CB1080B9E0FCF202ED5D75B4843202CD68BDF06',
        [ValidateRange(1, 3600)][int]$TimeoutSeconds = 30
    )

    # Verify the shared non-secret repository pin before invoking op so a
    # different Environment cannot become trusted by copying the signer name.
    Assert-AtlasoOnePasswordEnvironmentId `
        -EnvironmentId $EnvironmentId `
        -ExpectedEnvironmentIdSha256 $ExpectedEnvironmentIdSha256
    if ($env:ATLASO_DEVELOPMENT_ROOT_CA_PRIVATE_KEY) {
        throw 'ATLASO_DEVELOPMENT_ROOT_CA_PRIVATE_KEY must come only from the exact 1Password Environment bridge.'
    }
    $runHelp = Invoke-AtlasoBoundedProcess `
        -FilePath $OpPath `
        -ArgumentList @('run', '--help') `
        -TimeoutSeconds $TimeoutSeconds `
        -Action 'The 1Password beta Environment capability probe'
    if ([string]::IsNullOrWhiteSpace($runHelp) -or $runHelp -notlike '*--environment*') {
        throw 'The selected 1Password CLI does not support op run --environment. Install the Environments-enabled beta CLI and retry.'
    }
}

<#
.SYNOPSIS
Run the bounded development-CA secret child under 1Password.

.PARAMETER EnvironmentId
Opaque ID of the exact Atlaso 1Password Environment.

.PARAMETER OpPath
Resolved Environments-enabled beta 1Password CLI executable path.

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
Validate the non-secret 1Password account selector used by desktop authorization.

.PARAMETER Account
1Password account name or ID.
#>
function Assert-OnePasswordTestVmAccount {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Account)

    Assert-AtlasoOnePasswordAccount -Account $Account
}

<#
.SYNOPSIS
Resolve the explicit or unique installed 1Password account selector.

.PARAMETER Account
Optional explicit 1Password account name or ID.

.PARAMETER TimeoutSeconds
Positive deadline for bounded account discovery.

.PARAMETER CliPath
Optional exact CLI path already verified by the development-CA preflight.
#>
function Resolve-OnePasswordTestVmAccount {
    param(
        [AllowEmptyString()][string]$Account = '',
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds,
        [string]$CliPath = ''
    )

    return Resolve-AtlasoOnePasswordAccount `
        -Account $Account `
        -TimeoutSeconds $TimeoutSeconds `
        -CliPath $CliPath
}

<#
.SYNOPSIS
Resolve a Python runtime supported by the 1Password SDK Windows wheel.

.PARAMETER PythonCommand
Explicit CPython 3.10 through 3.13 executable or command.

.PARAMETER TimeoutSeconds
Positive deadline for the version probe.
#>
function Resolve-OnePasswordTestVmPython {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$PythonCommand,
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds
    )

    return Resolve-AtlasoOnePasswordPython `
        -PythonCommand $PythonCommand `
        -TimeoutSeconds $TimeoutSeconds `
        -ConsumerDescription 'Omitted VMware test-VM credentials'
}

<#
.SYNOPSIS
Prepare the isolated hash-locked 1Password SDK runtime.

.PARAMETER PythonCommand
Approved CPython 3.10 through 3.13 executable.

.PARAMETER RepositoryRoot
Atlaso checkout containing requirements-onepassword-deploy.lock.

.PARAMETER BridgeRoot
Private task-specific temporary root for wheels and installed dependencies.

.PARAMETER TimeoutSeconds
Positive deadline for each dependency operation.
#>
function Initialize-OnePasswordTestVmSdkRuntime {
    param(
        [Parameter(Mandatory = $true)][string]$PythonCommand,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$BridgeRoot,
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds
    )

    return Initialize-AtlasoOnePasswordSdkRuntime `
        -PythonCommand $PythonCommand `
        -RepositoryRoot $RepositoryRoot `
        -BridgeRoot $BridgeRoot `
        -TimeoutSeconds $TimeoutSeconds
}

<#
.SYNOPSIS
Translate a safe credential-bridge status code into an actionable error.

.PARAMETER Code
Machine-readable status emitted by the bounded credential helper.
#>
function Get-AtlasoTestVmCredentialBridgeError {
    param([Parameter(Mandatory = $true)][string]$Code)

    $message = switch ($Code) {
        'sdk_configuration_missing' {
            'Omitted VMware test-VM credentials require OnePasswordAccount and OnePasswordPython for the supported 1Password SDK bridge.'
        }
        'sdk_access_failed' {
            '1Password desktop authorization or exact Atlaso Environment access failed; no VMware network, VM, or disk mutation was attempted.'
        }
        'admin_variable_invalid' {
            'The exact Atlaso 1Password Environment must contain exactly one concealed DEFAULT_ADMIN_PASSWORD variable.'
        }
        'root_variable_invalid' {
            'The exact Atlaso 1Password Environment must contain exactly one concealed DEFAULT_ROOT_PASSWORD variable.'
        }
        'admin_password_invalid' {
            'DEFAULT_ADMIN_PASSWORD or the explicit AdminPassword does not satisfy the Atlaso first-boot credential policy.'
        }
        'root_password_invalid' {
            'DEFAULT_ROOT_PASSWORD or the explicit RootPassword does not satisfy the Atlaso first-boot credential policy.'
        }
        'sdk_runtime_invalid' {
            'The isolated 1Password SDK runtime could not be loaded; no VMware mutation was attempted.'
        }
        'sdk_output_protection_failed' {
            'The bounded 1Password child could not protect its credential result with current-user DPAPI.'
        }
        'credential_ciphertext_invalid' {
            'The current-user DPAPI credential handoff could not be decrypted in the bounded serializer child.'
        }
        'ovf_input_invalid' {
            'The bounded credential serializer rejected a non-secret first-boot input.'
        }
        'stage_input_invalid' {
            'The bounded credential stage did not receive the exact new VMX and protected OVF bundle.'
        }
        'stage_failed' {
            'The bounded credential stage could not update the exact new VMX.'
        }
        default {
            "The bounded VMware test-VM credential bridge failed safely ($Code)."
        }
    }
    return $message
}

<#
.SYNOPSIS
Remove one exact task-created credential bridge root.

.PARAMETER BridgeRoot
Exact private temporary root returned by New-AtlasoTestVmCredentialBridgeState.
#>
function Remove-AtlasoTestVmCredentialBridgeState {
    param([Parameter(Mandatory = $true)][string]$BridgeRoot)

    if (-not (Test-Path -LiteralPath $BridgeRoot)) {
        return
    }
    $resolvedBridgeRoot = [System.IO.Path]::GetFullPath($BridgeRoot).TrimEnd('\')
    $resolvedTempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\')
    $bridgeName = [System.IO.Path]::GetFileName($resolvedBridgeRoot)
    if (
        -not $resolvedBridgeRoot.StartsWith(
            $resolvedTempRoot + '\',
            [System.StringComparison]::OrdinalIgnoreCase
        ) -or
        -not $bridgeName.StartsWith('atlaso-test-vm-credentials-', [System.StringComparison]::Ordinal)
    ) {
        throw "Refusing to remove an unrecognized credential bridge root: $resolvedBridgeRoot"
    }
    $bridgeItem = Get-Item -LiteralPath $resolvedBridgeRoot -Force
    if (($bridgeItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to remove a reparse-point credential bridge root: $resolvedBridgeRoot"
    }
    foreach ($sensitiveName in @(
            'request.json',
            'status.json',
            'stage-status.json',
            'onepassword-defaults.json',
            'first-boot-ovf.dpapi',
            'atlaso-test-vm-onepassword.py'
        )) {
        $sensitivePath = Join-Path $resolvedBridgeRoot $sensitiveName
        if (Test-Path -LiteralPath $sensitivePath -PathType Leaf) {
            [System.IO.File]::Delete($sensitivePath)
        }
    }
    [System.IO.Directory]::Delete($resolvedBridgeRoot, $true)
    if (Test-Path -LiteralPath $resolvedBridgeRoot) {
        throw "Credential bridge cleanup did not remove the exact task-created root: $resolvedBridgeRoot"
    }
}

<#
.SYNOPSIS
Prepare a DPAPI-protected first-boot OVF bundle before VMware mutation.

.PARAMETER RepositoryRoot
Atlaso checkout root.

.PARAMETER EnvironmentId
Opaque ID of the already pinned and verified Atlaso Environment.

.PARAMETER OnePasswordAccount
Account name or ID used for desktop SDK authorization when a default is needed.

.PARAMETER OnePasswordPython
CPython 3.10 through 3.13 executable used when a default is needed.

.PARAMETER OnePasswordCliPath
Exact CLI path already verified by the development-CA preflight.

.PARAMETER AdminPassword
Optional explicit administrator SecureString override.

.PARAMETER RootPassword
Optional explicit root SecureString override.

.PARAMETER Fqdn
Validated first-boot appliance FQDN.

.PARAMETER RootSshEnabled
Whether first boot enables password-backed root SSH.

.PARAMETER DevelopmentAdminSshPublicKey
Optional validated development administrator public key.

.PARAMETER DevelopmentRootCaCertificatePem
Checked-in public development root certificate.

.PARAMETER TimeoutSeconds
Positive deadline for dependency and credential children.
#>
function New-AtlasoTestVmCredentialBridgeState {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingPlainTextForPassword',
        'OnePasswordCliPath',
        Justification = 'Path to the approved 1Password CLI executable, not a password.'
    )]
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$EnvironmentId,
        [string]$OnePasswordAccount = '',
        [string]$OnePasswordPython = '',
        [string]$OnePasswordCliPath = '',
        [SecureString]$AdminPassword,
        [SecureString]$RootPassword,
        [Parameter(Mandatory = $true)][string]$Fqdn,
        [Parameter(Mandatory = $true)][bool]$RootSshEnabled,
        [AllowEmptyString()][string]$DevelopmentAdminSshPublicKey = '',
        [Parameter(Mandatory = $true)][string]$DevelopmentRootCaCertificatePem,
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds
    )

    if ($env:DEFAULT_ADMIN_PASSWORD -or $env:DEFAULT_ROOT_PASSWORD) {
        throw 'DEFAULT_ADMIN_PASSWORD and DEFAULT_ROOT_PASSWORD must not be supplied by the caller; use the exact Atlaso 1Password Environment bridge.'
    }
    $bridgeRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
        "atlaso-test-vm-credentials-$([guid]::NewGuid().ToString('N'))"
    )
    [void][System.IO.Directory]::CreateDirectory($bridgeRoot)
    try {
        $requestPath = Join-Path $bridgeRoot 'request.json'
        $statusPath = Join-Path $bridgeRoot 'status.json'
        $ovfBundlePath = Join-Path $bridgeRoot 'first-boot-ovf.dpapi'
        $needsDefaults = $null -eq $AdminPassword -or $null -eq $RootPassword
        $request = [ordered]@{
            AdminPasswordCiphertext       = if ($null -eq $AdminPassword) {
                ''
            }
            else {
                ConvertFrom-SecureString -SecureString $AdminPassword
            }
            RootPasswordCiphertext        = if ($null -eq $RootPassword) {
                ''
            }
            else {
                ConvertFrom-SecureString -SecureString $RootPassword
            }
            Fqdn                          = $Fqdn
            RootSshEnabled                = $RootSshEnabled
            DevelopmentAdminSshPublicKey  = $DevelopmentAdminSshPublicKey
            DevelopmentRootCaCertificatePem = $DevelopmentRootCaCertificatePem
        }
        [System.IO.File]::WriteAllText(
            $requestPath,
            ($request | ConvertTo-Json -Compress),
            [System.Text.UTF8Encoding]::new($false)
        )

        $resolvedPython = ''
        $resolvedAccount = ''
        $dependencyPath = ''
        if ($needsDefaults) {
            $resolvedAccount = Resolve-OnePasswordTestVmAccount `
                -Account $OnePasswordAccount `
                -TimeoutSeconds $TimeoutSeconds `
                -CliPath $OnePasswordCliPath
            $resolvedPython = Resolve-OnePasswordTestVmPython `
                -PythonCommand $OnePasswordPython `
                -TimeoutSeconds $TimeoutSeconds
            $dependencyPath = Initialize-OnePasswordTestVmSdkRuntime `
                -PythonCommand $resolvedPython `
                -RepositoryRoot $RepositoryRoot `
                -BridgeRoot $bridgeRoot `
                -TimeoutSeconds $TimeoutSeconds
        }

        $helperPath = Join-Path $PSScriptRoot 'Invoke-AtlasoTestVmCredentials.ps1'
        $arguments = @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-File', $helperPath,
            '-Action', 'Prepare',
            '-RequestPath', $requestPath,
            '-StatusPath', $statusPath,
            '-OvfBundlePath', $ovfBundlePath,
            '-TimeoutSeconds', "$TimeoutSeconds"
        )
        if ($needsDefaults) {
            $arguments += @(
                '-PythonCommand', $resolvedPython,
                '-DependencyPath', $dependencyPath,
                '-OnePasswordAccount', $resolvedAccount,
                '-EnvironmentId', $EnvironmentId
            )
        }
        Invoke-AtlasoBoundedProcess `
            -FilePath (Get-Process -Id $PID).Path `
            -ArgumentList $arguments `
            -TimeoutSeconds $TimeoutSeconds `
            -Action 'The bounded VMware test-VM credential preparation child' | Out-Null
        if (-not (Test-Path -LiteralPath $statusPath -PathType Leaf)) {
            throw 'The bounded VMware test-VM credential child returned no safe status.'
        }
        $status = [System.IO.File]::ReadAllText($statusPath) | ConvertFrom-Json
        if (-not [bool]$status.Success) {
            throw (Get-AtlasoTestVmCredentialBridgeError -Code ([string]$status.Code))
        }
        if (-not (Test-Path -LiteralPath $ovfBundlePath -PathType Leaf)) {
            throw 'The bounded VMware test-VM credential child returned no protected OVF bundle.'
        }
        return [pscustomobject]@{
            Root          = $bridgeRoot
            OvfBundlePath = $ovfBundlePath
        }
    }
    catch {
        $failure = $_
        try {
            Remove-AtlasoTestVmCredentialBridgeState -BridgeRoot $bridgeRoot
        }
        catch {
            throw "$($failure.Exception.Message) Credential bridge cleanup also failed: $($_.Exception.Message)"
        }
        throw $failure
    }
}

<#
.SYNOPSIS
Stage a prepared DPAPI-protected OVF bundle into the exact new VMX.

.PARAMETER BridgeState
Protected credential bridge state returned by the preparation function.

.PARAMETER VmxPath
Exact newly created VMX path.

.PARAMETER TimeoutSeconds
Positive deadline for the staging child.
#>
function Invoke-AtlasoTestVmCredentialStage {
    param(
        [Parameter(Mandatory = $true)][psobject]$BridgeState,
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds
    )

    $statusPath = Join-Path $BridgeState.Root 'stage-status.json'
    Invoke-AtlasoBoundedProcess `
        -FilePath (Get-Process -Id $PID).Path `
        -ArgumentList @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
            (Join-Path $PSScriptRoot 'Invoke-AtlasoTestVmCredentials.ps1'),
            '-Action', 'Stage',
            '-StatusPath', $statusPath,
            '-OvfBundlePath', $BridgeState.OvfBundlePath,
            '-VmxPath', $VmxPath,
            '-TimeoutSeconds', "$TimeoutSeconds"
        ) `
        -TimeoutSeconds $TimeoutSeconds `
        -Action 'The bounded VMware test-VM credential staging child' | Out-Null
    if (-not (Test-Path -LiteralPath $statusPath -PathType Leaf)) {
        throw 'The bounded VMware test-VM credential stage returned no safe status.'
    }
    $status = [System.IO.File]::ReadAllText($statusPath) | ConvertFrom-Json
    if (-not [bool]$status.Success) {
        throw (Get-AtlasoTestVmCredentialBridgeError -Code ([string]$status.Code))
    }
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
Prove whether the exact normal test VM is currently running.

.PARAMETER VmxPath
Exact invocation-owned VMX to match against VMware's running list.

.PARAMETER VmrunPath
Resolved VMware vmrun executable path.

.PARAMETER TimeoutSeconds
Positive deadline for running-state discovery.
#>
function Test-AtlasoTestVmIsRunning {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds
    )

    $resolvedVmxPath = (Resolve-Path -LiteralPath $VmxPath).Path
    $targetIdentity = [Atlaso.WorkstationFileIdentity]::Get($resolvedVmxPath)
    $runningText = Invoke-AtlasoBoundedVmrun `
        -VmrunPath $VmrunPath `
        -ArgumentList @('-T', 'ws', 'list') `
        -TimeoutSeconds $TimeoutSeconds `
        -Action 'Prove the exact normal test VM running state'
    $runningTargets = @(ConvertFrom-AtlasoVmrunListOutput -Output @($runningText -split '\r?\n') |
        Where-Object {
            Test-AtlasoTestVmRunningPathMatchesIdentity `
                -RunningPath $_.Trim() `
                -TargetIdentity $targetIdentity
        })
    if ($runningTargets.Count -gt 1) {
        throw 'VMware reported the exact normal test VM more than once.'
    }
    return $runningTargets.Count -eq 1
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
Return the SHA-256 digest of one bounded UTF-8 cleanup identity.

.PARAMETER Value
Non-secret cleanup identity whose digest is persisted in the marker.
#>
function Get-AtlasoCleanupIdentityHash {
    param([Parameter(Mandatory = $true)][string]$Value)

    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($Value)
    return [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes))
}

<#
.SYNOPSIS
Stage a non-secret cleanup identity in one powered-off normal-test VMX.

.PARAMETER VmxPath
Exact invocation-owned VMX that VMware may replace during power-on.

.PARAMETER Identity
Fresh lowercase hexadecimal identity generated for this VM invocation.

.PARAMETER ExpectedVmxIdentity
Filesystem identity captured before acquiring the mutation lock.

.PARAMETER DurableIdentityAction
Optional marker-publication action that must complete while the VMX remains
locked against writers and same-path replacement.

.PARAMETER AllowExistingIdentity
Permit one exact matching cleanup identity to be rebound to a durable marker.
Use only for pre-secret rollback of the invocation-owned VM.
#>
function Set-AtlasoTestVmCleanupIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][string]$Identity,
        [Parameter(Mandatory = $true)][string]$ExpectedVmxIdentity,
        [scriptblock]$DurableIdentityAction,
        [switch]$AllowExistingIdentity
    )

    if ($Identity -cnotmatch '^[0-9a-f]{32}$') {
        throw 'The VMware cleanup identity is invalid.'
    }
    if ($ExpectedVmxIdentity -cnotmatch '^[0-9A-F]{8}:[0-9A-F]{16}$') {
        throw 'The VMware cleanup filesystem identity is invalid.'
    }
    $resolvedVmxPath = (Resolve-Path -LiteralPath $VmxPath).Path
    $pattern = '^\s*guestinfo\.atlaso\.test_vm_cleanup_identity\s*='
    $line = 'guestinfo.atlaso.test_vm_cleanup_identity = ' + (ConvertTo-AtlasoVmxString -Value $Identity)
    # Deny writers and deletion before validating the caller-bound file. This
    # closes the same-path replacement window and retains one file object from
    # validation through durable publication.
    $stream = [System.IO.File]::Open(
        $resolvedVmxPath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::Read
    )
    try {
        if ([Atlaso.WorkstationFileIdentity]::Get($resolvedVmxPath) -cne $ExpectedVmxIdentity) {
            throw "The VMX changed before cleanup identity publication; the file was preserved: $resolvedVmxPath"
        }
        $identityAssignmentCount = 0
        $reader = [System.IO.StreamReader]::new(
            $stream,
            [System.Text.UTF8Encoding]::new($false),
            $true,
            1024,
            $true
        )
        try {
            while (-not $reader.EndOfStream) {
                if ($reader.ReadLine() -match $pattern) {
                    $identityAssignmentCount++
                }
            }
        }
        finally {
            $reader.Dispose()
        }
        if ($identityAssignmentCount -ne 0 -and -not $AllowExistingIdentity) {
            throw "The VMX already carries a cleanup identity before marker publication: $resolvedVmxPath"
        }
        if ($identityAssignmentCount -eq 0) {
            $originalLength = $stream.Length
            $separator = ''
            if ($originalLength -gt 0) {
                $stream.Position = $originalLength - 1
                if ($stream.ReadByte() -notin @(10, 13)) {
                    $separator = "`r`n"
                }
            }
            $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
                "$separator$line`r`n"
            )
            $stream.Position = $originalLength
            try {
                # Append-only publication preserves every original VMX byte if
                # the host loses power before the marker becomes durable.
                $stream.Write($bytes, 0, $bytes.Length)
                $stream.Flush($true)
            }
            catch {
                $writeError = $_
                try {
                    $stream.SetLength($originalLength)
                    $stream.Flush($true)
                }
                catch {
                    throw "Cleanup identity publication failed and tail rollback could not be proven: $resolvedVmxPath"
                }
                throw $writeError
            }
        }
        elseif ($identityAssignmentCount -ne 1) {
            throw "The VMX does not carry one reusable cleanup identity: $resolvedVmxPath"
        }
        if (
            [Atlaso.WorkstationFileIdentity]::Get($resolvedVmxPath) -cne $ExpectedVmxIdentity -or
            (Get-AtlasoTestVmCleanupIdentityHash -VmxPath $resolvedVmxPath) -cne
            (Get-AtlasoCleanupIdentityHash -Value $Identity)
        ) {
            throw "The cleanup identity could not be proven in the VMX: $resolvedVmxPath"
        }
        if ($null -ne $DurableIdentityAction) {
            & $DurableIdentityAction
        }
    }
    finally {
        $stream.Dispose()
    }
}

<#
.SYNOPSIS
Read the exact non-secret cleanup identity from one VMX.

.PARAMETER VmxPath
Exact VMX whose stable cleanup binding must be verified.

.PARAMETER AllowAbsent
Return an empty value only when the VMX has no cleanup-identity assignment.
#>
function Get-AtlasoTestVmCleanupIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [switch]$AllowAbsent
    )

    $assignmentPattern = '^\s*guestinfo\.atlaso\.test_vm_cleanup_identity\s*='
    $valuePattern = '^\s*guestinfo\.atlaso\.test_vm_cleanup_identity\s*=\s*"(?<identity>[0-9a-f]{32})"\s*$'
    # Count every assignment before validating the value. One valid line plus
    # a malformed duplicate is still ambiguous and must fail closed.
    $identityLines = @(
        Get-Content -LiteralPath $VmxPath |
            Where-Object { $_ -match $assignmentPattern }
    )
    if ($AllowAbsent -and $identityLines.Count -eq 0) {
        return ''
    }
    if ($identityLines.Count -ne 1) {
        throw 'The VMX does not contain exactly one valid non-secret cleanup identity.'
    }
    $identityMatch = [regex]::Match($identityLines[0], $valuePattern)
    if (-not $identityMatch.Success) {
        throw 'The VMX does not contain exactly one valid non-secret cleanup identity.'
    }
    return $identityMatch.Groups['identity'].Value
}

<#
.SYNOPSIS
Read and hash the exact non-secret cleanup identity from one VMX.

.PARAMETER VmxPath
Exact VMX whose stable cleanup binding must be verified.
#>
function Get-AtlasoTestVmCleanupIdentityHash {
    param([Parameter(Mandatory = $true)][string]$VmxPath)

    return Get-AtlasoCleanupIdentityHash -Value (
        Get-AtlasoTestVmCleanupIdentity -VmxPath $VmxPath
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
Durably replace one validated cleanup-marker payload.

.PARAMETER MarkerPath
Exact existing marker path to replace atomically.

.PARAMETER Payload
Validated marker object serialized without secret material.
#>
function Write-AtlasoDevelopmentCaCleanupMarkerPayload {
    param(
        [Parameter(Mandatory = $true)][string]$MarkerPath,
        [Parameter(Mandatory = $true)][object]$Payload
    )

    $resolvedMarkerPath = (Resolve-Path -LiteralPath $MarkerPath).Path
    $temporaryPath = "$resolvedMarkerPath.$([guid]::NewGuid().ToString('N')).tmp"
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        ($Payload | ConvertTo-Json -Depth 4 -Compress)
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

.PARAMETER MarkerPathReference
Optional caller-owned path reference populated only after the cleanup marker is
durably published and bound to the VMX cleanup identity.

.PARAMETER InitialPhase
Initial durable cleanup phase. Pre-secret rollback uses stopped/scrubbed proof.

.PARAMETER AllowExistingCleanupIdentity
Reuse one exact cleanup identity already written by this invocation when its
original marker publication failed before any secret child started.
#>
function New-AtlasoDevelopmentCaCleanupMarker {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$DataDiskStates,
        [string]$MarkerRoot = (Get-AtlasoDevelopmentCaCleanupMarkerRoot),
        [ref]$MarkerPathReference,
        [ValidateSet('secret-child-active', 'stopped-vmx-scrubbed')]
        [string]$InitialPhase = 'secret-child-active',
        [switch]$AllowExistingCleanupIdentity
    )

    $resolvedVmxPath = (Resolve-Path -LiteralPath $VmxPath).Path
    $resolvedOutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
    Assert-AtlasoStrictDescendantPath `
        -ParentPath $resolvedOutputDirectory `
        -ChildPath $resolvedVmxPath `
        -FailureMessage 'Refusing to record development-CA cleanup outside the exact VM directory'
    # Publish a non-secret VM-owned binding before the durable marker. VMware
    # preserves this assignment when it atomically replaces the VMX at power-on.
    $existingCleanupIdentity = if ($AllowExistingCleanupIdentity) {
        Get-AtlasoTestVmCleanupIdentity -VmxPath $resolvedVmxPath -AllowAbsent
    }
    else {
        ''
    }
    $cleanupIdentity = if ($existingCleanupIdentity) {
        $existingCleanupIdentity
    }
    else {
        [guid]::NewGuid().ToString('N')
    }
    $vmxIdentity = [Atlaso.WorkstationFileIdentity]::Get($resolvedVmxPath)
    $cleanupIdentityHash = Get-AtlasoCleanupIdentityHash -Value $cleanupIdentity
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
        Schema = 3
        Phase = $InitialPhase
        HostBootIdentity = (Get-AtlasoHostBootIdentity)
        Name = $Name
        VmxPath = $resolvedVmxPath
        VmxIdentity = $vmxIdentity
        CleanupIdentityHash = $cleanupIdentityHash
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
    # GetNewClosure() captures values but does not retain this script's command
    # lookup scope. Capture the script-local helper itself so normal wrapper
    # execution cannot depend on ambient or global function state.
    $durableMarkerMoveAction = ${function:Move-AtlasoDurableCleanupMarkerFile}
    if ($null -eq $durableMarkerMoveAction) {
        throw 'The durable cleanup-marker rename helper is unavailable.'
    }
    $publishMarker = {
        $markerStream = [System.IO.FileStream]::new(
            $temporaryPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None,
            4096,
            [System.IO.FileOptions]::WriteThrough
        )
        try {
            $markerStream.Write($bytes, 0, $bytes.Length)
            $markerStream.Flush($true)
        }
        finally {
            $markerStream.Dispose()
        }
        # Keep the VMX write-excluding handle through durable marker rename so
        # the marker can never bind an unproven same-path replacement.
        & $durableMarkerMoveAction `
            -SourcePath $temporaryPath `
            -DestinationPath $markerPath
    }.GetNewClosure()
    try {
        Set-AtlasoTestVmCleanupIdentity `
            -VmxPath $resolvedVmxPath `
            -Identity $cleanupIdentity `
            -ExpectedVmxIdentity $vmxIdentity `
            -DurableIdentityAction $publishMarker `
            -AllowExistingIdentity:$AllowExistingCleanupIdentity
        if ($null -ne $MarkerPathReference) {
            # A caller-known intended pathname is not durable recovery state.
            # Expose it only after the write-through rename succeeds.
            $MarkerPathReference.Value = $markerPath
        }
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
            'vm-stop-child-active',
            'import-proven-stopped-vmx-scrubbed',
            'vm-restart-child-active',
            'restarted-vmx-scrubbed',
            'stopped-vmx-scrubbed',
            'removal-child-active',
            'retired'
        )]
        [string]$ExpectedPhase,
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'secret-child-active',
            'staged',
            'vm-start-child-active',
            'vm-stop-child-active',
            'import-proven-stopped-vmx-scrubbed',
            'vm-restart-child-active',
            'restarted-vmx-scrubbed',
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
        'staged' { $Phase -cin @('secret-child-active', 'vm-start-child-active', 'vm-stop-child-active', 'stopped-vmx-scrubbed', 'retired') }
        'vm-start-child-active' { $Phase -cin @('staged', 'stopped-vmx-scrubbed') }
        'vm-stop-child-active' { $Phase -cin @('staged', 'import-proven-stopped-vmx-scrubbed') }
        'import-proven-stopped-vmx-scrubbed' { $Phase -cin @('vm-stop-child-active', 'vm-restart-child-active') }
        'vm-restart-child-active' { $Phase -cin @('import-proven-stopped-vmx-scrubbed', 'restarted-vmx-scrubbed') }
        'restarted-vmx-scrubbed' { $Phase -cin @('import-proven-stopped-vmx-scrubbed', 'retired') }
        'stopped-vmx-scrubbed' { $Phase -cin @('removal-child-active', 'retired') }
        'removal-child-active' { $Phase -ceq 'stopped-vmx-scrubbed' }
        default { $false }
    }
    if ($payload.Schema -notin @(2, 3) -or $payload.Phase -cne $ExpectedPhase -or -not $validTransition) {
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
            if ($marker.Phase -notin @('staged', 'restarted-vmx-scrubbed', 'stopped-vmx-scrubbed')) {
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
        $marker.Schema -notin @(2, 3) -or
        $marker.Phase -notin @(
            'secret-child-active',
            'staged',
            'vm-start-child-active',
            'vm-stop-child-active',
            'import-proven-stopped-vmx-scrubbed',
            'vm-restart-child-active',
            'restarted-vmx-scrubbed',
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
    if (
        $marker.Schema -eq 3 -and
        ([string]$marker.CleanupIdentityHash -cnotmatch '^[0-9A-F]{64}$')
    ) {
        throw "Development-CA cleanup identity is invalid and blocks new VM creation: $MarkerPath"
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
            if (
                $marker.Schema -ne 3 -or
                (Get-AtlasoTestVmCleanupIdentityHash -VmxPath $resolvedVmxPath) -cne
                [string]$marker.CleanupIdentityHash
            ) {
                throw "The marked VMX changed filesystem identity; preserve it for manual review: $MarkerPath"
            }
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
        Schema = [int]$marker.Schema
        CleanupIdentityHash = [string]$marker.CleanupIdentityHash
        ArtifactsRemoved = $artifactsRemoved
    }
}

<#
.SYNOPSIS
Reconcile a durably published cleanup marker whose caller path was not exposed.

.PARAMETER VmxPath
Exact invocation-owned VMX whose non-secret cleanup identity binds the marker.

.PARAMETER Name
Exact normal-test VM name recorded by the interrupted publication.

.PARAMETER OutputDirectory
Exact invocation-owned VM artifact directory recorded by the marker.

.PARAMETER MarkerRoot
Per-user marker directory that may contain the interrupted publication.
#>
function Find-AtlasoDevelopmentCaCleanupMarker {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [string]$MarkerRoot = (Get-AtlasoDevelopmentCaCleanupMarkerRoot)
    )

    if (-not (Test-Path -LiteralPath $MarkerRoot -PathType Container)) {
        return $null
    }
    Assert-AtlasoStrictDescendantPath `
        -ParentPath (Split-Path -Parent $MarkerRoot) `
        -ChildPath $MarkerRoot `
        -FailureMessage 'Refusing a development-CA marker directory through a reparse point'
    $resolvedVmxPath = (Resolve-Path -LiteralPath $VmxPath).Path
    $resolvedOutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
    $markerFiles = @(Get-ChildItem -LiteralPath $MarkerRoot -File -Force)
    if (@($markerFiles | Where-Object Extension -ne '.json').Count -gt 0) {
        throw 'Cleanup-marker publication outcome is ambiguous; preserve the VM artifacts for retry.'
    }
    if ($markerFiles.Count -eq 0) {
        # A clean rollback of the VMX append leaves no identity and no durable
        # destination. Avoid demanding an identity until a marker exists that
        # could have crossed the write-through rename boundary.
        return $null
    }
    $cleanupIdentityHash = Get-AtlasoTestVmCleanupIdentityHash -VmxPath $resolvedVmxPath
    $matchingMarkers = @(
        foreach ($markerFile in $markerFiles) {
            $marker = Read-AtlasoDevelopmentCaCleanupMarker `
                -MarkerPath $markerFile.FullName `
                -MarkerRoot $MarkerRoot
            if (
                $marker.Schema -eq 3 -and
                $marker.Phase -ceq 'secret-child-active' -and
                $marker.Name -ceq $Name -and
                $marker.VmxPath.Equals($resolvedVmxPath, [System.StringComparison]::OrdinalIgnoreCase) -and
                $marker.OutputDirectory.Equals(
                    $resolvedOutputDirectory,
                    [System.StringComparison]::OrdinalIgnoreCase
                ) -and
                $marker.CleanupIdentityHash -ceq $cleanupIdentityHash
            ) {
                $marker
            }
        }
    )
    if ($matchingMarkers.Count -eq 1 -and $markerFiles.Count -eq 1) {
        return $matchingMarkers[0]
    }
    # Never publish a second marker when any durable destination cannot be
    # proven to be the one identity-bound result of this invocation.
    throw 'Cleanup-marker publication outcome is ambiguous; preserve the VM artifacts for retry.'
}

<#
.SYNOPSIS
Rebind one legacy staged marker after a proven VMware VMX replacement.

.PARAMETER MarkerPath
Exact schema-2 marker created by the previous wrapper version.

.PARAMETER MarkerRoot
Expected per-user marker parent.

.PARAMETER VmrunPath
Resolved vmrun executable used for exact running-path and guest proof.

.PARAMETER ExpectedFingerprint
Checked-in public development-root fingerprint expected from the guest.

.PARAMETER TimeoutSeconds
Positive deadline for each proof operation.
#>
function Repair-AtlasoLegacyDevelopmentCaCleanupMarkerIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$MarkerPath,
        [Parameter(Mandatory = $true)][string]$MarkerRoot,
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][string]$ExpectedFingerprint,
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds
    )

    Assert-AtlasoStrictDescendantPath `
        -ParentPath $MarkerRoot `
        -ChildPath $MarkerPath `
        -FailureMessage 'Refusing a legacy development-CA marker outside the exact marker root'
    $item = Get-Item -LiteralPath $MarkerPath -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -gt 32768) {
        throw "Legacy development-CA cleanup marker is unsafe: $MarkerPath"
    }
    try {
        $payload = Get-Content -LiteralPath $MarkerPath -Raw | ConvertFrom-Json
    }
    catch {
        throw "Legacy development-CA cleanup marker is invalid: $MarkerPath"
    }
    if (
        $payload.Schema -ne 2 -or
        $payload.Phase -cne 'staged' -or
        [string]$payload.HostBootIdentity -cne (Get-AtlasoHostBootIdentity) -or
        -not [System.IO.Path]::IsPathFullyQualified([string]$payload.VmxPath) -or
        -not [System.IO.Path]::IsPathFullyQualified([string]$payload.OutputDirectory)
    ) {
        throw "Legacy development-CA cleanup marker is not eligible for same-boot VMX rebinding: $MarkerPath"
    }
    $resolvedVmxPath = (Resolve-Path -LiteralPath ([string]$payload.VmxPath)).Path
    $resolvedOutputDirectory = (Resolve-Path -LiteralPath ([string]$payload.OutputDirectory)).Path
    Assert-AtlasoStrictDescendantPath `
        -ParentPath $resolvedOutputDirectory `
        -ChildPath $resolvedVmxPath `
        -FailureMessage 'Legacy marked VMX is outside its exact artifact directory'
    $displayName = Get-AtlasoVmxDisplayName -Path $resolvedVmxPath
    if (-not $displayName.Equals([string]$payload.Name, [System.StringComparison]::Ordinal)) {
        throw "Legacy marked VMX display identity changed; preserve it for manual review: $MarkerPath"
    }
    $runningText = Invoke-AtlasoBoundedVmrun `
        -VmrunPath $VmrunPath `
        -ArgumentList @('-T', 'ws', 'list') `
        -TimeoutSeconds $TimeoutSeconds `
        -Action 'Prove the legacy marked VM is the exact running path'
    $runningMatches = @(ConvertFrom-AtlasoVmrunListOutput -Output @($runningText -split '\r?\n') |
        Where-Object {
            [System.IO.Path]::IsPathFullyQualified($_) -and
            [System.IO.Path]::GetFullPath($_).Equals(
                $resolvedVmxPath,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        })
    if ($runningMatches.Count -ne 1) {
        throw "Legacy marked VMX replacement is not the one exact running path; preserve it for manual review: $MarkerPath"
    }
    Wait-AtlasoWorkstationDevelopmentRootCaPrivateKeyScrub `
        -VmxPath $resolvedVmxPath `
        -VmrunPath $VmrunPath `
        -TimeoutSeconds $TimeoutSeconds
    Wait-AtlasoWorkstationDevelopmentRootCaImportProof `
        -VmxPath $resolvedVmxPath `
        -VmrunPath $VmrunPath `
        -ExpectedFingerprint $ExpectedFingerprint `
        -TimeoutSeconds $TimeoutSeconds
    # Only the non-secret filesystem identity changes here. Exact running-path,
    # display-name, guest scrub, and import proofs all precede the durable rebind.
    $payload.VmxIdentity = [Atlaso.WorkstationFileIdentity]::Get($resolvedVmxPath)
    Write-AtlasoDevelopmentCaCleanupMarkerPayload -MarkerPath $MarkerPath -Payload $payload
}

<#
.SYNOPSIS
Upgrade a stopped schema-2 marker to the replacement-stable schema.

.PARAMETER Marker
Validated legacy marker whose exact VM is stopped and signer-free.
#>
function Upgrade-AtlasoLegacyDevelopmentCaCleanupMarker {
    param([Parameter(Mandatory = $true)][object]$Marker)

    $payload = Get-Content -LiteralPath $Marker.MarkerPath -Raw | ConvertFrom-Json
    if ($payload.Schema -ne 2 -or $payload.Phase -cne 'vm-stop-child-active') {
        throw "Legacy cleanup marker upgrade did not match the stopped transition: $($Marker.MarkerPath)"
    }
    $vmxIdentity = [Atlaso.WorkstationFileIdentity]::Get($Marker.VmxPath)
    $cleanupIdentity = Get-AtlasoTestVmCleanupIdentity `
        -VmxPath $Marker.VmxPath `
        -AllowAbsent
    if ([string]::IsNullOrEmpty($cleanupIdentity)) {
        $cleanupIdentity = [guid]::NewGuid().ToString('N')
        Set-AtlasoTestVmCleanupIdentity `
            -VmxPath $Marker.VmxPath `
            -Identity $cleanupIdentity `
            -ExpectedVmxIdentity $vmxIdentity
    }
    $resolvedVmxPath = (Resolve-Path -LiteralPath $Marker.VmxPath).Path
    # Hold the captured VMX against writers and same-path replacement while
    # rebinding the sole durable identity into the upgraded marker. The first
    # read decides only whether an append is needed; this locked read is the
    # authoritative value published by the schema transition.
    $stream = [System.IO.File]::Open(
        $resolvedVmxPath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read
    )
    try {
        if ([Atlaso.WorkstationFileIdentity]::Get($resolvedVmxPath) -cne $vmxIdentity) {
            throw "The VMX changed before legacy cleanup marker upgrade; the marker was preserved: $resolvedVmxPath"
        }
        $cleanupIdentity = Get-AtlasoTestVmCleanupIdentity -VmxPath $resolvedVmxPath
        $payload.Schema = 3
        $payload.Phase = 'import-proven-stopped-vmx-scrubbed'
        $payload.VmxIdentity = $vmxIdentity
        $payload | Add-Member `
            -NotePropertyName CleanupIdentityHash `
            -NotePropertyValue (Get-AtlasoCleanupIdentityHash -Value $cleanupIdentity)
        Write-AtlasoDevelopmentCaCleanupMarkerPayload -MarkerPath $Marker.MarkerPath -Payload $payload
    }
    finally {
        $stream.Dispose()
    }
    $Marker.Schema = 3
    $Marker.Phase = 'import-proven-stopped-vmx-scrubbed'
    $Marker.CleanupIdentityHash = [string]$payload.CleanupIdentityHash
}

<#
.SYNOPSIS
Finalize a proven development-signer import without leaving plaintext in VMX.

.PARAMETER Marker
Validated cleanup marker for the exact normal test VM.

.PARAMETER VmrunPath
Resolved VMware vmrun executable used for bounded stop and readback.

.PARAMETER TimeoutSeconds
Positive per-operation deadline.
#>
function Complete-AtlasoDevelopmentCaSuccessfulImport {
    param(
        [Parameter(Mandatory = $true)][object]$Marker,
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds
    )

    $restartScrubProven = $false
    if ($Marker.Phase -in @('staged', 'vm-stop-child-active')) {
        if ($Marker.Phase -ceq 'staged') {
            Set-AtlasoDevelopmentCaCleanupMarkerPhase `
                -MarkerPath $Marker.MarkerPath `
                -ExpectedPhase staged `
                -Phase vm-stop-child-active
            $Marker.Phase = 'vm-stop-child-active'
        }
        try {
            Stop-AtlasoTestVmForRollback `
                -VmxPath $Marker.VmxPath `
                -VmrunPath $VmrunPath `
                -TimeoutSeconds $TimeoutSeconds
            Clear-AtlasoWorkstationDevelopmentRootCaPrivateKey -VmxPath $Marker.VmxPath
        }
        catch {
            # Import proof precedes this phase. Keep the boot-bound stop marker
            # on every failure so a powered-off guest is never misclassified as
            # unproven and sent through destructive creation rollback.
            throw
        }
        if ($Marker.Schema -eq 2) {
            Upgrade-AtlasoLegacyDevelopmentCaCleanupMarker -Marker $Marker
        }
        else {
            Set-AtlasoDevelopmentCaCleanupMarkerPhase `
                -MarkerPath $Marker.MarkerPath `
                -ExpectedPhase vm-stop-child-active `
                -Phase import-proven-stopped-vmx-scrubbed
            $Marker.Phase = 'import-proven-stopped-vmx-scrubbed'
        }
        $restartScrubProven = $true
    }

    if ($Marker.Phase -ceq 'restarted-vmx-scrubbed') {
        if (-not (Test-AtlasoTestVmIsRunning `
                -VmxPath $Marker.VmxPath `
                -VmrunPath $VmrunPath `
                -TimeoutSeconds $TimeoutSeconds)) {
            # A host interruption after restart can leave the durable marker
            # ahead of runtime state. Return to the stopped proof and perform
            # the full stop/scrub/restart sequence before trusting readback.
            Set-AtlasoDevelopmentCaCleanupMarkerPhase `
                -MarkerPath $Marker.MarkerPath `
                -ExpectedPhase restarted-vmx-scrubbed `
                -Phase import-proven-stopped-vmx-scrubbed
            $Marker.Phase = 'import-proven-stopped-vmx-scrubbed'
        }
    }

    if ($Marker.Phase -in @('import-proven-stopped-vmx-scrubbed', 'vm-restart-child-active')) {
        if ($Marker.Phase -ceq 'vm-restart-child-active') {
            # A prior restart child can only be retried after the caller has
            # established a different host boot, proving its process tree gone.
            Set-AtlasoDevelopmentCaCleanupMarkerPhase `
                -MarkerPath $Marker.MarkerPath `
                -ExpectedPhase vm-restart-child-active `
                -Phase import-proven-stopped-vmx-scrubbed
            $Marker.Phase = 'import-proven-stopped-vmx-scrubbed'
        }
        # Re-prove powered-off state and durably scrub immediately before every
        # restart. This closes a power-loss window between VMX persistence and
        # the marker's durable stopped/scrubbed phase.
        if (-not $restartScrubProven) {
            Set-AtlasoDevelopmentCaCleanupMarkerPhase `
                -MarkerPath $Marker.MarkerPath `
                -ExpectedPhase import-proven-stopped-vmx-scrubbed `
                -Phase vm-stop-child-active
            $Marker.Phase = 'vm-stop-child-active'
            Stop-AtlasoTestVmForRollback `
                -VmxPath $Marker.VmxPath `
                -VmrunPath $VmrunPath `
                -TimeoutSeconds $TimeoutSeconds
            Clear-AtlasoWorkstationDevelopmentRootCaPrivateKey -VmxPath $Marker.VmxPath
            Set-AtlasoDevelopmentCaCleanupMarkerPhase `
                -MarkerPath $Marker.MarkerPath `
                -ExpectedPhase vm-stop-child-active `
                -Phase import-proven-stopped-vmx-scrubbed
            $Marker.Phase = 'import-proven-stopped-vmx-scrubbed'
        }
        Set-AtlasoDevelopmentCaCleanupMarkerPhase `
            -MarkerPath $Marker.MarkerPath `
            -ExpectedPhase import-proven-stopped-vmx-scrubbed `
            -Phase vm-restart-child-active
        $Marker.Phase = 'vm-restart-child-active'
        try {
            Invoke-AtlasoBoundedProcess `
                -FilePath (Get-Process -Id $PID).Path `
                -ArgumentList @(
                    '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
                    (Join-Path $PSScriptRoot 'start-atlaso-vm.ps1'),
                    '-VmxPath', $Marker.VmxPath,
                    '-VmrunPath', $VmrunPath,
                    '-Mode', 'gui'
                ) `
                -TimeoutSeconds $TimeoutSeconds `
                -Action 'Restart the normal test VM after powered-off signer scrub' | Out-Null
        }
        catch {
            if ($_.Exception.Data['AtlasoProcessTreeTerminationUnproven'] -ne $true) {
                Set-AtlasoDevelopmentCaCleanupMarkerPhase `
                    -MarkerPath $Marker.MarkerPath `
                    -ExpectedPhase vm-restart-child-active `
                    -Phase import-proven-stopped-vmx-scrubbed
                $Marker.Phase = 'import-proven-stopped-vmx-scrubbed'
            }
            throw
        }
        Set-AtlasoDevelopmentCaCleanupMarkerPhase `
            -MarkerPath $Marker.MarkerPath `
            -ExpectedPhase vm-restart-child-active `
            -Phase restarted-vmx-scrubbed
        $Marker.Phase = 'restarted-vmx-scrubbed'
    }

    if ($Marker.Phase -ceq 'restarted-vmx-scrubbed') {
        Wait-AtlasoWorkstationDevelopmentRootCaPrivateKeyScrub `
            -VmxPath $Marker.VmxPath `
            -VmrunPath $VmrunPath `
            -TimeoutSeconds $TimeoutSeconds
        Remove-AtlasoDevelopmentCaCleanupMarker -MarkerPath $Marker.MarkerPath
    }
}

<#
.SYNOPSIS
Retry every interrupted development-CA rollback before another VM mutation.

.PARAMETER VmrunPath
Resolved VMware vmrun executable used for bounded scrub and stop proof.

.PARAMETER TimeoutSeconds
Positive per-operation deadline.

.PARAMETER ExpectedFingerprint
Checked-in public development-root fingerprint used to recognize completed import.

.PARAMETER MarkerRoot
Per-user marker directory; override only for focused tests.
#>
function Invoke-PendingAtlasoDevelopmentCaCleanup {
    param(
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][ValidateRange(1, 3600)][int]$TimeoutSeconds,
        [string]$ExpectedFingerprint = ('0' * 64),
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
        try {
            $marker = Read-AtlasoDevelopmentCaCleanupMarker `
                -MarkerPath $markerFile.FullName `
                -MarkerRoot $MarkerRoot
        }
        catch {
            if ($_.Exception.Message -notlike 'The marked VMX changed filesystem identity;*') {
                throw
            }
            Repair-AtlasoLegacyDevelopmentCaCleanupMarkerIdentity `
                -MarkerPath $markerFile.FullName `
                -MarkerRoot $MarkerRoot `
                -VmrunPath $VmrunPath `
                -ExpectedFingerprint $ExpectedFingerprint `
                -TimeoutSeconds $TimeoutSeconds
            $marker = Read-AtlasoDevelopmentCaCleanupMarker `
                -MarkerPath $markerFile.FullName `
                -MarkerRoot $MarkerRoot
        }
        if ($marker.Phase -ceq 'retired') {
            Remove-AtlasoDevelopmentCaCleanupMarker -MarkerPath $marker.MarkerPath
            continue
        }
        if (
            $marker.Phase -in @(
                'secret-child-active',
                'vm-start-child-active',
                'vm-stop-child-active',
                'vm-restart-child-active',
                'removal-child-active'
            ) -and
            (Get-AtlasoHostBootIdentity) -ceq $marker.HostBootIdentity
        ) {
            throw "Development-CA cleanup is deferred until a Windows host restart proves the unbounded process tree is gone: $($marker.MarkerPath)"
        }
        if (
            $marker.Phase -in @(
                'staged',
                'vm-stop-child-active',
                'import-proven-stopped-vmx-scrubbed',
                'vm-restart-child-active',
                'restarted-vmx-scrubbed'
            )
        ) {
            # The stop-child phase is published only after runtime scrub and
            # encrypted-import proof. After a host restart proves that child
            # cannot still mutate the VM, resume powered-off scrub/restart
            # directly instead of re-reading a guest that may already be off.
            $importProven = $marker.Phase -in @(
                'vm-stop-child-active',
                'import-proven-stopped-vmx-scrubbed',
                'vm-restart-child-active',
                'restarted-vmx-scrubbed'
            )
            if (-not $importProven) {
                try {
                    Wait-AtlasoWorkstationDevelopmentRootCaPrivateKeyScrub `
                        -VmxPath $marker.VmxPath `
                        -VmrunPath $VmrunPath `
                        -TimeoutSeconds $TimeoutSeconds
                    Wait-AtlasoWorkstationDevelopmentRootCaImportProof `
                        -VmxPath $marker.VmxPath `
                        -VmrunPath $VmrunPath `
                        -ExpectedFingerprint $ExpectedFingerprint `
                        -TimeoutSeconds $TimeoutSeconds
                    $importProven = $true
                }
                catch {
                    $importProven = $false
                }
            }
            if ($importProven) {
                Complete-AtlasoDevelopmentCaSuccessfulImport `
                    -Marker $marker `
                    -VmrunPath $VmrunPath `
                    -TimeoutSeconds $TimeoutSeconds
                continue
            }
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
                Write-Verbose "Runtime signing-key scrub was unavailable before powered-off VMX cleanup: $($_.Exception.Message)"
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
                Write-Verbose "Could not remove partial root CA download: $($_.Exception.Message)"
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
    Operator-facing connection detail rendered beside the label.

    .PARAMETER ValueColor
    Console foreground color used to distinguish the connection detail.
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
        -TimeoutSeconds ([Math]::Min($TimeoutSeconds, 30)) `
        -ExpectedFingerprint $developmentRootCaFingerprint
}
if ($NoStart) {
    throw '-NoStart is not supported for normal test VMs because first boot must consume and scrub the shared development signing key.'
}
if (-not $WhatIfPreference) {
    # Resolve new Environment configuration only after credential-independent
    # recovery has scrubbed any signer staging left by an interrupted prior run.
    $OnePasswordEnvironmentId = Resolve-OnePasswordDevelopmentCaEnvironmentId `
        -EnvironmentId $OnePasswordEnvironmentId `
        -EnvironmentIdFile $EnvironmentIdFile `
        -RepositoryRoot $repoRoot
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
$credentialBridgeState = $null
if (-not $WhatIfPreference) {
    # The parent converts explicit SecureStrings only to current-user DPAPI
    # ciphertext. Retrieved defaults and OVF plaintext exist solely in bounded
    # children, and all credential failures precede provider preparation.
    $credentialBridgeState = New-AtlasoTestVmCredentialBridgeState `
        -RepositoryRoot $repoRoot `
        -EnvironmentId $OnePasswordEnvironmentId `
        -OnePasswordAccount $OnePasswordAccount `
        -OnePasswordPython $OnePasswordPython `
        -OnePasswordCliPath $resolvedOpPath `
        -AdminPassword $AdminPassword `
        -RootPassword $RootPassword `
        -Fqdn $FirstBootFqdn `
        -RootSshEnabled ([bool]$RootSshEnabled) `
        -DevelopmentAdminSshPublicKey $developmentAdminSshPublicKey `
        -DevelopmentRootCaCertificatePem $developmentRootCaCertificatePem `
        -TimeoutSeconds $TimeoutSeconds
}

try {
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
$credentialStageFailure = $null
$credentialBridgeCleanupError = ''
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
        $createdThisInvocation = $true
        try {
            # Credential staging can rewrite the new VMX. Publish the same
            # restart-safe child-active marker used by signer staging before
            # launching it, so an unproven process tree blocks later cleanup.
            New-AtlasoDevelopmentCaCleanupMarker `
                -VmxPath $targetVmx `
                -Name $Name `
                -OutputDirectory $resolvedOutputDirectory `
                -DataDiskStates $rollbackDataDiskStates `
                -MarkerPathReference ([ref]$developmentCaCleanupMarkerPath) | Out-Null
            try {
                Invoke-AtlasoTestVmCredentialStage `
                    -BridgeState $credentialBridgeState `
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
            Set-AtlasoDevelopmentCaCleanupMarkerPhase `
                -MarkerPath $developmentCaCleanupMarkerPath `
                -ExpectedPhase secret-child-active `
                -Phase staged
        }
        catch {
            # Defer the failure until after the DPAPI bridge cleanup attempt,
            # then enter the shared identity-bound VM rollback below.
            $credentialStageFailure = $_
        }
}
}
finally {
    if ($null -ne $credentialBridgeState) {
        try {
            Remove-AtlasoTestVmCredentialBridgeState -BridgeRoot $credentialBridgeState.Root
        }
        catch {
            $credentialBridgeCleanupError = $_.Exception.Message
        }
        $credentialBridgeState = $null
    }
}

if (-not $createdThisInvocation -and -not $WhatIfPreference) {
    if ($credentialBridgeCleanupError) {
        throw "Normal test VM creation was not approved, and credential bridge cleanup failed: $credentialBridgeCleanupError"
    }
    Write-Host 'Normal test VM creation was not approved; no development signing key was staged.' -ForegroundColor Yellow
    return
}

if (-not $WhatIfPreference) {
    try {
        if ($null -ne $credentialStageFailure) {
            if ($credentialBridgeCleanupError) {
                throw "$($credentialStageFailure.Exception.Message) Credential bridge cleanup also failed: $credentialBridgeCleanupError"
            }
            throw $credentialStageFailure
        }
        if ($credentialBridgeCleanupError) {
            throw "Credential bridge cleanup failed before signer staging: $credentialBridgeCleanupError"
        }
        # Re-enter child-active state before the signer child can rewrite the
        # exact VMX. Any unproven termination keeps restart-safe recovery active.
        Set-AtlasoDevelopmentCaCleanupMarkerPhase `
            -MarkerPath $developmentCaCleanupMarkerPath `
            -ExpectedPhase staged `
            -Phase secret-child-active
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
        $successfulImportMarker = Read-AtlasoDevelopmentCaCleanupMarker `
            -MarkerPath $developmentCaCleanupMarkerPath `
            -MarkerRoot (Get-AtlasoDevelopmentCaCleanupMarkerRoot)
        Complete-AtlasoDevelopmentCaSuccessfulImport `
            -Marker $successfulImportMarker `
            -VmrunPath $resolvedVmrunPath `
            -TimeoutSeconds $TimeoutSeconds
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
            if (
                $cleanupMarker.Phase -in @(
                    'secret-child-active',
                    'vm-start-child-active',
                    'vm-stop-child-active',
                    'vm-restart-child-active'
                )
            ) {
                throw "$($failure.Exception.Message) The durable cleanup marker remains at $developmentCaCleanupMarkerPath; no VM or VMX rollback was attempted. Restart Windows, then rerun the wrapper so the new host boot can prove the child process tree is gone before cleanup."
            }
            if (
                $cleanupMarker.Phase -in @(
                    'import-proven-stopped-vmx-scrubbed',
                    'restarted-vmx-scrubbed'
                )
            ) {
                # Encrypted import is already durable in these phases. Preserve
                # the exact VM and marker so a transient restart/readback failure
                # cannot enter failed-creation rollback and delete a healthy VM.
                throw "$($failure.Exception.Message) The encrypted development signer import is proven and its durable cleanup marker remains at $developmentCaCleanupMarkerPath; no VM or artifact rollback was attempted. Rerun the wrapper to resume final signer cleanup."
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
                if (-not $developmentCaCleanupMarkerPath) {
                    # The atomic rename may have succeeded before a later VMX
                    # readback or handle disposal failed. Reconcile that exact
                    # identity-bound destination before considering a fallback.
                    $publishedCleanupMarker = Find-AtlasoDevelopmentCaCleanupMarker `
                        -VmxPath $targetVmx `
                        -Name $Name `
                        -OutputDirectory $resolvedOutputDirectory
                    if ($null -ne $publishedCleanupMarker) {
                        $developmentCaCleanupMarkerPath = $publishedCleanupMarker.MarkerPath
                        Set-AtlasoDevelopmentCaCleanupMarkerPhase `
                            -MarkerPath $developmentCaCleanupMarkerPath `
                            -ExpectedPhase secret-child-active `
                            -Phase stopped-vmx-scrubbed
                    }
                    else {
                        # A pre-secret failure before rename may leave only the
                        # exact invocation-owned VMX identity. Publish boot-bound
                        # rollback ownership before any removal child can outlive
                        # this process.
                        New-AtlasoDevelopmentCaCleanupMarker `
                            -VmxPath $targetVmx `
                            -Name $Name `
                            -OutputDirectory $resolvedOutputDirectory `
                            -DataDiskStates $rollbackDataDiskStates `
                            -MarkerPathReference ([ref]$developmentCaCleanupMarkerPath) `
                            -InitialPhase stopped-vmx-scrubbed `
                            -AllowExistingCleanupIdentity | Out-Null
                    }
                }
                else {
                    Set-AtlasoDevelopmentCaCleanupMarkerPhase `
                        -MarkerPath $developmentCaCleanupMarkerPath `
                        -ExpectedPhase staged `
                        -Phase stopped-vmx-scrubbed
                }
                if ($rollbackDataDiskStates.Count -gt 0) {
                    $rollbackQuarantineId = [System.IO.Path]::GetFileNameWithoutExtension(
                        $developmentCaCleanupMarkerPath
                    )
                    $quarantineDirectory = Join-Path `
                        (Split-Path -Parent $resolvedOutputDirectory) `
                        ".atlaso-development-ca-cleanup-$rollbackQuarantineId"
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

if (($waitForIpEnabled -or $TrustRootCa) -and $readinessIdentity) {
    $ip = $readinessIdentity.IPAddress
    if ($waitForIpEnabled) {
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
