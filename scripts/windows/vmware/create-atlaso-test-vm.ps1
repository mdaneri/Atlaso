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
Wait for the started VM management address, verify its development root CA, and
print its connection summary. Enabled by default; opt out with -WaitForIp:$false.

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
Bounded wait used for management-address and root-CA readiness.
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
    [int]$TimeoutSeconds = 300
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
#>
function Assert-OnePasswordDevelopmentCaBridge {
    param(
        [Parameter(Mandatory = $true)][string]$EnvironmentId,
        [Parameter(Mandatory = $true)][string]$OpPath
    )

    if ($EnvironmentId -notmatch '^[A-Za-z0-9_-]{8,128}$') {
        throw 'OnePasswordEnvironmentId is required and must be the opaque ID of the exact Atlaso Environment.'
    }
    if ($env:ATLASO_DEVELOPMENT_ROOT_CA_PRIVATE_KEY) {
        throw 'ATLASO_DEVELOPMENT_ROOT_CA_PRIVATE_KEY must come only from the exact 1Password Environment bridge.'
    }
    $runHelp = (& $OpPath run --help 2>&1 | Out-String)
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
#>
function Invoke-OnePasswordDevelopmentCaChild {
    param(
        [Parameter(Mandatory = $true)][string]$EnvironmentId,
        [Parameter(Mandatory = $true)][string]$OpPath,
        [Parameter(Mandatory = $true)][ValidateSet('Validate', 'Stage')][string]$Action,
        [Parameter(Mandatory = $true)][string]$CertificatePath,
        [string]$VmxPath = ''
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
    & $OpPath @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "The bounded 1Password development-CA $Action child failed."
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
#>
function Write-ConnectionSummary {
    param(
        [Parameter(Mandatory = $true)][string]$IpAddress,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][bool]$RootCaTrusted,
        [Parameter(Mandatory = $true)][bool]$SshKeyProvisioned
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
$resolvedOpPath = ''
if ($NoStart) {
    throw '-NoStart is not supported for normal test VMs because first boot must consume and scrub the shared development signing key.'
}
if (-not $WhatIfPreference) {
    $resolvedOpPath = Resolve-OnePasswordCliPath
    Assert-OnePasswordDevelopmentCaBridge `
        -EnvironmentId $OnePasswordEnvironmentId `
        -OpPath $resolvedOpPath
    # The secret child validates the checked-in certificate, CA constraints,
    # expiry, signature, and private-key match before any network or VM mutation.
    Invoke-OnePasswordDevelopmentCaChild `
        -EnvironmentId $OnePasswordEnvironmentId `
        -OpPath $resolvedOpPath `
        -Action Validate `
        -CertificatePath $developmentRootCaCertificatePath
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

$createdThisInvocation = $false
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
        Invoke-OnePasswordDevelopmentCaChild `
            -EnvironmentId $OnePasswordEnvironmentId `
            -OpPath $resolvedOpPath `
            -Action Stage `
            -CertificatePath $developmentRootCaCertificatePath `
            -VmxPath $targetVmx
        $resolvedVmrunPath = Resolve-TestVmVmrunPath -Path $VmrunPath
        & (Join-Path $PSScriptRoot 'start-atlaso-vm.ps1') `
            -VmxPath $targetVmx `
            -VmrunPath $resolvedVmrunPath `
            -Mode gui
        if (-not $?) {
            throw 'Atlaso VMware Workstation VM start failed.'
        }
        Wait-AtlasoWorkstationDevelopmentRootCaPrivateKeyScrub `
            -VmxPath $targetVmx `
            -VmrunPath $resolvedVmrunPath `
            -TimeoutSeconds $TimeoutSeconds
    }
    catch {
        $failure = $_
        if ($createdThisInvocation -and (Test-Path -LiteralPath $targetVmx -PathType Leaf)) {
            try {
                & (Join-Path $PSScriptRoot 'remove-atlaso-vm.ps1') `
                    -VmxPath $targetVmx `
                    -VmrunPath $VmrunPath `
                    -ExpectedName $Name `
                    -Confirm:$false
            }
            catch {
                throw "$($failure.Exception.Message) Automatic rollback also failed; stop the VM and remove only $targetVmx after verifying ownership. Rollback error: $($_.Exception.Message)"
            }
        }
        throw $failure
    }
}

Write-Host "Atlaso Workstation test VM ready: $Name"
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

if (($WaitForIp -or $TrustRootCa) -and -not $WhatIfPreference) {
    $ip = & (Join-Path $PSScriptRoot 'get-atlaso-vm-ip.ps1') `
        -VmxPath $targetVmx `
        -VmrunPath $VmrunPath `
        -TimeoutSeconds $TimeoutSeconds
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
        -SshKeyProvisioned (-not [bool]$SkipSshKeyProvisioning)
}
elseif (-not $WhatIfPreference) {
    Write-Host 'Management wait and development-root verification were explicitly disabled with -WaitForIp:$false.' -ForegroundColor DarkGray
}
