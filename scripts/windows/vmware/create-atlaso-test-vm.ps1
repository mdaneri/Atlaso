<#
.SYNOPSIS
Create or redeploy the normal Atlaso VMware Workstation test appliance.

.DESCRIPTION
Clones the latest or explicitly selected Workstation appliance, attaches the fixed
data disks and requested lab adapters, injects the complete first-boot environment,
and optionally waits for the management address and trusts the appliance root CA.

By default the wrapper validates the current Windows user's existing
.ssh/id_ed25519.pub before any cleanup or VM mutation, then provisions that public
key for the bootstrap administrator with test-only passwordless sudo. It never
creates or reads a private key. Use -SkipSshKeyProvisioning to retain the prior
password-backed development behavior.

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
Leave the cloned VM powered off after preparation.

.PARAMETER SkipNetworkPrepare
Use existing VMware networks without running network preparation.

.PARAMETER WaitForIp
Wait for the started VM management address and print its connection summary.

.PARAMETER TrustRootCa
Wait for and trust the generated appliance root CA for the current Windows user.

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
    [switch]$WaitForIp,
    [switch]$TrustRootCa,
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
Wait for and trust the freshly generated Atlaso root CA.

.PARAMETER IpAddress
The running appliance management IPv4 address.

.PARAMETER Name
The test VM name used for bounded temporary filenames.

.PARAMETER TimeoutSeconds
The total readiness deadline.

.PARAMETER PollSeconds
The delay between transient readiness failures.
#>
function Install-ApplianceRootCa {
    param(
        [Parameter(Mandatory = $true)][string]$IpAddress,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [int]$PollSeconds = 5
    )

    $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    $rootPemPath = [System.IO.Path]::Combine($tempRoot, "atlaso-$Name-root-ca.pem")
    $rootCerPath = [System.IO.Path]::Combine($tempRoot, "atlaso-$Name-root-ca.cer")
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

    $pem = Get-Content -LiteralPath $rootPemPath -Raw
    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($pem)
    if ($certificate.Subject -ne $certificate.Issuer -or $certificate.Subject -notlike '*CN=Atlaso Internal Root CA*') {
        throw "Downloaded certificate is not the expected self-signed Atlaso root CA: $($certificate.Subject)"
    }

    [System.IO.File]::WriteAllBytes(
        $rootCerPath,
        $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    )
    $staleRoots = @(Get-ChildItem Cert:\CurrentUser\Root | Where-Object {
            $_.Subject -like '*CN=Atlaso Internal Root CA*' -and $_.Thumbprint -ne $certificate.Thumbprint
        })
    foreach ($staleRoot in $staleRoots) {
        Write-Host "Removing stale Atlaso root CA from current user: $($staleRoot.Thumbprint)"
        certutil.exe -user -delstore Root $staleRoot.Thumbprint | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to remove stale Atlaso root CA from the current-user Trusted Root store: $($staleRoot.Thumbprint)"
        }
    }
    certutil.exe -f -user -addstore Root $rootCerPath | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to import Atlaso root CA into the current-user Trusted Root store."
    }
    Write-Host "Trusted Atlaso root CA for current user: $($certificate.Thumbprint)"
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
    -DevelopmentAdminSshPublicKey $developmentAdminSshPublicKey

if ($SkipLabNetworkAdapters -and $IncludeLabNetworkAdapters) {
    throw "Pass either -SkipLabNetworkAdapters or -IncludeLabNetworkAdapters, not both."
}
if ($TrustRootCa -and $NoStart) {
    throw "Pass -TrustRootCa only when the VM will be started, because the script must fetch the appliance root CA from the running appliance."
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
}

if (-not $NoStart -and -not $WhatIfPreference) {
    & (Join-Path $PSScriptRoot 'start-atlaso-vm.ps1') `
        -VmxPath $targetVmx `
        -VmrunPath $VmrunPath `
        -Mode gui
    if (-not $?) {
        throw "Atlaso VMware Workstation VM start failed."
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

if (($WaitForIp -or $TrustRootCa) -and -not $NoStart -and -not $WhatIfPreference) {
    $ip = & (Join-Path $PSScriptRoot 'get-atlaso-vm-ip.ps1') `
        -VmxPath $targetVmx `
        -VmrunPath $VmrunPath `
        -TimeoutSeconds $TimeoutSeconds
    if ($WaitForIp) {
        Write-Host "Management IP: $ip"
    }
    if ($TrustRootCa) {
        Install-ApplianceRootCa -IpAddress $ip -Name $Name -TimeoutSeconds $TimeoutSeconds
    }
    Write-ConnectionSummary `
        -IpAddress $ip `
        -Name $Name `
        -VmxPath $targetVmx `
        -RootCaTrusted ([bool]$TrustRootCa) `
        -SshKeyProvisioned (-not [bool]$SkipSshKeyProvisioning)
}
elseif (-not $NoStart -and -not $WhatIfPreference) {
    Write-Host "Pass -WaitForIp to print the HTTPS console, Swagger, root certificate, and SSH connection summary." -ForegroundColor DarkGray
}
