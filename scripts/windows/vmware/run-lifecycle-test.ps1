<#
.SYNOPSIS
Run the VMware Workstation lifecycle interop scenario for Atlaso image regression and backup/restore verification.

.PARAMETER LabName
Lifecycle lab name prefix for created VM artifacts.
.PARAMETER ApplianceVmxPath
Path to the appliance source VMX.
.PARAMETER ClientVmdkPath
Path to the base client VMDK used by generated clients.
.PARAMETER VmrunPath
Optional explicit vmrun.exe path.
.PARAMETER ManagementNetwork
VMnet/LAN segment name for management traffic.
.PARAMETER SiteANetwork
VMnet/LAN segment name for site A traffic.
.PARAMETER SiteBNetwork
VMnet/LAN segment name for site B traffic.
.PARAMETER TrunkNetwork
VMnet/LAN segment name for trunk connectivity.
.PARAMETER ApplianceIPAddress
Optional override for appliance management IPv4.
.PARAMETER ApplianceUrl
Optional override for appliance URL.
.PARAMETER SiteInterface
Interface name used for site routing in workload checks.
.PARAMETER SiteCidr
Site A IPv4 CIDR used in test harness arguments.
.PARAMETER AdminUsername
Atlaso web admin username.
.PARAMETER SecretBundlePath
Path to the current-user DPAPI-protected CLIXML bundle; required unless PlanOnly is set.
.PARAMETER ApplianceSshUser
SSH username for appliance interactions.
.PARAMETER ClientSshUser
SSH username for client guest interactions.
.PARAMETER VlanId
VLAN identifier for WAN scenario traffic.
.PARAMETER TaggedVlanCidr
Tagged VLAN IPv4 CIDR.
.PARAMETER WanCidr
WAN IPv4 CIDR used by workload tests.
.PARAMETER AllowDryRunApply
Permit dry-run apply mode for the Python lifecycle harness.
.PARAMETER SkipBackupRestoreTest
Skip backup/restore validation pass.
.PARAMETER OidcOnly
Run only OIDC scenario path.
.PARAMETER RoutingWanOnly
Run only WAN routing scenario.
.PARAMETER FullEsxiPxeInstall
Include ESXi PXE install scenario.
.PARAMETER PxeInstallerIsoPath
Path to ESXi installer ISO when PXE mode is enabled.
.PARAMETER PxeClientIPAddress
Optional explicit ESXi PXE client address.
.PARAMETER EsxiInstallTimeoutSeconds
Timeout waiting for ESXi installer guest IP.
.PARAMETER EsxiInstallProbeDelaySeconds
Delay before probing PXE-installed guest.
.PARAMETER CleanupCreatedLab
Remove generated lifecycle VM artifacts when complete.
.PARAMETER PlanOnly
Emit and return planning JSON without executing scenarios.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$LabName = 'AtlasoWorkstationLifecycle',
    [Parameter(Mandatory = $true)]
    [string]$ApplianceVmxPath,
    [Parameter(Mandatory = $true)]
    [string]$ClientVmdkPath,
    [string]$VmrunPath = '',
    [string]$ManagementNetwork = 'VMnet8',
    [string]$SiteANetwork = 'VMnet2',
    [string]$SiteBNetwork = 'VMnet3',
    [string]$TrunkNetwork = 'VMnet4',
    [string]$ApplianceIPAddress = '',
    [string]$ApplianceUrl = '',
    [string]$SiteInterface = 'eth1',
    [string]$SiteCidr = '192.168.12.1/24',
    [string]$AdminUsername = 'admin',
    [string]$SecretBundlePath = '',
    [string]$ApplianceSshUser = 'admin',
    [string]$ClientSshUser = 'alpine',
    [int]$VlanId = 50,
    [string]$TaggedVlanCidr = '192.168.60.1/24',
    [string]$WanCidr = '172.31.50.1/24',
    [switch]$AllowDryRunApply,
    [switch]$SkipBackupRestoreTest,
    [switch]$OidcOnly,
    [switch]$RoutingWanOnly,
    [switch]$FullEsxiPxeInstall,
    [string]$PxeInstallerIsoPath = '',
    [string]$PxeClientIPAddress = '',
    [int]$EsxiInstallTimeoutSeconds = 3600,
    [int]$EsxiInstallProbeDelaySeconds = 300,
    [switch]$CleanupCreatedLab,
    [switch]$PlanOnly
)

$ErrorActionPreference = 'Stop'

# Plan-only execution consumes no credentials. Runtime execution imports the
# current-user-protected bundle before VMware or the harness needs plaintext.
$adminPasswordSecure = $null
$sshPasswordSecure = $null
$vcfBackupPasswordSecure = $null
$esxiPasswordSecure = $null
$AdminPassword = ''
$SshPassword = ''
$VcfBackupPassword = ''
if (-not $PlanOnly) {
    if ([string]::IsNullOrWhiteSpace($SecretBundlePath)) {
        throw 'SecretBundlePath is required unless PlanOnly is set.'
    }
    $secretBundle = Import-Clixml -LiteralPath $SecretBundlePath
    foreach ($propertyName in @('AdminPassword', 'SshPassword')) {
        if ($secretBundle.$propertyName -isnot [SecureString]) {
            throw "Lifecycle secret bundle property is missing or invalid: $propertyName"
        }
    }
    $focusedRun = $OidcOnly -or $RoutingWanOnly
    if (-not $focusedRun -and $secretBundle.VcfBackupPassword -isnot [SecureString]) {
        throw 'Lifecycle secret bundle property is missing or invalid: VcfBackupPassword'
    }
    if ($focusedRun -and $null -ne $secretBundle.VcfBackupPassword -and $secretBundle.VcfBackupPassword -isnot [SecureString]) {
        throw 'Lifecycle secret bundle property is invalid: VcfBackupPassword'
    }
    if ($FullEsxiPxeInstall -and $secretBundle.EsxiPassword -isnot [SecureString]) {
        throw 'Lifecycle secret bundle property is missing or invalid: EsxiPassword'
    }
    $adminPasswordSecure = $secretBundle.AdminPassword
    $sshPasswordSecure = $secretBundle.SshPassword
    $vcfBackupPasswordSecure = $secretBundle.VcfBackupPassword
    $esxiPasswordSecure = $secretBundle.EsxiPassword
    $AdminPassword = ConvertFrom-SecureString -SecureString $adminPasswordSecure -AsPlainText
    $SshPassword = ConvertFrom-SecureString -SecureString $sshPasswordSecure -AsPlainText
    if ($null -ne $vcfBackupPasswordSecure) {
        $VcfBackupPassword = ConvertFrom-SecureString -SecureString $vcfBackupPasswordSecure -AsPlainText
    }
}
. (Join-Path $PSScriptRoot 'Atlaso.WorkstationFirstBoot.ps1')
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationCleanup.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Atlaso.VmwarePayload.psm1') -Force

$repoRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')
if (-not $SshPassword) {
    $SshPassword = $AdminPassword
}
$ApplianceGuestPassword = $AdminPassword
if ($RoutingWanOnly) {
    $SkipBackupRestoreTest = $true
}
if ($OidcOnly) {
    $SkipBackupRestoreTest = $true
}

<#
.SYNOPSIS
Run the Python lifecycle consumer with a secret envelope supplied through standard input.

.PARAMETER Arguments
Literal Python arguments that contain no lifecycle passwords.

.PARAMETER AdminPassword
Protected Atlaso administrator password written only to the child process standard-input stream.

.PARAMETER SshPassword
Protected client SSH password written only to the child process standard-input stream.

.PARAMETER VcfBackupPassword
Optional protected VCF Backup password written only to the child process standard-input stream.

.PARAMETER EsxiPassword
Optional protected ESXi password written only to the child process standard-input stream.
#>
function Invoke-LifecyclePython {
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][SecureString]$AdminPassword,
        [Parameter(Mandatory = $true)][SecureString]$SshPassword,
        [SecureString]$VcfBackupPassword,
        [SecureString]$EsxiPassword
    )

    $adminPasswordText = ''
    $sshPasswordText = ''
    $vcfBackupPasswordText = ''
    $esxiPasswordText = ''
    $secretPayload = ''
    try {
        $adminPasswordText = ConvertFrom-SecureString -SecureString $AdminPassword -AsPlainText
        $sshPasswordText = ConvertFrom-SecureString -SecureString $SshPassword -AsPlainText
        if ($null -ne $VcfBackupPassword) {
            $vcfBackupPasswordText = ConvertFrom-SecureString -SecureString $VcfBackupPassword -AsPlainText
        }
        if ($null -ne $EsxiPassword) {
            $esxiPasswordText = ConvertFrom-SecureString -SecureString $EsxiPassword -AsPlainText
        }
        # One compressed JSON line keeps every lifecycle credential out of the
        # child command line without creating another plaintext file boundary.
        $secretPayload = [pscustomobject]@{
            password               = $adminPasswordText
            appliance_ssh_password = $adminPasswordText
            ssh_password           = $sshPasswordText
            vcf_backup_password    = $vcfBackupPasswordText
            esxi_password          = $esxiPasswordText
        } | ConvertTo-Json -Compress
        # Keep the child's progress output visible without adding it to this
        # function's success stream, which is reserved for the exit code.
        $secretPayload | & python @Arguments | Out-Host
        return $LASTEXITCODE
    }
    finally {
        $adminPasswordText = $null
        $sshPasswordText = $null
        $vcfBackupPasswordText = $null
        $esxiPasswordText = $null
        $secretPayload = $null
    }
}

$resultStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$resultRoot = Join-Path $repoRoot "test-results\vmware-workstation-lifecycle\$resultStamp"
$vmRoot = Join-Path $resultRoot 'vms'
$seedRoot = Join-Path $resultRoot 'seed'
$createdVmxPaths = New-Object System.Collections.Generic.List[string]

<#
.SYNOPSIS
Resolve the vmrun path from a user override or common install locations.

.PARAMETER VmrunPath
Optional vmrun.exe path or install directory.
#>

function Resolve-VmrunPath {
    if ($VmrunPath) {
        if (-not (Test-Path -LiteralPath $VmrunPath)) {
            throw "vmrun.exe not found: $VmrunPath"
        }
        return (Resolve-Path -LiteralPath $VmrunPath).Path
    }
    foreach ($candidate in @(
        'C:\Program Files\VMware\VMware Workstation\vmrun.exe',
        'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
    )) {
        if (Test-Path -LiteralPath $candidate) {
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
Resolve vmware-vdiskmanager from supported installation locations.
#>
function Resolve-VdiskManagerPath {
    $vmrunDirectory = Split-Path -Parent $resolvedVmrun
    $candidate = Join-Path $vmrunDirectory 'vmware-vdiskmanager.exe'
    if (Test-Path -LiteralPath $candidate) {
        return $candidate
    }
    foreach ($path in @(
        'C:\Program Files\VMware\VMware Workstation\vmware-vdiskmanager.exe',
        'C:\Program Files (x86)\VMware\VMware Workstation\vmware-vdiskmanager.exe'
    )) {
        if (Test-Path -LiteralPath $path) {
            return $path
        }
    }
    $command = Get-Command vmware-vdiskmanager -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    throw 'vmware-vdiskmanager.exe was not found. It is required for -FullEsxiPxeInstall.'
}

<#
.SYNOPSIS
Reject reserved VM names to avoid clobbering protected environments.

.PARAMETER Name
VM name to validate.
#>
function Assert-SafeLifecycleName {
    param([string]$Name)

    $reserved = @('Atlaso', 'Atlaso-Photon-Builder', 'Atlaso-Photon-Builder-VMware')
    if ($reserved -contains $Name) {
        throw "Refusing to use reserved VM name '$Name'. Lifecycle tests must use a separate VM set."
    }
    if (-not $Name.StartsWith($LabName)) {
        throw "Refusing VM name '$Name' because it does not start with lifecycle lab prefix '$LabName'."
    }
}

<#
.SYNOPSIS
Escape a value for single-quoted shell expansion.

.PARAMETER Value
String value to escape.
#>
function ConvertTo-GuestShellSingleQuote {
    param([string]$Value)
    return "'" + ($Value -replace "'", "'\''") + "'"
}

<#
.SYNOPSIS
Escape an argument for native command execution.

.PARAMETER Value
Input string to escape.
#>
function ConvertTo-NativeArgument {
    param([string]$Value)

    if ($null -eq $Value) {
        return '""'
    }
    if ($Value -notmatch '[\s"]') {
        return $Value
    }
    return '"' + ($Value -replace '"', '\"') + '"'
}

<#
.SYNOPSIS
Run vmrun through .NET process execution with bounded timeout.

.PARAMETER Arguments
Argument list for vmrun.
.PARAMETER TimeoutSeconds
Bounded timeout in seconds.
#>
function Invoke-VmrunBounded {
    param(
        [string[]]$Arguments,
        [int]$TimeoutSeconds = 30
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $resolvedVmrun
    $startInfo.Arguments = ($Arguments | ForEach-Object { ConvertTo-NativeArgument -Value $_ }) -join ' '
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    [void]$process.Start()
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        try {
            $process.Kill()
        } catch {
            Write-Verbose "Could not terminate timed-out vmrun process: $($_.Exception.Message)"
        }
        return [pscustomobject]@{
            ExitCode = -1
            TimedOut = $true
            StdOut   = ''
            StdErr   = "vmrun timed out after $TimeoutSeconds seconds: $($Arguments -join ' ')"
        }
    }
    return [pscustomobject]@{
        ExitCode = $process.ExitCode
        TimedOut = $false
        StdOut   = $process.StandardOutput.ReadToEnd()
        StdErr   = $process.StandardError.ReadToEnd()
    }
}

<#
.SYNOPSIS
Generate a randomized static MAC in VMware OUI space.
#>

function New-StaticVmwareMac {
    $bytes = [guid]::NewGuid().ToByteArray()
    return ('00:50:56:{0:x2}:{1:x2}:{2:x2}' -f (0x20 -bor ($bytes[0] -band 0x1f)), $bytes[1], $bytes[2])
}

<#
.SYNOPSIS
Escape a literal value for a VMX assignment.
.PARAMETER Value
Unquoted VMX property text to escape and quote.
#>
function ConvertTo-VmxString {
    param([string]$Value)
    return '"' + ($Value -replace '\\', '\\' -replace '"', '\"') + '"'
}

<#
.SYNOPSIS
Set one VMX key while preserving unrelated configuration.
.PARAMETER Path
VMX file whose exact key assignment is updated.
.PARAMETER Key
VMX property name to replace or append.
.PARAMETER Value
Unquoted VMX property value to serialize.
#>
function Set-VmxValue {
    param(
        [string]$Path,
        [string]$Key,
        [string]$Value
    )

    $line = "$Key = $(ConvertTo-VmxString -Value $Value)"
    $content = if (Test-Path -LiteralPath $Path) {
        @(Get-Content -LiteralPath $Path)
    } else {
        @()
    }
    $pattern = '^\s*' + [regex]::Escape($Key) + '\s*='
    $updated = $false
    $content = @($content | ForEach-Object {
        if ($_ -match $pattern) {
            $updated = $true
            $line
        } else {
            $_
        }
    })
    if (-not $updated) {
        $content += $line
    }
    [System.IO.File]::WriteAllLines($Path, [string[]]$content, [System.Text.UTF8Encoding]::new($false))
}

<#
.SYNOPSIS
Remove a VMX setting key from a VMX file.

.PARAMETER Path
Path to VMX file.
.PARAMETER Key
VMX key name to remove.
#>
function Remove-VmxValue {
    param(
        [string]$Path,
        [string]$Key
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $pattern = '^\s*' + [regex]::Escape($Key) + '\s*='
    $content = @(Get-Content -LiteralPath $Path | Where-Object { $_ -notmatch $pattern })
    [System.IO.File]::WriteAllLines($Path, [string[]]$content, [System.Text.UTF8Encoding]::new($false))
}

<#
.SYNOPSIS
Create deterministic SCSI-compatible IDs for LAN segments.

.PARAMETER Name
Segment name used as input entropy.
#>
function New-LanSegmentId {
    param([string]$Name)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("AtlasoWorkstationLifecycle:$Name"))
    } finally {
        $sha.Dispose()
    }
    $idBytes = [byte[]]$bytes[0..15]
    $idBytes[0] = 0x52
    $first = (($idBytes[0..7] | ForEach-Object { $_.ToString('x2') }) -join ' ')
    $second = (($idBytes[8..15] | ForEach-Object { $_.ToString('x2') }) -join ' ')
    return "$first-$second"
}

<#
.SYNOPSIS
Resolve or create a VMware LAN segment ID for a named segment.

.PARAMETER Name
LAN segment name to resolve.
#>
function Resolve-LanSegmentId {
    param([string]$Name)

    $preferenceDirectory = Join-Path $env:APPDATA 'VMware'
    $preferencePath = Join-Path $preferenceDirectory 'preferences.ini'
    if (-not (Test-Path -LiteralPath $preferenceDirectory)) {
        New-Item -ItemType Directory -Force -Path $preferenceDirectory | Out-Null
    }
    $content = if (Test-Path -LiteralPath $preferencePath) {
        @(Get-Content -LiteralPath $preferencePath)
    } else {
        @()
    }

    $segments = @{}
    for ($index = 0; $index -lt $content.Count; $index++) {
        if ($content[$index] -match '^pref\.namedPVNs(?<id>\d+)\.name\s*=\s*"(?<name>.*)"\s*$') {
            $entry = [int]$matches.id
            if (-not $segments.ContainsKey($entry)) {
                $segments[$entry] = @{}
            }
            $segments[$entry].Name = $matches.name
        } elseif ($content[$index] -match '^pref\.namedPVNs(?<id>\d+)\.pvnID\s*=\s*"(?<pvn>.*)"\s*$') {
            $entry = [int]$matches.id
            if (-not $segments.ContainsKey($entry)) {
                $segments[$entry] = @{}
            }
            $segments[$entry].PvnId = $matches.pvn
        }
    }

    $requiredCount = 0
    if ($segments.Count -gt 0) {
        $requiredCount = (($segments.Keys | Measure-Object -Maximum).Maximum + 1)
    }

    $countUpdated = $false
    $countChanged = $false
    $content = @($content | ForEach-Object {
        if ($_ -match '^pref\.namedPVNs\.count\s*=') {
            $countUpdated = $true
            $desiredLine = "pref.namedPVNs.count = $(ConvertTo-VmxString -Value ([string]$requiredCount))"
            if ($_ -ne $desiredLine) {
                $countChanged = $true
                $desiredLine
            } else {
                $_
            }
        } else {
            $_
        }
    })
    if (-not $countUpdated -and $requiredCount -gt 0) {
        $content += "pref.namedPVNs.count = $(ConvertTo-VmxString -Value ([string]$requiredCount))"
        $countChanged = $true
    }
    if ($countChanged) {
        [System.IO.File]::WriteAllLines($preferencePath, [string[]]$content, [System.Text.UTF8Encoding]::new($false))
    }

    foreach ($entry in $segments.GetEnumerator()) {
        if ($entry.Value.Name -eq $Name -and $entry.Value.PvnId) {
            if ($entry.Value.PvnId -notmatch '^52 ') {
                $pvnId = New-LanSegmentId -Name $Name
                $content = @($content | ForEach-Object {
                    if ($_ -match "^pref\.namedPVNs$($entry.Key)\.pvnID\s*=") {
                        "pref.namedPVNs$($entry.Key).pvnID = $(ConvertTo-VmxString -Value $pvnId)"
                    } else {
                        $_
                    }
                })
                [System.IO.File]::WriteAllLines($preferencePath, [string[]]$content, [System.Text.UTF8Encoding]::new($false))
                return $pvnId
            }
            return $entry.Value.PvnId
        }
    }

    $nextIndex = $requiredCount
    $pvnId = New-LanSegmentId -Name $Name
    $content += "pref.namedPVNs$nextIndex.name = $(ConvertTo-VmxString -Value $Name)"
    $content += "pref.namedPVNs$nextIndex.pvnID = $(ConvertTo-VmxString -Value $pvnId)"
    $content = @($content | ForEach-Object {
        if ($_ -match '^pref\.namedPVNs\.count\s*=') {
            "pref.namedPVNs.count = $(ConvertTo-VmxString -Value ([string]($nextIndex + 1)))"
        } else {
            $_
        }
    })
    if (-not ($content | Where-Object { $_ -match '^pref\.namedPVNs\.count\s*=' })) {
        $content += "pref.namedPVNs.count = $(ConvertTo-VmxString -Value ([string]($nextIndex + 1)))"
    }
    [System.IO.File]::WriteAllLines($preferencePath, [string[]]$content, [System.Text.UTF8Encoding]::new($false))
    return $pvnId
}

<#
.SYNOPSIS
Apply a VMX ethernet adapter configuration.

.PARAMETER Path
VMX path to mutate.
.PARAMETER Index
Ethernet adapter index.
.PARAMETER Vmnet
VMnet or lan-segment reference.
.PARAMETER StaticMac
Optional static MAC address.
.PARAMETER VirtualDev
VMXNET device type.
#>
function Set-VmxNetworkAdapter {
    param(
        [string]$Path,
        [int]$Index,
        [string]$Vmnet,
        [string]$StaticMac = '',
        [string]$VirtualDev = 'vmxnet3'
    )

    $prefix = "ethernet$Index"
    if ($Vmnet -match '^(?i)vmnet(\d+)$') {
        $Vmnet = "VMnet$($Matches[1])"
    }
    Set-VmxValue -Path $Path -Key "$prefix.present" -Value 'TRUE'
    if ($Vmnet.StartsWith('lan:')) {
        $segmentName = $Vmnet.Substring(4)
        $pvnId = Resolve-LanSegmentId -Name $segmentName
        Set-VmxValue -Path $Path -Key "$prefix.connectionType" -Value 'pvn'
        Set-VmxValue -Path $Path -Key "$prefix.pvnID" -Value $pvnId
        Remove-VmxValue -Path $Path -Key "$prefix.vnet"
    } else {
        Set-VmxValue -Path $Path -Key "$prefix.connectionType" -Value 'custom'
        Set-VmxValue -Path $Path -Key "$prefix.vnet" -Value $Vmnet
        Remove-VmxValue -Path $Path -Key "$prefix.pvnID"
    }
    Set-VmxValue -Path $Path -Key "$prefix.virtualDev" -Value $VirtualDev
    if ($StaticMac) {
        Set-VmxValue -Path $Path -Key "$prefix.addressType" -Value 'static'
        Set-VmxValue -Path $Path -Key "$prefix.address" -Value $StaticMac
    }
    Set-VmxValue -Path $Path -Key "$prefix.startConnected" -Value 'TRUE'
}

<#
.SYNOPSIS
Copy a source VMX into a managed lifecycle lab directory.

.PARAMETER SourceVmx
Source VMX path.
.PARAMETER DestinationDirectory
Destination directory for the copied appliance.
.PARAMETER Name
Lifecycle VM name.
#>
function Copy-VmDirectory {
    param(
        [string]$SourceVmx,
        [string]$DestinationDirectory,
        [string]$Name
    )

    Assert-SafeLifecycleName -Name $Name
    $resolvedSourceVmx = (Resolve-Path -LiteralPath $SourceVmx).Path
    Assert-AtlasoVmwarePayloadProvenance -VmxPath $resolvedSourceVmx | Out-Null
    if (Test-Path -LiteralPath $DestinationDirectory) {
        throw "Lifecycle VM directory already exists: $DestinationDirectory"
    }
    $sourceDirectory = Split-Path -Parent $resolvedSourceVmx
    if ($PSCmdlet.ShouldProcess($DestinationDirectory, "Copy Workstation VM $Name")) {
        Copy-Item -LiteralPath $sourceDirectory -Destination $DestinationDirectory -Recurse
    }
    $vmx = Get-ChildItem -LiteralPath $DestinationDirectory -Filter '*.vmx' | Select-Object -First 1
    if (-not $vmx) {
        throw "Copied Workstation VM has no VMX: $DestinationDirectory"
    }
    $targetVmx = Join-Path $DestinationDirectory "$Name.vmx"
    Rename-Item -LiteralPath $vmx.FullName -NewName "$Name.vmx"
    Set-VmxValue -Path $targetVmx -Key 'displayName' -Value $Name
    Get-AtlasoVmwarePayloadLayout -VmxPath $targetVmx -RequireExactlyTwoVmdks | Out-Null
    $createdVmxPaths.Add($targetVmx)
    return $targetVmx
}

<#
.SYNOPSIS
Create a new client VM from a base VMDK and seed ISO.

.PARAMETER Name
Client VM name.
.PARAMETER Directory
Destination VM directory.
.PARAMETER DiskPath
Base client VMDK path.
.PARAMETER SeedIso
NoCloud seed ISO path.
.PARAMETER Networks
VM adapter target networks by index.
#>
function New-ClientVm {
    param(
        [string]$Name,
        [string]$Directory,
        [string]$DiskPath,
        [string]$SeedIso,
        [string[]]$Networks
    )

    Assert-SafeLifecycleName -Name $Name
    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    $diskTarget = Join-Path $Directory "$Name.vmdk"
    if ($PSCmdlet.ShouldProcess($diskTarget, "Copy client VMDK for $Name")) {
        Copy-Item -LiteralPath $DiskPath -Destination $diskTarget
    }
    $vmxPath = Join-Path $Directory "$Name.vmx"
    $lines = @(
        '.encoding = "windows-1252"',
        'config.version = "8"',
        'virtualHW.version = "21"',
        'firmware = "efi"',
        'uefi.secureBoot.enabled = "FALSE"',
        "displayName = $(ConvertTo-VmxString -Value $Name)",
        'guestOS = "other5xlinux-64"',
        'memsize = "1024"',
        'numvcpus = "1"',
        'sata0.present = "TRUE"',
        'sata0:0.present = "TRUE"',
        "sata0:0.fileName = $(ConvertTo-VmxString -Value (Split-Path -Leaf $diskTarget))",
        'sata0:0.deviceType = "disk"',
        'sata0:1.present = "TRUE"',
        "sata0:1.fileName = $(ConvertTo-VmxString -Value $SeedIso)",
        'sata0:1.deviceType = "cdrom-image"',
        'sata0:1.startConnected = "TRUE"'
    )
    [System.IO.File]::WriteAllLines($vmxPath, [string[]]$lines, [System.Text.UTF8Encoding]::new($false))
    for ($index = 0; $index -lt $Networks.Count; $index++) {
        Set-VmxNetworkAdapter -Path $vmxPath -Index $index -Vmnet $Networks[$index] -VirtualDev 'e1000'
    }
    $createdVmxPaths.Add($vmxPath)
    return $vmxPath
}

<#
.SYNOPSIS
Create a temporary ESXi PXE install VM for extended lifecycle coverage.

.PARAMETER Name
ESXi VM name.
.PARAMETER Directory
VM directory.
.PARAMETER Network
Initial network attachment.
.PARAMETER MacAddress
Optional static MAC address.
#>
function New-EsxiPxeVm {
    param(
        [string]$Name,
        [string]$Directory,
        [string]$Network,
        [string]$MacAddress
    )

    Assert-SafeLifecycleName -Name $Name
    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
    $diskTarget = Join-Path $Directory "$Name.vmdk"
    $vdiskManager = Resolve-VdiskManagerPath
    if ($PSCmdlet.ShouldProcess($diskTarget, "Create ESXi PXE install disk for $Name")) {
        & $vdiskManager -c -s 32GB -a pvscsi -t 0 $diskTarget | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create ESXi PXE install disk with vmware-vdiskmanager."
        }
    }
    $vmxPath = Join-Path $Directory "$Name.vmx"
    $lines = @(
        '.encoding = "windows-1252"',
        'config.version = "8"',
        'virtualHW.version = "22"',
        'pciBridge0.present = "TRUE"',
        'pciBridge4.present = "TRUE"',
        'pciBridge4.virtualDev = "pcieRootPort"',
        'pciBridge4.functions = "8"',
        'pciBridge5.present = "TRUE"',
        'pciBridge5.virtualDev = "pcieRootPort"',
        'pciBridge5.functions = "8"',
        'pciBridge6.present = "TRUE"',
        'pciBridge6.virtualDev = "pcieRootPort"',
        'pciBridge6.functions = "8"',
        'pciBridge7.present = "TRUE"',
        'pciBridge7.virtualDev = "pcieRootPort"',
        'pciBridge7.functions = "8"',
        'vmci0.present = "TRUE"',
        'virtualHW.productCompatibility = "hosted"',
        'firmware = "efi"',
        'uefi.secureBoot.enabled = "FALSE"',
        "displayName = $(ConvertTo-VmxString -Value $Name)",
        'guestOS = "vmkernel9"',
        'memsize = "8192"',
        'numvcpus = "4"',
        'vhv.enable = "FALSE"',
        'tools.syncTime = "FALSE"',
        'floppy0.present = "FALSE"',
        'scsi0.present = "TRUE"',
        'scsi0.virtualDev = "pvscsi"',
        'scsi0:0.present = "TRUE"',
        "scsi0:0.fileName = $(ConvertTo-VmxString -Value (Split-Path -Leaf $diskTarget))"
    )
    [System.IO.File]::WriteAllLines($vmxPath, [string[]]$lines, [System.Text.UTF8Encoding]::new($false))
    Set-VmxNetworkAdapter -Path $vmxPath -Index 0 -Vmnet $Network -StaticMac $MacAddress -VirtualDev 'vmxnet3'
    $createdVmxPaths.Add($vmxPath)
    return $vmxPath
}

<#
.SYNOPSIS
Create a NoCloud seed ISO for a client VM.

.PARAMETER Path
Seed ISO output path.
.PARAMETER HostName
Client hostname for cloud-init metadata.
#>
function New-CloudInitSeedIso {
    param(
        [string]$Path,
        [string]$HostName
    )

    if ($PSCmdlet.ShouldProcess($Path, "Create NoCloud seed disk for $HostName")) {
        python -c 'import pycdlib' 2>$null
        if ($LASTEXITCODE -ne 0) {
            python -m pip install pycdlib
        }
        $helper = Join-Path $repoRoot 'scripts\interop\create_nocloud_seed_iso.py'
        # The repository-controlled seed helper reads one password line from
        # stdin so the client credential never appears in process arguments.
        $SshPassword | & python $helper --output $Path --hostname $HostName --user $ClientSshUser --password-stdin | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create NoCloud seed ISO for $HostName"
        }
    }
}

<#
.SYNOPSIS
Invoke vmrun with fail-fast behavior.

.PARAMETER Arguments
vmrun arguments.
#>
function Invoke-Vmrun {
    param([string[]]$Arguments)
    & $resolvedVmrun @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "vmrun $($Arguments -join ' ') failed with exit code $LASTEXITCODE."
    }
}

<#
.SYNOPSIS
Register a Workstation VM if possible.

.PARAMETER Path
VMX path to register.
#>
function Register-WorkstationVm {
    param([string]$Path)
    if ($PSCmdlet.ShouldProcess($Path, 'Register Workstation VM')) {
        & $resolvedVmrun -T ws register $Path 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Verbose "Workstation VM may already be registered: $Path"
        }
    }
}

<#
.SYNOPSIS
Start a Workstation VM with bounded registration workflow.

.PARAMETER Path
VMX path to start.
#>
function Start-WorkstationVm {
    param([string]$Path)
    if ($PSCmdlet.ShouldProcess($Path, 'Start Workstation VM')) {
        Register-WorkstationVm -Path $Path
        Invoke-Vmrun -Arguments @('-T', 'ws', 'start', $Path, 'nogui')
    }
}

<#
.SYNOPSIS
Report whether an exact VMware Workstation VMX is running.

.PARAMETER Path
VMX path whose running state is queried.
#>
function Test-WorkstationVmRunning {
    param([string]$Path)

    $listResult = Invoke-VmrunBounded -Arguments @('-T', 'ws', 'list') -TimeoutSeconds 15
    if ($listResult.ExitCode -ne 0) {
        throw "Failed to list running VMware Workstation VMs before seed cleanup: $($listResult.StdErr)"
    }
    $targetPath = [System.IO.Path]::GetFullPath($Path)
    foreach ($line in @($listResult.StdOut -split "`r?`n")) {
        $candidate = $line.Trim()
        if (-not $candidate -or $candidate -match '^Total running VMs:') {
            continue
        }
        try {
            $candidatePath = [System.IO.Path]::GetFullPath($candidate)
        } catch {
            continue
        }
        if ([string]::Equals($candidatePath, $targetPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }
    return $false
}

<#
.SYNOPSIS
Stop one running client VM before detaching its credential-bearing seed.

.PARAMETER Path
Client VMX path to stop.
#>
function Stop-WorkstationVmForSeedCleanup {
    [OutputType([bool])]
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf) -or -not (Test-WorkstationVmRunning -Path $Path)) {
        return $false
    }
    [void](Invoke-VmrunBounded -Arguments @('-T', 'ws', 'stop', $Path, 'soft') -TimeoutSeconds 45)
    if (Test-WorkstationVmRunning -Path $Path) {
        [void](Invoke-VmrunBounded -Arguments @('-T', 'ws', 'stop', $Path, 'hard') -TimeoutSeconds 30)
    }
    if (Test-WorkstationVmRunning -Path $Path) {
        throw "Client VM remained running during credential-bearing seed cleanup: $Path"
    }
    return $true
}

<#
.SYNOPSIS
Detach and delete credential-bearing client seed ISOs with absence verification.

.PARAMETER VmxPaths
Client VMX paths that may reference the seed ISOs.

.PARAMETER SeedPaths
Exact seed ISO paths to delete.

.PARAMETER Restart
Restart client VMs that were running after all seeds are verifiably absent.
#>
function Remove-ClientSeedArtifacts {
    param(
        [string[]]$VmxPaths,
        [string[]]$SeedPaths,
        [switch]$Restart
    )

    $restartPaths = New-Object System.Collections.Generic.List[string]
    foreach ($vmxPath in @($VmxPaths | Where-Object { $_ })) {
        if (Stop-WorkstationVmForSeedCleanup -Path $vmxPath) {
            $restartPaths.Add($vmxPath)
        }
        if (Test-Path -LiteralPath $vmxPath -PathType Leaf) {
            # A stopped VM cannot retain an open seed handle. Detach before
            # deletion so a later restart cannot reacquire the secret artifact.
            Set-VmxValue -Path $vmxPath -Key 'sata0:1.present' -Value 'FALSE'
            foreach ($key in @('sata0:1.fileName', 'sata0:1.deviceType', 'sata0:1.startConnected')) {
                Remove-VmxValue -Path $vmxPath -Key $key
            }
        }
    }
    foreach ($seedPath in @($SeedPaths | Where-Object { $_ })) {
        if (Test-Path -LiteralPath $seedPath) {
            if ($PSCmdlet.ShouldProcess($seedPath, 'Delete credential-bearing client seed ISO')) {
                Remove-Item -LiteralPath $seedPath -Force -ErrorAction Stop
            }
        }
        if (Test-Path -LiteralPath $seedPath) {
            throw "Credential-bearing client seed ISO remains after cleanup: $seedPath"
        }
    }
    if ($Restart) {
        foreach ($vmxPath in $restartPaths) {
            $startParameters = @{ Path = $vmxPath }
            Start-WorkstationVm @startParameters
        }
    }
}

function Test-TcpPort {
<#
.SYNOPSIS
Check host/port reachability with bounded timeout.

.PARAMETER HostName
Target host.
.PARAMETER Port
Target TCP port.
.PARAMETER TimeoutMilliseconds
Connection timeout in milliseconds.
#>
    param(
        [string]$HostName,
        [int]$Port,
        [int]$TimeoutMilliseconds = 1000
    )

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $async = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMilliseconds)) {
            return $false
        }
        $client.EndConnect($async)
        return $true
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

<#
.SYNOPSIS
Read host SSH key fingerprint text via plink probe.

.PARAMETER HostName
SSH host to probe.
.PARAMETER UserName
SSH username.
.PARAMETER Password
SSH password.
#>
function Get-PlinkHostKey {
    param(
        [string]$HostName,
        [string]$UserName,
        [SecureString]$Password
    )

    if (-not $HostName -or -not $Password -or -not (Get-Command plink -ErrorAction SilentlyContinue)) {
        return ''
    }

    $passwordText = ConvertFrom-SecureString -SecureString $Password -AsPlainText

    $deadline = (Get-Date).AddMinutes(4)
    while ((Get-Date) -lt $deadline) {
        if (-not (Test-TcpPort -HostName $HostName -Port 22 -TimeoutMilliseconds 1000)) {
            Start-Sleep -Seconds 5
            continue
        }

        $previousErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $output = & plink -batch -ssh -pw $passwordText "$UserName@$HostName" 'hostname' 2>&1
            $exitCode = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
        $text = ($output | Out-String)
        if ($text -match '(ssh-[A-Za-z0-9-]+\s+\d+\s+SHA256:[A-Za-z0-9+/=]+)') {
            $hostKey = $Matches[1]
            $passwordText = $null
            return $hostKey
        }
        if ($exitCode -eq 0) {
            $passwordText = $null
            return ''
        }
        Start-Sleep -Seconds 5
    }
    $passwordText = $null
    Write-Warning "Timed out waiting for SSH host key from $UserName@$HostName; continuing without host key pinning."
    return ''
}

<#
.SYNOPSIS
Parse IPv4 addresses from text lines.

.PARAMETER Lines
Text lines to scan.
#>
function Get-GuestIPv4FromAddressText {
    param([string[]]$Lines)

    foreach ($line in $Lines) {
        foreach ($match in [regex]::Matches($line, '(?<ip>(?:\d{1,3}\.){3}\d{1,3})/\d+')) {
            $ip = $match.Groups['ip'].Value
            if ($ip -notlike '127.*' -and $ip -notlike '169.254.*') {
                return $ip
            }
        }
        if ($line -match '^\s*(?<ip>(?:\d{1,3}\.){3}\d{1,3})\s*$') {
            $ip = $Matches['ip']
            if ($ip -notlike '127.*' -and $ip -notlike '169.254.*') {
                return $ip
            }
        }
    }
    return ''
}

<#
.SYNOPSIS
Normalize MAC addresses to hyphen format.

.PARAMETER MacAddress
MAC address input.
#>
function ConvertTo-HyphenMac {
    param([string]$MacAddress)

    return ($MacAddress -replace '[^0-9A-Fa-f]', '').ToLowerInvariant() -replace '(.{2})(?!$)', '$1-'
}

<#
.SYNOPSIS
Read a VMX ethernet MAC address by adapter index.

.PARAMETER Path
VMX path.
.PARAMETER Index
Ethernet adapter index.
#>
function Get-VmxEthernetMacAddress {
    param(
        [string]$Path,
        [int]$Index = 0
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return ''
    }
    $content = Get-Content -LiteralPath $Path
    $prefix = "ethernet$Index"
    foreach ($key in @('address', 'generatedAddress')) {
        $pattern = '^\s*' + [regex]::Escape("$prefix.$key") + '\s*=\s*"(?<value>[^"]+)"\s*$'
        $line = $content | Where-Object { $_ -match $pattern } | Select-Object -First 1
        if ($line -and $line -match $pattern) {
            return ConvertTo-HyphenMac -MacAddress $Matches['value']
        }
    }
    return ''
}

<#
.SYNOPSIS
Resolve a guest IPv4 address from neighbor cache by MAC.

.PARAMETER Path
VMX path.
.PARAMETER Index
Ethernet adapter index.
#>
function Get-GuestIPv4FromHostNeighbor {
    param(
        [string]$Path,
        [int]$Index = 0
    )

    $mac = Get-VmxEthernetMacAddress -Path $Path -Index $Index
    if (-not $mac) {
        return ''
    }
    try {
        $neighbors = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop
    } catch {
        return ''
    }
    foreach ($neighbor in $neighbors) {
        if (($neighbor.LinkLayerAddress -as [string]).ToLowerInvariant() -ne $mac) {
            continue
        }
        $ip = $neighbor.IPAddress -as [string]
        if ($ip -and $ip -notlike '127.*' -and $ip -notlike '169.254.*') {
            return $ip
        }
    }
    return ''
}

<#
.SYNOPSIS
Resolve guest IPv4 using VMware guest operations.

.PARAMETER Path
VMX path.
.PARAMETER GuestUser
Guest username.
.PARAMETER GuestPassword
Guest password.
.PARAMETER Name
VM-friendly name for temporary host output names.
#>
function Get-GuestIPv4ViaGuestOps {
    param(
        [string]$Path,
        [string]$GuestUser,
        [SecureString]$GuestPassword,
        [string]$Name
    )

    if (-not $GuestUser -or -not $GuestPassword) {
        return ''
    }
    $guestPasswordText = ConvertFrom-SecureString -SecureString $GuestPassword -AsPlainText
    $safeName = ($Name -replace '[^A-Za-z0-9_.-]', '-')
    $guestOutput = "/tmp/atlaso-ipv4-$safeName.txt"
    $hostOutput = Join-Path $resultRoot "guest-ipv4-$safeName.txt"
    $script = "ip -4 -br addr > $guestOutput 2>/dev/null || /sbin/ip -4 -br addr > $guestOutput 2>/dev/null || ifconfig > $guestOutput 2>/dev/null"
    $runResult = Invoke-VmrunBounded -Arguments @('-T', 'ws', '-gu', $GuestUser, '-gp', $guestPasswordText, 'runScriptInGuest', $Path, '/bin/sh', $script) -TimeoutSeconds 15
    if ($runResult.ExitCode -ne 0) {
        $guestPasswordText = $null
        return ''
    }
    $copyResult = Invoke-VmrunBounded -Arguments @('-T', 'ws', '-gu', $GuestUser, '-gp', $guestPasswordText, 'copyFileFromGuestToHost', $Path, $guestOutput, $hostOutput) -TimeoutSeconds 15
    if ($copyResult.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $hostOutput)) {
        $guestPasswordText = $null
        return ''
    }
    $guestAddress = Get-GuestIPv4FromAddressText -Lines @(Get-Content -LiteralPath $hostOutput)
    $guestPasswordText = $null
    return $guestAddress
}

<#
.SYNOPSIS
Wait for a guest IPv4 address from multiple retrieval methods.

.PARAMETER Path
VMX path.
.PARAMETER TimeoutSeconds
Maximum seconds to wait.
.PARAMETER GuestUser
Guest username used for guest-ops probing.
.PARAMETER GuestPassword
Guest password used for guest-ops probing.
.PARAMETER Name
VM name used for temporary artifacts.
#>
function Wait-GuestIPv4 {
    param(
        [string]$Path,
        [int]$TimeoutSeconds = 240,
        [string]$GuestUser = '',
        [SecureString]$GuestPassword,
        [string]$Name = 'guest'
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $reported = Invoke-VmrunBounded -Arguments @('-T', 'ws', 'getGuestIPAddress', $Path) -TimeoutSeconds 10
        if ($reported.ExitCode -eq 0) {
            $ip = Get-GuestIPv4FromAddressText -Lines @($reported.StdOut -split "`r?`n")
            if ($ip) {
                return $ip
            }
        }
        $neighborIp = Get-GuestIPv4FromHostNeighbor -Path $Path
        if ($neighborIp) {
            return $neighborIp
        }
        $fallbackIp = Get-GuestIPv4ViaGuestOps -Path $Path -GuestUser $GuestUser -GuestPassword $GuestPassword -Name $Name
        if ($fallbackIp) {
            return $fallbackIp
        }
        Start-Sleep -Seconds 5
    }
    return ''
}

<#
.SYNOPSIS
Execute a shell command inside the appliance guest.

.PARAMETER ApplianceVmx
Appliance VMX path.
.PARAMETER Script
Shell script content.
#>
function Invoke-ApplianceGuestScript {
    param(
        [string]$ApplianceVmx,
        [string]$Script
    )

    & $resolvedVmrun -T ws -gu $ApplianceSshUser -gp $ApplianceGuestPassword runScriptInGuest $ApplianceVmx /bin/sh $Script | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Appliance guest operation failed."
    }
}

<#
.SYNOPSIS
Probe a URL for successful openapi endpoint response.

.PARAMETER Url
OpenAPI URL to probe.
#>
function Test-ApplianceOpenApi {
    param([string]$Url)

    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        & $curl.Source -k -f -sS $Url 2>$null | Out-Null
        return $LASTEXITCODE -eq 0
    }

    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -SkipCertificateCheck -TimeoutSec 10
        return $response.StatusCode -eq 200
    } catch [System.Management.Automation.ParameterBindingException] {
        $previousCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
        try {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 10
            return $response.StatusCode -eq 200
        } catch {
            return $false
        } finally {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $previousCallback
        }
    } catch {
        return $false
    }
}

<#
.SYNOPSIS
Upload the lifecycle helper script to the appliance guest.
.PARAMETER ApplianceVmx
VMX path identifying the appliance guest that receives the helper.
#>
function Sync-ApplianceHelperScript {
    param([string]$ApplianceVmx)

    $localHelper = Join-Path $repoRoot 'scripts\appliance\atlaso-helper'
    if (-not (Test-Path -LiteralPath $localHelper)) {
        throw "Atlaso helper script not found: $localHelper"
    }
    $guestTemp = "/tmp/atlaso-helper"
    if ($PSCmdlet.ShouldProcess($ApplianceVmx, "Sync Atlaso helper into appliance")) {
        & $resolvedVmrun -T ws -gu $ApplianceSshUser -gp $ApplianceGuestPassword copyFileFromHostToGuest $ApplianceVmx $localHelper $guestTemp | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to copy Atlaso helper into the appliance with VMware guest operations."
        }
        $quotedPassword = ConvertTo-GuestShellSingleQuote -Value $ApplianceGuestPassword
        $quotedTemp = ConvertTo-GuestShellSingleQuote -Value $guestTemp
        $script = "printf '%s\n' $quotedPassword | sudo -S install -o root -g root -m 0755 $quotedTemp /opt/atlaso/bin/atlaso-helper"
        Invoke-ApplianceGuestScript -ApplianceVmx $ApplianceVmx -Script $script
    }
}

<#
.SYNOPSIS
Upload and install the lifecycle application wheel in the appliance guest.
.PARAMETER ApplianceVmx
VMX path identifying the appliance guest where the wheel is installed.
#>
function Sync-ApplianceApplicationWheel {
    param([string]$ApplianceVmx)

    $wheelRoot = Join-Path $resultRoot 'wheel'
    if (Test-Path -LiteralPath $wheelRoot) {
        Remove-Item -LiteralPath $wheelRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Force -Path $wheelRoot | Out-Null
    Write-Host "Building Atlaso wheel from current branch."
    & python -m pip wheel $repoRoot --no-deps -w $wheelRoot | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to build Atlaso wheel from $repoRoot."
    }
    $wheel = Get-ChildItem -LiteralPath $wheelRoot -Filter 'atlaso-*.whl' -File |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if (-not $wheel) {
        throw "Built wheel was not found under $wheelRoot."
    }

    $guestWheel = "/tmp/$($wheel.Name)"
    if ($PSCmdlet.ShouldProcess($ApplianceVmx, "Install current Atlaso wheel into appliance")) {
        & $resolvedVmrun -T ws -gu $ApplianceSshUser -gp $ApplianceGuestPassword copyFileFromHostToGuest $ApplianceVmx $wheel.FullName $guestWheel | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to copy Atlaso wheel into the appliance with VMware guest operations."
        }
        $quotedPassword = ConvertTo-GuestShellSingleQuote -Value $ApplianceGuestPassword
        $quotedWheel = ConvertTo-GuestShellSingleQuote -Value $guestWheel
        $script = "printf '%s\n' $quotedPassword | sudo -S /opt/atlaso/.venv/bin/python -m pip install --force-reinstall --no-deps $quotedWheel && printf '%s\n' $quotedPassword | sudo -S find /opt/atlaso/.venv -type d -exec chmod 0755 {} + && printf '%s\n' $quotedPassword | sudo -S find /opt/atlaso/.venv -type f -exec chmod 0644 {} + && printf '%s\n' $quotedPassword | sudo -S find /opt/atlaso/.venv/bin -type f -exec chmod 0755 {} + && printf '%s\n' $quotedPassword | sudo -S systemctl restart atlaso.service"
        Invoke-ApplianceGuestScript -ApplianceVmx $ApplianceVmx -Script $script
    }

    $deadline = (Get-Date).AddMinutes(3)
    do {
        if (Test-ApplianceOpenApi -Url "$ApplianceUrl/openapi.json") {
            return $wheel.FullName
        }
        Start-Sleep -Seconds 5
    } while ((Get-Date) -lt $deadline)
    throw "Timed out waiting for Atlaso web service after installing $($wheel.Name)."
}

<#
.SYNOPSIS
Find an ESXi installer ISO already stored on the appliance.
.PARAMETER ApplianceVmx
VMX path identifying the appliance guest whose depot is searched.
#>
function Find-ApplianceEsxiIsoPath {
    param([string]$ApplianceVmx)

    $guestOutput = '/tmp/atlaso-esxi-iso.txt'
    $hostOutput = Join-Path $resultRoot 'appliance-esxi-iso.txt'
    $script = "find /mnt/atlaso-vcf-offline-depot/PROD/COMP/ESX_HOST -maxdepth 1 -type f -iname '*.iso' | head -n 1 > $guestOutput"
    & $resolvedVmrun -T ws -gu $ApplianceSshUser -gp $ApplianceGuestPassword runScriptInGuest $ApplianceVmx /bin/sh $script 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        return ''
    }
    & $resolvedVmrun -T ws -gu $ApplianceSshUser -gp $ApplianceGuestPassword copyFileFromGuestToHost $ApplianceVmx $guestOutput $hostOutput 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $hostOutput)) {
        return ''
    }
    return ((Get-Content -LiteralPath $hostOutput | Select-Object -First 1) -as [string]).Trim()
}

<#
.SYNOPSIS
Resolve or upload the ESXi ISO required by the PXE scenario.
.PARAMETER ApplianceVmx
VMX path identifying the appliance guest that owns the ESXi depot.
#>
function Resolve-ApplianceEsxiIsoPath {
    param([string]$ApplianceVmx)

    if (-not $FullEsxiPxeInstall) {
        return ''
    }
    if (-not $PxeInstallerIsoPath) {
        $discovered = Find-ApplianceEsxiIsoPath -ApplianceVmx $ApplianceVmx
        if ($discovered) {
            return $discovered
        }
        throw "-FullEsxiPxeInstall requires -PxeInstallerIsoPath or an existing ESXi ISO under /mnt/atlaso-vcf-offline-depot/PROD/COMP/ESX_HOST on the appliance."
    }
    if ($PxeInstallerIsoPath.StartsWith('/')) {
        return $PxeInstallerIsoPath
    }
    $localIso = Resolve-Path -LiteralPath $PxeInstallerIsoPath
    $leaf = Split-Path -Leaf $localIso.Path
    $guestTemp = "/tmp/$leaf"
    $guestTarget = "/mnt/atlaso-vcf-offline-depot/PROD/COMP/ESX_HOST/$leaf"
    if ($PSCmdlet.ShouldProcess($guestTarget, "Stage ESXi installer ISO into appliance depot")) {
        & $resolvedVmrun -T ws -gu $ApplianceSshUser -gp $ApplianceGuestPassword copyFileFromHostToGuest $ApplianceVmx $localIso.Path $guestTemp | Out-Host
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to copy ESXi installer ISO into the appliance with VMware guest operations."
        }
        $quotedPassword = ConvertTo-GuestShellSingleQuote -Value $ApplianceGuestPassword
        $quotedTemp = ConvertTo-GuestShellSingleQuote -Value $guestTemp
        $quotedTarget = ConvertTo-GuestShellSingleQuote -Value $guestTarget
        $script = "printf '%s\n' $quotedPassword | sudo -S mkdir -p /mnt/atlaso-vcf-offline-depot/PROD/COMP/ESX_HOST && printf '%s\n' $quotedPassword | sudo -S mv $quotedTemp $quotedTarget && printf '%s\n' $quotedPassword | sudo -S chmod 0644 $quotedTarget"
        Invoke-ApplianceGuestScript -ApplianceVmx $ApplianceVmx -Script $script
    }
    return $guestTarget
}

<#
.SYNOPSIS
Append one timestamped validation step to the lifecycle result.
.PARAMETER ResultDirectory
Directory containing the lifecycle result JSON to update.
.PARAMETER Name
Stable result-step name recorded for the validation.
.PARAMETER Status
Validation outcome written to the step and aggregate result.
.PARAMETER Evidence
Non-secret structured evidence captured for the validation.
.PARAMETER ErrorMessage
Optional sanitized failure context for an unsuccessful step.
#>
function Add-LifecycleResultStep {
    param(
        [string]$ResultDirectory,
        [string]$Name,
        [string]$Status,
        [hashtable]$Evidence,
        [string]$ErrorMessage = ''
    )

    $path = Join-Path $ResultDirectory 'result.json'
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Lifecycle result JSON not found: $path"
    }
    $result = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $step = [ordered]@{
        name        = $Name
        status      = $Status
        started_at  = (Get-Date).ToUniversalTime().ToString('o')
        finished_at = (Get-Date).ToUniversalTime().ToString('o')
        evidence    = $Evidence
        error       = $ErrorMessage
    }
    $result.steps += @($step)
    if ($Status -ne 'passed') {
        $result.status = 'failed'
        if ($result.PSObject.Properties.Name -contains 'error') {
            $result.error = $ErrorMessage
        } else {
            $result | Add-Member -MemberType NoteProperty -Name 'error' -Value $ErrorMessage
        }
    }
    $result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8
}

$resolvedVmrun = Resolve-VmrunPath
if (($RoutingWanOnly -and $FullEsxiPxeInstall) -or ($OidcOnly -and ($RoutingWanOnly -or $FullEsxiPxeInstall))) {
    throw "-OidcOnly, -RoutingWanOnly, and -FullEsxiPxeInstall are mutually exclusive."
}
$applianceName = "$LabName-Appliance"
$clientAName = "$LabName-ClientA"
$clientBName = "$LabName-ClientB"
$esxiName = "$LabName-ESXiPXE"
$esxiMacAddress = if ($FullEsxiPxeInstall) { New-StaticVmwareMac } else { '' }
$planApplianceVmx = if (Test-Path -LiteralPath $ApplianceVmxPath) { (Resolve-Path -LiteralPath $ApplianceVmxPath).Path } else { $ApplianceVmxPath }
$planClientVmdk = if (Test-Path -LiteralPath $ClientVmdkPath) { (Resolve-Path -LiteralPath $ClientVmdkPath).Path } else { $ClientVmdkPath }

$plan = [ordered]@{
    name                  = 'vmware workstation lifecycle interop'
    lab_name              = $LabName
    appliance_vmx         = $planApplianceVmx
    client_vmdk           = $planClientVmdk
    result_root           = $resultRoot
    management_network    = $ManagementNetwork
    site_a_network        = $SiteANetwork
    trunk_network         = $TrunkNetwork
    site_b_network        = $SiteBNetwork
    oidc_only             = [bool]$OidcOnly
    routing_wan_only      = [bool]$RoutingWanOnly
    full_esxi_pxe_install = [bool]$FullEsxiPxeInstall
    pxe_installer_iso     = $PxeInstallerIsoPath
    pxe_client_ip         = $PxeClientIPAddress
    esxi_probe_delay_seconds = $EsxiInstallProbeDelaySeconds
    esxi_pxe_vm           = if ($FullEsxiPxeInstall) { $esxiName } else { '' }
    esxi_pxe_mac          = $esxiMacAddress
    workstation_fidelity  = 'Workstation vmnets are isolated layer-2 segments; tagged trunk behavior requires a compatible upstream virtual-network configuration.'
}

if ($PlanOnly) {
    New-Item -ItemType Directory -Force -Path $resultRoot | Out-Null
    $plan | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $resultRoot 'plan.json') -Encoding UTF8
    $plan | ConvertTo-Json -Depth 5
    return
}

$firstBootOvfEnvironment = New-AtlasoWorkstationOvfEnvironment `
    -Fqdn (New-AtlasoWorkstationFqdn -Name $applianceName) `
    -AdminPassword $adminPasswordSecure `
    -RootPassword $adminPasswordSecure `
    -RootSshEnabled:($ApplianceSshUser -eq 'root')

New-Item -ItemType Directory -Force -Path $vmRoot | Out-Null
New-Item -ItemType Directory -Force -Path $seedRoot | Out-Null

$clientASeedIso = ''
$clientBSeedIso = ''
$clientAVmx = ''
$clientBVmx = ''
$seedArtifactsRetired = [bool]$OidcOnly
$scenarioFailure = $null
try {
    if (-not $OidcOnly) {
        $clientASeedIso = Join-Path $seedRoot "$clientAName-seed.iso"
        $clientBSeedIso = Join-Path $seedRoot "$clientBName-seed.iso"
        New-CloudInitSeedIso -Path $clientASeedIso -HostName ($clientAName.ToLowerInvariant())
        New-CloudInitSeedIso -Path $clientBSeedIso -HostName ($clientBName.ToLowerInvariant())
    }
    $applianceVmx = Copy-VmDirectory -SourceVmx $ApplianceVmxPath -DestinationDirectory (Join-Path $vmRoot $applianceName) -Name $applianceName
    Set-VmxNetworkAdapter -Path $applianceVmx -Index 0 -Vmnet $ManagementNetwork
    Set-AtlasoWorkstationOvfEnvironment -VmxPath $applianceVmx -OvfEnvironment $firstBootOvfEnvironment
    if (-not $OidcOnly) {
        Set-VmxNetworkAdapter -Path $applianceVmx -Index 1 -Vmnet $SiteANetwork
        Set-VmxNetworkAdapter -Path $applianceVmx -Index 2 -Vmnet $TrunkNetwork
        Set-VmxNetworkAdapter -Path $applianceVmx -Index 3 -Vmnet $SiteBNetwork
        $clientAVmx = New-ClientVm -Name $clientAName -Directory (Join-Path $vmRoot $clientAName) -DiskPath $ClientVmdkPath -SeedIso $clientASeedIso -Networks @($ManagementNetwork, $SiteANetwork, $TrunkNetwork)
        $clientBVmx = New-ClientVm -Name $clientBName -Directory (Join-Path $vmRoot $clientBName) -DiskPath $ClientVmdkPath -SeedIso $clientBSeedIso -Networks @($ManagementNetwork, $SiteBNetwork)
    }
    $esxiVmx = ''
    if ($FullEsxiPxeInstall) {
        $esxiVmx = New-EsxiPxeVm -Name $esxiName -Directory (Join-Path $vmRoot $esxiName) -Network $SiteANetwork -MacAddress $esxiMacAddress
    }

    $vmxsToStart = @($applianceVmx)
    if (-not $OidcOnly) {
        $vmxsToStart += @($clientAVmx, $clientBVmx)
    }
    foreach ($vmx in $vmxsToStart) {
        Start-WorkstationVm -Path $vmx
    }

    Start-Sleep -Seconds 20
    if (-not $ApplianceIPAddress) {
        $ApplianceIPAddress = Wait-GuestIPv4 -Path $applianceVmx -TimeoutSeconds 300 -GuestUser $ApplianceSshUser -GuestPassword $adminPasswordSecure -Name $applianceName
        if (-not $ApplianceIPAddress) {
            throw "Timed out waiting for VMware Tools to report the appliance management IPv4 address."
        }
    }
    if (-not $ApplianceUrl) {
        $ApplianceUrl = "https://${ApplianceIPAddress}"
    }
    [pscustomobject]@{
        appliance_ip  = $ApplianceIPAddress
        appliance_url = $ApplianceUrl
    } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $resultRoot 'discovered-appliance.json') -Encoding UTF8
    Sync-ApplianceHelperScript -ApplianceVmx $applianceVmx
    $applianceWheelPath = Sync-ApplianceApplicationWheel -ApplianceVmx $applianceVmx
    $applianceHostKey = Get-PlinkHostKey -HostName $ApplianceIPAddress -UserName $ApplianceSshUser -Password $adminPasswordSecure
    $clientAHost = ''
    $clientBHost = ''
    $clientAHostKey = ''
    $clientBHostKey = ''
    if (-not $OidcOnly) {
        $clientAHost = Wait-GuestIPv4 -Path $clientAVmx -GuestUser $ClientSshUser -GuestPassword $sshPasswordSecure -Name $clientAName
        $clientBHost = Wait-GuestIPv4 -Path $clientBVmx -GuestUser $ClientSshUser -GuestPassword $sshPasswordSecure -Name $clientBName
        if (-not $clientAHost -or -not $clientBHost) {
            throw 'Client guest readiness did not return both lifecycle addresses.'
        }
        $clientAHostKey = Get-PlinkHostKey -HostName $clientAHost -UserName $ClientSshUser -Password $sshPasswordSecure
        $clientBHostKey = Get-PlinkHostKey -HostName $clientBHost -UserName $ClientSshUser -Password $sshPasswordSecure
    }
    $appliancePxeInstallerIsoPath = if ($FullEsxiPxeInstall) {
        Resolve-ApplianceEsxiIsoPath -ApplianceVmx $applianceVmx
    } else {
        ''
    }

    $basePythonArgs = @(
        (Join-Path $repoRoot 'scripts\interop\lifecycle_test.py'),
        '--appliance-url', $ApplianceUrl,
        '--appliance-ssh-host', $ApplianceIPAddress,
        '--username', $AdminUsername,
        '--appliance-ssh-user', $ApplianceSshUser,
        '--client-ssh-user', $ClientSshUser,
        '--secret-stdin',
        '--site-interface', $SiteInterface,
        '--site-cidr', $SiteCidr,
        '--vlan-id', "$VlanId",
        '--vlan-cidr', $TaggedVlanCidr,
        '--wan-cidr', $WanCidr,
        '--pxe-test-mode', $(if ($FullEsxiPxeInstall) { 'esxi' } else { 'linux' })
    )
    if ($FullEsxiPxeInstall) {
        $basePythonArgs += @(
            '--pxe-client-mac', $esxiMacAddress,
            '--pxe-installer-iso-path', $appliancePxeInstallerIsoPath
        )
        if ($PxeClientIPAddress) {
            $basePythonArgs += @('--pxe-client-ip', $PxeClientIPAddress)
        }
    }
    if ($applianceHostKey) { $basePythonArgs += @('--appliance-ssh-hostkey', $applianceHostKey) }
    if ($clientAHost) { $basePythonArgs += @('--client-a-host', $clientAHost) }
    if ($clientBHost) { $basePythonArgs += @('--client-b-host', $clientBHost) }
    if ($clientAHostKey) { $basePythonArgs += @('--client-a-hostkey', $clientAHostKey) }
    if ($clientBHostKey) { $basePythonArgs += @('--client-b-hostkey', $clientBHostKey) }
    if ($AllowDryRunApply) { $basePythonArgs += '--allow-dry-run' }
    if ($OidcOnly) { $basePythonArgs += '--oidc-only' }
    if ($RoutingWanOnly) { $basePythonArgs += '--routing-wan-only' }

    $initialResultRoot = if ($SkipBackupRestoreTest) { $resultRoot } else { Join-Path $resultRoot 'initial' }
    $restoredResultRoot = Join-Path $resultRoot 'restored'
    $backupArchivePath = Join-Path $resultRoot 'settings-backup.json'

    $initialPythonArgs = @($basePythonArgs + @('--result-dir', $initialResultRoot))
    if (-not $SkipBackupRestoreTest) {
        $initialPythonArgs += @('--export-settings-backup', $backupArchivePath)
    }

    if ($PSCmdlet.ShouldProcess($LabName, 'Run Workstation lifecycle interop scenario')) {
        $pythonExitCode = Invoke-LifecyclePython -Arguments $initialPythonArgs `
            -AdminPassword $adminPasswordSecure `
            -SshPassword $sshPasswordSecure `
            -VcfBackupPassword $vcfBackupPasswordSecure `
            -EsxiPassword $esxiPasswordSecure
        if ($pythonExitCode -ne 0) {
            throw "Lifecycle interop runner failed with exit code $pythonExitCode"
        }
        if ($FullEsxiPxeInstall) {
            try {
                Start-WorkstationVm -Path $esxiVmx
                if ($EsxiInstallProbeDelaySeconds -gt 0) {
                    Write-Host "Waiting $EsxiInstallProbeDelaySeconds seconds before probing ESXi guest operations."
                    Start-Sleep -Seconds $EsxiInstallProbeDelaySeconds
                }
                $esxiDetectedIp = Wait-GuestIPv4 -Path $esxiVmx -TimeoutSeconds $EsxiInstallTimeoutSeconds -GuestUser 'root' -GuestPassword $esxiPasswordSecure -Name $esxiName
                if (-not $esxiDetectedIp) {
                    throw "Timed out waiting for ESXi PXE install guest IP after $EsxiInstallTimeoutSeconds seconds."
                }
                Add-LifecycleResultStep -ResultDirectory $initialResultRoot -Name 'esxi-pxe-install-check' -Status 'passed' -Evidence @{
                    vmx                = $esxiVmx
                    mac_address        = $esxiMacAddress
                    detected_ip        = $esxiDetectedIp
                    installer_iso_path = $appliancePxeInstallerIsoPath
                }
            } catch {
                Add-LifecycleResultStep -ResultDirectory $initialResultRoot -Name 'esxi-pxe-install-check' -Status 'failed' -Evidence @{
                    vmx                = $esxiVmx
                    mac_address        = $esxiMacAddress
                    installer_iso_path = $appliancePxeInstallerIsoPath
                } -ErrorMessage $_.Exception.Message
                throw
            }
        }
        if (-not $SkipBackupRestoreTest) {
            $restoredPythonArgs = @($basePythonArgs + @(
                '--result-dir', $restoredResultRoot,
                '--restore-settings-backup', $backupArchivePath,
                '--restored-state-run',
                '--certificate-baseline-result', (Join-Path $initialResultRoot 'result.json')
            ))
            $pythonExitCode = Invoke-LifecyclePython -Arguments $restoredPythonArgs `
                -AdminPassword $adminPasswordSecure `
                -SshPassword $sshPasswordSecure `
                -VcfBackupPassword $vcfBackupPasswordSecure `
                -EsxiPassword $esxiPasswordSecure
            if ($pythonExitCode -ne 0) {
                throw "Restored lifecycle interop runner failed with exit code $pythonExitCode"
            }
        }
    }
    if (-not $OidcOnly) {
        # Successful lifecycle client access proves cloud-init consumed both
        # seeds. Leave retained labs running only after verified deletion.
        Remove-ClientSeedArtifacts `
            -VmxPaths @($clientAVmx, $clientBVmx) `
            -SeedPaths @($clientASeedIso, $clientBSeedIso) `
            -Restart:(-not $CleanupCreatedLab)
        $seedArtifactsRetired = $true
    }
} catch {
    $scenarioFailure = $_
}

$seedCleanupFailure = $null
if (-not $seedArtifactsRetired) {
    try {
        # Failure cleanup intentionally leaves affected clients stopped: a
        # restart is unsafe until every credential-bearing ISO is absent.
        Remove-ClientSeedArtifacts `
            -VmxPaths @($clientAVmx, $clientBVmx) `
            -SeedPaths @($clientASeedIso, $clientBSeedIso)
        $seedArtifactsRetired = $true
    } catch {
        $seedCleanupFailure = $_
    }
}

$cleanupFailure = $null
if ($CleanupCreatedLab) {
    $createdVmxPathArray = @($createdVmxPaths.ToArray())
    if ($createdVmxPathArray.Count -gt 0) {
        try {
            if ($PSCmdlet.ShouldProcess($vmRoot, 'Stop and delete created VMware Workstation lifecycle artifacts')) {
                Remove-AtlasoWorkstationVmArtifacts `
                    -VmrunPath $resolvedVmrun `
                    -VmxPaths $createdVmxPathArray `
                    -RemovalRoot $vmRoot `
                    -Confirm:$false
            }
        } catch {
            $cleanupFailure = $_
        }
    }
} else {
    Write-Host "Workstation lifecycle VMs were left in place under: $vmRoot"
}

if ($scenarioFailure) {
    if ($seedCleanupFailure -or $cleanupFailure) {
        $cleanupMessages = @(
            $seedCleanupFailure,
            $cleanupFailure
        ) | Where-Object { $null -ne $_ } | ForEach-Object { $_.Exception.Message }
        $combinedMessage = "Lifecycle scenario failed: $($scenarioFailure.Exception.Message) Cleanup also failed; VM artifacts were preserved at '$vmRoot': $($cleanupMessages -join '; ')"
        throw [System.InvalidOperationException]::new($combinedMessage, $scenarioFailure.Exception)
    }
    throw $scenarioFailure
}
if ($seedCleanupFailure) {
    if ($cleanupFailure) {
        throw "Credential-bearing seed cleanup failed: $($seedCleanupFailure.Exception.Message) VM cleanup also failed: $($cleanupFailure.Exception.Message)"
    }
    throw $seedCleanupFailure
}
if ($cleanupFailure) {
    throw $cleanupFailure
}
