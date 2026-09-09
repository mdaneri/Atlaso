<#
.SYNOPSIS
Import, boot, validate, reboot, and remove one Atlaso Hyper-V ZIP.
.PARAMETER ZipPath
Versioned Atlaso Hyper-V ZIP to extract and import.
.PARAMETER Name
Unique smoke-test VM name.
.PARAMETER ManagementSwitch
Existing Hyper-V switch for the management adapter.
.PARAMETER ServiceSwitch
Existing Hyper-V switch for the services adapter.
.PARAMETER OutputRoot
Repository-owned directory that receives disposable extracted and VM files.
Generated extraction and VM paths must fit the 240-character Hyper-V budget.
.PARAMETER PythonPath
Optional Python executable with Paramiko installed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ZipPath,
    [string]$Name = 'Atlaso-HyperV-Smoke',
    [Parameter(Mandatory = $true)][string]$ManagementSwitch,
    [Parameter(Mandatory = $true)][string]$ServiceSwitch,
    [string]$OutputRoot = '',
    [string]$PythonPath = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

<#
.SYNOPSIS
Read the first-boot access envelope published by one Hyper-V guest.
.PARAMETER VmId
Exact identifier of the invocation-owned virtual machine.
#>
function Get-AtlasoHyperVFirstBootAccess {
    param([Parameter(Mandatory = $true)][Guid]$VmId)

    $component = @(Get-CimInstance -Namespace 'root/virtualization/v2' -ClassName 'Msvm_KvpExchangeComponent' `
            -ErrorAction Stop | Where-Object { [string]$_.SystemName -eq $VmId.ToString() })
    if ($component.Count -ne 1) {
        return $null
    }
    # Pool 1 is guest-authored (extrinsic) data. Intrinsic items contain only
    # provider/OS metadata and cannot carry Atlaso's first-boot access envelope.
    foreach ($item in @($component[0].GuestExchangeItems)) {
        try {
            [xml]$record = $item
            $nameNode = $record.SelectSingleNode("//PROPERTY[@NAME='Name']/VALUE")
            $dataNode = $record.SelectSingleNode("//PROPERTY[@NAME='Data']/VALUE")
            if ($null -ne $nameNode -and $null -ne $dataNode -and
                [string]$nameNode.InnerText -eq 'atlaso.first_boot_access') {
                return ([string]$dataNode.InnerText | ConvertFrom-Json -ErrorAction Stop)
            }
        }
        catch {
            continue
        }
    }
    return $null
}

<#
.SYNOPSIS
Returns the stable Windows file identifier for a Hyper-V smoke path.
.PARAMETER Path
Existing file or directory whose identity must be captured.
#>
function Get-AtlasoHyperVSmokeWindowsFileId {
    param([Parameter(Mandatory = $true)][string]$Path)

    $output = @(& fsutil file queryfileid $Path 2>&1)
    $fileIdMatches = @([regex]::Matches(($output -join "`n"), '0x[0-9A-Fa-f]+'))
    if ($LASTEXITCODE -ne 0 -or $fileIdMatches.Count -ne 1) {
        throw "Could not resolve one stable Windows file ID for: $Path"
    }
    return $fileIdMatches[0].Value.ToLowerInvariant()
}

<#
.SYNOPSIS
Snapshots every non-reparse descendant beneath a Hyper-V smoke root.
.PARAMETER DirectoryPath
Invocation-owned operation directory to inventory.
#>
function Get-AtlasoHyperVSmokeDescendantIdentity {
    param([Parameter(Mandatory = $true)][string]$DirectoryPath)

    $identity = @{}
    foreach ($item in @(Get-ChildItem -LiteralPath $DirectoryPath -Recurse -Force)) {
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Hyper-V smoke descendant cannot be a reparse point: $($item.FullName)"
        }
        $relativePath = [System.IO.Path]::GetRelativePath($DirectoryPath, $item.FullName)
        $identity[$relativePath] = Get-AtlasoHyperVSmokeWindowsFileId -Path $item.FullName
    }
    return ,$identity
}

<#
.SYNOPSIS
Wait for one provider-bound Hyper-V management IPv4 identity.
.PARAMETER Vm
Exact invocation-owned Hyper-V virtual machine.
.PARAMETER ManagementSwitch
Expected switch for the named Management adapter.
.PARAMETER ServiceSwitch
Expected switch for the named Services adapter.
.PARAMETER ExpectedIdentity
Previously captured network identity that must remain unchanged.
.PARAMETER Deadline
Absolute readiness deadline for provider address discovery.
#>
function Wait-AtlasoHyperVSmokeNetworkIdentity {
    param(
        [Parameter(Mandatory = $true)][object]$Vm,
        [Parameter(Mandatory = $true)][string]$ManagementSwitch,
        [Parameter(Mandatory = $true)][string]$ServiceSwitch,
        [Parameter(Mandatory = $true)][object]$ExpectedIdentity,
        [Parameter(Mandatory = $true)][DateTimeOffset]$Deadline
    )

    while ([DateTimeOffset]::UtcNow -lt $Deadline) {
        $identity = Resolve-AtlasoHyperVSmokeNetworkIdentity `
            -Adapters @(Get-VMNetworkAdapter -VM $Vm -ErrorAction Stop) `
            -ManagementSwitch $ManagementSwitch `
            -ServiceSwitch $ServiceSwitch `
            -ExpectedIdentity $ExpectedIdentity `
            -AllowMissingAddress
        if ($identity.Address) {
            return $identity
        }
        Start-Sleep -Seconds 5
    }
    throw 'The provider-bound Hyper-V Management adapter did not report one usable IPv4 before the deadline.'
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
Import-Module (Join-Path $PSScriptRoot 'Atlaso.VirtualizationSmokeIdentity.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Atlaso.StorageCapacity.psm1') -Force
$sourceZip = Get-Item -LiteralPath $ZipPath -Force -ErrorAction Stop
if ($sourceZip.PSIsContainer -or
    ($sourceZip.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'The Hyper-V smoke-test ZIP must be an ordinary file.'
}
$python = if ($PythonPath) { (Get-Item -LiteralPath $PythonPath -ErrorAction Stop).FullName } else {
    (Get-Command python -ErrorAction Stop).Source
}
$allowedRoot = [System.IO.Path]::GetFullPath((Join-Path $repoRoot 'artifacts\virtualization-smoke'))
$resolvedRoot = if ($OutputRoot) {
    [System.IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputRoot))
}
else {
    $allowedRoot
}
$allowedPrefix = $allowedRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
if ($resolvedRoot -ne $allowedRoot -and
    -not $resolvedRoot.StartsWith($allowedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Hyper-V smoke output must stay beneath the repository-owned root: $allowedRoot"
}
$existingVm = @(Get-VM -ErrorAction Stop | Where-Object Name -eq $Name)
if ($existingVm.Count -ne 0) {
    throw "The Hyper-V smoke-test VM already exists: $Name"
}
# Keep all 128 random bits in a compact filename-safe identifier. Never relocate
# retained operations or escape the caller-approved root to evade provider limits.
$operationId = [Convert]::ToBase64String([guid]::NewGuid().ToByteArray()).TrimEnd('=').Replace('+', '-').Replace('/', '_')
$operationRoot = Join-Path $resolvedRoot ('.hv-' + $operationId)
$packageRoot = Join-Path $operationRoot 'p'
$vmRoot = $operationRoot
if ($Name -notmatch '^[A-Za-z0-9][A-Za-z0-9_. -]*$' -or $Name -in @('.', '..', 'p')) {
    throw 'Name must be a simple Hyper-V name distinct from the extracted package directory p.'
}
# Older verified ZIPs contain the importer that repeats Name in New-VM -Path.
# Budget that larger layout too, before extraction or provider mutation.
$providerRoot = Join-Path (Join-Path $vmRoot $Name) $Name
$generatedPaths = [System.Collections.Generic.List[string]]::new()
$generatedPaths.Add((Join-Path $providerRoot ('x' * 64)))
$archive = [System.IO.Compression.ZipFile]::OpenRead($sourceZip.FullName)
$expandedBytes = 0L
$diskCopyBytes = 0L
try {
    foreach ($entry in $archive.Entries) {
        if ($entry.FullName -ne $entry.Name -or -not $entry.Name -or
            $entry.Name -in @('.', '..') -or $entry.Name.Contains(':') -or $entry.Name.Contains('\')) {
            throw 'The Hyper-V smoke ZIP must contain only ordinary top-level package members.'
        }
        $generatedPaths.Add((Join-Path $packageRoot $entry.Name))
        $expandedBytes += $entry.Length
        if ($expandedBytes -gt 8GB) { throw 'Hyper-V expanded package exceeds the supported 8 GiB capacity estimate.' }
        $generatedPaths.Add((Join-Path (Join-Path $vmRoot $Name) $entry.Name))
        if ([System.IO.Path]::GetExtension($entry.Name) -eq '.vhdx') {
            $diskCopyBytes += $entry.Length
            $diskStem = [System.IO.Path]::GetFileNameWithoutExtension($entry.Name)
            $generatedPaths.Add((Join-Path (Join-Path $vmRoot $Name) "$diskStem-00000000-0000-0000-0000-000000000000.avhdx.rct"))
        }
    }
}
finally { $archive.Dispose() }
foreach ($generatedPath in $generatedPaths) {
    if ($generatedPath.Length -gt 240) {
        throw "Hyper-V smoke generated path exceeds the 240-character budget ($($generatedPath.Length) characters): $generatedPath. Choose a shorter -OutputRoot beneath $allowedRoot or a shorter -Name. No files were extracted or VM created."
    }
}
Assert-AtlasoStorageCapacity -Stage 'Hyper-V extraction and import' -Components @(
    [pscustomobject]@{ Path=$operationRoot; Name='ZIP extraction'; Bytes=$expandedBytes }
    [pscustomobject]@{ Path=$operationRoot; Name='VHDX copies'; Bytes=$diskCopyBytes }
    [pscustomobject]@{ Path=$operationRoot; Name='VMRS memory, metadata and guest disk growth'; Bytes=20GB }
)
New-Item -ItemType Directory -Path $operationRoot -ErrorAction Stop | Out-Null
New-Item -ItemType Directory -Path $packageRoot -ErrorAction Stop | Out-Null
$operationRootItem = Get-Item -LiteralPath $operationRoot -Force -ErrorAction Stop
if (($operationRootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'The Hyper-V smoke operation root became a reparse point.'
}
$operationRootId = Get-AtlasoHyperVSmokeWindowsFileId -Path $operationRoot
$ownedDescendantIds = Get-AtlasoHyperVSmokeDescendantIdentity -DirectoryPath $operationRoot
$vmCreated = $false
$createdVm = $null
$importAttempted = $false
$smokeFailure = $null
try {
    Expand-Archive -LiteralPath $sourceZip.FullName -DestinationPath $packageRoot
    $ownedDescendantIds = Get-AtlasoHyperVSmokeDescendantIdentity -DirectoryPath $operationRoot
    $importer = Join-Path $packageRoot 'Import-Atlaso.ps1'
    if (-not (Test-Path -LiteralPath $importer -PathType Leaf)) {
        throw 'The Hyper-V ZIP does not contain Import-Atlaso.ps1.'
    }
    $importAttempted = $true
    Assert-AtlasoStorageCapacity -Stage 'Hyper-V import and startup' -Components @(
        [pscustomobject]@{ Path=$operationRoot; Name='VHDX copies'; Bytes=$diskCopyBytes }
        [pscustomobject]@{ Path=$operationRoot; Name='VMRS memory, metadata and guest disk growth'; Bytes=20GB }
    )
    $createdVmMatches = @(
        & $importer `
            -Name $Name `
            -ManagementSwitch $ManagementSwitch `
            -ServiceSwitch $ServiceSwitch `
            -DestinationRoot $vmRoot `
            -Start
    )
    if ($createdVmMatches.Count -ne 1 -or
        [string]$createdVmMatches[0].Name -cne $Name -or
        [string]$createdVmMatches[0].Id -notmatch '^[0-9a-fA-F-]{36}$') {
        throw 'The Hyper-V smoke importer did not return one exact created virtual-machine identity.'
    }
    $createdVm = $createdVmMatches[0]
    $vmCreated = $true
    $providerIdentity = Resolve-AtlasoHyperVSmokeNetworkIdentity `
        -Adapters @(Get-VMNetworkAdapter -VM $createdVm -ErrorAction Stop) `
        -ManagementSwitch $ManagementSwitch `
        -ServiceSwitch $ServiceSwitch `
        -AllowMissingAddress
    $deadline = [DateTimeOffset]::UtcNow.AddMinutes(15)
    $access = $null
    $networkIdentity = $null
    while ([DateTimeOffset]::UtcNow -lt $deadline -and ($null -eq $networkIdentity -or $null -eq $access)) {
        $networkIdentity = Wait-AtlasoHyperVSmokeNetworkIdentity `
            -Vm $createdVm `
            -ManagementSwitch $ManagementSwitch `
            -ServiceSwitch $ServiceSwitch `
            -ExpectedIdentity $providerIdentity `
            -Deadline $deadline
        $access = Get-AtlasoHyperVFirstBootAccess -VmId $createdVm.Id
        if ($null -eq $access) {
            Start-Sleep -Seconds 5
        }
    }
    if ($null -eq $networkIdentity -or $null -eq $access) {
        throw 'Hyper-V KVP did not report both management IPv4 and one-time access within 15 minutes.'
    }
    $networkIdentity = Resolve-AtlasoHyperVSmokeNetworkIdentity `
        -Adapters @(Get-VMNetworkAdapter -VM $createdVm -ErrorAction Stop) `
        -ManagementSwitch $ManagementSwitch `
        -ServiceSwitch $ServiceSwitch `
        -ExpectedIdentity $networkIdentity
    $expectedHostKey = [string]$access.ssh_host_key
    if ([string]$access.username -notmatch '^[a-z_][a-z0-9_-]*$' -or
        [string]$access.password -notmatch '^.{12,}$' -or
        $expectedHostKey -notmatch '^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$') {
        throw 'Hyper-V KVP returned a malformed one-time access envelope.'
    }
    $secret = @{
        username = [string]$access.username
        password = [string]$access.password
    } | ConvertTo-Json -Compress
    $initialOutput = @($secret | & $python (Join-Path $repoRoot 'scripts\virtualization\smoke_guest_ssh.py') `
            '--host' ([string]$networkIdentity.Address) `
            '--host-key' $expectedHostKey `
            '--platform' 'hyperv' `
            '--phase' 'initial')
    if ($LASTEXITCODE -ne 0) {
        throw 'Initial Hyper-V guest validation failed.'
    }
    $tlsFingerprint = [string]($initialOutput | Select-Object -Last 1)
    if ($tlsFingerprint -notmatch '^[0-9a-f]{64}$') {
        throw 'Initial Hyper-V guest validation did not return one canonical TLS fingerprint.'
    }
    $networkIdentity = Wait-AtlasoHyperVSmokeNetworkIdentity `
        -Vm $createdVm `
        -ManagementSwitch $ManagementSwitch `
        -ServiceSwitch $ServiceSwitch `
        -ExpectedIdentity $networkIdentity `
        -Deadline ([DateTimeOffset]::UtcNow.AddMinutes(15))
    $postOutput = @($secret | & $python (Join-Path $repoRoot 'scripts\virtualization\smoke_guest_ssh.py') `
            '--host' ([string]$networkIdentity.Address) `
            '--host-key' $expectedHostKey `
            '--platform' 'hyperv' `
            '--phase' 'post-reboot' `
            '--expected-tls-fingerprint' $tlsFingerprint)
    if ($LASTEXITCODE -ne 0 -or
        ($postOutput -join "`n") -notmatch 'Atlaso hyperv guest smoke test passed\.') {
        throw 'Post-reboot Hyper-V guest validation failed.'
    }
    Resolve-AtlasoHyperVSmokeNetworkIdentity `
        -Adapters @(Get-VMNetworkAdapter -VM $createdVm -ErrorAction Stop) `
        -ManagementSwitch $ManagementSwitch `
        -ServiceSwitch $ServiceSwitch `
        -ExpectedIdentity $networkIdentity | Out-Null
}
catch {
    $smokeFailure = $_
    throw
}
finally {
    $cleanupFailure = ''
    if ($importAttempted -and -not $vmCreated) {
        $cleanupFailure = 'The Hyper-V importer did not return an exact created VM identity; its files were preserved.'
    }
    # Once the importer was invoked, an exact VM identity is required before
    # either provider state or the diagnostic operation root can be removed.
    $operationRootSafeToRemove = -not $importAttempted
    if (-not $cleanupFailure -and $vmCreated -and $null -ne $createdVm) {
        try {
            if ([string]$createdVm.State -ne 'Off') {
                Stop-VM -VM $createdVm -TurnOff -Force -ErrorAction Stop
            }
            $operationRootItem = Get-Item -LiteralPath $operationRoot -Force -ErrorAction Stop
            if (($operationRootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
                (Get-AtlasoHyperVSmokeWindowsFileId -Path $operationRoot) -ne $operationRootId) {
                throw 'The invocation-owned Hyper-V smoke root identity changed before provider deletion.'
            }
            $ownedDescendantIds = Get-AtlasoHyperVSmokeDescendantIdentity -DirectoryPath $operationRoot
            Remove-VM -VM $createdVm -Force -ErrorAction Stop
            $matchingVm = @(Get-VM -ErrorAction Stop | Where-Object Id -eq $createdVm.Id)
            if ($matchingVm.Count -ne 0) {
                throw 'The exact Hyper-V smoke virtual machine remains registered after Remove-VM.'
            }
            $operationRootSafeToRemove = $true
        }
        catch {
            $cleanupFailure = "The Hyper-V smoke VM could not be removed; its files were preserved. $($_.Exception.Message)"
        }
    }
    elseif ($vmCreated) {
        $cleanupFailure = 'The exact created Hyper-V smoke VM could not be resolved; its files were preserved.'
    }
    if ($operationRootSafeToRemove -and (Test-Path -LiteralPath $operationRoot)) {
        try {
            $operationRootItem = Get-Item -LiteralPath $operationRoot -Force -ErrorAction Stop
            if (($operationRootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
                (Get-AtlasoHyperVSmokeWindowsFileId -Path $operationRoot) -ne $operationRootId) {
                throw 'The invocation-owned Hyper-V smoke root identity changed before filesystem deletion.'
            }
            $currentDescendantIds = Get-AtlasoHyperVSmokeDescendantIdentity -DirectoryPath $operationRoot
            $descendantChanged = @($currentDescendantIds.Keys | Where-Object {
                    -not $ownedDescendantIds.ContainsKey($_) -or
                    $ownedDescendantIds[$_] -ne $currentDescendantIds[$_]
                })
            if ($descendantChanged.Count -ne 0) {
                throw 'The invocation-owned Hyper-V smoke descendant identity changed before filesystem deletion.'
            }
            Remove-Item -LiteralPath $operationRoot -Recurse -Force -ErrorAction Stop
            if (Test-Path -LiteralPath $operationRoot) {
                throw 'The invocation-owned Hyper-V smoke operation root remains after filesystem deletion.'
            }
        }
        catch {
            $cleanupFailure = "The Hyper-V smoke operation root could not be safely removed; its files were " +
                "preserved. $($_.Exception.Message)"
        }
    }
    if ($cleanupFailure) {
        if ($null -ne $smokeFailure) {
            throw [System.InvalidOperationException]::new(
                "Hyper-V smoke failed. Original error: $($smokeFailure.Exception.Message) Cleanup error: $cleanupFailure",
                $smokeFailure.Exception
            )
        }
        throw $cleanupFailure
    }
}

Write-Host "Atlaso Hyper-V smoke test passed for $Name."
