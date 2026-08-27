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
    foreach ($item in @($component[0].GuestIntrinsicExchangeItems)) {
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

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
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
$operationRoot = Join-Path $resolvedRoot ('.hyperv-smoke-' + [guid]::NewGuid().ToString('N'))
$packageRoot = Join-Path $operationRoot 'package'
$vmRoot = Join-Path $operationRoot 'vm'
New-Item -ItemType Directory -Path $packageRoot -Force | Out-Null
$vmCreated = $false
$createdVm = $null
$importAttempted = $false
try {
    Expand-Archive -LiteralPath $sourceZip.FullName -DestinationPath $packageRoot
    $importer = Join-Path $packageRoot 'Import-Atlaso.ps1'
    if (-not (Test-Path -LiteralPath $importer -PathType Leaf)) {
        throw 'The Hyper-V ZIP does not contain Import-Atlaso.ps1.'
    }
    $importAttempted = $true
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
    $deadline = [DateTimeOffset]::UtcNow.AddMinutes(15)
    $address = ''
    $access = $null
    while ([DateTimeOffset]::UtcNow -lt $deadline -and (-not $address -or $null -eq $access)) {
        $address = @(Get-VMNetworkAdapter -VMName $Name | ForEach-Object IPAddresses |
                Where-Object { $_ -match '^\d{1,3}(?:\.\d{1,3}){3}$' -and $_ -notlike '169.254.*' } |
                Select-Object -First 1)
        $access = Get-AtlasoHyperVFirstBootAccess -VmId $createdVm.Id
        if (-not $address -or $null -eq $access) {
            Start-Sleep -Seconds 5
        }
    }
    if (-not $address -or $null -eq $access) {
        throw 'Hyper-V KVP did not report both management IPv4 and one-time access within 15 minutes.'
    }
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
    $secret | & $python (Join-Path $repoRoot 'scripts\virtualization\smoke_guest_ssh.py') `
        '--host' ([string]$address) '--host-key' $expectedHostKey '--platform' 'hyperv'
    if ($LASTEXITCODE -ne 0) {
        throw 'Hyper-V guest validation failed.'
    }
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
        Remove-Item -LiteralPath $operationRoot -Recurse -Force
    }
    if ($cleanupFailure) {
        throw $cleanupFailure
    }
}

Write-Host "Atlaso Hyper-V smoke test passed for $Name."
