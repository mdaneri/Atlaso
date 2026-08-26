<#
.SYNOPSIS
Import, boot, validate, reboot, and remove one Atlaso Hyper-V ZIP.
.PARAMETER ZipPath
Versioned Atlaso Hyper-V ZIP to extract and import.
.PARAMETER Credential
Temporary appliance credential used only through the smoke helper standard-input envelope.
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
    [Parameter(Mandatory = $true)][PSCredential]$Credential,
    [string]$Name = 'Atlaso-HyperV-Smoke',
    [Parameter(Mandatory = $true)][string]$ManagementSwitch,
    [Parameter(Mandatory = $true)][string]$ServiceSwitch,
    [string]$OutputRoot = '',
    [string]$PythonPath = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
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
    & $importer `
        -Name $Name `
        -ManagementSwitch $ManagementSwitch `
        -ServiceSwitch $ServiceSwitch `
        -DestinationRoot $vmRoot `
        -Start | Out-Null
    $vmCreated = $true
    $createdVmMatches = @(Get-VM -Name $Name -ErrorAction Stop)
    if ($createdVmMatches.Count -ne 1) {
        throw 'The Hyper-V smoke importer did not create exactly one expected virtual machine.'
    }
    $createdVm = $createdVmMatches[0]
    $manifest = Get-Content -Raw -LiteralPath (Join-Path $packageRoot 'manifest.json') | ConvertFrom-Json
    $expectedHostKey = [string]$manifest.ssh_host_ed25519_public_key
    if ($expectedHostKey -notmatch '^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$') {
        throw 'The verified Hyper-V package did not provide its bound Ed25519 SSH host public key.'
    }
    $deadline = [DateTimeOffset]::UtcNow.AddMinutes(15)
    $address = ''
    while ([DateTimeOffset]::UtcNow -lt $deadline -and -not $address) {
        $address = @(Get-VMNetworkAdapter -VMName $Name | ForEach-Object IPAddresses |
                Where-Object { $_ -match '^\d{1,3}(?:\.\d{1,3}){3}$' -and $_ -notlike '169.254.*' } |
                Select-Object -First 1)
        if (-not $address) {
            Start-Sleep -Seconds 5
        }
    }
    if (-not $address) {
        throw 'Hyper-V KVP did not report a usable management IPv4 address within 15 minutes.'
    }
    $secret = @{
        username = $Credential.UserName
        password = $Credential.GetNetworkCredential().Password
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
        try {
            $createdVmMatches = @(Get-VM -ErrorAction Stop | Where-Object Name -eq $Name)
            if ($createdVmMatches.Count -gt 1) {
                throw 'More than one Hyper-V smoke VM resolved to the invocation-owned name.'
            }
            if ($createdVmMatches.Count -eq 1) {
                $createdVm = $createdVmMatches[0]
                $vmCreated = $true
            }
        }
        catch {
            $cleanupFailure = "The Hyper-V smoke VM ownership could not be resolved; its files were preserved. " +
                $_.Exception.Message
        }
    }
    $operationRootSafeToRemove = -not $vmCreated
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
