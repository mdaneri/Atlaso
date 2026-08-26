<#
.SYNOPSIS
Import, boot, validate, reboot, and remove one canonical OVA on VMware Workstation.
.PARAMETER OvaPath
Canonical Atlaso OVA to validate and import.
.PARAMETER Credential
Temporary appliance credential used only through the smoke helper standard-input envelope.
.PARAMETER Name
Unique smoke-test VM name.
.PARAMETER ManagementVmnet
Existing VMware vmnet mapped to the management adapter.
.PARAMETER ServiceVmnet
Existing VMware vmnet mapped to the services adapter.
.PARAMETER OutputRoot
Repository-owned directory that receives the disposable smoke VM.
.PARAMETER OvfToolPath
Optional VMware OVF Tool executable path.
.PARAMETER VmrunPath
Optional vmrun executable path.
.PARAMETER PythonPath
Optional Python executable with Paramiko installed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OvaPath,
    [Parameter(Mandatory = $true)][PSCredential]$Credential,
    [string]$Name = 'Atlaso-Ova-Smoke',
    [string]$ManagementVmnet = 'VMnet8',
    [string]$ServiceVmnet = 'VMnet1',
    [string]$OutputRoot = '',
    [string]$OvfToolPath = '',
    [string]$VmrunPath = '',
    [string]$PythonPath = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
$sourceOva = Get-Item -LiteralPath $OvaPath -Force -ErrorAction Stop
if ($sourceOva.PSIsContainer -or
    ($sourceOva.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'The VMware smoke-test OVA must be an ordinary file.'
}
$ovfTool = if ($OvfToolPath) { (Get-Item -LiteralPath $OvfToolPath -ErrorAction Stop).FullName } else {
    'C:\Program Files\VMware\VMware Workstation\OVFTool\ovftool.exe'
}
$vmrun = if ($VmrunPath) { (Get-Item -LiteralPath $VmrunPath -ErrorAction Stop).FullName } else {
    'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
}
$python = if ($PythonPath) { (Get-Item -LiteralPath $PythonPath -ErrorAction Stop).FullName } else {
    (Get-Command python -ErrorAction Stop).Source
}
foreach ($executable in @($ovfTool, $vmrun, $python)) {
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "Required VMware smoke-test executable was not found: $executable"
    }
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
    throw "VMware smoke output must stay beneath the repository-owned root: $allowedRoot"
}
$vmRoot = Join-Path $resolvedRoot $Name
$vmxPath = Join-Path $vmRoot "$Name.vmx"
$validationRoot = Join-Path $resolvedRoot ('.ova-validation-' + [guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $vmRoot) {
    throw "VMware smoke-test destination already exists: $vmRoot"
}
New-Item -ItemType Directory -Path $vmRoot -Force | Out-Null
New-Item -ItemType Directory -Path $validationRoot -Force | Out-Null
$vmStarted = $false
try {
    $contractOutput = @(& $python `
            (Join-Path $repoRoot 'scripts\virtualization\validate_ova.py') `
            $sourceOva.FullName `
            '--extract-directory' `
            (Join-Path $validationRoot 'members') 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Canonical OVA validation failed before VMware smoke import: $($contractOutput -join [Environment]::NewLine)"
    }
    $contract = ($contractOutput -join "`n") | ConvertFrom-Json -ErrorAction Stop
    $expectedHostKey = [string]$contract.ssh_host_ed25519_public_key
    if ($expectedHostKey -notmatch '^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$') {
        throw 'Canonical OVA validation did not return its bound Ed25519 SSH host public key.'
    }
    & $ovfTool `
        '--acceptAllEulas' `
        "--name=$Name" `
        "--net:Atlaso Management Network=$ManagementVmnet" `
        "--net:Atlaso Services Network=$ServiceVmnet" `
        $sourceOva.FullName `
        $vmxPath
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $vmxPath -PathType Leaf)) {
        throw 'VMware OVF Tool did not create the expected disposable VMX.'
    }
    & $vmrun -T ws start $vmxPath nogui | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'vmrun could not start the imported OVA.'
    }
    $vmStarted = $true
    $address = [string](& $vmrun -T ws getGuestIPAddress $vmxPath -wait)
    $address = $address.Trim()
    if ($LASTEXITCODE -ne 0 -or $address -notmatch '^\d{1,3}(?:\.\d{1,3}){3}$') {
        throw 'VMware Tools did not report a usable management IPv4 address.'
    }
    $secret = @{
        username = $Credential.UserName
        password = $Credential.GetNetworkCredential().Password
    } | ConvertTo-Json -Compress
    $secret | & $python (Join-Path $repoRoot 'scripts\virtualization\smoke_guest_ssh.py') `
        '--host' $address '--host-key' $expectedHostKey '--platform' 'vmware'
    if ($LASTEXITCODE -ne 0) {
        throw 'VMware OVA guest validation failed.'
    }
}
finally {
    if ($vmStarted) {
        & $vmrun -T ws stop $vmxPath hard 2>$null | Out-Null
    }
    if (Test-Path -LiteralPath $vmxPath) {
        & $vmrun -T ws deleteVM $vmxPath 2>$null | Out-Null
    }
    if (Test-Path -LiteralPath $vmRoot) {
        Remove-Item -LiteralPath $vmRoot -Recurse -Force
    }
    if (Test-Path -LiteralPath $validationRoot) {
        Remove-Item -LiteralPath $validationRoot -Recurse -Force
    }
}

Write-Host "Atlaso VMware OVA smoke test passed for $Name."
