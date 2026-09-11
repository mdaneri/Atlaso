<#
.SYNOPSIS
Verify or release one retained VMware builder-address reservation.
.DESCRIPTION
Defaults to read-only verification. Cleanup rechecks the exact allocation and
process evidence, releases only that allocation, and removes its handoff. It
never launches a build, retrieves credentials, stops a VM, or deletes VM files.
.PARAMETER HandoffPath
Absolute path to the exact pending-release JSON file reported by the build.
.PARAMETER VmrunPath
Optional exact VMware Workstation vmrun executable path.
.PARAMETER ReservationStateRoot
Optional existing shared allocator root. Omit to use the allocator default.
.PARAMETER Cleanup
Release the selected reservation when all checks pass.
.PARAMETER Json
Return one structured result with Id, Address, Status, Reason, and HandoffPath.
.EXAMPLE
.\manage-builder-reservation.ps1 -HandoffPath E:\task\.atlaso-local\photon-image-build-state\vmware-builder-addresses\pending-releases\builder-address-reservation-0123456789abcdef0123456789abcdef.json -Json
.EXAMPLE
.\manage-builder-reservation.ps1 -HandoffPath E:\task\.atlaso-local\photon-image-build-state\vmware-builder-addresses\pending-releases\builder-address-reservation-0123456789abcdef0123456789abcdef.json -Cleanup -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][string]$HandoffPath,
    [string]$VmrunPath = '',
    [string]$ReservationStateRoot = '',
    [switch]$Cleanup,
    [switch]$Json
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationBuilderAddress.psm1') -Force
if (-not [IO.Path]::IsPathFullyQualified($HandoffPath)) { throw 'HandoffPath must be absolute.' }
if ([string]::IsNullOrWhiteSpace($VmrunPath)) {
    foreach ($candidate in @(
        (Join-Path ${env:ProgramFiles(x86)} 'VMware\VMware Workstation\vmrun.exe'),
        (Join-Path $env:ProgramFiles 'VMware\VMware Workstation\vmrun.exe')
    )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { $VmrunPath = $candidate; break }
    }
}
if (-not (Test-Path -LiteralPath $VmrunPath -PathType Leaf)) { throw 'Pass the installed Workstation vmrun executable using -VmrunPath.' }
$execute = $Cleanup -and $PSCmdlet.ShouldProcess($HandoffPath, 'Release exact builder reservation and remove its handoff')
$result = Invoke-AtlasoBuilderReservationRecovery -HandoffPath $HandoffPath -VmrunPath $VmrunPath -StateRoot $ReservationStateRoot -Execute:$execute
if ($Json) { $result | ConvertTo-Json -Depth 4 } else { $result | Format-List }
if ($result.Status -eq 'blocked') { exit 2 }
