<#
.SYNOPSIS
Inspect or safely reset this checkout's retained 1Password credential bridge.

.DESCRIPTION
Uses only the fixed checkout-local schema-2 or schema-3 marker and its boot,
process-job, process-start, creation-time temporary-root, ancestry, and filesystem-identity evidence. Inspection and
WhatIf never open 1Password, terminate a process, or change retained state.

.PARAMETER Inspect
Return a sanitized read-only report of the marker, boot, process, job, root,
and planned recovery action.

.PARAMETER TerminateOwnedProcess
Permit termination of only the exact matching child process job recorded by
the marker. This never permits termination of the recorded controller process.

.EXAMPLE
pwsh -NoProfile -File .\scripts\windows\vmware\reset-atlaso-onepassword-credential-bridge.ps1 -Inspect

.EXAMPLE
pwsh -NoProfile -File .\scripts\windows\vmware\reset-atlaso-onepassword-credential-bridge.ps1 -WhatIf -TerminateOwnedProcess

.EXAMPLE
pwsh -NoProfile -File .\scripts\windows\vmware\reset-atlaso-onepassword-credential-bridge.ps1 -TerminateOwnedProcess -Confirm:$false
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [switch]$Inspect,
    [switch]$TerminateOwnedProcess
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..'))
$modulePath = Join-Path $PSScriptRoot 'Atlaso.OnePasswordCredentials.psm1'

try {
    Import-Module $modulePath -Force -ErrorAction Stop
    Invoke-AtlasoOnePasswordCredentialBridgeReset `
        -RepositoryRoot $repositoryRoot `
        -Inspect:$Inspect `
        -TerminateOwnedProcess:$TerminateOwnedProcess `
        -WhatIf:$WhatIfPreference
}
catch {
    $message = if ($_.Exception.Data['AtlasoOnePasswordRecoverySafe']) {
        $_.Exception.Message
    }
    else {
        'The retained credential bridge could not be inspected or reset safely.'
    }
    [Console]::Error.WriteLine("ERROR: $message")
    exit 1
}
