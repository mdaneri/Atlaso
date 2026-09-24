<#
.SYNOPSIS
Inspect or execute the receipt-bound PR871 native certificate handoff.
.PARAMETER Plan
Existing nonsecret plan within the original task-owned test-results tree.
.PARAMETER Evidence
New nonsecret evidence file within that same tree.
.PARAMETER EnvironmentId
Explicit pinned 1Password Environment selector.
.PARAMETER PythonPath
Exact supported Python executable with the locked Paramiko dependency.
.PARAMETER SshPassword
The peer client's SSH password, supplied separately from the appliance admin credential.
.PARAMETER Execute
Run the guarded native mutation and restoration; default inspects only.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Plan,
    [Parameter(Mandatory)][string]$Evidence,
    [Parameter(Mandatory)][string]$EnvironmentId,
    [Parameter(Mandatory)][string]$PythonPath,
    [Parameter(Mandatory)][SecureString]$SshPassword,
    [switch]$Execute
)

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')
$evidenceRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot 'test-results')).TrimEnd('\') + '\'
foreach ($candidate in @($Plan, $Evidence)) {
    if (-not [IO.Path]::GetFullPath($candidate).StartsWith($evidenceRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Certificate inspection paths must remain beneath the original owned test-results root.'
    }
}
if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $Plan -PathType Leaf) -or (Test-Path -LiteralPath $Evidence)) {
    throw 'Certificate Python, plan, and new evidence destination must be explicitly available.'
}
$env:TEMP = $evidenceRoot
$env:TMP = $evidenceRoot
Import-Module (Join-Path $PSScriptRoot 'Atlaso.OnePasswordCredentials.psm1') -Force
. (Join-Path $PSScriptRoot 'Atlaso.WorkstationFirstBoot.ps1')
$scriptPath = Join-Path $repoRoot 'scripts/interop/certificate_handoff_native.py'
$arguments = @('-I', $scriptPath, '--plan', $Plan, '--evidence', $Evidence)
Invoke-AtlasoBoundedProcess -FilePath $PythonPath `
    -ArgumentList @('-I', $scriptPath, '--plan', $Plan,
        '--evidence', ($Evidence + '.admission.json'), '--preflight-only') `
    -TimeoutSeconds 30 -Action 'PR871 canonical identity admission' -DiscardOutput | Out-Null
if ($Execute) { $arguments += '--execute' }
$pair = $null
$plain = $null
$peerPlain = $null
try {
    $pair = Get-AtlasoOnePasswordCredentialPair -RepositoryRoot $repoRoot -EnvironmentId $EnvironmentId `
        -OnePasswordServiceAccountTokenFile (Join-Path $repoRoot '.atlaso-local/onepassword-service-account-token.dpapi') `
        -OnePasswordPython $PythonPath -TimeoutSeconds 300 -ConsumerDescription 'PR871 certificate inspection'
    $plain = [Net.NetworkCredential]::new('', $pair.AdminPassword).Password
    $peerPlain = [Net.NetworkCredential]::new('', $SshPassword).Password
    Invoke-AtlasoBoundedProcess -FilePath $PythonPath -ArgumentList $arguments `
        -EnvironmentVariables @{ ATLASO_NATIVE_ADMIN = $plain; ATLASO_NATIVE_PEER = $peerPlain; TEMP = $evidenceRoot; TMP = $evidenceRoot } `
        -TimeoutSeconds 1500 -Action 'PR871 certificate inspection' -DiscardOutput | Out-Null
} finally {
    $plain = $null
    $peerPlain = $null
    if ($pair) { $pair.AdminPassword.Dispose(); $pair.RootPassword.Dispose() }
}
