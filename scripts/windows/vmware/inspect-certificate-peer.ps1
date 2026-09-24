<#
.SYNOPSIS
Publish receipt-bound, read-only native address proof for PR871.
.PARAMETER Plan
Existing nonsecret proof plan within the original task-owned test-results tree.
.PARAMETER AddressEvidence
New immutable address-proof destination within that same tree.
.PARAMETER RuntimeEvidence
New immutable controlled-runtime destination within that same tree.
.PARAMETER EnvironmentId
Explicit pinned 1Password Environment selector.
.PARAMETER PythonPath
Exact supported Python executable with the locked Paramiko dependency.
.PARAMETER SshPassword
The peer client's SSH password, supplied separately from the appliance admin credential.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Plan,
    [Parameter(Mandatory)][string]$AddressEvidence,
    [Parameter(Mandatory)][string]$RuntimeEvidence,
    [Parameter(Mandatory)][string]$EnvironmentId,
    [Parameter(Mandatory)][string]$PythonPath,
    [Parameter(Mandatory)][SecureString]$SshPassword
)

$ErrorActionPreference = 'Stop'
$repoRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')
$evidenceRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot 'test-results')).TrimEnd('\') + '\'
foreach ($candidate in @($Plan, $AddressEvidence, $RuntimeEvidence)) {
    if (-not [IO.Path]::GetFullPath($candidate).StartsWith($evidenceRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Certificate peer proof paths must remain beneath the original owned test-results root.'
    }
}
if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $Plan -PathType Leaf) -or
    (Test-Path -LiteralPath $AddressEvidence) -or (Test-Path -LiteralPath $RuntimeEvidence)) {
    throw 'Certificate proof requires an existing plan/Python and two new evidence destinations.'
}
$env:TEMP = $evidenceRoot
$env:TMP = $evidenceRoot
Import-Module (Join-Path $PSScriptRoot 'Atlaso.OnePasswordCredentials.psm1') -Force
. (Join-Path $PSScriptRoot 'Atlaso.WorkstationFirstBoot.ps1')
Import-Module (Join-Path $PSScriptRoot 'Atlaso.SourceSnapshot.psm1') -Force
$planIdentity = Get-Content -LiteralPath $Plan -Raw | ConvertFrom-Json
$snapshot = New-AtlasoCertificateInspectorSnapshot -RepositoryRoot $repoRoot -EvidenceRoot $evidenceRoot `
    -SourceCommit ([string]$planIdentity.source_commit) -TaskId ([string]$planIdentity.task_id)
try {
    $scriptPath = Join-Path $snapshot.Root 'scripts/interop/certificate_peer_proof.py'
    $arguments = @('-I', '-B', $scriptPath, '--plan', $Plan,
        '--address-output', $AddressEvidence, '--runtime-output', $RuntimeEvidence)
    Invoke-AtlasoBoundedProcess -FilePath $PythonPath -ArgumentList ($arguments + '--preflight-only') `
        -TimeoutSeconds 30 -Action 'PR871 original peer proof admission' -DiscardOutput | Out-Null
    $null = Assert-AtlasoSourceSnapshot -Root $snapshot.Root -ExpectedSha256 $snapshot.Sha256 `
        -ExpectedFileCount $snapshot.FileCount
    $pair = $null
    $plain = $null
    $peerPlain = $null
    try {
        $pair = Get-AtlasoOnePasswordCredentialPair -RepositoryRoot $repoRoot -EnvironmentId $EnvironmentId `
            -OnePasswordServiceAccountTokenFile (Join-Path $repoRoot '.atlaso-local/onepassword-service-account-token.dpapi') `
            -OnePasswordPython $PythonPath -TimeoutSeconds 300 -ConsumerDescription 'PR871 private address proof'
        $plain = [Net.NetworkCredential]::new('', $pair.AdminPassword).Password
        $peerPlain = [Net.NetworkCredential]::new('', $SshPassword).Password
        Invoke-AtlasoBoundedProcess -FilePath $PythonPath -ArgumentList $arguments `
            -EnvironmentVariables @{ ATLASO_NATIVE_ADMIN = $plain; ATLASO_NATIVE_PEER = $peerPlain; TEMP = $evidenceRoot; TMP = $evidenceRoot } `
            -TimeoutSeconds 300 -Action 'PR871 private address proof' -DiscardOutput | Out-Null
    } finally {
        $plain = $null
        $peerPlain = $null
        if ($pair) { $pair.AdminPassword.Dispose(); $pair.RootPassword.Dispose() }
    }
} finally {
    foreach ($pin in $snapshot.Pins) { $pin.Dispose() }
}
