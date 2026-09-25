<#
.SYNOPSIS
Publish receipt-bound, read-only native address proof for PR871.
.PARAMETER Plan
Existing nonsecret proof plan within the original task-owned test-results tree.
.PARAMETER RepositoryRoot
Exact task checkout supplied by the reviewed Git-blob bootstrap.
.PARAMETER ReviewedSourceCommit
Exact reviewed PR head used to load this entrypoint from Git.
.PARAMETER AddressEvidence
New immutable address-proof destination within that same tree.
.PARAMETER RuntimeEvidence
New immutable controlled-runtime destination within that same tree.
.PARAMETER EnvironmentId
Explicit pinned 1Password Environment selector.
.PARAMETER PythonPath
Task-owned isolated Python virtual environment with locked native dependencies.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepositoryRoot,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$ReviewedSourceCommit,
    [Parameter(Mandatory)][string]$Plan,
    [Parameter(Mandatory)][string]$AddressEvidence,
    [Parameter(Mandatory)][string]$RuntimeEvidence,
    [Parameter(Mandatory)][string]$EnvironmentId,
    [Parameter(Mandatory)][string]$PythonPath
)

$ErrorActionPreference = 'Stop'
if ($PSScriptRoot) {
    throw 'Invoke the certificate inspector from reviewed Git-blob bytes, not a checkout script path.'
}
$repoRoot = Resolve-Path -LiteralPath $RepositoryRoot
$helperRoot = Join-Path $repoRoot 'scripts/windows/vmware'
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
$planIdentity = Get-Content -LiteralPath $Plan -Raw | ConvertFrom-Json
$sourceCommit = [string]$planIdentity.source_commit
if ($sourceCommit -cne $ReviewedSourceCommit -or
    ([string](& git -C $repoRoot rev-parse --verify 'HEAD^{commit}')).Trim() -cne $sourceCommit) {
    throw 'Certificate peer proof source commit differs from its plan.'
}
$helperPins = [Collections.Generic.List[IDisposable]]::new()
try {
    # Pin every helper and transitive import before executing any of their
    # definitions. Raw Git blob identity refuses a transient altered module
    # even when a later clean-checkout test would see restored bytes.
    foreach ($relative in @(
            'scripts/windows/vmware/Atlaso.OnePasswordCredentials.psm1',
            'scripts/windows/vmware/Invoke-AtlasoOnePasswordCredentials.ps1',
            'scripts/windows/vmware/Atlaso.WorkstationFirstBoot.ps1',
            'scripts/windows/vmware/Atlaso.SourceSnapshot.psm1',
            'scripts/windows/vmware/Atlaso.WorkstationCleanup.psm1',
            'scripts/windows/vmware/Atlaso.WorkstationLanSegments.ps1'
        )) {
        $path = Join-Path $repoRoot $relative
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Certificate helper source is not an ordinary file.'
        }
        $helperPins.Add([IO.FileStream]::new($path, [IO.FileMode]::Open,
                [IO.FileAccess]::Read, [IO.FileShare]::Read))
        $expected = ([string](& git -C $repoRoot rev-parse --verify "${sourceCommit}:$relative")).Trim()
        $actual = ([string](& git hash-object --no-filters -- $path)).Trim()
        if ($LASTEXITCODE -ne 0 -or $expected -notmatch '^[0-9a-f]{40}$' -or $actual -cne $expected) {
            throw 'Certificate helper bytes differ from the admitted source commit.'
        }
    }
    Import-Module (Join-Path $helperRoot 'Atlaso.WorkstationCleanup.psm1') -Force
    $helperPins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($helperRoot))
    Import-Module (Join-Path $helperRoot 'Atlaso.OnePasswordCredentials.psm1') -Force
    . (Join-Path $helperRoot 'Atlaso.WorkstationFirstBoot.ps1')
    Import-Module (Join-Path $helperRoot 'Atlaso.SourceSnapshot.psm1') -Force
    if (([string](& git -C $repoRoot rev-parse --verify 'HEAD^{commit}')).Trim() -cne $sourceCommit) {
        throw 'Certificate helper source commit changed during import.'
    }
$runtime = Protect-AtlasoCertificatePythonRuntime -PythonPath $PythonPath -EvidenceRoot $evidenceRoot
try {
    $PythonPath = $runtime.Executable
    Assert-AtlasoCertificatePythonImportPaths -Runtime $runtime
    $snapshot = New-AtlasoCertificateInspectorSnapshot -RepositoryRoot $repoRoot -EvidenceRoot $evidenceRoot `
        -SourceCommit ([string]$planIdentity.source_commit) -TaskId ([string]$planIdentity.task_id)
    try {
    foreach ($pin in (Protect-AtlasoCertificateProofInputs -Plan $Plan -EvidenceRoot $evidenceRoot)) {
        $snapshot.Pins.Add($pin)
    }
    $scriptPath = Join-Path $snapshot.Root 'scripts/interop/certificate_peer_proof.py'
    $arguments = New-AtlasoCertificatePythonArguments -Runtime $runtime -ScriptPath $scriptPath `
        -ScriptArguments @('--plan', $Plan, '--address-output', $AddressEvidence,
            '--runtime-output', $RuntimeEvidence)
    Invoke-AtlasoBoundedProcess -FilePath $PythonPath -ArgumentList ($arguments + '--preflight-only') `
        -TimeoutSeconds 30 -Action 'PR871 original peer proof admission' -DiscardOutput | Out-Null
    $null = Assert-AtlasoSourceSnapshot -Root $snapshot.Root -ExpectedSha256 $snapshot.Sha256 `
        -ExpectedFileCount $snapshot.FileCount
    $pair = $null
    $plain = $null
    try {
        $pair = Get-AtlasoOnePasswordCredentialPair -RepositoryRoot $repoRoot -EnvironmentId $EnvironmentId `
            -OnePasswordServiceAccountTokenFile (Join-Path $repoRoot '.atlaso-local/onepassword-service-account-token.dpapi') `
            -OnePasswordPython $PythonPath -TimeoutSeconds 300 -ConsumerDescription 'PR871 private address proof'
        $plain = [Net.NetworkCredential]::new('', $pair.AdminPassword).Password
        Invoke-AtlasoBoundedProcess -FilePath $PythonPath -ArgumentList $arguments `
            -EnvironmentVariables @{ ATLASO_NATIVE_ADMIN = $plain; TEMP = $evidenceRoot; TMP = $evidenceRoot } `
            -TimeoutSeconds 300 -Action 'PR871 private address proof' -DiscardOutput | Out-Null
    } finally {
        $plain = $null
        if ($pair) { $pair.AdminPassword.Dispose(); $pair.RootPassword.Dispose() }
    }
} finally {
    foreach ($pin in $snapshot.Pins) { $pin.Dispose() }
}
} finally {
    foreach ($pin in $runtime.Pins) { $pin.Dispose() }
}
} finally {
    foreach ($pin in $helperPins) { $pin.Dispose() }
}
