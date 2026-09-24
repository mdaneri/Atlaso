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
Task-owned isolated Python virtual environment with locked native dependencies.
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
$planIdentity = Get-Content -LiteralPath $Plan -Raw | ConvertFrom-Json
$sourceCommit = [string]$planIdentity.source_commit
if ($sourceCommit -notmatch '^[0-9a-f]{40}$' -or
    ([string](& git -C $repoRoot rev-parse --verify 'HEAD^{commit}')).Trim() -cne $sourceCommit) {
    throw 'Certificate inspector source commit differs from its plan.'
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
    Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationCleanup.psm1') -Force
    $helperPins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($PSScriptRoot))
    Import-Module (Join-Path $PSScriptRoot 'Atlaso.OnePasswordCredentials.psm1') -Force
    . (Join-Path $PSScriptRoot 'Atlaso.WorkstationFirstBoot.ps1')
    Import-Module (Join-Path $PSScriptRoot 'Atlaso.SourceSnapshot.psm1') -Force
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
    $scriptPath = Join-Path $snapshot.Root 'scripts/interop/certificate_handoff_native.py'
    $arguments = @('-I', '-B', $scriptPath, '--plan', $Plan, '--evidence', $Evidence)
    Invoke-AtlasoBoundedProcess -FilePath $PythonPath `
        -ArgumentList @('-I', '-B', $scriptPath, '--plan', $Plan,
            '--evidence', ($Evidence + '.admission.json'), '--preflight-only') `
        -TimeoutSeconds 30 -Action 'PR871 canonical identity admission' -DiscardOutput | Out-Null
    $null = Assert-AtlasoSourceSnapshot -Root $snapshot.Root -ExpectedSha256 $snapshot.Sha256 `
        -ExpectedFileCount $snapshot.FileCount
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
} finally {
    foreach ($pin in $snapshot.Pins) { $pin.Dispose() }
}
} finally {
    foreach ($pin in $runtime.Pins) { $pin.Dispose() }
}
} finally {
    foreach ($pin in $helperPins) { $pin.Dispose() }
}
