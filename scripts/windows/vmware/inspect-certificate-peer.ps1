<#
.SYNOPSIS
Publish receipt-bound, read-only certificate address observations for the admitted task.
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
.PARAMETER Bootstrap
Inspect the original ISO fixture before its first static certificate-test baseline.
.PARAMETER ExecuteBootstrap
Permit the bootstrap's reviewed Physical Interfaces and Appliance Apply transition.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepositoryRoot,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$ReviewedSourceCommit,
    [Parameter(Mandatory)][string]$Plan,
    [Parameter(Mandatory)][string]$AddressEvidence,
    [Parameter(Mandatory)][string]$RuntimeEvidence,
    [Parameter(Mandatory)][string]$EnvironmentId,
    [Parameter(Mandatory)][string]$PythonPath,
    [switch]$Bootstrap,
    [switch]$ExecuteBootstrap
)

$ErrorActionPreference = 'Stop'
if ($ExecuteBootstrap -and -not $Bootstrap) { throw 'ExecuteBootstrap requires Bootstrap.' }
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
$originalTemp = [Environment]::GetEnvironmentVariable('TEMP', 'Process')
$originalTmp = [Environment]::GetEnvironmentVariable('TMP', 'Process')
$gitRoot = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'Git'
$trustedGit = Join-Path $gitRoot 'cmd/git.exe'
$gitCore = Join-Path $gitRoot 'mingw64/bin/git.exe'
$trustedGitPins = [Collections.Generic.List[IDisposable]]::new()
$originalPath = $env:PATH
try {
    $env:TEMP = $evidenceRoot
    $env:TMP = $evidenceRoot
    foreach ($path in @($gitRoot, (Join-Path $gitRoot 'cmd'), (Join-Path $gitRoot 'mingw64'),
            (Join-Path $gitRoot 'mingw64/bin'), $trustedGit, $gitCore)) {
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Trusted Git path cannot contain a reparse point.'
        }
    }
    foreach ($path in @($trustedGit, $gitCore)) {
        $trustedGitPins.Add([IO.FileStream]::new($path, [IO.FileMode]::Open,
                [IO.FileAccess]::Read, [IO.FileShare]::Read))
        $signature = Get-AuthenticodeSignature -FilePath $path
        if ($signature.Status -ne 'Valid' -or
            $signature.SignerCertificate.Thumbprint -cne '3EB14A3AEF84B7153E139397F0A49E2FAC662B0E') {
            throw 'Trusted Git executable signature is unavailable or unexpected.'
        }
    }
    $env:PATH = (Join-Path $gitRoot 'cmd') + [IO.Path]::PathSeparator + $originalPath
    $resolvedGit = Get-Command git -ErrorAction Stop
    if ($resolvedGit.CommandType -ne 'Application' -or $resolvedGit.Source -cne $trustedGit) {
        throw 'Certificate helper commands cannot resolve the trusted Git executable.'
    }
$planIdentity = Get-Content -LiteralPath $Plan -Raw | ConvertFrom-Json
$sourceCommit = [string]$planIdentity.source_commit
if ($sourceCommit -cne $ReviewedSourceCommit -or
    ([string](& $trustedGit -C $repoRoot rev-parse --verify 'HEAD^{commit}')).Trim() -cne $sourceCommit) {
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
        $expected = ([string](& $trustedGit -C $repoRoot rev-parse --verify "${sourceCommit}:$relative")).Trim()
        $actual = ([string](& $trustedGit hash-object --no-filters -- $path)).Trim()
        if ($LASTEXITCODE -ne 0 -or $expected -notmatch '^[0-9a-f]{40}$' -or $actual -cne $expected) {
            throw 'Certificate helper bytes differ from the admitted source commit.'
        }
    }
    Import-Module (Join-Path $helperRoot 'Atlaso.WorkstationCleanup.psm1') -Force
    $helperPins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($helperRoot))
    Import-Module (Join-Path $helperRoot 'Atlaso.OnePasswordCredentials.psm1') -Force
    . (Join-Path $helperRoot 'Atlaso.WorkstationFirstBoot.ps1')
    Import-Module (Join-Path $helperRoot 'Atlaso.SourceSnapshot.psm1') -Force
    if (([string](& $trustedGit -C $repoRoot rev-parse --verify 'HEAD^{commit}')).Trim() -cne $sourceCommit) {
        throw 'Certificate helper source commit changed during import.'
    }
$runtime = Protect-AtlasoCertificatePythonRuntime -PythonPath $PythonPath -EvidenceRoot $evidenceRoot
try {
    $PythonPath = $runtime.Executable
    $importPaths = Invoke-AtlasoBoundedProcess -FilePath $PythonPath `
        -ArgumentList @('-I', '-S', '-B', '-c', 'import json,sys;print(json.dumps(sys.path))') `
        -TimeoutSeconds 15 -Action 'Certificate Python import-path verification'
    Assert-AtlasoCertificatePythonImportPaths -Runtime $runtime -ImportPathJson $importPaths
    $snapshot = New-AtlasoCertificateInspectorSnapshot -RepositoryRoot $repoRoot -EvidenceRoot $evidenceRoot `
        -SourceCommit ([string]$planIdentity.source_commit) -TaskId ([string]$planIdentity.task_id)
    try {
    foreach ($pin in (Protect-AtlasoCertificateProofInputs -Plan $Plan -EvidenceRoot $evidenceRoot)) {
        $snapshot.Pins.Add($pin)
    }
    $scriptPath = Join-Path $snapshot.Root $(if ($Bootstrap) { 'scripts/interop/certificate_iso_bootstrap.py' } else { 'scripts/interop/certificate_peer_proof.py' })
    $scriptArguments = if ($Bootstrap) {
        @('--plan', $Plan, '--output-directory', [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($AddressEvidence)))
    } else { @('--plan', $Plan, '--address-output', $AddressEvidence, '--runtime-output', $RuntimeEvidence) }
    $arguments = New-AtlasoCertificatePythonArguments -Runtime $runtime -ScriptPath $scriptPath `
        -ScriptArguments $scriptArguments
    Invoke-AtlasoBoundedProcess -FilePath $PythonPath -ArgumentList ($arguments + '--preflight-only') `
        -TimeoutSeconds 30 -Action 'Certificate original peer admission' -DiscardOutput | Out-Null
    $null = Assert-AtlasoSourceSnapshot -Root $snapshot.Root -ExpectedSha256 $snapshot.Sha256 `
        -ExpectedFileCount $snapshot.FileCount
    if ($ExecuteBootstrap) { $arguments += '--execute' }
    $pair = $null
    $plain = $null
    $protectedPeerKey = $null
    $peerPlain = $null
    try {
        if ([string]$planIdentity.peer_transport.authentication_mode -ceq 'dpapi-task-key') {
            $keyPath = [string]$planIdentity.peer_key.path
            $null = Assert-AtlasoOnePasswordServiceAccountTokenFile -Path $keyPath
            $keyCreation = Get-Content -LiteralPath $planIdentity.peer_key_creation.path -Raw | ConvertFrom-Json
            if ([Atlaso.WorkstationFileIdentity]::Get($keyPath) -cne [string]$keyCreation.key_filesystem_identity) {
                throw 'Original protected peer key file was replaced.'
            }
            if ((Get-FileHash -LiteralPath $keyPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne [string]$planIdentity.peer_key.sha256) {
                throw 'Protected peer key changed after admission.'
            }
            $protectedPeerKey = ConvertTo-SecureString -String ([IO.File]::ReadAllText($keyPath))
            $peerPlain = [Net.NetworkCredential]::new('', $protectedPeerKey).Password
        }
        $pair = Get-AtlasoOnePasswordCredentialPair -RepositoryRoot $repoRoot -EnvironmentId $EnvironmentId `
            -OnePasswordServiceAccountTokenFile (Join-Path $repoRoot '.atlaso-local/onepassword-service-account-token.dpapi') `
            -OnePasswordPython $PythonPath -TimeoutSeconds 300 -ConsumerDescription 'Certificate private address observations'
        $plain = [Net.NetworkCredential]::new('', $pair.AdminPassword).Password
        Invoke-AtlasoBoundedProcess -FilePath $PythonPath -ArgumentList $arguments `
            -EnvironmentVariables @{ ATLASO_NATIVE_ADMIN = $plain; ATLASO_NATIVE_PEER_KEY = $peerPlain; TEMP = $evidenceRoot; TMP = $evidenceRoot } `
            -TimeoutSeconds 900 -Action 'Certificate private address observations' -DiscardOutput | Out-Null
    } finally {
        $plain = $null
        $peerPlain = $null
        if ($protectedPeerKey) { $protectedPeerKey.Dispose() }
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
} finally {
    $env:PATH = $originalPath
    [Environment]::SetEnvironmentVariable('TEMP', $originalTemp, 'Process')
    [Environment]::SetEnvironmentVariable('TMP', $originalTmp, 'Process')
    foreach ($pin in $trustedGitPins) { $pin.Dispose() }
}
