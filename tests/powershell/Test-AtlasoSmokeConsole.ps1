<#
.SYNOPSIS
Verifies protected console handoff and fail-closed retirement without external accounts.
.PARAMETER RepositoryRoot
Exact source checkout containing the console module.
#>
[CmdletBinding()]
param([string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) {
    Write-Host 'DPAPI handoff integration is Windows-only; Python tests cover the portable publication boundary.'
    return
}
$root = Join-Path $RepositoryRoot ('test-results/console-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
Import-Module (Join-Path $RepositoryRoot 'scripts/windows/virtualization/Atlaso.SmokeConsole.psm1') -Force
$module = Get-Module Atlaso.SmokeConsole
try {
    & $module {
        Set-Item function:script:Assert-AtlasoOnePasswordEnvironmentId -Value { }
        Set-Item function:script:Get-Command -Value { [pscustomobject]@{ Source='fixture-executable' } }
        Set-Item function:script:Invoke-AtlasoBoundedStreamingProcess -Value {
            param($FilePath, $ArgumentList, $TimeoutSeconds, $Action, $ProcessJobName, $ProcessOwnershipPublisher)
            if ($TimeoutSeconds -ne 120 -or $ProcessJobName -notlike 'Local\Atlaso-SmokeConsole-*') {
                throw 'Console child did not receive the bounded per-run process identity.'
            }
            $index = [Array]::IndexOf($ArgumentList, '--output')
            $secure = [SecureString]::new()
            foreach ($character in 'Fixture-only!123'.ToCharArray()) { $secure.AppendChar($character) }
            try {
                @{ ciphertext=(ConvertFrom-SecureString -SecureString $secure) } |
                    ConvertTo-Json | Set-Content -LiteralPath $ArgumentList[$index + 1]
            }
            finally { $secure.Dispose() }
        }
    }
    $run = [guid]::NewGuid().ToString('N')
    $vmRoot = Join-Path $root 'vm'
    $session = New-AtlasoSmokeConsoleSession -RepoRoot $RepositoryRoot -Operation $root `
        -EnvironmentId 'fixture' -RunId $run -VmRoot $vmRoot
    if ($session.Credential.Password.Length -ne 16 -or $session.Record.evidence_eligible) {
        throw 'Console handoff returned an invalid credential or eligible release evidence.'
    }
    if (@(Get-ChildItem -LiteralPath $root -Filter '*.dpapi.json' -Force).Count) {
        throw 'Credential ciphertext exchange survived successful handoff.'
    }
    Complete-AtlasoSmokeConsoleSession -Session $session
    $record = Get-Content -LiteralPath $session.RecordPath -Raw | ConvertFrom-Json
    if ($record.state -cne 'cleanup-required') { throw 'Path absence alone retired a credential.' }
    if ((Get-Content -LiteralPath $session.RecordPath -Raw).Contains('Fixture-only!123')) {
        throw 'The durable handoff exposed credential content.'
    }
    $next = New-AtlasoSmokeConsoleSession -RepoRoot $RepositoryRoot -Operation $root `
        -EnvironmentId 'fixture' -RunId ([guid]::NewGuid().ToString('N')) -VmRoot $vmRoot
    if ($next.Variable -ceq $session.Variable) { throw 'Parallel runs shared a credential identity.' }
    Complete-AtlasoSmokeConsoleSession -Session $next -CleanupVerified $true
    $record = Get-Content -LiteralPath $next.RecordPath -Raw | ConvertFrom-Json
    if ($record.state -cne 'vm-absent-credential-retired') { throw 'Verified cleanup did not retire the credential.' }
}
finally {
    # No provider or external-account calls occur in this exclusively owned fixture.
    if (@(Get-Item -LiteralPath $root; Get-ChildItem -LiteralPath $root -Recurse -Force) |
        Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }) {
        throw 'Console fixture cleanup refused a reparse point.'
    }
    Remove-Item -LiteralPath $root -Recurse
}
Write-Host 'Console handoff and retirement regression tests passed.'
