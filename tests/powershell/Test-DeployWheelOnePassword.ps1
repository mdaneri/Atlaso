[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

$ErrorActionPreference = 'Stop'

function Assert-Throws {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Script,
        [Parameter(Mandatory = $true)][string]$Message
    )

    try {
        & $Script
    } catch {
        return
    }
    throw $Message
}

function Assert-Contains {
    param(
        [Parameter(Mandatory = $true)][string[]]$Actual,
        [Parameter(Mandatory = $true)][string]$Expected,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if (-not ($Actual -contains $Expected)) {
        throw "$Message Expected '$Expected'."
    }
}

$deployPath = Join-Path $RepositoryRoot 'scripts\windows\vmware\deploy-wheel.ps1'
$deploySource = Get-Content -LiteralPath $deployPath -Raw
$executionMarker = '$resolvedRepoRoot = Resolve-RepoRoot -Path $RepoRoot'
$executionIndex = $deploySource.IndexOf($executionMarker, [System.StringComparison]::Ordinal)
if ($executionIndex -lt 0) {
    throw 'Unable to locate the deploy-wheel execution boundary.'
}
Invoke-Expression $deploySource.Substring(0, $executionIndex)

Assert-OnePasswordEnvironmentId -EnvironmentId 'blgexucrwfr2dtsxe2q4uu7dp4'
Assert-OnePasswordEnvironmentSupport -RunHelp "Flags:`n  --environment string"
Assert-Throws {
    Assert-OnePasswordEnvironmentId -EnvironmentId 'not safe'
} 'An unsafe Environment ID must fail closed.'
Assert-Throws {
    Assert-OnePasswordEnvironmentSupport -RunHelp 'Flags:`n  --env-file string'
} 'A CLI without Environment loading must fail closed.'

$boundParameters = @{
    OnePasswordEnvironmentId = 'blgexucrwfr2dtsxe2q4uu7dp4'
    IpAddress = '192.0.2.10'
    SkipBuild = [System.Management.Automation.SwitchParameter]::new($true)
}
$childArguments = Get-OnePasswordChildArguments `
    -BoundParameters $boundParameters `
    -ScriptPath 'C:\repo\deploy-wheel.ps1'
Assert-Contains -Actual $childArguments -Expected '-OnePasswordEnvironmentChild' -Message 'The child marker must be forwarded.'
Assert-Contains -Actual $childArguments -Expected '-IpAddress' -Message 'Bound deployment arguments must be forwarded.'
Assert-Contains -Actual $childArguments -Expected '192.0.2.10' -Message 'Bound deployment values must be forwarded.'
if ($childArguments -contains 'blgexucrwfr2dtsxe2q4uu7dp4') {
    throw 'The Environment ID must not be forwarded to the bridge child.'
}

$OnePasswordEnvironmentChild = $false
Remove-Item Env:\DEFAULT_ADMIN_PASSWORD -ErrorAction SilentlyContinue
if ((Resolve-OnePasswordChildPassword) -ne '') {
    throw 'The ordinary key/agent path must not consume DEFAULT_ADMIN_PASSWORD.'
}
$OnePasswordEnvironmentChild = $true
Assert-Throws {
    Resolve-OnePasswordChildPassword
} 'A missing DEFAULT_ADMIN_PASSWORD must fail closed.'
$env:DEFAULT_ADMIN_PASSWORD = 'fixture-secret-is-not-output'
try {
    if ((Resolve-OnePasswordChildPassword) -ne 'fixture-secret-is-not-output') {
        throw 'The bridge child did not consume the named Environment variable.'
    }
} finally {
    Remove-Item Env:\DEFAULT_ADMIN_PASSWORD -ErrorAction SilentlyContinue
}

$scriptText = $deploySource
if ($scriptText.Contains('ATLASO_DEPLOY_SSH_PASSWORD', [System.StringComparison]::Ordinal)) {
    throw 'The legacy ATLASO_DEPLOY_SSH_PASSWORD fallback must remain unavailable.'
}
if (-not $scriptText.Contains('paramiko.RejectPolicy()', [System.StringComparison]::Ordinal)) {
    throw 'Password-backed deployment must reject unknown SSH host keys.'
}
if (-not $scriptText.Contains('Secret redaction failed', [System.StringComparison]::Ordinal)) {
    throw 'Password-backed deployment must fail closed when output redaction fails.'
}

Write-Output 'Deploy wheel 1Password bridge tests passed.'
