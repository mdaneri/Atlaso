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

function Assert-Equal {
    param(
        [Parameter(Mandatory = $true)]$Actual,
        [Parameter(Mandatory = $true)]$Expected,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if ($Actual -is [array] -or $Expected -is [array]) {
        if ([string]::Join("`n", [string[]]@($Actual)) -ne [string]::Join("`n", [string[]]@($Expected))) {
            throw "$Message Expected '$(@($Expected) -join ', ')' but got '$(@($Actual) -join ', ')' ."
        }
        return
    }
    if ($Actual -ne $Expected) {
        throw "$Message Expected '$Expected' but got '$Actual'."
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
Assert-OnePasswordEnvironmentSupport -RunHelp '--environment string'
Assert-Throws {
    Assert-OnePasswordEnvironmentId -EnvironmentId 'not safe'
} 'An unsafe Environment ID must fail closed.'
Assert-Throws {
    Assert-OnePasswordEnvironmentSupport -RunHelp '--env-file string'
} 'A CLI without Environment loading must fail closed.'
$script:capturedCommand = $null
function Resolve-OnePasswordCliPath { return 'op.exe' }
function Assert-OnePasswordEnvironmentSupport { }
function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string[]]$Arguments,
        [string]$WorkingDirectory = ''
    )
    $script:capturedCommand = @{
        FilePath = $FilePath
        Arguments = @($Arguments)
        WorkingDirectory = $WorkingDirectory
    }
}

Invoke-OnePasswordBoundedCommand `
    -EnvironmentId 'blgexucrwfr2dtsxe2q4uu7dp4' `
    -CommandPath 'python' `
    -Arguments @('helper.py', '--host', '192.0.2.10') `
    -WorkingDirectory 'C:\repo'
Assert-Equal -Actual $script:capturedCommand.FilePath -Expected 'op.exe' `
    -Message 'Password deployment must invoke the 1Password CLI.'
Assert-Equal -Actual $script:capturedCommand.Arguments -Expected @(
    'run', '--environment', 'blgexucrwfr2dtsxe2q4uu7dp4', '--', 'python', 'helper.py', '--host', '192.0.2.10'
) -Message 'The bounded deployment command must be the direct op run child with separate arguments.'
Assert-Equal -Actual $script:capturedCommand.WorkingDirectory -Expected 'C:\repo' `
    -Message 'The bounded deployment command must preserve its working directory.'

$env:DEFAULT_ADMIN_PASSWORD = 'caller-secret-is-not-output'
Assert-Throws {
    Invoke-OnePasswordBoundedCommand `
        -EnvironmentId 'blgexucrwfr2dtsxe2q4uu7dp4' `
        -CommandPath 'python' `
        -Arguments @('helper.py')
} 'A caller-provided DEFAULT_ADMIN_PASSWORD must fail closed.'
Remove-Item Env:\DEFAULT_ADMIN_PASSWORD -ErrorAction SilentlyContinue

$scriptText = $deploySource
if ($scriptText.Contains('ATLASO_DEPLOY_SSH_PASSWORD', [System.StringComparison]::Ordinal) -or
    $scriptText.Contains('ATLASO_DEPLOY_RUNTIME_PASSWORD', [System.StringComparison]::Ordinal)) {
    throw 'The legacy or parent-process password fallback must remain unavailable.'
}
if (-not $scriptText.Contains('DEFAULT_ADMIN_PASSWORD', [System.StringComparison]::Ordinal) -or
    -not $scriptText.Contains('os.environ.pop("DEFAULT_ADMIN_PASSWORD", "")', [System.StringComparison]::Ordinal)) {
    throw 'The bounded deployment child must consume and immediately clear the exact Environment variable.'
}
if (-not $scriptText.Contains("'-I', '-S', $pythonDeploy", [System.StringComparison]::Ordinal) -or
    -not $scriptText.Contains("'--dependency-path', $pythonDependencyPath", [System.StringComparison]::Ordinal) -or
    $scriptText.Contains('$env:PYTHONPATH', [System.StringComparison]::Ordinal)) {
    throw 'The bounded Python child must disable startup hooks and load only its explicit dependency path.'
}
if (-not $scriptText.Contains('Invoke-OnePasswordBoundedCommand', [System.StringComparison]::Ordinal)) {
    throw 'Password deployment must use the supported direct op run child handoff.'
}
if (-not $scriptText.Contains('paramiko.RejectPolicy()', [System.StringComparison]::Ordinal)) {
    throw 'Password-backed deployment must reject unknown SSH host keys.'
}
if (-not $scriptText.Contains('auth_interactive', [System.StringComparison]::Ordinal) -or
    -not $scriptText.Contains('connect_password_or_keyboard_interactive', [System.StringComparison]::Ordinal)) {
    throw 'Password-backed deployment must support keyboard-interactive SSH authentication.'
}
if (-not $scriptText.Contains('one[- ]?time', [System.StringComparison]::Ordinal) -or
    -not $scriptText.Contains('multi[- ]?factor', [System.StringComparison]::Ordinal) -or
    -not $scriptText.Contains('verification', [System.StringComparison]::Ordinal)) {
    throw 'Password-backed deployment must reject OTP and MFA keyboard-interactive prompts.'
}
if (-not $scriptText.Contains('auth_password(username, password, fallback=False)', [System.StringComparison]::Ordinal)) {
    throw 'Password-backed deployment must disable Paramiko interactive fallback before validating prompts.'
}
if (-not $scriptText.Contains('get_pty=False', [System.StringComparison]::Ordinal) -or
    -not $scriptText.Contains('shutdown_write()', [System.StringComparison]::Ordinal)) {
    throw 'Password-backed sudo handoff must remain noninteractive.'
}
if (-not $scriptText.Contains('ConvertTo-WindowsSshRemoteCommand', [System.StringComparison]::Ordinal) -or
    -not $scriptText.Contains('base64 -d | sh', [System.StringComparison]::Ordinal)) {
    throw 'Windows key-backed SSH must use the PowerShell login-shell transport wrapper.'
}
if (-not $scriptText.Contains('Secret redaction failed', [System.StringComparison]::Ordinal)) {
    throw 'Password-backed deployment must fail closed when output redaction fails.'
}
if ($scriptText.Contains('AnonymousPipe', [System.StringComparison]::Ordinal) -or
    $scriptText.Contains('OnePasswordBridgeHandle', [System.StringComparison]::Ordinal) -or
    $scriptText.Contains('OnePasswordBridgeChallenge', [System.StringComparison]::Ordinal) -or
    $scriptText.Contains('Get-CimInstance -ClassName Win32_Process', [System.StringComparison]::Ordinal)) {
    throw 'The credential handoff must not depend on a handle that op.exe cannot forward or forgeable process ancestry.'
}

Write-Output 'Deploy wheel 1Password bridge tests passed.'
