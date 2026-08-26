<#
.SYNOPSIS
Validates the Windows 1Password SDK deployment bridge contract.
.PARAMETER RepositoryRoot
Atlaso checkout containing the deployment script under test.
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
Requires a script block to throw.
.PARAMETER Script
Script block expected to fail.
.PARAMETER Message
Failure message when no exception is raised.
#>
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

$deployPath = Join-Path $RepositoryRoot 'scripts\windows\vmware\deploy-wheel.ps1'
$deploySource = Get-Content -LiteralPath $deployPath -Raw
$executionMarker = '$resolvedRepoRoot = Resolve-RepoRoot -Path $RepoRoot'
$executionIndex = $deploySource.IndexOf($executionMarker, [System.StringComparison]::Ordinal)
if ($executionIndex -lt 0) {
    throw 'Unable to locate the deploy-wheel execution boundary.'
}
Invoke-Expression $deploySource.Substring(0, $executionIndex)

Assert-OnePasswordEnvironmentId -EnvironmentId 'blgexucrwfr2dtsxe2q4uu7dp4'
Assert-OnePasswordAccount -Account 'example.1password.com'
Assert-Throws {
    Assert-OnePasswordEnvironmentId -EnvironmentId 'not safe'
} 'An unsafe Environment ID must fail closed.'
Assert-Throws {
    Assert-OnePasswordAccount -Account "bad`naccount"
} 'A control-character account must fail closed.'

$scriptText = $deploySource
if ($scriptText.Contains('ATLASO_DEPLOY_SSH_PASSWORD', [System.StringComparison]::Ordinal) -or
    $scriptText.Contains('ATLASO_DEPLOY_RUNTIME_PASSWORD', [System.StringComparison]::Ordinal)) {
    throw 'The legacy or parent-process password fallback must remain unavailable.'
}
if (-not $scriptText.Contains('from onepassword import Client, DesktopAuth', [System.StringComparison]::Ordinal) -or
    -not $scriptText.Contains('onepassword.environments.get_variables(args.onepassword_environment_id)', [System.StringComparison]::Ordinal)) {
    throw 'The bounded deployment child must use the supported 1Password SDK Environments API.'
}
if (-not $scriptText.Contains('$script:PasswordDeployLockName = ''requirements-onepassword-deploy.lock''', [System.StringComparison]::Ordinal) -or
    -not $scriptText.Contains("'--no-index'", [System.StringComparison]::Ordinal) -or
    -not $scriptText.Contains("'--require-hashes'", [System.StringComparison]::Ordinal) -or
    -not $scriptText.Contains('''-r'', $lockPath', [System.StringComparison]::Ordinal)) {
    throw 'The bounded deployment child must install the vetted SDK runtime from the hashed lock and staged wheels only.'
}
if (-not $scriptText.Contains('[string]$OnePasswordPython =', [System.StringComparison]::Ordinal) -or
    -not $scriptText.Contains('$version -notmatch ''^3\.1[0-3]$''', [System.StringComparison]::Ordinal) -or
    -not $scriptText.Contains('-PythonCommand $resolvedOnePasswordPython', [System.StringComparison]::Ordinal)) {
    throw 'Password deployment must use an explicit CPython runtime with a supported 1Password SDK Windows wheel.'
}
if (-not $scriptText.Contains("'-I', '-S', $pythonDeploy", [System.StringComparison]::Ordinal) -or
    -not $scriptText.Contains("'--dependency-path', $pythonDependencyPath", [System.StringComparison]::Ordinal) -or
    $scriptText.Contains('$env:PYTHONPATH', [System.StringComparison]::Ordinal)) {
    throw 'The bounded Python child must disable startup hooks and load only its explicit dependency path.'
}
if (-not $scriptText.Contains('len(matches) != 1 or not matches[0].masked or not matches[0].value', [System.StringComparison]::Ordinal)) {
    throw 'Password deployment must require exactly one non-empty concealed variable.'
}
if (-not $scriptText.Contains('1Password desktop authorization or exact Environment access failed', [System.StringComparison]::Ordinal)) {
    throw 'Authorization and Environment failures must fail closed without secret output.'
}
if (($scriptText.Split('await asyncio.wait_for(', [System.StringSplitOptions]::None).Count - 1) -lt 2 -or
    ($scriptText.Split('timeout=args.timeout', [System.StringSplitOptions]::None).Count - 1) -lt 2) {
    throw 'Desktop authorization and Environment retrieval must each use the bounded deployment timeout.'
}
if ($scriptText.Contains("'run', '--environment'", [System.StringComparison]::Ordinal) -or
    $scriptText.Contains('Assert-OnePasswordEnvironmentSupport', [System.StringComparison]::Ordinal)) {
    throw 'The stable bridge must not depend on the beta-only op run Environment flag.'
}
if (-not $scriptText.Contains('paramiko.RejectPolicy()', [System.StringComparison]::Ordinal)) {
    throw 'Password-backed deployment must reject unknown SSH host keys.'
}
if (-not $scriptText.Contains('transport.get_security_options()', [System.StringComparison]::Ordinal) -or
    -not $scriptText.Contains('security_options.key_types', [System.StringComparison]::Ordinal)) {
    throw 'Password-backed deployment must prefer the recorded SSH host-key type before negotiation.'
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
