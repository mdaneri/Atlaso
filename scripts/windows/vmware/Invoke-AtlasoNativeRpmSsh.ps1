<#
.SYNOPSIS
Start the isolated native RPM SSH proxy inside the original refresh process job.
.PARAMETER ContextPath
Immutable public task/source-bound SSH context published by the refresh owner.
.PARAMETER PythonPath
Selected Windows CPython 3.14 executable for the isolated SDK child.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ContextPath,
    [Parameter(Mandatory)][string]$PythonPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$stage = 'context'
trap {
    # SDK and DPAPI exceptions may carry sensitive details. Expose only the
    # fixed stage so the owner can diagnose startup without logging an exception.
    [Console]::Out.WriteLine((@{kind = 'native-ssh-start-failure'; stage = $stage} | ConvertTo-Json -Compress))
    exit 2
}
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..')).TrimEnd('\', '/')
. (Join-Path $PSScriptRoot 'Atlaso.WorkstationFirstBoot.ps1')
Import-Module (Join-Path $PSScriptRoot 'Atlaso.OnePasswordCredentials.psm1') -Force
$context = Get-Content -LiteralPath $ContextPath -Raw | ConvertFrom-Json
if ($context.task_id -cne $env:CODEX_THREAD_ID -or $context.repository_root -cne $repositoryRoot) {
    throw 'Native SSH context differs from the actual task checkout.'
}
$stage = 'job'
$job = Open-AtlasoBoundedProcessJob -ProcessJobName $context.process_job_name
if (-not $job -or -not $job.ContainsProcess((Get-Process -Id $PID))) {
    if ($job) { $job.Dispose() }
    throw 'Native SSH requires the original enclosing refresh process job.'
}
$stage = 'credential-configuration'
$selector = Resolve-AtlasoOnePasswordEnvironmentId -RepositoryRoot $repositoryRoot
Assert-AtlasoOnePasswordEnvironmentId -EnvironmentId $selector
$tokenPath = Resolve-AtlasoOnePasswordServiceAccountTokenFile -RepositoryRoot $repositoryRoot `
    -TokenFile (Join-Path $repositoryRoot '.atlaso-local/onepassword-service-account-token.dpapi')
$stage = 'runtime'
$runtime = Initialize-AtlasoOnePasswordSdkRuntime -PythonCommand $PythonPath `
    -RepositoryRoot $repositoryRoot -BridgeRoot (Join-Path $context.directory ('sdk-' + $context.remote_id.Substring(0, 8))) -TimeoutSeconds 180
$stage = 'dpapi'
$protected = ConvertTo-SecureString -String ([IO.File]::ReadAllText($tokenPath))
$tokenText = $null
$process = [Diagnostics.Process]::new()
try {
    $tokenText = ConvertFrom-SecureString -SecureString $protected -AsPlainText
    if ($tokenText -notmatch '^ops_[A-Za-z0-9_-]{80,8188}$') { throw 'Native SSH service-account token is invalid.' }
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $PythonPath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    # Windows PowerShell-host standard handles are not reliably inherited by
    # a venv launcher. Relay raw pipes asynchronously so neither side can cross
    # the original-receipt barrier by buffering an entire child execution.
    foreach ($argument in @('-I', '-S', '-B', (Join-Path $repositoryRoot 'scripts/native_rpm_ssh.py'),
            '--context', $ContextPath, '--dependency-path', $runtime)) {
        $startInfo.ArgumentList.Add($argument)
    }
    $startInfo.Environment['OP_SERVICE_ACCOUNT_TOKEN'] = $tokenText
    $startInfo.Environment['ATLASO_NATIVE_ENVIRONMENT_ID'] = $selector
    $process.StartInfo = $startInfo
    $stage = 'proxy'
    if (-not $process.Start()) { throw 'Native SSH proxy did not start.' }
    $startInfo.Environment.Remove('OP_SERVICE_ACCOUNT_TOKEN') | Out-Null
    $startInfo.Environment.Remove('ATLASO_NATIVE_ENVIRONMENT_ID') | Out-Null
    $tokenText = $null
    $outputCopy = $process.StandardOutput.BaseStream.CopyToAsync([Console]::OpenStandardOutput())
    $inputCopy = [Console]::OpenStandardInput().CopyToAsync($process.StandardInput.BaseStream)
    $errorCopy = $process.StandardError.BaseStream.CopyToAsync([IO.Stream]::Null)
    $remaining = [Math]::Max(1, [Math]::Ceiling($context.deadline_epoch - [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()))
    if (-not $process.WaitForExit([int]([Math]::Min($remaining, 21600) * 1000))) {
        $process.Kill($true)
        if (-not $process.WaitForExit(10000)) { throw 'Native SSH proxy termination is unproven.' }
        throw 'Native SSH proxy exceeded the original phase deadline.'
    }
    if (-not $outputCopy.Wait(10000) -or -not $errorCopy.Wait(10000)) {
        throw 'Native SSH protocol stream completion is unproven.'
    }
    # The owner closes its input after receiving the terminal record. Do not
    # block cleanup on an idle parent writer after the proxy has already exited.
    if ($inputCopy.IsFaulted) { throw 'Native SSH owner input stream failed.' }
    exit $process.ExitCode
}
finally {
    $tokenText = $null
    $protected.Dispose()
    $process.Dispose()
    $job.Dispose()
}
