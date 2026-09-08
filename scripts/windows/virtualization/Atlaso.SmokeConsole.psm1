<#
.SYNOPSIS
Creates isolated, concealed 1Password credentials for bounded diagnostic smoke runs.
#>
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '../vmware/Atlaso.WorkstationFirstBoot.ps1')
Import-Module (Join-Path $PSScriptRoot '../vmware/Atlaso.OnePasswordCredentials.psm1') -Force

<#
.SYNOPSIS
Checks plugin authorization before any diagnostic build or staging work.
.PARAMETER RepoRoot
Exact source checkout containing the credential helper.
.PARAMETER EnvironmentId
Pinned Atlaso Environment identity.
#>
function Assert-AtlasoSmokeConsoleAvailable {
    param([Parameter(Mandatory)][string]$RepoRoot, [Parameter(Mandatory)][string]$EnvironmentId)
    Assert-AtlasoOnePasswordEnvironmentId -EnvironmentId $EnvironmentId
    $plugin = (Get-Command 1password-mcp -ErrorAction Stop).Source
    $python = (Get-Command python -ErrorAction Stop).Source
    Invoke-AtlasoBoundedStreamingProcess -FilePath $python -ArgumentList @(
        '-B', (Join-Path $RepoRoot 'scripts/virtualization/smoke_console_credential.py'),
        '--plugin', $plugin, '--environment-id', $EnvironmentId, '--check'
    ) -TimeoutSeconds 120 -Action '1Password console preflight' | Out-Null
}

<#
.SYNOPSIS
Publishes one per-run credential and returns only its protected PowerShell object.
.PARAMETER RepoRoot
Exact source checkout containing the bounded credential helper.
.PARAMETER Operation
Existing verified prerelease operation root for the durable non-secret handoff.
.PARAMETER EnvironmentId
Pinned Atlaso Environment identity, never a secret value.
.PARAMETER RunId
Unique lowercase UUID without separators for this invocation.
.PARAMETER VmRoot
Exact fresh diagnostic VM directory recorded before credential publication.
#>
function New-AtlasoSmokeConsoleSession {
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][string]$Operation,
        [Parameter(Mandatory)][string]$EnvironmentId,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{32}$')][string]$RunId,
        [Parameter(Mandatory)][string]$VmRoot
    )
    Assert-AtlasoOnePasswordEnvironmentId -EnvironmentId $EnvironmentId
    $plugin = (Get-Command 1password-mcp -ErrorAction Stop).Source
    $python = (Get-Command python -ErrorAction Stop).Source
    $variableName = 'ATLASO_SMOKE_CONSOLE_' + $RunId.ToUpperInvariant()
    $recordPath = Join-Path $Operation "smoke-console-$RunId.json"
    $bundlePath = Join-Path $Operation ".smoke-console-$RunId.dpapi.json"
    if ((Test-Path -LiteralPath $recordPath) -or (Test-Path -LiteralPath $bundlePath) -or
        (Test-Path -LiteralPath $VmRoot)) {
        throw 'Diagnostic console identity is already in use; existing state was preserved.'
    }
    $record = [ordered]@{
        schema_version=1; kind='atlaso-smoke-console'; run_id=$RunId
        variable=$variableName; environment='Atlaso'; account='root'; vm_root=$VmRoot
        state='publication-pending'; created_utc=[DateTimeOffset]::UtcNow.ToString('o')
        evidence_eligible=$false
    }
    Write-AtlasoDurableJsonFile -Path $recordPath -Payload $record
    $jobName = 'Local\Atlaso-SmokeConsole-' + $RunId
    $publisher = {
        param($ProcessJob)
        $record['job_name'] = $jobName
        $record['child_pid'] = $ProcessJob.RootProcess.Id
        $record['child_started'] = $ProcessJob.RootProcess.StartTime.ToUniversalTime().ToString('o')
        Write-AtlasoDurableJsonFile -Path $recordPath -Payload $record -Replace
    }
    try {
        Invoke-AtlasoBoundedStreamingProcess -FilePath $python -ArgumentList @(
            '-B', (Join-Path $RepoRoot 'scripts/virtualization/smoke_console_credential.py'),
            '--plugin', $plugin, '--environment-id', $EnvironmentId,
            '--run-id', $RunId, '--output', $bundlePath
        ) -TimeoutSeconds 120 -Action '1Password smoke console handoff' `
            -ProcessJobName $jobName -ProcessOwnershipPublisher $publisher | Out-Null
        $bundle = Get-Content -LiteralPath $bundlePath -Raw | ConvertFrom-Json
        $secure = ConvertTo-SecureString -String ([string]$bundle.ciphertext)
        $record['state'] = 'available'
        Write-AtlasoDurableJsonFile -Path $recordPath -Payload $record -Replace
        Write-Host "Diagnostic console: root; VM=$VmRoot; 1Password > Developer > Atlaso > $variableName"
        Write-Host "This diagnostic run cannot publish release evidence. Handoff record: $recordPath"
        return [pscustomobject]@{
            Credential=[PSCredential]::new('admin', $secure)
            Record=$record; RecordPath=$recordPath; Variable=$variableName
        }
    }
    finally {
        # This file contains DPAPI ciphertext only. Keep the non-secret handoff
        # record even after interruption; it binds any retained credential/VM.
        if (Test-Path -LiteralPath $bundlePath) {
            $item = Get-Item -LiteralPath $bundlePath -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'Console credential ciphertext path changed; preserved for recovery.'
            }
            Remove-Item -LiteralPath $bundlePath
        }
    }
}

<#
.SYNOPSIS
Records credential retirement only after the smoke cleanup returned and its VM is absent.
.PARAMETER Session
Exact handoff returned by New-AtlasoSmokeConsoleSession.
.PARAMETER CleanupVerified
True only when the smoke's exact provider and filesystem cleanup completed.
#>
function Complete-AtlasoSmokeConsoleSession {
    param([Parameter(Mandatory)][object]$Session, [bool]$CleanupVerified = $false)
    $Session.Record['state'] = if (-not $CleanupVerified -or (Test-Path -LiteralPath $Session.Record.vm_root)) {
        'cleanup-required'
    } else { 'vm-absent-credential-retired' }
    Write-AtlasoDurableJsonFile -Path $Session.RecordPath -Payload $Session.Record -Replace
    $Session.Credential.Password.Dispose()
    Write-Host "Console handoff $($Session.Record.run_id): $($Session.Record.state)."
}

Export-ModuleMember -Function Assert-AtlasoSmokeConsoleAvailable, New-AtlasoSmokeConsoleSession, Complete-AtlasoSmokeConsoleSession
