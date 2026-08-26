<#
.SYNOPSIS
Verify the Hyper-V lifecycle SecureString bridge under Windows PowerShell 5.1.
.PARAMETER RepositoryRoot
Atlaso checkout containing the Hyper-V lifecycle runner.
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$runnerPath = Join-Path $RepositoryRoot 'scripts\windows\hyperv\run-lifecycle-test.ps1'
$runnerSource = Get-Content -LiteralPath $runnerPath -Raw
$functionMarker = 'function ConvertFrom-AtlasoSecureString'
$boundaryMarker = '# Plan-only execution consumes no credentials.'
$functionStart = $runnerSource.IndexOf($functionMarker, [StringComparison]::Ordinal)
$functionEnd = $runnerSource.IndexOf($boundaryMarker, $functionStart, [StringComparison]::Ordinal)
if ($functionStart -lt 0 -or $functionEnd -le $functionStart) {
    throw 'Unable to locate the bounded SecureString compatibility helper.'
}

# Evaluate only the helper so this test does not import Hyper-V or mutate host state.
. ([scriptblock]::Create($runnerSource.Substring($functionStart, $functionEnd - $functionStart)))

$fixture = [SecureString]::new()
foreach ($character in 'fixture-value'.ToCharArray()) {
    $fixture.AppendChar($character)
}
$fixture.MakeReadOnly()
if ((ConvertFrom-AtlasoSecureString -Value $fixture) -cne 'fixture-value') {
    throw 'The Windows PowerShell-compatible SecureString conversion returned the wrong value.'
}

# Planning must remain credential-free in both launchers and runners. These
# source contracts avoid importing Hyper-V or VMware modules on CI hosts.
foreach ($provider in @('hyperv', 'vmware')) {
    $launcherSource = Get-Content -LiteralPath (
        Join-Path $RepositoryRoot "scripts\windows\$provider\invoke-lifecycle-test.ps1"
    ) -Raw
    if ($launcherSource -notmatch '(?s)if \(-not \$PlanOnly\) \{\s+if \(\$null -eq \$AdminPassword\).*?Read-Host') {
        throw "$provider lifecycle planning is not guarded from password prompting."
    }
    if ($launcherSource -notmatch '(?s)\$secretBundlePath = ['']{2}\s+(?:try \{\s+)?if \(-not \$PlanOnly\).*?Export-Clixml') {
        throw "$provider lifecycle planning is not guarded from secret-bundle creation."
    }
    if ($provider -eq 'vmware' -and
        $launcherSource -notmatch '(?s)\$secretBundlePath = ['']{2}\s+try \{.*?Export-Clixml.*?finally \{.*?Remove-Item -LiteralPath \$secretBundlePath') {
        throw 'VMware lifecycle secret-bundle serialization is not enclosed by cleanup.'
    }
    if ($provider -eq 'vmware' -and
        $launcherSource -notmatch 'if \(-not \(\$OidcOnly -or \$RoutingWanOnly\) -and \$null -eq \$VcfBackupPassword\)') {
        throw 'Focused VMware lifecycle runs still prompt for the unrelated VCF Backup credential.'
    }
    if ($provider -eq 'vmware' -and
        $launcherSource -notmatch 'Remove-Item -LiteralPath \$secretBundlePath -Force -ErrorAction Stop') {
        throw 'VMware lifecycle secret-bundle cleanup is not terminating.'
    }

    $providerRunnerSource = Get-Content -LiteralPath (
        Join-Path $RepositoryRoot "scripts\windows\$provider\run-lifecycle-test.ps1"
    ) -Raw
    if ($providerRunnerSource -notmatch "\[string\]\`$SecretBundlePath = ''" -or
        $providerRunnerSource -notmatch '(?s)if \(-not \$PlanOnly\).*?Import-Clixml -LiteralPath \$SecretBundlePath') {
        throw "$provider lifecycle runner still requires a secret bundle for plan-only execution."
    }
}

Write-Host 'Hyper-V lifecycle SecureString compatibility test passed.'
