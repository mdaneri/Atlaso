<#
.SYNOPSIS
Run the Atlaso development-CA child with a DPAPI-protected service-account token.

.DESCRIPTION
Decrypts the token only in this bounded PowerShell child, supplies
OP_SERVICE_ACCOUNT_TOKEN only to the descendant 1Password CLI process, and
clears it on every exit path.

.PARAMETER TokenFile
Current-user DPAPI ciphertext file containing the service-account token.

.PARAMETER OpPath
Exact verified 1Password CLI executable.

.PARAMETER EnvironmentId
Opaque ID of the pinned Atlaso Environment.

.PARAMETER Action
Validate the signer or stage it in the newly created VMX.

.PARAMETER CertificatePath
Exact checked-in public development root certificate.

.PARAMETER VmxPath
Exact newly created VMX required by the Stage action.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$TokenFile,
    [Parameter(Mandatory = $true)][string]$OpPath,
    [Parameter(Mandatory = $true)][string]$EnvironmentId,
    [Parameter(Mandatory = $true)][ValidateSet('Validate', 'Stage')][string]$Action,
    [Parameter(Mandatory = $true)][string]$CertificatePath,
    [AllowEmptyString()][string]$VmxPath = ''
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Atlaso.OnePasswordCredentials.psm1') -Force

$serviceAccountTokenText = $null
$exitCode = 1
$env:OP_SERVICE_ACCOUNT_TOKEN = $null
try {
    $resolvedTokenFile = Assert-AtlasoOnePasswordServiceAccountTokenFile -Path $TokenFile
    $tokenCiphertext = [System.IO.File]::ReadAllText($resolvedTokenFile)
    $tokenSecureString = ConvertTo-SecureString -String $tokenCiphertext
    $serviceAccountTokenText = ConvertFrom-SecureString `
        -SecureString $tokenSecureString `
        -AsPlainText
    if ($serviceAccountTokenText -notmatch '^ops_[A-Za-z0-9_-]{80,8188}$') {
        throw 'The current-user DPAPI 1Password service-account token is invalid.'
    }
    $childPath = Join-Path $PSScriptRoot 'Invoke-AtlasoDevelopmentCaSecret.ps1'
    $arguments = @(
        'run', '--environment', $EnvironmentId, '--',
        (Get-Process -Id $PID).Path, '-NoProfile', '-NonInteractive', '-File', $childPath,
        '-Action', $Action, '-CertificatePath', $CertificatePath
    )
    if ($Action -eq 'Stage') {
        $arguments += @('-VmxPath', $VmxPath)
    }
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $OpPath
    $startInfo.UseShellExecute = $false
    foreach ($argument in $arguments) {
        [void]$startInfo.ArgumentList.Add($argument)
    }
    $startInfo.Environment['OP_SERVICE_ACCOUNT_TOKEN'] = $serviceAccountTokenText
    $process = [System.Diagnostics.Process]::Start($startInfo)
    [void]$startInfo.Environment.Remove('OP_SERVICE_ACCOUNT_TOKEN')
    $serviceAccountTokenText = $null
    $process.WaitForExit()
    $exitCode = $process.ExitCode
    $process.Dispose()
}
finally {
    $serviceAccountTokenText = $null
    $tokenCiphertext = $null
    $env:OP_SERVICE_ACCOUNT_TOKEN = $null
}
exit $exitCode
