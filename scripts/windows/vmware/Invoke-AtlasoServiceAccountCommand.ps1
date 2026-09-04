<#
.SYNOPSIS
Run one exact child command with a DPAPI-protected 1Password service-account token.

.DESCRIPTION
Reads a non-secret JSON argument array, decrypts the token only in this child,
sets OP_SERVICE_ACCOUNT_TOKEN only for the descendant command, and clears it on
every exit path. The token is never accepted as an argument or written to output.

.PARAMETER TokenFile
Current-user DPAPI ciphertext file containing the service-account token.

.PARAMETER RepositoryRoot
Atlaso checkout that owns the permitted .atlaso-local token storage boundary.

.PARAMETER FilePath
Exact executable to invoke.

.PARAMETER ArgumentsPath
Exact JSON file containing a string array of non-secret child arguments.

.PARAMETER WorkingDirectory
Exact working directory for the child command.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$TokenFile,
    [Parameter(Mandatory = $true)][string]$RepositoryRoot,
    [Parameter(Mandatory = $true)][string]$FilePath,
    [Parameter(Mandatory = $true)][string]$ArgumentsPath,
    [Parameter(Mandatory = $true)][string]$WorkingDirectory
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Atlaso.OnePasswordCredentials.psm1') -Force

$serviceAccountTokenText = $null
$exitCode = 1
$env:OP_SERVICE_ACCOUNT_TOKEN = $null
try {
    $resolvedTokenFile = Resolve-AtlasoOnePasswordServiceAccountTokenFile `
        -TokenFile $TokenFile `
        -RepositoryRoot $RepositoryRoot
    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $ArgumentsPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $WorkingDirectory -PathType Container)) {
        throw 'The service-account child command contract is invalid.'
    }
    $argumentPayload = [System.IO.File]::ReadAllText($ArgumentsPath) | ConvertFrom-Json
    if ($argumentPayload -isnot [System.Collections.IEnumerable] -or
        $argumentPayload -is [string] -or @($argumentPayload).Count -gt 512) {
        throw 'The service-account child argument contract is invalid.'
    }
    $arguments = @($argumentPayload | ForEach-Object { [string]$_ })

    $tokenCiphertext = [System.IO.File]::ReadAllText($resolvedTokenFile)
    $tokenSecureString = ConvertTo-SecureString -String $tokenCiphertext
    $serviceAccountTokenText = ConvertFrom-SecureString `
        -SecureString $tokenSecureString `
        -AsPlainText
    if ($serviceAccountTokenText -notmatch '^ops_[A-Za-z0-9_-]{80,8188}$') {
        throw 'The current-user DPAPI 1Password service-account token is invalid.'
    }
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.WorkingDirectory = $WorkingDirectory
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
