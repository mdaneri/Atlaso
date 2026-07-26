[CmdletBinding()]
param(
    [ValidatePattern('^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$')]
    [string] $Version,

    [string] $Root = (Split-Path -Parent $PSScriptRoot)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$versionArguments = @(
    (Join-Path $PSScriptRoot 'version.py')
    'bump'
    '--root'
    $Root
)
if ($PSBoundParameters.ContainsKey('Version')) {
    $versionArguments += @('--version', $Version)
}

& python @versionArguments
if ($LASTEXITCODE -ne 0) {
    throw "Atlaso version update failed with exit code $LASTEXITCODE."
}
