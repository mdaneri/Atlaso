<#
.SYNOPSIS
Exercise the normal VMware test VM development-CA bridge contract.

.PARAMETER RepositoryRoot
Atlaso checkout containing the wrapper under test.
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
Assert that one test action terminates.

.PARAMETER Action
Action expected to throw.

.PARAMETER Message
Failure message when the action succeeds.
#>
function Assert-Throws {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Message
    )
    try {
        & $Action
    }
    catch {
        return
    }
    throw $Message
}

$wrapperPath = Join-Path $RepositoryRoot 'scripts\windows\vmware\create-atlaso-test-vm.ps1'
$wrapperSource = Get-Content -LiteralPath $wrapperPath -Raw
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput(
    $wrapperSource,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors) {
    throw 'The normal test VM wrapper could not be parsed for bridge tests.'
}
foreach ($functionAst in $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
        }, $true)) {
    Invoke-Expression $functionAst.Extent.Text
}

<#
.SYNOPSIS
Hide the installed 1Password CLI for the missing-command test.

.PARAMETER Name
Command name requested by the helper under test.

.PARAMETER ErrorAction
Error preference accepted by the Get-Command compatibility signature.
#>
function Get-Command {
    param(
        [Parameter(Position = 0)][string]$Name,
        [System.Management.Automation.ActionPreference]$ErrorAction
    )
    return $null
}
Assert-Throws {
    Resolve-OnePasswordCliPath -CandidatePaths @() -PackageRoot ''
} 'A missing 1Password CLI must fail closed.'
Remove-Item Function:\Get-Command

Assert-Throws {
    Assert-OnePasswordDevelopmentCaBridge -EnvironmentId 'unsafe id' -OpPath 'ignored'
} 'Unsafe Environment IDs must fail closed.'

$fakeOp = Join-Path ([System.IO.Path]::GetTempPath()) "atlaso-fake-op-$([guid]::NewGuid().ToString('N')).ps1"
try {
    [System.IO.File]::WriteAllText(
        $fakeOp,
        "param([Parameter(ValueFromRemainingArguments=`$true)][string[]]`$Remaining)`n'--env-file only'",
        [System.Text.UTF8Encoding]::new($false)
    )
    Assert-Throws {
        Assert-OnePasswordDevelopmentCaBridge `
            -EnvironmentId 'blgexucrwfr2dtsxe2q4uu7dp4' `
            -OpPath $fakeOp
    } 'A CLI without op run --environment support must fail closed.'
}
finally {
    Remove-Item -LiteralPath $fakeOp -Force -ErrorAction SilentlyContinue
}

$env:ATLASO_DEVELOPMENT_ROOT_CA_PRIVATE_KEY = 'caller-secret'
try {
    Assert-Throws {
        Assert-OnePasswordDevelopmentCaBridge `
            -EnvironmentId 'blgexucrwfr2dtsxe2q4uu7dp4' `
            -OpPath 'ignored'
    } 'A caller-provided development signer must fail closed.'
}
finally {
    Remove-Item Env:\ATLASO_DEVELOPMENT_ROOT_CA_PRIVATE_KEY -ErrorAction SilentlyContinue
}

$childPath = Join-Path $RepositoryRoot 'scripts\windows\vmware\Invoke-AtlasoDevelopmentCaSecret.ps1'
$publicCertificatePath = Join-Path $RepositoryRoot (
    'image\vmware-workstation\development-trust\atlaso-development-root-ca.pem'
)
$childOutput = & (Get-Process -Id $PID).Path `
    -NoLogo -NoProfile -NonInteractive -File $childPath `
    -Action Validate -CertificatePath $publicCertificatePath 2>&1
if ($LASTEXITCODE -eq 0) {
    throw 'The bounded child must reject an absent Environment signing key.'
}
if (($childOutput | Out-String) -match 'BEGIN PRIVATE KEY') {
    throw 'The bounded child failure must not expose private-key material.'
}

if ($wrapperSource -notmatch '\[switch\]\$WaitForIp = \$true') {
    throw 'Normal VMware test VM waiting must default to enabled.'
}
if ($wrapperSource -match '\[switch\]\$RootSshEnabled\s*=\s*\$true') {
    throw 'Root SSH must remain disabled by default.'
}
if ($wrapperSource.IndexOf('-Action Validate', [System.StringComparison]::Ordinal) -gt
    $wrapperSource.IndexOf("'prepare-networks.ps1'", [System.StringComparison]::Ordinal)) {
    throw 'Development CA validation must precede network preparation.'
}
foreach ($mutationMarker in @("'remove-atlaso-vm.ps1'", "'create-atlaso-vm.ps1'")) {
    if ($wrapperSource.IndexOf('-Action Validate', [System.StringComparison]::Ordinal) -gt
        $wrapperSource.IndexOf($mutationMarker, [System.StringComparison]::Ordinal)) {
        throw "Development CA validation must precede $mutationMarker."
    }
}
if ($wrapperSource -notmatch "certutil\.exe -f -user -addstore Root" -or
    $wrapperSource -match "certutil\.exe -user -delstore Root") {
    throw 'Windows trust must add the exact root idempotently without subject-wide deletion.'
}
if ($wrapperSource -notmatch "Wait-AtlasoWorkstationDevelopmentRootCaPrivateKeyScrub" -or
    $wrapperSource -notmatch "Automatic rollback also failed") {
    throw 'Unproven signing-key scrub must stop and safely roll back the new VM.'
}

$childSource = Get-Content -LiteralPath (
    Join-Path $RepositoryRoot 'scripts\windows\vmware\Invoke-AtlasoDevelopmentCaSecret.ps1'
) -Raw
if ($childSource.IndexOf(
        "SetEnvironmentVariable('ATLASO_DEVELOPMENT_ROOT_CA_PRIVATE_KEY', `$null)",
        [System.StringComparison]::Ordinal
    ) -gt $childSource.IndexOf('Assert-AtlasoDevelopmentRootCaMaterial', [System.StringComparison]::Ordinal)) {
    throw 'The bounded child must clear the inherited signer before validation.'
}
if ($childSource -match 'Write-Host|Write-Output' -or
    $childSource -match "'-PrivateKeyPem'") {
    throw 'The bounded child must not print or pass the signer through arguments.'
}

Write-Host 'Atlaso normal VMware test VM development-CA bridge tests passed.'
