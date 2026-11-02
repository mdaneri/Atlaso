<#
.SYNOPSIS
Exercise Photon installation-capture root admission without running Packer.
.PARAMETER RepositoryRoot
Atlaso checkout containing the supported Photon build wrapper.
.PARAMETER FixtureRoot
Existing pytest-owned temporary directory for isolated filesystem fixtures.
#>
param(
    [Parameter(Mandatory = $true)][string]$RepositoryRoot,
    [Parameter(Mandatory = $true)][string]$FixtureRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$resolvedRepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot -ErrorAction Stop).Path
$resolvedFixtureRoot = (Resolve-Path -LiteralPath $FixtureRoot -ErrorAction Stop).Path
Import-Module (
    Join-Path $resolvedRepositoryRoot 'scripts\windows\vmware\Atlaso.WorkstationCleanup.psm1'
) -Force
$wrapperPath = Join-Path $resolvedRepositoryRoot 'scripts\windows\vmware\build-photon-image.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $wrapperPath,
    [ref]$tokens,
    [ref]$parseErrors
)
if ($parseErrors.Count -ne 0) {
    throw "Photon build wrapper parse failed: $($parseErrors[0].Message)"
}
foreach ($functionName in @(
        'Open-AtlasoInstallationCaptureRoot',
        'Assert-AtlasoInstallationCaptureArchives'
    )) {
    $definitions = @(
        $ast.FindAll(
            {
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq $functionName
            },
            $true
        )
    )
    if ($definitions.Count -ne 1) {
        throw "Expected exactly one $functionName function in the Photon build wrapper."
    }
    . ([scriptblock]::Create($definitions[0].Extent.Text))
}

$captureRootPath = Join-Path $resolvedFixtureRoot 'capture-admission'
[void][IO.Directory]::CreateDirectory($captureRootPath)
$captureRootIdentity = [Atlaso.WorkstationFileIdentity]::Get($captureRootPath)
$separateConflictPath = Join-Path $resolvedFixtureRoot 'separate-output-root'
$captureRoot = Open-AtlasoInstallationCaptureRoot `
    -DirectoryPath $captureRootPath `
    -ExpectedIdentity $captureRootIdentity `
    -ConflictPaths @($separateConflictPath)
try {
    if ($captureRoot.Path -cne [IO.Path]::GetFullPath($captureRootPath)) {
        throw 'Capture-root admission did not retain the canonical directory path.'
    }
}
finally {
    $captureRoot.Pin.Dispose()
}

$missingPath = Join-Path $resolvedFixtureRoot 'capture-missing'
try {
    $null = Open-AtlasoInstallationCaptureRoot `
        -DirectoryPath $missingPath `
        -ExpectedIdentity $captureRootIdentity `
        -ConflictPaths @($separateConflictPath)
    throw 'Missing capture-root admission unexpectedly succeeded.'
}
catch {
    if ($_.Exception.Message -eq 'Missing capture-root admission unexpectedly succeeded.') { throw }
}

try {
    $null = Open-AtlasoInstallationCaptureRoot `
        -DirectoryPath $captureRootPath `
        -ExpectedIdentity 'FFFFFFFF:FFFFFFFFFFFFFFFF' `
        -ConflictPaths @($separateConflictPath)
    throw 'Changed capture-root identity unexpectedly succeeded.'
}
catch {
    if ($_.Exception.Message -eq 'Changed capture-root identity unexpectedly succeeded.') { throw }
}

try {
    $null = Open-AtlasoInstallationCaptureRoot `
        -DirectoryPath $captureRootPath `
        -ExpectedIdentity $captureRootIdentity `
        -ConflictPaths @($captureRootPath)
    throw 'Overlapping capture-root admission unexpectedly succeeded.'
}
catch {
    if ($_.Exception.Message -eq 'Overlapping capture-root admission unexpectedly succeeded.') { throw }
}

try {
    $null = Open-AtlasoInstallationCaptureRoot `
        -DirectoryPath $captureRootPath `
        -ExpectedIdentity $captureRootIdentity `
        -ConflictPaths @($resolvedRepositoryRoot)
    throw 'Source-root overlap admission unexpectedly succeeded.'
}
catch {
    if ($_.Exception.Message -eq 'Source-root overlap admission unexpectedly succeeded.') { throw }
}

$occupiedRootPath = Join-Path $resolvedFixtureRoot 'capture-occupied'
[void][IO.Directory]::CreateDirectory($occupiedRootPath)
[IO.File]::WriteAllText((Join-Path $occupiedRootPath 'prior.tar'), 'preserve')
$occupiedRootIdentity = [Atlaso.WorkstationFileIdentity]::Get($occupiedRootPath)
try {
    $null = Open-AtlasoInstallationCaptureRoot `
        -DirectoryPath $occupiedRootPath `
        -ExpectedIdentity $occupiedRootIdentity `
        -ConflictPaths @($separateConflictPath)
    throw 'Conflicting pre-existing capture contents unexpectedly succeeded.'
}
catch {
    if ($_.Exception.Message -eq 'Conflicting pre-existing capture contents unexpectedly succeeded.') { throw }
}

$archiveRootPath = Join-Path $resolvedFixtureRoot 'capture-archives'
[void][IO.Directory]::CreateDirectory($archiveRootPath)
$archiveRootIdentity = [Atlaso.WorkstationFileIdentity]::Get($archiveRootPath)
$archiveRoot = Open-AtlasoInstallationCaptureRoot `
    -DirectoryPath $archiveRootPath `
    -ExpectedIdentity $archiveRootIdentity `
    -ConflictPaths @($separateConflictPath)
try {
    [IO.File]::WriteAllBytes((Join-Path $archiveRootPath 'installation-rpms.tar'), [byte[]](1, 2, 3))
    [IO.File]::WriteAllBytes((Join-Path $archiveRootPath 'installation-powercli.tar'), [byte[]](4, 5, 6))
    Assert-AtlasoInstallationCaptureArchives -CaptureRoot $archiveRoot

    Remove-Item -LiteralPath (Join-Path $archiveRootPath 'installation-powercli.tar') -Force
    try {
        Assert-AtlasoInstallationCaptureArchives -CaptureRoot $archiveRoot
        throw 'Missing captured archive unexpectedly passed result admission.'
    }
    catch {
        if ($_.Exception.Message -eq 'Missing captured archive unexpectedly passed result admission.') { throw }
    }

    [IO.File]::WriteAllBytes((Join-Path $archiveRootPath 'installation-powercli.tar'), [byte[]](4, 5, 6))
    [IO.File]::WriteAllText((Join-Path $archiveRootPath 'unexpected.txt'), 'preserve')
    try {
        Assert-AtlasoInstallationCaptureArchives -CaptureRoot $archiveRoot
        throw 'Unexpected captured file passed result admission.'
    }
    catch {
        if ($_.Exception.Message -eq 'Unexpected captured file passed result admission.') { throw }
    }
}
finally {
    $archiveRoot.Pin.Dispose()
}

Write-Output 'Installation capture-root admission fixture passed.'
