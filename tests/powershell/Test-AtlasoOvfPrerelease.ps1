<#
.SYNOPSIS
Validate stable and prerelease tag selection for the Atlaso OVF exporter.

.PARAMETER RepositoryRoot
Absolute path to the Atlaso checkout under test.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RepositoryRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
Read one production function definition without executing the exporter entry point.

.PARAMETER ScriptPath
PowerShell script containing the function.
.PARAMETER Name
Exact function name to load.
#>
function Get-AtlasoScriptFunction {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $ScriptPath,
        [ref]$tokens,
        [ref]$parseErrors
    )
    if ($parseErrors.Count -ne 0) {
        throw "Could not parse $ScriptPath`: $($parseErrors[0].Message)"
    }
    $functionMatches = @(
        $ast.FindAll(
            {
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq $Name
            },
            $true
        )
    )
    if ($functionMatches.Count -ne 1) {
        throw "Expected exactly one $Name function in $ScriptPath; found $($functionMatches.Count)."
    }
    return $functionMatches[0].Extent.Text
}

<#
.SYNOPSIS
Require a script block to fail with a matching message.

.PARAMETER Action
Script block expected to throw.
.PARAMETER Pattern
Wildcard pattern expected in the exception message.
#>
function Assert-ThrowsLike {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Pattern
    )

    try {
        & $Action
    }
    catch {
        if ($_.Exception.Message -notlike $Pattern) {
            throw "Expected error like '$Pattern', got: $($_.Exception.Message)"
        }
        return
    }
    throw "Expected error like '$Pattern', but the command succeeded."
}

$exportScript = Join-Path $RepositoryRoot 'scripts\windows\vmware\export-ovf.ps1'
$powerShellPath = (Get-Process -Id $PID).Path
$conflictOutput = @(& $powerShellPath -NoProfile -File $exportScript -Release -Prerelease 2>&1)
if ($LASTEXITCODE -eq 0 -or
    ($conflictOutput -join "`n") -notlike '*-Release and -Prerelease are mutually exclusive publishing modes*') {
    throw 'The exporter did not reject conflicting stable and prerelease publication modes.'
}
foreach ($functionName in @('Select-AtlasoReleaseTag', 'Assert-AtlasoReleasePublicationTarget')) {
    $definition = Get-AtlasoScriptFunction -ScriptPath $exportScript -Name $functionName
    . ([scriptblock]::Create($definition))
}

$headCommit = '0123456789abcdef0123456789abcdef01234567'
$stableRecord = [pscustomobject]@{
    Name       = 'v0.9.219'
    ObjectType = 'tag'
    Commit     = $headCommit
}
$prereleaseRecord = [pscustomobject]@{
    Name       = 'v0.9.219-rc.1'
    ObjectType = 'tag'
    Commit     = $headCommit
}
$stableTag = Select-AtlasoReleaseTag `
    -Version '0.9.219' `
    -HeadCommit $headCommit `
    -TagRecords @($stableRecord, $prereleaseRecord)
if ($stableTag -ne 'v0.9.219') {
    throw "Stable publication selected unexpected tag $stableTag."
}
$prereleaseTag = Select-AtlasoReleaseTag `
    -Version '0.9.219' `
    -HeadCommit $headCommit `
    -TagRecords @($stableRecord, $prereleaseRecord) `
    -Prerelease
if ($prereleaseTag -ne 'v0.9.219-rc.1') {
    throw "Prerelease publication selected unexpected tag $prereleaseTag."
}

Assert-ThrowsLike -Action {
    Select-AtlasoReleaseTag `
        -Version '0.9.219' `
        -HeadCommit $headCommit `
        -TagRecords @() `
        -Prerelease
} -Pattern '*exactly one annotated prerelease tag*'
Assert-ThrowsLike -Action {
    Select-AtlasoReleaseTag `
        -Version '0.9.219' `
        -HeadCommit $headCommit `
        -TagRecords @($stableRecord) `
        -Prerelease
} -Pattern '*exactly one annotated prerelease tag*'
Assert-ThrowsLike -Action {
    Select-AtlasoReleaseTag `
        -Version '0.9.219' `
        -HeadCommit $headCommit `
        -TagRecords @(
            [pscustomobject]@{
                Name       = 'V0.9.219'
                ObjectType = 'tag'
                Commit     = $headCommit
            }
        )
} -Pattern '*exactly one annotated stable release tag*'
Assert-ThrowsLike -Action {
    Select-AtlasoReleaseTag `
        -Version '0.9.219' `
        -HeadCommit $headCommit `
        -TagRecords @(
            [pscustomobject]@{
                Name       = 'V0.9.219-RC.1'
                ObjectType = 'tag'
                Commit     = $headCommit
            }
        ) `
        -Prerelease
} -Pattern '*exactly one annotated prerelease tag*'
Assert-ThrowsLike -Action {
    Select-AtlasoReleaseTag `
        -Version '0.9.219' `
        -HeadCommit $headCommit `
        -TagRecords @(
            [pscustomobject]@{
                Name       = 'v0.9.219-01'
                ObjectType = 'tag'
                Commit     = $headCommit
            }
        ) `
        -Prerelease
} -Pattern '*exactly one annotated prerelease tag*'
Assert-ThrowsLike -Action {
    Select-AtlasoReleaseTag `
        -Version '0.9.219' `
        -HeadCommit $headCommit `
        -TagRecords @(
            $prereleaseRecord,
            [pscustomobject]@{
                Name       = 'v0.9.219-beta.1'
                ObjectType = 'tag'
                Commit     = $headCommit
            }
        ) `
        -Prerelease
} -Pattern '*multiple prerelease tags*'
Assert-ThrowsLike -Action {
    Select-AtlasoReleaseTag `
        -Version '0.9.219' `
        -HeadCommit $headCommit `
        -TagRecords @(
            [pscustomobject]@{
                Name       = 'v0.9.219-rc.1'
                ObjectType = 'commit'
                Commit     = $headCommit
            }
        ) `
        -Prerelease
} -Pattern '*lightweight tags are not accepted*'
Assert-ThrowsLike -Action {
    Select-AtlasoReleaseTag `
        -Version '0.9.219' `
        -HeadCommit $headCommit `
        -TagRecords @(
            [pscustomobject]@{
                Name       = 'v0.9.220-rc.1'
                ObjectType = 'tag'
                Commit     = $headCommit
            }
        ) `
        -Prerelease
} -Pattern '*exactly one annotated prerelease tag*'
Assert-ThrowsLike -Action {
    Select-AtlasoReleaseTag `
        -Version '0.9.219' `
        -HeadCommit $headCommit `
        -TagRecords @(
            [pscustomobject]@{
                Name       = 'v0.9.219-rc.1'
                ObjectType = 'tag'
                Commit     = 'fedcba9876543210fedcba9876543210fedcba98'
            }
        ) `
        -Prerelease
} -Pattern '*identifies*checked-out commit*'

$stableMetadata = [pscustomobject]@{
    tagName      = 'v0.9.219'
    isDraft      = $false
    isPrerelease = $false
    assets       = @()
}
$prereleaseMetadata = [pscustomobject]@{
    tagName      = 'v0.9.219-rc.1'
    isDraft      = $false
    isPrerelease = $true
    assets       = @()
}
Assert-AtlasoReleasePublicationTarget -Metadata $stableMetadata -Tag 'v0.9.219'
Assert-AtlasoReleasePublicationTarget `
    -Metadata $prereleaseMetadata `
    -Tag 'v0.9.219-rc.1' `
    -Prerelease
Assert-ThrowsLike -Action {
    Assert-AtlasoReleasePublicationTarget -Metadata $prereleaseMetadata -Tag 'v0.9.219-rc.1'
} -Pattern '*not classified as a stable release*'
Assert-ThrowsLike -Action {
    Assert-AtlasoReleasePublicationTarget -Metadata $stableMetadata -Tag 'v0.9.219' -Prerelease
} -Pattern '*not classified as a prerelease*'
Assert-ThrowsLike -Action {
    Assert-AtlasoReleasePublicationTarget `
        -Metadata ([pscustomobject]@{
                tagName      = 'v0.9.219-rc.1'
                isDraft      = $true
                isPrerelease = $true
                assets       = @()
            }) `
        -Tag 'v0.9.219-rc.1' `
        -Prerelease
} -Pattern '*is a draft*'
Assert-ThrowsLike -Action {
    Assert-AtlasoReleasePublicationTarget `
        -Metadata ([pscustomobject]@{
                tagName = 'v0.9.219-rc.1'
                isDraft = $false
                assets  = @()
            }) `
        -Tag 'v0.9.219-rc.1' `
        -Prerelease
} -Pattern '*returned malformed metadata*'

Write-Output 'Atlaso OVF prerelease tests passed.'
