<#
.SYNOPSIS
Enforce comment-based help on every new or changed PowerShell file.

.DESCRIPTION
Compares tracked PowerShell files with a base checkout. Every added or changed
script, module, and function must provide comment-based help with a synopsis and a
parameter entry for each declared parameter. Unchanged legacy files remain outside
the incremental gate until they are edited.

.PARAMETER Root
Candidate Atlaso repository root to validate.

.PARAMETER BaseRoot
Base-branch checkout used to identify added or changed PowerShell files.
#>
[CmdletBinding()]
param(
    [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [Parameter(Mandatory = $true)]
    [string]$BaseRoot
)

$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
Return repository-relative paths for tracked PowerShell source files.

.PARAMETER RepositoryRoot
Repository checkout queried through Git.
#>
function Get-TrackedPowerShellPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot
    )

    $paths = @(& git -C $RepositoryRoot ls-files --cached --others --exclude-standard -- '*.ps1' '*.psm1')
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to enumerate tracked PowerShell files in $RepositoryRoot."
    }
    return @($paths | Where-Object { $_ })
}

<#
.SYNOPSIS
Return whether two existing files have identical bytes.

.PARAMETER CandidatePath
Candidate-checkout file.

.PARAMETER BasePath
Corresponding base-checkout file.
#>
function Test-PowerShellFileUnchanged {
    param(
        [Parameter(Mandatory = $true)][string]$CandidatePath,
        [Parameter(Mandatory = $true)][string]$BasePath
    )

    if (-not (Test-Path -LiteralPath $BasePath -PathType Leaf)) {
        return $false
    }
    $candidateHash = (Get-FileHash -LiteralPath $CandidatePath -Algorithm SHA256).Hash
    $baseHash = (Get-FileHash -LiteralPath $BasePath -Algorithm SHA256).Hash
    return $candidateHash -eq $baseHash
}

<#
.SYNOPSIS
Return missing comment-help findings for one parsed PowerShell scope.

.PARAMETER Scope
Script or function AST whose help is validated.

.PARAMETER DisplayName
Operator-facing scope name included in findings.
#>
function Get-PowerShellScopeHelpFinding {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.Ast]$Scope,
        [Parameter(Mandatory = $true)]
        [string]$DisplayName
    )

    $findings = [System.Collections.Generic.List[string]]::new()
    $help = $Scope.GetHelpContent()
    if ($null -eq $help -or [string]::IsNullOrWhiteSpace($help.Synopsis)) {
        $findings.Add("$DisplayName has no comment-based .SYNOPSIS header.")
        return $findings
    }

    $parameters = @()
    if ($Scope -is [System.Management.Automation.Language.ScriptBlockAst]) {
        if ($null -ne $Scope.ParamBlock) {
            $parameters = @($Scope.ParamBlock.Parameters)
        }
    }
    elseif ($Scope -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
        if ($null -ne $Scope.Body.ParamBlock) {
            $parameters = @($Scope.Body.ParamBlock.Parameters)
        }
    }
    $documented = @($help.Parameters.Keys | ForEach-Object { $_.ToUpperInvariant() })
    foreach ($parameter in $parameters) {
        $name = $parameter.Name.VariablePath.UserPath
        if ($name.ToUpperInvariant() -notin $documented) {
            $findings.Add("$DisplayName parameter '$name' has no .PARAMETER entry.")
        }
    }
    return $findings
}

$candidateRoot = (Resolve-Path -LiteralPath $Root).Path
$baseCheckoutRoot = (Resolve-Path -LiteralPath $BaseRoot).Path
$findings = [System.Collections.Generic.List[string]]::new()
$checkedFiles = 0

foreach ($relativePath in Get-TrackedPowerShellPath -RepositoryRoot $candidateRoot) {
    $candidatePath = Join-Path $candidateRoot $relativePath
    $basePath = Join-Path $baseCheckoutRoot $relativePath
    if (Test-PowerShellFileUnchanged -CandidatePath $candidatePath -BasePath $basePath) {
        continue
    }
    $checkedFiles++
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $candidatePath,
        [ref]$tokens,
        [ref]$parseErrors
    )
    foreach ($parseError in @($parseErrors)) {
        $findings.Add("${relativePath}:$($parseError.Extent.StartLineNumber) $($parseError.Message)")
    }
    if (@($parseErrors).Count -gt 0) {
        continue
    }

    foreach ($finding in Get-PowerShellScopeHelpFinding -Scope $ast -DisplayName $relativePath) {
        $findings.Add($finding)
    }
    $functions = $ast.FindAll(
        { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] },
        $true
    )
    foreach ($function in $functions) {
        $displayName = "${relativePath}:$($function.Extent.StartLineNumber) function $($function.Name)"
        foreach ($finding in Get-PowerShellScopeHelpFinding -Scope $function -DisplayName $displayName) {
            $findings.Add($finding)
        }
    }
}

if ($findings.Count -gt 0) {
    Write-Error "PowerShell comment-help checks failed with $($findings.Count) issue(s):`n  - $($findings -join "`n  - ")"
    exit 1
}

Write-Host "PowerShell comment-help checks passed for $checkedFiles added or changed file(s)."
