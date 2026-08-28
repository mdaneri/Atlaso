<#
.SYNOPSIS
Enforce comment-based help on every new or changed PowerShell file.

.DESCRIPTION
Compares tracked PowerShell files with a base checkout. Every added or changed
script, module, and function must provide comment-based help with a meaningful
synopsis and a non-placeholder parameter description for each declared parameter.
Unchanged legacy files remain outside the incremental gate until they are edited.

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
    $synopsis = $help.Synopsis.Trim()
    if ($synopsis -match '(?i)helper for the bounded workflow' -or
        $synopsis -match '(?i)^[A-Za-z](?:\s+[A-Za-z]){4,}[.]?$') {
        $findings.Add("$DisplayName has placeholder or token-split .SYNOPSIS text: '$synopsis'")
    }

    $parameters = @()
    if ($Scope -is [System.Management.Automation.Language.ScriptBlockAst]) {
        if ($null -ne $Scope.ParamBlock) {
            $parameters = @($Scope.ParamBlock.Parameters)
        }
    }
    elseif ($Scope -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
        # Signature-style functions store their declaration on the function AST,
        # while ordinary param blocks live on the body AST.
        if ($null -ne $Scope.Parameters -and $Scope.Parameters.Count -gt 0) {
            $parameters = @($Scope.Parameters)
        }
        elseif ($null -ne $Scope.Body.ParamBlock) {
            $parameters = @($Scope.Body.ParamBlock.Parameters)
        }
    }
    $documented = @($help.Parameters.Keys | ForEach-Object { $_.ToUpperInvariant() })
    foreach ($parameter in $parameters) {
        $name = $parameter.Name.VariablePath.UserPath
        if ($name.ToUpperInvariant() -notin $documented) {
            $findings.Add("$DisplayName parameter '$name' has no .PARAMETER entry.")
            continue
        }
        $description = [string]$help.Parameters[$name]
        if ([string]::IsNullOrWhiteSpace($description)) {
            $description = [string]$help.Parameters[$name.ToUpperInvariant()]
        }
        if ([string]::IsNullOrWhiteSpace($description) -or
            $description -match '(?i)value used to configure this workflow' -or
            $description -match '(?i)^\s*[A-Za-z][A-Za-z0-9_-]*(?:\s+[A-Za-z][A-Za-z0-9_-]*)*\s+value[.]?\s*$') {
            $findings.Add("$DisplayName parameter '$name' has empty or placeholder .PARAMETER text.")
        }
    }
    return $findings
}

<#
.SYNOPSIS
Return comment-help tokens immediately preceding one PowerShell scope.

.PARAMETER Tokens
Parser tokens for the complete source file.

.PARAMETER SourceText
Exact source text used to validate whitespace between comments and the scope.

.PARAMETER StartOffset
Source offset where the associated script parameter block or function begins.
#>
function Get-AdjacentPowerShellHelpComment {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.Token[]]$Tokens,
        [Parameter(Mandatory = $true)]
        [string]$SourceText,
        [Parameter(Mandatory = $true)]
        [int]$StartOffset
    )

    $comments = @($Tokens | Where-Object {
            $_.Kind -eq [System.Management.Automation.Language.TokenKind]::Comment -and
            $_.Text -match '(?im)^\s*\.SYNOPSIS\s*$' -and
            $_.Extent.EndOffset -le $StartOffset
        } | Sort-Object { $_.Extent.StartOffset } -Descending)
    $adjacent = [System.Collections.Generic.List[System.Management.Automation.Language.Token]]::new()
    $cursor = $StartOffset
    foreach ($comment in $comments) {
        $gapLength = $cursor - $comment.Extent.EndOffset
        $gap = $SourceText.Substring($comment.Extent.EndOffset, $gapLength)
        if ($gap -notmatch '^\s*$') {
            break
        }
        $adjacent.Insert(0, $comment)
        $cursor = $comment.Extent.StartOffset
    }
    return @($adjacent)
}

<#
.SYNOPSIS
Return comment-help tokens from every supported location for one function.

.PARAMETER Function
Parsed function whose comment-based help locations are inspected.

.PARAMETER Tokens
Parser tokens for the complete source file.

.PARAMETER SourceText
Exact source text used to validate whitespace between comments and anchors.
#>
function Get-PowerShellFunctionHelpComment {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.FunctionDefinitionAst]$Function,
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.Token[]]$Tokens,
        [Parameter(Mandatory = $true)]
        [string]$SourceText
    )

    $anchors = [System.Collections.Generic.List[int]]::new()
    $anchors.Add($Function.Extent.StartOffset)

    $body = $Function.Body
    if ($null -ne $body.ParamBlock) {
        $parameterAttributes = @($body.ParamBlock.Attributes)
        $bodyStartAnchor = if ($parameterAttributes.Count -gt 0) {
            $parameterAttributes[0].Extent.StartOffset
        }
        else {
            $body.ParamBlock.Extent.StartOffset
        }
    }
    else {
        $firstBodyStatement = @($body.EndBlock.Statements) | Select-Object -First 1
        $bodyStartAnchor = if ($null -ne $firstBodyStatement) {
            $firstBodyStatement.Extent.StartOffset
        }
        else {
            $body.Extent.EndOffset - 1
        }
    }
    $anchors.Add($bodyStartAnchor)
    # PowerShell also resolves help placed after the final statement and before
    # the closing brace. A comment-only body shares both anchors, so findings
    # are deduplicated by source offset below.
    $anchors.Add($body.Extent.EndOffset - 1)

    $commentsByOffset = @{}
    foreach ($anchor in $anchors) {
        foreach ($comment in Get-AdjacentPowerShellHelpComment `
                -Tokens $Tokens `
                -SourceText $SourceText `
                -StartOffset $anchor) {
            $commentsByOffset[$comment.Extent.StartOffset] = $comment
        }
    }
    return @($commentsByOffset.Values | Sort-Object { $_.Extent.StartOffset })
}

<#
.SYNOPSIS
Return duplicate adjacent comment-help findings for one parsed PowerShell file.

.PARAMETER Ast
Complete parsed script AST.

.PARAMETER Tokens
Parser tokens for the complete source file.

.PARAMETER SourceText
Exact source text used for comment adjacency checks.

.PARAMETER RelativePath
Repository-relative file path included in findings.
#>
function Get-DuplicatePowerShellHelpFinding {
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.ScriptBlockAst]$Ast,
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Language.Token[]]$Tokens,
        [Parameter(Mandatory = $true)]
        [string]$SourceText,
        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    $findings = [System.Collections.Generic.List[string]]::new()
    $topLevelStatements = @($Ast.EndBlock.Statements)
    $firstStatement = $topLevelStatements | Select-Object -First 1
    $scriptAnchor = $null
    if ($null -ne $Ast.ParamBlock) {
        $parameterAttributes = @($Ast.ParamBlock.Attributes)
        $scriptAnchor = if ($parameterAttributes.Count -gt 0) {
            $parameterAttributes[0].Extent.StartOffset
        }
        else {
            $Ast.ParamBlock.Extent.StartOffset
        }
    }
    elseif ($null -ne $firstStatement -and
        $firstStatement -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) {
        $scriptAnchor = $firstStatement.Extent.StartOffset
    }
    if ($null -ne $scriptAnchor) {
        $scriptComments = @(Get-AdjacentPowerShellHelpComment `
                -Tokens $Tokens `
                -SourceText $SourceText `
                -StartOffset $scriptAnchor)
        if ($scriptComments.Count -gt 1) {
            $lines = $scriptComments | ForEach-Object { $_.Extent.StartLineNumber }
            $findings.Add("$RelativePath has multiple adjacent script help blocks at lines $($lines -join ', ').")
        }
    }

    $functions = @($Ast.FindAll(
            { param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] },
            $true
        ))
    foreach ($function in $functions) {
        $functionComments = @(Get-PowerShellFunctionHelpComment `
                -Function $function `
                -Tokens $Tokens `
                -SourceText $SourceText)
        if ($null -eq $Ast.ParamBlock -and
            $firstStatement -eq $function -and
            $null -ne $Ast.GetHelpContent() -and
            $functionComments.Count -gt 0) {
            # A script without a param block may place file help immediately
            # before the first function's own help. PowerShell assigns the
            # earliest block to the script, so it is not a function duplicate.
            $functionComments = @($functionComments | Select-Object -Skip 1)
        }
        if ($functionComments.Count -gt 1) {
            $lines = $functionComments | ForEach-Object { $_.Extent.StartLineNumber }
            $findings.Add(
                "${RelativePath}:$($function.Extent.StartLineNumber) function $($function.Name) has multiple adjacent help blocks at lines $($lines -join ', ')."
            )
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
    $sourceText = [System.IO.File]::ReadAllText($candidatePath)
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

    foreach ($finding in Get-DuplicatePowerShellHelpFinding `
            -Ast $ast `
            -Tokens $tokens `
            -SourceText $sourceText `
            -RelativePath $relativePath) {
        $findings.Add($finding)
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
    # Plain stderr keeps CI diagnostics stable across PowerShell hosts whose
    # Write-Error rendering may inject ANSI styling into asserted path text.
    [Console]::Error.WriteLine(
        "PowerShell comment-help checks failed with $($findings.Count) issue(s):`n  - $($findings -join "`n  - ")"
    )
    exit 1
}

Write-Host "PowerShell comment-help checks passed for $checkedFiles added or changed file(s)."
