<#
.SYNOPSIS
Run Atlaso's pinned PSScriptAnalyzer contract over every repository PowerShell source.
.PARAMETER RepoRoot
Repository checkout containing the settings file and tracked PowerShell sources.
.PARAMETER ModuleVersion
Exact PSScriptAnalyzer version required by the repository contract.
#>
[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
    [version]$ModuleVersion = '1.25.0'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$settingsPath = Join-Path $RepoRoot 'PSScriptAnalyzerSettings.psd1'
if (-not (Test-Path -LiteralPath $settingsPath -PathType Leaf)) {
    throw "PSScriptAnalyzer settings file is missing: $settingsPath"
}

$module = Get-Module -ListAvailable -Name PSScriptAnalyzer |
    Where-Object Version -EQ $ModuleVersion |
    Select-Object -First 1
if ($null -eq $module) {
    throw "PSScriptAnalyzer $ModuleVersion is required. Install that exact version before running repository checks."
}
Import-Module $module.Path -Force

$relativePaths = @(& git -C $RepoRoot ls-files --cached --others --exclude-standard -- '*.ps1' '*.psm1' '*.psd1') |
    Sort-Object -Unique
if ($LASTEXITCODE -ne 0) {
    throw "git ls-files failed with exit code $LASTEXITCODE."
}

$broadSuppressionPattern = [regex]::new(
    'SuppressMessageAttribute\s*\(\s*[''"]PSAvoidUsingPlainTextForPassword[''"]\s*,\s*[''"]{2}\s*\)',
    [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
)
$broadSuppressions = foreach ($relativePath in $relativePaths) {
    $path = Join-Path $RepoRoot $relativePath
    if ($broadSuppressionPattern.IsMatch((Get-Content -LiteralPath $path -Raw))) {
        $relativePath
    }
}
if ($broadSuppressions) {
    throw "Broad PSAvoidUsingPlainTextForPassword suppressions are forbidden: $($broadSuppressions -join ', ')"
}

# Analyzer suppressions must not become an escape hatch for credential inputs.
# OnePassword-prefixed values are SDK identifiers or executable paths, not passwords.
# Boolean Password switches describe OVF property metadata and carry no credential.
$credentialContractFailures = foreach ($relativePath in $relativePaths) {
    $tokens = $null
    $parseErrors = $null
    $syntaxTree = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $RepoRoot $relativePath),
        [ref]$tokens,
        [ref]$parseErrors
    )
    foreach ($parseError in $parseErrors) {
        "${relativePath}:$($parseError.Extent.StartLineNumber): PowerShell parse error: $($parseError.Message)"
    }
    $passwordParameters = $syntaxTree.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.ParameterAst] -and
            $node.Name.VariablePath.UserPath -match 'Password$' -and
            $node.Name.VariablePath.UserPath -notmatch '^OnePassword' -and
            $node.StaticType -ne [bool]
        }, $true)
    foreach ($passwordParameter in $passwordParameters) {
        $parameterName = $passwordParameter.Name.VariablePath.UserPath
        if ($passwordParameter.StaticType -notin @([SecureString], [PSCredential])) {
            "${relativePath}:$($passwordParameter.Extent.StartLineNumber): $parameterName must use SecureString or PSCredential."
        }
        if ($null -ne $passwordParameter.DefaultValue) {
            "${relativePath}:$($passwordParameter.Extent.StartLineNumber): $parameterName must not declare a default value."
        }
    }
    if ($relativePath -like 'scripts/*') {
        $literalPasswordAssignments = $syntaxTree.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
                $node.Left.VariablePath.UserPath -match 'Password$' -and
                $node.Left.VariablePath.UserPath -notmatch '^OnePassword' -and
                ($node.Right -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
                    $node.Right -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) -and
                -not [string]::IsNullOrEmpty($node.Right.Value)
            }, $true)
        foreach ($assignment in $literalPasswordAssignments) {
            "${relativePath}:$($assignment.Extent.StartLineNumber): literal password assignments are forbidden."
        }
    }
}
if ($credentialContractFailures) {
    throw "PowerShell credential parameter contract failed:`n$($credentialContractFailures -join "`n")"
}

$findings = foreach ($relativePath in $relativePaths) {
    Invoke-ScriptAnalyzer `
        -Path (Join-Path $RepoRoot $relativePath) `
        -Settings $settingsPath
}
if ($findings) {
    $findings |
        Sort-Object ScriptPath, Line, Column, RuleName |
        Format-Table ScriptPath, Line, Column, RuleName, Message -Wrap -AutoSize |
        Out-String |
        Write-Error
    throw "PSScriptAnalyzer failed with $($findings.Count) active finding(s)."
}

Write-Host "PSScriptAnalyzer $ModuleVersion passed for $($relativePaths.Count) repository PowerShell source(s)."
