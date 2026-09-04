<#
.SYNOPSIS
Exercise current-user DPAPI 1Password service-account setup and child isolation.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingConvertToSecureStringWithPlainText',
    '',
    Justification = 'Focused test constructs fixed synthetic values and never handles real credentials.'
)]
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
$modulePath = Join-Path $repositoryRoot 'scripts\windows\vmware\Atlaso.OnePasswordCredentials.psm1'
$setupPath = Join-Path $repositoryRoot 'scripts\windows\vmware\initialize-onepassword-service-account.ps1'
$launcherPath = Join-Path $repositoryRoot 'scripts\windows\vmware\Invoke-AtlasoServiceAccountCommand.ps1'
Import-Module $modulePath -Force

$testRoot = Join-Path $repositoryRoot (
    '.atlaso-local\service-account-test-' + [guid]::NewGuid().ToString('N')
)
[void][System.IO.Directory]::CreateDirectory($testRoot)
$tokenPath = Join-Path $testRoot 'token.dpapi'
$rotatedToken = 'ops_' + ('B' * 100)
try {
    $firstToken = 'ops_' + ('A' * 100)
    $firstSecureToken = ConvertTo-SecureString $firstToken -AsPlainText -Force
    $outsidePath = Join-Path $repositoryRoot 'onepassword-token-outside-local.dpapi'
    try {
        & $setupPath -Token $firstSecureToken -TokenFile $outsidePath | Out-Null
        throw 'A token destination outside .atlaso-local unexpectedly succeeded.'
    }
    catch {
        if ($_.Exception.Message -notlike '*beneath this checkout*') {
            throw
        }
    }
    if (Test-Path -LiteralPath $outsidePath) {
        throw 'The rejected outside token destination was created.'
    }
    $setupSource = [System.IO.File]::ReadAllText($setupPath)
    $existingAncestorCheck = $setupSource.IndexOf('$existingAncestorPath = $parentPath')
    $directoryCreation = $setupSource.IndexOf(
        '[System.IO.Directory]::CreateDirectory($parentPath)'
    )
    if ($existingAncestorCheck -lt 0 -or $directoryCreation -lt 0 -or
        $existingAncestorCheck -gt $directoryCreation) {
        throw 'The setup helper does not validate existing ancestors before directory creation.'
    }
    & $setupPath -Token $firstSecureToken -TokenFile $tokenPath | Out-Null
    $ciphertext = [System.IO.File]::ReadAllText($tokenPath)
    if ($ciphertext.Contains($firstToken)) {
        throw 'The service-account token was stored in plaintext.'
    }
    $resolvedTokenPath = Assert-AtlasoOnePasswordServiceAccountTokenFile -Path $tokenPath
    if ($resolvedTokenPath -cne $tokenPath) {
        throw 'The token-file validator changed the exact destination path.'
    }
    $roundTrip = ConvertFrom-SecureString `
        -SecureString (ConvertTo-SecureString -String $ciphertext) `
        -AsPlainText
    if ($roundTrip -cne $firstToken) {
        throw 'The current-user DPAPI token round trip failed.'
    }

    try {
        Resolve-AtlasoOnePasswordServiceAccountTokenFile `
            -TokenFile (Join-Path $testRoot 'missing.dpapi') `
            -RepositoryRoot $repositoryRoot | Out-Null
        throw 'An explicit missing token file unexpectedly succeeded.'
    }
    catch {
        if ($_.Exception.Message -notlike '*explicit*unavailable*') {
            throw
        }
    }

    try {
        Resolve-AtlasoOnePasswordServiceAccountTokenFile `
            -TokenFile (Join-Path $repositoryRoot 'outside-token.dpapi') `
            -RepositoryRoot $repositoryRoot | Out-Null
        throw 'An explicit token file outside .atlaso-local unexpectedly succeeded.'
    }
    catch {
        if ($_.Exception.Message -notlike '*beneath this checkout*') {
            throw
        }
    }

    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $systemSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $acl = Get-Acl -LiteralPath $tokenPath
    $accessSids = @($acl.GetAccessRules(
            $true,
            $true,
            [System.Security.Principal.SecurityIdentifier]
        ) | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique)
    if (-not $acl.AreAccessRulesProtected -or $accessSids.Count -ne 2 -or
        $currentSid.Value -notin $accessSids -or $systemSid.Value -notin $accessSids) {
        throw 'The setup helper did not restrict the token file to the current user and SYSTEM.'
    }

    $missingSystemPath = Join-Path $testRoot 'missing-system.dpapi'
    [System.IO.File]::Copy($tokenPath, $missingSystemPath)
    $missingSystemAcl = Get-Acl -LiteralPath $missingSystemPath
    $missingSystemAcl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($missingSystemAcl.Access)) {
        [void]$missingSystemAcl.RemoveAccessRuleAll($rule)
    }
    $currentUserRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
        $currentSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        [System.Security.AccessControl.AccessControlType]::Allow
    )
    $missingSystemAcl.AddAccessRule($currentUserRule)
    Set-Acl -LiteralPath $missingSystemPath -AclObject $missingSystemAcl
    try {
        Assert-AtlasoOnePasswordServiceAccountTokenFile -Path $missingSystemPath | Out-Null
        throw 'A token file without SYSTEM access unexpectedly succeeded.'
    }
    catch {
        if ($_.Exception.Message -notlike '*SYSTEM cannot read*') {
            throw
        }
    }

    $partialReadPath = Join-Path $testRoot 'partial-read.dpapi'
    [System.IO.File]::Copy($tokenPath, $partialReadPath)
    $partialReadAcl = Get-Acl -LiteralPath $partialReadPath
    $partialReadAcl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($partialReadAcl.Access)) {
        [void]$partialReadAcl.RemoveAccessRuleAll($rule)
    }
    $partialReadAcl.AddAccessRule(
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            $currentSid,
            ([System.Security.AccessControl.FileSystemRights]::ReadAttributes -bor
                [System.Security.AccessControl.FileSystemRights]::Delete),
            [System.Security.AccessControl.AccessControlType]::Allow
        )
    )
    $partialReadAcl.AddAccessRule(
        [System.Security.AccessControl.FileSystemAccessRule]::new(
            $systemSid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
    )
    Set-Acl -LiteralPath $partialReadPath -AclObject $partialReadAcl
    try {
        Assert-AtlasoOnePasswordServiceAccountTokenFile -Path $partialReadPath | Out-Null
        throw 'A token file with only partial current-user read rights unexpectedly succeeded.'
    }
    catch {
        if ($_.Exception.Message -notlike '*current user cannot read*') {
            throw
        }
    }

    try {
        & $setupPath -Token $firstSecureToken -TokenFile $tokenPath | Out-Null
        throw 'Token replacement succeeded without -Force.'
    }
    catch {
        if ($_.Exception.Message -notlike '*Pass -Force*') {
            throw
        }
    }
    $rotatedSecureToken = ConvertTo-SecureString $rotatedToken -AsPlainText -Force
    & $setupPath -Token $rotatedSecureToken -TokenFile $tokenPath -Force | Out-Null
    $rotatedCiphertext = [System.IO.File]::ReadAllText($tokenPath)
    $roundTrip = ConvertFrom-SecureString `
        -SecureString (ConvertTo-SecureString -String $rotatedCiphertext) `
        -AsPlainText
    if ($roundTrip -cne $rotatedToken -or $rotatedCiphertext.Contains($rotatedToken)) {
        throw 'Token rotation did not preserve ciphertext-only storage.'
    }

    $authentication = Resolve-AtlasoOnePasswordAuthentication `
        -RepositoryRoot $repositoryRoot `
        -ServiceAccountTokenFile $tokenPath `
        -Account 'desktop-must-not-win' `
        -TimeoutSeconds 5
    if ($authentication.Mode -cne 'service-account' -or
        $authentication.TokenFile -cne $tokenPath -or $authentication.Account) {
        throw 'Explicit service-account token precedence is incorrect.'
    }

    $malformedPath = Join-Path $testRoot 'malformed.dpapi'
    try {
        & $setupPath `
            -Token (ConvertTo-SecureString 'not-a-service-token' -AsPlainText -Force) `
            -TokenFile $malformedPath | Out-Null
        throw 'Malformed token setup unexpectedly succeeded.'
    }
    catch {
        if ($_.Exception.Message -notlike '*invalid format*') {
            throw
        }
    }
    if (Test-Path -LiteralPath $malformedPath) {
        throw 'Malformed token setup retained a destination file.'
    }

    $childPath = Join-Path $testRoot 'inspect-environment.ps1'
    $resultPath = Join-Path $testRoot 'child-result.json'
    $childSource = @'
param([Parameter(Mandatory = $true)][string]$ResultPath)
$present = -not [string]::IsNullOrWhiteSpace($env:OP_SERVICE_ACCOUNT_TOKEN)
[System.IO.File]::WriteAllText($ResultPath, (@{ TokenPresent = $present } | ConvertTo-Json -Compress))
'@
    [System.IO.File]::WriteAllText($childPath, $childSource)
    $argumentsPath = Join-Path $testRoot 'arguments.json'
    [System.IO.File]::WriteAllText(
        $argumentsPath,
        (@('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $childPath, '-ResultPath', $resultPath) |
            ConvertTo-Json -Compress)
    )
    $env:OP_SERVICE_ACCOUNT_TOKEN = $null
    & (Get-Process -Id $PID).Path -NoLogo -NoProfile -NonInteractive -File $launcherPath `
        -TokenFile $tokenPath `
        -RepositoryRoot $repositoryRoot `
        -FilePath (Get-Process -Id $PID).Path `
        -ArgumentsPath $argumentsPath `
        -WorkingDirectory $testRoot
    if ($LASTEXITCODE -ne 0) {
        throw 'The service-account child launcher failed.'
    }
    $childResult = [System.IO.File]::ReadAllText($resultPath) | ConvertFrom-Json
    if (-not $childResult.TokenPresent -or $env:OP_SERVICE_ACCOUNT_TOKEN) {
        throw 'The token was not isolated to the immediate child environment.'
    }

    $corruptPath = Join-Path $testRoot 'corrupt.dpapi'
    & $setupPath -Token $rotatedSecureToken -TokenFile $corruptPath | Out-Null
    [System.IO.File]::WriteAllText($corruptPath, 'not-dpapi-ciphertext')
    & (Get-Process -Id $PID).Path -NoLogo -NoProfile -NonInteractive -File $launcherPath `
        -TokenFile $corruptPath `
        -RepositoryRoot $repositoryRoot `
        -FilePath (Get-Process -Id $PID).Path `
        -ArgumentsPath $argumentsPath `
        -WorkingDirectory $testRoot 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        throw 'Corrupt DPAPI ciphertext unexpectedly reached the child command.'
    }

    Write-Output 'Atlaso 1Password service-account tests passed.'
}
finally {
    $env:OP_SERVICE_ACCOUNT_TOKEN = $null
    if (Test-Path -LiteralPath $testRoot) {
        [System.IO.Directory]::Delete($testRoot, $true)
    }
}
