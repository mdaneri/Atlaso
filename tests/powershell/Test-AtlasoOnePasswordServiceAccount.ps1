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

$testRoot = Join-Path $repositoryRoot (
    '.atlaso-local\service-account-test-' + [guid]::NewGuid().ToString('N')
)
[void][System.IO.Directory]::CreateDirectory($testRoot)
$sourceRoot = $repositoryRoot
$repositoryRoot = Join-Path $testRoot 'checkout'
$fixtureScripts = Join-Path $repositoryRoot 'scripts\windows\vmware'
[void][System.IO.Directory]::CreateDirectory($fixtureScripts)
Get-ChildItem -LiteralPath (Join-Path $sourceRoot 'scripts\windows\vmware') -File |
    Copy-Item -Destination $fixtureScripts
$modulePath = Join-Path $fixtureScripts 'Atlaso.OnePasswordCredentials.psm1'
$setupPath = Join-Path $fixtureScripts 'initialize-onepassword-service-account.ps1'
$launcherPath = Join-Path $fixtureScripts 'Invoke-AtlasoServiceAccountCommand.ps1'
# Patch only the isolated fixture's identity pin; production never accepts a test override.
$environmentId = 'atlaso-test-environment'
$environmentDigest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
        [Text.Encoding]::UTF8.GetBytes($environmentId)
    ))
$moduleSource = [IO.File]::ReadAllText($modulePath)
$moduleSource = $moduleSource -replace "(?<=ExpectedEnvironmentIdSha256 = ')[A-F0-9]{64}", $environmentDigest
[IO.File]::WriteAllText($modulePath, $moduleSource)
Import-Module $modulePath -Force
$fixtureLocalRoot = Join-Path $repositoryRoot '.atlaso-local'
$tokenPath = Join-Path $repositoryRoot '.atlaso-local\token.dpapi'
$environmentPath = Join-Path $repositoryRoot '.atlaso-local\onepassword-environment-id'
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
    foreach ($invalidId in @('', 'invalid id', 'different-environment')) {
        try {
            & $setupPath -Token $firstSecureToken -TokenFile $tokenPath -EnvironmentId $invalidId | Out-Null
            throw 'An invalid Environment ID unexpectedly succeeded.'
        }
        catch {
            if ($_.Exception.Message -notlike '*OnePasswordEnvironmentId*') { throw }
        }
        if ((Test-Path -LiteralPath $tokenPath) -or (Test-Path -LiteralPath $environmentPath)) {
            throw 'Invalid Environment setup created a configuration file.'
        }
    }
    & $setupPath -Token $firstSecureToken -TokenFile $tokenPath -EnvironmentId $environmentId | Out-Null
    if ([IO.File]::ReadAllText($environmentPath) -cne $environmentId) {
        throw 'Setup did not create the exact single-line Environment ID.'
    }
    # Preserve bytes (including an existing newline) through subsequent setup and rotation.
    [IO.File]::WriteAllText($environmentPath, "$environmentId`r`n")
    $ciphertext = [System.IO.File]::ReadAllText($tokenPath)
    if ($ciphertext.Contains($firstToken)) {
        throw 'The service-account token was stored in plaintext.'
    }
    $resolvedTokenPath = Assert-AtlasoOnePasswordServiceAccountTokenFile -Path $tokenPath
    if ($resolvedTokenPath -cne $tokenPath) {
        throw 'The token-file validator changed the exact destination path.'
    }
    $hardLinkPath = Join-Path $fixtureLocalRoot 'token-hard-link.dpapi'
    try {
        New-Item -ItemType HardLink -Path $hardLinkPath -Target $tokenPath | Out-Null
        try {
            Assert-AtlasoOnePasswordServiceAccountTokenFile -Path $tokenPath | Out-Null
            throw 'A multiply linked token file unexpectedly succeeded.'
        }
        catch {
            if ($_.Exception.Message -notlike '*exactly one hard link*') {
                throw
            }
        }
    }
    finally {
        Remove-Item -LiteralPath $hardLinkPath -Force -ErrorAction SilentlyContinue
    }
    $roundTrip = ConvertFrom-SecureString `
        -SecureString (ConvertTo-SecureString -String $ciphertext) `
        -AsPlainText
    if ($roundTrip -cne $firstToken) {
        throw 'The current-user DPAPI token round trip failed.'
    }

    try {
        Resolve-AtlasoOnePasswordServiceAccountTokenFile `
            -TokenFile (Join-Path $fixtureLocalRoot 'missing.dpapi') `
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

    $missingSystemPath = Join-Path $fixtureLocalRoot 'missing-system.dpapi'
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

    $partialReadPath = Join-Path $fixtureLocalRoot 'partial-read.dpapi'
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
    if ([IO.File]::ReadAllText($environmentPath) -cne "$environmentId`r`n") {
        throw 'Token rotation replaced the existing Environment ID file.'
    }
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

    $malformedPath = Join-Path $fixtureLocalRoot 'malformed.dpapi'
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

    $childPath = Join-Path $fixtureLocalRoot 'inspect-environment.ps1'
    $resultPath = Join-Path $fixtureLocalRoot 'child-result.json'
    $childSource = @'
param([Parameter(Mandatory = $true)][string]$ResultPath)
$present = -not [string]::IsNullOrWhiteSpace($env:OP_SERVICE_ACCOUNT_TOKEN)
[System.IO.File]::WriteAllText($ResultPath, (@{ TokenPresent = $present } | ConvertTo-Json -Compress))
'@
    [System.IO.File]::WriteAllText($childPath, $childSource)
    $argumentsPath = Join-Path $fixtureLocalRoot 'arguments.json'
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

    $corruptPath = Join-Path $fixtureLocalRoot 'corrupt.dpapi'
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

    [IO.File]::Delete($environmentPath)
    <#
    .SYNOPSIS
    Supply a synthetic Environment ID and reject unexpected secret prompts.
    .PARAMETER Prompt
    Expected Environment selector prompt.
    #>
    function Read-Host {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
            'PSAvoidOverwritingBuiltInCmdlets',
            '',
            Justification = 'Test-scoped prompt stub exercises omitted selectors without interactive input.'
        )]
        param([string]$Prompt)
        if ($Prompt -cne 'Atlaso 1Password Environment ID') {
            throw 'Unexpected setup prompt.'
        }
        return 'atlaso-test-environment'
    }
    & $setupPath -Token $firstSecureToken -TokenFile $tokenPath -Force | Out-Null
    if ([IO.File]::ReadAllText($environmentPath) -cne $environmentId) {
        throw 'The prompted Environment ID was not persisted.'
    }
    [IO.File]::WriteAllText($environmentPath, "invalid`nselector")
    $beforeInvalidSelector = [IO.File]::ReadAllText($tokenPath)
    try {
        & $setupPath -Token $rotatedSecureToken -TokenFile $tokenPath -Force | Out-Null
        throw 'An invalid existing selector unexpectedly succeeded.'
    }
    catch {
        if ($_.Exception.Message -notlike '*exactly one non-empty line*') { throw }
    }
    if ([IO.File]::ReadAllText($tokenPath) -cne $beforeInvalidSelector -or
        [IO.File]::ReadAllText($environmentPath) -cne "invalid`nselector") {
        throw 'Invalid existing selector validation modified configuration.'
    }
    Write-Output 'Atlaso 1Password service-account tests passed.'
}
finally {
    $env:OP_SERVICE_ACCOUNT_TOKEN = $null
    if (Test-Path -LiteralPath $testRoot) {
        $expectedParent = [IO.Path]::GetFullPath((Join-Path $sourceRoot '.atlaso-local')) + '\'
        if (-not [IO.Path]::GetFullPath($testRoot).StartsWith($expectedParent, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'The test cleanup root is outside the task checkout.'
        }
        [System.IO.Directory]::Delete($testRoot, $true)
    }
}
