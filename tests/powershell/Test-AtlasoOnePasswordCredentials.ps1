<#
.SYNOPSIS
Exercise the shared Atlaso 1Password credential bridge without live secrets.

.DESCRIPTION
Validates explicit SecureString round trips, policy rejection, independent
omission handling, caller-environment rejection, and bridge cleanup.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingConvertToSecureStringWithPlainText',
    '',
    Justification = 'Focused test constructs fixed synthetic values and never handles real credentials.'
)]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
. (Join-Path $repositoryRoot 'scripts\windows\vmware\Atlaso.WorkstationFirstBoot.ps1')
Import-Module (Join-Path $repositoryRoot 'scripts\windows\vmware\Atlaso.OnePasswordCredentials.psm1') -Force
$credentialModule = Get-Module -Name 'Atlaso.OnePasswordCredentials'
$explicitAccount = Resolve-AtlasoOnePasswordAccount `
    -Account 'atlaso-test-account' `
    -TimeoutSeconds 30
if ($explicitAccount -cne 'atlaso-test-account') {
    throw 'The explicit 1Password account selector was not authoritative.'
}
try {
    Assert-AtlasoOnePasswordAccount -Account ''
    throw 'An empty 1Password account selector was accepted.'
}
catch {
    if ($_.Exception.Message -notlike 'OnePasswordAccount is required*') {
        throw
    }
}
$inventoryAccount = & $credentialModule {
    param([string]$InventoryJson)
    ConvertFrom-AtlasoOnePasswordAccountInventory -AccountOutput $InventoryJson
} '[{"account_uuid":"TESTACCOUNT1234567890123456"}]'
if ($inventoryAccount -cne 'TESTACCOUNT1234567890123456') {
    throw 'The unique 1Password account inventory was not selected.'
}
foreach ($invalidInventory in @(
        '[]',
        '[{"account_uuid":"ONE"},{"account_uuid":"TWO"}]',
        'not-json'
    )) {
    try {
        & $credentialModule {
            param([string]$InventoryJson)
            ConvertFrom-AtlasoOnePasswordAccountInventory -AccountOutput $InventoryJson
        } $invalidInventory | Out-Null
        throw 'An unavailable or ambiguous 1Password account inventory was accepted.'
    }
    catch {
        if ($_.Exception.Message -notlike '*1Password account inventory*' -and
            $_.Exception.Message -notlike '*exactly one discoverable 1Password account*') {
            throw
        }
    }
}
$pythonInventoryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    "atlaso-python-inventory-$([guid]::NewGuid().ToString('N'))"
)
[void][System.IO.Directory]::CreateDirectory($pythonInventoryRoot)
try {
    $python312Path = Join-Path $pythonInventoryRoot 'python312.exe'
    $python313Path = Join-Path $pythonInventoryRoot 'python313.exe'
    $python311Path = Join-Path $pythonInventoryRoot 'python311.exe'
    [System.IO.File]::WriteAllBytes($python311Path, [byte[]](1))
    [System.IO.File]::WriteAllBytes($python312Path, [byte[]](1))
    [System.IO.File]::WriteAllBytes($python313Path, [byte[]](1))
    $pythonInventory = @(
        " -V:Astral/CPython3.11.1 $python311Path *",
        " -V:Astral/CPython3.12.1 * $python312Path",
        " -3.13-64 $python313Path *"
    ) -join "`n"
    $selectedPython = & $credentialModule {
        param([string]$InventoryOutput)
        Select-AtlasoOnePasswordPythonFromLauncherInventory -LauncherOutput $InventoryOutput
    } $pythonInventory
    if ($selectedPython.Path -cne $python313Path) {
        throw 'The highest compatible tagged or legacy Python runtime was not selected after removing default markers.'
    }
}
finally {
    [System.IO.Directory]::Delete($pythonInventoryRoot, $true)
}
$cleanupMarkerPath = Join-Path $repositoryRoot '.atlaso-local\onepassword-credential-cleanup.json'
if (Test-Path -LiteralPath $cleanupMarkerPath) {
    throw 'A focused credential test cannot start with retained cleanup ownership.'
}
$initialBridgeRoots = @(Get-ChildItem -LiteralPath ([System.IO.Path]::GetTempPath()) -Directory |
    Where-Object { $_.Name -like 'atlaso-onepassword-credentials-*' } |
    ForEach-Object { $_.FullName })

$adminText = 'unit-admin-credential-123!'
$rootText = 'unit-root-credential-456!'
$adminPassword = ConvertTo-SecureString $adminText -AsPlainText -Force
$rootPassword = ConvertTo-SecureString $rootText -AsPlainText -Force
$pair = Get-AtlasoOnePasswordCredentialPair `
    -RepositoryRoot $repositoryRoot `
    -AdminPassword $adminPassword `
    -RootPassword $rootPassword `
    -TimeoutSeconds 30 `
    -ConsumerDescription 'focused test'
try {
    if ((ConvertFrom-SecureString $pair.AdminPassword -AsPlainText) -cne $adminText) {
        throw 'The administrator SecureString did not round trip exactly.'
    }
    if ((ConvertFrom-SecureString $pair.RootPassword -AsPlainText) -cne $rootText) {
        throw 'The root SecureString did not round trip exactly.'
    }
}
finally {
    $adminText = $null
    $rootText = $null
    $pair = $null
}

$shortPassword = ConvertTo-SecureString 'too-short' -AsPlainText -Force
try {
    Get-AtlasoOnePasswordCredentialPair `
        -RepositoryRoot $repositoryRoot `
        -AdminPassword $adminPassword `
        -RootPassword $shortPassword `
        -TimeoutSeconds 30 `
        -ConsumerDescription 'focused test' | Out-Null
    throw 'A policy-invalid explicit credential was accepted.'
}
catch {
    if ($_.Exception.Message -notlike '*explicit root password does not satisfy*') {
        throw
    }
}

try {
    Get-AtlasoOnePasswordCredentialPair `
        -RepositoryRoot $repositoryRoot `
        -AdminPassword $adminPassword `
        -RootPassword $null `
        -TimeoutSeconds 30 `
        -ConsumerDescription 'focused test' | Out-Null
    throw 'An omitted credential was accepted without the exact Environment.'
}
catch {
    if ($_.Exception.Message -notlike 'OnePasswordEnvironmentId is required*') {
        throw
    }
}

$previousAdminEnvironment = $env:DEFAULT_ADMIN_PASSWORD
$previousRootEnvironment = $env:DEFAULT_ROOT_PASSWORD
try {
    $env:DEFAULT_ADMIN_PASSWORD = 'caller-admin-must-not-be-used'
    $env:DEFAULT_ROOT_PASSWORD = 'caller-root-must-not-be-used'
    try {
        Get-AtlasoOnePasswordCredentialPair `
            -RepositoryRoot $repositoryRoot `
            -AdminPassword $adminPassword `
            -RootPassword $rootPassword `
            -TimeoutSeconds 30 `
            -ConsumerDescription 'focused test' | Out-Null
        throw 'Caller credential environment variables were accepted.'
    }
    catch {
        if ($_.Exception.Message -notlike 'DEFAULT_ADMIN_PASSWORD and DEFAULT_ROOT_PASSWORD must not be supplied*') {
            throw
        }
    }
}
finally {
    $env:DEFAULT_ADMIN_PASSWORD = $previousAdminEnvironment
    $env:DEFAULT_ROOT_PASSWORD = $previousRootEnvironment
}

$newBridgeRoots = @(Get-ChildItem -LiteralPath ([System.IO.Path]::GetTempPath()) -Directory |
    Where-Object {
        $_.Name -like 'atlaso-onepassword-credentials-*' -and
        $_.FullName -notin $initialBridgeRoots
    })
if ($newBridgeRoots.Count -ne 0) {
    throw 'A focused credential bridge test left a task-created temporary root.'
}
if (Test-Path -LiteralPath $cleanupMarkerPath) {
    throw 'A focused credential bridge test left its durable cleanup marker.'
}

$processTreeToken = "atlaso-descendant-$([guid]::NewGuid().ToString('N'))"
$childSource = @'
$null = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList @(
    '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
    'Start-Sleep -Seconds 30', '__ATLASO_PROCESS_TREE_TOKEN__'
)
Start-Sleep -Seconds 30
'@.Replace('__ATLASO_PROCESS_TREE_TOKEN__', $processTreeToken)
$encodedChildSource = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childSource))
try {
    Invoke-AtlasoBoundedStreamingProcess `
        -FilePath (Get-Process -Id $PID).Path `
        -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encodedChildSource) `
        -TimeoutSeconds 1 `
        -Action 'Focused descendant termination test'
    throw 'The focused descendant termination test did not reach its deadline.'
}
catch {
    if (-not $_.Exception.Data['AtlasoProcessTreeTerminationProven']) {
        throw
    }
}
$survivingDescendants = @(Get-CimInstance -ClassName Win32_Process |
    Where-Object { $_.CommandLine -like "*$processTreeToken*" })
if ($survivingDescendants.Count -ne 0) {
    foreach ($survivingDescendant in $survivingDescendants) {
        Stop-Process -Id $survivingDescendant.ProcessId -Force -ErrorAction SilentlyContinue
    }
    throw 'A tracked process-tree descendant survived proven termination.'
}

$ordinaryExitToken = "atlaso-ordinary-descendant-$([guid]::NewGuid().ToString('N'))"
$ordinaryExitSource = @'
$null = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList @(
    '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
    'Start-Sleep -Seconds 30', '__ATLASO_ORDINARY_EXIT_TOKEN__'
)
'@.Replace('__ATLASO_ORDINARY_EXIT_TOKEN__', $ordinaryExitToken)
$encodedOrdinaryExitSource = [Convert]::ToBase64String(
    [Text.Encoding]::Unicode.GetBytes($ordinaryExitSource)
)
Invoke-AtlasoBoundedStreamingProcess `
    -FilePath (Get-Process -Id $PID).Path `
    -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encodedOrdinaryExitSource) `
    -TimeoutSeconds 10 `
    -Action 'Focused ordinary-exit descendant test'
$ordinaryExitSurvivors = @(Get-CimInstance -ClassName Win32_Process |
    Where-Object { $_.CommandLine -like "*$ordinaryExitToken*" })
if ($ordinaryExitSurvivors.Count -ne 0) {
    foreach ($ordinaryExitSurvivor in $ordinaryExitSurvivors) {
        Stop-Process -Id $ordinaryExitSurvivor.ProcessId -Force -ErrorAction SilentlyContinue
    }
    throw 'An ordinary-exit process-tree descendant survived completion proof.'
}

$breakawayToken = "atlaso-breakaway-$([guid]::NewGuid().ToString('N'))"
$escapedRunnerPath = (Join-Path $repositoryRoot 'scripts\windows\vmware\Atlaso.WorkstationFirstBoot.ps1') `
    -replace "'", "''"
$escapedPowerShellPath = ((Get-Process -Id $PID).Path) -replace "'", "''"
$breakawaySource = @'
. '__ATLASO_RUNNER_PATH__'
Initialize-AtlasoWorkstationProcessJobType
$breakawayArguments = @(
    '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
    'Start-Sleep -Seconds 30', '__ATLASO_BREAKAWAY_TOKEN__'
)
try {
    $breakaway = [Atlaso.WorkstationProcessJob]::StartBreakaway(
        '__ATLASO_POWERSHELL_PATH__',
        $breakawayArguments
    )
    $breakaway.Dispose()
}
catch {
    exit 23
}
'@.Replace('__ATLASO_RUNNER_PATH__', $escapedRunnerPath).
    Replace('__ATLASO_POWERSHELL_PATH__', $escapedPowerShellPath).
    Replace('__ATLASO_BREAKAWAY_TOKEN__', $breakawayToken)
$encodedBreakawaySource = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($breakawaySource))
$breakawayWasRejected = $false
try {
    Invoke-AtlasoBoundedStreamingProcess `
        -FilePath (Get-Process -Id $PID).Path `
        -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', $encodedBreakawaySource) `
        -TimeoutSeconds 10 `
        -Action 'Focused denied-breakaway test'
}
catch {
    $breakawayWasRejected = $true
}
$breakawayProcesses = @(Get-CimInstance -ClassName Win32_Process |
    Where-Object { $_.CommandLine -like "*$breakawayToken*" })
try {
    if (-not $breakawayWasRejected -or $breakawayProcesses.Count -ne 0) {
        throw 'A sensitive-consumer descendant was able to leave its Windows job.'
    }
}
finally {
    foreach ($breakawayProcess in $breakawayProcesses) {
        Stop-Process -Id $breakawayProcess.ProcessId -Force -ErrorAction SilentlyContinue
    }
}

Write-Host 'Shared Atlaso 1Password credential bridge tests passed.'
