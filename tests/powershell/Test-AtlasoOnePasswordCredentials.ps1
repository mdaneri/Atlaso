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
$defaultPackageSource = Resolve-AtlasoPipPackageSource
if ($defaultPackageSource.PipGlobalIndex -cne 'https://pypi.org/pypi' -or
    $defaultPackageSource.PipGlobalIndexUrl -cne 'https://pypi.org/simple' -or
    $defaultPackageSource.IsExplicit) {
    throw 'The omitted package-source pair did not resolve to the deterministic public defaults.'
}
$explicitPackageSource = Resolve-AtlasoPipPackageSource `
    -PipGlobalIndex 'https://mirror.example.test/api/pypi' `
    -PipGlobalIndexUrl 'https://mirror.example.test/simple'
if ($explicitPackageSource.PipGlobalIndex -cne 'https://mirror.example.test/api/pypi' -or
    $explicitPackageSource.PipGlobalIndexUrl -cne 'https://mirror.example.test/simple' -or
    -not $explicitPackageSource.IsExplicit) {
    throw 'The explicit package-source pair did not retain both distinct values.'
}
foreach ($invalidPackageSource in @(
        @{ PipGlobalIndex = 'https://mirror.example.test/api/pypi'; PipGlobalIndexUrl = '' },
        @{ PipGlobalIndex = ''; PipGlobalIndexUrl = 'https://mirror.example.test/simple' },
        @{ PipGlobalIndex = 'https://user:password@mirror.example.test/api/pypi'; PipGlobalIndexUrl = 'https://mirror.example.test/simple' },
        @{ PipGlobalIndex = 'https://mirror.example.test/api/pypi'; PipGlobalIndexUrl = 'https://mirror.example.test/simple?token=fixture' },
        @{ PipGlobalIndex = 'http://mirror.example.test/api/pypi'; PipGlobalIndexUrl = 'https://mirror.example.test/simple' }
    )) {
    try {
        Resolve-AtlasoPipPackageSource @invalidPackageSource | Out-Null
        throw 'An incomplete, credential-bearing, or non-HTTPS package-source pair was accepted.'
    }
    catch {
        if ($_.Exception.Message -notlike 'PipGlobalIndex*') {
            throw
        }
    }
}
$partialBoundaryFailure = $null
try {
    Initialize-AtlasoOnePasswordSdkRuntime `
        -PythonCommand 'must-not-run' `
        -RepositoryRoot 'must-not-read' `
        -BridgeRoot 'must-not-create' `
        -PipGlobalIndex 'https://mirror.example.test/api/pypi' `
        -TimeoutSeconds 1 | Out-Null
}
catch {
    $partialBoundaryFailure = $_
}
if ($null -eq $partialBoundaryFailure -or
    $partialBoundaryFailure.Exception.Message -notlike 'PipGlobalIndex and PipGlobalIndexUrl*') {
    throw 'The exported SDK download boundary did not reject a partial package-source pair before activity.'
}
$partialBridgeFailure = $null
try {
    Get-AtlasoOnePasswordCredentialPair `
        -RepositoryRoot 'must-not-read' `
        -PipGlobalIndexUrl 'https://mirror.example.test/simple' `
        -TimeoutSeconds 1 | Out-Null
}
catch {
    $partialBridgeFailure = $_
}
if ($null -eq $partialBridgeFailure -or
    $partialBridgeFailure.Exception.Message -notlike 'PipGlobalIndex and PipGlobalIndexUrl*') {
    throw 'The exported credential bridge did not reject a partial package-source pair before activity.'
}

$classifiedBoundedFailure = $null
$classifiedBoundedOutput = @()
try {
    $classifiedBoundedOutput = @(Invoke-AtlasoBoundedProcess `
            -FilePath (Get-Process -Id $PID).Path `
            -ArgumentList @(
                '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
                '[Console]::Out.Write("stdout-fixture"); [Console]::Error.Write("HTTPSConnectionPool token=hidden"); exit 2'
            ) `
            -TimeoutSeconds 30 `
            -Action 'Focused bounded classification test' `
            -FailureClassification onepassword_dependency `
            -DiscardOutput)
}
catch {
    $classifiedBoundedFailure = $_
}
if ($classifiedBoundedOutput.Count -ne 0 -or
    $null -eq $classifiedBoundedFailure -or
    $classifiedBoundedFailure.Exception.Message -notmatch 'exit code 2' -or
    $classifiedBoundedFailure.Exception.Message -notmatch 'index, connectivity, TLS, or proxy failure' -or
    $classifiedBoundedFailure.Exception.Message -match 'stdout-fixture|HTTPSConnectionPool|token=hidden') {
    throw 'The fixed bounded failure classifier allowed captured child streams to escape the runner.'
}
$discardedBoundedOutput = @(Invoke-AtlasoBoundedProcess `
        -FilePath (Get-Process -Id $PID).Path `
        -ArgumentList @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
            '[Console]::Out.Write("successful-output-must-not-surface")'
        ) `
        -TimeoutSeconds 30 `
        -Action 'Focused bounded discard-output test' `
        -DiscardOutput)
if ($discardedBoundedOutput.Count -ne 0) {
    throw 'The bounded runner emitted successful output despite explicit suppression.'
}
$ordinaryBoundedFailure = $null
try {
    Invoke-AtlasoBoundedProcess `
        -FilePath (Get-Process -Id $PID).Path `
        -ArgumentList @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
            '[Console]::Error.Write("raw-child-output-must-not-surface"); exit 4'
        ) `
        -TimeoutSeconds 30 `
        -Action 'Focused ordinary bounded failure' | Out-Null
}
catch {
    $ordinaryBoundedFailure = $_
}
if ($null -eq $ordinaryBoundedFailure -or
    $ordinaryBoundedFailure.Exception.Message -notmatch 'exit code 4' -or
    $ordinaryBoundedFailure.Exception.Message -match 'raw-child-output') {
    throw 'The ordinary bounded runner did not preserve its generic non-disclosing failure contract.'
}

$diagnosticFixtures = @(
    @{ Category = 'index_connectivity_tls_proxy'; Output = 'Could not find a version that satisfies fixture'; Error = "`e[31mHTTPSConnectionPool Max retries exceeded ConnectionResetError token=hidden" },
    @{ Category = 'index_connectivity_tls_proxy'; Output = 'No matching distribution found for fixture'; Error = 'NewConnectionError Failed to establish a new connection getaddrinfo failed' },
    @{ Category = 'invocation_runtime'; Output = 'usage: pip unknown option --fixture'; Error = '' },
    @{ Category = 'distribution_unavailable'; Output = ''; Error = 'No matching distribution found for fixture' },
    @{ Category = 'hash_mismatch'; Output = 'THESE PACKAGES DO NOT MATCH THE HASHES expected sha256 fixture'; Error = '' },
    @{ Category = 'unclassified'; Output = ''; Error = '' }
)
foreach ($fixture in $diagnosticFixtures) {
    $diagnostic = Get-AtlasoOnePasswordDependencyFailure `
        -ExitCode 2 `
        -StandardOutput $fixture.Output `
        -StandardError $fixture.Error
    if ($diagnostic.Category -cne $fixture.Category -or
        $diagnostic.Message -notmatch 'exit code 2' -or
        $diagnostic.Message -match 'token=hidden|fixture|HTTPSConnectionPool|[\x00-\x1f\x7f]') {
        throw "The $($fixture.Category) dependency diagnostic was not useful and fully sanitized."
    }
}

$indexLockTestRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    "atlaso-onepassword-index-lock-$([guid]::NewGuid().ToString('N'))"
)
[void][System.IO.Directory]::CreateDirectory($indexLockTestRoot)
try {
    $canonicalLockPath = Join-Path $repositoryRoot 'requirements-onepassword-deploy.lock'
    $indexLockPath = Join-Path $indexLockTestRoot 'remaining.lock'
    New-AtlasoOnePasswordIndexLock `
        -LockPath $canonicalLockPath `
        -DestinationPath $indexLockPath | Out-Null
    $indexLockText = Get-Content -LiteralPath $indexLockPath -Raw
    if ($indexLockText -cmatch '(?m)^onepassword-sdk==' -or
        $indexLockText -cnotmatch '(?m)^paramiko==') {
        throw 'The index-download lock did not exclude only the preverified 1Password SDK requirement.'
    }
    if ((Get-Content -LiteralPath $canonicalLockPath -Raw) -cnotmatch '(?m)^onepassword-sdk==0\.4\.1') {
        throw 'Creating the index-download lock modified the canonical deployment lock.'
    }
    $pipConfigurationPath = & $credentialModule {
        param([string]$Path, [string]$Index, [string]$IndexUrl)
        New-AtlasoOnePasswordPipConfiguration `
            -Path $Path `
            -PipGlobalIndex $Index `
            -PipGlobalIndexUrl $IndexUrl `
            -LocalWheelDirectory (Join-Path ([System.IO.Path]::GetDirectoryName($Path)) 'wheels')
    } (Join-Path $indexLockTestRoot 'pip.ini') `
        $explicitPackageSource.PipGlobalIndex `
        $explicitPackageSource.PipGlobalIndexUrl
    $pipConfigurationText = Get-Content -LiteralPath $pipConfigurationPath -Raw
    if ($pipConfigurationText -cnotmatch '(?m)^index = https://mirror\.example\.test/api/pypi\r?$' -or
        $pipConfigurationText -cnotmatch '(?m)^index-url = https://mirror\.example\.test/simple\r?$' -or
        ([regex]::Matches($pipConfigurationText, '(?m)^extra-index-url = https://mirror\.example\.test/simple\r?$')).Count -ne 2 -or
        ([regex]::Matches($pipConfigurationText, '(?m)^find-links = .+\\wheels\r?$')).Count -ne 2 -or
        ([regex]::Matches($pipConfigurationText, '(?m)^no-index = false\r?$')).Count -ne 2 -or
        $pipConfigurationText -cnotmatch '(?m)^\[download\]\r?$' -or
        $pipConfigurationText -match 'pypi\.org') {
        throw 'The private SDK pip configuration did not override global and download sources without public fallback.'
    }

    $duplicateLockPath = Join-Path $indexLockTestRoot 'duplicate.lock'
    $duplicateRequirement = @(
        'onepassword-sdk==0.4.1 \'
        '    --hash=sha256:070541f5d007f8bfa63ffd937e4717e4d3d04100096e807a05028a8a62d49b94'
    )
    [System.IO.File]::WriteAllLines(
        $duplicateLockPath,
        @($duplicateRequirement + $duplicateRequirement),
        [System.Text.UTF8Encoding]::new($false)
    )
    try {
        New-AtlasoOnePasswordIndexLock `
            -LockPath $duplicateLockPath `
            -DestinationPath (Join-Path $indexLockTestRoot 'invalid.lock') | Out-Null
        throw 'A duplicate 1Password SDK requirement was accepted for index resolution.'
    }
    catch {
        if ($_.Exception.Message -notlike '*exactly one onepassword-sdk==0.4.1*') {
            throw
        }
    }
}
finally {
    Remove-Item -LiteralPath $indexLockTestRoot -Recurse -Force -ErrorAction SilentlyContinue
}
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
    $python310Path = Join-Path $pythonInventoryRoot 'python310.exe'
    [System.IO.File]::WriteAllBytes($python310Path, [byte[]](1))
    [System.IO.File]::WriteAllBytes($python311Path, [byte[]](1))
    [System.IO.File]::WriteAllBytes($python312Path, [byte[]](1))
    [System.IO.File]::WriteAllBytes($python313Path, [byte[]](1))
    $pythonInventory = @(
        " -V:Astral/CPython3.11.1 $python311Path *",
        " -V:Astral/CPython3.12.1 * $python312Path",
        " -3.14-64 $python313Path *"
    ) -join "`n"
    $selectedPython = & $credentialModule {
        param([string]$InventoryOutput)
        Select-AtlasoOnePasswordPythonFromLauncherInventory -LauncherOutput $InventoryOutput
    } $pythonInventory
    if ($selectedPython.Path -cne $python313Path) {
        throw 'The highest compatible tagged or legacy Python runtime was not selected after removing default markers.'
    }
    $python314Path = Join-Path $pythonInventoryRoot 'python314.exe'
    [System.IO.File]::WriteAllBytes($python314Path, [byte[]](1))
    $bracketedInventory = @(
        " -V:3.14[-64] * $python314Path",
        " -V:3.13[-64] * $python313Path",
        " -V:3.12[-arm64] $python312Path *",
        " -V:3.11[-32] $python311Path",
        " -V:3.10[-64] $python310Path"
    ) -join "`n"
    $bracketedSelectedPython = & $credentialModule {
        param([string]$InventoryOutput)
        Select-AtlasoOnePasswordPythonFromLauncherInventory -LauncherOutput $InventoryOutput
    } $bracketedInventory
    if ($bracketedSelectedPython.Path -cne $python314Path -or
        $bracketedSelectedPython.Architecture -cne '64') {
        throw 'The highest compatible Python Install Manager bracketed runtime was not selected.'
    }
    $python3141Path = Join-Path $pythonInventoryRoot 'python314-a.exe'
    $python3142Path = Join-Path $pythonInventoryRoot 'python314-z.exe'
    [System.IO.File]::WriteAllBytes($python3141Path, [byte[]](1))
    [System.IO.File]::WriteAllBytes($python3142Path, [byte[]](1))
    $patchInventory = @(
        " -V:3.14.1[-64] $python3141Path",
        " -V:3.14.2[-64] $python3142Path"
    ) -join "`n"
    $patchSelectedPython = & $credentialModule {
        param([string]$InventoryOutput)
        Select-AtlasoOnePasswordPythonFromLauncherInventory -LauncherOutput $InventoryOutput
    } $patchInventory
    if ($patchSelectedPython.Path -cne $python3142Path -or
        $patchSelectedPython.Version -ne [version]'3.14.2') {
        throw 'An older CPython 3.14 patch release outranked the highest compatible registration.'
    }
    $bracketedArmSelectedPython = & $credentialModule {
        param([string]$InventoryOutput)
        Select-AtlasoOnePasswordPythonFromLauncherInventory -LauncherOutput $InventoryOutput
    } " -V:3.12[-arm64] $python312Path *"
    if (@($bracketedArmSelectedPython).Count -ne 0) {
        throw 'An unsupported bracketed ARM64 runtime was admitted.'
    }
    $unsupportedPythonPath = Join-Path $pythonInventoryRoot 'python313x86.exe'
    [System.IO.File]::WriteAllBytes($unsupportedPythonPath, [byte[]](1))
    $architectureInventory = @(
        " -3.14-32 $unsupportedPythonPath",
        " -3.14-64 $python312Path"
    ) -join "`n"
    $architectureSelectedPython = & $credentialModule {
        param([string]$InventoryOutput)
        Select-AtlasoOnePasswordPythonFromLauncherInventory -LauncherOutput $InventoryOutput
    } $architectureInventory
    if ($architectureSelectedPython.Path -cne $python312Path -or
        $architectureSelectedPython.Architecture -cne '64') {
        throw 'A newer unsupported x86 runtime outranked the compatible 64-bit runtime.'
    }
    $bracketedArchitectureInventory = @(
        " -V:3.14[-32] $unsupportedPythonPath",
        " -V:3.14[-64] $python312Path"
    ) -join "`n"
    $bracketedArchitectureSelectedPython = & $credentialModule {
        param([string]$InventoryOutput)
        Select-AtlasoOnePasswordPythonFromLauncherInventory -LauncherOutput $InventoryOutput
    } $bracketedArchitectureInventory
    if ($bracketedArchitectureSelectedPython.Path -cne $python312Path) {
        throw 'A bracketed x86 runtime outranked a compatible bracketed 64-bit runtime.'
    }
    $vendorPythonPath = Join-Path $pythonInventoryRoot 'python313vendor.exe'
    [System.IO.File]::WriteAllBytes($vendorPythonPath, [byte[]](1))
    $vendorArchitectureInventory = @(
        " -V:Astral/CPython3.14.1 $vendorPythonPath",
        " -3.14-64 $python312Path"
    ) -join "`n"
    $vendorArchitectureSelectedPython = & $credentialModule {
        param([string]$InventoryOutput, [scriptblock]$ArchitectureProbe)
        Select-AtlasoOnePasswordPythonFromLauncherInventory `
            -LauncherOutput $InventoryOutput `
            -ArchitectureResolver $ArchitectureProbe
    } $vendorArchitectureInventory {
        param([string]$CandidatePath, [int]$TimeoutSeconds)
        if ([System.IO.Path]::GetFileName($CandidatePath) -ceq 'python313vendor.exe' -and
            $TimeoutSeconds -eq 30) { '32' } else { '64' }
    }
    if ($vendorArchitectureSelectedPython.Path -cne $python312Path) {
        throw 'An architecture-unspecified vendor x86 runtime outranked the compatible 64-bit runtime.'
    }
    $missingPythonPath = Join-Path $pythonInventoryRoot 'missing-python.exe'
    foreach ($invalidInventory in @(
            " -V:3.14t[-64] $python314Path",
            " -V:3.9[-64] $python310Path",
            " -V:3.13[-32] $unsupportedPythonPath",
            " -V:3.13[-x64] $python313Path",
            " -V:3.13[-64 $python313Path",
            " -V:3.13[-64] $missingPythonPath",
            " -V:3.13[-64] $python313Path.txt",
            " malformed -V:3.13[-64] $python313Path"
        )) {
        $invalidSelectedPython = @(& $credentialModule {
                param([string]$InventoryOutput)
                Select-AtlasoOnePasswordPythonFromLauncherInventory -LauncherOutput $InventoryOutput
            } $invalidInventory)
        if ($invalidSelectedPython.Count -ne 0) {
            throw 'An unsupported, malformed, x86, or missing Python inventory entry was accepted.'
        }
    }
}
finally {
    [System.IO.Directory]::Delete($pythonInventoryRoot, $true)
}
$validRuntimeProbe = '{"implementation":"CPython","version":"3.14","bits":64,"machine":"amd64","gil_disabled":false}'
& $credentialModule {
    param([string]$RuntimeJson)
    Assert-AtlasoOnePasswordRuntimeProbe -RuntimeJson $RuntimeJson
} $validRuntimeProbe
foreach ($invalidRuntimeProbe in @(
        '{"implementation":"CPython","version":"3.13","bits":64,"machine":"amd64","gil_disabled":false}',
        '{"implementation":"CPython","version":"3.14","bits":32,"machine":"x86","gil_disabled":false}',
        '{"implementation":"CPython","version":"3.14","bits":64,"machine":"arm64","gil_disabled":false}',
        '{"implementation":"CPython","version":"3.14","bits":64,"machine":"amd64","gil_disabled":true}',
        '{"implementation":"PyPy","version":"3.14","bits":64,"machine":"amd64","gil_disabled":false}',
        'not-json'
    )) {
    try {
        & $credentialModule {
            param([string]$RuntimeJson)
            Assert-AtlasoOnePasswordRuntimeProbe -RuntimeJson $RuntimeJson
        } $invalidRuntimeProbe
        throw 'An unsupported CPython runtime probe was accepted.'
    }
    catch {
        if ($_.Exception.Message -notlike '*requires standard GIL-enabled*' -and
            $_.Exception.Message -notlike '*could not validate*') {
            throw
        }
    }
}
$cliPackageRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    "atlaso-cli-inventory-$([guid]::NewGuid().ToString('N'))"
)
$cliPackageDirectory = Join-Path $cliPackageRoot 'AgileBits.1Password.CLI_test'
[void][System.IO.Directory]::CreateDirectory($cliPackageDirectory)
$packagedCliPath = Join-Path $cliPackageDirectory 'op.exe'
[System.IO.File]::WriteAllBytes($packagedCliPath, [byte[]](1))
try {
    $resolvedPackagedCli = Resolve-AtlasoOnePasswordCliPath `
        -CandidatePaths @() `
        -PackageRoot $cliPackageRoot `
        -CommandResolver { param($Name) $null }
    if ($resolvedPackagedCli -cne $packagedCliPath) {
        throw 'The single WinGet package CLI fallback was not selected.'
    }
}
finally {
    [System.IO.Directory]::Delete($cliPackageRoot, $true)
}
$cleanupMarkerPath = Join-Path $repositoryRoot '.atlaso-local\onepassword-credential-cleanup.json'
if (Test-Path -LiteralPath $cleanupMarkerPath) {
    throw 'A focused credential test cannot start with retained cleanup ownership.'
}
$initialBridgeRoots = @(Get-ChildItem -LiteralPath ([System.IO.Path]::GetTempPath()) -Directory |
    Where-Object { $_.Name -like 'atlaso-onepassword-credentials-*' } |
    ForEach-Object { $_.FullName })

$recoveryBridgeRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'atlaso-onepassword-credentials-' + [guid]::NewGuid().ToString('N')
)
[void][System.IO.Directory]::CreateDirectory($recoveryBridgeRoot)
$recoveryRootIdentity = & $credentialModule {
    param([string]$Path)
    Get-AtlasoPathIdentity -Path $Path -Description 'Focused 1Password recovery root'
} $recoveryBridgeRoot
$recoveryTemporaryRoot = [System.IO.Path]::GetFullPath(
    (Split-Path -Parent $recoveryBridgeRoot)
).TrimEnd('\')
$recoveryTemporaryRootIdentity = & $credentialModule {
    param([string]$Path)
    Get-AtlasoPathIdentity -Path $Path -Description 'Focused 1Password temporary root'
} $recoveryTemporaryRoot
$recoveryJobName = 'Local\Atlaso-OnePassword-' + [guid]::NewGuid().ToString('N')
$recoveryJob = New-AtlasoBoundedProcessJob `
    -FilePath (Get-Process -Id $PID).Path `
    -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 30') `
    -ProcessJobName $recoveryJobName `
    -DeferResume
try {
    $recoveryMarker = [ordered]@{
        Schema                       = 3
        RootPath                     = $recoveryBridgeRoot
        RootIdentity                 = $recoveryRootIdentity
        TemporaryRootPath            = $recoveryTemporaryRoot
        TemporaryRootIdentity        = $recoveryTemporaryRootIdentity
        BootIdentity                 = Get-AtlasoWindowsBootIdentity
        Phase                        = 'active'
        OwnerProcessId               = [int]::MaxValue
        OwnerProcessStartFileTimeUtc = 1
        ProcessJobName               = $recoveryJobName
        ChildProcessId               = $recoveryJob.RootProcess.Id
        ChildProcessStartFileTimeUtc = `
            $recoveryJob.RootProcess.StartTime.ToUniversalTime().ToFileTimeUtc()
        ProcessOwnershipPhase        = 'assigned'
    }
    [void][System.IO.Directory]::CreateDirectory((Split-Path -Parent $cleanupMarkerPath))
    Write-AtlasoDurableJsonFile -Path $cleanupMarkerPath -Payload $recoveryMarker
    $recoveryJob.Resume()
    & $credentialModule {
        param([string]$RepositoryRoot)
        Invoke-AtlasoOnePasswordCredentialBridgeReset `
            -RepositoryRoot $RepositoryRoot `
            -TerminateOwnedProcess `
            -Confirm:$false | Out-Null
    } $repositoryRoot
    if ((Test-Path -LiteralPath $cleanupMarkerPath -PathType Leaf) -or
        (Test-Path -LiteralPath $recoveryBridgeRoot -PathType Container) -or
        (Get-Process -Id $recoveryMarker.ChildProcessId -ErrorAction SilentlyContinue)) {
        throw 'Same-boot 1Password bridge recovery did not terminate and retire its exact owned state.'
    }
}
finally {
    $recoveryJob.Dispose()
    if (Test-Path -LiteralPath $cleanupMarkerPath) {
        Remove-Item -LiteralPath $cleanupMarkerPath -Force
    }
    if (Test-Path -LiteralPath $recoveryBridgeRoot) {
        [System.IO.Directory]::Delete($recoveryBridgeRoot, $true)
    }
}

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

$ordinaryFailure = $null
try {
    Invoke-AtlasoBoundedStreamingProcess `
        -FilePath (Get-Process -Id $PID).Path `
        -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'exit 9') `
        -TimeoutSeconds 10 `
        -Action 'Focused ordinary failure test'
}
catch {
    $ordinaryFailure = $_
}
if ($null -eq $ordinaryFailure -or
    $ordinaryFailure.Exception.Message -notmatch 'exit code 9' -or
    -not $ordinaryFailure.Exception.Data['AtlasoProcessTreeTerminationProven']) {
    throw 'An ordinary nonzero exit was not reported after proven whole-process-tree termination.'
}

$publicationFailure = $null
try {
    Invoke-AtlasoBoundedStreamingProcess `
        -FilePath (Get-Process -Id $PID).Path `
        -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 30') `
        -TimeoutSeconds 10 `
        -Action 'Focused ownership-publication failure test' `
        -ProcessJobName "Local\Atlaso-Photon-$([guid]::NewGuid().ToString('N'))" `
        -ProcessOwnershipPublisher { throw 'Focused ownership publication failed.' }
}
catch {
    $publicationFailure = $_
}
if ($null -eq $publicationFailure -or
    $publicationFailure.Exception.Message -notmatch 'interrupted after proven whole-process-tree termination' -or
    $null -eq $publicationFailure.Exception.InnerException -or
    $publicationFailure.Exception.InnerException.Message -cne 'Focused ownership publication failed.' -or
    -not $publicationFailure.Exception.Data['AtlasoProcessTreeTerminationProven']) {
    throw 'An ownership-publication failure did not preserve its initiating cause after proven termination.'
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
