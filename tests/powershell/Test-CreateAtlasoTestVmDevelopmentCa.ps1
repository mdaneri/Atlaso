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
Import-Module (
    Join-Path $RepositoryRoot 'scripts\windows\vmware\Atlaso.WorkstationCleanup.psm1'
) -Force
. (Join-Path $RepositoryRoot 'scripts\windows\vmware\Atlaso.WorkstationFirstBoot.ps1')

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
$firstBootSource = Get-Content -LiteralPath (
    Join-Path $RepositoryRoot 'scripts\windows\vmware\Atlaso.WorkstationFirstBoot.ps1'
) -Raw

$missingEnvironmentIdRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    "atlaso-missing-environment-id-$([guid]::NewGuid().ToString('N'))"
)
try {
    New-Item -ItemType Directory -Path $missingEnvironmentIdRoot | Out-Null
    $missingEnvironmentVmRoot = Join-Path $missingEnvironmentIdRoot 'Atlaso-PR-634-credential-preflight'
    New-Item -ItemType Directory -Path $missingEnvironmentVmRoot | Out-Null
    $preservedMarker = Join-Path $missingEnvironmentVmRoot 'preserve.txt'
    [System.IO.File]::WriteAllText($preservedMarker, 'preserve-before-preflight')
    $inertVmrunPath = Join-Path $missingEnvironmentIdRoot 'must-not-invoke-vmrun.exe'
    [System.IO.File]::WriteAllText($inertVmrunPath, '')
    $missingEnvironmentIdError = ''
    try {
        & $wrapperPath `
            -PullRequestNumber 634 `
            -Purpose 'credential preflight' `
            -OutputDirectory $missingEnvironmentVmRoot `
            -Redeploy `
            -VmrunPath $inertVmrunPath `
            -OnePasswordEnvironmentId '' `
            -EnvironmentIdFile (Join-Path $missingEnvironmentIdRoot 'missing-environment-id')
    }
    catch {
        $missingEnvironmentIdError = $_.Exception.Message
    }
    $expectedMissingEnvironmentIdError = 'OnePasswordEnvironmentId is required for normal VMware test VM creation. Pass it explicitly or store it as the only line in .atlaso-local\onepassword-environment-id.'
    if ($missingEnvironmentIdError -cne $expectedMissingEnvironmentIdError) {
        throw "Missing Environment ID did not produce the intentional preflight error: $missingEnvironmentIdError"
    }
    if (
        -not (Test-Path -LiteralPath $preservedMarker -PathType Leaf) -or
        [System.IO.File]::ReadAllText($preservedMarker) -cne 'preserve-before-preflight'
    ) {
        throw 'Missing Environment ID preflight mutated the requested VM output before failing.'
    }
}
finally {
    Remove-Item -LiteralPath $missingEnvironmentIdRoot -Recurse -Force -ErrorAction SilentlyContinue
}

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
    # Compile each parsed function into the isolated test scope without using
    # Invoke-Expression, whose ambient command resolution is unnecessarily broad.
    # Dynamic scriptblocks have no file-backed PSScriptRoot, so bind the wrapper's
    # real directory before exercising helper-script path construction.
    $wrapperScriptRootLiteral = "'$(
        (Split-Path -Parent $wrapperPath).Replace("'", "''")
    )'"
    $functionSource = $functionAst.Extent.Text.Replace(
        '$PSScriptRoot',
        $wrapperScriptRootLiteral
    )
    $functionDefinition = [scriptblock]::Create($functionSource)
    . $functionDefinition
}

Assert-Throws {
    Resolve-OnePasswordCliPath -CandidatePaths @() -PackageRoot '' -CommandResolver { return $null }
} 'A missing 1Password CLI must fail closed.'

$testEnvironmentId = 'atlaso-test-environment-id-01'
$testEnvironmentIdSha256 = [Convert]::ToHexString(
    [System.Security.Cryptography.SHA256]::HashData(
        [System.Text.Encoding]::UTF8.GetBytes($testEnvironmentId)
    )
)
$environmentIdFileRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    "atlaso-environment-id-file-$([guid]::NewGuid().ToString('N'))"
)
try {
    New-Item -ItemType Directory -Path $environmentIdFileRoot | Out-Null
    $environmentIdFile = Join-Path $environmentIdFileRoot 'onepassword-environment-id'
    [System.IO.File]::WriteAllText($environmentIdFile, $testEnvironmentId)
    $resolvedEnvironmentId = Resolve-OnePasswordDevelopmentCaEnvironmentId `
        -EnvironmentIdFile $environmentIdFile `
        -RepositoryRoot $environmentIdFileRoot
    if ($resolvedEnvironmentId -cne $testEnvironmentId) {
        throw 'The local Environment ID file did not resolve its exact single-line value.'
    }
    $explicitEnvironmentId = Resolve-OnePasswordDevelopmentCaEnvironmentId `
        -EnvironmentId $testEnvironmentId `
        -EnvironmentIdFile (Join-Path $environmentIdFileRoot 'missing') `
        -RepositoryRoot $environmentIdFileRoot
    if ($explicitEnvironmentId -cne $testEnvironmentId) {
        throw 'The explicit Environment ID must take precedence over the local file.'
    }
    [System.IO.File]::WriteAllLines($environmentIdFile, @($testEnvironmentId, 'second-line'))
    Assert-Throws {
        Resolve-OnePasswordDevelopmentCaEnvironmentId `
            -EnvironmentIdFile $environmentIdFile `
            -RepositoryRoot $environmentIdFileRoot
    } 'A multiline Environment ID file must fail closed.'
}
finally {
    Remove-Item -LiteralPath $environmentIdFileRoot -Recurse -Force -ErrorAction SilentlyContinue
}
Assert-Throws {
    Assert-OnePasswordDevelopmentCaBridge -EnvironmentId 'unsafe id' -OpPath 'ignored'
} 'Unsafe Environment IDs must fail closed.'
Assert-Throws {
    Assert-OnePasswordDevelopmentCaBridge `
        -EnvironmentId 'different-test-environment-id' `
        -OpPath 'ignored' `
        -ExpectedEnvironmentIdSha256 $testEnvironmentIdSha256
} 'A different well-formed Environment ID must fail before invoking op.'

<#
.SYNOPSIS
Return synthetic beta-CLI capability help for bridge validation tests.

.PARAMETER FilePath
Ignored executable path accepted for signature compatibility.

.PARAMETER ArgumentList
Ignored CLI arguments accepted for signature compatibility.

.PARAMETER TimeoutSeconds
Ignored bounded deadline accepted for signature compatibility.

.PARAMETER Action
Ignored action text accepted for signature compatibility.
#>
function Invoke-AtlasoBoundedProcess {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList,
        [int]$TimeoutSeconds,
        [string]$Action
    )
    return $script:fakeRunHelp
}
$script:fakeRunHelp = '--env-file only'
Assert-Throws {
    Assert-OnePasswordDevelopmentCaBridge `
        -EnvironmentId $testEnvironmentId `
        -OpPath 'stable-op' `
        -ExpectedEnvironmentIdSha256 $testEnvironmentIdSha256 `
        -TimeoutSeconds 1
} 'A stable CLI without op run --environment must fail closed.'
$script:fakeRunHelp = '--environment strings'
Assert-OnePasswordDevelopmentCaBridge `
    -EnvironmentId $testEnvironmentId `
    -OpPath 'beta-op' `
    -ExpectedEnvironmentIdSha256 $testEnvironmentIdSha256 `
    -TimeoutSeconds 1

$env:ATLASO_DEVELOPMENT_ROOT_CA_PRIVATE_KEY = 'caller-secret'
try {
    Assert-Throws {
        Assert-OnePasswordDevelopmentCaBridge `
            -EnvironmentId $testEnvironmentId `
            -OpPath 'beta-op' `
            -ExpectedEnvironmentIdSha256 $testEnvironmentIdSha256 `
            -TimeoutSeconds 1
    } 'A caller-provided development signer must fail closed.'
}
finally {
    Remove-Item Env:\ATLASO_DEVELOPMENT_ROOT_CA_PRIVATE_KEY -ErrorAction SilentlyContinue
}
Remove-Item Function:\Invoke-AtlasoBoundedProcess
. (Join-Path $RepositoryRoot 'scripts\windows\vmware\Atlaso.WorkstationFirstBoot.ps1')

$boundedProcessRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    "atlaso-bounded-process-$([guid]::NewGuid().ToString('N'))"
)
$boundedChildPid = 0
try {
    New-Item -ItemType Directory -Path $boundedProcessRoot | Out-Null
    $boundedChildPath = Join-Path $boundedProcessRoot 'child.ps1'
    $boundedParentPath = Join-Path $boundedProcessRoot 'parent.ps1'
    $boundedChildPidPath = Join-Path $boundedProcessRoot 'child.pid'
    $powerShellPath = (Get-Process -Id $PID).Path
    $escapedPowerShellPath = $powerShellPath.Replace("'", "''")
    $escapedChildPath = $boundedChildPath.Replace("'", "''")
    $escapedChildPidPath = $boundedChildPidPath.Replace("'", "''")
    [System.IO.File]::WriteAllText(
        $boundedChildPath,
        'Start-Sleep -Seconds 30',
        [System.Text.UTF8Encoding]::new($false)
    )
    [System.IO.File]::WriteAllText(
        $boundedParentPath,
        @"
`$child = Start-Process -FilePath '$escapedPowerShellPath' -ArgumentList @(
    '-NoLogo', '-NoProfile', '-NonInteractive', '-File', '$escapedChildPath'
) -PassThru
[System.IO.File]::WriteAllText('$escapedChildPidPath', [string]`$child.Id)
Start-Sleep -Seconds 30
"@,
        [System.Text.UTF8Encoding]::new($false)
    )
    $deadlineObserved = $false
    try {
        Invoke-AtlasoBoundedProcess `
            -FilePath $powerShellPath `
            -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-File', $boundedParentPath) `
            -TimeoutSeconds 2 `
            -Action 'Bounded process regression'
    }
    catch {
        if ($_.Exception.Message -notlike '*exceeded its 2-second deadline*') {
            throw
        }
        $deadlineObserved = $true
    }
    if (-not $deadlineObserved) {
        throw 'The bounded process helper did not enforce its deadline.'
    }
    if (-not (Test-Path -LiteralPath $boundedChildPidPath -PathType Leaf)) {
        throw 'The bounded process regression did not start its descendant.'
    }
    $boundedChildPid = [int][System.IO.File]::ReadAllText($boundedChildPidPath)
    Start-Sleep -Milliseconds 250
    if (Get-Process -Id $boundedChildPid -ErrorAction SilentlyContinue) {
        throw 'The bounded process helper left its descendant running after timeout.'
    }
}
finally {
    if ($boundedChildPid -gt 0) {
        Stop-Process -Id $boundedChildPid -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $boundedProcessRoot -Recurse -Force -ErrorAction SilentlyContinue
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

if ($wrapperSource -notmatch '\[switch\]\$WaitForIp' -or
    $wrapperSource -notmatch "ContainsKey\('WaitForIp'\)" -or
    $wrapperSource -notmatch '\$waitForIpEnabled = if') {
    throw 'Normal VMware test VM waiting must preserve default-enabled switch compatibility.'
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
        $wrapperSource.LastIndexOf($mutationMarker, [System.StringComparison]::Ordinal)) {
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
$stageStart = $wrapperSource.IndexOf('-Action Stage', [System.StringComparison]::Ordinal)
$importProof = $wrapperSource.IndexOf(
    'Wait-AtlasoWorkstationDevelopmentRootCaImportProof',
    $stageStart,
    [System.StringComparison]::Ordinal
)
$rollbackCatch = $wrapperSource.IndexOf("`n    catch {", $stageStart, [System.StringComparison]::Ordinal)
if ($stageStart -lt 0 -or $importProof -lt $stageStart -or $rollbackCatch -lt $importProof) {
    throw 'Encrypted-import proof must remain inside the automatic rollback boundary.'
}
foreach ($rollbackMarker in @(
        'Clear-AtlasoWorkstationDevelopmentRootCaRuntimePrivateKey',
        'Clear-AtlasoWorkstationDevelopmentRootCaPrivateKey',
        'Move-AtlasoRollbackDataDisksToQuarantine',
        "'remove-atlaso-vm.ps1'"
    )) {
    if ($wrapperSource.IndexOf($rollbackMarker, [System.StringComparison]::Ordinal) -lt 0) {
        throw "Normal test VM rollback is missing required safety step: $rollbackMarker"
    }
}
$runtimeScrub = $wrapperSource.IndexOf(
    'Clear-AtlasoWorkstationDevelopmentRootCaRuntimePrivateKey',
    [System.StringComparison]::Ordinal
)
$rollbackStop = $wrapperSource.IndexOf(
    'Stop-AtlasoTestVmForRollback',
    $runtimeScrub,
    [System.StringComparison]::Ordinal
)
if ($runtimeScrub -lt 0 -or $rollbackStop -lt $runtimeScrub) {
    throw 'Rollback must attempt runtime signer scrub before VM stop discovery.'
}
$pendingCleanupCall = $wrapperSource.LastIndexOf(
    'Invoke-PendingAtlasoDevelopmentCaCleanup',
    [System.StringComparison]::Ordinal
)
if (
    $pendingCleanupCall -lt 0 -or
    $pendingCleanupCall -gt $wrapperSource.LastIndexOf('Resolve-OnePasswordCliPath', [System.StringComparison]::Ordinal) -or
    $pendingCleanupCall -gt $wrapperSource.IndexOf("'prepare-networks.ps1'", [System.StringComparison]::Ordinal)
) {
    throw 'Durable cleanup retry must precede 1Password preflight and every new VM/network mutation.'
}
$markerCreationScope = $wrapperSource.LastIndexOf(
    '$createdThisInvocation = $false',
    [System.StringComparison]::Ordinal
)
$markerCreation = $wrapperSource.IndexOf(
    'New-AtlasoDevelopmentCaCleanupMarker',
    $markerCreationScope,
    [System.StringComparison]::Ordinal
)
if ($markerCreationScope -lt 0 -or $markerCreation -lt $markerCreationScope -or $markerCreation -gt $stageStart) {
    throw 'A durable cleanup marker must be committed before development-signer staging.'
}
if (
    $wrapperSource -notmatch 'MoveFileEx\(string existingPath, string newPath, uint flags\)' -or
    $wrapperSource -notmatch '\[uint32\]\$flags = 0x00000008' -or
    $wrapperSource.IndexOf(
        'Move-AtlasoDurableCleanupMarkerFile',
        [System.StringComparison]::Ordinal
    ) -gt $stageStart
) {
    throw 'Cleanup-marker publication must use a Windows write-through rename before signer staging.'
}
$cleanupIdentityWriter = $wrapperSource.IndexOf(
    'function Set-AtlasoTestVmCleanupIdentity',
    [System.StringComparison]::Ordinal
)
$cleanupIdentityLock = $wrapperSource.IndexOf(
    '[System.IO.FileShare]::Read',
    $cleanupIdentityWriter,
    [System.StringComparison]::Ordinal
)
$cleanupIdentityVerification = $wrapperSource.IndexOf(
    '[Atlaso.WorkstationFileIdentity]::Get($resolvedVmxPath) -cne $ExpectedVmxIdentity',
    $cleanupIdentityLock,
    [System.StringComparison]::Ordinal
)
$cleanupIdentityAppend = $wrapperSource.IndexOf(
    '$stream.Write($bytes, 0, $bytes.Length)',
    $cleanupIdentityVerification,
    [System.StringComparison]::Ordinal
)
$cleanupIdentityFlush = $wrapperSource.IndexOf(
    '$stream.Flush($true)',
    $cleanupIdentityAppend,
    [System.StringComparison]::Ordinal
)
$cleanupIdentityFunctionEnd = $wrapperSource.IndexOf(
    'function Get-AtlasoTestVmCleanupIdentityHash',
    $cleanupIdentityWriter,
    [System.StringComparison]::Ordinal
)
if (
    $cleanupIdentityWriter -lt 0 -or
    $cleanupIdentityLock -lt $cleanupIdentityWriter -or
    $cleanupIdentityVerification -lt $cleanupIdentityLock -or
    $cleanupIdentityAppend -lt $cleanupIdentityVerification -or
    $cleanupIdentityFlush -lt $cleanupIdentityAppend -or
    $cleanupIdentityFlush -gt $markerCreation
) {
    throw 'Cleanup identity publication must be identity-bound, locked, and durably flushed before marker publication.'
}
if (
    $cleanupIdentityFunctionEnd -lt $cleanupIdentityWriter -or
    $wrapperSource.Substring(
        $cleanupIdentityWriter,
        $cleanupIdentityFunctionEnd - $cleanupIdentityWriter
    ) -match 'Write-AtlasoWorkstationDurableVmxLines|MoveFileEx'
) {
    throw 'Pre-marker cleanup identity publication must preserve the original VMX file object.'
}
$cleanupIdentityRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    "atlaso-cleanup-identity-lock-$([guid]::NewGuid().ToString('N'))"
)
try {
    New-Item -ItemType Directory -Path $cleanupIdentityRoot | Out-Null
    $cleanupIdentityVmx = Join-Path $cleanupIdentityRoot 'Atlaso-Cleanup-Identity.vmx'
    [System.IO.File]::WriteAllText(
        $cleanupIdentityVmx,
        'displayName = "Atlaso Cleanup Identity"',
        [System.Text.UTF8Encoding]::new($false)
    )
    $cleanupVmxIdentity = [Atlaso.WorkstationFileIdentity]::Get($cleanupIdentityVmx)
    $cleanupOriginal = [System.IO.File]::ReadAllText($cleanupIdentityVmx)
    $cleanupMismatch = '00000000:0000000000000000'
    if ($cleanupVmxIdentity -ceq $cleanupMismatch) {
        $cleanupMismatch = 'FFFFFFFF:FFFFFFFFFFFFFFFF'
    }
    Assert-Throws {
        Set-AtlasoTestVmCleanupIdentity `
            -VmxPath $cleanupIdentityVmx `
            -Identity ('a' * 32) `
            -ExpectedVmxIdentity $cleanupMismatch
    } 'A caller-bound filesystem identity mismatch must fail closed.'
    if ([System.IO.File]::ReadAllText($cleanupIdentityVmx) -cne $cleanupOriginal) {
        throw 'A rejected cleanup identity publication changed the caller-bound VMX.'
    }
    Set-AtlasoTestVmCleanupIdentity `
        -VmxPath $cleanupIdentityVmx `
        -Identity ('b' * 32) `
        -ExpectedVmxIdentity $cleanupVmxIdentity
    if (
        [Atlaso.WorkstationFileIdentity]::Get($cleanupIdentityVmx) -cne $cleanupVmxIdentity -or
        (Get-AtlasoTestVmCleanupIdentityHash -VmxPath $cleanupIdentityVmx) -cne
        (Get-AtlasoCleanupIdentityHash -Value ('b' * 32)) -or
        -not ([System.IO.File]::ReadAllText($cleanupIdentityVmx).StartsWith($cleanupOriginal))
    ) {
        throw 'Cleanup identity publication did not retain every original byte on the caller-bound VMX.'
    }
    [System.IO.File]::AppendAllText(
        $cleanupIdentityVmx,
        "guestinfo.atlaso.test_vm_cleanup_identity = malformed`r`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    Assert-Throws {
        Get-AtlasoTestVmCleanupIdentityHash -VmxPath $cleanupIdentityVmx
    } 'A malformed duplicate cleanup identity must remain ambiguous.'

    $legacyUpgradeVmx = Join-Path $cleanupIdentityRoot 'Atlaso-Legacy-Upgrade.vmx'
    $legacyUpgradeMarker = Join-Path $cleanupIdentityRoot 'legacy-upgrade.json'
    [System.IO.File]::WriteAllText(
        $legacyUpgradeVmx,
        'displayName = "Atlaso Legacy Upgrade"',
        [System.Text.UTF8Encoding]::new($false)
    )
    $legacyUpgradeIdentity = [Atlaso.WorkstationFileIdentity]::Get($legacyUpgradeVmx)
    [System.IO.File]::WriteAllText(
        $legacyUpgradeMarker,
        (([ordered]@{
                    Schema = 2
                    Phase = 'vm-stop-child-active'
                    VmxIdentity = $legacyUpgradeIdentity
                }) | ConvertTo-Json -Compress),
        [System.Text.UTF8Encoding]::new($false)
    )
    $legacyUpgradeState = [pscustomobject]@{
        MarkerPath = $legacyUpgradeMarker
        VmxPath = $legacyUpgradeVmx
        Schema = 2
        Phase = 'vm-stop-child-active'
        VmxIdentity = $legacyUpgradeIdentity
        CleanupIdentityHash = ''
    }
    Upgrade-AtlasoLegacyDevelopmentCaCleanupMarker -Marker $legacyUpgradeState
    $legacyUpgradePayload = Get-Content -LiteralPath $legacyUpgradeMarker -Raw | ConvertFrom-Json
    if (
        [Atlaso.WorkstationFileIdentity]::Get($legacyUpgradeVmx) -cne $legacyUpgradeIdentity -or
        $legacyUpgradePayload.Schema -ne 3 -or
        $legacyUpgradePayload.Phase -cne 'import-proven-stopped-vmx-scrubbed' -or
        $legacyUpgradePayload.VmxIdentity -cne $legacyUpgradeIdentity -or
        $legacyUpgradeState.Schema -ne 3 -or
        $legacyUpgradeState.Phase -cne 'import-proven-stopped-vmx-scrubbed' -or
        $legacyUpgradeState.CleanupIdentityHash -cnotmatch '^[0-9A-F]{64}$'
    ) {
        throw 'Legacy cleanup-marker upgrade did not retain and bind the exact stopped VMX identity.'
    }

    $legacyRetryVmx = Join-Path $cleanupIdentityRoot 'Atlaso-Legacy-Retry.vmx'
    $legacyRetryMarker = Join-Path $cleanupIdentityRoot 'legacy-retry.json'
    $legacyRetryCleanupIdentity = 'c' * 32
    [System.IO.File]::WriteAllText(
        $legacyRetryVmx,
        "displayName = `"Atlaso Legacy Retry`"`r`n" +
        "guestinfo.atlaso.test_vm_cleanup_identity = `"$legacyRetryCleanupIdentity`"`r`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    $legacyRetryIdentity = [Atlaso.WorkstationFileIdentity]::Get($legacyRetryVmx)
    [System.IO.File]::WriteAllText(
        $legacyRetryMarker,
        (([ordered]@{
                    Schema = 2
                    Phase = 'vm-stop-child-active'
                    VmxIdentity = $legacyRetryIdentity
                }) | ConvertTo-Json -Compress),
        [System.Text.UTF8Encoding]::new($false)
    )
    $legacyRetryState = [pscustomobject]@{
        MarkerPath = $legacyRetryMarker
        VmxPath = $legacyRetryVmx
        Schema = 2
        Phase = 'vm-stop-child-active'
        VmxIdentity = $legacyRetryIdentity
        CleanupIdentityHash = ''
    }
    Upgrade-AtlasoLegacyDevelopmentCaCleanupMarker -Marker $legacyRetryState
    $legacyRetryPayload = Get-Content -LiteralPath $legacyRetryMarker -Raw | ConvertFrom-Json
    $legacyRetryAssignments = @(
        Get-Content -LiteralPath $legacyRetryVmx |
            Where-Object { $_ -match '^\s*guestinfo\.atlaso\.test_vm_cleanup_identity\s*=' }
    )
    if (
        $legacyRetryAssignments.Count -ne 1 -or
        [Atlaso.WorkstationFileIdentity]::Get($legacyRetryVmx) -cne $legacyRetryIdentity -or
        $legacyRetryPayload.Schema -ne 3 -or
        $legacyRetryPayload.CleanupIdentityHash -cne
        (Get-AtlasoCleanupIdentityHash -Value $legacyRetryCleanupIdentity)
    ) {
        throw 'Legacy cleanup-marker retry did not reuse the sole durable VMX cleanup identity.'
    }
}
finally {
    Remove-Item -LiteralPath $cleanupIdentityRoot -Recurse -Force -ErrorAction SilentlyContinue
}
if (
    $firstBootSource -notmatch 'function Write-AtlasoWorkstationDurableVmxLines' -or
    $firstBootSource -notmatch '\[System\.IO\.FileOptions\]::WriteThrough' -or
    $firstBootSource -notmatch '\$stream\.Flush\(\$true\)' -or
    $firstBootSource -notmatch '0x1 -bor 0x8' -or
    $firstBootSource -notmatch 'Write-AtlasoWorkstationDurableVmxLines -VmxPath \$VmxPath'
) {
    throw 'Powered-off VMX signer changes must use a flushed write-through atomic replacement.'
}
if ($wrapperSource.IndexOf('Remove-AtlasoDevelopmentCaCleanupMarker', $importProof) -lt $importProof) {
    throw 'The durable cleanup marker must remain until encrypted-import proof succeeds.'
}
if ($firstBootSource -notmatch '\$Job\.TerminateAndWait\(10000\)' -or
    $firstBootSource -notmatch 'accounting\.ActiveProcesses == 0' -or
    $wrapperSource -notmatch '-TimeoutSeconds \$TimeoutSeconds') {
    throw 'The 1Password child must enforce a deadline and prove its Windows process job is inactive.'
}
if ($firstBootSource -notmatch "AtlasoProcessTreeTerminationUnproven") {
    throw 'Unproven process-tree termination must carry a machine-readable failure marker.'
}
$childActiveDeferral = $wrapperSource.IndexOf("'secret-child-active',", $rollbackCatch, [System.StringComparison]::Ordinal)
$stopChildActiveDeferral = $wrapperSource.IndexOf("'vm-stop-child-active',", $childActiveDeferral, [System.StringComparison]::Ordinal)
$restartChildActiveDeferral = $wrapperSource.IndexOf("'vm-restart-child-active'", $stopChildActiveDeferral, [System.StringComparison]::Ordinal)
$importFinalizationDeferral = $wrapperSource.IndexOf(
    "'import-proven-stopped-vmx-scrubbed',",
    $restartChildActiveDeferral,
    [System.StringComparison]::Ordinal
)
$restartedFinalizationDeferral = $wrapperSource.IndexOf(
    "'restarted-vmx-scrubbed'",
    $importFinalizationDeferral,
    [System.StringComparison]::Ordinal
)
$rollbackRuntimeScrub = $wrapperSource.IndexOf(
    'Clear-AtlasoWorkstationDevelopmentRootCaRuntimePrivateKey',
    $rollbackCatch,
    [System.StringComparison]::Ordinal
)
if (
    $childActiveDeferral -lt $rollbackCatch -or
    $stopChildActiveDeferral -lt $childActiveDeferral -or
    $restartChildActiveDeferral -lt $stopChildActiveDeferral -or
    $importFinalizationDeferral -lt $restartChildActiveDeferral -or
    $restartedFinalizationDeferral -lt $importFinalizationDeferral -or
    $rollbackRuntimeScrub -lt $restartedFinalizationDeferral
) {
    throw 'The broad rollback handler must preserve child-active and proven-import finalization states before VM mutation.'
}
$startChildPhase = $wrapperSource.IndexOf(
    '-Phase vm-start-child-active',
    $stageStart,
    [System.StringComparison]::Ordinal
)
$boundedStart = $wrapperSource.IndexOf(
    "'Start the normal test VM after development-signer staging'",
    $stageStart,
    [System.StringComparison]::Ordinal
)
if ($startChildPhase -lt $stageStart -or $boundedStart -lt $startChildPhase) {
    throw 'The durable marker must enter its boot-bound active phase before the bounded VM-start child launches.'
}
$removalChildPhase = $wrapperSource.LastIndexOf(
    '-Phase removal-child-active',
    [System.StringComparison]::Ordinal
)
$rollbackRemoval = $wrapperSource.LastIndexOf(
    "'Remove the exact failed normal test VM during rollback'",
    [System.StringComparison]::Ordinal
)
$conditionalRestore = $wrapperSource.LastIndexOf(
    'if ($quarantineDirectory -and -not $removalTreeUnproven)',
    [System.StringComparison]::Ordinal
)
$preSecretRollbackMarker = $wrapperSource.LastIndexOf(
    '-AllowExistingCleanupIdentity | Out-Null',
    [System.StringComparison]::Ordinal
)
$preSecretMarkerReconciliation = $wrapperSource.LastIndexOf(
    'Find-AtlasoDevelopmentCaCleanupMarker',
    [System.StringComparison]::Ordinal
)
if (
    $removalChildPhase -lt $rollbackCatch -or
    $preSecretMarkerReconciliation -lt $rollbackCatch -or
    $preSecretMarkerReconciliation -gt $preSecretRollbackMarker -or
    $preSecretRollbackMarker -lt $rollbackCatch -or
    $preSecretRollbackMarker -gt $removalChildPhase -or
    $rollbackRemoval -lt $removalChildPhase -or
    $conditionalRestore -lt $rollbackRemoval
) {
    throw 'Rollback must durably own pre-secret cleanup before removal and withhold quarantined disks until termination is proven.'
}
if ($wrapperSource -notmatch '\$runtimeSignerScrubError\s*=\s*\$_\.Exception\.Message' -or
    $wrapperSource -notmatch '\$stopped\s*=\s*\$true') {
    throw 'Runtime signer scrub and stop failures must be retained independently.'
}

$markerTestRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    "atlaso-development-ca-marker-$([guid]::NewGuid().ToString('N'))"
)
try {
    $markerVmRoot = Join-Path $markerTestRoot 'vm'
    $markerRoot = Join-Path $markerTestRoot 'markers'
    New-Item -ItemType Directory -Path $markerVmRoot | Out-Null
    $markerVmx = Join-Path $markerVmRoot 'Atlaso-Test.vmx'
    $markerDisk = Join-Path $markerVmRoot 'Atlaso-Depot.vmdk'
    $markerDiskExtentOne = Join-Path $markerVmRoot 'Atlaso-Depot-s001.vmdk'
    $markerDiskExtentTwo = Join-Path $markerVmRoot 'Atlaso-Depot-s002.vmdk'
    $blockedMarkerVmx = Join-Path $markerVmRoot 'Atlaso-Blocked-Marker.vmx'
    [System.IO.File]::WriteAllText(
        $blockedMarkerVmx,
        "displayName = `"Atlaso Blocked Marker`"`r`n" +
        "guestinfo.atlaso.test_vm_cleanup_identity = `"$('d' * 32)`"`r`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    $blockedMarkerPath = ''
    Assert-Throws {
        New-AtlasoDevelopmentCaCleanupMarker `
            -VmxPath $blockedMarkerVmx `
            -Name 'Atlaso-Blocked-Marker' `
            -OutputDirectory $markerVmRoot `
            -DataDiskStates @() `
            -MarkerRoot $markerRoot `
            -MarkerPathReference ([ref]$blockedMarkerPath)
    } 'A pre-existing VMX cleanup identity must block marker publication.'
    if (
        -not [string]::IsNullOrWhiteSpace($blockedMarkerPath) -or
        (Test-Path -LiteralPath $blockedMarkerPath) -or
        @(Get-ChildItem -LiteralPath $markerRoot -Filter '*.json' -ErrorAction SilentlyContinue).Count -ne 0
    ) {
        throw 'A marker-publication failure was incorrectly exposed as durable recovery state.'
    }

    # Run the production declarations as one file-backed child script. The
    # existing isolated-function tests intentionally dot-source extracted
    # definitions and therefore cannot reproduce script-local command lookup.
    $scriptScopeRoot = Join-Path $markerTestRoot 'script-scope'
    New-Item -ItemType Directory -Path $scriptScopeRoot | Out-Null
    $scriptScopeHarness = Join-Path $scriptScopeRoot 'marker-script-scope.ps1'
    $wrapperLines = Get-Content -LiteralPath $wrapperPath
    $lastFunctionEndLine = ($ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
            }, $true) | Measure-Object -Property {
                $_.Extent.EndLineNumber
            } -Maximum).Maximum
    $wrapperScriptRootLiteral = "'$((Split-Path -Parent $wrapperPath).Replace("'", "''"))'"
    $productionDeclarations = ($wrapperLines[0..($lastFunctionEndLine - 1)] -join "`r`n").Replace(
        '$PSScriptRoot',
        $wrapperScriptRootLiteral
    )
    $scriptScopeExercise = @'

$scopeRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    "atlaso-marker-script-scope-$([guid]::NewGuid().ToString('N'))"
)
try {
    $vmRoot = Join-Path $scopeRoot 'vm'
    $markerRoot = Join-Path $scopeRoot 'markers'
    New-Item -ItemType Directory -Path $vmRoot | Out-Null
    $vmxPath = Join-Path $vmRoot 'Atlaso-Script-Scope.vmx'
    [System.IO.File]::WriteAllText(
        $vmxPath,
        'config.version = "8"',
        [System.Text.UTF8Encoding]::new($false)
    )
    $publishedMarkerPath = ''
    $returnedMarkerPath = New-AtlasoDevelopmentCaCleanupMarker `
        -VmxPath $vmxPath `
        -Name 'Atlaso-Script-Scope' `
        -OutputDirectory $vmRoot `
        -DataDiskStates @() `
        -MarkerRoot $markerRoot `
        -MarkerPathReference ([ref]$publishedMarkerPath)
    if (
        [string]::IsNullOrWhiteSpace($publishedMarkerPath) -or
        $returnedMarkerPath -cne $publishedMarkerPath -or
        -not (Test-Path -LiteralPath $publishedMarkerPath -PathType Leaf)
    ) {
        throw 'The file-backed wrapper scope did not durably publish its cleanup marker.'
    }
    $recoveryVmxPath = Join-Path $vmRoot 'Atlaso-Script-Scope-Recovery.vmx'
    [System.IO.File]::WriteAllText(
        $recoveryVmxPath,
        "config.version = `"8`"`r`n" +
        "guestinfo.atlaso.test_vm_cleanup_identity = `"$('e' * 32)`"`r`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    $recoveryMarkerPath = New-AtlasoDevelopmentCaCleanupMarker `
        -VmxPath $recoveryVmxPath `
        -Name 'Atlaso-Script-Scope-Recovery' `
        -OutputDirectory $vmRoot `
        -DataDiskStates @() `
        -MarkerRoot $markerRoot `
        -InitialPhase stopped-vmx-scrubbed `
        -AllowExistingCleanupIdentity
    $recoveryMarker = Read-AtlasoDevelopmentCaCleanupMarker `
        -MarkerPath $recoveryMarkerPath `
        -MarkerRoot $markerRoot
    if ($recoveryMarker.Phase -cne 'stopped-vmx-scrubbed') {
        throw 'Pre-secret rollback did not durably bind its existing VMX cleanup identity.'
    }
    $absentIdentityRoot = Join-Path $scopeRoot 'absent-identity-markers'
    $absentIdentityVmxPath = Join-Path $vmRoot 'Atlaso-Script-Scope-Absent-Identity.vmx'
    New-Item -ItemType Directory -Path $absentIdentityRoot | Out-Null
    [System.IO.File]::WriteAllText(
        $absentIdentityVmxPath,
        'config.version = "8"',
        [System.Text.UTF8Encoding]::new($false)
    )
    $absentIdentityMarker = Find-AtlasoDevelopmentCaCleanupMarker `
        -VmxPath $absentIdentityVmxPath `
        -Name 'Atlaso-Script-Scope-Absent-Identity' `
        -OutputDirectory $vmRoot `
        -MarkerRoot $absentIdentityRoot
    if ($null -ne $absentIdentityMarker) {
        throw 'An empty marker root was incorrectly treated as a renamed durable marker.'
    }
    $absentIdentityFallbackPath = New-AtlasoDevelopmentCaCleanupMarker `
        -VmxPath $absentIdentityVmxPath `
        -Name 'Atlaso-Script-Scope-Absent-Identity' `
        -OutputDirectory $vmRoot `
        -DataDiskStates @() `
        -MarkerRoot $absentIdentityRoot `
        -InitialPhase stopped-vmx-scrubbed `
        -AllowExistingCleanupIdentity
    if (-not (Test-Path -LiteralPath $absentIdentityFallbackPath -PathType Leaf)) {
        throw 'An absent VMX cleanup identity did not admit fresh durable fallback publication.'
    }
    $reconciliationRoot = Join-Path $scopeRoot 'reconciliation-markers'
    $reconciliationVmxPath = Join-Path $vmRoot 'Atlaso-Script-Scope-Reconciliation.vmx'
    [System.IO.File]::WriteAllText(
        $reconciliationVmxPath,
        'config.version = "8"',
        [System.Text.UTF8Encoding]::new($false)
    )
    $renamedMarkerPath = New-AtlasoDevelopmentCaCleanupMarker `
        -VmxPath $reconciliationVmxPath `
        -Name 'Atlaso-Script-Scope-Reconciliation' `
        -OutputDirectory $vmRoot `
        -DataDiskStates @() `
        -MarkerRoot $reconciliationRoot
    # Model the post-rename failure window: durable state exists, but the
    # caller-owned marker reference was never exposed.
    $reconciledMarker = Find-AtlasoDevelopmentCaCleanupMarker `
        -VmxPath $reconciliationVmxPath `
        -Name 'Atlaso-Script-Scope-Reconciliation' `
        -OutputDirectory $vmRoot `
        -MarkerRoot $reconciliationRoot
    if (
        $null -eq $reconciledMarker -or
        $reconciledMarker.MarkerPath -cne $renamedMarkerPath -or
        @(Get-ChildItem -LiteralPath $reconciliationRoot -Filter '*.json').Count -ne 1
    ) {
        throw 'Post-rename cleanup-marker reconciliation did not recover the exact durable destination.'
    }
}
finally {
    Remove-Item -LiteralPath $scopeRoot -Recurse -Force -ErrorAction SilentlyContinue
}
'@
    [System.IO.File]::WriteAllText(
        $scriptScopeHarness,
        "$productionDeclarations$scriptScopeExercise",
        [System.Text.UTF8Encoding]::new($false)
    )
    $scriptScopeResult = & (Get-Process -Id $PID).Path `
        -NoLogo `
        -NoProfile `
        -NonInteractive `
        -File $scriptScopeHarness `
        -PullRequestNumber 634 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "The file-backed script-local marker regression failed: $($scriptScopeResult -join ' ')"
    }
    $markerFunctionStart = $wrapperSource.IndexOf(
        'function New-AtlasoDevelopmentCaCleanupMarker',
        [System.StringComparison]::Ordinal
    )
    $durableActionCall = $wrapperSource.IndexOf(
        '-DurableIdentityAction $publishMarker',
        $markerFunctionStart,
        [System.StringComparison]::Ordinal
    )
    $publishedPathAssignment = $wrapperSource.IndexOf(
        '$MarkerPathReference.Value = $markerPath',
        $markerFunctionStart,
        [System.StringComparison]::Ordinal
    )
    if (
        $markerFunctionStart -lt 0 -or
        $durableActionCall -lt $markerFunctionStart -or
        $publishedPathAssignment -lt $durableActionCall
    ) {
        throw 'The caller-visible marker path must follow successful durable publication.'
    }
    [System.IO.File]::WriteAllText($markerVmx, 'config.version = "8"')
    [System.IO.File]::WriteAllText(
        $markerDisk,
        @'
# Disk DescriptorFile
version=1
RW 524288000 SPARSE "Atlaso-Depot-s001.vmdk"
RW 524288000 SPARSE "Atlaso-Depot-s002.vmdk"
'@,
        [System.Text.UTF8Encoding]::new($false)
    )
    [System.IO.File]::WriteAllText($markerDiskExtentOne, 'preserved-development-extent-one')
    [System.IO.File]::WriteAllText($markerDiskExtentTwo, 'preserved-development-extent-two')
    $markerDiskState = @(Get-AtlasoRollbackDataDiskState `
            -DiskPath $markerDisk `
            -OutputDirectory $markerVmRoot)
    $markerPath = New-AtlasoDevelopmentCaCleanupMarker `
        -VmxPath $markerVmx `
        -Name 'Atlaso-Test' `
        -OutputDirectory $markerVmRoot `
        -DataDiskStates $markerDiskState `
        -MarkerRoot $markerRoot
    $marker = Read-AtlasoDevelopmentCaCleanupMarker `
        -MarkerPath $markerPath `
        -MarkerRoot $markerRoot
    if ($marker.VmxPath -cne (Resolve-Path -LiteralPath $markerVmx).Path) {
        throw 'The durable cleanup marker did not bind the exact VMX path and identity.'
    }
    $boundVmxContent = [System.IO.File]::ReadAllText($markerVmx)
    $boundVmxIdentity = [Atlaso.WorkstationFileIdentity]::Get($markerVmx)
    $replacementVmx = "$markerVmx.replacement"
    [System.IO.File]::WriteAllText($replacementVmx, $boundVmxContent, [System.Text.UTF8Encoding]::new($false))
    [System.IO.File]::Move($replacementVmx, $markerVmx, $true)
    if ([Atlaso.WorkstationFileIdentity]::Get($markerVmx) -ceq $boundVmxIdentity) {
        throw 'The focused VMX replacement did not change filesystem identity.'
    }
    $replacementMarker = Read-AtlasoDevelopmentCaCleanupMarker `
        -MarkerPath $markerPath `
        -MarkerRoot $markerRoot
    if ($replacementMarker.Schema -ne 3) {
        throw 'A replacement-stable cleanup marker must use schema 3.'
    }
    $tamperedVmxContent = $boundVmxContent -replace (
        'guestinfo\.atlaso\.test_vm_cleanup_identity\s*=\s*"[0-9a-f]{32}"'
    ), 'guestinfo.atlaso.test_vm_cleanup_identity = "00000000000000000000000000000000"'
    [System.IO.File]::WriteAllText($markerVmx, $tamperedVmxContent, [System.Text.UTF8Encoding]::new($false))
    Assert-Throws {
        Read-AtlasoDevelopmentCaCleanupMarker `
            -MarkerPath $markerPath `
            -MarkerRoot $markerRoot
    } 'A changed VMX without the exact cleanup identity must fail closed.'
    [System.IO.File]::WriteAllText($markerVmx, $boundVmxContent, [System.Text.UTF8Encoding]::new($false))
    if ($marker.Phase -cne 'secret-child-active' -or $marker.ArtifactsRemoved -or $marker.DataDisks.Count -ne 3) {
        throw 'A new cleanup marker must conservatively begin in the secret-child-active phase.'
    }
    $sameBootDeferred = $false
    try {
        Invoke-PendingAtlasoDevelopmentCaCleanup `
            -VmrunPath 'must-not-run-before-host-restart' `
            -TimeoutSeconds 5 `
            -MarkerRoot $markerRoot
    }
    catch {
        if ($_.Exception.Message -notlike '*deferred until a Windows host restart*') {
            throw
        }
        $sameBootDeferred = $true
    }
    if (
        -not $sameBootDeferred -or
        -not (Test-Path -LiteralPath $markerPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $markerVmx -PathType Leaf)
    ) {
        throw 'Same-boot retry must preserve the durable marker and VM while secret-child termination is unproven.'
    }

    $startVmRoot = Join-Path $markerTestRoot 'start-child-vm'
    $startMarkerRoot = Join-Path $markerTestRoot 'start-child-markers'
    New-Item -ItemType Directory -Path $startVmRoot | Out-Null
    $startVmx = Join-Path $startVmRoot 'Atlaso-Start-Child.vmx'
    [System.IO.File]::WriteAllText($startVmx, 'config.version = "8"')
    $startMarker = New-AtlasoDevelopmentCaCleanupMarker `
        -VmxPath $startVmx `
        -Name 'Atlaso-Start-Child' `
        -OutputDirectory $startVmRoot `
        -DataDiskStates @() `
        -MarkerRoot $startMarkerRoot
    Set-AtlasoDevelopmentCaCleanupMarkerPhase `
        -MarkerPath $startMarker `
        -ExpectedPhase secret-child-active `
        -Phase staged
    # Credential staging and signer staging are separate bounded children. The
    # marker must safely re-enter child-active state between those operations.
    Set-AtlasoDevelopmentCaCleanupMarkerPhase `
        -MarkerPath $startMarker `
        -ExpectedPhase staged `
        -Phase secret-child-active
    Set-AtlasoDevelopmentCaCleanupMarkerPhase `
        -MarkerPath $startMarker `
        -ExpectedPhase secret-child-active `
        -Phase staged
    Set-AtlasoDevelopmentCaCleanupMarkerPhase `
        -MarkerPath $startMarker `
        -ExpectedPhase staged `
        -Phase vm-start-child-active
    $startSameBootDeferred = $false
    try {
        Invoke-PendingAtlasoDevelopmentCaCleanup `
            -VmrunPath 'must-not-run-while-start-child-may-survive' `
            -TimeoutSeconds 5 `
            -MarkerRoot $startMarkerRoot
    }
    catch {
        if ($_.Exception.Message -notlike '*deferred until a Windows host restart*') {
            throw
        }
        $startSameBootDeferred = $true
    }
    if (
        -not $startSameBootDeferred -or
        -not (Test-Path -LiteralPath $startMarker -PathType Leaf) -or
        -not (Test-Path -LiteralPath $startVmx -PathType Leaf)
    ) {
        throw 'Same-boot retry mutated the VM while the bounded start child could still start it.'
    }

    $script:successfulImportRuntimeValue = '""'
    $script:successfulImportRunningVmxPath = ''
    $script:successfulImportVmrunCalls = [System.Collections.Generic.List[string]]::new()
    $script:successfulImportProcessActions = [System.Collections.Generic.List[string]]::new()

    <#
    .SYNOPSIS
    Emulate one powered-off VM and quoted-empty runtime readback.

    .PARAMETER Remaining
    Positional vmrun arguments supplied by successful-import recovery.
    #>
    function AtlasoSuccessfulImportVmrun {
        param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Remaining)

        $script:successfulImportVmrunCalls.Add(($Remaining -join ' '))
        $global:LASTEXITCODE = 0
        if ($Remaining -contains 'list') {
            if ($script:successfulImportRunningVmxPath) {
                'Total running VMs: 1'
                $script:successfulImportRunningVmxPath
            }
            else {
                'Total running VMs: 0'
            }
            return
        }
        if ($Remaining -contains 'readVariable') {
            $script:successfulImportRuntimeValue
            return
        }
        throw 'Successful-import recovery issued an unexpected vmrun operation.'
    }

    <#
    .SYNOPSIS
    Record the bounded restart child without launching VMware.

    .PARAMETER FilePath
    PowerShell executable selected by the recovery helper.

    .PARAMETER ArgumentList
    Exact child arguments used for the restart.

    .PARAMETER TimeoutSeconds
    Bounded child deadline accepted for signature compatibility.

    .PARAMETER Action
    Safe action description used for ordering assertions.
    #>
    function Invoke-AtlasoBoundedProcess {
        param(
            [string]$FilePath,
            [string[]]$ArgumentList,
            [int]$TimeoutSeconds,
            [string]$Action
        )

        $script:successfulImportProcessActions.Add($Action)
        if ($ArgumentList -notcontains (Join-Path $RepositoryRoot 'scripts\windows\vmware\start-atlaso-vm.ps1')) {
            throw 'Successful-import recovery launched an unexpected bounded child.'
        }
        return ''
    }

    try {
        $interruptedStopVmRoot = Join-Path $markerTestRoot 'interrupted-stop-vm'
        $interruptedStopMarkerRoot = Join-Path $markerTestRoot 'interrupted-stop-markers'
        New-Item -ItemType Directory -Path $interruptedStopVmRoot | Out-Null
        $interruptedStopVmx = Join-Path $interruptedStopVmRoot 'Atlaso-Interrupted-Stop.vmx'
        [System.IO.File]::WriteAllLines(
            $interruptedStopVmx,
            @(
                'config.version = "8"',
                'guestinfo.atlaso.test_vm_development_root_ca_private_key = "test-fixture"'
            ),
            [System.Text.UTF8Encoding]::new($false)
        )
        $interruptedStopMarker = New-AtlasoDevelopmentCaCleanupMarker `
            -VmxPath $interruptedStopVmx `
            -Name 'Atlaso-Interrupted-Stop' `
            -OutputDirectory $interruptedStopVmRoot `
            -DataDiskStates @() `
            -MarkerRoot $interruptedStopMarkerRoot
        Set-AtlasoDevelopmentCaCleanupMarkerPhase `
            -MarkerPath $interruptedStopMarker `
            -ExpectedPhase secret-child-active `
            -Phase staged
        Set-AtlasoDevelopmentCaCleanupMarkerPhase `
            -MarkerPath $interruptedStopMarker `
            -ExpectedPhase staged `
            -Phase vm-stop-child-active
        $interruptedStopPayload = Get-Content -LiteralPath $interruptedStopMarker -Raw | ConvertFrom-Json
        $interruptedStopPayload.HostBootIdentity = (
            [long](Get-AtlasoHostBootIdentity) - 1
        ).ToString([System.Globalization.CultureInfo]::InvariantCulture)
        Write-AtlasoDevelopmentCaCleanupMarkerPayload `
            -MarkerPath $interruptedStopMarker `
            -Payload $interruptedStopPayload

        Invoke-PendingAtlasoDevelopmentCaCleanup `
            -VmrunPath AtlasoSuccessfulImportVmrun `
            -TimeoutSeconds 5 `
            -ExpectedFingerprint ('A' * 64) `
            -MarkerRoot $interruptedStopMarkerRoot

        if (
            (Test-Path -LiteralPath $interruptedStopMarker) -or
            -not (Test-Path -LiteralPath $interruptedStopVmx -PathType Leaf) -or
            (Select-String -LiteralPath $interruptedStopVmx -Pattern (
                    '^\s*guestinfo\.atlaso\.test_vm_development_root_ca_private_key\s*='
                ) -Quiet) -or
            -not (Select-String -LiteralPath $interruptedStopVmx -Pattern (
                    '^\s*guestinfo\.atlaso\.test_vm_cleanup_identity\s*='
                ) -Quiet) -or
            $script:successfulImportProcessActions.Count -ne 1 -or
            $script:successfulImportProcessActions[0] -cnotlike 'Restart the normal test VM*' -or
            @($script:successfulImportVmrunCalls | Where-Object { $_ -match 'readVariable' }).Count -ne 3
        ) {
            throw 'Interrupted stop recovery did not preserve import proof through powered-off scrub and restart.'
        }

        $script:successfulImportVmrunCalls.Clear()
        $script:successfulImportProcessActions.Clear()
        $interruptedRestartVmRoot = Join-Path $markerTestRoot 'interrupted-restart-vm'
        $interruptedRestartMarkerRoot = Join-Path $markerTestRoot 'interrupted-restart-markers'
        New-Item -ItemType Directory -Path $interruptedRestartVmRoot | Out-Null
        $interruptedRestartVmx = Join-Path $interruptedRestartVmRoot 'Atlaso-Interrupted-Restart.vmx'
        [System.IO.File]::WriteAllLines(
            $interruptedRestartVmx,
            @(
                'config.version = "8"',
                'guestinfo.atlaso.test_vm_development_root_ca_private_key = "restored-after-crash"'
            ),
            [System.Text.UTF8Encoding]::new($false)
        )
        $interruptedRestartMarker = New-AtlasoDevelopmentCaCleanupMarker `
            -VmxPath $interruptedRestartVmx `
            -Name 'Atlaso-Interrupted-Restart' `
            -OutputDirectory $interruptedRestartVmRoot `
            -DataDiskStates @() `
            -MarkerRoot $interruptedRestartMarkerRoot
        Set-AtlasoDevelopmentCaCleanupMarkerPhase `
            -MarkerPath $interruptedRestartMarker `
            -ExpectedPhase secret-child-active `
            -Phase staged
        Set-AtlasoDevelopmentCaCleanupMarkerPhase `
            -MarkerPath $interruptedRestartMarker `
            -ExpectedPhase staged `
            -Phase vm-stop-child-active
        Set-AtlasoDevelopmentCaCleanupMarkerPhase `
            -MarkerPath $interruptedRestartMarker `
            -ExpectedPhase vm-stop-child-active `
            -Phase import-proven-stopped-vmx-scrubbed
        Set-AtlasoDevelopmentCaCleanupMarkerPhase `
            -MarkerPath $interruptedRestartMarker `
            -ExpectedPhase import-proven-stopped-vmx-scrubbed `
            -Phase vm-restart-child-active
        $interruptedRestartPayload = Get-Content -LiteralPath $interruptedRestartMarker -Raw | ConvertFrom-Json
        $interruptedRestartPayload.HostBootIdentity = (
            [long](Get-AtlasoHostBootIdentity) - 1
        ).ToString([System.Globalization.CultureInfo]::InvariantCulture)
        Write-AtlasoDevelopmentCaCleanupMarkerPayload `
            -MarkerPath $interruptedRestartMarker `
            -Payload $interruptedRestartPayload

        Invoke-PendingAtlasoDevelopmentCaCleanup `
            -VmrunPath AtlasoSuccessfulImportVmrun `
            -TimeoutSeconds 5 `
            -ExpectedFingerprint ('A' * 64) `
            -MarkerRoot $interruptedRestartMarkerRoot

        if (
            (Test-Path -LiteralPath $interruptedRestartMarker) -or
            -not (Test-Path -LiteralPath $interruptedRestartVmx -PathType Leaf) -or
            (Select-String -LiteralPath $interruptedRestartVmx -Pattern (
                    '^\s*guestinfo\.atlaso\.test_vm_development_root_ca_private_key\s*='
                ) -Quiet) -or
            $script:successfulImportProcessActions.Count -ne 1 -or
            $script:successfulImportProcessActions[0] -cnotlike 'Restart the normal test VM*' -or
            @($script:successfulImportVmrunCalls | Where-Object { $_ -match 'readVariable' }).Count -ne 3
        ) {
            throw 'Interrupted restart recovery did not safely retry and retire the successful-import marker.'
        }

        $script:successfulImportVmrunCalls.Clear()
        $script:successfulImportProcessActions.Clear()
        $finalReadVmRoot = Join-Path $markerTestRoot 'final-read-vm'
        $finalReadMarkerRoot = Join-Path $markerTestRoot 'final-read-markers'
        New-Item -ItemType Directory -Path $finalReadVmRoot | Out-Null
        $finalReadVmx = Join-Path $finalReadVmRoot 'Atlaso-Final-Read.vmx'
        [System.IO.File]::WriteAllText($finalReadVmx, 'config.version = "8"')
        $finalReadMarker = New-AtlasoDevelopmentCaCleanupMarker `
            -VmxPath $finalReadVmx `
            -Name 'Atlaso-Final-Read' `
            -OutputDirectory $finalReadVmRoot `
            -DataDiskStates @() `
            -MarkerRoot $finalReadMarkerRoot
        Set-AtlasoDevelopmentCaCleanupMarkerPhase `
            -MarkerPath $finalReadMarker `
            -ExpectedPhase secret-child-active `
            -Phase staged
        Set-AtlasoDevelopmentCaCleanupMarkerPhase `
            -MarkerPath $finalReadMarker `
            -ExpectedPhase staged `
            -Phase vm-stop-child-active
        Set-AtlasoDevelopmentCaCleanupMarkerPhase `
            -MarkerPath $finalReadMarker `
            -ExpectedPhase vm-stop-child-active `
            -Phase import-proven-stopped-vmx-scrubbed
        Set-AtlasoDevelopmentCaCleanupMarkerPhase `
            -MarkerPath $finalReadMarker `
            -ExpectedPhase import-proven-stopped-vmx-scrubbed `
            -Phase vm-restart-child-active
        Set-AtlasoDevelopmentCaCleanupMarkerPhase `
            -MarkerPath $finalReadMarker `
            -ExpectedPhase vm-restart-child-active `
            -Phase restarted-vmx-scrubbed
        $script:successfulImportRunningVmxPath = $finalReadVmx
        $script:successfulImportRuntimeValue = 'not-empty'
        Assert-Throws {
            $finalReadMarkerState = Read-AtlasoDevelopmentCaCleanupMarker `
                -MarkerPath $finalReadMarker `
                -MarkerRoot $finalReadMarkerRoot
            Complete-AtlasoDevelopmentCaSuccessfulImport `
                -Marker $finalReadMarkerState `
                -VmrunPath AtlasoSuccessfulImportVmrun `
                -TimeoutSeconds 1
        } 'A non-empty post-restart signer readback must keep finalization pending.'
        $pendingFinalReadMarker = Read-AtlasoDevelopmentCaCleanupMarker `
            -MarkerPath $finalReadMarker `
            -MarkerRoot $finalReadMarkerRoot
        if (
            $pendingFinalReadMarker.Phase -cne 'restarted-vmx-scrubbed' -or
            -not (Test-Path -LiteralPath $finalReadVmx -PathType Leaf) -or
            $script:successfulImportProcessActions.Count -ne 0
        ) {
            throw 'A failed final runtime proof did not preserve the running imported VM and retryable marker.'
        }
        $script:successfulImportRuntimeValue = '""'
        $script:successfulImportVmrunCalls.Clear()
        Invoke-PendingAtlasoDevelopmentCaCleanup `
            -VmrunPath AtlasoSuccessfulImportVmrun `
            -TimeoutSeconds 5 `
            -ExpectedFingerprint ('A' * 64) `
            -MarkerRoot $finalReadMarkerRoot
        if (
            (Test-Path -LiteralPath $finalReadMarker) -or
            -not (Test-Path -LiteralPath $finalReadVmx -PathType Leaf) -or
            $script:successfulImportProcessActions.Count -ne 0 -or
            @($script:successfulImportVmrunCalls | Where-Object { $_ -match 'readVariable' }).Count -ne 3
        ) {
            throw 'Final runtime-proof retry did not preserve the running VM and retire its marker.'
        }

        $script:successfulImportRuntimeValue = '""'
        $script:successfulImportRunningVmxPath = ''
        $script:successfulImportVmrunCalls.Clear()
        $script:successfulImportProcessActions.Clear()
        $offlineRestartedVmRoot = Join-Path $markerTestRoot 'offline-restarted-vm'
        $offlineRestartedMarkerRoot = Join-Path $markerTestRoot 'offline-restarted-markers'
        New-Item -ItemType Directory -Path $offlineRestartedVmRoot | Out-Null
        $offlineRestartedVmx = Join-Path $offlineRestartedVmRoot 'Atlaso-Offline-Restarted.vmx'
        [System.IO.File]::WriteAllLines(
            $offlineRestartedVmx,
            @(
                'config.version = "8"',
                'guestinfo.atlaso.test_vm_development_root_ca_private_key = "restored-after-power-loss"'
            ),
            [System.Text.UTF8Encoding]::new($false)
        )
        $offlineRestartedMarker = New-AtlasoDevelopmentCaCleanupMarker `
            -VmxPath $offlineRestartedVmx `
            -Name 'Atlaso-Offline-Restarted' `
            -OutputDirectory $offlineRestartedVmRoot `
            -DataDiskStates @() `
            -MarkerRoot $offlineRestartedMarkerRoot
        Set-AtlasoDevelopmentCaCleanupMarkerPhase `
            -MarkerPath $offlineRestartedMarker `
            -ExpectedPhase secret-child-active `
            -Phase staged
        Set-AtlasoDevelopmentCaCleanupMarkerPhase `
            -MarkerPath $offlineRestartedMarker `
            -ExpectedPhase staged `
            -Phase vm-stop-child-active
        Set-AtlasoDevelopmentCaCleanupMarkerPhase `
            -MarkerPath $offlineRestartedMarker `
            -ExpectedPhase vm-stop-child-active `
            -Phase import-proven-stopped-vmx-scrubbed
        Set-AtlasoDevelopmentCaCleanupMarkerPhase `
            -MarkerPath $offlineRestartedMarker `
            -ExpectedPhase import-proven-stopped-vmx-scrubbed `
            -Phase vm-restart-child-active
        Set-AtlasoDevelopmentCaCleanupMarkerPhase `
            -MarkerPath $offlineRestartedMarker `
            -ExpectedPhase vm-restart-child-active `
            -Phase restarted-vmx-scrubbed

        Invoke-PendingAtlasoDevelopmentCaCleanup `
            -VmrunPath AtlasoSuccessfulImportVmrun `
            -TimeoutSeconds 5 `
            -ExpectedFingerprint ('A' * 64) `
            -MarkerRoot $offlineRestartedMarkerRoot
        if (
            (Test-Path -LiteralPath $offlineRestartedMarker) -or
            -not (Test-Path -LiteralPath $offlineRestartedVmx -PathType Leaf) -or
            (Select-String -LiteralPath $offlineRestartedVmx -Pattern (
                    '^\s*guestinfo\.atlaso\.test_vm_development_root_ca_private_key\s*='
                ) -Quiet) -or
            $script:successfulImportProcessActions.Count -ne 1 -or
            @($script:successfulImportVmrunCalls | Where-Object { $_ -match 'readVariable' }).Count -ne 3
        ) {
            throw 'Offline restarted-marker recovery did not re-scrub, restart, and prove runtime empty.'
        }
    }
    finally {
        Remove-Item Function:\AtlasoSuccessfulImportVmrun -ErrorAction SilentlyContinue
        Remove-Item Function:\Invoke-AtlasoBoundedProcess -ErrorAction SilentlyContinue
        . (Join-Path $RepositoryRoot 'scripts\windows\vmware\Atlaso.WorkstationFirstBoot.ps1')
    }

    $successVmRoot = Join-Path $markerTestRoot 'successful-vm'
    $successMarkerRoot = Join-Path $markerTestRoot 'successful-markers'
    New-Item -ItemType Directory -Path $successVmRoot | Out-Null
    $successVmx = Join-Path $successVmRoot 'Atlaso-Success.vmx'
    [System.IO.File]::WriteAllText($successVmx, 'config.version = "8"')
    $successMarker = New-AtlasoDevelopmentCaCleanupMarker `
        -VmxPath $successVmx `
        -Name 'Atlaso-Success' `
        -OutputDirectory $successVmRoot `
        -DataDiskStates @() `
        -MarkerRoot $successMarkerRoot
    Set-AtlasoDevelopmentCaCleanupMarkerPhase `
        -MarkerPath $successMarker `
        -ExpectedPhase secret-child-active `
        -Phase staged
    Remove-AtlasoDevelopmentCaCleanupMarker -MarkerPath $successMarker
    if (
        (Test-Path -LiteralPath $successMarker) -or
        -not (Test-Path -LiteralPath $successVmx -PathType Leaf)
    ) {
        throw 'Successful encrypted import did not retire its marker without mutating the healthy VM.'
    }

    $retiredVmRoot = Join-Path $markerTestRoot 'retired-vm'
    $retiredMarkerRoot = Join-Path $markerTestRoot 'retired-markers'
    New-Item -ItemType Directory -Path $retiredVmRoot | Out-Null
    $retiredVmx = Join-Path $retiredVmRoot 'Atlaso-Retired.vmx'
    [System.IO.File]::WriteAllText($retiredVmx, 'config.version = "8"')
    $retiredMarker = New-AtlasoDevelopmentCaCleanupMarker `
        -VmxPath $retiredVmx `
        -Name 'Atlaso-Retired' `
        -OutputDirectory $retiredVmRoot `
        -DataDiskStates @() `
        -MarkerRoot $retiredMarkerRoot
    Set-AtlasoDevelopmentCaCleanupMarkerPhase `
        -MarkerPath $retiredMarker `
        -ExpectedPhase secret-child-active `
        -Phase staged
    Set-AtlasoDevelopmentCaCleanupMarkerPhase `
        -MarkerPath $retiredMarker `
        -ExpectedPhase staged `
        -Phase retired
    Invoke-PendingAtlasoDevelopmentCaCleanup `
        -VmrunPath 'must-not-run-for-retired-tombstone' `
        -TimeoutSeconds 5 `
        -MarkerRoot $retiredMarkerRoot
    if (
        (Test-Path -LiteralPath $retiredMarker) -or
        -not (Test-Path -LiteralPath $retiredVmx -PathType Leaf)
    ) {
        throw 'A resurrected retired marker was treated as actionable cleanup for a healthy VM.'
    }

    $removalVmRoot = Join-Path $markerTestRoot 'removal-child-vm'
    $removalMarkerRoot = Join-Path $markerTestRoot 'removal-child-markers'
    New-Item -ItemType Directory -Path $removalVmRoot | Out-Null
    $removalVmx = Join-Path $removalVmRoot 'Atlaso-Removal-Child.vmx'
    $removalDisk = Join-Path $removalVmRoot 'Atlaso-Depot.vmdk'
    [System.IO.File]::WriteAllText($removalVmx, 'config.version = "8"')
    [System.IO.File]::WriteAllText($removalDisk, 'removal-child-preserved-data')
    $removalDiskState = Get-AtlasoRollbackDataDiskState `
        -DiskPath $removalDisk `
        -OutputDirectory $removalVmRoot
    $removalMarker = New-AtlasoDevelopmentCaCleanupMarker `
        -VmxPath $removalVmx `
        -Name 'Atlaso-Removal-Child' `
        -OutputDirectory $removalVmRoot `
        -DataDiskStates @($removalDiskState) `
        -MarkerRoot $removalMarkerRoot
    $removalMarkerState = Read-AtlasoDevelopmentCaCleanupMarker `
        -MarkerPath $removalMarker `
        -MarkerRoot $removalMarkerRoot
    Set-AtlasoDevelopmentCaCleanupMarkerPhase `
        -MarkerPath $removalMarker `
        -ExpectedPhase secret-child-active `
        -Phase staged
    Set-AtlasoDevelopmentCaCleanupMarkerPhase `
        -MarkerPath $removalMarker `
        -ExpectedPhase staged `
        -Phase stopped-vmx-scrubbed
    Move-AtlasoRollbackDataDisksToQuarantine `
        -DataDiskStates @($removalDiskState) `
        -QuarantineDirectory $removalMarkerState.QuarantineDirectory
    Set-AtlasoDevelopmentCaCleanupMarkerPhase `
        -MarkerPath $removalMarker `
        -ExpectedPhase stopped-vmx-scrubbed `
        -Phase removal-child-active
    Remove-Item -LiteralPath $removalVmRoot -Recurse -Force
    $removalSameBootDeferred = $false
    try {
        Invoke-PendingAtlasoDevelopmentCaCleanup `
            -VmrunPath 'must-not-run-while-removal-child-may-survive' `
            -TimeoutSeconds 5 `
            -MarkerRoot $removalMarkerRoot
    }
    catch {
        if ($_.Exception.Message -notlike '*deferred until a Windows host restart*') {
            throw
        }
        $removalSameBootDeferred = $true
    }
    $quarantinedRemovalDisk = Join-Path $removalMarkerState.QuarantineDirectory 'Atlaso-Depot.vmdk'
    if (
        -not $removalSameBootDeferred -or
        -not (Test-Path -LiteralPath $removalMarker -PathType Leaf) -or
        -not (Test-Path -LiteralPath $quarantinedRemovalDisk -PathType Leaf) -or
        (Test-Path -LiteralPath $removalDisk)
    ) {
        throw 'Same-boot retry restored a quarantined disk while the removal child could still delete it.'
    }

    Set-AtlasoDevelopmentCaCleanupMarkerPhase `
        -MarkerPath $markerPath `
        -ExpectedPhase secret-child-active `
        -Phase staged
    Set-AtlasoDevelopmentCaCleanupMarkerPhase `
        -MarkerPath $markerPath `
        -ExpectedPhase staged `
        -Phase stopped-vmx-scrubbed
    Move-AtlasoRollbackDataDisksToQuarantine `
        -DataDiskStates $markerDiskState `
        -QuarantineDirectory $marker.QuarantineDirectory
    Remove-Item -LiteralPath $markerVmRoot -Recurse -Force
    $resumeMarker = Read-AtlasoDevelopmentCaCleanupMarker `
        -MarkerPath $markerPath `
        -MarkerRoot $markerRoot
    if (-not $resumeMarker.ArtifactsRemoved -or $resumeMarker.Phase -cne 'stopped-vmx-scrubbed') {
        throw 'A stopped and removed VM must enter persisted data-restoration resume.'
    }
    Invoke-PendingAtlasoDevelopmentCaCleanup `
        -VmrunPath 'unused-after-proven-removal' `
        -TimeoutSeconds 5 `
        -MarkerRoot $markerRoot
    if (Test-Path -LiteralPath $markerPath) {
        throw 'The resumed post-removal cleanup marker was not removed.'
    }
    if (
        -not (Test-Path -LiteralPath $markerDisk -PathType Leaf) -or
        -not (Test-Path -LiteralPath $markerDiskExtentOne -PathType Leaf) -or
        -not (Test-Path -LiteralPath $markerDiskExtentTwo -PathType Leaf) -or
        [System.IO.File]::ReadAllText($markerDiskExtentOne) -cne 'preserved-development-extent-one' -or
        [System.IO.File]::ReadAllText($markerDiskExtentTwo) -cne 'preserved-development-extent-two'
    ) {
        throw 'Persisted cleanup did not resume exact VMDK component restoration after VM removal.'
    }

    $preQuarantineVmRoot = Join-Path $markerTestRoot 'pre-quarantine-vm'
    New-Item -ItemType Directory -Path $preQuarantineVmRoot | Out-Null
    $preQuarantineVmx = Join-Path $preQuarantineVmRoot 'Atlaso-Pre-Quarantine.vmx'
    $preQuarantineDisk = Join-Path $preQuarantineVmRoot 'Atlaso-Depot.vmdk'
    [System.IO.File]::WriteAllText($preQuarantineVmx, 'config.version = "8"')
    [System.IO.File]::WriteAllText($preQuarantineDisk, 'pre-quarantine-data')
    $preQuarantineDiskState = Get-AtlasoRollbackDataDiskState `
        -DiskPath $preQuarantineDisk `
        -OutputDirectory $preQuarantineVmRoot
    $preQuarantineMarker = New-AtlasoDevelopmentCaCleanupMarker `
        -VmxPath $preQuarantineVmx `
        -Name 'Atlaso-Pre-Quarantine' `
        -OutputDirectory $preQuarantineVmRoot `
        -DataDiskStates @($preQuarantineDiskState) `
        -MarkerRoot $markerRoot
    Set-AtlasoDevelopmentCaCleanupMarkerPhase `
        -MarkerPath $preQuarantineMarker `
        -ExpectedPhase secret-child-active `
        -Phase staged
    Set-AtlasoDevelopmentCaCleanupMarkerPhase `
        -MarkerPath $preQuarantineMarker `
        -ExpectedPhase staged `
        -Phase stopped-vmx-scrubbed
    Remove-Item -LiteralPath $preQuarantineVmx -Force
    Invoke-PendingAtlasoDevelopmentCaCleanup `
        -VmrunPath 'unused-after-proven-removal' `
        -TimeoutSeconds 5 `
        -MarkerRoot $markerRoot
    if (
        (Test-Path -LiteralPath $preQuarantineMarker) -or
        [System.IO.File]::ReadAllText($preQuarantineDisk) -cne 'pre-quarantine-data'
    ) {
        throw 'Persisted cleanup did not resume across the output-parent quarantine boundary.'
    }
}
finally {
    Remove-Item -LiteralPath $markerTestRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$rollbackIdentityRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    "atlaso-rollback-identity-$([guid]::NewGuid().ToString('N'))"
)
try {
    New-Item -ItemType Directory -Path $rollbackIdentityRoot | Out-Null
    $targetVmx = Join-Path $rollbackIdentityRoot 'Atlaso.vmx'
    $aliasVmx = Join-Path $rollbackIdentityRoot 'ATLASO~1.VMX'
    $vmrunState = Join-Path $rollbackIdentityRoot 'vmrun-state.txt'
    [System.IO.File]::WriteAllText($targetVmx, 'config.version = "8"')
    New-Item -ItemType HardLink -Path $aliasVmx -Target $targetVmx | Out-Null
    [System.IO.File]::WriteAllText($vmrunState, 'running')
    <#
    .SYNOPSIS
    Emulate bounded vmrun list and stop operations for identity tests.

    .PARAMETER Remaining
    Positional vmrun arguments supplied by the wrapper helper.
    #>
    function AtlasoFakeVmrun {
        param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Remaining)
        if ($Remaining -contains 'list') {
            $global:LASTEXITCODE = 0
            if ([System.IO.File]::ReadAllText($vmrunState) -eq 'running') {
                'Total running VMs: 1'
                $aliasVmx
            }
            else {
                'Total running VMs: 0'
            }
            return
        }
        if ($Remaining -contains 'stop') {
            [System.IO.File]::WriteAllText($vmrunState, 'stopped')
            $global:LASTEXITCODE = 0
            return
        }
        $global:LASTEXITCODE = 1
    }
    Stop-AtlasoTestVmForRollback -VmxPath $targetVmx -VmrunPath AtlasoFakeVmrun
    if ([System.IO.File]::ReadAllText($vmrunState) -ne 'stopped') {
        throw 'Rollback failed to stop a running VMX reported through a filesystem alias.'
    }

    <#
    .SYNOPSIS
    Return a successful but truncated vmrun running-VM inventory.

    .PARAMETER Remaining
    Positional vmrun arguments supplied by the wrapper helper.
    #>
    function AtlasoMalformedVmrun {
        param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Remaining)
        if ($Remaining -contains 'list') {
            $global:LASTEXITCODE = 0
            'Total running VMs: 1'
            return
        }
        throw 'Rollback must not issue stop after malformed running-state output.'
    }
    try {
        Stop-AtlasoTestVmForRollback -VmxPath $targetVmx -VmrunPath AtlasoMalformedVmrun
        throw 'Rollback accepted a truncated vmrun list as stopped-state proof.'
    }
    catch {
        if ($_.Exception.Message -notlike '*reported 1 VMs but returned 0 paths*') {
            throw
        }
    }
}
finally {
    Remove-Item Function:\AtlasoFakeVmrun -ErrorAction SilentlyContinue
    Remove-Item Function:\AtlasoMalformedVmrun -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $rollbackIdentityRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$rollbackTestRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    "atlaso-rollback-test-$([guid]::NewGuid().ToString('N'))"
)
try {
    $outputDirectory = Join-Path $rollbackTestRoot 'vm'
    $dataDiskPath = Join-Path $outputDirectory 'Atlaso-Depot.vmdk'
    $backupDiskPath = Join-Path $outputDirectory 'Atlaso-Backups.vmdk'
    $dataDiskExtentOne = Join-Path $outputDirectory 'Atlaso-Depot-s001.vmdk'
    $dataDiskExtentTwo = Join-Path $outputDirectory 'Atlaso-Depot-s002.vmdk'
    $quarantineDirectory = Join-Path $rollbackTestRoot 'quarantine'
    New-Item -ItemType Directory -Path $outputDirectory | Out-Null
    [System.IO.File]::WriteAllText(
        $dataDiskPath,
        @'
# Disk DescriptorFile
version=1
RW 524288000 SPARSE "Atlaso-Depot-s001.vmdk"
RW 524288000 SPARSE "Atlaso-Depot-s002.vmdk"
'@,
        [System.Text.UTF8Encoding]::new($false)
    )
    [System.IO.File]::WriteAllText($dataDiskExtentOne, 'pre-existing-extent-one')
    [System.IO.File]::WriteAllText($dataDiskExtentTwo, 'pre-existing-extent-two')
    [System.IO.File]::WriteAllText(
        $backupDiskPath,
        @'
# Disk DescriptorFile
version=1
RW 524288000 SPARSE "Atlaso-Depot-s001.vmdk"
'@,
        [System.Text.UTF8Encoding]::new($false)
    )
    $overlapRejected = $false
    try {
        Get-AtlasoRollbackDataDiskStates `
            -DiskPaths @($dataDiskPath, $backupDiskPath) `
            -OutputDirectory $outputDirectory
    }
    catch {
        if ($_.Exception.Message -notlike '*overlap at one filesystem object*') {
            throw
        }
        $overlapRejected = $true
    }
    if (-not $overlapRejected) {
        throw 'Rollback state accepted two configured VMDKs that share one extent.'
    }
    Remove-Item -LiteralPath $backupDiskPath -Force
    $states = @(Get-AtlasoRollbackDataDiskState `
            -DiskPath $dataDiskPath `
            -OutputDirectory $outputDirectory)
    if ($states.Count -ne 3) {
        throw 'Rollback state did not capture the reused VMDK descriptor and every referenced extent.'
    }
    Move-AtlasoRollbackDataDisksToQuarantine `
        -DataDiskStates $states `
        -QuarantineDirectory $quarantineDirectory
    if (
        (Test-Path -LiteralPath $dataDiskPath) -or
        (Test-Path -LiteralPath $dataDiskExtentOne) -or
        (Test-Path -LiteralPath $dataDiskExtentTwo)
    ) {
        throw 'Rollback quarantine did not move every pre-existing in-directory VMDK component.'
    }
    Remove-Item -LiteralPath $outputDirectory -Recurse -Force
    Restore-AtlasoRollbackDataDisksFromQuarantine `
        -DataDiskStates $states `
        -QuarantineDirectory $quarantineDirectory
    if (
        -not (Test-Path -LiteralPath $dataDiskPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $dataDiskExtentOne -PathType Leaf) -or
        -not (Test-Path -LiteralPath $dataDiskExtentTwo -PathType Leaf) -or
        [System.IO.File]::ReadAllText($dataDiskExtentOne) -ne 'pre-existing-extent-one' -or
        [System.IO.File]::ReadAllText($dataDiskExtentTwo) -ne 'pre-existing-extent-two'
    ) {
        throw 'Rollback did not restore the exact reused VMDK descriptor and extents.'
    }
}
finally {
    Remove-Item -LiteralPath $rollbackTestRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$childSource = Get-Content -LiteralPath (
    Join-Path $RepositoryRoot 'scripts\windows\vmware\Invoke-AtlasoDevelopmentCaSecret.ps1'
) -Raw
if ($wrapperSource -notmatch 'ExpectedEnvironmentIdSha256|environmentIdDigest') {
    throw 'The normal test VM bridge must pin the exact Environment ID by SHA-256.'
}
$pendingCleanupIndex = $wrapperSource.IndexOf(
    'Invoke-PendingAtlasoDevelopmentCaCleanup `',
    [System.StringComparison]::Ordinal
)
$environmentIdResolutionIndex = $wrapperSource.IndexOf(
    '$OnePasswordEnvironmentId = Resolve-OnePasswordDevelopmentCaEnvironmentId `',
    [System.StringComparison]::Ordinal
)
if (
    $pendingCleanupIndex -lt 0 -or
    $environmentIdResolutionIndex -lt 0 -or
    $pendingCleanupIndex -ge $environmentIdResolutionIndex
) {
    throw 'Pending signer cleanup must precede local Environment ID resolution.'
}
foreach ($betaCliMarker in @(
        "@('run', '--help')",
        "'run', '--environment', `$EnvironmentId, '--'",
        'Install the Environments-enabled beta CLI and retry.',
        '.atlaso-local\onepassword-environment-id'
    )) {
    if (-not $wrapperSource.Contains($betaCliMarker, [System.StringComparison]::Ordinal)) {
        throw "The normal test VM wrapper is missing its beta CLI contract: $betaCliMarker"
    }
}
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

$credentialHelperPath = Join-Path $RepositoryRoot 'scripts\windows\vmware\Invoke-AtlasoTestVmCredentials.ps1'
$credentialHelperSource = Get-Content -LiteralPath $credentialHelperPath -Raw
foreach ($credentialMarker in @(
        'DEFAULT_ADMIN_PASSWORD',
        'DEFAULT_ROOT_PASSWORD',
        'len(matches) != 1',
        'not matches[0].masked',
        'os.environ.pop("DEFAULT_ADMIN_PASSWORD", None)',
        'os.environ.pop("DEFAULT_ROOT_PASSWORD", None)',
        "'-I', '-S', `$pythonChildPath",
        'ConvertFrom-SecureString -SecureString $ovfSecureString'
    )) {
    if (-not $credentialHelperSource.Contains($credentialMarker, [System.StringComparison]::Ordinal)) {
        throw "The bounded credential helper is missing its isolation contract: $credentialMarker"
    }
}
if (
    $credentialHelperSource -match 'Read-Host' -or
    $wrapperSource -match "Read-Host\s+-Prompt\s+'(?:Atlaso bootstrap administrator|Photon root console) password'"
) {
    throw 'Normal test-VM credentials must not fall back to an interactive password prompt.'
}
$credentialPreparationIndex = $wrapperSource.IndexOf(
    '$credentialBridgeState = New-AtlasoTestVmCredentialBridgeState `',
    [System.StringComparison]::Ordinal
)
$networkPreparationIndex = $wrapperSource.IndexOf(
    "& (Join-Path `$PSScriptRoot 'prepare-networks.ps1')",
    [System.StringComparison]::Ordinal
)
$redeployCleanupIndex = $wrapperSource.IndexOf(
    "& (Join-Path `$PSScriptRoot 'remove-atlaso-vm.ps1')",
    [System.StringComparison]::Ordinal
)
$dataDiskResetIndex = $wrapperSource.IndexOf(
    "Remove-Item -LiteralPath `$resolvedDiskPath -Force",
    [System.StringComparison]::Ordinal
)
if (
    $credentialPreparationIndex -lt 0 -or
    $networkPreparationIndex -lt 0 -or
    $redeployCleanupIndex -lt 0 -or
    $dataDiskResetIndex -lt 0 -or
    $credentialPreparationIndex -ge $networkPreparationIndex -or
    $credentialPreparationIndex -ge $redeployCleanupIndex -or
    $credentialPreparationIndex -ge $dataDiskResetIndex
) {
    throw 'Credential retrieval and validation must precede network preparation, cleanup, and data-disk reset.'
}
$whatIfGuardIndex = $wrapperSource.LastIndexOf(
    'if (-not $WhatIfPreference) {',
    $credentialPreparationIndex,
    [System.StringComparison]::Ordinal
)
if ($whatIfGuardIndex -lt 0 -or $whatIfGuardIndex -ge $credentialPreparationIndex) {
    throw 'Credential preparation must remain disabled for WhatIf execution.'
}
$credentialStageCallIndex = $wrapperSource.LastIndexOf(
    'Invoke-AtlasoTestVmCredentialStage `',
    [System.StringComparison]::Ordinal
)
$credentialStageMarkerIndex = $wrapperSource.LastIndexOf(
    'New-AtlasoDevelopmentCaCleanupMarker `',
    $credentialStageCallIndex,
    [System.StringComparison]::Ordinal
)
$credentialStageTerminationGuardIndex = $wrapperSource.IndexOf(
    "`$stageFailure.Exception.Data['AtlasoProcessTreeTerminationUnproven']",
    $credentialStageCallIndex,
    [System.StringComparison]::Ordinal
)
$credentialStageRollbackIndex = $wrapperSource.IndexOf(
    'if ($null -ne $credentialStageFailure) {',
    $credentialStageCallIndex,
    [System.StringComparison]::Ordinal
)
if (
    $credentialStageCallIndex -lt 0 -or
    $credentialStageMarkerIndex -lt 0 -or
    $credentialStageMarkerIndex -ge $credentialStageCallIndex -or
    $credentialStageTerminationGuardIndex -lt $credentialStageCallIndex -or
    $credentialStageRollbackIndex -lt $credentialStageTerminationGuardIndex
) {
    throw 'Credential staging must publish child-active recovery state and enter shared rollback safely.'
}

$credentialTestRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    "atlaso-test-vm-credential-helper-$([guid]::NewGuid().ToString('N'))"
)
try {
    New-Item -ItemType Directory -Path $credentialTestRoot | Out-Null
    $fakeDependencyPath = Join-Path $credentialTestRoot 'fake-sdk'
    $fakePackagePath = Join-Path $fakeDependencyPath 'onepassword'
    [void][System.IO.Directory]::CreateDirectory($fakePackagePath)
    [System.IO.File]::WriteAllText(
        (Join-Path $fakePackagePath '__init__.py'),
        @'
class DesktopAuth:
    def __init__(self, account_name):
        self.account_name = account_name


class Variable:
    def __init__(self, name, value):
        self.name = name
        self.value = value
        self.masked = True


class Environments:
    async def get_variables(self, environment_id):
        return type("Response", (), {"variables": [
            Variable("DEFAULT_ADMIN_PASSWORD", "SyntheticDefaultAdmin01!"),
            Variable("DEFAULT_ROOT_PASSWORD", "SyntheticDefaultRoot001!"),
        ]})()


class Client:
    @staticmethod
    async def authenticate(**kwargs):
        return type("Sdk", (), {"environments": Environments()})()
'@,
        [System.Text.UTF8Encoding]::new($false)
    )
    $omittedRequestPath = Join-Path $credentialTestRoot 'omitted-request.json'
    $omittedStatusPath = Join-Path $credentialTestRoot 'omitted-status.json'
    $omittedOvfBundlePath = Join-Path $credentialTestRoot 'omitted-first-boot-ovf.dpapi'
    $omittedRequest = [ordered]@{
        AdminPasswordCiphertext         = ''
        RootPasswordCiphertext          = ''
        Fqdn                            = 'issue558-defaults.atlaso.internal'
        RootSshEnabled                  = $false
        DevelopmentAdminSshPublicKey    = ''
        DevelopmentRootCaCertificatePem = [System.IO.File]::ReadAllText((
                Join-Path $RepositoryRoot 'image\vmware-workstation\development-trust\atlaso-development-root-ca.pem'
            ))
    }
    [System.IO.File]::WriteAllText($omittedRequestPath, ($omittedRequest | ConvertTo-Json -Compress))
    $credentialPython = (Get-Command python -CommandType Application | Select-Object -First 1).Source
    & $credentialHelperPath `
        -Action Prepare `
        -RequestPath $omittedRequestPath `
        -StatusPath $omittedStatusPath `
        -OvfBundlePath $omittedOvfBundlePath `
        -PythonCommand $credentialPython `
        -DependencyPath $fakeDependencyPath `
        -OnePasswordAccount 'atlaso-test-account' `
        -EnvironmentId 'atlaso-test-environment' `
        -TimeoutSeconds 5
    $omittedStatus = [System.IO.File]::ReadAllText($omittedStatusPath) | ConvertFrom-Json
    if (-not [bool]$omittedStatus.Success -or $omittedStatus.Code -cne 'prepared') {
        throw "Omitted credential preparation failed safely: $($omittedStatus.Code)"
    }
    $omittedVmxPath = Join-Path $credentialTestRoot 'issue558-defaults.vmx'
    [System.IO.File]::WriteAllText($omittedVmxPath, 'displayName = "issue558-defaults"')
    $omittedStageStatusPath = Join-Path $credentialTestRoot 'omitted-stage-status.json'
    & $credentialHelperPath `
        -Action Stage `
        -StatusPath $omittedStageStatusPath `
        -OvfBundlePath $omittedOvfBundlePath `
        -VmxPath $omittedVmxPath
    $omittedStageStatus = [System.IO.File]::ReadAllText($omittedStageStatusPath) | ConvertFrom-Json
    $omittedVmxText = [System.IO.File]::ReadAllText($omittedVmxPath)
    if (
        -not [bool]$omittedStageStatus.Success -or
        $omittedStageStatus.Code -cne 'staged' -or
        $omittedVmxText -notmatch 'atlaso\.admin_password' -or
        $omittedVmxText -notmatch 'atlaso\.root_password'
    ) {
        throw 'The Windows DPAPI bridge did not stage both omitted SDK defaults into the synthetic VMX.'
    }

    $syntheticAdmin = [SecureString]::new()
    foreach ($character in 'SyntheticAdmin01!'.ToCharArray()) {
        $syntheticAdmin.AppendChar($character)
    }
    $syntheticRoot = [SecureString]::new()
    foreach ($character in 'SyntheticRoot001!'.ToCharArray()) {
        $syntheticRoot.AppendChar($character)
    }
    $requestPath = Join-Path $credentialTestRoot 'request.json'
    $statusPath = Join-Path $credentialTestRoot 'status.json'
    $ovfBundlePath = Join-Path $credentialTestRoot 'first-boot-ovf.dpapi'
    $request = [ordered]@{
        AdminPasswordCiphertext         = ConvertFrom-SecureString -SecureString $syntheticAdmin
        RootPasswordCiphertext          = ConvertFrom-SecureString -SecureString $syntheticRoot
        Fqdn                            = 'issue558.atlaso.internal'
        RootSshEnabled                  = $false
        DevelopmentAdminSshPublicKey    = ''
        DevelopmentRootCaCertificatePem = [System.IO.File]::ReadAllText((
                Join-Path $RepositoryRoot 'image\vmware-workstation\development-trust\atlaso-development-root-ca.pem'
            ))
    }
    [System.IO.File]::WriteAllText($requestPath, ($request | ConvertTo-Json -Compress))
    & $credentialHelperPath `
        -Action Prepare `
        -RequestPath $requestPath `
        -StatusPath $statusPath `
        -OvfBundlePath $ovfBundlePath
    $prepareStatus = [System.IO.File]::ReadAllText($statusPath) | ConvertFrom-Json
    if (-not [bool]$prepareStatus.Success -or $prepareStatus.Code -cne 'prepared') {
        throw "Explicit SecureString credential preparation failed safely: $($prepareStatus.Code)"
    }
    $testVmxPath = Join-Path $credentialTestRoot 'issue558.vmx'
    [System.IO.File]::WriteAllText($testVmxPath, 'displayName = "issue558"')
    $stageStatusPath = Join-Path $credentialTestRoot 'stage-status.json'
    & $credentialHelperPath `
        -Action Stage `
        -StatusPath $stageStatusPath `
        -OvfBundlePath $ovfBundlePath `
        -VmxPath $testVmxPath
    $stageStatus = [System.IO.File]::ReadAllText($stageStatusPath) | ConvertFrom-Json
    $testVmxText = [System.IO.File]::ReadAllText($testVmxPath)
    if (
        -not [bool]$stageStatus.Success -or
        $stageStatus.Code -cne 'staged' -or
        $testVmxText -notmatch 'guestinfo\.ovfEnv' -or
        $testVmxText -notmatch 'atlaso\.admin_password' -or
        $testVmxText -notmatch 'atlaso\.root_password'
    ) {
        throw 'The bounded child did not stage both explicit SecureString overrides into the synthetic VMX.'
    }

    $invalidRequest = [ordered]@{}
    foreach ($requestKey in $request.Keys) {
        $invalidRequest[$requestKey] = $request[$requestKey]
    }
    $invalidAdmin = [SecureString]::new()
    foreach ($character in 'too-short'.ToCharArray()) {
        $invalidAdmin.AppendChar($character)
    }
    $invalidRequest.AdminPasswordCiphertext = ConvertFrom-SecureString -SecureString $invalidAdmin
    [System.IO.File]::WriteAllText($requestPath, ($invalidRequest | ConvertTo-Json -Compress))
    [System.IO.File]::Delete($statusPath)
    [System.IO.File]::Delete($ovfBundlePath)
    & $credentialHelperPath `
        -Action Prepare `
        -RequestPath $requestPath `
        -StatusPath $statusPath `
        -OvfBundlePath $ovfBundlePath
    $invalidStatus = [System.IO.File]::ReadAllText($statusPath) | ConvertFrom-Json
    if ([bool]$invalidStatus.Success -or $invalidStatus.Code -cne 'admin_password_invalid') {
        throw 'An invalid explicit administrator password did not fail in credential preflight.'
    }
    if (Test-Path -LiteralPath $ovfBundlePath) {
        throw 'Invalid credential preflight left a protected OVF bundle behind.'
    }
}
finally {
    Remove-Item -LiteralPath $credentialTestRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host 'Atlaso normal VMware test VM development-CA bridge tests passed.'
