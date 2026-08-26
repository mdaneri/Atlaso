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
    $preservedMarker = Join-Path $missingEnvironmentIdRoot 'preserve.txt'
    [System.IO.File]::WriteAllText($preservedMarker, 'preserve-before-preflight')
    $inertVmrunPath = Join-Path $missingEnvironmentIdRoot 'must-not-invoke-vmrun.exe'
    [System.IO.File]::WriteAllText($inertVmrunPath, '')
    $missingEnvironmentIdError = ''
    try {
        & $wrapperPath `
            -OutputDirectory $missingEnvironmentIdRoot `
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
    $functionDefinition = [scriptblock]::Create($functionAst.Extent.Text)
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
$markerCreation = $wrapperSource.LastIndexOf(
    'New-AtlasoDevelopmentCaCleanupMarker',
    [System.StringComparison]::Ordinal
)
if ($markerCreation -lt 0 -or $markerCreation -gt $stageStart) {
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
if ($wrapperSource.IndexOf('Remove-AtlasoDevelopmentCaCleanupMarker', $importProof) -lt $importProof) {
    throw 'The durable cleanup marker must remain until encrypted-import proof succeeds.'
}
if ($firstBootSource -notmatch '\$process\.Kill\(\$true\)' -or
    $wrapperSource -notmatch '-TimeoutSeconds \$TimeoutSeconds') {
    throw 'The 1Password child must enforce a deadline and terminate its complete process tree.'
}
if ($firstBootSource -notmatch "AtlasoProcessTreeTerminationUnproven") {
    throw 'Unproven process-tree termination must carry a machine-readable failure marker.'
}
$childActiveDeferral = $wrapperSource.IndexOf(
    "`$cleanupMarker.Phase -in @('secret-child-active', 'vm-start-child-active')",
    $rollbackCatch,
    [System.StringComparison]::Ordinal
)
$rollbackRuntimeScrub = $wrapperSource.IndexOf(
    'Clear-AtlasoWorkstationDevelopmentRootCaRuntimePrivateKey',
    $rollbackCatch,
    [System.StringComparison]::Ordinal
)
if (
    $childActiveDeferral -lt $rollbackCatch -or
    $rollbackRuntimeScrub -lt $childActiveDeferral
) {
    throw 'The broad rollback handler must defer before VM mutation while a staging or start child may remain active.'
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
if (
    $removalChildPhase -lt $rollbackCatch -or
    $rollbackRemoval -lt $removalChildPhase -or
    $conditionalRestore -lt $rollbackRemoval
) {
    throw 'Rollback must persist removal-child activity and withhold quarantined disks until termination is proven.'
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

Write-Host 'Atlaso normal VMware test VM development-CA bridge tests passed.'
