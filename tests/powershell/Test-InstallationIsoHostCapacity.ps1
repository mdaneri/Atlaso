<#
.SYNOPSIS
Test host-capacity guards for the development installation ISO VM.
.DESCRIPTION
Loads the capacity checks from the VM harness, injects read-only volume
measurements, and checks that guards precede VM artifact publication and starts.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Import-Module (Join-Path $repositoryRoot 'scripts/windows/vmware/Atlaso.InstallationFixture.psm1') -Force
$harnessPath = Join-Path $repositoryRoot 'scripts\windows\vmware\test-installation-iso.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($harnessPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw "Installation VM harness has PowerShell parse errors: $($parseErrors[0].Message)" }

foreach ($name in @('Get-InstallationHostVolumeInfo', 'Assert-InstallationHostCapacity')) {
    $definition = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $true) | Select-Object -First 1
    if (-not $definition) { throw "The capacity guard function is missing: $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
}

$script:capacityFixture = [pscustomobject]@{ IsReady = $true; AvailableFreeSpace = [long]74GB }
$script:capacityQueries = 0
$script:queriedOutputDirectories = [System.Collections.Generic.List[string]]::new()
<#
.SYNOPSIS
Return an injected read-only volume result for the capacity guard fixture.
.PARAMETER OutputDirectory
Exact task-owned path passed to the production capacity guard.
#>
function Get-InstallationHostVolumeInfo {
    param([string]$OutputDirectory)
    $script:capacityQueries++
    $script:queriedOutputDirectories.Add($OutputDirectory)
    return $script:capacityFixture
}

Assert-InstallationHostCapacity -OutputDirectory 'E:\owned\fresh-vm'
if ($script:capacityQueries -ne 1 -or $script:queriedOutputDirectories[0] -cne 'E:\owned\fresh-vm') {
    throw 'The guard must query the containing volume for the exact task-owned path before accepting capacity.'
}
$oldLabelRejected = $false
$script:capacityFixture = [pscustomobject]@{ IsReady = $true; AvailableFreeSpace = [long]77GB }
try { Assert-InstallationHostCapacity -OutputDirectory 'E:\owned\old-label-vm' -FixtureProfile OldSystemLabel }
catch { $oldLabelRejected = $true }
if (-not $oldLabelRejected) { throw 'Old-label creation must reserve its additional raw image capacity.' }
$script:capacityFixture = [pscustomobject]@{ IsReady = $true; AvailableFreeSpace = [long]78GB }
Assert-InstallationHostCapacity -OutputDirectory 'E:\owned\old-label-vm' -FixtureProfile OldSystemLabel

$belowFreshMinimumRejected = $false
$script:capacityFixture = [pscustomobject]@{ IsReady = $true; AvailableFreeSpace = [long]73GB }
try { Assert-InstallationHostCapacity -OutputDirectory 'E:\owned\fresh-vm' }
catch { $belowFreshMinimumRejected = $_.Exception.Message -match '^Installation VM host volume requires at least 74 GiB free;' }
if (-not $belowFreshMinimumRejected) { throw 'Create must refuse before mutation when less than the full sparse-disk budget is free.' }

$script:capacityFixture = [pscustomobject]@{ IsReady = $true; AvailableFreeSpace = [long]6GB }
Assert-InstallationHostCapacity -OutputDirectory 'E:\owned\existing-vm' -ExistingVm

$belowExistingMinimumRejected = $false
$script:capacityFixture = [pscustomobject]@{ IsReady = $true; AvailableFreeSpace = [long]5GB }
try { Assert-InstallationHostCapacity -OutputDirectory 'E:\owned\existing-vm' -ExistingVm }
catch { $belowExistingMinimumRejected = $_.Exception.Message -match '^Installation VM host volume requires at least 6 GiB free;' }
if (-not $belowExistingMinimumRejected) { throw 'An installed-VM restart must reserve a fresh 4 GiB memory file plus 2 GiB overhead.' }

$unreadyRejected = $false
$script:capacityFixture = [pscustomobject]@{ IsReady = $false; AvailableFreeSpace = [long]0 }
try { Assert-InstallationHostCapacity -OutputDirectory 'E:\owned\existing-vm' -ExistingVm }
catch { $unreadyRejected = $_.Exception.Message -ceq 'Installation VM host volume is not ready or its available capacity is unknown.' }
if (-not $unreadyRejected) { throw 'An unready host volume must fail closed.' }

$unknownCapacityRejected = $false
$script:capacityFixture = [pscustomobject]@{ IsReady = $true; AvailableFreeSpace = $null }
try { Assert-InstallationHostCapacity -OutputDirectory 'E:\owned\existing-vm' -ExistingVm }
catch { $unknownCapacityRejected = $_.Exception.Message -ceq 'Installation VM host volume is not ready or its available capacity is unknown.' }
if (-not $unknownCapacityRejected) { throw 'An unknown host capacity must fail closed.' }

$source = [System.IO.File]::ReadAllText($harnessPath)
$capacityCalls = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and
    $node.GetCommandName() -ceq 'Assert-InstallationHostCapacity'
}, $true))
if ($capacityCalls.Count -ne 3) { throw 'Create and both installed-boot paths must use the host-capacity guard.' }

$createCapacityIndex = $capacityCalls[2].Extent.StartOffset
$whatIfIndex = $source.IndexOf("ShouldProcess(`$resolvedOutput, 'Create isolated receipt-bound installation ISO test VM')", [StringComparison]::Ordinal)
$creationIntentCommands = @()
foreach ($command in $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -ceq 'Publish-AtlasoTestVmOwnershipRecord' }, $true)) {
    $elements = @($command.CommandElements)
    $recordIndex = -1; $kindIndex = -1
    for ($elementIndex = 0; $elementIndex -lt $elements.Count; $elementIndex++) {
        $element = $elements[$elementIndex]
        if ($element -is [System.Management.Automation.Language.CommandParameterAst]) {
            if ($element.ParameterName -ceq 'Record') { $recordIndex = $elementIndex }
            elseif ($element.ParameterName -ceq 'Kind') { $kindIndex = $elementIndex }
        }
    }
    if ($recordIndex -ge 0 -and $kindIndex -ge 0 -and $recordIndex + 1 -lt $elements.Count -and
        $kindIndex + 1 -lt $elements.Count -and
        $elements[$recordIndex + 1] -is [System.Management.Automation.Language.VariableExpressionAst] -and
        $elements[$recordIndex + 1].VariablePath.UserPath -ceq 'intent' -and
        $elements[$kindIndex + 1] -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
        $elements[$kindIndex + 1].Value -ceq 'intent') { $creationIntentCommands += $command }
}
if ($creationIntentCommands.Count -ne 1) { throw 'The Create ownership intent must be identified by its AST record and kind selectors.' }
$intentIndex = $creationIntentCommands[0].Extent.StartOffset
if ($whatIfIndex -lt 0 -or $intentIndex -lt 0 -or $createCapacityIndex -le $whatIfIndex -or $createCapacityIndex -ge $intentIndex) {
    throw 'Create must exit through ShouldProcess before querying capacity and check capacity before publishing ownership intent.'
}

$startText = "Start-InstallationIsoVm -VmrunPath `$vmrun -VmxPath `$context.VmxPath -OutputDirectory `$context.OutputDirectory"
$bootStartIndex = $source.IndexOf($startText, [StringComparison]::Ordinal)
$resumeStartIndex = $source.IndexOf($startText, $bootStartIndex + 1, [StringComparison]::Ordinal)
if ($bootStartIndex -lt 0 -or $resumeStartIndex -lt 0 -or
    $capacityCalls[0].Extent.StartOffset -ge $bootStartIndex -or $capacityCalls[1].Extent.StartOffset -ge $resumeStartIndex) {
    throw 'Both existing-VM paths must check capacity before starting the provider.'
}

Write-Output 'Installation ISO VM host-capacity checks passed.'
