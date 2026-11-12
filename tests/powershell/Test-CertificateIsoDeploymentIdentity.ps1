<#
.SYNOPSIS
Test original ISO identity argument reconstruction without creating native resources.
.PARAMETER RepositoryRoot
Repository checkout containing the admitted VMware identity helper and deployment owner.
#>
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$RepositoryRoot)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($RepositoryRoot)
$ownerPath = Join-Path $root 'scripts/windows/vmware/deploy-certificate-iso-wheel.ps1'
$identityPath = Join-Path $root 'scripts/windows/vmware/Atlaso.VmwareTestIdentity.psm1'
Import-Module $identityPath -Force

$parseErrors = $null
$ownerAst = [Management.Automation.Language.Parser]::ParseFile($ownerPath, [ref]$null, [ref]$parseErrors)
$definitions = @($ownerAst.FindAll({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Get-CertificateIsoNativeArguments'
}, $false))
if ($parseErrors.Count -or $definitions.Count -ne 1) {
    throw 'The original ISO native-argument builder is absent or ambiguous.'
}

$calls = @($ownerAst.FindAll({ param($node)
    $node -is [Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -ceq 'Get-CertificateIsoNativeArguments'
}, $false))
if ($calls.Count -ne 1) {
    throw 'The owner must invoke the native-argument builder once at its admission boundary.'
}

. ([scriptblock]::Create($definitions[0].Extent.Text))

<#
.SYNOPSIS
Build string-only receipt inputs for native identity admission tests.
.PARAMETER CollisionSuffix
Optional canonical collision suffix for the original VM identity.
#>
function New-TestNativeIdentityInputs {
    param([AllowEmptyString()][string]$CollisionSuffix = '')

    $identity = New-AtlasoVmwareTestIdentity -PullRequestNumber 1118 `
        -Purpose installation-iso -CollisionSuffix $CollisionSuffix
    $uncreatedRoot = Join-Path $root ('test-results/not-created-' + [guid]::NewGuid().ToString('N'))
    $original = @{
        canonical_name = $identity.Name
        output_directory = Join-Path $uncreatedRoot $identity.Name
        vmx_path = Join-Path (Join-Path $uncreatedRoot $identity.Name) ($identity.Name + '.vmx')
    }
    $plan = @{
        pr = 1118
        deployment_network_binding = @{ vmnet = 'vmnet9' }
        appliance_ownership = @{ path = Join-Path $uncreatedRoot 'original-ownership.json'; sha256 = 'a' * 64 }
        appliance_disk_baseline = @{ path = Join-Path $uncreatedRoot 'disk-baseline.json'; sha256 = 'b' * 64 }
        appliance_installed_boot = @{ path = Join-Path $uncreatedRoot 'installed-boot.json'; sha256 = 'c' * 64 }
    }
    return @{ Plan = $plan; Original = $original; Identity = $identity; UncreatedRoot = $uncreatedRoot }
}

<#
.SYNOPSIS
Require a native-argument admission assertion to hold.
.PARAMETER Condition
Boolean result of the assertion.
.PARAMETER Message
Failure detail for the synthetic identity case.
#>
function Assert-NativeIdentityCondition {
    param([Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message)
    if (-not $Condition) { throw $Message }
}

$cases = @(
    @{ Suffix = ''; Expected = '' },
    @{ Suffix = 'ca-static-terminal-off01'; Expected = 'ca-static-terminal-off01' },
    @{ Suffix = '0123456789abcdef0123456789abcdef'; Expected = '0123456789abcdef0123456789abcdef' }
)
foreach ($case in $cases) {
    $caseInput = New-TestNativeIdentityInputs -CollisionSuffix $case.Suffix
    $arguments = Get-CertificateIsoNativeArguments -RepositoryRoot $root `
        -Plan $caseInput.Plan -Original $caseInput.Original
    $expectedIdentity = New-AtlasoVmwareTestIdentity -PullRequestNumber 1118 `
        -Purpose installation-iso -CollisionSuffix $case.Expected
    Assert-NativeIdentityCondition ($arguments.Mode -ceq 'AdmitNetwork') 'The native mode must be AdmitNetwork.'
    Assert-NativeIdentityCondition ($arguments.Worktree -ceq $root) 'The admitted worktree must be the repository root.'
    Assert-NativeIdentityCondition ($arguments.PullRequestNumber -eq 1118) 'The original PR identity must be preserved.'
    Assert-NativeIdentityCondition ($arguments.CollisionSuffix -ceq $case.Expected) 'The canonical collision suffix must be preserved.'
    Assert-NativeIdentityCondition ($caseInput.Original.canonical_name -ceq $expectedIdentity.Name) 'The canonical VM name must match the real identity module.'
    Assert-NativeIdentityCondition ($caseInput.Original.vmx_path -ceq (Join-Path $caseInput.Original.output_directory ($expectedIdentity.Name + '.vmx'))) `
        'The original VMX must use the exact canonical identity.'
    Assert-NativeIdentityCondition ($arguments.OutputDirectory -ceq $caseInput.Original.output_directory) 'The original output directory must be retained.'
    Assert-NativeIdentityCondition ($arguments.NetworkVmnet -ceq 'vmnet9') 'The admitted host-only vmnet must be retained.'
    Assert-NativeIdentityCondition ($arguments.OriginalReceiptPath -ceq $caseInput.Plan.appliance_ownership.path) 'The original ownership receipt path must be retained.'
    Assert-NativeIdentityCondition ($arguments.OriginalReceiptSha256 -ceq ('a' * 64)) 'The original ownership digest must be retained.'
    Assert-NativeIdentityCondition ($arguments.BaselineReceiptPath -ceq $caseInput.Plan.appliance_disk_baseline.path) 'The disk-baseline receipt path must be retained.'
    Assert-NativeIdentityCondition ($arguments.BaselineReceiptSha256 -ceq ('b' * 64)) 'The disk-baseline digest must be retained.'
    Assert-NativeIdentityCondition ($arguments.BootReceiptPath -ceq $caseInput.Plan.appliance_installed_boot.path) 'The installed-boot receipt path must be retained.'
    Assert-NativeIdentityCondition ($arguments.BootReceiptSha256 -ceq ('c' * 64)) 'The installed-boot digest must be retained.'
    Assert-NativeIdentityCondition (-not (Test-Path -LiteralPath $caseInput.UncreatedRoot)) 'Identity tests must not create VM or receipt paths.'
}

$valid = New-TestNativeIdentityInputs -CollisionSuffix 'ca-static-terminal-off01'
$invalidCases = @(
    @{ Name = 'foreign PR'; Action = { param($p, $o) $p.pr = 1119 } },
    @{ Name = 'foreign canonical name'; Action = { param($p, $o) $o.canonical_name = 'Atlaso-PR-1118-other-purpose' } },
    @{ Name = 'suffix normalization change'; Action = { param($p, $o) $o.canonical_name += '-CA-Terminal' } },
    @{ Name = 'VMX basename mismatch'; Action = { param($p, $o) $o.vmx_path = Join-Path $o.output_directory 'different.vmx' } },
    @{ Name = 'missing canonical name'; Action = { param($p, $o) $o.Remove('canonical_name') } }
)
foreach ($invalidCase in $invalidCases) {
    $plan = $valid.Plan.Clone()
    $original = $valid.Original.Clone()
    & $invalidCase.Action $plan $original
    $refused = $false
    try { $null = Get-CertificateIsoNativeArguments -RepositoryRoot $root -Plan $plan -Original $original }
    catch { $refused = $true }
    Assert-NativeIdentityCondition $refused ("The builder must refuse " + $invalidCase.Name + '.')
    Assert-NativeIdentityCondition (-not (Test-Path -LiteralPath $valid.UncreatedRoot)) 'Refusal cases must not create fixture paths.'
}

Write-Output 'Certificate ISO native identity tests passed (3 admitted, 5 refused; no resources created).'
