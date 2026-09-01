<#
.SYNOPSIS
Build or validate the supported Atlaso VMware Workstation Photon image.
.PARAMETER IsoUrl
Pinned Photon HTTPS source URL, local path, or local file URI.
.PARAMETER IsoChecksum
Expected Photon ISO checksum.
.PARAMETER SshPassword
Optional temporary Packer SSH password override. When omitted, the wrapper
retrieves DEFAULT_ROOT_PASSWORD from the exact Atlaso 1Password Environment.
.PARAMETER BootstrapAdminPassword
Optional initial administrator password override. When omitted, the wrapper
retrieves DEFAULT_ADMIN_PASSWORD from the exact Atlaso 1Password Environment.
.PARAMETER OnePasswordEnvironmentId
Opaque ID of the exact Atlaso 1Password Environment. When omitted, the wrapper
reads the checkout-local onepassword-environment-id selector.
.PARAMETER EnvironmentIdFile
Optional single-line Atlaso Environment ID file. The legacy
OnePasswordEnvironmentIdFile name remains available as an alias.
.PARAMETER OnePasswordAccount
Optional 1Password account name or ID approved for desktop SDK authorization
when either credential is omitted. The single CLI account is used when this
selector is omitted.
.PARAMETER OnePasswordPython
Optional standard GIL-enabled Windows x64 CPython 3.14 executable used by the locked Windows
1Password SDK runtime. The highest compatible Windows-registered runtime is
used when this selector is omitted.
.PARAMETER CredentialTimeoutSeconds
Bounded timeout for each 1Password SDK preparation and retrieval operation.
.PARAMETER ImageBuildTimeoutSeconds
Bounded deadline for the isolated plaintext-consuming Photon/Packer child.
.PARAMETER CredentialBundlePath
Internal current-user DPAPI credential bundle used only by the isolated child.
.PARAMETER CredentialChild
Internal marker proving the current process is the isolated image-build child.
.PARAMETER BuilderStaticDnsJson
Internal JSON transport for the non-secret builder DNS server array.
.PARAMETER BuilderStaticDnsBound
Internal marker preserving whether the caller explicitly bound the builder DNS array.
.PARAMETER SensitiveBuildDirectory
Internal task-owned directory containing all plaintext image-build artifacts.
.PARAMETER OutputCleanupClaimPath
Internal durable marker proving the isolated child claimed a pre-existing output root.
.PARAMETER OutputClaimGeneration
Internal invocation-specific generation bound to the exclusive output claim.
.PARAMETER BuilderAddressReservationPath
Internal non-secret handoff for the exact temporary address reservation.
.PARAMETER SourceSnapshotRoot
Internal commit-derived source root consumed by the isolated child.
.PARAMETER SourceCommit
Internal exact source commit admitted before the isolated child starts.
.PARAMETER SourceBranch
Internal exact task branch admitted before the isolated child starts.
.PARAMETER TaskRepositoryRoot
Internal exact task worktree root recorded in the builder-address reservation.
.PARAMETER SourceInventorySha256
Internal deterministic SHA-256 inventory of the staged source tree.
.PARAMETER SourceInventoryFileCount
Internal number of regular files in the staged source inventory.
.PARAMETER VmName
Builder virtual-machine name.
.PARAMETER PullRequestNumber
Exact positive same-repository pull request that owns a task build.
.PARAMETER CollisionSuffix
Optional collision-safe suffix for multiple builders owned by one pull request.
.PARAMETER ReleaseBuilder
Select the protected version-and-commit-bound release builder identity.
.PARAMETER ReleaseVersion
Strict synchronized version for a protected release builder.
.PARAMETER ReleaseSourceCommit
Exact source commit for a protected release builder.
.PARAMETER ReleaseWorkflowRunId
Optional workflow run ID that further distinguishes a release builder.
.PARAMETER VerifiedRepository
Internal exact same-repository identity proven by the parent process.
.PARAMETER VerifiedSourceBranch
Internal exact pull-request head branch proven by the parent process.
.PARAMETER VerifiedSourceCommit
Internal exact source commit proven by the parent process.
.PARAMETER OutputDirectory
Artifact output directory.
.PARAMETER SshHost
Optional explicit builder SSH address.
.PARAMETER SharedSourceDirectory
Shared checksum-verified ISO cache.
.PARAMETER VmrunPath
Optional VMware vmrun executable path.
.PARAMETER VmnetName
Management VMware network.
.PARAMETER ServiceVmnetName
Services VMware network.
.PARAMETER BridgedInterfaceAlias
Optional host adapter for bridged management.
.PARAMETER BuilderStaticIp
Temporary Photon builder address.
.PARAMETER BuilderAddressPoolStartOffset
First host offset in the temporary builder-address pool.
.PARAMETER BuilderAddressPoolEndOffset
Final host offset in the temporary builder-address pool.
.PARAMETER VmwareDhcpConfigPath
Optional explicit VMware vmnetdhcp.conf path.
.PARAMETER BuilderStaticNetmask
Temporary Photon builder netmask.
.PARAMETER BuilderStaticGateway
Temporary Photon builder gateway.
.PARAMETER BuilderStaticDns
Temporary Photon builder DNS servers.
.PARAMETER FinalMgmtAddress
Final appliance management address policy.
.PARAMETER FinalMgmtGateway
Final appliance management gateway.
.PARAMETER FinalMgmtInterface
Final appliance management interface.
.PARAMETER PipGlobalIndex
Optional pip global index setting.
.PARAMETER PipGlobalIndexUrl
Optional pip index URL.
.PARAMETER PackerDirectory
VMware Packer template directory.
.PARAMETER PreparedIsoPath
Optional remastered ISO path.
.PARAMETER PackerOnError
Packer failure-handling mode.
.PARAMETER PackerStartupTimeoutSeconds
Maximum interval from monitored Packer process start to SSH provisioning.
.PARAMETER PackerHeartbeatSeconds
Interval for sanitized builder startup diagnostics.
.PARAMETER AllowExistingManagementSubnet
Permit an existing matching management subnet.
.PARAMETER SkipNetworkCheck
Skip VMware network preflight.
.PARAMETER Headless
Run the VMware builder without a console window.
.PARAMETER KeepExistingOutput
Preserve an existing output directory.
.PARAMETER EnableRealSystemAdapters
Enable real system adapters in the image.
.PARAMETER ValidateOnly
Validate Packer inputs without building.
.PARAMETER PrepareIsoOnly
Reject ISO-only preparation because the retained ISO would contain reusable credentials.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingPlainTextForPassword',
    'OnePasswordEnvironmentId',
    Justification = 'Opaque Environment identifier; bounded children retrieve concealed values.'
)]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingPlainTextForPassword',
    'OnePasswordAccount',
    Justification = 'Desktop authorization account identifier, not an account password.'
)]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingPlainTextForPassword',
    'OnePasswordPython',
    Justification = 'Executable selector for the isolated SDK runtime, not a password.'
)]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingPlainTextForPassword',
    'CredentialBundlePath',
    Justification = 'Path to current-user DPAPI ciphertext, not a plaintext password.'
)]
[CmdletBinding()]
param(
    [Parameter()]
    [string]$IsoUrl = 'https://packages.broadcom.com/photon/5.0/GA/iso/photon-5.0-dde71ec57.x86_64.iso',

    [Parameter()]
    [string]$IsoChecksum = 'sha512:6a7a258399a258da742032987c043ab25503698d35edafaf1ae000f12127da1a161d8b84caa17fd8f23d129e81e1faa7ab087c20ab9229772a643f8f9475305f',

    [SecureString]$SshPassword,
    [SecureString]$BootstrapAdminPassword,
    [string]$OnePasswordEnvironmentId = '',
    [Alias('OnePasswordEnvironmentIdFile')]
    [string]$EnvironmentIdFile = '',
    [string]$OnePasswordAccount = '',
    [string]$OnePasswordPython = '',
    [ValidateRange(1, 3600)]
    [int]$CredentialTimeoutSeconds = 300,
    [ValidateRange(300, 86400)]
    [int]$ImageBuildTimeoutSeconds = 21600,
    [string]$CredentialBundlePath = '',
    [switch]$CredentialChild,
    [string]$BuilderStaticDnsJson = '',
    [switch]$BuilderStaticDnsBound,
    [string]$SensitiveBuildDirectory = '',
    [string]$OutputCleanupClaimPath = '',
    [string]$OutputClaimGeneration = '',
    [string]$BuilderAddressReservationPath = '',
    [string]$SourceSnapshotRoot = '',
    [string]$SourceCommit = '',
    [string]$SourceBranch = '',
    [string]$TaskRepositoryRoot = '',
    [string]$SourceInventorySha256 = '',
    [int]$SourceInventoryFileCount = 0,
    [string]$VmName = '',
    [ValidateRange(1, 2147483647)]
    [int]$PullRequestNumber = 0,
    [string]$CollisionSuffix = '',
    [switch]$ReleaseBuilder,
    [string]$ReleaseVersion = '',
    [string]$ReleaseSourceCommit = '',
    [ValidateRange(1, [long]::MaxValue)]
    [long]$ReleaseWorkflowRunId = 0,
    [string]$VerifiedRepository = '',
    [string]$VerifiedSourceBranch = '',
    [string]$VerifiedSourceCommit = '',
    [string]$OutputDirectory = '',
    [string]$SshHost = '',
    [string]$SharedSourceDirectory = '',
    [string]$VmrunPath = '',
    [string]$VmnetName = 'VMnet8',
    [string]$ServiceVmnetName = 'VMnet1',
    [string]$BridgedInterfaceAlias = '',
    # Legacy fallbacks; normal builds replace these from the selected VMware vmnet unless explicitly passed.
    [string]$BuilderStaticIp = '192.168.167.30/24',
    [ValidateRange(1, 4294967294)]
    [uint32]$BuilderAddressPoolStartOffset = 30,
    [ValidateRange(1, 4294967294)]
    [uint32]$BuilderAddressPoolEndOffset = 49,
    [string]$VmwareDhcpConfigPath = '',
    [string]$BuilderStaticNetmask = '255.255.255.0',
    [string]$BuilderStaticGateway = '192.168.167.2',
    [string[]]$BuilderStaticDns = @(),
    [string]$FinalMgmtAddress = 'dhcp',
    [string]$FinalMgmtGateway = '',
    [string]$FinalMgmtInterface = 'eth0',
    [string]$PipGlobalIndex = '',
    [string]$PipGlobalIndexUrl = '',
    [string]$PackerDirectory = '',
    [string]$PreparedIsoPath = '',
    [ValidateSet('cleanup', 'abort', 'ask', 'run-cleanup-provisioner')]
    [string]$PackerOnError = 'cleanup',
    [ValidateRange(30, 3600)]
    [int]$PackerStartupTimeoutSeconds = 2700,
    [ValidateRange(1, 300)]
    [int]$PackerHeartbeatSeconds = 30,
    [switch]$AllowExistingManagementSubnet,
    [switch]$SkipNetworkCheck,
    [switch]$Headless,
    [switch]$KeepExistingOutput,
    [switch]$EnableRealSystemAdapters,
    [switch]$ValidateOnly,
    [switch]$PrepareIsoOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PrepareIsoOnly) {
    throw 'PrepareIsoOnly is not supported because a retained remastered ISO would contain reusable build credentials. Run Packer validation or a build so the ISO can be deleted after the bounded consumer exits.'
}

. (Join-Path $PSScriptRoot 'Atlaso.WorkstationFirstBoot.ps1')
Import-Module (Join-Path $PSScriptRoot 'Atlaso.OnePasswordCredentials.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\common\Atlaso.PhotonImage.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationCleanup.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Atlaso.VmwarePayload.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationBuildMonitor.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Atlaso.WorkstationBuilderAddress.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Atlaso.SourceSnapshot.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'Atlaso.VmwareBuilderIdentity.psm1') -Force

<#
.SYNOPSIS
Resolve and verify the exact same-repository pull request for a task build.
.PARAMETER RepositoryRoot
Atlaso checkout whose branch and remote repository must own the pull request.
.PARAMETER PullRequestNumber
Exact positive pull-request number selected by the caller.
.PARAMETER CollisionSuffix
Optional sanitized suffix for another builder owned by the pull request.
#>
function Resolve-AtlasoTaskBuilderIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][ValidateRange(1, 2147483647)][int]$PullRequestNumber,
        [string]$CollisionSuffix = ''
    )

    $branch = [string](& git -C $RepositoryRoot branch --show-current)
    $commit = [string](& git -C $RepositoryRoot rev-parse HEAD)
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($branch) -or
        $commit.Trim() -notmatch '^[0-9a-f]{40}$') {
        throw 'A task-owned Photon builder requires one checked-out branch and exact source commit.'
    }
    $branch = $branch.Trim()
    $commit = $commit.Trim()
    $trackedChanges = @(& git -C $RepositoryRoot status --short --untracked-files=no)
    if ($LASTEXITCODE -ne 0 -or $trackedChanges.Count -ne 0) {
        throw 'A task-owned Photon builder requires a clean tracked checkout at the exact pull-request head.'
    }

    $gh = Get-Command gh -ErrorAction SilentlyContinue
    if (-not $gh) {
        throw 'GitHub CLI is required to prove the task-owned Photon builder pull-request identity.'
    }
    $originUrl = ([string](& git -C $RepositoryRoot remote get-url origin)).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not resolve the exact origin remote for the Photon builder checkout.'
    }
    $originMatch = [regex]::Match(
        $originUrl,
        '^(?:https://github\.com/|ssh://git@github\.com/|git@github\.com:)(?<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?$'
    )
    if (-not $originMatch.Success) {
        throw 'The Photon builder origin must be one unambiguous GitHub repository URL.'
    }
    $repository = $originMatch.Groups['repository'].Value
    $pullJson = [string](& $gh.Source api "repos/$repository/pulls/$PullRequestNumber" `
        --jq '{number:.number,state:.state,head_repository:.head.repo.full_name,head_branch:.head.ref,head_commit:.head.sha}')
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($pullJson)) {
        throw "Could not verify pull request #$PullRequestNumber for repository $repository."
    }
    try {
        $pull = $pullJson | ConvertFrom-Json
    }
    catch {
        throw "GitHub returned invalid identity evidence for pull request #$PullRequestNumber."
    }
    if ([int]$pull.number -ne $PullRequestNumber -or [string]$pull.state -cne 'open' -or
        [string]$pull.head_repository -ine $repository -or
        [string]$pull.head_branch -cne $branch -or
        [string]$pull.head_commit -cne $commit) {
        throw "Pull request #$PullRequestNumber is not the open same-repository owner of branch '$branch' at commit $commit."
    }
    $canonicalRepository = [string]$pull.head_repository
    if ($canonicalRepository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') {
        throw "Pull request #$PullRequestNumber returned an invalid canonical repository identity."
    }
    return New-AtlasoVmwareBuilderIdentity `
        -PullRequestNumber $PullRequestNumber `
        -CollisionSuffix $CollisionSuffix `
        -Repository $canonicalRepository `
        -SourceBranch $branch `
        -SourceCommit $commit
}

<#
.SYNOPSIS
Revalidate that the task-owned builder identity still owns the exact open pull request.
.PARAMETER RepositoryRoot
Atlaso checkout whose current branch and commit must still own the pull request.
.PARAMETER PullRequestNumber
Exact positive pull-request number selected by the caller.
.PARAMETER CollisionSuffix
Optional sanitized suffix for another builder owned by the pull request.
.PARAMETER ExpectedIdentity
Previously verified builder identity that must remain unchanged.
#>
function Assert-AtlasoTaskBuilderIdentityCurrent {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][ValidateRange(1, 2147483647)][int]$PullRequestNumber,
        [string]$CollisionSuffix = '',
        [Parameter(Mandatory = $true)][object]$ExpectedIdentity
    )

    $currentIdentity = Resolve-AtlasoTaskBuilderIdentity `
        -RepositoryRoot $RepositoryRoot `
        -PullRequestNumber $PullRequestNumber `
        -CollisionSuffix $CollisionSuffix
    if ([string]$currentIdentity.Name -cne [string]$ExpectedIdentity.Name -or
        [string]$currentIdentity.Repository -cne [string]$ExpectedIdentity.Repository -or
        [string]$currentIdentity.SourceBranch -cne [string]$ExpectedIdentity.SourceBranch -or
        [string]$currentIdentity.SourceCommit -cne [string]$ExpectedIdentity.SourceCommit) {
        throw 'The task-owned Photon builder identity changed before a destructive or provider boundary.'
    }
    return $currentIdentity
}

<#
.SYNOPSIS
Resolve and verify the protected release builder identity.
.PARAMETER RepositoryRoot
Atlaso checkout whose version and commit are verified.
.PARAMETER ReleaseVersion
Strict synchronized release version.
.PARAMETER ReleaseSourceCommit
Exact release source commit.
.PARAMETER ReleaseWorkflowRunId
Optional workflow run ID that further distinguishes the builder.
#>
function Resolve-AtlasoReleaseBuilderIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$ReleaseVersion,
        [Parameter(Mandatory = $true)][string]$ReleaseSourceCommit,
        [long]$ReleaseWorkflowRunId = 0
    )

    $head = ([string](& git -C $RepositoryRoot rev-parse HEAD)).Trim()
    if ($LASTEXITCODE -ne 0 -or $head -notmatch '^[0-9a-f]{40}$' -or
        $ReleaseSourceCommit -cne $head) {
        throw 'The protected release builder source commit does not match exact checkout HEAD.'
    }
    $trackedChanges = @(& git -C $RepositoryRoot status --short --untracked-files=no)
    if ($LASTEXITCODE -ne 0 -or $trackedChanges.Count -ne 0) {
        throw 'A protected release builder requires a clean tracked checkout at exact HEAD.'
    }
    $version = ([string](& python (Join-Path $RepositoryRoot 'scripts/version.py') get --root $RepositoryRoot)).Trim()
    if ($LASTEXITCODE -ne 0 -or $version -cne $ReleaseVersion) {
        throw 'The protected release builder version does not match synchronized repository metadata.'
    }
    $gh = Get-Command gh -ErrorAction SilentlyContinue
    if (-not $gh) {
        throw 'GitHub CLI is required to prove the protected release builder source.'
    }
    $originUrl = ([string](& git -C $RepositoryRoot remote get-url origin)).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not resolve the exact origin remote for the protected release builder.'
    }
    $originMatch = [regex]::Match(
        $originUrl,
        '^(?:https://github\.com/|ssh://git@github\.com/|git@github\.com:)(?<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?$'
    )
    if (-not $originMatch.Success) {
        throw 'The protected release builder origin must be one unambiguous GitHub repository URL.'
    }
    $repository = $originMatch.Groups['repository'].Value
    $canonicalRepository = ([string](& $gh.Source repo view $repository `
            --json nameWithOwner --jq '.nameWithOwner')).Trim()
    if ($LASTEXITCODE -ne 0 -or
        $canonicalRepository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -or
        -not $canonicalRepository.Equals($repository, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'GitHub returned a repository identity that differs from the protected release checkout.'
    }
    & git -C $RepositoryRoot fetch origin main --no-tags
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not refresh protected main for release-builder verification.'
    }
    & git -C $RepositoryRoot merge-base --is-ancestor $ReleaseSourceCommit origin/main
    if ($LASTEXITCODE -ne 0) {
        throw 'The protected release builder source is not reachable from current origin/main.'
    }
    $softwareTag = "v$ReleaseVersion"
    $tagCommit = ([string](& $gh.Source api `
            "repos/$canonicalRepository/commits/$softwareTag" --jq '.sha')).Trim()
    if ($LASTEXITCODE -ne 0 -or $tagCommit -cne $ReleaseSourceCommit) {
        throw "The protected release tag $softwareTag does not identify exact checkout HEAD."
    }
    $releaseJson = [string](& $gh.Source release view $softwareTag `
        --repo $canonicalRepository `
        --json 'tagName,isDraft,isPrerelease,assets')
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($releaseJson)) {
        throw "Could not verify the protected software Release $softwareTag."
    }
    try {
        $release = $releaseJson | ConvertFrom-Json
    }
    catch {
        throw "GitHub returned invalid protected software Release evidence for $softwareTag."
    }
    if ([string]$release.tagName -cne $softwareTag -or
        [bool]$release.isDraft -or [bool]$release.isPrerelease) {
        throw "The protected software Release $softwareTag is missing or misclassified."
    }
    $assetNames = @($release.assets | ForEach-Object { [string]$_.name })
    $expectedAssetNames = @(
        "atlaso-appliance-$ReleaseVersion.tar.gz",
        "atlaso-third-party-notices-$ReleaseVersion.md",
        'release-manifest.json',
        'release-manifest.json.sig'
    )
    if ($assetNames.Count -ne $expectedAssetNames.Count -or
        @($expectedAssetNames | Where-Object { $_ -cnotin $assetNames }).Count -ne 0 -or
        @($assetNames | Where-Object { $_ -cnotin $expectedAssetNames }).Count -ne 0) {
        throw "The protected software Release $softwareTag does not contain the exact canonical asset set."
    }
    $successfulRunText = [string](& $gh.Source api --method GET `
        "repos/$canonicalRepository/actions/workflows/ci.yml/runs" `
        -f "head_sha=$ReleaseSourceCommit" `
        -f 'branch=main' `
        -f 'event=push' `
        -f 'status=success' `
        -f 'per_page=100' `
        --jq '.total_count')
    $successfulRuns = 0
    if ($LASTEXITCODE -ne 0 -or
        -not [int]::TryParse($successfulRunText.Trim(), [ref]$successfulRuns) -or
        $successfulRuns -lt 1) {
        throw 'The protected release builder source has no successful main push CI run.'
    }
    $releaseIdentityArguments = @{
        ReleaseVersion = $ReleaseVersion
        SourceCommit   = $ReleaseSourceCommit
    }
    if ($ReleaseWorkflowRunId -gt 0) {
        $releaseIdentityArguments['WorkflowRunId'] = $ReleaseWorkflowRunId
    }
    return New-AtlasoVmwareBuilderIdentity @releaseIdentityArguments
}

<#
.SYNOPSIS
Revalidate the selected task or release builder identity at a mutation boundary.
.PARAMETER RepositoryRoot
Atlaso checkout whose identity must remain current and clean.
.PARAMETER ExpectedIdentity
Previously verified task or release builder identity.
.PARAMETER PullRequestNumber
Exact same-repository pull request selected for a task build.
.PARAMETER CollisionSuffix
Optional collision-safe suffix for a task build.
.PARAMETER ReleaseBuilder
Select release identity revalidation instead of pull-request revalidation.
.PARAMETER ReleaseVersion
Strict synchronized version for a protected release builder.
.PARAMETER ReleaseSourceCommit
Exact source commit for a protected release builder.
.PARAMETER ReleaseWorkflowRunId
Optional workflow run ID distinguishing the release builder.
#>
function Assert-AtlasoBuilderIdentityCurrent {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][object]$ExpectedIdentity,
        [int]$PullRequestNumber = 0,
        [string]$CollisionSuffix = '',
        [switch]$ReleaseBuilder,
        [string]$ReleaseVersion = '',
        [string]$ReleaseSourceCommit = '',
        [long]$ReleaseWorkflowRunId = 0
    )

    if (-not $ReleaseBuilder) {
        $currentIdentity = Assert-AtlasoTaskBuilderIdentityCurrent `
            -RepositoryRoot $RepositoryRoot `
            -PullRequestNumber $PullRequestNumber `
            -CollisionSuffix $CollisionSuffix `
            -ExpectedIdentity $ExpectedIdentity
        return $currentIdentity
    }
    $currentIdentity = Resolve-AtlasoReleaseBuilderIdentity `
        -RepositoryRoot $RepositoryRoot `
        -ReleaseVersion $ReleaseVersion `
        -ReleaseSourceCommit $ReleaseSourceCommit `
        -ReleaseWorkflowRunId $ReleaseWorkflowRunId
    if ([string]$currentIdentity.Kind -cne [string]$ExpectedIdentity.Kind -or
        [string]$currentIdentity.Name -cne [string]$ExpectedIdentity.Name -or
        [string]$currentIdentity.ReleaseVersion -cne [string]$ExpectedIdentity.ReleaseVersion -or
        [string]$currentIdentity.SourceCommit -cne [string]$ExpectedIdentity.SourceCommit -or
        [long]$currentIdentity.WorkflowRunId -ne [long]$ExpectedIdentity.WorkflowRunId) {
        throw 'The protected release builder identity changed before a destructive or provider boundary.'
    }
    return $currentIdentity
}

<#
.SYNOPSIS
Remove a proven-inactive Photon root and durably retire its marker.

.PARAMETER MarkerPath
Exact non-secret cleanup marker path.

.PARAMETER Marker
Validated marker payload owning the exact root.

.PARAMETER ExpectedRootPath
Exact task-created root that the marker must still own.
#>
function Complete-AtlasoPhotonBuildCleanup {
    param(
        [Parameter(Mandatory = $true)][string]$MarkerPath,
        [Parameter(Mandatory = $true)][object]$Marker,
        [Parameter(Mandatory = $true)][string]$ExpectedRootPath
    )

    $markerProperties = @($Marker.PSObject.Properties.Name)
    if ($markerProperties.Count -ne 4 -or
        'Schema' -notin $markerProperties -or
        'RootPath' -notin $markerProperties -or
        'BootIdentity' -notin $markerProperties -or
        'Phase' -notin $markerProperties -or
        $Marker.Schema -ne 1 -or
        $Marker.Phase -notin @('active', 'root-absent', 'retired')) {
        throw 'Invalid cleanup marker schema.'
    }
    $resolvedRoot = [System.IO.Path]::GetFullPath([string]$Marker.RootPath)
    $resolvedExpectedRoot = [System.IO.Path]::GetFullPath($ExpectedRootPath)
    $rootLeaf = Split-Path -Leaf $resolvedRoot
    if (-not $resolvedRoot.Equals($resolvedExpectedRoot, [StringComparison]::OrdinalIgnoreCase) -or
        $rootLeaf -notmatch '^atlaso-photon-build-credentials-[0-9a-f]{32}$') {
        throw 'Cleanup marker root does not match the exact task-created Photon root.'
    }
    if (Test-Path -LiteralPath $resolvedRoot) {
        $rootItem = Get-Item -LiteralPath $resolvedRoot -Force -ErrorAction Stop
        if ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
            throw 'Invalid cleanup root type.'
        }
        $snapshotRoot = Join-Path $resolvedRoot 'sensitive-build\source'
        if (Test-Path -LiteralPath $snapshotRoot -PathType Container) {
            Unprotect-AtlasoSourceSnapshot -Root $snapshotRoot
        }
        [System.IO.Directory]::Delete($resolvedRoot, $true)
    }
    if (Test-Path -LiteralPath $resolvedRoot) {
        throw 'Retained Photon credential artifact cleanup did not complete.'
    }
    # Flush the parent on the sensitive root's own volume before a marker on a
    # different volume is allowed to claim that the deletion is durable.
    Sync-AtlasoDirectoryMetadata -DirectoryPath (Split-Path -Parent $resolvedRoot)
    $Marker.Phase = 'root-absent'
    Write-AtlasoDurableJsonFile -Path $MarkerPath -Payload $Marker -Replace
    $Marker.Phase = 'retired'
    Write-AtlasoDurableJsonFile -Path $MarkerPath -Payload $Marker -Replace
    Remove-Item -LiteralPath $MarkerPath -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $MarkerPath) {
        throw 'Retained Photon cleanup marker removal did not complete.'
    }
}

<#
.SYNOPSIS
Recover a retained Photon sensitive-build root after a proven host restart.

.PARAMETER MarkerPath
Exact non-secret cleanup marker path.
#>
function Invoke-AtlasoPhotonBuildCleanupRecovery {
    param([Parameter(Mandatory = $true)][string]$MarkerPath)

    if (-not (Test-Path -LiteralPath $MarkerPath -PathType Leaf)) {
        return
    }
    try {
        $marker = Get-Content -LiteralPath $MarkerPath -Raw -ErrorAction Stop | ConvertFrom-Json
        $markerProperties = @($marker.PSObject.Properties.Name)
        if ($markerProperties.Count -ne 4 -or
            'Schema' -notin $markerProperties -or
            'RootPath' -notin $markerProperties -or
            'BootIdentity' -notin $markerProperties -or
            'Phase' -notin $markerProperties -or
            $marker.Schema -ne 1) {
            throw 'Invalid cleanup marker schema.'
        }
        $resolvedRoot = [System.IO.Path]::GetFullPath([string]$marker.RootPath)
        $resolvedTempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
        $tempRootPrefix = $resolvedTempRoot.TrimEnd(
            [System.IO.Path]::DirectorySeparatorChar,
            [System.IO.Path]::AltDirectorySeparatorChar
        ) + [System.IO.Path]::DirectorySeparatorChar
        if (-not $resolvedRoot.StartsWith($tempRootPrefix, [StringComparison]::OrdinalIgnoreCase) -or
            (Split-Path -Leaf $resolvedRoot) -notmatch '^atlaso-photon-build-credentials-[0-9a-f]{32}$') {
            throw 'Invalid cleanup root.'
        }
        if ($marker.Phase -notin @('active', 'root-absent', 'retired')) {
            throw 'Invalid cleanup marker phase.'
        }
        if ($marker.Phase -ceq 'active' -and
            [string]$marker.BootIdentity -ceq (Get-AtlasoWindowsBootIdentity)) {
            throw 'A Windows restart is required before retained Photon credential artifacts can be cleaned safely.'
        }
        Complete-AtlasoPhotonBuildCleanup `
            -MarkerPath $MarkerPath `
            -Marker $marker `
            -ExpectedRootPath $resolvedRoot
    }
    catch {
        throw 'A prior Photon image build has unresolved sensitive cleanup. Restart Windows, then rerun this wrapper.'
    }
}

<#
.SYNOPSIS
Resolve the VMware Workstation vmrun executable.
.PARAMETER Path
Optional explicit executable path.
#>
function Resolve-WorkstationVmrunPath {
    param([string]$Path)

    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path)) {
            throw "vmrun.exe not found: $Path"
        }
        return (Resolve-Path -LiteralPath $Path).Path
    }

    $candidates = @(
        'C:\Program Files\VMware\VMware Workstation\vmrun.exe',
        'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    $command = Get-Command vmrun -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    throw 'vmrun.exe was not found. Install VMware Workstation Pro or pass -VmrunPath.'
}

<#
.SYNOPSIS
Resolve the guarded VMware build output directory.
.PARAMETER PackerDirectory
VMware Packer template directory.
.PARAMETER OutputDirectory
Optional explicit artifact directory.
.PARAMETER VmName
Canonical task- or release-owned builder name used as the default output leaf.
#>
function Resolve-WorkstationOutputDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$PackerDirectory,
        [string]$OutputDirectory,
        [Parameter(Mandatory = $true)][string]$VmName
    )

    $effectiveOutput = if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
        Join-Path (Join-Path $PackerDirectory 'output') $VmName
    } elseif ([System.IO.Path]::IsPathRooted($OutputDirectory)) {
        $OutputDirectory
    } else {
        Join-Path $PackerDirectory $OutputDirectory
    }
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($effectiveOutput)
}

function Complete-AtlasoBuilderAddressReservationHandoff {
    <#
    .SYNOPSIS
    Release one durable builder-address handoff and remove it after verification.
    .PARAMETER Path
    Exact non-secret reservation handoff path.
    .PARAMETER VmrunPath
    Exact vmrun executable path.
    .PARAMETER StateRoot
    Stable per-user builder-address state directory.
    #>
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][string]$StateRoot
    )

    $resolvedStateRoot = [System.IO.Path]::GetFullPath($StateRoot)
    $pendingRoot = [System.IO.Path]::GetFullPath((Join-Path $resolvedStateRoot 'pending-releases'))
    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    if (-not (Split-Path -Parent $resolvedPath).Equals(
            $pendingRoot,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        (Split-Path -Leaf $resolvedPath) -notmatch '^builder-address-reservation-[0-9a-f]{32}\.json$') {
        throw 'Refusing to process an invalid VMware builder-address release handoff path.'
    }
    if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
        return
    }
    $reservation = Get-Content -LiteralPath $resolvedPath -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    Exit-AtlasoVmwareBuilderAddressReservation `
        -Reservation $reservation `
        -VmrunPath $VmrunPath `
        -StateRoot $resolvedStateRoot
    Remove-Item -LiteralPath $resolvedPath -Force
    if (Test-Path -LiteralPath $resolvedPath) {
        throw "The released VMware builder-address handoff could not be removed: $resolvedPath"
    }
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
$identityModeInvalid = ($ReleaseBuilder -and $PullRequestNumber -gt 0) -or
    (-not $ReleaseBuilder -and $PullRequestNumber -le 0) -or
    ($ReleaseBuilder -and -not [string]::IsNullOrWhiteSpace($CollisionSuffix))
if ($identityModeInvalid) {
    throw 'Select exactly one Photon builder identity: -PullRequestNumber for a task build, or -ReleaseBuilder with release version and commit inputs.'
}
if (-not $CredentialChild -and (
        -not [string]::IsNullOrWhiteSpace($VerifiedRepository) -or
        -not [string]::IsNullOrWhiteSpace($VerifiedSourceBranch) -or
        -not [string]::IsNullOrWhiteSpace($VerifiedSourceCommit)
    )) {
    throw 'Verified builder identity fields are internal and may be supplied only to the isolated child.'
}
$builderReservationStateRoot = Join-Path (
    [Environment]::GetFolderPath('LocalApplicationData')
) 'Atlaso\vmware-builder-addresses'
$builderReservationPendingRoot = Join-Path $builderReservationStateRoot 'pending-releases'
$cleanupMarkerPath = Join-Path $repoRoot '.atlaso-local\photon-image-build-cleanup.json'
if (-not $CredentialChild) {
    # Recovery is bound to the prior boot and durable marker, not the requested
    # new build. Run it before a closed or advanced PR can block cleanup of the
    # retained sensitive root or address reservation.
    Invoke-AtlasoPhotonBuildCleanupRecovery -MarkerPath $cleanupMarkerPath
    [void][System.IO.Directory]::CreateDirectory($builderReservationPendingRoot)
    $pendingReservationHandoffs = @(
        Get-ChildItem -LiteralPath $builderReservationPendingRoot `
            -Filter 'builder-address-reservation-*.json' `
            -File `
            -ErrorAction Stop
    )
    if ($pendingReservationHandoffs.Count -gt 0) {
        $recoveryVmrunPath = Resolve-WorkstationVmrunPath -Path $VmrunPath
        foreach ($handoff in $pendingReservationHandoffs) {
            try {
                Complete-AtlasoBuilderAddressReservationHandoff `
                    -Path $handoff.FullName `
                    -VmrunPath $recoveryVmrunPath `
                    -StateRoot $builderReservationStateRoot
                Write-Host "Released prior VMware builder-address handoff $($handoff.Name)."
            }
            catch {
                Write-Warning "Retained prior VMware builder-address handoff $($handoff.Name): $($_.Exception.Message)"
            }
        }
    }
}
$identityRepositoryRoot = if ($CredentialChild) {
    if ([string]::IsNullOrWhiteSpace($TaskRepositoryRoot)) {
        throw 'The isolated child source repository identity is unavailable.'
    }
    (Resolve-Path -LiteralPath $TaskRepositoryRoot -ErrorAction Stop).Path
}
else {
    $repoRoot
}
$builderIdentity = if ($ReleaseBuilder) {
    if ([string]::IsNullOrWhiteSpace($ReleaseVersion) -or
        $ReleaseSourceCommit -notmatch '^[0-9a-f]{40}$') {
        throw 'A protected release builder requires -ReleaseVersion and exact -ReleaseSourceCommit.'
    }
    if ($CredentialChild) {
        $currentHead = ([string](& git -C $identityRepositoryRoot rev-parse HEAD)).Trim()
        $trackedChanges = @(& git -C $identityRepositoryRoot status --short --untracked-files=no)
        if ($LASTEXITCODE -ne 0 -or $currentHead -cne $ReleaseSourceCommit -or
            $VerifiedSourceCommit -cne $ReleaseSourceCommit -or $trackedChanges.Count -ne 0) {
            throw 'The isolated child release identity no longer matches exact checkout HEAD.'
        }
        $releaseIdentityArguments = @{
            ReleaseVersion = $ReleaseVersion
            SourceCommit   = $ReleaseSourceCommit
        }
        if ($ReleaseWorkflowRunId -gt 0) {
            $releaseIdentityArguments['WorkflowRunId'] = $ReleaseWorkflowRunId
        }
        New-AtlasoVmwareBuilderIdentity @releaseIdentityArguments
    }
    else {
        Resolve-AtlasoReleaseBuilderIdentity `
            -RepositoryRoot $repoRoot `
            -ReleaseVersion $ReleaseVersion `
            -ReleaseSourceCommit $ReleaseSourceCommit `
            -ReleaseWorkflowRunId $ReleaseWorkflowRunId
    }
}
else {
    if ($CredentialChild) {
        $currentBranch = ([string](& git -C $identityRepositoryRoot branch --show-current)).Trim()
        $currentHead = ([string](& git -C $identityRepositoryRoot rev-parse HEAD)).Trim()
        $trackedChanges = @(& git -C $identityRepositoryRoot status --short --untracked-files=no)
        if ($LASTEXITCODE -ne 0 -or
            $VerifiedRepository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -or
            $VerifiedSourceBranch -cne $currentBranch -or
            $VerifiedSourceCommit -cne $currentHead -or $trackedChanges.Count -ne 0) {
            throw 'The isolated child task identity no longer matches the proven repository branch and commit.'
        }
        New-AtlasoVmwareBuilderIdentity `
            -PullRequestNumber $PullRequestNumber `
            -CollisionSuffix $CollisionSuffix `
            -Repository $VerifiedRepository `
            -SourceBranch $VerifiedSourceBranch `
            -SourceCommit $VerifiedSourceCommit
    }
    else {
        Resolve-AtlasoTaskBuilderIdentity `
            -RepositoryRoot $repoRoot `
            -PullRequestNumber $PullRequestNumber `
            -CollisionSuffix $CollisionSuffix
    }
}
$VmName = [string]$builderIdentity.Name
if ($CredentialChild) {
    if ($SshPassword -or $BootstrapAdminPassword -or
        [string]::IsNullOrWhiteSpace($CredentialBundlePath) -or
        -not (Test-Path -LiteralPath $CredentialBundlePath -PathType Leaf)) {
        throw 'The isolated Photon credential bundle is unavailable or invalid.'
    }
    $credentialBundleRoot = [System.IO.Path]::GetFullPath((Split-Path -Parent $CredentialBundlePath))
    $resolvedOutputCleanupClaimPath = if ([string]::IsNullOrWhiteSpace($OutputCleanupClaimPath)) {
        ''
    }
    else {
        [System.IO.Path]::GetFullPath($OutputCleanupClaimPath)
    }
    $resolvedBuilderAddressReservationPath = if ([string]::IsNullOrWhiteSpace($BuilderAddressReservationPath)) {
        ''
    }
    else {
        [System.IO.Path]::GetFullPath($BuilderAddressReservationPath)
    }
    $sensitiveBuildRoot = if ([string]::IsNullOrWhiteSpace($SensitiveBuildDirectory)) {
        ''
    }
    else {
        [System.IO.Path]::GetFullPath($SensitiveBuildDirectory)
    }
    $credentialRootPrefix = $credentialBundleRoot.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    ) + [System.IO.Path]::DirectorySeparatorChar
    if ([string]::IsNullOrWhiteSpace($sensitiveBuildRoot) -or
        -not $sensitiveBuildRoot.StartsWith($credentialRootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The isolated Photon sensitive-build root is unavailable or invalid.'
    }
    $sensitiveBuildPrefix = $sensitiveBuildRoot.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    ) + [System.IO.Path]::DirectorySeparatorChar
    $resolvedSourceSnapshotRoot = if ([string]::IsNullOrWhiteSpace($SourceSnapshotRoot)) {
        ''
    }
    else {
        [System.IO.Path]::GetFullPath($SourceSnapshotRoot)
    }
    $expectedSourceSnapshotRoot = [System.IO.Path]::GetFullPath((Join-Path $sensitiveBuildRoot 'source'))
    $resolvedTaskRepositoryRoot = if ([string]::IsNullOrWhiteSpace($TaskRepositoryRoot)) {
        ''
    }
    else {
        (Resolve-Path -LiteralPath $TaskRepositoryRoot -ErrorAction Stop).Path
    }
    if ([string]::IsNullOrWhiteSpace($resolvedSourceSnapshotRoot) -or
        -not $resolvedSourceSnapshotRoot.Equals(
            $expectedSourceSnapshotRoot,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        $SourceCommit -notmatch '^[0-9a-f]{40}$' -or
        [string]::IsNullOrWhiteSpace($SourceBranch) -or
        [string]::IsNullOrWhiteSpace($resolvedTaskRepositoryRoot) -or
        $SourceInventorySha256 -notmatch '^[0-9a-f]{64}$' -or
        $SourceInventoryFileCount -le 0) {
        throw 'The isolated Photon source snapshot identity is unavailable or invalid.'
    }
    if ($SourceBranch -cne '(detached-release)') {
        & git check-ref-format --branch $SourceBranch 2>$null | Out-Null
    }
    if ($SourceBranch -cne '(detached-release)' -and $LASTEXITCODE -ne 0) {
        throw 'The isolated Photon task branch identity is unavailable or invalid.'
    }
    $resolvedChildPackerDirectory = if ([string]::IsNullOrWhiteSpace($PackerDirectory)) {
        ''
    }
    else {
        [System.IO.Path]::GetFullPath($PackerDirectory)
    }
    $expectedChildPackerDirectory = [System.IO.Path]::GetFullPath((Join-Path $sensitiveBuildRoot 'packer-work'))
    if ([string]::IsNullOrWhiteSpace($resolvedChildPackerDirectory) -or
        -not $resolvedChildPackerDirectory.Equals(
            $expectedChildPackerDirectory,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'The isolated Photon Packer working directory is unavailable or invalid.'
    }
    $null = Assert-AtlasoSourceSnapshotCommitBinding `
        -Root $resolvedSourceSnapshotRoot `
        -RepositoryRoot $resolvedTaskRepositoryRoot `
        -Commit $SourceCommit `
        -ExpectedSha256 $SourceInventorySha256 `
        -ExpectedFileCount $SourceInventoryFileCount `
        -VerificationRoot (Join-Path $sensitiveBuildRoot 'source-verification')
    New-Item -ItemType Directory -Path $resolvedChildPackerDirectory -ErrorAction Stop | Out-Null
    $packerTemplatePath = Join-Path `
        $resolvedSourceSnapshotRoot `
        'image\vmware-workstation\atlaso-photon.pkr.hcl'
    if (-not (Test-Path -LiteralPath $packerTemplatePath -PathType Leaf)) {
        throw 'The inventory-bound VMware Packer template is missing.'
    }
    $PackerDirectory = $resolvedChildPackerDirectory
    $SourceSnapshotRoot = $resolvedSourceSnapshotRoot
    $TaskRepositoryRoot = $resolvedTaskRepositoryRoot
    if ([string]::IsNullOrWhiteSpace($resolvedOutputCleanupClaimPath) -or
        -not $resolvedOutputCleanupClaimPath.StartsWith(
            $credentialRootPrefix,
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        (Split-Path -Leaf $resolvedOutputCleanupClaimPath) -cne 'output-cleanup-claimed.json') {
        throw 'The isolated Photon output-cleanup claim path is unavailable or invalid.'
    }
    if ($OutputClaimGeneration -notmatch '^[0-9a-f]{32}$') {
        throw 'The isolated Photon output-claim generation is unavailable or invalid.'
    }
    if ([string]::IsNullOrWhiteSpace($resolvedBuilderAddressReservationPath) -or
        -not (Split-Path -Parent $resolvedBuilderAddressReservationPath).Equals(
            [System.IO.Path]::GetFullPath($builderReservationPendingRoot),
            [StringComparison]::OrdinalIgnoreCase
        ) -or
        (Split-Path -Leaf $resolvedBuilderAddressReservationPath) -notmatch
            '^builder-address-reservation-[0-9a-f]{32}\.json$') {
        throw 'The isolated Photon builder-address reservation path is unavailable or invalid.'
    }
    if (-not [string]::IsNullOrWhiteSpace($PreparedIsoPath)) {
        $resolvedChildPreparedIsoPath = [System.IO.Path]::GetFullPath($PreparedIsoPath)
        if (-not $resolvedChildPreparedIsoPath.StartsWith(
                $sensitiveBuildPrefix,
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw 'The isolated Photon prepared-ISO path is unavailable or invalid.'
        }
    }
    try {
        $credentialBundle = Get-Content -LiteralPath $CredentialBundlePath -Raw | ConvertFrom-Json
        $bundleProperties = @($credentialBundle.PSObject.Properties.Name)
        if ($bundleProperties.Count -ne 2 -or
            'AdminPasswordCiphertext' -notin $bundleProperties -or
            'RootPasswordCiphertext' -notin $bundleProperties) {
            throw 'The isolated Photon credential bundle is invalid.'
        }
        $BootstrapAdminPassword = ConvertTo-SecureString $credentialBundle.AdminPasswordCiphertext
        $SshPassword = ConvertTo-SecureString $credentialBundle.RootPasswordCiphertext
    }
    catch {
        throw 'The isolated Photon credential bundle is unavailable or invalid.'
    }
    $credentialBundle = $null
    if (-not [string]::IsNullOrWhiteSpace($BuilderStaticDnsJson)) {
        try {
            $transportedDns = @(ConvertFrom-Json -InputObject $BuilderStaticDnsJson)
            if (@($transportedDns | Where-Object { $_ -isnot [string] }).Count -ne 0) {
                throw 'Invalid builder DNS transport.'
            }
            $BuilderStaticDns = @($transportedDns)
        }
        catch {
            throw 'The isolated Photon builder DNS transport is invalid.'
        }
    }
}
else {
    $canonicalPackerDirectory = [System.IO.Path]::GetFullPath(
        (Join-Path $repoRoot 'image\vmware-workstation')
    )
    $taskSourceCommit = [string]$builderIdentity.SourceCommit
    $taskSourceBranch = if ($ReleaseBuilder) {
        '(detached-release)'
    }
    else {
        [string]$builderIdentity.SourceBranch
    }
    $requestedPackerDirectory = if ([string]::IsNullOrWhiteSpace($PackerDirectory)) {
        $canonicalPackerDirectory
    }
    else {
        [System.IO.Path]::GetFullPath($PackerDirectory)
    }
    if (-not $requestedPackerDirectory.Equals(
            $canonicalPackerDirectory,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw 'VMware image builds require the canonical commit-derived Packer template.'
    }
    $outerSharedSourceDirectory = if ([string]::IsNullOrWhiteSpace($SharedSourceDirectory)) {
        [System.IO.Path]::GetFullPath((Join-Path $repoRoot 'image\common\source'))
    }
    else {
        [System.IO.Path]::GetFullPath($SharedSourceDirectory)
    }
    $needsOnePasswordDefaults = $null -eq $SshPassword -or $null -eq $BootstrapAdminPassword
    $resolvedEnvironmentId = ''
    if ($needsOnePasswordDefaults) {
        $resolvedEnvironmentId = Resolve-AtlasoOnePasswordEnvironmentId `
            -EnvironmentId $OnePasswordEnvironmentId `
            -EnvironmentIdFile $EnvironmentIdFile `
            -RepositoryRoot $repoRoot `
            -ConsumerDescription 'VMware Photon image building'
    }

    # Credential preflight completes before the isolated child can perform any
    # network, cleanup, ISO, Packer, or image mutation.
    $credentialPair = Get-AtlasoOnePasswordCredentialPair `
        -RepositoryRoot $repoRoot `
        -EnvironmentId $resolvedEnvironmentId `
        -OnePasswordAccount $OnePasswordAccount `
        -OnePasswordPython $OnePasswordPython `
        -AdminPassword $BootstrapAdminPassword `
        -RootPassword $SshPassword `
        -TimeoutSeconds $CredentialTimeoutSeconds `
        -ConsumerDescription 'VMware Photon image build'
    $credentialRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
        "atlaso-photon-build-credentials-$([guid]::NewGuid().ToString('N'))"
    )
    # Resolve every operator-controlled output and child path before publishing
    # an active cleanup marker, so a normalization failure cannot strand it.
    $childCredentialBundlePath = Join-Path $credentialRoot 'credentials.json'
    $childSensitiveBuildDirectory = Join-Path $credentialRoot 'sensitive-build'
    $childPackerDirectory = Join-Path $childSensitiveBuildDirectory 'packer-work'
    $childOutputCleanupClaimPath = Join-Path $credentialRoot 'output-cleanup-claimed.json'
    $childOutputClaimGeneration = [guid]::NewGuid().ToString('N')
    $childBuilderAddressReservationPath = Join-Path $builderReservationPendingRoot (
        "builder-address-reservation-$([guid]::NewGuid().ToString('N')).json"
    )
    $outerCleanupPackerDirectory = $canonicalPackerDirectory
    $outerCleanupOutputDirectory = Resolve-WorkstationOutputDirectory `
        -PackerDirectory $outerCleanupPackerDirectory `
        -OutputDirectory $OutputDirectory `
        -VmName $VmName
    $outerCleanupOutputDirectory = Assert-AtlasoVmwareBuilderOutputDirectory `
        -OutputDirectory $outerCleanupOutputDirectory `
        -Identity $builderIdentity
    $preparedIsoLeaf = if ($PSBoundParameters.ContainsKey('PreparedIsoPath') -and
        -not [string]::IsNullOrWhiteSpace($PreparedIsoPath)) {
        [System.IO.Path]::GetFileName($PreparedIsoPath)
    }
    else {
        'atlaso-photon-with-kickstart.iso'
    }
    if ([string]::IsNullOrWhiteSpace($preparedIsoLeaf)) {
        $preparedIsoLeaf = 'atlaso-photon-with-kickstart.iso'
    }
    $childPreparedIsoPath = Join-Path (Join-Path $childSensitiveBuildDirectory 'kickstart') $preparedIsoLeaf
    if (-not $Headless -and -not $ValidateOnly) {
        # Credential retrieval can outlive the initial identity proof. Refresh
        # task or release state before the parent mutates VMware provider state.
        $null = Assert-AtlasoBuilderIdentityCurrent `
            -RepositoryRoot $repoRoot `
            -ExpectedIdentity $builderIdentity `
            -PullRequestNumber $PullRequestNumber `
            -CollisionSuffix $CollisionSuffix `
            -ReleaseBuilder:$ReleaseBuilder `
            -ReleaseVersion $ReleaseVersion `
            -ReleaseSourceCommit $ReleaseSourceCommit `
            -ReleaseWorkflowRunId $ReleaseWorkflowRunId
        $parentRepairOutputClaim = $null
        try {
            # Stabilize the output, sibling manifest, VMX, and provider repair
            # against another build using the same canonical identity.
            $parentRepairOutputClaim = Enter-AtlasoVmwareBuilderOutputClaim `
                -OutputDirectory $outerCleanupOutputDirectory `
                -Identity $builderIdentity `
                -ClaimGeneration $childOutputClaimGeneration
            $outerCleanupOutputExistedBeforeChild = Test-Path -LiteralPath $outerCleanupOutputDirectory
        $outerBuilderManifestPath = Get-AtlasoVmwareBuilderIdentityManifestPath `
            -OutputDirectory $outerCleanupOutputDirectory
        $outerBuilderManifestExists = Test-Path -LiteralPath $outerBuilderManifestPath -PathType Leaf
        if ($outerCleanupOutputExistedBeforeChild -and -not $outerBuilderManifestExists) {
            throw "Refusing parent-side VMware mutation without the retained builder ownership manifest: $outerCleanupOutputDirectory"
        }
        if ($outerBuilderManifestExists) {
            $null = Assert-AtlasoVmwareBuilderOwnershipManifest `
                -Path $outerBuilderManifestPath `
                -OutputDirectory $outerCleanupOutputDirectory `
                -Identity $builderIdentity
            if ($KeepExistingOutput) {
                $null = Assert-AtlasoVmwareBuilderIdentityManifest `
                    -Path $outerBuilderManifestPath `
                    -OutputDirectory $outerCleanupOutputDirectory `
                    -Identity $builderIdentity
            }
        }
        $outerBuilderVmx = Join-Path $outerCleanupOutputDirectory "$VmName.vmx"
        if (Test-Path -LiteralPath $outerBuilderVmx -PathType Leaf) {
            $null = Assert-AtlasoVmwareBuilderVmx `
                -VmxPath $outerBuilderVmx `
                -OutputDirectory $outerCleanupOutputDirectory `
                -Identity $builderIdentity
        }
        $parentVmrunPath = Resolve-WorkstationVmrunPath -Path $VmrunPath
        if (-not $KeepExistingOutput) {
            # Stale library repair requires Workstation to be closed. Repair
            # only missing registrations here; the child retains full output
            # cleanup after network preparation and immediately before build.
            Repair-AtlasoWorkstationStaleRegistrations `
                -ScopeRoot $outerCleanupOutputDirectory `
                -Confirm:$false
        }
        # This parent is outside the sensitive Windows job and owns the only
        # permitted Workstation UI launch; descendants receive no breakaway right.
        $null = Initialize-AtlasoWorkstationGui -VmrunPath $parentVmrunPath
        }
        finally {
            if ($null -ne $parentRepairOutputClaim) {
                $parentRepairOutputClaim.Dispose()
            }
        }
    }
    [void][System.IO.Directory]::CreateDirectory($credentialRoot)
    [void][System.IO.Directory]::CreateDirectory($childSensitiveBuildDirectory)
    $cleanupMarkerDirectory = Split-Path -Parent $cleanupMarkerPath
    [void][System.IO.Directory]::CreateDirectory($cleanupMarkerDirectory)
    $cleanupMarkerPayload = [ordered]@{
        Schema       = 1
        RootPath     = [System.IO.Path]::GetFullPath($credentialRoot)
        BootIdentity = Get-AtlasoWindowsBootIdentity
        Phase        = 'active'
    }
    Write-AtlasoDurableJsonFile -Path $cleanupMarkerPath -Payload $cleanupMarkerPayload
    if (-not (Test-Path -LiteralPath $cleanupMarkerPath -PathType Leaf)) {
        throw 'Photon sensitive-cleanup ownership could not be established.'
    }
    $cleanupMarkerPayload = $null
    $processTreeTerminationUnproven = $false
    $reservationReleaseBlocked = $false
    try {
        $sourceSnapshot = New-AtlasoImmutableSourceSnapshot `
            -RepositoryRoot $repoRoot `
            -StagingRoot $childSensitiveBuildDirectory
        $recheckedTaskSourceCommit = ([string](& git -C $repoRoot rev-parse HEAD)).Trim()
        $recheckedTaskSourceBranch = ([string](& git -C $repoRoot branch --show-current)).Trim()
        $expectedCheckoutBranch = if ($ReleaseBuilder) { '' } else { $taskSourceBranch }
        if ($LASTEXITCODE -ne 0 -or
            $sourceSnapshot.Commit -cne $taskSourceCommit -or
            $recheckedTaskSourceCommit -cne $taskSourceCommit -or
            $recheckedTaskSourceBranch -cne $expectedCheckoutBranch) {
            throw 'The VMware image build source checkout changed during snapshot admission.'
        }
        $null = Protect-AtlasoSourceSnapshot `
            -Root $sourceSnapshot.Root `
            -ExpectedSha256 $sourceSnapshot.Sha256 `
            -ExpectedFileCount $sourceSnapshot.FileCount
        $credentialPayload = [ordered]@{
            AdminPasswordCiphertext = ConvertFrom-SecureString -SecureString $credentialPair.AdminPassword
            RootPasswordCiphertext  = ConvertFrom-SecureString -SecureString $credentialPair.RootPassword
        }
        [System.IO.File]::WriteAllText(
            $childCredentialBundlePath,
            ($credentialPayload | ConvertTo-Json -Compress),
            [System.Text.UTF8Encoding]::new($false)
        )
        $credentialPayload = $null
        $credentialPair = $null
        $SshPassword = $null
        $BootstrapAdminPassword = $null

        $childScriptPath = Join-Path $sourceSnapshot.Root 'scripts\windows\vmware\build-photon-image.ps1'
        $childArguments = @(
            '-NoLogo', '-NoProfile', '-NonInteractive',
            '-File', $childScriptPath,
            '-CredentialChild',
            '-CredentialBundlePath', $childCredentialBundlePath,
            '-SensitiveBuildDirectory', $childSensitiveBuildDirectory,
            '-OutputCleanupClaimPath', $childOutputCleanupClaimPath,
            '-OutputClaimGeneration', $childOutputClaimGeneration,
            '-BuilderAddressReservationPath', $childBuilderAddressReservationPath,
            '-PreparedIsoPath', $childPreparedIsoPath,
            '-PackerDirectory', $childPackerDirectory,
            '-OutputDirectory', $outerCleanupOutputDirectory,
            '-SharedSourceDirectory', $outerSharedSourceDirectory,
            '-SourceSnapshotRoot', $sourceSnapshot.Root,
            '-SourceCommit', $sourceSnapshot.Commit,
            '-SourceBranch', $taskSourceBranch,
            '-TaskRepositoryRoot', $repoRoot,
            '-SourceInventorySha256', $sourceSnapshot.Sha256,
            '-SourceInventoryFileCount', $sourceSnapshot.FileCount.ToString()
        )
        if ($ReleaseBuilder) {
            $childArguments += @('-VerifiedSourceCommit', $builderIdentity.SourceCommit)
        }
        else {
            $childArguments += @(
                '-VerifiedRepository', $builderIdentity.Repository,
                '-VerifiedSourceBranch', $builderIdentity.SourceBranch,
                '-VerifiedSourceCommit', $builderIdentity.SourceCommit
            )
        }
        $excludedParameters = @(
            'SshPassword', 'BootstrapAdminPassword',
            'OnePasswordEnvironmentId', 'EnvironmentIdFile',
            'OnePasswordAccount', 'OnePasswordPython',
            'CredentialTimeoutSeconds', 'ImageBuildTimeoutSeconds',
            'CredentialBundlePath', 'CredentialChild',
            'BuilderStaticDnsJson', 'BuilderStaticDnsBound',
            'SensitiveBuildDirectory', 'OutputCleanupClaimPath',
            'OutputClaimGeneration',
            'BuilderAddressReservationPath', 'PreparedIsoPath',
            'PackerDirectory', 'OutputDirectory', 'SharedSourceDirectory',
            'SourceSnapshotRoot', 'SourceCommit', 'SourceBranch',
            'TaskRepositoryRoot',
            'SourceInventorySha256', 'SourceInventoryFileCount',
            'VerifiedRepository', 'VerifiedSourceBranch', 'VerifiedSourceCommit'
        )
        foreach ($entry in $PSBoundParameters.GetEnumerator()) {
            if ($entry.Key -in $excludedParameters) {
                continue
            }
            if ($entry.Value -is [switch]) {
                if ($entry.Value.IsPresent) {
                    $childArguments += "-$($entry.Key)"
                }
                continue
            }
            if ($entry.Key -ceq 'BuilderStaticDns' -and
                ($null -eq $entry.Value -or $entry.Value -is [array])) {
                $transportedDns = if ($null -eq $entry.Value) { @() } else { @($entry.Value) }
                $childArguments += '-BuilderStaticDnsJson'
                $childArguments += ConvertTo-Json -InputObject $transportedDns -Compress
                $childArguments += '-BuilderStaticDnsBound'
                continue
            }
            if ($entry.Value -is [array]) {
                if ($entry.Key -cne 'BuilderStaticDns') {
                    throw "Unsupported isolated Photon array parameter: $($entry.Key)."
                }
            }
            else {
                if ($null -eq $entry.Value) {
                    throw "Unsupported null isolated Photon parameter: $($entry.Key)."
                }
                $childArguments += "-$($entry.Key)"
                $childArguments += $entry.Value.ToString()
            }
        }
        try {
            Invoke-AtlasoBoundedStreamingProcess `
                -FilePath (Get-Process -Id $PID).Path `
                -ArgumentList $childArguments `
                -TimeoutSeconds $ImageBuildTimeoutSeconds `
                -Action 'The isolated VMware Photon image build'
        }
        catch {
            $isolatedBuildFailure = $_
            if ($isolatedBuildFailure.Exception.Data['AtlasoProcessTreeTerminationUnproven']) {
                $processTreeTerminationUnproven = $true
                throw 'The isolated VMware Photon image build could not prove whole-tree termination. Restart Windows, then rerun this wrapper to complete sensitive cleanup.'
            }
            $checkedFailureHandlingError = $null
            try {
                if ($isolatedBuildFailure.Exception.Data['AtlasoProcessTreeTerminationProven'] -and
                    $PackerOnError -eq 'cleanup' -and (
                        (Test-Path -LiteralPath $childOutputCleanupClaimPath -PathType Leaf)
                    )) {
                    if (Test-Path -LiteralPath $outerCleanupOutputDirectory) {
                        $parentOutputClaim = $null
                        try {
                            $timeoutCleanupClaim = Get-Content `
                                -LiteralPath $childOutputCleanupClaimPath `
                                -Raw | ConvertFrom-Json
                            if ([int]$timeoutCleanupClaim.Schema -ne 2 -or
                                [string]$timeoutCleanupClaim.ClaimGeneration -cne $childOutputClaimGeneration -or
                                -not ([string]$timeoutCleanupClaim.OutputPath).Equals(
                                    $outerCleanupOutputDirectory,
                                    [StringComparison]::OrdinalIgnoreCase
                                )) {
                                throw 'The isolated child output-cleanup claim does not match this build invocation.'
                            }
                            # The child releases its claim only after proven whole-tree
                            # termination. Revalidate identity, reacquire the output,
                            # and reject any intervening claimant generation before cleanup.
                            $null = Assert-AtlasoBuilderIdentityCurrent `
                                -RepositoryRoot $repoRoot `
                                -ExpectedIdentity $builderIdentity `
                                -PullRequestNumber $PullRequestNumber `
                                -CollisionSuffix $CollisionSuffix `
                                -ReleaseBuilder:$ReleaseBuilder `
                                -ReleaseVersion $ReleaseVersion `
                                -ReleaseSourceCommit $ReleaseSourceCommit `
                                -ReleaseWorkflowRunId $ReleaseWorkflowRunId
                            $parentOutputClaim = Enter-AtlasoVmwareBuilderOutputClaim `
                                -OutputDirectory $outerCleanupOutputDirectory `
                                -Identity $builderIdentity
                            $null = Assert-AtlasoVmwareBuilderOutputClaimGeneration `
                                -Claim $parentOutputClaim `
                                -ExpectedGeneration $childOutputClaimGeneration
                            $cleanupVmrunPath = Resolve-WorkstationVmrunPath -Path $VmrunPath
                            Write-Host 'The proven outer process boundary selected checked VMware artifact cleanup.'
                            Remove-AtlasoWorkstationArtifactRoot `
                                -VmrunPath $cleanupVmrunPath `
                                -ExpectedRemovalRoot $outerCleanupOutputDirectory `
                                -RemovalRoot $outerCleanupOutputDirectory `
                                -Confirm:$false
                        }
                        finally {
                            if ($null -ne $parentOutputClaim) {
                                $parentOutputClaim.Dispose()
                            }
                        }
                    }
                }
            }
            catch {
                $checkedFailureHandlingError = $_
            }
            if ($null -ne $checkedFailureHandlingError) {
                $reservationReleaseBlocked = $true
                throw "$($isolatedBuildFailure.Exception.Message) Checked failure handling also failed: $($checkedFailureHandlingError.Exception.Message) The VMware builder address reservation was retained."
            }
            throw $isolatedBuildFailure
        }
    }
    finally {
        $credentialPair = $null
        $SshPassword = $null
        $BootstrapAdminPassword = $null
        $resolvedCredentialRoot = [System.IO.Path]::GetFullPath($credentialRoot)
        $resolvedTempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
        if (-not $resolvedCredentialRoot.StartsWith($resolvedTempRoot, [StringComparison]::OrdinalIgnoreCase) -or
            (Split-Path -Leaf $resolvedCredentialRoot) -notmatch '^atlaso-photon-build-credentials-[0-9a-f]{32}$') {
            throw 'Refusing to clean an invalid Photon credential bridge root.'
        }
        if (-not $processTreeTerminationUnproven) {
            $reservationReleaseError = $null
            if (Test-Path -LiteralPath $childBuilderAddressReservationPath -PathType Leaf) {
                if (-not $reservationReleaseBlocked) {
                    try {
                        $builderReservation = Get-Content -LiteralPath $childBuilderAddressReservationPath -Raw |
                            ConvertFrom-Json
                        Exit-AtlasoVmwareBuilderAddressReservation `
                            -Reservation $builderReservation `
                            -VmrunPath (Resolve-WorkstationVmrunPath -Path $VmrunPath) `
                            -StateRoot $builderReservationStateRoot `
                            -ProcessTreeTerminationProven
                        Remove-Item -LiteralPath $childBuilderAddressReservationPath -Force
                        if (Test-Path -LiteralPath $childBuilderAddressReservationPath) {
                            throw 'The released VMware builder-address handoff could not be removed.'
                        }
                    }
                    catch {
                        $reservationReleaseError = $_
                    }
                }
            }
            $cleanupMarker = Get-Content -LiteralPath $cleanupMarkerPath -Raw -ErrorAction Stop |
                ConvertFrom-Json
            Complete-AtlasoPhotonBuildCleanup `
                -MarkerPath $cleanupMarkerPath `
                -Marker $cleanupMarker `
                -ExpectedRootPath $credentialRoot
            if ($null -ne $reservationReleaseError) {
                throw "The VMware builder address reservation was retained: $($reservationReleaseError.Exception.Message)"
            }
        }
    }
    return
}

<#
.SYNOPSIS
Normalize and validate a VMware vmnet name.
.PARAMETER Name
Network name to normalize.
.PARAMETER ParameterName
Caller parameter name used in diagnostics.
#>
function ConvertTo-WorkstationVmnetName {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$ParameterName
    )

    if ($Name -notmatch '^(?i)vmnet(\d+)$') {
        throw "$ParameterName must be a VMware Workstation VMnet name such as VMnet1; got '$Name'."
    }
    return "VMnet$($Matches[1])"
}

<#
.SYNOPSIS
Convert an IPv4 address to its integer representation.
.PARAMETER Address
IPv4 address to convert.
#>
function ConvertTo-Ipv4Integer {
    param([Parameter(Mandatory = $true)][string]$Address)

    $bytes = [System.Net.IPAddress]::Parse($Address).GetAddressBytes()
    if ($bytes.Count -ne 4) {
        throw "Expected an IPv4 address, got: $Address"
    }
    return (([uint32]$bytes[0] -shl 24) -bor ([uint32]$bytes[1] -shl 16) -bor ([uint32]$bytes[2] -shl 8) -bor [uint32]$bytes[3])
}

<#
.SYNOPSIS
Convert an integer to an IPv4 address.
.PARAMETER Address
Unsigned 32-bit network-order address to render in dotted-decimal form.
#>
function ConvertFrom-Ipv4Integer {
    param([Parameter(Mandatory = $true)][uint32]$Address)

    $bytes = [byte[]]@(
        (($Address -shr 24) -band 0xff),
        (($Address -shr 16) -band 0xff),
        (($Address -shr 8) -band 0xff),
        ($Address -band 0xff)
    )
    return ([System.Net.IPAddress]::new($bytes)).ToString()
}

<#
.SYNOPSIS
Return the prefix length for a contiguous IPv4 netmask.
.PARAMETER Netmask
IPv4 netmask to validate.
#>
function Get-Ipv4PrefixLength {
    param([Parameter(Mandatory = $true)][string]$Netmask)

    $mask = ConvertTo-Ipv4Integer -Address $Netmask
    $prefix = 0
    $seenZero = $false
    for ($bit = 31; $bit -ge 0; $bit--) {
        $isSet = (($mask -shr $bit) -band 1) -eq 1
        if ($isSet -and $seenZero) {
            throw "Netmask is not contiguous: $Netmask"
        }
        if ($isSet) {
            $prefix++
        } else {
            $seenZero = $true
        }
    }
    return $prefix
}

<#
.SYNOPSIS
Return a host CIDR at an offset within an IPv4 subnet.
.PARAMETER Subnet
IPv4 subnet base address.
.PARAMETER Netmask
IPv4 subnet netmask.
.PARAMETER HostOffset
Host offset within the subnet.
#>
function Get-Ipv4CidrFromSubnetOffset {
    param(
        [Parameter(Mandatory = $true)][string]$Subnet,
        [Parameter(Mandatory = $true)][string]$Netmask,
        [Parameter(Mandatory = $true)][uint32]$HostOffset
    )

    $prefix = Get-Ipv4PrefixLength -Netmask $Netmask
    $hostBits = 32 - $prefix
    if ($hostBits -lt 2) {
        throw "VMware network $Subnet/$prefix does not have enough host addresses for a static Atlaso appliance address."
    }

    $hostCapacity = [uint64]1 -shl $hostBits
    if ([uint64]$HostOffset -ge ($hostCapacity - 1)) {
        throw "Host offset $HostOffset is outside VMware network $Subnet/$prefix."
    }

    $network = ConvertTo-Ipv4Integer -Address $Subnet
    $address = $network + $HostOffset
    return "$(ConvertFrom-Ipv4Integer -Address $address)/$prefix"
}

<#
.SYNOPSIS
Return a host address at an offset within an IPv4 subnet.
.PARAMETER Subnet
IPv4 subnet base address.
.PARAMETER Netmask
IPv4 subnet netmask.
.PARAMETER HostOffset
Host offset within the subnet.
#>
function Get-Ipv4AddressFromSubnetOffset {
    param(
        [Parameter(Mandatory = $true)][string]$Subnet,
        [Parameter(Mandatory = $true)][string]$Netmask,
        [Parameter(Mandatory = $true)][uint32]$HostOffset
    )

    return (Get-Ipv4CidrFromSubnetOffset -Subnet $Subnet -Netmask $Netmask -HostOffset $HostOffset) -split '/', 2 | Select-Object -First 1
}

<#
.SYNOPSIS
Write and verify role-bound VMware build provenance.
.PARAMETER OutputDirectory
Completed Packer artifact directory.
.PARAMETER VmName
Expected VMX base name.
.PARAMETER RepoRoot
Deprecated compatibility parameter retained for existing callers.
.PARAMETER SourceCommit
Exact commit admitted before source staging.
.PARAMETER SourceSnapshotRoot
Commit-derived source tree used by Packer.
.PARAMETER SourceInventorySha256
Deterministic staged-source inventory SHA-256.
.PARAMETER SourceInventoryFileCount
Number of regular files in the staged-source inventory.
.PARAMETER BuilderIdentity
Validated task or release identity bound to the output and VMX.
#>
function Write-AtlasoVmwareBuildProvenance {
    param(
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][string]$VmName,
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string]$SourceCommit,
        [Parameter(Mandatory = $true)][string]$SourceSnapshotRoot,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{64}$')][string]$SourceInventorySha256,
        [Parameter(Mandatory = $true)][ValidateRange(1, [int]::MaxValue)][int]$SourceInventoryFileCount,
        [Parameter(Mandatory = $true)][psobject]$BuilderIdentity
    )

    $null = $RepoRoot
    if ([string]$BuilderIdentity.SourceCommit -cne $SourceCommit) {
        throw 'VMware build provenance source snapshot and builder identity identify different commits.'
    }
    $null = Assert-AtlasoSourceSnapshot `
        -Root $SourceSnapshotRoot `
        -ExpectedSha256 $SourceInventorySha256 `
        -ExpectedFileCount $SourceInventoryFileCount
    $resolvedVmx = Assert-AtlasoVmwareBuilderVmx `
        -VmxPath (Join-Path $OutputDirectory "$VmName.vmx") `
        -OutputDirectory $OutputDirectory `
        -Identity $BuilderIdentity
    $vmx = Get-Item -LiteralPath $resolvedVmx -ErrorAction Stop
    $payloadLayout = @(Get-AtlasoVmwarePayloadLayout -VmxPath $vmx.FullName -RequireExactlyTwoVmdks)
    $provenance = [ordered]@{
        schema_version       = 3
        source_commit        = $SourceCommit
        tracked_source_dirty = $false
        source_snapshot      = [ordered]@{
            schema_version = 1
            file_count     = $SourceInventoryFileCount
            sha256         = $SourceInventorySha256
        }
        builder_identity     = [ordered]@{
            schema_version      = 1
            kind                = [string]$BuilderIdentity.Kind
            name                = [string]$BuilderIdentity.Name
            repository          = [string]$BuilderIdentity.Repository
            pull_request_number = [int]$BuilderIdentity.PullRequestNumber
            source_branch       = [string]$BuilderIdentity.SourceBranch
            source_commit       = [string]$BuilderIdentity.SourceCommit
            collision_suffix    = [string]$BuilderIdentity.CollisionSuffix
            release_version     = [string]$BuilderIdentity.ReleaseVersion
            workflow_run_id     = [long]$BuilderIdentity.WorkflowRunId
        }
        vmx                  = [ordered]@{
            name   = $vmx.Name
            bytes  = $vmx.Length
            sha256 = (Get-FileHash -LiteralPath $vmx.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        payload_disks        = @($payloadLayout | ForEach-Object {
                [ordered]@{
                    role           = $_.Role
                    scsi_unit      = $_.ScsiUnit
                    name           = $_.File.Name
                    capacity_bytes = $_.CapacityBytes
                    bytes          = $_.File.Length
                    sha256         = (Get-FileHash -LiteralPath $_.File.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                }
            })
    }
    $provenancePath = [System.IO.Path]::ChangeExtension($vmx.FullName, 'provenance.json')
    $json = $provenance | ConvertTo-Json -Depth 5
    [System.IO.File]::WriteAllText($provenancePath, "$json`n", [System.Text.UTF8Encoding]::new($false))
    $null = Assert-AtlasoVmwarePayloadProvenance -VmxPath $vmx.FullName -ProvenancePath $provenancePath
    Write-Host "VMware build provenance: $provenancePath ($($provenance.source_commit), source snapshot $($provenance.source_snapshot.sha256))"
}

<#
.SYNOPSIS
Return the validated VMware management-network build plan.
.PARAMETER NetworkName
Management vmnet name.
.PARAMETER ServiceNetworkName
Services vmnet name.
.PARAMETER ResolvedVmrunPath
Resolved vmrun executable.
.PARAMETER BridgedInterfaceAlias
Optional host adapter for bridged management.
#>
function Get-WorkstationManagementNetwork {
    param(
        [string]$NetworkName,
        [string]$ServiceNetworkName,
        [string]$ResolvedVmrunPath,
        [string]$BridgedInterfaceAlias
    )

    $networkArgs = @{
        VmrunPath         = $ResolvedVmrunPath
        ManagementNetwork = $NetworkName
        BridgedInterfaceAlias = $BridgedInterfaceAlias
        ManagementOnly    = $true
        PlanOnly          = $true
    }
    if ([string]::IsNullOrWhiteSpace($ResolvedVmrunPath)) {
        $networkArgs.Remove('VmrunPath')
    }
    if ([string]::IsNullOrWhiteSpace($BridgedInterfaceAlias)) {
        $networkArgs.Remove('BridgedInterfaceAlias')
    }

    $planText = (& (Join-Path $PSScriptRoot 'prepare-networks.ps1') @networkArgs | Out-String).Trim()
    if (-not $?) {
        throw 'VMware Workstation network discovery failed.'
    }
    $plan = $planText | ConvertFrom-Json
    if ($plan.missing_networks.Count -gt 0) {
        throw "Missing VMware Workstation networks: $($plan.missing_networks -join ', '). Create them in Virtual Network Editor, then rerun this script."
    }

    $name = $NetworkName.ToLowerInvariant()
    $management = $plan.discovered_networks | Where-Object { $_.Name -eq $name } | Select-Object -First 1
    if (-not $management) {
        throw "Management VMware network was not found: $NetworkName"
    }
    if ([string]::IsNullOrWhiteSpace($management.Subnet) -or [string]::IsNullOrWhiteSpace($management.Mask)) {
        throw "Management VMware network $NetworkName did not report an IPv4 subnet and mask."
    }
    if ([string]$management.Type -ieq 'bridged') {
        if (-not $management.PSObject.Properties['InterfaceAlias'] -or
            [string]::IsNullOrWhiteSpace([string]$management.InterfaceAlias)) {
            throw 'Bridged VMware network discovery did not identify the selected host interface.'
        }
        try {
            $hostConfigurations = @(Get-NetIPConfiguration `
                    -InterfaceAlias ([string]$management.InterfaceAlias) `
                    -ErrorAction Stop)
            $hostAddresses = @($hostConfigurations.IPv4Address | ForEach-Object {
                    [string]$_.IPAddress
                } | Where-Object {
                    -not [string]::IsNullOrWhiteSpace($_)
                } | Select-Object -Unique)
        }
        catch {
            throw "Could not inspect the selected bridged host interface '$($management.InterfaceAlias)' for address exclusion."
        }
        if ($hostAddresses.Count -eq 0) {
            throw "The selected bridged host interface '$($management.InterfaceAlias)' has no IPv4 address to exclude."
        }
        $management | Add-Member `
            -NotePropertyName HostAddresses `
            -NotePropertyValue $hostAddresses `
            -Force
    }

    if (-not [string]::IsNullOrWhiteSpace($ServiceNetworkName)) {
        $serviceName = $ServiceNetworkName.ToLowerInvariant()
        $service = $plan.discovered_networks | Where-Object { $_.Name -eq $serviceName } | Select-Object -First 1
        if (-not $service) {
            throw "Services VMware network was not found: $ServiceNetworkName. Create it in Virtual Network Editor, pass -ServiceVmnetName, or pass -SkipNetworkCheck."
        }
    }
    return $management
}

if ([string]::IsNullOrWhiteSpace($PackerDirectory)) {
    $PackerDirectory = Join-Path $PSScriptRoot '..\..\..\image\vmware-workstation'
}
$workstationOutputDirectory = Resolve-WorkstationOutputDirectory `
    -PackerDirectory $PackerDirectory `
    -OutputDirectory $OutputDirectory `
    -VmName $VmName
$workstationOutputDirectory = Assert-AtlasoVmwareBuilderOutputDirectory `
    -OutputDirectory $workstationOutputDirectory `
    -Identity $builderIdentity
$builderIdentityManifestPath = Get-AtlasoVmwareBuilderIdentityManifestPath `
    -OutputDirectory $workstationOutputDirectory
$builderOutputExists = Test-Path -LiteralPath $workstationOutputDirectory
$builderManifestExists = Test-Path -LiteralPath $builderIdentityManifestPath -PathType Leaf
if ($builderOutputExists -and -not $builderManifestExists) {
    throw "Refusing to reuse or clean a Photon builder output without its exact ownership manifest: $workstationOutputDirectory"
}
if ($builderManifestExists) {
    $null = Assert-AtlasoVmwareBuilderOwnershipManifest `
        -Path $builderIdentityManifestPath `
        -OutputDirectory $workstationOutputDirectory `
        -Identity $builderIdentity
}
$existingBuilderVmx = Join-Path $workstationOutputDirectory "$VmName.vmx"
if (Test-Path -LiteralPath $existingBuilderVmx -PathType Leaf) {
    $null = Assert-AtlasoVmwareBuilderVmx `
        -VmxPath $existingBuilderVmx `
        -OutputDirectory $workstationOutputDirectory `
        -Identity $builderIdentity
}

$VmnetName = ConvertTo-WorkstationVmnetName -Name $VmnetName -ParameterName 'VmnetName'
$ServiceVmnetName = ConvertTo-WorkstationVmnetName -Name $ServiceVmnetName -ParameterName 'ServiceVmnetName'

$builderIpWasPassed = $PSBoundParameters.ContainsKey('BuilderStaticIp')
$builderNetmaskWasPassed = $PSBoundParameters.ContainsKey('BuilderStaticNetmask')
$builderGatewayWasPassed = $PSBoundParameters.ContainsKey('BuilderStaticGateway')
$builderDnsWasPassed = $PSBoundParameters.ContainsKey('BuilderStaticDns') -or $BuilderStaticDnsBound
$finalAddressWasPassed = $PSBoundParameters.ContainsKey('FinalMgmtAddress')
$finalGatewayWasPassed = $PSBoundParameters.ContainsKey('FinalMgmtGateway')
$management = $null
$managementGateway = ''
$requiresBuilderReservation = -not $ValidateOnly -and -not $PrepareIsoOnly

if (-not $SkipNetworkCheck) {
    $management = Get-WorkstationManagementNetwork -NetworkName $VmnetName -ServiceNetworkName $ServiceVmnetName -ResolvedVmrunPath $VmrunPath -BridgedInterfaceAlias $BridgedInterfaceAlias
    $managementGateway = if ($management.PSObject.Properties['Gateway'] -and -not [string]::IsNullOrWhiteSpace($management.Gateway)) {
        $management.Gateway
    } else {
        Get-Ipv4AddressFromSubnetOffset -Subnet $management.Subnet -Netmask $management.Mask -HostOffset 2
    }
    if (-not $builderNetmaskWasPassed) {
        $BuilderStaticNetmask = $management.Mask
    }
    if (-not $builderIpWasPassed) {
        $BuilderStaticIp = Get-Ipv4CidrFromSubnetOffset -Subnet $management.Subnet -Netmask $management.Mask -HostOffset 30
    }
    if (-not $builderGatewayWasPassed) {
        $BuilderStaticGateway = $managementGateway
    }
    if (-not $builderDnsWasPassed -and $BuilderStaticDns.Count -eq 0 -and $management.Type -eq 'nat') {
        $BuilderStaticDns = @($managementGateway)
        Write-Host "Using VMware NAT gateway DNS for Photon builder: $($BuilderStaticDns -join ', ')."
    }
    if (-not $finalAddressWasPassed) {
        $FinalMgmtAddress = 'dhcp'
    }
    if (-not $finalGatewayWasPassed -and $FinalMgmtAddress -ne 'dhcp') {
        $FinalMgmtGateway = $managementGateway
    }
    Write-Host "Using VMware management network $($management.Name) on $($management.Subnet)/$($management.Mask)."
    Write-Host "Using VMware services network $ServiceVmnetName for the second appliance NIC."
    Write-Host "Photon builder temporary SSH address: $BuilderStaticIp; final appliance management address: $FinalMgmtAddress."
}
elseif ($requiresBuilderReservation) {
    if ([string]::IsNullOrWhiteSpace($BuilderStaticIp)) {
        throw 'BuilderStaticIp must not be empty for a VMware Photon image build.'
    }
    # SkipNetworkCheck suppresses topology preparation, not allocator safety.
    # Read-only discovery is still required to establish exact DHCP exclusions.
    $management = Get-WorkstationManagementNetwork `
        -NetworkName $VmnetName `
        -ServiceNetworkName '' `
        -ResolvedVmrunPath $VmrunPath `
        -BridgedInterfaceAlias $BridgedInterfaceAlias
    $managementGateway = if ($management.PSObject.Properties['Gateway'] -and
        -not [string]::IsNullOrWhiteSpace($management.Gateway)) {
        $management.Gateway
    }
    else {
        Get-Ipv4AddressFromSubnetOffset -Subnet $management.Subnet -Netmask $management.Mask -HostOffset 2
    }
    if (-not $builderNetmaskWasPassed) {
        $BuilderStaticNetmask = $management.Mask
    }
    if (-not $builderIpWasPassed) {
        $BuilderStaticIp = Get-Ipv4CidrFromSubnetOffset `
            -Subnet $management.Subnet `
            -Netmask $management.Mask `
            -HostOffset 30
    }
    if (-not $builderGatewayWasPassed) {
        $BuilderStaticGateway = $managementGateway
    }
    if (-not $builderDnsWasPassed -and $BuilderStaticDns.Count -eq 0 -and $management.Type -eq 'nat') {
        $BuilderStaticDns = @($managementGateway)
        Write-Host "Using VMware NAT gateway DNS for Photon builder: $($BuilderStaticDns -join ', ')."
    }
    if (-not $finalAddressWasPassed) {
        $FinalMgmtAddress = 'dhcp'
    }
    if (-not $finalGatewayWasPassed -and $FinalMgmtAddress -ne 'dhcp') {
        $FinalMgmtGateway = $managementGateway
    }
    Write-Host "Discovered VMware management network $($management.Name) for safe builder-address admission."
}

if ($requiresBuilderReservation) {
    if ([string]::IsNullOrWhiteSpace($BuilderStaticIp)) {
        throw 'BuilderStaticIp must not be empty for a VMware Photon image build.'
    }
    $resolvedReservationVmrun = Resolve-WorkstationVmrunPath -Path $VmrunPath
    $builderParts = @($BuilderStaticIp -split '/', 2)
    if ($builderParts.Count -ne 2 -or $builderParts[1] -notmatch '^\d{1,2}$') {
        throw "BuilderStaticIp must be a canonical IPv4 CIDR; got '$BuilderStaticIp'."
    }
    $builderPrefix = [int]$builderParts[1]
    if ($builderPrefix -ne (Get-Ipv4PrefixLength -Netmask $BuilderStaticNetmask)) {
        throw 'BuilderStaticIp prefix and BuilderStaticNetmask do not describe the same network.'
    }
    $reservationSubnet = if ($null -ne $management) {
        [string]$management.Subnet
    }
    else {
        $builderValue = ConvertTo-Ipv4Integer -Address $builderParts[0]
        $maskValue = ConvertTo-Ipv4Integer -Address $BuilderStaticNetmask
        ConvertFrom-Ipv4Integer -Address ($builderValue -band $maskValue)
    }
    $reservationDhcpEnabled = $null -ne $management -and [string]$management.Dhcp -ieq 'true'
    $managementHostAddresses = if ($null -ne $management -and
        $management.PSObject.Properties['HostAddresses']) {
        @($management.HostAddresses)
    }
    else {
        @()
    }
    $preferredBuilderAddress = if ($builderIpWasPassed) { $builderParts[0] } else { '' }
    # Network discovery can outlive every earlier identity proof. Refresh task
    # or release state before reservation data is durably admitted.
    $null = Assert-AtlasoBuilderIdentityCurrent `
        -RepositoryRoot $identityRepositoryRoot `
        -ExpectedIdentity $builderIdentity `
        -PullRequestNumber $PullRequestNumber `
        -CollisionSuffix $CollisionSuffix `
        -ReleaseBuilder:$ReleaseBuilder `
        -ReleaseVersion $ReleaseVersion `
        -ReleaseSourceCommit $ReleaseSourceCommit `
        -ReleaseWorkflowRunId $ReleaseWorkflowRunId
    $builderReservation = Enter-AtlasoVmwareBuilderAddressReservation `
        -NetworkName $VmnetName `
        -Subnet $reservationSubnet `
        -Netmask $BuilderStaticNetmask `
        -DhcpEnabled:$reservationDhcpEnabled `
        -PreferredAddress $preferredBuilderAddress `
        -PoolStartOffset $BuilderAddressPoolStartOffset `
        -PoolEndOffset $BuilderAddressPoolEndOffset `
        -AdditionalExcludedAddresses (@($BuilderStaticGateway) + $managementHostAddresses) `
        -DhcpConfigPath $VmwareDhcpConfigPath `
        -ReservationHandoffPath $resolvedBuilderAddressReservationPath `
        -VmrunPath $resolvedReservationVmrun `
        -OutputDirectory $workstationOutputDirectory `
        -VmName $VmName `
        -RepositoryRoot $TaskRepositoryRoot `
        -SourceCommit $SourceCommit `
        -SourceBranch $SourceBranch
    $BuilderStaticIp = $builderReservation.Cidr
    if (-not (Test-Path -LiteralPath $resolvedBuilderAddressReservationPath -PathType Leaf)) {
        throw 'The VMware builder-address reservation was not paired with its durable release handoff.'
    }
    Write-Host "Reserved Photon builder temporary SSH address $BuilderStaticIp for this exact build."
}

if (-not $ValidateOnly -and -not $PrepareIsoOnly -and -not $SkipNetworkCheck) {
    $builderAddress = if ($BuilderStaticIp) { ($BuilderStaticIp -split '/', 2)[0] } else { '' }
    $managementSubnet = if ($builderAddress -match '^(\d+)\.(\d+)\.(\d+)\.') { "$($Matches[1]).$($Matches[2]).$($Matches[3]).0" } else { '192.168.49.0' }
    $networkArgs = @{
        VmrunPath          = $VmrunPath
        ManagementNetwork = $VmnetName
        ManagementSubnet  = $managementSubnet
        BridgedInterfaceAlias = $BridgedInterfaceAlias
        ManagementOnly    = $true
    }
    if ([string]::IsNullOrWhiteSpace($VmrunPath)) {
        $networkArgs.Remove('VmrunPath')
    }
    if ([string]::IsNullOrWhiteSpace($BridgedInterfaceAlias)) {
        $networkArgs.Remove('BridgedInterfaceAlias')
    }
    if ($AllowExistingManagementSubnet) {
        $networkArgs['AllowExistingManagementSubnet'] = $true
    }
    & (Join-Path $PSScriptRoot 'prepare-networks.ps1') @networkArgs | Out-Host
    if (-not $?) {
        throw 'VMware Workstation network validation failed.'
    }
}

$packerVariables = @{
    vmnet_name         = $VmnetName
    service_vmnet_name = $ServiceVmnetName
    headless           = [bool]$Headless
    source_root        = $SourceSnapshotRoot
}

$packerBuildInvoker = $null
$builderOutputClaim = $null
try {
if (-not $ValidateOnly -and -not $PrepareIsoOnly) {
    $resolvedVmrunPath = Resolve-WorkstationVmrunPath -Path $VmrunPath
    # Network preparation can outlive the prior proof, so refresh task or
    # release identity immediately before manifest and output mutation.
    $null = Assert-AtlasoBuilderIdentityCurrent `
        -RepositoryRoot $identityRepositoryRoot `
        -ExpectedIdentity $builderIdentity `
        -PullRequestNumber $PullRequestNumber `
        -CollisionSuffix $CollisionSuffix `
        -ReleaseBuilder:$ReleaseBuilder `
        -ReleaseVersion $ReleaseVersion `
        -ReleaseSourceCommit $ReleaseSourceCommit `
        -ReleaseWorkflowRunId $ReleaseWorkflowRunId
    # Hold an OS-enforced exclusive file handle from ownership admission through
    # cleanup, Packer, and provenance so parallel builds cannot both pass a
    # point-in-time absence check and adopt the same canonical output.
    $builderOutputClaim = Enter-AtlasoVmwareBuilderOutputClaim `
        -OutputDirectory $workstationOutputDirectory `
        -Identity $builderIdentity `
        -ClaimGeneration $OutputClaimGeneration
    if (-not $builderManifestExists) {
        $outputAppearedBeforeOwnershipClaim = Test-Path -LiteralPath $workstationOutputDirectory
        $manifestAppearedBeforeOwnershipClaim = Test-Path `
            -LiteralPath $builderIdentityManifestPath `
            -PathType Leaf
        if ($outputAppearedBeforeOwnershipClaim -or $manifestAppearedBeforeOwnershipClaim) {
            throw 'The Photon builder output or manifest appeared after initial ownership validation; refusing to claim or clean concurrent artifacts.'
        }
        Write-AtlasoVmwareBuilderIdentityManifest `
            -Path $builderIdentityManifestPath `
            -OutputDirectory $workstationOutputDirectory `
            -Identity $builderIdentity
        $builderManifestExists = $true
    }
    if (-not $KeepExistingOutput -or -not $builderOutputExists) {
        $null = Assert-AtlasoVmwareBuilderOwnershipManifest `
            -Path $builderIdentityManifestPath `
            -OutputDirectory $workstationOutputDirectory `
            -Identity $builderIdentity
        # Claim a pre-existing output only after all network preparation has
        # completed and immediately before checked removal begins. The bounded
        # parent may finish that exact removal after proven child termination.
        Write-AtlasoDurableJsonFile -Path $resolvedOutputCleanupClaimPath -Payload ([ordered]@{
            Schema          = 2
            OutputPath      = $workstationOutputDirectory
            ClaimGeneration = $OutputClaimGeneration
        })
        Remove-AtlasoWorkstationArtifactRoot `
            -VmrunPath $resolvedVmrunPath `
            -ExpectedRemovalRoot $workstationOutputDirectory `
            -RemovalRoot $workstationOutputDirectory `
            -Confirm:$false
        Write-AtlasoVmwareBuilderIdentityManifest `
            -Path $builderIdentityManifestPath `
            -OutputDirectory $workstationOutputDirectory `
            -Identity $builderIdentity `
            -ReplaceSameOwner
        $null = Assert-AtlasoVmwareBuilderIdentityManifest `
            -Path $builderIdentityManifestPath `
            -OutputDirectory $workstationOutputDirectory `
            -Identity $builderIdentity
    }
    else {
        $null = Assert-AtlasoVmwareBuilderIdentityManifest `
            -Path $builderIdentityManifestPath `
            -OutputDirectory $workstationOutputDirectory `
            -Identity $builderIdentity
    }
    $builderAddress = if (-not [string]::IsNullOrWhiteSpace($SshHost)) {
        $SshHost
    }
    elseif ($BuilderStaticIp) {
        ($BuilderStaticIp -split '/', 2)[0]
    }
    else {
        ''
    }
    if ([string]::IsNullOrWhiteSpace($builderAddress)) {
        throw 'A configured builder address is required for bounded VMware startup monitoring.'
    }
    $builderVmxPath = Join-Path $workstationOutputDirectory "$VmName.vmx"
    $packerBuildInvoker = {
        param($PackerArguments, $WorkingDirectory)

        # ISO preparation and Packer initialization can be lengthy, so prove the
        # GUI provider is responsive at the last safe point before Packer starts.
        if (-not $Headless) {
            $requireExistingUi = {
                param($FilePath)
                throw 'The parent-launched VMware Workstation UI is no longer available.'
            }.GetNewClosure()
            $null = Initialize-AtlasoWorkstationGui `
                -VmrunPath $resolvedVmrunPath `
                -ProcessLauncher $requireExistingUi
        }
        $packerPath = (Get-Command packer -ErrorAction Stop).Source
        # ISO preparation and Packer initialization happen outside this
        # callback, so refresh identity at the final provider boundary.
        $null = Assert-AtlasoBuilderIdentityCurrent `
            -RepositoryRoot $identityRepositoryRoot `
            -ExpectedIdentity $builderIdentity `
            -PullRequestNumber $PullRequestNumber `
            -CollisionSuffix $CollisionSuffix `
            -ReleaseBuilder:$ReleaseBuilder `
            -ReleaseVersion $ReleaseVersion `
            -ReleaseSourceCommit $ReleaseSourceCommit `
            -ReleaseWorkflowRunId $ReleaseWorkflowRunId
        Invoke-AtlasoMonitoredPackerBuild `
            -PackerPath $packerPath `
            -Arguments $PackerArguments `
            -WorkingDirectory $WorkingDirectory `
            -VmrunPath $resolvedVmrunPath `
            -VmxPath $builderVmxPath `
            -BuilderAddress $builderAddress `
            -StartupTimeoutSeconds $PackerStartupTimeoutSeconds `
            -HeartbeatSeconds $PackerHeartbeatSeconds `
            -PackerOnError $PackerOnError
    }.GetNewClosure()
}

if (-not $ValidateOnly -and -not $PrepareIsoOnly) {
    $null = Assert-AtlasoBuilderIdentityCurrent `
        -RepositoryRoot $identityRepositoryRoot `
        -ExpectedIdentity $builderIdentity `
        -PullRequestNumber $PullRequestNumber `
        -CollisionSuffix $CollisionSuffix `
        -ReleaseBuilder:$ReleaseBuilder `
        -ReleaseVersion $ReleaseVersion `
        -ReleaseSourceCommit $ReleaseSourceCommit `
        -ReleaseWorkflowRunId $ReleaseWorkflowRunId
}

Invoke-AtlasoPhotonImageBuild `
    -IsoUrl $IsoUrl `
    -IsoChecksum $IsoChecksum `
    -PackerDirectory $PackerDirectory `
    -PackerTemplatePath $packerTemplatePath `
    -SshPassword $SshPassword `
    -BootstrapAdminPassword $BootstrapAdminPassword `
    -VmName $VmName `
    -OutputDirectory $workstationOutputDirectory `
    -SshHost $SshHost `
    -SharedSourceDirectory $SharedSourceDirectory `
    -BuilderStaticIp $BuilderStaticIp `
    -BuilderStaticNetmask $BuilderStaticNetmask `
    -BuilderStaticGateway $BuilderStaticGateway `
    -BuilderStaticDns $BuilderStaticDns `
    -FinalMgmtAddress $FinalMgmtAddress `
    -FinalMgmtGateway $FinalMgmtGateway `
    -FinalMgmtInterface $FinalMgmtInterface `
    -PipGlobalIndex $PipGlobalIndex `
    -PipGlobalIndexUrl $PipGlobalIndexUrl `
    -PreparedIsoPath $PreparedIsoPath `
    -SensitiveBuildDirectory $SensitiveBuildDirectory `
    -PackerOnError $PackerOnError `
    -GuestPackages @('open-vm-tools', 'hyper-v') `
    -GuestPostInstallCommands @(
        'systemctl enable vmtoolsd || true',
        'systemctl enable hv_kvp_daemon || true',
        'systemctl enable hv_fcopy_daemon || true',
        'systemctl enable hv_vss_daemon || true'
    ) `
    -InstallDiskLayout 'vmware-workstation' `
    -AdditionalPackerVariables $packerVariables `
    -PackerBuildInvoker $packerBuildInvoker `
    -KeepExistingOutput:$KeepExistingOutput `
    -EnableRealSystemAdapters:$EnableRealSystemAdapters `
    -ValidateOnly:$ValidateOnly `
    -PrepareIsoOnly:$PrepareIsoOnly

if (-not $ValidateOnly -and -not $PrepareIsoOnly) {
    # A Packer build can outlive every pre-launch ownership proof. Refresh the
    # task or release identity before the completed artifact gains provenance.
    $null = Assert-AtlasoBuilderIdentityCurrent `
        -RepositoryRoot $identityRepositoryRoot `
        -ExpectedIdentity $builderIdentity `
        -PullRequestNumber $PullRequestNumber `
        -CollisionSuffix $CollisionSuffix `
        -ReleaseBuilder:$ReleaseBuilder `
        -ReleaseVersion $ReleaseVersion `
        -ReleaseSourceCommit $ReleaseSourceCommit `
        -ReleaseWorkflowRunId $ReleaseWorkflowRunId
}

if (-not $ValidateOnly -and -not $PrepareIsoOnly) {
    $null = Assert-AtlasoVmwareBuilderIdentityManifest `
        -Path $builderIdentityManifestPath `
        -OutputDirectory $workstationOutputDirectory `
        -Identity $builderIdentity
    Write-AtlasoVmwareBuildProvenance `
        -OutputDirectory $workstationOutputDirectory `
        -VmName $VmName `
        -RepoRoot $repoRoot `
        -SourceCommit $SourceCommit `
        -SourceSnapshotRoot $SourceSnapshotRoot `
        -SourceInventorySha256 $SourceInventorySha256 `
        -SourceInventoryFileCount $SourceInventoryFileCount `
        -BuilderIdentity $builderIdentity
}
}
finally {
    if ($null -ne $builderOutputClaim) {
        $builderOutputClaim.Dispose()
    }
}
