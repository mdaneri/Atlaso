<#
.SYNOPSIS
Orchestrates manual Atlaso virtualization prereleases and stable promotions.

.DESCRIPTION
Keeps local and self-hosted Windows systems outside the signing boundary. The
workstation creates and smokes candidate bytes; protected GitHub-hosted jobs
sign and publish them.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
Runs GitHub CLI and rejects a failed invocation.
.PARAMETER Arguments
Arguments passed to GitHub CLI.
#>
function Invoke-AtlasoReleaseGh {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    $gh = Get-Command gh -CommandType Application -ErrorAction Stop
    $output = @(& $gh.Source @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "GitHub CLI failed: $($output -join [Environment]::NewLine)"
    }
    return ,$output
}

<#
.SYNOPSIS
Returns the current repository name-with-owner.
.PARAMETER RepoRoot
Exact Atlaso checkout root.
#>
function Get-AtlasoReleaseRepository {
    param([Parameter(Mandatory = $true)][string]$RepoRoot)

    $value = [string](Invoke-AtlasoReleaseGh -Arguments @(
        'repo', 'view', '--json', 'nameWithOwner', '--jq', '.nameWithOwner'
    ))
    $value = $value.Trim()
    if ($value -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') {
        throw 'GitHub CLI returned an invalid repository identity.'
    }
    return $value
}

<#
.SYNOPSIS
Validates and creates one invocation-owned staging directory.
.PARAMETER StagingRoot
Absolute fixed-volume staging root selected by the operator.
.PARAMETER Tag
Virtualization prerelease tag used as the invocation leaf.
#>
function Resolve-AtlasoVirtualizationStagingDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$StagingRoot,
        [Parameter(Mandatory = $true)][string]$Tag
    )

    if (-not [System.IO.Path]::IsPathFullyQualified($StagingRoot)) {
        throw 'StagingRoot must be an absolute filesystem path.'
    }
    $root = [System.IO.Path]::GetFullPath($StagingRoot)
    $filesystemRoot = [System.IO.Path]::GetPathRoot($root)
    if ($root.TrimEnd('\', '/') -eq $filesystemRoot.TrimEnd('\', '/')) {
        throw 'StagingRoot cannot be a filesystem root.'
    }
    if (-not (Test-Path -LiteralPath $root)) {
        New-Item -ItemType Directory -Path $root | Out-Null
    }
    $rootItem = Get-Item -LiteralPath $root -Force
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'StagingRoot must be an ordinary directory, not a reparse point.'
    }
    $operation = Join-Path $root $Tag
    if (-not (Test-Path -LiteralPath $operation)) {
        New-Item -ItemType Directory -Path $operation | Out-Null
    }
    $operationItem = Get-Item -LiteralPath $operation -Force
    if (-not $operationItem.PSIsContainer -or
        ($operationItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'The release staging directory must be an ordinary directory.'
    }
    return $operationItem.FullName
}

<#
.SYNOPSIS
Copies one local release asset without replacing different bytes.
.PARAMETER Source
Existing ordinary source file.
.PARAMETER Destination
Exact local staging destination.
#>
function Copy-AtlasoVirtualizationExactAsset {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    $sourceItem = Get-Item -LiteralPath $Source -Force -ErrorAction Stop
    if ($sourceItem.PSIsContainer -or
        ($sourceItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'A virtualization release source must be an ordinary file.'
    }
    if (Test-Path -LiteralPath $Destination) {
        $destinationItem = Get-Item -LiteralPath $Destination -Force
        if ($destinationItem.PSIsContainer -or
            ($destinationItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            (Get-FileHash -LiteralPath $sourceItem.FullName -Algorithm SHA256).Hash -ne
            (Get-FileHash -LiteralPath $destinationItem.FullName -Algorithm SHA256).Hash) {
            throw "Local release staging contains different bytes: $Destination"
        }
        return
    }
    Copy-Item -LiteralPath $sourceItem.FullName -Destination $Destination
    if ((Get-FileHash -LiteralPath $sourceItem.FullName -Algorithm SHA256).Hash -ne
        (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash) {
        throw "Local release staging copy verification failed: $Destination"
    }
}

<#
.SYNOPSIS
Proves that HEAD is an exact successful-main software Release.
.PARAMETER RepoRoot
Exact Atlaso checkout root.
.PARAMETER Repository
GitHub name-with-owner.
#>
function Get-AtlasoVirtualizationSourceIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$Repository
    )

    $dirty = @(& git -C $RepoRoot status --porcelain)
    if ($LASTEXITCODE -ne 0 -or $dirty.Count -ne 0) {
        throw 'Virtualization publication requires a completely clean checkout.'
    }
    $commit = [string](& git -C $RepoRoot rev-parse HEAD)
    $commit = $commit.Trim()
    if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') {
        throw 'Could not resolve the exact source commit.'
    }
    & git -C $RepoRoot fetch origin main --no-tags
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not refresh protected main.'
    }
    & git -C $RepoRoot merge-base --is-ancestor $commit origin/main
    if ($LASTEXITCODE -ne 0) {
        throw 'The source commit is no longer reachable from origin/main.'
    }
    $version = [string](& python (Join-Path $RepoRoot 'scripts\version.py') get --root $RepoRoot)
    $version = $version.Trim()
    if ($LASTEXITCODE -ne 0 -or $version -notmatch '^\d+\.\d+\.\d+$') {
        throw 'Could not resolve the synchronized Atlaso version.'
    }
    $softwareTag = "v$version"
    $tagCommit = [string](Invoke-AtlasoReleaseGh -Arguments @(
        'api', "repos/$Repository/commits/$softwareTag", '--jq', '.sha'
    ))
    if ($tagCommit.Trim() -ne $commit) {
        throw "Automatic software Release $softwareTag does not identify the exact checkout."
    }
    $releaseJson = (Invoke-AtlasoReleaseGh -Arguments @(
        'release', 'view', $softwareTag, '--repo', $Repository,
        '--json', 'tagName,isDraft,isPrerelease,assets'
    )) -join [Environment]::NewLine
    $release = $releaseJson | ConvertFrom-Json
    if ($release.tagName -ne $softwareTag -or $release.isDraft -or $release.isPrerelease) {
        throw "Automatic software Release $softwareTag is missing or misclassified."
    }
    $assetNames = @($release.assets | ForEach-Object { [string]$_.name })
    foreach ($required in @(
        "atlaso-appliance-$version.tar.gz",
        'release-manifest.json',
        'release-manifest.json.sig'
    )) {
        if ($required -notin $assetNames) {
            throw "Automatic software Release $softwareTag is missing $required."
        }
    }
    $countText = [string](Invoke-AtlasoReleaseGh -Arguments @(
        'api', '--method', 'GET', "repos/$Repository/actions/workflows/ci.yml/runs",
        '-f', "head_sha=$commit", '-f', 'branch=main', '-f', 'event=push',
        '-f', 'status=success', '-f', 'per_page=100', '--jq', '.total_count'
    ))
    $successfulRuns = 0
    if (-not [int]::TryParse($countText.Trim(), [ref]$successfulRuns) -or $successfulRuns -lt 1) {
        throw "$commit has no successful main push CI run."
    }
    return [pscustomobject]@{
        Commit = $commit
        Version = $version
        SoftwareTag = $softwareTag
    }
}

<#
.SYNOPSIS
Uploads a complete draft asset set without replacing different bytes.
.PARAMETER Repository
GitHub name-with-owner.
.PARAMETER Tag
Draft virtualization prerelease tag.
.PARAMETER AssetDirectory
Flat directory containing exact candidate assets.
#>
function Publish-AtlasoVirtualizationDraftAssets {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$Tag,
        [Parameter(Mandatory = $true)][string]$AssetDirectory
    )

    $metadataJson = (Invoke-AtlasoReleaseGh -Arguments @(
        'release', 'view', $Tag, '--repo', $Repository,
        '--json', 'tagName,isDraft,isPrerelease,assets'
    )) -join [Environment]::NewLine
    $metadata = $metadataJson | ConvertFrom-Json
    if ($metadata.tagName -ne $Tag -or -not $metadata.isDraft -or -not $metadata.isPrerelease) {
        throw "Virtualization prerelease $Tag must remain a draft until hosted finalization."
    }
    $existing = @{}
    foreach ($asset in @($metadata.assets)) {
        $existing[[string]$asset.name] = $true
    }
    $candidateAssets = @(Get-ChildItem -LiteralPath $AssetDirectory -File | Sort-Object Name)
    $allowedNames = @{} 
    foreach ($asset in $candidateAssets) {
        $allowedNames[$asset.Name] = $true
    }
    $allowedNames['virtualization-artifact-index.json'] = $true
    $allowedNames['virtualization-artifact-index.json.sig'] = $true
    $unexpected = @($existing.Keys | Where-Object { -not $allowedNames.ContainsKey($_) } | Sort-Object)
    if ($unexpected.Count -ne 0) {
        throw "Draft $Tag contains unexpected assets: $($unexpected -join ', ')."
    }
    foreach ($asset in $candidateAssets) {
        if ($existing.ContainsKey($asset.Name)) {
            $verification = Join-Path ([System.IO.Path]::GetTempPath()) (
                "atlaso-virtualization-asset-$([guid]::NewGuid().ToString('N'))"
            )
            New-Item -ItemType Directory -Path $verification | Out-Null
            try {
                Invoke-AtlasoReleaseGh -Arguments @(
                    'release', 'download', $Tag, '--repo', $Repository,
                    '--pattern', $asset.Name, '--dir', $verification
                ) | Out-Null
                $published = Join-Path $verification $asset.Name
                if ((Get-FileHash -LiteralPath $published -Algorithm SHA256).Hash -ne
                    (Get-FileHash -LiteralPath $asset.FullName -Algorithm SHA256).Hash) {
                    throw "Draft $Tag already contains different bytes for $($asset.Name)."
                }
            }
            finally {
                Remove-Item -LiteralPath $verification -Recurse -Force -ErrorAction SilentlyContinue
            }
            continue
        }
        Invoke-AtlasoReleaseGh -Arguments @(
            'release', 'upload', $Tag, $asset.FullName, '--repo', $Repository
        ) | Out-Null
    }
}

<#
.SYNOPSIS
Creates, smokes, and stages one local virtualization prerelease.
.PARAMETER RepoRoot
Exact Atlaso checkout root.
.PARAMETER PrereleaseIdentifier
Explicit rc.N identifier.
.PARAMETER StagingRoot
Absolute fixed-volume staging root.
.PARAMETER ManagementVmnet
VMware management vmnet used by smoke.
.PARAMETER ServiceVmnet
VMware services vmnet used by smoke.
.PARAMETER ManagementSwitch
Hyper-V management switch used by smoke.
.PARAMETER ServiceSwitch
Hyper-V services switch used by smoke.
.PARAMETER OnePasswordEnvironmentId
Optional exact Atlaso Environment ID for password-backed wheel deployment.
.PARAMETER OnePasswordAccount
Optional 1Password account selector.
.PARAMETER OnePasswordPython
Optional supported Python executable for the 1Password SDK.
.PARAMETER NoWait
Return after dispatch instead of waiting for hosted publication.
.PARAMETER CandidateOnly
Stop after producing and smoking the candidate set without changing GitHub.
#>
function Invoke-AtlasoVirtualizationPrerelease {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingPlainTextForPassword',
        'OnePasswordEnvironmentId',
        Justification = 'Opaque Environment identifier; the SDK child retrieves concealed values.'
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
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$PrereleaseIdentifier,
        [Parameter(Mandatory = $true)][string]$StagingRoot,
        [string]$ManagementVmnet = 'VMnet8',
        [string]$ServiceVmnet = 'VMnet1',
        [Parameter(Mandatory = $true)][string]$ManagementSwitch,
        [Parameter(Mandatory = $true)][string]$ServiceSwitch,
        [string]$OnePasswordEnvironmentId = '',
        [string]$OnePasswordAccount = '',
        [string]$OnePasswordPython = '',
        [switch]$CandidateOnly,
        [switch]$NoWait
    )

    if ($PrereleaseIdentifier -notmatch '^rc\.[1-9]\d*$') {
        throw 'PrereleaseIdentifier must be an explicit rc.N value with N greater than zero.'
    }
    if (-not $OnePasswordEnvironmentId -or -not $OnePasswordAccount -or -not $OnePasswordPython) {
        throw 'Virtualization production requires OnePasswordEnvironmentId, OnePasswordAccount, and OnePasswordPython.'
    }
    $repository = Get-AtlasoReleaseRepository -RepoRoot $RepoRoot
    $identity = Get-AtlasoVirtualizationSourceIdentity -RepoRoot $RepoRoot -Repository $repository
    $tag = "virtualization-v$($identity.Version)-$PrereleaseIdentifier"
    $operation = Resolve-AtlasoVirtualizationStagingDirectory -StagingRoot $StagingRoot -Tag $tag
    $sourceDownloads = Join-Path $operation 'software-release'
    $sourceInput = Join-Path $operation 'verified-source'
    if (-not (Test-Path -LiteralPath $sourceDownloads)) {
        New-Item -ItemType Directory -Path $sourceDownloads | Out-Null
    }
    foreach ($pattern in @(
        'release-manifest.json',
        'release-manifest.json.sig',
        "atlaso-appliance-$($identity.Version).tar.gz"
    )) {
        $path = Join-Path $sourceDownloads $pattern
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            Invoke-AtlasoReleaseGh -Arguments @(
                'release', 'download', $identity.SoftwareTag, '--repo', $repository,
                '--pattern', $pattern, '--dir', $sourceDownloads
            ) | Out-Null
        }
    }
    $sourceMetadata = Join-Path $sourceInput 'virtualization-source.json'
    if (-not (Test-Path -LiteralPath $sourceMetadata -PathType Leaf)) {
        # The preparer publishes this directory with one atomic rename only after
        # complete signature, archive, and digest validation. An interrupted run
        # therefore leaves this exact destination absent and safely resumable.
        $prepareArguments = @(
            (Join-Path $RepoRoot 'scripts\prepare_virtualization_source.py'),
            '--manifest', (Join-Path $sourceDownloads 'release-manifest.json'),
            '--signature', (Join-Path $sourceDownloads 'release-manifest.json.sig'),
            '--bundle', (Join-Path $sourceDownloads "atlaso-appliance-$($identity.Version).tar.gz"),
            '--trust-key', (Join-Path $RepoRoot 'image\common\update-trust\atlaso-release-2026-01.pem'),
            '--output', $sourceInput,
            '--expected-version', $identity.Version,
            '--expected-commit', $identity.Commit
        )
        $sourceJson = & python @prepareArguments
        if ($LASTEXITCODE -ne 0) {
            throw 'Automatic software Release verification failed.'
        }
    }
    $source = Get-Content -LiteralPath $sourceMetadata -Raw | ConvertFrom-Json
    $buildRoot = Join-Path $operation 'vmware-build'
    $vmName = "Atlaso-Photon-Builder-VMware-$($identity.Version)"
    $vmx = Join-Path $buildRoot "$vmName.vmx"
    if (-not (Test-Path -LiteralPath $vmx -PathType Leaf)) {
        $buildArguments = @(
            '-VmName', $vmName, '-OutputDirectory', $buildRoot,
            '-Headless', '-EnableRealSystemAdapters',
            '-OnePasswordEnvironmentId', $OnePasswordEnvironmentId,
            '-OnePasswordAccount', $OnePasswordAccount,
            '-OnePasswordPython', $OnePasswordPython
        )
        & (Join-Path $RepoRoot 'scripts\windows\vmware\build-photon-image.ps1') @buildArguments
        if ($LASTEXITCODE -ne 0) {
            throw 'Canonical VMware image build failed.'
        }
    }
    $wheel = Join-Path $sourceInput ([string]$source.application_wheel -replace '/', '\')
    $deployArguments = @{
        RepoRoot = $RepoRoot
        VmxPath = $vmx
        SkipBuild = $true
        WheelPath = $wheel
        RuntimeDependencyDirectory = (Join-Path $sourceInput 'wheelhouse\cp314')
        SkipInventoryLinuxSync = $true
    }
    if ($OnePasswordEnvironmentId) {
        $deployArguments.OnePasswordEnvironmentId = $OnePasswordEnvironmentId
        $deployArguments.OnePasswordAccount = $OnePasswordAccount
        $deployArguments.OnePasswordPython = $OnePasswordPython
    }
    & (Join-Path $RepoRoot 'scripts\windows\vmware\deploy-wheel.ps1') @deployArguments
    if ($LASTEXITCODE -ne 0) {
        throw 'Exact published application-wheel deployment failed.'
    }
    $name = "atlaso-v$($identity.Version)"
    & (Join-Path $RepoRoot 'scripts\windows\vmware\export-ovf.ps1') `
        -SourceVmxPath $vmx -Name $name -Force -VirtualizationSourceMetadata $sourceMetadata
    if ($LASTEXITCODE -ne 0) {
        throw 'Canonical OVA export failed.'
    }
    $ovaRoot = Join-Path $RepoRoot "image\vmware-workstation\ovf\$name"
    $ovaPath = Join-Path $RepoRoot "image\vmware-workstation\ovf\$name.ova"
    Copy-AtlasoVirtualizationExactAsset `
        -Source $ovaPath `
        -Destination (Join-Path $ovaRoot "$name.ova")
    $hypervRoot = Join-Path $RepoRoot "artifacts\virtualization\$tag"
    $expectedHypervZip = Join-Path $hypervRoot "atlaso-v$($identity.Version)-hyperv-x86_64.zip"
    if (-not (Test-Path -LiteralPath $expectedHypervZip -PathType Leaf)) {
        & (Join-Path $RepoRoot 'scripts\windows\virtualization\export-artifacts.ps1') -OvaPath $ovaPath -OutputRoot $hypervRoot
        if ($LASTEXITCODE -ne 0) {
            throw 'Exact OVA-to-Hyper-V conversion failed.'
        }
    }
    $hypervZip = @(Get-ChildItem -LiteralPath $hypervRoot -Filter '*-hyperv-x86_64.zip' -File)
    if ($hypervZip.Count -ne 1) {
        throw 'Hyper-V conversion did not produce exactly one package.'
    }
    $smokeText = 'A!a1' + [Convert]::ToBase64String(
        [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
    )
    try {
        $smokePassword = [SecureString]::new()
        foreach ($character in $smokeText.ToCharArray()) {
            $smokePassword.AppendChar($character)
        }
        $smokePassword.MakeReadOnly()
        $smokeCredential = [PSCredential]::new('admin', $smokePassword)
        $smokeRoot = Join-Path $RepoRoot "artifacts\virtualization-smoke\$tag"
        & (Join-Path $RepoRoot 'scripts\windows\virtualization\smoke-ova-vmware.ps1') -OvaPath $ovaPath -Credential $smokeCredential -ManagementVmnet $ManagementVmnet -ServiceVmnet $ServiceVmnet -OutputRoot (Join-Path $smokeRoot 'vmware')
        if ($LASTEXITCODE -ne 0) {
            throw 'VMware smoke failed.'
        }
        & (Join-Path $RepoRoot 'scripts\windows\virtualization\smoke-hyperv.ps1') -ZipPath $hypervZip[0].FullName -ManagementSwitch $ManagementSwitch -ServiceSwitch $ServiceSwitch -OutputRoot (Join-Path $smokeRoot 'hyperv')
        if ($LASTEXITCODE -ne 0) {
            throw 'Hyper-V smoke failed.'
        }
    }
    finally {
        $smokeCredential = $null
        $smokePassword = $null
        $smokeText = $null
    }
    $evidencePath = Join-Path $operation 'windows-smoke-evidence.json'
    [ordered]@{
        schema_version = 1
        kind = 'atlaso-windows-virtualization-smoke'
        version = $identity.Version
        source_commit = $identity.Commit
        ova_sha256 = (Get-FileHash -LiteralPath $ovaPath -Algorithm SHA256).Hash.ToLowerInvariant()
        hyperv_sha256 = (Get-FileHash -LiteralPath $hypervZip[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        vmware = 'success'
        hyperv = 'success'
    } | ConvertTo-Json | Set-Content -LiteralPath $evidencePath -Encoding utf8NoBOM
    $candidate = Join-Path $operation 'candidate'
    $stageArguments = @(
        (Join-Path $RepoRoot 'scripts\stage_virtualization_release.py'),
        '--ova-directory', $ovaRoot, '--hyperv-zip', $hypervZip[0].FullName,
        '--source-metadata', $sourceMetadata, '--windows-smoke-evidence', $evidencePath,
        '--output', $candidate, '--version', $identity.Version, '--commit', $identity.Commit
    )
    & python @stageArguments
    if ($LASTEXITCODE -ne 0) {
        throw 'Virtualization candidate staging failed.'
    }
    if ($CandidateOnly) {
        return $candidate
    }
    $remoteTag = @(& git -C $RepoRoot ls-remote --tags origin "refs/tags/$tag" "refs/tags/$tag^{}")
    if ($LASTEXITCODE -ne 0) {
        throw "Could not inspect remote tag $tag."
    }
    if ($remoteTag.Count -eq 0) {
        & git -C $RepoRoot -c user.name=github-actions[bot] -c user.email=41898282+github-actions[bot]@users.noreply.github.com tag -a $tag -m "Atlaso virtualization prerelease $tag" $identity.Commit
        if ($LASTEXITCODE -ne 0) {
            throw "Could not create annotated tag $tag."
        }
        & git -C $RepoRoot push origin "refs/tags/$tag"
        if ($LASTEXITCODE -ne 0) {
            throw "Could not publish annotated tag $tag."
        }
    }
    else {
        $peeled = @($remoteTag | Where-Object { $_ -match '\^\{\}$' })
        if ($peeled.Count -ne 1 -or ([string]$peeled[0] -split '\s+')[0] -ne $identity.Commit) {
            throw "Remote tag $tag is not one annotated tag for the exact source commit."
        }
    }
    $releaseExists = $true
    try {
        Invoke-AtlasoReleaseGh -Arguments @('release', 'view', $tag, '--repo', $repository, '--json', 'tagName') | Out-Null
    }
    catch {
        $releaseExists = $false
    }
    if (-not $releaseExists) {
        Invoke-AtlasoReleaseGh -Arguments @(
            'release', 'create', $tag, '--repo', $repository, '--draft', '--prerelease',
            '--verify-tag', '--title', "Atlaso Virtualization v$($identity.Version) $PrereleaseIdentifier",
            '--notes', 'Windows-produced OVA and Hyper-V candidate for protected hosted finalization.'
        ) | Out-Null
    }
    Publish-AtlasoVirtualizationDraftAssets -Repository $repository -Tag $tag -AssetDirectory $candidate
    Invoke-AtlasoReleaseGh -Arguments @(
        'workflow', 'run', 'virtualization-prerelease.yml', '--repo', $repository,
        '-f', "release_sha=$($identity.Commit)", '-f', "prerelease_tag=$tag"
    ) | Out-Null
    if (-not $NoWait) {
        $deadline = [DateTime]::UtcNow.AddHours(2)
        do {
            Start-Sleep -Seconds 15
            $state = ((Invoke-AtlasoReleaseGh -Arguments @(
                'release', 'view', $tag, '--repo', $repository, '--json', 'isDraft,isPrerelease'
            )) -join [Environment]::NewLine) | ConvertFrom-Json
            if (-not $state.isDraft -and $state.isPrerelease) {
                return $tag
            }
        } while ([DateTime]::UtcNow -lt $deadline)
        throw "Hosted finalization did not publish $tag within two hours."
    }
    return $tag
}

<#
.SYNOPSIS
Dispatches exact-byte promotion of a virtualization prerelease.
.PARAMETER RepoRoot
Exact Atlaso checkout root.
.PARAMETER FromPrerelease
Published virtualization-vX.Y.Z-rc.N tag.
.PARAMETER ProxmoxRunnerLabel
Release-specific ephemeral Proxmox runner label.
.PARAMETER KvmRunnerLabel
Release-specific ephemeral KVM runner label.
.PARAMETER NoWait
Return after dispatch instead of waiting for stable publication.
#>
function Invoke-AtlasoVirtualizationStablePromotion {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$FromPrerelease,
        [string]$ProxmoxRunnerLabel = '',
        [string]$KvmRunnerLabel = '',
        [switch]$NoWait
    )

    if ($FromPrerelease -notmatch '^virtualization-v(\d+\.\d+\.\d+)-rc\.([1-9]\d*)$') {
        throw 'FromPrerelease must be a virtualization-vX.Y.Z-rc.N tag.'
    }
    $version = $Matches[1]
    $suffix = ($FromPrerelease -replace '[^A-Za-z0-9_-]', '-').ToLowerInvariant()
    if (-not $ProxmoxRunnerLabel) {
        $ProxmoxRunnerLabel = "atlaso-proxmox-$suffix"
    }
    if (-not $KvmRunnerLabel) {
        $KvmRunnerLabel = "atlaso-kvm-$suffix"
    }
    foreach ($label in @($ProxmoxRunnerLabel, $KvmRunnerLabel)) {
        if ($label -notmatch '^[a-z0-9][a-z0-9_-]{0,62}$') {
            throw "Runner label is invalid: $label"
        }
    }
    $repository = Get-AtlasoReleaseRepository -RepoRoot $RepoRoot
    $release = ((Invoke-AtlasoReleaseGh -Arguments @(
        'release', 'view', $FromPrerelease, '--repo', $repository,
        '--json', 'isDraft,isPrerelease'
    )) -join [Environment]::NewLine) | ConvertFrom-Json
    if ($release.isDraft -or -not $release.isPrerelease) {
        throw "$FromPrerelease is not a published prerelease."
    }
    Invoke-AtlasoReleaseGh -Arguments @(
        'workflow', 'run', 'virtualization-stable.yml', '--repo', $repository,
        '-f', "prerelease_tag=$FromPrerelease",
        '-f', "proxmox_runner_label=$ProxmoxRunnerLabel",
        '-f', "kvm_runner_label=$KvmRunnerLabel"
    ) | Out-Null
    $stableTag = "virtualization-v$version"
    if (-not $NoWait) {
        $deadline = [DateTime]::UtcNow.AddHours(4)
        do {
            Start-Sleep -Seconds 20
            try {
                $stable = ((Invoke-AtlasoReleaseGh -Arguments @(
                    'release', 'view', $stableTag, '--repo', $repository,
                    '--json', 'isDraft,isPrerelease'
                )) -join [Environment]::NewLine) | ConvertFrom-Json
                if (-not $stable.isDraft -and -not $stable.isPrerelease) {
                    return $stableTag
                }
            }
            catch {
                # Absence is expected until both Linux smoke jobs finish.
                Write-Verbose "Stable Release $stableTag is not published yet."
            }
        } while ([DateTime]::UtcNow -lt $deadline)
        throw "Stable promotion did not publish $stableTag within four hours."
    }
    return $stableTag
}

Export-ModuleMember -Function @(
    'Get-AtlasoVirtualizationSourceIdentity',
    'Invoke-AtlasoVirtualizationPrerelease',
    'Invoke-AtlasoVirtualizationStablePromotion',
    'Publish-AtlasoVirtualizationDraftAssets',
    'Resolve-AtlasoVirtualizationStagingDirectory'
)
