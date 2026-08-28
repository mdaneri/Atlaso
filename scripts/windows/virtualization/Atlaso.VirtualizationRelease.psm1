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
Import-Module (Join-Path $PSScriptRoot '..\vmware\Atlaso.VmwarePayload.psm1') -Force

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
Dispatches and optionally waits for one exact GitHub Actions workflow run.
.PARAMETER Repository
GitHub name-with-owner.
.PARAMETER Workflow
Workflow filename dispatched through GitHub CLI.
.PARAMETER DisplayTitle
Exact run title declared by the workflow's run-name contract.
.PARAMETER Fields
Workflow dispatch fields in name=value form.
.PARAMETER TimeoutHours
Maximum bounded wait for discovery and successful completion.
.PARAMETER NoWait
Return immediately after GitHub accepts the dispatch.
#>
function Invoke-AtlasoReleaseWorkflow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$Workflow,
        [Parameter(Mandatory = $true)][string]$DisplayTitle,
        [Parameter(Mandatory = $true)][string[]]$Fields,
        [ValidateRange(1, 24)][int]$TimeoutHours,
        [switch]$NoWait
    )

    $knownRunIds = @{}
    if (-not $NoWait) {
        $knownJson = (Invoke-AtlasoReleaseGh -Arguments @(
            'run', 'list', '--repo', $Repository, '--workflow', $Workflow,
            '--event', 'workflow_dispatch', '--limit', '100', '--json', 'databaseId'
        )) -join [Environment]::NewLine
        foreach ($run in @($knownJson | ConvertFrom-Json)) {
            $knownRunIds[[string]$run.databaseId] = $true
        }
    }
    $dispatchArguments = @('workflow', 'run', $Workflow, '--repo', $Repository)
    foreach ($field in $Fields) {
        $dispatchArguments += @('-f', $field)
    }
    Invoke-AtlasoReleaseGh -Arguments $dispatchArguments | Out-Null
    if ($NoWait) {
        return
    }

    $deadline = [DateTime]::UtcNow.AddHours($TimeoutHours)
    $runId = $null
    do {
        Start-Sleep -Seconds 5
        $runsJson = (Invoke-AtlasoReleaseGh -Arguments @(
            'run', 'list', '--repo', $Repository, '--workflow', $Workflow,
            '--event', 'workflow_dispatch', '--limit', '100',
            '--json', 'databaseId,displayTitle'
        )) -join [Environment]::NewLine
        $candidateRuns = @($runsJson | ConvertFrom-Json | Where-Object {
                [string]$_.displayTitle -ceq $DisplayTitle -and
                -not $knownRunIds.ContainsKey([string]$_.databaseId)
            })
        if ($candidateRuns.Count -gt 1) {
            throw "Workflow dispatch is ambiguous for ${Workflow}: $DisplayTitle."
        }
        if ($candidateRuns.Count -eq 1) {
            $runId = [long]$candidateRuns[0].databaseId
            break
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($null -eq $runId) {
        throw "GitHub did not expose the dispatched ${Workflow} run before the timeout."
    }

    do {
        $runJson = (Invoke-AtlasoReleaseGh -Arguments @(
            'run', 'view', [string]$runId, '--repo', $Repository,
            '--json', 'databaseId,displayTitle,status,conclusion,url'
        )) -join [Environment]::NewLine
        $run = $runJson | ConvertFrom-Json
        if ([long]$run.databaseId -ne $runId -or [string]$run.displayTitle -cne $DisplayTitle) {
            throw "GitHub returned a different workflow run while waiting for $runId."
        }
        if ([string]$run.status -ceq 'completed') {
            if ([string]$run.conclusion -cne 'success') {
                throw "Workflow run $runId concluded $($run.conclusion): $($run.url)"
            }
            return $runId
        }
        Start-Sleep -Seconds 15
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Workflow run $runId did not complete within $TimeoutHours hour(s)."
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
    $sourceInput = Join-Path $operation 'verified-source'
    $sourceDownloads = Join-Path $operation (
        '.software-release-download-' + [guid]::NewGuid().ToString('N')
    )
    New-Item -ItemType Directory -Path $sourceDownloads | Out-Null
    try {
        foreach ($pattern in @(
                'release-manifest.json',
                'release-manifest.json.sig',
                "atlaso-appliance-$($identity.Version).tar.gz"
            )) {
            Invoke-AtlasoReleaseGh -Arguments @(
                'release', 'download', $identity.SoftwareTag, '--repo', $repository,
                '--pattern', $pattern, '--dir', $sourceDownloads
            ) | Out-Null
        }
        $sourceMetadata = Join-Path $sourceInput 'virtualization-source.json'
        # Always reconstruct the signed source in private staging. The preparer
        # publishes an absent destination atomically or requires an existing cache
        # to match the complete reconstructed tree byte for byte.
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
    finally {
        # This invocation owns only its unpredictable fresh download directory.
        # A retry never trusts retained pre-verification network bytes.
        if (Test-Path -LiteralPath $sourceDownloads) {
            Remove-Item -LiteralPath $sourceDownloads -Recurse -Force
        }
    }
    $source = Get-Content -LiteralPath $sourceMetadata -Raw | ConvertFrom-Json
    $buildRoot = Join-Path $operation 'vmware-build'
    $vmName = "Atlaso-Photon-Builder-VMware-$($identity.Version)"
    $vmx = Join-Path $buildRoot "$vmName.vmx"
    $requiresBuild = -not (Test-Path -LiteralPath $vmx -PathType Leaf)
    $existingProvenance = $null
    if (-not $requiresBuild) {
        try {
            $existingProvenance = Assert-AtlasoVmwarePayloadProvenance -VmxPath $vmx
        }
        catch {
            # Re-entering the wrapper is required so it can recover any durable
            # sensitive-build marker before replacing the partial output.
            Write-Warning "The retained VMware image is incomplete and will be rebuilt: $($_.Exception.Message)"
            $requiresBuild = $true
        }
    }
    if ($requiresBuild) {
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
        $existingProvenance = Assert-AtlasoVmwarePayloadProvenance -VmxPath $vmx
    }
    $wheel = Join-Path $sourceInput ([string]$source.application_wheel -replace '/', '\')
    $sourceMetadataSha256 = (Get-FileHash -LiteralPath $sourceMetadata -Algorithm SHA256).Hash.ToLowerInvariant()
    $payloadStateProperty = $existingProvenance.PSObject.Properties['payload_state']
    $sourceNameProperty = $existingProvenance.PSObject.Properties['deployment_source_name']
    $sourceHashProperty = $existingProvenance.PSObject.Properties['deployment_source_sha256']
    $alreadyDeployed = (
        $null -ne $payloadStateProperty -and
        $payloadStateProperty.Value -ceq 'software-deployed' -and
        $null -ne $sourceNameProperty -and
        $sourceNameProperty.Value -ceq (Split-Path -Leaf $sourceMetadata) -and
        $null -ne $sourceHashProperty -and
        $sourceHashProperty.Value -ceq $sourceMetadataSha256
    )
    if ($null -ne $payloadStateProperty -and -not $alreadyDeployed) {
        throw 'The retained VMware image is bound to different deployed software-source metadata.'
    }
    if (-not $alreadyDeployed) {
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
        # Deployment mutates the system-content VMDK. Publish its new exact bytes
        # before export so the exporter never validates stale build-time hashes.
        $existingProvenance = Update-AtlasoVmwarePayloadProvenance `
            -VmxPath $vmx `
            -DeploymentSourcePath $sourceMetadata
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
    & (Join-Path $RepoRoot 'scripts\windows\virtualization\export-artifacts.ps1') `
        -OvaPath $ovaPath -OutputRoot $hypervRoot -Force
    if ($LASTEXITCODE -ne 0) {
        throw 'Exact OVA-to-Hyper-V conversion failed.'
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
        & git -C $RepoRoot show-ref --verify --quiet "refs/tags/$tag"
        $localTagStatus = $LASTEXITCODE
        if ($localTagStatus -eq 0) {
            $localType = [string](& git -C $RepoRoot cat-file -t "refs/tags/$tag")
            $localCommit = [string](& git -C $RepoRoot rev-parse "refs/tags/$tag^{}")
            if ($LASTEXITCODE -ne 0 -or $localType.Trim() -cne 'tag' -or
                $localCommit.Trim() -cne $identity.Commit) {
                throw "Local tag $tag is not one annotated tag for the exact source commit."
            }
        }
        elseif ($localTagStatus -eq 1) {
            & git -C $RepoRoot -c user.name=github-actions[bot] -c user.email=41898282+github-actions[bot]@users.noreply.github.com tag -a $tag -m "Atlaso virtualization prerelease $tag" $identity.Commit
            if ($LASTEXITCODE -ne 0) {
                throw "Could not create annotated tag $tag."
            }
        }
        else {
            throw "Could not inspect local tag $tag."
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
    $releaseState = $null
    try {
        $releaseState = ((Invoke-AtlasoReleaseGh -Arguments @(
            'release', 'view', $tag, '--repo', $repository,
            '--json', 'tagName,isDraft,isPrerelease'
        )) -join [Environment]::NewLine) | ConvertFrom-Json
    }
    catch {
        $releaseState = $null
    }
    if ($null -eq $releaseState) {
        Invoke-AtlasoReleaseGh -Arguments @(
            'release', 'create', $tag, '--repo', $repository, '--draft', '--prerelease',
            '--verify-tag', '--title', "Atlaso Virtualization v$($identity.Version) $PrereleaseIdentifier",
            '--notes', 'Windows-produced OVA and Hyper-V candidate for protected hosted finalization.'
        ) | Out-Null
        Publish-AtlasoVirtualizationDraftAssets -Repository $repository -Tag $tag -AssetDirectory $candidate
    }
    elseif ($releaseState.tagName -cne $tag -or -not $releaseState.isPrerelease) {
        throw "Existing virtualization Release $tag is misclassified."
    }
    elseif ($releaseState.isDraft) {
        Publish-AtlasoVirtualizationDraftAssets -Repository $repository -Tag $tag -AssetDirectory $candidate
    }
    # A published prerelease may need hosted attestation or live-verification
    # recovery. Its immutable assets are left untouched while the idempotent
    # protected finalizer is dispatched again.
    Invoke-AtlasoReleaseWorkflow `
        -Repository $repository `
        -Workflow 'virtualization-prerelease.yml' `
        -DisplayTitle "Finalize $tag" `
        -Fields @("release_sha=$($identity.Commit)", "prerelease_tag=$tag") `
        -TimeoutHours 2 `
        -NoWait:$NoWait | Out-Null
    if (-not $NoWait) {
        $state = ((Invoke-AtlasoReleaseGh -Arguments @(
            'release', 'view', $tag, '--repo', $repository, '--json', 'isDraft,isPrerelease'
        )) -join [Environment]::NewLine) | ConvertFrom-Json
        if ($state.isDraft -or -not $state.isPrerelease) {
            throw "Successful hosted finalization did not publish $tag as a prerelease."
        }
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
    Invoke-AtlasoReleaseWorkflow `
        -Repository $repository `
        -Workflow 'virtualization-stable.yml' `
        -DisplayTitle "Promote $FromPrerelease" `
        -Fields @(
            "prerelease_tag=$FromPrerelease",
            "proxmox_runner_label=$ProxmoxRunnerLabel",
            "kvm_runner_label=$KvmRunnerLabel"
        ) `
        -TimeoutHours 4 `
        -NoWait:$NoWait | Out-Null
    $stableTag = "virtualization-v$version"
    if (-not $NoWait) {
        $stable = ((Invoke-AtlasoReleaseGh -Arguments @(
            'release', 'view', $stableTag, '--repo', $repository,
            '--json', 'isDraft,isPrerelease'
        )) -join [Environment]::NewLine) | ConvertFrom-Json
        if ($stable.isDraft -or $stable.isPrerelease) {
            throw "Successful promotion did not publish $stableTag as a stable Release."
        }
    }
    return $stableTag
}

Export-ModuleMember -Function @(
    'Get-AtlasoVirtualizationSourceIdentity',
    'Invoke-AtlasoReleaseWorkflow',
    'Invoke-AtlasoVirtualizationPrerelease',
    'Invoke-AtlasoVirtualizationStablePromotion',
    'Publish-AtlasoVirtualizationDraftAssets',
    'Resolve-AtlasoVirtualizationStagingDirectory'
)
