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
Import-Module (Join-Path $PSScriptRoot '..\vmware\Atlaso.WorkstationReadiness.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\vmware\Atlaso.VmwareBuilderIdentity.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '..\vmware\Atlaso.OnePasswordCredentials.psm1') -Force

<#
.SYNOPSIS
Resolve VMware vmrun for bounded release-producer lifecycle operations.
#>
function Resolve-AtlasoVirtualizationVmrunPath {
    foreach ($candidate in @(
            'C:\Program Files\VMware\VMware Workstation\vmrun.exe',
            'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
        )) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return $candidate
        }
    }
    $command = Get-Command vmrun -CommandType Application -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    throw 'vmrun.exe was not found for the virtualization release producer.'
}

<#
.SYNOPSIS
Start the exact release VM and return its bounded usable guest address.
.PARAMETER VmrunPath
Resolved vmrun executable.
.PARAMETER VmxPath
Exact canonical VMX to start and query.
.PARAMETER TimeoutSeconds
Shared upper bound for start and guest-address readiness.
#>
function Start-AtlasoVirtualizationDeploymentVm {
    param(
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [ValidateRange(30, 900)][int]$TimeoutSeconds = 300
    )

    $resolvedVmx = (Resolve-Path -LiteralPath $VmxPath -ErrorAction Stop).Path
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $running = @(Get-AtlasoWorkstationRunningVmxPath -VmrunPath $VmrunPath -Deadline $deadline)
    if ($resolvedVmx -notin $running) {
        $start = Invoke-AtlasoWorkstationVmrunBounded `
            -VmrunPath $VmrunPath `
            -Arguments @('-T', 'ws', 'start', $resolvedVmx, 'nogui') `
            -Deadline $deadline
        if ($start.TimedOut -or $start.ExitCode -ne 0) {
            throw 'The canonical VMware release VM could not be started within the deployment deadline.'
        }
    }
    $address = Invoke-AtlasoWorkstationVmrunBounded `
        -VmrunPath $VmrunPath `
        -Arguments @('-T', 'ws', 'getGuestIPAddress', $resolvedVmx, '-wait') `
        -Deadline $deadline
    $ip = $address.StdOut.Trim()
    if ($address.TimedOut -or $address.ExitCode -ne 0 -or
        $ip -notmatch '^\d+\.\d+\.\d+\.\d+$' -or $ip -like '169.254.*') {
        throw 'The canonical VMware release VM did not report a usable IPv4 address within the deployment deadline.'
    }
    return $ip
}

<#
.SYNOPSIS
Shut down the exact release VM and prove it is no longer running.
.PARAMETER VmrunPath
Resolved vmrun executable.
.PARAMETER VmxPath
Exact canonical VMX whose shutdown is verified.
.PARAMETER TimeoutSeconds
Upper bound for soft shutdown and provider readback.
#>
function Stop-AtlasoVirtualizationDeploymentVm {
    param(
        [Parameter(Mandatory = $true)][string]$VmrunPath,
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [ValidateRange(30, 600)][int]$TimeoutSeconds = 180
    )

    $resolvedVmx = (Resolve-Path -LiteralPath $VmxPath -ErrorAction Stop).Path
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $running = @(Get-AtlasoWorkstationRunningVmxPath -VmrunPath $VmrunPath -Deadline $deadline)
    if ($resolvedVmx -notin $running) {
        return
    }
    $stop = Invoke-AtlasoWorkstationVmrunBounded `
        -VmrunPath $VmrunPath `
        -Arguments @('-T', 'ws', 'stop', $resolvedVmx, 'soft') `
        -Deadline $deadline
    if ($stop.TimedOut -or $stop.ExitCode -ne 0) {
        throw 'The canonical VMware release VM did not accept bounded soft shutdown.'
    }
    do {
        $running = @(Get-AtlasoWorkstationRunningVmxPath -VmrunPath $VmrunPath -Deadline $deadline)
        if ($resolvedVmx -notin $running) {
            return
        }
        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $deadline)
    throw 'The canonical VMware release VM remained running after bounded soft shutdown.'
}

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

    $remote = [string](& git -C $RepoRoot remote get-url origin)
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not resolve the origin remote from the Atlaso checkout.'
    }
    $remote = $remote.Trim()
    $repository = ''
    foreach ($prefix in @(
            'https://github.com/',
            'git@github.com:',
            'ssh://git@github.com/'
        )) {
        if ($remote.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            $repository = $remote.Substring($prefix.Length).TrimEnd('/')
            break
        }
    }
    if ($repository.EndsWith('.git', [StringComparison]::OrdinalIgnoreCase)) {
        $repository = $repository.Substring(0, $repository.Length - 4)
    }
    if ($repository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') {
        throw 'The Atlaso checkout origin is not a supported GitHub repository URL.'
    }
    $value = [string](Invoke-AtlasoReleaseGh -Arguments @(
        'repo', 'view', $repository, '--json', 'nameWithOwner', '--jq', '.nameWithOwner'
    ))
    $value = $value.Trim()
    if ($value -cne $repository) {
        throw 'GitHub CLI returned a repository identity that differs from the checkout origin.'
    }
    return $value
}

<#
.SYNOPSIS
Resolves and validates the non-mutating virtualization staging root.
.PARAMETER RepoRoot
Exact Atlaso checkout root.
.PARAMETER StagingRoot
Optional operator-selected absolute staging root.
#>
function Resolve-AtlasoVirtualizationStagingRoot {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [string]$StagingRoot = ''
    )

    $candidate = $StagingRoot
    if (-not $candidate) {
        $candidate = Join-Path $RepoRoot 'artifacts\virtualization-release'
    }
    if (-not [System.IO.Path]::IsPathFullyQualified($candidate)) {
        throw 'StagingRoot must be an absolute filesystem path.'
    }
    $root = [System.IO.Path]::GetFullPath($candidate)
    $filesystemRoot = [System.IO.Path]::GetPathRoot($root)
    if ($root.TrimEnd('\', '/') -eq $filesystemRoot.TrimEnd('\', '/')) {
        throw 'StagingRoot cannot be a filesystem root.'
    }
    if (Test-Path -LiteralPath $root) {
        $rootItem = Get-Item -LiteralPath $root -Force
        if (-not $rootItem.PSIsContainer -or
            ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'StagingRoot must be an ordinary directory, not a reparse point.'
        }
        return $rootItem.FullName
    }
    return $root
}

<#
.SYNOPSIS
Returns retained current-version prerelease operation tags without mutation.
.PARAMETER StagingRoot
Validated staging root, which may not exist yet.
.PARAMETER Version
Synchronized Atlaso version.
#>
function Get-AtlasoVirtualizationRetainedOperationTags {
    param(
        [Parameter(Mandatory = $true)][string]$StagingRoot,
        [Parameter(Mandatory = $true)][string]$Version
    )

    if (-not (Test-Path -LiteralPath $StagingRoot)) {
        return @()
    }
    $pattern = '^virtualization-v' + [regex]::Escape($Version) + '-rc\.[1-9]\d*$'
    $retainedOperations = @()
    foreach ($item in @(Get-ChildItem -LiteralPath $StagingRoot -Force)) {
        if ($item.Name -notmatch $pattern) {
            continue
        }
        if ($item.Name -cnotmatch $pattern) {
            throw "Retained virtualization operation $($item.FullName) does not use the canonical tag casing."
        }
        if (-not $item.PSIsContainer -or
            ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Retained virtualization operation $($item.FullName) must be an ordinary directory."
        }
        $retainedOperations += $item.Name
    }
    return @($retainedOperations | Sort-Object)
}

<#
.SYNOPSIS
Inventories canonical remote virtualization prerelease tag names.
.PARAMETER RepoRoot
Exact Atlaso checkout root.
.PARAMETER Version
Synchronized Atlaso version.
#>
function Get-AtlasoVirtualizationRemoteTagNames {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$Version
    )

    $lines = @(& git -C $RepoRoot ls-remote --tags origin "refs/tags/virtualization-v$Version-rc.*")
    if ($LASTEXITCODE -ne 0) {
        throw "Could not inventory remote virtualization-v$Version release-candidate tags."
    }
    $pattern = '^refs/tags/(virtualization-v' + [regex]::Escape($Version) + '-rc\.[1-9]\d*)(?:\^\{\})?$'
    $names = foreach ($line in $lines) {
        $fields = [string]$line -split '\s+'
        if ($fields.Count -ge 2 -and $fields[1] -cmatch $pattern) {
            $Matches[1]
        }
    }
    return @($names | Sort-Object -Unique)
}

<#
.SYNOPSIS
Inventories canonical virtualization prerelease tags from all GitHub Releases.
.PARAMETER Repository
GitHub name-with-owner.
.PARAMETER Version
Synchronized Atlaso version.
#>
function Get-AtlasoVirtualizationReleaseTagNames {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$Version
    )

    $pattern = '^virtualization-v' + [regex]::Escape($Version) + '-rc\.[1-9]\d*$'
    $releaseTagOutput = Invoke-AtlasoReleaseGh -Arguments @(
        'api', '--paginate', "repos/$Repository/releases?per_page=100", '--jq', '.[].tag_name'
    )
    $names = @(
        # Invoke-AtlasoReleaseGh preserves its captured output as one array
        # object. Enumerate both levels explicitly before matching tag lines.
        foreach ($entry in @($releaseTagOutput)) {
            foreach ($line in @($entry)) {
                if ([string]$line -cmatch $pattern) {
                    [string]$line
                }
            }
        }
    )
    return @($names | ForEach-Object { ([string]$_).Trim() } | Sort-Object -Unique)
}

<#
.SYNOPSIS
Selects one frozen current-version virtualization prerelease tag.
.PARAMETER Version
Synchronized Atlaso version.
.PARAMETER RetainedTags
Validated retained current-version operation tags.
.PARAMETER RemoteTagNames
Canonical current-version remote Git tag names.
.PARAMETER ReleaseTagNames
Canonical current-version GitHub Release tag names.
#>
function Select-AtlasoVirtualizationPrereleaseTag {
    param(
        [Parameter(Mandatory = $true)][string]$Version,
        [string[]]$RetainedTags = @(),
        [string[]]$RemoteTagNames = @(),
        [string[]]$ReleaseTagNames = @()
    )

    if ($RetainedTags.Count -gt 1) {
        throw "Multiple retained virtualization-v$Version release-candidate operations make retry intent ambiguous."
    }
    if ($RetainedTags.Count -eq 1) {
        return $RetainedTags[0]
    }
    $prefix = "virtualization-v$Version-rc."
    $ordinals = @(
        @($RemoteTagNames) + @($ReleaseTagNames) |
            Sort-Object -Unique |
            ForEach-Object { [long]([string]$_).Substring($prefix.Length) }
    )
    [long]$next = 1
    if ($ordinals.Count -gt 0) {
        $maximum = [long]($ordinals | Measure-Object -Maximum).Maximum
        if ($maximum -eq [long]::MaxValue) {
            throw "No higher virtualization-v$Version release-candidate ordinal can be represented."
        }
        $next = $maximum + 1
    }
    return "$prefix$next"
}

<#
.SYNOPSIS
Rejects remote identity presence changes after prerelease selection.
.PARAMETER Tag
Frozen virtualization prerelease tag.
.PARAMETER IdentityKind
Remote identity kind being compared.
.PARAMETER WasPresent
Whether the identity existed during preflight selection.
.PARAMETER IsPresent
Whether the identity exists at the collision guard.
#>
function Assert-AtlasoVirtualizationFrozenPresence {
    param(
        [Parameter(Mandatory = $true)][string]$Tag,
        [Parameter(Mandatory = $true)][ValidateSet('tag', 'Release')][string]$IdentityKind,
        [Parameter(Mandatory = $true)][bool]$WasPresent,
        [Parameter(Mandatory = $true)][bool]$IsPresent
    )

    if ($WasPresent -ne $IsPresent) {
        throw "Remote $IdentityKind presence for $Tag changed after prerelease selection."
    }
}

<#
.SYNOPSIS
Validates a retained tag against corresponding remote tag and Release state.
.PARAMETER RepoRoot
Exact Atlaso checkout root.
.PARAMETER Repository
GitHub name-with-owner.
.PARAMETER Tag
Frozen retained virtualization prerelease tag.
.PARAMETER Commit
Exact source commit.
.PARAMETER RemoteTagNames
Inventoried canonical remote Git tag names.
.PARAMETER ReleaseTagNames
Inventoried canonical GitHub Release tag names.
#>
function Assert-AtlasoVirtualizationRetainedRemoteIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$Tag,
        [Parameter(Mandatory = $true)][string]$Commit,
        [string[]]$RemoteTagNames = @(),
        [string[]]$ReleaseTagNames = @()
    )

    $hasTag = $Tag -cin @($RemoteTagNames)
    $hasRelease = $Tag -cin @($ReleaseTagNames)
    if ($hasRelease -and -not $hasTag) {
        throw "Retained virtualization Release $Tag has no corresponding remote tag."
    }
    if ($hasTag) {
        $remoteTag = @(& git -C $RepoRoot ls-remote --tags origin "refs/tags/$Tag" "refs/tags/$Tag^{}")
        if ($LASTEXITCODE -ne 0) {
            throw "Could not inspect remote tag $Tag."
        }
        $peeled = @($remoteTag | Where-Object { $_ -match '\^\{\}$' })
        if ($peeled.Count -ne 1 -or ([string]$peeled[0] -split '\s+')[0] -cne $Commit) {
            throw "Remote tag $Tag is not one annotated tag for the exact source commit."
        }
    }
    if ($hasRelease) {
        $release = ((Invoke-AtlasoReleaseGh -Arguments @(
            'release', 'view', $Tag, '--repo', $Repository,
            '--json', 'tagName,isDraft,isPrerelease'
        )) -join [Environment]::NewLine) | ConvertFrom-Json
        if ($release.tagName -cne $Tag -or -not $release.isPrerelease) {
            throw "Existing virtualization Release $Tag is misclassified."
        }
    }
}

<#
.SYNOPSIS
Resolves exact Hyper-V smoke switches and rejects missing or duplicate names.
.PARAMETER ManagementSwitch
Optional exact management switch name.
.PARAMETER ServiceSwitch
Optional exact services switch name.
.PARAMETER SwitchInventory
Optional pre-inventoried switch objects for focused validation.
#>
function Resolve-AtlasoVirtualizationHyperVSwitches {
    param(
        [string]$ManagementSwitch = '',
        [string]$ServiceSwitch = '',
        [object[]]$SwitchInventory = @()
    )

    $management = if ($ManagementSwitch) { $ManagementSwitch } else { 'Atlaso Management' }
    $service = if ($ServiceSwitch) { $ServiceSwitch } else { 'Atlaso Services' }
    $inventory = @($SwitchInventory)
    if ($PSBoundParameters.ContainsKey('SwitchInventory') -eq $false) {
        $inventory = @(Get-VMSwitch -ErrorAction Stop)
    }
    foreach ($name in @($management, $service)) {
        $switchMatches = @($inventory | Where-Object { [string]$_.Name -ceq $name })
        if ($switchMatches.Count -ne 1) {
            throw "Hyper-V switch '$name' must exist exactly once."
        }
    }
    return [pscustomobject]@{ Management = $management; Service = $service }
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

    if ([string]::IsNullOrWhiteSpace($StagingRoot)) {
        throw 'StagingRoot must be an absolute filesystem path.'
    }
    $root = Resolve-AtlasoVirtualizationStagingRoot -RepoRoot $PSScriptRoot -StagingRoot $StagingRoot
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
Dispatches protected prerelease finalization and verifies publication.
.PARAMETER Repository
GitHub name-with-owner.
.PARAMETER Tag
Exact virtualization prerelease tag.
.PARAMETER Commit
Exact admitted successful-main commit.
.PARAMETER NoWait
Return after workflow dispatch instead of waiting for publication.
#>
function Invoke-AtlasoVirtualizationPrereleaseFinalizer {
    param(
        [Parameter(Mandatory = $true)][string]$Repository,
        [Parameter(Mandatory = $true)][string]$Tag,
        [Parameter(Mandatory = $true)][string]$Commit,
        [switch]$NoWait
    )

    Invoke-AtlasoReleaseWorkflow `
        -Repository $Repository `
        -Workflow 'virtualization-prerelease.yml' `
        -DisplayTitle "Finalize $Tag" `
        -Fields @("release_sha=$Commit", "prerelease_tag=$Tag") `
        -TimeoutHours 2 `
        -NoWait:$NoWait | Out-Null
    if (-not $NoWait) {
        $state = ((Invoke-AtlasoReleaseGh -Arguments @(
            'release', 'view', $Tag, '--repo', $Repository, '--json', 'isDraft,isPrerelease'
        )) -join [Environment]::NewLine) | ConvertFrom-Json
        if ($state.isDraft -or -not $state.isPrerelease) {
            throw "Successful hosted finalization did not publish $Tag as a prerelease."
        }
    }
}

<#
.SYNOPSIS
Invokes the canonical VMware release image builder with named parameters.
.PARAMETER BuilderScriptPath
Exact path to the canonical VMware image-builder script.
.PARAMETER ReleaseVersion
Synchronized Atlaso version for the protected release builder.
.PARAMETER ReleaseSourceCommit
Exact source commit for the protected release builder.
.PARAMETER OutputDirectory
Task-owned output directory for the VMware builder.
.PARAMETER OnePasswordEnvironmentId
Resolved exact Atlaso Environment ID.
.PARAMETER OnePasswordAccount
Resolved 1Password account selector.
.PARAMETER OnePasswordServiceAccountTokenFile
Resolved current-user DPAPI service-account ciphertext file.
.PARAMETER OnePasswordPython
Resolved supported Python executable.
#>
function Invoke-AtlasoVirtualizationReleaseImageBuilder {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingPlainTextForPassword',
        'OnePasswordServiceAccountTokenFile',
        Justification = 'Path to current-user DPAPI ciphertext, not a plaintext token.'
    )]
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
        [Parameter(Mandatory = $true)][string]$BuilderScriptPath,
        [Parameter(Mandatory = $true)][string]$ReleaseVersion,
        [Parameter(Mandatory = $true)][string]$ReleaseSourceCommit,
        [Parameter(Mandatory = $true)][string]$OutputDirectory,
        [Parameter(Mandatory = $true)][string]$OnePasswordEnvironmentId,
        [AllowEmptyString()][string]$OnePasswordAccount = '',
        [AllowEmptyString()][string]$OnePasswordServiceAccountTokenFile = '',
        [Parameter(Mandatory = $true)][string]$OnePasswordPython
    )

    # Named splatting is a credential boundary: positional binding would send
    # the release version into the builder's SecureString password parameter.
    $buildArguments = @{
        ReleaseBuilder           = $true
        ReleaseVersion           = $ReleaseVersion
        ReleaseSourceCommit      = $ReleaseSourceCommit
        OutputDirectory          = $OutputDirectory
        Headless                 = $true
        EnableRealSystemAdapters = $true
        OnePasswordEnvironmentId = $OnePasswordEnvironmentId
        OnePasswordAccount       = $OnePasswordAccount
        OnePasswordServiceAccountTokenFile = $OnePasswordServiceAccountTokenFile
        OnePasswordPython        = $OnePasswordPython
    }
    & $BuilderScriptPath @buildArguments
}

<#
.SYNOPSIS
Creates, smokes, and stages one local virtualization prerelease.
.PARAMETER RepoRoot
Exact Atlaso checkout root.
.PARAMETER StagingRoot
Optional absolute fixed-volume staging root. Defaults to artifacts\virtualization-release beneath the checkout.
.PARAMETER ManagementVmnet
VMware management vmnet used by smoke.
.PARAMETER ServiceVmnet
VMware services vmnet used by smoke.
.PARAMETER ManagementSwitch
Optional Hyper-V management switch used by smoke. Defaults to Atlaso Management.
.PARAMETER ServiceSwitch
Optional Hyper-V services switch used by smoke. Defaults to Atlaso Services.
.PARAMETER OnePasswordEnvironmentId
Optional exact Atlaso Environment ID. Omission uses the checkout-local selector file.
.PARAMETER OnePasswordAccount
Optional 1Password account selector. Omission requires one uniquely signed-in CLI account.
.PARAMETER OnePasswordServiceAccountTokenFile
Optional current-user DPAPI ciphertext file. The checkout-local default is
preferred before desktop discovery when neither authentication selector is explicit.
.PARAMETER OnePasswordPython
Optional supported Python executable. Omission discovers standard Windows x64 CPython 3.14.
.PARAMETER NoWait
Return after dispatch instead of waiting for hosted publication.
.PARAMETER CandidateOnly
Stop after producing and smoking the candidate set without changing GitHub.
#>
function Invoke-AtlasoVirtualizationPrerelease {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingPlainTextForPassword',
        'OnePasswordServiceAccountTokenFile',
        Justification = 'Path to current-user DPAPI ciphertext, not a plaintext token.'
    )]
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
        [string]$StagingRoot = '',
        [string]$ManagementVmnet = 'VMnet8',
        [string]$ServiceVmnet = 'VMnet1',
        [string]$ManagementSwitch = '',
        [string]$ServiceSwitch = '',
        [string]$OnePasswordEnvironmentId = '',
        [string]$OnePasswordAccount = '',
        [string]$OnePasswordServiceAccountTokenFile = '',
        [string]$OnePasswordPython = '',
        [switch]$CandidateOnly,
        [switch]$NoWait
    )

    $repository = Get-AtlasoReleaseRepository -RepoRoot $RepoRoot
    $identity = Get-AtlasoVirtualizationSourceIdentity -RepoRoot $RepoRoot -Repository $repository
    $resolvedStagingRoot = Resolve-AtlasoVirtualizationStagingRoot `
        -RepoRoot $RepoRoot `
        -StagingRoot $StagingRoot
    $retainedTags = @(Get-AtlasoVirtualizationRetainedOperationTags `
        -StagingRoot $resolvedStagingRoot `
        -Version $identity.Version)
    $remoteTagNames = @(Get-AtlasoVirtualizationRemoteTagNames `
        -RepoRoot $RepoRoot `
        -Version $identity.Version)
    $releaseTagNames = @(Get-AtlasoVirtualizationReleaseTagNames `
        -Repository $repository `
        -Version $identity.Version)
    $tag = Select-AtlasoVirtualizationPrereleaseTag `
        -Version $identity.Version `
        -RetainedTags $retainedTags `
        -RemoteTagNames $remoteTagNames `
        -ReleaseTagNames $releaseTagNames
    $tagExistedAtSelection = $tag -cin $remoteTagNames
    $releaseExistedAtSelection = $tag -cin $releaseTagNames
    if ($retainedTags.Count -eq 1) {
        Assert-AtlasoVirtualizationRetainedRemoteIdentity `
            -RepoRoot $RepoRoot `
            -Repository $repository `
            -Tag $tag `
            -Commit $identity.Commit `
            -RemoteTagNames $remoteTagNames `
            -ReleaseTagNames $releaseTagNames
    }
    $resolvedSwitches = Resolve-AtlasoVirtualizationHyperVSwitches `
        -ManagementSwitch $ManagementSwitch `
        -ServiceSwitch $ServiceSwitch
    $environmentSource = if ($OnePasswordEnvironmentId) { 'explicit parameter' } else { 'checkout-local selector file' }
    $authenticationSource = if ($OnePasswordServiceAccountTokenFile) {
        'explicit service-account token file'
    }
    elseif ($OnePasswordAccount) {
        'explicit desktop account'
    }
    else {
        'checkout-local service-account token or desktop discovery'
    }
    $pythonSource = if ($OnePasswordPython) { 'explicit parameter' } else { 'discovered Windows x64 CPython 3.14' }
    $OnePasswordEnvironmentId = Resolve-AtlasoOnePasswordEnvironmentId `
        -EnvironmentId $OnePasswordEnvironmentId `
        -RepositoryRoot $RepoRoot `
        -ConsumerDescription 'virtualization production'
    Assert-AtlasoOnePasswordEnvironmentId `
        -EnvironmentId $OnePasswordEnvironmentId
    $authentication = Resolve-AtlasoOnePasswordAuthentication `
        -RepositoryRoot $RepoRoot `
        -ServiceAccountTokenFile $OnePasswordServiceAccountTokenFile `
        -Account $OnePasswordAccount `
        -TimeoutSeconds 300
    $OnePasswordAccount = $authentication.Account
    $OnePasswordServiceAccountTokenFile = $authentication.TokenFile
    $OnePasswordPython = Resolve-AtlasoOnePasswordPython `
        -PythonCommand $OnePasswordPython `
        -ConsumerDescription 'virtualization production' `
        -TimeoutSeconds 300
    $ManagementSwitch = $resolvedSwitches.Management
    $ServiceSwitch = $resolvedSwitches.Service

    Write-Host 'Virtualization prerelease preflight:'
    Write-Host "  Version/tag: $($identity.Version) / $tag"
    Write-Host "  Staging root: $resolvedStagingRoot"
    Write-Host "  Hyper-V switches: $ManagementSwitch / $ServiceSwitch"
    Write-Host "  1Password Environment selector: $environmentSource"
    Write-Host "  1Password authentication: $authenticationSource"
    Write-Host "  Python selector: $pythonSource"

    # The selected tag is frozen before the first staging mutation. Later tag or
    # Release collisions are rejected by the existing no-clobber guards.
    $operation = Resolve-AtlasoVirtualizationStagingDirectory -StagingRoot $resolvedStagingRoot -Tag $tag
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
    $candidate = Join-Path $operation 'candidate'
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
    Assert-AtlasoVirtualizationFrozenPresence `
        -Tag $tag `
        -IdentityKind Release `
        -WasPresent $releaseExistedAtSelection `
        -IsPresent ($null -ne $releaseState)
    if ($null -ne $releaseState -and
        ($releaseState.tagName -cne $tag -or -not $releaseState.isPrerelease)) {
        throw "Existing virtualization Release $tag is misclassified."
    }
    if ($null -ne $releaseState -and -not $releaseState.isDraft) {
        $remoteTag = @(& git -C $RepoRoot ls-remote --tags origin "refs/tags/$tag" "refs/tags/$tag^{}")
        if ($LASTEXITCODE -ne 0) {
            throw "Could not inspect remote tag $tag."
        }
        $peeled = @($remoteTag | Where-Object { $_ -match '\^\{\}$' })
        if ($peeled.Count -ne 1 -or ([string]$peeled[0] -split '\s+')[0] -ne $identity.Commit) {
            throw "Remote tag $tag is not one annotated tag for the exact source commit."
        }
        # Published assets are immutable. A finalizer retry re-downloads and
        # verifies those exact bytes, so rebuilding a nondeterministic OVA here
        # would be both unnecessary and unsafe.
        if ($CandidateOnly) {
            return $tag
        }
        Invoke-AtlasoVirtualizationPrereleaseFinalizer `
            -Repository $repository `
            -Tag $tag `
            -Commit $identity.Commit `
            -NoWait:$NoWait
        return $tag
    }
    $reuseCandidate = Test-Path -LiteralPath $candidate
    if ($reuseCandidate) {
        $verifyArguments = @(
            (Join-Path $RepoRoot 'scripts\stage_virtualization_release.py'),
            '--verify-existing', $candidate,
            '--source-metadata', $sourceMetadata,
            '--version', $identity.Version,
            '--commit', $identity.Commit
        )
        & python @verifyArguments
        if ($LASTEXITCODE -ne 0) {
            throw 'Retained virtualization candidate verification failed.'
        }
    }
    if (-not $reuseCandidate) {
    $buildRoot = Join-Path $operation 'vmware-build'
    $builderIdentity = New-AtlasoVmwareBuilderIdentity `
        -ReleaseVersion $identity.Version `
        -SourceCommit $identity.Commit
    $builderOutput = Join-Path $buildRoot $builderIdentity.Name
    $vmx = Join-Path $builderOutput "$($builderIdentity.Name).vmx"
    $requiresBuild = -not (Test-Path -LiteralPath $vmx -PathType Leaf)
    $existingProvenance = $null
    if (-not $requiresBuild) {
        try {
            $existingProvenance = Assert-AtlasoVmwarePayloadProvenance `
                -VmxPath $vmx `
                -ExpectedSourceCommit $identity.Commit `
                -RequireCleanSource `
                -RequireReleaseBuilder
        }
        catch {
            # Re-entering the wrapper is required so it can recover any durable
            # sensitive-build marker before replacing the partial output.
            Write-Warning "The retained VMware image is incomplete and will be rebuilt: $($_.Exception.Message)"
            $requiresBuild = $true
        }
    }
    if ($requiresBuild) {
        Invoke-AtlasoVirtualizationReleaseImageBuilder `
            -BuilderScriptPath (Join-Path $RepoRoot 'scripts\windows\vmware\build-photon-image.ps1') `
            -ReleaseVersion $identity.Version `
            -ReleaseSourceCommit $identity.Commit `
            -OutputDirectory $builderOutput `
            -OnePasswordEnvironmentId $OnePasswordEnvironmentId `
            -OnePasswordAccount $OnePasswordAccount `
            -OnePasswordServiceAccountTokenFile $OnePasswordServiceAccountTokenFile `
            -OnePasswordPython $OnePasswordPython
        if ($LASTEXITCODE -ne 0) {
            throw 'Canonical VMware image build failed.'
        }
        $existingProvenance = Assert-AtlasoVmwarePayloadProvenance `
            -VmxPath $vmx `
            -ExpectedSourceCommit $identity.Commit `
            -RequireCleanSource `
            -RequireReleaseBuilder
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
        $deploymentVmrun = Resolve-AtlasoVirtualizationVmrunPath
        $deployArguments = @{
            RepoRoot = $RepoRoot
            VmxPath = $vmx
            SkipBuild = $true
            WheelPath = $wheel
            RuntimeDependencyDirectory = (Join-Path $sourceInput 'wheelhouse\cp314')
        }
        $deployArguments.OnePasswordEnvironmentId = $OnePasswordEnvironmentId
        $deployArguments.OnePasswordAccount = $OnePasswordAccount
        $deployArguments.OnePasswordServiceAccountTokenFile = $OnePasswordServiceAccountTokenFile
        $deployArguments.OnePasswordPython = $OnePasswordPython
        try {
            $deployArguments.IpAddress = Start-AtlasoVirtualizationDeploymentVm `
                -VmrunPath $deploymentVmrun `
                -VmxPath $vmx
            & (Join-Path $RepoRoot 'scripts\windows\vmware\deploy-wheel.ps1') @deployArguments
            if ($LASTEXITCODE -ne 0) {
                throw 'Exact published application-wheel deployment failed.'
            }
        }
        finally {
            # Proven shutdown is required before hashing or exporting mutable
            # VMware disks, including after a failed deployment attempt.
            Stop-AtlasoVirtualizationDeploymentVm `
                -VmrunPath $deploymentVmrun `
                -VmxPath $vmx
        }
        # Deployment mutates the system-content VMDK. Publish its new exact bytes
        # before export so the exporter never validates stale build-time hashes.
        $existingProvenance = Update-AtlasoVmwarePayloadProvenance `
            -VmxPath $vmx `
            -DeploymentSourcePath $sourceMetadata
    }
    else {
        # A resumed post-deployment image must also remain powered off while its
        # bound bytes are hashed and exported.
        Stop-AtlasoVirtualizationDeploymentVm `
            -VmrunPath (Resolve-AtlasoVirtualizationVmrunPath) `
            -VmxPath $vmx
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
    }
    if ($CandidateOnly) {
        return $candidate
    }
    $remoteTag = @(& git -C $RepoRoot ls-remote --tags origin "refs/tags/$tag" "refs/tags/$tag^{}")
    if ($LASTEXITCODE -ne 0) {
        throw "Could not inspect remote tag $tag."
    }
    Assert-AtlasoVirtualizationFrozenPresence `
        -Tag $tag `
        -IdentityKind tag `
        -WasPresent $tagExistedAtSelection `
        -IsPresent ($remoteTag.Count -gt 0)
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
    if ($null -eq $releaseState) {
        Invoke-AtlasoReleaseGh -Arguments @(
            'release', 'create', $tag, '--repo', $repository, '--draft', '--prerelease',
            '--verify-tag', '--title', "Atlaso Virtualization v$($identity.Version) $($tag.Substring($tag.LastIndexOf('-') + 1))",
            '--notes', 'Windows-produced OVA and Hyper-V candidate for protected hosted finalization.'
        ) | Out-Null
        Publish-AtlasoVirtualizationDraftAssets -Repository $repository -Tag $tag -AssetDirectory $candidate
    }
    elseif ($releaseState.isDraft) {
        Publish-AtlasoVirtualizationDraftAssets -Repository $repository -Tag $tag -AssetDirectory $candidate
    }
    # A published prerelease may need hosted attestation or live-verification
    # recovery. Its immutable assets are left untouched while the idempotent
    # protected finalizer is dispatched again.
    Invoke-AtlasoVirtualizationPrereleaseFinalizer `
        -Repository $repository `
        -Tag $tag `
        -Commit $identity.Commit `
        -NoWait:$NoWait
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
    $expectedProxmoxRunnerLabel = "atlaso-proxmox-$suffix"
    $expectedKvmRunnerLabel = "atlaso-kvm-$suffix"
    if ($ProxmoxRunnerLabel -ne $expectedProxmoxRunnerLabel) {
        throw "ProxmoxRunnerLabel must be the release-specific label $expectedProxmoxRunnerLabel."
    }
    if ($KvmRunnerLabel -ne $expectedKvmRunnerLabel) {
        throw "KvmRunnerLabel must be the release-specific label $expectedKvmRunnerLabel."
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
