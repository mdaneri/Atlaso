<#
.SYNOPSIS
Build and deploy one reviewed development wheel to its original host-only ISO fixture.
.PARAMETER RepositoryRoot
Exact clean task-owned Atlaso checkout containing the reviewed commit.
.PARAMETER ReviewedSourceCommit
Full reviewed Git commit used to load this entrypoint from Git blob bytes.
.PARAMETER Plan
Immutable public plan retaining original ISO, boot, host-only transition and console inspections.
.PARAMETER PythonPath
Prepared task-owned Python runtime with the locked inspector and wheel-build dependencies.
.PARAMETER EnvironmentId
Opaque preverified Atlaso 1Password Environment selector, used only by the bounded deployment child.
.PARAMETER RuntimeDependencyDirectory
Complete original signed cp314 offline wheelhouse, pinned through the invocation.
.PARAMETER Execute
Create a fresh owned output, claim this original fixture once, and run the existing direct deployer.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RepositoryRoot,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$ReviewedSourceCommit,
    [Parameter(Mandatory)][string]$Plan,
    [Parameter(Mandatory)][string]$PythonPath,
    [Parameter(Mandatory)][string]$EnvironmentId,
    [Parameter(Mandatory)][string]$RuntimeDependencyDirectory,
    [switch]$Execute
)
$ErrorActionPreference = 'Stop'
<#
.SYNOPSIS
Create one output exclusively and publish its original handle identity before use.
.PARAMETER DurableRoot
Independently resolved configured Codex worktree root receiving immutable ownership.
.PARAMETER Worktree
Exact admitted task checkout containing the output namespace.
.PARAMETER OutputRoot
Absent strict descendant of the checkout's existing test-results directory.
.PARAMETER TaskId
Exact originating Codex task identity.
.PARAMETER SourceCommit
Reviewed source commit owning this new validation resource.
.PARAMETER PullRequestNumber
Positive pull request owning the deployment fixture.
#>
function New-CertificateIsoDeploymentOutput {
    param([Parameter(Mandatory)][string]$DurableRoot, [Parameter(Mandatory)][string]$Worktree,
        [Parameter(Mandatory)][string]$OutputRoot, [Parameter(Mandatory)][string]$TaskId,
        [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$SourceCommit,
        [Parameter(Mandatory)][ValidateRange(1, 2147483647)][int]$PullRequestNumber)
    if (-not (Test-AtlasoStrictDescendantPath -ParentPath $DurableRoot -ChildPath $Worktree) -or
        -not (Test-AtlasoStrictDescendantPath -ParentPath (Join-Path $Worktree 'test-results') -ChildPath $OutputRoot) -or
        $TaskId -cne $env:CODEX_THREAD_ID -or (Test-Path -LiteralPath $OutputRoot)) {
        throw 'Deployment output requires an absent original task-bound directory.'
    }
    $published = [Collections.Generic.List[object]]::new()
    $receiptDirectory = Join-Path $DurableRoot '.task-ownership'
    $receiptDirectoryPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($receiptDirectory, $true)
    $callback = [Action[string, string]]{
        param($CreatedPath, $OriginalIdentity)
        if ($CreatedPath -ine $OutputRoot -or $OriginalIdentity -cnotmatch '^([0-9A-F]{8}):([0-9A-F]{8})([0-9A-F]{8})$') {
            throw 'Unexpected deployment creation identity.'
        }
        $identity = @([Convert]::ToUInt32($Matches[1], 16), [Convert]::ToUInt32($Matches[2], 16), [Convert]::ToUInt32($Matches[3], 16))
        $record = [ordered]@{ schema = 1; kind = 'lifecycle'; task_id = $TaskId; repository = 'mdaneri/Atlaso'
            source_commit = $SourceCommit; pr = $PullRequestNumber; worktree = $Worktree
            lab_root = $OutputRoot; path = $CreatedPath; root_identity = $identity
            created_utc = [DateTimeOffset]::UtcNow.ToString('o'); cleanup_tool = 'Remove-AtlasoWorkstationArtifactRoot' }
        $path = Join-Path $receiptDirectory ('atlaso-lifecycle-original-' + $PullRequestNumber + '-' + [guid]::NewGuid().ToString('N') + '.json')
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($record | ConvertTo-Json -Depth 8 -Compress))
        $writer = [Atlaso.WorkstationDurablePublisherV3]::CreateStage($path + '.pending')
        try {
            $writer.Write($bytes)
            [Atlaso.WorkstationDurablePublisherV3]::PublishDurableFile($writer, $path, $false)
        } finally { $writer.Dispose() }
        $published.Add([pscustomobject]@{ path = $path
            sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
            resource = $CreatedPath; native_identity = $OriginalIdentity })
    }
    $parentPin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath([IO.Path]::GetDirectoryName($OutputRoot), $true)
    try {
        $creation = [Atlaso.WorkstationFileIdentity]::CreateAndPinOrdinaryDirectoryPath($OutputRoot, $callback)
        $creation.Dispose()
        if ($published.Count -ne 1) { throw 'Original deployment ownership was not durably published.' }
        $pin = [Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($OutputRoot, $true)
        try {
            if ([Atlaso.WorkstationFileIdentity]::Get($OutputRoot) -cne $published[0].native_identity) {
                throw 'Original deployment output changed before first use.'
            }
            return [pscustomobject]@{ Ownership = $published[0]; Pin = $pin }
        } catch { $pin.Dispose(); throw }
    } finally { $parentPin.Dispose(); $receiptDirectoryPin.Dispose() }
}
<#
.SYNOPSIS
Preserve the original appliance's canonical identity in every native admission call.
.PARAMETER RepositoryRoot
Exact admitted task checkout that owns the original appliance.
.PARAMETER Plan
Digest-bound deployment plan retaining the original receipt selectors and host-only network.
.PARAMETER Original
Digest-checked original ISO ownership record containing its canonical name and VMX path.
#>
function Get-CertificateIsoNativeArguments {
    param([Parameter(Mandatory)][string]$RepositoryRoot,
        [Parameter(Mandatory)][hashtable]$Plan, [Parameter(Mandatory)][hashtable]$Original)
    $base = New-AtlasoVmwareTestIdentity -PullRequestNumber ([int]$Plan.pr) -Purpose installation-iso
    $name = [string]$Original.canonical_name
    $suffix = ''
    if ($name -cne $base.Name) {
        $prefix = $base.Name + '-'
        if (-not $name.StartsWith($prefix, [StringComparison]::Ordinal)) {
            throw 'Original ISO canonical identity differs from this pull request.'
        }
        $suffix = $name.Substring($prefix.Length)
    }
    $identity = New-AtlasoVmwareTestIdentity -PullRequestNumber ([int]$Plan.pr) `
        -Purpose installation-iso -CollisionSuffix $suffix
    if ($identity.Name -cne $name -or
        [IO.Path]::GetFileNameWithoutExtension([string]$Original.vmx_path) -cne $identity.Name) {
        throw 'Original ISO canonical VMX identity is not preserved.'
    }
    return @{
        Mode = 'AdmitNetwork'; Worktree = $RepositoryRoot; OutputDirectory = $Original.output_directory
        PullRequestNumber = [int]$Plan.pr; CollisionSuffix = $identity.CollisionSuffix
        NetworkVmnet = $Plan.deployment_network_binding.vmnet
        OriginalReceiptPath = $Plan.appliance_ownership.path; OriginalReceiptSha256 = $Plan.appliance_ownership.sha256
        BaselineReceiptPath = $Plan.appliance_disk_baseline.path; BaselineReceiptSha256 = $Plan.appliance_disk_baseline.sha256
        BootReceiptPath = $Plan.appliance_installed_boot.path; BootReceiptSha256 = $Plan.appliance_installed_boot.sha256
    }
}
if ($PSScriptRoot) { throw 'Load this entrypoint from the exact reviewed Git blob.' }
if ($env:DEFAULT_ADMIN_PASSWORD -or $env:OP_SERVICE_ACCOUNT_TOKEN) {
    throw 'Use only the existing task-local 1Password credential bridge.'
}
$repo = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\', '/')
$pins = [Collections.Generic.List[IDisposable]]::new()
$sourcePins = [Collections.Generic.List[IDisposable]]::new()
$runtime = $null
$savedTemp = $env:TEMP
$savedTmp = $env:TMP
$savedBytecode = $env:PYTHONDONTWRITEBYTECODE
$savedPythonCache = $env:PYTHONPYCACHEPREFIX
try {
    $env:TEMP = Join-Path $repo 'test-results'
    $env:TMP = $env:TEMP
    $env:PYTHONDONTWRITEBYTECODE = '1'
    $head = ([string](& git -C $repo rev-parse --verify 'HEAD^{commit}')).Trim()
    if ($LASTEXITCODE -ne 0 -or $head -cne $ReviewedSourceCommit) { throw 'The reviewed deployment head changed.' }
    $changes = @(& git -C $repo status --porcelain=v1 --untracked-files=all)
    if ($LASTEXITCODE -ne 0 -or $changes.Count -ne 0) { throw 'The deployment checkout must be completely clean.' }
    $branch = ([string](& git -C $repo branch --show-current)).Trim()
    if ($LASTEXITCODE -ne 0 -or $branch -in @('', 'main') -or
        $env:CODEX_THREAD_ID -notmatch '^[A-Za-z0-9_-]{1,128}$') {
        throw 'Original-ISO deployment requires its clean task-owned reviewed head.'
    }
    foreach ($relative in @(
        'scripts/windows/vmware/Atlaso.WorkstationCleanup.psm1',
        'scripts/windows/vmware/Atlaso.SourceSnapshot.psm1',
        'scripts/windows/vmware/Atlaso.LifecycleOwnership.ps1',
        'scripts/windows/vmware/Atlaso.WorkstationFirstBoot.ps1',
        'scripts/windows/vmware/Atlaso.VmwareTestIdentity.psm1',
        'scripts/windows/vmware/Atlaso.FixtureWheel.psm1',
        'scripts/windows/vmware/test-installation-iso.ps1'
    )) {
        $path = Join-Path $repo $relative
        $pins.Add([IO.FileStream]::new($path, 'Open', 'Read', 'Read'))
        $expected = ([string](& git -C $repo rev-parse --verify "${ReviewedSourceCommit}:$relative")).Trim()
        $actual = ([string](& git hash-object --no-filters -- $path)).Trim()
        if ($LASTEXITCODE -ne 0 -or $expected -cnotmatch '^[0-9a-f]{40}$' -or $actual -cne $expected) {
            throw 'Original-ISO helper bytes differ from the reviewed Git source.'
        }
    }
    $helpers = Join-Path $repo 'scripts/windows/vmware'
    $runnerSource = @(& git -C $repo show "${ReviewedSourceCommit}:scripts/windows/vmware/run-lifecycle-test.ps1")
    if ($LASTEXITCODE -ne 0 -or -not $runnerSource.Count) { throw 'The admitted lifecycle bootstrap is unavailable.' }
    $parseErrors = $null
    $runnerAst = [Management.Automation.Language.Parser]::ParseInput(($runnerSource -join "`n"), [ref]$null, [ref]$parseErrors)
    $bootstrap = @($runnerAst.FindAll({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Import-LifecycleOwnershipPrimitives'
    }, $false))
    if ($parseErrors.Count -or $bootstrap.Count -ne 1) { throw 'The admitted lifecycle bootstrap shape changed.' }
    . ([scriptblock]::Create($bootstrap[0].Extent.Text))
    Import-LifecycleOwnershipPrimitives -RepositoryRoot $repo -Commit $ReviewedSourceCommit
    $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($helpers, $false, $true))
    Import-Module (Join-Path $helpers 'Atlaso.SourceSnapshot.psm1') -Force
    Import-Module (Join-Path $helpers 'Atlaso.FixtureWheel.psm1') -Force
    Import-Module (Join-Path $helpers 'Atlaso.VmwareTestIdentity.psm1') -Force
    . (Join-Path $helpers 'Atlaso.LifecycleOwnership.ps1')
    . (Join-Path $helpers 'Atlaso.WorkstationFirstBoot.ps1')
    $durable = Get-AtlasoLifecycleDurableRoot
    if (-not (Test-AtlasoStrictDescendantPath -ParentPath $durable -ChildPath $repo)) {
        throw 'Original-ISO worktree is outside the active configured root.'
    }
    $evidenceRoot = Join-Path $repo 'test-results'
    $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($repo, $true))
    $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($evidenceRoot, $true))
    $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath([IO.Path]::GetDirectoryName($Plan), $true))
    $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($Plan, $true))
    if ((Get-Item -LiteralPath $Plan).Length -gt 262144) { throw 'The public deployment plan exceeds its bound.' }
    $planData = Get-Content -LiteralPath $Plan -Raw | ConvertFrom-Json -AsHashtable
    if ($planData.source_commit -cne $ReviewedSourceCommit -or $planData.deployed_commit -cne $ReviewedSourceCommit -or
        $planData.task_id -cne $env:CODEX_THREAD_ID -or $planData.trust_model -cne 'trusted-host' -or
        ($planData.pr -isnot [long] -and $planData.pr -isnot [int]) -or $planData.pr -le 0) {
        throw 'Original-ISO plan does not select the exact task, source and PR.'
    }
    $records = @{}
    foreach ($key in @('appliance_intent', 'appliance_ownership', 'appliance_disk_baseline',
        'appliance_installed_boot', 'installed_inspection', 'host_only_transition', 'deployment_network_inspection')) {
        $reference = $planData[$key]
        if ($reference.path -cnotmatch '^[A-Za-z]:[\\/]' -or $reference.sha256 -cnotmatch '^[0-9a-f]{64}$' -or
            -not (Test-AtlasoStrictDescendantPath -ParentPath $durable -ChildPath $reference.path)) {
            throw 'Original-ISO receipt reference is outside its permitted durable root.'
        }
        $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath([IO.Path]::GetDirectoryName($reference.path), $true))
        $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($reference.path, $true))
        if ((Get-Item -LiteralPath $reference.path).Length -gt 262144) { throw 'A public deployment receipt exceeds its bound.' }
        if ((Get-FileHash -LiteralPath $reference.path -Algorithm SHA256).Hash -ine $reference.sha256) {
            throw 'Original-ISO receipt bytes changed from the pinned plan.'
        }
        $records[$key] = Get-Content -LiteralPath $reference.path -Raw | ConvertFrom-Json -AsHashtable
    }
    $original = $records.appliance_ownership
    $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($original.output_directory, $true))
    $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryMutableFile($original.vmx_path))
    $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath([IO.Path]::GetDirectoryName($original.installation_iso.path), $true))
    $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($original.installation_iso.path, $true))
    $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath([IO.Path]::GetDirectoryName($records.host_only_transition.backup_path), $true))
    $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($records.host_only_transition.backup_path, $true))
    $dependencies = [IO.Path]::GetFullPath($RuntimeDependencyDirectory)
    if (-not (Test-AtlasoStrictDescendantPath -ParentPath $durable -ChildPath $dependencies)) {
        throw 'Offline dependencies must remain inside the configured task-state root.'
    }
    $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryDirectoryPath($dependencies, $true))
    foreach ($wheelFile in @(Get-ChildItem -LiteralPath $dependencies -Filter '*.whl' -File)) {
        $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($wheelFile.FullName, $true))
    }
    $nativeArguments = Get-CertificateIsoNativeArguments -RepositoryRoot $repo -Plan $planData -Original $original
    $output = Join-Path $evidenceRoot ('certificate-wheel-' + [guid]::NewGuid().ToString('N'))
    $preparedOutput = New-CertificateIsoDeploymentOutput -DurableRoot $durable -Worktree $repo -OutputRoot $output `
        -TaskId $env:CODEX_THREAD_ID -SourceCommit $ReviewedSourceCommit -PullRequestNumber ([int]$planData.pr)
    $originalOutput = $preparedOutput.Ownership
    $pins.Add($preparedOutput.Pin)
    $env:TEMP = $output
    $env:TMP = $output
    $env:PYTHONDONTWRITEBYTECODE = '1'
    $env:PYTHONPYCACHEPREFIX = Join-Path $output 'python-cache'
    $runtime = Protect-AtlasoCertificatePythonRuntime -PythonPath $PythonPath -EvidenceRoot $evidenceRoot -RequiredModules @('pycdlib', 'packaging')
    $PythonPath = $runtime.Executable
    $source = New-LifecycleSourceSnapshot -RepositoryRoot $repo -Commit $ReviewedSourceCommit `
        -DestinationRoot $output -ConsumerPins $sourcePins
    $inventory = Get-AtlasoSourceSnapshotInventory -Root $source
    $archive = @(Get-ChildItem -LiteralPath $output -Filter 'source-*.zip' -File)
    if ($archive.Count -ne 1) { throw 'The exact source archive is unavailable.' }
    $buildArguments = New-AtlasoCertificatePythonArguments -Runtime $runtime `
        -ScriptPath (Join-Path $source 'scripts/interop/certificate_iso_deployment.py')
    # The canonical owner pins and validates the complete checkout, including
    # already parsed code. Loading its archive copy beneath that checkout would
    # correctly fail its untracked-code guard. Keep its pinned canonical entrypoint;
    # the wheel builder and deployment child still use the exact immutable archive.
    $nativeOwner = Join-Path $repo 'scripts/windows/vmware/test-installation-iso.ps1'
    $nativeBefore = & $nativeOwner @nativeArguments
    $nativeBeforePath = Join-Path $output 'native-before.json'
    $recordsToPublish = @{
        'native-before.json' = $nativeBefore
        'output-owner.json' = $originalOutput
    }
    foreach ($entry in $recordsToPublish.GetEnumerator()) {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($entry.Value | ConvertTo-Json -Depth 30 -Compress))
        $writer = [IO.File]::Open((Join-Path $output $entry.Key), 'CreateNew', 'Write', 'None')
        try { $writer.Write($bytes); $writer.Flush($true) } finally { $writer.Dispose() }
    }
    if (-not $Execute) {
        Invoke-AtlasoBoundedProcess -FilePath $PythonPath -ArgumentList @($buildArguments + @(
            'inspect', '--plan', $Plan, '--output-root', $output, '--native-admission', $nativeBeforePath
        )) -TimeoutSeconds 180 -Action 'Inspect original ISO deployment identity' -DiscardOutput
        Assert-LifecycleSourcePins -Pins $sourcePins
        [pscustomobject]@{ SourceCommit = $ReviewedSourceCommit; VmxPath = $nativeBefore.VmxPath
            Inspection = Join-Path $output 'inspection.json'; OriginalOutputOwnership = $originalOutput }
        return
    }
    $wheels = Join-Path $output 'wheels'
    [void][IO.Directory]::CreateDirectory($wheels)
    # pip's own machine-readable created-wheel record binds this invocation's sole output.
    $buildOutput = Invoke-AtlasoBoundedProcess -FilePath $PythonPath -ArgumentList @(
        '-I', '-B', '-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation', '--no-cache-dir',
        '--disable-pip-version-check', '--wheel-dir', $wheels, $source
    ) -TimeoutSeconds 180 -Action 'Build admitted certificate fixture wheel'
    Assert-LifecycleSourcePins -Pins $sourcePins
    $wheel = Get-LifecycleBuiltWheel -OutputRoot $wheels -BuildOutput @($buildOutput) -ConsumerPins $sourcePins
    Invoke-AtlasoBoundedProcess -FilePath $PythonPath -ArgumentList @($buildArguments + @(
        'prepare', '--plan', $Plan, '--output-root', $output, '--source-root', $source,
        '--wheel', $wheel.FullName, '--source-archive', $archive[0].FullName,
        '--snapshot-sha256', $inventory.Sha256, '--snapshot-file-count', [string]$inventory.FileCount,
        '--native-admission', $nativeBeforePath, '--runtime-dependency-directory', $dependencies
    )) -TimeoutSeconds 180 -Action 'Admit original ISO deployment inputs' -DiscardOutput
    $requestPath = Join-Path $output 'request.json'
    $pins.Add([Atlaso.WorkstationFileIdentity]::PinOrdinaryReadFile($requestPath, $true))
    $request = Get-Content -LiteralPath $requestPath -Raw | ConvertFrom-Json -AsHashtable
    $requestHash = (Get-FileHash -LiteralPath $requestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $claim = $planData.appliance_ownership.path + '.certificate-pr-wheel-claim.json'
    $claimValue = [ordered]@{ schema = 1; task_id = $env:CODEX_THREAD_ID; repository = 'mdaneri/Atlaso'
        pr = [int]$planData.pr; source_commit = $ReviewedSourceCommit; output_owner = $originalOutput
        request_path = $requestPath; request_sha256 = $requestHash; ownership = $planData.appliance_ownership }
    $claimBytes = [Text.UTF8Encoding]::new($false).GetBytes(($claimValue | ConvertTo-Json -Depth 20 -Compress))
    $claimWriter = [IO.File]::Open($claim, 'CreateNew', 'Write', 'None')
    try { $claimWriter.Write($claimBytes); $claimWriter.Flush($true) } finally { $claimWriter.Dispose() }
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds(900)
    $jobName = 'Local\AtlasoCertificateWheel-' + [guid]::NewGuid().ToString('N')
    $bootIdentity = Get-AtlasoWindowsBootIdentity
    $controllerId = $PID
    $controllerStart = (Get-Process -Id $PID).StartTime.ToUniversalTime().ToFileTimeUtc()
    $publisher = {
        param($Job)
        $record = [ordered]@{ schema = 1; task_id = $env:CODEX_THREAD_ID; source_commit = $ReviewedSourceCommit
            process_job_name = $jobName; host_boot_identity = $bootIdentity
            child_process_id = $Job.RootProcess.Id; child_start_filetime_utc = $Job.RootProcess.StartTime.ToUniversalTime().ToFileTimeUtc()
            controller_process_id = $controllerId; controller_start_filetime_utc = $controllerStart
            deadline_utc = $deadline.ToString('o'); request_sha256 = $requestHash }
        $writer = [IO.File]::Open((Join-Path $output 'deployer-started.json'), 'CreateNew', 'Write', 'None')
        try {
            $writer.Write([Text.UTF8Encoding]::new($false).GetBytes(($record | ConvertTo-Json -Depth 10 -Compress)))
            $writer.Flush($true)
        } finally { $writer.Dispose() }
    }.GetNewClosure()
    $pwsh = (Get-Process -Id $PID).Path
    $deployArguments = @('-NoProfile', '-File', (Join-Path $source 'scripts/windows/vmware/deploy-wheel.ps1'),
        '-RepoRoot', $repo, '-AdmittedSourceRoot', $source, '-IsoFixtureDeploymentRequest', $requestPath,
        '-IsoFixtureDeploymentRequestSha256', $requestHash, '-WheelPath', $wheel.FullName,
        '-IpAddress', $request.host_address, '-VmxPath', $nativeBefore.VmxPath, '-RemoteDirectory', $request.remote_directory,
        '-RuntimeDependencyDirectory', $dependencies, '-OnePasswordEnvironmentId', $EnvironmentId,
        '-OnePasswordPython', $PythonPath, '-SkipBuild', '-SkipHelperSync', '-SkipConsoleAssetSync',
        '-SkipBootBrandingSync', '-SkipHostCheck')
    Assert-LifecycleSourcePins -Pins $sourcePins
    try {
        Invoke-AtlasoBoundedStreamingProcess -FilePath $pwsh -ArgumentList $deployArguments -TimeoutSeconds 900 `
            -Action 'Deploy original ISO certificate fixture wheel' -ProcessJobName $jobName `
            -ProcessOwnershipPublisher $publisher -DeadlineUtc $deadline -DiscardOutput
    } catch {
        $failure = [ordered]@{ schema = 1; status = 'failed-or-unknown'; task_id = $env:CODEX_THREAD_ID
            whole_job_quiescent = [bool]$_.Exception.Data['AtlasoProcessTreeTerminationProven']
            request_sha256 = $requestHash; reconciliation_required = $true }
        $writer = [IO.File]::Open((Join-Path $output 'deployer-failed.json'), 'CreateNew', 'Write', 'None')
        try {
            $writer.Write([Text.UTF8Encoding]::new($false).GetBytes(($failure | ConvertTo-Json -Compress)))
            $writer.Flush($true)
        } finally { $writer.Dispose() }
        throw 'Original-ISO deployment failed or its outcome is unknown; retain the fixture, claim and process records for reconciliation.'
    }
    Assert-LifecycleSourcePins -Pins $sourcePins
    $nativeAfter = & $nativeOwner @nativeArguments
    $terminalRecords = @{
        'native-after.json' = $nativeAfter
        'deployer-exited.json' = @{ schema = 1; exit_code = 0; whole_job_quiescent = $true; source_guards_verified = $true }
    }
    foreach ($entry in $terminalRecords.GetEnumerator()) {
        $writer = [IO.File]::Open((Join-Path $output $entry.Key), 'CreateNew', 'Write', 'None')
        try {
            $writer.Write([Text.UTF8Encoding]::new($false).GetBytes(($entry.Value | ConvertTo-Json -Depth 30 -Compress)))
            $writer.Flush($true)
        } finally { $writer.Dispose() }
    }
    Invoke-AtlasoBoundedProcess -FilePath $PythonPath -ArgumentList @($buildArguments + @(
        'finish', '--plan', $Plan, '--output-root', $output, '--native-admission', (Join-Path $output 'native-after.json')
    )) -TimeoutSeconds 180 -Action 'Validate exact deployed certificate fixture payload' -DiscardOutput
    Assert-LifecycleSourcePins -Pins $sourcePins
    [pscustomobject]@{ DeploymentReceipt = Join-Path $output 'deployment.json'
        Sha256 = (Get-FileHash -LiteralPath (Join-Path $output 'deployment.json') -Algorithm SHA256).Hash.ToLowerInvariant()
        OriginalOutputOwnership = $originalOutput }
} finally {
    if ($runtime) { foreach ($pin in $runtime.Pins) { $pin.Dispose() } }
    for ($i = $sourcePins.Count - 1; $i -ge 0; $i--) { $sourcePins[$i].Dispose() }
    for ($i = $pins.Count - 1; $i -ge 0; $i--) { $pins[$i].Dispose() }
    $env:TEMP = $savedTemp
    $env:TMP = $savedTmp
    $env:PYTHONDONTWRITEBYTECODE = $savedBytecode
    $env:PYTHONPYCACHEPREFIX = $savedPythonCache
}
