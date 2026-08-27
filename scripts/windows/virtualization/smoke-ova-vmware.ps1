<#
.SYNOPSIS
Import, boot, validate, reboot, and remove one canonical OVA on VMware Workstation.
.PARAMETER OvaPath
Canonical Atlaso OVA to validate and import.
.PARAMETER Credential
Temporary appliance credential used only through the smoke helper standard-input envelope.
.PARAMETER Name
Unique smoke-test VM name.
.PARAMETER ManagementVmnet
Existing VMware vmnet mapped to the management adapter.
.PARAMETER ServiceVmnet
Existing VMware vmnet mapped to the services adapter.
.PARAMETER OutputRoot
Repository-owned directory that receives the disposable smoke VM.
.PARAMETER OvfToolPath
Optional VMware OVF Tool executable path.
.PARAMETER VmrunPath
Optional vmrun executable path.
.PARAMETER PythonPath
Optional Python executable with Paramiko installed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OvaPath,
    [Parameter(Mandatory = $true)][PSCredential]$Credential,
    [string]$Name = 'Atlaso-Ova-Smoke',
    [string]$ManagementVmnet = 'VMnet8',
    [string]$ServiceVmnet = 'VMnet1',
    [string]$OutputRoot = '',
    [string]$OvfToolPath = '',
    [string]$VmrunPath = '',
    [string]$PythonPath = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

<#
.SYNOPSIS
Returns the stable Windows file identifier for an owned smoke path.
.PARAMETER Path
Existing file or directory whose identity must be captured.
#>
function Get-AtlasoWindowsFileId {
    param([Parameter(Mandatory = $true)][string]$Path)

    $output = @(& fsutil file queryfileid $Path 2>&1)
    $fileIdMatches = @([regex]::Matches(($output -join "`n"), '0x[0-9A-Fa-f]+'))
    if ($LASTEXITCODE -ne 0 -or $fileIdMatches.Count -ne 1) {
        throw "Could not resolve one stable Windows file ID for: $Path"
    }
    return $fileIdMatches[0].Value.ToLowerInvariant()
}

<#
.SYNOPSIS
Revalidates the exact VMware smoke VM filesystem identity.
.PARAMETER DirectoryPath
Invocation-owned VM directory.
.PARAMETER VmxPath
Exact imported VMX path.
.PARAMETER Name
Expected VMware display name.
.PARAMETER DirectoryId
Captured directory file ID.
.PARAMETER VmxId
Captured VMX file ID.
#>
function Assert-AtlasoVmwareVmIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$DirectoryPath,
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$DirectoryId,
        [Parameter(Mandatory = $true)][string]$VmxId
    )

    foreach ($path in @($DirectoryPath, $VmxPath)) {
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "VMware smoke identity traverses a reparse point: $path"
        }
    }
    if ((Get-AtlasoWindowsFileId -Path $DirectoryPath) -ne $DirectoryId -or
        (Get-AtlasoWindowsFileId -Path $VmxPath) -ne $VmxId) {
        throw 'The invocation-owned VMware smoke filesystem identity changed.'
    }
    $vmxFiles = @(Get-ChildItem -LiteralPath $DirectoryPath -Filter '*.vmx' -File -Recurse -Force)
    if ($vmxFiles.Count -ne 1 -or $vmxFiles[0].FullName -ine $VmxPath) {
        throw 'The invocation-owned VMware smoke directory has an unexpected VMX set.'
    }
    $displayNamePattern = '^displayName = "' + [regex]::Escape($Name) + '"$'
    if (-not (Select-String -LiteralPath $VmxPath -Pattern $displayNamePattern -Quiet)) {
        throw 'The invocation-owned VMware smoke VMX has an unexpected display name.'
    }
}

<#
.SYNOPSIS
Snapshots every descendant path and stable file ID beneath an owned VM root.
.PARAMETER DirectoryPath
Invocation-owned VM directory to inventory.
#>
function Get-AtlasoVmwareDescendantIdentity {
    param([Parameter(Mandatory = $true)][string]$DirectoryPath)

    $identity = @{}
    foreach ($item in @(Get-ChildItem -LiteralPath $DirectoryPath -Recurse -Force)) {
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "VMware smoke descendant cannot be a reparse point: $($item.FullName)"
        }
        $relativePath = [System.IO.Path]::GetRelativePath($DirectoryPath, $item.FullName)
        $identity[$relativePath] = Get-AtlasoWindowsFileId -Path $item.FullName
    }
    return ,$identity
}

<#
.SYNOPSIS
Returns provider inventory paths that identify the captured VMX file.
.PARAMETER Paths
Raw paths returned by vmrun inventory.
.PARAMETER VmxId
Captured stable VMX file ID.
#>
function Get-AtlasoVmwareInventoryPathById {
    param(
        [Parameter(Mandatory = $true)][string[]]$Paths,
        [Parameter(Mandatory = $true)][string]$VmxId
    )

    foreach ($entry in $Paths) {
        $candidate = $entry.Trim().Trim('"')
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            $item = Get-Item -LiteralPath $candidate -Force
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
                (Get-AtlasoWindowsFileId -Path $item.FullName) -eq $VmxId) {
                $candidate
            }
        }
    }
}

<#
.SYNOPSIS
Wait for a unique VMware management neighbor bound to ethernet0 and its vmnet.
.PARAMETER VmxPath
Exact invocation-owned VMX file.
.PARAMETER ManagementVmnet
Expected vmnet mapped to ethernet0.
.PARAMETER ServiceVmnet
Expected vmnet mapped to ethernet1.
.PARAMETER ExpectedIdentity
Previously captured VMX and address identity that must remain unchanged.
.PARAMETER Deadline
Absolute readiness deadline for host-neighbor discovery.
#>
function Wait-AtlasoVmwareSmokeNetworkIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$VmxPath,
        [Parameter(Mandatory = $true)][string]$ManagementVmnet,
        [Parameter(Mandatory = $true)][string]$ServiceVmnet,
        [Parameter(Mandatory = $true)][object]$ExpectedIdentity,
        [Parameter(Mandatory = $true)][DateTimeOffset]$Deadline
    )

    while ([DateTimeOffset]::UtcNow -lt $Deadline) {
        $vmxIdentity = Get-AtlasoVmwareSmokeVmxNetworkIdentity `
            -VmxPath $VmxPath `
            -ManagementVmnet $ManagementVmnet `
            -ServiceVmnet $ServiceVmnet `
            -ExpectedIdentity $ExpectedIdentity
        $neighbors = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue)
        $identity = Resolve-AtlasoVmwareSmokeAddressIdentity `
            -VmxIdentity $vmxIdentity `
            -NetworkAdapters @(Get-NetAdapter -IncludeHidden -ErrorAction Stop) `
            -Neighbors $neighbors `
            -ExpectedIdentity $ExpectedIdentity `
            -AllowMissingAddress
        if ($identity.Address) {
            return $identity
        }
        Start-Sleep -Seconds 5
    }
    throw 'The VMware ethernet0 management MAC did not resolve to one usable IPv4 neighbor before the deadline.'
}

$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
Import-Module (Join-Path $PSScriptRoot 'Atlaso.VirtualizationSmokeIdentity.psm1') -Force
if ($Name -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$') {
    throw 'VMware smoke-test Name must be one safe filesystem component.'
}
$sourceOva = Get-Item -LiteralPath $OvaPath -Force -ErrorAction Stop
if ($sourceOva.PSIsContainer -or
    ($sourceOva.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'The VMware smoke-test OVA must be an ordinary file.'
}
$ovfTool = if ($OvfToolPath) { (Get-Item -LiteralPath $OvfToolPath -ErrorAction Stop).FullName } else {
    'C:\Program Files\VMware\VMware Workstation\OVFTool\ovftool.exe'
}
$vmrun = if ($VmrunPath) {
    (Get-Item -LiteralPath $VmrunPath -ErrorAction Stop).FullName
}
else {
    $resolvedVmrun = @(
        'C:\Program Files\VMware\VMware Workstation\vmrun.exe',
        'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $resolvedVmrun) {
        $vmrunCommand = Get-Command vmrun -ErrorAction SilentlyContinue
        $resolvedVmrun = if ($vmrunCommand) { $vmrunCommand.Source } else { '' }
    }
    if (-not $resolvedVmrun) {
        throw 'vmrun.exe was not found. Install VMware Workstation Pro or pass -VmrunPath.'
    }
    $resolvedVmrun
}
$python = if ($PythonPath) { (Get-Item -LiteralPath $PythonPath -ErrorAction Stop).FullName } else {
    (Get-Command python -ErrorAction Stop).Source
}
foreach ($executable in @($ovfTool, $vmrun, $python)) {
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "Required VMware smoke-test executable was not found: $executable"
    }
}

$allowedRoot = [System.IO.Path]::GetFullPath((Join-Path $repoRoot 'artifacts\virtualization-smoke'))
$resolvedRoot = if ($OutputRoot) {
    [System.IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputRoot))
}
else {
    $allowedRoot
}
$allowedPrefix = $allowedRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
if ($resolvedRoot -ne $allowedRoot -and
    -not $resolvedRoot.StartsWith($allowedPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "VMware smoke output must stay beneath the repository-owned root: $allowedRoot"
}
if (Test-Path -LiteralPath $resolvedRoot) {
    $currentPath = $resolvedRoot
    while ($true) {
        $currentItem = Get-Item -LiteralPath $currentPath -Force
        if (($currentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "VMware smoke output cannot traverse a reparse point: $currentPath"
        }
        if ($currentPath -ieq $allowedRoot) { break }
        $currentPath = [System.IO.Directory]::GetParent($currentPath).FullName
    }
}
$vmRoot = [System.IO.Path]::GetFullPath((Join-Path $resolvedRoot $Name))
$resolvedRootPrefix = $resolvedRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) +
    [System.IO.Path]::DirectorySeparatorChar
if (-not $vmRoot.StartsWith($resolvedRootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'VMware smoke VM directory must be a strict descendant of its owned output root.'
}
$vmxPath = [System.IO.Path]::GetFullPath((Join-Path $vmRoot "$Name.vmx"))
$validationRoot = Join-Path $resolvedRoot ('.ova-validation-' + [guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $vmRoot) {
    throw "VMware smoke-test destination already exists: $vmRoot"
}
New-Item -ItemType Directory -Path $vmRoot -Force | Out-Null
New-Item -ItemType Directory -Path $validationRoot -Force | Out-Null
foreach ($ownedDirectory in @($vmRoot, $validationRoot)) {
    $ownedItem = Get-Item -LiteralPath $ownedDirectory -Force
    if (($ownedItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "VMware smoke owned directory cannot be a reparse point: $ownedDirectory"
    }
}
$vmStarted = $false
$vmRootId = Get-AtlasoWindowsFileId -Path $vmRoot
$vmxId = ''
$ownedDescendantIds = $null
$ownedRegisteredPaths = @()
try {
    $contractOutput = @(& $python `
            (Join-Path $repoRoot 'scripts\virtualization\validate_ova.py') `
            $sourceOva.FullName `
            '--extract-directory' `
            (Join-Path $validationRoot 'members') 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "Canonical OVA validation failed before VMware smoke import: $($contractOutput -join [Environment]::NewLine)"
    }
    $contract = ($contractOutput -join "`n") | ConvertFrom-Json -ErrorAction Stop
    $passwordText = $Credential.GetNetworkCredential().Password
    $fqdn = ($Name.ToLowerInvariant() -replace '[^a-z0-9-]', '-') + '.smoke.atlaso.internal'
    $ovfToolConfigPath = Join-Path $validationRoot 'ovftool.cfg'
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $configAcl = [Security.AccessControl.DirectorySecurity]::new()
    $configAcl.SetOwner($currentSid)
    $configAcl.SetAccessRuleProtection($true, $false)
    $configAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $currentSid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow))
    Set-Acl -LiteralPath $validationRoot -AclObject $configAcl
    $ovfToolConfig = @(
        "prop:atlaso.fqdn=$fqdn",
        "prop:atlaso.admin_password=$passwordText",
        "prop:atlaso.root_password=$passwordText"
    )
    try {
        # OVF Tool's config file is the supported non-argv option channel. The
        # containing directory admits only this runner identity and the file is
        # removed immediately after the bounded import attempt.
        [IO.File]::WriteAllLines(
            $ovfToolConfigPath,
            $ovfToolConfig,
            [Text.UTF8Encoding]::new($false))
        & $ovfTool `
            '--acceptAllEulas' `
            "--configFile=$ovfToolConfigPath" `
            "--name=$Name" `
            "--net:Atlaso Management Network=$ManagementVmnet" `
            "--net:Atlaso Services Network=$ServiceVmnet" `
            $sourceOva.FullName `
            $vmxPath
    }
    finally {
        $ovfToolConfig = $null
        $passwordText = $null
        if (Test-Path -LiteralPath $ovfToolConfigPath) {
            Remove-Item -LiteralPath $ovfToolConfigPath -Force
        }
    }
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $vmxPath -PathType Leaf)) {
        throw 'VMware OVF Tool did not create the expected disposable VMX.'
    }
    $vmRootId = Get-AtlasoWindowsFileId -Path $vmRoot
    $vmxId = Get-AtlasoWindowsFileId -Path $vmxPath
    Assert-AtlasoVmwareVmIdentity -DirectoryPath $vmRoot -VmxPath $vmxPath `
        -Name $Name -DirectoryId $vmRootId -VmxId $vmxId
    $providerIdentity = Get-AtlasoVmwareSmokeVmxNetworkIdentity `
        -VmxPath $vmxPath `
        -ManagementVmnet $ManagementVmnet `
        -ServiceVmnet $ServiceVmnet
    & $vmrun -T ws start $vmxPath nogui | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw 'vmrun could not start the imported OVA.'
    }
    $vmStarted = $true
    $hostKeyDeadline = [DateTimeOffset]::UtcNow.AddMinutes(15)
    $expectedHostKey = ''
    while ([DateTimeOffset]::UtcNow -lt $hostKeyDeadline -and
        $expectedHostKey -notmatch '^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$') {
        $expectedHostKey = [string](& $vmrun -T ws readVariable $vmxPath guestVar `
                guestinfo.atlaso.test_vm_ssh_host_ed25519_public_key 2>$null)
        $expectedHostKey = $expectedHostKey.Trim()
        if ($expectedHostKey -notmatch '^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$') {
            Start-Sleep -Seconds 5
        }
    }
    if ($expectedHostKey -notmatch '^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$') {
        throw 'VMware guest-info did not publish the regenerated Ed25519 SSH host key.'
    }
    $networkIdentity = Wait-AtlasoVmwareSmokeNetworkIdentity `
        -VmxPath $vmxPath `
        -ManagementVmnet $ManagementVmnet `
        -ServiceVmnet $ServiceVmnet `
        -ExpectedIdentity $providerIdentity `
        -Deadline ([DateTimeOffset]::UtcNow.AddMinutes(15))
    $vmxIdentity = Get-AtlasoVmwareSmokeVmxNetworkIdentity `
        -VmxPath $vmxPath `
        -ManagementVmnet $ManagementVmnet `
        -ServiceVmnet $ServiceVmnet `
        -ExpectedIdentity $networkIdentity
    $networkIdentity = Resolve-AtlasoVmwareSmokeAddressIdentity `
        -VmxIdentity $vmxIdentity `
        -NetworkAdapters @(Get-NetAdapter -IncludeHidden -ErrorAction Stop) `
        -Neighbors @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop) `
        -ExpectedIdentity $networkIdentity
    $secret = @{
        username = $Credential.UserName
        password = $Credential.GetNetworkCredential().Password
    } | ConvertTo-Json -Compress
    $initialOutput = @($secret | & $python (Join-Path $repoRoot 'scripts\virtualization\smoke_guest_ssh.py') `
            '--host' ([string]$networkIdentity.Address) `
            '--host-key' $expectedHostKey `
            '--platform' 'vmware' `
            '--phase' 'initial')
    if ($LASTEXITCODE -ne 0) {
        throw 'Initial VMware OVA guest validation failed.'
    }
    $tlsFingerprint = [string]($initialOutput | Select-Object -Last 1)
    if ($tlsFingerprint -notmatch '^[0-9a-f]{64}$') {
        throw 'Initial VMware guest validation did not return one canonical TLS fingerprint.'
    }
    $networkIdentity = Wait-AtlasoVmwareSmokeNetworkIdentity `
        -VmxPath $vmxPath `
        -ManagementVmnet $ManagementVmnet `
        -ServiceVmnet $ServiceVmnet `
        -ExpectedIdentity $networkIdentity `
        -Deadline ([DateTimeOffset]::UtcNow.AddMinutes(15))
    $postOutput = @($secret | & $python (Join-Path $repoRoot 'scripts\virtualization\smoke_guest_ssh.py') `
            '--host' ([string]$networkIdentity.Address) `
            '--host-key' $expectedHostKey `
            '--platform' 'vmware' `
            '--phase' 'post-reboot' `
            '--expected-tls-fingerprint' $tlsFingerprint)
    if ($LASTEXITCODE -ne 0 -or
        ($postOutput -join "`n") -notmatch 'Atlaso vmware guest smoke test passed\.') {
        throw 'Post-reboot VMware OVA guest validation failed.'
    }
    $vmxIdentity = Get-AtlasoVmwareSmokeVmxNetworkIdentity `
        -VmxPath $vmxPath `
        -ManagementVmnet $ManagementVmnet `
        -ServiceVmnet $ServiceVmnet `
        -ExpectedIdentity $networkIdentity
    Resolve-AtlasoVmwareSmokeAddressIdentity `
        -VmxIdentity $vmxIdentity `
        -NetworkAdapters @(Get-NetAdapter -IncludeHidden -ErrorAction Stop) `
        -Neighbors @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop) `
        -ExpectedIdentity $networkIdentity | Out-Null
}
finally {
    $vmRootSafeToRemove = $true
    $cleanupFailure = ''
    if (-not $vmxId -and (Test-Path -LiteralPath $vmRoot)) {
        try {
            $rootItem = Get-Item -LiteralPath $vmRoot -Force
            if (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
                (Get-AtlasoWindowsFileId -Path $vmRoot) -ne $vmRootId) {
                throw 'The pre-provider VMware smoke root identity changed.'
            }
            $partialDescendants = Get-AtlasoVmwareDescendantIdentity -DirectoryPath $vmRoot
            $verifiedPartialDescendants = Get-AtlasoVmwareDescendantIdentity -DirectoryPath $vmRoot
            $partialChanged = $partialDescendants.Count -ne $verifiedPartialDescendants.Count -or
                @($verifiedPartialDescendants.Keys | Where-Object {
                        -not $partialDescendants.ContainsKey($_) -or
                        $partialDescendants[$_] -ne $verifiedPartialDescendants[$_]
                    }).Count -ne 0
            if ($partialChanged) {
                throw 'The pre-provider VMware smoke descendant identity changed.'
            }
            Remove-Item -LiteralPath $vmRoot -Recurse -Force
        }
        catch {
            $cleanupFailure = "Partial VMware smoke output was preserved. $($_.Exception.Message)"
        }
        $vmRootSafeToRemove = $false
    }
    if ($vmxId -and $vmRootId) {
        try {
            Assert-AtlasoVmwareVmIdentity -DirectoryPath $vmRoot -VmxPath $vmxPath `
                -Name $Name -DirectoryId $vmRootId -VmxId $vmxId
        }
        catch {
            $vmRootSafeToRemove = $false
            $cleanupFailure = "VMware smoke identity changed; its files were preserved. $($_.Exception.Message)"
        }
    }
    if ($vmStarted -and $vmRootSafeToRemove) {
        & $vmrun -T ws stop $vmxPath hard 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            $vmRootSafeToRemove = $false
            $cleanupFailure = 'vmrun could not stop the disposable VMware smoke VM; its files were preserved.'
        }
    }
    if ($vmRootSafeToRemove -and (Test-Path -LiteralPath $vmxPath)) {
        $runningVmPaths = @(& $vmrun -T ws list 2>$null)
        $runningInventoryExitCode = $LASTEXITCODE
        $runningOwnedPaths = @(Get-AtlasoVmwareInventoryPathById -Paths $runningVmPaths -VmxId $vmxId)
        if ($runningInventoryExitCode -ne 0 -or $runningOwnedPaths.Count -ne 0) {
            $vmRootSafeToRemove = $false
            $cleanupFailure = 'vmrun could not prove the disposable VMware smoke VM was stopped; its files were preserved.'
        }
    }
    if ($vmRootSafeToRemove -and (Test-Path -LiteralPath $vmxPath)) {
        Assert-AtlasoVmwareVmIdentity -DirectoryPath $vmRoot -VmxPath $vmxPath `
            -Name $Name -DirectoryId $vmRootId -VmxId $vmxId
        $registeredBeforeDelete = @(& $vmrun -T ws listRegisteredVM 2>$null)
        $registeredBeforeDeleteExitCode = $LASTEXITCODE
        if ($registeredBeforeDeleteExitCode -ne 0) {
            throw 'vmrun could not inventory registered VMs before deletion; files were preserved.'
        }
        $ownedRegisteredPaths = @(
            Get-AtlasoVmwareInventoryPathById -Paths $registeredBeforeDelete -VmxId $vmxId
        )
        $ownedDescendantIds = Get-AtlasoVmwareDescendantIdentity -DirectoryPath $vmRoot
        & $vmrun -T ws deleteVM $vmxPath 2>$null | Out-Null
        if ($LASTEXITCODE -ne 0) {
            $vmRootSafeToRemove = $false
            $cleanupFailure = 'vmrun could not delete the disposable VMware smoke VM; its files were preserved.'
        }
    }
    if ($vmRootSafeToRemove) {
        $registeredVmPaths = @(& $vmrun -T ws listRegisteredVM 2>$null)
        $registeredInventoryExitCode = $LASTEXITCODE
        $registeredOwnedAlias = @($registeredVmPaths | Where-Object {
                $candidate = $_.Trim().Trim('"')
                $ownedRegisteredPaths -icontains $candidate
            })
        if ($registeredInventoryExitCode -ne 0 -or
            (Test-Path -LiteralPath $vmxPath) -or
            $registeredOwnedAlias.Count -ne 0) {
            $vmRootSafeToRemove = $false
            $cleanupFailure = 'vmrun could not prove the disposable VMware smoke VM was deleted; its files were preserved.'
        }
    }
    if ($vmRootSafeToRemove -and (Test-Path -LiteralPath $vmRoot)) {
        $rootItem = Get-Item -LiteralPath $vmRoot -Force
        $currentDescendantIds = Get-AtlasoVmwareDescendantIdentity -DirectoryPath $vmRoot
        $descendantChanged = @($currentDescendantIds.Keys | Where-Object {
                -not $ownedDescendantIds.ContainsKey($_) -or
                $ownedDescendantIds[$_] -ne $currentDescendantIds[$_]
            }).Count -ne 0
        if (($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            (Get-AtlasoWindowsFileId -Path $vmRoot) -ne $vmRootId -or
            $descendantChanged -or
            @(Get-ChildItem -LiteralPath $vmRoot -Filter '*.vmx' -File -Recurse -Force).Count -ne 0) {
            throw 'VMware smoke root identity changed after provider deletion; its files were preserved.'
        }
        Remove-Item -LiteralPath $vmRoot -Recurse -Force
    }
    if (Test-Path -LiteralPath $validationRoot) {
        Remove-Item -LiteralPath $validationRoot -Recurse -Force
    }
    if ($cleanupFailure) {
        throw $cleanupFailure
    }
}

Write-Host "Atlaso VMware OVA smoke test passed for $Name."
