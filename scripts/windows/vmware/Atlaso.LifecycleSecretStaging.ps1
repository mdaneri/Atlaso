<#
.SYNOPSIS
Validate and prepare checkout-local private staging for lifecycle SecureString bundles.
#>

<#
.SYNOPSIS
Accept an inherited checkout-local parent ACL only when no untrusted principal can mutate children.
.PARAMETER Acl
Directory ACL to inspect without changing it.
.PARAMETER CurrentSid
Current Windows user's SID.
#>
function Assert-AtlasoLifecycleStagingParentAcl {
    param(
        [Parameter(Mandatory)][Security.AccessControl.DirectorySecurity]$Acl,
        [Parameter(Mandatory)][Security.Principal.SecurityIdentifier]$CurrentSid
    )

    $ownerSid = $Acl.GetOwner([Security.Principal.SecurityIdentifier])
    if (-not $ownerSid.Equals($CurrentSid)) {
        throw 'Task-local credential parent must be owned by the current user.'
    }
    $privileged = @($CurrentSid.Value, 'S-1-5-18', 'S-1-5-32-544', 'S-1-3-0')
    $writeRights = [Security.AccessControl.FileSystemRights]::Write -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $Acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            ($rule.FileSystemRights -band $writeRights) -ne 0 -and
            $rule.IdentityReference.Value -notin $privileged) {
            throw 'Task-local credential parent allows an untrusted principal to mutate children.'
        }
    }
}

<#
.SYNOPSIS
Require protected current-user-and-SYSTEM ACLs on the lifecycle bundle directory or file.
.PARAMETER Acl
File or directory ACL to inspect.
.PARAMETER CurrentSid
Current Windows user's SID.
#>
function Assert-AtlasoLifecyclePrivateStagingAcl {
    param(
        [Parameter(Mandatory)][Security.AccessControl.FileSystemSecurity]$Acl,
        [Parameter(Mandatory)][Security.Principal.SecurityIdentifier]$CurrentSid
    )

    if (-not $Acl.AreAccessRulesProtected -or
        -not $Acl.GetOwner([Security.Principal.SecurityIdentifier]).Equals($CurrentSid)) {
        throw 'Lifecycle secret staging must have current-user ownership and disabled inheritance.'
    }
    $seen = @{}
    foreach ($rule in $Acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        $sid = $rule.IdentityReference.Value
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $sid -notin @($CurrentSid.Value, 'S-1-5-18')) {
            throw 'Lifecycle secret staging grants access outside the current user and SYSTEM.'
        }
        if (($rule.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq
            [Security.AccessControl.FileSystemRights]::FullControl) {
            $seen[$sid] = $true
        }
    }
    if (-not $seen.ContainsKey($CurrentSid.Value) -or -not $seen.ContainsKey('S-1-5-18')) {
        throw 'Lifecycle secret staging lacks current-user or SYSTEM full control.'
    }
}

<#
.SYNOPSIS
Build a private ACL before publishing a new lifecycle staging directory.
.PARAMETER CurrentSid
Current Windows user's SID.
#>
function New-AtlasoLifecyclePrivateDirectoryAcl {
    param([Parameter(Mandatory)][Security.Principal.SecurityIdentifier]$CurrentSid)

    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($CurrentSid)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($CurrentSid, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        ))
    }
    return $acl
}

<#
.SYNOPSIS
Create and verify private checkout-local staging directories, or verify existing ones.
.PARAMETER RepositoryRoot
Exact task checkout that owns the `.atlaso-local` parent.
#>
function Initialize-AtlasoLifecycleSecretBundleRoot {
    param([Parameter(Mandatory)][string]$RepositoryRoot)

    $parent = Join-Path $RepositoryRoot '.atlaso-local'
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    if (-not (Test-Path -LiteralPath $parent)) {
        $repositoryItem = Get-Item -LiteralPath $RepositoryRoot -Force -ErrorAction Stop
        if (-not $repositoryItem.PSIsContainer -or
            ($repositoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'Lifecycle credential checkout must be an ordinary directory.'
        }
        Assert-AtlasoLifecycleStagingParentAcl -Acl (Get-Acl -LiteralPath $RepositoryRoot) -CurrentSid $currentSid
        # No secret is published while the new Git-ignored parent inherits its
        # checkout ACL. Protect and verify it before creating the child.
        $null = New-Item -ItemType Directory -Path $parent -ErrorAction Stop
        Set-Acl -LiteralPath $parent -AclObject (New-AtlasoLifecyclePrivateDirectoryAcl -CurrentSid $currentSid)
    }
    $parentItem = Get-Item -LiteralPath $parent -Force -ErrorAction Stop
    if (-not $parentItem.PSIsContainer -or
        ($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Task-local credential parent must be an ordinary directory.'
    }
    Assert-AtlasoLifecycleStagingParentAcl -Acl (Get-Acl -LiteralPath $parent) -CurrentSid $currentSid

    $bundleRoot = Join-Path $parent 'lifecycle-secret-bundles'
    $newDirectory = -not (Test-Path -LiteralPath $bundleRoot)
    if ($newDirectory) {
        # No secret is written until the new child has a verified private ACL.
        $null = New-Item -ItemType Directory -Path $bundleRoot -ErrorAction Stop
        Set-Acl -LiteralPath $bundleRoot -AclObject (New-AtlasoLifecyclePrivateDirectoryAcl -CurrentSid $currentSid)
    }
    $bundleItem = Get-Item -LiteralPath $bundleRoot -Force -ErrorAction Stop
    if (-not $bundleItem.PSIsContainer -or
        ($bundleItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Lifecycle secret staging path must be an ordinary directory.'
    }
    Assert-AtlasoLifecyclePrivateStagingAcl -Acl (Get-Acl -LiteralPath $bundleRoot) -CurrentSid $currentSid
    return $bundleRoot
}

<#
.SYNOPSIS
Protect and verify one newly exported lifecycle SecureString bundle before a child can read it.
.PARAMETER Path
Exact new bundle file beneath the verified private directory.
#>
function Protect-AtlasoLifecycleSecretBundleFile {
    param([Parameter(Mandatory)][string]$Path)

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Lifecycle secret bundle must be an ordinary file.'
    }
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = [Security.AccessControl.FileSecurity]::new()
    $acl.SetOwner($currentSid)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @($currentSid, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
            $sid, [Security.AccessControl.FileSystemRights]::FullControl,
            [Security.AccessControl.AccessControlType]::Allow
        ))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
    Assert-AtlasoLifecyclePrivateStagingAcl -Acl (Get-Acl -LiteralPath $Path) -CurrentSid $currentSid
}
