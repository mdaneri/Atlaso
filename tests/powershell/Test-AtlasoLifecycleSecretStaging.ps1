<#
.SYNOPSIS
Check inherited initializer ACL admission and private lifecycle bundle ACL refusal without secrets.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../../scripts/windows/vmware/Atlaso.LifecycleSecretStaging.ps1')
$current = [Security.Principal.WindowsIdentity]::GetCurrent().User
$system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$everyone = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')

$inheritedParent = [Security.AccessControl.DirectorySecurity]::new()
$inheritedParent.SetOwner($current)
$inheritedParent.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    $current, [Security.AccessControl.FileSystemRights]::FullControl,
    [Security.AccessControl.AccessControlType]::Allow
))
$inheritedParent.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    $everyone, [Security.AccessControl.FileSystemRights]::ReadAndExecute,
    [Security.AccessControl.AccessControlType]::Allow
))
if ($inheritedParent.AreAccessRulesProtected) { throw 'The parent fixture unexpectedly disables inheritance.' }
Assert-AtlasoLifecycleStagingParentAcl -Acl $inheritedParent -CurrentSid $current

$newParentAcl = New-AtlasoLifecyclePrivateDirectoryAcl -CurrentSid $current
Assert-AtlasoLifecyclePrivateStagingAcl -Acl $newParentAcl -CurrentSid $current
Assert-AtlasoLifecycleStagingParentAcl -Acl $newParentAcl -CurrentSid $current

$unsafeParent = [Security.AccessControl.DirectorySecurity]::new()
$unsafeParent.SetOwner($current)
$unsafeParent.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    $everyone, [Security.AccessControl.FileSystemRights]::Modify,
    [Security.AccessControl.AccessControlType]::Allow
))
try {
    Assert-AtlasoLifecycleStagingParentAcl -Acl $unsafeParent -CurrentSid $current
    throw 'An untrusted parent writer was admitted.'
} catch {
    if ($_.Exception.Message -notlike '*untrusted principal*') { throw }
}

$privateChild = [Security.AccessControl.DirectorySecurity]::new()
$privateChild.SetOwner($current)
$privateChild.SetAccessRuleProtection($true, $false)
foreach ($sid in @($current, $system)) {
    $privateChild.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $sid, [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Allow
    ))
}
Assert-AtlasoLifecyclePrivateStagingAcl -Acl $privateChild -CurrentSid $current

$inheritedChild = [Security.AccessControl.DirectorySecurity]::new()
$inheritedChild.SetOwner($current)
foreach ($sid in @($current, $system)) {
    $inheritedChild.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $sid, [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Allow
    ))
}
try {
    Assert-AtlasoLifecyclePrivateStagingAcl -Acl $inheritedChild -CurrentSid $current
    throw 'An inherited bundle directory was admitted.'
} catch {
    if ($_.Exception.Message -notlike '*disabled inheritance*') { throw }
}

$unsafeChild = [Security.AccessControl.DirectorySecurity]::new()
$unsafeChild.SetOwner($current)
$unsafeChild.SetAccessRuleProtection($true, $false)
foreach ($sid in @($current, $system)) {
    $unsafeChild.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $sid, [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Allow
    ))
}
$unsafeChild.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
    $everyone, [Security.AccessControl.FileSystemRights]::ReadData,
    [Security.AccessControl.AccessControlType]::Allow
))
try {
    Assert-AtlasoLifecyclePrivateStagingAcl -Acl $unsafeChild -CurrentSid $current
    throw 'An extra bundle directory reader was admitted.'
} catch {
    if ($_.Exception.Message -notlike '*outside the current user and SYSTEM*') { throw }
}

'Lifecycle staging ACL checks passed.'
