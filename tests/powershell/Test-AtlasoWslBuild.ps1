[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RepositoryRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $RepositoryRoot 'scripts\windows\common\Atlaso.WslBuild.psm1'
$contractPath = Join-Path $RepositoryRoot 'image\inventory-linux\wsl-build-contract.json'
$contract = Get-Content -LiteralPath $contractPath -Raw | ConvertFrom-Json

function Import-TestModule {
    return Import-Module $modulePath -Force -PassThru
}

function Assert-ThrowsLike {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Pattern
    )

    try {
        & $Action
    } catch {
        if ($_.Exception.Message -notlike $Pattern) {
            throw "Expected error like '$Pattern', got: $($_.Exception.Message)"
        }
        return
    }
    throw "Expected error like '$Pattern', but the command succeeded."
}

$module = Import-TestModule
& $module {
    Set-Item -Path Function:script:Get-Command -Value { return $null }
}
Assert-ThrowsLike -Action {
    Assert-AtlasoWslAvailable | Out-Null
} -Pattern '*WSL is required for Atlaso image builds*'

$failingCommand = if ($IsWindows) { Join-Path $env:SystemRoot 'System32\where.exe' } else { '/usr/bin/false' }
$module = Import-TestModule
& $module {
    param([string]$CommandPath)
    $script:AtlasoTestFailingCommand = $CommandPath
    Set-Item -Path Function:script:Get-Command -Value {
        return [pscustomobject]@{ Source = $script:AtlasoTestFailingCommand }
    }
} $failingCommand
Assert-ThrowsLike -Action {
    Assert-AtlasoWslAvailable | Out-Null
} -Pattern '*WSL is installed but unavailable or incomplete*'

$module = Import-TestModule
& $module {
    Set-Item -Path Function:script:Get-AtlasoWslDistributions -Value { return @() }
}
Assert-ThrowsLike -Action {
    Assert-AtlasoWslBuildEnvironment -Contract $contract -Distribution 'Atlaso-Build' | Out-Null
} -Pattern '*no Linux distributions are installed*'

$module = Import-TestModule
& $module {
    Set-Item -Path Function:script:Get-AtlasoWslDistributions -Value { return @('Ubuntu-24.04') }
}
Assert-ThrowsLike -Action {
    Assert-AtlasoWslBuildEnvironment -Contract $contract -Distribution 'Atlaso-Build' | Out-Null
} -Pattern "*WSL distribution 'Atlaso-Build' is not installed*"

$module = Import-TestModule
& $module {
    Set-Item -Path Function:script:Get-AtlasoWslDistributions -Value { return @('Ubuntu-24.04') }
    Set-Item -Path Function:script:Get-AtlasoWslCacheRoot -Value { return '/home/contributor/.cache/atlaso/inventory-linux' }
}
$alternate = Assert-AtlasoWslBuildEnvironment -Contract $contract -Distribution 'Ubuntu-24.04'
if ($alternate.User -ne '' -or $alternate.CacheRoot -ne '/home/contributor/.cache/atlaso/inventory-linux') {
    throw 'Compatible user-selected distribution did not retain its default user and native cache.'
}

$module = Import-TestModule
& $module {
    Set-Item -Path Function:script:Get-AtlasoWslDistributions -Value { return @('Atlaso-Build') }
    Set-Item -Path Function:script:Assert-AtlasoManagedWslContract -Value { return }
    Set-Item -Path Function:script:Get-AtlasoWslCacheRoot -Value { return '/home/atlaso-build/.cache/atlaso/inventory-linux' }
}
$managed = Assert-AtlasoWslBuildEnvironment -Contract $contract -Distribution 'Atlaso-Build'
if ($managed.User -ne 'atlaso-build' -or $managed.CacheRoot -ne '/home/atlaso-build/.cache/atlaso/inventory-linux') {
    throw 'Managed Atlaso-Build distribution did not select its pinned non-root user and native cache.'
}

Write-Output 'Atlaso WSL build module behavior tests passed.'
