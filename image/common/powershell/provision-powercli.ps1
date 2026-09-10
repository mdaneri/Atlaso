<#
.SYNOPSIS
Install or verify the complete reviewed image PowerCLI dependency closure.
.PARAMETER Mode
Install downloads exact modules, Validate checks a bundle, and Verify imports it.
.PARAMETER ModuleRoot
Versioned module directory to install or validate.
.PARAMETER LockPath
Reviewed complete module lock accompanying this script.
.PARAMETER SuiteVersion
Requested suite version; it must agree with the reviewed lock.
.PARAMETER ConfigureCeip
Set the appliance-wide CEIP default before verifying it.
#>
[CmdletBinding()]
param(
    [ValidateSet('Install', 'Validate', 'Verify')]
    [string]$Mode = 'Verify',
    [string]$ModuleRoot = '/usr/local/share/powershell/Modules',
    [string]$LockPath = (Join-Path $PSScriptRoot 'powercli-lock.json'),
    [string]$SuiteVersion = $env:ATLASO_POWERCLI_VERSION,
    [switch]$ConfigureCeip
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ModuleRoot = [System.IO.Path]::GetFullPath($ModuleRoot)
$lock = Get-Content -LiteralPath $LockPath -Raw | ConvertFrom-Json -AsHashtable
if ($lock.schema_version -ne 1 -or $lock.modules.Count -eq 0 -or
    $lock.modules['VCF.PowerCLI'] -ne $lock.suite_version -or
    ($SuiteVersion -and $SuiteVersion -ne $lock.suite_version)) {
    throw 'PowerCLI requested version does not match the complete reviewed lock.'
}
foreach ($name in $lock.modules.Keys) {
    if ($name -notmatch '^(VCF|VMware)\.[A-Za-z0-9.]+$' -or
        $lock.modules[$name] -notmatch '^\d+\.\d+\.\d+(\.\d+)?$') {
        throw 'Invalid PowerCLI lock entry.'
    }
}

function Test-PowerCliBundle {
    <#
    .SYNOPSIS
    Reject missing, mixed, or incompatible module versions without importing vendor code.
    .PARAMETER Root
    Directory containing the versioned PowerCLI modules.
    #>
    param([string]$Root)

    $manifests = @{}
    foreach ($name in ($lock.modules.Keys | Sort-Object)) {
        $version = $lock.modules[$name]
        $directory = Join-Path $Root $name
        $versions = @(Get-ChildItem -LiteralPath $directory -Directory)
        if ($versions.Count -ne 1 -or $versions[0].Name -ne $version) {
            throw "PowerCLI bundle requires only ${name} ${version}; found $($versions.Name -join ', ')."
        }
        $path = Join-Path $directory "$version/$name.psd1"
        $manifest = Import-PowerShellDataFile -LiteralPath $path
        if ([version]$manifest.ModuleVersion -ne [version]$version) {
            throw "PowerCLI manifest version mismatch: $name $version."
        }
        $manifests[$name] = $manifest
    }
    # Validate the vendor's declarations, never rewrite them to make a lock fit.
    foreach ($name in $manifests.Keys) {
        $manifest = $manifests[$name]
        foreach ($requirement in @($manifest['RequiredModules'])) {
            if ($null -eq $requirement) { continue }
            if ($requirement -is [string]) {
                $dependency = $requirement
                $specification = @{}
            } else {
                $dependency = $requirement.ModuleName
                $specification = $requirement
            }
            if (-not $lock.modules.ContainsKey($dependency)) {
                throw "PowerCLI lock omits dependency $dependency required by $name."
            }
            $selected = [version]$lock.modules[$dependency]
            foreach ($constraint in @('RequiredVersion', 'ModuleVersion', 'MaximumVersion')) {
                if (-not $specification.ContainsKey($constraint)) { continue }
                $bound = [version]$specification[$constraint]
                if (($constraint -eq 'RequiredVersion' -and $selected -ne $bound) -or
                    ($constraint -eq 'ModuleVersion' -and $selected -lt $bound) -or
                    ($constraint -eq 'MaximumVersion' -and $selected -gt $bound)) {
                    throw "PowerCLI locked $dependency $selected violates $name $constraint $bound."
                }
            }
            if ($specification.ContainsKey('GUID') -and
                [guid]$specification.GUID -ne [guid]$manifests[$dependency].GUID) {
                throw "PowerCLI dependency GUID mismatch: $name requires $dependency."
            }
        }
    }
}

if ($Mode -eq 'Install') {
    # Photon does not bundle PSResourceGet. Extract exact Gallery packages with
    # built-in .NET APIs, retaining publisher manifests, catalogs and signatures.
    New-Item -ItemType Directory -Path $ModuleRoot -Force | Out-Null
    foreach ($name in ($lock.modules.Keys | Sort-Object)) {
        $version = $lock.modules[$name]
        $destination = Join-Path $ModuleRoot "$name/$version"
        if (Test-Path -LiteralPath $destination) {
            throw "PowerCLI install destination already exists: $name $version."
        }
        $archive = Join-Path $ModuleRoot ".powercli-$([guid]::NewGuid().ToString('N')).nupkg"
        Write-Host "Saving locked PowerCLI module $name $version"
        try {
            Invoke-WebRequest -Uri "https://www.powershellgallery.com/api/v2/package/$name/$version" `
                -OutFile $archive -TimeoutSec 300
            [System.IO.Compression.ZipFile]::ExtractToDirectory($archive, $destination)
        } finally {
            if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }
        }
    }
}
Test-PowerCliBundle -Root $ModuleRoot
if ($Mode -ne 'Verify') { return }

try {
    # A user-local or side-by-side module must not shadow the image's closure.
    foreach ($name in ($lock.modules.Keys | Sort-Object)) {
        $expected = (Resolve-Path -LiteralPath (Join-Path $ModuleRoot "$name/$($lock.modules[$name])/$name.psd1")).Path
        $available = @(Get-Module -Name $name -ListAvailable)
        if ($available.Count -ne 1 -or $available[0].Path -ne $expected) {
            throw "PowerCLI discovery is ambiguous or outside the locked tree: $name."
        }
    }
    Import-Module (Join-Path $ModuleRoot "VCF.PowerCLI/$($lock.suite_version)/VCF.PowerCLI.psd1") -Force
    foreach ($name in ($lock.modules.Keys | Sort-Object)) {
        $loaded = @(Get-Module -Name $name)
        if ($loaded.Count -ne 1 -or $loaded[0].Version -ne [version]$lock.modules[$name]) {
            throw "PowerCLI loaded version differs from the lock: $name."
        }
        Write-Host "Loaded locked PowerCLI module $name $($loaded[0].Version)"
    }
    if ($ConfigureCeip) {
        Set-PowerCLIConfiguration -ParticipateInCeip $false -Scope AllUsers -Confirm:$false | Out-Null
        # PowerCLI caches CEIP at import; its setter requires a restart before
        # readback. Prove persistence in a fresh process, never accept cached null.
        $executable = Join-Path $PSHOME $(if ($IsWindows) { 'pwsh.exe' } else { 'pwsh' })
        & $executable -NoLogo -NoProfile -NonInteractive -File $PSCommandPath `
            -Mode Verify -ModuleRoot $ModuleRoot -LockPath $LockPath -SuiteVersion $lock.suite_version
        if ($LASTEXITCODE -ne 0) { throw 'Fresh-process PowerCLI CEIP verification failed.' }
        return
    }
    $configured = Get-PowerCLIConfiguration -Scope AllUsers
    if ($null -eq $configured.ParticipateInCEIP -or [bool]$configured.ParticipateInCEIP) {
        throw 'PowerCLI appliance-wide CEIP default is not disabled.'
    }
    Get-Command Connect-VIServer -ErrorAction Stop | Out-Null
    Write-Host "VCF.PowerCLI $($lock.suite_version) verified as $([Environment]::UserName) with appliance-wide CEIP disabled"
} catch {
    # Bound diagnostics to public module identities, never environment or configuration data.
    Get-Module -Name @($lock.modules.Keys) | Select-Object -First 100 | ForEach-Object {
        Write-Host "PowerCLI failure inventory: $($_.Name) $($_.Version)"
    }
    throw
}
