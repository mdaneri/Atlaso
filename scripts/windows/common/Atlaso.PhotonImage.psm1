<#
.SYNOPSIS
Provide shared Photon image-build helpers for supported Atlaso hypervisors.
#>

Set-StrictMode -Version Latest

<#
.SYNOPSIS
Resolve a repository-relative or absolute path.
.PARAMETER Path
Path to resolve.
#>
function Resolve-AtlasoRepoPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Resolve-Path -LiteralPath $Path).Path
}

<#
.SYNOPSIS
Return the host address from a builder CIDR.
.PARAMETER Cidr
Builder address in CIDR notation.
#>
function Get-AtlasoBuilderAddress {
    param([string]$Cidr)
    if ([string]::IsNullOrWhiteSpace($Cidr)) {
        return ''
    }
    return ($Cidr -split '/', 2)[0]
}

<#
.SYNOPSIS
Return usable host IPv4 DNS servers.
.PARAMETER ExcludedInterfaceAlias
Interface whose DNS servers must be excluded.
#>
function Get-AtlasoHostIpv4DnsServers {
    param([string]$ExcludedInterfaceAlias = 'vEthernet (Atlaso-Mgmt)')

    $dnsRows = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue
    $servers = foreach ($row in $dnsRows) {
        if ($row.InterfaceAlias -eq $ExcludedInterfaceAlias) {
            continue
        }
        foreach ($server in $row.ServerAddresses) {
            if ([string]::IsNullOrWhiteSpace($server)) {
                continue
            }
            if ($server -eq '0.0.0.0' -or $server -like '127.*' -or $server -like '169.254.*') {
                continue
            }
            $server
        }
    }

    return @($servers | Select-Object -Unique)
}

<#
.SYNOPSIS
Encode a string as UTF-8 Base64.
.PARAMETER Value
String to encode.
#>
function ConvertTo-AtlasoUtf8Base64 {
    param([AllowEmptyString()][string]$Value)

    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($Value)
    return [System.Convert]::ToBase64String($bytes)
}

<#
.SYNOPSIS
Write the canonical Photon kickstart document.
.PARAMETER Path
Destination JSON path.
.PARAMETER RootPassword
Photon root password embedded for installation.
.PARAMETER BuildPassword
Temporary image-build account password.
.PARAMETER BuildUsername
Temporary image-build account name.
.PARAMETER StaticAddress
Optional builder static address.
.PARAMETER StaticNetmask
Optional builder static netmask.
.PARAMETER StaticGateway
Optional builder static gateway.
.PARAMETER StaticDns
Optional builder DNS servers.
.PARAMETER AdditionalPackages
Provider-specific Photon packages.
.PARAMETER PostInstallCommands
Provider-specific post-install commands.
.PARAMETER InstallDiskLayout
Provider disk-discovery policy used by the installer.
#>
function New-AtlasoPhotonKickstart {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][SecureString]$RootPassword,
        [Parameter(Mandatory = $true)][SecureString]$BuildPassword,
        [Parameter(Mandatory = $true)][string]$BuildUsername,
        [string]$StaticAddress,
        [string]$StaticNetmask,
        [string]$StaticGateway,
        [string[]]$StaticDns = @(),
        [string[]]$AdditionalPackages = @(),
        [string[]]$PostInstallCommands = @(),
        [ValidateSet('default', 'vmware-workstation')]
        [string]$InstallDiskLayout = 'default'
    )

    # Photon kickstart JSON requires plaintext at its serialization boundary. Keep
    # that representation local to this function instead of accepting it from callers.
    $rootPasswordText = ConvertFrom-SecureString -SecureString $RootPassword -AsPlainText
    $buildPasswordText = ConvertFrom-SecureString -SecureString $BuildPassword -AsPlainText

    try {
        $network = if ($StaticAddress) {
        $nameserver = if ($StaticDns.Count -gt 0) { $StaticDns[0] } else { '1.1.1.1' }
        [ordered]@{
            type       = 'static'
            ip_addr    = $StaticAddress
            netmask    = $StaticNetmask
            gateway    = $StaticGateway
            nameserver = $nameserver
        }
    } else {
        [ordered]@{ type = 'dhcp' }
    }

    $basePackages = @(
        'openssh-server',
        'sudo',
        'curl',
        'rsync',
        'tar',
        'gzip',
        'shadow',
        'python3',
        'python3-pip',
        'python3-devel',
        'python3-virtualenv',
        'systemd'
    )

    # Keep the credential out of the nested shell grammar. The installer decodes
    # one complete chpasswd record directly to stdin without evaluating its bytes.
    $buildCredentialBase64 = ConvertTo-AtlasoUtf8Base64 -Value "${BuildUsername}:$buildPasswordText`n"
    $postInstall = @(
        '#!/bin/sh',
        "useradd -m -G sudo -s /bin/bash $BuildUsername || true",
        "printf '%s' '$buildCredentialBase64' | base64 -d | chpasswd",
        'systemctl disable sshd.socket',
        'systemctl enable sshd.service',
        "echo '$BuildUsername ALL=(ALL) NOPASSWD:ALL' >/etc/sudoers.d/90-atlaso-build",
        'chmod 0440 /etc/sudoers.d/90-atlaso-build'
    ) + $PostInstallCommands

    $installDisk = '/dev/sda'
    $preInstall = @()
    if ($InstallDiskLayout -eq 'vmware-workstation') {
        $installDisk = '$ATLASO_PHOTON_INSTALL_DISK'
        $preInstall = @(
            '#!/bin/sh',
            'set -eu',
            'disk_matches="$(find /dev/disk/by-path -maxdepth 1 -type l -name ''*-scsi-0:0:0:0'' -print)"',
            'disk_count="$(printf ''%s\n'' "$disk_matches" | awk ''NF { count++ } END { print count + 0 }'')"',
            'if [ "$disk_count" -ne 1 ]; then echo "Expected exactly one VMware Photon install disk at SCSI identity 0:0:0; found $disk_count." >&2; exit 2; fi',
            'ATLASO_PHOTON_INSTALL_DISK="$disk_matches"',
            'export ATLASO_PHOTON_INSTALL_DISK'
        )
    }

    $kickstart = [ordered]@{
        hostname            = 'atlaso'
        password            = [ordered]@{
            crypted = $false
            text    = $rootPasswordText
        }
        disk                = $installDisk
        partitions          = @(
            [ordered]@{ mountpoint = '/'; size = 0; filesystem = 'ext4' },
            [ordered]@{ mountpoint = '/boot'; size = 256; filesystem = 'ext4' },
            [ordered]@{ size = 1024; filesystem = 'swap' }
        )
        bootmode            = 'efi'
        packagelist_file    = 'packages_minimal.json'
        additional_packages = @($basePackages + $AdditionalPackages | Select-Object -Unique)
        linux_flavor        = 'linux'
        network             = $network
        preinstall          = $preInstall
        postinstall         = $postInstall
    }

    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    $json = $kickstart | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($Path, $json, [System.Text.UTF8Encoding]::new($false))
    }
    finally {
        $rootPasswordText = $null
        $buildPasswordText = $null
    }
}

<#
.SYNOPSIS
Split a Packer checksum into algorithm and digest.
.PARAMETER Checksum
Packer checksum expression.
#>
function Split-AtlasoPackerChecksum {
    param([Parameter(Mandatory = $true)][string]$Checksum)

    $parts = $Checksum -split ':', 2
    if ($parts.Count -ne 2 -or [string]::IsNullOrWhiteSpace($parts[0]) -or [string]::IsNullOrWhiteSpace($parts[1])) {
        throw "IsoChecksum must use Packer format such as sha512:<hex>."
    }
    return [pscustomobject]@{
        Algorithm = $parts[0].ToUpperInvariant()
        Hash      = $parts[1].ToUpperInvariant()
    }
}

<#
.SYNOPSIS
Return a file digest in normalized hexadecimal form.
.PARAMETER Path
File to hash.
.PARAMETER Algorithm
Digest algorithm.
#>
function Get-AtlasoFileHashHex {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Algorithm
    )

    $hashAlgorithm = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)
    if ($null -eq $hashAlgorithm) {
        throw "Unsupported checksum algorithm: $Algorithm"
    }
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        try {
            $hashBytes = $hashAlgorithm.ComputeHash($stream)
            return -join ($hashBytes | ForEach-Object { $_.ToString('x2') })
        } finally {
            $stream.Dispose()
        }
    } finally {
        $hashAlgorithm.Dispose()
    }
}

<#
.SYNOPSIS
Return whether a file matches a Packer checksum.
.PARAMETER Path
File to validate.
.PARAMETER Checksum
Expected Packer checksum.
#>
function Test-AtlasoFileChecksum {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Checksum
    )

    $parsed = Split-AtlasoPackerChecksum -Checksum $Checksum
    $actual = (Get-AtlasoFileHashHex -Path $Path -Algorithm $parsed.Algorithm).ToUpperInvariant()
    return $actual -eq $parsed.Hash
}

<#
.SYNOPSIS
Resolve or download the checksum-pinned Photon source ISO.
.PARAMETER UrlOrPath
Source HTTPS URL, local ISO path, or local file URI.
.PARAMETER Checksum
Expected source checksum.
.PARAMETER BuildDirectory
Provider build workspace.
.PARAMETER PackerDirectory
Packer template directory.
.PARAMETER SharedSourceDirectory
Shared verified-image cache.
#>
function Resolve-AtlasoPhotonSourceIso {
    param(
        [Parameter(Mandatory = $true)][string]$UrlOrPath,
        [Parameter(Mandatory = $true)][string]$Checksum,
        [Parameter(Mandatory = $true)][string]$BuildDirectory,
        [Parameter(Mandatory = $true)][string]$PackerDirectory,
        [Parameter(Mandatory = $true)][string]$SharedSourceDirectory
    )

    $localInput = $UrlOrPath
    $sourceUri = $null
    if ($UrlOrPath.StartsWith('file:', [System.StringComparison]::OrdinalIgnoreCase)) {
        if (-not [Uri]::TryCreate($UrlOrPath, [UriKind]::Absolute, [ref]$sourceUri) -or -not $sourceUri.IsFile) {
            throw "IsoUrl file URI is malformed: $UrlOrPath"
        }
        if (-not [string]::IsNullOrEmpty($sourceUri.Host)) {
            throw "IsoUrl file URI must use an empty authority and reference a local file: $UrlOrPath"
        }

        # Convert the URI before cache discovery so an explicit local source is
        # always checksum-verified directly and never falls through to download.
        $localInput = $sourceUri.LocalPath
        if (-not (Test-Path -LiteralPath $localInput -PathType Leaf)) {
            throw "IsoUrl file URI does not reference an existing local file: $UrlOrPath"
        }
    }

    if (Test-Path -LiteralPath $localInput -PathType Leaf) {
        $local = (Resolve-Path -LiteralPath $localInput).Path
        if (-not (Test-AtlasoFileChecksum -Path $local -Checksum $Checksum)) {
            throw "Local ISO checksum does not match IsoChecksum: $local"
        }
        return $local
    }

    $candidateDirs = @(
        $SharedSourceDirectory,
        (Join-Path $BuildDirectory 'source'),
        (Join-Path $PackerDirectory 'packer_cache')
    )
    foreach ($dir in $candidateDirs) {
        if (-not (Test-Path -LiteralPath $dir)) {
            continue
        }
        foreach ($candidate in Get-ChildItem -LiteralPath $dir -Filter '*.iso' -File -ErrorAction SilentlyContinue) {
            if (Test-AtlasoFileChecksum -Path $candidate.FullName -Checksum $Checksum) {
                return $candidate.FullName
            }
        }
    }

    $sourceDir = $SharedSourceDirectory
    New-Item -ItemType Directory -Force -Path $sourceDir | Out-Null
    $fileName = 'photon-source.iso'
    try {
        $uri = [Uri]$UrlOrPath
        $leaf = Split-Path -Leaf $uri.AbsolutePath
        if (-not [string]::IsNullOrWhiteSpace($leaf)) {
            $fileName = $leaf
        }
    } catch {
        $fileName = 'photon-source.iso'
    }
    $downloadPath = Join-Path $sourceDir $fileName
    Write-Host "Downloading Photon ISO to $downloadPath"
    Invoke-WebRequest -Uri $UrlOrPath -OutFile $downloadPath
    if (-not (Test-AtlasoFileChecksum -Path $downloadPath -Checksum $Checksum)) {
        throw "Downloaded ISO checksum does not match IsoChecksum: $downloadPath"
    }
    return $downloadPath
}

<#
.SYNOPSIS
Create a Photon ISO with the Atlaso unattended installer embedded.
.PARAMETER SourceIso
Verified Photon source ISO.
.PARAMETER KickstartJson
Generated Photon kickstart document.
.PARAMETER OutputIso
Destination remastered ISO.
.PARAMETER CleanupPaths
Mutable list that records only task-owned partial or replaced ISO paths.
#>
function New-AtlasoRemasteredPhotonIso {
    param(
        [Parameter(Mandatory = $true)][string]$SourceIso,
        [Parameter(Mandatory = $true)][string]$KickstartJson,
        [Parameter(Mandatory = $true)][string]$OutputIso,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$CleanupPaths
    )

    $repoRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')
    $script = Join-Path $repoRoot 'scripts\interop\create_photon_kickstart_iso.py'
    if (-not (Test-Path -LiteralPath $script)) {
        throw "Photon ISO remaster helper not found: $script"
    }
    $pythonPath = (Get-Command python -ErrorAction Stop).Source
    $outputDirectory = Split-Path -Parent $OutputIso
    $outputLeaf = [System.IO.Path]::GetFileNameWithoutExtension($OutputIso)
    $outputExtension = [System.IO.Path]::GetExtension($OutputIso)
    $attemptIsoPath = Join-Path $outputDirectory ".$outputLeaf.$([guid]::NewGuid().ToString('N')).partial$outputExtension"
    # The unique attempt path is task-owned before the helper can write a
    # credential-bearing byte. A caller-selected target is not task-owned yet.
    $CleanupPaths.Add($attemptIsoPath)
    & $pythonPath $script --source-iso $SourceIso --kickstart $KickstartJson --output $attemptIsoPath
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create remastered Photon ISO."
    }
    if (Test-Path -LiteralPath $OutputIso) {
        Remove-Item -LiteralPath $OutputIso -Force -ErrorAction Stop
        if (Test-Path -LiteralPath $OutputIso) {
            throw "Could not replace prepared Photon ISO: $OutputIso"
        }
    }
    # Only after successful remastering and target replacement preflight does
    # the final path become task-owned and eligible for credential cleanup.
    $CleanupPaths.Add($OutputIso)
    Move-Item -LiteralPath $attemptIsoPath -Destination $OutputIso -Force -ErrorAction Stop
    if ((Test-Path -LiteralPath $attemptIsoPath) -or -not (Test-Path -LiteralPath $OutputIso -PathType Leaf)) {
        throw "Remastered Photon ISO promotion did not complete: $OutputIso"
    }
}

<#
.SYNOPSIS
Convert a value to a Packer HCL literal.
.PARAMETER Value
Value to serialize.
#>
function ConvertTo-AtlasoHclLiteral {
    param([AllowNull()]$Value)
    return ConvertTo-Json -InputObject $Value -Compress
}

<#
.SYNOPSIS
Write generated Packer variables as HCL.
.PARAMETER Path
Destination variable-file path.
.PARAMETER Variables
Variables to serialize.
#>
function Write-AtlasoPackerVarFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][hashtable]$Variables
    )

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Path) | Out-Null
    $lines = foreach ($key in ($Variables.Keys | Sort-Object)) {
        "$key = $(ConvertTo-AtlasoHclLiteral -Value $Variables[$key])"
    }
    [System.IO.File]::WriteAllLines($Path, [string[]]$lines, [System.Text.UTF8Encoding]::new($false))
}

<#
.SYNOPSIS
Return whether an existing file can be opened for writing.
.PARAMETER Path
File to probe.
#>
function Test-AtlasoFileWritable {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return $true
    }
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        $stream.Dispose()
        return $true
    } catch {
        return $false
    }
}

<#
.SYNOPSIS
Resolve a prepared ISO path while preserving actionable lock failures.
.PARAMETER Path
Requested prepared ISO path.
#>
function Resolve-AtlasoPreparedIsoPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (Test-AtlasoFileWritable -Path $Path) {
        return $Path
    }

    $directory = Split-Path -Parent $Path
    $leaf = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    $extension = [System.IO.Path]::GetExtension($Path)
    $stamp = Get-Date -Format 'yyyyMMddHHmmss'
    $fallback = Join-Path $directory "$leaf-$stamp$extension"
    Write-Warning "Prepared ISO is locked; writing this run to $fallback"
    return $fallback
}

<#
.SYNOPSIS
Create a collision-resistant fallback prepared-ISO path.
.PARAMETER Path
Original prepared ISO path.
#>
function New-AtlasoFallbackPreparedIsoPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $directory = Split-Path -Parent $Path
    $leaf = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    $extension = [System.IO.Path]::GetExtension($Path)
    $stamp = Get-Date -Format 'yyyyMMddHHmmss'
    return (Join-Path $directory "$leaf-$stamp$extension")
}

<#
.SYNOPSIS
Remove a plaintext credential artifact and prove that it is absent.
.PARAMETER Path
Exact file or directory path whose failed cleanup must terminate the build.
#>
function Remove-AtlasoSensitiveBuildArtifact {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (Test-Path -LiteralPath $Path -ErrorAction Stop) {
        $artifact = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if ($artifact.PSIsContainer) {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        }
        else {
            Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
        }
    }
    if (Test-Path -LiteralPath $Path -ErrorAction Stop) {
        throw "Plaintext credential artifact cleanup did not complete: $Path"
    }
}

<#
.SYNOPSIS
Invoke an optional provider-owned sensitive-path identity guard.
.PARAMETER Validator
Optional callback that proves the destination remains inside pinned build state.
.PARAMETER Path
Path whose ancestry and identity must be revalidated.
#>
function Assert-AtlasoSensitiveBuildPath {
    param(
        [scriptblock]$Validator,
        [Parameter(Mandatory = $true)][string]$Path
    )

    if ($null -ne $Validator) {
        & $Validator $Path
    }
}

<#
.SYNOPSIS
Build or validate a supported Atlaso Photon image with Packer.
.PARAMETER IsoUrl
Pinned Photon source URL or path.
.PARAMETER IsoChecksum
Expected Photon source checksum.
.PARAMETER PackerDirectory
Provider Packer template directory.
.PARAMETER PackerTemplatePath
Optional exact Packer template file; defaults to atlaso-photon.pkr.hcl in PackerDirectory.
.PARAMETER SshPassword
Temporary Packer SSH password.
.PARAMETER BootstrapAdminPassword
Initial appliance administrator password. Required for Packer validation and builds.
.PARAMETER VmName
Builder virtual-machine name.
.PARAMETER OutputDirectory
Packer artifact output directory.
.PARAMETER SshHost
Optional explicit Packer SSH target.
.PARAMETER SharedSourceDirectory
Shared verified Photon ISO cache.
.PARAMETER BuilderStaticIp
Temporary builder address.
.PARAMETER BuilderStaticNetmask
Temporary builder netmask.
.PARAMETER BuilderStaticGateway
Temporary builder gateway.
.PARAMETER BuilderStaticDns
Temporary builder DNS servers.
.PARAMETER FinalMgmtAddress
Final appliance management address policy.
.PARAMETER FinalMgmtGateway
Final appliance management gateway.
.PARAMETER FinalMgmtInterface
Final appliance management interface.
.PARAMETER PipGlobalIndex
Optional pip index configuration.
.PARAMETER PipGlobalIndexUrl
Optional pip index URL.
.PARAMETER PreparedIsoPath
Optional remastered ISO destination.
.PARAMETER SensitiveBuildDirectory
Optional task-owned directory that contains every plaintext credential artifact.
.PARAMETER SensitivePathValidator
Optional provider callback that revalidates pinned sensitive-path ancestry.
.PARAMETER PackerOnError
Packer failure-handling mode.
.PARAMETER GuestPackages
Provider-specific guest packages.
.PARAMETER GuestPostInstallCommands
Provider-specific guest post-install commands.
.PARAMETER InstallDiskLayout
Provider install-disk discovery policy.
.PARAMETER AdditionalPackerVariables
Provider-specific Packer variables.
.PARAMETER PackerBuildInvoker
Optional provider-specific monitored Packer build callback.
.PARAMETER KeepExistingOutput
Preserve an existing artifact directory.
.PARAMETER EnableRealSystemAdapters
Enable real system adapters in the image.
.PARAMETER ValidateOnly
Validate without building an artifact.
.PARAMETER PrepareIsoOnly
Reject ISO-only preparation because the retained ISO would contain reusable credentials.
#>
function Invoke-AtlasoPhotonImageBuild {
    param(
        [Parameter(Mandatory = $true)][string]$IsoUrl,
        [Parameter(Mandatory = $true)][string]$IsoChecksum,
        [Parameter(Mandatory = $true)][string]$PackerDirectory,
        [string]$PackerTemplatePath = '',
        [Parameter(Mandatory = $true)][SecureString]$SshPassword,
        [SecureString]$BootstrapAdminPassword,
        [string]$VmName = 'Atlaso-Photon-Builder',
        [string]$OutputDirectory = '',
        [string]$SshHost = '',
        [string]$SharedSourceDirectory = '',
        [string]$BuilderStaticIp = '192.168.49.30/24',
        [string]$BuilderStaticNetmask = '255.255.255.0',
        [string]$BuilderStaticGateway = '192.168.49.254',
        [string[]]$BuilderStaticDns = @(),
        [string]$FinalMgmtAddress = '192.168.49.1/24',
        [string]$FinalMgmtGateway = '192.168.49.254',
        [string]$FinalMgmtInterface = 'eth0',
        [string]$PipGlobalIndex = '',
        [string]$PipGlobalIndexUrl = '',
        [string]$PreparedIsoPath = '',
        [string]$SensitiveBuildDirectory = '',
        [scriptblock]$SensitivePathValidator,
        [ValidateSet('cleanup', 'abort', 'ask', 'run-cleanup-provisioner')]
        [string]$PackerOnError = 'cleanup',
        [string[]]$GuestPackages = @(),
        [string[]]$GuestPostInstallCommands = @(),
        [ValidateSet('default', 'vmware-workstation')]
        [string]$InstallDiskLayout = 'default',
        [hashtable]$AdditionalPackerVariables = @{},
        [scriptblock]$PackerBuildInvoker,
        [switch]$KeepExistingOutput,
        [switch]$EnableRealSystemAdapters,
        [switch]$ValidateOnly,
        [switch]$PrepareIsoOnly
    )

    if ($null -eq $BuilderStaticDns) {
        $BuilderStaticDns = @()
    }

    if ($BuilderStaticIp -and $BuilderStaticDns.Count -eq 0) {
        $BuilderStaticDns = @(Get-AtlasoHostIpv4DnsServers)
        if ($BuilderStaticDns.Count -eq 0) {
            $BuilderStaticDns = @('1.1.1.1', '9.9.9.9')
            Write-Warning "Could not discover host IPv4 DNS servers; falling back to public DNS: $($BuilderStaticDns -join ', ')"
        } else {
            Write-Host "Using host IPv4 DNS for Photon builder/appliance: $($BuilderStaticDns -join ', ')"
        }
    }

    $packerDir = Resolve-AtlasoRepoPath -Path $PackerDirectory
    $resolvedPackerTemplatePath = if ([string]::IsNullOrWhiteSpace($PackerTemplatePath)) {
        Join-Path $packerDir 'atlaso-photon.pkr.hcl'
    }
    else {
        [System.IO.Path]::GetFullPath($PackerTemplatePath)
    }
    if (-not (Test-Path -LiteralPath $resolvedPackerTemplatePath -PathType Leaf)) {
        throw "The exact Packer template is missing: $resolvedPackerTemplatePath"
    }
    if ([string]::IsNullOrWhiteSpace($SharedSourceDirectory)) {
        $repoRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')
        $SharedSourceDirectory = Join-Path $repoRoot 'image\common\source'
    }
    $sharedSourceDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($SharedSourceDirectory)
    $buildDir = Join-Path $packerDir 'build'
    $sensitiveBuildDir = if ([string]::IsNullOrWhiteSpace($SensitiveBuildDirectory)) {
        $buildDir
    }
    else {
        $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($SensitiveBuildDirectory)
    }
    Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $sensitiveBuildDir
    New-Item -ItemType Directory -Force -Path $sensitiveBuildDir | Out-Null
    Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $sensitiveBuildDir
    if ([string]::IsNullOrWhiteSpace($PreparedIsoPath)) {
        $PreparedIsoPath = Join-Path $sensitiveBuildDir 'kickstart\atlaso-photon-with-kickstart.iso'
    }

    $varFilePath = Join-Path $sensitiveBuildDir 'packer-vars\atlaso-photon.auto.pkrvars.hcl'
    $ksSourceDir = Join-Path $sensitiveBuildDir 'kickstart-src'
    $kickstartJson = Join-Path $ksSourceDir 'photon-ks.json'
    $resolvedPreparedIsoPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($PreparedIsoPath)
    $resolvedPreparedIsoPath = Resolve-AtlasoPreparedIsoPath -Path $resolvedPreparedIsoPath

    if ($PrepareIsoOnly) {
        throw 'PrepareIsoOnly is not supported because a retained remastered ISO would contain reusable build credentials. Run Packer validation or a build so the ISO can be deleted after the bounded consumer exits.'
    }

    $preparedIsoCleanupPaths = [System.Collections.Generic.List[string]]::new()
    try {
        try {
            Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $ksSourceDir
            Remove-AtlasoSensitiveBuildArtifact -Path $ksSourceDir
            Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $ksSourceDir
            New-Item -ItemType Directory -Force -Path $ksSourceDir | Out-Null
            Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $ksSourceDir
            Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $kickstartJson
            New-AtlasoPhotonKickstart `
                -Path $kickstartJson `
                -RootPassword $SshPassword `
                -BuildPassword $SshPassword `
                -BuildUsername 'atlaso-build' `
                -StaticAddress (Get-AtlasoBuilderAddress -Cidr $BuilderStaticIp) `
                -StaticNetmask $BuilderStaticNetmask `
                -StaticGateway $BuilderStaticGateway `
                -StaticDns $BuilderStaticDns `
                -AdditionalPackages $GuestPackages `
                -PostInstallCommands $GuestPostInstallCommands `
                -InstallDiskLayout $InstallDiskLayout
            Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $kickstartJson

            Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $buildDir
            $sourceIsoPath = Resolve-AtlasoPhotonSourceIso -UrlOrPath $IsoUrl -Checksum $IsoChecksum -BuildDirectory $buildDir -PackerDirectory $packerDir -SharedSourceDirectory $sharedSourceDir
            try {
                Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $resolvedPreparedIsoPath
                Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $kickstartJson
                New-AtlasoRemasteredPhotonIso `
                    -SourceIso $sourceIsoPath `
                    -KickstartJson $kickstartJson `
                    -OutputIso $resolvedPreparedIsoPath `
                    -CleanupPaths $preparedIsoCleanupPaths
                Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $resolvedPreparedIsoPath
            } catch {
                foreach ($candidatePath in @($preparedIsoCleanupPaths | Select-Object -Unique)) {
                    Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $candidatePath
                }
                $fallbackPreparedIsoPath = New-AtlasoFallbackPreparedIsoPath -Path $resolvedPreparedIsoPath
                Write-Warning "Could not replace prepared ISO at $resolvedPreparedIsoPath; retrying this run with $fallbackPreparedIsoPath"
                $resolvedPreparedIsoPath = $fallbackPreparedIsoPath
                Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $resolvedPreparedIsoPath
                Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $kickstartJson
                New-AtlasoRemasteredPhotonIso `
                    -SourceIso $sourceIsoPath `
                    -KickstartJson $kickstartJson `
                    -OutputIso $resolvedPreparedIsoPath `
                    -CleanupPaths $preparedIsoCleanupPaths
                Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $resolvedPreparedIsoPath
            }
        } finally {
            # The remastered ISO owns the consumed kickstart payload. Do not retain
            # its plaintext build password in the ignored repository workspace.
            Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $kickstartJson
            Remove-AtlasoSensitiveBuildArtifact -Path $kickstartJson
            Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $ksSourceDir
            Remove-AtlasoSensitiveBuildArtifact -Path $ksSourceDir
        }
        $preparedIso = Get-Item -LiteralPath $resolvedPreparedIsoPath -ErrorAction Stop
        if ($preparedIso.Length -le 0) {
            throw "Remastered Photon ISO was created but is empty: $resolvedPreparedIsoPath"
        }
        $preparedIsoChecksum = "sha512:$(Get-AtlasoFileHashHex -Path $resolvedPreparedIsoPath -Algorithm SHA512)"
        Write-Host "Using remastered Photon ISO: $resolvedPreparedIsoPath"
        Write-Host "Packer will boot a single DVD with embedded photon-ks.json and a GRUB auto-install entry."

    # Packer's HCL boundary requires strings. Convert only after all password-free
    # preparation has completed, then remove the generated secret-bearing var file.
        if ($null -eq $BootstrapAdminPassword) {
            throw 'BootstrapAdminPassword is required.'
        }
        $sshPasswordText = $null
        $bootstrapAdminPasswordText = $null
        try {
            Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $varFilePath
            $sshPasswordText = ConvertFrom-SecureString -SecureString $SshPassword -AsPlainText
            $bootstrapAdminPasswordText = ConvertFrom-SecureString -SecureString $BootstrapAdminPassword -AsPlainText
            $packerVariables = @{
        iso_url                  = $resolvedPreparedIsoPath
        iso_checksum             = $preparedIsoChecksum
        iso_contains_kickstart   = $true
        ssh_password             = $sshPasswordText
        bootstrap_admin_password = $bootstrapAdminPasswordText
        vm_name                  = $VmName
        builder_static_ip        = $BuilderStaticIp
        builder_static_netmask   = $BuilderStaticNetmask
        builder_static_gateway   = $BuilderStaticGateway
        builder_static_dns       = $BuilderStaticDns
        final_mgmt_address       = $FinalMgmtAddress
        final_mgmt_gateway       = $FinalMgmtGateway
        final_mgmt_interface     = $FinalMgmtInterface
        pip_global_index         = $PipGlobalIndex
        pip_global_index_url     = $PipGlobalIndexUrl
        dry_run_system_adapters  = -not $EnableRealSystemAdapters
    }

    if (-not [string]::IsNullOrWhiteSpace($OutputDirectory)) {
        $packerVariables['output_directory'] = $OutputDirectory
    }
    if (-not [string]::IsNullOrWhiteSpace($SshHost)) {
        $packerVariables['ssh_host'] = $SshHost
    }
    foreach ($key in $AdditionalPackerVariables.Keys) {
        $packerVariables[$key] = $AdditionalPackerVariables[$key]
    }

    Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $varFilePath
    Write-AtlasoPackerVarFile -Path $varFilePath -Variables $packerVariables
    Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $varFilePath
    Write-Host "Using Packer var-file: $varFilePath"

    $packerArgs = @($(if ($ValidateOnly) { 'validate' } else { 'build' }))
    if (-not $ValidateOnly -and -not $KeepExistingOutput) {
        Write-Host "Packer build will replace any existing output directory for this build."
        $packerArgs += '-force'
    }
    if (-not $ValidateOnly) {
        $packerArgs += "-on-error=$PackerOnError"
    }
    $packerArgs += @('-var-file', $varFilePath, $resolvedPackerTemplatePath)

            Push-Location $packerDir
            try {
                & packer init $resolvedPackerTemplatePath
                if ($LASTEXITCODE -ne 0) {
                    throw "packer init failed with exit code $LASTEXITCODE."
                }
                $pluginCheckScript = Join-Path $PSScriptRoot '..\..\check_packer_plugins.py'
                & python $pluginCheckScript `
                    --packer (Get-Command packer -ErrorAction Stop).Source `
                    $resolvedPackerTemplatePath
                if ($LASTEXITCODE -ne 0) {
                    throw "Exact Packer plugin verification failed with exit code $LASTEXITCODE."
                }
                if (-not $ValidateOnly -and $null -ne $PackerBuildInvoker) {
                    Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $varFilePath
                    & $PackerBuildInvoker $packerArgs $packerDir
                }
                else {
                    Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $varFilePath
                    & packer @packerArgs
                    if ($LASTEXITCODE -ne 0) {
                        $operation = if ($ValidateOnly) { 'validate' } else { 'build' }
                        throw "packer $operation failed with exit code $LASTEXITCODE."
                    }
                }
            } finally {
                Pop-Location
            }
        } finally {
            try {
                # The var file is needed only by the bounded Packer child and must
                # not leave reusable plaintext credentials in the build workspace.
                Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $varFilePath
                Remove-AtlasoSensitiveBuildArtifact -Path $varFilePath
            }
            finally {
                $sshPasswordText = $null
                $bootstrapAdminPasswordText = $null
            }
        }
    } finally {
        # The remastered ISO embeds the temporary SSH password and is safe only
        # while owned by the bounded Packer consumer. Try every attempted path so
        # a failed fallback cannot leave a credential-bearing partial ISO behind.
        $preparedIsoCleanupFailures = [System.Collections.Generic.List[string]]::new()
        foreach ($candidatePath in @($preparedIsoCleanupPaths | Select-Object -Unique)) {
            try {
                Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $candidatePath
                Remove-AtlasoSensitiveBuildArtifact -Path $candidatePath
            } catch {
                $preparedIsoCleanupFailures.Add("$candidatePath ($($_.Exception.Message))")
            }
        }
        if ($preparedIsoCleanupFailures.Count -gt 0) {
            throw "Remastered Photon ISO credential cleanup failed: $($preparedIsoCleanupFailures -join '; ')"
        }
    }
}

Export-ModuleMember -Function `
    Invoke-AtlasoPhotonImageBuild, `
    Get-AtlasoFileHashHex, `
    Test-AtlasoFileChecksum
