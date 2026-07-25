Set-StrictMode -Version Latest

function Resolve-AtlasoRepoPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return (Resolve-Path -LiteralPath $Path).Path
}

function Get-AtlasoBuilderAddress {
    param([string]$Cidr)
    if ([string]::IsNullOrWhiteSpace($Cidr)) {
        return ''
    }
    return ($Cidr -split '/', 2)[0]
}

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

function New-AtlasoPhotonKickstart {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$RootPassword,
        [Parameter(Mandatory = $true)][string]$BuildPassword,
        [Parameter(Mandatory = $true)][string]$BuildUsername,
        [string]$StaticAddress,
        [string]$StaticNetmask,
        [string]$StaticGateway,
        [string[]]$StaticDns = @(),
        [string[]]$AdditionalPackages = @(),
        [string[]]$PostInstallCommands = @()
    )

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

    $postInstall = @(
        '#!/bin/sh',
        "useradd -m -G sudo -s /bin/bash $BuildUsername || true",
        "printf '%s:%s\n' '$BuildUsername' '$BuildPassword' | chpasswd",
        'systemctl disable sshd.socket',
        'systemctl enable sshd.service',
        "echo '$BuildUsername ALL=(ALL) NOPASSWD:ALL' >/etc/sudoers.d/90-atlaso-build",
        'chmod 0440 /etc/sudoers.d/90-atlaso-build'
    ) + $PostInstallCommands

    $kickstart = [ordered]@{
        hostname            = 'atlaso'
        password            = [ordered]@{
            crypted = $false
            text    = $RootPassword
        }
        disk                = '/dev/sda'
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
        postinstall         = $postInstall
    }

    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
    $json = $kickstart | ConvertTo-Json -Depth 10
    [System.IO.File]::WriteAllText($Path, $json, [System.Text.UTF8Encoding]::new($false))
}

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

function Test-AtlasoFileChecksum {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Checksum
    )

    $parsed = Split-AtlasoPackerChecksum -Checksum $Checksum
    $actual = (Get-AtlasoFileHashHex -Path $Path -Algorithm $parsed.Algorithm).ToUpperInvariant()
    return $actual -eq $parsed.Hash
}

function Resolve-AtlasoPhotonSourceIso {
    param(
        [Parameter(Mandatory = $true)][string]$UrlOrPath,
        [Parameter(Mandatory = $true)][string]$Checksum,
        [Parameter(Mandatory = $true)][string]$BuildDirectory,
        [Parameter(Mandatory = $true)][string]$PackerDirectory,
        [Parameter(Mandatory = $true)][string]$SharedSourceDirectory
    )

    if (Test-Path -LiteralPath $UrlOrPath -PathType Leaf) {
        $local = (Resolve-Path -LiteralPath $UrlOrPath).Path
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

function New-AtlasoRemasteredPhotonIso {
    param(
        [Parameter(Mandatory = $true)][string]$SourceIso,
        [Parameter(Mandatory = $true)][string]$KickstartJson,
        [Parameter(Mandatory = $true)][string]$OutputIso
    )

    $repoRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')
    $script = Join-Path $repoRoot 'scripts\interop\create_photon_kickstart_iso.py'
    if (-not (Test-Path -LiteralPath $script)) {
        throw "Photon ISO remaster helper not found: $script"
    }
    & python $script --source-iso $SourceIso --kickstart $KickstartJson --output $OutputIso
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create remastered Photon ISO."
    }
}

function ConvertTo-AtlasoHclLiteral {
    param([AllowNull()]$Value)
    return ConvertTo-Json -InputObject $Value -Compress
}

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

function New-AtlasoFallbackPreparedIsoPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $directory = Split-Path -Parent $Path
    $leaf = [System.IO.Path]::GetFileNameWithoutExtension($Path)
    $extension = [System.IO.Path]::GetExtension($Path)
    $stamp = Get-Date -Format 'yyyyMMddHHmmss'
    return (Join-Path $directory "$leaf-$stamp$extension")
}

function Invoke-AtlasoPhotonImageBuild {
    param(
        [Parameter(Mandatory = $true)][string]$IsoUrl,
        [Parameter(Mandatory = $true)][string]$IsoChecksum,
        [Parameter(Mandatory = $true)][string]$PackerDirectory,
        [string]$SshPassword = 'VMware01!',
        [string]$BootstrapAdminPassword = 'VMware01!',
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
        [ValidateSet('cleanup', 'abort', 'ask', 'run-cleanup-provisioner')]
        [string]$PackerOnError = 'cleanup',
        [string[]]$GuestPackages = @(),
        [string[]]$GuestPostInstallCommands = @(),
        [hashtable]$AdditionalPackerVariables = @{},
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
    if ([string]::IsNullOrWhiteSpace($SharedSourceDirectory)) {
        $repoRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')
        $SharedSourceDirectory = Join-Path $repoRoot 'image\common\source'
    }
    $sharedSourceDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($SharedSourceDirectory)
    if ([string]::IsNullOrWhiteSpace($PreparedIsoPath)) {
        $PreparedIsoPath = Join-Path $packerDir 'build\kickstart\atlaso-photon-with-kickstart.iso'
    }

    $buildDir = Join-Path $packerDir 'build'
    $varFilePath = Join-Path $buildDir 'packer-vars\atlaso-photon.auto.pkrvars.hcl'
    $ksSourceDir = Join-Path $buildDir 'kickstart-src'
    $kickstartJson = Join-Path $ksSourceDir 'photon-ks.json'
    $resolvedPreparedIsoPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($PreparedIsoPath)
    $resolvedPreparedIsoPath = Resolve-AtlasoPreparedIsoPath -Path $resolvedPreparedIsoPath

    Remove-Item -LiteralPath $ksSourceDir -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force -Path $ksSourceDir | Out-Null
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
        -PostInstallCommands $GuestPostInstallCommands

    $sourceIsoPath = Resolve-AtlasoPhotonSourceIso -UrlOrPath $IsoUrl -Checksum $IsoChecksum -BuildDirectory $buildDir -PackerDirectory $packerDir -SharedSourceDirectory $sharedSourceDir
    try {
        New-AtlasoRemasteredPhotonIso -SourceIso $sourceIsoPath -KickstartJson $kickstartJson -OutputIso $resolvedPreparedIsoPath
    } catch {
        $fallbackPreparedIsoPath = New-AtlasoFallbackPreparedIsoPath -Path $resolvedPreparedIsoPath
        Write-Warning "Could not replace prepared ISO at $resolvedPreparedIsoPath; retrying this run with $fallbackPreparedIsoPath"
        $resolvedPreparedIsoPath = $fallbackPreparedIsoPath
        New-AtlasoRemasteredPhotonIso -SourceIso $sourceIsoPath -KickstartJson $kickstartJson -OutputIso $resolvedPreparedIsoPath
    }
    $preparedIso = Get-Item -LiteralPath $resolvedPreparedIsoPath -ErrorAction Stop
    if ($preparedIso.Length -le 0) {
        throw "Remastered Photon ISO was created but is empty: $resolvedPreparedIsoPath"
    }
    $preparedIsoChecksum = "sha512:$(Get-AtlasoFileHashHex -Path $resolvedPreparedIsoPath -Algorithm SHA512)"
    Write-Host "Using remastered Photon ISO: $resolvedPreparedIsoPath"
    Write-Host "Packer will boot a single DVD with embedded photon-ks.json and a GRUB auto-install entry."

    if ($PrepareIsoOnly) {
        Write-Host "Remastered Photon ISO prepared at $resolvedPreparedIsoPath"
        return
    }

    $packerVariables = @{
        iso_url                  = $resolvedPreparedIsoPath
        iso_checksum             = $preparedIsoChecksum
        iso_contains_kickstart   = $true
        ssh_password             = $SshPassword
        bootstrap_admin_password = $BootstrapAdminPassword
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

    Write-AtlasoPackerVarFile -Path $varFilePath -Variables $packerVariables
    Write-Host "Using Packer var-file: $varFilePath"

    $packerArgs = @($(if ($ValidateOnly) { 'validate' } else { 'build' }))
    if (-not $ValidateOnly -and -not $KeepExistingOutput) {
        Write-Host "Packer build will replace any existing output directory for this build."
        $packerArgs += '-force'
    }
    if (-not $ValidateOnly) {
        $packerArgs += "-on-error=$PackerOnError"
    }
    $packerArgs += @('-var-file', $varFilePath, '.')

    Push-Location $packerDir
    try {
        & packer @packerArgs
        if ($LASTEXITCODE -ne 0) {
            $operation = if ($ValidateOnly) { 'validate' } else { 'build' }
            throw "packer $operation failed with exit code $LASTEXITCODE."
        }
    } finally {
        Pop-Location
    }
}

Export-ModuleMember -Function `
    Invoke-AtlasoPhotonImageBuild, `
    Get-AtlasoFileHashHex, `
    Test-AtlasoFileChecksum
