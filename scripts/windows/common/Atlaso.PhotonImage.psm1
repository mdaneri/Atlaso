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
.PARAMETER SensitivePathValidator
Optional callback that pins and revalidates sensitive-path filesystem identity.
.PARAMETER PinnedHandles
Optional invocation-owned map that retains no-delete handles through consumption and cleanup.
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
        [string]$InstallDiskLayout = 'default',
        [scriptblock]$SensitivePathValidator,
        [hashtable]$PinnedHandles
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
    Write-AtlasoPinnedUtf8Text `
        -Path $Path `
        -Text $json `
        -SensitivePathValidator $SensitivePathValidator `
        -PinnedHandles $PinnedHandles
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
        $stream = if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
            Initialize-AtlasoPhotonPinnedFileType
            $readHandle = [Atlaso.PhotonPinnedFile]::OpenReadSharedDelete($Path)
            [System.IO.FileStream]::new($readHandle, [System.IO.FileAccess]::Read)
        }
        else {
            [System.IO.File]::OpenRead($Path)
        }
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
Load the Windows handle-relative file promotion helper once.
#>
function Initialize-AtlasoPhotonPinnedFileType {
    if ('Atlaso.PhotonPinnedFile' -as [type]) {
        return
    }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Atlaso
{
    public static class PhotonPinnedFile
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct FileRenameInfo
        {
            [MarshalAs(UnmanagedType.U1)] public bool ReplaceIfExists;
            public IntPtr RootDirectory;
            public uint FileNameLength;
            public char FileName;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileId128
        {
            public ulong Low;
            public ulong High;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileIdInfo
        {
            public ulong VolumeSerialNumber;
            public FileId128 FileId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ByHandleFileInformation
        {
            public uint FileAttributes;
            public uint CreationTimeLow;
            public uint CreationTimeHigh;
            public uint LastAccessTimeLow;
            public uint LastAccessTimeHigh;
            public uint LastWriteTimeLow;
            public uint LastWriteTimeHigh;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct FileIdUnion
        {
            [FieldOffset(0)] public long FileId;
            [FieldOffset(0)] public Guid ObjectId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FileIdDescriptor
        {
            public uint Size;
            public int Type;
            public FileIdUnion Value;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string fileName,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern SafeFileHandle ReOpenFile(
            SafeFileHandle originalFile,
            uint desiredAccess,
            uint shareMode,
            uint flagsAndAttributes);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandleEx(
            SafeFileHandle file,
            int fileInformationClass,
            out FileIdInfo fileInformation,
            uint bufferSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle file,
            out ByHandleFileInformation fileInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern SafeFileHandle OpenFileById(
            SafeFileHandle volumeHint,
            ref FileIdDescriptor fileId,
            uint desiredAccess,
            uint shareMode,
            IntPtr securityAttributes,
            uint flagsAndAttributes);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandleW(
            SafeFileHandle file,
            StringBuilder filePath,
            uint filePathLength,
            uint flags);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetFileInformationByHandle(
            SafeFileHandle file,
            int fileInformationClass,
            IntPtr fileInformation,
            uint bufferSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetFilePointerEx(
            SafeFileHandle file,
            long distance,
            out long newPosition,
            uint moveMethod);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetEndOfFile(SafeFileHandle file);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool WriteFile(
            SafeFileHandle file,
            byte[] buffer,
            uint bytesToWrite,
            out uint bytesWritten,
            IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FlushFileBuffers(SafeFileHandle file);

        public static SafeFileHandle Create(string path)
        {
            const uint GenericRead = 0x80000000;
            const uint GenericWrite = 0x40000000;
            const uint ShareRead = 0x00000001;
            const uint ShareWrite = 0x00000002;
            const uint CreateNew = 1;
            const uint Normal = 0x00000080;
            SafeFileHandle handle = CreateFileW(
                path,
                GenericRead | GenericWrite,
                ShareRead | ShareWrite,
                IntPtr.Zero,
                CreateNew,
                Normal,
                IntPtr.Zero);
            if (handle.IsInvalid)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return handle;
        }

        public static SafeFileHandle PinForReadConsumers(SafeFileHandle handle)
        {
            const uint FileReadAttributes = 0x00000080;
            const uint ShareRead = 0x00000001;
            const uint ShareWrite = 0x00000002;
            SafeFileHandle consumerHandle = ReOpenFile(
                handle,
                FileReadAttributes,
                ShareRead | ShareWrite,
                0);
            if (consumerHandle.IsInvalid)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return consumerHandle;
        }

        public static SafeFileHandle OpenReadSharedDelete(string path)
        {
            const uint GenericRead = 0x80000000;
            const uint ShareRead = 0x00000001;
            const uint ShareWrite = 0x00000002;
            const uint ShareDelete = 0x00000004;
            const uint OpenExisting = 3;
            const uint Normal = 0x00000080;
            SafeFileHandle handle = CreateFileW(
                path,
                GenericRead,
                ShareRead | ShareWrite | ShareDelete,
                IntPtr.Zero,
                OpenExisting,
                Normal,
                IntPtr.Zero);
            if (handle.IsInvalid)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return handle;
        }

        public static void Rename(SafeFileHandle handle, string destinationPath)
        {
            byte[] nameBytes = System.Text.Encoding.Unicode.GetBytes(destinationPath);
            int nameOffset = (int)Marshal.OffsetOf<FileRenameInfo>("FileName");
            // FileNameLength excludes the terminator, but the variable-length
            // FILE_RENAME_INFO buffer still needs one zero UTF-16 code unit so
            // the kernel never consumes adjacent unmanaged bytes as a suffix.
            int bufferLength = checked(nameOffset + nameBytes.Length + 2);
            IntPtr buffer = Marshal.AllocHGlobal(bufferLength);
            try
            {
                for (int index = 0; index < bufferLength; index++)
                {
                    Marshal.WriteByte(buffer, index, 0);
                }
                Marshal.WriteByte(buffer, 0, 1);
                Marshal.WriteInt32(buffer, (int)Marshal.OffsetOf<FileRenameInfo>("FileNameLength"), nameBytes.Length);
                Marshal.Copy(nameBytes, 0, IntPtr.Add(buffer, nameOffset), nameBytes.Length);
                const int FileRenameInfoClass = 3;
                if (!SetFileInformationByHandle(
                    handle,
                    FileRenameInfoClass,
                    buffer,
                    (uint)bufferLength))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        public static void WriteUtf8(SafeFileHandle handle, string text)
        {
            byte[] bytes = new System.Text.UTF8Encoding(false).GetBytes(text);
            long position;
            if (!SetFilePointerEx(handle, 0, out position, 0) || !SetEndOfFile(handle))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            uint written;
            if (!WriteFile(handle, bytes, (uint)bytes.Length, out written, IntPtr.Zero) ||
                written != bytes.Length || !FlushFileBuffers(handle))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }

        private static bool TryDelete(SafeFileHandle handle, out int error)
        {
            IntPtr disposition = Marshal.AllocHGlobal(1);
            try
            {
                Marshal.WriteByte(disposition, 0, 1);
                const int FileDispositionInfoClass = 4;
                if (!SetFileInformationByHandle(
                    handle,
                    FileDispositionInfoClass,
                    disposition,
                    1))
                {
                    error = Marshal.GetLastWin32Error();
                    return false;
                }
                error = 0;
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(disposition);
            }
        }

        public static void DeleteExact(SafeFileHandle handle, string path)
        {
            int error;
            if (TryDelete(handle, out error))
            {
                return;
            }
            const int ErrorAccessDenied = 5;
            if (error != ErrorAccessDenied)
            {
                throw new Win32Exception(error);
            }

            const int FileIdInfoClass = 18;
            FileIdInfo identity;
            if (!GetFileInformationByHandleEx(
                handle,
                FileIdInfoClass,
                out identity,
                (uint)Marshal.SizeOf<FileIdInfo>()))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            ByHandleFileInformation legacyIdentity;
            if (!GetFileInformationByHandle(handle, out legacyIdentity))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            string root = System.IO.Path.GetPathRoot(System.IO.Path.GetFullPath(path));
            if (String.IsNullOrEmpty(root) || root.Length < 2 || root[1] != ':')
            {
                throw new InvalidOperationException(
                    "Pinned plaintext cleanup requires a local Windows volume.");
            }
            const uint GenericRead = 0x80000000;
            const uint FileReadAttributes = 0x00000080;
            const uint Delete = 0x00010000;
            const uint ShareRead = 0x00000001;
            const uint ShareWrite = 0x00000002;
            const uint ShareDelete = 0x00000004;
            const uint OpenExisting = 3;
            const uint Normal = 0x00000080;
            const uint BackupSemantics = 0x02000000;

            using (SafeFileHandle volumeHint = CreateFileW(
                root,
                GenericRead,
                ShareRead | ShareWrite | ShareDelete,
                IntPtr.Zero,
                OpenExisting,
                BackupSemantics,
                IntPtr.Zero))
            {
                if (volumeHint.IsInvalid)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                FileIdDescriptor descriptor = new FileIdDescriptor();
                descriptor.Size = (uint)Marshal.SizeOf<FileIdDescriptor>();
                descriptor.Type = 0;
                descriptor.Value.FileId = unchecked((long)(
                    ((ulong)legacyIdentity.FileIndexHigh << 32) |
                    legacyIdentity.FileIndexLow));
                using (SafeFileHandle identityHandle = OpenFileById(
                    volumeHint,
                    ref descriptor,
                    FileReadAttributes,
                    ShareRead | ShareWrite | ShareDelete,
                    IntPtr.Zero,
                    0))
                {
                    if (identityHandle.IsInvalid)
                    {
                        throw new Win32Exception(
                            Marshal.GetLastWin32Error(),
                            "Could not bind the exact pinned file identity for cleanup.");
                    }

                    // Bind the captured object by file ID before releasing the
                    // no-delete pin. If the link moves afterward, the binding
                    // follows that exact object so cleanup cannot lose it.
                    handle.Dispose();
                    const int MaximumAttempts = 8;
                    for (int attempt = 0; attempt < MaximumAttempts; attempt++)
                    {
                        StringBuilder currentPath = new StringBuilder(32768);
                        uint pathLength = GetFinalPathNameByHandleW(
                            identityHandle,
                            currentPath,
                            (uint)currentPath.Capacity,
                            0);
                        if (pathLength == 0 || pathLength >= currentPath.Capacity)
                        {
                            throw new Win32Exception(
                                Marshal.GetLastWin32Error(),
                                "Could not resolve the exact pinned file path for cleanup.");
                        }
                        using (SafeFileHandle exact = CreateFileW(
                            currentPath.ToString(),
                            FileReadAttributes | Delete,
                            ShareRead | ShareWrite,
                            IntPtr.Zero,
                            OpenExisting,
                            Normal,
                            IntPtr.Zero))
                        {
                            if (exact.IsInvalid)
                            {
                                continue;
                            }
                            FileIdInfo reopenedIdentity;
                            if (!GetFileInformationByHandleEx(
                                exact,
                                FileIdInfoClass,
                                out reopenedIdentity,
                                (uint)Marshal.SizeOf<FileIdInfo>()))
                            {
                                throw new Win32Exception(Marshal.GetLastWin32Error());
                            }
                            if (reopenedIdentity.VolumeSerialNumber != identity.VolumeSerialNumber ||
                                reopenedIdentity.FileId.Low != identity.FileId.Low ||
                                reopenedIdentity.FileId.High != identity.FileId.High)
                            {
                                continue;
                            }
                            if (!TryDelete(exact, out error))
                            {
                                throw new Win32Exception(
                                    error,
                                    "Could not mark the exact pinned file identity for deletion.");
                            }
                            return;
                        }
                    }
                    throw new InvalidOperationException(
                        "Pinned plaintext moved repeatedly during exact cleanup.");
                }
            }
        }
    }
}
'@
}

<#
.SYNOPSIS
Create, identity-pin, and write one plaintext UTF-8 file through its open handle.
.PARAMETER Path
Unique destination path that must not already exist.
.PARAMETER Text
Plaintext content to write without a byte-order mark.
.PARAMETER SensitivePathValidator
Optional callback that pins and revalidates sensitive-path filesystem identity.
.PARAMETER PinnedHandles
Optional invocation-owned map that retains the no-delete handle through consumption and cleanup.
#>
function Write-AtlasoPinnedUtf8Text {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text,
        [scriptblock]$SensitivePathValidator,
        [hashtable]$PinnedHandles
    )

    if (Test-Path -LiteralPath $Path) {
        if ($null -ne $SensitivePathValidator) {
            throw "Sensitive plaintext destination already exists: $Path"
        }
        # Provider-neutral unit fixtures do not transport the Windows identity
        # callback. Production callers always supply it and require an absent
        # create-new destination.
        Remove-Item -LiteralPath $Path -Force -ErrorAction Stop
    }
    Initialize-AtlasoPhotonPinnedFileType
    $handle = $null
    try {
        $handle = [Atlaso.PhotonPinnedFile]::Create($Path)
        Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $Path
        [Atlaso.PhotonPinnedFile]::WriteUtf8($handle, $Text)
        Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $Path
        if ($null -ne $PinnedHandles) {
            # Reopen as a minimal no-delete pin before releasing the writer.
            # Ordinary readers then remain compatible without opening a rename
            # window between plaintext serialization and consumer completion.
            $consumerHandle = [Atlaso.PhotonPinnedFile]::PinForReadConsumers($handle)
            $PinnedHandles[[System.IO.Path]::GetFullPath($Path)] = $consumerHandle
            $handle.Dispose()
            $handle = $null
        }
    }
    finally {
        if ($null -ne $handle) {
            $handle.Dispose()
        }
    }
}

<#
.SYNOPSIS
Delete one pinned plaintext file through its retained no-delete handle.
.PARAMETER Path
Exact plaintext path to delete.
.PARAMETER PinnedHandles
Invocation-owned map containing the retained file handle.
.PARAMETER SensitivePathValidator
Optional callback that revalidates sensitive-path filesystem identity.
#>
function Remove-AtlasoPinnedPlaintextFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][hashtable]$PinnedHandles,
        [scriptblock]$SensitivePathValidator
    )

    $resolvedPath = [System.IO.Path]::GetFullPath($Path)
    try {
        if (-not $PinnedHandles.ContainsKey($resolvedPath)) {
            if (-not (Test-Path -LiteralPath $resolvedPath)) {
                return
            }
            throw "Pinned plaintext handle is unavailable: $resolvedPath"
        }
        $handle = $PinnedHandles[$resolvedPath]
        Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $resolvedPath
        [Atlaso.PhotonPinnedFile]::DeleteExact($handle, $resolvedPath)
        $null = $PinnedHandles.Remove($resolvedPath)
        $handle.Dispose()
        if (Test-Path -LiteralPath $resolvedPath) {
            throw "Pinned plaintext cleanup did not complete: $resolvedPath"
        }
    }
    catch {
        $_.Exception.Data['AtlasoPlaintextCleanupUnproven'] = $true
        throw
    }
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
.PARAMETER SensitivePathValidator
Optional callback that pins and revalidates sensitive-path filesystem identity.
.PARAMETER PinnedHandles
Optional invocation-owned map that retains the no-delete handle through consumption and cleanup.
#>
function New-AtlasoRemasteredPhotonIso {
    param(
        [Parameter(Mandatory = $true)][string]$SourceIso,
        [Parameter(Mandatory = $true)][string]$KickstartJson,
        [Parameter(Mandatory = $true)][string]$OutputIso,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$CleanupPaths,
        [scriptblock]$SensitivePathValidator,
        [hashtable]$PinnedHandles
    )

    $repoRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')
    $script = Join-Path $repoRoot 'scripts\interop\create_photon_kickstart_iso.py'
    if (-not (Test-Path -LiteralPath $script)) {
        throw "Photon ISO remaster helper not found: $script"
    }
    $pythonPath = (Get-Command python -ErrorAction Stop).Source
    $outputDirectory = Split-Path -Parent $OutputIso
    Initialize-AtlasoPhotonPinnedFileType
    $attemptHandle = $null
    try {
        if (Test-Path -LiteralPath $OutputIso) {
            Remove-Item -LiteralPath $OutputIso -Force -ErrorAction Stop
            if (Test-Path -LiteralPath $OutputIso) {
                throw "Could not replace prepared Photon ISO: $OutputIso"
            }
        }
        # CreateNew pins the final task-owned path before the helper can expose
        # credential-bearing bytes. Writing the final object directly avoids a
        # DELETE-capable promotion handle that ordinary Packer readers cannot share.
        $attemptHandle = [Atlaso.PhotonPinnedFile]::Create($OutputIso)
        if ($null -ne $PinnedHandles) {
            $PinnedHandles[[System.IO.Path]::GetFullPath($OutputIso)] = $attemptHandle
        }
        $CleanupPaths.Add($OutputIso)
        Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $OutputIso
        & $pythonPath $script --source-iso $SourceIso --kickstart $KickstartJson --output $OutputIso
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to create remastered Photon ISO."
        }
        Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $OutputIso
        if ($null -ne $PinnedHandles) {
            $consumerHandle = [Atlaso.PhotonPinnedFile]::PinForReadConsumers($attemptHandle)
            $PinnedHandles[[System.IO.Path]::GetFullPath($OutputIso)] = $consumerHandle
            $attemptHandle.Dispose()
            $attemptHandle = $consumerHandle
        }
        if (-not (Test-Path -LiteralPath $OutputIso -PathType Leaf)) {
            throw "Remastered Photon ISO creation did not complete: $OutputIso"
        }
        if ($null -ne $PinnedHandles) {
            $attemptHandle = $null
        }
    }
    finally {
        if ($null -ne $attemptHandle -and $null -eq $PinnedHandles) {
            $attemptHandle.Dispose()
        }
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
.PARAMETER SensitivePathValidator
Optional callback that pins and revalidates sensitive-path filesystem identity.
.PARAMETER PinnedHandles
Optional invocation-owned map that retains the no-delete handle through consumption and cleanup.
#>
function Write-AtlasoPackerVarFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][hashtable]$Variables,
        [scriptblock]$SensitivePathValidator,
        [hashtable]$PinnedHandles
    )

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Path) | Out-Null
    $lines = foreach ($key in ($Variables.Keys | Sort-Object)) {
        "$key = $(ConvertTo-AtlasoHclLiteral -Value $Variables[$key])"
    }
    Write-AtlasoPinnedUtf8Text `
        -Path $Path `
        -Text (($lines -join [System.Environment]::NewLine) + [System.Environment]::NewLine) `
        -SensitivePathValidator $SensitivePathValidator `
        -PinnedHandles $PinnedHandles
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
    $extension = [System.IO.Path]::GetExtension($Path)
    # Keep the retry leaf shorter than the ordinary destination. The remaster
    # helper adds its own GUID-bearing partial suffix before CreateFileW opens
    # it, so lengthening the fallback leaf can cross the Win32 path boundary.
    $token = [guid]::NewGuid().ToString('N').Substring(0, 12)
    return (Join-Path $directory ".atlaso-$token$extension")
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
    $preparedIsoDirectory = Split-Path -Parent $resolvedPreparedIsoPath

    if ($PrepareIsoOnly) {
        throw 'PrepareIsoOnly is not supported because a retained remastered ISO would contain reusable build credentials. Run Packer validation or a build so the ISO can be deleted after the bounded consumer exits.'
    }

    $preparedIsoCleanupPaths = [System.Collections.Generic.List[string]]::new()
    $pinnedPlaintextHandles = @{}
    try {
        try {
            Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $preparedIsoDirectory
            New-Item -ItemType Directory -Force -Path $preparedIsoDirectory | Out-Null
            Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $preparedIsoDirectory
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
                -InstallDiskLayout $InstallDiskLayout `
                -SensitivePathValidator $SensitivePathValidator `
                -PinnedHandles $pinnedPlaintextHandles
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
                    -CleanupPaths $preparedIsoCleanupPaths `
                    -SensitivePathValidator $SensitivePathValidator `
                    -PinnedHandles $pinnedPlaintextHandles
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
                    -CleanupPaths $preparedIsoCleanupPaths `
                    -SensitivePathValidator $SensitivePathValidator `
                    -PinnedHandles $pinnedPlaintextHandles
                Assert-AtlasoSensitiveBuildPath -Validator $SensitivePathValidator -Path $resolvedPreparedIsoPath
            }
        } finally {
            # The remastered ISO owns the consumed kickstart payload. Do not retain
            # its plaintext build password in the ignored repository workspace.
            Remove-AtlasoPinnedPlaintextFile `
                -Path $kickstartJson `
                -PinnedHandles $pinnedPlaintextHandles `
                -SensitivePathValidator $SensitivePathValidator
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
    Write-AtlasoPackerVarFile `
        -Path $varFilePath `
        -Variables $packerVariables `
        -SensitivePathValidator $SensitivePathValidator `
        -PinnedHandles $pinnedPlaintextHandles
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
                Remove-AtlasoPinnedPlaintextFile `
                    -Path $varFilePath `
                    -PinnedHandles $pinnedPlaintextHandles `
                    -SensitivePathValidator $SensitivePathValidator
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
                Remove-AtlasoPinnedPlaintextFile `
                    -Path $candidatePath `
                    -PinnedHandles $pinnedPlaintextHandles `
                    -SensitivePathValidator $SensitivePathValidator
            } catch {
                $preparedIsoCleanupFailures.Add("$candidatePath ($($_.Exception.Message))")
            }
        }
        if ($preparedIsoCleanupFailures.Count -gt 0) {
            $cleanupFailure = [System.InvalidOperationException]::new(
                "Remastered Photon ISO credential cleanup failed: $($preparedIsoCleanupFailures -join '; ')"
            )
            $cleanupFailure.Data['AtlasoPlaintextCleanupUnproven'] = $true
            throw $cleanupFailure
        }
    }
}

Export-ModuleMember -Function `
    Invoke-AtlasoPhotonImageBuild, `
    Get-AtlasoFileHashHex, `
    Test-AtlasoFileChecksum
