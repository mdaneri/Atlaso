<#
.SYNOPSIS
Deploys the current Atlaso wheel and deployment assets to a VMware test appliance.
.PARAMETER RepoRoot
Repository checkout used for build and deployment inputs.
.PARAMETER IpAddress
Explicit appliance IP address.
.PARAMETER VmxPath
VMX path used for VMware guest discovery and verified development host-key evidence.
.PARAMETER VmrunPath
Explicit VMware vmrun executable path.
.PARAMETER SshUser
Remote bootstrap SSH account.
.PARAMETER RemoteDirectory
Validated POSIX staging directory on the appliance.
.PARAMETER Python
Python executable used for build and the isolated deployment child.
.PARAMETER ReadinessTimeoutSeconds
Maximum post-restart readiness wait.
.PARAMETER DeploymentTimeoutSeconds
Maximum remote deployment-command wait.
.PARAMETER ReadinessPollSeconds
Readiness polling interval.
.PARAMETER SkipBuild
Uses existing local wheel artifacts.
.PARAMETER SkipHelperSync
Leaves the installed privileged helper unchanged.
.PARAMETER SkipConsoleAssetSync
Leaves console assets unchanged.
.PARAMETER SkipBootBrandingSync
Leaves boot-branding assets unchanged.
.PARAMETER SkipInventoryLinuxSync
Leaves Inventory Linux unchanged.
.PARAMETER WheelPath
Explicit Atlaso wheel path.
.PARAMETER RuntimeDependencyDirectory
Directory containing the complete exact dependency wheelhouse used with an explicit release wheel.
.PARAMETER OnePasswordEnvironmentId
Opaque ID of the preverified Atlaso 1Password Environment.
.PARAMETER OnePasswordAccount
1Password account name or ID approved for desktop SDK authorization.
.PARAMETER OnePasswordPython
CPython 3.10 through 3.13 executable used by the supported 1Password SDK Windows wheel and locked dependencies.
.PARAMETER UseVmwareGuestInfoHostKey
Trusts the selected normal test VM's verified Ed25519 guest-info key only for the password-backed child.
.PARAMETER ResetVaultEntries
Clears appliance vault entries during deployment.
.PARAMETER SkipHostCheck
Skips the final host-facing OpenAPI probe.
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingPlainTextForPassword',
    'OnePasswordEnvironmentId',
    Justification = 'Opaque Environment identifier; the SDK child retrieves the concealed password.'
)]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingPlainTextForPassword',
    'OnePasswordAccount',
    Justification = 'Desktop authorization account identifier, not an account password.'
)]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingPlainTextForPassword',
    'OnePasswordPython',
    Justification = 'Path to the approved Python interpreter, not a password.'
)]
[CmdletBinding()]
param(
    [string]$RepoRoot = '',
    [string]$IpAddress = '',
    [string]$VmxPath = '',
    [string]$VmrunPath = '',
    [string]$SshUser = 'admin',
    [string]$RemoteDirectory = '/tmp',
    [string]$Python = 'python',
    [int]$ReadinessTimeoutSeconds = 60,
    [int]$DeploymentTimeoutSeconds = 600,
    [int]$ReadinessPollSeconds = 2,
    [switch]$SkipBuild,
    [switch]$SkipHelperSync,
    [switch]$SkipConsoleAssetSync,
    [switch]$SkipBootBrandingSync,
    [switch]$SkipInventoryLinuxSync,
    [string]$WheelPath = '',
    [string]$RuntimeDependencyDirectory = '',
    [string]$OnePasswordEnvironmentId = '',
    [string]$OnePasswordAccount = '',
    [string]$OnePasswordPython = '',
    [switch]$UseVmwareGuestInfoHostKey,
    [switch]$ResetVaultEntries,
    [switch]$SkipHostCheck
)

$ErrorActionPreference = 'Stop'

$script:PasswordDeployLockName = 'requirements-onepassword-deploy.lock'

<#
.SYNOPSIS
Validates an opaque 1Password Environment ID before SDK access.
.PARAMETER EnvironmentId
Environment identifier copied from the exact Atlaso Environment.
#>
function Assert-OnePasswordEnvironmentId {
    param([Parameter(Mandatory = $true)][string]$EnvironmentId)

    if ($EnvironmentId -notmatch '^[A-Za-z0-9_-]{8,128}$') {
        throw 'The 1Password Environment ID is invalid. Copy the opaque ID from the exact Atlaso Environment.'
    }
}

<#
.SYNOPSIS
Validates the non-secret 1Password account selector used by desktop authorization.
.PARAMETER Account
1Password account name or ID.
#>
function Assert-OnePasswordAccount {
    param([Parameter(Mandatory = $true)][string]$Account)

    if ([string]::IsNullOrWhiteSpace($Account) -or $Account.Length -gt 255 -or $Account -match '[\x00-\x1f\x7f]') {
        throw 'The 1Password account name or ID is invalid.'
    }
}

<#
.SYNOPSIS
Resolves a Python runtime supported by the 1Password SDK Windows wheel.
.PARAMETER PythonCommand
Explicit CPython 3.10 through 3.13 executable or command.
#>
function Resolve-OnePasswordPython {
    param([Parameter(Mandatory = $true)][string]$PythonCommand)

    $command = Get-Command -Name $PythonCommand -CommandType Application -ErrorAction SilentlyContinue
    if (-not $command) {
        throw "The 1Password SDK Python executable was not found: $PythonCommand."
    }
    $resolvedCommand = $command.Source
    $version = & $resolvedCommand -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")'
    if ($LASTEXITCODE -ne 0 -or $version -notmatch '^3\.1[0-3]$') {
        throw 'Password-backed deployment requires a separate CPython 3.10 through 3.13 runtime supported by the locked 1Password SDK Windows dependencies.'
    }
    return $resolvedCommand
}

<#
.SYNOPSIS
Resolves the VMware Workstation vmrun executable.
.PARAMETER Path
Optional explicit executable path.
#>
function Resolve-VmrunPath {
    param([string]$Path)

    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path)) {
            throw "vmrun.exe not found: $Path"
        }
        return (Resolve-Path -LiteralPath $Path).Path
    }

    foreach ($candidate in @(
        'C:\Program Files\VMware\VMware Workstation\vmrun.exe',
        'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
    )) {
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    $command = Get-Command vmrun -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    throw 'vmrun.exe was not found. Install VMware Workstation Pro, pass -IpAddress, or pass -VmrunPath.'
}

<#
.SYNOPSIS
Resolves the repository root used for deployment inputs.
.PARAMETER Path
Optional explicit repository path.
#>
function Resolve-RepoRoot {
    param([string]$Path)

    if ($Path) {
        return (Resolve-Path -LiteralPath $Path).Path
    }
    return (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
}

<#
.SYNOPSIS
Runs a native command and fails on a nonzero exit code.
.PARAMETER FilePath
Executable path.
.PARAMETER Arguments
Separate native command arguments.
.PARAMETER WorkingDirectory
Optional command working directory.
#>
function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string[]]$Arguments,
        [string]$WorkingDirectory = ''
    )

    $previousLocation = Get-Location
    try {
        if ($WorkingDirectory) {
            Set-Location -LiteralPath $WorkingDirectory
        }
        & $FilePath @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "$FilePath $($Arguments -join ' ') failed with exit code $LASTEXITCODE."
        }
    } finally {
        Set-Location $previousLocation
    }
}

<#
.SYNOPSIS
Returns the exact running VMX entries reported by vmrun.
.PARAMETER ResolvedVmrun
Resolved vmrun executable path.
#>
function Get-AtlasoRunningVmx {
    param([string]$ResolvedVmrun)

    $running = @(& $ResolvedVmrun -T ws list 2>$null | Select-Object -Skip 1)
    if ($LASTEXITCODE -ne 0) {
        throw "vmrun list failed with exit code $LASTEXITCODE."
    }
    $candidates = @($running | Where-Object { $_ -match '(?i)Atlaso' })
    if ($candidates.Count -eq 1) {
        return $candidates[0]
    }
    if ($candidates.Count -gt 1) {
        throw "Multiple running Atlaso VMware VMs found. Pass -VmxPath explicitly: $($candidates -join '; ')"
    }
    if ($running.Count -eq 1) {
        return $running[0]
    }
    throw 'No running Atlaso VMware VM was found. Pass -IpAddress or -VmxPath.'
}

<#
.SYNOPSIS
Gets the guest IP address for the selected VMX.
.PARAMETER ResolvedVmrun
Resolved vmrun executable path.
.PARAMETER ResolvedVmxPath
Resolved VMX path.
#>
function Get-GuestIpAddress {
    param(
        [string]$ResolvedVmrun,
        [string]$ResolvedVmxPath
    )

    $ip = (& $ResolvedVmrun -T ws getGuestIPAddress $ResolvedVmxPath -wait 2>$null | Select-Object -First 1)
    if ($LASTEXITCODE -ne 0 -or $ip -notmatch '^\d+\.\d+\.\d+\.\d+$' -or $ip -like '169.254.*') {
        throw "No usable IPv4 address reported for VM '$ResolvedVmxPath'. Confirm open-vm-tools is running in the guest."
    }
    return $ip
}

<#
.SYNOPSIS
Selects and validates the Atlaso wheel to deploy.
.PARAMETER Path
Optional explicit wheel path.
.PARAMETER Root
Repository root containing generated wheels.
#>
function Get-WheelPath {
    param(
        [string]$Path,
        [string]$Root
    )

    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            throw "Wheel not found: $Path"
        }
        return (Resolve-Path -LiteralPath $Path).Path
    }
    $wheel = Get-ChildItem -LiteralPath (Join-Path $Root 'dist') -Filter 'atlaso-*.whl' -File |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if (-not $wheel) {
        throw "No Atlaso wheel found under $(Join-Path $Root 'dist'). Run without -SkipBuild or pass -WheelPath."
    }
    return $wheel.FullName
}

<#
.SYNOPSIS
Requires a native command to be available.
.PARAMETER Name
Command name.
#>
function Test-RequiredCommand {
    param([string]$Name)

    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $command) {
        throw "$Name was not found on PATH. Install Windows OpenSSH Client or run from a shell where $Name is available."
    }
    return $command.Source
}

<#
.SYNOPSIS
Validates the host-facing appliance OpenAPI endpoint.
.PARAMETER HostAddress
Appliance address to probe.
#>
function Invoke-HostOpenApiCheck {
    param([string]$HostAddress)

    $url = "https://$HostAddress/openapi.json"
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        & $curl.Source -k -f -sS $url | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Host OpenAPI check failed: $url"
        }
        return
    }

    try {
        Invoke-WebRequest -Uri $url -UseBasicParsing -SkipCertificateCheck | Out-Null
    } catch [System.Management.Automation.ParameterBindingException] {
        $previousCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
        try {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            Invoke-WebRequest -Uri $url -UseBasicParsing | Out-Null
        } finally {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $previousCallback
        }
    }
}

<#
.SYNOPSIS
Builds the shared strict SSH connection arguments.
.PARAMETER ControlPath
Optional SSH control-socket path.
#>
function Get-SshConnectionArguments {
    param([string]$ControlPath)

    if ($IsWindows -or $env:OS -eq 'Windows_NT') {
        return @()
    }

    return @(
        '-o', 'ControlMaster=auto',
        '-o', 'ControlPersist=60',
        '-o', "ControlPath=$ControlPath"
    )
}

<#
.SYNOPSIS
Validates and canonicalizes the remote POSIX staging directory.
.PARAMETER Path
Remote directory candidate.
#>
function Resolve-RemoteDirectoryPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $contractError = 'RemoteDirectory must be an absolute POSIX path using only ASCII letters, digits, /, ., _, and -, without . or .. path components.'
    if (
        [string]::IsNullOrWhiteSpace($Path) -or
        -not $Path.StartsWith('/', [System.StringComparison]::Ordinal) -or
        $Path -match '[\x00-\x1F\x7F]' -or
        $Path -notmatch '^/[A-Za-z0-9._/-]*\z' -or
        $Path.Contains('//', [System.StringComparison]::Ordinal)
    ) {
        throw $contractError
    }

    $components = @($Path.Trim('/').Split('/', [System.StringSplitOptions]::RemoveEmptyEntries))
    if ($components -contains '.' -or $components -contains '..') {
        throw $contractError
    }

    $normalized = $Path.TrimEnd('/')
    if (-not $normalized) {
        return '/'
    }
    return $normalized
}

<#
.SYNOPSIS
Joins a validated remote directory and leaf name.
.PARAMETER Directory
Canonical remote directory.
.PARAMETER Leaf
Remote leaf name.
#>
function Join-RemotePath {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$Leaf
    )

    if ($Directory -eq '/') {
        return "/$Leaf"
    }
    return "$Directory/$Leaf"
}

<#
.SYNOPSIS
Quotes one value as a literal POSIX shell argument.
.PARAMETER Value
Untrusted command argument to quote as one literal shell token.
#>
function ConvertTo-PosixShellArgument {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)

    $apostrophe = [char]0x27
    $doubleQuote = [char]0x22
    $escapedApostrophe = "$apostrophe$doubleQuote$apostrophe$doubleQuote$apostrophe"
    return "$apostrophe$($Value.Replace("$apostrophe", $escapedApostrophe))$apostrophe"
}

<#
.SYNOPSIS
Encodes a secret-free remote command for Windows OpenSSH transport.
.PARAMETER Command
Remote shell command.
#>
function ConvertTo-WindowsSshRemoteCommand {
    param([Parameter(Mandatory = $true)][string]$Command)

    if (-not ($IsWindows -or $env:OS -eq 'Windows_NT')) {
        return $Command
    }

    $encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Command))
    return "sh -lc `"printf '%s' $encodedCommand | base64 -d | sh`""
}

<#
.SYNOPSIS
Stages the vetted 1Password SDK deployment wheels.
.PARAMETER PythonCommand
Python executable.
.PARAMETER WorkingDirectory
Repository working directory.
#>
function Stage-PasswordDeployPythonWheels {
    param(
        [Parameter(Mandatory = $true)][string]$PythonCommand,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory
    )

    $lockPath = Join-Path $WorkingDirectory $script:PasswordDeployLockName
    $wheelDirectory = Join-Path $WorkingDirectory 'dist'
    if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
        throw "The vetted 1Password deployment lock is unavailable: $lockPath."
    }
    Write-Host 'Staging the vetted 1Password SDK and Paramiko deployment wheels...'
    Invoke-CheckedCommand -FilePath $PythonCommand -WorkingDirectory $WorkingDirectory -Arguments @(
        '-m', 'pip', 'download',
        '--disable-pip-version-check',
        '--index-url', 'https://pypi.org/simple',
        '--require-hashes',
        '--only-binary=:all:',
        '--dest', $wheelDirectory,
        '-r', $lockPath
    ) | Out-Host
}

<#
.SYNOPSIS
Creates an isolated Python dependency directory for 1Password and Paramiko.
.PARAMETER PythonCommand
Python executable.
.PARAMETER WorkingDirectory
Repository working directory.
.PARAMETER TemporaryDirectory
Private temporary deployment directory.
#>
function Initialize-PasswordDeployPythonPath {
    param(
        [Parameter(Mandatory = $true)][string]$PythonCommand,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$TemporaryDirectory
    )

    $wheelDirectory = Join-Path $WorkingDirectory 'dist'
    $lockPath = Join-Path $WorkingDirectory $script:PasswordDeployLockName
    if (-not (Test-Path -LiteralPath $wheelDirectory -PathType Container)) {
        throw "The vetted password-deployment wheel directory does not exist: $wheelDirectory. Rerun without -SkipBuild."
    }
    if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
        throw "The vetted 1Password deployment lock is unavailable: $lockPath."
    }

    $dependencyDirectory = Join-Path $TemporaryDirectory 'python-dependencies'
    New-Item -ItemType Directory -Force -Path $dependencyDirectory | Out-Null
    Write-Host 'Preparing the isolated 1Password SDK and Paramiko deployment runtime...'
    try {
        Invoke-CheckedCommand -FilePath $PythonCommand -WorkingDirectory $WorkingDirectory -Arguments @(
            '-m', 'pip', 'install',
            '--disable-pip-version-check',
            '--no-index',
            '--find-links', $wheelDirectory,
            '--require-hashes',
            '--target', $dependencyDirectory,
            '-r', $lockPath
        ) | Out-Host
    } catch {
        throw "Unable to prepare the isolated 1Password SDK and Paramiko deployment runtime. $($_.Exception.Message)"
    }
    return $dependencyDirectory
}

<#
.SYNOPSIS
Runs the bounded 1Password SDK and Paramiko password-backed deployment child.
.PARAMETER PythonCommand
Python executable used for the isolated child.
.PARAMETER HostAddress
Appliance SSH address.
.PARAMETER UserName
Remote bootstrap account.
.PARAMETER LocalWheelPath
Local Atlaso wheel path.
.PARAMETER LocalRuntimeDependencyPaths
Local runtime dependency wheel paths.
.PARAMETER LocalHelperPath
Optional local privileged helper path.
.PARAMETER LocalConsoleManagerPath
Optional local console-manager path.
.PARAMETER LocalBootInstallerPath
Optional local boot installer path.
.PARAMETER LocalBootThemePath
Optional local boot-theme path.
.PARAMETER LocalBootBackgroundPath
Optional local boot-background path.
.PARAMETER LocalInventoryLinuxPackagePath
Optional local Inventory Linux package path.
.PARAMETER LocalTrustKeyPaths
Local public release trust-key paths.
.PARAMETER LocalAtlasoServicePath
Local Atlaso systemd unit path.
.PARAMETER LocalWorkerServicePath
Local worker systemd unit path.
.PARAMETER LocalAtlasoServiceDropInPath
Local Atlaso data-disk dependency drop-in path.
.PARAMETER LocalNginxServiceDropInPath
Local nginx data-disk dependency drop-in path.
.PARAMETER LocalScriptPath
Local deployment script path.
.PARAMETER RemoteDirectoryPath
Validated remote staging directory.
.PARAMETER RemoteWheel
Remote Atlaso wheel path.
.PARAMETER RemoteRuntimeDependencies
Remote runtime dependency wheel paths.
.PARAMETER RemoteHelper
Optional remote privileged helper path.
.PARAMETER RemoteConsoleManager
Optional remote console-manager path.
.PARAMETER RemoteBootInstaller
Optional remote boot installer path.
.PARAMETER RemoteBootTheme
Optional remote boot-theme path.
.PARAMETER RemoteBootBackground
Optional remote boot-background path.
.PARAMETER RemoteInventoryLinuxPackage
Optional remote Inventory Linux package path.
.PARAMETER RemoteTrustKeys
Remote public release trust-key paths.
.PARAMETER RemoteAtlasoService
Remote Atlaso systemd unit path.
.PARAMETER RemoteWorkerService
Remote worker systemd unit path.
.PARAMETER RemoteAtlasoServiceDropIn
Remote Atlaso data-disk dependency drop-in path.
.PARAMETER RemoteNginxServiceDropIn
Remote nginx data-disk dependency drop-in path.
.PARAMETER RemoteScript
Remote deployment script path.
.PARAMETER ResetVaultEntryTable
Whether deployment clears vault entries.
.PARAMETER ReadinessTimeoutSeconds
Post-restart readiness timeout.
.PARAMETER DeploymentTimeoutSeconds
Remote command timeout.
.PARAMETER PollSeconds
Readiness polling interval.
.PARAMETER WorkingDirectory
Repository working directory.
.PARAMETER EnvironmentId
Opaque ID of the verified Atlaso Environment.
.PARAMETER Account
Account name or ID used for desktop authorization.
.PARAMETER TrustedHostKey
Optional verified Ed25519 host key supplied from VMware guest-info.
#>
function Invoke-PasswordBackedDeploy {
    param(
        [Parameter(Mandatory = $true)][string]$PythonCommand,
        [Parameter(Mandatory = $true)][string]$HostAddress,
        [Parameter(Mandatory = $true)][string]$UserName,
        [Parameter(Mandatory = $true)][string]$LocalWheelPath,
        [Parameter(Mandatory = $true)][string[]]$LocalRuntimeDependencyPaths,
        [string]$LocalHelperPath = '',
        [string]$LocalConsoleManagerPath = '',
        [string]$LocalBootInstallerPath = '',
        [string]$LocalBootThemePath = '',
        [string]$LocalBootBackgroundPath = '',
        [string]$LocalInventoryLinuxPackagePath = '',
        [Parameter(Mandatory = $true)][string[]]$LocalTrustKeyPaths,
        [Parameter(Mandatory = $true)][string]$LocalAtlasoServicePath,
        [Parameter(Mandatory = $true)][string]$LocalWorkerServicePath,
        [Parameter(Mandatory = $true)][string]$LocalAtlasoServiceDropInPath,
        [Parameter(Mandatory = $true)][string]$LocalNginxServiceDropInPath,
        [Parameter(Mandatory = $true)][string]$LocalScriptPath,
        [Parameter(Mandatory = $true)][string]$RemoteDirectoryPath,
        [Parameter(Mandatory = $true)][string]$RemoteWheel,
        [Parameter(Mandatory = $true)][string[]]$RemoteRuntimeDependencies,
        [string]$RemoteHelper = '',
        [string]$RemoteConsoleManager = '',
        [string]$RemoteBootInstaller = '',
        [string]$RemoteBootTheme = '',
        [string]$RemoteBootBackground = '',
        [string]$RemoteInventoryLinuxPackage = '',
        [Parameter(Mandatory = $true)][string[]]$RemoteTrustKeys,
        [Parameter(Mandatory = $true)][string]$RemoteAtlasoService,
        [Parameter(Mandatory = $true)][string]$RemoteWorkerService,
        [Parameter(Mandatory = $true)][string]$RemoteAtlasoServiceDropIn,
        [Parameter(Mandatory = $true)][string]$RemoteNginxServiceDropIn,
        [Parameter(Mandatory = $true)][string]$RemoteScript,
        [Parameter(Mandatory = $true)][bool]$ResetVaultEntryTable,
        [Parameter(Mandatory = $true)][int]$ReadinessTimeoutSeconds,
        [Parameter(Mandatory = $true)][int]$DeploymentTimeoutSeconds,
        [Parameter(Mandatory = $true)][int]$PollSeconds,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$EnvironmentId,
        [Parameter(Mandatory = $true)][string]$Account,
        [string]$TrustedHostKey = ''
    )

    $passwordDeployDirectory = Join-Path ([System.IO.Path]::GetTempPath()) "atlaso-password-deploy-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Force -Path $passwordDeployDirectory | Out-Null
    $pythonDeploy = Join-Path $passwordDeployDirectory 'atlaso-paramiko-deploy.py'
    $pythonDeploySource = @'
import argparse
import asyncio
import base64
import os
import pathlib
import re
import shlex
import socket
import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(errors="replace")


def shell_quote(value):
    return shlex.quote(str(value))


def sanitized(value, password):
    redacted = value.replace(password, "[redacted]")
    if password in redacted:
        raise SystemExit("Secret redaction failed; refusing to emit deployment output.")
    return redacted


def read_paramiko_command_output(channel, timeout_seconds):
    stdout_chunks = []
    stderr_chunks = []
    deadline = time.monotonic() + timeout_seconds
    while True:
        if time.monotonic() >= deadline:
            channel.close()
            raise SystemExit("Remote deployment output timed out; refusing to wait indefinitely.")
        drained = False
        while channel.recv_ready():
            stdout_chunks.append(channel.recv(65536))
            drained = True
        while channel.recv_stderr_ready():
            stderr_chunks.append(channel.recv_stderr(65536))
            drained = True
        if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
            break
        if not drained:
            time.sleep(0.01)
    return (
        b"".join(stdout_chunks).decode("utf-8", "replace"),
        b"".join(stderr_chunks).decode("utf-8", "replace"),
        channel.recv_exit_status(),
    )


parser = argparse.ArgumentParser()
parser.add_argument("--host", required=True)
parser.add_argument("--user", required=True)
parser.add_argument("--local-wheel", required=True)
parser.add_argument("--local-runtime-dependency", action="append", default=[])
parser.add_argument("--local-helper", default="")
parser.add_argument("--local-console-manager", default="")
parser.add_argument("--local-boot-installer", default="")
parser.add_argument("--local-boot-theme", default="")
parser.add_argument("--local-boot-background", default="")
parser.add_argument("--local-inventory-linux-package", default="")
parser.add_argument("--local-trust-key", action="append", default=[])
parser.add_argument("--local-atlaso-service", required=True)
parser.add_argument("--local-worker-service", required=True)
parser.add_argument("--local-atlaso-service-drop-in", required=True)
parser.add_argument("--local-nginx-service-drop-in", required=True)
parser.add_argument("--local-script", required=True)
parser.add_argument("--remote-dir", required=True)
parser.add_argument("--remote-wheel", required=True)
parser.add_argument("--remote-runtime-dependency", action="append", default=[])
parser.add_argument("--remote-helper", default="")
parser.add_argument("--remote-console-manager", default="")
parser.add_argument("--remote-boot-installer", default="")
parser.add_argument("--remote-boot-theme", default="")
parser.add_argument("--remote-boot-background", default="")
parser.add_argument("--remote-inventory-linux-package", default="")
parser.add_argument("--remote-trust-key", action="append", default=[])
parser.add_argument("--remote-atlaso-service", required=True)
parser.add_argument("--remote-worker-service", required=True)
parser.add_argument("--remote-atlaso-service-drop-in", required=True)
parser.add_argument("--remote-nginx-service-drop-in", required=True)
parser.add_argument("--remote-script", required=True)
parser.add_argument("--dependency-path", required=True)
parser.add_argument("--onepassword-account", required=True)
parser.add_argument("--onepassword-environment-id", required=True)
parser.add_argument("--trusted-host-key", default="")
parser.add_argument("--reset-vault-entries", action="store_true")
parser.add_argument("--timeout", type=int, required=True)
parser.add_argument("--readiness-timeout", type=int, required=True)
parser.add_argument("--poll", type=int, required=True)
args = parser.parse_args()

if not args.local_trust_key or len(args.local_trust_key) != len(args.remote_trust_key):
    raise SystemExit("At least one matched local and remote Atlaso release trust key is required.")
if not args.local_runtime_dependency or len(args.local_runtime_dependency) != len(args.remote_runtime_dependency):
    raise SystemExit("Matched local and remote runtime dependency wheels are required.")

sys.path.insert(0, args.dependency_path)
try:
    import paramiko
    from onepassword import Client, DesktopAuth
except ImportError as exc:
    raise SystemExit(
        "The isolated 1Password SDK and Paramiko deployment runtime could not be loaded."
    ) from exc


async def load_password():
    try:
        onepassword = await asyncio.wait_for(
            Client.authenticate(
                auth=DesktopAuth(account_name=args.onepassword_account),
                integration_name="Atlaso VMware deployment",
                integration_version="v1",
            ),
            timeout=args.timeout,
        )
        response = await asyncio.wait_for(
            onepassword.environments.get_variables(args.onepassword_environment_id),
            timeout=args.timeout,
        )
    except Exception as exc:
        raise SystemExit(
            "1Password desktop authorization or exact Environment access failed; no deployment was attempted."
        ) from None
    matches = [variable for variable in response.variables if variable.name == "DEFAULT_ADMIN_PASSWORD"]
    if len(matches) != 1 or not matches[0].masked or not matches[0].value:
        raise SystemExit(
            "The exact Atlaso 1Password Environment must contain one concealed DEFAULT_ADMIN_PASSWORD variable."
        )
    selected_password = matches[0].value
    del matches
    del response
    return selected_password


password = asyncio.run(load_password())

uploads = [
    (pathlib.Path(args.local_wheel), args.remote_wheel),
    (pathlib.Path(args.local_script), args.remote_script),
    (pathlib.Path(args.local_atlaso_service), args.remote_atlaso_service),
    (pathlib.Path(args.local_worker_service), args.remote_worker_service),
    (pathlib.Path(args.local_atlaso_service_drop_in), args.remote_atlaso_service_drop_in),
    (pathlib.Path(args.local_nginx_service_drop_in), args.remote_nginx_service_drop_in),
]
uploads.extend(
    (pathlib.Path(local_path), remote_path)
    for local_path, remote_path in zip(args.local_runtime_dependency, args.remote_runtime_dependency)
)
uploads.extend(
    (pathlib.Path(local_path), remote_path)
    for local_path, remote_path in zip(args.local_trust_key, args.remote_trust_key)
)
if args.local_helper:
    uploads.append((pathlib.Path(args.local_helper), args.remote_helper))
if args.local_console_manager:
    uploads.append((pathlib.Path(args.local_console_manager), args.remote_console_manager))
if args.local_boot_installer:
    uploads.extend(
        [
            (pathlib.Path(args.local_boot_installer), args.remote_boot_installer),
            (pathlib.Path(args.local_boot_theme), args.remote_boot_theme),
            (pathlib.Path(args.local_boot_background), args.remote_boot_background),
        ]
    )
if args.local_inventory_linux_package:
    uploads.append(
        (pathlib.Path(args.local_inventory_linux_package), args.remote_inventory_linux_package)
    )

def connect_password_or_keyboard_interactive(client, host, username, password):
    sock = socket.create_connection((host, 22), timeout=15)
    transport = paramiko.Transport(sock)
    try:
        known_key_entry = None
        for host_keys in (client._system_host_keys, client._host_keys):
            host_key_entry = host_keys.lookup(host)
            if host_key_entry:
                known_key_entry = host_key_entry
                break
        if known_key_entry is not None:
            # Match SSHClient.connect: negotiate the recorded host-key type first so a
            # different server key type cannot win before strict known-host checking.
            key_type = next(iter(known_key_entry.keys()))
            security_options = transport.get_security_options()
            if key_type == "ssh-rsa":
                if "rsa-sha2-512" in security_options.key_types:
                    key_type = "rsa-sha2-512"
                elif "rsa-sha2-256" in security_options.key_types:
                    key_type = "rsa-sha2-256"
                elif "ssh-rsa" not in security_options.key_types:
                    raise paramiko.SSHException("Recorded SSH host-key type is unavailable.")
            if key_type not in security_options.key_types:
                raise paramiko.SSHException("Recorded SSH host-key type is unavailable.")
            other_key_types = [item for item in security_options.key_types if item != key_type]
            security_options.key_types = [key_type] + other_key_types

        transport.start_client(timeout=15)
        server_key = transport.get_remote_server_key()
        if known_key_entry is None:
            raise paramiko.SSHException(
                f"Unknown SSH host key for {host}; add the verified key to known_hosts "
                "or pass the normal test VM's verified guest-info evidence with -VmxPath."
            )
        elif not any(server_key == expected_key for expected_key in known_key_entry.values()):
            expected_key = next(iter(known_key_entry.values()))
            raise paramiko.BadHostKeyException(host, server_key, expected_key)

        try:
            transport.auth_password(username, password, fallback=False)
        except (paramiko.AuthenticationException, paramiko.BadAuthenticationType):
            def keyboard_interactive_handler(title, instructions, prompts):
                if len(prompts) != 1:
                    raise paramiko.SSHException(
                        "Unexpected keyboard-interactive prompt count; refusing non-password input."
                    )
                prompt, echo = prompts[0]
                prompt_text = f"{title} {instructions} {prompt}".lower()
                if (
                    echo
                    or "password" not in prompt_text
                    or re.search(r"\b(?:otp|one[- ]?time|mfa|multi[- ]?factor|verification|code|token)\b", prompt_text)
                ):
                    raise paramiko.SSHException(
                        "Unexpected keyboard-interactive prompt; refusing non-password input."
                    )
                return [password]

            transport.auth_interactive(username, keyboard_interactive_handler)
        if not transport.is_authenticated():
            raise paramiko.AuthenticationException("Password or keyboard-interactive authentication failed.")
        client._transport = transport
    except Exception:
        transport.close()
        raise


def add_trusted_host_key(client, host, public_key):
    parts = public_key.split()
    if len(parts) != 2 or parts[0] != "ssh-ed25519":
        raise paramiko.SSHException("Verified VMware host-key evidence is not one Ed25519 public key.")
    try:
        key_blob = base64.b64decode(parts[1], validate=True)
        trusted_key = paramiko.PKey.from_type_string(parts[0], key_blob)
    except Exception:
        raise paramiko.SSHException("Verified VMware host-key evidence is malformed.") from None
    if trusted_key.get_name() != parts[0]:
        raise paramiko.SSHException("Verified VMware host-key evidence has an unexpected key type.")
    # This augments only the child's in-memory trust set. System known_hosts is
    # consulted first and remains authoritative when it already records the host.
    client.get_host_keys().add(host, parts[0], trusted_key)


client = paramiko.SSHClient()
client.load_system_host_keys()
client.set_missing_host_key_policy(paramiko.RejectPolicy())
if args.trusted_host_key:
    add_trusted_host_key(client, args.host, args.trusted_host_key)
connect_password_or_keyboard_interactive(client, args.host, args.user, password)
try:
    sftp = client.open_sftp()
    try:
        for local_path, remote_path in uploads:
            if not local_path.exists():
                raise SystemExit(f"Local deploy input is missing: {local_path}")
            sftp.put(str(local_path), remote_path)
        sftp.chmod(args.remote_script, 0o755)
        if args.local_boot_installer:
            sftp.chmod(args.remote_boot_installer, 0o755)
    finally:
        sftp.close()

    remote_helper_argument = args.remote_helper if args.local_helper else ""
    remote_console_manager_argument = args.remote_console_manager if args.local_console_manager else ""
    remote_boot_installer_argument = args.remote_boot_installer if args.local_boot_installer else ""
    remote_boot_theme_argument = args.remote_boot_theme if args.local_boot_installer else ""
    remote_boot_background_argument = args.remote_boot_background if args.local_boot_installer else ""
    remote_inventory_linux_package_argument = (
        args.remote_inventory_linux_package if args.local_inventory_linux_package else ""
    )
    remote_runtime_dependencies_argument = ":".join(args.remote_runtime_dependency)
    remote_trust_keys_argument = ":".join(args.remote_trust_key)
    command = (
        "sudo -S -p '' sh "
        f"{shell_quote(args.remote_script)} "
        f"{shell_quote(args.remote_wheel)} "
        f"{shell_quote(args.readiness_timeout)} "
        f"{shell_quote(args.poll)} "
        f"{shell_quote(remote_helper_argument)} "
        f"{shell_quote(remote_console_manager_argument)} "
        f"{shell_quote(remote_boot_installer_argument)} "
        f"{shell_quote(remote_boot_theme_argument)} "
        f"{shell_quote(remote_boot_background_argument)} "
        f"{shell_quote(args.remote_atlaso_service)} "
        f"{shell_quote(args.remote_worker_service)} "
        f"{shell_quote(args.remote_atlaso_service_drop_in)} "
        f"{shell_quote(args.remote_nginx_service_drop_in)} "
        f"{shell_quote(remote_runtime_dependencies_argument)} "
        f"{shell_quote(remote_trust_keys_argument)} "
        f"{shell_quote('true' if args.reset_vault_entries else 'false')} "
        f"{shell_quote(remote_inventory_linux_package_argument)}"
    )
    stdin, stdout, stderr = client.exec_command(command, get_pty=False, timeout=args.timeout)
    stdin.write(password + "\n")
    stdin.flush()
    stdin.channel.shutdown_write()
    stdout_text, stderr_text, exit_code = read_paramiko_command_output(stdout.channel, args.timeout)
    if stdout_text.strip():
        print(sanitized(stdout_text, password).strip())
    if stderr_text.strip():
        print(sanitized(stderr_text, password).strip(), file=sys.stderr)
    if exit_code:
        raise SystemExit(exit_code)
finally:
    client.close()
'@
    [System.IO.File]::WriteAllText($pythonDeploy, ($pythonDeploySource -replace "`r?`n", "`n"), [System.Text.UTF8Encoding]::new($false))

    try {
        $pythonDependencyPath = Initialize-PasswordDeployPythonPath `
            -PythonCommand $PythonCommand `
            -WorkingDirectory $WorkingDirectory `
            -TemporaryDirectory $passwordDeployDirectory
        $deployArguments = @(
            '-I', '-S', $pythonDeploy,
            '--dependency-path', $pythonDependencyPath,
            '--onepassword-account', $Account,
            '--onepassword-environment-id', $EnvironmentId,
            '--host', $HostAddress,
            '--user', $UserName,
            '--local-wheel', $LocalWheelPath,
            '--local-script', $LocalScriptPath,
            '--remote-dir', $RemoteDirectoryPath,
            '--remote-wheel', $RemoteWheel,
            '--remote-script', $RemoteScript,
            '--timeout', "$DeploymentTimeoutSeconds",
            '--readiness-timeout', "$ReadinessTimeoutSeconds",
            '--poll', "$PollSeconds"
        )
        foreach ($optionalPathPair in @(
            @('--local-helper', $LocalHelperPath, '--remote-helper', $RemoteHelper),
            @('--local-console-manager', $LocalConsoleManagerPath, '--remote-console-manager', $RemoteConsoleManager),
            @('--local-boot-installer', $LocalBootInstallerPath, '--remote-boot-installer', $RemoteBootInstaller),
            @('--local-boot-theme', $LocalBootThemePath, '--remote-boot-theme', $RemoteBootTheme),
            @('--local-boot-background', $LocalBootBackgroundPath, '--remote-boot-background', $RemoteBootBackground),
            @(
                '--local-inventory-linux-package',
                $LocalInventoryLinuxPackagePath,
                '--remote-inventory-linux-package',
                $RemoteInventoryLinuxPackage
            )
        )) {
            $localPath = [string]$optionalPathPair[1]
            $remotePath = [string]$optionalPathPair[3]
            if (-not $localPath -and -not $remotePath) {
                continue
            }
            if (-not $localPath -or -not $remotePath) {
                throw "Optional deployment paths must provide both $($optionalPathPair[0]) and $($optionalPathPair[2])."
            }
            $deployArguments += $optionalPathPair
        }
        if ($ResetVaultEntryTable) {
            $deployArguments += '--reset-vault-entries'
        }
        if ($TrustedHostKey) {
            $deployArguments += @('--trusted-host-key', $TrustedHostKey)
        }
        foreach ($runtimeDependencyPath in $LocalRuntimeDependencyPaths) {
            $deployArguments += @('--local-runtime-dependency', $runtimeDependencyPath)
        }
        foreach ($remoteRuntimeDependency in $RemoteRuntimeDependencies) {
            $deployArguments += @('--remote-runtime-dependency', $remoteRuntimeDependency)
        }
        foreach ($trustKeyPath in $LocalTrustKeyPaths) {
            $deployArguments += @('--local-trust-key', $trustKeyPath)
        }
        foreach ($remoteTrustKey in $RemoteTrustKeys) {
            $deployArguments += @('--remote-trust-key', $remoteTrustKey)
        }
        $deployArguments += @(
            '--local-atlaso-service', $LocalAtlasoServicePath,
            '--remote-atlaso-service', $RemoteAtlasoService,
            '--local-worker-service', $LocalWorkerServicePath,
            '--remote-worker-service', $RemoteWorkerService,
            '--local-atlaso-service-drop-in', $LocalAtlasoServiceDropInPath,
            '--remote-atlaso-service-drop-in', $RemoteAtlasoServiceDropIn,
            '--local-nginx-service-drop-in', $LocalNginxServiceDropInPath,
            '--remote-nginx-service-drop-in', $RemoteNginxServiceDropIn
        )
        Invoke-CheckedCommand -FilePath $PythonCommand -Arguments $deployArguments -WorkingDirectory $WorkingDirectory
    } finally {
        Remove-Item -LiteralPath $passwordDeployDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($env:DEFAULT_ADMIN_PASSWORD) {
    throw 'DEFAULT_ADMIN_PASSWORD must not be supplied by the caller; use the exact Atlaso 1Password Environment bridge.'
}

$resolvedRepoRoot = Resolve-RepoRoot -Path $RepoRoot
$RemoteDirectory = Resolve-RemoteDirectoryPath -Path $RemoteDirectory

$UsePasswordDeploy = -not [string]::IsNullOrEmpty($OnePasswordEnvironmentId)
$resolvedOnePasswordPython = ''
if ($UsePasswordDeploy) {
    Assert-OnePasswordEnvironmentId -EnvironmentId $OnePasswordEnvironmentId
    Assert-OnePasswordAccount -Account $OnePasswordAccount
    if ([string]::IsNullOrWhiteSpace($OnePasswordPython)) {
        throw '-OnePasswordPython is required with -OnePasswordEnvironmentId.'
    }
    $resolvedOnePasswordPython = Resolve-OnePasswordPython -PythonCommand $OnePasswordPython
} elseif ($OnePasswordAccount -or $OnePasswordPython) {
    throw '-OnePasswordAccount and -OnePasswordPython require -OnePasswordEnvironmentId.'
}
if ($UseVmwareGuestInfoHostKey -and (-not $UsePasswordDeploy -or -not $VmxPath)) {
    throw '-UseVmwareGuestInfoHostKey requires password-backed deployment and an explicit normal test VM -VmxPath.'
}

$generatedRuntimeDependencyRoot = ''
$generatedWheelPath = ''
if (-not $SkipBuild) {
    New-Item -ItemType Directory -Force -Path (Join-Path $resolvedRepoRoot 'dist') | Out-Null
    # Dependency selection must not inherit stale wheels from an earlier version.
    $generatedRuntimeDependencyRoot = Join-Path (
        [System.IO.Path]::GetTempPath()
    ) "atlaso-runtime-wheels-$([guid]::NewGuid().ToString('N'))"
    New-Item -ItemType Directory -Path $generatedRuntimeDependencyRoot | Out-Null
    Write-Host "Building Atlaso wheel..."
    try {
        Invoke-CheckedCommand -FilePath $Python -Arguments @(
            '-m', 'pip', 'wheel', '.', '-w', $generatedRuntimeDependencyRoot
        ) -WorkingDirectory $resolvedRepoRoot
        $generatedWheels = @(
            Get-ChildItem -LiteralPath $generatedRuntimeDependencyRoot -Filter 'atlaso-*.whl' -File
        )
        if ($generatedWheels.Count -ne 1) {
            throw "The fresh wheel build produced $($generatedWheels.Count) Atlaso wheels; exactly one is required."
        }
        $generatedWheelPath = Join-Path $resolvedRepoRoot "dist\$($generatedWheels[0].Name)"
        Copy-Item -LiteralPath $generatedWheels[0].FullName -Destination $generatedWheelPath -Force
    } catch {
        Remove-Item -LiteralPath $generatedRuntimeDependencyRoot -Recurse -Force -ErrorAction SilentlyContinue
        throw
    }
    if ($UsePasswordDeploy) {
        Stage-PasswordDeployPythonWheels -PythonCommand $resolvedOnePasswordPython -WorkingDirectory $resolvedRepoRoot
    }
}

$resolvedWheelPath = if ($generatedWheelPath -and [string]::IsNullOrWhiteSpace($WheelPath)) {
    $generatedWheelPath
}
else {
    Get-WheelPath -Path $WheelPath -Root $resolvedRepoRoot
}
$wheelName = Split-Path -Leaf $resolvedWheelPath
$runtimeDependencyRoot = if ([string]::IsNullOrWhiteSpace($RuntimeDependencyDirectory)) {
    if ($generatedRuntimeDependencyRoot) {
        $generatedRuntimeDependencyRoot
    }
    else {
        Join-Path $resolvedRepoRoot 'dist'
    }
}
else {
    $candidate = Get-Item -LiteralPath $RuntimeDependencyDirectory -ErrorAction Stop
    if (-not $candidate.PSIsContainer -or
        ($candidate.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'RuntimeDependencyDirectory must be an ordinary directory, not a reparse point.'
    }
    $candidate.FullName
}
$runtimeDependencies = if ([string]::IsNullOrWhiteSpace($RuntimeDependencyDirectory)) {
    @(
        foreach ($runtimeDependencyPattern in @('authlib-*.whl', 'joserfc-*.whl', 'pycdlib-*.whl')) {
            $runtimeDependency = @(Get-ChildItem -LiteralPath $runtimeDependencyRoot -Filter $runtimeDependencyPattern -File)
            if ($runtimeDependency.Count -ne 1) {
                throw "Exactly one $runtimeDependencyPattern runtime dependency wheel is required under $runtimeDependencyRoot. Rerun without -SkipBuild or provide the verified release wheelhouse."
            }
            $runtimeDependency[0]
        }
    )
}
else {
    @(Get-ChildItem -LiteralPath $runtimeDependencyRoot -Filter '*.whl' -File | Sort-Object Name)
}
$runtimeDependencyPaths = @($runtimeDependencies | Select-Object -ExpandProperty FullName)
$runtimeDependencyNames = @($runtimeDependencies | Select-Object -ExpandProperty Name)
if ($runtimeDependencyPaths.Count -lt 3 -or $runtimeDependencyNames.Count -ne (@($runtimeDependencyNames | Sort-Object -Unique)).Count) {
    throw 'The runtime dependency wheel set is incomplete or contains duplicate file names.'
}
foreach ($runtimeDependencyPattern in @('authlib-*.whl', 'joserfc-*.whl', 'pycdlib-*.whl')) {
    if (@($runtimeDependencies | Where-Object { $_.Name -like $runtimeDependencyPattern }).Count -ne 1) {
        throw "The runtime dependency wheel set requires exactly one $runtimeDependencyPattern wheel."
    }
}
$helperPath = Join-Path $resolvedRepoRoot 'scripts\appliance\atlaso-helper'
$consoleManagerPath = Join-Path $resolvedRepoRoot 'image\common\systemd\atlaso-console-manager.conf'
$bootInstallerPath = Join-Path $resolvedRepoRoot 'scripts\appliance\atlaso-install-boot-branding'
$bootThemePath = Join-Path $resolvedRepoRoot 'image\common\boot\grub\theme.txt'
$bootBackgroundPath = Join-Path $resolvedRepoRoot 'image\common\boot\grub\atlaso.png'
$trustKeyDirectory = Join-Path $resolvedRepoRoot 'image\common\update-trust'
$trustKeyPaths = @(
    Get-ChildItem -LiteralPath $trustKeyDirectory -Filter '*.pem' -File -ErrorAction SilentlyContinue |
        Sort-Object Name |
        Select-Object -ExpandProperty FullName
)
$atlasoServicePath = Join-Path $resolvedRepoRoot 'image\common\systemd\atlaso.service'
$workerServicePath = Join-Path $resolvedRepoRoot 'image\common\systemd\atlaso-worker.service'
$atlasoServiceDropInPath = Join-Path $resolvedRepoRoot 'image\common\systemd\atlaso-require-data-disks.conf'
$nginxServiceDropInPath = Join-Path $resolvedRepoRoot 'image\common\systemd\nginx-atlaso-data-disks.conf'
$inventoryLinuxPackagePath = ''
if (-not $SkipInventoryLinuxSync) {
    $inventoryLinuxOutput = Join-Path $resolvedRepoRoot 'image\inventory-linux\output'
    foreach ($inventoryAsset in @('bzImage', 'rootfs.cpio.gz', 'manifest.json')) {
        if (-not (Test-Path -LiteralPath (Join-Path $inventoryLinuxOutput $inventoryAsset) -PathType Leaf)) {
            throw "Bundled Inventory Linux output is missing $inventoryAsset. Run scripts/windows/common/Build-AtlasoInventoryLinux.ps1 or pass -SkipInventoryLinuxSync."
        }
    }
    $inventoryPackageOutput = Join-Path $resolvedRepoRoot 'dist\inventory-linux'
    Invoke-CheckedCommand -FilePath $Python -WorkingDirectory $resolvedRepoRoot -Arguments @(
        'scripts/build_inventory_linux_package.py',
        '--source', $inventoryLinuxOutput,
        '--output', $inventoryPackageOutput
    )
    $inventoryLinuxPackagePath = (
        Get-ChildItem -LiteralPath $inventoryPackageOutput -Filter 'atlaso-inventory-linux-*.zip' -File |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
    ).FullName
}
if (-not $SkipHelperSync -and -not (Test-Path -LiteralPath $helperPath -PathType Leaf)) {
    throw "Atlaso helper script not found: $helperPath"
}
if (-not $SkipConsoleAssetSync -and -not (Test-Path -LiteralPath $consoleManagerPath -PathType Leaf)) {
    throw "Atlaso console manager config not found: $consoleManagerPath"
}
if (-not $SkipBootBrandingSync) {
    foreach ($bootAsset in @($bootInstallerPath, $bootThemePath, $bootBackgroundPath)) {
        if (-not (Test-Path -LiteralPath $bootAsset -PathType Leaf)) {
            throw "Atlaso boot branding asset not found: $bootAsset"
        }
    }
}
if (-not (Test-Path -LiteralPath $atlasoServicePath -PathType Leaf)) {
    throw "Atlaso service not found: $atlasoServicePath"
}
if (-not (Test-Path -LiteralPath $workerServicePath -PathType Leaf)) {
    throw "Atlaso worker service not found: $workerServicePath"
}
foreach ($serviceDropInPath in @($atlasoServiceDropInPath, $nginxServiceDropInPath)) {
    if (-not (Test-Path -LiteralPath $serviceDropInPath -PathType Leaf)) {
        throw "Atlaso service drop-in not found: $serviceDropInPath"
    }
}
if ($trustKeyPaths.Count -eq 0) {
    throw "No Atlaso release trust keys found under: $trustKeyDirectory"
}
$remoteWheelPath = Join-RemotePath -Directory $RemoteDirectory -Leaf $wheelName
$remoteRuntimeDependencyPaths = @(
    $runtimeDependencyNames | ForEach-Object {
        Join-RemotePath -Directory $RemoteDirectory -Leaf $_
    }
)
$remoteHelperPath = Join-RemotePath -Directory $RemoteDirectory -Leaf 'atlaso-helper'
$remoteConsoleManagerPath = Join-RemotePath -Directory $RemoteDirectory -Leaf 'atlaso-console-manager.conf'
$remoteBootInstallerPath = Join-RemotePath -Directory $RemoteDirectory -Leaf 'atlaso-install-boot-branding'
$remoteBootThemePath = Join-RemotePath -Directory $RemoteDirectory -Leaf 'atlaso-grub-theme.txt'
$remoteBootBackgroundPath = Join-RemotePath -Directory $RemoteDirectory -Leaf 'atlaso-grub.png'
$remoteTrustKeyPaths = @(
    $trustKeyPaths | ForEach-Object {
        Join-RemotePath -Directory $RemoteDirectory -Leaf (Split-Path -Leaf $_)
    }
)
$remoteAtlasoServicePath = Join-RemotePath -Directory $RemoteDirectory -Leaf 'atlaso.service'
$remoteWorkerServicePath = Join-RemotePath -Directory $RemoteDirectory -Leaf 'atlaso-worker.service'
$remoteAtlasoServiceDropInPath = Join-RemotePath -Directory $RemoteDirectory -Leaf 'atlaso-require-data-disks.conf'
$remoteNginxServiceDropInPath = Join-RemotePath -Directory $RemoteDirectory -Leaf 'nginx-atlaso-data-disks.conf'
$remoteInventoryLinuxPackagePath = if ($inventoryLinuxPackagePath) {
    Join-RemotePath -Directory $RemoteDirectory -Leaf (Split-Path -Leaf $inventoryLinuxPackagePath)
} else {
    ''
}
$remoteScriptPath = Join-RemotePath -Directory $RemoteDirectory -Leaf 'atlaso-deploy-wheel.sh'

$resolvedVmrun = ''
$resolvedVmxPath = ''
if ($VmxPath -or -not $IpAddress) {
    $resolvedVmrun = Resolve-VmrunPath -Path $VmrunPath
    if (-not $VmxPath) {
        $VmxPath = Get-AtlasoRunningVmx -ResolvedVmrun $resolvedVmrun
    }
    $resolvedVmxPath = (Resolve-Path -LiteralPath $VmxPath).Path
}
if (-not $IpAddress) {
    $IpAddress = Get-GuestIpAddress -ResolvedVmrun $resolvedVmrun -ResolvedVmxPath $resolvedVmxPath
}

$trustedSshHostKey = ''
if ($UseVmwareGuestInfoHostKey) {
    $workstationFirstBootPath = Join-Path $resolvedRepoRoot 'scripts\windows\vmware\Atlaso.WorkstationFirstBoot.ps1'
    . $workstationFirstBootPath
    $trustedSshHostKey = (Get-AtlasoWorkstationSshHostKey `
            -VmxPath $resolvedVmxPath `
            -VmrunPath $resolvedVmrun `
            -TimeoutSeconds 15 `
            -PollSeconds $ReadinessPollSeconds).PublicKey
}

if (-not $UsePasswordDeploy) {
    Test-RequiredCommand -Name 'scp' | Out-Null
    Test-RequiredCommand -Name 'ssh' | Out-Null
}

$deployScript = @'
#!/bin/sh
set -eu

wheel="${1:?wheel path required}"
timeout_seconds="${2:-60}"
poll_seconds="${3:-2}"
helper_path="${4:-}"
console_manager_path="${5:-}"
boot_installer_path="${6:-}"
boot_theme_path="${7:-}"
boot_background_path="${8:-}"
atlaso_service_path="${9:?atlaso service path required}"
worker_service_path="${10:?worker service path required}"
atlaso_service_drop_in_path="${11:?Atlaso service drop-in path required}"
nginx_service_drop_in_path="${12:?nginx service drop-in path required}"
runtime_dependency_paths="${13:?runtime dependency wheel paths required}"
trust_key_paths="${14:?release trust key paths required}"
reset_vault_entries="${15:-false}"
inventory_linux_package="${16:-}"
venv="/opt/atlaso/.venv"
python="$venv/bin/python"

if [ ! -x "$python" ]; then
    echo "Atlaso venv python not found or not executable: $python" >&2
    exit 2
fi

preflight_powershell_layouts() {
    pwsh_path="$(command -v pwsh || true)"
    if [ -z "$pwsh_path" ]; then
        return
    fi
    if ! powershell_binary="$(readlink -f "$pwsh_path")" || [ -z "$powershell_binary" ]; then
        echo "PowerShell executable could not be resolved through a canonical path." >&2
        exit 2
    fi
    powershell_home="$(dirname "$powershell_binary")"
    case "$powershell_home" in
        /usr/share/powershell)
            powershell_ancestors="/ /usr /usr/share /usr/share/powershell"
            inactive_powershell_home="/opt/microsoft/powershell/7"
            inactive_powershell_ancestors="/ /opt /opt/microsoft /opt/microsoft/powershell /opt/microsoft/powershell/7"
            ;;
        /opt/microsoft/powershell/7)
            powershell_ancestors="/ /opt /opt/microsoft /opt/microsoft/powershell /opt/microsoft/powershell/7"
            inactive_powershell_home="/usr/share/powershell"
            inactive_powershell_ancestors="/ /usr /usr/share /usr/share/powershell"
            ;;
        *)
            echo "PowerShell resolved to an unsupported global profile directory: $powershell_home" >&2
            exit 2
            ;;
    esac
    powershell_binary_metadata="$(stat -c '%u:%g:%a' "$powershell_binary")"
    old_ifs="$IFS"
    IFS=:
    set -- $powershell_binary_metadata
    IFS="$old_ifs"
    if [ ! -f "$powershell_binary" ] || [ "$1" != "0" ] || [ "$2" != "0" ] || \
        [ $((0$3 & 0022)) -ne 0 ] || [ $((0$3 & 0111)) -eq 0 ]; then
        echo "PowerShell executable must be root-owned, executable, and non-writable by group or other: $powershell_binary" >&2
        exit 2
    fi
    for powershell_directory in $powershell_ancestors; do
        if [ -L "$powershell_directory" ] || [ ! -d "$powershell_directory" ]; then
            echo "PowerShell profile directory must be a canonical directory: $powershell_directory" >&2
            exit 2
        fi
        powershell_metadata="$(stat -c '%u:%g:%a' "$powershell_directory")"
        old_ifs="$IFS"
        IFS=:
        set -- $powershell_metadata
        IFS="$old_ifs"
        if [ "$1" != "0" ] || [ "$2" != "0" ]; then
            echo "PowerShell profile directory must be owned by root: $powershell_directory" >&2
            exit 2
        fi
        if [ $((0$3 & 0022)) -ne 0 ]; then
            echo "PowerShell profile directory must not be writable by group or other: $powershell_directory" >&2
            exit 2
        fi
    done
    powershell_profile="$powershell_home/profile.ps1"
    if [ -L "$powershell_profile" ] || { [ -e "$powershell_profile" ] && [ ! -f "$powershell_profile" ]; }; then
        echo "PowerShell global profile path must be a regular file or absent: $powershell_profile" >&2
        exit 2
    fi
    inactive_powershell_profile="$inactive_powershell_home/profile.ps1"
    if [ -L "$inactive_powershell_profile" ] || [ -e "$inactive_powershell_profile" ]; then
        for powershell_directory in $inactive_powershell_ancestors; do
            if [ -L "$powershell_directory" ] || [ ! -d "$powershell_directory" ]; then
                echo "PowerShell profile directory must be a canonical directory: $powershell_directory" >&2
                exit 2
            fi
            powershell_metadata="$(stat -c '%u:%g:%a' "$powershell_directory")"
            old_ifs="$IFS"
            IFS=:
            set -- $powershell_metadata
            IFS="$old_ifs"
            if [ "$1" != "0" ] || [ "$2" != "0" ]; then
                echo "PowerShell profile directory must be owned by root: $powershell_directory" >&2
                exit 2
            fi
            if [ $((0$3 & 0022)) -ne 0 ]; then
                echo "PowerShell profile directory must not be writable by group or other: $powershell_directory" >&2
                exit 2
            fi
        done
        if [ -L "$inactive_powershell_profile" ] || [ ! -f "$inactive_powershell_profile" ] || \
            [ "$(stat -c '%u:%g:%a' "$inactive_powershell_profile")" != "0:0:644" ] || \
            ! cmp -s -- "$inactive_powershell_profile" - <<'ATLASO_EXPECTED_GLOBAL_POWERSHELL_PROFILE'
<#
.SYNOPSIS
Loads the Atlaso vault helpers into PowerShell sessions.
#>
. '/opt/atlaso/bin/atlaso-vault-profile.ps1'
ATLASO_EXPECTED_GLOBAL_POWERSHELL_PROFILE
        then
            echo "Inactive PowerShell global profile is not Atlaso-owned: $inactive_powershell_profile" >&2
            exit 2
        fi
    fi
}

# Validate every supported PowerShell path before package or service mutation.
# Re-run immediately before profile installation to retain the same trust boundary.
preflight_powershell_layouts

if ! command -v gpg >/dev/null 2>&1; then
    if ! command -v tdnf >/dev/null 2>&1; then
        echo "GnuPG is required for signed Network Boot media and tdnf is unavailable." >&2
        exit 2
    fi
    echo "Installing GnuPG for signed Network Boot media verification..."
    tdnf -y install gnupg
fi

old_ifs="$IFS"
IFS=:
for runtime_dependency_path in $runtime_dependency_paths; do
    "$python" -m pip install --force-reinstall --no-compile --no-deps "$runtime_dependency_path"
done
IFS="$old_ifs"
"$python" -m pip install --force-reinstall --no-compile --no-deps "$wheel"
site_packages="$("$python" -c 'import sysconfig; print(sysconfig.get_path("purelib"))')"
if [ "$site_packages" != "$venv/lib/python3.14/site-packages" ]; then
    echo "Atlaso site-packages resolved outside the active environment." >&2
    exit 2
fi
find "$site_packages" -type f -name '*.pyc' -delete
find "$site_packages" -depth -type d -name __pycache__ -empty -delete
atlaso_was_active=false
worker_was_active=false
if systemctl is-active --quiet atlaso.service; then
    atlaso_was_active=true
fi
if systemctl is-active --quiet atlaso-worker.service; then
    worker_was_active=true
fi
restore_services_on_exit() {
    exit_status=$?
    trap - EXIT
    set +e
    if [ "$atlaso_was_active" = "true" ]; then
        systemctl restart atlaso.service
    else
        systemctl stop atlaso.service
    fi
    if [ "$worker_was_active" = "true" ]; then
        systemctl restart atlaso-worker.service
    else
        systemctl stop atlaso-worker.service
    fi
    exit "$exit_status"
}
trap restore_services_on_exit EXIT
systemctl stop atlaso-worker.service atlaso.service
"$python" - <<'PY'
import pathlib

required_directories = (
    pathlib.Path("/var/lib/atlaso"),
    pathlib.Path("/var/lib/atlaso/pxe"),
)
optional_directories = (
    pathlib.Path("/var/lib/atlaso/pxe/media"),
    pathlib.Path("/var/lib/atlaso/pxe/uploads"),
)
for directory in (*required_directories, *optional_directories):
    if directory.is_symlink():
        raise SystemExit(f"Atlaso media path must not be a symlink: {directory}")
    if directory.exists() and not directory.is_dir():
        raise SystemExit(f"Atlaso media path must be a directory: {directory}")
for directory in required_directories:
    if not directory.is_dir():
        raise SystemExit(f"Required Atlaso media parent is missing: {directory}")
PY
install -d -o atlaso -g atlaso -m 0755 /var/lib/atlaso/pxe/media /var/lib/atlaso/pxe/uploads
if [ "$reset_vault_entries" = "true" ]; then
    sqlite3 /var/lib/atlaso/atlaso.db 'DROP TABLE IF EXISTS vault_entries;'
    echo "Reset vault_entries table; Atlaso will recreate it from the installed model."
fi
if [ -n "$inventory_linux_package" ]; then
    "$python" - "$inventory_linux_package" <<'PY'
import hashlib
import json
import pathlib
import re
import secrets
import shutil
import sys
import tempfile
import zipfile

package = pathlib.Path(sys.argv[1])
with zipfile.ZipFile(package) as archive:
    names = set(archive.namelist())
    if not {"manifest.json", "bzImage", "rootfs.cpio.gz"} <= names:
        raise SystemExit("Atlaso Inventory Linux package is incomplete.")
    manifest = json.loads(archive.read("manifest.json"))
    version = str(manifest.get("version") or "")
    if (
        manifest.get("kind") != "atlaso-inventory-linux"
        or manifest.get("schema_version") != 1
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,118}[A-Za-z0-9]", version) is None
    ):
        raise SystemExit("Atlaso Inventory Linux package identity is invalid.")
    target = pathlib.Path("/var/lib/atlaso/pxe/media/inventory") / version
    if target.parent.is_symlink():
        raise SystemExit("Atlaso Inventory Linux media root must not be a symlink.")
    if target.parent.exists() and not target.parent.is_dir():
        raise SystemExit("Atlaso Inventory Linux media root must be a directory.")
    target.parent.mkdir(exist_ok=True)
    target.parent.chmod(0o755)
    if target.is_symlink():
        raise SystemExit(
            f"Atlaso Inventory Linux {version} target must not be a symlink."
        )
    if target.exists() and not target.is_dir():
        raise SystemExit(
            f"Atlaso Inventory Linux {version} target must be a directory."
        )
    with tempfile.TemporaryDirectory(prefix=".inventory-", dir=target.parent) as temporary:
        staging = pathlib.Path(temporary)
        staging.chmod(0o755)
        for name in ("bzImage", "rootfs.cpio.gz"):
            destination = staging / name
            with archive.open(name) as source, destination.open("wb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
            actual = hashlib.sha256(destination.read_bytes()).hexdigest()
            expected = str((manifest.get("artifacts") or {}).get(name) or "").lower()
            if not secrets.compare_digest(actual, expected):
                raise SystemExit(f"Atlaso Inventory Linux artifact digest mismatch: {name}")
            destination.chmod(0o644)
        (staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (staging / "manifest.json").chmod(0o644)
        if target.exists():
            for name in ("bzImage", "rootfs.cpio.gz"):
                installed_artifact = target / name
                if (
                    installed_artifact.is_symlink()
                    or not installed_artifact.is_file()
                    or installed_artifact.read_bytes() != (staging / name).read_bytes()
                ):
                    raise SystemExit(f"Immutable Atlaso Inventory Linux {version} is already installed with different content.")
            installed_manifest_path = target / "manifest.json"
            if installed_manifest_path.is_symlink() or not installed_manifest_path.is_file():
                raise SystemExit(f"Installed Atlaso Inventory Linux {version} has no manifest.")
            installed_manifest = json.loads(installed_manifest_path.read_text(encoding="utf-8"))
            if installed_manifest_path.read_bytes() != (staging / "manifest.json").read_bytes():
                if (
                    installed_manifest.get("kind") != "atlaso-network-boot-media"
                    or installed_manifest.get("schema_version") != 1
                    or installed_manifest.get("environment") != "inventory"
                    or installed_manifest.get("version") != version
                ):
                    raise SystemExit(f"Immutable Atlaso Inventory Linux {version} is already installed with a different manifest.")
            target.chmod(0o755)
        else:
            pathlib.Path(temporary).replace(target)
    owned_paths = [
        target.parent,
        target,
        *(target / name for name in ("bzImage", "rootfs.cpio.gz", "manifest.json")),
    ]
    if any(owned_path.is_symlink() for owned_path in owned_paths):
        raise SystemExit(
            f"Atlaso Inventory Linux {version} ownership path must not be a symlink."
        )
    for owned_path in owned_paths:
        shutil.chown(
            owned_path,
            user="atlaso",
            group="atlaso",
            follow_symlinks=False,
        )
print(f"Installed Atlaso Inventory Linux {version}.")
PY
fi
install -d -o root -g root -m 0755 /usr/local/bin
ln -sfn "$venv/bin/atlaso-vault" /usr/local/bin/atlaso-vault
ln -sfn "$venv/bin/atlaso-vault" /usr/bin/atlaso-vault
preflight_powershell_layouts
pwsh_path="$(command -v pwsh || true)"
if [ -n "$pwsh_path" ]; then
    powershell_binary="$(readlink -f "$pwsh_path")"
    powershell_home="$(dirname "$powershell_binary")"
    case "$powershell_home" in
        /usr/share/powershell)
            powershell_ancestors="/ /usr /usr/share /usr/share/powershell"
            inactive_powershell_home="/opt/microsoft/powershell/7"
            inactive_powershell_ancestors="/ /opt /opt/microsoft /opt/microsoft/powershell /opt/microsoft/powershell/7"
            ;;
        /opt/microsoft/powershell/7)
            powershell_ancestors="/ /opt /opt/microsoft /opt/microsoft/powershell /opt/microsoft/powershell/7"
            inactive_powershell_home="/usr/share/powershell"
            inactive_powershell_ancestors="/ /usr /usr/share /usr/share/powershell"
            ;;
        *)
            echo "PowerShell resolved to an unsupported global profile directory: $powershell_home" >&2
            exit 2
            ;;
    esac
    powershell_binary_metadata="$(stat -c '%u:%g:%a' "$powershell_binary")"
    old_ifs="$IFS"
    IFS=:
    set -- $powershell_binary_metadata
    IFS="$old_ifs"
    if [ ! -f "$powershell_binary" ] || [ "$1" != "0" ] || [ "$2" != "0" ] || \
        [ $((0$3 & 0022)) -ne 0 ] || [ $((0$3 & 0111)) -eq 0 ]; then
        echo "PowerShell executable must be root-owned, executable, and non-writable by group or other: $powershell_binary" >&2
        exit 2
    fi
    for powershell_directory in $powershell_ancestors; do
        if [ -L "$powershell_directory" ] || [ ! -d "$powershell_directory" ]; then
            echo "PowerShell profile directory must be a canonical directory: $powershell_directory" >&2
            exit 2
        fi
        powershell_metadata="$(stat -c '%u:%g:%a' "$powershell_directory")"
        old_ifs="$IFS"
        IFS=:
        set -- $powershell_metadata
        IFS="$old_ifs"
        if [ "$1" != "0" ] || [ "$2" != "0" ]; then
            echo "PowerShell profile directory must be owned by root: $powershell_directory" >&2
            exit 2
        fi
        if [ $((0$3 & 0022)) -ne 0 ]; then
            echo "PowerShell profile directory must not be writable by group or other: $powershell_directory" >&2
            exit 2
        fi
    done
    powershell_profile="$powershell_home/profile.ps1"
    if [ -L "$powershell_profile" ] || { [ -e "$powershell_profile" ] && [ ! -f "$powershell_profile" ]; }; then
        echo "PowerShell global profile path must be a regular file or absent: $powershell_profile" >&2
        exit 2
    fi
    cat >"/opt/atlaso/bin/atlaso-vault-profile.ps1" <<'ATLASO_POWERSHELL_PROFILE'
function global:Get-AtlasoVault {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Key
    )

    $value = & '/opt/atlaso/.venv/bin/atlaso-vault' get --key $Key
    if ($LASTEXITCODE -ne 0) {
        throw "Atlaso vault lookup failed for key: $Key"
    }
    return ($value -join [Environment]::NewLine)
}
ATLASO_POWERSHELL_PROFILE
    chown root:root /opt/atlaso/bin/atlaso-vault-profile.ps1
    chmod 0644 /opt/atlaso/bin/atlaso-vault-profile.ps1
    # Replace the complete Atlaso-owned global profile; preserving producer bytes
    # would let unverified commands execute before the authenticated vault import.
    powershell_profile_temporary="$(mktemp "$powershell_home/.atlaso-profile.XXXXXX")"
    cat >"$powershell_profile_temporary" <<'ATLASO_GLOBAL_POWERSHELL_PROFILE'
<#
.SYNOPSIS
Loads the Atlaso vault helpers into PowerShell sessions.
#>
. '/opt/atlaso/bin/atlaso-vault-profile.ps1'
ATLASO_GLOBAL_POWERSHELL_PROFILE
    chown root:root "$powershell_profile_temporary"
    chmod 0644 "$powershell_profile_temporary"
    mv -fT -- "$powershell_profile_temporary" "$powershell_profile"
    profile_metadata="$(stat -c '%u:%g:%a' "$powershell_profile")"
    if [ "$profile_metadata" != "0:0:644" ]; then
        echo "PowerShell global profile verification failed: $powershell_profile" >&2
        exit 2
    fi
    inactive_powershell_profile="$inactive_powershell_home/profile.ps1"
    if [ -L "$inactive_powershell_profile" ] || [ -e "$inactive_powershell_profile" ]; then
        # A package-layout transition may leave Atlaso's prior profile behind.
        # Delete only the exact root-owned Atlaso bytes through a canonical,
        # non-writable supported directory chain.
        for powershell_directory in $inactive_powershell_ancestors; do
            if [ -L "$powershell_directory" ] || [ ! -d "$powershell_directory" ]; then
                echo "PowerShell profile directory must be a canonical directory: $powershell_directory" >&2
                exit 2
            fi
            powershell_metadata="$(stat -c '%u:%g:%a' "$powershell_directory")"
            old_ifs="$IFS"
            IFS=:
            set -- $powershell_metadata
            IFS="$old_ifs"
            if [ "$1" != "0" ] || [ "$2" != "0" ]; then
                echo "PowerShell profile directory must be owned by root: $powershell_directory" >&2
                exit 2
            fi
            if [ $((0$3 & 0022)) -ne 0 ]; then
                echo "PowerShell profile directory must not be writable by group or other: $powershell_directory" >&2
                exit 2
            fi
        done
        if [ -L "$inactive_powershell_profile" ] || [ ! -f "$inactive_powershell_profile" ] || \
            [ "$(stat -c '%u:%g:%a' "$inactive_powershell_profile")" != "0:0:644" ] || \
            ! cmp -s -- "$inactive_powershell_profile" "$powershell_profile"; then
            echo "Inactive PowerShell global profile is not Atlaso-owned: $inactive_powershell_profile" >&2
            exit 2
        fi
        rm -f -- "$inactive_powershell_profile"
        sync -f "$inactive_powershell_home"
    fi
fi
if [ -n "$helper_path" ]; then
    install -o root -g root -m 0755 "$helper_path" /opt/atlaso/bin/atlaso-helper
    sed -i 's/\r$//' /opt/atlaso/bin/atlaso-helper
fi
if [ -n "$console_manager_path" ]; then
    install -d -o root -g root -m 0755 /etc/systemd/system.conf.d
    install -o root -g root -m 0644 "$console_manager_path" /etc/systemd/system.conf.d/atlaso-console.conf
    sed -i 's/\r$//' /etc/systemd/system.conf.d/atlaso-console.conf
    systemctl mask --force ctrl-alt-del.target
    systemctl daemon-reexec
fi
if [ -n "$boot_installer_path" ]; then
    install -o root -g root -m 0755 "$boot_installer_path" /opt/atlaso/bin/atlaso-install-boot-branding
    sed -i 's/\r$//' /opt/atlaso/bin/atlaso-install-boot-branding
    /opt/atlaso/bin/atlaso-install-boot-branding "$boot_theme_path" "$boot_background_path"
fi
install -d -o root -g root -m 0755 /etc/atlaso/update-trust.d
old_ifs="$IFS"
IFS=:
for trust_key_path in $trust_key_paths; do
    if [ ! -f "$trust_key_path" ]; then
        echo "Atlaso release trust key upload is missing: $trust_key_path" >&2
        exit 1
    fi
    trust_key_name="$(basename "$trust_key_path")"
    case "$trust_key_name" in
        *.pem) ;;
        *)
            echo "Atlaso release trust key must use a .pem filename: $trust_key_name" >&2
            exit 1
            ;;
    esac
    if ! trust_key_details="$(openssl pkey -pubin -in "$trust_key_path" -text -noout 2>/dev/null)"; then
        echo "Atlaso release trust key is not a valid public key: $trust_key_name" >&2
        exit 1
    fi
    case "$trust_key_details" in
        *ED25519*) ;;
        *)
            echo "Atlaso release trust key is not Ed25519: $trust_key_name" >&2
            exit 1
            ;;
    esac
    install -o root -g root -m 0644 "$trust_key_path" "/etc/atlaso/update-trust.d/$trust_key_name"
done
IFS="$old_ifs"
if ! getent group atlaso-automation >/dev/null 2>&1; then
    groupadd --system atlaso-automation
fi
if ! id atlaso-automation >/dev/null 2>&1; then
    useradd --system --gid atlaso-automation --home-dir /var/lib/atlaso/automation --shell /sbin/nologin atlaso-automation
fi
usermod -a -G atlaso-automation atlaso
install -d -o root -g atlaso -m 0750 /var/lib/atlaso-privileged /var/lib/atlaso-privileged/factory-reset
install -d -o atlaso -g atlaso-automation -m 0750 /var/lib/atlaso/automation /var/lib/atlaso/automation/scripts
install -d -o atlaso-automation -g atlaso-automation -m 0750 /var/lib/atlaso/automation/runs
install -o root -g root -m 0644 "$atlaso_service_path" /etc/systemd/system/atlaso.service
sed -i 's/\r$//' /etc/systemd/system/atlaso.service
install -o root -g root -m 0644 "$worker_service_path" /etc/systemd/system/atlaso-worker.service
sed -i 's/\r$//' /etc/systemd/system/atlaso-worker.service
install -d -o root -g root -m 0755 /etc/systemd/system/atlaso.service.d /etc/systemd/system/nginx.service.d
install -o root -g root -m 0644 "$atlaso_service_drop_in_path" /etc/systemd/system/atlaso.service.d/atlaso-data-disks.conf
install -o root -g root -m 0644 "$nginx_service_drop_in_path" /etc/systemd/system/nginx.service.d/atlaso-data-disks.conf
sed -i 's/\r$//' /etc/systemd/system/atlaso.service.d/atlaso-data-disks.conf /etc/systemd/system/nginx.service.d/atlaso-data-disks.conf
systemctl daemon-reload
find "$venv" -type d -exec chmod 755 {} \;
find "$venv" -type f -exec chmod 644 {} \;
find "$venv/bin" -type f -exec chmod 755 {} \;
if systemctl cat atlaso-console.service >/dev/null 2>&1; then
    systemctl restart atlaso-console.service
    systemctl is-active atlaso-console.service
fi
systemctl restart atlaso
systemctl is-active atlaso
systemctl enable atlaso-worker.service
systemctl restart atlaso-worker.service
systemctl is-active atlaso-worker.service
deadline=$(( $(date +%s) + timeout_seconds ))
while ! curl -fsS http://127.0.0.1:8000/openapi.json >/dev/null; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
        echo "Atlaso service is active, but loopback OpenAPI did not become reachable within ${timeout_seconds}s." >&2
        journalctl -u atlaso -n 80 --no-pager >&2 || true
        exit 1
    fi
    sleep "$poll_seconds"
done
trap - EXIT
echo "Atlaso service restarted and loopback OpenAPI is reachable."
'@

$tempDeployDirectory = Join-Path ([System.IO.Path]::GetTempPath()) "atlaso-deploy-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $tempDeployDirectory | Out-Null
$tempScript = Join-Path $tempDeployDirectory 'atlaso-deploy-wheel.sh'
[System.IO.File]::WriteAllText($tempScript, ($deployScript -replace "`r?`n", "`n"), [System.Text.UTF8Encoding]::new($false))
$sshControlPath = Join-Path ([System.IO.Path]::GetTempPath()) "lf-ssh-$([guid]::NewGuid().ToString('N')).sock"
$sshConnectionArguments = @(Get-SshConnectionArguments -ControlPath $sshControlPath)

try {
    $uploadPaths = @($resolvedWheelPath) + $runtimeDependencyPaths + $trustKeyPaths
    if (-not $SkipHelperSync) {
        $uploadPaths += $helperPath
    }
    if (-not $SkipConsoleAssetSync) {
        $uploadPaths += $consoleManagerPath
    }
    if (-not $SkipBootBrandingSync) {
        $uploadPaths += $bootInstallerPath
    }
    $uploadPaths += $atlasoServicePath
    $uploadPaths += $workerServicePath
    $uploadPaths += $atlasoServiceDropInPath
    $uploadPaths += $nginxServiceDropInPath
    if ($inventoryLinuxPackagePath) {
        $uploadPaths += $inventoryLinuxPackagePath
    }
    $uploadPaths += $tempScript

    $remoteHelperArgument = if ($SkipHelperSync) { '' } else { $remoteHelperPath }
    $localHelperArgument = if ($SkipHelperSync) { '' } else { $helperPath }
    $remoteConsoleManagerArgument = if ($SkipConsoleAssetSync) { '' } else { $remoteConsoleManagerPath }
    $localConsoleManagerArgument = if ($SkipConsoleAssetSync) { '' } else { $consoleManagerPath }
    $remoteBootInstallerArgument = if ($SkipBootBrandingSync) { '' } else { $remoteBootInstallerPath }
    $remoteBootThemeArgument = if ($SkipBootBrandingSync) { '' } else { $remoteBootThemePath }
    $remoteBootBackgroundArgument = if ($SkipBootBrandingSync) { '' } else { $remoteBootBackgroundPath }
    $localBootInstallerArgument = if ($SkipBootBrandingSync) { '' } else { $bootInstallerPath }
    $localBootThemeArgument = if ($SkipBootBrandingSync) { '' } else { $bootThemePath }
    $localBootBackgroundArgument = if ($SkipBootBrandingSync) { '' } else { $bootBackgroundPath }
    $remoteTrustKeysArgument = $remoteTrustKeyPaths -join ':'
    if ($UsePasswordDeploy) {
        Write-Host "Uploading deployment files to $SshUser@$IpAddress`:$RemoteDirectory with password-backed SSH"
        Invoke-PasswordBackedDeploy `
            -PythonCommand $resolvedOnePasswordPython `
            -HostAddress $IpAddress `
            -UserName $SshUser `
            -LocalWheelPath $resolvedWheelPath `
            -LocalRuntimeDependencyPaths $runtimeDependencyPaths `
            -LocalHelperPath $localHelperArgument `
            -LocalConsoleManagerPath $localConsoleManagerArgument `
            -LocalBootInstallerPath $localBootInstallerArgument `
            -LocalBootThemePath $localBootThemeArgument `
            -LocalBootBackgroundPath $localBootBackgroundArgument `
            -LocalInventoryLinuxPackagePath $inventoryLinuxPackagePath `
            -LocalTrustKeyPaths $trustKeyPaths `
            -LocalAtlasoServicePath $atlasoServicePath `
            -LocalWorkerServicePath $workerServicePath `
            -LocalAtlasoServiceDropInPath $atlasoServiceDropInPath `
            -LocalNginxServiceDropInPath $nginxServiceDropInPath `
            -LocalScriptPath $tempScript `
            -RemoteDirectoryPath $RemoteDirectory `
            -RemoteWheel $remoteWheelPath `
            -RemoteRuntimeDependencies $remoteRuntimeDependencyPaths `
            -RemoteHelper $remoteHelperArgument `
            -RemoteConsoleManager $remoteConsoleManagerArgument `
            -RemoteBootInstaller $remoteBootInstallerArgument `
            -RemoteBootTheme $remoteBootThemeArgument `
            -RemoteBootBackground $remoteBootBackgroundArgument `
            -RemoteInventoryLinuxPackage $remoteInventoryLinuxPackagePath `
            -RemoteTrustKeys $remoteTrustKeyPaths `
            -RemoteAtlasoService $remoteAtlasoServicePath `
            -RemoteWorkerService $remoteWorkerServicePath `
            -RemoteAtlasoServiceDropIn $remoteAtlasoServiceDropInPath `
            -RemoteNginxServiceDropIn $remoteNginxServiceDropInPath `
            -RemoteScript $remoteScriptPath `
            -ResetVaultEntryTable ([bool]$ResetVaultEntries) `
            -ReadinessTimeoutSeconds $ReadinessTimeoutSeconds `
            -DeploymentTimeoutSeconds $DeploymentTimeoutSeconds `
            -PollSeconds $ReadinessPollSeconds `
            -WorkingDirectory $resolvedRepoRoot `
            -EnvironmentId $OnePasswordEnvironmentId `
            -Account $OnePasswordAccount `
            -TrustedHostKey $trustedSshHostKey
    } else {
        Write-Host "Uploading deployment files to $SshUser@$IpAddress`:$RemoteDirectory"
        Invoke-CheckedCommand -FilePath 'scp' -Arguments @($sshConnectionArguments + $uploadPaths + "${SshUser}@${IpAddress}:$RemoteDirectory/")
        if (-not $SkipBootBrandingSync) {
            Invoke-CheckedCommand -FilePath 'scp' -Arguments @($sshConnectionArguments + $bootThemePath + "${SshUser}@${IpAddress}:$remoteBootThemePath")
            Invoke-CheckedCommand -FilePath 'scp' -Arguments @($sshConnectionArguments + $bootBackgroundPath + "${SshUser}@${IpAddress}:$remoteBootBackgroundPath")
        }

        Write-Host "Installing wheel and restarting atlaso.service..."
        $remoteRuntimeDependenciesArgument = $remoteRuntimeDependencyPaths -join ':'
        $resetVaultEntriesArgument = if ($ResetVaultEntries) { 'true' } else { 'false' }
        $remoteCommandArguments = @(
            'sudo', 'sh',
            $remoteScriptPath,
            $remoteWheelPath,
            "$ReadinessTimeoutSeconds",
            "$ReadinessPollSeconds",
            $remoteHelperArgument,
            $remoteConsoleManagerArgument,
            $remoteBootInstallerArgument,
            $remoteBootThemeArgument,
            $remoteBootBackgroundArgument,
            $remoteAtlasoServicePath,
            $remoteWorkerServicePath,
            $remoteAtlasoServiceDropInPath,
            $remoteNginxServiceDropInPath,
            $remoteRuntimeDependenciesArgument,
            $remoteTrustKeysArgument,
            $resetVaultEntriesArgument,
            $remoteInventoryLinuxPackagePath
        )
        $remoteCommand = (
            $remoteCommandArguments | ForEach-Object { ConvertTo-PosixShellArgument -Value $_ }
        ) -join ' '
        $remoteCommand = ConvertTo-WindowsSshRemoteCommand -Command $remoteCommand
        Invoke-CheckedCommand -FilePath 'ssh' -Arguments @(
            $sshConnectionArguments + '-t', "${SshUser}@${IpAddress}", $remoteCommand
        )
    }

    if (-not $SkipHostCheck) {
        Write-Host "Checking host-facing OpenAPI..."
        Invoke-HostOpenApiCheck -HostAddress $IpAddress
    }

    Write-Host "Deployed $wheelName to $IpAddress and verified atlaso.service."
} finally {
    if ($sshConnectionArguments.Count -gt 0) {
        & ssh @sshConnectionArguments -O exit "${SshUser}@${IpAddress}" 2>$null | Out-Null
    }
    Remove-Item -LiteralPath $tempDeployDirectory -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $sshControlPath -Force -ErrorAction SilentlyContinue
    if ($generatedRuntimeDependencyRoot) {
        Remove-Item -LiteralPath $generatedRuntimeDependencyRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
