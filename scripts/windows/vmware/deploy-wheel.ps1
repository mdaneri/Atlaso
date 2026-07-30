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
    [int]$ReadinessPollSeconds = 2,
    [switch]$SkipBuild,
    [switch]$SkipHelperSync,
    [switch]$SkipConsoleAssetSync,
    [switch]$SkipBootBrandingSync,
    [switch]$SkipInventoryLinuxSync,
    [string]$WheelPath = '',
    [string]$SshPassword = $env:ATLASO_DEPLOY_SSH_PASSWORD,
    [switch]$ResetVaultEntries,
    [switch]$SkipHostCheck
)

$ErrorActionPreference = 'Stop'

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

function Resolve-RepoRoot {
    param([string]$Path)

    if ($Path) {
        return (Resolve-Path -LiteralPath $Path).Path
    }
    return (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..\..')).Path
}

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

function Test-RequiredCommand {
    param([string]$Name)

    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $command) {
        throw "$Name was not found on PATH. Install Windows OpenSSH Client or run from a shell where $Name is available."
    }
    return $command.Source
}

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

function Initialize-PasswordDeployPythonPath {
    param(
        [Parameter(Mandatory = $true)][string]$PythonCommand,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$TemporaryDirectory
    )

    $paramikoAvailable = $false
    try {
        & $PythonCommand -c 'import paramiko' 2>$null
        $paramikoAvailable = $LASTEXITCODE -eq 0
    } catch {
        $paramikoAvailable = $false
    }
    if ($paramikoAvailable) {
        return ''
    }

    $wheelDirectory = Join-Path $WorkingDirectory 'dist'
    if (-not (Test-Path -LiteralPath $wheelDirectory -PathType Container)) {
        throw "Paramiko is not installed and the local wheel directory does not exist: $wheelDirectory. Rerun without -SkipBuild or install the Atlaso Python dependencies."
    }

    $dependencyDirectory = Join-Path $TemporaryDirectory 'python-dependencies'
    New-Item -ItemType Directory -Force -Path $dependencyDirectory | Out-Null
    Write-Host 'Preparing temporary Paramiko runtime from local deployment wheels...'
    try {
        Invoke-CheckedCommand -FilePath $PythonCommand -WorkingDirectory $WorkingDirectory -Arguments @(
            '-m', 'pip', 'install',
            '--disable-pip-version-check',
            '--no-index',
            '--find-links', $wheelDirectory,
            '--target', $dependencyDirectory,
            'paramiko>=3.5.0'
        ) | Out-Host
    } catch {
        throw "Unable to prepare the temporary Paramiko runtime from $wheelDirectory. Rerun without -SkipBuild so dependency wheels are downloaded, or install the Atlaso Python dependencies. $($_.Exception.Message)"
    }
    return $dependencyDirectory
}

function Invoke-PasswordBackedDeploy {
    param(
        [Parameter(Mandatory = $true)][string]$PythonCommand,
        [Parameter(Mandatory = $true)][string]$HostAddress,
        [Parameter(Mandatory = $true)][string]$UserName,
        [Parameter(Mandatory = $true)][string]$Password,
        [Parameter(Mandatory = $true)][string]$LocalWheelPath,
        [Parameter(Mandatory = $true)][string[]]$LocalRuntimeDependencyPaths,
        [string]$LocalHelperPath = '',
        [string]$LocalConsoleManagerPath = '',
        [string]$LocalBootInstallerPath = '',
        [string]$LocalBootThemePath = '',
        [string]$LocalBootBackgroundPath = '',
        [string]$LocalInventoryLinuxPackagePath = '',
        [Parameter(Mandatory = $true)][string[]]$LocalTrustKeyPaths,
        [Parameter(Mandatory = $true)][string]$LocalWorkerServicePath,
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
        [Parameter(Mandatory = $true)][string]$RemoteWorkerService,
        [Parameter(Mandatory = $true)][string]$RemoteScript,
        [Parameter(Mandatory = $true)][bool]$ResetVaultEntryTable,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][int]$PollSeconds,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory
    )

    $pythonDeploy = Join-Path (Split-Path -Parent $LocalScriptPath) 'atlaso-paramiko-deploy.py'
    $pythonDeploySource = @'
import argparse
import os
import pathlib
import shlex
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(errors="replace")

try:
    import paramiko
except ImportError as exc:
    raise SystemExit(
        "Paramiko could not be loaded for password-backed deployment after dependency preparation. "
        "Rerun without -SkipBuild or install the Atlaso Python dependencies."
    ) from exc


def shell_quote(value):
    return shlex.quote(str(value))


def sanitized(value, password):
    return value.replace(password, "[redacted]") if password else value


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
parser.add_argument("--local-worker-service", required=True)
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
parser.add_argument("--remote-worker-service", required=True)
parser.add_argument("--remote-script", required=True)
parser.add_argument("--reset-vault-entries", action="store_true")
parser.add_argument("--timeout", type=int, required=True)
parser.add_argument("--poll", type=int, required=True)
args = parser.parse_args()

if not args.local_trust_key or len(args.local_trust_key) != len(args.remote_trust_key):
    raise SystemExit("At least one matched local and remote Atlaso release trust key is required.")
if not args.local_runtime_dependency or len(args.local_runtime_dependency) != len(args.remote_runtime_dependency):
    raise SystemExit("Matched local and remote runtime dependency wheels are required.")

password = os.environ.get("ATLASO_DEPLOY_SSH_PASSWORD", "")
if not password:
    raise SystemExit("ATLASO_DEPLOY_SSH_PASSWORD is required for password-backed deployment.")

uploads = [
    (pathlib.Path(args.local_wheel), args.remote_wheel),
    (pathlib.Path(args.local_script), args.remote_script),
    (pathlib.Path(args.local_worker_service), args.remote_worker_service),
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

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(
    hostname=args.host,
    username=args.user,
    password=password,
    allow_agent=False,
    look_for_keys=False,
    timeout=15,
    banner_timeout=15,
    auth_timeout=15,
)
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
        f"{shell_quote(args.timeout)} "
        f"{shell_quote(args.poll)} "
        f"{shell_quote(remote_helper_argument)} "
        f"{shell_quote(remote_console_manager_argument)} "
        f"{shell_quote(remote_boot_installer_argument)} "
        f"{shell_quote(remote_boot_theme_argument)} "
        f"{shell_quote(remote_boot_background_argument)} "
        f"{shell_quote(args.remote_worker_service)} "
        f"{shell_quote(remote_runtime_dependencies_argument)} "
        f"{shell_quote(remote_trust_keys_argument)} "
        f"{shell_quote('true' if args.reset_vault_entries else 'false')} "
        f"{shell_quote(remote_inventory_linux_package_argument)}"
    )
    stdin, stdout, stderr = client.exec_command(command, get_pty=True, timeout=args.timeout + 60)
    stdin.write(password + "\n")
    stdin.flush()
    stdout_text = stdout.read().decode("utf-8", "replace")
    stderr_text = stderr.read().decode("utf-8", "replace")
    exit_code = stdout.channel.recv_exit_status()
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

    $temporaryPythonPath = Initialize-PasswordDeployPythonPath `
        -PythonCommand $PythonCommand `
        -WorkingDirectory $WorkingDirectory `
        -TemporaryDirectory (Split-Path -Parent $LocalScriptPath)
    $previousPassword = $env:ATLASO_DEPLOY_SSH_PASSWORD
    $previousPythonPath = $env:PYTHONPATH
    try {
        $env:ATLASO_DEPLOY_SSH_PASSWORD = $Password
        if ($temporaryPythonPath) {
            $env:PYTHONPATH = if ($previousPythonPath) {
                "$temporaryPythonPath$([System.IO.Path]::PathSeparator)$previousPythonPath"
            } else {
                $temporaryPythonPath
            }
        }
        $deployArguments = @(
            $pythonDeploy,
            '--host', $HostAddress,
            '--user', $UserName,
            '--local-wheel', $LocalWheelPath,
            '--local-helper', $LocalHelperPath,
            '--local-console-manager', $LocalConsoleManagerPath,
            '--local-boot-installer', $LocalBootInstallerPath,
            '--local-boot-theme', $LocalBootThemePath,
            '--local-boot-background', $LocalBootBackgroundPath,
            '--local-inventory-linux-package', $LocalInventoryLinuxPackagePath,
            '--local-script', $LocalScriptPath,
            '--remote-dir', $RemoteDirectoryPath,
            '--remote-wheel', $RemoteWheel,
            '--remote-helper', $RemoteHelper,
            '--remote-console-manager', $RemoteConsoleManager,
            '--remote-boot-installer', $RemoteBootInstaller,
            '--remote-boot-theme', $RemoteBootTheme,
            '--remote-boot-background', $RemoteBootBackground,
            '--remote-inventory-linux-package', $RemoteInventoryLinuxPackage,
            '--remote-script', $RemoteScript,
            '--timeout', "$TimeoutSeconds",
            '--poll', "$PollSeconds"
        )
        if ($ResetVaultEntryTable) {
            $deployArguments += '--reset-vault-entries'
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
            '--local-worker-service', $LocalWorkerServicePath,
            '--remote-worker-service', $RemoteWorkerService
        )
        Invoke-CheckedCommand -FilePath $PythonCommand -WorkingDirectory $WorkingDirectory -Arguments $deployArguments
    } finally {
        if ($null -eq $previousPassword) {
            Remove-Item Env:\ATLASO_DEPLOY_SSH_PASSWORD -ErrorAction SilentlyContinue
        } else {
            $env:ATLASO_DEPLOY_SSH_PASSWORD = $previousPassword
        }
        if ($null -eq $previousPythonPath) {
            Remove-Item Env:\PYTHONPATH -ErrorAction SilentlyContinue
        } else {
            $env:PYTHONPATH = $previousPythonPath
        }
    }
}

$resolvedRepoRoot = Resolve-RepoRoot -Path $RepoRoot

if (-not $SkipBuild) {
    New-Item -ItemType Directory -Force -Path (Join-Path $resolvedRepoRoot 'dist') | Out-Null
    Write-Host "Building Atlaso wheel..."
    Invoke-CheckedCommand -FilePath $Python -Arguments @('-m', 'pip', 'wheel', '.', '-w', 'dist') -WorkingDirectory $resolvedRepoRoot
}

$resolvedWheelPath = Get-WheelPath -Path $WheelPath -Root $resolvedRepoRoot
$wheelName = Split-Path -Leaf $resolvedWheelPath
$runtimeDependencies = @(
    foreach ($runtimeDependencyPattern in @('authlib-*.whl', 'joserfc-*.whl')) {
        $runtimeDependency = Get-ChildItem -LiteralPath (Join-Path $resolvedRepoRoot 'dist') -Filter $runtimeDependencyPattern -File |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
        if (-not $runtimeDependency) {
            throw "The $runtimeDependencyPattern runtime dependency wheel was not found under $(Join-Path $resolvedRepoRoot 'dist'). Rerun without -SkipBuild."
        }
        $runtimeDependency
    }
)
$runtimeDependencyPaths = @($runtimeDependencies | Select-Object -ExpandProperty FullName)
$runtimeDependencyNames = @($runtimeDependencies | Select-Object -ExpandProperty Name)
if ($runtimeDependencyPaths.Count -ne 2) {
    throw 'Exactly the Authlib and joserfc runtime dependency wheels are required.'
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
$workerServicePath = Join-Path $resolvedRepoRoot 'image\common\systemd\atlaso-worker.service'
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
if (-not (Test-Path -LiteralPath $workerServicePath -PathType Leaf)) {
    throw "Atlaso worker service not found: $workerServicePath"
}
if ($trustKeyPaths.Count -eq 0) {
    throw "No Atlaso release trust keys found under: $trustKeyDirectory"
}
$remoteWheelPath = "$($RemoteDirectory.TrimEnd('/'))/$wheelName"
$remoteRuntimeDependencyPaths = @(
    $runtimeDependencyNames | ForEach-Object {
        "$($RemoteDirectory.TrimEnd('/'))/$_"
    }
)
$remoteHelperPath = "$($RemoteDirectory.TrimEnd('/'))/atlaso-helper"
$remoteConsoleManagerPath = "$($RemoteDirectory.TrimEnd('/'))/atlaso-console-manager.conf"
$remoteBootInstallerPath = "$($RemoteDirectory.TrimEnd('/'))/atlaso-install-boot-branding"
$remoteBootThemePath = "$($RemoteDirectory.TrimEnd('/'))/atlaso-grub-theme.txt"
$remoteBootBackgroundPath = "$($RemoteDirectory.TrimEnd('/'))/atlaso-grub.png"
$remoteTrustKeyPaths = @(
    $trustKeyPaths | ForEach-Object {
        "$($RemoteDirectory.TrimEnd('/'))/$(Split-Path -Leaf $_)"
    }
)
$remoteWorkerServicePath = "$($RemoteDirectory.TrimEnd('/'))/atlaso-worker.service"
$remoteInventoryLinuxPackagePath = if ($inventoryLinuxPackagePath) {
    "$($RemoteDirectory.TrimEnd('/'))/$(Split-Path -Leaf $inventoryLinuxPackagePath)"
} else {
    ''
}
$remoteScriptPath = "$($RemoteDirectory.TrimEnd('/'))/atlaso-deploy-wheel.sh"

if (-not $IpAddress) {
    $resolvedVmrun = Resolve-VmrunPath -Path $VmrunPath
    if (-not $VmxPath) {
        $VmxPath = Get-AtlasoRunningVmx -ResolvedVmrun $resolvedVmrun
    }
    $resolvedVmxPath = (Resolve-Path -LiteralPath $VmxPath).Path
    $IpAddress = Get-GuestIpAddress -ResolvedVmrun $resolvedVmrun -ResolvedVmxPath $resolvedVmxPath
}

if (-not $SshPassword) {
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
worker_service_path="${9:?worker service path required}"
runtime_dependency_paths="${10:?runtime dependency wheel paths required}"
trust_key_paths="${11:?release trust key paths required}"
reset_vault_entries="${12:-false}"
inventory_linux_package="${13:-}"
venv="/opt/atlaso/.venv"
python="$venv/bin/python"

if [ ! -x "$python" ]; then
    echo "Atlaso venv python not found or not executable: $python" >&2
    exit 2
fi

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
    "$python" -m pip install --force-reinstall --no-deps "$runtime_dependency_path"
done
IFS="$old_ifs"
"$python" -m pip install --force-reinstall --no-deps "$wheel"
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
pwsh_path="$(command -v pwsh || true)"
if [ -n "$pwsh_path" ]; then
    powershell_home="$(dirname "$(readlink -f "$pwsh_path")")"
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
    touch "$powershell_home/profile.ps1"
    if ! grep -qxF ". '/opt/atlaso/bin/atlaso-vault-profile.ps1'" "$powershell_home/profile.ps1"; then
        printf "\n. '/opt/atlaso/bin/atlaso-vault-profile.ps1'\n" >>"$powershell_home/profile.ps1"
    fi
    chown root:root "$powershell_home/profile.ps1"
    chmod 0644 "$powershell_home/profile.ps1"
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
install -d -o atlaso -g atlaso-automation -m 0750 /var/lib/atlaso/automation /var/lib/atlaso/automation/scripts
install -d -o atlaso-automation -g atlaso-automation -m 0750 /var/lib/atlaso/automation/runs
install -o root -g root -m 0644 "$worker_service_path" /etc/systemd/system/atlaso-worker.service
sed -i 's/\r$//' /etc/systemd/system/atlaso-worker.service
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
echo "Atlaso service restarted and loopback OpenAPI is reachable."
'@

$tempDeployDirectory = Join-Path ([System.IO.Path]::GetTempPath()) "atlaso-deploy-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $tempDeployDirectory | Out-Null
$tempScript = Join-Path $tempDeployDirectory 'atlaso-deploy-wheel.sh'
[System.IO.File]::WriteAllText($tempScript, ($deployScript -replace "`r?`n", "`n"), [System.Text.UTF8Encoding]::new($false))
$sshControlPath = Join-Path ([System.IO.Path]::GetTempPath()) "lf-ssh-$([guid]::NewGuid().ToString('N')).sock"
$sshConnectionArguments = Get-SshConnectionArguments -ControlPath $sshControlPath

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
    $uploadPaths += $workerServicePath
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
    if ($SshPassword) {
        Write-Host "Uploading deployment files to $SshUser@$IpAddress`:$RemoteDirectory with password-backed SSH"
        Invoke-PasswordBackedDeploy `
            -PythonCommand $Python `
            -HostAddress $IpAddress `
            -UserName $SshUser `
            -Password $SshPassword `
            -LocalWheelPath $resolvedWheelPath `
            -LocalRuntimeDependencyPaths $runtimeDependencyPaths `
            -LocalHelperPath $localHelperArgument `
            -LocalConsoleManagerPath $localConsoleManagerArgument `
            -LocalBootInstallerPath $localBootInstallerArgument `
            -LocalBootThemePath $localBootThemeArgument `
            -LocalBootBackgroundPath $localBootBackgroundArgument `
            -LocalInventoryLinuxPackagePath $inventoryLinuxPackagePath `
            -LocalTrustKeyPaths $trustKeyPaths `
            -LocalWorkerServicePath $workerServicePath `
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
            -RemoteWorkerService $remoteWorkerServicePath `
            -RemoteScript $remoteScriptPath `
            -ResetVaultEntryTable ([bool]$ResetVaultEntries) `
            -TimeoutSeconds $ReadinessTimeoutSeconds `
            -PollSeconds $ReadinessPollSeconds `
            -WorkingDirectory $resolvedRepoRoot
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
        Invoke-CheckedCommand -FilePath 'ssh' -Arguments @($sshConnectionArguments + '-t', "${SshUser}@${IpAddress}", "sudo sh '$remoteScriptPath' '$remoteWheelPath' '$ReadinessTimeoutSeconds' '$ReadinessPollSeconds' '$remoteHelperArgument' '$remoteConsoleManagerArgument' '$remoteBootInstallerArgument' '$remoteBootThemeArgument' '$remoteBootBackgroundArgument' '$remoteWorkerServicePath' '$remoteRuntimeDependenciesArgument' '$remoteTrustKeysArgument' '$resetVaultEntriesArgument' '$remoteInventoryLinuxPackagePath'")
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
}
