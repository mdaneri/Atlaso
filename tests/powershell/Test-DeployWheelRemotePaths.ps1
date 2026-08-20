[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
)

$ErrorActionPreference = 'Stop'

function Assert-Equal {
    param(
        [Parameter(Mandatory = $true)]$Actual,
        [Parameter(Mandatory = $true)]$Expected,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if ($Actual -ne $Expected) {
        throw "$Message Expected '$Expected', got '$Actual'."
    }
}

$deployPath = Join-Path $RepositoryRoot 'scripts\windows\vmware\deploy-wheel.ps1'
$deploySource = Get-Content -LiteralPath $deployPath -Raw
$executionMarker = '$resolvedRepoRoot = Resolve-RepoRoot -Path $RepoRoot'
$executionIndex = $deploySource.IndexOf($executionMarker, [System.StringComparison]::Ordinal)
if ($executionIndex -lt 0) {
    throw 'Unable to locate the deploy-wheel execution boundary.'
}

Invoke-Expression $deploySource.Substring(0, $executionIndex)

Assert-Equal (Resolve-RemoteDirectoryPath -Path '/tmp') '/tmp' 'The default path must remain unchanged.'
Assert-Equal (Resolve-RemoteDirectoryPath -Path '/tmp/atlaso-build_1.2/') '/tmp/atlaso-build_1.2' 'One trailing slash must be normalized.'
Assert-Equal (Resolve-RemoteDirectoryPath -Path '/') '/' 'The POSIX root must remain canonical.'
Assert-Equal (Join-RemotePath -Directory '/tmp/atlaso-build' -Leaf 'atlaso.whl') '/tmp/atlaso-build/atlaso.whl' 'A normal remote path must join once.'
Assert-Equal (Join-RemotePath -Directory '/' -Leaf 'atlaso.whl') '/atlaso.whl' 'A root remote path must not gain a second slash.'
Assert-Equal (ConvertTo-PosixShellArgument -Value '') "''" 'An empty remote argument must remain one empty argument.'
Assert-Equal (ConvertTo-PosixShellArgument -Value "/tmp/atlaso'build") "'/tmp/atlaso'`"'`"'build'" 'An apostrophe must remain quoted data.'

$validationCall = '$RemoteDirectory = Resolve-RemoteDirectoryPath -Path $RemoteDirectory'
$validationIndex = $deploySource.IndexOf($validationCall, [System.StringComparison]::Ordinal)
$buildIndex = $deploySource.IndexOf('if (-not $SkipBuild) {', [System.StringComparison]::Ordinal)
$authenticationIndex = $deploySource.IndexOf('if ($SshPassword) {', [System.StringComparison]::Ordinal)
if ($validationIndex -lt 0 -or $validationIndex -gt $buildIndex -or $validationIndex -gt $authenticationIndex) {
    throw 'RemoteDirectory validation must run before build work and authentication-specific deployment.'
}
if ($deploySource.Contains('$RemoteDirectory.TrimEnd')) {
    throw 'Remote paths must use the shared normalized join contract.'
}
if (-not $deploySource.Contains('$remoteCommandArguments | ForEach-Object { ConvertTo-PosixShellArgument -Value $_ }')) {
    throw 'The key-backed remote command must serialize every argument through the POSIX quoting helper.'
}

$invalidPaths = @(
    "/tmp/atlaso'build",
    '/tmp/atlaso build',
    '/tmp/atlaso$build',
    '/tmp/atlaso`build',
    '/tmp/atlaso;build',
    "/tmp/atlaso`nbuild",
    "/tmp/atlaso`n",
    "/tmp/atlaso`r",
    "/tmp/atlaso`t",
    "/tmp/atlaso$([char]0)",
    'relative/path',
    '/tmp/../etc'
)
$secretSentinel = 'deploy-password-must-not-appear'

foreach ($invalidPath in $invalidPaths) {
    foreach ($password in @('', $secretSentinel)) {
        $arguments = @{
            RepoRoot = $RepositoryRoot
            RemoteDirectory = $invalidPath
            SkipBuild = $true
            SkipHelperSync = $true
            SkipConsoleAssetSync = $true
            SkipBootBrandingSync = $true
            SkipInventoryLinuxSync = $true
            SkipHostCheck = $true
            SshPassword = $password
        }
        try {
            & $deployPath @arguments 2>&1 | Out-String | Out-Null
            throw "Unsafe RemoteDirectory unexpectedly reached deployment: $invalidPath"
        } catch {
            $diagnostic = $_ | Out-String
            if ($diagnostic -notmatch 'absolute POSIX path using only ASCII letters, digits, /, \., _, and -') {
                throw "Unsafe RemoteDirectory did not fail at the shared validation boundary: $invalidPath`n$diagnostic"
            }
            if ($diagnostic.Contains($secretSentinel, [System.StringComparison]::Ordinal)) {
                throw 'RemoteDirectory validation exposed the SSH password in diagnostics.'
            }
        }
    }
}

$capturedCommands = [System.Collections.Generic.List[object]]::new()
function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string[]]$Arguments,
        [string]$WorkingDirectory = ''
    )

    $capturedCommands.Add([pscustomobject]@{
        Command = $FilePath
        Arguments = @($Arguments)
    })
}
function Get-SshConnectionArguments {
    param([string]$ControlPath)

    return @()
}

$safeDirectory = '/tmp/atlaso-safe_1.2'
$fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) "atlaso-deploy-path-fixture-$([guid]::NewGuid().ToString('N'))"
$fixtureFiles = @(
    'dist\atlaso-9.9.9-py3-none-any.whl',
    'dist\authlib-9.9.9-py3-none-any.whl',
    'dist\joserfc-9.9.9-py3-none-any.whl',
    'dist\pycdlib-9.9.9-py3-none-any.whl',
    'image\common\update-trust\atlaso-release-test.pem',
    'image\vmware-workstation\systemd\atlaso.service',
    'image\common\systemd\atlaso-worker.service',
    'image\common\systemd\atlaso-require-data-disks.conf',
    'image\common\systemd\nginx-atlaso-data-disks.conf'
)
foreach ($fixtureFile in $fixtureFiles) {
    $fixturePath = Join-Path $fixtureRoot $fixtureFile
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $fixturePath) | Out-Null
    [System.IO.File]::WriteAllText($fixturePath, 'fixture', [System.Text.UTF8Encoding]::new($false))
}
$wheelPath = Get-Item -LiteralPath (Join-Path $fixtureRoot 'dist\atlaso-9.9.9-py3-none-any.whl')
$wheelFileName = $wheelPath.Name

$RepoRoot = $fixtureRoot
$IpAddress = '192.0.2.10'
$VmxPath = ''
$VmrunPath = ''
$SshUser = 'admin'
$RemoteDirectory = "$safeDirectory/"
$Python = 'python'
$ReadinessTimeoutSeconds = 60
$ReadinessPollSeconds = 2
$SkipBuild = $true
$SkipHelperSync = $true
$SkipConsoleAssetSync = $true
$SkipBootBrandingSync = $true
$SkipInventoryLinuxSync = $true
$WheelPath = $wheelPath.FullName
$SshPassword = ''
$ResetVaultEntries = $false
$SkipHostCheck = $true
try {
    Invoke-Expression $deploySource.Substring($executionIndex)
} finally {
    Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$upload = $capturedCommands |
    Where-Object { $_.Command -eq 'scp' } |
    Select-Object -First 1
if (-not $upload) {
    throw 'The safe key-backed fixture did not reach scp.'
}
$uploadArguments = @($upload.Arguments)
Assert-Equal $uploadArguments[-1] "admin@192.0.2.10:$safeDirectory/" 'The normalized safe directory must remain one scp destination argument.'

$install = $capturedCommands |
    Where-Object { $_.Command -eq 'ssh' -and $_.Arguments -contains '-t' } |
    Select-Object -First 1
if (-not $install) {
    throw 'The safe key-backed fixture did not reach the remote install command.'
}
$installArguments = @($install.Arguments)
$remoteCommand = $installArguments[-1]
$expectedScriptArgument = ConvertTo-PosixShellArgument -Value "$safeDirectory/atlaso-deploy-wheel.sh"
$expectedWheelArgument = ConvertTo-PosixShellArgument -Value "$safeDirectory/$wheelFileName"
if (-not $remoteCommand.Contains($expectedScriptArgument, [System.StringComparison]::Ordinal)) {
    throw 'The exact safe remote script path was not preserved as one shell argument.'
}
if (-not $remoteCommand.Contains($expectedWheelArgument, [System.StringComparison]::Ordinal)) {
    throw 'The exact safe remote wheel path was not preserved as one shell argument.'
}

Write-Output 'Deploy wheel remote path contract tests passed.'
