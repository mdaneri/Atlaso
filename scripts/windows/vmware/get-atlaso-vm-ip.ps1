[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$VmxPath,
    [string]$VmrunPath = '',
    [int]$TimeoutSeconds = 120,
    [int]$PollSeconds = 5
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
    throw 'vmrun.exe was not found. Install VMware Workstation Pro or pass -VmrunPath.'
}

$resolvedVmxPath = (Resolve-Path -LiteralPath $VmxPath).Path
$resolvedVmrun = Resolve-VmrunPath -Path $VmrunPath
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)

do {
    $ip = (& $resolvedVmrun -T ws getGuestIPAddress $resolvedVmxPath -wait 2>$null | Select-Object -First 1)
    if ($LASTEXITCODE -eq 0 -and $ip -match '^\d+\.\d+\.\d+\.\d+$' -and $ip -notlike '169.254.*') {
        $ip
        exit 0
    }

    if ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $PollSeconds
    }
} while ((Get-Date) -lt $deadline)

throw "No IPv4 address reported for VM '$resolvedVmxPath'. Confirm open-vm-tools is running in the guest."
