<#
.SYNOPSIS
Verify real vmrun launcher console isolation with a surviving native descendant.
.PARAMETER RepositoryRoot
Checkout containing the production launcher.
.PARAMETER HarnessRoot
Private fixture directory passed only to the hidden console harness.
#>
[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string]$HarnessRoot = ''
)
$ErrorActionPreference = 'Stop'
if (-not $IsWindows) { throw 'This regression requires Windows.' }
$pwsh = (Get-Process -Id $PID).Path
if ($HarnessRoot) {
    try {
        . (Join-Path $RepositoryRoot 'scripts/windows/vmware/Atlaso.WorkstationFirstBoot.ps1')
        $env:ATLASO_CONSOLE_FIXTURE_ROOT = $HarnessRoot
        foreach ($mode in @('gui', 'nogui')) {
            $env:ATLASO_CONSOLE_FIXTURE_MODE = $mode
            $output = Invoke-AtlasoBoundedProcess -FilePath $pwsh -ArgumentList @(
                '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
                (Join-Path $RepositoryRoot 'scripts/windows/vmware/start-atlaso-vm.ps1'),
                '-VmxPath', (Join-Path $HarnessRoot 'fixture with spaces.vmx'),
                '-VmrunPath', (Join-Path $HarnessRoot 'vmrun.exe'), '-Mode', $mode
            ) -TimeoutSeconds 15 -Action 'Console-isolated vmrun regression'
            if ($output -notmatch 'Started VMware Workstation VM:') {
                throw 'The launcher did not report successful root completion.'
            }
            $evidence = Get-Content (Join-Path $HarnessRoot "$mode.txt")
            if ($evidence[0] -ne '0' -or $evidence[1] -ne '-T|ws|start' -or
                $evidence[2] -ne (Join-Path $HarnessRoot 'fixture with spaces.vmx') -or
                $evidence[3] -ne $mode) {
                throw 'vmrun inherited the parent console or lost its exact arguments.'
            }
            $descendant = Get-Process -Id ([int]$evidence[4]) -ErrorAction Stop
            if ($descendant.HasExited) { throw 'The descendant must survive launcher completion.' }
            $descendant.Kill()
            $descendant.WaitForExit()
        }
        [IO.File]::WriteAllText((Join-Path $HarnessRoot 'passed'), 'passed')
    }
    catch {
        [IO.File]::WriteAllText((Join-Path $HarnessRoot 'failed'), $_.Exception.Message)
        throw
    }
    return
}
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('atlaso-console-' + [guid]::NewGuid().ToString('N'))
$harness = $null
try {
    New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
    $source = @'
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
public static class VmrunFixture {
    [DllImport("kernel32.dll")] static extern uint GetConsoleProcessList(uint[] ids, uint count);
    public static int Main(string[] args) {
        if (args.Length == 1 && args[0] == "child") { Thread.Sleep(30000); return 0; }
        string root = Environment.GetEnvironmentVariable("ATLASO_CONSOLE_FIXTURE_ROOT");
        string mode = Environment.GetEnvironmentVariable("ATLASO_CONSOLE_FIXTURE_MODE");
        ProcessStartInfo start = new ProcessStartInfo(Path.Combine(root, "vmrun.exe"), "child");
        start.UseShellExecute = false;
        Process child = Process.Start(start);
        File.WriteAllLines(Path.Combine(root, mode + ".txt"), new [] {
            GetConsoleProcessList(new uint[16], 16).ToString(),
            string.Join("|", args, 0, 3), args[3], args[4], child.Id.ToString()
        });
        return 0;
    }
}
'@
    [IO.File]::WriteAllText((Join-Path $fixtureRoot 'fixture.cs'), $source)
    [IO.File]::WriteAllText((Join-Path $fixtureRoot 'fixture with spaces.vmx'), '# non-VM fixture')
    & "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /target:exe `
        "/out:$fixtureRoot\vmrun.exe" (Join-Path $fixtureRoot 'fixture.cs')
    if ($LASTEXITCODE -ne 0) { throw 'Native fixture compilation failed.' }
    # A hidden NEW console reproduces the interactive Windows Terminal path;
    # a pipe-only test runner would otherwise miss console inheritance entirely.
    $harness = Start-Process -FilePath $pwsh -WindowStyle Hidden -PassThru -ArgumentList @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-File', ('"' + $PSCommandPath + '"'),
        '-RepositoryRoot', ('"' + $RepositoryRoot + '"'), '-HarnessRoot', ('"' + $fixtureRoot + '"')
    )
    if (-not $harness.WaitForExit(60000)) { throw 'Console regression harness exceeded its deadline.' }
    if (Test-Path (Join-Path $fixtureRoot 'failed')) {
        throw (Get-Content (Join-Path $fixtureRoot 'failed') -Raw)
    }
    if (-not (Test-Path (Join-Path $fixtureRoot 'passed'))) { throw 'Console harness did not finish.' }
    Write-Host 'VMware GUI/nogui console isolation regression passed.'
}
finally {
    if ($harness -and -not $harness.HasExited) { $harness.Kill($true); $harness.WaitForExit() }
    # Only exact executable paths inside this invocation's fixture root qualify.
    foreach ($process in @(Get-Process vmrun -ErrorAction SilentlyContinue)) {
        if ($process.Path -eq (Join-Path $fixtureRoot 'vmrun.exe')) { $process.Kill(); $process.WaitForExit() }
    }
    if (Test-Path -LiteralPath $fixtureRoot) { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force }
}
