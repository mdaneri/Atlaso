"""Focused contracts for Photon image-build 1Password credential defaults."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest


def _embedded_child(path: str) -> str:
    """Return the embedded isolated Python SDK child from a PowerShell helper.

    Args:
        path: Repository-relative PowerShell helper path.

    Returns:
        Exact embedded Python source.
    """
    source = Path(path).read_text(encoding="utf-8")
    start_marker = "$pythonSource = @'\n"
    end_marker = "\n'@\n"
    start = source.index(start_marker) + len(start_marker)
    end = source.index(end_marker, start)
    return source[start:end]


def test_photon_bridge_reuses_the_established_test_vm_sdk_child() -> None:
    """Keep Photon retrieval identical to the already tested issue 558 child."""
    generic = _embedded_child(
        "scripts/windows/vmware/Invoke-AtlasoOnePasswordCredentials.ps1"
    )
    established = _embedded_child(
        "scripts/windows/vmware/Invoke-AtlasoTestVmCredentials.ps1"
    )

    assert generic == established


def test_photon_wrapper_preflights_credentials_before_image_mutation() -> None:
    """Require credential preparation before every VMware or image mutation."""
    wrapper = Path("scripts/windows/vmware/build-photon-image.ps1").read_text(
        encoding="utf-8"
    )
    module = Path(
        "scripts/windows/vmware/Atlaso.OnePasswordCredentials.psm1"
    ).read_text(encoding="utf-8")
    build_module = Path(
        "scripts/windows/common/Atlaso.PhotonImage.psm1"
    ).read_text(encoding="utf-8")
    runner = Path(
        "scripts/windows/vmware/Atlaso.WorkstationFirstBoot.ps1"
    ).read_text(encoding="utf-8")

    assert "[SecureString]$SshPassword" in wrapper
    assert "[SecureString]$BootstrapAdminPassword" in wrapper
    assert "[string]$OnePasswordEnvironmentId = ''" in wrapper
    assert "[Alias('OnePasswordEnvironmentIdFile')]" in wrapper
    assert "[string]$EnvironmentIdFile = ''" in wrapper
    assert "[string]$OnePasswordAccount = ''" in wrapper
    assert "[string]$OnePasswordPython = ''" in wrapper
    assert "Read-Host" not in wrapper
    assert "-AdminPassword $BootstrapAdminPassword" in wrapper
    assert "-RootPassword $SshPassword" in wrapper
    assert "if ($CredentialChild) {" in wrapper
    assert "AdminPasswordCiphertext = ConvertFrom-SecureString" in wrapper
    assert "RootPasswordCiphertext  = ConvertFrom-SecureString" in wrapper
    assert "Invoke-AtlasoBoundedStreamingProcess `" in wrapper
    assert "$childArguments += '-BuilderStaticDnsJson'" in wrapper
    assert "ConvertTo-Json -InputObject $transportedDns -Compress" in wrapper
    assert "$childArguments += '-BuilderStaticDnsBound'" in wrapper
    assert "$transportedDns = if ($null -eq $entry.Value) { @() }" in wrapper
    assert "$BuilderStaticDns = @($transportedDns)" in wrapper
    assert "$transportedDns.Count -eq 0" not in wrapper
    assert (
        "$PSBoundParameters.ContainsKey('BuilderStaticDns') -or $BuilderStaticDnsBound"
        in wrapper
    )
    assert (
        "$childSensitiveBuildDirectory = Join-Path $credentialRoot 'sensitive-build'"
        in wrapper
    )
    assert "'-SensitiveBuildDirectory', $childSensitiveBuildDirectory" in wrapper
    assert "'SensitiveBuildDirectory', 'OutputCleanupClaimPath'," in wrapper
    assert "'BuilderAddressReservationPath', 'PreparedIsoPath'" in wrapper
    assert "'pending-releases'" in wrapper
    assert "Complete-AtlasoBuilderAddressReservationHandoff" in wrapper
    assert "-SensitiveBuildDirectory $SensitiveBuildDirectory" in wrapper
    assert "[System.IO.Directory]::Delete($resolvedRoot, $true)" in wrapper
    assert "photon-image-build-cleanup.json" in wrapper
    assert "Get-AtlasoWindowsBootIdentity" in wrapper
    assert "Write-AtlasoDurableJsonFile" in wrapper
    assert "$Marker.Phase = 'root-absent'" in wrapper
    assert "$Marker.Phase = 'retired'" in wrapper
    assert "Sync-AtlasoDirectoryMetadata -DirectoryPath (Split-Path -Parent $resolvedRoot)" in wrapper
    assert "AtlasoProcessTreeTerminationUnproven" in wrapper
    assert "AtlasoProcessTreeTerminationProven" in wrapper
    assert "if (-not $processTreeTerminationUnproven)" in wrapper
    assert "$reservationReleaseBlocked = $true" in wrapper
    assert "if (-not $reservationReleaseBlocked)" in wrapper
    assert "Restart Windows, then rerun this wrapper" in wrapper
    assert "The proven outer process boundary selected checked VMware artifact cleanup." in wrapper
    assert "$outerCleanupOutputExistedBeforeChild = Test-Path" in wrapper
    assert "Test-Path -LiteralPath $childOutputCleanupClaimPath -PathType Leaf" in wrapper
    assert "if (-not $KeepExistingOutput -or -not $builderOutputExists) {" in wrapper
    assert "output-cleanup-claimed.json" in wrapper
    parent_output_resolution = wrapper.index(
        "$outerCleanupOutputDirectory = Resolve-WorkstationOutputDirectory"
    )
    parent_vmrun_resolution = wrapper.index(
        "$parentVmrunPath = Resolve-WorkstationVmrunPath -Path $VmrunPath"
    )
    assert wrapper.index("function Resolve-WorkstationOutputDirectory {") < parent_output_resolution
    assert wrapper.index("function Resolve-WorkstationVmrunPath {") < parent_vmrun_resolution
    assert parent_output_resolution < wrapper.index(
        "Write-AtlasoDurableJsonFile -Path $cleanupMarkerPath"
    )
    output_claim = "Write-AtlasoDurableJsonFile -Path $resolvedOutputCleanupClaimPath"
    output_removal = "Remove-AtlasoWorkstationArtifactRoot `"
    assert wrapper.index(output_claim) < wrapper.index(output_removal, wrapper.index(output_claim))
    assert wrapper.index("[System.IO.Directory]::Delete($resolvedRoot, $true)") < wrapper.index(
        "Remove-Item -LiteralPath $MarkerPath"
    )
    assert "Join-Path $sensitiveBuildDir 'packer-vars\\atlaso-photon.auto.pkrvars.hcl'" in build_module
    assert "Join-Path $sensitiveBuildDir 'kickstart-src'" in build_module
    assert "-Action 'The isolated VMware Photon image build'" in wrapper

    credential_preflight = wrapper.index(
        "$credentialPair = Get-AtlasoOnePasswordCredentialPair `"
    )
    artifact_admission = wrapper.index(
        "$OnePasswordPython = Confirm-AtlasoPhotonOnePasswordArtifact `"
    )
    recovery_block = wrapper.index(
        "if (-not $CredentialChild) {", wrapper.index("$cleanupMarkerPath")
    )
    assert artifact_admission < recovery_block
    assert artifact_admission < wrapper.index(
        "Invoke-AtlasoPhotonBuildCleanupRecovery -MarkerPath $cleanupMarkerPath",
        recovery_block,
    )
    assert artifact_admission < wrapper.index(
        "Complete-AtlasoBuilderAddressReservationHandoff `", recovery_block
    )
    assert artifact_admission < credential_preflight
    isolated_child = wrapper.index(
        "-Action 'The isolated VMware Photon image build'"
    )
    assert wrapper.index("AtlasoProcessTreeTerminationProven") < wrapper.index(
        "Remove-AtlasoWorkstationArtifactRoot `", isolated_child
    )
    parent_return = wrapper.index("    return\n}", isolated_child)
    network_discovery = wrapper.index("if (-not $SkipNetworkCheck) {")
    network_preparation = wrapper.index(
        "& (Join-Path $PSScriptRoot 'prepare-networks.ps1') @networkArgs"
    )
    output_cleanup = wrapper.index("Remove-AtlasoWorkstationArtifactRoot `")
    image_build = wrapper.index("Invoke-AtlasoPhotonImageBuild `")
    assert credential_preflight < network_discovery
    assert credential_preflight < network_preparation
    assert credential_preflight < output_cleanup
    assert credential_preflight < image_build
    assert credential_preflight < isolated_child < parent_return < network_discovery
    assert parent_return < image_build

    assert "$env:DEFAULT_ADMIN_PASSWORD -or $env:DEFAULT_ROOT_PASSWORD" in module
    assert "ConvertFrom-SecureString -SecureString $AdminPassword" in module
    assert "ConvertFrom-SecureString -SecureString $RootPassword" in module
    credential_root_cleanup = (
        "Remove-AtlasoOnePasswordCredentialBridge -BridgeRoot ([string]$Marker.RootPath)"
    )
    assert credential_root_cleanup in module
    assert "Sync-AtlasoDirectoryMetadata -DirectoryPath (Split-Path -Parent $resolvedBridgeRoot)" in module
    assert "onepassword-credential-cleanup.json" in module
    assert "Invoke-AtlasoOnePasswordCredentialCleanupRecovery" in module
    assert "Write-AtlasoDurableJsonFile -Path $cleanupMarkerPath" in module
    assert "$processTreeTerminationUnproven" in module
    assert module.index(credential_root_cleanup) < module.index("return $result")
    assert "[System.IO.FileOptions]::WriteThrough" in runner
    assert "$stream.Flush($true)" in runner
    assert "MoveFileEx" in runner
    assert "FlushFileBuffers" in runner
    assert "FILE_FLAG_BACKUP_SEMANTICS" in runner
    assert "StartSuspended($FilePath, $ArgumentList)" in runner
    assert "ResumeThread(processInformation.Thread)" in runner
    assert "JOB_OBJECT_LIMIT_BREAKAWAY_OK" not in runner
    assert "CREATE_BREAKAWAY_FROM_JOB" in runner
    assert "Start-AtlasoWorkstationUiBreakawayProcess" not in runner
    assert "-ExpectedRootPath $credentialRoot" in wrapper
    assert "Remove-Item -LiteralPath $childBuilderAddressReservationPath -Force" in wrapper
    assert "-ReservationHandoffPath $resolvedBuilderAddressReservationPath" in wrapper
    assert "was not paired with its durable release handoff" in wrapper
    assert "-ProcessTreeTerminationProven" in wrapper
    assert "SkipNetworkCheck suppresses topology preparation, not allocator safety" in wrapper
    assert "$requiresBuilderReservation = -not $ValidateOnly -and -not $PrepareIsoOnly" in wrapper
    assert "BuilderStaticIp must not be empty for a VMware Photon image build." in wrapper
    skipped_check_branch = wrapper.index("elseif ($requiresBuilderReservation) {")
    reservation_branch = wrapper.index("\nif ($requiresBuilderReservation) {", skipped_check_branch + 1)
    skipped_check_defaults = wrapper[skipped_check_branch:reservation_branch]
    assert "$BuilderStaticNetmask = $management.Mask" in skipped_check_defaults
    assert "$BuilderStaticGateway = $managementGateway" in skipped_check_defaults
    assert "$BuilderStaticDns = @($managementGateway)" in skipped_check_defaults
    assert "Get-Ipv4CidrFromSubnetOffset `" in skipped_check_defaults
    assert "$FinalMgmtAddress = 'dhcp'" in skipped_check_defaults
    assert "$FinalMgmtGateway = $managementGateway" in skipped_check_defaults
    assert "(@($BuilderStaticGateway) + $managementHostAddresses)" in wrapper
    assert "Cleanup marker root does not match the exact task-created Photon root." in wrapper
    assert "$Job.TerminateAndWait(10000)" in runner
    assert "$Job.CompleteAndWait(10000)" in runner
    assert "$jobCompletionProven = $false" in runner
    assert "$interruptionTerminationProven = $false" in runner
    assert "if (-not $jobCompletionProven)" in runner
    assert "if ($interruptionTerminationProven)" in runner
    assert "$processJob.TerminateAndWait(10000)" in runner
    assert "was interrupted and whole-process-tree cleanup could not be proven" in runner
    assert "was interrupted after proven whole-process-tree termination" in runner
    assert "accounting.ActiveProcesses == 0" in runner
    assert "AtlasoProcessTreeTerminationProven" in runner
    assert "Invoke-AtlasoBoundedStreamingProcess `" in module
    assert "MOVEFILE" not in wrapper


def test_environment_selector_and_sdk_runtime_are_shared_with_test_vm() -> None:
    """Prevent the image builder from creating a divergent Environment path."""
    wrapper = Path("scripts/windows/vmware/build-photon-image.ps1").read_text(
        encoding="utf-8"
    )
    test_vm = Path("scripts/windows/vmware/create-atlaso-test-vm.ps1").read_text(
        encoding="utf-8"
    )

    assert "Atlaso.OnePasswordCredentials.psm1" in wrapper
    assert "Atlaso.OnePasswordCredentials.psm1" in test_vm
    assert "Resolve-AtlasoOnePasswordEnvironmentId" in wrapper
    assert "Resolve-AtlasoOnePasswordEnvironmentId" in test_vm
    assert "Assert-AtlasoOnePasswordEnvironmentId" in test_vm
    assert "Resolve-AtlasoOnePasswordAccount" in test_vm
    assert "Resolve-AtlasoOnePasswordPython" in test_vm
    assert "Initialize-AtlasoOnePasswordSdkRuntime" in test_vm


def test_omitted_nonsecret_sdk_selectors_are_discovered_fail_closed() -> None:
    """Keep the documented no-selector command deterministic and pre-mutation."""
    module = Path(
        "scripts/windows/vmware/Atlaso.OnePasswordCredentials.psm1"
    ).read_text(encoding="utf-8")
    test_vm = Path("scripts/windows/vmware/create-atlaso-test-vm.ps1").read_text(
        encoding="utf-8"
    )
    image_wrapper = Path("scripts/windows/vmware/build-photon-image.ps1").read_text(
        encoding="utf-8"
    )

    assert "function Resolve-AtlasoOnePasswordAccount" in module
    assert "function Resolve-AtlasoOnePasswordCliPath" in module
    assert "'account', 'list', '--format', 'json'" in module
    assert "AgileBits.1Password.CLI_*" in module
    assert "if ($accounts.Count -ne 1)" in module
    assert "exactly one discoverable 1Password account" in module
    assert "Join-Path $env:WINDIR 'py.exe'" in module
    assert "Get-Command -Name 'py' -CommandType Application" in module
    assert "-ArgumentList @('-0p')" in module
    assert "\\*?\\s*(?<Path>.+?\\.exe)\\s*\\*?" in module
    assert "\\[-(?<Architecture>32|64|arm64)\\]" in module
    assert "-(?<Architecture>32|64|arm64)" in module
    assert "$candidate.Architecture -cne '64'" in module
    assert "free-threaded 3.14t are unsupported" in module
    assert module.index("Initialize-AtlasoOnePasswordSdkRuntime `", module.index("function Get-AtlasoOnePasswordCredentialPair")) < module.index(
        "Resolve-AtlasoOnePasswordAccount `",
        module.index("function Get-AtlasoOnePasswordCredentialPair"),
    )
    assert "struct.calcsize(\"P\") * 8" in module
    assert "CPython(?<Version>3\\.14)" in module
    assert "highest compatible" in image_wrapper
    assert "highest compatible" in test_vm
    assert "Resolve-OnePasswordTestVmAccount" in test_vm
    assert "return Resolve-AtlasoOnePasswordPython `" in test_vm
    artifact_preflight = test_vm.index(
        "$OnePasswordPython = Confirm-OnePasswordTestVmArtifact `"
    )
    assert artifact_preflight < test_vm.index(
        "Invoke-PendingAtlasoDevelopmentCaCleanup `"
    )
    assert artifact_preflight < test_vm.index("$resolvedOpPath = Resolve-OnePasswordCliPath")
    assert artifact_preflight < test_vm.index("Assert-OnePasswordDevelopmentCaBridge `")
    bridge_function = test_vm.index("function New-AtlasoTestVmCredentialBridgeState {")
    assert test_vm.index(
        "Initialize-OnePasswordTestVmSdkRuntime `", bridge_function
    ) < test_vm.index("Resolve-OnePasswordTestVmAccount `", bridge_function)
    assert "-OnePasswordPython $OnePasswordPython `" in image_wrapper
    assert "-OnePasswordCliPath $resolvedOpPath" in test_vm
    assert "'-OnePasswordAccount', $resolvedAccount" in test_vm
    assert "'-OnePasswordAccount', $resolvedAccount" in module


def test_shared_credential_bridge_explicit_and_fail_closed_cases() -> None:
    """Run real DPAPI explicit, invalid, partial, and caller-environment cases."""
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("PowerShell 7 is required")

    result = subprocess.run(
        [
            pwsh,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            "tests/powershell/Test-AtlasoOnePasswordCredentials.ps1",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Shared Atlaso 1Password credential bridge tests passed." in result.stdout
    assert "unit-admin-credential" not in result.stdout + result.stderr
    assert "unit-root-credential" not in result.stdout + result.stderr
    assert "caller-admin-must-not-be-used" not in result.stdout + result.stderr
    assert "caller-root-must-not-be-used" not in result.stdout + result.stderr
