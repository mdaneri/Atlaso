"""Keep the NTP cold-start launcher contract separate from certificate mode."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / 'scripts/windows/vmware/invoke-lifecycle-test.ps1'


def test_ntp_parameters_are_available_for_run_and_plan_with_peer_aliases():
    """Expose NTP selectors in both wrapper parameter sets and keep peer aliases."""
    launcher = LAUNCHER.read_text(encoding='utf-8')

    for name in (
        'NtpColdStartOnly',
        'NtpPeerSourceReceiptPath',
        'NtpPeerSourceReceiptSha256',
        'NtpPeerPreparedReceiptPath',
        'NtpPeerPreparedReceiptSha256',
    ):
        marker = f'${name}'
        declaration = launcher[launcher.index(marker) - 220:launcher.index(marker) + len(marker)]
        assert "ParameterSetName = 'Run'" in declaration
        assert "ParameterSetName = 'Plan'" in declaration

    assert "[Alias('NtpPeerCidr')]" in launcher
    assert "[Alias('NtpLeaseAddress')]" in launcher
    assert "[Alias('NtpPeerPublicKeyPath')]" in launcher


def test_ntp_run_requires_private_receipt_backed_inputs_and_protected_credentials():
    """Reject incomplete NTP fixture runs before prompting or launching VMware."""
    launcher = LAUNCHER.read_text(encoding='utf-8')
    start = launcher.index('if ($NtpColdStartOnly) {')
    end = launcher.index("} elseif ($PSBoundParameters.ContainsKey('NtpPeerSourceReceiptPath')", start)
    gate = launcher[start:end]

    assert '$SiteInterface -cne \'eth0\'' in gate
    assert "$SiteANetwork -notmatch '^lan:.+$'" in gate
    assert "$ManagementNetwork -notmatch '^VMnet\\d+$'" in gate
    assert '$AllowDryRunApply' in gate
    assert "ContainsKey('ApplianceIPAddress')" in gate
    assert "ContainsKey('ApplianceUrl')" in gate
    assert "ContainsKey('SignedReleaseRepositoryUrl')" in gate
    assert '$KeepVms' in gate and '$SkipClientPrepare' in gate
    assert "ContainsKey('ApplianceVmxPath')" in gate and 'Test-Path -LiteralPath $ApplianceVmxPath -PathType Leaf' in gate
    assert "ContainsKey('ClientVmdkPath')" in gate and 'Test-Path -LiteralPath $ClientVmdkPath -PathType Leaf' in gate
    assert '$null -eq $AdminPassword -or $null -eq $RootPassword' in gate
    assert "Test-Path -LiteralPath $CertificatePeerPublicKeyPath -PathType Leaf" in gate
    assert "-notmatch '^[0-9a-fA-F]{64}$'" in gate
    assert 'existing source and prepared peer receipt files' in gate


def test_ntp_mode_skips_full_lifecycle_preparation_and_forwards_receipts():
    """Preserve NTP focused behavior and carry every receipt through Plan and Run."""
    launcher = LAUNCHER.read_text(encoding='utf-8')

    assert '-not ($OidcOnly -or $TimeSourceOnly -or $NtpColdStartOnly -or $RoutingWanOnly' in launcher
    assert '-not ($TimeSourceOnly -or $NtpColdStartOnly -or $CertificateOnly)' in launcher
    assert '$TimeSourceOnly -or $NtpColdStartOnly -or $CertificateOnly' in launcher

    start = launcher.index('if ($NtpColdStartOnly) {', launcher.index("$arguments = @("))
    end = launcher.index('\n}', start)
    forwarded = launcher[start:end]
    for name in (
        'NtpColdStartOnly',
        'NtpPeerSourceReceiptPath',
        'NtpPeerSourceReceiptSha256',
        'NtpPeerPreparedReceiptPath',
        'NtpPeerPreparedReceiptSha256',
        'CertificatePeerCidr',
        'CertificateLeaseAddress',
        'CertificatePeerPublicKeyPath',
    ):
        assert f"'-{name}'" in forwarded
    assert 'CertificateOnly' not in forwarded
    assert 'CertificateDhcpPeer' not in forwarded


def test_pr871_certificate_dhcp_guard_remains_unchanged():
    """Keep the existing certificate peer admission bound to PR 871."""
    launcher = LAUNCHER.read_text(encoding='utf-8')
    expected = """if ($CertificateDhcpPeer -and ($PullRequestNumber -ne 871 -or -not $CertificateOnly -or -not $SiteANetwork.StartsWith('lan:', [StringComparison]::OrdinalIgnoreCase) -or $SiteANetwork.Length -le 4 -or $SiteInterface -ne 'eth0')) {
    throw '-CertificateDhcpPeer requires PR 871, -CertificateOnly, a named private lan: SiteANetwork, and SiteInterface eth0.'
}
if ($CertificateDhcpPeer -and -not $PlanOnly -and -not $PSBoundParameters.ContainsKey('ClientVmdkPath')) {
    throw '-CertificateDhcpPeer requires an explicit, provenance-admitted -ClientVmdkPath.'
}
if ($CertificateDhcpPeer -and -not $PlanOnly -and -not $CertificatePeerPublicKeyPath) {
    throw '-CertificateDhcpPeer requires -CertificatePeerPublicKeyPath for passwordless bootstrap.'
}"""
    assert expected in launcher
